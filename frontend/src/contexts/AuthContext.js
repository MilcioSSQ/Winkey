import React, { createContext, useContext, useState, useRef, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import {
  deriveMasterKey, deriveAuthSubkey, deriveEncSubkey,
  deriveRecoveryWrappingKey, deriveRecoveryAuthSubkey,
  generateAesKey, wrapKey, unwrapKey, randomBytes,
  generateRecoveryKey, parseRecoveryKey, toBase64, fromBase64,
  DEFAULT_KDF_PARAMS,
} from '../crypto/windkeyCrypto.js';

const AuthContext = createContext(null);

export const useAuth = () => useContext(AuthContext);

// The frontend and backend are reached via whatever host the browser used
// to load this page (localhost while developing on the server itself,
// or the server's LAN IP from any other family device) - never hardcode it.
axios.defaults.withCredentials = true;
axios.defaults.baseURL = `https://${window.location.hostname}:5000`;

let csrfTokenCache = null;
axios.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();
  if (['post', 'put', 'delete', 'patch'].includes(method) && !config.headers['X-CSRFToken']) {
    if (!csrfTokenCache) {
      const resp = await axios.get('/api/csrf-token');
      csrfTokenCache = resp.data.csrfToken;
    }
    config.headers['X-CSRFToken'] = csrfTokenCache;
  }
  return config;
});

function friendlyError(error, fallback = 'Ein Fehler ist aufgetreten') {
  return error.response?.data?.error || fallback;
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  // 'checking' | 'unauthenticated' | 'locked' | 'unlocked'
  const [authStatus, setAuthStatus] = useState('checking');
  const [userKey, setUserKey] = useState(null);
  const navigate = useNavigate();

  // Intermediate crypto material held between the password step and the 2FA
  // step of login - never touches component state/props, just an in-memory ref.
  const pendingLogin = useRef(null);
  const lockedKeyInfo = useRef(null);

  useEffect(() => {
    const check = async () => {
      try {
        const resp = await axios.get('/api/check-auth');
        setUser(resp.data.user);
        lockedKeyInfo.current = {
          wrappedUserKeyPassword: resp.data.wrappedUserKeyPassword,
          wrappedUserKeyPasswordIv: resp.data.wrappedUserKeyPasswordIv,
          kdfSalt: resp.data.kdfSalt,
          kdfMemoryCost: resp.data.kdfMemoryCost,
          kdfTimeCost: resp.data.kdfTimeCost,
          kdfParallelism: resp.data.kdfParallelism,
        };
        setAuthStatus('locked');
      } catch (error) {
        setUser(null);
        setAuthStatus('unauthenticated');
      }
    };
    check();
  }, []);

  useEffect(() => {
    if (authStatus === 'unauthenticated' && !['/login', '/register', '/recovery', '/verify-email'].includes(window.location.pathname)) {
      navigate('/login');
    }
  }, [authStatus, navigate]);

  const register = async (email, password) => {
    try {
      const salt = randomBytes(16);
      const masterKey = await deriveMasterKey(password, salt, DEFAULT_KDF_PARAMS);
      const authSubkey = await deriveAuthSubkey(masterKey);
      const encSubkey = await deriveEncSubkey(masterKey);
      const userKeyBytes = await generateAesKey();
      const { wrapped: wrappedUserKeyPassword, iv: wrappedUserKeyPasswordIv } = await wrapKey(userKeyBytes, encSubkey);

      const { bytes: recoveryKeyBytes, formatted: recoveryKeyFormatted } = generateRecoveryKey();
      const recoveryKdfSalt = randomBytes(16);
      const recoveryWrappingKey = await deriveRecoveryWrappingKey(recoveryKeyBytes, recoveryKdfSalt);
      const recoveryAuthSubkey = await deriveRecoveryAuthSubkey(recoveryKeyBytes, recoveryKdfSalt);
      const { wrapped: wrappedUserKeyRecovery, iv: wrappedUserKeyRecoveryIv } = await wrapKey(userKeyBytes, recoveryWrappingKey);

      const resp = await axios.post('/api/register', {
        email,
        authSubkey: toBase64(authSubkey),
        kdfSalt: toBase64(salt),
        kdfMemoryCost: DEFAULT_KDF_PARAMS.memoryCost,
        kdfTimeCost: DEFAULT_KDF_PARAMS.timeCost,
        kdfParallelism: DEFAULT_KDF_PARAMS.parallelism,
        wrappedUserKeyPassword, wrappedUserKeyPasswordIv,
        wrappedUserKeyRecovery, wrappedUserKeyRecoveryIv,
        recoveryKdfSalt: toBase64(recoveryKdfSalt),
        recoveryAuthSubkey: toBase64(recoveryAuthSubkey),
      });

      return {
        success: true,
        twoFactorSecret: resp.data.two_factor_secret,
        qrCode: resp.data.qr_code,
        emailSent: resp.data.email_sent,
        recoveryKeyFormatted,
      };
    } catch (error) {
      return { success: false, error: friendlyError(error, 'Registrierung fehlgeschlagen') };
    }
  };

  /** Step 1: prove knowledge of the master password. Returns whether 2FA is needed next. */
  const login = async (email, password, rememberMe = false) => {
    try {
      const pre = await axios.get(`/api/prelogin?email=${encodeURIComponent(email)}`);
      const salt = fromBase64(pre.data.salt);
      const masterKey = await deriveMasterKey(password, salt, {
        memoryCost: pre.data.kdfMemoryCost, timeCost: pre.data.kdfTimeCost, parallelism: pre.data.kdfParallelism,
      });
      const authSubkey = await deriveAuthSubkey(masterKey);
      const encSubkey = await deriveEncSubkey(masterKey);

      const resp = await axios.post('/api/login', { email, authSubkey: toBase64(authSubkey), rememberMe });

      pendingLogin.current = { encSubkey, temporaryToken: resp.data.temporaryToken };
      return { success: true, requiresTwoFactor: true };
    } catch (error) {
      return { success: false, error: friendlyError(error, 'Ungültige Anmeldedaten') };
    }
  };

  /** Step 2: TOTP code completes login and unwraps the vault key. */
  const verifyTwoFactor = async (code) => {
    if (!pendingLogin.current) {
      return { success: false, error: 'Sitzung abgelaufen, bitte erneut anmelden' };
    }
    try {
      const { encSubkey, temporaryToken } = pendingLogin.current;
      const resp = await axios.post('/api/verify-2fa', { temporaryToken, code });
      const unwrapped = await unwrapKey(resp.data.wrappedUserKeyPassword, resp.data.wrappedUserKeyPasswordIv, encSubkey);
      setUser(resp.data.user);
      setUserKey(unwrapped);
      setAuthStatus('unlocked');
      pendingLogin.current = null;
      navigate('/dashboard');
      return { success: true };
    } catch (error) {
      return { success: false, error: friendlyError(error, 'Ungültiger 2FA-Code') };
    }
  };

  /** After a page reload: session cookie is still valid, but userKey is gone from memory. */
  const unlock = async (masterPassword) => {
    if (!lockedKeyInfo.current) {
      return { success: false, error: 'Keine gesperrte Sitzung gefunden' };
    }
    try {
      const info = lockedKeyInfo.current;
      const masterKey = await deriveMasterKey(masterPassword, fromBase64(info.kdfSalt), {
        memoryCost: info.kdfMemoryCost, timeCost: info.kdfTimeCost, parallelism: info.kdfParallelism,
      });
      const encSubkey = await deriveEncSubkey(masterKey);
      const unwrapped = await unwrapKey(info.wrappedUserKeyPassword, info.wrappedUserKeyPasswordIv, encSubkey);
      setUserKey(unwrapped);
      setAuthStatus('unlocked');
      return { success: true };
    } catch (error) {
      return { success: false, error: 'Falsches Master-Passwort' };
    }
  };

  const recoverAccount = async (email, recoveryKeyFormatted, newPassword) => {
    try {
      const recoveryKeyBytes = parseRecoveryKey(recoveryKeyFormatted);
      const start = await axios.post('/api/recovery/start', { email });
      const recoveryKdfSalt = fromBase64(start.data.recoveryKdfSalt);
      const recoveryWrappingKey = await deriveRecoveryWrappingKey(recoveryKeyBytes, recoveryKdfSalt);

      let userKeyBytes;
      try {
        userKeyBytes = await unwrapKey(start.data.wrappedUserKeyRecovery, start.data.wrappedUserKeyRecoveryIv, recoveryWrappingKey);
      } catch {
        return { success: false, error: 'Ungültiger Recovery Key' };
      }

      const recoveryAuthSubkey = await deriveRecoveryAuthSubkey(recoveryKeyBytes, recoveryKdfSalt);
      const newSalt = randomBytes(16);
      const newMasterKey = await deriveMasterKey(newPassword, newSalt, DEFAULT_KDF_PARAMS);
      const newAuthSubkey = await deriveAuthSubkey(newMasterKey);
      const newEncSubkey = await deriveEncSubkey(newMasterKey);
      const { wrapped: newWrappedUserKeyPassword, iv: newWrappedUserKeyPasswordIv } = await wrapKey(userKeyBytes, newEncSubkey);

      await axios.post('/api/recovery/complete', {
        email,
        recoveryAuthSubkey: toBase64(recoveryAuthSubkey),
        newAuthSubkey: toBase64(newAuthSubkey),
        newKdfSalt: toBase64(newSalt),
        newKdfMemoryCost: DEFAULT_KDF_PARAMS.memoryCost,
        newKdfTimeCost: DEFAULT_KDF_PARAMS.timeCost,
        newKdfParallelism: DEFAULT_KDF_PARAMS.parallelism,
        newWrappedUserKeyPassword, newWrappedUserKeyPasswordIv,
      });
      return { success: true };
    } catch (error) {
      return { success: false, error: friendlyError(error, 'Wiederherstellung fehlgeschlagen') };
    }
  };

  const logout = useCallback(async () => {
    try {
      await axios.post('/api/logout');
    } catch (error) {
      console.error('Logout failed:', error);
    } finally {
      setUser(null);
      setUserKey(null);
      lockedKeyInfo.current = null;
      pendingLogin.current = null;
      setAuthStatus('unauthenticated');
      navigate('/login');
    }
  }, [navigate]);

  const value = {
    user,
    authStatus,
    isAuthenticated: authStatus === 'unlocked',
    loading: authStatus === 'checking',
    userKey,
    register,
    login,
    verifyTwoFactor,
    unlock,
    recoverAccount,
    logout,
  };

  if (authStatus === 'checking') {
    return null;
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
