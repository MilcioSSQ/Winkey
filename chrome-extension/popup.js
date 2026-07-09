import {
  deriveMasterKey, deriveAuthSubkey, deriveEncSubkey,
  unwrapKey, toBase64, fromBase64, encryptJson, decryptJson,
} from './vendor/windkeyCrypto.js';

let API_URL = 'https://localhost:5000';
let csrfTokenCache = null;
let userKey = null; // Uint8Array, in-memory only for this popup session
let pendingLogin = null; // { encSubkey, temporaryToken } between login step 1 and 2FA
let vaultEntries = []; // decrypted {id, title, username, password, url, notes, category_id}

async function loadServerUrl() {
  const { serverUrl } = await chrome.storage.local.get('serverUrl');
  API_URL = serverUrl || 'https://localhost:5000';
}

async function apiFetch(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };

  if (['POST', 'PUT', 'DELETE'].includes(method)) {
    if (!csrfTokenCache) {
      const r = await fetch(`${API_URL}/api/csrf-token`, { credentials: 'include' });
      csrfTokenCache = (await r.json()).csrfToken;
    }
    headers['X-CSRFToken'] = csrfTokenCache;
  }

  const resp = await fetch(`${API_URL}${path}`, { ...options, headers, credentials: 'include' });
  const text = await resp.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = {}; }
  if (!resp.ok) {
    const err = new Error(data.error || `HTTP ${resp.status}`);
    err.status = resp.status;
    err.data = data;
    throw err;
  }
  return data;
}

document.addEventListener('DOMContentLoaded', async () => {
  await loadServerUrl();

  const loginForm = document.getElementById('login-form');
  const twofaForm = document.getElementById('twofa-form');
  const passwordList = document.getElementById('password-list');
  const addPasswordForm = document.getElementById('add-password-form');
  const searchInput = document.getElementById('search');
  const passwordsContainer = document.getElementById('passwords-container');
  const loginError = document.getElementById('login-error');
  const twofaError = document.getElementById('twofa-error');
  const fillBanner = document.getElementById('fill-this-page');
  const fillLabel = document.getElementById('fill-this-page-label');
  const fillBtn = document.getElementById('fill-this-page-btn');

  document.getElementById('login').addEventListener('submit', handleLogin);
  document.getElementById('twofa').addEventListener('submit', handle2FASubmit);
  document.getElementById('add-password').addEventListener('click', showAddPasswordForm);
  document.getElementById('new-password').addEventListener('submit', handleAddPassword);
  document.getElementById('cancel-add').addEventListener('click', showPasswordList);
  document.getElementById('sync').addEventListener('click', syncPasswords);
  document.getElementById('logout').addEventListener('click', handleLogout);
  document.getElementById('generate-password').addEventListener('click', generatePassword);
  document.getElementById('toggle-password').addEventListener('click', togglePasswordVisibility);
  searchInput.addEventListener('input', handleSearch);

  const codeInput = document.getElementById('2fa-code');
  codeInput.addEventListener('input', (e) => {
    e.target.value = e.target.value.replace(/[^0-9]/g, '').slice(0, 6);
  });

  function showLoginForm() {
    loginForm.style.display = 'block';
    twofaForm.style.display = 'none';
    passwordList.style.display = 'none';
    addPasswordForm.style.display = 'none';
  }
  function show2FAForm() {
    loginForm.style.display = 'none';
    twofaForm.style.display = 'block';
    passwordList.style.display = 'none';
    addPasswordForm.style.display = 'none';
    codeInput.focus();
  }
  function showPasswordList() {
    loginForm.style.display = 'none';
    twofaForm.style.display = 'none';
    passwordList.style.display = 'block';
    addPasswordForm.style.display = 'none';
  }
  function showAddPasswordForm() {
    loginForm.style.display = 'none';
    twofaForm.style.display = 'none';
    passwordList.style.display = 'none';
    addPasswordForm.style.display = 'block';
  }

  async function checkExistingSession() {
    try {
      const { userKeyB64 } = await chrome.storage.session.get('userKeyB64');
      if (!userKeyB64) {
        showLoginForm();
        return;
      }
      await apiFetch('/api/check-auth');
      userKey = fromBase64(userKeyB64);
      showPasswordList();
      await syncPasswords();
      await checkFillableForCurrentTab();
    } catch {
      await chrome.storage.session.remove('userKeyB64');
      showLoginForm();
    }
  }

  async function handleLogin(e) {
    e.preventDefault();
    loginError.textContent = '';
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const button = e.target.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const pre = await apiFetch(`/api/prelogin?email=${encodeURIComponent(email)}`);
      const salt = fromBase64(pre.salt);
      const masterKey = await deriveMasterKey(password, salt, {
        memoryCost: pre.kdfMemoryCost, timeCost: pre.kdfTimeCost, parallelism: pre.kdfParallelism,
      });
      const authSubkey = await deriveAuthSubkey(masterKey);
      const encSubkey = await deriveEncSubkey(masterKey);

      const loginResp = await apiFetch('/api/login', {
        method: 'POST',
        body: JSON.stringify({ email, authSubkey: toBase64(authSubkey) }),
      });
      pendingLogin = { encSubkey, temporaryToken: loginResp.temporaryToken };
      show2FAForm();
    } catch (err) {
      loginError.textContent = err.data?.error || 'Anmeldung fehlgeschlagen';
    } finally {
      button.disabled = false;
    }
  }

  async function handle2FASubmit(e) {
    e.preventDefault();
    twofaError.textContent = '';
    if (!pendingLogin) {
      twofaError.textContent = 'Sitzung abgelaufen, bitte erneut anmelden';
      showLoginForm();
      return;
    }
    const code = codeInput.value;
    const button = e.target.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const resp = await apiFetch('/api/verify-2fa', {
        method: 'POST',
        body: JSON.stringify({ temporaryToken: pendingLogin.temporaryToken, code }),
      });
      userKey = await unwrapKey(resp.wrappedUserKeyPassword, resp.wrappedUserKeyPasswordIv, pendingLogin.encSubkey);
      await chrome.storage.session.set({ userKeyB64: toBase64(userKey) });
      pendingLogin = null;
      showPasswordList();
      await syncPasswords();
      await checkFillableForCurrentTab();
    } catch (err) {
      twofaError.textContent = err.data?.error || 'Ungültiger 2FA-Code';
    } finally {
      button.disabled = false;
    }
  }

  async function handleLogout() {
    try { await apiFetch('/api/logout', { method: 'POST' }); } catch { /* ignore */ }
    await chrome.storage.session.remove('userKeyB64');
    userKey = null;
    vaultEntries = [];
    csrfTokenCache = null;
    showLoginForm();
  }

  async function syncPasswords() {
    try {
      const rows = await apiFetch('/api/passwords');
      vaultEntries = await Promise.all(rows.map(async (row) => {
        const entry = await decryptJson(userKey, row.encrypted_data, row.data_iv);
        return { ...entry, id: row.id, category_id: row.category_id };
      }));
      displayPasswords(vaultEntries);
    } catch (err) {
      alert('Synchronisation fehlgeschlagen.');
    }
  }

  function displayPasswords(entries) {
    passwordsContainer.replaceChildren();
    for (const entry of entries) {
      const item = document.createElement('div');
      item.className = 'password-item';

      const h3 = document.createElement('h3');
      h3.textContent = entry.title;
      item.appendChild(h3);

      if (entry.url) {
        const urlP = document.createElement('p');
        urlP.className = 'url';
        urlP.textContent = entry.url;
        item.appendChild(urlP);
      }

      const userP = document.createElement('p');
      userP.className = 'username';
      userP.textContent = `Benutzername: ${entry.username || '-'}`;
      item.appendChild(userP);

      const buttonsDiv = document.createElement('div');
      buttonsDiv.className = 'copy-buttons';

      const userBtn = document.createElement('button');
      userBtn.className = 'copy-button';
      userBtn.textContent = 'Benutzername kopieren';
      userBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        copyToClipboard(entry.username, 'Benutzername');
      });

      const passBtn = document.createElement('button');
      passBtn.className = 'copy-button';
      passBtn.textContent = 'Passwort kopieren';
      passBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        copyToClipboard(entry.password, 'Passwort');
      });

      buttonsDiv.appendChild(userBtn);
      buttonsDiv.appendChild(passBtn);
      item.appendChild(buttonsDiv);
      passwordsContainer.appendChild(item);
    }
  }

  async function copyToClipboard(text, label) {
    try {
      await navigator.clipboard.writeText(text || '');
      showCopyFeedback(`${label} kopiert!`);
    } catch {
      showCopyFeedback('Fehler beim Kopieren', true);
    }
  }

  let feedbackTimeout;
  function showCopyFeedback(message, isError = false) {
    const feedback = document.getElementById('copy-feedback');
    feedback.textContent = message;
    feedback.style.background = isError ? 'var(--error-color)' : 'var(--success-color)';
    if (feedbackTimeout) { clearTimeout(feedbackTimeout); feedback.classList.remove('show', 'hide'); }
    feedback.classList.add('show');
    feedbackTimeout = setTimeout(() => {
      feedback.classList.remove('show');
      feedback.classList.add('hide');
      setTimeout(() => feedback.classList.remove('hide'), 300);
    }, 2000);
  }

  async function handleAddPassword(e) {
    e.preventDefault();
    const entry = {
      title: document.getElementById('title').value,
      username: document.getElementById('username').value,
      password: document.getElementById('new-pass').value,
      url: document.getElementById('website').value,
      notes: document.getElementById('notes').value,
    };
    try {
      const { data, iv } = await encryptJson(userKey, entry);
      await apiFetch('/api/passwords', {
        method: 'POST',
        body: JSON.stringify({ encrypted_data: data, data_iv: iv }),
      });
      e.target.reset();
      showPasswordList();
      await syncPasswords();
    } catch (err) {
      alert('Fehler beim Speichern des Passworts.');
    }
  }

  function handleSearch(e) {
    const query = e.target.value.toLowerCase();
    const filtered = vaultEntries.filter((p) =>
      p.title.toLowerCase().includes(query) ||
      p.url?.toLowerCase().includes(query) ||
      p.username?.toLowerCase().includes(query)
    );
    displayPasswords(filtered);
  }

  async function generatePassword() {
    try {
      const data = await apiFetch('/api/generate-password?length=16');
      document.getElementById('new-pass').value = data.password;
    } catch {
      // Fall back to a client-side generator if the API is unreachable.
      const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+';
      let pw = '';
      for (let i = 0; i < 16; i++) pw += charset.charAt(Math.floor(Math.random() * charset.length));
      document.getElementById('new-pass').value = pw;
    }
  }

  function togglePasswordVisibility() {
    const passwordInput = document.getElementById('new-pass');
    passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
  }

  async function checkFillableForCurrentTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) return;
      const hostname = new URL(tab.url).hostname;
      const match = vaultEntries.find((p) => {
        if (!p.url) return false;
        try { return new URL(p.url).hostname === hostname; } catch { return false; }
      });
      if (match) {
        fillLabel.textContent = `Zugangsdaten für ${hostname} gefunden`;
        fillBanner.style.display = 'flex';
        fillBtn.onclick = () => {
          chrome.tabs.sendMessage(tab.id, {
            action: 'fillCredentials', username: match.username, password: match.password,
          });
        };
      } else {
        fillBanner.style.display = 'none';
      }
    } catch {
      fillBanner.style.display = 'none';
    }
  }

  checkExistingSession();
});
