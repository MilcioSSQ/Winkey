/**
 * Windkey's zero-knowledge crypto core.
 *
 * KEEP THIS FILE BYTE-IDENTICAL to chrome-extension/vendor/windkeyCrypto.js
 * (copy, don't hand-reimplement) - the React app and the extension both
 * derive the same keys from the same master password independently, and a
 * silent divergence here fails as an opaque "decryption failed" with no
 * useful error message.
 *
 * Key hierarchy (Bitwarden-style dual key-wrap):
 *   masterKey  = Argon2id(masterPassword, kdfSalt, params)
 *   authSubkey = HKDF-Expand(masterKey, info="windkey-auth-v1")  -> sent to
 *                the server (further hashed there with bcrypt) to prove
 *                knowledge of the password. The server never learns
 *                masterKey or encSubkey from this value (HKDF, one-way).
 *   encSubkey  = HKDF-Expand(masterKey, info="windkey-enc-v1")   -> stays
 *                on the client, used only to unwrap userKey.
 *   userKey    = random AES-256 key, generated once at registration. This
 *                is what actually encrypts vault data. It never changes
 *                when the master password changes - only its wrapping does.
 *   wrappedUserKeyPassword = AES-GCM(userKey, key=encSubkey)  -> server-side
 *   wrappedUserKeyRecovery = AES-GCM(userKey, key=recoveryWrappingKey) -> server-side
 *
 * The server only ever stores/returns opaque ciphertext + IV pairs. It
 * never sees a master password, userKey, or vault plaintext.
 */

import { argon2idAsync } from './noble-hashes/argon2.js';

const ENC = new TextEncoder();
const DEC = new TextDecoder();

export const KDF_VERSION_ARGON2ID_V1 = 1;

// OWASP-minimum-ish Argon2id parameters, tuned for a ~0.5-1.5s login on
// typical family hardware since this runs in pure JS (no WASM/native speed).
// memoryCost is in KiB.
export const DEFAULT_KDF_PARAMS = { memoryCost: 19456, timeCost: 2, parallelism: 1 };

// ---- encoding helpers ----

export function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function fromBase64(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * SHA-1 of a password for the HaveIBeenPwned k-anonymity breach check only -
 * SHA-1 is not used anywhere for actual security/authentication in this app.
 * Only the 5-char prefix of the result is ever sent to the server, exactly
 * like HIBP's own client-side integration guidance; the full password never
 * leaves the browser.
 */
export async function sha1Hex(text) {
  const digest = await crypto.subtle.digest('SHA-1', ENC.encode(text));
  return toHex(new Uint8Array(digest)).toUpperCase();
}

// ---- key derivation ----

/** Argon2id-derive the 32-byte masterKey from the user's master password. */
export async function deriveMasterKey(password, saltBytes, params = DEFAULT_KDF_PARAMS) {
  return argon2idAsync(ENC.encode(password), saltBytes, {
    t: params.timeCost,
    m: params.memoryCost,
    p: params.parallelism,
    dkLen: 32,
  });
}

async function hkdfExpand(ikmBytes, saltBytes, infoLabel, lengthBytes = 32) {
  const key = await crypto.subtle.importKey('raw', ikmBytes, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: ENC.encode(infoLabel) },
    key,
    lengthBytes * 8
  );
  return new Uint8Array(bits);
}

/** Domain-separated subkey used only to prove password knowledge to the server. */
export async function deriveAuthSubkey(masterKeyBytes) {
  return hkdfExpand(masterKeyBytes, new Uint8Array(0), 'windkey-auth-v1');
}

/** Domain-separated subkey used only client-side to unwrap userKey. Never sent anywhere. */
export async function deriveEncSubkey(masterKeyBytes) {
  return hkdfExpand(masterKeyBytes, new Uint8Array(0), 'windkey-enc-v1');
}

/**
 * Recovery Key wrapping key. The Recovery Key is already ~160 bits of
 * CSPRNG entropy (no human password to stretch), so this intentionally
 * skips Argon2id and uses a fast HKDF instead - correct given no
 * low-entropy secret needs memory-hard stretching here.
 */
export async function deriveRecoveryWrappingKey(recoveryKeyBytes, saltBytes) {
  return hkdfExpand(recoveryKeyBytes, saltBytes, 'windkey-recovery-v1');
}

/**
 * Domain-separated proof-of-possession subkey for the Recovery Key,
 * analogous to authSubkey for the master password. The server bcrypt-hashes
 * this at registration and requires it again during account recovery -
 * without it, anyone who merely knows a user's email could trigger a
 * password reset without ever having the Recovery Key.
 */
export async function deriveRecoveryAuthSubkey(recoveryKeyBytes, saltBytes) {
  return hkdfExpand(recoveryKeyBytes, saltBytes, 'windkey-recovery-auth-v1');
}

// ---- AES-256-GCM ----

async function importAesKey(rawKeyBytes) {
  return crypto.subtle.importKey('raw', rawKeyBytes, 'AES-GCM', true, ['encrypt', 'decrypt']);
}

/** Generates a fresh random AES-256 key (used for userKey). */
export async function generateAesKey() {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const raw = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(raw);
}

/** Encrypts raw bytes under a raw AES-256 key with a fresh random 12-byte IV. */
export async function aesGcmEncrypt(rawKeyBytes, plaintextBytes) {
  const key = await importAesKey(rawKeyBytes);
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintextBytes);
  return { ciphertext: new Uint8Array(ciphertext), iv };
}

export async function aesGcmDecrypt(rawKeyBytes, ciphertextBytes, ivBytes) {
  const key = await importAesKey(rawKeyBytes);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, ciphertextBytes);
  return new Uint8Array(plaintext);
}

/** Convenience: encrypt a JS object to {data, iv} base64 strings (vault entries, category names). */
export async function encryptJson(rawKeyBytes, obj) {
  const { ciphertext, iv } = await aesGcmEncrypt(rawKeyBytes, ENC.encode(JSON.stringify(obj)));
  return { data: toBase64(ciphertext), iv: toBase64(iv) };
}

export async function decryptJson(rawKeyBytes, dataB64, ivB64) {
  const plaintext = await aesGcmDecrypt(rawKeyBytes, fromBase64(dataB64), fromBase64(ivB64));
  return JSON.parse(DEC.decode(plaintext));
}

// ---- key wrapping (userKey <-> password / recovery key) ----

export async function wrapKey(rawKeyToWrap, wrappingKeyBytes) {
  const { ciphertext, iv } = await aesGcmEncrypt(wrappingKeyBytes, rawKeyToWrap);
  return { wrapped: toBase64(ciphertext), iv: toBase64(iv) };
}

export async function unwrapKey(wrappedB64, ivB64, wrappingKeyBytes) {
  return aesGcmDecrypt(wrappingKeyBytes, fromBase64(wrappedB64), fromBase64(ivB64));
}

// ---- Recovery Key generation (human-facing) ----

/** Generates a 20-byte (160-bit) Recovery Key, formatted as dash-grouped hex for display. */
export function generateRecoveryKey() {
  const bytes = randomBytes(20);
  return { bytes, formatted: formatRecoveryKey(bytes) };
}

export function formatRecoveryKey(bytes) {
  return toHex(bytes).toUpperCase().match(/.{1,4}/g).join('-');
}

export function parseRecoveryKey(formatted) {
  const hex = formatted.replace(/[^0-9A-Fa-f]/g, '');
  return fromHex(hex);
}

// ---- fixed self-test vector (run before wiring any UI to this module) ----

/**
 * Verifies this crypto module produces the expected output for a fixed
 * password/salt/params. Run in both the frontend and extension contexts to
 * confirm they haven't silently drifted apart. Throws on any mismatch.
 */
export async function selfTest() {
  const password = 'windkey-self-test-vector';
  const salt = fromHex('000102030405060708090a0b0c0d0e0f');
  const params = { memoryCost: 1024, timeCost: 1, parallelism: 1 }; // fast, test-only params
  const masterKey = await deriveMasterKey(password, salt, params);
  const authSubkey = await deriveAuthSubkey(masterKey);
  const encSubkey = await deriveEncSubkey(masterKey);

  const expected = {
    masterKey: 'd3b2a4b335755fed54734cbff013da4b5fd3bf156896603ba88b0fe3aa2194c3',
    authSubkey: '6a62cb85683179ac5cd0ce298c4937109f00abfc9c04f9b237e5dde325ec347b',
    encSubkey: '27065318e258c06d4b4a37ee8385df79af4524084c244172197217468bc90eb5',
  };

  const actual = {
    masterKey: toHex(masterKey),
    authSubkey: toHex(authSubkey),
    encSubkey: toHex(encSubkey),
  };

  for (const k of Object.keys(expected)) {
    if (actual[k] !== expected[k]) {
      throw new Error(
        `windkeyCrypto.selfTest() FAILED on "${k}": expected ${expected[k]}, got ${actual[k]}. ` +
        `This module has drifted from its known-good test vector.`
      );
    }
  }
  return true;
}
