# Windkey Password Manager

A zero-knowledge password manager for home/family use over your local network (LAN), built with Flask, React, and a Chrome extension. The server never sees your master password or your decrypted passwords - all encryption and decryption happens in your browser.

## Security architecture

- **Zero-knowledge**: Your master password is run through Argon2id in the browser to derive keys. Only a one-way derived value ever reaches the server (to verify login) - never the password itself, and never the key that encrypts your vault.
- **AES-256-GCM** encrypts every vault entry client-side before it's sent to the server. The server only ever stores/returns opaque ciphertext.
- **Recovery Key**: Since the server never has your password or vault key, a normal "reset password by email" is cryptographically impossible here. At registration you get a one-time **Recovery Key** - save it somewhere safe. It's the only way to change your master password later without losing your data. If you lose both your master password and your Recovery Key, your vault is unrecoverable by design.
- **2FA required**: Every account uses TOTP (Google Authenticator or compatible) in addition to the master password.
- **LAN-only**: The backend refuses any request whose source IP isn't in a private/loopback range, regardless of how it was reached. This app is meant for your home network, not the public internet.
- Rate limiting + account lockout, CSRF protection, security headers, and HTTPS (via a self-signed dev certificate) are all built in - see the [security review notes] section below for what this does and doesn't cover.

## Installation

### Prerequisites

- Python 3.11+
- Node.js 18+ and npm
- A Gmail account with an [App Password](https://myaccount.google.com/apppasswords) (optional - without it, verification emails are just printed to the backend console, which is fine for solo/testing use)

### 1. Generate a local HTTPS certificate

Browsers only expose the WebCrypto API (which the zero-knowledge encryption depends on) on `https://` or `http://localhost` - not on a plain LAN IP like `http://192.168.1.50`. So both the backend and frontend need to run over HTTPS, even without a public domain:

```bash
cd backend
pip install -r ../requirements.txt
python generate_dev_cert.py
```

This writes a self-signed certificate to `backend/certs/` covering `localhost` and your machine's detected LAN IP. Each family device will see a one-time "connection not private" browser warning on first visit - that's expected for a self-signed cert and safe to click through; it doesn't weaken the encryption.

### 2. Configure the backend

Copy/edit `backend/.env`:

```
SECRET_KEY=                      # leave blank to auto-generate on first run
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-specific-password   # a Gmail App Password, not your normal password
FRONTEND_URL=https://<your-lan-ip>:3000    # so emailed links work from any device
```

### 3. Start the backend

```bash
cd backend
python app.py
```

Runs on `https://0.0.0.0:5000` (reachable at `https://localhost:5000` and `https://<your-lan-ip>:5000`).

### 4. Start the frontend

```bash
cd frontend
npm install
npm start
```

`frontend/.env` already points it at the same self-signed certificate and serves over HTTPS on port 3000.

### 5. Chrome extension (optional)

1. Go to `chrome://extensions/`, enable "Developer mode"
2. "Load unpacked" → select the `chrome-extension` folder
3. Open the extension's options page and set your server's address (defaults to `https://localhost:5000`)

## Features

- Zero-knowledge encrypted password vault with categories
- TOTP 2FA (Google Authenticator compatible)
- Password generator with configurable rules
- Password strength + duplicate detection, HaveIBeenPwned breach check (k-anonymity, never sends your password anywhere)
- Activity history
- Responsive UI (desktop, tablet, mobile)
- Chrome extension with autofill

## Project structure

```
windkey/
├── backend/                # Flask API (zero-knowledge auth, never sees plaintext vault data)
│   ├── app.py              # App config, DB models, security middleware
│   ├── routes.py           # API endpoints
│   ├── mail.py             # Verification/recovery emails
│   └── generate_dev_cert.py
├── frontend/                # React app
│   └── src/
│       ├── crypto/windkeyCrypto.js   # Argon2id + AES-GCM + HKDF - the crypto core
│       ├── contexts/AuthContext.js   # Auth/session/vault-key state
│       └── components/
├── chrome-extension/         # MV3 extension, shares the crypto module with the frontend
└── requirements.txt
```

## Known limitations

- **Recovery Key loss = permanent data loss** if you also forget your master password. This is inherent to zero-knowledge encryption, not a missing feature.
- **Master password rules are enforced client-side only** - the server never sees the raw password, so it structurally cannot double-check it server-side.
- **Screenshot prevention is best-effort only.** Revealed passwords auto-hide when the tab loses focus, but no web page can block OS-level screenshots, a phone camera, or a compromised browser/extension.
- This is a hardened personal/family project, not an audited, compliance-certified product - don't store anything in it you wouldn't be comfortable losing if you misconfigure your home network.

## License

MIT - see [LICENSE](LICENSE).
