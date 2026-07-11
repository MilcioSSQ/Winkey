# Winkey — Zero-Knowledge Password Manager

A self-hosted, zero-knowledge password manager for your home network. Built with **Flask**, **React** (Material UI), and a **Chrome extension**. Your master password and vault data never leave your browser unencrypted — the server only ever stores opaque ciphertext.

> **Originally created by [Hood Informatik](https://github.com/hoodinformatik)** ([Windkey](https://github.com/hoodinformatik/Windkey)) — continued and finished by [MilcioSSQ](https://github.com/MilcioSSQ).

---

## Features

- **Zero-knowledge encryption** — Argon2id key derivation + AES-256-GCM, entirely client-side. The server never sees your master password or decrypted vault.
- **2FA (TOTP)** — Every account requires Google Authenticator (or compatible). QR code setup built in.
- **Password generator** — Configurable length, character sets, and rules.
- **Password health check** — Strength analysis for all stored passwords at a glance.
- **Breach scanner** — Checks your passwords against HaveIBeenPwned using k-anonymity (never sends your actual password anywhere).
- **Duplicate detection** — Flags reused passwords across entries.
- **Categories** — Organize passwords into custom groups.
- **Activity history** — Logs every vault action with timestamps and IP.
- **Recovery key** — One-time key generated at registration. The only way to change your master password without losing data. No "forgot password" email reset — by design.
- **Import / Export** — Move your data in and out.
- **Chrome extension** — Autofill credentials in the browser, connected to your self-hosted server.
- **Dark mode** — Full theme support.
- **Responsive UI** — Works on desktop, tablet, and mobile.
- **LAN-only** — The backend rejects any request from outside your local network. This is a home tool, not a cloud service.

## Security

| Layer | What it does |
| --- | --- |
| **Argon2id** | Derives your vault key from your master password in the browser (memory-hard, anti-brute-force). |
| **AES-256-GCM** | Encrypts every vault entry client-side before it hits the server. |
| **CSRF protection** | Flask-WTF synchronizer tokens on all state-changing requests. |
| **Rate limiting** | Flask-Limiter on login, register, and recovery endpoints. |
| **Account lockout** | 10 failed login attempts → 15 min lockout. |
| **HTTPS** | Self-signed dev certificate (generated locally) for WebCrypto API access on LAN IPs. |
| **Enumeration protection** | Pre-login and recovery responses are deterministic per email — no user-exists oracle. |

## Tech Stack

**Backend:** Python 3.11+, Flask, SQLAlchemy (SQLite), Flask-Login, Flask-Limiter, PyOTP, bcrypt

**Frontend:** React, Material UI, Axios, react-router-dom

**Crypto:** Argon2id + AES-256-GCM + HKDF (via noble-hashes, client-side)

**Chrome Extension:** Manifest V3, content scripts + popup + options page

## Project Structure

```
winkey/
├── backend/
│   ├── app.py                  # Flask app, DB models, LAN-only middleware
│   ├── routes.py               # API endpoints (auth, vault, recovery, history)
│   ├── mail.py                 # Verification & recovery emails
│   └── generate_dev_cert.py    # Self-signed HTTPS cert generator
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── Dashboard.js    # Main vault view (add/edit/delete/search)
│       │   ├── Login.js        # Login + 2FA
│       │   ├── Register.js     # Registration + TOTP setup
│       │   ├── Recovery.js     # Master password recovery via recovery key
│       │   ├── Stats.js        # Password health, duplicates, breach check
│       │   ├── Tools.js        # Generator, health check, breach scanner, import/export
│       │   ├── History.js      # Activity log
│       │   ├── Layout.js       # App shell / navigation
│       │   ├── Unlock.js       # Session unlock
│       │   └── VerifyEmail.js  # Email verification flow
│       ├── contexts/
│       │   ├── AuthContext.js   # Auth state, session, vault key
│       │   └── ThemeContext.js  # Dark/light mode
│       └── crypto/
│           └── windkeyCrypto.js # Argon2id + AES-GCM + HKDF — the crypto core
├── chrome-extension/           # MV3 extension with autofill
│   ├── manifest.json
│   ├── popup.html / popup.js   # Extension popup (quick access)
│   ├── options.html / options.js # Server URL configuration
│   ├── content.js / content.css # Autofill injection
│   ├── background.js           # Service worker
│   └── vendor/                 # Bundled noble-hashes for offline crypto
└── requirements.txt
```

## Installation

### Prerequisites

- Python 3.11+
- Node.js 18+ and npm
- A Gmail account with an [App Password](https://myaccount.google.com/apppasswords) (optional — without it, verification emails are printed to the console, which is fine for solo use)

### 1. Generate HTTPS certificate

Browsers require `https://` for the WebCrypto API on LAN IPs. Generate a self-signed cert:

```bash
cd backend
pip install -r ../requirements.txt
python generate_dev_cert.py
```

Family devices will see a one-time "connection not private" warning on first visit — expected and safe to click through.

### 2. Configure the backend

Edit `backend/.env`:

```
SECRET_KEY=                      # leave blank to auto-generate on first run
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-specific-password
FRONTEND_URL=https://<your-lan-ip>:3000
```

### 3. Start the backend

```bash
cd backend
python app.py
```

Runs on `https://0.0.0.0:5000`.

### 4. Start the frontend

```bash
cd frontend
npm install
npm start
```

Serves on `https://localhost:3000` (reachable from other devices via your LAN IP).

### 5. Chrome extension (optional)

1. `chrome://extensions/` → enable **Developer mode**
2. **Load unpacked** → select the `chrome-extension` folder
3. Open the extension's options and set your server address

## Known Limitations

- **Recovery key lost + master password forgotten = permanent data loss.** This is inherent to zero-knowledge encryption, not a bug.
- **Master password rules are client-side only** — the server structurally cannot verify them (it never sees the raw password).
- **Screenshot prevention is best-effort.** Revealed passwords auto-hide when the tab loses focus, but no web app can block OS-level screenshots.
- This is a hardened personal project, not an audited enterprise product.

## Credits

Originally created by **[Hood Informatik](https://github.com/hoodinformatik)** as [Windkey](https://github.com/hoodinformatik/Windkey). The initial version was built on stream — I ([MilcioSSQ](https://github.com/MilcioSSQ)) picked it up, finished the remaining features, and maintain this version.

## License

MIT — see [LICENSE](LICENSE).
