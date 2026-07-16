import hashlib
import ipaddress
import os
import re
import secrets
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

SECRET_KEY_FILE = 'secret.key'

        
def get_or_create_secret_key():
    env_key = os.environ.get('SECRET_KEY')
    if env_key and env_key != 'your-super-secret-key-change-this-in-production':
        return env_key
    # No usable secret configured - persist a generated one locally instead of
    # falling back to a hardcoded value that would be identical for every install.
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(key)
    return key


app = Flask(__name__)
app.config['SECRET_KEY'] = get_or_create_secret_key()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///windkey.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true'
# Flask-WTF's CSRFProtect additionally checks the Referer header on HTTPS
# requests by default, comparing its origin to request.host. That check
# assumes a same-origin form-based app; here the frontend (port 3000) and
# API (port 5000) are deliberately different origins, so it would always
# fail even for legitimate requests. The synchronizer token (X-CSRFToken)
# plus our CORS allowlist + SameSite cookies remain the actual protection.
app.config['WTF_CSRF_SSL_STRICT'] = False

# HMAC pepper for enumeration-safe dummy responses (prelogin / recovery-start).
# Derived from SECRET_KEY rather than managed as a separate secret file - a
# distinct label keeps it out of the session-signing keyspace.
ENUMERATION_PEPPER = hashlib.sha256((app.config['SECRET_KEY'] + ':enumeration-pepper').encode()).digest()

limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

# ---- LAN-only access control ----
# This app is meant to be reachable only from the home network. Binding to
# 0.0.0.0 is what lets other family devices reach it - but that's also
# exactly what a router misconfiguration (accidental port-forward) would
# expose to the internet. This guard is a real enforcement layer, not just
# documentation: any request whose source IP isn't in a private/loopback
# range gets rejected regardless of how it reached the process.
#
# This trusts request.remote_addr directly, which is only correct because
# there is no reverse proxy in front of Flask in this deployment. If one is
# ever added, this must be paired with a trusted ProxyFix configuration or
# it becomes spoofable via X-Forwarded-For.
PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]


@app.before_request
def enforce_private_network():
    if request.method == 'OPTIONS':
        return None
    try:
        addr = ipaddress.ip_address(request.remote_addr)
    except (ValueError, TypeError):
        return jsonify({'error': 'Forbidden'}), 403
    if not any(addr in net for net in PRIVATE_NETWORKS):
        return jsonify({'error': 'Forbidden - LAN access only'}), 403
    return None


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
    )
    response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
    # No public domain/CA on a home LAN, so HSTS is opt-in only - forcing it
    # prematurely on a self-signed/plain-HTTP host can lock out browsers.
    if os.environ.get('FORCE_HSTS', 'false').lower() == 'true':
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
    return response


# CORS - restricted to LAN-reachable frontend origins + the extension.
LAN_ORIGIN_RE = re.compile(
    r'^https?://('
    r'localhost|127\.0\.0\.1|'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r')(:\d+)?$'
)
_extra_origins = [o.strip() for o in os.environ.get('EXTRA_CORS_ORIGINS', '').split(',') if o.strip()]

CORS(app, supports_credentials=True, resources={
    r"/api/*": {
        "origins": [LAN_ORIGIN_RE, "chrome-extension://*"] + _extra_origins,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-CSRFToken"],
        "expose_headers": ["Content-Range", "X-Content-Range"],
        "supports_credentials": True
    }
})

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    history = db.relationship('History', backref='user', lazy=True)
    categories = db.relationship('Category', backref='user', lazy=True)

    # ---- zero-knowledge auth (password_hash holds bcrypt(base64(authSubkey)),
    # never the raw master password - the server never sees the raw password) ----
    password_hash = db.Column(db.String(128))
    kdf_salt = db.Column(db.LargeBinary, nullable=False)
    kdf_memory_cost = db.Column(db.Integer, nullable=False)
    kdf_time_cost = db.Column(db.Integer, nullable=False)
    kdf_parallelism = db.Column(db.Integer, nullable=False)
    kdf_version = db.Column(db.Integer, nullable=False, default=1)

    # userKey (the actual vault encryption key), dual-wrapped
    wrapped_user_key_password = db.Column(db.LargeBinary, nullable=False)
    wrapped_user_key_password_iv = db.Column(db.LargeBinary, nullable=False)
    wrapped_user_key_recovery = db.Column(db.LargeBinary, nullable=False)
    wrapped_user_key_recovery_iv = db.Column(db.LargeBinary, nullable=False)
    recovery_kdf_salt = db.Column(db.LargeBinary, nullable=False)
    recovery_auth_subkey_hash = db.Column(db.String(128), nullable=False)
    recovery_key_created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 2FA (Google Authenticator-compatible TOTP) - an auth factor, not vault
    # data; storing it server-side is normal and doesn't violate zero-knowledge.
    two_factor_secret = db.Column(db.String(32))

    # Email verification
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    email_verification_token_hash = db.Column(db.String(128))
    email_verification_expires_at = db.Column(db.DateTime)

    # Brute-force lockout (in addition to IP-based rate limiting)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime)

    def set_auth_subkey(self, auth_subkey_b64):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(auth_subkey_b64)

    def check_auth_subkey(self, auth_subkey_b64):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, auth_subkey_b64)

    def set_recovery_auth_subkey(self, recovery_auth_subkey_b64):
        from werkzeug.security import generate_password_hash
        self.recovery_auth_subkey_hash = generate_password_hash(recovery_auth_subkey_b64)

    def check_recovery_auth_subkey(self, recovery_auth_subkey_b64):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.recovery_auth_subkey_hash, recovery_auth_subkey_b64)

    def generate_2fa_secret(self):
        import pyotp
        self.two_factor_secret = pyotp.random_base32()

    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_name = db.Column(db.LargeBinary, nullable=False)
    name_iv = db.Column(db.LargeBinary, nullable=False)
    icon = db.Column(db.String(50))  # Material-UI icon name - not identifying, kept in clear
    color = db.Column(db.String(50))  # hex color - not identifying, kept in clear
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    passwords = db.relationship('Password', backref='category', lazy=True)

    def to_dict(self):
        import base64
        return {
            'id': self.id,
            'encrypted_name': base64.b64encode(self.encrypted_name).decode(),
            'name_iv': base64.b64encode(self.name_iv).decode(),
            'icon': self.icon,
            'color': self.color,
            'password_count': len(self.passwords)
        }


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    # One AES-GCM blob per row, containing {title, username, password, url,
    # notes} - encrypted client-side with the vault's userKey. The server
    # never decrypts this and never sees the plaintext.
    encrypted_data = db.Column(db.LargeBinary, nullable=False)
    data_iv = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        import base64
        return {
            'id': self.id,
            'encrypted_data': base64.b64encode(self.encrypted_data).decode(),
            'data_iv': base64.b64encode(self.data_iv).decode(),
            'category_id': self.category_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    # Deliberately non-identifying - no titles/URLs/emails-of-other-accounts.
    # Vault metadata must not leak into a server-visible log.
    details = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat()
        }


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()
    print("Database initialized")

from routes import *  # noqa: E402,F401,F403

if __name__ == '__main__':
    app.debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    cert_file = os.path.join(os.path.dirname(__file__), 'certs', 'dev-cert.pem')
    key_file = os.path.join(os.path.dirname(__file__), 'certs', 'dev-key.pem')
    ssl_context = (cert_file, key_file) if os.path.exists(cert_file) and os.path.exists(key_file) else None
    if ssl_context is None:
        print("No TLS cert found at backend/certs/ - run `python generate_dev_cert.py` first.")
        print("WebCrypto (crypto.subtle) will not work from any LAN IP without HTTPS.")
    app.run(host='0.0.0.0', port=5000, ssl_context=ssl_context)
