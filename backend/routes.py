import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

import pyotp
import qrcode
import requests
from flask import jsonify, request, session
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from io import BytesIO

from app import ENUMERATION_PEPPER, Category, History, Password, User, app, db, limiter
from mail import send_recovery_notification_email, send_verification_email

csrf = CSRFProtect(app)

DEFAULT_KDF_MEMORY_COST = 19456
DEFAULT_KDF_TIME_COST = 2
DEFAULT_KDF_PARALLELISM = 1

MAX_FAILED_LOGIN_ATTEMPTS = 10
LOCKOUT_DURATION = timedelta(minutes=15)
EMAIL_VERIFICATION_TTL = timedelta(hours=24)


def b64d(s):
    return base64.b64decode(s)


def b64e(b):
    return base64.b64encode(b).decode()


def normalize_email(email):
    return email.strip().lower()


# Login/register/recovery establish a session as a side effect but don't rely
# on an *existing* authenticated session to do anything destructive, so the
# classic CSRF threat model (a malicious page riding a victim's cookies to
# perform an action on their behalf) doesn't apply the same way here. Each is
# explicitly exempted via csrf.exempt() right after its view is defined below.
# All state-changing vault/account operations that DO run against an
# existing session are left CSRF-protected (the default).


def log_user_action(action, details=None):
    try:
        history_entry = History(
            user_id=current_user.id,
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(history_entry)
        db.session.commit()
    except Exception as e:
        print(f"Failed to log action: {str(e)}")
        db.session.rollback()


def deterministic_dummy_bytes(email, label, length):
    """Derives fixed, reproducible-per-email pseudo-random bytes so unknown
    emails get a plausible-looking (but meaningless) response of the right
    shape - the same every time, so no enumeration oracle exists via response
    differences between calls."""
    out = b''
    counter = 0
    while len(out) < length:
        out += hmac.new(
            ENUMERATION_PEPPER, f'{label}:{email}:{counter}'.encode(), hashlib.sha256
        ).digest()
        counter += 1
    return out[:length]


@app.route('/api/prelogin', methods=['GET'])
@limiter.limit("20 per minute")
def prelogin():
    email = normalize_email(request.args.get('email', ''))
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({
            'salt': b64e(user.kdf_salt),
            'kdfMemoryCost': user.kdf_memory_cost,
            'kdfTimeCost': user.kdf_time_cost,
            'kdfParallelism': user.kdf_parallelism,
            'kdfVersion': user.kdf_version,
        })

    dummy_salt = deterministic_dummy_bytes(email, 'prelogin-salt', 16)
    return jsonify({
        'salt': b64e(dummy_salt),
        'kdfMemoryCost': DEFAULT_KDF_MEMORY_COST,
        'kdfTimeCost': DEFAULT_KDF_TIME_COST,
        'kdfParallelism': DEFAULT_KDF_PARALLELISM,
        'kdfVersion': 1,
    })


csrf.exempt(prelogin)


@app.route('/api/register', methods=['POST', 'OPTIONS'])
@limiter.limit("10 per hour", methods=['POST'])
def register():
    if request.method == 'OPTIONS':
        return '', 200

    data = request.get_json()
    required = [
        'email', 'authSubkey', 'kdfSalt', 'kdfMemoryCost', 'kdfTimeCost', 'kdfParallelism',
        'wrappedUserKeyPassword', 'wrappedUserKeyPasswordIv',
        'wrappedUserKeyRecovery', 'wrappedUserKeyRecoveryIv',
        'recoveryKdfSalt', 'recoveryAuthSubkey',
    ]
    if not data or any(k not in data for k in required):
        return jsonify({'error': 'Missing required registration fields'}), 400

    email = normalize_email(data['email'])
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400

    try:
        user = User(
            email=email,
            kdf_salt=b64d(data['kdfSalt']),
            kdf_memory_cost=int(data['kdfMemoryCost']),
            kdf_time_cost=int(data['kdfTimeCost']),
            kdf_parallelism=int(data['kdfParallelism']),
            kdf_version=int(data.get('kdfVersion', 1)),
            wrapped_user_key_password=b64d(data['wrappedUserKeyPassword']),
            wrapped_user_key_password_iv=b64d(data['wrappedUserKeyPasswordIv']),
            wrapped_user_key_recovery=b64d(data['wrappedUserKeyRecovery']),
            wrapped_user_key_recovery_iv=b64d(data['wrappedUserKeyRecoveryIv']),
            recovery_kdf_salt=b64d(data['recoveryKdfSalt']),
        )
        user.set_auth_subkey(data['authSubkey'])
        user.set_recovery_auth_subkey(data['recoveryAuthSubkey'])
        user.generate_2fa_secret()

        totp = pyotp.TOTP(user.two_factor_secret)
        provisioning_uri = totp.provisioning_uri(user.email, issuer_name='Windkey')
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img_buffer = BytesIO()
        qr.make_image(fill_color="black", back_color="white").save(img_buffer, format='PNG')
        img_buffer.seek(0)
        img_str = base64.b64encode(img_buffer.getvalue()).decode()

        raw_token = secrets.token_urlsafe(32)
        user.email_verification_token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        user.email_verification_expires_at = datetime.utcnow() + EMAIL_VERIFICATION_TTL

        db.session.add(user)
        db.session.commit()

        email_sent = send_verification_email(user.email, raw_token)

        return jsonify({
            'message': 'Registration successful',
            'two_factor_secret': user.two_factor_secret,
            'qr_code': f'data:image/png;base64,{img_str}',
            'email_sent': email_sent,
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500


csrf.exempt(register)


@app.route('/api/verify-email', methods=['GET'])
@limiter.limit("20 per minute")
def verify_email():
    token = request.args.get('token', '')
    if not token:
        return jsonify({'error': 'Missing token'}), 400

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    user = User.query.filter_by(email_verification_token_hash=token_hash).first()
    if not user or not user.email_verification_expires_at or user.email_verification_expires_at < datetime.utcnow():
        return jsonify({'error': 'Invalid or expired verification link'}), 400

    user.email_verified = True
    user.email_verification_token_hash = None
    user.email_verification_expires_at = None
    db.session.commit()
    return jsonify({'message': 'Email verified successfully'})


csrf.exempt(verify_email)


@app.route('/api/resend-verification', methods=['POST'])
@limiter.limit("5 per hour")
def resend_verification():
    data = request.get_json() or {}
    email = normalize_email(data.get('email', ''))
    user = User.query.filter_by(email=email).first()
    if user and not user.email_verified:
        raw_token = secrets.token_urlsafe(32)
        user.email_verification_token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        user.email_verification_expires_at = datetime.utcnow() + EMAIL_VERIFICATION_TTL
        db.session.commit()
        send_verification_email(user.email, raw_token)
    # Same response whether the account exists or is already verified - avoids
    # leaking which emails are registered.
    return jsonify({'message': 'If that account exists and is unverified, a new email was sent.'})


csrf.exempt(resend_verification)


@app.route('/api/login', methods=['POST', 'OPTIONS'])
@limiter.limit("10 per minute", methods=['POST'])
def login():
    if request.method == 'OPTIONS':
        return '', 200

    data = request.get_json()
    if not data or 'email' not in data or 'authSubkey' not in data:
        return jsonify({'error': 'Email and authSubkey are required'}), 400

    email = normalize_email(data['email'])
    user = User.query.filter_by(email=email).first()

    generic_error = jsonify({'error': 'Invalid credentials'}), 401

    if not user:
        return generic_error

    if user.locked_until and user.locked_until > datetime.utcnow():
        return jsonify({'error': 'Account temporarily locked due to repeated failed attempts. Try again later.'}), 423

    if not user.check_auth_subkey(data['authSubkey']):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            user.locked_until = datetime.utcnow() + LOCKOUT_DURATION
        db.session.commit()
        return generic_error

    if not user.email_verified:
        return jsonify({'error': 'Email not verified', 'emailVerified': False}), 403

    user.failed_login_attempts = 0
    db.session.commit()

    temp_token = secrets.token_urlsafe(32)
    session['temp_token'] = temp_token
    session['temp_user_id'] = user.id
    session['remember_me'] = bool(data.get('rememberMe'))
    return jsonify({'requires2FA': True, 'temporaryToken': temp_token}), 200


csrf.exempt(login)


@app.route('/api/verify-2fa', methods=['POST', 'OPTIONS'])
@limiter.limit("10 per minute", methods=['POST'])
def verify_2fa():
    if request.method == 'OPTIONS':
        return '', 200

    data = request.get_json()
    if not data or 'temporaryToken' not in data or data['temporaryToken'] != session.get('temp_token'):
        return jsonify({'error': 'Invalid session'}), 401

    user_id = session.get('temp_user_id')
    if not user_id:
        return jsonify({'error': 'Invalid session'}), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 401

    totp = pyotp.TOTP(user.two_factor_secret)
    if not totp.verify(data.get('code', ''), valid_window=1):
        return jsonify({'error': 'Invalid 2FA code'}), 401

    remember_me = session.get('remember_me', False)
    session.pop('temp_token', None)
    session.pop('temp_user_id', None)
    session.pop('remember_me', None)

    token = secrets.token_urlsafe(32)
    session['user_id'] = user.id
    session['token'] = token
    if remember_me:
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=30)
    else:
        session.permanent = False

    login_user(user)
    log_user_action('login')

    # Only now, after 2FA has fully succeeded, hand back the wrapped vault
    # key - never before both factors are verified.
    return jsonify({
        'token': token,
        'user': {'id': user.id, 'email': user.email},
        'wrappedUserKeyPassword': b64e(user.wrapped_user_key_password),
        'wrappedUserKeyPasswordIv': b64e(user.wrapped_user_key_password_iv),
        'kdfSalt': b64e(user.kdf_salt),
        'kdfMemoryCost': user.kdf_memory_cost,
        'kdfTimeCost': user.kdf_time_cost,
        'kdfParallelism': user.kdf_parallelism,
        'kdfVersion': user.kdf_version,
    }), 200


csrf.exempt(verify_2fa)


@app.route('/api/recovery/start', methods=['POST'])
@limiter.limit("10 per hour")
def recovery_start():
    data = request.get_json() or {}
    email = normalize_email(data.get('email', ''))
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({
            'recoveryKdfSalt': b64e(user.recovery_kdf_salt),
            'wrappedUserKeyRecovery': b64e(user.wrapped_user_key_recovery),
            'wrappedUserKeyRecoveryIv': b64e(user.wrapped_user_key_recovery_iv),
        })

    return jsonify({
        'recoveryKdfSalt': b64e(deterministic_dummy_bytes(email, 'recovery-salt', 16)),
        'wrappedUserKeyRecovery': b64e(deterministic_dummy_bytes(email, 'recovery-wrapped', 48)),
        'wrappedUserKeyRecoveryIv': b64e(deterministic_dummy_bytes(email, 'recovery-iv', 12)),
    })


csrf.exempt(recovery_start)


@app.route('/api/recovery/complete', methods=['POST'])
@limiter.limit("10 per hour")
def recovery_complete():
    data = request.get_json() or {}
    required = [
        'email', 'recoveryAuthSubkey', 'newAuthSubkey', 'newKdfSalt',
        'newKdfMemoryCost', 'newKdfTimeCost', 'newKdfParallelism',
        'newWrappedUserKeyPassword', 'newWrappedUserKeyPasswordIv',
    ]
    if any(k not in data for k in required):
        return jsonify({'error': 'Missing required fields'}), 400

    email = normalize_email(data['email'])
    user = User.query.filter_by(email=email).first()
    generic_error = jsonify({'error': 'Invalid recovery key or account'}), 401
    if not user:
        return generic_error

    if not user.check_recovery_auth_subkey(data['recoveryAuthSubkey']):
        return generic_error

    user.set_auth_subkey(data['newAuthSubkey'])
    user.kdf_salt = b64d(data['newKdfSalt'])
    user.kdf_memory_cost = int(data['newKdfMemoryCost'])
    user.kdf_time_cost = int(data['newKdfTimeCost'])
    user.kdf_parallelism = int(data['newKdfParallelism'])
    user.kdf_version = int(data.get('newKdfVersion', 1))
    user.wrapped_user_key_password = b64d(data['newWrappedUserKeyPassword'])
    user.wrapped_user_key_password_iv = b64d(data['newWrappedUserKeyPasswordIv'])
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()

    send_recovery_notification_email(user.email)
    return jsonify({'message': 'Master password updated successfully'})


csrf.exempt(recovery_complete)


@app.route('/api/csrf-token', methods=['GET'])
def csrf_token():
    return jsonify({'csrfToken': generate_csrf()})


@app.route('/api/check-auth', methods=['GET', 'OPTIONS'])
@login_required
def check_auth():
    if request.method == 'OPTIONS':
        return '', 200
    # The session cookie surviving a reload proves the user is still logged
    # in, but userKey only ever lives in page memory and is gone after a
    # reload. Handing back the wrapped key here (same as verify-2fa) lets the
    # UI show a lightweight "enter your master password to unlock" prompt
    # instead of a full re-login - it's the same trust level as an existing
    # authenticated session, not a new grant of access.
    return jsonify({
        'authenticated': True,
        'user': {'id': current_user.id, 'email': current_user.email},
        'wrappedUserKeyPassword': b64e(current_user.wrapped_user_key_password),
        'wrappedUserKeyPasswordIv': b64e(current_user.wrapped_user_key_password_iv),
        'kdfSalt': b64e(current_user.kdf_salt),
        'kdfMemoryCost': current_user.kdf_memory_cost,
        'kdfTimeCost': current_user.kdf_time_cost,
        'kdfParallelism': current_user.kdf_parallelism,
        'kdfVersion': current_user.kdf_version,
    })


@app.route('/api/logout', methods=['POST', 'OPTIONS'])
@login_required
def logout():
    if request.method == 'OPTIONS':
        return '', 200
    log_user_action('logout')
    logout_user()
    return jsonify({'message': 'Logged out successfully'})


@app.route('/api/refresh-token', methods=['POST', 'OPTIONS'])
def refresh_token():
    if request.method == 'OPTIONS':
        return '', 200
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'No valid session'}), 401
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 401
    token = secrets.token_urlsafe(32)
    session['token'] = token
    return jsonify({'token': token, 'user': {'id': user.id, 'email': user.email}}), 200


csrf.exempt(refresh_token)


# ---- Password vault (opaque ciphertext - the server never decrypts this) ----

@app.route('/api/passwords', methods=['GET', 'OPTIONS'])
@login_required
def get_passwords():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        passwords = Password.query.filter_by(user_id=current_user.id).all()
        return jsonify([p.to_dict() for p in passwords])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/passwords', methods=['POST', 'OPTIONS'])
@login_required
def create_password():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        data = request.get_json()
        if not data or 'encrypted_data' not in data or 'data_iv' not in data:
            return jsonify({'error': 'encrypted_data and data_iv are required'}), 400

        password = Password(
            user_id=current_user.id,
            encrypted_data=b64d(data['encrypted_data']),
            data_iv=b64d(data['data_iv']),
            category_id=data.get('category_id'),
        )
        db.session.add(password)
        db.session.commit()
        log_user_action('create_password', f'entry #{password.id}')
        return jsonify(password.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/passwords/<int:id>', methods=['PUT', 'OPTIONS'])
@login_required
def update_password(id):
    if request.method == 'OPTIONS':
        return '', 200
    password = Password.query.get_or_404(id)
    if password.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json() or {}
    if 'encrypted_data' in data and 'data_iv' in data:
        password.encrypted_data = b64d(data['encrypted_data'])
        password.data_iv = b64d(data['data_iv'])
    if 'category_id' in data:
        password.category_id = data['category_id']

    db.session.commit()
    log_user_action('update_password', f'entry #{password.id}')
    return jsonify(password.to_dict())


@app.route('/api/passwords/<int:id>', methods=['GET', 'OPTIONS'])
@login_required
def get_password(id):
    if request.method == 'OPTIONS':
        return '', 200
    password = Password.query.filter_by(id=id, user_id=current_user.id).first()
    if not password:
        return jsonify({'error': 'Password not found'}), 404
    return jsonify(password.to_dict())


@app.route('/api/passwords/<int:id>', methods=['DELETE', 'OPTIONS'])
@login_required
def delete_password(id):
    if request.method == 'OPTIONS':
        return '', 200
    password = Password.query.get_or_404(id)
    if password.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    log_user_action('delete_password', f'entry #{password.id}')
    db.session.delete(password)
    db.session.commit()
    return jsonify({'message': 'Password deleted successfully'})


@app.route('/api/generate-password', methods=['GET', 'OPTIONS'])
def generate_password():
    if request.method == 'OPTIONS':
        return '', 200
    import string
    try:
        length = min(max(int(request.args.get('length', 16)), 4), 128)
        use_uppercase = request.args.get('uppercase', 'true').lower() == 'true'
        use_lowercase = request.args.get('lowercase', 'true').lower() == 'true'
        use_numbers = request.args.get('numbers', 'true').lower() == 'true'
        use_special = request.args.get('special', 'true').lower() == 'true'

        characters = ''
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_numbers:
            characters += string.digits
        if use_special:
            characters += string.punctuation
        if not characters:
            characters = string.ascii_letters + string.digits

        password = ''.join(secrets.choice(characters) for _ in range(length))
        if use_uppercase and not any(c.isupper() for c in password):
            password = secrets.choice(string.ascii_uppercase) + password[1:]
        if use_lowercase and not any(c.islower() for c in password):
            password = password[:-1] + secrets.choice(string.ascii_lowercase)
        if use_numbers and not any(c.isdigit() for c in password):
            password = password[len(password) // 2:] + secrets.choice(string.digits) + password[:len(password) // 2]
        if use_special and not any(c in string.punctuation for c in password):
            pos = secrets.randbelow(len(password))
            password = password[:pos] + secrets.choice(string.punctuation) + password[pos + 1:]

        return jsonify({
            'password': password,
            'length': len(password),
            'uppercase': any(c.isupper() for c in password),
            'lowercase': any(c.islower() for c in password),
            'numbers': any(c.isdigit() for c in password),
            'special': any(c in string.punctuation for c in password),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


csrf.exempt(generate_password)


@app.route('/api/check-password-breach', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def check_password_breach():
    """Client computes the full SHA-1 locally and sends only the 5-char
    k-anonymity prefix - the full password/hash never leaves the browser.
    The server proxies to HIBP and returns the raw suffix:count list; the
    client matches its own suffix against it locally."""
    try:
        data = request.get_json() or {}
        prefix = (data.get('sha1Prefix') or '').strip().upper()
        if len(prefix) != 5 or not all(c in '0123456789ABCDEF' for c in prefix):
            return jsonify({'error': 'sha1Prefix must be 5 hex characters'}), 400

        response = requests.get(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            headers={'User-Agent': 'Windkey Password Manager', 'Accept': 'application/json'},
            timeout=10,
        )
        if response.status_code != 200:
            return jsonify({'error': 'API request failed'}), 502

        suffixes = []
        for line in response.text.splitlines():
            suffix, _, count = line.partition(':')
            if suffix:
                suffixes.append({'suffix': suffix, 'count': int(count or 0)})
        return jsonify({'suffixes': suffixes})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---- Categories (name is client-encrypted; icon/color are non-identifying) ----

@app.route('/api/categories', methods=['GET', 'OPTIONS'])
@login_required
def get_categories():
    if request.method == 'OPTIONS':
        return '', 200
    categories = Category.query.filter_by(user_id=current_user.id).all()
    return jsonify([c.to_dict() for c in categories])


@app.route('/api/categories', methods=['POST', 'OPTIONS'])
@login_required
def create_category():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        data = request.get_json()
        if not data or 'encrypted_name' not in data or 'name_iv' not in data:
            return jsonify({'error': 'encrypted_name and name_iv are required'}), 400

        category = Category(
            user_id=current_user.id,
            encrypted_name=b64d(data['encrypted_name']),
            name_iv=b64d(data['name_iv']),
            icon=data.get('icon', 'Folder'),
            color=data.get('color', '#2563EB'),
        )
        db.session.add(category)
        db.session.commit()
        log_user_action('create_category', f'category #{category.id}')
        return jsonify(category.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/categories/<int:id>', methods=['PUT', 'OPTIONS'])
@login_required
def update_category(id):
    if request.method == 'OPTIONS':
        return '', 200
    category = Category.query.get(id)
    if not category:
        return jsonify({'error': 'Category not found'}), 404
    if category.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json() or {}
    if 'encrypted_name' in data and 'name_iv' in data:
        category.encrypted_name = b64d(data['encrypted_name'])
        category.name_iv = b64d(data['name_iv'])
    if 'icon' in data:
        category.icon = data['icon']
    if 'color' in data:
        category.color = data['color']

    db.session.commit()
    log_user_action('update_category', f'category #{category.id}')
    return jsonify(category.to_dict())


@app.route('/api/categories/<int:id>', methods=['DELETE', 'OPTIONS'])
@login_required
def delete_category(id):
    if request.method == 'OPTIONS':
        return '', 200
    category = Category.query.get(id)
    if not category:
        return jsonify({'error': 'Category not found'}), 404
    if category.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    Password.query.filter_by(category_id=id).update({'category_id': None})
    category_id = category.id
    db.session.delete(category)
    db.session.commit()
    log_user_action('delete_category', f'category #{category_id}')
    return jsonify({'message': 'Category deleted successfully'})


@app.route('/api/history', methods=['GET', 'OPTIONS'])
@login_required
def get_history():
    if request.method == 'OPTIONS':
        return '', 200
    entries = History.query.filter_by(user_id=current_user.id).order_by(History.timestamp.desc()).all()
    return jsonify([e.to_dict() for e in entries])
