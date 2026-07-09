import os

from flask_mail import Mail, Message

from app import app

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

# Where family devices reach the frontend - set this to your server's LAN IP
# in .env (e.g. https://192.168.2.42:3000) so links in emails work from any
# phone/laptop on the network, not just the machine running the backend.
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'https://localhost:3000')

mail = Mail(app)


_PLACEHOLDER_VALUES = {'your-email@gmail.com', 'your-app-specific-password', ''}


def _mail_configured():
    username = app.config['MAIL_USERNAME'] or ''
    password = app.config['MAIL_PASSWORD'] or ''
    return username not in _PLACEHOLDER_VALUES and password not in _PLACEHOLDER_VALUES


def send_verification_email(to_email, raw_token):
    if not _mail_configured():
        print(f"[mail] MAIL_USERNAME/MAIL_PASSWORD not configured - "
              f"verification link for {to_email}: "
              f"{FRONTEND_URL}/verify-email?token={raw_token}", flush=True)
        return False
    try:
        link = f'{FRONTEND_URL}/verify-email?token={raw_token}'
        msg = Message(
            subject='Bestätige deine Windkey-E-Mail-Adresse',
            recipients=[to_email],
            body=(
                f'Willkommen bei Windkey!\n\n'
                f'Bitte bestätige deine E-Mail-Adresse, um dein Konto zu aktivieren:\n'
                f'{link}\n\n'
                f'Dieser Link ist 24 Stunden gültig.'
            ),
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"[mail] Failed to send verification email: {e}", flush=True)
        return False


def send_recovery_notification_email(to_email):
    if not _mail_configured():
        print(f"[mail] MAIL_USERNAME/MAIL_PASSWORD not configured - "
              f"would have notified {to_email} of a master password change via Recovery Key", flush=True)
        return False
    try:
        msg = Message(
            subject='Dein Windkey Master-Passwort wurde geändert',
            recipients=[to_email],
            body=(
                'Dein Master-Passwort wurde soeben über deinen Recovery Key geändert.\n\n'
                'Warst du das nicht? Dann hat jemand Zugriff auf deinen Recovery Key erlangt - '
                'kontaktiere den Administrator dieser Windkey-Installation sofort.'
            ),
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"[mail] Failed to send recovery notification email: {e}", flush=True)
        return False
