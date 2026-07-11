"""
Generates a self-signed TLS certificate for local/LAN development.

Winkey's zero-knowledge crypto relies on the browser's WebCrypto API
(crypto.subtle), which browsers only expose in "secure contexts" - that's
https:// or http://localhost, but NOT plain http://192.168.x.x. Since family
members reach this server over the LAN by IP, both the Flask API and the
React dev server need to be served over HTTPS, even though there's no public
domain to get a CA-signed certificate for.

Run this once (and again if your LAN IP changes):
    python generate_dev_cert.py

Each family device will see a one-time "connection not private" browser
warning on first visit (self-signed certs aren't in any trusted CA store) -
click through it once per device. That is expected and does not weaken
security: the "not trusted" warning is about certificate provenance, not
about the encryption itself, and the page still counts as a secure context
once loaded, so crypto.subtle works normally.
"""
import ipaddress
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_DIR = Path(__file__).parent / "certs"
CERT_FILE = CERT_DIR / "dev-cert.pem"
KEY_FILE = CERT_DIR / "dev-key.pem"


def detect_lan_ips():
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr)
                if ip.is_private and not ip.is_loopback:
                    ips.add(addr)
            except ValueError:
                continue
    except socket.gaierror:
        pass
    return sorted(ips)


def main():
    CERT_DIR.mkdir(exist_ok=True)

    lan_ips = detect_lan_ips()
    print(f"Detected LAN IP(s): {lan_ips or '(none found - localhost only)'}")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Winkey Local Dev"),
    ])

    san_entries = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]
    for ip in lan_ips:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(key, hashes.SHA256())
    )

    KEY_FILE.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Wrote {CERT_FILE}")
    print(f"Wrote {KEY_FILE}")
    print()
    print("Next steps:")
    print("  1. Point frontend/.env's SSL_CRT_FILE/SSL_KEY_FILE at these files.")
    print("  2. Restart the backend (python app.py) and frontend (npm start).")
    print("  3. On each family device, visit https://<this-machine-LAN-IP>:3000")
    print("     once and click through the one-time certificate warning.")


if __name__ == "__main__":
    main()
