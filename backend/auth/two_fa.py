"""
backend/auth/two_fa.py
-----------------------
Two-Factor Authentication (TOTP) helpers using pyotp + qrcode.
"""

import pyotp
import qrcode
import base64
from io import BytesIO


def generate_totp_secret() -> str:
    """Generate a new random Base32 TOTP secret."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "SecureMsg Blockchain") -> str:
    """Return the otpauth:// URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_base64(uri: str) -> str:
    """Generate a QR code image from the URI and return as base64 PNG."""
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")


def verify_totp(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code. Allows 1 window (±30 sec) for clock skew."""
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code.strip(), valid_window=1)


def get_current_totp(secret: str) -> str:
    """Return the current valid TOTP code (useful for testing)."""
    return pyotp.TOTP(secret).now()
