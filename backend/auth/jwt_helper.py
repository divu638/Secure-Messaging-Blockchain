"""
backend/auth/jwt_helper.py
---------------------------
JWT token generation and verification helpers using PyJWT.
"""

import jwt
import datetime
import os


def _secret() -> str:
    return os.environ.get("SECRET_KEY", "dev-secret-key-change-this-in-production")


def generate_tokens(user_id: int, username: str, is_admin: bool = False) -> tuple:
    """
    Generate an (access_token, refresh_token) pair.
    - access_token: valid for 15 minutes
    - refresh_token: valid for 7 days
    """
    now = datetime.datetime.utcnow()

    access_payload = {
        "user_id":  user_id,
        "username": username,
        "is_admin": is_admin,
        "type":     "access",
        "iat":      now,
        "exp":      now + datetime.timedelta(minutes=15),
    }

    refresh_payload = {
        "user_id":  user_id,
        "username": username,
        "type":     "refresh",
        "iat":      now,
        "exp":      now + datetime.timedelta(days=7),
    }

    access_token  = jwt.encode(access_payload,  _secret(), algorithm="HS256")
    refresh_token = jwt.encode(refresh_payload, _secret(), algorithm="HS256")
    return access_token, refresh_token


def decode_token(token: str) -> dict:
    """
    Decode and verify a JWT token.
    Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure.
    """
    return jwt.decode(token, _secret(), algorithms=["HS256"])


def get_token_jti(token: str) -> str:
    """Return the 'jti' claim from token payload (used for blacklisting)."""
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
        return payload.get("jti", "")
    except Exception:
        return ""
