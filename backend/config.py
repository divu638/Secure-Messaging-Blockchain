"""
config.py
----------
Centralized configuration for the Flask application.
Supports both local SQLite (development) and PostgreSQL (production).
"""

import os
from dotenv import load_dotenv

_backend_dir = os.path.abspath(os.path.dirname(__file__))
_root_dir    = os.path.abspath(os.path.join(_backend_dir, ".."))
load_dotenv(os.path.join(_root_dir, ".env"))


class Config:
    # ── Security ────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-this-in-production")

    # ── Database ─────────────────────────────────────────────────────────────
    _raw_db_url = os.environ.get("DATABASE_URL", "").strip()
    if _raw_db_url:
        if _raw_db_url.startswith("postgres://"):
            _raw_db_url = "postgresql://" + _raw_db_url[len("postgres://"):]
        if "supabase" in _raw_db_url.lower() and "sslmode=" not in _raw_db_url.lower():
            sep = "&" if "?" in _raw_db_url else "?"
            _raw_db_url = f"{_raw_db_url}{sep}sslmode=require"
    DATABASE_URL = _raw_db_url if _raw_db_url else None
    SQLITE_PATH  = os.path.join(_root_dir, "database", "instance", "database.db")

    # ── Debug ─────────────────────────────────────────────────────────────────
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    # ── IPFS / Pinata ─────────────────────────────────────────────────────────
    PINATA_API_KEY    = os.environ.get("PINATA_API_KEY", "")
    PINATA_SECRET_KEY = os.environ.get("PINATA_SECRET_KEY", "")

    # ── Supabase ──────────────────────────────────────────────────────────────
    SUPABASE_URL             = os.environ.get("SUPABASE_URL", "")
    SUPABASE_PUBLISHABLE_KEY = os.environ.get("SUPABASE_PUBLISHABLE_KEY", "")
    SUPABASE_SECRET_KEY      = os.environ.get("SUPABASE_SECRET_KEY", "")

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATELIMIT_STORAGE_URI    = "memory://"
    RATELIMIT_DEFAULT        = "300 per hour"

    # ── Account Lockout ───────────────────────────────────────────────────────
    MAX_FAILED_LOGINS    = 5
    LOCKOUT_MINUTES      = 15
