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
    DATABASE_URL = os.environ.get("DATABASE_URL", None)
    SQLITE_PATH  = os.path.join(_root_dir, "database", "instance", "database.db")

    # ── Debug ─────────────────────────────────────────────────────────────────
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    # ── IPFS / Pinata ─────────────────────────────────────────────────────────
    PINATA_API_KEY    = os.environ.get("PINATA_API_KEY", "")
    PINATA_SECRET_KEY = os.environ.get("PINATA_SECRET_KEY", "")

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATELIMIT_STORAGE_URI    = "memory://"
    RATELIMIT_DEFAULT        = "300 per hour"

    # ── Account Lockout ───────────────────────────────────────────────────────
    MAX_FAILED_LOGINS    = 5
    LOCKOUT_MINUTES      = 15
