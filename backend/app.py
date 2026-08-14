"""
app.py
------
Secure Messaging Blockchain System — Full-Featured Flask App (v2.0).

Features:
  - User Registration & Login (Werkzeug password hashing)
  - Google OAuth 2.0 Login (Sign in with Google)
  - RSA E2E Encrypted Chat stored on Blockchain
  - Real-time Messaging via Flask-SocketIO (WebSockets)
  - User Profiles with Avatar Upload
  - Admin Panel (user management, system stats)
  - SQLite (dev) / PostgreSQL (production) dual support
  [NEW] Two-Factor Authentication (TOTP / Google Authenticator)
  [NEW] Rate Limiting (Flask-Limiter)
  [NEW] Account Lockout after failed logins
  [NEW] JWT Token API endpoints
  [NEW] Merkle Tree integrity verification
  [NEW] Digital Signature verification
  [NEW] IPFS Distributed Storage via Pinata (Phase 4 — Completed)
        - Encrypted payloads uploaded to IPFS CID on every message
        - Async Pinata cloud pinning with instant local fallback cache
        - /api/ipfs/upload, /ipfs/<cid>, /api/ipfs/status endpoints
"""

import os
import sys
import hashlib
import time
import base64
import json
import datetime
from io import BytesIO
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g, jsonify)
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt as pyjwt

from config import Config

# ── Add backend sub-packages to path ─────────────────────────────────────────
_backend_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, _backend_dir)

from auth.two_fa      import generate_totp_secret, get_totp_uri, generate_qr_base64, verify_totp
from auth.jwt_helper  import generate_tokens, decode_token
from blockchain.merkle     import MerkleTree, compute_chain_merkle_root, get_block_proof
from blockchain.signatures import verify_rsa_signature
from blockchain.ipfs_pinata import upload_to_ipfs, fetch_from_ipfs, get_ipfs_gateway_url

# ── Detect database mode ──────────────────────────────────────────────────────
USE_POSTGRES = bool(Config.DATABASE_URL)

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
    import psycopg2.errors
else:
    import sqlite3

# ── Resolve paths relative to backend/ ───────────────────────────────────────
_root_dir     = os.path.abspath(os.path.join(_backend_dir, ".."))
_template_dir = os.path.join(_root_dir, "frontend", "templates")
_static_dir   = os.path.join(_root_dir, "frontend", "static")

# ── App Initialization ────────────────────────────────────────────────────────
app = Flask(__name__,
            template_folder=_template_dir,
            static_folder=_static_dir)
app.config.from_object(Config)
app.config["SECRET_KEY"] = Config.SECRET_KEY

# ── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per hour"],
    storage_uri="memory://",
)

# ── Security headers ──────────────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]         = "SAMEORIGIN"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
    return response

# ── SocketIO Setup ────────────────────────────────────────────────────────────
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── OAuth Setup ───────────────────────────────────────────────────────────────
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID", ""),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


# ═══════════════════════════════════════════════════════════════════════════════
#  DATABASE HELPERS  (unified SQLite + PostgreSQL)
# ═══════════════════════════════════════════════════════════════════════════════

def get_db():
    if "db" not in g:
        if USE_POSTGRES:
            g.db = psycopg2.connect(
                Config.DATABASE_URL,
                cursor_factory=psycopg2.extras.RealDictCursor,
            )
        else:
            db_dir = os.path.dirname(Config.SQLITE_PATH)
            os.makedirs(db_dir, exist_ok=True)
            g.db = sqlite3.connect(Config.SQLITE_PATH)
            g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def db_execute(query, params=(), fetchone=False, fetchall=False, commit=False):
    db = get_db()
    if USE_POSTGRES:
        pg_query = query.replace("?", "%s")
        cur = db.cursor()
        cur.execute(pg_query, params)
        if commit:
            db.commit()
        if fetchone:
            row = cur.fetchone()
            return dict(row) if row else None
        if fetchall:
            rows = cur.fetchall()
            return [dict(r) for r in rows] if rows else []
        return cur
    else:
        cur = db.execute(query, params)
        if commit:
            db.commit()
        if fetchone:
            row = cur.fetchone()
            return dict(row) if row else None
        if fetchall:
            rows = cur.fetchall()
            return [dict(r) for r in rows] if rows else []
        return cur


def last_insert_id():
    db = get_db()
    if USE_POSTGRES:
        cur = db.cursor()
        cur.execute("SELECT lastval()")
        row = cur.fetchone()
        return list(row.values())[0] if row else None
    else:
        return db.execute("SELECT last_insert_rowid()").fetchone()[0]


def init_db():
    db = get_db()
    if USE_POSTGRES:
        cur = db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                full_name     TEXT NOT NULL,
                username      TEXT UNIQUE NOT NULL,
                email         TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                google_id     TEXT UNIQUE,
                avatar_url    TEXT,
                bio           TEXT,
                is_admin      BOOLEAN DEFAULT FALSE,
                totp_secret   TEXT,
                two_fa_enabled BOOLEAN DEFAULT FALSE,
                failed_logins INTEGER DEFAULT 0,
                locked_until  TIMESTAMP,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_keys (
                user_id    INTEGER PRIMARY KEY,
                public_key TEXT NOT NULL,
                signing_public_key TEXT,
                encrypted_private_key TEXT,
                encrypted_signing_key TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blockchain (
                id                SERIAL PRIMARY KEY,
                sender            TEXT NOT NULL,
                recipient         TEXT NOT NULL,
                encrypted_message TEXT NOT NULL,
                sender_encrypted  TEXT,
                previous_hash     TEXT NOT NULL,
                hash              TEXT NOT NULL,
                nonce             INTEGER NOT NULL,
                digital_signature TEXT,
                sig_valid         BOOLEAN DEFAULT NULL,
                timestamp         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS token_blacklist (
                id         SERIAL PRIMARY KEY,
                token_jti  TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        db.commit()
    else:
        db_dir = os.path.dirname(Config.SQLITE_PATH)
        os.makedirs(db_dir, exist_ok=True)
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name      TEXT NOT NULL,
                username       TEXT UNIQUE NOT NULL,
                email          TEXT UNIQUE NOT NULL,
                password_hash  TEXT,
                google_id      TEXT UNIQUE,
                avatar_url     TEXT,
                bio            TEXT,
                is_admin       INTEGER DEFAULT 0,
                totp_secret    TEXT,
                two_fa_enabled INTEGER DEFAULT 0,
                failed_logins  INTEGER DEFAULT 0,
                locked_until   TIMESTAMP,
                created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS user_keys (
                user_id    INTEGER PRIMARY KEY,
                public_key TEXT NOT NULL,
                signing_public_key TEXT,
                encrypted_private_key TEXT,
                encrypted_signing_key TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS blockchain (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                sender            TEXT NOT NULL,
                recipient         TEXT NOT NULL,
                encrypted_message TEXT NOT NULL,
                sender_encrypted  TEXT,
                previous_hash     TEXT NOT NULL,
                hash              TEXT NOT NULL,
                nonce             INTEGER NOT NULL,
                digital_signature TEXT,
                sig_valid         INTEGER DEFAULT NULL,
                timestamp         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS token_blacklist (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                token_jti  TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        db.commit()
    _migrate_db()


def _migrate_db():
    """Safe migration: add columns to existing tables if missing."""
    try:
        db = get_db()
        if USE_POSTGRES:
            cur = db.cursor()
            for col_sql in [
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT UNIQUE",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS two_fa_enabled BOOLEAN DEFAULT FALSE",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_logins INTEGER DEFAULT 0",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP",
                "ALTER TABLE blockchain ADD COLUMN IF NOT EXISTS digital_signature TEXT",
                "ALTER TABLE blockchain ADD COLUMN IF NOT EXISTS sig_valid BOOLEAN",
                "ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS signing_public_key TEXT",
                "ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS encrypted_private_key TEXT",
                "ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS encrypted_signing_key TEXT",
            ]:
                cur.execute(col_sql)
            db.commit()
        else:
            user_cols  = [r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()]
            block_cols = [r[1] for r in db.execute("PRAGMA table_info(blockchain)").fetchall()]
            key_cols = [r[1] for r in db.execute("PRAGMA table_info(user_keys)").fetchall()]

            for col, sql in [
                ("google_id",     "ALTER TABLE users ADD COLUMN google_id TEXT"),
                ("avatar_url",    "ALTER TABLE users ADD COLUMN avatar_url TEXT"),
                ("bio",           "ALTER TABLE users ADD COLUMN bio TEXT"),
                ("is_admin",      "ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0"),
                ("totp_secret",   "ALTER TABLE users ADD COLUMN totp_secret TEXT"),
                ("two_fa_enabled","ALTER TABLE users ADD COLUMN two_fa_enabled INTEGER DEFAULT 0"),
                ("failed_logins", "ALTER TABLE users ADD COLUMN failed_logins INTEGER DEFAULT 0"),
                ("locked_until",  "ALTER TABLE users ADD COLUMN locked_until TIMESTAMP"),
            ]:
                if col not in user_cols:
                    db.execute(sql)

            for col, sql in [
                ("digital_signature", "ALTER TABLE blockchain ADD COLUMN digital_signature TEXT"),
                ("sig_valid",         "ALTER TABLE blockchain ADD COLUMN sig_valid INTEGER"),
            ]:
                if col not in block_cols:
                    db.execute(sql)
                    
            for col, sql in [
                ("signing_public_key", "ALTER TABLE user_keys ADD COLUMN signing_public_key TEXT"),
                ("encrypted_private_key", "ALTER TABLE user_keys ADD COLUMN encrypted_private_key TEXT"),
                ("encrypted_signing_key", "ALTER TABLE user_keys ADD COLUMN encrypted_signing_key TEXT"),
            ]:
                if col not in key_cols:
                    db.execute(sql)

            db.commit()
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
#  AUTH HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


def jwt_required(f):
    """Decorator for API endpoints that accept JWT Bearer tokens."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth_header[7:]
        try:
            payload = decode_token(token)
            if payload.get("type") != "access":
                return jsonify({"error": "Invalid token type"}), 401
            request.jwt_user_id  = payload["user_id"]
            request.jwt_username = payload["username"]
            request.jwt_is_admin = payload.get("is_admin", False)
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated


def _set_session(user):
    session["user_id"]   = user["id"]
    session["username"]  = user["username"]
    session["full_name"] = user["full_name"]
    session["is_admin"]  = bool(user["is_admin"]) if user["is_admin"] else False
    session["avatar_url"] = user["avatar_url"] or ""
    session["two_fa_enabled"] = bool(user.get("two_fa_enabled", False))


def _is_account_locked(user) -> tuple[bool, str]:
    """Return (is_locked, message)."""
    locked_until = user.get("locked_until")
    if not locked_until:
        return False, ""
    if isinstance(locked_until, str):
        try:
            locked_until = datetime.datetime.fromisoformat(locked_until)
        except ValueError:
            return False, ""
    if locked_until > datetime.datetime.utcnow():
        remaining = int((locked_until - datetime.datetime.utcnow()).total_seconds() / 60)
        return True, f"Account locked. Try again in {remaining} minute(s)."
    return False, ""


def _record_failed_login(user_id: int, current_count: int):
    new_count = current_count + 1
    if new_count >= Config.MAX_FAILED_LOGINS:
        locked_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=Config.LOCKOUT_MINUTES)
        db_execute(
            "UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
            (new_count, locked_until.isoformat(), user_id), commit=True,
        )
    else:
        db_execute(
            "UPDATE users SET failed_logins=? WHERE id=?",
            (new_count, user_id), commit=True,
        )


def _reset_failed_logins(user_id: int):
    db_execute(
        "UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?",
        (user_id,), commit=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES: PUBLIC PAGES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES: REGISTRATION
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def register():
    if request.method == "POST":
        full_name        = request.form.get("full_name", "").strip()
        username         = request.form.get("username", "").strip()
        email            = request.form.get("email", "").strip()
        password         = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not username or not email or not password:
            flash("Please fill in all fields.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        try:
            password_hash = generate_password_hash(password)
            db_execute(
                "INSERT INTO users (full_name, username, email, password_hash) VALUES (?, ?, ?, ?)",
                (full_name, username, email, password_hash),
                commit=True,
            )
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            err = str(e).lower()
            if "unique" in err or "duplicate" in err:
                flash("Username or email already exists.", "danger")
            else:
                flash("An error occurred during registration. Please try again.", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES: LOGIN / LOGOUT
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db_execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (username, username),
            fetchone=True,
        )

        if not user:
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

        # ── Account lockout check ──────────────────────────────────────────
        is_locked, lock_msg = _is_account_locked(user)
        if is_locked:
            flash(lock_msg, "danger")
            return redirect(url_for("login"))

        # ── Password verification ──────────────────────────────────────────
        if user["password_hash"] and check_password_hash(user["password_hash"], password):
            _reset_failed_logins(user["id"])

            # ── 2FA check ─────────────────────────────────────────────────
            if user.get("two_fa_enabled"):
                session["_2fa_pending_user_id"] = user["id"]
                return redirect(url_for("two_fa_verify"))

            _set_session(user)
            flash(f"Welcome back, {user['full_name']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            _record_failed_login(user["id"], user.get("failed_logins", 0))
            remaining = Config.MAX_FAILED_LOGINS - (user.get("failed_logins", 0) + 1)
            if remaining > 0:
                flash(f"Invalid password. {remaining} attempt(s) left before lockout.", "danger")
            else:
                flash(f"Account locked for {Config.LOCKOUT_MINUTES} minutes due to too many failed attempts.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES: TWO-FACTOR AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/2fa/verify", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def two_fa_verify():
    """Step-2 of login: verify TOTP code."""
    pending_id = session.get("_2fa_pending_user_id")
    if not pending_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        user = db_execute("SELECT * FROM users WHERE id = ?", (pending_id,), fetchone=True)

        if user and verify_totp(user["totp_secret"], code):
            session.pop("_2fa_pending_user_id", None)
            _set_session(user)
            flash(f"Welcome back, {user['full_name']}! 2FA verified. ✅", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid 2FA code. Please try again.", "danger")

    return render_template("two_fa_verify.html")


@app.route("/2fa/setup")
@login_required
def two_fa_setup():
    """Generate a fresh TOTP secret and show QR code."""
    user = db_execute("SELECT * FROM users WHERE id = ?", (session["user_id"],), fetchone=True)
    if user.get("two_fa_enabled"):
        flash("2FA is already enabled on your account.", "info")
        return redirect(url_for("profile"))

    secret = generate_totp_secret()
    session["_2fa_setup_secret"] = secret
    uri    = get_totp_uri(secret, session["username"])
    qr_b64 = generate_qr_base64(uri)
    return render_template("two_fa_setup.html", secret=secret, qr_b64=qr_b64)


@app.route("/2fa/enable", methods=["POST"])
@login_required
def two_fa_enable():
    """Confirm setup code and permanently enable 2FA."""
    secret = session.get("_2fa_setup_secret")
    code   = request.form.get("code", "").strip()

    if not secret:
        flash("Session expired. Please restart 2FA setup.", "danger")
        return redirect(url_for("two_fa_setup"))

    if verify_totp(secret, code):
        db_execute(
            "UPDATE users SET totp_secret=?, two_fa_enabled=1 WHERE id=?",
            (secret, session["user_id"]),
            commit=True,
        )
        session.pop("_2fa_setup_secret", None)
        session["two_fa_enabled"] = True
        flash("Two-Factor Authentication enabled successfully! 🔐", "success")
    else:
        flash("Invalid code. Please scan the QR again and try once more.", "danger")
        return redirect(url_for("two_fa_setup"))

    return redirect(url_for("profile"))


@app.route("/2fa/disable", methods=["POST"])
@login_required
def two_fa_disable():
    """Disable 2FA for the logged-in user."""
    code = request.form.get("code", "").strip()
    user = db_execute("SELECT * FROM users WHERE id = ?", (session["user_id"],), fetchone=True)

    if not user.get("two_fa_enabled"):
        flash("2FA is not enabled.", "info")
        return redirect(url_for("profile"))

    if verify_totp(user["totp_secret"], code):
        db_execute(
            "UPDATE users SET totp_secret=NULL, two_fa_enabled=0 WHERE id=?",
            (session["user_id"],), commit=True,
        )
        session["two_fa_enabled"] = False
        flash("2FA has been disabled.", "info")
    else:
        flash("Invalid code. 2FA not disabled.", "danger")

    return redirect(url_for("profile"))


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES: GOOGLE OAUTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/auth/google")
def google_login():
    if not os.environ.get("GOOGLE_CLIENT_ID"):
        flash("Google login is not configured.", "warning")
        return redirect(url_for("login"))
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    try:
        token    = google.authorize_access_token()
        userinfo = token.get("userinfo")
        if not userinfo:
            flash("Failed to get user info from Google.", "danger")
            return redirect(url_for("login"))

        google_id  = userinfo["sub"]
        email      = userinfo["email"]
        full_name  = userinfo.get("name", email.split("@")[0])
        avatar_url = userinfo.get("picture", "")

        user = db_execute(
            "SELECT * FROM users WHERE google_id = ? OR email = ?",
            (google_id, email), fetchone=True,
        )

        if user:
            db_execute(
                "UPDATE users SET google_id = ?, avatar_url = ? WHERE id = ?",
                (google_id, avatar_url, user["id"]), commit=True,
            )
            user = db_execute("SELECT * FROM users WHERE id = ?", (user["id"],), fetchone=True)
        else:
            username      = email.split("@")[0].replace(".", "_").lower()
            base_username = username
            counter       = 1
            while db_execute("SELECT id FROM users WHERE username = ?", (username,), fetchone=True):
                username = f"{base_username}{counter}"
                counter += 1
            db_execute(
                "INSERT INTO users (full_name, username, email, google_id, avatar_url) VALUES (?, ?, ?, ?, ?)",
                (full_name, username, email, google_id, avatar_url), commit=True,
            )
            user = db_execute("SELECT * FROM users WHERE google_id = ?", (google_id,), fetchone=True)

        _set_session(user)
        flash(f"Welcome, {user['full_name']}! Signed in with Google.", "success")
        return redirect(url_for("dashboard"))
    except Exception as e:
        flash(f"Google login failed: {str(e)}", "danger")
        return redirect(url_for("login"))


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES: PROTECTED PAGES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html",
                           full_name=session.get("full_name"),
                           username=session.get("username"),
                           avatar_url=session.get("avatar_url", ""))


@app.route("/chat")
@login_required
def chat():
    return render_template("chat.html",
                           full_name=session.get("full_name"),
                           username=session.get("username"),
                           avatar_url=session.get("avatar_url", ""))


@app.route("/keys")
@login_required
def key_manager():
    return render_template("keys.html",
                           full_name=session.get("full_name"),
                           username=session.get("username"))


@app.route("/blockchain")
@login_required
def blockchain_ledger():
    return render_template("blockchain.html",
                           full_name=session.get("full_name"),
                           username=session.get("username"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        full_name  = request.form.get("full_name", "").strip()
        bio        = request.form.get("bio", "").strip()
        avatar_url = session.get("avatar_url", "")

        if "avatar" in request.files:
            file = request.files["avatar"]
            if file and file.filename:
                try:
                    from PIL import Image
                    img = Image.open(file.stream)
                    img.thumbnail((256, 256))
                    buf = BytesIO()
                    img.save(buf, format="JPEG", quality=85)
                    encoded    = base64.b64encode(buf.getvalue()).decode("utf-8")
                    avatar_url = f"data:image/jpeg;base64,{encoded}"
                except Exception:
                    pass

        db_execute(
            "UPDATE users SET full_name = ?, bio = ?, avatar_url = ? WHERE id = ?",
            (full_name, bio, avatar_url, session["user_id"]),
            commit=True,
        )
        session["full_name"]  = full_name
        session["avatar_url"] = avatar_url
        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))

    user = db_execute("SELECT * FROM users WHERE id = ?", (session["user_id"],), fetchone=True)
    return render_template("profile.html",
                           full_name=session.get("full_name"),
                           username=session.get("username"),
                           avatar_url=session.get("avatar_url", ""),
                           two_fa_enabled=bool(user.get("two_fa_enabled", False)),
                           user=user)


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES: ADMIN PANEL
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/admin")
@admin_required
def admin_panel():
    users        = db_execute("SELECT * FROM users ORDER BY created_at DESC", fetchall=True)
    total_blocks = db_execute("SELECT COUNT(*) as cnt FROM blockchain", fetchone=True)
    total_users  = db_execute("SELECT COUNT(*) as cnt FROM users", fetchone=True)
    return render_template("admin.html",
                           users=[dict(u) for u in users],
                           total_blocks=total_blocks["cnt"],
                           total_users=total_users["cnt"],
                           full_name=session.get("full_name"),
                           username=session.get("username"))


@app.route("/admin/toggle_admin/<int:user_id>", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    if user_id == session["user_id"]:
        return jsonify({"error": "Cannot modify your own admin status"}), 400
    user = db_execute("SELECT is_admin FROM users WHERE id = ?", (user_id,), fetchone=True)
    if user:
        new_status = 0 if user["is_admin"] else 1
        db_execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id), commit=True)
    return jsonify({"success": True})


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == session["user_id"]:
        return jsonify({"error": "Cannot delete your own account"}), 400
    db_execute("DELETE FROM user_keys WHERE user_id = ?", (user_id,), commit=True)
    db_execute("DELETE FROM users WHERE id = ?", (user_id,), commit=True)
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════════════════════════
#  BLOCKCHAIN & MESSAGING HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_hash(sender, recipient, encrypted_message, sender_encrypted,
                   previous_hash, nonce, timestamp):
    payload = (
        f"{sender}{recipient}{encrypted_message}"
        f"{sender_encrypted or ''}{previous_hash}{nonce}{timestamp}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def mine_block(sender, recipient, encrypted_message, sender_encrypted, previous_hash):
    timestamp  = time.strftime("%Y-%m-%d %H:%M:%S")
    nonce      = 0
    difficulty = "00"
    while True:
        block_hash = calculate_hash(
            sender, recipient, encrypted_message, sender_encrypted,
            previous_hash, nonce, timestamp,
        )
        if block_hash.startswith(difficulty):
            break
        nonce += 1
    return nonce, block_hash, timestamp


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES: API — IPFS (Pinata + local fallback)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/ipfs/upload", methods=["POST"])
@login_required
def ipfs_upload():
    data    = request.get_json()
    payload = data.get("encrypted_payload")
    if not payload:
        return jsonify({"error": "No payload provided"}), 400

    cid = upload_to_ipfs(payload)
    return jsonify({"ipfs_cid": cid})


@app.route("/ipfs/<cid>", methods=["GET"])
def ipfs_fetch(cid):
    content = fetch_from_ipfs(cid)
    if content is not None:
        return content, 200, {"Content-Type": "text/plain"}
    return jsonify({"error": "CID not found"}), 404


@app.route("/api/ipfs/status", methods=["GET"])
def ipfs_status():
    """Return IPFS/Pinata configuration status and local storage stats."""
    from blockchain.ipfs_pinata import _is_configured, _local_ipfs_dir
    configured = _is_configured()
    local_dir  = _local_ipfs_dir()
    try:
        stored_cids = len([f for f in os.listdir(local_dir) if os.path.isfile(os.path.join(local_dir, f))])
    except Exception:
        stored_cids = 0

    return jsonify({
        "pinata_configured": configured,
        "local_fallback":    True,
        "stored_cids":       stored_cids,
        "local_storage_path": local_dir,
        "gateway": "https://gateway.pinata.cloud/ipfs" if configured else "/ipfs",
    })


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES: API — KEYS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/users")
@login_required
def api_users():
    users = db_execute("""
        SELECT users.id, users.username, users.full_name, users.avatar_url,
               (user_keys.public_key IS NOT NULL) AS has_key
        FROM users
        LEFT JOIN user_keys ON users.id = user_keys.user_id
        WHERE users.id != ?
        ORDER BY users.username ASC
    """, (session["user_id"],), fetchall=True)
    return jsonify({"users": [dict(u) for u in users]})


@app.route("/api/keys/upload", methods=["POST"])
@login_required
def upload_key():
    data               = request.json or {}
    public_key         = data.get("public_key")
    signing_public_key = data.get("signing_public_key")
    encrypted_private_key = data.get("encrypted_private_key")
    encrypted_signing_key = data.get("encrypted_signing_key")
    if not public_key:
        return jsonify({"error": "Missing public key"}), 400

    if USE_POSTGRES:
        db_execute("""
            INSERT INTO user_keys (user_id, public_key, signing_public_key, encrypted_private_key, encrypted_signing_key) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (user_id) DO UPDATE SET 
                public_key = EXCLUDED.public_key, 
                signing_public_key = EXCLUDED.signing_public_key,
                encrypted_private_key = EXCLUDED.encrypted_private_key,
                encrypted_signing_key = EXCLUDED.encrypted_signing_key
        """, (session["user_id"], public_key, signing_public_key, encrypted_private_key, encrypted_signing_key), commit=True)
    else:
        db_execute("""
            INSERT OR REPLACE INTO user_keys (user_id, public_key, signing_public_key, encrypted_private_key, encrypted_signing_key) VALUES (?, ?, ?, ?, ?)
        """, (session["user_id"], public_key, signing_public_key, encrypted_private_key, encrypted_signing_key), commit=True)
    return jsonify({"status": "success"})


@app.route("/api/keys/download", methods=["GET"])
@login_required
def download_keys():
    user_keys = db_execute(
        "SELECT public_key, signing_public_key, encrypted_private_key, encrypted_signing_key FROM user_keys WHERE user_id = ?",
        (session["user_id"],), fetchone=True
    )
    if not user_keys:
        return jsonify({"error": "No keys found"}), 404
        
    return jsonify({
        "public_key": user_keys["public_key"],
        "signing_public_key": user_keys["signing_public_key"],
        "encrypted_private_key": user_keys["encrypted_private_key"],
        "encrypted_signing_key": user_keys["encrypted_signing_key"]
    })


@app.route("/api/keys/<username>")
@login_required
def get_public_key(username):
    row = db_execute("""
        SELECT public_key FROM user_keys
        JOIN users ON user_keys.user_id = users.id
        WHERE users.username = ?
    """, (username,), fetchone=True)
    if not row:
        return jsonify({"error": "Key not found"}), 404
    return jsonify({"public_key": row["public_key"]})


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES: API — MESSAGES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/messages/send", methods=["POST"])
@login_required
@limiter.limit("60 per minute")
def send_message():
    data              = request.json or {}
    recipient         = data.get("recipient")
    encrypted_message = data.get("encrypted_message")
    sender_encrypted  = data.get("sender_encrypted")
    digital_signature = data.get("digital_signature")   # NEW: RSA-PSS signature
    plain_hash        = data.get("plain_hash")           # SHA-256 hash of plaintext (for sig verify)

    if not recipient or not encrypted_message:
        return jsonify({"error": "Missing recipient or message"}), 400

    rec_user = db_execute("SELECT id FROM users WHERE username = ?", (recipient,), fetchone=True)
    if not rec_user:
        return jsonify({"error": "Recipient user not found"}), 404

    # ── Verify digital signature (if provided) ──────────────────────────────
    sig_valid = None
    if digital_signature and plain_hash:
        sender_key_row = db_execute("""
            SELECT signing_public_key FROM user_keys
            JOIN users ON user_keys.user_id = users.id
            WHERE users.username = ?
        """, (session["username"],), fetchone=True)

        if sender_key_row and sender_key_row.get("signing_public_key"):
            sig_valid = verify_rsa_signature(
                sender_key_row["signing_public_key"], plain_hash, digital_signature
            )

    latest_block  = db_execute("SELECT hash FROM blockchain ORDER BY id DESC LIMIT 1", fetchone=True)
    previous_hash = (
        latest_block["hash"] if latest_block
        else "0" * 64
    )

    sender = session["username"]
    nonce, block_hash, timestamp = mine_block(
        sender, recipient, encrypted_message, sender_encrypted, previous_hash
    )

    db_execute("""
        INSERT INTO blockchain
            (sender, recipient, encrypted_message, sender_encrypted,
             previous_hash, hash, nonce, digital_signature, sig_valid, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (sender, recipient, encrypted_message, sender_encrypted,
          previous_hash, block_hash, nonce,
          digital_signature, 1 if sig_valid else (0 if sig_valid is False else None),
          timestamp), commit=True)

    new_id = last_insert_id()
    block_data = {
        "id":               new_id,
        "sender":           sender,
        "recipient":        recipient,
        "encrypted_message": encrypted_message,
        "sender_encrypted": sender_encrypted,
        "previous_hash":    previous_hash,
        "hash":             block_hash,
        "nonce":            nonce,
        "timestamp":        timestamp,
        "sig_valid":        sig_valid,
    }

    socketio.emit("new_message", block_data, room=recipient)
    socketio.emit("new_message", block_data, room=sender)
    return jsonify({"status": "success", "block": block_data})


@app.route("/api/messages/history")
@login_required
def get_messages_history():
    username = session["username"]
    rows = db_execute(
        "SELECT * FROM blockchain WHERE sender = ? OR recipient = ? ORDER BY id ASC",
        (username, username), fetchall=True,
    )
    return jsonify({"messages": [dict(r) for r in rows]})


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES: API — BLOCKCHAIN
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/blockchain/blocks")
@login_required
def get_blockchain_blocks():
    rows = db_execute("SELECT * FROM blockchain ORDER BY id ASC", fetchall=True)
    return jsonify({"blocks": [dict(r) for r in rows]})


@app.route("/api/blockchain/audit", methods=["POST"])
@login_required
def audit_blockchain():
    blocks        = db_execute("SELECT * FROM blockchain ORDER BY id ASC", fetchall=True)
    audit_results = []
    is_valid      = True
    expected_prev = "0" * 64
    difficulty    = "00"

    for block in blocks:
        b        = dict(block)
        recalc   = calculate_hash(
            b["sender"], b["recipient"], b["encrypted_message"],
            b.get("sender_encrypted"), b["previous_hash"], b["nonce"], b["timestamp"],
        )
        issues = []
        if recalc != b["hash"]:
            issues.append(f"Hash mismatch")
            is_valid = False
        if b["previous_hash"] != expected_prev:
            issues.append("Broken chain link")
            is_valid = False
        if not b["hash"].startswith(difficulty):
            issues.append("PoW invalid")
            is_valid = False

        audit_results.append({
            "id":              b["id"],
            "sender":          b["sender"],
            "recipient":       b["recipient"],
            "stored_hash":     b["hash"],
            "calculated_hash": recalc,
            "previous_hash":   b["previous_hash"],
            "is_valid":        len(issues) == 0,
            "sig_valid":       b.get("sig_valid"),
            "issues":          issues,
        })
        expected_prev = b["hash"]

    return jsonify({"is_valid": is_valid, "results": audit_results})


@app.route("/api/blockchain/tamper", methods=["POST"])
@login_required
def tamper_blockchain():
    blocks = db_execute("SELECT id FROM blockchain ORDER BY id DESC", fetchall=True)
    if not blocks:
        return jsonify({"error": "No blocks to tamper. Send some messages first!"}), 400
    tamper_id = dict(blocks[0])["id"]
    db_execute(
        "UPDATE blockchain SET encrypted_message = ? WHERE id = ?",
        ("!!! WARNING: ENCRYPTED MESSAGE TAMPERED IN DATABASE DIRECTLY !!!", tamper_id),
        commit=True,
    )
    return jsonify({"status": "success", "tampered_block_id": tamper_id})


# ── NEW: Merkle Tree API ──────────────────────────────────────────────────────

@app.route("/api/blockchain/merkle")
@login_required
def get_merkle_root():
    """Return the current Merkle root of all blocks in the chain."""
    blocks = db_execute("SELECT hash FROM blockchain ORDER BY id ASC", fetchall=True)
    if not blocks:
        return jsonify({"merkle_root": "0" * 64, "total_blocks": 0})

    block_list  = [dict(b) for b in blocks]
    merkle_root = compute_chain_merkle_root(block_list)
    return jsonify({"merkle_root": merkle_root, "total_blocks": len(block_list)})


@app.route("/api/blockchain/merkle/proof/<int:block_index>")
@login_required
def get_merkle_proof(block_index):
    """Return the Merkle proof for a specific block by its position (0-indexed)."""
    blocks = db_execute("SELECT hash FROM blockchain ORDER BY id ASC", fetchall=True)
    if not blocks:
        return jsonify({"error": "No blocks in chain"}), 404

    block_list = [dict(b) for b in blocks]
    if block_index >= len(block_list):
        return jsonify({"error": f"Block index {block_index} out of range"}), 400

    proof_data = get_block_proof(block_list, block_index)
    return jsonify(proof_data)


# ── NEW: JWT Auth API ─────────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def api_jwt_login():
    """Issue JWT access + refresh tokens for API clients."""
    data     = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    user = db_execute(
        "SELECT * FROM users WHERE username = ? OR email = ?",
        (username, username), fetchone=True,
    )

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    is_locked, lock_msg = _is_account_locked(user)
    if is_locked:
        return jsonify({"error": lock_msg}), 429

    if user["password_hash"] and check_password_hash(user["password_hash"], password):
        _reset_failed_logins(user["id"])

        if user.get("two_fa_enabled"):
            return jsonify({
                "two_fa_required": True,
                "message": "Provide TOTP code at /api/auth/2fa",
            }), 200

        access_token, refresh_token = generate_tokens(
            user["id"], user["username"], bool(user.get("is_admin", False))
        )
        return jsonify({
            "access_token":  access_token,
            "refresh_token": refresh_token,
            "token_type":    "Bearer",
            "expires_in":    900,   # 15 minutes
        })

    _record_failed_login(user["id"], user.get("failed_logins", 0))
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/auth/2fa", methods=["POST"])
@limiter.limit("10 per minute")
def api_jwt_2fa():
    """Complete JWT login with 2FA TOTP code."""
    data     = request.json or {}
    username = data.get("username", "").strip()
    code     = data.get("code", "").strip()

    user = db_execute("SELECT * FROM users WHERE username = ?", (username,), fetchone=True)
    if not user or not user.get("two_fa_enabled"):
        return jsonify({"error": "2FA not required or user not found"}), 400

    if verify_totp(user["totp_secret"], code):
        access_token, refresh_token = generate_tokens(
            user["id"], user["username"], bool(user.get("is_admin", False))
        )
        return jsonify({
            "access_token":  access_token,
            "refresh_token": refresh_token,
            "token_type":    "Bearer",
        })

    return jsonify({"error": "Invalid 2FA code"}), 401


@app.route("/api/auth/refresh", methods=["POST"])
def api_jwt_refresh():
    """Exchange refresh token for a new access token."""
    data  = request.json or {}
    token = data.get("refresh_token", "")

    try:
        payload = decode_token(token)
        if payload.get("type") != "refresh":
            return jsonify({"error": "Not a refresh token"}), 400

        access_token, _ = generate_tokens(
            payload["user_id"], payload["username"],
        )
        return jsonify({"access_token": access_token, "token_type": "Bearer"})
    except pyjwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired. Please log in again."}), 401
    except pyjwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401


@app.route("/api/auth/me")
@jwt_required
def api_jwt_me():
    """Return current user info (JWT-protected endpoint example)."""
    user = db_execute("SELECT id, username, full_name, email, is_admin FROM users WHERE id = ?",
                      (request.jwt_user_id,), fetchone=True)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(dict(user))


# ── NEW: Health check ─────────────────────────────────────────────────────────

@app.route("/health")
def health_check():
    try:
        db_execute("SELECT 1", fetchone=True)
        db_status = "ok"
    except Exception:
        db_status = "error"

    total_blocks = 0
    try:
        row = db_execute("SELECT COUNT(*) as cnt FROM blockchain", fetchone=True)
        total_blocks = row["cnt"] if row else 0
    except Exception:
        pass

    return jsonify({
        "status":       "ok",
        "database":     db_status,
        "total_blocks": total_blocks,
        "version":      "2.0.0",
    })


# ═══════════════════════════════════════════════════════════════════════════════
#  SOCKETIO: REAL-TIME EVENTS
# ═══════════════════════════════════════════════════════════════════════════════

@socketio.on("connect")
def on_connect():
    if "username" in session:
        join_room(session["username"])
        emit("connected", {"user": session["username"]})


@socketio.on("disconnect")
def on_disconnect():
    if "username" in session:
        leave_room(session["username"])


@socketio.on("typing")
def on_typing(data):
    recipient = data.get("recipient")
    sender    = session.get("username")
    if recipient and sender:
        emit("user_typing", {"sender": sender}, room=recipient)


@socketio.on("stop_typing")
def on_stop_typing(data):
    recipient = data.get("recipient")
    sender    = session.get("username")
    if recipient and sender:
        emit("user_stop_typing", {"sender": sender}, room=recipient)


# ═══════════════════════════════════════════════════════════════════════════════
#  RATE LIMIT ERROR HANDLER
# ═══════════════════════════════════════════════════════════════════════════════

@app.errorhandler(429)
def rate_limit_exceeded(e):
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"error": "Rate limit exceeded. Please slow down.", "retry_after": str(e.retry_after)}), 429
    flash("Too many requests. Please wait a moment before trying again. 🛡️", "warning")
    return redirect(request.referrer or url_for("home"))


# ── Entry point is run.py at project root.
# To start the server, run: python run.py
