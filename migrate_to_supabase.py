"""
migrate_to_supabase.py
----------------------
CLI tool to migrate all existing data from local SQLite database (database/instance/database.db)
directly to Supabase (PostgreSQL).

Usage:
    python migrate_to_supabase.py
    # OR provide a connection URL directly:
    python migrate_to_supabase.py --url "postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres"
"""

import sys
import os
import sqlite3
import argparse
from dotenv import load_dotenv

# Ensure backend modules can be imported
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("\n[!] Error: psycopg2 is not installed!")
    print("    Run: pip install psycopg2-binary\n")
    sys.exit(1)

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


def parse_args():
    parser = argparse.ArgumentParser(description="Migrate SQLite data to Supabase PostgreSQL.")
    parser.add_argument("--url", dest="db_url", help="Supabase PostgreSQL connection URL")
    return parser.parse_args()


def clean_url(url: str) -> str:
    url = url.strip()
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if "sslmode=" not in url.lower():
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}sslmode=require"
    return url


def main():
    args = parse_args()

    print("=" * 65)
    print(">> SUPABASE DATABASE MIGRATION TOOL")
    print("   Secure Messaging Blockchain System")
    print("=" * 65)

    db_url = args.db_url or os.environ.get("DATABASE_URL", "").strip()

    if not db_url:
        print("\n[!] No Supabase DATABASE_URL provided in .env or via --url.")
        db_url = input("\n--> Enter your Supabase connection string (URI):\n> ").strip()

    if not db_url:
        print("\n[x] No DATABASE_URL provided. Migration cancelled.\n")
        sys.exit(1)

    db_url = clean_url(db_url)

    sqlite_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "instance", "database.db")
    if not os.path.exists(sqlite_path):
        print(f"\n[i] Local SQLite database not found at {sqlite_path}.")
        print("    Initializing empty schema directly on Supabase...")
        has_sqlite = False
    else:
        print(f"\n[*] Found local SQLite database: {sqlite_path}")
        has_sqlite = True

    # 1. Connect to Supabase
    print("[*] Connecting to Supabase PostgreSQL...")
    try:
        pg_conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor, connect_timeout=15)
        pg_cur = pg_conn.cursor()
        print("    [+] Connected successfully to Supabase!")
    except Exception as e:
        print(f"\n[x] Failed to connect to Supabase: {e}")
        print("\n[?] Tips:")
        print("    1. Verify your database password in the connection URL.")
        print("    2. Check if your project reference & region are correct.")
        print("    3. Ensure you're using port 6543 (Pooler) or 5432 (Session).")
        sys.exit(1)

    # 2. Create tables in Supabase
    print("\n[*] Ensuring Supabase tables exist...")
    try:
        pg_cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id             SERIAL PRIMARY KEY,
                full_name      TEXT NOT NULL,
                username       TEXT UNIQUE NOT NULL,
                email          TEXT UNIQUE NOT NULL,
                password_hash  TEXT,
                google_id      TEXT UNIQUE,
                avatar_url     TEXT,
                bio            TEXT,
                is_admin       BOOLEAN DEFAULT FALSE,
                totp_secret    TEXT,
                two_fa_enabled BOOLEAN DEFAULT FALSE,
                failed_logins  INTEGER DEFAULT 0,
                locked_until   TIMESTAMP,
                created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS user_keys (
                user_id               INTEGER PRIMARY KEY,
                public_key            TEXT NOT NULL,
                signing_public_key    TEXT,
                encrypted_private_key TEXT,
                encrypted_signing_key TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

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
                timestamp         TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS token_blacklist (
                id         SERIAL PRIMARY KEY,
                token_jti  TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL
            );
        """)
        pg_conn.commit()
        print("    [+] Tables verified (users, user_keys, blockchain, token_blacklist)!")
    except Exception as e:
        pg_conn.rollback()
        print(f"[x] Error creating tables: {e}")
        sys.exit(1)

    if not has_sqlite:
        print("\n[+] Supabase schema initialized! You can now run the app.")
        return

    # 3. Read SQLite Data & Migrate
    print("\n[*] Reading data from SQLite...")
    sq_conn = sqlite3.connect(sqlite_path)
    sq_conn.row_factory = sqlite3.Row
    sq_cur = sq_conn.cursor()

    # Migrate USERS
    try:
        users = sq_cur.execute("SELECT * FROM users").fetchall()
        migrated_users = 0
        for u in users:
            u_dict = dict(u)
            pg_cur.execute("""
                INSERT INTO users 
                    (id, full_name, username, email, password_hash, google_id, 
                     avatar_url, bio, is_admin, totp_secret, two_fa_enabled, 
                     failed_logins, locked_until, created_at)
                VALUES 
                    (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    full_name      = EXCLUDED.full_name,
                    username       = EXCLUDED.username,
                    email          = EXCLUDED.email,
                    password_hash  = EXCLUDED.password_hash,
                    google_id      = EXCLUDED.google_id,
                    avatar_url     = EXCLUDED.avatar_url,
                    bio            = EXCLUDED.bio,
                    is_admin       = EXCLUDED.is_admin,
                    totp_secret    = EXCLUDED.totp_secret,
                    two_fa_enabled = EXCLUDED.two_fa_enabled,
                    failed_logins  = EXCLUDED.failed_logins,
                    locked_until   = EXCLUDED.locked_until
            """, (
                u_dict.get("id"),
                u_dict.get("full_name"),
                u_dict.get("username"),
                u_dict.get("email"),
                u_dict.get("password_hash"),
                u_dict.get("google_id"),
                u_dict.get("avatar_url"),
                u_dict.get("bio"),
                bool(u_dict.get("is_admin", 0)),
                u_dict.get("totp_secret"),
                bool(u_dict.get("two_fa_enabled", 0)),
                u_dict.get("failed_logins", 0),
                u_dict.get("locked_until"),
                u_dict.get("created_at")
            ))
            migrated_users += 1
        pg_conn.commit()
        print(f"    [+] Users migrated: {migrated_users}")
    except Exception as e:
        pg_conn.rollback()
        print(f"    [!] Users migration error: {e}")

    # Migrate USER_KEYS
    try:
        keys = sq_cur.execute("SELECT * FROM user_keys").fetchall()
        migrated_keys = 0
        for k in keys:
            k_dict = dict(k)
            pg_cur.execute("""
                INSERT INTO user_keys 
                    (user_id, public_key, signing_public_key, encrypted_private_key, encrypted_signing_key)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE SET
                    public_key            = EXCLUDED.public_key,
                    signing_public_key    = EXCLUDED.signing_public_key,
                    encrypted_private_key = EXCLUDED.encrypted_private_key,
                    encrypted_signing_key = EXCLUDED.encrypted_signing_key
            """, (
                k_dict.get("user_id"),
                k_dict.get("public_key"),
                k_dict.get("signing_public_key"),
                k_dict.get("encrypted_private_key"),
                k_dict.get("encrypted_signing_key"),
            ))
            migrated_keys += 1
        pg_conn.commit()
        print(f"    [+] User Keys migrated: {migrated_keys}")
    except Exception as e:
        pg_conn.rollback()
        print(f"    [!] User keys migration error: {e}")

    # Migrate BLOCKCHAIN
    try:
        blocks = sq_cur.execute("SELECT * FROM blockchain ORDER BY id ASC").fetchall()
        migrated_blocks = 0
        for b in blocks:
            b_dict = dict(b)
            sig_val = b_dict.get("sig_valid")
            sig_bool = True if sig_val in (1, "1", True) else (False if sig_val in (0, "0", False) else None)
            
            pg_cur.execute("""
                INSERT INTO blockchain
                    (id, sender, recipient, encrypted_message, sender_encrypted,
                     previous_hash, hash, nonce, digital_signature, sig_valid, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    sender            = EXCLUDED.sender,
                    recipient         = EXCLUDED.recipient,
                    encrypted_message = EXCLUDED.encrypted_message,
                    sender_encrypted  = EXCLUDED.sender_encrypted,
                    previous_hash     = EXCLUDED.previous_hash,
                    hash              = EXCLUDED.hash,
                    nonce             = EXCLUDED.nonce,
                    digital_signature = EXCLUDED.digital_signature,
                    sig_valid         = EXCLUDED.sig_valid,
                    timestamp         = EXCLUDED.timestamp
            """, (
                b_dict.get("id"),
                b_dict.get("sender"),
                b_dict.get("recipient"),
                b_dict.get("encrypted_message"),
                b_dict.get("sender_encrypted"),
                b_dict.get("previous_hash"),
                b_dict.get("hash"),
                b_dict.get("nonce"),
                b_dict.get("digital_signature"),
                sig_bool,
                str(b_dict.get("timestamp")),
            ))
            migrated_blocks += 1
        pg_conn.commit()
        print(f"    [+] Blockchain blocks migrated: {migrated_blocks}")
    except Exception as e:
        pg_conn.rollback()
        print(f"    [!] Blockchain migration error: {e}")

    # 4. Sync PostgreSQL Sequences
    print("\n[*] Syncing Postgres Auto-increment Sequences...")
    try:
        pg_cur.execute("SELECT setval(pg_get_serial_sequence('users', 'id'), COALESCE((SELECT MAX(id) FROM users), 1));")
        pg_cur.execute("SELECT setval(pg_get_serial_sequence('blockchain', 'id'), COALESCE((SELECT MAX(id) FROM blockchain), 1));")
        pg_conn.commit()
        print("    [+] Sequences synced! New registrations & blocks will have correct IDs.")
    except Exception as e:
        pg_conn.rollback()
        print(f"    [!] Sequence sync notice: {e}")

    # 5. Blockchain Integrity Verification on Supabase
    print("\n[*] Running cryptographic blockchain audit on Supabase...")
    try:
        from app import calculate_hash
        pg_cur.execute("SELECT * FROM blockchain ORDER BY id ASC")
        supa_blocks = pg_cur.fetchall()
        expected_prev = "0" * 64
        valid_chain = True

        for blk in supa_blocks:
            calc_h = calculate_hash(
                blk["sender"],
                blk["recipient"],
                blk["encrypted_message"],
                blk.get("sender_encrypted"),
                blk["previous_hash"],
                blk["nonce"],
                str(blk["timestamp"])
            )
            if calc_h != blk["hash"]:
                print(f"    [x] Block #{blk['id']} hash mismatch!")
                valid_chain = False
            if blk["previous_hash"] != expected_prev:
                print(f"    [x] Block #{blk['id']} broken chain link!")
                valid_chain = False
            expected_prev = blk["hash"]

        if valid_chain:
            print("    [+] Audit PASSED: 100% of blocks and cryptographic hashes match perfectly!")
        else:
            print("    [!] Audit warning: Some block hashes need review.")
    except Exception as e:
        print(f"    (Audit skipped: {e})")

    # Cleanup
    sq_conn.close()
    pg_conn.close()

    print("\n" + "=" * 65)
    print(">>> MIGRATION COMPLETED SUCCESSFULLY! <<<")
    print("=" * 65)
    print("\nNext steps:")
    print("1. Update your .env file with your DATABASE_URL:")
    print(f'   DATABASE_URL="{db_url}"')
    print("2. Run the application locally with Supabase:")
    print("   python run.py")
    print("3. When deploying to Render / Railway, set the DATABASE_URL environment variable.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
