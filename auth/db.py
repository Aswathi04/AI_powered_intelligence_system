"""
auth/db.py

SQLite database setup for Sentinel AI authentication system.

Responsibilities:
  - Create sentinel.db on first run (auto, no manual setup needed)
  - Create the `users` table and `audit_log` table
  - Seed the three default accounts on first run
  - Provide low-level DB helper functions used by auth.py

Tables
------
users
  id            INTEGER  PRIMARY KEY AUTOINCREMENT
  username      TEXT     UNIQUE NOT NULL
  password_hash TEXT     NOT NULL        -- hashed, never plain text
  salt          TEXT     NOT NULL        -- unique per user
  role          TEXT     NOT NULL        -- 'security' | 'administrator' | 'supervisor'
  full_name     TEXT     NOT NULL
  email         TEXT
  is_active     INTEGER  DEFAULT 1       -- 0 = disabled account
  created_at    TEXT     NOT NULL
  last_login    TEXT                     -- NULL until first login

audit_log
  id            INTEGER  PRIMARY KEY AUTOINCREMENT
  username      TEXT     NOT NULL
  action        TEXT     NOT NULL        -- e.g. 'LOGIN', 'LOGOUT', 'ALERT_ACK'
  detail        TEXT                     -- optional extra context
  ip_address    TEXT                     -- reserved for future use
  timestamp     TEXT     NOT NULL

Default accounts (change passwords after first login):
  username: security_officer   password: Security@123   role: security
  username: admin              password: Admin@123      role: administrator
  username: supervisor         password: Supervisor@123 role: supervisor
"""

import sqlite3
import secrets
import hashlib
import hmac
import os
from datetime import datetime

# Path to the database file — sits in the project root alongside sentinel_dashboard.py
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sentinel.db")


# ---------------------------------------------------------------------------
# Password hashing  (bcrypt if available, otherwise PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------

def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """
    Hash a plain-text password.  Returns (hash_hex, salt_hex).

    Uses bcrypt when installed (pip install bcrypt) for strongest security.
    Falls back to PBKDF2-HMAC-SHA256 with 600,000 iterations — NIST-approved
    and perfectly safe for a local security system with 3 users.

    Args:
        password : plain-text password string
        salt     : existing salt hex string (pass when verifying),
                   or None to generate a fresh one (pass when creating)

    Returns:
        (hash_hex, salt_hex) — both are hex strings safe to store in SQLite
    """
    try:
        import bcrypt
        if salt is None:
            # New password — generate hash with built-in salt
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
            return hashed.decode(), "bcrypt"   # salt is embedded in bcrypt hash
        else:
            # Verification path — salt field holds "bcrypt" as a marker
            return password, salt   # comparison done in verify_password
    except ImportError:
        pass

    # PBKDF2 fallback
    if salt is None:
        salt = secrets.token_hex(32)   # 256-bit random salt
    dk = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),
        salt=bytes.fromhex(salt),
        iterations=600_000,
    )
    return dk.hex(), salt


def verify_password(plain: str, stored_hash: str, salt: str) -> bool:
    """
    Return True if `plain` matches the stored hash.
    Handles both bcrypt and PBKDF2 hashes transparently.
    """
    try:
        import bcrypt
        if salt == "bcrypt":
            return bcrypt.checkpw(plain.encode(), stored_hash.encode())
    except ImportError:
        pass

    # PBKDF2 verification — recompute and compare with constant-time hmac.compare_digest
    recomputed, _ = _hash_password(plain, salt)
    return hmac.compare_digest(recomputed, stored_hash)


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    """
    Return a sqlite3 connection with row_factory set so rows behave
    like dicts (access columns by name: row['username']).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # safe for concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# Schema creation
# ---------------------------------------------------------------------------

def _create_tables(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            salt          TEXT    NOT NULL,
            role          TEXT    NOT NULL
                            CHECK(role IN ('security','administrator','supervisor')),
            full_name     TEXT    NOT NULL,
            email         TEXT    DEFAULT '',
            is_active     INTEGER DEFAULT 1,
            created_at    TEXT    NOT NULL,
            last_login    TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            action     TEXT NOT NULL,
            detail     TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            timestamp  TEXT NOT NULL
        );
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# Seed default accounts
# ---------------------------------------------------------------------------

_DEFAULT_USERS = [
    {
        "username":  "security_officer",
        "password":  "Security@123",
        "role":      "security",
        "full_name": "Security Officer",
        "email":     "security@sentinel.local",
    },
    {
        "username":  "admin",
        "password":  "Admin@123",
        "role":      "administrator",
        "full_name": "System Administrator",
        "email":     "admin@sentinel.local",
    },
    {
        "username":  "supervisor",
        "password":  "Supervisor@123",
        "role":      "supervisor",
        "full_name": "System Supervisor",
        "email":     "supervisor@sentinel.local",
    },
]


def _seed_users(conn: sqlite3.Connection):
    """Insert default accounts only if the users table is empty."""
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count > 0:
        return   # already seeded — don't overwrite

    now = datetime.now().isoformat()
    for user in _DEFAULT_USERS:
        pw_hash, salt = _hash_password(user["password"])
        conn.execute(
            """
            INSERT INTO users
                (username, password_hash, salt, role, full_name, email, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["username"],
                pw_hash,
                salt,
                user["role"],
                user["full_name"],
                user["email"],
                now,
            ),
        )
    conn.commit()
    print("[DB] Default accounts created.")


# ---------------------------------------------------------------------------
# Public user functions
# ---------------------------------------------------------------------------

def get_user(username: str) -> sqlite3.Row | None:
    """
    Fetch a single user row by username.
    Returns None if not found.
    """
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,)
        ).fetchone()


def update_last_login(username: str):
    """Stamp the last_login column with the current timestamp."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET last_login = ? WHERE username = ?",
            (datetime.now().isoformat(), username)
        )
        conn.commit()


def get_all_users() -> list[sqlite3.Row]:
    """Return all user rows — used by the admin page to manage accounts."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT id, username, role, full_name, email, is_active, "
            "created_at, last_login FROM users ORDER BY role, username"
        ).fetchall()


def add_user(username: str, password: str, role: str,
             full_name: str, email: str = "") -> bool:
    """
    Create a new user account.
    Returns True on success, False if username already exists.
    """
    pw_hash, salt = _hash_password(password)
    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users
                    (username, password_hash, salt, role, full_name, email, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (username, pw_hash, salt, role, full_name, email,
                 datetime.now().isoformat())
            )
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False   # username already exists


def update_password(username: str, new_password: str) -> bool:
    """Update a user's password. Returns True on success."""
    pw_hash, salt = _hash_password(new_password)
    with get_connection() as conn:
        rows = conn.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
            (pw_hash, salt, username)
        ).rowcount
        conn.commit()
    return rows > 0


def set_user_active(username: str, is_active: bool) -> bool:
    """Enable or disable a user account."""
    with get_connection() as conn:
        rows = conn.execute(
            "UPDATE users SET is_active = ? WHERE username = ?",
            (int(is_active), username)
        ).rowcount
        conn.commit()
    return rows > 0


# ---------------------------------------------------------------------------
# Audit log functions
# ---------------------------------------------------------------------------

def log_action(username: str, action: str, detail: str = ""):
    """
    Write one row to the audit_log table.

    Common action strings used across the system:
      'LOGIN'        — successful login
      'LOGIN_FAILED' — wrong password attempt
      'LOGOUT'       — user logged out
      'ALERT_ACK'    — security officer acknowledged an alert
      'ALERT_DISMISS'— security officer dismissed an alert
      'CONFIG_CHANGE'— administrator changed a system setting
      'REPORT_GEN'   — supervisor generated a report
    """
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO audit_log (username, action, detail, timestamp) "
            "VALUES (?, ?, ?, ?)",
            (username, action, detail, datetime.now().isoformat())
        )
        conn.commit()


def get_audit_log(limit: int = 200) -> list[sqlite3.Row]:
    """Return the most recent `limit` audit log entries, newest first."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()


def get_audit_log_for_user(username: str, limit: int = 100) -> list[sqlite3.Row]:
    """Return audit entries for a specific user."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM audit_log WHERE username = ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (username, limit)
        ).fetchall()


# ---------------------------------------------------------------------------
# Initialise on import
# ---------------------------------------------------------------------------

def init_db():
    """
    Create tables and seed default users.
    Safe to call multiple times — it checks before creating/inserting.
    Called automatically when this module is first imported.
    """
    os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else ".", exist_ok=True)
    with get_connection() as conn:
        _create_tables(conn)
        _seed_users(conn)
    print(f"[DB] sentinel.db ready at: {DB_PATH}")


# Run on import so sentinel_dashboard.py needs zero setup code
init_db()