"""
Simple SQLite data layer for Session Manager Pro (Web).
No ORM — plain sqlite3 with small helper functions, mirroring the
style of the original Telegram bot's storage.
"""
import sqlite3
import os
from datetime import datetime, timedelta, timezone

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "webapp.sqlite")


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def get_conn():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        access TEXT NOT NULL DEFAULT 'none',      -- none | trial | premium
        max_sessions INTEGER NOT NULL DEFAULT 1,
        trial_expires TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tg_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        phone TEXT,
        name TEXT,
        session_string TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS broadcasts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        key_hash TEXT UNIQUE NOT NULL,
        key_prefix TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        revoked_at TEXT
    );

    CREATE TABLE IF NOT EXISTS redeem_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        access TEXT NOT NULL,             -- trial | premium
        max_sessions INTEGER NOT NULL DEFAULT 1,
        duration_hours INTEGER,           -- NULL = permanent access (premium); else hours of trial time
        used_by INTEGER REFERENCES users(id),
        used_at TEXT,
        created_at TEXT NOT NULL
    );
    """)
    conn.commit()

    # Seed a default admin account on first run
    cur = conn.execute("SELECT COUNT(*) c FROM users WHERE is_admin = 1")
    if cur.fetchone()["c"] == 0:
        from werkzeug.security import generate_password_hash
        admin_user = os.environ.get("ADMIN_USERNAME", "admin")
        admin_pass = os.environ.get("ADMIN_PASSWORD", "luckyop")
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, access, max_sessions, created_at) "
            "VALUES (?, ?, 1, 'premium', 999, ?)",
            (admin_user, generate_password_hash(admin_pass), now())
        )
        conn.commit()
        print(f"[init_db] Seeded default admin -> username='{admin_user}' password='{admin_pass}' "
              f"(change this immediately / set ADMIN_USERNAME & ADMIN_PASSWORD env vars).")
    conn.close()


# ───────────────────────── users ─────────────────────────

def create_user(username, password_hash):
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, access, max_sessions, trial_expires, created_at) "
            "VALUES (?, ?, 'trial', 1, ?, ?)",
            (username, password_hash, (datetime.now(timezone.utc) + timedelta(hours=1)).replace(tzinfo=None).isoformat(), now())
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def get_user(uid):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return row


def all_users():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return rows


def set_user_access(uid, access, max_sessions=None, trial_hours=None):
    conn = get_conn()
    if access == "trial" and trial_hours:
        expires = (datetime.now(timezone.utc) + timedelta(hours=trial_hours)).replace(tzinfo=None).isoformat()
        conn.execute("UPDATE users SET access=?, trial_expires=? WHERE id=?", (access, expires, uid))
    else:
        conn.execute("UPDATE users SET access=? WHERE id=?", (access, uid))
    if max_sessions is not None:
        conn.execute("UPDATE users SET max_sessions=? WHERE id=?", (max_sessions, uid))
    conn.commit()
    conn.close()


def delete_user(uid):
    conn = get_conn()
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()


def has_access(user_row):
    if not user_row:
        return False
    if user_row["is_admin"]:
        return True
    if user_row["access"] == "premium":
        return True
    if user_row["access"] == "trial":
        exp = user_row["trial_expires"]
        if not exp:
            return False
        return datetime.fromisoformat(exp) > datetime.now(timezone.utc).replace(tzinfo=None)
    return False


# ───────────────────────── sessions ─────────────────────────

def add_session(user_id, phone, name, session_string):
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO tg_sessions (user_id, phone, name, session_string, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, phone, name, session_string, now())
    )
    conn.commit()
    sid = cur.lastrowid
    conn.close()
    return sid


def user_sessions(user_id):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM tg_sessions WHERE user_id=? ORDER BY id", (user_id,)).fetchall()
    conn.close()
    return rows


def count_sessions(user_id):
    conn = get_conn()
    c = conn.execute("SELECT COUNT(*) c FROM tg_sessions WHERE user_id=?", (user_id,)).fetchone()["c"]
    conn.close()
    return c


def get_session(session_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM tg_sessions WHERE id=?", (session_id,)).fetchone()
    conn.close()
    return row


def delete_session(session_id):
    conn = get_conn()
    conn.execute("DELETE FROM tg_sessions WHERE id=?", (session_id,))
    conn.commit()
    conn.close()


def update_session_string(session_id, new_string):
    conn = get_conn()
    conn.execute("UPDATE tg_sessions SET session_string=? WHERE id=?", (new_string, session_id))
    conn.commit()
    conn.close()


# ───────────────────────── stats / broadcasts ─────────────────────────

def stats():
    conn = get_conn()
    users_c = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    sess_c = conn.execute("SELECT COUNT(*) c FROM tg_sessions").fetchone()["c"]
    premium_c = conn.execute("SELECT COUNT(*) c FROM users WHERE access='premium'").fetchone()["c"]
    trial_c = conn.execute("SELECT COUNT(*) c FROM users WHERE access='trial'").fetchone()["c"]
    conn.close()
    return {"users": users_c, "sessions": sess_c, "premium": premium_c, "trial": trial_c}


def add_broadcast(message):
    conn = get_conn()
    conn.execute("INSERT INTO broadcasts (message, created_at) VALUES (?, ?)", (message, now()))
    conn.commit()
    conn.close()


def recent_broadcasts(limit=3):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM broadcasts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


# ───────────────────────── redeem codes ─────────────────────────

def create_redeem_code(code, access, max_sessions, duration_hours=None):
    conn = get_conn()
    conn.execute(
        "INSERT INTO redeem_codes (code, access, max_sessions, duration_hours, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (code, access, max_sessions, duration_hours, now())
    )
    conn.commit()
    conn.close()


def all_redeem_codes():
    conn = get_conn()
    rows = conn.execute("""
        SELECT rc.*, u.username AS used_by_username
        FROM redeem_codes rc LEFT JOIN users u ON u.id = rc.used_by
        ORDER BY rc.id DESC
    """).fetchall()
    conn.close()
    return rows


def get_redeem_code(code):
    conn = get_conn()
    row = conn.execute("SELECT * FROM redeem_codes WHERE code=?", (code,)).fetchone()
    conn.close()
    return row


def redeem_code_for_user(code, user_id):
    """Validate + apply a redeem code to a user, atomically. Returns (ok, message)."""
    conn = get_conn()
    row = conn.execute("SELECT * FROM redeem_codes WHERE code=?", (code,)).fetchone()
    if not row:
        conn.close()
        return False, "Invalid redeem code."
    if row["used_by"] is not None:
        conn.close()
        return False, "This code has already been used."

    if row["access"] == "trial" and row["duration_hours"]:
        expires = (datetime.now(timezone.utc) + timedelta(hours=row["duration_hours"])).replace(tzinfo=None).isoformat()
        conn.execute("UPDATE users SET access='trial', trial_expires=?, max_sessions=? WHERE id=?",
                     (expires, row["max_sessions"], user_id))
    else:
        conn.execute("UPDATE users SET access='premium', max_sessions=? WHERE id=?",
                     (row["max_sessions"], user_id))

    conn.execute("UPDATE redeem_codes SET used_by=?, used_at=? WHERE code=?", (user_id, now(), code))
    conn.commit()
    conn.close()
    return True, f"Code redeemed — {row['access']} access granted ({row['max_sessions']} session(s))."


# ───────────────────────── API keys ─────────────────────────

def add_api_key(user_id, key_hash, key_prefix):
    conn = get_conn()
    cur = conn.execute("INSERT INTO api_keys (user_id, key_hash, key_prefix, created_at) VALUES (?, ?, ?, ?)",
                       (user_id, key_hash, key_prefix, now()))
    conn.commit(); kid = cur.lastrowid; conn.close(); return kid

def get_api_key_by_hash(key_hash):
    conn = get_conn()
    row = conn.execute("SELECT ak.*, u.username, u.is_admin, u.access, u.max_sessions, u.trial_expires FROM api_keys ak JOIN users u ON u.id=ak.user_id WHERE ak.key_hash=? AND ak.revoked_at IS NULL", (key_hash,)).fetchone()
    conn.close(); return row

def user_api_keys(user_id):
    conn = get_conn()
    rows = conn.execute("SELECT id, key_prefix, created_at, last_used_at, revoked_at FROM api_keys WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()
    conn.close(); return rows

def revoke_api_key(key_id, user_id):
    conn = get_conn(); conn.execute("UPDATE api_keys SET revoked_at=? WHERE id=? AND user_id=?", (now(), key_id, user_id)); conn.commit(); conn.close()

def touch_api_key(key_id):
    conn = get_conn(); conn.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (now(), key_id)); conn.commit(); conn.close()
