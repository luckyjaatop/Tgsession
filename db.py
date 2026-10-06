"""
MongoDB data layer for Session Manager Pro (Web).
Drop-in replacement for the original sqlite3-based db.py — every function
keeps the same name, arguments and return shape (dict access like row["col"]),
so app.py and the templates do not need to change.

Fixes the Vercel "unable to open database file" crash: serverless functions
have a read-only filesystem (except /tmp, which is wiped on every cold
start), so a local SQLite file never worked there. Mongo is a real external
database, so there's nothing to "open" on disk at all.

Connection string is hardcoded below (MongoDB Atlas cluster, user ffg201592_db_user).
"""
import os
from datetime import datetime, timedelta, timezone

from pymongo import MongoClient, ASCENDING, ReturnDocument

MONGODB_URI = "mongodb+srv://ffg201592_db_user:hJ5rEFOQQihvqIG1@cluster0.t9gdv1m.mongodb.net/?appName=Cluster0"
DB_NAME = os.environ.get("MONGODB_DB", "session_manager_pro")

_client = None
_db = None


def _get_db():
    global _client, _db
    if _db is None:
        if not MONGODB_URI:
            raise RuntimeError(
                "MONGODB_URI is not set. Add it in Vercel -> Project -> Settings -> "
                "Environment Variables (and locally in your .env)."
            )
        _client = MongoClient(MONGODB_URI)
        _db = _client[DB_NAME]
    return _db


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def _next_id(name):
    """Atomic auto-increment counter, mimics SQLite's AUTOINCREMENT integer ids
    so existing <int:...> Flask routes and templates keep working unchanged."""
    counters = _get_db().counters
    doc = counters.find_one_and_update(
        {"_id": name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return doc["seq"]


def _strip(doc):
    """Drop Mongo's internal _id (ObjectId) -- callers only ever use the
    integer 'id' field, and ObjectId isn't JSON/template friendly."""
    if doc is None:
        return None
    doc = dict(doc)
    doc.pop("_id", None)
    return doc


def init_db():
    database = _get_db()
    database.users.create_index([("username", ASCENDING)], unique=True)
    database.users.create_index([("id", ASCENDING)], unique=True)
    database.tg_sessions.create_index([("id", ASCENDING)], unique=True)
    database.tg_sessions.create_index([("user_id", ASCENDING)])
    database.broadcasts.create_index([("id", ASCENDING)], unique=True)
    database.api_keys.create_index([("id", ASCENDING)], unique=True)
    database.api_keys.create_index([("key_hash", ASCENDING)], unique=True)
    database.api_keys.create_index([("user_id", ASCENDING)])
    database.redeem_codes.create_index([("code", ASCENDING)], unique=True)
    database.redeem_codes.create_index([("id", ASCENDING)], unique=True)

    # Seed a default admin account on first run
    if database.users.count_documents({"is_admin": 1}) == 0:
        from werkzeug.security import generate_password_hash
        admin_user = os.environ.get("ADMIN_USERNAME", "admin")
        admin_pass = os.environ.get("ADMIN_PASSWORD", "luckyop")
        database.users.insert_one({
            "id": _next_id("users"),
            "username": admin_user,
            "password_hash": generate_password_hash(admin_pass),
            "is_admin": 1,
            "access": "premium",
            "max_sessions": 999,
            "trial_expires": None,
            "created_at": now(),
        })
        print(f"[init_db] Seeded default admin -> username='{admin_user}' password='{admin_pass}' "
              f"(change this immediately / set ADMIN_USERNAME & ADMIN_PASSWORD env vars).")


# ───────────────────────── users ─────────────────────────

def create_user(username, password_hash):
    database = _get_db()
    try:
        database.users.insert_one({
            "id": _next_id("users"),
            "username": username,
            "password_hash": password_hash,
            "is_admin": 0,
            "access": "trial",
            "max_sessions": 1,
            "trial_expires": (datetime.now(timezone.utc) + timedelta(hours=1)).replace(tzinfo=None).isoformat(),
            "created_at": now(),
        })
        return True
    except Exception:
        # duplicate username -> unique index violation
        return False


def get_user_by_username(username):
    return _strip(_get_db().users.find_one({"username": username}))


def get_user(uid):
    return _strip(_get_db().users.find_one({"id": int(uid)}))


def all_users():
    return [_strip(d) for d in _get_db().users.find().sort("id", -1)]


def set_user_access(uid, access, max_sessions=None, trial_hours=None):
    database = _get_db()
    update = {"access": access}
    if access == "trial" and trial_hours:
        update["trial_expires"] = (datetime.now(timezone.utc) + timedelta(hours=trial_hours)).replace(tzinfo=None).isoformat()
    if max_sessions is not None:
        update["max_sessions"] = max_sessions
    database.users.update_one({"id": int(uid)}, {"$set": update})


def delete_user(uid):
    _get_db().users.delete_one({"id": int(uid)})


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
    sid = _next_id("tg_sessions")
    _get_db().tg_sessions.insert_one({
        "id": sid,
        "user_id": int(user_id),
        "phone": phone,
        "name": name,
        "session_string": session_string,
        "created_at": now(),
    })
    return sid


def user_sessions(user_id):
    return [_strip(d) for d in _get_db().tg_sessions.find({"user_id": int(user_id)}).sort("id", 1)]


def count_sessions(user_id):
    return _get_db().tg_sessions.count_documents({"user_id": int(user_id)})


def get_session(session_id):
    return _strip(_get_db().tg_sessions.find_one({"id": int(session_id)}))


def delete_session(session_id):
    _get_db().tg_sessions.delete_one({"id": int(session_id)})


def update_session_string(session_id, new_string):
    _get_db().tg_sessions.update_one({"id": int(session_id)}, {"$set": {"session_string": new_string}})


# ───────────────────────── stats / broadcasts ─────────────────────────

def stats():
    database = _get_db()
    return {
        "users": database.users.count_documents({}),
        "sessions": database.tg_sessions.count_documents({}),
        "premium": database.users.count_documents({"access": "premium"}),
        "trial": database.users.count_documents({"access": "trial"}),
    }


def add_broadcast(message):
    _get_db().broadcasts.insert_one({
        "id": _next_id("broadcasts"),
        "message": message,
        "created_at": now(),
    })


def recent_broadcasts(limit=3):
    return [_strip(d) for d in _get_db().broadcasts.find().sort("id", -1).limit(limit)]


# ───────────────────────── redeem codes ─────────────────────────

def create_redeem_code(code, access, max_sessions, duration_hours=None):
    _get_db().redeem_codes.insert_one({
        "id": _next_id("redeem_codes"),
        "code": code,
        "access": access,
        "max_sessions": max_sessions,
        "duration_hours": duration_hours,
        "used_by": None,
        "used_at": None,
        "created_at": now(),
    })


def all_redeem_codes():
    database = _get_db()
    rows = [_strip(d) for d in database.redeem_codes.find().sort("id", -1)]
    for r in rows:
        u = database.users.find_one({"id": r["used_by"]}) if r.get("used_by") else None
        r["used_by_username"] = u["username"] if u else None
    return rows


def get_redeem_code(code):
    return _strip(_get_db().redeem_codes.find_one({"code": code}))


def redeem_code_for_user(code, user_id):
    """Validate + apply a redeem code to a user, atomically. Returns (ok, message)."""
    database = _get_db()
    # Atomically claim the code: only succeeds if it's still unused.
    row = database.redeem_codes.find_one_and_update(
        {"code": code, "used_by": None},
        {"$set": {"used_by": int(user_id), "used_at": now()}},
        return_document=ReturnDocument.AFTER,
    )
    if row is None:
        existing = database.redeem_codes.find_one({"code": code})
        if not existing:
            return False, "Invalid redeem code."
        return False, "This code has already been used."

    if row["access"] == "trial" and row["duration_hours"]:
        expires = (datetime.now(timezone.utc) + timedelta(hours=row["duration_hours"])).replace(tzinfo=None).isoformat()
        database.users.update_one(
            {"id": int(user_id)},
            {"$set": {"access": "trial", "trial_expires": expires, "max_sessions": row["max_sessions"]}},
        )
    else:
        database.users.update_one(
            {"id": int(user_id)},
            {"$set": {"access": "premium", "max_sessions": row["max_sessions"]}},
        )

    return True, f"Code redeemed — {row['access']} access granted ({row['max_sessions']} session(s))."


# ───────────────────────── API keys ─────────────────────────

def add_api_key(user_id, key_hash, key_prefix):
    kid = _next_id("api_keys")
    _get_db().api_keys.insert_one({
        "id": kid,
        "user_id": int(user_id),
        "key_hash": key_hash,
        "key_prefix": key_prefix,
        "created_at": now(),
        "last_used_at": None,
        "revoked_at": None,
    })
    return kid


def get_api_key_by_hash(key_hash):
    database = _get_db()
    row = database.api_keys.find_one({"key_hash": key_hash, "revoked_at": None})
    if not row:
        return None
    user = database.users.find_one({"id": row["user_id"]})
    if not user:
        return None
    merged = _strip(row)
    merged.update({
        "username": user["username"],
        "is_admin": user["is_admin"],
        "access": user["access"],
        "max_sessions": user["max_sessions"],
        "trial_expires": user["trial_expires"],
    })
    return merged


def user_api_keys(user_id):
    rows = _get_db().api_keys.find({"user_id": int(user_id)}).sort("id", -1)
    return [
        {
            "id": r["id"],
            "key_prefix": r["key_prefix"],
            "created_at": r["created_at"],
            "last_used_at": r["last_used_at"],
            "revoked_at": r["revoked_at"],
        }
        for r in rows
    ]


def revoke_api_key(key_id, user_id):
    _get_db().api_keys.update_one(
        {"id": int(key_id), "user_id": int(user_id)},
        {"$set": {"revoked_at": now()}},
    )


def touch_api_key(key_id):
    _get_db().api_keys.update_one({"id": int(key_id)}, {"$set": {"last_used_at": now()}})
