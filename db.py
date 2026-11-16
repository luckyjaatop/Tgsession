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




def acquire_session_lease(session_id, owner, ttl_seconds=180):
    """Acquire a distributed MongoDB lease for a Telegram session.

    This prevents the same Telegram auth key from being connected from two
    Vercel/serverless instances at the same time. Returns True on success.
    """
    database = _get_db()
    sid = int(session_id)
    expires = datetime.now(timezone.utc) + timedelta(seconds=int(ttl_seconds))
    doc = database.tg_session_locks.find_one_and_update(
        {
            "_id": sid,
            "$or": [
                {"expires_at": {"$lte": expires}},
                {"owner": owner},
                {"owner": {"$exists": False}},
            ],
        },
        {"$set": {"owner": owner, "expires_at": expires}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return bool(doc and doc.get("owner") == owner)


def release_session_lease(session_id, owner):
    """Release a distributed Telegram-session lease only if we own it."""
    try:
        _get_db().tg_session_locks.delete_one({"_id": int(session_id), "owner": owner})
    except Exception:
        pass

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
    database.tg_session_locks.create_index([("expires_at", ASCENDING)])
    database.redeem_codes.create_index([("code", ASCENDING)], unique=True)
    database.redeem_codes.create_index([("id", ASCENDING)], unique=True)
    database.registrations.create_index([("ip", ASCENDING), ("created_at", ASCENDING)])
    database.orders.create_index([("order_id", ASCENDING)], unique=True)
    database.orders.create_index([("user_id", ASCENDING)])
    database.pending_logins.create_index([("token", ASCENDING)], unique=True)
    database.pending_logins.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)

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


def record_registration(ip):
    """Log a signup's IP so repeat free-trial signups from the same network
    can be rate-limited."""
    _get_db().registrations.insert_one({
        "id": _next_id("registrations"),
        "ip": ip,
        "created_at": now(),
    })


def count_recent_registrations(ip, hours=24):
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).replace(tzinfo=None).isoformat()
    return _get_db().registrations.count_documents({"ip": ip, "created_at": {"$gte": cutoff}})


def get_user_by_username(username):
    return _strip(_get_db().users.find_one({"username": username}))


def get_user(uid):
    return _strip(_get_db().users.find_one({"id": int(uid)}))


def set_session_token(uid, token):
    """Logging in anywhere overwrites this, so a previously-logged-in
    browser's old token stops matching and gets signed out automatically —
    only one active website login per account at a time."""
    _get_db().users.update_one({"id": int(uid)}, {"$set": {"session_token": token}})


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


def grant_premium(uid, days, max_sessions=None):
    """Grant (or extend) paid premium access for `days` days. If the account
    already has active premium time left, the new period stacks on top of
    it instead of overwriting it."""
    database = _get_db()
    current = database.users.find_one({"id": int(uid)})
    now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
    base = now_dt
    if current and current.get("access") == "premium" and current.get("premium_expires"):
        try:
            existing_exp = datetime.fromisoformat(current["premium_expires"])
            if existing_exp > now_dt:
                base = existing_exp
        except Exception:
            pass
    new_exp = (base + timedelta(days=days)).isoformat()
    update = {"access": "premium", "premium_expires": new_exp}
    if max_sessions is not None:
        update["max_sessions"] = max_sessions
    database.users.update_one({"id": int(uid)}, {"$set": update})
    return new_exp


def create_order_record(order_id, user_id, plan_id, amount, days, extra=None):
    doc = {
        "order_id": order_id,
        "user_id": int(user_id),
        "plan_id": plan_id,
        "amount": amount,
        "days": days,
        "status": "pending",
        "fulfilled": False,
        "created_at": now(),
    }
    if extra:
        doc.update(extra)
    _get_db().orders.insert_one(doc)


def get_order(order_id):
    return _strip(_get_db().orders.find_one({"order_id": order_id}))


def mark_order_fulfilled(order_id):
    """Atomically flips an order to fulfilled; returns True only the first
    time this succeeds, so a webhook firing at the same moment as the
    browser's own status poll can never grant access twice."""
    res = _get_db().orders.update_one(
        {"order_id": order_id, "fulfilled": False},
        {"$set": {"fulfilled": True, "status": "paid", "fulfilled_at": now()}},
    )
    return res.modified_count == 1


def mark_order_status(order_id, status):
    _get_db().orders.update_one({"order_id": order_id}, {"$set": {"status": status}})


def user_orders(user_id, limit=10):
    rows = _get_db().orders.find({"user_id": int(user_id)}).sort("created_at", -1).limit(limit)
    return [_strip(d) for d in rows]


def has_access(user_row):
    if not user_row:
        return False
    if user_row["is_admin"]:
        return True
    if user_row["access"] == "premium":
        exp = user_row.get("premium_expires")
        if not exp:
            return True  # permanent grant (e.g. set by an admin with no expiry)
        return datetime.fromisoformat(exp) > datetime.now(timezone.utc).replace(tzinfo=None)
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


def update_session_phone(session_id, new_phone, new_name=None):
    updates = {"phone": new_phone}
    if new_name:
        updates["name"] = new_name
    _get_db().tg_sessions.update_one({"id": int(session_id)}, {"$set": updates})


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
    # API policy: one key per account. Generating a new key permanently
    # removes the previous key so it can no longer authenticate API calls —
    # this also means a key you shared with someone else stops working the
    # moment you regenerate.
    database = _get_db()
    database.api_keys.delete_many({"user_id": int(user_id)})
    kid = _next_id("api_keys")
    database.api_keys.insert_one({
        "id": kid,
        "user_id": int(user_id),
        "key_hash": key_hash,
        "key_prefix": key_prefix,
        "created_at": now(),
        "last_used_at": None,
        "revoked_at": None,
        "bound_ip": None,
    })
    return kid


def check_and_bind_api_key_ip(key_id, ip, grace_seconds=45):
    """Soft anti-sharing check. Mobile networks (carrier NAT) rotate a
    single phone's IP constantly, so locking to one IP forever causes
    false "locked to another device" failures on normal mobile data.
    Instead: only reject when a DIFFERENT IP showed up very recently
    (grace_seconds) — that pattern means two places are active near-
    simultaneously, which is what real sharing looks like. A normal
    network change over time just re-binds quietly."""
    database = _get_db().api_keys
    row = database.find_one({"id": int(key_id)})
    if not row:
        return False

    now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
    last_ip = row.get("bound_ip")

    if not last_ip:
        database.update_one({"id": int(key_id)}, {"$set": {"bound_ip": ip, "ip_last_seen": now_dt.isoformat()}})
        return True

    if last_ip == ip:
        database.update_one({"id": int(key_id)}, {"$set": {"ip_last_seen": now_dt.isoformat()}})
        return True

    too_soon = False
    last_seen_raw = row.get("ip_last_seen")
    if last_seen_raw:
        try:
            too_soon = (now_dt - datetime.fromisoformat(last_seen_raw)).total_seconds() < grace_seconds
        except Exception:
            too_soon = False

    if too_soon:
        return False  # a different IP was active moments ago — likely genuine concurrent use

    database.update_one({"id": int(key_id)}, {"$set": {"bound_ip": ip, "ip_last_seen": now_dt.isoformat()}})
    return True


def reset_api_key_binding(user_id):
    """Lets the account owner clear the IP lock (e.g. after switching
    networks) from the website, without regenerating the key itself."""
    _get_db().api_keys.update_many({"user_id": int(user_id)}, {"$set": {"bound_ip": None, "ip_last_seen": None}})


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
            "bound_ip": r.get("bound_ip"),
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

# ───────────────────────── pending OTP logins ─────────────────────────

def create_pending_login(user_id, phone, phone_code_hash, temp_session, api_id, api_hash, ttl_seconds=600):
    import secrets
    token = secrets.token_urlsafe(24)
    expires = datetime.now(timezone.utc) + timedelta(seconds=int(ttl_seconds))
    _get_db().pending_logins.insert_one({
        "token": token,
        "user_id": int(user_id),
        "phone": phone,
        "phone_code_hash": phone_code_hash,
        "temp_session": temp_session,
        "api_id": int(api_id),
        "api_hash": api_hash,
        "needs_password": False,
        "hint": "",
        "expires_at": expires,
        "created_at": now(),
    })
    return token


def get_pending_login(token, user_id):
    doc = _get_db().pending_logins.find_one({"token": token, "user_id": int(user_id)})
    if not doc:
        return None
    exp = doc.get("expires_at")
    if exp is not None:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= datetime.now(timezone.utc):
            delete_pending_login(token)
            return None
    return _strip(doc)


def update_pending_login(token, **fields):
    if fields:
        _get_db().pending_logins.update_one({"token": token}, {"$set": fields})


def delete_pending_login(token):
    _get_db().pending_logins.delete_one({"token": token})
