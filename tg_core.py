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
import time
import base64
import json
import struct
import uuid
import contextvars
from functools import wraps

import db

from telethon import TelegramClient, events
from telethon.crypto import AuthKey
from telethon.sessions import StringSession
from telethon.errors import (
    SessionPasswordNeededError, PhoneCodeInvalidError, PhoneCodeExpiredError,
    PasswordHashInvalidError, PhoneNumberInvalidError, PhoneNumberBannedError
)
from telethon.tl.functions.account import (
    GetAuthorizationsRequest, ResetAuthorizationRequest,
    GetPasswordRequest, ResetPasswordRequest, UpdateProfileRequest, UpdateUsernameRequest
)
from telethon.tl.functions.contacts import (
    GetContactsRequest, DeleteContactsRequest, GetBlockedRequest, UnblockRequest, SearchRequest, AddContactRequest, ImportContactsRequest, ResolveUsernameRequest
)
from telethon.tl.functions.photos import UploadProfilePhotoRequest
from telethon.tl.functions.channels import JoinChannelRequest, GetFullChannelRequest
from telethon.tl.functions.messages import (
    ImportChatInviteRequest, GetCustomEmojiDocumentsRequest, GetFullChatRequest
)
try:
    from telethon.tl.functions.messages import (
        SendReactionRequest, GetAllStickersRequest, GetStickerSetRequest,
        GetRecentStickersRequest
    )
except ImportError:
    SendReactionRequest = None
    GetAllStickersRequest = None
    GetStickerSetRequest = None
    GetRecentStickersRequest = None
from telethon.tl.functions.users import GetFullUserRequest
from telethon.errors import FloodWaitError
from telethon.tl.types import (
    PeerUser, PeerChat, PeerChannel, MessageEntityCustomEmoji, InputPhoneContact
)
try:
    from telethon.tl.types import (
        InputDocument, InputStickerSetID, ReactionEmoji, DocumentAttributeSticker
    )
except ImportError:
    InputDocument = None
    InputStickerSetID = None
    ReactionEmoji = None
    DocumentAttributeSticker = None
from telethon.utils import get_peer_id

API_ID = int(os.environ.get("TELEGRAM_API_ID", "38785545"))
API_HASH = os.environ.get("TELEGRAM_API_HASH", "d5ad8c7bd2b01e837e2deb0b41dee770")
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


DC_IPS = {
    1: "149.154.175.53",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "91.108.56.130",
}


def _build_telethon_string(dc_id: int, key_bytes: bytes) -> str:
    if dc_id not in DC_IPS or len(key_bytes) != 256:
        raise ValueError("Invalid DC ID or auth key length.")
    ss = StringSession()
    ss.set_dc(int(dc_id), DC_IPS[int(dc_id)], 443)
    ss.auth_key = AuthKey(data=key_bytes)
    return ss.save()


def _safe_b64_decode(val: str) -> bytes:
    cleaned = re.sub(r"\s+", "", val)
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    pad = (-len(cleaned)) % 4
    if pad:
        cleaned += "=" * pad
    return base64.b64decode(cleaned)


def _parse_text_candidates(raw_text: str, dc_id_hint: int | None = None):
    """Parse Telethon, Pyrogram v1/v2, JSON, or 512-char Hex Auth Key strings.
    Returns list of (telethon_string, detected_type, dc_id)."""
    s = raw_text.strip()
    if not s:
        return []

    if s.startswith("{") and s.endswith("}"):
        try:
            obj = json.loads(s)
            nested = (
                obj.get("session_string")
                or obj.get("sessionString")
                or obj.get("session")
                or obj.get("string")
                or obj.get("telethon")
                or obj.get("pyrogram")
            )
            if isinstance(nested, str) and nested.strip():
                return _parse_text_candidates(nested, dc_id_hint=dc_id_hint)
            key = obj.get("auth_key") or obj.get("authKey") or obj.get("key") or obj.get("hex")
            dc = obj.get("dc_id") or obj.get("dcId") or obj.get("dc") or dc_id_hint
            if isinstance(key, str) and dc is not None:
                dc_int = int(dc)
                kclean = re.sub(r"\s+", "", key)
                key_bytes = bytes.fromhex(kclean) if re.fullmatch(r"[0-9a-fA-F]{512}", kclean) else _safe_b64_decode(kclean)
                return [(_build_telethon_string(dc_int, key_bytes), "JSON Session Data", dc_int)]
        except Exception:
            pass

    clean = re.sub(r"\s+", "", s)
    if re.fullmatch(r"[0-9a-fA-F]{512}", clean):
        key_bytes = bytes.fromhex(clean)
        dcs = [int(dc_id_hint)] if dc_id_hint in DC_IPS else [2, 4, 1, 5, 3]
        return [(_build_telethon_string(dc, key_bytes), "Hex Auth Key", dc) for dc in dcs]

    if clean.startswith("1"):
        try:
            parsed = StringSession(clean)
            if parsed.auth_key and len(parsed.auth_key.key) == 256:
                return [(clean, "Telethon String Session", int(parsed.dc_id or 2))]
        except Exception:
            pass

    try:
        decoded = _safe_b64_decode(clean)
        ln = len(decoded)
        if ln == 271 and decoded[0] in DC_IPS:
            dc = int(decoded[0])
            return [(_build_telethon_string(dc, decoded[6:262]), "Pyrogram v2 Session", dc)]
        if ln in (267, 263) and decoded[0] in DC_IPS:
            dc = int(decoded[0])
            return [(_build_telethon_string(dc, decoded[2:258]), "Pyrogram v1 Session", dc)]
        if ln == 260 and decoded[0] in DC_IPS:
            dc = int(decoded[0])
            return [(_build_telethon_string(dc, decoded[4:260]), "Pyrogram Session", dc)]
        if ln >= 261 and decoded[0] in DC_IPS:
            dc = int(decoded[0])
            return [(_build_telethon_string(dc, decoded[-256:]), "Telethon String Session", dc)]
    except Exception:
        pass

    return [(s, "Telethon String Session", int(dc_id_hint or 2))]


async def _load_from_raw(raw: bytes, dc_id_hint: int | None = None):
    """Try to build a connected, authorized client from raw bytes (Telethon,
    Pyrogram, JSON, Hex Auth Key, or SQLite .session file).
    Returns (client, session_string, detected_type, dc_id) or (None, None, None, None)."""
    is_sqlite = raw[:16] == b"SQLite format 3\x00"
    if not is_sqlite:
        try:
            ss_text = raw.decode("utf-8").strip()
            for candidate_ss, dtype, dc_id in _parse_text_candidates(ss_text, dc_id_hint=dc_id_hint):
                for aid, ahash in API_PAIRS:
                    try:
                        cl = await _connect_string(candidate_ss, aid, ahash)
                        if cl:
                            return cl, candidate_ss, dtype, dc_id
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
                    dc_id = int(getattr(cl.session, "dc_id", 2) or 2)
                    await cl.disconnect()
                    cl2 = await _connect_string(ss_str, aid, ahash)
                    if cl2:
                        return cl2, ss_str, "SQLite .session File", dc_id
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
    return None, None, None, None


def inspect_session_bytes(raw: bytes, dc_id_hint: int | None = None):
    """Validate and inspect session bytes without saving to DB."""
    async def _inspect():
        cl, ss, dtype, dc_id = await _load_from_raw(raw, dc_id_hint=dc_id_hint)
        if not cl:
            return None
        try:
            me = await cl.get_me()
            if not me:
                return None
            name = f"{me.first_name or ''} {me.last_name or ''}".strip() or "Telegram User"
            phone = me.phone or ""
            username = getattr(me, "username", None) or ""
            return {
                "valid": True,
                "type": dtype or "Telethon String Session",
                "dc_id": int(dc_id or 2),
                "user_id": int(me.id),
                "name": name,
                "phone": phone,
                "username": username,
                "session_string": ss,
            }
        finally:
            try:
                await cl.disconnect()
            except Exception:
                pass

    info = run_async(_inspect())
    if not info:
        raise ValueError("Could not authorize this session (invalid, expired, or revoked).")
    return info


def login_from_bytes(raw: bytes, dc_id_hint: int | None = None):
    """Sync wrapper: returns (session_string, name, phone) or raises ValueError."""
    info = inspect_session_bytes(raw, dc_id_hint=dc_id_hint)
    return info["session_string"], info["name"], info["phone"] or "unknown"


def validate_session(session_row):
    """Check whether a stored Telegram session is still authorized.

    Returns:
      True  -> Telegram still authorizes the session.
      False -> Telegram explicitly says the authorization is gone/revoked.
      None  -> could not decide because the failure looks transient.

    This deliberately does not cache the result: the session-list endpoint uses
    it to reconcile the app database with Telegram after a session is revoked
    or logged out elsewhere.
    """
    ss = (session_row.get("session_string") or "").strip()
    if not ss:
        return False

    definitive = False
    transient = False

    async def _check():
        nonlocal definitive, transient
        for aid, ahash in API_PAIRS:
            cl = TelegramClient(StringSession(ss), aid, ahash)
            try:
                await cl.connect()
                authorized = await cl.is_user_authorized()
                if authorized:
                    return True
                definitive = True
            except Exception as exc:
                name = exc.__class__.__name__.lower()
                # These indicate the Telegram authorization itself is no longer
                # usable. Other errors may simply be a temporary network/DC issue.
                if any(x in name for x in (
                    "authkeyunregistered", "authkeyduplicated", "sessionrevoked",
                    "sessionexpired", "userdeactivated", "userdeactivatedban",
                    "unauthorized",
                )):
                    definitive = True
                else:
                    transient = True
            finally:
                try:
                    await cl.disconnect()
                except Exception:
                    pass
        return None

    result = run_async(_check(), timeout=30)
    if result is True:
        return True
    if definitive and not transient:
        return False
    return None


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


_session_context = contextvars.ContextVar("tg_session_context", default=None)


def _serialized_telegram(fn):
    """Serialize access to one Telegram auth key across Vercel instances.

    Telegram can invalidate an authorization key when the same key is actively
    connected from different IPs. Vercel may run two requests on different
    instances, so an in-memory Python lock is not enough. A short Mongo lease
    makes the session exclusive for the duration of each Telegram operation.
    The client is disconnected after the outer operation so another request can
    safely use the session later.
    """
    @wraps(fn)
    def wrapper(session_row, *args, **kwargs):
        sid = int(session_row["id"])
        current = _session_context.get()
        nested = bool(current and current.get("sid") == sid)
        token = None
        owner = None
        outer = not nested

        if outer:
            owner = f"{os.environ.get('VERCEL_INSTANCE_ID', 'server')}:{uuid.uuid4().hex}"
            deadline = time.monotonic() + 25.0
            acquired = False
            while time.monotonic() < deadline:
                try:
                    acquired = db.acquire_session_lease(sid, owner, ttl_seconds=180)
                except Exception:
                    acquired = False
                if acquired:
                    break
                time.sleep(0.25)
            if not acquired:
                raise RuntimeError("Telegram session is busy on another server instance. Please retry in a moment.")
            token = _session_context.set({"sid": sid, "owner": owner})

        try:
            return fn(session_row, *args, **kwargs)
        finally:
            if outer:
                try:
                    drop_client(sid)
                finally:
                    try:
                        db.release_session_lease(sid, owner)
                    except Exception:
                        pass
                    if token is not None:
                        _session_context.reset(token)

    return wrapper


# ─────────────────────── feature functions ───────────────────────

@_serialized_telegram
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


@_serialized_telegram
def send_message(session_row, target, text, reply_to=None, fallback_username=None):
    """Send a text message from this session's account to `target`, which can
    be a @username (str) or an existing dialog's peer id (int)."""
    cl = get_client(session_row)

    async def _f():
        entity = await _resolve_entity_async(cl, target, fallback_username=fallback_username)
        cls = entity.__class__.__name__.lower()
        is_broadcast_channel = bool(cls.endswith("channel") and not getattr(entity, "megagroup", False))
        if is_broadcast_channel:
            try:
                perms = await cl.get_permissions(entity, "me")
                admin_rights = getattr(perms, "admin_rights", None)
                allowed = bool(
                    getattr(perms, "is_creator", False)
                    or (getattr(perms, "is_admin", False) and admin_rights is not None and getattr(admin_rights, "post_messages", False))
                )
            except Exception:
                allowed = False
            if not allowed:
                raise PermissionError("You cannot send messages in this channel because this account is not an admin with posting permission.")

        msg = await cl.send_message(entity, text, reply_to=(int(reply_to) if reply_to else None))
        is_group = bool(getattr(entity, "megagroup", False) or cls.endswith("chat"))
        return {
            "message_id": msg.id,
            "to": str(target),
            "sent_at": str(msg.date),
            "message": _message_dict(msg, is_group=is_group),
        }

    return run_async(_f())


@_serialized_telegram
def list_dialogs(session_row, limit=80):
    """Return the account's dialogs with photo/username metadata for the
    Telegram-style main chat list."""
    cl = get_client(session_row)

    async def _f():
        out = []
        async for d in cl.iter_dialogs(limit=limit):
            last = d.message
            entity = d.entity
            if d.is_user:
                first = getattr(entity, "first_name", "") or ""
                last_name = getattr(entity, "last_name", "") or ""
                display_name = (f"{first} {last_name}").strip() or getattr(entity, "username", None) or "Unknown"
                if getattr(entity, "is_self", False):
                    display_name = "Saved Messages"
            else:
                display_name = getattr(entity, "title", None) or d.name or "Unknown"
            out.append({
                "id": d.id,
                "name": display_name,
                "username": getattr(entity, "username", None),
                "is_user": d.is_user,
                "is_bot": bool(getattr(entity, "bot", False)),
                "is_group": d.is_group,
                "is_channel": bool(d.is_channel and not d.is_group),
                "is_broadcast": bool(d.is_channel and not d.is_group),
                "has_photo": bool(getattr(entity, "photo", None)),
                "unread_count": d.unread_count,
                "last_text": (last.text if (last and last.text) else ("[media]" if (last and last.media) else "")),
                "last_date": str(last.date) if last else "",
                "last_out": bool(last.out) if last else False,
            })
        return out

    return run_async(_f())


def _normalize_peer(peer_ref):
    if isinstance(peer_ref, str):
        peer_ref = peer_ref.strip()
        m = re.match(r"^(?:https?://)?(?:t\.me|telegram\.me)/([A-Za-z0-9_]{3,})(?:[/?#].*)?$", peer_ref, re.IGNORECASE)
        if m and m.group(1).lower() not in ("joinchat", "c"):
            peer_ref = m.group(1)
        if peer_ref.startswith("@"):
            peer_ref = peer_ref[1:]
        if peer_ref.lstrip("-").isdigit():
            peer_ref = int(peer_ref)
    return peer_ref


def _format_user_status(entity):
    if bool(getattr(entity, "bot", False)):
        return "bot"
    status = getattr(entity, "status", None)
    if not status:
        return "last seen recently"
    sname = status.__class__.__name__.lower()
    if "online" in sname:
        return "online"
    if "recently" in sname:
        return "last seen recently"
    if "lastweek" in sname:
        return "last seen within a week"
    if "lastmonth" in sname:
        return "last seen within a month"
    if "offline" in sname:
        return "last seen recently"
    return "last seen a long time ago"


def _entity_summary(entity):
    cls = entity.__class__.__name__.lower()
    is_user = hasattr(entity, "first_name")
    is_bot = bool(getattr(entity, "bot", False))
    is_channel = cls.endswith("channel")
    is_megagroup = bool(getattr(entity, "megagroup", False))
    is_group = is_megagroup or cls.endswith("chat")
    is_broadcast = bool(is_channel and not is_megagroup)
    if is_user:
        first = getattr(entity, "first_name", "") or ""
        last = getattr(entity, "last_name", "") or ""
        name = (f"{first} {last}").strip() or getattr(entity, "username", None) or "Unknown"
        if getattr(entity, "is_self", False):
            name = "Saved Messages"
    else:
        name = getattr(entity, "title", None) or "Unknown"
    left_flag = getattr(entity, "left", None)
    is_member = (not bool(left_flag)) if (is_channel or is_group) and left_flag is not None else True
    return {
        "id": get_peer_id(entity),
        "name": name,
        "username": getattr(entity, "username", None),
        "is_user": is_user,
        "is_bot": is_bot,
        "is_group": is_group,
        "is_channel": is_broadcast,
        "is_broadcast": is_broadcast,
        "verified": bool(getattr(entity, "verified", False)),
        "has_photo": bool(getattr(entity, "photo", None)),
        "participants_count": getattr(entity, "participants_count", None),
        "is_member": is_member,
        "status": _format_user_status(entity) if is_user else None,
    }


async def _resolve_entity_async(cl, peer_ref, fallback_username=None):
    peer_ref = _normalize_peer(peer_ref)
    try:
        return await cl.get_entity(peer_ref)
    except (ValueError, TypeError):
        await cl.get_dialogs(limit=300)
        try:
            return await cl.get_entity(peer_ref)
        except (ValueError, TypeError):
            if isinstance(peer_ref, int):
                if peer_ref > 0:
                    try:
                        return await cl.get_entity(PeerUser(peer_ref))
                    except Exception:
                        pass
                else:
                    for candidate in (PeerChannel(peer_ref), PeerChat(peer_ref)):
                        try:
                            return await cl.get_entity(candidate)
                        except Exception:
                            pass
            uname = (fallback_username or "").strip().lstrip("@")
            if uname:
                try:
                    return await cl.get_entity(uname)
                except Exception:
                    try:
                        res = await cl(ResolveUsernameRequest(uname))
                        users = getattr(res, "users", None) or []
                        chats = getattr(res, "chats", None) or []
                        if users or chats:
                            return (users + chats)[0]
                    except Exception:
                        pass
            raise


def _message_media_info(m):
    file_obj = getattr(m, "file", None)
    mime = getattr(file_obj, "mime_type", None)
    name = getattr(file_obj, "name", None)
    media = None
    if getattr(m, "sticker", None):
        if mime and ("tgsticker" in mime or mime == "application/x-tgsticker"):
            media = "sticker"
        elif mime == "video/webm" or (name and name.lower().endswith(".webm")):
            media = "sticker_video"
        else:
            media = "sticker"
    elif getattr(m, "photo", None):
        media = "photo"
    elif getattr(m, "gif", None):
        media = "gif"
    elif mime and mime.startswith("video/"):
        media = "video"
    elif getattr(m, "voice", None):
        media = "voice"
    elif mime and mime.startswith("audio/"):
        media = "audio"
    elif getattr(m, "document", None):
        media = "document"
    elif m.media:
        media = "media"
    return media, mime, name


def _sender_fields(sender):
    if not sender:
        return None, "Unknown", None, False
    if hasattr(sender, "first_name"):
        first = getattr(sender, "first_name", None) or ""
        last = getattr(sender, "last_name", None) or ""
        name = (f"{first} {last}").strip() or getattr(sender, "username", None) or "Unknown"
    else:
        name = getattr(sender, "title", None) or "Unknown"
    return getattr(sender, "id", None), name, getattr(sender, "username", None), bool(getattr(sender, "photo", None))


def _message_buttons(m):
    """Serialize Telegram inline/reply keyboard buttons for the web UI.

    Telethon exposes both inline keyboards and reply keyboards through
    ``Message.buttons``.  Only safe display metadata is sent to the browser;
    callback buttons are executed server-side through the button endpoint.
    """
    out = []
    try:
        rows = getattr(m, "buttons", None) or []
        for r, row in enumerate(rows):
            row_out = []
            for c, btn in enumerate(row or []):
                raw = getattr(btn, "button", btn)
                text = getattr(btn, "text", None) or getattr(raw, "text", None) or "Button"
                item = {"text": str(text), "row": r, "col": c, "type": "text"}
                url = getattr(btn, "url", None) or getattr(raw, "url", None)
                data = getattr(btn, "data", None) or getattr(raw, "data", None)
                if url:
                    item["type"] = "url"
                    item["url"] = str(url)
                elif data is not None:
                    item["type"] = "callback"
                name = raw.__class__.__name__.lower()
                if "requestphone" in name:
                    item["type"] = "request_phone"
                elif "requestgeo" in name or "requestlocation" in name:
                    item["type"] = "request_location"
                elif "switchinline" in name:
                    item["type"] = "switch_inline"
                    item["query"] = str(getattr(raw, "query", "") or "")
                row_out.append(item)
            if row_out:
                out.append(row_out)
    except Exception:
        return []
    return out


def _sticker_emoji_alt(m):
    doc = getattr(getattr(m, "media", None), "document", None) or getattr(m, "document", None)
    for attr in (getattr(doc, "attributes", None) or []):
        if isinstance(attr, DocumentAttributeSticker) or getattr(attr, "alt", None):
            alt = getattr(attr, "alt", None)
            if alt:
                return str(alt)
    return None


def _message_reactions_list(m):
    out = []
    rx = getattr(m, "reactions", None)
    for res in (getattr(rx, "results", None) or []):
        reaction = getattr(res, "reaction", None)
        emoji = getattr(reaction, "emoticon", None)
        if emoji:
            out.append({
                "emoji": str(emoji),
                "count": int(getattr(res, "count", 1) or 1),
                "chosen": getattr(res, "chosen_order", None) is not None,
            })
    return out


def _message_dict(m, is_group=False, reply_lookup=None):
    media, mime, name = _message_media_info(m)
    sender = getattr(m, "sender", None)
    sender_id = sender_name = sender_username = sender_has_photo = None
    if is_group and not m.out:
        try:
            sender_id, sender_name, sender_username, sender_has_photo = _sender_fields(sender)
        except Exception:
            pass
    custom_emojis = []
    for ent in getattr(m, "entities", None) or []:
        if isinstance(ent, MessageEntityCustomEmoji):
            custom_emojis.append({
                "offset": int(ent.offset),
                "length": int(ent.length),
                "document_id": str(ent.document_id),
                "alt": (m.text or "")[int(ent.offset):int(ent.offset)+int(ent.length)],
            })
    reply_header = getattr(m, "reply_to", None)
    reply_to_msg_id = getattr(reply_header, "reply_to_msg_id", None) if reply_header else None
    reply_to_text = None
    reply_to_sender = None
    if reply_to_msg_id and reply_lookup and int(reply_to_msg_id) in reply_lookup:
        rm = reply_lookup[int(reply_to_msg_id)]
        r_media, _, _ = _message_media_info(rm)
        reply_to_text = (rm.text or "").strip() or (f"[{r_media}]" if r_media else "Message")
        if len(reply_to_text) > 90:
            reply_to_text = reply_to_text[:87] + "..."
        if getattr(rm, "out", False):
            reply_to_sender = "You"
        else:
            _, r_sname, _, _ = _sender_fields(getattr(rm, "sender", None))
            reply_to_sender = r_sname if r_sname and r_sname != "Unknown" else None
    return {
        "id": m.id,
        "text": m.text or "",
        "date": str(m.date),
        "out": bool(m.out),
        "media_type": media,
        "mime_type": mime,
        "file_name": name,
        "has_media": bool(media),
        "sticker_emoji": _sticker_emoji_alt(m) if media and "sticker" in media else None,
        "sender_id": sender_id,
        "sender_name": sender_name,
        "sender_username": sender_username,
        "sender_has_photo": bool(sender_has_photo),
        "is_group_message": bool(is_group),
        "edited": bool(getattr(m, "edit_date", None)),
        "views": getattr(m, "views", None),
        "reply_to_msg_id": int(reply_to_msg_id) if reply_to_msg_id else None,
        "reply_to_text": reply_to_text,
        "reply_to_sender": reply_to_sender,
        "reactions": _message_reactions_list(m),
        "custom_emojis": custom_emojis,
        "buttons": _message_buttons(m),
    }


@_serialized_telegram
def click_message_button(session_row, peer_ref, message_id, row, col):
    """Handle a Telegram inline/reply keyboard button server-side."""
    cl = get_client(session_row)
    peer_ref = _normalize_peer(peer_ref)
    message_id = int(message_id)
    row = int(row)
    col = int(col)

    async def _f():
        entity = await _resolve_entity_async(cl, peer_ref)
        msg = await cl.get_messages(entity, ids=message_id)
        if not msg:
            raise ValueError("Message not found")
        buttons = getattr(msg, "buttons", None) or []
        if row < 0 or row >= len(buttons) or col < 0 or col >= len(buttons[row]):
            raise ValueError("Button not found")
        btn = buttons[row][col]
        raw = getattr(btn, "button", btn)
        url = getattr(btn, "url", None) or getattr(raw, "url", None)
        if url:
            return {"type": "url", "url": str(url)}
        name = raw.__class__.__name__.lower()
        if "requestphone" in name or "requestgeo" in name or "requestlocation" in name:
            return {"type": "unsupported", "message": "This Telegram button requires information from the Telegram app."}
        if name.endswith("keyboardbutton") or name == "keyboardbuttontext":
            text = getattr(raw, "text", None) or getattr(btn, "text", None)
            if text:
                sent = await cl.send_message(entity, text)
                return {"type": "sent", "message_id": str(getattr(sent, "id", ""))}
        # Telethon's click handles callback, switch-inline and other inline
        # button types using the current authorized account.
        result = await msg.click(row, col)
        return {"type": "clicked", "result": getattr(result, "id", None) and str(getattr(result, "id")) or None}

    return run_async(_f(), timeout=60)


@_serialized_telegram
def get_messages(session_row, peer_ref, limit=60, after_id=None, fallback_username=None):
    """Return recent Telegram history, including group sender metadata and
    sticker/custom-emoji information."""
    cl = get_client(session_row)
    peer_ref = _normalize_peer(peer_ref)

    async def _f():
        entity = await _resolve_entity_async(cl, peer_ref, fallback_username=fallback_username)
        kwargs = {"limit": min(int(limit), 100)}
        if after_id is not None:
            kwargs["min_id"] = int(after_id)
        msgs = await cl.get_messages(entity, **kwargs)
        msg_list = list(msgs or [])
        reply_lookup = {m.id: m for m in msg_list if getattr(m, "id", None)}
        is_group = bool(getattr(entity, "megagroup", False) or entity.__class__.__name__.lower().endswith("chat"))
        out = []
        for m in reversed(msg_list):
            if is_group and not m.out:
                try:
                    await m.get_sender()
                except Exception:
                    pass
            out.append(_message_dict(m, is_group=is_group, reply_lookup=reply_lookup))
        return out

    return run_async(_f(), timeout=60)


@_serialized_telegram
def get_messages_bundle(session_row, peer_ref, limit=60, fallback_username=None):
    """Return messages plus lightweight peer membership/posting metadata in one Telethon call."""
    cl = get_client(session_row)
    peer_ref = _normalize_peer(peer_ref)

    async def _f():
        entity = await _resolve_entity_async(cl, peer_ref, fallback_username=fallback_username)
        msgs = await cl.get_messages(entity, limit=min(int(limit), 100))
        msg_list = list(msgs or [])
        reply_lookup = {m.id: m for m in msg_list if getattr(m, "id", None)}
        is_group = bool(getattr(entity, "megagroup", False) or entity.__class__.__name__.lower().endswith("chat"))
        out = []
        for m in reversed(msg_list):
            if is_group and not m.out:
                try:
                    await m.get_sender()
                except Exception:
                    pass
            out.append(_message_dict(m, is_group=is_group, reply_lookup=reply_lookup))
        peer_info = _entity_summary(entity)
        can_send = True
        is_member = peer_info.get("is_member", True)
        is_admin = False
        send_restriction = ""
        if peer_info.get("is_channel") or peer_info.get("is_group"):
            try:
                perms = await cl.get_permissions(entity, "me")
                is_member = True
                is_admin = bool(getattr(perms, "is_admin", False) or getattr(perms, "is_creator", False))
                if peer_info.get("is_broadcast"):
                    admin_rights = getattr(perms, "admin_rights", None)
                    can_send = bool(
                        getattr(perms, "is_creator", False)
                        or (is_admin and admin_rights is not None and getattr(admin_rights, "post_messages", False))
                    )
                    if not can_send:
                        send_restriction = "You can’t post in this channel."
                else:
                    banned = getattr(perms, "banned_rights", None)
                    if banned is not None and getattr(banned, "send_messages", False):
                        can_send = False
                        send_restriction = "You can’t send messages in this chat."
            except Exception:
                if getattr(entity, "left", None) is not None:
                    is_member = not bool(getattr(entity, "left", True))
                else:
                    is_member = False
                if peer_info.get("is_broadcast"):
                    can_send = False
                    send_restriction = "Join channel to subscribe."
        peer_info["is_member"] = bool(is_member)
        peer_info["is_admin"] = bool(is_admin)
        peer_info["can_send"] = bool(can_send)
        peer_info["send_restriction"] = send_restriction
        return {"messages": out, "peer": peer_info}

    return run_async(_f(), timeout=60)


@_serialized_telegram
def resolve_peer(session_row, target):
    """Resolve a @username, t.me link, or peer id into dialog/profile summary."""
    cl = get_client(session_row)
    raw = (target or "").strip()

    async def _f():
        norm = _normalize_peer(raw)
        try:
            entity = await _resolve_entity_async(cl, norm)
        except Exception:
            uname = raw.split("/")[-1].lstrip("@").strip()
            res = await cl(ResolveUsernameRequest(uname))
            users = getattr(res, "users", None) or []
            chats = getattr(res, "chats", None) or []
            entity = (users + chats)[0] if (users or chats) else None
            if not entity:
                raise ValueError("Telegram could not find that username or link.")
        return _entity_summary(entity)

    return run_async(_f(), timeout=30)


def _sniff_image_mime(data, default_mime="application/octet-stream"):
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:2] == b"\xff\xd8":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    return default_mime


@_serialized_telegram
def download_media(session_row, peer_ref, message_id, thumb=False, fallback_username=None):
    """Download one Telegram message's media (or thumbnail for stickers/videos) and return (bytes, mime, filename)."""
    cl = get_client(session_row)
    peer_ref = _normalize_peer(peer_ref)
    message_id = int(message_id)

    async def _f():
        from io import BytesIO
        entity = await _resolve_entity_async(cl, peer_ref, fallback_username=fallback_username)
        msg = await cl.get_messages(entity, ids=message_id)
        if not msg or not msg.media:
            raise ValueError("This message has no media.")
        mime = getattr(getattr(msg, "file", None), "mime_type", None) or "application/octet-stream"
        name = getattr(getattr(msg, "file", None), "name", None) or f"telegram-{message_id}"
        is_animated_sticker = ("tgsticker" in mime) or (mime == "video/webm") or name.lower().endswith(".webm")
        buf = BytesIO()
        data = b""
        if thumb or is_animated_sticker:
            for t in (-1, 0):
                try:
                    tbuf = BytesIO()
                    await cl.download_media(msg, file=tbuf, thumb=t)
                    if tbuf.getvalue():
                        data = tbuf.getvalue()
                        mime = _sniff_image_mime(data, "image/webp")
                        break
                except Exception:
                    pass
        if not data and not (thumb and is_animated_sticker):
            await cl.download_media(msg, file=buf)
            data = buf.getvalue()
            if mime == "application/octet-stream" and data:
                mime = _sniff_image_mime(data, mime)
        if not data:
            raise ValueError("Telegram returned empty media.")
        return data, mime, name

    return run_async(_f(), timeout=120)


@_serialized_telegram
def send_media(session_row, target, file_bytes, filename, caption="", force_document=False, reply_to=None, fallback_username=None):
    """Upload and send a photo, video, or document to a Telegram chat."""
    cl = get_client(session_row)

    async def _f():
        entity = await _resolve_entity_async(cl, target, fallback_username=fallback_username)
        cls = entity.__class__.__name__.lower()
        is_broadcast_channel = bool(cls.endswith("channel") and not getattr(entity, "megagroup", False))
        if is_broadcast_channel:
            try:
                perms = await cl.get_permissions(entity, "me")
                admin_rights = getattr(perms, "admin_rights", None)
                allowed = bool(
                    getattr(perms, "is_creator", False)
                    or (getattr(perms, "is_admin", False) and admin_rights is not None and getattr(admin_rights, "post_messages", False))
                )
            except Exception:
                allowed = False
            if not allowed:
                raise PermissionError("You cannot post media in this channel.")
        ext = os.path.splitext(filename or "upload.bin")[1] or ".bin"
        tmp = tempfile.mktemp(suffix=ext)
        with open(tmp, "wb") as f:
            f.write(file_bytes)
        try:
            msg = await cl.send_file(
                entity,
                tmp,
                caption=(caption or None),
                force_document=bool(force_document),
                reply_to=(int(reply_to) if reply_to else None),
            )
            is_group = bool(getattr(entity, "megagroup", False) or cls.endswith("chat"))
            return {
                "message_id": msg.id,
                "message": _message_dict(msg, is_group=is_group),
            }
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass

    return run_async(_f(), timeout=120)


def _sticker_doc_dict(doc):
    alt = None
    for attr in (getattr(doc, "attributes", None) or []):
        if isinstance(attr, DocumentAttributeSticker) or getattr(attr, "alt", None):
            alt = getattr(attr, "alt", None)
            if alt:
                break
    return {
        "id": str(doc.id),
        "access_hash": str(doc.access_hash),
        "file_reference": base64.urlsafe_b64encode(getattr(doc, "file_reference", b"") or b"").decode("ascii"),
        "emoji": str(alt) if alt else "",
        "mime_type": getattr(doc, "mime_type", None) or "image/webp",
    }


@_serialized_telegram
def get_stickers(session_row):
    """Return user's recent Telegram stickers and top installed sticker packs."""
    cl = get_client(session_row)

    async def _f():
        recent_out = []
        try:
            recent_res = await cl(GetRecentStickersRequest(hash=0))
            for doc in (getattr(recent_res, "stickers", None) or [])[:24]:
                if getattr(doc, "id", None) and getattr(doc, "access_hash", None) is not None:
                    recent_out.append(_sticker_doc_dict(doc))
        except Exception:
            pass

        packs_out = []
        try:
            all_sets = await cl(GetAllStickersRequest(hash=0))
            for s in (getattr(all_sets, "sets", None) or [])[:6]:
                try:
                    full_set = await cl(GetStickerSetRequest(
                        stickerset=InputStickerSetID(id=s.id, access_hash=s.access_hash),
                        hash=0,
                    ))
                    docs = [
                        _sticker_doc_dict(d)
                        for d in (getattr(full_set, "documents", None) or [])[:20]
                        if getattr(d, "id", None) and getattr(d, "access_hash", None) is not None
                    ]
                    if docs:
                        packs_out.append({
                            "id": str(s.id),
                            "title": getattr(s, "title", None) or "Stickers",
                            "stickers": docs,
                        })
                except Exception:
                    continue
        except Exception:
            pass
        return {"recent": recent_out, "packs": packs_out}

    return run_async(_f(), timeout=60)


@_serialized_telegram
def download_sticker_image(session_row, doc_id, access_hash, file_reference_b64=""):
    cl = get_client(session_row)
    doc_id = int(doc_id)
    access_hash = int(access_hash)

    async def _f():
        from io import BytesIO
        raw_ref = b""
        if file_reference_b64:
            pad = "=" * ((4 - len(file_reference_b64) % 4) % 4)
            raw_ref = base64.urlsafe_b64decode((file_reference_b64 + pad).encode("ascii"))
        doc = InputDocument(id=doc_id, access_hash=access_hash, file_reference=raw_ref)
        data = b""
        for t in (-1, 0):
            try:
                tbuf = BytesIO()
                await cl.download_media(doc, file=tbuf, thumb=t)
                if tbuf.getvalue():
                    data = tbuf.getvalue()
                    break
            except Exception:
                pass
        if not data:
            fbuf = BytesIO()
            await cl.download_media(doc, file=fbuf)
            data = fbuf.getvalue()
        if not data:
            return None, None
        mime = _sniff_image_mime(data, "image/webp")
        return data, mime

    return run_async(_f(), timeout=60)


@_serialized_telegram
def send_sticker(session_row, target, doc_id, access_hash, file_reference_b64="", reply_to=None, fallback_username=None):
    cl = get_client(session_row)
    doc_id = int(doc_id)
    access_hash = int(access_hash)

    async def _f():
        entity = await _resolve_entity_async(cl, target, fallback_username=fallback_username)
        raw_ref = b""
        if file_reference_b64:
            pad = "=" * ((4 - len(file_reference_b64) % 4) % 4)
            raw_ref = base64.urlsafe_b64decode((file_reference_b64 + pad).encode("ascii"))
        doc = InputDocument(id=doc_id, access_hash=access_hash, file_reference=raw_ref)
        msg = await cl.send_file(entity, doc, reply_to=(int(reply_to) if reply_to else None))
        cls = entity.__class__.__name__.lower()
        is_group = bool(getattr(entity, "megagroup", False) or cls.endswith("chat"))
        return {
            "message_id": msg.id,
            "message": _message_dict(msg, is_group=is_group),
        }

    return run_async(_f(), timeout=60)


@_serialized_telegram
def react_message(session_row, target, message_id, emoji=None, fallback_username=None):
    cl = get_client(session_row)
    message_id = int(message_id)

    async def _f():
        entity = await _resolve_entity_async(cl, target, fallback_username=fallback_username)
        reactions = [ReactionEmoji(emoticon=emoji)] if emoji else []
        await cl(SendReactionRequest(peer=entity, msg_id=message_id, reaction=reactions))
        msgs = await cl.get_messages(entity, ids=message_id)
        is_group = bool(getattr(entity, "megagroup", False) or entity.__class__.__name__.lower().endswith("chat"))
        return {"ok": True, "message": _message_dict(msgs, is_group=is_group) if msgs else None}

    return run_async(_f(), timeout=30)


@_serialized_telegram
def edit_message(session_row, target, message_id, new_text, fallback_username=None):
    cl = get_client(session_row)
    message_id = int(message_id)

    async def _f():
        entity = await _resolve_entity_async(cl, target, fallback_username=fallback_username)
        msg = await cl.edit_message(entity, message_id, new_text)
        is_group = bool(getattr(entity, "megagroup", False) or entity.__class__.__name__.lower().endswith("chat"))
        return {"ok": True, "message": _message_dict(msg, is_group=is_group)}

    return run_async(_f(), timeout=30)


@_serialized_telegram
def delete_messages(session_row, target, message_ids, revoke=True, fallback_username=None):
    cl = get_client(session_row)

    async def _f():
        entity = await _resolve_entity_async(cl, target, fallback_username=fallback_username)
        ids = [int(x) for x in (message_ids or [])]
        await cl.delete_messages(entity, ids, revoke=bool(revoke))
        return {"ok": True, "deleted": len(ids)}

    return run_async(_f(), timeout=30)


@_serialized_telegram
def forward_messages(session_row, from_peer, to_peer, message_ids, fallback_from_username=None, fallback_to_username=None):
    cl = get_client(session_row)

    async def _f():
        src = await _resolve_entity_async(cl, from_peer, fallback_username=fallback_from_username)
        dst = await _resolve_entity_async(cl, to_peer, fallback_username=fallback_to_username)
        ids = [int(x) for x in (message_ids or [])]
        await cl.forward_messages(dst, ids, from_peer=src)
        return {"ok": True, "forwarded": len(ids)}

    return run_async(_f(), timeout=60)


@_serialized_telegram
def pin_message(session_row, target, message_id, unpin=False, fallback_username=None):
    cl = get_client(session_row)
    message_id = int(message_id)

    async def _f():
        entity = await _resolve_entity_async(cl, target, fallback_username=fallback_username)
        if unpin:
            await cl.unpin_message(entity, message_id)
        else:
            await cl.pin_message(entity, message_id, notify=False)
        return {"ok": True}

    return run_async(_f(), timeout=30)


@_serialized_telegram
def mark_read(session_row, target, fallback_username=None):
    cl = get_client(session_row)

    async def _f():
        entity = await _resolve_entity_async(cl, target, fallback_username=fallback_username)
        await cl.send_read_acknowledge(entity)
        return {"ok": True}

    return run_async(_f(), timeout=20)


@_serialized_telegram
def download_sender_photo(session_row, chat_peer, message_id):
    cl = get_client(session_row)
    chat_peer = _normalize_peer(chat_peer)
    message_id = int(message_id)

    async def _f():
        from io import BytesIO
        entity = await _resolve_entity_async(cl, chat_peer)
        msg = await cl.get_messages(entity, ids=message_id)
        if not msg:
            return None
        sender = await msg.get_sender()
        if not sender or not getattr(sender, "photo", None):
            return None
        buf = BytesIO()
        result = await cl.download_profile_photo(sender, file=buf)
        return buf.getvalue() if result else None

    return run_async(_f(), timeout=60)


@_serialized_telegram
def download_custom_emoji(session_row, document_id):
    cl = get_client(session_row)
    document_id = int(document_id)

    async def _f():
        from io import BytesIO
        result = await cl(GetCustomEmojiDocumentsRequest(document_id=[document_id]))
        docs = getattr(result, "documents", None) or []
        if not docs:
            return None, None, None
        doc = docs[0]
        buf = BytesIO()
        await cl.download_media(doc, file=buf)
        data = buf.getvalue()
        return data, getattr(doc, "mime_type", None) or "application/octet-stream", f"emoji-{document_id}"

    return run_async(_f(), timeout=60)


async def _fetch_own_profile_async(cl):
    me = await cl.get_me()
    if not me:
        return {"name": "Telegram", "first_name": "", "last_name": "", "username": None, "id": None, "bio": "", "has_photo": False}
    first = getattr(me, "first_name", "") or ""
    last = getattr(me, "last_name", "") or ""
    name = (f"{first} {last}").strip() or getattr(me, "username", None) or "Telegram"
    bio = None
    try:
        full = await cl(GetFullUserRequest(me))
        bio = getattr(getattr(full, "full_user", None), "about", None)
    except Exception:
        pass
    return {
        "id": me.id,
        "name": name,
        "first_name": first,
        "last_name": last,
        "username": getattr(me, "username", None),
        "phone": getattr(me, "phone", None),
        "bio": bio or "",
        "has_photo": bool(getattr(me, "photo", None)),
    }


@_serialized_telegram
def get_own_profile(session_row):
    """Return the currently authorized Telegram account profile."""
    cl = get_client(session_row)
    async def _f():
        return await _fetch_own_profile_async(cl)
    return run_async(_f())


@_serialized_telegram
def download_own_profile_photo(session_row):
    """Download the current account's Telegram profile photo."""
    cl = get_client(session_row)
    async def _f():
        me = await cl.get_me()
        if not me or not getattr(me, "photo", None):
            return None
        from io import BytesIO
        buf = BytesIO()
        result = await cl.download_profile_photo(me, file=buf)
        return buf.getvalue() if result else None
    return run_async(_f(), timeout=60)


async def _apply_username_async(cl, raw_username):
    clean = (raw_username or "").strip().lstrip("@")
    try:
        await cl(UpdateUsernameRequest(username=clean))
    except Exception as e:
        msg = str(e)
        cls = e.__class__.__name__.lower()
        if "notmodified" in cls or "not modified" in msg.lower():
            return
        if "occupied" in cls or "occupied" in msg.lower():
            raise ValueError("This username is already taken.")
        if "invalid" in cls or "invalid" in msg.lower():
            raise ValueError("Username must be 5–32 chars (a-z, 0-9, _).")
        if "purchase" in cls or "purchase" in msg.lower():
            raise ValueError("This collectible username cannot be assigned here.")
        raise ValueError(msg or "Could not update username.")


@_serialized_telegram
def update_own_profile(session_row, first_name=None, last_name=None, bio=None, username=None):
    cl = get_client(session_row)
    async def _f():
        kwargs = {}
        if first_name is not None:
            kwargs["first_name"] = str(first_name).strip()
        if last_name is not None:
            kwargs["last_name"] = str(last_name).strip()
        if bio is not None:
            kwargs["about"] = str(bio).strip()[:70]
        if kwargs:
            await cl(UpdateProfileRequest(**kwargs))
        if username is not None:
            await _apply_username_async(cl, username)
        return await _fetch_own_profile_async(cl)
    return run_async(_f())


@_serialized_telegram
def update_own_username(session_row, username=""):
    cl = get_client(session_row)
    async def _f():
        await _apply_username_async(cl, username)
        return await _fetch_own_profile_async(cl)
    return run_async(_f())


@_serialized_telegram
def get_profile(session_row, peer_ref, fallback_username=None):
    """Return Telegram-style profile/about information for a user, group or channel."""
    cl = get_client(session_row)
    peer_ref = _normalize_peer(peer_ref)

    async def _f():
        entity = await _resolve_entity_async(cl, peer_ref, fallback_username=fallback_username)
        cls = entity.__class__.__name__.lower()
        is_user = hasattr(entity, "first_name")
        is_channel = cls.endswith("channel")
        is_group = bool(getattr(entity, "megagroup", False)) or cls.endswith("chat")

        about = ""
        participants = None
        online_count = None
        pinned_text = ""
        personal_channel = None
        linked_chat = None
        if is_user:
            full = await cl(GetFullUserRequest(entity))
            about = getattr(full.full_user, "about", None) or ""
            first = getattr(entity, "first_name", "") or ""
            last = getattr(entity, "last_name", "") or ""
            name = (f"{first} {last}").strip() or "Unknown"
            pchan_id = getattr(full.full_user, "personal_channel_id", None)
            if pchan_id:
                for ch in getattr(full, "chats", []) or []:
                    if getattr(ch, "id", None) == pchan_id:
                        personal_channel = {
                            "id": get_peer_id(ch),
                            "name": getattr(ch, "title", None) or "Channel",
                            "username": getattr(ch, "username", None),
                            "participants_count": getattr(ch, "participants_count", None),
                            "has_photo": bool(getattr(ch, "photo", None)),
                        }
                        break
        elif is_channel:
            full = await cl(GetFullChannelRequest(entity))
            about = getattr(full.full_chat, "about", None) or ""
            participants = getattr(full.full_chat, "participants_count", None)
            online_count = getattr(full.full_chat, "online_count", None)
            pinned_id = getattr(full.full_chat, "pinned_msg_id", None)
            if pinned_id:
                try:
                    pm = await cl.get_messages(entity, ids=pinned_id)
                    pinned_text = (pm.text or "") if pm else ""
                except Exception:
                    pass
            linked_id = getattr(full.full_chat, "linked_chat_id", None)
            if linked_id:
                for ch in getattr(full, "chats", []) or []:
                    if getattr(ch, "id", None) == linked_id:
                        linked_chat = {
                            "id": get_peer_id(ch),
                            "name": getattr(ch, "title", None) or "Discussion",
                            "username": getattr(ch, "username", None),
                            "participants_count": getattr(ch, "participants_count", None),
                            "has_photo": bool(getattr(ch, "photo", None)),
                        }
                        break
            name = getattr(entity, "title", None) or "Channel"
        else:
            name = getattr(entity, "title", None) or "Group"
            try:
                full = await cl(GetFullChatRequest(entity.id))
                about = getattr(full.full_chat, "about", None) or ""
                participants = getattr(full.full_chat, "participants_count", None)
                online_count = getattr(full.full_chat, "online_count", None)
                pinned_id = getattr(full.full_chat, "pinned_msg_id", None)
                if pinned_id:
                    pm = await cl.get_messages(entity, ids=pinned_id)
                    pinned_text = (pm.text or "") if pm else ""
            except Exception:
                pass

        is_member = False
        is_admin = False
        can_send = True
        send_restriction = ""
        if is_channel or is_group:
            try:
                perms = await cl.get_permissions(entity, "me")
                is_member = True
                is_admin = bool(getattr(perms, "is_admin", False) or getattr(perms, "is_creator", False))

                # Broadcast channels only allow posting by the channel owner/admins
                # with the post_messages right. Regular subscribers must never be
                # offered a send box because Telegram will reject the message.
                if is_channel and not bool(getattr(entity, "megagroup", False)):
                    admin_rights = getattr(perms, "admin_rights", None)
                    can_post = bool(
                        getattr(perms, "is_creator", False)
                        or (is_admin and admin_rights is not None and getattr(admin_rights, "post_messages", False))
                    )
                    can_send = can_post
                    if not can_send:
                        send_restriction = "You can’t post in this channel because you are not an admin with posting permission."
                else:
                    banned = getattr(perms, "banned_rights", None)
                    if banned is not None and getattr(banned, "send_messages", False):
                        can_send = False
                        send_restriction = "You can’t send messages in this chat."
            except Exception:
                is_member = False
                if is_channel and not bool(getattr(entity, "megagroup", False)):
                    can_send = False
                    send_restriction = "You can’t post in this channel."

        return {
            "id": get_peer_id(entity),
            "name": name,
            "first_name": getattr(entity, "first_name", None) if is_user else None,
            "last_name": getattr(entity, "last_name", None) if is_user else None,
            "username": getattr(entity, "username", None),
            "phone": getattr(entity, "phone", None) if is_user else None,
            "bio": about,
            "is_user": is_user,
            "is_bot": bool(getattr(entity, "bot", False)),
            "is_contact": bool(getattr(entity, "contact", False)),
            "verified": bool(getattr(entity, "verified", False)),
            "is_group": is_group,
            "is_channel": bool(is_channel and not getattr(entity, "megagroup", False)),
            "is_broadcast": bool(is_channel and not getattr(entity, "megagroup", False)),
            "participants_count": participants,
            "online_count": online_count,
            "pinned_text": pinned_text,
            "is_member": is_member if (is_channel or is_group) else True,
            "is_admin": is_admin,
            "can_send": bool(can_send),
            "send_restriction": send_restriction,
            "has_photo": bool(getattr(entity, "photo", None)),
            "status": _format_user_status(entity) if is_user else None,
            "personal_channel": personal_channel,
            "linked_chat": linked_chat,
        }

    return run_async(_f())


@_serialized_telegram
def download_profile_photo(session_row, peer_ref):
    cl = get_client(session_row)
    peer_ref = _normalize_peer(peer_ref)

    async def _f():
        from io import BytesIO
        entity = await _resolve_entity_async(cl, peer_ref)
        buf = BytesIO()
        result = await cl.download_profile_photo(entity, file=buf)
        if not result:
            return None
        return buf.getvalue()

    return run_async(_f(), timeout=60)


@_serialized_telegram
def join_chat(session_row, target):
    """Join a public channel/supergroup by username, peer id, or a private t.me invite link."""
    cl = get_client(session_row)
    target = (target or "").strip()

    async def _f():
        invite_hash = None
        m = re.search(r"(?:t\.me|telegram\.me)/(?:joinchat/|\+)([A-Za-z0-9_-]+)", target)
        if m:
            invite_hash = m.group(1)
        joined_entity = None
        if invite_hash:
            result = await cl(ImportChatInviteRequest(invite_hash))
            chats = getattr(result, "chats", None) or []
            if chats:
                joined_entity = chats[0]
        else:
            norm = _normalize_peer(target)
            if not norm and norm != 0:
                raise ValueError("Provide a public @username or Telegram invite link.")
            entity = await _resolve_entity_async(cl, norm)
            await cl(JoinChannelRequest(entity))
            joined_entity = entity
        summary = _entity_summary(joined_entity) if joined_entity is not None else None
        if summary is not None:
            summary["is_member"] = True
        return {"ok": True, "message": "Joined successfully.", "dialog": summary}

    return run_async(_f())


@_serialized_telegram
def leave_chat(session_row, target):
    """Leave a channel or group."""
    cl = get_client(session_row)
    target = (target or "").strip()

    async def _f():
        entity = await _resolve_entity_async(cl, target)
        await cl.delete_dialog(entity)
        return {"ok": True, "message": "Left chat successfully."}

    return run_async(_f())


@_serialized_telegram
def get_contacts(session_row):
    """Return the actual Telegram contacts for the selected session."""
    cl = get_client(session_row)

    async def _f():
        result = await cl(GetContactsRequest(hash=0))
        out = []
        for user in getattr(result, "users", []) or []:
            first = getattr(user, "first_name", "") or ""
            last = getattr(user, "last_name", "") or ""
            name = (f"{first} {last}").strip() or getattr(user, "username", None) or "Unknown"
            out.append({
                "id": user.id,
                "name": name,
                "first_name": first,
                "last_name": last,
                "username": getattr(user, "username", None),
                "phone": getattr(user, "phone", None),
                "bot": bool(getattr(user, "bot", False)),
                "has_photo": bool(getattr(user, "photo", None)),
                "mutual_contact": bool(getattr(user, "mutual_contact", False)),
            })
        out.sort(key=lambda x: (x["name"] or "").lower())
        return out

    return run_async(_f())


@_serialized_telegram
def add_contact(session_row, target, first_name=None, last_name=""):
    """Add a Telegram user to the selected account's contacts. Target can be @username or user id."""
    cl = get_client(session_row)
    target = (target or "").strip()
    if not target:
        raise ValueError("Provide a username or Telegram user id.")

    async def _f():
        clean_phone = target.replace(" ", "").replace("-", "")
        if re.fullmatch(r"\+?\d{7,20}", clean_phone):
            first = (first_name or "Contact").strip()
            last = (last_name or "").strip()
            result = await cl(ImportContactsRequest(contacts=[InputPhoneContact(
                client_id=0, phone=clean_phone, first_name=first, last_name=last
            )]))
            users = getattr(result, "users", []) or []
            if not users:
                raise ValueError("Telegram could not find a user for that phone number.")
            return {"ok": True, "message": f"{first} {last}".strip() + " added to contacts."}

        entity = await _resolve_entity_async(cl, target)
        if not hasattr(entity, "first_name"):
            raise ValueError("The selected entity is not a user.")
        first = (first_name or getattr(entity, "first_name", None) or getattr(entity, "username", None) or "Contact").strip()
        last = (last_name or getattr(entity, "last_name", None) or "").strip()
        phone = getattr(entity, "phone", None) or ""
        await cl(AddContactRequest(
            id=entity, first_name=first, last_name=last, phone=phone,
            add_phone_privacy_exception=False
        ))
        return {"ok": True, "message": f"{first} {last}".strip() + " added to contacts."}

    return run_async(_f())


@_serialized_telegram
def search_dialogs(session_row, query, limit=25):
    """Search Telegram globally for users/chats/channels by username or name."""
    cl = get_client(session_row)
    raw_query = (query or "").strip()
    query = raw_query.lstrip("@")
    if not query:
        return []

    async def _f():
        seen_ids = set()
        out = []
        if re.fullmatch(r"[A-Za-z0-9_]{3,}", query):
            try:
                resolved = await cl(ResolveUsernameRequest(query))
                for entity in list(getattr(resolved, "users", [])) + list(getattr(resolved, "chats", [])):
                    if entity.id not in seen_ids:
                        seen_ids.add(entity.id)
                        out.append(_entity_summary(entity))
            except Exception:
                pass
        result = await cl(SearchRequest(q=query, limit=max(1, min(int(limit), 50))))
        for entity in list(getattr(result, "users", [])) + list(getattr(result, "chats", [])):
            if entity.id not in seen_ids:
                seen_ids.add(entity.id)
                out.append(_entity_summary(entity))
        return out

    return run_async(_f())


@_serialized_telegram
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


@_serialized_telegram
def set_2fa_email(session_row, current_password, new_email):
    """Change just the 2FA recovery email, keeping the password itself
    unchanged — mirrors Telegram's own Settings > Privacy & Security >
    Two-Step Verification > Change Recovery Email. Requires the current
    2FA password, same as Telegram's own app requires."""
    cl = get_client(session_row)

    async def _f():
        await cl.edit_2fa(
            current_password=current_password,
            new_password=current_password,  # unchanged — only the email updates
            email=new_email,
        )
        return True

    return run_async(_f())


@_serialized_telegram
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


@_serialized_telegram
def logout_device(session_row, device_hash):
    cl = get_client(session_row)

    async def _f():
        await cl(ResetAuthorizationRequest(hash=device_hash))
        return True

    return run_async(_f())


@_serialized_telegram
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


@_serialized_telegram
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


@_serialized_telegram
def get_2fa_status(session_row):
    cl = get_client(session_row)

    async def _f():
        try:
            pwd = await cl(GetPasswordRequest())
            return {"enabled": pwd.has_password, "hint": getattr(pwd, "hint", "") or ""}
        except Exception as e:
            return {"enabled": False, "hint": "", "error": str(e)}

    return run_async(_f())


@_serialized_telegram
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


@_serialized_telegram
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


@_serialized_telegram
def logout_session(session_row):
    cl = get_client(session_row)

    async def _f():
        try:
            await cl.log_out()
        except Exception:
            pass

    run_async(_f())


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
            chat = await event.get_chat()
            chat_id = getattr(event, "chat_id", None)
            chat_username = getattr(chat, "username", None)
            chat_name = getattr(chat, "title", None) or getattr(chat, "first_name", None) or getattr(chat, "username", None) or "Unknown"
            cls = chat.__class__.__name__.lower() if chat else ""
            is_group = bool(getattr(chat, "megagroup", False) or cls.endswith("chat"))
            try:
                md = _message_dict(event.message, is_group=is_group)
            except Exception:
                md = {"id": getattr(event.message, "id", 0), "text": event.raw_text or "", "date": str(getattr(event.message, "date", "")), "out": bool(getattr(event.message, "out", False))}
            md.update({
                "chat_id": chat_id,
                "chat_username": chat_username,
                "chat_name": str(chat_name),
                "chat_is_group": is_group,
                "chat_is_channel": bool(cls.endswith("channel")),
            })
            q.put_nowait(md)
        except Exception as e:
            q.put_nowait({"error": str(e), "text": ""})

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

# ─────────────────────── phone OTP + 2FA login & export ───────────────────────

def _normalize_phone(phone: str) -> str:
    cleaned = re.sub(r"[^\d+]", "", (phone or "").strip())
    if cleaned and not cleaned.startswith("+"):
        cleaned = "+" + cleaned
    if not re.fullmatch(r"\+\d{7,15}", cleaned):
        raise ValueError("Enter a valid phone number with country code (e.g. +15551234567).")
    return cleaned


def _delivery_label(sent) -> str:
    t = str(getattr(getattr(sent, "type", None), "__class__", "") or getattr(sent, "type", "")).lower()
    if "app" in t:
        return "Telegram app"
    if "sms" in t:
        return "SMS"
    if "call" in t:
        return "Phone call"
    if "email" in t:
        return "Email"
    return "Telegram"


def start_phone_login(phone: str):
    clean_phone = _normalize_phone(phone)
    aid, ahash = API_PAIRS[0]

    async def _start():
        cl = TelegramClient(StringSession(), aid, ahash)
        await cl.connect()
        try:
            sent = await cl.send_code_request(clean_phone)
            temp_ss = StringSession.save(cl.session)
            return {
                "phone": clean_phone,
                "phone_code_hash": sent.phone_code_hash,
                "temp_session": temp_ss,
                "delivery": _delivery_label(sent),
                "api_id": aid,
                "api_hash": ahash,
            }
        except PhoneNumberInvalidError:
            raise ValueError("Invalid phone number format.")
        except PhoneNumberBannedError:
            raise ValueError("This phone number is banned on Telegram.")
        except FloodWaitError as fw:
            raise ValueError(f"Too many attempts. Please wait {fw.seconds} seconds.")
        finally:
            try:
                await cl.disconnect()
            except Exception:
                pass

    return run_async(_start())


def verify_phone_code(temp_session: str, api_id: int, api_hash: str, phone: str, phone_code_hash: str, code: str):
    clean_code = re.sub(r"\s+", "", (code or "").strip())
    if not clean_code:
        raise ValueError("Verification code cannot be empty.")

    async def _verify():
        cl = TelegramClient(StringSession(temp_session), int(api_id), api_hash)
        await cl.connect()
        try:
            try:
                await cl.sign_in(phone=phone, code=clean_code, phone_code_hash=phone_code_hash)
            except SessionPasswordNeededError:
                hint = ""
                try:
                    pwd = await cl(GetPasswordRequest())
                    hint = getattr(pwd, "hint", "") or ""
                except Exception:
                    pass
                new_temp = StringSession.save(cl.session)
                return {
                    "password_required": True,
                    "temp_session": new_temp,
                    "hint": hint,
                }
            except PhoneCodeInvalidError:
                raise ValueError("Invalid verification code. Please check and try again.")
            except PhoneCodeExpiredError:
                raise ValueError("This verification code expired. Please request a new code.")
            except FloodWaitError as fw:
                raise ValueError(f"Too many attempts. Please wait {fw.seconds} seconds.")

            ss = StringSession.save(cl.session)
            me = await cl.get_me()
            name = f"{getattr(me, 'first_name', '') or ''} {getattr(me, 'last_name', '') or ''}".strip() or "Telegram User"
            resolved_phone = getattr(me, "phone", None) or phone
            return {
                "password_required": False,
                "session_string": ss,
                "name": name,
                "phone": resolved_phone,
                "user_id": int(me.id),
            }
        finally:
            try:
                await cl.disconnect()
            except Exception:
                pass

    return run_async(_verify())


def verify_phone_password(temp_session: str, api_id: int, api_hash: str, phone: str, password: str):
    if not password:
        raise ValueError("Two-Step Verification password cannot be empty.")

    async def _verify_pw():
        cl = TelegramClient(StringSession(temp_session), int(api_id), api_hash)
        await cl.connect()
        try:
            try:
                await cl.sign_in(password=password)
            except PasswordHashInvalidError:
                raise ValueError("Incorrect Two-Step Verification password.")
            except FloodWaitError as fw:
                raise ValueError(f"Too many attempts. Please wait {fw.seconds} seconds.")

            ss = StringSession.save(cl.session)
            me = await cl.get_me()
            name = f"{getattr(me, 'first_name', '') or ''} {getattr(me, 'last_name', '') or ''}".strip() or "Telegram User"
            resolved_phone = getattr(me, "phone", None) or phone
            return {
                "session_string": ss,
                "name": name,
                "phone": resolved_phone,
                "user_id": int(me.id),
            }
        finally:
            try:
                await cl.disconnect()
            except Exception:
                pass

    return run_async(_verify_pw())


def export_session_formats(session_row):
    ss = (session_row.get("session_string") or "").strip()
    if not ss:
        raise ValueError("Session string is empty.")
    parsed = StringSession(ss)
    dc_id = int(parsed.dc_id or 2)
    hex_key = parsed.auth_key.key.hex() if parsed.auth_key else ""
    return {
        "dc_id": dc_id,
        "telethon": ss,
        "hex": hex_key,
    }
