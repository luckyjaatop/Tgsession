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
import uuid
import contextvars
from functools import wraps

import db

from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.tl.functions.account import (
    GetAuthorizationsRequest, ResetAuthorizationRequest,
    GetPasswordRequest, ResetPasswordRequest, UpdateProfileRequest, UpdateUsernameRequest
)
from telethon.tl.functions.contacts import (
    GetContactsRequest, DeleteContactsRequest, GetBlockedRequest, UnblockRequest, SearchRequest, AddContactRequest, ImportContactsRequest
)
from telethon.tl.functions.photos import UploadProfilePhotoRequest
from telethon.tl.functions.channels import JoinChannelRequest, GetFullChannelRequest
from telethon.tl.functions.messages import ImportChatInviteRequest, GetCustomEmojiDocumentsRequest, GetFullChatRequest
from telethon.tl.functions.users import GetFullUserRequest
from telethon.errors import FloodWaitError
from telethon.tl.types import PeerUser, PeerChat, PeerChannel, MessageEntityCustomEmoji, InputPhoneContact

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
def send_message(session_row, target, text):
    """Send a text message from this session's account to `target`, which can
    be a @username (str) or an existing dialog's peer id (int)."""
    cl = get_client(session_row)

    async def _f():
        entity = await _resolve_entity_async(cl, target)
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

        msg = await cl.send_message(entity, text)
        return {
            "message_id": msg.id,
            "to": str(target),
            "sent_at": str(msg.date),
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
                "is_channel": d.is_channel,
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
        if peer_ref.startswith("@"): 
            peer_ref = peer_ref[1:]
        if peer_ref.lstrip("-").isdigit():
            peer_ref = int(peer_ref)
    return peer_ref


async def _resolve_entity_async(cl, peer_ref):
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
                    # Telethon's marked channel/group IDs are normally cached
                    # after get_dialogs(); these explicit peers are a final try.
                    for candidate in (PeerChannel(peer_ref), PeerChat(peer_ref)):
                        try:
                            return await cl.get_entity(candidate)
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


def _message_dict(m, is_group=False):
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
            # Telegram offsets/lengths are UTF-16 code-unit offsets, which
            # match JavaScript string indexing.
            custom_emojis.append({
                "offset": int(ent.offset),
                "length": int(ent.length),
                "document_id": str(ent.document_id),
                "alt": (m.text or "")[int(ent.offset):int(ent.offset)+int(ent.length)],
            })
    return {
        "id": m.id,
        "text": m.text or "",
        "date": str(m.date),
        "out": bool(m.out),
        "media_type": media,
        "mime_type": mime,
        "file_name": name,
        "sender_id": sender_id,
        "sender_name": sender_name,
        "sender_username": sender_username,
        "sender_has_photo": bool(sender_has_photo),
        "is_group_message": bool(is_group),
        "custom_emojis": custom_emojis,
    }


@_serialized_telegram
def get_messages(session_row, peer_ref, limit=60, after_id=None):
    """Return recent Telegram history, including group sender metadata and
    sticker/custom-emoji information."""
    cl = get_client(session_row)
    peer_ref = _normalize_peer(peer_ref)

    async def _f():
        entity = await _resolve_entity_async(cl, peer_ref)
        kwargs = {"limit": min(int(limit), 100)}
        if after_id is not None:
            kwargs["min_id"] = int(after_id)
        msgs = await cl.get_messages(entity, **kwargs)
        is_group = bool(getattr(entity, "megagroup", False) or entity.__class__.__name__.lower().endswith("chat"))
        out = []
        for m in reversed(list(msgs or [])):
            if is_group and not m.out:
                try:
                    await m.get_sender()
                except Exception:
                    pass
            out.append(_message_dict(m, is_group=is_group))
        return out

    return run_async(_f(), timeout=60)


@_serialized_telegram
def download_media(session_row, peer_ref, message_id):
    """Download one Telegram message's media and return (bytes, mime, filename)."""
    cl = get_client(session_row)
    peer_ref = _normalize_peer(peer_ref)
    message_id = int(message_id)

    async def _f():
        from io import BytesIO
        entity = await _resolve_entity_async(cl, peer_ref)
        msg = await cl.get_messages(entity, ids=message_id)
        if not msg or not msg.media:
            raise ValueError("This message has no media.")
        buf = BytesIO()
        await cl.download_media(msg, file=buf)
        data = buf.getvalue()
        if not data:
            raise ValueError("Telegram returned empty media.")
        mime = getattr(getattr(msg, "file", None), "mime_type", None) or "application/octet-stream"
        name = getattr(getattr(msg, "file", None), "name", None) or f"telegram-{message_id}"
        return data, mime, name

    return run_async(_f(), timeout=120)


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


@_serialized_telegram
def get_own_profile(session_row):
    """Return the currently authorized Telegram account profile."""
    cl = get_client(session_row)
    async def _f():
        me = await cl.get_me()
        if not me:
            return {"name": "Telegram", "username": None, "id": None, "has_photo": False}
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
            "username": getattr(me, "username", None),
            "phone": getattr(me, "phone", None),
            "bio": bio or "",
            "has_photo": bool(getattr(me, "photo", None)),
        }
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


@_serialized_telegram
def update_own_profile(session_row, first_name, last_name="", bio=""):
    cl = get_client(session_row)
    async def _f():
        await cl(UpdateProfileRequest(first_name=(first_name or "").strip(), last_name=(last_name or "").strip(), about=(bio or "").strip()))
        return get_own_profile(session_row)
    return run_async(_f())


@_serialized_telegram
def get_profile(session_row, peer_ref):
    """Return Telegram-style profile/about information for a user, group or channel."""
    cl = get_client(session_row)
    peer_ref = _normalize_peer(peer_ref)

    async def _f():
        entity = await _resolve_entity_async(cl, peer_ref)
        cls = entity.__class__.__name__.lower()
        is_user = hasattr(entity, "first_name")
        is_channel = cls.endswith("channel")
        is_group = bool(getattr(entity, "megagroup", False)) or cls.endswith("chat")

        about = ""
        participants = None
        online_count = None
        pinned_text = ""
        if is_user:
            full = await cl(GetFullUserRequest(entity))
            about = getattr(full.full_user, "about", None) or ""
            first = getattr(entity, "first_name", "") or ""
            last = getattr(entity, "last_name", "") or ""
            name = (f"{first} {last}").strip() or "Unknown"
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
            "id": entity.id,
            "name": name,
            "username": getattr(entity, "username", None),
            "bio": about,
            "is_user": is_user,
            "is_group": is_group,
            "is_channel": is_channel,
            "is_broadcast": bool(is_channel and not getattr(entity, "megagroup", False)),
            "participants_count": participants,
            "online_count": online_count,
            "pinned_text": pinned_text,
            "is_member": is_member,
            "is_admin": is_admin,
            "can_send": bool(can_send),
            "send_restriction": send_restriction,
            "has_photo": bool(getattr(entity, "photo", None)),
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
    """Join a public channel/supergroup by username or a private t.me invite link."""
    cl = get_client(session_row)
    target = (target or "").strip()

    async def _f():
        invite_hash = None
        m = re.search(r"(?:t\.me|telegram\.me)/(?:joinchat/|\+)([A-Za-z0-9_-]+)", target)
        if m:
            invite_hash = m.group(1)
        if invite_hash:
            result = await cl(ImportChatInviteRequest(invite_hash))
        else:
            username = target.split("/")[-1].lstrip("@").strip()
            if not username:
                raise ValueError("Provide a public @username or Telegram invite link.")
            entity = await cl.get_entity(username)
            result = await cl(JoinChannelRequest(entity))
        return {"ok": True, "message": "Joined successfully."}

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
