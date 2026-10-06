# Session Manager Pro — Web

A website version of your Telegram bot, with the same features, built with
Flask + Telethon, plus a full admin panel.

## Features (same as the bot)

- Register / login (website accounts, separate from Telegram)
- Add a session via `.session` file upload
- Bulk-add many sessions via a `.zip` upload (paced to avoid Telegram flood limits)
- Per-session control panel:
  - 📩 **Get OTP** — fetch the latest login code from Telegram (777000)
  - 📨 **Give Message** — live-stream every new incoming message on that
    account into the page (Server-Sent Events, no refresh needed)
  - 📱 **Devices** — list active sessions, logout individual devices, or
    logout every device except the current one
  - 🔐 **2FA Status** — check whether a cloud password is set
  - 🧹 **Clean Account** — leave all channels/groups, delete chats &
    contacts, unblock everyone, reset name/username
  - 🖼 **Change Profile Photo**
  - 📤 **Get Session String**
  - 🚪 **Logout & Remove** or **Remove From Site Only** (keeps the Telegram
    account logged in, just stops managing it here)
- Trial / Premium licensing with per-user session limits, same model as the bot
- **Admin Panel**: stats dashboard, manage every user's access level & session
  limit, delete users, and broadcast a message that appears as a banner for
  every logged-in user

Session-string **login** (pasting a raw string to log in) is intentionally
not offered on the add-session form — same as your bot, only `.session`
file / ZIP upload is supported. The "Get Session String" button still lets
you **export** a string from an already-added session.

## Setup

```bash
cd SESSION_WEB
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Optionally set a few environment variables before first run:

```bash
export SECRET_KEY="something-random-and-long"
export ADMIN_USERNAME="admin"       # default: admin
export ADMIN_PASSWORD="change-me"   # default: admin123
```

Run it:

```bash
python3 app.py
```

It starts on `http://0.0.0.0:5000` by default (set `PORT` to change).
On first run it creates `instance/webapp.sqlite` and seeds the admin account
from `ADMIN_USERNAME` / `ADMIN_PASSWORD` (printed once in the console log —
**log in and treat that account carefully**).

## How it works

- `app.py` — Flask routes (auth, dashboard, per-session actions, admin panel)
- `tg_core.py` — bridges Flask (sync) to Telethon (async) using one
  background event-loop thread; also owns the Telegram-side logic (login,
  OTP, devices, 2FA, clean account, change DP, live message forwarding) —
  ported directly from your bot's `main.py`
- `db.py` — plain SQLite storage (users, sessions, broadcasts), no ORM
- `templates/` + `static/style.css` — dark-themed UI matching the bot's look

Each logged-in Telegram client is kept connected in memory while the server
runs (cached per session id), reconnecting automatically from its stored
session string the next time you open that session's panel if the
connection dropped.

## Admin access

Promote a user to admin directly in SQLite if ever needed:

```bash
sqlite3 instance/webapp.sqlite "UPDATE users SET is_admin=1 WHERE username='someuser';"
```

## Production notes

This ships with Flask's built-in dev server (`threaded=True`), which is fine
for testing or light use. For real production traffic, run it behind
Gunicorn/uWSGI + nginx, and move `SECRET_KEY` / admin credentials into
environment variables (never commit them).
