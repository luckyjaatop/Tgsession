import os
import json
import zipfile
import io
import time
import secrets
import string
import hashlib
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session as flask_session, jsonify, Response, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

import db
import tg_core

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-in-production")

db.init_db()


# ─────────────────────── auth helpers ───────────────────────

def current_user():
    uid = flask_session.get("uid")
    if not uid:
        return None
    return db.get_user(uid)


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or not u["is_admin"]:
            abort(403)
        return f(*a, **kw)
    return wrapper


def access_required(f):
    """User must be logged in AND have an active trial/premium/admin license."""
    @wraps(f)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            return redirect(url_for("login", next=request.path))
        if not db.has_access(u):
            flash("Your access has expired or isn't active yet. Contact the admin.", "warning")
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return wrapper


@app.context_processor
def inject_user():
    return {"current_user": current_user(), "has_access": db.has_access}


def _hash_api_key(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def api_user():
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None, (jsonify({"ok": False, "error": "Missing Authorization: Bearer <API_KEY> header."}), 401)
    raw = auth[7:].strip()
    if not raw:
        return None, (jsonify({"ok": False, "error": "Empty API key."}), 401)
    row = db.get_api_key_by_hash(_hash_api_key(raw))
    if not row:
        return None, (jsonify({"ok": False, "error": "Invalid or revoked API key."}), 401)
    if not db.has_access(row):
        return None, (jsonify({"ok": False, "error": "Your account does not have active access."}), 403)
    db.touch_api_key(row["id"])
    return row, None


def api_owned_session(row, session_id):
    s = db.get_session(session_id)
    if not s or (s["user_id"] != row["user_id"] and not row["is_admin"]):
        return None
    return s


# ─────────────────────── auth routes ───────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "danger")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
        else:
            ok = db.create_user(username, generate_password_hash(password))
            if not ok:
                flash("That username is already taken.", "danger")
            else:
                flash("Account created! You've been given a 1-hour free trial. Log in to continue.", "success")
                return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        u = db.get_user_by_username(username)
        if u and check_password_hash(u["password_hash"], password):
            flask_session["uid"] = u["id"]
            flash(f"Welcome back, {username}!", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    flask_session.clear()
    return redirect(url_for("login"))


# ─────────────────────── dashboard ───────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    sessions = db.user_sessions(u["id"])
    broadcasts = db.recent_broadcasts(3)
    return render_template("dashboard.html", user=u, sessions=sessions, broadcasts=broadcasts,
                            access_ok=db.has_access(u))


@app.route("/api")
@login_required
def api_dashboard():
    return render_template("api.html", keys=db.user_api_keys(current_user()["id"]))


@app.route("/api/keys/generate", methods=["POST"])
@login_required
def api_generate_key():
    raw = "smp_" + secrets.token_urlsafe(36)
    db.add_api_key(current_user()["id"], _hash_api_key(raw), raw[:12])
    return render_template("api.html", keys=db.user_api_keys(current_user()["id"]), new_key=raw)


@app.route("/api/keys/<int:key_id>/revoke", methods=["POST"])
@login_required
def api_revoke_key(key_id):
    db.revoke_api_key(key_id, current_user()["id"])
    flash("API key revoked.", "success")
    return redirect(url_for("api_dashboard"))


# ─────────────────────── session add (file / zip) ───────────────────────

@app.route("/sessions/add", methods=["POST"])
@access_required
def sessions_add():
    u = current_user()
    if db.count_sessions(u["id"]) >= u["max_sessions"] and not u["is_admin"]:
        flash(f"Session limit reached ({u['max_sessions']}). Ask the admin to raise your limit.", "warning")
        return redirect(url_for("dashboard"))

    f = request.files.get("session_file")
    if not f or not f.filename:
        flash("Please choose a .session file.", "danger")
        return redirect(url_for("dashboard"))

    raw = f.read()
    try:
        ss, name, phone = tg_core.login_from_bytes(raw)
        db.add_session(u["id"], phone, name, ss)
        flash(f"Session added: {name} (+{phone})", "success")
    except Exception as e:
        flash(f"Failed to add session: {e}", "danger")
    return redirect(url_for("dashboard"))


@app.route("/sessions/add_zip", methods=["POST"])
@access_required
def sessions_add_zip():
    u = current_user()
    f = request.files.get("zip_file")
    if not f or not f.filename:
        flash("Please choose a .zip file.", "danger")
        return redirect(url_for("dashboard"))

    raw = f.read()
    success, fail = 0, 0
    results = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        names = [n for n in zf.namelist() if not n.endswith("/")]
    except Exception:
        flash("That doesn't look like a valid .zip file.", "danger")
        return redirect(url_for("dashboard"))

    for name in names:
        # Respect each user's session limit as we go (admins are unlimited)
        if not u["is_admin"] and db.count_sessions(u["id"]) >= u["max_sessions"]:
            results.append(f"⏭ {name}: skipped (session limit reached)")
            continue
        try:
            raw_file = zf.read(name)
            try:
                ss, sname, phone = tg_core.login_from_bytes(raw_file)
            except Exception as e:
                fail += 1
                results.append(f"❌ {name}: {e}")
                time.sleep(1.2)  # pace even on failure to avoid IP flood-limits
                continue
            db.add_session(u["id"], phone, sname, ss)
            success += 1
            results.append(f"✅ {name}: {sname} (+{phone})")
            # Pacing between successful logins — connecting many accounts
            # back-to-back with zero delay is what makes Telegram flood-limit
            # the connection after the first couple of accounts.
            time.sleep(1.2)
        except Exception as e:
            fail += 1
            results.append(f"❌ {name}: {e}")

    flash(f"ZIP import finished — {success} added, {fail} failed.", "success" if success else "warning")
    flask_session["last_zip_results"] = results[-50:]
    return redirect(url_for("dashboard"))


# ─────────────────────── session control panel ───────────────────────

def _owned_session_or_404(session_id):
    u = current_user()
    row = db.get_session(session_id)
    if not row or (row["user_id"] != u["id"] and not u["is_admin"]):
        abort(404)
    return row


@app.route("/sessions/<int:session_id>")
@access_required
def session_panel(session_id):
    row = _owned_session_or_404(session_id)
    giving = tg_core.give_message_active(session_id)
    return render_template("session.html", s=row, giving=giving)


@app.route("/sessions/<int:session_id>/otp")
@access_required
def session_otp(session_id):
    row = _owned_session_or_404(session_id)
    try:
        result = tg_core.fetch_otp(row)
        if result:
            return jsonify({"ok": True, "code": result["code"], "full": result["full"]})
        return jsonify({"ok": False, "error": "No recent login-code message found from Telegram (777000)."})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/sessions/<int:session_id>/devices")
@access_required
def session_devices(session_id):
    row = _owned_session_or_404(session_id)
    try:
        return jsonify({"ok": True, "devices": tg_core.get_devices(row)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/sessions/<int:session_id>/devices/<int:device_hash>/logout", methods=["POST"])
@access_required
def session_device_logout(session_id, device_hash):
    row = _owned_session_or_404(session_id)
    try:
        tg_core.logout_device(row, device_hash)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/sessions/<int:session_id>/logout_all_others", methods=["POST"])
@access_required
def session_logout_all_others(session_id):
    row = _owned_session_or_404(session_id)
    try:
        n = tg_core.logout_all_other_devices(row)
        return jsonify({"ok": True, "count": n})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/sessions/<int:session_id>/2fa")
@access_required
def session_2fa(session_id):
    row = _owned_session_or_404(session_id)
    try:
        return jsonify({"ok": True, **tg_core.get_2fa_status(row)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/sessions/<int:session_id>/2fa/reset", methods=["POST"])
@access_required
def session_2fa_reset(session_id):
    row = _owned_session_or_404(session_id)
    try:
        return jsonify({"ok": True, "result": tg_core.reset_2fa(row)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/sessions/<int:session_id>/clean", methods=["POST"])
@access_required
def session_clean(session_id):
    row = _owned_session_or_404(session_id)
    try:
        return jsonify({"ok": True, "result": tg_core.clean_account(row)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/sessions/<int:session_id>/change_dp", methods=["POST"])
@access_required
def session_change_dp(session_id):
    row = _owned_session_or_404(session_id)
    f = request.files.get("photo")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "No photo uploaded."})
    try:
        tg_core.change_dp(row, f.read())
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/sessions/<int:session_id>/string")
@access_required
def session_string(session_id):
    row = _owned_session_or_404(session_id)
    return jsonify({"ok": True, "session_string": tg_core.get_session_string(row)})


@app.route("/sessions/<int:session_id>/logout", methods=["POST"])
@access_required
def session_logout_delete(session_id):
    row = _owned_session_or_404(session_id)
    try:
        tg_core.logout_session(row)
    except Exception:
        pass
    tg_core.stop_give_message(row)
    db.delete_session(session_id)
    flash("Session logged out and removed.", "success")
    return redirect(url_for("dashboard"))


@app.route("/sessions/<int:session_id>/remove", methods=["POST"])
@access_required
def session_remove_only(session_id):
    """Remove from the site WITHOUT logging the Telegram account out."""
    row = _owned_session_or_404(session_id)
    tg_core.stop_give_message(row)
    tg_core.drop_client(session_id)
    db.delete_session(session_id)
    flash("Session removed from the site (Telegram account left logged in).", "success")
    return redirect(url_for("dashboard"))


# ─────────────────────── Give Message (SSE live stream) ───────────────────────

@app.route("/sessions/<int:session_id>/give_message/toggle", methods=["POST"])
@access_required
def give_message_toggle(session_id):
    row = _owned_session_or_404(session_id)
    try:
        if tg_core.give_message_active(session_id):
            tg_core.stop_give_message(row)
            return jsonify({"ok": True, "active": False})
        else:
            tg_core.start_give_message(row)
            return jsonify({"ok": True, "active": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/sessions/<int:session_id>/give_message/stream")
@access_required
def give_message_stream(session_id):
    row = _owned_session_or_404(session_id)  # auth check before opening the stream

    def gen():
        while True:
            if not tg_core.give_message_active(session_id):
                yield "event: stopped\ndata: {}\n\n"
                break
            msg = tg_core.pop_give_messages(session_id, block_timeout=15)
            if msg is None:
                yield ": keep-alive\n\n"
                continue
            yield f"data: {json.dumps(msg)}\n\n"

    return Response(gen(), mimetype="text/event-stream")


# ─────────────────────── public API v1 ───────────────────────

@app.route("/api/v1/me")
def api_me():
    u, err = api_user()
    if err: return err
    return jsonify({"ok": True, "user": {"username": u["username"], "access": u["access"], "max_sessions": u["max_sessions"], "sessions": db.count_sessions(u["user_id"])}})

@app.route("/api/v1/sessions")
def api_sessions():
    u, err = api_user()
    if err: return err
    rows = db.user_sessions(u["user_id"])
    return jsonify({"ok": True, "sessions": [{"id": r["id"], "name": r["name"], "phone": r["phone"], "created_at": r["created_at"]} for r in rows]})

@app.route("/api/v1/sessions/<int:session_id>/2fa")
def api_2fa_status(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try: return jsonify({"ok": True, **tg_core.get_2fa_status(row)})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/v1/sessions/<int:session_id>/2fa/reset", methods=["POST"])
def api_2fa_reset(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try: return jsonify({"ok": True, "result": tg_core.reset_2fa(row)})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/v1")
def api_root():
    return jsonify({"ok": True, "name": "Session Manager Pro API", "version": "1.0", "docs": "/api"})


# ─────────────────────── admin panel ───────────────────────

@app.route("/admin")
@admin_required
def admin_home():
    return render_template("admin.html", users=db.all_users(), stats=db.stats(),
                            broadcasts=db.recent_broadcasts(10), codes=db.all_redeem_codes())


@app.route("/admin/users/<int:uid>/access", methods=["POST"])
@admin_required
def admin_set_access(uid):
    access = request.form.get("access", "none")
    max_sessions = request.form.get("max_sessions", type=int)
    trial_hours = request.form.get("trial_hours", type=int)
    db.set_user_access(uid, access, max_sessions=max_sessions, trial_hours=trial_hours)
    flash("User updated.", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_delete_user(uid):
    if uid == current_user()["id"]:
        flash("You can't delete your own admin account.", "danger")
    else:
        db.delete_user(uid)
        flash("User deleted.", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/broadcast", methods=["POST"])
@admin_required
def admin_broadcast():
    message = request.form.get("message", "").strip()
    if message:
        db.add_broadcast(message)
        flash("Broadcast sent to all users.", "success")
    return redirect(url_for("admin_home"))


def _generate_code():
    alphabet = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "SMP-" + "-".join(parts)


@app.route("/admin/redeem/generate", methods=["POST"])
@admin_required
def admin_generate_redeem():
    access = request.form.get("access", "trial")
    max_sessions = request.form.get("max_sessions", type=int) or 1
    duration_hours = request.form.get("duration_hours", type=int) or None
    code = _generate_code()
    db.create_redeem_code(code, access, max_sessions, duration_hours)
    flash(f"Redeem code generated: {code}", "success")
    return redirect(url_for("admin_home"))


@app.route("/redeem", methods=["GET", "POST"])
@login_required
def redeem():
    if request.method == "POST":
        code = request.form.get("code", "").strip().upper()
        ok, msg = db.redeem_code_for_user(code, current_user()["id"])
        flash(msg, "success" if ok else "danger")
        if ok:
            return redirect(url_for("dashboard"))
    return render_template("redeem.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
