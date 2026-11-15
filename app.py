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
    session as flask_session, jsonify, Response, abort, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash

import requests

import db
import tg_core

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-in-production")

db.init_db()

# ─────────────────────── billing / payments (FamGateway) ───────────────────────
FAMGATEWAY_API_KEY = "fam_ba78cad2a3ffd89a2c248e36995b3e129b349fd1d209e3de"
FAMGATEWAY_BASE = "https://gatewaylive.qzz.io/api/v1"
FAMGATEWAY_UPI_ID = "luckystore@fam"  # display-only

PLANS = {
    "10d": {"label": "10 Days",  "days": 10, "amount": 40.0},
    "15d": {"label": "15 Days",  "days": 15, "amount": 60.0, "featured": True},
    "1m":  {"label": "1 Month",  "days": 30, "amount": 100.0},
}
PREMIUM_MAX_SESSIONS = 3  # sessions granted per paid plan; adjust as needed


def fg_create_order(amount, ref, webhook_url=None):
    payload = {"amount": amount, "ref": ref}
    if webhook_url:
        payload["webhook_url"] = webhook_url
    r = requests.post(
        f"{FAMGATEWAY_BASE}/orders", json=payload,
        headers={"x-api-key": FAMGATEWAY_API_KEY, "content-type": "application/json"},
        timeout=15,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("status") != "success":
        raise RuntimeError(body.get("message") or "FamGateway order creation failed")
    return body["data"]


def fg_verify_order(order_id):
    r = requests.get(
        f"{FAMGATEWAY_BASE}/verify", params={"order_id": order_id},
        headers={"x-api-key": FAMGATEWAY_API_KEY}, timeout=15,
    )
    r.raise_for_status()
    return r.json().get("data", {}) or {}


def fg_verify_utr(order_id, utr):
    r = requests.post(
        f"{FAMGATEWAY_BASE}/verify_utr", json={"order_id": order_id, "utr": utr},
        headers={"x-api-key": FAMGATEWAY_API_KEY, "content-type": "application/json"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json().get("data", {}) or {}


# ─────────────────────── auth helpers ───────────────────────

def current_user():
    uid = flask_session.get("uid")
    if not uid:
        return None
    u = db.get_user(uid)
    if not u:
        return None
    # Single active session: if someone logged into this account from
    # elsewhere since this browser last logged in, this session's token
    # no longer matches and gets signed out — stops two people sharing
    # one username/password at the same time.
    if u.get("session_token") and flask_session.get("stoken") != u.get("session_token"):
        flask_session.clear()
        return None
    return u


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
    if not db.check_and_bind_api_key_ip(row["id"], get_client_ip()):
        return None, (jsonify({
            "ok": False,
            "error": "This API key is already active on another device/network. Reset the device binding from the website's API page if this is you."
        }), 409)
    db.touch_api_key(row["id"])
    return row, None


def api_owned_session(row, session_id):
    s = db.get_session(session_id)
    if not s or (s["user_id"] != row["user_id"] and not row["is_admin"]):
        return None
    return s


# ─────────────────────── auth routes ───────────────────────

MAX_SIGNUPS_PER_IP = 1
SIGNUP_WINDOW_DAYS = 30


def get_client_ip():
    # Vercel sits in front of the app as a proxy, so request.remote_addr is
    # the proxy's own IP, not the visitor's. The real client IP is the first
    # entry in X-Forwarded-For.
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        # Honeypot: a field hidden from real users via CSS. Simple signup
        # bots/scripts that fill every field in the form will trip it.
        if request.form.get("website"):
            flash("Account created! You've been given a 1-hour free trial. Log in to continue.", "success")
            return redirect(url_for("login"))

        ip = get_client_ip()
        if not username or not password:
            flash("Username and password are required.", "danger")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
        elif db.count_recent_registrations(ip, hours=24 * SIGNUP_WINDOW_DAYS) >= MAX_SIGNUPS_PER_IP:
            flash("Only one free account is allowed per network per month. Please try again later.", "danger")
        else:
            ok = db.create_user(username, generate_password_hash(password))
            if not ok:
                flash("That username is already taken.", "danger")
            else:
                db.record_registration(ip)
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
            token = secrets.token_hex(16)
            db.set_session_token(u["id"], token)
            flask_session["uid"] = u["id"]
            flask_session["stoken"] = token
            flash(f"Welcome back, {username}!", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    u = current_user()
    if u:
        db.set_session_token(u["id"], "")  # also signs this account out everywhere else
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


@app.route("/api/keys/reset-device", methods=["POST"])
@login_required
def api_reset_device():
    db.reset_api_key_binding(current_user()["id"])
    flash("Device binding cleared — your key will lock to the next device/network that uses it.", "success")
    return redirect(url_for("api_dashboard"))


@app.route("/billing")
@login_required
def billing():
    u = current_user()
    return render_template(
        "billing.html",
        plans=PLANS,
        orders=db.user_orders(u["id"]),
        access_ok=db.has_access(u),
    )


def _fulfill_if_paid(order):
    """Shared by polling, the webhook, and manual UTR entry. Always re-checks
    with FamGateway's own /verify endpoint server-side before granting
    anything — never trusts a client or webhook claim by itself."""
    if order["fulfilled"]:
        return "paid"
    try:
        data = fg_verify_order(order["order_id"])
    except Exception as e:
        return f"error: {e}"
    if data.get("paid"):
        if db.mark_order_fulfilled(order["order_id"]):
            db.grant_premium(order["user_id"], order["days"], max_sessions=PREMIUM_MAX_SESSIONS)
        return "paid"
    if data.get("status") == "expired":
        db.mark_order_status(order["order_id"], "expired")
        return "expired"
    return "pending"


@app.route("/billing/buy/<plan_id>", methods=["POST"])
@login_required
def billing_buy(plan_id):
    plan = PLANS.get(plan_id)
    if not plan:
        flash("Unknown plan.", "danger")
        return redirect(url_for("billing"))

    u = current_user()
    ref = f"u{u['id']}-{plan_id}-{secrets.token_hex(4)}"
    webhook_url = request.url_root.rstrip("/") + url_for("billing_webhook")
    try:
        data = fg_create_order(plan["amount"], ref, webhook_url=webhook_url)
    except Exception as e:
        flash(f"Could not start payment: {e}", "danger")
        return redirect(url_for("billing"))

    order_id = data.get("order_id")
    if not order_id:
        flash("Payment gateway did not return an order id.", "danger")
        return redirect(url_for("billing"))

    # FamGateway returns a slightly adjusted amount (e.g. 10 -> 10.15) with a
    # unique fractional suffix so it can auto-match the payment — that exact
    # amount is what the customer must actually pay, not the plan's flat price.
    # Cast explicitly: some APIs send amount as a string ("10.15") in JSON,
    # which would otherwise crash the %.2f formatting on the payment page.
    try:
        actual_amount = float(data.get("amount", plan["amount"]))
    except (TypeError, ValueError):
        actual_amount = plan["amount"]

    db.create_order_record(
        order_id, u["id"], plan_id, actual_amount, plan["days"],
        extra={"qr_url": data.get("qr_url"), "upi_url": data.get("upi_url"), "ref": ref},
    )
    return redirect(url_for("billing_pay", order_id=order_id))


@app.route("/billing/pay/<order_id>")
@login_required
def billing_pay(order_id):
    u = current_user()
    order = db.get_order(order_id)
    if not order or (order["user_id"] != u["id"] and not u["is_admin"]):
        flash("Order not found.", "danger")
        return redirect(url_for("billing"))
    plan = PLANS.get(order["plan_id"], {})
    try:
        return render_template("payment.html", order=order, plan=plan, upi_id=FAMGATEWAY_UPI_ID)
    except Exception as e:
        flash(f"Could not open the payment page: {e}", "danger")
        return redirect(url_for("billing"))


@app.route("/billing/check/<order_id>", methods=["POST"])
@login_required
def billing_check(order_id):
    order = db.get_order(order_id)
    u = current_user()
    if not order or (order["user_id"] != u["id"] and not u["is_admin"]):
        return jsonify({"ok": False, "error": "Order not found."}), 404
    result = _fulfill_if_paid(order)
    return jsonify({"ok": True, "status": result})


@app.route("/billing/verify-utr/<order_id>", methods=["POST"])
@login_required
def billing_verify_utr(order_id):
    """Fallback for when FamGateway's Gmail-based auto-verification is
    delayed — lets the payer submit their 12-digit UTR directly."""
    order = db.get_order(order_id)
    u = current_user()
    if not order or (order["user_id"] != u["id"] and not u["is_admin"]):
        return jsonify({"ok": False, "error": "Order not found."}), 404

    utr = (request.get_json(silent=True) or {}).get("utr", "").strip()
    if not utr.isdigit() or len(utr) != 12:
        return jsonify({"ok": False, "error": "Enter the 12-digit UTR number from your payment."}), 400

    if order["fulfilled"]:
        return jsonify({"ok": True, "status": "paid"})
    try:
        data = fg_verify_utr(order["order_id"], utr)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    if data.get("paid"):
        if db.mark_order_fulfilled(order["order_id"]):
            db.grant_premium(order["user_id"], order["days"], max_sessions=PREMIUM_MAX_SESSIONS)
        return jsonify({"ok": True, "status": "paid"})
    return jsonify({"ok": True, "status": "pending", "message": "UTR submitted but not matched yet — try again shortly."})


@app.route("/billing/webhook", methods=["POST"])
def billing_webhook():
    # The sample handler FamGateway documents has no signature check, so we
    # don't trust the webhook body's own claims — we just treat it as a
    # "check now" trigger and re-verify server-side via fg_verify_order.
    data = request.get_json(silent=True) or {}
    if data.get("event") != "order.paid":
        return jsonify({"received": True})
    order_id = data.get("order_id")
    order = db.get_order(order_id) if order_id else None
    if order:
        _fulfill_if_paid(order)
    return jsonify({"received": True})


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
    valid_rows = []
    should_validate = request.args.get("validate", "0") == "1"

    # The database is the authoritative app list.  When the client asks for a
    # validation pass, also reconcile each stored Telegram authorization.
    # Only a definitive Telegram revocation/logout removes the DB row;
    # transient network errors are kept.
    for row in rows:
        if should_validate:
            try:
                state = tg_core.validate_session(row)
            except Exception:
                state = None

            if state is False:
                try:
                    tg_core.stop_give_message(row)
                except Exception:
                    pass
                try:
                    tg_core.drop_client(row["id"])
                except Exception:
                    pass
                db.delete_session(row["id"])
                continue

        valid_rows.append(row)

    response = jsonify({
        "ok": True,
        "sessions": [
            {"id": r["id"], "name": r["name"], "phone": r["phone"], "created_at": r["created_at"]}
            for r in valid_rows
        ]
    })
    # The UI must always receive the current database state after an add/remove.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response

def _extract_session_raw_and_dc():
    f = request.files.get("session_file")
    dc_val = request.form.get("dc_id")
    if f and f.filename:
        raw = f.read()
    else:
        data = request.get_json(silent=True) or {}
        ss = data.get("session_string") or data.get("session") or request.form.get("session_string") or request.form.get("session")
        raw = ss.strip().encode("utf-8") if ss else None
        if dc_val is None:
            dc_val = data.get("dc_id")
    try:
        dc_hint = int(dc_val) if dc_val is not None and str(dc_val).strip() else None
    except Exception:
        dc_hint = None
    return raw, dc_hint


@app.route("/api/v1/sessions/resolve", methods=["POST"])
def api_sessions_resolve():
    """Validate and inspect a session string/file without saving it to the database."""
    u, err = api_user()
    if err: return err
    raw, dc_hint = _extract_session_raw_and_dc()
    if not raw:
        return jsonify({"ok": False, "error": "Provide a session_file upload or a session_string field."}), 400
    try:
        info = tg_core.inspect_session_bytes(raw, dc_id_hint=dc_hint)
        return jsonify({
            "ok": True,
            "valid": True,
            "type": info["type"],
            "dc_id": info["dc_id"],
            "user_id": info["user_id"],
            "name": info["name"],
            "phone": info["phone"],
            "username": info["username"],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/add", methods=["POST"])
def api_sessions_add():
    """Add one session. Accepts either a multipart file upload
    (field: session_file) or a JSON/form body with session_string."""
    u, err = api_user()
    if err: return err
    if not u["is_admin"] and db.count_sessions(u["user_id"]) >= u["max_sessions"]:
        return jsonify({"ok": False, "error": f"Session limit reached ({u['max_sessions']})."}), 403

    raw, dc_hint = _extract_session_raw_and_dc()
    if not raw:
        return jsonify({"ok": False, "error": "Provide a session_file upload or a session_string field."}), 400

    try:
        ss, name, phone = tg_core.login_from_bytes(raw, dc_id_hint=dc_hint)
        sid = db.add_session(u["user_id"], phone, name, ss)

        # Verify the newly inserted row is immediately visible to the same
        # account. This prevents the frontend from reporting success while
        # the session list still cannot see the saved record.
        saved = db.get_session(sid) if sid is not None else None
        if not saved or saved["user_id"] != u["user_id"]:
            return jsonify({
                "ok": False,
                "error": "Session was verified but could not be loaded from storage. Please try again."
            }), 500

        return jsonify({
            "ok": True,
            "session": {
                "id": saved["id"],
                "name": saved["name"],
                "phone": saved["phone"],
                "created_at": saved["created_at"]
            }
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/add_zip", methods=["POST"])
def api_sessions_add_zip():
    """Bulk-add sessions from a .zip of raw .session files (field: zip_file)."""
    u, err = api_user()
    if err: return err
    f = request.files.get("zip_file")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "Provide a zip_file upload."}), 400

    raw = f.read()
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        names = [n for n in zf.namelist() if not n.endswith("/")]
    except Exception:
        return jsonify({"ok": False, "error": "That doesn't look like a valid .zip file."}), 400

    success, fail = 0, 0
    results = []
    for name in names:
        if not u["is_admin"] and db.count_sessions(u["user_id"]) >= u["max_sessions"]:
            results.append({"file": name, "ok": False, "error": "session limit reached"})
            continue
        try:
            raw_file = zf.read(name)
            ss, sname, phone = tg_core.login_from_bytes(raw_file)
            sid = db.add_session(u["user_id"], phone, sname, ss)
            success += 1
            results.append({"file": name, "ok": True, "id": sid, "name": sname, "phone": phone})
        except Exception as e:
            fail += 1
            results.append({"file": name, "ok": False, "error": str(e)})
        time.sleep(1.2)  # pace logins to avoid Telegram flood-limits

    return jsonify({"ok": True, "added": success, "failed": fail, "results": results})


@app.route("/api/v1/sessions/login/start", methods=["POST"])
def api_sessions_login_start():
    """Start phone + OTP login and store the pending Telethon pre-auth session in MongoDB."""
    u, err = api_user()
    if err: return err
    if not u["is_admin"] and db.count_sessions(u["user_id"]) >= u["max_sessions"]:
        return jsonify({"ok": False, "error": f"Session limit reached ({u['max_sessions']})."}), 403
    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or request.form.get("phone") or "").strip()
    if not phone:
        return jsonify({"ok": False, "error": "Provide a phone number with country code."}), 400
    try:
        started = tg_core.start_phone_login(phone)
        token = db.create_pending_login(
            user_id=u["user_id"],
            phone=started["phone"],
            phone_code_hash=started["phone_code_hash"],
            temp_session=started["temp_session"],
            api_id=started["api_id"],
            api_hash=started["api_hash"],
        )
        return jsonify({
            "ok": True,
            "login_token": token,
            "phone": started["phone"],
            "delivery": started["delivery"],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/login/code", methods=["POST"])
def api_sessions_login_code():
    """Verify the Telegram OTP code for a pending login."""
    u, err = api_user()
    if err: return err
    data = request.get_json(silent=True) or {}
    token = (data.get("login_token") or request.form.get("login_token") or "").strip()
    code = (data.get("code") or request.form.get("code") or "").strip()
    if not token or not code:
        return jsonify({"ok": False, "error": "Provide login_token and code."}), 400
    pending = db.get_pending_login(token, u["user_id"])
    if not pending:
        return jsonify({"ok": False, "error": "Login attempt expired or not found. Please request a new code."}), 404
    try:
        res = tg_core.verify_phone_code(
            temp_session=pending["temp_session"],
            api_id=pending["api_id"],
            api_hash=pending["api_hash"],
            phone=pending["phone"],
            phone_code_hash=pending["phone_code_hash"],
            code=code,
        )
        if res.get("password_required"):
            db.update_pending_login(
                token,
                temp_session=res["temp_session"],
                needs_password=True,
                hint=res.get("hint") or "",
            )
            return jsonify({
                "ok": True,
                "password_required": True,
                "hint": res.get("hint") or "",
            })

        if not u["is_admin"] and db.count_sessions(u["user_id"]) >= u["max_sessions"]:
            db.delete_pending_login(token)
            return jsonify({"ok": False, "error": f"Session limit reached ({u['max_sessions']})."}), 403

        sid = db.add_session(u["user_id"], res["phone"], res["name"], res["session_string"])
        db.delete_pending_login(token)
        saved = db.get_session(sid) if sid is not None else None
        if not saved:
            return jsonify({"ok": False, "error": "Logged in, but failed to save session. Please try again."}), 500
        return jsonify({
            "ok": True,
            "password_required": False,
            "session": {
                "id": saved["id"],
                "name": saved["name"],
                "phone": saved["phone"],
                "created_at": saved["created_at"],
            },
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/login/password", methods=["POST"])
def api_sessions_login_password():
    """Complete a pending phone login that requires a 2FA password."""
    u, err = api_user()
    if err: return err
    data = request.get_json(silent=True) or {}
    token = (data.get("login_token") or request.form.get("login_token") or "").strip()
    password = data.get("password") if "password" in data else request.form.get("password")
    if not token or not password:
        return jsonify({"ok": False, "error": "Provide login_token and password."}), 400
    pending = db.get_pending_login(token, u["user_id"])
    if not pending:
        return jsonify({"ok": False, "error": "Login attempt expired or not found. Please start again."}), 404
    try:
        res = tg_core.verify_phone_password(
            temp_session=pending["temp_session"],
            api_id=pending["api_id"],
            api_hash=pending["api_hash"],
            phone=pending["phone"],
            password=password,
        )
        if not u["is_admin"] and db.count_sessions(u["user_id"]) >= u["max_sessions"]:
            db.delete_pending_login(token)
            return jsonify({"ok": False, "error": f"Session limit reached ({u['max_sessions']})."}), 403

        sid = db.add_session(u["user_id"], res["phone"], res["name"], res["session_string"])
        db.delete_pending_login(token)
        saved = db.get_session(sid) if sid is not None else None
        if not saved:
            return jsonify({"ok": False, "error": "Logged in, but failed to save session. Please try again."}), 500
        return jsonify({
            "ok": True,
            "session": {
                "id": saved["id"],
                "name": saved["name"],
                "phone": saved["phone"],
                "created_at": saved["created_at"],
            },
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/login/cancel", methods=["POST"])
def api_sessions_login_cancel():
    u, err = api_user()
    if err: return err
    data = request.get_json(silent=True) or {}
    token = (data.get("login_token") or "").strip()
    if token and db.get_pending_login(token, u["user_id"]):
        db.delete_pending_login(token)
    return jsonify({"ok": True})


@app.route("/api/v1/sessions/<int:session_id>/export")
def api_session_export(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        return jsonify({"ok": True, **tg_core.export_session_formats(row)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/<int:session_id>/otp")
def api_otp(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        result = tg_core.fetch_otp(row)
        if not result:
            return jsonify({"ok": True, "found": False, "code": None})
        return jsonify({"ok": True, "found": True, **result})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/send_message", methods=["POST"])
def api_send_message(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404

    data = request.get_json(silent=True) or {}
    peer_id = data.get("peer_id")
    username = (data.get("username") or request.form.get("username") or "").strip().lstrip("@")
    text = data.get("message") or request.form.get("message") or ""
    reply_to = data.get("reply_to_msg_id")
    if not text or (not username and not peer_id):
        return jsonify({"ok": False, "error": "Provide 'message' plus either 'username' or 'peer_id'."}), 400

    target = int(peer_id) if peer_id else username
    try:
        result = tg_core.send_message(row, target, text, reply_to=reply_to, fallback_username=username)
        return jsonify({
            "ok": True,
            "result": result,
            "message_id": result.get("message_id"),
            "message": result.get("message"),
        })
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e), "code": "SEND_NOT_ALLOWED"}), 403
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/dialogs")
def api_dialogs(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        try:
            limit = max(20, min(int(request.args.get("limit", "80")), 100))
        except (TypeError, ValueError):
            limit = 80
        last = None
        for attempt in range(3):
            try:
                return jsonify({"ok": True, "dialogs": tg_core.list_dialogs(row, limit=limit)})
            except Exception as exc:
                last = exc
                if attempt < 2:
                    time.sleep(0.35 * (attempt + 1))
        raise last or RuntimeError("Telegram request failed")
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/search")
def api_search(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"ok": True, "results": []})
    try:
        last = None
        for attempt in range(3):
            try:
                return jsonify({"ok": True, "results": tg_core.search_dialogs(row, q)})
            except Exception as exc:
                last = exc
                if attempt < 2:
                    time.sleep(0.35 * (attempt + 1))
        raise last or RuntimeError("Telegram search failed")
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram search failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/messages/button", methods=["POST"])
def api_message_button(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    peer = data.get("peer") or data.get("username")
    try:
        message_id = int(data.get("message_id"))
        button_row = int(data.get("row"))
        button_col = int(data.get("col"))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "message_id, row and col are required."}), 400
    if not peer:
        return jsonify({"ok": False, "error": "peer or username is required."}), 400
    try:
        result = tg_core.click_message_button(row, peer, message_id, button_row, button_col)
        return jsonify({"ok": True, **(result or {})})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Button action failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/messages")
def api_messages(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    peer = request.args.get("peer") or request.args.get("username")
    fallback_username = request.args.get("username")
    if not peer:
        return jsonify({"ok": False, "error": "Provide ?peer=<dialog id> or ?username=<username>."}), 400
    last_error = None
    # Telegram/Vercel can occasionally cancel a short-lived request while the
    # session is reconnecting. Retry a couple of times instead of exposing a
    # transient CancelledError to the UI.
    for attempt in range(3):
        try:
            bundle = tg_core.get_messages_bundle(row, peer, limit=50, fallback_username=fallback_username)
            return jsonify({"ok": True, "messages": bundle["messages"], "peer": bundle["peer"]})
        except Exception as e:
            last_error = e
            if attempt < 2:
                time.sleep(0.25 * (attempt + 1))
    e = last_error or RuntimeError("Telegram request failed")
    return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/messages/updates")
def api_message_updates(session_id):
    """Return only messages newer than after_id for fast chat polling."""
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    peer = request.args.get("peer") or request.args.get("username")
    fallback_username = request.args.get("username")
    if not peer:
        return jsonify({"ok": False, "error": "Provide ?peer=<dialog id> or ?username=<username>."}), 400
    last_error = None
    for attempt in range(2):
        try:
            after_id = int(request.args.get("after_id") or 0)
            messages = tg_core.get_messages(row, peer, limit=50, after_id=after_id, fallback_username=fallback_username)
            return jsonify({"ok": True, "messages": messages})
        except Exception as e:
            last_error = e
            if attempt == 0:
                time.sleep(0.15)
    e = last_error or RuntimeError("Telegram request failed")
    return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/events")
def api_live_events(session_id):
    # Vercel/serverless instances are not safe for a long-lived Telethon
    # connection: the same Telegram auth key can land on another outbound IP.
    # The frontend now uses short-lived Mongo-serialized polling instead.
    return jsonify({
        "ok": False,
        "error": "Live SSE is disabled on the serverless deployment; use polling updates."
    }), 410


@app.route("/api/v1/sessions/<int:session_id>/contacts")
def api_contacts(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row:
        return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        return jsonify({"ok": True, "contacts": tg_core.get_contacts(row)})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/contacts", methods=["POST"])
def api_add_contact(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row:
        return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    target = (data.get("username") or data.get("target") or data.get("user_id") or data.get("phone") or "").strip()
    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    if not target:
        return jsonify({"ok": False, "error": "Provide username, user_id or phone."}), 400
    try:
        return jsonify(tg_core.add_contact(row, target, first_name, last_name))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/<int:session_id>/message/sender-photo/<int:message_id>")
def api_message_sender_photo(session_id, message_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    peer = request.args.get("peer") or request.args.get("username")
    if not peer:
        return jsonify({"ok": False, "error": "Provide ?peer=<id> or ?username=<username>."}), 400
    try:
        data = tg_core.download_sender_photo(row, peer, message_id)
        if not data:
            return jsonify({"ok": False, "error": "No sender photo."}), 404
        return send_file(io.BytesIO(data), mimetype="image/jpeg", as_attachment=False)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404


@app.route("/api/v1/sessions/<int:session_id>/custom-emoji/<int:document_id>")
def api_custom_emoji(session_id, document_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        data, mime, name = tg_core.download_custom_emoji(row, document_id)
        if not data:
            return jsonify({"ok": False, "error": "Custom emoji not found."}), 404
        return send_file(io.BytesIO(data), mimetype=mime, as_attachment=False, download_name=name)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404


@app.route("/api/v1/sessions/<int:session_id>/messages/<path:peer>")
def api_messages_path(session_id, peer):
    """Compatibility route for clients that use /messages/<peer>."""
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        return jsonify({"ok": True, "messages": tg_core.get_messages(row, peer)})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500




@app.route("/api/v1/sessions/<int:session_id>/media/<int:message_id>")
def api_media(session_id, message_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    peer = request.args.get("peer") or request.args.get("username")
    fallback_username = request.args.get("username")
    thumb = request.args.get("thumb") == "1"
    if not peer:
        return jsonify({"ok": False, "error": "Provide ?peer=<id> or ?username=<username>."}), 400
    try:
        data, mime, name = tg_core.download_media(row, peer, message_id, thumb=thumb, fallback_username=fallback_username)
        return send_file(io.BytesIO(data), mimetype=mime, as_attachment=False, download_name=name)
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/send_media", methods=["POST"])
def api_send_media(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    f = request.files.get("file")
    if not f:
        return jsonify({"ok": False, "error": "Provide multipart 'file'."}), 400
    peer_id = request.form.get("peer_id")
    username = (request.form.get("username") or "").strip().lstrip("@")
    if not peer_id and not username:
        return jsonify({"ok": False, "error": "Provide 'peer_id' or 'username'."}), 400
    target = int(peer_id) if peer_id and peer_id != "0" else username
    caption = request.form.get("caption") or ""
    force_document = request.form.get("force_document") in ("1", "true", "True")
    reply_to = request.form.get("reply_to_msg_id")
    try:
        res = tg_core.send_media(
            row, target, f.read(), f.filename or "upload.bin",
            caption=caption, force_document=force_document,
            reply_to=reply_to, fallback_username=username,
        )
        return jsonify({"ok": True, **res})
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Upload failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/stickers")
def api_stickers(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        return jsonify({"ok": True, **tg_core.get_stickers(row)})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Failed to load stickers")}), 500


@app.route("/api/v1/sessions/<int:session_id>/sticker/<int:document_id>")
def api_sticker_image(session_id, document_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    access_hash = request.args.get("access_hash")
    ref = request.args.get("ref") or ""
    if not access_hash:
        return jsonify({"ok": False, "error": "Missing access_hash"}), 400
    try:
        data, mime = tg_core.download_sticker_image(row, document_id, access_hash, ref)
        if not data:
            return jsonify({"ok": False, "error": "Sticker not found"}), 404
        return send_file(io.BytesIO(data), mimetype=mime, as_attachment=False)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404


@app.route("/api/v1/sessions/<int:session_id>/send_sticker", methods=["POST"])
def api_send_sticker(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    peer_id = data.get("peer_id")
    username = (data.get("username") or "").strip().lstrip("@")
    doc_id = data.get("document_id")
    access_hash = data.get("access_hash")
    ref = data.get("file_reference") or ""
    reply_to = data.get("reply_to_msg_id")
    if not doc_id or access_hash is None or (not peer_id and not username):
        return jsonify({"ok": False, "error": "Missing peer or sticker parameters."}), 400
    target = int(peer_id) if peer_id else username
    try:
        res = tg_core.send_sticker(row, target, doc_id, access_hash, ref, reply_to=reply_to, fallback_username=username)
        return jsonify({"ok": True, **res})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Failed to send sticker")}), 500


@app.route("/api/v1/sessions/<int:session_id>/messages/react", methods=["POST"])
def api_react_message(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    peer_id = data.get("peer_id")
    username = (data.get("username") or "").strip().lstrip("@")
    msg_id = data.get("message_id")
    emoji = data.get("emoji")
    target = int(peer_id) if peer_id else username
    try:
        return jsonify(tg_core.react_message(row, target, msg_id, emoji=emoji, fallback_username=username))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/<int:session_id>/messages/edit", methods=["POST"])
def api_edit_message(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    peer_id = data.get("peer_id")
    username = (data.get("username") or "").strip().lstrip("@")
    msg_id = data.get("message_id")
    new_text = data.get("text") or ""
    target = int(peer_id) if peer_id else username
    try:
        return jsonify(tg_core.edit_message(row, target, msg_id, new_text, fallback_username=username))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/<int:session_id>/messages/delete", methods=["POST"])
def api_delete_messages(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    peer_id = data.get("peer_id")
    username = (data.get("username") or "").strip().lstrip("@")
    msg_ids = data.get("message_ids") or []
    revoke = data.get("revoke", True)
    target = int(peer_id) if peer_id else username
    try:
        return jsonify(tg_core.delete_messages(row, target, msg_ids, revoke=revoke, fallback_username=username))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/<int:session_id>/messages/forward", methods=["POST"])
def api_forward_messages(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    from_peer = data.get("from_peer_id") or data.get("from_username")
    to_peer = data.get("to_peer_id") or data.get("to_username")
    msg_ids = data.get("message_ids") or []
    try:
        return jsonify(tg_core.forward_messages(
            row, from_peer, to_peer, msg_ids,
            fallback_from_username=data.get("from_username"),
            fallback_to_username=data.get("to_username"),
        ))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/<int:session_id>/messages/pin", methods=["POST"])
def api_pin_message(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    peer_id = data.get("peer_id")
    username = (data.get("username") or "").strip().lstrip("@")
    msg_id = data.get("message_id")
    unpin = bool(data.get("unpin", False))
    target = int(peer_id) if peer_id else username
    try:
        return jsonify(tg_core.pin_message(row, target, msg_id, unpin=unpin, fallback_username=username))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/<int:session_id>/messages/read", methods=["POST"])
def api_mark_read(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    peer_id = data.get("peer_id")
    username = (data.get("username") or "").strip().lstrip("@")
    target = int(peer_id) if peer_id else username
    if not target:
        return jsonify({"ok": False, "error": "Provide peer_id or username."}), 400
    try:
        return jsonify(tg_core.mark_read(row, target, fallback_username=username))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/<int:session_id>/me/profile")
def api_me_profile(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        return jsonify({"ok": True, "profile": tg_core.get_own_profile(row)})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/me/profile/photo")
def api_me_profile_photo(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        data = tg_core.download_own_profile_photo(row)
        if not data:
            return jsonify({"ok": False, "error": "No profile photo."}), 404
        return send_file(io.BytesIO(data), mimetype="image/jpeg", as_attachment=False)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404


@app.route("/api/v1/sessions/<int:session_id>/me/profile/photo", methods=["POST"])
def api_update_me_profile_photo(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    f = request.files.get("photo")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "No photo uploaded."}), 400
    try:
        tg_core.change_dp(row, f.read())
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/<int:session_id>/me/profile", methods=["POST"])
def api_update_me_profile(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    bio_val = data["bio"] if "bio" in data else (data["about"] if "about" in data else None)
    uname_val = data["username"] if "username" in data else None
    try:
        profile = tg_core.update_own_profile(
            row,
            first_name=data.get("first_name"),
            last_name=data.get("last_name"),
            bio=bio_val,
            username=uname_val,
        )
        return jsonify({"ok": True, "profile": profile})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/<int:session_id>/me/username", methods=["POST"])
def api_update_me_username(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    try:
        profile = tg_core.update_own_username(row, data.get("username", ""))
        return jsonify({"ok": True, "profile": profile})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/v1/sessions/<int:session_id>/profile")
def api_profile(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    peer = request.args.get("peer") or request.args.get("username")
    fallback_username = request.args.get("username")
    if not peer:
        return jsonify({"ok": False, "error": "Provide ?peer=<id> or ?username=<username>."}), 400
    try:
        return jsonify({"ok": True, "profile": tg_core.get_profile(row, peer, fallback_username=fallback_username)})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/profile/photo")
def api_profile_photo(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    peer = request.args.get("peer") or request.args.get("username")
    if not peer:
        return jsonify({"ok": False, "error": "Provide ?peer=<id> or ?username=<username>."}), 400
    try:
        data = tg_core.download_profile_photo(row, peer)
        if not data:
            return jsonify({"ok": False, "error": "No profile photo."}), 404
        return send_file(io.BytesIO(data), mimetype="image/jpeg", as_attachment=False)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404


@app.route("/api/v1/sessions/<int:session_id>/join", methods=["POST"])
def api_join(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    raw_target = data.get("target") or data.get("link_or_username") or data.get("peer_id") or request.form.get("target") or ""
    target = str(raw_target).strip()
    if not target:
        return jsonify({"ok": False, "error": "Provide a public @username or Telegram invite link."}), 400
    try:
        return jsonify(tg_core.join_chat(row, target))
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/leave", methods=["POST"])
def api_leave(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    data = request.get_json(silent=True) or {}
    raw_target = data.get("target") or data.get("peer_id") or data.get("username") or ""
    target = str(raw_target).strip()
    if not target:
        return jsonify({"ok": False, "error": "Provide a channel or group to leave."}), 400
    try:
        return jsonify(tg_core.leave_chat(row, target))
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/resolve")
def api_resolve_peer(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    q = (request.args.get("q") or request.args.get("username") or request.args.get("peer") or "").strip()
    if not q:
        return jsonify({"ok": False, "error": "Provide ?q=<@username or link>."}), 400
    try:
        return jsonify({"ok": True, "peer": tg_core.resolve_peer(row, q)})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Could not resolve peer")}), 404


@app.route("/api/v1/sessions/<int:session_id>/2fa/change", methods=["POST"])
def api_2fa_change(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404

    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password") or None
    new_password = data.get("new_password")
    hint = data.get("hint") or ""
    if not new_password:
        return jsonify({"ok": False, "error": "Provide 'new_password'."}), 400

    try:
        tg_core.set_2fa_password(row, current_password, new_password, hint)
        return jsonify({"ok": True, "message": "2FA password updated."})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/2fa/email", methods=["POST"])
def api_2fa_email(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404

    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password")
    new_email = (data.get("email") or "").strip()
    if not current_password:
        return jsonify({"ok": False, "error": "Provide 'current_password' — Telegram requires it to change the recovery email."}), 400
    if not new_email:
        return jsonify({"ok": False, "error": "Provide 'email'."}), 400

    try:
        tg_core.set_2fa_email(row, current_password, new_email)
        return jsonify({"ok": True, "message": "Recovery email updated. Check the inbox for Telegram's confirmation code if prompted."})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/devices")
def api_devices(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        return jsonify({"ok": True, "devices": tg_core.get_devices(row)})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/devices/<int:device_hash>/logout", methods=["POST"])
def api_device_logout(session_id, device_hash):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        tg_core.logout_device(row, device_hash)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/logout_all_others", methods=["POST"])
def api_logout_all_others(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try:
        n = tg_core.logout_all_other_devices(row)
        return jsonify({"ok": True, "count": n})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/logout", methods=["POST"])
def api_session_logout(session_id):
    """Log the selected Telegram session out completely and remove its stored session."""
    u, err = api_user()
    if err:
        return err

    row = api_owned_session(u, session_id)
    if not row:
        return jsonify({"ok": False, "error": "Session not found."}), 404

    try:
        # Telegram logout: invalidate this stored login on Telegram.
        tg_core.logout_session(row)
        # Stop any live message feed before deleting the local record.
        tg_core.stop_give_message(row)
        # Remove the session record from this API user's account.
        db.delete_session(session_id)
        return jsonify({"ok": True, "message": "Session logged out and removed."})
    except Exception as e:
        return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500


@app.route("/api/v1/sessions/<int:session_id>/2fa")
def api_2fa_status(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try: return jsonify({"ok": True, **tg_core.get_2fa_status(row)})
    except Exception as e: return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500

@app.route("/api/v1/sessions/<int:session_id>/2fa/reset", methods=["POST"])
def api_2fa_reset(session_id):
    u, err = api_user()
    if err: return err
    row = api_owned_session(u, session_id)
    if not row: return jsonify({"ok": False, "error": "Session not found."}), 404
    try: return jsonify({"ok": True, "result": tg_core.reset_2fa(row)})
    except Exception as e: return jsonify({"ok": False, "error": (str(e) or e.__class__.__name__ or "Telegram request failed")}), 500

@app.route("/api/v1")
def api_root():
    return jsonify({"ok": True, "name": "Session Manager Pro API", "version": "1.0", "docs": "/api"})


@app.after_request
def _cors_headers(resp):
    if request.path.startswith("/api/v1"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    return resp


@app.route("/api/v1/<path:_any>", methods=["OPTIONS"])
def _api_preflight(_any):
    return ("", 204)


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
