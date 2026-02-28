import os
import re
import json
import random
import requests
from functools import wraps
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("APP_SECRET", "change-this-in-production")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"]   = os.getenv("FLASK_ENV") == "production"
CORS(app, supports_credentials=True)

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
SUPABASE_URL      = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
SUPABASE_KEY      = os.getenv("SUPABASE_KEY", "")  # service role key

SUPER_ADMIN_EMAIL    = os.getenv("SUPER_ADMIN_EMAIL", "admin@qcode.com").strip().lower()
SUPER_ADMIN_PASSWORD = os.getenv("SUPER_ADMIN_PASSWORD", "admin123").strip()

if not SUPABASE_URL or not SUPABASE_ANON_KEY or not SUPABASE_KEY:
    raise RuntimeError(
        "Missing required env vars: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_KEY"
    )

def get_groq():
    from groq import Groq
    return Groq(api_key=os.getenv("GROQ_API_KEY", ""))

SMS_GATEWAY_NUMBER = os.getenv("SMS_GATEWAY_NUMBER", "+2349155189936")

# Android SMS Gateway config
ANDROID_GW_URL      = os.getenv("ANDROID_GW_URL", "")
ANDROID_GW_LOGIN    = os.getenv("ANDROID_GW_LOGIN", "")
ANDROID_GW_PASSWORD = os.getenv("ANDROID_GW_PASSWORD", "")
ANDROID_GW_DEVICE   = os.getenv("ANDROID_GW_DEVICE", "")

# Fallback cloud SMS config
FALLBACK_SMS_URL   = os.getenv("FALLBACK_SMS_URL", "")
FALLBACK_SMS_KEY   = os.getenv("FALLBACK_SMS_KEY", "")
FALLBACK_KEY_FLD   = os.getenv("FALLBACK_KEY_FLD", "apikey")
FALLBACK_PHONE_FLD = os.getenv("FALLBACK_PHONE_FLD", "to")
FALLBACK_MSG_FLD   = os.getenv("FALLBACK_MSG_FLD", "message")
SMS_SENDER_ID      = os.getenv("SMS_SENDER_ID", "QCode")

# ─────────────────────────────────────────────
# HEADERS
# ─────────────────────────────────────────────
def _h_service():
    """Service role key — bypasses RLS, used for all DB reads/writes."""
    return {
        "apikey":        SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type":  "application/json",
        "Prefer":        "return=representation",
    }

def _h_anon():
    """Anon key — used only for signin."""
    return {
        "apikey":        SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type":  "application/json",
    }

# ─────────────────────────────────────────────
# SUPABASE AUTH HELPERS
# ─────────────────────────────────────────────

def admin_create_user(email, password):
    r = requests.post(
        f"{SUPABASE_URL}/auth/v1/admin/users",
        headers={
            "apikey":        SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type":  "application/json",
        },
        json={
            "email":         email,
            "password":      password,
            "email_confirm": True,
        },
        timeout=15
    )
    return r.json()

def sb_signin(email, password):
    r = requests.post(
        f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
        headers=_h_anon(),
        json={"email": email, "password": password},
        timeout=15
    )
    return r.json()

def sb_signout(token):
    try:
        requests.post(
            f"{SUPABASE_URL}/auth/v1/logout",
            headers={
                "apikey":        SUPABASE_ANON_KEY,
                "Authorization": f"Bearer {token}",
            },
            timeout=5
        )
    except Exception:
        pass

# ─────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────

def db_insert(table, data):
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/{table}",
        headers=_h_service(),
        json=data,
        timeout=15
    )
    return {"ok": r.ok, "data": r.json(), "status": r.status_code}

def db_select(table, filters=None, single=False):
    params = {"select": "*"}
    if filters:
        params.update(filters)
    h = dict(_h_service())
    if single:
        h["Accept"] = "application/vnd.pgrst.object+json"
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{table}",
        headers=h, params=params, timeout=15
    )
    if not r.ok:
        return None if single else []
    return r.json()

def db_update(table, match, data):
    params = {k: f"eq.{v}" for k, v in match.items()}
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{table}",
        headers=_h_service(),
        params=params, json=data, timeout=15
    )
    return r.ok

def db_count(table, filters=None):
    h = {**_h_service(), "Prefer": "count=exact"}
    params = {"select": "id"}
    if filters:
        params.update(filters)
    r = requests.head(
        f"{SUPABASE_URL}/rest/v1/{table}",
        headers=h, params=params, timeout=15
    )
    try:
        return int(r.headers.get("content-range", "0/0").split("/")[1])
    except Exception:
        return 0

def get_profile(user_id):
    return db_select("profiles", {"id": f"eq.{user_id}"}, single=True) or {}

# ─────────────────────────────────────────────
# PAGE ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register-user")
@app.route("/auth/register-user")
def register_user_page():
    return render_template("register-user.html")

@app.route("/register-org")
@app.route("/auth/register-org")
def register_org_page():
    return render_template("register-org.html")

@app.route("/login-user")
@app.route("/auth/login-user")
def login_user_page():
    return render_template("login-user.html")

@app.route("/login-org")
@app.route("/auth/login-org")
def login_org_page():
    return render_template("login-org.html")

@app.route("/user")
@app.route("/dashboard/user")
def user_dashboard():
    return render_template("user.html")

@app.route("/org")
@app.route("/dashboard/org")
def org_dashboard():
    return render_template("org.html")

@app.route("/guest")
@app.route("/dashboard/guest")
def guest_dashboard():
    return render_template("guest.html")

@app.route("/super-admin")
@app.route("/admin")
def super_admin_page():
    return render_template("super_admin.html")

# ─────────────────────────────────────────────
# SESSION CHECK
# ─────────────────────────────────────────────

@app.route("/api/auth/me", methods=["GET"])
def api_me():
    if not session.get("user_id"):
        return jsonify({"logged_in": False}), 200
    return jsonify({
        "logged_in":  True,
        "user_id":    session["user_id"],
        "role":       session.get("role"),
        "email":      session.get("email"),
        "full_name":  session.get("full_name"),
        "org_name":   session.get("org_name"),
    }), 200

# ─────────────────────────────────────────────
# REGISTER USER
# ─────────────────────────────────────────────

@app.route("/api/auth/register-user", methods=["POST"])
@app.route("/api/register-user",      methods=["POST"])
def register_user():
    data      = request.get_json() or {}
    full_name = (data.get("full_name") or "").strip()
    email     = (data.get("email")     or "").strip().lower()
    password  = (data.get("password")  or "")
    phone     = (data.get("phone")     or "").strip()

    if not full_name or not email or not password:
        return jsonify({"error": "Name, email and password are required."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    result = admin_create_user(email, password)
    uid    = result.get("id")

    if not uid:
        msg = (result.get("message")
               or result.get("msg")
               or result.get("error_description")
               or str(result))
        if "already been registered" in msg.lower() or "already exists" in msg.lower():
            return jsonify({"error": "An account with this email already exists. Please log in."}), 400
        return jsonify({"error": f"Registration failed: {msg}"}), 400

    ins = db_insert("profiles", {
        "id":              uid,
        "role":            "user",
        "full_name":       full_name,
        "email":           email,
        "phone":           phone or None,
        "approval_status": "approved",
        "is_online":       False,
    })
    if not ins["ok"]:
        return jsonify({"error": "Account created but profile save failed. Contact support."}), 500

    return jsonify({
        "success": True,
        "message": "Account created! You can now log in."
    }), 201

# ─────────────────────────────────────────────
# AI FAQ
# ─────────────────────────────────────────────

@app.route("/api/ai/faq", methods=["POST"])
def ai_faq():
    data          = request.get_json()
    messages      = data.get("messages", [])
    system_prompt = data.get("system", "You are QCode Assistant, a helpful queue management support AI.")

    if not messages:
        return jsonify({"error": "No messages"}), 400

    try:
        client   = get_groq()
        response = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[{"role": "system", "content": system_prompt}, *messages],
            max_tokens=600,
            temperature=0.7,
        )
        return jsonify({"response": response.choices[0].message.content})
    except Exception as e:
        print(f"Groq error: {e}")
        return jsonify({"error": "AI service unavailable. Please try again."}), 500

# ─────────────────────────────────────────────
# REGISTER ORG
# ─────────────────────────────────────────────

@app.route("/api/auth/register-org", methods=["POST"])
@app.route("/api/register-org",      methods=["POST"])
def register_org():
    ct = (request.content_type or "").lower()
    if "multipart" in ct or "form" in ct:
        org_name = (request.form.get("org_name")    or "").strip()
        email    = (request.form.get("email")        or "").strip().lower()
        password = (request.form.get("password")     or "")
        phone    = (request.form.get("org_phone")    or "").strip()
        address  = (request.form.get("org_address")  or "").strip()
        org_type = (request.form.get("org_type")     or "").strip()
    else:
        d        = request.get_json() or {}
        org_name = (d.get("org_name")    or "").strip()
        email    = (d.get("email")       or "").strip().lower()
        password = (d.get("password")    or "")
        phone    = (d.get("org_phone")   or "").strip()
        address  = (d.get("org_address") or "").strip()
        org_type = (d.get("org_type")    or "").strip()

    if not org_name or not email or not password:
        return jsonify({"error": "Organization name, email and password are required."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    result = admin_create_user(email, password)
    uid    = result.get("id")

    if not uid:
        msg = (result.get("message")
               or result.get("msg")
               or result.get("error_description")
               or str(result))
        if "already been registered" in msg.lower() or "already exists" in msg.lower():
            return jsonify({"error": "An account with this email already exists."}), 400
        return jsonify({"error": f"Registration failed: {msg}"}), 400

    address_full = " | ".join(filter(None, [org_type, address])) or None

    ins = db_insert("profiles", {
        "id":              uid,
        "role":            "organization",
        "org_name":        org_name,
        "full_name":       org_name,
        "email":           email,
        "phone":           phone or None,
        "company_address": address_full,
        "approval_status": "pending",
        "is_online":       False,
    })
    if not ins["ok"]:
        return jsonify({"error": "Account created but profile save failed."}), 500

    return jsonify({
        "success":  True,
        "org_name": org_name,
        "message":  (
            f"Registration submitted! '{org_name}' is pending admin approval. "
            "You will be contacted once your account is reviewed."
        )
    }), 201

# ─────────────────────────────────────────────
# LOGIN USER
# ─────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
@app.route("/api/login-user", methods=["POST"])
def login_user():
    data     = request.get_json() or {}
    email    = (data.get("email")    or "").strip().lower()
    password = (data.get("password") or "")

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    signin = sb_signin(email, password)
    token  = signin.get("access_token")

    if not token:
        raw = (signin.get("error_description")
               or signin.get("msg")
               or signin.get("message")
               or signin.get("error")
               or "Login failed.")
        if "invalid" in raw.lower() or "credentials" in raw.lower():
            raw = "Incorrect email or password."
        elif "not confirmed" in raw.lower():
            raw = "Account not confirmed. Please contact support."
        return jsonify({"error": raw}), 401

    uid = (signin.get("user") or {}).get("id")
    if not uid:
        return jsonify({"error": "Could not retrieve user info."}), 401

    profile = get_profile(uid)
    if not profile:
        return jsonify({"error": "Profile not found. Please contact support."}), 404

    role   = profile.get("role", "user")
    status = profile.get("approval_status", "approved")

    if status == "suspended":
        sb_signout(token)
        return jsonify({"error": "This account has been suspended. Contact support."}), 403

    session.permanent = True
    session["user_id"]   = uid
    session["role"]      = role
    session["email"]     = profile.get("email", "")
    session["full_name"] = profile.get("full_name", "")
    session["org_name"]  = profile.get("org_name", "")

    db_update("profiles", {"id": uid}, {"is_online": True})

    redirect_map = {
        "user":         "/user",
        "organization": "/org",
        "super_admin":  "/super-admin",
    }
    return jsonify({
        "success":  True,
        "role":     role,
        "redirect": redirect_map.get(role, "/user"),
    }), 200

# ─────────────────────────────────────────────
# LOGIN ORG
# ─────────────────────────────────────────────

@app.route("/api/auth/login-org", methods=["POST"])
@app.route("/api/login-org",      methods=["POST"])
def login_org():
    data     = request.get_json() or {}
    email    = (data.get("email")    or "").strip().lower()
    password = (data.get("password") or "")

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    # Super Admin: env-var check, zero Supabase calls
    if email == SUPER_ADMIN_EMAIL and password == SUPER_ADMIN_PASSWORD:
        session.permanent = True
        session["user_id"]   = "super-admin"
        session["role"]      = "super_admin"
        session["email"]     = SUPER_ADMIN_EMAIL
        session["full_name"] = "Super Admin"
        session["org_name"]  = "QCode Admin"
        return jsonify({
            "success":  True,
            "role":     "super_admin",
            "redirect": "/super-admin",
        }), 200

    signin = sb_signin(email, password)
    token  = signin.get("access_token")

    if not token:
        raw = (signin.get("error_description")
               or signin.get("msg")
               or signin.get("message")
               or signin.get("error")
               or "Login failed.")
        if "invalid" in raw.lower() or "credentials" in raw.lower():
            raw = "Incorrect email or password."
        elif "not confirmed" in raw.lower():
            raw = "Account not confirmed. Please contact support."
        return jsonify({"error": raw}), 401

    uid = (signin.get("user") or {}).get("id")
    if not uid:
        return jsonify({"error": "Could not retrieve user info."}), 401

    profile = get_profile(uid)
    if not profile:
        return jsonify({"error": "Profile not found."}), 404

    role   = profile.get("role")
    status = profile.get("approval_status", "pending")

    if role != "organization":
        sb_signout(token)
        return jsonify({"error": "This page is for organizations only. Use the user login instead."}), 403

    if status == "pending":
        sb_signout(token)
        return jsonify({
            "error": "Your organization is pending admin approval. You will be notified once approved."
        }), 403

    if status == "suspended":
        sb_signout(token)
        return jsonify({"error": "This account has been suspended. Contact support."}), 403

    session.permanent = True
    session["user_id"]   = uid
    session["role"]      = "organization"
    session["email"]     = profile.get("email", "")
    session["org_name"]  = profile.get("org_name", "")
    session["full_name"] = profile.get("org_name", "")

    db_update("profiles", {"id": uid}, {"is_online": True})

    return jsonify({
        "success":  True,
        "role":     "organization",
        "redirect": "/org",
    }), 200

# ─────────────────────────────────────────────
# LOGOUT
# ─────────────────────────────────────────────

@app.route("/api/auth/logout", methods=["POST"])
@app.route("/api/logout",      methods=["POST"])
def logout():
    uid = session.get("user_id")
    if uid and uid != "super-admin":
        db_update("profiles", {"id": uid}, {"is_online": False})
    session.clear()
    return jsonify({"success": True, "redirect": "/"}), 200

# ─────────────────────────────────────────────
# USER DASHBOARD API
# ─────────────────────────────────────────────

@app.route("/api/user/profile", methods=["GET"])
def api_user_profile():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Not logged in"}), 401
    profile = get_profile(uid)
    profile["total_queues"] = db_count("queue_entries", {"user_id": f"eq.{uid}"})
    return jsonify(profile), 200

@app.route("/api/user/profile", methods=["POST"])
def api_user_profile_update():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Not logged in"}), 401
    d   = request.get_json() or {}
    upd = {}
    if "full_name"      in d: upd["full_name"]     = d["full_name"] or None
    if "phone"          in d: upd["phone"]          = d["phone"] or None
    if "preferred_lang" in d: upd["preferred_lang"] = d["preferred_lang"]
    if upd:
        db_update("profiles", {"id": uid}, upd)
    return jsonify({"success": True}), 200

@app.route("/api/user/find-service", methods=["GET"])
def api_find_service():
    code = (request.args.get("code") or "").strip().upper()
    if not code:
        return jsonify({"error": "Service code required"}), 400
    svcs = db_select("services", {"service_code": f"eq.{code}"})
    if not svcs:
        return jsonify({"error": f"No service found with code '{code}'."}), 404
    svc = svcs[0]
    org = db_select("profiles", {"id": f"eq.{svc['org_id']}"}, single=True) or {}
    if org.get("approval_status") != "approved":
        return jsonify({"error": "This organization is not currently active."}), 403
    if svc["status"] == "closed":
        return jsonify({"error": f"'{svc['name']}' queue is closed."}), 400
    if svc["status"] == "paused":
        return jsonify({"error": f"'{svc['name']}' queue is paused. Try again soon."}), 400
    waiting              = db_count("queue_entries", {"service_id": f"eq.{svc['id']}", "status": "eq.waiting"})
    svc["waiting_count"] = waiting
    svc["org_name"]      = org.get("org_name", "")
    svc["eta_minutes"]   = (waiting + 1) * (svc.get("time_interval") or 5)
    return jsonify(svc), 200

@app.route("/api/user/join-queue", methods=["POST"])
def api_join_queue():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Not logged in"}), 401
    d      = request.get_json() or {}
    svc_id = d.get("service_id")
    if not svc_id:
        return jsonify({"error": "service_id required"}), 400
    svcs = db_select("services", {"id": f"eq.{svc_id}"})
    if not svcs:
        return jsonify({"error": "Service not found"}), 404
    svc = svcs[0]
    if svc["status"] != "open":
        return jsonify({"error": f"Queue is {svc['status']}."}), 400
    already = db_select("queue_entries", {
        "service_id": f"eq.{svc_id}",
        "user_id":    f"eq.{uid}",
        "status":     "in.(waiting,called,serving)",
    })
    if already:
        return jsonify({"error": "You are already in this queue.", "entry": already[0]}), 409
    n     = (svc.get("ticket_counter") or 0) + 1
    label = f"{svc.get('ticket_prefix', 'Q')}{str(n).zfill(3)}"
    db_update("services", {"id": svc_id}, {"ticket_counter": n})
    pos   = db_count("queue_entries", {"service_id": f"eq.{svc_id}", "status": "eq.waiting"}) + 1
    eta_t = (datetime.now(timezone.utc) + timedelta(minutes=pos * (svc.get("time_interval") or 5))).isoformat()
    res   = db_insert("queue_entries", {
        "service_id":       svc_id,
        "user_id":          uid,
        "ticket_label":     label,
        "ticket_number":    n,
        "status":           "waiting",
        "estimated_time":   eta_t,
        "join_method":      "web",
        "custom_form_data": json.dumps(d.get("custom_form_data") or {}),
    })
    if not res["ok"]:
        return jsonify({"error": "Failed to join queue."}), 500
    entry = res["data"][0] if isinstance(res["data"], list) else res["data"]
    entry["position"] = pos
    entry["svc_name"] = svc["name"]
    entry["org_name"] = (db_select("profiles", {"id": f"eq.{svc['org_id']}"}, single=True) or {}).get("org_name", "")
    return jsonify({"success": True, "entry": entry}), 201

@app.route("/api/user/queue-status/<entry_id>", methods=["GET"])
def api_queue_status(entry_id):
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Not logged in"}), 401
    rows = db_select("queue_entries", {"id": f"eq.{entry_id}"})
    if not rows or rows[0].get("user_id") != uid:
        return jsonify({"error": "Not found"}), 404
    entry = rows[0]
    ahead = db_count("queue_entries", {
        "service_id":    f"eq.{entry['service_id']}",
        "status":        "eq.waiting",
        "ticket_number": f"lt.{entry['ticket_number']}",
    })
    total = db_count("queue_entries", {"service_id": f"eq.{entry['service_id']}", "status": "eq.waiting"})
    svcs  = db_select("services", {"id": f"eq.{entry['service_id']}"})
    svc   = svcs[0] if svcs else {}
    entry["position"]    = ahead + 1
    entry["ahead"]       = ahead
    entry["total"]       = total
    entry["eta_minutes"] = max(0, (ahead + 1) * (svc.get("time_interval") or 5))
    entry["svc_name"]    = svc.get("name", "")
    entry["svc_status"]  = svc.get("status", "")
    return jsonify(entry), 200

@app.route("/api/user/leave-queue/<entry_id>", methods=["POST"])
def api_leave_queue(entry_id):
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Not logged in"}), 401
    rows = db_select("queue_entries", {"id": f"eq.{entry_id}"})
    if not rows or rows[0].get("user_id") != uid:
        return jsonify({"error": "Not found"}), 404
    db_update("queue_entries", {"id": entry_id}, {
        "status":       "cancelled",
        "completed_at": datetime.now(timezone.utc).isoformat(),
    })
    return jsonify({"success": True}), 200

@app.route("/api/user/history", methods=["GET"])
def api_user_history():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Not logged in"}), 401
    rows      = db_select("queue_entries", {"user_id": f"eq.{uid}", "order": "joined_at.desc", "limit": "50"})
    svc_cache = {}
    for row in rows:
        sid = row.get("service_id")
        if sid and sid not in svc_cache:
            svcs = db_select("services", {"id": f"eq.{sid}"})
            if svcs:
                org = db_select("profiles", {"id": f"eq.{svcs[0]['org_id']}"}, single=True) or {}
                svc_cache[sid] = {"name": svcs[0]["name"], "org_name": org.get("org_name", "")}
        if sid in svc_cache:
            row["svc_name"] = svc_cache[sid]["name"]
            row["org_name"] = svc_cache[sid]["org_name"]
    return jsonify(rows), 200

@app.route("/api/user/open-services", methods=["GET"])
def api_open_services():
    svcs   = db_select("services", {"status": "eq.open", "deleted_at": "is.null", "order": "created_at.desc", "limit": "30"})
    result = []
    for svc in svcs:
        org = db_select("profiles", {"id": f"eq.{svc['org_id']}"}, single=True) or {}
        if org.get("approval_status") != "approved":
            continue
        svc["org_name"]      = org.get("org_name", "")
        svc["waiting_count"] = db_count("queue_entries", {"service_id": f"eq.{svc['id']}", "status": "eq.waiting"})
        result.append(svc)
    return jsonify(result), 200

# ─────────────────────────────────────────────
# ORG DASHBOARD API
# ─────────────────────────────────────────────

@app.route("/api/org/profile", methods=["GET"])
def api_org_profile():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify(get_profile(uid)), 200

@app.route("/api/org/profile", methods=["POST"])
def api_org_profile_update():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    d = request.get_json() or {}
    if "phone" in d:
        db_update("profiles", {"id": uid}, {"phone": d["phone"] or None})
    return jsonify({"success": True}), 200

@app.route("/api/org/services", methods=["GET"])
def api_org_services():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    svcs = db_select("services", {"org_id": f"eq.{uid}", "deleted_at": "is.null", "order": "created_at.desc"})
    for svc in svcs:
        for s in ("waiting", "called", "serving", "completed", "no_show"):
            svc[f"count_{s}"] = db_count("queue_entries", {"service_id": f"eq.{svc['id']}", "status": f"eq.{s}"})
    return jsonify(svcs), 200

@app.route("/api/org/services", methods=["POST"])
def api_org_create_service():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    d    = request.get_json() or {}
    name = (d.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Service name is required"}), 400
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    for _ in range(20):
        code = "".join(random.choices(chars, k=6))
        if not db_select("services", {"service_code": f"eq.{code}"}):
            break
    res = db_insert("services", {
        "org_id":         uid,
        "name":           name,
        "staff_name":     d.get("staff_name") or None,
        "description":    d.get("description") or None,
        "service_code":   code,
        "ticket_prefix":  (d.get("ticket_prefix") or "A").upper()[:3],
        "ticket_counter": 0,
        "time_interval":  int(d.get("time_interval") or 5),
        "max_users":      int(d.get("max_users")) if d.get("max_users") else None,
        "status":         "open",
        "user_info_form": json.dumps(d.get("user_info_form") or []),
    })
    if not res["ok"]:
        return jsonify({"error": "Failed to create service"}), 500
    svc = res["data"][0] if isinstance(res["data"], list) else res["data"]
    return jsonify({"success": True, "service": svc}), 201

@app.route("/api/org/services/<svc_id>/status", methods=["POST"])
def api_org_service_status(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    status = (request.get_json() or {}).get("status")
    if status not in ("open", "paused", "closed"):
        return jsonify({"error": "Invalid status"}), 400
    db_update("services", {"id": svc_id}, {"status": status})
    return jsonify({"success": True}), 200

@app.route("/api/org/services/<svc_id>/delete", methods=["POST"])
def api_org_delete_service(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    db_update("services", {"id": svc_id}, {
        "deleted_at": datetime.now(timezone.utc).isoformat(),
        "status":     "closed",
    })
    return jsonify({"success": True}), 200

@app.route("/api/org/services/<svc_id>/restore", methods=["POST"])
def api_org_restore_service(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    db_update("services", {"id": svc_id}, {"deleted_at": None})
    return jsonify({"success": True}), 200

@app.route("/api/org/services/deleted", methods=["GET"])
def api_org_deleted_services():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    svcs = db_select("services", {"org_id": f"eq.{uid}", "deleted_at": "not.is.null", "order": "deleted_at.desc"})
    return jsonify(svcs), 200

@app.route("/api/org/queue/<svc_id>", methods=["GET"])
def api_org_queue(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    entries = db_select("queue_entries", {
        "service_id": f"eq.{svc_id}",
        "status":     "in.(waiting,called,serving)",
        "order":      "ticket_number.asc",
    })
    for e in entries:
        if e.get("user_id"):
            p = db_select("profiles", {"id": f"eq.{e['user_id']}"}, single=True) or {}
            e["user_name"]   = p.get("full_name") or p.get("email") or "User"
            e["user_online"] = p.get("is_online", False)
        else:
            e["user_name"]   = e.get("guest_name") or "Guest"
            e["user_online"] = False
    return jsonify(entries), 200

@app.route("/api/org/queue/call-next/<svc_id>", methods=["POST"])
def api_org_call_next(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    waiting = db_select("queue_entries", {
        "service_id": f"eq.{svc_id}",
        "status":     "eq.waiting",
        "order":      "ticket_number.asc",
        "limit":      "1",
    })
    if not waiting:
        return jsonify({"error": "No one waiting"}), 404
    entry = waiting[0]
    db_update("queue_entries", {"id": entry["id"]}, {
        "status":    "called",
        "called_at": datetime.now(timezone.utc).isoformat(),
    })
    entry["status"] = "called"
    return jsonify({"success": True, "entry": entry}), 200

@app.route("/api/org/queue/entry/<entry_id>", methods=["POST"])
def api_org_update_entry(entry_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    status = (request.get_json() or {}).get("status")
    if status not in ("serving", "completed", "no_show", "waiting", "called", "cancelled"):
        return jsonify({"error": "Invalid status"}), 400
    upd = {"status": status}
    if status in ("completed", "no_show", "cancelled"):
        upd["completed_at"] = datetime.now(timezone.utc).isoformat()
    db_update("queue_entries", {"id": entry_id}, upd)
    return jsonify({"success": True}), 200

@app.route("/api/org/report/<svc_id>", methods=["GET"])
def api_org_report(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    entries = db_select("queue_entries", {
        "service_id": f"eq.{svc_id}",
        "status":     "in.(completed,no_show,cancelled)",
        "order":      "ticket_number.desc",
        "limit":      "200",
    })
    return jsonify(entries), 200

# ─────────────────────────────────────────────
# ADMIN API
# ─────────────────────────────────────────────

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "super_admin":
            return jsonify({"error": "Unauthorized"}), 403
        return f(*args, **kwargs)
    return wrapper

@app.route("/api/admin/stats")
@require_admin
def api_admin_stats():
    return jsonify({
        "total_orgs":    db_count("profiles", {"role": "eq.organization"}),
        "approved_orgs": db_count("profiles", {"role": "eq.organization", "approval_status": "eq.approved"}),
        "pending_orgs":  db_count("profiles", {"role": "eq.organization", "approval_status": "eq.pending"}),
        "total_users":   db_count("profiles", {"role": "eq.user"}),
        "total_served":  db_count("queue_entries", {"status": "eq.completed"}),
    }), 200

@app.route("/api/admin/orgs")
@require_admin
def api_admin_orgs():
    return jsonify(db_select("profiles", {"role": "eq.organization", "order": "created_at.desc"})), 200

@app.route("/api/admin/users")
@require_admin
def api_admin_users():
    return jsonify(db_select("profiles", {"role": "eq.user", "order": "created_at.desc"})), 200

@app.route("/api/admin/approve-org", methods=["POST"])
@require_admin
def api_approve_org():
    org_id = (request.get_json() or {}).get("org_id")
    if not org_id:
        return jsonify({"error": "org_id required"}), 400
    db_update("profiles", {"id": org_id}, {"approval_status": "approved"})
    return jsonify({"success": True}), 200

@app.route("/api/admin/reject-org", methods=["POST"])
@require_admin
def api_reject_org():
    d      = request.get_json() or {}
    org_id = d.get("org_id")
    reason = (d.get("reason") or "").strip()
    if not org_id or not reason:
        return jsonify({"error": "org_id and reason required"}), 400
    db_update("profiles", {"id": org_id}, {
        "approval_status":  "suspended",
        "rejection_reason": reason,
    })
    return jsonify({"success": True}), 200

@app.route("/api/admin/suspend-org", methods=["POST"])
@require_admin
def api_suspend_org():
    org_id = (request.get_json() or {}).get("org_id")
    if not org_id:
        return jsonify({"error": "org_id required"}), 400
    db_update("profiles", {"id": org_id}, {"approval_status": "suspended"})
    return jsonify({"success": True}), 200

@app.route("/api/admin/analytics", methods=["GET"])
@require_admin
def admin_analytics():
    return jsonify({
        "total_orgs":    db_count("profiles", {"role": "eq.organization"}),
        "approved_orgs": db_count("profiles", {"role": "eq.organization", "approval_status": "eq.approved"}),
        "pending_orgs":  db_count("profiles", {"role": "eq.organization", "approval_status": "eq.pending"}),
        "total_users":   db_count("profiles", {"role": "eq.user"}),
    }), 200

@app.route("/api/admin/reinstate-org", methods=["POST"])
@require_admin
def api_reinstate_org():
    org_id = (request.get_json() or {}).get("org_id")
    if not org_id:
        return jsonify({"error": "org_id required"}), 400
    db_update("profiles", {"id": org_id}, {"approval_status": "approved", "rejection_reason": None})
    db_insert("admin_logs", {
        "admin_id":    session.get("user_id"),
        "action":      "REINSTATE_ORG",
        "target_id":   org_id,
        "target_type": "organization",
        "details":     json.dumps({"action": "reinstated"}),
    })
    return jsonify({"success": True}), 200

@app.route("/api/admin/ban-user", methods=["POST"])
@require_admin
def api_ban_user():
    user_id = (request.get_json() or {}).get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    db_update("profiles", {"id": user_id}, {"approval_status": "suspended"})
    db_insert("admin_logs", {
        "admin_id":    session.get("user_id"),
        "action":      "BAN_USER",
        "target_id":   user_id,
        "target_type": "user",
        "details":     json.dumps({"action": "banned"}),
    })
    return jsonify({"success": True}), 200

@app.route("/api/admin/all-queues", methods=["GET"])
@require_admin
def api_admin_all_queues():
    org_id  = request.args.get("org_id", "")
    filters = {"order": "joined_at.desc", "limit": "200"}
    if org_id:
        svcs    = db_select("services", {"org_id": f"eq.{org_id}"})
        svc_ids = ",".join(s["id"] for s in svcs)
        if svc_ids:
            filters["service_id"] = f"in.({svc_ids})"
        else:
            return jsonify([]), 200
    entries    = db_select("queue_entries", filters)
    svc_cache  = {}
    user_cache = {}
    for e in entries:
        sid = e.get("service_id")
        if sid and sid not in svc_cache:
            svcs = db_select("services", {"id": f"eq.{sid}"})
            if svcs:
                s   = svcs[0]
                org = db_select("profiles", {"id": f"eq.{s['org_id']}"}, single=True) or {}
                svc_cache[sid] = {
                    "svc_name": s.get("name", ""),
                    "svc_code": s.get("service_code", ""),
                    "org_name": org.get("org_name", ""),
                }
        if sid in svc_cache:
            e.update(svc_cache[sid])
        uid = e.get("user_id")
        if uid and uid not in user_cache:
            p              = db_select("profiles", {"id": f"eq.{uid}"}, single=True) or {}
            user_cache[uid] = p.get("full_name") or p.get("email") or "User"
        if uid:
            e["user_name"] = user_cache.get(uid, "User")
        else:
            e["user_name"] = e.get("guest_name") or "Guest"
    return jsonify(entries), 200

@app.route("/api/admin/all-services", methods=["GET"])
@require_admin
def api_admin_all_services():
    svcs = db_select("services", {"deleted_at": "is.null", "order": "created_at.desc"})
    for s in svcs:
        org          = db_select("profiles", {"id": f"eq.{s['org_id']}"}, single=True) or {}
        s["org_name"]  = org.get("org_name", "")
        s["total"]     = db_count("queue_entries", {"service_id": f"eq.{s['id']}"})
        s["waiting"]   = db_count("queue_entries", {"service_id": f"eq.{s['id']}", "status": "eq.waiting"})
        s["completed"] = db_count("queue_entries", {"service_id": f"eq.{s['id']}", "status": "eq.completed"})
    return jsonify(svcs), 200

@app.route("/api/admin/sms-joins", methods=["GET"])
@require_admin
def api_admin_sms_joins():
    rows = db_select("sms_joins", {"order": "created_at.desc", "limit": "100"})
    for r in rows:
        eid = r.get("queue_entry_id")
        if eid:
            entries = db_select("queue_entries", {"id": f"eq.{eid}"})
            if entries:
                r["ticket_label"] = entries[0].get("ticket_label", "—")
                r["entry_status"] = entries[0].get("status", "—")
    return jsonify(rows), 200

@app.route("/api/admin/logs", methods=["GET"])
@require_admin
def api_admin_logs():
    return jsonify(db_select("admin_logs", {"order": "created_at.desc", "limit": "100"})), 200

@app.route("/api/admin/log-action", methods=["POST"])
@require_admin
def api_admin_log_action():
    d = request.get_json() or {}
    db_insert("admin_logs", {
        "admin_id":    session.get("user_id"),
        "action":      d.get("action", ""),
        "target_id":   d.get("target_id", ""),
        "target_type": d.get("target_type", ""),
        "details":     json.dumps(d.get("details") or {}),
    })
    return jsonify({"success": True}), 200

# ─────────────────────────────────────────────
# SMS WEBHOOK — Android gateway POSTs here
# ─────────────────────────────────────────────

@app.route("/api/sms/receive", methods=["POST"])
def receive_sms():
    """
    The Android SMS Gateway app forwards every received SMS here.

    sms-gateway.me sends JSON like:
    {
      "deviceId":    "...",
      "message":     "QC-ABC123 John",
      "phoneNumber": "+2348012345678",
      "receivedAt":  "2025-01-01T12:00:00Z"
    }

    Other Android gateway apps may use different field names —
    all common variations are handled below.
    """
    if request.is_json:
        payload = request.get_json() or {}
    else:
        payload = request.form.to_dict()

    print(f"[SMS In] {payload}")

    from_phone = (
        payload.get("phoneNumber") or
        payload.get("from")        or
        payload.get("From")        or
        payload.get("sender")      or
        payload.get("msisdn")      or
        payload.get("mobile")      or
        payload.get("phone")       or
        "Unknown"
    )

    message_body = (
        payload.get("message")  or
        payload.get("text")     or
        payload.get("Text")     or
        payload.get("Body")     or
        payload.get("body")     or
        payload.get("sms")      or
        ""
    ).strip()

    if not message_body:
        return "", 200

    # Parse service code: QC-ABC123 | QC ABC123 | QCABC123 | ABC123
    code_match = re.search(r'\b(QC[-\s]?[A-Z0-9]{6})\b', message_body.upper())

    if not code_match:
        bare = re.search(r'\b([A-Z0-9]{6})\b', message_body.upper())
        if bare:
            service_code = "QC-" + bare.group(1)
            name_part    = re.sub(r'\b' + bare.group(1) + r'\b', '', message_body, flags=re.IGNORECASE).strip()
        else:
            _log_sms(from_phone, message_body, None, None, "invalid_code")
            send_sms(from_phone, "Invalid code. Text your QCode service code e.g. QC-ABC123 to join a queue.")
            return "", 200
    else:
        raw          = code_match.group(1).replace(" ", "-")
        service_code = raw if raw.startswith("QC-") else "QC-" + raw[-6:]
        name_part    = re.sub(r'\b' + re.escape(code_match.group(1)) + r'\b', '', message_body, flags=re.IGNORECASE).strip()

    guest_name = name_part.title() if name_part else f"SMS User ({from_phone[-4:]})"

    try:
        svcs = db_select("services", {"service_code": f"eq.{service_code}", "status": "eq.open"})
        if not svcs:
            _log_sms(from_phone, message_body, service_code, None, "invalid_code")
            send_sms(from_phone, f"Code {service_code} not found or inactive. Please check and try again.")
            return "", 200

        service  = svcs[0]
        svc_id   = service["id"]
        max_u    = service.get("max_users") or 9999
        current  = db_count("queue_entries", {"service_id": f"eq.{svc_id}", "status": "in.(waiting,called,serving)"})

        if current >= max_u:
            _log_sms(from_phone, message_body, service_code, None, "failed")
            send_sms(from_phone, f"Sorry, {service['name']} queue is full. Try again later.")
            return "", 200

        n        = (service.get("ticket_counter") or 0) + 1
        label    = f"{service.get('ticket_prefix', 'Q')}{str(n).zfill(3)}"
        db_update("services", {"id": svc_id}, {"ticket_counter": n})

        pos      = current + 1
        wait_min = pos * (service.get("time_interval") or 5)
        eta      = (datetime.now(timezone.utc) + timedelta(minutes=wait_min)).isoformat()

        res = db_insert("queue_entries", {
            "service_id":     svc_id,
            "user_id":        None,
            "guest_name":     guest_name,
            "guest_phone":    from_phone,
            "ticket_label":   label,
            "ticket_number":  n,
            "status":         "waiting",
            "estimated_time": eta,
            "join_method":    "sms",
        })

        entry_id = res["data"][0]["id"] if res.get("ok") and res["data"] else None
        _log_sms(from_phone, message_body, service_code, entry_id, "processed")

        org = db_select("profiles", {"id": f"eq.{service['org_id']}"}, single=True) or {}
        reply = (
            f"QCode Confirmed!\n"
            f"Service: {service['name']} @ {org.get('org_name', 'the organization')}\n"
            f"Your ticket: {label}\n"
            f"Position: #{pos}\n"
            f"Est. time: {_format_time(eta)}\n"
            f"Wait: ~{wait_min} mins. Stay nearby."
        )
        send_sms(from_phone, reply)
        return "", 200

    except Exception as e:
        print(f"[SMS Error] {e}")
        _log_sms(from_phone, message_body, service_code, None, "failed")
        send_sms(from_phone, "Something went wrong. Please try again.")
        return "", 200


# ─────────────────────────────────────────────
# SEND SMS via Android Gateway
# ─────────────────────────────────────────────

def send_sms(to_phone, message):
    """
    Tells the Android phone to send an SMS.

    sms-gateway.me API:
        POST http://<phone-ip>:8080/message
        { "phoneNumbers": ["+234..."], "message": "Hello" }
    with Basic Auth (login:password).

    Falls back to a cloud SMS API if ANDROID_GW_URL is not set.
    If neither is configured, prints to console (good for dev testing).
    """
    if ANDROID_GW_URL:
        try:
            url  = ANDROID_GW_URL.rstrip("/") + "/message"
            body = {"phoneNumbers": [to_phone], "message": message}
            if ANDROID_GW_DEVICE:
                body["simNumber"] = ANDROID_GW_DEVICE
            auth = None
            if ANDROID_GW_LOGIN and ANDROID_GW_PASSWORD:
                auth = (ANDROID_GW_LOGIN, ANDROID_GW_PASSWORD)
            resp = requests.post(url, json=body, auth=auth, timeout=10)
            print(f"[SMS Sent via Android] To: {to_phone} | {resp.status_code} | {resp.text[:80]}")
            return
        except Exception as e:
            print(f"[Android GW Error] {e} — trying fallback...")

    if FALLBACK_SMS_URL:
        try:
            payload = {
                FALLBACK_KEY_FLD:   FALLBACK_SMS_KEY,
                FALLBACK_PHONE_FLD: to_phone,
                FALLBACK_MSG_FLD:   message,
                "sender":           SMS_SENDER_ID,
            }
            resp = requests.post(FALLBACK_SMS_URL, data=payload, timeout=10)
            print(f"[SMS Sent via Fallback] To: {to_phone} | {resp.status_code}")
            return
        except Exception as e:
            print(f"[Fallback SMS Error] {e}")

    print(f"\n[SMS Reply — no gateway configured]\nTo: {to_phone}\n{message}\n")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _log_sms(from_phone, message_body, service_code, entry_id, status):
    try:
        db_insert("sms_joins", {
            "from_phone":     from_phone,
            "message_body":   message_body,
            "service_code":   service_code,
            "queue_entry_id": entry_id,
            "status":         status,
            "created_at":     datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        print(f"[Log Error] {e}")

def _format_time(iso_string):
    try:
        dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
        return dt.strftime("%I:%M %p")
    except Exception:
        return iso_string

@app.route("/api/notify/org", methods=["POST"])
def notify_org():
    data = request.get_json()
    print(f"[Notify] Org {data.get('org_id')} → {data.get('status')}")
    return jsonify({"sent": True})


@app.route("/api/guest/join", methods=["POST"])
def api_guest_join():
    d          = request.get_json() or {}
    svc_id     = d.get("service_id")
    guest_name = (d.get("guest_name") or "").strip()

    if not svc_id:
        return jsonify({"error": "service_id required"}), 400
    if not guest_name:
        return jsonify({"error": "Guest name required"}), 400

    svcs = db_select("services", {"id": f"eq.{svc_id}"})
    if not svcs:
        return jsonify({"error": "Service not found"}), 404
    svc = svcs[0]
    if svc["status"] != "open":
        return jsonify({"error": f"Queue is {svc['status']}."}), 400

    n     = (svc.get("ticket_counter") or 0) + 1
    label = f"{svc.get('ticket_prefix', 'Q')}{str(n).zfill(3)}"
    db_update("services", {"id": svc_id}, {"ticket_counter": n})

    pos   = db_count("queue_entries", {"service_id": f"eq.{svc_id}", "status": "eq.waiting"}) + 1
    eta_t = (datetime.now(timezone.utc) + timedelta(minutes=pos * (svc.get("time_interval") or 5))).isoformat()

    res = db_insert("queue_entries", {
        "service_id":     svc_id,
        "user_id":        None,
        "guest_name":     guest_name,
        "ticket_label":   label,
        "ticket_number":  n,
        "status":         "waiting",
        "estimated_time": eta_t,
        "join_method":    "web",
    })
    if not res["ok"]:
        return jsonify({"error": "Failed to join queue."}), 500

    entry = res["data"][0] if isinstance(res["data"], list) else res["data"]
    entry["position"] = pos
    entry["svc_name"] = svc["name"]
    return jsonify({"success": True, "entry": entry}), 201


# ─────────────────────────────────────────────
# PUBLIC STATS — called from index.html stats bar
# No auth required — returns approved orgs + total served
# ─────────────────────────────────────────────

@app.route("/api/public/stats", methods=["GET"])
def api_public_stats():
    return jsonify({
        "approved_orgs":   db_count("profiles",     {"role": "eq.organization", "approval_status": "eq.approved"}),
        "total_served":    db_count("queue_entries", {"status": "eq.completed"}),
        "active_services": db_count("services",     {"status": "eq.open", "deleted_at": "is.null"}),
    }), 200

# ─────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({
        "status":       "ok",
        "supabase_url": bool(SUPABASE_URL),
        "time":         datetime.now().isoformat(),
    })

# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
