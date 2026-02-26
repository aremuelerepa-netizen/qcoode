import os, re, json
from functools import wraps
from datetime import datetime, timezone, timedelta

import requests
from flask import Flask, render_template, request, jsonify, session, redirect
from dotenv import load_dotenv
from flask_cors import CORS  # <-- Added for frontend fetch cross-origin support

# ── Africa's Talking (optional) ───────────────────────────────
try:
    import africastalking
    AT_AVAILABLE = True
except ImportError:
    AT_AVAILABLE = False
    print("⚠ africastalking not installed — SMS will be mocked in console.")

load_dotenv()

app = Flask(__name__)
CORS(app)  # <-- Enable CORS globally
app.secret_key = os.getenv("APP_SECRET", "qcode-dev-secret-CHANGE-IN-PROD")

# ── CONFIG ─────────────────────────────────────────────
SUPABASE_URL      = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
SUPABASE_KEY      = os.getenv("SUPABASE_KEY", "")
AT_USERNAME       = os.getenv("AT_USERNAME", "sandbox")
AT_API_KEY        = os.getenv("AT_API_KEY", "")
AT_SENDER_ID      = os.getenv("AT_SENDER_ID", "QCode")
SMS_NUMBER        = os.getenv("SMS_NUMBER", "+0000000000")
ADMIN_PASSWORD    = os.getenv("ADMIN_PASSWORD", "admin123")

sms_client = None
if AT_AVAILABLE and AT_API_KEY:
    africastalking.initialize(AT_USERNAME, AT_API_KEY)
    sms_client = africastalking.SMS

# ── SUPABASE HELPERS ─────────────────────────────
def _h_anon(extra=None):
    h = {"apikey": SUPABASE_ANON_KEY,
         "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
         "Content-Type": "application/json",
         "Prefer": "return=representation"}
    if extra: h.update(extra)
    return h

def _h_service(extra=None):
    h = {"apikey": SUPABASE_KEY,
         "Authorization": f"Bearer {SUPABASE_KEY}",
         "Content-Type": "application/json",
         "Prefer": "return=representation"}
    if extra: h.update(extra)
    return h

def _h_user(token, extra=None):
    h = {"apikey": SUPABASE_ANON_KEY,
         "Authorization": f"Bearer {token}",
         "Content-Type": "application/json",
         "Prefer": "return=representation"}
    if extra: h.update(extra)
    return h

def sb_signup(email: str, password: str) -> dict:
    try:
        r = requests.post(
            f"{SUPABASE_URL}/auth/v1/signup",
            headers=_h_anon(),
            json={"email": email, "password": password},
            timeout=15,
        )
        return r.json()
    except Exception as e:
        print(f"[SIGNUP ERROR] {e}")
        return {"error": "Signup request failed."}

def sb_signin(email: str, password: str) -> dict:
    try:
        r = requests.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers=_h_anon(),
            json={"email": email, "password": password},
            timeout=15,
        )
        return r.json()
    except Exception as e:
        print(f"[SIGNIN ERROR] {e}")
        return {"error": "Signin request failed."}

def sb_signout(token: str):
    try:
        requests.post(
            f"{SUPABASE_URL}/auth/v1/logout",
            headers=_h_user(token),
            timeout=5
        )
    except Exception:
        pass

# ── Database helpers ─────────────────────────────
def db_insert(table: str, data: dict) -> dict:
    try:
        r = requests.post(f"{SUPABASE_URL}/rest/v1/{table}", headers=_h_service(), json=data, timeout=15)
        return {"ok": r.ok, "data": r.json(), "status": r.status_code}
    except Exception as e:
        print(f"[DB INSERT ERROR] {table} {e}")
        return {"ok": False, "data": None, "status": 500}

def db_select(table: str, filters: dict = None, cols: str = "*", single: bool = False) -> any:
    try:
        params = {"select": cols}
        if filters:
            params.update(filters)
        h = _h_service()
        if single:
            h["Accept"] = "application/vnd.pgrst.object+json"
        r = requests.get(f"{SUPABASE_URL}/rest/v1/{table}", headers=h, params=params, timeout=15)
        if not r.ok:
            return None if single else []
        return r.json()
    except Exception as e:
        print(f"[DB SELECT ERROR] {table} {e}")
        return None if single else []

def db_update(table: str, match: dict, data: dict) -> dict:
    params = {k: f"eq.{v}" for k, v in match.items()}
    try:
        r = requests.patch(f"{SUPABASE_URL}/rest/v1/{table}", headers=_h_service(), params=params, json=data, timeout=15)
        return {"ok": r.ok, "status": r.status_code}
    except Exception as e:
        print(f"[DB UPDATE ERROR] {table} {e}")
        return {"ok": False, "status": 500}

def db_count(table: str, filters: dict = None) -> int:
    try:
        h = {**_h_service(), "Prefer": "count=exact"}
        params = {"select": "id"}
        if filters:
            params.update(filters)
        r = requests.head(f"{SUPABASE_URL}/rest/v1/{table}", headers=h, params=params, timeout=15)
        return int(r.headers.get("content-range", "0/0").split("/")[1])
    except Exception:
        return 0

def get_profile(user_id: str) -> dict:
    return db_select("profiles", {"id": f"eq.{user_id}"}, single=True) or {}

# ── Session Utilities ─────────────────────────────
def save_session(user_id: str, token: str, profile: dict):
    session.permanent = True
    session.update({
        "user_id": user_id,
        "access_token": token,
        "role": profile.get("role", "user"),
        "email": profile.get("email", ""),
        "full_name": profile.get("full_name") or profile.get("org_name") or "",
        "org_name": profile.get("org_name", ""),
        "preferred_lang": profile.get("preferred_lang", "en"),
        "approval_status": profile.get("approval_status", "approved"),
    })

def role_to_url(role: str) -> str:
    return {"user": "/dashboard/user", "organization": "/dashboard/org", "super_admin": "/admin"}.get(role, "/")

def mark_online(uid: str, online: bool = True):
    db_update("profiles", {"id": uid}, {"is_online": online})

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "super_admin":
            return jsonify({"error": "Unauthorized"}), 403
        return f(*args, **kwargs)
    return wrapper

# ── Page Routes ─────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/auth/register-user")
@app.route("/auth/register-user.html")
def page_register_user():
    return render_template("auth/register-user.html")

@app.route("/auth/login-user")
@app.route("/auth/login-user.html")
def page_login_user():
    if session.get("role") == "user":
        return redirect("/dashboard/user")
    return render_template("auth/login-user.html")

# ── API Routes (User registration/login) ─────────────────────────────
@app.route("/api/auth/register-user", methods=["POST"])
def api_register_user():
    data = request.get_json() or {}
    name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not name:
        return jsonify({"error": "Full name required"}), 400
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Valid email required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 chars"}), 400

    signup = sb_signup(email, password)
    uid = signup.get("id")
    if not uid:
        msg = signup.get("error_description") or signup.get("message") or "Registration failed"
        if "already registered" in str(msg).lower():
            msg = "Email already exists"
        return jsonify({"error": msg}), 400

    ins = db_insert("profiles", {"id": uid, "role": "user", "full_name": name, "email": email, "approval_status": "approved"})
    if not ins["ok"]:
        return jsonify({"error": "Profile could not be saved"}), 500

    return jsonify({"success": True, "message": "Account created! Please confirm email."}), 201

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    signin = sb_signin(email, password)
    token = signin.get("access_token")
    if not token:
        return jsonify({"error": "Invalid email or password"}), 401

    uid = (signin.get("user") or {}).get("id")
    profile = get_profile(uid)
    if not profile:
        sb_signout(token)
        return jsonify({"error": "Profile not found"}), 404

    save_session(uid, token, profile)
    mark_online(uid, True)
    return jsonify({"success": True, "role": profile.get("role"), "redirect": role_to_url(profile.get("role"))}), 200

# ── Health Check ─────────────────────────────
@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "QCode",
        "supabase_url": bool(SUPABASE_URL),
        "sms_ready": sms_client is not None,
        "time": datetime.now().isoformat()
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV", "development") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
