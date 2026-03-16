import os, re, json, random, requests
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
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=1)
CORS(app, supports_credentials=True)

SUPABASE_URL         = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY    = os.getenv("SUPABASE_ANON_KEY", "")
SUPABASE_KEY         = os.getenv("SUPABASE_KEY", "")
SUPABASE_BUCKET      = os.getenv("SUPABASE_STORAGE_BUCKET", "org-logos")
SUPER_ADMIN_EMAIL    = os.getenv("SUPER_ADMIN_EMAIL", "admin@qcode.com").strip().lower()
SUPER_ADMIN_PASSWORD = os.getenv("SUPER_ADMIN_PASSWORD", "admin123").strip()
SENDGRID_API_KEY     = os.getenv("SENDGRID_API_KEY", "")
SENDGRID_FROM        = os.getenv("SENDGRID_FROM_EMAIL", "noreply@qcode.com")
VAPID_PUBLIC_KEY     = os.getenv("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY    = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_CLAIM_EMAIL    = os.getenv("VAPID_CLAIM_EMAIL", "admin@qcode.com")

if not SUPABASE_URL or not SUPABASE_ANON_KEY or not SUPABASE_KEY:
    raise RuntimeError("Missing required env vars: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_KEY")

SMS_GATEWAY_NUMBER = os.getenv("SMS_GATEWAY_NUMBER", "")
ANDROID_GW_URL     = os.getenv("ANDROID_GW_URL", "")
ANDROID_GW_LOGIN   = os.getenv("ANDROID_GW_LOGIN", "")
ANDROID_GW_PASSWORD= os.getenv("ANDROID_GW_PASSWORD", "")
ANDROID_GW_DEVICE  = os.getenv("ANDROID_GW_DEVICE", "")
FALLBACK_SMS_URL   = os.getenv("FALLBACK_SMS_URL", "")
FALLBACK_SMS_KEY   = os.getenv("FALLBACK_SMS_KEY", "")
FALLBACK_KEY_FLD   = os.getenv("FALLBACK_KEY_FLD", "apikey")
FALLBACK_PHONE_FLD = os.getenv("FALLBACK_PHONE_FLD", "to")
FALLBACK_MSG_FLD   = os.getenv("FALLBACK_MSG_FLD", "message")
SMS_SENDER_ID      = os.getenv("SMS_SENDER_ID", "QCode")

# ── SCHEMA CACHE ──────────────────────────────────────────────
_schema_cache: dict = {}

def _fetch_columns(table: str) -> set:
    if table in _schema_cache:
        return _schema_cache[table]
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/{table}?limit=1",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                     "Accept": "application/json"}, timeout=10)
        cols = set(r.json()[0].keys()) if r.ok and r.json() else set()
        _schema_cache[table] = cols
        return cols
    except Exception as e:
        print(f"[Schema Cache] {e}")
        return set()

def _safe_payload(table: str, required: dict, optional: dict) -> dict:
    existing = _fetch_columns(table)
    payload  = dict(required)
    for col, val in optional.items():
        if not existing or col in existing:
            payload[col] = val
    return payload

# ── DB HELPERS ────────────────────────────────────────────────
def _h_service():
    return {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json", "Prefer": "return=representation"}

def _h_anon():
    return {"apikey": SUPABASE_ANON_KEY, "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
            "Content-Type": "application/json"}

def admin_create_user(email, password):
    r = requests.post(f"{SUPABASE_URL}/auth/v1/admin/users",
        headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                 "Content-Type": "application/json"},
        json={"email": email, "password": password, "email_confirm": True}, timeout=15)
    return r.json()

def sb_signin(email, password):
    r = requests.post(f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
                      headers=_h_anon(), json={"email": email, "password": password}, timeout=15)
    return r.json()

def sb_signout(token):
    try:
        requests.post(f"{SUPABASE_URL}/auth/v1/logout",
                      headers={"apikey": SUPABASE_ANON_KEY, "Authorization": f"Bearer {token}"}, timeout=5)
    except: pass

def db_insert(table, data):
    r = requests.post(f"{SUPABASE_URL}/rest/v1/{table}", headers=_h_service(), json=data, timeout=15)
    return {"ok": r.ok, "data": r.json(), "status": r.status_code}

def db_select(table, filters=None, single=False):
    params = {"select": "*"}
    if filters: params.update(filters)
    h = dict(_h_service())
    if single: h["Accept"] = "application/vnd.pgrst.object+json"
    r = requests.get(f"{SUPABASE_URL}/rest/v1/{table}", headers=h, params=params, timeout=15)
    if not r.ok: return None if single else []
    return r.json()

def db_update(table, match, data):
    params = {k: f"eq.{v}" for k, v in match.items()}
    r = requests.patch(f"{SUPABASE_URL}/rest/v1/{table}",
                       headers=_h_service(), params=params, json=data, timeout=15)
    return r.ok

def db_count(table, filters=None):
    h = {**_h_service(), "Prefer": "count=exact"}
    params = {"select": "id"}
    if filters: params.update(filters)
    r = requests.head(f"{SUPABASE_URL}/rest/v1/{table}", headers=h, params=params, timeout=15)
    try: return int(r.headers.get("content-range","0/0").split("/")[1])
    except: return 0

def get_profile(user_id):
    return db_select("profiles", {"id": f"eq.{user_id}"}, single=True) or {}

def _rcode(n=6):
    return "".join(random.choices("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", k=n))

# ── SMS ───────────────────────────────────────────────────────
def send_sms(to_phone, message):
    if ANDROID_GW_URL:
        try:
            body = {"phoneNumbers": [to_phone], "message": message}
            if ANDROID_GW_DEVICE: body["simNumber"] = ANDROID_GW_DEVICE
            auth = (ANDROID_GW_LOGIN, ANDROID_GW_PASSWORD) if ANDROID_GW_LOGIN else None
            requests.post(ANDROID_GW_URL.rstrip("/")+"/message", json=body, auth=auth, timeout=10)
            return
        except Exception as e: print(f"[Android GW Error] {e}")
    if FALLBACK_SMS_URL:
        try:
            requests.post(FALLBACK_SMS_URL, data={FALLBACK_KEY_FLD: FALLBACK_SMS_KEY,
                FALLBACK_PHONE_FLD: to_phone, FALLBACK_MSG_FLD: message, "sender": SMS_SENDER_ID}, timeout=10)
            return
        except Exception as e: print(f"[Fallback SMS Error] {e}")
    print(f"[SMS]\nTo: {to_phone}\n{message}")

def _log_sms(from_phone, message_body, service_code, entry_id, status):
    try:
        db_insert("sms_joins", {"from_phone": from_phone, "message_body": message_body,
                                "service_code": service_code, "queue_entry_id": entry_id,
                                "status": status, "created_at": datetime.now(timezone.utc).isoformat()})
    except Exception as e: print(f"[Log Error] {e}")

# ── PUSH ──────────────────────────────────────────────────────
def send_push_to_user(user_id, title, body, data=None):
    if not VAPID_PRIVATE_KEY: return
    subs = db_select("push_subscriptions", {"user_id": f"eq.{user_id}"})
    for sub in subs:
        try:
            from pywebpush import webpush
            sub_data = sub.get("subscription_data")
            if isinstance(sub_data, str): sub_data = json.loads(sub_data)
            webpush(subscription_info=sub_data,
                    data=json.dumps({"title": title, "body": body, "data": data or {}}),
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims={"sub": f"mailto:{VAPID_CLAIM_EMAIL}"})
        except Exception as e: print(f"[Push Error] {e}")

# ── EMAIL (unified) ───────────────────────────────────────────
def _send_email(to_email, subject, html_body):
    """
    Sends an email via SendGrid.
    Falls back to printing if SENDGRID_API_KEY is not set.
    Returns True on success.
    """
    if not SENDGRID_API_KEY:
        print(f"[EMAIL - no SendGrid key]\nTo: {to_email}\nSubject: {subject}\n{html_body[:200]}")
        return False
    try:
        r = requests.post("https://api.sendgrid.com/v3/mail/send",
            headers={"Authorization": f"Bearer {SENDGRID_API_KEY}", "Content-Type": "application/json"},
            json={"personalizations": [{"to": [{"email": to_email}]}],
                  "from": {"email": SENDGRID_FROM, "name": "QCode"},
                  "subject": subject,
                  "content": [{"type": "text/html", "value": html_body}]},
            timeout=15)
        if not r.ok:
            print(f"[SendGrid Error] {r.status_code} {r.text[:200]}")
        return r.ok
    except Exception as e:
        print(f"[SendGrid Exception] {e}")
        return False

def send_reset_email(to_email, reset_link, is_org=False):
    label = "Organization" if is_org else "Account"
    html  = f"""
    <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#f4f6fb;border-radius:12px">
      <div style="background:#fff;border-radius:12px;padding:2rem;border-top:4px solid #4361ee">
        <h2 style="color:#4361ee;margin-bottom:.5rem">Reset your QCode password</h2>
        <p style="color:#475569;line-height:1.6;margin-bottom:1.5rem">
          A password reset was requested for your QCode {label} account.
          Click the button below to set a new password. This link expires in <strong>1 hour</strong>.
        </p>
        <a href="{reset_link}"
           style="display:inline-block;background:#4361ee;color:#fff;padding:.875rem 2rem;
                  border-radius:.75rem;text-decoration:none;font-weight:700;font-size:1rem">
          Reset Password &rarr;
        </a>
        <p style="color:#94a3b8;font-size:.82rem;margin-top:1.5rem;line-height:1.5">
          If you did not request this, you can safely ignore this email.<br/>
          Your password will not change until you click the link above.
        </p>
      </div>
    </div>"""
    return _send_email(to_email, f"Reset your QCode {label} password", html)

def send_approval_email(to_email, org_name):
    """Email sent to org when super admin approves their account."""
    html = f"""
    <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#f4f6fb;border-radius:12px">
      <div style="background:#fff;border-radius:12px;padding:2rem;border-top:4px solid #06d6a0">
        <h2 style="color:#047857;margin-bottom:.5rem">🎉 Your organization has been approved!</h2>
        <p style="color:#475569;line-height:1.6;margin-bottom:1rem">
          Congratulations! <strong>{org_name}</strong> has been approved on QCode.
          You can now log in and start creating queue services for your customers.
        </p>
        <a href="https://qcode.onrender.com/login-org"
           style="display:inline-block;background:#4361ee;color:#fff;padding:.875rem 2rem;
                  border-radius:.75rem;text-decoration:none;font-weight:700;font-size:1rem">
          Log In to Dashboard &rarr;
        </a>
        <p style="color:#94a3b8;font-size:.82rem;margin-top:1.5rem">
          Welcome to QCode — the smarter way to manage queues.
        </p>
      </div>
    </div>"""
    return _send_email(to_email, "✅ Your QCode organization has been approved!", html)

# ── GROQ AI ───────────────────────────────────────────────────
def get_groq():
    from groq import Groq
    return Groq(api_key=os.getenv("GROQ_API_KEY", ""))


# ══════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ══════════════════════════════════════════════════════════════
@app.route("/")
def home(): return render_template("index.html")

@app.route("/register-user")
@app.route("/auth/register-user")
def register_user_page(): return render_template("register-user.html")

@app.route("/register-org")
@app.route("/auth/register-org")
def register_org_page(): return render_template("register-org.html")

@app.route("/login-user")
@app.route("/auth/login-user")
def login_user_page(): return render_template("login-user.html")

@app.route("/login-org")
@app.route("/auth/login-org")
def login_org_page(): return render_template("login-org.html")

@app.route("/forgot-password-user")
def forgot_password_user_page(): return render_template("forgot-password-user.html")

@app.route("/forgot-password-org")
def forgot_password_org_page(): return render_template("forgot-password-org.html")

@app.route("/reset-password-user")
def reset_password_user_page(): return render_template("reset-password-user.html")

@app.route("/reset-password-org")
def reset_password_org_page(): return render_template("reset-password-org.html")

@app.route("/user")
@app.route("/dashboard/user")
def user_dashboard(): return render_template("user.html")

@app.route("/org")
@app.route("/dashboard/org")
def org_dashboard(): return render_template("org.html")

@app.route("/super-admin")
@app.route("/admin")
def super_admin_page(): return render_template("super_admin.html")

@app.route("/staff/<code>")
def staff_page(code): return render_template("staff.html", stage_code=code)

@app.route("/sitemap.xml")
def sitemap(): return app.send_static_file("sitemap.xml")

@app.route("/robots.txt")
def robots_txt(): return app.send_static_file("robots.txt")

@app.route("/manifest.json")
def manifest(): return app.send_static_file("manifest.json")

@app.route("/service-worker.js")
def service_worker(): return app.send_static_file("service-worker.js")


# ══════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════
@app.route("/api/auth/me")
def api_me():
    if not session.get("user_id"): return jsonify({"logged_in": False}), 200
    return jsonify({"logged_in": True, "user_id": session["user_id"], "role": session.get("role"),
                    "email": session.get("email"), "full_name": session.get("full_name"),
                    "org_name": session.get("org_name")}), 200

@app.route("/api/auth/register-user", methods=["POST"])
@app.route("/api/register-user", methods=["POST"])
def register_user():
    d = request.get_json() or {}
    full_name = (d.get("full_name") or "").strip()
    email     = (d.get("email") or "").strip().lower()
    password  = (d.get("password") or "")
    phone     = (d.get("phone") or "").strip()
    if not full_name or not email or not password:
        return jsonify({"error": "Name, email and password are required."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    result = admin_create_user(email, password)
    uid = result.get("id")
    if not uid:
        msg = result.get("message") or result.get("msg") or result.get("error_description") or str(result)
        if "already" in msg.lower():
            return jsonify({"error": "An account with this email already exists."}), 400
        return jsonify({"error": f"Registration failed: {msg}"}), 400
    ins = db_insert("profiles", {"id": uid, "role": "user", "full_name": full_name, "email": email,
                                  "phone": phone or None, "approval_status": "approved", "is_online": False})
    if not ins["ok"]: return jsonify({"error": "Account created but profile save failed."}), 500
    return jsonify({"success": True, "message": "Account created! You can now log in."}), 201

@app.route("/api/auth/register-org", methods=["POST"])
@app.route("/api/register-org", methods=["POST"])
def register_org():
    ct = (request.content_type or "").lower()
    if "multipart" in ct or "form" in ct:
        org_name = (request.form.get("org_name") or "").strip()
        email    = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "")
        phone    = (request.form.get("org_phone") or "").strip()
        address  = (request.form.get("org_address") or "").strip()
        org_type = (request.form.get("org_type") or "").strip()
    else:
        d = request.get_json() or {}
        org_name = (d.get("org_name") or "").strip()
        email    = (d.get("email") or "").strip().lower()
        password = (d.get("password") or "")
        phone    = (d.get("org_phone") or "").strip()
        address  = (d.get("org_address") or "").strip()
        org_type = (d.get("org_type") or "").strip()
    if not org_name or not email or not password:
        return jsonify({"error": "Organization name, email and password are required."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    result = admin_create_user(email, password)
    uid = result.get("id")
    if not uid:
        msg = result.get("message") or result.get("msg") or result.get("error_description") or str(result)
        if "already" in msg.lower():
            return jsonify({"error": "An account with this email already exists."}), 400
        return jsonify({"error": f"Registration failed: {msg}"}), 400
    address_full = " | ".join(filter(None, [org_type, address])) or None
    ins = db_insert("profiles", {"id": uid, "role": "organization", "org_name": org_name,
                                  "full_name": org_name, "email": email, "phone": phone or None,
                                  "company_address": address_full, "approval_status": "pending",
                                  "is_online": False})
    if not ins["ok"]: return jsonify({"error": "Account created but profile save failed."}), 500
    return jsonify({"success": True, "org_name": org_name,
                    "message": f"Registration submitted! '{org_name}' is pending admin approval."}), 201

@app.route("/api/auth/login", methods=["POST"])
@app.route("/api/login-user", methods=["POST"])
def login_user():
    d = request.get_json() or {}
    email    = (d.get("email") or "").strip().lower()
    password = (d.get("password") or "")
    if not email or not password: return jsonify({"error": "Email and password are required."}), 400
    signin = sb_signin(email, password)
    token  = signin.get("access_token")
    if not token:
        raw = signin.get("error_description") or signin.get("msg") or signin.get("message") or signin.get("error") or "Login failed."
        if "invalid" in raw.lower() or "credentials" in raw.lower(): raw = "Incorrect email or password."
        return jsonify({"error": raw}), 401
    uid = (signin.get("user") or {}).get("id")
    if not uid: return jsonify({"error": "Could not retrieve user info."}), 401
    profile = get_profile(uid)
    if not profile: return jsonify({"error": "Profile not found."}), 404
    role   = profile.get("role", "user")
    status = profile.get("approval_status", "approved")
    if status == "suspended":
        sb_signout(token)
        return jsonify({"error": "This account has been suspended."}), 403
    session.permanent = True
    session.update({"user_id": uid, "role": role, "email": profile.get("email",""),
                    "full_name": profile.get("full_name",""), "org_name": profile.get("org_name","")})
    db_update("profiles", {"id": uid}, {"is_online": True})
    return jsonify({"success": True, "role": role,
                    "redirect": {"user":"/user","organization":"/org","super_admin":"/super-admin"}.get(role,"/user")}), 200

@app.route("/api/auth/login-org", methods=["POST"])
@app.route("/api/login-org", methods=["POST"])
def login_org():
    d = request.get_json() or {}
    email    = (d.get("email") or "").strip().lower()
    password = (d.get("password") or "")
    if not email or not password: return jsonify({"error": "Email and password are required."}), 400
    if email == SUPER_ADMIN_EMAIL and password == SUPER_ADMIN_PASSWORD:
        session.permanent = True
        session.update({"user_id": "super-admin", "role": "super_admin", "email": SUPER_ADMIN_EMAIL,
                        "full_name": "Super Admin", "org_name": "QCode Admin"})
        return jsonify({"success": True, "role": "super_admin", "redirect": "/super-admin"}), 200
    signin = sb_signin(email, password)
    token  = signin.get("access_token")
    if not token:
        raw = signin.get("error_description") or signin.get("msg") or signin.get("message") or signin.get("error") or "Login failed."
        if "invalid" in raw.lower(): raw = "Incorrect email or password."
        return jsonify({"error": raw}), 401
    uid = (signin.get("user") or {}).get("id")
    if not uid: return jsonify({"error": "Could not retrieve user info."}), 401
    profile = get_profile(uid)
    if not profile: return jsonify({"error": "Profile not found."}), 404
    role   = profile.get("role")
    status = profile.get("approval_status", "pending")
    if role != "organization": sb_signout(token); return jsonify({"error": "This page is for organizations only."}), 403
    if status == "pending":    sb_signout(token); return jsonify({"error": "Your organization is pending admin approval."}), 403
    if status == "suspended":  sb_signout(token); return jsonify({"error": "This account has been suspended."}), 403
    session.permanent = True
    session.update({"user_id": uid, "role": "organization", "email": profile.get("email",""),
                    "org_name": profile.get("org_name",""), "full_name": profile.get("org_name","")})
    db_update("profiles", {"id": uid}, {"is_online": True})
    return jsonify({"success": True, "role": "organization", "redirect": "/org"}), 200

@app.route("/api/auth/logout", methods=["POST"])
@app.route("/api/logout", methods=["POST"])
def logout():
    uid = session.get("user_id")
    if uid and uid != "super-admin": db_update("profiles", {"id": uid}, {"is_online": False})
    session.clear()
    return jsonify({"success": True, "redirect": "/"}), 200

# ── PASSWORD RESET ────────────────────────────────────────────
@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    d      = request.get_json() or {}
    email  = (d.get("email") or "").strip().lower()
    is_org = bool(d.get("is_org", False))
    if not email: return jsonify({"error": "Email is required."}), 400
    # Always return success to prevent email enumeration
    profiles = db_select("profiles", {"email": f"eq.{email}"})
    if profiles:
        profile = profiles[0]
        role    = profile.get("role","")
        if (is_org and role == "organization") or (not is_org and role == "user"):
            token  = _rcode(32)
            expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            # Save token — table must exist (see supabase_schema.sql)
            ins = db_insert("password_resets", {
                "user_id": profile["id"], "email": email, "token": token,
                "expires_at": expiry, "used": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            })
            if ins["ok"]:
                route = "reset-password-org" if is_org else "reset-password-user"
                link  = f"{request.host_url.rstrip('/')}/{route}?token={token}"
                ok    = send_reset_email(email, link, is_org=is_org)
                if not ok:
                    print(f"[Password Reset] Email failed — link: {link}")
            else:
                print(f"[Password Reset] DB insert failed: {ins['data']}")
    return jsonify({"success": True, "message": "If an account exists, a reset link has been sent."}), 200

@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    d        = request.get_json() or {}
    token    = (d.get("token") or "").strip()
    password = (d.get("password") or "")
    if not token or not password: return jsonify({"error": "Token and password are required."}), 400
    if len(password) < 8: return jsonify({"error": "Password must be at least 8 characters."}), 400
    resets = db_select("password_resets", {"token": f"eq.{token}", "used": "eq.false"})
    if not resets: return jsonify({"error": "Invalid or expired reset link."}), 400
    reset   = resets[0]
    expires = datetime.fromisoformat(reset["expires_at"].replace("Z","+00:00"))
    if datetime.now(timezone.utc) > expires:
        return jsonify({"error": "This reset link has expired. Please request a new one."}), 400
    uid = reset["user_id"]
    r = requests.put(f"{SUPABASE_URL}/auth/v1/admin/users/{uid}",
                     headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                              "Content-Type": "application/json"},
                     json={"password": password}, timeout=15)
    if not r.ok: return jsonify({"error": "Failed to update password. Please try again."}), 500
    db_update("password_resets", {"token": token}, {"used": True})
    return jsonify({"success": True}), 200


# ══════════════════════════════════════════════════════════════
#  USER APIs
# ══════════════════════════════════════════════════════════════
@app.route("/api/user/profile", methods=["GET"])
def api_user_profile():
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    profile = get_profile(uid)
    profile["total_queues"] = db_count("queue_entries", {"user_id": f"eq.{uid}"})
    return jsonify(profile), 200

@app.route("/api/user/profile", methods=["POST"])
def api_user_profile_update():
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    d   = request.get_json() or {}
    upd = {k: d[k] or None for k in ("full_name","phone","preferred_lang") if k in d}
    if upd: db_update("profiles", {"id": uid}, upd)
    return jsonify({"success": True}), 200

@app.route("/api/user/find-service")
def api_find_service():
    code = (request.args.get("code") or "").strip().upper()
    if not code: return jsonify({"error": "Service code required"}), 400
    # Check stages table first (for stage-specific codes)
    stages = db_select("stages", {"stage_code": f"eq.{code}"})
    if stages:
        stage = stages[0]
        svcs  = db_select("services", {"id": f"eq.{stage['service_id']}"})
        if svcs:
            svc = svcs[0]
            org = db_select("profiles", {"id": f"eq.{svc['org_id']}"}, single=True) or {}
            waiting = db_count("queue_entries", {"service_id": f"eq.{svc['id']}", "status": "eq.waiting"})
            svc["waiting_count"] = waiting
            svc["org_name"]      = org.get("org_name","")
            svc["org_logo"]      = org.get("logo_url","")
            svc["eta_minutes"]   = (waiting+1)*(stage.get("time_interval") or svc.get("time_interval") or 5)
            svc["stage_id"]      = stage["id"]
            svc["stage_name"]    = stage.get("name","")
            return jsonify(svc), 200
    # Regular service code
    svcs = db_select("services", {"service_code": f"eq.{code}"})
    if not svcs: return jsonify({"error": f"No service found with code '{code}'."}), 404
    svc = svcs[0]
    if svc.get("deleted_at"): return jsonify({"error": "This service no longer exists."}), 404
    org = db_select("profiles", {"id": f"eq.{svc['org_id']}"}, single=True) or {}
    if org.get("approval_status") != "approved":
        return jsonify({"error": "This organization is not currently active."}), 403
    if svc["status"] == "closed": return jsonify({"error": f"'{svc['name']}' queue is closed."}), 400
    if svc["status"] == "paused": return jsonify({"error": f"'{svc['name']}' queue is paused. Try again soon."}), 400
    waiting = db_count("queue_entries", {"service_id": f"eq.{svc['id']}", "status": "eq.waiting"})
    svc["waiting_count"] = waiting
    svc["org_name"]      = org.get("org_name","")
    svc["org_logo"]      = org.get("logo_url","")
    svc["eta_minutes"]   = (waiting+1)*(svc.get("time_interval") or 5)
    # Include stages info if multi-stage
    stages_list = db_select("stages", {"service_id": f"eq.{svc['id']}", "order": "order.asc"})
    if stages_list:
        svc["stages"] = [{"id": s["id"], "name": s.get("name",""), "order": s.get("order",1),
                          "stage_code": s.get("stage_code","")} for s in stages_list]
    return jsonify(svc), 200

@app.route("/api/user/join-queue", methods=["POST"])
def api_join_queue():
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    d      = request.get_json() or {}
    svc_id = d.get("service_id")
    if not svc_id: return jsonify({"error": "service_id required"}), 400
    svcs = db_select("services", {"id": f"eq.{svc_id}"})
    if not svcs: return jsonify({"error": "Service not found"}), 404
    svc = svcs[0]
    if svc["status"] != "open": return jsonify({"error": f"Queue is {svc['status']}."}), 400
    max_u   = svc.get("max_users") or 9999
    current = db_count("queue_entries", {"service_id":f"eq.{svc_id}","status":"in.(waiting,called,serving)"})
    if current >= max_u: return jsonify({"error": "Queue is full. Please try again later."}), 400
    already = db_select("queue_entries", {"service_id":f"eq.{svc_id}","user_id":f"eq.{uid}",
                                          "status":"in.(waiting,called,serving)"})
    if already: return jsonify({"error": "You are already in this queue.", "entry": already[0]}), 409
    n     = (svc.get("ticket_counter") or 0) + 1
    label = f"{svc.get('ticket_prefix','Q')}{str(n).zfill(3)}"
    db_update("services", {"id": svc_id}, {"ticket_counter": n})
    pos   = db_count("queue_entries", {"service_id":f"eq.{svc_id}","status":"eq.waiting"}) + 1
    eta_t = (datetime.now(timezone.utc)+timedelta(minutes=pos*(svc.get("time_interval") or 5))).isoformat()
    end_code = _rcode(4)
    profile  = get_profile(uid)
    # If multi-stage, join the first stage
    first_stage_id = None
    stages_list = db_select("stages", {"service_id": f"eq.{svc_id}", "order": "order.asc"})
    if stages_list:
        first_stage_id = stages_list[0]["id"]
    required = {"service_id": svc_id, "user_id": uid, "ticket_label": label,
                "ticket_number": n, "status": "waiting", "estimated_time": eta_t,
                "join_method": "web", "joined_at": datetime.now(timezone.utc).isoformat()}
    optional = {"end_code": end_code, "custom_form_data": d.get("custom_form_data") or {},
                "pushback_count": 0, "stage_id": first_stage_id}
    res = db_insert("queue_entries", _safe_payload("queue_entries", required, optional))
    if not res["ok"]:
        err = res["data"].get("message","Failed to join queue.") if isinstance(res["data"],dict) else "Failed to join queue."
        return jsonify({"error": err}), 500
    entry = res["data"][0] if isinstance(res["data"],list) else res["data"]
    org   = db_select("profiles",{"id":f"eq.{svc['org_id']}"},single=True) or {}
    entry.update({"position": pos, "svc_name": svc["name"], "time_interval": svc.get("time_interval",5),
                  "end_code": end_code, "org_name": org.get("org_name",""), "org_logo": org.get("logo_url",""),
                  "stages": [{"id":s["id"],"name":s.get("name",""),"order":s.get("order",1)} for s in stages_list],
                  "current_stage_index": 0, "stage_name": stages_list[0]["name"] if stages_list else ""})
    send_push_to_user(uid,"✅ Joined Queue!",f"Ticket {label} — Position #{pos}",
                      {"type":"joined","entry_id":entry.get("id"),"url":"/user"})
    if profile.get("phone"):
        send_sms(profile["phone"], f"QCode: Joined {svc['name']}. Ticket: {label} | #{pos} | ~{pos*(svc.get('time_interval') or 5)} min.")
    return jsonify({"success": True, "entry": entry, "end_code": end_code}), 201

@app.route("/api/user/queue-status/<entry_id>")
def api_queue_status(entry_id):
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    rows = db_select("queue_entries", {"id": f"eq.{entry_id}"})
    if not rows or rows[0].get("user_id") != uid: return jsonify({"error": "Not found"}), 404
    entry = rows[0]
    ahead = db_count("queue_entries", {"service_id":f"eq.{entry['service_id']}","status":"eq.waiting",
                                        "ticket_number":f"lt.{entry['ticket_number']}"})
    total = db_count("queue_entries", {"service_id":f"eq.{entry['service_id']}","status":"eq.waiting"})
    svcs  = db_select("services", {"id": f"eq.{entry['service_id']}"})
    svc   = svcs[0] if svcs else {}
    org   = db_select("profiles", {"id": f"eq.{svc.get('org_id','')}"}, single=True) or {}
    eta_mins = max(0,(ahead+1)*(svc.get("time_interval") or 5))
    # Stage info
    stage_name = ""; current_stage_index = 0; stages_list = []
    stage_id = entry.get("stage_id")
    if stage_id:
        cur_stage = db_select("stages", {"id": f"eq.{stage_id}"})
        if cur_stage:
            stage_name = cur_stage[0].get("name","")
            all_stages = db_select("stages", {"service_id": f"eq.{entry['service_id']}", "order": "order.asc"})
            stages_list = [{"id":s["id"],"name":s.get("name",""),"order":s.get("order",1)} for s in all_stages]
            for i,s in enumerate(all_stages):
                if s["id"] == stage_id:
                    current_stage_index = i; break
    entry.update({"position": ahead+1, "ahead": ahead, "total": total, "eta_minutes": eta_mins,
                  "svc_name": svc.get("name",""), "svc_status": svc.get("status",""),
                  "time_interval": svc.get("time_interval",5),
                  "estimated_time": (datetime.now(timezone.utc)+timedelta(minutes=eta_mins)).isoformat(),
                  "org_name": org.get("org_name",""), "org_logo": org.get("logo_url",""),
                  "stage_name": stage_name, "stages": stages_list,
                  "current_stage_index": current_stage_index})
    return jsonify(entry), 200

@app.route("/api/user/leave-queue/<entry_id>", methods=["POST"])
def api_leave_queue(entry_id):
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    rows = db_select("queue_entries", {"id": f"eq.{entry_id}"})
    if not rows or rows[0].get("user_id") != uid: return jsonify({"error": "Not found"}), 404
    db_update("queue_entries", {"id": entry_id},
              {"status": "cancelled", "completed_at": datetime.now(timezone.utc).isoformat()})
    return jsonify({"success": True}), 200

# ── READY TO CHECKOUT (THE MISSING ENDPOINT) ──────────────────
@app.route("/api/user/ready-checkout", methods=["POST"])
def api_ready_checkout():
    """
    Customer presses 'Ready to Checkout' after shopping.
    1. Mark current entry as completed (shopping stage done)
    2. Find the next stage (checkout stage)
    3. Find the least-busy counter in that stage (smart assignment)
    4. Create new queue_entry for checkout stage
    5. Return assigned counter + new ticket info
    """
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    d        = request.get_json() or {}
    entry_id = d.get("entry_id")
    if not entry_id: return jsonify({"error": "entry_id required"}), 400
    rows = db_select("queue_entries", {"id": f"eq.{entry_id}"})
    if not rows or rows[0].get("user_id") != uid:
        return jsonify({"error": "Entry not found"}), 404
    entry  = rows[0]
    svc_id = entry.get("service_id")
    stage_id = entry.get("stage_id")
    if not svc_id: return jsonify({"error": "Invalid queue entry"}), 400
    # Mark current entry as completed (shopping done)
    db_update("queue_entries", {"id": entry_id},
              {"status": "completed", "completed_at": datetime.now(timezone.utc).isoformat()})
    # Find next stage after current
    next_stage = None
    if stage_id:
        cur_stage = db_select("stages", {"id": f"eq.{stage_id}"})
        if cur_stage:
            cur_order = cur_stage[0].get("order", 1)
            next_stages = db_select("stages", {"service_id": f"eq.{svc_id}", "order": f"eq.{cur_order+1}"})
            next_stage  = next_stages[0] if next_stages else None
    else:
        # No stage_id — find first checkout stage by name
        all_stages = db_select("stages", {"service_id": f"eq.{svc_id}", "order": "order.asc"})
        for s in all_stages:
            if "checkout" in (s.get("name","")).lower():
                next_stage = s; break
        if not next_stage and all_stages:
            next_stage = all_stages[1] if len(all_stages) > 1 else None
    if not next_stage:
        return jsonify({"error": "No checkout stage configured for this service."}), 400
    next_stage_id = next_stage["id"]
    # ── SMART COUNTER ASSIGNMENT: find least busy counter ──
    counters = db_select("staff_counters", {"stage_id": f"eq.{next_stage_id}", "is_active": "eq.true"})
    assigned_counter = None
    if counters:
        # Count how many waiting/called entries each counter has
        counter_loads = []
        for ctr in counters:
            load = db_count("queue_entries", {"service_id": f"eq.{svc_id}",
                                               "stage_id": f"eq.{next_stage_id}",
                                               "status": "in.(waiting,called,serving)"})
            # Simple least-busy: distribute evenly
            counter_loads.append((ctr, load))
        counter_loads.sort(key=lambda x: x[1])
        best_counter = counter_loads[0][0]
        assigned_counter = f"Counter {best_counter.get('counter_number',1)} — {best_counter.get('staff_name','')}"
    # Create new queue entry for checkout stage
    svcs = db_select("services", {"id": f"eq.{svc_id}"})
    svc  = svcs[0] if svcs else {}
    n    = (svc.get("ticket_counter") or 0) + 1
    # Checkout tickets use P prefix by convention
    label = f"P{str(n).zfill(3)}"
    db_update("services", {"id": svc_id}, {"ticket_counter": n})
    pos   = db_count("queue_entries", {"service_id": f"eq.{svc_id}", "stage_id": f"eq.{next_stage_id}",
                                        "status": "eq.waiting"}) + 1
    eta_t = (datetime.now(timezone.utc)+timedelta(minutes=pos*(next_stage.get("time_interval") or 5))).isoformat()
    required = {"service_id": svc_id, "user_id": uid, "ticket_label": label,
                "ticket_number": n, "status": "waiting", "estimated_time": eta_t,
                "join_method": entry.get("join_method","web"),
                "joined_at": datetime.now(timezone.utc).isoformat()}
    optional = {"end_code": entry.get("end_code"), "pushback_count": 0,
                "stage_id": next_stage_id, "assigned_counter": assigned_counter,
                "guest_name": entry.get("guest_name"), "guest_phone": entry.get("guest_phone")}
    res = db_insert("queue_entries", _safe_payload("queue_entries", required, optional))
    if not res["ok"]:
        return jsonify({"error": "Failed to join checkout queue."}), 500
    new_entry = res["data"][0] if isinstance(res["data"],list) else res["data"]
    new_entry_id = new_entry.get("id")
    send_push_to_user(uid, "🛒 Checkout Queue Joined!",
                      f"Assigned to {assigned_counter or 'checkout'}. Ticket {label}.",
                      {"type":"next_stage","stage_name": next_stage.get("name","Checkout"),
                       "entry_id": new_entry_id, "url": "/user"})
    if entry.get("guest_phone"):
        send_sms(entry["guest_phone"],
                 f"QCode: Ready for checkout! Ticket {label} | {assigned_counter or 'checkout counter'}. Position #{pos}.")
    return jsonify({"success": True, "ticket_label": label, "new_entry_id": new_entry_id,
                    "position": pos, "assigned_counter": assigned_counter,
                    "estimated_time": eta_t, "stage_name": next_stage.get("name","Checkout")}), 200

@app.route("/api/user/history")
def api_user_history():
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    rows  = db_select("queue_entries", {"user_id":f"eq.{uid}","order":"joined_at.desc","limit":"50"})
    cache = {}
    for row in rows:
        sid = row.get("service_id")
        if sid and sid not in cache:
            svcs = db_select("services", {"id": f"eq.{sid}"})
            if svcs:
                org = db_select("profiles",{"id":f"eq.{svcs[0]['org_id']}"},single=True) or {}
                cache[sid] = {"name": svcs[0]["name"], "org_name": org.get("org_name","")}
        if sid in cache: row["svc_name"] = cache[sid]["name"]; row["org_name"] = cache[sid]["org_name"]
    return jsonify(rows), 200

@app.route("/api/user/open-services")
def api_open_services():
    svcs = db_select("services",{"status":"eq.open","deleted_at":"is.null","order":"created_at.desc","limit":"30"})
    result = []
    for svc in svcs:
        org = db_select("profiles",{"id":f"eq.{svc['org_id']}"},single=True) or {}
        if org.get("approval_status") != "approved": continue
        svc["org_name"]      = org.get("org_name","")
        svc["org_logo"]      = org.get("logo_url","")
        svc["waiting_count"] = db_count("queue_entries",{"service_id":f"eq.{svc['id']}","status":"eq.waiting"})
        result.append(svc)
    return jsonify(result), 200

@app.route("/api/user/feedback", methods=["POST"])
def api_user_feedback():
    d        = request.get_json() or {}
    entry_id = d.get("entry_id"); rating = d.get("rating")
    comment  = (d.get("comment") or "").strip(); uid = session.get("user_id")
    if not entry_id or not rating: return jsonify({"error": "entry_id and rating required"}), 400
    rows   = db_select("queue_entries", {"id": f"eq.{entry_id}"})
    svc_id = rows[0].get("service_id") if rows else None
    payload = {"entry_id": entry_id, "user_id": uid, "rating": int(rating),
               "comment": comment or None, "created_at": datetime.now(timezone.utc).isoformat()}
    if svc_id: payload["service_id"] = svc_id
    db_insert("feedbacks", payload)
    return jsonify({"success": True}), 201

# ── PUSH SUBSCRIBE ────────────────────────────────────────────
@app.route("/api/push/vapid-public-key")
def api_vapid_key():
    return jsonify({"publicKey": VAPID_PUBLIC_KEY}), 200

@app.route("/api/push/subscribe", methods=["POST"])
@app.route("/api/user/push-subscribe", methods=["POST"])   # FIXED: both URLs work
def api_push_subscribe():
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    subscription = (request.get_json() or {}).get("subscription")
    if not subscription: return jsonify({"error": "subscription required"}), 400
    endpoint = subscription.get("endpoint","")
    existing = db_select("push_subscriptions", {"endpoint": f"eq.{endpoint}"})
    if existing:
        db_update("push_subscriptions", {"endpoint": endpoint},
                  {"user_id": uid, "subscription_data": json.dumps(subscription),
                   "updated_at": datetime.now(timezone.utc).isoformat()})
    else:
        db_insert("push_subscriptions", {"user_id": uid, "endpoint": endpoint,
                                          "subscription_data": json.dumps(subscription),
                                          "created_at": datetime.now(timezone.utc).isoformat()})
    return jsonify({"success": True}), 201

# ── AUTO SYSTEMS ──────────────────────────────────────────────
@app.route("/api/system/auto-cancel", methods=["POST"])
def api_auto_cancel():
    called = db_select("queue_entries", {"status": "eq.called"})
    cancelled = []; pushed_back = []
    for entry in called:
        called_at_str = entry.get("called_at")
        if not called_at_str: continue
        svcs = db_select("services", {"id": f"eq.{entry.get('service_id')}"})
        if not svcs: continue
        grace_min = max(1, svcs[0].get("time_interval",5) // 4)
        called_at = datetime.fromisoformat(called_at_str.replace("Z","+00:00"))
        if (datetime.now(timezone.utc)-called_at).total_seconds() < grace_min*60: continue
        pb = entry.get("pushback_count", 0) or 0
        if pb >= 3:
            db_update("queue_entries", {"id": entry["id"]},
                      {"status":"no_show","completed_at":datetime.now(timezone.utc).isoformat()})
            cancelled.append(entry["id"])
            if entry.get("user_id"):
                send_push_to_user(entry["user_id"],"❌ Removed from Queue",
                                  f"Ticket {entry.get('ticket_label','—')} removed after 3 missed calls.",
                                  {"type":"no_show","url":"/user"})
        else:
            db_update("queue_entries", {"id": entry["id"]}, {
                "status": "waiting", "ticket_number": entry["ticket_number"]+3,
                "pushback_count": pb+1, "called_at": None
            })
            pushed_back.append(entry["id"])
            if entry.get("user_id"):
                send_push_to_user(entry["user_id"],f"⚠️ Pushed Back ({pb+1}/3)",
                                  "You missed your call. Moved back 3 positions.",
                                  {"type":"pushback","count":pb+1,"url":"/user"})
            if entry.get("guest_phone"):
                send_sms(entry["guest_phone"],
                         f"QCode: Ticket {entry.get('ticket_label','—')} missed call #{pb+1}. Pushed back 3 positions.")
    return jsonify({"cancelled": cancelled, "pushed_back": pushed_back}), 200

@app.route("/api/system/auto-schedule", methods=["POST"])
def api_auto_schedule():
    now  = datetime.now(timezone.utc)
    svcs = db_select("services", {"deleted_at": "is.null"})
    opened = []; closed = []
    for svc in svcs:
        for sc in ("schedule_start","queue_start"):
            s = svc.get(sc)
            if s:
                try:
                    if now >= datetime.fromisoformat(s.replace("Z","+00:00")) and svc["status"]=="closed":
                        db_update("services",{"id":svc["id"]},{"status":"open"})
                        opened.append(svc["id"]); break
                except: pass
        for ec in ("schedule_end","queue_end"):
            e = svc.get(ec)
            if e:
                try:
                    if now >= datetime.fromisoformat(e.replace("Z","+00:00")) and svc["status"] in ("open","paused"):
                        db_update("services",{"id":svc["id"]},{"status":"closed"})
                        closed.append(svc["id"]); break
                except: pass
    return jsonify({"opened": opened, "closed": closed}), 200


# ══════════════════════════════════════════════════════════════
#  ORG APIs
# ══════════════════════════════════════════════════════════════
@app.route("/api/org/profile", methods=["GET"])
def api_org_profile():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    return jsonify(get_profile(uid)), 200

@app.route("/api/org/profile", methods=["POST"])
def api_org_profile_update():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    d = request.get_json() or {}
    upd = {k: d[k] or None for k in ("phone","logo_url") if k in d}
    if upd: db_update("profiles", {"id": uid}, upd)
    return jsonify({"success": True}), 200

@app.route("/api/org/upload-logo", methods=["POST"])
def api_org_upload_logo():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    if "logo" not in request.files: return jsonify({"error": "No file uploaded. Use field name 'logo'."}), 400
    file = request.files["logo"]
    if not file.filename: return jsonify({"error": "Empty filename."}), 400
    allowed = {"image/jpeg","image/png","image/webp","image/gif"}
    content_type = file.content_type or "image/jpeg"
    if content_type not in allowed: return jsonify({"error": "Only JPG, PNG or WebP images are allowed."}), 400
    data = file.read()
    if len(data) > 2*1024*1024: return jsonify({"error": "Logo must be under 2MB."}), 400
    ext      = (file.filename.rsplit(".",1)[-1] if "." in file.filename else "jpg").lower()
    filename = f"{uid}/logo.{ext}"
    url      = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{filename}"
    headers  = {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                 "Content-Type": content_type, "x-upsert": "true"}
    r = requests.post(url, headers=headers, data=data, timeout=30)
    if not r.ok: r = requests.put(url, headers=headers, data=data, timeout=30)
    if not r.ok:
        print(f"[Logo Upload Error] {r.status_code} — {r.text[:200]}")
        return jsonify({"error": "Upload failed. Check Supabase Storage bucket name, public access, and RLS policies."}), 500
    public_url = f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{filename}"
    db_update("profiles", {"id": uid}, {"logo_url": public_url})
    return jsonify({"success": True, "logo_url": public_url}), 200

@app.route("/api/org/services", methods=["GET"])
def api_org_services():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    svcs = db_select("services",{"org_id":f"eq.{uid}","deleted_at":"is.null","order":"created_at.desc"})
    for svc in svcs:
        for s in ("waiting","called","serving","completed","no_show"):
            svc[f"count_{s}"] = db_count("queue_entries",{"service_id":f"eq.{svc['id']}","status":f"eq.{s}"})
        # Include stages with their staff links
        stages = db_select("stages",{"service_id":f"eq.{svc['id']}","order":"order.asc"})
        svc["stages_data"] = [{"id":s["id"],"name":s.get("name",""),"order":s.get("order",1),
                                "stage_code":s.get("stage_code",""),"counter_count":s.get("counter_count",1),
                                "staff_names":s.get("staff_names",[])} for s in stages]
    return jsonify(svcs), 200

@app.route("/api/org/services", methods=["POST"])
def api_org_create_service():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    d    = request.get_json() or {}
    name = (d.get("name") or "").strip()
    if not name: return jsonify({"error": "Service name is required"}), 400
    for _ in range(20):
        code = _rcode(6)
        if not db_select("services", {"service_code": f"eq.{code}"}): break
    end_code = _rcode(4)
    required = {"org_id": uid, "name": name, "service_code": code,
                "ticket_prefix": (d.get("ticket_prefix") or "A").upper()[:3],
                "ticket_counter": 0, "time_interval": int(d.get("time_interval") or 5),
                "status": "open"}
    optional = {"staff_name": d.get("staff_name") or None, "description": d.get("description") or None,
                "end_code": end_code, "max_users": int(d.get("max_users")) if d.get("max_users") else None,
                "user_info_form": d.get("user_info_form") or [], "break_times": d.get("break_times") or [],
                "schedule_start": d.get("schedule_start") or d.get("queue_start") or None,
                "schedule_end":   d.get("schedule_end")   or d.get("queue_end")   or None,
                "queue_start":    d.get("schedule_start") or d.get("queue_start") or None,
                "queue_end":      d.get("schedule_end")   or d.get("queue_end")   or None,
                "stages_enabled": bool(d.get("stages")),
                "batch_enabled":  bool(d.get("batch_enabled")),
                "batch_size":     int(d.get("batch_size") or 50) if d.get("batch_enabled") else None,
                "batch_buffer_min": int(d.get("batch_buffer_min") or 30) if d.get("batch_enabled") else None}
    payload = _safe_payload("services", required, optional)
    res     = db_insert("services", payload)
    if not res["ok"]:
        err = "Failed to create service."
        if isinstance(res["data"], dict): err = res["data"].get("message") or res["data"].get("hint") or err
        print(f"[Create Service ERROR] status={res['status']} body={res['data']}")
        return jsonify({"error": err, "detail": res["data"]}), 500
    svc    = res["data"][0] if isinstance(res["data"],list) else res["data"]
    svc_id = svc["id"]
    # Create stages and staff links
    stages_out  = []
    stages_data = d.get("stages") or []
    if isinstance(stages_data, list) and stages_data:
        for i, st in enumerate(stages_data):
            s_req = {"service_id": svc_id, "name": (st.get("name") or "").strip(),
                     "order": st.get("order", i+1), "time_interval": int(st.get("time_interval") or 5),
                     "stage_code": _rcode(6), "staff_pin": st.get("staff_pin") or None,
                     "counter_count": int(st.get("counter_count") or len(st.get("staff_names") or []) or 1),
                     "created_at": datetime.now(timezone.utc).isoformat()}
            s_opt = {"staff_names": st.get("staff_names") or []}
            s_res = db_insert("stages", _safe_payload("stages", s_req, s_opt))
            if s_res.get("ok") and s_res["data"]:
                stage_row = s_res["data"][0] if isinstance(s_res["data"],list) else s_res["data"]
                stage_id  = stage_row.get("id")
                stage_code= stage_row.get("stage_code","")
                staff_link= f"https://qcode.onrender.com/staff/{stage_code}"
                stages_out.append({"stage_name": stage_row.get("name",""), "stage_code": stage_code,
                                    "staff_link": staff_link, "stage_id": stage_id})
                for j, sname in enumerate(st.get("staff_names") or []):
                    db_insert("staff_counters", _safe_payload("staff_counters",
                        {"stage_id": stage_id, "service_id": svc_id, "staff_name": sname,
                         "counter_number": j+1, "is_active": True,
                         "created_at": datetime.now(timezone.utc).isoformat()}, {}))
    return jsonify({"success": True, "service": svc, "service_code": code,
                    "end_code": end_code, "stages": stages_out}), 201

@app.route("/api/org/services/<svc_id>/status", methods=["POST"])
def api_org_service_status(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    status = (request.get_json() or {}).get("status")
    if status not in ("open","paused","closed"): return jsonify({"error": "Invalid status"}), 400
    db_update("services", {"id": svc_id}, {"status": status})
    return jsonify({"success": True}), 200

@app.route("/api/org/services/<svc_id>/interval", methods=["POST"])
def api_org_service_interval(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    val = int((request.get_json() or {}).get("time_interval") or 5)
    if not 1 <= val <= 120: return jsonify({"error": "Interval must be 1-120 minutes"}), 400
    db_update("services", {"id": svc_id}, {"time_interval": val})
    return jsonify({"success": True, "time_interval": val}), 200

@app.route("/api/org/services/<svc_id>/delete", methods=["POST"])
def api_org_delete_service(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    db_update("services", {"id": svc_id},
              {"deleted_at": datetime.now(timezone.utc).isoformat(), "status": "closed"})
    return jsonify({"success": True}), 200

@app.route("/api/org/services/<svc_id>/restore", methods=["POST"])
def api_org_restore_service(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    db_update("services", {"id": svc_id}, {"deleted_at": None})
    return jsonify({"success": True}), 200

@app.route("/api/org/services/deleted")
def api_org_deleted_services():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    return jsonify(db_select("services",{"org_id":f"eq.{uid}","deleted_at":"not.is.null","order":"deleted_at.desc"})), 200

@app.route("/api/org/queue/<svc_id>")
def api_org_queue(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    entries = db_select("queue_entries",{"service_id":f"eq.{svc_id}",
                                          "status":"in.(waiting,called,serving)","order":"ticket_number.asc"})
    for e in entries:
        if e.get("user_id"):
            p = db_select("profiles",{"id":f"eq.{e['user_id']}"},single=True) or {}
            e["user_name"] = p.get("full_name") or p.get("email") or "User"
            e["user_online"] = p.get("is_online",False); e["user_phone"] = p.get("phone","")
        else:
            e["user_name"] = e.get("guest_name") or "Walk-in"
            e["user_online"] = False; e["user_phone"] = e.get("guest_phone","")
    return jsonify(entries), 200

@app.route("/api/org/queue/call-next/<svc_id>", methods=["POST"])
def api_org_call_next(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    waiting = db_select("queue_entries",{"service_id":f"eq.{svc_id}","status":"eq.waiting",
                                          "order":"ticket_number.asc","limit":"1"})
    if not waiting: return jsonify({"error": "No one waiting"}), 404
    entry = waiting[0]
    db_update("queue_entries",{"id":entry["id"]},
              {"status":"called","called_at":datetime.now(timezone.utc).isoformat()})
    entry["status"] = "called"
    if entry.get("user_id"):
        send_push_to_user(entry["user_id"],"📢 It's Your Turn!",
                          f"Ticket {entry['ticket_label']} — Please go to the counter now.",
                          {"type":"called","entry_id":entry["id"],"url":"/user"})
    if entry.get("guest_phone"):
        send_sms(entry["guest_phone"],
                 f"📢 QCode: Ticket {entry['ticket_label']} called! Come to the counter now.")
    return jsonify({"success": True, "entry": entry}), 200

@app.route("/api/org/queue/walk-in/<svc_id>", methods=["POST"])
def api_org_walk_in(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    d     = request.get_json() or {}
    name  = (d.get("name") or "Walk-in Customer").strip()
    phone = (d.get("phone") or "").strip() or None
    svcs  = db_select("services", {"id": f"eq.{svc_id}"})
    if not svcs: return jsonify({"error": "Service not found"}), 404
    svc  = svcs[0]
    n    = (svc.get("ticket_counter") or 0)+1
    label= f"{svc.get('ticket_prefix','Q')}{str(n).zfill(3)}"
    db_update("services",{"id":svc_id},{"ticket_counter":n})
    pos  = db_count("queue_entries",{"service_id":f"eq.{svc_id}","status":"eq.waiting"})+1
    eta  = (datetime.now(timezone.utc)+timedelta(minutes=pos*(svc.get("time_interval") or 5))).isoformat()
    end_code = _rcode(4)
    first_stage_id = None
    stages_list = db_select("stages",{"service_id":f"eq.{svc_id}","order":"order.asc"})
    if stages_list: first_stage_id = stages_list[0]["id"]
    required = {"service_id":svc_id,"user_id":None,"guest_name":name,"guest_phone":phone,
                "ticket_label":label,"ticket_number":n,"status":"waiting","estimated_time":eta,
                "join_method":"walk_in","joined_at":datetime.now(timezone.utc).isoformat()}
    optional = {"end_code":end_code,"pushback_count":0,"stage_id":first_stage_id}
    res = db_insert("queue_entries", _safe_payload("queue_entries", required, optional))
    if not res["ok"]: return jsonify({"error": "Failed to add walk-in."}), 500
    entry = res["data"][0] if isinstance(res["data"],list) else res["data"]
    entry["position"] = pos; entry["end_code"] = end_code
    if phone:
        send_sms(phone, f"QCode Walk-In: Ticket {label} | #{pos} | ~{pos*(svc.get('time_interval') or 5)} min. End code: {end_code}")
    return jsonify({"success": True, "entry": entry}), 201

@app.route("/api/org/queue/move-ticket/<svc_id>", methods=["POST"])
def api_org_move_ticket(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    d = request.get_json() or {}
    ticket_label = (d.get("ticket_label") or "").strip().upper()
    new_pos      = int(d.get("position") or 1)
    rows = db_select("queue_entries",{"service_id":f"eq.{svc_id}","ticket_label":f"eq.{ticket_label}","status":"eq.waiting"})
    if not rows: return jsonify({"error": f"Ticket {ticket_label} not found in waiting queue."}), 404
    waiting = db_select("queue_entries",{"service_id":f"eq.{svc_id}","status":"eq.waiting","order":"ticket_number.asc"})
    target_num = waiting[new_pos-2]["ticket_number"]-1 if new_pos>1 and len(waiting)>=new_pos-1 else 0
    db_update("queue_entries",{"id":rows[0]["id"]},{"ticket_number":target_num})
    return jsonify({"success": True}), 200

@app.route("/api/org/queue/entry/<entry_id>", methods=["POST"])
def api_org_update_entry(entry_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    status = (request.get_json() or {}).get("status")
    if status not in ("serving","completed","no_show","waiting","called","cancelled"):
        return jsonify({"error": "Invalid status"}), 400
    upd = {"status": status}
    if status in ("completed","no_show","cancelled"):
        upd["completed_at"] = datetime.now(timezone.utc).isoformat()
    db_update("queue_entries",{"id":entry_id},upd)
    if status == "completed":
        rows = db_select("queue_entries",{"id":f"eq.{entry_id}"})
        if rows and rows[0].get("user_id"):
            send_push_to_user(rows[0]["user_id"],"✅ Service Complete!",
                              "You've been served. Please rate your experience.",
                              {"type":"completed","entry_id":entry_id,"url":"/user"})
    return jsonify({"success": True}), 200

@app.route("/api/org/report/<svc_id>")
def api_org_report(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    return jsonify(db_select("queue_entries",{"service_id":f"eq.{svc_id}",
                                               "status":"in.(completed,no_show,cancelled)",
                                               "order":"ticket_number.desc","limit":"200"})), 200

@app.route("/api/org/analytics")
def api_org_analytics():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization": return jsonify({"error": "Unauthorized"}), 403
    svc_id  = request.args.get("service_id","")
    today_s = datetime.now(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0).isoformat()
    if svc_id:
        base_f = {"service_id":f"eq.{svc_id}","joined_at":f"gte.{today_s}"}
        wait_f = {"service_id":f"eq.{svc_id}","status":"eq.waiting"}
    else:
        org_svcs = db_select("services",{"org_id":f"eq.{uid}","deleted_at":"is.null"})
        if not org_svcs:
            return jsonify({"served_today":0,"waiting_now":0,"avg_wait_min":0,"no_shows_today":0,
                            "avg_rating":None,"throughput_per_hr":0,"peak_hours":[],"feedback":[]}), 200
        ids = ",".join(s["id"] for s in org_svcs)
        base_f = {"service_id":f"in.({ids})","joined_at":f"gte.{today_s}"}
        wait_f = {"service_id":f"in.({ids})","status":"eq.waiting"}
    served   = db_count("queue_entries",{**base_f,"status":"eq.completed"})
    waiting  = db_count("queue_entries",wait_f)
    no_shows = db_count("queue_entries",{**base_f,"status":"eq.no_show"})
    completed_entries = db_select("queue_entries",{**base_f,"status":"eq.completed"})
    waits = []
    for e in completed_entries:
        try:
            j = datetime.fromisoformat(e["joined_at"].replace("Z","+00:00"))
            c = datetime.fromisoformat(e["completed_at"].replace("Z","+00:00"))
            waits.append((c-j).total_seconds()/60)
        except: pass
    avg_wait = round(sum(waits)/len(waits)) if waits else 0
    fb_f = {}
    if svc_id: fb_f["service_id"] = f"eq.{svc_id}"
    feedbacks = db_select("feedbacks",{**fb_f,"created_at":f"gte.{today_s}"})
    ratings   = [f["rating"] for f in feedbacks if f.get("rating")]
    avg_rating= round(sum(ratings)/len(ratings),1) if ratings else None
    throughput  = round(served/max(1,datetime.now(timezone.utc).hour+1),1)
    all_today   = db_select("queue_entries",base_f)
    hour_counts = {}
    for e in all_today:
        try:
            h = datetime.fromisoformat(e["joined_at"].replace("Z","+00:00")).hour
            hour_counts[h] = hour_counts.get(h,0)+1
        except: pass
    return jsonify({"served_today":served,"waiting_now":waiting,"avg_wait_min":avg_wait,
                    "no_shows_today":no_shows,"avg_rating":avg_rating,"throughput_per_hr":throughput,
                    "peak_hours":[{"hour":h,"count":c} for h,c in sorted(hour_counts.items())],
                    "feedback":feedbacks[-10:][::-1]}), 200


# ══════════════════════════════════════════════════════════════
#  STAFF APIs
# ══════════════════════════════════════════════════════════════
@app.route("/api/staff/access", methods=["POST"])
def api_staff_access():
    d          = request.get_json() or {}
    stage_code = (d.get("stage_code") or "").strip().upper()
    staff_name = (d.get("staff_name") or "").strip()
    pin        = (d.get("pin") or "").strip()
    if not stage_code or not staff_name or not pin:
        return jsonify({"error": "Stage code, name and PIN are required."}), 400
    stages = db_select("stages", {"stage_code": f"eq.{stage_code}"})
    if not stages:
        svcs = db_select("services", {"service_code": f"eq.{stage_code}"})
        if not svcs: return jsonify({"error": "Invalid stage code."}), 404
        svc = svcs[0]
        stored = svc.get("staff_pin") or svc.get("end_code","")
        if stored and stored != pin: return jsonify({"error": "Incorrect PIN."}), 401
        return jsonify({"success":True,"stage_id":svc["id"],"stage_name":svc["name"],
                        "service_id":svc["id"],"service_name":svc["name"],
                        "service_code":svc["service_code"],"staff_name":staff_name,
                        "counter_id":None,"counter_number":1,"time_interval":svc.get("time_interval",5)}), 200
    stage = stages[0]
    stored_pin = stage.get("staff_pin","")
    if stored_pin and stored_pin != pin: return jsonify({"error": "Incorrect PIN."}), 401
    counters = db_select("staff_counters",{"stage_id":f"eq.{stage['id']}","staff_name":f"eq.{staff_name}"})
    if not counters:
        existing = db_select("staff_counters",{"stage_id":f"eq.{stage['id']}"})
        db_insert("staff_counters",_safe_payload("staff_counters",
            {"stage_id":stage["id"],"service_id":stage["service_id"],"staff_name":staff_name,
             "counter_number":len(existing)+1,"is_active":True,
             "created_at":datetime.now(timezone.utc).isoformat()},{}))
        counters = db_select("staff_counters",{"stage_id":f"eq.{stage['id']}","staff_name":f"eq.{staff_name}"})
    ctr  = counters[0] if counters else {}
    svcs = db_select("services",{"id":f"eq.{stage['service_id']}"})
    svc  = svcs[0] if svcs else {}
    db_update("staff_counters",{"id":ctr.get("id","x")},
              {"is_active":True,"last_seen":datetime.now(timezone.utc).isoformat()})
    return jsonify({"success":True,"stage_id":stage["id"],"stage_name":stage.get("name",""),
                    "service_id":stage["service_id"],"service_name":svc.get("name",""),
                    "service_code":svc.get("service_code",""),"staff_name":staff_name,
                    "counter_id":ctr.get("id"),"counter_number":ctr.get("counter_number",1),
                    "time_interval":stage.get("time_interval") or svc.get("time_interval",5)}), 200

@app.route("/api/staff/queue/<stage_id>")
def api_staff_queue(stage_id):
    stages = db_select("stages",{"id":f"eq.{stage_id}"})
    svc_id = stages[0]["service_id"] if stages else stage_id
    entries = db_select("queue_entries",{"service_id":f"eq.{svc_id}",
                                          "status":"in.(waiting,called,serving)","order":"ticket_number.asc"})
    for e in entries:
        if e.get("user_id"):
            p = db_select("profiles",{"id":f"eq.{e['user_id']}"},single=True) or {}
            e["user_name"] = p.get("full_name") or "User"
        else:
            e["user_name"] = e.get("guest_name") or "Walk-in"
    return jsonify(entries), 200

@app.route("/api/staff/call-next", methods=["POST"])
def api_staff_call_next():
    d = request.get_json() or {}
    stage_id = d.get("stage_id")
    if not stage_id: return jsonify({"error": "stage_id required"}), 400
    stages = db_select("stages",{"id":f"eq.{stage_id}"})
    svc_id = stages[0]["service_id"] if stages else stage_id
    waiting = db_select("queue_entries",{"service_id":f"eq.{svc_id}","status":"eq.waiting",
                                          "order":"ticket_number.asc","limit":"1"})
    if not waiting: return jsonify({"error": "No one waiting"}), 404
    entry = waiting[0]
    db_update("queue_entries",{"id":entry["id"]},
              {"status":"called","called_at":datetime.now(timezone.utc).isoformat()})
    if entry.get("user_id"):
        send_push_to_user(entry["user_id"],"📢 Your Turn!",
                          f"Ticket {entry['ticket_label']} — Come to the counter.",
                          {"type":"called","entry_id":entry["id"],"url":"/user"})
    if entry.get("guest_phone"):
        send_sms(entry["guest_phone"],
                 f"📢 QCode: Ticket {entry['ticket_label']} called! Come to the counter now.")
    return jsonify({"success":True,"entry":entry}), 200

@app.route("/api/staff/mark-done", methods=["POST"])
def api_staff_mark_done():
    d = request.get_json() or {}
    entry_id = d.get("entry_id"); status = d.get("status","completed")
    if not entry_id: return jsonify({"error":"entry_id required"}), 400
    if status not in ("completed","no_show","serving"): return jsonify({"error":"Invalid status"}), 400
    upd = {"status":status}
    if status in ("completed","no_show"): upd["completed_at"] = datetime.now(timezone.utc).isoformat()
    db_update("queue_entries",{"id":entry_id},upd)
    if status == "completed":
        rows = db_select("queue_entries",{"id":f"eq.{entry_id}"})
        if rows:
            entry    = rows[0]
            svc_id   = entry.get("service_id")
            stage_id = entry.get("stage_id")
            if svc_id and stage_id:
                cur = db_select("stages",{"id":f"eq.{stage_id}"})
                if cur:
                    nxt = db_select("stages",{"service_id":f"eq.{svc_id}","order":f"eq.{cur[0].get('order',1)+1}"})
                    if nxt:
                        pos = db_count("queue_entries",{"service_id":f"eq.{svc_id}",
                                                         "stage_id":f"eq.{nxt[0]['id']}","status":"eq.waiting"})+1
                        eta = (datetime.now(timezone.utc)+timedelta(minutes=pos*nxt[0].get("time_interval",5))).isoformat()
                        new_req = {"service_id":svc_id,"user_id":entry.get("user_id"),
                                   "guest_name":entry.get("guest_name"),"guest_phone":entry.get("guest_phone"),
                                   "ticket_label":entry.get("ticket_label",""),
                                   "ticket_number":entry.get("ticket_number",0),
                                   "status":"waiting","estimated_time":eta,
                                   "join_method":entry.get("join_method","web"),
                                   "joined_at":datetime.now(timezone.utc).isoformat()}
                        db_insert("queue_entries",_safe_payload("queue_entries",new_req,
                            {"end_code":entry.get("end_code"),"stage_id":nxt[0]["id"],"pushback_count":0}))
                        if entry.get("user_id"):
                            send_push_to_user(entry["user_id"],f"➡️ Next: {nxt[0]['name']}",
                                              f"You've been moved to {nxt[0]['name']}. Position #{pos}.",
                                              {"type":"next_stage","stage_name":nxt[0]["name"],"url":"/user"})
                    else:
                        # Last stage done → notify for feedback
                        if entry.get("user_id"):
                            send_push_to_user(entry["user_id"],"✅ All Done!",
                                              "Your visit is complete. Please rate your experience.",
                                              {"type":"completed","entry_id":entry_id,"url":"/user"})
    return jsonify({"success":True}), 200


# ══════════════════════════════════════════════════════════════
#  AI FAQ (unified route — one model, one endpoint)
# ══════════════════════════════════════════════════════════════
@app.route("/api/ai/faq", methods=["POST"])
@app.route("/api/ai/chat", methods=["POST"])
def ai_faq():
    d        = request.get_json() or {}
    messages = d.get("messages") or []
    # Support both formats: {messages:[]} and {message:""}
    if not messages and d.get("message"):
        messages = [{"role":"user","content":d["message"]}]
    if not messages: return jsonify({"error": "No messages provided"}), 400
    system_prompt = d.get("system") or (
        "You are QCode Assistant — the AI helper for QCode, a digital queue management platform in Nigeria. "
        "QCode lets users join queues by entering a 6-character service code at qcode.onrender.com. "
        "Features: real-time position tracking, multi-stage queues (Entry → Shopping → Checkout → Packing), "
        "Ready to Checkout button, smart counter assignment, push notifications, SMS joining, "
        "automated pushback after 3 missed calls, staff counter pages, organization dashboards. "
        "Be concise, friendly and helpful. If the user writes in Yoruba, Hausa or Pidgin, respond in kind."
    )
    try:
        client   = get_groq()
        # Try the faster model first, fallback to 70b if needed
        try:
            response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[{"role":"system","content":system_prompt},*messages[-20:]],
                max_tokens=600, temperature=0.7)
        except Exception:
            response = client.chat.completions.create(
                model="llama3-8b-8192",
                messages=[{"role":"system","content":system_prompt},*messages[-20:]],
                max_tokens=600, temperature=0.7)
        reply = response.choices[0].message.content
        return jsonify({"response": reply, "reply": reply}), 200
    except Exception as e:
        print(f"[Groq Error] {e}")
        return jsonify({"error": "AI service temporarily unavailable. Please try again shortly."}), 500


# ══════════════════════════════════════════════════════════════
#  ADMIN APIs
# ══════════════════════════════════════════════════════════════
def require_admin(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if session.get("role") != "super_admin": return jsonify({"error": "Unauthorized"}), 403
        return f(*a, **kw)
    return wrapper

@app.route("/api/admin/stats")
@require_admin
def api_admin_stats():
    return jsonify({"total_orgs":db_count("profiles",{"role":"eq.organization"}),
                    "approved_orgs":db_count("profiles",{"role":"eq.organization","approval_status":"eq.approved"}),
                    "pending_orgs":db_count("profiles",{"role":"eq.organization","approval_status":"eq.pending"}),
                    "total_users":db_count("profiles",{"role":"eq.user"}),
                    "total_served":db_count("queue_entries",{"status":"eq.completed"})}), 200

@app.route("/api/admin/orgs")
@require_admin
def api_admin_orgs():
    return jsonify(db_select("profiles",{"role":"eq.organization","order":"created_at.desc"})), 200

@app.route("/api/admin/users")
@require_admin
def api_admin_users():
    return jsonify(db_select("profiles",{"role":"eq.user","order":"created_at.desc"})), 200

@app.route("/api/admin/approve-org", methods=["POST"])
@require_admin
def api_approve_org():
    org_id = (request.get_json() or {}).get("org_id")
    if not org_id: return jsonify({"error": "org_id required"}), 400
    db_update("profiles",{"id":org_id},{"approval_status":"approved"})
    # SEND APPROVAL EMAIL
    org = db_select("profiles",{"id":f"eq.{org_id}"},single=True) or {}
    if org.get("email") and org.get("org_name"):
        ok = send_approval_email(org["email"], org["org_name"])
        if not ok:
            print(f"[Approval Email] Failed to send to {org['email']}")
    return jsonify({"success":True}), 200

@app.route("/api/admin/reject-org", methods=["POST"])
@require_admin
def api_reject_org():
    d = request.get_json() or {}
    org_id = d.get("org_id"); reason = (d.get("reason") or "").strip()
    if not org_id or not reason: return jsonify({"error":"org_id and reason required"}), 400
    db_update("profiles",{"id":org_id},{"approval_status":"suspended","rejection_reason":reason})
    return jsonify({"success":True}), 200

@app.route("/api/admin/suspend-org", methods=["POST"])
@require_admin
def api_suspend_org():
    org_id = (request.get_json() or {}).get("org_id")
    if not org_id: return jsonify({"error":"org_id required"}), 400
    db_update("profiles",{"id":org_id},{"approval_status":"suspended"})
    return jsonify({"success":True}), 200

@app.route("/api/admin/reinstate-org", methods=["POST"])
@require_admin
def api_reinstate_org():
    org_id = (request.get_json() or {}).get("org_id")
    if not org_id: return jsonify({"error":"org_id required"}), 400
    db_update("profiles",{"id":org_id},{"approval_status":"approved","rejection_reason":None})
    return jsonify({"success":True}), 200

@app.route("/api/admin/ban-user", methods=["POST"])
@require_admin
def api_ban_user():
    user_id = (request.get_json() or {}).get("user_id")
    if not user_id: return jsonify({"error":"user_id required"}), 400
    db_update("profiles",{"id":user_id},{"approval_status":"suspended"})
    return jsonify({"success":True}), 200

@app.route("/api/admin/analytics")
@require_admin
def admin_analytics():
    return jsonify({"total_orgs":db_count("profiles",{"role":"eq.organization"}),
                    "approved_orgs":db_count("profiles",{"role":"eq.organization","approval_status":"eq.approved"}),
                    "pending_orgs":db_count("profiles",{"role":"eq.organization","approval_status":"eq.pending"}),
                    "total_users":db_count("profiles",{"role":"eq.user"}),
                    "total_served":db_count("queue_entries",{"status":"eq.completed"})}), 200

@app.route("/api/admin/all-queues")
@require_admin
def api_admin_all_queues():
    org_id = request.args.get("org_id","")
    filters = {"order":"joined_at.desc","limit":"200"}
    if org_id:
        svcs = db_select("services",{"org_id":f"eq.{org_id}"})
        ids  = ",".join(s["id"] for s in svcs)
        if ids: filters["service_id"] = f"in.({ids})"
        else: return jsonify([]), 200
    entries = db_select("queue_entries",filters); sc={}; uc={}
    for e in entries:
        sid = e.get("service_id")
        if sid and sid not in sc:
            s = db_select("services",{"id":f"eq.{sid}"})
            if s:
                org = db_select("profiles",{"id":f"eq.{s[0]['org_id']}"},single=True) or {}
                sc[sid] = {"svc_name":s[0].get("name",""),"svc_code":s[0].get("service_code",""),"org_name":org.get("org_name","")}
        if sid in sc: e.update(sc[sid])
        uid2 = e.get("user_id")
        if uid2 and uid2 not in uc:
            p = db_select("profiles",{"id":f"eq.{uid2}"},single=True) or {}
            uc[uid2] = p.get("full_name") or p.get("email") or "User"
        e["user_name"] = uc.get(uid2,"User") if uid2 else (e.get("guest_name") or "Walk-in")
    return jsonify(entries), 200

@app.route("/api/admin/all-services")
@require_admin
def api_admin_all_services():
    svcs = db_select("services",{"deleted_at":"is.null","order":"created_at.desc"})
    for s in svcs:
        org = db_select("profiles",{"id":f"eq.{s['org_id']}"},single=True) or {}
        s["org_name"]  = org.get("org_name","")
        s["total"]     = db_count("queue_entries",{"service_id":f"eq.{s['id']}"})
        s["waiting"]   = db_count("queue_entries",{"service_id":f"eq.{s['id']}","status":"eq.waiting"})
        s["completed"] = db_count("queue_entries",{"service_id":f"eq.{s['id']}","status":"eq.completed"})
    return jsonify(svcs), 200

@app.route("/api/admin/sms-joins")
@require_admin
def api_admin_sms_joins():
    rows = db_select("sms_joins",{"order":"created_at.desc","limit":"100"})
    for r in rows:
        eid = r.get("queue_entry_id")
        if eid:
            entries = db_select("queue_entries",{"id":f"eq.{eid}"})
            if entries:
                r["ticket_label"] = entries[0].get("ticket_label","—")
                r["entry_status"] = entries[0].get("status","—")
    return jsonify(rows), 200

@app.route("/api/admin/logs")
@require_admin
def api_admin_logs():
    return jsonify(db_select("admin_logs",{"order":"created_at.desc","limit":"100"})), 200

@app.route("/api/admin/log-action", methods=["POST"])
@require_admin
def api_admin_log_action():
    d = request.get_json() or {}
    db_insert("admin_logs",{"admin_id":session.get("user_id"),"action":d.get("action",""),
                             "target_id":d.get("target_id",""),"target_type":d.get("target_type",""),
                             "details":json.dumps(d.get("details") or {})})
    return jsonify({"success":True}), 200


# ══════════════════════════════════════════════════════════════
#  SMS WEBHOOK
# ══════════════════════════════════════════════════════════════
@app.route("/api/sms/receive", methods=["POST"])
def receive_sms():
    payload = request.get_json() or {} if request.is_json else request.form.to_dict()
    from_phone   = (payload.get("phoneNumber") or payload.get("from") or payload.get("From") or
                    payload.get("sender") or payload.get("msisdn") or "Unknown")
    message_body = (payload.get("message") or payload.get("text") or payload.get("Text") or
                    payload.get("Body") or payload.get("body") or "").strip()
    if not message_body: return "", 200
    if message_body.upper().strip() == "CHECKOUT":
        entries = db_select("queue_entries",{"guest_phone":f"eq.{from_phone}","status":"eq.waiting",
                                              "order":"joined_at.desc","limit":"1"})
        if entries:
            db_update("queue_entries",{"id":entries[0]["id"]},
                      {"status":"called","called_at":datetime.now(timezone.utc).isoformat()})
            send_sms(from_phone,f"QCode: {entries[0].get('ticket_label','—')} marked ready for checkout.")
        return "",200
    code_match = re.search(r'\b(QC[-\s]?[A-Z0-9]{6})\b', message_body.upper())
    if not code_match:
        bare = re.search(r'\b([A-Z0-9]{5,8})\b', message_body.upper())
        if bare:
            service_code = bare.group(1)
            name_part    = re.sub(r'\b'+bare.group(1)+r'\b','',message_body,flags=re.IGNORECASE).strip()
        else:
            _log_sms(from_phone,message_body,None,None,"invalid_code")
            send_sms(from_phone,"Invalid code. Text your QCode service code to join."); return "",200
    else:
        raw          = code_match.group(1).replace(" ","-")
        service_code = raw if raw.startswith("QC-") else "QC-"+raw[-6:]
        name_part    = re.sub(r'\b'+re.escape(code_match.group(1))+r'\b','',message_body,flags=re.IGNORECASE).strip()
    guest_name = name_part.title() if name_part else f"SMS User ({from_phone[-4:]})"
    try:
        svcs = db_select("services",{"service_code":f"eq.{service_code}","status":"eq.open"})
        if not svcs:
            _log_sms(from_phone,message_body,service_code,None,"invalid_code")
            send_sms(from_phone,f"Code '{service_code}' not found or queue is closed."); return "",200
        service = svcs[0]; svc_id = service["id"]
        max_u   = service.get("max_users") or 9999
        current = db_count("queue_entries",{"service_id":f"eq.{svc_id}","status":"in.(waiting,called,serving)"})
        if current >= max_u:
            _log_sms(from_phone,message_body,service_code,None,"failed")
            send_sms(from_phone,f"Sorry, {service['name']} queue is full."); return "",200
        n     = (service.get("ticket_counter") or 0)+1
        label = f"{service.get('ticket_prefix','Q')}{str(n).zfill(3)}"
        db_update("services",{"id":svc_id},{"ticket_counter":n})
        pos      = current+1; wait_min = pos*(service.get("time_interval") or 5)
        eta      = (datetime.now(timezone.utc)+timedelta(minutes=wait_min)).isoformat()
        eta_time = (datetime.now(timezone.utc)+timedelta(minutes=wait_min)).strftime("%I:%M %p")
        end_code = _rcode(4)
        first_stage_id = None
        sl = db_select("stages",{"service_id":f"eq.{svc_id}","order":"order.asc"})
        if sl: first_stage_id = sl[0]["id"]
        required = {"service_id":svc_id,"user_id":None,"guest_name":guest_name,"guest_phone":from_phone,
                    "ticket_label":label,"ticket_number":n,"status":"waiting","estimated_time":eta,
                    "join_method":"sms","joined_at":datetime.now(timezone.utc).isoformat()}
        optional = {"end_code":end_code,"pushback_count":0,"stage_id":first_stage_id}
        res      = db_insert("queue_entries",_safe_payload("queue_entries",required,optional))
        entry_id = res["data"][0]["id"] if res.get("ok") and res["data"] else None
        _log_sms(from_phone,message_body,service_code,entry_id,"processed")
        org = db_select("profiles",{"id":f"eq.{service['org_id']}"},single=True) or {}
        send_sms(from_phone,
                 f"QCode ✅\nService: {service['name']} @ {org.get('org_name','')}\n"
                 f"Ticket: {label}\nPosition: #{pos} | ~{wait_min} mins (~{eta_time})\n"
                 f"Reply CHECKOUT when ready to check out.")
        return "",200
    except Exception as e:
        print(f"[SMS Error] {e}")
        _log_sms(from_phone,message_body,service_code,None,"failed")
        send_sms(from_phone,"Something went wrong. Please try again."); return "",200


# ══════════════════════════════════════════════════════════════
#  GUEST APIs
# ══════════════════════════════════════════════════════════════
@app.route("/api/guest/queue-status/<entry_id>")
def api_guest_queue_status(entry_id):
    rows = db_select("queue_entries",{"id":f"eq.{entry_id}"})
    if not rows: return jsonify({"error":"Not found"}),404
    entry = rows[0]
    ahead = db_count("queue_entries",{"service_id":f"eq.{entry['service_id']}","status":"eq.waiting",
                                       "ticket_number":f"lt.{entry['ticket_number']}"})
    total = db_count("queue_entries",{"service_id":f"eq.{entry['service_id']}","status":"eq.waiting"})
    svcs  = db_select("services",{"id":f"eq.{entry['service_id']}"}); svc = svcs[0] if svcs else {}
    eta_mins = max(0,(ahead+1)*(svc.get("time_interval") or 5))
    entry.update({"position":ahead+1,"ahead":ahead,"total":total,"eta_minutes":eta_mins,
                  "svc_name":svc.get("name",""),"svc_status":svc.get("status",""),
                  "time_interval":svc.get("time_interval",5),
                  "estimated_time":(datetime.now(timezone.utc)+timedelta(minutes=eta_mins)).isoformat()})
    return jsonify(entry), 200

@app.route("/api/guest/leave/<entry_id>", methods=["POST"])
def api_guest_leave(entry_id):
    rows = db_select("queue_entries",{"id":f"eq.{entry_id}"})
    if not rows: return jsonify({"error":"Not found"}),404
    db_update("queue_entries",{"id":entry_id},{"status":"cancelled","completed_at":datetime.now(timezone.utc).isoformat()})
    return jsonify({"success":True}), 200

@app.route("/api/guest/feedback", methods=["POST"])
def api_guest_feedback():
    d = request.get_json() or {}
    entry_id = d.get("entry_id"); rating = d.get("rating"); comment = (d.get("comment") or "").strip()
    if not entry_id or not rating: return jsonify({"error":"entry_id and rating required"}), 400
    db_insert("feedbacks",{"entry_id":entry_id,"user_id":None,"rating":int(rating),
                           "comment":comment or None,"created_at":datetime.now(timezone.utc).isoformat()})
    return jsonify({"success":True}), 201


# ══════════════════════════════════════════════════════════════
#  PUBLIC
# ══════════════════════════════════════════════════════════════
@app.route("/api/public/stats")
def api_public_stats():
    return jsonify({"approved_orgs":db_count("profiles",{"role":"eq.organization","approval_status":"eq.approved"}),
                    "total_served":db_count("queue_entries",{"status":"eq.completed"}),
                    "active_services":db_count("services",{"status":"eq.open","deleted_at":"is.null"})}), 200

@app.route("/api/notify/org", methods=["POST"])
def notify_org(): return jsonify({"sent": True})

@app.route("/health")
def health(): return jsonify({"status":"ok","time":datetime.now().isoformat()}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
