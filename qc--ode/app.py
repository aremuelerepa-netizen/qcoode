import os, re, json, random, base64, requests
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

SUPABASE_URL      = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
SUPABASE_KEY      = os.getenv("SUPABASE_KEY", "")
SUPABASE_STORAGE_BUCKET = os.getenv("SUPABASE_STORAGE_BUCKET", "org-logos")
SUPER_ADMIN_EMAIL    = os.getenv("SUPER_ADMIN_EMAIL", "admin@qcode.com").strip().lower()
SUPER_ADMIN_PASSWORD = os.getenv("SUPER_ADMIN_PASSWORD", "admin123").strip()
VAPID_PUBLIC_KEY  = os.getenv("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_CLAIM_EMAIL = os.getenv("VAPID_CLAIM_EMAIL", "admin@qcode.com")
SENDGRID_API_KEY  = os.getenv("SENDGRID_API_KEY", "")
SENDGRID_FROM     = os.getenv("SENDGRID_FROM_EMAIL", "noreply@qcode.com")

if not SUPABASE_URL or not SUPABASE_ANON_KEY or not SUPABASE_KEY:
    raise RuntimeError("Missing required env vars: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_KEY")

# ─── SCHEMA COLUMN CACHE ───────────────────────────────────────
_schema_cache: dict = {}

def _fetch_columns(table: str) -> set:
    if table in _schema_cache:
        return _schema_cache[table]
    try:
        h  = {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
        r2 = requests.get(f"{SUPABASE_URL}/rest/v1/{table}?limit=1",
                          headers={**h, "Accept": "application/json"}, timeout=10)
        cols = set()
        if r2.ok:
            rows = r2.json()
            if rows:
                cols = set(rows[0].keys())
            else:
                known = {
                    "queue_entries": {"id","service_id","user_id","guest_name","guest_phone",
                                      "ticket_label","ticket_number","status","join_method",
                                      "custom_form_data","end_code","estimated_time","joined_at",
                                      "called_at","completed_at","stage_id","counter_id",
                                      "batch_number","batch_open_time","pushback_count"},
                    "services":      {"id","org_id","name","description","staff_name","service_code",
                                      "ticket_prefix","ticket_counter","time_interval","max_users",
                                      "status","end_code","user_info_form","schedule_start",
                                      "schedule_end","queue_start","queue_end","break_times",
                                      "stages_enabled","batch_enabled","batch_size","batch_buffer_min",
                                      "next_service_group","service_group","is_entry","is_final",
                                      "has_free_time","deleted_at","created_at"},
                    "profiles":      {"id","role","full_name","org_name","email","phone",
                                      "company_address","logo_url","approval_status","rejection_reason",
                                      "preferred_lang","is_online","state","created_at"},
                    "stages":        {"id","service_id","name","order","time_interval","stage_code",
                                      "staff_names","staff_pin","counter_count","created_at"},
                    "staff_counters":{"id","stage_id","service_id","staff_name","counter_number",
                                      "is_active","last_seen","created_at"},
                    "push_subscriptions":{"id","user_id","endpoint","subscription_data",
                                          "created_at","updated_at"},
                    "feedbacks":     {"id","entry_id","service_id","user_id","rating","comment",
                                      "created_at"},
                    "password_resets":{"id","user_id","email","token","expires_at","used",
                                       "created_at"},
                    "sms_joins":     {"id","from_phone","message_body","service_code",
                                      "queue_entry_id","status","created_at"},
                    "admin_logs":    {"id","admin_id","action","target_id","target_type",
                                      "details","created_at"},
                }
                cols = known.get(table, set())
        _schema_cache[table] = cols
        return cols
    except Exception as e:
        print(f"[Schema Cache Error] {e}")
        return set()

def _safe_payload(table: str, required: dict, optional: dict) -> dict:
    existing = _fetch_columns(table)
    payload  = dict(required)
    for col, val in optional.items():
        if col in existing:
            payload[col] = val
    return payload

# ─── SMS CONFIG ────────────────────────────────────────────────
SMS_GATEWAY_NUMBER = os.getenv("SMS_GATEWAY_NUMBER", "+2349155189936")
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

def get_groq():
    import httpx
    from groq import Groq
    return Groq(api_key=os.getenv("GROQ_API_KEY", ""), http_client=httpx.Client())

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
                      headers={"apikey": SUPABASE_ANON_KEY,
                               "Authorization": f"Bearer {token}"}, timeout=5)
    except: pass

def db_insert(table, data):
    r = requests.post(f"{SUPABASE_URL}/rest/v1/{table}",
                      headers=_h_service(), json=data, timeout=15)
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
    h      = {**_h_service(), "Prefer": "count=exact"}
    params = {"select": "id"}
    if filters: params.update(filters)
    r = requests.head(f"{SUPABASE_URL}/rest/v1/{table}", headers=h, params=params, timeout=15)
    try: return int(r.headers.get("content-range","0/0").split("/")[1])
    except: return 0

def get_profile(user_id):
    return db_select("profiles", {"id": f"eq.{user_id}"}, single=True) or {}

def _rcode(n=6):
    return "".join(random.choices("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", k=n))

def send_sms(to_phone, message):
    if ANDROID_GW_URL:
        try:
            body = {"phoneNumbers": [to_phone], "message": message}
            if ANDROID_GW_DEVICE: body["simNumber"] = ANDROID_GW_DEVICE
            auth = (ANDROID_GW_LOGIN, ANDROID_GW_PASSWORD) if ANDROID_GW_LOGIN else None
            requests.post(ANDROID_GW_URL.rstrip("/")+"/api/3rdparty/v1/message",
                          json=body, auth=auth, timeout=10)
            return
        except Exception as e: print(f"[Android GW Error] {e}")
    if FALLBACK_SMS_URL:
        try:
            requests.post(FALLBACK_SMS_URL, data={
                FALLBACK_KEY_FLD: FALLBACK_SMS_KEY, FALLBACK_PHONE_FLD: to_phone,
                FALLBACK_MSG_FLD: message, "sender": SMS_SENDER_ID}, timeout=10)
            return
        except Exception as e: print(f"[Fallback SMS Error] {e}")
    print(f"[SMS] To: {to_phone}\n{message}")

def _log_sms(from_phone, message_body, service_code, entry_id, status):
    try:
        db_insert("sms_joins", {"from_phone": from_phone, "message_body": message_body,
                                "service_code": service_code, "queue_entry_id": entry_id,
                                "status": status,
                                "created_at": datetime.now(timezone.utc).isoformat()})
    except Exception as e: print(f"[Log Error] {e}")

def send_push_notification(subscription_data, title, body, data=None):
    try:
        from pywebpush import webpush, WebPushException
        webpush(
            subscription_info=subscription_data,
            data=json.dumps({"title": title, "body": body, "data": data or {}}),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={"sub": f"mailto:{VAPID_CLAIM_EMAIL}"}
        )
        return True
    except Exception as e:
        print(f"[Push Error] {e}")
        return False

def send_push_to_user(user_id, title, body, data=None):
    if not VAPID_PRIVATE_KEY:
        return
    subs = db_select("push_subscriptions", {"user_id": f"eq.{user_id}"})
    for sub in subs:
        try:
            sub_data = sub.get("subscription_data")
            if isinstance(sub_data, str):
                sub_data = json.loads(sub_data)
            if sub_data:
                send_push_notification(sub_data, title, body, data)
        except Exception as e:
            print(f"[Push User Error] {e}")

def send_email_reset(to_email, reset_link, is_org=False):
    if not SENDGRID_API_KEY:
        print(f"[Reset Email] To: {to_email} Link: {reset_link}")
        return True
    try:
        role_label = "Organization" if is_org else "Account"
        r = requests.post("https://api.sendgrid.com/v3/mail/send",
            headers={"Authorization": f"Bearer {SENDGRID_API_KEY}",
                     "Content-Type": "application/json"},
            json={
                "personalizations": [{"to": [{"email": to_email}]}],
                "from": {"email": SENDGRID_FROM, "name": "QCode"},
                "subject": f"Reset your QCode {role_label} password",
                "content": [{"type": "text/html", "value":
                    f"""<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:2rem">
                    <h2 style="color:#4361ee">QCode Password Reset</h2>
                    <p>We received a request to reset your password for <strong>{to_email}</strong>.</p>
                    <p>Click the button below to set a new password. This link expires in <strong>1 hour</strong>.</p>
                    <a href="{reset_link}" style="display:inline-block;background:#4361ee;color:#fff;padding:.875rem 2rem;border-radius:.75rem;text-decoration:none;font-weight:700;margin:1rem 0">Reset Password →</a>
                    <p style="color:#8892a4;font-size:.85rem">If you didn't request this, ignore this email. Your password won't change.</p>
                    </div>"""
                }]
            }, timeout=15)
        return r.ok
    except Exception as e:
        print(f"[SendGrid Error] {e}")
        return False

# ─── NEXT SERVICE HELPER ───────────────────────────────────────
def _get_next_service(entry, next_group):
    """
    Safely find the least busy open service in next_group,
    STRICTLY within the same org as the entry's current service.

    Always hard-filters by org_id — never falls through to cross-org
    results even if lookups are slow or return partial data.

    Returns (service_dict, None) on success.
    Returns (None, error_string) on failure.
    """
    # Step 1 — resolve org_id from current service, hard-fail if missing
    if not entry.get("service_id"):
        return None, "Entry has no service_id"
    svc_rows = db_select("services", {"id": f"eq.{entry['service_id']}"})
    if not svc_rows:
        return None, "Current service not found"
    org_id = svc_rows[0].get("org_id")
    if not org_id:
        return None, "Could not verify organization — cannot proceed"

    # Step 2 — find open services in next_group WITHIN same org only
    # org_id filter is ALWAYS applied — never optional
    svcs = db_select("services", {
        "service_group": f"eq.{next_group}",
        "org_id":        f"eq.{org_id}",
        "status":        "eq.open",
        "deleted_at":    "is.null",
    })
    if not svcs:
        return None, f"No open services available for the next step. Please ask staff for help."

    # Step 3 — pick the least busy service in the group
    # (handles multiple counters / load balancing within same org)
    def _waiting_count(s):
        return db_count("queue_entries", {
            "service_id": f"eq.{s['id']}",
            "status":     "in.(waiting,called,serving)",
        })

    best_svc   = None
    best_count = 999999
    for s in svcs:
        c = _waiting_count(s)
        if c < best_count:
            best_count = c
            best_svc   = s

    if not best_svc:
        return None, "No available service found in next step"

    return best_svc, None


def _create_next_entry(entry, best_svc, uid=None):
    """
    Create a new queue_entries row for a customer moving to the next service.
    ETA is always anchored to NOW + position × time_interval.
    Position = number of people already waiting/called/serving in that service + 1.

    Returns (new_entry_dict, None) on success.
    Returns (None, error_string) on failure.
    """
    svc_id = best_svc["id"]

    # Count current load — this becomes the new customer's position
    current = db_count("queue_entries", {
        "service_id": f"eq.{svc_id}",
        "status":     "in.(waiting,called,serving)",
    })
    pos       = current + 1
    interval  = best_svc.get("time_interval") or 5

    # ETA = NOW + position × interval
    # If first person → pos=1 → ETA = NOW + 1 interval
    # If 3 people already there → pos=4 → ETA = NOW + 4 intervals
    eta_t = (datetime.now(timezone.utc) + timedelta(minutes=pos * interval)).isoformat()

    # New ticket number
    n     = (best_svc.get("ticket_counter") or 0) + 1
    label = f"{best_svc.get('ticket_prefix','A')}{str(n).zfill(3)}"
    db_update("services", {"id": svc_id}, {"ticket_counter": n})

    required = {
        "service_id":    svc_id,
        "user_id":       uid or entry.get("user_id"),
        "guest_name":    entry.get("guest_name"),
        "guest_phone":   entry.get("guest_phone"),
        "ticket_label":  label,
        "ticket_number": n,
        "status":        "waiting",
        "estimated_time": eta_t,
        "join_method":   entry.get("join_method", "web"),
        "joined_at":     datetime.now(timezone.utc).isoformat(),
    }
    optional = {
        "end_code":         entry.get("end_code") or _rcode(4),
        "pushback_count":   0,
        "custom_form_data": entry.get("custom_form_data") or {},
    }
    res = db_insert("queue_entries", _safe_payload("queue_entries", required, optional))
    if not res["ok"]:
        err = res["data"].get("message","") if isinstance(res["data"], dict) else str(res["data"])
        return None, f"Failed to join next service: {err}"

    new_entry = res["data"][0] if isinstance(res["data"], list) else res["data"]
    new_entry["position"]      = pos
    new_entry["svc_name"]      = best_svc.get("name","")
    new_entry["time_interval"] = interval
    return new_entry, None


# ─── PAGE ROUTES ───────────────────────────────────────────────
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

# ─── SESSION ───────────────────────────────────────────────────
@app.route("/api/auth/me")
def api_me():
    if not session.get("user_id"): return jsonify({"logged_in": False}), 200
    return jsonify({"logged_in": True, "user_id": session["user_id"],
                    "role": session.get("role"), "email": session.get("email"),
                    "full_name": session.get("full_name"),
                    "org_name": session.get("org_name")}), 200

# ─── REGISTER USER ─────────────────────────────────────────────
@app.route("/api/auth/register-user", methods=["POST"])
@app.route("/api/register-user",      methods=["POST"])
def register_user():
    d         = request.get_json() or {}
    full_name = (d.get("full_name") or "").strip()
    email     = (d.get("email")     or "").strip().lower()
    password  = (d.get("password")  or "")
    phone     = (d.get("phone")     or "").strip()
    if not full_name or not email or not password:
        return jsonify({"error": "Name, email and password are required."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    result = admin_create_user(email, password)
    uid    = result.get("id")
    if not uid:
        msg = result.get("message") or result.get("msg") or result.get("error_description") or str(result)
        if "already" in msg.lower():
            return jsonify({"error": "An account with this email already exists."}), 400
        return jsonify({"error": f"Registration failed: {msg}"}), 400
    ins = db_insert("profiles", {"id": uid, "role": "user", "full_name": full_name,
                                  "email": email, "phone": phone or None,
                                  "approval_status": "approved", "is_online": False})
    if not ins["ok"]:
        return jsonify({"error": "Account created but profile save failed."}), 500
    return jsonify({"success": True, "message": "Account created! You can now log in."}), 201

# ─── AI FAQ ────────────────────────────────────────────────────
@app.route("/api/ai/faq", methods=["POST"])
def ai_faq():
    d             = request.get_json() or {}
    messages      = d.get("messages", [])
    system_prompt = d.get("system", "You are QCode Assistant, a helpful queue management AI.")
    if not messages: return jsonify({"error": "No messages"}), 400
    try:
        client   = get_groq()
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": system_prompt}, *messages],
            max_tokens=600, temperature=0.7
        )
        return jsonify({"response": response.choices[0].message.content})
    except Exception as e:
        print(f"Groq error: {e}")
        return jsonify({"error": "AI service unavailable."}), 500

# ─── REGISTER ORG ──────────────────────────────────────────────
@app.route("/api/auth/register-org", methods=["POST"])
@app.route("/api/register-org",      methods=["POST"])
def register_org():
    ct = (request.content_type or "").lower()
    if "multipart" in ct or "form" in ct:
        org_name = (request.form.get("org_name") or "").strip()
        email    = (request.form.get("email")    or "").strip().lower()
        password = (request.form.get("password") or "")
        phone    = (request.form.get("org_phone")   or "").strip()
        address  = (request.form.get("org_address") or "").strip()
        org_type = (request.form.get("org_type")    or "").strip()
    else:
        d = request.get_json() or {}
        org_name = (d.get("org_name") or "").strip()
        email    = (d.get("email")    or "").strip().lower()
        password = (d.get("password") or "")
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
        msg = result.get("message") or result.get("msg") or result.get("error_description") or str(result)
        if "already" in msg.lower():
            return jsonify({"error": "An account with this email already exists."}), 400
        return jsonify({"error": f"Registration failed: {msg}"}), 400
    address_full = " | ".join(filter(None, [org_type, address])) or None
    ins = db_insert("profiles", {"id": uid, "role": "organization", "org_name": org_name,
                                  "full_name": org_name, "email": email, "phone": phone or None,
                                  "company_address": address_full, "approval_status": "pending",
                                  "is_online": False})
    if not ins["ok"]:
        return jsonify({"error": "Account created but profile save failed."}), 500
    return jsonify({"success": True, "org_name": org_name,
                    "message": f"Registration submitted! '{org_name}' is pending admin approval."}), 201

# ─── LOGIN USER ────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
@app.route("/api/login-user", methods=["POST"])
def login_user():
    d        = request.get_json() or {}
    email    = (d.get("email")    or "").strip().lower()
    password = (d.get("password") or "")
    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400
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
                    "redirect": {"user": "/user", "organization": "/org",
                                 "super_admin": "/super-admin"}.get(role, "/user")}), 200

# ─── LOGIN ORG ─────────────────────────────────────────────────
@app.route("/api/auth/login-org", methods=["POST"])
@app.route("/api/login-org",      methods=["POST"])
def login_org():
    d        = request.get_json() or {}
    email    = (d.get("email")    or "").strip().lower()
    password = (d.get("password") or "")
    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400
    if email == SUPER_ADMIN_EMAIL and password == SUPER_ADMIN_PASSWORD:
        session.permanent = True
        session.update({"user_id": "super-admin", "role": "super_admin",
                        "email": SUPER_ADMIN_EMAIL, "full_name": "Super Admin",
                        "org_name": "QCode Admin"})
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
    if role != "organization":
        sb_signout(token)
        return jsonify({"error": "This page is for organizations only."}), 403
    if status == "pending":
        sb_signout(token)
        return jsonify({"error": "Your organization is pending admin approval."}), 403
    if status == "suspended":
        sb_signout(token)
        return jsonify({"error": "This account has been suspended."}), 403
    session.permanent = True
    session.update({"user_id": uid, "role": "organization", "email": profile.get("email",""),
                    "org_name": profile.get("org_name",""), "full_name": profile.get("org_name","")})
    db_update("profiles", {"id": uid}, {"is_online": True})
    return jsonify({"success": True, "role": "organization", "redirect": "/org"}), 200

# ─── LOGOUT ────────────────────────────────────────────────────
@app.route("/api/auth/logout", methods=["POST"])
@app.route("/api/logout",      methods=["POST"])
def logout():
    uid = session.get("user_id")
    if uid and uid != "super-admin":
        db_update("profiles", {"id": uid}, {"is_online": False})
    session.clear()
    return jsonify({"success": True, "redirect": "/"}), 200

# ─── FORGOT / RESET PASSWORD ───────────────────────────────────
@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    d      = request.get_json() or {}
    email  = (d.get("email") or "").strip().lower()
    is_org = d.get("is_org", False)
    if not email:
        return jsonify({"error": "Email is required."}), 400
    profiles = db_select("profiles", {"email": f"eq.{email}"})
    if not profiles:
        return jsonify({"success": True, "message": "If an account exists, a reset email has been sent."}), 200
    profile = profiles[0]
    if is_org and profile.get("role") != "organization":
        return jsonify({"success": True, "message": "If an account exists, a reset email has been sent."}), 200
    if not is_org and profile.get("role") not in ("user",):
        return jsonify({"success": True, "message": "If an account exists, a reset email has been sent."}), 200
    token  = _rcode(32)
    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    db_insert("password_resets", {"user_id": profile["id"], "email": email, "token": token,
                                   "expires_at": expiry, "used": False,
                                   "created_at": datetime.now(timezone.utc).isoformat()})
    route = "reset-password-org" if is_org else "reset-password-user"
    base  = request.host_url.rstrip("/")
    link  = f"{base}/{route}?token={token}"
    send_email_reset(email, link, is_org=is_org)
    return jsonify({"success": True, "message": "If an account exists, a reset email has been sent."}), 200

@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    d        = request.get_json() or {}
    token    = (d.get("token")    or "").strip()
    password = (d.get("password") or "")
    if not token or not password:
        return jsonify({"error": "Token and password are required."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    resets = db_select("password_resets", {"token": f"eq.{token}", "used": "eq.false"})
    if not resets:
        return jsonify({"error": "Invalid or expired reset link."}), 400
    reset   = resets[0]
    expires = datetime.fromisoformat(reset["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires:
        return jsonify({"error": "This reset link has expired. Please request a new one."}), 400
    uid = reset["user_id"]
    r   = requests.put(f"{SUPABASE_URL}/auth/v1/admin/users/{uid}",
        headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                 "Content-Type": "application/json"},
        json={"password": password}, timeout=15)
    if not r.ok:
        return jsonify({"error": "Failed to update password. Please try again."}), 500
    db_update("password_resets", {"token": token}, {"used": True})
    return jsonify({"success": True, "message": "Password updated! You can now sign in."}), 200

# ─── USER APIs ─────────────────────────────────────────────────
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
    upd = {}
    for k in ("full_name","phone","preferred_lang","state"):
        if k in d: upd[k] = d[k] or None
    if upd: db_update("profiles", {"id": uid}, upd)
    return jsonify({"success": True}), 200

@app.route("/api/user/find-service")
def api_find_service():
    code = (request.args.get("code") or "").strip().upper()
    if not code: return jsonify({"error": "Service code required"}), 400
    svcs = db_select("services", {"service_code": f"eq.{code}"})
    if not svcs: return jsonify({"error": f"No service found with code '{code}'."}), 404
    svc  = svcs[0]
    if svc.get("deleted_at"): return jsonify({"error": "This service no longer exists."}), 404
    org  = db_select("profiles", {"id": f"eq.{svc['org_id']}"}, single=True) or {}
    if org.get("approval_status") != "approved":
        return jsonify({"error": "This organization is not currently active."}), 403
    if svc["status"] == "closed": return jsonify({"error": f"'{svc['name']}' queue is closed."}), 400
    if svc["status"] == "paused": return jsonify({"error": f"'{svc['name']}' queue is paused. Try again soon."}), 400
    waiting          = db_count("queue_entries", {"service_id": f"eq.{svc['id']}", "status": "eq.waiting"})
    svc["waiting_count"] = waiting
    svc["org_name"]      = org.get("org_name", "")
    svc["org_logo"]      = org.get("logo_url", "")
    svc["eta_minutes"]   = (waiting + 1) * (svc.get("time_interval") or 5)
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
    current = db_count("queue_entries", {"service_id": f"eq.{svc_id}",
                                          "status": "in.(waiting,called,serving)"})
    if current >= max_u: return jsonify({"error": "Queue is full. Please try again later."}), 400
    already = db_select("queue_entries", {"service_id": f"eq.{svc_id}", "user_id": f"eq.{uid}",
                                           "status": "in.(waiting,called,serving)"})
    if already: return jsonify({"error": "You are already in this queue.", "entry": already[0]}), 409

    # Validate required custom form fields
    form_def = svc.get("user_info_form") or []
    if isinstance(form_def, str):
        try: form_def = json.loads(form_def)
        except: form_def = []
    custom_form_data = d.get("custom_form_data") or {}
    for field in form_def:
        if field.get("required"):
            val = custom_form_data.get(field.get("label",""))
            if not val or not str(val).strip():
                return jsonify({"error": f"'{field.get('label','Field')}' is required before joining."}), 400

    # Find Stage 1 if service has stages
    first_stage = None
    if svc.get("stages_enabled"):
        stage_rows = db_select("stages", {"service_id": f"eq.{svc_id}",
                                           "order": "order.asc", "limit": "1"})
        if stage_rows:
            first_stage = stage_rows[0]

    n     = (svc.get("ticket_counter") or 0) + 1
    label = f"{svc.get('ticket_prefix','Q')}{str(n).zfill(3)}"
    db_update("services", {"id": svc_id}, {"ticket_counter": n})

    if first_stage:
        pos = db_count("queue_entries", {
            "service_id": f"eq.{svc_id}",
            "stage_id":   f"eq.{first_stage['id']}",
            "status":     "eq.waiting",
        }) + 1
    else:
        pos = db_count("queue_entries", {
            "service_id": f"eq.{svc_id}",
            "status":     "eq.waiting",
        }) + 1

    interval = svc.get("time_interval") or 5
    eta_t    = (datetime.now(timezone.utc) + timedelta(minutes=pos * interval)).isoformat()
    end_code = _rcode(4)
    profile  = get_profile(uid)

    required = {
        "service_id":    svc_id, "user_id": uid,
        "ticket_label":  label,  "ticket_number": n,
        "status":        "waiting", "estimated_time": eta_t,
        "join_method":   "web", "joined_at": datetime.now(timezone.utc).isoformat(),
    }
    optional = {
        "end_code":         end_code,
        "custom_form_data": custom_form_data,
        "pushback_count":   0,
        "stage_id":         first_stage["id"] if first_stage else None,
    }

    # Batch assignment
    if svc.get("batch_enabled"):
        batch_size   = int(svc.get("batch_size") or 50)
        buffer_min   = int(svc.get("batch_buffer_min") or 30)
        batch_number = ((n - 1) // batch_size) + 1
        batch_open_time = None
        if svc.get("schedule_start"):
            try:
                base = datetime.fromisoformat(svc["schedule_start"].replace("Z","+00:00"))
                batch_open_time = (base + timedelta(minutes=(batch_number-1)*buffer_min)).isoformat()
            except: pass
        optional["batch_number"]    = batch_number
        optional["batch_open_time"] = batch_open_time
        pos_in_batch = ((n - 1) % batch_size) + 1
        eta_t = (datetime.now(timezone.utc) + timedelta(
            minutes=((batch_number-1)*buffer_min) + pos_in_batch * interval
        )).isoformat()

    payload = _safe_payload("queue_entries", required, optional)
    res     = db_insert("queue_entries", payload)
    if not res["ok"]:
        err = res["data"].get("message","") if isinstance(res["data"], dict) else "Failed to join queue."
        return jsonify({"error": err}), 500

    entry = res["data"][0] if isinstance(res["data"], list) else res["data"]
    entry["position"]      = pos
    entry["svc_name"]      = svc["name"]
    entry["time_interval"] = interval
    entry["end_code"]      = end_code
    org = db_select("profiles", {"id": f"eq.{svc['org_id']}"}, single=True) or {}
    entry["org_name"] = org.get("org_name", "")
    entry["org_logo"] = org.get("logo_url", "")

    send_push_to_user(uid, "✅ Joined Queue!",
                      f"Ticket {label} — Position #{pos}. ~{pos*interval} min wait.",
                      {"type": "joined", "entry_id": entry.get("id")})
    phone = profile.get("phone") or ""
    if phone:
        send_sms(phone, f"QCode: Joined {svc['name']}. Ticket: {label} | "
                        f"Position: #{pos} | ~{pos*interval} min wait. End code: {end_code}")
    return jsonify({"success": True, "entry": entry, "end_code": end_code}), 201

@app.route("/api/user/queue-status/<entry_id>")
def api_queue_status(entry_id):
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    rows = db_select("queue_entries", {"id": f"eq.{entry_id}"})
    if not rows or rows[0].get("user_id") != uid: return jsonify({"error": "Not found"}), 404
    entry = rows[0]
    svcs  = db_select("services", {"id": f"eq.{entry['service_id']}"})
    svc   = svcs[0] if svcs else {}
    org   = db_select("profiles", {"id": f"eq.{svc.get('org_id','')}"}, single=True) or {}

    # Stage-aware position and ETA
    if entry.get("stage_id"):
        ahead = db_count("queue_entries", {
            "service_id":    f"eq.{entry['service_id']}",
            "stage_id":      f"eq.{entry['stage_id']}",
            "status":        "eq.waiting",
            "ticket_number": f"lt.{entry['ticket_number']}",
        })
        total = db_count("queue_entries", {
            "service_id": f"eq.{entry['service_id']}",
            "stage_id":   f"eq.{entry['stage_id']}",
            "status":     "eq.waiting",
        })
    else:
        ahead = db_count("queue_entries", {
            "service_id":    f"eq.{entry['service_id']}",
            "status":        "eq.waiting",
            "ticket_number": f"lt.{entry['ticket_number']}",
        })
        total = db_count("queue_entries", {
            "service_id": f"eq.{entry['service_id']}",
            "status":     "eq.waiting",
        })

    interval = svc.get("time_interval") or 5
    eta_mins = max(0, (ahead + 1) * interval)

    # Stage info
    stage_name   = ""
    stage_order  = 0
    total_stages = 0
    if entry.get("stage_id"):
        stage_rows = db_select("stages", {"id": f"eq.{entry['stage_id']}"})
        if stage_rows:
            stage_name  = stage_rows[0].get("name", "")
            stage_order = stage_rows[0].get("order", 1)
        total_stages = db_count("stages", {"service_id": f"eq.{entry['service_id']}"})

    # Counter info
    counter_name = ""
    if entry.get("counter_id"):
        crows = db_select("staff_counters", {"id": f"eq.{entry['counter_id']}"})
        if crows:
            cnum  = crows[0].get("counter_number", 1)
            cstaff= crows[0].get("staff_name", "")
            counter_name = f"Counter {cnum}" + (f" — {cstaff}" if cstaff else "")

    entry.update({
        "position":    ahead + 1, "ahead": ahead, "total": total,
        "eta_minutes": eta_mins,
        "estimated_time": (datetime.now(timezone.utc) + timedelta(minutes=eta_mins)).isoformat(),
        "svc_name":    svc.get("name",""), "svc_status": svc.get("status",""),
        "time_interval": interval,
        "org_name":    org.get("org_name",""), "org_logo": org.get("logo_url",""),
        "stage_name":  stage_name, "stage_order": stage_order, "total_stages": total_stages,
        "counter_name":       counter_name,
        "next_service_group": svc.get("next_service_group") or None,
        "is_final":           svc.get("is_final", False),
        "has_free_time":      svc.get("has_free_time", False),
        "advanced_to_next_stage": False,
    })
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

# ─── READY CHECKOUT ────────────────────────────────────────────
@app.route("/api/user/ready-checkout", methods=["POST"])
def api_user_ready_checkout():
    """
    Customer presses Ready for Checkout after free-time shopping.
    Uses _get_next_service to safely find the right checkout counter
    within the same org only, then _create_next_entry for accurate ETA.
    """
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    d        = request.get_json() or {}
    entry_id = d.get("entry_id")
    if not entry_id: return jsonify({"error": "entry_id required"}), 400

    rows = db_select("queue_entries", {"id": f"eq.{entry_id}"})
    if not rows or rows[0].get("user_id") != uid:
        return jsonify({"error": "Entry not found"}), 404
    entry = rows[0]

    svc_rows = db_select("services", {"id": f"eq.{entry.get('service_id','')}"})
    if not svc_rows: return jsonify({"error": "Service not found"}), 404
    svc        = svc_rows[0]
    next_group = svc.get("next_service_group") or None
    if not next_group:
        return jsonify({"error": "No next service configured for checkout"}), 400

    # Safe org-locked service lookup
    best_svc, err = _get_next_service(entry, next_group)
    if err:
        return jsonify({"error": err}), 404

    # Create entry with accurate NOW-based ETA
    new_entry, err = _create_next_entry(entry, best_svc, uid=uid)
    if err:
        return jsonify({"error": err}), 500

    counter_name = best_svc.get("staff_name") or best_svc.get("name") or "Checkout"
    send_push_to_user(uid, "✅ Checkout Ready!",
                      f"Ticket {new_entry['ticket_label']} — Head to {counter_name}. "
                      f"Position #{new_entry['position']}.",
                      {"type": "checkout_ready", "entry_id": new_entry.get("id")})

    return jsonify({
        "success":          True,
        "assigned_counter": counter_name,
        "ticket_label":     new_entry["ticket_label"],
        "estimated_time":   new_entry.get("estimated_time"),
        "new_entry_id":     new_entry.get("id"),
    }), 201

# ─── JOIN NEXT ─────────────────────────────────────────────────
@app.route("/api/user/join-next", methods=["POST"])
def api_user_join_next():
    """
    After Stage N completes, customer joins the next linked service.
    Uses _get_next_service (org-locked) + _create_next_entry (accurate ETA).
    """
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    d        = request.get_json() or {}
    entry_id = d.get("entry_id")
    group    = (d.get("next_service_group") or "").strip()
    if not entry_id or not group:
        return jsonify({"error": "entry_id and next_service_group required"}), 400

    rows = db_select("queue_entries", {"id": f"eq.{entry_id}"})
    if not rows or rows[0].get("user_id") != uid:
        return jsonify({"error": "Entry not found"}), 404
    entry = rows[0]

    # Already in this group?
    already = db_select("queue_entries", {
        "user_id": f"eq.{uid}",
        "status":  "in.(waiting,called,serving)",
    })
    # Check if any active entry belongs to the target group
    for ae in already:
        ae_svc = db_select("services", {"id": f"eq.{ae.get('service_id','')}"}, single=True) or {}
        if ae_svc.get("service_group") == group:
            return jsonify({"error": "Already in this queue", "entry": ae}), 409

    best_svc, err = _get_next_service(entry, group)
    if err:
        return jsonify({"error": err}), 404

    new_entry, err = _create_next_entry(entry, best_svc, uid=uid)
    if err:
        return jsonify({"error": err}), 500

    org = db_select("profiles", {"id": f"eq.{best_svc['org_id']}"}, single=True) or {}
    new_entry["org_name"] = org.get("org_name","")

    send_push_to_user(uid, f"✅ Joined {best_svc['name']}!",
                      f"Ticket {new_entry['ticket_label']} — Position #{new_entry['position']}. "
                      f"~{new_entry['position'] * (best_svc.get('time_interval') or 5)} min wait.",
                      {"type": "joined", "entry_id": new_entry.get("id")})

    return jsonify({"success": True, "entry": new_entry,
                    "service_name": best_svc["name"]}), 201

@app.route("/api/user/history")
def api_user_history():
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    rows      = db_select("queue_entries", {"user_id": f"eq.{uid}",
                                             "order": "joined_at.desc", "limit": "50"})
    svc_cache = {}
    for row in rows:
        sid = row.get("service_id")
        if sid and sid not in svc_cache:
            svcs = db_select("services", {"id": f"eq.{sid}"})
            if svcs:
                org = db_select("profiles", {"id": f"eq.{svcs[0]['org_id']}"}, single=True) or {}
                svc_cache[sid] = {"name": svcs[0]["name"], "org_name": org.get("org_name","")}
        if sid in svc_cache:
            row["svc_name"] = svc_cache[sid]["name"]
            row["org_name"] = svc_cache[sid]["org_name"]
    return jsonify(rows), 200

@app.route("/api/user/open-services")
def api_open_services():
    state_filter = (request.args.get("state") or "").strip()
    search_query = (request.args.get("q")     or "").strip().lower()
    svcs   = db_select("services", {"status": "eq.open", "deleted_at": "is.null",
                                     "order": "created_at.desc", "limit": "100"})
    result = []
    for svc in svcs:
        org = db_select("profiles", {"id": f"eq.{svc['org_id']}"}, single=True) or {}
        if org.get("approval_status") != "approved": continue
        if state_filter and org.get("state","") != state_filter: continue
        svc_group = svc.get("service_group") or ""
        is_entry  = svc.get("is_entry", False)
        if svc_group and not is_entry: continue
        svc["org_name"]      = org.get("org_name","")
        svc["org_logo"]      = org.get("logo_url","")
        svc["org_state"]     = org.get("state","")
        svc["is_linked"]     = bool(svc_group)
        svc["waiting_count"] = db_count("queue_entries",
                                         {"service_id": f"eq.{svc['id']}", "status": "eq.waiting"})
        if search_query:
            if search_query not in f"{svc['name']} {svc['org_name']}".lower(): continue
        result.append(svc)
    return jsonify(result), 200

@app.route("/api/user/feedback", methods=["POST"])
def api_user_feedback():
    d        = request.get_json() or {}
    entry_id = d.get("entry_id")
    rating   = d.get("rating")
    comment  = (d.get("comment") or "").strip()
    uid      = session.get("user_id")
    if not entry_id or not rating:
        return jsonify({"error": "entry_id and rating required"}), 400
    rows   = db_select("queue_entries", {"id": f"eq.{entry_id}"})
    svc_id = rows[0].get("service_id") if rows else None
    payload = {"entry_id": entry_id, "user_id": uid, "rating": int(rating),
               "comment": comment or None, "created_at": datetime.now(timezone.utc).isoformat()}
    if svc_id: payload["service_id"] = svc_id
    db_insert("feedbacks", payload)
    return jsonify({"success": True}), 201

@app.route("/api/user/verify-end-code", methods=["POST"])
def api_verify_end_code():
    d        = request.get_json() or {}
    entry_id = d.get("entry_id")
    end_code = (d.get("end_code") or "").strip().upper()
    uid      = session.get("user_id")
    rows     = db_select("queue_entries", {"id": f"eq.{entry_id}"})
    if not rows: return jsonify({"error": "Entry not found"}), 404
    entry  = rows[0]
    if uid != entry.get("user_id") and session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    stored = (entry.get("end_code") or "").upper()
    if stored and stored != end_code: return jsonify({"error": "Invalid end code"}), 400
    db_update("queue_entries", {"id": entry_id},
              {"status": "completed", "completed_at": datetime.now(timezone.utc).isoformat()})
    return jsonify({"success": True}), 200

@app.route("/api/user/linked-services", methods=["GET"])
def api_user_linked_services():
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    group  = request.args.get("group","").strip()
    org_id = request.args.get("org_id","").strip()
    if not group: return jsonify({"error": "group required"}), 400
    if not org_id: return jsonify({"error": "org_id required"}), 400
    svcs = db_select("services", {
        "service_group": f"eq.{group}",
        "org_id":        f"eq.{org_id}",
        "status":        "eq.open",
        "deleted_at":    "is.null",
    })
    result = []
    for svc in svcs:
        waiting = db_count("queue_entries", {"service_id": f"eq.{svc['id']}",
                                              "status": "in.(waiting,called,serving)"})
        result.append({"id": svc["id"], "name": svc["name"],
                       "service_code":  svc["service_code"],
                       "waiting":       waiting,
                       "time_interval": svc.get("time_interval", 5)})
    result.sort(key=lambda x: x["waiting"])
    return jsonify(result), 200

# ─── PUSH NOTIFICATIONS ────────────────────────────────────────
@app.route("/api/push/vapid-public-key")
def api_push_vapid_key():
    return jsonify({"publicKey": VAPID_PUBLIC_KEY}), 200

@app.route("/api/push/subscribe", methods=["POST"])
@app.route("/api/user/push-subscribe", methods=["POST"])
def api_push_subscribe():
    uid = session.get("user_id")
    if not uid: return jsonify({"error": "Not logged in"}), 401
    d            = request.get_json() or {}
    subscription = d.get("subscription")
    if not subscription: return jsonify({"error": "subscription required"}), 400
    endpoint = subscription.get("endpoint","")
    existing = db_select("push_subscriptions", {"endpoint": f"eq.{endpoint}"})
    if existing:
        db_update("push_subscriptions", {"endpoint": endpoint},
                  {"user_id": uid, "subscription_data": json.dumps(subscription),
                   "updated_at": datetime.now(timezone.utc).isoformat()})
    else:
        db_insert("push_subscriptions", {
            "user_id": uid, "endpoint": endpoint,
            "subscription_data": json.dumps(subscription),
            "created_at": datetime.now(timezone.utc).isoformat()
        })
    return jsonify({"success": True}), 201

@app.route("/api/push/send", methods=["POST"])
def api_push_send():
    if session.get("role") not in ("organization", "super_admin"):
        return jsonify({"error": "Unauthorized"}), 403
    d       = request.get_json() or {}
    user_id = d.get("user_id")
    title   = d.get("title", "QCode Update")
    body    = d.get("body", "")
    data    = d.get("data", {})
    if not user_id: return jsonify({"error": "user_id required"}), 400
    send_push_to_user(user_id, title, body, data)
    return jsonify({"success": True}), 200

# ─── AUTO-CANCEL / PUSHBACK ────────────────────────────────────
@app.route("/api/system/auto-cancel", methods=["POST"])
def api_auto_cancel():
    called      = db_select("queue_entries", {"status": "eq.called"})
    cancelled   = []
    pushed_back = []
    for entry in called:
        called_at_str = entry.get("called_at")
        if not called_at_str: continue
        svcs = db_select("services", {"id": f"eq.{entry.get('service_id')}"})
        if not svcs: continue
        svc       = svcs[0]
        grace_min = max(1, (svc.get("time_interval", 5) // 4))
        called_at = datetime.fromisoformat(called_at_str.replace("Z","+00:00"))
        elapsed   = (datetime.now(timezone.utc) - called_at).total_seconds()
        if elapsed < grace_min * 60: continue
        pushback_count = entry.get("pushback_count", 0) or 0
        if pushback_count >= 3:
            db_update("queue_entries", {"id": entry["id"]},
                      {"status": "no_show", "completed_at": datetime.now(timezone.utc).isoformat()})
            cancelled.append(entry["id"])
            if entry.get("user_id"):
                send_push_to_user(entry["user_id"], "❌ Removed from Queue",
                                  f"Ticket {entry.get('ticket_label','—')} removed after 3 missed calls.",
                                  {"type": "no_show"})
        else:
            new_ticket_num = entry["ticket_number"] + 3
            new_pushback   = pushback_count + 1
            db_update("queue_entries", {"id": entry["id"]}, {
                "status":         "waiting",
                "ticket_number":  new_ticket_num,
                "pushback_count": new_pushback,
                "called_at":      None,
            })
            pushed_back.append(entry["id"])
            if entry.get("user_id"):
                send_push_to_user(entry["user_id"],
                                  f"⚠️ Pushed Back ({new_pushback}/3)",
                                  f"You missed your call. Moved back 3 positions. Strike {new_pushback} of 3.",
                                  {"type": "pushback", "count": new_pushback})
            if entry.get("guest_phone"):
                send_sms(entry["guest_phone"],
                         f"QCode: Ticket {entry.get('ticket_label','—')} missed call #{new_pushback}. "
                         f"Pushed back 3 positions. Strike {new_pushback}/3.")
    return jsonify({"cancelled": cancelled, "pushed_back": pushed_back,
                    "count": len(cancelled)}), 200

@app.route("/api/system/auto-schedule", methods=["POST"])
def api_auto_schedule():
    now    = datetime.now(timezone.utc)
    now_t  = now.strftime("%H:%M")
    svcs   = db_select("services", {"deleted_at": "is.null"})
    opened = []; closed = []; paused = []; resumed = []
    for svc in svcs:
        s_start = svc.get("schedule_start") or svc.get("queue_start")
        s_end   = svc.get("schedule_end")   or svc.get("queue_end")
        if s_start:
            try:
                start_dt = datetime.fromisoformat(s_start.replace("Z","+00:00"))
                if now >= start_dt and svc["status"] == "closed":
                    db_update("services", {"id": svc["id"]}, {"status": "open"})
                    opened.append(svc["id"]); svc["status"] = "open"
            except: pass
        if s_end:
            try:
                end_dt = datetime.fromisoformat(s_end.replace("Z","+00:00"))
                if now >= end_dt and svc["status"] in ("open","paused"):
                    db_update("services", {"id": svc["id"]}, {"status": "closed"})
                    closed.append(svc["id"]); svc["status"] = "closed"
            except: pass
        break_times = svc.get("break_times") or []
        if isinstance(break_times, str):
            try: break_times = json.loads(break_times)
            except: break_times = []
        if break_times and svc["status"] in ("open","paused"):
            in_break = False
            for brk in break_times:
                b_start = (brk.get("start") or "")[:5]
                b_end   = (brk.get("end")   or "")[:5]
                if b_start and b_end and b_start <= now_t < b_end:
                    in_break = True; break
            if in_break and svc["status"] == "open":
                db_update("services", {"id": svc["id"]}, {"status": "paused"})
                paused.append(svc["id"])
            elif not in_break and svc["status"] == "paused":
                within_schedule = True
                if s_start and s_end:
                    try:
                        st = datetime.fromisoformat(s_start.replace("Z","+00:00"))
                        en = datetime.fromisoformat(s_end.replace("Z","+00:00"))
                        within_schedule = st <= now <= en
                    except: pass
                if within_schedule:
                    db_update("services", {"id": svc["id"]}, {"status": "open"})
                    resumed.append(svc["id"])
    return jsonify({"opened": opened, "closed": closed,
                    "paused": paused, "resumed": resumed}), 200

# ─── ORG APIs ──────────────────────────────────────────────────
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
    d   = request.get_json() or {}
    upd = {}
    for k in ("phone","logo_url","org_name","company_address","state"):
        if k in d: upd[k] = d[k] or None
    if upd: db_update("profiles", {"id": uid}, upd)
    return jsonify({"success": True}), 200

@app.route("/api/org/upload-logo", methods=["POST"])
def api_org_upload_logo():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    if "logo" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["logo"]
    if not file.filename: return jsonify({"error": "Empty filename"}), 400
    allowed = {"image/jpeg","image/png","image/webp","image/gif"}
    if file.content_type not in allowed:
        return jsonify({"error": "Only JPG, PNG, or WebP images allowed"}), 400
    data = file.read()
    if len(data) > 2 * 1024 * 1024:
        return jsonify({"error": "Logo must be under 2MB"}), 400
    ext        = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else "jpg"
    filename   = f"{uid}/logo.{ext}"
    upload_url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_STORAGE_BUCKET}/{filename}"
    r = requests.post(upload_url,
        headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                 "Content-Type": file.content_type, "x-upsert": "true"},
        data=data, timeout=30)
    if not r.ok:
        r = requests.put(upload_url,
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                     "Content-Type": file.content_type},
            data=data, timeout=30)
    if not r.ok:
        err_detail = r.text[:500]
        print(f"[Logo Upload Error] {r.status_code} {err_detail}")
        return jsonify({"error": f"Upload failed ({r.status_code}): {err_detail}"}), 500
    public_url = f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_STORAGE_BUCKET}/{filename}"
    db_update("profiles", {"id": uid}, {"logo_url": public_url})
    return jsonify({"success": True, "logo_url": public_url}), 200

@app.route("/api/org/services", methods=["GET"])
def api_org_services():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    svcs = db_select("services", {"org_id": f"eq.{uid}", "deleted_at": "is.null",
                                   "order": "created_at.desc"})
    for svc in svcs:
        for s in ("waiting","called","serving","completed","no_show"):
            svc[f"count_{s}"] = db_count("queue_entries",
                                          {"service_id": f"eq.{svc['id']}", "status": f"eq.{s}"})
        svc["stages"] = []
    return jsonify(svcs), 200

@app.route("/api/org/services", methods=["POST"])
def api_org_create_service():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    d    = request.get_json() or {}
    name = (d.get("name") or "").strip()
    if not name: return jsonify({"error": "Service name is required"}), 400
    for _ in range(20):
        code = _rcode(6)
        if not db_select("services", {"service_code": f"eq.{code}"}): break
    end_code = (d.get("end_code") or "").strip().upper() or _rcode(4)
    required = {
        "org_id":         uid,
        "name":           name,
        "staff_name":     d.get("staff_name") or None,
        "description":    d.get("description") or None,
        "service_code":   code,
        "ticket_prefix":  (d.get("ticket_prefix") or "A").upper()[:3],
        "ticket_counter": 0,
        "time_interval":  int(d.get("time_interval") or 5),
        "max_users":      int(d.get("max_users")) if d.get("max_users") else None,
        "status": "closed" if (d.get("schedule_start") and
                  datetime.fromisoformat(d["schedule_start"].replace("Z","+00:00")) >
                  datetime.now(timezone.utc)) else "open",
    }
    optional = {
        "end_code":           end_code,
        "user_info_form":     d.get("user_info_form") or [],
        "schedule_start":     d.get("schedule_start") or d.get("queue_start") or None,
        "schedule_end":       d.get("schedule_end")   or d.get("queue_end")   or None,
        "queue_start":        d.get("schedule_start") or d.get("queue_start") or None,
        "queue_end":          d.get("schedule_end")   or d.get("queue_end")   or None,
        "break_times":        d.get("break_times") or [],
        "batch_enabled":      bool(d.get("batch_enabled")),
        "batch_size":         int(d.get("batch_size") or 50) if d.get("batch_enabled") else None,
        "batch_buffer_min":   int(d.get("batch_buffer_min") or 30) if d.get("batch_enabled") else None,
        "next_service_group": d.get("next_service_group") or None,
        "is_entry":           bool(d.get("is_entry")),
        "is_final":           bool(d.get("is_final")),
        "service_group":      d.get("service_group") or None,
        "has_free_time":      bool(d.get("has_free_time")),
    }
    payload = _safe_payload("services", required, optional)
    res     = db_insert("services", payload)
    if not res["ok"]:
        err = res["data"].get("message","") if isinstance(res["data"], dict) else "Failed to create service."
        return jsonify({"error": err}), 500
    svc = res["data"][0] if isinstance(res["data"], list) else res["data"]
    return jsonify({"success": True, "service": svc, "service_code": code,
                    "staff_link": f"/staff/{code}", "end_code": end_code}), 201

@app.route("/api/org/services/<svc_id>/edit", methods=["POST"])
def api_org_edit_service(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    svcs = db_select("services", {"id": f"eq.{svc_id}", "org_id": f"eq.{uid}"})
    if not svcs: return jsonify({"error": "Service not found"}), 404
    d   = request.get_json() or {}
    upd = {}
    for k in ("name","description","staff_name","ticket_prefix","time_interval",
              "max_users","service_group","next_service_group","has_free_time",
              "is_entry","is_final","batch_enabled","batch_size","batch_buffer_min",
              "schedule_start","schedule_end"):
        if k in d:
            if k in ("time_interval","batch_size","batch_buffer_min"):
                upd[k] = int(d[k]) if d[k] else None
            elif k in ("has_free_time","is_entry","is_final","batch_enabled"):
                upd[k] = bool(d[k])
            elif k == "max_users":
                upd[k] = int(d[k]) if d[k] else None
            else:
                upd[k] = (d[k] or "").strip() or None
    if not upd: return jsonify({"error": "Nothing to update"}), 400
    db_update("services", {"id": svc_id}, upd)
    return jsonify({"success": True}), 200

@app.route("/api/org/services/<svc_id>/status", methods=["POST"])
def api_org_service_status(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    status = (request.get_json() or {}).get("status")
    if status not in ("open","paused","closed"):
        return jsonify({"error": "Invalid status"}), 400
    db_update("services", {"id": svc_id}, {"status": status})
    return jsonify({"success": True}), 200

@app.route("/api/org/services/<svc_id>/interval", methods=["POST"])
def api_org_service_interval(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    new_interval = int((request.get_json() or {}).get("time_interval") or 5)
    if new_interval < 1 or new_interval > 120:
        return jsonify({"error": "Interval must be 1–120 minutes"}), 400
    db_update("services", {"id": svc_id}, {"time_interval": new_interval})
    return jsonify({"success": True, "time_interval": new_interval}), 200

@app.route("/api/org/services/<svc_id>/delete", methods=["POST"])
def api_org_delete_service(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    db_update("services", {"id": svc_id},
              {"deleted_at": datetime.now(timezone.utc).isoformat(), "status": "closed"})
    return jsonify({"success": True}), 200

@app.route("/api/org/services/<svc_id>/restore", methods=["POST"])
def api_org_restore_service(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    db_update("services", {"id": svc_id}, {"deleted_at": None})
    return jsonify({"success": True}), 200

@app.route("/api/org/services/deleted")
def api_org_deleted_services():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify(db_select("services", {"org_id": f"eq.{uid}",
                                           "deleted_at": "not.is.null",
                                           "order": "deleted_at.desc"})), 200

@app.route("/api/org/queue/<svc_id>")
def api_org_queue(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    entries     = db_select("queue_entries", {
        "service_id": f"eq.{svc_id}",
        "status":     "in.(waiting,called,serving)",
        "order":      "ticket_number.asc"
    })
    stage_cache = {}
    for st in db_select("stages", {"service_id": f"eq.{svc_id}", "order": "order.asc"}):
        stage_cache[st["id"]] = st
    for e in entries:
        if e.get("user_id"):
            p = db_select("profiles", {"id": f"eq.{e['user_id']}"}, single=True) or {}
            e["user_name"]   = p.get("full_name") or p.get("email") or "User"
            e["user_online"] = p.get("is_online", False)
            e["user_phone"]  = p.get("phone","")
        else:
            e["user_name"]   = e.get("guest_name") or "Guest"
            e["user_online"] = False
            e["user_phone"]  = e.get("guest_phone","")
        sid              = e.get("stage_id")
        e["stage_name"]  = stage_cache[sid]["name"] if sid and sid in stage_cache else ""
        e["stage_order"] = stage_cache[sid].get("order",1) if sid and sid in stage_cache else 0
        cfd = e.get("custom_form_data") or {}
        if isinstance(cfd, str):
            try: cfd = json.loads(cfd)
            except: cfd = {}
        e["custom_form_data"] = cfd
        eta_raw = e.get("estimated_time") or ""
        if eta_raw:
            try:
                eta_dt    = datetime.fromisoformat(eta_raw.replace("Z","+00:00"))
                now_utc   = datetime.now(timezone.utc)
                mins_left = max(0, int((eta_dt - now_utc).total_seconds() / 60))
                e["eta_display"]   = eta_dt.strftime("%I:%M %p")
                e["eta_mins_left"] = mins_left
                e["eta_due"]       = now_utc >= eta_dt
            except:
                e["eta_display"] = ""; e["eta_mins_left"] = 0; e["eta_due"] = False
        else:
            e["eta_display"] = ""; e["eta_mins_left"] = 0; e["eta_due"] = False
    return jsonify(entries), 200

@app.route("/api/org/queue/call-next/<svc_id>", methods=["POST"])
def api_org_call_next(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    waiting = db_select("queue_entries", {
        "service_id": f"eq.{svc_id}", "status": "eq.waiting",
        "order": "ticket_number.asc", "limit": "1"
    })
    if not waiting: return jsonify({"error": "No one waiting"}), 404
    entry   = waiting[0]
    force   = (request.get_json() or {}).get("force", False)
    eta_raw = entry.get("estimated_time") or ""
    if eta_raw and not force:
        try:
            eta_dt  = datetime.fromisoformat(eta_raw.replace("Z","+00:00"))
            now_utc = datetime.now(timezone.utc)
            if now_utc < eta_dt:
                mins_left = int((eta_dt - now_utc).total_seconds() / 60)
                return jsonify({"error": f"Customer's turn is not yet. {mins_left} min remaining.",
                                "eta_display": eta_dt.strftime("%I:%M %p"),
                                "eta_mins_left": mins_left, "can_force": True}), 400
        except: pass
    db_update("queue_entries", {"id": entry["id"]},
              {"status": "called", "called_at": datetime.now(timezone.utc).isoformat()})
    entry["status"] = "called"
    if entry.get("user_id"):
        send_push_to_user(entry["user_id"], "📢 It's Your Turn!",
                          f"Ticket {entry['ticket_label']} — Please go to the counter now.",
                          {"type": "called", "entry_id": entry["id"]})
    if entry.get("guest_phone"):
        send_sms(entry["guest_phone"],
                 f"📢 QCode: Ticket {entry['ticket_label']} is being called! Go to the counter now.")
    return jsonify({"success": True, "entry": entry}), 200

@app.route("/api/org/queue/walk-in/<svc_id>", methods=["POST"])
def api_org_walk_in(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    d     = request.get_json() or {}
    name  = (d.get("name") or "Walk-in Customer").strip()
    phone = (d.get("phone") or "").strip() or None
    svcs  = db_select("services", {"id": f"eq.{svc_id}"})
    if not svcs: return jsonify({"error": "Service not found"}), 404
    svc      = svcs[0]
    n        = (svc.get("ticket_counter") or 0) + 1
    label    = f"{svc.get('ticket_prefix','Q')}{str(n).zfill(3)}"
    db_update("services", {"id": svc_id}, {"ticket_counter": n})
    pos      = db_count("queue_entries", {"service_id": f"eq.{svc_id}", "status": "eq.waiting"}) + 1
    interval = svc.get("time_interval") or 5
    eta_t    = (datetime.now(timezone.utc) + timedelta(minutes=pos * interval)).isoformat()
    end_code = _rcode(4)
    required = {
        "service_id": svc_id, "user_id": None, "guest_name": name,
        "guest_phone": phone, "ticket_label": label, "ticket_number": n,
        "status": "waiting", "estimated_time": eta_t,
        "join_method": "walk_in", "joined_at": datetime.now(timezone.utc).isoformat(),
    }
    optional = {"end_code": end_code, "pushback_count": 0}
    res = db_insert("queue_entries", _safe_payload("queue_entries", required, optional))
    if not res["ok"]:
        err = res["data"].get("message","") if isinstance(res["data"],dict) else str(res["data"])
        return jsonify({"error": f"Failed to add walk-in: {err}"}), 500
    entry = res["data"][0] if isinstance(res["data"], list) else res["data"]
    entry["position"] = pos
    entry["end_code"] = end_code
    if phone:
        send_sms(phone, f"QCode Walk-In: Ticket {label} | Position #{pos} | "
                        f"~{pos*interval} min wait. End code: {end_code}")
    return jsonify({"success": True, "entry": entry}), 201

@app.route("/api/org/queue/move-ticket/<svc_id>", methods=["POST"])
def api_org_move_ticket(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    d            = request.get_json() or {}
    ticket_label = (d.get("ticket_label") or "").strip().upper()
    new_pos      = int(d.get("position") or 1)
    rows = db_select("queue_entries", {"service_id": f"eq.{svc_id}",
                                        "ticket_label": f"eq.{ticket_label}",
                                        "status": "eq.waiting"})
    if not rows: return jsonify({"error": f"Ticket {ticket_label} not found in waiting queue"}), 404
    waiting    = db_select("queue_entries", {"service_id": f"eq.{svc_id}",
                                              "status": "eq.waiting",
                                              "order": "ticket_number.asc"})
    target_num = waiting[new_pos-2]["ticket_number"] - 1 \
                 if new_pos > 1 and len(waiting) >= new_pos-1 else 0
    db_update("queue_entries", {"id": rows[0]["id"]}, {"ticket_number": target_num})
    return jsonify({"success": True}), 200

@app.route("/api/org/queue/entry/<entry_id>", methods=["POST"])
def api_org_update_entry(entry_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    status = (request.get_json() or {}).get("status")
    if status not in ("serving","completed","no_show","waiting","called","cancelled"):
        return jsonify({"error": "Invalid status"}), 400
    upd = {"status": status}
    if status in ("completed","no_show","cancelled"):
        upd["completed_at"] = datetime.now(timezone.utc).isoformat()
    db_update("queue_entries", {"id": entry_id}, upd)

    advanced = False
    if status == "completed":
        rows = db_select("queue_entries", {"id": f"eq.{entry_id}"})
        if rows:
            entry    = rows[0]
            svc_id   = entry.get("service_id")
            stage_id = entry.get("stage_id")

            # Old stages model — move to next stage
            if svc_id and stage_id:
                current_stage = db_select("stages", {"id": f"eq.{stage_id}"})
                if current_stage:
                    cur_order   = current_stage[0].get("order", 1)
                    next_stages = db_select("stages", {"service_id": f"eq.{svc_id}",
                                                        "order": f"eq.{cur_order+1}"})
                    if next_stages:
                        next_stage = next_stages[0]
                        svcs       = db_select("services", {"id": f"eq.{svc_id}"})
                        svc        = svcs[0] if svcs else {}
                        pos  = db_count("queue_entries", {
                            "service_id": f"eq.{svc_id}",
                            "stage_id":   f"eq.{next_stage['id']}",
                            "status":     "eq.waiting",
                        }) + 1
                        interval = next_stage.get("time_interval") or svc.get("time_interval",5)
                        eta_t    = (datetime.now(timezone.utc) +
                                    timedelta(minutes=pos * interval)).isoformat()
                        new_req = {
                            "service_id":    svc_id,
                            "user_id":       entry.get("user_id"),
                            "guest_name":    entry.get("guest_name"),
                            "guest_phone":   entry.get("guest_phone"),
                            "ticket_label":  entry.get("ticket_label",""),
                            "ticket_number": entry.get("ticket_number",0),
                            "status":        "waiting",
                            "estimated_time": eta_t,
                            "join_method":   entry.get("join_method","web"),
                            "joined_at":     datetime.now(timezone.utc).isoformat(),
                        }
                        new_opt = {"end_code": entry.get("end_code"),
                                   "stage_id": next_stage["id"], "pushback_count": 0}
                        db_insert("queue_entries", _safe_payload("queue_entries", new_req, new_opt))
                        advanced = True
                        if entry.get("user_id"):
                            send_push_to_user(entry["user_id"],
                                              f"➡️ Next Stage: {next_stage['name']}",
                                              f"Moved to {next_stage['name']}. Position #{pos}.",
                                              {"type": "next_stage",
                                               "stage_name": next_stage["name"],
                                               "entry_id":   entry_id})
                        if entry.get("guest_phone"):
                            send_sms(entry["guest_phone"],
                                     f"QCode: Moving to {next_stage['name']}. "
                                     f"Position #{pos}. ~{pos*interval} min wait.")

            # New linked service model — route via _get_next_service
            if not advanced and svc_id:
                svc_rows = db_select("services", {"id": f"eq.{svc_id}"})
                if svc_rows:
                    svc           = svc_rows[0]
                    next_group    = svc.get("next_service_group") or None
                    has_free_time = bool(svc.get("has_free_time", False))

                    if next_group and has_free_time:
                        # Customer shops freely — they press Ready for Checkout themselves
                        if entry.get("user_id"):
                            send_push_to_user(entry["user_id"], "🛒 You're in! Happy Shopping!",
                                              "Tap 'Ready for Checkout' when done shopping.",
                                              {"type": "free_time", "entry_id": entry_id,
                                               "next_service_group": next_group})

                    elif next_group:
                        # Auto-join next service using safe helper
                        best_svc, err = _get_next_service(entry, next_group)
                        if best_svc:
                            new_entry, err2 = _create_next_entry(entry, best_svc)
                            if new_entry:
                                advanced = True
                                if entry.get("user_id"):
                                    send_push_to_user(entry["user_id"],
                                                      f"➡️ Next: {best_svc['name']}",
                                                      f"Ticket {new_entry['ticket_label']} — "
                                                      f"Position #{new_entry['position']}.",
                                                      {"type": "join_next", "entry_id": entry_id,
                                                       "next_service_group": next_group})
                                if entry.get("guest_phone"):
                                    send_sms(entry["guest_phone"],
                                             f"QCode: Next step — {best_svc['name']}. "
                                             f"Ticket {new_entry['ticket_label']}, "
                                             f"Position #{new_entry['position']}.")
                        else:
                            print(f"[Next Service Error] {err}")

                    else:
                        # Final stage — service complete
                        if entry.get("user_id"):
                            send_push_to_user(entry["user_id"], "✅ Service Complete!",
                                              "You've been fully served. Please rate your experience.",
                                              {"type": "completed", "entry_id": entry_id})

    return jsonify({"success": True, "advanced_to_next_stage": advanced}), 200

@app.route("/api/org/queue/batch-call-entry/<svc_id>", methods=["POST"])
def api_org_batch_call_entry(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    d     = request.get_json() or {}
    count = max(1, min(int(d.get("count") or 20), 100))
    svcs  = db_select("services", {"id": f"eq.{svc_id}"})
    if not svcs: return jsonify({"error": "Service not found"}), 404
    svc     = svcs[0]
    waiting = db_select("queue_entries", {"service_id": f"eq.{svc_id}", "status": "eq.waiting",
                                           "order": "ticket_number.asc", "limit": str(count)})
    if not waiting: return jsonify({"error": "No customers waiting"}), 404
    called_entries = []
    for entry in waiting:
        db_update("queue_entries", {"id": entry["id"]},
                  {"status": "called", "called_at": datetime.now(timezone.utc).isoformat()})
        called_entries.append(entry["ticket_label"])
        if entry.get("user_id"):
            send_push_to_user(entry["user_id"], "🚪 You May Enter!",
                              f"Ticket {entry['ticket_label']} — Please enter the store now.",
                              {"type": "entry_called", "ticket_label": entry["ticket_label"],
                               "entry_id": entry["id"]})
        if entry.get("guest_phone"):
            send_sms(entry["guest_phone"],
                     f"QCode: Ticket {entry['ticket_label']} — You may now enter.")
    return jsonify({"success": True, "called_count": len(called_entries),
                    "called_tickets": called_entries,
                    "service_name": svc.get("name","Entry")}), 200

@app.route("/api/org/queue/entry-batch-size/<svc_id>", methods=["GET"])
def api_org_entry_batch_waiting(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    svcs = db_select("services", {"id": f"eq.{svc_id}"})
    if not svcs: return jsonify({"waiting": 0}), 200
    waiting = db_count("queue_entries", {"service_id": f"eq.{svc_id}", "status": "eq.waiting"})
    return jsonify({"waiting": waiting, "service_name": svcs[0].get("name","Entry")}), 200

@app.route("/api/org/report/<svc_id>")
def api_org_report(svc_id):
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    entries = db_select("queue_entries", {
        "service_id": f"eq.{svc_id}",
        "status": "in.(completed,no_show,cancelled)",
        "order": "ticket_number.desc", "limit": "200"
    })
    svcs        = db_select("services", {"id": f"eq.{svc_id}"})
    form_fields = []
    if svcs:
        raw = svcs[0].get("user_info_form") or []
        if isinstance(raw, str):
            try: raw = json.loads(raw)
            except: raw = []
        form_fields = raw
    for e in entries:
        if e.get("user_id"):
            p = db_select("profiles", {"id": f"eq.{e['user_id']}"}, single=True) or {}
            e["user_name"] = p.get("full_name") or p.get("email") or "User"
        else:
            e["user_name"] = e.get("guest_name") or "Guest"
        cfd = e.get("custom_form_data") or {}
        if isinstance(cfd, str):
            try: cfd = json.loads(cfd)
            except: cfd = {}
        e["custom_form_data"] = cfd
    return jsonify({"entries": entries, "form_fields": form_fields}), 200

@app.route("/api/org/analytics")
def api_org_analytics():
    uid = session.get("user_id")
    if not uid or session.get("role") != "organization":
        return jsonify({"error": "Unauthorized"}), 403
    svc_id  = request.args.get("service_id","")
    today_s = datetime.now(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0).isoformat()
    base_f  = {"joined_at": f"gte.{today_s}"}
    if svc_id:
        base_f["service_id"] = f"eq.{svc_id}"
    else:
        org_svcs = db_select("services", {"org_id": f"eq.{uid}", "deleted_at": "is.null"})
        if not org_svcs:
            return jsonify({"served_today":0,"waiting_now":0,"avg_wait_min":0,
                            "no_shows_today":0,"avg_rating":None,
                            "throughput_per_hr":0,"peak_hours":[],"feedback":[]}), 200
        svc_ids = ",".join(s["id"] for s in org_svcs)
        base_f["service_id"] = f"in.({svc_ids})"
    served_f  = {**base_f, "status": "eq.completed"}
    served    = db_count("queue_entries", served_f)
    waiting_f = {"service_id": base_f.get("service_id",""), "status": "eq.waiting"}
    if svc_id: waiting_f["service_id"] = f"eq.{svc_id}"
    waiting   = db_count("queue_entries", waiting_f)
    no_shows  = db_count("queue_entries", {**base_f, "status": "eq.no_show"})
    completed_entries = db_select("queue_entries", served_f)
    avg_wait  = 0
    if completed_entries:
        waits = []
        for e in completed_entries:
            if e.get("joined_at") and e.get("completed_at"):
                try:
                    j = datetime.fromisoformat(e["joined_at"].replace("Z","+00:00"))
                    c = datetime.fromisoformat(e["completed_at"].replace("Z","+00:00"))
                    waits.append((c-j).total_seconds()/60)
                except: pass
        avg_wait = round(sum(waits)/len(waits)) if waits else 0
    hours_elapsed = max(1, datetime.now(timezone.utc).hour + 1)
    throughput    = round(served / hours_elapsed, 1)
    fb_filter     = {}
    if svc_id: fb_filter["service_id"] = f"eq.{svc_id}"
    feedbacks_today = db_select("feedbacks", {**fb_filter, "created_at": f"gte.{today_s}"})
    avg_rating = None
    if feedbacks_today:
        ratings    = [f["rating"] for f in feedbacks_today if f.get("rating")]
        avg_rating = round(sum(ratings)/len(ratings),1) if ratings else None
    all_today   = db_select("queue_entries", base_f)
    hour_counts = {}
    for e in all_today:
        try:
            h = datetime.fromisoformat(e["joined_at"].replace("Z","+00:00")).hour
            hour_counts[h] = hour_counts.get(h,0) + 1
        except: pass
    peak_hours = [{"hour": h, "count": c} for h,c in sorted(hour_counts.items())]
    recent_fb  = feedbacks_today[-10:][::-1] if feedbacks_today else []
    for fb in recent_fb:
        if not svc_id:
            s = db_select("services", {"id": f"eq.{fb.get('service_id','')}"}, single=True) or {}
            fb["service_name"] = s.get("name","")
        else:
            fb["service_name"] = ""
    return jsonify({"served_today": served, "waiting_now": waiting, "avg_wait_min": avg_wait,
                    "no_shows_today": no_shows, "avg_rating": avg_rating,
                    "throughput_per_hr": throughput, "peak_hours": peak_hours,
                    "feedback": recent_fb}), 200

# ─── STAFF APIs ────────────────────────────────────────────────
@app.route("/api/staff/access", methods=["POST"])
def api_staff_access():
    d            = request.get_json() or {}
    service_code = (d.get("stage_code") or d.get("service_code") or "").strip().upper()
    staff_name   = (d.get("staff_name") or "").strip()
    pin          = (d.get("pin") or "").strip()
    if not service_code or not staff_name or not pin:
        return jsonify({"error": "Service code, name, and PIN are required."}), 400
    svcs = db_select("services", {"service_code": f"eq.{service_code}"})
    if svcs:
        svc        = svcs[0]
        stored_pin = (svc.get("end_code") or "").strip().upper()
        if stored_pin and stored_pin.upper() != pin.upper():
            return jsonify({"error": "Incorrect PIN."}), 401
        return jsonify({
            "success": True, "stage_id": svc["id"], "stage_name": svc.get("name",""),
            "service_id": svc["id"], "service_name": svc.get("name",""),
            "service_code": svc.get("service_code",""), "staff_name": staff_name,
            "counter_id": None, "counter_number": 1,
            "is_service_mode": True, "time_interval": svc.get("time_interval",5),
        }), 200
    stages = db_select("stages", {"stage_code": f"eq.{service_code}"})
    if not stages:
        return jsonify({"error": "Invalid code. Check the service code and try again."}), 404
    stage      = stages[0]
    stored_pin = stage.get("staff_pin") or ""
    if stored_pin and stored_pin != pin:
        return jsonify({"error": "Incorrect PIN."}), 401
    counter = db_select("staff_counters", {"stage_id": f"eq.{stage['id']}",
                                            "staff_name": f"eq.{staff_name}"})
    if not counter:
        existing = db_select("staff_counters", {"stage_id": f"eq.{stage['id']}"})
        next_num = len(existing) + 1
        db_insert("staff_counters", {
            "stage_id": stage["id"], "service_id": stage["service_id"],
            "staff_name": staff_name, "counter_number": next_num,
            "is_active": True, "created_at": datetime.now(timezone.utc).isoformat()
        })
        counter = db_select("staff_counters", {"stage_id": f"eq.{stage['id']}",
                                                "staff_name": f"eq.{staff_name}"})
    counter_row = counter[0] if counter else {}
    db_update("staff_counters", {"id": counter_row.get("id","x")},
              {"is_active": True, "last_seen": datetime.now(timezone.utc).isoformat()})
    svc_rows = db_select("services", {"id": f"eq.{stage['service_id']}"})
    svc      = svc_rows[0] if svc_rows else {}
    return jsonify({
        "success": True, "stage_id": stage["id"], "stage_name": stage["name"],
        "service_id": stage["service_id"], "service_name": svc.get("name",""),
        "service_code": svc.get("service_code",""), "staff_name": staff_name,
        "counter_id": counter_row.get("id"), "counter_number": counter_row.get("counter_number",1),
        "is_service_mode": False,
    }), 200

@app.route("/api/staff/queue/<stage_id>")
def api_staff_queue(stage_id):
    # New linked service model — stage_id IS the service_id
    entries = db_select("queue_entries", {
        "service_id": f"eq.{stage_id}",
        "status":     "in.(waiting,called,serving)",
        "order":      "ticket_number.asc"
    })
    if not entries:
        # Old stages model — filter by stage_id
        entries = db_select("queue_entries", {
            "stage_id": f"eq.{stage_id}",
            "status":   "in.(waiting,called,serving)",
            "order":    "ticket_number.asc"
        })
    if not entries:
        # Old stages model fallback — FIX: must still filter by stage_id
        stages = db_select("stages", {"id": f"eq.{stage_id}"})
        if stages:
            entries = db_select("queue_entries", {
                "service_id": f"eq.{stages[0]['service_id']}",
                "stage_id":   f"eq.{stage_id}",   # ← critical: stage-scoped only
                "status":     "in.(waiting,called,serving)",
                "order":      "ticket_number.asc"
            })
    for e in entries:
        if e.get("user_id"):
            p = db_select("profiles", {"id": f"eq.{e['user_id']}"}, single=True) or {}
            e["user_name"] = p.get("full_name") or "User"
        else:
            e["user_name"] = e.get("guest_name") or "Guest"
    return jsonify(entries), 200

@app.route("/api/staff/call-next", methods=["POST"])
def api_staff_call_next():
    d          = request.get_json() or {}
    stage_id   = d.get("stage_id")
    counter_id = d.get("counter_id")
    if not stage_id: return jsonify({"error": "stage_id required"}), 400
    svcs = db_select("services", {"id": f"eq.{stage_id}"})
    if svcs:
        svc_id  = stage_id
        waiting = db_select("queue_entries", {
            "service_id": f"eq.{svc_id}", "status": "eq.waiting",
            "order": "ticket_number.asc", "limit": "1"
        })
    else:
        stages = db_select("stages", {"id": f"eq.{stage_id}"})
        if not stages: return jsonify({"error": "Stage not found"}), 404
        svc_id  = stages[0]["service_id"]
        waiting = db_select("queue_entries", {
            "service_id": f"eq.{svc_id}", "stage_id": f"eq.{stage_id}",
            "status": "eq.waiting", "order": "ticket_number.asc", "limit": "1"
        })
    if not waiting: return jsonify({"error": "No one waiting at this stage"}), 404
    entry   = waiting[0]
    force   = d.get("force", False)
    eta_raw = entry.get("estimated_time") or ""
    if eta_raw and not force:
        try:
            eta_dt  = datetime.fromisoformat(eta_raw.replace("Z","+00:00"))
            now_utc = datetime.now(timezone.utc)
            if now_utc < eta_dt:
                mins_left = int((eta_dt - now_utc).total_seconds() / 60)
                return jsonify({"error": f"Not yet time. {mins_left} min remaining.",
                                "eta_display": eta_dt.strftime("%I:%M %p"),
                                "eta_mins_left": mins_left, "can_force": True}), 400
        except: pass
    upd = {"status": "called", "called_at": datetime.now(timezone.utc).isoformat()}
    if counter_id: upd["counter_id"] = counter_id
    db_update("queue_entries", {"id": entry["id"]}, upd)
    entry["status"] = "called"
    if entry.get("user_id"):
        counter_name = ""
        if counter_id:
            crows = db_select("staff_counters", {"id": f"eq.{counter_id}"})
            if crows:
                cnum  = crows[0].get("counter_number",1)
                cname = crows[0].get("staff_name","")
                counter_name = f"Counter {cnum}" + (f" — {cname}" if cname else "")
        body = (f"Ticket {entry['ticket_label']} — Please go to {counter_name}."
                if counter_name else
                f"Ticket {entry['ticket_label']} — Please go to the counter now.")
        send_push_to_user(entry["user_id"], "📢 Your Turn!", body,
                          {"type": "called", "entry_id": entry["id"], "counter_name": counter_name})
    if entry.get("guest_phone"):
        send_sms(entry["guest_phone"],
                 f"📢 QCode: Ticket {entry['ticket_label']} called! Come to the counter now.")
    return jsonify({"success": True, "entry": entry}), 200

@app.route("/api/staff/mark-done", methods=["POST"])
def api_staff_mark_done():
    d        = request.get_json() or {}
    entry_id = d.get("entry_id")
    status   = d.get("status", "completed")
    if not entry_id: return jsonify({"error": "entry_id required"}), 400
    if status not in ("completed","no_show","serving"):
        return jsonify({"error": "Invalid status"}), 400
    upd = {"status": status}
    if status in ("completed","no_show"):
        upd["completed_at"] = datetime.now(timezone.utc).isoformat()
    db_update("queue_entries", {"id": entry_id}, upd)

    if status == "completed":
        rows = db_select("queue_entries", {"id": f"eq.{entry_id}"})
        if rows:
            entry  = rows[0]
            svc_id = entry.get("service_id")
            if svc_id:
                svc_rows = db_select("services", {"id": f"eq.{svc_id}"})
                if svc_rows:
                    svc           = svc_rows[0]
                    next_group    = svc.get("next_service_group") or None
                    has_free_time = bool(svc.get("has_free_time", False))

                    if next_group and has_free_time:
                        if entry.get("user_id"):
                            send_push_to_user(entry["user_id"], "🛒 You're in! Happy Shopping!",
                                              "Tap Ready for Checkout when done.",
                                              {"type": "free_time", "entry_id": entry_id,
                                               "next_service_group": next_group})
                    elif next_group:
                        best_svc, err = _get_next_service(entry, next_group)
                        if best_svc:
                            new_entry, err2 = _create_next_entry(entry, best_svc)
                            if new_entry:
                                if entry.get("user_id"):
                                    send_push_to_user(entry["user_id"],
                                                      f"➡️ Next: {best_svc['name']}",
                                                      f"Ticket {new_entry['ticket_label']} — "
                                                      f"Position #{new_entry['position']}.",
                                                      {"type": "join_next", "entry_id": entry_id,
                                                       "next_service_group": next_group})
                                if entry.get("guest_phone"):
                                    send_sms(entry["guest_phone"],
                                             f"QCode: Next — {best_svc['name']}. "
                                             f"Ticket {new_entry['ticket_label']}, "
                                             f"Position #{new_entry['position']}.")
                        else:
                            print(f"[Staff Mark Done - Next Service Error] {err}")
                    else:
                        if entry.get("user_id"):
                            send_push_to_user(entry["user_id"], "✅ Service Complete!",
                                              "You've been fully served. Please rate your experience.",
                                              {"type": "completed", "entry_id": entry_id})
    return jsonify({"success": True}), 200

# ─── ADMIN APIs ────────────────────────────────────────────────
def require_admin(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if session.get("role") != "super_admin":
            return jsonify({"error": "Unauthorized"}), 403
        return f(*a, **kw)
    return wrapper

@app.route("/api/admin/stats")
@require_admin
def api_admin_stats():
    return jsonify({
        "total_orgs":   db_count("profiles",{"role":"eq.organization"}),
        "approved_orgs":db_count("profiles",{"role":"eq.organization","approval_status":"eq.approved"}),
        "pending_orgs": db_count("profiles",{"role":"eq.organization","approval_status":"eq.pending"}),
        "total_users":  db_count("profiles",{"role":"eq.user"}),
        "total_served": db_count("queue_entries",{"status":"eq.completed"}),
    }), 200

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
    db_update("profiles", {"id": org_id}, {"approval_status": "approved"})
    return jsonify({"success": True}), 200

@app.route("/api/admin/reject-org", methods=["POST"])
@require_admin
def api_reject_org():
    d      = request.get_json() or {}
    org_id = d.get("org_id")
    reason = (d.get("reason") or "").strip()
    if not org_id or not reason: return jsonify({"error": "org_id and reason required"}), 400
    db_update("profiles", {"id": org_id}, {"approval_status": "suspended", "rejection_reason": reason})
    return jsonify({"success": True}), 200

@app.route("/api/admin/suspend-org", methods=["POST"])
@require_admin
def api_suspend_org():
    org_id = (request.get_json() or {}).get("org_id")
    if not org_id: return jsonify({"error": "org_id required"}), 400
    db_update("profiles", {"id": org_id}, {"approval_status": "suspended"})
    return jsonify({"success": True}), 200

@app.route("/api/admin/reinstate-org", methods=["POST"])
@require_admin
def api_reinstate_org():
    org_id = (request.get_json() or {}).get("org_id")
    if not org_id: return jsonify({"error": "org_id required"}), 400
    db_update("profiles", {"id": org_id}, {"approval_status": "approved", "rejection_reason": None})
    return jsonify({"success": True}), 200

@app.route("/api/admin/ban-user", methods=["POST"])
@require_admin
def api_ban_user():
    user_id = (request.get_json() or {}).get("user_id")
    if not user_id: return jsonify({"error": "user_id required"}), 400
    db_update("profiles", {"id": user_id}, {"approval_status": "suspended"})
    return jsonify({"success": True}), 200

@app.route("/api/admin/analytics")
@require_admin
def admin_analytics():
    return jsonify({
        "total_orgs":   db_count("profiles",{"role":"eq.organization"}),
        "approved_orgs":db_count("profiles",{"role":"eq.organization","approval_status":"eq.approved"}),
        "pending_orgs": db_count("profiles",{"role":"eq.organization","approval_status":"eq.pending"}),
        "total_users":  db_count("profiles",{"role":"eq.user"}),
        "total_served": db_count("queue_entries",{"status":"eq.completed"}),
    }), 200

@app.route("/api/admin/all-queues")
@require_admin
def api_admin_all_queues():
    org_id  = request.args.get("org_id","")
    filters = {"order": "joined_at.desc", "limit": "200"}
    if org_id:
        svcs    = db_select("services", {"org_id": f"eq.{org_id}"})
        svc_ids = ",".join(s["id"] for s in svcs)
        if svc_ids: filters["service_id"] = f"in.({svc_ids})"
        else: return jsonify([]), 200
    entries    = db_select("queue_entries", filters)
    svc_cache  = {}; user_cache = {}
    for e in entries:
        sid = e.get("service_id")
        if sid and sid not in svc_cache:
            svcs2 = db_select("services", {"id": f"eq.{sid}"})
            if svcs2:
                s   = svcs2[0]
                org = db_select("profiles",{"id":f"eq.{s['org_id']}"},single=True) or {}
                svc_cache[sid] = {"svc_name": s.get("name",""),
                                   "svc_code": s.get("service_code",""),
                                   "org_name": org.get("org_name","")}
        if sid in svc_cache: e.update(svc_cache[sid])
        uid2 = e.get("user_id")
        if uid2 and uid2 not in user_cache:
            p = db_select("profiles",{"id":f"eq.{uid2}"},single=True) or {}
            user_cache[uid2] = p.get("full_name") or p.get("email") or "User"
        e["user_name"] = user_cache.get(uid2,"User") if uid2 else (e.get("guest_name") or "Walk-in")
    return jsonify(entries), 200

@app.route("/api/admin/all-services")
@require_admin
def api_admin_all_services():
    svcs = db_select("services", {"deleted_at": "is.null", "order": "created_at.desc"})
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
    rows = db_select("sms_joins", {"order": "created_at.desc", "limit": "100"})
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
    db_insert("admin_logs", {"admin_id": session.get("user_id"), "action": d.get("action",""),
                              "target_id": d.get("target_id",""), "target_type": d.get("target_type",""),
                              "details": json.dumps(d.get("details") or {})})
    return jsonify({"success": True}), 200

# ─── SMS WEBHOOK ───────────────────────────────────────────────
@app.route("/api/sms/receive", methods=["POST"])
def receive_sms():
    payload      = request.get_json() or {} if request.is_json else request.form.to_dict()
    from_phone   = (payload.get("phoneNumber") or payload.get("from") or payload.get("From") or
                    payload.get("sender") or payload.get("msisdn") or "Unknown")
    message_body = (payload.get("message") or payload.get("text") or payload.get("Text") or
                    payload.get("Body") or payload.get("body") or "").strip()
    if not message_body: return "", 200
    if message_body.upper().strip() == "CHECKOUT":
        entries = db_select("queue_entries", {"guest_phone": f"eq.{from_phone}",
                                               "status": "eq.waiting",
                                               "order": "joined_at.desc", "limit": "1"})
        if entries:
            db_update("queue_entries", {"id": entries[0]["id"]},
                      {"status": "called", "called_at": datetime.now(timezone.utc).isoformat()})
            send_sms(from_phone, f"✅ QCode: {entries[0].get('ticket_label','—')} marked ready. "
                                  "Please go to the counter.")
        return "", 200
    code_match = re.search(r'\b(QC[-\s]?[A-Z0-9]{6})\b', message_body.upper())
    if not code_match:
        bare = re.search(r'\b([A-Z0-9]{5,8})\b', message_body.upper())
        if bare:
            service_code = bare.group(1)
            name_part    = re.sub(r'\b'+bare.group(1)+r'\b','',message_body,flags=re.IGNORECASE).strip()
        else:
            _log_sms(from_phone,message_body,None,None,"invalid_code")
            send_sms(from_phone,"Invalid code. Text your QCode service code (e.g. PINNA) to join.")
            return "",200
    else:
        raw          = code_match.group(1).replace(" ","-")
        service_code = raw if raw.startswith("QC-") else "QC-"+raw[-6:]
        name_part    = re.sub(r'\b'+re.escape(code_match.group(1))+r'\b','',
                               message_body, flags=re.IGNORECASE).strip()
    guest_name = name_part.title() if name_part else f"SMS User ({from_phone[-4:]})"
    try:
        svcs = db_select("services",{"service_code":f"eq.{service_code}","status":"eq.open"})
        if not svcs:
            _log_sms(from_phone,message_body,service_code,None,"invalid_code")
            send_sms(from_phone,f"Code '{service_code}' not found or queue is closed.")
            return "",200
        service  = svcs[0]; svc_id = service["id"]
        max_u    = service.get("max_users") or 9999
        current  = db_count("queue_entries",{"service_id":f"eq.{svc_id}",
                                              "status":"in.(waiting,called,serving)"})
        if current >= max_u:
            _log_sms(from_phone,message_body,service_code,None,"failed")
            send_sms(from_phone,f"Sorry, {service['name']} queue is full.")
            return "",200
        n        = (service.get("ticket_counter") or 0)+1
        label    = f"{service.get('ticket_prefix','Q')}{str(n).zfill(3)}"
        db_update("services",{"id":svc_id},{"ticket_counter":n})
        pos      = current+1
        interval = service.get("time_interval") or 5
        wait_min = pos * interval
        eta      = (datetime.now(timezone.utc)+timedelta(minutes=wait_min)).isoformat()
        eta_time = (datetime.now(timezone.utc)+timedelta(minutes=wait_min)).strftime("%I:%M %p")
        end_code = _rcode(4)
        required = {"service_id":svc_id,"user_id":None,"guest_name":guest_name,
                    "guest_phone":from_phone,"ticket_label":label,"ticket_number":n,
                    "status":"waiting","estimated_time":eta,
                    "join_method":"sms","joined_at":datetime.now(timezone.utc).isoformat()}
        optional = {"end_code": end_code, "pushback_count": 0}
        res      = db_insert("queue_entries", _safe_payload("queue_entries", required, optional))
        entry_id = res["data"][0]["id"] if res.get("ok") and res["data"] else None
        _log_sms(from_phone,message_body,service_code,entry_id,"processed")
        org = db_select("profiles",{"id":f"eq.{service['org_id']}"},single=True) or {}
        send_sms(from_phone,
                 f"QCode ✅\nService: {service['name']} @ {org.get('org_name','')}\n"
                 f"Ticket: {label} | End code: {end_code}\n"
                 f"Position: #{pos} | ~{wait_min} mins (~{eta_time})\n"
                 f"Reply CHECKOUT when ready to check out.")
        return "",200
    except Exception as e:
        print(f"[SMS Error] {e}")
        _log_sms(from_phone,message_body,service_code,None,"failed")
        send_sms(from_phone,"Something went wrong. Please try again.")
        return "",200

# ─── PUBLIC ────────────────────────────────────────────────────
@app.route("/api/public/stats")
def api_public_stats():
    return jsonify({
        "approved_orgs":  db_count("profiles",{"role":"eq.organization","approval_status":"eq.approved"}),
        "total_served":   db_count("queue_entries",{"status":"eq.completed"}),
        "active_services":db_count("services",{"status":"eq.open","deleted_at":"is.null"}),
    }), 200

@app.route("/api/notify/org", methods=["POST"])
def notify_org(): return jsonify({"sent": True})

@app.route("/health")
def health():
    return jsonify({"status":"ok","time":datetime.now().isoformat()}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
