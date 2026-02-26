"""
app.py — QCode SMS Gateway + Web Backend
========================================
Handles web pages, admin dashboard, and incoming SMS via Africa's Talking.

HOW TO RUN:
  pip install flask supabase africastalking python-dotenv
  python app.py

DEPLOY:
  - Render: set Start Command to "python app.py"
  - Africa's Talking SMS webhook → POST /sms/incoming
"""

import os
import re
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from supabase import create_client, Client
from dotenv import load_dotenv

# Africa's Talking (optional)
try:
    import africastalking
    AT_AVAILABLE = True
except ImportError:
    AT_AVAILABLE = False
    print("⚠ africastalking not installed. Run: pip install africastalking")

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET", "super-secret-dev-key")

# -----------------------------
# Supabase
# -----------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# -----------------------------
# Africa's Talking SMS
# -----------------------------
AT_USERNAME  = os.getenv("AT_USERNAME", "sandbox")
AT_API_KEY   = os.getenv("AT_API_KEY", "")
AT_SENDER_ID = os.getenv("AT_SENDER_ID", "QCode")

if AT_AVAILABLE:
    africastalking.initialize(AT_USERNAME, AT_API_KEY)
    sms = africastalking.SMS

# -----------------------------
# Admin Config
# -----------------------------
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

def require_admin(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_super_admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper

# -----------------------------
# Helpers
# -----------------------------
def send_sms(phone: str, message: str) -> bool:
    if not AT_AVAILABLE:
        print(f"[SMS MOCK] To: {phone}\n{message}")
        return True
    try:
        sms.send(message, [phone], sender_id=AT_SENDER_ID)
        return True
    except Exception as e:
        print(f"[SMS ERROR] {e}")
        return False

def normalize_phone(phone: str) -> str:
    phone = re.sub(r"[^\d+]", "", phone)
    if phone.startswith("0"):
        phone = "+234" + phone[1:]
    elif not phone.startswith("+"):
        phone = "+" + phone
    return phone

def calculate_eta(position: int, interval_minutes: int) -> str:
    total_mins = position * interval_minutes
    eta_time = datetime.now(timezone.utc) + timedelta(minutes=total_mins)
    return f"~{total_mins} min ({eta_time.strftime('%I:%M %p UTC')})"

def find_active_entry(phone: str):
    result = supabase.table("queue_entries") \
        .select("*") \
        .eq("phone", phone) \
        .in_("status", ["waiting", "called", "serving"]) \
        .order("created_at", desc=True).limit(1).execute()
    return result.data[0] if result.data else None

def get_position(service_id, ticket_number):
    res = supabase.table("queue_entries") \
        .select("id", count="exact") \
        .eq("service_id", service_id) \
        .eq("status", "waiting") \
        .lt("ticket_number", ticket_number).execute()
    return (res.count or 0) + 1

# -----------------------------
# Web Pages
# -----------------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register-user")
def register_user():
    return render_template("register-user.html")

@app.route("/register-org")
def register_org():
    return render_template("register-org.html")

@app.route("/login-user")
def login_user():
    return render_template("login-user.html")

@app.route("/login-org")
def login_org():
    return render_template("login-org.html")

@app.route("/dashboard-user")
def dashboard_user():
    return render_template("user.html")

@app.route("/dashboard-org")
def dashboard_org():
    return render_template("org.html")

@app.route("/guest-ticket")
def guest_ticket():
    return render_template("guest.html")

# Redirect .html URLs to avoid 404
@app.route("/register-user.html")
def redirect_user_html(): return redirect(url_for("register_user"))
@app.route("/register-org.html")
def redirect_org_html(): return redirect(url_for("register_org"))
@app.route("/login-user.html")
def redirect_login_user_html(): return redirect(url_for("login_user"))
@app.route("/login-org.html")
def redirect_login_org_html(): return redirect(url_for("login_org"))

# -----------------------------
# Admin
# -----------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password")
        if password == ADMIN_PASSWORD:
            session["is_super_admin"] = True
            return redirect(url_for("admin_dashboard"))
        return "❌ Invalid credentials", 401
    return render_template("login-admin.html")

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/admin/dashboard")
@require_admin
def admin_dashboard():
    services = supabase.table("services").select("*").execute().data
    return render_template("super_admin.html", services=services)

# -----------------------------
# SMS Handlers
# -----------------------------
def handle_join(phone: str, code: str, guest_name=None) -> str:
    result = supabase.table("services").select("*").eq("service_code", code.upper()).execute()
    if not result.data:
        return f"❌ Service '{code.upper()}' not found."
    svc = result.data[0]

    # Check if already in queue
    existing = supabase.table("queue_entries") \
        .select("*") \
        .eq("service_id", svc['id']) \
        .eq("phone", phone) \
        .in_("status", ["waiting", "called", "serving"]) \
        .execute()
    if existing.data:
        entry = existing.data[0]
        return f"⚠ Already in queue: {entry['ticket_label']} ({entry['status']})"

    # Increment ticket
    new_counter = svc.get("ticket_counter", 0) + 1
    ticket_label = f"{svc.get('ticket_prefix','Q')}{str(new_counter).zfill(3)}"
    supabase.table("services").update({"ticket_counter": new_counter}).eq("id", svc['id']).execute()

    # Insert queue entry
    position = 1 + (supabase.table("queue_entries").select("id", count="exact")
                    .eq("service_id", svc['id']).eq("status", "waiting").execute().count or 0)
    eta = calculate_eta(position, svc.get("time_interval", 5))

    supabase.table("queue_entries").insert({
        "service_id": svc['id'],
        "guest_name": guest_name or f"SMS:{phone[-4:]}",
        "phone": phone,
        "ticket_label": ticket_label,
        "ticket_number": new_counter,
        "status": "waiting",
        "estimated_time": (datetime.now(timezone.utc) + timedelta(minutes=position*svc.get("time_interval",5))).isoformat(),
        "join_method": "sms"
    }).execute()

    return f"✅ Joined '{svc['name']}'! Ticket: {ticket_label} | Position: {position} | ETA: {eta}"

def handle_status(phone: str) -> str:
    entry = find_active_entry(phone)
    if not entry: return "ℹ Not in any queue."
    position = get_position(entry['service_id'], entry['ticket_number'])
    svc_name = entry.get('service_name', 'Queue')
    eta = calculate_eta(position, entry.get('time_interval', 5))
    return f"📋 {svc_name} Update | Ticket: {entry['ticket_label']} | Position: {position} | ETA: {eta}"

def handle_cancel(phone: str) -> str:
    entry = find_active_entry(phone)
    if not entry: return "ℹ Not in any queue."
    if entry['status'] in ("called","serving"): return "⚠ Cannot cancel, already being served."
    supabase.table("queue_entries").update({"status":"cancelled"}).eq("id", entry['id']).execute()
    return f"✅ Cancelled ticket {entry['ticket_label']}"

def handle_help() -> str:
    return "📱 Commands: [CODE] JOIN queue | STATUS | CANCEL | HELP"

@app.route("/sms/incoming", methods=["POST"])
def sms_incoming():
    data = request.form if request.form else request.json or {}
    phone = normalize_phone(data.get("from", ""))
    msg = (data.get("text", "") or "").strip().upper()
    print(f"[SMS IN] {phone}: {msg}")

    if not phone or not msg: return jsonify({'status':'ignored'}), 200
    reply = ""
    if msg == "STATUS": reply = handle_status(phone)
    elif msg == "CANCEL": reply = handle_cancel(phone)
    elif msg in ("HELP","HI","HELLO","?"): reply = handle_help()
    elif msg.startswith("JOIN "):
        parts = msg.split(" ",2)
        code = parts[1]
        name = parts[2].title() if len(parts)>2 else None
        reply = handle_join(phone, code, guest_name=name)
    elif re.match(r"^[A-Z0-9]{4,8}$", msg):
        reply = handle_join(phone, msg)
    else:
        reply = "❓ Unknown command. Reply HELP for instructions."

    send_sms(phone, reply)
    return jsonify({'status':'processed','reply_sent':True}), 200

@app.route("/health", methods=["GET"])
def health(): return jsonify({"status":"ok","time":datetime.now().isoformat()})

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT",5000))
    debug = os.getenv("FLASK_ENV","development") != "production"
    print(f"QCode Gateway running on port {port} | Debug={debug} | AT Available={AT_AVAILABLE}")
    app.run(host="0.0.0.0", port=port, debug=debug)
