import os
import re
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from supabase import create_client, Client
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps

# -----------------------------
# Load environment variables
# -----------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super-secret-dev-key")

# -----------------------------
# Supabase Configuration
# -----------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise Exception("Supabase credentials missing")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# -----------------------------
# Environment Config
# -----------------------------
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

if not WEBHOOK_SECRET:
    raise Exception("WEBHOOK_SECRET not set")

# -----------------------------
# Utilities
# -----------------------------
def normalize_phone(phone):
    digits = re.sub(r"\D", "", phone)
    if digits.startswith("0"):
        digits = "234" + digits[1:]
    if not digits.startswith("234") and len(digits) == 10:
        digits = "234" + digits
    return "+" + digits

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_super_admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated

# -----------------------------
# Basic Routes
# -----------------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/health")
def health():
    return "OK", 200

# -----------------------------
# User & Org Routes
# -----------------------------
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

# -----------------------------
# Redirects for old .html URLs
# -----------------------------
@app.route("/register-user.html")
def redirect_register_user():
    return redirect(url_for("register_user"))

@app.route("/register-org.html")
def redirect_register_org():
    return redirect(url_for("register_org"))

@app.route("/login-user.html")
def redirect_login_user():
    return redirect(url_for("login_user"))

@app.route("/login-org.html")
def redirect_login_org():
    return redirect(url_for("login_org"))

# -----------------------------
# Admin Login & Dashboard
# -----------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password")
        if password == ADMIN_PASSWORD:
            session["is_super_admin"] = True
            session["login_time"] = datetime.utcnow().isoformat()
            return redirect(url_for("super_admin_dashboard"))
        return "Invalid credentials", 401
    return render_template("login-admin.html")

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/admin/dashboard")
@require_admin
def super_admin_dashboard():
    services = supabase.table("services").select("*").execute().data
    return render_template("super_admin.html", services=services)

# -----------------------------
# SMS Webhook
# -----------------------------
@app.route("/sms/incoming", methods=["POST"])
def incoming_sms():
    secret = request.headers.get("X-Webhook-Secret")
    if secret != WEBHOOK_SECRET:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json or request.form
    phone = normalize_phone(data.get("from") or data.get("sender", ""))
    message = (data.get("text") or data.get("message", "")).strip().upper()
    if not phone or not message:
        return jsonify({"error": "Missing phone or message"}), 400

    # Commands: JOIN <CODE> or STATUS
    parts = message.split()
    try:
        if parts[0] == "JOIN" and len(parts) >= 2:
            service_code = parts[1]
            guest_name = " ".join(parts[2:]) if len(parts) > 2 else "SMS Guest"
            return handle_join(phone, service_code, guest_name)
        elif parts[0] == "STATUS":
            return handle_status(phone)
        else:
            return jsonify({"message": "Invalid command. Use JOIN <CODE> or STATUS."}), 200
    except Exception as e:
        print(f"Webhook Error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# -----------------------------
# JOIN Logic
# -----------------------------
def handle_join(phone, service_code, guest_name):
    svc = supabase.table("services").select("*").eq("service_code", service_code).single().execute()
    if not svc.data:
        return jsonify({"message": "Service not found"}), 200

    svc_id = svc.data['id']

    # Already waiting?
    existing = supabase.table("queue_entries").select("*")\
        .eq("phone", phone).eq("service_id", svc_id).eq("status", "waiting").execute()
    if existing.data:
        return jsonify({"message": "Already in queue"}), 200

    # Increment ticket
    rpc_res = supabase.rpc("increment_ticket_counter", {"service_id_input": svc_id}).execute()
    if not rpc_res.data:
        return jsonify({"error": "Failed to generate ticket"}), 500

    ticket_info = rpc_res.data[0]
    ticket_label = f"{ticket_info['ticket_prefix']}{str(ticket_info['new_counter']).zfill(3)}"
    time_interval = ticket_info.get('time_interval') or 5

    # Calculate ETA
    ahead = supabase.table("queue_entries").select("*", count="exact")\
        .eq("service_id", svc_id).eq("status", "waiting").execute()
    wait_mins = ahead.count * time_interval if ahead.count else 0
    eta = datetime.utcnow() + timedelta(minutes=wait_mins)

    # Insert queue entry
    supabase.table("queue_entries").insert({
        "service_id": svc_id,
        "guest_name": guest_name,
        "phone": phone,
        "ticket_label": ticket_label,
        "ticket_number": ticket_info['new_counter'],
        "status": "waiting",
        "estimated_time": eta.isoformat(),
        "join_method": "sms"
    }).execute()

    return jsonify({
        "message": f"Joined successfully. Ticket: {ticket_label}, Est. wait: {wait_mins} mins."
    }), 200

# -----------------------------
# STATUS Logic
# -----------------------------
def handle_status(phone):
    entry = supabase.table("queue_entries").select("*")\
        .eq("phone", phone).eq("status", "waiting")\
        .order("created_at", desc=False).limit(1).execute()
    if not entry.data:
        return jsonify({"message": "No active queue entry"}), 200

    svc_id = entry.data[0]['service_id']
    created_at = entry.data[0]['created_at']
    ahead = supabase.table("queue_entries").select("*", count="exact")\
        .eq("service_id", svc_id).eq("status", "waiting")\
        .lt("created_at", created_at).execute()
    count_ahead = ahead.count if ahead.count else 0

    return jsonify({"message": f"There are {count_ahead} people ahead of you."}), 200

# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
