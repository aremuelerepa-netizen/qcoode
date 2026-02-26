import os
import re
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from supabase import create_client, Client
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super-secret-dev-key")

# -----------------------------
# Supabase Config
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

    # Nigerian default handling example
    if digits.startswith("0"):
        digits = "234" + digits[1:]

    if not digits.startswith("234") and len(digits) == 10:
        digits = "234" + digits

    return "+" + digits


def is_admin():
    return session.get("is_super_admin") is True


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
# Admin Login
# -----------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password")

        if password and password == ADMIN_PASSWORD:
            session["is_super_admin"] = True
            session["login_time"] = datetime.utcnow().isoformat()
            return redirect(url_for("super_admin_dashboard"))

        return "Invalid credentials", 401

    return render_template("login-admin.html")

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
    
@app.route("/admin")
def super_admin_dashboard():
    if not is_admin():
        return redirect(url_for("admin_login"))

    services = supabase.table("services").select("*").execute().data
    return render_template("super_admin.html", services=services)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("home"))


# -----------------------------
# SMS Webhook (CRITICAL CORE)
# -----------------------------
@app.route("/sms/incoming", methods=["POST"])
def incoming_sms():
    secret = request.headers.get("X-Webhook-Secret")

    if secret != WEBHOOK_SECRET:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    if not data:
        return jsonify({"error": "Invalid payload"}), 400

    phone = normalize_phone(data.get("from", ""))
    message = data.get("text", "").strip().upper()

    if not phone or not message:
        return jsonify({"error": "Missing phone or message"}), 400

    # Format expected:
    # JOIN <service_code>
    # STATUS

    parts = message.split()

    if parts[0] == "JOIN" and len(parts) == 2:
        return handle_join(phone, parts[1])

    if parts[0] == "STATUS":
        return handle_status(phone)

    return jsonify({"message": "Invalid command"}), 200


# -----------------------------
# JOIN LOGIC
# -----------------------------
def handle_join(phone, service_code):
    svc = (
        supabase.table("services")
        .select("*")
        .eq("code", service_code)
        .execute()
    )

    if not svc.data:
        return jsonify({"message": "Service not found"}), 200

    svc_id = svc.data[0]["id"]

    # Check if already waiting
    existing = (
        supabase.table("queue_entries")
        .select("*")
        .eq("phone", phone)
        .eq("service_id", svc_id)
        .eq("status", "waiting")
        .execute()
    )

    if existing.data:
        return jsonify({"message": "Already in queue"}), 200

    # Increment ticket safely
    rpc_res = supabase.rpc(
        "increment_ticket_counter",
        {"service_id_input": svc_id}
    ).execute()

    if not rpc_res.data:
        return jsonify({"error": "Failed to generate ticket"}), 500

    new_ticket_number = rpc_res.data[0]

    insert_res = supabase.table("queue_entries").insert({
        "phone": phone,
        "service_id": svc_id,
        "ticket_number": new_ticket_number,
        "status": "waiting"
    }).execute()

    if not insert_res.data:
        return jsonify({"error": "Failed to join queue"}), 500

    return jsonify({
        "message": f"Joined successfully. Your ticket number is {new_ticket_number}"
    }), 200


# -----------------------------
# STATUS LOGIC
# -----------------------------
def handle_status(phone):
    entry = (
        supabase.table("queue_entries")
        .select("*")
        .eq("phone", phone)
        .eq("status", "waiting")
        .order("created_at", desc=False)
        .limit(1)
        .execute()
    )

    if not entry.data:
        return jsonify({"message": "No active queue entry"}), 200

    svc_id = entry.data[0]["service_id"]
    created_at = entry.data[0]["created_at"]

    ahead = (
        supabase.table("queue_entries")
        .select("*", count="exact")
        .eq("service_id", svc_id)
        .eq("status", "waiting")
        .lt("created_at", created_at)
        .execute()
    )

    count_ahead = ahead.count if ahead.count is not None else 0

    return jsonify({
        "message": f"There are {count_ahead} people ahead of you."
    }), 200


# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
