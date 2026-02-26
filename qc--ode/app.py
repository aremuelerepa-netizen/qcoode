import os
import re
import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from supabase import create_client, Client
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "super-secret-key")

# --- CONFIGURATION ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") # Use Service Role for atomic DB ops
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET") # Set this in your SMS gateway & Env
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") # Your special admin password

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- UTILITIES ---

def normalize_phone(phone):
    """Clean phone numbers and ensure E.164 format."""
    phone = re.sub(r'\D', '', phone)
    if not phone.startswith('+'):
        # Default to +234 if 11 digits starting with 0, else keep as is
        if len(phone) == 11 and phone.startswith('0'):
            return '+234' + phone[1:]
        return '+' + phone
    return phone

def require_webhook_secret(f):
    """Security decorator for incoming SMS webhooks."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        secret = request.headers.get('X-Webhook-Secret')
        if not secret or secret != WEBHOOK_SECRET:
            return jsonify({"error": "Unauthorized"}), 403
        return f(*args, **kwargs)
    return decorated_function

def send_sms_via_gateway(phone, message):
    """
    Replace this with your specific SMS Gateway API logic.
    """
    # Example for a generic gateway
    gateway_url = os.environ.get("SMS_GATEWAY_URL")
    api_key = os.environ.get("SMS_GATEWAY_API_KEY")
    
    try:
        # payload = {"to": phone, "message": message, "key": api_key}
        # requests.post(gateway_url, json=payload, timeout=5)
        print(f"SMS SENT TO {phone}: {message}") # Logging for dev
    except Exception as e:
        print(f"Failed to send SMS: {e}")

# --- SMS COMMAND LOGIC ---

@app.route("/sms/incoming", methods=["POST"])
@require_webhook_secret
def handle_sms():
    # Adjust based on your Gateway's POST format (request.json or request.form)
    data = request.get_json() or request.form
    sender = normalize_phone(data.get("from") or data.get("sender"))
    text = (data.get("text") or data.get("message", "")).strip().upper()

    try:
        # 1. COMMAND: STATUS
        if text == "STATUS":
            entry = supabase.table("queue_entries").select("*, services(name)").eq("phone", sender).eq("status", "waiting").order("created_at", desc=True).limit(1).execute()
            if not entry.data:
                send_sms_via_gateway(sender, "QCode: You are not in any active queue.")
            else:
                svc_id = entry.data[0]['service_id']
                ahead = supabase.table("queue_entries").select("*", count="exact").eq("service_id", svc_id).eq("status", "waiting").lt("created_at", entry.data[0]['created_at']).execute()
                send_sms_via_gateway(sender, f"QCode: {entry.data[0]['services']['name']}. Position: {ahead.count + 1}. Ticket: {entry.data[0]['ticket_label']}")

        # 2. COMMAND: JOIN [CODE] [NAME]
        elif text.startswith("JOIN"):
            parts = text.split(" ", 2)
            if len(parts) < 2:
                send_sms_via_gateway(sender, "Usage: JOIN [CODE] [NAME]. Example: JOIN VISA24 John Doe")
                return "OK"
            
            code = parts[1]
            name = parts[2] if len(parts) > 2 else "SMS Guest"
            
            # Fetch Service
            svc = supabase.table("services").select("*, profiles(approval_status)").eq("service_code", code).single().execute()
            if not svc.data:
                send_sms_via_gateway(sender, "Error: Invalid service code.")
                return "OK"
            
            if svc.data['profiles']['approval_status'] != 'approved' or svc.data['status'] != 'open':
                send_sms_via_gateway(sender, "Error: This service is currently unavailable.")
                return "OK"

            # Check Duplicates
            dup = supabase.table("queue_entries").select("id").eq("service_id", svc.data['id']).eq("phone", sender).eq("status", "waiting").execute()
            if dup.data:
                send_sms_via_gateway(sender, "You are already in this queue.")
                return "OK"

            # ATOMIC INCREMENT (Using the SQL function created earlier)
            rpc_res = supabase.rpc("increment_ticket_counter", {"service_id_input": svc.data['id']}).execute()
            new_val = rpc_res.data[0] # Returns {new_counter, ticket_prefix, time_interval}

            label = f"{new_val['ticket_prefix']}{str(new_val['new_counter']).zfill(3)}"
            
            # Calculate ETA
            ahead = supabase.table("queue_entries").select("*", count="exact").eq("service_id", svc.data['id']).eq("status", "waiting").execute()
            wait_mins = (ahead.count) * (new_val['time_interval'] or 5)
            eta = datetime.utcnow() + timedelta(minutes=wait_mins)

            # Insert Entry
            supabase.table("queue_entries").insert({
                "service_id": svc.data['id'],
                "guest_name": name,
                "phone": sender,
                "ticket_label": label,
                "ticket_number": new_val['new_counter'],
                "status": "waiting",
                "estimated_time": eta.isoformat(),
                "join_method": "sms"
            }).execute()

            send_sms_via_gateway(sender, f"Success! You joined {svc.data['name']}. Ticket: {label}. Est. Wait: {wait_mins} mins.")

        else:
            send_sms_via_gateway(sender, "QCode: Command not recognized. Reply HELP for commands.")

    except Exception as e:
        print(f"Critical Webhook Error: {e}")
    
    return "OK", 200

# --- ADMIN AUTH & ROUTES ---

@app.route("/super-admin-login", methods=["POST"])
def admin_login():
    """Custom login route for the Super Admin using Environment Password."""
    email = request.form.get("email")
    password = request.form.get("password")
    
    # We allow the super admin to login through the organization login page
    # by checking if the password matches the secret env variable
    if password == ADMIN_PASSWORD:
        session['is_super_admin'] = True
        return redirect("/admin-dashboard") # Redirect to your super_admin.html
    
    return "Invalid Admin Credentials", 401

@app.route("/admin-dashboard")
def admin_dashboard():
    if not session.get('is_super_admin'):
        return redirect("/")
    return render_template("super_admin.html")

@app.route("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    # In production, this is ignored by Gunicorn
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
