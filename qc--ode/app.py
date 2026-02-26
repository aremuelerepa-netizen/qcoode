"""
app.py — QCode SMS Gateway Backend
===================================
Handles incoming SMS messages via Africa's Talking webhook.

HOW TO RUN:
  pip install flask supabase africastalking python-dotenv
  python app.py

DEPLOY:
  - Railway: git push (auto-detects Flask)
  - Render:  set Start Command to "python app.py"
  - Heroku:  uses Procfile → "web: python app.py"

Then point your Africa's Talking SMS callback URL to:
  https://your-domain.com/sms/incoming
"""

import os
import re
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from supabase import create_client, Client
from dotenv import load_dotenv

# ── Try to import Africa's Talking (optional at startup) ──────
try:
    import africastalking
    AT_AVAILABLE = True
except ImportError:
    AT_AVAILABLE = False
    print("⚠  africastalking not installed. Run: pip install africastalking")

load_dotenv()

app = Flask(__name__)

# ── CONFIG — set these in a .env file ────────────────────────
SUPABASE_URL      = os.getenv('SUPABASE_URL',  'https://YOUR_PROJECT_ID.supabase.co')
SUPABASE_KEY      = os.getenv('SUPABASE_KEY',  'YOUR_SERVICE_ROLE_KEY')  # Use service role for backend!
AT_USERNAME       = os.getenv('AT_USERNAME',   'sandbox')                # Your AT username
AT_API_KEY        = os.getenv('AT_API_KEY',    'YOUR_AT_API_KEY')
AT_SENDER_ID      = os.getenv('AT_SENDER_ID',  'QCode')                  # Your approved sender ID
APP_SECRET        = os.getenv('APP_SECRET',    'change-this-secret')

# ── Init clients ──────────────────────────────────────────────
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

if AT_AVAILABLE:
    africastalking.initialize(AT_USERNAME, AT_API_KEY)
    sms = africastalking.SMS


# ────────────────────────────────────────────────────────────
# HELPERS
# ────────────────────────────────────────────────────────────

def send_sms(phone: str, message: str) -> bool:
    """Send an SMS reply via Africa's Talking."""
    if not AT_AVAILABLE:
        print(f"[SMS MOCK] To: {phone}\n{message}")
        return True
    try:
        response = sms.send(message, [phone], sender_id=AT_SENDER_ID)
        print(f"[SMS SENT] {phone}: {response}")
        return True
    except Exception as e:
        print(f"[SMS ERROR] {e}")
        return False


def normalize_phone(phone: str) -> str:
    """Normalize phone number to E.164 format."""
    phone = re.sub(r'[^\d+]', '', phone)
    if phone.startswith('0'):
        phone = '+234' + phone[1:]  # Default to Nigeria — change to your country
    elif not phone.startswith('+'):
        phone = '+' + phone
    return phone


def calculate_eta(position: int, interval_minutes: int) -> str:
    """Return a human-readable ETA string."""
    total_mins = position * interval_minutes
    eta_time   = datetime.now(timezone.utc)
    from datetime import timedelta
    eta_time  += timedelta(minutes=total_mins)
    local_time = eta_time.strftime('%I:%M %p')
    return f"~{total_mins} min ({local_time} UTC)"


def get_position(service_id: str, ticket_number: int) -> int:
    """Count how many people are waiting ahead of this ticket."""
    result = supabase.table('queue_entries') \
        .select('id', count='exact') \
        .eq('service_id', service_id) \
        .eq('status', 'waiting') \
        .lt('ticket_number', ticket_number) \
        .execute()
    return (result.count or 0) + 1


def find_active_entry(phone: str):
    """Find an active queue entry by phone number."""
    result = supabase.table('queue_entries') \
        .select('*, services(name, service_code, time_interval, status)') \
        .eq('phone', phone) \
        .in_('status', ['waiting', 'called', 'serving']) \
        .order('joined_at', desc=True) \
        .limit(1) \
        .execute()
    return result.data[0] if result.data else None


def log_sms(phone: str, code: str, entry_id, raw: str, reply: str):
    """Log SMS join to the database."""
    try:
        supabase.table('sms_joins').insert({
            'phone':        phone,
            'service_code': code,
            'entry_id':     entry_id,
            'raw_message':  raw,
            'reply_sent':   reply,
        }).execute()
    except Exception as e:
        print(f"[LOG ERROR] {e}")


# ────────────────────────────────────────────────────────────
# COMMAND HANDLERS
# ────────────────────────────────────────────────────────────

def handle_join(phone: str, code: str, guest_name: str = None) -> str:
    """Join a queue via SMS. Returns reply message."""

    # 1. Find service
    result = supabase.table('services') \
        .select('*, profiles(org_name, approval_status)') \
        .eq('service_code', code.upper()) \
        .execute()

    if not result.data:
        return f"❌ No service found with code '{code.upper()}'. Check the code and try again."

    svc = result.data[0]

    # 2. Check org approved
    if svc.get('profiles', {}).get('approval_status') != 'approved':
        return f"❌ This organization is not currently active."

    # 3. Check service status
    if svc['status'] == 'closed':
        return f"❌ '{svc['name']}' queue is closed."
    if svc['status'] == 'paused':
        return f"⏸ '{svc['name']}' queue is paused. Please try again soon."

    # 4. Check max users
    if svc.get('max_users'):
        count_res = supabase.table('queue_entries') \
            .select('id', count='exact') \
            .eq('service_id', svc['id']) \
            .in_('status', ['waiting', 'called', 'serving']) \
            .execute()
        if (count_res.count or 0) >= svc['max_users']:
            return f"❌ '{svc['name']}' queue is full ({svc['max_users']} max)."

    # 5. Check already in queue
    existing = supabase.table('queue_entries') \
        .select('ticket_label, status') \
        .eq('service_id', svc['id']) \
        .eq('phone', phone) \
        .in_('status', ['waiting', 'called', 'serving']) \
        .execute()

    if existing.data:
        entry = existing.data[0]
        return f"⚠ You're already in '{svc['name']}' queue! Ticket: {entry['ticket_label']} (Status: {entry['status']}). Reply STATUS to check your position."

    # 6. Increment ticket counter atomically
    svc_fresh = supabase.table('services') \
        .select('ticket_counter, ticket_prefix') \
        .eq('id', svc['id']) \
        .execute().data[0]

    new_counter = svc_fresh['ticket_counter'] + 1
    supabase.table('services') \
        .update({'ticket_counter': new_counter}) \
        .eq('id', svc['id']) \
        .execute()

    ticket_label = f"{svc_fresh['ticket_prefix']}{str(new_counter).zfill(3)}"

    # 7. Calculate ETA
    waiting_res = supabase.table('queue_entries') \
        .select('id', count='exact') \
        .eq('service_id', svc['id']) \
        .eq('status', 'waiting') \
        .execute()
    position    = (waiting_res.count or 0) + 1
    eta_str     = calculate_eta(position, svc.get('time_interval', 5))
    from datetime import datetime, timezone, timedelta
    eta_dt      = datetime.now(timezone.utc) + timedelta(minutes=position * svc.get('time_interval', 5))

    # 8. Insert queue entry
    entry_res = supabase.table('queue_entries').insert({
        'service_id':     svc['id'],
        'user_id':        None,
        'guest_name':     guest_name or f"SMS:{phone[-4:]}",
        'phone':          phone,
        'ticket_label':   ticket_label,
        'ticket_number':  new_counter,
        'status':         'waiting',
        'estimated_time': eta_dt.isoformat(),
        'join_method':    'sms',
    }).execute()

    entry_id = entry_res.data[0]['id'] if entry_res.data else None

    reply = (
        f"✅ Joined '{svc['name']}'!\n"
        f"Ticket: {ticket_label}\n"
        f"Position: {position} | ETA: {eta_str}\n"
        f"By: {svc.get('profiles', {}).get('org_name', '')}\n"
        f"Reply STATUS to check. Reply CANCEL to leave."
    )

    log_sms(phone, code.upper(), entry_id, code, reply)
    return reply


def handle_status(phone: str) -> str:
    """Check queue status for this phone number."""
    entry = find_active_entry(phone)

    if not entry:
        return "ℹ You are not currently in any queue. Text a service code (e.g. VISA24) to join."

    svc = entry.get('services', {})
    position = get_position(entry['service_id'], entry['ticket_number'])
    eta_str  = calculate_eta(position, svc.get('time_interval', 5))

    status_msg = {
        'waiting': f"Position: {position} | ETA: {eta_str}",
        'called':  "📢 YOU ARE BEING CALLED! Please proceed to the counter NOW.",
        'serving': "✅ You are currently being served.",
    }.get(entry['status'], f"Status: {entry['status']}")

    return (
        f"📋 {svc.get('name', 'Queue')} Update\n"
        f"Ticket: {entry['ticket_label']}\n"
        f"{status_msg}"
    )


def handle_cancel(phone: str) -> str:
    """Cancel the active queue entry for this phone number."""
    entry = find_active_entry(phone)

    if not entry:
        return "ℹ You are not currently in any queue."

    if entry['status'] in ('called', 'serving'):
        return "⚠ You cannot cancel — you are already being called/served!"

    supabase.table('queue_entries') \
        .update({'status': 'cancelled', 'completed_at': datetime.now(timezone.utc).isoformat()}) \
        .eq('id', entry['id']) \
        .execute()

    return f"✅ You have left '{entry['services']['name']}' queue. Ticket {entry['ticket_label']} cancelled."


def handle_help() -> str:
    """Return help message."""
    return (
        "📱 QCode SMS Commands:\n"
        "• [CODE]    — Join queue (e.g. VISA24)\n"
        "• STATUS    — Check your position\n"
        "• CANCEL    — Leave your queue\n"
        "• HELP      — Show this message\n"
        "Visit qcode.app for more options."
    )


# ────────────────────────────────────────────────────────────
# ROUTES
# ────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'ok', 'service': 'QCode SMS Gateway', 'time': datetime.now().isoformat()})


@app.route('/sms/incoming', methods=['POST'])
def sms_incoming():
    """
    Africa's Talking SMS webhook.
    AT sends: from, to, text, id, linkId, date
    """
    data     = request.form if request.form else request.json or {}
    phone    = normalize_phone(data.get('from', ''))
    raw_text = (data.get('text', '') or '').strip()
    msg      = raw_text.upper().strip()

    print(f"[SMS IN] From: {phone} | Message: {raw_text}")

    if not phone or not msg:
        return jsonify({'status': 'ignored'}), 200

    # ── Route command ─────────────────────────────────────
    reply = ''

    if msg == 'STATUS':
        reply = handle_status(phone)

    elif msg == 'CANCEL':
        reply = handle_cancel(phone)

    elif msg in ('HELP', 'HI', 'HELLO', '?'):
        reply = handle_help()

    elif re.match(r'^[A-Z0-9]{4,8}$', msg):
        # Looks like a service code — try to join
        reply = handle_join(phone, msg)

    elif msg.startswith('JOIN '):
        # Format: "JOIN VISA24 John Doe"
        parts = msg.split(' ', 2)
        code  = parts[1] if len(parts) > 1 else ''
        name  = parts[2].title() if len(parts) > 2 else None
        reply = handle_join(phone, code, guest_name=name)

    else:
        reply = (
            f"❓ Unknown command: '{raw_text[:20]}'\n"
            "Reply HELP for instructions, or send your service code to join."
        )

    # ── Send reply ────────────────────────────────────────
    print(f"[SMS OUT] To: {phone} | {reply}")
    send_sms(phone, reply)

    # AT expects a 200 OK
    return jsonify({'status': 'processed', 'reply_sent': True}), 200


@app.route('/sms/delivery', methods=['POST'])
def sms_delivery():
    """Africa's Talking delivery report webhook (optional)."""
    data = request.form if request.form else request.json or {}
    print(f"[DELIVERY] {data.get('id')} → {data.get('status')}")
    return jsonify({'status': 'ok'}), 200


@app.route('/sms/test', methods=['GET'])
def sms_test():
    """
    Manual test endpoint (development only).
    Usage: /sms/test?phone=+2348001234567&msg=VISA24
    """
    if os.getenv('FLASK_ENV') == 'production':
        return jsonify({'error': 'Disabled in production'}), 403

    phone = request.args.get('phone', '+2340000000001')
    msg   = request.args.get('msg',   'HELP')
    result = {'phone': phone, 'message': msg}

    phone = normalize_phone(phone)
    msg_u = msg.upper().strip()

    if msg_u == 'STATUS':
        result['reply'] = handle_status(phone)
    elif msg_u == 'CANCEL':
        result['reply'] = handle_cancel(phone)
    elif msg_u in ('HELP', '?'):
        result['reply'] = handle_help()
    elif re.match(r'^[A-Z0-9]{4,8}$', msg_u):
        result['reply'] = handle_join(phone, msg_u)
    else:
        result['reply'] = 'Unknown command'

    return jsonify(result)


# ────────────────────────────────────────────────────────────
# MAIN
# ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'development') != 'production'
    print(f"""
╔══════════════════════════════════════════════╗
║         QCode SMS Gateway Running            ║
║  Port:  {port}                                   ║
║  Debug: {debug}                               ║
║  AT Available: {AT_AVAILABLE}                       ║
╚══════════════════════════════════════════════╝
    Webhook URL → POST /sms/incoming
    Test URL    → GET  /sms/test?phone=+234xxx&msg=VISA24
    Health      → GET  /health
""")
    app.run(host='0.0.0.0', port=port, debug=debug)
