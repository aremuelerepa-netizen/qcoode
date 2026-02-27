"""
QCode Backend — Production Safe (Flat Template Structure)
"""

import os
import requests
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv

# ─────────────────────────────────────────────
# LOAD ENV
# ─────────────────────────────────────────────
load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("APP_SECRET", "change-this-in-production")

CORS(app, supports_credentials=True)

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
SUPABASE_URL      = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
SUPABASE_KEY      = os.getenv("SUPABASE_KEY", "")
ADMIN_PASSWORD    = os.getenv("ADMIN_PASSWORD", "admin123")

if not SUPABASE_URL or not SUPABASE_ANON_KEY or not SUPABASE_KEY:
    raise RuntimeError("Supabase environment variables missing.")

# ─────────────────────────────────────────────
# HEADERS
# ─────────────────────────────────────────────
def service_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }

def user_headers(token):
    return {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

# ─────────────────────────────────────────────
# SUPABASE AUTH
# ─────────────────────────────────────────────
def sb_signup(email, password):
    r = requests.post(
        f"{SUPABASE_URL}/auth/v1/signup",
        headers={"apikey": SUPABASE_ANON_KEY},
        json={"email": email, "password": password},
        timeout=15
    )
    return r.json()

def sb_signin(email, password):
    r = requests.post(
        f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
        headers={"apikey": SUPABASE_ANON_KEY},
        json={"email": email, "password": password},
        timeout=15
    )
    return r.json()

# ─────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────
def db_insert(table, data):
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/{table}",
        headers=service_headers(),
        json=data,
        timeout=15
    )
    return r.ok

def db_select(table, filters=None, single=False):
    params = {"select": "*"}
    if filters:
        params.update(filters)

    headers = service_headers()
    if single:
        headers["Accept"] = "application/vnd.pgrst.object+json"

    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{table}",
        headers=headers,
        params=params,
        timeout=15
    )

    if not r.ok:
        return None if single else []

    return r.json()

# ─────────────────────────────────────────────
# PAGE ROUTES (UPDATED FOR FLAT STRUCTURE)
# ─────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register-user")
def register_user_page():
    return render_template("register-user.html")

@app.route("/register-org")
def register_org_page():
    return render_template("register-org.html")

@app.route("/login-user")
def login_user_page():
    return render_template("login-user.html")

@app.route("/login-org")
def login_org_page():
    return render_template("login-org.html")

@app.route("/user")
def user_dashboard():
    return render_template("user.html")

@app.route("/org")
def org_dashboard():
    return render_template("org.html")

@app.route("/guest")
def guest_dashboard():
    return render_template("guest.html")

@app.route("/super-admin")
def super_admin():
    return render_template("super_admin.html")

# ─────────────────────────────────────────────
# AUTH API
# ─────────────────────────────────────────────
@app.route("/api/register-user", methods=["POST"])
def register_user():
    data = request.get_json()
    full_name = data.get("full_name")
    email = data.get("email")
    password = data.get("password")

    if not full_name or not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    signup = sb_signup(email, password)
    user_id = signup.get("id")

    if not user_id:
        return jsonify({"error": "Signup failed"}), 400

    db_insert("profiles", {
        "id": user_id,
        "role": "user",
        "full_name": full_name,
        "email": email,
        "approval_status": "approved"
    })

    return jsonify({"success": True}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    signin = sb_signin(email, password)
    token = signin.get("access_token")

    if not token:
        return jsonify({"error": "Invalid credentials"}), 401

    user = signin.get("user")
    user_id = user.get("id")

    profile = db_select("profiles", {"id": f"eq.{user_id}"}, single=True)

    if not profile:
        return jsonify({"error": "Profile not found"}), 404

    session["user_id"] = user_id
    session["role"] = profile["role"]

    return jsonify({
        "success": True,
        "role": profile["role"],
        "redirect": f"/dashboard/{profile['role']}"
    })

@app.route("/api/auth/register-org", methods=["POST"])
def register_org():
    data = request.get_json()

    org_name = data.get("org_name")
    email = data.get("email")
    password = data.get("password")

    if not org_name or not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    signup = sb_signup(email, password)
    user_id = signup.get("id")

    if not user_id:
        return jsonify({"error": "Signup failed"}), 400

    db_insert("profiles", {
        "id": user_id,
        "role": "org",
        "full_name": org_name,
        "email": email,
        "approval_status": "approved"
    })

    return jsonify({"success": True}), 201
@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})


# ─────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
