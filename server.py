#!/usr/bin/env python3
import os, json, sqlite3, hashlib, secrets
from pathlib import Path
from flask import Flask, request, session, redirect, jsonify, send_from_directory
from authlib.integrations.flask_client import OAuth
import stripe
import bcrypt

ROOT = Path(__file__).parent
# Use RENDER_DATA_DIR if set and exists, otherwise use project dir
_data_dir = Path(os.environ.get("RENDER_DATA_DIR", str(ROOT)))
if not _data_dir.exists():
    _data_dir = ROOT
DB = _data_dir / "users.db"

def load_env():
    # Start with OS environment variables (used on Render)
    keys = dict(os.environ)
    # Override/supplement with .env file if it exists (used locally)
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                keys[k.strip()] = v.strip()
    return keys

ENV = load_env()

app = Flask(__name__, static_folder=str(ROOT))
_sk = ENV.get("SECRET_KEY", "")
if not _sk:
    _sk = secrets.token_hex(32)
    with open(ROOT / ".env", "a") as f:
        f.write(f"\nSECRET_KEY={_sk}\n")
app.secret_key = _sk
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

TEST_MODE = False  # Set to False for live payments
stripe.api_key = ENV.get("STRIPE_TEST_SECRET_KEY" if TEST_MODE else "STRIPE_SECRET_KEY", "")

# ── OAuth ──────────────────────────────────────────────────────────────────────
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=ENV.get("GOOGLE_CLIENT_ID"),
    client_secret=ENV.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# ── Database ───────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                email    TEXT UNIQUE NOT NULL,
                name     TEXT,
                password TEXT,
                google_id TEXT,
                credits  INTEGER DEFAULT 0,
                created  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()

init_db()

def get_user(user_id):
    with get_db() as db:
        return db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

def get_user_by_email(email):
    with get_db() as db:
        return db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

def deduct_credit(user_id):
    with get_db() as db:
        db.execute("UPDATE users SET credits = credits - 1 WHERE id=? AND credits > 0", (user_id,))
        db.commit()
        row = db.execute("SELECT credits FROM users WHERE id=?", (user_id,)).fetchone()
        return row["credits"] if row else 0

def add_credits(user_id, amount):
    with get_db() as db:
        db.execute("UPDATE users SET credits = credits + ? WHERE id=?", (amount, user_id))
        db.commit()

# ── Static files ───────────────────────────────────────────────────────────────
@app.route("/")
@app.route("/morphopsychology.html")
def index():
    return send_from_directory(ROOT, "morphopsychology.html")

# ── Config (Anthropic key + user state) ───────────────────────────────────────
@app.route("/config")
def config():
    user_id = session.get("user_id")
    user = get_user(user_id) if user_id else None
    return jsonify({
        "key": ENV.get("ANTHROPIC_API_KEY", ""),
        "stripe_key": ENV.get("STRIPE_TEST_PUBLISHABLE_KEY" if TEST_MODE else "STRIPE_PUBLISHABLE_KEY", ""),
        "user": {"name": user["name"], "email": user["email"], "credits": user["credits"]} if user else None
    })

# ── Auth: email/password ───────────────────────────────────────────────────────
@app.route("/auth/register", methods=["POST"])
def register():
    data = request.json
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    name = (data.get("name") or email.split("@")[0]).strip()
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if get_user_by_email(email):
        return jsonify({"error": "Email already registered"}), 400
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    with get_db() as db:
        cur = db.execute("INSERT INTO users (email, name, password) VALUES (?,?,?)", (email, name, hashed))
        db.commit()
        session["user_id"] = cur.lastrowid
    user = get_user(session["user_id"])
    return jsonify({"name": user["name"], "email": user["email"], "credits": user["credits"]})

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.json
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    user = get_user_by_email(email)
    if not user or not user["password"]:
        return jsonify({"error": "Invalid email or password"}), 401
    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Invalid email or password"}), 401
    session["user_id"] = user["id"]
    return jsonify({"name": user["name"], "email": user["email"], "credits": user["credits"]})

@app.route("/auth/logout")
def logout():
    session.clear()
    return redirect("/")

# ── Auth: Google OAuth ─────────────────────────────────────────────────────────
@app.route("/auth/google")
def auth_google():
    redirect_uri = request.host_url.rstrip("/") + "/auth/google/callback"
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def auth_google_callback():
    token = google.authorize_access_token()
    info  = token.get("userinfo") or google.userinfo()
    email = info["email"].lower()
    name  = info.get("name") or email.split("@")[0]
    google_id = info["sub"]
    user = get_user_by_email(email)
    if user:
        with get_db() as db:
            db.execute("UPDATE users SET google_id=? WHERE id=?", (google_id, user["id"]))
            db.commit()
        session["user_id"] = user["id"]
    else:
        with get_db() as db:
            cur = db.execute("INSERT INTO users (email, name, google_id) VALUES (?,?,?)", (email, name, google_id))
            db.commit()
            session["user_id"] = cur.lastrowid
    return redirect("/")

# ── Credits check before analysis ─────────────────────────────────────────────
@app.route("/use-credit", methods=["POST"])
def use_credit():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not_logged_in"}), 401
    user = get_user(user_id)
    if not user or user["credits"] < 1:
        return jsonify({"error": "no_credits"}), 402
    remaining = deduct_credit(user_id)
    return jsonify({"ok": True, "credits": remaining})

# ── Admin: give credits ────────────────────────────────────────────────────────
ADMIN_KEY = ENV.get("ADMIN_KEY", "")

@app.route("/admin/give-credits", methods=["POST"])
def admin_give_credits():
    if not ADMIN_KEY or request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "unauthorized"}), 401
    data = request.json
    email   = (data.get("email") or "").strip().lower()
    credits = int(data.get("credits", 1))
    user = get_user_by_email(email)
    if not user:
        return jsonify({"error": "user not found"}), 404
    add_credits(user["id"], credits)
    updated = get_user_by_email(email)
    return jsonify({"ok": True, "email": email, "credits": updated["credits"]})

# ── Stripe checkout ────────────────────────────────────────────────────────────
PRICES = {
    "single": {"amount": 500,  "credits": 1,  "label": "1 analysis"},
    "pack":   {"amount": 1500, "credits": 10, "label": "10 analyses"},
}

@app.route("/create-checkout", methods=["POST"])
def create_checkout():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not_logged_in"}), 401
    pack = request.json.get("pack", "single")
    if pack not in PRICES:
        return jsonify({"error": "invalid pack"}), 400
    p = PRICES[pack]
    base = request.host_url.rstrip("/")
    checkout = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{"price_data": {
            "currency": "eur",
            "product_data": {"name": f"Readyourface.net — {p['label']}"},
            "unit_amount": p["amount"],
        }, "quantity": 1}],
        mode="payment",
        success_url=base + "/payment-success?session_id={CHECKOUT_SESSION_ID}&pack=" + pack,
        cancel_url=base + "/",
        metadata={"user_id": str(user_id), "pack": pack},
    )
    return jsonify({"url": checkout.url})

@app.route("/payment-success")
def payment_success():
    session_id = request.args.get("session_id")
    pack       = request.args.get("pack", "single")
    user_id    = session.get("user_id")
    if session_id and user_id and pack in PRICES:
        try:
            cs = stripe.checkout.Session.retrieve(session_id)
            if cs.payment_status == "paid":
                add_credits(user_id, PRICES[pack]["credits"])
        except Exception:
            pass
    return redirect("/")

# ── Stripe webhook (backup confirmation) ──────────────────────────────────────
@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig     = request.headers.get("Stripe-Signature", "")
    secret  = ENV.get("STRIPE_WEBHOOK_SECRET", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, secret) if secret else json.loads(payload)
    except Exception:
        return "", 400
    if event.get("type") == "checkout.session.completed":
        cs   = event["data"]["object"]
        meta = cs.get("metadata", {})
        uid  = int(meta.get("user_id", 0))
        pack = meta.get("pack", "single")
        if uid and pack in PRICES and cs.get("payment_status") == "paid":
            add_credits(uid, PRICES[pack]["credits"])
    return "", 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8787))
    print(f"Open http://localhost:{port}/")
    app.run(host="0.0.0.0", port=port, debug=False)
