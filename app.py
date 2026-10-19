"""
Secure REST API — Work 1 (HDU Information Security Lab)

Endpoints:
    POST /auth/login      -> authenticate user, issue JWT
    POST /auth/register   -> register a new user
    GET  /api/data        -> return list of posts (protected, JWT required)

Security measures:
    - SQLi  : parameterized queries (never string-concatenate SQL)
    - XSS   : all user data returned to the client is escaped
    - Auth  : JWT issued on login, verified by a middleware decorator
    - Hashing: passwords stored with scrypt, never in plaintext
"""

import os
import sqlite3
import datetime

import jwt
from flask import Flask, request, jsonify
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# NOTE: in production this must come from an environment variable / secret manager.
# (At least 32 bytes for HMAC-SHA256 per RFC 7518.)
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "dev-only-insecure-secret-key-change-me-in-production-1234567890"
)
app.config["TOKEN_EXPIRY_HOURS"] = 1


def get_db():
    """Open a SQLite connection with dict-like rows."""
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Endpoint 1 — POST /auth/login
# Authenticates the user and returns a signed JWT.
# ---------------------------------------------------------------------------
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("login")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "login and password are required"}), 400

    db = get_db()
    # Parameterized query: the '?' placeholder prevents SQL injection.
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    # Compare against the scrypt hash — never against a plaintext password.
    if user and check_password_hash(user["password_hash"], password):
        token = jwt.encode(
            {
                "sub": user["username"],
                "exp": datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(hours=app.config["TOKEN_EXPIRY_HOURS"]),
            },
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )
        return jsonify({"token": token})

    return jsonify({"error": "invalid credentials"}), 401


# ---------------------------------------------------------------------------
# Endpoint 3 (self-defined) — POST /auth/register
# Creates a new account, storing only the bcrypt hash of the password.
# ---------------------------------------------------------------------------
@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    # scrypt hashing (one of the algorithms allowed by the lab manual):
    # the password is never stored in plaintext.
    password_hash = generate_password_hash(password, method="scrypt")

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409

    return jsonify({"message": "user created"}), 201


# ---------------------------------------------------------------------------
# JWT middleware — verifies the token on every protected endpoint.
# ---------------------------------------------------------------------------
def require_auth(f):
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        try:
            payload = jwt.decode(
                auth.split(" ", 1)[1],
                app.config["SECRET_KEY"],
                algorithms=["HS256"],
            )
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


# ---------------------------------------------------------------------------
# Endpoint 2 — GET /api/data
# Returns posts. Requires a valid JWT. User data is escaped to prevent XSS.
# ---------------------------------------------------------------------------
@app.route("/api/data")
@require_auth
def get_data():
    db = get_db()
    posts = db.execute(
        "SELECT id, title, content, author FROM posts"
    ).fetchall()

    # escape() neutralises HTML in any user-supplied value before it is
    # returned to the client, preventing reflected/stored XSS.
    result = [
        {
            "id": p["id"],
            "title": escape(p["title"]),
            "content": escape(p["content"]),
            "author": escape(p["author"]),
        }
        for p in posts
    ]
    return jsonify(result)


if __name__ == "__main__":
    from db import init_db

    init_db()
    app.run(host="0.0.0.0", port=5000)
