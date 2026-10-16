"""Intentionally VULNERABLE Flask app — LAB USE ONLY.

This target exists so the SentinelX attack lab has something to attack.
It demonstrates real vulnerabilities (SQL injection, reflected XSS, weak
credentials) so the detection engine has realistic log traffic to fire on.

DO NOT deploy this anywhere reachable. DO NOT copy these patterns into
real code. Run it only inside the isolated lab container/network.
"""

from __future__ import annotations

import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)

DB_PATH = os.environ.get("LAB_DB_PATH", "/app/lab.db")

SEED_USERS = [
    ("admin", "password123"),
    ("labuser", "lab12345"),
]


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create and seed the users table if it does not exist yet."""
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "password TEXT NOT NULL)"
    )
    for username, password in SEED_USERS:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
            (username, password),
        )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return (
        "<h1>SentinelX lab target</h1>"
        "<p>Vulnerable demo app. LAB USE ONLY.</p>"
        "<ul>"
        "<li><a href='/login'>/login</a> — login form (POST user/pass)</li>"
        "<li><a href='/search?q=hello'>/search?q=...</a> — echo search</li>"
        "<li><a href='/admin'>/admin</a> — admin area</li>"
        "</ul>"
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return (
            "<h1>Login</h1>"
            "<form method='post'>"
            "User: <input name='user'><br>"
            "Pass: <input name='pass' type='password'><br>"
            "<input type='submit' value='Login'>"
            "</form>"
        )

    user = request.form.get("user", "")
    password = request.form.get("pass", "")

    # VULNERABLE BY DESIGN — do not copy this pattern.
    # The credentials are interpolated straight into the SQL string.
    query = (
        f"SELECT id, username FROM users "
        f"WHERE username = '{user}' AND password = '{password}'"
    )
    conn = get_db()
    row = conn.execute(query).fetchone()
    conn.close()

    if row:
        return f"<h1>Welcome, {row['username']}!</h1><p>Login successful.</p>"
    return "<h1>Invalid credentials</h1><p>Invalid username or password.</p>", 401


@app.route("/search")
def search():
    # VULNERABLE BY DESIGN — do not copy this pattern.
    # The raw query string is reflected into the HTML unescaped (reflected XSS).
    q = request.args.get("q", "")
    return f"<h1>Search results</h1><p>You searched for: {q}</p>"


@app.route("/admin", methods=["GET", "POST"])
def admin():
    # VULNERABLE BY DESIGN — do not copy this pattern.
    # Weak, hardcoded credentials gate the "admin" area.
    if request.method == "GET":
        return (
            "<h1>Admin</h1>"
            "<form method='post'>"
            "User: <input name='user'><br>"
            "Pass: <input name='pass' type='password'><br>"
            "<input type='submit' value='Login'>"
            "</form>"
        )
    user = request.form.get("user", "")
    password = request.form.get("pass", "")
    if user == "admin" and password == "password123":
        return "<h1>Admin panel</h1><p>Super secret admin content.</p>"
    return "<h1>Access denied</h1>", 403


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
