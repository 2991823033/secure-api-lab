"""
Database bootstrap for the Secure REST API lab.

Creates the SQLite schema and seeds a demo account + demo posts.
Run directly:  python db.py
"""

import sqlite3

from werkzeug.security import generate_password_hash


def init_db():
    conn = sqlite3.connect("app.db")
    c = conn.cursor()

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS posts (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            title   TEXT NOT NULL,
            content TEXT NOT NULL,
            author  TEXT NOT NULL
        )
        """
    )

    # Seed a demo user (admin / admin123) — password stored as a scrypt hash.
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", generate_password_hash("admin123", method="scrypt")),
        )

    # Seed a demo post whose content includes an HTML string — useful to
    # demonstrate XSS escaping on the /api/data endpoint.
    c.execute("SELECT COUNT(*) FROM posts")
    if c.fetchone()[0] == 0:
        c.execute(
            "INSERT INTO posts (title, content, author) VALUES (?, ?, ?)",
            (
                "Welcome",
                "<script>alert('xss')</script> — this text must be escaped",
                "admin",
            ),
        )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized. Demo account: admin / admin123")
