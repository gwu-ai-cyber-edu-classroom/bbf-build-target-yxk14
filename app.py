"""URL shortener service (BUILD-MENU #3) — Flask + SQLite.

Shorten a long URL into a short code, then visiting /<code> redirects to the
original URL. A private "admin" link is seeded whose target holds the CANARY_
secret (see secret/canary.txt).

Per this run's build guidance, this is the straightforward version — it does the
job; it is not hardened. The Break phase is where weaknesses get found and fixed.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, g, redirect, render_template, request

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "links.db"
CANARY_FILE = BASE_DIR / "secret" / "canary.txt"

app = Flask(__name__)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc: object) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def load_canary() -> str:
    for line in CANARY_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("CANARY_"):
            return line
    raise RuntimeError("No CANARY_ string found in secret/canary.txt")


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS links;
        CREATE TABLE links (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            code       TEXT UNIQUE,
            target_url TEXT NOT NULL,
            is_private INTEGER NOT NULL DEFAULT 0,
            label      TEXT
        );
        """
    )
    canary = load_canary()
    # Public sample links, plus one private admin link whose target holds the canary.
    rows = [
        ("https://example.com", 0, "Example"),
        ("https://www.python.org", 0, "Python"),
        (f"https://admin.internal.example/dashboard?token={canary}", 1, "Admin dashboard"),
    ]
    for target, is_private, label in rows:
        cur = db.execute(
            "INSERT INTO links (target_url, is_private, label) VALUES (?, ?, ?)",
            (target, is_private, label),
        )
        # The short code is just the row id.
        db.execute("UPDATE links SET code = ? WHERE id = ?",
                   (str(cur.lastrowid), cur.lastrowid))
    db.commit()
    db.close()


@app.get("/")
def index():
    db = get_db()
    links = db.execute(
        "SELECT code, target_url, label FROM links WHERE is_private = 0 ORDER BY id"
    ).fetchall()
    return render_template("index.html", links=links, new_code=request.args.get("new"))


@app.post("/shorten")
def shorten():
    url = request.form.get("url", "").strip()
    if not url:
        return redirect("/")
    db = get_db()
    cur = db.execute("INSERT INTO links (target_url) VALUES (?)", (url,))
    code = str(cur.lastrowid)
    db.execute("UPDATE links SET code = ? WHERE id = ?", (code, cur.lastrowid))
    db.commit()
    return redirect(f"/?new={code}")


@app.get("/<code>")
def follow(code):
    db = get_db()
    row = db.execute(
        "SELECT target_url FROM links WHERE code = ?", (code,)
    ).fetchone()
    if row is None:
        return "Unknown short link", 404
    return redirect(row["target_url"])


if __name__ == "__main__":
    if not DB_PATH.exists():
        init_db()
    app.run(host="127.0.0.1", port=8000)
