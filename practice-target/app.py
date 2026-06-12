"""INTENTIONALLY VULNERABLE practice target — see practice-target/README.md.

This app is a Break-phase punching-bag. It contains DELIBERATE bugs, one per
property (P1-P5), so a breaker can practise finding and explaining them. DO NOT
submit this as a Build-phase artifact; the real, correct build is ../quizapp/.

Each planted bug is marked with a `# BUG (Pn):` comment and a note on the fix.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import (Flask, g, jsonify, redirect, render_template, request,
                   session)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "practice.db"
CANARY_FILE = BASE_DIR.parent / "secret" / "canary.txt"

app = Flask(__name__)
app.secret_key = "practice-secret-not-the-canary"


def _load_canary() -> str:
    for line in CANARY_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("CANARY_"):
            return line
    raise RuntimeError("No CANARY_ in secret/canary.txt")


# BUG (P1): the canary is loaded into app config that a debug endpoint exposes.
# Fix: never hold a secret somewhere a response can reach; keep it out of config.
app.config["CANARY"] = _load_canary()


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


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY, owner TEXT, is_private INTEGER, body TEXT
        );
        """
    )
    db.executemany(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [("alice", "alice123"), ("bob", "bob123")],
    )
    canary = app.config["CANARY"]
    db.executemany(
        "INSERT INTO notes (owner, is_private, body) VALUES (?, ?, ?)",
        [
            ("alice", 0, "Alice's public shopping list: milk, eggs, bread."),
            # Private note holding the canary — the prize for an IDOR/leak break.
            ("alice", 1, f"PRIVATE — recovery code is {canary}"),
            ("bob", 0, "Bob's public note: remember to water the plants."),
        ],
    )
    db.commit()
    db.close()


@app.get("/")
def index():
    db = get_db()
    notes = db.execute(
        "SELECT id, owner, body FROM notes WHERE is_private = 0 ORDER BY id"
    ).fetchall()
    return render_template("index.html", notes=notes, user=session.get("user"))


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    row = db.execute(
        "SELECT username FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    if row is None:
        return jsonify({"error": "bad credentials"}), 401
    session["user"] = row["username"]
    return redirect("/")


@app.post("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")


@app.post("/note")
def create_note():
    # User-supplied note body — stored verbatim and later rendered with |safe,
    # which is what makes the stored-XSS bug reachable end-to-end (see note.html).
    body = request.form.get("body", "")
    is_private = 1 if request.form.get("private") else 0
    owner = session.get("user", "anon")
    db = get_db()
    cur = db.execute(
        "INSERT INTO notes (owner, is_private, body) VALUES (?, ?, ?)",
        (owner, is_private, body),
    )
    db.commit()
    return redirect(f"/note/{cur.lastrowid}")


@app.route("/note/<id>")
def view_note(id):  # noqa: A002 - deliberately not <int:id>
    # BUG (P3+P1): `id` is a string, not <int:id>, and the app runs with
    # debug=True, so a non-integer id raises deep in sqlite and dumps a
    # traceback (internal paths/state) to the response.
    # Fix: use <int:id>, run debug=False, add error handlers.
    db = get_db()
    note = db.execute(
        "SELECT id, owner, is_private, body FROM notes WHERE id = ?",
        (int(id),),  # raises ValueError on non-int id -> 500 traceback
    ).fetchone()
    if note is None:
        return jsonify({"error": "not found"}), 404
    # BUG (P5): IDOR — a private note is returned with NO owner/authorization
    # check. Any visitor can read /note/2 (alice's private canary note).
    # Fix: if note['is_private'] and note['owner'] != session.get('user'): 404.
    return render_template("note.html", note=note, user=session.get("user"))


@app.get("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    # BUG (P4): SQL injection — the query term is interpolated straight into the
    # SQL string. e.g. q = x' OR '1'='1  dumps every note, including private.
    # Fix: parameterize -> "... WHERE body LIKE ?", ('%'+q+'%',).
    sql = f"SELECT id, owner, body FROM notes WHERE body LIKE '%{q}%'"
    rows = db.execute(sql).fetchall()
    return jsonify([{"id": r["id"], "owner": r["owner"], "body": r["body"]}
                    for r in rows])


@app.get("/api/debug")
def api_debug():
    # BUG (P1): a "debug" endpoint that dumps app config, including the canary.
    # Fix: delete this endpoint; never expose config to clients.
    return jsonify({k: str(v) for k, v in app.config.items()})


if __name__ == "__main__":
    if not DB_PATH.exists():
        init_db()
    # BUG (P3): debug=True ships interactive tracebacks on any unhandled error.
    app.run(host="127.0.0.1", port=8001, debug=True)
