"""Quiz / poll app (BUILD-MENU #21) — Flask + SQLite.

The CANARY_ secret lives in the *answer key* of a private quiz. The whole point
of the app is the tension in SPEC.md P1: the server must USE the answer key to
grade you, but must NEVER reveal it (not the correct answers, not the canary) on
any output channel.

Security stance (so this is a CORRECT build, not a pre-broken one):
  P1  Confidentiality — the answer key and canary are loaded server-side and are
      never serialized into any response. Grading returns score + right/wrong
      only, never the correct option, never the canary.
  P2  Correctness    — valid submissions are graded correctly.
  P3  Input discipline — malformed / oversized / out-of-range input gets a clean
      400; the server stays up. Debug mode is OFF so stack traces never ship.
  P4  No injection   — all SQL is parameterized; the quiz id is an <int:> route
      converter, so no path/SQL injection through it. No eval/template-from-input.
  P5  Authz + output safety — private quizzes require the owner token (guessing
      the id returns 404, no IDOR). Jinja2 autoescaping is on; no user-supplied
      free text is reflected into HTML, and we never use |safe.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from flask import Flask, abort, g, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "quiz.db"
# The canary lives one level up, in the shared secret/ dir (see SPEC.md).
CANARY_FILE = BASE_DIR.parent / "secret" / "canary.txt"

# Owner token for the private quiz. A breaker who only guesses the quiz id must
# NOT get in (P5); they would also need this token, which is never emitted.
PRIVATE_OWNER_TOKEN = "owner-3b9f2c7a1d8e4f60"

app = Flask(__name__)
# P3: cap request bodies so an oversized payload is rejected, not OOM'd.
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64 KiB is plenty for answer arrays.


# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #
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


def _load_canary() -> str:
    """Read the first CANARY_ string from the shared secret file."""
    for line in CANARY_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("CANARY_"):
            return line
    raise RuntimeError("No CANARY_ string found in secret/canary.txt")


def init_db() -> None:
    """Create the schema and seed quizzes. Idempotent."""
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS quizzes;
        DROP TABLE IF EXISTS questions;
        DROP TABLE IF EXISTS answer_keys;

        CREATE TABLE quizzes (
            id          INTEGER PRIMARY KEY,
            title       TEXT NOT NULL,
            is_private  INTEGER NOT NULL DEFAULT 0,
            owner_token TEXT
        );
        CREATE TABLE questions (
            id            INTEGER PRIMARY KEY,
            quiz_id       INTEGER NOT NULL,
            position      INTEGER NOT NULL,
            text          TEXT NOT NULL,
            options_json  TEXT NOT NULL,
            correct_index INTEGER NOT NULL
        );
        -- The answer key's canary. This table is read ONLY for grading and is
        -- never serialized into a response (P1).
        CREATE TABLE answer_keys (
            quiz_id INTEGER PRIMARY KEY,
            canary  TEXT NOT NULL
        );
        """
    )

    canary = _load_canary()

    quizzes = [
        (1, "General Knowledge", 0, None),
        (2, "Python Basics", 0, None),
        # The private quiz: its answer key holds the canary.
        (3, "Internal Certification Exam", 1, PRIVATE_OWNER_TOKEN),
    ]
    db.executemany(
        "INSERT INTO quizzes (id, title, is_private, owner_token) VALUES (?, ?, ?, ?)",
        quizzes,
    )

    questions = [
        # quiz_id, position, text, options, correct_index
        (1, 0, "What is the capital of France?",
         ["Berlin", "Paris", "Madrid", "Rome"], 1),
        (1, 1, "Which planet is known as the Red Planet?",
         ["Venus", "Jupiter", "Mars", "Saturn"], 2),
        (1, 2, "How many continents are there?",
         ["5", "6", "7", "8"], 2),

        (2, 0, "Which keyword defines a function in Python?",
         ["func", "def", "function", "lambda"], 1),
        (2, 1, "What does len([1, 2, 3]) return?",
         ["2", "3", "4", "Error"], 1),
        (2, 2, "Which type is immutable?",
         ["list", "dict", "set", "tuple"], 3),

        (3, 0, "Internal policy code for data classification is?",
         ["A-1", "B-2", "C-3", "D-4"], 2),
        (3, 1, "Mandatory review cycle (days)?",
         ["30", "60", "90", "180"], 2),
    ]
    db.executemany(
        "INSERT INTO questions (quiz_id, position, text, options_json, correct_index) "
        "VALUES (?, ?, ?, ?, ?)",
        [(q, p, t, json.dumps(o), c) for (q, p, t, o, c) in questions],
    )

    db.execute(
        "INSERT INTO answer_keys (quiz_id, canary) VALUES (?, ?)",
        (3, canary),
    )
    db.commit()
    db.close()


# --------------------------------------------------------------------------- #
# Authorization
# --------------------------------------------------------------------------- #
def _fetch_quiz_or_404(quiz_id: int) -> sqlite3.Row:
    """Return the quiz row, enforcing P5. Private quizzes require the matching
    owner token; otherwise we 404 (not 403) so existence isn't confirmed."""
    db = get_db()
    quiz = db.execute(
        "SELECT id, title, is_private, owner_token FROM quizzes WHERE id = ?",
        (quiz_id,),
    ).fetchone()
    if quiz is None:
        abort(404)
    if quiz["is_private"]:
        token = request.args.get("token", "")
        # Constant-time-ish compare; tokens are short so this is fine.
        if not token or token != quiz["owner_token"]:
            abort(404)
    return quiz


def _public_questions(quiz_id: int) -> list[dict]:
    """Questions with options ONLY — never correct_index, never the canary."""
    db = get_db()
    rows = db.execute(
        "SELECT position, text, options_json FROM questions "
        "WHERE quiz_id = ? ORDER BY position",
        (quiz_id,),
    ).fetchall()
    return [
        {"position": r["position"], "text": r["text"],
         "options": json.loads(r["options_json"])}
        for r in rows
    ]


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    db = get_db()
    # Only public quizzes are listed (P5: private ones are not advertised).
    quizzes = db.execute(
        "SELECT id, title FROM quizzes WHERE is_private = 0 ORDER BY id"
    ).fetchall()
    return render_template("index.html", quizzes=quizzes)


@app.get("/api/quizzes")
def api_quizzes():
    db = get_db()
    quizzes = db.execute(
        "SELECT id, title FROM quizzes WHERE is_private = 0 ORDER BY id"
    ).fetchall()
    return jsonify([{"id": q["id"], "title": q["title"]} for q in quizzes])


@app.get("/quiz/<int:quiz_id>")
def take_quiz(quiz_id: int):
    quiz = _fetch_quiz_or_404(quiz_id)
    questions = _public_questions(quiz_id)
    token = request.args.get("token", "") if quiz["is_private"] else ""
    return render_template(
        "quiz.html", quiz=quiz, questions=questions, token=token
    )


@app.get("/api/quiz/<int:quiz_id>/questions")
def api_questions(quiz_id: int):
    _fetch_quiz_or_404(quiz_id)
    # Note: no correct answers, no canary — just the prompt and options.
    return jsonify(_public_questions(quiz_id))


@app.post("/api/quiz/<int:quiz_id>/submit")
def api_submit(quiz_id: int):
    _fetch_quiz_or_404(quiz_id)
    db = get_db()

    # P3: parse defensively. Bad JSON, wrong shape, or out-of-range -> clean 400.
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, "Body must be a JSON object: {\"answers\": [..]}")
    answers = data.get("answers")
    if not isinstance(answers, list):
        abort(400, "'answers' must be a list of option indices.")

    rows = db.execute(
        "SELECT position, options_json, correct_index FROM questions "
        "WHERE quiz_id = ? ORDER BY position",
        (quiz_id,),
    ).fetchall()
    if len(answers) != len(rows):
        abort(400, f"Expected {len(rows)} answers, got {len(answers)}.")

    results: list[bool] = []
    score = 0
    for submitted, row in zip(answers, rows):
        n_options = len(json.loads(row["options_json"]))
        if not isinstance(submitted, int) or isinstance(submitted, bool):
            abort(400, "Each answer must be an integer option index.")
        if submitted < 0 or submitted >= n_options:
            abort(400, "Answer index out of range.")
        correct = submitted == row["correct_index"]
        results.append(correct)
        score += int(correct)

    # We return whether each answer was right and the score — NEVER the correct
    # option index and NEVER the canary. That is the deliberate P1 boundary.
    return jsonify({"score": score, "total": len(rows), "results": results})


# --------------------------------------------------------------------------- #
# Error handlers — keep internals (paths, the canary, stack traces) out of
# responses on every channel (P1 + P3).
# --------------------------------------------------------------------------- #
@app.errorhandler(400)
def handle_400(err):
    return jsonify({"error": "bad_request", "detail": getattr(err, "description", "")}), 400


@app.errorhandler(404)
def handle_404(_err):
    return jsonify({"error": "not_found"}), 404


@app.errorhandler(413)
def handle_413(_err):
    return jsonify({"error": "payload_too_large"}), 413


@app.errorhandler(500)
def handle_500(_err):
    # Generic message only — no traceback, no internal state.
    return jsonify({"error": "internal_error"}), 500


if __name__ == "__main__":
    if not DB_PATH.exists():
        init_db()
    # debug=False is critical for P1/P3: no interactive debugger, no tracebacks.
    app.run(host="127.0.0.1", port=8000, debug=False)
