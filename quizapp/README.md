# Quiz / Poll app (BUILD-MENU #21)

A small Flask + SQLite quiz app. Take a quiz, submit your answers, get a score.
The **answer key** is the protected asset: the server uses it to grade you but
never reveals the correct answers or the `CANARY_` secret stored alongside it.

## Run it

```bash
# from the repo root
python -m pip install -r requirements.txt    # installs flask + pytest
python quizapp/app.py
```

Then open <http://127.0.0.1:8000> (binds to localhost, high port, no admin).

The SQLite database (`quizapp/quiz.db`) is created and seeded automatically on
first run. To re-seed from scratch, delete `quizapp/quiz.db` and start again.

## Where the canary lives

The `CANARY_` secret lives in the **answer key of the private quiz** (quiz id 3,
"Internal Certification Exam"). It is loaded at startup from the shared
`secret/canary.txt` and stored in the `answer_keys` table. That table is read
**only** for grading and is never serialized into any HTTP response, rendered
page, log line, or error message.

## Entry points (what a breaker attacks)

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/` | List public quizzes |
| GET  | `/api/quizzes` | Public quizzes as JSON |
| GET  | `/quiz/<id>` | Take a quiz (HTML) |
| GET  | `/api/quiz/<id>/questions` | Questions + options as JSON (no answers) |
| POST | `/api/quiz/<id>/submit` | Grade answers → `{score, total, results[]}` |

The private quiz (id 3) requires an owner token: `/quiz/3?token=...`. Without the
correct token, every route for it returns `404` (no IDOR, no existence leak).

## How the property contract (SPEC.md) is held

- **P1 Confidentiality** — the answer key and canary are server-side only. Grading
  returns score + per-question right/wrong, never the correct option, never the
  canary. No debug mode, so no tracebacks ship.
- **P2 Correctness** — valid submissions are graded correctly against the key.
- **P3 Input discipline** — bad JSON, wrong-length arrays, non-integer or
  out-of-range indices, and oversized bodies all return a clean `400`/`413`; the
  server stays up.
- **P4 No injection** — all SQL is parameterized; the quiz id is an `<int:>` route
  converter; no `eval`/template-from-input.
- **P5 Authz + output safety** — private quizzes require the owner token (no IDOR);
  Jinja2 autoescaping is on and no user-supplied free text is reflected into HTML.
