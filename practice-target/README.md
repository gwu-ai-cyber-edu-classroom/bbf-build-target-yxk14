# ⚠️ Practice target — INTENTIONALLY VULNERABLE

**This app is a deliberately-broken punching-bag for practising the Break phase
(see [AGENTS_BREAK.md](../AGENTS_BREAK.md)). It is NOT a valid Build-phase
artifact — do not submit it as your team's build.** Your real, correct build is
[../quizapp/](../quizapp/).

It's a tiny multi-user "notes" app. Use it to rehearse black-box attacks across
P1–P5, capture request/response evidence, and explain each mechanism — exactly
the workflow `AGENTS_BREAK.md` asks for.

## Run it

```bash
python -m pip install -r ../requirements.txt
python practice-target/app.py        # http://127.0.0.1:8001
```

The SQLite DB (`practice-target/practice.db`) is seeded on first run. Two users:

| user  | password | note ids |
|-------|----------|----------|
| alice | alice123 | 1 (public), 2 (**private — holds the canary**) |
| bob   | bob123   | 3 (public) |

Log in via `POST /login` (form fields `username`, `password`) — it sets a cookie.

## The planted bugs (one root cause per property)

Try to find these **black-box first**. Each is a separate defect with its own fix.

| # | Property | Where | Probe |
|---|----------|-------|-------|
| 1 | **P5** IDOR | `GET /note/<id>` | read someone else's note by guessing the id |
| 2 | **P5** Stored XSS | note body on the note page | save a note whose body is `<script>` |
| 3 | **P4** SQL injection | `GET /search?q=` | inject through the unparameterized query |
| 4 | **P1** Debug leak | `GET /api/debug` | a verbose endpoint that dumps config incl. the canary |
| 5 | **P3+P1** Stack trace | `GET /note/<id>` with a non-int id | unhandled exception + `debug=True` dumps a traceback |

When you reproduce one against the running app, that's a finding for the gate in
`AGENTS_BREAK.md`. (Against a *real* target you'd file it; here it's just practice.)

## What "fixing" each one looks like (for the Fix-phase muscle memory)

1. Check `note.owner == session_user` before returning it.
2. Escape note bodies (drop `|safe`; let Jinja2 autoescape).
3. Use a parameterized query (`WHERE body LIKE ?`).
4. Delete the debug endpoint; never put the canary in client-visible config.
5. Validate/route-convert the id (`<int:id>`) and run with `debug=False` + error handlers.
