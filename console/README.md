# Governance console

A read-only window onto the airlock: the live decision ledger, the taint
inventory the sweep found in the warehouse, and the policy replay diff.

```bash
uv run airlock-api        # http://127.0.0.1:8000
```

That one command serves both the JSON API (`src/airlock/api.py`) and this page.
There is no build step and no Node toolchain -- the console is three static
files, so the demo has one less thing that can fail on stage.

## Read-only by construction

Every endpoint is a `SELECT`. Nothing here writes a policy, appends to the
ledger, or executes agent SQL -- the console watches the airlock, it is not a
second door through it.

Replay is the one endpoint that takes a `POST`, and it runs with
`persist=False`: the amended rule set is built in memory, the ledger is
re-decided against it, and `AIRLOCK.POLICY` and `AIRLOCK.REPLAY_RESULT` are both
left exactly as they were. You can ask what a rule change would have cost
without inheriting the consequences of making it.

## A note on rendering

The taint inventory displays prompt-injection payloads: that is its whole
purpose. Everything from the database is escaped before it reaches the DOM
(`esc()` in `app.js`), because a console that renders `<|im_start|>` as markup
would be a fresh injection surface rather than a view of one.

## Layout

| File | What's in it |
|---|---|
| `index.html` | Structure: vitals strip, five tabs, detail drawer |
| `style.css` | The whole look, no framework |
| `app.js` | Fetches `/api/*`, renders, polls every 5s |
