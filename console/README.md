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

Six destinations in a left rail -- Overview, Ledger, Taint inventory, Policy
replay, Rule set, Sessions -- and a detail drawer that opens on any ledger row.
Overview lands first: the four verdict counts, the split bar, the eight most
recent decisions, and a fold holding the measurements behind those verdicts.

Every page is a stack of cards. The rail collapses to icons below 1200px and
goes off-canvas behind a toggle below 700px. 960px is the width that matters --
the run sheet puts the console beside an agent chat pane -- so that is the width
the layout is tuned for.

| File | What's in it |
|---|---|
| `index.html` | Structure: icon sprite, rail, top bar, six panels, detail drawer |
| `style.css` | The whole look, no framework |
| `app.js` | Fetches `/api/*`, renders, polls every 5s |

Icons are inline `<symbol>`s in `index.html`, not a font and not a package, for
the same reason there is no build step: an icon set that can 404 on stage is a
dependency the demo does not need.
