# Maze

Maze is a layered honeypot / deception service. It presents a fake web login
page. An attacker who starts guessing passwords is led through a maze of
"progress": fake breakthroughs, slower and slower responses, and a fake exit
that sends them back to the start. Every move is logged.

> **Status:** prototype (v0.1.0). Local testing only.

## How it works

### Layers

| Layer | What is checked | On match |
|------:|-----------------|----------|
| 1 | Decoy list `layers.1` in `config/layers.json` | "First password found", move to layer 2 |
| 2 | Decoy list `layers.2` in `config/layers.json` | "Second password found", move to layer 3 |
| 3 | The real password (`MAZE_REAL_PASSWORD` env var) | "Access granted" |

* Anything else is "Wrong password." and the session stays on its current layer.
* Decoys only work on their own layer. The real password is checked **only** on
  layer 3, so it is rejected on layers 1 and 2.
* Session state (current layer, failure count, decoys used) is stored
  **server-side** in memory. The cookie only holds a random session id.

### Fake exit flow (stalling, not security)

`/exit` asks the attacker to "confirm" the passwords of every layer already
cleared. These must be the exact decoys this session used. If they match, the
session is sent back to layer 1. If they don't, the exit is denied and the
back-off delay grows.

**This is not a real lock or an access control.** It exists only to waste the
attacker's time and to produce more log data. Nothing is protected by it.

### Stalling delay and rate limits

Every login or exit attempt waits before it is answered. The wait depends only
on how many times **this IP** has failed recently: 1s, 2s, 4s, then 8s (capped).

The design blocks the usual shortcuts:

* **No timing oracle.** The delay is applied *before* the password is checked,
  and correct guesses wait exactly as long as wrong ones. A client cannot hang up
  early on slow replies and treat them as "wrong".
* **Keyed by IP, not by session.** Dropping the cookie does not reset the delay.
  Finding a decoy does not reset it either. It resets after
  `reset_after_seconds` (default 900) without failures, or on the real password.
* **Concurrency caps.** At most `per_ip_concurrency` (default 2) requests per IP
  and `global_concurrency` (default 32) in total are processed at once. Extra
  requests are refused immediately with HTTP 429, so sleeping threads cannot
  pile up and exhaust the server.
* **No machine-readable tells.** Every evaluated attempt returns HTTP 200 with the
  same page. Only the visible message differs.

All of this is in `config/layers.json` (`delay`, `limits`). `MAZE_DELAY_ENABLED=0`
turns the delay off. Tests turn it off or record sleeps instead of sleeping.

Resulting worst-case guessing rates on layer 3:

| Attacker | Rate |
|----------|------|
| One IP | <= 2 slots / 8s = **0.25 guesses/s** |
| Many IPs (e.g. a botnet) | <= 32 slots / 1s = **32 guesses/s** (global cap) |

This slows an attacker down. It does **not** make a weak real password strong.
Use a long, random `MAZE_REAL_PASSWORD` (60+ bits, e.g. 12+ random characters).

### Logging

Every attempt is written to SQLite (`maze.db` by default; override with
`MAZE_DB_PATH`). The `attempts` table is created automatically when missing.

| Column | Meaning |
|--------|---------|
| `ts` | Unix timestamp |
| `ip` | Client address (`remote_addr`; `X-Forwarded-For` is ignored) |
| `session_id` | Opaque server-side session id |
| `action` | `login` or `exit` |
| `layer` | Layer the attempt was made on |
| `password` | Attempted password(s); exit answers are joined with ` \| ` |
| `outcome` | `wrong`, `decoy_found`, `real_success`, `exit_denied`, `exit_granted`, `exit_unavailable`, `throttled` |
| `user_agent` | Client User-Agent |
| `seconds_since_prev` | Seconds since the previous attempt from the same IP |

Input is treated as untrusted:

* All SQL is parameterized.
* Passwords and User-Agents are truncated (128 / 256 chars, configurable) and
  control characters are escaped before they are stored.
* The real password is **never** written to the log. It is stored as
  `[REDACTED:REAL_PASSWORD]`.
* Request bodies are capped at 16 KB.

## Project layout

```
app/                Flask service (maze.py = core logic, throttle.py = delay/limits,
                    storage.py = SQLite log)
config/layers.json  Decoy password lists and tunables (no real password!)
tests/              pytest suite
tools/attacker_sim.py  Local attacker simulator (+ wordlist.txt)
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running

The real password comes only from the environment. If it is not set, the
service refuses to start. It also refuses to start if the real password appears
in a decoy list.

```bash
export MAZE_REAL_PASSWORD='choose-something-long'   # or put it in .env (git-ignored)
python -m app                                        # http://127.0.0.1:5000
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `MAZE_REAL_PASSWORD` | *(required)* | Real layer-3 password |
| `MAZE_HOST` | `127.0.0.1` | Bind address |
| `MAZE_PORT` | `5000` | Port |
| `MAZE_DB_PATH` | `./maze.db` | SQLite log file |
| `MAZE_DELAY_ENABLED` | from config | `0` disables stalling |
| `MAZE_SECRET_KEY` | random per start | Cookie signing key |

## Testing with the simulator

With the service running in another terminal:

```bash
python tools/attacker_sim.py                       # uses tools/wordlist.txt
python tools/attacker_sim.py --url http://127.0.0.1:5000 --wordlist my_list.txt
```

The simulator tries every word in order, reports each layer it gets through,
then tries the fake exit (first with wrong answers, then with the decoys it
found) and prints a summary. It refuses any target that is not a loopback
address.

## Tests

```bash
pytest
```

The tests cover layer transitions, the real password on and off layer 3, exit
rules, logging (including redaction, truncation and control characters), SQL
injection payloads, refusing to start without a password, and the hardening
rules: equal delay for right and wrong guesses, per-IP delay that survives
cookie loss and decoys, quiet-period reset, and concurrency caps.

## Security note

**Local testing only. Do not expose Maze to the internet without isolation.**
This prototype runs the Flask development server and keeps sessions and
throttle state in memory (lost on restart). The global concurrency cap also
means a flood can make the page unavailable to everyone; for a honeypot this
is acceptable, for a real login it would not be. If you deploy it as a real honeypot, run it in an
isolated, disposable environment (separate host/VM/container, no access to
real systems or credentials, egress filtering) and treat its logs as hostile
data.

## Roadmap

Out of scope for this prototype:

- **Docker**: containerized, isolated deployment with a production WSGI server.
- Async delays (ASGI), so a waiting request does not hold a thread.
- Persist session and throttle state across restarts.
- **Minotor**: a companion service for log analysis, alerting and IP blocking
  on *our own* infrastructure.
- An SSH-like service as another maze entrance.

Maze will not include hack-back or any offensive action against real systems.
