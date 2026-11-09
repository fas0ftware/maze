# Maze

Maze is a layered honeypot and deception service. It shows a fake web login
page. An attacker who starts guessing passwords is led through a maze of fake
progress: breakthroughs that lead nowhere, replies that get slower and slower,
and a fake exit that sends them back to the start. Every move is logged.

> **Status:** v0.x prototype, written in **Python** (Flask + SQLite).
> A rewrite in **C** is planned (see [Roadmap](#roadmap)). This Python version
> is the reference implementation: its behavior and tests define what the C
> version must do.
>
> **For local testing only.** Do not expose Maze to the internet without isolation.

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Logging](#logging)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Security notes](#security-notes)
- [Roadmap](#roadmap)

## Quick start

Requires Python 3.10 or newer.

```bash
git clone https://github.com/fas0ftware/maze.git
cd maze
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# The real password is read ONLY from the environment. Use a long random one.
export MAZE_REAL_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
python -m app            # serves http://127.0.0.1:5000
```

If you prefer a `.env` file, copy `.env.example` to `.env`. `.env` is
git-ignored. Maze does not read the file by itself, so load it into your shell:

```bash
cp .env.example .env     # then edit it
set -a; source .env; set +a
python -m app
```

## How it works

### Layers

| Layer | What is checked | On match |
|------:|-----------------|----------|
| 1 | Decoy list `layers.1` in `config/layers.json` | "First password found", move to layer 2 |
| 2 | Decoy list `layers.2` in `config/layers.json` | "Second password found", move to layer 3 |
| 3 | The real password (`MAZE_REAL_PASSWORD`) | "Access granted" |

- Anything else gets "Wrong password." and the session stays on its layer.
- A decoy only works on its own layer. The real password is checked **only** on
  layer 3, so it is rejected on layers 1 and 2.
- Session state (current layer, decoys used) is kept **on the server**, in
  memory. The cookie only holds a random session id.

### Fake exit flow (stalling, not security)

`/exit` asks the attacker to "confirm" the password of every layer already
cleared. The answers must be the exact decoys this session used. If they
match, the session goes back to layer 1. If they don't, the exit is denied and
the delay grows.

**This is not a real lock or access control.** It only wastes the attacker's
time and produces more log data. Nothing is protected by it.

### Delays and rate limits

Every login or exit attempt waits before it gets a reply. The wait depends only
on how many times **this IP** failed recently: 1s, 2s, 4s, then 8s (the cap).

The design blocks the usual shortcuts:

- **No timing oracle.** The delay is applied *before* the password is checked,
  so right and wrong guesses wait equally long. A client cannot hang up on slow
  replies and treat them as "wrong".
- **Keyed by IP, not by session.** Dropping the cookie does not reset the delay,
  and neither does finding a decoy. The counter resets after
  `reset_after_seconds` (default 900) with no failures, or on the real password.
- **Concurrency caps.** At most 2 requests per IP and 32 in total are processed
  at once (configurable). Extra requests get HTTP 429 at once, so sleeping
  threads cannot pile up.
- **No machine-readable tells.** Every evaluated attempt returns HTTP 200 and
  the same page. Only the visible message differs.

Worst-case guessing rates on layer 3 with the default settings:

| Attacker | Max rate |
|----------|----------|
| One IP | 2 slots / 8 s = **0.25 guesses/s** |
| Many IPs (a botnet) | 32 slots / 1 s = **32 guesses/s** (global cap) |

Maze slows attackers down. It does **not** make a weak password strong, because
the decoy layers add no entropy. A password from a leaked list falls to a botnet
in days. Use 60+ bits of entropy, for example 12+ random characters.

## Configuration

### Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `MAZE_REAL_PASSWORD` | *(required)* | Real layer-3 password. Maze refuses to start if it is unset or also appears in a decoy list. |
| `MAZE_HOST` | `127.0.0.1` | Bind address (prints a warning when not loopback) |
| `MAZE_PORT` | `5000` | Port |
| `MAZE_DB_PATH` | `./maze.db` | SQLite log file |
| `MAZE_DELAY_ENABLED` | from config | `0` turns delays off (demos only) |
| `MAZE_SECRET_KEY` | random per start | Cookie signing key |

### `config/layers.json`

| Key | Meaning |
|-----|---------|
| `layers.1`, `layers.2` | Decoy password lists. **Never put the real password here.** |
| `delay.enabled` | Turn delays on or off |
| `delay.base_seconds`, `delay.max_seconds` | Back-off curve: base, 2×base, 4×base, … up to max |
| `delay.reset_after_seconds` | Quiet time after which an IP's failure count resets |
| `limits.per_ip_concurrency` | Requests processed at once per IP |
| `limits.global_concurrency` | Requests processed at once in total |
| `logging.max_password_length`, `logging.max_user_agent_length` | Truncation limits for the log |

## Logging

Every attempt is written to SQLite. The `attempts` table is created
automatically if it is missing.

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

All input is treated as untrusted:

- Every SQL query is parameterized.
- Passwords and User-Agents are truncated and control characters are escaped
  before they are stored.
- The real password is **never** logged. It is stored as `[REDACTED:REAL_PASSWORD]`.
- Request bodies are capped at 16 KB.

Quick look at the log:

```bash
sqlite3 maze.db "SELECT datetime(ts,'unixepoch'), ip, layer, outcome, password FROM attempts ORDER BY id DESC LIMIT 20"
```

## Testing

### Unit and integration tests

```bash
pytest -v
```

The tests cover:

- layer transitions, and the real password on and off layer 3
- exit rules
- logging: redaction, truncation, control characters
- SQL injection payloads
- refusing to start without a password
- hardening: equal delay for right and wrong guesses, a per-IP delay that
  survives cookie loss and decoys, the quiet-period reset, and concurrency caps

### Attacker simulator

Start the service, then in another terminal:

```bash
python tools/attacker_sim.py                                   # uses tools/wordlist.txt
python tools/attacker_sim.py --url http://127.0.0.1:5000 --wordlist my_list.txt
```

The simulator:

1. tries each word in order and reports every layer it gets through
2. tries the fake exit, first with wrong answers, then with the decoys it found
3. prints a summary

Like a real attacker, it reads only the visible page text. It refuses any target
that is not a loopback address.

## Project layout

```
app/
  __init__.py        Flask app and routes
  __main__.py        Entry point: python -m app
  maze.py            Core logic: layers, fake exit (no Flask)
  throttle.py        Per-IP back-off delay and concurrency caps
  storage.py         SQLite attempt log and input sanitizing
  config.py          Config loading and startup checks
  templates/         Login and exit pages
config/layers.json   Decoy lists and tunables (no real password)
tests/               pytest suite
tools/
  attacker_sim.py    Local attacker simulator
  wordlist.txt       Demo wordlist
.env.example         Template for local environment variables
```

## Security notes

- **For local testing only. Do not expose Maze to the internet without
  isolation.** If you run it as a real honeypot, use a separate, disposable
  host, VM or container with no access to real systems or credentials, and
  filter its outbound traffic.
- The prototype uses Flask's development server. Sessions and throttle state
  live in memory and are lost on restart.
- The global concurrency cap means a flood can make the page unavailable to
  everyone. That is acceptable for a honeypot, not for a real login.
- Treat the log as hostile data: it holds whatever attackers typed.
- Never commit `.env`, `*.db` or real passwords. `.gitignore` covers these.

## Roadmap

### C rewrite (planned)

Maze will be rewritten in C. The Python version stays as the reference until
then. Goals for the port:

- Same external behavior: same routes, messages, layer and exit rules, delay
  curve, limits and log schema.
- Reuse `config/layers.json` and the SQLite schema, so tools and logs carry over.
- Event-driven I/O (for example `epoll`), so a delayed request does not hold a
  thread.
- Strict input handling: bounded buffers, length checks on every field, and
  prepared SQLite statements only.
- Build with hardening flags (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`,
  PIE, RELRO) and test under AddressSanitizer, UBSan and a fuzzer.
- Port the tests as black-box HTTP tests that run against **either**
  implementation, so the Python and C versions can be checked for the same behavior.

### Other items

- **Docker**: an isolated deployment image.
- **Minotor**: a companion service for log analysis, alerting and IP blocking
  on *our own* infrastructure.
- Persist session and throttle state across restarts.
- An SSH-like service as another maze entrance.

Maze will not include hack-back or any offensive action against real systems.
