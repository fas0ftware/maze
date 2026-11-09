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

### Stalling delay

Every wrong login or denied exit makes the response slower: 1s, 2s, 4s, then
8s for each further failure (capped). Finding a decoy resets the counter.
You can change these values in `config/layers.json` under `delay`, or turn the
delay off with `MAZE_DELAY_ENABLED=0`. Tests turn it off.

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
| `outcome` | `wrong`, `decoy_found`, `real_success`, `exit_denied`, `exit_granted`, `exit_unavailable` |
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
app/                Flask service (maze.py = core logic, storage.py = SQLite log)
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
injection payloads, delay timing, and refusing to start without a password.

## Security note

**Local testing only. Do not expose Maze to the internet without isolation.**
This prototype runs the Flask development server, keeps sessions in memory,
and has not been hardened. If you deploy it as a real honeypot, run it in an
isolated, disposable environment (separate host/VM/container, no access to
real systems or credentials, egress filtering) and treat its logs as hostile
data.

## Roadmap

Out of scope for this prototype:

- **Docker**: containerized, isolated deployment with a production WSGI server.
- **Minotor**: a companion service for log analysis, alerting and IP blocking
  on *our own* infrastructure.
- An SSH-like service as another maze entrance.

Maze will not include hack-back or any offensive action against real systems.
