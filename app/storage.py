"""SQLite attempt log. Every query is parameterized."""

import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                REAL    NOT NULL,
    ip                TEXT    NOT NULL,
    session_id        TEXT    NOT NULL,
    action            TEXT    NOT NULL,
    layer             INTEGER NOT NULL,
    password          TEXT    NOT NULL,
    outcome           TEXT    NOT NULL,
    user_agent        TEXT    NOT NULL,
    seconds_since_prev REAL
)
"""

INDEX = "CREATE INDEX IF NOT EXISTS idx_attempts_ip ON attempts (ip, id)"


def sanitize(value, max_length: int) -> str:
    """Make untrusted input safe to store and print.

    Truncates to max_length and escapes control characters so a log viewer
    cannot be tricked by terminal escape sequences or fake newlines.
    """
    if value is None:
        return ""
    text = str(value)
    truncated = len(text) > max_length
    text = text[:max_length]
    text = "".join(
        ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii")
        for ch in text
    )
    if truncated:
        text += "...[truncated]"
    return text


class AttemptLog:
    def __init__(self, db_path):
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute(SCHEMA)
            conn.execute(INDEX)

    def _connect(self):
        return sqlite3.connect(self.db_path, timeout=10)

    def record(self, *, ip, session_id, action, layer, password, outcome, user_agent, now=None):
        """Insert one attempt and return seconds since the previous attempt from this IP."""
        now = time.time() if now is None else now
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT ts FROM attempts WHERE ip = ? ORDER BY id DESC LIMIT 1",
                (ip,),
            ).fetchone()
            since_prev = round(now - row[0], 3) if row else None
            conn.execute(
                "INSERT INTO attempts (ts, ip, session_id, action, layer, password, outcome, "
                "user_agent, seconds_since_prev) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (now, ip, session_id, action, layer, password, outcome, user_agent, since_prev),
            )
        return since_prev

    def all(self):
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute("SELECT * FROM attempts ORDER BY id")]
