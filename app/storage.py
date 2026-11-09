"""SQLite attempt log. Every query is parameterized."""

import os
import sqlite3
import threading
import time
from contextlib import contextmanager

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
    """Append-only attempt log with optional retention.

    max_rows > 0 keeps only the newest max_rows rows. Pruning runs every
    `prune_every` inserts, so the table can briefly exceed max_rows by up to
    prune_every - 1 rows. max_rows = 0 keeps everything.

    A newly created database file is private (mode 0600): it holds whatever
    attackers typed, and near-misses of the real password.
    """

    def __init__(self, db_path, max_rows: int = 0, prune_every: int = 100):
        self.db_path = str(db_path)
        self.max_rows = max(0, int(max_rows))
        self.prune_every = max(1, int(prune_every))
        self._inserts = 0
        self._lock = threading.Lock()
        self._create_private_file()
        with self._connect() as conn:
            conn.execute(SCHEMA)
            conn.execute(INDEX)

    def _create_private_file(self) -> None:
        # An empty file is a valid new SQLite database. Existing files are left alone.
        if self.db_path == ":memory:" or os.path.exists(self.db_path):
            return
        os.close(os.open(self.db_path, os.O_CREAT | os.O_WRONLY, 0o600))

    @contextmanager
    def _connect(self):
        """Open a connection, commit on success, and ALWAYS close it.

        (sqlite3's own `with connection` only commits; it never closes.)
        """
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _prune_with(conn, keep: int) -> int:
        cur = conn.execute(
            "DELETE FROM attempts WHERE id <= (SELECT MAX(id) FROM attempts) - ?", (keep,)
        )
        return cur.rowcount

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
            self._inserts += 1
            if self.max_rows and self._inserts % self.prune_every == 0:
                self._prune_with(conn, self.max_rows)
        return since_prev

    def prune(self) -> int:
        """Delete everything except the newest max_rows rows. Returns rows deleted."""
        if not self.max_rows:
            return 0
        with self._lock, self._connect() as conn:
            return self._prune_with(conn, self.max_rows)

    def all(self):
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute("SELECT * FROM attempts ORDER BY id")]
