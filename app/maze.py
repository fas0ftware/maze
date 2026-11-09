"""Core maze logic: server-side session state, layer transitions, fake exit.

Delays and rate limits live in throttle.py.

Kept free of Flask so it can be tested and reasoned about on its own.
"""

import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

FINAL_LAYER = 3

# Outcome codes (also stored in the log)
DECOY_FOUND = "decoy_found"
WRONG = "wrong"
REAL_SUCCESS = "real_success"
EXIT_GRANTED = "exit_granted"
EXIT_DENIED = "exit_denied"
EXIT_UNAVAILABLE = "exit_unavailable"
OVERSIZE = "oversize"  # request body over the size cap; treated as a failed attempt

# Visible messages (the page text is the only signal an attacker gets).
WRONG_MESSAGE = "Wrong password."
EXIT_DENIED_MESSAGE = "Exit denied. Previous layer passwords do not match."

# Placeholder written to the log instead of the real password, so the
# secret never ends up in the database.
REAL_PASSWORD_REDACTED = "[REDACTED:REAL_PASSWORD]"
# What is logged when the body was too large to read at all.
OVERSIZE_LOG_TEXT = "[oversize request body]"


@dataclass
class SessionState:
    layer: int = 1
    # Decoy password the attacker used to clear each layer (layer -> password).
    cleared_with: dict = field(default_factory=dict)
    last_seen: float = field(default_factory=time.time)


class SessionStore:
    """Thread-safe in-memory server-side session store.

    The client cookie only carries an opaque random id; all state stays here.
    Sessions expire after `ttl` seconds without use, and the store never holds
    more than `max_sessions` (oldest evicted first).

    get(..., create=False) never stores anything, so read-only traffic (GET
    floods, throttled requests) cannot fill the store or push real sessions out.
    """

    def __init__(self, max_sessions: int = 10000, ttl: float = 3600.0, clock=time.time):
        self.max_sessions = max_sessions
        self.ttl = ttl
        self.clock = clock
        self._data = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    @staticmethod
    def new_id() -> str:
        return secrets.token_urlsafe(24)

    def _purge_expired(self, now: float) -> None:
        # Entries are ordered by recency, so expired ones are always at the front.
        while self._data:
            oldest = next(iter(self._data.values()))
            if now - oldest.last_seen <= self.ttl:
                break
            self._data.popitem(last=False)

    def get(self, session_id: str, create: bool = True) -> SessionState:
        now = self.clock()
        with self._lock:
            self._purge_expired(now)
            state = self._data.get(session_id)
            if state is None:
                state = SessionState(last_seen=now)
                if create:
                    self._data[session_id] = state
                    while len(self._data) > self.max_sessions:
                        self._data.popitem(last=False)  # evict oldest
                return state
            self._data.move_to_end(session_id)
            state.last_seen = now
            return state


def _digest(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest()


def _equals(a: str, b: str) -> bool:
    """Constant-time equality that does not leak the length either (compares digests)."""
    return hmac.compare_digest(_digest(a), _digest(b))


@dataclass
class Result:
    outcome: str
    message: str
    layer_before: int
    layer_after: int
    log_password: str  # what is safe to write to the log
    failed: bool       # counts toward the per-IP back-off


class Maze:
    def __init__(self, decoys: dict, real_password: str):
        self.decoys = decoys
        self._real_password = real_password
        # Evaluation is a few microseconds; the long waits happen outside (throttle).
        # The lock keeps layer/cleared_with consistent when one session sends
        # several requests at once.
        self._lock = threading.Lock()

    def _is_real(self, password: str) -> bool:
        return _equals(password, self._real_password)

    def redact(self, text: str) -> str:
        """Return a version of the text that is safe to write to the log.

        Every occurrence of the real password is replaced, not only an exact
        match, so a stray space, a pasted newline or extra characters around the
        real password do not put it in the log. (This only decides what is
        logged; the access decision uses the constant-time _is_real.)

        Limit: a near-miss, such as one mistyped character, cannot be recognised
        and is logged as typed. Treat the log as sensitive.
        """
        real = self._real_password
        if real and real in text:
            return text.replace(real, REAL_PASSWORD_REDACTED)
        return text

    _safe_for_log = redact

    def login(self, state: SessionState, password: str) -> Result:
        with self._lock:
            before = state.layer
            log_pw = self._safe_for_log(password)

            if before < FINAL_LAYER:
                if password in self.decoys[before]:
                    state.cleared_with[before] = password
                    state.layer = before + 1
                    ordinal = "First" if before == 1 else "Second"
                    return Result(DECOY_FOUND,
                                  f"{ordinal} password found. Proceed to layer {state.layer}.",
                                  before, state.layer, log_pw, False)
                return Result(WRONG, WRONG_MESSAGE, before, before, log_pw, True)

            # Final layer: the only place the real password is checked.
            if self._is_real(password):
                return Result(REAL_SUCCESS, "Access granted.", before, before, log_pw, False)
            return Result(WRONG, WRONG_MESSAGE, before, before, log_pw, True)

    def exit(self, state: SessionState, answers: dict) -> Result:
        """Fake exit: asks for the passwords of every previously cleared layer.

        This is NOT a security control; it is a stalling loop. A correct answer
        sends the session back to layer 1.
        """
        with self._lock:
            before = state.layer
            required = list(range(1, before))
            log_pw = " | ".join(self._safe_for_log(answers.get(i, "")) for i in required)

            if not required:
                return Result(EXIT_UNAVAILABLE, "No exit from here. Find the first password.",
                              before, before, log_pw, False)

            ok = all(_equals(answers.get(i, ""), state.cleared_with.get(i, "\x00"))
                     for i in required)
            if ok:
                state.layer = 1
                state.cleared_with.clear()
                return Result(EXIT_GRANTED, "Exit verified. Returning to the entrance.",
                              before, 1, log_pw, False)
            return Result(EXIT_DENIED, EXIT_DENIED_MESSAGE, before, before, log_pw, True)
