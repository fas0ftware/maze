"""Maze logic on top of the C engine: server-side sessions, messages, logging text.

The decisions (layers, routes, the constant-time final layer, the exit check)
are made by libmaze (core/, bound in core.py). This module keeps the session
store, turns engine results into visible messages, and decides what is safe
to write to the log.
"""

import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from . import core

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
# What is logged for a throttled request. It is rejected before any hashing,
# so the guess cannot be checked against the real password; it is not stored.
THROTTLED_LOG_TEXT = "[not stored: throttled]"


@dataclass
class SessionState:
    # Engine state: current layer and the HASHES of the decoys that cleared
    # each layer (for the exit flow). No plain-text guess is kept.
    core: core.Session = field(default_factory=core.new_session)
    last_seen: float = field(default_factory=time.time)
    # Serialises requests of one session; different sessions run in parallel.
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def layer(self) -> int:
        return self.core.layer

    @property
    def cleared_layers(self) -> list:
        return [n for n in range(1, core.MAX_LAYERS + 1) if self.core.cleared_mask >> n & 1]


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


@dataclass
class Result:
    outcome: str
    message: str
    layer_before: int
    layer_after: int
    log_password: str  # what is safe to write to the log
    failed: bool       # counts toward the per-IP back-off
    # Log only, never shown: on the final layer, the decoy layer the guess matched.
    decoy_layer: int = 0


_ORDINALS = ["First", "Second", "Third", "Fourth", "Fifth", "Sixth", "Seventh", "Eighth",
             "Ninth", "Tenth", "Eleventh", "Twelfth", "Thirteenth", "Fourteenth", "Fifteenth"]


def _redacted(text: str, real_mask: int, bit: int) -> str:
    return REAL_PASSWORD_REDACTED if real_mask >> bit & 1 else text


class Maze:
    def __init__(self, engine: core.Engine):
        self.engine = engine
        self.layer_count = engine.layer_count

    def login(self, state: SessionState, password: str) -> Result:
        with state.lock:
            r = self.engine.login(state.core, password)
        # The real password is redacted when the guess was exactly it, on any
        # layer. Only its hash is known, so a near-miss (an extra space, one
        # wrong character) cannot be recognised and is logged as typed.
        log_pw = _redacted(password, r.real_mask, 0)
        before, after = r.layer_before, r.layer_after
        if r.outcome == core.DECOY_FOUND:
            ordinal = _ORDINALS[before - 1]
            return Result(DECOY_FOUND, f"{ordinal} password found. Proceed to layer {after}.",
                          before, after, log_pw, False, r.decoy_layer)
        if r.outcome == core.REAL_SUCCESS:
            return Result(REAL_SUCCESS, "Access granted.", before, after, log_pw, False)
        return Result(WRONG, WRONG_MESSAGE, before, after, log_pw, True, r.decoy_layer)

    def exit(self, state: SessionState, answers: dict) -> Result:
        """Fake exit: asks for the passwords of every previously cleared layer.

        This is NOT a security control; it is a stalling loop. A correct answer
        sends the session back to layer 1. answers maps layer -> answer.
        """
        with state.lock:
            required = range(1, state.layer)
            given = [answers.get(i, "") for i in required]
            r = self.engine.exit(state.core, given)
        log_pw = " | ".join(_redacted(a, r.real_mask, i) for i, a in enumerate(given))
        before = r.layer_before
        if r.outcome == core.EXIT_UNAVAILABLE:
            return Result(EXIT_UNAVAILABLE, "No exit from here. Find the first password.",
                          before, before, log_pw, False)
        if r.outcome == core.EXIT_GRANTED:
            return Result(EXIT_GRANTED, "Exit verified. Returning to the entrance.",
                          before, 1, log_pw, False)
        return Result(EXIT_DENIED, EXIT_DENIED_MESSAGE, before, before, log_pw, True)
