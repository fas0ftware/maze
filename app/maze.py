"""Core maze logic: server-side session state, layer transitions, fake exit, delays.

Kept free of Flask so it can be tested and reasoned about on its own.
"""

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

# Placeholder written to the log instead of the real password, so the
# secret never ends up in the database.
REAL_PASSWORD_REDACTED = "[REDACTED:REAL_PASSWORD]"


@dataclass
class SessionState:
    layer: int = 1
    failures: int = 0
    # Decoy password the attacker used to clear each layer (layer -> password).
    cleared_with: dict = field(default_factory=dict)
    last_seen: float = field(default_factory=time.time)


class SessionStore:
    """Thread-safe in-memory server-side session store with a size cap.

    The client cookie only carries an opaque random id; all state stays here.
    """

    def __init__(self, max_sessions: int = 10000):
        self.max_sessions = max_sessions
        self._data = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def new_id() -> str:
        return secrets.token_urlsafe(24)

    def get(self, session_id: str) -> SessionState:
        with self._lock:
            state = self._data.get(session_id)
            if state is None:
                state = SessionState()
                self._data[session_id] = state
                while len(self._data) > self.max_sessions:
                    self._data.popitem(last=False)  # evict oldest
            else:
                self._data.move_to_end(session_id)
            state.last_seen = time.time()
            return state


def compute_delay(failures: int, base: float, maximum: float) -> float:
    """Exponential back-off: 1s, 2s, 4s, 8s, 8s ... for base=1, max=8."""
    if failures <= 0 or base <= 0:
        return 0.0
    return min(base * (2 ** (failures - 1)), maximum)


def _equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


@dataclass
class Result:
    outcome: str
    message: str
    layer_before: int
    layer_after: int
    log_password: str  # what is safe to write to the log
    failed: bool       # whether this counts toward the stalling delay


class Maze:
    def __init__(self, decoys: dict, real_password: str):
        self.decoys = decoys
        self._real_password = real_password

    def _is_real(self, password: str) -> bool:
        return _equals(password, self._real_password)

    def _safe_for_log(self, password: str) -> str:
        return REAL_PASSWORD_REDACTED if self._is_real(password) else password

    def login(self, state: SessionState, password: str) -> Result:
        before = state.layer
        log_pw = self._safe_for_log(password)

        if before < FINAL_LAYER:
            if password in self.decoys[before]:
                state.cleared_with[before] = password
                state.layer = before + 1
                state.failures = 0
                ordinal = "First" if before == 1 else "Second"
                return Result(DECOY_FOUND, f"{ordinal} password found. Proceed to layer {state.layer}.",
                              before, state.layer, log_pw, False)
            state.failures += 1
            return Result(WRONG, "Wrong password.", before, before, log_pw, True)

        # Final layer: the only place the real password is checked.
        if self._is_real(password):
            state.failures = 0
            return Result(REAL_SUCCESS, "Access granted.", before, before, log_pw, False)
        state.failures += 1
        return Result(WRONG, "Wrong password.", before, before, log_pw, True)

    def exit(self, state: SessionState, answers: dict) -> Result:
        """Fake exit: asks for the passwords of every previously cleared layer.

        This is NOT a security control; it is a stalling loop. A correct answer
        sends the session back to layer 1.
        """
        before = state.layer
        required = list(range(1, before))
        log_pw = " | ".join(self._safe_for_log(answers.get(i, "")) for i in required)

        if not required:
            return Result(EXIT_UNAVAILABLE, "No exit from here. Find the first password.",
                          before, before, log_pw, False)

        ok = all(_equals(answers.get(i, ""), state.cleared_with.get(i, "\x00")) for i in required)
        if ok:
            state.layer = 1
            state.failures = 0
            state.cleared_with.clear()
            return Result(EXIT_GRANTED, "Exit verified. Returning to the entrance.",
                          before, 1, log_pw, False)
        state.failures += 1
        return Result(EXIT_DENIED, "Exit denied. Previous layer passwords do not match.",
                      before, before, log_pw, True)
