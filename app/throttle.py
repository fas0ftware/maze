"""Per-IP throttling: back-off delay and concurrency limits.

Design goals:
* The delay depends only on the IP's PAST failures, never on whether the
  current guess is right. It is applied BEFORE the password is checked, so
  response time leaks nothing (no "abort if it takes long" shortcut).
* State is keyed by IP, so dropping the session cookie does not reset it.
  Finding a decoy does not reset it either; only a quiet period or the real
  password does.
* Concurrency is capped per IP and globally. Requests over the cap are
  rejected immediately instead of piling up sleeping threads.
"""

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


def compute_delay(failures: int, base: float, maximum: float) -> float:
    """Exponential back-off: 1s, 2s, 4s, 8s, 8s ... for base=1, max=8."""
    if failures <= 0 or base <= 0:
        return 0.0
    return min(base * (2 ** (failures - 1)), maximum)


@dataclass
class _IpState:
    failures: int = 0
    last_failure: float = 0.0
    in_flight: int = 0


class Throttle:
    def __init__(self, *, base, maximum, reset_after, per_ip_concurrency,
                 global_concurrency, max_tracked_ips=100_000, clock=time.monotonic):
        self.base = base
        self.maximum = maximum
        self.reset_after = reset_after
        self.per_ip_concurrency = per_ip_concurrency
        self.global_concurrency = global_concurrency
        self.max_tracked_ips = max_tracked_ips
        self.clock = clock
        self._ips = OrderedDict()
        self._global_in_flight = 0
        self._lock = threading.Lock()

    def _state(self, ip) -> _IpState:
        state = self._ips.get(ip)
        if state is None:
            state = _IpState()
            self._ips[ip] = state
            self._evict_idle()
        else:
            self._ips.move_to_end(ip)
        if state.failures and self.clock() - state.last_failure >= self.reset_after:
            state.failures = 0
        return state

    def _evict_idle(self):
        # Drop the oldest IPs that have nothing in flight.
        while len(self._ips) > self.max_tracked_ips:
            for ip, st in self._ips.items():
                if st.in_flight == 0:
                    del self._ips[ip]
                    break
            else:
                return

    def try_enter(self, ip) -> bool:
        """Reserve a concurrency slot. False means: reject this request now."""
        with self._lock:
            state = self._state(ip)
            if (self._global_in_flight >= self.global_concurrency
                    or state.in_flight >= self.per_ip_concurrency):
                return False
            state.in_flight += 1
            self._global_in_flight += 1
            return True

    def leave(self, ip) -> None:
        with self._lock:
            state = self._ips.get(ip)
            if state and state.in_flight > 0:
                state.in_flight -= 1
            self._global_in_flight = max(0, self._global_in_flight - 1)

    def delay_for(self, ip) -> float:
        """Delay for the next attempt, as if that attempt were going to fail."""
        with self._lock:
            return compute_delay(self._state(ip).failures + 1, self.base, self.maximum)

    def record(self, ip, *, failed: bool, real_success: bool = False) -> None:
        with self._lock:
            state = self._state(ip)
            if failed:
                state.failures += 1
                state.last_failure = self.clock()
            elif real_success:
                state.failures = 0
