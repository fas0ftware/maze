"""Hardening tests: timing-independent delay, per-IP state, concurrency limits."""

from app.throttle import Throttle
from conftest import LAYER1, LAYER2, TEST_REAL_PASSWORD, layer_of, login, outcome_of

# The `clock` and `slow_app` fixtures live in conftest.py.


def test_delay_sequence_for_wrong_guesses(slow_app):
    c = slow_app.test_client()
    for _ in range(6):
        login(c, "wrong")
    assert slow_app.recorded_sleeps == [1, 2, 4, 8, 8, 8]


def test_correct_and_wrong_guess_wait_the_same(slow_app):
    """The delay is decided before the password is checked: no timing oracle."""
    c = slow_app.test_client()
    login(c, LAYER1)
    login(c, LAYER2)
    login(c, "wrong")
    login(c, "wrong")
    before_wrong = len(slow_app.recorded_sleeps)
    login(c, "wrong")                      # 3rd failure
    wait_wrong = slow_app.recorded_sleeps[before_wrong]
    r = login(c, TEST_REAL_PASSWORD)       # would be the 4th failure if wrong
    wait_right = slow_app.recorded_sleeps[-1]
    assert outcome_of(r) == "real_success"
    assert wait_wrong == 4 and wait_right == 8  # follows the same curve
    # Directly: the delay for the next attempt does not depend on its password.
    t = slow_app.extensions["maze"]["throttle"]
    assert t.delay_for("127.0.0.1") == 1  # reset only by the real password


def test_success_is_delayed_too(slow_app):
    """Even the very first, correct attempt waits like a wrong one would."""
    c = slow_app.test_client()
    r = login(c, LAYER1)
    assert outcome_of(r) == "decoy_found"
    assert slow_app.recorded_sleeps == [1]


def test_dropping_cookie_does_not_reset_delay(slow_app):
    first = slow_app.test_client()
    for _ in range(3):
        login(first, "wrong")
    fresh = slow_app.test_client()  # new session, same IP
    login(fresh, "wrong")
    assert slow_app.recorded_sleeps[-1] == 8


def test_finding_a_decoy_does_not_reset_delay(slow_app):
    c = slow_app.test_client()
    for _ in range(3):
        login(c, "wrong")
    login(c, LAYER1)              # decoy found
    login(c, "wrong")
    assert slow_app.recorded_sleeps[-2:] == [8, 8]


def test_delay_resets_after_quiet_period(slow_app, clock):
    c = slow_app.test_client()
    for _ in range(4):
        login(c, "wrong")
    clock.now += 901
    login(c, "wrong")
    assert slow_app.recorded_sleeps[-1] == 1


def test_failed_exit_counts_toward_delay(slow_app):
    c = slow_app.test_client()
    login(c, LAYER1)                             # delay 1, no failure
    c.post("/exit", data={"layer1": "nope"})     # delay 1, failure #1
    login(c, "wrong")                            # delay 2
    assert slow_app.recorded_sleeps == [1, 1, 2]


def test_per_ip_concurrency_limit(app, db_rows):
    """Requests beyond the per-IP cap are refused at once, without sleeping."""
    t = app.extensions["maze"]["throttle"]
    assert t.try_enter("127.0.0.1") and t.try_enter("127.0.0.1")  # cap = 2, both busy
    c = app.test_client()
    r = login(c, LAYER1)
    assert r.status_code == 429 and outcome_of(r) == "throttled"
    assert layer_of(r) == 1                      # password was NOT evaluated
    assert db_rows()[-1]["outcome"] == "throttled"
    t.leave("127.0.0.1")
    assert layer_of(login(c, LAYER1)) == 2       # works again once a slot frees


def test_throttled_real_password_is_redacted(app, db_rows):
    t = app.extensions["maze"]["throttle"]
    t.try_enter("127.0.0.1"); t.try_enter("127.0.0.1")
    login(app.test_client(), TEST_REAL_PASSWORD)
    assert TEST_REAL_PASSWORD not in db_rows()[-1]["password"]


def test_global_concurrency_limit():
    t = Throttle(base=1, maximum=8, reset_after=900, per_ip_concurrency=2,
                 global_concurrency=3)
    assert t.try_enter("10.0.0.1") and t.try_enter("10.0.0.2") and t.try_enter("10.0.0.3")
    assert not t.try_enter("10.0.0.4")          # global cap reached
    t.leave("10.0.0.1")
    assert t.try_enter("10.0.0.4")


def test_slots_released_after_requests(app):
    c = app.test_client()
    for _ in range(10):
        login(c, "wrong")
    t = app.extensions["maze"]["throttle"]
    assert t._global_in_flight == 0
