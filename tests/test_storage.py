import gc
import os
import stat
import warnings

import pytest

from app.storage import AttemptLog, sanitize


def add(log, n=1, **kwargs):
    for i in range(n):
        log.record(**{"ip": "1.1.1.1", "session_id": "s", "action": "login", "layer": 1,
                      "password": f"p{i}", "outcome": "wrong", "user_agent": "ua", **kwargs})


# --- sanitize --------------------------------------------------------------

def test_sanitize_none_and_empty():
    assert sanitize(None, 10) == "" and sanitize("", 10) == ""


def test_sanitize_truncates_with_marker():
    assert sanitize("a" * 10, 4) == "aaaa...[truncated]"


def test_sanitize_exact_length_is_not_truncated():
    assert sanitize("abcd", 4) == "abcd"


def test_sanitize_escapes_control_and_format_characters():
    # NUL, and U+202E (right-to-left override, used to disguise log lines).
    assert sanitize("a\x00b‮c", 50) == "a\\x00b\\u202ec"


def test_sanitize_keeps_normal_unicode():
    assert sanitize("şifre-パスワード", 50) == "şifre-パスワード"


# --- retention -------------------------------------------------------------

def test_prune_keeps_only_the_newest_rows(tmp_path):
    log = AttemptLog(tmp_path / "a.db", max_rows=5, prune_every=1000)
    add(log, 12)
    assert len(log.all()) == 12
    assert log.prune() == 7
    assert [r["password"] for r in log.all()] == [f"p{i}" for i in range(7, 12)]


def test_automatic_pruning_bounds_the_table(tmp_path):
    log = AttemptLog(tmp_path / "a.db", max_rows=10, prune_every=5)
    add(log, 100)
    assert 10 <= len(log.all()) <= 10 + 4


def test_max_rows_zero_keeps_everything(tmp_path):
    log = AttemptLog(tmp_path / "a.db", max_rows=0, prune_every=1)
    add(log, 30)
    assert len(log.all()) == 30 and log.prune() == 0


def test_seconds_since_prev_uses_the_same_ip(tmp_path):
    log = AttemptLog(tmp_path / "a.db")
    assert log.record(ip="1.1.1.1", session_id="s", action="login", layer=1, password="x",
                      outcome="wrong", user_agent="ua", now=100.0) is None
    assert log.record(ip="2.2.2.2", session_id="s", action="login", layer=1, password="x",
                      outcome="wrong", user_agent="ua", now=101.0) is None
    assert log.record(ip="1.1.1.1", session_id="s", action="login", layer=1, password="x",
                      outcome="wrong", user_agent="ua", now=102.5) == 2.5


# --- file safety -----------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_new_database_file_is_private(tmp_path):
    path = tmp_path / "private.db"
    AttemptLog(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_existing_database_permissions_are_left_alone(tmp_path):
    path = tmp_path / "shared.db"
    path.touch()
    os.chmod(path, 0o640)
    AttemptLog(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640


def test_connections_are_closed(tmp_path):
    """An unclosed sqlite3 connection raises ResourceWarning when it is collected."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        log = AttemptLog(tmp_path / "c.db")
        add(log, 3)
        log.all()
        gc.collect()
    assert [w for w in caught if issubclass(w.category, ResourceWarning)] == []
