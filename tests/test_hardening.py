"""Regression tests for gaps found in the v0.x review."""

import json

import pytest

from app import create_app
from app.config import DEFAULT_LAYERS_PATH
from app.maze import OVERSIZE_LOG_TEXT, REAL_PASSWORD_REDACTED
from app.throttle import ip_key
from conftest import LAYER1, TEST_REAL_PASSWORD, layer_of, login, outcome_of


# --- the real password never reaches the log --------------------------------

@pytest.mark.parametrize("typed", [
    TEST_REAL_PASSWORD + " ",
    " " + TEST_REAL_PASSWORD,
    TEST_REAL_PASSWORD + "\n",
    "x" + TEST_REAL_PASSWORD + "y",
    TEST_REAL_PASSWORD * 2,
], ids=["trailing space", "leading space", "newline", "wrapped", "repeated"])
def test_real_password_inside_a_longer_guess_is_redacted(client, db_rows, typed):
    login(client, typed)
    stored = db_rows()[-1]["password"]
    assert TEST_REAL_PASSWORD not in stored
    assert REAL_PASSWORD_REDACTED in stored


def test_real_password_inside_an_exit_answer_is_redacted(client, db_rows):
    login(client, LAYER1)
    client.post("/exit", data={"layer1": TEST_REAL_PASSWORD + "!"})
    row = db_rows()[-1]
    assert row["action"] == "exit" and TEST_REAL_PASSWORD not in row["password"]


def test_real_password_inside_a_throttled_guess_is_redacted(app, db_rows):
    t = app.extensions["maze"]["throttle"]
    t.try_enter("127.0.0.1")
    t.try_enter("127.0.0.1")
    login(app.test_client(), "x" + TEST_REAL_PASSWORD)
    assert TEST_REAL_PASSWORD not in db_rows()[-1]["password"]


def test_ordinary_guesses_are_logged_unchanged(client, db_rows):
    login(client, "hello world")
    assert db_rows()[-1]["password"] == "hello world"


# --- oversize bodies ----------------------------------------------------------

def test_oversize_login_is_a_normal_failed_attempt(client, db_rows):
    r = login(client, "A" * 40000)
    assert r.status_code == 200
    assert b"413" not in r.data and b"Entity Too Large" not in r.data
    assert outcome_of(r) == "wrong" and layer_of(r) == 1
    row = db_rows()[-1]
    assert (row["action"], row["outcome"], row["password"]) == ("login", "oversize",
                                                               OVERSIZE_LOG_TEXT)


def test_oversize_exit_is_a_normal_failed_attempt(client, db_rows):
    login(client, LAYER1)
    r = client.post("/exit", data={"layer1": "A" * 40000})
    assert r.status_code == 200 and outcome_of(r) == "exit_denied" and layer_of(r) == 2
    row = db_rows()[-1]
    assert (row["action"], row["outcome"]) == ("exit", "oversize")


def test_oversize_requests_count_toward_the_delay(slow_app):
    c = slow_app.test_client()
    login(c, "A" * 40000)
    login(c, "A" * 40000)
    login(c, "wrong")
    assert slow_app.recorded_sleeps == [1, 2, 4]


def test_oversize_requests_respect_the_concurrency_cap(app, db_rows):
    t = app.extensions["maze"]["throttle"]
    t.try_enter("127.0.0.1")
    t.try_enter("127.0.0.1")
    r = login(app.test_client(), "A" * 40000)
    assert r.status_code == 429 and db_rows()[-1]["outcome"] == "throttled"


# --- response headers ---------------------------------------------------------

@pytest.mark.parametrize("method, path", [("get", "/"), ("get", "/exit"), ("post", "/login"),
                                          ("get", "/no-such-page"), ("get", "/login")])
def test_security_headers_on_every_response(client, method, path):
    h = getattr(client, method)(path).headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer"
    assert h["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]


def test_pages_work_under_their_own_csp(client):
    """The CSP forbids scripts, so no page may need one."""
    for path in ("/", "/exit"):
        assert b"<script" not in client.get(path).data


# --- IPv6 / throttle keys -----------------------------------------------------

@pytest.mark.parametrize("address, key", [
    ("127.0.0.1", "127.0.0.1"),
    ("2001:db8::1", "2001:db8::/64"),
    ("2001:db8:0:0:ffff::5", "2001:db8::/64"),
    ("2001:db8:0:1::1", "2001:db8:0:1::/64"),
    ("::ffff:10.0.0.1", "10.0.0.1"),
    ("fe80::1%eth0", "fe80::/64"),
    ("not-an-ip", "not-an-ip"),
    ("", ""),
    (None, ""),
])
def test_ip_key(address, key):
    assert ip_key(address) == key


def test_rotating_addresses_inside_one_ipv6_prefix_share_the_delay(slow_app, db_rows):
    c = slow_app.test_client()
    for addr in ("2001:db8::1", "2001:db8::2", "2001:db8::beef"):
        login(c, "bad", environ_base={"REMOTE_ADDR": addr})
    assert slow_app.recorded_sleeps == [1, 2, 4]
    login(c, "bad", environ_base={"REMOTE_ADDR": "2001:db8:0:1::1"})  # another /64
    assert slow_app.recorded_sleeps[-1] == 1
    rows = slow_app.extensions["maze"]["log"].all()
    assert rows[0]["ip"] == "2001:db8::1"  # the log keeps the exact address


def test_ipv4_mapped_ipv6_shares_the_ipv4_delay(slow_app):
    c = slow_app.test_client()
    login(c, "bad", environ_base={"REMOTE_ADDR": "127.0.0.1"})
    login(c, "bad", environ_base={"REMOTE_ADDR": "::ffff:127.0.0.1"})
    assert slow_app.recorded_sleeps == [1, 2]


# --- retention through the app config ---------------------------------------------

def test_log_retention_comes_from_the_config(tmp_path, monkeypatch):
    monkeypatch.setenv("MAZE_REAL_PASSWORD", TEST_REAL_PASSWORD)
    cfg = json.loads(DEFAULT_LAYERS_PATH.read_text())
    cfg["logging"]["max_rows"] = 3
    path = tmp_path / "layers.json"
    path.write_text(json.dumps(cfg))
    app = create_app({"LAYERS_PATH": path, "DB_PATH": tmp_path / "r.db", "DELAY_ENABLED": False})
    c = app.test_client()
    for i in range(10):
        login(c, f"guess{i}")
    log = app.extensions["maze"]["log"]
    assert log.max_rows == 3
    log.prune()
    assert [r["password"] for r in log.all()] == ["guess7", "guess8", "guess9"]
