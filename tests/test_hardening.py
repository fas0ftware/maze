"""Regression tests for gaps found in the v0.x review."""

import json

import pytest

from app import create_app
from app.config import DEFAULT_LAYERS_PATH
from app.maze import OVERSIZE_LOG_TEXT, REAL_PASSWORD_REDACTED, THROTTLED_LOG_TEXT
from app.throttle import ip_key
from conftest import LAYER1, LAYER2, TEST_REAL_PASSWORD, write_hashed_config, layer_of, login, outcome_of


# --- the real password never reaches the log --------------------------------

def test_real_password_is_redacted_on_every_layer(client, db_rows):
    for decoy in (None, LAYER1, LAYER2):
        if decoy:
            login(client, decoy)
        login(client, TEST_REAL_PASSWORD)
        assert db_rows()[-1]["password"] == REAL_PASSWORD_REDACTED


@pytest.mark.parametrize("typed", [
    TEST_REAL_PASSWORD + " ",
    "x" + TEST_REAL_PASSWORD + "y",
], ids=["trailing space", "wrapped"])
def test_near_miss_of_real_password_is_logged_as_typed(client, db_rows, typed):
    """Documented limit: only the hash of the real password is known, so only an
    exact match can be recognised and redacted. Treat the log as sensitive."""
    login(client, typed)
    assert db_rows()[-1]["password"] == typed


def test_real_password_as_an_exit_answer_is_redacted(client, db_rows):
    login(client, LAYER1)
    login(client, LAYER2)
    client.post("/exit", data={"layer1": TEST_REAL_PASSWORD, "layer2": "x"})
    row = db_rows()[-1]
    assert row["action"] == "exit"
    assert row["password"] == f"{REAL_PASSWORD_REDACTED} | x"


def test_throttled_guess_is_not_stored(app, db_rows):
    t = app.extensions["maze"]["throttle"]
    t.try_enter("127.0.0.1")
    t.try_enter("127.0.0.1")
    login(app.test_client(), "x" + TEST_REAL_PASSWORD)
    assert db_rows()[-1]["password"] == THROTTLED_LOG_TEXT


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
    cfg = json.loads(DEFAULT_LAYERS_PATH.read_text())
    path = write_hashed_config(tmp_path / "layers.json",
                               logging={**cfg["logging"], "max_rows": 3})
    app = create_app({"LAYERS_PATH": path, "DB_PATH": tmp_path / "r.db", "DELAY_ENABLED": False})
    c = app.test_client()
    for i in range(10):
        login(c, f"guess{i}")
    log = app.extensions["maze"]["log"]
    assert log.max_rows == 3
    log.prune()
    assert [r["password"] for r in log.all()] == ["guess7", "guess8", "guess9"]
