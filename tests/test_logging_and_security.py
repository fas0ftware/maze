import pytest

from app import ConfigError, create_app
from app.maze import REAL_PASSWORD_REDACTED
from app.throttle import compute_delay
from conftest import LAYER1, LAYER2, TEST_REAL_PASSWORD, count_tables, layer_of, login, outcome_of


# --- logging -------------------------------------------------------------

def test_table_created_automatically(app, tmp_path):
    assert ("attempts",) in count_tables(tmp_path / "test.db")


def test_attempt_is_logged(client, db_rows):
    login(client, "guess1", headers={"User-Agent": "sim/1.0"})
    login(client, LAYER1, headers={"User-Agent": "sim/1.0"})
    rows = db_rows()
    assert len(rows) == 2
    first, second = rows
    assert first["password"] == "guess1" and first["layer"] == 1 and first["outcome"] == "wrong"
    assert first["user_agent"] == "sim/1.0"
    assert first["ip"] == "127.0.0.1"
    assert first["seconds_since_prev"] is None
    assert second["outcome"] == "decoy_found"
    assert second["seconds_since_prev"] is not None and second["seconds_since_prev"] >= 0


def test_exit_attempts_are_logged(client, db_rows):
    login(client, LAYER1)
    client.post("/exit", data={"layer1": "x"})
    assert db_rows()[-1]["action"] == "exit"


def test_real_password_never_written_to_log(client, db_rows):
    login(client, TEST_REAL_PASSWORD)  # layer 1: wrong, but still must be redacted
    login(client, LAYER1)
    login(client, LAYER2)
    login(client, TEST_REAL_PASSWORD)
    passwords = [r["password"] for r in db_rows()]
    assert TEST_REAL_PASSWORD not in passwords
    assert passwords.count(REAL_PASSWORD_REDACTED) == 2


def test_long_inputs_are_truncated(client, db_rows):
    login(client, "A" * 5000, headers={"User-Agent": "B" * 5000})
    row = db_rows()[0]
    assert len(row["password"]) <= 128 + len("...[truncated]")
    assert len(row["user_agent"]) <= 256 + len("...[truncated]")


def test_control_characters_are_escaped(client, db_rows):
    # The test client rejects newlines in headers, so use other control chars there.
    login(client, "evil\r\n\x1b[31mred", headers={"User-Agent": "ua\x1b[2J\x07"})
    row = db_rows()[0]
    assert not any(c in row["password"] for c in "\r\n\x1b")
    assert not any(c in row["user_agent"] for c in "\x1b\x07")
    assert "\\x1b" in row["user_agent"]


# --- SQL injection -------------------------------------------------------

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "admin'--",
    "'; DROP TABLE attempts; --",
    "\" OR \"\"=\"",
    "1); DELETE FROM attempts; --",
]


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_sql_injection_is_stored_verbatim(client, db_rows, payload):
    r = login(client, payload, headers={"User-Agent": payload})
    assert outcome_of(r) == "wrong" and layer_of(r) == 1
    rows = db_rows()
    assert len(rows) == 1
    assert rows[0]["password"] == payload and rows[0]["user_agent"] == payload


def test_table_survives_drop_attempt(client, db_rows):
    login(client, "'; DROP TABLE attempts; --")
    login(client, "after")
    assert [r["password"] for r in db_rows()][-1] == "after"


# --- delay / stalling ----------------------------------------------------

def test_compute_delay_sequence():
    assert [compute_delay(n, 1, 8) for n in range(0, 7)] == [0, 1, 2, 4, 8, 8, 8]


def test_delay_disabled_in_tests(client, sleeps):
    login(client, "x")
    assert sleeps == []


# --- startup safety ------------------------------------------------------

def test_refuses_to_start_without_real_password(tmp_path, monkeypatch):
    monkeypatch.delenv("MAZE_REAL_PASSWORD", raising=False)
    with pytest.raises(ConfigError):
        create_app({"DB_PATH": tmp_path / "x.db"})


def test_refuses_if_real_password_is_a_decoy(tmp_path, monkeypatch):
    monkeypatch.setenv("MAZE_REAL_PASSWORD", LAYER1)
    with pytest.raises(ConfigError):
        create_app({"DB_PATH": tmp_path / "x.db"})


def test_layers_json_does_not_contain_test_password():
    from app.config import DEFAULT_LAYERS_PATH
    assert TEST_REAL_PASSWORD not in DEFAULT_LAYERS_PATH.read_text()
