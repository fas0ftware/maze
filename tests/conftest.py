import re
import sqlite3

import pytest

from app import create_app

TEST_REAL_PASSWORD = "test-only-real-pw"
LAYER1 = "admin123"
LAYER2 = "root!2024"


@pytest.fixture
def sleeps():
    """Records requested delays instead of actually sleeping."""
    return []


@pytest.fixture
def app(tmp_path, monkeypatch, sleeps):
    monkeypatch.setenv("MAZE_REAL_PASSWORD", TEST_REAL_PASSWORD)
    monkeypatch.delenv("MAZE_DELAY_ENABLED", raising=False)
    application = create_app({
        "DB_PATH": tmp_path / "test.db",
        "DELAY_ENABLED": False,
        "SLEEP_FUNC": sleeps.append,
    })
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db_rows(app):
    def rows():
        return app.extensions["maze"]["log"].all()
    return rows


# The page has no machine-readable markers on purpose; read the visible text.
MESSAGE_TO_OUTCOME = [
    ("password found", "decoy_found"),
    ("Wrong password", "wrong"),
    ("Access granted", "real_success"),
    ("Exit verified", "exit_granted"),
    ("Exit denied", "exit_denied"),
    ("No exit from here", "exit_unavailable"),
    ("Too many requests", "throttled"),
]


def layer_of(response) -> int:
    return int(re.search(rb"Stage (\d) of 3", response.data).group(1))


def outcome_of(response) -> str:
    m = re.search(rb'<div class="msg">(.*?)</div>', response.data)
    if not m:
        return ""
    text = m.group(1).decode()
    for needle, outcome in MESSAGE_TO_OUTCOME:
        if needle in text:
            return outcome
    raise AssertionError(f"Unknown message: {text!r}")


def login(client, password, **kwargs):
    return client.post("/login", data={"password": password}, **kwargs)


def count_tables(db_path):
    with sqlite3.connect(db_path) as conn:
        return conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
