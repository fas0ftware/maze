import json
import re
import sqlite3
from contextlib import closing

import pytest

from app import create_app
from app.config import DEFAULT_LAYERS_PATH, load_layer_config
from app.hashtool import hash_layer_config, real_password_hash

TEST_REAL_PASSWORD = "test-only-real-pw"
LAYER1 = "admin123"
LAYER2 = "root!2024"
# The cheapest Argon2id settings: the tests check behaviour, not strength.
CHEAP = {"opslimit": 1, "memlimit_kib": 8}

PLAIN_LAYERS = {"1": {"decoys": [LAYER1, "Winter2024!", "letmein"]},
                "2": {"decoys": [LAYER2, "SuperSecret99", "changeme_now"]}}


def plain_config(**overrides) -> dict:
    """The shipped config's tunables with plain-text test decoys."""
    shipped = json.loads(DEFAULT_LAYERS_PATH.read_text())
    base = {k: v for k, v in shipped.items() if k not in ("_comment", "decoy_kdf", "layers")}
    return {**base, "layer_count": 3, "layers": PLAIN_LAYERS, **overrides}


def write_hashed_config(path, **overrides):
    """Write a hashed (cheap) layer config built from plain_config(**overrides)."""
    path.write_text(json.dumps(hash_layer_config(plain_config(**overrides), **CHEAP)))
    return path


def real_hash_for(layers_path, password=TEST_REAL_PASSWORD) -> str:
    return real_password_hash(password, load_layer_config(layers_path), **CHEAP)


@pytest.fixture(scope="session")
def test_layers(tmp_path_factory):
    return write_hashed_config(tmp_path_factory.mktemp("cfg") / "layers.json")


@pytest.fixture(scope="session")
def test_real_hash(test_layers):
    return real_hash_for(test_layers)


@pytest.fixture(autouse=True)
def maze_env(monkeypatch, test_layers, test_real_hash):
    """Every test runs on the cheap test config and the test real-password hash."""
    monkeypatch.delenv("MAZE_REAL_PASSWORD", raising=False)
    monkeypatch.setenv("MAZE_REAL_PASSWORD_HASH", test_real_hash)
    monkeypatch.setenv("MAZE_LAYERS_PATH", str(test_layers))


@pytest.fixture
def sleeps():
    """Records requested delays instead of actually sleeping."""
    return []


@pytest.fixture
def app(tmp_path, monkeypatch, sleeps):
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


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def slow_app(tmp_path, monkeypatch, clock):
    """App with delays ENABLED; sleeps are recorded, not performed."""
    monkeypatch.delenv("MAZE_DELAY_ENABLED", raising=False)
    recorded = []
    application = create_app({"DB_PATH": tmp_path / "slow.db", "DELAY_ENABLED": True,
                              "SLEEP_FUNC": recorded.append, "CLOCK": clock})
    application.recorded_sleeps = recorded
    return application


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
    # `with sqlite3.connect(...)` only commits; closing() is what actually closes.
    with closing(sqlite3.connect(db_path)) as conn:
        return conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
