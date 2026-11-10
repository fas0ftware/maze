import json
import logging

import pytest

from app import ConfigError, create_app
from app.config import (
    DEFAULT_LAYERS_PATH,
    MAX_DELAY_CAP_SECONDS,
    load_layer_config,
    real_password_warnings,
)
from app.hashtool import hash_layer_config
from conftest import CHEAP, real_hash_for

_HASHED = hash_layer_config({"layers": {"1": ["a1"], "2": ["b2"]}}, **CHEAP)
LAYERS = _HASHED["layers"]
KDF = _HASHED["decoy_kdf"]
HASH = LAYERS["1"]["decoys"][0]


def write_cfg(tmp_path, data):
    path = tmp_path / "layers.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


def cfg_with(**sections):
    return {"decoy_kdf": KDF, "layers": LAYERS, **sections}


def layers_with(**entries):
    return cfg_with(layers={**LAYERS, **entries})


BAD_CONFIGS = {
    "not json": "{oops",
    "top-level list": "[]",
    "layers is a list": cfg_with(layers=[]),
    "layer is a bare list": layers_with(**{"1": [HASH]}),
    "empty decoy list": layers_with(**{"1": {"decoys": []}}),
    "layer 2 missing": cfg_with(layers={"1": LAYERS["1"]}),
    "plain-text decoy": layers_with(**{"1": {"decoys": ["admin123"]}}),
    "short hash": layers_with(**{"1": {"decoys": [HASH[:-4]]}}),
    "non-string decoy": layers_with(**{"1": {"decoys": [5]}}),
    "too many decoys": layers_with(**{"1": {"decoys": [HASH] * 65}}),
    "decoys on final layer": layers_with(**{"3": {"decoys": [HASH]}}),
    "route out of range": layers_with(**{"1": {"decoys": [HASH], "on_match": 4}}),
    "route zero": layers_with(**{"2": {"decoys": [HASH], "on_wrong": 0}}),
    "unknown layer": layers_with(**{"7": {"decoys": [HASH]}}),
    "layer_count zero": cfg_with(layer_count=0),
    "layer_count too big": cfg_with(layer_count=17),
    "layer_count text": cfg_with(layer_count="3"),
    "kdf missing": {"layers": LAYERS},
    "kdf salt short": cfg_with(decoy_kdf={**KDF, "salt": "AAAA"}),
    "kdf salt not base64": cfg_with(decoy_kdf={**KDF, "salt": "!" * 22}),
    "kdf ops zero": cfg_with(decoy_kdf={**KDF, "opslimit": 0}),
    "kdf ops huge": cfg_with(decoy_kdf={**KDF, "opslimit": 11}),
    "kdf mem tiny": cfg_with(decoy_kdf={**KDF, "memlimit_kib": 4}),
    "kdf mem huge": cfg_with(decoy_kdf={**KDF, "memlimit_kib": 10**9}),
    "limits is a string": cfg_with(limits="x"),
    "delay is a list": cfg_with(delay=[]),
    "logging is a number": cfg_with(logging=3),
    "base is text": cfg_with(delay={"base_seconds": "abc"}),
    "base is bool": cfg_with(delay={"base_seconds": True}),
    "enabled is text": cfg_with(delay={"enabled": "false"}),
    "max is infinite": json.dumps(cfg_with())[:-1] + ', "delay": {"max_seconds": 1e999}}',
    "base is NaN": json.dumps(cfg_with())[:-1] + ', "delay": {"base_seconds": NaN}}',
    "negative base": cfg_with(delay={"base_seconds": -1}),
    "max below base": cfg_with(delay={"base_seconds": 5, "max_seconds": 1}),
    "max above cap": cfg_with(delay={"max_seconds": MAX_DELAY_CAP_SECONDS + 1}),
    "reset_after zero": cfg_with(delay={"reset_after_seconds": 0}),
    "reset_after negative": cfg_with(delay={"reset_after_seconds": -5}),
    "per_ip zero": cfg_with(limits={"per_ip_concurrency": 0}),
    "per_ip fractional": cfg_with(limits={"per_ip_concurrency": 1.5}),
    "global zero": cfg_with(limits={"global_concurrency": 0}),
    "max_sessions zero": cfg_with(limits={"max_sessions": 0}),
    "session_ttl zero": cfg_with(limits={"session_ttl_seconds": 0}),
    "password length zero": cfg_with(logging={"max_password_length": 0}),
    "user agent length negative": cfg_with(logging={"max_user_agent_length": -1}),
    "max_rows negative": cfg_with(logging={"max_rows": -1}),
}


@pytest.mark.parametrize("data", BAD_CONFIGS.values(), ids=BAD_CONFIGS.keys())
def test_bad_config_is_a_config_error(tmp_path, data):
    """Every bad config must give a clean ConfigError, never a raw traceback."""
    with pytest.raises(ConfigError):
        load_layer_config(write_cfg(tmp_path, data))


def test_missing_file_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_layer_config(tmp_path / "does-not-exist.json")


def test_invalid_utf8_is_a_config_error(tmp_path):
    path = tmp_path / "layers.json"
    path.write_bytes(b'{"layers": "\xff\xfe"}')
    with pytest.raises(ConfigError):
        load_layer_config(path)


def test_defaults_when_sections_are_omitted(tmp_path):
    cfg = load_layer_config(write_cfg(tmp_path, cfg_with()))
    assert cfg["layer_count"] == 3
    assert cfg["routes"] == {1: (2, 1), 2: (3, 2), 3: (3, 3)}
    assert cfg["delay_enabled"] is True
    assert (cfg["delay_base"], cfg["delay_max"], cfg["delay_reset_after"]) == (1, 8, 900)
    assert (cfg["per_ip_concurrency"], cfg["global_concurrency"]) == (2, 32)
    assert (cfg["max_sessions"], cfg["session_ttl"], cfg["max_rows"]) == (10000, 3600, 100000)


def test_whole_number_floats_are_accepted(tmp_path):
    cfg = load_layer_config(write_cfg(tmp_path, cfg_with(limits={"per_ip_concurrency": 3.0})))
    assert cfg["per_ip_concurrency"] == 3 and isinstance(cfg["per_ip_concurrency"], int)


def test_max_rows_zero_means_keep_everything(tmp_path):
    cfg = load_layer_config(write_cfg(tmp_path, cfg_with(logging={"max_rows": 0})))
    assert cfg["max_rows"] == 0


def test_shipped_config_is_valid():
    cfg = load_layer_config(DEFAULT_LAYERS_PATH)
    assert cfg["layer_count"] == 3
    assert len(cfg["decoys"][1]) == 4 and len(cfg["decoys"][2]) == 4
    # No plain text: the shipped decoys appear only as hashes.
    assert "admin123" not in DEFAULT_LAYERS_PATH.read_text()


def test_routes_and_layer_count_are_read(tmp_path):
    data = cfg_with(layer_count=4, layers={
        "1": {"decoys": [HASH], "on_match": 3, "on_wrong": 1},
        "2": {"decoys": [HASH]},
        "3": {"decoys": [HASH], "on_wrong": 1},
        "4": {"on_wrong": 1},
    })
    cfg = load_layer_config(write_cfg(tmp_path, data))
    assert cfg["layer_count"] == 4
    assert cfg["routes"] == {1: (3, 1), 2: (3, 2), 3: (4, 1), 4: (4, 1)}


def test_layers_path_env_is_used(tmp_path, monkeypatch):
    monkeypatch.setenv("MAZE_LAYERS_PATH", str(write_cfg(tmp_path, cfg_with(layer_count=3))))
    assert load_layer_config()["decoys"][1]


@pytest.mark.parametrize("raw, expected", [("0", False), ("false", False), ("1", True),
                                           ("YES", True), (" on ", True)])
def test_env_flag_overrides_delay(monkeypatch, raw, expected):
    monkeypatch.setenv("MAZE_DELAY_ENABLED", raw)
    assert load_layer_config(DEFAULT_LAYERS_PATH)["delay_enabled"] is expected


# --- real password: hash only -------------------------------------------------

def test_plain_text_real_password_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("MAZE_REAL_PASSWORD", "a-long-random-password-9X")
    with pytest.raises(ConfigError, match="no longer accepted"):
        create_app({"DB_PATH": tmp_path / "w.db"})


@pytest.mark.parametrize("value", ["", "plain-password", "$argon2id$v=19$m=8,t=1,p=1$AAAA$BBBB",
                                   "$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$" + "A" * 43,
                                   "$argon2id$v=19$m=8,t=99,p=1$c2FsdHNhbHRzYWx0c2FsdA$" + "A" * 43])
def test_bad_real_password_hash_is_refused(tmp_path, monkeypatch, value):
    monkeypatch.setenv("MAZE_REAL_PASSWORD_HASH", value)
    with pytest.raises(ConfigError, match="MAZE_REAL_PASSWORD_HASH"):
        create_app({"DB_PATH": tmp_path / "w.db"})


def test_hashtool_refuses_a_decoy_as_real_password(test_layers):
    with pytest.raises(ConfigError, match="decoy"):
        real_hash_for(test_layers, "admin123")


def test_short_real_password_gets_a_warning():
    assert any("shorter than" in w for w in real_password_warnings("s3cr3t"))
    assert not any("s3cr3t" in w for w in real_password_warnings("s3cr3t"))
    assert real_password_warnings("a-long-random-password-9X") == []


def test_whitespace_around_real_password_is_flagged():
    assert any("whitespace" in w for w in real_password_warnings(" long-enough-password "))
    assert real_password_warnings("long-enough-password") == []
