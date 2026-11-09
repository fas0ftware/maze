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

LAYERS = {"1": ["a1"], "2": ["b2"]}


def write_cfg(tmp_path, data):
    path = tmp_path / "layers.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


def cfg_with(**sections):
    return {"layers": LAYERS, **sections}


BAD_CONFIGS = {
    "not json": "{oops",
    "top-level list": "[]",
    "layers is a list": {"layers": []},
    "empty layer list": {"layers": {"1": [], "2": ["b"]}},
    "layer 2 missing": {"layers": {"1": ["a"]}},
    "empty-string decoy": {"layers": {"1": [""], "2": ["b"]}},
    "non-string decoy": {"layers": {"1": [5], "2": ["b"]}},
    "limits is a string": cfg_with(limits="x"),
    "delay is a list": cfg_with(delay=[]),
    "logging is a number": cfg_with(logging=3),
    "base is text": cfg_with(delay={"base_seconds": "abc"}),
    "base is bool": cfg_with(delay={"base_seconds": True}),
    "enabled is text": cfg_with(delay={"enabled": "false"}),
    "max is infinite": '{"layers": {"1": ["a"], "2": ["b"]}, "delay": {"max_seconds": 1e999}}',
    "base is NaN": '{"layers": {"1": ["a"], "2": ["b"]}, "delay": {"base_seconds": NaN}}',
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
    cfg = load_layer_config(write_cfg(tmp_path, {"layers": LAYERS}))
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
    assert cfg["decoys"][1] and cfg["decoys"][2]


@pytest.mark.parametrize("raw, expected", [("0", False), ("false", False), ("1", True),
                                           ("YES", True), (" on ", True)])
def test_env_flag_overrides_delay(monkeypatch, raw, expected):
    monkeypatch.setenv("MAZE_DELAY_ENABLED", raw)
    assert load_layer_config(DEFAULT_LAYERS_PATH)["delay_enabled"] is expected


# --- real password quality ------------------------------------------------

def test_short_real_password_logs_a_warning_without_the_password(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("MAZE_REAL_PASSWORD", "s3cr3t")
    with caplog.at_level(logging.WARNING, logger="maze"):
        create_app({"DB_PATH": tmp_path / "w.db"})
    messages = [r.getMessage() for r in caplog.records]
    assert any("shorter than" in m for m in messages)
    assert not any("s3cr3t" in m for m in messages)


def test_strong_real_password_logs_no_warning(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("MAZE_REAL_PASSWORD", "a-long-random-password-9X")
    with caplog.at_level(logging.WARNING, logger="maze"):
        create_app({"DB_PATH": tmp_path / "w.db"})
    assert caplog.records == []


def test_whitespace_around_real_password_is_flagged():
    assert any("whitespace" in w for w in real_password_warnings(" long-enough-password "))
    assert real_password_warnings("long-enough-password") == []
