"""Configuration loading for Maze.

Decoy passwords and tunables live in config/layers.json.
The real password is read ONLY from the MAZE_REAL_PASSWORD environment variable.

Every problem with the configuration surfaces as ConfigError (never a raw
AttributeError/ValueError), so the service can refuse to start with a clear message.
"""

import json
import math
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LAYERS_PATH = PROJECT_ROOT / "config" / "layers.json"
DEFAULT_DB_PATH = PROJECT_ROOT / "maze.db"

REAL_PASSWORD_ENV = "MAZE_REAL_PASSWORD"

MIN_REAL_PASSWORD_LENGTH = 12
# A single request must never be able to hold a worker for longer than this.
MAX_DELAY_CAP_SECONDS = 3600.0


class ConfigError(RuntimeError):
    """Raised when the service must refuse to start."""


def read_real_password() -> str:
    """Return the real password from the environment or refuse to start."""
    value = os.environ.get(REAL_PASSWORD_ENV, "")
    if not value:
        raise ConfigError(
            f"{REAL_PASSWORD_ENV} is not set. Refusing to start without a real password."
        )
    return value


def real_password_warnings(value: str) -> list:
    """Non-fatal problems with the real password. Never includes the password itself."""
    problems = []
    if len(value) < MIN_REAL_PASSWORD_LENGTH:
        problems.append(
            f"{REAL_PASSWORD_ENV} is shorter than {MIN_REAL_PASSWORD_LENGTH} characters. "
            "The decoy layers add no entropy, so use 12+ random characters."
        )
    if value != value.strip():
        problems.append(
            f"{REAL_PASSWORD_ENV} starts or ends with whitespace. "
            "If that is not intended, check how you set the variable (.env quoting?)."
        )
    return problems


def _env_flag(name: str):
    """Parse an optional boolean env var. Returns None when unset."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _section(raw: dict, name: str) -> dict:
    value = raw.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"'{name}' in the layer config must be a JSON object")
    return value


def _number(section: dict, section_name: str, key: str, default, *, integer: bool = False):
    """Read a finite number (or whole number) from a config section."""
    value = section.get(key, default)
    label = f"{section_name}.{key}"
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{label} must be a number")
    if not math.isfinite(value):
        raise ConfigError(f"{label} must be a finite number")
    if integer:
        if value != int(value):
            raise ConfigError(f"{label} must be a whole number")
        return int(value)
    return float(value)


def _flag(section: dict, section_name: str, key: str, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{section_name}.{key} must be true or false")
    return value


def load_layer_config(path=None) -> dict:
    """Load and validate config/layers.json, returning a normalized dict."""
    path = Path(path) if path else DEFAULT_LAYERS_PATH
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:  # ValueError covers bad JSON and bad UTF-8
        raise ConfigError(f"Cannot read layer config {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"Layer config {path} must be a JSON object")

    layers = _section(raw, "layers")
    decoys = {}
    for key in ("1", "2"):
        values = layers.get(key)
        if not isinstance(values, list) or not values or not all(
            isinstance(v, str) and v for v in values
        ):
            raise ConfigError(f"Layer {key} must be a non-empty list of strings")
        decoys[int(key)] = frozenset(values)

    delay = _section(raw, "delay")
    log_cfg = _section(raw, "logging")
    limits = _section(raw, "limits")
    config = {
        "decoys": decoys,
        "delay_enabled": _flag(delay, "delay", "enabled", True),
        "delay_base": _number(delay, "delay", "base_seconds", 1),
        "delay_max": _number(delay, "delay", "max_seconds", 8),
        "delay_reset_after": _number(delay, "delay", "reset_after_seconds", 900),
        "per_ip_concurrency": _number(limits, "limits", "per_ip_concurrency", 2, integer=True),
        "global_concurrency": _number(limits, "limits", "global_concurrency", 32, integer=True),
        "max_sessions": _number(limits, "limits", "max_sessions", 10000, integer=True),
        "session_ttl": _number(limits, "limits", "session_ttl_seconds", 3600),
        "max_password_length": _number(log_cfg, "logging", "max_password_length", 128,
                                       integer=True),
        "max_user_agent_length": _number(log_cfg, "logging", "max_user_agent_length", 256,
                                         integer=True),
        "max_rows": _number(log_cfg, "logging", "max_rows", 100_000, integer=True),
    }

    # Environment override, handy for demos: MAZE_DELAY_ENABLED=0
    env_delay = _env_flag("MAZE_DELAY_ENABLED")
    if env_delay is not None:
        config["delay_enabled"] = env_delay

    if config["delay_base"] < 0 or config["delay_max"] < config["delay_base"]:
        raise ConfigError("Invalid delay settings: need 0 <= base_seconds <= max_seconds")
    if config["delay_max"] > MAX_DELAY_CAP_SECONDS:
        raise ConfigError(f"delay.max_seconds must not exceed {MAX_DELAY_CAP_SECONDS:g}")
    if config["delay_reset_after"] <= 0:
        raise ConfigError("delay.reset_after_seconds must be greater than 0")
    if config["per_ip_concurrency"] < 1 or config["global_concurrency"] < 1:
        raise ConfigError("Concurrency limits must be >= 1")
    if config["max_sessions"] < 1:
        raise ConfigError("limits.max_sessions must be >= 1")
    if config["session_ttl"] <= 0:
        raise ConfigError("limits.session_ttl_seconds must be greater than 0")
    if config["max_password_length"] < 1 or config["max_user_agent_length"] < 1:
        raise ConfigError("logging.max_password_length and max_user_agent_length must be >= 1")
    if config["max_rows"] < 0:
        raise ConfigError("logging.max_rows must be >= 0 (0 keeps every row)")
    return config


def ensure_real_password_not_in_decoys(real_password: str, decoys: dict) -> None:
    """Refuse to run if the real password was accidentally put in a decoy list."""
    for layer, values in decoys.items():
        if real_password in values:
            raise ConfigError(
                f"The real password appears in the layer {layer} decoy list. Remove it."
            )
