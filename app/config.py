"""Configuration loading for Maze.

Decoy passwords and tunables live in config/layers.json.
The real password is read ONLY from the MAZE_REAL_PASSWORD environment variable.
"""

import json
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LAYERS_PATH = PROJECT_ROOT / "config" / "layers.json"
DEFAULT_DB_PATH = PROJECT_ROOT / "maze.db"

REAL_PASSWORD_ENV = "MAZE_REAL_PASSWORD"


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


def _env_flag(name: str):
    """Parse an optional boolean env var. Returns None when unset."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    return raw.strip().lower() in ("1", "true", "yes", "on")


def load_layer_config(path=None) -> dict:
    """Load and validate config/layers.json, returning a normalized dict."""
    path = Path(path) if path else DEFAULT_LAYERS_PATH
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot read layer config {path}: {exc}") from exc

    layers = raw.get("layers", {})
    decoys = {}
    for key in ("1", "2"):
        values = layers.get(key)
        if not isinstance(values, list) or not values or not all(
            isinstance(v, str) and v for v in values
        ):
            raise ConfigError(f"Layer {key} must be a non-empty list of strings")
        decoys[int(key)] = frozenset(values)

    delay = raw.get("delay", {})
    log_cfg = raw.get("logging", {})
    config = {
        "decoys": decoys,
        "delay_enabled": bool(delay.get("enabled", True)),
        "delay_base": float(delay.get("base_seconds", 1)),
        "delay_max": float(delay.get("max_seconds", 8)),
        "max_password_length": int(log_cfg.get("max_password_length", 128)),
        "max_user_agent_length": int(log_cfg.get("max_user_agent_length", 256)),
    }

    # Environment override, handy for demos: MAZE_DELAY_ENABLED=0
    env_delay = _env_flag("MAZE_DELAY_ENABLED")
    if env_delay is not None:
        config["delay_enabled"] = env_delay

    if config["delay_base"] < 0 or config["delay_max"] < config["delay_base"]:
        raise ConfigError("Invalid delay settings: need 0 <= base_seconds <= max_seconds")
    return config


def ensure_real_password_not_in_decoys(real_password: str, decoys: dict) -> None:
    """Refuse to run if the real password was accidentally put in a decoy list."""
    for layer, values in decoys.items():
        if real_password in values:
            raise ConfigError(
                f"The real password appears in the layer {layer} decoy list. Remove it."
            )
