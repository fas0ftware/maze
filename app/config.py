"""Configuration loading for Maze.

Decoy password HASHES, routing rules and tunables live in config/layers.json
(or the file named by MAZE_LAYERS_PATH). The real password is never stored in
plain text: only its Argon2id hash is read, from MAZE_REAL_PASSWORD_HASH.
Both are produced by `python -m app.hashtool`.

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

REAL_PASSWORD_HASH_ENV = "MAZE_REAL_PASSWORD_HASH"  # env var name, not a secret  # nosec B105
# Plain-text variable of earlier versions; refused so it is not used by mistake.
LEGACY_REAL_PASSWORD_ENV = "MAZE_REAL_PASSWORD"  # env var name, not a secret  # nosec B105
LAYERS_PATH_ENV = "MAZE_LAYERS_PATH"
HASH_TOOL_HINT = "Create it with: python -m app.hashtool real"

MIN_REAL_PASSWORD_LENGTH = 12
# A single request must never be able to hold a worker for longer than this.
MAX_DELAY_CAP_SECONDS = 3600.0


class ConfigError(RuntimeError):
    """Raised when the service must refuse to start."""


def read_real_password_hash():
    """Return (Kdf, hash) of the real password from the environment, or refuse to start."""
    from . import core

    if os.environ.get(LEGACY_REAL_PASSWORD_ENV):
        raise ConfigError(
            f"{LEGACY_REAL_PASSWORD_ENV} (plain text) is no longer accepted. Unset it and set "
            f"{REAL_PASSWORD_HASH_ENV} instead. {HASH_TOOL_HINT}"
        )
    value = os.environ.get(REAL_PASSWORD_HASH_ENV, "")
    if not value:
        raise ConfigError(
            f"{REAL_PASSWORD_HASH_ENV} is not set. Refusing to start without a real "
            f"password. {HASH_TOOL_HINT}"
        )
    try:
        return core.parse_phc(value)
    except ConfigError as exc:
        raise ConfigError(f"{REAL_PASSWORD_HASH_ENV}: {exc}") from exc


def real_password_warnings(value: str) -> list:
    """Non-fatal problems with the real password. Never includes the password itself."""
    problems = []
    if len(value) < MIN_REAL_PASSWORD_LENGTH:
        problems.append(
            f"The real password is shorter than {MIN_REAL_PASSWORD_LENGTH} characters. "
            "The decoy layers add no entropy, so use 12+ random characters."
        )
    if value != value.strip():
        problems.append(
            "The real password starts or ends with whitespace. "
            "If that is not intended, check how you typed or piped it."
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


def _whole(section: dict, section_name: str, key: str, default, low: int, high: int) -> int:
    value = _number(section, section_name, key, default, integer=True)
    if not low <= value <= high:
        raise ConfigError(f"{section_name}.{key} must be from {low} to {high}")
    return value


def _decoy_kdf(raw: dict):
    from . import core

    section = _section(raw, "decoy_kdf")
    if "salt" not in section:
        raise ConfigError("decoy_kdf.salt is missing. Generate the config with "
                          "python -m app.hashtool decoys")
    salt = core.b64decode(section["salt"], core.SALT_BYTES, "decoy_kdf.salt")
    ops = _whole(section, "decoy_kdf", "opslimit", 2, core.KDF_OPS_MIN, core.KDF_OPS_MAX)
    mem = _whole(section, "decoy_kdf", "memlimit_kib", 19456,
                 core.KDF_MEM_KIB_MIN, core.KDF_MEM_KIB_MAX)
    return core.make_kdf(salt, ops, mem)


def _layer_settings(raw: dict) -> dict:
    """Validate layer_count and the layers section (decoy hashes and routes)."""
    from . import core

    count = raw.get("layer_count", 3)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= core.MAX_LAYERS:
        raise ConfigError(f"layer_count must be a whole number from 1 to {core.MAX_LAYERS}")
    layers = _section(raw, "layers")
    allowed = {str(n) for n in range(1, count + 1)}
    unknown = sorted(set(layers) - allowed)
    if unknown:
        raise ConfigError(f"layers has entries outside 1..{count}: {', '.join(unknown)}")

    decoys, routes = {}, {}
    for layer in range(1, count + 1):
        name = f"layers.{layer}"
        entry = layers.get(str(layer), {} if layer == count else None)
        if not isinstance(entry, dict):
            raise ConfigError(f"{name} must be a JSON object with a 'decoys' list")
        is_final = layer == count
        if is_final:
            if "decoys" in entry or "on_match" in entry:
                raise ConfigError(f"{name} is the final layer: it takes only 'on_wrong'")
        else:
            hashes = entry.get("decoys")
            if not isinstance(hashes, list) or not 1 <= len(hashes) <= core.MAX_DECOYS_PER_LAYER:
                raise ConfigError(f"{name}.decoys must be a list of 1 to "
                                  f"{core.MAX_DECOYS_PER_LAYER} decoy hashes")
            decoys[layer] = [core.b64decode(h, core.HASH_BYTES, f"{name}.decoys entry")
                             for h in hashes]
        on_match = layer if is_final else _whole(entry, name, "on_match", layer + 1, 1, count)
        on_wrong = _whole(entry, name, "on_wrong", layer, 1, count)
        routes[layer] = (on_match, on_wrong)

    return {"layer_count": count, "decoy_kdf": _decoy_kdf(raw), "decoys": decoys,
            "routes": routes}


def read_json_config(path=None) -> dict:
    """Read the raw JSON of the layer config (MAZE_LAYERS_PATH or the default)."""
    path = Path(path or os.environ.get(LAYERS_PATH_ENV) or DEFAULT_LAYERS_PATH)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:  # ValueError covers bad JSON and bad UTF-8
        raise ConfigError(f"Cannot read layer config {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"Layer config {path} must be a JSON object")
    return raw


def load_layer_config(path=None) -> dict:
    """Load and validate the layer config, returning a normalized dict."""
    raw = read_json_config(path)
    layer_settings = _layer_settings(raw)

    delay = _section(raw, "delay")
    log_cfg = _section(raw, "logging")
    limits = _section(raw, "limits")
    config = {
        **layer_settings,
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
