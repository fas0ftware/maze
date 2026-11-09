"""Run the Maze service: python -m app

Binds to 127.0.0.1 by default. Override with MAZE_HOST / MAZE_PORT.
"""

import os
import sys

from . import ConfigError, create_app


def _port_from_env() -> int:
    raw = os.environ.get("MAZE_PORT", "5000")
    try:
        port = int(raw)
    except ValueError:
        port = -1
    if not 1 <= port <= 65535:
        raise ConfigError(f"MAZE_PORT must be a number from 1 to 65535, got {raw!r}.")
    return port


def main() -> int:
    host = os.environ.get("MAZE_HOST", "127.0.0.1")
    try:
        port = _port_from_env()
        app = create_app()
    except ConfigError as exc:
        print(f"[maze] {exc}", file=sys.stderr)
        return 1
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[maze] WARNING: binding to {host}. Do not expose Maze to the internet "
              "without isolation.", file=sys.stderr)
    try:
        app.run(host=host, port=port, debug=False, threaded=True)
    except OSError as exc:  # port in use, no permission, bad address...
        print(f"[maze] Cannot listen on {host}:{port}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
