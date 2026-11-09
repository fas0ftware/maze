"""Run the Maze service: python -m app

Binds to 127.0.0.1 by default. Override with MAZE_HOST / MAZE_PORT.
"""

import os
import sys

from . import ConfigError, create_app


def main() -> int:
    host = os.environ.get("MAZE_HOST", "127.0.0.1")
    port = int(os.environ.get("MAZE_PORT", "5000"))
    try:
        app = create_app()
    except ConfigError as exc:
        print(f"[maze] {exc}", file=sys.stderr)
        return 1
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[maze] WARNING: binding to {host}. Do not expose Maze to the internet "
              "without isolation.", file=sys.stderr)
    app.run(host=host, port=port, debug=False, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
