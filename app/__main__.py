"""Run the Maze service: python -m app

Binds to 127.0.0.1 by default. Override with MAZE_HOST / MAZE_PORT.

The pages are served by waitress, a production WSGI server: it reads each
request completely before a worker thread sees it, so a slow client (or a
slowloris attack) cannot tie up threads, and it caps open connections.
MAZE_SERVER=dev uses Flask's development server instead (local debugging only).
"""

import os
import sys

from . import ConfigError, create_app

SERVERS = ("waitress", "dev")
CONNECTION_LIMIT = 500   # open sockets at once; more wait in the listen backlog
CHANNEL_TIMEOUT = 30     # seconds an idle or trickling connection may stay open
EXTRA_THREADS = 4        # above global_concurrency, so a throttled 429 is still answered quickly


def _port_from_env() -> int:
    raw = os.environ.get("MAZE_PORT", "5000")
    try:
        port = int(raw)
    except ValueError:
        port = -1
    if not 1 <= port <= 65535:
        raise ConfigError(f"MAZE_PORT must be a number from 1 to 65535, got {raw!r}.")
    return port


def _server_from_env() -> str:
    server = os.environ.get("MAZE_SERVER", "waitress").strip().lower() or "waitress"
    if server not in SERVERS:
        raise ConfigError(f"MAZE_SERVER must be one of {', '.join(SERVERS)}, got {server!r}.")
    return server


def run_server(app, host: str, port: int, server: str) -> None:
    if server == "dev":
        app.run(host=host, port=port, debug=False, threaded=True)
        return
    from waitress import serve

    cfg = app.extensions["maze"]["config"]
    serve(
        app,
        host=host,
        port=port,
        threads=cfg["global_concurrency"] + EXTRA_THREADS,
        connection_limit=CONNECTION_LIMIT,
        channel_timeout=CHANNEL_TIMEOUT,
        ident="",  # no Server header: nothing to fingerprint
        # remote_addr must stay the TCP peer; forwarded headers are attacker-controlled.
        clear_untrusted_proxy_headers=True,
        _quiet=True,
    )


def main() -> int:
    host = os.environ.get("MAZE_HOST", "127.0.0.1")
    try:
        port = _port_from_env()
        server = _server_from_env()
        app = create_app()
    except ConfigError as exc:
        print(f"[maze] {exc}", file=sys.stderr)
        return 1
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[maze] WARNING: binding to {host}. Do not expose Maze to the internet "
              "without isolation.", file=sys.stderr)
    if server == "dev":
        print("[maze] Using Flask's development server (MAZE_SERVER=dev); not for real use.",
              file=sys.stderr)
    else:
        print(f"[maze] Serving on http://{host}:{port}/", file=sys.stderr)
    try:
        run_server(app, host, port, server)
    except OSError as exc:  # port in use, no permission, bad address...
        print(f"[maze] Cannot listen on {host}:{port}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
