"""Maze: a layered honeypot login service (prototype)."""

import logging
import os
import time

from flask import Flask, render_template, request, session

from .config import (
    DEFAULT_DB_PATH,
    ConfigError,
    ensure_real_password_not_in_decoys,
    load_layer_config,
    read_real_password,
    real_password_warnings,
)
from .maze import (
    EXIT_DENIED_MESSAGE,
    FINAL_LAYER,
    OVERSIZE,
    OVERSIZE_LOG_TEXT,
    REAL_SUCCESS,
    WRONG_MESSAGE,
    Maze,
    Result,
    SessionStore,
)
from .storage import AttemptLog, sanitize
from .throttle import Throttle

__all__ = ["create_app", "ConfigError"]

LOG = logging.getLogger("maze")

MAX_FIELD_LENGTH_ACCEPTED = 4096  # anything longer is cut before processing
THROTTLED = "throttled"
THROTTLED_MESSAGE = "Too many requests. Please slow down."

# Sent on every response, error pages included.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    ),
}


def create_app(overrides=None) -> Flask:
    """Build the Flask app. Raises ConfigError if MAZE_REAL_PASSWORD is not set.

    overrides (all optional): LAYERS_PATH, DB_PATH, DELAY_ENABLED, SLEEP_FUNC, CLOCK.
    """
    overrides = overrides or {}
    real_password = read_real_password()
    for warning in real_password_warnings(real_password):
        LOG.warning(warning)
    cfg = load_layer_config(overrides.get("LAYERS_PATH"))
    ensure_real_password_not_in_decoys(real_password, cfg["decoys"])
    if "DELAY_ENABLED" in overrides:
        cfg["delay_enabled"] = bool(overrides["DELAY_ENABLED"])

    app = Flask(__name__)
    app.config.update(
        # The cookie only carries a random session id; a per-process key is fine.
        SECRET_KEY=os.environ.get("MAZE_SECRET_KEY") or os.urandom(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=16 * 1024,
    )

    maze = Maze(cfg["decoys"], real_password)
    store = SessionStore(max_sessions=cfg["max_sessions"], ttl=cfg["session_ttl"])
    throttle = Throttle(
        base=cfg["delay_base"],
        maximum=cfg["delay_max"],
        reset_after=cfg["delay_reset_after"],
        per_ip_concurrency=cfg["per_ip_concurrency"],
        global_concurrency=cfg["global_concurrency"],
        clock=overrides.get("CLOCK", time.monotonic),
    )
    db_path = overrides.get("DB_PATH") or os.environ.get("MAZE_DB_PATH") or DEFAULT_DB_PATH
    attempt_log = AttemptLog(db_path, max_rows=cfg["max_rows"])
    sleep = overrides.get("SLEEP_FUNC", time.sleep)

    app.extensions["maze"] = {"log": attempt_log, "store": store, "config": cfg,
                              "throttle": throttle}

    @app.after_request
    def add_security_headers(response):
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    def current_session(create: bool):
        """Return (session id, state).

        With create=False nothing is stored and no cookie is issued: a visitor
        without a session just sees layer 1.
        """
        sid = session.get("sid")
        if not isinstance(sid, str) or not sid or len(sid) > 64:
            if not create:
                return "", store.get("", create=False)
            sid = store.new_id()
            session["sid"] = sid
        return sid, store.get(sid, create=create)

    def form_value(name: str) -> str:
        value = request.form.get(name, "")
        return value[:MAX_FIELD_LENGTH_ACCEPTED] if isinstance(value, str) else ""

    def client_ip() -> str:
        # remote_addr only: X-Forwarded-For is attacker-controlled.
        return sanitize(request.remote_addr, 64)

    def log_attempt(*, ip, sid, action, layer, password, outcome):
        attempt_log.record(
            ip=ip,
            session_id=sid,
            action=action,
            layer=layer,
            password=sanitize(password, cfg["max_password_length"]),
            outcome=outcome,
            user_agent=sanitize(request.headers.get("User-Agent", ""), cfg["max_user_agent_length"]),
        )

    def attempt(action, template, evaluate, raw_log_text):
        """Shared flow for login and exit attempts.

        1. Reserve a concurrency slot, or reject immediately (429). Rejected
           requests never create a session.
        2. Sleep for a delay based only on this IP's PAST failures, BEFORE the
           password is looked at, so timing never reveals the answer.
        3. Evaluate, record the failure count, log.
        """
        ip = client_ip()
        sid, state = current_session(create=False)
        if not throttle.try_enter(ip):
            log_attempt(ip=ip, sid=sid, action=action, layer=state.layer,
                        password=raw_log_text, outcome=THROTTLED)
            return render_template(template, layer=state.layer, message=THROTTLED_MESSAGE,
                                   required=list(range(1, state.layer))), 429
        try:
            sid, state = current_session(create=True)
            if cfg["delay_enabled"]:
                sleep(throttle.delay_for(ip))
            result = evaluate(state)
            throttle.record(ip, failed=result.failed,
                            real_success=result.outcome == REAL_SUCCESS)
            log_attempt(ip=ip, sid=sid, action=action, layer=result.layer_before,
                        password=result.log_password, outcome=result.outcome)
        finally:
            throttle.leave(ip)
        # Same status for every outcome: the page text is the only signal.
        return render_template(template, layer=state.layer, message=result.message,
                               required=list(range(1, state.layer)))

    @app.errorhandler(413)
    def request_too_large(_error):
        """An oversize body is a failed attempt like any other.

        Without this, Werkzeug's stock 413 page would be sent: a different page
        from the rest of the maze, not logged, not delayed and not counted.
        """
        exiting = request.path.rstrip("/") == "/exit"
        message = EXIT_DENIED_MESSAGE if exiting else WRONG_MESSAGE

        def evaluate(state):
            return Result(OVERSIZE, message, state.layer, state.layer, OVERSIZE_LOG_TEXT, True)

        return attempt("exit" if exiting else "login",
                       "exit.html" if exiting else "login.html",
                       evaluate, OVERSIZE_LOG_TEXT)

    @app.get("/")
    def index():
        _, state = current_session(create=False)
        return render_template("login.html", layer=state.layer, message="")

    @app.post("/login")
    def login():
        password = form_value("password")
        return attempt("login", "login.html",
                       lambda state: maze.login(state, password),
                       maze.redact(password))

    @app.route("/exit", methods=["GET", "POST"])
    def exit_flow():
        if request.method == "GET":
            _, state = current_session(create=False)
            return render_template("exit.html", layer=state.layer,
                                   required=list(range(1, state.layer)), message="")
        answers = {i: form_value(f"layer{i}") for i in range(1, FINAL_LAYER)}
        return attempt("exit", "exit.html",
                       lambda state: maze.exit(state, answers),
                       " | ".join(maze.redact(v) for v in answers.values() if v))

    return app
