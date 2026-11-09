"""Maze: a layered honeypot login service (prototype)."""

import os
import time

from flask import Flask, render_template, request, session

from .config import (
    DEFAULT_DB_PATH,
    ConfigError,
    ensure_real_password_not_in_decoys,
    load_layer_config,
    read_real_password,
)
from .maze import FINAL_LAYER, WRONG, Maze, SessionStore, compute_delay
from .storage import AttemptLog, sanitize

__all__ = ["create_app", "ConfigError"]

MAX_FIELD_LENGTH_ACCEPTED = 4096  # anything longer is cut before processing


def create_app(overrides=None) -> Flask:
    """Build the Flask app. Raises ConfigError if MAZE_REAL_PASSWORD is not set.

    overrides (all optional): LAYERS_PATH, DB_PATH, DELAY_ENABLED, SLEEP_FUNC.
    """
    overrides = overrides or {}
    real_password = read_real_password()
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
    store = SessionStore()
    db_path = overrides.get("DB_PATH") or os.environ.get("MAZE_DB_PATH") or DEFAULT_DB_PATH
    attempt_log = AttemptLog(db_path)
    sleep = overrides.get("SLEEP_FUNC", time.sleep)

    app.extensions["maze"] = {"log": attempt_log, "store": store, "config": cfg}

    def current_session():
        sid = session.get("sid")
        if not isinstance(sid, str) or len(sid) > 64:
            sid = store.new_id()
            session["sid"] = sid
        return sid, store.get(sid)

    def form_value(name: str) -> str:
        value = request.form.get(name, "")
        return value[:MAX_FIELD_LENGTH_ACCEPTED] if isinstance(value, str) else ""

    def record_and_stall(action, sid, state, result):
        attempt_log.record(
            ip=sanitize(request.remote_addr, 64),
            session_id=sid,
            action=action,
            layer=result.layer_before,
            password=sanitize(result.log_password, cfg["max_password_length"]),
            outcome=result.outcome,
            user_agent=sanitize(request.headers.get("User-Agent", ""), cfg["max_user_agent_length"]),
        )
        if result.failed and cfg["delay_enabled"]:
            sleep(compute_delay(state.failures, cfg["delay_base"], cfg["delay_max"]))

    @app.get("/")
    def index():
        _, state = current_session()
        return render_template("login.html", layer=state.layer, outcome="", message="")

    @app.post("/login")
    def login():
        sid, state = current_session()
        result = maze.login(state, form_value("password"))
        record_and_stall("login", sid, state, result)
        status = 401 if result.outcome == WRONG else 200
        return render_template("login.html", layer=state.layer, outcome=result.outcome,
                               message=result.message), status

    @app.route("/exit", methods=["GET", "POST"])
    def exit_flow():
        sid, state = current_session()
        if request.method == "GET":
            return render_template("exit.html", layer=state.layer,
                                   required=list(range(1, state.layer)), outcome="", message="")
        answers = {i: form_value(f"layer{i}") for i in range(1, FINAL_LAYER)}
        result = maze.exit(state, answers)
        record_and_stall("exit", sid, state, result)
        return render_template("exit.html", layer=state.layer,
                               required=list(range(1, state.layer)),
                               outcome=result.outcome, message=result.message)

    return app
