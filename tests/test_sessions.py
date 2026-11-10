import threading

from app.maze import SessionState, SessionStore
from conftest import LAYER1, LAYER2, TEST_REAL_PASSWORD, layer_of, login


class Clock:
    def __init__(self):
        self.now = 5000.0

    def __call__(self):
        return self.now


# --- SessionStore ----------------------------------------------------------

def test_get_without_create_stores_nothing():
    store = SessionStore()
    assert store.get("abc", create=False).layer == 1
    assert len(store) == 0


def test_get_with_create_keeps_the_state():
    store = SessionStore()
    store.get("abc").core.layer = 2
    assert store.get("abc").layer == 2 and len(store) == 1


def test_idle_session_expires():
    clock = Clock()
    store = SessionStore(ttl=60, clock=clock)
    store.get("a").core.layer = 2
    clock.now += 61
    assert store.get("a").layer == 1


def test_active_session_does_not_expire():
    clock = Clock()
    store = SessionStore(ttl=60, clock=clock)
    store.get("a").core.layer = 2
    for _ in range(5):
        clock.now += 40  # each visit is inside the ttl, so the clock keeps restarting
        assert store.get("a").layer == 2


def test_expired_sessions_are_removed_from_memory():
    clock = Clock()
    store = SessionStore(ttl=60, clock=clock)
    for i in range(5):
        store.get(f"s{i}")
    clock.now += 61
    store.get("fresh")
    assert len(store) == 1


def test_size_cap_evicts_the_oldest_first():
    store = SessionStore(max_sessions=3)
    for name in ("a", "b", "c"):
        store.get(name).core.layer = 2
    store.get("a")          # touch: "b" is now the oldest
    store.get("d").core.layer = 2
    assert len(store) == 3
    assert store.get("b", create=False).layer == 1   # evicted
    assert store.get("a", create=False).layer == 2   # kept


# --- Flask integration -----------------------------------------------------

def test_get_requests_create_no_session_and_no_cookie(app, client):
    store = app.extensions["maze"]["store"]
    r = client.get("/")
    assert "Set-Cookie" not in r.headers
    client.get("/exit")
    assert len(store) == 0


def test_login_creates_the_session_and_cookie(app, client):
    r = login(client, "wrong")
    assert "Set-Cookie" in r.headers
    assert len(app.extensions["maze"]["store"]) == 1


def test_throttled_requests_create_no_session(app):
    t = app.extensions["maze"]["throttle"]
    t.try_enter("127.0.0.1")
    t.try_enter("127.0.0.1")
    r = login(app.test_client(), "x")
    assert r.status_code == 429
    assert len(app.extensions["maze"]["store"]) == 0


def test_get_flood_cannot_push_a_real_session_out(app):
    store = app.extensions["maze"]["store"]
    store.max_sessions = 5
    owner = app.test_client()
    login(owner, LAYER1)
    for _ in range(100):
        app.test_client().get("/")
    assert layer_of(owner.get("/")) == 2
    assert len(store) == 1


# --- Maze under concurrency -------------------------------------------------

def test_maze_state_stays_consistent_when_requests_overlap(app):
    maze = app.extensions["maze"]["maze"]
    state = SessionState()
    sequence = [LAYER1, LAYER2, "nope", TEST_REAL_PASSWORD] * 25

    def worker():
        for pw in sequence:
            maze.login(state, pw)
            maze.exit(state, {1: LAYER1, 2: LAYER2})

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert state.layer in (1, 2, 3)
    # Only layers below the current one can have been cleared.
    assert all(layer < state.layer for layer in state.cleared_layers)
