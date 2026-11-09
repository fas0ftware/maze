"""End-to-end: the attacker simulator against a real HTTP server running the app."""

import importlib.util
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from conftest import LAYER1, LAYER2, TEST_REAL_PASSWORD

SIM_PATH = Path(__file__).resolve().parent.parent / "tools" / "attacker_sim.py"


@pytest.fixture(scope="module")
def sim():
    spec = importlib.util.spec_from_file_location("attacker_sim", SIM_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def live_url(app):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join(timeout=5)


def test_sim_walks_every_layer_and_the_fake_exit(sim, live_url, db_rows, capsys):
    assert sim.run(live_url, ["nope", LAYER1, "nah", LAYER2, "x"]) == 0
    out = capsys.readouterr().out
    assert "Layer 1 password found: 'admin123'" in out
    assert "Layer 2 password found: 'root!2024'" in out
    rows = db_rows()
    assert [r["outcome"] for r in rows] == [
        "wrong", "decoy_found", "wrong", "decoy_found", "wrong",  # the wordlist
        "exit_denied", "exit_granted",                            # the fake exit
    ]
    assert {r["user_agent"] for r in rows} == {"maze-attacker-sim/0.1"}


def test_sim_with_the_real_password_never_leaks_it_to_the_log(sim, live_url, db_rows, capsys):
    sim.run(live_url, [LAYER1, LAYER2, TEST_REAL_PASSWORD, "unused"])
    assert "Real password accepted" in capsys.readouterr().out
    rows = db_rows()
    assert "real_success" in [r["outcome"] for r in rows]
    assert TEST_REAL_PASSWORD not in [r["password"] for r in rows]


def test_sim_survives_a_page_that_is_not_the_maze(sim, live_url):
    client = sim.Client(live_url)
    assert client.request("/")[0] == 1
    assert client.request("/does-not-exist") == (1, "unexpected_page")


def test_sim_reads_the_429_page(sim, live_url, app):
    t = app.extensions["maze"]["throttle"]
    t.try_enter("127.0.0.1")
    t.try_enter("127.0.0.1")
    assert sim.Client(live_url).request("/login", {"password": "x"}) == (1, "throttled")


def test_sim_refuses_non_loopback_targets(sim):
    sim.ensure_loopback("http://127.0.0.1:5000")  # fine
    with pytest.raises(SystemExit):
        sim.ensure_loopback("http://10.1.2.3:5000")


def test_sim_load_words_skips_blanks_and_comments(sim, tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("one\n\n# comment\n  two  \n", encoding="utf-8")
    assert sim.load_words(path) == ["one", "two"]
