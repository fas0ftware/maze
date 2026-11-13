import pytest
from flask import Flask

from app import __main__ as entry


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("MAZE_DB_PATH", str(tmp_path / "main.db"))
    monkeypatch.delenv("MAZE_HOST", raising=False)
    monkeypatch.delenv("MAZE_PORT", raising=False)


@pytest.fixture
def served(monkeypatch):
    """Replace both servers so main() does not block; records how they were called."""
    calls = []
    monkeypatch.setattr(Flask, "run", lambda self, **kw: calls.append({"server": "dev", **kw}))
    monkeypatch.setattr("waitress.serve", lambda app, **kw: calls.append({"server": "waitress", **kw}))
    return calls


def test_missing_password_returns_1(env, monkeypatch, capsys, served):
    monkeypatch.delenv("MAZE_REAL_PASSWORD_HASH")
    assert entry.main() == 1
    assert "MAZE_REAL_PASSWORD_HASH" in capsys.readouterr().err
    assert served == []


def test_missing_library_returns_1(env, monkeypatch, capsys, served, tmp_path):
    from app import core
    monkeypatch.setattr(core, "_lib", None)
    monkeypatch.setenv("MAZE_LIB", str(tmp_path / "nope.so"))
    assert entry.main() == 1
    assert "make -C core" in capsys.readouterr().err
    assert served == []


@pytest.mark.parametrize("port", ["abc", "", "0", "-1", "70000", "5000.5"])
def test_bad_port_returns_1_without_a_traceback(env, monkeypatch, capsys, served, port):
    monkeypatch.setenv("MAZE_PORT", port)
    assert entry.main() == 1
    assert "MAZE_PORT" in capsys.readouterr().err
    assert served == []


def test_serves_with_waitress_on_loopback_by_default_without_warning(env, capsys, served):
    assert entry.main() == 0
    assert len(served) == 1
    call = served[0]
    assert call["server"] == "waitress" and call["host"] == "127.0.0.1" and call["port"] == 5000
    # Enough threads for every allowed in-flight request plus quick 429 answers.
    assert call["threads"] == 32 + entry.EXTRA_THREADS
    assert call["ident"] == "" and call["clear_untrusted_proxy_headers"] is True
    assert call["connection_limit"] > 0 and call["channel_timeout"] > 0
    assert "WARNING" not in capsys.readouterr().err


def test_dev_server_on_request(env, monkeypatch, capsys, served):
    monkeypatch.setenv("MAZE_SERVER", "dev")
    assert entry.main() == 0
    assert served == [{"server": "dev", "host": "127.0.0.1", "port": 5000, "debug": False, "threaded": True}]
    assert "development server" in capsys.readouterr().err


def test_unknown_server_returns_1(env, monkeypatch, capsys, served):
    monkeypatch.setenv("MAZE_SERVER", "gunicorn")
    assert entry.main() == 1
    assert "MAZE_SERVER" in capsys.readouterr().err
    assert served == []


def test_warns_when_binding_beyond_loopback(env, monkeypatch, capsys, served):
    monkeypatch.setenv("MAZE_HOST", "0.0.0.0")
    assert entry.main() == 0
    assert "WARNING" in capsys.readouterr().err


def test_bind_failure_returns_1(env, monkeypatch, capsys):
    def boom(*a, **kw):
        raise OSError("Address already in use")
    monkeypatch.setattr("waitress.serve", boom)
    assert entry.main() == 1
    assert "Address already in use" in capsys.readouterr().err
