import pytest
from flask import Flask

from app import __main__ as entry


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("MAZE_REAL_PASSWORD", "a-long-random-password-9X")
    monkeypatch.setenv("MAZE_DB_PATH", str(tmp_path / "main.db"))
    monkeypatch.delenv("MAZE_HOST", raising=False)
    monkeypatch.delenv("MAZE_PORT", raising=False)


@pytest.fixture
def served(monkeypatch):
    """Replace Flask.run so main() does not block; records how it was called."""
    calls = []
    monkeypatch.setattr(Flask, "run", lambda self, **kw: calls.append(kw))
    return calls


def test_missing_password_returns_1(env, monkeypatch, capsys):
    monkeypatch.delenv("MAZE_REAL_PASSWORD")
    assert entry.main() == 1
    assert "MAZE_REAL_PASSWORD" in capsys.readouterr().err


@pytest.mark.parametrize("port", ["abc", "", "0", "-1", "70000", "5000.5"])
def test_bad_port_returns_1_without_a_traceback(env, monkeypatch, capsys, served, port):
    monkeypatch.setenv("MAZE_PORT", port)
    assert entry.main() == 1
    assert "MAZE_PORT" in capsys.readouterr().err
    assert served == []


def test_serves_on_loopback_by_default_without_warning(env, capsys, served):
    assert entry.main() == 0
    assert served == [{"host": "127.0.0.1", "port": 5000, "debug": False, "threaded": True}]
    assert "WARNING" not in capsys.readouterr().err


def test_warns_when_binding_beyond_loopback(env, monkeypatch, capsys, served):
    monkeypatch.setenv("MAZE_HOST", "0.0.0.0")
    assert entry.main() == 0
    assert "WARNING" in capsys.readouterr().err


def test_bind_failure_returns_1(env, monkeypatch, capsys):
    def boom(self, **kw):
        raise OSError("Address already in use")
    monkeypatch.setattr(Flask, "run", boom)
    assert entry.main() == 1
    assert "Address already in use" in capsys.readouterr().err
