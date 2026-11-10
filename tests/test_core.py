"""The ctypes binding to libmaze and N-layer configs through the web app."""

import pytest

from app import ConfigError, core, create_app
from conftest import TEST_REAL_PASSWORD, login, outcome_of, real_hash_for, write_hashed_config


def test_phc_round_trip():
    kdf = core.make_kdf(core.random_salt(), 1, 8)
    digest = core.hash_password(kdf, "pw")
    parsed_kdf, parsed = core.parse_phc(core.encode_phc(kdf, digest))
    assert parsed == digest
    assert bytes(parsed_kdf.salt) == bytes(kdf.salt)
    assert core.hash_password(parsed_kdf, "pw") == digest


@pytest.mark.parametrize("text", ["", "$argon2id$v=19$m=8,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$" + "A" * 43,
                                  "$argon2id$v=19$m=8,t=1,p=1$AAAA$" + "A" * 43, None, 5])
def test_parse_phc_rejects_bad_input(text):
    with pytest.raises(ConfigError):
        core.parse_phc(text)


def test_hash_uses_every_byte_and_caps_length():
    kdf = core.make_kdf(b"s" * 16, 1, 8)
    assert core.hash_password(kdf, "a\x00b") != core.hash_password(kdf, "a")
    long_guess = "x" * (core.MAX_PASSWORD_BYTES + 100)
    assert core.hash_password(kdf, long_guess) == core.hash_password(
        kdf, "x" * core.MAX_PASSWORD_BYTES)


def test_five_layer_maze_end_to_end(tmp_path, monkeypatch):
    layers = {str(n): {"decoys": [f"decoy{n}"]} for n in range(1, 5)}
    layers["5"] = {"on_wrong": 1}  # a wrong final guess restarts the maze
    path = write_hashed_config(tmp_path / "five.json", layer_count=5, layers=layers)
    monkeypatch.setenv("MAZE_REAL_PASSWORD_HASH", real_hash_for(path))
    app = create_app({"LAYERS_PATH": path, "DB_PATH": tmp_path / "f.db",
                      "DELAY_ENABLED": False})
    c = app.test_client()
    for n in range(1, 5):
        assert login(c, TEST_REAL_PASSWORD).status_code == 200  # never works early
        r = login(c, f"decoy{n}")
        assert outcome_of(r) == "decoy_found"
    assert b"Stage 5 of 5" in r.data
    r = login(c, "decoy2")                      # a decoy on the final layer is just wrong
    assert outcome_of(r) == "wrong" and b"Stage 1 of 5" in r.data
    for n in range(1, 5):
        login(c, f"decoy{n}")
    assert outcome_of(login(c, TEST_REAL_PASSWORD)) == "real_success"
