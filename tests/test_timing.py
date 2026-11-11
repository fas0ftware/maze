"""Roadmap item 4: the final layer must take the same time for the real
password, a decoy and a wrong guess (no timing oracle).

Medians of many interleaved runs are compared, so scheduler noise on a busy
CI machine does not make the test flaky, while a real early-exit (e.g.
skipping the decoy scan or one of the two Argon2id hashes) would show up as a
large, systematic difference."""
import statistics
import time

from app import core
from app.config import load_layer_config, read_real_password_hash
from tests.conftest import LAYER1, LAYER2, TEST_REAL_PASSWORD

ROUNDS = 150


def final_layer_time(engine, password):
    session = core.new_session()
    session.layer = engine.layer_count
    start = time.perf_counter()
    engine.login(session, password)
    return time.perf_counter() - start


def test_final_layer_time_does_not_depend_on_the_password(test_layers):
    cfg = load_layer_config(test_layers)
    real_kdf, real_hash = read_real_password_hash()
    engine = core.Engine(cfg["layer_count"], cfg["decoy_kdf"], real_kdf, real_hash,
                         cfg["decoys"], cfg["routes"])
    cases = {"real": TEST_REAL_PASSWORD, "decoy1": LAYER1, "decoy2": LAYER2,
             "wrong": "definitely-wrong-guess", "empty-ish": "x"}
    samples = {k: [] for k in cases}
    for _ in range(5):  # warm-up
        for pw in cases.values():
            final_layer_time(engine, pw)
    for i in range(ROUNDS):
        order = list(cases.items())
        order = order[i % len(order):] + order[: i % len(order)]  # rotate to spread noise
        for name, pw in order:
            samples[name].append(final_layer_time(engine, pw))
    medians = {k: statistics.median(v) for k, v in samples.items()}
    ratio = max(medians.values()) / min(medians.values())
    print(f"median per guess: { {k: round(v * 1e6, 1) for k, v in medians.items()} } us, ratio {ratio:.3f}")
    assert ratio < 1.5, f"timing differs by {ratio:.2f}x: {medians}"


def test_final_layer_outcomes_are_still_correct(test_layers):
    cfg = load_layer_config(test_layers)
    real_kdf, real_hash = read_real_password_hash()
    engine = core.Engine(cfg["layer_count"], cfg["decoy_kdf"], real_kdf, real_hash,
                         cfg["decoys"], cfg["routes"])
    results = {}
    for pw in (TEST_REAL_PASSWORD, LAYER1, "wrong"):
        s = core.new_session()
        s.layer = engine.layer_count
        results[pw] = engine.login(s, pw)
    assert results[TEST_REAL_PASSWORD].layer_after == engine.layer_count
    fields = [f[0] for f in core.Result._fields_]
    assert "layer_after" in fields
