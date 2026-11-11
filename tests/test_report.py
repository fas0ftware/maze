"""Minator (app.report): passive attacker report built from the attempt log."""
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from app import report
from app.storage import AttemptLog

ROOT = Path(__file__).resolve().parent.parent


def add(log, ip, pw, t, outcome="wrong", action="login", layer=1, sid=None, ua="Mozilla/5.0"):
    log.record(ip=ip, session_id=sid or f"s-{ip}", action=action, layer=layer, password=pw,
               outcome=outcome, user_agent=ua, now=t)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "log.db"
    log = AttemptLog(path)
    # bot: 12 common passwords, every 5 s, hydra UA
    for i, pw in enumerate(["123456", "password", "qwerty", "admin", "letmein", "root",
                            "abc123", "111111", "dragon", "monkey", "toor", "master"]):
        add(log, "203.0.113.7", pw, 1000 + i * 5, ua="Mozilla/4.0 (Hydra)")
    # human: bait taken, reaches layer 3, tries exit
    add(log, "198.51.100.2", "admin123", 2000, "decoy_found", layer=1)
    add(log, "198.51.100.2", "root!2024", 2100, "decoy_found", layer=2)
    add(log, "198.51.100.2", "guess", 2400, layer=3)
    add(log, "198.51.100.2", "admin123 | root!2024", 2500, "exit_granted", action="exit", layer=3)
    # prober with injection payloads, then a pause longer than the idle gap
    add(log, "2001:db8::1", "' OR '1'='1", 3000)
    add(log, "2001:db8::1", "<script>alert(1)</script>\x1b[31m", 3010)
    add(log, "2001:db8::1", "x", 3010 + 4 * 3600)
    # throttled / redacted rows carry no guess
    add(log, "192.0.2.9", "[not stored: throttled]", 5000, "throttled")
    add(log, "192.0.2.9", "[REDACTED:REAL_PASSWORD]", 5001, "real_success", layer=3)
    return str(path)


def by_ip(db_path):
    return {a.ip: a for a in report.analyze(report.load_rows(db_path))}


def test_busy_time_ignores_long_pauses():
    assert report.busy_time([0, 10, 20, 20 + 3600, 20 + 3610], idle_gap=1800) == 30
    assert report.busy_time([5]) == 0


def test_bot_is_detected(db):
    bot = by_ip(db)["203.0.113.7"]
    assert bot.attempts == 12 and bot.busy_seconds == 55
    assert {"tool user-agent", "automated (regular timing)", "common wordlist"} <= set(bot.tags)
    assert bot.median_gap == 5


def test_human_progress_and_exit(db):
    h = by_ip(db)["198.51.100.2"]
    assert h.max_layer == 3 and h.decoys_found == 2 and h.exit_attempts == 1 and h.exits_granted == 1
    assert "took the bait" in h.tags and "tried the exit" in h.tags
    assert "automated (regular timing)" not in h.tags
    assert h.threat == "medium"


def test_injection_probes_and_idle_gap(db):
    p = by_ip(db)["2001:db8::1"]
    assert "injection probes" in p.tags
    assert p.busy_seconds == 10  # the 4-hour pause is not "busy" time


def test_real_password_use_is_critical_and_placeholders_are_not_guesses(db):
    r = by_ip(db)["192.0.2.9"]
    assert r.threat == "critical" and "REAL PASSWORD USED" in r.tags
    assert r.distinct_passwords == 0 and r.top_passwords == []


def test_summary_counts_and_hours(db):
    rows = report.load_rows(db)
    s = report.summary(rows, report.analyze(rows))
    assert s["attempts"] == len(rows) == 21 and s["attackers"] == 4
    assert s["outcomes"]["decoy_found"] == 2
    assert sum(n for _, n in s["per_hour"]) == 21
    assert len(s["per_hour"]) >= 5  # quiet hours between the first and last attempt are included


def test_since_filter(db):
    assert len(report.load_rows(db, since_hours=1, now=3010 + 4 * 3600 + 60)) == 1


def test_html_escapes_attacker_input(db):
    rows = report.load_rows(db)
    out = report.render_html(report.summary(rows, report.analyze(rows)), report.analyze(rows), 25)
    assert "<script>alert(1)" not in out
    assert "&lt;script&gt;" in out or "script" not in out.split("<style>")[0]
    assert "default-src 'none'" in out  # CSP: the report can never run script


def test_text_escapes_terminal_sequences(db):
    rows = report.load_rows(db)
    out = report.render_text(report.summary(rows, report.analyze(rows)), report.analyze(rows), 25)
    assert "\x1b" not in out
    assert "Passive report only" in out


def test_json_round_trip(db):
    rows = report.load_rows(db)
    data = json.loads(report.render_json(report.summary(rows, report.analyze(rows)), report.analyze(rows)))
    assert {a["ip"] for a in data["attackers"]} == {"203.0.113.7", "198.51.100.2", "2001:db8::1", "192.0.2.9"}


def test_log_is_opened_read_only(db):
    before = os.path.getmtime(db)
    report.load_rows(db)
    assert os.path.getmtime(db) == before


def test_cli_writes_private_file(db, tmp_path, capsys):
    out = tmp_path / "r.html"
    assert report.main(["--db", db, "--format", "html", "-o", str(out)]) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert report.main(["--db", str(tmp_path / "missing.db")]) == 1
    assert "No attempt log" in capsys.readouterr().err


def test_demo_log_tool_produces_a_report(tmp_path):
    demo = tmp_path / "demo.db"
    subprocess.run([sys.executable, str(ROOT / "tools" / "demo_log.py"), str(demo)], check=True,
                   capture_output=True)
    ips = {a.ip for a in report.analyze(report.load_rows(str(demo)))}
    assert len(ips) == 7
    # documentation ranges only (RFC 5737 / RFC 3849)
    assert all(ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "2001:db8:")) for ip in ips)
