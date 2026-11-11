"""Minator: a passive report on what attackers did inside the Maze.

    python -m app.report                       # text report of ./maze.db
    python -m app.report --format html -o report.html
    python -m app.report --format json --since 24

It only READS the attempt log. It never contacts, blocks or probes anyone:
no hack-back, no active response. Every value in the log was typed by an
attacker, so it is treated as hostile data and escaped in every output format.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sqlite3
import statistics
import sys
import time
from collections import Counter
from contextlib import closing
from dataclasses import asdict, dataclass, field

from .storage import sanitize

IDLE_GAP = 30 * 60  # a pause longer than this ends a "busy" stretch

# A short list of the most common leaked passwords (public, from many breach lists).
COMMON_PASSWORDS = frozenset("""
123456 password 123456789 12345678 12345 qwerty 1234567 111111 123123 abc123 1234567890
password1 1234 iloveyou 000000 qwerty123 1q2w3e4r dragon monkey letmein football admin
admin123 welcome login master hello sunshine princess 654321 superman qazwsx 123qwe
michael shadow trustno1 baseball passw0rd p@ssw0rd p@ssword starwars whatever freedom
root toor changeme hunter2 secret default guest test test123 pass 666666 121212 7777777
zaq12wsx asdfgh 1qaz2wsx administrator root123 qwertyuiop
""".split())

TOOL_AGENTS = re.compile(
    r"(hydra|medusa|ncrack|nmap|sqlmap|nikto|curl|wget|python-requests|python-urllib|aiohttp|"
    r"go-http-client|okhttp|libwww-perl|java/|httpclient|masscan|zgrab|burp|wfuzz|ffuf|gobuster|"
    r"maze-attacker-sim)", re.I)

INJECTION = re.compile(
    r"('\s*(or|and)\s*'?\d|--|;\s*drop\s|union\s+select|<script|javascript:|\$\{jndi:|"
    r"\.\./|/etc/passwd|\bsleep\(\d|\|\||`|\$\()", re.I)


@dataclass
class Attacker:
    ip: str
    attempts: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    busy_seconds: float = 0.0
    sessions: int = 0
    max_layer: int = 0
    decoys_found: int = 0
    exit_attempts: int = 0
    exits_granted: int = 0
    real_success: int = 0
    throttled: int = 0
    distinct_passwords: int = 0
    common_password_share: float = 0.0
    median_gap: float | None = None
    user_agents: list = field(default_factory=list)
    top_passwords: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    threat: str = "low"


def load_rows(db_path: str, since_hours: float | None = None, now: float | None = None) -> list[dict]:
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"No attempt log at {db_path!r}")
    uri = f"file:{db_path}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=10)) as conn:
        conn.row_factory = sqlite3.Row
        query = "SELECT * FROM attempts"
        params: tuple = ()
        if since_hours is not None:
            query += " WHERE ts >= ?"
            params = ((now or time.time()) - since_hours * 3600,)
        return [dict(r) for r in conn.execute(query + " ORDER BY ts, id", params)]


def busy_time(timestamps: list[float], idle_gap: float = IDLE_GAP) -> float:
    """Sum of gaps between consecutive attempts, ignoring pauses longer than idle_gap."""
    return float(sum(b - a for a, b in zip(timestamps, timestamps[1:]) if 0 <= b - a <= idle_gap))


def _passwords(row) -> list[str]:
    text = row["password"] or ""
    if text.startswith("[not stored") or text.startswith("[REDACTED"):
        return []
    return [p for p in text.split(" | ")] if row["action"] == "exit" else [text]


def analyze(rows: list[dict], idle_gap: float = IDLE_GAP) -> list[Attacker]:
    by_ip: dict[str, list[dict]] = {}
    for row in rows:
        by_ip.setdefault(row["ip"], []).append(row)

    result = []
    for ip, items in by_ip.items():
        ts = [r["ts"] for r in items]
        outcomes = Counter(r["outcome"] for r in items)
        pw = [p for r in items if r["action"] == "login" for p in _passwords(r)]
        all_pw = [p for r in items for p in _passwords(r)]
        agents = Counter(r["user_agent"] for r in items)
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        a = Attacker(
            ip=ip,
            attempts=len(items),
            first_ts=ts[0],
            last_ts=ts[-1],
            busy_seconds=round(busy_time(ts, idle_gap), 1),
            sessions=len({r["session_id"] for r in items}),
            max_layer=max(r["layer"] for r in items),
            decoys_found=outcomes["decoy_found"],
            exit_attempts=outcomes["exit_denied"] + outcomes["exit_granted"],
            exits_granted=outcomes["exit_granted"],
            real_success=outcomes["real_success"],
            throttled=outcomes["throttled"],
            distinct_passwords=len(set(pw)),
            common_password_share=round(sum(p.lower() in COMMON_PASSWORDS for p in pw) / len(pw), 2) if pw else 0.0,
            median_gap=round(statistics.median(gaps), 2) if gaps else None,
            user_agents=[ua for ua, _ in agents.most_common(3)],
            top_passwords=[p for p, _ in Counter(pw).most_common(5)],
        )
        a.tags = classify(a, gaps, all_pw)
        a.threat = threat_level(a)
        result.append(a)
    return sorted(result, key=lambda x: (-x.busy_seconds, -x.attempts, x.ip))


def classify(a: Attacker, gaps: list[float], passwords: list[str]) -> list[str]:
    tags = []
    if a.real_success:
        tags.append("REAL PASSWORD USED")
    if any(TOOL_AGENTS.search(ua or "") for ua in a.user_agents):
        tags.append("tool user-agent")
    if len(gaps) >= 8:
        mean = statistics.mean(gaps)
        if mean > 0 and statistics.pstdev(gaps) / mean < 0.15:
            tags.append("automated (regular timing)")
    if a.common_password_share >= 0.5 and a.distinct_passwords >= 5:
        tags.append("common wordlist")
    if any(INJECTION.search(p) for p in passwords):
        tags.append("injection probes")
    if a.decoys_found:
        tags.append("took the bait")
    if a.exit_attempts:
        tags.append("tried the exit")
    if a.sessions > 3:
        tags.append(f"{a.sessions} sessions (cookie reset)")
    if a.throttled > 5:
        tags.append("hit rate limits")
    return tags


def threat_level(a: Attacker) -> str:
    if a.real_success:
        return "critical"
    score = 0
    score += 2 if a.attempts >= 50 else 1 if a.attempts >= 10 else 0
    score += 2 if a.max_layer >= 3 else 1 if a.max_layer >= 2 else 0
    score += 1 if "injection probes" in a.tags else 0
    score += 1 if "automated (regular timing)" in a.tags or "tool user-agent" in a.tags else 0
    return "high" if score >= 4 else "medium" if score >= 2 else "low"


def summary(rows: list[dict], attackers: list[Attacker]) -> dict:
    outcomes = Counter(r["outcome"] for r in rows)
    passwords = Counter(p for r in rows if r["action"] == "login" for p in _passwords(r))
    hours = Counter(int(r["ts"] // 3600) for r in rows)
    per_hour = []
    if hours:  # every hour between the first and last attempt, quiet hours included
        for h in range(min(hours), max(hours) + 1):
            per_hour.append((time.strftime("%Y-%m-%d %H:00", time.localtime(h * 3600)), hours.get(h, 0)))
    return {
        "attempts": len(rows),
        "attackers": len(attackers),
        "busy_seconds_total": round(sum(a.busy_seconds for a in attackers), 1),
        "first": rows[0]["ts"] if rows else None,
        "last": rows[-1]["ts"] if rows else None,
        "outcomes": dict(outcomes.most_common()),
        "top_passwords": passwords.most_common(10),
        "per_hour": per_hour,
        "threats": dict(Counter(a.threat for a in attackers)),
    }


def human(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {seconds % 3600 // 60:02d}m"


def when(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "-"


# --- output formats ---------------------------------------------------------------

def render_text(summ: dict, attackers: list[Attacker], top: int) -> str:
    s = lambda v, n=40: sanitize(v, n)  # noqa: E731 - escape terminal control chars again
    lines = [
        "MINATOR - Maze attacker report",
        f"Period   {when(summ['first'])} .. {when(summ['last'])}",
        f"Totals   {summ['attempts']} attempts from {summ['attackers']} source(s), "
        f"attackers kept busy for {human(summ['busy_seconds_total'])}",
        "Outcomes " + ", ".join(f"{k} {v}" for k, v in summ["outcomes"].items()),
        "",
        f"{'THREAT':<9}{'SOURCE':<26}{'TRIES':>6}{'BUSY':>10}{'LAYER':>6}{'BAIT':>5}{'EXIT':>5}  TAGS",
        "-" * 100,
    ]
    for a in attackers[:top]:
        lines.append(f"{a.threat:<9}{s(a.ip, 25):<26}{a.attempts:>6}{human(a.busy_seconds):>10}"
                     f"{a.max_layer:>6}{a.decoys_found:>5}{a.exit_attempts:>5}  {', '.join(a.tags) or '-'}")
    if len(attackers) > top:
        lines.append(f"... {len(attackers) - top} more")
    lines += ["", "Top guesses: " + ", ".join(f"{s(p, 24)} ({n})" for p, n in summ["top_passwords"]),
              "", "Passive report only: no attacker system was contacted."]
    return "\n".join(lines)


def render_json(summ: dict, attackers: list[Attacker]) -> str:
    return json.dumps({"summary": summ, "attackers": [asdict(a) for a in attackers]}, indent=2,
                      ensure_ascii=False)


def _bar_chart(per_hour: list[tuple[str, int]]) -> str:
    if not per_hour:
        return ""
    data = per_hour[-48:]
    peak = max(n for _, n in data) or 1
    w, h, gap = 720, 160, 2
    bw = (w - gap * len(data)) / len(data)
    bars = []
    for i, (label, n) in enumerate(data):
        bh = (h - 20) * n / peak if n else 0.0
        x = i * (bw + gap)
        bars.append(f'<rect x="{x:.1f}" y="{h - 16 - bh:.1f}" width="{bw:.1f}" height="{bh:.1f}" rx="2">'
                    f'<title>{html.escape(label)}: {n}</title></rect>')
    first, last = html.escape(data[0][0]), html.escape(data[-1][0])
    return (f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="Attempts per hour">'
            f'<g class="bars">{"".join(bars)}</g>'
            f'<text x="0" y="{h - 2}" class="axis">{first}</text>'
            f'<text x="{w}" y="{h - 2}" class="axis" text-anchor="end">{last}</text></svg>')


def render_html(summ: dict, attackers: list[Attacker], top: int) -> str:
    e = lambda v: html.escape(str(v))  # noqa: E731
    rows = []
    for a in attackers[:top]:
        tags = "".join(f'<span class="tag{" crit" if t.startswith("REAL") else ""}">{e(t)}</span>' for t in a.tags)
        rows.append(
            f'<tr><td><span class="lvl {e(a.threat)}">{e(a.threat)}</span></td><td class="mono">{e(a.ip)}</td>'
            f'<td>{a.attempts}</td><td>{e(human(a.busy_seconds))}</td><td>{a.max_layer}</td>'
            f'<td>{a.decoys_found}</td><td>{a.exit_attempts}</td><td>{e(when(a.first_ts))}</td>'
            f'<td class="mono small">{e(", ".join(a.top_passwords[:3]))}</td><td>{tags}</td></tr>')
    top_pw = "".join(f"<li><code>{e(p)}</code> <span class='muted'>×{n}</span></li>" for p, n in summ["top_passwords"])
    outcomes = "".join(f"<li>{e(k)} <b>{v}</b></li>" for k, v in summ["outcomes"].items())
    cards = [("Attempts", summ["attempts"]), ("Sources", summ["attackers"]),
             ("Time wasted", human(summ["busy_seconds_total"])),
             ("High / critical", summ["threats"].get("high", 0) + summ["threats"].get("critical", 0))]
    card_html = "".join(f'<div class="card"><div class="muted">{e(k)}</div><div class="big">{e(v)}</div></div>'
                        for k, v in cards)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Minator report</title>
<style>
:root{{color-scheme:dark;--bg:#0d1117;--panel:#161b22;--line:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#d29922}}
body{{margin:0;padding:28px;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}}
h1{{margin:0;font-size:24px;letter-spacing:.04em}} h2{{font-size:13px;text-transform:uppercase;color:var(--muted);letter-spacing:.08em}}
.muted{{color:var(--muted)}} .mono{{font-family:ui-monospace,monospace}} .small{{font-size:12px}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}}
.card,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}}
.big{{font-size:28px;font-weight:700}} .grid{{display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px}}
table{{width:100%;border-collapse:collapse;margin-top:12px}} th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-size:12px;text-transform:uppercase}}
.tag{{display:inline-block;margin:0 4px 4px 0;padding:1px 8px;border-radius:10px;background:#21262d;font-size:12px}}
.tag.crit{{background:#5a1e1e;color:#ff7b72}} .lvl{{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600}}
.low{{background:#1f2d22;color:#3fb950}} .medium{{background:#3a2e12;color:#d29922}} .high{{background:#3d1d1d;color:#f85149}} .critical{{background:#f85149;color:#fff}}
.bars rect{{fill:var(--accent)}} .axis{{fill:var(--muted);font-size:11px}} ul{{margin:0;padding-left:18px}}
</style></head><body>
<h1>MINATOR <span class="muted">· Maze attacker report</span></h1>
<div class="muted">{e(when(summ['first']))} – {e(when(summ['last']))} · passive report, no attacker system was contacted</div>
<div class="cards">{card_html}</div>
<div class="grid">
  <div class="panel"><h2>Attempts per hour</h2>{_bar_chart(summ['per_hour'])}</div>
  <div class="panel"><h2>Top guesses</h2><ul>{top_pw}</ul></div>
  <div class="panel"><h2>Outcomes</h2><ul>{outcomes}</ul></div>
</div>
<div class="panel" style="margin-top:12px"><h2>Sources</h2>
<table><thead><tr><th>Threat</th><th>Source</th><th>Tries</th><th>Kept busy</th><th>Layer</th><th>Bait</th><th>Exit</th><th>First seen</th><th>Guesses</th><th>Tags</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
</body></html>
"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.report", description=__doc__.split("\n\n")[0])
    parser.add_argument("--db", default=os.environ.get("MAZE_DB_PATH", "maze.db"), help="attempt log (SQLite)")
    parser.add_argument("--format", choices=("text", "json", "html"), default="text")
    parser.add_argument("-o", "--output", help="write to this file instead of stdout")
    parser.add_argument("--since", type=float, metavar="HOURS", help="only the last N hours")
    parser.add_argument("--top", type=int, default=25, help="sources to list (default 25)")
    parser.add_argument("--idle-gap", type=float, default=IDLE_GAP,
                        help="seconds of silence that end a busy stretch (default 1800)")
    args = parser.parse_args(argv)
    try:
        rows = load_rows(args.db, args.since)
    except (FileNotFoundError, sqlite3.Error) as exc:
        print(f"[minator] {exc}", file=sys.stderr)
        return 1
    attackers = analyze(rows, args.idle_gap)
    summ = summary(rows, attackers)
    if args.format == "json":
        out = render_json(summ, attackers)
    elif args.format == "html":
        out = render_html(summ, attackers, args.top)
    else:
        out = render_text(summ, attackers, args.top)
    if args.output:
        fd = os.open(args.output, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)  # holds attacker data
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[minator] wrote {args.output}", file=sys.stderr)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
