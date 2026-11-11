#!/usr/bin/env python3
"""Write a SAMPLE attempt log for trying Minator (python -m app.report).

Every address is from the IPv4/IPv6 documentation ranges (RFC 5737 / RFC 3849),
so the data can never be mistaken for, or point at, a real host.

    python tools/demo_log.py demo.db && python -m app.report --db demo.db
"""
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.storage import AttemptLog  # noqa: E402

WORDLIST = [w.strip() for w in Path(__file__).with_name("wordlist.txt").read_text().splitlines()
            if w.strip() and not w.startswith("#")]
COMMON = ["123456", "password", "12345678", "qwerty", "abc123", "111111", "letmein", "welcome",
          "admin", "iloveyou", "monkey", "dragon", "football", "master", "trustno1", "root", "toor"]
INJECT = ["' OR '1'='1", "admin'--", "1' UNION SELECT NULL--", "<script>alert(1)</script>",
          "${jndi:ldap://x}", "../../etc/passwd", "'; DROP TABLE users;--", "1' AND sleep(5)--"]


def main(path: str) -> None:
    rng = random.Random(7)  # sample data, not security  # nosec B311
    Path(path).unlink(missing_ok=True)
    log = AttemptLog(path)
    t0 = time.time() - 30 * 3600

    def run(ip, ua, start, guesses, gap, jitter, session_every=10_000, decoys=(), exits=0):
        t, layer, sid = start, 1, f"s-{ip}-0"
        for i, pw in enumerate(guesses):
            if i and i % session_every == 0:
                sid = f"s-{ip}-{i}"
            outcome = "wrong"
            if pw in decoys and layer < 3:
                outcome, layer = "decoy_found", layer + 1
            log.record(ip=ip, session_id=sid, action="login", layer=layer if outcome == "wrong" else layer - 1,
                       password=pw, outcome=outcome, user_agent=ua, now=t)
            t += gap + rng.uniform(-jitter, jitter)
        for _ in range(exits):
            log.record(ip=ip, session_id=sid, action="exit", layer=layer, password="admin123 | guess",  # nosec B106
                       outcome="exit_denied", user_agent=ua, now=t)
            t += gap
        return t

    # 1. Hydra-style brute force: common list, machine-regular timing, cookie reset every 25 tries
    run("203.0.113.7", "Mozilla/4.0 (Hydra)", t0, (COMMON * 9)[:140], 8.0, 0.2, session_every=25,
        decoys=("admin123",))
    # 2. A patient human in a browser: walks the layers, then tries the fake exit
    human = ["admin", "Admin123", "admin123", "Summer2024", "SuperSecret99", "root", "root!2024",
             "Root2024!", "letmein", "trustno1", "P@ssw0rd!", "company2024"]
    run("198.51.100.23", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        t0 + 6 * 3600, human, 95.0, 70.0, decoys=("admin123", "SuperSecret99"), exits=3)
    # 3. sqlmap probing the form for injection
    run("2001:db8::4f", "sqlmap/1.8.4#stable (https://sqlmap.org)", t0 + 14 * 3600, INJECT * 3, 3.0, 0.1)
    # 4. Wordlist from the repo, python-requests, cookie reset each time
    run("192.0.2.55", "python-requests/2.32.3", t0 + 20 * 3600, WORDLIST * 4, 4.0, 1.5, session_every=6,
        decoys=("admin123", "SuperSecret99"))
    # 5. A few curious probes
    for k, ip in enumerate(["203.0.113.140", "198.51.100.77", "192.0.2.201"]):
        run(ip, "curl/8.5.0", t0 + (22 + k) * 3600, rng.sample(COMMON, 4), 2.0, 0.5)
    print(f"sample log written to {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo.db")
