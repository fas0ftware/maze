#!/usr/bin/env python3
"""Attacker simulator for a LOCAL Maze instance.

Tries a password list against the Maze login page, walks through the layers,
then attempts the fake exit flow and prints what happened.

It refuses to target anything other than a loopback address: this tool exists
to exercise our own service, not someone else's.
"""

import argparse
import http.cookiejar
import ipaddress
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_WORDLIST = Path(__file__).with_name("wordlist.txt")
USER_AGENT = "maze-attacker-sim/0.1"
LAYER_RE = re.compile(r'data-layer="(\d)"')
OUTCOME_RE = re.compile(r'data-outcome="([a-z_]*)"')


def ensure_loopback(url: str) -> None:
    host = urllib.parse.urlparse(url).hostname or ""
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        sys.exit(f"Cannot resolve {host!r}")
    if not addrs or not all(ipaddress.ip_address(a.split("%")[0]).is_loopback for a in addrs):
        sys.exit(f"Refusing to target {host!r}: only loopback addresses are allowed.")


class Client:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def request(self, path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(self.base + path, data=body,
                                     headers={"User-Agent": USER_AGENT})
        try:
            with self.opener.open(req, timeout=30) as resp:
                html = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:  # 401 on wrong password is expected
            html = err.read().decode("utf-8", "replace")
        layer = int(LAYER_RE.search(html).group(1))
        m = OUTCOME_RE.search(html)
        return layer, (m.group(1) if m else "")


def load_words(path: Path):
    words = [w.strip() for w in path.read_text(encoding="utf-8").splitlines()]
    return [w for w in words if w and not w.startswith("#")]


def run(base_url: str, words) -> int:
    client = Client(base_url)
    layer, _ = client.request("/")
    print(f"[*] Target {base_url} - starting on layer {layer}")
    found = {}
    started = time.monotonic()

    for word in words:
        if layer == 3 and 3 in found:
            break
        t0 = time.monotonic()
        new_layer, outcome = client.request("/login", {"password": word})
        took = time.monotonic() - t0
        print(f"    layer {layer}  try {word!r:<18} -> {outcome:<13} ({took:4.1f}s)")
        if outcome == "decoy_found":
            found[layer] = word
            print(f"[+] Layer {layer} password found: {word!r}. Now on layer {new_layer}.")
        elif outcome == "real_success":
            found[3] = word
            print("[!] Real password accepted on layer 3.")
        layer = new_layer

    print(f"[*] Wordlist done. Reached layer {layer}.")

    # Fake exit flow: first with a wrong answer, then with the real decoys.
    if layer > 1:
        wrong = {f"layer{i}": "guess" for i in range(1, layer)}
        _, outcome = client.request("/exit", wrong)
        print(f"[*] Exit with wrong passwords           -> {outcome}")
        right = {f"layer{i}": found.get(i, "") for i in range(1, layer)}
        layer, outcome = client.request("/exit", right)
        print(f"[*] Exit with collected layer passwords -> {outcome} (back on layer {layer})")
    else:
        _, outcome = client.request("/exit", {})
        print(f"[*] Exit attempt on layer 1 -> {outcome}")

    print("\n=== Summary ===")
    for i in (1, 2, 3):
        print(f"  layer {i}: {found.get(i, '-')!r}")
    print(f"  total time: {time.monotonic() - started:.1f}s (server-side stalling included)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://127.0.0.1:5000")
    parser.add_argument("--wordlist", type=Path, default=DEFAULT_WORDLIST)
    args = parser.parse_args()
    ensure_loopback(args.url)
    try:
        return run(args.url, load_words(args.wordlist))
    except urllib.error.URLError as exc:
        print(f"Cannot reach {args.url}: {exc.reason}. Is the service running?", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
