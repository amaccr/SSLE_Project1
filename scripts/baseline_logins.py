#!/usr/bin/env python3
"""Legitimate login traffic, for the credential-stuffing BASELINE (run from client-01).

Why this exists: before we can pick a detection threshold for credential stuffing we need to
know what NORMAL login traffic looks like. Real operators (alice, carol, ...) log in with the
RIGHT password, occasionally fat-finger it (a rare `bad_password`), and essentially never type a
username that does not exist. So a healthy system sits at ~0 failed logins/minute and ~0
`no_user` events. That floor is what the attack has to stand out from.

It talks only to lb-01 (the one exposed surface), exactly like a real client. stdlib only, so it
runs on the stock container with nothing to install.

  python3 baseline_logins.py --target http://192.168.100.10 --duration 300 --rate 6

--rate is logins per minute across all operators (a handful: this is background noise, not load).
"""
import argparse
import json
import random
import time
import urllib.error
import urllib.request

# The real operators and their CORRECT passwords (see apps/api/app.py `seed`). bob is left out on
# purpose: his password is weak ("password123") and is what the attack takes over, so keeping him
# out of the baseline avoids muddying "normal" traffic with the very credential under attack.
OPERATORS = {
    "alice": "Sunrise-Tuesday-42",
    "carol": "c4rol!2026",
}
TYPO_RATE = 0.05  # 1 in 20 logins is mistyped -> a rare bad_password, like a real user


def attempt(target, username, password, timeout=5):
    body = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        target.rstrip("/") + "/login", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code  # 401 for a wrong password
    except urllib.error.URLError as e:
        return f"error:{e.reason}"


def main():
    p = argparse.ArgumentParser(description="Legitimate login baseline traffic.")
    p.add_argument("--target", default="http://192.168.100.10", help="lb-01 base URL")
    p.add_argument("--duration", type=int, default=300, help="seconds to run")
    p.add_argument("--rate", type=float, default=6.0, help="logins per minute (all operators)")
    args = p.parse_args()

    interval = 60.0 / args.rate  # average seconds between logins
    end = time.monotonic() + args.duration
    ok = bad = 0
    print(f"baseline: {args.rate}/min for {args.duration}s against {args.target}")
    while time.monotonic() < end:
        username = random.choice(list(OPERATORS))
        password = OPERATORS[username]
        mistyped = random.random() < TYPO_RATE
        if mistyped:
            password = "wrong"
        status = attempt(args.target, username, password)
        if status == 200:
            ok += 1
        else:
            bad += 1
        print(f"  {username:6} {'(typo) ' if mistyped else '       '}-> {status}")
        # Jitter so the logins are not a metronome (a real workplace is bursty, not periodic).
        time.sleep(random.uniform(0.5 * interval, 1.5 * interval))
    print(f"done: {ok} ok, {bad} failed")


if __name__ == "__main__":
    main()
