"""Sensor portal API (api-01, api-02).

Operators log in to read and submit temperature readings (the Guide 1 pipeline concept, behind nginx).
  app      :5000  reached only by lb-01 (nginx)
  metrics  :9102  reached only by Prometheus (see docs/architecture.md)
Run with:  gunicorn -c gunicorn.conf.py app:app

Configuration comes from the environment (set by the build script):
  DB_HOST, DB_NAME, DB_USER, DB_PASSWORD, SECRET_KEY, LOG_FILE, SSLE_VULNERABLE
"""
import functools
import json
import logging
import os
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone

import psycopg2
from flask import Flask, g, jsonify, request, session
from prometheus_client import Counter, Histogram, start_http_server
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

APP_PORT = 5000
METRICS_PORT = 9102

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

# nginx sets X-Forwarded-For. Trust exactly one proxy hop, so request.remote_addr is the real client
# (the attacker's IP), not lb-01. This is only safe because the firewall lets nothing but lb-01 reach :5000;
# otherwise anyone could send a fake X-Forwarded-For and hide their IP from the logs.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

# --- Logs: what Wazuh reads -------------------------------------------------------------------------
# One JSON object per line. json.dumps escapes quotes and newlines inside values, so user input can never
# end a line early (a forged log line) or add a field of its own (a second "src"). Wazuh's built-in JSON
# decoder reads the fields, so no custom decoder is needed.
# The VALUES are still attacker-controlled (e.g. "user"): only "src" is trustworthy, and only because of
# nginx + the firewall. Values are cut to MAX_FIELD characters so a huge username can't make a huge event.
MAX_FIELD = 128
HOST = socket.gethostname()
logging.basicConfig(
    filename=os.environ.get("LOG_FILE", "/var/log/ssle/api.log"),
    level=logging.INFO,
    format="%(message)s",
)
log = logging.getLogger("ssle-api")


def log_event(event, **fields):
    record = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
              "host": HOST, "app": "ssle-api", "event": event, "src": request.remote_addr}
    record.update({k: str(v)[:MAX_FIELD] for k, v in fields.items()})
    log.info(json.dumps(record))


# --- Metrics: what Prometheus reads -----------------------------------------------------------------
# Labels are low-cardinality on purpose: never a username or an IP. Every distinct label value is a new
# time series, so an attacker trying 100 000 usernames would otherwise blow up Prometheus's memory.
# Per-IP / per-user detail belongs in the logs (Wazuh), counts belong here.
REQUESTS = Counter("ssle_http_requests_total", "HTTP requests", ["endpoint", "method", "status"])
LATENCY = Histogram("ssle_http_request_seconds", "Request duration", ["endpoint"])
LOGINS = Counter("ssle_login_attempts_total", "Login attempts", ["result"])  # ok|bad_password|no_user|locked

# Credential-stuffing response (threat 2): lock an account after too many consecutive failed logins.
# Defends a TARGETED brute-force of one account. It does NOT stop the horizontal spray (each username is
# tried once, so no account reaches the threshold) nor a takeover with a correct reused password (no
# failure at all) -- those are caught by the aggregate no_user alert and by password strength/MFA. That
# split is the point: no single control is sufficient (see docs/threats/credstuffing.md).
LOCKOUT_THRESHOLD = 5     # consecutive failures on an existing account before it locks
LOCKOUT_MINUTES = 15      # how long it stays locked


@app.before_request
def start_timer():
    g.start = time.monotonic()


@app.after_request
def record_metrics(response):
    endpoint = request.url_rule.rule if request.url_rule else "unknown"  # the route, not the raw URL
    REQUESTS.labels(endpoint, request.method, response.status_code).inc()
    LATENCY.labels(endpoint).observe(time.monotonic() - g.start)
    return response


# --- Database ---------------------------------------------------------------------------------------
def db():
    # One connection per request: simple, but each request costs a TCP + auth handshake with db-01.
    # Under a flood that cost multiplies (a DoS limitation to discuss; a connection pool would fix it).
    if "db" not in g:
        g.db = psycopg2.connect(
            host=os.environ["DB_HOST"], dbname=os.environ.get("DB_NAME", "ssle"),
            user=os.environ["DB_USER"], password=os.environ["DB_PASSWORD"], connect_timeout=3,
        )
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return jsonify(error="login required"), 401
        return view(*args, **kwargs)
    return wrapped


# --- Endpoints --------------------------------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify(status="ok", host=socket.gethostname())


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username, password = str(data.get("username", "")), str(data.get("password", ""))
    conn = db()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT u.password_hash, s.failed_count, s.locked_until "
            "FROM users u LEFT JOIN login_state s USING (username) WHERE u.username = %s",  # parameterised
            (username,),
        )
        row = cur.fetchone()

    # Unknown user: nothing to lock, and we never create lock state for a name that is not in users
    # (the FK would reject it anyway), so a spray of random usernames can't grow login_state.
    if row is None:
        LOGINS.labels("no_user").inc()
        log_event("login_failed", reason="no_user", user=username)
        return jsonify(error="invalid credentials"), 401

    password_hash, failed_count, locked_until = row
    now = datetime.now(timezone.utc)

    # Locked: reject BEFORE checking the password, so even a correct password (a successful stuffing hit)
    # cannot take over a locked account -- and we skip the deliberately slow pbkdf2 hash (threat-1 link:
    # a locked account stops costing CPU). Same generic 401 as any failure, so the lock is not revealed.
    if locked_until and locked_until > now:
        LOGINS.labels("locked").inc()
        log_event("login_failed", reason="locked", user=username)
        return jsonify(error="invalid credentials"), 401

    if check_password_hash(password_hash, password):
        with conn.cursor() as cur:                      # success: clear any failure/lock state
            cur.execute("DELETE FROM login_state WHERE username = %s", (username,))
        conn.commit()
        session["user"] = username
        LOGINS.labels("ok").inc()
        log_event("login_ok", user=username)
        return jsonify(status="ok")

    # Wrong password on an existing account: count it. An expired lock (locked_until <= now) is cleared
    # first so the counter starts fresh instead of re-locking on the first new failure.
    with conn.cursor() as cur:
        if locked_until and locked_until <= now:
            cur.execute("DELETE FROM login_state WHERE username = %s", (username,))
        cur.execute(
            "INSERT INTO login_state (username, failed_count, last_failed_at) VALUES (%s, 1, %s) "
            "ON CONFLICT (username) DO UPDATE SET failed_count = login_state.failed_count + 1, "
            "last_failed_at = EXCLUDED.last_failed_at RETURNING failed_count",
            (username, now),
        )
        failed_count = cur.fetchone()[0]
        locked = failed_count >= LOCKOUT_THRESHOLD
        if locked:
            cur.execute("UPDATE login_state SET locked_until = %s WHERE username = %s",
                        (now + timedelta(minutes=LOCKOUT_MINUTES), username))
    conn.commit()
    LOGINS.labels("bad_password").inc()
    log_event("login_failed", reason="bad_password", user=username)
    if locked:
        # A distinct event so Wazuh/Prometheus can see the lock engage (server-side only; the client got
        # the same generic 401 above).
        log_event("account_locked", user=username, after=failed_count)
    return jsonify(error="invalid credentials"), 401


@app.get("/readings")
@login_required
def list_readings():
    sensor = request.args.get("sensor")
    with db().cursor() as cur:
        if sensor:
            cur.execute("SELECT sensor, value, ts FROM readings WHERE sensor = %s "
                        "ORDER BY ts DESC LIMIT 100", (sensor,))
        else:
            cur.execute("SELECT sensor, value, ts FROM readings ORDER BY ts DESC LIMIT 100")
        rows = cur.fetchall()
    return jsonify([{"sensor": s, "value": v, "ts": t.isoformat()} for s, v, t in rows])


@app.post("/readings")
@login_required
def add_reading():
    data = request.get_json(silent=True) or {}
    try:
        sensor, value = str(data["sensor"]), float(data["value"])
    except (KeyError, ValueError, TypeError):
        return jsonify(error="need sensor (string) and value (number)"), 400
    with db().cursor() as cur:
        cur.execute("INSERT INTO readings (sensor, value) VALUES (%s, %s)", (sensor, value))
    db().commit()
    log_event("reading_added", user=session["user"], sensor=sensor)
    return jsonify(status="ok"), 201


# --- !!! DELIBERATELY VULNERABLE: the APT entry point (docs/architecture.md, "APT entry path") !!! ----
# The sensor id goes into a shell command unchecked, so  sensor=x;cat /proc/self/environ  runs a second
# command and leaks DB_PASSWORD (APT step 3). Only enabled when SSLE_VULNERABLE=1, so the app is safe by
# default and the weakness is a visible, documented choice. Fix: no shell=True, pass a list of arguments,
# and validate sensor against ^[a-z0-9-]+$.
@app.get("/report")
@login_required
def report():
    if os.environ.get("SSLE_VULNERABLE") != "1":
        return jsonify(error="disabled"), 404
    sensor = request.args.get("sensor", "")
    log_event("report", user=session["user"], sensor=sensor)
    out = subprocess.run(f"echo Report for sensor {sensor}; date -u",
                         shell=True, capture_output=True, text=True, timeout=5)
    return out.stdout, 200, {"Content-Type": "text/plain"}


# --- Setup helper: flask --app app seed ---------------------------------------------------------------
@app.cli.command("seed")
def seed():
    """Create the operator accounts (run once, after schema.sql)."""
    users = {"alice": "Sunrise-Tuesday-42", "bob": "password123", "carol": "c4rol!2026"}
    with db().cursor() as cur:
        for name, password in users.items():
            cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s) "
                        "ON CONFLICT (username) DO NOTHING", (name, generate_password_hash(password)))
    db().commit()
    print("seeded:", ", ".join(users))


if __name__ == "__main__":
    # Development only (single process). In the lab the app runs under gunicorn (gunicorn.conf.py),
    # which serves /metrics from the master instead.
    start_http_server(METRICS_PORT)
    app.run(host="0.0.0.0", port=APP_PORT)
