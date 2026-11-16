"""Sensor portal API (api-01, api-02).

Operators log in to read and submit temperature readings (the Guide 1 pipeline concept, behind nginx).
  app      :5000  reached only by lb-01 (nginx)
  metrics  :9102  reached only by Prometheus (see docs/architecture.md)
Run with:  gunicorn -c gunicorn.conf.py app:app

Configuration comes from the environment (set by the build script):
  DB_HOST, DB_NAME, DB_USER, DB_PASSWORD, SECRET_KEY, LOG_FILE, SSLE_VULNERABLE
"""
import functools
import logging
import os
import socket
import subprocess
import time

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
# One line per event, key=value, always with src= (an IP, never a name: see docs/naming.md).
logging.basicConfig(
    filename=os.environ.get("LOG_FILE", "/var/log/ssle/api.log"),
    level=logging.INFO,
    format=f"%(asctime)s {socket.gethostname()} ssle-api: %(message)s",
)
log = logging.getLogger("ssle-api")

# --- Metrics: what Prometheus reads -----------------------------------------------------------------
# Labels are low-cardinality on purpose: never a username or an IP. Every distinct label value is a new
# time series, so an attacker trying 100 000 usernames would otherwise blow up Prometheus's memory.
# Per-IP / per-user detail belongs in the logs (Wazuh), counts belong here.
REQUESTS = Counter("ssle_http_requests_total", "HTTP requests", ["endpoint", "method", "status"])
LATENCY = Histogram("ssle_http_request_seconds", "Request duration", ["endpoint"])
LOGINS = Counter("ssle_login_attempts_total", "Login attempts", ["result"])  # ok | bad_password | no_user


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
    with db().cursor() as cur:
        cur.execute("SELECT password_hash FROM users WHERE username = %s", (username,))  # parameterised
        row = cur.fetchone()

    # Note: the hash check is deliberately slow (that's what stops offline cracking), so every login
    # costs CPU on the API. Credential stuffing therefore also loads the API: threats 1 and 2 overlap.
    if row and check_password_hash(row[0], password):
        session["user"] = username
        LOGINS.labels("ok").inc()
        log.info("login_ok user=%s src=%s", username, request.remote_addr)
        return jsonify(status="ok")

    result = "bad_password" if row else "no_user"
    LOGINS.labels(result).inc()
    log.info("login_failed reason=%s user=%s src=%s", result, username, request.remote_addr)
    # Same answer for both cases, so the attacker can't learn which usernames exist.
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
    log.info("reading_added user=%s sensor=%s src=%s", session["user"], sensor, request.remote_addr)
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
    log.info("report user=%s sensor=%s src=%s", session["user"], sensor, request.remote_addr)
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
