"""gunicorn settings for the API:  gunicorn -c gunicorn.conf.py app:app

Pre-fork model: one master process starts `workers` processes and only supervises them
(restarts crashed ones, kills ones stuck longer than `timeout`).

Metrics with several processes: each worker has its own counters, so prometheus_client runs in
multiprocess mode. Workers write their counters to files in PROMETHEUS_MULTIPROC_DIR, and the master
serves one combined /metrics on :9102. (Older prometheus_client, e.g. Ubuntu 22.04's 0.9, reads the
lowercase prometheus_multiproc_dir instead, so the start command sets both names.) That directory must exist and be EMPTY when gunicorn starts
(old files would be added to the new counts); the start command takes care of that.
"""
import os

from prometheus_client import CollectorRegistry, multiprocess, start_http_server

bind = "0.0.0.0:5000"                              # only lb-01 may reach it (firewall)
workers = int(os.environ.get("WORKERS", "3"))      # sync workers: one request at a time each
timeout = 30                                       # a worker stuck longer than this is killed
accesslog = "-"                                    # access log to stdout (journald); app events go to LOG_FILE


def when_ready(server):
    """Runs once in the master: start the combined /metrics endpoint."""
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
    start_http_server(9102, registry=registry)


def child_exit(server, worker):
    """A worker died: tell prometheus_client, so its live-only values are dropped."""
    multiprocess.mark_process_dead(worker.pid)
