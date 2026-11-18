#!/usr/bin/env python3
"""Render the DoS report graphs from Prometheus's range API (no browser, reproducible).

Pulls each panel's time series over a window and writes a clean PNG per metric.
Colours: Okabe-Ito (colourblind-safe). api-01 and api-02 keep the same colour across
every graph so the four line up.

Usage:
    python3 scripts/plot_metrics.py --start '2026-11-16 22:34:40' \
        --end '2026-11-16 22:39:10' --label during --outdir images/dos/plots
"""
import argparse
import datetime as dt
import json
import os
import urllib.parse
import urllib.request

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt

PROM = os.environ.get("PROM_URL", "http://10.10.0.10:9090")

# Okabe-Ito
BLUE, ORANGE, VERMILLION, GREEN, GREY = "#0072B2", "#E69F00", "#D55E00", "#009E73", "#999999"
# Fixed colour per entity, so the graphs line up and colour follows the entity (not its rank).
COLOURS = {"api-01.avr.pt.ssle": BLUE, "api-02.avr.pt.ssle": ORANGE,
           "api-01": BLUE, "api-02": ORANGE,
           "bad_password": VERMILLION, "ok": GREEN, "no_user": GREY, "locked": BLUE}

# One entry per graph: filename stem, title, y-axis label, query, and which label picks the series.
PANELS = [
    ("throughput", "HTTP throughput per API", "requests / second",
     "sum by (instance) (rate(ssle_http_requests_total[1m]))", "instance"),
    ("latency-p95", "p95 /login latency per API (server-side)", "p95 latency (seconds)",
     'histogram_quantile(0.95, sum by (le, instance) (rate(ssle_http_request_seconds_bucket{endpoint="/login"}[1m])))',
     "instance"),
    ("bad-logins", "Login attempts per second by result", "logins / second",
     "sum by (result) (rate(ssle_login_attempts_total[1m]))", "result"),
    ("cpu", "API container CPU", "CPU cores used",
     'rate(container_cpu_seconds_total{container=~"api-0.*"}[1m])', "container"),
]


def query_range(query, start, end, step=5):
    params = urllib.parse.urlencode({"query": query, "start": start, "end": end, "step": f"{step}s"})
    with urllib.request.urlopen(f"{PROM}/api/v1/query_range?{params}", timeout=15) as r:
        return json.load(r)["data"]["result"]


def plot(panel, start, end, label, outdir):
    stem, title, ylabel, query, key = panel
    series = query_range(query, start, end)
    fig, ax = plt.subplots(figsize=(8, 3.4), dpi=150)
    for s in sorted(series, key=lambda s: s["metric"].get(key, "")):
        name = s["metric"].get(key, "?")
        xs = [dt.datetime.fromtimestamp(float(t)) for t, _ in s["values"]]
        ys = [float(v) for _, v in s["values"]]
        ax.plot(xs, ys, label=name, color=COLOURS.get(name, GREY), linewidth=2)
    ax.set_title(title, fontsize=12, fontweight="bold", loc="left", color="#222222")
    ax.set_ylabel(ylabel, fontsize=10, color="#444444")
    ax.set_ylim(bottom=0)
    ax.grid(True, color="#E6E6E6", linewidth=0.8)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color("#CCCCCC")
    ax.tick_params(colors="#444444", labelsize=9)
    if len(series) >= 2:
        ax.legend(frameon=False, fontsize=9, loc="upper left")
    fig.tight_layout()
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"{stem}_{label}.png")
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    peak = max((float(v) for s in series for _, v in s["values"]), default=0)
    print(f"  wrote {path}  (series={len(series)}, peak={peak:.2f})")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--start", required=True, help="'YYYY-MM-DD HH:MM:SS' local time")
    p.add_argument("--end", required=True)
    p.add_argument("--label", required=True, help="phase label, e.g. during / after")
    p.add_argument("--outdir", default="images/dos/plots")
    a = p.parse_args()
    to_epoch = lambda s: dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").timestamp()
    start, end = to_epoch(a.start), to_epoch(a.end)
    print(f"plotting {a.label}: {a.start} -> {a.end}")
    for panel in PANELS:
        plot(panel, start, end, a.label, a.outdir)


if __name__ == "__main__":
    main()
