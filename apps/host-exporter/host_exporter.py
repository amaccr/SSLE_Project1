"""Per-host exporter for the SSLE lab (the "observed, not declared" host exporter,
docs/architecture.md, "One host exporter, two listeners").

Runs on the VM (h01) only: only the VM can query Incus about every container, so a
compromised container cannot fake its own numbers. Reused from Guide 3's
container_exporter.py, adapted for this project:
  - one Incus project PER SITE, so the query uses all-projects=true;
  - a `project` label, because short names repeat across sites (api-01 in avr and lis).

Values are read from Incus at scrape time (no polling loop): Prometheus sets the rate.
Standard library only, to show the Prometheus exposition format is just text:
    metric_name{label="value"} number

One process, one listener PER monitoring domain (the "two listeners" of the title). Each
--listen is ADDR[=proj,proj]: the optional project list filters what that listener shows,
so the interface a scraper connects through decides what it sees (a URL parameter would let
the caller forge it). No project list = every project.
    # mgmt listener shows the mgmt plane + avr; a per-site listener shows only lis:
    python3 host_exporter.py --listen 10.10.0.1=default,avr --listen 10.10.2.1=lis --port 9101
Metrics on http://<addr>:9101/metrics
"""
import argparse
import json
import logging
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [host-exporter] %(message)s")
logger = logging.getLogger("host-exporter")

# name -> (type, help). Counters only grow; Prometheus turns them into rates with rate().
METRICS = {
    "container_running": ("gauge", "1 if the container is running"),
    "container_cpu_seconds_total": ("counter", "CPU time used by the container"),
    "container_memory_bytes": ("gauge", "Memory used by the container"),
    "container_memory_swap_bytes": ("gauge", "Swap used by the container"),
    "container_processes": ("gauge", "Number of processes in the container"),
    "container_network_receive_bytes_total": ("counter", "Bytes received"),
    "container_network_transmit_bytes_total": ("counter", "Bytes sent"),
    "container_network_receive_packets_total": ("counter", "Packets received"),
    "container_network_transmit_packets_total": ("counter", "Packets sent"),
    "container_network_receive_dropped_total": ("counter", "Inbound packets dropped"),
}


def read_instances():
    """One Incus API call returns every instance of every project with its live state."""
    out = subprocess.run(
        ["incus", "query", "/1.0/instances?recursion=2&all-projects=true"],
        capture_output=True, text=True, timeout=10, check=True)
    return json.loads(out.stdout)


def collect(projects=None):
    """projects: a set of project names to include, or None for every project. The caller is the
    listener the scrape arrived on, so one host exporter serves a different view per interface."""
    samples = {name: [] for name in METRICS}
    for inst in read_instances():
        name = inst["name"]
        project = inst.get("project", "default")
        if projects is not None and project not in projects:
            continue
        state = inst.get("state") or {}
        labels = f'container="{name}",project="{project}"'
        samples["container_running"].append((labels, 1 if inst["status"] == "Running" else 0))
        if inst["status"] != "Running":
            continue
        samples["container_cpu_seconds_total"].append((labels, state["cpu"]["usage"] / 1e9))  # ns -> s
        samples["container_memory_bytes"].append((labels, state["memory"]["usage"]))
        samples["container_memory_swap_bytes"].append((labels, state["memory"]["swap_usage"]))
        samples["container_processes"].append((labels, state["processes"]))

        counters = (state.get("network") or {}).get("eth0", {}).get("counters")
        if counters:
            for metric, key in [("container_network_receive_bytes_total", "bytes_received"),
                                ("container_network_transmit_bytes_total", "bytes_sent"),
                                ("container_network_receive_packets_total", "packets_received"),
                                ("container_network_transmit_packets_total", "packets_sent"),
                                ("container_network_receive_dropped_total", "packets_dropped_inbound")]:
                samples[metric].append((labels + ',interface="eth0"', counters[key]))
    return samples


def render(samples):
    lines = []
    for name, (mtype, help_text) in METRICS.items():
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")
        lines.extend(f"{name}{{{labels}}} {value}" for labels, value in samples[name])
    return "\n".join(lines) + "\n"


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        try:
            body, status = render(collect(self.server.projects)).encode(), 200
        except Exception as e:  # Incus unavailable: fail the scrape, so Prometheus sets up=0
            logger.warning("Collection failed: %s", e)
            body, status = f"# collection failed: {type(e).__name__}\n".encode(), 500
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence per-request logs
        pass


def parse_listen(spec):
    """'ADDR[=proj,proj]' -> (addr, projects or None). No project list means every project."""
    addr, _, projects = spec.partition("=")
    return addr, frozenset(projects.split(",")) if projects else None


def main():
    parser = argparse.ArgumentParser(description="Incus per-host metrics exporter for Prometheus")
    parser.add_argument("--listen", action="append", metavar="ADDR[=proj,proj]",
                        help="address to bind, with an optional project filter; repeatable "
                             "(default: 10.10.0.1, every project)")
    parser.add_argument("--port", type=int, default=9101)
    args = parser.parse_args()

    # One ThreadingHTTPServer per listener, each with its own project filter, served from its own thread.
    servers = []
    for spec in args.listen or ["10.10.0.1"]:
        addr, projects = parse_listen(spec)
        server = ThreadingHTTPServer((addr, args.port), MetricsHandler)
        server.projects = projects
        servers.append(server)
        logger.info("Serving metrics on http://%s:%d/metrics (projects: %s)",
                    addr, args.port, ",".join(sorted(projects)) if projects else "all")
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
