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

Usage (single listener for now; lis would add a second on 10.10.2.1):
    python3 host_exporter.py --listen 10.10.0.1 --port 9101
Metrics on http://10.10.0.1:9101/metrics
"""
import argparse
import json
import logging
import subprocess
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


def collect():
    samples = {name: [] for name in METRICS}
    for inst in read_instances():
        name = inst["name"]
        project = inst.get("project", "default")
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
            body, status = render(collect()).encode(), 200
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


def main():
    parser = argparse.ArgumentParser(description="Incus per-host metrics exporter for Prometheus")
    parser.add_argument("--listen", default="10.10.0.1",
                        help="address to bind (default: the mgmt bridge only, not every interface)")
    parser.add_argument("--port", type=int, default=9101)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.listen, args.port), MetricsHandler)
    logger.info("Serving metrics on http://%s:%d/metrics", args.listen, args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
