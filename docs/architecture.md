# Architecture

## Instances and application call graph

| Instance | Role | Network/subnet | Talks to | Exposed to `inet`? |
|---|---|---|---|---|
| lb-01.avr.pt.ssle | nginx load balancer | ssle-avr 10.10.1.0/24 | api-01, api-02, analytics-01 | yes, only this (80) |
| api-01.avr.pt.ssle | Flask API + login | ssle-avr | db-01 (5432) | No |
| api-02.avr.pt.ssle | Flask API + login | ssle-avr | db-01 (5432) | No |
| analytics-01.avr.pt.ssle | aggregates/stats (`/stats`, `/average`) | ssle-avr | db-01 (5432, read-only) | No |
| db-01.avr.pt.ssle | postgres | ssle-avr | nobody | No |
| api-01.lis.pt.ssle | site 2: a small API | ssle-lis 10.10.2.0/24 | db-01.lis (5432) | No |
| db-01.lis.pt.ssle | site 2: postgres | ssle-lis | nobody | No |
| prom-01.lis.pt.ssle | local Prometheus, federated by prom-01.ssle | ssle-lis | lis exporters | No |
| prom-01.ssle | central Prometheus | ssle-mgmt 10.10.0.0/24 | every exporter in avr, prom-01.lis | No |
| siem-01.ssle | Wazuh manager + dashboard | ssle-mgmt | nobody; agents connect to it | No |
| h01.ssle | physical host (the VM) running the host exporter (observed host) | exporter listens on 10.10.0.1 (ssle-mgmt) and 10.10.2.1 (ssle-lis, lis containers only) | Prometheus pulls from it | No |
| client-01.inet | legitimate user | inet 192.168.100.0/24 | lb-01 only | n/a |
| attacker-01.inet | adversary | inet | lb-01 only | n/a |

Any connection that is not in the "Talks to" column (or in the management flows below) is suspicious.
This call graph is what the APT detection compares against.

## Decisions

**Analytics is routed through nginx.** `lb-01` sends `/stats` and `/average` to `analytics-01`. This puts the
expensive endpoint where outsiders can reach it, which is the realistic weakness the DoS section needs: each
cheap request makes analytics read a lot from `db-01` (amplification). The defences then sit in the right layers:
rate limiting in nginx, caching in analytics, and Wazuh blocking IPs from the nginx logs. If the APIs called
analytics instead, there would be a hidden internal hop that is harder to watch and explain.

**Each site is self-contained.** `lis` has its own small `db-01.lis.pt.ssle` instead of sharing `db-01.avr`. A shared
database would bring cross-site DNS and routing and a single point of failure. With one db per site, the same
build script runs per site, so adding a site is one more run of the script. `db-01.lis` and `db-01.avr` share a
short name, which is fine with per-site numbering.

**Physical vs logical.** `h01` is a physical machine, an org-level asset owned by `secops`, so it is named
`h01.ssle` and not `h01.pt.ssle`. The logical sites (`avr`, `lis`) are placed onto it.

**One host exporter, two listeners.** One exporter per physical host keeps the host "observed, not declared":
exporters inside the containers would report about themselves, and root inside a compromised container could
fake its own numbers. To let `prom-01.lis` scrape its own site, the exporter has two listeners:
- `10.10.0.1:9101` (ssle-mgmt): the avr containers, for `prom-01.ssle`
- `10.10.2.1:9101` (ssle-lis): only the lis containers, for `prom-01.lis`

The interface you connect through decides what you see. A URL parameter (`/metrics?site=lis`) was rejected:
the caller chooses it, so anything on the lis network could ask for `?site=avr` and read another site's data.
Trade-off: listening on the lis bridge makes the VM itself reachable from a site network, so a compromised lis
container can talk to a process on the host. A firewall rule allows only `prom-01.lis`'s IP to reach `10.10.2.1:9101`.
This covers resource metrics only (CPU, memory, network). Request counts and login failures are only known by the
apps, so the apps also expose their own `/metrics`. The two answer different questions.

**DNS delegation with dnsmasq forwarding, only where needed.** Each Incus network's DNS only knows its own
`dns.domain`. One `raw.dnsmasq` line per delegated zone fixes that, e.g. on `ssle-mgmt`:
`server=/avr.pt.ssle/10.10.1.1` (same for `lis`). The org's DNS doesn't know site names, it knows who to ask.
(Incus also has built-in network zones, which is more setup for the same idea.)
- mgmt → sites: needed, so Prometheus can find targets by name.
- sites → mgmt: needed, so agents find `siem-01.ssle`: forward `ssle` from each site to `10.10.0.1`
  (test that the site's own zone still answers locally).
- site ↔ site: not added. Each site is self-contained, and less resolution means less attack surface.

Limitations: if the mgmt DNS goes down, cross-zone resolution fails. There is no DNSSEC (`resolvectl` shows
`DNSSEC=no`), so names can be spoofed. This links to "route and signal hijacking" from the syllabus, which is
not one of the three threats handled here.

**Uneven Prometheus, on purpose.** Having avr scraped directly and lis federated is an experiment. I can measure
how many bytes per minute leave each site toward prom-01.ssle, which gives the bandwidth bonus real numbers
instead of a claim. Limitation: both sites share one VM, so the "bandwidth saved" is between bridges on one
machine, not across a real WAN.

**Port 80 only.** HTTPS adds certificate work and doesn't help any of the three threats: in credential stuffing
the attacker sends the passwords themselves, so encryption doesn't stop the attack. Limitation: credentials
travel in clear text; production would terminate TLS at `lb-01`. (A self-signed certificate on nginx is optional
extra work if time allows.)

## APT entry path

Only `lb-01` is exposed, so the APT has to go through the application:

1. A deliberately weak API endpoint (e.g. command injection or unsafe file upload, documented as intentional)
2. → foothold on `api-01`
3. → read the DB credentials from its environment/config
4. → log into `db-01`, or pivot to `api-02` / `analytics-01`

Each step leaves something Wazuh can catch:
- an unusual process starting inside a container
- file-integrity (FIM) alerts on changed files
- a new outgoing connection that is not in the call graph
- DB logins from an unexpected source, or at odd times

That is why APT is the "correlation" threat: no single alert proves it, but the chain does.
`analytics-01` being read-only limits what an attacker gains from compromising it.

## Management flows

These cross from `ssle-mgmt` into the site networks through the VM. Each row becomes one firewall rule later.

| Source | Destination | Port | Purpose |
|---|---|---|---|
| every instance with a Wazuh agent (avr + lis) | siem-01.ssle | 1514/tcp | agent → manager events |
| every instance with a Wazuh agent (avr + lis) | siem-01.ssle | 1515/tcp | agent enrollment |
| prom-01.ssle | h01.ssle (10.10.0.1) | 9101/tcp | scrape the host exporter |
| prom-01.ssle | avr app `/metrics` | TBD | app metrics (requests, logins), scraped directly |
| prom-01.ssle | prom-01.lis.pt.ssle | 9090/tcp (`/federate`) | federation |
| prom-01.lis.pt.ssle (its IP only) | h01.ssle (10.10.2.1) | 9101/tcp | scrape lis container metrics |
| prom-01.lis.pt.ssle | lis app `/metrics` | TBD | app metrics (requests, logins) |
| ssle-mgmt DNS (10.10.0.1) | site DNS (10.10.1.1, 10.10.2.1) | 53 | delegated zones `avr.pt.ssle`, `lis.pt.ssle` |
| site DNS (10.10.1.1, 10.10.2.1) | ssle-mgmt DNS (10.10.0.1) | 53 | zone `ssle` (agents find siem-01) |
| admin (VM) | siem-01.ssle | 443/tcp | Wazuh dashboard |
| admin (VM) | prom-01.ssle | 9090/tcp | Prometheus UI |
