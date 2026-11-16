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

**App on 5000, app metrics on a separate port (9102).** `lb-01` proxies only to port 5000 on the apps.
The `/metrics` endpoint runs on its own port (`prometheus_client.start_http_server(9102)`) that nginx never
routes to, so from `inet` it doesn't exist. A firewall rule then allows only Prometheus to reach 9102.
Both layers are needed: without the firewall, anything inside the site (e.g. an APT foothold on `api-01`)
could read the counters and check whether its activity is being counted. With `/metrics` on the app port,
`http://lb-01/metrics` would show the login-failure counters to everyone unless nginx blocked that path, which
is an easy rule to forget. 9200 was avoided because the Wazuh indexer on `siem-01` uses it.
Limitation: `/metrics` is plain HTTP without authentication; it relies on the network rule alone.

**lb-01 is dual-homed.** It has `eth0` on `ssle-avr` (default route, DNS, backends) and `eth1` on `inet` with a
fixed address, `192.168.100.10` (from `config/sites.conf`; a public address shouldn't change on rebuild). nginx
overwrites `X-Forwarded-For` with the address it saw, and the API trusts exactly one proxy hop.
Tested from `client-01` (192.168.100.235), 16 Nov:

| Request | Logged `src` |
|---|---|
| through lb-01, with a forged `X-Forwarded-For: 6.6.6.6` | 192.168.100.235 (forged header discarded) |
| straight to api-01:5000, same forged header | **6.6.6.6** (the attacker chooses their own IP) |
| straight to api-01:5000, no header | 192.168.100.235 |

The last two rows show that the VM routes between its bridges **without NAT**, so today an outsider can skip
lb-01 and reach the APIs directly, and then also fake their IP in the logs. Dual-homing alone does not prevent
this; it makes the fix simple. Clients never need to be forwarded by the VM to reach lb-01, so the firewall
rule is "drop all forwarding from `inet` into the internal subnets", with no exceptions. (If lb-01 were only on
`ssle-avr`, the rule would need an exception for its DHCP address on port 80.)

**App logs are JSON, one object per line.** The first version wrote `key=value` lines with the username raw,
which allowed **log injection**: a username containing a newline could write a whole fake line (e.g. many
`login_failed` lines with a legitimate client's IP, so Wazuh's active response would block an innocent user,
which is a DoS without a flood), and `x src=8.8.8.8` gave a line with two `src` fields. Now each event is written
with `json.dumps`, which escapes quotes and newlines inside values, and Wazuh's built-in JSON decoder reads it.
Values are cut to 128 characters. Tested 16 Nov through lb-01: a forged `login_ok` line, a second `src` and a
1000-character username all stayed inside the `user` value; every line parsed as JSON with the real `src`.
Limitation: JSON stops user input from changing the **structure** of an event, not its **content**. Values like
`user` are still attacker-controlled (rules must not trust them, and the dashboard must display them safely).
Only `src` is trustworthy, and only because of nginx + the firewall.

**DNS delegation with dnsmasq forwarding, only where needed.** Each Incus network's DNS only knows its own
`dns.domain`. One `raw.dnsmasq` line per delegated zone fixes that, e.g. on `ssle-mgmt`:
`server=/avr.pt.ssle/10.10.1.1` (same for `lis`). The org's DNS doesn't know site names, it knows who to ask.
(Incus also has built-in network zones, which is more setup for the same idea.)
- mgmt → sites: needed, so Prometheus can find targets by name.
- sites → mgmt: needed, so agents find `siem-01.ssle`: forward `ssle` from each site to `10.10.0.1`
  (tested: the site's own zone still answers locally, see "DNS test" below).
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
| prom-01.ssle | avr app `/metrics` | 9102/tcp | app metrics (requests, logins), scraped directly |
| prom-01.ssle | prom-01.lis.pt.ssle | 9090/tcp (`/federate`) | federation |
| prom-01.lis.pt.ssle (its IP only) | h01.ssle (10.10.2.1) | 9101/tcp | scrape lis container metrics |
| prom-01.lis.pt.ssle | lis app `/metrics` | 9102/tcp | app metrics (requests, logins) |
| ssle-mgmt DNS (10.10.0.1) | site DNS (10.10.1.1, 10.10.2.1) | 53 | delegated zones `avr.pt.ssle`, `lis.pt.ssle` |
| site DNS (10.10.1.1, 10.10.2.1) | ssle-mgmt DNS (10.10.0.1) | 53 | zone `ssle` (agents find siem-01) |
| admin (VM) | siem-01.ssle | 443/tcp | Wazuh dashboard |
| admin (VM) | prom-01.ssle | 9090/tcp | Prometheus UI |

## DNS test: does a site resolve its own names when the mgmt DNS is down?

Setup: throwaway containers `t-avr` (project `avr`, network `ssle-avr`) and `t-mgmt` (project `default`,
network `ssle-mgmt`). The mgmt DNS was taken down by killing its dnsmasq, and both containers' caches were
flushed with `resolvectl flush-caches` so that a cached answer could not hide the result.

| Query | From | mgmt DNS up | mgmt DNS down |
|---|---|---|---|
| t-avr.avr.pt.ssle | t-avr | resolves (exit 0) | resolves (exit 0) |
| t-mgmt.ssle | t-avr | resolves (exit 0) | fails (exit 2) after ~20 s |
| t-avr.avr.pt.ssle | t-mgmt | resolves (exit 0) | fails (exit 2) |
| t-mgmt.ssle | t-mgmt | resolves (exit 0) | fails (exit 2) |

**Why avr still answers its own names.** Two rules in avr's dnsmasq match `t-avr.avr.pt.ssle`:
`-S /avr.pt.ssle/` (added by Incus because of `dns.domain`; a server with no address means "answer locally,
never forward") and our `server=/ssle/10.10.0.1`. dnsmasq uses the **most specific (longest) matching
domain**, and `avr.pt.ssle` (3 labels) beats `ssle` (1 label). This is the same idea as longest-prefix match
in IP routing (`10.10.1.0/24` wins over `10.0.0.0/8`). It has nothing to do with `t-avr` being up: avr
answers from its own records whether or not mgmt is reachable.

**Why the first test alone proved nothing.** With mgmt up, both possible behaviours give the same answer:
if avr answered locally it resolves, and if avr forwarded to mgmt, mgmt would ask avr back
(`server=/avr.pt.ssle/10.10.1.1`) and it would still resolve. A test that passes either way can't tell them
apart. Only with mgmt down do the two behaviours give different results, which is why the test was needed.

**Limitation.** `10.10.0.1` is a single point of failure for everything except a site's own names:
- Every instance on `ssle-mgmt` gets only `10.10.0.1` from DHCP, with no second resolver to fall back to.
  That is why `t-mgmt` can't even resolve itself: its only DNS server is the one that is down.
- Every lookup that crosses zones goes through it (mgmt → site and site → mgmt).
- Consequence for monitoring: Wazuh agents in the sites find the manager by the name `siem-01.ssle`. An agent
  that restarts or enrolls while the mgmt DNS is down can't find the SIEM, so its events stop arriving
  exactly when something may be going wrong. Prometheus scrape targets given by name stop resolving too.
- A failed lookup takes ~20 s to time out, so anything that resolves names on every request slows down
  instead of failing fast. A DNS outage turns into a slowdown (a DoS side effect).

**Mitigation.**
- *Detection (not prevention):* monitor the DNS, e.g. a Prometheus probe that resolves a known name in each
  zone and alerts when it fails. It doesn't stop the outage, but responders learn about it straight away
  instead of from side effects.
- *Prevention:* give the agents the manager's IP instead of its name (no DNS dependency; the cost is that
  the IP must stay fixed, which a reserved DHCP address can guarantee), or run a second resolver for the
  `ssle` zone so that dnsmasq has another `server=` line to fall back to.
