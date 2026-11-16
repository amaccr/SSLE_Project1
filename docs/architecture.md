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

## Addressing plan

Every subnet: `.1` gateway (the VM: DNS, routing), `.2`–`.99` **fixed** addresses, `.100`–`.254` DHCP (so a dynamic
lease can never take a fixed address). Fixed addresses are DHCP reservations set by the build script.

| Where | Fixed addresses |
|---|---|
| each site (`instances.conf`, 4th column) | lb `.10`, api `.21`–`.29`, analytics `.31`, db `.41`, prom `.51` |
| ssle-mgmt | prom-01 `10.10.0.10`, siem-01 `10.10.0.20` |
| inet | lb-01 (public) `.10`, client-01 `.20`, attacker-01 `.66` |

Why fixed: the firewall rules are written with IPs. Incus ACLs on bridge networks can't match "instances that
have ACL x" (tested 16 Nov: `Unsupported nftables subject`), only addresses.

## Firewall: Incus network ACLs, deny by default

One ACL per role and site (`acl-<site>-<role>`), generated by `build.sh` from the call graph and attached to every
network card of the role's instances. Unmatched traffic is **dropped** coming in (no answer, so a scan learns nothing)
and **rejected** going out (our own services fail fast instead of hanging). Replies to allowed connections pass
automatically. Every network card also has `security.ipv4_filtering` and `security.mac_filtering`, so a container
can't send from another instance's address. Without that, IP-based rules could be passed by changing an IP.

| Role | Ingress allowed | Egress allowed (plus the common flows) |
|---|---|---|
| lb | tcp/80 from inet | tcp/5000 to api + analytics |
| api, analytics | tcp/5000 from lb; tcp/9102 from prom | tcp/5432 to db |
| db | tcp/5432 from api + analytics | (only the common flows) |
| common to all | | DNS (udp+tcp/53) to the site gateway; tcp/1514–1515 to siem-01; tcp/80,443 to any (apt) |

Tested 16 Nov (`client-01` = outside world):

| Connection | Expected | Result |
|---|---|---|
| client → lb-01:80; lb-01 → api-01/02:5000; api-01/02 → db-01:5432 | open | open |
| client → api-01:5000, → api-01:9102, → db-01:5432 (skipping the lb) | blocked | blocked |
| lb-01 → db-01:5432; api-01 → api-02:5000; api-01 → lb-01:80; db-01 → api-01:5000; api-01 → db-01:22; api-01 → VM:22 | blocked | blocked |
| DNS and apt from db-01, api-01, lb-01 | open | open |
| api-02 sends from lb-01's address (10.10.1.10) to api-01:5000 | blocked | blocked (anti-spoofing) |
| login through lb-01 | 200 | 200, logged with the real client IP |

Limitations:
- **apt needs the internet**, so tcp/80,443 out is allowed to any address. That's also an exfiltration or
  reverse-shell path for an APT. Internal targets are still protected by their own ingress rules. Better: an apt
  proxy as the only allowed destination, or remove the rule after the build.
- **Blocked attempts are logged by the kernel on the VM**, but for bridge networks Incus can't show them
  (`incus network acl show-log` works only for OVN). Using them as an APT signal needs the VM's kernel log
  shipped to Wazuh.
- Rules use IPs, so the addressing plan and the rules must stay in sync. Both come from `instances.conf`, and
  re-running the script regenerates them.
- prom-01 and siem-01 don't exist yet; their ACLs (and the mgmt side of the management flows) come with them.

## Monitoring: prom-01.ssle

Prometheus from the Ubuntu package (Guide 3's pull model), on `10.10.0.10`. Its config is generated by `build.sh`:
- **job `app`:** each site's API/analytics `/metrics` on 9102. The site build writes `targets/app-<site>.json` into
  prom-01 (file-based service discovery), so adding a site needs no restart and no hand-edited list.
  The `instance` label is relabelled to the bare DNS name (`api-01.avr.pt.ssle`) so it joins with `container_info`.
- **job `federate`:** sites with their own Prometheus (lis) write `targets/federate-<site>.json` instead.
- Targets are DNS names, so scraping depends on the mgmt → site DNS delegation (see the DNS test).
- Firewall `acl-mgmt-prom`: UI (9090) only from the VM; egress only to the app metrics ports, site Prometheus,
  the host exporter, DNS, Wazuh and apt. Rewritten on every site build from all sites' addresses.

Tested 16 Nov: both APIs `up` with `site="avr"`; after 3 failed + 1 good login through lb-01,
`sum by (result) (ssle_login_attempts_total)` gave `bad_password 3, ok 1`; client-01 → prom-01:9090 and
prom-01 → db-01:5432 both blocked.
Limitation: counters live in the gunicorn processes and restart from 0 when the API restarts, so alerts must use
`rate()`/`increase()` (which handle resets), never raw counter values.

## SIEM: siem-01.ssle

Wazuh 4.14 all-in-one (Guide 4's installer, `wazuh-install.sh -a -i`) on `10.10.0.20`. Agents on every avr instance and
on prom-01, named by their full DNS name (short names repeat across sites) and pinned to the manager's version.

Keeping Wazuh from hurting the VM:
- **Disk:** siem-01 lives on the Incus storage pool `wazuh`, on a second VM disk mounted at `/mnt/wazuh`
  (`LABEL=ssle-wazuh`, `nofail` in `/etc/fstab`). The pool uses the subfolder `incus/`, which exists only on that
  disk, so if the disk isn't mounted the pool fails instead of writing to the root disk. If Wazuh fills its disk,
  Wazuh stops and the VM keeps running. The root disk had 8.2 GB free, and the VM's swap partition sits right after
  root, so growing the root partition would have meant repartitioning.
- **Memory:** `limits.memory=5GiB` for the container, indexer heap 2 GB (by default it takes half of the RAM it
  can see, which inside a container is the whole VM's).
- **Vulnerability detection off:** it kept a local CVE database of ~10 GB (refreshed hourly) and none of the three
  threats uses it. Disk use went from 16 GB to 4 GB. Limitation: a real deployment would keep it, since unpatched
  packages are a classic APT entry point.
- **Retention:** an ISM policy (`ssle-retention`) deletes daily alerts/archives/monitoring/statistics indices after
  14 days. 14, not 7, so the first attack tests survive until the report and demo. In production the number comes
  from policy or law (often 90+ days).
- Firewall `acl-mgmt-siem`: 1514/1515 only from lab instances, dashboard (443) only from the VM.

Limitation: agent enrollment (1515) has no password, so anything that can reach 1515 could enroll a fake agent;
only the firewall limits who can.
