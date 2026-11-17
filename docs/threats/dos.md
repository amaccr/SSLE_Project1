# Threat 1 — Denial of Service (application-layer flood)

Working notes + report draft. Mirrors the required report subsections
(description, relevance, exploitation, metrics, response, PoC post-mortem).

## Target and idea
A volume flood from `attacker-01.inet` (192.168.100.66) against the only exposed
surface, `lb-01` (192.168.100.10:80). The flood hits `POST /login`, whose password
check is a deliberately slow pbkdf2 hash: a cheap request for the attacker costs real
CPU on the API. Detection is by **volume + saturation** (this keeps it distinct from
credential stuffing, which is detected by *failed logins across many usernames*).

## Amplification (measured 2026-11-16, baseline, c=1)
| Path | Per-request | Single-thread throughput |
|---|---|---|
| `/login` (bad password -> pbkdf2 hash) | 66.7 ms | 15 req/s |
| `/health` (no DB, no hash) | 1.4 ms | 708 req/s |

Amplification factor ~47x: one login request ~= 47 health checks of server work.
Predicted saturation ceiling on the login path: 1000/66.7 ~= 15 req/s per worker
x 6 workers (3 per API x 2 APIs) ~= **~90 req/s** before requests queue. (To confirm
empirically with the ramp.)

## Attack commands (from attacker-01)
Body (real user, wrong password, so every request pays the hash):
```
printf '%s' '{"username":"alice","password":"wrong"}' > /root/login.json
```
Ramp (find the knee): run at rising concurrency, record req/s + p95 from ab's output
```
ab -n <N> -c <C> -p /root/login.json -T application/json http://192.168.100.10/login
```
Sustained flood (for the Prometheus "during" capture): c=50 for ~3 min.

## Ramp results (2026-11-16, client-side, ab -t 10 per level)
VM has 4 cores, no per-container CPU limit, shared by all services.
| conc | req/s | mean latency | p95 |
|---|---|---|---|
| 1 | 14.7 | 68 ms | 98 ms |
| 2 | 28.7 | 70 ms | 94 ms |
| 5 | 49.8 | 100 ms | 147 ms  <- knee: throughput maxed, latency starts rising |
| 10 | 53.2 | 188 ms | 298 ms |
| 20 | 52.9 | 378 ms | 500 ms |
| 40 | 51.5 | 777 ms | 918 ms |
| 80 | 50.0 | 1602 ms | 1565 ms |

**Key finding — ceiling ~50 req/s, not the predicted ~90.** The ~90 assumed 6 CPU cores
(6 workers x 15/s). The VM has 4, shared with nginx/db/prometheus/wazuh/OS, so ~3 are free for
hashing; at saturation the two APIs together burn ~3 cores (1.5 each). Worker count is only an
upper bound; the real DoS ceiling is PHYSICAL CPU. Running 2 API instances did NOT double
capacity (shared cores on one VM) -> confirms docs/architecture.md "both sites share one VM".
Past the knee throughput is flat and latency grows linearly with concurrency (Little's Law):
at c=80 legitimate users wait 1.6 s/request.

## Monitoring queries (Prometheus, http://10.10.0.10:9090/graph)
Open all three at the SAME range (the `– [15m] +` box, top-left of the graph), Graph tab.
These are the before / during / after panels.

1. Throughput per API (the flood = a spike):
```
sum by (instance) (rate(ssle_http_requests_total[1m]))
```
2. p95 login latency per API (the "knee": climbs before throughput maxes out):
```
histogram_quantile(0.95, sum by (le, instance) (rate(ssle_http_request_seconds_bucket{endpoint="/login"}[1m])))
```
3. Bad logins/sec by result (the attack signature):
```
sum by (result) (rate(ssle_login_attempts_total[1m]))
```
4. API container CPU saturation (cores used; host exporter restored 2026-11-16):
```
rate(container_cpu_seconds_total{container=~"api-0.*"}[1m])
```
(Host exporter = apps/host-exporter on the VM, scraped as job `host`. Idle baseline ~0 cores;
a saturated API worker set approaches the container's CPU allowance.)
Why `rate()` and not raw counters: the app counters restart from 0 when gunicorn
restarts; `rate()`/`increase()` handle resets (docs/architecture.md, prom-01 limitation).

## Images (images/dos/)
Two sets, on purpose: Prometheus UI screenshots (prove monitoring is deployed) + clean
matplotlib plots rendered from Prometheus's range API (for the report figures).
- `*_baseline.png` — Prometheus UI, light baseline traffic (before)
- `*_during.png` — Prometheus UI, the c=50 flood (cpu_during.png was captured at the wrong
  time window; use the plot instead)
- `plots/*_during.png` — matplotlib, the c=50 flood (throughput ~28/API, p95 ~0.24s,
  bad_password ~57/s, CPU ~1.6 cores/API). Regenerate for "after" with:
  `python3 scripts/plot_metrics.py --start '<t0>' --end '<t1>' --label after`
- `client-baseline.png` — ab baseline table (before, client-side)
- `ui/prometheus_alerts.png` — Prometheus /classic/alerts, both DoS rules loaded
- `ui/wazuh_threat-hunting.png` — Wazuh Threat Hunting, the 100101+651 events over the test window
- `ui/wazuh_dos-detection-and-block.png` — Wazuh table: rule 100101 (level 12, DoS detected, srcip
  192.168.100.66) and rule 651 (Host Blocked by firewall-drop) together on lb-01 = detection + response

## Detection
- Wazuh (DONE): nginx lines decode as `web-accesslog` (srcip, id=status, url). Built-in rule 31101
  = "web 4xx"; 429 = a rate-limit trip. Custom rules (wazuh/local_rules.xml, on the manager):
  - 100100 (level 3): one HTTP 429 from srcip (narrows 31101 to status 429).
  - 100101 (level 12): >=30 x 100100 from the SAME source IP in 60s = DoS confirmed.
  Verified with wazuh-logtest (30 x level-3 then level-12) and live (100101 fired on the burst).
  Note: the built-in rule 31151 ("multiple 4xx from same IP", 14/90s) ALSO fires, but its threshold
  is low (legit retries could trip it); 100101 is DoS-specific and higher-confidence for auto-block.
- Prometheus alert rule (DONE): /etc/prometheus/rules/ssle-dos.yml (generated by provision_prom):
  DoSHighRequestRate (sum(rate(ssle_http_requests_total[1m])) > 20 for 2m) and DoSAPICPUSaturation
  (sum(rate(container_cpu_seconds_total{container=~"api-0.*"}[1m])) > 2 for 2m). Loaded + valid
  (Prometheus /classic/alerts, image images/dos/ui/prometheus_alerts.png).
  IMPORTANT insight: thresholds sit above the ~10 req/s a single IP can push ONCE nginx rate-limiting
  is on, so these stay green while the per-IP limit holds. In fact, after rate-limiting the flood is
  INVISIBLE to the app-level Prometheus metrics (the 429s never reach the app), so DoS detection then
  comes from the EDGE (nginx logs -> Wazuh), not the app. The Prometheus alert is a backstop that fires
  for an UNMITIGATED or DISTRIBUTED flood (the undefended flood hit ~56 req/s / ~3 cores, well over
  both thresholds). Defence-in-depth: Prometheus = "are we saturated?", Wazuh = "who, and block them".

## Response (active)
- Wazuh active response (DONE): firewall-drop, location=local, rules_id=100101, timeout=600
  (wazuh/active-response.conf, applied in siem-01 /var/ossec/etc/ossec.conf; NOTE the stock file wraps
  the example in <!-- -->, so the block must be UNCOMMENTED). Needs iptables on the agent (installed
  on lb-01). On trigger, lb-01 adds `iptables -I INPUT/FORWARD -s <srcip> -j DROP` for 600s, then
  auto-removes. Verified 2026-11-17: attacker (.66) blocked (curl 000), client-01 unaffected (200),
  built-in rule 651 "Host Blocked by firewall-drop" confirms. Duplicate triggers abort safely.
  Limitation: per-IP block, like the rate limit, is evaded by a distributed botnet (threat 2). A
  volumetric flood also drops Wazuh agent events (buffer) -> detection can lag the attack.

## Response
- nginx `limit_req` (DONE): `limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;`
  + `limit_req zone=perip burst=20 nodelay;` + `limit_req_status 429;` in provision_lb.
  Result: capped the flood from ~56 req/s to ~10 req/s reaching the APIs; API CPU 3.07 -> 0.54
  cores; p95 latency 0.24 -> 0.074 s. Over-limit requests get 429 instantly (cheap), so the
  expensive hash path is shielded. A single-source flood is effectively neutralised.
  Finding: once rate-limited, ab at c=50 generated ~12,000 req/s of 429s (nginx shrugged it off,
  only ~10/s reached the APIs) -> nginx is far more resilient than the hash path, but that volume
  floods the logs. For the sustained "after" capture the attacker was throttled to ~80 req/s.
- Wazuh **active response** (TO BUILD): block the offending IP (firewall-drop) on the alert.

## Limitation found: the monitoring pipeline has its own DoS ceiling
During the 12k req/s burst the lb-01 Wazuh AGENT hit its client_buffer limit and logged
"Agent buffer is full: Events may be lost" (recovered ~10 s later). The agent self-throttles to
protect the manager, so under a volumetric flood the SIEM DROPS events exactly when the attack is
loudest. Consequence: don't rely on per-event SIEM alerting alone for volumetric DoS -- the
aggregate signal (Prometheus request-rate/CPU) and the edge defence (nginx) are more reliable.
Mitigation: tune the agent buffer / events-per-second, or detect the flood by rate at nginx.

## Metrics — before / during / after
| Phase | req/s (Prom) | p95 login latency (server) | API CPU (cores) | ab client view |
|---|---|---|---|---|
| before | ~0 | ~0.08 s | ~0 | 15 req/s @ c=1, 68 ms |
| during (c=50, 3 min) | ~54 (26.6+26.2) | 0.24 s | ~3.07 (1.53+1.54) | 54 req/s, mean 923 ms, p95 1524 ms, 0 failed |
| after (nginx limit_req) | ~10 (capped) | 0.074 s | ~0.54 (0.27+0.27) | ~10/s reach API; nginx 1520 through (401) / 4397 blocked (429) |

Two report points from the "during" run:
- Service DEGRADED, not crashed: 0 failed requests but latency 68 ms -> ~920 ms (13x). A heavier
  flood would cross the 30 s gunicorn timeout into real errors.
- Client p95 (1524 ms) >> server p95 (238 ms): the server histogram times only work inside a
  worker; the ~1.3 s waiting in gunicorn's backlog is invisible to it. So the Prometheus latency
  metric UNDER-reports user pain -> for alerting, request-rate and CPU saturation are more faithful
  signals than server-side latency.

## PoC post-mortem (to write the same evening)
What worked, what the limits are (e.g. no resource monitoring until the exporter was
restored; nginx limit_req is per-IP so a botnet spreads under it -> links to threat 2).
