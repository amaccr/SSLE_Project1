# Demo runbook

How to rebuild the lab and run the three threats live. Every command runs on the VM (h01) as the normal
user, except where it says `sudo`. Never run `build.sh` itself under sudo: root's `incus` does not see
the user's instances, so the two host steps ask for sudo themselves.

## 0. Rebuild (or check) the lab

```bash
./scripts/build.sh core            # mgmt + inet zones: prom-01, siem-01, client-01, attacker-01..03
./scripts/build.sh site avr        # site 1: lb-01, api-01/02, db-01
./scripts/build.sh site lis        # site 2: api-01, db-01, its own prom-01 (federated)
./scripts/build.sh host-exporter   # sudo: per-host metrics exporter + its nft firewall
./scripts/build.sh host-agent      # sudo: Wazuh agent on h01 + the SSLE-C2 nft log rule
```

Every step is idempotent, so re-running one is safe. `core` also copies the attack scripts into the
containers: `credstuffing.py`, `apt_chain.py` and `login.json` go to every attacker, and
`baseline_logins.py` goes to `client-01`.

**Pre-flight check (about 1 minute, do it before every demo):**

```bash
incus list --all-projects                                   # 15 instances, all RUNNING
incus exec siem-01 -- /var/ossec/bin/agent_control -l       # 9 agents Active (incl. h01.ssle)
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.100.10/health   # 200
sudo nft list table inet ssle_ids | grep -c SSLE-C2         # 1, otherwise the APT chain cannot fire
```

If the VM was rebooted before the `ssle-nft` unit existed, the last check prints an error. Then run
`./scripts/build.sh host-agent` again; it reloads the rule and installs the unit that keeps it after the
next reboot.

**Where to look:**
- **Prometheus:** <http://10.10.0.10:9090>. Use the *Alerts* page and the *Graph* tab with the queries below.
- **Wazuh:** <https://10.10.0.20>, user `admin`. Accept the self-signed certificate. Go to *Discover*,
  pick the `wazuh-alerts-*` index and type the DQL query in the search box. The password is the admin
  `indexer_password` in:
  ```bash
  incus exec siem-01 -- sh -c "tar -xOf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt" | grep -A1 "'admin'"
  ```

### Screen setup (before you start)

Open these tabs in advance so switching takes one click:

| Tab | What it holds |
|---|---|
| Prometheus *Graph* #1 | **throughput** (below), range `15m` |
| Prometheus *Graph* #2 | **logins by result**, range `15m` |
| Prometheus *Graph* #3 | **API CPU**, range `15m` |
| Prometheus *Alerts* | `/alerts`: the 4 rules in groups `ssle-dos` and `ssle-credstuffing` |
| Wazuh *Discover* | `wazuh-alerts-*`, time picker **Last 15 minutes**, auto-refresh 10 s. Add the columns `rule.id`, `rule.level`, `rule.description`, `agent.name` |

Prometheus queries:

| Panel | PromQL |
|---|---|
| targets up (tour) | `up` |
| throughput per API | `sum by (instance) (rate(ssle_http_requests_total[1m]))` |
| responses by status | `sum by (status) (rate(ssle_http_requests_total[1m]))` |
| p95 login latency | `histogram_quantile(0.95, sum by (le, instance) (rate(ssle_http_request_seconds_bucket{endpoint="/login"}[1m])))` |
| logins by result | `sum by (result) (rate(ssle_login_attempts_total[1m]))` |
| unknown users per min (the alert's expression) | `sum(rate(ssle_login_attempts_total{result="no_user"}[1m])) * 60` |
| API CPU (cores) | `rate(container_cpu_seconds_total{container=~"api-0.*"}[1m])` |
| traffic hitting the edge | `rate(container_network_receive_bytes_total{container="lb-01"}[1m])` |

Wazuh DQL queries, one per detection:

| Threat | DQL | Should show |
|---|---|---|
| everything from this project | `rule.id:1001*` | all custom alerts |
| DoS | `rule.id:100101 or rule.id:651` | flood alert, then the `firewall-drop` block |
| Credential stuffing | `rule.id:100111` | 1 source, many `data.dstuser` |
| Single failed logins | `rule.id:100110` | the raw events that 100111 correlates |
| APT injection | `rule.id:100121` | level 12, api agent |
| APT network legs | `rule.id:100122 or rule.id:100123` | agent `h01.ssle` |
| APT chain | `rule.id:100130` | level 14 |
| only the serious alerts | `rule.level >= 10` | |

### Monitoring tour (2 minutes, before the first attack)

This shows that the monitoring exists before anything is attacked.

1. **Prometheus → Status → Targets.** The jobs `host`, `app` (avr APIs, scraped directly) and `federate`
   (the `lis` site's own Prometheus) are all UP.
2. **Graph: `up`.** The `lis` series arrive through `federate`. This is the scalability point from the report.
3. **Alerts page.** All 4 rules are *inactive* (green). This is the baseline.
4. **Wazuh → Agents.** 9 agents are active. Then show *Discover* with
   `rule.id:1001*`. It is empty or almost empty: there are no custom alerts yet.

If you start the client baseline (`baseline_logins.py`, section 2) now, the graphs have a "normal"
line to compare against when the attacks begin.

**Suggested order:** run the threats in the report's order, but remember that the DoS block stops
`attacker-01` for 10 minutes. Either unblock it (end of section 1) or run the DoS last.

## 1. DoS: application-layer flood (report §5.1)

```bash
incus exec attacker-01 -- ab -n 5000 -c 50 -p /root/login.json -T application/json http://192.168.100.10/login
```

The request count, not the time, bounds the flood. Once rate-limited, nginx answers at roughly 12k req/s,
and a bigger burst only overflows the Wazuh agent buffer. If the block lands mid-run, `ab` stalls on the
dropped packets; press Ctrl-C.

**What to show, in order:**
1. **Terminal, while `ab` runs:** thousands of non-2xx responses. These are nginx's `429`s:
   `limit_req` caps each source IP at 10 r/s.
2. **Prometheus, right after `ab` ends** (allow ~15 s for a scrape):
   - Graph `rate(container_network_receive_bytes_total{container="lb-01"}[1m])`: a clear spike. The flood
     did reach the edge.
   - Graph `sum by (instance) (rate(ssle_http_requests_total[1m]))`: it stays at about 10 req/s.
     `sum by (status) (...)` shows no `429`, because the 429s never reach the app.
   - Graph `rate(container_cpu_seconds_total{container=~"api-0.*"}[1m])`: CPU stays low, so the edge shields the hash path.
   - *Alerts*: `DoSHighRequestRate` and `DoSAPICPUSaturation` stay **inactive**. That is expected:
     their thresholds sit above what one rate-limited IP can push, so they are meant for an unmitigated
     or distributed flood. With one source, Wazuh carries the detection.
3. **Wazuh, ~10–30 s after the start:** run `rule.id:100101 or rule.id:651`. Rule 100101 (level 12)
   names `data.srcip: 192.168.100.66`. A few seconds later rule 651 shows the `firewall-drop` block
   on agent `lb-01`. Expand one document to show the fields.
4. **Terminal, during the block**, the attacker times out but the client is unaffected:
   ```bash
   incus exec attacker-01 -- curl -s -m 3 -o /dev/null -w '%{http_code}\n' http://192.168.100.10/health   # 000
   incus exec client-01  -- curl -s -m 3 -o /dev/null -w '%{http_code}\n' http://192.168.100.10/health   # 200
   ```

**Unblock early** (otherwise the block expires by itself after 600 s):

```bash
incus exec lb-01 --project avr -- sh -c 'iptables -D INPUT -s 192.168.100.66 -j DROP; iptables -D FORWARD -s 192.168.100.66 -j DROP' 2>/dev/null
```

## 2. Credential stuffing and the botnet variant (report §5.2)

Optional baseline, in a second terminal: `incus exec client-01 -- python3 /root/baseline_logins.py --duration 300`.

**Single source (about 1 minute):**

```bash
incus exec attacker-01 -- python3 /root/credstuffing.py --rate 60
```

**What to show, in order:**
1. **Terminal:** the output marks `bob:password123` as a takeover.
2. **Wazuh, while it runs** (it fires after 8 failures in 60 s, so within seconds): run `rule.id:100111`.
   Every alert has the same `data.src` and a different `data.dstuser`. Then run `rule.id:100110` to show
   the individual failures it correlates.
3. **Prometheus, during the run and ~1 minute after:**
   - Graph `sum by (result) (rate(ssle_login_attempts_total[1m]))`: `no_user` jumps from 0 and `ok`
     barely moves.
   - Graph `sum by (status) (rate(ssle_http_requests_total[1m]))`: there are no `429`s, so the DoS
     edge never sees this attack.
   - *Alerts*: `CredentialStuffingUnknownUsers` goes *pending*, and after its `for: 1m` it goes
     **firing**. Wait for the firing state before moving on. `CredentialStuffingFailedLogins` needs
     2 minutes, so it may only reach pending.

**Botnet (3 sources, 1 dump):**

```bash
for n in 1 2 3; do incus exec attacker-0$n -T -- python3 /root/credstuffing.py --slice $n/3 --rate 5 & done; wait
```

The `-T` is essential: without it `incus exec` allocates a TTY, and a backgrounded (`&`) TTY job is
stopped by the shell (you see `Interrompido`/`Stopped`), so the attacks never actually run and only one
or two sources show up in Wazuh.

**What to show:** this is the key comparison, so put the two screens side by side.
- **Wazuh:** `rule.id:100110` shows the failures coming in from 3 different `data.src` values.
  `rule.id:100111` gets **no new** hits for these sources: each one stays under 8 failures per 60 s.
  Set the time picker to the botnet run only, so the earlier single-source hits don't confuse the view.
- **Prometheus:** the graph `sum(rate(ssle_login_attempts_total{result="no_user"}[1m])) * 60` stays above
  the threshold of 3, and *Alerts* shows `CredentialStuffingUnknownUsers` firing again.
- The point: per-source controls are blind, while the aggregate still sees the attack.

**Lockout (vertical brute force):**

```bash
incus exec attacker-01 -- python3 /root/credstuffing.py --brute-user alice --rate 120
```

After 5 failures `alice` is locked for 15 minutes, and even her correct password is rejected.
**Prometheus:** the graph `sum by (result) (rate(ssle_login_attempts_total[1m]))` shows a new `locked`
series, and `bad_password` stops growing once the lock lands. **Wazuh:**
`rule.id:100110 and data.dstuser:alice` shows the failures against a single user. Note that the baseline script uses `alice`, so run this one last.

## 3. APT: the kill chain (report §5.3)

```bash
incus exec attacker-01 -- python3 /root/apt_chain.py --out /root/apt_transcript.txt
```

**What to show:**
1. The transcript: `bob` session, reverse shell from `api-01` or `api-02`, a blocked probe to the mgmt
   network, the leaked `DB_PASSWORD`, and the `users` hashes dumped.
2. **Prometheus first, briefly:** the throughput, logins-by-result and CPU graphs show **nothing**, and
   no alert fires. This is on purpose: APT is low and slow and stays under every volume threshold. That
   is why it needs correlation in the SIEM.
3. **Wazuh, after the script ends.** Build the story one leg at a time:
   1. `rule.id:100121`: the injection (level 12, agent `api-01`/`api-02`, the `sensor` field holds the payload).
   2. `rule.id:100123 or rule.id:100122`: the C2 egress to the attacker network and the blocked recon
      probe to mgmt (agent `h01.ssle`).
   3. `rule.id:100130`: the chain alert, level 14, the highest in the project. It fires only because both
      legs came from the same foothold within 10 minutes.
   4. Optionally run `rule.level >= 10` for the whole timeline in one view.
4. Point out that there is no automatic response: this is the alert-only + human playbook decision.

**Clean up the foothold.** The detached reverse shell outlives the script. `setsid` takes it out of
gunicorn's session but not out of the service's cgroup, so restarting the unit kills it:

```bash
for i in api-01 api-02; do incus exec $i --project avr -- systemctl restart ssle-api; done
```

## Known gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `100130` never fires | The `SSLE-C2` nft rule is missing (reboot before the `ssle-nft` unit existed) | `./scripts/build.sh host-agent` |
| Attacks from `attacker-01` time out | It is still blocked by the DoS active response | Unblock (section 1) or wait 10 minutes |
| `alice` cannot log in | Locked by the brute-force demo | Wait 15 minutes |
| Wazuh shows events late during the flood | The `lb-01` agent buffer overflows ("Events may be lost"); report §5.1 | Expected. Keep the flood short (`-n 5000`) |
| Botnet shows only 1–2 sources; jobs print `Interrompido`/`Stopped` | Backgrounded `incus exec` without `-T` is suspended by the shell (SIGTTOU) | Use `-T` in the botnet loop (already in section 2) |
| Prometheus throughput graph is empty | `rate(...[1m])` needs recent samples; there is no live traffic right now | Query while an attack or the baseline is running, or widen the range to a window that had traffic |
| APT / any Wazuh query shows no results | The *Discover* time picker (Last 15 min) does not cover the run, or you queried before the script finished | Widen to Last 1 hour, re-run the query after the script ends |
| `iptables -D ... Bad rule` on manual unblock | The DoS block already auto-expired (600 s timeout) | Harmless; there was no rule left to delete |
