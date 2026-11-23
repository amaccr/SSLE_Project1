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

Useful Prometheus queries:

| Panel | PromQL |
|---|---|
| throughput per API | `sum by (instance) (rate(ssle_http_requests_total[1m]))` |
| p95 login latency | `histogram_quantile(0.95, sum by (le, instance) (rate(ssle_http_request_seconds_bucket{endpoint="/login"}[1m])))` |
| logins by result | `sum by (result) (rate(ssle_login_attempts_total[1m]))` |
| API CPU (cores) | `rate(container_cpu_seconds_total{container=~"api-0.*"}[1m])` |

**Suggested order:** run the threats in the report's order, but remember that the DoS block stops
`attacker-01` for 10 minutes. Either unblock it (end of section 1) or run the DoS last.

## 1. DoS: application-layer flood (report §5.1)

```bash
incus exec attacker-01 -- ab -n 5000 -c 50 -p /root/login.json -T application/json http://192.168.100.10/login
```

The request count, not the time, bounds the flood. Once rate-limited, nginx answers at roughly 12k req/s,
and a bigger burst only overflows the Wazuh agent buffer. If the block lands mid-run, `ab` stalls on the
dropped packets; press Ctrl-C.

**What to show:**
1. `ab` reports thousands of non-2xx responses. These are nginx's `429`s: `limit_req` caps each source IP at 10 r/s.
2. The Prometheus throughput panel stays at about 10 req/s, and API CPU stays low. The edge shields the hash path.
3. Wazuh: run `rule.id:100101 or rule.id:651`. Rule 100101 (level 12) names `192.168.100.66`. A few
   seconds later rule 651 shows the `firewall-drop` block.
4. During the block, the attacker times out but the client is unaffected:
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

**What to show:**
1. The output marks `bob:password123` as a takeover.
2. In Prometheus, the "logins by result" panel shows `no_user` jumping from 0. The *Alerts* page shows
   `CredentialStuffingUnknownUsers` firing. There are zero `429`s, so the DoS edge never sees this attack.
3. Wazuh: run `rule.id:100111`. Every alert has the same `data.src` and a different `data.dstuser`.

**Botnet (3 sources, 1 dump):**

```bash
for n in 1 2 3; do incus exec attacker-0$n -- python3 /root/credstuffing.py --slice $n/3 --rate 5 & done; wait
```

**What to show:** Wazuh `100111` fires **0** times for these sources, while the Prometheus `no_user` alert
still fires. Per-source controls are blind; the aggregate is not.

**Lockout (vertical brute force):**

```bash
incus exec attacker-01 -- python3 /root/credstuffing.py --brute-user alice --rate 120
```

After 5 failures `alice` is locked for 15 minutes, and even her correct password is rejected. Logins by
result shows `locked`. Note that the baseline script uses `alice`, so run this one last.

## 3. APT: the kill chain (report §5.3)

```bash
incus exec attacker-01 -- python3 /root/apt_chain.py --out /root/apt_transcript.txt
```

**What to show:**
1. The transcript: `bob` session, reverse shell from `api-01` or `api-02`, a blocked probe to the mgmt
   network, the leaked `DB_PASSWORD`, and the `users` hashes dumped.
2. Wazuh: run `rule.id:100121` (injection, level 12, api agent). Then `rule.id:100123 or rule.id:100122`
   (C2 egress and blocked recon, host agent `h01.ssle`). Then `rule.id:100130`: the chain alert,
   level 14, the highest in the project.
3. Point out that there is no automatic response: this is the alert-only + human playbook decision.

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
