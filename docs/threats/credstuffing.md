# Threat 2 — Credential stuffing (and targeted brute force)

Working notes + report draft. Mirrors the required report subsections
(description, relevance, exploitation, metrics, response, PoC post-mortem).

## Target and idea
A credential-stuffing run from `attacker-01.inet` (192.168.100.66) against the only
exposed surface, `lb-01` (192.168.100.10:80), replaying a leaked `username:password`
dump at `POST /login`. Detection is by **login semantics** — failed logins across
**many distinct usernames** from one source — NOT by volume. This is what keeps it
distinct from the DoS threat:

| | DoS (threat 1) | Credential stuffing (threat 2) |
|---|---|---|
| shape | huge volume on ONE username (alice) | one try each across MANY usernames |
| signature | request rate / CPU saturation | `login_failed` across distinct users; mostly `no_user` |
| pace | as fast as possible | **low-and-slow**, under the nginx per-IP limit |
| edge defence sees it? | yes (429s, CPU) | **no** (measured: zero 429s) |
| detected from | nginx access log, Prometheus request-rate | app JSON log, Prometheus `ssle_login_attempts_total` |
| response | per-IP block (firewall-drop) | account lockout + aggregate alert (per-IP block is **evaded by a botnet**) |

The app already labels every login `ok | bad_password | no_user` (+ `locked`, added as
the response). `no_user` (the username does not exist) is the clean signal: legitimate
users never type a username that is not there, so its baseline is **0**, while a leaked
dump is full of them.

## Why it matters (relevance)
Password reuse makes stuffing cheap and effective: an attacker replays credentials
breached elsewhere and bets that some user reused them here. One of our three seeded
operators, `bob`, uses `password123` — a password in every leak list — so the run
**takes over his account** while `alice` (a strong passphrase `Sunrise-Tuesday-42`) and
`carol` survive. No exploit, no malware: just other sites' breaches plus reuse.

## Baseline (measured 2026-11-17, from client-01)
`scripts/baseline_logins.py` plays legitimate operators (alice/carol, correct passwords,
a 5% typo rate), ~6 logins/min for 5 min. Peak 1-minute rates:

| result | baseline peak | note |
|---|---|---|
| `no_user` | **0.00 / min** | legit traffic has no reason to hit a non-existent user |
| `bad_password` | 2.67 / min | the occasional typo |
| `ok` | ~8 / min (bursty) | successful logins |

So the floor the attack must stand out from is: `no_user` = 0, total failures ~2.67/min.
Figure: `images/credstuffing/ui/baseline.png` (green `no_user` pinned on zero).

## Attack (from attacker-01)
`scripts/credstuffing.py` (stdlib `urllib`, talks only to lb-01). Two modes:

**Horizontal spray (stuffing):**
```
python3 credstuffing.py --target http://192.168.100.10 --rate 60 --loop --shuffle
```
An embedded "leaked dump" of 43 `user:password` pairs: 40 usernames that do not exist
here (→ `no_user`), `alice`/`carol` with WRONG leaked passwords (→ `bad_password`, they
survive), and `bob:password123` (→ `ok`, **takeover**). `--rate` is attempts/min; 60/min
= 1/s sits well under the nginx 10 r/s per-IP limit.

Run result (240 s sustained): **4 × 200 (bob taken over), 163 × 401, and 0 × 429** —
the flood never tripped the rate limit, confirming it is invisible to the threat-1 edge
defence. Peak 1-minute rates during the spray: `no_user` **58.7/min**, `bad_password`
4.0/min. The takeover is visible only in the LOG (`login_ok`, `user=bob`,
`src=192.168.100.66`), never in the metrics (labels carry no IP, by design).

**Vertical brute force (single account):**
```
python3 credstuffing.py --brute-user alice --rate 120
```
Tries a password list against ONE real account. This is the attack the per-account
lockout is built to stop (see Response). Verified: 15 guesses, all 401; `alice` locked
after 5.

### The botnet variant — per-source defences are evaded, the aggregate survives (measured 2026-11-18)
A distributed run spreads the same dump over three source IPs: `attacker-01/02/03`
(192.168.100.66/67/68, added to `build.sh core`). Each bot sprays a disjoint chunk
(`credstuffing.py --slice I/3`) paced at 5/min, so within any 60 s window a single source
touches < 8 distinct usernames — just under the Wazuh correlation threshold.

Result (3 bots, 180 s):

| signal | single source (earlier) | distributed (3 bots) |
|---|---|---|
| Wazuh `100110` (one failed login) | fired per event | **+43 events** (the failures still arrive and are logged) |
| Wazuh `100111` (≥8 distinct users/60 s from one `src`) | fired **25×** | **0** — never fires for any bot |
| Prometheus `CredentialStuffingUnknownUsers` (aggregate `no_user`) | fired | **fired** (18.7/min, `images/credstuffing/ui/botnet_prometheus_alerts.png`) |
| takeover of bob | yes (from .66) | yes (from **.67**) |

So splitting the spray across sources **blinds every per-source control** — the Wazuh
per-`src` correlation, the nginx per-IP rate limit (no 429s), and, by extension, a
firewall-drop block (it would have to chase three IPs, then thirty, then three thousand) —
while the **aggregate** `no_user` rate is unchanged and still trips the Prometheus alert.
That is the whole argument for the response being account lockout + an aggregate alert
rather than a per-IP block. Figure: `images/credstuffing/plots/bad-logins_botnet.png`.

Per-source event counts over the run confirm the evasion: 14 / 13 / 14 distinct usernames
each across the full ~3 min, but never 8 inside one 60 s window. Scaling note: the Wazuh
rule could be tightened (lower the frequency, or correlate on `dstuser` across sources),
but a large enough botnet always drives the per-source rate toward zero — only an
aggregate or per-account view is robust to distribution.

## Detection
Two independent layers, both verified firing live.

**Prometheus** — aggregate "is the whole site being stuffed?" `rules/ssle-credstuffing.yml`
(generated by `provision_prom`), two tiers:
- `CredentialStuffingUnknownUsers` (PRIMARY): `sum(rate(ssle_login_attempts_total{result="no_user"}[1m])) * 60 > 3`, `for: 1m`.
  Baseline 0, so a sensitive 3/min threshold with a huge margin and ~no false positives;
  catches the broad spray even when paced low-and-slow.
- `CredentialStuffingFailedLogins` (BACKSTOP): total failures `> 10/min`, `for: 2m`.
  Catches a TARGETED run that only tries valid usernames (all `bad_password`, no
  `no_user`, so the primary would miss it); 10/min sits above the 2.67/min typo floor.

Both fired during the 240 s run (`images/credstuffing/ui/prometheus_alerts.png`: Firing (2)),
while the DoS rules stayed inactive — the two threats light up different alerts. Quantified: during
the spray the API containers used ~**0.014 cores** (`images/credstuffing/plots/cpu_spray.png`) against
the DoS flood's ~3 cores (~200× less) and a DoS CPU alert threshold of 2 cores, so the saturation
alert never even approaches firing. Credential stuffing is effectively invisible to the DoS signals.

**Wazuh** — who, and across how many usernames. `wazuh/local_rules.xml`, reading the app
JSON log `/var/log/ssle/api.log` via the built-in JSON decoder:
- `100110` (level 5): one `login_failed` event (`decoded_as json`, `app=ssle-api`).
- `100111` (level 10, frequency 8 / 60 s): `if_matched_sid 100110` with `same_field src`
  and `different_field dstuser` = ≥ 8 failed logins from the SAME source across DISTINCT
  usernames in 60 s. `different_field dstuser` is what separates stuffing from a DoS
  brute-force (which hammers ONE user).
- NOTE (found with `wazuh-logtest`): the JSON decoder maps the log key `user` → the
  standard field `dstuser`, and keeps `src` as `src` (not `srcip`), so the rule uses
  `same_field src` / `different_field dstuser`, not `same_source_ip`.
- **No active response, on purpose.** Level 10 does not drive firewall-drop: a per-IP
  block is evaded by a botnet, and blocking a shared/NAT IP would itself be a DoS.

Live run: 183 × 100110, split almost evenly **api-01: 91 / api-02: 92** (nginx round-robins
the logins), and 25 × 100111, all `src=192.168.100.66`. Key point: the correlation runs at
the MANAGER keyed on `src`, so splitting the logs across two API agents does **not** blind
it — load-balancing is transparent to the detection. Dashboard evidence:
`images/credstuffing/ui/wazuh_credstuffing.png` (Discover, `rule.id:100111` — the hits, every
one `data.src=192.168.100.66` with a different `data.dstuser`: the distinct-username signature).

Why `rate()`/per-min and not raw counters: the app counters restart from 0 when gunicorn
restarts (docs/architecture.md, prom-01 limitation).

## Response
**Per-account lockout** (`apps/api/app.py`, state in `login_state`): after
`LOCKOUT_THRESHOLD = 5` consecutive failures on an existing account it is locked for
`LOCKOUT_MINUTES = 15`. Design choices and why:
- **Only existing accounts get lock state** — `login_state.username` is a FK to `users`,
  so a spray of random usernames can never grow the table (a memory-DoS guard enforced by
  the database). A non-existent user has nothing to lock.
- **Checked BEFORE the password hash** — a locked account is rejected without running the
  deliberately slow pbkdf2 check, so (a) even a correct password (a successful stuffing
  hit) cannot take over a locked account, and (b) a locked account stops costing CPU
  (links back to the threat-1 hash cost).
- **Same generic 401 when locked** — the lock is not revealed to the client; a server-side
  `account_locked` event and a `result="locked"` metric give us the visibility instead.
- State is in the DB, shared by both APIs, so lockout holds no matter which API served the
  request.

Verified (vertical brute against alice): all 15 guesses 401; `alice` reached
`failed_count = 5`, `locked_until` set; then **alice's correct password returned 401 while
locked** (the decisive test); `result="locked"` counter = 11; one `account_locked` event
`user=alice, after=5`.

**Aggregate alert (no auto-block)** — the Prometheus/Wazuh rules above alert a human rather
than acting, because the only safe automated per-IP action (block) is the one a botnet
defeats.

### What each control stops — and does NOT (the point)
| attack shape | lockout | aggregate alert | what actually stops it |
|---|---|---|---|
| horizontal spray (1 try/user) | **no** (no account reaches 5) | **yes** (detects) | detection + human response; MFA |
| vertical brute (1 user, many tries) | **yes** (locks at 5) | partial | lockout |
| reused-password takeover (bob) | **no** (0 failures, instant ok) | **no** | strong password / MFA |

No single control is sufficient: lockout defends the targeted account, the aggregate alert
sees the spray, and neither stops a takeover with a correct reused password — only password
strength or MFA does. That layering is the report's thesis.

## Metrics — before / during / after
| Phase | `no_user` (Prom) | `bad_password` | nginx 429s | outcome |
|---|---|---|---|---|
| before (baseline) | 0 / min | 2.67 / min | 0 | normal |
| during (spray, c=1, 1/s) | **58.7 / min** | 4.0 / min | **0** | bob taken over; both Prom alerts + Wazuh 100111 fire |
| during (vertical brute) | 0 | → lock | 0 | alice locked at 5; `locked`=11 |
| "after" (lockout on) | unchanged for the spray | — | 0 | lockout stops the VERTICAL brute, not the spray |

Note on "after": unlike DoS (where nginx `limit_req` visibly cuts the flood), the lockout
does **not** change the spray's metrics — each username is still tried once. "After" here
means the vertical brute is now blocked, shown by the `locked` result and the correct
password being rejected, not by a drop in the spray curve. That asymmetry is itself a
finding: the stuffing spray has no clean automated "stop", which is why detection + MFA
matter more than any single block.

Figures (`images/credstuffing/`): `ui/baseline.png`, `ui/during.png` (`no_user` 0 → ~58/min),
`ui/prometheus_alerts.png` (both tiers firing); matplotlib renders from the range API in `plots/`:
`bad-logins_spray.png` (the detection signal — `no_user` spike, everything else flat) and
`cpu_spray.png` / `throughput_spray.png` / `latency-p95_spray.png` (the DoS panels, flat throughout).
Regenerate with `python3 scripts/plot_metrics.py --start '<t0>' --end '<t1>' --label <phase> --outdir images/credstuffing/plots`.

## Limitations (report rewards discussing these)
- **Timing side-channel / username enumeration.** `no_user` and `locked` return before the
  pbkdf2 hash, while a real account with a wrong password pays it, so response TIME
  distinguishes them even though the 401 body is identical. (Pre-existing; the body-level
  non-enumeration in architecture.md does not cover timing.) Fix: a constant-time dummy
  hash on the miss/locked paths.
- **Lockout as a DoS.** An attacker who knows a victim's username can lock them out on
  purpose with 5 bad guesses. This is the account-lockout version of "blocking can
  self-DoS". Mitigations: lock softly (throttle/backoff instead of hard deny), or require
  the lock only from unfamiliar sources.
- **Per-IP controls are evaded by a botnet** — the reason the response is aggregate, not a
  block. The distributed variant (TODO) will demonstrate this directly.
- **HTTP, not HTTPS** (architecture.md, "Port 80 only"): credentials travel in clear text.
  Encryption would not stop stuffing (the attacker sends the passwords), but production
  would terminate TLS at lb-01.
- **SIEM under load**: a fast stuffing run still generates one `100110` per failed login
  (183 in a short run); at botnet scale this is a lot of events — the base rule could be set
  to level 0 (correlate but do not alert) to keep the dashboard readable.

## PoC post-mortem (to finish)
What worked: `no_user` is a near-perfect discriminator (baseline 0 → 58.7/min); detection
fired on both layers and survived load-balancing; lockout provably stops the vertical brute
and blocks even a correct password while locked. What the limits are: the spray itself has
no safe automated block, the bob takeover is stopped by neither control (→ MFA/password
policy), per-account lockout is itself a DoS vector, and per-IP controls fall to a botnet
(demonstrated: 3 bots fired the aggregate Prometheus alert while the Wazuh per-source
correlation never triggered — 0 vs 25 from a single source). Links to threat 1 (the slow hash is both a DoS cost and, once a lock is set,
a cost the lock avoids) and to the APT threat (a stolen valid credential like bob's is a
quiet foothold, not a flood).
