# SSLE_Project1

Threat detection, monitoring and prevention on a pure-Incus lab (SSLE, Universidade de Aveiro).

A small sensor-portal service (nginx load balancer → 2× Flask API → PostgreSQL) in two sites, monitored
by Prometheus (metrics, federation for the second site) and Wazuh (SIEM). It is attacked by three threats,
each with detection and an action-response:

| Threat | Detection | Response |
|---|---|---|
| DoS (login flood) | Prometheus rate/CPU alerts; Wazuh `100101` (nginx 429s per source) | nginx `limit_req` + Wazuh `firewall-drop` (automatic) |
| Credential stuffing (+ botnet) | Prometheus `no_user` aggregate alert; Wazuh `100111` (distinct users per source) | per-account lockout + alert (no automatic block) |
| APT (multi-stage) | Wazuh `100121` injection, `100123` C2 egress, `100122` recon, `100130` chain | alert-only + human incident-response playbook |

## Build

```bash
./scripts/build.sh core            # mgmt + inet zones (Prometheus, Wazuh, client, attackers)
./scripts/build.sh site avr        # site 1
./scripts/build.sh site lis        # site 2 (own Prometheus, federated)
./scripts/build.sh host-exporter   # asks for sudo: per-host metrics exporter
./scripts/build.sh host-agent      # asks for sudo: Wazuh agent on the host + IDS nft rule
```

Run it as your normal user (never `sudo ./scripts/build.sh`). Every step is idempotent, so running it
again converges to the same state and deploys the current code. Adding a site means one line in
`config/sites.conf`, its instances in `config/instances.conf`, and `./scripts/build.sh site <name>`.

**Building the report PDF** (from the repository root, needs `texlive-xetex` and `texlive-latex-extra`):

```bash
pandoc docs/report.md -o report.pdf --pdf-engine=xelatex --toc \
  --shift-heading-level-by=-1 --resource-path=docs
```

Section numbers are written by hand in the headings, so do not add `--number-sections`.
The `newunicodechar` lines in the YAML header map arrows and relations that the Latin Modern
font lacks to math symbols. The attack-defence trees are `images/Adtree*.drawio.png`: each PNG
embeds its draw.io source, so open it in draw.io, edit, and export again as PNG (zoom 300%,
"Include a copy of my diagram" ticked) over the same file. PNG rather than SVG because
draw.io's SVG labels are HTML, which the SVG-to-PDF step drops.

**Running the demo:** see [`docs/demo.md`](docs/demo.md) for the pre-flight check, each attack command,
what to show in Prometheus and Wazuh, and how to reset between runs.

## Layout

| Path | What |
|---|---|
| `docs/report.md` | The report (see *Building the report PDF* above) |
| `docs/demo.md` | Demo runbook |
| `docs/architecture.md`, `docs/naming.md` | Design decisions: instances, flows, firewall, DNS; the naming scheme |
| `docs/threats/` | Working notes and measurements per threat (`dos.md`, `credstuffing.md`, `apt.md`) |
| `scripts/build.sh` | Builds the whole lab |
| `scripts/credstuffing.py`, `scripts/apt_chain.py` | Attack PoCs (copied to the attackers by `build.sh core`) |
| `scripts/baseline_logins.py` | Legitimate login traffic (baseline) |
| `scripts/plot_metrics.py`, `scripts/measure_bandwidth.sh` | Report figures from Prometheus; federation bandwidth measurement |
| `scripts/provision_host_agent.sh` | Host Wazuh agent + IDS rule (called by `build.sh host-agent`) |
| `apps/` | The API, the DB schema, the per-host exporter |
| `wazuh/` | Custom rules (`local_rules.xml`) and the active-response block |
| `config/` | Sites, instances, the IDS nft rule; generated secrets (git-ignored) |
| `images/` | Report figures and evidence (screenshots, plots, the APT transcript) |
| `Projeto.pdf` | Teacher guidelines |
