#!/usr/bin/env bash
# Builds the SSLE lab on Incus.
#   ./scripts/build.sh core        mgmt + inet networks and their instances (run once)
#   ./scripts/build.sh site avr    one site: its network, project and instances
# Safe to run again: anything that already exists is left as it is (idempotent).
set -euo pipefail

MGMT_DNS=10.10.0.1
# Fixed addresses outside the sites (see docs/architecture.md, "Addressing plan").
PROM_IP=10.10.0.10          # prom-01.ssle
SIEM_IP=10.10.0.20          # siem-01.ssle
INET_SUBNET=192.168.100.0/24
CLIENT_IP=192.168.100.20    # client-01.inet
ATTACKER_IP=192.168.100.66  # attacker-01.inet (outside adversary; load/flood source for the DoS threat)
WAZUH_VERSION=4.14          # same installer line as Guide 4
WAZUH_DISK=/mnt/wazuh       # second VM disk (LABEL=ssle-wazuh in /etc/fstab): Wazuh can only fill this disk

REPO=$(dirname "$(realpath "$0")")/..
IMAGE=images:ubuntu/22.04

# The sites live in config/sites.conf (the only place that knows which sites exist),
# their instances in config/instances.conf.
SITES_CONF=$REPO/config/sites.conf
INSTANCES_CONF=$REPO/config/instances.conf

# site_info <name>: prints "<region> <subnet prefix> <lb public address>" from sites.conf,
# fails if the site isn't listed.
site_info() {
    awk -v s="$1" '$1 == s { print $2, $3, $4; found = 1 } END { exit !found }' "$SITES_CONF" \
        || { echo "unknown site: $1 (not in $SITES_CONF)" >&2; return 1; }
}

# ensure_network <name> <key=value>...
# Creates the network only if it doesn't exist yet.
# Limitation: if it already exists with a different config (e.g. another subnet),
# it is NOT corrected, only reported as existing.
ensure_network() {
    local name=$1; shift
    if incus network show "$name" > /dev/null 2>&1; then
        echo "network $name: already exists"
    else
        incus network create "$name" "$@" > /dev/null
        echo "network $name: created"
    fi
}

# ensure_project <name>
# Shares images and profiles with the default project (otherwise the new project
# has an empty default profile: no disk, no network card). Networks are shared by default.
ensure_project() {
    local name=$1
    if incus project show "$name" > /dev/null 2>&1; then
        echo "project $name: already exists"
    else
        incus project create "$name" -c features.images=false -c features.profiles=false > /dev/null
        echo "project $name: created"
    fi
}

# ensure_network_key <network> <key> <value>
# Sets one key only if it differs: any change restarts the network's dnsmasq (a short DNS outage).
ensure_network_key() {
    local net=$1 key=$2 value=$3
    if [ "$(incus network get "$net" "$key")" != "$value" ]; then
        incus network set "$net" "$key=$value"
        echo "network $net: $key=$value"
    fi
}

# ensure_dnsmasq_line <network> <line>
# Appends one line to the network's raw.dnsmasq, only if it isn't there yet.
# Keeps the lines other sites added (raw.dnsmasq is one multi-line string).
ensure_dnsmasq_line() {
    local net=$1 line=$2 current
    current=$(incus network get "$net" raw.dnsmasq)
    if grep -qxF "$line" <<< "$current"; then
        echo "dns $net: '$line' already set"
    else
        incus network set "$net" raw.dnsmasq="${current:+$current
}$line"
        echo "dns $net: added '$line'"
    fi
}

# ensure_secrets <site>
# Secrets live in config/secrets-<site>.env (git-ignored). Generated randomly the FIRST time only, then
# reused: db-01 and api-01 both read the same file, so rebuilding one of them alone keeps them matching.
# One file per site: stealing avr's secrets gives nothing in lis.
ensure_secrets() {
    local file=$REPO/config/secrets-$1.env
    if [ ! -f "$file" ]; then
        ( umask 077
          { echo "DB_PASSWORD_API=$(openssl rand -hex 16)"
            echo "DB_PASSWORD_ANALYTICS=$(openssl rand -hex 16)"
            echo "SECRET_KEY=$(openssl rand -hex 32)"; } > "$file" )
        echo "secrets $1: generated $file"
    fi
    # shellcheck disable=SC1090
    . "$file"
}

# ensure_instance <project> <name> <network> <fixed address> [owner] [storage pool]
# Creates the container if it doesn't exist, pins its address, and waits until it has working DNS +
# internet (apt needs it). user.owner is set on every run, so a hand-made change is put back to what the
# config says (drift).
ensure_instance() {
    local project=$1 inst=$2 net=$3 addr=$4 owner=${5:-} pool=${6:-default} new=
    if incus info "$inst" --project "$project" > /dev/null 2>&1; then
        echo "instance $inst: already exists"
    else
        incus create "$IMAGE" "$inst" --project "$project" --network "$net" --storage "$pool" > /dev/null
        echo "instance $inst: created"
        new=1
    fi
    # Fixed address (a DHCP reservation) + anti-spoofing: the container can't send from any other IP or MAC.
    # Without the filtering, a compromised container could take a trusted IP and pass the firewall rules.
    if [ "$(incus config device get "$inst" eth0 ipv4.address --project "$project")" != "$addr" ]; then
        [ -n "$new" ] || incus stop "$inst" --project "$project"
        incus config device set "$inst" eth0 ipv4.address="$addr" \
            security.ipv4_filtering=true security.mac_filtering=true --project "$project"
        echo "instance $inst: address $addr"
        [ -n "$new" ] || incus start "$inst" --project "$project"
    fi
    [ -z "$new" ] || incus start "$inst" --project "$project"
    if [ -n "$owner" ]; then
        incus config set "$inst" --project "$project" user.owner="$owner"
    fi
    for _ in $(seq 60); do
        incus exec "$inst" --project "$project" -- getent hosts archive.ubuntu.com > /dev/null 2>&1 && return 0
        sleep 1
    done
    echo "instance $inst: no network after 60 s" >&2; return 1
}

# run_in <project> <instance> <command...>: run a command inside an instance
# Starts in /tmp: the default /root isn't readable by the postgres user (noisy warnings).
run_in() { local p=$1 i=$2; shift 2; incus exec "$i" --project "$p" --cwd /tmp -- "$@"; }

apt_install() {
    local p=$1 i=$2; shift 2
    run_in "$p" "$i" env DEBIAN_FRONTEND=noninteractive \
        apt-get -o DPkg::Lock::Timeout=120 -qq install -y "$@" > /dev/null
}

# --- Roles: how each kind of instance is set up. Safe to re-run: they converge to the same state,
# --- and re-running deploys the current code from the repo.

provision_db() {
    local p=$1 i=$2 subnet=$3
    run_in "$p" "$i" test -x /usr/bin/psql \
        || { run_in "$p" "$i" apt-get -qq update; apt_install "$p" "$i" postgresql; }

    # Listen on the network (default is localhost only), and log every connection:
    # "DB logins from an unexpected source" is one of the APT signals.
    run_in "$p" "$i" runuser -u postgres -- psql -qc "ALTER SYSTEM SET listen_addresses = '*'"
    run_in "$p" "$i" runuser -u postgres -- psql -qc "ALTER SYSTEM SET log_connections = on"

    # Who may connect over the network: only the two app roles, only to db ssle, only from the site subnet.
    # Limitation: the whole subnet, not specific IPs (IPs come from DHCP); the firewall narrows it later.
    local hba line="host ssle api,analytics $subnet scram-sha-256"
    hba=$(run_in "$p" "$i" runuser -u postgres -- psql -tAc "SHOW hba_file")
    run_in "$p" "$i" grep -qxF "$line" "$hba" || run_in "$p" "$i" sh -c "echo '$line' >> '$hba'"

    run_in "$p" "$i" runuser -u postgres -- psql -qtA \
        -c "SELECT 'CREATE DATABASE ssle' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ssle')" \
        | run_in "$p" "$i" runuser -u postgres -- psql -q
    run_in "$p" "$i" env PGOPTIONS="-c client_min_messages=warning" runuser -u postgres -- psql -q -v ON_ERROR_STOP=1 -d ssle < "$REPO/apps/db/schema.sql"
    # Passwords go through stdin, not the command line (command lines are visible in ps).
    run_in "$p" "$i" runuser -u postgres -- psql -q -v ON_ERROR_STOP=1 <<SQL
ALTER ROLE api       PASSWORD '$DB_PASSWORD_API';
ALTER ROLE analytics PASSWORD '$DB_PASSWORD_ANALYTICS';
SQL
    run_in "$p" "$i" systemctl restart postgresql
    echo "instance $i: db ready"
}

provision_api() {
    local p=$1 i=$2 domain=$3
    run_in "$p" "$i" test -x /usr/bin/gunicorn \
        || { run_in "$p" "$i" apt-get -qq update
             apt_install "$p" "$i" gunicorn python3-flask python3-psycopg2 python3-prometheus-client; }

    # The app runs as its own unprivileged user, not root: a command injection then gets a normal
    # user's shell, not root (the attacker would need privilege escalation for more).
    run_in "$p" "$i" sh -c 'id ssle > /dev/null 2>&1 || useradd --system --no-create-home ssle'
    run_in "$p" "$i" mkdir -p /opt/ssle-api
    incus file push "$REPO/apps/api/app.py" "$REPO/apps/api/gunicorn.conf.py" "$i/opt/ssle-api/" --project "$p"

    # Environment: readable only by root (systemd reads it before dropping to the ssle user).
    # Note: the running process still has these values, which is exactly what APT step 3 steals.
    run_in "$p" "$i" sh -c 'umask 077; cat > /etc/ssle-api.env' <<ENV
DB_HOST=db-01.$domain
DB_NAME=ssle
DB_USER=api
DB_PASSWORD=$DB_PASSWORD_API
SECRET_KEY=$SECRET_KEY
LOG_FILE=/var/log/ssle/api.log
SSLE_VULNERABLE=1
PROMETHEUS_MULTIPROC_DIR=/run/ssle-api-metrics
prometheus_multiproc_dir=/run/ssle-api-metrics
ENV

    # A real systemd unit instead of systemd-run: it survives a container restart, restarts the app if it
    # crashes (e.g. during a DoS) and can be re-applied safely. RuntimeDirectory is created empty on every
    # start, which is what prometheus multiprocess mode needs. LogsDirectory creates /var/log/ssle for user ssle.
    run_in "$p" "$i" sh -c 'cat > /etc/systemd/system/ssle-api.service' <<'UNIT'
[Unit]
Description=SSLE sensor portal API
After=network-online.target

[Service]
User=ssle
EnvironmentFile=/etc/ssle-api.env
WorkingDirectory=/opt/ssle-api
RuntimeDirectory=ssle-api-metrics
LogsDirectory=ssle
ExecStart=/usr/bin/gunicorn -c gunicorn.conf.py app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
    run_in "$p" "$i" systemctl daemon-reload
    run_in "$p" "$i" systemctl enable --now ssle-api > /dev/null 2>&1
    run_in "$p" "$i" systemctl restart ssle-api      # picks up new code on a re-run

    # Operator accounts (ON CONFLICT DO NOTHING, so re-running is harmless). Runs outside gunicorn, so
    # without the metrics dir and with its log thrown away.
    run_in "$p" "$i" sh -c 'cd /opt/ssle-api && set -a && . /etc/ssle-api.env && set +a &&
        env -u PROMETHEUS_MULTIPROC_DIR -u prometheus_multiproc_dir LOG_FILE=/dev/null FLASK_APP=app \
        python3 -m flask seed'
    echo "instance $i: api ready"
}

provision_lb() {
    local p=$1 i=$2 site=$3 domain=$4 public=$5
    [ "$public" != "-" ] || { echo "instance $i: site $site has no public address in sites.conf" >&2; return 1; }

    # Second network card on inet with a fixed address (a public address shouldn't change on rebuild).
    # Clients reach lb-01 on inet itself, without being forwarded by the VM. So the firewall can simply
    # drop ALL forwarding from inet into the internal subnets (see docs/architecture.md, "lb-01 is dual-homed").
    if ! incus config device get "$i" eth1 network --project "$p" > /dev/null 2>&1; then
        incus config device add "$i" eth1 nic network=inet ipv4.address="$public" --project "$p" > /dev/null
    fi
    # Set on every run (not only when the card is added), so an older card also gets anti-spoofing.
    incus config device set "$i" eth1 security.ipv4_filtering=true security.mac_filtering=true --project "$p"
    # eth1 only for the clients: no default route and no DNS from inet (those stay on the site network).
    run_in "$p" "$i" sh -c 'umask 077; cat > /etc/netplan/20-inet.yaml' <<'NETPLAN'
network:
  version: 2
  ethernets:
    eth1:
      dhcp4: true
      dhcp4-overrides:
        use-routes: false
        use-dns: false
NETPLAN
    run_in "$p" "$i" netplan apply

    run_in "$p" "$i" test -x /usr/sbin/nginx \
        || { run_in "$p" "$i" apt-get -qq update; apt_install "$p" "$i" nginx; }
    # iptables: the Wazuh firewall-drop active response (DoS threat) adds DROP rules here.
    run_in "$p" "$i" test -x /usr/sbin/iptables || apt_install "$p" "$i" iptables

    # Backends = every api instance of this site in instances.conf (adding api-0N = one line there).
    # Limitation: nginx resolves these names when it (re)loads, so a rebuilt api with a new IP needs a
    # reload; re-running this script does that.
    local servers
    servers=$(awk -v s="$site" -v d="$domain" '$1 == s && $3 == "api" { printf "    server %s.%s:5000;\n", $2, d }' \
        "$INSTANCES_CONF")
    run_in "$p" "$i" sh -c 'cat > /etc/nginx/sites-available/ssle' <<NGINX
# DoS defence (threat 1): one request-rate counter per client IP. nginx sees the real client IP
# (X-Forwarded-For is overwritten below), so this throttles the actual attacker. 10 MB ~= 160k IPs.
# Limitation: per-IP limiting is defeated by a distributed botnet (each IP stays under the cap) -> that
# is threat 2's problem and needs an aggregate defence.
limit_req_zone \$binary_remote_addr zone=perip:10m rate=10r/s;
limit_req_status 429;                                   # over-limit -> 429 Too Many Requests (not 503)

upstream ssle_api {
$servers
}

server {
    listen 80 default_server;
    server_name _;
    server_tokens off;                                  # don't advertise the nginx version

    location / {
        # Absorb a burst of 20, then reject excess immediately (nodelay) with 429. This caps the flood
        # at the edge so it never reaches the APIs' expensive hash path.
        limit_req zone=perip burst=20 nodelay;
        proxy_pass http://ssle_api;
        proxy_set_header Host \$host;
        # Overwrite, don't append: whatever X-Forwarded-For the client sends is thrown away, so the
        # API (ProxyFix, one hop) always gets the address nginx actually saw.
        proxy_set_header X-Forwarded-For \$remote_addr;
    }
}
NGINX
    run_in "$p" "$i" ln -sf /etc/nginx/sites-available/ssle /etc/nginx/sites-enabled/ssle
    run_in "$p" "$i" rm -f /etc/nginx/sites-enabled/default
    run_in "$p" "$i" nginx -tq
    run_in "$p" "$i" systemctl reload nginx
    echo "instance $i: lb ready on $public:80 ->$(echo "$servers" | awk '{ printf " %s", $2 }')"
}

# --- Per-host exporter on the VM (h01): "observed, not declared" (docs/architecture.md) --------------
# Runs on the VM, not in a container, because only the VM can query Incus about every container. Reuses
# Guide 3's exporter (apps/host-exporter). Installing a systemd unit needs root, so THIS function is the
# only place build.sh uses sudo (one prompt); the rest must run as the normal incus user, never under
# sudo (root's incus wouldn't see the user's instances). The service itself runs as the invoking user,
# who has incus access through the incus group.
#
# One exporter, one listener PER monitoring domain (docs/architecture.md "One host exporter, two listeners").
# Generated from config so adding a site needs no hand-editing:
#   - the mgmt listener (10.10.0.1): the central prom. Shows the mgmt plane (default project) plus every
#     DIRECTLY-scraped site (one with no prom of its own, e.g. avr).
#   - one listener per FEDERATED site (one with its own prom, e.g. lis) on that site's gateway: shows ONLY
#     that site, so its local prom scrapes it and the central prom does not double-count it via federation.
# The interface you connect through decides what you see, so a URL parameter (which the caller could forge)
# is not needed. A host firewall then lets only a site's own prom reach its listener.
provision_host_exporter() {
    local user; user=$(id -un)
    sudo install -D -m 755 "$REPO/apps/host-exporter/host_exporter.py" /opt/ssle-host-exporter/host_exporter.py

    local site region prefix prom_ip mgmt_projects="default" listen="" fed_rules=""
    for site in $(awk '!/^#/ && NF { print $1 }' "$SITES_CONF"); do
        read -r region prefix _ < <(site_info "$site")
        prom_ip=$(ips_of "$site" prom)
        # A federated site gets its own listener only once its network exists (so binding can't fail on a
        # site that is defined but not built yet); until then it rides the mgmt listener harmlessly.
        if [ -n "$prom_ip" ] && incus network show "ssle-$site" > /dev/null 2>&1; then
            listen="$listen --listen $prefix.1=$site"
            fed_rules="$fed_rules        ip daddr $prefix.1 tcp dport 9101 ip saddr != $prom_ip drop
"
        else
            mgmt_projects="$mgmt_projects,$site"
        fi
    done
    listen="--listen $MGMT_DNS=$mgmt_projects$listen"

    sudo tee /etc/systemd/system/ssle-host-exporter.service > /dev/null <<UNIT
[Unit]
Description=SSLE per-host Incus metrics exporter
After=incus.service network-online.target

[Service]
User=$user
ExecStart=/usr/bin/python3 /opt/ssle-host-exporter/host_exporter.py $listen --port 9101
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
    sudo systemctl daemon-reload
    sudo systemctl enable --now ssle-host-exporter > /dev/null 2>&1
    sudo systemctl restart ssle-host-exporter          # pick up new code / new listeners on a re-run

    # Host firewall for the site listeners: only a site's own Prometheus may reach its gateway:9101.
    # Separate nft table with a delete guard + policy accept, so it can never break other traffic (same
    # pattern as config/ssle_ids.nft). Re-applied on every run; not persistent across reboot.
    if command -v nft > /dev/null; then
        sudo nft -f - <<NFT
table inet ssle_exporter
delete table inet ssle_exporter
table inet ssle_exporter {
    chain exporter_in {
        type filter hook input priority -100; policy accept;
$fed_rules    }
}
NFT
    fi
    echo "host exporter: $listen"
}

# --- SIEM agent on the VM host: ships the kernel firewall-drop logs (APT lateral-movement signal) --------
# Host-level, so it needs root (like provision_host_exporter). The manager version is read here (as the
# normal incus user) and passed to the root script, since root's incus can't see the user's instances.
provision_host_agent() {
    incus info siem-01 > /dev/null 2>&1 || { echo "wazuh: siem-01 not built yet, no host agent"; return 0; }
    local ver
    ver=$(run_in default siem-01 /var/ossec/bin/wazuh-control info -v | tr -d 'v')
    sudo WAZUH_MANAGER="$SIEM_IP" WAZUH_AGENT_NAME="h01.ssle" "$REPO/scripts/provision_host_agent.sh" "$ver"
}

# --- Monitoring: prom-01.ssle (central Prometheus, Guide 3's pull model) -------------------------------
provision_prom() {
    local p=$1 i=$2
    run_in "$p" "$i" test -x /usr/bin/prometheus \
        || { run_in "$p" "$i" apt-get -qq update; apt_install "$p" "$i" --no-install-recommends prometheus; }
    run_in "$p" "$i" mkdir -p /etc/prometheus/targets
    run_in "$p" "$i" sh -c 'cat > /etc/prometheus/prometheus.yml' <<'PROM'
# Generated by scripts/build.sh (edits are overwritten).
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - /etc/prometheus/rules/*.yml

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['localhost:9090']

  # Per-host exporter on the VM (CPU/mem/net of every container, read from Incus). One listener for now;
  # a second site (lis) would add 10.10.2.1:9101. Each sample carries its own container/project labels.
  - job_name: host
    static_configs:
      - targets: ['10.10.0.1:9101']

  # App /metrics (port 9102) of sites scraped directly. Each site writes its own file
  # (targets/app-<site>.json) when it is built: Prometheus re-reads these files without a restart.
  - job_name: app
    file_sd_configs:
      - files: ['/etc/prometheus/targets/app-*.json']
    relabel_configs:
      # instance = the bare DNS name (api-01.avr.pt.ssle), so it joins with container_info (docs/naming.md)
      - source_labels: [__address__]
        regex: '([^:]+):\d+'
        target_label: instance

  # Sites with their own Prometheus (lis) are federated instead: one pull of the site's summary.
  - job_name: federate
    honor_labels: true
    metrics_path: /federate
    params:
      'match[]': ['{job=~".+"}']
    file_sd_configs:
      - files: ['/etc/prometheus/targets/federate-*.json']
PROM
    # DoS alert rules (aggregate "are we saturated?" signal). Thresholds sit between normal load and
    # the undefended flood (measured ~56 req/s, ~3 CPU cores), and ABOVE the ~10 req/s a single IP can
    # push once nginx rate-limiting is on -- so these fire for an unmitigated or distributed flood, and
    # stay green while the per-IP limit holds (then Wazuh/nginx-logs carry the detection).
    run_in "$p" "$i" mkdir -p /etc/prometheus/rules
    run_in "$p" "$i" sh -c 'cat > /etc/prometheus/rules/ssle-dos.yml' <<'RULES'
# Generated by scripts/build.sh (edits are overwritten).
groups:
  - name: ssle-dos
    rules:
      - alert: DoSHighRequestRate
        expr: sum(rate(ssle_http_requests_total[1m])) > 20
        for: 2m
        labels: {severity: warning, threat: dos}
        annotations:
          summary: "High HTTP request rate reaching the APIs ({{ $value | printf \"%.0f\" }} req/s) - possible DoS"
      - alert: DoSAPICPUSaturation
        expr: sum(rate(container_cpu_seconds_total{container=~"api-0.*"}[1m])) > 2
        for: 2m
        labels: {severity: critical, threat: dos}
        annotations:
          summary: "API containers CPU-saturated ({{ $value | printf \"%.1f\" }} cores) - possible DoS"
RULES
    # Credential-stuffing alert rules (threat 2). Not volume/saturation but login SEMANTICS. Baseline
    # measured 2026-11-17: no_user = 0/min, bad_password (typos) ~= 2.67/min. Two tiers:
    #   - unknown usernames (no_user): baseline 0, so a sensitive 3/min threshold with ~no false
    #     positives; catches the broad "leaked dump" spray even paced low-and-slow under the nginx limit.
    #   - total failed logins: backstop for a TARGETED run that only tries valid usernames (all
    #     bad_password); 10/min sits well above the typo floor.
    run_in "$p" "$i" sh -c 'cat > /etc/prometheus/rules/ssle-credstuffing.yml' <<'RULES'
# Generated by scripts/build.sh (edits are overwritten).
groups:
  - name: ssle-credstuffing
    rules:
      - alert: CredentialStuffingUnknownUsers
        expr: sum(rate(ssle_login_attempts_total{result="no_user"}[1m])) * 60 > 3
        for: 1m
        labels: {severity: warning, threat: credstuffing}
        annotations:
          summary: "Logins against unknown usernames ({{ $value | printf \"%.0f\" }}/min) - credential stuffing"
      - alert: CredentialStuffingFailedLogins
        expr: sum(rate(ssle_login_attempts_total{result=~"bad_password|no_user"}[1m])) * 60 > 10
        for: 2m
        labels: {severity: warning, threat: credstuffing}
        annotations:
          summary: "High failed-login rate ({{ $value | printf \"%.0f\" }}/min) - targeted stuffing or brute force"
RULES
    run_in "$p" "$i" promtool check config /etc/prometheus/prometheus.yml > /dev/null
    run_in "$p" "$i" systemctl restart prometheus
    echo "instance $i: prometheus ready"
}

# provision_site_prom <project> <instance> <domain> <prefix>
# A site-LOCAL Prometheus (e.g. prom-01.lis), as opposed to the central provision_prom above. It scrapes
# ONLY its own site -- the site's app /metrics (:9102) and the site's host-exporter listener (<gw>:9101) --
# and exposes the built-in /federate endpoint, which prom-01.ssle pulls in bulk (register_prom_targets
# writes federate-<site>.json for it). This is the federation half of the bandwidth-optimisation design
# (docs/architecture.md "Uneven Prometheus, on purpose"): the central server makes ONE compact /federate
# pull per interval instead of scraping every target across the link. Alert rules stay central (they
# evaluate the federated series), so a site prom carries none.
provision_site_prom() {
    local p=$1 i=$2 domain=$3 prefix=$4 site=$1 apps
    run_in "$p" "$i" test -x /usr/bin/prometheus \
        || { run_in "$p" "$i" apt-get -qq update; apt_install "$p" "$i" --no-install-recommends prometheus; }
    # app targets = this site's api/analytics instances, as full DNS names (resolved by the site's own DNS).
    apps=$(awk -v s="$site" -v d="$domain" \
        '$1 == s && ($3 == "api" || $3 == "analytics") { printf "%s'\''%s.%s:9102'\''", sep, $2, d; sep = ", " }' \
        "$INSTANCES_CONF")
    run_in "$p" "$i" sh -c 'cat > /etc/prometheus/prometheus.yml' <<PROM
# Generated by scripts/build.sh (edits are overwritten). Site-local Prometheus for $site, federated by prom-01.ssle.
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['localhost:9090']

  # The site's own containers, from the host exporter's site-bridge listener ($prefix.1:9101). Only this
  # site's Prometheus may reach that listener (host firewall, docs/architecture.md "two listeners").
  - job_name: host
    static_configs:
      - targets: ['$prefix.1:9101']

  # The site's app /metrics (:9102), scraped LOCALLY; the central server never scrapes these directly.
  - job_name: app
    static_configs:
      - targets: [$apps]
        labels: {site: $site}
    relabel_configs:
      # instance = the bare DNS name (api-01.lis.pt.ssle), so it joins with container_info (docs/naming.md)
      - source_labels: [__address__]
        regex: '([^:]+):\d+'
        target_label: instance
PROM
    run_in "$p" "$i" promtool check config /etc/prometheus/prometheus.yml > /dev/null
    run_in "$p" "$i" systemctl restart prometheus
    echo "instance $i: site Prometheus ready (federated by prom-01.ssle)"
}

# register_prom_targets <site>: tells prom-01.ssle what to scrape in this site.
# A site with its own prom instance is federated; otherwise its apps are scraped directly.
register_prom_targets() {
    local site=$1 region prefix domain targets file
    incus info prom-01 > /dev/null 2>&1 || { echo "prometheus: prom-01 not built yet, $site not registered"; return 0; }
    read -r region prefix _ < <(site_info "$site")
    domain=$site.$region.ssle
    targets=$(awk -v s="$site" -v d="$domain" '$1 == s && $3 == "prom" { printf "%s\"%s.%s:9090\"", sep, $2, d; sep = ", " }' \
        "$INSTANCES_CONF")
    if [ -n "$targets" ]; then
        file=federate-$site.json
    else
        file=app-$site.json
        targets=$(awk -v s="$site" -v d="$domain" '$1 == s && ($3 == "api" || $3 == "analytics") { printf "%s\"%s.%s:9102\"", sep, $2, d; sep = ", " }' \
            "$INSTANCES_CONF")
    fi
    run_in default prom-01 sh -c "cat > /etc/prometheus/targets/$file" <<JSON
[{"targets": [$targets], "labels": {"site": "$site", "region": "$region"}}]
JSON
    echo "prometheus: $file -> $targets"
}

# ensure_siem_acl <agent IPs>: siem-01's firewall
ensure_siem_acl() {
    local agents=$1 acl=acl-mgmt-siem
    incus network acl show "$acl" > /dev/null 2>&1 || incus network acl create "$acl" > /dev/null
    {
        echo "description: deny by default; siem-01.ssle (generated by build.sh, edits are overwritten)"
        echo "ingress:"
        acl_rule ingress tcp "$agents,$MGMT_DNS" 1514,1515 "agents (+ h01 host agent) -> manager (events, enrollment)"
        acl_rule ingress tcp "$MGMT_DNS" 443       "admin on the VM -> Wazuh dashboard"
        echo "egress:"
        acl_rule egress udp "$MGMT_DNS" 53     "DNS (mgmt dnsmasq)"
        acl_rule egress tcp "$MGMT_DNS" 53     "DNS over TCP"
        acl_rule egress tcp any         80,443 "apt / Wazuh packages (any address)"
    } | incus network acl edit "$acl"
    incus config device set siem-01 eth0 security.acls="$acl" \
        security.acls.default.ingress.action=drop security.acls.default.egress.action=reject \
        security.acls.default.ingress.logged=true security.acls.default.egress.logged=true
    echo "firewall: siem-01 -> $acl"
}

# ensure_mgmt_acls: prom-01's (and siem-01's) firewall. Needs every site's addresses, so it is rewritten by core AND by every
# site build (a new site must become scrapable without remembering to re-run core).
ensure_mgmt_acls() {
    local site apps="" proms="" all="" a
    for site in $(awk '!/^#/ && NF { print $1 }' "$SITES_CONF"); do
        a=$(ips_of "$site" api analytics); [ -z "$a" ] || apps=${apps:+$apps,}$a
        a=$(ips_of "$site" prom);          [ -z "$a" ] || proms=${proms:+$proms,}$a
        a=$(ips_of "$site" lb api analytics db prom); [ -z "$a" ] || all=${all:+$all,}$a
    done
    incus info siem-01 > /dev/null 2>&1 && ensure_siem_acl "${all:+$all,}$PROM_IP"
    incus info prom-01 > /dev/null 2>&1 || return 0
    local acl=acl-mgmt-prom
    incus network acl show "$acl" > /dev/null 2>&1 || incus network acl create "$acl" > /dev/null
    {
        echo "description: deny by default; prom-01.ssle (generated by build.sh, edits are overwritten)"
        echo "ingress:"
        acl_rule ingress tcp "$MGMT_DNS" 9090 "admin on the VM -> Prometheus UI"
        echo "egress:"
        acl_rule egress tcp "$apps"     9102 "scrape app /metrics (sites without their own prom)"
        acl_rule egress tcp "$proms"    9090 "federate site Prometheus"
        acl_rule egress tcp "$MGMT_DNS" 9101 "scrape the host exporter (h01.ssle)"
        acl_rule egress udp "$MGMT_DNS" 53   "DNS (mgmt dnsmasq)"
        acl_rule egress tcp "$MGMT_DNS" 53   "DNS over TCP"
        acl_rule egress tcp "$SIEM_IP"  1514,1515 "wazuh agent -> manager"
        acl_rule egress tcp any         80,443 "apt updates (any address)"
    } | incus network acl edit "$acl"
    incus config device set prom-01 eth0 security.acls="$acl" \
        security.acls.default.ingress.action=drop security.acls.default.egress.action=reject \
        security.acls.default.ingress.logged=true security.acls.default.egress.logged=true
    echo "firewall: prom-01 -> $acl"
}

# --- SIEM: siem-01.ssle (Wazuh all-in-one, Guide 4's installer) -------------------------------------
# ensure_wazuh_pool: a storage pool on the second disk, so Wazuh can never fill the VM's root disk.
# Uses the subfolder incus/, which exists only ON that disk: if the disk isn't mounted, the pool fails to
# start instead of quietly writing into the empty mount point on the root disk.
ensure_wazuh_pool() {
    mountpoint -q "$WAZUH_DISK" || { echo "wazuh: $WAZUH_DISK is not mounted, refusing to continue" >&2; return 1; }
    if incus storage show wazuh > /dev/null 2>&1; then
        echo "storage wazuh: already exists"
    else
        incus storage create wazuh dir source="$WAZUH_DISK/incus" > /dev/null
        echo "storage wazuh: created on $WAZUH_DISK"
    fi
}

provision_siem() {
    local p=$1 i=$2 secrets=$REPO/config/secrets-mgmt.env
    # Memory cap for the whole container (indexer + manager + dashboard), so Wazuh can't starve the lab.
    incus config set "$i" limits.memory=5GiB --project "$p"
    if ! run_in "$p" "$i" test -x /var/ossec/bin/wazuh-control; then
        echo "instance $i: installing Wazuh $WAZUH_VERSION (all-in-one, takes ~10-15 min)"
        run_in "$p" "$i" apt-get -qq update
        apt_install "$p" "$i" curl
        run_in "$p" "$i" sh -c "cd /root && curl -sO https://packages.wazuh.com/$WAZUH_VERSION/wazuh-install.sh &&
            bash wazuh-install.sh -a -i > /root/wazuh-install.log 2>&1" \
            || { echo "instance $i: install failed, see /root/wazuh-install.log inside $i" >&2; return 1; }
    fi
    # Indexer heap: by default half of the RAM it can see, and in a container that's the whole VM's RAM.
    if ! run_in "$p" "$i" grep -qx -- -Xmx2g /etc/wazuh-indexer/jvm.options; then
        run_in "$p" "$i" sed -i 's/^-Xms.*/-Xms2g/; s/^-Xmx.*/-Xmx2g/' /etc/wazuh-indexer/jvm.options
        run_in "$p" "$i" systemctl restart wazuh-indexer
        echo "instance $i: indexer heap 2 GB"
    fi
    # Vulnerability detection off: it keeps a local copy of the whole CVE database (~10 GB, refreshed hourly)
    # and none of our three threats uses it (the APT enters through our own weak endpoint, not a known CVE).
    # Limitation: a real deployment would keep it, unpatched packages are a classic APT entry point.
    if run_in "$p" "$i" sed -n '/<vulnerability-detection>/,/<\/vulnerability-detection>/p' /var/ossec/etc/ossec.conf |
            grep -q '<enabled>yes</enabled>'; then
        run_in "$p" "$i" sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/ s|<enabled>yes</enabled>|<enabled>no</enabled>|' \
            /var/ossec/etc/ossec.conf
        run_in "$p" "$i" systemctl restart wazuh-manager
        run_in "$p" "$i" rm -rf /var/ossec/queue/vd /var/ossec/queue/vd_updater
        echo "instance $i: vulnerability detection off (CVE database deleted)"
    fi
    # Single rule-matching thread: analysisd defaults to one thread PER CORE, and stateful correlation
    # (if_matched_sid / frequency) keeps its history per thread -- so correlated events landing on different
    # threads never match. The APT chain rule (100130) and the DoS/cred-stuffing frequency rules all depend
    # on this. Trade-off: lower rule throughput, irrelevant at this lab's event rate. (docs/threats/apt.md)
    if ! run_in "$p" "$i" grep -qx 'analysisd.rule_matching_threads=1' /var/ossec/etc/local_internal_options.conf 2>/dev/null; then
        run_in "$p" "$i" sh -c 'echo "analysisd.rule_matching_threads=1" >> /var/ossec/etc/local_internal_options.conf'
        run_in "$p" "$i" systemctl restart wazuh-manager
        echo "instance $i: analysisd pinned to 1 rule-matching thread (reliable correlation)"
    fi
    run_in "$p" "$i" apt-get clean        # the installer leaves ~2 GB of downloaded packages behind

    # The installer generates random passwords; keep the dashboard admin's in the git-ignored secrets file.
    if [ ! -f "$secrets" ]; then
        local pw
        pw=$(run_in "$p" "$i" tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt |
             awk '/indexer_username: .admin./ { getline; gsub(/.*: *\047|\047.*/, ""); print; exit }')
        ( umask 077; echo "WAZUH_ADMIN_PASSWORD=$pw" > "$secrets" )
        echo "secrets mgmt: dashboard password saved in $secrets"
    fi
    ensure_index_retention "$p" "$i" "$secrets"
    ensure_wazuh_dos "$p" "$i"
    echo "instance $i: wazuh ready (dashboard https://$SIEM_IP from the VM, user admin)"
}

# ensure_wazuh_dos <project> <instance>: DoS detection rules + firewall-drop active response.
# Custom rules (wazuh/local_rules.xml): 100100 = one HTTP 429, 100101 = >=30 from one IP in 60s.
# Active response: firewall-drop on the reporting agent (lb-01) for 600s. The stock ossec.conf wraps
# the active-response example in <!-- -->, so this uncomments our block (or inserts it if absent).
ensure_wazuh_dos() {
    local p=$1 i=$2
    incus file push "$REPO/wazuh/local_rules.xml" "$i/var/ossec/etc/rules/local_rules.xml" --project "$p"
    run_in "$p" "$i" chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
    run_in "$p" "$i" python3 - <<'PY'
import re
p = "/var/ossec/etc/ossec.conf"
s = open(p).read()
block = """  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100101</rules_id>
    <timeout>600</timeout>
  </active-response>"""
orig = s
# uncomment our block if the stock file wraps it in a comment
s = re.sub(r"<!--\s*(<active-response>\s*<command>firewall-drop</command>.*?<rules_id>100101</rules_id>.*?</active-response>)\s*-->",
           r"\1", s, flags=re.DOTALL)
# insert before </ossec_config> if still absent
if "<rules_id>100101</rules_id>" not in s:
    s = s.replace("</ossec_config>", block + "\n\n</ossec_config>", 1)
if s != orig:
    open(p, "w").write(s)
    print("ossec.conf: firewall-drop active response enabled")
else:
    print("ossec.conf: active response already present")
PY
    run_in "$p" "$i" systemctl restart wazuh-manager
    echo "wazuh: DoS rules (100100/100101) + firewall-drop active response applied"
}

# ensure_index_retention <project> <instance> <secrets file>
# An ISM (Index State Management) policy in the indexer: daily Wazuh indices are deleted automatically
# after RETENTION. 14 days, not 7: evidence from the first attack tests must survive until the report/demo.
# The admin password goes in a root-only curl config file inside siem-01, never on a command line.
RETENTION=14d
ensure_index_retention() {
    local p=$1 i=$2 secrets=$3 api="https://localhost:9200"
    # shellcheck disable=SC1090
    . "$secrets"
    printf 'user = "admin:%s"\n' "$WAZUH_ADMIN_PASSWORD" | run_in "$p" "$i" sh -c 'umask 077; cat > /root/.idx-curlrc'
    idx() { run_in "$p" "$i" curl -sk -K /root/.idx-curlrc -H 'Content-Type: application/json' "$@"; }
    if idx -o /dev/null -w '%{http_code}' "$api/_plugins/_ism/policies/ssle-retention" | grep -q 200; then
        echo "instance $i: index retention policy already set"
        return 0
    fi
    idx -X PUT "$api/_plugins/_ism/policies/ssle-retention" -d @- > /dev/null <<JSON
{"policy": {
  "description": "SSLE: delete Wazuh indices older than $RETENTION (generated by build.sh)",
  "default_state": "hot",
  "states": [
    {"name": "hot", "actions": [], "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "$RETENTION"}}]},
    {"name": "delete", "actions": [{"delete": {}}], "transitions": []}
  ],
  "ism_template": [{"index_patterns": ["wazuh-alerts-*", "wazuh-archives-*", "wazuh-monitoring-*", "wazuh-statistics-*"],
                    "priority": 100}]
}}
JSON
    # ism_template only covers indices created from now on; attach the policy to the ones that already exist.
    local pat
    for pat in wazuh-alerts-* wazuh-archives-* wazuh-monitoring-* wazuh-statistics-*; do
        idx -X POST "$api/_plugins/_ism/add/$pat" -d '{"policy_id": "ssle-retention"}' > /dev/null
    done
    echo "instance $i: index retention $RETENTION (ISM policy ssle-retention)"
}

# ensure_agent <project> <instance> <full DNS name>
# Version pinned to the manager's: an agent newer than its manager is rejected.
# Agent name = full DNS name, because short names repeat across sites (api-01 in avr and lis).
# Limitation: enrollment (1515) has no password, so anything that can reach 1515 could enroll a fake agent;
# only the firewall limits who can.
ensure_agent() {
    local p=$1 i=$2 fqdn=$3 ver
    incus info siem-01 > /dev/null 2>&1 || return 0
    run_in "$p" "$i" test -x /var/ossec/bin/wazuh-agentd && { echo "agent $fqdn: already installed"; return 0; }
    ver=$(run_in default siem-01 /var/ossec/bin/wazuh-control info -v | tr -d 'v')
    run_in "$p" "$i" test -x /usr/bin/gpg || apt_install "$p" "$i" gnupg
    run_in "$p" "$i" sh -c "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH |
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import > /dev/null 2>&1 &&
        chmod 644 /usr/share/keyrings/wazuh.gpg &&
        echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
            > /etc/apt/sources.list.d/wazuh.list"
    run_in "$p" "$i" apt-get -qq update
    run_in "$p" "$i" env WAZUH_MANAGER="$SIEM_IP" WAZUH_AGENT_NAME="$fqdn" DEBIAN_FRONTEND=noninteractive \
        apt-get -o DPkg::Lock::Timeout=120 -qq install -y "wazuh-agent=$ver-1" > /dev/null
    run_in "$p" "$i" apt-mark hold wazuh-agent > /dev/null      # no accidental upgrade past the manager
    run_in "$p" "$i" systemctl daemon-reload
    run_in "$p" "$i" systemctl enable --now wazuh-agent > /dev/null 2>&1
    echo "agent $fqdn: installed ($ver)"
}

# ensure_agent_localfile <project> <instance> <log_format> <location>
# Idempotently declare a log for the agent to ship to the manager, then restart the agent if it changed.
# This is separate from ensure_agent (which returns early for an already-installed agent and so never
# configures WHAT to monitor). Without this, the manager's rules never see these logs:
#   - api/analytics: the app's JSON log (/var/log/ssle/api.log) -> credential-stuffing rules (threat 2)
#   - lb: nginx access/error logs -> DoS rules (threat 1)
ensure_agent_localfile() {
    local p=$1 i=$2 fmt=$3 loc=$4 changed
    incus info siem-01 > /dev/null 2>&1 || return 0
    run_in "$p" "$i" test -x /var/ossec/bin/wazuh-agentd || return 0
    changed=$(run_in "$p" "$i" env LOC="$loc" FMT="$fmt" python3 -I - <<'PY'
import os
p = "/var/ossec/etc/ossec.conf"; loc = os.environ["LOC"]; fmt = os.environ["FMT"]
s = open(p).read()
if f"<location>{loc}</location>" in s:          # already declared: leave it (and other sites' lines)
    raise SystemExit(0)
block = f"  <localfile>\n    <log_format>{fmt}</log_format>\n    <location>{loc}</location>\n  </localfile>\n"
open(p, "w").write(s.replace("</ossec_config>", block + "\n</ossec_config>", 1))
print("added")
PY
)
    if [ "$changed" = added ]; then
        run_in "$p" "$i" systemctl restart wazuh-agent
        echo "agent $i: now shipping $loc ($fmt)"
    fi
}

# ensure_site_agents <site>: an agent on every instance of the site (if siem-01 exists), each shipping
# the logs its role produces so the manager's rules have something to match.
ensure_site_agents() {
    local site=$1 region inst role
    incus info siem-01 > /dev/null 2>&1 || { echo "wazuh: siem-01 not built yet, no agents for $site"; return 0; }
    read -r region _ _ < <(site_info "$site")
    while read -r inst role <&3; do
        ensure_agent "$site" "$inst" "$inst.$site.$region.ssle"
        case $role in
            api|analytics) ensure_agent_localfile "$site" "$inst" json   /var/log/ssle/api.log ;;
            lb)            ensure_agent_localfile "$site" "$inst" apache /var/log/nginx/access.log
                           ensure_agent_localfile "$site" "$inst" apache /var/log/nginx/error.log ;;
        esac
    done 3< <(awk -v s="$site" '$1 == s { print $2, $3 }' "$INSTANCES_CONF")
}

provision_client() {
    local p=$1 i=$2
    run_in "$p" "$i" test -x /usr/bin/curl || { run_in "$p" "$i" apt-get -qq update; apt_install "$p" "$i" curl; }
    echo "instance $i: client ready"
}

# The adversary: curl for probing, plus the load tool used to generate the DoS flood against lb-01.
# (Load tool chosen in the DoS threat section; added here once decided.)
provision_attacker() {
    local p=$1 i=$2
    run_in "$p" "$i" test -x /usr/bin/curl \
        || { run_in "$p" "$i" apt-get -qq update; apt_install "$p" "$i" curl; }
    # ab (apache2-utils): generates the DoS load and reports throughput + latency percentiles.
    run_in "$p" "$i" test -x /usr/bin/ab || apt_install "$p" "$i" apache2-utils
    echo "instance $i: attacker ready"
}

# --- Firewall: Incus network ACLs, deny by default --------------------------------------------------
# One ACL per role and site (acl-<site>-<role>), attached to the instances' network cards. Anything not
# allowed here is dropped (incoming) or rejected (outgoing), and logged: a blocked attempt is itself a
# detection signal (e.g. a compromised api-01 trying to reach lb-01).
# Rules use IPs because bridge ACLs can't match "instances that have ACL x" (tested: "Unsupported
# nftables subject"). Replies to allowed connections pass automatically (the rules are stateful).

# ips_of <site> <role>...: comma-separated fixed IPs of the site's instances with those roles
ips_of() {
    local site=$1 prefix; shift
    read -r _ prefix _ < <(site_info "$site")
    awk -v s="$site" -v p="$prefix" -v roles=" $* " \
        '$1 == s && index(roles, " " $3 " ") { printf "%s%s.%s", sep, p, $4; sep = "," }' "$INSTANCES_CONF"
}

# acl_rule <ingress|egress> <protocol> <peers|any> <port(s)> <description>  -> one YAML rule
# Peers empty = the role doesn't exist (yet) in this site = no rule.
acl_rule() {
    local dir=$1 proto=$2 peers=$3 port=$4 desc=$5 key=destination
    [ -n "$peers" ] || return 0
    [ "$dir" = ingress ] && key=source
    echo "- action: allow"
    echo "  state: enabled"
    echo "  protocol: $proto"
    [ "$peers" = any ] || echo "  $key: $peers"
    echo "  destination_port: \"$port\""
    echo "  description: \"$desc\""
}

# acl_yaml <site> <role>: the call graph (docs/architecture.md) written as rules
acl_yaml() {
    local site=$1 role=$2 prefix gw lb backends db prom prom_site
    read -r _ prefix _ < <(site_info "$site")
    gw=$prefix.1
    lb=$(ips_of "$site" lb); backends=$(ips_of "$site" api analytics); db=$(ips_of "$site" db)
    prom_site=$(ips_of "$site" prom)                         # the site's own Prometheus (lis), if any
    prom=$PROM_IP${prom_site:+,$prom_site}

    echo "description: deny by default; $role in $site (generated by build.sh, edits are overwritten)"
    echo "ingress:"
    case $role in
        lb)            acl_rule ingress tcp "$INET_SUBNET" 80   "clients (inet) -> nginx" ;;
        api|analytics) acl_rule ingress tcp "$lb"          5000 "lb -> app"
                       acl_rule ingress tcp "$prom"        9102 "prometheus -> app /metrics" ;;
        db)            acl_rule ingress tcp "$backends"    5432 "api, analytics -> postgres" ;;
        prom)          acl_rule ingress tcp "$PROM_IP"     9090 "central prom -> /federate" ;;
    esac
    echo "egress:"
    case $role in
        lb)            acl_rule egress tcp "$backends" 5000 "nginx -> api, analytics" ;;
        api|analytics) acl_rule egress tcp "$db"       5432 "app -> postgres" ;;
        prom)          acl_rule egress tcp "$backends" 9102 "scrape site app /metrics"
                       acl_rule egress tcp "$gw"       9101 "scrape host exporter (site bridge)" ;;
    esac
    # Flows every instance needs (deny by default would silently break them):
    acl_rule egress udp "$gw"      53        "DNS (site dnsmasq)"
    acl_rule egress tcp "$gw"      53        "DNS over TCP (large answers)"
    acl_rule egress tcp "$SIEM_IP" 1514,1515 "wazuh agent -> manager (events, enrollment)"
    # Limitation: apt needs the internet, so web traffic out is allowed to ANY address. That's also an
    # exfiltration path for an APT. Internal targets are still protected by their own ingress rules.
    # Better: an apt proxy (allow only it), or remove this rule after the build.
    acl_rule egress tcp any        80,443    "apt updates (any address)"
}

# ensure_acls <site>: (re)writes each role's ACL and attaches it to the site's instances
ensure_acls() {
    local site=$1 inst role nic acl
    for role in $(awk -v s="$site" '$1 == s { print $3 }' "$INSTANCES_CONF" | sort -u); do
        acl=acl-$site-$role
        incus network acl show "$acl" > /dev/null 2>&1 || incus network acl create "$acl" > /dev/null
        acl_yaml "$site" "$role" | incus network acl edit "$acl"   # replaces all rules: no stale ones
        echo "firewall: $acl written"
    done
    while read -r inst role <&3; do
        for nic in $(incus config device list "$inst" --project "$site"); do
            # Only network cards take ACLs: an instance created with --storage also has an instance-level
            # "root" disk device, and security.acls is invalid on a disk (it would fail the whole build).
            [ "$(incus config device get "$inst" "$nic" type --project "$site")" = nic ] || continue
            incus config device set "$inst" "$nic" --project "$site" security.acls="acl-$site-$role" \
                security.acls.default.ingress.action=drop security.acls.default.egress.action=reject \
                security.acls.default.ingress.logged=true security.acls.default.egress.logged=true
        done
        echo "firewall: $inst -> acl-$site-$role"
    done 3< <(awk -v s="$site" '$1 == s { print $2, $3 }' "$INSTANCES_CONF")
}

core() {
    ensure_network ssle-mgmt ipv4.address=$MGMT_DNS/24 ipv4.nat=true ipv6.address=none dns.domain=ssle
    ensure_network inet ipv4.address=192.168.100.1/24 ipv4.nat=true ipv6.address=none dns.domain=inet
    # .2-.99 fixed addresses, .100-.254 DHCP: a dynamic lease can never take a fixed address.
    ensure_network_key ssle-mgmt ipv4.dhcp.ranges 10.10.0.100-10.10.0.254
    ensure_network_key inet ipv4.dhcp.ranges 192.168.100.100-192.168.100.254
    # Outside actors live in the default project (they belong to no site).
    ensure_instance default client-01 inet "$CLIENT_IP"
    provision_client default client-01
    # Outside adversary, same base image as the legitimate client (only curl); the DoS load tool is
    # installed by provision_attacker (see docs/architecture.md, the DoS threat section).
    ensure_instance default attacker-01 inet "$ATTACKER_IP"
    provision_attacker default attacker-01
    # Botnet nodes for the credential-stuffing threat (threat 2): extra outside sources so the spray can
    # be DISTRIBUTED. Each stays under every per-source control (the nginx rate limit, the Wazuh per-src
    # correlation 100111, a firewall-drop block) while the AGGREGATE no_user rate still trips the
    # Prometheus alert -- which is exactly why the response is account lockout + aggregate alert, not a
    # per-IP block. .67/.68 continue the attacker range after attacker-01 (.66).
    local bot
    for bot in 02:67 03:68; do
        ensure_instance default "attacker-${bot%%:*}" inet "192.168.100.${bot##*:}"
        provision_attacker default "attacker-${bot%%:*}"
    done

    ensure_wazuh_pool
    ensure_instance default siem-01 ssle-mgmt "$SIEM_IP" "" wazuh
    provision_siem default siem-01

    provision_host_exporter          # on the VM itself; must be up before prom scrapes :9101
    provision_host_agent             # host Wazuh agent: ships kernel firewall-drop logs (APT signal)
    ensure_instance default prom-01 ssle-mgmt "$PROM_IP"
    provision_prom default prom-01
    ensure_agent default prom-01 prom-01.ssle
    local site
    for site in $(awk '!/^#/ && NF { print $1 }' "$SITES_CONF"); do
        incus project show "$site" > /dev/null 2>&1 || continue                      # site not built yet
        register_prom_targets "$site"
        ensure_site_agents "$site"
    done
    ensure_mgmt_acls
}

site() {
    local name=$1 region prefix public domain
    read -r region prefix public < <(site_info "$name") || exit 1
    domain=$name.$region.ssle

    ensure_network "ssle-$name" ipv4.address="$prefix.1/24" ipv4.nat=true ipv6.address=none dns.domain="$domain"
    ensure_network_key "ssle-$name" ipv4.dhcp.ranges "$prefix.100-$prefix.254"
    ensure_project "$name"

    # Delegation, both directions (see docs/architecture.md, "DNS delegation"):
    ensure_dnsmasq_line ssle-mgmt "server=/$domain/$prefix.1"     # mgmt asks the site about its zone
    ensure_dnsmasq_line "ssle-$name" "server=/ssle/$MGMT_DNS"     # the site asks mgmt about the rest

    ensure_secrets "$name"
    local inst role host owner
    while read -r inst role host owner <&3; do
        ensure_instance "$name" "$inst" "ssle-$name" "$prefix.$host" "$owner"
        case $role in
            db)   provision_db        "$name" "$inst" "$prefix.0/24" ;;
            api)  provision_api       "$name" "$inst" "$domain" ;;
            lb)   provision_lb        "$name" "$inst" "$name" "$domain" "$public" ;;
            prom) provision_site_prom "$name" "$inst" "$domain" "$prefix" ;;
            *)    echo "instance $inst: role '$role' not written yet, skipped" >&2 ;;
        esac
    done 3< <(awk -v s="$name" '$1 == s { print $2, $3, $4, $5 }' "$INSTANCES_CONF")
    # The list is read from fd 3, not stdin: incus exec inside the loop reads stdin and would
    # otherwise swallow the remaining lines (only the first instance would be built).

    # Last: the firewall, once every instance and its address exist; then tell mgmt about this site.
    ensure_acls "$name"
    register_prom_targets "$name"
    ensure_mgmt_acls
    ensure_site_agents "$name"
}

case "${1:-}" in
    core) core ;;
    site) [ -n "${2:-}" ] || { echo "usage: $0 site <name>" >&2; exit 1; }
          site "$2" ;;
    host-exporter) provision_host_exporter ;;   # just the VM exporter (prompts once for sudo)
    host-agent)    provision_host_agent ;;      # just the VM's Wazuh agent (prompts once for sudo)
    *)    echo "usage: $0 core | site <name> | host-exporter | host-agent" >&2; exit 1 ;;
esac
