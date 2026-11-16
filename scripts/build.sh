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

# ensure_instance <project> <name> <network> <fixed address> [owner]
# Creates the container if it doesn't exist, pins its address, and waits until it has working DNS +
# internet (apt needs it). user.owner is set on every run, so a hand-made change is put back to what the
# config says (drift).
ensure_instance() {
    local project=$1 inst=$2 net=$3 addr=$4 owner=${5:-} new=
    if incus info "$inst" --project "$project" > /dev/null 2>&1; then
        echo "instance $inst: already exists"
    else
        incus create "$IMAGE" "$inst" --project "$project" --network "$net" > /dev/null
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

    # Backends = every api instance of this site in instances.conf (adding api-0N = one line there).
    # Limitation: nginx resolves these names when it (re)loads, so a rebuilt api with a new IP needs a
    # reload; re-running this script does that.
    local servers
    servers=$(awk -v s="$site" -v d="$domain" '$1 == s && $3 == "api" { printf "    server %s.%s:5000;\n", $2, d }' \
        "$INSTANCES_CONF")
    run_in "$p" "$i" sh -c 'cat > /etc/nginx/sites-available/ssle' <<NGINX
upstream ssle_api {
$servers
}

server {
    listen 80 default_server;
    server_name _;
    server_tokens off;                                  # don't advertise the nginx version

    location / {
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

provision_client() {
    local p=$1 i=$2
    run_in "$p" "$i" test -x /usr/bin/curl || { run_in "$p" "$i" apt-get -qq update; apt_install "$p" "$i" curl; }
    echo "instance $i: client ready"
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
    esac
    echo "egress:"
    case $role in
        lb)            acl_rule egress tcp "$backends" 5000 "nginx -> api, analytics" ;;
        api|analytics) acl_rule egress tcp "$db"       5432 "app -> postgres" ;;
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
            db)  provision_db  "$name" "$inst" "$prefix.0/24" ;;
            api) provision_api "$name" "$inst" "$domain" ;;
            lb)  provision_lb  "$name" "$inst" "$name" "$domain" "$public" ;;
            *)   echo "instance $inst: role '$role' not written yet, skipped" >&2 ;;
        esac
    done 3< <(awk -v s="$name" '$1 == s { print $2, $3, $4, $5 }' "$INSTANCES_CONF")
    # The list is read from fd 3, not stdin: incus exec inside the loop reads stdin and would
    # otherwise swallow the remaining lines (only the first instance would be built).

    # Last: the firewall, once every instance and its address exist.
    ensure_acls "$name"
}

case "${1:-}" in
    core) core ;;
    site) [ -n "${2:-}" ] || { echo "usage: $0 site <name>" >&2; exit 1; }
          site "$2" ;;
    *)    echo "usage: $0 core | site <name>" >&2; exit 1 ;;
esac
