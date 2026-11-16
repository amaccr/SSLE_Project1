#!/usr/bin/env bash
# Builds the SSLE lab on Incus.
#   ./scripts/build.sh core        mgmt + inet networks and their instances (run once)
#   ./scripts/build.sh site avr    one site: its network, project and instances
# Safe to run again: anything that already exists is left as it is (idempotent).
set -euo pipefail

MGMT_DNS=10.10.0.1

REPO=$(dirname "$(realpath "$0")")/..
IMAGE=images:ubuntu/22.04

# The sites live in config/sites.conf (the only place that knows which sites exist),
# their instances in config/instances.conf.
SITES_CONF=$REPO/config/sites.conf
INSTANCES_CONF=$REPO/config/instances.conf

# site_info <name>: prints "<region> <subnet prefix>" from sites.conf, fails if the site isn't listed.
site_info() {
    awk -v s="$1" '$1 == s { print $2, $3; found = 1 } END { exit !found }' "$SITES_CONF" \
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

# ensure_instance <project> <name> <network> [owner]
# Launches the container if it doesn't exist, and waits until it has working DNS + internet (apt needs it).
# user.owner is set on every run, so a hand-made change is put back to what the config says (drift).
ensure_instance() {
    local project=$1 inst=$2 net=$3 owner=${4:-}
    if incus info "$inst" --project "$project" > /dev/null 2>&1; then
        echo "instance $inst: already exists"
    else
        incus launch "$IMAGE" "$inst" --project "$project" --network "$net" > /dev/null
        echo "instance $inst: launched"
    fi
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

core() {
    ensure_network ssle-mgmt ipv4.address=$MGMT_DNS/24 ipv4.nat=true ipv6.address=none dns.domain=ssle
    ensure_network inet ipv4.address=192.168.100.1/24 ipv4.nat=true ipv6.address=none dns.domain=inet
}

site() {
    local name=$1 region prefix domain
    read -r region prefix < <(site_info "$name") || exit 1
    domain=$name.$region.ssle

    ensure_network "ssle-$name" ipv4.address="$prefix.1/24" ipv4.nat=true ipv6.address=none dns.domain="$domain"
    ensure_project "$name"

    # Delegation, both directions (see docs/architecture.md, "DNS delegation"):
    ensure_dnsmasq_line ssle-mgmt "server=/$domain/$prefix.1"     # mgmt asks the site about its zone
    ensure_dnsmasq_line "ssle-$name" "server=/ssle/$MGMT_DNS"     # the site asks mgmt about the rest

    ensure_secrets "$name"
    local inst role owner
    while read -r inst role owner <&3; do
        ensure_instance "$name" "$inst" "ssle-$name" "$owner"
        case $role in
            db)  provision_db  "$name" "$inst" "$prefix.0/24" ;;
            api) provision_api "$name" "$inst" "$domain" ;;
            *)   echo "instance $inst: role '$role' not written yet, skipped" >&2 ;;
        esac
    done 3< <(awk -v s="$name" '$1 == s { print $2, $3, $4 }' "$INSTANCES_CONF")
    # The list is read from fd 3, not stdin: incus exec inside the loop reads stdin and would
    # otherwise swallow the remaining lines (only the first instance would be built).
}

case "${1:-}" in
    core) core ;;
    site) [ -n "${2:-}" ] || { echo "usage: $0 site <name>" >&2; exit 1; }
          site "$2" ;;
    *)    echo "usage: $0 core | site <name>" >&2; exit 1 ;;
esac
