#!/usr/bin/env bash
# Builds the SSLE lab on Incus.
#   ./scripts/build.sh core        mgmt + inet networks and their instances (run once)
#   ./scripts/build.sh site avr    one site: its network, project and instances
# Safe to run again: anything that already exists is left as it is (idempotent).
set -euo pipefail

MGMT_DNS=10.10.0.1

# The sites live in config/sites.conf (the only place that knows which sites exist).
SITES_CONF=$(dirname "$(realpath "$0")")/../config/sites.conf

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

    # TODO: launch the site's instances (after the apps exist)
}

case "${1:-}" in
    core) core ;;
    site) [ -n "${2:-}" ] || { echo "usage: $0 site <name>" >&2; exit 1; }
          site "$2" ;;
    *)    echo "usage: $0 core | site <name>" >&2; exit 1 ;;
esac
