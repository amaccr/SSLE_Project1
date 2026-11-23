#!/usr/bin/env bash
# Measure the monitoring bandwidth each site sends toward the central Prometheus (prom-01.ssle, 10.10.0.10),
# to turn the bandwidth-optimisation bonus into measured bytes/min instead of a claim (docs/report.md 6.3).
#
# WHAT IT MEASURES, and why it is a fair read of the FEDERATION pattern:
#   The central prom only ever talks to a site to collect its metrics, so counting bytes between a site's
#   subnet and 10.10.0.10 isolates monitoring traffic exactly. The two collection patterns then show up as:
#     - avr (DIRECTLY scraped):  central pulls each app /metrics across the link  -> avr -> prom carries
#       every target's full exposition, N times per minute.
#     - lis (FEDERATED):         central makes ONE /federate pull from prom-01.lis -> lis -> prom carries a
#       single summarised payload; lis's own prom scraping its host exporter and app stays WITHIN lis and
#       never crosses to the centre (that intra-site traffic is the bandwidth federation keeps off the link).
#   The host-exporter scrape (central -> 10.10.0.1:9101) is host-local (mgmt<->mgmt) and so is not counted
#   against any site, which is correct: it does not cross a site boundary.
#
# HONEST LIMITATION (already stated in the report): both sites are bridges on ONE VM, so this measures the
# PATTERN, not a real-WAN figure. It also depends on each site's target COUNT, not only the pattern, so read
# it as "a federated site crosses the link once per interval regardless of how many targets it has".
#
# Uses a separate nft table (ssle_meter) with policy accept, so it only COUNTS and can never drop traffic.
# Run as root (nft needs it):   sudo scripts/measure_bandwidth.sh [--window SECONDS] [--clean]
set -euo pipefail

WINDOW=120
CLEAN=0
while [ $# -gt 0 ]; do
    case $1 in
        --window) WINDOW=$2; shift 2 ;;
        --clean)  CLEAN=1; shift ;;
        *) echo "usage: $0 [--window SECONDS] [--clean]" >&2; exit 1 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0 $*" >&2; exit 1; }
command -v nft > /dev/null || { echo "nft not found" >&2; exit 1; }

REPO=$(dirname "$(realpath "$0")")/..
SITES_CONF=$REPO/config/sites.conf
PROM_IP=10.10.0.10          # prom-01.ssle (keep in sync with build.sh)

# One named counter per site per direction, and a forward-hook rule that matches that direction.
# <site>_tx = bytes the site sends TO the central prom (the figure the report wants).
sites=$(awk '!/^#/ && NF { print $1 }' "$SITES_CONF")
counters="" rules=""
for s in $sites; do
    prefix=$(awk -v s="$s" '$1 == s { print $3 }' "$SITES_CONF")
    counters="$counters    counter ${s}_tx { }
    counter ${s}_rx { }
"
    rules="$rules        ip saddr $prefix.0/24 ip daddr $PROM_IP counter name ${s}_tx
        ip saddr $PROM_IP ip daddr $prefix.0/24 counter name ${s}_rx
"
done

nft -f - <<NFT
table inet ssle_meter
delete table inet ssle_meter
table inet ssle_meter {
$counters    chain bw {
        type filter hook forward priority -150; policy accept;
$rules    }
}
NFT

if [ "$CLEAN" = 1 ]; then
    nft delete table inet ssle_meter
    echo "ssle_meter removed"
    exit 0
fi

# Reset to zero, let real monitoring traffic accumulate for the window, then read.
for s in $sites; do nft reset counter inet ssle_meter "${s}_tx" > /dev/null
                    nft reset counter inet ssle_meter "${s}_rx" > /dev/null; done
echo "measuring monitoring traffic to prom-01.ssle ($PROM_IP) for ${WINDOW}s ..."
sleep "$WINDOW"

printf '\n%-6s  %-10s  %12s  %12s  %10s\n' site pattern "bytes->prom" "bytes/min" "pkts->prom"
printf '%-6s  %-10s  %12s  %12s  %10s\n' ------ ---------- ------------ ------------ ----------
for s in $sites; do
    # a site with its own prom instance is federated; otherwise it is scraped directly
    if awk -v s="$s" '$1 == s && $3 == "prom" { f = 1 } END { exit !f }' "$REPO/config/instances.conf"; then
        pattern=federated
    else
        pattern=direct
    fi
    read -r bytes pkts < <(nft -j list counter inet ssle_meter "${s}_tx" |
        python3 -I -c 'import json,sys; c=json.load(sys.stdin)["nftables"][1]["counter"]; print(c["bytes"], c["packets"])')
    printf '%-6s  %-10s  %12d  %12.0f  %10d\n' "$s" "$pattern" "$bytes" "$(echo "$bytes * 60 / $WINDOW" | bc)" "$pkts"
done
echo
echo "('federated' crosses the link once per scrape interval as one /federate payload; 'direct' crosses"
echo " once per target per interval. Re-run with --clean to remove the counters.)"
