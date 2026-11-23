#!/usr/bin/env bash
# Provision a Wazuh agent on the VM HOST (h01), so the host's kernel firewall-drop logs reach the SIEM.
#
# Why an agent on the host (and not just the containers): the APT's two network signals are only visible
# on the host. (1) Blocked lateral recon -- the Incus bridge ACLs drop it and the kernel logs it with the
# "eth0-egress " prefix. (2) C2 / exfil egress -- a backend reaching the external actor network; the
# firewall ALLOWS it, so our own nft rule (config/ssle_ids.nft) logs it with the "SSLE-C2 " prefix. Both
# land in the HOST's journald, which no container can see. The manager correlates the two (rule 100130).
# See docs/architecture.md "Firewall" and docs/threats/apt.md.
#
# This is host-level work, so (like provision_host_exporter in build.sh) it needs root. It is idempotent:
# re-running only reconciles the manager address and the journald localfile.
#
# Usage:  sudo scripts/provision_host_agent.sh [VERSION]
#   VERSION defaults to 4.14.10 (match the manager). build.sh passes the manager's live version.
set -euo pipefail

VER="${1:-4.14.10}"
MANAGER="${WAZUH_MANAGER:-10.10.0.20}"     # siem-01.ssle
NAME="${WAZUH_AGENT_NAME:-h01.ssle}"       # the physical host, org-level asset (docs/naming.md)

[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0 $*" >&2; exit 1; }

# Host IDS nft rule: logs the backend->external C2 egress the firewall allows (the "new outbound not in the
# call graph" APT signal). Idempotent via the file's own delete-table guard.
# Persistent across reboots: the file is installed in /etc/ssle/nft/ and the ssle-nft oneshot unit loads
# every file there at boot. Without this, a reboot silently removes the C2 leg (100123), so the APT chain
# alert 100130 can never fire. The same unit also restores build.sh's ssle_exporter table.
IDS="$(dirname "$(realpath "$0")")/../config/ssle_ids.nft"
if [ -f "$IDS" ]; then
    install -D -m 644 "$IDS" /etc/ssle/nft/ssle_ids.nft
    /usr/sbin/nft -f /etc/ssle/nft/ssle_ids.nft && echo "host IDS nft rule loaded (/etc/ssle/nft/ssle_ids.nft)"
fi
# After nftables.service: Debian's own unit flushes the whole ruleset when it starts.
cat > /etc/systemd/system/ssle-nft.service <<'UNIT'
[Unit]
Description=SSLE host nft tables (IDS C2 log, exporter firewall)
After=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'for f in /etc/ssle/nft/*.nft; do [ -f "$f" ] && /usr/sbin/nft -f "$f"; done; true'

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable ssle-nft.service >/dev/null 2>&1

if [ ! -x /var/ossec/bin/wazuh-agentd ]; then
    echo "installing wazuh-agent $VER on the host as $NAME -> $MANAGER"
    command -v gpg >/dev/null || { apt-get -qq update; apt-get -qq install -y gnupg; }
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH |
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
        > /etc/apt/sources.list.d/wazuh.list
    apt-get -qq update
    WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$NAME" DEBIAN_FRONTEND=noninteractive \
        apt-get -o DPkg::Lock::Timeout=120 -qq install -y "wazuh-agent=$VER-1"
    apt-mark hold wazuh-agent >/dev/null     # never upgrade past the manager
else
    echo "wazuh-agent already installed; reconciling config"
    sed -i "0,/<address>.*<\/address>/s//<address>$MANAGER<\/address>/" /var/ossec/etc/ossec.conf || true
fi

# Ship the two APT network signals from journald. Authoritative: strip any existing journald localfile
# (ours or the stock one) so there is exactly ONE, with no merge ambiguity. Filters (AND):
#   1. MESSAGE matches "eth0-egress " (blocked lateral recon) OR "SSLE-C2 " (external C2 egress)
#   2. MESSAGE matches "PROTO=TCP"  -- drops all the routine DHCP noise (UDP) at the source
# So the manager only ever sees genuinely blocked recon or a backend calling the external network, both
# parsed by Wazuh's built-in kernel decoder (rule 4100 -> 100122 / 100123, correlated by 100130).
python3 - <<'PY'
import re
p = "/var/ossec/etc/ossec.conf"; s = open(p).read()
s = re.sub(r"[ \t]*<localfile>(?:(?!</localfile>).)*?<location>journald</location>.*?</localfile>\n?",
           "", s, flags=re.S)
block = ('  <localfile>\n'
         '    <log_format>journald</log_format>\n'
         '    <location>journald</location>\n'
         '    <filter field="MESSAGE">eth0-egress |SSLE-C2 </filter>\n'
         '    <filter field="MESSAGE">PROTO=TCP</filter>\n'
         '  </localfile>\n')
open(p, "w").write(s.replace("</ossec_config>", block + "\n</ossec_config>", 1))
print("journald localfile reconciled (recon + C2, TCP only)")
PY

# wazuh-logcollector runs as root and can read the journal, but add the group defensively in case a
# future build runs it unprivileged.
getent group systemd-journal >/dev/null && usermod -aG systemd-journal wazuh 2>/dev/null || true

systemctl daemon-reload
systemctl enable --now wazuh-agent >/dev/null 2>&1
systemctl restart wazuh-agent
echo "host agent provisioned: $NAME -> $MANAGER (v$VER)"
