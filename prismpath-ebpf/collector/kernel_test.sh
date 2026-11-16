#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# The collector in a real kernel, deployed the way README.md says: CI's ebpf_kernel job runs this as root
# on a throwaway runner (sudo -E env "PATH=$PATH" bash prismpath-ebpf/collector/kernel_test.sh), after
# `make -C prismpath-ebpf` and `cargo build --release` in this directory. It attaches the governed net
# program to lo in generic XDP mode through iproute2 (which pins its maps under /sys/fs/bpf/tc/globals),
# fills it with the network policy for 127.0.0.1, does the README's one time setup (groups, account, pin
# permissions), starts the collector under the shipped systemd unit, and checks
#   * the running collector holds CAP_BPF alone (effective and permitted), no inheritable or ambient
#     capability, and no_new_privs;
#   * the binary refuses to start as root;
#   * kernel_check.py, as the invoking account in the feed group only, gets every decision it caused;
#   * the enforcer's maps are as the loader left them (the collector wrote none of them).
# It undoes all of it on exit.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PINS=/sys/fs/bpf/tc/globals
BIN="$HERE/target/release/prismpath-collector"
CLIENT="${SUDO_USER:?run this through sudo from the account that will read the feed}"
BUILD="$(mktemp -d)"
[ "$(id -u)" -eq 0 ] || { echo "kernel_test.sh needs root (a throwaway CI runner)"; exit 2; }
[ -x "$BIN" ] || { echo "build the collector first: cargo build --release --manifest-path $HERE/Cargo.toml"; exit 2; }

cleanup() {
    set +e
    systemctl stop prismpath-collector 2>/dev/null
    journalctl -u prismpath-collector --no-pager -o cat 2>/dev/null | tail -20
    ip link set dev lo xdpgeneric off 2>/dev/null
    for map in gn_config_map gn_action_map gn_counts_map gn_events atoms_map nodes_map edges_map prog_map regs_map; do
        rm -f "$PINS/$map"
    done
    rm -rf "$BUILD"
}
trap cleanup EXIT

cd "$REPO"
python3 -m integrations.governed_net.policy "$BUILD" >/dev/null
ip link set dev lo xdpgeneric obj prismpath-ebpf/gnet/gn_xdp.pin.bpf.o sec xdp
python3 prismpath-ebpf/gnet/gn_loader.py fill --maps-dir "$PINS" --table "$BUILD/net_rules.ppt" \
    --actions "$BUILD/net_rules.actions" --server-ip 127.0.0.1 --port 47011
config_before="$(python3 - "$PINS" <<'EOF'
import sys
sys.path.insert(0, "prismpath-ebpf/gnet")
import gn_loader
bpf = gn_loader.Bpf()
fd = bpf.obj_get(sys.argv[1] + "/gn_config_map")
print(bpf.map_lookup(fd, gn_loader._u32(0), gn_loader.CONFIG.size).hex())
EOF
)"

# README "Deploying": the account and its groups, and pin permissions that let the account open three pins
getent group prismpath-collector >/dev/null || groupadd --system prismpath-collector
getent group prismpath-feed >/dev/null || groupadd --system prismpath-feed
id prismpath-collector >/dev/null 2>&1 || useradd --system --gid prismpath-collector --no-create-home --shell /usr/sbin/nologin prismpath-collector
for dir in /sys/fs/bpf /sys/fs/bpf/tc "$PINS"; do chgrp prismpath-collector "$dir"; chmod g+x "$dir"; done
chgrp prismpath-collector "$PINS/gn_events" "$PINS/gn_config_map" "$PINS/gn_counts_map"
chmod 0660 "$PINS/gn_events"
chmod 0640 "$PINS/gn_config_map" "$PINS/gn_counts_map"
install -m 0755 "$BIN" /usr/local/bin/prismpath-collector
install -m 0644 "$HERE/prismpath-collector.service" /etc/systemd/system/prismpath-collector.service
echo "COLLECTOR_ARGS=--source gnet --maps-dir $PINS --socket-group prismpath-feed --allow-uid $(id -u "$CLIENT") --seal-interval-ms 200" \
    > /etc/default/prismpath-collector
systemctl daemon-reload
systemctl start prismpath-collector

SOCKET=/run/prismpath-collector/feed.sock
for _ in $(seq 100); do [ -S "$SOCKET" ] && break; sleep 0.1; done
[ -S "$SOCKET" ] || { echo "FAIL the feed socket never appeared"; systemctl status prismpath-collector --no-pager; exit 1; }
stat -c '%a %G %n' "$SOCKET"
[ "$(stat -c '%a %G' "$SOCKET")" = "660 prismpath-feed" ] || { echo "FAIL the socket is not 0660 prismpath-feed"; exit 1; }

PID="$(systemctl show -p MainPID --value prismpath-collector)"
grep -E '^(Cap(Inh|Prm|Eff|Amb)|NoNewPrivs):' "/proc/$PID/status"
expect() { grep -q "^$1:[[:space:]]*$2\$" "/proc/$PID/status" || { echo "FAIL $1 is not $2"; exit 1; }; }
expect CapEff 0000008000000000
expect CapPrm 0000008000000000
expect CapInh 0000000000000000
expect CapAmb 0000000000000000
expect NoNewPrivs 1
echo "ok the running collector holds cap_bpf alone, nothing inheritable or ambient, no_new_privs"

if /usr/local/bin/prismpath-collector --source gnet --maps-dir "$PINS" --socket "$BUILD/root.sock" 2>"$BUILD/root.err"; then
    echo "FAIL the collector started as root"; exit 1
fi
grep -q "does not run as root" "$BUILD/root.err" && echo "ok the collector refuses to run as root"

# the reader: the invoking account with the feed group as its only group, no capability
setpriv --reuid="$(id -u "$CLIENT")" --regid="$(getent group prismpath-feed | cut -d: -f3)" --clear-groups --inh-caps=-all \
    python3 "$HERE/kernel_check.py" --socket "$SOCKET"

config_after="$(python3 - "$PINS" <<'EOF'
import sys
sys.path.insert(0, "prismpath-ebpf/gnet")
import gn_loader
bpf = gn_loader.Bpf()
fd = bpf.obj_get(sys.argv[1] + "/gn_config_map")
print(bpf.map_lookup(fd, gn_loader._u32(0), gn_loader.CONFIG.size).hex())
EOF
)"
[ "$config_before" = "$config_after" ] || { echo "FAIL the configuration map changed: $config_before -> $config_after"; exit 1; }
echo "ok the enforcer's configuration is as the loader left it"
systemctl stop prismpath-collector
journalctl -u prismpath-collector --no-pager -o cat | grep -q "Stopped after" && echo "ok a stop ends with a final seal"
echo "PASS collector kernel test"
