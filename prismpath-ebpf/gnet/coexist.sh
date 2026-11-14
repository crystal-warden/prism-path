#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# coexist.sh: measure that the governed net XDP program leaves the shared LAN alone.
#
# It does nothing heavier than ping, plus a read-only read of the program's per-verdict counters. Run it
# ONCE with the program detached and ONCE with it attached (SETUP.md, "coexistence check"), from a host on
# the LAN (the Mac, or the firewall), and compare: the ping RTTs to the firewall and to the tool server
# should be unchanged, and when attached the counters show how much traffic passed untouched (other)
# against how much was the agent protocol (allow/drop/malformed).
#
#   coexist.sh <ping-target> [<ping-target> ...]            just the RTTs (detached baseline)
#   MAPS_DIR=/sys/fs/bpf/tc/globals coexist.sh <target> ...        RTTs + counters (attached; reads the pinned maps)
#
# MAPS_DIR, when set, must be the bpffs directory iproute2 pinned the maps under; reading the counters
# needs the gn_loader.py in this directory and python3. It only READS; it changes nothing.
set -eu

COUNT="${COUNT:-10}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$#" -lt 1 ]; then
    echo "usage: [MAPS_DIR=/sys/fs/bpf/tc/globals] [COUNT=10] $0 <ping-target> [<ping-target> ...]" >&2
    exit 2
fi

echo "== ping RTT ($COUNT each) =="
for target in "$@"; do
    # -c COUNT pings; the summary line carries min/avg/max on both Linux and macOS
    if out=$(ping -c "$COUNT" "$target" 2>/dev/null); then
        line=$(printf '%s\n' "$out" | grep -E 'min/avg/max|round-trip' | head -1)
        printf '  %-18s %s\n' "$target" "${line:-<no summary>}"
    else
        printf '  %-18s %s\n' "$target" "<unreachable>"
    fi
done

if [ "${MAPS_DIR:-}" != "" ]; then
    echo "== governed net counters (other allow drop malformed) =="
    if [ -e "$MAPS_DIR/gn_counts_map" ]; then
        python3 "$HERE/gn_loader.py" stats --maps-dir "$MAPS_DIR"
    else
        echo "  no pinned maps at $MAPS_DIR (is the program attached with the pinned object?)" >&2
    fi
else
    echo "(set MAPS_DIR=/sys/fs/bpf/tc/globals to also read the counters when the program is attached)"
fi
