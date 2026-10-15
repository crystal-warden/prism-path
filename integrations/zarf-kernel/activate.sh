#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# Activation: load the policy the host accepted into the in-kernel evaluator and show the kernel decides
# with it. The file loaded is the host's own copy, <deployed>/state/active.ppt, and it is hashed and
# compared with what the host attests is active before anything reaches the kernel; a mismatch refuses
# and the kernel is never touched. The kernel's path for the probe reading is then checked against the
# host reference interpreter, and the outcome is written to <deployed>/activation.json.
set -euo pipefail

# ============================================================================
# CONFIGURE: set these to your own environment, then run. Nothing below needs editing.
# ----------------------------------------------------------------------------
DEPLOYED="${1:?usage: activate.sh <deployed dir>}"
PRISMPATH_EBPF="${PRISMPATH_EBPF:?set PRISMPATH_EBPF to the built prismpath-ebpf directory (loader and ppt_xdp.bpf.o)}"
PRISMPATH="${PRISMPATH:-prismpath}"     # the prismpath CLI, if it is not on PATH
SUDO="${SUDO-sudo -n}"                  # loading a BPF program needs CAP_BPF; set SUDO= when already root
# ============================================================================

DEPLOYED="$(cd "$DEPLOYED" && pwd)"
RECEIPT="$DEPLOYED/activation.json"

write_receipt() {
  ACTIVATED="$1" REASON="$2" ATTESTED="$3" LOADED="$4" HOST_PATH="$5" KERNEL_PATH="$6" \
  python3 - "$RECEIPT" <<'PY'
import json, os, sys
from datetime import datetime, timezone
env = os.environ
receipt = {"activated": env["ACTIVATED"] == "true", "reason": env["REASON"],
           "attested_active": env["ATTESTED"] or None, "loaded_sha256": env["LOADED"] or None,
           "host_reference_path": env["HOST_PATH"] or None, "in_kernel_path": env["KERNEL_PATH"] or None,
           "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
with open(sys.argv[1], "w") as handle:
    json.dump(receipt, handle, indent=1)
    handle.write("\n")
print(json.dumps(receipt, indent=1))
PY
}

attestation="$("$PRISMPATH" swap attest --out "$DEPLOYED/state" --pub "$DEPLOYED/authority.pub" --envelope "$DEPLOYED/env1.envelope")"
attested="$(python3 -c 'import json, sys; print(json.load(sys.stdin).get("active") or "")' <<<"$attestation")"
loaded="$(sha256sum "$DEPLOYED/state/active.ppt" | cut -d' ' -f1)"

if [ -z "$attested" ] || [ "$attested" != "$loaded" ]; then
  write_receipt false "refused: the host's copy hashes to $loaded but the host attests ${attested:-nothing} active" \
    "$attested" "$loaded" "" ""
  exit 1
fi

# The loader opens its BPF objects relative to its own directory.
cd "$PRISMPATH_EBPF"
set +e
output="$($SUDO ./loader "$DEPLOYED/state/active.ppt" run "$DEPLOYED/probe.regs.bin" "$DEPLOYED/policy.names" 2>&1)"
status=$?
set -e
host_path="$(awk '/^\[Host reference path/{getline; sub(/^ +/, ""); print; exit}' <<<"$output")"
kernel_path="$(awk '/^\[In-kernel path/{getline; sub(/^ +/, ""); print; exit}' <<<"$output")"

if [ "$status" -ne 0 ] || ! grep -q "^PASS:" <<<"$output"; then
  write_receipt false "refused: the in-kernel path did not match the host reference (loader exit $status)" \
    "$attested" "$loaded" "$host_path" "$kernel_path"
  exit 1
fi
write_receipt true "the kernel decided the probe with the attested policy, along the host reference path" \
  "$attested" "$loaded" "$host_path" "$kernel_path"
