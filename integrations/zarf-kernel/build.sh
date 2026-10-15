#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# Reproduce the signed pack, its SBOM and the probe for the kernel activation demo. The policy image is
# the committed ../zarf/policy.ppt; keys are generated fresh and never committed.
set -euo pipefail
cd "$(dirname "$0")"
PP="${PRISMPATH:-prismpath}"         # set PRISMPATH to your prismpath CLI if it is not on PATH
PY="${PYTHON:-python3}"              # a Python with the prismpath package importable
REPO="${PRISMPATH_REPO:-$(cd ../.. && pwd)}"   # the prism-path checkout, for the compliance emitter

cp ../zarf/policy.ppt policy.ppt
mkdir -p keys
"$PP" swap keygen --name authority --out keys
"$PP" swap pack --ppt policy.ppt --priv keys/authority.key --pub keys/authority.pub --version 1 --envelope-id env1
"$PP" swap envelope --priv keys/authority.key --pub keys/authority.pub --out . --envelope-id env1 \
  --caps atoms=1024,nodes=256,edges=1024,prog_words=4096,max_steps=25,max_stack=16
cp keys/authority.pub authority.pub
PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}" "$PY" -m adapters.compliance.emit --pack-sbom policy.ppt \
  --pub keys/authority.pub --name prismpath-policy --supplier "${SBOM_SUPPLIER:-Crystal Warden Supply Chain Labs LLC}"
"$PY" make_probe.py

# The negative control: the same image with one byte flipped inside the policy tables, carried with the
# authentic manifest and signature. Verification must refuse it before activation can run.
cp policy.ppt policy.tampered.ppt
printf '\xff' | dd of=policy.tampered.ppt bs=1 seek=64 count=1 conv=notrunc 2>/dev/null

echo "signed pack, SBOM and probe ready."
echo "  activate   : PRISMPATH_EBPF=<built prismpath-ebpf> zarf package create . --confirm && zarf package deploy zarf-package-*.tar.zst --confirm"
echo "  fail closed: cd tampered && zarf package create . --confirm && zarf package deploy zarf-package-*.tar.zst --confirm"
