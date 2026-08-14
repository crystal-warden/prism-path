#!/usr/bin/env bash
# Reproduce the signed pack + envelope for the Zarf/UDS demos. Keys are generated fresh
# (never committed); the compiled policy.ppt is the committed input.
set -euo pipefail
cd "$(dirname "$0")"
PP="${PRISMPATH:-prismpath}"   # set PRISMPATH to your prismpath CLI if it is not on PATH

mkdir -p keys
"$PP" swap keygen --name authority --out keys
"$PP" swap pack --ppt policy.ppt --priv keys/authority.key --pub keys/authority.pub --version 1 --envelope-id env1
"$PP" swap envelope --priv keys/authority.key --pub keys/authority.pub --out . --envelope-id env1 \
  --caps atoms=1024,nodes=256,edges=1024,prog_words=4096,max_steps=25,max_stack=16
cp keys/authority.pub authority.pub

# The negative-control image: a byte-flipped copy of the same policy (authentic sig stays put).
cp policy.ppt policy.tampered.ppt
printf '\xff' | dd of=policy.tampered.ppt bs=1 seek=64 count=1 conv=notrunc 2>/dev/null

echo "signed pack + envelope ready."
echo "  happy path : zarf package create . --confirm && zarf package deploy zarf-package-prismpath-policy-*.tar.zst --confirm"
echo "  fail closed: zarf package create zarf.tampered.yaml --confirm  (the deploy verify will abort)"
