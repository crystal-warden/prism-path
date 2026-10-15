#!/usr/bin/env bash
# Reproduce the signed pack + envelope for the Zarf/UDS demos. Keys are generated fresh
# (never committed); the compiled policy.ppt is the committed input.
set -euo pipefail
cd "$(dirname "$0")"
PP="${PRISMPATH:-prismpath}"   # set PRISMPATH to your prismpath CLI if it is not on PATH
PY="${PYTHON:-python3}"        # a Python with the prismpath package importable
REPO="${PRISMPATH_REPO:-$(cd ../.. && pwd)}"   # the prism-path checkout, for the compliance emitter

mkdir -p keys
"$PP" swap keygen --name authority --out keys
"$PP" swap pack --ppt policy.ppt --priv keys/authority.key --pub keys/authority.pub --version 1 --envelope-id env1
"$PP" swap envelope --priv keys/authority.key --pub keys/authority.pub --out . --envelope-id env1 \
  --caps atoms=1024,nodes=256,edges=1024,prog_words=4096,max_steps=25,max_stack=16
cp keys/authority.pub authority.pub

# The policy's bill of materials. Zarf's own SBOM catalogs software packages and finds none in a signed
# policy, so the compliance emitter describes the pack: CycloneDX 1.6, written only after the pack
# verifies and the schema accepts it, the same document for the same pack. The deploy delivers it beside the policy.
PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}" "$PY" -m adapters.compliance.emit --pack-sbom policy.ppt \
  --pub keys/authority.pub --name prismpath-policy --supplier "${SBOM_SUPPLIER:-Crystal Warden Supply Chain Labs LLC}"

# The negative-control image: a byte-flipped copy of the same policy (authentic sig stays put).
# The manifest signs the sha256 of the WHOLE image, so any offset inside the file breaks the
# verification; 64 is past the 28 byte header, so the flip lands in the policy tables themselves
# rather than in a header field a reader might dismiss as cosmetic.
cp policy.ppt policy.tampered.ppt
printf '\xff' | dd of=policy.tampered.ppt bs=1 seek=64 count=1 conv=notrunc 2>/dev/null

echo "signed pack + envelope ready."
echo "  happy path : zarf package create . --confirm && zarf package deploy zarf-package-prismpath-policy-*.tar.zst --confirm"
echo "  fail closed: zarf package create zarf.tampered.yaml --confirm  (the deploy verify will abort)"
