#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Check the general theory's Lean core, then the FQ bridge against the repository's own FQ project.
# The core imports nothing. The bridge imports FQ from formal/ at the repository root, which must be built
# once (cd formal && lake exe cache get && lake build). FQ_PROJECT overrides that location.
set -euo pipefail
cd "$(dirname "$0")"
echo "[core] Governance.lean (imports nothing)"
lean Governance.lean
REPO_FORMAL="$(cd ../../../../../formal 2>/dev/null && pwd || true)"
FQ="${FQ_PROJECT:-$REPO_FORMAL}"
if [ -n "$FQ" ] && [ -d "$FQ/.lake" ]; then
  echo "[bridge] FQBridge.lean (imports the FQ project at $FQ)"
  lean -o Governance.olean Governance.lean
  LP="$(cd "$FQ" && lake env printenv LEAN_PATH)"
  LEAN_PATH="$LP:$(pwd)" lean FQBridge.lean
  rm -f Governance.olean
  echo "[ok] core and FQ bridge both check"
else
  echo "[ok] core checks"
  echo "[not checked] FQ bridge: build the FQ project first, cd formal && lake exe cache get && lake build"
  echo "              (from the repository root; FQ_PROJECT overrides the location, see README.md)"
fi
