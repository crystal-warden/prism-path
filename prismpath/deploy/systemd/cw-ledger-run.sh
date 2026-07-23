#!/usr/bin/env bash
# Wrapper for the out-of-band Flow-Ledger anchoring timers (#53).
# Sources the project environment (numpy/requests/ots on PATH) and runs the
# prismpath ledger CLI. Keeps the systemd units interpreter-agnostic.
set -euo pipefail

PRISMPATH_HOME="${PRISMPATH_HOME:-$HOME/cwprojects/prismpath}"
ENV_SH="${PRISMPATH_ENV:-$HOME/cwprojects/Refract/env.gb10.sh}"

# shellcheck disable=SC1090
[ -f "$ENV_SH" ] && source "$ENV_SH" 2>/dev/null || true
export PATH="$HOME/.local/bin:$PATH"
export PYTHONPATH="$PRISMPATH_HOME:${PYTHONPATH:-}"

cd "$PRISMPATH_HOME"
exec python3 -m prismpath.cli ledger "$@"
