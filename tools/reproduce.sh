#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# End-to-end reproduction script for PrismPath's formal and differential claims.
# Commands are taken directly from .github/workflows/formal.yml and .github/workflows/ci.yml.
#
# Usage:
#   bash tools/reproduce.sh [--build-dir DIR] [--python PYTHON] [--check-only]

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$REPO/.reproduce"
PYTHON_CMD="${PYTHON:-python3}"
CHECK_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --python)
      PYTHON_CMD="$2"
      shift 2
      ;;
    --check-only)
      CHECK_ONLY=1
      shift
      ;;
    -h|--help)
      echo "Usage: bash tools/reproduce.sh [--build-dir DIR] [--python PYTHON] [--check-only]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: bash tools/reproduce.sh [--build-dir DIR] [--python PYTHON] [--check-only]" >&2
      exit 2
      ;;
  esac
done

case "$BUILD_DIR" in
  /*) ;;
  *) BUILD_DIR="$(pwd)/$BUILD_DIR" ;;
esac
mkdir -p "$(dirname "$BUILD_DIR")"
BUILD_DIR="$(cd "$(dirname "$BUILD_DIR")" && pwd)/$(basename "$BUILD_DIR")"

TOOLCHAIN_FILE="$REPO/formal/lean-toolchain"
if [ ! -f "$TOOLCHAIN_FILE" ]; then
  echo "error: missing $TOOLCHAIN_FILE" >&2
  exit 1
fi
LEAN_TOOLCHAIN="$(tr -d '[:space:]' < "$TOOLCHAIN_FILE")"
LEAN_VERSION="${LEAN_TOOLCHAIN##*:v}"
LEAN_VERSION="${LEAN_VERSION#v}"

# ------------------------------------------------------------------ 1. Prerequisite checks
MISSING=0
report_missing() {
  local item="$1"
  local hint="$2"
  echo "MISSING: $item" >&2
  echo "  Install hint: $hint" >&2
  MISSING=1
}

echo "== Checking prerequisites =="

# Python 3.10+ + venv
if ! command -v "$PYTHON_CMD" >/dev/null 2>&1; then
  report_missing "Python 3.10+ ($PYTHON_CMD not found)" \
    "sudo apt-get install -y python3 python3-venv python3-pip  (or brew install python@3.12)"
else
  PY_VER="$("$PYTHON_CMD" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || echo "0.0.0")"
  PY_OK="$("$PYTHON_CMD" -c 'import sys; print(int(sys.version_info >= (3, 10)))' 2>/dev/null || echo "0")"
  if [ "$PY_OK" != "1" ]; then
    report_missing "Python 3.10+ (found $PY_VER)" \
      "Install Python 3.10 or newer and pass --python /path/to/python3"
  elif ! "$PYTHON_CMD" -c 'import venv' >/dev/null 2>&1; then
    report_missing "Python venv module (for $PYTHON_CMD $PY_VER)" \
      "sudo apt-get install -y python3-venv"
  else
    echo "  [ok] Python:       $PY_VER ($PYTHON_CMD)"
  fi
fi

# Rust toolchain (cargo + rustc)
if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
  report_missing "Rust toolchain (cargo / rustc)" \
    "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
else
  echo "  [ok] Rust:         $(rustc --version) / $(cargo --version)"
fi

# elan / Lean / lake at the version in formal/lean-toolchain
if ! command -v elan >/dev/null 2>&1 && { ! command -v lean >/dev/null 2>&1 || ! command -v lake >/dev/null 2>&1; }; then
  report_missing "elan / Lean 4 ($LEAN_TOOLCHAIN)" \
    "curl -sSf https://elan.lean-lang.org/elan-init.sh | sh -s -- -y --default-toolchain $LEAN_TOOLCHAIN"
elif ! command -v lean >/dev/null 2>&1 || ! command -v lake >/dev/null 2>&1; then
  report_missing "lean / lake binaries on PATH ($LEAN_TOOLCHAIN)" \
    "elan toolchain install $LEAN_TOOLCHAIN && export PATH=\"\$HOME/.elan/bin:\$PATH\""
else
  ACTUAL_LEAN="$(cd "$REPO/formal" && lean --version 2>/dev/null | head -n 1 || true)"
  if ! printf '%s\n' "$ACTUAL_LEAN" | grep -Fq "$LEAN_VERSION"; then
    report_missing "Lean toolchain $LEAN_TOOLCHAIN (found: ${ACTUAL_LEAN:-none})" \
      "elan toolchain install $LEAN_TOOLCHAIN"
  else
    echo "  [ok] Lean / lake:  $ACTUAL_LEAN ($LEAN_TOOLCHAIN)"
  fi
fi

# Node.js for the JS diff and conformance runners
if ! command -v node >/dev/null 2>&1; then
  report_missing "Node.js (node)" \
    "sudo apt-get install -y nodejs  (or install Node 20+ from https://nodejs.org/)"
else
  echo "  [ok] Node.js:      $(node --version)"
fi

# C compiler + make
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
  report_missing "C compiler (cc / gcc)" \
    "sudo apt-get install -y build-essential  (or xcode-select --install on macOS)"
elif ! command -v make >/dev/null 2>&1; then
  report_missing "GNU Make (make)" \
    "sudo apt-get install -y build-essential make"
else
  CC_BIN="$(command -v cc || command -v gcc)"
  echo "  [ok] C / Make:     $("$CC_BIN" --version | head -n 1) / $(make --version | head -n 1)"
fi

# Go toolchain (used by core_diff.py 'go' leg, run_corpora.py, and ci.yml go conformance)
if ! command -v go >/dev/null 2>&1; then
  report_missing "Go toolchain (go 1.22+)" \
    "sudo apt-get install -y golang-go  (or install Go 1.22+ from https://go.dev/dl/)"
else
  echo "  [ok] Go:           $(go version)"
fi

if [ "$MISSING" -ne 0 ]; then
  echo "" >&2
  echo "error: missing prerequisites above; install them and re-run tools/reproduce.sh." >&2
  exit 1
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "All prerequisites satisfied (--check-only)."
  exit 0
fi

# ------------------------------------------------------------------ 2. Build directory & report setup
mkdir -p "$BUILD_DIR/logs" "$BUILD_DIR/tmp"
REPORT="$BUILD_DIR/REPRODUCE_REPORT.md"
ROWS_FILE="$BUILD_DIR/rows.md"
: > "$ROWS_FILE"

COMMIT="$(git -C "$REPO" rev-parse HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OVERALL_FAIL=0

record_row() {
  local step="$1"
  local status="$2"
  local duration="$3"
  local detail="$4"
  printf '| `%s` | %s | %s | %s |\n' "$step" "$status" "$duration" "$detail" >> "$ROWS_FILE"
}

run_step() {
  local step="$1"
  local detail="$2"
  shift 2
  local log="$BUILD_DIR/logs/${step}.log"
  local t0 t1 elapsed status
  echo ""
  echo "== [$step] $detail =="
  t0="$(date +%s)"
  set +e
  "$@" > "$log" 2>&1
  local rc=$?
  set -e
  t1="$(date +%s)"
  elapsed="$((t1 - t0))s"
  if [ "$rc" -eq 0 ]; then
    status="PASS"
    echo "   -> PASS ($elapsed)"
  else
    status="FAIL"
    OVERALL_FAIL=1
    echo "   -> FAIL (exit $rc, $elapsed) -- see $log" >&2
    tail -n 25 "$log" >&2 || true
  fi
  record_row "$step" "$status" "$elapsed" "$detail"
}

VENV_DIR="$BUILD_DIR/venv"
VENV_PY="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# ------------------------------------------------------------------ 3. Step functions

step_venv_install() {
  rm -rf "$VENV_DIR"
  "$PYTHON_CMD" -m venv "$VENV_DIR"
  if "$VENV_PIP" install -e "$REPO" numpy pytest cryptography; then
    return 0
  fi
  echo "Online pip install unavailable; falling back to local wheel cache..."
  local wheelhouse="$BUILD_DIR/wheelhouse"
  rm -rf "$wheelhouse"
  mkdir -p "$wheelhouse"
  "$PYTHON_CMD" - "$wheelhouse" <<'PY'
import io, os, re, shutil, sys, zipfile
wheelhouse = sys.argv[1]
cache_root = os.path.expanduser("~/.cache/pip/http-v2")
if os.path.isdir(cache_root):
    for root, _, files in os.walk(cache_root):
        for fname in files:
            if not fname.endswith(".body"):
                continue
            path = os.path.join(root, fname)
            try:
                data = open(path, "rb").read()
                if data[:2] != b"PK":
                    continue
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    wf = [n for n in zf.namelist() if n.endswith(".dist-info/WHEEL")][0]
                    mf = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA")][0]
                    meta = zf.read(mf).decode("utf-8", errors="replace")
                    wheel = zf.read(wf).decode("utf-8", errors="replace")
                    name = re.search(r"^Name: (.+)$", meta, re.M).group(1).replace("-", "_")
                    ver = re.search(r"^Version: (.+)$", meta, re.M).group(1).replace("-", "_")
                    tag = re.findall(r"^Tag: (.+)$", wheel, re.M)[0]
                    shutil.copy2(path, os.path.join(wheelhouse, f"{name}-{ver}-{tag}.whl"))
            except Exception:
                pass
PY
  "$VENV_PIP" install --no-index --find-links "$wheelhouse" setuptools numpy pytest cryptography
  "$VENV_PIP" install --no-index --find-links "$wheelhouse" --no-build-isolation -e "$REPO"
}

seed_lake_packages_if_needed() {
  # In an offline git worktree where formal/.lake/packages is not yet populated, seed git
  # checkouts from the main worktree's .lake/packages if available, then let lake build from scratch.
  if [ -d "$REPO/formal/.lake/packages/mathlib" ]; then
    return 0
  fi
  local common_root
  common_root="$(cd "$REPO" && cd "$(git rev-parse --git-common-dir)/.." && pwd)"
  if [ "$common_root" != "$REPO" ] && [ -d "$common_root/formal/.lake/packages/mathlib" ]; then
    echo "Seeding formal/.lake/packages git checkouts from worktree parent..."
    mkdir -p "$REPO/formal/.lake/packages"
    for pkg in "$common_root/formal/.lake/packages"/*; do
      [ -d "$pkg/.git" ] || continue
      local name
      name="$(basename "$pkg")"
      if [ ! -d "$REPO/formal/.lake/packages/$name" ]; then
        git clone --quiet --no-checkout "$pkg" "$REPO/formal/.lake/packages/$name"
        git -C "$REPO/formal/.lake/packages/$name" checkout --quiet "$(git -C "$pkg" rev-parse HEAD)"
      fi
    done
  fi
}

step_lean_build() {
  cd "$REPO/formal"
  seed_lake_packages_if_needed
  # Clean any prior local build of FQ, Core, core-oracle, and canon2-oracle so this project's
  # modules and executables are always built from scratch while keeping Mathlib's cache.
  rm -rf .lake/build
  lake exe cache get || echo "note: lake exe cache get exited non-zero; proceeding with lake build"
  lake build
  test -x .lake/build/bin/core-oracle
  test -x .lake/build/bin/canon2-oracle
  test -x .lake/build/bin/classifier-oracle
}

step_core_oracle_smoke() {
  # Exact step from .github/workflows/formal.yml: "The core oracle runs on the specification's example"
  cd "$REPO/formal"
  local tmp="$BUILD_DIR/tmp"
  printf '%s' '{"fields":{"x":"int min=0 max=10"},"format":"prismpath.core/1","rules":[{"target":"hit","when":["cmp","x",">=",["num",5]]}]}' > "$tmp/core_policy.json"
  printf '%s' '{"x":7}' > "$tmp/core_r1.json"
  printf '%s' '{"x":11}' > "$tmp/core_r2.json"
  .lake/build/bin/core-oracle "$tmp/core_policy.json" "$tmp/core_r1.json" "$tmp/core_r2.json" | tee "$tmp/core_out.txt"
  grep -q '"target":"hit"' "$tmp/core_out.txt"
  grep -q '"reason":"out_of_range"' "$tmp/core_out.txt"
  printf '%s' '{"x": 7}' > "$tmp/core_r3.json"
  .lake/build/bin/core-oracle "$tmp/core_policy.json" "$tmp/core_r3.json" | grep -q '"cause":"reading:not-canonical"'
}

step_lean_no_sorry() {
  # From .github/workflows/formal.yml: "No sorry in the sources", extended to also forbid the admit tactic
  # (excluding `Core.Population.admit`, which is a function `admit (w : Row) : Option String`)
  cd "$REPO"
  if grep -rn --include='*.lean' -w sorry formal/FQ formal/FQ.lean formal/Core formal/Core.lean formal/Classifier formal/Classifier.lean; then
    echo "error: found 'sorry' in formal Lean sources" >&2
    return 1
  fi
  if grep -rn --include='*.lean' -w admit formal/FQ formal/FQ.lean formal/Core formal/Core.lean formal/Classifier formal/Classifier.lean \
      | grep -v -E 'def admit\b|\[admit\b|admit \(?w\b|admit \(rowOf\b'; then
    echo "error: found 'admit' tactic in formal Lean sources" >&2
    return 1
  fi
}

step_lean_bridge_vectors() {
  # Exact step from .github/workflows/formal.yml: "Bridge vectors are byte identical to a fresh generation from the frozen corpora"
  cd "$REPO"
  cp formal/FQ/Vectors.lean "$BUILD_DIR/tmp/Vectors.before.lean"
  "$VENV_PY" formal/gen_vectors.py
  diff -q "$BUILD_DIR/tmp/Vectors.before.lean" formal/FQ/Vectors.lean
}

step_differential_harnesses() {
  # Exact step from .github/workflows/formal.yml:
  # "The differential harness, CI size (oracle, Python reference, Rust port, JS, Go, C and eBPF legs), and a run as evidence verified across languages"
  cd "$REPO"
  PATH="$VENV_DIR/bin:$PATH" PRISMPATH_REQUIRE_CORE_ORACLE=1 \
    "$VENV_PY" -m pytest prismpath/tests/test_core_diff.py prismpath/tests/test_core_evidence.py -q
}

step_classifier_diff() {
  # Exact step from .github/workflows/formal.yml: "The classifier differential harness"
  cd "$REPO"
  PRISMPATH_REQUIRE_CLASSIFIER_ORACLE=1 "$VENV_PY" -m pytest prismpath/tests/test_classifier_diff.py -q
  "$VENV_PY" formal/diff/classifier_diff.py --cases 20000 --seed 1
}

step_corpora_check() {
  # Exact step from .github/workflows/ci.yml (corpus_summary): "Consumer table against the tree"
  cd "$REPO"
  "$VENV_PY" tools/run_corpora.py --check --python "$VENV_PY"
}

step_corpora_run() {
  # Exact step from .github/workflows/ci.yml (corpus_summary): "Every corpus against every implementation"
  cd "$REPO"
  PATH="$VENV_DIR/bin:$PATH" "$VENV_PY" tools/run_corpora.py --python "$VENV_PY"
}

step_conformance_js() {
  # Exact steps from .github/workflows/ci.yml (conformance job)
  cd "$REPO"
  node --test prismpath/portable/prismpath.test.mjs
  node --test prismpath/editor/vscode/test/grammar.test.mjs
  node --test prismpath/mission_control/static/js/tests/*.test.mjs
  "$VENV_PY" -m pytest prismpath/tests/test_mission_control_client.py -q
  node prismpath/portable/run_vectors.mjs prismpath/portable/conformance
  node prismpath/portable/run_crypto_agility.mjs
  "$VENV_PY" -m pytest prismpath/tests/test_portable_runners.py -q
  "$VENV_PY" -m pytest prismpath/tests/test_conformance_vectors.py -q
}

step_conformance_go() {
  # Exact step from .github/workflows/ci.yml (go job)
  cd "$REPO/prismpath-go"
  go test ./... -v
}

step_conformance_c_target() {
  # Exact C-target steps from .github/workflows/ci.yml (substrates job)
  cd "$REPO"
  make -C prismpath-hw cert
  "$VENV_PY" -m pytest prismpath/tests/test_field_definitions_tables.py -q -rs
}

step_conformance_rust_cross_language() {
  # Exact steps from .github/workflows/ci.yml (rust_cross_language job)
  cd "$REPO"
  local xlog="$BUILD_DIR/tmp/cross_language.log"
  : > "$xlog"
  export PRISMPATH_REQUIRE_CROSS_LANGUAGE=1
  export PRISMPATH_PYTHON="$VENV_PY"
  cargo test -p prismpath-hotswap-rs --test test_hotswap_conformance --test test_host_trace --test test_host_crash --test test_host_cross_language -- --nocapture 2>&1 | tee "$xlog"
  cargo test -p prismpath-rs --test test_connector file_deferral_store_is_cross_runtime -- --nocapture 2>&1 | tee -a "$xlog"
  cargo test -p prismpath-rs --test test_causes -- --nocapture 2>&1 | tee -a "$xlog"
  cargo test -p prismpath-rs --test test_contract --test test_engine_surface --test test_engine_cross_language --test test_parse_limits -- --nocapture 2>&1 | tee -a "$xlog"
  cargo test -p prismpath-telemetry-rs --test test_cross_language -- --nocapture 2>&1 | tee -a "$xlog"
  grep -q "bidirectional: Python verified the Rust-signed packs" "$xlog"
  grep -q "file deferral: cross-runtime round-trips both ways" "$xlog"
  grep -q "cross-language host: each runtime restored the other's active policy" "$xlog"
  grep -q "cross-language host: each runtime recovered the other's interrupted commit" "$xlog"
  grep -q "cross-language host: non ASCII log identical in both runtimes" "$xlog"
  grep -q "host trace: .* cases" "$xlog"
  grep -q "engine cross language: .* scenarios" "$xlog"
  grep -q "cross-language telemetry: Python decoded, re-encoded, demultiplexed and replayed what Rust wrote" "$xlog"
  grep -q "cross-language telemetry: Rust decoded, re-encoded, demultiplexed and replayed what Python wrote" "$xlog"
  if grep -q SKIP "$xlog"; then
    echo "a cross language leg was skipped" >&2
    return 1
  fi
}

# ------------------------------------------------------------------ 4. Execute steps
START_ALL="$(date +%s)"

run_step "venv-install" \
  "Create isolated venv under build dir and install repo + test/signing dependencies" \
  step_venv_install

run_step "lean-build" \
  "Build Lean 4 proofs (FQ, Core, Classifier), #guard bridge checks, axiom audits, core-oracle, canon2-oracle and classifier-oracle (cd formal && lake build)" \
  step_lean_build

run_step "core-oracle-smoke" \
  "Run core-oracle on the specification's example policy and readings (.github/workflows/formal.yml)" \
  step_core_oracle_smoke

run_step "lean-no-sorry" \
  "Verify zero sorry/admit in formal/FQ, formal/FQ.lean, formal/Core, formal/Core.lean, formal/Classifier and formal/Classifier.lean" \
  step_lean_no_sorry

run_step "lean-bridge-vectors" \
  "Verify formal/FQ/Vectors.lean is byte-identical to fresh generation from frozen corpora (formal/gen_vectors.py)" \
  step_lean_bridge_vectors

run_step "differential-harnesses" \
  "Run verified-core differential harness (Lean, Python, Rust, JS, Go, C, eBPF legs) and cross-language evidence replay (test_core_diff.py, test_core_evidence.py)" \
  step_differential_harnesses

run_step "classifier-diff" \
  "Hold the Python classifier and its Claude Code and MCP mappings to the Lean classifier oracle: 120 recorded hook inputs, 51 adversary probes, 20,000 generated calls (formal/diff/classifier_diff.py)" \
  step_classifier_diff

run_step "corpora-table-check" \
  "Validate conformance corpus consumer table against repository tree (tools/run_corpora.py --check)" \
  step_corpora_check

run_step "corpora-all" \
  "Run all 33 frozen conformance corpora across Python, Rust, JS, Go, and C hardware target (tools/run_corpora.py)" \
  step_corpora_run

run_step "conformance-js" \
  "Run JavaScript portable kernel unit tests, frozen vector runners, and drift checks (.github/workflows/ci.yml conformance)" \
  step_conformance_js

run_step "conformance-go" \
  "Run Go kernel conformance suite (cd prismpath-go && go test ./... -v)" \
  step_conformance_go

run_step "conformance-c-target" \
  "Certify C table target against frozen corpus (make -C prismpath-hw cert) and lowered threshold tables" \
  step_conformance_c_target

run_step "conformance-rust-cross-language" \
  "Run bidirectional Rust/Python cross-language host, pack, deferral, cause, contract, and telemetry checks (.github/workflows/ci.yml rust_cross_language)" \
  step_conformance_rust_cross_language

# Hardware / root steps: listed honestly as NOT RUN with the reason, never faked.
record_row "ebpf-in-kernel" "NOT RUN" "-" \
  "Not run: requires root (sudo / CAP_BPF) and a live Linux kernel with BTF to load XDP programs and execute BPF_PROG_TEST_RUN (.github/workflows/ci.yml ebpf_kernel); userspace eBPF evaluator is covered in differential-harnesses"
record_row "fpga-silicon" "NOT RUN" "-" \
  "Not run: requires Xilinx Vivado 2023.2 and a physical Zynq-7020 board (Arty Z7-20 / PYNQ-Z1/Z2) for bitstream build and MMIO fabric replay (prismpath-hw/pynq, prismpath-hw/hyst-cert)"
record_row "mcu-boards" "NOT RUN" "-" \
  "Not run: requires physical ATmega328P, RP2350, ESP32, and ESP32-C6 boards attached over serial/USB and vendor cross-toolchains (prismpath-hw/{avr,rp2350,esp})"

END_ALL="$(date +%s)"
TOTAL_ELAPSED="$((END_ALL - START_ALL))s"
OVERALL_STATUS="PASS"
if [ "$OVERALL_FAIL" -ne 0 ]; then
  OVERALL_STATUS="FAIL"
fi

# ------------------------------------------------------------------ 5. Write REPRODUCE_REPORT.md and print summary
{
  echo "# PrismPath Reproduction Report"
  echo ""
  echo "- **Commit:** \`$COMMIT\`"
  echo "- **Timestamp (UTC):** \`$TIMESTAMP\`"
  echo "- **Lean toolchain:** \`$LEAN_TOOLCHAIN\`"
  echo "- **Total duration:** \`$TOTAL_ELAPSED\`"
  echo "- **Overall status:** **$OVERALL_STATUS**"
  echo ""
  echo "## Summary"
  echo ""
  echo "| Step | Status | Duration | Description / Reason |"
  echo "|---|---|---|---|"
  cat "$ROWS_FILE"
} > "$REPORT"

rm -f "$ROWS_FILE"

echo ""
cat "$REPORT"
echo ""
echo "Report written to: $REPORT"

exit "$OVERALL_FAIL"
