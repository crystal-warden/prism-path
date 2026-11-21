#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# The acceptance gates, run outside any source checkout. The tree is exported from git into a
# temporary directory, so an uncommitted file cannot pass by accident; the Python legs install the
# built wheel into a fresh virtual environment and run the shipped tests against the installed
# package with PYTHONPATH cleared; the Rust leg builds and tests each crate from a cargo package
# extraction so a crate cannot lean on the source tree. Every gate writes its exit status to the
# report; a missing prerequisite is a reported blocker, never a pass.
#
#   tools/acceptance.sh --leg full|python|rust [--out DIR] [--python PYTHON] [--research DIR]
#
# full runs everything including the cross language tests, the end to end run of one flow through the
# installed wheel and the extracted crates, and the repository checks; python runs the Python gates on
# a box without Rust; rust runs the crate gates on a box without Python packages. The tree under test is
# the export of the research repository that the product repository holds; --research names a research
# checkout at the commit PROVENANCE.md records, and the provenance gate then also proves every file is
# what that checkout's exporter writes. Without it the gate proves only that no file changed since the
# export.
#
# Without --out the run works in a temporary directory of its own (several GB: the export, virtual
# environments, cargo targets) and removes it on every exit, a pass, a failure or an interruption, after
# printing the report. PRISMPATH_ACCEPTANCE_KEEP=1 keeps it for debugging. A directory named by --out is
# the caller's and is kept. TMPDIR points inside the working directory for the run, so whatever a gate
# creates as a temporary file (pytest's base temp, mktemp, tempfile) goes with it.
set -u

LEG="full"
OUT=""
RESEARCH=""
PYTHON="${PYTHON:-python3}"
while [ $# -gt 0 ]; do
  case "$1" in
    --leg) LEG="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    --research) RESEARCH="$2"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

case "$LEG" in
  full|python|rust) ;;
  *) echo "unknown leg '$LEG': use full, python or rust" >&2; exit 2 ;;
esac

REPO="$(cd "$(dirname "$0")/.." && pwd)"
COMMIT="$(git -C "$REPO" rev-parse HEAD)"
OWN_OUT=0
if [ -z "$OUT" ]; then
  OUT="$(mktemp -d -t prismpath-acceptance-XXXXXX)" || { echo "cannot create a temporary directory" >&2; exit 2; }
  OWN_OUT=1
fi
cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  if [ "$OWN_OUT" = "1" ]; then
    if [ "${PRISMPATH_ACCEPTANCE_KEEP:-0}" = "1" ]; then
      echo "kept $OUT (PRISMPATH_ACCEPTANCE_KEEP=1); remove it when done" >&2
    else
      chmod -R u+w "$OUT" 2>/dev/null   # cargo and pip leave read only files behind
      rm -rf "$OUT"
      [ "$status" = "0" ] || echo "removed $OUT; run again with PRISMPATH_ACCEPTANCE_KEEP=1 to keep the logs" >&2
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mkdir -p "$OUT"
mkdir -p "$OUT/tmp"
export TMPDIR="$OUT/tmp"
REPORT="$OUT/report.md"
EXPORT="$OUT/tree"
unset PYTHONPATH
export PYTHONDONTWRITEBYTECODE=1
export SOURCE_DATE_EPOCH="$(git -C "$REPO" log -1 --format=%ct)"
export XDG_STATE_HOME="$OUT/state"
FAILED=0

record() {   # record <gate> <status> <detail>
  printf '| %s | %s | %s |\n' "$1" "$2" "$3" >> "$REPORT"
  if [ "$2" != "pass" ] && [ "$2" != "skip" ]; then FAILED=1; fi
}
run_gate() { # run_gate <gate> <logfile> <command...>
  local gate="$1"; local log="$2"; shift 2
  if "$@" > "$log" 2>&1; then record "$gate" pass "$(basename "$log")"; else record "$gate" FAIL "exit $? see $(basename "$log")"; fi
}

{
  echo "# Acceptance report"
  echo
  echo "commit $COMMIT, leg $LEG, $(date -u +%Y-%m-%dT%H:%MZ)"
  echo
  echo "| Gate | Status | Detail |"
  echo "|---|---|---|"
} > "$REPORT"

# ------------------------------------------------------------------ export the tracked tree
mkdir -p "$EXPORT"
git -C "$REPO" archive --format=tar HEAD | tar -x -C "$EXPORT"
record "export tracked tree" pass "$(find "$EXPORT" -type f | wc -l) files"

if [ "$LEG" = "full" ] || [ "$LEG" = "python" ]; then
  if ! command -v "$PYTHON" > /dev/null; then record "python prerequisite" BLOCKED "$PYTHON not found"; fi
  "$PYTHON" --version > "$OUT/python-version.txt" 2>&1
  # -------------------------------------------------------------- build wheel and sdist, twice
  run_gate "build wheel and sdist" "$OUT/build.log" bash -c "cd '$EXPORT' && '$PYTHON' -m venv '$OUT/venv-build' && '$OUT/venv-build/bin/pip' -q install build && '$OUT/venv-build/bin/python' -m build --outdir '$OUT/dist' ."
  run_gate "build again for reproducibility" "$OUT/build2.log" bash -c "cd '$EXPORT' && '$OUT/venv-build/bin/python' -m build --outdir '$OUT/dist2' ."
  WHEEL="$(ls "$OUT"/dist/*.whl 2>/dev/null | head -1)"
  SDIST="$(ls "$OUT"/dist/*.tar.gz 2>/dev/null | head -1)"
  if [ -n "$WHEEL" ]; then
    run_gate "reproducible wheel and sdist" "$OUT/reproducible.log" "$PYTHON" - "$OUT/dist" "$OUT/dist2" <<'PY'
import hashlib, sys, tarfile, zipfile
from pathlib import Path
first, second = Path(sys.argv[1]), Path(sys.argv[2])
def wheel_members(path):
    """Every member's content hash and external mode bits; nothing excluded. The zip entry timestamps
    are pinned by SOURCE_DATE_EPOCH and so compared too."""
    with zipfile.ZipFile(path) as archive:
        return {info.filename: (hashlib.sha256(archive.read(info.filename)).hexdigest(), info.external_attr >> 16, info.date_time)
                for info in archive.infolist()}
def sdist_members(path):
    """Every member's content hash, mode, type, owner names and ids. The one normalized field is the
    tar member mtime: setuptools stamps directory entries and a few generated files with the build
    time rather than SOURCE_DATE_EPOCH, a documented incidental difference; the members' bytes and
    modes are compared in full, PKG-INFO included."""
    with tarfile.open(path) as archive:
        out = {}
        for member in archive.getmembers():
            content = hashlib.sha256(archive.extractfile(member).read()).hexdigest() if member.isfile() else None
            out[member.name.split("/", 1)[1] if "/" in member.name else member.name] = (content, member.mode, member.type, member.uname, member.gname, member.uid, member.gid)
        return out
problems = []
for kind, members, glob in (("wheel", wheel_members, "*.whl"), ("sdist", sdist_members, "*.tar.gz")):
    one, two = sorted(first.glob(glob)), sorted(second.glob(glob))
    if len(one) != 1 or len(two) != 1:
        problems.append(f"{kind}: expected one artifact per build"); continue
    first_members, second_members = members(one[0]), members(two[0])
    differing = sorted(name for name in set(first_members) | set(second_members) if first_members.get(name) != second_members.get(name))
    if differing:
        problems.append(f"{kind}: {len(differing)} member(s) differ between two builds: {differing[:8]}")
print("\n".join(problems) if problems else "identical contents, modes, types and owners across two builds; wheel timestamps identical; only sdist member mtimes normalized")
sys.exit(1 if problems else 0)
PY
    run_gate "package boundary (wheel and sdist)" "$OUT/boundary-package.log" bash -c "cd '$EXPORT' && '$PYTHON' -m tools.check_boundary --wheel '$WHEEL' --sdist '$SDIST'"
    # -------------------------------------------------------------- base install: numpy only, no research, no rust, no node
    run_gate "python base: fresh venv install of the wheel" "$OUT/base-install.log" bash -c "'$PYTHON' -m venv '$OUT/venv-base' && '$OUT/venv-base/bin/pip' -q install '$WHEEL'"
    run_gate "python base: CLI, import and runtime asset smoke" "$OUT/base-smoke.log" bash -c "
      set -e; cd '$OUT'; export PRISMPATH_ACCEPTANCE_INSTALLED=1
      VENV_BIN='$OUT/venv-base/bin'
      \$VENV_BIN/prismpath --help > /dev/null
      \$VENV_BIN/python -c 'import prismpath; print(prismpath.__file__); assert \"site-packages\" in prismpath.__file__'
      rm -rf smoke && mkdir smoke && cd smoke
      \$VENV_BIN/prismpath init --template incident_severity > /dev/null
      \$VENV_BIN/prismpath validate incident_severity.md
      \$VENV_BIN/prismpath test incident_severity.md
      \$VENV_BIN/prismpath portable incident_severity.md
      \$VENV_BIN/python -m prismpath.kernel.ppt_compile incident_severity.md -o incident_severity.ppt --json incident_severity.names.json
      test -s incident_severity.ppt
      \$VENV_BIN/prismpath facet quantize incident_severity.md '{\"data_at_risk\": false, \"user_facing\": true, \"error_rate\": 7}' > facet.out
      grep -Eq '^\([0-9]+(, [0-9]+)*\)$' facet.out
      if \$VENV_BIN/prismpath compile incident_severity.md --tier p0 2> compile.err; then echo 'compile must fail'; exit 1; fi
      grep -q 'not available in this distribution' compile.err
      printf '{\"data_at_risk\": false, \"user_facing\": true, \"error_rate\": 7}\n{\"data_at_risk\": true, \"user_facing\": false, \"error_rate\": 0}\n{\"data_at_risk\": false, \"user_facing\": false, \"error_rate\": 0}\n' > sample.ndjson
      \$VENV_BIN/python -m prismpath.telemetry.preflight incident_severity.md sample.ndjson --json preflight.json > preflight.out
      \$VENV_BIN/python -c 'import json; r = json.load(open(\"preflight.json\")); assert r[\"events\"] == 3, r; print(\"preflight\", r[\"events\"], \"events\")'
      echo 'base smoke ok'"
    run_gate "python base: installed package test (base extras only)" "$OUT/base-tests.log" bash -c "cd '$OUT' && '$OUT/venv-base/bin/pip' -q install pytest && PATH='$OUT/venv-base/bin':\$PATH PRISMPATH_ACCEPTANCE_INSTALLED=1 '$OUT/venv-base/bin/python' -m pytest --pyargs prismpath.tests.test_installed_package prismpath.tests.test_cli_without_js_engine prismpath.tests.test_compatibility_hashes prismpath.tests.test_compiler_parity -q -p no:cacheprovider"
    # -------------------------------------------------------------- full install: extras, the shipped suites against the installed package
    run_gate "python full: install with signing, control-plane, test extras" "$OUT/full-install.log" bash -c "'$PYTHON' -m venv '$OUT/venv-full' && '$OUT/venv-full/bin/pip' -q install '$WHEEL[signing,control-plane,test]' httpx"
    run_gate "python full: runtime suite against the installed package" "$OUT/full-tests.log" bash -c "cd '$OUT' && PATH='$OUT/venv-full/bin':\$PATH PRISMPATH_ACCEPTANCE_INSTALLED=1 '$OUT/venv-full/bin/python' -m pytest --pyargs prismpath.tests prismpath.telemetry.tests -q -p no:cacheprovider -m 'not cross_language' -rs"
    run_gate "python full: skip budget" "$OUT/skips.log" "$PYTHON" - "$OUT/full-tests.log" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
# One allowance per test file, each an optional extra deliberately absent from the acceptance venv.
# bwrap is not allowed: the sandbox test must run with enforcement, so its absence is a blocker.
allowed = {
    "test_gates_behavioral_findings.py": "could not import 'playwright'",
    "test_gates_infra_error.py": "could not import 'playwright'",
    "test_mission_control_page_verify.py": "could not import 'playwright",   # the headless browser check of the page's verdict
    "test_mission_control_feed_browser.py": "could not import 'playwright",   # the headless browser check of the collector feed's screens
    "test_llm_local.py": "could not import 'torch'",
    "test_lockfile.py": "needs the real bge embedder",
    "test_router.py": "could not import 'sentence_transformers'",
    "test_facet_init.py": "tomllib needs Python 3.11",
    "_repo.py": "docs/standards is only in a repo checkout",   # the cause and regulatory crosswalk referees, whose data is repository documentation
    "test_governed_agent_guide.py": "is only in a repo checkout",   # the guide is not in the wheel; the repo job runs it
    "test_facet_mcp.py": "are only in a repo checkout",   # its three policies are not in the wheel; the repo job runs it
}
skips = re.findall(r"^SKIPPED \[\d+\] (.+)$", text, re.M)
def budgeted(line):
    for test_file, reason in allowed.items():
        if f"/{test_file}:" in line and reason in line:
            return True
    return False
unbudgeted = [line for line in skips if not budgeted(line)]
print("skips:", len(skips)); [print("  ", line) for line in skips]
if unbudgeted:
    print("UNBUDGETED SKIPS:"); [print("  ", line) for line in unbudgeted]
sys.exit(1 if unbudgeted else 0)
PY
    run_gate "python full: fuzz the predicate sandbox" "$OUT/fuzz.log" bash -c "cd '$OUT' && '$OUT/venv-full/bin/python' -m prismpath.safety.fuzz_predicates -n 20000"
    run_gate "canary verifier from the installed module" "$OUT/canary.log" bash -c "cd '$OUT' && '$OUT/venv-full/bin/python' -m pytest --pyargs prismpath.telemetry.tests.test_canary_verify -q -p no:cacheprovider"
    # -------------------------------------------------------------- the signed pack, inside the project Mission Control will follow
    run_gate "signed pack from the installed wheel: keygen, envelope, compile, pack, verify" "$OUT/pack.log" bash -c "
      set -e; rm -rf '$OUT/mc-project' && mkdir -p '$OUT/mc-project/flows' && cd '$OUT/mc-project'
      PRISMPATH_BIN='$OUT/venv-full/bin/prismpath'; PYTHON_BIN='$OUT/venv-full/bin/python'
      printf -- '---\nname: triage\nstart: intake\n---\n## intake\n-> escalate: when priority > 5\n-> resolve: else\n## escalate\n## resolve\n' > flows/triage.md
      \$PRISMPATH_BIN swap keygen --out keys --name authority > /dev/null
      \$PRISMPATH_BIN swap envelope --envelope-id env1 --fields priority:int --caps atoms=1024,nodes=256 --priv keys/authority.key --pub keys/authority.pub --out env > /dev/null
      \$PYTHON_BIN -m prismpath.kernel.ppt_compile flows/triage.md -o triage.ppt
      \$PRISMPATH_BIN swap pack --ppt triage.ppt --fields priority:int --priv keys/authority.key --pub keys/authority.pub --version 1 > /dev/null
      \$PRISMPATH_BIN swap verify --ppt triage.ppt --pub keys/authority.pub | grep -q '\"ok\": true'
      echo 'pack verified'"
    # -------------------------------------------------------------- Mission Control from the installed wheel
    run_gate "mission control: installed launch, defaults, assets, validate, facet, pack verify, sprint subprocess" "$OUT/mission-control.log" "$OUT/venv-full/bin/python" - "$OUT" <<'PY'
import json, os, subprocess, sys, time, urllib.error, urllib.request, tempfile
from pathlib import Path
out = Path(sys.argv[1]); project = out / "mc-project"
flow = project / "flows" / "triage.md"
assert flow.exists(), "the pack gate prepares the project"
# LLM_BASE points at a closed loopback port so a sprint that tries to reach a model fails fast and
# touches no live service; the launch is what is under test, not the model.
env = dict(os.environ, MC_PROJ=str(project), MC_PORT="9917", MC_SCAN=str(project / "status.json"), LLM_BASE="http://127.0.0.1:9/v1", LLM_MODEL="none")
env.pop("MC_AUDIT", None)
state_home = Path(os.environ["XDG_STATE_HOME"]); env["XDG_STATE_HOME"] = str(state_home)
server = subprocess.Popen([sys.executable, "-m", "prismpath.mission_control"], env=env, cwd=str(out), stdout=open(out / "mc-server.log", "w"), stderr=subprocess.STDOUT)
# The console writes its session token, owner only, into its state directory; a script on the same
# machine reads it there and sends it in the session header, as the page does from its meta tag.
def token_of(port):
    return (state_home / "prismpath" / f"mission_control-{port}.session").read_text().strip()
TOKEN = {}
def get(path, headers=None):
    request = urllib.request.Request(f"http://127.0.0.1:9917{path}", headers={"X-PrismPath-Session": TOKEN.get("t", ""), **(headers or {})})
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, response.read()
def post(path, payload):
    request = urllib.request.Request(f"http://127.0.0.1:9917{path}", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "X-PrismPath-Session": TOKEN.get("t", "")}, method="POST")
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.status, json.loads(response.read())
def refused(path, headers):
    try:
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:9917{path}", headers=headers), timeout=5)
    except urllib.error.HTTPError as error:
        return error.code
    return 200
try:
    for _ in range(50):
        try: TOKEN["t"] = token_of(9917); get("/api/v1/status"); break
        except Exception: time.sleep(0.2)
    else: raise SystemExit("mission control did not start; see mc-server.log")
    token_file = state_home / "prismpath" / "mission_control-9917.session"
    assert os.name == "nt" or token_file.stat().st_mode & 0o777 == 0o600, oct(token_file.stat().st_mode)
    assert TOKEN["t"] not in (out / "mc-server.log").read_text(), "the launch printed the session token"
    assert refused("/api/v1/status", {}) == 403, "an API request without the session header was served"
    assert refused("/api/v1/status", {"X-PrismPath-Session": TOKEN["t"], "Host": "evil.example:9917"}) == 403, "a foreign Host was served"
    assert refused("/api/v1/status", {"X-PrismPath-Session": TOKEN["t"], "Origin": "http://evil.example"}) == 403, "a foreign Origin was served"
    print("session guard: token file owner only, missing token, foreign Host and foreign Origin refused")
    for asset in ("/", "/style.css", "/js/main.mjs", "/js/markup.mjs", "/js/verify.mjs", "/portable/canon2.mjs", "/portable/merkle.mjs", "/vendor/cytoscape.min.js"):
        status, body = get(asset); assert status == 200 and body, asset
    status, page = get("/")
    assert f'<meta name="prismpath-session" content="{TOKEN["t"]}">'.encode() in page, "the page carries no session token"
    print("static assets served")
    status, validation = post("/api/v1/inspect/validate", {"flow_md": "flows/triage.md"}); print("validate:", status, str(validation)[:120])
    assert status == 200 and validation.get("ok") is True and validation.get("errors") == 0, validation
    status, facet = post("/api/v1/policy/facet-encode", {"flow_md": "flows/triage.md", "reading_json": {"priority": 7}}); print("facet-encode:", status, str(facet)[:160])
    assert status == 200 and facet.get("quantized") == {"priority": 1} and facet.get("payload_hex"), facet
    status, verified = post("/api/v1/policy/pack-verify", {"ppt_path": "triage.ppt", "pub": ["keys/authority.pub"]}); print("pack-verify:", status, verified.get("ok"), verified.get("reasons"))
    assert verified.get("ok") is True, verified
    status, started = post("/api/v1/sprint/start", {"proj": str(project), "agent": "served", "seconds": 1, "max_iters": 1}); print("sprint start:", status, started)
    time.sleep(4)
    log_path = project / "mc_sprint.log"
    assert log_path.exists(), "the sprint wrote no log: it was not launched in the project"
    log = log_path.read_text()
    assert "[sprint]" in log, f"the sprint module did not run: {log[-500:]}"
    assert "No module named" not in log and "can't open file" not in log, log[-500:]
    assert "port=9)" in log, "the sprint did not fail on the closed loopback endpoint it was pointed at"
    assert "8888" not in log, "the sprint reached for the default model endpoint"
    print("sprint subprocess launched from the installed module in the project; log head:", log[:300].replace("\n", " | "))
    # The audit log is created by the first audited action, and the sprint start is one; only now
    # can its location be asserted.
    audit_default = state_home / "prismpath" / "mission_audit.log"
    assert audit_default.exists(), f"audit log not at the state directory default: {audit_default}"
    assert not list(Path(sys.prefix).rglob("mission_audit.log")), "audit log written into the installation"
    print("audit log at", audit_default)
finally:
    server.terminate(); server.wait(timeout=10)
# the override, in a second process
env2 = dict(env, MC_AUDIT=str(out / "override-audit.log"), MC_PORT="9918")
server = subprocess.Popen([sys.executable, "-m", "prismpath.mission_control"], env=env2, cwd=str(out), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
try:
    for _ in range(50):
        try:
            second = token_of(9918)
            with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:9918/api/v1/status", headers={"X-PrismPath-Session": second}), timeout=5): break
        except Exception: time.sleep(0.2)
    request = urllib.request.Request("http://127.0.0.1:9918/api/v1/sprint/start", data=json.dumps({"proj": str(project), "agent": "served", "seconds": 1, "max_iters": 1}).encode(), headers={"Content-Type": "application/json", "X-PrismPath-Session": second}, method="POST")
    with urllib.request.urlopen(request, timeout=20) as response:
        assert response.status == 200
    time.sleep(2)
    assert (out / "override-audit.log").exists(), "MC_AUDIT override not honoured"
    print("MC_AUDIT override honoured")
finally:
    server.terminate(); server.wait(timeout=10)
PY
    # -------------------------------------------------------------- source archive
    run_gate "source archive: unpack, rebuild, install, promised tests present" "$OUT/sdist.log" bash -c "rm -rf '$OUT/sdist-work' && mkdir '$OUT/sdist-work' && tar -xzf '$SDIST' -C '$OUT/sdist-work' && cd '$OUT'/sdist-work/prismpath-* && test -f prismpath/tests/test_causes.py && test -f prismpath/tests/fixtures/compiler/SHA256SUMS && test -f COMPATIBILITY.md && '$OUT/venv-build/bin/python' -m build --outdir '$OUT/dist-from-sdist' . && '$PYTHON' -m venv '$OUT/venv-sdist' && '$OUT/venv-sdist/bin/pip' -q install '$OUT'/dist-from-sdist/*.whl pytest && cd '$OUT' && PATH='$OUT/venv-sdist/bin':\$PATH PRISMPATH_ACCEPTANCE_INSTALLED=1 '$OUT/venv-sdist/bin/python' -m pytest --pyargs prismpath.tests.test_compatibility_hashes prismpath.tests.test_installed_package -q -p no:cacheprovider"
    # -------------------------------------------------------------- examples and quickstart
    run_gate "documentation: examples and quickstart commands" "$OUT/examples.log" bash -c "cd '$EXPORT' && export PATH='$OUT/venv-full/bin':\$PATH && PRISMPATH_BIN='$OUT/venv-full/bin/prismpath' && \$PRISMPATH_BIN validate prismpath/examples/pr_demo/triage.md && \$PRISMPATH_BIN test prismpath/examples/pr_demo/triage.md && \$PRISMPATH_BIN validate prismpath/examples/operator_overlay/overlay.md && \$PRISMPATH_BIN test prismpath/examples/operator_overlay/overlay.md && \$PRISMPATH_BIN validate prismpath/examples/governed_worker/governed_worker.md && \$PRISMPATH_BIN validate prismpath/examples/code_nodes/pipeline.md && \$PRISMPATH_BIN validate prismpath/examples/cli_worker/ci_gate.md && \$PRISMPATH_BIN graph prismpath/gallery/incident_severity/incident_severity.md > /dev/null && \$PRISMPATH_BIN contract prismpath/gallery/incident_severity/incident_severity.md > /dev/null && \$PRISMPATH_BIN capability prismpath/gallery/incident_severity/incident_severity.md > /dev/null && \$PRISMPATH_BIN verify prismpath/gallery/incident_severity/incident_severity.md > /dev/null && bash prismpath/examples/pr_demo/demo.sh > /dev/null"
  else
    record "wheel built" FAIL "no wheel in $OUT/dist"
  fi
fi

if [ "$LEG" = "full" ] || [ "$LEG" = "rust" ]; then
  if ! command -v cargo > /dev/null; then record "rust prerequisite" BLOCKED "cargo not found"; else
    cargo --version > "$OUT/cargo-version.txt"
    export CARGO_TARGET_DIR="$OUT/cargo-target"
    run_gate "rust: workspace tests" "$OUT/cargo-test.log" bash -c "cd '$EXPORT' && cargo test --workspace -q"
    run_gate "rust: clippy, warnings denied" "$OUT/clippy.log" bash -c "cd '$EXPORT' && cargo clippy --workspace --all-targets -q -- -D warnings"
    # The four crates are packaged in one invocation from the workspace root, so a crate whose sibling's
    # new version is not yet on crates.io still resolves it: cargo stages the packages being assembled
    # as a local overlay of the registry. Packaged one at a time, prismpath-telemetry-rs 0.2.0 failed to
    # find prismpath-rs 0.2.0 before its publication (October 2026). The extracted candidates below are
    # still tested together and patched to one another, never against the registry.
    ALL_CRATES="-p prismpath-rs -p prismpath-telemetry-rs -p prismpath-hotswap-rs -p prismpath-preflight"
    for crate in prismpath-rs prismpath-telemetry-rs prismpath-hotswap-rs prismpath-preflight; do
      run_gate "rust: cargo package $crate" "$OUT/package-$crate.log" bash -c "cd '$EXPORT' && cargo package -q --allow-dirty --no-verify --list -p $crate > '$OUT/package-$crate.list' && cargo package -q --allow-dirty --no-verify $ALL_CRATES && ls '$OUT'/cargo-target/package/$crate-*.crate > /dev/null && grep -q 'tests/' '$OUT/package-$crate.list'"
      # The package is extracted for the candidate gate below. Testing it alone would resolve its
      # sibling crates from the registry, whose published API can lag the candidate, so the only
      # extracted test that means anything runs the four candidates together, patched to each other.
      run_gate "rust: extract package $crate" "$OUT/extracted-$crate.log" bash -c "rm -rf '$OUT/extracted-$crate' && mkdir '$OUT/extracted-$crate' && tar -xzf '$OUT'/cargo-target/package/$crate-*.crate -C '$OUT/extracted-$crate' && ls '$OUT'/extracted-$crate/$crate-*/tests > /dev/null"
    done
    run_gate "rust: extracted candidates resolve one another, not the registry" "$OUT/candidates.log" "$PYTHON" - "$OUT" <<'PY'
import json, shutil, subprocess, sys
from pathlib import Path
out = Path(sys.argv[1]); candidates = out / "candidates"
shutil.rmtree(candidates, ignore_errors=True); candidates.mkdir()
crates = ["prismpath-rs", "prismpath-telemetry-rs", "prismpath-hotswap-rs", "prismpath-preflight"]
members = {}
for crate in crates:
    extracted = next((out / f"extracted-{crate}").glob(f"{crate}-*"))
    shutil.copytree(extracted, candidates / extracted.name)
    (candidates / extracted.name / "Cargo.lock").unlink(missing_ok=True)
    members[crate] = extracted.name
# A workspace of the four extracted packages where every inter crate dependency is patched to the
# extracted candidate, so a crates.io release of the same version cannot satisfy it silently.
patch = "\n".join(f'{crate} = {{ path = "{name}" }}' for crate, name in members.items())
(candidates / "Cargo.toml").write_text('[workspace]\nresolver = "2"\nmembers = [' + ", ".join(f'"{name}"' for name in members.values()) + ']\n\n[patch.crates-io]\n' + patch + "\n")
env = dict(__import__("os").environ)
env["CARGO_TARGET_DIR"] = str(out / "cargo-target-candidates")
meta = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1"], cwd=candidates, env=env))
by_id = {package["id"]: package for package in meta["packages"]}
problems = []
for node in meta["resolve"]["nodes"]:
    package = by_id[node["id"]]
    if package["name"] not in crates:
        continue
    for dependency_id in node["dependencies"]:
        dependency = by_id[dependency_id]
        if dependency["name"] in crates:
            source = dependency.get("source") or dependency["manifest_path"]
            expected = str(candidates / members[dependency["name"]] / "Cargo.toml")
            if dependency["manifest_path"] != expected or dependency.get("source"):
                problems.append(f"{package['name']} resolved {dependency['name']} {dependency['version']} from {source}, not the candidate at {expected}")
            else:
                print(f"{package['name']} -> {dependency['name']} {dependency['version']} from the extracted candidate")
    # The requirement floor each crate declares for a sibling, against the candidate's version: a floor
    # below the candidate means a registry consumer could resolve an older sibling whose API lags. This
    # is reported for the publication decision, where versions are set; it does not fail preparation.
    for declared in package["dependencies"]:
        if declared["name"] in crates:
            floor = declared["req"]
            candidate_version = by_id[next(identifier for identifier in by_id if by_id[identifier]["name"] == declared["name"] and by_id[identifier]["manifest_path"].startswith(str(candidates)))]["version"]
            note = "matches" if floor.lstrip("^=") == candidate_version else "BELOW the candidate; set the floor to the candidate's version when publishing"
            print(f"publication note: {package['name']} requires {declared['name']} {floor}; candidate is {candidate_version}: {note}")
if problems:
    print("\n".join(problems)); sys.exit(1)
completed = subprocess.run(["cargo", "test", "--workspace", "-q"], cwd=candidates, env=env, capture_output=True, text=True)
print(completed.stdout[-1500:], completed.stderr[-1500:])
sys.exit(completed.returncode)
PY
  fi
fi

if [ "$LEG" = "full" ]; then
  run_gate "boundary: repository" "$OUT/boundary-repo.log" bash -c "cd '$EXPORT' && '$OUT/venv-full/bin/python' -m tools.check_boundary --repo '$REPO'"
  run_gate "compatibility" "$OUT/compatibility.log" bash -c "cd '$EXPORT' && '$OUT/venv-full/bin/python' -m tools.check_compatibility --repo '$EXPORT'"
  run_gate "product maintenance suite" "$OUT/tools-tests.log" bash -c "cd '$REPO' && '$OUT/venv-full/bin/python' -m pytest tools/tests -q -p no:cacheprovider"
  run_gate "cross language tests" "$OUT/cross-language.log" bash -c "cd '$EXPORT' && '$OUT/venv-full/bin/python' -m pytest prismpath/tests prismpath/telemetry/tests -q -p no:cacheprovider -m cross_language -rs"
  # One flow through everything: the installed wheel's command line, engine, compiler, signing, host,
  # ledger, wire, journal, preflight and console, and the same flow through the extracted Rust
  # candidates, compared at every seam. Runs from $OUT so the source tree cannot be imported.
  run_gate "end to end: Python chain from the wheel, Rust chain from the candidates, seams compared" "$OUT/end-to-end.log" bash -c "cd '$OUT' && '$OUT/venv-full/bin/python' '$EXPORT/tools/end_to_end.py' --candidates '$OUT/candidates' --out '$OUT/end-to-end'"
  run_gate "provenance check" "$OUT/provenance.log" bash -c "cd '$REPO' && '$OUT/venv-full/bin/python' -m tools.provenance check ${RESEARCH:+--research '$RESEARCH'}"
fi

# A leg passes only when every gate it is defined to run has recorded a status. A gate that never
# ran leaves no row, and a report with missing rows is a failure, not a pass by omission.
PYTHON_GATES=("build wheel and sdist" "build again for reproducibility" "reproducible wheel and sdist" "package boundary (wheel and sdist)" "python base: fresh venv install of the wheel" "python base: CLI, import and runtime asset smoke" "python base: installed package test (base extras only)" "python full: install with signing, control-plane, test extras" "python full: runtime suite against the installed package" "python full: skip budget" "python full: fuzz the predicate sandbox" "canary verifier from the installed module" "signed pack from the installed wheel: keygen, envelope, compile, pack, verify" "mission control: installed launch, defaults, assets, validate, facet, pack verify, sprint subprocess" "source archive: unpack, rebuild, install, promised tests present" "documentation: examples and quickstart commands")
RUST_GATES=("rust: workspace tests" "rust: clippy, warnings denied" "rust: cargo package prismpath-rs" "rust: extract package prismpath-rs" "rust: cargo package prismpath-telemetry-rs" "rust: extract package prismpath-telemetry-rs" "rust: cargo package prismpath-hotswap-rs" "rust: extract package prismpath-hotswap-rs" "rust: cargo package prismpath-preflight" "rust: extract package prismpath-preflight" "rust: extracted candidates resolve one another, not the registry")
FULL_GATES=("boundary: repository" "compatibility" "product maintenance suite" "cross language tests" "end to end: Python chain from the wheel, Rust chain from the candidates, seams compared" "provenance check")
EXPECTED=("export tracked tree")
case "$LEG" in
  full) EXPECTED+=("${PYTHON_GATES[@]}" "${RUST_GATES[@]}" "${FULL_GATES[@]}") ;;
  python) EXPECTED+=("${PYTHON_GATES[@]}") ;;
  rust) EXPECTED+=("${RUST_GATES[@]}") ;;
esac
for gate in "${EXPECTED[@]}"; do
  if ! grep -Fq "| $gate | " "$REPORT"; then record "missing gate: $gate" FAIL "the leg defines this gate and it recorded no status"; fi
done

# PrismPath judging its own release eligibility over the facts above (tools/release_policy.md). The
# decision is advisory: it can add a failure to this report, never remove one, and the exit status of
# this script stays the authority, so a defect in the engine cannot certify the engine.
if [ "$LEG" = "full" ] && [ -x "$OUT/venv-full/bin/python" ]; then
  if (cd "$EXPORT" && "$OUT/venv-full/bin/python" -m tools.release_eligibility --out "$OUT" --revision "$COMMIT" > "$OUT/release-eligibility.log" 2>&1); then
    record "release eligibility (PrismPath flow, advisory)" pass "$(head -c 160 "$OUT/release-eligibility.log")"
  else
    record "release eligibility (PrismPath flow, advisory)" FAIL "$(head -c 160 "$OUT/release-eligibility.log")"
  fi
fi

{
  echo
  echo "Python: $(cat "$OUT/python-version.txt" 2>/dev/null || echo 'not run'); cargo: $(cat "$OUT/cargo-version.txt" 2>/dev/null || echo 'not run')"
  echo
  if [ "$FAILED" = "0" ]; then echo "RESULT: all gates passed"; else echo "RESULT: FAILED gates present"; fi
} >> "$REPORT"
cat "$REPORT"
exit "$FAILED"
