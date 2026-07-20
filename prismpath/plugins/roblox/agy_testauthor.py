#!/usr/bin/env python3
"""agy (Antigravity/Gemini) TEST-AUTHOR — the semantic upgrade over qwen_testauthor.

qwen-7B is a semantically-blind drafter: every failure we saw was a TEST bug it couldn't reason about
(mis-sequenced state machines, phantom gates, wrong ids). agy is a frontier model AND a CLI agent, so it
doesn't just draft — it READS the core, AUTHORS the spec, RUNS lune itself, reads the failure, and
SELF-CORRECTS to green. We are no longer the verify step; agy closes the loop.

Isolation: agy works in a COPIED staging tree of the project (its "own environment"), never the live repo,
with a lune binary placed inside so the sandbox can reach it. We trust-but-verify (re-run lune ourselves)
and merge only the green spec files back.

  Usage:  python prismpath/agy_testauthor.py <Core> [<Core> ...]      (e.g. Towers Resources)
Constraints honored: agy is on a LIMITED plan — one bounded call per core, no retry-spam, off the critical
path (a stall fails THIS core, nothing else). Always --sandbox --dangerously-skip-permissions.
"""
import os
import subprocess
import sys
import time

# Reuse the domain knowledge we already hardened for qwen — the 5 elements, state-machine preconditions.
from qwen_testauthor import DOMAIN_FACTS, SHIM_NOTE

LIVE = os.environ.get("SPRINT_PROJ") or os.getcwd()
STAGE = os.environ.get("AGY_STAGE") or (os.path.abspath(LIVE).rstrip("/") + ".agystage")
AGY = os.path.expanduser("~/.local/bin/agy")
LUNE_LIVE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "bin", "lune")
MODEL = os.environ.get("AGY_MODEL", "Gemini 3.5 Flash (High)")
PRINT_TIMEOUT = os.environ.get("AGY_PRINT_TIMEOUT", "3m")  # backstop: a hung remote fails fast, not in 8m

# Pacing (the endpoint throttles back-to-back calls; a live request streams stdout within ~5-10s — empirically
# 189B@5s, 600B@10s — while a throttled one emits NOTHING. So: space requests, and kill-retry on no-output).
PRE_SLEEP = int(os.environ.get("AGY_PRE_SLEEP", "30"))     # sleep before EACH request to dodge the throttle
STALL_CHECK = int(os.environ.get("AGY_STALL_CHECK", "27"))  # by now a working request has clearly streamed
ALIVE_BYTES = int(os.environ.get("AGY_ALIVE_BYTES", "150"))  # >this much stdout = it's working (probe: 189B@5s)
HARD_CAP = int(os.environ.get("AGY_HARD_CAP", "300"))       # a live request finishes in ~30-90s; cap the tail
MAX_RETRY = int(os.environ.get("AGY_MAX_RETRY", "1"))       # one kill+retry on an early stall


def _read(p):
    try:
        return open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


def refresh_stage():
    """Mirror the live (uncommitted) tree into the staging env and drop a lune binary inside it.
    `git init` the staging dir so agy's CLI project-root detection stays CONTAINED here and it can't
    walk up to the real repo (which is how it escaped to write 2/7 specs to the live tree last run)."""
    os.makedirs(STAGE, exist_ok=True)
    subprocess.run(["rsync", "-a", "--delete", "--exclude=.git", "--exclude=*.rbxl",
                    LIVE + "/", STAGE + "/"], check=True)
    subprocess.run(["cp", "-f", LUNE_LIVE, os.path.join(STAGE, "lune")], check=True)
    os.chmod(os.path.join(STAGE, "lune"), 0o755)
    if not os.path.isdir(os.path.join(STAGE, ".git")):
        subprocess.run(["git", "init", "-q"], cwd=STAGE, check=False)


def prompt_for(core: str) -> str:
    rel = f"tests/core/{core}.spec.luau"
    return f"""You are authoring a Lune behavioral unit-test file for a pure Luau reducer module in THIS workspace.

GOAL: write `{rel}` and drive it to GREEN. You have a terminal — use it.

STEPS (do them, don't just plan):
1. READ these files in the workspace to understand the exact contract:
   - src/shared/core/{core}.luau          (the module under test — its real exported functions + semantics)
   - specs/{core}.md                       (intended behavior, if present)
   - tests/robloxshim.luau                 (the test harness — how cores are loaded)
   - tests/core/Combat.spec.luau           (the TEMPLATE — match this file's shape EXACTLY)
2. WRITE `{rel}` matching the template's structure: `--!nonstrict` header; `local shim = require("../robloxshim")`;
   `shim.require("core/{core}")` (and shim.require any sibling cores it depends on); a set of `local function`
   tests using assert(...); run them via pcall in an ordered list, error with the test name on failure; finish
   with a print line. Cover the REAL behaviors + edge cases: rejected actions returning the SAME state reference,
   sticky/idempotent rules, gates, defaults, and any numeric/matchup math the module computes.
3. RUN it yourself from the workspace root:  ./lune run {rel}
4. If it FAILS, the bug is almost certainly in YOUR TEST, not the core — re-read the core and fix your
   assertions to match its ACTUAL behavior. Iterate until lune prints "...passed!". (If after careful reading
   you are convinced the CORE itself is wrong, STILL write a passing test of its actual current behavior, and
   describe the suspected core bug in your final summary — do NOT edit the core.)

{DOMAIN_FACTS}

=== SHIM USAGE (mandatory) ===
{SHIM_NOTE}

Only create/edit `{rel}` — do not modify the core, the shim, or any other file.
When done, reply with: the final lune output line, the number of tests, and any suspected-core-bug notes.
"""


def _agy_attempt(core: str) -> tuple:
    """One agy launch with early-stall detection. Returns (state, output); state is 'done' (process
    exited — spec may or may not be green) or 'stalled' (no stdout in the window, or blew the hard cap)."""
    logpath = os.path.join(STAGE, f".agy_{core}.log")
    cmd = [AGY, "-p", prompt_for(core),
           "--add-dir", STAGE, "--sandbox", "--dangerously-skip-permissions",
           "--model", MODEL, "--print-timeout", PRINT_TIMEOUT]
    with open(logpath, "w") as lf:
        p = subprocess.Popen(cmd, cwd=STAGE, stdout=lf, stderr=subprocess.STDOUT, text=True)
    # Early-stall window: a working request streams output within seconds; a throttled one stays silent.
    waited, alive = 0, False
    while waited < STALL_CHECK:
        time.sleep(3)
        waited += 3
        if p.poll() is not None:
            return "done", _read(logpath)            # finished fast (small cores do)
        if os.path.getsize(logpath) >= ALIVE_BYTES:
            alive = True
            break                                     # streaming -> it's working
    if not alive:
        p.kill()
        try:
            p.wait(timeout=10)
        except Exception:
            pass
        return "stalled", f"no stdout in {STALL_CHECK}s ({os.path.getsize(logpath)}B) — endpoint throttle"
    try:
        p.wait(timeout=HARD_CAP)                       # alive: let it finish, capped
    except subprocess.TimeoutExpired:
        p.kill()
        return "stalled", f"streamed then exceeded {HARD_CAP}s hard cap"
    return "done", _read(logpath)


def run_core(core: str) -> dict:
    rel = f"tests/core/{core}.spec.luau"
    state, agy_out = "stalled", ""
    for attempt in range(MAX_RETRY + 1):
        time.sleep(PRE_SLEEP)                          # space each request to dodge the throttle
        state, agy_out = _agy_attempt(core)
        if state == "done":
            break                                      # got a real run; verify it below
    if state != "done":
        return {"core": core, "ok": False, "stalled": True, "note": agy_out}

    # trust-but-verify: re-run lune ourselves on what agy produced. Prefer the staged file; fall back
    # to the live path in case agy wrote there directly (project-root escape). Verify wherever it landed.
    staged_spec = os.path.join(STAGE, rel)
    live_spec = os.path.join(LIVE, rel)
    src_spec = staged_spec if os.path.exists(staged_spec) else (live_spec if os.path.exists(live_spec) else None)
    if not src_spec:
        return {"core": core, "ok": False, "note": "agy produced no spec file", "agy_out": agy_out[-800:]}
    # verify in staging (the isolated toolchain); copy the candidate in first if it only exists live
    if src_spec == live_spec:
        subprocess.run(["cp", "-f", live_spec, staged_spec], check=True)
    v = subprocess.run([os.path.join(STAGE, "lune"), "run", rel], cwd=STAGE,
                       capture_output=True, text=True, timeout=120)
    green = v.returncode == 0 and "passed!" in (v.stdout + v.stderr)
    if green:  # merge the verified spec back into the live tree
        subprocess.run(["cp", "-f", staged_spec, live_spec], check=True)
    return {"core": core, "ok": green, "verify": (v.stdout + v.stderr).strip()[-400:],
            "merged": green, "agy_out": agy_out[-600:]}


def main():
    cores = sys.argv[1:] or ["Towers"]
    refresh_stage()
    for c in cores:
        print(f"\n===== agy authoring {c} (model: {MODEL}) =====", flush=True)
        r = run_core(c)
        status = "PASS (merged to live)" if r.get("ok") else ("STALLED" if r.get("stalled") else "FAIL")
        print(f"----- {c}: {status} -----")
        print("verify:", r.get("verify", r.get("note", "")))
        if r.get("agy_out"):
            print("agy said:", r["agy_out"])


if __name__ == "__main__":
    main()
