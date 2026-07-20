#!/usr/bin/env python3
"""agy SEMANTIC AUDIT — point agy (read-only) at a flow's files and have it report sequencing/edge-case bugs.

Complements the behavioral specs: those lock reducer logic; this catches cross-file ORDERING bugs (trigger
must fire before outcome), re-entrancy, double/lost credit, and reachable edge cases the type/compile gate
is blind to. agy reads the files itself in the staging tree and returns a triaged findings list — it does NOT
edit anything. Output is appended to <SPRINT_PROJ>/AUDIT_FINDINGS.md.

  Usage:  python prismpath/agy_audit.py [target ...]   (default: all targets below)

Reuses the paced/early-stall agy launcher from agy_testauthor (one call per target, throttle-safe).
"""
import os
import subprocess
import sys
import time

import agy_testauthor as A  # reuse STAGE, AGY, MODEL, pacing constants, _agy_attempt-style launcher

REPORT = os.path.join(A.LIVE, "AUDIT_FINDINGS.md")

TARGETS = {
    "combat_lifecycle": {
        "files": ["src/shared/core/Combat.luau", "src/shared/ports/CombatService.luau",
                  "src/shared/core/Waves.luau"],
        "focus": ("Per-tick event ordering in the combat run. Does every TRIGGER fire before its OUTCOME? "
                  "Check: wave spawn vs clear vs advance vs victory/defeat ordering; enemy-arrival damage "
                  "vs enemy removal; status (slow) decay timing; the cooldown gate on tower fire; any "
                  "iteration/index hazard when an action replaces state mid-loop; off-by-one on wave counts "
                  "or the final-wave victory."),
    },
    "run_handoff": {
        "files": ["src/shared/core/Portal.luau", "src/server/main.server.luau",
                  "src/shared/ports/CombatService.luau"],
        "focus": ("Entering and leaving a combat run. Check: drop STAGING vs CREDITING order on return; any "
                  "double-credit or lost-credit of drops/cash; re-entrancy (entering a portal while a run is "
                  "already active); cleanup of per-run state (combat slot, equipped weapon) on victory, "
                  "defeat, and manual abandon; whether the natural-end and manual-return paths agree."),
    },
    "economy_loop": {
        "files": ["src/shared/core/Economy.luau", "src/shared/ports/AppService.luau"],
        "focus": ("The tycoon earn/spend loop. Check: cash accrual vs spend ordering (can a purchase apply "
                  "before its debit, or debit without applying?); negative balances; prestige/ascension reset "
                  "ordering and what survives a reset; welcome-back/offline accrual edges; idempotency of the "
                  "per-frame tick."),
    },
    "flagged_reducers": {
        "files": ["src/shared/core/Resources.luau", "src/shared/core/InvestmentBank.luau",
                  "src/shared/core/ResourceConversion.luau"],
        "focus": ("TRIAGE three earlier-flagged issues — for EACH, say whether it is reachable in the live "
                  "wiring and whether it is MVP-BLOCKING or post-MVP: (1) Resources GATHER_NODE may return "
                  "state unchanged (harvest no-op stub); (2) InvestmentBank CLAIM trusts an arbitrary "
                  "action.reward and lacks bounds-checking on the index (state inflation); (3) "
                  "ResourceConversion.reduce may crash on a nil action (no guard before indexing action.type)."),
    },
}


def audit_prompt(name: str, spec: dict) -> str:
    files = "\n".join(f"   - {f}" for f in spec["files"])
    return f"""You are doing a READ-ONLY sequencing & edge-case audit of one flow in this Roblox/Luau game. Do
NOT edit any file. Read these files in the workspace and reason about them together:
{files}

FOCUS: {spec['focus']}

Method: trace the actual call/dispatch order across the files. A bug is "trigger fires AFTER its outcome",
a reachable crash/edge, a double- or lost- credit, a re-entrancy hole, or an off-by-one — backed by specific
file:line evidence. Ignore style. Only report things that are REAL and reachable in the live wiring.

Output ONLY a markdown list, one bullet per finding, each as:
- [BLOCKER|MAJOR|MINOR|OK] `file:line` — <what's wrong, the bad ordering/edge> → <the one-line fix>
If the flow is sound, emit a single `- [OK] ...` bullet saying so. Be concise and concrete."""


def run_target(name: str, spec: dict) -> str:
    # reuse the paced, early-stall launcher: build a temp "core" prompt via monkeypatch of prompt_for
    orig = A.prompt_for
    A.prompt_for = lambda _core: audit_prompt(name, spec)
    try:
        state, out = "stalled", ""
        for attempt in range(A.MAX_RETRY + 1):
            time.sleep(A.PRE_SLEEP)
            state, out = A._agy_attempt(name)
            if state == "done":
                break
    finally:
        A.prompt_for = orig
    return out if state == "done" else f"(audit stalled: {out})"


def main():
    targets = sys.argv[1:] or list(TARGETS.keys())
    A.refresh_stage()
    with open(REPORT, "a", encoding="utf-8") as f:
        f.write("\n# agy semantic audit — sequencing & edge cases\n")
    for t in targets:
        if t not in TARGETS:
            print(f"skip unknown target {t}")
            continue
        print(f"\n===== auditing {t} ({A.MODEL}) =====", flush=True)
        findings = run_target(t, TARGETS[t])
        block = f"\n## {t}\n{findings.strip()}\n"
        with open(REPORT, "a", encoding="utf-8") as f:
            f.write(block)
        print(findings.strip()[-1500:])
    print(f"\n>>> findings appended to {REPORT}")


if __name__ == "__main__":
    main()
