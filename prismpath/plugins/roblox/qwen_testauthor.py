#!/usr/bin/env python3
"""qwen TEST-AUTHOR — qwen writes a Lune behavioral .spec.luau for a pure core, run via the game-shim.

This is the logic-verification half of "agents propose, gates dispose": gemma4+cecli builds the cores,
qwen (its own idle VRAM) writes behavioral tests the gate's lune_test_check then runs, so reducer-logic
bugs the compile/type gate is blind to turn the gate red automatically.

Usage:  python prismpath/qwen_testauthor.py <Core> [<Core> ...]   (e.g. Portal Tools)
Reusable: import write_spec_for(target) to wire into run_sprint after a core builds.
"""
import os
import re
import subprocess
import sys

import requests

PROJ = os.environ.get("SPRINT_PROJ") or os.getcwd()
QWEN_BASE = os.environ.get("QWEN_BASE", "http://127.0.0.1:8889/v1")
QWEN_MODEL = os.environ.get("QWEN_MODEL", "qwen25")
LUNE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "bin", "lune")
MAX_FIX = 1  # one self-correction attempt after a failing run

SHIM_NOTE = """The game-shim (tests/robloxshim.luau) loads the pure cores under Lune. A spec MUST start:
  local shim = require("../robloxshim")
  local <Core> = shim.require("core/<Core>")     -- and shim.require("core/Economy") etc. for any sibling it needs
Do NOT use `require("game...")` or a relative require of the core; ALWAYS go through shim.require.
A core that only reads one field of a dependency can be given a minimal stub table (e.g. { cash = 600 })."""

SYSTEM = ("You write concise, CORRECT Lune behavioral unit tests (.spec.luau) for pure Luau reducer modules. "
          "Assert the INTENDED behavior from the spec, exercising the real exported functions. "
          "Output ONLY raw Lua code — no markdown fences, no prose, no explanation.")

# Explicit, prominent facts — the GLOSSARY alone didn't stop the 7B hallucinating elements / mis-sequencing.
DOMAIN_FACTS = """CRITICAL DOMAIN FACTS — get these RIGHT or the test is wrong:
- The ONLY element ids are: "Sunstone", "Sapphire", "Emerald", "Onyx", "Diamond". There is NO Water/Fire/etc.
  Use only those 5 strings anywhere an ElementId / node element / pet color is needed.
- These are STATE-MACHINE reducers. An action is REJECTED (returns the SAME state, unchanged) when its
  preconditions don't hold. Model preconditions exactly:
    * Portal.ENTER requires state.location == "Hub" AND state.unlocked AND cash >= the map's unlockCost
      (the signature map "obelisk_vale" unlockCost is 500). After a successful ENTER you are in "Combat" —
      to test ENTER again you must RETURN to "Hub" first. Do NOT chain a second ENTER expecting it to behave
      like the first.
  Set up EACH test from a FRESH create()/begin() so its preconditions are clean; never assume a rejected
  action moves you somewhere — it leaves state IDENTICAL.
- To assert "rejected", check the returned state == the input state (same reference), not a guessed location."""


def _strip_fences(s: str) -> str:
    s = s.strip()
    s = re.sub(r"^```[a-zA-Z]*\n", "", s)
    s = re.sub(r"\n```$", "", s)
    return s.strip() + "\n"


def _qwen(messages: list, max_tokens: int = 3500) -> str:
    r = requests.post(QWEN_BASE + "/chat/completions",
                      json={"model": QWEN_MODEL, "messages": messages, "temperature": 0.2,
                            "max_tokens": max_tokens},
                      timeout=240)
    r.raise_for_status()
    return _strip_fences(r.json()["choices"][0]["message"]["content"])


def _read(path: str) -> str:
    try:
        return open(path, encoding="utf-8").read()
    except OSError:
        return ""


def _run_spec(rel: str):
    p = subprocess.run([LUNE, "run", rel], cwd=PROJ, capture_output=True, text=True, timeout=90)
    return p.returncode, (p.stdout + p.stderr).strip()


def write_spec_for(target: str) -> dict:
    core_src = _read(os.path.join(PROJ, f"src/shared/core/{target}.luau"))
    if not core_src.strip():
        return {"target": target, "ok": False, "note": "no core source"}
    template = _read(os.path.join(PROJ, "tests/core/Combat.spec.luau"))
    spec_md = _read(os.path.join(PROJ, f"specs/{target}.md"))
    rel = f"tests/core/{target}.spec.luau"

    user = (f"Write {rel}: Lune behavioral tests for the module below, matching the TEMPLATE's structure "
            f"EXACTLY (--!nonstrict header; `local shim = require(\"../robloxshim\")`; shim.require the cores; "
            f"a set of `local function` tests using assert(...); run them through pcall in a list and error with "
            f"the test name on failure; finish with a print). Cover the module's real behaviors + edge cases "
            f"(rejected actions returning the SAME state reference, sticky/idempotent rules, gates, defaults).\n\n"
            f"=== {DOMAIN_FACTS}\n\n"
            f"=== SHIM USAGE (mandatory) ===\n{SHIM_NOTE}\n\n"
            f"=== TEMPLATE (tests/core/Combat.spec.luau) — match this shape ===\n{template}\n\n"
            f"=== MODULE UNDER TEST: src/shared/core/{target}.luau ===\n{core_src}\n\n"
            f"=== SPEC (intended behavior): specs/{target}.md ===\n{spec_md[:6000]}\n\n"
            f"Output ONLY the Lua code for {rel}.")

    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
    spec = _qwen(messages)
    open(os.path.join(PROJ, rel), "w", encoding="utf-8").write(spec)
    rc, out = _run_spec(rel)

    fixes = 0
    while rc != 0 and fixes < MAX_FIX:
        fixes += 1
        messages.append({"role": "assistant", "content": spec})
        messages.append({"role": "user", "content":
                         f"Running `lune run {rel}` FAILED:\n{out[:900]}\n\n"
                         f"Fix the test file so it passes. Output ONLY the corrected Lua code."})
        spec = _qwen(messages)
        open(os.path.join(PROJ, rel), "w", encoding="utf-8").write(spec)
        rc, out = _run_spec(rel)

    return {"target": target, "ok": rc == 0, "rel": rel, "fixes": fixes,
            "lines": spec.count("\n") + 1, "out": out}


def main():
    targets = sys.argv[1:] or ["Portal"]
    for t in targets:
        r = write_spec_for(t)
        status = "PASS" if r.get("ok") else "FAIL"
        print(f"\n===== {t}: {status} (lines={r.get('lines')}, self-fixes={r.get('fixes')}) =====")
        print(r.get("out", r.get("note", ""))[-1200:])


if __name__ == "__main__":
    main()
