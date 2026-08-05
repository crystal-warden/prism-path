"""Generic TIMED + SUPERVISED agent build sprint — a 5-ROLE pipeline on the served model.

Evolves the old builder+critic loop into separated roles with hard boundaries (the architect never
builds; the coder never validates its own work):

  ARCHITECT  designs only  -> a persisted BLUEPRINT.md (file manifest + port contracts). No code.
  CODER      implements the blueprint (ideate + one critic-chosen feature per turn). No tests, no
             self-grading. Can remove a file with a `DELETE: <path>` line.
  TEST-AUTHOR writes/maintains the headless specs (the behavioral validation) — independent of the
             implementation. Owns specs; never touches impl. (Only when the gate has a spec layer.)
  GATE       deterministic validation (syntax/type/build/logic).  [gates.py / a gate plugin]
  FIXER      makes the SMALLEST change to satisfy the gate (impl only; specs are the authoritative
             contract — it conforms code to them, never edits them).
  CRITIC     reviews quality + architecture + blueprint adherence; picks the next step or says DONE.

Flow:  nudge -> ARCHITECT -(blueprint)-> CODER -(code)-> TEST-AUTHOR -(specs)-> GATE -> CRITIC -> loop

Runs on a WALL CLOCK (open-ended until a STOP file, or until the critic says DONE and the gate is
green), and escalates hard problems to a HELP.md file a supervisor answers out-of-band.

Help escalation has TWO triggers:
  1. agent-declared — any role emits a line `HELP_NEEDED: <specific question>`
  2. auto-detected  — the gate returns the SAME error signature N times in a row (default 3)
On escalation the driver appends an OPEN block to HELP.md and KEEPS WORKING. A supervisor adds an
`## ANSWER <id>` block; the driver injects it into the next turn, marks RESOLVED, and resumes.

Config (env):
  LLM_BASE, LLM_MODEL          served OpenAI-compatible endpoint
  SPRINT_PROJ                  output project dir (required)
  SPRINT_ARCH                  architecture contract file (default prismpath/APP_ARCHITECTURE.md)
  SPRINT_NUDGE | SPRINT_NUDGE_FILE   the goal (required; file wins if both set)
  SPRINT_GATE                  "browser" (default) | a gate-plugin name
  SPRINT_SECONDS               wall-clock budget; 0/unset = open-ended (until STOP file)
  SPRINT_MAX_NEW               generation budget per call (default 12000)
  SPRINT_STUCK_REPEAT          identical-error repeats before auto-escalate (default 3)
  SPRINT_FRESH                 "1" to wipe SPRINT_PROJ at start (default 1)

Live files written in SPRINT_PROJ: BLUEPRINT.md, STOP (touch to end), HELP.md, status.json, sprint.log
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

import requests

try:                                    # glass-window interaction log (best-effort, never fatal)
    from prismpath import interactions as _ix
except Exception:
    try:
        import interactions as _ix
    except Exception:
        _ix = None

try:                                    # Oblique-Strategies council dice + category-balance ledger
    from prismpath import dice
except Exception:
    try:
        import dice
    except Exception:
        dice = None

BASE = os.environ.get("LLM_BASE", "http://127.0.0.1:8888/v1")
MODEL = os.environ.get("LLM_MODEL", "gemma4")
PROJ = os.environ["SPRINT_PROJ"]
GATE = os.environ.get("SPRINT_GATE", "browser")
SECONDS = int(os.environ.get("SPRINT_SECONDS", "0"))          # 0 = open-ended
MAX_ITERS = int(os.environ.get("SPRINT_MAX_ITERS", "0"))      # 0 = no cap (mission-control iteration cap)
MAX_NEW = int(os.environ.get("SPRINT_MAX_NEW", "12000"))
ENABLE_THINKING = os.environ.get("SPRINT_ENABLE_THINKING", "0") == "1"  # let the model reason before emitting files
STUCK_REPEAT = int(os.environ.get("SPRINT_STUCK_REPEAT", "3"))
REGRESS_LIMIT = int(os.environ.get("SPRINT_REGRESS_LIMIT", "4"))   # consecutive-invalid before revert
FRESH = os.environ.get("SPRINT_FRESH", "1") == "1"
LEDGER = os.environ.get("SPRINT_LEDGER", "0") == "1"   # opt-in git Flow-Ledger of gate-green proofs
_LEDGER = None                                          # lazy Ledger instance (ledger imported only if on)
_RUN_ID = None                                          # minted once per sprint when LEDGER is on
# SPRINT_FLOW=1 (dogfood, roadmap item #6): run the inner loop as flows/sprint_loop.md — the loop's
# SEMANTICS (gate routing, 3x-same-error, escalation, per-unit proofs) live in the document; this
# driver keeps only the harness concerns (wall clock, pause, heartbeat, endpoint checks).
FLOW_MODE = os.environ.get("SPRINT_FLOW", "0") == "1"

if os.environ.get("SPRINT_NUDGE_FILE"):
    NUDGE = open(os.environ["SPRINT_NUDGE_FILE"], encoding="utf-8").read()
else:
    NUDGE = os.environ["SPRINT_NUDGE"]

# The GOAL is injected into EVERY turn (not just ideate) so a resumed sprint never loses its objective.
GOAL = ("PROJECT GOAL — stay strictly on this; do NOT drift into a different kind of app:\n"
        + NUDGE + "\n\n")

STOP_FILE = os.path.join(PROJ, "STOP")
PAUSE_FILE = os.path.join(PROJ, "PAUSE")          # mission-control pause/resume (loop waits while present)
HELP_FILE = os.path.join(PROJ, "HELP.md")
STATUS_FILE = os.path.join(PROJ, "status.json")
LOG_FILE = os.path.join(PROJ, "sprint.log")
BLUEPRINT_FILE = os.path.join(PROJ, "BLUEPRINT.md")
LASTGOOD = PROJ.rstrip("/") + ".lastgood"   # sibling dir (outside PROJ so gates/load_project don't scan it)

from prismpath.gates import token_est   # noqa: E402
# Gate selection (the ports/adapters seam). The engine itself is target/platform-agnostic: "browser" is the
# built-in default gate; ANY other value is an optional plugin loaded via plugins.load_gate. The
# engine only ever touches the plugin interface, never a target's specifics.
GATE_PLUGIN = None
if GATE == "browser":
    from prismpath.gates import validate_browser as validate_fn    # noqa: E402
    HAS_SPEC_LAYER = False  # the browser gate is playwright-on-the-app, not unit specs
else:
    from prismpath.plugins import load_gate   # noqa: E402
    GATE_PLUGIN = load_gate(GATE)
    validate_fn = GATE_PLUGIN.validate
    HAS_SPEC_LAYER = GATE_PLUGIN.HAS_SPEC_LAYER  # the plugin's gate runs specs the test-author owns

# Architecture contract: explicit SPRINT_ARCH wins; else the active gate plugin's contract; else browser default.
ARCH_FILE = (os.environ.get("SPRINT_ARCH")
             or (getattr(GATE_PLUGIN, "ARCH_PATH", "") if GATE_PLUGIN else "")
             or "prismpath/APP_ARCHITECTURE.md")
ARCH = open(ARCH_FILE, encoding="utf-8").read()

# --- the lazy-dev / verification / help posture baked into every role (AGENT_PRINCIPLES #5-8) ---
POSTURE = (
    "Standing rules: (1) LAZY-DEV — the LEAST code that works; YAGNI; prefer stdlib/native features/"
    "existing files; no abstractions, deps, or boilerplate nobody asked for; deletion over addition; "
    "fewest files. (2) Build for the REAL target, not a stub. (3) If you are TRULY stuck (an ambiguity "
    "you can't resolve, a contract you cannot satisfy after trying), emit ONE line "
    "`HELP_NEEDED: <specific question>` and a human will answer — do NOT fake or stub past it.")

# ARCHITECT — designs only, hands off. Never writes code.
ARCHITECT_SYS = (
    "You are a software ARCHITECT. You DESIGN ONLY and then hand off to a coder — you NEVER write "
    "implementation code and you NEVER emit files. From the GOAL and the architecture contract, produce "
    "the SMALLEST blueprint that delivers it (YAGNI; fewest files). Output EXACTLY:\n"
    "1. one line: the approach.\n"
    "2. `## FILE MANIFEST` — one bullet per file as `- <relative/path> — <ring> — <single responsibility>`. "
    "List every path ONCE, in ONE extension; include the spec files the test-author will fill.\n"
    "3. `## CONTRACTS` — the key port/type signatures in one fenced code block.\n"
    "Output ONLY this blueprint. No prose beyond the above, NO implementation, NO FILE: blocks. " + POSTURE)

# CODER — implements the blueprint. No tests, no self-validation.
BUILDER_SYS = (
    "You are an inventive, detail-oriented CODER. You implement the ARCHITECT's blueprint EXACTLY, writing "
    "clean, small, single-responsibility files that conform to the architecture contract. You do NOT write "
    "test specs (a separate test author owns all tests) and you do NOT judge or validate your own output "
    "(a deterministic gate + a reviewer do that) — just implement. To remove a file, emit a line "
    "`DELETE: <relative/path>` (this actually deletes it; do not leave orphans). " + POSTURE)

# TEST-AUTHOR — writes the behavioral validation, independent of the implementation.
TESTER_SYS = (
    "You are an adversarial TEST AUTHOR. You write ONLY tests, NEVER implementation. Following the "
    "architecture contract's testing section, write/maintain headless specs that exercise the PURE CORE "
    "modules' behaviour, edge cases, and contract violations — INDEPENDENT of how they're implemented "
    "(test the CONTRACT; try to break it). Keep specs small and assert-based. Emit ONLY spec files in "
    "FILE: format. " + POSTURE)

# FIXER — minimal repair to satisfy the gate. Conforms code to the specs; never edits specs.
FIXER_SYS = (
    "You are a careful FIXER/debugger. Make the SMALLEST change that makes the FAILING validation pass — "
    "nothing more. Do NOT add features, do NOT refactor files that already work, do NOT rename. The test "
    "specs are the AUTHORITATIVE contract (written by a separate test author): if a test fails, fix the "
    "CODE to satisfy it — NEVER edit a spec. Preserve the blueprint's manifest; if the error is a "
    "duplicate/orphan file, emit `DELETE: <path>`. " + POSTURE)

# CRITIC — reviews only; never writes code.
CRITIC_SYS = (
    "You are a discerning REVIEWER with strong taste. You enforce the architecture, the BLUEPRINT, and the "
    "lazy-dev posture (reward simplicity/deletion; flag scaffolding built ahead of need, duplication, and "
    "drift from the manifest). You review ONLY — you never write code. " + POSTURE)

# --- agent backend: the served model (chat) OR the Hermes role-swarm (one memory-forming agent/role) ---
AGENT_BACKEND = os.environ.get("SPRINT_AGENT", "served")        # "served" | "swarm"
_ROLE_OF = {ARCHITECT_SYS: "architect", BUILDER_SYS: "coder", TESTER_SYS: "test-author",
            FIXER_SYS: "fixer", CRITIC_SYS: "critic"}
if AGENT_BACKEND == "swarm":
    from prismpath.hermes_swarm import (dispatch as _swarm_dispatch, setup_roles as _setup_roles,  # noqa: E402
                                     reflect as _reflect)
    _setup_roles()

# --- execution backend: how a build/fix step EDITS the tree ---
#   "agent" (default) = the role agent emits WHOLE files (the original path).
#   "cecli"           = drive cecli to DIFF-EDIT the real tree, gate-looped (proven to beat whole-file
#                       regen: no require-scrambling, minimal targeted edits). Council still = the brain.
EXEC = os.environ.get("SPRINT_EXEC", "agent")                   # "agent" | "cecli"
SPRINT_DIR = os.path.dirname(os.path.abspath(__file__))
CECLI = os.environ.get("SPRINT_CECLI_BIN", os.path.expanduser("~/.cecli-venv/bin/cecli"))
CECLI_REFLECTIONS = int(os.environ.get("SPRINT_CECLI_REFLECTIONS", "3"))  # was 5: 5 failed reflections x slow large-context builds = 20-min CECLI_TIMEOUT spins; 3 fails fast + the 3x-same-error auto-stuck detector escalates instead
CECLI_TIMEOUT = int(os.environ.get("SPRINT_CECLI_TIMEOUT", "1200"))   # bound stalled-completion hangs
CECLI_SETTINGS = os.environ.get("SPRINT_CECLI_SETTINGS", "")     # model-settings yml (e.g. no-think for qwen)
CECLI_TESTCMD = os.environ.get("SPRINT_CECLI_TESTCMD",           # default: the gate script over PROJ
                               f"bash {os.path.join(SPRINT_DIR, 'gate_test.sh')} {PROJ}")

# --- consistency AUDITOR: a qwen coder checks each just-built file against the GLOSSARY (opt-in SPRINT_AUDIT=1).
#     Advisory only (logs drift flags), runs in qwen's idle window after a gemma4 build; never blocks. ---
AUDIT = os.environ.get("SPRINT_AUDIT", "0") == "1"
GLOSSARY_FILE = os.environ.get("SPRINT_GLOSSARY", os.path.join(PROJ, "specs", "GLOSSARY.md"))

# --- frontier auto-unblocker: when the swarm is AUTO-STUCK (3x the same gate error), hand it to the
#     Antigravity CLI (agy) to fix autonomously BEFORE escalating to a human. Opt-in (SPRINT_AGY=1).
#     Sandboxed file-edits only (run_sprint re-runs the gate to verify); one dispatch per error signature. ---
AGY = os.environ.get("SPRINT_AGY", "0") == "1"
AGY_BIN = os.environ.get("SPRINT_AGY_BIN", os.path.expanduser("~/.local/bin/agy"))
AGY_MODEL = os.environ.get("SPRINT_AGY_MODEL", "gemini-3.1-pro")   # the model ID (binary), not the display name
AGY_SANDBOX = os.environ.get("SPRINT_AGY_SANDBOX", "1") == "1"     # restrict terminal; file-edits still apply
AGY_TIMEOUT = int(os.environ.get("SPRINT_AGY_TIMEOUT", "900"))
AGY_MAX = int(os.environ.get("SPRINT_AGY_MAX", "4"))              # cap frontier dispatches per run

# --- spec-driven sprint mode: build each named module to green in DEPENDENCY ORDER from its
#     specs/<Module>.md contract — a deterministic alternative to the council's dice exploration.
#     Enabled when both SPRINT_SPEC_DIR and SPRINT_SPEC_ORDER are set. ---
SPEC_DIR = os.environ.get("SPRINT_SPEC_DIR", "")
SPEC_ORDER = [s.strip() for s in os.environ.get("SPRINT_SPEC_ORDER", "").split(",") if s.strip()]
SPEC_MODE = bool(SPEC_DIR and SPEC_ORDER)

# --- KG-driven STEPPED spec mode: execute ONE structured spec (its `## ` requirements) one node at a time,
#     ordered + tracked by a knowledge graph (deterministic — the graph, not the council, decides what is
#     done + what is next). The spec is ingested whole; each step embeds only that requirement's section. ---
SPEC_FILE = os.environ.get("SPRINT_SPEC_FILE", "")          # e.g. specs/INTEGRATION.md (rel to PROJ or abs)
KG_PATH = os.environ.get("SPRINT_KG", "")                   # e.g. specs/INTEGRATION.kg.json; default derived
KG_MODE = bool(SPEC_FILE)
if KG_MODE and not KG_PATH:
    KG_PATH = os.path.splitext(SPEC_FILE)[0] + ".kg.json"

# --- RAG: the Retriever role — ground the coder in retrieved real docs (opt-in via SPRINT_RAG=1) ---
#   gemma4 demonstrably USES injected docs where it lacks knowledge (rag_worthit contrast +0.833),
#   so per build step we retrieve the most relevant target docs and inject them into the coder prompt.
RAG = os.environ.get("SPRINT_RAG", "0") == "1"
RAG_INDEX = os.environ.get("SPRINT_RAG_INDEX") or (getattr(GATE_PLUGIN, "RAG_INDEX", "") if GATE_PLUGIN else "")
RAG_K = int(os.environ.get("SPRINT_RAG_K", "4"))

# --- supervisor lessons: hard-won project rules ("my answers") injected into every coder prompt.
# Always-on (SPRINT_LESSONS=0 to disable); a gate plugin auto-loads its own ruleset. Also lives in the
# RAG corpus (source `prismpath-lessons`) so it is retrievable, per the "in the docs AND the prompts" ask.
LESSONS_ON = os.environ.get("SPRINT_LESSONS", "1") == "1"
LESSONS_FILE = os.environ.get("SPRINT_LESSONS_FILE") or (
    getattr(GATE_PLUGIN, "LESSONS_PATH", "") if GATE_PLUGIN else "")


def _load_lessons() -> str:
    if not (LESSONS_ON and LESSONS_FILE and os.path.isfile(LESSONS_FILE)):
        return ""
    try:
        txt = open(LESSONS_FILE, encoding="utf-8").read().strip()
        return ("\n\n" + txt + "\n") if txt else ""
    except Exception:
        return ""


LESSONS_BLOCK = _load_lessons()


def _doc_block(hits) -> str:
    if not hits:
        return ""
    b = "## Relevant OFFICIAL documentation (use these real APIs — do not guess):\n"
    for h in hits:
        b += f"\n--- {h['source']}/{h['path']} ---\n{h['text']}\n"
    return b


def retrieve_docs(query: str) -> str:
    """Retriever role: fetch target docs for `query`, return an injectable doc block ('' if off/empty).
    Lazy + defensive — a missing retriever/deps degrades to no grounding, never breaks the sprint."""
    if not RAG:
        return ""
    try:
        from prismpath import retriever as _rtr
    except Exception:
        try:
            import retriever as _rtr
        except Exception:
            return ""
    try:
        hits = _rtr.retrieve(query, RAG_K, RAG_INDEX)
    except Exception as e:
        log(f"    [rag] retrieve failed: {str(e)[:100]}")
        return ""
    block = _doc_block(hits)
    if _ix:
        _ix.record("retriever", "retriever", query, block or "(no hits)", phase="retrieve", hits=len(hits))
    log(f"    [rag] {len(hits)} docs grounding: {query[:55]}")
    return ("\n\n" + block) if block else ""


def _cecli_run(message: str, focus: list, label: str = "build") -> dict:
    """One cecli diff-edit pass over PROJ, gate-looped via --auto-test. Returns the reloaded file tree.
    cecli owns the inner build->gate->fix loop; the swarm council decides WHAT this step should do."""
    focus = sorted({f for f in focus if f and os.path.isfile(os.path.join(PROJ, f))})
    args = [CECLI, "--model", f"openai/{MODEL}", "--openai-api-base", BASE,
            "--edit-format", "diff", "--map-tokens", "2048",
            "--auto-test", "--test-cmd", CECLI_TESTCMD, "--no-auto-lint",
            "--max-reflections", str(CECLI_REFLECTIONS),
            "--no-git", "--yes", "--no-stream", "--disable-playwright"]
    if CECLI_SETTINGS:
        args += ["--model-settings-file", CECLI_SETTINGS]
    args += focus + ["--message", message]
    env = dict(os.environ, OPENAI_API_KEY=os.environ.get("OPENAI_API_KEY", "dummy"))
    _t0 = time.time()
    # liveness: a cecli build runs for minutes and only logs on completion, so the Lens looks frozen.
    # Emit a start marker so the feed shows the build is underway the moment it kicks off.
    if _ix:
        _ix.record("cecli", label, f"build started — focus: {', '.join(focus)}",
                   "⏳ cecli diff-edit + auto-test in progress (runs for several minutes)…", phase=label)
    out, rc = "", None
    try:
        r = subprocess.run(args, cwd=PROJ, env=env, timeout=CECLI_TIMEOUT,
                           capture_output=True, text=True)
        rc = r.returncode
        out = (r.stdout or "") + (("\n--- stderr ---\n" + r.stderr) if r.stderr else "")
        log(f"    [cecli] rc={rc} (focus={','.join(focus) or 'repo-map'})")
    except subprocess.TimeoutExpired:
        out = f"(cecli timed out after {CECLI_TIMEOUT}s)"
        log(f"    [cecli] timeout after {CECLI_TIMEOUT}s")
    except Exception as e:
        out = f"(cecli error: {e})"
        log(f"    [cecli] error: {str(e)[:120]}")
    if _ix:
        _ix.record("cecli", label, message, out, phase=label,
                   dur_ms=int((time.time() - _t0) * 1000), rc=rc,
                   focus=",".join(focus))
    # guard: cecli/gemma4 occasionally writes a file at a DOUBLED nested path (e.g.
    # core/core/X.js). RELOCATE it to the de-doubled canonical path so the work is
    # KEPT (deleting would lose the just-built module and force a rebuild churn); fall back to delete
    # only when we can't compute a canonical path or a canonical copy already exists.
    # generic: relocate over the gate plugin's declared source extensions (none -> no-op for the browser gate)
    _exts = getattr(GATE_PLUGIN, "FILE_EXTS", ()) if GATE_PLUGIN else ()
    _relocatable: list = []
    for _ext in _exts:
        _relocatable += glob.glob(os.path.join(PROJ, "**", "*" + _ext), recursive=True)
    for f in _relocatable:
        rel = os.path.relpath(f, PROJ)
        if not re.search(r"^(src|tests)/.+/src/", rel):
            continue
        m = re.match(r"^((?:src|tests)/(?:[^/]+/)+?)(?=\1)", rel)   # immediately-repeated path root (ANY depth)
        fixed = rel[len(m.group(1)):] if m else None
        try:
            if fixed and fixed != rel and not os.path.exists(os.path.join(PROJ, fixed)):
                dst = os.path.join(PROJ, fixed)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.move(f, dst)
                log(f"    [cecli] relocated misplaced {rel} -> {fixed}")
            else:
                os.remove(f)
                log(f"    [cecli] pruned misplaced file {rel}")
        except OSError:
            pass
    return load_project()


def _src_context() -> list:
    """Pure core + ports source files — always handed to cecli so it can SEE the contract it's
    editing against (the #1 churn cause was cecli lacking the core module and asking for it in prose).

    Also includes the server ADAPTERS + the composition roots (main.server, client). Integration-phase
    churn cause #2: when wiring main.server, cecli couldn't see the adapters (e.g. CombatWorldAdapter) it
    must COMPOSE, so it improvised wrong port tables. The adapters ARE the port implementations the root
    wires — cecli needs them in context. (world/ is excluded: bulky scenery, never part of the contract.)"""
    out = []
    # In KG integration mode the GLOSSARY + the requirement spec (both embedded in the build prompt) ARE
    # the core contracts, so SKIP the pure cores here: dumping all ~44 made every wiring build a ~55-file,
    # 20-min context that blew CECLI_TIMEOUT and spun without finishing its reflections. Wiring needs the
    # ports, the adapters (the port implementations it composes), and the composition roots — that's it.
    # The target LAYOUT (source dirs, core dir, entry files, file extensions) is provided by the gate plugin;
    # the engine itself knows no project structure. Empty (no plugin / browser gate) -> no focus files collected.
    _exts = tuple(getattr(GATE_PLUGIN, "FILE_EXTS", ()) if GATE_PLUGIN else ())
    subs = (getattr(GATE_PLUGIN, "KG_SOURCE_DIRS" if KG_MODE else "SOURCE_DIRS", ()) if GATE_PLUGIN else ())
    for sub in subs:
        d = os.path.join(PROJ, sub)
        if os.path.isdir(d):
            out += [os.path.join(sub, f) for f in os.listdir(d) if f.endswith(_exts)]
    # KG mode skips the bulk source dir above (avoids the timeout). But a spec that EDITS those modules needs to
    # SEE them — so include ONLY the ones the spec text references by name. Lean, but un-blinds editing specs.
    cdir_rel = getattr(GATE_PLUGIN, "CORE_DIR", "") if GATE_PLUGIN else ""
    cdir = os.path.join(PROJ, cdir_rel) if cdir_rel else ""
    if KG_MODE and cdir and os.path.isdir(cdir):
        spec_txt = ""
        try:
            spec_txt = open(_abs(SPEC_FILE), encoding="utf-8", errors="ignore").read()
        except OSError:
            pass
        for f in sorted(os.listdir(cdir)):
            if f.endswith(_exts):
                stem = os.path.splitext(f)[0]
                if re.search(r"\b" + re.escape(stem) + r"\b", spec_txt):
                    out.append(os.path.join(cdir_rel, f))
    for f in (getattr(GATE_PLUGIN, "ENTRY_FILES", ()) if GATE_PLUGIN else ()):
        if os.path.isfile(os.path.join(PROJ, f)):
            out.append(f)
    return out


def cecli_build(files: dict, instruction: str, target: str, blueprint: str) -> dict:
    """CECLI build step: implement ONE council-chosen action via diff-editing, looped to green."""
    # Target-specific build conventions (a plugin's strict-mode / wiring / surfacing rules) live in the gate
    # plugin; the engine itself only states GENERIC build discipline. Empty for the generic/browser gate.
    def _plugin_rules(attr: str) -> str:
        r = getattr(GATE_PLUGIN, attr, "") if GATE_PLUGIN else ""
        return ("\n" + r) if r else ""
    if SPEC_MODE:
        # Spec-driven build: the embedded spec + GLOSSARY (in `instruction`) ARE the contract — no blueprint/ARCH.
        msg = (GOAL + LESSONS_BLOCK
               + f"\n\nTASK: {instruction}\nTarget file: {target}.\n"
               + "Rules: implement EXACTLY the embedded spec; least code; make small targeted edits; reference "
               "other modules ONLY by their exact GLOSSARY type names and function signatures. Keep the test "
               "command passing." + _plugin_rules("BUILD_RULES_SPEC"))
    else:
        msg = (GOAL + ARCH + "\n\nAPPROVED BLUEPRINT (conform to it):\n" + blueprint
               + LESSONS_BLOCK
               + retrieve_docs(f"{instruction}  ({target})")
               + f"\n\nTASK (serve the GOAL): {instruction}\nTarget file: {target}.\n"
               + "Rules: least code; make SMALL targeted edits, do NOT rewrite files that already pass. If you "
               "rename or add ANY symbol, update ALL call sites INCLUDING tests — search the repo for the old "
               "name first so nothing is left stale. Keep the test command passing." + _plugin_rules("BUILD_RULES"))
    if _ix:
        _ix.set_phase("build")
    if SPEC_MODE:
        # pure-core build: focus = target + only the already-built IN-LAYER (combat) cores it can depend on.
        # The full contract is embedded in the message; handing cecli all ~36 core modules just bloated the
        # context (10-20 min builds, timeouts). Cross-layer dep contracts are described in the spec text.
        _cdir = getattr(GATE_PLUGIN, "CORE_DIR", "") if GATE_PLUGIN else ""
        _ext = (getattr(GATE_PLUGIN, "FILE_EXTS", ()) or ("",))[0] if GATE_PLUGIN else ""
        _corep = lambda x: os.path.join(_cdir, f"{x}{_ext}")
        built = [_corep(x) for x in SPEC_ORDER
                 if _cdir and _corep(x) != target and os.path.isfile(os.path.join(PROJ, _corep(x)))]
        focus = [target] + built
    else:
        focus = [target] + _src_context()
    return _cecli_run(msg, focus, label="build")


def cecli_fix(files: dict, last_error: str, answer: str, blueprint: str) -> dict:
    """CECLI fix step: smallest change to make the gate pass, supervisor guidance honored."""
    hint = f"\n\nA SUPERVISOR PROVIDED THIS GUIDANCE — follow it:\n{answer}\n" if answer else ""
    named = sorted(set(re.findall(r"([\w./\-]+\.(?:js|mjs|html|css|json))", last_error)))
    msg = (GOAL + ARCH + "\n\nAPPROVED BLUEPRINT (preserve it):\n" + blueprint
           + f"\n\nThe project FAILS its test command:\n{last_error}{hint}\n\n"
           "Make the SMALLEST change so the test command passes. Conform to the architecture; do NOT "
           "refactor files that already work; if a test references a renamed/removed symbol, reconcile it.")
    if _ix:
        _ix.set_phase("fix")
    return _cecli_run(msg, named + _src_context(), label="fix")


def agent_call(system: str, user: str, max_new: int, temp: float) -> str:
    """Dispatch one role turn. Swarm mode routes to that role's Hermes agent (persona = SOUL.md, so
    the system prompt is carried by the agent); served mode is the single served model with retry."""
    if AGENT_BACKEND == "swarm":
        return _swarm_dispatch(_ROLE_OF.get(system, "coder"), user)
    return chat(system, user, max_new, temp)


FILE_RE = re.compile(r"FILE:\s*([^\n`]+?)\s*\n+```[a-zA-Z0-9]*\n(.*?)```", re.DOTALL)
HELP_RE = re.compile(r"HELP_NEEDED:\s*(.+)")
DELETE_RE = re.compile(r"^\s*DELETE:\s*([^\n`]+?)\s*$", re.MULTILINE)


def log(msg: str):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


def chat(system: str, user: str, max_new: int, temp: float) -> str:
    """Call the served model with retry — a transient HTTP error must NOT kill an unattended sprint."""
    last = None
    _t0 = time.time()
    for attempt in range(4):
        try:
            r = requests.post(BASE.rstrip("/") + "/chat/completions", json={
                "model": MODEL, "messages": [{"role": "system", "content": system},
                                              {"role": "user", "content": user}],
                "max_tokens": int(max_new), "temperature": temp, "stream": False,
                "chat_template_kwargs": {"enable_thinking": ENABLE_THINKING}}, timeout=600)
            r.raise_for_status()
            out = (r.json()["choices"][0].get("message") or {}).get("content", "") or ""
            if _ix:
                _ix.record("served", _ROLE_OF.get(system, "?"), user, out,
                           dur_ms=int((time.time() - _t0) * 1000))
            return out
        except Exception as e:
            last = e
            log(f"    [chat] attempt {attempt + 1}/4 failed: {str(e)[:120]}")
            time.sleep(5 * (attempt + 1))
    raise last


def parse_files(text: str) -> dict:
    out = {}
    for m in FILE_RE.finditer(text):
        path = m.group(1).strip().lstrip("./")
        if path and ".." not in path:
            out[path] = m.group(2).rstrip("\n") + "\n"
    return out


def parse_deletes(text: str) -> list:
    return [d.strip().lstrip("./") for d in DELETE_RE.findall(text)
            if d.strip() and ".." not in d]


def _is_spec(path: str) -> bool:
    sfx = tuple(getattr(GATE_PLUGIN, "SPEC_SUFFIXES", ()) if GATE_PLUGIN else ())
    return bool(sfx) and path.endswith(sfx)


def _is_core(path: str) -> bool:
    """A pure-core/port module the test-author can exercise headlessly (plugin-defined layers)."""
    dirs = tuple(getattr(GATE_PLUGIN, "TESTABLE_DIRS", ()) if GATE_PLUGIN else ())
    exts = tuple(getattr(GATE_PLUGIN, "FILE_EXTS", ()) if GATE_PLUGIN else ())
    return bool(dirs) and path.startswith(dirs) and path.endswith(exts) and not _is_spec(path)


def apply_deletes(files: dict, dels: list) -> list:
    done = []
    for d in dels:
        files.pop(d, None)
        ap = os.path.join(PROJ, d)
        try:
            if os.path.isfile(ap):
                os.remove(ap)
                done.append(d)
        except OSError:
            pass
    return done


def write_project(files: dict):
    os.makedirs(PROJ, exist_ok=True)
    if GATE == "browser":
        with open(os.path.join(PROJ, "package.json"), "w") as fh:
            fh.write('{"type":"module"}\n')
    for path, content in files.items():
        ap = os.path.join(PROJ, path)
        os.makedirs(os.path.dirname(ap) or PROJ, exist_ok=True)
        with open(ap, "w", encoding="utf-8") as fh:
            fh.write(content)


def manifest(files: dict) -> str:
    lines = []
    for p in sorted(files):
        first = next((l.strip(" /*#<!-") for l in files[p].splitlines()
                      if l.strip() and not l.strip().startswith("import")), "")
        lines.append(f"  - {p} ({token_est(files[p])} tok): {first[:70]}")
    return "\n".join(lines)


_SRC_EXT = (".html", ".js", ".mjs", ".css", ".json")
_NON_SRC = {"package.json", "status.json", "HELP.md", "sprint.log", "STOP", "NUDGE.md",
            "orch_run.out", "BLUEPRINT.md"}


def load_project() -> dict:
    """Load existing source files from PROJ into the in-memory map — so a crashed sprint RESUMES
    from disk instead of re-ideating and losing work (the box is flaky; restarts must be cheap)."""
    files = {}
    for f in glob.glob(os.path.join(PROJ, "**", "*"), recursive=True):
        if not os.path.isfile(f) or "/node_modules/" in f:
            continue
        rel = os.path.relpath(f, PROJ)
        if rel in _NON_SRC or not rel.endswith(_SRC_EXT):
            continue
        try:
            files[rel] = open(f, encoding="utf-8").read()
        except Exception:
            pass
    return files


def snapshot_green(files: dict):
    """Checkpoint the current VALID build to the sibling last-good dir (regression guard)."""
    if os.path.isdir(LASTGOOD):
        shutil.rmtree(LASTGOOD, ignore_errors=True)
    for path, content in files.items():
        ap = os.path.join(LASTGOOD, path)
        os.makedirs(os.path.dirname(ap) or LASTGOOD, exist_ok=True)
        open(ap, "w", encoding="utf-8").write(content)


def restore_green() -> dict:
    """Revert: wipe current source files, restore the last-good snapshot. Returns the files map."""
    for f in glob.glob(os.path.join(PROJ, "**", "*"), recursive=True):
        if os.path.isfile(f):
            rel = os.path.relpath(f, PROJ)
            if rel not in _NON_SRC and rel.endswith(_SRC_EXT):
                os.remove(f)
    files = {}
    for f in glob.glob(os.path.join(LASTGOOD, "**", "*"), recursive=True):
        if os.path.isfile(f):
            files[os.path.relpath(f, LASTGOOD)] = open(f, encoding="utf-8").read()
    return files


def err_signature(errs: list) -> str:
    norm = " ".join(sorted(re.sub(r"\d+", "#", e) for e in errs))[:600]
    return hashlib.sha1(norm.encode()).hexdigest()[:12]


# ---------------- HELP.md channel (checkbox-driven; the supervisor is Claude, watching via Monitor) ----------------
# Each escalation is a Markdown task item — `- [ ]` awaits the supervisor, `- [x]` = attended. The
# supervisor replaces the Answer placeholder with guidance and ticks the box; the driver then injects
# that guidance into the next agent turn. (Renders as a live checklist in any Markdown viewer.)
def help_escalate(hid: int, kind: str, phase: str, problem: str, files: list):
    block = (f"\n- [ ] **HELP {hid}** — {time.strftime('%H:%M:%S')} — {kind} — "
             f"files: {', '.join(files) or '(n/a)'}\n"
             f"  - **Problem:** {problem.strip()[:1400]}\n"
             f"  - **Answer:** _supervisor: replace this with guidance, then tick the box above_\n")
    with open(HELP_FILE, "a", encoding="utf-8") as fh:
        fh.write(block)
    log(f"    [HELP {hid}] escalated ({kind}): {problem.strip()[:90]}")


def help_check_answer(hid: int):
    """Guidance for HELP `hid`, once its checkbox is ticked `[x]` and the Answer is filled in, else None."""
    if not os.path.isfile(HELP_FILE):
        return None
    txt = open(HELP_FILE, encoding="utf-8").read()
    m = re.search(rf"^- \[(?P<box>[ xX])\] \*\*HELP {hid}\*\*.*?"
                  rf"(?:\n\s*-\s*\*\*Answer:\*\*\s*(?P<ans>.*?))?(?=\n- \[|\Z)",
                  txt, re.DOTALL | re.MULTILINE)
    if not m or m.group("box").strip().lower() != "x":
        return None
    ans = (m.group("ans") or "").strip()
    return None if (not ans or ans.startswith("_")) else ans   # ignore the italic placeholder


def help_resolve(hid: int):
    # The ticked `[x]` checkbox IS the resolution marker; nothing to rewrite. Kept for call compatibility.
    return


def status(**kw):
    kw["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        json.dump(kw, open(STATUS_FILE, "w"), indent=2)
    except Exception:
        pass


# ---------------- agent roles ----------------
def plan(files: dict | None = None) -> str:
    """ARCHITECT: design-only. Produces & persists BLUEPRINT.md. Emits NO code (any is ignored)."""
    ctx = GOAL + ARCH
    if files:
        ctx += f"\n\nExisting files (re-plan around them):\n{manifest(files)}"
    bp = agent_call(ARCHITECT_SYS, ctx + "\n\nProduce the blueprint now. Design only — no code, no FILE: blocks.",
                    2500, 0.4)
    try:
        open(BLUEPRINT_FILE, "w", encoding="utf-8").write(bp)
    except Exception:
        pass
    nfiles = bp.count("\n- ")
    log(f"    [architect] blueprint: ~{nfiles} files, {token_est(bp)} tok")
    return bp


def _coder_write(resp: str, files: dict) -> dict:
    """Apply a CODER/FIXER response: write impl files (specs are the test-author's domain), do deletes."""
    got = {p: c for p, c in parse_files(resp).items() if not _is_spec(p)}
    files.update(got)
    dels = apply_deletes(files, parse_deletes(resp))
    write_project(files)
    if dels:
        log(f"    [delete] {', '.join(dels)}")
    return got


def ideate(blueprint: str):
    """CODER: implement the architect's blueprint into the initial minimal project."""
    resp = agent_call(BUILDER_SYS, GOAL + ARCH + "\n\nAPPROVED BLUEPRINT (implement EXACTLY this):\n" + blueprint
                + "\n\nImplement the INITIAL minimal project NOW — the smallest thing that runs per the "
                "blueprint. Keep every file small. Emit files in FILE: format (specs are handled separately).",
                MAX_NEW, 0.6)
    got = _coder_write(resp, {})
    h = HELP_RE.search(resp)
    log(f"    [ideate] {len(got)} files: {', '.join(sorted(got))}" + (f"  HELP:{h.group(1)[:60]}" if h else ""))
    return got, (h.group(1).strip() if h else None)


def build(files: dict, instruction: str, target: str, blueprint: str):
    """CODER: implement ONE critic-chosen improvement (net-new feature work; no tests, no self-grading)."""
    cur = files.get(target, "(this file does not exist yet — create it)")
    user = (GOAL + ARCH + "\n\nAPPROVED BLUEPRINT (conform to it):\n" + blueprint
            + LESSONS_BLOCK
            + retrieve_docs(f"{instruction}  ({target})")
            + f"\n\nProject files:\n{manifest(files)}\n\nFull content of {target}:\n```\n{cur[:60000]}"
            f"\n```\n\nTask (must serve the GOAL above): {instruction}\nRespect the architecture and the "
            f"blueprint (least code; a feature is a plugin/adapter; keep the core pure). Emit the COMPLETE "
            f"updated/new file(s) in FILE: format; `DELETE: <path>` to remove one. Do NOT write tests.")
    resp = agent_call(BUILDER_SYS, user, MAX_NEW, 0.5)
    got = _coder_write(resp, files)
    h = HELP_RE.search(resp)
    log(f"    [build] {instruction[:55]} -> {', '.join(sorted(got)) or '(none!)'}")
    return got, (h.group(1).strip() if h else None)


def fix(files: dict, last_error: str, answer: str, blueprint: str):
    """FIXER: smallest change to satisfy the gate. Impl only — conforms code to the specs."""
    named = sorted(set(re.findall(r"([\w./\-]+\.(?:js|mjs|html|css|json))", last_error)))
    bodies = "\n\n".join(f"--- {p} ---\n{files.get(p, '(missing)')[:60000]}" for p in named[:12])
    hint = f"\n\nA SUPERVISOR PROVIDED THIS GUIDANCE — follow it:\n{answer}\n" if answer else ""
    user = (GOAL + ARCH + "\n\nAPPROVED BLUEPRINT (preserve it):\n" + blueprint
            + f"\n\nProject files:\n{manifest(files)}\n\nThe project FAILED validation:\n{last_error}"
            f"{hint}\n\nMake the SMALLEST change so it passes (align contracts; respect the architecture). "
            f"Relevant files:\n{bodies}\n\nEmit the COMPLETE corrected file(s) in FILE: format; "
            f"`DELETE: <path>` to remove a duplicate/orphan. Do NOT edit test specs; do NOT add features.")
    resp = agent_call(FIXER_SYS, user, MAX_NEW, 0.3)
    got = _coder_write(resp, files)
    h = HELP_RE.search(resp)
    log(f"    [fix] {last_error[:50]}… -> {', '.join(sorted(got)) or '(none!)'}")
    return got, (h.group(1).strip() if h else None)


def refactor(files: dict, ofile: str):
    """CODER: split an oversized file along an architecture seam (structural code work, behavior-preserving)."""
    cur = files.get(ofile, "")
    user = (ARCH + "\n\nAPPROVED BLUEPRINT:\n(see manifest)\n\n"
            f"The file `{ofile}` (~{token_est(cur)} tok) exceeds the budget. PAUSE features and split it "
            f"along an architecture seam (extract a core sub-module, a port, or an adapter), preserving "
            f"behavior and updating imports. Emit ALL affected files in FILE: format; `DELETE: <path>` if "
            f"a file is wholly replaced.\n\nOther files:\n{manifest(files)}\n\nFull content of {ofile}:\n"
            f"```\n{cur}\n```")
    resp = agent_call(BUILDER_SYS, user, MAX_NEW, 0.4)
    got = _coder_write(resp, files)
    log(f"    [refactor] split {ofile} -> {', '.join(sorted(got))}")


def test_author(files: dict, blueprint: str, repair_error: str = ""):
    """TEST-AUTHOR: write/maintain headless specs for the pure core. Owns specs; never touches impl."""
    if not HAS_SPEC_LAYER:
        return
    core = {p: c for p, c in files.items() if _is_core(p)}
    if not core:
        return
    bodies = "\n\n".join(f"--- {p} ---\n{c[:60000]}" for p, c in sorted(core.items()))
    specs = "\n\n".join(f"--- {p} ---\n{c[:20000]}" for p, c in sorted(files.items()) if _is_spec(p))
    rep = (f"\n\nA spec is FAILING TO LOAD — fix the SPEC (not the code):\n{repair_error}\n"
           if repair_error else "")
    user = (GOAL + ARCH + "\n\nAPPROVED BLUEPRINT:\n" + blueprint
            + f"\n\nPURE CORE modules to test (test their CONTRACT, adversarially):\n{bodies}"
            + (f"\n\nExisting specs:\n{specs}" if specs else "") + rep
            + "\n\nWrite or update the headless specs now. Emit ONLY spec files in FILE: format.")
    resp = agent_call(TESTER_SYS, user, MAX_NEW, 0.4)
    got = {p: c for p, c in parse_files(resp).items() if _is_spec(p)}
    files.update(got)
    write_project(files)
    log(f"    [test-author] specs: {', '.join(sorted(got)) or '(none!)'}")
    return got


def review(files: dict, blueprint: str) -> dict:
    """CRITIC: review quality + architecture + blueprint adherence; pick next step or DONE."""
    key = {p: c for p, c in files.items()
           if p in ("index.html", "main.js") or p.startswith(("core/", "src/"))}
    keytext = "\n\n".join(f"--- {p} ---\n{c[:12000]}" for p, c in sorted(key.items()))
    crit = agent_call(CRITIC_SYS, GOAL + ARCH + "\n\nAPPROVED BLUEPRINT:\n" + blueprint
                + f"\n\nProject files:\n{manifest(files)}\n\nKey files:\n{keytext}\n\n"
                "Critique BRIEFLY against the GOAL and the BLUEPRINT (product quality AND architecture/"
                "lazy-dev adherence; flag duplication or drift from the manifest). Every improvement must "
                "move toward the GOAL — do NOT propose features for a different kind of app. If the app "
                "genuinely fulfills the GOAL at high quality with NO worthwhile improvement left, reply with "
                "exactly `DONE` on its own line. Otherwise choose the single highest-value next improvement "
                "and end with EXACTLY two lines — a BITE-SIZED task with an EXACT file path, no placeholders:\n"
                "TARGET: <relative path of the file to create or edit next>\n"
                "NEXT: <one concrete, specific improvement achievable in one iteration>", 1200, 0.4)
    if re.search(r"^\s*DONE\s*$", crit, re.MULTILINE):
        log("    [review] critic says DONE")
        return {"done": True, "raw": crit[:300]}
    tm = re.search(r"TARGET:\s*([^\n`]+)", crit)
    nm = re.search(r"NEXT:\s*(.+)", crit)
    nxt = {"done": False, "target": (tm.group(1).strip().lstrip("./") if tm else "main.js"),
           "instruction": (nm.group(1).strip() if nm else crit.strip())[:300], "raw": crit[:300]}
    log(f"    [review] TARGET={nxt['target']} NEXT={nxt['instruction'][:70]}")
    return nxt


# --- council expansion engine: a deterministic EXPAND/REFINE cadence + coverage map + distinct
# role lenses, so the council DRIVES BREADTH instead of re-optimizing the same salient file. ---
EXPAND_N = int(os.environ.get("SPRINT_EXPAND", "5"))   # net-new-subsystem iterations per cycle
REFINE_N = int(os.environ.get("SPRINT_REFINE", "2"))   # refinement/hardening iterations per cycle
WORLD_N = int(os.environ.get("SPRINT_WORLD", "0"))     # WORLD-BUILD rounds per cycle (the World Lens die)
_COUNCIL_ROUND = 0
_RECENT_TARGETS: list = []                              # anti-churn: files chosen recently
DICE = os.environ.get("SPRINT_DICE", "1") == "1"        # Oblique-Strategies exploration roll (EXPAND)
BALANCE = os.environ.get("SPRINT_BALANCE", "1") == "1"  # category-balance weighting (dice + vote tally)
LEDGER_PATH = os.path.join(PROJ, "category_balance.json")
try:                                                    # append-only log of every roll + balance update
    from prismpath import audit_log as _al
    _COUNCIL_AUDIT = _al.AuditLog(os.path.join(PROJ, "council_audit.log"))
except Exception:
    _COUNCIL_AUDIT = None

ROLE_LENS = {
    "architect": "a NEW structural subsystem — a new port + adapter giving the product a whole new capability",
    "coder": "a NEW gameplay mechanic players directly interact with (not a tweak to an existing one)",
    "test-author": "an entirely NEW pure-core module with rules worth unit-testing",
    "fixer": "a MISSING safeguard the product lacks (abuse resistance, data-loss protection, an unhandled edge)",
    "critic": "the single NEW feature that most increases player-facing DEPTH and fun",
    "product-manager": "the single MISSING player-facing system that delivers the most NEW value — reject optimizing files that already work",
    "engagement-manager": "the boldest FUN/retention feature that makes a player say 'one more run' — dissent from dry technical or test-only work",
}
# WORLD-round lenses: every voice thinks about the PHYSICAL/VISUAL world, not server rulesets.
WORLD_LENS = {
    "architect": "the structural layout of the physical plot — how the owned space is organized and reads",
    "coder": "a visible, interactive world object the player physically touches and gets feedback from",
    "fixer": "a missing piece of physical presence the world lacks (it feels empty / a system is invisible)",
    "product-manager": "the feature that most makes the product feel complete and worth using",
    "engagement-manager": "the most alive, screenshot-worthy visual moment in the world",
}
# Optional, CONSUMER-PROVIDED "expected subsystems -> presence keywords" map (domain-specific). The
# engine ships with NONE — it knows nothing about any particular product. Point SPRINT_SUBSYSTEMS_FILE at a JSON
# map to drive coverage-based EXPAND proposals; empty -> the coverage map is simply unused (the role-lensed
# council still proposes net-new subsystems). Map format: {subsystem-name: [presence keywords]}.
SUBSYSTEMS = {}
_SUBSYS_FILE = os.environ.get("SPRINT_SUBSYSTEMS_FILE")
if _SUBSYS_FILE and os.path.isfile(_SUBSYS_FILE):
    import json as _json
    try:
        SUBSYSTEMS = _json.load(open(_SUBSYS_FILE, encoding="utf-8"))
    except Exception:
        SUBSYSTEMS = {}


def _coverage(files: dict):
    blob = "\n".join((p + "\n" + c) for p, c in files.items()).lower()
    present, missing = [], []
    for name, kws in SUBSYSTEMS.items():
        (present if any(k in blob for k in kws) else missing).append(name)
    return present, missing


def council_next(files: dict, blueprint: str) -> dict:
    """DEMOCRATIZED next-step: 5 role-lensed proposals → vote. A 5:2 EXPAND/REFINE cadence + coverage
    map drive BREADTH (in EXPAND, proposals must be net-new subsystems; existing/recent files filtered)."""
    global _COUNCIL_ROUND
    if _ix:
        _ix.set_phase("council")
    # 3 engineering voices (gemma4) + 2 contrarian product voices (qwen25): real diversity + a built-in
    # push toward expansion/fun (the PM vetoes optimization; the engagement manager champions player joy).
    roles = ["architect", "coder", "fixer", "product-manager", "engagement-manager"]
    _COUNCIL_ROUND += 1
    cycle = max(1, WORLD_N + EXPAND_N + REFINE_N)
    _pos = (_COUNCIL_ROUND - 1) % cycle
    phase = "WORLD" if _pos < WORLD_N else ("EXPAND" if _pos < WORLD_N + EXPAND_N else "REFINE")
    present, missing = _coverage(files)
    cov = (f"\n\nSUBSYSTEM COVERAGE — present: {', '.join(present) or 'none'}\n"
           f"MISSING (build these): {', '.join(missing) or 'none — all core systems exist'}\n")
    ledger = dice.load_ledger(LEDGER_PATH) if dice is not None else {}
    rolled = None
    recent = ", ".join(_RECENT_TARGETS) or "none"
    if phase == "WORLD" and dice is not None:
        wr = dice.world_roll(_COUNCIL_ROUND, files)                 # World Lens: build the physical space
        directive = (dice.world_mandate(wr) + f"\nRecently-built (do NOT re-pick): {recent}.")
        log(f"    [council/world] seed={wr['seed']} aspect='{wr['axis']}' scope={wr['scope']}")
        if _ix:
            _ix.record("dice", "council", dice.world_mandate(wr),
                       f"WORLD aspect={wr['axis']} | scope={wr['scope']} | seed={wr['seed']}", phase="WORLD")
        if _COUNCIL_AUDIT is not None:
            try:
                _COUNCIL_AUDIT.append("council", "world.roll", wr)
            except Exception:
                pass
    elif phase == "EXPAND" and DICE and dice is not None:
        rolled = dice.roll(_COUNCIL_ROUND, files, ledger)           # seeded; coverage × balance weighted
        directive = (dice.mandate(rolled) + f"\nCreate a NEW file (new core module + its port/adapter); do "
                     f"NOT edit or optimize a file that already exists. Recently-built (do NOT re-pick): {recent}.")
        log(f"    [council/dice] seed={rolled['seed']} dir='{rolled['direction']}' scope={rolled['scope']}")
        if _ix:
            _ix.record("dice", "council", dice.mandate(rolled),
                       f"DIRECTION={rolled['direction']} | SCOPE={rolled['scope']} | weights={rolled['weights']}",
                       phase="EXPAND")
        if _COUNCIL_AUDIT is not None:
            try:
                _COUNCIL_AUDIT.append("council", "dice.roll", rolled)
            except Exception:
                pass
    elif phase == "EXPAND":
        directive = ("This is an EXPANSION round (the product must GROW). Propose a NET-NEW subsystem it LACKS — "
                     "pick from MISSING above. Create a NEW file (new core module + its adapter/port); do NOT "
                     f"propose editing or optimizing a file that already exists. Recently-built (do NOT re-pick): {recent}.")
    else:
        directive = ("This is a REFINEMENT round. Propose a robustness/balance/UX improvement to an EXISTING "
                     "system (edge-cases, tuning, polish). No new subsystem needed.")
    # LEAN council context: the council decides WHAT to build next (a target + action), so it needs the
    # goal, coverage, and what already exists — NOT the full architecture contract or blueprint (those are
    # the BUILD step's concern). The old ctx was ~14KB, so each of 5 SEQUENTIAL propose dispatches took
    # ~20s (≈80s/round, which froze the lens and ballooned under load). This ~3KB ctx makes them ~5s.
    ctx = (GOAL + cov + "\nExisting files: " + ", ".join(sorted(files)) + "\n")
    proposals = []
    for role in roles:
        lens = WORLD_LENS.get(role, ROLE_LENS[role]) if phase == "WORLD" else ROLE_LENS[role]
        p = _swarm_dispatch(role, ctx + f"\nYOUR LENS ({role}): propose {lens}.\n{directive}\n"
            "If the product is genuinely complete and excellent with nothing worthwhile left, reply exactly `DONE`. "
            "Otherwise reply EXACTLY two lines:\nTARGET: <relative file path>\nACTION: <one concrete improvement>")
        proposals.append((role, p or ""))
    if sum(1 for _, p in proposals if re.search(r"^\s*DONE\s*$", p, re.M) and "TARGET" not in p) >= 3:
        log("    [council] majority DONE")
        return {"done": True, "raw": "council DONE"}
    opts = []
    for role, p in proposals:
        tm, am = re.search(r"TARGET:\s*([^\n`]+)", p), re.search(r"ACTION:\s*(.+)", p)
        if tm and am:
            opts.append({"role": role, "target": tm.group(1).strip().lstrip("./"),
                         "instruction": am.group(1).strip()[:240]})
    if not opts:
        return {"done": False, "target": "core/new_system.js",
                "instruction": "Add a net-new subsystem the product lacks."}
    if phase in ("EXPAND", "WORLD"):                   # enforce novelty: prefer net-new, un-churned targets
        fresh = [o for o in opts if o["target"] not in files and o["target"] not in _RECENT_TARGETS]
        if fresh:
            opts = fresh
    ballot = "\n".join(f"{i + 1}. [{o['role']}] {o['target']}: {o['instruction']}" for i, o in enumerate(opts))
    tally = [0] * len(opts)
    for role in roles:
        v = _swarm_dispatch(role, ctx + "Proposed next actions:\n" + ballot + "\n\nVote for the SINGLE best "
                            "one to do next (most value toward the GOAL, least risk). Reply with ONLY its number.")
        mv = re.search(r"\b(\d+)\b", v or "")
        if mv and 0 <= int(mv.group(1)) - 1 < len(opts):
            tally[int(mv.group(1)) - 1] += 1
    # BALANCE: scale each proposal's raw votes by its category weight — a path we've travelled often counts
    # for LESS, so neglected categories can win and the product expands evenly. (Near no-op within an EXPAND
    # round where every proposal shares the rolled direction; decisive on REFINE / cross-category rounds.)
    if BALANCE and dice is not None:
        cats = [dice.classify(o["target"], o["instruction"]) for o in opts]
        bw = [round(dice.balance_weight(ledger, c), 2) for c in cats]
        eff = [tally[i] * bw[i] for i in range(len(opts))]
        win_i = eff.index(max(eff))
    else:
        cats, bw = ["" for _ in opts], [1.0 for _ in opts]
        eff = [float(t) for t in tally]
        win_i = tally.index(max(tally))
    win = opts[win_i]
    _RECENT_TARGETS.append(win["target"])
    del _RECENT_TARGETS[:-6]
    # Record the EXPANDED direction so future rounds steer AWAY from it (ledger = expansion history by
    # direction). Only EXPAND rounds count — REFINE polishes, it does not expand. The ROLLED direction is
    # authoritative (the whole round built toward it); classify(winner) is a fallback only when dice are
    # off. Recording classify(winner) on EXPAND was wrong: a cross-flavored proposal (e.g. an economy
    # round whose winner reads "trade with rivals") miscredits Social, so the neglected axis never rises.
    if BALANCE and dice is not None and phase == "EXPAND":
        wcat = rolled["direction"] if rolled else (cats[win_i] if cats[win_i] != "other" else None)
        if wcat:
            dice.record(ledger, wcat)
            dice.save_ledger(LEDGER_PATH, ledger)
            if _COUNCIL_AUDIT is not None:
                try:
                    _COUNCIL_AUDIT.append("council", "balance.update", {"category": wcat, "ledger": ledger})
                except Exception:
                    pass
    log(f"    [council/{phase}] {len(opts)} proposals, votes={tally}"
        + (f" xW={bw} -> eff={[round(e, 1) for e in eff]}" if (BALANCE and dice is not None) else "")
        + f" -> [{win['role']}] {win['target']}: {win['instruction'][:48]} | missing={len(missing)}")
    return {"done": False, "target": win["target"], "instruction": win["instruction"], "raw": ballot[:300]}


def audit_consistency(target: str) -> None:
    """qwen CONSISTENCY AUDITOR (opt-in SPRINT_AUDIT=1): does the just-built `target` conform to the GLOSSARY?
    Advisory only — logs drift flags to the run log; the auditor dispatch is auto-recorded to the glass lens.
    Never blocks the build. Runs in qwen's idle window right after a gemma4 cecli build."""
    if not (AUDIT and AGENT_BACKEND == "swarm" and os.path.isfile(GLOSSARY_FILE)):
        return
    try:
        src = open(os.path.join(PROJ, target), encoding="utf-8").read()
        glossary = open(GLOSSARY_FILE, encoding="utf-8").read()
    except OSError:
        return
    if not src.strip():
        return
    prompt = (f"GLOSSARY — the canonical contract (single source of truth):\n{glossary}\n\n"
              f"--- FULL CONTENTS of {target} (this is everything; there is nothing to fetch) ---\n{src}\n"
              f"--- end of {target} ---\n\n"
              "Audit the file above against the GLOSSARY now. You have no tools — do NOT emit JSON or any tool "
              "call. Output ONLY DRIFT/DUP lines, or exactly AUDIT-CLEAN.")
    try:
        out = _swarm_dispatch("auditor", prompt, timeout=180)
    except Exception as e:
        log(f"    [audit] skipped ({str(e)[:70]})")
        return
    def _real(ln: str) -> bool:                      # drop the 7B's `DRIFT X -> X` self-flags + empties
        if ln.startswith("DUP"):
            return True
        if "->" in ln:
            x = ln.split("->", 1)[0].split(":", 1)[-1].strip()
            y = ln.split("->", 1)[1].strip()
            return bool(x) and bool(y) and x != y
        return False
    seen: set = set()
    flags = []
    for ln in (out or "").splitlines():
        ln = ln.strip()
        if ln.startswith(("DRIFT", "DUP")) and _real(ln) and ln not in seen:
            seen.add(ln)
            flags.append(ln)
    if flags:
        log(f"    [audit/qwen] {len(flags)} drift flag(s) on {target}:")
        for fl in flags[:12]:
            log(f"        {fl}")
    else:
        log(f"    [audit/qwen] clean: {target}")


def antigravity_unblock(errors: str, named: list) -> bool:
    """Frontier auto-unblocker: hand a STUCK gate failure to the Antigravity CLI (agy, Gemini 3.1 Pro) to fix
    autonomously instead of waiting for a human. Sandboxed — file edits apply, terminal is restricted; the
    loop re-runs the gate next iteration to verify. Returns True if agy ran. One dispatch per call."""
    if not os.path.isfile(AGY_BIN):
        log(f"    [agy] binary not found at {AGY_BIN}; falling back to human escalation")
        return False
    hint = ""
    if os.path.isfile(os.path.join(PROJ, "specs", "GLOSSARY.md")):
        hint = (" The canonical type contract is specs/GLOSSARY.md (+ the per-module specs in specs/) — "
                "conform to it exactly and do NOT change any public interface.")
    task = (
        "You are an automated build unblocker for this project (its directory is in your "
        "workspace). A DETERMINISTIC build gate is STUCK — the local swarm failed to fix the SAME error three "
        "times. Make the SMALLEST change that resolves it: do NOT refactor working code, rename public "
        f"symbols, or add features.{hint}\n\nThe stuck gate errors:\n{errors}\n\n"
        f"Files implicated: {', '.join(named) or '(infer from the errors above)'}.\n"
        "Edit the file(s) to fix it, then stop — the build system re-runs the gate to verify your fix."
    )
    args = [AGY_BIN, "--add-dir", PROJ, "--dangerously-skip-permissions"]
    if AGY_SANDBOX:
        args.append("--sandbox")
    if AGY_MODEL:
        args += ["--model", AGY_MODEL]
    args += ["--print", task]   # --print takes the PROMPT as its value — it MUST be adjacent + last
    log(f"    [agy] frontier unblocker dispatching (model={AGY_MODEL}, sandbox={AGY_SANDBOX})")
    _t0 = time.time()
    try:
        env = dict(os.environ, PATH=os.path.dirname(AGY_BIN) + ":" + os.environ.get("PATH", ""))
        p = subprocess.run(args, cwd=PROJ, capture_output=True, text=True, timeout=AGY_TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        log(f"    [agy] timed out after {AGY_TIMEOUT}s")
        return False
    except Exception as e:
        log(f"    [agy] failed to launch: {str(e)[:120]}")
        return False
    dur = int(time.time() - _t0)
    out = p.stdout or ""
    log(f"    [agy] done rc={p.returncode} dur={dur}s; tail: {out[-180:].strip()}")
    if _ix is not None:
        _ix.record("antigravity", "unblocker", task, out or (p.stderr or ""), dur_ms=dur * 1000, rc=p.returncode)
    return p.returncode == 0


def spec_next(files: dict) -> dict:
    """Spec-driven next-step: build each module in SPEC_ORDER to green, in dependency order, straight from
    its `<SPEC_DIR>/<Module>.md` contract — the deterministic alternative to council_next's dice exploration.
    Returns the first module whose core file isn't present yet; done when all are built (gate is green)."""
    for m in SPEC_ORDER:
        target = f"core/{m}.js"
        if target not in files:
            def _spec_read(rel: str) -> str:
                try:
                    return open(os.path.join(PROJ, SPEC_DIR, rel), encoding="utf-8").read()
                except OSError:
                    return ""
            spec_txt, gloss_txt = _spec_read(f"{m}.md"), _spec_read("GLOSSARY.md")
            instruction = (
                f"Implement {target} EXACTLY per the MODULE SPEC and the canonical GLOSSARY embedded below — "
                f"they ARE the contract. Conform every shared type name, field, and signature to the GLOSSARY. "
                f"Create ONLY {target} as a pure --!strict core.\n\n"
                f"===== MODULE SPEC ({SPEC_DIR}/{m}.md) =====\n{spec_txt}\n\n"
                f"===== CANONICAL GLOSSARY ({SPEC_DIR}/GLOSSARY.md) =====\n{gloss_txt}\n"
                f"===== END CONTRACT ====="
            )
            return {"done": False, "target": target, "instruction": instruction, "raw": f"spec:{m}"}
    return {"done": True, "target": "", "instruction": ""}


# ---------------- KG-driven stepped execution (the deterministic PrismPath path) ----------------
def _abs(p: str) -> str:
    return p if os.path.isabs(p) else os.path.join(PROJ, p)


def _kg_save(kg: dict):
    kp = _abs(KG_PATH)
    os.makedirs(os.path.dirname(kp) or ".", exist_ok=True)
    tmp = kp + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(kg, f, indent=2)
    os.replace(tmp, kp)                                     # atomic


def _kg_load() -> dict:
    """Load the knowledge graph; on first run INSTANTIATE it from the spec's seeded ```json block
    (deterministic — the graph is authored in the spec, not derived by the LLM)."""
    kp = _abs(KG_PATH)
    if os.path.isfile(kp):
        try:
            return json.load(open(kp, encoding="utf-8"))
        except (OSError, ValueError):
            pass
    spec = open(_abs(SPEC_FILE), encoding="utf-8").read()
    m = re.search(r"```json\s*(.*?)```", spec, re.S)
    kg = json.loads(m.group(1).strip()) if m else {"nodes": []}
    _kg_save(kg)
    log(f"    [kg] instantiated {KG_PATH}: {len(kg.get('nodes', []))} nodes")
    return kg


def kg_mark_done(node_id: str):
    kg = _kg_load()
    for n in kg.get("nodes", []):
        if n.get("id") == node_id:
            n["status"] = "done"
    _kg_save(kg)


def _ledger():
    """Lazy Ledger for this sprint. SPRINT_LEDGER_RUN reuses a prior run's ref (resume the same
    proof chain); otherwise a fresh run id is minted."""
    global _LEDGER, _RUN_ID
    from prismpath import ledger as _lg
    if _RUN_ID is None:
        _RUN_ID = os.environ.get("SPRINT_LEDGER_RUN") or _lg.new_run_id()
    if _LEDGER is None:
        _LEDGER = _lg.Ledger(flow=os.path.basename(PROJ.rstrip("/")) or "sprint", run_id=_RUN_ID)
    return _LEDGER


def _apply_ledger_done(kg: dict, done_units) -> int:
    """Mark KG nodes done for every unit proven in the ledger. Returns the count newly marked."""
    n = 0
    for node in kg.get("nodes", []):
        if node.get("id") in done_units and node.get("status") != "done":
            node["status"] = "done"
            n += 1
    return n


def _kg_seed_from_ledger():
    """Resume-from-git: mark KG nodes done from the ledger's proofs, so a sprint whose .kg.json was
    wiped (SPRINT_FRESH) restarts at the first UNPROVEN node instead of rebuilding what git already
    attests. Point at a prior run with SPRINT_LEDGER_RUN=<id>. Best-effort — never blocks a sprint."""
    if not LEDGER:
        return
    try:
        done_units = set(_ledger().done_set())
        if not done_units:
            return
        kg = _kg_load()
        seeded = _apply_ledger_done(kg, done_units)
        if seeded:
            _kg_save(kg)
            log(f"    [ledger] resumed {seeded} node(s) from {_LEDGER.ref}")
    except Exception as e:                                 # noqa: BLE001 - resume must never block a sprint
        log(f"    [ledger] resume-seed skipped ({str(e)[:100]})")


def _ledger_commit(unit: str, files: dict, edge: str = None):
    """Record a gate-green unit as a git proof-commit (SPRINT_LEDGER=1). Best-effort and strictly
    off the critical path: any failure degrades to the existing .lastgood/.kg.json path — the
    ledger records progress, it never drives or breaks a sprint."""
    try:
        from prismpath import ledger as _lg
        led = _ledger()
        node = next((n for n in _kg_load().get("nodes", []) if n.get("id") == unit), {}) if KG_MODE else {}
        produces = node.get("produces", [])
        out = {p: files[p] for p in produces if p in files}
        led.commit_unit(
            unit, node=unit, gate="green", gate_name=GATE, files=files,
            output_hash=_lg.sha256_files(out) if out else None,
            depends=node.get("depends_on") or None, edge=edge)
        log(f"    [ledger] {unit} -> proof-commit ({led.ref})")
    except Exception as e:                                 # noqa: BLE001 - never let the ledger break a run
        log(f"    [ledger] skipped ({str(e)[:100]})")


def kg_next(files: dict) -> dict:
    """Deterministic next-step: the first PENDING node whose `depends_on` are all done. Embeds ONLY that
    requirement's `## ` section + the GLOSSARY + any per-module specs it names + what is already built."""
    kg = _kg_load()
    nodes = kg.get("nodes", [])
    done = {n["id"] for n in nodes if n.get("status") == "done"}
    spec_text = open(_abs(SPEC_FILE), encoding="utf-8").read()
    sections = re.split(r"\n(?=## )", spec_text)
    specs_dir = os.path.dirname(_abs(SPEC_FILE))
    glossary = ""
    gp = os.path.join(specs_dir, "GLOSSARY.md")
    if os.path.isfile(gp):
        glossary = open(gp, encoding="utf-8").read()
    for n in nodes:
        if n.get("status") == "done":
            continue
        if not all(d in done for d in n.get("depends_on", [])):
            continue
        key = (n.get("section") or n.get("id") or "").lower()
        section = next((s.strip() for s in sections
                        if s.strip().lower().startswith("## ") and key and key in s.splitlines()[0].lower()), "")
        ref = ""
        for name in sorted(set(re.findall(r"specs/(\w+)\.md", section))):
            rp = os.path.join(specs_dir, name + ".md")
            if name != "GLOSSARY" and os.path.isfile(rp):
                ref += f"\n\n===== specs/{name}.md =====\n" + open(rp, encoding="utf-8").read()
        prod = n.get("produces", [])
        target = next((p for p in prod if p.endswith((".js", ".mjs"))), prod[0] if prod else "")
        donelist = "; ".join(f"{x} -> {','.join(next((mm.get('produces', []) for mm in nodes if mm['id'] == x), []))}"
                             for x in done) or "(nothing yet)"
        instruction = (
            f"Build integration REQUIREMENT '{n['id']}' to its Definition of done. Implement ONLY this "
            f"requirement (the other steps are built separately); COMPOSE the already-built modules, never "
            f"rebuild them.\n\n===== REQUIREMENT (from INTEGRATION.md) =====\n{section}\n\n"
            f"===== CANONICAL GLOSSARY =====\n{glossary}{ref}\n\n"
            f"ALREADY BUILT (compose these, do not rebuild): {donelist}\n"
            f"Conform every shared identifier to the GLOSSARY EXACTLY."
        )
        return {"done": False, "target": target, "instruction": instruction, "raw": f"kg:{n['id']}",
                "_kg_node": n["id"]}
    return {"done": True, "target": "", "instruction": ""}


def _spec_load_error(errs: list) -> bool:
    """A failing spec that can't even load (bad require) is the test-author's to fix, not the fixer's."""
    blob = " ".join(errs).lower()
    return ("lune test failed" in blob
            and ("could not resolve" in blob or "error requiring module" in blob
                 or "cannot find" in blob))


# ---------------- main loop ----------------
def _register_sprint():
    """Announce this sprint's project dir to Mission Control's registry so the dashboard auto-discovers
    it no matter where/how it was launched (CLI, the wrapper, the Control tab). Best-effort, never fatal."""
    try:
        reg = os.path.expanduser(os.environ.get("MC_REGISTRY", "~/.prismpath/sprints.json"))
        os.makedirs(os.path.dirname(reg), exist_ok=True)
        try:
            data = json.load(open(reg, encoding="utf-8"))
            data = data if isinstance(data, dict) else {}
        except Exception:
            data = {}
        data[os.path.abspath(PROJ)] = {"gate": GATE, "started": int(time.time())}
        data = {k: v for k, v in data.items() if os.path.isdir(k)}       # prune dead dirs
        json.dump(data, open(reg, "w", encoding="utf-8"), indent=2)
    except Exception:
        pass


def _start_heartbeat():
    """Keep status.json's mtime fresh while a long cecli build blocks the loop. Mission Control treats a
    sprint as 'running' only if status.json was touched < 120s ago, but status() is written once per
    iteration — so a multi-minute build would flip the dashboard to 'idle' mid-build even though the GPU
    is busy. This daemon touches the mtime every 30s (content is still authored by status() each turn)."""
    import threading
    sp = os.path.join(PROJ, "status.json")

    def _beat():
        while not os.path.exists(STOP_FILE):
            try:
                if os.path.exists(sp):
                    os.utime(sp, None)
            except OSError:
                pass
            time.sleep(30)

    threading.Thread(target=_beat, daemon=True).start()


def _flow_loop(files: dict, blueprint: str) -> str:
    """SPRINT_FLOW=1 (roadmap item #6): drive the sprint through flows/sprint_loop.md instead of the
    Python while-loop below. Same primitives (kg_next/council_next, cecli/swarm executor, validate_fn,
    help_escalate) wired as SprintSeams; the routing, retry budget, escalation, and per-unit ledger
    proofs are now edges + a @checkpoint in the DOCUMENT. Returns the stop reason."""
    from prismpath.sprint_flow import GateRed, SprintSeams, run_sprint_flow
    cur = {"files": files, "nxt": None}

    def pick(state):
        cur["files"] = load_project() or cur["files"]        # the executor edits the real tree
        done_units = state.get("_done_units") or set()
        if KG_MODE:
            r = kg_next(cur["files"])
        elif SPEC_MODE:
            r = spec_next(cur["files"])
        else:
            r = council_next(cur["files"], blueprint) if AGENT_BACKEND == "swarm" else review(cur["files"], blueprint)
        if r.get("done"):
            return {"text": "sprint complete", "done": True}
        unit = str(r.get("_kg_node") or r.get("target") or f"step-{len(done_units) + 1}")
        if unit in done_units:                               # picker ignored the ledger -> stop safely
            return {"text": f"{unit} already proven", "done": True}
        state["unit"] = {"id": unit}
        cur["nxt"] = r
        return {"text": f"next: {unit}", "done": False,
                "instruction": r.get("instruction", ""), "target": r.get("target", "")}

    def build(state):
        r = cur["nxt"] or {}
        if EXEC == "cecli":
            cur["files"] = cecli_build(cur["files"], r.get("instruction", ""), r.get("target", ""), blueprint)
        else:
            got, bhelp = globals()["build"](cur["files"], r.get("instruction", ""), r.get("target", ""), blueprint)
            if HAS_SPEC_LAYER and any(_is_core(p) for p in got):
                test_author(cur["files"], blueprint)
        return {"text": f"built {r.get('target', '')}"}

    def gate(state):
        v = validate_fn(PROJ)
        if not v["valid"]:
            raise GateRed("; ".join(v["errs"])[:1400])
        snapshot_green(cur["files"])
        if KG_MODE and state.get("unit"):
            kg_mark_done(state["unit"]["id"])
        state["gate_report"] = f"gate={GATE} valid; files={len(cur['files'])}"
        return {"text": "gate green", "gate_green": True}

    def fix(state):
        last = next((t["outcome"] for t in reversed(state.get("transcript", [])) if t.get("error")), "")
        if EXEC == "cecli":
            cur["files"] = cecli_fix(cur["files"], last, "", blueprint)
        else:
            got, _ = globals()["build"](cur["files"], f"Fix the gate failure: {last}",
                                        (cur["nxt"] or {}).get("target", ""), blueprint)
        return {"text": "fix applied"}

    def escalate(state):
        unit = (state.get("unit") or {}).get("id", "?")
        last = next((t["outcome"] for t in reversed(state.get("transcript", [])) if t.get("error")), "")
        help_escalate(int(time.time()) % 100000, "auto-detected", f"flow-gate:{unit}", last,
                      [(cur["nxt"] or {}).get("target", "")])
        return {"text": f"HELP written for {unit}"}

    seams = SprintSeams(pick=pick, build=build, gate=gate, fix=fix, escalate=escalate)
    led = _ledger() if LEDGER else None
    committed = run_sprint_flow(seams, ledger=led)
    return f"flow loop done — {len(committed)} unit(s) proven this pass"


def main():
    try:
        if not requests.get(BASE.rstrip("/") + "/models", timeout=5).ok:
            log("[sprint] served endpoint not reachable — aborting."); return
    except Exception as e:
        log(f"[sprint] endpoint check failed: {e} — aborting."); return

    if FRESH:
        shutil.rmtree(PROJ, ignore_errors=True)
    os.makedirs(PROJ, exist_ok=True)
    open(HELP_FILE, "a").close()
    budget = f"{SECONDS}s" if SECONDS else "open-ended (until STOP file)"
    log(f"[sprint] model={MODEL} gate={GATE} budget={budget} proj={PROJ}")
    _start_heartbeat()
    _register_sprint()
    log(f"[sprint] arch={ARCH_FILE} | build=architect,coder,test-author,fixer | "
        f"council=architect,coder,fixer,product-manager(qwen25),engagement-manager(qwen25) | stop: touch {STOP_FILE}")

    t0 = time.time()
    nxt = {"done": False, "target": "main.js", "instruction": "Add the most valuable next improvement."}
    last_sig, repeat, help_id, open_help, cinv = "", 0, 0, None, 0
    last_err_text = ""
    it = 0
    stopped = "?"
    _kg_current = None        # KG-mode: the node currently being built (marked done once the gate is green)
    if KG_MODE and LEDGER:    # resume-from-git: re-mark nodes the ledger already attests as done
        _kg_seed_from_ledger()
    _agy_tried: set = set()   # error signatures already handed to the frontier unblocker (one shot each)

    def agent_help(htext, phase, named):
        nonlocal help_id, open_help
        if htext and open_help is None:
            help_id += 1
            open_help = help_id
            help_escalate(help_id, "agent-declared", phase, htext, named)

    existing = load_project()
    if existing and any(k.endswith(("index.html", "default.project.json")) for k in existing):
        files = existing
        blueprint = open(BLUEPRINT_FILE, encoding="utf-8").read() if os.path.isfile(BLUEPRINT_FILE) else plan(files)
        if os.path.isfile(HELP_FILE):
            help_id = open(HELP_FILE, encoding="utf-8").read().count("**HELP ")
        log(f"    [resume] loaded {len(files)} existing files — skipping ideate")
    else:
        blueprint = plan()                       # ARCHITECT designs first
        files, ihelp = ideate(blueprint)         # CODER implements the handoff
        agent_help(ihelp, "ideate", sorted(files))
        if HAS_SPEC_LAYER:
            test_author(files, blueprint)        # TEST-AUTHOR writes the initial specs
    while True:
        it += 1
        if FLOW_MODE:                                # item #6: the loop semantics live in the document
            stopped = _flow_loop(files, blueprint); break
        if os.path.exists(STOP_FILE):
            stopped = "STOP file"; break
        if SECONDS and time.time() - t0 > SECONDS:
            stopped = "time budget"; break
        if MAX_ITERS and it > MAX_ITERS:
            stopped = f"iteration cap ({MAX_ITERS})"; break
        while os.path.exists(PAUSE_FILE) and not os.path.exists(STOP_FILE):   # mission-control pause
            it -= 1                                  # don't burn an iteration while paused
            time.sleep(3)
            it += 1
        try:
            v = validate_fn(PROJ)
            elapsed = int(time.time() - t0)
            status(sprint=os.path.basename(PROJ), gate=GATE, iteration=it, elapsed_s=elapsed,
                   valid=v["valid"], biggest_tok=v.get("biggest"), files=sorted(files),
                   last_error=("" if v["valid"] else "; ".join(v["errs"])[:300]),
                   help_open=open_help, help_count=help_id, done=False)
            log(f"[it {it} | {elapsed}s] valid={v['valid']}"
                + ("" if v["valid"] else " :: " + "; ".join(v["errs"])[:140]))

            if v["valid"]:
                last_sig, repeat, cinv = "", 0, 0
                snapshot_green(files)
                if AGENT_BACKEND == "swarm" and last_err_text:
                    try:
                        les = _reflect("fixer", f"You just fixed this gate failure: {last_err_text}")
                        log(f"    [reflect] fixer learned: {les[:90]}")
                    except Exception as e:
                        log(f"    [reflect] skipped: {str(e)[:80]}")
                    last_err_text = ""
                if KG_MODE:
                    if _kg_current:                          # the prior step's build is now green -> mark it done
                        kg_mark_done(_kg_current)
                        log(f"    [kg] {_kg_current} -> done")
                        if LEDGER:                           # ...and record a gate-green proof-commit
                            _ledger_commit(_kg_current, files)
                        _kg_current = None
                    r = kg_next(files)
                elif SPEC_MODE:
                    r = spec_next(files)
                else:
                    r = council_next(files, blueprint) if AGENT_BACKEND == "swarm" else review(files, blueprint)
                if r.get("done"):
                    stopped = ("all KG nodes done + gate green" if KG_MODE
                               else "all specs built + gate green" if SPEC_MODE
                               else "critic DONE + gate green"); break
                if KG_MODE:
                    _kg_current = r.get("_kg_node")
                nxt = r
                if EXEC == "cecli":
                    files = cecli_build(files, r["instruction"], r["target"], blueprint)  # cecli owns build+specs
                    audit_consistency(r["target"])   # qwen checks the built file vs the GLOSSARY (opt-in, advisory)
                else:
                    got, bhelp = build(files, r["instruction"], r["target"], blueprint)
                    agent_help(bhelp, "build", [r["target"]])
                    if HAS_SPEC_LAYER and any(_is_core(p) for p in got):
                        test_author(files, blueprint)   # keep specs in sync with the evolving core
                continue

            if v.get("oversized") and EXEC != "cecli":
                # refactor() is a single ~25KB hermes coder dispatch (ARCH + manifest + full file) that
                # HANGS to the 300s timeout, and it fires on RED-before-fix — so for the cecli swarm we
                # skip it: cecli owns its own structure, and oversized is a soft warning (see gate_cli).
                refactor(files, v.get("oversized_file") or v.get("biggest_file"))
                continue

            named = sorted(set(re.findall(r"([\w./\-]+\.(?:js|mjs|html|css|json))", "; ".join(v["errs"]))))
            sig = err_signature(v["errs"])
            repeat = repeat + 1 if sig == last_sig else 1
            last_sig = sig
            cinv += 1
            if cinv >= REGRESS_LIMIT and os.path.isdir(LASTGOOD) and open_help is None:
                files = restore_green()
                write_project(files)
                help_id += 1
                open_help = help_id
                help_escalate(help_id, "regression-guard", "validate",
                              f"Reverted to last-green after {cinv} consecutive invalid iterations — the "
                              f"agents kept breaking the working build. Last error:\n"
                              + "; ".join(v["errs"])[:900] + "\n\nGuidance: make the SMALLEST change toward "
                              "the goal; do NOT refactor files that already work. If a feature truly can't be "
                              "added without breaking the core, say so via a HELP_NEEDED line.", named)
                cinv = 0
                last_sig, repeat = "", 0
                continue
            answer = None
            if open_help is not None:
                answer = help_check_answer(open_help)
                if answer:
                    log(f"    [HELP {open_help}] supervisor answered — injecting + resuming")
                    help_resolve(open_help); open_help = None; repeat = 0
            if open_help is None and repeat >= STUCK_REPEAT:
                if AGY and sig not in _agy_tried and len(_agy_tried) < AGY_MAX:
                    _agy_tried.add(sig)
                    log(f"    [agy] auto-stuck ({repeat}x same error) — frontier unblocker before human escalation")
                    antigravity_unblock("; ".join(v["errs"])[:1500], named)
                    continue                  # re-validate; agy may have resolved it, else next pass escalates
                help_id += 1
                open_help = help_id
                help_escalate(help_id, "auto-stuck", "validate",
                              f"Gate failed {repeat}x with the same error"
                              + ("; the frontier unblocker (agy) also could not resolve it" if AGY else
                                 "; agents can't self-repair")
                              + ":\n" + "; ".join(v["errs"])[:1200], named)
            # route: a spec that won't LOAD is the test-author's; everything else is the fixer's (impl).
            last_err_text = "; ".join(v["errs"])[:400]
            if EXEC == "cecli":
                files = cecli_fix(files, "; ".join(v["errs"])[:1000], answer, blueprint)
            elif _spec_load_error(v["errs"]) and HAS_SPEC_LAYER:
                test_author(files, blueprint, repair_error="; ".join(v["errs"])[:1000])
            else:
                _got, bhelp = fix(files, "; ".join(v["errs"])[:1000], answer, blueprint)
                agent_help(bhelp, "fix", named)
        except Exception as e:
            log(f"[it {it}] iteration error (continuing): {str(e)[:160]}")
            time.sleep(5)

    elapsed = int(time.time() - t0)
    v = validate_fn(PROJ)
    status(sprint=os.path.basename(PROJ), gate=GATE, iteration=it, elapsed_s=elapsed,
           valid=v["valid"], biggest_tok=v.get("biggest"), files=sorted(files),
           last_error=("" if v["valid"] else "; ".join(v["errs"])[:300]),
           help_open=open_help, help_count=help_id, done=True, stopped_reason=stopped)
    log(f"[sprint] DONE in {elapsed}s  stopped={stopped}  final valid={v['valid']}  "
        f"files={sorted(files)}  helps={help_id}")


if __name__ == "__main__":
    main()
