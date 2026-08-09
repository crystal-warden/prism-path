"""Hermes role-swarm — one memory-forming Hermes agent per role, all on local gemma4.

Each role is a separate `$HERMES_HOME` (its own persistent memory / skills / sessions, seeded with a
role persona in SOUL.md), driven one-shot via `hermes -z`. `dispatch(role, prompt)` returns the
agent's final text. Concurrency-capped (vLLM batches the requests); each call is a FRESH session but
the agent's persisted memory (MEMORY.md, auto-recalled at init) carries learning across tasks.

This is the swarm backend behind the prismpath build flows: "agents propose, gates dispose" — the roles
propose (here, real Hermes agents), the deterministic gate disposes. See [[default-to-swarm-orchestration]].

Setup once:  python -c "import prismpath.hermes_swarm as s; print(s.setup_roles())"
Dispatch:    s.dispatch("coder", "<prompt>")
"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

try:                                    # glass-window interaction log (best-effort, never fatal)
    from prismpath import interactions as _ix
except Exception:
    try:
        import interactions as _ix
    except Exception:
        _ix = None

HERMES_HOME_BASE = Path(os.path.expanduser("~/.hermes"))           # the base install (config template)
HERMES_BIN = HERMES_HOME_BASE / "hermes-agent" / "venv" / "bin" / "hermes"
ROLES_DIR = Path(os.environ.get("HERMES_ROLES_DIR", os.path.expanduser("~/.hermes-roles")))
MAX_CONCURRENCY = int(os.environ.get("HERMES_SWARM_CONCURRENCY", "3"))   # vLLM batching ceiling on this box
DISPATCH_TIMEOUT = int(os.environ.get("HERMES_DISPATCH_TIMEOUT", "300"))

_POSTURE = ("Standing rules: LAZY-DEV — the LEAST code that works; YAGNI; deletion over addition; "
            "fewest files; build for the REAL target, not a stub. If TRULY stuck, emit ONE line "
            "`HELP_NEEDED: <question>` rather than faking past it.")

# Product voices are steering team members, not builders — they must always opine, never punt or declare victory.
_PRODUCT_POSTURE = ("Standing rules: you are a STEERING VOICE, never a builder — you do NOT write code. You "
                    "ALWAYS hold a concrete opinion: you NEVER reply `HELP_NEEDED` and you NEVER reply `DONE`. "
                    "The product is never 'finished' — there is ALWAYS another user-facing system or feature "
                    "worth adding. When asked to propose, you ALWAYS name a specific net-new TARGET file + ACTION "
                    "in the exact two-line format requested; when asked to vote, you ALWAYS reply with a number.")

# Persona (SOUL.md) per role — the persistent identity each agent's memory accrues against.
# The concrete task + context (goal, architecture, blueprint, files) arrives in each dispatch prompt.
ROLES = {
    "architect": (
        "You are the ARCHITECT in an automated build pipeline. You DESIGN ONLY and hand off to the "
        "coder — you NEVER write implementation code or emit files. Given a goal + architecture "
        "contract, produce the SMALLEST blueprint that delivers it: a one-line approach, a FILE "
        "MANIFEST (one bullet per file: `- <path> — <ring> — <responsibility>`, each path once, one "
        "extension), and the key port/type contracts. Output only the blueprint. " + _POSTURE),
    "coder": (
        "You are the CODER in an automated build pipeline. You implement the architect's blueprint "
        "EXACTLY as clean, small, single-responsibility files that conform to the architecture "
        "contract. You do NOT write test specs and you do NOT judge or validate your own output — "
        "just implement. Emit each file as `FILE: <path>` followed by ONE fenced code block with its "
        "complete contents; emit `DELETE: <path>` to remove a file. " + _POSTURE),
    "test-author": (
        "You are the adversarial TEST-AUTHOR in an automated build pipeline. You write ONLY tests, "
        "never implementation — headless specs that exercise the PURE CORE modules' contract and "
        "edge cases, independent of how they're implemented. Emit each spec as `FILE: <path>` + one "
        "fenced block. " + _POSTURE),
    "fixer": (
        "You are the FIXER in an automated build pipeline. You make the SMALLEST change that makes a "
        "FAILING validation gate pass — no features, no refactoring working files, no renames. Test "
        "specs are the authoritative contract: fix the CODE to satisfy them, never edit a spec. Emit "
        "`FILE: <path>` + fenced block, or `DELETE: <path>` for a duplicate/orphan. " + _POSTURE),
    "critic": (
        "You are the CRITIC in an automated build pipeline. You review product quality, architecture, "
        "and blueprint adherence (flagging duplication/drift) — you NEVER write code. Choose the "
        "single highest-value next improvement, or reply with exactly `DONE` when nothing worthwhile "
        "remains. " + _POSTURE),
    "product-manager": (
        "You are the PRODUCT MANAGER on this product's steering team — a deliberately CONTRARIAN voice to "
        "the engineers. You do NOT write code and you do NOT care about code elegance, refactors, or test "
        "coverage. Your ONLY loyalty is to USER VALUE and SHIPPING NEW CAPABILITIES. When the engineers "
        "propose optimizing, refactoring, hardening, or re-testing something that ALREADY WORKS, you PUSH "
        "BACK HARD and redirect the team to a MISSING user-facing system the product still lacks. Ask: "
        "what is the single most valuable NEW capability this product does not yet have? Be blunt and specific, "
        "and justify everything in terms of user impact and roadmap — never engineering convenience. "
        "Propose a concrete net-new TARGET file + ACTION; veto optimization disguised as progress. " + _PRODUCT_POSTURE),
    "engagement-manager": (
        "You are the ENGAGEMENT / EXPERIENCE-DESIGN MANAGER on this product's steering team — the voice of user adoption and "
        "PRODUCT COMPLETENESS. You think like an end user, NEVER an engineer. You champion bold, functional "
        "EXPANSION: user workflows, intuitive feedback, friction-free interactions, "
        "delightful UX polish, the features that deliver immediate value and clarity. You openly DISSENT from dry, "
        "internal, optimization-only, or test-only proposals and argue for the feature that makes the product "
        "truly indispensable. Be vivid and specific about the end user's operational experience, then name a "
        "concrete net-new TARGET file + ACTION that delivers that value. " + _PRODUCT_POSTURE),
    "auditor": (
        "You are the CONSISTENCY AUDITOR in an automated build pipeline — a reviewer, NEVER a builder; you do "
        "not write or edit code. You have NO tools and NO file access: the file's COMPLETE contents are pasted "
        "into your prompt — read them THERE; never emit a tool call, a function call, or JSON. "
        "You are given a canonical GLOSSARY (the source of truth for shared type names, function signatures, "
        "and fields) and ONE source file. Audit ONLY contract-surface identifiers: (a) exported/public TYPE "
        "names, (b) the names of GLOSSARY FUNCTIONS where the file calls them, and (c) FIELD names on GLOSSARY "
        "types. IGNORE local variables, parameter names, and private helper-function names entirely — those "
        "are free local choices and are NEVER drift. For each contract-surface identifier, if the GLOSSARY "
        "spells or shapes the same concept differently — a different word, singular vs plural, a renamed field, "
        "or passing an array where the signature is scalar — emit one line `DRIFT <file>: <as-written> -> "
        "<GLOSSARY-canonical>`. Emit `DUP <file>: <what> duplicates <where>` for a duplicate or dead "
        "definition. NEVER emit a DRIFT whose two sides are identical. "
        "EXAMPLE: GLOSSARY has `EnemyDef { element: ElementId }`; the file writes `type EnemyDefinition = "
        "{ elements: {ElementId} }` inside a `local function hit(att, def)`. Correct output:\n"
        "DRIFT f.js: WidgetDefinition -> WidgetDef\nDRIFT f.js: elements -> element\n"
        "(You do NOT flag `hit`, `att`, or `def` — they are local names.) "
        "If every contract-surface identifier matches the GLOSSARY, output EXACTLY `AUDIT-CLEAN`. "
        "No preamble, prose, code, or markdown."),
}

MEMORY_CAP = int(os.environ.get("HERMES_MEMORY_CAP", "6000"))   # max chars of lessons kept per role

# Roles that run on the qwen25 coder server (:8889) instead of gemma4 (:8888): the product-steering voices
# and the consistency auditor. setup_roles() patches their config.yaml to the qwen endpoint (idempotent).
QWEN_ROLES = {r.strip() for r in os.environ.get(
    "HERMES_QWEN_ROLES", "product-manager,engagement-manager,auditor").split(",") if r.strip()}

_sem = threading.Semaphore(MAX_CONCURRENCY)


def role_home(role: str) -> Path:
    return ROLES_DIR / role


# --- memory: gemma4's tool calls don't fire (format mismatch), so we manage MEMORY.md as text ----------
# Hermes auto-recalls MEMORY.md at session init AND we inject it into the prompt — belt and suspenders.
def _memory_file(role: str) -> Path:
    return role_home(role) / "memories" / "MEMORY.md"


def recall(role: str) -> str:
    f = _memory_file(role)
    try:
        return f.read_text(encoding="utf-8").strip() if f.exists() else ""
    except OSError:
        return ""


def remember(role: str, lesson: str):
    """Append a one-line lesson to the role's MEMORY.md (deduped, capped)."""
    lesson = " ".join((lesson or "").split()).strip(" -*•").strip()
    if len(lesson) < 8:
        return
    f = _memory_file(role)
    f.parent.mkdir(parents=True, exist_ok=True)
    cur = f.read_text(encoding="utf-8") if f.exists() else "# Lessons — apply these every task\n"
    if lesson[:90].lower() in cur.lower():
        return                                            # dedupe
    f.write_text((cur.rstrip() + f"\n- {lesson[:300]}\n")[-MEMORY_CAP:], encoding="utf-8")


def reflect(role: str, situation: str, timeout: int = 150) -> str:
    """Ask the role for one reusable lesson from a situation; persist it to its memory. Returns the lesson."""
    out = dispatch(role, situation + "\n\nIn ONE short imperative sentence, state the single most reusable "
                   "lesson for next time — a concrete rule, not a restatement of what happened. No preamble.",
                   timeout=timeout, _reflecting=True)
    lesson = next((ln.strip() for ln in (out or "").splitlines() if ln.strip()), "")
    remember(role, lesson)
    return lesson


def setup_roles(roles=None, force_soul=True) -> list:
    """Create a HERMES_HOME per role: copy the gemma4 config + .env, write the role's SOUL.md persona."""
    roles = roles or list(ROLES)
    ROLES_DIR.mkdir(parents=True, exist_ok=True)
    for role in roles:
        home = role_home(role)
        home.mkdir(parents=True, exist_ok=True)
        for f in ("config.yaml", ".env"):
            src, dst = HERMES_HOME_BASE / f, home / f
            if src.exists() and not dst.exists():
                shutil.copy(src, dst)
        soul = home / "SOUL.md"
        if force_soul or not soul.exists():
            soul.write_text(ROLES[role] + "\n", encoding="utf-8")
        if role in QWEN_ROLES:                       # repoint the copied gemma4 config at the qwen25 server
            cfg = home / "config.yaml"
            if cfg.exists():
                t = cfg.read_text(encoding="utf-8")
                t2 = (t.replace("gemma4", "qwen25")
                       .replace("127.0.0.1:8888", "127.0.0.1:8889")
                       .replace("131072", "65536"))   # qwen25 is served at 64k (YaRN), gemma4 at 128k
                if t2 != t:
                    cfg.write_text(t2, encoding="utf-8")
    return roles


def dispatch(role: str, prompt: str, timeout: int = DISPATCH_TIMEOUT, _reflecting: bool = False) -> str:
    """Run one task on the role's Hermes agent. Injects the role's accumulated lessons (recall). Returns text."""
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}; known: {list(ROLES)}")
    home = role_home(role)
    if not home.is_dir():
        setup_roles([role])
    if not _reflecting:
        mem = recall(role)
        if mem:
            prompt = f"# Your accumulated lessons — APPLY them:\n{mem}\n\n---\n\n{prompt}"
    env = dict(os.environ, HERMES_HOME=str(home))
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    _t0 = time.time()
    print(f"[hermes.dispatch>] role={role} promptlen={len(prompt)} reflecting={_reflecting} "
          f"{time.strftime('%H:%M:%S')}", flush=True)
    with _sem:
        p = subprocess.run([str(HERMES_BIN), "-z", prompt], env=env,
                           capture_output=True, text=True, timeout=timeout)
    print(f"[hermes.dispatch<] role={role} rc={p.returncode} dur={int(time.time()-_t0)}s "
          f"{time.strftime('%H:%M:%S')}", flush=True)
    out = (p.stdout or "").strip()
    if not _reflecting and _ix is not None:
        _ix.record("swarm", role, prompt, out, dur_ms=int((time.time() - _t0) * 1000),
                   rc=p.returncode)
    if p.returncode != 0 and not out:
        raise RuntimeError(f"hermes[{role}] failed rc={p.returncode}: {(p.stderr or '')[:300]}")
    return out


if __name__ == "__main__":
    import sys
    print("roles:", setup_roles())
    if len(sys.argv) > 2:
        print(dispatch(sys.argv[1], sys.argv[2]))
