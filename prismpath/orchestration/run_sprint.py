# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Generic TIMED + SUPERVISED agent build sprint - a 5-ROLE pipeline on the served model.

Evolves the old builder+critic loop into separated roles with hard boundaries (the architect never
builds; the coder never validates its own work):

  ARCHITECT  designs only -> a persisted BLUEPRINT.md (file manifest + port contracts). No code.
  CODER      implements the blueprint (ideate + one critic-chosen feature per turn). No tests, no
             self-grading. Can remove a file with a `DELETE: <path>` line.
  TEST-AUTHOR writes/maintains the headless specs (the behavioral validation) - independent of the
             implementation. Owns specs; never touches impl. (Only when the gate has a spec layer.)
  GATE       deterministic validation (syntax/type/build/logic).  [gates.py / a gate plugin]
  FIXER      makes the SMALLEST change to satisfy the gate (impl only; specs are the authoritative
             contract - it conforms code to them, never edits them).
  CRITIC     reviews quality + architecture + blueprint adherence; picks the next step or says DONE.

Flow:  nudge -> ARCHITECT -(blueprint)-> CODER -(code)-> TEST-AUTHOR -(specs)-> GATE -> CRITIC -> loop

Runs on a WALL CLOCK (open-ended until a STOP file, or until the critic says DONE and the gate is
green), and escalates hard problems to a HELP.md file a supervisor answers out-of-band.
"""
from __future__ import annotations

from dataclasses import dataclass
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

import requests
from prismpath import canon

try:
    from prismpath.ledgers import interactions as _ix
except Exception:
    try:
        import interactions as _ix
    except Exception:
        _ix = None


class BrowserGate:
    """Built-in browser validation gate adapter."""

    from prismpath.orchestration.gates import validate_browser as validate  # type: ignore

    HAS_SPEC_LAYER = False
    ARCH_PATH = ""
    RAG_INDEX = ""
    LESSONS_PATH = ""
    FILE_EXTS = (".html", ".js", ".mjs", ".css", ".json")
    SOURCE_DIRS = ()
    KG_SOURCE_DIRS = ()
    ENTRY_FILES = ()
    CORE_DIR = ""
    SPEC_SUFFIXES = ()
    TESTABLE_DIRS = ()
    BUILD_RULES = ""
    BUILD_RULES_SPEC = ""


def select_gate(gate_name: str):
    """Factory for loading gate plugins by name without module-level rebinding."""
    if gate_name == "browser":
        return BrowserGate()
    from prismpath.plugins import load_gate

    return load_gate(gate_name)


@dataclass(frozen=True)
class SprintConfig:
    """Configuration dataclass holding all settings for a sprint run."""

    proj: str
    llm_base: str = "http://127.0.0.1:8888/v1"
    llm_model: str = "gemma4"
    gate: str = "browser"
    seconds: int = 0
    max_iters: int = 0
    max_new: int = 12000
    enable_thinking: bool = False
    stuck_repeat: int = 3
    regress_limit: int = 4
    extend: bool = False
    ledger: bool = False
    flow_mode: bool = False
    nudge: str = ""
    arch_file: str = ""
    arch: str = ""
    agent_backend: str = "served"
    exec_mode: str = "agent"
    cecli_bin: str = ""
    cecli_reflections: int = 3
    cecli_timeout: int = 1200
    cecli_settings: str = ""
    cecli_testcmd: str = ""
    audit: bool = False
    glossary_file: str = ""
    agy: bool = False
    agy_bin: str = ""
    agy_model: str = "gemini-3.1-pro"
    agy_sandbox: bool = True
    agy_timeout: int = 900
    agy_max: int = 4
    spec_dir: str = ""
    spec_order: tuple[str, ...] = ()
    spec_file: str = ""
    kg_path: str = ""
    rag: bool = False
    rag_index: str = ""
    rag_k: int = 4
    lessons_on: bool = True
    lessons_file: str = ""
    lessons_block: str = ""
    mc_registry: str = "~/.prismpath/sprints.json"
    ledger_run_id: str = ""
    ledger_dir: str = ""

    def __post_init__(self):
        gate_plugin = select_gate(self.gate)
        if not self.arch_file:
            arch_path = getattr(gate_plugin, "ARCH_PATH", "")
            if not arch_path:
                arch_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "nudges",
                    "APP_ARCHITECTURE.md",
                )
            object.__setattr__(self, "arch_file", arch_path)
        if not self.arch and self.arch_file and os.path.isfile(self.arch_file):
            try:
                arch_txt = open(self.arch_file, encoding="utf-8").read()
                object.__setattr__(self, "arch", arch_txt)
            except OSError:
                pass
        if not self.glossary_file and self.proj:
            object.__setattr__(self, "glossary_file", os.path.join(self.proj, "specs", "GLOSSARY.md"))
        if self.spec_file and not self.kg_path:
            object.__setattr__(self, "kg_path", os.path.splitext(self.spec_file)[0] + ".kg.json")
        if not self.rag_index and gate_plugin:
            rag_idx = getattr(gate_plugin, "RAG_INDEX", "")
            if rag_idx:
                object.__setattr__(self, "rag_index", rag_idx)
        if not self.lessons_file and gate_plugin:
            lessons_path = getattr(gate_plugin, "LESSONS_PATH", "")
            if lessons_path:
                object.__setattr__(self, "lessons_file", lessons_path)
        if self.lessons_on and self.lessons_file and not self.lessons_block and os.path.isfile(self.lessons_file):
            try:
                txt = open(self.lessons_file, encoding="utf-8").read().strip()
                if txt:
                    object.__setattr__(self, "lessons_block", "\n\n" + txt + "\n")
            except OSError:
                pass
        if not self.cecli_testcmd and self.proj:
            sprint_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cmd = f"bash {os.path.join(sprint_dir, 'gate_test.sh')} {self.proj}"
            object.__setattr__(self, "cecli_testcmd", cmd)
        if not self.cecli_bin:
            object.__setattr__(self, "cecli_bin", os.path.expanduser("~/.cecli-venv/bin/cecli"))
        if not self.agy_bin:
            object.__setattr__(self, "agy_bin", os.path.expanduser("~/.local/bin/agy"))

    @classmethod
    def from_env(cls) -> SprintConfig:
        """Construct SprintConfig by reading environment variables."""
        proj = os.environ.get("SPRINT_PROJ", "")
        if not proj:
            raise KeyError("SPRINT_PROJ environment variable is required")

        nudge_file = os.environ.get("SPRINT_NUDGE_FILE")
        if nudge_file and os.path.isfile(nudge_file):
            nudge = open(nudge_file, encoding="utf-8").read()
        else:
            nudge = os.environ.get("SPRINT_NUDGE", "")

        gate_name = os.environ.get("SPRINT_GATE", "browser")
        gate_plugin = select_gate(gate_name)

        arch_file = (
            os.environ.get("SPRINT_ARCH")
            or getattr(gate_plugin, "ARCH_PATH", "")
            or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "nudges", "APP_ARCHITECTURE.md")
        )
        arch = ""
        if arch_file and os.path.isfile(arch_file):
            arch = open(arch_file, encoding="utf-8").read()

        sprint_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cecli_bin = os.environ.get("SPRINT_CECLI_BIN", os.path.expanduser("~/.cecli-venv/bin/cecli"))
        cecli_testcmd = os.environ.get("SPRINT_CECLI_TESTCMD", f"bash {os.path.join(sprint_dir, 'gate_test.sh')} {proj}")

        glossary_file = os.environ.get("SPRINT_GLOSSARY", "")
        if not glossary_file and proj:
            glossary_file = os.path.join(proj, "specs", "GLOSSARY.md")

        spec_dir = os.environ.get("SPRINT_SPEC_DIR", "")
        spec_order_raw = os.environ.get("SPRINT_SPEC_ORDER", "")
        spec_order = tuple(spec_item.strip() for spec_item in spec_order_raw.split(",") if spec_item.strip())

        spec_file = os.environ.get("SPRINT_SPEC_FILE", "")
        kg_path = os.environ.get("SPRINT_KG", "")
        if spec_file and not kg_path:
            kg_path = os.path.splitext(spec_file)[0] + ".kg.json"

        rag_index = os.environ.get("SPRINT_RAG_INDEX") or getattr(gate_plugin, "RAG_INDEX", "")

        lessons_on = os.environ.get("SPRINT_LESSONS", "1") == "1"
        lessons_file = os.environ.get("SPRINT_LESSONS_FILE") or getattr(gate_plugin, "LESSONS_PATH", "")
        lessons_block = ""
        if lessons_on and lessons_file and os.path.isfile(lessons_file):
            try:
                txt = open(lessons_file, encoding="utf-8").read().strip()
                if txt:
                    lessons_block = "\n\n" + txt + "\n"
            except Exception:
                pass

        return cls(
            proj=proj,
            llm_base=os.environ.get("LLM_BASE", "http://127.0.0.1:8888/v1"),
            llm_model=os.environ.get("LLM_MODEL", "gemma4"),
            gate=gate_name,
            seconds=int(os.environ.get("SPRINT_SECONDS", "0")),
            max_iters=int(os.environ.get("SPRINT_MAX_ITERS", "0")),
            max_new=int(os.environ.get("SPRINT_MAX_NEW", "12000")),
            enable_thinking=os.environ.get("SPRINT_ENABLE_THINKING", "0") == "1",
            stuck_repeat=int(os.environ.get("SPRINT_STUCK_REPEAT", "3")),
            regress_limit=int(os.environ.get("SPRINT_REGRESS_LIMIT", "4")),
            extend=os.environ.get("SPRINT_EXTEND", "0") == "1",
            ledger=os.environ.get("SPRINT_LEDGER", "0") == "1",
            flow_mode=os.environ.get("SPRINT_FLOW", "0") == "1",
            nudge=nudge,
            arch_file=arch_file,
            arch=arch,
            agent_backend=os.environ.get("SPRINT_AGENT", "served"),
            exec_mode=os.environ.get("SPRINT_EXEC", "agent"),
            cecli_bin=cecli_bin,
            cecli_reflections=int(os.environ.get("SPRINT_CECLI_REFLECTIONS", "3")),
            cecli_timeout=int(os.environ.get("SPRINT_CECLI_TIMEOUT", "1200")),
            cecli_settings=os.environ.get("SPRINT_CECLI_SETTINGS", ""),
            cecli_testcmd=cecli_testcmd,
            audit=os.environ.get("SPRINT_AUDIT", "0") == "1",
            glossary_file=glossary_file,
            agy=os.environ.get("SPRINT_AGY", "0") == "1",
            agy_bin=os.environ.get("SPRINT_AGY_BIN", os.path.expanduser("~/.local/bin/agy")),
            agy_model=os.environ.get("SPRINT_AGY_MODEL", "gemini-3.1-pro"),
            agy_sandbox=os.environ.get("SPRINT_AGY_SANDBOX", "1") == "1",
            agy_timeout=int(os.environ.get("SPRINT_AGY_TIMEOUT", "900")),
            agy_max=int(os.environ.get("SPRINT_AGY_MAX", "4")),
            spec_dir=spec_dir,
            spec_order=spec_order,
            spec_file=spec_file,
            kg_path=kg_path,
            rag=os.environ.get("SPRINT_RAG", "0") == "1",
            rag_index=rag_index,
            rag_k=int(os.environ.get("SPRINT_RAG_K", "4")),
            lessons_on=lessons_on,
            lessons_file=lessons_file,
            lessons_block=lessons_block,
            mc_registry=os.environ.get("MC_REGISTRY", "~/.prismpath/sprints.json"),
            ledger_run_id=os.environ.get("SPRINT_LEDGER_RUN", ""),
            ledger_dir=os.environ.get("PRISMPATH_LEDGER_DIR", ""),
        )

    @property
    def goal(self) -> str:
        return f"PROJECT GOAL - stay strictly on this; do NOT drift into a different kind of app:\n{self.nudge}\n\n"

    @property
    def stop_file(self) -> str:
        return os.path.join(self.proj, "STOP")

    @property
    def pause_file(self) -> str:
        return os.path.join(self.proj, "PAUSE")

    @property
    def help_file(self) -> str:
        return os.path.join(self.proj, "HELP.md")

    @property
    def status_file(self) -> str:
        return os.path.join(self.proj, "status.json")

    @property
    def log_file(self) -> str:
        return os.path.join(self.proj, "sprint.log")

    @property
    def blueprint_file(self) -> str:
        return os.path.join(self.proj, "BLUEPRINT.md")

    @property
    def lastgood(self) -> str:
        return self.proj.rstrip("/") + ".lastgood"

    @property
    def spec_mode(self) -> bool:
        return bool(self.spec_dir and self.spec_order)

    @property
    def kg_mode(self) -> bool:
        return bool(self.spec_file)

    @property
    def gate_plugin(self):
        return select_gate(self.gate)

    @property
    def validate_fn(self):
        return self.gate_plugin.validate

    @property
    def has_spec_layer(self) -> bool:
        return getattr(self.gate_plugin, "HAS_SPEC_LAYER", False)

    @property
    def src_ext() -> tuple[str, ...]:
        return tuple(getattr(self.gate_plugin, "FILE_EXTS", None) or (".html", ".js", ".mjs", ".css", ".json"))


POSTURE = (
    "Standing rules: (1) LAZY-DEV - the LEAST code that works; YAGNI; prefer stdlib/native features/"
    "existing files; no abstractions, deps, or boilerplate nobody asked for; deletion over addition; "
    "fewest files. (2) Build for the REAL target, not a stub. (3) If you are TRULY stuck (an ambiguity "
    "you can't resolve, a contract you cannot satisfy after trying), emit ONE line "
    "`HELP_NEEDED: <specific question>` and a human will answer - do NOT fake or stub past it."
)

ARCHITECT_SYS = (
    "You are a software ARCHITECT. You DESIGN ONLY and then hand off to a coder - you NEVER write "
    "implementation code and you NEVER emit files. From the GOAL and the architecture contract, produce "
    "the SMALLEST blueprint that delivers it (YAGNI; fewest files). Output EXACTLY:\n"
    "1. one line: the approach.\n"
    "2. `## FILE MANIFEST` - one bullet per file as `- <relative/path> - <ring> - <single responsibility>`. "
    "List every path ONCE, in ONE extension; include the spec files the test-author will fill.\n"
    "3. `## CONTRACTS` - the key port/type signatures in one fenced code block.\n"
    "Output ONLY this blueprint. No prose beyond the above, NO implementation, NO FILE: blocks. " + POSTURE
)

BUILDER_SYS = (
    "You are an inventive, detail-oriented CODER. You implement the ARCHITECT's blueprint EXACTLY, writing "
    "clean, small, single-responsibility files that conform to the architecture contract. You do NOT write "
    "test specs (a separate test author owns all tests) and you do NOT judge or validate your own output "
    "(a deterministic gate + a reviewer do that) - just implement. To remove a file, emit a line "
    "`DELETE: <relative/path>` (this actually deletes it; do not leave orphans). " + POSTURE
)

TESTER_SYS = (
    "You are an adversarial TEST AUTHOR. You write ONLY tests, NEVER implementation. Following the "
    "architecture contract's testing section, write/maintain headless specs that exercise the PURE CORE "
    "modules' behaviour, edge cases, and contract violations - INDEPENDENT of how they're implemented "
    "(test the CONTRACT; try to break it). Keep specs small and assert-based. Emit ONLY spec files in "
    "FILE: format. " + POSTURE
)

FIXER_SYS = (
    "You are a careful FIXER/debugger. Make the SMALLEST change that makes the FAILING validation pass - "
    "nothing more. Do NOT add features, do NOT refactor files that already work, do NOT rename. The test "
    "specs are the AUTHORITATIVE contract (written by a separate test author): if a test fails, fix the "
    "CODE to satisfy it - NEVER edit a spec. Preserve the blueprint's manifest; if the error is a "
    "duplicate/orphan file, emit `DELETE: <path>`. " + POSTURE
)

CRITIC_SYS = (
    "You are a discerning REVIEWER with strong taste. You enforce the architecture, the BLUEPRINT, and the "
    "lazy-dev posture (reward simplicity/deletion; flag scaffolding built ahead of need, duplication, and "
    "drift from the manifest). You review ONLY - you never write code. " + POSTURE
)

_ROLE_OF = {
    ARCHITECT_SYS: "architect",
    BUILDER_SYS: "coder",
    TESTER_SYS: "test-author",
    FIXER_SYS: "fixer",
    CRITIC_SYS: "critic",
}

FILE_RE = re.compile(r"FILE:\s*([^\n`]+?)\s*\n+```[a-zA-Z0-9]*\n(.*?)```", re.DOTALL)
HELP_RE = re.compile(r"HELP_NEEDED:\s*(.+)")
DELETE_RE = re.compile(r"^\s*DELETE:\s*([^\n`]+?)\s*$", re.MULTILINE)
_NON_SRC = {
    "package.json",
    "status.json",
    "HELP.md",
    "sprint.log",
    "STOP",
    "NUDGE.md",
    "orch_run.out",
    "BLUEPRINT.md",
}


def log(msg: str, config: SprintConfig | None = None):
    """Write log entry to stdout and sprint.log if config is provided."""
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    if config and config.log_file:
        try:
            with open(config.log_file, "a", encoding="utf-8") as file_handle:
                file_handle.write(line + "\n")
        except Exception:
            pass


def _doc_block(hits: list) -> str:
    """Format documentation hits into an prompt block."""
    if not hits:
        return ""
    block_str = "## Relevant OFFICIAL documentation (use these real APIs - do not guess):\n"
    for hit_entry in hits:
        block_str += f"\n--- {hit_entry['source']}/{hit_entry['path']} ---\n{hit_entry['text']}\n"
    return block_str


def retrieve_docs(query: str, config: SprintConfig) -> str:
    """Retriever role: fetch target docs for query."""
    if not config.rag:
        return ""
    try:
        from prismpath.orchestration import retriever as _rtr
    except Exception:
        try:
            import retriever as _rtr
        except Exception:
            return ""
    try:
        hits = _rtr.retrieve(query, config.rag_k, config.rag_index)
    except Exception as exc:
        log(f"    [rag] retrieve failed: {str(exc)[:100]}", config)
        return ""
    block_str = _doc_block(hits)
    if _ix:
        hits_meta = [
            {
                "source": hit_entry.get("source", ""),
                "path": hit_entry.get("path", ""),
                "score": round(float(hit_entry.get("score", 0)), 3),
            }
            for hit_entry in hits
        ]
        _ix.record(
            "retriever",
            "retriever",
            query,
            block_str or "(no hits)",
            phase="retrieve",
            hits=len(hits),
            hits_meta=hits_meta,
        )
    log(f"    [rag] {len(hits)} docs grounding: {query[:55]}", config)
    return ("\n\n" + block_str) if block_str else ""


def _cecli_run(message: str, focus: list, config: SprintConfig, label: str = "build") -> dict:
    """Run one CECLI diff-edit pass over project directory."""
    focus_files = sorted({file_item for file_item in focus if file_item and os.path.isfile(os.path.join(config.proj, file_item))})
    command_args = [
        config.cecli_bin,
        "--model",
        f"openai/{config.llm_model}",
        "--openai-api-base",
        config.llm_base,
        "--edit-format",
        "diff",
        "--map-tokens",
        "2048",
        "--auto-test",
        "--test-cmd",
        config.cecli_testcmd,
        "--no-auto-lint",
        "--max-reflections",
        str(config.cecli_reflections),
        "--no-git",
        "--yes",
        "--no-stream",
        "--disable-playwright",
    ]
    if config.cecli_settings:
        command_args += ["--model-settings-file", config.cecli_settings]
    command_args += focus_files + ["--message", message]
    run_env = dict(os.environ, OPENAI_API_KEY=os.environ.get("OPENAI_API_KEY", "dummy"))
    start_time = time.time()
    if _ix:
        _ix.record(
            "cecli",
            label,
            f"build started - focus: {', '.join(focus_files)}",
            "cecli diff-edit + auto-test in progress...",
            phase=label,
        )
    output_text = ""
    return_code = None
    try:
        proc_res = subprocess.run(
            command_args,
            cwd=config.proj,
            env=run_env,
            timeout=config.cecli_timeout,
            capture_output=True,
            text=True,
        )
        return_code = proc_res.returncode
        output_text = (proc_res.stdout or "") + (("\n--- stderr ---\n" + proc_res.stderr) if proc_res.stderr else "")
        log(f"    [cecli] rc={return_code} (focus={','.join(focus_files) or 'repo-map'})", config)
    except subprocess.TimeoutExpired:
        output_text = f"(cecli timed out after {config.cecli_timeout}s)"
        log(f"    [cecli] timeout after {config.cecli_timeout}s", config)
    except Exception as exc:
        output_text = f"(cecli error: {exc})"
        log(f"    [cecli] error: {str(exc)[:120]}", config)
    if _ix:
        _ix.record(
            "cecli",
            label,
            message,
            output_text,
            phase=label,
            dur_ms=int((time.time() - start_time) * 1000),
            rc=return_code,
            focus=",".join(focus_files),
        )
    gate_plugin = config.gate_plugin
    reloc_extensions = getattr(gate_plugin, "FILE_EXTS", ()) if gate_plugin else ()
    relocatable_files: list = []
    for ext_str in reloc_extensions:
        relocatable_files += glob.glob(os.path.join(config.proj, "**", "*" + ext_str), recursive=True)
    for file_path in relocatable_files:
        rel_path = os.path.relpath(file_path, config.proj)
        if not re.search(r"^(src|tests)/.+/src/", rel_path):
            continue
        match_root = re.match(r"^((?:src|tests)/(?:[^/]+/)+?)(?=\1)", rel_path)
        fixed_path = rel_path[len(match_root.group(1)) :] if match_root else None
        try:
            if fixed_path and fixed_path != rel_path and not os.path.exists(os.path.join(config.proj, fixed_path)):
                destination_path = os.path.join(config.proj, fixed_path)
                os.makedirs(os.path.dirname(destination_path), exist_ok=True)
                shutil.move(file_path, destination_path)
                log(f"    [cecli] relocated misplaced {rel_path} -> {fixed_path}", config)
            else:
                os.remove(file_path)
                log(f"    [cecli] pruned misplaced file {rel_path}", config)
        except OSError:
            pass
    return load_project(config)


def _src_context(config: SprintConfig) -> list:
    """Collect source files for CECLI context, skipping bulk sources in KG mode unless referenced."""
    out_files = []
    gate_plugin = config.gate_plugin
    extensions = tuple(getattr(gate_plugin, "FILE_EXTS", ()) if gate_plugin else ())
    sub_directories = getattr(
        gate_plugin,
        "KG_SOURCE_DIRS" if config.kg_mode else "SOURCE_DIRS",
        (),
    ) if gate_plugin else ()
    for sub_dir in sub_directories:
        directory_path = os.path.join(config.proj, sub_dir)
        if os.path.isdir(directory_path):
            out_files += [
                os.path.join(sub_dir, file_name)
                for file_name in os.listdir(directory_path)
                if file_name.endswith(extensions)
            ]
    core_dir_relative = getattr(gate_plugin, "CORE_DIR", "") if gate_plugin else ""
    core_dir_path = os.path.join(config.proj, core_dir_relative) if core_dir_relative else ""
    if config.kg_mode and core_dir_path and os.path.isdir(core_dir_path):
        spec_content = ""
        try:
            spec_content = open(_abs(config.spec_file, config.proj), encoding="utf-8", errors="ignore").read()
        except OSError:
            pass
        for file_name in sorted(os.listdir(core_dir_path)):
            if file_name.endswith(extensions):
                file_stem = os.path.splitext(file_name)[0]
                if re.search(r"\b" + re.escape(file_stem) + r"\b", spec_content):
                    out_files.append(os.path.join(core_dir_relative, file_name))
    for entry_file in (getattr(gate_plugin, "ENTRY_FILES", ()) if gate_plugin else ()):
        if os.path.isfile(os.path.join(config.proj, entry_file)):
            out_files.append(entry_file)
    return out_files


def cecli_build(files: dict, instruction: str, target: str, blueprint: str, config: SprintConfig) -> dict:
    """Implement one review-chosen action via diff-editing using CECLI."""
    gate_plugin = config.gate_plugin

    def _plugin_rules(attr_name: str) -> str:
        rules_str = getattr(gate_plugin, attr_name, "") if gate_plugin else ""
        return ("\n" + rules_str) if rules_str else ""

    if config.spec_mode:
        msg_text = (
            config.goal
            + config.lessons_block
            + f"\n\nTASK: {instruction}\nTarget file: {target}.\n"
            + "Rules: implement EXACTLY the embedded spec; least code; make small targeted edits; reference "
            "other modules ONLY by their exact GLOSSARY type names and function signatures. Keep the test "
            "command passing."
            + _plugin_rules("BUILD_RULES_SPEC")
        )
    else:
        msg_text = (
            config.goal
            + config.arch
            + "\n\nAPPROVED BLUEPRINT (conform to it):\n"
            + blueprint
            + config.lessons_block
            + retrieve_docs(f"{instruction}  ({target})", config)
            + f"\n\nTASK (serve the GOAL): {instruction}\nTarget file: {target}.\n"
            + "Rules: least code; make SMALL targeted edits, do NOT rewrite files that already pass. If you "
            "rename or add ANY symbol, update ALL call sites INCLUDING tests - search the repo for the old "
            "name first so nothing is left stale. Keep the test command passing."
            + _plugin_rules("BUILD_RULES")
        )
    if _ix:
        _ix.set_phase("build")
    if config.spec_mode:
        core_dir_rel = getattr(gate_plugin, "CORE_DIR", "") if gate_plugin else ""
        ext_list = (getattr(gate_plugin, "FILE_EXTS", ()) or ("",))[0] if gate_plugin else ""
        core_path_fn = lambda name_stem: os.path.join(core_dir_rel, f"{name_stem}{ext_list}")
        built_files = [
            core_path_fn(spec_item)
            for spec_item in config.spec_order
            if core_dir_rel
            and core_path_fn(spec_item) != target
            and os.path.isfile(os.path.join(config.proj, core_path_fn(spec_item)))
        ]
        focus_files = [target] + built_files
    else:
        focus_files = [target] + _src_context(config)
    return _cecli_run(msg_text, focus_files, config, label="build")


def cecli_fix(files: dict, last_error: str, answer: str, blueprint: str, config: SprintConfig) -> dict:
    """Apply minimal change to satisfy failing gate via CECLI."""
    guidance_hint = f"\n\nA SUPERVISOR PROVIDED THIS GUIDANCE - follow it:\n{answer}\n" if answer else ""
    named_files = sorted(set(re.findall(r"([\w./\-]+\.(?:js|mjs|html|css|json))", last_error)))
    msg_text = (
        config.goal
        + config.arch
        + "\n\nAPPROVED BLUEPRINT (preserve it):\n"
        + blueprint
        + f"\n\nThe project FAILS its test command:\n{last_error}{guidance_hint}\n\n"
        "Make the SMALLEST change so the test command passes. Conform to the architecture; do NOT "
        "refactor files that already work; if a test references a renamed/removed symbol, reconcile it."
    )
    if _ix:
        _ix.set_phase("fix")
    return _cecli_run(msg_text, named_files + _src_context(config), config, label="fix")


def agent_call(system: str, user: str, max_new: int, temp: float, config: SprintConfig) -> str:
    """Dispatch one role turn to Hermes agent or served model."""
    if config.agent_backend == "swarm":
        from prismpath.orchestration import hermes_swarm

        role_name = _ROLE_OF.get(system, "coder")
        return hermes_swarm.dispatch(role_name, user)
    return chat(system, user, max_new, temp, config)


def chat(system: str, user: str, max_new: int, temp: float, config: SprintConfig) -> str:
    """Call the served model with retry."""
    last_error = None
    start_time = time.time()
    for attempt in range(4):
        try:
            resp = requests.post(
                config.llm_base.rstrip("/") + "/chat/completions",
                json={
                    "model": config.llm_model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "max_tokens": int(max_new),
                    "temperature": temp,
                    "stream": False,
                    "chat_template_kwargs": {"enable_thinking": config.enable_thinking},
                },
                timeout=600,
            )
            resp.raise_for_status()
            out_content = (resp.json()["choices"][0].get("message") or {}).get("content", "") or ""
            if _ix:
                _ix.record(
                    "served",
                    _ROLE_OF.get(system, "?"),
                    user,
                    out_content,
                    dur_ms=int((time.time() - start_time) * 1000),
                )
            return out_content
        except Exception as exc:
            last_error = exc
            log(f"    [chat] attempt {attempt + 1}/4 failed: {str(exc)[:120]}", config)
            time.sleep(5 * (attempt + 1))
    raise last_error


def parse_files(text: str) -> dict:
    """Parse FILE: blocks from agent output."""
    out_dict = {}
    for match in FILE_RE.finditer(text):
        file_path = match.group(1).strip().lstrip("./")
        if file_path and ".." not in file_path:
            out_dict[file_path] = match.group(2).rstrip("\n") + "\n"
    return out_dict


def parse_deletes(text: str) -> list:
    """Parse DELETE: targets from agent output."""
    return [
        delete_target.strip().lstrip("./")
        for delete_target in DELETE_RE.findall(text)
        if delete_target.strip() and ".." not in delete_target
    ]


def _is_spec(path: str, gate_plugin=None) -> bool:
    """Check if path matches gate plugin spec suffixes."""
    suffixes = tuple(getattr(gate_plugin, "SPEC_SUFFIXES", ()) if gate_plugin else ())
    return bool(suffixes) and path.endswith(suffixes)


def _is_core(path: str, gate_plugin=None) -> bool:
    """Check if path is a pure-core/port module."""
    dirs = tuple(getattr(gate_plugin, "TESTABLE_DIRS", ()) if gate_plugin else ())
    exts = tuple(getattr(gate_plugin, "FILE_EXTS", ()) if gate_plugin else ())
    return bool(dirs) and path.startswith(dirs) and path.endswith(exts) and not _is_spec(path, gate_plugin)


def apply_deletes(files: dict, dels: list, proj: str) -> list:
    """Remove deleted files from map and disk."""
    done_list = []
    for target_file in dels:
        files.pop(target_file, None)
        abs_path = os.path.join(proj, target_file)
        try:
            if os.path.isfile(abs_path):
                os.remove(abs_path)
                done_list.append(target_file)
        except OSError:
            pass
    return done_list


def write_project(files: dict, config: SprintConfig):
    """Write files map to project directory."""
    os.makedirs(config.proj, exist_ok=True)
    if config.gate == "browser":
        with open(os.path.join(config.proj, "package.json"), "w", encoding="utf-8") as file_handle:
            file_handle.write('{"type":"module"}\n')
    for relative_path, file_content in files.items():
        abs_path = os.path.join(config.proj, relative_path)
        os.makedirs(os.path.dirname(abs_path) or config.proj, exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as file_handle:
            file_handle.write(file_content)


def manifest(files: dict) -> str:
    """Format manifest summary of project files."""
    summary_lines = []
    for file_path in sorted(files):
        first_line = next(
            (
                line.strip(" /*#<!-")
                for line in files[file_path].splitlines()
                if line.strip() and not line.strip().startswith("import")
            ),
            "",
        )
        summary_lines.append(f"  - {file_path} ({token_est(files[file_path])} tok): {first_line[:70]}")
    return "\n".join(summary_lines)


def load_project(config: SprintConfig) -> dict:
    """Load existing source files from project directory into memory map."""
    files_map = {}
    src_extensions = config.src_ext
    for file_path in glob.glob(os.path.join(config.proj, "**", "*"), recursive=True):
        if not os.path.isfile(file_path) or "/node_modules/" in file_path:
            continue
        relative_path = os.path.relpath(file_path, config.proj)
        if relative_path in _NON_SRC or not relative_path.endswith(src_extensions):
            continue
        try:
            files_map[relative_path] = open(file_path, encoding="utf-8").read()
        except Exception:
            pass
    return files_map


def snapshot_green(files: dict, config: SprintConfig):
    """Checkpoint valid build to last-good directory."""
    if os.path.isdir(config.lastgood):
        shutil.rmtree(config.lastgood, ignore_errors=True)
    for relative_path, file_content in files.items():
        abs_path = os.path.join(config.lastgood, relative_path)
        os.makedirs(os.path.dirname(abs_path) or config.lastgood, exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as file_handle:
            file_handle.write(file_content)


def restore_green(config: SprintConfig) -> dict:
    """Revert current source files to last-good snapshot."""
    src_extensions = config.src_ext
    for file_path in glob.glob(os.path.join(config.proj, "**", "*"), recursive=True):
        if os.path.isfile(file_path):
            relative_path = os.path.relpath(file_path, config.proj)
            if relative_path not in _NON_SRC and relative_path.endswith(src_extensions):
                os.remove(file_path)
    files_map = {}
    for file_path in glob.glob(os.path.join(config.lastgood, "**", "*"), recursive=True):
        if os.path.isfile(file_path):
            relative_path = os.path.relpath(file_path, config.lastgood)
            files_map[relative_path] = open(file_path, encoding="utf-8").read()
    return files_map


def err_signature(errs: list) -> str:
    """Compute sha1 signature of error list."""
    normalized = " ".join(sorted(re.sub(r"\d+", "#", err_entry) for err_entry in errs))[:600]
    return hashlib.sha1(normalized.encode()).hexdigest()[:12]


def help_escalate(help_id: int, kind: str, phase: str, problem: str, file_list: list, config: SprintConfig):
    """Append escalation block to HELP.md file."""
    block_content = (
        f"\n- [ ] **HELP {help_id}** - {time.strftime('%H:%M:%S')} - {kind} - "
        f"files: {', '.join(file_list) or '(n/a)'}\n"
        f"  - **Problem:** {problem.strip()[:1400]}\n"
        f"  - **Answer:** _supervisor: replace this with guidance, then tick the box above_\n"
    )
    with open(config.help_file, "a", encoding="utf-8") as file_handle:
        file_handle.write(block_content)
    log(f"    [HELP {help_id}] escalated ({kind}): {problem.strip()[:90]}", config)


def help_check_answer(help_id: int, config: SprintConfig):
    """Check if supervisor answered guidance in HELP.md."""
    if not os.path.isfile(config.help_file):
        return None
    content_text = open(config.help_file, encoding="utf-8").read()
    match_obj = re.search(
        rf"^- \[(?P<box>[ xX])\] \*\*HELP {help_id}\*\*.*?"
        rf"(?:\n\s*-\s*\*\*Answer:\*\*\s*(?P<ans>.*?))?(?=\n- \[|\Z)",
        content_text,
        re.DOTALL | re.MULTILINE,
    )
    if not match_obj or match_obj.group("box").strip().lower() != "x":
        return None
    ans_text = (match_obj.group("ans") or "").strip()
    return None if (not ans_text or ans_text.startswith("_")) else ans_text


def help_resolve(help_id: int):
    """Mark help item resolved."""
    return


def status(config: SprintConfig, **kw):
    """Write current sprint status JSON."""
    kw["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        json.dump(kw, open(config.status_file, "w", encoding="utf-8"), indent=2)
    except Exception:
        pass


def plan(config: SprintConfig, files: dict | None = None) -> str:
    """ARCHITECT: design-only. Produces and persists BLUEPRINT.md."""
    context = config.goal + config.arch
    if files:
        context += f"\n\nExisting files (re-plan around them):\n{manifest(files)}"
    blueprint_text = agent_call(
        ARCHITECT_SYS,
        context + "\n\nProduce the blueprint now. Design only - no code, no FILE: blocks.",
        2500,
        0.4,
        config,
    )
    try:
        open(config.blueprint_file, "w", encoding="utf-8").write(blueprint_text)
    except Exception:
        pass
    file_count = blueprint_text.count("\n- ")
    log(f"    [architect] blueprint: ~{file_count} files, {token_est(blueprint_text)} tok", config)
    return blueprint_text


def _coder_write(resp: str, files: dict, config: SprintConfig) -> dict:
    """Apply a CODER/FIXER response: write impl files, process deletes."""
    got_files = {path_key: content_val for path_key, content_val in parse_files(resp).items() if not _is_spec(path_key, config.gate_plugin)}
    files.update(got_files)
    deletes_done = apply_deletes(files, parse_deletes(resp), config.proj)
    write_project(files, config)
    if deletes_done:
        log(f"    [delete] {', '.join(deletes_done)}", config)
    return got_files


def ideate(blueprint: str, config: SprintConfig):
    """CODER: implement architect's blueprint into initial minimal project."""
    user_prompt = (
        config.goal
        + config.arch
        + "\n\nAPPROVED BLUEPRINT (implement EXACTLY this):\n"
        + blueprint
        + "\n\nImplement the INITIAL minimal project NOW - the smallest thing that runs per the "
        "blueprint. Keep every file small. Emit files in FILE: format (specs are handled separately)."
    )
    resp = agent_call(BUILDER_SYS, user_prompt, config.max_new, 0.6, config)
    got_files = _coder_write(resp, {}, config)
    help_match = HELP_RE.search(resp)
    log(
        f"    [ideate] {len(got_files)} files: {', '.join(sorted(got_files))}"
        + (f"  HELP:{help_match.group(1)[:60]}" if help_match else ""),
        config,
    )
    return got_files, (help_match.group(1).strip() if help_match else None)


def build_step(files: dict, instruction: str, target: str, blueprint: str, config: SprintConfig):
    """CODER: implement ONE critic-chosen improvement."""
    current_content = files.get(target, "(this file does not exist yet - create it)")
    user_prompt = (
        config.goal
        + config.arch
        + "\n\nAPPROVED BLUEPRINT (conform to it):\n"
        + blueprint
        + config.lessons_block
        + retrieve_docs(f"{instruction}  ({target})", config)
        + f"\n\nProject files:\n{manifest(files)}\n\nFull content of {target}:\n```\n{current_content[:60000]}"
        f"\n```\n\nTask (must serve the GOAL above): {instruction}\nRespect the architecture and the "
        f"blueprint (least code; a feature is a plugin/adapter; keep the core pure). Emit the COMPLETE "
        f"updated/new file(s) in FILE: format; `DELETE: <path>` to remove one. Do NOT write tests."
    )
    resp = agent_call(BUILDER_SYS, user_prompt, config.max_new, 0.5, config)
    got_files = _coder_write(resp, files, config)
    help_match = HELP_RE.search(resp)
    log(f"    [build] {instruction[:55]} -> {', '.join(sorted(got_files)) or '(none!)'}", config)
    return got_files, (help_match.group(1).strip() if help_match else None)


def fix(files: dict, last_error: str, answer: str, blueprint: str, config: SprintConfig):
    """FIXER: smallest change to satisfy gate."""
    named_files = sorted(set(re.findall(r"([\w./\-]+\.(?:js|mjs|html|css|json))", last_error)))
    file_bodies = "\n\n".join(f"--- {path_item} ---\n{files.get(path_item, '(missing)')[:60000]}" for path_item in named_files[:12])
    guidance_hint = f"\n\nA SUPERVISOR PROVIDED THIS GUIDANCE - follow it:\n{answer}\n" if answer else ""
    user_prompt = (
        config.goal
        + config.arch
        + "\n\nAPPROVED BLUEPRINT (preserve it):\n"
        + blueprint
        + f"\n\nProject files:\n{manifest(files)}\n\nThe project FAILED validation:\n{last_error}"
        f"{guidance_hint}\n\nMake the SMALLEST change so it passes (align contracts; respect the architecture). "
        f"Relevant files:\n{file_bodies}\n\nEmit the COMPLETE corrected file(s) in FILE: format; "
        f"`DELETE: <path>` to remove a duplicate/orphan. Do NOT edit test specs; do NOT add features."
    )
    resp = agent_call(FIXER_SYS, user_prompt, config.max_new, 0.3, config)
    got_files = _coder_write(resp, files, config)
    help_match = HELP_RE.search(resp)
    log(f"    [fix] {last_error[:50]}... -> {', '.join(sorted(got_files)) or '(none!)'}", config)
    return got_files, (help_match.group(1).strip() if help_match else None)


def refactor(files: dict, ofile: str, config: SprintConfig):
    """CODER: split an oversized file along an architecture seam."""
    current_content = files.get(ofile, "")
    user_prompt = (
        config.arch
        + "\n\nAPPROVED BLUEPRINT:\n(see manifest)\n\n"
        f"The file `{ofile}` (~{token_est(current_content)} tok) exceeds the budget. PAUSE features and split it "
        f"along an architecture seam (extract a core sub-module, a port, or an adapter), preserving "
        f"behavior and updating imports. Emit ALL affected files in FILE: format; `DELETE: <path>` if "
        f"a file is wholly replaced.\n\nOther files:\n{manifest(files)}\n\nFull content of {ofile}:\n"
        f"```\n{current_content}\n```"
    )
    resp = agent_call(BUILDER_SYS, user_prompt, config.max_new, 0.4, config)
    got_files = _coder_write(resp, files, config)
    log(f"    [refactor] split {ofile} -> {', '.join(sorted(got_files))}", config)


def test_author(files: dict, blueprint: str, config: SprintConfig, repair_error: str = ""):
    """TEST-AUTHOR: write/maintain headless specs for pure core."""
    if not config.has_spec_layer:
        return
    core_files = {path_key: content_val for path_key, content_val in files.items() if _is_core(path_key, config.gate_plugin)}
    if not core_files:
        return
    core_bodies = "\n\n".join(f"--- {path_item} ---\n{content_str[:60000]}" for path_item, content_str in sorted(core_files.items()))
    spec_bodies = "\n\n".join(
        f"--- {path_item} ---\n{content_str[:20000]}"
        for path_item, content_str in sorted(files.items())
        if _is_spec(path_item, config.gate_plugin)
    )
    repair_prompt = f"\n\nA spec is FAILING TO LOAD - fix the SPEC (not the code):\n{repair_error}\n" if repair_error else ""
    user_prompt = (
        config.goal
        + config.arch
        + "\n\nAPPROVED BLUEPRINT:\n"
        + blueprint
        + f"\n\nPURE CORE modules to test (test their CONTRACT, adversarially):\n{core_bodies}"
        + (f"\n\nExisting specs:\n{spec_bodies}" if spec_bodies else "")
        + repair_prompt
        + "\n\nWrite or update the headless specs now. Emit ONLY spec files in FILE: format."
    )
    resp = agent_call(TESTER_SYS, user_prompt, config.max_new, 0.4, config)
    got_specs = {path_key: content_val for path_key, content_val in parse_files(resp).items() if _is_spec(path_key, config.gate_plugin)}
    files.update(got_specs)
    write_project(files, config)
    log(f"    [test-author] specs: {', '.join(sorted(got_specs)) or '(none!)'}", config)
    return got_specs


def review(files: dict, blueprint: str, config: SprintConfig) -> dict:
    """CRITIC: review quality + architecture + blueprint adherence."""
    key_files = {
        path_item: content_str
        for path_item, content_str in files.items()
        if path_item in ("index.html", "main.js") or path_item.startswith(("core/", "src/"))
    }
    key_bodies = "\n\n".join(f"--- {path_item} ---\n{content_str[:12000]}" for path_item, content_str in sorted(key_files.items()))
    critique_text = agent_call(
        CRITIC_SYS,
        config.goal
        + config.arch
        + "\n\nAPPROVED BLUEPRINT:\n"
        + blueprint
        + f"\n\nProject files:\n{manifest(files)}\n\nKey files:\n{key_bodies}\n\n"
        "Critique BRIEFLY against the GOAL and the BLUEPRINT (product quality AND architecture/"
        "lazy-dev adherence; flag duplication or drift from the manifest). Every improvement must "
        "move toward the GOAL - do NOT propose features for a different kind of app. If the app "
        "genuinely fulfills the GOAL at high quality with NO worthwhile improvement left, reply with "
        "exactly `DONE` on its own line. Otherwise choose the single highest-value next improvement "
        "and end with EXACTLY two lines - a BITE-SIZED task with an EXACT file path, no placeholders:\n"
        "TARGET: <relative path of the file to create or edit next>\n"
        "NEXT: <one concrete, specific improvement achievable in one iteration>",
        1200,
        0.4,
        config,
    )
    if re.search(r"^\s*DONE\s*$", critique_text, re.MULTILINE):
        log("    [review] critic says DONE", config)
        return {"done": True, "raw": critique_text[:300]}
    target_match = re.search(r"TARGET:\s*([^\n`]+)", critique_text)
    next_match = re.search(r"NEXT:\s*(.+)", critique_text)
    next_dict = {
        "done": False,
        "target": (target_match.group(1).strip().lstrip("./") if target_match else "main.js"),
        "instruction": (next_match.group(1).strip() if next_match else critique_text.strip())[:300],
        "raw": critique_text[:300],
    }
    log(f"    [review] TARGET={next_dict['target']} NEXT={next_dict['instruction'][:70]}", config)
    return next_dict


def audit_consistency(target: str, config: SprintConfig) -> None:
    """qwen CONSISTENCY AUDITOR (opt-in config.audit): check just-built target against GLOSSARY."""
    if not (config.audit and config.agent_backend == "swarm" and os.path.isfile(config.glossary_file)):
        return
    try:
        src_text = open(os.path.join(config.proj, target), encoding="utf-8").read()
        glossary_text = open(config.glossary_file, encoding="utf-8").read()
    except OSError:
        return
    if not src_text.strip():
        return
    prompt_text = (
        f"GLOSSARY - the canonical contract (single source of truth):\n{glossary_text}\n\n"
        f"--- FULL CONTENTS of {target} (this is everything; there is nothing to fetch) ---\n{src_text}\n"
        f"--- end of {target} ---\n\n"
        "Audit the file above against the GLOSSARY now. You have no tools - do NOT emit JSON or any tool "
        "call. Output ONLY DRIFT/DUP lines, or exactly AUDIT-CLEAN."
    )
    try:
        from prismpath.orchestration import hermes_swarm

        audit_output = hermes_swarm.dispatch("auditor", prompt_text, timeout=180)
    except Exception as exc:
        log(f"    [audit] skipped ({str(exc)[:70]})", config)
        return

    def _real(line_text: str) -> bool:
        if line_text.startswith("DUP"):
            return True
        if "->" in line_text:
            drift_from = line_text.split("->", 1)[0].split(":", 1)[-1].strip()
            drift_to = line_text.split("->", 1)[1].strip()
            return bool(drift_from) and bool(drift_to) and drift_from != drift_to
        return False

    seen_set: set = set()
    flags_list = []
    for raw_line in (audit_output or "").splitlines():
        line_item = raw_line.strip()
        if line_item.startswith(("DRIFT", "DUP")) and _real(line_item) and line_item not in seen_set:
            seen_set.add(line_item)
            flags_list.append(line_item)
    if flags_list:
        log(f"    [audit/qwen] {len(flags_list)} drift flag(s) on {target}:", config)
        for flag_item in flags_list[:12]:
            log(f"        {flag_item}", config)
    else:
        log(f"    [audit/qwen] clean: {target}", config)


def antigravity_unblock(errors: str, named_files: list, config: SprintConfig) -> bool:
    """Frontier auto-unblocker: hand STUCK gate failure to agy."""
    if not os.path.isfile(config.agy_bin):
        log(f"    [agy] binary not found at {config.agy_bin}; falling back to human escalation", config)
        return False
    guidance_hint = ""
    glossary_path = os.path.join(config.proj, "specs", "GLOSSARY.md")
    if os.path.isfile(glossary_path):
        guidance_hint = (
            " The canonical type contract is specs/GLOSSARY.md (+ the per-module specs in specs/) - "
            "conform to it exactly and do NOT change any public interface."
        )
    task_text = (
        "You are an automated build unblocker for this project (its directory is in your "
        "workspace). A DETERMINISTIC build gate is STUCK - the local swarm failed to fix the SAME error three "
        "times. Make the SMALLEST change that resolves it: do NOT refactor working code, rename public "
        f"symbols, or add features.{guidance_hint}\n\nThe stuck gate errors:\n{errors}\n\n"
        f"Files implicated: {', '.join(named_files) or '(infer from the errors above)'}.\n"
        "Edit the file(s) to fix it, then stop - the build system re-runs the gate to verify your fix."
    )
    cmd_args = [config.agy_bin, "--add-dir", config.proj, "--dangerously-skip-permissions"]
    if config.agy_sandbox:
        cmd_args.append("--sandbox")
    if config.agy_model:
        cmd_args += ["--model", config.agy_model]
    cmd_args += ["--print", task_text]
    log(f"    [agy] frontier unblocker dispatching (model={config.agy_model}, sandbox={config.agy_sandbox})", config)
    start_time = time.time()
    try:
        run_env = dict(os.environ, PATH=os.path.dirname(config.agy_bin) + ":" + os.environ.get("PATH", ""))
        proc_res = subprocess.run(cmd_args, cwd=config.proj, capture_output=True, text=True, timeout=config.agy_timeout, env=run_env)
    except subprocess.TimeoutExpired:
        log(f"    [agy] timed out after {config.agy_timeout}s", config)
        return False
    except Exception as exc:
        log(f"    [agy] failed to launch: {str(exc)[:120]}", config)
        return False
    duration_s = int(time.time() - start_time)
    output_str = proc_res.stdout or ""
    log(f"    [agy] done rc={proc_res.returncode} dur={duration_s}s; tail: {output_str[-180:].strip()}", config)
    if _ix is not None:
        _ix.record("antigravity", "unblocker", task_text, output_str or (proc_res.stderr or ""), dur_ms=duration_s * 1000, rc=proc_res.returncode)
    return proc_res.returncode == 0


def spec_next(files: dict, config: SprintConfig) -> dict:
    """Spec-driven next-step: build each module in spec_order to green."""
    for module_name in config.spec_order:
        target_file = f"core/{module_name}.js"
        if target_file not in files:
            def _spec_read(rel_path: str) -> str:
                try:
                    return open(os.path.join(config.proj, config.spec_dir, rel_path), encoding="utf-8").read()
                except OSError:
                    return ""
            spec_txt = _spec_read(f"{module_name}.md")
            gloss_txt = _spec_read("GLOSSARY.md")
            instruction_text = (
                f"Implement {target_file} EXACTLY per the MODULE SPEC and the canonical GLOSSARY embedded below - "
                f"they ARE the contract. Conform every shared type name, field, and signature to the GLOSSARY. "
                f"Create ONLY {target_file} as a pure --!strict core.\n\n"
                f"===== MODULE SPEC ({config.spec_dir}/{module_name}.md) =====\n{spec_txt}\n\n"
                f"===== CANONICAL GLOSSARY ({config.spec_dir}/GLOSSARY.md) =====\n{gloss_txt}\n"
                f"===== END CONTRACT ====="
            )
            return {"done": False, "target": target_file, "instruction": instruction_text, "raw": f"spec:{module_name}"}
    return {"done": True, "target": "", "instruction": ""}


def _abs(path_str: str, proj_dir: str) -> str:
    """Resolve path relative to project directory if not absolute."""
    return path_str if os.path.isabs(path_str) else os.path.join(proj_dir, path_str)


def _kg_save(kg_data: dict, config: SprintConfig):
    """Atomically save knowledge graph JSON."""
    kg_abs_path = _abs(config.kg_path, config.proj)
    canon.atomic_write(kg_abs_path, json.dumps(kg_data, indent=2))


def _kg_load(config: SprintConfig) -> dict:
    """Load or instantiate knowledge graph JSON."""
    kg_abs_path = _abs(config.kg_path, config.proj)
    if os.path.isfile(kg_abs_path):
        try:
            return json.load(open(kg_abs_path, encoding="utf-8"))
        except (OSError, ValueError):
            pass
    spec_text = open(_abs(config.spec_file, config.proj), encoding="utf-8").read()
    match_obj = re.search(r"```json\s*(.*?)```", spec_text, re.S)
    kg_data = json.loads(match_obj.group(1).strip()) if match_obj else {"nodes": []}
    _kg_save(kg_data, config)
    log(f"    [kg] instantiated {config.kg_path}: {len(kg_data.get('nodes', []))} nodes", config)
    return kg_data


def kg_mark_done(node_id: str, config: SprintConfig):
    """Mark specified node done in knowledge graph."""
    kg_data = _kg_load(config)
    for node_entry in kg_data.get("nodes", []):
        if node_entry.get("id") == node_id:
            node_entry["status"] = "done"
    _kg_save(kg_data, config)


def _ledger(config: SprintConfig):
    """Create Ledger instance using sprint configuration."""
    from prismpath.ledgers import ledger as ledger_module

    run_id = config.ledger_run_id or ledger_module.new_run_id()
    state_directory = config.ledger_dir or None
    flow_name = os.path.basename(config.proj.rstrip("/")) or "sprint"
    return ledger_module.Ledger(flow=flow_name, run_id=run_id, state_dir=state_directory)


def _apply_ledger_done(kg_data: dict, done_units: set) -> int:
    """Mark KG nodes done for every unit proven in ledger."""
    newly_marked_count = 0
    for node_entry in kg_data.get("nodes", []):
        if node_entry.get("id") in done_units and node_entry.get("status") != "done":
            node_entry["status"] = "done"
            newly_marked_count += 1
    return newly_marked_count


def _kg_seed_from_ledger(config: SprintConfig):
    """Resume-from-git: mark KG nodes done from ledger proofs."""
    if not config.ledger:
        return
    try:
        done_units = set(_ledger(config).done_set())
        if not done_units:
            return
        kg_data = _kg_load(config)
        seeded_count = _apply_ledger_done(kg_data, done_units)
        if seeded_count:
            _kg_save(kg_data, config)
            ledger_instance = _ledger(config)
            log(f"    [ledger] resumed {seeded_count} node(s) from {ledger_instance.ref}", config)
    except Exception as exc:
        log(f"    [ledger] resume-seed skipped ({str(exc)[:100]})", config)


def _ledger_commit(unit: str, files: dict, config: SprintConfig, edge: str = None):
    """Record gate-green unit as git proof-commit."""
    try:
        from prismpath.ledgers import ledger as ledger_module

        ledger_instance = _ledger(config)
        kg_nodes = _kg_load(config).get("nodes", []) if config.kg_mode else []
        node_info = next((node_item for node_item in kg_nodes if node_item.get("id") == unit), {})
        produces_list = node_info.get("produces", [])
        out_files = {path_name: files[path_name] for path_name in produces_list if path_name in files}
        ledger_instance.commit_unit(
            unit,
            node=unit,
            gate="green",
            gate_name=config.gate,
            files=files,
            output_hash=ledger_module.sha256_files(out_files) if out_files else None,
            depends=node_info.get("depends_on") or None,
            edge=edge,
        )
        log(f"    [ledger] {unit} -> proof-commit ({ledger_instance.ref})", config)
    except Exception as exc:
        log(f"    [ledger] skipped ({str(exc)[:100]})", config)


def kg_next(files: dict, config: SprintConfig) -> dict:
    """Deterministic next-step selection from knowledge graph."""
    kg_data = _kg_load(config)
    nodes_list = kg_data.get("nodes", [])
    done_set = {node["id"] for node in nodes_list if node.get("status") == "done"}
    spec_text = open(_abs(config.spec_file, config.proj), encoding="utf-8").read()
    sections_list = re.split(r"\n(?=## )", spec_text)
    specs_dir = os.path.dirname(_abs(config.spec_file, config.proj))
    glossary_text = ""
    glossary_path = os.path.join(specs_dir, "GLOSSARY.md")
    if os.path.isfile(glossary_path):
        glossary_text = open(glossary_path, encoding="utf-8").read()
    for node_entry in nodes_list:
        if node_entry.get("status") == "done":
            continue
        if not all(dep_id in done_set for dep_id in node_entry.get("depends_on", [])):
            continue
        section_key = (node_entry.get("section") or node_entry.get("id") or "").lower()
        matching_section = next(
            (
                section_item.strip()
                for section_item in sections_list
                if section_item.strip().lower().startswith("## ")
                and section_key
                and section_key in section_item.splitlines()[0].lower()
            ),
            "",
        )
        ref_text = ""
        for ref_name in sorted(set(re.findall(r"specs/(\w+)\.md", matching_section))):
            ref_path = os.path.join(specs_dir, ref_name + ".md")
            if ref_name != "GLOSSARY" and os.path.isfile(ref_path):
                ref_text += f"\n\n===== specs/{ref_name}.md =====\n" + open(ref_path, encoding="utf-8").read()
        produces_files = node_entry.get("produces", [])
        target_file = next(
            (path_item for path_item in produces_files if path_item.endswith((".js", ".mjs"))),
            produces_files[0] if produces_files else "",
        )
        done_summary = "; ".join(
            f"{unit_id} -> {','.join(next((node_item.get('produces', []) for node_item in nodes_list if node_item['id'] == unit_id), []))}"
            for unit_id in done_set
        ) or "(nothing yet)"
        instruction_text = (
            f"Build integration REQUIREMENT '{node_entry['id']}' to its Definition of done. Implement ONLY this "
            f"requirement (the other steps are built separately); COMPOSE the already-built modules, never "
            f"rebuild them.\n\n===== REQUIREMENT (from INTEGRATION.md) =====\n{matching_section}\n\n"
            f"===== CANONICAL GLOSSARY =====\n{glossary_text}{ref_text}\n\n"
            f"ALREADY BUILT (compose these, do not rebuild): {done_summary}\n"
            f"Conform every shared identifier to the GLOSSARY EXACTLY."
        )
        return {
            "done": False,
            "target": target_file,
            "instruction": instruction_text,
            "raw": f"kg:{node_entry['id']}",
            "_kg_node": node_entry["id"],
        }
    return {"done": True, "target": "", "instruction": ""}


def _spec_load_error(errs: list) -> bool:
    """Check if gate failure is due to spec loading error."""
    err_blob = " ".join(errs).lower()
    return (
        "lune test failed" in err_blob
        and ("could not resolve" in err_blob or "error requiring module" in err_blob or "cannot find" in err_blob)
    )


def _register_sprint(config: SprintConfig):
    """Announce project directory to Mission Control registry."""
    try:
        registry_path = os.path.expanduser(config.mc_registry)
        os.makedirs(os.path.dirname(registry_path), exist_ok=True)
        try:
            registry_data = json.load(open(registry_path, encoding="utf-8"))
            registry_data = registry_data if isinstance(registry_data, dict) else {}
        except Exception:
            registry_data = {}
        registry_data[os.path.abspath(config.proj)] = {"gate": config.gate, "started": int(time.time())}
        registry_data = {key_path: value_data for key_path, value_data in registry_data.items() if os.path.isdir(key_path)}
        json.dump(registry_data, open(registry_path, "w", encoding="utf-8"), indent=2)
    except Exception:
        pass


def _start_heartbeat(config: SprintConfig):
    """Keep status.json mtime fresh while long builds block the loop."""
    import threading

    status_file_path = config.status_file

    def _beat():
        while not os.path.exists(config.stop_file):
            try:
                if os.path.exists(status_file_path):
                    os.utime(status_file_path, None)
            except OSError:
                pass
            time.sleep(30)

    threading.Thread(target=_beat, daemon=True).start()


def _flow_loop(files: dict, blueprint: str, config: SprintConfig) -> str:
    """Drive sprint loop through flows/sprint_loop.md when flow_mode is set."""
    from prismpath.orchestration.sprint_flow import GateRed, SprintSeams, run_sprint_flow

    state_container = {"files": files, "nxt": None}

    def pick(loop_state):
        state_container["files"] = load_project(config) or state_container["files"]
        done_units = loop_state.get("_done_units") or set()
        if config.kg_mode:
            next_action = kg_next(state_container["files"], config)
        elif config.spec_mode:
            next_action = spec_next(state_container["files"], config)
        else:
            next_action = review(state_container["files"], blueprint, config)
        if next_action.get("done"):
            return {"text": "sprint complete", "done": True}
        unit_id = str(next_action.get("_kg_node") or next_action.get("target") or f"step-{len(done_units) + 1}")
        if unit_id in done_units:
            return {"text": f"{unit_id} already proven", "done": True}
        loop_state["unit"] = {"id": unit_id}
        state_container["nxt"] = next_action
        return {
            "text": f"next: {unit_id}",
            "done": False,
            "instruction": next_action.get("instruction", ""),
            "target": next_action.get("target", ""),
        }

    def flow_build(loop_state):
        next_action = state_container["nxt"] or {}
        if config.exec_mode == "cecli":
            state_container["files"] = cecli_build(
                state_container["files"],
                next_action.get("instruction", ""),
                next_action.get("target", ""),
                blueprint,
                config,
            )
        else:
            got_files, build_help = build_step(
                state_container["files"],
                next_action.get("instruction", ""),
                next_action.get("target", ""),
                blueprint,
                config,
            )
            if config.has_spec_layer and any(_is_core(path_item, config.gate_plugin) for path_item in got_files):
                test_author(state_container["files"], blueprint, config)
        return {"text": f"built {next_action.get('target', '')}"}

    def gate(loop_state):
        gate_result = config.validate_fn(config.proj)
        if not gate_result["valid"]:
            raise GateRed("; ".join(gate_result["errs"])[:1400])
        snapshot_green(state_container["files"], config)
        if config.kg_mode and loop_state.get("unit"):
            kg_mark_done(loop_state["unit"]["id"], config)
        loop_state["gate_report"] = f"gate={config.gate} valid; files={len(state_container['files'])}"
        return {"text": "gate green", "gate_green": True}

    def fix(loop_state):
        last_err = next(
            (transcript_entry["outcome"] for transcript_entry in reversed(loop_state.get("transcript", [])) if transcript_entry.get("error")),
            "",
        )
        if config.exec_mode == "cecli":
            state_container["files"] = cecli_fix(state_container["files"], last_err, "", blueprint, config)
        else:
            build_step(
                state_container["files"],
                f"Fix the gate failure: {last_err}",
                (state_container["nxt"] or {}).get("target", ""),
                blueprint,
                config,
            )
        return {"text": "fix applied"}

    def escalate(loop_state):
        unit_id = (loop_state.get("unit") or {}).get("id", "?")
        last_err = next(
            (transcript_entry["outcome"] for transcript_entry in reversed(loop_state.get("transcript", [])) if transcript_entry.get("error")),
            "",
        )
        help_escalate(
            int(time.time()) % 100000,
            "auto-detected",
            f"flow-gate:{unit_id}",
            last_err,
            [(state_container["nxt"] or {}).get("target", "")],
            config,
        )
        return {"text": f"HELP written for {unit_id}"}

    seams = SprintSeams(pick=pick, build=flow_build, gate=gate, fix=fix, escalate=escalate)
    ledger_instance = _ledger(config) if config.ledger else None
    committed = run_sprint_flow(seams, ledger=ledger_instance)
    return f"flow loop done - {len(committed)} unit(s) proven this pass"


def run(config: SprintConfig):
    """Execute a sprint loop driven by config."""
    try:
        if not requests.get(config.llm_base.rstrip("/") + "/models", timeout=5).ok:
            log("[sprint] served endpoint not reachable - aborting.", config)
            return
    except Exception as exc:
        log(f"[sprint] endpoint check failed: {exc} - aborting.", config)
        return

    os.makedirs(config.proj, exist_ok=True)
    if not config.extend:
        keep_set = {"STOP", os.path.basename(config.help_file), "status.json", "sprint.log", "BLUEPRINT.md"}
        existing_items = [item_name for item_name in os.listdir(config.proj) if not item_name.startswith(".") and item_name not in keep_set]
        if existing_items:
            log(
                f"[sprint] refusing to run greenfield in a non-empty directory: {config.proj}\n"
                f"         it holds {len(existing_items)} item(s) (e.g. {', '.join(sorted(existing_items)[:5])}).\n"
                f"         The sprint never deletes your files - empty the dir yourself, point "
                f"SPRINT_PROJ at an empty one, or pass SPRINT_EXTEND=1 to build on this tree.",
                config,
            )
            return

    open(config.help_file, "a", encoding="utf-8").close()
    budget_label = f"{config.seconds}s" if config.seconds else "open-ended (until STOP file)"
    log(f"[sprint] model={config.llm_model} gate={config.gate} budget={budget_label} proj={config.proj}", config)
    _start_heartbeat(config)
    _register_sprint(config)
    log(f"[sprint] arch={config.arch_file} | build=architect,coder,test-author,fixer | stop: touch {config.stop_file}", config)

    start_time = time.time()
    nxt = {"done": False, "target": "main.js", "instruction": "Add the most valuable next improvement."}
    last_sig = ""
    repeat_count = 0
    help_id = 0
    open_help = None
    consecutive_invalid = 0
    last_err_text = ""
    iteration_count = 0
    stopped_reason = "?"
    kg_current_node = None
    if config.kg_mode and config.ledger:
        _kg_seed_from_ledger(config)
    agy_tried_signatures: set = set()

    def agent_help(htext: str | None, phase: str, named_files: list):
        nonlocal help_id, open_help
        if htext and open_help is None:
            help_id += 1
            open_help = help_id
            help_escalate(help_id, "agent-declared", phase, htext, named_files, config)

    existing_files = load_project(config)
    if existing_files and (config.extend or any(key_name.endswith(("index.html", "default.project.json")) for key_name in existing_files)):
        files = existing_files
        blueprint = (
            open(config.blueprint_file, encoding="utf-8").read()
            if os.path.isfile(config.blueprint_file)
            else plan(config, files)
        )
        if os.path.isfile(config.help_file):
            help_id = open(config.help_file, encoding="utf-8").read().count("**HELP ")
        log(f"    [{'extend' if config.extend else 'resume'}] loaded {len(files)} existing files - skipping ideate", config)
    else:
        blueprint = plan(config)
        files, initial_help = ideate(blueprint, config)
        agent_help(initial_help, "ideate", sorted(files))
        if config.has_spec_layer:
            test_author(files, blueprint, config)

    while True:
        iteration_count += 1
        if config.flow_mode:
            stopped_reason = _flow_loop(files, blueprint, config)
            break
        if os.path.exists(config.stop_file):
            stopped_reason = "STOP file"
            break
        if config.seconds and time.time() - start_time > config.seconds:
            stopped_reason = "time budget"
            break
        if config.max_iters and iteration_count > config.max_iters:
            stopped_reason = f"iteration cap ({config.max_iters})"
            break
        while os.path.exists(config.pause_file) and not os.path.exists(config.stop_file):
            iteration_count -= 1
            time.sleep(3)
            iteration_count += 1
        try:
            gate_result = config.validate_fn(config.proj)
            elapsed_seconds = int(time.time() - start_time)
            status(
                config,
                sprint=os.path.basename(config.proj),
                gate=config.gate,
                iteration=iteration_count,
                elapsed_s=elapsed_seconds,
                valid=gate_result["valid"],
                biggest_tok=gate_result.get("biggest"),
                files=sorted(files),
                last_error=("" if gate_result["valid"] else "; ".join(gate_result["errs"])[:300]),
                help_open=open_help,
                help_count=help_id,
                done=False,
            )
            log(
                f"[it {iteration_count} | {elapsed_seconds}s] valid={gate_result['valid']}"
                + ("" if gate_result["valid"] else " :: " + "; ".join(gate_result["errs"])[:140]),
                config,
            )

            if gate_result["valid"]:
                last_sig = ""
                repeat_count = 0
                consecutive_invalid = 0
                snapshot_green(files, config)
                if config.agent_backend == "swarm" and last_err_text:
                    try:
                        from prismpath.orchestration import hermes_swarm

                        reflection = hermes_swarm.reflect("fixer", f"You just fixed this gate failure: {last_err_text}")
                        log(f"    [reflect] fixer learned: {reflection[:90]}", config)
                    except Exception as exc:
                        log(f"    [reflect] skipped: {str(exc)[:80]}", config)
                    last_err_text = ""
                if config.kg_mode:
                    if kg_current_node:
                        kg_mark_done(kg_current_node, config)
                        log(f"    [kg] {kg_current_node} -> done", config)
                        if config.ledger:
                            _ledger_commit(kg_current_node, files, config)
                        kg_current_node = None
                    next_step = kg_next(files, config)
                elif config.spec_mode:
                    next_step = spec_next(files, config)
                else:
                    next_step = review(files, blueprint, config)
                if next_step.get("done"):
                    stopped_reason = (
                        "all KG nodes done + gate green"
                        if config.kg_mode
                        else "all specs built + gate green"
                        if config.spec_mode
                        else "critic DONE + gate green"
                    )
                    break
                if config.kg_mode:
                    kg_current_node = next_step.get("_kg_node")
                nxt = next_step
                if config.exec_mode == "cecli":
                    files = cecli_build(files, next_step["instruction"], next_step["target"], blueprint, config)
                    audit_consistency(next_step["target"], config)
                else:
                    got_files, build_help = build_step(files, next_step["instruction"], next_step["target"], blueprint, config)
                    agent_help(build_help, "build", [next_step["target"]])
                    if config.has_spec_layer and any(_is_core(path_item, config.gate_plugin) for path_item in got_files):
                        test_author(files, blueprint, config)
                continue

            if gate_result.get("oversized") and config.exec_mode != "cecli":
                refactor(files, gate_result.get("oversized_file") or gate_result.get("biggest_file"), config)
                continue

            named_files = sorted(set(re.findall(r"([\w./\-]+\.(?:js|mjs|html|css|json))", "; ".join(gate_result["errs"]))))
            signature = err_signature(gate_result["errs"])
            repeat_count = repeat_count + 1 if signature == last_sig else 1
            last_sig = signature
            consecutive_invalid += 1
            if consecutive_invalid >= config.regress_limit and os.path.isdir(config.lastgood) and open_help is None:
                files = restore_green(config)
                write_project(files, config)
                help_id += 1
                open_help = help_id
                help_escalate(
                    help_id,
                    "regression-guard",
                    "validate",
                    f"Reverted to last-green after {consecutive_invalid} consecutive invalid iterations - the "
                    f"agents kept breaking the working build. Last error:\n"
                    + "; ".join(gate_result["errs"])[:900]
                    + "\n\nGuidance: make the SMALLEST change toward "
                    "the goal; do NOT refactor files that already work. If a feature truly can't be "
                    "added without breaking the core, say so via a HELP_NEEDED line.",
                    named_files,
                    config,
                )
                consecutive_invalid = 0
                last_sig = ""
                repeat_count = 0
                continue
            answer_text = None
            if open_help is not None:
                answer_text = help_check_answer(open_help, config)
                if answer_text:
                    log(f"    [HELP {open_help}] supervisor answered - injecting + resuming", config)
                    help_resolve(open_help)
                    open_help = None
                    repeat_count = 0
            if open_help is None and repeat_count >= config.stuck_repeat:
                if config.agy and signature not in agy_tried_signatures and len(agy_tried_signatures) < config.agy_max:
                    agy_tried_signatures.add(signature)
                    log(f"    [agy] auto-stuck ({repeat_count}x same error) - frontier unblocker before human escalation", config)
                    antigravity_unblock("; ".join(gate_result["errs"])[:1500], named_files, config)
                    continue
                help_id += 1
                open_help = help_id
                help_escalate(
                    help_id,
                    "auto-stuck",
                    "validate",
                    f"Gate failed {repeat_count}x with the same error"
                    + ("; the frontier unblocker (agy) also could not resolve it" if config.agy else "; agents can't self-repair")
                    + ":\n"
                    + "; ".join(gate_result["errs"])[:1200],
                    named_files,
                    config,
                )
            last_err_text = "; ".join(gate_result["errs"])[:400]
            if config.exec_mode == "cecli":
                files = cecli_fix(files, "; ".join(gate_result["errs"])[:1000], answer_text, blueprint, config)
            elif _spec_load_error(gate_result["errs"]) and config.has_spec_layer:
                test_author(files, blueprint, config, repair_error="; ".join(gate_result["errs"])[:1000])
            else:
                _got_files, fix_help = fix(files, "; ".join(gate_result["errs"])[:1000], answer_text, blueprint, config)
                agent_help(fix_help, "fix", named_files)
        except Exception as exc:
            log(f"[it {iteration_count}] iteration error (continuing): {str(exc)[:160]}", config)
            time.sleep(5)

    elapsed_seconds = int(time.time() - start_time)
    gate_result = config.validate_fn(config.proj)
    status(
        config,
        sprint=os.path.basename(config.proj),
        gate=config.gate,
        iteration=iteration_count,
        elapsed_s=elapsed_seconds,
        valid=gate_result["valid"],
        biggest_tok=gate_result.get("biggest"),
        files=sorted(files),
        last_error=("" if gate_result["valid"] else "; ".join(gate_result["errs"])[:300]),
        help_open=open_help,
        help_count=help_id,
        done=True,
        stopped_reason=stopped_reason,
    )
    log(
        f"[sprint] DONE in {elapsed_seconds}s  stopped={stopped_reason}  final valid={gate_result['valid']}  "
        f"files={sorted(files)}  helps={help_id}",
        config,
    )


def main(config: SprintConfig | None = None):
    """Main CLI entry point for run_sprint.py."""
    if config is None:
        config = SprintConfig.from_env()
    run(config)


if __name__ == "__main__":
    main()
