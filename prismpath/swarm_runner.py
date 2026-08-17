# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Wire prismpath -> the local agent swarm.

`make_swarm_agent(...)` returns an prismpath-compatible agent callable
`(node, instruction, state) -> str | {"text":..., ...fields}` whose work is performed by
the swarm. It dispatches each node's instruction (plus the relevant `state` — prior files,
last error) through the EXISTING swarm interface and does NOT rewrite the swarm core:

  backend="swarm"  -> reuse `pipeline.agent_io.run_task(...)` against the OpenAI-compatible
                      endpoint the swarm/pipeline coders talk to (Atlas :8888 / $LLM_BASE).
  backend="local"  -> reuse `prismpath.llm_local.generate(...)` (a local 7B/27B), so a run still
                      proceeds when no serving backend is up.
  backend="auto"   -> probe the swarm endpoint; use it if it answers, else fall back to local.

Whichever path is chosen, the SAME callable is returned, so the engine is unaffected. The
adapter returns STRUCTURED outcomes for nodes whose downstream edges are deterministic
(`run_tests`/`validate` -> `{"tests_pass": bool, ...}`), and plain text for semantic nodes.

The node vocabulary mirrors the SDLC flow this drives (see flows/build_prismpath.md):
  plan        : the agent lays out the work (semantic-ish, but usually `when always`).
  implement   : the agent writes/revises a file; the file + path are stashed in state and
                written to a real scratch dir so run_tests can execute it.
  run_tests   : runs pytest over the produced suite in a subprocess -> {tests_pass, ...}.
  debug       : the agent judges the failure in one line -> a SEMANTIC edge.
  document    : the agent writes a README/doc artifact.
The flow author decides the graph; this module only decides HOW a node's work gets done.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import Callable, Optional


# --------------------------------------------------------------------------------------------
# backend: a single text-generation primitive `generate(prompt, max_new_tokens) -> str`,
# backed by either the real swarm endpoint or a local model.
# --------------------------------------------------------------------------------------------

def _swarm_endpoint_up(base: Optional[str] = None, timeout: float = 4.0) -> bool:
    """Is the OpenAI-compatible endpoint the swarm/pipeline coders use reachable?"""
    import requests
    from pipeline import agent_io
    base = (base or agent_io.DEFAULT_BASE).rstrip("/")
    for path in ("/models", "/models/"):
        try:
            r = requests.get(base + path, timeout=timeout)
            if r.status_code < 500:
                return True
        except Exception:
            pass
    return False


def _swarm_generate_fn(base: Optional[str] = None, model: Optional[str] = None,
                       max_default: int = 2048) -> Callable[[str, int], str]:
    """A generate(prompt, max_new_tokens) backed by the swarm via pipeline.agent_io.run_task.

    run_task expects a task dict; we adapt a free-form prompt into the minimal shape it needs
    and return the model's text (run_task already strips fenced code, which we re-wrap so the
    caller's own extract_code still works uniformly)."""
    from pipeline import agent_io

    def generate(prompt: str, max_new_tokens: int = max_default) -> str:
        task = {"id": "prismpath", "title": "prismpath node",
                "spec": prompt, "target": "out.py",
                "role_desc": "an expert Python framework engineer",
                "max_tokens": int(max_new_tokens)}
        code, _usage = agent_io.run_task(task, docs=None, prior_files=None,
                                         base=base, model=model)
        # run_task returns only the code block; re-fence so extract_code() is path-agnostic.
        return f"```python\n{code}\n```" if code else ""

    return generate


def _local_generate_fn() -> Callable[[str, int], str]:
    from prismpath import llm_local

    def generate(prompt: str, max_new_tokens: int = 1024) -> str:
        return llm_local.generate(prompt, max_new_tokens=max_new_tokens)

    return generate


def resolve_backend(backend: str = "auto", base: Optional[str] = None,
                    model: Optional[str] = None):
    """Return (generate_fn, label). label in {'swarm','local'} for honest reporting."""
    if backend == "swarm":
        return _swarm_generate_fn(base, model), "swarm"
    if backend == "local":
        return _local_generate_fn(), "local"
    # auto: prefer the real swarm if its endpoint answers.
    if _swarm_endpoint_up(base):
        return _swarm_generate_fn(base, model), "swarm"
    return _local_generate_fn(), "local"


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------

_FENCE = re.compile(r"```(?:[a-zA-Z0-9_+\-]*)\n(.*?)```", re.DOTALL)


def extract_code(text: str) -> str:
    """Largest fenced block, else the raw text (mirrors agent_io.extract_file leniency)."""
    blocks = _FENCE.findall(text or "")
    if blocks:
        return max(blocks, key=len).strip("\n")
    return (text or "").strip()


def run_pytest(test_dir: str, target: str = "", timeout: int = 600):
    """Run pytest in `test_dir` (over `target` if given). Returns (passed, n_pass, n_fail, log).

    Runs from the repo root so `import prismpath...` resolves; isolated tmp cache."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    args = [sys.executable, "-m", "pytest", "-q", "--no-header",
            "-p", "no:cacheprovider", target or test_dir]
    env = dict(os.environ)
    env.setdefault("EMBED_DEVICE", "cpu")
    try:
        p = subprocess.run(args, cwd=repo_root, capture_output=True, text=True,
                           timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return False, 0, 0, "pytest timed out"
    log = (p.stdout + "\n" + p.stderr).strip()
    n_pass = _count(log, r"(\d+) passed")
    n_fail = _count(log, r"(\d+) failed") + _count(log, r"(\d+) error")
    passed = p.returncode == 0 and n_fail == 0
    return passed, n_pass, n_fail, log


def _count(log: str, pat: str) -> int:
    m = re.search(pat, log)
    return int(m.group(1)) if m else 0


# --------------------------------------------------------------------------------------------
# the agent callable
# --------------------------------------------------------------------------------------------

def make_swarm_agent(spec: dict, backend: str = "auto", base: Optional[str] = None,
                     model: Optional[str] = None, scratch_dir: Optional[str] = None,
                     max_new: int = 2048, verbose: bool = False,
                     judge_fn: Optional[Callable[[str, int], str]] = None):
    """Return (agent, label). `spec` describes the build target:

      spec = {
        "goal":       <high-level goal text>,
        "files":      [ {name, path, brief, max_new?}, ... ]  # the deliverables to write
        "test_glob":  <relative path under scratch to run pytest over>,  # for run_tests
        "context":    <optional shared reference text injected into every implement prompt>,
      }

    The agent walks `spec["files"]` one per `implement` visit, writes each into `scratch_dir`,
    and `run_tests` executes the produced pytest suite. State carries `code`, `last_error`,
    and an index of which file is next.
    """
    generate, label = resolve_backend(backend, base, model)
    # `debug` is a free-text JUDGMENT, not code — use a plain-text generator so the code-gen
    # system prompt (one fenced block) doesn't mangle it into a code/markdown blob. Falls back
    # to the code-gen generate only if no judge is supplied.
    judge = judge_fn or generate
    if scratch_dir is None:
        scratch_dir = os.path.join("/tmp", "prismpath_build")
    os.makedirs(scratch_dir, exist_ok=True)
    files = spec.get("files", [])
    ctx = spec.get("context", "")
    goal = spec.get("goal", "")

    def _log(msg):
        if verbose:
            print(msg, flush=True)

    def agent(node, instruction, state):
        # ---------------- plan ----------------
        if node == "plan":
            state.setdefault("file_idx", 0)
            todo = ", ".join(f["name"] for f in files)
            return {"text": f"plan ready: will implement {todo}",
                    "files_total": len(files), "planned": True}

        # ---------------- implement ----------------
        if node == "implement":
            # retry mode (set by debug): rewrite ONLY the blamed file, then go to run_tests.
            retry_idx = state.pop("retry_idx", None)
            if retry_idx is not None:
                idx = retry_idx
                single = True
            else:
                idx = state.get("file_idx", 0)
                single = False
            if idx >= len(files):
                return {"text": "all files already implemented", "more_files": False}
            f = files[idx]
            prior = state.get("written", {})
            prior_block = ""
            if prior:
                prior_block = "\n\n## Files already written (keep them consistent):\n" + \
                    "\n".join(f"- {p}" for p in prior)
            err = state.get("last_error", "")
            if err and state.get("last_file") == f["name"]:
                prompt = (f"{goal}\n\n{ctx}\n\nFile to (re)write: `{f['path']}`\n"
                          f"{f['brief']}\n{prior_block}\n\nYour previous version of this file "
                          f"failed:\n```\n{err[:1800]}\n```\nReturn the COMPLETE corrected file "
                          f"in ONE ```python code block, nothing else.")
            else:
                prompt = (f"{goal}\n\n{ctx}\n\nWrite the file `{f['path']}`.\n{f['brief']}"
                          f"{prior_block}\n\nReturn the COMPLETE file in ONE ```python code "
                          f"block, nothing else.")
            raw = generate(prompt, f.get("max_new", max_new))
            code = extract_code(raw)
            abspath = os.path.join(scratch_dir, f["path"])
            os.makedirs(os.path.dirname(abspath) or ".", exist_ok=True)
            with open(abspath, "w") as fh:
                fh.write(code + ("\n" if not code.endswith("\n") else ""))
            state.setdefault("written", {})[f["path"]] = abspath
            state["last_file"] = f["name"]
            if not single:
                state["file_idx"] = idx + 1
            more = (not single) and state["file_idx"] < len(files)
            _log(f"    [implement] wrote {f['path']} ({len(code)} chars) "
                 f"[{idx+1}/{len(files)}{' retry' if single else ''}]")
            return {"text": f"wrote {f['path']} ({len(code)} chars)",
                    "more_files": more, "wrote_file": f["path"]}

        # ---------------- run_tests (deterministic outcome) ----------------
        if node == "run_tests":
            test_target = os.path.join(scratch_dir, spec.get("test_glob", "tests"))
            passed, n_pass, n_fail, log = run_pytest(scratch_dir, test_target)
            state["last_error"] = "" if passed else log[-2500:]
            state["last_pass"], state["last_fail"] = n_pass, n_fail
            _log(f"    [run_tests] pass={n_pass} fail={n_fail} -> "
                 f"{'PASS' if passed else 'FAIL'}")
            return {"tests_pass": passed, "n_pass": n_pass, "n_fail": n_fail,
                    "text": (f"all {n_pass} tests passed" if passed
                             else f"{n_fail} failing, {n_pass} passing: {log[-200:]}")}

        # ---------------- debug (semantic outcome) ----------------
        if node == "debug":
            err = state.get("last_error", "")
            # re-target the failing file for the next implement pass.
            assess = judge(
                f"{goal}\n\nThe test suite failed:\n```\n{err[:1600]}\n```\n\n"
                f"In ONE short sentence: is the fix clear so we should edit code and retry, "
                f"or is the task genuinely blocked/unsolvable?", 64)
            # point implement back at the file most implicated by the failure, else last file.
            state["retry_idx"] = _blame_file_idx(err, files, state.get("file_idx", 0))
            txt = extract_code(assess) if "```" in assess else assess.strip()
            _log(f"    [debug] {txt[:120]}")
            return {"text": txt or "the fix is clear, retry"}

        # ---------------- document ----------------
        if node == "document":
            doc = spec.get("doc")
            if not doc:
                return {"text": "no document deliverable", "documented": False}
            prompt = (f"{goal}\n\n{ctx}\n\nWrite `{doc['path']}`: {doc['brief']}\n"
                      f"Return ONLY the markdown content in a ```markdown code block.")
            raw = generate(prompt, doc.get("max_new", max_new))
            content = extract_code(raw)
            abspath = os.path.join(scratch_dir, doc["path"])
            os.makedirs(os.path.dirname(abspath) or ".", exist_ok=True)
            with open(abspath, "w") as fh:
                fh.write(content + "\n")
            state.setdefault("written", {})[doc["path"]] = abspath
            _log(f"    [document] wrote {doc['path']} ({len(content)} chars)")
            return {"text": f"wrote {doc['path']}", "documented": True}

        return {"text": "(noop)"}

    return agent, label


def _blame_file_idx(err: str, files, default_idx: int) -> int:
    """Pick which file the failure most implicates, so implement rewrites the right one.

    Prefer files named in pytest's `FAILED ...`/`ERROR ...` summary lines (the actual failing
    test files) over an incidental stem match anywhere in the traceback (which previously
    mis-targeted, e.g. rewriting test_engine when test_predicates was failing)."""
    err = err or ""
    by_base = {os.path.basename(f["path"]).lower(): i for i, f in enumerate(files)}
    # 1) tally files cited in FAILED/ERROR summary lines (most-implicated wins)
    counts = {}
    for path in re.findall(r"(?:FAILED|ERROR)\s+\S*?([A-Za-z0-9_./-]+\.py)", err):
        i = by_base.get(os.path.basename(path).lower())
        if i is not None:
            counts[i] = counts.get(i, 0) + 1
    if counts:
        return max(counts, key=counts.get)
    # 2) else any filename mentioned anywhere (last match wins)
    err_low = err.lower()
    best = None
    for base, i in by_base.items():
        if base in err_low:
            best = i
    if best is not None:
        return best
    # 3) otherwise re-run the last file we touched (default_idx points one PAST it).
    return max(0, default_idx - 1)
