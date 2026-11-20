# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Differential harness for the governed agent's classifier (docs/design/spec-verified-classifier.md).

The Lean model of the classifier's syntactic reading (formal/Classifier/) is compiled to an oracle
(`formal/.lake/build/bin/classifier-oracle --batch`). This module holds the Python to it: every case is read by
the Python (`classifier.classify`, `claude_code.hook_call`, `mcp_map.classifier_call`) and by the oracle, and the
two must give the same call, workspace and reading, field for field.

The disk is an input of both, never something either reads on its own. The Python's three disk functions
(`classifier.disk_facts`, `claude_code._inside`, `_same_dir`, `_exists`) are replaced for the run by a provider
that records every fact it is asked; the facts go to the oracle as tables. When the oracle needs a fact the
Python did not ask (its query set is a proved over-approximation), it names it, the provider is asked, and the
case is run again. Two providers:

  * the real disk: a throwaway workspace and decoy directory with symbolic links in and out
    (`integrations.governed_harness.adversary.make_world`), the original functions observing it; used for every
    recorded hook input of `prismpath/tests/fixtures/claude_code_hooks.json` and the governed harness's 51
    adversary probes;
  * a synthetic disk: each fact a seeded function of its key, so every combination of disk facts meets every
    text; used for the generated calls.

The generated calls (`--cases`, seeded) are direct classifier calls, Claude Code hook inputs and MCP
`tools/call` params, biased toward the boundaries of the reading: every program set, every git subcommand and
listing flag, every kill form, URLs, `..`, globs, `/workspace`, quoting of every kind, shell operators, tilde
and brace words, non ASCII and control characters, lone surrogates, wrong types and extra keys, long paths and
long argvs. The control paths of the agent (settings, hooks, MCP file, CLAUDE.md, git hooks and config, in several spellings) are named in the PATHS and ordinary
words, and redirects and file changing programs are joined to them, so a change that names one meets every text. A string with a lone surrogate is outside the model's domain (Lean strings hold Unicode scalar values);
the transport says so (`nonscalar`) and both sides must read the call unknown. Numbers reach the oracle as 0,
since no part of the reading reads a number's value.

    python formal/diff/classifier_diff.py --cases 20000 --seed 1     # the full run
    python formal/diff/classifier_diff.py --cases 2000 --seed 7      # a quick run

Exit status 0 when every case agrees and every shipped agent policy's field definitions fit every reading.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from prismpath.agent import claude_code, classifier, mcp_map  # noqa: E402

ORACLE = Path(os.environ.get("PRISMPATH_CLASSIFIER_ORACLE")
              or ROOT / "formal" / ".lake" / "build" / "bin" / "classifier-oracle")
FIXTURES = ROOT / "prismpath" / "tests" / "fixtures" / "claude_code_hooks.json"
POLICIES = sorted((ROOT / "prismpath" / "agent" / "policy").glob("*.core.json"))
EXACT = 2 ** 53 - 1

_ORIGINAL = {"disk": classifier.disk_facts, "inside": claude_code._inside, "same": claude_code._same_dir,
             "exists": claude_code._exists}


# ----------------------------------------------------------------- providers of disk facts
class RealDisk:
    """The original functions, observing the real disk."""

    def disk(self, raw: str, config: classifier.Config) -> classifier.DiskFacts:
        return _ORIGINAL["disk"](raw, config)

    def inside(self, path: str, root: str) -> bool:
        return _ORIGINAL["inside"](path, root)

    def same(self, path: str, root: str) -> bool:
        return _ORIGINAL["same"](path, root)

    def exists(self, path: str) -> bool:
        return _ORIGINAL["exists"](path)


class SyntheticDisk:
    """Each fact a seeded function of its key: every combination of facts, independent of any real disk."""

    def __init__(self, seed: int):
        self.seed = seed

    def _bits(self, *key: str) -> int:
        text = json.dumps([self.seed, *key], ensure_ascii=True)
        return int.from_bytes(hashlib.sha256(text.encode()).digest()[:4], "big")

    def disk(self, raw: str, config: classifier.Config) -> classifier.DiskFacts:
        b = self._bits("disk", raw)
        return classifier.DiskFacts(inside=b % 10 < 6, toolchain=(b >> 4) % 7 == 0, symlink=(b >> 8) % 7 == 0,
                                    control=(b >> 12) % 5 == 0)

    def inside(self, path: str, root: str) -> bool:
        return self._bits("inside", path, root) % 8 != 0

    def same(self, path: str, root: str) -> bool:
        return self._bits("same", path, root) % 2 == 0

    def exists(self, path: str) -> bool:
        return self._bits("exists", path) % 3 == 0


class Recorder:
    """The facts one case asked, by kind, for the oracle's tables."""

    def __init__(self, provider, config: Optional[classifier.Config]):
        self.provider, self.config = provider, config
        self.disk: Dict[str, classifier.DiskFacts] = {}
        self.inside: Dict[Tuple[str, str], bool] = {}
        self.same: Dict[Tuple[str, str], bool] = {}
        self.exists: Dict[str, bool] = {}

    def ask_disk(self, raw, config=None):
        if raw not in self.disk:
            self.disk[raw] = self.provider.disk(raw, config or self.config)
        return self.disk[raw]

    def ask_inside(self, path, root):
        if (path, root) not in self.inside:
            self.inside[(path, root)] = self.provider.inside(path, root)
        return self.inside[(path, root)]

    def ask_same(self, path, root):
        if (path, root) not in self.same:
            self.same[(path, root)] = self.provider.same(path, root)
        return self.same[(path, root)]

    def ask_exists(self, path):
        if path not in self.exists:
            self.exists[path] = self.provider.exists(path)
        return self.exists[path]

    def tables(self) -> Dict[str, Any]:
        return {"disk": [[k, v.inside, v.toolchain, v.symlink, v.control] for k, v in self.disk.items()],
                "inside": [[a, b, v] for (a, b), v in self.inside.items()],
                "same": [[a, b, v] for (a, b), v in self.same.items()],
                "exists": [[k, v] for k, v in self.exists.items()]}


@contextmanager
def recording(rec: Recorder):
    """The Python's disk functions answered by `rec` for the duration."""
    saved = (classifier.disk_facts, claude_code._inside, claude_code._same_dir, claude_code._exists)
    classifier.disk_facts = lambda raw, config: rec.ask_disk(raw, config)
    claude_code._inside, claude_code._same_dir, claude_code._exists = rec.ask_inside, rec.ask_same, rec.ask_exists
    try:
        yield rec
    finally:
        classifier.disk_facts, claude_code._inside, claude_code._same_dir, claude_code._exists = saved


# ----------------------------------------------------------------- one case through the Python
def transport(value: Any) -> Any:
    """A Python value as the oracle reads it: numbers carry only their kind, so every number is 0."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return 0
    if isinstance(value, dict):
        return {key: transport(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [transport(item) for item in value]
    return str(value)


class Case:
    def __init__(self, ident: str, kind: str, value: Any, provider, config: Optional[classifier.Config] = None,
                 project_dir: Optional[str] = None, server_cwd: str = "/srv", remotes: Tuple[str, ...] = ()):
        self.id, self.kind, self.value, self.provider = ident, kind, value, provider
        self.config = config or classifier.Config(Path("/"), (), remotes)
        self.project_dir, self.server_cwd, self.remotes = project_dir, server_cwd, tuple(remotes)
        self.config.allowed_remotes = self.remotes if self.kind != "hook" else ()
        self.rec = Recorder(provider, self.config)
        self.python: Dict[str, Any] = {}
        self.proc_cwd = os.getcwd()

    def run_python(self) -> None:
        with recording(self.rec):
            if self.kind == "call":
                self.python = {"reading": classifier.classify(self.value, self.config)}
            elif self.kind == "mcp":
                call = mcp_map.classifier_call(self.value, self.server_cwd)
                self.python = {"call": call, "reading": classifier.classify(call, self.config)}
            else:
                env = {"CLAUDE_PROJECT_DIR": self.project_dir} if self.project_dir is not None else {}
                hc = claude_code.hook_call(self.value, env)
                config = self.config if isinstance(self.provider, SyntheticDisk) else \
                    classifier.Config.for_workspace(hc.workspace)
                self.rec.config = config
                self.python = {"call": hc.call, "workspace": hc.workspace,
                               "reading": claude_code.hook_reading(self.value, hc, config)}

    def nonscalar(self) -> bool:
        values = [self.value, self.server_cwd, self.project_dir or "", self.proc_cwd]
        return not all(_scalar(v) for v in values)

    def line(self) -> str:
        doc = {"id": self.id, "kind": self.kind, "nonscalar": self.nonscalar(),
               "input": None if self.nonscalar() else transport(self.value),
               "remotes": list(self.remotes) if self.kind != "hook" else [],
               "project_dir": self.project_dir, "proc_cwd": self.proc_cwd, "server_cwd": self.server_cwd}
        doc.update(self.rec.tables())
        if self.nonscalar():
            doc.update({"project_dir": None, "server_cwd": "", "disk": [], "inside": [], "same": [], "exists": []})
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))

    def fill(self, missing: Dict[str, Any]) -> None:
        for raw in missing.get("disk", []):
            self.rec.ask_disk(raw)
        for path, root in missing.get("inside", []):
            self.rec.ask_inside(path, root)
        for path, root in missing.get("same", []):
            self.rec.ask_same(path, root)
        for path in missing.get("exists", []):
            self.rec.ask_exists(path)

    def compare(self, lean: Dict[str, Any]) -> Optional[str]:
        want = {"reading": self.python["reading"]}
        if self.kind in ("hook", "mcp"):
            want["call"] = transport(self.python["call"])
        if self.kind == "hook" and not self.nonscalar():
            want["workspace"] = self.python["workspace"]
        got = {key: lean.get(key) for key in want}
        return None if got == want else json.dumps({"python": want, "lean": got}, ensure_ascii=True)


def _scalar(value: Any) -> bool:
    """The transport's own test of the model's domain (not the classifier's `scalar`, which it checks)."""
    if isinstance(value, str):
        return not any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)
    if isinstance(value, dict):
        return all(_scalar(k) and _scalar(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return all(_scalar(v) for v in value)
    return True


# ----------------------------------------------------------------- the oracle
def run_oracle(cases: List[Case]) -> Dict[str, Dict[str, Any]]:
    text = "".join(case.line() + "\n" for case in cases)
    out = subprocess.run([str(ORACLE), "--batch"], input=text.encode("utf-8"), capture_output=True, check=True)
    answers = {}
    for line in out.stdout.decode("utf-8").split("\n"):
        if not line:
            continue
        doc = json.loads(line)
        if "id" not in doc:
            raise RuntimeError(f"the oracle refused a case: {line}")
        answers[doc["id"]] = doc
    return answers


def check_policies() -> List[str]:
    """Every shipped agent policy's field definitions fit every reading (Theorems.boundary_accepts_every_reading), no
    reading the hazard scan gives is allowed (ScanTheorems.scan_safe_reading) and every change that names a control
    file of the agent is refused (Control.control_refused)."""
    bad = []
    for image in POLICIES:
        out = subprocess.run([str(ORACLE), "--policy", str(image)], capture_output=True, check=True, text=True)
        if json.loads(out.stdout) != {"policy": "accepted", "fits": True, "scan_refused": True, "control_refused": True}:
            bad.append(f"{image.name}: {out.stdout.strip()}")
    return bad


def run(cases: List[Case], rounds: int = 4) -> Dict[str, Any]:
    for case in cases:
        case.run_python()
    pending, answers, asked = list(cases), {}, 0
    for _ in range(rounds):
        if not pending:
            break
        got = run_oracle(pending)
        again = []
        for case in pending:
            doc = got[case.id]
            if "missing" in doc:
                case.fill(doc["missing"])
                again.append(case)
            else:
                answers[case.id] = doc
        asked += len(again)
        pending = again
    disagreements = {}
    for case in cases:
        if case.id not in answers:
            disagreements[case.id] = "the oracle still needs disk facts after every round"
            continue
        diff = case.compare(answers[case.id])
        if diff is not None:
            disagreements[case.id] = diff
    kinds = Counter(case.kind for case in cases)
    readings = Counter((case.python["reading"]["tool"], case.python["reading"]["command_class"]) for case in cases)
    return {"cases": len(cases), "kinds": dict(kinds), "refilled": asked, "disagreements": disagreements,
            "nonscalar": sum(case.nonscalar() for case in cases), "readings": readings}


# ----------------------------------------------------------------- recorded inputs on the real disk
def _fill(value: Any, world: Dict[str, str]) -> Any:
    if isinstance(value, str):
        return value.replace("@WS@", world["ws"]).replace("@DECOY@", world["decoy"])
    if isinstance(value, list):
        return [_fill(v, world) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, world) for k, v in value.items()}
    return value


def recorded_cases(root: Path) -> List[Case]:
    """The 120 recorded hook inputs and the 51 adversary probes, on a real throwaway world."""
    from integrations.governed_harness import adversary
    made = adversary.make_world(root / "world")
    world = {"ws": str(made["ws"].resolve()), "decoy": str(made["decoy"].resolve())}
    real = RealDisk()
    out: List[Case] = []
    for case in json.loads(FIXTURES.read_text(encoding="utf-8")):
        hook = {"session_id": "s1", "transcript_path": "/tmp/t.jsonl", "cwd": _fill(case["cwd"], world),
                "hook_event_name": "PreToolUse", "tool_name": case["tool_name"], "tool_use_id": "toolu_1",
                "tool_input": _fill(case["tool_input"], world)}
        pd = _fill(case["project_dir"], world) if case.get("project_dir") else None
        out.append(Case("fixture:" + case["id"], "hook", hook, real, project_dir=pd))
    config = classifier.Config.for_workspace(made["ws"])
    for case in adversary.CASES:
        calls = adversary._fill(case.probe if isinstance(case.probe, list) else [case.probe], made["decoy"])
        for n, call in enumerate(calls):
            out.append(Case(f"adversary:{case.id}:{n}", "call", call, real, config=config))
    return out


# ----------------------------------------------------------------- the generator
PROGRAMS = sorted(classifier.READ_ONLY | classifier.MUTATING | classifier.NETWORK | classifier.PRIVILEGE |
                  set(classifier.INSTALLERS) | classifier.WRAPPERS) + ["git", "mytool", "LS", "Cat", "rm2", "k1ll"]
SUBCOMMANDS = sorted(classifier.GIT_LOCAL_READ | classifier.GIT_LOCAL_WRITE | classifier.GIT_MUTATING |
                     classifier.GIT_NETWORK) + ["push", "remote", "reset", "tag", "branch", "-c", "", "frobnicate",
                                                "--version", "Push"]
FLAGS = ["-rf", "-r", "-f", "-i", "-i.bak", "-iE", "--in-place", "--in-place=.b", "-o", "-ofile", "--output",
         "--output=x", "-exec", "-execdir", "-delete", "-ok", "-fprint", "-fls", "-name", "-m", "pip", "-s", "-9",
         "-KILL", "-SIGTERM", "-HUP", "-sigterm", "-1", "-0", "-", "--", "-v", "--verbose", "-vv", "--hard", "--soft",
         "--list", "-l", "-n", "-n5", "-n12", "-n", "-a", "--all", "-r", "--remotes", "--sort=x", "--format=%h",
         "--abbrev=4", "--color", "--color=never", "--column", "--contains", "--merged", "--points-at",
         "--no-contains", "-d", "-D", "--delete", "--force", "-u", "--exec=x", "--upload-pack", "--upload-pack=x",
         "--receive-pack", "-c", "-cfoo", "--config", "--config=a=b", "--git-dir=/x", "--work-tree", "-C", "-Cx",
         "--x=/etc/passwd", "--x=a/b", "--x=ab", "--file=../x", "-x=/a", "-n\u0661", "-\u0661"]
PIDS = ["1", "12", "1234", "0", "00", "007", "-1", "\u0661\u0662", "\xb2", "1a", "", "%1", "12 ", "\uff11"]
SIGNALS = ["-9", "-KILL", "-SIGKILL", "-s", "TERM", "-sKILL", "-15", "-K1", "-k", "-9\n", "-\u0669", "-\u0669", "-\xb2",
           "-\u0130", "-K\u0669"]
PATHS = [".", "..", "./a", "a/../b", "../decoy/x", "src/app.py", "notes.txt", "/etc/passwd", "/etc", "/", "//",
         "/workspace", "/workspace/a", "/workspace/../x", "/./workspace/a", "/workspacex", "~", "~/x", "~root", "a~",
         "*.txt", "a?b", "[ab]", "{a,b}", "x}", "a/**/b", "a\x00b", "a" * 4097, "a" * 4096, ".claude/settings.json", ".claude/settings.local.json", ".claude/hooks/pre.sh", ".mcp.json", ".claude",
         "src/../.claude/settings.json", ".claude/commands/x.md", ".CLAUDE/Settings.json", ".git/hooks/pre-commit", ".git/config", ".git", "CLAUDE.md",
         "sub/CLAUDE.local.md", "AGENTS.md", "/workspace/.mcp.json", "x//y", "a/", "a/.",
         "..a", "a..", "...", "a/..", "../", "/usr/bin/x", "/usr/local/bin/h", ".toolchain/bin/py", "a=b/c",
         "link_out/x", "cfg", "-", "--", "https://example.invalid/x", "git@host:x.git", "ftp://a", "a1+.-://b",
         "1://x", "\xe9://x", "x://", "://x", "S3://b", "a b", "\t", "\u200b", "\u202e", "\xe9", "e\u0301",
         "\U0001f600", "\x1f", "\x7f", "\x85", "\xa0", "\u3000", "\u2028"]
KILLISH = ["pkill", "killall", "kill", "xpkill", "pkill_x", "pkill-x", "pkillx", "killall2", "kill 123", "kill -9 123",
           "kill -s TERM 12", "kill %1", "kill 0", "kill", "kill -9", "a;kill 0", "a&kill 1 x", "kill\t1", "kill\xa01",
           "kill\x1c1", "foo|killall", "\xe9pkill", "pkill\xe9", "kill -9\n1", "kill 1;pkill x", "(kill 7)", "`kill x`",
           "kill -s", "kill -s 1", "kill 12 13", "kill 12 x", "sleep 1", "echo kill", "KILL 1", "kil l"]
REMOTES = ["origin", "backup", "upstream", "-u", "https://x.invalid/r.git", "o\xe9", ""]
ODD = ["", " ", "\t", "\n", "\r", "\x00", "\x0b", "\x0c", "\x1b", "\x7f", "\x85", "\xa0", "\u2000", "\u3000", "\ufeff",
       "\u200d", "\ud800", "\udc80", "\U0010ffff", "\xe9", "\u0301", "\\", "'", '"', "`", "$", "$(id)", "${x}", ";", "&",
       "&&", "|", "||", ">", "<", "(", ")", "#", "!", "^", "~", "{", "}", "*", "?", "[", "]", "=", "%", "@", ",", ":",
       "+", "\\n", "\\'"]


CLEAN_PATHS = ["notes.txt", "src/app.py", "src", ".", "build/out.o", "logs/a.log", "README.md", "/etc/hosts",
               "../x", "a/../b", ".claude/settings.json", ".mcp.json", ".claude/hooks/a.sh", "*.txt", "logs/[ab].log", "/workspace/notes.txt", ".toolchain/VERSION", "cfg", "link_out/x"]
SEP_AROUND = ["", "", "", "\xe9", "_", "1", " ", ";", "-", "x", "|", "\n", "(", "/", "\xa0", "\x1c"]


def _killish(rng: random.Random) -> str:
    """A kill written inside one argument, with every kind of character around the kill words."""
    core = rng.choice(["pkill", "killall", "kill", "kill " + rng.choice(PIDS + SIGNALS),
                       "kill " + rng.choice(SIGNALS) + " " + rng.choice(PIDS), "kill -s TERM " + rng.choice(PIDS)])
    return rng.choice(SEP_AROUND) + core + rng.choice(SEP_AROUND) + (rng.choice(KILLISH) if rng.random() < 0.2 else "")


def _clean_word(rng: random.Random) -> str:
    r = rng.random()
    if r < 0.5:
        return rng.choice(CLEAN_PATHS)
    if r < 0.85:
        return rng.choice(FLAGS[:40])
    return rng.choice(PROGRAMS)


def _word(rng: random.Random) -> str:
    if rng.random() < 0.4:
        return _clean_word(rng)
    r = rng.random()
    if r < 0.30:
        return rng.choice(PATHS)
    if r < 0.55:
        return rng.choice(FLAGS)
    if r < 0.65:
        return rng.choice(PIDS + SIGNALS)
    if r < 0.75:
        return rng.choice(KILLISH)
    if r < 0.82:
        return rng.choice(PROGRAMS)
    if r < 0.88:
        return rng.choice(REMOTES)
    if r < 0.94:
        return rng.choice(ODD)
    return "".join(rng.choice(PATHS + ODD + FLAGS) for _ in range(rng.randint(2, 3)))


def _program(rng: random.Random) -> str:
    p = rng.choice(PROGRAMS)
    r = rng.random()
    if r < 0.12:
        return rng.choice(["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"]) + p
    if r < 0.18:
        return rng.choice(["/usr//bin/", "/usr/bin//", "//", "./", "/opt/", "bin/", "/usr/local/bin/", "~/",
                           "/./usr/bin/", "/usr/bin/../bin/"]) + p
    if r < 0.2:
        return rng.choice(["/usr/bin/", "/", "", p + "/", "\xe9" + p, p + "\x00", p.upper()])
    return p


def _argv(rng: random.Random) -> List[Any]:
    r = rng.random()
    if r < 0.03:
        return []
    if r < 0.05:
        return [rng.choice(PROGRAMS)] + [rng.choice(PATHS) for _ in range(rng.choice([63, 64, 65, 70]))]
    argv: List[Any] = [_program(rng)]
    first = os.path.basename(argv[0])
    if rng.random() < 0.1:
        argv[0] = rng.choice(["git", "/usr/bin/git", "git"])
        first = "git"
    if first == "git" or rng.random() < 0.08:
        argv.append(rng.choice(SUBCOMMANDS))
    elif first in ("kill", "pkill", "killall") or rng.random() < 0.12:
        if rng.random() < 0.3:
            argv[0] = rng.choice(["kill", "/bin/kill", "/usr/bin/kill", "./kill"])
        argv += [rng.choice(SIGNALS)] if rng.random() < 0.5 else (["-s", rng.choice(SIGNALS + ["TERM"])]
                                                                   if rng.random() < 0.2 else [])
        argv += [rng.choice(PIDS[:6]) if rng.random() < 0.7 else rng.choice(PIDS) for _ in range(rng.randint(0, 3))]
        return argv
    elif first in classifier.WRAPPERS and rng.random() < 0.6:
        argv += [rng.choice(["-c", "-e", "-x", "--", "5"]), _killish(rng) if rng.random() < 0.7 else _word(rng)]
    elif first in classifier.INSTALLERS and rng.random() < 0.6:
        argv.append(rng.choice(classifier.INSTALLERS[first] + ("list", "-m", "show")))
    elif first in ("python", "python3") and rng.random() < 0.5:
        argv += ["-m", rng.choice(["pip", "venv", "http.server"])]
    argv += [_word(rng) for _ in range(rng.choice([0, 1, 1, 2, 2, 3, 4, 6]))]
    if rng.random() < 0.5:
        argv = [a.replace("\x00", "") or "x" for a in argv]       # most argvs are well formed
    if rng.random() < 0.04:
        argv.insert(rng.randrange(len(argv) + 1), rng.choice([None, 1, 2.5, True, [], {}, ""]))
    return argv


def _git_args(rng: random.Random) -> List[Any]:
    args: List[Any] = [_word(rng) for _ in range(rng.choice([0, 0, 1, 1, 2, 3, 5]))]
    if rng.random() < 0.3:
        args.insert(0, rng.choice(REMOTES))
    if rng.random() < 0.03:
        args = ["x"] * rng.choice([64, 65])
    if rng.random() < 0.04:
        args.append(rng.choice([None, 3, ["a"], "a\x00"]))
    return args


def _maybe_break(rng: random.Random, call: Dict[str, Any]) -> Any:
    r = rng.random()
    if r < 0.03:
        return rng.choice([None, [], "read_file", 7, {"tool": "read_file"}])
    if r < 0.06:
        call = dict(call)
        call[rng.choice(["extra", "Tool", "argv"])] = rng.choice([1, "x", None])
    elif r < 0.09 and isinstance(call.get("args"), dict):
        args = dict(call["args"])
        if args and rng.random() < 0.5:
            args.pop(rng.choice(sorted(args)))
        else:
            args[rng.choice(["path", "content", "argv", "subcommand", "args", "mode"])] = \
                rng.choice([None, 1, True, "x", ["x"], {"a": 1}])
        call["args"] = args
    elif r < 0.1:
        call = {"tool": call["tool"]}
    elif r < 0.11:
        call["args"] = rng.choice([None, [], "x"])
    return call


def gen_call(rng: random.Random) -> Any:
    tool = rng.choice(list(classifier.TOOLS) * 6 + ["run_command"] * 12 + ["git"] * 4 + ["unknown", "", "Read", "list_dirs"])
    if tool in ("list_dir", "read_file", "delete_path"):
        args = {} if tool == "list_dir" and rng.random() < 0.2 else {"path": rng.choice(PATHS + [_word(rng)])}
    elif tool == "write_file":
        args = {"path": rng.choice(PATHS + [_word(rng)]), "content": rng.choice(["", "x", "\x00", "\ud800"])}
    elif tool == "run_command":
        args = {"argv": _argv(rng)}
    elif tool == "git":
        args = {"subcommand": rng.choice(SUBCOMMANDS)}
        if rng.random() < 0.85:
            args["args"] = _git_args(rng)
    else:
        args = {"path": "x"}
    return _maybe_break(rng, {"tool": tool, "args": args})


def _quote(rng: random.Random, word: str) -> str:
    r = rng.random()
    if r < 0.75:
        return word
    if r < 0.72:
        return "'" + word + "'"
    if r < 0.82:
        return '"' + word + '"'
    if r < 0.86:
        cut = rng.randrange(len(word) + 1)
        return word[:cut] + rng.choice(["'", '"']) + word[cut:] + rng.choice(["'", '"', ""])
    if r < 0.9:
        return "\\" + word if rng.random() < 0.5 else word.replace(" ", "\\ ")
    if r < 0.93:
        return "''" if rng.random() < 0.5 else '""'
    return word + rng.choice(ODD)


def _git_compound(rng: random.Random) -> str:
    """Several git invocations joined by shell operators: the hazard scan's git rule, its severity order included."""
    parts = []
    for _ in range(rng.randint(1, 3)):
        if rng.random() < 0.35:     # an installer and maybe one of its fetch words, the scan's installer rule
            name = rng.choice(sorted(claude_code.SCAN_INSTALLERS) + ["python -m pip", "/usr/bin/pip", "pipx2"])
            fetch = rng.choice([w for subs in claude_code.SCAN_INSTALLERS.values() for w in subs] + ["run", "list", "-q"])
            parts.append(f"{name} {rng.choice(['', '-q ', '--user '])}{fetch} pkg")
            continue
        words = [rng.choice(["git", "/usr/bin/git", "./git", "git2"]), rng.choice(SUBCOMMANDS + ["reset", "reset", "remote"])]
        words += [rng.choice(["--hard", "-v", "--verbose", "-f", "x", "origin", "--exec=x", "-c", "-C", "add"])
                  for _ in range(rng.randint(0, 3))]
        parts.append(" ".join(words))
    return rng.choice([" ; ", " && ", " | ", "\n", " & "]).join(parts) + rng.choice(["", ";", " \\"])


REDIRECTS = [">", ">>", " > ", " >> ", "2>", "&>", ">&", ">|", "> ", ">>", "2>&1", ">&2", "1>&-", ">/dev/null",
             "2>/dev/null", "&>/dev/null", "> /dev/null", ">/dev/nullx", ">&x", ">& ", ">&1x", ">>/dev/null"]
WRITERS = ["rm -rf", "rm", "mv", "cp", "tee", "tee -a", "touch", "sed -i s/a/b/", "sed -n p", "sed", "find . -delete", "find",
           "sort -o", "sort", "tree -o x", "tree", "git add", "git commit -m x", "git diff", "git status", "python", "pytest",
           "vim", "dd of=", "tar xf", "install", "/usr/bin/rm", "echo", "printf x", "cat", "grep -r x", "ls", "kill 1"]


def _redirect_compound(rng: random.Random) -> str:
    """A command outside the grammar that redirects, or names a file changing program, with control paths and
    ordinary paths among its words: the scan's control rule, its redirect and writer tests included."""
    parts = []
    for _ in range(rng.randint(1, 3)):
        words = [rng.choice(WRITERS)] + [rng.choice(PATHS + ["x", "-n", "."]) for _ in range(rng.randint(0, 2))]
        if rng.random() < 0.6:
            words.insert(rng.randint(1, len(words)), rng.choice(REDIRECTS) + rng.choice(["", "", " "]))
            words.append(rng.choice(PATHS))
        parts.append(" ".join(words))
    return rng.choice([" ; ", " && ", " | ", "\n"]).join(parts)


def gen_command(rng: random.Random) -> str:
    if rng.random() < 0.08:
        return _git_compound(rng)
    if rng.random() < 0.12:
        return _redirect_compound(rng)
    argv = [a for a in _argv(rng) if isinstance(a, str)] or ["ls"]
    if rng.random() < 0.5:         # a command in the grammar, quoted where a word needs it
        argv = [a for a in argv if all(c in claude_code.QUOTED or c in "'\"" for c in a)] or ["ls", "-la"]
        words = [("'" + w + "'" if not all(c in claude_code.PLAIN for c in w) or rng.random() < 0.1 else w)
                 if "'" not in w else '"' + w + '"' for w in argv]
        return rng.choice([" ", "  ", "\t"]).join(words)
    words = [_quote(rng, w) for w in argv]
    seps = [rng.choice([" ", " ", " ", "  ", "\t", " \t", "\xa0", "\n", ";", " | ", "&&", "\r"]) if rng.random() < 0.25
            else " " for _ in words]
    text = "".join(w + s for w, s in zip(words, seps)).rstrip(" ")
    r = rng.random()
    if r < 0.05:
        text = rng.choice(["", " ", "\t", "\xa0", "  \t "])
    elif r < 0.1:
        text = rng.choice(ODD) + text
    return text


def gen_hook(rng: random.Random, ws: str) -> Tuple[Dict[str, Any], Optional[str]]:
    name = rng.choice(["Bash"] * 30 + ["Read"] * 6 + ["Write"] * 4 + ["Edit", "Edit", "MultiEdit", "MultiEdit", "NotebookEdit",
                       "NotebookEdit"] + ["Glob"] * 4 + ["Grep", "Grep", "LS", "LS", "WebFetch", "Task", "mcp__fs__read",
                       "bash", "", "Read "])
    path = lambda: rng.choice(PATHS + [ws, ws + "/.claude/settings.json", ws + "/.mcp.json", ws + "/src/a.py", ws + "/../decoy/x", "/tmp/x", _word(rng)])  # noqa: E731
    if name == "Bash":
        ti: Any = {"command": gen_command(rng)}
        if rng.random() < 0.2:
            ti["description"], ti["timeout"] = "run it", rng.choice([1000, 1.5, None])
        if rng.random() < 0.03:
            ti["command"] = rng.choice([None, 5, ["ls"], {"c": "ls"}])
    elif name == "Read":
        ti = {"file_path": path()} if rng.random() < 0.9 else rng.choice([{}, {"file_path": None}, {"file_path": 3}])
    elif name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        key = "notebook_path" if name == "NotebookEdit" and rng.random() < 0.8 else "file_path"
        ti = {key: path(), "content": "x"} if rng.random() < 0.85 else {}
        if rng.random() < 0.2:
            ti["notebook_path" if key == "file_path" else "file_path"] = rng.choice([path(), None])
        if name == "MultiEdit" or rng.random() < 0.1:
            ti["edits"] = [rng.choice([{"old_string": "a"}, {"file_path": path()}, {"notebook_path": None},
                                       {"file_path": ti.get(key, "x")}, "x", {"file_path": ""}])
                           for _ in range(rng.randint(0, 3))]
    elif name in ("Glob", "Grep", "LS"):
        ti = {}
        if rng.random() < 0.7:
            ti["pattern"] = rng.choice(["**/*.py", "*.txt", "/etc/*", "../*", "~/x", "", "TODO", "a/b", 5])
        if rng.random() < 0.6:
            ti["path"] = rng.choice([path(), "", None, 3])
        if rng.random() < 0.05:
            ti["paths"] = ["a"]
    else:
        ti = {"url": "https://x.invalid", "prompt": "x"}
    if rng.random() < 0.02:
        ti = rng.choice([None, [], "x"])
    cwd = rng.choice([ws, ws, ws, ws, ws, ws + "/src", ws + "/src", ws + "/", "/tmp/decoy", "", None, "src", 7, "/workspace", ws + "/\xe9"])
    hook: Dict[str, Any] = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": name, "tool_input": ti}
    if cwd is not None:
        hook["cwd"] = cwd
    if rng.random() < 0.02:
        hook["tool_name"] = rng.choice([None, 3, ["Bash"]])
    if rng.random() < 0.01:
        hook = rng.choice([[], "x", None])
    pd = rng.choice([None, None, None, ws, "", "/tmp/decoy"])
    return hook, pd


FS_NAMES = ["read_text_file", "read_media_file", "get_file_info", "list_directory", "list_directory_with_sizes",
            "directory_tree", "search_files", "edit_file", "create_directory", "list_allowed_directories", "move_file",
            "read_multiple_files", "write_file", "read_file"]


def gen_mcp(rng: random.Random) -> Any:
    name = rng.choice(FS_NAMES + list(classifier.TOOLS) + ["", "exec", None])
    if name in classifier.TOOLS:
        args = gen_call(rng)
        arguments = args.get("args", {}) if isinstance(args, dict) else args
    else:
        arguments = {}
        for key in rng.sample(["path", "pattern", "edits", "head", "tail", "sortBy", "excludePatterns", "dryRun",
                               "content", "source"], rng.randint(0, 3)):
            arguments[key] = rng.choice(PATHS + ["*.py", "", None, 3, ["x"]])
        if rng.random() < 0.6 and name not in (None, "list_allowed_directories"):
            arguments["path"] = rng.choice(PATHS)
    params: Any = {"name": name, "arguments": arguments}
    if rng.random() < 0.1:
        params.pop("arguments")
    if rng.random() < 0.02:
        params = rng.choice([None, [], "x", {"arguments": {}}])
    return params


def generated_cases(n: int, seed: int) -> List[Case]:
    rng = random.Random(seed)
    disk = SyntheticDisk(seed)
    ws = "/home/u/ws"
    out = []
    for i in range(n):
        r = rng.random()
        remotes = tuple(rng.sample(["origin", "backup", "upstream", ""], rng.randint(0, 2)))
        if r < 0.4:
            out.append(Case(f"gen:{i}:call", "call", gen_call(rng), disk, remotes=remotes))
        elif r < 0.85:
            hook, pd = gen_hook(rng, ws)
            out.append(Case(f"gen:{i}:hook", "hook", hook, disk, project_dir=pd))
        else:
            out.append(Case(f"gen:{i}:mcp", "mcp", gen_mcp(rng), disk, remotes=remotes,
                            server_cwd=rng.choice([ws, ws + "/", "/", "/workspace", "srv"])))
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--cases", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--no-recorded", action="store_true", help="skip the recorded inputs on the real disk")
    args = parser.parse_args(argv)
    if not ORACLE.exists():
        print(f"the classifier oracle is not built ({ORACLE}); cd formal && lake build", file=sys.stderr)
        return 2
    bad = check_policies()
    with tempfile.TemporaryDirectory() as tmp:
        recorded = [] if args.no_recorded else recorded_cases(Path(tmp))
        result_recorded = run(recorded) if recorded else None
    result = run(generated_cases(args.cases, args.seed))
    for name, res in (("recorded", result_recorded), ("generated", result)):
        if res is None:
            continue
        print(f"{name}: {res['cases']} cases {res['kinds']}, {res['nonscalar']} outside the scalar domain, "
              f"{res['refilled']} asked again for disk facts, {len(res['disagreements'])} disagreements")
        for ident, diff in list(res["disagreements"].items())[:20]:
            print(f"  {ident}: {diff}")
    print(f"policies: {len(POLICIES)} images, {len(bad)} with a definition some reading does not fit")
    for line in bad:
        print("  " + line)
    total = len(result["disagreements"]) + (len(result_recorded["disagreements"]) if result_recorded else 0)
    return 0 if total == 0 and not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
