# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Context Cloud information point: whether a change reaches the owner's protected code, asked of Context Cloud.

The point supplies `zone_reach` and, as fields of its own, `cc_certainty` and `cc_engine_agreement`: Context Cloud's
answer before the policy's requirements are applied, and how many engines agree with it. `policy.cc_required_certainty`
and `policy.cc_engine_agreement` narrow `zone_reach` only (`ContextCloudZones._reading`).

The point is evidence and never authority. It reads `unknown` for every path, and says why, when the index or the
program that reads it could have been written by the agent (`_distrust`). This module imports no other prismpath
package. What it needs from the agent kind is handed to it: `host_path` (how a model's path names a host file) and
`unconfined` (whether no per call sandbox confines the agent). A point built without them reads `unknown`.
The trust checks on the index and the program are described in the docstring of prismpath/agent/zones.py.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sqlite3
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from prismpath.ports.information import Change, Evidence

CACHE_FILE = "zones-cache.json"
DEFAULT_BUDGET_S = 0.1          # what one path may spend asking Context Cloud before it reads unknown
WORKERS = min(16, os.cpu_count() or 4)     # lookups run side by side: each one is a process start
ZONE_REACH = ("none", "protected", "unknown")
# What Context Cloud says of a file: its strongest answer over the file's functions, in Context Cloud's own words
# (`contextcloud reaches --json`, `certainty`: no, certain, likely or unknown; `no` is read as `none`).
CC_CERTAINTY = ("none", "likely", "certain", "unknown")
# How many engines OTHER than Context Cloud agree with that answer, as Context Cloud reports it: 0 to 63. Context Cloud
# itself is the one engine a requirement counts first, so a requirement of N (1 to 64) is met by N - 1 of these.
CC_ENGINE_AGREEMENT = tuple(range(64))
REQUIRED_CERTAINTIES = ("likely", "certain")      # `policy.cc_required_certainty`, weakest first
RANK = {"unknown": 0, "likely": 1, "certain": 2}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clean_env(home: Path) -> Dict[str, str]:
    """The only environment the program runs in: no PYTHON* variable (a PYTHONPATH inside the project would let the
    agent put its own `contextcloud` package ahead of the installed one, and run in the hook outside the sandbox), a
    fixed system PATH, and the little a program needs."""
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "TMPDIR": tempfile.gettempdir()}


def program_argv(real: str) -> List[str]:
    """What runs the program at the real path `real`: its own Python interpreter with `-I` (no user site, no PYTHON*
    variable, no current directory on the path) when its shebang names one by an absolute path, else the program."""
    try:
        with open(real, "rb") as handle:
            first = handle.readline(512).decode("utf-8", "replace").strip()
    except OSError:
        return [real]
    words = first[2:].split() if first.startswith("#!") else []
    if words and os.path.isabs(words[0]) and os.path.basename(words[0]).startswith("python"):
        return [words[0], "-I", real]
    return [real]


def control_paths_of(doc: Mapping[str, Any]) -> Tuple[str, ...]:
    """The control paths a verified zone document makes: the index's directory, with a trailing slash, when it is
    strictly inside the project, else the index file and its -wal and -shm siblings."""
    index, project = Path(doc["index"]), Path(doc["project"])
    parent = index.parent
    if parent != project and project in parent.parents:
        return (str(parent) + "/",)
    return tuple(str(index) + suffix for suffix in ("", "-wal", "-shm"))


def contextcloud_executable(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """`$CONTEXTCLOUD`, else `contextcloud` on the PATH, else None (Context Cloud is absent)."""
    env = os.environ if env is None else env
    named = env.get("CONTEXTCLOUD")
    if named:
        return named if os.access(named, os.X_OK) else None
    return shutil.which("contextcloud", path=env.get("PATH"))


def agent_uid() -> int:
    """The user the agent runs as: the hook's own, since the hook and the agent are one user's processes."""
    return os.geteuid()


def _requirement_problem(required_certainty: Any, engine_agreement: Any) -> str:
    """'' when the two requirements are values the grammar allows, else why not."""
    if not isinstance(required_certainty, str) or required_certainty not in REQUIRED_CERTAINTIES:
        return f"the required certainty {required_certainty!r} is not one of {', '.join(REQUIRED_CERTAINTIES)}"
    if isinstance(engine_agreement, bool) or not isinstance(engine_agreement, int) or not 1 <= engine_agreement <= 64:
        return f"the required engine agreement {engine_agreement!r} is not a whole number from 1 to 64"
    return ""


# ------------------------------------------------------------------------------------------------ the adapter
def _covered(name: str, protected: Sequence[str]) -> bool:
    """`name` is a protected name, or lies inside a protected module or class."""
    return any(name == p or name.startswith(p + ".") for p in protected)


def _covering(name: str, protected: Sequence[str]) -> frozenset:
    """The protected names that cover `name`."""
    return frozenset(p for p in protected if name == p or name.startswith(p + "."))


class ContextCloudZones:
    """The information point that asks Context Cloud (`contextcloud reaches --json`, whose JSON output is described in the Context Cloud repository)."""

    name = "contextcloud"
    fields = {"zone_reach": ZONE_REACH, "cc_certainty": CC_CERTAINTY, "cc_engine_agreement": CC_ENGINE_AGREEMENT}
    restrictive = {"zone_reach": "unknown", "cc_certainty": "unknown", "cc_engine_agreement": 0}
    classifier_fields = ("zone_reach",)     # fields the agent's classifier already has; the catalog lists the others

    def __init__(self, doc: Dict[str, Any], home: Path, executable: str, budget_s: float = DEFAULT_BUDGET_S,
                 run=subprocess.run, host_write: bool = False, unconfined: Optional[Callable[[], bool]] = None,
                 host_path: Optional[Callable[[str, Any], str]] = None, required_certainty: Any = "likely",
                 engine_agreement: Any = 1):
        """`required_certainty` (`policy.cc_required_certainty`) is the weakest answer of Context Cloud that
        `zone_reach` reads `protected` for: `likely` (the default, and what the point always did) reads a `certain`
        and a `likely` answer `protected`, `certain` only a `certain` one. `engine_agreement`
        (`policy.cc_engine_agreement`) is how many engines must agree before `zone_reach` reads `protected`: 1 (the
        default) asks nothing beyond Context Cloud's own answer, N asks for `cc_engine_agreement` (the engines other than
        Context Cloud that agree) to be at least N - 1. An answer that does not meet either reads `unknown` for
        `zone_reach`, never `none`. A requirement that is not one of the listed values (not `likely` or `certain`,
        not an int from 1 to 64) is recorded in `requirement_why` and makes every path read `unknown`; the index trust
        check still runs and is reported apart in `why`. Both requirements are read only after construction."""
        self._unconfined, self._host_path = unconfined, host_path
        self._required_certainty, self._engine_agreement = required_certainty, engine_agreement
        self.requirement_why = _requirement_problem(required_certainty, engine_agreement)
        self.doc, self.home, self.exe, self.budget_s, self._run = doc, Path(home), executable, budget_s, run
        self.protected: List[str] = list(doc["protected"])
        self.project = Path(doc["project"])
        self.index = Path(doc["index"])
        self.zones_sha = _sha256(json.dumps(doc, sort_keys=True).encode())
        self.stats: Dict[str, Any] = {}
        self.host_write = host_write
        self.real_exe = os.path.realpath(executable)
        self.why = self._distrust()

    # --- the index is a control path, and must not be one the agent could have written
    @property
    def control_paths(self) -> Tuple[str, ...]:
        return control_paths_of(self.doc)

    def _below_project(self, path: Path) -> bool:
        return path != self.project and self.project in path.parents

    def _within_project(self, path: Path) -> bool:
        return path == self.project or self._below_project(path)

    def _confined(self) -> bool:
        """The per call sandbox holds the agent to the workspace here (see the docstring of prismpath/agent/zones.py).
        Only a probe that answers exactly False says so; no probe, a probe that raises, or any other answer is not."""
        if self.host_write or self._unconfined is None:
            return False
        try:
            return self._unconfined() is False
        except Exception:   # noqa: BLE001 - a probe that fails cannot say the sandbox holds
            return False

    @staticmethod
    def _not_the_agents(targets: Sequence[str]) -> str:
        """'' when the agent's user neither owns nor can write any of `targets`, else the first that it does."""
        uid = agent_uid()
        for target in targets:
            st = os.stat(target)
            if uid == 0 or st.st_uid == uid or os.access(target, os.W_OK):
                return target
        return ""

    def _distrust(self) -> str:
        """Why this index, or the program that reads it, cannot be trusted ('' when they can)."""
        try:
            index = str(self.index)
            if os.path.realpath(index) != index:
                return f"the index path {index} goes through a link"
            parent = self.index.parent
            files = [index + s for s in ("", "-wal", "-shm") if os.path.lexists(index + s)]
            for name in files:
                st = os.lstat(name)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    return f"{name} is not a plain file with one link, so another name could write it"
            by_sandbox = self._confined() and (not self._within_project(parent) or parent.parent == self.project)
            if not by_sandbox:
                mine = self._not_the_agents(files + [str(parent)])
                if mine:
                    return (f"the agent's user owns or can write {mine}, so the index could have been changed by the "
                            "agent; keep it in a direct subdirectory of the project, or outside it, on a host with the "
                            "sandbox and a profile that does not write the host, or give it to another user")
            return self._exe_distrust()
        except OSError as exc:
            return f"the index at {self.index} cannot be examined ({type(exc).__name__})"

    def _exe_distrust(self) -> str:
        """Why the program that answers cannot be trusted: it must be the one the zone document recorded, and it and
        its package directory must pass the test (nothing is run)."""
        recorded = self.doc.get("program")
        if not isinstance(recorded, dict) or not isinstance(recorded.get("path"), str) \
                or not isinstance(recorded.get("package"), str):
            return "the zone file does not record the Context Cloud program and its package; run `prismpath agent zones set`"
        real = self.real_exe
        if recorded["path"] != real:
            return f"the Context Cloud program is {real}, not the {recorded['path']} the zone file records; run `prismpath agent zones set`"
        for what, path in (("program", real), ("package", os.path.realpath(recorded["package"]))):
            if self._within_project(Path(path)):
                return f"the Context Cloud {what} {path} is inside the project, where the agent can change it"
        if self._confined():
            return ""
        mine = self._not_the_agents([real, os.path.dirname(real), os.path.realpath(recorded["package"]),
                                     os.path.dirname(os.path.realpath(recorded["package"]))])
        return (f"the agent's user owns or can write {mine}, part of the Context Cloud program") if mine else ""

    # --- the index (read only: which functions a file holds, and the version of it that was indexed)
    def _connect(self, immutable: bool = False):
        mode = "immutable=1" if immutable else "mode=ro"
        return sqlite3.connect(f"file:{self.index}?{mode}", uri=True, timeout=0.05)

    def _index_rows(self, rel: str) -> Optional[Tuple[str, str, List[str]]]:
        # A write protected index in a write protected directory cannot be opened as a WAL database (SQLite must
        # create its -shm file), so it is read as immutable: nothing can be writing it, and a -wal that holds newer
        # rows is left unread, which at worst reads a file as stale (`unknown`).
        for immutable in (False, True):
            try:
                db = self._connect(immutable)
                try:
                    row = db.execute("SELECT module, sha256 FROM files WHERE file = ? AND tier = 'saved'", (rel,)).fetchone()
                    if row is None:
                        return None
                    names = [r[0] for r in db.execute(
                        "SELECT symbol FROM symbols WHERE file = ? AND tier = 'saved' AND symbol_kind IN ('function', 'method')",
                        (rel,))]
                finally:
                    db.close()
            except sqlite3.Error:
                if immutable:
                    return None
                continue
            return row[0], row[1], sorted(set(names))
        return None

    def _index_signature(self) -> str:
        parts = []
        for suffix in ("", "-wal"):
            try:
                st = os.stat(str(self.index) + suffix)
                parts.append(f"{st.st_size}:{st.st_mtime_ns}")
            except OSError:
                parts.append("-")
        return "|".join(parts)

    # --- the cache (a fact per file version, index version and zone file)
    def _cache_path(self) -> Path:
        return self.home / CACHE_FILE

    def _cache_get(self, key: str) -> Optional[str]:
        try:
            value = json.loads(self._cache_path().read_text(encoding="utf-8")).get(key)
        except Exception:   # noqa: BLE001
            return None
        return value if value in ("none", "likely", "certain") else None

    def _cache_put(self, key: str, value: str) -> None:
        try:
            try:
                table = json.loads(self._cache_path().read_text(encoding="utf-8"))
                table = table if isinstance(table, dict) else {}
            except Exception:   # noqa: BLE001
                table = {}
            table[key] = value
            if len(table) > 5000:
                table = {key: value}
            fd, tmp = tempfile.mkstemp(dir=self.home, prefix=CACHE_FILE + ".")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(table, handle)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._cache_path())
        except OSError:
            pass            # a cache that cannot be written only costs the next call its lookup

    # --- one function
    def _function(self, name: str, timeout: float) -> str:
        command = [*program_argv(self.real_exe), "reaches", name, "--json", "--no-color", "--index", str(self.index),
                   "--protected", ",".join(self.protected)]
        try:
            done = self._run(command, capture_output=True, text=True, timeout=max(timeout, 0.001), cwd=str(self.home),
                             env=clean_env(self.home))
            if done.returncode != 0:
                return "unknown"
            certainty = json.loads(done.stdout).get("certainty")
        except Exception:   # noqa: BLE001 - a timeout, a missing program and bad output all say nothing
            return "unknown"
        if not isinstance(certainty, str):
            return "unknown"
        return {"no": "none", "certain": "certain", "likely": "likely"}.get(certainty, "unknown")

    # --- one path
    def reach(self, raw: str, config: Any, budget_s: Optional[float] = None) -> str:
        return self.reach_names(raw, config, budget_s)[0]

    @property
    def required_certainty(self) -> Any:
        return self._required_certainty

    @property
    def engine_agreement(self) -> Any:
        return self._engine_agreement

    def _reading(self, certainty: str) -> str:
        """`zone_reach` for Context Cloud's answer `certainty` (none, likely, certain or unknown) under the point's
        requirements: `none` stays `none`, an answer of the required rank or above that has the engine agreement
        asked reads `protected`, and every other answer reads `unknown`, never `none`. A requirement of N engines is
        met by Context Cloud's own answer and N - 1 others (`1 + _engines() >= N`), so 1 asks nothing more. A point
        with a bad requirement reads `unknown` for every answer."""
        if self.requirement_why:
            return "unknown"
        if certainty == "none":
            return "none"
        if certainty not in ("likely", "certain") or RANK[certainty] < RANK[self._required_certainty]:
            return "unknown"
        return "protected" if 1 + self._engines() >= self._engine_agreement else "unknown"

    @staticmethod
    def _engines() -> int:
        """How many engines other than Context Cloud agree with the answer. `contextcloud reaches --json` names no engine beside its own call
        graph and value flow (each witness edge says `by: call graph` or `by: value flow`, two analyses of one engine),
        and the other engines' answers (Pyrefly, scip-python) sit in the index's `edge_evidence` table, which `reaches`
        does not read. So nothing is reported and this is the restrictive value."""
        return 0

    def certainty_names(self, raw: str, config: Any, budget_s: Optional[float] = None) -> Tuple[str, bool, frozenset]:
        """Context Cloud's answer for the path (`CC_CERTAINTY`), whether it is complete, and the protected names the
        path reaches. An answer is incomplete when some function of the file timed out or errored and the answer is
        `likely`: the function that did not answer could have been `certain`, so `likely` is only a lower bound.
        `unknown` and no names whenever the point distrusts its index or program, has a bad requirement, has no
        `host_path`, or the path is not a Python file of the index; the restrictive value on every error."""
        self.names = frozenset()
        if self.requirement_why or self.why or self._host_path is None:
            self.stats = {"functions": 0, "cached": False, "seconds": 0.0}
            if self.why:
                self.stats["untrusted_index"] = self.why
            if self.requirement_why:
                self.stats["bad_requirement"] = self.requirement_why
            return "unknown", True, frozenset()
        started = time.monotonic()
        budget = self.budget_s if budget_s is None else budget_s
        self.stats = {"functions": 0, "cached": False, "seconds": 0.0}
        try:
            real = Path(os.path.realpath(self._host_path(raw, config)))
            rel = real.relative_to(self.project).as_posix()
            if real.suffix != ".py" or not real.is_file():
                return "unknown", True, frozenset()
            content = real.read_bytes()
        except (ValueError, OSError):
            return "unknown", True, frozenset()
        try:
            certainty, complete = self._file(rel, content, started, budget)
            return certainty, complete, self.names
        finally:
            self.stats["seconds"] = round(time.monotonic() - started, 4)

    def reach_names(self, raw: str, config: Any, budget_s: Optional[float] = None) -> Tuple[str, frozenset]:
        """`reach`, and the protected names of the zone document the path reaches (spec-policy-distribution.md, AF1),
        for `zone_name`. A file that defines protected code names the names that cover it. A file found protected only
        by a lookup of its functions names none, since Context Cloud answers for the protected set as a whole. A path
        whose answer does not meet the point's requirements reads `unknown` and names none."""
        certainty, _complete, names = self.certainty_names(raw, config, budget_s)
        fact = self._reading(certainty)
        if fact != "protected":
            self.names = frozenset()
            return fact, frozenset()
        return fact, names

    def facts(self, change: Change, budget_s: float) -> Evidence:
        """The port's one question: `reach_names` of the change's path, as Evidence. The names are the protected
        names the path reaches; `why` is why the point reads `unknown` when it distrusts its index or program.
        `cc_certainty` is Context Cloud's answer whatever the requirements, so a rule can read a `likely` that
        `zone_reach` did not call protected, except that an incomplete `likely` (a function timed out or errored)
        reads `unknown` there while `zone_reach` still reads it as `likely`; `cc_engine_agreement` is what
        `_engines` says."""
        try:
            certainty, complete, names = self.certainty_names(change.raw_path, change.config, budget_s)
            fact = self._reading(certainty)
            if not complete:
                certainty = "unknown"
            if certainty not in CC_CERTAINTY or fact not in ZONE_REACH:
                raise ValueError("an answer outside the closed lists")
            agreement = self._engines()
            if isinstance(agreement, bool) or not isinstance(agreement, int) or agreement not in CC_ENGINE_AGREEMENT:
                raise ValueError("an agreement outside the closed list")
        except Exception as exc:   # noqa: BLE001 - a point that fails says nothing, which is its restrictive value
            return Evidence(dict(self.restrictive), frozenset(), f"the point failed ({type(exc).__name__})", {})
        why = self.requirement_why or self.why or ("no function that names the host path was supplied" if self._host_path is None else "")
        return Evidence({"zone_reach": fact, "cc_certainty": certainty, "cc_engine_agreement": agreement},
                        names if fact == "protected" else frozenset(), why, dict(self.stats))

    def _file(self, rel: str, content: bytes, started: float, budget: float) -> Tuple[str, bool]:
        """(Context Cloud's answer for one file, whether it is complete). `certain` for a file that defines protected
        code, else the strongest answer of its functions (`certain`, then `likely`), `unknown` when one function said
        so or timed out and none was `certain` or `likely`, and `none` only when every function answered `no`. A
        `likely` beside a function that timed out or errored is incomplete (that function could be `certain`); a
        `certain` is complete (nothing raises it). Only a complete answer is cached."""
        rows = self._index_rows(rel)
        if rows is None:
            return "unknown", True                # a file the index does not hold
        module, indexed_sha, names = rows
        if indexed_sha != _sha256(content):
            return "unknown", True                # the index holds another version of this file
        if _covered(module, self.protected) or any(_covered(n, self.protected) for n in names):
            self.names = _covering(module, self.protected).union(*(_covering(n, self.protected) for n in names))
            return "certain", True                # the file defines protected code, no lookup needed
        key = _sha256("|".join((self._index_signature(), self.zones_sha, indexed_sha, rel)).encode())
        cached = self._cache_get(key) if self._confined() else None      # elsewhere the agent can write the cache
        if cached is not None:
            self.stats.update(cached=True)
            return cached, True
        self.stats["functions"] = len(names)
        if not names:
            return "none", True
        deadline = started + budget
        answers: List[str] = []
        timed_out = False
        pool = ThreadPoolExecutor(max_workers=min(WORKERS, len(names)))
        try:
            futures = [pool.submit(self._function, n, max(deadline - time.monotonic(), 0.001)) for n in names]
            done, pending = wait(futures, timeout=max(deadline - time.monotonic(), 0.0))
            answers = [f.result() for f in done]
            timed_out = bool(pending)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        incomplete = timed_out or "unknown" in answers or len(answers) < len(names)
        if "certain" in answers:
            fact, complete = "certain", True
        elif "likely" in answers:
            fact, complete = "likely", not incomplete
        elif incomplete:
            self.stats["timed_out"] = timed_out
            return "unknown", True
        else:
            fact, complete = "none", True
        if complete and self._confined():
            self._cache_put(key, fact)
        return fact, complete

    def warm(self, files: Optional[Iterable[str]] = None, budget_s: float = 600.0) -> Dict[str, str]:
        """The fact of every Python file of the index (or of `files`, relative paths), computed and cached, so a hook
        later answers from the cache. Returns {file: fact}."""
        if files is None:
            db = sqlite3.connect(f"file:{self.index}?mode=ro", uri=True)
            try:
                files = [r[0] for r in db.execute("SELECT file FROM files WHERE tier = 'saved' ORDER BY file")]
            finally:
                db.close()
        facts: Dict[str, str] = {}
        for rel in files:
            facts[rel] = self.reach(str(self.project / rel), SimpleNamespace(workspace=self.project), budget_s)
        return facts
