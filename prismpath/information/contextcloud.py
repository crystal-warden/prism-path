# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Context Cloud information point: whether a change reaches the owner's protected code, asked of Context Cloud.

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
    fields = {"zone_reach": ZONE_REACH}
    restrictive = {"zone_reach": "unknown"}

    def __init__(self, doc: Dict[str, Any], home: Path, executable: str, budget_s: float = DEFAULT_BUDGET_S,
                 run=subprocess.run, host_write: bool = False, unconfined: Optional[Callable[[], bool]] = None,
                 host_path: Optional[Callable[[str, Any], str]] = None):
        self._unconfined, self._host_path = unconfined, host_path
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
        return value if value in ("none", "protected") else None

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
        return {"no": "none", "certain": "protected", "likely": "protected"}.get(certainty, "unknown")

    # --- one path
    def reach(self, raw: str, config: Any, budget_s: Optional[float] = None) -> str:
        return self.reach_names(raw, config, budget_s)[0]

    def reach_names(self, raw: str, config: Any, budget_s: Optional[float] = None) -> Tuple[str, frozenset]:
        """`reach`, and the protected names of the zone document the path reaches (spec-policy-distribution.md, AF1),
        for `zone_name`. A file that defines protected code names the names that cover it. A file found protected only
        by a lookup of its functions names none, since Context Cloud answers for the protected set as a whole."""
        self.names = frozenset()
        if self.why or self._host_path is None:
            self.stats = {"functions": 0, "cached": False, "seconds": 0.0, "untrusted_index": self.why}
            return "unknown", frozenset()
        started = time.monotonic()
        budget = self.budget_s if budget_s is None else budget_s
        self.stats = {"functions": 0, "cached": False, "seconds": 0.0}
        try:
            real = Path(os.path.realpath(self._host_path(raw, config)))
            rel = real.relative_to(self.project).as_posix()
            if real.suffix != ".py" or not real.is_file():
                return "unknown", frozenset()
            content = real.read_bytes()
        except (ValueError, OSError):
            return "unknown", frozenset()
        try:
            return self._file(rel, content, started, budget), self.names
        finally:
            self.stats["seconds"] = round(time.monotonic() - started, 4)

    def facts(self, change: Change, budget_s: float) -> Evidence:
        """The port's one question: `reach_names` of the change's path, as Evidence. The names are the protected
        names the path reaches; `why` is why the point reads `unknown` when it distrusts its index or program."""
        try:
            fact, names = self.reach_names(change.raw_path, change.config, budget_s)
        except Exception as exc:   # noqa: BLE001 - a point that fails says nothing, which is its restrictive value
            return Evidence(dict(self.restrictive), frozenset(), f"the point failed ({type(exc).__name__})", {})
        why = self.why or ("no function that names the host path was supplied" if self._host_path is None else "")
        return Evidence({"zone_reach": fact}, names, why, dict(self.stats))

    def _file(self, rel: str, content: bytes, started: float, budget: float) -> str:
        rows = self._index_rows(rel)
        if rows is None:
            return "unknown"                      # a file the index does not hold
        module, indexed_sha, names = rows
        if indexed_sha != _sha256(content):
            return "unknown"                      # the index holds another version of this file
        if _covered(module, self.protected) or any(_covered(n, self.protected) for n in names):
            self.names = _covering(module, self.protected).union(*(_covering(n, self.protected) for n in names))
            return "protected"                    # the file defines protected code, no lookup needed
        key = _sha256("|".join((self._index_signature(), self.zones_sha, indexed_sha, rel)).encode())
        cached = self._cache_get(key) if self._confined() else None      # elsewhere the agent can write the cache
        if cached is not None:
            self.stats.update(cached=True)
            return cached
        self.stats["functions"] = len(names)
        if not names:
            return "none"
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
        if "protected" in answers:
            fact = "protected"
        elif timed_out or "unknown" in answers:
            self.stats["timed_out"] = timed_out
            return "unknown"
        else:
            fact = "none"
        if self._confined():
            self._cache_put(key, fact)
        return fact

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
