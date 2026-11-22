"""Zones: the owner's protected code, and the one fact of a reading that says whether a change reaches it.

A firewall groups addresses into zones and sets rules between them. Here the zones are the owner's protected
functions, classes and modules (token checks, payments), and a call that changes files gets the reading field
`zone_reach` (prismpath/agent/classifier.py): `none`, `protected` or `unknown`. The policy asks about a change that
reaches a zone, or whose reach is not known, and leaves a change that does not as it was.
The rule protects the resource, whatever the worker that changes it is.

Where the fact comes from. The classifier asks an INFORMATION POINT, an object with `reach(raw_path, config)` that
answers `none`, `protected` or `unknown` for one path. Three points exist.

  NO_ZONES       the owner declared no zone: nothing is protected, so every path is `none` (the default of
                 `Config.for_workspace`, and what the hook installs when `zones.json` does not exist)
  UNKNOWN_ZONES  a zone file is declared and cannot be used (it does not verify, it is bound to another policy or
                 project, or Context Cloud or its index is missing): every path is `unknown`, so the policy asks
  ContextCloudZones  the real adapter: Context Cloud's `contextcloud reaches --json` for each function of the file

The zone file is never inferred. The owner writes the protected names (`prismpath agent zones set`), and the file is
signed with the policy's authority key and bound to the sha256 of the recorded policy, so recording another policy
(or editing the file) makes it unusable until the owner signs it again. A file that does not verify reads `unknown`,
never `none`.

The index is a control path, and the point does not trust one the agent could have written. The agent can write the
workspace, so an index in it (`.contextcloud/` by default) could be edited to claim that protected code reaches nothing.
The directory of the zone document's `index` is therefore a control path like `.claude/` (`control_paths`): the hook
refuses a write, delete or mutating command onto it with the control-write cause (classifier.py takes the point's
`control_paths` as control paths), and both per call sandbox backends hold it read only (controls.discover `extra`,
passed to the runner as `--control-path`, and bound by the launcher). Context Cloud's own indexing runs outside
the agent's sandbox and still writes it. When the index file sits directly in the project root the directory
cannot be held read only without holding the whole project, so only the index file and its -wal and -shm siblings
that exist are control paths, and the next rule applies to it.
The point answers `unknown` for every path, and says why (`why`), when the agent could have written the index. That is
decided from how the other control paths are trusted. The agent writes only the workspace: the hook refuses a write
outside it (`path_scope`) and the per call sandbox mounts the rest of the host read only, which is also what keeps the
recorded policy and the zone file themselves out of its reach. So the index is trusted when this host has the per call
sandbox (Linux, sandbox_hook.supported) and either it lies below a directory strictly inside the project, the control
path above, or it lies outside the project and the recorded policy's sandbox profile does not write the host
(`host_write`, which the caller passes in). In every other case, which is a host with no sandbox (a shell command is
decided and not confined), an index directly in the project root (its directory is writable and a -wal could be
planted), or a profile that writes the host, the agent's user must have no write permission (`os.access`) on the index
file, its -wal and -shm siblings that exist, or the directory that holds them, or the point answers `unknown`. (Context
Cloud itself opens an index read and write, so this last route serves an index that is only read by the point.) An
index path that goes through a link, or one that cannot be examined, is not trusted either. Running as root counts as
able to write.

A path is `protected` when the file defines a protected name (or sits under a protected module), or any function of
the file reaches the protected set with certainty `certain` or `likely`; `unknown` when the file is not a Python
file of the index, the index holds a different version of it (a stale index), a lookup fails or times out, or Context
Cloud says `unknown`; `none` only when every function of the file answered `no`. The file is the unit because a
write names a file and not a line. Code at module level (outside every function) is not a function in Context
Cloud's index, so a change to it is read by the file's functions only.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

ZONE_FORMAT = "prismpath.zones/1"
ATTESTATION_FORMAT = "prismpath.zones.attestation/1"
ZONE_DOMAIN = b"prismpath.zones/1\x00"
ZONES_FILE = "zones.json"
ATTESTATION_FILE = "zones.attestation.json"
CACHE_FILE = "zones-cache.json"
MAX_NAMES = 10000
MAX_NAME = 512
DEFAULT_BUDGET_S = 0.1          # what one path may spend asking Context Cloud before it reads unknown
WORKERS = min(16, os.cpu_count() or 4)     # lookups run side by side: each one is a process start
ANSWERS = ("none", "protected", "unknown")


class ZoneError(Exception):
    """A zone file that cannot be made, read or trusted."""


class _Fixed:
    def __init__(self, answer: str, why: str):
        self.answer, self.why = answer, why

    def reach(self, raw: str, config: Any = None) -> str:
        return self.answer

    def __repr__(self) -> str:
        return f"<zones {self.answer}: {self.why}>"


NO_ZONES = _Fixed("none", "no zone is declared")
UNKNOWN_ZONES = _Fixed("unknown", "no information point")


def fixed(answer: str) -> "_Fixed":
    """A point that answers `answer` for every path (for tests and the recorded inputs)."""
    if answer not in ANSWERS:
        raise ZoneError(f"{answer!r} is not one of {ANSWERS}")
    return _Fixed(answer, "a fixed answer")


def unusable(why: str) -> "_Fixed":
    """The point of a declared zone file that cannot be used: it says `unknown` for every path."""
    return _Fixed("unknown", why)


# ------------------------------------------------------------------------------------------------ the zone file
def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def zone_document(protected: Iterable[str], project: Path, index: Optional[Path], policy_image: bytes) -> Dict[str, Any]:
    names = sorted({name for name in protected})
    if not names or len(names) > MAX_NAMES:
        raise ZoneError(f"a zone file names between 1 and {MAX_NAMES} protected names, not {len(names)}")
    for name in names:
        if not isinstance(name, str) or not name or len(name) > MAX_NAME or any(c.isspace() or c == "," for c in name):
            raise ZoneError(f"{name!r} is not a dotted name (no space, no comma, at most {MAX_NAME} characters)")
    project = Path(os.path.realpath(project))
    index = Path(os.path.realpath(index)) if index is not None else project / ".contextcloud" / "index.sqlite"
    return {"format": ZONE_FORMAT, "index": str(index), "policy_sha256": _sha256(policy_image),
            "project": str(project), "protected": names}


def sign(home: Path, doc: Dict[str, Any]) -> None:
    """Record `doc` in the agent's config directory, signed with the authority key that signed the policy."""
    from prismpath.agent import commands
    from prismpath.hotswap import policy_pack
    from prismpath.kernel import canon2
    key_path = commands._key_paths(home, "authority")[0]
    if not key_path.is_file():
        raise ZoneError(f"no authority key at {key_path}; run `prismpath agent init`")
    data = canon2.dumps(doc) + b"\n"
    signer = policy_pack._load_private(str(key_path))
    statement = canon2.dumps({"format": ATTESTATION_FORMAT, "key_id": commands._key_id(home, "authority"),
                              "sig": signer.sign(ZONE_DOMAIN + data).hex(), "zones_sha256": _sha256(data)}) + b"\n"
    for name, content in ((ZONES_FILE, data), (ATTESTATION_FILE, statement)):
        target = home / name
        fd, tmp = tempfile.mkstemp(dir=home, prefix=name + ".")
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)


def load(home: Path, policy_image: bytes, workspace: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """The verified zone document, None when no zone file exists, ZoneError when one exists and cannot be trusted:
    the signature does not verify under the authority key, it is bound to another policy, or (when `workspace` is
    given) to another project."""
    from prismpath.agent import commands
    from prismpath.hotswap import policy_pack
    from prismpath.kernel import canon2
    path, attestation = home / ZONES_FILE, home / ATTESTATION_FILE
    if not path.exists() and not attestation.exists():
        return None
    try:
        data = path.read_bytes()
        statement = canon2.loads(attestation.read_bytes().rstrip(b"\n"))
        authority, authority_id = policy_pack.load_public(str(commands._key_paths(home, "authority")[1]))
        if (not isinstance(statement, dict) or statement.get("format") != ATTESTATION_FORMAT
                or statement.get("key_id") != authority_id or statement.get("zones_sha256") != _sha256(data)):
            raise ZoneError("the zone file's attestation does not name this file and the authority key")
        authority.verify(bytes.fromhex(statement["sig"]), ZONE_DOMAIN + data)
        doc = canon2.loads(data.rstrip(b"\n"))
    except ZoneError:
        raise
    except Exception as exc:    # noqa: BLE001 - anything unreadable is untrusted
        raise ZoneError(f"the zone file does not verify: {type(exc).__name__}") from exc
    if not isinstance(doc, dict) or doc.get("format") != ZONE_FORMAT or not isinstance(doc.get("protected"), list) \
            or not doc["protected"] or not all(isinstance(n, str) and n for n in doc["protected"]) \
            or not isinstance(doc.get("project"), str) or not isinstance(doc.get("index"), str):
        raise ZoneError("the zone file is not a prismpath.zones/1 document")
    if doc.get("policy_sha256") != _sha256(policy_image):
        raise ZoneError("the zone file is bound to another policy than the recorded one; sign it again")
    if workspace is not None and os.path.realpath(workspace) != doc["project"]:
        raise ZoneError("the zone file is for another project")
    return doc


def contextcloud_executable(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """`$CONTEXTCLOUD`, else `contextcloud` on the PATH, else None (Context Cloud is absent)."""
    env = os.environ if env is None else env
    named = env.get("CONTEXTCLOUD")
    if named:
        return named if os.access(named, os.X_OK) else None
    return shutil.which("contextcloud", path=env.get("PATH"))


def information_point(home: Path, policy_image: bytes, workspace: Path, env: Optional[Mapping[str, str]] = None):
    """The point the hook gives the classifier: no zone file is NO_ZONES; a zone file that does not verify, or
    without Context Cloud or its index, is a point that says `unknown`; otherwise the Context Cloud adapter."""
    try:
        doc = load(home, policy_image, workspace)
    except ZoneError as exc:
        return unusable(str(exc))
    if doc is None:
        return NO_ZONES
    exe = contextcloud_executable(env)
    if exe is None:
        return unusable("Context Cloud is not installed (no `contextcloud` on the PATH and no $CONTEXTCLOUD)")
    if not Path(doc["index"]).is_file():
        return unusable(f"no Context Cloud index at {doc['index']}; run `contextcloud index`")
    return ContextCloudZones(doc, home, exe, host_write=_host_write(home, policy_image))


def _agent_unconfined() -> bool:
    """True where no per call sandbox confines a shell command (not Linux)."""
    from prismpath.agent import sandbox_hook
    return not sandbox_hook.supported()


def _host_write(home: Path, policy_image: bytes) -> bool:
    """Whether the recorded policy's per call sandbox profile writes the host; True when that cannot be told."""
    try:
        from prismpath.agent import sandbox_hook
        return bool(sandbox_hook.profile_for(home, policy_image).host_write)
    except Exception:   # noqa: BLE001 - an unreadable profile is the cautious answer
        return True


# ------------------------------------------------------------------------------------------------ the adapter
def _covered(name: str, protected: Sequence[str]) -> bool:
    """`name` is a protected name, or lies inside a protected module or class."""
    return any(name == p or name.startswith(p + ".") for p in protected)


class ContextCloudZones:
    """The information point that asks Context Cloud (`contextcloud reaches --json`, whose JSON output is described in the Context Cloud repository)."""

    def __init__(self, doc: Dict[str, Any], home: Path, executable: str, budget_s: float = DEFAULT_BUDGET_S,
                 run=subprocess.run, host_write: bool = False):
        self.doc, self.home, self.exe, self.budget_s, self._run = doc, Path(home), executable, budget_s, run
        self.protected: List[str] = list(doc["protected"])
        self.project = Path(doc["project"])
        self.index = Path(doc["index"])
        self.zones_sha = _sha256(json.dumps(doc, sort_keys=True).encode())
        self.stats: Dict[str, Any] = {}
        self.host_write = host_write
        self.why = self._distrust()

    # --- the index is a control path, and must not be one the agent could have written
    @property
    def control_paths(self) -> Tuple[str, ...]:
        """The paths the hook and both sandbox backends hold read only: the index directory when it is strictly
        inside the project, else the index file and its -wal and -shm siblings."""
        parent = self.index.parent
        if self._below_project(parent):
            return (str(parent),)
        return tuple(str(self.index) + s for s in ("", "-wal", "-shm"))

    def _below_project(self, path: Path) -> bool:
        try:
            return path != self.project and path.relative_to(self.project) is not None
        except ValueError:
            return False

    def _within_project(self, path: Path) -> bool:
        return path == self.project or self._below_project(path)

    def _distrust(self) -> str:
        """Why this index cannot be trusted ('' when it can), as the module docstring states."""
        try:
            if os.path.realpath(self.index) != str(self.index):
                return f"the index path {self.index} goes through a link"
            parent = self.index.parent
            if not _agent_unconfined() and (self._below_project(parent) or (
                    not self.host_write and not self._within_project(parent))):
                return ""
            targets = [str(self.index) + s for s in ("", "-wal", "-shm") if os.path.lexists(str(self.index) + s)]
            targets.append(str(parent))
            writable = [t for t in targets if os.access(t, os.W_OK)]
        except OSError as exc:
            return f"the index at {self.index} cannot be examined ({type(exc).__name__})"
        if writable:
            return (f"the agent's user can write {writable[0]}, so the index could have been changed by the agent; "
                    "take its write permission off, or keep it below a directory of the project, or outside it, on a host with the sandbox")
        return ""

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
        command = [self.exe, "reaches", name, "--json", "--no-color", "--index", str(self.index),
                   "--protected", ",".join(self.protected)]
        try:
            done = self._run(command, capture_output=True, text=True, timeout=max(timeout, 0.001))
            if done.returncode != 0:
                return "unknown"
            certainty = json.loads(done.stdout).get("certainty")
        except Exception:   # noqa: BLE001 - a timeout, a missing program and bad output all say nothing
            return "unknown"
        return {"no": "none", "certain": "protected", "likely": "protected"}.get(certainty, "unknown")

    # --- one path
    def reach(self, raw: str, config: Any, budget_s: Optional[float] = None) -> str:
        from prismpath.agent import classifier
        if self.why:
            self.stats = {"functions": 0, "cached": False, "seconds": 0.0, "untrusted_index": self.why}
            return "unknown"
        started = time.monotonic()
        budget = self.budget_s if budget_s is None else budget_s
        self.stats = {"functions": 0, "cached": False, "seconds": 0.0}
        try:
            real = Path(os.path.realpath(classifier.host_path(raw, config)))
            rel = real.relative_to(self.project).as_posix()
            if real.suffix != ".py" or not real.is_file():
                return "unknown"
            content = real.read_bytes()
        except (ValueError, OSError):
            return "unknown"
        try:
            return self._file(rel, content, started, budget)
        finally:
            self.stats["seconds"] = round(time.monotonic() - started, 4)

    def _file(self, rel: str, content: bytes, started: float, budget: float) -> str:
        rows = self._index_rows(rel)
        if rows is None:
            return "unknown"                      # a file the index does not hold
        module, indexed_sha, names = rows
        if indexed_sha != _sha256(content):
            return "unknown"                      # the index holds another version of this file
        if _covered(module, self.protected) or any(_covered(n, self.protected) for n in names):
            return "protected"                    # the file defines protected code, no lookup needed
        key = _sha256("|".join((self._index_signature(), self.zones_sha, indexed_sha, rel)).encode())
        cached = self._cache_get(key)
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


def status(home: Path, policy_image: bytes, workspace: Path, env: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """What the hook will do about zones for this workspace, for `prismpath agent zones status`."""
    point = information_point(home, policy_image, workspace, env)
    if point is NO_ZONES:
        return {"declared": False, "point": "none", "detail": "no zone file: nothing is protected"}
    if isinstance(point, _Fixed):
        return {"declared": True, "point": "unknown", "detail": point.why}
    out = {"declared": True, "point": "contextcloud", "protected": point.protected, "index": str(point.index),
           "executable": point.exe, "control_paths": list(point.control_paths)}
    if point.why:
        out.update(point="unknown", detail=point.why)
    return out
