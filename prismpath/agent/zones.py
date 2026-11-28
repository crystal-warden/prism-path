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
The directory of the zone document's `index` is therefore a control path like `.claude/` (`control_paths_of`, a
function of the verified document alone, so every point built from it names the same paths, an unusable one too): the
hook refuses a write, delete or mutating command onto it with the control-write cause (classifier.py takes the point's
`control_paths` as control paths), and both per call sandbox backends hold it read only (controls.discover `extra`,
passed to the runner as `--control-path`, and bound by the launcher, which creates a missing one empty as it does
`.claude/`, so a script cannot make it). A directory is named with a trailing slash. Context Cloud's own indexing runs
outside the agent's sandbox and still writes it. When the index file sits directly in the project root the directory
cannot be held read only without holding the whole project, so only the index file and its -wal and -shm siblings are
control paths, and the permission rule below applies to it.
The index holds facts the policy relies on, so its content must begin after protection does: `prismpath agent zones
set` signs the zone file, then deletes the index and rebuilds it with `contextcloud index`, or refuses when Context
Cloud is absent and an index exists.

The point answers `unknown` for every path, and says why (`why`), when the agent could have written the index, or the
`contextcloud` program that reads it. The agent writes only the workspace: the hook refuses a write outside it
(`path_scope`) and the per call sandbox mounts the rest of the host read only, which also keeps the recorded policy and
the zone file out of its reach. That holds only where this host has the per call sandbox (Linux,
sandbox_hook.supported) and the recorded policy's profile does not write the host (`host_write`, passed in by
`information_point`): Landlock cannot hold a control path read only under a `host_write` profile, and the hook's cache
file, which the profile then lets the agent write, is neither read nor written. Where that holds, the index is trusted
when it lies outside the project, or when its directory is a direct child of the project root (a deeper one could be
renamed away and made again beside the bound directory). In every other case (no sandbox, `host_write`, an index
directly in the root or in a deeper directory) it is trusted by permissions only: the agent's user must neither own the
index, its existing -wal and -shm, and the directory that holds them (an owner can change the mode back), nor have write
access to them (`os.access`). So on a host where one user runs the agent and owns the files, those cases read
`unknown`. Whatever the route, the index and its existing siblings must be regular files with one link (a hard link
elsewhere writes through a read only bind), and the path must not go through a link. The executable (`$CONTEXTCLOUD`
or the first `contextcloud` on the PATH) is tested the same way on its resolved real path: inside the project it is
never trusted, outside it it is trusted where the sandbox holds, and otherwise by the permission rule on the file and
its directory; it runs, as the real path that was tested and not the name it was found by (by its own interpreter with `-I` when its
shebang names one), with the hook's config directory as its working directory, not the workspace, and in a fixed
environment with no PYTHON* variable (`clean_env`), so a PYTHONPATH inside the project shadows nothing. The code that answers lives in Context Cloud's package, which an editable
install may put inside the project, so `zones set` finds the program's real path and the real path of the
`contextcloud` package directory (by running the program's own interpreter once, `-I`, outside the workspace) and
records both in the signed zone document (`program`). At hook time, with nothing run, the program's real path must be
the recorded one, and both it and the package directory get the test above (inside the project is never trusted); a
zone document without them reads `unknown`. At hook time the package's files are not walked (its directory and the one above are what the permission rule looks at),
but `zones set` walks the whole package once and refuses when the sandbox does not hold and the agent's user owns or can
write any file or directory below it, or when it is inside the project (`package_tree_problem`). The cache (`zones-cache.json`) is read and written only where the sandbox holds
(`_confined`), since otherwise the agent can write it. An index that cannot be examined is not trusted. Running as root
counts as able to write.

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
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from prismpath.information import contextcloud
from prismpath.information.contextcloud import (CACHE_FILE, DEFAULT_BUDGET_S, clean_env, contextcloud_executable,
                                                control_paths_of, program_argv)
from prismpath.ports.information import Change, Evidence

ZONE_FORMAT = "prismpath.zones/1"
ATTESTATION_FORMAT = "prismpath.zones.attestation/1"
ZONE_DOMAIN = b"prismpath.zones/1\x00"
ZONES_FILE = "zones.json"
ATTESTATION_FILE = "zones.attestation.json"
MAX_NAMES = 10000
MAX_NAME = 512
ANSWERS = ("none", "protected", "unknown")


class ZoneError(Exception):
    """A zone file that cannot be made, read or trusted."""


class _Fixed:
    name = "fixed"
    fields = {"zone_reach": ANSWERS}
    restrictive = {"zone_reach": "unknown"}
    control_paths: Tuple[str, ...] = ()

    def __init__(self, answer: str, why: str):
        self.answer, self.why = answer, why

    def reach(self, raw: str, config: Any = None) -> str:
        return self.answer

    def reach_names(self, raw: str, config: Any = None) -> Tuple[str, frozenset]:
        """`reach` and the protected names the path reaches, none known for a fixed answer."""
        return self.answer, frozenset()

    def facts(self, change: Change, budget_s: float) -> Evidence:
        return Evidence({"zone_reach": self.answer}, frozenset(), self.why, {})

    def __repr__(self) -> str:
        return f"<zones {self.answer}: {self.why}>"


NO_ZONES = _Fixed("none", "no zone is declared")
UNKNOWN_ZONES = _Fixed("unknown", "no information point")


def fixed(answer: str) -> "_Fixed":
    """A point that answers `answer` for every path (for tests and the recorded inputs)."""
    if answer not in ANSWERS:
        raise ZoneError(f"{answer!r} is not one of {ANSWERS}")
    return _Fixed(answer, "a fixed answer")


def unusable(why: str, control_paths: Sequence[str] = ()) -> "_Fixed":
    """The point of a declared zone file that cannot be used: it says `unknown` for every path. `control_paths` are
    those of the verified zone document, if there was one, which stay control paths whether the point works or not."""
    point = _Fixed("unknown", why)
    point.control_paths = tuple(control_paths)
    return point


# ------------------------------------------------------------------------------------------------ the zone file
def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def zone_document(protected: Iterable[str], project: Path, index: Optional[Path], policy_image: bytes,
                  program: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    names = sorted({name for name in protected})
    if not names or len(names) > MAX_NAMES:
        raise ZoneError(f"a zone file names between 1 and {MAX_NAMES} protected names, not {len(names)}")
    for name in names:
        if not isinstance(name, str) or not name or len(name) > MAX_NAME or any(c.isspace() or c == "," for c in name):
            raise ZoneError(f"{name!r} is not a dotted name (no space, no comma, at most {MAX_NAME} characters)")
    project = Path(os.path.realpath(project))
    index = Path(os.path.realpath(index)) if index is not None else project / ".contextcloud" / "index.sqlite"
    doc = {"format": ZONE_FORMAT, "index": str(index), "policy_sha256": _sha256(policy_image),
           "project": str(project), "protected": names}
    if program is not None:
        doc["program"] = {"package": str(program["package"]), "path": str(program["path"])}
    return doc


def package_tree_problem(package: str, project: Path, confined: bool) -> str:
    """Why the package directory cannot be trusted by `zones set`, or '': inside the project, or, where the sandbox does
    not hold (`confined` false), any directory or file below it that the agent's user owns or can write."""
    real = os.path.realpath(package)
    if Path(real) == project or project in Path(real).parents:
        return f"the Context Cloud package {real} is inside the project, where the agent can change it"
    if confined:
        return ""
    uid = contextcloud.agent_uid()
    for here, dirs, files in os.walk(real):
        for name in [here] + [os.path.join(here, n) for n in dirs + files]:
            try:
                st = os.lstat(name)
            except OSError:
                continue
            if uid == 0 or st.st_uid == uid or (not stat.S_ISLNK(st.st_mode) and os.access(name, os.W_OK)):
                return (f"the agent's user owns or can write {name} in the Context Cloud package, and nothing confines "
                        "the agent here, so the package could be changed by it")
    return ""


def find_program(exe: str, home: Path, run=subprocess.run) -> Dict[str, str]:
    """{"path", "package"}: the real path of the `contextcloud` program and of its package directory, found by running
    the program's own interpreter once (`-I`, with the config directory as working directory, so nothing of the
    workspace is imported). The interpreter is the shebang of the program, else the `python` beside it."""
    real = os.path.realpath(exe)
    interpreter = None
    try:
        with open(real, "rb") as handle:
            first = handle.readline(512).decode("utf-8", "replace").strip()
        if first.startswith("#!"):
            words = first[2:].split()
            if words and os.path.basename(words[0]) != "env":
                interpreter = words[0]
    except OSError as exc:
        raise ZoneError(f"the Context Cloud program {real} cannot be read ({type(exc).__name__})") from exc
    if interpreter is None:
        for name in ("python", "python3"):
            if os.access(os.path.join(os.path.dirname(real), name), os.X_OK):
                interpreter = os.path.join(os.path.dirname(real), name)
                break
    if interpreter is None:
        raise ZoneError(f"the interpreter of the Context Cloud program {real} cannot be found")
    code = "import contextcloud, os; print(os.path.dirname(os.path.realpath(contextcloud.__file__)))"
    try:
        done = run([interpreter, "-I", "-c", code], capture_output=True, text=True, timeout=60, cwd=str(home),
                   env=clean_env(home))
    except (OSError, subprocess.SubprocessError) as exc:
        raise ZoneError(f"the Context Cloud package could not be located ({type(exc).__name__})") from exc
    package = done.stdout.strip()
    if done.returncode != 0 or not package or not os.path.isabs(package):
        raise ZoneError("the Context Cloud package could not be located: " + " ".join(done.stderr.split())[:200])
    return {"path": real, "package": package}


def sign(home: Path, doc: Dict[str, Any]) -> None:
    """Record `doc` in the agent's config directory, signed with the authority key that signed the policy."""
    from prismpath.agent import commands
    from prismpath.onion import keys as onion_keys
    from prismpath.kernel import canon2
    key_path = commands._key_paths(home, "authority")[0]
    if not key_path.is_file():
        raise ZoneError(f"no authority key at {key_path}; run `prismpath agent init`")
    data = canon2.dumps(doc) + b"\n"
    signer = onion_keys.load_signer(str(key_path))
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
    from prismpath.distribution.adapters import agent_home
    from prismpath.hotswap import policy_pack
    from prismpath.kernel import canon2
    if agent_home.is_distributed(home):
        return _load_distributed(home, policy_image, workspace)
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


LOCAL_SETTINGS = "zones.local.json"     # a distributed home's own setting: the project, its index, the program


def set_local(home: Path, project: Path, index: Optional[Path], program: Mapping[str, str]) -> Dict[str, Any]:
    """Record a distributed home's own zone setting: the project, its index and the Context Cloud program
    `find_program` found. The protected names are the committed `agent.zones`, never this file's."""
    import json
    project = Path(os.path.realpath(project))
    index = Path(os.path.realpath(index)) if index is not None else project / ".contextcloud" / "index.sqlite"
    settings = {"index": str(index), "program": {"package": str(program["package"]), "path": str(program["path"])},
                "project": str(project)}
    fd, tmp = tempfile.mkstemp(dir=home, prefix=LOCAL_SETTINGS + ".")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(settings, handle, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, home / LOCAL_SETTINGS)
    return settings


def _load_distributed(home: Path, policy_image: bytes, workspace: Optional[Path]) -> Optional[Dict[str, Any]]:
    """The zone document of a home that follows a stream: the protected names are the committed `agent.zones`
    artifact (spec-policy-distribution.md, section 3), checked again on this load, and the project and its index
    are the home's own setting in `zones.local.json`, else the workspace and its default index. No zone artifact
    is no zone. The index stays a control path (`control_paths_of`)."""
    import json
    from prismpath.agent import commands
    from prismpath.distribution import kinds
    try:
        policy, bodies = commands.load_distributed(home)
    except commands.AgentError as exc:
        raise ZoneError(str(exc)) from None
    if policy.image != bytes(policy_image):
        raise ZoneError("the committed release holds another policy than the one deciding")
    if "agent.zones" not in bodies:
        return None
    try:
        names = kinds.read_zones(bodies["agent.zones"])["protected"]
    except kinds.Refused as refused:
        raise ZoneError(f"the committed zone file does not read: {refused}") from None
    settings_path = home / LOCAL_SETTINGS
    program = None
    if settings_path.is_file():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
            project = Path(settings["project"])
            index = Path(settings["index"]) if settings.get("index") else None
            if settings.get("program") is not None:
                program = {"path": str(settings["program"]["path"]), "package": str(settings["program"]["package"])}
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ZoneError(f"{settings_path} does not read ({type(exc).__name__}); run `prismpath agent zones set`") from None
    elif workspace is not None:
        project, index = Path(workspace), None
    else:
        raise ZoneError(f"the home names no project for its zones; run `prismpath agent zones set`")
    doc = zone_document(names, project, index, policy_image, program=program)
    if workspace is not None and os.path.realpath(workspace) != doc["project"]:
        raise ZoneError("the zone file is for another project")
    return doc


def rebuild_index_after_signing(home: Path, doc: Dict[str, Any], sign_now, env: Optional[Mapping[str, str]] = None,
                                timeout_s: float = 3600.0) -> None:
    """Record the zone file (`sign_now()`), and only then make the index: an index that exists before the zone file
    does (or that was written while it was not a control path) is unauthenticated, so it is deleted with its -wal and
    -shm and rebuilt by `contextcloud index`. Raises ZoneError, before anything is recorded or deleted, when an index
    exists and Context Cloud is absent, and after the zone file is recorded when the rebuild fails (the index is then
    missing, which the point reads as `unknown`)."""
    index = Path(doc["index"])
    names = [str(index) + suffix for suffix in ("", "-wal", "-shm")]
    existing = [n for n in names if os.path.lexists(n)]
    exe = contextcloud_executable(env)
    if existing and exe is None:
        raise ZoneError(f"an index exists at {index} and was not built since it became a control path, so it cannot be "
                        "trusted, and Context Cloud is not installed to rebuild it; remove the index or install Context Cloud")
    sign_now()
    if not existing:
        return
    for name in existing:
        os.unlink(name)
    index.parent.mkdir(parents=True, exist_ok=True)
    try:
        done = subprocess.run([*program_argv(os.path.realpath(exe)), "index", doc["project"], "--index", str(index),
                               "--no-color"], capture_output=True, text=True, timeout=timeout_s, cwd=str(home),
                              env=clean_env(home))
    except (OSError, subprocess.SubprocessError) as exc:
        raise ZoneError(f"the zone file is recorded and the old index was removed, but `contextcloud index` could not run "
                        f"({type(exc).__name__}); run it") from exc
    if done.returncode != 0:
        raise ZoneError("the zone file is recorded and the old index was removed, but `contextcloud index` failed "
                        f"({' '.join(done.stderr.split())[:200]}); run it")


def information_point(home: Path, policy_image: bytes, workspace: Path, env: Optional[Mapping[str, str]] = None):
    """The point the hook gives the classifier: no zone file is NO_ZONES; a zone file that does not verify, or
    without Context Cloud or its index, is a point that says `unknown`; otherwise the Context Cloud adapter."""
    try:
        doc = load(home, policy_image, workspace)
    except ZoneError as exc:
        return unusable(str(exc))
    if doc is None:
        return NO_ZONES
    held = control_paths_of(doc)
    exe = contextcloud_executable(env)
    if exe is None:
        return unusable("Context Cloud is not installed (no `contextcloud` on the PATH and no $CONTEXTCLOUD)", held)
    if not Path(doc["index"]).is_file():
        return unusable(f"no Context Cloud index at {doc['index']}; run `contextcloud index`", held)
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
class ContextCloudZones(contextcloud.ContextCloudZones):
    """The Context Cloud point of the agent kind: the point of information/contextcloud.py, given the two things the
    agent kind knows and the information package may not import, how a model's path names a host file
    (`classifier.host_path`) and whether no per call sandbox confines the agent (`_agent_unconfined`)."""

    def __init__(self, doc: Dict[str, Any], home: Path, executable: str, budget_s: float = DEFAULT_BUDGET_S,
                 run=subprocess.run, host_write: bool = False, unconfined=None, host_path=None):
        from prismpath.agent import classifier
        super().__init__(doc, home, executable, budget_s, run, host_write,
                         unconfined=_agent_unconfined if unconfined is None else unconfined,
                         host_path=classifier.host_path if host_path is None else host_path)


def status(home: Path, policy_image: bytes, workspace: Path, env: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """What the hook will do about zones for this workspace, for `prismpath agent zones status`."""
    point = information_point(home, policy_image, workspace, env)
    if point is NO_ZONES:
        return {"declared": False, "point": "none", "detail": "no zone file: nothing is protected"}
    if isinstance(point, _Fixed):
        return {"declared": True, "point": "unknown", "detail": point.why}
    out = {"declared": True, "point": "contextcloud", "protected": point.protected, "index": str(point.index),
           "executable": point.exe, "control_paths": list(point.control_paths),
           "checked": {"program": point.doc.get("program"), "index": str(point.index), "confined": point._confined()}}
    if point.why:
        out.update(point="unknown", detail=point.why)
    return out
