# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every path, port and cap Mission Control reads, in one place.

A deployment that sets nothing gets defaults that work from an installed wheel: the console's own
files go to the platform state directory, never beside the package, because the package lives in
site-packages after a pip install and that tree is not the console's to write. The environment
variables are the ones documented in docs/guides/mission-control-api.md. One `Settings` instance is
shared by the whole package and read through the object at call time, so a test or an embedder can
change one field and every job sees it.
"""
import os
from dataclasses import dataclass, field

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))      # prismpath/mission_control/
PRISM_DIR = os.path.dirname(PACKAGE_DIR)                      # prismpath/, where the package data lives


def default_state_directory() -> str:
    """Where the console keeps its own files, the audit log above all.

    Linux and macOS: $XDG_STATE_HOME/prismpath, falling back to ~/.local/state/prismpath. Windows:
    %LOCALAPPDATA%\\prismpath. The directory is created on first write by the audit log itself.
    MC_AUDIT overrides the audit log path outright; this only supplies the default."""
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        base = os.environ["LOCALAPPDATA"]
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "prismpath")


@dataclass
class Settings:
    """The console's configuration. Mutable on purpose: one shared instance, read at call time."""

    # The console's own directory: the audit log, the session token file and the default project live
    # here. A factory, not a value: the state directory depends on the environment at the time Settings
    # is built, which is what lets a deployment or a test set XDG_STATE_HOME before the console reads it.
    state_dir: str = field(default_factory=default_state_directory)
    # The project the console follows at startup. Empty means `<state_dir>/project`, a directory of the
    # console's own, never a shared one such as /tmp that another local user can create first.
    proj: str = ""
    # Auto-discovery: MC follows whichever sprint is live, whoever started it (control tab / CLI / hand).
    # Sprints self-announce in the registry; `scan` adds status.json globs (os.pathsep-separated) and is
    # empty unless the launch names some.
    scan: str = ""
    registry: str = "~/.prismpath/sprints.json"               # sprints self-announce here on start
    audit_path: str = ""                                      # empty means <state_dir>/mission_audit.log
    # Directories a project may be selected from besides the discovered sprints (MC_EVIDENCE,
    # os.pathsep-separated). An assessor names the copy of the evidence they were handed.
    evidence_roots: list = field(default_factory=list)
    # The posture. Read only mounts no route that controls a sprint or writes a file (MC_READ_ONLY=1 or
    # --read-only); the default on loopback is the full console.
    read_only: bool = False
    # SECURITY: loopback only. MC can start and stop the swarm and edit flow files, never LAN reachable.
    host: str = "127.0.0.1"
    port: int = 9109
    # Resource caps for the single-user control plane. Flow files and checkpoints are small; refuse anything
    # larger so a runaway read/write can't exhaust memory, and bound the file listing on a pathological tree.
    max_file_bytes: int = 4 * 1024 * 1024                     # 4 MiB
    max_tree_entries: int = 5000
    # How long a status.json heartbeat stays live. Discovery and the running check must agree on this, or
    # the sprint list and the status view disagree about the same run.
    heartbeat_stale_s: int = 120
    # Where the package is installed, so the rest of the code asks the settings object for a path
    # rather than recomputing one from __file__. Facts, not environment configuration.
    package_dir: str = PACKAGE_DIR
    prism_dir: str = PRISM_DIR

    def __post_init__(self):
        self.state_dir = os.path.abspath(os.path.expanduser(self.state_dir))
        self.proj = os.path.abspath(os.path.expanduser(self.proj or os.path.join(self.state_dir, "project")))
        self.audit_path = self.audit_path or os.path.join(self.state_dir, "mission_audit.log")
        self.registry = os.path.expanduser(self.registry)
        self.evidence_roots = [os.path.abspath(os.path.expanduser(root)) for root in self.evidence_roots if root]

    @classmethod
    def from_environment(cls, environ=None):
        """The defaults above, each overridable by its MC_ environment variable."""
        environ = os.environ if environ is None else environ
        fallback = cls(state_dir=environ.get("MC_STATE_DIR") or default_state_directory())
        return cls(
            state_dir=fallback.state_dir,
            proj=environ.get("MC_PROJ", fallback.proj),
            scan=environ.get("MC_SCAN", fallback.scan),
            registry=environ.get("MC_REGISTRY", fallback.registry),
            audit_path=environ.get("MC_AUDIT", fallback.audit_path),
            evidence_roots=environ.get("MC_EVIDENCE", "").split(os.pathsep),
            read_only=environ.get("MC_READ_ONLY", "").strip().lower() in ("1", "true", "yes", "on"),
            host=environ.get("MC_HOST", fallback.host),
            port=int(environ.get("MC_PORT", str(fallback.port))),
            max_file_bytes=int(environ.get("MC_MAX_FILE_BYTES", str(fallback.max_file_bytes))),
            max_tree_entries=int(environ.get("MC_MAX_TREE_ENTRIES", str(fallback.max_tree_entries))),
            heartbeat_stale_s=int(environ.get("MC_HEARTBEAT_STALE_S", str(fallback.heartbeat_stale_s))),
        )


SETTINGS = Settings.from_environment()
