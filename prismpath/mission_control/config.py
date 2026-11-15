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

    proj: str = "/tmp/demo"                                   # the project the console follows at startup
    # Auto-discovery: MC follows whichever sprint is live, whoever started it (control tab / CLI / hand).
    scan: str = "/tmp/*/status.json"                          # glob(s), os.pathsep-separated
    registry: str = "~/.prismpath/sprints.json"               # sprints self-announce here on start
    # A factory, not a value: the state directory depends on the environment at the time Settings is
    # built, which is what lets a deployment or a test set XDG_STATE_HOME before the console reads it.
    audit_path: str = field(default_factory=lambda: os.path.join(default_state_directory(), "mission_audit.log"))
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
        self.proj = os.path.abspath(self.proj)
        self.registry = os.path.expanduser(self.registry)

    @classmethod
    def from_environment(cls, environ=None):
        """The defaults above, each overridable by its MC_ environment variable."""
        environ = os.environ if environ is None else environ
        fallback = cls()
        return cls(
            proj=environ.get("MC_PROJ", fallback.proj),
            scan=environ.get("MC_SCAN", fallback.scan),
            registry=environ.get("MC_REGISTRY", fallback.registry),
            audit_path=environ.get("MC_AUDIT", fallback.audit_path),
            host=environ.get("MC_HOST", fallback.host),
            port=int(environ.get("MC_PORT", str(fallback.port))),
            max_file_bytes=int(environ.get("MC_MAX_FILE_BYTES", str(fallback.max_file_bytes))),
            max_tree_entries=int(environ.get("MC_MAX_TREE_ENTRIES", str(fallback.max_tree_entries))),
            heartbeat_stale_s=int(environ.get("MC_HEARTBEAT_STALE_S", str(fallback.heartbeat_stale_s))),
        )


SETTINGS = Settings.from_environment()
