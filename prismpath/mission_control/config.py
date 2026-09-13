# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every path, port and cap Mission Control reads, in one place.

The field defaults are the values the console has always run with, so a deployment that sets nothing
behaves exactly as before; the environment variables are the ones documented in
docs/guides/mission-control-api.md. One `Settings` instance is shared by the whole package and read
through the object at call time, so a test or an embedder can change one field and every job sees it.
"""
import os
from dataclasses import dataclass

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))      # prismpath/mission_control/
PRISM_DIR = os.path.dirname(PACKAGE_DIR)                      # prismpath/  (the old "HERE")
REPO_ROOT = os.path.dirname(PRISM_DIR)                        # repo root (run_sprint cwd)


@dataclass
class Settings:
    """The console's configuration. Mutable on purpose: one shared instance, read at call time."""

    proj: str = "/tmp/demo"                                   # the project the console follows at startup
    # Auto-discovery: MC follows whichever sprint is live, whoever started it (control tab / CLI / hand).
    scan: str = "/tmp/*/status.json"                          # glob(s), os.pathsep-separated
    registry: str = "~/.prismpath/sprints.json"               # sprints self-announce here on start
    audit_path: str = os.path.join(PRISM_DIR, "mission_audit.log")
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
    repo_root: str = REPO_ROOT

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
