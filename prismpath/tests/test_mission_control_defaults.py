# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mission Control's installed defaults: the audit log lives under the platform state directory, never
beside the package; MC_AUDIT still overrides it; and a sprint launch runs the installed module under the
console's own interpreter with the followed project as the working directory. The launch is exercised
for real with a stub module on the path, not by inspecting an argv string."""
import json
import os
import sys
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")

from prismpath.mission_control import config as mc_config  # noqa: E402


def test_default_audit_path_is_under_the_state_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("MC_AUDIT", raising=False)
    settings = mc_config.Settings.from_environment()
    expected = tmp_path / "state" / "prismpath" / "mission_audit.log"
    assert Path(settings.audit_path) == expected
    assert not Path(settings.audit_path).is_relative_to(Path(mc_config.PACKAGE_DIR))


def test_default_audit_path_falls_back_to_local_state(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    if os.name != "nt":
        assert Path(mc_config.default_state_directory()) == tmp_path / ".local" / "state" / "prismpath"


def test_explicit_override_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("MC_AUDIT", str(tmp_path / "elsewhere.log"))
    settings = mc_config.Settings.from_environment()
    assert settings.audit_path == str(tmp_path / "elsewhere.log")


def test_sprint_launch_runs_the_installed_module_in_the_project(monkeypatch, tmp_path):
    """A stub prismpath.orchestration.run_sprint on a private path records the interpreter and the
    working directory it was started with; the real launcher must pick sys.executable and the project."""
    from prismpath.mission_control import launch
    from prismpath.ledgers import audit_log
    from prismpath.mission_control import audit

    project = tmp_path / "proj"
    project.mkdir()
    stub_root = tmp_path / "stub"
    (stub_root / "prismpath" / "orchestration").mkdir(parents=True)
    (stub_root / "prismpath" / "__init__.py").write_text("")
    (stub_root / "prismpath" / "orchestration" / "__init__.py").write_text("")
    (stub_root / "prismpath" / "orchestration" / "run_sprint.py").write_text(
        "import json, os, sys\n"
        "json.dump({'executable': sys.executable, 'cwd': os.getcwd()}, open(os.path.join(os.environ['SPRINT_PROJ'], 'launched.json'), 'w'))\n")
    monkeypatch.setenv("PYTHONPATH", str(stub_root))
    monkeypatch.setattr(audit, "LOG", audit_log.AuditLog(str(tmp_path / "audit.log")))
    state = {"proc": None, "proj": str(project), "cfg": {}, "pinned": True}
    result = launch.start_sprint({"proj": str(project)}, state)
    assert result["ok"], result
    state["proc"].wait(timeout=30)
    launched = json.loads((project / "launched.json").read_text())
    assert launched["executable"] == sys.executable
    assert Path(launched["cwd"]).resolve() == project.resolve()
