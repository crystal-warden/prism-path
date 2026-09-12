# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Build-flow resume-from-ledger (Area 6, Slice 3).

A KG sprint records a git proof per gate-green node (Slice 1). If its `.kg.json` is wiped,
progress would be lost - but the ledger (a separate bare repo) survives. This
tests that a fresh sprint pointed at a prior run (SPRINT_LEDGER_RUN) re-marks the proven nodes
done from git and restarts at the first UNPROVEN node instead of rebuilding.
"""
import os
import subprocess

import pytest

# This exercises run_sprint.py (the control plane), which imports requests - absent from the
# minimal kernel CI env. Skip cleanly there; it runs in the full dev env.
pytest.importorskip("requests", reason="control-plane test: run_sprint needs requests")

from prismpath.ledgers.ledger import Ledger
from prismpath.orchestration.run_sprint import (
    SprintConfig,
    _apply_ledger_done,
    _kg_load,
    _kg_seed_from_ledger,
    _ledger,
    kg_next,
)

HAS_GIT = subprocess.run(["git", "--version"], capture_output=True).returncode == 0
pytestmark = pytest.mark.skipif(not HAS_GIT, reason="git not available")

SPEC = """# Integration

## auth
Build the auth module.

## store
Build the store module.

## ui
Build the ui module.

```json
{"nodes": [
  {"id": "auth",  "section": "auth",  "depends_on": [],               "produces": ["auth.js"]},
  {"id": "store", "section": "store", "depends_on": ["auth"],         "produces": ["store.js"]},
  {"id": "ui",    "section": "ui",    "depends_on": ["auth","store"], "produces": ["ui.js"]}
]}
```
"""


def _make_config(proj_dir, spec_file_path, ledger_dir, run_identifier) -> SprintConfig:
    return SprintConfig(
        proj=str(proj_dir),
        nudge="build the thing",
        spec_file=str(spec_file_path),
        ledger=True,
        ledger_run_id=run_identifier,
        ledger_dir=str(ledger_dir),
        arch_file=os.path.join(os.path.dirname(__file__), "..", "nudges", "APP_ARCHITECTURE.md"),
    )


def _setup(tmp_path):
    proj_dir = tmp_path / "myproj"
    proj_dir.mkdir()
    spec_file_path = proj_dir / "INTEGRATION.md"
    spec_file_path.write_text(SPEC, encoding="utf-8")
    return proj_dir, spec_file_path, tmp_path / "ledger"


def test_run_id_honors_resume_env(tmp_path):
    proj_dir, spec_file_path, ledger_dir = _setup(tmp_path)
    config = _make_config(proj_dir, spec_file_path, ledger_dir, "01HFIXED")
    ledger_instance = _ledger(config)
    assert ledger_instance.run_id == "01HFIXED"
    assert ledger_instance.ref == "refs/prismpath/runs/01HFIXED"


def test_apply_ledger_done_is_pure(tmp_path):
    proj_dir, spec_file_path, ledger_dir = _setup(tmp_path)
    config = _make_config(proj_dir, spec_file_path, ledger_dir, "01HX")
    kg_data = {"nodes": [{"id": "a"}, {"id": "b", "status": "done"}, {"id": "c"}]}
    assert _apply_ledger_done(kg_data, {"a", "c"}) == 2
    assert {node["id"]: node.get("status") for node in kg_data["nodes"]} == {"a": "done", "b": "done", "c": "done"}


def test_kg_resumes_at_first_unproven_node(tmp_path):
    proj_dir, spec_file_path, ledger_dir = _setup(tmp_path)
    run_identifier = "01HRESUME"
    ledger_instance = Ledger(flow="myproj", run_id=run_identifier, state_dir=ledger_dir)
    ledger_instance.commit_unit("auth", files={"auth.js": "// auth"})
    ledger_instance.commit_unit("store", files={"store.js": "// store"})

    config = _make_config(proj_dir, spec_file_path, ledger_dir, run_identifier)
    assert not os.path.exists(proj_dir / "INTEGRATION.kg.json")

    _kg_seed_from_ledger(config)

    status_dict = {node["id"]: node.get("status") for node in _kg_load(config)["nodes"]}
    assert status_dict["auth"] == "done"
    assert status_dict["store"] == "done"
    assert status_dict.get("ui") != "done"
    assert kg_next({}, config)["_kg_node"] == "ui"


def test_no_ledger_commits_means_no_seed(tmp_path):
    proj_dir, spec_file_path, ledger_dir = _setup(tmp_path)
    config = _make_config(proj_dir, spec_file_path, ledger_dir, "01HEMPTY")
    _kg_seed_from_ledger(config)
    status_dict = {node["id"]: node.get("status") for node in _kg_load(config)["nodes"]}
    assert all(node_status != "done" for node_status in status_dict.values())
    assert kg_next({}, config)["_kg_node"] == "auth"
