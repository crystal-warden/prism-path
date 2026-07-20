"""Build-flow resume-from-ledger (Area 6, Slice 3).

A KG sprint records a git proof per gate-green node (Slice 1). If its `.kg.json` is wiped
(SPRINT_FRESH), progress would be lost — but the ledger (a separate bare repo) survives. This
tests that a fresh sprint pointed at a prior run (SPRINT_LEDGER_RUN) re-marks the proven nodes
done from git and restarts at the first UNPROVEN node instead of rebuilding.
"""
import importlib.util
import os
import subprocess
import sys

import pytest

# This exercises run_sprint.py (the control plane), which imports `requests` — absent from the
# minimal kernel CI env. Skip cleanly there; it runs in the full dev env.
pytest.importorskip("requests", reason="control-plane test: run_sprint needs requests")

from prismpath.ledger import Ledger

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
  {"id": "auth",  "section": "auth",  "depends_on": [],               "produces": ["auth.luau"]},
  {"id": "store", "section": "store", "depends_on": ["auth"],         "produces": ["store.luau"]},
  {"id": "ui",    "section": "ui",    "depends_on": ["auth","store"], "produces": ["ui.luau"]}
]}
```
"""


def _load(monkeypatch, proj, spec_file, ledger_dir, run_id):
    monkeypatch.setenv("SPRINT_NUDGE", "build the thing")
    monkeypatch.setenv("SPRINT_PROJ", str(proj))
    monkeypatch.setenv("SPRINT_SPEC_FILE", str(spec_file))
    monkeypatch.setenv("SPRINT_FRESH", "0")
    monkeypatch.setenv("SPRINT_LEDGER", "1")
    monkeypatch.setenv("SPRINT_LEDGER_RUN", run_id)
    monkeypatch.setenv("PRISMPATH_LEDGER_DIR", str(ledger_dir))
    # run_sprint reads ARCH at import; without SPRINT_ARCH it falls back to a hardcoded relative path
    # (prismpath/APP_ARCHITECTURE.md) that doesn't resolve in this flat layout, so make the load hermetic
    # by pointing at the repo's real arch file — otherwise this file passes only when a sibling test
    # happens to leak SPRINT_ARCH into the environment, and fails in isolation.
    monkeypatch.setenv("SPRINT_ARCH",
                       os.path.join(os.path.dirname(__file__), "..", "APP_ARCHITECTURE.md"))
    sys.modules.pop("run_sprint_uut", None)
    path = os.path.join(os.path.dirname(__file__), "..", "run_sprint.py")
    spec = importlib.util.spec_from_file_location("run_sprint_uut", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _setup(tmp_path):
    proj = tmp_path / "myproj"
    proj.mkdir()
    spec_file = proj / "INTEGRATION.md"
    spec_file.write_text(SPEC)
    return proj, spec_file, tmp_path / "ledger"


def test_run_id_honors_resume_env(tmp_path, monkeypatch):
    proj, spec_file, ledger_dir = _setup(tmp_path)
    m = _load(monkeypatch, proj, spec_file, ledger_dir, "01HFIXED")
    led = m._ledger()
    assert led.run_id == "01HFIXED"
    assert led.ref == "refs/prismpath/runs/01HFIXED"           # resumes the SAME proof chain


def test_apply_ledger_done_is_pure(tmp_path, monkeypatch):
    proj, spec_file, ledger_dir = _setup(tmp_path)
    m = _load(monkeypatch, proj, spec_file, ledger_dir, "01HX")
    kg = {"nodes": [{"id": "a"}, {"id": "b", "status": "done"}, {"id": "c"}]}
    assert m._apply_ledger_done(kg, {"a", "c"}) == 2        # b already done -> not recounted
    assert {n["id"]: n.get("status") for n in kg["nodes"]} == {"a": "done", "b": "done", "c": "done"}


def test_kg_resumes_at_first_unproven_node(tmp_path, monkeypatch):
    proj, spec_file, ledger_dir = _setup(tmp_path)
    run_id = "01HRESUME"
    # a prior sprint proved auth + store, then its .kg.json was wiped; the ledger survives
    led = Ledger(flow="myproj", run_id=run_id, state_dir=ledger_dir)
    led.commit_unit("auth", files={"auth.luau": "-- auth"})
    led.commit_unit("store", files={"store.luau": "-- store"})

    m = _load(monkeypatch, proj, spec_file, ledger_dir, run_id)
    assert not os.path.exists(proj / "INTEGRATION.kg.json")   # fresh: no local progress record

    m._kg_seed_from_ledger()

    status = {n["id"]: n.get("status") for n in m._kg_load()["nodes"]}
    assert status["auth"] == "done" and status["store"] == "done"
    assert status.get("ui") != "done"
    # kg_next now selects UI (first pending whose depends_on are all proven), NOT auth
    assert m.kg_next({})["_kg_node"] == "ui"


def test_no_ledger_commits_means_no_seed(tmp_path, monkeypatch):
    proj, spec_file, ledger_dir = _setup(tmp_path)
    m = _load(monkeypatch, proj, spec_file, ledger_dir, "01HEMPTY")
    m._kg_seed_from_ledger()                                  # empty ledger -> nothing marked
    status = {n["id"]: n.get("status") for n in m._kg_load()["nodes"]}
    assert all(s != "done" for s in status.values())
    assert m.kg_next({})["_kg_node"] == "auth"               # starts from the beginning
