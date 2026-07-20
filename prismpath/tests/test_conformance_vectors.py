"""The FROZEN conformance vectors (portable/conformance/) — the kernel spec as data.

Two guarantees, enforced on every test run:
  1. NO SILENT PYTHON DRIFT — regenerating the vectors from the live reference implementation
     must reproduce the committed files byte-for-byte. A semantics change in predicates.py or
     engine.py shows up here as a diff; if intentional, re-run gen_conformance.py and commit
     the new vectors (that diff IS the spec-change review).
  2. THE PORT CONFORMS — run_vectors.mjs must pass every committed case (skipped without node).
"""
import json
import shutil
import subprocess
import warnings
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CONF = REPO / "portable" / "conformance"
NODE = shutil.which("node")


def _load_generator():
    # the generator lives beside the port (portable/ is not a python package); load it by path
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen_conformance",
                                                  REPO / "portable" / "gen_conformance.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_no_silent_python_drift():
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=SyntaxWarning)
        docs = _load_generator().generate()
    for name, doc in docs.items():
        committed = json.loads((CONF / name).read_text(encoding="utf-8"))
        assert committed == doc, (
            f"{name}: the committed conformance vectors no longer match the live Python "
            f"reference — semantics changed. If intentional, regenerate "
            f"(python portable/gen_conformance.py) and commit the diff.")


@pytest.mark.skipif(NODE is None, reason="node not installed — port conformance untested here")
def test_the_port_passes_the_frozen_vectors():
    p = subprocess.run([NODE, str(REPO / "portable" / "run_vectors.mjs"), str(CONF)],
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, f"port is NON-CONFORMANT:\n{p.stdout[-2000:]}\n{p.stderr[-1000:]}"
    assert "CONFORMANT" in p.stdout
