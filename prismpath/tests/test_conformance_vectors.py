# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The FROZEN conformance vectors (portable/conformance/) — the kernel spec as data.

Two guarantees, enforced on every test run:
  1. NO SILENT PYTHON DRIFT — regenerating the vectors from the live reference implementation
     must reproduce the committed files byte-for-byte. A semantics change in predicates.py or
     engine.py shows up here as a diff; if intentional, re-run gen_conformance.py and commit
     the new vectors (that diff IS the spec-change review).
  2. The JavaScript port's side of this check lives in the research repository with the port.
"""
import json
import warnings
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
CONF = REPO / "portable" / "conformance"


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
