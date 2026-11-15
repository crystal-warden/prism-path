# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The carried compiler reproduces the frozen references byte for byte: each of the thirteen regression
flows compiles into a temporary image and sidecar equal to the fixture pair, and the incident_severity
flow compiles to the historical image. The references are read, never written; a mismatch is a
compiler change to explain, not a fixture to regenerate."""
import subprocess
import sys
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent
FIXTURES = PACKAGE / "tests" / "fixtures" / "compiler"


def _reference_stems():
    return sorted(path.stem for path in FIXTURES.glob("*.ppt"))


def _source_flow(stem: str) -> Path:
    return PACKAGE / (stem.replace("__", "/") + ".md")


def _compile(flow: Path, out_dir: Path, stem: str):
    image = out_dir / f"{stem}.ppt"
    names = out_dir / f"{stem}.names.json"
    completed = subprocess.run([sys.executable, "-m", "prismpath.kernel.ppt_compile", str(flow), "-o", str(image), "--json", str(names)],
                               capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    return image.read_bytes(), names.read_bytes()


def test_there_are_thirteen_regression_pairs():
    assert len(_reference_stems()) == 13
    for stem in _reference_stems():
        assert (FIXTURES / f"{stem}.names.json").exists(), f"{stem} has no sidecar"
        assert _source_flow(stem).exists(), f"{stem}: source flow missing from the package"


@pytest.mark.parametrize("stem", _reference_stems())
def test_regression_pair_reproduces(stem, tmp_path):
    image, names = _compile(_source_flow(stem), tmp_path, stem)
    assert image == (FIXTURES / f"{stem}.ppt").read_bytes(), f"{stem}: image bytes differ from the frozen reference"
    assert names == (FIXTURES / f"{stem}.names.json").read_bytes(), f"{stem}: names sidecar differs from the frozen reference"


def test_historical_image_reproduces(tmp_path):
    image, _ = _compile(PACKAGE / "gallery" / "incident_severity" / "incident_severity.md", tmp_path, "historical")
    assert image == (FIXTURES / "anchored" / "incident_severity.ppt").read_bytes()
