# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Pytest suite for portable JavaScript conformance runners and their Python generators.

Executes each JavaScript conformance runner using Node and asserts exit code zero.
Validates that each generator reproduces the corresponding committed JSON corpus byte for byte.
"""
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

NODE_EXECUTABLE = shutil.which("node")
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
PORTABLE_DIRECTORY = REPOSITORY_ROOT / "portable"
CONFORMANCE_DIRECTORY = PORTABLE_DIRECTORY / "conformance"

RUNNERS_LIST = [
    "run_capability.mjs",
    "run_reach.mjs",
    "run_level_m.mjs",
    "run_p1_conformance.mjs",
]


def _load_generator(module_filename: str):
    # Dynamic loader is required because portable directory sits outside the python package root.
    module_path = PORTABLE_DIRECTORY / module_filename
    module_name = module_filename.removesuffix(".py")
    spec_object = importlib.util.spec_from_file_location(module_name, module_path)
    module_object = importlib.util.module_from_spec(spec_object)
    spec_object.loader.exec_module(module_object)
    return module_object


@pytest.mark.skipif(NODE_EXECUTABLE is None, reason="node not installed - portable runners untested here")
@pytest.mark.parametrize("runner_filename", RUNNERS_LIST)
def test_portable_runner_exits_zero(runner_filename: str):
    # Node execution of each runner certifies that the JavaScript kernel passes the frozen conformance corpus.
    runner_path = PORTABLE_DIRECTORY / runner_filename
    process_result = subprocess.run(
        [NODE_EXECUTABLE, str(runner_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert process_result.returncode == 0, (
        f"Runner {runner_filename} failed with return code {process_result.returncode}:\n"
        f"STDOUT:\n{process_result.stdout}\nSTDERR:\n{process_result.stderr}"
    )


def test_capability_generator_reproduces_committed_json():
    # Regeneration from the Python reference implementation must match committed bytes to prevent specification drift.
    generator_module = _load_generator("gen_capability.py")
    generated_data = generator_module.generate()
    generated_text = json.dumps(generated_data, indent=2)
    committed_bytes = (CONFORMANCE_DIRECTORY / "capability.json").read_bytes()
    assert generated_text.encode("utf-8") == committed_bytes, (
        "gen_capability.py output differs from committed capability.json file"
    )


def test_reach_generator_reproduces_committed_json():
    # Regeneration from the Python reference implementation must match committed bytes to prevent specification drift.
    generator_module = _load_generator("gen_reach.py")
    generated_data = generator_module.generate()
    generated_text = json.dumps(generated_data, indent=2)
    committed_bytes = (CONFORMANCE_DIRECTORY / "reach.json").read_bytes()
    assert generated_text.encode("utf-8") == committed_bytes, (
        "gen_reach.py output differs from committed reach.json file"
    )


def test_level_m_generator_reproduces_committed_json():
    # Regeneration from the Python reference implementation must match committed bytes to prevent specification drift.
    generator_module = _load_generator("gen_level_m.py")
    generated_data = generator_module.generate()
    generated_text = json.dumps(generated_data, indent=2)
    committed_bytes = (CONFORMANCE_DIRECTORY / "level_m.json").read_bytes()
    assert generated_text.encode("utf-8") == committed_bytes, (
        "gen_level_m.py output differs from committed level_m.json file"
    )
