# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every optional extra the package can ask for is declared by pyproject.toml, which the wheel does not
ship, so the check lives in the repository maintenance suite."""
import tomllib
from pathlib import Path

from prismpath import extras

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def test_every_extra_module_maps_to_an_extra_pyproject_declares():
    with open(PYPROJECT, "rb") as handle:
        declared = tomllib.load(handle)["project"]["optional-dependencies"]
    for module, (extra, package) in extras.EXTRAS.items():
        assert extra in declared, module
        assert any(req.split()[0].split(";")[0].strip() == package for req in declared[extra]), module
