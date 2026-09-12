# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Helper for locating repo-only files in pytest test suites."""

from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def repo_file(*parts: str | Path) -> Path:
    path = REPO_ROOT.joinpath(*parts)
    if not path.exists():
        pytest.skip(f"{path} is only in a repo checkout", allow_module_level=True)
    return path
