# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every GitHub workflow file parses as YAML with jobs in it. A workflow that does not parse never starts, so its
required checks never report and a pull request waits on them with nothing saying why."""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from prismpath.tests._repo import REPO_ROOT  # noqa: E402

WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
if not WORKFLOWS:   # skipped here so the acceptance skip budget can name this file
    pytest.skip("the workflows are only in a repo checkout", allow_module_level=True)


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_the_workflow_parses_and_has_jobs(path: Path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict) and isinstance(doc.get("jobs"), dict) and doc["jobs"], path.name
