# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The product tree is what the research repository makes, and it passes the checks the product ships.
Research only: the export is held back from the tree this tests."""
import subprocess
import sys

import pytest

from tools import check_boundary, export_clean, fixture_sync, provenance


@pytest.fixture(scope="module")
def exported(tmp_path_factory):
    out = tmp_path_factory.mktemp("export")
    # the working tree is what is under test, so it need not be committed; the commit named is HEAD's
    subprocess.run([sys.executable, str(export_clean.ROOT / "tools" / "export_clean.py"), "--out", str(out), "--allow-dirty"],
                   check=True, capture_output=True)
    return out


def test_no_held_path_is_in_the_export(exported):
    held = [path for path in provenance.tree.tracked_paths(exported) if not export_clean.is_included(path)
            and path not in {"README.md", "PROVENANCE.md", "SHA256SUMS", "pyproject.toml", "MANIFEST.in",
                             "docs/DICTIONARY.md", ".github/workflows/ci.yml", ".github/workflows/publish.yml"}]
    assert held == []


def test_the_export_is_not_edited_and_names_a_commit(exported):
    assert provenance.check_hashes(exported) == []


def test_the_export_has_no_dangling_link_and_carries_what_features_need(exported):
    assert check_boundary.check_repository(exported) == []


def test_the_export_carries_its_crate_fixtures_byte_identical(exported):
    assert fixture_sync.check(exported) == []


def test_the_overlay_replaces_research_files_and_nothing_else_is_rewritten(exported):
    overlaid = {path for path, _ in export_clean.overlay_files()} | {"README.md", ".github/workflows/publish.yml"}
    for path in provenance.tree.tracked_paths(exported):
        if path in overlaid or path in ("PROVENANCE.md", "SHA256SUMS"):
            continue
        assert (exported / path).read_bytes() == (export_clean.ROOT / path).read_bytes(), path


def test_the_version_is_research_s_and_publish_is_carried(exported):
    import re
    version = re.search(r'^version = "([^"]*)"', (export_clean.ROOT / "pyproject.toml").read_text(), re.M).group(1)
    assert f'version = "{version}"' in (exported / "pyproject.toml").read_text()
    assert (exported / ".github" / "workflows" / "publish.yml").read_bytes() == (export_clean.ROOT / "tools" / "mirror_publish.yml").read_bytes()
