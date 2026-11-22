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
                             "docs/DICTIONARY.md", ".github/workflows/ci.yml", ".github/workflows/publish.yml",
                             ".github/workflows/publish-crates.yml"}]
    assert held == []


def test_the_export_is_not_edited_and_names_a_commit(exported):
    assert provenance.check_hashes(exported) == []


def test_the_export_has_no_dangling_link_and_carries_what_features_need(exported):
    assert check_boundary.check_repository(exported) == []


def test_the_export_carries_its_crate_fixtures_byte_identical(exported):
    assert fixture_sync.check(exported) == []


def test_the_overlay_replaces_research_files_and_nothing_else_is_rewritten(exported):
    overlaid = {path for path, _ in export_clean.overlay_files()} | {"README.md", ".github/workflows/publish.yml", ".github/workflows/publish-crates.yml"}
    for path in provenance.tree.tracked_paths(exported):
        if path in overlaid or path in ("PROVENANCE.md", "SHA256SUMS"):
            continue
        assert (exported / path).read_bytes() == (export_clean.ROOT / path).read_bytes(), path


def test_the_version_is_research_s_and_publish_is_carried(exported):
    import re
    version = re.search(r'^version = "([^"]*)"', (export_clean.ROOT / "pyproject.toml").read_text(), re.M).group(1)
    assert f'version = "{version}"' in (exported / "pyproject.toml").read_text()
    assert (exported / ".github" / "workflows" / "publish.yml").read_bytes() == (export_clean.ROOT / "tools" / "mirror_publish.yml").read_bytes()


def test_the_crates_publish_workflow_is_carried_gated_and_pinned(exported):
    import re
    text = (exported / ".github" / "workflows" / "publish-crates.yml").read_text()
    assert text.encode() == (export_clean.ROOT / "tools" / "mirror_crates_publish.yml").read_bytes()
    assert re.search(r"^on:\n  workflow_dispatch:\n\npermissions:", text, re.M)   # by hand only, nothing else triggers it
    assert "environment: crates-io" in text and "id-token: write" in text
    uses = re.findall(r"uses: (\S+)", text)
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u) for u in uses), uses
    order = re.search(r"CRATES: (.+)", text).group(1).split()
    assert order == ["prismpath-rs", "prismpath-telemetry-rs", "prismpath-hotswap-rs", "prismpath-preflight"]


def test_bytecode_beside_an_overlay_file_is_not_exported(tmp_path, monkeypatch):
    overlay = tmp_path / export_clean.OVERLAY_DIR / "tools"
    (overlay / "__pycache__").mkdir(parents=True)
    (overlay / "kept.py").write_text("# kept\n")
    (overlay / "__pycache__" / "kept.cpython-312.pyc").write_bytes(b"bytecode")
    (overlay / "stray.pyc").write_bytes(b"bytecode")
    monkeypatch.setattr(export_clean, "ROOT", tmp_path)
    assert [path for path, _ in export_clean.overlay_files()] == ["tools/kept.py"]


def test_a_new_file_under_an_included_prefix_fails_the_export_until_it_is_listed(tmp_path):
    tracked = export_clean.tracked_files()
    assert export_clean.unlisted(tracked) == []                      # today's tree is fully listed
    new = "docs/design/a-new-research-note.md"
    assert export_clean.unlisted(tracked + [new]) == [new]
    assert export_clean.unlisted(tracked + [new], export_clean.read_manifest() | {new}) == []
    held = ["docs/research/new.md", "tools/arith_lint_new.py", "tools/export_manifest.txt"]
    assert export_clean.unlisted(tracked + [p for p in held if p != "tools/arith_lint_new.py"]) == []


def test_the_export_script_names_an_unlisted_file_and_writes_nothing(tmp_path):
    repo = tmp_path / "repo"
    (repo / "tools").mkdir(parents=True)
    for name in ("export_clean.py", "provenance.py", "tree.py", "export_manifest.txt", "__init__.py"):
        src = export_clean.ROOT / "tools" / name
        if src.exists():
            (repo / "tools" / name).write_bytes(src.read_bytes())
    (repo / "docs" / "design").mkdir(parents=True)
    (repo / "docs" / "design" / "unlisted.md").write_text("research\n")
    git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)
    git("init", "-q")
    git("add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x")
    out = tmp_path / "out"
    run = subprocess.run([sys.executable, str(repo / "tools" / "export_clean.py"), "--out", str(out)], capture_output=True, text=True)
    assert run.returncode != 0
    assert "docs/design/unlisted.md" in run.stderr and "export_manifest.txt" in run.stderr
    assert not out.exists()


CRATES_YML = export_clean.ROOT / "tools" / "mirror_crates_publish.yml"


def _already_published_check(tmp_path, code):
    """Run the workflow's check step with curl and cargo stubbed, the index answering `code` ("000" is a network error)."""
    import re
    step = re.search(r"Require that no crate version is already on crates\.io\n\s+run: \|\n((?:          .*\n)+)", CRATES_YML.read_text()).group(1)
    stubs = tmp_path / "bin"
    stubs.mkdir(exist_ok=True)
    (stubs / "curl").write_text('#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && f=$2; shift; done\n: > "$f"\necho -n "$CODE"\n')
    (stubs / "cargo").write_text('#!/bin/sh\necho \'{"packages":[{"name":"prismpath-rs","version":"1.0.0"},{"name":"prismpath-telemetry-rs","version":"1.0.0"},'
                                 '{"name":"prismpath-hotswap-rs","version":"1.0.0"},{"name":"prismpath-preflight","version":"1.0.0"}]}\'\n')
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    env = {"PATH": f"{stubs}:/usr/bin:/bin", "CODE": code, "CRATES": "prismpath-rs prismpath-telemetry-rs"}
    return subprocess.run(["bash", "-c", step], cwd=tmp_path, env=env, capture_output=True, text=True)


def test_only_a_404_from_the_crates_index_means_not_published(tmp_path):
    assert _already_published_check(tmp_path, "404").returncode == 0
    for code in ("429", "500", "503", "000"):
        run = _already_published_check(tmp_path, code)
        assert run.returncode != 0 and f"answered {code}" in run.stderr, code


def test_case_099_neither_the_export_tree_nor_the_built_packages_hold_the_dev_build_marker(exported, tmp_path):
    """case_099: D4. prismpath/_dev_build.py makes a dev build, so the export leaves it out, and the sdist and
    the wheel `python -m build` makes from that sdist leave it out too."""
    import tarfile
    import zipfile
    marker = "prismpath/_dev_build.py"
    assert (export_clean.ROOT / marker).exists() and not export_clean.is_included(marker)
    assert not (exported / marker).exists()
    pytest.importorskip("build")
    subprocess.run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(tmp_path), str(export_clean.ROOT)],
                   check=True, capture_output=True)
    (sdist,), (wheel,) = tmp_path.glob("*.tar.gz"), tmp_path.glob("*.whl")
    with tarfile.open(sdist) as archive:
        sdist_names = archive.getnames()
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
    assert "prismpath/distribution/devbuild.py" in wheel_names
    assert not [name for name in sdist_names + wheel_names if name.endswith("_dev_build.py")]
