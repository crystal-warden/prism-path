# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The tree a tool is looking at: its root, and the files in it.

A tool takes `--repo DIR` and defaults to the tree it is part of. In the product repository that tree is
an export of the research repository, so it is the product tree itself. In the research repository it is
research, which is not a product tree, and the tools that judge a product tree are pointed at an export.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def tracked_paths(repo_root: Path = REPO_ROOT) -> list[str]:
    """Every file of the tree: git's tracked files where it is a checkout, every file where it is an
    unpacked export."""
    if (repo_root / ".git").exists():
        output = subprocess.check_output(["git", "-C", str(repo_root), "ls-files"], text=True)
        return sorted(line for line in output.splitlines() if line)
    found = []
    for directory, subdirectories, files in os.walk(repo_root):
        subdirectories[:] = [name for name in subdirectories if name != ".git"]
        for name in files:
            found.append((Path(directory) / name).relative_to(repo_root).as_posix())
    return sorted(found)


def is_product_tree(repo_root: Path = REPO_ROOT) -> bool:
    """True for an export: it carries PROVENANCE.md and not the exporter."""
    return (repo_root / "PROVENANCE.md").exists() and not (repo_root / "tools" / "export_clean.py").exists()
