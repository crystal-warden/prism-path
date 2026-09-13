# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The filesystem surface: containment against the followed project, and the editable file listing.

Containment is the whole security story of the edit router, so it lives on its own and is called
before any read or write of a caller-supplied path.
"""
import os

from .config import SETTINGS

EDITABLE_SUFFIXES = (".js", ".mjs", ".html", ".css", ".json", ".md", ".txt", ".pdf")
SKIPPED_DIRS = (".git", "tools", "__pycache__", "last-good")


def is_contained(path, base):
    """True if `path` is `base` itself or nested inside it (the sandbox containment check)."""
    resolved = os.path.abspath(path)
    root = os.path.abspath(base)
    return resolved == root or resolved.startswith(root + os.sep)


def safe_path(proj, rel):
    """Resolve `rel` against `proj`, refusing any path that escapes the project tree."""
    resolved = os.path.abspath(os.path.join(proj, rel))
    if not is_contained(resolved, proj):
        raise ValueError("path escapes project")
    return resolved


def file_tree(proj):
    """Every editable file under the followed project, bounded by `SETTINGS.max_tree_entries`."""
    out = []
    for dirpath, dirnames, filenames in os.walk(proj):
        dirnames[:] = [dirname for dirname in dirnames if dirname not in SKIPPED_DIRS]
        for filename in sorted(filenames):
            if len(out) >= SETTINGS.max_tree_entries:
                return out                        # bound the listing on a pathological tree
            if not filename.endswith(EDITABLE_SUFFIXES) or filename.startswith("."):
                continue
            rel = os.path.relpath(os.path.join(dirpath, filename), proj)
            try:
                stat_result = os.stat(os.path.join(dirpath, filename))
            except OSError:
                continue
            # float mtime (sub-second): a same-size rewrite within one wall-clock second must
            # still change the signature, or the editor re-shows stale content.
            out.append({"path": rel, "size": stat_result.st_size, "mtime": stat_result.st_mtime})
    return sorted(out, key=lambda entry: entry["path"])
