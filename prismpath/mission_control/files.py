# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The filesystem surface: containment against the followed project, the kinds of file the authoring
interface may edit, and the file listing.

Containment is the whole security story of the edit router, so it lives on its own and is called
before any read or write of a caller-supplied path. The authoring interface edits flow documents and
their fixture tables and nothing else (plan section 3.4): a fixture is a `.tests.md` file, a flow is any
other Markdown document, and every other file is `other`, listed so the process owner can read it and
never written by the console. A flow manifest beside a flow (`<flow>.md.manifest.json` and `.sig`) is
`other`, so the console cannot write the signature that authorizes a flow.
"""
import os

from .config import SETTINGS

EDITABLE_SUFFIXES = (".md",)                 # flows, and fixtures by their name (FIXTURE_SUFFIX)
FIXTURE_SUFFIX = ".tests.md"
# Listed for reading beside the flows: manifests, lockfiles, routing data and notes.
LISTED_SUFFIXES = EDITABLE_SUFFIXES + (".json", ".jsonl", ".txt", ".yaml", ".yml", ".sig")
SKIPPED_DIRS = (".git", "tools", "__pycache__", "last-good")
KINDS = ("flow", "fixture", "other")


def file_kind(path: str) -> str:
    """`fixture` for a fixture table, `flow` for any other Markdown document, `other` for the rest."""
    name = os.path.basename(path)
    if name.endswith(FIXTURE_SUFFIX):
        return "fixture"
    return "flow" if name.endswith(EDITABLE_SUFFIXES) else "other"


def not_editable(rel: str):
    """Why the authoring interface may not write the project relative path `rel`, or None when it may: a
    file that is not a flow or a fixture, or one under a directory the listing skips or a hidden name,
    which the editor never shows."""
    parts = [part for part in os.path.normpath(rel).replace("\\", "/").split("/") if part not in ("", ".")]
    if any(part.startswith(".") or part in SKIPPED_DIRS for part in parts):
        return "hidden"
    if file_kind(rel) == "other":
        return "not-editable"
    return None


def _real(path):
    """The path with every symlink resolved, for the part of it that exists. A path that does not exist
    yet resolves through its nearest existing ancestor, so a symlinked parent directory cannot carry a
    new file outside the project."""
    return os.path.realpath(path)


def is_contained(path, base):
    """True if `path` is `base` itself or nested inside it, after resolving symlinks on both sides.

    A lexical check is not containment: a symlink inside the project that points outside it has an
    inside looking name and an outside target. The comparison is made on real paths, and for a path
    that does not exist yet on the real path of its parent, so a new file cannot be written through a
    linked directory either."""
    root = _real(base)
    candidate = os.path.abspath(path)
    if os.path.lexists(candidate):
        resolved = _real(candidate)
    else:
        resolved = os.path.join(_real(os.path.dirname(candidate)), os.path.basename(candidate))
    return resolved == root or resolved.startswith(root + os.sep)


def safe_path(proj, rel):
    """Resolve `rel` against `proj`, refusing any path that escapes the project tree once symlinks
    are followed. Returns the real path, so the caller reads and writes the file the check looked at."""
    candidate = os.path.abspath(os.path.join(proj, rel))
    if not is_contained(candidate, proj):
        raise ValueError("path escapes project")
    if os.path.lexists(candidate):
        return _real(candidate)
    return os.path.join(_real(os.path.dirname(candidate)), os.path.basename(candidate))


def file_tree(proj):
    """Every listed file under the followed project with its kind (`flow`, `fixture` or `other`), bounded
    by `SETTINGS.max_tree_entries`. Only `flow` and `fixture` entries are editable."""
    out = []
    for dirpath, dirnames, filenames in os.walk(proj):
        dirnames[:] = [dirname for dirname in dirnames if dirname not in SKIPPED_DIRS]
        for filename in sorted(filenames):
            if len(out) >= SETTINGS.max_tree_entries:
                return out                        # bound the listing on a pathological tree
            if not filename.endswith(LISTED_SUFFIXES) or filename.startswith("."):
                continue
            rel = os.path.relpath(os.path.join(dirpath, filename), proj)
            try:
                stat_result = os.stat(os.path.join(dirpath, filename))
            except OSError:
                continue
            # float mtime (sub-second): a same-size rewrite within one wall-clock second must
            # still change the signature, or the editor re-shows stale content.
            out.append({"path": rel, "size": stat_result.st_size, "mtime": stat_result.st_mtime,
                        "kind": file_kind(rel)})
    return sorted(out, key=lambda entry: entry["path"])
