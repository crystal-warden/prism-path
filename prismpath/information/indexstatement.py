# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""What the manifest keys of Context Cloud pin, decided for A5 (the A4a review, F12).

1. The protected set. `policy.cc_protected` and the `protected` list of the `policy.zones` file are two signed
   statements of one set. The set in force is their union (`effective_protected`). Neither wins and neither can take
   a name away from the other: a name either one lists is protected. A manifest that wants a name unprotected writes it
   in neither. Union is the safe reading because a signed statement that protects a name is a claim the owner made, and
   the one error that matters, a protected name read as unprotected, needs one of two signed statements to be ignored.

2. The index. `policy.cc_index` pins the sha256 of an index STATEMENT (`IndexStatement`), a small file that names the
   index and the program that reads it, and not of the SQLite file. The index is rebuilt as the code changes, so a pin
   of its bytes would need a new signature at every build and would be stale as soon as the agent edits a file, which
   is the freshness the index is checked for by the per file hashes it already holds (a file whose sha256 differs from
   the index's row reads `unknown`) and by `policy.cc_freshness_s`, a maximum age (`fresh`). What a signature can pin
   and stays true across builds is where the index is and what is allowed to read it, which is what the statement says.
   The statement does not make the index trusted: `ContextCloudZones._distrust` still refuses an index the agent could
   have written. It stops the zone file, the index path and the program being swapped without a new signature.

The statement is a canonical JSON object with exactly these keys: `format` ("prismpath.cc-index/1"), `schema`
("contextcloud-sqlite/1": the tables `files` and `symbols` the point reads), `index` (a path under the project, no
`..`) and `program` (`path` and `package`, absolute, as the zone file records them). This module imports nothing from
prismpath.
"""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Tuple

FORMAT = "prismpath.cc-index/1"
SCHEMA = "contextcloud-sqlite/1"
KEYS = ("format", "index", "program", "schema")
MAX_BYTES = 4096


def effective_protected(zones: Iterable[str], manifest: Iterable[str]) -> Tuple[str, ...]:
    """The protected names in force: those of the zone file together with those of `policy.cc_protected`."""
    return tuple(sorted({n for n in (*zones, *manifest) if isinstance(n, str) and n}))


@dataclass(frozen=True)
class IndexStatement:
    index: str                 # relative to the project
    program_path: str
    program_package: str


def _problem(text: str) -> ValueError:
    return ValueError(f"the index statement {text}")


def parse(data: bytes) -> IndexStatement:
    """The statement `data` writes, or ValueError saying what is wrong with it."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_BYTES:
        raise _problem(f"is not at most {MAX_BYTES} bytes")
    try:
        doc = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _problem("is not JSON text")
    if not isinstance(doc, dict) or tuple(sorted(doc)) != KEYS:
        raise _problem(f"does not have exactly the keys {', '.join(KEYS)}")
    if doc["format"] != FORMAT:
        raise _problem(f"is not format {FORMAT}")
    if doc["schema"] != SCHEMA:
        raise _problem(f"is not schema {SCHEMA}")
    index, program = doc["index"], doc["program"]
    if not isinstance(index, str) or not index or os.path.isabs(index) or "\\" in index \
            or any(part in ("", ".", "..") for part in index.split("/")):
        raise _problem("names an index that is not a plain path under the project")
    if not isinstance(program, dict) or tuple(sorted(program)) != ("package", "path") \
            or not all(isinstance(program[k], str) and os.path.isabs(program[k]) for k in program):
        raise _problem("names a program without an absolute path and package")
    return IndexStatement(index, program["path"], program["package"])


def matches(statement: IndexStatement, zone_doc: Mapping[str, Any]) -> Optional[str]:
    """None when the zone document's index and program are the ones the statement names, else why not."""
    try:
        project, index = str(zone_doc["project"]), str(zone_doc["index"])
        program = zone_doc.get("program")
        if index != os.path.join(project, *statement.index.split("/")):
            return f"the zone file's index is {index}, not {statement.index} under the project"
        if not isinstance(program, dict) or program.get("path") != statement.program_path \
                or program.get("package") != statement.program_package:
            return "the zone file records another Context Cloud program than the statement names"
    except (KeyError, TypeError):
        return "the zone file does not say where its project and index are"
    return None


def schema_ok(index_path: str) -> bool:
    """The index has the tables and columns the point reads (nothing is written; the file is opened read only)."""
    needs = {"files": {"file", "module", "sha256", "tier"}, "symbols": {"file", "symbol", "symbol_kind", "tier"}}
    try:
        db = sqlite3.connect(f"file:{index_path}?mode=ro", uri=True, timeout=0.05)
        try:
            for table, columns in needs.items():
                have = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
                if not columns <= have:
                    return False
        finally:
            db.close()
    except sqlite3.Error:
        return False
    return True


def fresh(index_path: str, max_age_s: int, now: float) -> bool:
    """The index (or its write ahead log, the newer of the two) was written at most `max_age_s` seconds before `now`.
    An index that cannot be examined is not fresh."""
    newest = None
    for suffix in ("", "-wal"):
        try:
            mtime = os.stat(index_path + suffix).st_mtime
        except OSError:
            continue
        newest = mtime if newest is None else max(newest, mtime)
    return newest is not None and 0 <= now - newest <= max_age_s
