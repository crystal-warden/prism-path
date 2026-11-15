# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""JSON that is not hashed and not signed stays plain JSON, and a check holds it there: a durable run
checkpoint, the connector's JSONL sink lines and the flow authority's version floor file are written and read
with `canon.plain_dumps`, `plain_load` and `plain_loads`, and they never flow into a hash or a signature.

  1. AT RUN TIME (Python). The document `plain_loads` reads is a `PlainDict`, and every hashing helper of
     `prismpath.canon` refuses a value that holds one (`PlainJSONRefused`). The checkpoint, a sink line and the
     version floor file each read back as one.
  2. IN THE SOURCE (Python and Rust). No function that reads or writes plain JSON also hashes or signs: a
     Python function that calls a `plain_*` helper calls none of the hashing helpers, and a Rust function that
     calls `parse_plain`, `parse_content` or `plain_dumps` names none of the hashing functions.
"""
import ast
import re

import pytest

from prismpath import canon
from prismpath.tests._repo import REPO_ROOT

HASHERS = (canon.canon2_bytes, canon.content_bytes, canon.document_bytes, canon.document_hash,
           canon.signed_message, canon.manifest_hash, canon.tagged)


def _refused(value):
    for helper in HASHERS:
        with pytest.raises(canon.PlainJSONRefused):
            helper(value)


def test_a_document_read_as_plain_json_is_refused_by_every_hashing_helper():
    document = canon.plain_loads('{"version": 1, "state": {"x": 1.5}, "encoding": "canon/2"}')
    assert isinstance(document, canon.PlainDict)
    _refused(document)
    _refused({"wrapped": document})                    # inside a new document too
    _refused([document])
    assert issubclass(canon.PlainJSONRefused, canon.CanonicalError)


def test_what_is_taken_out_of_a_plain_document_is_content_not_the_document():
    document = canon.plain_loads('{"state": {"verdict": "hit", "n": 3}}')
    assert canon.content_bytes(document["state"]) == b'{"n":3,"verdict":"hit"}'
    assert type(canon.loads_content('{"a": 1}')) is dict            # a model's reply is content
    assert isinstance(canon.plain_loads("[1, 2]"), list)


def test_a_durable_checkpoint_reads_back_as_a_plain_document(tmp_path):
    from prismpath.kernel.parser import parse
    from prismpath.ledgers import checkpoint
    flow = tmp_path / "f.md"
    flow.write_text("---\nname: f\nstart: a\n---\n## a\nGo.\n-> b: when ok\n## b\nDone.\n")
    path = tmp_path / "f.ckpt.json"
    checkpoint.run_durable(str(flow), lambda node, instruction, state: {"text": node}, str(path))
    loaded = checkpoint.load_checkpoint(str(path))
    assert isinstance(loaded, canon.PlainDict) and loaded["version"] == checkpoint.CHECKPOINT_VERSION
    _refused(loaded)
    assert parse(flow.read_text()).name == "f"


def test_a_sink_line_and_the_version_floor_are_plain_documents(tmp_path):
    from prismpath.hotswap import flow_authority
    from prismpath.ledgers import ledger_runner
    sink = tmp_path / "out.jsonl"
    assert ledger_runner.upsert_jsonl(sink, {"id": "a", "v": 1.5}, "id")
    line = canon.plain_loads(sink.read_text().strip())
    assert line == {"id": "a", "v": 1.5}
    _refused(line)
    floor_path = tmp_path / "floor.json"
    floor_path.write_text('{"triage": {"version": 3, "flow_sha256": "ab", "manifest_sha256": "cd"}}')
    floor = flow_authority.VersionFloor(str(floor_path))
    assert isinstance(floor.entries, canon.PlainDict)
    _refused(floor.entries)


# ------------------------------------------------------------------ the source

_PLAIN_PY = {"plain_loads", "plain_load", "plain_dumps"}
_HASH_PY = {"canon2_bytes", "content_bytes", "document_bytes", "document_hash", "signed_message", "manifest_hash",
            "sha256", "sha256_hex", "sha256_prefixed", "file_sha256_prefixed", "new", "md5"}


def _called_names(node):
    names = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Attribute):
                names.add(func.attr)
            elif isinstance(func, ast.Name):
                names.add(func.id)
    return names


def _python_sources():
    for top in ("prismpath", "adapters", "integrations"):
        for path in sorted((REPO_ROOT / top).rglob("*.py")):
            rel = path.relative_to(REPO_ROOT).as_posix()
            parts = rel.split("/")
            if "tests" in parts or rel.startswith("prismpath/comparisons/") or rel == "prismpath/canon.py":
                continue
            yield rel, path.read_text(encoding="utf-8")


def test_no_python_function_that_reads_or_writes_plain_json_also_hashes():
    users, violations = set(), []
    for rel, text in _python_sources():
        if not any(name in text for name in _PLAIN_PY):
            continue
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names = _called_names(node)
                if names & _PLAIN_PY:
                    users.add(rel)
                    if names & _HASH_PY:
                        violations.append(f"{rel}:{node.name} calls {sorted(names & _PLAIN_PY)} and {sorted(names & _HASH_PY)}")
        # a module level call counts too
        top = ast.Module(body=[n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))],
                         type_ignores=[])
        if _called_names(top) & _PLAIN_PY:
            users.add(rel)
            if _called_names(top) & _HASH_PY:
                violations.append(f"{rel}: module level")
    assert violations == []
    # the three kinds of document the rule names, and the tools that read telemetry lines, are among the users
    assert {"prismpath/ledgers/checkpoint.py", "prismpath/workers/connector.py", "prismpath/hotswap/flow_authority.py"} <= users


_PLAIN_RS = re.compile(r"\b(parse_plain|parse_content|plain_dumps)\b")
_HASH_RS = re.compile(r"\b(Sha256|canon2_bytes|content_bytes|document_bytes|signed_message|sha256_hex|manifest_hash_of|short_hash)\b")
_FN = re.compile(r"\bfn\s+(\w+)\s*(?:<[^>{]*>)?\s*\(")


def _rust_functions(text):
    """(name, body) for every `fn` with a block body, by brace matching (strings and comments are blanked first)."""
    blank = re.sub(r"'(?:\\.|[^'\\])'", "''", text)           # character literals, one of which is a quote
    blank = re.sub(r'r#"[\s\S]*?"#', '""', blank)                 # raw strings
    blank = re.sub(r'"(?:\\.|[^"\\])*"', '""', blank)
    blank = re.sub(r"//[^\n]*", "", blank)
    out = []
    for match in _FN.finditer(blank):
        brace = blank.find("{", match.end())
        semicolon = blank.find(";", match.end())
        if brace < 0 or (0 <= semicolon < brace):
            continue
        depth, index = 0, brace
        while index < len(blank):
            if blank[index] == "{":
                depth += 1
            elif blank[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        out.append((match.group(1), blank[match.start():index + 1]))
    return out


@pytest.mark.cross_language
def test_no_rust_function_that_reads_or_writes_plain_json_also_hashes():
    users, violations = set(), []
    for top in ("prismpath-rs", "prismpath-hotswap-rs", "prismpath-telemetry-rs", "prismpath-preflight"):
        for path in sorted((REPO_ROOT / top / "src").rglob("*.rs")):
            rel = path.relative_to(REPO_ROOT).as_posix()
            for name, body in _rust_functions(path.read_text(encoding="utf-8")):
                if name in ("parse_plain", "parse_content", "plain_dumps"):
                    continue                                  # the helpers themselves
                if _PLAIN_RS.search(body):
                    users.add(rel)
                    if _HASH_RS.search(body):
                        violations.append(f"{rel}:{name}")
    assert violations == []
    assert {"prismpath-rs/src/durable.rs", "prismpath-rs/src/connector.rs", "prismpath-hotswap-rs/src/flow_authority.rs"} <= users
