# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A golden of what `prismpath validate`, `test`, `lint` and `capability` print for every shipped flow.

The flows are the files under `prismpath/flows/` and `prismpath/gallery/`. The text each command prints, and the exit
code, are compared with `fixtures/cli_flow_golden.json`. A refactor of the kernel or the routing package must not move
one byte of it. To write it again, which only a change of the printed text on purpose does, run
`python -m prismpath.tests.test_cli_flow_golden --write` from the repository root.
"""
import contextlib
import io
import json
import os
import re
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
ROOT = PKG.parent
FIXTURE = PKG / "tests" / "fixtures" / "cli_flow_golden.json"
COMMANDS = ("validate", "test", "lint", "capability")


def _flows():
    found = []
    for base in (PKG / "flows", PKG / "gallery"):
        for path in sorted(base.rglob("*.md")):
            if path.name.endswith(".tests.md") or path.name.lower() == "readme.md":
                continue
            found.append(path.relative_to(ROOT).as_posix())
    return found


def _capture(command, flow):
    from prismpath import cli
    out, err = io.StringIO(), io.StringIO()
    previous = os.getcwd()
    os.chdir(ROOT)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main([command, flow])
            except SystemExit as exc:
                code = exc.code
    finally:
        os.chdir(previous)
    noise = re.compile(r"Loading weights|\bit/s\b")
    stderr = "\n".join(line for line in err.getvalue().splitlines() if not noise.search(line))
    return {"code": code, "stdout": out.getvalue(), "stderr": stderr}


def capture_all():
    return {f"{command} {flow}": _capture(command, flow) for flow in _flows() for command in COMMANDS}


def test_the_flow_list_is_not_empty():
    assert len(_flows()) >= 15


def test_the_commands_print_what_they_printed():
    pytest.importorskip("numpy")
    golden = json.loads(FIXTURE.read_text(encoding="utf-8"))
    commands = COMMANDS
    try:
        import sentence_transformers  # noqa: F401  (lint embeds the edge texts)
    except ImportError:
        # Without the embeddings extra `lint` and `test` refuse before they read a flow, so their captures say
        # nothing here. The gate, which has the extra, holds all four.
        commands = ("validate", "capability")
        golden = {key: value for key, value in golden.items() if key.split(" ", 1)[0] in commands}
    got = {f"{command} {flow}": _capture(command, flow) for flow in _flows() for command in commands}
    assert sorted(got) == sorted(golden)
    for key in sorted(got):
        assert got[key] == golden[key], key


if __name__ == "__main__":
    if "--write" not in sys.argv:
        sys.exit("pass --write to write the golden again")
    FIXTURE.write_text(json.dumps(capture_all(), indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
