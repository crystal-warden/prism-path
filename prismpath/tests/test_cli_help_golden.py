# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A golden of what `prismpath --help` prints for the root CLI and every command and subcommand.

Walks the registered argparse subparser tree from `prismpath.cli.build_parser()` and compares the
stdout, stderr, and exit code of `--help` for each command path with `fixtures/cli_help_golden.json`.
To write the fixture again, run `python -m prismpath.tests.test_cli_help_golden --write` from the
repository root.
"""
import argparse
import contextlib
import io
import json
import os
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
FIXTURE = PKG / "tests" / "fixtures" / "cli_help_golden.json"
HELP_COLUMNS = "80"


def _walk_commands(parser, prefix=()):
    """Every command path (tuple of subcommand names) registered on `parser`, in sorted order."""
    paths = [prefix]
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, subparser in sorted(action.choices.items()):
                paths.extend(_walk_commands(subparser, prefix + (name,)))
    return paths


def _capture_help(parts):
    """Run `cli.main([*parts, '--help'])` with fixed terminal width and return code, stdout, stderr."""
    from prismpath import cli
    out, err = io.StringIO(), io.StringIO()
    previous_columns = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = HELP_COLUMNS
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main([*parts, "--help"])
            except SystemExit as exc:
                code = exc.code
    finally:
        if previous_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = previous_columns
    return {"code": code, "stdout": out.getvalue(), "stderr": err.getvalue()}


def capture_all():
    from prismpath import cli
    parser = cli.build_parser()
    captured = {}
    for parts in _walk_commands(parser):
        key = " ".join(("prismpath", *parts))
        captured[key] = _capture_help(parts)
    return captured


def test_the_command_tree_is_not_empty():
    from prismpath import cli
    commands = _walk_commands(cli.build_parser())
    assert () in commands
    assert ("policy", "manifest", "check") in commands
    assert len(commands) >= 50


def test_every_command_help_matches_golden():
    from prismpath import cli
    golden = json.loads(FIXTURE.read_text(encoding="utf-8"))
    got = capture_all()
    if cli.WITHDRAWN_COMMANDS:
        # In the exported product distribution, withdrawn commands (such as `compile`) are omitted
        # from the grouped root help and carry suppressed help; compare every remaining command.
        withdrawn = set(cli.WITHDRAWN_COMMANDS)
        golden = {key: value for key, value in golden.items()
                  if key != "prismpath" and key.split()[1] not in withdrawn}
        got = {key: value for key, value in got.items()
               if key != "prismpath" and key.split()[1] not in withdrawn}
    assert sorted(got) == sorted(golden)
    for key in sorted(got):
        assert got[key] == golden[key], key


if __name__ == "__main__":
    if "--write" not in sys.argv:
        sys.exit("pass --write to write the golden again")
    FIXTURE.write_text(json.dumps(capture_all(), indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                       encoding="utf-8")
