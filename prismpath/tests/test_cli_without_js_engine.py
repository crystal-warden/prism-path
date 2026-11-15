# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The JavaScript bundle compile is withdrawn: not advertised, and an explicit call fails clearly with
a nonzero exit. The pure Python portable check still works, and nothing in the package tree carries
the JavaScript engine the old command bundled."""
import subprocess
import sys
from pathlib import Path

from prismpath import cli

PACKAGE = Path(__file__).resolve().parent.parent


def _run(*arguments):
    return subprocess.run([sys.executable, "-m", "prismpath", *arguments], capture_output=True, text=True)


def test_compile_is_not_advertised():
    text = cli.build_parser().format_help()
    assert "  compile     " not in text
    assert "compile" in cli.WITHDRAWN_COMMANDS
    assert "compile" not in [name for _, names in cli.PERSONAS for name in names]


def test_compile_fails_clearly_and_nonzero(tmp_path):
    flow = tmp_path / "flow.md"
    flow.write_text("---\nname: f\nstart: a\n---\n## a\n-> b: when x > 1\n-> c: else\n## b\n## c\n")
    result = _run("compile", str(flow), "--tier", "p0")
    assert result.returncode == 2
    assert "not available in this distribution" in result.stderr
    assert not result.stdout.strip()
    assert not (tmp_path / "flow.bundle.mjs").exists()


def test_portable_check_still_works(tmp_path):
    flow = tmp_path / "flow.md"
    flow.write_text("---\nname: f\nstart: a\n---\n## a\n-> b: when x > 1\n-> c: else\n## b\n## c\n")
    result = _run("portable", str(flow))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "P0" in result.stdout
    assert "prismpath.mjs" not in result.stdout


def test_no_javascript_engine_in_the_package():
    assert not list((PACKAGE / "portable").glob("*.mjs"))
    assert not (PACKAGE / "portable" / "playground.html").exists()
