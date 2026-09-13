# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The manifest reader in tools/evidence_check.py.

A manifest written with a single space or a tab used to parse as a digest with no file name, which
counted every file in it as absent instead of checking it.
"""
import importlib.util

from prismpath.tests._repo import repo_file

_spec = importlib.util.spec_from_file_location("evidence_check", repo_file("tools", "evidence_check.py"))
evidence_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evidence_check)

DIGEST = "a" * 64


def test_reads_every_separator_a_manifest_is_written_with():
    for separator in ("  ", " ", "\t", " *"):
        assert evidence_check.parse_line(f"{DIGEST}{separator}evidence/run.log") == (DIGEST, "evidence/run.log")


def test_keeps_a_name_that_contains_spaces():
    assert evidence_check.parse_line(f"{DIGEST}  a name with spaces.txt") == (DIGEST, "a name with spaces.txt")


def test_skips_blank_and_comment_lines():
    assert evidence_check.parse_line("") is None
    assert evidence_check.parse_line("   ") is None
    assert evidence_check.parse_line("# anchored 2026-08-20") is None
    assert evidence_check.parse_line(DIGEST) is None
