# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath run` names the thing that does the work a worker; `--agent` still parses, unadvertised."""
import argparse

from prismpath import cli


def _run_action(option_string):
    parser = cli.build_parser()
    for action in parser._actions:
        if hasattr(action, "choices") and isinstance(action.choices, dict):
            for sub_action in action.choices["run"]._actions:
                if option_string in sub_action.option_strings:
                    return sub_action
    raise AssertionError(f"`run` has no {option_string}")


def test_both_spellings_parse_to_the_same_value():
    parser = cli.build_parser()
    spec = "ollama:llama3.2"
    with_worker = parser.parse_args(["run", "flow.md", "--worker", spec])
    with_agent = parser.parse_args(["run", "flow.md", "--agent", spec])
    assert with_worker.agent == with_agent.agent == spec


def test_neither_spelling_given_leaves_the_mock_worker():
    parser = cli.build_parser()
    assert parser.parse_args(["run", "flow.md"]).agent is None


def test_the_old_spelling_is_hidden_and_the_new_one_is_documented():
    # An alias kept for callers, not offered to new ones: suppressed help keeps it out of `run --help`
    # so the dictionary's word is the only one a reader is taught.
    assert _run_action("--agent").help is argparse.SUPPRESS
    assert "worker" in _run_action("--worker").help
    assert "--agent" not in cli.build_parser().format_help()
