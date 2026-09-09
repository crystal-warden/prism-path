# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every CLI subcommand belongs to exactly one persona group, and the grouped help renders them all."""
from prismpath import cli


def _registered(parser):
    for action in parser._actions:
        if hasattr(action, "choices") and isinstance(action.choices, dict):
            return set(action.choices)
    raise AssertionError("no subparsers")


def test_every_command_in_exactly_one_group():
    parser = cli.build_parser()
    registered = _registered(parser)
    grouped = [n for _, names in cli.PERSONAS for n in names]
    assert len(grouped) == len(set(grouped)), "a command is listed under two personas"
    assert set(grouped) == registered, {"unlisted": registered - set(grouped), "unregistered": set(grouped) - registered}


def test_help_is_grouped():
    text = cli.build_parser().format_help()
    for title, names in cli.PERSONAS:
        assert title.split(":")[0] in text
        for n in names:
            assert f"  {n:<12}" in text
    assert "{run," not in text  # the flat choice list is hidden behind the metavar
