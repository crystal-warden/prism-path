# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Mission Control API guide's route tables are the console's own schema, so they cannot drift.

`tools/gen_mission_control_guide.py` rebuilds the block between the guide's markers from
`app.openapi()`. These tests fail when the committed guide differs from a fresh build, when a route
has no docstring to describe it, and when the hand written sections the generator must leave alone
are gone."""
import importlib.util
import os

import pytest

pytest.importorskip("fastapi")

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOOL = os.path.join(ROOT, "tools", "gen_mission_control_guide.py")
if not os.path.isfile(TOOL):                      # the exported product carries the guide, not the tool
    pytest.skip("tools/gen_mission_control_guide.py is not in this tree", allow_module_level=True)

spec = importlib.util.spec_from_file_location("gen_mission_control_guide", TOOL)
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


def _guide():
    with open(gen.GUIDE, encoding="utf-8") as handle:
        return handle.read()


def test_the_guide_matches_the_app():
    assert gen.splice(_guide(), gen.build_block()) == _guide(), \
        "run: python tools/gen_mission_control_guide.py"


def test_every_route_has_a_description():
    block = gen.build_block()
    empty = [line for line in block.splitlines() if line.startswith("| ") and line.endswith("|  |")]
    assert not empty, empty


def test_regeneration_keeps_the_hand_written_sections():
    text = _guide()
    stale = gen.splice(text, "| nothing |")
    assert gen.splice(stale, gen.build_block()) == text
    for heading in ("## The session", "## Security posture", "## Roots", "## Command center"):
        assert heading in stale
