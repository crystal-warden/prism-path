# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""facet-init must transcribe faithfully and refuse honestly: every Level M-expressible VRL
condition becomes an identical flow edge, everything else is reported verbatim with a reason, and
no condition is ever invented from the sample (the tool drafts, the author signs)."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
sys.path.insert(0, str(_ADAPTER.parent.parent))
import facet_init as fi  # noqa: E402
from prismpath.parser import parse_file  # noqa: E402

_needs_toml = pytest.mark.skipif(
    fi.tomllib is None, reason="tomllib needs Python 3.11+ (or tomli installed)")


def _t(cond):
    return fi.transcribe(cond, fi.FieldMap())


def test_transcribe_level_m_forms():
    assert _t(".level >= 7") == ("level >= 7", None)
    assert _t(".rule.level >= 3 && !.archived") == ("level >= 3 and not archived", None)
    assert _t('.a == "x" || .b != 2') == ('a == "x" or b != 2', None)
    assert _t('includes(["watch", "contain"], .action)') == \
        ('action in ["watch", "contain"]', None)
    assert _t(".armed == true") == ("armed == True", None)
    assert _t({"type": "vrl", "source": ".level < 5"}) == ("level < 5", None)


def test_transcribe_refusals_name_the_reason():
    for cond, why in [
            ('match(.msg, r"probe")', "not Level M"),
            (".a < .b", "field vs field"),
            ("3 <= .level <= 7", "chained comparison"),
            (".x == null", "null comparison"),
            (".ratio > 1.5", "float threshold"),
            (".level > threshold", "unrecognized identifier"),
            ({"type": "datadog_search", "query": "x"}, "not a VRL string")]:
        text, reason = _t(cond)
        assert text is None and why in reason, (cond, reason)


def test_field_map_leaf_wins_until_collision():
    fm = fi.FieldMap()
    assert fm.token("rule.level") == "level"
    assert fm.token("rule.level") == "level"          # stable
    assert fm.token("agent.level") == "agent_level"   # collision -> full path
    assert fm.token("x.in") == "x_in"                 # keyword leaf -> full path
    assert fm.non_identity() == {"level": "rule.level", "agent_level": "agent.level",
                                 "x_in": "x.in"}


def _setup(tmp_path, toml_text, events):
    toml = tmp_path / "vector.toml"
    toml.write_text(toml_text)
    sample = tmp_path / "sample.ndjson"
    sample.write_text("".join(json.dumps(e) + "\n" for e in events))
    return toml, sample


_TOML = """
[transforms.gate]
type = "filter"
inputs = ["src"]
condition = '.level >= 3'

[transforms.sev]
type = "route"
inputs = ["gate"]
route.high = '.level >= 7'
route.noise = 'match(.msg, r"test")'
route.low = '.level < 7'
"""


@_needs_toml
def test_end_to_end_draft_parses_and_preflight_is_ready(tmp_path):
    toml, sample = _setup(tmp_path, _TOML, [{"level": v, "msg": "m"} for v in (1, 5, 9)])
    out = tmp_path / "draft.flow.md"
    r = subprocess.run(
        [sys.executable, str(_ADAPTER / "facet_init.py"), str(sample),
         "--vector-toml", str(toml), "--out", str(out)],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    g = parse_file(str(out))                          # the draft is a valid flow
    assert [t for t, _c in g.nodes["gate"].edges] == ["sev", "gate_dropped"]
    assert [t for t, _c in g.nodes["sev"].edges] == ["sev_high", "sev_low", "sev_unmatched"]
    assert "sev.noise" in r.stdout and "match(" in r.stdout   # refused verbatim, with the culprit
    assert "**READY.**" in r.stdout                   # preflight ran on the draft and passed


def test_skeleton_mode_never_invents_conditions(tmp_path):
    _toml, sample = _setup(tmp_path, "", [{"level": 5, "tag": "a"}])
    out = tmp_path / "skel.flow.md"
    r = subprocess.run(
        [sys.executable, str(_ADAPTER / "facet_init.py"), str(sample), "--out", str(out)],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    text = out.read_text()
    assert "when" not in text                         # annotations only, zero learned conditions
    assert "level (int, 1/1 events" in text
    parse_file(str(out))


def test_empty_sample_fails_loud(tmp_path):
    sample = tmp_path / "empty.ndjson"
    sample.write_text("")
    r = subprocess.run(
        [sys.executable, str(_ADAPTER / "facet_init.py"), str(sample)],
        capture_output=True, text=True)
    assert r.returncode == 1 and "no events" in r.stdout
