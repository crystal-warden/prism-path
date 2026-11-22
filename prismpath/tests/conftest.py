# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests that assert what the product repository's export does not carry are not collected in the
research repository, which carries all of it. The research repository is told by the standalone
JavaScript kernel beside the package; the export has no such file, so there every test is collected."""
from pathlib import Path

_PACKAGE = Path(__file__).resolve().parent.parent
_CARRIES_THE_JAVASCRIPT_KERNEL = (_PACKAGE / "portable" / "prismpath.mjs").exists()

# each of these asserts an absence the export guarantees: no JavaScript engine in the package
_ASSERTS_AN_ABSENCE = ("test_cli_without_js_engine.py",)

collect_ignore = list(_ASSERTS_AN_ABSENCE) if _CARRIES_THE_JAVASCRIPT_KERNEL else []


# The profile's walk over a policy's reading domain (`profile.needs_all`) takes 1 to 10 s an image and is a pure
# function of the policy document and the fields read besides it, and dozens of tests compile the same starter images.
# Within one test session each (document, fields) pair is walked once and the answer shared. A test that checks the
# walk itself gives the same answer twice is marked `fresh_needs` and walks every time.
import json as _json

import pytest as _pytest

from prismpath.agent import profile as _profile

_WALK = _profile.needs_all
_WALKED = {}


def _shared_needs_all(policy, read_also=()):
    key = (_json.dumps(policy.doc, sort_keys=True), tuple(read_also))
    if key not in _WALKED:
        _WALKED[key] = _WALK(policy, read_also)
    return _WALKED[key]


_profile.needs_all = _shared_needs_all


@_pytest.fixture(autouse=True)
def _fresh_needs(request, monkeypatch):
    if request.node.get_closest_marker("fresh_needs"):
        monkeypatch.setattr(_profile, "needs_all", _WALK)
    yield
