# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Polarity-lint tests (Area 2a) — flag semantic conditions that differ only by logical polarity."""
import numpy as np

from prismpath import embedder, lint
from prismpath.parser import parse


def test_polarity_signal_pure():
    assert lint._polarity_signal("the tests pass", "the tests fail")            # antonym
    assert lint._polarity_signal("it is ready", "it is not ready")              # negation
    assert lint._polarity_signal("the change is valid", "the change is invalid")
    assert lint._polarity_signal("it works", "it doesn't work")
    assert not lint._polarity_signal("reporting a bug", "asking about billing") # different topics
    assert not lint._polarity_signal("the fix is clear", "the fix is obvious")  # synonyms


def _stub_high_sim(monkeypatch):
    # every condition embeds to nearly the same vector -> high cosine (topic-similar)
    monkeypatch.setattr(embedder, "embed",
                        lambda texts, is_query=False: np.asarray([[1.0, 0.001 * i] for i in range(len(texts))],
                                                                 dtype="float32"))


POLAR = """---
start: run_tests
---
## run_tests
Report the result.
-> review: all tests pass
-> implement: some tests fail
## review
-> done: when always
## implement
-> done: when always
## done
"""

CLEAN = """---
start: classify
---
## classify
Sort the request.
-> bug: the customer is reporting something broken
-> billing: the message is about a payment or refund
## bug
-> done: when always
## billing
-> done: when always
## done
"""


def test_polarity_mirror_flags_pass_fail(monkeypatch):
    _stub_high_sim(monkeypatch)
    findings = lint.polarity_mirror(parse(POLAR))
    assert any(f.code == "polarity-mirror" and f.node == "run_tests" for f in findings)


def test_polarity_mirror_clean_on_distinct_topics(monkeypatch):
    _stub_high_sim(monkeypatch)   # even at high cosine, no polarity signal -> no flag
    assert lint.polarity_mirror(parse(CLEAN)) == []
