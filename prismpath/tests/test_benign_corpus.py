# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for benign_corpus module."""

from prismpath.safety import benign_corpus


def test_split_of_deterministic():
    text = "how do I write a for loop in Rust"
    res1 = benign_corpus.split_of(text)
    res2 = benign_corpus.split_of(text)
    assert res1 in (benign_corpus.DEV, benign_corpus.HOLDOUT)
    assert res1 == res2


def test_benign_dict_structure():
    assert isinstance(benign_corpus.BENIGN, dict)
    assert len(benign_corpus.BENIGN) > 0
    for stratum, items in benign_corpus.BENIGN.items():
        assert isinstance(stratum, str) and len(stratum) > 0
        assert isinstance(items, list) and len(items) > 0
        for text in items:
            assert isinstance(text, str) and len(text) > 0


def test_generate_all_and_shape():
    cases = benign_corpus.generate()
    assert isinstance(cases, list)
    assert len(cases) > 0
    for case in cases:
        assert set(case.keys()) == {"stratum", "text", "split"}
        assert case["split"] in (benign_corpus.DEV, benign_corpus.HOLDOUT)
        assert case["stratum"] in benign_corpus.BENIGN
        assert case["text"] in benign_corpus.BENIGN[case["stratum"]]


def test_generate_filtered():
    dev_cases = benign_corpus.generate(split=benign_corpus.DEV)
    holdout_cases = benign_corpus.generate(split=benign_corpus.HOLDOUT)
    all_cases = benign_corpus.generate()

    assert all(c["split"] == benign_corpus.DEV for c in dev_cases)
    assert all(c["split"] == benign_corpus.HOLDOUT for c in holdout_cases)
    assert len(dev_cases) + len(holdout_cases) == len(all_cases)


def test_generate_determinism():
    run1 = benign_corpus.generate()
    run2 = benign_corpus.generate()
    assert run1 == run2


def test_counts():
    tally = benign_corpus.counts()
    assert isinstance(tally, dict)
    assert set(tally.keys()) == set(benign_corpus.BENIGN.keys())
    for stratum, counts in tally.items():
        assert counts[benign_corpus.DEV] + counts[benign_corpus.HOLDOUT] == len(benign_corpus.BENIGN[stratum])
