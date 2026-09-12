# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for bypass_corpus module."""

from prismpath.safety import bypass_corpus


def test_strata_transforms():
    assert bypass_corpus._alternate_case("hello world") == "HeLlO wOrLd"
    assert bypass_corpus._interleave("hello world", "_") == "h_e_l_l_o w_o_r_l_d"
    assert bypass_corpus._punctuate("hello world foo") == "hello.world.foo"

    diacritics_out = bypass_corpus._add_diacritics("aeiou")
    assert len(diacritics_out) > 0


def test_load_seeds():
    seeds = bypass_corpus.load_seeds()
    assert isinstance(seeds, list)
    assert len(seeds) > 0
    for seed in seeds:
        assert set(seed.keys()) == {"text", "rule", "policy", "direction"}
        assert seed["policy"] == bypass_corpus.FLOOR_POLICY
        assert seed["rule"] not in bypass_corpus.EXCLUDED_RULES
        assert isinstance(seed["text"], str) and len(seed["text"]) > 0


def test_generate_shape_and_fields():
    variants = bypass_corpus.generate()
    assert isinstance(variants, list)
    assert len(variants) > 0
    required_keys = {"text", "rule", "policy", "direction", "stratum", "klass", "variant"}
    valid_klasses = {bypass_corpus.CONTROL, bypass_corpus.MECHANICAL, bypass_corpus.SEMANTIC}

    for v in variants:
        assert required_keys.issubset(set(v.keys()))
        assert v["klass"] in valid_klasses
        assert isinstance(v["variant"], str) and len(v["variant"]) > 0


def test_generate_determinism():
    run1 = bypass_corpus.generate()
    run2 = bypass_corpus.generate()
    assert run1 == run2
