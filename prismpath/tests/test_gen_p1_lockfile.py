# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for gen_p1_lockfile module."""

import json
import sys
import numpy as np
from prismpath.safety import gen_p1_lockfile


def test_cos_helper():
    a = [1.0, 0.0, 0.0]
    b = [1.0, 0.0, 0.0]
    c = [0.0, 1.0, 0.0]
    assert abs(gen_p1_lockfile._cos(a, b) - 1.0) < 1e-6
    assert abs(gen_p1_lockfile._cos(a, c) - 0.0) < 1e-6


def _fake_embedder(texts):
    # Deterministic dummy unit vector of dimension 384
    dim = 384
    val = 1.0 / (dim ** 0.5)
    return np.array([[val] * dim for _ in texts], dtype=np.float32)


def test_generate_with_stub_embedder(monkeypatch):
    monkeypatch.setattr(gen_p1_lockfile, "_load_embedder", lambda: _fake_embedder)

    res = gen_p1_lockfile.generate()
    assert isinstance(res, dict)

    required_keys = {
        "version", "embedder_id", "reference_impl", "fingerprint_probe",
        "fingerprint", "threshold", "centroids", "centroids_are_unit_length",
        "reference_scores", "parity_vectors", "measurement"
    }
    assert required_keys.issubset(set(res.keys()))
    assert len(res["fingerprint"]) == 384
    assert res["threshold"] == gen_p1_lockfile.THRESHOLD
    assert isinstance(res["centroids"], dict)
    assert len(res["centroids"]) > 0
    assert len(res["parity_vectors"]) == 2


def test_generate_determinism(monkeypatch):
    monkeypatch.setattr(gen_p1_lockfile, "_load_embedder", lambda: _fake_embedder)

    res1 = gen_p1_lockfile.generate()
    res2 = gen_p1_lockfile.generate()
    assert res1 == res2


def test_main_check(monkeypatch, tmp_path):
    monkeypatch.setattr(gen_p1_lockfile, "_load_embedder", lambda: _fake_embedder)

    lockfile_path = tmp_path / "p1_lockfile.json"
    monkeypatch.setattr(gen_p1_lockfile, "OUT_PATH", lockfile_path)

    # When file does not exist
    monkeypatch.setattr(sys, "argv", ["gen_p1_lockfile", "--check"])
    assert gen_p1_lockfile.main() == 1

    # Write file
    data = gen_p1_lockfile.generate()
    text = json.dumps(data, indent=1, sort_keys=True) + "\n"
    lockfile_path.write_text(text, encoding="utf-8")

    # Now --check should pass
    monkeypatch.setattr(sys, "argv", ["gen_p1_lockfile", "--check"])
    assert gen_p1_lockfile.main() == 0


def test_main_missing_dependency(monkeypatch):
    def bad_loader():
        raise ImportError("sentence-transformers not installed")

    monkeypatch.setattr(gen_p1_lockfile, "_load_embedder", bad_loader)
    monkeypatch.setattr(sys, "argv", ["gen_p1_lockfile"])
    assert gen_p1_lockfile.main() == 2
