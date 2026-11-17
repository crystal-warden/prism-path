# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The episode evidence writer ships as `prismpath.agent.evidence`. This module re-exports it and adds the
research path: `verify` replays every receipt through the Lean oracle (`formal/diff/core_evidence.py`),
which the package's own verifier does through the Python reference kernel, so the harness's results keep
being checked against the independent implementation."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

from prismpath.agent.evidence import DECIDER, EpisodeRun, ensure_keys, replay  # noqa: F401

REPO = Path(__file__).resolve().parents[2]
for extra in (REPO, REPO / "formal" / "diff"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import core_evidence  # noqa: E402


def verify(run: Path, keys: Path, oracle=None) -> Dict[str, Any]:
    """The repository's verifier on the episode, every receipt replayed through the Lean oracle, keys pinned."""
    return core_evidence.verify(Path(run), sample=None, pin_authority=Path(keys) / "authority.pub",
                                pin_instance=Path(keys) / "instance.pub", oracle=oracle)
