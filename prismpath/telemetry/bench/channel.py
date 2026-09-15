# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Gilbert-Elliott burst-loss channel + retransmission accounting.

Gilbert-Elliott is the standard 2-state (Good/Bad) model for bursty links (satellite/RF): in Good, loss
prob p_g (~0); in Bad, loss prob p_b (~1); transitions g->b with prob p, b->g with prob r. Mean burst
length ~= 1/r. We chunk the stream into fixed-size blocks, mark blocks that overlap any lost sample as
lost, and compare selective-block repair (retransmit only lost blocks — the MMR self-heal) vs full
retransmit.
"""
from __future__ import annotations

from typing import Dict

import numpy as np


def lost_mask(sample_count: int, loss_probability: float, recovery_probability: float,
              p_b: float = 1.0, p_g: float = 0.0, seed: int = 0):
    """Per-sample loss mask under Gilbert-Elliott(p=g->b, r=b->g)."""
    rng = np.random.default_rng(seed)
    mask = np.zeros(sample_count, dtype=bool)
    bad = False
    for sample_index in range(sample_count):
        mask[sample_index] = rng.random() < (p_b if bad else p_g)
        if bad:
            if rng.random() < recovery_probability:   # b -> g (mean burst length ~ 1/r)
                bad = False
        elif rng.random() < loss_probability:         # g -> b
            bad = True
    return mask


def retransmit_bytes(sample_count: int, block_size: int, mask, bytes_per_sample: float) -> Dict[str, float]:
    """Bytes needed to repair the losses: selective (only blocks touching a loss) vs full retransmit."""
    n_blocks = (sample_count + block_size - 1) // block_size
    lost_blocks = 0
    for block_index in range(n_blocks):
        seg = mask[block_index * block_size:(block_index + 1) * block_size]
        if seg.any():
            lost_blocks += 1
    block_bytes = block_size * bytes_per_sample
    selective = lost_blocks * block_bytes
    full = n_blocks * block_bytes                 # resend the whole window
    return {
        "n_blocks": n_blocks,
        "lost_blocks": lost_blocks,
        "selective_bytes": selective,
        "full_bytes": full,
        "ratio": (selective / full) if full else 0.0,
    }
