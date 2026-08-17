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


def lost_mask(n: int, p: float, r: float, p_b: float = 1.0, p_g: float = 0.0, seed: int = 0):
    """Per-sample loss mask under Gilbert-Elliott(p=g->b, r=b->g)."""
    rng = np.random.default_rng(seed)
    mask = np.zeros(n, dtype=bool)
    bad = False
    for i in range(n):
        mask[i] = rng.random() < (p_b if bad else p_g)
        if bad:
            if rng.random() < r:      # b -> g (mean burst length ~ 1/r)
                bad = False
        elif rng.random() < p:        # g -> b
            bad = True
    return mask


def retransmit_bytes(n: int, block_size: int, mask, bytes_per_sample: float) -> Dict[str, float]:
    """Bytes needed to repair the losses: selective (only blocks touching a loss) vs full retransmit."""
    n_blocks = (n + block_size - 1) // block_size
    lost_blocks = 0
    for b in range(n_blocks):
        seg = mask[b * block_size:(b + 1) * block_size]
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
