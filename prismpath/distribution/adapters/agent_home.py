# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The old path of the agent home adapter, kept only for `prismpath/agent/zones.py`, which asks it whether a home
follows a stream. The adapter and the `agent` kind live in `prismpath/agent/dist_kind.py`, and the home functions
in `prismpath/onion/home.py`. This module goes when that one import of zones.py names `prismpath.onion.home`.
"""
from __future__ import annotations

from prismpath.onion.home import is_distributed  # noqa: F401
