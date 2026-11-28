# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The adapter interface between the one enforcement point machine (`prismpath.distribution.pep`) and the
runtime a target kind protects. It is the target runtime port, `prismpath.ports.target.Adapter`, and its names
are kept here. The `host` and `mesh` adapters live beside it, and the `agent` and `gateway` ones with their kinds
(`prismpath.agent.dist_kind`, `prismpath.gateway.dist_kind`).
"""
from __future__ import annotations

from prismpath.ports.target import CANNOT_DECIDE, LARGER, NOT_LARGER, Adapter  # noqa: F401
