# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""This module's presence makes a dev build (spec-policy-distribution.md, D2). It is in the repository and
is left out of the wheel, the sdist and the product export, so an installed package is a production build
and refuses every escape hatch (`prismpath.distribution.devbuild`). It holds nothing else."""
