# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The classifier now ships in the wheel as `prismpath.agent.classifier`. This name stays for the research
harness and its callers and is the package module itself, not a copy."""
import sys

from prismpath.agent import classifier as _classifier

sys.modules[__name__] = _classifier
