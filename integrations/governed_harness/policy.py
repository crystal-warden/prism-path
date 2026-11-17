# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The agent rules policy and its decider now ship in the wheel as `prismpath.agent.policy`, with the policy
files beside it. This name stays for the research harness and its callers and is the package module itself,
not a copy."""
import sys

from prismpath.agent import policy as _policy

sys.modules[__name__] = _policy
