# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The governed agent core that ships in the wheel: the classifier that reads a proposed tool call into
typed fields (trusted code outside the verified core), the policy loader and decider, and the evidence
writer and verifier. The research loop that drives a model with these (integrations/governed_harness)
imports them from here."""
