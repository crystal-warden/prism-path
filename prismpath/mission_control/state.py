# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The single operator's live state: which sprint the console follows, and the locks that serialize writes."""
import threading

from .config import SETTINGS

# One operator, one followed-sprint state. `proc` is the sprint we launched (if any); `proj` is the
# directory we observe; `pinned` freezes auto-follow to a chosen sprint.
STATE = {"proc": None, "proj": SETTINGS.proj, "cfg": {}, "pinned": False}

LAUNCH_LOCK = threading.Lock()       # guards launch (one sprint at a time)
FILE_LOCK = threading.Lock()         # serializes flow-file writes
