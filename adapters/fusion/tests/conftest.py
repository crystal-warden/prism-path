# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.dirname(HERE)
for p in (os.path.dirname(os.path.dirname(ADAPTER)), ADAPTER, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)
