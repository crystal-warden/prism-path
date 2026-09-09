# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# Moved to prismpath.kernel.model_check (September 2026). This name stays importable: it is the same module object.
import sys as _sys
from prismpath.kernel import model_check as _m
_sys.modules[__name__] = _m
