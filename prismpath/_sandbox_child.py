# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# Moved to prismpath.workers._sandbox_child (September 2026). This name stays importable: it is the same module object.
import sys as _sys
import warnings as _warnings
_warnings.warn("prismpath._sandbox_child moved to prismpath.workers; import it from there, this alias goes away in a later release", DeprecationWarning, stacklevel=2)
from prismpath.workers import _sandbox_child as _m
_sys.modules[__name__] = _m
