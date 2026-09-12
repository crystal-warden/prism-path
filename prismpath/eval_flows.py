# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# Moved to prismpath.evals.eval_flows (September 2026). This name stays importable: it is the same module object.
import sys as _sys
import warnings as _warnings
_warnings.warn("prismpath.eval_flows moved to prismpath.evals; import it from there, this alias goes away in a later release", DeprecationWarning, stacklevel=2)
from prismpath.evals import eval_flows as _m
_sys.modules[__name__] = _m
