# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# Moved to prismpath.evals.eval_hybrid_served (September 2026). This name stays importable: it is the same module object.
import sys as _sys
import warnings as _warnings
_warnings.warn("prismpath.eval_hybrid_served moved to prismpath.evals; import it from there, this alias goes away in a later release", DeprecationWarning, stacklevel=2)
from prismpath.evals import eval_hybrid_served as _m
_sys.modules[__name__] = _m
