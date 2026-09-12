# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# Moved to prismpath.ledgers.checkpoint (September 2026). This name stays importable: it is the same module object.
import sys as _sys
import warnings as _warnings
_warnings.warn("prismpath.checkpoint moved to prismpath.ledgers; import it from there, this alias goes away in a later release", DeprecationWarning, stacklevel=2)
from prismpath.ledgers import checkpoint as _m
_sys.modules[__name__] = _m
