# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# Moved to prismpath.hotswap.crypto_registry (September 2026). This name stays importable: it is the same module object.
import sys as _sys
import warnings as _warnings
_warnings.warn("prismpath.crypto_registry moved to prismpath.hotswap; import it from there, this alias goes away in a later release", DeprecationWarning, stacklevel=2)
from prismpath.hotswap import crypto_registry as _m
_sys.modules[__name__] = _m
