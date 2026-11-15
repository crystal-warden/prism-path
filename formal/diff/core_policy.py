# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The oracle's check of a policy image, ported from Lean, now shipped as `prismpath.kernel.core_policy` so
the package's evidence verifier decides a run's exclusions with no research tooling. This name stays for
the research tools and their callers (`import core_policy` with formal/diff on the path) and is the
package module itself, not a copy."""
import sys

from prismpath.kernel import core_policy as _core_policy

sys.modules[__name__] = _core_policy
