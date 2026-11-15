# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests that assert what the product repository's export does not carry are not collected in the
research repository, which carries all of it. The research repository is told by the standalone
JavaScript kernel beside the package; the export has no such file, so there every test is collected."""
from pathlib import Path

_PACKAGE = Path(__file__).resolve().parent.parent
_CARRIES_THE_JAVASCRIPT_KERNEL = (_PACKAGE / "portable" / "prismpath.mjs").exists()

# each of these asserts an absence the export guarantees: no JavaScript engine in the package
_ASSERTS_AN_ABSENCE = ("test_cli_without_js_engine.py",)

collect_ignore = list(_ASSERTS_AN_ABSENCE) if _CARRIES_THE_JAVASCRIPT_KERNEL else []
