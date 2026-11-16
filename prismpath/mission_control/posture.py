# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The console's two postures and the capability a route declares.

`full` is the loopback default. `read-only` (`--read-only` or MC_READ_ONLY=1) mounts no route whose
capability is `write`, so an assessor can run the console over a copy of the evidence with no way to
change it. A route declares `write` with `openapi_extra=WRITE`; an undeclared route reads. The
capability is published in the OpenAPI document as `x-prismpath-capability`.
"""
CAPABILITY_KEY = "x-prismpath-capability"
WRITE = {CAPABILITY_KEY: "write"}


def capability(route) -> str:
    """`write` for a route that declared it, otherwise `read`."""
    extra = getattr(route, "openapi_extra", None) or {}
    return extra.get(CAPABILITY_KEY, "read")
