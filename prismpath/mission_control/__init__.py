# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""PrismPath Mission Control — the proving + observability command center.

Single-user, loopback reference deployment of the control plane. The FastAPI app lives in
`prismpath.mission_control.app:app`; the transport-agnostic half is split by job into one module each
(`discovery`, `launch`, `status`, `lens`, `graph`, ...) and re-exported by `core`, which is the facade
the routers import. Kept import-light so `from prismpath.mission_control import core` works without
the `control-plane` extra installed.
"""
