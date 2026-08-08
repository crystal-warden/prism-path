"""PrismPath Mission Control — the proving + observability command center.

Single-user, loopback reference deployment of the control plane. The FastAPI app lives in
`prismpath.mission_control.app:app`; the transport-agnostic engine is `core`. Kept import-light so
`from prismpath.mission_control import core` works without the `control-plane` extra installed.
"""
