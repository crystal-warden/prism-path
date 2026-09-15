# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`python -m prismpath.mission_control` — the loopback command center."""
import uvicorn

from . import core
from .app import app

if __name__ == "__main__":
    settings = core.SETTINGS
    print(f"mission control on {settings.host}:{settings.port}  proj={settings.proj}  "
          f"audit_root={core.audit.LOG.current_root()[:16]}", flush=True)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="warning")
