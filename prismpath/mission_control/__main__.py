# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`python -m prismpath.mission_control` — the loopback command center."""
import sys

try:
    import uvicorn

    from . import core
    from .app import app
except ImportError as exc:
    from prismpath import extras
    missing = extras.from_exception(exc)
    if missing is None:
        raise
    sys.exit(f"prismpath mission_control: {missing.install}")

if __name__ == "__main__":
    settings = core.SETTINGS
    print(f"mission control on {settings.host}:{settings.port}  proj={settings.proj}  "
          f"audit_root={core.audit.LOG.current_root()[:16]}", flush=True)
    log = core.audit.LOG
    print(f"audit log signed by instance key {log.instance_key.fingerprint}, statements in {log.statements_path}"
          if log.signing else
          "audit log not signed: no instance key (set PRISMPATH_INSTANCE_KEY to sign root statements)", flush=True)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="warning")
