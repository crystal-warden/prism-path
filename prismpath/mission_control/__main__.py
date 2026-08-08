"""`python -m prismpath.mission_control` — the loopback command center."""
import uvicorn

from . import core
from .app import app

if __name__ == "__main__":
    print(f"mission control on {core.HOST}:{core.PORT}  proj={core.PROJ}  "
          f"audit_root={core.AUDIT.current_root()[:16]}", flush=True)
    uvicorn.run(app, host=core.HOST, port=core.PORT, log_level="warning")
