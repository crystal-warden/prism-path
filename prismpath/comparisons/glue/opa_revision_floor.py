# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""OPA policy revision floor enforcement point wrapper."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path


def read_revision(bundle_path: str | Path) -> str:
    try:
        with tarfile.open(bundle_path, "r:*") as tf:
            for m in tf.getmembers():
                if Path(m.name).name == ".manifest":
                    f = tf.extractfile(m)
                    if f:
                        rev = json.loads(f.read().decode("utf-8")).get("revision")
                        return "" if rev is None else str(rev)
    except Exception:
        pass
    return ""


class Floor:
    def __init__(self, state_path: str | Path) -> None:
        self.state_path = Path(state_path)

    def check(self, bundle_path: str | Path) -> tuple[bool, str]:
        R = read_revision(bundle_path)
        if not R or not R.isdigit():
            return False, "refused: unparseable revision"
        F_str, f_val = "none", None
        if self.state_path.exists():
            try:
                F_str = str(json.loads(self.state_path.read_text("utf-8")).get("revision", "none"))
                f_val = int(F_str) if F_str.isdigit() else None
            except Exception:
                pass
        if f_val is not None and int(R) < f_val:
            return False, f"refused: stale revision {R} below floor {F_str}"
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"revision": R}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)
        return True, f"accepted: revision {R} (floor was {F_str})"


def activate(bundle_path: str | Path, state_path: str | Path, opa_bin: str | Path, pub_key_pem: str | Path, port: int) -> subprocess.Popen | None:
    ok, msg = Floor(state_path).check(bundle_path)
    if not ok:
        print(msg)
        return None
    cmd = [str(opa_bin), "run", "-s", "-a", f"127.0.0.1:{port}", "-b", "--verification-key", str(pub_key_pem), "--signing-alg", "RS256", str(bundle_path)]
    return subprocess.Popen(cmd, start_new_session=True)


if __name__ == "__main__":
    if len(sys.argv) >= 5:
        activate(sys.argv[1], sys.argv[2], "opa", sys.argv[3], int(sys.argv[4]))
