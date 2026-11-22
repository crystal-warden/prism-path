# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `host` adapter: the software tier of `prismpath/hotswap/policy_host.py` as a distribution target
(spec-policy-distribution.md, section 3).

A committed release is installed with `PolicyHost.install_verified`, the commit half `swap` also ends in,
so the host's own record, audit log and restore on start are what they always were. A release without a
policy is `PolicyHost.withdraw`, so the host holds nothing and allows nothing (X3). The adapter's own check
is the spiral sidecar: when the `policy.ppt` envelope's `meta.packing` declares one, the release needs a
`policy.spiral` whose SHA-256 is the declared `sidecar_sha256` (C2, V11).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Tuple

from prismpath import canon
from prismpath.distribution.adapters import Adapter
from prismpath.hotswap import policy_pack


class HostAdapter(Adapter):
    kind = "host"

    def __init__(self, host):
        self.host = host
        self.home = host.state_dir
        self.qualification = host.envelope

    def check(self, artifact: str, body: bytes, staged: Mapping[str, Tuple[Any, bytes]]) -> Optional[str]:
        packing = staged["policy.ppt"][0].meta.get("packing") if "policy.ppt" in staged else None
        if artifact == "policy.ppt" and packing is not None and "policy.spiral" not in staged:
            return "spiral:sidecar-missing"
        if artifact == "policy.spiral":
            declared = packing.get("sidecar_sha256") if isinstance(packing, dict) else None
            if declared != canon.sha256_hex(body):
                return "spiral:sidecar-hash-mismatch"
        return None

    def activate(self, release) -> None:
        image = release.bodies["policy.ppt"]
        sha256 = canon.sha256_hex(image)
        current = self.host.active()
        if current.get("active") == sha256 and current.get("version") == release.seq:
            return                                             # a restart that finds the host already there
        envelope = release.envelopes["policy.ppt"]
        meta = envelope.meta
        record = {"sha256": sha256, "version": release.seq, "key_id": None,
                  "envelope_id": meta["qualification"], "unsigned": False, "overlay_of": meta.get("overlay_of"),
                  "counts": policy_pack.read_ppt_header(image),
                  "since": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "ppt_path": os.path.abspath(release.paths["policy.ppt"])}
        distribution = {"stream": release.stream, "seq": release.seq, "release": release.release,
                        "envelope_id": envelope.envelope_id}
        if "policy.spiral" in release.bodies:
            distribution["spiral_sha256"] = canon.sha256_hex(release.bodies["policy.spiral"])
        self.host.install_verified(image, {**record, "distribution": distribution}, {"distribution": distribution})

    def deactivate(self, cause: str) -> None:
        self.host.withdraw(cause)
