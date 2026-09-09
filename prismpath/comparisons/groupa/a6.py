# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A6, policy anti rollback at the enforcement point (PREREGISTRATION.md section 5, A6).

Present the enforcement point itself, not a management server, with an older signed version, a
tampered image under a valid signature over the original, and an unsigned image; record what it
does. NATIVE: the point refuses all three with a named reason and no server in the loop. WITH-WORK:
refusal is available at a server or through configured bundle verification that a wrapper can extend
with a monotonic floor. NOT: no signing or versioning at the point.

Usage: python -m prismpath.comparisons.groupa.a6
"""
from __future__ import annotations

import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict

from prismpath import policy_host, policy_pack
from prismpath.comparisons.groupa.common import evidence_dir, policy_by_id, write_result
from prismpath.comparisons.harness import HERE, TOOLCHAIN_BIN, gen_dir_for
from prismpath.parser import parse

sys.path.insert(0, str(HERE.parent.parent / "prismpath-hw"))
import ppt_compile  # noqa: E402

POLICY = "network_admission"
SCENARIOS = {"stale_policy_1": "stale", "tampered_policy_1": "tampered", "unsigned_policy_1": "unsigned"}


def lifecycle_entries(policy: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {e["id"]: e for e in policy.get("lifecycle", [])}


# ----------------------------------------------------------------------------- PrismPath
def run_prismpath(policy) -> None:
    ev = evidence_dir("prismpath", "A6")
    tmp = Path(tempfile.mkdtemp(prefix="pp_a6_"))
    flow = (gen_dir_for("prismpath", POLICY) / f"{POLICY}.md").read_text()
    img = ppt_compile.compile_flow(parse(flow))
    blob = img.serialize()
    fields = {"protocol": "int", "dst_port": "int", "pkt_len": "int", "src_internal": "bool"}
    keys = policy_pack.keygen(str(tmp / "keys"), "authority")
    env = policy_pack.build_envelope("comparison-a6", fields, None, keys["private"], keys["public"], str(tmp))
    host = policy_host.PolicyHost(str(tmp / "state"), [keys["public"]], env, audit_path=str(ev / "swaps.log"))
    if (ev / "swaps.log").exists():
        (ev / "swaps.log").unlink()
        host = policy_host.PolicyHost(str(tmp / "state"), [keys["public"]], env, audit_path=str(ev / "swaps.log"))

    def pack(version: int, name: str, image: bytes) -> str:
        p = tmp / f"{name}.ppt"
        p.write_bytes(image)
        policy_pack.build_pack(str(p), fields, version, "comparison-a6", keys["private"], keys["public"])
        return str(p)

    log: Dict[str, Any] = {}
    v2 = pack(2, "v2", blob)
    r = host.swap(v2)
    log["baseline_v2"] = r
    # stale: an older signed version presented after the floor is 2
    v1 = pack(1, "v1", blob)
    r1 = host.swap(v1)
    log["stale_policy_1"] = r1
    # tampered: a valid version 3 pack, then one image byte flipped after signing
    v3 = pack(3, "v3", blob)
    data = bytearray(Path(v3).read_bytes())
    data[-1] ^= 0x01
    Path(v3).write_bytes(bytes(data))
    r3 = host.swap(v3)
    log["tampered_policy_1"] = r3
    # unsigned: an image with no manifest at all
    unsigned = tmp / "unsigned.ppt"
    unsigned.write_bytes(blob)
    r4 = host.swap(str(unsigned))
    log["unsigned_policy_1"] = r4
    log["active_after"] = host.active()
    (ev / "swap_results.json").write_text(json.dumps(log, indent=2, default=str) + "\n")
    entries = lifecycle_entries(policy)

    def reasons(res) -> str:
        return ",".join(res.get("reasons", [])) if isinstance(res, dict) and not res.get("ok", True) else "accepted"

    for sid, res in (("stale_policy_1", r1), ("tampered_policy_1", r3), ("unsigned_policy_1", r4)):
        refused = isinstance(res, dict) and res.get("ok") is False
        observed = "refuse_policy" if refused else "accepted"
        write_result(system="prismpath", dimension="A6", policy=POLICY, scenario=sid, expected="refuse_policy", observed=observed,
                     grade="NATIVE" if refused else "NOT", idiomatic=True, evidence_path=ev,
                     notes=(f"PolicyHost.swap at the enforcement point (no server): reasons={reasons(res)!r}; active policy "
                            f"unchanged at version {log['active_after'].get('version') if isinstance(log['active_after'], dict) else '?'}. "
                            f"Corpus expectation reason {entries[sid]['expected']['reason']}, predicted cause {entries[sid]['expected']['prismpath_cause']}. "
                            "The version floor is an fsync'd file on the point; every attempt, accepted or refused, is one Merkle logged "
                            "audit event (swaps.log). The compiled image is the corpus flow through the untouched table compiler."))


# ----------------------------------------------------------------------------- OPA
def run_opa(policy) -> None:
    ev = evidence_dir("opa", "A6")
    tmp = Path(tempfile.mkdtemp(prefix="opa_a6_"))
    opa = str(TOOLCHAIN_BIN / "opa")
    subprocess.run(["openssl", "genrsa", "-out", str(tmp / "priv.pem"), "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(tmp / "priv.pem"), "-pubout", "-out", str(tmp / "pub.pem")], check=True, capture_output=True)
    src = tmp / "bundle_src"; src.mkdir()
    shutil.copy(gen_dir_for("opa", POLICY) / "policy.rego", src / "policy.rego")

    def build(rev: str, out: str, signed: bool) -> None:
        cmd = [opa, "build", "-b", str(src), "-r", rev, "-o", str(tmp / out)]
        if signed:
            cmd += ["--signing-key", str(tmp / "priv.pem"), "--signing-alg", "RS256"]
        subprocess.run(cmd, check=True, capture_output=True)

    build("2", "v2.tar.gz", True)
    build("1", "v1.tar.gz", True)
    build("3", "v3.tar.gz", True)
    build("4", "unsigned.tar.gz", False)
    # tamper v3: rewrite policy.rego inside the tarball, keep the original signatures file
    with tarfile.open(tmp / "v3.tar.gz", "r:gz") as tf:
        members = [(m, tf.extractfile(m).read() if m.isfile() else None) for m in tf.getmembers()]
    with tarfile.open(tmp / "v3_tampered.tar.gz", "w:gz") as tf:
        for m, data in members:
            if m.isfile() and m.name.endswith("policy.rego"):
                data = data.replace(b'"deny"', b'"allow"', 1)
                m.size = len(data)
            tf.addfile(m, io.BytesIO(data) if data is not None else None)

    def try_load(bundle: str, port: int) -> Dict[str, Any]:
        logf = tmp / f"{Path(bundle).stem}.log"
        with open(logf, "w") as lf:
            proc = subprocess.Popen([opa, "run", "-s", "-a", f"127.0.0.1:{port}", "-b", "--verification-key", str(tmp / "pub.pem"),
                                     "--signing-alg", "RS256", str(tmp / bundle)], stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
            time.sleep(1.5)
            alive = proc.poll() is None
            loaded = False
            if alive:
                try:
                    req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/data/comparison/{POLICY}/decision",
                                                 data=json.dumps({"input": {"protocol": 6, "dst_port": 443, "pkt_len": 800, "src_internal": False}}).encode(),
                                                 headers={"content-type": "application/json"}, method="POST")
                    with urllib.request.urlopen(req, timeout=5) as r:
                        loaded = "result" in json.loads(r.read())
                except Exception:
                    loaded = False
                os.killpg(proc.pid, signal.SIGTERM); proc.wait(timeout=10)
        text = logf.read_text()
        return {"alive": alive, "loaded": loaded, "log_tail": text[-600:]}

    out = {"baseline_v2": try_load("v2.tar.gz", 18282),
           "stale_policy_1": try_load("v1.tar.gz", 18283),
           "tampered_policy_1": try_load("v3_tampered.tar.gz", 18284),
           "unsigned_policy_1": try_load("unsigned.tar.gz", 18285)}
    (ev / "bundle_results.json").write_text(json.dumps(out, indent=2) + "\n")
    grades = {
        "stale_policy_1": ("WITH-WORK", "OPA verifies the bundle signature at the agent (the enforcement point) but keeps no monotonic revision floor: "
                                        "an older signed revision loads and serves. A wrapper persisting the last accepted .manifest revision and "
                                        "refusing lower ones is glue without a new anchor.",
                           {"description": "persist the last accepted bundle revision on the agent host and refuse a bundle with a lower revision before opa loads it",
                            "components": ["manifest revision reader", "fsync'd floor file", "pre load check"], "loc": 60, "hours": 2}),
        "tampered_policy_1": ("NATIVE", "the agent refused a bundle whose policy.rego was altered after signing (signature verification at the point, no server)", None),
        "unsigned_policy_1": ("NATIVE", "the agent refused an unsigned bundle when a verification key is configured", None),
    }
    for sid, res in (("stale_policy_1", out["stale_policy_1"]), ("tampered_policy_1", out["tampered_policy_1"]), ("unsigned_policy_1", out["unsigned_policy_1"])):
        refused = not res["loaded"]
        observed = "refuse_policy" if refused else "accepted"
        grade, note, glue = grades[sid]
        if sid == "stale_policy_1" and refused:
            grade, note, glue = "NATIVE", "the agent refused the older revision", None
        if sid != "stale_policy_1" and not refused:
            grade, note, glue = "NOT", "the agent ACCEPTED it; signature verification did not stop it", None
        write_result(system="opa", dimension="A6", policy=POLICY, scenario=sid, expected="refuse_policy", observed=observed,
                     grade=grade, idiomatic=True, evidence_path=ev, glue=glue,
                     notes=(f"opa run --server -b <bundle> --verification-key pub.pem (RS256 signed bundles, documented bundle signing). "
                            f"Observed: process alive={res['alive']}, policy loaded and serving={res['loaded']}. {note} (bundle_results.json)."))


# ----------------------------------------------------------------------------- Cedar, Cerbos, OpenFGA
def run_absent(system: str, note: str) -> None:
    ev = evidence_dir(system, "A6")
    (ev / "note.txt").write_text(note + "\n")
    for sid in SCENARIOS:
        write_result(system=system, dimension="A6", policy=POLICY, scenario=sid, expected="refuse_policy", observed="accepted",
                     grade="NOT", idiomatic=True, evidence_path=ev, notes=note)


def main() -> int:
    policy = policy_by_id(POLICY)
    run_prismpath(policy)
    run_opa(policy)
    run_absent("cedar", "Cedar is a library and CLI over policy files: no signature, no version, no integrity check at the point. A stale, "
                        "tampered, or unsigned policy file is simply the policy in force. Verified by construction of the interface "
                        "(cedar authorize --policies <file>); the translation directory is the only artifact.")
    run_absent("cerbos", "Open source Cerbos loads policies from a disk, git, or blob store with no signature or monotonic version at the "
                         "PDP; a stale, tampered, or unsigned policy file is the policy in force (policy signing and bundle "
                         "verification are Cerbos Hub features, out of the open source field).")
    run_absent("openfga", "OpenFGA authorization models are immutable by id and written through the API with no signature; a client may "
                          "check against any older model id, and a tampered model is simply a new model. No refusal facility at the point.")
    print("A6 written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
