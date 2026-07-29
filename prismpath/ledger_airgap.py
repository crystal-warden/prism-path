#!/usr/bin/env python3
"""Air-gap attestation tier for the Flow-Ledger (task #53 / SPEC_ledger_opentimestamps.md §4, §6).

Extends the connected OTS engine (ledger_ots.py, #36) to disconnected deployments — the DIB/OT/
healthcare vertical where OTS calendars are unreachable. Implements the tiered, strongest-available
attestation from SPEC §4, plus the C1/C4 compensations from SPEC §6.

Tiers (strongest available wins; a deployment may use several):
  T0  connected      -> ledger_ots.anchor/upgrade (Bitcoin via calendars)          [ledger_ots.py]
  T1  batch-forward  -> export tiny hash-only request across the diode; stamp on a  [this module]
                        connected relay; carry .ots proofs back. Trustless like T0,
                        just latency-shifted through a maintenance window.
  T2  RFC-3161 TSA   -> internal trusted-timestamp appliance for fully-disconnected  [this module]
                        sites. Trusts a party (weaker than Bitcoin) but standards-
                        based, compliance-recognized, and works offline. Immediate.

Only high-entropy Merkle ROOTS ever cross the boundary (SPEC §4.1 / C4). C1 provenance
(POLICY_HASH + gate identity + ingestion hashes) travels in the request manifest so the chain of
custody is provable from ingestion, and *what logic ran* is bound, not just the output.
"""
import os, json, hashlib, subprocess, shutil, tarfile, datetime

_OTSENV = {**os.environ, "PATH": os.path.expanduser("~/.local/bin") + ":" + os.environ.get("PATH", "")}


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# C1 / C4 compensations (SPEC §6): bind logic + ingestion, salt low-entropy leaves.
# ---------------------------------------------------------------------------
def salt_leaf(leaf_hex, secret):
    """C4: HMAC a (possibly low-entropy, brute-forceable) unit hash with an in-enclave secret so a
    leaked hash can't be confirmed by guessing the content. Anchor the salted value instead."""
    import hmac
    return hmac.new(secret.encode() if isinstance(secret, str) else secret,
                    bytes.fromhex(leaf_hex), hashlib.sha256).hexdigest()


def provenance_manifest(root_hex, label, policy_hash=None, gate_id=None, ingestion_hashes=None,
                        knowledge_base_hash=None):
    """C1: the provable chain of custody that travels with the root. Binds WHAT LOGIC produced the
    record (policy_hash + gate_id), WHERE THE CHAIN STARTS (ingestion_hashes), and — for
    retrieval-augmented triage (#58) — WHICH KNOWLEDGE SNAPSHOT informed it (knowledge_base_hash),
    so a verdict is provable against the exact published-knowledge library that was retrieved from."""
    m = {"root": root_hex, "label": label, "created": _now_iso(),
         "policy_hash": policy_hash, "gate_id": gate_id, "knowledge_base_hash": knowledge_base_hash,
         "ingestion_hashes": list(ingestion_hashes or [])}
    # the manifest itself is content-addressed so it can't be silently edited post-anchor
    body = json.dumps({k: m[k] for k in m if k != "manifest_hash"}, sort_keys=True).encode()
    m["manifest_hash"] = hashlib.sha256(body).hexdigest()
    return m


def override_manifest(prior, overrider_id, rationale, new_root_hex, new_label=None):
    """Attest a HUMAN OVERRIDE of a prior automated decision as a SUPERSEDING commit. The prior manifest
    stays immutable; this binds its manifest_hash + the overrider + the rationale + the new decision, so
    the override trail is attested and auditable — who overrode what, when, and why, with the
    automated output PRESERVED, never erased. NOT "cryptographically provable": until the root is
    OTS-anchored (SPEC_ledger_opentimestamps.md §1), an adversary with filesystem access can rewrite
    the whole chain, and that spec's own §5 gates the stronger wording behind a passing
    stamp->upgrade->verify round-trip. Domain-neutral: a SOC analyst, a compliance auditor, or a
    tutor mentor superseding an automated call all use this same core capability."""
    m = {"kind": "override", "supersedes": prior["manifest_hash"], "prior_root": prior.get("root"),
         "prior_created": prior.get("created"), "overrider_id": overrider_id, "rationale": rationale,
         "root": new_root_hex, "label": new_label or ("override:" + str(prior.get("label", ""))),
         "created": _now_iso(),
         # carry forward the prior decision's provenance bindings so the chain stays complete
         "policy_hash": prior.get("policy_hash"), "gate_id": prior.get("gate_id"),
         "knowledge_base_hash": prior.get("knowledge_base_hash"),
         "ingestion_hashes": list(prior.get("ingestion_hashes", []))}
    body = json.dumps({k: m[k] for k in m if k != "manifest_hash"}, sort_keys=True).encode()
    m["manifest_hash"] = hashlib.sha256(body).hexdigest()
    return m


# ---------------------------------------------------------------------------
# T1 — batch-and-forward across the one-way boundary (SPEC §4.2)
# ---------------------------------------------------------------------------

def verify_manifest(m):
    """Recompute the content-address over every bound field and confirm it matches m['manifest_hash'].
    Any tampering with a bound field (root, policy_hash, gate_id, ingestion_hashes, knowledge_base_hash,
    supersedes, overrider_id, rationale, ...) flips this to False. This is what makes a manifest a
    tamper-evidence anchor rather than a mere label."""
    body = json.dumps({k: m[k] for k in m if k != "manifest_hash"}, sort_keys=True).encode()
    return hashlib.sha256(body).hexdigest() == m.get("manifest_hash")


def export_stamp_request(roots, out_bundle, policy_hash=None, gate_id=None, ingestion_hashes=None):
    """IN-ENCLAVE (no internet). `roots` = list of (rootfile_path, label). Package ONLY the root
    files + a provenance manifest into a small tar the one-way review process can pass. No sensitive
    payload crosses — just high-entropy roots + hashes (SPEC §4.1)."""
    staging = out_bundle + ".d"
    if os.path.isdir(staging):
        shutil.rmtree(staging)
    os.makedirs(staging)
    entries = []
    for rootfile, label in roots:
        root_hex = open(rootfile).read().strip()
        dst = os.path.join(staging, f"root_{label}.txt")
        shutil.copyfile(rootfile, dst)
        entries.append(provenance_manifest(root_hex, label, policy_hash, gate_id, ingestion_hashes))
    req = {"kind": "cw-stamp-request", "created": _now_iso(), "n": len(entries), "entries": entries}
    with open(os.path.join(staging, "request.json"), "w") as f:
        json.dump(req, f, indent=1)
    with tarfile.open(out_bundle, "w:gz") as t:
        t.add(staging, arcname="cw-stamp-request")
    shutil.rmtree(staging)
    return {"bundle": out_bundle, "n": len(entries),
            "bundle_sha256": _sha256_file(out_bundle),
            "roots": [e["root"] for e in entries]}


def relay_stamp(request_bundle, out_bundle):
    """ON A CONNECTED RELAY (has internet, holds NO enclave secrets). Unpack the request, `ots stamp`
    each root, package the .ots proofs to carry back. Trustless: the relay only sees random-looking
    roots, never enclave data."""
    work = out_bundle + ".relay.d"
    if os.path.isdir(work):
        shutil.rmtree(work)
    os.makedirs(work)
    with tarfile.open(request_bundle, "r:gz") as t:
        t.extractall(work)
    src = os.path.join(work, "cw-stamp-request")
    req = json.load(open(os.path.join(src, "request.json")))
    stamped = []
    for e in req["entries"]:
        rootfile = os.path.join(src, f"root_{e['label']}.txt")
        r = subprocess.run(["ots", "stamp", rootfile], capture_output=True, text=True, env=_OTSENV)
        ok = os.path.exists(rootfile + ".ots")
        stamped.append({"label": e["label"], "root": e["root"], "stamped": ok,
                        "ots": (r.stdout + r.stderr).strip()[-200:]})
    # proof bundle carries back ONLY the .ots proofs + a receipt (echoes provenance for the audit trail)
    pack = out_bundle + ".d"
    if os.path.isdir(pack):
        shutil.rmtree(pack)
    os.makedirs(pack)
    for e in req["entries"]:
        p = os.path.join(src, f"root_{e['label']}.txt.ots")
        if os.path.exists(p):
            shutil.copyfile(p, os.path.join(pack, f"root_{e['label']}.txt.ots"))
    json.dump({"kind": "cw-proof-bundle", "created": _now_iso(),
               "request_created": req["created"], "stamped": stamped},
              open(os.path.join(pack, "receipt.json"), "w"), indent=1)
    with tarfile.open(out_bundle, "w:gz") as t:
        t.add(pack, arcname="cw-proof-bundle")
    shutil.rmtree(pack); shutil.rmtree(work)
    return {"bundle": out_bundle, "stamped": stamped}


def import_proofs(proof_bundle, roots_dir):
    """BACK IN-ENCLAVE. Place the returned .ots proofs beside their roots so verification is
    self-contained from the ledger (SPEC §6/C3)."""
    work = os.path.join(roots_dir, ".import.d")
    if os.path.isdir(work):
        shutil.rmtree(work)
    os.makedirs(work)
    with tarfile.open(proof_bundle, "r:gz") as t:
        t.extractall(work)
    src = os.path.join(work, "cw-proof-bundle")
    receipt = json.load(open(os.path.join(src, "receipt.json")))
    placed = []
    for fn in os.listdir(src):
        if fn.endswith(".ots"):
            shutil.copyfile(os.path.join(src, fn), os.path.join(roots_dir, fn))
            placed.append(fn)
    shutil.rmtree(work)
    return {"placed": placed, "receipt": receipt}


# ---------------------------------------------------------------------------
# T2 — RFC-3161 trusted-timestamp tier for fully-disconnected sites (SPEC §4.3)
# ---------------------------------------------------------------------------
def rfc3161_query(rootfile, out_tsq=None):
    """Build an RFC-3161 timestamp REQUEST over a root (offline; no network). This is what crosses to
    an internal TSA appliance."""
    out_tsq = out_tsq or rootfile + ".tsq"
    r = subprocess.run(["openssl", "ts", "-query", "-data", rootfile, "-sha256", "-cert", "-out", out_tsq],
                       capture_output=True, text=True)
    return {"tsq": out_tsq, "ok": os.path.exists(out_tsq), "err": r.stderr.strip()[-200:]}


def rfc3161_verify(rootfile, tsr, cafile):
    """Verify an RFC-3161 response against the root and the TSA's CA (offline, self-contained)."""
    r = subprocess.run(["openssl", "ts", "-verify", "-data", rootfile, "-in", tsr, "-CAfile", cafile],
                       capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    return {"verified": "OK" in out, "detail": out[-200:]}


def make_test_tsa(dirpath):
    """Stand up a throwaway local RFC-3161 TSA (CA + timestamping cert) so the offline tier can be
    validated end-to-end with NO internet — the exact air-gapped condition. Returns paths + a signer
    callable that plays the appliance role."""
    os.makedirs(dirpath, exist_ok=True)
    ca_key = os.path.join(dirpath, "ca.key"); ca_crt = os.path.join(dirpath, "ca.crt")
    tsa_key = os.path.join(dirpath, "tsa.key"); tsa_csr = os.path.join(dirpath, "tsa.csr")
    tsa_crt = os.path.join(dirpath, "tsa.crt"); cnf = os.path.join(dirpath, "tsa.cnf")
    serial = os.path.join(dirpath, "serial")
    with open(serial, "w") as f:
        f.write("01\n")
    ext = os.path.join(dirpath, "tsa_ext.cnf")
    with open(ext, "w") as f:
        f.write("[v3_tsa]\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n")
    with open(cnf, "w") as f:
        f.write(
            "[tsa]\ndefault_tsa=tsa_config\n[tsa_config]\n"
            f"serial={serial}\ncrypto_device=builtin\n"
            f"signer_cert={tsa_crt}\ncerts={tsa_crt}\nsigner_key={tsa_key}\n"
            "signer_digest=sha256\n"
            "default_policy=1.2.3.4.1\ndigests=sha256,sha1\naccuracy=secs:1\n"
            "ordering=yes\ntsa_name=yes\n")
    run = lambda a: subprocess.run(a, capture_output=True, text=True)
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", ca_key, "-out", ca_crt,
         "-days", "3650", "-nodes", "-subj", "/CN=CW Test Root CA"])
    run(["openssl", "req", "-newkey", "rsa:2048", "-keyout", tsa_key, "-out", tsa_csr,
         "-nodes", "-subj", "/CN=CW Internal TSA"])
    run(["openssl", "x509", "-req", "-in", tsa_csr, "-CA", ca_crt, "-CAkey", ca_key,
         "-set_serial", "2", "-days", "3650", "-extfile", ext, "-extensions", "v3_tsa", "-out", tsa_crt])

    def sign(tsq, out_tsr):
        r = run(["openssl", "ts", "-reply", "-queryfile", tsq, "-config", cnf, "-out", out_tsr])
        return {"tsr": out_tsr, "ok": os.path.exists(out_tsr), "err": (r.stdout + r.stderr).strip()[-200:]}

    return {"ca_crt": ca_crt, "tsa_crt": tsa_crt, "cnf": cnf, "sign": sign}


# ---------------------------------------------------------------------------
# Self-test — exercises T1 packaging + T2 full RFC-3161 round-trip OFFLINE.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile
    d = tempfile.mkdtemp(prefix="cw_airgap_")
    # a fake high-entropy root
    rootfile = os.path.join(d, "root_demo.txt")
    with open(rootfile, "w") as f:
        f.write(hashlib.sha256(b"demo-merkle-root").hexdigest())
    out = {}

    # --- C1 manifest ---
    m = provenance_manifest(open(rootfile).read().strip(), "demo",
                            policy_hash="sha256:deadbeef", gate_id="wazuh_triage@v3",
                            ingestion_hashes=["sha256:aa", "sha256:bb"], knowledge_base_hash="sha256:kb26e3")
    out["C1_manifest_binds_policy_and_ingestion"] = bool(m["policy_hash"] and m["ingestion_hashes"] and m["manifest_hash"])
    out["C1_manifest_binds_knowledge_base"] = m["knowledge_base_hash"] == "sha256:kb26e3"

    # --- override chain (a human supersedes an automated decision, immutably) ---
    ov = override_manifest(m, overrider_id="auditor:jsmith", rationale="compensating control accepted",
                           new_root_hex=hashlib.sha256(b"override-decision").hexdigest())
    out["override_supersedes_prior"] = ov["supersedes"] == m["manifest_hash"]
    out["override_preserves_prior_root_and_actor"] = bool(ov["prior_root"] == m["root"] and ov["overrider_id"] and ov["rationale"])

    # --- C4 salt ---
    leaf = hashlib.sha256(b"logon success user=admin").hexdigest()
    out["C4_salt_changes_hash"] = salt_leaf(leaf, "enclave-secret") != leaf

    # --- T1 batch-forward packaging round-trip (relay stamp needs internet; packaging is offline) ---
    req = export_stamp_request([(rootfile, "demo")], os.path.join(d, "req.tar.gz"),
                               policy_hash="sha256:deadbeef", gate_id="wazuh_triage@v3")
    out["T1_request_bundle_built"] = req["n"] == 1 and os.path.exists(req["bundle"])
    out["T1_only_roots_cross"] = req["roots"] == [open(rootfile).read().strip()]

    # --- T2 RFC-3161 full round-trip, fully offline ---
    tsa = make_test_tsa(os.path.join(d, "tsa"))
    q = rfc3161_query(rootfile)
    out["T2_query_built"] = q["ok"]
    tsr = os.path.join(d, "root_demo.tsr")
    s = tsa["sign"](q["tsq"], tsr)
    out["T2_tsa_signed"] = s["ok"]
    v = rfc3161_verify(rootfile, tsr, tsa["ca_crt"])
    out["T2_offline_verify"] = v["verified"]
    out["T2_verify_detail"] = v["detail"]
    # tamper check: verifying a DIFFERENT root against the same proof must FAIL
    badroot = os.path.join(d, "bad.txt")
    with open(badroot, "w") as f:
        f.write(hashlib.sha256(b"tampered").hexdigest())
    out["T2_tamper_rejected"] = not rfc3161_verify(badroot, tsr, tsa["ca_crt"])["verified"]

    print(json.dumps(out, indent=1))
    shutil.rmtree(d, ignore_errors=True)
