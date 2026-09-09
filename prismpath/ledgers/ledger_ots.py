#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""OpenTimestamps anchoring for the Flow-Ledger (task #36 / docs/design/spec-ledger-opentimestamps.md).

Upgrades the ledger from ACCIDENT-tamper-evident to ADVERSARIAL temporal integrity: batches the
per-unit `PrismPath-Output-Hash` values into a Merkle tree, stamps the single ROOT via OpenTimestamps
(free Bitcoin anchoring via calendar servers), and stores per-unit inclusion proofs. Verification
walks: output-hash -> Merkle path -> root -> OTS proof -> Bitcoin block time. Out-of-band by design
(network I/O), so the pure engine is never touched. Two-phase: stamp returns a PENDING calendar proof
immediately; `upgrade` promotes it to a full Bitcoin proof after ~1-6h.
"""
import hashlib, os, json, subprocess, glob

_OTSENV = {**os.environ, "PATH": os.path.expanduser("~/.local/bin") + ":" + os.environ.get("PATH", "")}
def _h(b): return hashlib.sha256(b).digest()

def merkle_root_and_paths(leaves_hex):
    """Bitcoin-style Merkle (duplicate last if odd). -> (root_hex, [path per leaf])."""
    if not leaves_hex: return None, []
    layers=[[bytes.fromhex(h) for h in leaves_hex]]
    while len(layers[-1])>1:
        cur=layers[-1][:]
        if len(cur)%2: cur=cur+[cur[-1]]
        layers.append([_h(cur[i]+cur[i+1]) for i in range(0,len(cur),2)])
    root=layers[-1][0]
    def path(idx):
        p=[]
        for lvl in range(len(layers)-1):
            L=layers[lvl][:]
            if len(L)%2: L=L+[L[-1]]
            p.append(("R", L[idx+1].hex()) if idx%2==0 else ("L", L[idx-1].hex()))
            idx//=2
        return p
    return root.hex(), [path(i) for i in range(len(leaves_hex))]

def verify_leaf(leaf_hex, path, root_hex):
    cur=bytes.fromhex(leaf_hex)
    for side,sib in path:
        s=bytes.fromhex(sib); cur=_h(cur+s) if side=="R" else _h(s+cur)
    return cur.hex()==root_hex

def from_ledger(ledger_repo, ref="refs/prismpath/runs"):
    """Enumerate PrismPath-Output-Hash values from a Flow-Ledger bare repo (git log trailers)."""
    env={**os.environ, "GIT_DIR":ledger_repo}
    refs=subprocess.run(["git","for-each-ref","--format=%(refname)",ref],capture_output=True,text=True,env=env).stdout.split()
    out=[]
    for r in refs:
        log=subprocess.run(["git","log","--format=%(trailers:key=PrismPath-Output-Hash,valueonly)",r],capture_output=True,text=True,env=env).stdout
        out+=[l.strip() for l in log.splitlines() if l.strip()]
    return out

def anchor(hashes, out_dir, label):
    """Build Merkle root over `hashes`, write root file + manifest, and OTS-stamp the root."""
    os.makedirs(out_dir, exist_ok=True)
    root,paths=merkle_root_and_paths(hashes)
    rootfile=os.path.join(out_dir, f"root_{label}.txt"); open(rootfile,"w").write(root+"\n")
    json.dump(dict(label=label, root=root, n=len(hashes), leaves={h:paths[i] for i,h in enumerate(hashes)}),
              open(os.path.join(out_dir,f"manifest_{label}.json"),"w"), indent=2)
    r=subprocess.run(["ots","stamp",rootfile],capture_output=True,text=True,env=_OTSENV)
    return dict(root=root, n=len(hashes), rootfile=rootfile, stamped=os.path.exists(rootfile+".ots"),
                ots_msg=(r.stdout+r.stderr).strip()[-200:])

def upgrade(out_dir, label):
    r=subprocess.run(["ots","upgrade",os.path.join(out_dir,f"root_{label}.txt.ots")],capture_output=True,text=True,env=_OTSENV)
    return (r.stdout+r.stderr).strip()[-200:]

def verify_unit(leaf_hex, out_dir, label):
    """Full chain: Merkle path to the anchored root, then OTS-verify the root against Bitcoin."""
    m=json.load(open(os.path.join(out_dir,f"manifest_{label}.json")))
    path=m["leaves"].get(leaf_hex)
    if path is None: return dict(merkle_ok=False, reason="output-hash not in this anchor batch")
    merkle_ok=verify_leaf(leaf_hex, path, m["root"])
    r=subprocess.run(["ots","verify",os.path.join(out_dir,f"root_{label}.txt.ots")],capture_output=True,text=True,env=_OTSENV)
    return dict(merkle_ok=merkle_ok, root=m["root"], ots_verify=(r.stdout+r.stderr).strip()[-300:])
