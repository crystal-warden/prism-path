# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Re-run of condition C of docs/research/facet-model-reading.md against the Facet MCP server's tools
(prismpath/telemetry/facet_mcp.py), on the same streams, policies and seeds as tools/facet_model_reading.py.

    PYTHONPATH=. python tools/facet_mcp_reading.py runs.jsonl [--reps 5] [--only D,E,S,U] [--lengths 1,8,64]
    PYTHONPATH=. python tools/facet_mcp_summarize.py runs.jsonl results/facet_mcp_reading_2026-11-20.json

D  the baseline's question, answered with the server's facet_describe and facet_decode (full form: every cell with
   its index and meaning) and the epoch's Merkle root in the binding.
E  as D, with facet_decode asked for its compact form (the index list and decision per reading).
S  the summary question: the decision distribution, the cells that appear in each field, and the exception
   readings (every reading whose decision is not the default), through facet_summary.
U  tamper tests with the server: a detectable flip, a silent flip, and a wrong hash, each with the root in the
   binding, and a silent flip with no root in the binding.

The policies are signed with a throwaway authority key into a temporary registry, and the server serves only
those. The model is the local vLLM server (gemma4), at most 4 requests at once, no outside API.
"""
import argparse
import concurrent.futures as cf
import json
import os
import random
import shutil
import tempfile
import threading
import time

from prismpath.hotswap import flow_authority, policy_pack
from prismpath.telemetry import facet_mcp, packed, selfheal
from tools.facet_model_reading import ANSWER, POLICIES, chat, extract_json, make_stream, score, tamper
from tools.facet_model_reading import key as _key

FORMAT = facet_mcp.FORMAT
BLOCK_BITS = 64
TOOL_SPECS = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                "parameters": t["inputSchema"]}} for t in facet_mcp.TOOLS]

SYSTEM = ("You read Facet telemetry streams. A stream carries no header, no field names and no codebook; the "
          "codebook comes from the signed policy named in the binding. Use the tools you are given. The binding "
          "also names the epoch's Merkle root; pass it to every tool call so the stream is checked.")

INTEGRITY_LINE = ('\nAlso add "integrity": the integrity status the tool reported ("checked" or "unchecked"), or '
                  'null if no tool answered.')
SUMMARY_ANSWER = """Reply with only a JSON object, no other text:
{"decision_distribution": {"<decision>": <how many readings>},
 "cells_present": {"<field>": [<the 0-based cell indices that appear in that field, ascending>]},
 "exceptions": [<the 0-based reading numbers of every exception reading, ascending>],
 "integrity": "<checked or unchecked, as the tool reported>",
 "error": null}
If you cannot read the stream, or a tool refuses it, give "decision_distribution": {} and put the reason in "error".
Do not guess."""


def make_registry(directory):
    """Sign the three policies with a throwaway authority key into `directory`. Returns the registry."""
    keys = policy_pack.keygen(os.path.join(directory, "keys"))
    reg = os.path.join(directory, "registry")
    os.makedirs(reg)
    for path in POLICIES.values():
        dst = os.path.join(reg, os.path.basename(path))
        shutil.copy(path, dst)
        if dst.endswith(".md"):
            flow_authority.sign_flow(dst, 1, keys["private"], keys["public"])
        else:
            facet_mcp.sign_image(dst, keys["private"], keys["public"])
    return facet_mcp.Registry(reg, [keys["public"]])


def epoch_root(data):
    return selfheal.commit(selfheal.chunk(packed.unpack(data), BLOCK_BITS))[0]


def summary_truth(policy, truth):
    decisions = [t["decision"] for t in truth]
    dist = {}
    for d in decisions:
        dist[d] = dist.get(d, 0) + 1
    base = policy.default if policy.default is not None else max(sorted(dist), key=lambda k: dist[k])
    return {"distribution": dist, "base": base,
            "exceptions": [i for i, d in enumerate(decisions) if d != base],
            "cells": {f: sorted({t["cells"][k] for t in truth}) for k, f in enumerate(policy.order)}}


def score_summary(policy, truth, text):
    ans = extract_json(text)
    st = summary_truth(policy, truth)
    s = {"n_truth": len(truth), "parsed": ans is not None, "dist_ok": False, "exceptions_ok": False,
         "cells_fields_ok": 0, "cells_fields": len(policy.order), "exceptions_truth": len(st["exceptions"]),
         "exceptions_missed": 0, "exceptions_false": 0, "abstained": False, "error": None, "integrity": None,
         "base": st["base"]}
    if ans is None:
        return s
    s["error"], s["integrity"] = ans.get("error"), ans.get("integrity")
    dist = ans.get("decision_distribution")
    s["abstained"] = not dist
    s["dist_ok"] = isinstance(dist, dict) and {k: v for k, v in dist.items()} == st["distribution"]
    exc = ans.get("exceptions")
    if isinstance(exc, list) and all(isinstance(x, int) for x in exc):
        s["exceptions_ok"] = sorted(set(exc)) == st["exceptions"]
        s["exceptions_missed"] = len(set(st["exceptions"]) - set(exc))
        s["exceptions_false"] = len(set(exc) - set(st["exceptions"]))
    cells = ans.get("cells_present")
    if isinstance(cells, dict):
        s["cells_fields_ok"] = sum(1 for f in policy.order
                                   if isinstance(cells.get(f), list) and sorted(cells[f]) == st["cells"][f])
    return s


def prompt(cond, policy, data, binding_hash, with_root=True):
    root = (f" epoch_merkle_root={epoch_root(data)} block_bits={BLOCK_BITS}" if with_root else "")
    head = f"Out of band binding: format={FORMAT} policy_sha256={binding_hash} epoch=1{root}\n\nStream (hex):\n{data.hex()}\n\n"
    if cond == "S":
        return (head + "How is this stream distributed? Use facet_summary, with its default exception rule (do not "
                "name a decision). Report the decision distribution, the cells that appear in each field, and the "
                "exception readings the tool lists.\n\n" + SUMMARY_ANSWER)
    how = ('Use the tools. Call facet_decode with format "compact".' if cond == "E" else "Use the tools.")
    return head + f"What does this say? {how}\n\n{ANSWER}{INTEGRITY_LINE}"


def run_one(job, registry, policies):
    cond, pname, n, rep = job["cond"], job["policy"], job["n"], job["rep"]
    policy = policies[pname]
    data, truth = make_stream(policy, n, rep)
    binding_hash, with_root, tamper_info = policy.sha256, True, None
    shown = data
    if cond == "U":
        variant = job["variant"]
        if variant == "wrong_hash":
            binding_hash = [p for k, p in policies.items() if k != pname][rep % 2].sha256
        else:
            t = tamper(policy, data, "detectable" if variant == "detectable" else "silent",
                       random.Random(f"t{rep}{pname}"))
            if t is None:
                return {**job, "skipped": "no bit flip of that kind exists"}
            tamper_info = {"bit": t[0]}
            with_root = variant != "silent_noroot"
            # the root in the binding is the sealed epoch's: the original stream's, not the flipped one's
            root_of_original = epoch_root(data)
            shown = t[1]
    p = prompt("D" if cond == "U" else cond, policy, shown, binding_hash, with_root)
    if cond == "U" and with_root:
        p = p.replace(epoch_root(shown), root_of_original)
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": p}]
    server = facet_mcp.FacetServer(registry, policy.sha256)
    mt = (1500 + n * 12) if cond == "S" else 400 + n * (len(policy.order) * 3 + 12) + 1500
    t0 = time.time()
    try:
        text, usage, tool_log, finish = chat(messages, TOOL_SPECS, mt, server=server)
        err = None
    except Exception as e:  # noqa: BLE001
        text, usage, tool_log, finish, err = "", {"prompt": 0, "completion": 0, "calls": 0}, [], "exception", repr(e)
    if cond == "S":
        sc = score_summary(policy, truth, text)
    else:
        sc = score(policy, truth, text)
        ans = extract_json(text) or {}
        sc["integrity"] = ans.get("integrity")
    return {**job, "tamper": tamper_info, "answer": text, "usage": usage, "tool_log": tool_log, "finish": finish,
            "exception": err, "seconds": round(time.time() - t0, 1), "score": sc, "hex_len": len(shown) * 2}


def jobs(only, reps, lengths):
    out = []
    for n in lengths:
        for rep in range(reps):
            for pname in POLICIES:
                for cond in ("D", "E", "S"):
                    if cond in only:
                        out.append({"cond": cond, "policy": pname, "n": n, "rep": rep})
    if "U" in only:
        for pname in POLICIES:
            for rep in range(reps):
                for variant in ("detectable", "silent", "wrong_hash", "silent_noroot"):
                    out.append({"cond": "U", "policy": pname, "n": 8, "rep": rep, "variant": variant})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--only", default="D,E,S,U")
    ap.add_argument("--lengths", default="1,8,64")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    policies = {k: facet_mcp.Policy(v) for k, v in POLICIES.items()}
    tmp = tempfile.mkdtemp(prefix="facet_mcp_reading_")
    registry = make_registry(tmp)
    for p in policies.values():       # the registry serves exactly the bytes the harness drew its truth from
        assert registry.get(p.sha256).sha256 == p.sha256
    try:
        done = {_key(json.loads(line)) for line in open(a.out)}
    except FileNotFoundError:
        done = set()
    todo = [j for j in jobs(a.only.split(","), a.reps, [int(x) for x in a.lengths.split(",")]) if _key(j) not in done]
    print(f"{len(todo)} runs to do", flush=True)
    lock = threading.Lock()
    with cf.ThreadPoolExecutor(min(a.workers, 4)) as ex, open(a.out, "a") as f:
        for fut in cf.as_completed([ex.submit(run_one, j, registry, policies) for j in todo]):
            r = fut.result()
            with lock:
                f.write(json.dumps(r) + "\n")
                f.flush()
            sc = r.get("score", {})
            print(_key(r), r.get("finish"), r.get("usage", {}).get("completion"), r.get("seconds"),
                  sc.get("both_ok", sc.get("dist_ok")), "/", sc.get("n_truth"), flush=True)


if __name__ == "__main__":
    main()
