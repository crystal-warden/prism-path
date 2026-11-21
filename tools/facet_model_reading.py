# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Can a model read a Facet stream? Three conditions over the same streams, scored against exact truth.

    PYTHONPATH=. python tools/facet_model_reading.py runs.jsonl [--reps 5] [--only A,B,C,T] [--lengths 1,8,64]
    PYTHONPATH=. python tools/facet_model_reading.py runs.jsonl [--reps 5] [--only A,B,C,T] [--lengths 1,8,64]
    PYTHONPATH=. python tools/facet_model_summarize.py runs.jsonl results/facet_model_reading_2026-11-20.json

A  the bare stream as hex.
B  the stream plus the signed policy text and a short statement of the wire rules. No tools.
C  the stream plus an out of band binding (format, policy sha256, epoch) and two tools, facet_describe and
   facet_decode (tools/facet_model_tools.py), reached through function calling.
T  C with a tampered stream (a detectable bit flip, and one the codec cannot see) and with a wrong hash in the binding.

The model is the local vLLM server, at most 4 requests at once, temperature as the server sets it.
"""
import argparse
import concurrent.futures as cf
import json
import random
import re
import sys
import threading
import time
import urllib.request

from tools.facet_model_tools import FORMAT, FacetServer, Policy, TOOL_SPECS, Refused

URL = "http://localhost:8888/v1/chat/completions"
POLICIES = {
    "fusion_triage": "adapters/fusion/flows/fusion_triage.md",
    "demo_input": "prismpath-hw/demo/flows/demo_input.md",
    "intent_calls": "integrations/governed_intent/policy/intent_calls.core.json",
}
LENGTHS = (1, 8, 64)

ANSWER = """Reply with only a JSON object, no other text:
{"field_order": [<the field names, in the order the stream sends them>],
 "readings": [{"cells": [<for each field in field_order, the 0-based index of the cell the reading falls in>],
               "decision": "<the decision the policy makes on that reading>"}],
 "error": null}
Give one entry in "readings" per reading in the stream. If you cannot read the stream, or a tool refuses it, give
"readings": [] and put the reason in "error". Do not guess."""

WIRE_RULES = """How a Facet stream is built (format facet/1):
- A reading is one cell per field, sent in the order of the field names sorted alphabetically.
- A cell is sent as the Fibonacci (Zeckendorf) code of (cell index + 1). The code is the Zeckendorf bits, lowest
  Fibonacci number first (1, 2, 3, 5, 8, ...), followed by a 1, so every code ends in 11 and 11 appears nowhere
  else. 1 -> 11, 2 -> 011, 3 -> 0011, 4 -> 1011, 5 -> 00011.
- Readings are concatenated with nothing between them. The bits are packed most significant bit first into bytes
  and the end is padded with zero bits.
- Cells of a field come from the conditions in the policy. Numeric fields: every constant in a condition is a cut
  point; cells run in ascending order and neighbouring cells no condition can tell apart are one cell. Categorical
  fields: the string constants in order of first appearance, then one cell for any other value. Boolean fields:
  false is cell 0, true is cell 1. A field that allows absence has a last cell for absent.
- The decision is the target of the first edge, read from the top, whose condition holds at the node named below."""

SYSTEM_C = ("You read Facet telemetry streams. A stream carries no header, no field names and no codebook; the "
            "codebook comes from the signed policy named in the binding. Use the tools you are given.")


def post(body, timeout=1500):
    req = urllib.request.Request(URL, json.dumps(body).encode(), {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


NATIVE = re.compile(r"<\|tool_call>call:(\w+)\{(.*?)\}<tool_call\|>", re.S)
NATIVE_ARG = re.compile(r'(\w+):(?:<\|"\|>(.*?)<\|"\|>|(-?\d+|true|false))', re.S)


def native_args(text):
    """Gemma's native call arguments: strings between <|"|> marks, bare integers and booleans."""
    out = {}
    for key, string, bare in NATIVE_ARG.findall(text):
        out[key] = string if bare == "" and (string or f"{key}:<|\"|>" in text) else json.loads(bare)
    return out


def native_calls(content):
    return [{"function": {"name": m.group(1), "arguments": json.dumps(native_args(m.group(2)))}}
            for m in NATIVE.finditer(content)]


def chat(messages, tools=None, max_tokens=2000, max_turns=6, server=None):
    usage = {"prompt": 0, "completion": 0, "calls": 0}
    tool_log = []
    finish = None
    for _ in range(max_turns):
        body = {"model": "gemma4", "messages": messages, "max_tokens": max_tokens}
        if tools:
            body["tools"] = tools
        resp = post(body)
        usage["calls"] += 1
        usage["prompt"] += resp["usage"]["prompt_tokens"]
        usage["completion"] += resp["usage"]["completion_tokens"]
        msg = resp["choices"][0]["message"]
        finish = resp["choices"][0]["finish_reason"]
        content = msg.get("content") or ""
        calls = msg.get("tool_calls") or []
        if not calls:                  # the served vLLM has no tool parser: read Gemma's native call text ourselves
            calls = native_calls(content)
        if not calls:
            messages.append({"role": "assistant", "content": content})
            return content, usage, tool_log, finish
        messages.append({"role": "assistant", "content": content})
        results = []
        for tc in calls:
            name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"]["arguments"] or "{}")
            except json.JSONDecodeError:
                args = {}
            out = server.call(name, args)
            results.append(f"[result of {name}]\n{out}")
            tool_log.append({"name": name, "args": {k: (v[:20] + "..." if isinstance(v, str) and len(v) > 40 else v)
                                                    for k, v in args.items()},
                             "refused": '"error":"refused"' in out})
        messages.append({"role": "user", "content": "\n\n".join(results)})
    return "", usage, tool_log, "turn-limit"


# ------------------------------------------------------------------ truth and scoring
def make_stream(policy, n, seed):
    rng = random.Random(f"{policy.sha256}:{n}:{seed}")
    syms = [{f: rng.randrange(policy.parts[f].n) for f in policy.order} for _ in range(n)]
    readings = [{f: policy.parts[f].cells[s[f]]["rep"] for f in policy.order} for s in syms]
    data = policy.encode(readings)
    truth = [{"cells": [s[f] for f in policy.order], "decision": policy.decision(r)} for s, r in zip(syms, readings)]
    return data, truth


def extract_json(text):
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    cand = m.group(1) if m else text[text.find("{"): text.rfind("}") + 1] if "{" in text else ""
    try:
        return json.loads(cand)
    except (json.JSONDecodeError, ValueError):
        return None


def score(policy, truth, text):
    """Per reading: cells all correct, decision correct. Invented: field names the policy lacks, readings beyond the
    stream, decisions the node cannot make."""
    ans = extract_json(text)
    s = {"n_truth": len(truth), "parsed": ans is not None, "cells_ok": 0, "decision_ok": 0, "both_ok": 0,
         "invented_fields": 0, "invented_decisions": 0, "extra_readings": 0, "abstained": False, "error": None}
    if ans is None:
        return s
    s["error"] = ans.get("error")
    order = ans.get("field_order") if isinstance(ans.get("field_order"), list) else []
    s["invented_fields"] = len([f for f in order if f not in policy.parts])
    readings = ans.get("readings") if isinstance(ans.get("readings"), list) else []
    if not readings:
        s["abstained"] = True
    s["extra_readings"] = max(0, len(readings) - len(truth))
    # a model may order fields differently from the policy's canonical order, so map by name
    for i, t in enumerate(truth):
        if i >= len(readings) or not isinstance(readings[i], dict):
            continue
        r = readings[i]
        cells = r.get("cells")
        ok_c = False
        if isinstance(cells, list) and order and len(cells) == len(order):
            got = dict(zip(order, cells))
            ok_c = all(got.get(f) == c for f, c in zip(policy.order, t["cells"]))
        elif isinstance(cells, list) and not order:
            ok_c = cells == t["cells"]
        ok_d = r.get("decision") == t["decision"]
        s["cells_ok"] += ok_c
        s["decision_ok"] += ok_d
        s["both_ok"] += ok_c and ok_d
    for r in readings:
        d = r.get("decision") if isinstance(r, dict) else None
        if d is not None and d not in policy.targets:
            s["invented_decisions"] += 1
    return s


# ------------------------------------------------------------------ one run
def prompt_for(cond, policy, data, binding_hash=None, epoch=1):
    hexs = data.hex()
    if cond == "A":
        return f"Here is a byte stream in hex:\n{hexs}\n\nWhat does this say?\n\n{ANSWER}", None
    if cond == "B":
        return (f"Here is a signed policy.\n\n<policy>\n{policy.text}\n</policy>\n\n{WIRE_RULES}\nThe decision node is "
                f"'{policy.node}'.\n\nThe following hex is a Facet stream encoded under that policy:\n{hexs}\n\n"
                f"What does it say?\n\n{ANSWER}", None)
    return (f"Out of band binding: format={FORMAT} policy_sha256={binding_hash} epoch={epoch}\n\n"
            f"Stream (hex):\n{hexs}\n\nWhat does this say? Use the tools.\n\n{ANSWER}", True)


def tamper(policy, data, kind, rng):
    """Flip one bit chosen so the codec does (detectable) or does not (silent) refuse the result."""
    cands = []
    for i in range(len(data) * 8):
        x = bytearray(data)
        x[i // 8] ^= 0x80 >> (i % 8)
        try:
            policy.symbols(bytes(x))
            silent = True
        except Refused:
            silent = False
        if silent == (kind == "silent"):
            cands.append((i, bytes(x)))
    return rng.choice(cands) if cands else None


def run_one(job, policies):
    cond, pname, n, rep = job["cond"], job["policy"], job["n"], job["rep"]
    policy = policies[pname]
    data, truth = make_stream(policy, n, rep)
    mt = 400 + n * (len(policy.order) * 3 + 12)
    tamper_info = None
    binding_hash = policy.sha256
    if cond == "T":
        variant = job["variant"]
        if variant == "wrong_hash":
            other = [p for k, p in policies.items() if k != pname][rep % 2]
            binding_hash = other.sha256
        else:
            t = tamper(policy, data, variant, random.Random(f"t{rep}{pname}"))
            if t is None:
                return {**job, "skipped": "no bit flip of that kind exists"}
            tamper_info = {"bit": t[0]}
            data = t[1]
    c_like = cond in ("C", "T")
    prompt, use_tools = prompt_for("C" if c_like else cond, policy, data, binding_hash)
    messages = [{"role": "user", "content": prompt}]
    server = None
    if c_like:
        messages.insert(0, {"role": "system", "content": SYSTEM_C})
        server = FacetServer(list(policies.values()), policy.sha256)
        mt += 1500
    t0 = time.time()
    try:
        text, usage, tool_log, finish = chat(messages, TOOL_SPECS if c_like else None, mt, server=server)
        err = None
    except Exception as e:  # noqa: BLE001
        text, usage, tool_log, finish, err = "", {"prompt": 0, "completion": 0, "calls": 0}, [], "exception", repr(e)
    return {**job, "tamper": tamper_info, "answer": text, "usage": usage, "tool_log": tool_log, "finish": finish,
            "exception": err, "seconds": round(time.time() - t0, 1), "score": score(policy, truth, text),
            "hex_len": len(data) * 2}


def jobs(only, reps, lengths):
    out = []
    for n in lengths:
        for rep in range(reps):
            for pname in POLICIES:
                for cond in ("A", "B", "C"):
                    if cond in only:
                        out.append({"cond": cond, "policy": pname, "n": n, "rep": rep})
    if "T" in only:
        for pname in POLICIES:
            for rep in range(reps):
                for variant in ("detectable", "silent", "wrong_hash"):
                    out.append({"cond": "T", "policy": pname, "n": 8, "rep": rep, "variant": variant})
    return out


def key(j):
    return (j["cond"], j["policy"], j["n"], j["rep"], j.get("variant"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--only", default="A,B,C,T")
    ap.add_argument("--lengths", default="1,8,64")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    policies = {k: Policy(v) for k, v in POLICIES.items()}
    try:
        done = {key(json.loads(line)) for line in open(a.out)}
    except FileNotFoundError:
        done = set()
    todo = [j for j in jobs(a.only.split(","), a.reps, [int(x) for x in a.lengths.split(",")]) if key(j) not in done]
    print(f"{len(todo)} runs to do", flush=True)
    lock = threading.Lock()
    with cf.ThreadPoolExecutor(min(a.workers, 4)) as ex, open(a.out, "a") as f:
        for fut in cf.as_completed([ex.submit(run_one, j, policies) for j in todo]):
            r = fut.result()
            with lock:
                f.write(json.dumps(r) + "\n")
                f.flush()
            sc = r.get("score", {})
            print(key(r), r.get("finish"), r.get("usage", {}).get("completion"), r.get("seconds"),
                  sc.get("both_ok"), "/", sc.get("n_truth"), flush=True)


if __name__ == "__main__":
    main()
