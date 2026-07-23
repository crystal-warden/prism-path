#!/usr/bin/env python3
"""#1 sequence corpus + 3-arm context experiment.
Builds an ORDERED, anchor-marked multi-event corpus and tests whether ENGINEERED
context (kill-chain timeline) recovers the lift that NAIVE context (#2, unordered
bag) destroyed. Arms per case, same paired sample:
  A single-event (baseline)   B naive bag (#2 replica)   C engineered timeline
"""
import csv, json, requests
from collections import defaultdict, Counter
GEMMA = "http://127.0.0.1:8888/v1/chat/completions"; MODEL = "gemma4"
SCHEMA = {"type": "object", "properties": {
    "threat_class": {"type": "string", "enum": ["malware", "intrusion", "recon", "exfil", "benign", "other"]},
    "is_active_threat": {"type": "boolean"}, "confidence": {"type": "number"},
    "recommended_action": {"type": "string", "enum": ["contain", "watch", "ignore"]},
    "rationale": {"type": "string"}},
    "required": ["threat_class", "is_active_threat", "confidence", "recommended_action", "rationale"]}


def verdict(prompt, concise=False):
    p = prompt + ("\nRespond with ONE JSON object; rationale under 20 words." if concise else "")
    body = {"model": MODEL, "temperature": 0, "max_tokens": 768, "messages": [{"role": "user", "content": p}],
            "response_format": {"type": "json_schema", "json_schema": {"name": "v", "schema": SCHEMA}}}
    r = requests.post(GEMMA, json=body, timeout=120); r.raise_for_status()
    try:
        return json.loads(r.json()["choices"][0]["message"]["content"])["recommended_action"]
    except Exception:
        return verdict(prompt, True) if not concise else None


CSV = "/home/cwadmin/cwprojects/triage-corpus/EVTX-ATTACK-SAMPLES/evtx_data.csv"
DETAIL = ["CommandLine", "Image", "ProcessName", "NewProcessName", "ParentCommandLine", "DestinationIp",
          "DestAddress", "TargetFilename", "QueryName", "ImageLoaded", "ServiceName", "TargetUserName", "PipeName"]
rows = list(csv.DictReader(open(CSV, encoding="utf-8", errors="ignore")))
byfile = defaultdict(list)
for r in rows:
    nm = (r.get("EVTX_FileName") or "").strip()
    if nm:
        byfile[nm].append(r)


def evt_str(r):
    eid = (r.get("EventID") or "").strip(); parts = []
    for dc in DETAIL:
        v = (r.get(dc) or "").strip()
        if v and v not in ("-", "0"):
            parts.append(f"{dc}={v[:60]}")
        if len(parts) >= 2:
            break
    return f"EventID {eid}" + (" | " + ", ".join(parts) if parts else "")


by_tac = defaultdict(list)
for nm, evs in byfile.items():
    by_tac[(evs[0].get("EVTX_Tactic") or "?").strip()].append((nm, evs))
sample = []
for t, fs in by_tac.items():
    sample += fs[:8]

# ---- build the ordered sequence corpus (the #1 data artifact) ----
corpus = []
for nm, evs in byfile.items():
    seq = []; seen = set()
    for r in evs:
        e = evt_str(r)
        if e not in seen:
            seen.add(e); seq.append(e)
    corpus.append({"evtx_file": nm, "tactic": (evs[0].get("EVTX_Tactic") or "?").strip(),
                   "technique": nm.replace(".evtx", "").replace("_", " "),
                   "n_events": len(evs), "n_distinct": len(seq), "anchor_idx": 0, "events": seq})
with open("/home/cwadmin/cwprojects/triage-corpus/triage_sequence_corpus.jsonl", "w") as f:
    for c in corpus:
        f.write(json.dumps(c) + "\n")
multi = sum(1 for c in corpus if c["n_distinct"] >= 3)
print(f"corpus: {len(corpus)} files, {multi} with >=3 distinct events (true sequences)")


# ---- 3-arm experiment ----
def alert_line(nm, evs):
    tac = (evs[0].get("EVTX_Tactic") or "").strip(); tech = nm.replace(".evtx", "").replace("_", " ")
    return f'"{tac} | {tech} | {evt_str(evs[0])}" on a Windows endpoint'


HEAD = "You are a SOC triage analyst. Classify and recommend contain/watch/ignore; weigh evidence.\n"


def prompt_A(nm, evs):
    return HEAD + f"Alert: {alert_line(nm, evs)}."


def distinct_ctx(evs):
    seen = set(); ctx = []
    for r in evs[1:]:
        e = evt_str(r)
        if e not in seen:
            seen.add(e); ctx.append(e)
        if len(ctx) >= 8:
            break
    return ctx


def prompt_B(nm, evs):  # naive bag (replicates #2)
    ctx = distinct_ctx(evs)
    if not ctx:
        return prompt_A(nm, evs)
    return (HEAD + f"Alert: {alert_line(nm, evs)}.\n"
            "Correlated context - other events observed on this host in the same activity window:\n"
            + "\n".join(f"  - {e}" for e in ctx) + "\nWeigh the alert together with this correlated context.")


def prompt_C(nm, evs):  # engineered ordered timeline + kill-chain framing
    ctx = distinct_ctx(evs)
    if not ctx:
        return prompt_A(nm, evs)
    lines = [evt_str(evs[0])] + ctx
    tl = "\n".join(f"  {i+1}. {e}" + ("   <== ALERTING EVENT" if i == 0 else "") for i, e in enumerate(lines))
    return (HEAD + f"Alert: {alert_line(nm, evs)}.\n"
            "Reconstructed activity timeline on this host, in observed order (the ALERTING EVENT is marked):\n" + tl + "\n"
            "Read this as a potential attack SEQUENCE. Individual steps may each resemble normal administration, "
            "but a PROGRESSION across steps (e.g. execution -> persistence -> credential access -> lateral movement) "
            "indicates an active intrusion and warrants containment. Conversely, a lone admin-looking event with NO "
            "supporting chain around it may be a benign false positive. Judge the sequence as a whole, not any single line.")


res = []; cnt = {"A": Counter(), "B": Counter(), "C": Counter()}
per_tac = defaultdict(lambda: {"n": 0, "A": 0, "B": 0, "C": 0})


def esc(a):
    return a in ("contain", "watch")


for nm, evs in sample:
    if len(distinct_ctx(evs)) == 0:
        continue  # need real multi-event cases for the comparison
    tac = (evs[0].get("EVTX_Tactic") or "?").strip()
    aA = verdict(prompt_A(nm, evs)); aB = verdict(prompt_B(nm, evs)); aC = verdict(prompt_C(nm, evs))
    if None in (aA, aB, aC):
        continue
    for k, a in (("A", aA), ("B", aB), ("C", aC)):
        cnt[k]["esc"] += esc(a)
    per_tac[tac]["n"] += 1
    for k, a in (("A", aA), ("B", aB), ("C", aC)):
        per_tac[tac][k] += esc(a)
    res.append({"tactic": tac, "technique": nm.replace(".evtx", ""), "A": aA, "B": aB, "C": aC})

n = sum(v["n"] for v in per_tac.values())


def uc(k):
    return sum(1 for r in res if not esc(r[k]))  # under-calls (all malicious -> non-esc = miss)


out = {"n_multi_event_cases": n,
       "escalation": {"A_single": round(cnt["A"]["esc"] / n, 3), "B_naive_bag": round(cnt["B"]["esc"] / n, 3),
                      "C_engineered": round(cnt["C"]["esc"] / n, 3)},
       "undercalls": {"A_single": uc("A"), "B_naive_bag": uc("B"), "C_engineered": uc("C")},
       "C_recovers_over_B": round((cnt["C"]["esc"] - cnt["B"]["esc"]) / n, 3),
       "C_vs_A": round((cnt["C"]["esc"] - cnt["A"]["esc"]) / n, 3),
       "per_tactic": {t: {"n": v["n"], "A": f'{v["A"]}/{v["n"]}', "B": f'{v["B"]}/{v["n"]}', "C": f'{v["C"]}/{v["n"]}'}
                      for t, v in per_tac.items()},
       "disagreements": [r for r in res if len({r["A"], r["B"], r["C"]}) > 1][:20]}
with open("/home/cwadmin/cwprojects/triage-corpus/sequence_lift_v0.json", "w") as f:
    json.dump(out, f, indent=1)
print(json.dumps({k: out[k] for k in ("n_multi_event_cases", "escalation", "undercalls", "C_recovers_over_B", "C_vs_A")}, indent=1))
