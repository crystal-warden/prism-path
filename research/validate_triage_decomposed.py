#!/usr/bin/env python3
"""#54 — decomposed PrismPath triage GRAPH vs flat single-shot.

Tests PrismPath's core thesis: does routing an alert through narrow decision NODES beat one
monolithic prompt? My #1/#2/#3 negative result only indicted context-STUFFING; decomposition is
untested. Two arms on the SAME paired sample (malicious + benign, so 'escalate everything' is caught):

  A  single-shot   flat "classify + recommend" prompt (the baseline, arm A of #1)
  D  decomposed     (1) deterministic SIGNATURE GATE (no LLM) for un-rationalizable IOCs
                    (2) tactic ROUTER
                    (3) escalation-DEFAULTED narrow adjudication node ('could be admin' != evidence)

Win = D raises malicious recall WITHOUT tanking benign-correct. Reports both for both arms + the
fraction of D decisions resolved deterministically (cost + auditability story).
"""
import json, re, requests
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


CORPUS = "/home/cwadmin/cwprojects/triage-corpus/triage_corpus_v0.jsonl"
recs = [json.loads(l) for l in open(CORPUS)]
mal = [r for r in recs if r["_label"] == "contain"]
ben = [r for r in recs if r["_label"] == "ignore"]

# stratified sample: 8 malicious / tactic + 48 benign
by_tac = defaultdict(list)
for r in mal:
    by_tac[r.get("_tactic") or "?"].append(r)
sample_mal = []
for t, rs in by_tac.items():
    sample_mal += rs[:8]
sample_ben = ben[:48]
sample = [("mal", r) for r in sample_mal] + [("ben", r) for r in sample_ben]

# ---- Node 1: deterministic signature gate (high-precision, un-rationalizable IOCs) ----
SIGS = [
    (r"mimikatz|sekurlsa", "mimikatz/sekurlsa credential theft"),
    (r"ntds\.dit|ntdsutil|drsuapi|getncchanges|dcsync", "NTDS/DCSync domain credential dump"),
    (r"lsass.*(dump|access|memory|comsvcs|procdump)|comsvcs.*minidump", "LSASS memory dump"),
    (r"wevtutil.*\bcl\b|security log cleared|\b1102\b.*(clear|cleared)", "security event log cleared (anti-forensics)"),
    (r"-encodedcommand|\benc\b\s|frombase64string|downloadstring|iex\s*\(|invoke-expression", "obfuscated/encoded PowerShell exec"),
    (r"rubeus|kerberoast|asktgt|overpass|sekurlsa::pth|pass-the-hash|pass the hash", "Kerberos abuse / pass-the-hash"),
    (r"hashdump|samdump|reg (save|export).*\bsam\b", "SAM/hash dump"),
    (r"cobaltstrike|beacon\.|meterpreter|psexesvc", "known C2 / offensive tooling"),
]
_sig_re = [(re.compile(p, re.I), why) for p, why in SIGS]


def sig_gate(desc):
    for rx, why in _sig_re:
        if rx.search(desc):
            return why
    return None


# ---- Node 2: tactic router (parse the detection's tactic; benign homelab alerts -> 'general') ----
ATTACK_TACTICS = {"Command and Control", "Credential Access", "Defense Evasion", "Discovery",
                  "Execution", "Lateral Movement", "Persistence", "Privilege Escalation",
                  "Exfiltration", "Collection", "Initial Access", "Impact"}


def route(desc, tactic_hint):
    if tactic_hint in ATTACK_TACTICS:
        return tactic_hint
    head = desc.split("|")[0].strip()
    return head if head in ATTACK_TACTICS else "general"


# ---- Node 3: adjudication nodes (narrow, escalation-defaulted for attack tactics) ----
def flat_prompt(desc):  # arm A
    return ('You are a SOC triage analyst. Classify and recommend contain/watch/ignore; weigh evidence.\n'
            f'Alert: "{desc}" on a Windows endpoint.')


def adj_prompt(desc, tactic):  # arm D node
    if tactic == "general":
        return ('You are a SOC triage analyst.\n'
                f'Alert: "{desc}" on a host.\n'
                "Assess whether this indicates a real security threat requiring action, or routine "
                "operational noise. Classify and recommend contain/watch/ignore.")
    # strip the leading "Tactic |" so the node reasons on the EVENT, not the label
    event = desc.split("|", 1)[1].strip() if "|" in desc else desc
    return (f"You are a SOC triage analyst reviewing a {tactic} detection.\n"
            f'Detection: "{event}" on a Windows endpoint.\n'
            "A named-technique detection fired. Treat it as a TRUE positive requiring action "
            "(contain or watch) UNLESS you can cite SPECIFIC positive evidence of an authorized "
            "business process. 'It could be normal admin activity' is NOT sufficient — attackers "
            "deliberately mimic admin tools. Recommend ignore ONLY with concrete benign justification. "
            "Classify and recommend contain/watch/ignore.")


def esc(a):
    return a in ("contain", "watch")


res = []
A = Counter(); D = Counter()
sig_hits = Counter()  # by kind/mal-ben
per_tac = defaultdict(lambda: {"n": 0, "A": 0, "D": 0})
for kind, r in sample:
    desc = r["description"]
    tac = r.get("_tactic") or "?"
    # arm A
    aA = verdict(flat_prompt(desc))
    # arm D
    why = sig_gate(desc)
    if why:
        aD = "contain"; d_by = "signature"
        sig_hits[kind] += 1
    else:
        rt = route(desc, tac)
        aD = verdict(adj_prompt(desc, rt)); d_by = "llm:" + rt
    if aA is None or aD is None:
        continue
    res.append({"kind": kind, "tactic": tac, "technique": r.get("_technique", "")[:40],
                "A": aA, "D": aD, "d_by": d_by})
    if kind == "mal":
        A["mal_esc"] += esc(aA); D["mal_esc"] += esc(aD); A["mal_n"] += 1; D["mal_n"] += 1
        per_tac[tac]["n"] += 1; per_tac[tac]["A"] += esc(aA); per_tac[tac]["D"] += esc(aD)
    else:
        A["ben_ok"] += (not esc(aA)); D["ben_ok"] += (not esc(aD)); A["ben_n"] += 1; D["ben_n"] += 1

mn, bn = A["mal_n"], A["ben_n"]
d_sig = sum(sig_hits.values())
out = {
    "n_malicious": mn, "n_benign": bn,
    "A_single_shot": {"malicious_recall": round(A["mal_esc"] / mn, 3),
                      "benign_correct": round(A["ben_ok"] / bn, 3),
                      "under_calls": mn - A["mal_esc"], "over_calls": bn - A["ben_ok"]},
    "D_decomposed": {"malicious_recall": round(D["mal_esc"] / mn, 3),
                     "benign_correct": round(D["ben_ok"] / bn, 3),
                     "under_calls": mn - D["mal_esc"], "over_calls": bn - D["ben_ok"]},
    "D_recall_gain_over_A": round((D["mal_esc"] - A["mal_esc"]) / mn, 3),
    "D_benign_delta_vs_A": round((D["ben_ok"] - A["ben_ok"]) / bn, 3),
    "sig_gate": {"total_hits": d_sig, "on_malicious": sig_hits["mal"], "on_benign_FALSE_POS": sig_hits["ben"],
                 "pct_of_malicious_resolved_deterministically": round(sig_hits["mal"] / mn, 3)},
    "per_tactic_recall": {t: {"n": v["n"], "A": f'{v["A"]}/{v["n"]}', "D": f'{v["D"]}/{v["n"]}'}
                          for t, v in per_tac.items()},
    "D_undercalls_detail": [x for x in res if x["kind"] == "mal" and not esc(x["D"])][:20],
    "D_overcalls_detail": [x for x in res if x["kind"] == "ben" and esc(x["D"])][:20],
}
with open("/home/cwadmin/cwprojects/triage-corpus/decomposed_v0.json", "w") as f:
    json.dump(out, f, indent=1)
print(json.dumps({k: out[k] for k in ("n_malicious", "n_benign", "A_single_shot", "D_decomposed",
                                      "D_recall_gain_over_A", "D_benign_delta_vs_A", "sig_gate")}, indent=1))
