#!/usr/bin/env python3
"""#56 — does the decomposed graph's routing survive WITHOUT the free tactic label?

#54 proved decomposition wins, but its router read the corpus's built-in _tactic. A production router
must EARN that classification. Here EmbeddingGemma routes each alert to a decision node by embedding
similarity to per-tactic centroids learned from a TRAIN split. The test alert's _tactic is used ONLY
to score routing accuracy, never to route. The leading 'Tactic |' prefix is STRIPPED before embedding
so the embedder can't read the label off the text (the #54/#1 confound).

Arms compared (same 64 mal + 48 benign test set as #54):
  A         single-shot            (ref: recall 0.844 / benign 0.792)   [#54]
  D_oracle  decomposed, GT routing (ref: recall 0.969 / benign 0.938)   [#54]
  D_embed   decomposed, EMBEDDER routing                                 [THIS RUN]
If D_embed ~ D_oracle, the #54 win is real and unconfounded. If it slides toward A, routing error
eats the gain.
"""
import json, re, requests
import numpy as np
from collections import defaultdict, Counter
from sentence_transformers import SentenceTransformer

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

ATTACK_TACTICS = {"Command and Control", "Credential Access", "Defense Evasion", "Discovery",
                  "Execution", "Lateral Movement", "Persistence", "Privilege Escalation",
                  "Exfiltration", "Collection", "Initial Access", "Impact"}


def route_text(desc):
    """Strip the leading 'Tactic |' label so the embedder routes on EVENT CONTENT, not the label."""
    head = desc.split("|")[0].strip()
    return desc.split("|", 1)[1].strip() if head in ATTACK_TACTICS and "|" in desc else desc


# ---- same test split as #54: 8 malicious/tactic + first 48 benign ----
by_tac = defaultdict(list)
for r in mal:
    by_tac[r.get("_tactic") or "?"].append(r)
test_mal, test_mal_ids = [], set()
for t, rs in by_tac.items():
    for r in rs[:8]:
        test_mal.append(r); test_mal_ids.add(id(r))
test_ben = ben[:48]; test_ben_ids = {id(r) for r in test_ben}
train_mal = [r for r in mal if id(r) not in test_mal_ids]
train_ben = [r for r in ben if id(r) not in test_ben_ids]

# ---- EmbeddingGemma centroids from TRAIN (labels used here = legit supervision) ----
gm = SentenceTransformer("google/embeddinggemma-300m", device="cuda")


def emb(texts):
    for kw in ({"prompt_name": "Classification"}, {}):
        try:
            return np.asarray(gm.encode([route_text(t) for t in texts], normalize_embeddings=True,
                                        batch_size=64, show_progress_bar=False, **kw), np.float64)
        except Exception:
            continue
    raise RuntimeError("encode failed")


cen = {}
tac_train = defaultdict(list)
for r in train_mal:
    tac_train[r.get("_tactic") or "?"].append(r["description"])
for t, ds in tac_train.items():
    if t in ATTACK_TACTICS and ds:
        v = emb(ds).mean(0); cen[t] = v / (np.linalg.norm(v) + 1e-9)
gv = emb([r["description"] for r in train_ben]).mean(0)
cen["general"] = gv / (np.linalg.norm(gv) + 1e-9)
cen_names = list(cen.keys())
cen_mat = np.stack([cen[c] for c in cen_names])


def route_embed(desc):
    v = emb([desc])[0]
    return cen_names[int(np.argmax(cen_mat @ v))]


# ---- signature gate + adjudication (identical to #54) ----
SIGS = [
    (r"mimikatz|sekurlsa", "mimikatz/sekurlsa"), (r"ntds\.dit|ntdsutil|drsuapi|getncchanges|dcsync", "NTDS/DCSync"),
    (r"lsass.*(dump|access|memory|comsvcs|procdump)|comsvcs.*minidump", "LSASS dump"),
    (r"wevtutil.*\bcl\b|security log cleared|\b1102\b.*(clear|cleared)", "log cleared"),
    (r"-encodedcommand|\benc\b\s|frombase64string|downloadstring|iex\s*\(|invoke-expression", "encoded PS"),
    (r"rubeus|kerberoast|asktgt|overpass|sekurlsa::pth|pass-the-hash|pass the hash", "Kerberos/PtH"),
    (r"hashdump|samdump|reg (save|export).*\bsam\b", "SAM dump"),
    (r"cobaltstrike|beacon\.|meterpreter|psexesvc", "C2 tooling"),
]
_sig_re = [(re.compile(p, re.I), why) for p, why in SIGS]


def sig_gate(desc):
    for rx, why in _sig_re:
        if rx.search(desc):
            return why
    return None


def adj_prompt(desc, tactic):
    if tactic == "general":
        return ('You are a SOC triage analyst.\n'
                f'Alert: "{desc}" on a host.\n'
                "Assess whether this indicates a real security threat requiring action, or routine "
                "operational noise. Classify and recommend contain/watch/ignore.")
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


# ---- route accuracy (embeddings only) ----
route_stats = {"mal_to_attack": 0, "mal_to_general_MISROUTE": 0, "mal_fine_correct": 0,
               "ben_to_general": 0, "ben_to_attack_MISROUTE": 0}
routed = {}
for r in test_mal:
    rt = route_embed(r["description"]); routed[id(r)] = rt
    if rt == "general":
        route_stats["mal_to_general_MISROUTE"] += 1
    else:
        route_stats["mal_to_attack"] += 1
        if rt == (r.get("_tactic") or "?"):
            route_stats["mal_fine_correct"] += 1
for r in test_ben:
    rt = route_embed(r["description"]); routed[id(r)] = rt
    if rt == "general":
        route_stats["ben_to_general"] += 1
    else:
        route_stats["ben_to_attack_MISROUTE"] += 1

import os, sys
if os.environ.get("ROUTE_ONLY"):
    print(json.dumps(route_stats, indent=1)); sys.exit(0)

# ---- D_embed end-to-end ----
D = Counter(); per_tac = defaultdict(lambda: {"n": 0, "e": 0}); miss = []
for kind, cases in (("mal", test_mal), ("ben", test_ben)):
    for r in cases:
        desc = r["description"]
        why = sig_gate(desc)
        if why:
            a = "contain"
        else:
            a = verdict(adj_prompt(desc, routed[id(r)]))
        if a is None:
            continue
        if kind == "mal":
            D["mal_e"] += esc(a); D["mal_n"] += 1
            per_tac[r.get("_tactic") or "?"]["n"] += 1; per_tac[r.get("_tactic") or "?"]["e"] += esc(a)
            if not esc(a):
                miss.append({"tactic": r.get("_tactic"), "tech": r.get("_technique", "")[:36],
                             "routed": routed[id(r)], "action": a})
        else:
            D["ben_ok"] += (not esc(a)); D["ben_n"] += 1

mn, bn = D["mal_n"], D["ben_n"]
out = {
    "n_malicious": mn, "n_benign": bn,
    "routing_accuracy": {
        "malicious_reached_attack_node": f'{route_stats["mal_to_attack"]}/{mn}',
        "malicious_MISROUTED_to_general": route_stats["mal_to_general_MISROUTE"],
        "malicious_fine_tactic_correct": f'{route_stats["mal_fine_correct"]}/{mn}',
        "benign_reached_general_node": f'{route_stats["ben_to_general"]}/{bn}',
        "benign_MISROUTED_to_attack": route_stats["ben_to_attack_MISROUTE"]},
    "D_embed": {"malicious_recall": round(D["mal_e"] / mn, 3), "benign_correct": round(D["ben_ok"] / bn, 3),
                "under_calls": mn - D["mal_e"], "over_calls": bn - D["ben_ok"]},
    "reference_A_single_shot": {"malicious_recall": 0.844, "benign_correct": 0.792},
    "reference_D_oracle_routing": {"malicious_recall": 0.969, "benign_correct": 0.938},
    "per_tactic_recall": {t: f'{v["e"]}/{v["n"]}' for t, v in per_tac.items()},
    "D_embed_undercalls": miss[:20],
}
with open("/home/cwadmin/cwprojects/triage-corpus/embed_routed_v0.json", "w") as f:
    json.dump(out, f, indent=1)
print(json.dumps({k: out[k] for k in ("n_malicious", "n_benign", "routing_accuracy", "D_embed",
                                      "reference_A_single_shot", "reference_D_oracle_routing")}, indent=1))
