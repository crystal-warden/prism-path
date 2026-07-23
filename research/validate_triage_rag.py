#!/usr/bin/env python3
"""#58 — do retrieval-augmented decision nodes fix knowledge-gap under-calls WITHOUT dilution?

Holds routing at ORACLE (isolates the RAG variable; compare to #54 D_oracle = 0.969 recall / 0.938
benign, escalation-default node, NO knowledge). Two knowledge-augmented nodes, LOLBAS retrieval gated
by similarity (retrieve FEW, inject as CRITERIA — the anti-dilution discipline):
  RN  neutral node   + retrieved knowledge  (does published knowledge SUBSTITUTE for the blunt prior?)
  ER  escalation-def  + retrieved knowledge  (production design: does knowledge ADD precision, no harm?)
Benign cases scored too (the dilution guard: scary LOLBAS text must not over-escalate benign).
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
    "rationale": {"type": "string"}}, "required": ["threat_class", "is_active_threat", "confidence", "recommended_action", "rationale"]}


def verdict(prompt, concise=False):
    p = prompt + ("\nRespond with ONE JSON object; rationale under 20 words." if concise else "")
    body = {"model": MODEL, "temperature": 0, "max_tokens": 768, "messages": [{"role": "user", "content": p}],
            "response_format": {"type": "json_schema", "json_schema": {"name": "v", "schema": SCHEMA}}}
    r = requests.post(GEMMA, json=body, timeout=120); r.raise_for_status()
    try:
        return json.loads(r.json()["choices"][0]["message"]["content"])["recommended_action"]
    except Exception:
        return verdict(prompt, True) if not concise else None


recs = [json.loads(l) for l in open("/home/cwadmin/cwprojects/triage-corpus/triage_corpus_v0.jsonl")]
mal = [r for r in recs if r["_label"] == "contain"]; ben = [r for r in recs if r["_label"] == "ignore"]
by_tac = defaultdict(list)
for r in mal:
    by_tac[r.get("_tactic") or "?"].append(r)
test_mal = []
for t, rs in by_tac.items():
    test_mal += rs[:8]
test_ben = ben[:48]

ATTACK_TACTICS = {"Command and Control", "Credential Access", "Defense Evasion", "Discovery", "Execution",
                  "Lateral Movement", "Persistence", "Privilege Escalation", "Exfiltration", "Collection", "Initial Access", "Impact"}
SIGS = [r"mimikatz|sekurlsa", r"ntds\.dit|ntdsutil|drsuapi|getncchanges|dcsync",
        r"lsass.*(dump|access|memory|comsvcs|procdump)|comsvcs.*minidump", r"wevtutil.*\bcl\b|security log cleared|\b1102\b.*(clear|cleared)",
        r"-encodedcommand|\benc\b\s|frombase64string|downloadstring|iex\s*\(|invoke-expression",
        r"rubeus|kerberoast|asktgt|overpass|sekurlsa::pth|pass-the-hash|pass the hash",
        r"hashdump|samdump|reg (save|export).*\bsam\b", r"cobaltstrike|beacon\.|meterpreter|psexesvc"]
_sig = [re.compile(p, re.I) for p in SIGS]


def sig_gate(d):
    return any(x.search(d) for x in _sig)


def route_text(desc):
    head = desc.split("|")[0].strip()
    return desc.split("|", 1)[1].strip() if head in ATTACK_TACTICS and "|" in desc else desc


# ---- knowledge index ----
IDX = "/home/cwadmin/cwprojects/knowledge-lib/index"
KE = np.load(IDX + "/emb.npy")
cards = [json.loads(l) for l in open(IDX + "/cards.jsonl")]
gm = SentenceTransformer("google/embeddinggemma-300m", device="cuda")
RET_THR = 0.45


def retrieve(desc, k=1):
    q = gm.encode([route_text(desc)], normalize_embeddings=True, prompt_name="Retrieval", show_progress_bar=False)[0].astype(np.float32)
    sims = KE @ q
    top = np.argsort(-sims)[:k]
    return [(cards[i], float(sims[i])) for i in top if sims[i] >= RET_THR]


def know_block(desc):
    hits = retrieve(desc, k=1)
    if not hits:
        return "", None
    c, s = hits[0]
    # v1 fix: ONE-DIRECTIONAL abuse evidence only. v0 injected the full card incl. its "legitimate
    # binary, mere presence not malicious" framing, which the model used as an off-ramp (recall 0.969->0.875,
    # the #1/#2/#3 dilution effect). Strip the exculpatory half; inject abuse as evidence FOR escalation.
    cats = ", ".join(c.get("categories") or []) or "execution"
    mitre = ", ".join(c.get("mitre") or []) or "LOLBin"
    return (f"\nKnown-abuse match (published LOLBAS knowledge): {c['binary']} is a documented "
            f"living-off-the-land binary abused for {cats} ({mitre}). A named LOLBin-abuse technique "
            f"matching this alert is EVIDENCE FOR malicious use — weight it toward escalation.", c["binary"])


def prompt_RN(desc, tac, kb):  # neutral node + knowledge
    return ('You are a SOC triage analyst. Classify and recommend contain/watch/ignore; weigh evidence.\n'
            f'Alert: "{desc}" on a Windows endpoint.' + kb)


def prompt_ER(desc, tac, kb):  # escalation-default node + knowledge
    if tac not in ATTACK_TACTICS:
        return ('You are a SOC triage analyst.\n'
                f'Alert: "{desc}" on a host.\n'
                "Assess whether this indicates a real security threat requiring action, or routine "
                "operational noise. Classify and recommend contain/watch/ignore." + kb)
    event = desc.split("|", 1)[1].strip() if "|" in desc else desc
    return (f"You are a SOC triage analyst reviewing a {tac} detection.\n"
            f'Detection: "{event}" on a Windows endpoint.\n'
            "A named-technique detection fired. Treat it as a TRUE positive requiring action (contain "
            "or watch) UNLESS you can cite SPECIFIC positive evidence of an authorized process. 'It "
            "could be normal admin activity' is NOT sufficient. Recommend ignore ONLY with concrete "
            "justification. Classify and recommend contain/watch/ignore." + kb)


def esc(a):
    return a in ("contain", "watch")


res = []; C = {"RN": Counter(), "ER": Counter()}
ret_stats = {"mal_retrieved": 0, "ben_retrieved": 0}
wuauclt = {}
for kind, cases in (("mal", test_mal), ("ben", test_ben)):
    for r in cases:
        desc = r["description"]; tac = r.get("_tactic") or "?"
        kb, card = know_block(desc)
        if card:
            ret_stats[kind + "_retrieved"] += 1
        if sig_gate(desc):
            aRN = aER = "contain"
        else:
            aRN = verdict(prompt_RN(desc, tac, kb)); aER = verdict(prompt_ER(desc, tac, kb))
        if None in (aRN, aER):
            continue
        for arm, a in (("RN", aRN), ("ER", aER)):
            if kind == "mal":
                C[arm]["mal_e"] += esc(a); C[arm]["mal_n"] += 1
            else:
                C[arm]["ben_ok"] += (not esc(a)); C[arm]["ben_n"] += 1
        if "wuauclt" in desc.lower():
            wuauclt = {"tactic": tac, "retrieved_card": card, "RN": aRN, "ER": aER}
        res.append({"kind": kind, "tac": tac, "tech": r.get("_technique", "")[:34], "card": card, "RN": aRN, "ER": aER})

mn = C["RN"]["mal_n"]; bn = C["RN"]["ben_n"]
out = {
    "n_malicious": mn, "n_benign": bn, "retrieval_threshold": RET_THR,
    "retrieval": {"malicious_got_card": f'{ret_stats["mal_retrieved"]}/{mn}',
                  "benign_got_card": f'{ret_stats["ben_retrieved"]}/{bn}'},
    "RN_neutral_plus_knowledge": {"malicious_recall": round(C["RN"]["mal_e"] / mn, 3), "benign_correct": round(C["RN"]["ben_ok"] / bn, 3),
                                  "under_calls": mn - C["RN"]["mal_e"], "over_calls": bn - C["RN"]["ben_ok"]},
    "ER_escalation_plus_knowledge": {"malicious_recall": round(C["ER"]["mal_e"] / mn, 3), "benign_correct": round(C["ER"]["ben_ok"] / bn, 3),
                                     "under_calls": mn - C["ER"]["mal_e"], "over_calls": bn - C["ER"]["ben_ok"]},
    "reference_E_escalation_no_knowledge_#54Doracle": {"malicious_recall": 0.969, "benign_correct": 0.938},
    "reference_A_single_shot": {"malicious_recall": 0.844, "benign_correct": 0.792},
    "wuauclt_case": wuauclt,
    "RN_undercalls": [x for x in res if x["kind"] == "mal" and not esc(x["RN"])][:15],
}
json.dump(out, open("/home/cwadmin/cwprojects/triage-corpus/rag_nodes_v1.json", "w"), indent=1)
print(json.dumps({k: out[k] for k in ("n_malicious", "n_benign", "retrieval", "RN_neutral_plus_knowledge",
                                      "ER_escalation_plus_knowledge", "reference_E_escalation_no_knowledge_#54Doracle",
                                      "wuauclt_case")}, indent=1))
