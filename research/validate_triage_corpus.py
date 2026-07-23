#!/usr/bin/env python3
"""Validate triage_corpus_v0 through the triage LLM (#40). First agreement measure on DIVERSE labeled
data (249 ATT&CK techniques / 8 tactics), vs the homelab-monotony shadow run. Ground truth = the
by-construction `_label`. Key metrics: malicious ESCALATION rate (contain|watch = correctly flagged a
threat), DANGEROUS UNDER-CALLS (malicious -> ignore = missed attack), benign handling, per-tactic."""
import sys, os, json, time, urllib3, requests
from collections import defaultdict, Counter
urllib3.disable_warnings()
GEMMA="http://127.0.0.1:8888/v1/chat/completions"; MODEL="gemma4"
SCHEMA={"type":"object","properties":{
  "threat_class":{"type":"string","enum":["malware","intrusion","recon","exfil","benign","other"]},
  "is_active_threat":{"type":"boolean"},"confidence":{"type":"number"},
  "recommended_action":{"type":"string","enum":["contain","watch","ignore"]},"rationale":{"type":"string"}},
  "required":["threat_class","is_active_threat","confidence","recommended_action","rationale"]}
def verdict(a, concise=False):
    p=(f"You are a SOC triage analyst. Classify this alert and recommend contain/watch/ignore. "
       f"Weigh the evidence over any severity number.\nAlert: rule {a.get('rule_id')} "
       f"\"{a.get('description','')}\" on agent '{a.get('agent','')}'"
       f"{', source '+str(a['srcip']) if a.get('srcip') else ''}. MITRE: {a.get('mitre') or 'n/a'}.")
    if concise: p+="\nRespond with ONE JSON object; rationale under 20 words."
    body={"model":MODEL,"temperature":0,"max_tokens":768,"messages":[{"role":"user","content":p}],
          "response_format":{"type":"json_schema","json_schema":{"name":"v","schema":SCHEMA}}}
    r=requests.post(GEMMA,json=body,timeout=120); r.raise_for_status()
    try: return json.loads(r.json()["choices"][0]["message"]["content"])["recommended_action"]
    except Exception:
        return verdict(a,True) if not concise else None
corpus=[json.loads(l) for l in open("/home/cwadmin/cwprojects/triage-corpus/triage_corpus_v0.jsonl")]
mal=[c for c in corpus if c["_label"]=="contain"]; ben=[c for c in corpus if c["_label"] in ("ignore","watch")]
# stratified sample: up to 8 malicious per tactic + 26 benign
by_tac=defaultdict(list)
for c in mal: by_tac[c.get("_tactic","?")].append(c)
sample=[]
for t,cs in by_tac.items(): sample+=cs[:8]
sample_mal=sample[:]; sample_ben=ben[:26]; sample=sample_mal+sample_ben
esc=Counter(); und=[]; overc=0; ben_ok=0; perr=0; per_tac=defaultdict(lambda:{"n":0,"esc":0})
for c in sample:
    act=verdict(c)
    if act is None: perr+=1; continue
    if c["_label"]=="contain":  # malicious
        t=c.get("_tactic","?"); per_tac[t]["n"]+=1
        if act in ("contain","watch"): esc["escalated"]+=1; per_tac[t]["esc"]+=1; esc[act]+=1
        else: und.append({"tactic":t,"technique":c.get("_technique",""),"act":act})
    else:  # benign
        if act in ("ignore","watch"): ben_ok+=1
        elif act=="contain": overc+=1
nm=len(sample_mal); nb=len(sample_ben)
out=dict(sampled=len(sample), malicious=nm, benign=nb, parse_errors=perr,
    malicious_escalation_rate=round(esc["escalated"]/nm,3), malicious_contain=esc["contain"], malicious_watch=esc["watch"],
    dangerous_undercalls=len(und), undercall_examples=und[:8],
    benign_correct_rate=round(ben_ok/nb,3), benign_overcalls=overc,
    per_tactic_escalation={t:f"{v['esc']}/{v['n']}" for t,v in per_tac.items()})
json.dump(out, open("/home/cwadmin/cwprojects/triage-corpus/validation_v0.json","w"), indent=2)
print(json.dumps(out, indent=2))
