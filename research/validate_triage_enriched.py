#!/usr/bin/env python3
"""#2 — measure the ENRICH/correlation lift on triage under-calls (#40).
Same single-event ATT&CK cases, PAIRED: verdict WITHOUT context vs WITH the correlated co-occurring
events from the same technique file (the sequence signal the single event lacks). Isolates
'missing context' from 'model gap': how many of the ~33% dangerous under-calls does correlation flip?"""
import sys, csv, json
from collections import defaultdict, Counter
import requests, urllib3
urllib3.disable_warnings()
GEMMA="http://127.0.0.1:8888/v1/chat/completions"; MODEL="gemma4"
SCHEMA={"type":"object","properties":{
  "threat_class":{"type":"string","enum":["malware","intrusion","recon","exfil","benign","other"]},
  "is_active_threat":{"type":"boolean"},"confidence":{"type":"number"},
  "recommended_action":{"type":"string","enum":["contain","watch","ignore"]},"rationale":{"type":"string"}},
  "required":["threat_class","is_active_threat","confidence","recommended_action","rationale"]}
def verdict(prompt, concise=False):
    p=prompt+("\nRespond with ONE JSON object; rationale under 20 words." if concise else "")
    body={"model":MODEL,"temperature":0,"max_tokens":768,"messages":[{"role":"user","content":p}],
          "response_format":{"type":"json_schema","json_schema":{"name":"v","schema":SCHEMA}}}
    r=requests.post(GEMMA,json=body,timeout=120); r.raise_for_status()
    try: return json.loads(r.json()["choices"][0]["message"]["content"])["recommended_action"]
    except Exception: return verdict(prompt,True) if not concise else None
CSV="/home/cwadmin/cwprojects/triage-corpus/EVTX-ATTACK-SAMPLES/evtx_data.csv"
DETAIL=["CommandLine","Image","ProcessName","NewProcessName","ParentCommandLine","DestinationIp","DestAddress","TargetFilename","QueryName","ImageLoaded","ServiceName","TargetUserName","PipeName"]
rows=list(csv.DictReader(open(CSV,encoding="utf-8",errors="ignore")))
byfile=defaultdict(list)
for r in rows:
    nm=(r.get("EVTX_FileName") or "").strip()
    if nm: byfile[nm].append(r)
def evt_str(r):
    eid=(r.get("EventID") or "").strip(); d=""
    for dc in DETAIL:
        v=(r.get(dc) or "").strip()
        if v and v not in ("-","0"): d=f"{dc}={v[:70]}"; break
    return f"EventID {eid}"+(f" | {d}" if d else "")
# stratified sample: 8 files per tactic
by_tac=defaultdict(list)
for nm,evs in byfile.items(): by_tac[(evs[0].get("EVTX_Tactic") or "?").strip()].append((nm,evs))
sample=[]
for t,fs in by_tac.items(): sample+=fs[:8]
def base_prompt(nm,evs):
    tac=(evs[0].get("EVTX_Tactic") or "").strip(); tech=nm.replace(".evtx","").replace("_"," ")
    return (f'You are a SOC triage analyst. Classify and recommend contain/watch/ignore; weigh evidence.\n'
            f'Alert: "{tac} | {tech} | {evt_str(evs[0])}" on a Windows endpoint.')
res=[]; wo=Counter(); wi=Counter(); flips=[]; per_tac=defaultdict(lambda:{"n":0,"wo":0,"wi":0})
for nm,evs in sample:
    tac=(evs[0].get("EVTX_Tactic") or "?").strip()
    bp=base_prompt(nm,evs)
    # correlated context = other distinct events in the same file
    seen=set(); ctx=[]
    for r in evs[1:]:
        e=evt_str(r)
        if e not in seen: seen.add(e); ctx.append(e)
        if len(ctx)>=8: break
    cp=bp+("\nCorrelated context — other events observed on this host in the same activity window:\n"
           +"\n".join(f"  - {e}" for e in ctx)+"\nWeigh the alert together with this correlated context." if ctx else "")
    a_wo=verdict(bp); a_wi=verdict(cp)
    if a_wo is None or a_wi is None: continue
    esc_wo=a_wo in ("contain","watch"); esc_wi=a_wi in ("contain","watch")
    wo["esc"]+=esc_wo; wi["esc"]+=esc_wi; per_tac[tac]["n"]+=1; per_tac[tac]["wo"]+=esc_wo; per_tac[tac]["wi"]+=esc_wi
    if (not esc_wo) and esc_wi: flips.append({"tactic":tac,"technique":nm.replace(".evtx",""),"wo":a_wo,"wi":a_wi})
n=sum(v["n"] for v in per_tac.values())
out=dict(sampled_malicious=n, n_correlated_context_events="up to 8/file",
    escalation_WITHOUT_context=round(wo["esc"]/n,3), escalation_WITH_context=round(wi["esc"]/n,3),
    undercalls_WITHOUT=n-wo["esc"], undercalls_WITH=n-wi["esc"],
    undercalls_FLIPPED_by_context=len(flips), flip_examples=flips[:8],
    per_tactic={t:{"without":f"{v['wo']}/{v['n']}","with":f"{v['wi']}/{v['n']}"} for t,v in per_tac.items()})
json.dump(out, open("/home/cwadmin/cwprojects/triage-corpus/enrich_lift_v0.json","w"), indent=2)
print(json.dumps(out, indent=2))
