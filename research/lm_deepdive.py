#!/usr/bin/env python3
"""#3 — Lateral Movement deep-dive: WHY does triage under-call LM (2/8)? Runs each LM single-event
case and captures the LLM's RATIONALE + threat_class, to see the failure reason (hypothesis: LM
techniques manifest as events indistinguishable from normal admin/remote activity in isolation)."""
import sys, csv, json, requests, urllib3
from collections import Counter
urllib3.disable_warnings()
GEMMA="http://127.0.0.1:8888/v1/chat/completions"; MODEL="gemma4"
SCHEMA={"type":"object","properties":{
  "threat_class":{"type":"string","enum":["malware","intrusion","recon","exfil","benign","other"]},
  "is_active_threat":{"type":"boolean"},"confidence":{"type":"number"},
  "recommended_action":{"type":"string","enum":["contain","watch","ignore"]},"rationale":{"type":"string"}},
  "required":["threat_class","is_active_threat","confidence","recommended_action","rationale"]}
def vf(prompt, concise=False):
    p=prompt+("\nONE JSON object; rationale under 22 words." if concise else "")
    body={"model":MODEL,"temperature":0,"max_tokens":768,"messages":[{"role":"user","content":p}],
          "response_format":{"type":"json_schema","json_schema":{"name":"v","schema":SCHEMA}}}
    r=requests.post(GEMMA,json=body,timeout=120); r.raise_for_status()
    try: return json.loads(r.json()["choices"][0]["message"]["content"])
    except Exception: return vf(prompt,True) if not concise else {"recommended_action":None,"rationale":"parse_error"}
CSV="/home/cwadmin/cwprojects/triage-corpus/EVTX-ATTACK-SAMPLES/evtx_data.csv"
DETAIL=["CommandLine","Image","ProcessName","NewProcessName","ParentCommandLine","DestinationIp","DestAddress","TargetFilename","ServiceName","TargetUserName","PipeName","LogonType"]
rows=list(csv.DictReader(open(CSV,encoding="utf-8",errors="ignore")))
byfile={}
for r in rows:
    if (r.get("EVTX_Tactic") or "").strip()=="Lateral Movement":
        nm=(r.get("EVTX_FileName") or "").strip()
        if nm and nm not in byfile: byfile[nm]=r
out=[]
for nm,r in list(byfile.items())[:14]:
    eid=(r.get("EventID") or "").strip(); tech=nm.replace(".evtx","").replace("_"," ")
    d=""
    for dc in DETAIL:
        v=(r.get(dc) or "").strip()
        if v and v not in ("-","0"): d=f"{dc}={v[:70]}"; break
    prompt=(f'You are a SOC triage analyst. Classify and recommend contain/watch/ignore; weigh evidence.\n'
            f'Alert: "Lateral Movement | {tech} | EventID {eid}'+(f" | {d}" if d else "")+'" on a Windows endpoint.')
    v=vf(prompt)
    out.append(dict(technique=tech[:50], eid=eid, action=v.get("recommended_action"),
                    threat_class=v.get("threat_class"), rationale=(v.get("rationale") or "")[:130]))
esc=sum(1 for r in out if r["action"] in ("contain","watch"))
threats=Counter(r["threat_class"] for r in out)
res=dict(lm_cases=len(out), escalated=esc, ignored=len(out)-esc,
         threat_class_dist=dict(threats), cases=out)
json.dump(res, open("/home/cwadmin/cwprojects/triage-corpus/lm_deepdive.json","w"), indent=2)
print(json.dumps(res, indent=2))
