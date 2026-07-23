#!/usr/bin/env python3
"""Shadow-mode agreement harness (the design-partner pilot instrument).

Runs PrismPath's triage disposition on a stream of alerts and scores it against a
REFERENCE disposition, producing the base-rate-real metric that replaces the homelab
FP number in any external claim:
  "across N alerts from K environments, PrismPath agreed with the analyst X% of the
   time, with Z dangerous under-calls, at Y% of the per-alert triage cost."

Reference modes:
  --reference human          read a human disposition from --label-field (REAL PILOT)
  --reference fresh-oracle    re-adjudicate with a fresh LLM, bypassing the cache
                              (measures prefilter reuse-fidelity — the paper's
                              'continuous reuse-error monitoring' future-work item)
  --reference second-opinion  independent skeptical second-analyst LLM pass (DRY RUN:
                              produces non-trivial agreement to exercise the metric)

Reuses the deployed gemma4 endpoint + VERDICT_SCHEMA. Optional prefilter cache = the
cheap path (cost saving). Self-contained; no model load; NEVER touches model-gemma
beyond ordinary inference calls.
"""
import os, sys, json, time, argparse, subprocess, collections
import requests, urllib3
urllib3.disable_warnings()
sys.path.insert(0, os.path.expanduser("~/cwprojects"))
sys.path.insert(0, os.path.expanduser("~/cwprojects/mdflow"))

GEMMA = "http://127.0.0.1:8888/v1/chat/completions"; MODEL = "gemma4"
IDX = "https://127.0.0.1:9200/wazuh-alerts-4.x-*/_search"
VERDICT_SCHEMA = {"type":"object","properties":{
    "threat_class":{"type":"string","enum":["malware","intrusion","recon","exfil","benign","other"]},
    "is_active_threat":{"type":"boolean"},"confidence":{"type":"number"},
    "recommended_action":{"type":"string","enum":["contain","watch","ignore"]},
    "rationale":{"type":"string"}},
    "required":["threat_class","is_active_threat","confidence","recommended_action","rationale"]}

try:
    from mdflow.prefilter import PrefilterCache
    CACHE = PrefilterCache(os.path.expanduser("~/cw-staging/prefilter_corpus"))
except Exception:
    CACHE = None

def _pw():
    out = subprocess.run(["sudo","tar","-O","-xf",os.path.expanduser("~/wazuh-install-files.tar"),
                          "wazuh-install-files/wazuh-passwords.txt"],capture_output=True,text=True).stdout
    take=False
    for line in out.splitlines():
        if "indexer_username: 'admin'" in line: take=True
        elif take and "indexer_password:" in line: return line.split("'")[1]
    for line in out.splitlines():
        if "username: 'admin'" in line: take=True
        elif take and "password:" in line: return line.split("'")[1]
    raise RuntimeError("indexer admin password not found")

def fetch_alerts(n, min_level, diverse=False, per_rule=2, pool=1200):
    pw=_pw()
    size = pool if diverse else n
    body={"size":size,"sort":[{"@timestamp":{"order":"desc"}}],"query":{"range":{"rule.level":{"gte":min_level}}}}
    r=requests.get(IDX,json=body,auth=("admin",pw),verify=False,timeout=45); r.raise_for_status()
    cand=[]
    for h in r.json()["hits"]["hits"]:
        s=h["_source"]; rule=s.get("rule",{}); data=s.get("data",{})
        mitre=(rule.get("mitre",{}) or {}).get("id")
        cand.append(dict(rule_id=rule.get("id"),description=rule.get("description",""),level=rule.get("level"),
                         agent=(s.get("agent",{}) or {}).get("name",""),srcip=data.get("srcip"),
                         mitre=mitre, human=s.get("disposition")))
    if not diverse:
        return cand[:n]
    seen={}; out=[]
    for a in cand:                          # spread across distinct rules (<= per_rule each)
        c=seen.get(a["rule_id"],0)
        if c<per_rule:
            out.append(a); seen[a["rule_id"]]=c+1
        if len(out)>=n: break
    return out

def prompt_for(a, persona):
    base=(f"Alert: rule {a['rule_id']} (level {a['level']}) \"{a['description']}\" on agent "
          f"'{a['agent']}'{', source '+str(a['srcip']) if a['srcip'] else ''}. MITRE: {a.get('mitre') or 'n/a'}.")
    if persona=="second":
        return ("You are a SENIOR SOC analyst giving an INDEPENDENT second opinion. Be equally skeptical "
                "of false alarms and of missed threats; weigh evidence over the raw severity number. "
                f"Classify and recommend contain/watch/ignore.\n{base}")
    return ("You are a SOC triage analyst. Classify this alert and recommend contain/watch/ignore. "
            f"Weigh the evidence over the raw severity number.\n{base}")

def verdict(a, persona="primary", concise=False):
    p = prompt_for(a,persona)
    if concise: p += "\nRespond with ONE JSON object; keep rationale under 20 words."
    body={"model":MODEL,"temperature":0,"max_tokens":768,
          "messages":[{"role":"user","content":p}],
          "response_format":{"type":"json_schema","json_schema":{"name":"verdict","schema":VERDICT_SCHEMA}}}
    t=time.time(); r=requests.post(GEMMA,json=body,timeout=120); r.raise_for_status()
    content=r.json()["choices"][0]["message"]["content"]
    try:
        return json.loads(content), round(time.time()-t,2)
    except json.JSONDecodeError:
        if not concise: return verdict(a,persona,concise=True)   # break degenerate loop
        return None, round(time.time()-t,2)

def prism_disposition(a):
    """Cheap path: prefilter cache hit reuses a prior verdict; else the LLM adjudicates."""
    if CACHE is not None:
        try:
            res=CACHE.lookup(f"description: {a['description']} | agent: {a['agent']} | srcip: {a['srcip'] or 'none'} | rule_id: {a['rule_id']}")
            if getattr(res,"hit",False):
                return res.record["action"], "cache", 0.0
        except Exception: pass
    v,dt=verdict(a,"primary")
    if v is None: return None,"parse_error",dt
    return v["recommended_action"], "llm", dt

CONTAIN=lambda act: act=="contain"
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--n",type=int,default=8)
    ap.add_argument("--min-level",type=int,default=6)
    ap.add_argument("--diverse",action="store_true")
    ap.add_argument("--per-rule",type=int,default=2)
    ap.add_argument("--reference",choices=["human","fresh-oracle","second-opinion"],default="second-opinion")
    ap.add_argument("--label-field",default="human")
    ap.add_argument("--out",default=os.path.expanduser("~/cw-staging/shadow"))
    args=ap.parse_args()
    os.makedirs(args.out,exist_ok=True)
    alerts=fetch_alerts(args.n,args.min_level,diverse=args.diverse,per_rule=args.per_rule)

    rows=[]; agree=cont_agree=undercall=overcall=cache_hits=llm_calls=parse_errors=0
    for a in alerts:
        p_act,path,dt=prism_disposition(a)
        if p_act is None: parse_errors+=1; continue
        if path=="cache": cache_hits+=1
        else: llm_calls+=1
        if args.reference=="human":
            r_act=a.get(args.label_field)
            if r_act is None: continue
        elif args.reference=="fresh-oracle":
            rv,_=verdict(a,"primary")
            if rv is None: parse_errors+=1; continue
            r_act=rv["recommended_action"]
        else:
            rv,_=verdict(a,"second")
            if rv is None: parse_errors+=1; continue
            r_act=rv["recommended_action"]
        m_action = (p_act==r_act); m_contain=(CONTAIN(p_act)==CONTAIN(r_act))
        dang = (p_act in ("ignore","watch") and r_act=="contain")
        over = (p_act=="contain" and r_act!="contain")
        agree+=m_action; cont_agree+=m_contain; undercall+=dang; overcall+=over
        rows.append(dict(rule_id=a["rule_id"],desc=a["description"][:60],level=a["level"],
                         prism=p_act,path=path,reference=r_act,action_match=m_action,
                         contain_match=m_contain,dangerous_undercall=dang,overcall=over))
    n=len(rows); distinct_rules=len(set(r["rule_id"] for r in rows))
    by_rule=collections.Counter(r["rule_id"] for r in rows if not r["action_match"])
    summ=dict(n=n, distinct_rules=distinct_rules, reference=args.reference,
              action_agreement=round(agree/n,3) if n else None,
              containment_agreement=round(cont_agree/n,3) if n else None,
              dangerous_undercalls=undercall, overcalls=overcall,
              cache_hits=cache_hits, llm_calls=llm_calls,
              cost_saving_vs_all_llm=round(cache_hits/n,3) if n else 0.0,
              parse_errors=parse_errors,
              disagreements_by_rule=dict(by_rule.most_common(8)))
    json.dump(dict(summary=summ,rows=rows),open(f"{args.out}/shadow_raw.json","w"),indent=2)
    with open(f"{args.out}/shadow_agreement_report.md","w") as fh:
        fh.write("# Shadow-Mode Agreement Report\n\n")
        fh.write(f"Reference: **{args.reference}** | alerts: **{n}** | min level {args.min_level}\n\n")
        fh.write(f"- **Action agreement:** {summ['action_agreement']}\n")
        fh.write(f"- **Containment-decision agreement:** {summ['containment_agreement']}\n")
        fh.write(f"- **Dangerous under-calls** (PrismPath watch/ignore where reference=contain): **{undercall}**\n")
        fh.write(f"- Over-calls (PrismPath contain where reference not): {overcall}\n")
        fh.write(f"- Cheap-path cost saving (cache hits / n): {summ['cost_saving_vs_all_llm']} ({cache_hits}/{n})\n\n")
        fh.write("| rule | lvl | PrismPath | via | reference | match |\n|---|---|---|---|---|---|\n")
        for r in rows:
            fh.write(f"| {r['rule_id']} | {r['level']} | {r['prism']} | {r['path']} | {r['reference']} | {'OK' if r['action_match'] else ('UNDER' if r['dangerous_undercall'] else 'x')} |\n")
    print(json.dumps(summ,indent=2))

if __name__=="__main__": main()
