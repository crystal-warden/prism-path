#!/usr/bin/env python3
"""Task #39 — Gaussian-per-edge density routing vs cosine+centroid on the N=301 suite.

Converts the escalation margin (a 'the embedder can't say how unsure it is' hack) into a native
density test. Reuses centroid.py's _decision_items + the SAME 5-fold split (no leakage). Two Gaussian
arms with the mandatory shrinkage (full per-edge cov is singular at these n):
  g_shared : per-edge mean + POOLED shrinkage covariance (LDA-style Mahalanobis) — robust at small n
  g_diag   : per-edge mean + per-edge diagonal variance shrunk toward pooled diagonal
Plus the payoff: don't-know detection — does min-Mahalanobis (confidence) separate correct picks from
wrong ones? (AUC: P(wrong is farther than correct)). That's the principled replacement for the margin.
"""
import os, sys, json, numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prismpath import embedder
from prismpath.centroid import _decision_items, load_graphs, _unit
from collections import defaultdict

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BENCH=os.path.join(_REPO, "prismpath", "benchmark/routing_bench.jsonl")
FLOWS=os.path.join(_REPO, "prismpath", "flows")
records=[json.loads(l) for l in open(BENCH)]
graphs=load_graphs(records, flows_dir=FLOWS)
items=_decision_items(records, graphs)
outs=[it[0]["outcome"] for it in items]
op=np.asarray(embedder.embed(outs, is_query=False), dtype=np.float32)   # passage (centroid) space
oq=np.asarray(embedder.embed(outs, is_query=True),  dtype=np.float32)   # query (cosine baseline)
conds=sorted({c for _,sem,_ in items for _,c in sem})
cvec={c:np.asarray(v,dtype=np.float32) for c,v in zip(conds, embedder.embed(conds,is_query=False))}
d=op.shape[1]; folds=5; prior=4.0; LAM=0.3

def cos1(a,B):
    an=a/np.clip(np.linalg.norm(a),1e-8,None); Bn=B/np.clip(np.linalg.norm(B,axis=1,keepdims=True),1e-8,None)
    return Bn@an

tally=defaultdict(lambda:{"n":0,"baseline":0,"centroid":0,"g_shared":0,"g_diag":0})
dk_c, dk_w = [], []
for f in range(folds):
    tr=[i for i in range(len(items)) if i%folds!=f]; te=[i for i in range(len(items)) if i%folds==f]
    by=defaultdict(list)
    for i in tr:
        _r,sem,ci=items[i]; by[sem[ci][1]].append(op[i])
    cen={c:_unit(np.mean(v,axis=0)) for c,v in by.items()}; cnt={c:len(v) for c,v in by.items()}
    Xc=[]
    for c,v in by.items():
        m=np.mean(v,axis=0); Xc+=[x-m for x in v]
    Xc=np.asarray(Xc,dtype=np.float32)
    S=(Xc.T@Xc)/max(len(Xc)-1,1)
    S_sh=(1-LAM)*S + LAM*(np.trace(S)/d)*np.eye(d,dtype=np.float32)
    S_inv=np.linalg.pinv(S_sh)
    pooled_var=np.var(Xc,axis=0)+1e-6
    diagvar={}
    for c,v in by.items():
        v=np.asarray(v)
        dv=np.var(v-np.mean(v,axis=0),axis=0) if len(v)>1 else pooled_var
        diagvar[c]=0.5*dv+0.5*pooled_var+1e-6
    for i in te:
        rec,sem,ci=items[i]; ec=[c for _,c in sem]
        b=int(np.argmax(cos1(oq[i], np.asarray([cvec[c] for c in ec]))))
        eff=[_unit(cvec[c]) if cnt.get(c,0)==0 else _unit((prior*cvec[c]+cnt[c]*cen[c])/(prior+cnt[c])) for c in ec]
        cp=int(np.argmax(cos1(op[i], np.asarray(eff))))
        means=[cen[c] if c in cen else _unit(cvec[c]) for c in ec]
        maha=[float((op[i]-m)@S_inv@(op[i]-m)) for m in means]
        gs=int(np.argmin(maha))
        dll=[float(np.sum((op[i]-m)**2/diagvar.get(c,pooled_var))) for c,m in zip(ec,means)]
        gd=int(np.argmin(dll))
        for key in (rec.get("stratum","?"),"ALL"):
            t=tally[key]; t["n"]+=1
            t["baseline"]+=int(b==ci); t["centroid"]+=int(cp==ci); t["g_shared"]+=int(gs==ci); t["g_diag"]+=int(gd==ci)
        (dk_c if gs==ci else dk_w).append(min(maha))

res={}
for k,v in tally.items():
    n=v["n"]; res[k]={m:round(v[m]/n,4) for m in ("baseline","centroid","g_shared","g_diag")}; res[k]["n"]=n
c=np.array(dk_c); w=np.array(dk_w); auc=None
if len(c) and len(w):
    allv=np.concatenate([w,c]); order=allv.argsort(); ranks=np.empty_like(order,float); ranks[order]=np.arange(1,len(allv)+1)
    auc=float((ranks[:len(w)].sum()-len(w)*(len(w)+1)/2)/(len(w)*len(c)))
res["dont_know"]={"n_correct":len(c),"n_wrong":len(w),
                  "maha_correct_mean":round(float(c.mean()),2) if len(c) else None,
                  "maha_wrong_mean":round(float(w.mean()),2) if len(w) else None,
                  "auc_wrong_farther_than_correct":round(auc,4) if auc else None}
res["config"]={"folds":folds,"shrinkage_lambda":LAM,"prior":prior,"n_decisions":len(items),"dim":d}
json.dump(res, open(os.path.join(_REPO, "research", "benchmark/gaussian_route_eval.json"),"w"), indent=2)
print(json.dumps(res, indent=2))
