#!/usr/bin/env python3
"""Task #41 — PCA-reduced density routing + don't-know, PRE-REGISTERED bar.
Per fold: PCA-fit on TRAIN outcomes (no leakage) -> k dims; per-edge mean + FULL shrunk covariance
(now estimable); route by Gaussian log-likelihood. Don't-know = max log-lik under candidates.
SCREEN: don't-know AUC (correct vs wrong) >= 0.75 (raw 768-d gave 0.582).
GRADUATION: likelihood-abstention must BEAT cosine-margin-escalation on the accuracy/escalation
frontier at matched escalation rate. Else park.
"""
import os, sys, json, numpy as np
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prismpath import embedder
from prismpath.centroid import _decision_items, load_graphs, _unit

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
K=32; LAM=0.3; folds=5
recs=[json.loads(l) for l in open(os.path.join(_REPO, "prismpath", "benchmark/routing_bench.jsonl"))]
graphs=load_graphs(recs, flows_dir=os.path.join(_REPO, "prismpath", "flows"))
items=_decision_items(recs, graphs)
outs=[it[0]["outcome"] for it in items]
op=np.asarray(embedder.embed(outs,is_query=False),dtype=np.float64)

rows=[]  # (correct_gpca, max_ll, cos_margin, stratum)
n_corr=0
for f in range(folds):
    tr=[i for i in range(len(items)) if i%folds!=f]; te=[i for i in range(len(items)) if i%folds==f]
    # PCA on train (center + top-K)
    Xtr=op[tr]; mu=Xtr.mean(0); Xc=Xtr-mu
    U,S,Vt=np.linalg.svd(Xc, full_matrices=False); W=Vt[:K].T           # (768,K)
    proj=lambda X:(X-mu)@W
    Ptr={i:proj(op[i:i+1])[0] for i in tr}; Pte={i:proj(op[i:i+1])[0] for i in te}
    by=defaultdict(list)
    for i in tr:
        _r,sem,ci=items[i]; by[sem[ci][1]].append(Ptr[i])
    gp={}  # edge -> (mean, inv_cov, logdet)
    kI=np.eye(K)
    for c,v in by.items():
        V=np.asarray(v); m=V.mean(0)
        if len(V)>1:
            Sc=np.cov(V.T)
        else:
            Sc=np.zeros((K,K))
        Ssh=(1-LAM)*Sc + LAM*(np.trace(Sc)/K if np.trace(Sc)>0 else 1.0)*kI + 1e-4*kI
        sign,logdet=np.linalg.slogdet(Ssh); inv=np.linalg.inv(Ssh)
        gp[c]=(m,inv,logdet)
    cen={c:_unit(np.asarray(v).mean(0)) for c,v in by.items()}   # PCA-space centroid for the margin baseline
    for i in te:
        rec,sem,ci=items[i]; ec=[c for _,c in sem]; x=Pte[i]
        lls=[]
        for c in ec:
            if c in gp:
                m,inv,ld=gp[c]; d=x-m; lls.append(-0.5*float(d@inv@d)-0.5*ld)
            else:
                lls.append(-1e9)
        pred=int(np.argmax(lls)); maxll=max(lls)
        # cosine margin on PCA-space centroids (fallback tiny for unseen)
        cs=[float(_unit(x)@cen[c]) if c in cen else -1.0 for c in ec]
        cs_sorted=sorted(cs, reverse=True); margin=cs_sorted[0]-(cs_sorted[1] if len(cs_sorted)>1 else 0.0)
        ok=int(pred==ci); n_corr+=ok
        rows.append((ok, maxll, margin, rec.get("stratum","?")))

n=len(rows); acc=n_corr/n
ok=np.array([r[0] for r in rows]); mll=np.array([r[1] for r in rows]); marg=np.array([r[2] for r in rows])
# don't-know AUC: wrong should have LOWER max-ll -> P(ll_correct > ll_wrong)
c_ll=mll[ok==1]; w_ll=mll[ok==0]
def auc(pos,neg):
    if len(pos)==0 or len(neg)==0: return None
    allv=np.concatenate([pos,neg]); order=allv.argsort(); ranks=np.empty_like(order,float); ranks[order]=np.arange(1,len(allv)+1)
    return float((ranks[:len(pos)].sum()-len(pos)*(len(pos)+1)/2)/(len(pos)*len(neg)))
dk_auc=auc(c_ll,w_ll)   # higher => ll separates correct(high) from wrong(low)
# frontier: escalate lowest-confidence fraction to oracle(correct); acc = (kept_correct + escalated)/n
def frontier(conf):  # higher conf = keep; escalate lowest conf first
    idx=np.argsort(conf)  # ascending: lowest conf first
    out={}
    for fr in [0.0,0.1,0.2,0.3,0.4,0.5]:
        k=int(round(fr*n)); esc=set(idx[:k].tolist())
        kept_ok=sum(ok[i] for i in range(n) if i not in esc)
        out[fr]=round((kept_ok+k)/n,4)
    return out
fr_ll=frontier(mll); fr_marg=frontier(marg)
wins=sum(1 for fr in fr_ll if fr>0 and fr_ll[fr]>fr_marg[fr]); ties=sum(1 for fr in fr_ll if fr>0 and abs(fr_ll[fr]-fr_marg[fr])<1e-9)
verdict = "GRADUATE" if (dk_auc and dk_auc>=0.75 and all(fr_ll[fr]>=fr_marg[fr] for fr in fr_ll if fr>0)) else "PARK"
res=dict(K=K, gpca_accuracy=round(acc,4), dont_know_auc=round(dk_auc,4) if dk_auc else None,
         screen_ge_0p75=bool(dk_auc and dk_auc>=0.75),
         frontier_likelihood=fr_ll, frontier_margin=fr_marg,
         likelihood_beats_margin_at_matched_escalation=all(fr_ll[fr]>=fr_marg[fr] for fr in fr_ll if fr>0),
         VERDICT=verdict, note="baselines for ref: centroid 0.827, raw-768 gaussian 0.797/0.803, raw dont-know AUC 0.582")
json.dump(res, open(os.path.join(_REPO, "research", "benchmark/gaussian_route_pca.json"),"w"), indent=2)
print(json.dumps(res, indent=2))
