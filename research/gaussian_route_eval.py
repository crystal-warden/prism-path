#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
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
from prismpath.routing import embedder
from prismpath.routing.centroid import _decision_items, load_graphs, _unit
from collections import defaultdict

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BENCH=os.path.join(_REPO, "prismpath", "benchmark/routing_bench.jsonl")
FLOWS=os.path.join(_REPO, "prismpath", "flows")
records=[json.loads(line) for line in open(BENCH)]
graphs=load_graphs(records, flows_dir=FLOWS)
items=_decision_items(records, graphs)
outs=[it[0]["outcome"] for it in items]
op=np.asarray(embedder.embed(outs, is_query=False), dtype=np.float32)   # passage (centroid) space
oq=np.asarray(embedder.embed(outs, is_query=True),  dtype=np.float32)   # query (cosine baseline)
conds=sorted({condition for _,sem,_ in items for _,condition in sem})
cvec={condition:np.asarray(vectors,dtype=np.float32) for condition,vectors in zip(conds, embedder.embed(conds,is_query=False))}
dimension=op.shape[1]; folds=5; prior=4.0; LAM=0.3

def cos1(vector_a,matrix_b):
    an=vector_a/np.clip(np.linalg.norm(vector_a),1e-8,None); Bn=matrix_b/np.clip(np.linalg.norm(matrix_b,axis=1,keepdims=True),1e-8,None)
    return Bn@an

tally=defaultdict(lambda:{"n":0,"baseline":0,"centroid":0,"g_shared":0,"g_diag":0})
dk_c, dk_w = [], []
for fold_index in range(folds):
    tr=[item_index for item_index in range(len(items)) if item_index%folds!=fold_index]; te=[item_index for item_index in range(len(items)) if item_index%folds==fold_index]
    by=defaultdict(list)
    for item_index in tr:
        _r,sem,ci=items[item_index]; by[sem[ci][1]].append(op[item_index])
    cen={condition:_unit(np.mean(vectors,axis=0)) for condition,vectors in by.items()}; cnt={condition:len(vectors) for condition,vectors in by.items()}
    Xc=[]
    for condition,vectors in by.items():
        mean_vector=np.mean(vectors,axis=0); Xc+=[sample_vec-mean_vector for sample_vec in vectors]
    Xc=np.asarray(Xc,dtype=np.float32)
    cov_matrix=(Xc.T@Xc)/max(len(Xc)-1,1)
    S_sh=(1-LAM)*cov_matrix + LAM*(np.trace(cov_matrix)/dimension)*np.eye(dimension,dtype=np.float32)
    S_inv=np.linalg.pinv(S_sh)
    pooled_var=np.var(Xc,axis=0)+1e-6
    diagvar={}
    for condition,vectors in by.items():
        vectors=np.asarray(vectors)
        dv=np.var(vectors-np.mean(vectors,axis=0),axis=0) if len(vectors)>1 else pooled_var
        diagvar[condition]=0.5*dv+0.5*pooled_var+1e-6
    for item_index in te:
        rec,sem,ci=items[item_index]; ec=[condition for _,condition in sem]
        baseline_pred=int(np.argmax(cos1(oq[item_index], np.asarray([cvec[condition] for condition in ec]))))
        eff=[_unit(cvec[condition]) if cnt.get(condition,0)==0 else _unit((prior*cvec[condition]+cnt[condition]*cen[condition])/(prior+cnt[condition])) for condition in ec]
        cp=int(np.argmax(cos1(op[item_index], np.asarray(eff))))
        means=[cen[condition] if condition in cen else _unit(cvec[condition]) for condition in ec]
        maha=[float((op[item_index]-mean_vector)@S_inv@(op[item_index]-mean_vector)) for mean_vector in means]
        gs=int(np.argmin(maha))
        dll=[float(np.sum((op[item_index]-mean_vector)**2/diagvar.get(condition,pooled_var))) for condition,mean_vector in zip(ec,means)]
        gd=int(np.argmin(dll))
        for key in (rec.get("stratum","?"),"ALL"):
            tally_entry=tally[key]; tally_entry["n"]+=1
            tally_entry["baseline"]+=int(baseline_pred==ci); tally_entry["centroid"]+=int(cp==ci); tally_entry["g_shared"]+=int(gs==ci); tally_entry["g_diag"]+=int(gd==ci)
        (dk_c if gs==ci else dk_w).append(min(maha))

res={}
for stratum_key,vectors in tally.items():
    sample_count=vectors["n"]; res[stratum_key]={mean_vector:round(vectors[mean_vector]/sample_count,4) for mean_vector in ("baseline","centroid","g_shared","g_diag")}; res[stratum_key]["n"]=sample_count
condition=np.array(dk_c); wrong_scores=np.array(dk_w); auc=None
if len(condition) and len(wrong_scores):
    allv=np.concatenate([wrong_scores,condition]); order=allv.argsort(); ranks=np.empty_like(order,float); ranks[order]=np.arange(1,len(allv)+1)
    auc=float((ranks[:len(wrong_scores)].sum()-len(wrong_scores)*(len(wrong_scores)+1)/2)/(len(wrong_scores)*len(condition)))
res["dont_know"]={"n_correct":len(condition),"n_wrong":len(wrong_scores),
                  "maha_correct_mean":round(float(condition.mean()),2) if len(condition) else None,
                  "maha_wrong_mean":round(float(wrong_scores.mean()),2) if len(wrong_scores) else None,
                  "auc_wrong_farther_than_correct":round(auc,4) if auc else None}
res["config"]={"folds":folds,"shrinkage_lambda":LAM,"prior":prior,"n_decisions":len(items),"dim":dimension}
json.dump(res, open(os.path.join(_REPO, "research", "benchmark/gaussian_route_eval.json"),"w"), indent=2)
print(json.dumps(res, indent=2))
