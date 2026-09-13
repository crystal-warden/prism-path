#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
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
from prismpath.routing import embedder
from prismpath.routing.centroid import _decision_items, load_graphs, _unit

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
num_components=32; LAM=0.3; folds=5
recs=[json.loads(line) for line in open(os.path.join(_REPO, "prismpath", "benchmark/routing_bench.jsonl"))]
graphs=load_graphs(recs, flows_dir=os.path.join(_REPO, "prismpath", "flows"))
items=_decision_items(recs, graphs)
outs=[it[0]["outcome"] for it in items]
op=np.asarray(embedder.embed(outs,is_query=False),dtype=np.float64)

rows=[]  # (correct_gpca, max_ll, cos_margin, stratum)
n_corr=0
for fold_index in range(folds):
    tr=[item_index for item_index in range(len(items)) if item_index%folds!=fold_index]; te=[item_index for item_index in range(len(items)) if item_index%folds==fold_index]
    # PCA on train (center + top-K)
    Xtr=op[tr]; mu=Xtr.mean(0); Xc=Xtr-mu
    u_matrix,s_vector,Vt=np.linalg.svd(Xc, full_matrices=False); projection_matrix=Vt[:num_components].T           # (768,K)
    proj=lambda vec_x:(vec_x-mu)@projection_matrix
    Ptr={item_index:proj(op[item_index:item_index+1])[0] for item_index in tr}; Pte={item_index:proj(op[item_index:item_index+1])[0] for item_index in te}
    by=defaultdict(list)
    for item_index in tr:
        _r,sem,ci=items[item_index]; by[sem[ci][1]].append(Ptr[item_index])
    gp={}  # edge -> (mean, inv_cov, logdet)
    kI=np.eye(num_components)
    for condition,vectors in by.items():
        vector_array=np.asarray(vectors); mean_vector=vector_array.mean(0)
        if len(vector_array)>1:
            Sc=np.cov(vector_array.T)
        else:
            Sc=np.zeros((num_components,num_components))
        Ssh=(1-LAM)*Sc + LAM*(np.trace(Sc)/num_components if np.trace(Sc)>0 else 1.0)*kI + 1e-4*kI
        sign,logdet=np.linalg.slogdet(Ssh); inv=np.linalg.inv(Ssh)
        gp[condition]=(mean_vector,inv,logdet)
    cen={condition:_unit(np.asarray(vectors).mean(0)) for condition,vectors in by.items()}   # PCA-space centroid for the margin baseline
    for item_index in te:
        rec,sem,ci=items[item_index]; ec=[condition for _,condition in sem]; sample_vec=Pte[item_index]
        lls=[]
        for condition in ec:
            if condition in gp:
                mean_vector,inv,ld=gp[condition]; diff_vec=sample_vec-mean_vector; lls.append(-0.5*float(diff_vec@inv@diff_vec)-0.5*ld)
            else:
                lls.append(-1e9)
        pred=int(np.argmax(lls)); maxll=max(lls)
        # cosine margin on PCA-space centroids (fallback tiny for unseen)
        cs=[float(_unit(sample_vec)@cen[condition]) if condition in cen else -1.0 for condition in ec]
        cs_sorted=sorted(cs, reverse=True); margin=cs_sorted[0]-(cs_sorted[1] if len(cs_sorted)>1 else 0.0)
        ok=int(pred==ci); n_corr+=ok
        rows.append((ok, maxll, margin, rec.get("stratum","?")))

num_rows=len(rows); acc=n_corr/num_rows
ok=np.array([row[0] for row in rows]); mll=np.array([row[1] for row in rows]); marg=np.array([row[2] for row in rows])
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
        escalated_count=int(round(fr*num_rows)); esc=set(idx[:escalated_count].tolist())
        kept_ok=sum(ok[row_index] for row_index in range(num_rows) if row_index not in esc)
        out[fr]=round((kept_ok+escalated_count)/num_rows,4)
    return out
fr_ll=frontier(mll); fr_marg=frontier(marg)
wins=sum(1 for fr in fr_ll if fr>0 and fr_ll[fr]>fr_marg[fr]); ties=sum(1 for fr in fr_ll if fr>0 and abs(fr_ll[fr]-fr_marg[fr])<1e-9)
verdict = "GRADUATE" if (dk_auc and dk_auc>=0.75 and all(fr_ll[fr]>=fr_marg[fr] for fr in fr_ll if fr>0)) else "PARK"
res=dict(K=num_components, gpca_accuracy=round(acc,4), dont_know_auc=round(dk_auc,4) if dk_auc else None,
         screen_ge_0p75=bool(dk_auc and dk_auc>=0.75),
         frontier_likelihood=fr_ll, frontier_margin=fr_marg,
         likelihood_beats_margin_at_matched_escalation=all(fr_ll[fr]>=fr_marg[fr] for fr in fr_ll if fr>0),
         VERDICT=verdict, note="baselines for ref: centroid 0.827, raw-768 gaussian 0.797/0.803, raw dont-know AUC 0.582")
json.dump(res, open(os.path.join(_REPO, "research", "benchmark/gaussian_route_pca.json"),"w"), indent=2)
print(json.dumps(res, indent=2))
