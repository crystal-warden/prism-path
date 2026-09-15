#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Task #42 — learning-curve model: would MORE/differentiated data change results?
Subsamples EXISTING data (no collection) and reads the slope near the top of our range.
  A) Routing: centroid & g_diag accuracy vs samples-per-edge  (does more labeled disposition help?)
  B) Detection: cross-family recall@0.95 vs flows-per-family   (does more per-family data lift the 22%?)
Rising, unplateaued near the top => collection (#38/#40 dispositions, #35/#30 flows) will move it.
Flat => it won't. NEVER touches model-gemma.
"""
import os, sys, json, numpy as np
from collections import defaultdict, Counter
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------- A) ROUTING ----------
from prismpath.routing import embedder
from prismpath.routing.centroid import _decision_items, load_graphs, _unit

recs=[json.loads(line) for line in open(os.path.join(_REPO, "prismpath", "benchmark/routing_bench.jsonl"))]
graphs=load_graphs(recs, flows_dir=os.path.join(_REPO, "prismpath", "flows"))
items=_decision_items(recs, graphs)
outs=[it[0]["outcome"] for it in items]
op=np.asarray(embedder.embed(outs,is_query=False),dtype=np.float32)
conds=sorted({condition for _,sem,_ in items for _,condition in sem})
cvec={condition:np.asarray(vectors,np.float32) for condition,vectors in zip(conds,embedder.embed(conds,is_query=False))}
def cos1(vector_a,matrix_b):
    an=vector_a/np.clip(np.linalg.norm(vector_a),1e-8,None); Bn=matrix_b/np.clip(np.linalg.norm(matrix_b,axis=1,keepdims=True),1e-8,None); return Bn@an
def routing_at_cap(cap, folds=5, prior=4.0):
    sample_count=0; cc=0; gg=0
    for fold_index in range(folds):
        tr=[item_index for item_index in range(len(items)) if item_index%folds!=fold_index]; te=[item_index for item_index in range(len(items)) if item_index%folds==fold_index]
        by=defaultdict(list)
        for item_index in tr:
            _r,sem,ci=items[item_index]; condition=sem[ci][1]
            if cap is None or len(by[condition])<cap: by[condition].append(op[item_index])
        cen={condition:_unit(np.mean(vectors,axis=0)) for condition,vectors in by.items()}; cnt={condition:len(vectors) for condition,vectors in by.items()}
        allc=np.concatenate([np.asarray(vectors)-np.mean(vectors,axis=0) for vectors in by.values()]) if by else np.zeros((1,op.shape[1]))
        pooled=np.var(allc,axis=0)+1e-6
        dv={condition:(0.5*(np.var(np.asarray(vectors)-np.mean(vectors,axis=0),axis=0) if len(vectors)>1 else pooled)+0.5*pooled+1e-6) for condition,vectors in by.items()}
        for item_index in te:
            rec,sem,ci=items[item_index]; ec=[condition for _,condition in sem]
            eff=[_unit(cvec[condition]) if cnt.get(condition,0)==0 else _unit((prior*cvec[condition]+cnt[condition]*cen[condition])/(prior+cnt[condition])) for condition in ec]
            cp=int(np.argmax(cos1(op[item_index],np.asarray(eff))))
            means=[cen[condition] if condition in cen else _unit(cvec[condition]) for condition in ec]
            gd=int(np.argmin([np.sum((op[item_index]-mean_vector)**2/dv.get(condition,pooled)) for condition,mean_vector in zip(ec,means)]))
            sample_count+=1; cc+=int(cp==ci); gg+=int(gd==ci)
    return {"centroid":round(cc/sample_count,4),"g_diag":round(gg/sample_count,4)}
per_edge=Counter(sem[ci][1] for _,sem,ci in items)
routeA={str(sample_cap):routing_at_cap(sample_cap) for sample_cap in [3,5,8,15,None]}
routeA["_meta"]={"max_samples_per_edge":max(per_edge.values()),"median_per_edge":int(np.median(list(per_edge.values())))}

# ---------- B) DETECTION ----------
import torch

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB=os.environ.get("ETBERT_LAB", os.path.expanduser("~/cwprojects/etbert-lab"))  # part-B corpus (first-party lab repo; not in this repo)
def l2(matrix_x): matrix_x=np.asarray(matrix_x,np.float32); return matrix_x/np.clip(np.linalg.norm(matrix_x,axis=1,keepdims=True),1e-8,None)
embeddings_matrix=l2(np.load(f"{LAB}/corpus_v2/emb.npy")); fam=np.load(f"{LAB}/corpus_v2/family.npy",allow_pickle=True).astype(str)
dev="cuda" if torch.cuda.is_available() else "cpu"
def xfam_recall_cap(cap, thr=0.95):
    idx=[]
    for family_label in np.unique(fam):
        fi=np.where(fam==family_label)[0]; idx.extend(fi[:cap].tolist() if cap else fi.tolist())
    idx=np.array(sorted(idx)); Ms=embeddings_matrix[idx]; fs=fam[idx]
    _,inv=np.unique(fs,return_inverse=True); Mt=torch.tensor(Ms,device=dev); ft=torch.tensor(inv,device=dev)
    sbad=np.empty(len(Ms),np.float32)
    for chunk_offset in range(0,len(Ms),4096):
        sim_matrix=Mt[chunk_offset:chunk_offset+4096]@Mt.T; sim_matrix=sim_matrix.masked_fill(ft[chunk_offset:chunk_offset+4096,None]==ft[None,:],-1.0); sbad[chunk_offset:chunk_offset+4096]=sim_matrix.max(1).values.cpu().numpy()
    flag=sbad>=thr
    return round(float(np.mean([flag[fs==family_label].mean() for family_label in np.unique(fs)])),4), int(len(Ms))
detB={}
for cap in [25,50,100,200,None]:
    macro_recall_val,ntot=xfam_recall_cap(cap); detB[str(cap)]={"macro_recall":macro_recall_val,"corpus_flows":ntot}

out={"routing_vs_samples_per_edge":routeA,"detection_vs_flows_per_family":detB,
     "read":"compare the last two rows in each: still rising => more data helps; flat => it won't"}
json.dump(out,open(os.path.join(_REPO, "research", "benchmark/learning_curve.json"),"w"),indent=2)
print(json.dumps(out,indent=2))
