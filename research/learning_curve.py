#!/usr/bin/env python3
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
from prismpath import embedder
from prismpath.centroid import _decision_items, load_graphs, _unit
recs=[json.loads(l) for l in open(os.path.join(_REPO, "prismpath", "benchmark/routing_bench.jsonl"))]
graphs=load_graphs(recs, flows_dir=os.path.join(_REPO, "prismpath", "flows"))
items=_decision_items(recs, graphs)
outs=[it[0]["outcome"] for it in items]
op=np.asarray(embedder.embed(outs,is_query=False),dtype=np.float32)
conds=sorted({c for _,sem,_ in items for _,c in sem})
cvec={c:np.asarray(v,np.float32) for c,v in zip(conds,embedder.embed(conds,is_query=False))}
def cos1(a,B):
    an=a/np.clip(np.linalg.norm(a),1e-8,None); Bn=B/np.clip(np.linalg.norm(B,axis=1,keepdims=True),1e-8,None); return Bn@an
def routing_at_cap(cap, folds=5, prior=4.0):
    n=0; cc=0; gg=0
    for f in range(folds):
        tr=[i for i in range(len(items)) if i%folds!=f]; te=[i for i in range(len(items)) if i%folds==f]
        by=defaultdict(list)
        for i in tr:
            _r,sem,ci=items[i]; c=sem[ci][1]
            if cap is None or len(by[c])<cap: by[c].append(op[i])
        cen={c:_unit(np.mean(v,axis=0)) for c,v in by.items()}; cnt={c:len(v) for c,v in by.items()}
        allc=np.concatenate([np.asarray(v)-np.mean(v,axis=0) for v in by.values()]) if by else np.zeros((1,op.shape[1]))
        pooled=np.var(allc,axis=0)+1e-6
        dv={c:(0.5*(np.var(np.asarray(v)-np.mean(v,axis=0),axis=0) if len(v)>1 else pooled)+0.5*pooled+1e-6) for c,v in by.items()}
        for i in te:
            rec,sem,ci=items[i]; ec=[c for _,c in sem]
            eff=[_unit(cvec[c]) if cnt.get(c,0)==0 else _unit((prior*cvec[c]+cnt[c]*cen[c])/(prior+cnt[c])) for c in ec]
            cp=int(np.argmax(cos1(op[i],np.asarray(eff))))
            means=[cen[c] if c in cen else _unit(cvec[c]) for c in ec]
            gd=int(np.argmin([np.sum((op[i]-m)**2/dv.get(c,pooled)) for c,m in zip(ec,means)]))
            n+=1; cc+=int(cp==ci); gg+=int(gd==ci)
    return {"centroid":round(cc/n,4),"g_diag":round(gg/n,4)}
per_edge=Counter(sem[ci][1] for _,sem,ci in items)
routeA={str(c):routing_at_cap(c) for c in [3,5,8,15,None]}
routeA["_meta"]={"max_samples_per_edge":max(per_edge.values()),"median_per_edge":int(np.median(list(per_edge.values())))}

# ---------- B) DETECTION ----------
import torch

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB=os.environ.get("ETBERT_LAB", os.path.expanduser("~/cwprojects/etbert-lab"))  # part-B corpus (first-party lab repo; not in this repo)
def l2(X): X=np.asarray(X,np.float32); return X/np.clip(np.linalg.norm(X,axis=1,keepdims=True),1e-8,None)
M=l2(np.load(f"{LAB}/corpus_v2/emb.npy")); fam=np.load(f"{LAB}/corpus_v2/family.npy",allow_pickle=True).astype(str)
dev="cuda" if torch.cuda.is_available() else "cpu"
def xfam_recall_cap(cap, thr=0.95):
    idx=[]
    for c in np.unique(fam):
        fi=np.where(fam==c)[0]; idx.extend(fi[:cap].tolist() if cap else fi.tolist())
    idx=np.array(sorted(idx)); Ms=M[idx]; fs=fam[idx]
    _,inv=np.unique(fs,return_inverse=True); Mt=torch.tensor(Ms,device=dev); ft=torch.tensor(inv,device=dev)
    sbad=np.empty(len(Ms),np.float32)
    for i in range(0,len(Ms),4096):
        S=Mt[i:i+4096]@Mt.T; S=S.masked_fill(ft[i:i+4096,None]==ft[None,:],-1.0); sbad[i:i+4096]=S.max(1).values.cpu().numpy()
    flag=sbad>=thr
    return round(float(np.mean([flag[fs==c].mean() for c in np.unique(fs)])),4), int(len(Ms))
detB={}
for cap in [25,50,100,200,None]:
    r,ntot=xfam_recall_cap(cap); detB[str(cap)]={"macro_recall":r,"corpus_flows":ntot}

out={"routing_vs_samples_per_edge":routeA,"detection_vs_flows_per_family":detB,
     "read":"compare the last two rows in each: still rising => more data helps; flat => it won't"}
json.dump(out,open(os.path.join(_REPO, "prismpath", "benchmark/learning_curve.json"),"w"),indent=2)
print(json.dumps(out,indent=2))
