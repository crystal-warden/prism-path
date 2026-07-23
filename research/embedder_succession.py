#!/usr/bin/env python3
"""Task #48 — embedder scouting harness + succession alignment.
A) SCOUTING: score any candidate embedder on the N=301 routing suite (per-stratum centroid CV) vs
   the bge-base baseline. The 'upgrade engine' = tooling, not a model.
B) SUCCESSION: migrate locked artifacts (centroids) across an embedder change via a fitted linear map,
   with the PRE-REGISTERED bar: routing accuracy under MAPPED artifacts must retain >=98% of native.
   Unit test: a random rotation (must retain ~100%, validates the machinery). Real test:
   bge-base -> bge-small (cross-model AND cross-dim -> a general ridge linear map, not orthogonal).
NEVER touches model-gemma (bge models are tiny).
"""
import sys, json, numpy as np
from collections import defaultdict
sys.path.insert(0,"/home/cwadmin/cwprojects")
from sentence_transformers import SentenceTransformer
from mdflow.centroid import _decision_items, load_graphs, _unit
BENCH="/home/cwadmin/cwprojects/mdflow/benchmark/routing_bench.jsonl"; FLOWS="/home/cwadmin/cwprojects/mdflow/flows"
recs=[json.loads(l) for l in open(BENCH)]; graphs=load_graphs(recs,flows_dir=FLOWS); items=_decision_items(recs,graphs)
outs=[it[0]["outcome"] for it in items]; conds=sorted({c for _,sem,_ in items for _,c in sem})
folds=5; PRIOR=4.0
def embed_all(model, dev="cuda"):
    m=SentenceTransformer(model, device=dev)
    O=np.asarray(m.encode(outs,normalize_embeddings=True,batch_size=256,show_progress_bar=False),np.float64)
    C=np.asarray(m.encode(conds,normalize_embeddings=True,batch_size=256,show_progress_bar=False),np.float64)
    del m
    try:
        import torch; torch.cuda.empty_cache()
    except Exception: pass
    return O, {c:v for c,v in zip(conds,C)}
def cos1(a,B): 
    an=a/np.clip(np.linalg.norm(a),1e-8,None); Bn=B/np.clip(np.linalg.norm(B,axis=1,keepdims=True),1e-8,None); return Bn@an
def centroid_cv(O, cvec):
    t=defaultdict(lambda:{"n":0,"c":0})
    for f in range(folds):
        tr=[i for i in range(len(items)) if i%folds!=f]; te=[i for i in range(len(items)) if i%folds==f]
        by=defaultdict(list)
        for i in tr:
            _r,sem,ci=items[i]; by[sem[ci][1]].append(O[i])
        cen={c:_unit(np.mean(v,0)) for c,v in by.items()}; cnt={c:len(v) for c,v in by.items()}
        for i in te:
            rec,sem,ci=items[i]; ec=[c for _,c in sem]
            eff=[_unit(cvec[c]) if cnt.get(c,0)==0 else _unit((PRIOR*cvec[c]+cnt[c]*cen[c])/(PRIOR+cnt[c])) for c in ec]
            p=int(np.argmax(cos1(O[i],np.asarray(eff))))
            for k in (rec.get("stratum","?"),"ALL"): t[k]["n"]+=1; t[k]["c"]+=int(p==ci)
    return {k:round(v["c"]/v["n"],4) for k,v in t.items()}

# --- embed under available models ---
Ob,Cb=embed_all("BAAI/bge-base-en-v1.5")
Os,Cs=embed_all("BAAI/bge-small-en-v1.5")
scout={"bge-base_768(baseline)":centroid_cv(Ob,Cb), "bge-small_384(candidate)":centroid_cv(Os,Cs)}
extra=None
try:
    Og,Cg=embed_all("google/embeddinggemma-300m"); scout["embeddinggemma"]=centroid_cv(Og,Cg); extra="embeddinggemma scored"
except Exception as e:
    extra=f"embeddinggemma unavailable offline ({str(e)[:60]}) -> queued as first real customer"

# --- succession: map OLD->NEW, migrate centroids built in OLD, test on NEW held-out ---
def ridge_map(A,B,lam=1e-2):   # A(n,d1)->B(n,d2): M=(A'A+lamI)^-1 A'B
    d=A.shape[1]; return np.linalg.solve(A.T@A+lam*np.eye(d), A.T@B)
def succession_cv(Oo,Co,On,Cn):
    ret=[]; anchor_o=np.vstack([Oo,np.asarray([Co[c] for c in conds])]); anchor_n=np.vstack([On,np.asarray([Cn[c] for c in conds])])
    for f in range(folds):
        tr=[i for i in range(len(items)) if i%folds!=f]; te=[i for i in range(len(items)) if i%folds==f]
        A=np.vstack([Oo[tr],np.asarray([Co[c] for c in conds])]); Bn=np.vstack([On[tr],np.asarray([Cn[c] for c in conds])])
        M=ridge_map(A,Bn)
        by=defaultdict(list)
        for i in tr:
            _r,sem,ci=items[i]; by[sem[ci][1]].append(Oo[i])   # OLD-space centroids (the stranded artifact)
        cen_old={c:np.mean(v,0) for c,v in by.items()}
        cen_map={c:_unit(cen_old[c]@M) for c in cen_old}          # migrate to NEW space via M
        cen_nat={c:_unit(np.mean([On[i] for i in tr if items[i][1][items[i][2]][1]==c],0)) if any(items[i][1][items[i][2]][1]==c for i in tr) else _unit(Cn[c]) for c in by}
        mok=nok=n=0
        for i in te:
            rec,sem,ci=items[i]; ec=[c for _,c in sem]
            mp=int(np.argmax(cos1(On[i],np.asarray([cen_map.get(c,_unit(Cn[c])) for c in ec]))))
            npk=int(np.argmax(cos1(On[i],np.asarray([cen_nat.get(c,_unit(Cn[c])) for c in ec]))))
            n+=1; mok+=int(mp==ci); nok+=int(npk==ci)
        ret.append((mok/n, nok/n))
    m=np.mean([r[0] for r in ret]); nat=np.mean([r[1] for r in ret])
    return dict(mapped_acc=round(float(m),4), native_acc=round(float(nat),4),
                retention=round(float(m/nat),4) if nat>0 else None, passes_98=bool(nat>0 and m/nat>=0.98))
# unit test: random rotation of bge-base (spaces ARE rotation-related -> should retain ~100%)
rng=np.random.RandomState(0); Q,_=np.linalg.qr(rng.randn(Ob.shape[1],Ob.shape[1]))
Orot=Ob@Q; Crot={c:Cb[c]@Q for c in conds}
unit=succession_cv(Ob,Cb,Orot,Crot)
real=succession_cv(Ob,Cb,Os,Cs)
out=dict(scouting=scout, scouting_note=extra,
         succession_unit_test_rotation=unit, succession_real_bgebase_to_bgesmall=real,
         verdict_real=("PASS ≥98%" if real["passes_98"] else "BELOW 98% -> vector-only artifacts don't survive this succession; retain text"))
json.dump(out, open("/home/cwadmin/cwprojects/mdflow/benchmark/embedder_succession.json","w"), indent=2)
print(json.dumps(out, indent=2))
