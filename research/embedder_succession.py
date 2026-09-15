#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Task #48 — embedder scouting harness + succession alignment.
A) SCOUTING: score any candidate embedder on the N=301 routing suite (per-stratum centroid CV) vs
   the bge-base baseline. The 'upgrade engine' = tooling, not a model.
B) SUCCESSION: migrate locked artifacts (centroids) across an embedder change via a fitted linear map,
   with the PRE-REGISTERED bar: routing accuracy under MAPPED artifacts must retain >=98% of native.
   Unit test: a random rotation (must retain ~100%, validates the machinery). Real test:
   bge-base -> bge-small (cross-model AND cross-dim -> a general ridge linear map, not orthogonal).
NEVER touches model-gemma (bge models are tiny).
"""
import os, sys, json, numpy as np
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentence_transformers import SentenceTransformer
from prismpath.routing.centroid import _decision_items, load_graphs, _unit

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH=os.path.join(_REPO, "prismpath", "benchmark/routing_bench.jsonl"); FLOWS=os.path.join(_REPO, "prismpath", "flows")
recs=[json.loads(line) for line in open(BENCH)]; graphs=load_graphs(recs,flows_dir=FLOWS); items=_decision_items(recs,graphs)
outs=[it[0]["outcome"] for it in items]; conds=sorted({condition for _,sem,_ in items for _,condition in sem})
folds=5; PRIOR=4.0
def embed_all(model, dev="cuda"):
    transformer_model=SentenceTransformer(model, device=dev)
    outcome_matrix=np.asarray(transformer_model.encode(outs,normalize_embeddings=True,batch_size=256,show_progress_bar=False),np.float64)
    condition_matrix=np.asarray(transformer_model.encode(conds,normalize_embeddings=True,batch_size=256,show_progress_bar=False),np.float64)
    del transformer_model
    try:
        import torch; torch.cuda.empty_cache()
    except Exception: pass
    return outcome_matrix, {condition:vector for condition,vector in zip(conds,condition_matrix)}
def cos1(vector_a,matrix_b): 
    an=vector_a/np.clip(np.linalg.norm(vector_a),1e-8,None); Bn=matrix_b/np.clip(np.linalg.norm(matrix_b,axis=1,keepdims=True),1e-8,None); return Bn@an
def centroid_cv(outcome_embeddings, cvec):
    tally=defaultdict(lambda:{"n":0,"c":0})
    for fold_index in range(folds):
        tr=[item_index for item_index in range(len(items)) if item_index%folds!=fold_index]; te=[item_index for item_index in range(len(items)) if item_index%folds==fold_index]
        by=defaultdict(list)
        for item_index in tr:
            _r,sem,ci=items[item_index]; by[sem[ci][1]].append(outcome_embeddings[item_index])
        cen={condition:_unit(np.mean(vectors,0)) for condition,vectors in by.items()}; cnt={condition:len(vectors) for condition,vectors in by.items()}
        for item_index in te:
            rec,sem,ci=items[item_index]; ec=[condition for _,condition in sem]
            eff=[_unit(cvec[condition]) if cnt.get(condition,0)==0 else _unit((PRIOR*cvec[condition]+cnt[condition]*cen[condition])/(PRIOR+cnt[condition])) for condition in ec]
            pred_index=int(np.argmax(cos1(outcome_embeddings[item_index],np.asarray(eff))))
            for stratum_key in (rec.get("stratum","?"),"ALL"): tally[stratum_key]["n"]+=1; tally[stratum_key]["c"]+=int(pred_index==ci)
    return {stratum_key:round(counts["c"]/counts["n"],4) for stratum_key,counts in tally.items()}

# --- embed under available models ---
Ob,Cb=embed_all("BAAI/bge-base-en-v1.5")
Os,Cs=embed_all("BAAI/bge-small-en-v1.5")
scout={"bge-base_768(baseline)":centroid_cv(Ob,Cb), "bge-small_384(candidate)":centroid_cv(Os,Cs)}
extra=None
try:
    Og,Cg=embed_all("google/embeddinggemma-300m"); scout["embeddinggemma"]=centroid_cv(Og,Cg); extra="embeddinggemma scored"
except Exception as exc:
    extra=f"embeddinggemma unavailable offline ({str(exc)[:60]}) -> queued as first real customer"

# --- succession: map OLD->NEW, migrate centroids built in OLD, test on NEW held-out ---
def ridge_map(matrix_a,matrix_b,lam=1e-2):   # A(n,d1)->B(n,d2): M=(A'A+lamI)^-1 A'B
    dimension=matrix_a.shape[1]; return np.linalg.solve(matrix_a.T@matrix_a+lam*np.eye(dimension), matrix_a.T@matrix_b)
def succession_cv(Oo,Co,On,Cn):
    ret=[]; anchor_o=np.vstack([Oo,np.asarray([Co[condition] for condition in conds])]); anchor_n=np.vstack([On,np.asarray([Cn[condition] for condition in conds])])
    for fold_index in range(folds):
        tr=[item_index for item_index in range(len(items)) if item_index%folds!=fold_index]; te=[item_index for item_index in range(len(items)) if item_index%folds==fold_index]
        matrix_a_train=np.vstack([Oo[tr],np.asarray([Co[condition] for condition in conds])]); Bn=np.vstack([On[tr],np.asarray([Cn[condition] for condition in conds])])
        map_matrix=ridge_map(matrix_a_train,Bn)
        by=defaultdict(list)
        for item_index in tr:
            _r,sem,ci=items[item_index]; by[sem[ci][1]].append(Oo[item_index])   # OLD-space centroids (the stranded artifact)
        cen_old={condition:np.mean(vectors,0) for condition,vectors in by.items()}
        cen_map={condition:_unit(cen_old[condition]@map_matrix) for condition in cen_old}          # migrate to NEW space via M
        cen_nat={condition:_unit(np.mean([On[item_index] for item_index in tr if items[item_index][1][items[item_index][2]][1]==condition],0)) if any(items[item_index][1][items[item_index][2]][1]==condition for item_index in tr) else _unit(Cn[condition]) for condition in by}
        mok=nok=sample_count=0
        for item_index in te:
            rec,sem,ci=items[item_index]; ec=[condition for _,condition in sem]
            mp=int(np.argmax(cos1(On[item_index],np.asarray([cen_map.get(condition,_unit(Cn[condition])) for condition in ec]))))
            npk=int(np.argmax(cos1(On[item_index],np.asarray([cen_nat.get(condition,_unit(Cn[condition])) for condition in ec]))))
            sample_count+=1; mok+=int(mp==ci); nok+=int(npk==ci)
        ret.append((mok/sample_count, nok/sample_count))
    mean_mapped_acc=np.mean([res_pair[0] for res_pair in ret]); nat=np.mean([res_pair[1] for res_pair in ret])
    return dict(mapped_acc=round(float(mean_mapped_acc),4), native_acc=round(float(nat),4),
                retention=round(float(mean_mapped_acc/nat),4) if nat>0 else None, passes_98=bool(nat>0 and mean_mapped_acc/nat>=0.98))
# unit test: random rotation of bge-base (spaces ARE rotation-related -> should retain ~100%)
rng=np.random.RandomState(0); rot_matrix,_=np.linalg.qr(rng.randn(Ob.shape[1],Ob.shape[1]))
Orot=Ob@rot_matrix; Crot={condition:Cb[condition]@rot_matrix for condition in conds}
unit=succession_cv(Ob,Cb,Orot,Crot)
real=succession_cv(Ob,Cb,Os,Cs)
out=dict(scouting=scout, scouting_note=extra,
         succession_unit_test_rotation=unit, succession_real_bgebase_to_bgesmall=real,
         verdict_real=("PASS ≥98%" if real["passes_98"] else "BELOW 98% -> vector-only artifacts don't survive this succession; retain text"))
json.dump(out, open(os.path.join(_REPO, "research", "benchmark/embedder_succession.json"),"w"), indent=2)
print(json.dumps(out, indent=2))
