#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Task #52 — fetch + scout EmbeddingGemma; cross-family succession + native-Matryoshka density.
Robust to prompt/dim API differences. NEVER touches model-gemma (bge/egemma are small)."""
import os, sys, json, numpy as np
os.environ.pop("HF_HUB_OFFLINE", None)
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentence_transformers import SentenceTransformer
from prismpath.routing.centroid import _decision_items, load_graphs, _unit

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
recs=[json.loads(line) for line in open(os.path.join(_REPO, "prismpath", "benchmark/routing_bench.jsonl"))]
graphs=load_graphs(recs,flows_dir=os.path.join(_REPO, "prismpath", "flows")); items=_decision_items(recs,graphs)
outs=[it[0]["outcome"] for it in items]; conds=sorted({condition for _,sem,_ in items for _,condition in sem})
folds=5; PRIOR=4.0
def cos1(vector_a,matrix_b):
    an=vector_a/np.clip(np.linalg.norm(vector_a),1e-8,None); Bn=matrix_b/np.clip(np.linalg.norm(matrix_b,axis=1,keepdims=True),1e-8,None); return Bn@an
def centroid_cv(outcome_embeddings,cvec):
    tally=defaultdict(lambda:{"n":0,"c":0})
    for fold_index in range(folds):
        tr=[item_index for item_index in range(len(items)) if item_index%folds!=fold_index]; te=[item_index for item_index in range(len(items)) if item_index%folds==fold_index]
        by=defaultdict(list)
        for item_index in tr: _r,sem,ci=items[item_index]; by[sem[ci][1]].append(outcome_embeddings[item_index])
        cen={condition:_unit(np.mean(vectors,0)) for condition,vectors in by.items()}; cnt={condition:len(vectors) for condition,vectors in by.items()}
        for item_index in te:
            rec,sem,ci=items[item_index]; ec=[condition for _,condition in sem]
            eff=[_unit(cvec[condition]) if cnt.get(condition,0)==0 else _unit((PRIOR*cvec[condition]+cnt[condition]*cen[condition])/(PRIOR+cnt[condition])) for condition in ec]
            pred_index=int(np.argmax(cos1(outcome_embeddings[item_index],np.asarray(eff))))
            for stratum_key in (rec.get("stratum","?"),"ALL"): tally[stratum_key]["n"]+=1; tally[stratum_key]["c"]+=int(pred_index==ci)
    return {stratum_key:round(counts["c"]/counts["n"],4) for stratum_key,counts in tally.items()}
def enc(model, texts, kind, dim=None):
    for kw in ([{"prompt_name":kind}] if kind else [])+[{}]:
        try:
            embeddings=model.encode(texts, normalize_embeddings=True, batch_size=64, show_progress_bar=False, **kw)
            embeddings=np.asarray(embeddings,np.float64)
            if dim and embeddings.shape[1]>dim:  # Matryoshka truncate + renorm
                embeddings=embeddings[:,:dim]; embeddings=embeddings/np.clip(np.linalg.norm(embeddings,axis=1,keepdims=True),1e-8,None)
            return embeddings, (list(kw.keys())[0] if kw else "no-prompt")
        except Exception: continue
    raise RuntimeError("encode failed")

out={"model":"google/embeddinggemma-300m"}
try:
    # bge-base baseline (cached)
    bge_model=SentenceTransformer("BAAI/bge-base-en-v1.5",device="cuda")
    Ob=np.asarray(bge_model.encode(outs,normalize_embeddings=True,show_progress_bar=False),np.float64)
    Cb={condition:vector for condition,vector in zip(conds,bge_model.encode(conds,normalize_embeddings=True,show_progress_bar=False))}
    del bge_model
    # EmbeddingGemma (fetch on first load)
    gemma_model=SentenceTransformer("google/embeddinggemma-300m",device="cuda")
    Og,pmode=enc(gemma_model,outs,"query"); Cg_arr,_=enc(gemma_model,conds,"document"); Cg={condition:vector for condition,vector in zip(conds,Cg_arr)}
    out["dim_full"]=int(Og.shape[1]); out["prompt_mode"]=pmode
    out["scouting"]={"bge-base_768":centroid_cv(Ob,Cb),"embeddinggemma_full":centroid_cv(Og,{condition:np.asarray(Cg[condition],np.float64) for condition in conds})}
    # cross-family succession: bge-base -> egemma (ridge linear map), retention vs >=98%
    def ridge(matrix_a,matrix_b,lam=1e-2): dimension=matrix_a.shape[1]; return np.linalg.solve(matrix_a.T@matrix_a+lam*np.eye(dimension),matrix_a.T@matrix_b)
    source_matrix=np.vstack([Ob,np.asarray([Cb[condition] for condition in conds])]); Bn=np.vstack([Og,np.asarray([Cg[condition] for condition in conds])])
    map_matrix=ridge(source_matrix,Bn); ret=[]
    for fold_index in range(folds):
        tr=[item_index for item_index in range(len(items)) if item_index%folds!=fold_index]; te=[item_index for item_index in range(len(items)) if item_index%folds==fold_index]
        by=defaultdict(list)
        for item_index in tr: _r,sem,ci=items[item_index]; by[sem[ci][1]].append(Ob[item_index])
        cen_map={condition:_unit(np.mean(by[condition],0)@map_matrix) for condition in by}
        bynew=defaultdict(list)
        for item_index in tr: _r,sem,ci=items[item_index]; bynew[sem[ci][1]].append(Og[item_index])
        cen_nat={condition:_unit(np.mean(vectors,0)) for condition,vectors in bynew.items()}
        mok=nok=sample_count=0
        for item_index in te:
            rec,sem,ci=items[item_index]; ec=[condition for _,condition in sem]
            mp=int(np.argmax(cos1(Og[item_index],np.asarray([cen_map[condition] if condition in cen_map else _unit(np.asarray(Cg[condition])) for condition in ec]))))
            npk=int(np.argmax(cos1(Og[item_index],np.asarray([cen_nat.get(condition,_unit(np.asarray(Cg[condition]))) for condition in ec]))))
            sample_count+=1; mok+=int(mp==ci); nok+=int(npk==ci)
        ret.append((mok/sample_count,nok/sample_count))
    mm=float(np.mean([res_pair[0] for res_pair in ret])); nn=float(np.mean([res_pair[1] for res_pair in ret]))
    out["cross_family_succession"]={"mapped_acc":round(mm,4),"native_acc":round(nn,4),"retention":round(mm/nn,4) if nn else None,"passes_98":bool(nn and mm/nn>=0.98)}
    # native-128 Matryoshka density: don't-know AUC (last shot at #41)
    Og128,_=enc(gemma_model,outs,"query",dim=128)
    dkc=[]; dkw=[]
    for fold_index in range(folds):
        tr=[item_index for item_index in range(len(items)) if item_index%folds!=fold_index]; te=[item_index for item_index in range(len(items)) if item_index%folds==fold_index]
        by=defaultdict(list)
        for item_index in tr: _r,sem,ci=items[item_index]; by[sem[ci][1]].append(Og128[item_index])
        gp={}
        for condition,vectors in by.items():
            vector_array=np.asarray(vectors); mean_vector=vector_array.mean(0); cov_matrix=np.cov(vector_array.T) if len(vector_array)>1 else np.zeros((128,128))
            Ssh=0.7*cov_matrix+0.3*(np.trace(cov_matrix)/128 if np.trace(cov_matrix)>0 else 1.0)*np.eye(128)+1e-4*np.eye(128)
            gp[condition]=(mean_vector,np.linalg.inv(Ssh))
        for item_index in te:
            rec,sem,ci=items[item_index]; ec=[condition for _,condition in sem]
            lls=[-0.5*float((Og128[item_index]-gp[condition][0])@gp[condition][1]@(Og128[item_index]-gp[condition][0])) if condition in gp else -1e9 for condition in ec]
            pred=int(np.argmax(lls)); (dkc if pred==ci else dkw).append(max(lls))
    condition=np.array(dkc); wrong_scores=np.array(dkw)
    allv=np.concatenate([condition,wrong_scores]); order=allv.argsort(); ranks=np.empty_like(order,float); ranks[order]=np.arange(1,len(allv)+1)
    auc=float((ranks[:len(condition)].sum()-len(condition)*(len(condition)+1)/2)/(len(condition)*len(wrong_scores))) if len(condition) and len(wrong_scores) else None
    out["native128_dontknow_auc"]=round(auc,4) if auc else None
    out["native128_verdict"]="density rescued (AUC>=0.75)" if auc and auc>=0.75 else "still parked (AUC<0.75)"
    del gemma_model
except Exception as exc:
    import traceback; out["error"]=str(exc)[:200]; out["trace"]=traceback.format_exc()[-400:]
json.dump(out, open(os.path.join(_REPO, "research", "benchmark/embeddinggemma_scout.json"),"w"), indent=2)
print(json.dumps(out, indent=2))
