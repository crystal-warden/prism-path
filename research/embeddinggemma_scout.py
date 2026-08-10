#!/usr/bin/env python3
"""Task #52 — fetch + scout EmbeddingGemma; cross-family succession + native-Matryoshka density.
Robust to prompt/dim API differences. NEVER touches model-gemma (bge/egemma are small)."""
import os, sys, json, numpy as np
os.environ.pop("HF_HUB_OFFLINE", None)
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentence_transformers import SentenceTransformer
from prismpath.centroid import _decision_items, load_graphs, _unit

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
recs=[json.loads(l) for l in open(os.path.join(_REPO, "prismpath", "benchmark/routing_bench.jsonl"))]
graphs=load_graphs(recs,flows_dir=os.path.join(_REPO, "prismpath", "flows")); items=_decision_items(recs,graphs)
outs=[it[0]["outcome"] for it in items]; conds=sorted({c for _,sem,_ in items for _,c in sem})
folds=5; PRIOR=4.0
def cos1(a,B):
    an=a/np.clip(np.linalg.norm(a),1e-8,None); Bn=B/np.clip(np.linalg.norm(B,axis=1,keepdims=True),1e-8,None); return Bn@an
def centroid_cv(O,cvec):
    t=defaultdict(lambda:{"n":0,"c":0})
    for f in range(folds):
        tr=[i for i in range(len(items)) if i%folds!=f]; te=[i for i in range(len(items)) if i%folds==f]
        by=defaultdict(list)
        for i in tr: _r,sem,ci=items[i]; by[sem[ci][1]].append(O[i])
        cen={c:_unit(np.mean(v,0)) for c,v in by.items()}; cnt={c:len(v) for c,v in by.items()}
        for i in te:
            rec,sem,ci=items[i]; ec=[c for _,c in sem]
            eff=[_unit(cvec[c]) if cnt.get(c,0)==0 else _unit((PRIOR*cvec[c]+cnt[c]*cen[c])/(PRIOR+cnt[c])) for c in ec]
            p=int(np.argmax(cos1(O[i],np.asarray(eff))))
            for k in (rec.get("stratum","?"),"ALL"): t[k]["n"]+=1; t[k]["c"]+=int(p==ci)
    return {k:round(v["c"]/v["n"],4) for k,v in t.items()}
def enc(model, texts, kind, dim=None):
    for kw in ([{"prompt_name":kind}] if kind else [])+[{}]:
        try:
            V=model.encode(texts, normalize_embeddings=True, batch_size=64, show_progress_bar=False, **kw)
            V=np.asarray(V,np.float64)
            if dim and V.shape[1]>dim:  # Matryoshka truncate + renorm
                V=V[:,:dim]; V=V/np.clip(np.linalg.norm(V,axis=1,keepdims=True),1e-8,None)
            return V, (list(kw.keys())[0] if kw else "no-prompt")
        except Exception: continue
    raise RuntimeError("encode failed")

out={"model":"google/embeddinggemma-300m"}
try:
    # bge-base baseline (cached)
    b=SentenceTransformer("BAAI/bge-base-en-v1.5",device="cuda")
    Ob=np.asarray(b.encode(outs,normalize_embeddings=True,show_progress_bar=False),np.float64)
    Cb={c:v for c,v in zip(conds,b.encode(conds,normalize_embeddings=True,show_progress_bar=False))}
    del b
    # EmbeddingGemma (fetch on first load)
    g=SentenceTransformer("google/embeddinggemma-300m",device="cuda")
    Og,pmode=enc(g,outs,"query"); Cg_arr,_=enc(g,conds,"document"); Cg={c:v for c,v in zip(conds,Cg_arr)}
    out["dim_full"]=int(Og.shape[1]); out["prompt_mode"]=pmode
    out["scouting"]={"bge-base_768":centroid_cv(Ob,Cb),"embeddinggemma_full":centroid_cv(Og,{c:np.asarray(Cg[c],np.float64) for c in conds})}
    # cross-family succession: bge-base -> egemma (ridge linear map), retention vs >=98%
    def ridge(A,B,lam=1e-2): d=A.shape[1]; return np.linalg.solve(A.T@A+lam*np.eye(d),A.T@B)
    A=np.vstack([Ob,np.asarray([Cb[c] for c in conds])]); Bn=np.vstack([Og,np.asarray([Cg[c] for c in conds])])
    M=ridge(A,Bn); ret=[]
    for f in range(folds):
        tr=[i for i in range(len(items)) if i%folds!=f]; te=[i for i in range(len(items)) if i%folds==f]
        by=defaultdict(list)
        for i in tr: _r,sem,ci=items[i]; by[sem[ci][1]].append(Ob[i])
        cen_map={c:_unit(np.mean(by[c],0)@M) for c in by}
        bynew=defaultdict(list)
        for i in tr: _r,sem,ci=items[i]; bynew[sem[ci][1]].append(Og[i])
        cen_nat={c:_unit(np.mean(v,0)) for c,v in bynew.items()}
        mok=nok=n=0
        for i in te:
            rec,sem,ci=items[i]; ec=[c for _,c in sem]
            mp=int(np.argmax(cos1(Og[i],np.asarray([cen_map[c] if c in cen_map else _unit(np.asarray(Cg[c])) for c in ec]))))
            npk=int(np.argmax(cos1(Og[i],np.asarray([cen_nat.get(c,_unit(np.asarray(Cg[c]))) for c in ec]))))
            n+=1; mok+=int(mp==ci); nok+=int(npk==ci)
        ret.append((mok/n,nok/n))
    mm=float(np.mean([r[0] for r in ret])); nn=float(np.mean([r[1] for r in ret]))
    out["cross_family_succession"]={"mapped_acc":round(mm,4),"native_acc":round(nn,4),"retention":round(mm/nn,4) if nn else None,"passes_98":bool(nn and mm/nn>=0.98)}
    # native-128 Matryoshka density: don't-know AUC (last shot at #41)
    Og128,_=enc(g,outs,"query",dim=128)
    dkc=[]; dkw=[]
    for f in range(folds):
        tr=[i for i in range(len(items)) if i%folds!=f]; te=[i for i in range(len(items)) if i%folds==f]
        by=defaultdict(list)
        for i in tr: _r,sem,ci=items[i]; by[sem[ci][1]].append(Og128[i])
        gp={}
        for c,v in by.items():
            V=np.asarray(v); m=V.mean(0); S=np.cov(V.T) if len(V)>1 else np.zeros((128,128))
            Ssh=0.7*S+0.3*(np.trace(S)/128 if np.trace(S)>0 else 1.0)*np.eye(128)+1e-4*np.eye(128)
            gp[c]=(m,np.linalg.inv(Ssh))
        for i in te:
            rec,sem,ci=items[i]; ec=[c for _,c in sem]
            lls=[-0.5*float((Og128[i]-gp[c][0])@gp[c][1]@(Og128[i]-gp[c][0])) if c in gp else -1e9 for c in ec]
            pred=int(np.argmax(lls)); (dkc if pred==ci else dkw).append(max(lls))
    c=np.array(dkc); w=np.array(dkw)
    allv=np.concatenate([c,w]); order=allv.argsort(); ranks=np.empty_like(order,float); ranks[order]=np.arange(1,len(allv)+1)
    auc=float((ranks[:len(c)].sum()-len(c)*(len(c)+1)/2)/(len(c)*len(w))) if len(c) and len(w) else None
    out["native128_dontknow_auc"]=round(auc,4) if auc else None
    out["native128_verdict"]="density rescued (AUC>=0.75)" if auc and auc>=0.75 else "still parked (AUC<0.75)"
    del g
except Exception as e:
    import traceback; out["error"]=str(e)[:200]; out["trace"]=traceback.format_exc()[-400:]
json.dump(out, open(os.path.join(_REPO, "prismpath", "benchmark/embeddinggemma_scout.json"),"w"), indent=2)
print(json.dumps(out, indent=2))
