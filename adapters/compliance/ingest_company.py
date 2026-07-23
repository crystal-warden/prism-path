#!/usr/bin/env python3
"""Blind ingestion + disposition observation (#72).

agy blindly authored a company documentation package (no control list, no labels). This is the REAL
ingestion problem: free-form company docs -> per-control evidence. We map them with lexical TF-IDF
retrieval (un-hand-tuned), run the gemma adjudicator across a breadth sample of controls (one per
family), and OBSERVE the disposition distribution. There is no accuracy score — there are no ground-truth
labels — the signal is a VARIED spread (proving the nodes are not padded by me authoring the evidence)
plus spot-checkable per-control dispositions and honest empty-retrieval (discovery) cases.
"""
import os, sys, re, math, json, collections
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import compliance_adapter as ca

ca.use_standard("nist_800171_r2")
COMPANY = os.path.join(HERE, "efficacy", "company")
TOPK = 3
MAX_EXCERPT = 1600
STOP = set("the a an and or of to in for on with is are be as by at from this that your you we our it "
           "will shall must should may can not no all any each per via which who whom whose into within "
           "system information data policy procedure control controls access".split())


def tokenize(t):
    return [w for w in re.findall(r"[a-z0-9]+", t.lower()) if len(w) > 2 and w not in STOP]


def load_docs():
    docs = []
    if not os.path.isdir(COMPANY):
        return docs
    for f in sorted(os.listdir(COMPANY)):
        p = os.path.join(COMPANY, f)
        if os.path.isfile(p) and not f.startswith("_"):
            try:
                txt = open(p, errors="ignore").read()
            except Exception:
                continue
            if txt.strip():
                docs.append({"name": f, "text": txt, "tf": collections.Counter(tokenize(txt))})
    return docs


def breadth_controls():
    """One representative control per family (lowest id), for cross-family spread."""
    cat = ca._catalog()["controls"]
    by_fam = {}
    for cid, c in cat.items():
        by_fam.setdefault(c["family"], []).append(cid)
    def keyfn(cid):
        return [int(x) for x in cid.split(".")]
    return [sorted(v, key=keyfn)[0] for _, v in sorted(by_fam.items())]


def _cos(a, b):
    dot = sum(a.get(t, 0) * b.get(t, 0) for t in a)
    na = math.sqrt(sum(v * v for v in a.values())); nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def retrieve(control, docs, idf):
    # query = objective text + title + family + evidence types; cosine (length-normalized) + filename boost
    qtok = tokenize(control["title"] + " " + control.get("family_name", "") + " " +
                    " ".join(o["text"] for o in control["objectives"]) + " " +
                    " ".join(control.get("evidence_types", [])))
    qvec = {t: c * idf.get(t, 0) for t, c in collections.Counter(qtok).items()}
    # tokens that most identify this control's topic — used to reward on-topic FILENAMES
    topic = set(tokenize(control["title"] + " " + control.get("family_name", "") + " " +
                         " ".join(control.get("evidence_types", []))))
    scored = []
    for d in docs:
        dvec = {t: c * idf.get(t, 0) for t, c in d["tf"].items()}
        fname_tok = set(tokenize(d["name"]))
        boost = 0.15 * len(fname_tok & topic)                  # a doc named for the control's topic wins
        s = _cos(dvec, qvec) + boost
        if s > 0:
            scored.append((s, d))
    scored.sort(key=lambda x: -x[0])
    return [d for _, d in scored[:TOPK]]


def main(dry=False, map_path=None):
    docs = load_docs()
    if not docs:
        print(json.dumps({"error": "no company docs in " + COMPANY})); return
    by_name = {d["name"]: d for d in docs}
    smap = json.load(open(map_path)) if map_path else None     # precomputed semantic map {control: [docs]}
    df = collections.Counter()
    for d in docs:
        for t in d["tf"]:
            df[t] += 1
    idf = {t: math.log(1 + len(docs) / (1 + c)) for t, c in df.items()}
    controls = breadth_controls()

    rows, dist = [], collections.Counter()
    empty = 0
    for cid in controls:
        c = ca.get_control(cid)
        hits = [by_name[n] for n in smap.get(cid, []) if n in by_name] if smap is not None \
            else retrieve(c, docs, idf)
        if not hits:
            empty += 1
            rows.append({"control": cid, "family": c["family"], "top_docs": [], "disposition": "no-evidence-retrieved"})
            dist["not-met(empty)"] += 1
            continue
        if dry:
            rows.append({"control": cid, "family": c["family"], "top_docs": [h["name"] for h in hits]})
            continue
        req = {"control_id": cid, "boundary": "Meridian Aerospace CUI environment",
               "evidence": [{"type": "document", "source": h["name"], "text": h["text"][:MAX_EXCERPT]} for h in hits]}
        det = ca.adjudicate(c, req)
        status = det["status"] if det else "ERROR"
        dist[status] += 1
        rows.append({"control": cid, "family": c["family"], "profile": ca._method_profile(c),
                     "top_docs": [h["name"] for h in hits], "disposition": status,
                     "gap_summary": (det or {}).get("gap_summary", "")})

    report = {"n_docs": len(docs), "n_controls": len(controls), "empty_retrieval": empty,
              "disposition_distribution": dict(dist),
              "note": ("Blind test: docs authored by agy with no control list / no labels; dispositions are "
                       "OBSERVED (no accuracy score). A varied spread indicates the nodes are not padded."),
              "rows": rows}
    report["retrieval"] = "semantic(EmbeddingGemma)" if map_path else "lexical(tfidf)"
    if not dry:
        fn = "company_report_semantic.json" if map_path else "company_report.json"
        json.dump(report, open(os.path.join(HERE, "efficacy", fn), "w"), indent=1)
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    mp = None
    if "--map" in sys.argv:
        mp = sys.argv[sys.argv.index("--map") + 1]
    main(dry="--dry" in sys.argv, map_path=mp)
