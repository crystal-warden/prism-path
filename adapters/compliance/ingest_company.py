#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Blind ingestion + disposition observation (#72).

agy blindly authored a company documentation package (no control list, no labels). This is the REAL
ingestion problem: free-form company docs -> per-control evidence. We map them with lexical TF-IDF
retrieval (un-hand-tuned), run the gemma adjudicator across a breadth sample of controls (one per
family), and OBSERVE the disposition distribution. There is no accuracy score — there are no ground-truth
labels — the signal is a VARIED spread (proving the nodes are not padded by me authoring the evidence)
plus spot-checkable per-control dispositions and honest empty-retrieval (discovery) cases.
"""
import os, sys, re, math, json, collections
HERE = os.path.dirname(os.path.abspath(__file__))
from adapters.compliance import compliance_adapter as ca

# ============================================================================
# CONFIGURE -- point COMPANY at your own free-form company-docs directory, then run.
# ============================================================================
COMPANY = os.path.join(HERE, "efficacy", "company")  # your company documentation directory (SAMPLE default)
STANDARD = "nist_800171_r2"                           # the control catalog to map against
TOPK = 3                                              # top-K control matches per doc (tuning)
MAX_EXCERPT = 1600                                    # excerpt length (tuning)
# ============================================================================

ca.use_standard(STANDARD)
STOP = set("the a an and or of to in for on with is are be as by at from this that your you we our it "
           "will shall must should may can not no all any each per via which who whom whose into within "
           "system information data policy procedure control controls access".split())


def tokenize(text):
    return [word for word in re.findall(r"[a-z0-9]+", text.lower()) if len(word) > 2 and word not in STOP]


def load_docs():
    docs = []
    if not os.path.isdir(COMPANY):
        return docs
    for filename in sorted(os.listdir(COMPANY)):
        path = os.path.join(COMPANY, filename)
        if os.path.isfile(path) and not filename.startswith("_"):
            try:
                txt = open(path, errors="ignore").read()
            except Exception:
                continue
            if txt.strip():
                docs.append({"name": filename, "text": txt, "tf": collections.Counter(tokenize(txt))})
    return docs


def breadth_controls():
    """One representative control per family (lowest id), for cross-family spread."""
    cat = ca._catalog()["controls"]
    by_fam = {}
    for cid, control in cat.items():
        by_fam.setdefault(control["family"], []).append(cid)
    def keyfn(cid):
        return [int(part) for part in cid.split(".")]
    return [sorted(family_controls, key=keyfn)[0] for _, family_controls in sorted(by_fam.items())]


def _cos(left_vector, right_vector):
    dot = sum(left_vector.get(term, 0) * right_vector.get(term, 0) for term in left_vector)
    na = math.sqrt(sum(weight * weight for weight in left_vector.values()))
    nb = math.sqrt(sum(weight * weight for weight in right_vector.values()))
    return dot / (na * nb) if na and nb else 0.0


def retrieve(control, docs, idf):
    # query = objective text + title + family + evidence types; cosine (length-normalized) + filename boost
    qtok = tokenize(control["title"] + " " + control.get("family_name", "") + " " +
                    " ".join(objective["text"] for objective in control["objectives"]) + " " +
                    " ".join(control.get("evidence_types", [])))
    qvec = {term: count * idf.get(term, 0) for term, count in collections.Counter(qtok).items()}
    # tokens that most identify this control's topic — used to reward on-topic FILENAMES
    topic = set(tokenize(control["title"] + " " + control.get("family_name", "") + " " +
                         " ".join(control.get("evidence_types", []))))
    scored = []
    for document in docs:
        dvec = {term: count * idf.get(term, 0) for term, count in document["tf"].items()}
        fname_tok = set(tokenize(document["name"]))
        boost = 0.15 * len(fname_tok & topic)                  # a doc named for the control's topic wins
        score = _cos(dvec, qvec) + boost
        if score > 0:
            scored.append((score, document))
    scored.sort(key=lambda scored_document: -scored_document[0])
    return [document for _, document in scored[:TOPK]]


def main(dry=False, map_path=None):
    docs = load_docs()
    if not docs:
        print(json.dumps({"error": "no company docs in " + COMPANY})); return
    by_name = {document["name"]: document for document in docs}
    smap = json.load(open(map_path)) if map_path else None     # precomputed semantic map {control: [docs]}
    df = collections.Counter()
    for document in docs:
        for term in document["tf"]:
            df[term] += 1
    idf = {term: math.log(1 + len(docs) / (1 + document_frequency)) for term, document_frequency in df.items()}
    controls = breadth_controls()

    rows, dist = [], collections.Counter()
    empty = 0
    for cid in controls:
        control = ca.get_control(cid)
        hits = [by_name[doc_name] for doc_name in smap.get(cid, []) if doc_name in by_name] if smap is not None \
            else retrieve(control, docs, idf)
        if not hits:
            empty += 1
            rows.append({"control": cid, "family": control["family"], "top_docs": [], "disposition": "no-evidence-retrieved"})
            dist["not-met(empty)"] += 1
            continue
        if dry:
            rows.append({"control": cid, "family": control["family"], "top_docs": [hit["name"] for hit in hits]})
            continue
        req = {"control_id": cid, "boundary": "Meridian Aerospace CUI environment",
               "evidence": [{"type": "document", "source": hit["name"], "text": hit["text"][:MAX_EXCERPT]} for hit in hits]}
        det = ca.adjudicate(control, req)
        status = det["status"] if det else "ERROR"
        dist[status] += 1
        rows.append({"control": cid, "family": control["family"], "profile": ca._method_profile(control),
                     "top_docs": [hit["name"] for hit in hits], "disposition": status,
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
