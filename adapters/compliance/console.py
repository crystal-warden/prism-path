#!/usr/bin/env python3
"""Console — the buyer-facing pane that runs the whole platform end to end and surfaces every capability.

It assesses every control of the active standard through the unified adjudicator (config from the
scanned posture, operational from task-completion records, the LLM for prose objectives when enabled),
then assembles the decision view the market actually wants: per control, the verdict, why, WHO DECIDES
when it is not clean, and WHAT BREAKS (the FAIR loss scenarios the control mitigates and their dollar
exposure). It rolls up the SPRS score, the FAIR risk register, the operational task queue, the available
SOP documents, and the signed receipts.

Nothing here is a mock. Every field is produced by a real call into the engine: deterministic_checks and
control_tasks and the LLM via unified.full_determination, control_tasks for the task queue, sop_generator
for the documents, rollup for SPRS, fair_risk for the risk register, ai_safety_receipts for the receipts,
and oscal_catalog for the interop export.
"""
import os
import compliance_adapter as _ca
import posture_connector as _pc
import unified as _un
import control_tasks as _ct
import sop_generator as _sg
import fair_risk as _fr
import ai_safety_receipts as _sig
import oscal_catalog as _ox
import rollup as _rollup

# assessment-method profile -> the role that owns the decision when a control is not clean
_OWNER = {"technical": "System / Security Administrator", "procedural": "ISSM / Policy Owner",
          "operational": "Operations / Process Owner", "general": "ISSM"}


def _who_decides(control, status):
    owner = _OWNER.get(_ca._method_profile(control), "ISSM")
    if status == "insufficient":
        return owner + "; escalate to the Assessor for review"
    if status in ("not-met", "partially-met"):
        return owner + " (remediation owner)"
    return owner


def _scenario_index(scenarios):
    idx = {}
    for s in scenarios:
        for cid in s.get("controls", []):
            idx.setdefault(cid, []).append(s)
    return idx


def _sop_by_family():
    out = {}
    for d in _sg.list_documents():
        try:
            out[_sg.load_spec(d).get("family")] = d
        except Exception:
            continue
    return out


def build(posture, completions=None, as_of=None, key=None, signed_at=None, use_llm=False):
    """Run the full pipeline and return the console model. Every section is populated by a real call."""
    facts = (posture or {}).get("facts") or {}
    boundary = (posture or {}).get("boundary", "(unspecified)")
    req_base = {"facts": facts, "boundary": boundary}
    catalog = _ca._catalog()
    scenarios = _fr.load_scenarios()
    scen_idx = _scenario_index(scenarios)
    sop_fam = _sop_by_family()

    # pass 1: adjudicate every control -> verdicts (needed whole before risk and what-breaks)
    dets = {}
    verdicts = {}
    for cid in sorted(catalog["controls"]):
        control = _ca.get_control(cid)
        det = _un.full_determination(control, dict(req_base, control_id=cid),
                                     completions=completions, as_of=as_of, use_llm=use_llm)
        dets[cid] = (control, det)
        verdicts[cid] = det["status"]

    risk = _fr.risk_register(verdicts, scenarios)
    scen_ale = {s["id"]: _fr.ale(s, verdicts) for s in scenarios}
    scen_name = {s["id"]: s["name"] for s in scenarios}

    # pass 2: assemble the per-control decision view + receipts + tallies
    controls_view, receipts = [], []
    tally = {"met": 0, "partially-met": 0, "not-met": 0, "insufficient": 0}
    by_mech = {"config": 0, "operational": 0, "llm": 0, "undetermined": 0}
    for cid in sorted(catalog["controls"]):
        control, det = dets[cid]
        status = det["status"]
        tally[status] = tally.get(status, 0) + 1
        for m, objs in det["coverage"].items():
            if m in by_mech:
                by_mech[m] += len(objs)
        if status == "met":
            cause = "all %d objectives satisfied" % det["objectives_total"]
        elif det["undetermined_objective_ids"]:
            cause = "insufficient evidence for " + ", ".join(det["undetermined_objective_ids"][:4])
        else:
            cause = "unmet objectives " + ", ".join(det["unmet_objective_ids"][:4])
        what_breaks = [{"scenario": scen_name[s["id"]], "exposed": status != "met",
                        "ale_likely": (scen_ale[s["id"]]["likely"] if status != "met" else 0)}
                       for s in scen_idx.get(cid, [])]
        signed = False
        if key is not None and signed_at is not None:
            rec = _sig.sign_receipt(det, key, signed_at)
            receipts.append({"control_id": cid, "root": rec["determination_root"][:16],
                             "sig": rec["signature"][:24] + "..."})
            signed = True
        controls_view.append({
            "control_id": cid, "title": control["title"], "verdict": status,
            "coverage": det["coverage"], "cause": cause,
            "who_decides": _who_decides(control, status), "what_breaks": what_breaks,
            "sop": sop_fam.get(control.get("family_name")),
            "tasks": [t["id"] for t in _ct.tasks_for(cid)], "signed": signed,
        })

    records = [{"control_id": cid, "status": v} for cid, v in verdicts.items()]
    weights = _ca.catalog_weights()
    sprs = _rollup.sprs_partial(records, weights) if weights else {"applicable": False}

    return {
        "standard": _ca.active_standard(),
        "standards_available": sorted(_ca.list_standards()),
        "boundary": boundary,
        "provenance": (posture or {}).get("provenance", {}),
        "summary": {"n_controls": len(controls_view), "tally": tally, "by_mechanism": by_mech},
        "sprs": {"ceiling_if_unassessed_all_met": sprs.get("ceiling_if_unassessed_all_met"),
                 "deducted_points": sprs.get("deducted_points"), "n_assessed": sprs.get("n_assessed"),
                 "caveat": sprs.get("caveat")},
        "risk": {"aggregate_ale": risk["aggregate_ale"],
                 "top": sorted(risk["scenarios"], key=lambda r: -r["ale"]["likely"])[:5]},
        "controls": controls_view,
        "tasks_due": _ct.due_tasks(completions or [], as_of) if as_of else [],
        "sops": [{"doc_id": d, "family": _sg.load_spec(d).get("family")} for d in _sg.list_documents()],
        "receipts": {"n_signed": len(receipts), "sample": receipts[:3]},
        "oscal_export": {"available": True, "controls": len(_ox.export_oscal(catalog)["catalog"]["groups"])},
    }


def demo(use_llm=False):
    """Assemble a realistic end-to-end input (a scanned posture, a few retest/task completions, a signing
    key) and build the console. Runs the entire platform with real calls, no mocks."""
    from prismpath import policy_pack as _pp
    import tempfile
    _ca.use_standard("nist_800171_r2")
    posture = _pc.load_sample("example_host")
    posture.setdefault("provenance", {})["scanners"] = ["osquery", "lynis", "prowler"]
    completions = [
        _ct.record_completion("ir-capability-test", "3.6.3", "2026-08-15", "ISSM", "aar-2026.pdf"),
        _ct.record_completion("vulnerability-scan", "3.11.2", "2026-08-28", "SecOps", "scan.html"),
        _ct.record_completion("security-role-training", "3.2.2", "2026-06-01", "ISSM", "training.csv"),
    ]
    key = _pp.keygen(tempfile.mkdtemp(), "console")
    return build(posture, completions=completions, as_of="2026-09-03",
                 key=key, signed_at="2026-09-03T00:00:00Z", use_llm=use_llm)


def render_text(model):
    """A compact terminal rendering of the console (the HTML pane is render_html)."""
    L = []
    s = model["summary"]
    L.append("PrismPath GRC console  |  standard: %s  |  boundary: %s" % (model["standard"], model["boundary"]))
    L.append("standards available: %s" % ", ".join(model["standards_available"]))
    L.append("verdicts: %s" % s["tally"])
    L.append("objectives decided by: %s" % s["by_mechanism"])
    L.append("SPRS ceiling (optimistic): %s  |  points deducted: %s  |  assessed: %s"
             % (model["sprs"]["ceiling_if_unassessed_all_met"], model["sprs"]["deducted_points"],
                model["sprs"]["n_assessed"]))
    L.append("aggregate risk (likely ALE): $%s" % format(model["risk"]["aggregate_ale"]["likely"], ","))
    L.append("top risk: %s ($%s)" % (model["risk"]["top"][0]["name"],
                                     format(model["risk"]["top"][0]["ale"]["likely"], ",")))
    L.append("SOP documents: %d  |  tasks overdue: %d  |  signed receipts: %d  |  OSCAL export: %s"
             % (len(model["sops"]), len(model["tasks_due"]), model["receipts"]["n_signed"],
                model["oscal_export"]["available"]))
    L.append("decision view (first 6 controls):")
    for c in model["controls"][:6]:
        wb = c["what_breaks"][0]["scenario"] if c["what_breaks"] else "none"
        L.append("  %-9s %-13s who: %-45s breaks: %s" % (c["control_id"], c["verdict"],
                                                         c["who_decides"][:45], wb))
    return "\n".join(L)


_VERDICT_CLASS = {"met": "met", "partially-met": "partial", "not-met": "notmet", "insufficient": "insuff"}

_CSS = """
*{box-sizing:border-box}
:root{
  --ground:#eef3f4; --surface:#ffffff; --ink:#0d1b21; --muted:#5c6b71; --line:#d8e2e5;
  --accent:#17697a; --accent-soft:#e0edf0;
  --met:#0f7a52; --met-bg:#e2f2eb; --partial:#9a6410; --partial-bg:#f6ecd8;
  --notmet:#b3382f; --notmet-bg:#f6e1df; --insuff:#5f6f76; --insuff-bg:#e7edef;
}
:root:not([data-theme="light"]){}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){
  --ground:#091317; --surface:#0f2027; --ink:#e7eef0; --muted:#8ba0a7; --line:#1f333b;
  --accent:#41b7cf; --accent-soft:#12303a;
  --met:#39cd8c; --met-bg:#0f2a22; --partial:#e0a63a; --partial-bg:#2a2413;
  --notmet:#f0736a; --notmet-bg:#2c1a19; --insuff:#8496a0; --insuff-bg:#182731;
}}
:root[data-theme="dark"]{
  --ground:#091317; --surface:#0f2027; --ink:#e7eef0; --muted:#8ba0a7; --line:#1f333b;
  --accent:#41b7cf; --accent-soft:#12303a;
  --met:#39cd8c; --met-bg:#0f2a22; --partial:#e0a63a; --partial-bg:#2a2413;
  --notmet:#f0736a; --notmet-bg:#2c1a19; --insuff:#8496a0; --insuff-bg:#182731;
}
body{margin:0;background:var(--ground);color:var(--ink);
  font-family:"IBM Plex Sans",system-ui,sans-serif;line-height:1.5;-webkit-font-smoothing:antialiased}
.mono{font-family:"IBM Plex Mono",ui-monospace,monospace;font-variant-numeric:tabular-nums}
.muted{color:var(--muted);font-weight:400}
.wrap{max-width:1120px;margin:0 auto;padding:28px 24px 56px}
.top{display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:10px;
  padding-bottom:16px;border-bottom:1px solid var(--line);margin-bottom:22px}
.brand{font-family:"IBM Plex Mono",monospace;font-weight:600;font-size:15px;letter-spacing:.04em;
  text-transform:uppercase;display:flex;align-items:center;gap:9px}
.brand .dot{width:9px;height:9px;border-radius:2px;background:var(--accent);
  box-shadow:0 0 0 3px var(--accent-soft)}
.ctx{color:var(--muted);font-size:14px}
.cards{display:grid;grid-template-columns:1fr 1fr 1.6fr;gap:14px;margin-bottom:14px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.card .k{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:600}
.card .v{font-size:34px;font-weight:600;line-height:1.1;margin-top:6px}
.card .v.neg{color:var(--notmet)}
.card .sub{font-size:12px;color:var(--muted);margin-top:8px}
.vbar{display:flex;height:12px;border-radius:6px;overflow:hidden;margin:12px 0 10px;background:var(--insuff-bg)}
.seg{display:block;height:100%}
.seg.met{background:var(--met)}.seg.partial{background:var(--partial)}
.seg.notmet{background:var(--notmet)}.seg.insuff{background:var(--insuff)}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:12.5px;color:var(--muted)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:baseline}
.sw.met{background:var(--met)}.sw.partial{background:var(--partial)}.sw.notmet{background:var(--notmet)}.sw.insuff{background:var(--insuff)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:14px 0}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:18px 20px}
.panel h2{font-size:15px;margin:0 0 12px;font-weight:600;display:flex;gap:10px;align-items:baseline}
.panel h2 .muted{font-size:12px;font-weight:400}
ul.risk{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:9px}
ul.risk li{display:grid;grid-template-columns:1fr auto auto;gap:12px;align-items:baseline;
  padding-bottom:9px;border-bottom:1px solid var(--line);font-size:14px}
ul.risk li:last-child{border-bottom:0;padding-bottom:0}
.rk-ale{color:var(--notmet);font-weight:600}.rk-vuln{color:var(--muted);font-size:12px}
ul.cov{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:9px}
ul.cov li{display:flex;justify-content:space-between;font-size:14px;padding-bottom:9px;border-bottom:1px solid var(--line)}
ul.cov li:last-child{border-bottom:0;padding-bottom:0}
ul.cov span:first-child{color:var(--muted)}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:13px;min-width:820px}
thead th{text-align:left;padding:10px 12px;background:var(--accent-soft);color:var(--accent);
  font-size:11px;text-transform:uppercase;letter-spacing:.06em;position:sticky;top:0}
tbody td{padding:9px 12px;border-top:1px solid var(--line);vertical-align:top}
tbody tr:hover{background:var(--accent-soft)}
td.cid{font-weight:600;white-space:nowrap}
td.title{color:var(--ink);max-width:180px}
td.cause,td.who,td.breaks{color:var(--muted);font-size:12.5px}
.pill{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:600;white-space:nowrap;
  font-family:"IBM Plex Mono",monospace}
.pill.met{background:var(--met-bg);color:var(--met)}
.pill.partial{background:var(--partial-bg);color:var(--partial)}
.pill.notmet{background:var(--notmet-bg);color:var(--notmet)}
.pill.insuff{background:var(--insuff-bg);color:var(--insuff)}
.ok{color:var(--met);font-weight:500}
.foot{margin-top:22px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}
@media(max-width:760px){.cards{grid-template-columns:1fr}.grid2{grid-template-columns:1fr}}
"""


def _money(n):
    return "$" + format(int(n or 0), ",")


def render_html(model):
    """Artifact-ready HTML for the console pane: a Google Fonts link, a themed stylesheet, and the
    content, all data-driven from the console model. Safe to publish as an artifact."""
    s, risk, sprs = model["summary"], model["risk"], model["sprs"]
    tally, mech = s["tally"], s["by_mechanism"]
    total = s["n_controls"] or 1

    def seg(k, cls):
        pct = round(100 * tally.get(k, 0) / total, 3)
        return '<span class="seg %s" style="width:%s%%" title="%s: %d"></span>' % (cls, pct, k, tally.get(k, 0))
    vbar = "".join(seg(k, c) for k, c in [("met", "met"), ("partially-met", "partial"),
                                          ("not-met", "notmet"), ("insufficient", "insuff")])

    def row(c):
        vc = _VERDICT_CLASS.get(c["verdict"], "insuff")
        exposed = [wb for wb in c["what_breaks"] if wb["exposed"]]
        if not c["what_breaks"]:
            breaks = '<span class="muted">not modeled</span>'
        elif not exposed:
            breaks = '<span class="ok">mitigated</span>'
        else:
            breaks = "<br>".join('%s <span class="mono">%s</span>' % (wb["scenario"], _money(wb["ale_likely"]))
                                 for wb in exposed)
        return ('<tr><td class="mono cid">%s</td><td class="title">%s</td>'
                '<td><span class="pill %s">%s</span></td><td class="cause">%s</td>'
                '<td class="who">%s</td><td class="breaks">%s</td></tr>'
                % (c["control_id"], c["title"], vc, c["verdict"], c["cause"], c["who_decides"], breaks))
    rows = "".join(row(c) for c in model["controls"])

    top = "".join('<li><span class="rk-name">%s</span><span class="rk-ale mono">%s</span>'
                  '<span class="rk-vuln mono">vuln %s</span></li>'
                  % (r["name"], _money(r["ale"]["likely"]), r["vulnerability"]) for r in risk["top"])
    scanners = ", ".join(model["provenance"].get("scanners", [])) or model["provenance"].get("source", "manual")
    ceil = sprs["ceiling_if_unassessed_all_met"]

    return (
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">\n'
        '<style>%s</style>\n' % _CSS +
        '<main class="wrap">\n'
        '<header class="top"><div class="brand"><span class="dot"></span>PrismPath GRC</div>'
        '<div class="ctx"><span class="mono">%s</span> &nbsp;/&nbsp; %s</div></header>\n' % (model["standard"], model["boundary"]) +
        '<section class="cards">'
        '<div class="card"><div class="k">SPRS ceiling</div><div class="v mono %s">%s</div>'
        '<div class="sub">optimistic upper bound &middot; %s pts deducted &middot; %s assessed</div></div>'
        % (("neg" if (ceil or 0) < 0 else ""), ceil, sprs["deducted_points"], sprs["n_assessed"]) +
        '<div class="card"><div class="k">Aggregate risk (likely)</div><div class="v mono">%s</div>'
        '<div class="sub">annualized loss expectancy, verdict-driven</div></div>'
        % _money(risk["aggregate_ale"]["likely"]) +
        '<div class="card"><div class="k">Verdicts (%d controls)</div><div class="vbar">%s</div>'
        '<div class="legend"><span><i class="sw met"></i>met %d</span><span><i class="sw partial"></i>partial %d</span>'
        '<span><i class="sw notmet"></i>not-met %d</span><span><i class="sw insuff"></i>insufficient %d</span></div>'
        '<div class="sub">decided by config %d, operational %d, LLM %d; %d objectives still open</div></div></section>'
        % (total, vbar, tally.get("met", 0), tally.get("partially-met", 0), tally.get("not-met", 0),
           tally.get("insufficient", 0), mech["config"], mech["operational"], mech["llm"], mech["undetermined"]) +
        '<section class="grid2">'
        '<div class="panel"><h2>Top loss scenarios</h2><ul class="risk">%s</ul></div>' % top +
        '<div class="panel"><h2>Coverage</h2><ul class="cov">'
        '<li><span>Scanners</span><span class="mono">%s</span></li>'
        '<li><span>Signed receipts</span><span class="mono">%s</span></li>'
        '<li><span>SOP documents</span><span class="mono">%s</span></li>'
        '<li><span>Tasks overdue</span><span class="mono">%s</span></li>'
        '<li><span>Standards</span><span class="mono">%s</span></li>'
        '<li><span>OSCAL export</span><span class="mono">%s</span></li></ul></div></section>'
        % (scanners, model["receipts"]["n_signed"], len(model["sops"]), len(model["tasks_due"]),
           len(model["standards_available"]), ("yes" if model["oscal_export"]["available"] else "no")) +
        '<section class="panel"><h2>Decision view <span class="muted">control, verdict, cause, who decides, what breaks</span></h2>'
        '<div class="tablewrap"><table><thead><tr><th>Control</th><th>Title</th><th>Verdict</th>'
        '<th>Cause</th><th>Who decides</th><th>What breaks</th></tr></thead><tbody>%s</tbody></table></div></section>' % rows +
        '<footer class="foot mono">Every verdict is a decidable, signed determination. Insufficient means the '
        'evidence did not positively demonstrate the objective; it is never assumed met.</footer>\n</main>')


if __name__ == "__main__":
    print(render_text(demo()))
