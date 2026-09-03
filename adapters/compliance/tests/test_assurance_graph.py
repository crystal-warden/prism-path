# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The connectivity graph joins what we already hold — controls, objectives, crosswalks, FAIR risk, and
ownership — so one control's assurance chain is a single query: what it satisfies across frameworks, what
risk it mitigates, and who owns it. No new data, just the connections made explicit."""
import compliance_adapter as ca
import assurance_graph as g


def test_graph_summary_links_the_pieces():
    s = g.graph_summary("nist_800171_r2")
    assert s["nodes"]["controls"] == 110 and s["nodes"]["objectives"] == 320
    # the crosswalks we built are all linked in from 800-171
    assert {"cmmc", "nist_800_53_r5", "soc2_tsc"} <= set(s["nodes"]["frameworks_linked"])
    assert s["edges"]["crosswalk_links"] > 0 and s["edges"]["risk_links"] > 0
    assert s["owners"]
    ca.use_standard("nist_800171_r2")


def test_trace_walks_the_whole_chain_for_one_control():
    t = g.trace("3.1.1", "nist_800171_r2")
    assert t["control_id"] == "3.1.1" and t["title"] and t["owner"]
    assert t["objectives"]                                          # its assessment objectives
    # 3.1.1 reaches CMMC, 800-53, and SOC 2 through the crosswalks
    assert {"cmmc", "nist_800_53_r5", "soc2_tsc"} <= set(t["frameworks_satisfied"])
    # each reach names concrete target controls
    assert all(r["controls"] for r in t["crosswalk_reach"])
    assert isinstance(t["mitigates_risk"], list)
    ca.use_standard("nist_800171_r2")


def test_render_runs():
    txt = g.render_text(g.demo())
    assert "Assurance connectivity graph" in txt and "trace 3.1.1" in txt
