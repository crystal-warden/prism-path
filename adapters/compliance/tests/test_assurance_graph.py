# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The connectivity graph joins what we already hold — controls, objectives, crosswalks, FAIR risk, and
ownership — so one control's assurance chain is a single query: what it satisfies across frameworks, what
risk it mitigates, and who owns it. No new data, just the connections made explicit."""
from adapters.compliance import compliance_adapter as ca
from adapters.compliance import assurance_graph as assurance_graph


def test_graph_summary_links_the_pieces():
    summary = assurance_graph.graph_summary("nist_800171_r2")
    assert summary["nodes"]["controls"] == 110 and summary["nodes"]["objectives"] == 320
    # the crosswalks we built are all linked in from 800-171
    assert {"cmmc", "nist_800_53_r5", "soc2_tsc"} <= set(summary["nodes"]["frameworks_linked"])
    assert summary["edges"]["crosswalk_links"] > 0 and summary["edges"]["risk_links"] > 0
    assert summary["owners"]
    ca.use_standard("nist_800171_r2")


def test_trace_walks_the_whole_chain_for_one_control():
    trace = assurance_graph.trace("3.1.1", "nist_800171_r2")
    assert trace["control_id"] == "3.1.1" and trace["title"] and trace["owner"]
    assert trace["objectives"]                                          # its assessment objectives
    # 3.1.1 reaches CMMC, 800-53, and SOC 2 through the crosswalks
    assert {"cmmc", "nist_800_53_r5", "soc2_tsc"} <= set(trace["frameworks_satisfied"])
    # each reach names concrete target controls
    assert all(reached["controls"] for reached in trace["crosswalk_reach"])
    assert isinstance(trace["mitigates_risk"], list)
    ca.use_standard("nist_800171_r2")


def test_render_runs():
    txt = assurance_graph.render_text(assurance_graph.demo())
    assert "Assurance connectivity graph" in txt and "trace 3.1.1" in txt
