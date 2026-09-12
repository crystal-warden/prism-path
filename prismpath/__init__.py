# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""PrismPath: a control plane for autonomous systems.

A person authors a decision structure as a Markdown flow; the deterministic fragment of it (Level M)
compiles to a small table image that decides identically from this Python engine down to a 1.7 KB
interpreter on a microcontroller or an FPGA fabric; the image is signed, envelope bounded, and version
floored before it takes effect; every decision leaves a receipt with a cause code. Prove what can happen,
enforce what may happen, prove what happened. The public position, with what is claimed and what is not,
is docs/POSITION.md; the map of every part is docs/SYSTEM_MAP.md; the glossary is docs/decoder-ring.md.

The package is grouped by concern:

    prismpath.kernel         parser, predicates, engine, causes, contract, analysis, level_m,
                             model_check, lint, graph_export, flow_context, flow_test
    prismpath.routing        embedder, router, centroid, calibrate, lockfile, routelog, llm_local, prefilter
    prismpath.safety         guard, guard_semantic, guard_ledger, the bypass and benign corpora,
                             bypass_report, measure_p1, gen_p1_lockfile, fuzz_predicates
    prismpath.hotswap        policy_pack, policy_host, crypto_registry, crypto_agility, crypto_host
    prismpath.ledgers        audit_log, ledger, ledger_runner, ledger_ots, ledger_airgap, context_ledger,
                             interactions, otel, checkpoint
    prismpath.workers        connector, cli_worker, chat_agent, code_nodes, sandbox, deferral, scheduler,
                             composer, langgraph_import
    prismpath.orchestration  run_sprint, sprint_flow, hermes_swarm, swarm_runner, swarm_exporter,
                             orchestrator, gates, retriever (the fallback orchestration layer)
    prismpath.evals          eval_flows, eval_routing, eval_hybrid, kappa, annotate
    prismpath.telemetry      Facet: quantizer, zeckendorf, wire, packed, receipts, epochs, ackchannel,
                             selfheal, concentrator, spiral (PROTOCOL.md)
    prismpath.canon          the byte level helpers every persisted or signed artifact is built from
    prismpath.cli            the command line, grouped by who runs it; prismpath.trail, lsp, ci_report
    prismpath.mission_control  the operator's console
    prismpath.portable       the JavaScript kernel and the frozen conformance corpora every kernel is judged by

Every pre regroup name (prismpath.engine, prismpath.checkpoint, ...) still imports and is the same module
object as its grouped counterpart, with a DeprecationWarning; the aliases go away in a later release. The reading order for "a flow becomes a decision" is kernel.parser,
kernel.predicates, kernel.engine, kernel.causes, kernel.analysis. Who the pieces are for: the process
owner authors and tests the flow; the engineer establishes the contract once and delivers; the operator
runs, swaps, attests, and reads the trail; the evaluator anchors and verifies the receipts.

This module re exports the connector SDK, which is what an adapter imports to plug a domain in behind the
six ports (adapters/ADAPTER_GUIDE.md).
"""
from prismpath.workers.connector import BaseConnector, node, PayloadFlattener

__all__ = ["BaseConnector", "node", "PayloadFlattener"]
