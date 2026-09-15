// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/**
 * bundle_engine.mjs: the engine that `prismpath compile` puts in a single file bundle.
 *
 * A compiled bundle is the portable kernel (prismpath.mjs), the serialized graph, the embedded
 * lock and this file, concatenated. The kernel is inlined ABOVE this source, so the compiler
 * drops the import block below and every name it binds resolves to the inlined kernel. Nothing
 * here re-implements routing: the tiers, the suspension payloads and the error tier are the
 * kernel's own helpers, which the cross language conformance suite already pins.
 *
 * What this file adds to the kernel's run() is one thing: the worker and the embedder may be
 * ASYNC, because a bundle is deployed where the worker is a network call. The awaiting happens
 * here and the decisions happen in the kernel.
 *
 * Agreement with prismpath/kernel/engine.py, which this replaces a hand kept copy of:
 *   - humanFloor is the absolute confidence floor engine.py calls human_floor. Below it the run
 *     suspends with stopped="needs_human" and engine.py's reason wording. The earlier embedded
 *     copy had no floor at all.
 *   - a narrow top1 to top2 margin is NOT a suspension. engine.py routes the top scoring edge
 *     and leaves escalation to the router it was given; the earlier embedded copy invented
 *     stopped="needs_human" with a reason string no other engine can produce, which meant a
 *     bundle and the Python engine could disagree on the same outcome.
 *   - engine.py's derived contract type gate (type_gate) is OFF here, which is engine.py's own
 *     default. The portable kernel has no contract derivation, so a bundle cannot turn it on;
 *     a flow that needs the type gate belongs on the Python engine.
 */
// prismpath-bundle-strip-begin: `prismpath compile` inlines the kernel above and removes this import
import {
  decodeVecF16, firstDeterministic, handleErrorTier, isSemantic, normalize,
  pendingNeedsHuman, pendingWait, portabilityViolations, pyTruthy, recordStep, selectTier,
} from "./prismpath.mjs";
// prismpath-bundle-strip-end

/**
 * Decode the lock a bundle carries: the compiler stores the committed vectors as float16 to
 * halve the file, so decode them once at run start into the shape the kernel's locked router
 * reads (its lockVec accepts vectors that are already decoded).
 */
export function decodeEmbeddedLock(embeddedLock) {
  if (!embeddedLock || !embeddedLock.conditions) {
    return null;
  }
  const conditions = {};
  for (const [conditionText, base64String] of Object.entries(embeddedLock.conditions)) {
    conditions[conditionText] = decodeVecF16(base64String);
  }
  return { delta: embeddedLock.delta, conditions };
}

/**
 * Run a compiled flow. `agent(node, instruction, state)` and `embed(text)` may return a promise.
 * Options: {maxSteps=25, start=null, state=null, onStep=null, embed=null, humanFloor=null}.
 * Returns {path, steps, stopped, state, pending}, the same record the Python RunResult carries.
 */
export async function runCompiled(graph, embeddedLock, agent, opts = {}) {
  const {
    maxSteps = 25, start = null, state: initialState = null, onStep = null,
    embed = null, humanFloor = null,
  } = opts;
  const lock = decodeEmbeddedLock(embeddedLock);
  const violations = portabilityViolations(graph);
  if (violations.length && (!lock || !embed)) {
    const violationRec = violations[0];
    throw new Error(
      `this bundle needs an embedder: semantic edge [${violationRec.node}] -> ${violationRec.target} ` +
      `(${JSON.stringify(violationRec.condition)}) routes against the embedded lock, so call ` +
      "runFlow(agent, { embed })");
  }

  let currentNode = start !== null ? start : graph.start;
  const runState = initialState || {};
  runState.transcript = runState.transcript || [];
  runState.visits = runState.visits || {};
  const runResult = { path: [currentNode], steps: [], stopped: "", state: runState, pending: null };
  const checkpoint = (pendingNode) => {
    if (onStep) {
      onStep(runResult, pendingNode);
    }
  };

  for (let stepIndex = 0; stepIndex < maxSteps; stepIndex++) {
    const nodeRec = graph.nodes[currentNode];
    if (nodeRec.edges.length === 0) {
      runResult.stopped = "terminal";
      checkpoint(null);
      break;
    }
    checkpoint(currentNode);
    runState.visits[currentNode] = (runState.visits[currentNode] || 0) + 1;

    let outcome;
    try {
      outcome = await agent(currentNode, nodeRec.instruction, runState);
    } catch (err) {
      currentNode = handleErrorTier(currentNode, nodeRec, runState, err, runResult);
      continue;
    }

    const [outcomeText, fieldsObj] = normalize(outcome);
    runState.transcript.push({ node: currentNode, outcome: outcomeText });
    (runState._outcomes = runState._outcomes || {})[currentNode] = { ...fieldsObj };

    if (pyTruthy(fieldsObj.needs_human)) {
      runResult.stopped = "needs_human";
      runResult.pending = pendingNeedsHuman(currentNode, nodeRec, fieldsObj, outcomeText);
      checkpoint(currentNode);
      break;
    }

    if (pyTruthy(fieldsObj.wait) || fieldsObj.spawn != null) {
      runResult.stopped = "waiting";
      runResult.pending = pendingWait(currentNode, nodeRec, fieldsObj);
      checkpoint(currentNode);
      break;
    }

    const contextObj = { ...fieldsObj, visits: runState.visits[currentNode] };
    const embedFn = await embedderFor(nodeRec, contextObj, outcomeText, embed);
    const tierResult = selectTier(nodeRec, outcomeText, fieldsObj, contextObj, lock, embedFn, humanFloor);
    if (tierResult.needsHuman) {
      runResult.stopped = "needs_human";
      runResult.pending = tierResult.pending;
      checkpoint(currentNode);
      break;
    }
    if (tierResult.stuck) {
      runResult.stopped = "stuck";
      checkpoint(currentNode);
      break;
    }
    recordStep(runResult, currentNode, outcomeText, tierResult.target, tierResult.info);
    currentNode = tierResult.target;
  }
  if (!runResult.stopped) {
    runResult.stopped = "max_steps";
  }
  return runResult;
}

/**
 * The kernel's tier selector is synchronous, so a semantic step needs its query vector in hand
 * before the selector runs. Ask the same question the selector will ask, and embed only when the
 * answer is yes: the deterministic tier wins first, so a node that routes on a `when` predicate
 * never pays for an embedding call.
 */
async function embedderFor(nodeRec, contextObj, outcomeText, embed) {
  if (!embed) {
    return null;
  }
  const [deterministicTarget] = firstDeterministic(nodeRec.edges, contextObj);
  if (deterministicTarget !== null) {
    return null;
  }
  if (!nodeRec.edges.some(([, conditionText]) => isSemantic(conditionText))) {
    return null;
  }
  const queryVector = await embed(outcomeText);
  return () => queryVector;
}
