#!/usr/bin/env python3
"""Emit one self-contained agy prompt per control (3 difficulty bundles each), grounded in the real
objectives from spec.json. The loop driver feeds these to agy on a single --continue session."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
spec = json.load(open(os.path.join(HERE, "efficacy", "spec.json")))
pdir = os.path.join(HERE, "efficacy", "prompts")
os.makedirs(pdir, exist_ok=True)

DIFF = ("Difficulty tiers: easy = unambiguous (fully evidenced -> met, OR irrelevant/absent -> not-met); "
        "medium = genuinely partially-met (most objectives evidenced, at least one clearly unaddressed); "
        "hard = a TRAP a shallow reviewer gets wrong — pick ONE of: intent-only policy with no implementing "
        "config/enforcement; out-of-scope evidence (different boundary); satisfies most but subtly misses one "
        "sub-objective; or a plausible distractor that does not actually address the objectives.")

order = []
for c in spec["controls"]:
    cid = c["control_id"]
    objs = "\n".join("  %s: %s" % (o["id"], o["text"]) for o in c["objectives"])
    p = f"""You are an independent senior NIST SP 800-171 Rev 2 assessor authoring HELD-OUT test evidence to
evaluate a separate, weaker automated adjudicator. Do not try to make it pass — author realistic evidence
and assign the HONEST determination.

DOCUMENT-AUTHORING ONLY: do not start any model/inference server, do not use the GPU, do not touch port 8888.
Write only JSON files under ./efficacy/corpus/ . Stay in this directory.

Control {cid} — {c['title']}
Family: {c['family_name']} ({c['method_profile']} assessment-method profile)
Control statement: {c['control_statement']}
Assessment methods (800-171A): {', '.join(c['methods'])}
Assessment objectives:
{objs}

Write exactly THREE files: ./efficacy/corpus/{cid}__easy.json, {cid}__medium.json, {cid}__hard.json.
Each file is one JSON object:
{{"control_id":"{cid}","boundary":"<assessed boundary>","evidence":[{{"type":"policy|config|screenshot|log|interview|test|attestation","text":"<realistic artifact a tenant would submit>"}}],
  "_label":{{"status":"met|partially-met|not-met","decisive_objective_id":"<id from above>","rationale":"<2-3 sentences>","difficulty":"easy|medium|hard","trap":"<hard only: the fallacy; else empty>"}}}}

{DIFF}
Author evidence appropriate to the {c['method_profile']} profile (technical->config/scan/enforced-setting;
procedural->policy+interview/records; operational->exercise records/logs/observations). Escalation-default:
an objective is MET only when POSITIVELY demonstrated on the assessed boundary by the required method.
For this control, make the easy file cleanly met OR cleanly not-met (your choice), medium partially-met, hard a trap.
After writing the three files, print one line: {cid} done easy=<status> medium=<status> hard=<status>."""
    open(os.path.join(pdir, f"{cid}.txt"), "w").write(p)
    order.append(cid)

json.dump(order, open(os.path.join(pdir, "_order.json"), "w"))
print("wrote %d per-control prompts to %s" % (len(order), pdir))
