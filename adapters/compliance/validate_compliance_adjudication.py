#!/usr/bin/env python3
"""#62 — compliance adjudication efficacy (the #54 analogue for adapter #2).

Runs hand-labeled NIST 800-171 Access Control evidence bundles through gemma two ways:
  N  neutral            "is the control met?"
  E  escalation-default  "NOT MET unless every objective is positively evidenced on the boundary"
The dangerous error in compliance is OVER-PASS (claiming more compliance than the evidence supports —
worst case, 'met' when it is 'not-met'). The escalation-default should drive over-pass toward zero
while a neutral prompt rubber-stamps intent-only / absent / out-of-boundary evidence.
"""
import json
import os, requests
from collections import Counter
GEMMA = "http://127.0.0.1:8888/v1/chat/completions"; MODEL = "gemma4"
SCHEMA = {"type": "object", "properties": {
    "status": {"type": "string", "enum": ["met", "partially-met", "not-met"]},
    "rationale": {"type": "string"}}, "required": ["status", "rationale"]}
RANK = {"not-met": 0, "partially-met": 1, "met": 2}


def determine(prompt, concise=False):
    p = prompt + ("\nReturn ONE JSON object; rationale under 25 words." if concise else "")
    body = {"model": MODEL, "temperature": 0, "max_tokens": 512, "messages": [{"role": "user", "content": p}],
            "response_format": {"type": "json_schema", "json_schema": {"name": "d", "schema": SCHEMA}}}
    r = requests.post(GEMMA, json=body, timeout=120); r.raise_for_status()
    try:
        return json.loads(r.json()["choices"][0]["message"]["content"])["status"]
    except Exception:
        return determine(prompt, True) if not concise else None


# --- hand-labeled evidence bundles (ground truth in `expected`) ---
B = [
 {"id": "3.1.1", "title": "Limit system access to authorized users, processes, and devices",
  "obj": ["authorized users identified", "processes acting for users identified", "devices identified", "access limited to authorized users/processes/devices"],
  "evidence": "AD security-group export listing authorized users; Intune device inventory for the enclave; screenshots of conditional-access enforcement applied to the assessed OU covering users, service accounts, and devices.",
  "expected": "met"},
 {"id": "3.1.1", "title": "Limit system access to authorized users, processes, and devices",
  "obj": ["authorized users identified", "devices identified", "access limited"],
  "evidence": "A signed Access Control Policy PDF stating 'system access is limited to authorized users and devices.' No configuration, enforcement screenshots, or user/device inventory provided.",
  "expected": "not-met"},
 {"id": "3.1.5", "title": "Employ least privilege",
  "obj": ["least privilege employed for user accounts", "privileged accounts restricted"],
  "evidence": "Verbal attestation in an interview note: 'we follow least privilege.' No role definitions, PAM configuration, or privileged-account listing.",
  "expected": "not-met"},
 {"id": "3.1.5", "title": "Employ least privilege",
  "obj": ["least privilege employed for user accounts", "privileged accounts restricted"],
  "evidence": "PAM tool config export showing just-in-time elevation; documented least-privilege role matrix; screenshots restricting Domain Admin membership to 2 break-glass accounts on the assessed domain.",
  "expected": "met"},
 {"id": "3.1.12", "title": "Monitor and control remote access sessions",
  "obj": ["remote access sessions permitted are identified", "remote access is controlled", "remote access is monitored"],
  "evidence": "VPN config export showing MFA-gated remote access and an allow-list of remote methods (controlled + identified). No evidence of session logging, review, or monitoring of remote sessions.",
  "expected": "partially-met"},
 {"id": "3.1.2", "title": "Limit access to permitted transactions and functions",
  "obj": ["permitted transactions/functions defined", "access limited to permitted transactions/functions"],
  "evidence": "RBAC configuration export and screenshots — but for the corporate SharePoint tenant, which is OUTSIDE the assessed CUI enclave boundary. No evidence for the enclave itself.",
  "expected": "not-met"},
 {"id": "3.1.11", "title": "Terminate (or lock) a user session after a defined condition",
  "obj": ["a condition requiring session termination/lock is defined", "the system terminates/locks the session after the condition"],
  "evidence": "GPO report showing 15-minute inactivity lock and forced session termination at 30 minutes, linked to the assessed enclave OU, with a screenshot of the applied policy on an enclave workstation.",
  "expected": "met"},
 {"id": "3.1.1", "title": "Limit system access to authorized users, processes, and devices",
  "obj": ["authorized users identified", "processes identified", "devices identified & limited"],
  "evidence": "Authorized-user list and service-account inventory with enforcement screenshots (users + processes covered). No device identification or device-based access limitation evidence provided.",
  "expected": "partially-met"},
]

HEAD_N = "You are a compliance assessor for NIST SP 800-171.\n"
HEAD_E = "You are a NIST SP 800-171 compliance assessor.\n"


def bundle_text(b):
    return (f"Control {b['id']} — {b['title']}.\nAssessment objectives:\n"
            + "\n".join(f"  - {o}" for o in b["obj"])
            + f"\nSubmitted evidence: {b['evidence']}\n")


def prompt_N(b):
    return (HEAD_N + bundle_text(b) +
            "Determine whether the control is met. Return status (met / partially-met / not-met) and a rationale.")


def prompt_E(b):
    return (HEAD_E + bundle_text(b) +
            "The control is NOT MET unless the submitted evidence POSITIVELY DEMONSTRATES each assessment "
            "objective on the assessed system boundary. Intent-only policy without implementing configuration, "
            "evidence outside the assessed boundary, or any missing objective each mean that objective is NOT "
            "satisfied. Return status = 'met' only if EVERY objective is evidenced; 'partially-met' if some but "
            "not all; 'not-met' otherwise. Return status and a rationale.")


res = []
C = {"N": Counter(), "E": Counter()}
for b in B:
    aN = determine(prompt_N(b)); aE = determine(prompt_E(b))
    if aN is None or aE is None:
        continue
    exp = b["expected"]
    row = {"control": b["id"], "expected": exp, "N": aN, "E": aE}
    for arm, a in (("N", aN), ("E", aE)):
        if a == exp: C[arm]["exact"] += 1
        if RANK[a] > RANK[exp]: C[arm]["over_pass"] += 1           # claimed MORE compliance than reality (dangerous)
        if RANK[a] < RANK[exp]: C[arm]["under_call"] += 1          # over-strict
        if a == "met" and exp == "not-met": C[arm]["severe_overpass"] += 1
    res.append(row)

n = len(res)
out = {"n_bundles": n,
       "N_neutral": {"exact": C["N"]["exact"], "accuracy": round(C["N"]["exact"] / n, 3),
                     "OVER_PASS": C["N"]["over_pass"], "severe_overpass(met_when_notmet)": C["N"]["severe_overpass"],
                     "over_strict": C["N"]["under_call"]},
       "E_escalation_default": {"exact": C["E"]["exact"], "accuracy": round(C["E"]["exact"] / n, 3),
                                "OVER_PASS": C["E"]["over_pass"], "severe_overpass(met_when_notmet)": C["E"]["severe_overpass"],
                                "over_strict": C["E"]["under_call"]},
       "per_bundle": res}
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "compliance_efficacy_v0.json"), "w"), indent=1)
print(json.dumps({k: out[k] for k in ("n_bundles", "N_neutral", "E_escalation_default")}, indent=1))
print("\nper-bundle (control | expected | N | E):")
for r in res:
    flag = "  <-- N over-passes" if RANK[r["N"]] > RANK[r["expected"]] else ""
    print(f"  {r['control']:6} exp={r['expected']:13} N={r['N']:13} E={r['E']:13}{flag}")
