#!/usr/bin/env python3
"""#67 — enrich the NIST 800-171 AC catalog with the Translation layer (Gap 1):
control-level `evidence_types` (what artifacts satisfy the control) and per-objective `discovery_query`
(the specific ask routed to the client when that objective is not demonstrated). Idempotent: re-running
overwrites the enrichment fields, never touches control/objective text."""
import os, json
HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "catalog", "nist_800171_ac.json")

# control-level evidence artifact categories
EVIDENCE_TYPES = {
    "3.1.1": ["authorized-user/role inventory", "device/asset inventory + NAC config", "IAM/directory export showing access limitation", "screenshot of enforcement on the boundary"],
    "3.1.2": ["role-to-transaction/function permission matrix", "application/OS authorization config (RBAC)", "screenshot showing a user limited to permitted functions"],
    "3.1.4": ["separation-of-duties matrix / policy", "role assignments showing conflicting duties split across individuals", "access-privilege grants per individual"],
    "3.1.5": ["privileged-account inventory", "least-privilege authorization records / approval tickets", "security-function inventory", "PAM/JIT-elevation config"],
    "3.1.7": ["definition of privileged functions", "definition of non-privileged users (AD groups)", "config preventing non-privileged execution", "audit-log sample capturing privileged-function execution"],
    "3.1.11": ["session-termination policy (defined conditions)", "GPO/OS config enforcing auto-logoff/lock", "screenshot of enforced timeout on a boundary asset"],
    "3.1.12": ["remote-access policy (permitted types)", "VPN/gateway config controlling remote access", "monitoring/SIEM evidence of remote-session logging + review"],
    "3.1.22": ["list of individuals authorized to post public content", "procedure preventing CUI on public systems", "content-review/approval workflow record", "evidence of periodic public-content review for CUI"],
}

# per-objective specific asks (keyed by objective id)
DISCOVERY = {
    "3.1.1[a]": "Provide the inventory or directory export identifying every authorized user.",
    "3.1.1[b]": "Provide the list of processes/service accounts acting on behalf of authorized users.",
    "3.1.1[c]": "Provide the device/asset inventory identifying devices and systems authorized to connect.",
    "3.1.1[d]": "Provide the IAM/access config demonstrating system access is limited to those authorized users.",
    "3.1.1[e]": "Provide config showing access is limited to the authorized processes/service accounts.",
    "3.1.1[f]": "Provide NAC/802.1X or equivalent config limiting access to authorized devices only.",
    "3.1.2[a]": "Provide the matrix defining which transactions/functions each authorized role may execute.",
    "3.1.2[b]": "Provide RBAC/authorization config demonstrating users are limited to those defined functions.",
    "3.1.4[a]": "Provide the documentation defining which duties require separation.",
    "3.1.4[b]": "Provide role assignments showing those duties are split across separate individuals.",
    "3.1.4[c]": "Provide access-privilege grants showing the enabling privileges are held by separate individuals.",
    "3.1.5[a]": "Provide the inventory of privileged accounts.",
    "3.1.5[b]": "Provide the authorization/approval records showing privileged access follows least privilege.",
    "3.1.5[c]": "Provide the inventory of security functions.",
    "3.1.5[d]": "Provide the authorization records showing access to security functions follows least privilege.",
    "3.1.7[a]": "Provide the definition/list of privileged functions.",
    "3.1.7[b]": "Provide the definition of non-privileged users (e.g., the relevant AD groups).",
    "3.1.7[c]": "Provide config demonstrating non-privileged users cannot execute privileged functions.",
    "3.1.7[d]": "Provide an audit-log sample showing privileged-function execution is captured.",
    "3.1.11[a]": "Provide the policy defining the conditions that require a session to terminate.",
    "3.1.11[b]": "Provide GPO/OS config (and a screenshot) showing sessions auto-terminate after those conditions.",
    "3.1.12[a]": "Confirm and document that remote access sessions are permitted (or prohibited).",
    "3.1.12[b]": "Provide the list identifying the permitted types of remote access.",
    "3.1.12[c]": "Provide the gateway/VPN config demonstrating remote sessions are controlled.",
    "3.1.12[d]": "Provide SIEM/monitoring evidence that remote sessions are logged and reviewed.",
    "3.1.22[a]": "Provide the list of individuals authorized to post/process content on public systems.",
    "3.1.22[b]": "Provide the procedure ensuring CUI is not posted/processed on publicly accessible systems.",
    "3.1.22[c]": "Provide evidence of a pre-posting review process for public content.",
    "3.1.22[d]": "Provide records of periodic review of public content for inadvertent CUI.",
}

cat = json.load(open(PATH))
n_obj = 0
for cid, ctl in cat["controls"].items():
    ctl["evidence_types"] = EVIDENCE_TYPES.get(cid, [])
    for o in ctl["objectives"]:
        q = DISCOVERY.get(o["id"])
        if q is None:
            q = "Provide evidence that %s." % o["text"]
        o["discovery_query"] = q
        n_obj += 1
cat["_meta"]["translation"] = ("Each control carries evidence_types; each objective carries a discovery_query. "
                               "The discovery loop (defer_for_evidence) uses these to generate catalog-driven, "
                               "objective-specific evidence requests (Gap-1 Translation layer).")
json.dump(cat, open(PATH, "w"), indent=2)
print("enriched %d controls, %d objectives with evidence_types + discovery_query" % (len(cat["controls"]), n_obj))
