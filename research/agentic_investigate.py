#!/usr/bin/env python3
"""#55 — bounded agentic PULL-context investigation node (escalation path only).

#2/#1 proved PUSHing correlated context at the triage LLM DILUTES it. PULL is the inverse: the model
requests the ONE fact it needs via a tool, gets a focused answer, reasons on it. This is the residual
'hard case' path — for alerts a decomposed node adjudicated but couldn't resolve confidently
(e.g. the wuauclt LotL masquerade #56 still under-called, or an admin-mimicry event that might be
genuinely benign noise).

This file delivers the MECHANISM: a bounded ReAct loop (manual, via structured output — no dependence
on native tool-calling) + a production-shaped tool interface (binds to Wazuh/Zeek/baseline stores or
the future polyglot probes). It validates on hand-built hard cases with a PULL-vs-PUSH-vs-single-shot
contrast. A CORPUS-WIDE lift is NOT claimed: the single-event corpus has no telemetry for tools to
query — that efficacy is gated on real telemetry (pilot / Tier-1 emulation / probe signals).
"""
import json, requests
GEMMA = "http://127.0.0.1:8888/v1/chat/completions"; MODEL = "gemma4"

STEP_SCHEMA = {"type": "object", "properties": {
    "step_type": {"type": "string", "enum": ["investigate", "decide"]},
    "tool": {"type": "string", "enum": ["process_lineage", "host_baseline", "prior_logons",
                                        "related_alerts", "ioc_reputation", "none"]},
    "args": {"type": "string"},
    "recommended_action": {"type": "string", "enum": ["contain", "watch", "ignore", "none"]},
    "rationale": {"type": "string"}},
    "required": ["step_type", "rationale"]}
VERDICT_SCHEMA = {"type": "object", "properties": {
    "recommended_action": {"type": "string", "enum": ["contain", "watch", "ignore"]},
    "rationale": {"type": "string"}}, "required": ["recommended_action", "rationale"]}


def _call(messages, schema, name, _retry=True):
    body = {"model": MODEL, "temperature": 0, "max_tokens": 900, "messages": messages,
            "response_format": {"type": "json_schema", "json_schema": {"name": name, "schema": schema}}}
    r = requests.post(GEMMA, json=body, timeout=120); r.raise_for_status()
    content = r.json()["choices"][0]["message"]["content"]
    try:
        return json.loads(content)
    except Exception:
        if _retry:  # break gemma degenerate/truncated-JSON loops with a concise nudge
            m2 = messages + [{"role": "user", "content": "Return ONE compact JSON object only; rationale under 12 words."}]
            return _call(m2, schema, name, _retry=False)
        raise


# ---- tool interface. In production each binds to a real backend (Wazuh search, Zeek conn log,
# a per-host baseline store, an IOC feed, or the polyglot probe signal layer). Here they read a
# per-case evidence store that holds what such a backend WOULD truthfully return. Un-wired -> honest
# "no data" so the model can't hallucinate telemetry. ----
TOOLS = {
    "process_lineage": "parent/child process chain and launch path for the alert's process",
    "host_baseline": "how often this activity has been seen on THIS host before (rarity / first-seen)",
    "prior_logons": "recent logon history for the source (who/where/when)",
    "related_alerts": "other detections on the same host in the surrounding time window",
    "ioc_reputation": "reputation of an indicator (hash, domain, ip, dll)",
}


def run_tool(tool, args, evidence):
    return evidence.get(tool, f"no data available for {tool} (telemetry backend not wired)")


def investigate(alert, evidence, budget=3, log=None):
    """Bounded PULL loop. Returns (action, trace)."""
    toollist = "\n".join(f"  - {t}: {d}" for t, d in TOOLS.items())
    sys = ("You are a SOC triage analyst investigating ONE alert. You may PULL specific facts you need "
           "via tools, one at a time, then decide. Do not guess — if a fact would change your verdict, "
           "request it. Be economical: request only what you need.\n"
           f"Tools:\n{toollist}\n"
           "Each turn, return step_type='investigate' with a tool+args to pull a fact, OR "
           "step_type='decide' with a recommended_action (contain/watch/ignore) once you have enough.")
    msgs = [{"role": "system", "content": sys},
            {"role": "user", "content": f'Alert: "{alert}" on a Windows endpoint.'}]
    trace = []
    for i in range(budget):
        step = _call(msgs, STEP_SCHEMA, "step")
        if step["step_type"] == "decide" and step.get("recommended_action", "none") != "none":
            trace.append({"decide": step["recommended_action"], "why": step["rationale"][:80]})
            return step["recommended_action"], trace
        tool = step.get("tool", "none"); args = step.get("args", "")
        if tool == "none":
            break
        fact = run_tool(tool, args, evidence)
        trace.append({"pull": f"{tool}({args[:40]})", "fact": fact[:90]})
        msgs.append({"role": "assistant", "content": json.dumps({"tool": tool, "args": args})})
        msgs.append({"role": "user", "content": f"TOOL {tool} -> {fact}\nContinue: investigate again or decide."})
    # budget exhausted -> force a decision on what was gathered
    msgs.append({"role": "user", "content": "Investigation budget reached. Decide now."})
    v = _call(msgs, VERDICT_SCHEMA, "verdict")
    trace.append({"decide(forced)": v["recommended_action"], "why": v["rationale"][:80]})
    return v["recommended_action"], trace


def single_shot(alert):
    v = _call([{"role": "user", "content":
                'You are a SOC triage analyst. Classify and recommend contain/watch/ignore.\n'
                f'Alert: "{alert}" on a Windows endpoint.'}], VERDICT_SCHEMA, "v")
    return v["recommended_action"]


def push_all(alert, evidence):
    dump = "\n".join(f"  - {t}: {run_tool(t, '', evidence)}" for t in evidence)
    v = _call([{"role": "user", "content":
                'You are a SOC triage analyst. Classify and recommend contain/watch/ignore.\n'
                f'Alert: "{alert}" on a Windows endpoint.\n'
                f"Correlated context (all available):\n{dump}\nWeigh it all together."}],
              VERDICT_SCHEMA, "v")
    return v["recommended_action"]


# ---- hard-case demos: evidence = what a real backend/probe WOULD return (truthful, not the label) ----
CASES = [
    {"name": "wuauclt LotL masquerade (a #56 residual under-call)",
     "alert": "Execution | evasion execution imageload wuauclt | EventID 7 | ImageLoaded by wuauclt.exe",
     "truth": "contain",
     "evidence": {
         "process_lineage": "wuauclt.exe was launched by cmd.exe from C:\\Users\\Public\\, NOT by svchost.exe/services.exe as Windows Update normally is",
         "host_baseline": "wuauclt.exe launching from a user-writable path has NEVER been observed on this host",
         "ioc_reputation": "the DLL loaded by wuauclt.exe is unsigned and unknown to reputation feeds"}},
    {"name": "DCOM 10016 admin-mimicry that is GENUINELY benign noise",
     "alert": "Lateral Movement | DCOM mmc 10016 | EventID 10016",
     "truth": "ignore",
     "evidence": {
         "host_baseline": "DCOM event 10016 for the mmc CLSID fires ~40x/day on this host — a known-benign DCOM permissioning artifact",
         "related_alerts": "no other suspicious detections on this host in the surrounding 24h window"}},
    {"name": "PowerShell Remoting — malicious in context",
     "alert": "Lateral Movement | PowershellRemoting wsmprovhost | EventID 1 | wsmprovhost.exe",
     "truth": "contain",
     "evidence": {
         "prior_logons": "the source IP is a workstation that has never before initiated PowerShell Remoting to this server",
         "related_alerts": "immediately preceded by a credential-access detection (LSASS access) from the same source",
         "host_baseline": "this server has never received PS-Remoting from a workstation subnet"}},
]

if __name__ == "__main__":
    out = []
    for c in CASES:
        ss = single_shot(c["alert"])
        pu = push_all(c["alert"], c["evidence"])
        pl, trace = investigate(c["alert"], c["evidence"])
        out.append({"case": c["name"], "truth": c["truth"],
                    "single_shot": ss, "push_all": pu, "PULL_agentic": pl,
                    "pull_correct": pl == c["truth"], "n_pulls": sum(1 for t in trace if "pull" in t),
                    "trace": trace})
    summary = {"cases": len(CASES),
               "single_shot_correct": sum(o["single_shot"] == o["truth"] for o in out),
               "push_all_correct": sum(o["push_all"] == o["truth"] for o in out),
               "PULL_agentic_correct": sum(o["PULL_agentic"] == o["truth"] for o in out),
               "detail": out}
    with open("/home/cwadmin/cwprojects/triage-corpus/agentic_pull_demo.json", "w") as f:
        json.dump(summary, f, indent=1)
    print(json.dumps({k: summary[k] for k in ("cases", "single_shot_correct", "push_all_correct",
                                              "PULL_agentic_correct")}, indent=1))
    for o in out:
        print(f"\n{o['case']}\n  truth={o['truth']} | single={o['single_shot']} push={o['push_all']} PULL={o['PULL_agentic']} ({o['n_pulls']} pulls)")
        for t in o["trace"]:
            print("   ", t)
