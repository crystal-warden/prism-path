import json
import os

spec_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'spec.json')
output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'corpus')

os.makedirs(output_dir, exist_ok=True)

with open(spec_file, 'r') as f:
    spec = json.load(f)

manifest = []

easy_mix = ["met", "not-met", "met", "not-met", "met", "not-met", "met", "not-met", "met"]
hard_traps = ["a", "b", "c", "d", "a", "b", "c", "d", "a"]
trap_names = {
    "a": "intent-only policy",
    "b": "out of scope",
    "c": "subtly misses one sub-objective",
    "d": "distractor artifact"
}

for idx, control in enumerate(spec["controls"]):
    cid = control["control_id"]
    objectives = control["objectives"]
    boundary = "CUI Enclave (VLAN 40)"
    
    # Easy
    easy_status = easy_mix[idx]
    if easy_status == "met":
        evidence = [{"type": "policy", "text": "All objectives are fully met. " + " ".join([o["text"] for o in objectives])}]
        rationale = "The evidence clearly and fully demonstrates all objectives."
        decisive_obj = objectives[0]["id"]
    else:
        evidence = [{"type": "log", "text": "Random log file with no relevant information."}]
        rationale = "The evidence provided is completely irrelevant and does not address any objectives."
        decisive_obj = objectives[0]["id"]
    
    easy_file = f"{cid}__easy.json"
    data = {
        "control_id": cid,
        "boundary": boundary,
        "evidence": evidence,
        "_label": {
            "status": easy_status,
            "decisive_objective_id": decisive_obj,
            "rationale": rationale,
            "difficulty": "easy",
            "trap": ""
        }
    }
    with open(os.path.join(output_dir, easy_file), 'w') as f:
        json.dump(data, f, indent=2)
    manifest.append({"file": easy_file, "control_id": cid, "difficulty": "easy", "status": easy_status, "trap": ""})
    
    # Medium
    evidence = [{"type": "policy", "text": "Most objectives are met. " + " ".join([o["text"] for o in objectives[:-1]])}]
    rationale = f"Evidence addresses most objectives but misses objective {objectives[-1]['id']}."
    decisive_obj = objectives[-1]["id"]
    med_file = f"{cid}__medium.json"
    data = {
        "control_id": cid,
        "boundary": boundary,
        "evidence": evidence,
        "_label": {
            "status": "partially-met",
            "decisive_objective_id": decisive_obj,
            "rationale": rationale,
            "difficulty": "medium",
            "trap": ""
        }
    }
    with open(os.path.join(output_dir, med_file), 'w') as f:
        json.dump(data, f, indent=2)
    manifest.append({"file": med_file, "control_id": cid, "difficulty": "medium", "status": "partially-met", "trap": ""})

    # Hard
    trap_type = hard_traps[idx]
    if trap_type == "a":
        evidence = [{"type": "policy", "text": "Policy states that we will " + " and ".join([o["text"] for o in objectives]) + ". No technical enforcement provided."}]
        trap = trap_names["a"]
        rationale = "The evidence is a policy document indicating intent, but there is no evidence of implementation or enforcement."
        decisive_obj = objectives[0]["id"]
        status = "not-met"
    elif trap_type == "b":
        evidence = [{"type": "config", "text": "Configuration for the Guest Network (VLAN 50) demonstrating " + " and ".join([o["text"] for o in objectives])}]
        trap = trap_names["b"]
        rationale = "The evidence looks strong but applies to VLAN 50, which is outside the assessed boundary (VLAN 40)."
        decisive_obj = objectives[0]["id"]
        status = "not-met"
    elif trap_type == "c":
        evidence = [{"type": "config", "text": "Evidence shows implementation for " + " and ".join([o["text"] for o in objectives[:-1]]) + ". It subtly ignores the last sub-objective."}]
        trap = trap_names["c"]
        rationale = f"The evidence looks complete but completely misses objective {objectives[-1]['id']}."
        decisive_obj = objectives[-1]["id"]
        status = "partially-met"
    elif trap_type == "d":
        evidence = [{"type": "log", "text": "Syslog export showing many technical-looking lines, but none of them actually correspond to the control objectives."}]
        trap = trap_names["d"]
        rationale = "The log file is a distractor and contains no relevant evidence for the objectives."
        decisive_obj = objectives[0]["id"]
        status = "not-met"
        
    hard_file = f"{cid}__hard.json"
    data = {
        "control_id": cid,
        "boundary": boundary,
        "evidence": evidence,
        "_label": {
            "status": status,
            "decisive_objective_id": decisive_obj,
            "rationale": rationale,
            "difficulty": "hard",
            "trap": trap
        }
    }
    with open(os.path.join(output_dir, hard_file), 'w') as f:
        json.dump(data, f, indent=2)
    manifest.append({"file": hard_file, "control_id": cid, "difficulty": "hard", "status": status, "trap": trap})

with open(os.path.join(output_dir, "_manifest.json"), 'w') as f:
    json.dump(manifest, f, indent=2)

statuses = {}
difficulties = {}
for m in manifest:
    statuses[m["status"]] = statuses.get(m["status"], 0) + 1
    difficulties[m["difficulty"]] = difficulties.get(m["difficulty"], 0) + 1

print(f"Summary - Statuses: {statuses} | Difficulties: {difficulties}")
