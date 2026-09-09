# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Layer comparison matrix validator, aggregator, and report generator."""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

SYSTEMS = ["prismpath", "opa", "cedar", "cerbos", "openfga", "openlane"]
DIMENSIONS = [
    "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8",
    "B1", "B2", "B3", "B4", "B5"
]

GRADE_ORDER = {"NOT": 0, "WITH-WORK": 1, "NATIVE": 2}
REQUIRED_FIELDS = [
    "system", "system_version", "dimension", "policy", "scenario",
    "expected", "observed", "match", "grade", "idiomatic", "glue",
    "evidence_path", "harness_commit", "run_at", "notes"
]


def validate_and_load_results(
    results_dir: Path
) -> Tuple[List[Tuple[str, Path, Dict[str, Any], str]], List[str]]:
    """Scan results_dir, validate files against SCHEMA.md, return consumed files and systems."""
    errors: List[str] = []
    consumed_files: List[Tuple[str, Path, Dict[str, Any], str]] = []
    scenario_expected_map: Dict[Tuple[str, str], Tuple[Optional[str], str]] = {}   # keyed by (policy, scenario): scenario ids repeat across policies
    extra_systems: List[str] = []

    if not results_dir.exists() or not results_dir.is_dir():
        return consumed_files, list(SYSTEMS)

    # Discover system directories
    for sys_entry in sorted(os.listdir(results_dir)):
        sys_path = results_dir / sys_entry
        if not sys_path.is_dir():
            continue

        if sys_entry in SYSTEMS:
            pass
        elif sys_entry.endswith("+glue"):
            if sys_entry not in extra_systems:
                extra_systems.append(sys_entry)
        else:
            errors.append(
                f"Directory '{sys_entry}' under results is not a registered system "
                f"or '<system>+glue' combination system."
            )
            continue

        for filename in sorted(os.listdir(sys_path)):
            if not filename.endswith(".json"):
                continue

            file_path = sys_path / filename
            rel_path = f"{sys_entry}/{filename}"

            name_part = filename[:-5]
            parts = name_part.split("__")
            if len(parts) != 3:
                errors.append(
                    f"File '{rel_path}' filename does not match structure '<dimension>__<policy>__<scenario>.json'"
                )
                fn_dim, fn_pol, fn_scen = None, None, None
            else:
                fn_dim, fn_pol, fn_scen = parts[0], parts[1], parts[2]

            try:
                raw_bytes = file_path.read_bytes()
                sha256 = hashlib.sha256(raw_bytes).hexdigest()
                data = json.loads(raw_bytes.decode("utf-8"))
            except Exception as e:
                errors.append(f"File '{rel_path}' is invalid JSON: {e}")
                continue

            if not isinstance(data, dict):
                errors.append(f"File '{rel_path}' top-level JSON must be an object.")
                continue

            missing = [f for f in REQUIRED_FIELDS if f not in data]
            if missing:
                errors.append(f"File '{rel_path}' missing required fields: {', '.join(missing)}")
                continue

            # Field agreement and type validations
            if not isinstance(data["system"], str):
                errors.append(f"File '{rel_path}' field 'system' must be a string.")
            elif data["system"] != sys_entry:
                errors.append(
                    f"File '{rel_path}' field 'system' ('{data['system']}') disagrees with directory name ('{sys_entry}')."
                )

            if not isinstance(data["dimension"], str):
                errors.append(f"File '{rel_path}' field 'dimension' must be a string.")
            else:
                if fn_dim is not None and data["dimension"] != fn_dim:
                    errors.append(
                        f"File '{rel_path}' field 'dimension' ('{data['dimension']}') disagrees with filename dimension ('{fn_dim}')."
                    )
                if data["dimension"] not in DIMENSIONS:
                    errors.append(
                        f"File '{rel_path}' field 'dimension' ('{data['dimension']}') is not a registered dimension."
                    )

            if not isinstance(data["policy"], str):
                errors.append(f"File '{rel_path}' field 'policy' must be a string.")
            elif fn_pol is not None and data["policy"] != fn_pol:
                errors.append(
                    f"File '{rel_path}' field 'policy' ('{data['policy']}') disagrees with filename policy ('{fn_pol}')."
                )

            if not isinstance(data["scenario"], str):
                errors.append(f"File '{rel_path}' field 'scenario' must be a string.")
            elif fn_scen is not None and data["scenario"] != fn_scen:
                errors.append(
                    f"File '{rel_path}' field 'scenario' ('{data['scenario']}') disagrees with filename scenario ('{fn_scen}')."
                )

            if not isinstance(data["system_version"], str):
                errors.append(f"File '{rel_path}' field 'system_version' must be a string.")

            if not isinstance(data["evidence_path"], str):
                errors.append(f"File '{rel_path}' field 'evidence_path' must be a string.")

            if not isinstance(data["harness_commit"], str):
                errors.append(f"File '{rel_path}' field 'harness_commit' must be a string.")

            if not isinstance(data["run_at"], str):
                errors.append(f"File '{rel_path}' field 'run_at' must be a string.")

            if not isinstance(data["notes"], str):
                errors.append(f"File '{rel_path}' field 'notes' must be a string.")

            if data["expected"] is not None and not isinstance(data["expected"], str):
                errors.append(f"File '{rel_path}' field 'expected' must be string or null.")

            if not isinstance(data["observed"], str):
                errors.append(f"File '{rel_path}' field 'observed' must be a string.")

            if type(data["match"]) is not bool:
                errors.append(f"File '{rel_path}' field 'match' must be boolean.")

            if type(data["idiomatic"]) is not bool:
                errors.append(f"File '{rel_path}' field 'idiomatic' must be boolean.")

            if data["grade"] not in ("NATIVE", "WITH-WORK", "NOT"):
                errors.append(
                    f"File '{rel_path}' field 'grade' ('{data['grade']}') must be NATIVE, WITH-WORK, or NOT."
                )

            # Glue validation
            if data["grade"] == "WITH-WORK":
                glue = data.get("glue")
                if glue is None or not isinstance(glue, dict):
                    errors.append(
                        f"File '{rel_path}' has grade 'WITH-WORK' but missing or non-object 'glue'."
                    )
                else:
                    glue_req = ["description", "components", "loc", "hours"]
                    missing_glue = [g for g in glue_req if g not in glue]
                    if missing_glue:
                        errors.append(
                            f"File '{rel_path}' glue object missing fields: {', '.join(missing_glue)}."
                        )
                    else:
                        if not isinstance(glue["description"], str):
                            errors.append(f"File '{rel_path}' glue.description must be a string.")
                        if not isinstance(glue["components"], list) or not all(isinstance(c, str) for c in glue["components"]):
                            errors.append(f"File '{rel_path}' glue.components must be a list of strings.")
                        if type(glue["loc"]) is not int:
                            errors.append(f"File '{rel_path}' glue.loc must be an int.")
                        if type(glue["hours"]) not in (int, float) or type(glue["hours"]) is bool:
                            errors.append(f"File '{rel_path}' glue.hours must be a number.")
            elif data["grade"] in ("NATIVE", "NOT"):
                if data.get("glue") is not None:
                    errors.append(f"File '{rel_path}' has grade '{data['grade']}' but 'glue' is not null.")

            if "measurements" in data and data["measurements"] is not None:
                if not isinstance(data["measurements"], dict):
                    errors.append(f"File '{rel_path}' field 'measurements' must be an object.")

            # Same-scenario expected consistency
            scen = data.get("scenario")
            pol = data.get("policy")
            exp = data.get("expected")
            if scen and isinstance(scen, str) and isinstance(pol, str):
                key = (pol, scen)
                if key in scenario_expected_map:
                    prev_exp, prev_file = scenario_expected_map[key]
                    if exp != prev_exp:
                        errors.append(
                            f"Scenario '{pol}/{scen}' has conflicting 'expected' values: '{prev_exp}' ({prev_file}) vs '{exp}' ({rel_path})."
                        )
                else:
                    scenario_expected_map[key] = (exp, rel_path)

            if not errors:
                consumed_files.append((rel_path, file_path, data, sha256))

    if errors:
        msg = "Validation errors found in results:\n" + "\n".join(f"  - {e}" for e in errors)
        raise ValueError(msg)

    all_systems = list(SYSTEMS) + sorted(extra_systems)
    return consumed_files, all_systems


def compute_verdict(dim: str, dim_row: Dict[str, Dict[str, Any]], systems: List[str]) -> str:
    """Compute the distinct-layer verdict for a dimension."""
    prism_grade = dim_row["prismpath"]["grade"]
    comparators = [s for s in systems if s != "prismpath"]

    if dim.startswith("A"):
        if prism_grade != "NATIVE":
            return "OPEN"
        if any(dim_row[comp]["grade"] == "UNTESTED" for comp in comparators):
            return "OPEN"
        if any(dim_row[comp]["grade"] in ("NATIVE", "WITH-WORK") for comp in comparators):
            return "NOT-DISTINCT"
        return "DISTINCT"
    else:
        comparator_grades = [dim_row[comp]["grade"] for comp in comparators]
        if prism_grade in ("WITH-WORK", "NOT") and any(g == "NATIVE" for g in comparator_grades):
            return "LOSES"
        if prism_grade == "NOT" and any(g in ("NATIVE", "WITH-WORK") for g in comparator_grades):
            return "LOSES"
        if prism_grade == "UNTESTED" or any(g == "UNTESTED" for g in comparator_grades):
            return "OPEN"
        return "HOLDS"


def build_matrix(results_dir: str | Path) -> Dict[str, Any]:
    """Build layer comparison matrix data structure from results_dir."""
    results_path = Path(results_dir)
    consumed_files, systems = validate_and_load_results(results_path)

    cells_files: Dict[Tuple[str, str], List[Tuple[str, Dict[str, Any], str]]] = {}
    for rel_path, file_path, data, sha256 in consumed_files:
        key = (data["dimension"], data["system"])
        cells_files.setdefault(key, []).append((rel_path, data, sha256))

    matrix: Dict[str, Dict[str, Dict[str, Any]]] = {}
    verdicts: Dict[str, str] = {}
    generated_from_map: Dict[str, str] = {}

    for rel_path, _, _, sha256 in consumed_files:
        generated_from_map[rel_path] = sha256

    generated_from = [
        {"path": rel_path, "sha256": sha256}
        for rel_path, sha256 in sorted(generated_from_map.items())
    ]

    for dim in DIMENSIONS:
        matrix[dim] = {}
        for sys_id in systems:
            cell_data = cells_files.get((dim, sys_id), [])
            if not cell_data:
                matrix[dim][sys_id] = {
                    "grade": "UNTESTED",
                    "counts": {"NATIVE": 0, "WITH-WORK": 0, "NOT": 0},
                    "mismatches": 0,
                    "files": []
                }
            else:
                grades = [d["grade"] for _, d, _ in cell_data]
                min_rank = min(GRADE_ORDER[g] for g in grades)
                cell_grade = [g for g, r in GRADE_ORDER.items() if r == min_rank][0]

                counts = {
                    "NATIVE": grades.count("NATIVE"),
                    "WITH-WORK": grades.count("WITH-WORK"),
                    "NOT": grades.count("NOT")
                }
                mismatches = sum(1 for _, d, _ in cell_data if d.get("match") is False)
                file_paths = sorted(rel_path for rel_path, _, _ in cell_data)

                matrix[dim][sys_id] = {
                    "grade": cell_grade,
                    "counts": counts,
                    "mismatches": mismatches,
                    "files": file_paths
                }

        verdicts[dim] = compute_verdict(dim, matrix[dim], systems)

    return {
        "systems": systems,
        "dimensions": list(DIMENSIONS),
        "matrix": matrix,
        "verdicts": verdicts,
        "generated_from": generated_from
    }


def generate_markdown(matrix_data: Dict[str, Any]) -> str:
    """Generate Markdown comparison matrix representation."""
    systems = matrix_data["systems"]
    dimensions = matrix_data["dimensions"]
    matrix = matrix_data["matrix"]
    verdicts = matrix_data["verdicts"]

    headers = ["Dimension", "Verdict"] + systems
    header_row = "| " + " | ".join(headers) + " |"
    divider_row = "| " + " | ".join(["---"] * len(headers)) + " |"

    rows = [header_row, divider_row]
    all_files: List[str] = []

    for dim in dimensions:
        row_cells = [dim, verdicts[dim]]
        for sys_id in systems:
            cell = matrix[dim][sys_id]
            grade = cell["grade"]
            if grade == "UNTESTED":
                row_cells.append("UNTESTED")
            else:
                counts = cell["counts"]
                cell_str = f"{grade} (N:{counts['NATIVE']}, W:{counts['WITH-WORK']}, X:{counts['NOT']})"
                if cell["mismatches"] > 0:
                    cell_str += f" [mm:{cell['mismatches']}]"
                row_cells.append(cell_str)
            for fpath in cell.get("files", []):
                all_files.append(fpath)

        rows.append("| " + " | ".join(row_cells) + " |")

    lines = ["# Comparison Matrix", "", "\n".join(rows), "", "## Evidence Files"]
    if all_files:
        lines.append("")
        for fpath in sorted(set(all_files)):
            lines.append(f"- `{fpath}`")
    else:
        lines.append("")
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI main entry point."""
    parser = argparse.ArgumentParser(description="Generate layer comparison matrix")
    default_base = Path(__file__).resolve().parent
    parser.add_argument(
        "--results",
        default=str(default_base / "results"),
        help="Path to results directory"
    )
    parser.add_argument(
        "--out",
        default=str(default_base),
        help="Output directory for MATRIX.md and matrix.json"
    )

    args = parser.parse_args(argv)

    results_dir = Path(args.results)
    out_dir = Path(args.out)

    try:
        matrix_data = build_matrix(results_dir)
    except ValueError as err:
        sys.stderr.write(f"{err}\n")
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "matrix.json"
    md_path = out_dir / "MATRIX.md"

    json_content = json.dumps(matrix_data, indent=2, sort_keys=True) + "\n"
    md_content = generate_markdown(matrix_data)

    json_path.write_text(json_content, encoding="utf-8")
    md_path.write_text(md_content, encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
