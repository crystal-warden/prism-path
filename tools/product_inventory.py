# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The inventory and its lock: what may be in the product, and what is.

tools/inventory.toml holds the rules. A rule is `ship` or `hold`, has a purpose, an owner (`research`
for adopted copies, `product` for product authored files), and matches either one exact `path` or
every path under a `prefix`. A hold rule names a research area that must never enter the product.

tools/inventory.lock enumerates every classified product path with the rule that classified it, the
research source path it was adopted from, that source's git blob id, and the research revision the
path was last adopted from (all three empty for product authored files). The revision is per path
because a promotion may take one component and leave another, so no single revision describes the
tree; [meta] adopted_revision in the inventory is the seed revision. The lock, not the rules, is the review gate: a tracked path that
is absent from the lock is unclassified even when a rule matches it, so a new file is always seen and
acknowledged in a reviewed lock update before it counts as classified. That is why a broad hold or
ship prefix cannot absorb a new file silently.

    python -m tools.product_inventory check          # every tracked path classified and locked
    python -m tools.product_inventory unclassified   # list what a lock update would have to add
    python -m tools.product_inventory update-lock    # add unclassified paths under their matching rule
"""
from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY_PATH = REPO_ROOT / "tools" / "inventory.toml"
LOCK_PATH = REPO_ROOT / "tools" / "inventory.lock"
LOCK_FIELDS = ("path", "rule", "source_path", "source_blob", "adopted_revision")


@dataclass(frozen=True)
class Rule:
    identifier: str
    kind: str            # ship or hold
    purpose: str
    owner: str           # research or product
    path: str | None
    prefix: str | None
    source_prefix: str | None
    reason: str

    def matches(self, repo_path: str) -> bool:
        if self.path is not None:
            return repo_path == self.path
        return repo_path.startswith(self.prefix or "\0")


def load_rules(inventory_path: Path = INVENTORY_PATH) -> list[Rule]:
    document = tomllib.loads(inventory_path.read_text(encoding="utf-8"))
    rules = []
    for entry in document.get("rule", []):
        if entry.get("kind") not in ("ship", "hold"):
            raise ValueError(f"rule {entry.get('id')!r}: kind must be ship or hold")
        if bool(entry.get("path")) == bool(entry.get("prefix")):
            raise ValueError(f"rule {entry.get('id')!r}: exactly one of path or prefix")
        rules.append(Rule(entry["id"], entry["kind"], entry.get("purpose", ""), entry.get("owner", "research"),
                          entry.get("path"), entry.get("prefix"), entry.get("source_prefix"), entry.get("reason", "")))
    identifiers = [rule.identifier for rule in rules]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate rule id in the inventory")
    return rules


def adopted_revision(inventory_path: Path = INVENTORY_PATH) -> str:
    return tomllib.loads(inventory_path.read_text(encoding="utf-8"))["meta"]["adopted_revision"]


def classify(repo_path: str, rules: list[Rule]) -> Rule | None:
    """The single rule that matches, exact paths before prefixes and longer prefixes before shorter
    ones, so a narrow rule inside a broad one wins. None when nothing matches."""
    exact = [rule for rule in rules if rule.path == repo_path]
    if exact:
        return exact[0]
    by_prefix = [rule for rule in rules if rule.prefix and repo_path.startswith(rule.prefix)]
    if not by_prefix:
        return None
    return max(by_prefix, key=lambda rule: len(rule.prefix or ""))


def load_lock(lock_path: Path = LOCK_PATH) -> dict[str, dict[str, str]]:
    entries = {}
    with lock_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != LOCK_FIELDS:
            raise ValueError(f"{lock_path}: header must be {LOCK_FIELDS}")
        for row in reader:
            if row["path"] in entries:
                raise ValueError(f"{lock_path}: {row['path']} listed twice")
            entries[row["path"]] = row
    return entries


def write_lock(entries: dict[str, dict[str, str]], lock_path: Path = LOCK_PATH) -> None:
    with lock_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LOCK_FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        for path in sorted(entries):
            writer.writerow({field: entries[path].get(field, "") for field in LOCK_FIELDS})


def tracked_paths(repo_root: Path = REPO_ROOT) -> list[str]:
    output = subprocess.check_output(["git", "-C", str(repo_root), "ls-files"], text=True)
    return [line for line in output.splitlines() if line]


def unclassified(paths: list[str], rules: list[Rule], lock: dict[str, dict[str, str]]) -> list[tuple[str, str]]:
    """Every path that is not both matched by a ship rule and listed in the lock, with the reason."""
    findings = []
    for repo_path in paths:
        rule = classify(repo_path, rules)
        if rule is None:
            findings.append((repo_path, "no rule matches"))
        elif rule.kind == "hold":
            findings.append((repo_path, f"matches hold rule {rule.identifier}: {rule.reason}"))
        elif repo_path not in lock:
            findings.append((repo_path, f"matches ship rule {rule.identifier} but is not in the lock"))
        elif lock[repo_path]["rule"] != rule.identifier:
            findings.append((repo_path, f"locked under {lock[repo_path]['rule']} but the inventory says {rule.identifier}"))
    return findings


def stale_lock_entries(paths: list[str], lock: dict[str, dict[str, str]]) -> list[str]:
    present = set(paths)
    return sorted(path for path in lock if path not in present)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["check", "unclassified", "update-lock"])
    parser.add_argument("--repo", default=str(REPO_ROOT), help="the product checkout (default: this one)")
    args = parser.parse_args(argv)
    repo_root = Path(args.repo).resolve()
    rules = load_rules(repo_root / "tools" / "inventory.toml")
    lock_path = repo_root / "tools" / "inventory.lock"
    lock = load_lock(lock_path)
    paths = tracked_paths(repo_root)
    findings = unclassified(paths, rules, lock)
    stale = stale_lock_entries(paths, lock)
    if args.command == "update-lock":
        added = 0
        for repo_path, reason in findings:
            rule = classify(repo_path, rules)
            if rule is None or rule.kind == "hold":
                continue
            lock[repo_path] = {"path": repo_path, "rule": rule.identifier, "source_path": "", "source_blob": "", "adopted_revision": ""}
            added += 1
        for repo_path in stale:
            del lock[repo_path]
        write_lock(lock, lock_path)
        print(f"lock updated: {added} added, {len(stale)} stale entries removed")
        return 0
    for repo_path, reason in findings:
        print(f"unclassified  {repo_path}: {reason}")
    for repo_path in stale:
        print(f"stale lock    {repo_path}: locked but no longer tracked")
    if findings or stale:
        print(f"{len(findings)} unclassified, {len(stale)} stale")
        return 1
    print(f"inventory ok: {len(paths)} tracked paths classified and locked, {len(rules)} rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
