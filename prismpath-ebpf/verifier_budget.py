#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Check a compiled eBPF object against the verifier limits this repo already models, with no kernel.

The kernel certification (`ebpf_kernel` in CI) loads each object under the real verifier, which needs
CAP_BPF. This reads the same object offline and refuses what the verifier is known to refuse, so a change
to ppt_eval_bpf.h that cannot load fails the unprivileged build job as well as the privileged one:

  * stack: the combined stack of the deepest call chain, each frame rounded up to 32 bytes as the kernel
    rounds it, within 512 bytes (README section 4.1: "combined stack size ... Too large"). A bpf_loop
    callback is a frame of its caller's chain, so the walk follows pointers to callbacks as well as calls;
  * loops: no cycle in the control flow of the evaluator (evaluate, edge_loop_cb, prog_word_cb). Its
    loops are bpf_loop() callbacks verified once, so a cycle there is a loop the verifier would unroll
    state by state (README section 4.1). A backward jump alone is not a loop, since the compiler lays a
    shared tail out behind its users, so the control flow graph is searched for a cycle instead. The
    programs around the evaluator keep their own bounded loops and are not held to this;
  * the evaluator's shape: an object that carries evaluate() carries edge_loop_cb and prog_word_cb too,
    reached through bpf_loop, and no recursion in the call graph;
  * size: no more instructions than the verifier's static limit of one million.

What it cannot model is the processed instruction count (the 1M budget over verified paths) and the
JIT: those stay with the kernel job. The static instruction count of each function is printed so a change
that grows the evaluator shows its size here before the kernel job shows its cost.

    python verifier_budget.py OBJECT.bpf.o [...]     exit 1 if any object is refused
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set

STACK_LIMIT = 512
FRAME_ROUND = 32
INSN_LIMIT = 1_000_000
HELPER_BPF_LOOP = 0xb5          # 181
EVALUATOR_FUNCTIONS = ("evaluate", "edge_loop_cb", "prog_word_cb")

FUNCTION = re.compile(r"^([0-9a-f]+) <([A-Za-z_][\w.]*)>:$")
LABEL = re.compile(r"^(LBB|LBL)\d")
INSN = re.compile(r"^\s*(\d+):\s+(.*)$")
STACK = re.compile(r"\br10 ([+-]) (0x[0-9a-f]+|\d+)")
BRANCH = re.compile(r"goto ([+-])(0x[0-9a-f]+|\d+)")
CALL = re.compile(r"^call (-?(?:0x)?[0-9a-f]+)$")
RELOC = re.compile(r"R_BPF_64_(?:32|64)\s+(\S+)")
PTR = re.compile(r"= (0x[0-9a-f]+) ll$")


def objdump() -> str:
    """LLVM_OBJDUMP, else llvm-objdump, else the newest versioned llvm-objdump-N on the path."""
    named = os.environ.get("LLVM_OBJDUMP") or shutil.which("llvm-objdump")
    if named:
        return named
    for version in range(30, 12, -1):
        found = shutil.which(f"llvm-objdump-{version}")
        if found:
            return found
    raise SystemExit("verifier_budget: no llvm-objdump on the path (install llvm, or set LLVM_OBJDUMP)")


def disassemble(path: Path) -> str:
    return subprocess.run([objdump(), "-dr", "--no-show-raw-insn", str(path)], capture_output=True,
                          text=True, check=True).stdout


def parse(text: str):
    """{section: {function: {"insns": [...], "start": byte offset}}} with each instruction as
    (index, text, relocation symbol or None)."""
    sections: Dict[str, Dict[str, dict]] = {}
    section = function = None
    for line in text.splitlines():
        if line.startswith("Disassembly of section "):
            section = line.split()[-1].rstrip(":")
            sections[section] = {}
            function = None
            continue
        found = FUNCTION.match(line.strip())
        if found and section is not None:
            if LABEL.match(found.group(2)):
                continue                      # a basic block label, not a function
            function = {"insns": [], "start": int(found.group(1), 16)}
            sections[section][found.group(2)] = function
            continue
        found = INSN.match(line)
        if found and function is not None:
            function["insns"].append([int(found.group(1)), found.group(2).strip(), None])
            continue
        found = RELOC.search(line)
        if found and function is not None and function["insns"]:
            function["insns"][-1][2] = found.group(1)
    return sections


def own_stack(insns) -> int:
    """The deepest r10 relative byte any instruction names, which is the function's own frame."""
    depth = 0
    for _index, text, _reloc in insns:
        for sign, amount in STACK.findall(text):
            if sign == "-":
                depth = max(depth, int(amount, 0))
    return depth


def has_cycle(insns) -> bool:
    """Whether the function's control flow graph, instruction by instruction, contains a cycle."""
    slots = [entry[0] for entry in insns]
    successors: Dict[int, List[int]] = {}
    for position, (index, text, _reloc) in enumerate(insns):
        following = [slots[position + 1]] if position + 1 < len(slots) else []
        branch = BRANCH.search(text)
        targets = []
        if branch:
            offset = int(branch.group(2), 0) * (-1 if branch.group(1) == "-" else 1)
            targets = [index + 1 + offset]
        if text == "exit":
            following = []
        elif text.startswith("goto "):
            following = []
        successors[index] = [slot for slot in following + targets if slot in successors or slot in slots]
    colour: Dict[int, int] = {}
    for root in slots:
        if root in colour:
            continue
        colour[root] = 1
        walk = [(root, iter(successors[root]))]
        while walk:
            node, remaining = walk[-1]
            for nxt in remaining:
                if colour.get(nxt) == 1:
                    return True
                if nxt not in colour:
                    colour[nxt] = 1
                    walk.append((nxt, iter(successors[nxt])))
                    break
            else:
                colour[node] = 2
                walk.pop()
    return False


def callees(name: str, section: str, sections, insns) -> Set[str]:
    """The functions this one calls or hands to bpf_loop, resolved through the .text relocations."""
    text_functions = {entry["start"]: fname for fname, entry in sections.get(".text", {}).items()}
    found: Set[str] = set()
    for _index, text, reloc in insns:
        call = CALL.match(text)
        if call and reloc == ".text":
            offset = (int(call.group(1), 0) + 1) * 8        # a pc relative call into the .text section
            hit = text_functions.get(offset)
            if hit:
                found.add(hit)
        pointer = PTR.search(text)
        if pointer and reloc == ".text":
            hit = text_functions.get(int(pointer.group(1), 0))   # a callback pointer for bpf_loop
            if hit:
                found.add(hit)
    return found


def refusals(path: Path) -> List[str]:
    sections = parse(disassemble(path))
    refused: List[str] = []
    total = sum(len(entry["insns"]) for functions in sections.values() for entry in functions.values())
    if total > INSN_LIMIT:
        refused.append(f"{total} instructions, past the verifier's {INSN_LIMIT}")
    graph, frames = {}, {}
    for section, functions in sections.items():
        for name, entry in functions.items():
            graph[name if section == ".text" else f"{section}:{name}"] = callees(name, section, sections, entry["insns"])
            frames[name if section == ".text" else f"{section}:{name}"] = \
                -(-max(own_stack(entry["insns"]), 1) // FRAME_ROUND) * FRAME_ROUND
            if section == ".text" and name in EVALUATOR_FUNCTIONS and has_cycle(entry["insns"]):
                refused.append(f"{name} has a cycle in its control flow: a loop outside bpf_loop")
    memo: Dict[str, int] = {}

    def depth(node: str, trail: tuple) -> int:
        if node in trail:
            refused.append(f"{node} is recursive")
            return 0
        if node not in memo:
            memo[node] = frames[node] + max((depth(callee, trail + (node,)) for callee in graph.get(node, ())), default=0)
        return memo[node]

    for node in sorted(graph):
        if depth(node, ()) > STACK_LIMIT:
            refused.append(f"{node} reaches a combined stack of {memo[node]} bytes, past {STACK_LIMIT}")
    text_names = set(sections.get(".text", {}))
    if "evaluate" in text_names:
        for needed in EVALUATOR_FUNCTIONS:
            if needed not in text_names:
                refused.append(f"the object carries evaluate() but not {needed}")
        loop_calls = sum(1 for entry in sections[".text"].values() for _i, text, _r in entry["insns"]
                         if text == f"call {HELPER_BPF_LOOP:#x}")
        if loop_calls < 2:
            refused.append(f"the evaluator calls bpf_loop {loop_calls} times, not once for edges and once for words")
    return refused


def report(path: Path) -> List[str]:
    sections = parse(disassemble(path))
    lines = []
    for section, functions in sections.items():
        for name, entry in functions.items():
            lines.append(f"    {section}:{name} {len(entry['insns'])} insns, frame {own_stack(entry['insns'])} bytes")
    return lines


def main(argv: List[str]) -> int:
    if not argv:
        print(__doc__.strip().splitlines()[-1].strip())
        return 2
    failed = 0
    for argument in argv:
        path = Path(argument)
        problems = refusals(path)
        print(("REFUSED " if problems else "ok      ") + argument)
        for line in report(path):
            print(line)
        for problem in problems:
            print(f"  {problem}")
        failed += bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
