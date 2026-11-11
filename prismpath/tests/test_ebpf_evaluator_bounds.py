# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The eBPF evaluator at its bounds, and the compiled objects against the verifier limits, with no kernel.

The kernel job loads each object under the real verifier and replays the boundary corpus
(`cert_corpus.py --boundary`); this runs what can run unprivileged. The evaluator's own text
(ppt_eval_bpf.h) is compiled natively against the harness's shim of the three BPF facilities it uses
(formal/diff/ebpf_batch.c) and given every boundary table: an operand stack at depth 25, 63 and 64, programs
of 33, 2,000 and 4,000 words, and a node of 200 edges. Each answer is held to an RPN evaluation written
independently in cert_corpus.py. The objects clang builds from the same header are then held to the stack,
loop and shape limits verifier_budget.py models.
"""
import importlib.util
import os
import shutil
import subprocess
import sys

import pytest

from prismpath.tests._repo import repo_file

_ebpf = repo_file("prismpath-ebpf")
repo_file("prismpath-ebpf", "ppt_common.h")
_batch = repo_file("formal", "diff", "ebpf_batch.c")
sys.path.insert(0, str(repo_file("prismpath-hw")))
sys.path.insert(0, str(_ebpf))
import ppt_compile as pc  # noqa: E402


def _load(name):
    spec = importlib.util.spec_from_file_location(name, _ebpf / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("cert_corpus")
budget = _load("verifier_budget")


@pytest.fixture(scope="module")
def batch(tmp_path_factory):
    cc = shutil.which("cc")
    if not cc:
        pytest.skip("no C compiler")
    out = tmp_path_factory.mktemp("ebpf_batch") / "ebpf_batch"
    subprocess.run([cc, "-O2", "-std=gnu11", "-Wno-unknown-pragmas", "-I", str(_ebpf), "-o", str(out), str(_batch),
                    str(_ebpf / "ppt_image.c")], check=True)
    return out


def test_the_evaluator_routes_every_boundary_table_as_the_reference_does(batch):
    cases = corpus.boundary_images()
    data = bytearray()
    for index, (_name, image, ctx, _expected) in enumerate(cases):
        blob = image.serialize()
        regs = pc.encode_regs(image, ctx, node_idx=0)
        data += f"case {index} 1\n{len(blob)}\n".encode() + blob + b"\n" + f"{len(regs)}\n".encode() + regs + b"\n"
    result = subprocess.run([str(batch)], input=bytes(data), capture_output=True, check=True)
    answers = dict(line.split(" ", 1) for line in result.stdout.decode().splitlines())
    for index, (name, _image, _ctx, expected) in enumerate(cases):
        answer = answers[str(index)].split()
        got = int(answer[2]) if answer[0] == "m" else -1
        assert got == expected, f"{name}: the evaluator answered {answers[str(index)]}, expected target {expected}"


def test_a_cycle_in_the_control_flow_is_found_and_a_shared_tail_is_not():
    loop = [[0, "r1 = 0x0", None], [1, "r1 += 0x1", None], [2, "if r1 < 0x9 goto -0x2 <L>", None], [3, "exit", None]]
    tail = [[0, "if r1 == 0x0 goto +0x2 <L>", None], [1, "r0 = 0x1", None], [2, "goto +0x3 <M>", None],
            [3, "r0 = 0x2", None], [4, "goto -0x3 <K>", None], [5, "exit", None]]
    assert budget.has_cycle(loop)
    assert not budget.has_cycle(tail)


@pytest.mark.parametrize("name", ["ppt_xdp", "ppt_net", "ppt_select", "a6/ppt_xdp", "facet_decode"])
def test_a_built_object_is_within_the_modelled_verifier_limits(name):
    obj = _ebpf / f"{name}.bpf.o"
    if not obj.exists() or not (shutil.which("llvm-objdump") or os.environ.get("LLVM_OBJDUMP")):
        pytest.skip("the eBPF objects are not built here (make -C prismpath-ebpf)")
    assert budget.refusals(obj) == []
