# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath compile`: a flow and its lock as a single file JavaScript bundle.

The bundle inlines the standalone JavaScript kernel (portable/prismpath.mjs) and its engine
(portable/bundle_engine.mjs), which only the research repository carries. The product repository is
generated from this one without this module and without those files, and prismpath.cli registers
`compile` as withdrawn there (it exits 2 with a message) because it cannot import this module.
"""
import json
import os


def _gather_compile_inputs(flow_md_path: str, target_tier: str):
    """Gather and validate inputs for compiling a JS bundle."""
    from prismpath.kernel.parser import parse_file
    from prismpath import flow_files
    from prismpath.routing import lockfile
    import base64

    parsed_graph = parse_file(flow_md_path)
    tier_tree = flow_files.portability_tier_tree(parsed_graph, flow_md_path)
    flow_tier = tier_tree["tier"]

    if target_tier == "p0" and flow_tier != "P0":
        print(f"✗ Flow is not P0 (current tier: {flow_tier}). It has semantic edges. "
              f"Please rewrite them as deterministic 'when' predicates to compile for P0, "
              f"or compile for P1.")
        return None

    if target_tier == "p1" and flow_tier == "P2":
        print(f"✗ Flow has unlocked semantic edges (current tier: P2). "
              f"Please run `prismpath lock {flow_md_path}` first to commit routing vectors, "
              f"or rewrite them to compile for P0.")
        return None

    embedded_lock_js = "null"
    lock_data = {}
    compressed_conditions = {}
    if target_tier == "p1":
        import numpy as numpy_module
        lock_file_path = lockfile.lock_path(flow_md_path)
        if not os.path.exists(lock_file_path):
            print(f"✗ Lockfile missing: {lock_file_path}. Please run `prismpath lock {flow_md_path}` first.")
            return None
        try:
            lock_data = lockfile.load_lock(lock_file_path)
        except Exception as lock_exception:
            print(f"✗ Failed to load lockfile {lock_file_path}: {lock_exception}")
            return None

        for condition_str, f32_b64 in lock_data.get("conditions", {}).items():
            f32_bytes = base64.b64decode(f32_b64)
            array_f32 = numpy_module.frombuffer(f32_bytes, dtype="<f4").astype(numpy_module.float32)
            array_f16 = array_f32.astype(numpy_module.float16)
            compressed_conditions[condition_str] = base64.b64encode(array_f16.tobytes()).decode("ascii")

        embedded_lock_js = json.dumps({
            "delta": lock_data.get("delta", 0.05),
            "conditions": compressed_conditions
        }, indent=2)

    package_directory = os.path.dirname(os.path.abspath(__file__))
    kernel_path = os.path.join(package_directory, "portable", "prismpath.mjs")
    try:
        with open(kernel_path, "r", encoding="utf-8") as file_handle:
            js_kernel = file_handle.read()
    except Exception as file_exception:
        print(f"✗ Failed to read JS kernel from {kernel_path}: {file_exception}")
        return None

    nodes_dict = {}
    for node_name, node_obj in parsed_graph.nodes.items():
        nodes_dict[node_name] = {
            "name": node_name,
            "instruction": node_obj.instruction,
            "terminal": node_obj.terminal,
            "annotations": node_obj.annotations,
            "edges": node_obj.edges
        }
    parsed_graph_js = json.dumps({
        "name": parsed_graph.name,
        "start": parsed_graph.start,
        "nodes": nodes_dict
    }, indent=2)

    lock_info = {
        "lock_data": lock_data,
        "compressed_conditions": compressed_conditions
    }
    return js_kernel, parsed_graph_js, embedded_lock_js, lock_info


BUNDLE_ENGINE_FILE = "bundle_engine.mjs"
# The engine source is a real module that imports the kernel; the bundle inlines the kernel instead,
# so the import between these markers is dropped on the way in. The markers are the whole contract
# between the compiler here and portable/bundle_engine.mjs (test_compile asserts both sides of it).
BUNDLE_STRIP_BEGIN = "// prismpath-bundle-strip-begin"
BUNDLE_STRIP_END = "// prismpath-bundle-strip-end"


def _read_bundle_engine() -> str:
    """Read portable/bundle_engine.mjs and drop the import of the kernel the bundle inlines."""
    engine_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "portable", BUNDLE_ENGINE_FILE)
    with open(engine_path, "r", encoding="utf-8") as file_handle:
        engine_source = file_handle.read()
    begin_index = engine_source.find(BUNDLE_STRIP_BEGIN)
    end_index = engine_source.find(BUNDLE_STRIP_END)
    if begin_index < 0 or end_index < begin_index:
        raise RuntimeError(f"{engine_path} is missing its bundle strip markers")
    end_of_line = engine_source.find("\n", end_index)
    return engine_source[:begin_index] + engine_source[end_of_line + 1:]


def _build_compile_bundle(target_tier: str, js_kernel: str, parsed_graph_js: str, embedded_lock_js: str) -> str:
    """Assemble the standalone JS bundle containing kernel and serialized graph."""
    bundle_parts = []
    bundle_parts.append(f"// Auto-generated by prismpath compile --tier {target_tier}")
    bundle_parts.append("// Single-file portable JS bundle ready for Node/Browser.\n")
    bundle_parts.append(js_kernel)
    bundle_parts.append(f"\nexport const GRAPH = {parsed_graph_js};\n")
    bundle_parts.append(f"export const EMBEDDED_LOCK = {embedded_lock_js};\n")

    bundle_parts.append(_read_bundle_engine())
    # The engine takes the graph and the lock as arguments, so the bundle binds its own to the
    # runFlow(agent, opts) entry point that compiled bundles have always exported.
    bundle_parts.append(
        "\nexport function runFlow(agent, opts = {}) {\n"
        "  return runCompiled(GRAPH, EMBEDDED_LOCK, agent, opts);\n"
        "}\n")
    return "\n".join(bundle_parts)


def _b64_decoded_size(vector_b64: str) -> int:
    """The number of bytes a base64 payload decodes to, exactly. Three quarters of the encoded
    length counts the padding as data, which is what turned the compile report's KB figure into an
    estimate printed as a measurement."""
    text = vector_b64.strip()
    return len(text) * 3 // 4 - text.count("=")


def _write_compile_output(out_path: str, bundle_code: str, flow_md_path: str, target_tier: str, lock_info: dict) -> int:
    """Write the compiled bundle code to disk and print status feedback."""
    with open(out_path, "w", encoding="utf-8") as file_handle:
        file_handle.write(bundle_code)

    f32_size = 0
    f16_size = 0
    if target_tier == "p1":
        lock_data = lock_info.get("lock_data", {})
        compressed_conditions = lock_info.get("compressed_conditions", {})
        f32_size = sum(_b64_decoded_size(vector_b64) for vector_b64 in lock_data.get("conditions", {}).values())
        f16_size = sum(_b64_decoded_size(vector_b64) for vector_b64 in compressed_conditions.values())

    saving_message = f" (lock vectors compressed f32 -> f16: {f32_size/1024:.1f}KB -> {f16_size/1024:.1f}KB)" if target_tier == "p1" else ""
    print(f"✓ compiled {flow_md_path} to {out_path}{saving_message}")
    return 0


def compile_cmd(args) -> int:
    """Compile the flow and its lock into a single-file portable JS bundle."""
    gathered_inputs = _gather_compile_inputs(args.flow_md, args.tier)
    if gathered_inputs is None:
        return 1
    js_kernel, parsed_graph_js, embedded_lock_js, lock_info = gathered_inputs
    bundle_code = _build_compile_bundle(args.tier, js_kernel, parsed_graph_js, embedded_lock_js)
    out_path = args.out or (os.path.splitext(args.flow_md)[0] + ".bundle.mjs")
    return _write_compile_output(out_path, bundle_code, args.flow_md, args.tier, lock_info)
