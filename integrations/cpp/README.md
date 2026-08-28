# Embedding PrismPath in C++

The certified C11 interpreter (`prismpath-hw/interp.c`, the C target certified against the
frozen conformance vectors and the 4568-event hysteresis sequence oracle) compiles into a C++
application unmodified: `interp.h` exposes a small extern "C" API over the identical certified
code paths, and `PPT_INTERP_NO_MAIN` omits the CLI entry point. The RAII wrapper in
`example.cpp` is about forty lines; that is the whole integration.

What makes the port provable rather than plausible is the replay. `gen_fixture.py` runs the
certified CLI over every event of the frozen sequence oracle and records its verdicts (the
generation step itself re-certifies the build against the oracle); `ppt_replay` then evaluates
the same events in-process through the embedded API and must agree on every one:

```bash
make -C ../../prismpath-hw cert
python3 gen_fixture.py
mkdir -p build && cd build && cmake .. && make
./ppt_replay ../../../prismpath-hw/demo/flows/hyst_band.ppt ../hyst_fixture.bin
```

Passing output is `EMBED PROOF PASS: 4568/4568 events byte-identical to the certified CLI`.
The fixture is committed, so the last two commands alone reproduce the proof; the first two
regenerate it from source. The policy under replay is the resident-FSM hysteresis band
controller, the same signed policy certified on FPGA silicon (evidence ledger row #123), so a
C++ host evaluating it in-process is running a table image whose behavior is pinned by the
same oracle across Python, C, kernel eBPF, and fabric.

## Scope, stated honestly

This embeds the **evaluator**. Signature and envelope verification run upstream in the pack
loader (`policy_pack`), and an embedding application keeps that boundary: verify the signed
pack, then hand the verified image path to `ppt_image_open`. A malformed or truncated image
exits(2) with a diagnostic, which is the certified CLI's contract, deliberately unchanged; if
your host cannot tolerate exit-on-bad-image, gate loading behind the upstream verifier, which
is where rejection belongs. In this policy the deadband holds ride explicit self-edges, so the
no-match path (`std::nullopt`, a clean hold for stateful policies) exists in the API but is
not exercised by this corpus. The wrapper is single-threaded per image handle; share-nothing
across threads or add your own synchronization.
