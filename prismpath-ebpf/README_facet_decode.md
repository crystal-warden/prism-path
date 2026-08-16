# The kernel decode plane: XDP decode-and-rewrite (facet_decode)

`facet_decode.bpf.c` is an XDP program that makes any Linux box Facet-capable with zero
application changes. A UDP datagram to port 4711 carrying one byte-aligned Facet frame is decoded
in kernel (self-delimiting Zeckendorf, policy independent) and its payload REWRITTEN in place to
`[ 'F' ][ u8 count ][ u16le wire_int * count ]`, then XDP_PASSed: an ordinary UDP socket
application reads decoded cell values and never knows Facet existed.

Strict contract in kernel, verified: a structurally malformed frame (truncated codeword, symbol
overflow, empty) is XDP_DROP, counted in the `facet_stats` map, never a wrong event. Single-bit
corruption that stays a syntactically valid Fibonacci stream decodes to a different valid value
and is NOT caught here — detecting that is the upstream Merkle integrity layer's job, out of the
decode plane's scope by design.

Verifier notes (the bring-up findings, each a real eBPF sharp edge):
- Payload length comes from the UDP header (a scalar), not pointer subtraction, so the verifier
  keeps it bounded rather than pointer-derived.
- The per-bit decode runs under `bpf_loop` (kernel 5.17+, the documented floor): the callback is
  verified once, so the program stays in the instruction budget regardless of frame length. A
  fully-unrolled FSM blows the 1M-instruction limit.
- The payload is copied off the packet with `bpf_xdp_load_bytes` into a stack buffer first;
  packet pointers cannot cross a bpf_loop callback boundary.
- Fibonacci values are advanced incrementally (fa, fb) rather than read from a `.rodata` table:
  a const global array does NOT resolve correctly when read inside the bpf_loop callback
  subprogram (it silently returned the wrong element — caught by the conformance corpus).

Certify (root): `sudo python facet_decode_cert.py` — 250 reference-generated frames byte-identical
in kernel via BPF_PROG_TEST_RUN, plus a negative matrix (truncated, overflow, dangling, empty ->
DROP). v1 handles frames up to 32 bytes / 16 fields; larger frames fall to the userspace decoder.
