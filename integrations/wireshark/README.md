# Facet Wireshark dissector

`facet.lua` dissects the Facet/1 datagram profile (PROTOCOL.md section 2) in Wireshark and
tshark: UDP port 4711, one byte aligned Facet frame per datagram. It exists so that operators
can see Facet traffic with the tools they already trust, and it is conformance checked against
the reference codec on a committed pcap corpus.

## Scope, stated honestly

The dissector shows wire level structure only. It decodes the self framing Zeckendorf stream to
wire integers and symbol indices, labels the trailing zero pad, and applies the same strict
decode contract the kernel decode plane enforces (`prismpath-ebpf/facet_decode.bpf.c`): a frame
with no terminator, a dangling partial codeword, or a wire integer beyond the u16 cell range is
flagged malformed. What it cannot show is what a symbol means: the codebook is derived from the
signed policy and never travels on the wire (invariant I3), so semantics require the policy, not
the packet. Corruption that stays a syntactically valid stream decodes to a different valid
value here exactly as it does everywhere else; catching that is the Merkle integrity layer's
job. An optional preference accepts comma separated canonical field names purely as viewing
labels.

Two payload forms are recognized. Raw frames are the wire. The decoded form
(`'F'`, u8 count, u16le cells) is the kernel decode plane's local rewrite, present when the
capture point sits behind the XDP hook. Detection is an exact length check, and a raw frame can
collide with it; a colliding frame is dissected as decoded and carries an expert note (frame 18
of the corpus is a deliberate specimen). Capture on the wire side of the XDP hook to see raw
frames.

## Use

One shot, no install:

```bash
tshark -r capture.pcap -X lua_script:facet.lua
```

Install for Wireshark: copy or symlink `facet.lua` into the Wireshark personal plugins folder
(`~/.local/lib/wireshark/plugins/`), then restart. The UDP port and the field name labels are
Wireshark preferences under Protocols, FACET.

Field extraction for scripting:

```bash
tshark -r capture.pcap -X lua_script:facet.lua -T fields \
  -e frame.number -e facet.form -e facet.count -e facet.wireints \
  -e facet.symbols -e facet.padbits -e facet.malformed
```

## Conformance

The committed corpus is `facet_corpus.pcap` (18 frames: positive vectors including the 16 field
kernel cap, the negative matrix mirroring the kernel decode plane cert, both decoded form frames,
and the deliberate heuristic collision) with `facet_corpus.expected.json` computed by the
reference codec plus a strict decode mirror, independent of the Lua. The harness runs tshark
with the dissector over the corpus and compares every frame:

```bash
python3 check_dissector.py
```

Passing output is `18/18 frames match the reference decode`. Frame 11 (empty payload) expects
no dissection: Wireshark's UDP layer never invokes a subdissector for a zero length payload, so
the kernel decode plane is the only observer that sees and drops empties.

Regenerate the corpus (byte identical output, fixed timestamps, no randomness):

```bash
python3 gen_pcap_corpus.py
```
