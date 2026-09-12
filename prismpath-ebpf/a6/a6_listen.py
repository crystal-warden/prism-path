# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A6 listener on the kernel host: a socket above the stack that only reads. Each packet was decided by the XDP program on
the NIC path, which rewrote node_idx to the verdict. The trailer the sender appended (after the registers) carries the
sender's sequence and the verdict the relay reached, so agreement is measured here with no application in the decision.
usage: a6_listen.py PORT names.json LOG"""
import socket, struct, sys, json, time, signal
port, names_path, log_path = int(sys.argv[1]), sys.argv[2], sys.argv[3]; names = json.load(open(names_path))["names"]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", port)); s.settimeout(1.0)
log = open(log_path, "a"); agree = 0; disagree = 0; undecided = 0; odd = 0; t0 = time.time(); stop = False
def fin(*a):
    global stop; stop = True
signal.signal(signal.SIGTERM, fin); signal.signal(signal.SIGINT, fin)
log.write(f"# a6 listener on {port} started {time.strftime('%H:%M:%S')}\n"); log.flush()
while not stop:
    try: pkt, addr = s.recvfrom(2048)
    except socket.timeout: continue
    if len(pkt) < 12: odd += 1; log.write(f"odd short {len(pkt)} B\n"); continue
    magic, node_idx, n_fields = struct.unpack_from("<III", pkt, 0)
    trailer = pkt[12 + 8 * n_fields:] if n_fields < 64 else b""
    seq, relay_ix, tag = struct.unpack_from("<IIB", trailer, 0) if len(trailer) >= 9 else (None, None, None)
    if tag is None and node_idx == 0xFFFFFFFE: undecided += 1; log.write(f"truncated packet ({len(pkt)} B, claims {n_fields} fields): kernel refused-short\n"); log.flush(); continue
    if magic != 0x4D545050:
        odd += 1; log.write(f"not a PPT packet (magic {magic:#x}): passed untouched, undecided, {len(pkt)} B\n"); log.flush(); continue
    kernel = names[node_idx] if node_idx < len(names) else ("no-match" if node_idx == 0xFFFFFFFF else "refused-short" if node_idx == 0xFFFFFFFE else f"?{node_idx}")
    relay = names[relay_ix] if relay_ix is not None and relay_ix < len(names) else "?"
    if tag == 1:   # a deliberately malformed sender packet (n_fields 0 or truncated registers)
        undecided += 1 if kernel in ("no-match", "refused-short") else 0; log.write(f"seq {seq} malformed by design (n_fields {n_fields}, {len(pkt)} B): kernel {kernel}\n"); log.flush(); continue
    if kernel == relay: agree += 1
    else: disagree += 1
    log.write(f"seq {seq} kernel {kernel} relay {relay} {'AGREE' if kernel == relay else 'DISAGREE'}\n"); log.flush()
log.write(f"# summary: agree {agree}, disagree {disagree}, malformed decided no-match {undecided}, not PPT {odd}, {time.time() - t0:.0f} s\n"); log.close()
print(f"agree {agree} disagree {disagree} undecided {undecided} odd {odd}")
