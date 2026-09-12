# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A6 listener on the kernel host: a socket above the stack that only reads.

Each packet was decided by the XDP program on the NIC path, which rewrote
node_idx to the verdict. The trailer the sender appended (after the registers)
carries the sender sequence and relay verdict for agreement measurement.
usage: a6_listen.py PORT names.json LOG
"""

import json
import signal
import socket
import struct
import sys
import time

from a6_config import PPT_A6_NO_MATCH, PPT_A6_REFUSED_SHORT

stop_requested = False


def handle_signal(*unused_args):
    """Why: handles shutdown signals gracefully without abruptly breaking log writes."""
    global stop_requested
    stop_requested = True


def verdict_name(node_idx, node_names):
    """Why: maps kernel node index sentinels and integers into human readable verdict strings."""
    if node_idx < len(node_names):
        return node_names[node_idx]
    if node_idx == PPT_A6_NO_MATCH:
        return "no-match"
    if node_idx == PPT_A6_REFUSED_SHORT:
        return "refused-short"
    return f"?{node_idx}"


def classify(packet_bytes):
    """Why: extracts header fields and trailer metadata from raw packet datagrams."""
    if len(packet_bytes) < 12:
        return None
    magic_val, node_idx, n_fields = struct.unpack_from("<III", packet_bytes, 0)
    if n_fields < 64:
        trailer_data = packet_bytes[12 + 8 * n_fields :]
    else:
        trailer_data = b""
    if len(trailer_data) >= 9:
        seq_num, relay_ix, packet_tag = struct.unpack_from(
            "<IIB", trailer_data, 0
        )
    else:
        seq_num, relay_ix, packet_tag = None, None, None
    return {
        "magic": magic_val,
        "node_idx": node_idx,
        "n_fields": n_fields,
        "seq": seq_num,
        "relay_ix": relay_ix,
        "tag": packet_tag,
    }


def main():
    """Why: executes the socket listener loop when invoked as a command line tool."""
    global stop_requested
    port_number = int(sys.argv[1])
    names_path = sys.argv[2]
    log_path = sys.argv[3]

    with open(names_path, "r", encoding="utf-8") as names_file:
        names_data = json.load(names_file)
        names = names_data["names"]

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_socket.bind(("0.0.0.0", port_number))
    listen_socket.settimeout(1.0)

    log_file = open(log_path, "a", encoding="utf-8")
    agree_count = 0
    disagree_count = 0
    undecided_count = 0
    odd_count = 0
    start_time = time.time()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    log_file.write(
        f"# a6 listener on {port_number} started {time.strftime('%H:%M:%S')}\n"
    )
    log_file.flush()

    while not stop_requested:
        try:
            packet_bytes, sender_address = listen_socket.recvfrom(2048)
        except socket.timeout:
            continue

        parsed = classify(packet_bytes)
        if parsed is None:
            odd_count += 1
            log_file.write(f"odd short {len(packet_bytes)} B\n")
            continue

        node_idx = parsed["node_idx"]
        n_fields = parsed["n_fields"]
        packet_tag = parsed["tag"]
        seq_num = parsed["seq"]
        relay_ix = parsed["relay_ix"]
        magic_val = parsed["magic"]

        if packet_tag is None and node_idx == PPT_A6_REFUSED_SHORT:
            undecided_count += 1
            log_file.write(
                f"truncated packet ({len(packet_bytes)} B, claims {n_fields} fields): kernel refused-short\n"
            )
            log_file.flush()
            continue

        if magic_val != 0x4D545050:
            odd_count += 1
            log_file.write(
                f"not a PPT packet (magic {magic_val:#x}): passed untouched, undecided, {len(packet_bytes)} B\n"
            )
            log_file.flush()
            continue

        kernel_verdict = verdict_name(node_idx, names)
        if relay_ix is not None and relay_ix < len(names):
            relay_verdict = names[relay_ix]
        else:
            relay_verdict = "?"

        if packet_tag == 1:
            if kernel_verdict in ("no-match", "refused-short"):
                undecided_count += 1
            log_file.write(
                f"seq {seq_num} malformed by design (n_fields {n_fields}, {len(packet_bytes)} B): kernel {kernel_verdict}\n"
            )
            log_file.flush()
            continue

        if kernel_verdict == relay_verdict:
            agree_count += 1
            status_str = "AGREE"
        else:
            disagree_count += 1
            status_str = "DISAGREE"

        log_file.write(
            f"seq {seq_num} kernel {kernel_verdict} relay {relay_verdict} {status_str}\n"
        )
        log_file.flush()

    elapsed_time = time.time() - start_time
    log_file.write(
        f"# summary: agree {agree_count}, disagree {disagree_count}, malformed decided no-match {undecided_count}, not PPT {odd_count}, {elapsed_time:.0f} s\n"
    )
    log_file.close()
    print(
        f"agree {agree_count} disagree {disagree_count} undecided {undecided_count} odd {odd_count}"
    )


if __name__ == "__main__":
    main()
