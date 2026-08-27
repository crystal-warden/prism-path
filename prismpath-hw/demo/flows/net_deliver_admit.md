---
name: net_deliver_admit
start: admit_check
---

## admit_check
Link 6 of the provenance chain: the artifact-delivery admission policy, enforced inline on the
Protectli in XDP. One packet, classified on its 5-tuple against the canonical network schema
(0 src_ip, 1 dst_ip, 2 src_port, 3 dst_port, 4 protocol, 5 pkt_len, 6 tcp_flags, 7 ttl). The
signed pack travels from the dev station to the target over the delivery port; this policy admits
that flow and drops an unauthorized attempt to reach the same port from anywhere else. First edge
wins. It does NOT verify the signature (XDP cannot); the target's verify-then-activate does that.
This layer gates which flow reaches the target, and every decision here is logged.

Constants set at deploy (placeholders below compile fine and are exercised by the cert corpus).
`src_ip` is matched by bit-equality on the host-order u32 stored in the signed val (the schema's
documented idiom): 192.168.4.128 = 0xC0A80480 = -1062730880 as i32. Delivery port 8443, TCP = 6.

-> ssh: when dst_port == 22
-> deliver: when dst_port == 8443 and protocol == 6 and src_ip == -1062730880
-> reject: when dst_port == 8443
-> other: else

## ssh
The control plane. SSH (TCP 22) always passes; never in the drop set, so management is excluded
by construction. Mapped to XDP_PASS.

## deliver
The authorized artifact-delivery flow: the delivery port, over TCP, from the dev station. Admit.
This is the packet carrying the signed pack toward the target. Mapped to XDP_PASS; logged as an
admission decision.

## reject
An attempt to reach the delivery port from an unauthorized source. The reserved drop node: the
loader maps this name to XDP_DROP. The pack never reaches the target over this flow. Logged.

## other
All other traffic on the segment passes unchanged. Mapped to XDP_PASS.
