---
name: network_admission
start: decide
---

## decide
Packet admission: integer only match action, the cross substrate policy
The worker reports the request as fields; the edges below are the policy, first true wins.
@emits(protocol, dst_port, pkt_len, src_internal)
-> r1_deny: when dst_port == 23
-> r2_allow: when (dst_port == 22) and (src_internal)
-> r3_deny: when dst_port == 22
-> r4_allow: when (dst_port == 53) and (pkt_len <= 512)
-> r5_deny: when (dst_port == 53) and (pkt_len > 512)
-> r6_allow: when dst_port == 443
-> r7_observe: when pkt_len >= 1400
-> r8_allow: when protocol == 1
-> r9_observe: else

## r1_deny
telnet is never admitted

## r2_allow
internal ssh

## r3_deny
external ssh

## r4_allow
ordinary dns

## r5_deny
oversized dns, amplification shape

## r6_allow
tls

## r7_observe
jumbo, admit and log

## r8_allow
icmp

## r9_observe
everything else admitted under observation
