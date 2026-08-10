---
name: net_triage_enforce
start: classify
---
## classify
Classify one packet by its 5-tuple; DROP the designated test port, PASS everything else. First edge
wins, so the drop rule is evaluated before any pass classification. SSH (22) and all real traffic route
to their own pass nodes and are never dropped — the control plane is excluded by construction.
-> drop: when dst_port == 9999
-> ssh: when dst_port == 22
-> dns: when dst_port == 53
-> http: when dst_port == 80
-> quic: when dst_port == 443 and protocol == 17
-> https: when dst_port == 443
-> icmp: when protocol == 1
-> jumbo: when pkt_len >= 1400
-> other: else
## drop
Inline enforcement action: the loader maps this reserved node name to XDP_DROP; every other decision
node is XDP_PASS. Editing which edge routes here — or renaming the node — changes enforcement policy.
## ssh
SSH (TCP 22) — pass. The control plane; never in the drop set.
## dns
DNS — pass.
## http
HTTP — pass.
## https
HTTPS / TLS (TCP 443) — pass.
## quic
QUIC (UDP 443) — pass.
## icmp
ICMP — pass.
## jumbo
Large packet (>= 1400 bytes) — pass.
## other
Everything else — pass.
