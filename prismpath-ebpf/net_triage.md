---
name: net_triage
start: classify
---
## classify
Classify one packet by its 5-tuple and size. Deterministic match-action, first edge wins.
-> ssh: when dst_port == 22
-> dns: when dst_port == 53
-> http: when dst_port == 80
-> quic: when dst_port == 443 and protocol == 17
-> https: when dst_port == 443
-> icmp: when protocol == 1
-> jumbo: when pkt_len >= 1400
-> other: else
## ssh
SSH.
## dns
DNS.
## http
HTTP.
## https
HTTPS / TLS (TCP 443).
## quic
QUIC (UDP 443).
## icmp
ICMP.
## jumbo
Large packet (>= 1400 bytes).
## other
Everything else.
