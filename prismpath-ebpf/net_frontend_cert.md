---
name: net_frontend_cert
start: classify
---
## classify
The conformance flow for ppt_net's real packet front end (net_cert.py). Each edge is aimed at one thing
the front end must get right: an address compared for equality and membership, including addresses at
or above 128.0.0.0 whose register reads negative; TCP flags present only on TCP; ports present only on
the first fragment of a TCP or UDP packet with its whole header; and an absent port deciding as absence
does, where `!=` holds and an ordering does not. Before October 2026 a packet without ports read port 0
and took `low_port`.
-> from_host: when src_ip == 167772165
-> to_set: when dst_ip in [167772166, 167772167]
-> syn: when tcp_flags == 2
-> low_port: when dst_port < 1024
-> high_port: when dst_port >= 1024
-> portless: when src_port != 22
-> other: else
## from_host
From 10.0.0.5.
## to_set
To 10.0.0.6 or 10.0.0.7.
## syn
A TCP segment with only SYN set.
## low_port
A destination port below 1024.
## high_port
A destination port of 1024 or above.
## portless
No ports: neither TCP nor UDP, a later fragment, or a header cut short.
## other
Unreachable on a well formed reading; kept so the table has an else.
