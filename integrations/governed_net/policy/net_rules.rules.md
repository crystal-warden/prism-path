---
name: net_rules
description: the governed network's rules over the protocol's seven header fields (PROTOCOL.md)
start: core_decision
field.arg0: int min=0 max=2147483647
field.arg1: int min=0 max=2147483647
field.cmd: int min=1 max=11
field.data_len: int min=0 max=1024
field.hclass: int min=0 max=255
field.name_len: int min=0 max=64
field.version: int min=1 max=1
---
## core_decision
The rules are read from the top. The first one that holds decides the datagram.
Compile with `prismpath policy compile net_rules.rules.md -o net_rules.core.json`.

-> refuse agent:unclassifiable: when hclass > 4
-> refuse agent:toolchain-write: when cmd in [3, 4, 5] and hclass in [3, 4]
-> refuse agent:network: when cmd == 11
-> escalate agent:push-escalated: when cmd == 10
-> allow: when cmd == 1 and hclass in [2, 4]
-> allow: when cmd == 2 and hclass in [1, 3] and arg1 >= 1 and arg1 <= 4096
-> allow: when cmd == 3 and hclass == 1
-> allow: when cmd == 4 and hclass == 2 and name_len >= 1
-> allow: when cmd == 5 and hclass == 1
-> allow: when cmd == 6 and hclass in [1, 3] and arg0 in [1, 2, 3]
-> allow: when cmd == 7
-> allow: when cmd == 8 and arg0 >= 1 and arg0 <= 50
-> allow: when cmd == 9 and data_len >= 1
