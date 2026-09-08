package comparison.network_admission

decision := {"outcome": "deny", "rule": "r1"} if {
    input.dst_port == 23
}
else := {"outcome": "allow", "rule": "r2"} if {
    input.dst_port == 22
    input.src_internal == true
}
else := {"outcome": "deny", "rule": "r3"} if {
    input.dst_port == 22
}
else := {"outcome": "allow", "rule": "r4"} if {
    input.dst_port == 53
    input.pkt_len <= 512
}
else := {"outcome": "deny", "rule": "r5"} if {
    input.dst_port == 53
    input.pkt_len > 512
}
else := {"outcome": "allow", "rule": "r6"} if {
    input.dst_port == 443
}
else := {"outcome": "observe", "rule": "r7"} if {
    input.pkt_len >= 1400
}
else := {"outcome": "allow", "rule": "r8"} if {
    input.protocol == 1
}
else := {"outcome": "observe", "rule": "r9"}
