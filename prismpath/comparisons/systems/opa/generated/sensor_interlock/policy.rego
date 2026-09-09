package comparison.sensor_interlock

cond_r2 if {
    input.temp_c >= 150
}
cond_r2 if {
    input.pressure_kpa >= 900
}
cond_r3 if {
    input.temp_c >= 120
}
cond_r3 if {
    input.pressure_kpa >= 750
}

decision := {"outcome": "escalate_human", "rule": "r1"} if {
    input.sensor_ok == false
    input.armed == true
}
else := {"outcome": "deny", "rule": "r2"} if {
    cond_r2
}
else := {"outcome": "observe", "rule": "r3"} if {
    cond_r3
}
else := {"outcome": "allow", "rule": "r4"} if {
    input.temp_c < 120
    input.pressure_kpa < 750
    input.sensor_ok == true
}
