@id("r1")
@outcome("escalate_human")
permit(principal, action == Action::"decide", resource)
when {
    ((context has sensor_ok && context.sensor_ok == false) && (context has armed && context.armed == true))
};

@id("r2")
@outcome("deny")
permit(principal, action == Action::"decide", resource)
when {
    ((context has temp_c && context.temp_c >= 150) || (context has pressure_kpa && context.pressure_kpa >= 900)) &&
    !((context has sensor_ok && context.sensor_ok == false) && (context has armed && context.armed == true))
};

@id("r3")
@outcome("observe")
permit(principal, action == Action::"decide", resource)
when {
    ((context has temp_c && context.temp_c >= 120) || (context has pressure_kpa && context.pressure_kpa >= 750)) &&
    !((context has sensor_ok && context.sensor_ok == false) && (context has armed && context.armed == true)) &&
    !((context has temp_c && context.temp_c >= 150) || (context has pressure_kpa && context.pressure_kpa >= 900))
};

@id("r4")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    ((context has temp_c && context.temp_c < 120) && (context has pressure_kpa && context.pressure_kpa < 750) && (context has sensor_ok && context.sensor_ok == true)) &&
    !((context has sensor_ok && context.sensor_ok == false) && (context has armed && context.armed == true)) &&
    !((context has temp_c && context.temp_c >= 150) || (context has pressure_kpa && context.pressure_kpa >= 900)) &&
    !((context has temp_c && context.temp_c >= 120) || (context has pressure_kpa && context.pressure_kpa >= 750))
};
