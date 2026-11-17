module PrismPathRef {

  @ A stand in for the vehicle: the command the guard protects. It records what it was commanded.
  passive component Vehicle {

    @ Carry out a command
    sync command ACTUATE(
      cmd_class: U8 @< the command class
      ground_contact: U8 @< 1 with ground contact
      slew_deg: U16 @< the slew in degrees
      thrust_pct: U16 @< the thrust in percent
    ) opcode 0

    @ A command was carried out
    event Actuated(
      cmd_class: U8
      ground_contact: U8
      slew_deg: U16
      thrust_pct: U16
    ) \
      severity activity high id 0 format "ACTUATED class={} contact={} slew={} thrust={}"

    time get port timeCaller
    command reg port cmdRegOut
    command recv port cmdIn
    command resp port cmdResponseOut
    event port eventOut
    text event port textEventOut
    telemetry port tlmOut

    @ Commands carried out
    telemetry Actuated: U32 id 0

  }

}
