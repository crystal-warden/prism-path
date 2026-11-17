module PrismPathRef {

  @ A stand in for an autonomy function: it turns a ground command into a proposed command packet for
  @ Vehicle.ACTUATE and sends it to the guard, never to the dispatcher directly.
  passive component Proposer {

    @ The proposed command packet
    output port proposalOut: Fw.Com

    @ Propose Vehicle.ACTUATE with all four arguments
    sync command PROPOSE(
      cmd_class: U8 @< the command class
      ground_contact: U8 @< 1 with ground contact
      slew_deg: U16 @< the slew in degrees
      thrust_pct: U16 @< the thrust in percent
    ) opcode 0

    @ Propose a packet that ends after slew_deg, the way a truncated command arrives
    sync command PROPOSE_PARTIAL(
      cmd_class: U8
      ground_contact: U8
      slew_deg: U16
    ) opcode 1

    @ A proposal was sent
    event Proposed(
      bytes: U32 @< argument bytes in the packet
    ) \
      severity activity low id 0 format "PROPOSED {} argument bytes"

    time get port timeCaller
    command reg port cmdRegOut
    command recv port cmdIn
    command resp port cmdResponseOut
    event port eventOut
    text event port textEventOut
    telemetry port tlmOut

    @ Proposals sent
    telemetry Sent: U32 id 0

  }

}
