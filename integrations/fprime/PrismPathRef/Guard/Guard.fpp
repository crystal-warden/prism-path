module PrismPathRef {

  @ Decides every proposed command with PrismPath's C kernel before it reaches the command dispatcher, and keeps a
  @ receipt of every decision in a signed core run the ground verifies. The decision and receipt code is the C the
  @ cFS app uses (integrations/cfs/prismpath_app/fsw/src), compiled in place from that directory.
  passive component Guard {

    # ----------------------------------------------------------------------
    # The command path
    # ----------------------------------------------------------------------

    @ A proposed command, as the serialized command packet the dispatcher would dispatch
    sync input port proposalIn: Fw.Com

    @ An allowed command, forwarded unchanged to the command dispatcher
    output port comOut: Fw.Com

    @ The dispatcher's answer for a forwarded command (the guard keeps no state for it)
    sync input port cmdResponseIn: Fw.CmdResponse

    # ----------------------------------------------------------------------
    # Commands
    # ----------------------------------------------------------------------

    @ Read the policy table, the authority key and the instance key named by the parameters, check the table (the
    @ kernel's structural checks, the authority's two signatures, the version floor) and make it the active policy
    sync command LOAD_POLICY() opcode 0

    @ Close the run, sign a root statement over every receipt with the instance key and write the run files
    sync command SEAL() opcode 1

    @ Report the counters as an event
    sync command REPORT() opcode 2

    # ----------------------------------------------------------------------
    # Events
    # ----------------------------------------------------------------------

    @ The policy table was accepted and is active
    event PolicyLoaded(
      version: U32 @< the table's image version
      rules: U32 @< rules in the table
    ) \
      severity activity high id 0 format "POLICY LOADED version={} rules={}"

    @ The policy table was refused, with the registered cause code; the active policy is unchanged
    event PolicyRejected(
      cause: U32 @< registered cause code
    ) \
      severity warning high id 1 format "POLICY REJECTED cause={}"

    @ A file the guard needs could not be read
    event FileError(
      what: string size 64 @< which file
    ) \
      severity warning high id 2 format "FILE ERROR {}"

    @ A proposal was allowed and forwarded
    event Allow(
      seq: U32 @< proposal number
      rule: I32 @< the rule that allowed it
      receipt: I64 @< receipt index, -1 for none
    ) \
      severity activity high id 3 format "ALLOW seq={} rule={} receipt={}"

    @ A proposal was refused and not forwarded
    event Refuse(
      seq: U32
      cause: U32 @< registered cause code
      field: string size 16 @< the field the boundary refused, empty for a rule
      receipt: I64
    ) \
      severity warning low id 4 format "REFUSE seq={} cause={} field={} receipt={}"

    @ A proposal was escalated and not forwarded
    event Escalate(
      seq: U32
      cause: U32 @< registered cause code
      receipt: I64
    ) \
      severity warning high id 5 format "ESCALATE seq={} cause={} receipt={}"

    @ A decision could not be receipted, so it was not acted on
    event RecordError(
      seq: U32
    ) \
      severity warning high id 6 format "RECORD ERROR seq={}: the decision could not be receipted and is not acted on"

    @ A proposal was not a command packet
    event Malformed(
      seq: U32
    ) \
      severity warning low id 7 format "MALFORMED seq={}"

    @ The run was sealed
    event Sealed(
      receipts: U32
      root: string size 64 @< the root, 64 hex digits
    ) \
      severity activity high id 8 format "SEALED receipts={} root={}"

    @ The seal failed
    event SealFailed(
      code: I32
    ) \
      severity warning high id 9 format "SEAL FAILED code={}"

    @ The counters
    event Report(
      proposed: U32
      allowed: U32
      refused: U32
      escalated: U32
      receipts: U32
    ) \
      severity activity low id 10 format "REPORT proposed={} allowed={} refused={} escalated={} receipts={}"

    # ----------------------------------------------------------------------
    # Telemetry
    # ----------------------------------------------------------------------

    @ Proposals decided
    telemetry Proposed: U32 id 0

    @ Proposals allowed
    telemetry Allowed: U32 id 1

    @ Proposals refused
    telemetry Refused: U32 id 2

    @ Proposals escalated
    telemetry Escalated: U32 id 3

    @ Receipts written
    telemetry Receipts: U32 id 4

    @ The last cause code refused or escalated
    telemetry LastCause: U32 id 5

    # ----------------------------------------------------------------------
    # Parameters
    # ----------------------------------------------------------------------

    @ The policy table file, the raw bytes of PP_PolicyTable_t signed by the authority
    param POLICY_FILE: string size 40 default "pp/pp_policy.tbl" id 0

    @ The directory with pp_authority.pub and pp_instance.key
    param KEYS_DIR: string size 40 default "pp" id 1

    @ The directory the run is written to (it must exist)
    param RUN_DIR: string size 40 default "pp/run" id 2

    # ----------------------------------------------------------------------
    # Special ports
    # ----------------------------------------------------------------------

    time get port timeCaller
    command reg port cmdRegOut
    command recv port cmdIn
    command resp port cmdResponseOut
    event port eventOut
    text event port textEventOut
    telemetry port tlmOut
    param get port prmGetOut
    param set port prmSetOut

  }

}
