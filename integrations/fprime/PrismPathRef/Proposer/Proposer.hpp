// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
#ifndef PRISMPATHREF_PROPOSER_HPP
#define PRISMPATHREF_PROPOSER_HPP

#include "PrismPathRef/Proposer/ProposerComponentAc.hpp"

namespace PrismPathRef {

class Proposer final : public ProposerComponentBase {
  public:
    explicit Proposer(const char* const compName);

    //! The opcode the dispatcher knows Vehicle.ACTUATE by (the vehicle instance's base id plus the command's
    //! opcode); the topology sets it once the instances exist
    void setActuateOpcode(FwOpcodeType opcode) { this->m_opcode = opcode; }

  private:
    void PROPOSE_cmdHandler(FwOpcodeType opCode, U32 cmdSeq, U8 cmd_class, U8 ground_contact, U16 slew_deg, U16 thrust_pct) override;
    void PROPOSE_PARTIAL_cmdHandler(FwOpcodeType opCode, U32 cmdSeq, U8 cmd_class, U8 ground_contact, U16 slew_deg) override;

    // Send Vehicle.ACTUATE's packet with the argument bytes given
    void send(const U8* args, U32 length);
    U32 m_sent;
    FwOpcodeType m_opcode;
};

}  // namespace PrismPathRef

#endif
