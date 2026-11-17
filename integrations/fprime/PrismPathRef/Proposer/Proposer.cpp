// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
#include "PrismPathRef/Proposer/Proposer.hpp"

#include <Fw/Cmd/CmdPacket.hpp>
#include <Fw/Com/ComPacket.hpp>

namespace PrismPathRef {

Proposer::Proposer(const char* const compName) : ProposerComponentBase(compName), m_sent(0), m_opcode(0) {}

void Proposer::send(const U8* args, U32 length) {
    // A command packet as the dispatcher reads it: descriptor, opcode, then the serialized arguments. The opcode
    // is Vehicle.ACTUATE's, which the topology gave this component.
    Fw::ComBuffer buffer;
    (void)buffer.serializeFrom(static_cast<FwPacketDescriptorType>(Fw::ComPacketType::FW_PACKET_COMMAND));
    (void)buffer.serializeFrom(this->m_opcode);
    (void)buffer.serializeFrom(args, length, Fw::Serialization::OMIT_LENGTH);
    this->proposalOut_out(0, buffer, 0);
    this->m_sent++;
    this->tlmWrite_Sent(this->m_sent);
    this->log_ACTIVITY_LO_Proposed(length);
}

void Proposer::PROPOSE_cmdHandler(FwOpcodeType opCode, U32 cmdSeq, U8 cmd_class, U8 ground_contact, U16 slew_deg, U16 thrust_pct) {
    const U8 args[6] = {cmd_class, ground_contact, static_cast<U8>(slew_deg >> 8), static_cast<U8>(slew_deg & 0xFF),
                        static_cast<U8>(thrust_pct >> 8), static_cast<U8>(thrust_pct & 0xFF)};
    this->send(args, sizeof(args));
    this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
}

void Proposer::PROPOSE_PARTIAL_cmdHandler(FwOpcodeType opCode, U32 cmdSeq, U8 cmd_class, U8 ground_contact, U16 slew_deg) {
    const U8 args[4] = {cmd_class, ground_contact, static_cast<U8>(slew_deg >> 8), static_cast<U8>(slew_deg & 0xFF)};
    this->send(args, sizeof(args));
    this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
}

}  // namespace PrismPathRef
