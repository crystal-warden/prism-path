// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
#include "PrismPathRef/Vehicle/Vehicle.hpp"

namespace PrismPathRef {

Vehicle::Vehicle(const char* const compName) : VehicleComponentBase(compName), m_count(0) {}

void Vehicle::ACTUATE_cmdHandler(FwOpcodeType opCode, U32 cmdSeq, U8 cmd_class, U8 ground_contact, U16 slew_deg, U16 thrust_pct) {
    this->m_count++;
    this->tlmWrite_Actuated(this->m_count);
    this->log_ACTIVITY_HI_Actuated(cmd_class, ground_contact, slew_deg, thrust_pct);
    this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
}

}  // namespace PrismPathRef
