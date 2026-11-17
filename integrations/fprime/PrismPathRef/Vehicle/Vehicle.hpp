// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
#ifndef PRISMPATHREF_VEHICLE_HPP
#define PRISMPATHREF_VEHICLE_HPP

#include "PrismPathRef/Vehicle/VehicleComponentAc.hpp"

namespace PrismPathRef {

class Vehicle final : public VehicleComponentBase {
  public:
    explicit Vehicle(const char* const compName);

    //! The opcode the dispatcher knows ACTUATE by
    FwOpcodeType actuateOpcode() const { return this->getIdBase() + OPCODE_ACTUATE; }

  private:
    void ACTUATE_cmdHandler(FwOpcodeType opCode, U32 cmdSeq, U8 cmd_class, U8 ground_contact, U16 slew_deg, U16 thrust_pct) override;
    U32 m_count;
};

}  // namespace PrismPathRef

#endif
