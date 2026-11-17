// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
#ifndef PRISMPATHREF_GUARD_HPP
#define PRISMPATHREF_GUARD_HPP

#include "PrismPathRef/Guard/GuardComponentAc.hpp"

struct GC;

namespace PrismPathRef {

class Guard final : public GuardComponentBase {
  public:
    explicit Guard(const char* const compName);
    ~Guard();

  private:
    // The proposed command is decided, receipted, and forwarded only when allowed
    void proposalIn_handler(FwIndexType portNum, Fw::ComBuffer& data, U32 context) override;

    // The dispatcher's answer for a command the guard forwarded; nothing to do
    void cmdResponseIn_handler(FwIndexType portNum, FwOpcodeType opCode, U32 cmdSeq, const Fw::CmdResponse& response) override;

    void LOAD_POLICY_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) override;
    void SEAL_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) override;
    void REPORT_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) override;

    ::GC* m_core;
    U32 m_proposed;
    U32 m_allowed;
    U32 m_refused;
    U32 m_escalated;
};

}  // namespace PrismPathRef

#endif
