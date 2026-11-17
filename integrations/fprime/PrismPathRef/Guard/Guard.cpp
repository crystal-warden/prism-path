// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
#include "PrismPathRef/Guard/Guard.hpp"

#include <Fw/Cmd/CmdPacket.hpp>
#include <Fw/Types/String.hpp>

#include "PrismPathRef/Guard/GuardCore.h"

namespace PrismPathRef {

Guard::Guard(const char* const compName)
    : GuardComponentBase(compName), m_core(GC_Create()), m_proposed(0), m_allowed(0), m_refused(0), m_escalated(0) {}

Guard::~Guard() {
    GC_Destroy(this->m_core);
}

void Guard::proposalIn_handler(FwIndexType portNum, Fw::ComBuffer& data, U32 context) {
    (void)portNum;
    const U32 seq = ++this->m_proposed;
    this->tlmWrite_Proposed(seq);

    // The packet is read as the dispatcher reads it: its descriptor, its opcode, then the argument bytes.
    Fw::CmdPacket packet;
    if (packet.deserializeFrom(data) != Fw::FW_SERIALIZE_OK) {
        this->m_refused++;
        this->log_WARNING_LO_Malformed(seq);
        return;
    }
    Fw::CmdArgBuffer& args = packet.getArgBuffer();
    ::GC_Outcome out;
    (void)::GC_Propose(this->m_core, args.getBuffAddr(), static_cast<size_t>(args.getSize()), &out);

    switch (out.Kind) {
        case GC_ALLOW: {
            this->m_allowed++;
            this->log_ACTIVITY_HI_Allow(seq, out.Rule, out.Receipt);
            // Forward the packet exactly as it came: its bytes are the ones that were decided.
            data.resetDeser();
            this->comOut_out(0, data, context);
            break;
        }
        case GC_ESCALATE:
            this->m_escalated++;
            this->tlmWrite_LastCause(out.Cause);
            this->log_WARNING_HI_Escalate(seq, out.Cause, out.Receipt);
            break;
        case GC_RECORD_ERROR:
            // an allow nobody can audit is not carried out
            this->m_refused++;
            this->log_WARNING_HI_RecordError(seq);
            break;
        default:
            this->m_refused++;
            this->tlmWrite_LastCause(out.Cause);
            this->log_WARNING_LO_Refuse(seq, out.Cause, Fw::String(out.Field), out.Receipt);
            break;
    }
    this->tlmWrite_Allowed(this->m_allowed);
    this->tlmWrite_Refused(this->m_refused);
    this->tlmWrite_Escalated(this->m_escalated);
    this->tlmWrite_Receipts(::GC_Receipts(this->m_core));
}

void Guard::cmdResponseIn_handler(FwIndexType portNum, FwOpcodeType opCode, U32 cmdSeq, const Fw::CmdResponse& response) {
    (void)portNum;
    (void)opCode;
    (void)cmdSeq;
    (void)response;
}

void Guard::LOAD_POLICY_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) {
    Fw::ParamValid valid;
    const Fw::ParamString policy = this->paramGet_POLICY_FILE(valid);
    const Fw::ParamString keys = this->paramGet_KEYS_DIR(valid);
    const Fw::ParamString run = this->paramGet_RUN_DIR(valid);
    U32 version = 0;
    U32 rules = 0;
    char what[64] = "";
    const int rc = ::GC_Load(this->m_core, policy.toChar(), keys.toChar(), run.toChar(), &version, &rules, what);
    if (rc == 0) {
        this->log_ACTIVITY_HI_PolicyLoaded(version, rules);
        this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
    } else if (rc < 0) {
        this->log_WARNING_HI_FileError(Fw::String(what));
        this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::EXECUTION_ERROR);
    } else {
        this->log_WARNING_HI_PolicyRejected(static_cast<U32>(rc));
        this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::VALIDATION_ERROR);
    }
}

void Guard::SEAL_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) {
    const Fw::Time now = this->getTime();
    U32 leaves = 0;
    char root[65];
    const int rc = ::GC_Seal(this->m_core, static_cast<U64>(now.getSeconds()) * 1000000u + now.getUSeconds(), &leaves, root);
    if (rc == 0) {
        this->log_ACTIVITY_HI_Sealed(leaves, Fw::String(leaves != 0 ? root : "-"));
        this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
    } else {
        this->log_WARNING_HI_SealFailed(rc);
        this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::EXECUTION_ERROR);
    }
}

void Guard::REPORT_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) {
    this->log_ACTIVITY_LO_Report(this->m_proposed, this->m_allowed, this->m_refused, this->m_escalated,
                                 ::GC_Receipts(this->m_core));
    this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
}

}  // namespace PrismPathRef
