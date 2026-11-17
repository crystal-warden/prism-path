/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file
 *   The PrismPath command validation app for cFS.
 *
 * A proposer (the autonomy app) publishes commands on the PROPOSED_CMD message id. This app is the only
 * subscriber. Each proposal is read into the policy's fields as prismpath_app_layout.h defines them, decided
 * by PrismPath's C kernel against the active policy image, and then
 *
 *   allow     republished on the VEHICLE_CMD message id, and an event sent
 *   refuse    an event with the registered cause code, nothing republished
 *   escalate  an event with the registered cause code, nothing republished (S1 holds nothing; see the README)
 *
 * The policy image comes from the cFE table "PolicyTable". Its validation callback runs the kernel's checks,
 * and the app runs the same checks again when it activates the image, so an image that fails never decides.
 * All storage is static; nothing is allocated after initialization.
 */
#include <string.h>

#include "prismpath_app.h"
#include "prismpath_app_eventids.h"
#include "prismpath_app_kernel.h"

/* the command struct and the layout header must agree, byte for byte */
#define PAYLOAD_OFFSET(member) (offsetof(PRISMPATH_APP_ProposedCmd_t, member) - sizeof(CFE_MSG_CommandHeader_t))
_Static_assert(PAYLOAD_OFFSET(CmdClass) == 0, "cmd_class offset");
_Static_assert(PAYLOAD_OFFSET(GroundContact) == 1, "ground_contact offset");
_Static_assert(PAYLOAD_OFFSET(SlewDeg) == 2, "slew_deg offset");
_Static_assert(PAYLOAD_OFFSET(ThrustPct) == 4, "thrust_pct offset");
_Static_assert(sizeof(PRISMPATH_APP_ProposedCmd_t) - sizeof(CFE_MSG_CommandHeader_t) == PRISMPATH_APP_PAYLOAD_LEN,
               "payload length");

PRISMPATH_APP_Data_t PRISMPATH_APP_Data;

/* ----------------------------------------------------------------- the policy table */
int32 PRISMPATH_APP_TblValidationFunc(void *TblData)
{
    int rc = PP_Kernel_Check((const PP_PolicyTable_t *)TblData);

    if (rc != 0)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.PoliciesRejected++;
        CFE_EVS_SendEvent(PRISMPATH_APP_POLICY_REJECTED_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP POLICY REJECTED cause=%d (validation); the active image is unchanged", rc);
        return -1;
    }
    return CFE_SUCCESS;
}

/* Take the table's active image into the kernel. The kernel checks it again, so an image that reached the
 * active buffer by a path that skipped the validation command still never decides. */
static void PRISMPATH_APP_ActivateFromTable(void)
{
    PP_PolicyTable_t *Table = NULL;
    int               rc;
    unsigned int      Rules;

    if (CFE_TBL_GetAddress((void **)&Table, PRISMPATH_APP_Data.TblHandle) < CFE_SUCCESS)
    {
        return;
    }
    rc    = PP_Kernel_Activate(Table);
    Rules = Table->RuleCount;
    CFE_TBL_ReleaseAddress(PRISMPATH_APP_Data.TblHandle);
    if (rc == 0)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.PoliciesLoaded++;
        CFE_EVS_SendEvent(PRISMPATH_APP_POLICY_LOADED_EID, CFE_EVS_EventType_INFORMATION,
                          "PRISMPATH_APP POLICY LOADED layout=0x%08X rules=%u", (unsigned int)PP_Kernel_LayoutHash(),
                          Rules);
    }
    else
    {
        PRISMPATH_APP_Data.HkTlm.Payload.PoliciesRejected++;
        CFE_EVS_SendEvent(PRISMPATH_APP_POLICY_REJECTED_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP POLICY REJECTED cause=%d (activation); the active image is unchanged", rc);
    }
    PRISMPATH_APP_Data.HkTlm.Payload.PolicyActive = (uint8)PP_Kernel_Active();
}

static void PRISMPATH_APP_ManageTable(void)
{
    int32 Status = CFE_TBL_Manage(PRISMPATH_APP_Data.TblHandle);

    if (Status == CFE_TBL_INFO_UPDATED)
    {
        PRISMPATH_APP_ActivateFromTable();
    }
}

/* ----------------------------------------------------------------- one proposed command */
static void PRISMPATH_APP_Forward(PRISMPATH_APP_ProposedCmd_t *Proposed, uint32 Seq)
{
    CFE_MSG_FcnCode_t Fc = 0;
    int32             Status;

    PRISMPATH_APP_Data.VehicleCmd = *Proposed;
    (void)CFE_MSG_SetMsgId(CFE_MSG_PTR(PRISMPATH_APP_Data.VehicleCmd.CommandHeader), PRISMPATH_APP_Data.VehicleMid);
    (void)CFE_MSG_GetFcnCode(CFE_MSG_PTR(Proposed->CommandHeader), &Fc);
    (void)CFE_MSG_SetFcnCode(CFE_MSG_PTR(PRISMPATH_APP_Data.VehicleCmd.CommandHeader), Fc);
    (void)CFE_MSG_GenerateChecksum(CFE_MSG_PTR(PRISMPATH_APP_Data.VehicleCmd.CommandHeader));
    Status = CFE_SB_TransmitMsg(CFE_MSG_PTR(PRISMPATH_APP_Data.VehicleCmd.CommandHeader), true);
    if (Status == CFE_SUCCESS)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.Forwarded++;
    }
    else
    {
        PRISMPATH_APP_Data.HkTlm.Payload.ForwardErrors++;
        CFE_EVS_SendEvent(PRISMPATH_APP_FORWARD_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP FORWARD ERROR seq=%u rc=0x%08X", (unsigned int)Seq, (unsigned int)Status);
    }
}

static void PRISMPATH_APP_Proposal(const CFE_SB_Buffer_t *SBBufPtr)
{
    PRISMPATH_APP_ProposedCmd_t Proposed;
    PP_Verdict_t                Verdict;
    CFE_MSG_Size_t              Size = 0;
    size_t                      PayloadLen;
    uint32                      Seq;

    (void)CFE_MSG_GetSize(&SBBufPtr->Msg, &Size);
    PayloadLen = (Size > sizeof(CFE_MSG_CommandHeader_t)) ? (Size - sizeof(CFE_MSG_CommandHeader_t)) : 0;
    memset(&Proposed, 0, sizeof(Proposed));
    memcpy(&Proposed, SBBufPtr, (Size < sizeof(Proposed)) ? Size : sizeof(Proposed));

    Seq = ++PRISMPATH_APP_Data.HkTlm.Payload.Proposed;
    CFE_ES_PerfLogEntry(PRISMPATH_APP_DECIDE_PERF_ID);
    PP_Kernel_Decide(&((const uint8 *)&Proposed)[sizeof(CFE_MSG_CommandHeader_t)],
                     (PayloadLen < PRISMPATH_APP_PAYLOAD_LEN) ? PayloadLen : PRISMPATH_APP_PAYLOAD_LEN, &Verdict);
    CFE_ES_PerfLogExit(PRISMPATH_APP_DECIDE_PERF_ID);

    switch (Verdict.Kind)
    {
        case PP_KIND_ALLOW:
            PRISMPATH_APP_Data.HkTlm.Payload.Allowed++;
            CFE_EVS_SendEvent(PRISMPATH_APP_ALLOW_EID, CFE_EVS_EventType_INFORMATION,
                              "PRISMPATH_APP ALLOW seq=%u rule=%d", (unsigned int)Seq, (int)Verdict.Rule);
            PRISMPATH_APP_Forward(&Proposed, Seq);
            break;
        case PP_KIND_ESCALATE:
            PRISMPATH_APP_Data.HkTlm.Payload.Escalated++;
            PRISMPATH_APP_Data.HkTlm.Payload.LastRefusalCause = Verdict.Cause;
            CFE_EVS_SendEvent(PRISMPATH_APP_ESCALATE_EID, CFE_EVS_EventType_CRITICAL,
                              "PRISMPATH_APP ESCALATE seq=%u rule=%d cause=%u", (unsigned int)Seq,
                              (int)Verdict.Rule, (unsigned int)Verdict.Cause);
            break;
        default:
            PRISMPATH_APP_Data.HkTlm.Payload.Refused++;
            PRISMPATH_APP_Data.HkTlm.Payload.LastRefusalCause = Verdict.Cause;
            if (Verdict.Rule >= 0)
            {
                CFE_EVS_SendEvent(PRISMPATH_APP_REFUSE_EID, CFE_EVS_EventType_ERROR,
                                  "PRISMPATH_APP REFUSE seq=%u rule=%d cause=%u", (unsigned int)Seq,
                                  (int)Verdict.Rule, (unsigned int)Verdict.Cause);
            }
            else
            {
                CFE_EVS_SendEvent(PRISMPATH_APP_REFUSE_EID, CFE_EVS_EventType_ERROR,
                                  "PRISMPATH_APP REFUSE seq=%u core cause=%u field=%s", (unsigned int)Seq,
                                  (unsigned int)Verdict.Cause, PP_Kernel_FieldName(Verdict.Field));
            }
            break;
    }
}

/* ----------------------------------------------------------------- housekeeping and ground commands */
static void PRISMPATH_APP_SendHk(void)
{
    PRISMPATH_APP_HkTlm_Payload_t *Hk = &PRISMPATH_APP_Data.HkTlm.Payload;

    Hk->PolicyActive     = (uint8)PP_Kernel_Active();
    Hk->PolicyLayoutHash = PP_Kernel_LayoutHash();
    CFE_SB_TimeStampMsg(CFE_MSG_PTR(PRISMPATH_APP_Data.HkTlm.TelemetryHeader));
    CFE_SB_TransmitMsg(CFE_MSG_PTR(PRISMPATH_APP_Data.HkTlm.TelemetryHeader), true);
    CFE_EVS_SendEvent(PRISMPATH_APP_HK_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "PRISMPATH_APP HK proposed=%u allowed=%u refused=%u escalated=%u forwarded=%u active=%u",
                      (unsigned int)Hk->Proposed, (unsigned int)Hk->Allowed, (unsigned int)Hk->Refused,
                      (unsigned int)Hk->Escalated, (unsigned int)Hk->Forwarded, (unsigned int)Hk->PolicyActive);
}

static bool PRISMPATH_APP_VerifyLength(const CFE_MSG_Message_t *MsgPtr, size_t Expected)
{
    CFE_MSG_Size_t Actual = 0;

    (void)CFE_MSG_GetSize(MsgPtr, &Actual);
    if (Actual != Expected)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.CommandErrorCounter++;
        CFE_EVS_SendEvent(PRISMPATH_APP_CMD_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP invalid command length %u, expected %u", (unsigned int)Actual,
                          (unsigned int)Expected);
        return false;
    }
    return true;
}

static void PRISMPATH_APP_GroundCommand(const CFE_SB_Buffer_t *SBBufPtr)
{
    CFE_MSG_FcnCode_t Cc = 0;

    (void)CFE_MSG_GetFcnCode(&SBBufPtr->Msg, &Cc);
    switch (Cc)
    {
        case PRISMPATH_APP_NOOP_CC:
            if (PRISMPATH_APP_VerifyLength(&SBBufPtr->Msg, sizeof(PRISMPATH_APP_NoopCmd_t)))
            {
                PRISMPATH_APP_Data.HkTlm.Payload.CommandCounter++;
                CFE_EVS_SendEvent(PRISMPATH_APP_NOOP_INF_EID, CFE_EVS_EventType_INFORMATION, "PRISMPATH_APP NOOP");
            }
            break;
        case PRISMPATH_APP_RESET_COUNTERS_CC:
            if (PRISMPATH_APP_VerifyLength(&SBBufPtr->Msg, sizeof(PRISMPATH_APP_ResetCountersCmd_t)))
            {
                PRISMPATH_APP_HkTlm_Payload_t *Hk = &PRISMPATH_APP_Data.HkTlm.Payload;
                Hk->CommandCounter = 0;
                Hk->CommandErrorCounter = 0;
                Hk->Proposed = Hk->Allowed = Hk->Refused = Hk->Escalated = 0;
                Hk->Forwarded = Hk->ForwardErrors = Hk->LastRefusalCause = 0;
                CFE_EVS_SendEvent(PRISMPATH_APP_RESET_INF_EID, CFE_EVS_EventType_INFORMATION,
                                  "PRISMPATH_APP counters reset");
            }
            break;
        default:
            PRISMPATH_APP_Data.HkTlm.Payload.CommandErrorCounter++;
            CFE_EVS_SendEvent(PRISMPATH_APP_CC_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP invalid ground command code %d", (int)Cc);
            break;
    }
}

static void PRISMPATH_APP_TaskPipe(const CFE_SB_Buffer_t *SBBufPtr)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    (void)CFE_MSG_GetMsgId(&SBBufPtr->Msg, &MsgId);
    if (CFE_SB_MsgId_Equal(MsgId, PRISMPATH_APP_Data.ProposedMid))
    {
        PRISMPATH_APP_Proposal(SBBufPtr);
    }
    else if (CFE_SB_MsgId_Equal(MsgId, PRISMPATH_APP_Data.SendHkMid))
    {
        PRISMPATH_APP_SendHk();
    }
    else if (CFE_SB_MsgId_Equal(MsgId, PRISMPATH_APP_Data.CmdMid))
    {
        PRISMPATH_APP_GroundCommand(SBBufPtr);
    }
    else
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_MID_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP invalid message id 0x%x", (unsigned int)CFE_SB_MsgIdToValue(MsgId));
    }
}

/* ----------------------------------------------------------------- entry point and initialization */
void PRISMPATH_APP_Main(void)
{
    CFE_Status_t     Status;
    CFE_SB_Buffer_t *SBBufPtr;

    CFE_ES_PerfLogEntry(PRISMPATH_APP_PERF_ID);

    Status = PRISMPATH_APP_Init();
    if (Status != CFE_SUCCESS)
    {
        PRISMPATH_APP_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&PRISMPATH_APP_Data.RunStatus) == true)
    {
        CFE_ES_PerfLogExit(PRISMPATH_APP_PERF_ID);
        Status = CFE_SB_ReceiveBuffer(&SBBufPtr, PRISMPATH_APP_Data.CommandPipe, PRISMPATH_APP_PLATFORM_TABLE_POLL_MS);
        CFE_ES_PerfLogEntry(PRISMPATH_APP_PERF_ID);

        /* a ground table load, validate and activate is picked up here, between messages */
        PRISMPATH_APP_ManageTable();

        if (Status == CFE_SUCCESS)
        {
            PRISMPATH_APP_TaskPipe(SBBufPtr);
        }
        else if (Status != CFE_SB_TIME_OUT)
        {
            CFE_EVS_SendEvent(PRISMPATH_APP_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP SB pipe read error 0x%08X, app will exit", (unsigned int)Status);
            PRISMPATH_APP_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    CFE_ES_PerfLogExit(PRISMPATH_APP_PERF_ID);
    CFE_ES_ExitApp(PRISMPATH_APP_Data.RunStatus);
}

/* The software bus queues at most MsgLim messages of one id on a pipe, and drops the rest with an event. The
 * default is 4, which a burst of proposals from one ingest cycle exceeds, so each id gets the whole pipe. */
static CFE_Status_t PRISMPATH_APP_Subscribe(CFE_SB_MsgId_t Mid)
{
    CFE_Status_t Status = CFE_SB_SubscribeEx(Mid, PRISMPATH_APP_Data.CommandPipe, CFE_SB_DEFAULT_QOS,
                                             PRISMPATH_APP_PLATFORM_PIPE_DEPTH);

    if (Status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_SUB_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP error subscribing to 0x%x, rc=0x%08X",
                          (unsigned int)CFE_SB_MsgIdToValue(Mid), (unsigned int)Status);
    }
    return Status;
}

CFE_Status_t PRISMPATH_APP_Init(void)
{
    CFE_Status_t Status;

    memset(&PRISMPATH_APP_Data, 0, sizeof(PRISMPATH_APP_Data));
    PRISMPATH_APP_Data.RunStatus   = CFE_ES_RunStatus_APP_RUN;
    PRISMPATH_APP_Data.CmdMid      = CFE_SB_ValueToMsgId(PRISMPATH_APP_CMD_MID);
    PRISMPATH_APP_Data.SendHkMid   = CFE_SB_ValueToMsgId(PRISMPATH_APP_SEND_HK_MID);
    PRISMPATH_APP_Data.ProposedMid = CFE_SB_ValueToMsgId(PRISMPATH_APP_PROPOSED_CMD_MID);
    PRISMPATH_APP_Data.VehicleMid  = CFE_SB_ValueToMsgId(PRISMPATH_APP_VEHICLE_CMD_MID);

    Status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (Status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("PRISMPATH_APP: error registering events, RC = 0x%08lX\n", (unsigned long)Status);
        return Status;
    }

    CFE_MSG_Init(CFE_MSG_PTR(PRISMPATH_APP_Data.HkTlm.TelemetryHeader), CFE_SB_ValueToMsgId(PRISMPATH_APP_HK_TLM_MID),
                 sizeof(PRISMPATH_APP_Data.HkTlm));
    CFE_MSG_Init(CFE_MSG_PTR(PRISMPATH_APP_Data.VehicleCmd.CommandHeader), PRISMPATH_APP_Data.VehicleMid,
                 sizeof(PRISMPATH_APP_Data.VehicleCmd));

    Status = CFE_SB_CreatePipe(&PRISMPATH_APP_Data.CommandPipe, PRISMPATH_APP_PLATFORM_PIPE_DEPTH,
                               PRISMPATH_APP_PLATFORM_PIPE_NAME);
    if (Status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_CR_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP error creating pipe, RC = 0x%08lX", (unsigned long)Status);
        return Status;
    }

    /* the proposed command id is subscribed here and nowhere else, and the vehicle id only ever published */
    if (PRISMPATH_APP_Subscribe(PRISMPATH_APP_Data.SendHkMid) != CFE_SUCCESS ||
        PRISMPATH_APP_Subscribe(PRISMPATH_APP_Data.CmdMid) != CFE_SUCCESS ||
        PRISMPATH_APP_Subscribe(PRISMPATH_APP_Data.ProposedMid) != CFE_SUCCESS)
    {
        return CFE_SB_BAD_ARGUMENT;
    }

    Status = CFE_TBL_Register(&PRISMPATH_APP_Data.TblHandle, "PolicyTable", sizeof(PRISMPATH_APP_PolicyTable_t),
                              CFE_TBL_OPT_DEFAULT, PRISMPATH_APP_TblValidationFunc);
    if (Status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_TABLE_REG_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP error registering the policy table, RC = 0x%08lX", (unsigned long)Status);
        return Status;
    }

    /* The initial load. A refused image leaves the kernel with no policy, which refuses every proposal: the
     * app fails closed, and says so in an event. */
    Status = CFE_TBL_Load(PRISMPATH_APP_Data.TblHandle, CFE_TBL_SRC_FILE, PRISMPATH_APP_PLATFORM_TABLE_FILE);
    if (Status == CFE_SUCCESS || Status == CFE_TBL_INFO_UPDATED)
    {
        PRISMPATH_APP_ActivateFromTable();
    }
    else
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_POLICY_REJECTED_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP POLICY NOT LOADED rc=0x%08X; every proposal will be refused",
                          (unsigned int)Status);
    }

    CFE_EVS_SendEvent(PRISMPATH_APP_INIT_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "PRISMPATH_APP initialized, policy %s", PP_Kernel_Active() ? "active" : "NOT active");
    return CFE_SUCCESS;
}
