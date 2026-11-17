/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   A simple autonomy app for the NOS3 scenario. It proposes attitude and payload commands and never commands the
 *   vehicle itself: every command goes out on PRISMPATH_APP_PROPOSED_CMD_MID, which only the PrismPath app reads.
 *
 *   After a START ground command it proposes the plan (pp_autonomy_plan.inc, generated from
 *   integrations/cfs/nos3/plan.py) one command a second, paced by cFE Time Services' 1 Hz command, which in NOS3
 *   follows the simulation clock. It also reads the payload's housekeeping (NOS3's sample
 *   instrument): when the device status word turns nonzero it proposes the fault playbook at once, ahead of the
 *   rest of the plan. Some of the plan, and some of the playbook, is outside the policy on purpose.
 *
 *   Each proposal carries its tag in the command's spare word and is announced with a PROPOSE event, so the
 *   PrismPath app's decision with sequence number n is the decision on the n-th PROPOSE.
 */
#include <string.h>

#include "cfe.h"
#include "cfe_msgids.h"
#include "prismpath_app_msgids.h"
#include "prismpath_app_msg.h"
#include "sample_msgids.h"
#include "sample_msg.h"

#include "pp_autonomy.h"

typedef struct
{
    uint16 Tag;
    uint8  CmdClass;
    uint8  GroundContact;
    uint16 SlewDeg;
    uint16 ThrustPct;
} PP_AUTONOMY_Proposal_t;

#include "pp_autonomy_plan.inc"

#define PP_AUTONOMY_COUNT(a) (sizeof(a) / sizeof((a)[0]))

static struct
{
    CFE_SB_PipeId_t             Pipe;
    uint32                      RunStatus;
    bool                        Started;
    uint32                      NextPlan;      /**< index of the next plan entry */
    uint32                      PendingFault;  /**< playbook entries still to propose */
    uint32                      LastStatus;    /**< the payload's last device status word */
    uint32                      Proposed;
    PRISMPATH_APP_ProposedCmd_t Cmd;           /**< built in static storage, as the PrismPath app does */
} PP_AUTONOMY_Data;

static void PP_AUTONOMY_Propose(const PP_AUTONOMY_Proposal_t *P, const char *Why)
{
    PRISMPATH_APP_ProposedCmd_t *Cmd = &PP_AUTONOMY_Data.Cmd;

    memset(Cmd, 0, sizeof(*Cmd));
    CFE_MSG_Init(CFE_MSG_PTR(Cmd->CommandHeader), CFE_SB_ValueToMsgId(PRISMPATH_APP_PROPOSED_CMD_MID), sizeof(*Cmd));
    Cmd->CmdClass      = P->CmdClass;
    Cmd->GroundContact = P->GroundContact;
    Cmd->SlewDeg       = P->SlewDeg;
    Cmd->ThrustPct     = P->ThrustPct;
    Cmd->Spare         = P->Tag;
    CFE_MSG_GenerateChecksum(CFE_MSG_PTR(Cmd->CommandHeader));

    PP_AUTONOMY_Data.Proposed++;
    CFE_EVS_SendEvent(PP_AUTONOMY_PROPOSE_EID, CFE_EVS_EventType_INFORMATION,
                      "PP_AUTONOMY PROPOSE n=%lu tag=%u class=%u contact=%u slew=%u thrust=%u (%s)",
                      (unsigned long)PP_AUTONOMY_Data.Proposed, P->Tag, P->CmdClass, P->GroundContact, P->SlewDeg,
                      P->ThrustPct, Why);
    CFE_SB_TransmitMsg(CFE_MSG_PTR(Cmd->CommandHeader), true);
}

/** One step a second: the fault playbook first, then the next plan entry. */
static void PP_AUTONOMY_Step(void)
{
    if (PP_AUTONOMY_Data.PendingFault > 0)
    {
        uint32 i = (uint32)PP_AUTONOMY_COUNT(PP_AUTONOMY_FaultResponse) - PP_AUTONOMY_Data.PendingFault;
        PP_AUTONOMY_Data.PendingFault--;
        PP_AUTONOMY_Propose(&PP_AUTONOMY_FaultResponse[i], "fault playbook");
        return;
    }
    if (PP_AUTONOMY_Data.NextPlan < PP_AUTONOMY_COUNT(PP_AUTONOMY_Plan))
    {
        PP_AUTONOMY_Propose(&PP_AUTONOMY_Plan[PP_AUTONOMY_Data.NextPlan++], "plan");
        if (PP_AUTONOMY_Data.NextPlan == PP_AUTONOMY_COUNT(PP_AUTONOMY_Plan))
        {
            CFE_EVS_SendEvent(PP_AUTONOMY_PLAN_DONE_EID, CFE_EVS_EventType_INFORMATION,
                              "PP_AUTONOMY PLAN DONE proposed=%lu", (unsigned long)PP_AUTONOMY_Data.Proposed);
        }
    }
}

static void PP_AUTONOMY_PayloadHk(const CFE_SB_Buffer_t *Buf)
{
    size_t Size = 0;
    uint32 Status;

    CFE_MSG_GetSize(&Buf->Msg, &Size);
    if (Size < sizeof(SAMPLE_Hk_tlm_t))
    {
        return;
    }
    Status = ((const SAMPLE_Hk_tlm_t *)Buf)->DeviceHK.DeviceStatus;
    if (Status != PP_AUTONOMY_Data.LastStatus)
    {
        CFE_EVS_SendEvent(PP_AUTONOMY_PAYLOAD_STATUS_EID, CFE_EVS_EventType_INFORMATION,
                          "PP_AUTONOMY PAYLOAD STATUS %lu -> %lu", (unsigned long)PP_AUTONOMY_Data.LastStatus,
                          (unsigned long)Status);
        if (PP_AUTONOMY_Data.LastStatus == 0 && Status != 0 && PP_AUTONOMY_Data.Started)
        {
            CFE_EVS_SendEvent(PP_AUTONOMY_FAULT_EID, CFE_EVS_EventType_INFORMATION,
                              "PP_AUTONOMY FAULT payload status=%lu: proposing the %u command playbook",
                              (unsigned long)Status, (unsigned)PP_AUTONOMY_COUNT(PP_AUTONOMY_FaultResponse));
            PP_AUTONOMY_Data.PendingFault = (uint32)PP_AUTONOMY_COUNT(PP_AUTONOMY_FaultResponse);
        }
        PP_AUTONOMY_Data.LastStatus = Status;
    }
}

static void PP_AUTONOMY_Command(const CFE_SB_Buffer_t *Buf)
{
    CFE_MSG_FcnCode_t Fc = 0;

    CFE_MSG_GetFcnCode(&Buf->Msg, &Fc);
    if (Fc == PP_AUTONOMY_START_CC)
    {
        PP_AUTONOMY_Data.Started = true;
        CFE_EVS_SendEvent(PP_AUTONOMY_START_EID, CFE_EVS_EventType_INFORMATION,
                          "PP_AUTONOMY START plan=%u playbook=%u", (unsigned)PP_AUTONOMY_COUNT(PP_AUTONOMY_Plan),
                          (unsigned)PP_AUTONOMY_COUNT(PP_AUTONOMY_FaultResponse));
    }
    else if (Fc == PP_AUTONOMY_NOOP_CC)
    {
        CFE_EVS_SendEvent(PP_AUTONOMY_NOOP_EID, CFE_EVS_EventType_INFORMATION, "PP_AUTONOMY NOOP proposed=%lu",
                          (unsigned long)PP_AUTONOMY_Data.Proposed);
    }
}

void PP_AUTONOMY_Main(void)
{
    CFE_SB_Buffer_t *Buf;
    int32            Status;

    memset(&PP_AUTONOMY_Data, 0, sizeof(PP_AUTONOMY_Data));
    PP_AUTONOMY_Data.RunStatus = CFE_ES_RunStatus_APP_RUN;
    CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    Status = CFE_SB_CreatePipe(&PP_AUTONOMY_Data.Pipe, 16, "PP_AUTONOMY_PIPE");
    if (Status == CFE_SUCCESS)
    {
        Status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(PP_AUTONOMY_CMD_MID), PP_AUTONOMY_Data.Pipe);
    }
    if (Status == CFE_SUCCESS)
    {
        Status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SAMPLE_HK_TLM_MID), PP_AUTONOMY_Data.Pipe);
    }
    if (Status == CFE_SUCCESS)
    {
        Status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CFE_TIME_1HZ_CMD_MID), PP_AUTONOMY_Data.Pipe);
    }
    if (Status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("PP_AUTONOMY: init failed 0x%08lX\n", (unsigned long)Status);
        PP_AUTONOMY_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }
    else
    {
        CFE_EVS_SendEvent(PP_AUTONOMY_INIT_EID, CFE_EVS_EventType_INFORMATION,
                          "PP_AUTONOMY initialized, proposals on 0x%04X", (unsigned)PRISMPATH_APP_PROPOSED_CMD_MID);
    }

    while (CFE_ES_RunLoop(&PP_AUTONOMY_Data.RunStatus))
    {
        Status = CFE_SB_ReceiveBuffer(&Buf, PP_AUTONOMY_Data.Pipe, CFE_SB_PEND_FOREVER);
        if (Status == CFE_SUCCESS)
        {
            CFE_SB_MsgId_t Mid = CFE_SB_INVALID_MSG_ID;
            CFE_MSG_GetMsgId(&Buf->Msg, &Mid);
            if (CFE_SB_MsgIdToValue(Mid) == PP_AUTONOMY_CMD_MID)
            {
                PP_AUTONOMY_Command(Buf);
            }
            else if (CFE_SB_MsgIdToValue(Mid) == SAMPLE_HK_TLM_MID)
            {
                PP_AUTONOMY_PayloadHk(Buf);
            }
            else if (CFE_SB_MsgIdToValue(Mid) == CFE_TIME_1HZ_CMD_MID && PP_AUTONOMY_Data.Started)
            {
                PP_AUTONOMY_Step();
            }
        }
    }
    CFE_ES_ExitApp(PP_AUTONOMY_Data.RunStatus);
}
