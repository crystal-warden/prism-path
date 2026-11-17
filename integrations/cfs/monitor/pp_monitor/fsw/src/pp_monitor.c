/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   A runtime monitor for the NOS3 scenario, built on NASA's R2U2 (C version). It runs a compiled temporal
 *   property over the payload's housekeeping, one R2U2 step a second (cFE Time Services' 1 Hz command, which in
 *   NOS3 follows the simulation clock), and publishes its verdict on PRISMPATH_APP_MONITOR_VERDICT_MID every second.
 *   The PrismPath app reads the latest verdict into the policy's monitor_ok field.
 *
 *   The property (spec/payload_quiet.c2po, compiled by R2U2's own compiler C2PO into pp_monitor_spec.inc, which the
 *   scenario script generates beside this file): the payload's device status word has been zero for the last
 *   five seconds, as a past time formula, `H[0,5] !(status != 0)`.
 *
 *   The monitor only watches. It never commands the vehicle and never decides anything about a command. Two ground
 *   commands stand in for the monitor failing: HALT stops it publishing, as if it had hung, and RESUME starts it
 *   again. R2U2 keeps stepping while halted, so its timeline stays right.
 */
#include <string.h>

#include "cfe.h"
#include "cfe_msgids.h"
#include "prismpath_app_msgids.h"
#include "prismpath_app_msg.h"
#include "sample_msgids.h"
#include "sample_msg.h"

#include "pp_monitor.h"

/* R2U2's own header (the checkout is a build input, never copied). It uses binary constants, a GCC extension the
 * mission's -pedantic -Werror flags reject, so CMakeLists.txt compiles this file without -pedantic. */
#include "r2u2.h"

#include "pp_monitor_spec.inc" /* static uint8_t PP_MONITOR_Spec[]; the signal index of `status` is 0 */

#define PP_MONITOR_SIGNAL_STATUS 0

static r2u2_monitor_t PP_MONITOR_Monitor = R2U2_DEFAULT_MONITOR;

static struct
{
    CFE_SB_PipeId_t               Pipe;
    uint32                        RunStatus;
    bool                          Halted;
    bool                          HaveVerdict;  /**< R2U2 has reported at least once */
    bool                          Truth;        /**< the latest verdict: the property holds */
    int                           Published;    /**< the last verdict published, -1 before the first */
    uint32                        Status;       /**< the payload's last device status word */
    uint32                        Step;
    PRISMPATH_APP_MonitorVerdict_t Msg;         /**< built in static storage */
} PP_MONITOR_Data;

/* R2U2 calls this for each verdict the property's output reports. A verdict covers every step since the last one
 * it reported, so between reports the monitor holds the last truth value. */
static r2u2_status_t PP_MONITOR_OnVerdict(r2u2_mltl_instruction_t Instr, r2u2_verdict *Result)
{
    (void)Instr;
    PP_MONITOR_Data.HaveVerdict = true;
    PP_MONITOR_Data.Truth       = get_verdict_truth(*Result) ? true : false;
    return R2U2_OK;
}

static void PP_MONITOR_Step(void)
{
    r2u2_status_t Rc;
    uint8         Ok;

    r2u2_load_int_signal(&PP_MONITOR_Monitor, PP_MONITOR_SIGNAL_STATUS, (r2u2_int)PP_MONITOR_Data.Status);
    Rc = r2u2_step(&PP_MONITOR_Monitor);
    if (Rc != R2U2_OK)
    {
        CFE_EVS_SendEvent(PP_MONITOR_ERR_EID, CFE_EVS_EventType_ERROR, "PP_MONITOR R2U2 step failed rc=%d", (int)Rc);
        PP_MONITOR_Data.HaveVerdict = false; /* a monitor that cannot step has no verdict: not ok */
    }
    PP_MONITOR_Data.Step++;
    Ok = (PP_MONITOR_Data.HaveVerdict && PP_MONITOR_Data.Truth) ? 1u : 0u;
    if ((int)Ok != PP_MONITOR_Data.Published)
    {
        PP_MONITOR_Data.Published = (int)Ok;
        CFE_EVS_SendEvent(PP_MONITOR_VERDICT_EID, CFE_EVS_EventType_INFORMATION,
                          "PP_MONITOR VERDICT payload_quiet=%s step=%lu status=%lu", Ok ? "holds" : "VIOLATED",
                          (unsigned long)PP_MONITOR_Data.Step, (unsigned long)PP_MONITOR_Data.Status);
    }
    if (!PP_MONITOR_Data.Halted)
    {
        PP_MONITOR_Data.Msg.Ok   = Ok;
        PP_MONITOR_Data.Msg.Step = PP_MONITOR_Data.Step;
        CFE_SB_TimeStampMsg(CFE_MSG_PTR(PP_MONITOR_Data.Msg.TelemetryHeader));
        CFE_SB_TransmitMsg(CFE_MSG_PTR(PP_MONITOR_Data.Msg.TelemetryHeader), true);
    }
}

static void PP_MONITOR_PayloadHk(const CFE_SB_Buffer_t *Buf)
{
    size_t Size = 0;

    CFE_MSG_GetSize(&Buf->Msg, &Size);
    if (Size >= sizeof(SAMPLE_Hk_tlm_t))
    {
        PP_MONITOR_Data.Status = ((const SAMPLE_Hk_tlm_t *)Buf)->DeviceHK.DeviceStatus;
    }
}

static void PP_MONITOR_Command(const CFE_SB_Buffer_t *Buf)
{
    CFE_MSG_FcnCode_t Fc = 0;

    CFE_MSG_GetFcnCode(&Buf->Msg, &Fc);
    if (Fc == PP_MONITOR_HALT_CC)
    {
        PP_MONITOR_Data.Halted = true;
        CFE_EVS_SendEvent(PP_MONITOR_HALT_EID, CFE_EVS_EventType_INFORMATION, "PP_MONITOR HALT step=%lu: no verdicts",
                          (unsigned long)PP_MONITOR_Data.Step);
    }
    else if (Fc == PP_MONITOR_RESUME_CC)
    {
        PP_MONITOR_Data.Halted = false;
        CFE_EVS_SendEvent(PP_MONITOR_RESUME_EID, CFE_EVS_EventType_INFORMATION,
                          "PP_MONITOR RESUME step=%lu: verdicts again", (unsigned long)PP_MONITOR_Data.Step);
    }
    else if (Fc == PP_MONITOR_NOOP_CC)
    {
        CFE_EVS_SendEvent(PP_MONITOR_NOOP_EID, CFE_EVS_EventType_INFORMATION, "PP_MONITOR NOOP step=%lu",
                          (unsigned long)PP_MONITOR_Data.Step);
    }
}

void PP_MONITOR_Main(void)
{
    CFE_SB_Buffer_t *Buf;
    int32            Status;
    r2u2_status_t    Rc;

    memset(&PP_MONITOR_Data, 0, sizeof(PP_MONITOR_Data));
    PP_MONITOR_Data.RunStatus = CFE_ES_RunStatus_APP_RUN;
    PP_MONITOR_Data.Published = -1;
    CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    CFE_MSG_Init(CFE_MSG_PTR(PP_MONITOR_Data.Msg.TelemetryHeader),
                 CFE_SB_ValueToMsgId(PRISMPATH_APP_MONITOR_VERDICT_MID), sizeof(PP_MONITOR_Data.Msg));

    Rc = r2u2_load_specification(PP_MONITOR_Spec, &PP_MONITOR_Monitor);
    PP_MONITOR_Monitor.out_func = PP_MONITOR_OnVerdict;
    Status = CFE_SB_CreatePipe(&PP_MONITOR_Data.Pipe, 16, "PP_MONITOR_PIPE");
    if (Status == CFE_SUCCESS)
    {
        Status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(PP_MONITOR_CMD_MID), PP_MONITOR_Data.Pipe);
    }
    if (Status == CFE_SUCCESS)
    {
        Status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SAMPLE_HK_TLM_MID), PP_MONITOR_Data.Pipe);
    }
    if (Status == CFE_SUCCESS)
    {
        Status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CFE_TIME_1HZ_CMD_MID), PP_MONITOR_Data.Pipe);
    }
    if (Status != CFE_SUCCESS || Rc != R2U2_OK)
    {
        CFE_ES_WriteToSysLog("PP_MONITOR: init failed 0x%08lX, R2U2 %d\n", (unsigned long)Status, (int)Rc);
        PP_MONITOR_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }
    else
    {
        CFE_EVS_SendEvent(PP_MONITOR_INIT_EID, CFE_EVS_EventType_INFORMATION,
                          "PP_MONITOR initialized, R2U2 %d.%d.%d, verdicts on 0x%04X", R2U2_C_VERSION_MAJOR,
                          R2U2_C_VERSION_MINOR, R2U2_C_VERSION_PATCH, (unsigned)PRISMPATH_APP_MONITOR_VERDICT_MID);
    }

    while (CFE_ES_RunLoop(&PP_MONITOR_Data.RunStatus))
    {
        Status = CFE_SB_ReceiveBuffer(&Buf, PP_MONITOR_Data.Pipe, CFE_SB_PEND_FOREVER);
        if (Status == CFE_SUCCESS)
        {
            CFE_SB_MsgId_t Mid = CFE_SB_INVALID_MSG_ID;
            CFE_MSG_GetMsgId(&Buf->Msg, &Mid);
            if (CFE_SB_MsgIdToValue(Mid) == PP_MONITOR_CMD_MID)
            {
                PP_MONITOR_Command(Buf);
            }
            else if (CFE_SB_MsgIdToValue(Mid) == SAMPLE_HK_TLM_MID)
            {
                PP_MONITOR_PayloadHk(Buf);
            }
            else if (CFE_SB_MsgIdToValue(Mid) == CFE_TIME_1HZ_CMD_MID)
            {
                PP_MONITOR_Step();
            }
        }
    }
    CFE_ES_ExitApp(PP_MONITOR_Data.RunStatus);
}
