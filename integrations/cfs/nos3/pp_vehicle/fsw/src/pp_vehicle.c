/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   The vehicle side of the NOS3 scenario. It subscribes to PRISMPATH_APP_VEHICLE_CMD_MID, where the PrismPath app
 *   republishes only the commands it allowed, and turns each into the command of the NOS3 component app that drives
 *   the simulated hardware:
 *
 *     class 1, attitude: GENERIC_RW_APP_SET_TORQUE_CC on reaction wheel 0, slew_deg x 10^-4 N m
 *                        (the wheel app sends SET_TORQUE=<N m> to the wheel simulator over its UART)
 *     class 3, payload:  SAMPLE_CONFIG_CC with the proposal's tag as the configuration word
 *                        (the sample app sends the configuration command to the instrument simulator)
 *     class 2, thruster: this vehicle carries no thruster; the command is reported and dropped
 *
 *   It is the only app in the scenario that commands those two apps. It never reads PROPOSED_CMD.
 */
#include <string.h>

#include "cfe.h"
#include "prismpath_app_msgids.h"
#include "prismpath_app_msg.h"
#include "generic_reaction_wheel_msgids.h"
#include "generic_reaction_wheel_msg.h"
#include "sample_msgids.h"
#include "sample_msg.h"

#define PP_VEHICLE_INIT_EID     1
#define PP_VEHICLE_ATTITUDE_EID 10
#define PP_VEHICLE_PAYLOAD_EID  11
#define PP_VEHICLE_DROPPED_EID  12

static struct
{
    CFE_SB_PipeId_t     Pipe;
    uint32              RunStatus;
    uint32              Received;
    GENERIC_RW_Cmd_t    Torque;
    SAMPLE_Config_cmd_t Config;
} PP_VEHICLE_Data;

static void PP_VEHICLE_Attitude(const PRISMPATH_APP_ProposedCmd_t *Cmd)
{
    GENERIC_RW_Cmd_t *Out = &PP_VEHICLE_Data.Torque;

    memset(Out, 0, sizeof(*Out));
    CFE_MSG_Init(CFE_MSG_PTR(Out->CmdHeader), CFE_SB_ValueToMsgId(GENERIC_RW_APP_CMD_MID), sizeof(*Out));
    CFE_MSG_SetFcnCode(CFE_MSG_PTR(Out->CmdHeader), GENERIC_RW_APP_SET_TORQUE_CC);
    Out->wheel_number = 0;
    Out->data         = (int16)Cmd->SlewDeg;
    CFE_MSG_GenerateChecksum(CFE_MSG_PTR(Out->CmdHeader));
    CFE_EVS_SendEvent(PP_VEHICLE_ATTITUDE_EID, CFE_EVS_EventType_INFORMATION,
                      "PP_VEHICLE ATTITUDE tag=%u wheel=0 torque=%d (x 10^-4 N m)", Cmd->Spare, (int)Out->data);
    CFE_SB_TransmitMsg(CFE_MSG_PTR(Out->CmdHeader), true);
}

static void PP_VEHICLE_Payload(const PRISMPATH_APP_ProposedCmd_t *Cmd)
{
    SAMPLE_Config_cmd_t *Out = &PP_VEHICLE_Data.Config;

    memset(Out, 0, sizeof(*Out));
    CFE_MSG_Init(CFE_MSG_PTR(Out->CmdHeader), CFE_SB_ValueToMsgId(SAMPLE_CMD_MID), sizeof(*Out));
    CFE_MSG_SetFcnCode(CFE_MSG_PTR(Out->CmdHeader), SAMPLE_CONFIG_CC);
    Out->DeviceCfg = Cmd->Spare;
    CFE_MSG_GenerateChecksum(CFE_MSG_PTR(Out->CmdHeader));
    CFE_EVS_SendEvent(PP_VEHICLE_PAYLOAD_EID, CFE_EVS_EventType_INFORMATION, "PP_VEHICLE PAYLOAD tag=%u config=%lu",
                      Cmd->Spare, (unsigned long)Out->DeviceCfg);
    CFE_SB_TransmitMsg(CFE_MSG_PTR(Out->CmdHeader), true);
}

void PP_VEHICLE_Main(void)
{
    CFE_SB_Buffer_t *Buf;
    int32            Status;

    memset(&PP_VEHICLE_Data, 0, sizeof(PP_VEHICLE_Data));
    PP_VEHICLE_Data.RunStatus = CFE_ES_RunStatus_APP_RUN;
    CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    Status = CFE_SB_CreatePipe(&PP_VEHICLE_Data.Pipe, 16, "PP_VEHICLE_PIPE");
    if (Status == CFE_SUCCESS)
    {
        Status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(PRISMPATH_APP_VEHICLE_CMD_MID), PP_VEHICLE_Data.Pipe);
    }
    if (Status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("PP_VEHICLE: init failed 0x%08lX\n", (unsigned long)Status);
        PP_VEHICLE_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }
    else
    {
        CFE_EVS_SendEvent(PP_VEHICLE_INIT_EID, CFE_EVS_EventType_INFORMATION,
                          "PP_VEHICLE initialized, allowed commands from 0x%04X", (unsigned)PRISMPATH_APP_VEHICLE_CMD_MID);
    }

    while (CFE_ES_RunLoop(&PP_VEHICLE_Data.RunStatus))
    {
        size_t Size = 0;

        Status = CFE_SB_ReceiveBuffer(&Buf, PP_VEHICLE_Data.Pipe, CFE_SB_PEND_FOREVER);
        if (Status != CFE_SUCCESS)
        {
            continue;
        }
        CFE_MSG_GetSize(&Buf->Msg, &Size);
        if (Size < sizeof(PRISMPATH_APP_ProposedCmd_t))
        {
            continue;
        }
        const PRISMPATH_APP_ProposedCmd_t *Cmd = (const PRISMPATH_APP_ProposedCmd_t *)Buf;
        PP_VEHICLE_Data.Received++;
        switch (Cmd->CmdClass)
        {
            case 1:
                PP_VEHICLE_Attitude(Cmd);
                break;
            case 3:
                PP_VEHICLE_Payload(Cmd);
                break;
            default:
                CFE_EVS_SendEvent(PP_VEHICLE_DROPPED_EID, CFE_EVS_EventType_INFORMATION,
                                  "PP_VEHICLE DROPPED tag=%u class=%u: no such actuator on this vehicle", Cmd->Spare,
                                  Cmd->CmdClass);
                break;
        }
    }
    CFE_ES_ExitApp(PP_VEHICLE_Data.RunStatus);
}
