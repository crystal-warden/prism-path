/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file
 *   The PrismPath command validation app for cFS: main header. */
#ifndef PRISMPATH_APP_H
#define PRISMPATH_APP_H

#include "cfe.h"

#include "prismpath_app_mission_cfg.h"
#include "prismpath_app_platform_cfg.h"
#include "prismpath_app_perfids.h"
#include "prismpath_app_msgids.h"
#include "prismpath_app_msg.h"
#include "prismpath_app_run.h"

typedef struct
{
    PRISMPATH_APP_HkTlm_t       HkTlm;
    PRISMPATH_APP_ProposedCmd_t VehicleCmd; /**< the republished command, built in static storage */
    uint32                      RunStatus;
    CFE_SB_PipeId_t             CommandPipe;
    CFE_TBL_Handle_t            TblHandle;
    CFE_SB_MsgId_t              CmdMid;
    CFE_SB_MsgId_t              SendHkMid;
    CFE_SB_MsgId_t              ProposedMid;
    CFE_SB_MsgId_t              VehicleMid;
    CFE_ES_CDSHandle_t          CdsHandle;
    bool                        HaveCds;
    PP_RunState_t               Run;          /**< the receipts and the version floor; the CDS's copy */
    PP_RunKeys_t                Keys;
    PP_PolicyTable_t            Active;       /**< the active table, as it was checked and activated */
    uint8                       ActiveDigest[32];
} PRISMPATH_APP_Data_t;

extern PRISMPATH_APP_Data_t PRISMPATH_APP_Data;

void         PRISMPATH_APP_Main(void);
CFE_Status_t PRISMPATH_APP_Init(void);

/** The table validation callback: the kernel's own checks on the candidate image. Returns CFE_SUCCESS to accept. */
int32 PRISMPATH_APP_TblValidationFunc(void *TblData);

#endif
