/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/* The few cFE and OSAL types and calls prismpath_app.c uses, for app_check.c to compile the app on a host with no cFS.
 * A command header is a CCSDS primary header (the message id in its first two bytes, its length less 7 in bytes 4
 * and 5) and a command secondary header (the function code, then the checksum), 8 bytes as cFE's. app_check.c
 * defines every call; the software bus records what is sent. */
#ifndef PP_STUB_CFE_H
#define PP_STUB_CFE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t  uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef int8_t   int8;
typedef int16_t  int16;
typedef int32_t  int32;
typedef int64_t  int64;

typedef int32 CFE_Status_t;
#define CFE_SUCCESS               ((CFE_Status_t)0)
#define CFE_SB_TIME_OUT           ((CFE_Status_t)0xCA00000E)
#define CFE_SB_BAD_ARGUMENT       ((CFE_Status_t)0xCA000003)
#define CFE_ES_CDS_ALREADY_EXISTS ((CFE_Status_t)0x4400000D)
#define CFE_TBL_INFO_UPDATED      ((CFE_Status_t)0x4C000001)

/* ----------------------------------------------------------------- messages */
typedef struct
{
    uint8 Byte[6];
} CFE_MSG_Message_t;
typedef struct
{
    CFE_MSG_Message_t Msg;
    uint8             Sec[2];
} CFE_MSG_CommandHeader_t;
typedef struct
{
    CFE_MSG_Message_t Msg;
    uint8             Sec[6];
    uint8             Spare[4];
} CFE_MSG_TelemetryHeader_t;
typedef union
{
    CFE_MSG_Message_t Msg;
    long long         Align;
    uint8             Bytes[512];
} CFE_SB_Buffer_t;
typedef size_t CFE_MSG_Size_t;
typedef uint8  CFE_MSG_FcnCode_t;
typedef uint32 CFE_SB_MsgId_Atom_t;
typedef uint32 CFE_SB_MsgId_t;
typedef uint32 CFE_SB_PipeId_t;
#define CFE_SB_INVALID_MSG_ID ((CFE_SB_MsgId_t)0)
#define CFE_SB_DEFAULT_QOS    0
#define CFE_MSG_PTR(shdr)     (&((shdr).Msg))

#define CFE_PLATFORM_CMD_TOPICID_TO_MIDV(topic) (0x1800u | (uint32)(topic))
#define CFE_PLATFORM_TLM_TOPICID_TO_MIDV(topic) (0x0800u | (uint32)(topic))

CFE_SB_MsgId_t      CFE_SB_ValueToMsgId(CFE_SB_MsgId_Atom_t Value);
CFE_SB_MsgId_Atom_t CFE_SB_MsgIdToValue(CFE_SB_MsgId_t MsgId);
bool                CFE_SB_MsgId_Equal(CFE_SB_MsgId_t A, CFE_SB_MsgId_t B);
CFE_Status_t        CFE_MSG_Init(CFE_MSG_Message_t *Msg, CFE_SB_MsgId_t MsgId, CFE_MSG_Size_t Size);
CFE_Status_t        CFE_MSG_GetSize(const CFE_MSG_Message_t *Msg, CFE_MSG_Size_t *Size);
CFE_Status_t        CFE_MSG_GetMsgId(const CFE_MSG_Message_t *Msg, CFE_SB_MsgId_t *MsgId);
CFE_Status_t        CFE_MSG_SetMsgId(CFE_MSG_Message_t *Msg, CFE_SB_MsgId_t MsgId);
CFE_Status_t        CFE_MSG_GetFcnCode(const CFE_MSG_Message_t *Msg, CFE_MSG_FcnCode_t *Fc);
CFE_Status_t        CFE_MSG_SetFcnCode(CFE_MSG_Message_t *Msg, CFE_MSG_FcnCode_t Fc);
CFE_Status_t        CFE_MSG_GenerateChecksum(CFE_MSG_Message_t *Msg);
CFE_Status_t        CFE_SB_TransmitMsg(const CFE_MSG_Message_t *Msg, bool IncrementSequence);
void                CFE_SB_TimeStampMsg(CFE_MSG_Message_t *Msg);
CFE_Status_t        CFE_SB_CreatePipe(CFE_SB_PipeId_t *Pipe, uint16 Depth, const char *Name);
CFE_Status_t        CFE_SB_SubscribeEx(CFE_SB_MsgId_t MsgId, CFE_SB_PipeId_t Pipe, int Qos, uint16 Limit);
CFE_Status_t        CFE_SB_ReceiveBuffer(CFE_SB_Buffer_t **Buf, CFE_SB_PipeId_t Pipe, int32 TimeOut);

/* ----------------------------------------------------------------- events, executive services, time, tables */
enum
{
    CFE_EVS_EventType_DEBUG = 1,
    CFE_EVS_EventType_INFORMATION,
    CFE_EVS_EventType_ERROR,
    CFE_EVS_EventType_CRITICAL
};
#define CFE_EVS_EventFilter_BINARY 0
CFE_Status_t CFE_EVS_Register(const void *Filters, uint16 N, uint16 Scheme);
CFE_Status_t CFE_EVS_SendEvent(uint16 EventID, uint16 EventType, const char *Spec, ...)
    __attribute__((format(printf, 3, 4)));

typedef uint32 CFE_ES_CDSHandle_t;
enum
{
    CFE_ES_RunStatus_APP_RUN = 1,
    CFE_ES_RunStatus_APP_EXIT,
    CFE_ES_RunStatus_APP_ERROR
};
#define CFE_PSP_RST_TYPE_PROCESSOR 1
#define CFE_PSP_RST_TYPE_POWERON   2
void         CFE_ES_WriteToSysLog(const char *Spec, ...) __attribute__((format(printf, 1, 2)));
CFE_Status_t CFE_ES_RegisterCDS(CFE_ES_CDSHandle_t *Handle, size_t Size, const char *Name);
CFE_Status_t CFE_ES_CopyToCDS(CFE_ES_CDSHandle_t Handle, const void *Data);
CFE_Status_t CFE_ES_RestoreFromCDS(void *Data, CFE_ES_CDSHandle_t Handle);
int32        CFE_ES_GetResetType(uint32 *Subtype);
bool         CFE_ES_RunLoop(uint32 *RunStatus);
void         CFE_ES_ExitApp(uint32 ExitStatus);
void         CFE_ES_PerfLogEntry(uint32 Id);
void         CFE_ES_PerfLogExit(uint32 Id);

typedef struct
{
    uint32 Seconds;
    uint32 Subseconds;
} CFE_TIME_SysTime_t;
CFE_TIME_SysTime_t CFE_TIME_GetMET(void);
CFE_TIME_SysTime_t CFE_TIME_GetUTC(void);
CFE_TIME_SysTime_t CFE_TIME_GetTime(void);
uint32             CFE_TIME_GetMETseconds(void);
uint32             CFE_TIME_Sub2MicroSecs(uint32 Subseconds);

typedef int32 CFE_TBL_Handle_t;
#define CFE_TBL_OPT_DEFAULT 0
#define CFE_TBL_SRC_ADDRESS 1
typedef int32 (*CFE_TBL_CallbackFuncPtr_t)(void *TblPtr);
CFE_Status_t CFE_TBL_Register(CFE_TBL_Handle_t *Handle, const char *Name, size_t Size, uint16 Options,
                              CFE_TBL_CallbackFuncPtr_t Validate);
CFE_Status_t CFE_TBL_Load(CFE_TBL_Handle_t Handle, int SrcType, const void *Src);
CFE_Status_t CFE_TBL_Manage(CFE_TBL_Handle_t Handle);

/* ----------------------------------------------------------------- OSAL files */
typedef int32 osal_id_t;
typedef struct
{
    size_t FileSize;
} os_fstat_t;
#define OS_SUCCESS            0
#define OS_MAX_PATH_LEN       256
#define OS_READ_ONLY          0
#define OS_WRITE_ONLY         1
#define OS_FILE_FLAG_NONE     0
#define OS_FILE_FLAG_CREATE   1
#define OS_FILE_FLAG_TRUNCATE 2
#define OS_SEEK_END           2
#define OS_FILESTAT_SIZE(st)  ((st).FileSize)
int32 OS_OpenCreate(osal_id_t *Fd, const char *Path, int32 Flags, int32 Access);
int32 OS_close(osal_id_t Fd);
int32 OS_read(osal_id_t Fd, void *Buf, size_t Len);
int32 OS_write(osal_id_t Fd, const void *Buf, size_t Len);
int32 OS_lseek(osal_id_t Fd, int32 Offset, uint32 Whence);
int32 OS_stat(const char *Path, os_fstat_t *St);
int32 OS_rename(const char *Old, const char *New);
int32 OS_mkdir(const char *Path, uint32 Access);

#endif
