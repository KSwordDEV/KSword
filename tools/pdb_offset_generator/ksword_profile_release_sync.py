#!/usr/bin/env python3
"""
Validate and publish KswordARK DynData profiles.

Inputs:
- A private corpus directory, normally D:\\PDB\\profiles\\ark_dyndata.
- A KswordARK release root, normally the directory containing Ksword5.1.exe.
- Optional local ntoskrnl.exe path for an identity match smoke test.

Processing:
- Parse every JSON profile and enforce the same schema assumptions used by the
  R3 KernelDock loader and R0 packed profile apply protocol.
- Reject profiles with missing module identity, no usable fields/items, unknown
  fields, or offsets outside the shared protocol range.
- Validate the v4 item matrix and capability groups using shared names, stable
  IDs, allowed item kinds, and safe uint32 payload ranges.
- Deduplicate profiles by the R0 identity tuple used for safe apply:
  module class, machine, TimeDateStamp, and SizeOfImage.
- Copy only accepted profile JSON files into Release\\profiles\\ark_dyndata
  when scattered JSON publishing is requested.
- Emit one compact Release\\profiles\\ark_dyndata_pack_v4.json pack. Legacy
  fields and typed-item mirrors are projected once and omitted from the pack.
- Write a manifest outside the scanned JSON directory so KernelDock does not
  attempt to parse the manifest as a scattered runtime profile.

Returns:
- Process exit code 0 when validation and optional copy complete.
- Non-zero exit code when the source directory is missing or no publishable
  profiles remain.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

def load_protocol_constants() -> tuple[dict[str, int], set[int]]:
    """Read IDs and the accepted special-item catalog from the R0/R3 protocol."""
    header = Path(__file__).resolve().parents[2] / "shared/driver/KswordArkDynDataIoctl.h"
    text = header.read_text(encoding="utf-8-sig")
    definitions = dict(re.findall(r"^#define\s+(KSW_\w+)\s+(\w+)", text, re.MULTILINE))
    values: dict[str, int] = {}
    for name in definitions:
        token = definitions[name]
        while token in definitions:
            token = definitions[token]
        try:
            values[name] = int(token.rstrip("ULul"), 0)
        except ValueError:
            continue
    catalog = text.split("#define KSW_DYN_V4_SUPPORTED_SPECIAL_ITEMS(X)", 1)[1].split("\n\n", 1)[0]
    special = {values[name] for name in re.findall(r"X\((KSW_\w+)\)", catalog)}
    return values, set(range(1, values["KSW_DYN_FIELD_ID_MAX"] + 1)) | special


PROTOCOL_CONSTANTS, SUPPORTED_V4_ITEM_IDS = load_protocol_constants()

DEFAULT_SOURCE_DIR = Path(r"D:\PDB\profiles\ark_dyndata")
DEFAULT_LOCAL_KERNEL = Path(r"C:\Windows\System32\ntoskrnl.exe")
KSW_PACK_VERSION_V4 = 4
KSW_DEFAULT_PACK_VERSION = KSW_PACK_VERSION_V4
# v4 is the only release format.
KSW_SUPPORTED_PACK_VERSIONS = (KSW_PACK_VERSION_V4,)
DEFAULT_PACK_FILE_NAMES = {
    KSW_PACK_VERSION_V4: "ark_dyndata_pack_v4.json",
}
DEFAULT_PACK_FILE_NAME = DEFAULT_PACK_FILE_NAMES[KSW_DEFAULT_PACK_VERSION]
KSW_DYN_PROFILE_OFFSET_MAX = PROTOCOL_CONSTANTS["KSW_DYN_PROFILE_OFFSET_MAX"]
KSW_DYN_PROFILE_GLOBAL_RVA_MAX = PROTOCOL_CONSTANTS["KSW_DYN_PROFILE_GLOBAL_RVA_MAX"]
KSW_SCHEMA_VERSION = 1
KSW_PACK_VERSION = KSW_DEFAULT_PACK_VERSION

CALLBACK_ITEM_KIND_GLOBAL_RVA = "GlobalRva"
CALLBACK_ITEM_KIND_STRUCT_OFFSET = "StructOffset"
CALLBACK_ITEM_KIND_TYPE_SIZE = "TypeSize"
CALLBACK_ITEM_KINDS = {CALLBACK_ITEM_KIND_GLOBAL_RVA, CALLBACK_ITEM_KIND_STRUCT_OFFSET, CALLBACK_ITEM_KIND_TYPE_SIZE}

# These names mirror the KSW_DYN_FIELD_ID_CB_* field-id additions in
# shared/driver/KswordArkDynDataIoctl.h. The numeric values are kept here as
# validation evidence and to catch duplicate aliases that target the same shared
# callback field ID before a bad source item reaches the v4 pack.
CALLBACK_GLOBAL_RVA_FIELD_IDS = {
    "PspCreateProcessNotifyRoutine": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_PSP_CREATE_PROCESS_NOTIFY_ROUTINE"],
    "PspCreateThreadNotifyRoutine": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_PSP_CREATE_THREAD_NOTIFY_ROUTINE"],
    "PspLoadImageNotifyRoutine": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_PSP_LOAD_IMAGE_NOTIFY_ROUTINE"],
    "PspNotifyEnableMask": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_PSP_NOTIFY_ENABLE_MASK"],
    "CmCallbackListHead": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_CM_CALLBACK_LIST_HEAD"],
}

KERNEL_GLOBAL_RVA_FIELD_IDS = {
    "PspCidTable": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KG_PSP_CID_TABLE"],
    "PsLoadedModuleList": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KG_PS_LOADED_MODULE_LIST"],
    "MmUnloadedDrivers": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KG_MM_UNLOADED_DRIVERS"],
    "PiDDBCacheTable": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KG_PIDDB_CACHE_TABLE"],
    "PiDDBLock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KG_PIDDB_LOCK"],
    "KeServiceDescriptorTableShadow": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KG_KE_SERVICE_DESCRIPTOR_TABLE_SHADOW"],
    "MmLastUnloadedDriver": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KG_MM_LAST_UNLOADED_DRIVER"],
    "PiDDBLock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KG_PIDDB_LOCK"],
}

CALLBACK_STRUCT_OFFSET_FIELD_IDS = {
    "_OBJECT_TYPE.CallbackList": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_OBJECT_TYPE_CALLBACK_LIST"],
    "_CALLBACK_ENTRY_ITEM.EntryList": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_ENTRY_LIST"],
    "_CALLBACK_ENTRY_ITEM.PreOperation": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_PRE_OPERATION"],
    "_CALLBACK_ENTRY_ITEM.PostOperation": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_POST_OPERATION"],
    "_CALLBACK_ENTRY_ITEM.Operations": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_OPERATIONS"],
    "_CALLBACK_ENTRY_ITEM.CallbackEntry": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_CALLBACK_ENTRY"],
    "_CALLBACK_ENTRY.Altitude": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ALTITUDE"],
    "_CALLBACK_ENTRY.RegistrationContext": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_REGISTRATION_CONTEXT"],
}

KNOWN_FIELD_IDS = {
    "EpObjectTable": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_OBJECT_TABLE"],
    "EpSectionObject": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_SECTION_OBJECT"],
    "HtHandleContentionEvent": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_HT_HANDLE_CONTENTION_EVENT"],
    "OtName": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_OT_NAME"],
    "OtIndex": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_OT_INDEX"],
    "ObDecodeShift": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_OB_DECODE_SHIFT"],
    "ObAttributesShift": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_OB_ATTRIBUTES_SHIFT"],
    "KtInitialStack": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KT_INITIAL_STACK"],
    "KtStackLimit": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KT_STACK_LIMIT"],
    "KtStackBase": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KT_STACK_BASE"],
    "KtKernelStack": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KT_KERNEL_STACK"],
    "KtReadOperationCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KT_READ_OPERATION_COUNT"],
    "KtWriteOperationCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KT_WRITE_OPERATION_COUNT"],
    "KtOtherOperationCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KT_OTHER_OPERATION_COUNT"],
    "KtReadTransferCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KT_READ_TRANSFER_COUNT"],
    "KtWriteTransferCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KT_WRITE_TRANSFER_COUNT"],
    "KtOtherTransferCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KT_OTHER_TRANSFER_COUNT"],
    "MmSectionControlArea": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_MM_SECTION_CONTROL_AREA"],
    "MmControlAreaListHead": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_MM_CONTROL_AREA_LIST_HEAD"],
    "MmControlAreaLock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_MM_CONTROL_AREA_LOCK"],
    "AlpcCommunicationInfo": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_COMMUNICATION_INFO"],
    "AlpcOwnerProcess": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_OWNER_PROCESS"],
    "AlpcConnectionPort": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_CONNECTION_PORT"],
    "AlpcServerCommunicationPort": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_SERVER_COMMUNICATION_PORT"],
    "AlpcClientCommunicationPort": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_CLIENT_COMMUNICATION_PORT"],
    "AlpcHandleTable": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_HANDLE_TABLE"],
    "AlpcHandleTableLock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_HANDLE_TABLE_LOCK"],
    "AlpcAttributes": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_ATTRIBUTES"],
    "AlpcAttributesFlags": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_ATTRIBUTES_FLAGS"],
    "AlpcPortContext": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_PORT_CONTEXT"],
    "AlpcPortObjectLock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_PORT_OBJECT_LOCK"],
    "AlpcSequenceNo": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_SEQUENCE_NO"],
    "AlpcState": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ALPC_STATE"],
    "LxPicoProc": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_LX_PICO_PROC"],
    "LxPicoProcInfo": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO"],
    "LxPicoProcInfoPID": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO_PID"],
    "LxPicoThrdInfo": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO"],
    "LxPicoThrdInfoTID": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO_TID"],
    "EpProtection": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_PROTECTION"],
    "EpSignatureLevel": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_SIGNATURE_LEVEL"],
    "EpSectionSignatureLevel": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_SECTION_SIGNATURE_LEVEL"],
    "EgeGuid": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EGE_GUID"],
    "EreGuidEntry": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ERE_GUID_ENTRY"],
    "EpUniqueProcessId": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID"],
    "EpActiveProcessLinks": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS"],
    "EpThreadListHead": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD"],
    "EpImageFileName": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_IMAGE_FILE_NAME"],
    "EpToken": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_TOKEN"],
    "EpFlags": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_FLAGS"],
    "EpFlags2": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_FLAGS2"],
    "EpRundownProtect": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_RUNDOWN_PROTECT"],
    "EpProcessLock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_PROCESS_LOCK"],
    "EpCreateTime": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_CREATE_TIME"],
    "EpExitTime": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_EXIT_TIME"],
    "EpExitStatus": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_EXIT_STATUS"],
    "EpPeb": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_PEB"],
    "EpSession": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_SESSION"],
    "EpWin32Process": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_WIN32_PROCESS"],
    "EpWow64Process": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_WOW64_PROCESS"],
    "EpInheritedFromUniqueProcessId": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_INHERITED_FROM_UNIQUE_PROCESS_ID"],
    "EpSeAuditProcessCreationInfo": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_SE_AUDIT_PROCESS_CREATION_INFO"],
    "EpJob": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_JOB"],
    "EpDeviceMap": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_DEVICE_MAP"],
    "EpDebugPort": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_DEBUG_PORT"],
    "EpExceptionPortData": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_EXCEPTION_PORT_DATA"],
    "EpSectionBaseAddress": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_SECTION_BASE_ADDRESS"],
    "EpImageFilePointer": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_IMAGE_FILE_POINTER"],
    "EpPriorityClass": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_PRIORITY_CLASS"],
    "EpActiveThreads": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS"],
    "EpVadRoot": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_VAD_ROOT"],
    "EpVadHint": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_VAD_HINT"],
    "EpCloneRoot": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_CLONE_ROOT"],
    "EpNumberOfPrivatePages": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_NUMBER_OF_PRIVATE_PAGES"],
    "EpNumberOfLockedPages": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_NUMBER_OF_LOCKED_PAGES"],
    "EpCommitCharge": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE"],
    "EpCommitChargePeak": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_PEAK"],
    "EpPeakVirtualSize": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_PEAK_VIRTUAL_SIZE"],
    "EpVirtualSize": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_VIRTUAL_SIZE"],
    "EpSessionProcessLinks": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_SESSION_PROCESS_LINKS"],
    "EpMitigationFlags": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS"],
    "EpMitigationFlags2": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS2"],
    "EpProcessQuotaUsage": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_USAGE"],
    "EpProcessQuotaPeak": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_PEAK"],
    "EpAddressCreationLock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_ADDRESS_CREATION_LOCK"],
    "EpPageTableCommitmentLock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_PAGE_TABLE_COMMITMENT_LOCK"],
    "EpRotateInProgress": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_ROTATE_IN_PROGRESS"],
    "EpForkInProgress": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_FORK_IN_PROGRESS"],
    "EpCommitChargeJob": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_JOB"],
    "EpCookie": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_COOKIE"],
    "EpWorkingSetWatch": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_WORKING_SET_WATCH"],
    "EpWin32WindowStation": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_WIN32_WINDOW_STATION"],
    "EpOwnerProcessId": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_OWNER_PROCESS_ID"],
    "EpQuotaBlock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_QUOTA_BLOCK"],
    "EpEtwDataSource": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_ETW_DATA_SOURCE"],
    "EpPageDirectoryPte": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_PAGE_DIRECTORY_PTE"],
    "EpSecurityPort": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_SECURITY_PORT"],
    "EpJobLinks": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_JOB_LINKS"],
    "EpHighestUserAddress": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_HIGHEST_USER_ADDRESS"],
    "EpImagePathHash": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_IMAGE_PATH_HASH"],
    "EpDefaultHardErrorProcessing": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_DEFAULT_HARD_ERROR_PROCESSING"],
    "EpLastThreadExitStatus": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_LAST_THREAD_EXIT_STATUS"],
    "EpPrefetchTrace": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_PREFETCH_TRACE"],
    "EpLockedPagesList": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_LOCKED_PAGES_LIST"],
    "EpReadOperationCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_READ_OPERATION_COUNT"],
    "EpWriteOperationCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_WRITE_OPERATION_COUNT"],
    "EpOtherOperationCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_OTHER_OPERATION_COUNT"],
    "EpReadTransferCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_READ_TRANSFER_COUNT"],
    "EpWriteTransferCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_WRITE_TRANSFER_COUNT"],
    "EpOtherTransferCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_OTHER_TRANSFER_COUNT"],
    "EpCommitChargeLimit": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_LIMIT"],
    "EpVm": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_VM"],
    "EpMmProcessLinks": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_MM_PROCESS_LINKS"],
    "EpModifiedPageCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_MODIFIED_PAGE_COUNT"],
    "EpVadCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_VAD_COUNT"],
    "EpVadPhysicalPages": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES"],
    "EpVadPhysicalPagesLimit": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES_LIMIT"],
    "EpAlpcContext": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_ALPC_CONTEXT"],
    "EpTimerResolutionLink": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_LINK"],
    "EpTimerResolutionStackRecord": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_STACK_RECORD"],
    "EpRequestedTimerResolution": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_REQUESTED_TIMER_RESOLUTION"],
    "EpSmallestTimerResolution": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_SMALLEST_TIMER_RESOLUTION"],
    "EpInvertedFunctionTable": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE"],
    "EpInvertedFunctionTableLock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE_LOCK"],
    "EpActiveThreadsHighWatermark": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS_HIGH_WATERMARK"],
    "EpLargePrivateVadCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_LARGE_PRIVATE_VAD_COUNT"],
    "EpThreadListLock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_THREAD_LIST_LOCK"],
    "EpWnfContext": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_WNF_CONTEXT"],
    "EpFlags3": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_FLAGS3"],
    "EpDiskCounters": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_EP_DISK_COUNTERS"],
    "TokTokenSource": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_TOKEN_SOURCE"],
    "TokTokenId": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_TOKEN_ID"],
    "TokAuthenticationId": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_AUTHENTICATION_ID"],
    "TokParentTokenId": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_PARENT_TOKEN_ID"],
    "TokExpirationTime": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_EXPIRATION_TIME"],
    "TokTokenLock": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_TOKEN_LOCK"],
    "TokModifiedId": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_MODIFIED_ID"],
    "TokPrivileges": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_PRIVILEGES"],
    "TokAuditPolicy": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_AUDIT_POLICY"],
    "TokSessionId": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_SESSION_ID"],
    "TokUserAndGroupCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_USER_AND_GROUP_COUNT"],
    "TokRestrictedSidCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_COUNT"],
    "TokVariableLength": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_VARIABLE_LENGTH"],
    "TokDynamicCharged": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_DYNAMIC_CHARGED"],
    "TokDynamicAvailable": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_DYNAMIC_AVAILABLE"],
    "TokDefaultOwnerIndex": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_DEFAULT_OWNER_INDEX"],
    "TokUserAndGroups": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_USER_AND_GROUPS"],
    "TokRestrictedSids": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_RESTRICTED_SIDS"],
    "TokPrimaryGroup": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_PRIMARY_GROUP"],
    "TokDynamicPart": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_DYNAMIC_PART"],
    "TokDefaultDacl": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_DEFAULT_DACL"],
    "TokTokenType": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_TOKEN_TYPE"],
    "TokImpersonationLevel": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_IMPERSONATION_LEVEL"],
    "TokTokenFlags": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_TOKEN_FLAGS"],
    "TokTokenInUse": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_TOKEN_IN_USE"],
    "TokIntegrityLevelIndex": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_INDEX"],
    "TokMandatoryPolicy": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_MANDATORY_POLICY"],
    "TokLogonSession": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_LOGON_SESSION"],
    "TokOriginatingLogonSession": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_ORIGINATING_LOGON_SESSION"],
    "TokSidHash": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_SID_HASH"],
    "TokRestrictedSidHash": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_HASH"],
    "TokPSecurityAttributes": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_P_SECURITY_ATTRIBUTES"],
    "TokPackage": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_PACKAGE"],
    "TokCapabilities": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_CAPABILITIES"],
    "TokCapabilityCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_CAPABILITY_COUNT"],
    "TokCapabilitiesHash": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_CAPABILITIES_HASH"],
    "TokLowboxNumberEntry": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_LOWBOX_NUMBER_ENTRY"],
    "TokLowboxHandlesEntry": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_LOWBOX_HANDLES_ENTRY"],
    "TokPClaimAttributes": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_P_CLAIM_ATTRIBUTES"],
    "TokTrustLevelSid": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_TRUST_LEVEL_SID"],
    "TokTrustLinkedToken": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_TRUST_LINKED_TOKEN"],
    "TokIntegrityLevelSidValue": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_SID_VALUE"],
    "TokTokenSidValues": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_TOKEN_SID_VALUES"],
    "TokSessionObject": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_SESSION_OBJECT"],
    "TokVariablePart": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_TOK_VARIABLE_PART"],
    "EtCid": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ET_CID"],
    "EtThreadListEntry": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY"],
    "EtStartAddress": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ET_START_ADDRESS"],
    "EtWin32StartAddress": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ET_WIN32_START_ADDRESS"],
    "KtProcess": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KT_PROCESS"],
    "HtTableCode": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_HT_TABLE_CODE"],
    "HtHandleCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_HT_HANDLE_COUNT"],
    "HteLowValue": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_HTE_LOW_VALUE"],
    "KldrInLoadOrderLinks": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KLDR_IN_LOAD_ORDER_LINKS"],
    "KldrDllBase": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KLDR_DLL_BASE"],
    "KldrSizeOfImage": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KLDR_SIZE_OF_IMAGE"],
    "KldrFullDllName": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KLDR_FULL_DLL_NAME"],
    "KldrBaseDllName": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KLDR_BASE_DLL_NAME"],
    "KldrFlags": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_KLDR_FLAGS"],
    "DoDriverStart": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_DO_DRIVER_START"],
    "DoDriverSize": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_DO_DRIVER_SIZE"],
    "DoDriverSection": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_DO_DRIVER_SECTION"],
    "DoMajorFunction": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_DO_MAJOR_FUNCTION"],
    "DoFastIoDispatch": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_DO_FAST_IO_DISPATCH"],
    "DoDriverUnload": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_DO_DRIVER_UNLOAD"],
    "UldName": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ULD_NAME"],
    "UldStartAddress": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ULD_START_ADDRESS"],
    "UldEndAddress": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ULD_END_ADDRESS"],
    "UldCurrentTime": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ULD_CURRENT_TIME"],
    "UldTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_ULD_TYPE_SIZE"],
    "RtlAvlBalancedRoot": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_RTL_AVL_BALANCED_ROOT"],
    "RtlAvlOrderedPointer": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_RTL_AVL_ORDERED_POINTER"],
    "RtlAvlWhichOrderedElement": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_RTL_AVL_WHICH_ORDERED_ELEMENT"],
    "RtlAvlNumberGenericTableElements": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_RTL_AVL_NUMBER_GENERIC_TABLE_ELEMENTS"],
    "RtlAvlDepthOfTree": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_RTL_AVL_DEPTH_OF_TREE"],
    "RtlAvlRestartKey": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_RTL_AVL_RESTART_KEY"],
    "RtlAvlDeleteCount": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_RTL_AVL_DELETE_COUNT"],
    "RtlAvlTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_RTL_AVL_TYPE_SIZE"],
    "PiDdbDriverName": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_PIDDB_DRIVER_NAME"],
    "PiDdbTimeDateStamp": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_PIDDB_TIME_DATE_STAMP"],
    "PiDdbLoadStatus": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_PIDDB_LOAD_STATUS"],
    "PiDdbTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_FIELD_ID_PIDDB_TYPE_SIZE"],
}

LXCORE_FIELD_NAMES = {
    "LxPicoProc",
    "LxPicoProcInfo",
    "LxPicoProcInfoPID",
    "LxPicoThrdInfo",
    "LxPicoThrdInfoTID",
}

TYPED_KERNEL_STRUCT_OFFSET_FIELD_IDS = {
    name: field_id
    for name, field_id in KNOWN_FIELD_IDS.items()
    if name not in LXCORE_FIELD_NAMES and not name.endswith("TypeSize")
}

TYPED_TYPE_SIZE_FIELD_IDS = {
    name: field_id
    for name, field_id in KNOWN_FIELD_IDS.items()
    if name.endswith("TypeSize")
}

# The generator historically emitted the concrete PDB member spelling
# EntryItemList. The shared protocol field name is EntryList, so release sync
# accepts the generator spelling as an input alias and writes the canonical name
# to the canonical v4 item name.
CALLBACK_NAME_ALIASES = {
    "_CALLBACK_ENTRY_ITEM.EntryItemList": "_CALLBACK_ENTRY_ITEM.EntryList",
}

CALLBACK_FIELD_IDS = {
    **CALLBACK_GLOBAL_RVA_FIELD_IDS,
    **CALLBACK_STRUCT_OFFSET_FIELD_IDS,
    **{alias: CALLBACK_STRUCT_OFFSET_FIELD_IDS[canonical] for alias, canonical in CALLBACK_NAME_ALIASES.items()},
}

GLOBAL_RVA_FIELD_IDS = {
    **CALLBACK_GLOBAL_RVA_FIELD_IDS,
    **KERNEL_GLOBAL_RVA_FIELD_IDS,
}

TYPED_STRUCT_OFFSET_FIELD_IDS = {
    **TYPED_KERNEL_STRUCT_OFFSET_FIELD_IDS,
    **CALLBACK_STRUCT_OFFSET_FIELD_IDS,
    **{alias: CALLBACK_STRUCT_OFFSET_FIELD_IDS[canonical] for alias, canonical in CALLBACK_NAME_ALIASES.items()},
}

CALLBACK_KIND_BY_NAME = {
    **{name: CALLBACK_ITEM_KIND_GLOBAL_RVA for name in CALLBACK_GLOBAL_RVA_FIELD_IDS},
    **{name: CALLBACK_ITEM_KIND_STRUCT_OFFSET for name in CALLBACK_STRUCT_OFFSET_FIELD_IDS},
    **{alias: CALLBACK_ITEM_KIND_STRUCT_OFFSET for alias in CALLBACK_NAME_ALIASES},
}

CALLBACK_CANONICAL_NAME_BY_NAME = {
    **{name: name for name in CALLBACK_GLOBAL_RVA_FIELD_IDS},
    **{name: name for name in CALLBACK_STRUCT_OFFSET_FIELD_IDS},
    **CALLBACK_NAME_ALIASES,
}

KNOWN_FIELD_NAMES = set(KNOWN_FIELD_IDS)

V4_ITEM_KIND_IDS = {
    "StructOffset": 1,
    "GlobalRva": 2,
    "FunctionRva": 3,
    "EnumValue": 4,
    "TypeSize": 5,
    "BitField": 6,
    "ListHeadGlobal": 7,
}
V4_ITEM_KIND_NAMES = set(V4_ITEM_KIND_IDS)
V4_CORE_GROUP_ID = 1
V4_TIMER_GROUP_ID = 2
V4_FLTMGR_MINIFILTER_GROUP_ID = 3
V4_CI_KERNEL_HASH_GROUP_ID = 4
V4_WORK_QUEUE_GROUP_ID = 5
V4_FIXED_CAPABILITY_GROUP_COUNTS = {
    # 1004/1006 were never consumed by the timer snapshot.  Keep their
    # protocol IDs reserved, but do not generate them or count them here.
    V4_TIMER_GROUP_ID: (15, 0),
    V4_FLTMGR_MINIFILTER_GROUP_ID: (1, 0),
    V4_CI_KERNEL_HASH_GROUP_ID: (5, 4),
    V4_WORK_QUEUE_GROUP_ID: (23, 0),
}
V4_SPECIAL_ITEM_IDS = {
    "PspTerminateProcess": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_PSP_TERMINATE_PROCESS"],
    "EthActiveExWorker": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_ETH_ACTIVE_EX_WORKER"],
    "KprcbTimerTable": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KPRCB_TIMER_TABLE"],
    "KtimerTableTimerEntries": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_TIMER_ENTRIES"],
    # 1004 reserved: KtimerTableEntryLock had no runtime consumer.
    "KtimerTableEntryEntry": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_ENTRY"],
    # 1006 reserved: KtimerTableEntryTime had no runtime consumer.
    "KtimerTimerListEntry": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KTIMER_TIMER_LIST_ENTRY"],
    "KtimerDueTime": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KTIMER_DUE_TIME"],
    "KtimerDpc": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KTIMER_DPC"],
    "KtimerTimerType": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KTIMER_TIMER_TYPE"],
    "KtimerPeriod": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KTIMER_PERIOD"],
    "KdpcDeferredRoutine": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KDPC_DEFERRED_ROUTINE"],
    "KdpcDeferredContext": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KDPC_DEFERRED_CONTEXT"],
    "KtimerTableTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_TYPE_SIZE"],
    "KtimerTableEntryTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_TYPE_SIZE"],
    "KtimerTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KTIMER_TYPE_SIZE"],
    "KdpcTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_KDPC_TYPE_SIZE"],
    "FltFilterOperations": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_FLT_FILTER_OPERATIONS"],
    "CiKernelHashBucketList": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_CI_KERNEL_HASH_BUCKET_LIST"],
    "CiHashCacheLock": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_CI_HASH_CACHE_LOCK"],
    "CiHashEntryNext": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_NEXT"],
    "CiHashEntryDriverName": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_DRIVER_NAME"],
    "CiHashEntryTimeDateStamp": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_TIME_DATE_STAMP"],
    "CiHashEntryLoadStatus": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_LOAD_STATUS"],
    "CiHashEntryImageBase": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_IMAGE_BASE"],
    "CiHashEntryImageSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_IMAGE_SIZE"],
    "CiHashEntryTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_TYPE_SIZE"],
    "WqPspSystemPartition": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_PSP_SYSTEM_PARTITION"],
    "WqExpBuiltinPriorities": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_EXP_BUILTIN_PRIORITIES"],
    "WqEpartitionExPartition": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_EPARTITION_EX_PARTITION"],
    "WqExPartitionWorkQueues": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_EX_PARTITION_WORK_QUEUES"],
    "WqExWorkQueueWorkPriQueue": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_WORK_PRI_QUEUE"],
    "WqExWorkQueueQueueIndex": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_QUEUE_INDEX"],
    "WqKpriQueueEntryListHead": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_ENTRY_LIST_HEAD"],
    "WqKpriQueueThreadListHead": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_THREAD_LIST_HEAD"],
    "WqKthreadQueue": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_QUEUE"],
    "WqKthreadQueueListEntry": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_QUEUE_LIST_ENTRY"],
    "WqWorkItemList": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_LIST"],
    "WqWorkItemRoutine": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_ROUTINE"],
    "WqWorkItemParameter": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_PARAMETER"],
    "WqExPoolUntrusted": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_EX_POOL_UNTRUSTED"],
    "WqEpartitionTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_EPARTITION_TYPE_SIZE"],
    "WqExPartitionTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_EX_PARTITION_TYPE_SIZE"],
    "WqExWorkQueueTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_TYPE_SIZE"],
    "WqKpriQueueTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_TYPE_SIZE"],
    "WqKthreadTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_TYPE_SIZE"],
    "WqWorkItemTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_TYPE_SIZE"],
    "WqEthreadStartAddress": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_START_ADDRESS"],
    "WqEthreadTypeSize": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_TYPE_SIZE"],
    "WqEthreadTcb": PROTOCOL_CONSTANTS["KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_TCB"],
}
V4_ITEM_IDS_BY_NAME = {**KNOWN_FIELD_IDS, **V4_SPECIAL_ITEM_IDS}
V4_CORE_ITEM_IDS = {
    **KNOWN_FIELD_IDS,
    **GLOBAL_RVA_FIELD_IDS,
    **CALLBACK_STRUCT_OFFSET_FIELD_IDS,
    **TYPED_TYPE_SIZE_FIELD_IDS,
}
V4_SPECIAL_ITEM_GROUPS = {
    **{
        name: V4_TIMER_GROUP_ID
        for name in V4_SPECIAL_ITEM_IDS
        if name != "FltFilterOperations" and
        not name.startswith("Ci") and
        not name.startswith("Wq")
    },
    "FltFilterOperations": V4_FLTMGR_MINIFILTER_GROUP_ID,
    **{name: V4_CI_KERNEL_HASH_GROUP_ID for name in V4_SPECIAL_ITEM_IDS if name.startswith("Ci")},
    **{name: V4_WORK_QUEUE_GROUP_ID for name in V4_SPECIAL_ITEM_IDS if name.startswith("Wq")},
    "PspTerminateProcess": V4_CORE_GROUP_ID,
}


@dataclass(frozen=True)
class ProfileIdentity:
    """Stable identity tuple used by R3/R0 profile matching.

    Inputs:
    - module_class: Ksword module class text, for example ntoskrnl or ntkrla57.
    - machine/time_date_stamp/size_of_image: PE identity fields.

    Processing:
    - The dataclass is frozen and hashable so it can be used as a dictionary key.

    Return behavior:
    - Instances do not perform I/O; callers use them for exact comparisons.
    """

    module_class: str
    machine: int
    time_date_stamp: int
    size_of_image: int


@dataclass
class ProfileRecord:
    """One validated profile candidate.

    Inputs:
    - path: Source JSON profile path.
    - data: Parsed JSON dictionary.
    - identity: R0-safe identity tuple.
    - field_count: Number of accepted fields.
    - callback_items: Validated callback v2 items normalized for pack output.
    - typed_items: Validated v3 typed items normalized for pack output.
    - missing_fields/missing_globals/coverage_percent: Coverage report values
      propagated from the generator or computed from the accepted payload.

    Processing:
    - The record keeps enough metadata for deduplication, pack generation, and
      manifest output.

    Return behavior:
    - Instances are plain data containers and do not copy files by themselves.
    """

    path: Path
    data: dict[str, Any]
    identity: ProfileIdentity
    field_count: int
    callback_items: list[dict[str, Any]] = field(default_factory=list)
    typed_items: list[dict[str, Any]] = field(default_factory=list)
    v4_items: list[dict[str, Any]] = field(default_factory=list)
    idt_baseline: dict[str, Any] | None = None
    missing_fields: list[str] = field(default_factory=list)
    missing_globals: list[str] = field(default_factory=list)
    coverage_percent: float = 0.0

    @property
    def profile_name(self) -> str:
        """Return the human-readable profileName, or the file stem if missing."""
        value = self.data.get("profileName")
        return str(value) if value else self.path.stem


@dataclass
class ValidationState:
    """Validation accumulator for one publish pass.

    Inputs:
    - accepted: publishable profiles after schema validation but before dedup.
    - rejected: rejected file records with reasons.
    - duplicate_groups: duplicate identity groups observed during dedup.

    Processing:
    - Callers append records while scanning and then build a manifest from it.

    Return behavior:
    - The object is mutated by scanner helpers and returned to the caller.
    """

    accepted: list[ProfileRecord] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)
    duplicate_groups: list[dict[str, Any]] = field(default_factory=list)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options and return an argparse namespace."""
    parser = argparse.ArgumentParser(description="Validate and publish KswordARK DynData JSON profiles.")
    parser.add_argument("--source", default=str(DEFAULT_SOURCE_DIR), help="Directory containing generated JSON profiles.")
    parser.add_argument(
        "--release-root",
        default=str(Path("Ksword5.1") / "Ksword5.1" / "x64" / "Release"),
        help="KswordARK release root that contains Ksword5.1.exe.",
    )
    parser.add_argument("--local-kernel", default=str(DEFAULT_LOCAL_KERNEL), help="Optional ntoskrnl.exe path for match smoke test.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and write reports without copying profiles.")
    parser.add_argument("--clean-target", action="store_true", help="Move stale scattered profiles to the temporary archive before copying.")
    parser.add_argument("--max-copy", type=int, default=0, help="Copy at most N accepted profiles; 0 means all.")
    parser.add_argument("--manifest", default="", help="Manifest path; defaults to <release-root>\\profiles\\ark_dyndata_manifest.json.")
    parser.add_argument("--report", default=str(Path(r"D:\PDB") / "logs" / "ark_dyndata_publish_report.json"), help="Detailed report JSON path.")
    parser.add_argument("--emit-pack", action="store_true", help="Write compact profile pack JSON into the release profiles directory.")
    parser.add_argument("--pack-only", action="store_true", help="Publish only the compact pack and skip scattered JSON copies.")
    parser.add_argument(
        "--pack-version",
        type=int,
        choices=KSW_SUPPORTED_PACK_VERSIONS,
        default=KSW_DEFAULT_PACK_VERSION,
        help="Must be 4. v4 is the only published compact profile format.",
    )
    parser.add_argument(
        "--pack-output",
        default="",
        help="Pack output path; defaults to <release-root>\\profiles\\ark_dyndata_pack_v4.json.",
    )
    return parser.parse_args(argv)


def parse_uint32(value: Any) -> int | None:
    """Parse a JSON number or string into an unsigned 32-bit integer.

    Inputs:
    - value: JSON value from profile metadata or field offsets.

    Processing:
    - Supports decimal integers and strings with optional 0x prefix.
    - Rejects negative values and values outside uint32.

    Return behavior:
    - Returns an int on success; returns None on invalid input.
    """
    try:
        if isinstance(value, int):
            parsed = value
        elif isinstance(value, float):
            if not value.is_integer():
                return None
            parsed = int(value)
        elif isinstance(value, str):
            text = value.strip()
            base = 16 if text.lower().startswith("0x") else 10
            parsed = int(text, base)
        else:
            return None
    except ValueError:
        return None
    if parsed < 0 or parsed > 0xFFFFFFFF:
        return None
    return parsed


def parse_float_percent(value: Any) -> float | None:
    """Parse a JSON value into a bounded percentage.

    Inputs:
    - value: JSON number or decimal string from profile coverage metadata.

    Processing:
    - Accepts values in the inclusive 0.0 to 100.0 range.
    - Rejects booleans and malformed strings so report data remains numeric.

    Return behavior:
    - Returns a float on success; returns None when the value is absent or
      invalid.
    """
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            parsed = float(value)
        elif isinstance(value, str):
            parsed = float(value.strip())
        else:
            return None
    except ValueError:
        return None
    if parsed < 0.0 or parsed > 100.0:
        return None
    return parsed


def normalize_string_list(value: Any) -> list[str]:
    """Normalize an optional JSON string array for coverage reporting.

    Inputs:
    - value: Candidate JSON array, usually missingFields or missingGlobals.

    Processing:
    - Keeps only non-empty string entries after trimming whitespace.
    - Ignores malformed entries instead of rejecting the profile because
      coverage reporting should not block publishable offsets.

    Return behavior:
    - Returns a list of normalized strings; returns an empty list for invalid
      or absent input.
    """
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if text:
            result.append(text)
    return result


def require_uint32(value: Any, context: str) -> int:
    """Parse a required unsigned 32-bit value or raise a precise error.

    Inputs:
    - value: JSON value to parse.
    - context: Field name/path used in the error message.

    Processing:
    - Reuses parse_uint32 so pack generation follows the same numeric rules as
      validation.

    Return behavior:
    - Returns the parsed integer on success; raises ValueError on failure.
    """
    parsed = parse_uint32(value)
    if parsed is None:
        raise ValueError(f"required uint32 is invalid: {context}")
    return parsed


def pack_file_name_for_version(pack_version: int) -> str:
    """Return the default compact pack file name for one supported version.

    Inputs:
    - pack_version: Integer selected by --pack-version.

    Processing:
    - Looks up the version-specific file name so v1 remains the default legacy
      artifact and v2 gets its own release-side file.

    Return behavior:
    - Returns the default file name on success; raises ValueError for an
      unsupported version before any release file is written.
    """
    try:
        return DEFAULT_PACK_FILE_NAMES[pack_version]
    except KeyError as exc:
        raise ValueError(f"unsupported pack version: {pack_version}") from exc


def normalize_callback_item_name(name: str) -> str | None:
    """Normalize a callback item name to the shared protocol spelling.

    Inputs:
    - name: JSON callbackItems[].name value after whitespace trimming.

    Processing:
    - Accepts only names that correspond to KSW_DYN_FIELD_ID_CB_* shared field
      IDs.
    - Converts known generator aliases to the canonical shared field-name text
      used by R3/R0.

    Return behavior:
    - Returns the canonical callback name on success; returns None for unknown
      names.
    """
    if name not in CALLBACK_FIELD_IDS:
        return None
    return CALLBACK_CANONICAL_NAME_BY_NAME[name]


def normalize_typed_item_name(name: str, kind: str) -> tuple[str, int] | None:
    """Normalize a v3 typed item name and return its shared field ID.

    Inputs:
    - name: JSON items[].name value after whitespace trimming.
    - kind: JSON items[].kind value, either StructOffset or GlobalRva.

    Processing:
    - Routes GlobalRva names through callback and kernel-global maps.
    - Routes StructOffset names through known kernel fields plus callback
      structure offsets, accepting the historical EntryItemList alias.

    Return behavior:
    - Returns (canonicalName, fieldId) when name/kind are valid; returns None
      when the item is unsupported.
    """
    if kind == CALLBACK_ITEM_KIND_GLOBAL_RVA:
        field_id = GLOBAL_RVA_FIELD_IDS.get(name)
        return (name, field_id) if field_id is not None else None
    if kind == CALLBACK_ITEM_KIND_STRUCT_OFFSET:
        canonical_name = CALLBACK_NAME_ALIASES.get(name, name)
        if canonical_name in CALLBACK_STRUCT_OFFSET_FIELD_IDS:
            return canonical_name, CALLBACK_STRUCT_OFFSET_FIELD_IDS[canonical_name]
        field_id = TYPED_STRUCT_OFFSET_FIELD_IDS.get(name)
        return (name, field_id) if field_id is not None else None
    if kind == CALLBACK_ITEM_KIND_TYPE_SIZE:
        field_id = TYPED_TYPE_SIZE_FIELD_IDS.get(name)
        return (name, field_id) if field_id is not None else None
    return None


def v4_kind_for_field_name(name: str) -> str | None:
    """Return the v4 item kind for a legacy field name.

    This is used only while ingesting older corpus JSON.  The emitted pack
    always stores the resulting numeric v4 item once, with no legacy mirror.
    """
    if name in GLOBAL_RVA_FIELD_IDS:
        return CALLBACK_ITEM_KIND_GLOBAL_RVA
    if name in TYPED_TYPE_SIZE_FIELD_IDS:
        return CALLBACK_ITEM_KIND_TYPE_SIZE
    if name in TYPED_STRUCT_OFFSET_FIELD_IDS or name in CALLBACK_STRUCT_OFFSET_FIELD_IDS:
        return CALLBACK_ITEM_KIND_STRUCT_OFFSET
    return None


def validate_callback_items(path: Path, data: dict[str, Any], state: ValidationState) -> list[dict[str, Any]] | None:
    """Validate optional callbackItems and return a compact normalized list.

    Inputs:
    - path: Source JSON profile path used in diagnostics.
    - data: Parsed profile root dictionary.
    - state: Validation accumulator used for precise rejection reasons.

    Processing:
    - Treats a missing callbackItems key as a valid empty callback set, which
      keeps legacy profiles publishable.
    - Requires every present item to be an object with a supported name, kind,
      and uint32 value.
    - Enforces name/kind semantics: callback global names must use GlobalRva,
      and callback struct/member names must use StructOffset.
    - Validates values with the same upper bound used by R3/R0 struct offsets;
      GlobalRva values must be non-zero and remain within the shared
      KSW_DYN_PROFILE_GLOBAL_RVA_MAX range.
    - Rejects duplicate shared callback field IDs so aliases cannot create two
      entries for the same R0 item.

    Return behavior:
    - Returns a list of JSON-ready objects containing only name/kind/value when
      validation succeeds.
    - Returns None and records a profile rejection when validation fails.
    """
    if "callbackItems" not in data:
        return []

    callback_items = data.get("callbackItems")
    if callback_items is None:
        return []
    if not isinstance(callback_items, list):
        reject(state, path, "callback_items_not_array")
        return None

    normalized_items: list[dict[str, Any]] = []
    seen_field_ids: set[int] = set()
    for index, item in enumerate(callback_items):
        context = f"callbackItems[{index}]"
        if not isinstance(item, dict):
            reject(state, path, f"callback_item_not_object:{context}")
            return None

        raw_name = item.get("name")
        if not isinstance(raw_name, str):
            reject(state, path, f"callback_name_invalid:{context}")
            return None
        name = raw_name.strip()
        canonical_name = normalize_callback_item_name(name)
        if canonical_name is None:
            reject(state, path, f"callback_name_unknown:{name}")
            return None

        raw_kind = item.get("kind")
        if not isinstance(raw_kind, str):
            reject(state, path, f"callback_kind_invalid:{canonical_name}")
            return None
        kind = raw_kind.strip()
        if kind not in CALLBACK_ITEM_KINDS:
            reject(state, path, f"callback_kind_unsupported:{canonical_name}:{kind}")
            return None

        expected_kind = CALLBACK_KIND_BY_NAME[name]
        if kind != expected_kind:
            reject(state, path, f"callback_kind_mismatch:{canonical_name}:{kind}:expected_{expected_kind}")
            return None

        value = parse_uint32(item.get("value"))
        if value is None:
            reject(state, path, f"callback_value_invalid:{canonical_name}")
            return None
        if kind == CALLBACK_ITEM_KIND_GLOBAL_RVA:
            if value == 0:
                reject(state, path, f"callback_global_rva_zero:{canonical_name}")
                return None
            if value > KSW_DYN_PROFILE_GLOBAL_RVA_MAX:
                reject(state, path, f"callback_global_rva_out_of_range:{canonical_name}")
                return None
        if kind == CALLBACK_ITEM_KIND_STRUCT_OFFSET and (value == 0xFFFFFFFF or value > KSW_DYN_PROFILE_OFFSET_MAX):
            reject(state, path, f"callback_struct_offset_invalid:{canonical_name}")
            return None

        field_id = CALLBACK_FIELD_IDS[name]
        if field_id in seen_field_ids:
            reject(state, path, f"callback_duplicate:{canonical_name}")
            return None
        seen_field_ids.add(field_id)

        normalized_items.append({"name": canonical_name, "kind": kind, "value": value})

    return normalized_items


def typed_items_from_data(data: dict[str, Any]) -> Any:
    """Return the preferred v3 typed item array from one profile root.

    Inputs:
    - data: Parsed profile dictionary.

    Processing:
    - Accepts both items and typedItems so the release tool can read the compact
      pack spelling and the scattered-profile spelling.
    - Prefers items when both are present because it is the newer source key.

    Return behavior:
    - Returns the raw JSON value for downstream validation.
    """
    items_value = data.get("items")
    if isinstance(items_value, list) and items_value:
        return items_value
    typed_items_value = data.get("typedItems")
    if isinstance(typed_items_value, list):
        return typed_items_value
    return items_value if "items" in data else typed_items_value


def validate_typed_items(path: Path, data: dict[str, Any], state: ValidationState) -> list[dict[str, Any]] | None:
    """Validate optional v3 typed items and return normalized pack records.

    Inputs:
    - path: Source JSON profile path used in diagnostics.
    - data: Parsed profile root dictionary.
    - state: Validation accumulator used for precise rejection reasons.

    Processing:
    - Treats a missing items/typedItems key as an empty typed set.
    - Requires every present item to contain a supported name, StructOffset or
      GlobalRva kind, and safe uint32 value.
    - Enforces duplicate detection by shared field ID so aliases cannot target
      the same R0 item twice.

    Return behavior:
    - Returns normalized objects with name/kind/value and optional required flag
      when validation succeeds.
    - Returns None and records a rejection when validation fails.
    """
    raw_items = typed_items_from_data(data)
    if raw_items is None:
        return []
    if not isinstance(raw_items, list):
        reject(state, path, "typed_items_not_array")
        return None

    normalized_items: list[dict[str, Any]] = []
    seen_field_ids: set[int] = set()
    for index, item in enumerate(raw_items):
        context = f"typedItems[{index}]"
        if not isinstance(item, dict):
            reject(state, path, f"typed_item_not_object:{context}")
            return None

        raw_kind = item.get("kind")
        if not isinstance(raw_kind, str):
            reject(state, path, f"typed_kind_invalid:{context}")
            return None
        kind = raw_kind.strip()
        if kind not in CALLBACK_ITEM_KINDS:
            reject(state, path, f"typed_kind_unsupported:{context}:{kind}")
            return None

        raw_name = item.get("name")
        if not isinstance(raw_name, str):
            reject(state, path, f"typed_name_invalid:{context}")
            return None
        name = raw_name.strip()
        normalized_name = normalize_typed_item_name(name, kind)
        if normalized_name is None:
            reject(state, path, f"typed_name_unknown:{name}:{kind}")
            return None
        canonical_name, field_id = normalized_name

        value = parse_uint32(item.get("value"))
        if value is None:
            reject(state, path, f"typed_value_invalid:{canonical_name}")
            return None
        if kind == CALLBACK_ITEM_KIND_GLOBAL_RVA and (value == 0 or value > KSW_DYN_PROFILE_GLOBAL_RVA_MAX):
            reject(state, path, f"typed_global_rva_out_of_range:{canonical_name}")
            return None
        if kind == CALLBACK_ITEM_KIND_STRUCT_OFFSET and (value == 0xFFFFFFFF or value > KSW_DYN_PROFILE_OFFSET_MAX):
            reject(state, path, f"typed_struct_offset_invalid:{canonical_name}")
            return None
        if kind == CALLBACK_ITEM_KIND_TYPE_SIZE and (value == 0 or value > KSW_DYN_PROFILE_OFFSET_MAX):
            reject(state, path, f"typed_type_size_invalid:{canonical_name}")
            return None
        if field_id in seen_field_ids:
            reject(state, path, f"typed_duplicate:{canonical_name}")
            return None
        seen_field_ids.add(field_id)

        normalized_item: dict[str, Any] = {"name": canonical_name, "kind": kind, "value": value}
        if isinstance(item.get("required"), bool):
            normalized_item["required"] = bool(item.get("required"))
        normalized_items.append(normalized_item)

    return normalized_items


def validate_v4_items(path: Path, data: dict[str, Any], state: ValidationState) -> list[dict[str, Any]] | None:
    """Validate generator v4Items and normalize them to the wire-pack shape."""
    raw_items = data.get("v4Items")
    if raw_items is None:
        return []
    if not isinstance(raw_items, list):
        reject(state, path, "v4_items_not_array")
        return None

    normalized_items: list[dict[str, Any]] = []
    seen_item_ids: set[int] = set()
    for index, item in enumerate(raw_items):
        context = f"v4Items[{index}]"
        if not isinstance(item, dict):
            reject(state, path, f"v4_item_not_object:{context}")
            return None

        name = str(item.get("name", "")).strip()
        expected_item_id = V4_SPECIAL_ITEM_IDS.get(name)
        if expected_item_id is None:
            expected_item_id = V4_CORE_ITEM_IDS.get(name)
        item_id = parse_uint32(item.get("itemId"))
        if expected_item_id is None or item_id != expected_item_id or item_id not in SUPPORTED_V4_ITEM_IDS or item_id in seen_item_ids:
            reject(state, path, f"v4_item_id_invalid:{name}:{item_id}")
            return None
        seen_item_ids.add(item_id)

        kind_name = str(item.get("kind", "")).strip()
        item_kind = V4_ITEM_KIND_IDS.get(kind_name)
        group_id = parse_uint32(item.get("capabilityGroupId"))
        value = parse_uint32(item.get("value"))
        aux_values = [parse_uint32(item.get(f"aux{aux_index}", 0)) for aux_index in range(4)]
        expected_group_id = V4_SPECIAL_ITEM_GROUPS.get(name, V4_CORE_GROUP_ID if name in V4_CORE_ITEM_IDS else None)
        if item_kind is None or group_id != expected_group_id or value is None or any(aux is None for aux in aux_values):
            reject(state, path, f"v4_item_shape_invalid:{name}")
            return None

        if name in V4_CORE_ITEM_IDS:
            expected_kind = v4_kind_for_field_name(name)
            if expected_kind is None or kind_name != expected_kind:
                reject(state, path, f"v4_item_kind_invalid:{name}")
                return None

        if kind_name == "StructOffset" and (value == 0xFFFFFFFF or value > KSW_DYN_PROFILE_OFFSET_MAX):
            reject(state, path, f"v4_struct_offset_invalid:{name}")
            return None
        if kind_name in {"GlobalRva", "ListHeadGlobal"} and (value == 0 or value > KSW_DYN_PROFILE_GLOBAL_RVA_MAX):
            reject(state, path, f"v4_global_rva_invalid:{name}")
            return None
        if kind_name == "TypeSize" and (value == 0 or value > KSW_DYN_PROFILE_OFFSET_MAX):
            reject(state, path, f"v4_type_size_invalid:{name}")
            return None
        if kind_name == "BitField":
            bit_offset, bit_count, storage_bytes, _reserved = [int(aux) for aux in aux_values]
            if storage_bytes not in {1, 2, 4, 8} or bit_count == 0 or bit_count > 64 or bit_offset + bit_count > storage_bytes * 8:
                reject(state, path, f"v4_bit_field_invalid:{name}")
                return None

        raw_flags = item.get("flags", "required")
        if isinstance(raw_flags, str):
            normalized_flags = 1 if raw_flags.strip().lower() == "required" else 2 if raw_flags.strip().lower() == "optional" else 0
        else:
            normalized_flags = parse_uint32(raw_flags) or 0
        if normalized_flags not in {1, 2}:
            reject(state, path, f"v4_flags_invalid:{name}")
            return None

        normalized_items.append(
            {
                "itemId": item_id,
                "name": name,
                "itemKind": item_kind,
                "kind": kind_name,
                "flags": normalized_flags,
                "capabilityGroupId": group_id,
                "value": value,
                "aux0": int(aux_values[0]),
                "aux1": int(aux_values[1]),
                "aux2": int(aux_values[2]),
                "aux3": int(aux_values[3]),
            }
        )
    return normalized_items


def reject(state: ValidationState, path: Path, reason: str) -> None:
    """Append one rejection record to the validation state.

    Inputs:
    - state: Current validation accumulator.
    - path: Profile path that failed validation.
    - reason: Stable text describing the failure.

    Processing:
    - Adds a small dictionary suitable for JSON manifest/report output.

    Return behavior:
    - No return value; state.rejected is updated in place.
    """
    state.rejected.append({"path": str(path), "reason": reason})


def validate_idt_baseline(
    path: Path,
    data: dict[str, Any],
    module_class: str,
    machine: int,
    state: ValidationState,
) -> dict[str, Any] | None:
    """Validate optional exact-PDB KiInterruptInitTable metadata."""
    raw = data.get("idtBaseline")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        reject(state, path, "idt_baseline_not_object")
        return None
    if module_class != "ntoskrnl" or machine != 0x8664:
        reject(state, path, "idt_baseline_module_or_machine_invalid")
        return None
    table_rva = parse_uint32(raw.get("tableRva"))
    handlers = raw.get("handlers")
    if (
        raw.get("schemaVersion") != 2
        or str(raw.get("sourceSymbol", "")).strip() != "KiInterruptInitTable"
        or table_rva is None
        or table_rva == 0
        or table_rva > KSW_DYN_PROFILE_GLOBAL_RVA_MAX
        or not isinstance(handlers, list)
        or not handlers
    ):
        reject(state, path, "idt_baseline_shape_invalid")
        return None
    normalized_handlers: list[dict[str, Any]] = []
    seen_handlers: set[tuple[int, str]] = set()
    for index, handler in enumerate(handlers):
        if not isinstance(handler, dict):
            reject(state, path, f"idt_handler_not_object:{index}")
            return None
        vector = parse_uint32(handler.get("vector"))
        rva = parse_uint32(handler.get("rva"))
        symbol = str(handler.get("symbol", "")).strip()
        identity = (vector or 0, symbol)
        if (
            vector is None
            or vector > 0xFF
            or rva is None
            or rva == 0
            or rva > KSW_DYN_PROFILE_GLOBAL_RVA_MAX
            or not symbol.startswith("Ki")
            or identity in seen_handlers
        ):
            reject(state, path, f"idt_handler_invalid:{index}")
            return None
        seen_handlers.add(identity)
        normalized_handlers.append(
            {
                "vector": vector,
                "symbol": symbol,
                "rva": rva,
            }
        )
    return {
        "schemaVersion": 2,
        "sourceSymbol": "KiInterruptInitTable",
        "tableRva": table_rva,
        "handlers": normalized_handlers,
    }


def validate_profile(path: Path, state: ValidationState) -> ProfileRecord | None:
    """Validate one JSON profile and return a publishable record.

    Inputs:
    - path: Candidate JSON file.
    - state: Validation accumulator used to record rejection reasons.

    Processing:
    - Checks root keys, schema version, module identity, field names, and offsets.
    - Mirrors the R3/R0 v1 apply constraints so bad files never enter release.

    Return behavior:
    - Returns ProfileRecord on success; returns None and records a reason on failure.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - diagnostics must preserve any parser failure.
        reject(state, path, f"invalid_json: {exc}")
        return None

    if not isinstance(data, dict):
        reject(state, path, "root_not_object")
        return None
    if data.get("schemaVersion") != KSW_SCHEMA_VERSION:
        reject(state, path, f"schema_version_not_{KSW_SCHEMA_VERSION}")
        return None

    module = data.get("module")
    fields = data.get("fields", {})
    if not isinstance(module, dict):
        reject(state, path, "module_not_object")
        return None
    if not isinstance(fields, dict):
        reject(state, path, "fields_not_object")
        return None

    module_class = str(module.get("class", "")).strip().lower()
    if module_class not in {"ntoskrnl", "ntkrla57", "fltmgr", "ci"}:
        reject(state, path, f"unsupported_module_class:{module_class}")
        return None

    machine = parse_uint32(module.get("machine"))
    time_date_stamp = parse_uint32(module.get("timeDateStamp"))
    size_of_image = parse_uint32(module.get("sizeOfImage"))
    if machine is None or time_date_stamp is None or size_of_image is None:
        reject(state, path, "module_identity_invalid")
        return None

    for field_name, offset_value in fields.items():
        if field_name not in KNOWN_FIELD_NAMES:
            reject(state, path, f"unknown_field:{field_name}")
            return None
        offset = parse_uint32(offset_value)
        if offset is None or offset == 0xFFFFFFFF or offset > KSW_DYN_PROFILE_OFFSET_MAX:
            reject(state, path, f"offset_invalid:{field_name}")
            return None

    callback_items = validate_callback_items(path, data, state)
    if callback_items is None:
        return None
    typed_items = validate_typed_items(path, data, state)
    if typed_items is None:
        return None
    v4_items = validate_v4_items(path, data, state)
    if v4_items is None:
        return None
    idt_baseline = validate_idt_baseline(
        path,
        data,
        module_class,
        machine,
        state,
    )
    if data.get("idtBaseline") is not None and idt_baseline is None:
        return None
    module_sha256 = str(module.get("sha256", "")).strip().lower()
    if idt_baseline is not None and (
        len(module_sha256) != 64
        or any(character not in "0123456789abcdef" for character in module_sha256)
    ):
        reject(state, path, "idt_baseline_sha256_invalid")
        return None
    if not fields and not typed_items and not v4_items:
        reject(state, path, "fields_and_typed_items_empty")
        return None

    missing_fields = normalize_string_list(data.get("missingFields"))
    missing_globals = normalize_string_list(data.get("missingGlobals"))
    coverage_percent = parse_float_percent(data.get("coveragePercent"))
    if coverage_percent is None:
        resolved_count = len(typed_items) if typed_items else (len(fields) + len(callback_items))
        missing_count = len(missing_fields) + len(missing_globals)
        total_count = resolved_count + missing_count
        coverage_percent = 0.0 if total_count == 0 else round((resolved_count / total_count) * 100.0, 1)

    identity = ProfileIdentity(module_class, machine, time_date_stamp, size_of_image)
    return ProfileRecord(
        path=path,
        data=data,
        identity=identity,
        field_count=len(fields),
        callback_items=callback_items,
        typed_items=typed_items,
        v4_items=v4_items,
        idt_baseline=idt_baseline,
        missing_fields=missing_fields,
        missing_globals=missing_globals,
        coverage_percent=coverage_percent,
    )


def choose_duplicate_winner(records: list[ProfileRecord]) -> ProfileRecord:
    """Choose a deterministic winner for one duplicate identity group.

    Inputs:
    - records: Profiles with the same class/machine/timestamp/size tuple.

    Processing:
    - Prefers the record with more fields.
    - For equal field coverage, prefers the record with more callbackItems so
      v2 publishing does not discard newer callback metadata.
    - For otherwise equal records, preserves exact-PDB IDT baseline metadata.
    - Uses profileName and path as stable tie-breakers to avoid nondeterminism.

    Return behavior:
    - Returns the selected ProfileRecord; does not mutate input records.
    """
    return sorted(
        records,
        key=lambda item: (
            -item.field_count,
            -len(item.typed_items),
            -len(item.callback_items),
            -int(item.idt_baseline is not None),
            -item.coverage_percent,
            item.profile_name,
            str(item.path),
        ),
    )[0]


def deduplicate_profiles(state: ValidationState) -> list[ProfileRecord]:
    """Deduplicate accepted profiles by R0-safe module identity.

    Inputs:
    - state: ValidationState containing schema-valid profile records.

    Processing:
    - Groups by ProfileIdentity and chooses one deterministic winner per group.
    - Records duplicate diagnostics for the manifest.

    Return behavior:
    - Returns the final publish list sorted by class and profileName.
    """
    groups: dict[ProfileIdentity, list[ProfileRecord]] = {}
    for record in state.accepted:
        groups.setdefault(record.identity, []).append(record)

    final_records: list[ProfileRecord] = []
    for identity, records in groups.items():
        if len(records) == 1:
            final_records.append(records[0])
            continue
        winner = choose_duplicate_winner(records)
        state.duplicate_groups.append(
            {
                "identity": identity.__dict__,
                "winner": str(winner.path),
                "duplicates": [str(item.path) for item in records],
            }
        )
        final_records.append(winner)

    return sorted(final_records, key=lambda item: (item.identity.module_class, item.profile_name, str(item.path)))


def module_class_id_from_text(module_class: str) -> int | None:
    """Map a profile module class string to the shared numeric class id.

    Inputs:
    - module_class: Text value from the source JSON profile.

    Processing:
    - Accepts the stable ntoskrnl/ntkrla57 aliases already used by the corpus.
    - Returns the shared R0/R3 class id so the pack can store a compact integer.

    Return behavior:
    - Returns a class id on success; returns None for unsupported input.
    """
    normalized = module_class.strip().lower()
    if normalized in {"ntoskrnl", "ntoskrnl.exe", "ntkrnlmp", "ntkrnlmp.exe"}:
        return 0
    if normalized in {"ntkrla57", "ntkrla57.exe"}:
        return 1
    if normalized in {"lxcore", "lxcore.exe"}:
        return 2
    if normalized in {"fltmgr", "fltmgr.sys"}:
        return 48
    if normalized in {"ci", "ci.dll", "ci.sys"}:
        return 65
    return None


def records_for_pack_version(records: list[ProfileRecord], pack_version: int) -> list[ProfileRecord]:
    """Return records representable by one compact pack format.

    v4 is the only publishable format.  A record is retained only when its
    v4 item projection contains at least one complete capability/core item.
    """
    if pack_version not in KSW_SUPPORTED_PACK_VERSIONS:
        raise ValueError(f"unsupported pack version: {pack_version}")
    return [record for record in records if build_pack_v4_items(record)]


def build_pack_typed_items(record: ProfileRecord, pack_version: int) -> list[dict[str, Any]]:
    """Build pack typed items for one profile record.

    Inputs:
    - record: Validated profile record.
    - pack_version: Selected compact pack schema version.

    Processing:
    - Reuses prevalidated typed_items when the source profile already provided
      them.
    - Falls back to legacy fields plus callbackItems when a typed v3 payload was
      not present in the source JSON.

    Return behavior:
    - Returns a JSON-ready typed item list.
    """
    if pack_version != KSW_PACK_VERSION_V4:
        return []
    if record.typed_items:
        return [dict(item) for item in record.typed_items]

    typed_items: list[dict[str, Any]] = []
    for field_name, offset_value in sorted(record.data.get("fields", {}).items()):
        kind_name = v4_kind_for_field_name(str(field_name))
        if kind_name is None:
            continue
        typed_items.append({"name": field_name, "kind": kind_name, "value": require_uint32(offset_value, f"{record.path}:{field_name}")})
    for item in record.callback_items:
        typed_items.append(dict(item))
    return typed_items


def build_pack_v4_items(record: ProfileRecord) -> list[dict[str, Any]]:
    """Convert source items to the single stable v4 wire representation.

    The source generator may still provide legacy-shaped fields while a local
    corpus is being migrated.  They are projected once here and never copied
    into the release pack, so the pack has no duplicate ``fields`` or
    ``legacyItems`` payload.
    """
    source_typed_items: list[dict[str, Any]] = []
    if record.identity.module_class in {"ntoskrnl", "ntkrla57"}:
        source_typed_items = record.typed_items or build_pack_typed_items(record, KSW_PACK_VERSION_V4)
        if not source_typed_items:
            for field_name, offset_value in record.data.get("fields", {}).items():
                kind_name = v4_kind_for_field_name(str(field_name))
                if kind_name is not None:
                    source_typed_items.append({"name": field_name, "kind": kind_name, "value": offset_value})
            source_typed_items.extend(record.callback_items)
    packed_items: list[dict[str, Any]] = []
    seen_item_ids: set[int] = set()
    for item in source_typed_items:
        name = str(item.get("name", "")).strip()
        kind_name = str(item.get("kind", "")).strip()
        normalized = normalize_typed_item_name(name, kind_name)
        if normalized is None:
            continue
        canonical_name, item_id = normalized
        if item_id in seen_item_ids:
            continue
        seen_item_ids.add(item_id)
        required = bool(item.get("required", True))
        packed_items.append(
            {
                "itemId": item_id,
                "name": canonical_name,
                "itemKind": V4_ITEM_KIND_IDS[kind_name],
                "flags": 1 if required else 2,
                "capabilityGroupId": V4_CORE_GROUP_ID,
                "valueLow": require_uint32(item.get("value"), f"{record.path}:{canonical_name}"),
                "valueHigh": 0,
                "aux0": 0,
                "aux1": 0,
                "aux2": 0,
                "aux3": 0,
            }
        )

    for item in record.v4_items:
        item_id = int(item["itemId"])
        if item_id in seen_item_ids:
            raise ValueError(f"duplicate v4 item id {item_id} in {record.path}")
        seen_item_ids.add(item_id)
        packed_items.append(
            {
                "itemId": item_id,
                "name": str(item["name"]),
                "itemKind": int(item["itemKind"]),
                "flags": int(item["flags"]),
                "capabilityGroupId": int(item["capabilityGroupId"]),
                "valueLow": int(item["value"]),
                "valueHigh": 0,
                "aux0": int(item["aux0"]),
                "aux1": int(item["aux1"]),
                "aux2": int(item["aux2"]),
                "aux3": int(item["aux3"]),
            }
        )
    # A partially resolved special group is unusable at runtime.  Drop the
    # whole group so the pack cannot advertise a capability that the R0
    # contract will immediately reject.
    present_groups: dict[int, tuple[int, int]] = {}
    for item in packed_items:
        group_id = int(item["capabilityGroupId"])
        required, optional = present_groups.get(group_id, (0, 0))
        if int(item["flags"]) & 1:
            required += 1
        else:
            optional += 1
        present_groups[group_id] = (required, optional)
    complete_groups = {
        group_id
        for group_id, counts in present_groups.items()
        if group_id not in V4_FIXED_CAPABILITY_GROUP_COUNTS
        or counts == V4_FIXED_CAPABILITY_GROUP_COUNTS[group_id]
    }
    return sorted(
        [item for item in packed_items if int(item["capabilityGroupId"]) in complete_groups],
        key=lambda item: int(item["itemId"]),
    )


def build_pack_v4_capability_groups(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build exact required/optional counts expected by the R0 v4 validator."""
    names = {
        V4_CORE_GROUP_ID: "ntos.core",
        V4_TIMER_GROUP_ID: "timer.dpc",
        V4_FLTMGR_MINIFILTER_GROUP_ID: "fltmgr.minifilter",
        V4_CI_KERNEL_HASH_GROUP_ID: "ci.kernel_hash",
        V4_WORK_QUEUE_GROUP_ID: "ntos.work_queue",
    }
    groups: list[dict[str, Any]] = []
    for group_id in sorted({int(item["capabilityGroupId"]) for item in items}):
        group_items = [item for item in items if int(item["capabilityGroupId"]) == group_id]
        present_required = sum(1 for item in group_items if int(item["flags"]) & 1)
        present_optional = sum(1 for item in group_items if int(item["flags"]) & 2)
        required_count, optional_count = V4_FIXED_CAPABILITY_GROUP_COUNTS.get(
            group_id,
            (present_required, present_optional),
        )
        groups.append(
            {
                "groupId": group_id,
                "flags": 0,
                "requiredItemCount": required_count,
                "optionalItemCount": optional_count,
                "groupName": names.get(group_id, f"group.{group_id}"),
            }
        )
    return groups


def build_pack_profile_entry(record: ProfileRecord, field_index: dict[str, int] | None = None, pack_version: int = KSW_PACK_VERSION_V4) -> dict[str, Any]:
    """Convert one validated profile record into a compact pack entry.

    Inputs:
    - record: Deduplicated profile record.
    - field_index: Field dictionary lookup table.
    - pack_version: Selected compact pack schema version.

    Processing:
    - Normalizes module identity and PDB metadata to compact numeric/string
      values.
    - Stores one numeric v4 item payload per resolved offset.
    - Does not copy legacy fields, callbackItems, typedItems, or legacyItems.

    Return behavior:
    - Returns a JSON-serializable dictionary for the pack file.
    """
    module = record.data.get("module")
    if not isinstance(module, dict):
        raise ValueError(f"invalid module object for {record.path}")

    module_class = module_class_id_from_text(str(module.get("class", "")))
    if module_class is None:
        raise ValueError(f"unsupported module class for {record.path}")

    pdb_age = parse_uint32(module.get("pdbAge")) or 0
    if pack_version != KSW_PACK_VERSION_V4:
        raise ValueError("only v4 profile packs are supported")
    v4_items = build_pack_v4_items(record)
    if not v4_items:
        raise ValueError(f"v4 item set is empty for {record.path}")

    profile_entry = {
        "moduleClassId": module_class,
        "machine": require_uint32(module.get("machine"), f"{record.path}:machine"),
        "timeDateStamp": require_uint32(module.get("timeDateStamp"), f"{record.path}:timeDateStamp"),
        "sizeOfImage": require_uint32(module.get("sizeOfImage"), f"{record.path}:sizeOfImage"),
        "profileName": record.profile_name,
        "pdbName": str(module.get("pdbName", "")),
        "pdbGuid": str(module.get("pdbGuid", "")),
        "pdbAge": pdb_age,
        "sha256": str(module.get("sha256", "")).strip().lower(),
        "items": v4_items,
        "capabilityGroups": build_pack_v4_capability_groups(v4_items),
        "coveragePercent": record.coverage_percent,
        "missingFields": record.missing_fields,
        "missingGlobals": record.missing_globals,
    }
    if record.idt_baseline is not None:
        profile_entry["idtBaseline"] = record.idt_baseline
    return profile_entry


def build_profile_pack(records: list[ProfileRecord], pack_version: int) -> dict[str, Any]:
    """Build the selected compact profile pack from validated records.

    Inputs:
    - records: Final deduplicated publish list.
    - pack_version: Compact pack schema version selected by the caller.

    Processing:
    - Converts each profile into a compact identity plus canonical v4 items and
      complete capability groups.
    - Omits every legacy offset mirror.

    Return behavior:
    - Returns a JSON-serializable pack dictionary.
    """
    if pack_version not in KSW_SUPPORTED_PACK_VERSIONS:
        raise ValueError(f"unsupported pack version: {pack_version}")
    selected_records = records_for_pack_version(records, pack_version)
    if not selected_records:
        raise ValueError(f"no profiles are representable in pack version {pack_version}")
    return {
        "schemaVersion": KSW_SCHEMA_VERSION,
        "packVersion": pack_version,
        "profiles": [build_pack_profile_entry(record, pack_version=pack_version) for record in selected_records],
    }


def parse_pe_identity(path: Path) -> ProfileIdentity | None:
    """Parse minimal PE identity for a local ntoskrnl.exe smoke test.

    Inputs:
    - path: PE image path, usually C:\\Windows\\System32\\ntoskrnl.exe.

    Processing:
    - Reads DOS header, NT signature, COFF header, and OptionalHeader SizeOfImage.
    - Does not need pefile or symbol data.

    Return behavior:
    - Returns ProfileIdentity for ntoskrnl on success; returns None on failure.
    """
    try:
        data = path.read_bytes()
        if len(data) < 0x100 or data[0:2] != b"MZ":
            return None
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 0x108 >= len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            return None
        machine, _sections, time_date_stamp = struct.unpack_from("<HHI", data, pe_offset + 4)
        optional_header_offset = pe_offset + 24
        size_of_image = struct.unpack_from("<I", data, optional_header_offset + 56)[0]
        return ProfileIdentity("ntoskrnl", machine, time_date_stamp, size_of_image)
    except OSError:
        return None


def ensure_safe_target(target_dir: Path) -> None:
    """Validate that a clean operation is limited to the profile target folder.

    Inputs:
    - target_dir: Directory intended to hold runtime JSON profiles.

    Processing:
    - Resolves the absolute path and checks the expected profiles\\ark_dyndata
      suffix before deleting stale JSON files.

    Return behavior:
    - Raises ValueError if the path is not safe; otherwise returns None.
    """
    resolved = target_dir.resolve()
    if resolved.name.lower() != "ark_dyndata" or resolved.parent.name.lower() != "profiles":
        raise ValueError(f"Refusing to clean unexpected target directory: {resolved}")


def clean_scattered_profile_target(target_dir: Path, keep_names: set[str] | None = None) -> int:
    """Move stale scattered JSON profiles to a recoverable temp archive.

    Inputs:
    - target_dir: Release\\profiles\\ark_dyndata destination.

    Processing:
    - Verifies the expected directory suffix before moving anything.
    - Moves only direct child *.json files not named in keep_names; pack files
      and manifests live in the parent profiles directory and are never touched.

    Return behavior:
    - Returns the number of JSON files archived.
    """
    if not target_dir.exists():
        return 0

    ensure_safe_target(target_dir)
    archive_root = Path(os.environ.get("TEMP", tempfile.gettempdir())) / "Ksword5.1-stale-offsets" / time.strftime("%Y%m%d-%H%M%S")
    archived_count = 0
    for stale_file in target_dir.glob("*.json"):
        if keep_names is not None and stale_file.name in keep_names:
            continue
        archive_root.mkdir(parents=True, exist_ok=True)
        destination = archive_root / stale_file.name
        suffix = 1
        while destination.exists():
            destination = archive_root / f"{stale_file.stem}.{suffix}{stale_file.suffix}"
            suffix += 1
        shutil.move(str(stale_file), str(destination))
        archived_count += 1
    return archived_count


def atomic_copy2(source_path: Path, destination: Path) -> None:
    """Copy one profile through a sibling temporary file and atomically publish it.

    The temporary file lives in destination.parent, so os.replace never exposes a
    partially copied JSON profile to the running Ksword process on interruption.
    """

    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary_path = Path(temporary_name)
    os.close(descriptor)
    try:
        shutil.copy2(source_path, temporary_path)
        # r+b keeps a writable handle on Windows, which FlushFileBuffers requires.
        with temporary_path.open("r+b") as temporary_file:
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, destination)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def copy_profiles(records: list[ProfileRecord], target_dir: Path, clean_target: bool, max_copy: int) -> list[Path]:
    """Copy accepted profile JSON files into the release profile directory.

    Inputs:
    - records: Final deduplicated publish list.
    - target_dir: Release\\profiles\\ark_dyndata destination.
    - clean_target: Whether to remove stale target JSON files first.
    - max_copy: Optional copy limit used for small smoke tests.

    Processing:
    - Creates the target directory and atomically refreshes selected files before
      optionally deleting stale JSON, so an interrupted publish keeps old files.

    Return behavior:
    - Returns the list of destination paths copied or refreshed.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    selected = records[:max_copy] if max_copy > 0 else records
    copied: list[Path] = []
    for record in selected:
        destination = target_dir / record.path.name
        atomic_copy2(record.path, destination)
        copied.append(destination)

    if clean_target:
        clean_scattered_profile_target(target_dir, {record.path.name for record in selected})
    return copied


def build_manifest(
    state: ValidationState,
    records: list[ProfileRecord],
    copied: list[Path],
    local_identity: ProfileIdentity | None,
    pack_path: Path | None,
    pack: dict[str, Any] | None,
    removed_scattered_profiles: int,
    pack_only: bool,
    include_profile_list: bool,
) -> dict[str, Any]:
    """Build a manifest/report dictionary for the publish pass.

    Inputs:
    - state: Validation details including rejected and duplicate records.
    - records: Final deduplicated publish list.
    - copied: Destination files copied during this run.
    - local_identity: Optional local ntoskrnl identity.
    - pack_path/pack: Optional compact pack output metadata.
    - removed_scattered_profiles: Count of stale scattered JSON files removed.
    - pack_only: Whether this pass intentionally skipped scattered JSON copies.
    - include_profile_list: Whether to include every profile identity in this
      output. Reports use this for audit detail; Release manifests omit it to
      avoid duplicating pack data.

    Processing:
    - Computes count summaries, class coverage, pack metadata, and local profile
      match status.

    Return behavior:
    - Returns a JSON-serializable dictionary.
    """
    class_counts: dict[str, int] = {}
    local_match: dict[str, Any] | None = None
    v4_item_count = 0
    for record in records:
        class_counts[record.identity.module_class] = class_counts.get(record.identity.module_class, 0) + 1
        v4_item_count += len(build_pack_v4_items(record))
        if local_identity is not None and record.identity == local_identity:
            local_match = {"profile": str(record.path), "profileName": record.profile_name}

    pack_summary = None
    manifest_pack_version = KSW_DEFAULT_PACK_VERSION
    if pack is not None:
        pack_profiles = pack.get("profiles", [])
        pack_v4_item_count = 0
        if isinstance(pack_profiles, list):
            for profile in pack_profiles:
                if not isinstance(profile, dict):
                    continue
                items = profile.get("items", [])
                if isinstance(items, list):
                    pack_v4_item_count += len(items)
        manifest_pack_version = parse_uint32(pack.get("packVersion")) or KSW_DEFAULT_PACK_VERSION
        pack_summary = {
            "path": str(pack_path) if pack_path is not None else None,
            "schemaVersion": pack.get("schemaVersion"),
            "packVersion": pack.get("packVersion"),
            "profileCount": len(pack_profiles) if isinstance(pack_profiles, list) else 0,
            "v4ItemCount": pack_v4_item_count,
        }

    manifest = {
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "schemaVersion": KSW_SCHEMA_VERSION,
        "packVersion": manifest_pack_version,
        "publishMode": "pack-only" if pack_only else ("pack-and-json" if pack is not None else "json"),
        "acceptedBeforeDedup": len(state.accepted),
        "publishedProfiles": len(records),
        "v4ItemCount": v4_item_count,
        "copiedProfiles": len(copied),
        "removedScatteredProfiles": removed_scattered_profiles,
        "rejectedProfiles": len(state.rejected),
        "duplicateGroups": len(state.duplicate_groups),
        "classCounts": class_counts,
        "pack": pack_summary,
        "localKernelIdentity": local_identity.__dict__ if local_identity is not None else None,
        "localKernelProfileMatch": local_match,
        "rejected": state.rejected,
        "duplicates": state.duplicate_groups,
    }
    if include_profile_list:
        manifest["profiles"] = [
            {
                "fileName": record.path.name,
                "profileName": record.profile_name,
                "identity": record.identity.__dict__,
                "fieldCount": record.field_count,
                "v4ItemCount": len(build_pack_v4_items(record)),
                "missingFields": record.missing_fields,
                "missingGlobals": record.missing_globals,
                "coveragePercent": record.coverage_percent,
            }
            for record in records
        ]
    else:
        manifest["profileListOmitted"] = True
    return manifest


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Write bytes through a sibling temp file and atomically replace the target."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as temporary_file:
            temporary_file.write(payload)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def write_json(path: Path, data: dict[str, Any]) -> None:
    """Atomically write a stable, UTF-8, indented JSON document."""

    atomic_write_bytes(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def write_compact_json(path: Path, data: dict[str, Any]) -> None:
    """Write compact UTF-8 JSON without whitespace-heavy pretty formatting.

    Inputs:
    - path: Destination pack path.
    - data: JSON-serializable pack dictionary.

    Processing:
    - Creates parent directories and writes deterministic key ordering.
    - Uses compact separators so Release carries one small pack file.

    Return behavior:
    - No return value; raises OSError/TypeError if writing fails.
    """
    # v4 的唯一发布文件同时携带用户态完整布局；原驱动 profiles/items 保持原协议。
    if data.get("packVersion") == KSW_PACK_VERSION_V4:
        if __package__:
            from .ksword_v4_structure_layouts import build_structure_layouts
        else:
            from ksword_v4_structure_layouts import build_structure_layouts

        layout_root = Path(__file__).resolve().parents[2] / "Ksword5.1/Ksword5.1/profiles"
        data["structureLayouts"] = build_structure_layouts(layout_root)
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    atomic_write_bytes(path, payload.encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    """Program entry point; returns a process exit code."""
    args = parse_args(argv)
    source_dir = Path(args.source)
    release_root = Path(args.release_root)
    target_dir = release_root / "profiles" / "ark_dyndata"
    manifest_path = Path(args.manifest) if args.manifest else release_root / "profiles" / "ark_dyndata_manifest.json"
    pack_version = int(args.pack_version)
    pack_file_name = pack_file_name_for_version(pack_version)
    pack_path = Path(args.pack_output) if args.pack_output else release_root / "profiles" / pack_file_name
    report_path = Path(args.report)
    emit_pack = bool(args.emit_pack or args.pack_only)

    if not source_dir.exists():
        print(f"source directory does not exist: {source_dir}", file=sys.stderr)
        return 2

    state = ValidationState()
    for path in sorted(source_dir.glob("*.json")):
        record = validate_profile(path, state)
        if record is not None:
            state.accepted.append(record)

    final_records = records_for_pack_version(deduplicate_profiles(state), KSW_PACK_VERSION_V4)
    local_identity = parse_pe_identity(Path(args.local_kernel)) if args.local_kernel else None
    if not final_records:
        print("no publishable profiles remain after validation", file=sys.stderr)
        return 3

    copied: list[Path] = []
    removed_scattered_profiles = 0
    pack: dict[str, Any] | None = None
    if not args.dry_run:
        if args.pack_only and args.clean_target:
            removed_scattered_profiles = clean_scattered_profile_target(target_dir)
        if not args.pack_only:
            copied = copy_profiles(final_records, target_dir, args.clean_target, args.max_copy)
        if emit_pack:
            pack = build_profile_pack(final_records, pack_version)
            write_compact_json(pack_path, pack)
    elif emit_pack:
        pack = build_profile_pack(final_records, pack_version)

    report_manifest = build_manifest(
        state=state,
        records=final_records,
        copied=copied,
        local_identity=local_identity,
        pack_path=pack_path if emit_pack else None,
        pack=pack,
        removed_scattered_profiles=removed_scattered_profiles,
        pack_only=bool(args.pack_only),
        include_profile_list=True,
    )
    release_manifest = build_manifest(
        state=state,
        records=final_records,
        copied=copied,
        local_identity=local_identity,
        pack_path=pack_path if emit_pack else None,
        pack=pack,
        removed_scattered_profiles=removed_scattered_profiles,
        pack_only=bool(args.pack_only),
        include_profile_list=False,
    )
    write_json(report_path, report_manifest)
    if not args.dry_run:
        write_json(manifest_path, release_manifest)

    print(f"sourceProfiles={len(list(source_dir.glob('*.json')))}")
    print(f"acceptedBeforeDedup={len(state.accepted)}")
    print(f"publishedProfiles={len(final_records)}")
    print(f"v4Items={report_manifest['v4ItemCount']}")
    print(f"rejectedProfiles={len(state.rejected)}")
    print(f"duplicateGroups={len(state.duplicate_groups)}")
    print(f"copiedProfiles={len(copied)}")
    print(f"removedScatteredProfiles={removed_scattered_profiles}")
    print(f"targetDir={target_dir}")
    print(f"pack={pack_path if emit_pack and not args.dry_run else ('<dry-run>' if emit_pack else '<disabled>')}")
    print(f"manifest={manifest_path if not args.dry_run else '<dry-run>'}")
    print(f"report={report_path}")
    print(f"localKernelMatch={'yes' if report_manifest['localKernelProfileMatch'] else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
