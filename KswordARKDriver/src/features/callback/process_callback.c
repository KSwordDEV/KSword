/*++

Module Name:

    process_callback.c

Abstract:

    Process create callback registration and dispatch.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "ark/ark_bugcheck.h"
#include "ark/ark_process_protect.h"

NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

VOID
KswordArkProcessCreateNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    KSWORD_ARK_CALLBACK_MATCH_RESULT matchResult;
    UNICODE_STRING initiatorPath = { 0 };
    UNICODE_STRING targetPath = { 0 };
    WCHAR initiatorPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS] = { 0 };
    WCHAR targetPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS] = { 0 };
    BOOLEAN initiatorPathUnavailable = TRUE;
    ULONG operationType = KSWORD_ARK_PROCESS_OP_CREATE;
    NTSTATUS matchStatus = STATUS_SUCCESS;

    KswordARKBugcheckTrackProcess(Process, ProcessId, CreateInfo);

    if (CreateInfo == NULL) {
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_INPUT monitorInput;
        PCHAR shortImageName = NULL;

        // 退出通知只读取 EPROCESS 内的固定短名称，避免为遥测新增池分配。
        if (KswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS)) {
            shortImageName = PsGetProcessImageFileName(Process);
            if (shortImageName != NULL && shortImageName[0] != '\0') {
                (VOID)RtlStringCbPrintfW(
                    targetPathBuffer,
                    sizeof(targetPathBuffer),
                    L"%S",
                    shortImageName);
            }
            RtlInitUnicodeString(&targetPath, targetPathBuffer);
            RtlZeroMemory(&monitorInput, sizeof(monitorInput));
            monitorInput.Category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS;
            monitorInput.Operation = KSWORD_ARK_CALLBACK_MONITOR_PROCESS_OP_EXIT;
            monitorInput.OriginatingProcessId = HandleToULong(PsGetCurrentProcessId());
            monitorInput.OriginatingThreadId = HandleToULong(PsGetCurrentThreadId());
            monitorInput.TargetProcessId = HandleToULong(ProcessId);
            monitorInput.SessionId = KswordArkGetProcessSessionIdSafe(Process);
            monitorInput.ProcessName = &targetPath;
            monitorInput.Path = &targetPath;
            KswordArkCallbackMonitorPublish(&monitorInput);
        }
        // 退出通知：把进程移出 PP 自愈台账，避免死 PID 占位。
        KswordArkProcessProtectNotifyProcessExit(HandleToULong(ProcessId));
        return;
    }

    // 内核 PP 层先于通用规则执行：目标进程重启后只有这一个时机能在它开始执行
    // 之前重新打上保护。它不改 CreationStatus，不会影响下面的 DENY 判定。
    KswordArkProcessProtectNotifyProcessCreate(
        Process,
        HandleToULong(ProcessId),
        CreateInfo->ImageFileName);

    (VOID)KswordArkResolveProcessImagePath(
        PsGetCurrentProcess(),
        initiatorPathBuffer,
        RTL_NUMBER_OF(initiatorPathBuffer),
        &initiatorPathUnavailable);
    RtlInitUnicodeString(&initiatorPath, initiatorPathBuffer);

    if (CreateInfo->ImageFileName != NULL &&
        CreateInfo->ImageFileName->Buffer != NULL &&
        CreateInfo->ImageFileName->Length > 0U) {
        targetPath = *CreateInfo->ImageFileName;
    }
    else {
        RtlInitUnicodeString(&targetPath, targetPathBuffer);
    }

    // 遥测与规则判定相互独立；没有规则时仍应发布进程创建事件。
    if (KswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS)) {
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_INPUT monitorInput;
        RtlZeroMemory(&monitorInput, sizeof(monitorInput));
        monitorInput.Category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS;
        monitorInput.Operation = operationType;
        monitorInput.OriginatingProcessId = HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess);
        monitorInput.OriginatingThreadId = HandleToULong(CreateInfo->CreatingThreadId.UniqueThread);
        monitorInput.TargetProcessId = HandleToULong(ProcessId);
        monitorInput.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
        monitorInput.SessionId = KswordArkGetProcessSessionIdSafe(Process);
        monitorInput.ProcessName = &initiatorPath;
        monitorInput.Path = &targetPath;
        KswordArkCallbackMonitorPublish(&monitorInput);
    }

    matchStatus = KswordArkCallbackMatchRule(
        KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE,
        operationType,
        &initiatorPath,
        &targetPath,
        &matchResult);
    if (!NT_SUCCESS(matchStatus) || !matchResult.Matched) {
        return;
    }

    if (matchResult.Action == KSWORD_ARK_RULE_ACTION_LOG_ONLY) {
        KswordArkCallbackLogFormat(
            "Info",
            "Process callback log rule hit, creatorPid=%lu, targetPid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)HandleToULong(PsGetCurrentProcessId()),
            (unsigned long)HandleToULong(ProcessId),
            (unsigned long)matchResult.GroupId,
            (unsigned long)matchResult.RuleId);
        return;
    }

    if (matchResult.Action == KSWORD_ARK_RULE_ACTION_DENY) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        KswordArkCallbackLogFormat(
            "Warn",
            "Process creation denied, creatorPid=%lu, targetPid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)HandleToULong(PsGetCurrentProcessId()),
            (unsigned long)HandleToULong(ProcessId),
            (unsigned long)matchResult.GroupId,
            (unsigned long)matchResult.RuleId);
        return;
    }

    if (matchResult.Action == KSWORD_ARK_RULE_ACTION_ALLOW) {
        KswordArkCallbackLogFormat(
            "Info",
            "Process callback allow rule hit, creatorPid=%lu, targetPid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)HandleToULong(PsGetCurrentProcessId()),
            (unsigned long)HandleToULong(ProcessId),
            (unsigned long)matchResult.GroupId,
            (unsigned long)matchResult.RuleId);
    }
}

NTSTATUS
KswordArkProcessCallbackRegister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    status = PsSetCreateProcessNotifyRoutineEx(KswordArkProcessCreateNotifyEx, FALSE);
    if (NT_SUCCESS(status)) {
        // 注册期全局 runtime 尚未发布，必须用显式 runtime 版本写日志。
        KswordArkCallbackLogFrameForRuntime(runtime, "Info", "Process create callback registered.");
    }
    return status;
}

VOID
KswordArkProcessCallbackUnregister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(runtime);

    status = PsSetCreateProcessNotifyRoutineEx(KswordArkProcessCreateNotifyEx, TRUE);
    if (NT_SUCCESS(status)) {
        KswordArkCallbackLogFrame("Info", "Process create callback unregistered.");
    }
}
