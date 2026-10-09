/*++

Module Name:

    redirect_file.c

Abstract:

    File-system create redirection helper for the shared minifilter runtime.

Environment:

    Kernel-mode minifilter

--*/

#include "redirect_internal.h"
#include "ark/ark_push_lock.h"

// 中文说明：规则加载阶段解析盘符，classify/pre-create 热路径不打开对象管理器句柄。
NTSTATUS KswordARKRedirectNormalizeFilePath(WCHAR* Path)
{
    UNICODE_STRING pathName; // 已验证的有界原始路径。
    UNICODE_STRING prefix; // 用于区分 DOS namespace。
    UNICODE_STRING linkName; // 盘符链接对象名。
    UNICODE_STRING targetName; // 解析后的设备名字。
    OBJECT_ATTRIBUTES attributes; // 使用内核句柄访问符号链接。
    HANDLE linkHandle = NULL; // 必须在返回前关闭。
    WCHAR target[KSWORD_ARK_REDIRECT_PATH_CHARS]; // 临时设备全名。
    USHORT chars = 0U; // 原路径字符数。
    ULONG suffixIndex = 0UL; // 盘符后路径起点。
    NTSTATUS status; // 保留真实解析结果。
    if (!KswordARKRedirectIsRulePathValid(Path, KSWORD_ARK_REDIRECT_PATH_CHARS, &chars)) return STATUS_INVALID_PARAMETER; // 禁止无终止符。
    RtlInitUnicodeString(&pathName, Path); // 已保证 NUL 终止。
    RtlInitUnicodeString(&prefix, L"\\??\\"); // CLI/GUI 常用 NT DOS 路径。
    if (RtlPrefixUnicodeString(&prefix, &pathName, TRUE)) suffixIndex = 4UL; // 排除 namespace 前缀。
    RtlInitUnicodeString(&prefix, L"\\DosDevices\\"); // 接受等价的 DOS namespace。
    if (RtlPrefixUnicodeString(&prefix, &pathName, TRUE)) suffixIndex = 12UL; // 同样定位盘符。
    if (suffixIndex == 0UL) return STATUS_SUCCESS; // 设备全名及卷内路径无需解析。
    if (chars <= suffixIndex + 2UL || Path[suffixIndex + 1UL] != L':' || Path[suffixIndex + 2UL] != L'\\') return STATUS_NOT_SUPPORTED; // 只解析绝对盘符路径。
    linkName = pathName; // 链接名截到盘符冒号，不含文件后缀。
    linkName.Length = (USHORT)((suffixIndex + 2UL) * sizeof(WCHAR)); // 明确字节长度。
    linkName.MaximumLength = linkName.Length; // 链接名不需要额外终止符。
    InitializeObjectAttributes(&attributes, &linkName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL); // 使用请求者盘符映射。
    status = ZwOpenSymbolicLinkObject(&linkHandle, SYMBOLIC_LINK_QUERY, &attributes); // 解析 C: 等真实链接。
    if (!NT_SUCCESS(status)) return status; // 不把未解析的 DOS 路径作为设备路径发布。
    targetName.Buffer = target; // 设备前缀缓冲。
    targetName.Length = 0U; // 查询填写实际长度。
    targetName.MaximumLength = sizeof(target) - sizeof(WCHAR); // 保留终止符空间。
    status = ZwQuerySymbolicLinkObject(linkHandle, &targetName, NULL); // 得到 \Device\HarddiskVolumeX。
    ZwClose(linkHandle); // 查询成功与失败均关闭句柄。
    if (!NT_SUCCESS(status)) return status; // 保留符号链接查询状态。
    suffixIndex += 2UL; // 后缀从盘符后反斜杠开始。
    if ((ULONG)(targetName.Length / sizeof(WCHAR)) + chars - suffixIndex >= KSWORD_ARK_REDIRECT_PATH_CHARS) return STATUS_NAME_TOO_LONG; // 组合必须容纳 NUL。
    RtlCopyMemory(target + targetName.Length / sizeof(WCHAR), Path + suffixIndex, (chars - suffixIndex + 1UL) * sizeof(WCHAR)); // 拼接设备全名与原文件后缀。
    RtlCopyMemory(Path, target, targetName.Length + (chars - suffixIndex + 1UL) * sizeof(WCHAR)); // 原位保存规范名字。
    return STATUS_SUCCESS; // 完成规则名字解析。
}

NTSTATUS
KswordARKRedirectTryRewriteFileCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ BOOLEAN* RedirectedOut
    )
/*++

Routine Description:

    在 IRP_MJ_CREATE pre-operation 中尝试替换 FileObject->FileName。中文说明：
    该实现只使用 FltMgr/IO manager 公开字段，命中规则后用目标 NT 路径替换本次
    create 名称，并调用 FltSetCallbackDataDirty 通知 FltMgr 重新处理参数。

Arguments:

    Data - FltMgr callback data。
    FltObjects - FltMgr related objects。
    RedirectedOut - 返回 TRUE 表示已经改写本次 create 路径。

Return Value:

    STATUS_SUCCESS 表示已检查完成；失败状态表示规则命中但改写失败。

--*/
{
    KSWORD_ARK_REDIRECT_RUNTIME* runtime = KswordARKRedirectGetRuntime();
    KSWORD_ARK_REDIRECT_RULE matchedRule;
    UNICODE_STRING sourceName;
    UNICODE_STRING targetName;
    PFLT_FILE_NAME_INFORMATION nameInformation = NULL; // FltMgr 提供完整卷和打开名字。
    UNICODE_STRING relativeName; // 在同一卷内匹配历史相对规则。
    WCHAR targetBuffer[KSWORD_ARK_REDIRECT_PATH_CHARS]; // 卷内目标转换为完整 namespace 名字。
    ULONG processId = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (RedirectedOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *RedirectedOut = FALSE;

    if (Data == NULL || FltObjects == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Data->Iopb == NULL || Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        return STATUS_SUCCESS;
    }
    if ((runtime->RuntimeFlags & KSWORD_ARK_REDIRECT_RUNTIME_FILE_ACTIVE) == 0UL) {
        return STATUS_SUCCESS;
    }
    if (FltObjects->FileObject->FileName.Buffer == NULL ||
        FltObjects->FileObject->FileName.Length == 0U) {
        return STATUS_SUCCESS;
    }

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInformation); // pre-create 使用打开名，允许目标尚不存在。
    if (!NT_SUCCESS(status) || nameInformation == NULL) return status; // 不能将名字读取失败视作已改写。
    status = FltParseFileNameInformation(nameInformation); // 获取 Volume 与卷内后缀。
    if (!NT_SUCCESS(status)) { // 不以未解析名字拼接目标。
        FltReleaseFileNameInformation(nameInformation); // 释放名字引用。
        return status; // 返回实际解析错误。
    }
    sourceName = nameInformation->Name; // 使用 \Device\卷\路径完整名字。
    relativeName = sourceName; // 原有卷内规则采用同一打开名后缀。
    relativeName.Buffer += nameInformation->Volume.Length / sizeof(WCHAR); // 跳过卷 namespace。
    relativeName.Length -= nameInformation->Volume.Length; // 保留卷内反斜杠及文件名。
    relativeName.MaximumLength = relativeName.Length; // 不跨过原缓冲区末尾。
    processId = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);

    KswordARKAcquirePushLockShared(&runtime->Lock);
    status = KswordARKRedirectFindMatchLocked(
        runtime,
        KSWORD_ARK_REDIRECT_TYPE_FILE,
        processId,
        &sourceName,
        &matchedRule);
    if (!NT_SUCCESS(status)) { // 完整路径未命中时兼容卷内绝对路径规则。
        status = KswordARKRedirectFindMatchLocked(runtime, KSWORD_ARK_REDIRECT_TYPE_FILE,
            processId, &relativeName, &matchedRule); // 仍保留 processId 和 exact/prefix 判断。
    }
    KswordARKReleasePushLockShared(&runtime->Lock);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInformation); // 未命中也释放名字缓存引用。
        return STATUS_SUCCESS;
    }
    *RedirectedOut = TRUE; // 已命中规则；若后续改写失败，调用者应完成失败而非写入源文件。

    RtlInitUnicodeString(&targetName, matchedRule.targetPath);
    if (targetName.Buffer == NULL || targetName.Length == 0U) {
        FltReleaseFileNameInformation(nameInformation); // 错误目标不泄漏引用。
        return STATUS_INVALID_PARAMETER;
    }

    if (matchedRule.targetPath[0] == L'\\' &&
        _wcsnicmp(matchedRule.targetPath, L"\\Device\\", 8U) != 0) { // 非设备全名按源卷内目标处理。
        if ((SIZE_T)nameInformation->Volume.Length + targetName.Length + sizeof(WCHAR) > sizeof(targetBuffer)) { // 有界组合源卷和目标后缀。
            FltReleaseFileNameInformation(nameInformation); // 失败释放 FltMgr 引用。
            return STATUS_NAME_TOO_LONG; // 禁止截断路径。
        }
        RtlCopyMemory(targetBuffer, nameInformation->Volume.Buffer, nameInformation->Volume.Length); // 复制实际源卷。
        RtlCopyMemory((PUCHAR)targetBuffer + nameInformation->Volume.Length, targetName.Buffer, targetName.Length); // 拼接卷内目标。
        targetName.Buffer = targetBuffer; // 替换本次 create 为完整目标。
        targetName.Length += nameInformation->Volume.Length; // 合成名字字节数。
        targetName.MaximumLength = targetName.Length; // IoReplace 按长度复制，无需 NUL。
    }

    status = IoReplaceFileObjectName(
        FltObjects->FileObject,
        targetName.Buffer,
        targetName.Length);
    FltReleaseFileNameInformation(nameInformation); // IoReplace 已复制名字，可以释放源查询结果。
    if (!NT_SUCCESS(status)) {
        KswordARKRedirectLogFormat(
            "Warn",
            "File redirect failed, pid=%lu, ruleId=%lu, status=0x%08X.",
            (unsigned long)processId,
            (unsigned long)matchedRule.ruleId,
            (unsigned int)status);
        return status;
    }

    FltSetCallbackDataDirty(Data);
    FltObjects->FileObject->RelatedFileObject = NULL; // 重解析的是绝对 namespace 名字，不再相对原目录句柄。
    InterlockedIncrement64(&runtime->FileRedirectHits);
    *RedirectedOut = TRUE;

    KswordARKRedirectLogFormat(
        "Info",
        "File redirect applied, pid=%lu, ruleId=%lu.",
        (unsigned long)processId,
        (unsigned long)matchedRule.ruleId);
    return STATUS_SUCCESS;
}
