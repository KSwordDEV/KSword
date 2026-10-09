/*++

Module Name:

    redirect_runtime.c

Abstract:

    Shared runtime for KswordARK file and registry redirection rules.

Environment:

    Kernel-mode Driver Framework

--*/

#include "redirect_internal.h"
#include "ark/ark_push_lock.h"
#include "ark/ark_file_monitor.h" // 文件重定向与文件监控共用同一个 minifilter。

#include <stdarg.h>

static KSWORD_ARK_REDIRECT_RUNTIME g_KswordArkRedirectRuntime;

KSWORD_ARK_REDIRECT_RUNTIME*
KswordARKRedirectGetRuntime(
    VOID
    )
/*++

Routine Description:

    返回全局重定向运行时。中文说明：该指针只在驱动生命周期内有效，调用方仍
    必须使用 Runtime->Lock 保护规则快照访问。

Arguments:

    None.

Return Value:

    指向全局 KSWORD_ARK_REDIRECT_RUNTIME 的指针。

--*/
{
    return &g_KswordArkRedirectRuntime;
}

VOID
KswordARKRedirectLogFormat(
    _In_z_ PCSTR LevelText,
    _In_z_ _Printf_format_string_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    写入重定向模块日志。中文说明：日志失败不改变重定向逻辑，避免在高频路径
    中因为日志通道拥塞影响 I/O 行为。

Arguments:

    LevelText - 日志级别字符串。
    FormatText - printf 风格格式字符串。
    ... - 格式化参数。

Return Value:

    None. 本函数没有返回值。

--*/
{
    KSWORD_ARK_REDIRECT_RUNTIME* runtime = KswordARKRedirectGetRuntime();
    CHAR logBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    if (runtime == NULL || runtime->Device == WDF_NO_HANDLE || FormatText == NULL) {
        return;
    }

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), FormatText, arguments))) {
        (VOID)KswordARKDriverEnqueueLogFrame(
            runtime->Device,
            LevelText != NULL ? LevelText : "Info",
            logBuffer);
    }
    va_end(arguments);
}

ULONG
KswordARKRedirectCountRulesByTypeLocked(
    _In_ const KSWORD_ARK_REDIRECT_RUNTIME* Runtime,
    _In_ ULONG Type
    )
/*++

Routine Description:

    统计指定类型的启用规则数量。中文说明：调用方需持有 Runtime->Lock，函数只
    遍历固定大小数组，不自行加锁以避免热路径重复开销。

Arguments:

    Runtime - 重定向运行时。
    Type - KSWORD_ARK_REDIRECT_TYPE_* 类型。

Return Value:

    匹配类型且启用的规则数量。

--*/
{
    ULONG ruleIndex = 0UL;
    ULONG count = 0UL;

    if (Runtime == NULL) {
        return 0UL;
    }

    for (ruleIndex = 0UL; ruleIndex < KSWORD_ARK_REDIRECT_MAX_RULES; ++ruleIndex) {
        const KSWORD_ARK_REDIRECT_RULE* rule = &Runtime->Rules[ruleIndex];
        if ((rule->flags & KSWORD_ARK_REDIRECT_RULE_FLAG_ENABLED) != 0UL &&
            rule->type == Type) {
            count += 1UL;
        }
    }

    return count;
}

BOOLEAN
KswordARKRedirectIsRulePathValid(
    _In_ const WCHAR* Text,
    _In_ ULONG MaxChars,
    _Out_ USHORT* LengthCharsOut
    )
/*++

Routine Description:

    校验共享协议中的固定宽字符路径。中文说明：路径必须非空、NUL 终止并以 NT
    namespace 反斜杠开头，避免 R3 传入 UI 风格路径造成歧义。

Arguments:

    Text - 固定数组首地址。
    MaxChars - 固定数组容量。
    LengthCharsOut - 返回不含 NUL 的字符数。

Return Value:

    TRUE 表示路径可用；FALSE 表示路径非法。

--*/
{
    ULONG charIndex = 0UL;

    if (LengthCharsOut == NULL) {
        return FALSE;
    }
    *LengthCharsOut = 0U;

    if (Text == NULL || MaxChars == 0UL || Text[0] != L'\\') {
        return FALSE;
    }

    for (charIndex = 0UL; charIndex < MaxChars; ++charIndex) {
        if (Text[charIndex] == L'\0') {
            if (charIndex == 0UL || charIndex > 0x7FFFUL) {
                return FALSE;
            }
            *LengthCharsOut = (USHORT)charIndex;
            return TRUE;
        }
    }

    return FALSE;
}

NTSTATUS
KswordARKRedirectCopyUnicodeToAllocatedString(
    _In_ const UNICODE_STRING* Source,
    _Out_ UNICODE_STRING* Destination,
    _In_ ULONG PoolTag
    )
/*++

Routine Description:

    复制 UNICODE_STRING 到非分页池。中文说明：文件 pre-create 与注册表 pre 回调
    都可能需要暂存目标路径，复制时额外补 NUL，便于调试和日志。

Arguments:

    Source - 源字符串。
    Destination - 目标字符串，成功后 Buffer 需要调用方释放。
    PoolTag - 非分页池标签。

Return Value:

    STATUS_SUCCESS 或参数/内存错误。

--*/
{
    SIZE_T allocateBytes = 0U;

    if (Destination == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Destination, sizeof(*Destination));

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Source->Length > (USHORT)(0xFFFEU - sizeof(WCHAR))) {
        return STATUS_NAME_TOO_LONG;
    }

    allocateBytes = (SIZE_T)Source->Length + sizeof(WCHAR);
#pragma warning(push)
#pragma warning(disable:4996)
    Destination->Buffer = (PWSTR)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        allocateBytes,
        PoolTag);
#pragma warning(pop)
    if (Destination->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Destination->Buffer, allocateBytes);
    RtlCopyMemory(Destination->Buffer, Source->Buffer, Source->Length);
    Destination->Length = Source->Length;
    Destination->MaximumLength = (USHORT)allocateBytes;
    return STATUS_SUCCESS;
}

static BOOLEAN
KswordARKRedirectPathMatchesRule(
    _In_ const KSWORD_ARK_REDIRECT_RULE* Rule,
    _In_ const UNICODE_STRING* SourcePath
    )
/*++

Routine Description:

    判断路径是否命中规则。中文说明：EXACT 使用大小写不敏感相等，PREFIX 使用
    RtlPrefixUnicodeString，保持与 Windows 路径大小写语义一致。

Arguments:

    Rule - 规则快照项。
    SourcePath - 当前源路径。

Return Value:

    TRUE 表示命中；FALSE 表示未命中。

--*/
{
    UNICODE_STRING rulePath;
    USHORT ruleChars = 0U;

    if (Rule == NULL || SourcePath == NULL || SourcePath->Buffer == NULL) {
        return FALSE;
    }
    if (!KswordARKRedirectIsRulePathValid(
        Rule->sourcePath,
        KSWORD_ARK_REDIRECT_PATH_CHARS,
        &ruleChars)) {
        return FALSE;
    }

    rulePath.Buffer = (PWSTR)Rule->sourcePath;
    rulePath.Length = (USHORT)(ruleChars * sizeof(WCHAR));
    rulePath.MaximumLength = rulePath.Length;

    if (Rule->matchMode == KSWORD_ARK_REDIRECT_MATCH_EXACT) {
        return RtlEqualUnicodeString(&rulePath, SourcePath, TRUE) ? TRUE : FALSE;
    }
    if (Rule->matchMode == KSWORD_ARK_REDIRECT_MATCH_PREFIX) {
        return RtlPrefixUnicodeString(&rulePath, SourcePath, TRUE) ? TRUE : FALSE;
    }

    return FALSE;
}

NTSTATUS
KswordARKRedirectFindMatchLocked(
    _In_ KSWORD_ARK_REDIRECT_RUNTIME* Runtime,
    _In_ ULONG Type,
    _In_ ULONG ProcessId,
    _In_ const UNICODE_STRING* SourcePath,
    _Out_ KSWORD_ARK_REDIRECT_RULE* MatchedRuleOut
    )
/*++

Routine Description:

    在规则快照中查找第一个匹配项。中文说明：调用方必须持有共享锁或独占锁，
    规则按 R3 提交顺序匹配，便于 UI 控制优先级。

Arguments:

    Runtime - 重定向运行时。
    Type - 文件或注册表类型。
    ProcessId - 当前请求进程 ID；0 表示系统未知。
    SourcePath - 当前源路径。
    MatchedRuleOut - 返回命中的规则副本。

Return Value:

    STATUS_SUCCESS 表示命中；STATUS_NOT_FOUND 表示没有匹配规则。

--*/
{
    ULONG ruleIndex = 0UL;

    if (Runtime == NULL || SourcePath == NULL || MatchedRuleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(MatchedRuleOut, sizeof(*MatchedRuleOut));

    for (ruleIndex = 0UL; ruleIndex < KSWORD_ARK_REDIRECT_MAX_RULES; ++ruleIndex) {
        const KSWORD_ARK_REDIRECT_RULE* rule = &Runtime->Rules[ruleIndex];
        if ((rule->flags & KSWORD_ARK_REDIRECT_RULE_FLAG_ENABLED) == 0UL) {
            continue;
        }
        if (rule->type != Type || rule->action != KSWORD_ARK_REDIRECT_ACTION_REPLACE) {
            continue;
        }
        if (rule->processId != 0UL && rule->processId != ProcessId) {
            continue;
        }
        if (!KswordARKRedirectPathMatchesRule(rule, SourcePath)) {
            continue;
        }

        RtlCopyMemory(MatchedRuleOut, rule, sizeof(*MatchedRuleOut));
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

static NTSTATUS
KswordARKRedirectValidateRule(
    _In_ const KSWORD_ARK_REDIRECT_RULE* Rule
    )
/*++

Routine Description:

    校验一条重定向规则。中文说明：只接受文件/注册表替换规则，源和目标路径都
    必须是 NT namespace 路径，并且匹配模式只能为 exact/prefix。

Arguments:

    Rule - 待校验规则。

Return Value:

    STATUS_SUCCESS 表示规则可用；失败状态表示拒绝该规则。

--*/
{
    USHORT sourceChars = 0U;
    USHORT targetChars = 0U;

    if (Rule == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((Rule->flags & KSWORD_ARK_REDIRECT_RULE_FLAG_ENABLED) == 0UL) {
        return STATUS_SUCCESS;
    }
    if (Rule->type != KSWORD_ARK_REDIRECT_TYPE_FILE &&
        Rule->type != KSWORD_ARK_REDIRECT_TYPE_REGISTRY) {
        return STATUS_NOT_SUPPORTED;
    }
    if (Rule->action != KSWORD_ARK_REDIRECT_ACTION_REPLACE) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Rule->matchMode != KSWORD_ARK_REDIRECT_MATCH_EXACT &&
        Rule->matchMode != KSWORD_ARK_REDIRECT_MATCH_PREFIX) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKRedirectIsRulePathValid(
        Rule->sourcePath,
        KSWORD_ARK_REDIRECT_PATH_CHARS,
        &sourceChars)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKRedirectIsRulePathValid(
        Rule->targetPath,
        KSWORD_ARK_REDIRECT_PATH_CHARS,
        &targetChars)) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static VOID
KswordARKRedirectRefreshFlagsLocked(
    _Inout_ KSWORD_ARK_REDIRECT_RUNTIME* Runtime
    )
/*++

Routine Description:

    根据规则数量刷新运行时标志。中文说明：Registry callback 注册标志保留，文件
    与注册表启用状态由有效规则数量动态决定。

Arguments:

    Runtime - 重定向运行时。

Return Value:

    None. 本函数没有返回值。

--*/
{
    ULONG registryHooked = 0UL;

    if (Runtime == NULL) {
        return;
    }

    registryHooked = Runtime->RuntimeFlags & KSWORD_ARK_REDIRECT_RUNTIME_REGISTRY_HOOKED;
    Runtime->RuntimeFlags = registryHooked;
    Runtime->FileRuleCount = KswordARKRedirectCountRulesByTypeLocked(
        Runtime,
        KSWORD_ARK_REDIRECT_TYPE_FILE);
    Runtime->RegistryRuleCount = KswordARKRedirectCountRulesByTypeLocked(
        Runtime,
        KSWORD_ARK_REDIRECT_TYPE_REGISTRY);

    if (Runtime->FileRuleCount != 0UL) {
        Runtime->RuntimeFlags |= KSWORD_ARK_REDIRECT_RUNTIME_FILE_ACTIVE;
    }
    if (Runtime->RegistryRuleCount != 0UL) {
        Runtime->RuntimeFlags |= KSWORD_ARK_REDIRECT_RUNTIME_REGISTRY_ACTIVE;
    }
}

NTSTATUS
KswordARKRedirectInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_opt_ WDFDEVICE Device
    )
/*++

Routine Description:

    初始化重定向运行时。中文说明：规则表默认为空，注册表 callback 只在规则命中
    时生效，因此加载驱动不会改变系统行为。

Arguments:

    DriverObject - 驱动对象，用于注册 Cm callback。
    Device - WDF 控制设备，用于日志。

Return Value:

    STATUS_SUCCESS 或注册表 callback 注册失败状态。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&g_KswordArkRedirectRuntime, sizeof(g_KswordArkRedirectRuntime));
    ExInitializePushLock(&g_KswordArkRedirectRuntime.Lock);
    g_KswordArkRedirectRuntime.Device = Device;
    g_KswordArkRedirectRuntime.RegistryRegisterStatus = STATUS_NOT_SUPPORTED;

    status = KswordARKRedirectRegistryRegister(
        &g_KswordArkRedirectRuntime,
        DriverObject);
    g_KswordArkRedirectRuntime.RegistryRegisterStatus = status;
    if (NT_SUCCESS(status)) {
        g_KswordArkRedirectRuntime.RuntimeFlags |= KSWORD_ARK_REDIRECT_RUNTIME_REGISTRY_HOOKED;
        KswordARKRedirectLogFormat("Info", "Redirect registry callback registered.");
        return STATUS_SUCCESS;
    }

    KswordARKRedirectLogFormat(
        "Warn",
        "Redirect registry callback registration failed, status=0x%08X.",
        (unsigned int)status);
    return status;
}

VOID
KswordARKRedirectUninitialize(
    VOID
    )
/*++

Routine Description:

    卸载重定向运行时。中文说明：先清空规则表，再注销 Cm callback，避免卸载窗口
    中继续发生路径替换。

Arguments:

    None.

Return Value:

    None. 本函数没有返回值。

--*/
{
    KSWORD_ARK_REDIRECT_RUNTIME* runtime = KswordARKRedirectGetRuntime();

    if (runtime == NULL) {
        return;
    }

    KswordARKAcquirePushLockExclusive(&runtime->Lock);
    RtlZeroMemory(runtime->Rules, sizeof(runtime->Rules));
    runtime->FileRuleCount = 0UL;
    runtime->RegistryRuleCount = 0UL;
    runtime->RuntimeFlags &= KSWORD_ARK_REDIRECT_RUNTIME_REGISTRY_HOOKED;
    runtime->Generation += 1UL;
    KswordARKReleasePushLockExclusive(&runtime->Lock);

    KswordARKRedirectRegistryUnregister(runtime);
    runtime->RuntimeFlags = 0UL;
    runtime->RegistryRegisterStatus = STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKRedirectSetRules(
    _In_ const KSWORD_ARK_REDIRECT_SET_RULES_REQUEST* Request,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    替换或清空重定向规则快照。中文说明：函数先完整校验输入，再一次性切换规则
    表，避免半更新状态被回调路径观察到。

Arguments:

    Request - R3 规则请求。
    OutputBuffer - 响应缓冲。
    OutputBufferLength - 响应缓冲长度。
    BytesWrittenOut - 返回写入字节数。

Return Value:

    STATUS_SUCCESS 表示响应已写入；缓冲错误直接返回失败。

--*/
{
    KSWORD_ARK_REDIRECT_RUNTIME* runtime = KswordARKRedirectGetRuntime();
    KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE* response = NULL;
    ULONG ruleIndex = 0UL;
    ULONG appliedCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Request == NULL || OutputBuffer == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < sizeof(*response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_REDIRECT_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_REDIRECT_STATUS_UNKNOWN;
    response->rejectedIndex = 0xFFFFFFFFUL;
    response->lastStatus = STATUS_SUCCESS;
    *BytesWrittenOut = sizeof(*response);

    if (Request->version != KSWORD_ARK_REDIRECT_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_REDIRECT_STATUS_OPERATION_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }

    if (Request->action == KSWORD_ARK_REDIRECT_ACTION_REPLACE) {
        if (Request->ruleCount > KSWORD_ARK_REDIRECT_MAX_RULES) {
            response->status = KSWORD_ARK_REDIRECT_STATUS_INVALID_RULE;
            response->lastStatus = STATUS_INVALID_PARAMETER;
            return STATUS_SUCCESS;
        }

        for (ruleIndex = 0UL; ruleIndex < Request->ruleCount; ++ruleIndex) {
            status = KswordARKRedirectValidateRule(&Request->rules[ruleIndex]);
            if (!NT_SUCCESS(status)) {
                response->status = (status == STATUS_NOT_SUPPORTED) ?
                    KSWORD_ARK_REDIRECT_STATUS_UNSUPPORTED_TYPE :
                    KSWORD_ARK_REDIRECT_STATUS_INVALID_RULE;
                response->rejectedIndex = ruleIndex;
                response->lastStatus = status;
                return STATUS_SUCCESS;
            }
            if ((Request->rules[ruleIndex].flags & KSWORD_ARK_REDIRECT_RULE_FLAG_ENABLED) != 0UL) { // caller 已建立稳定池快照，无需再次在栈上复制 16 条路径规则。
                appliedCount += 1UL;
            }
        }
    }
    else if (Request->action != KSWORD_ARK_REDIRECT_ACTION_CLEAR &&
        Request->action != KSWORD_ARK_REDIRECT_ACTION_DISABLE) {
        response->status = KSWORD_ARK_REDIRECT_STATUS_INVALID_RULE;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    if (Request->action == KSWORD_ARK_REDIRECT_ACTION_REPLACE) { // 发布文件规则前确保回调实际运行。
        for (ruleIndex = 0UL; ruleIndex < Request->ruleCount; ++ruleIndex) { // 注册表规则不启动文件引擎。
            if (Request->rules[ruleIndex].type == KSWORD_ARK_REDIRECT_TYPE_FILE &&
                (Request->rules[ruleIndex].flags & KSWORD_ARK_REDIRECT_RULE_FLAG_ENABLED) != 0UL) { // 仅启用规则需要过滤。
                status = KswordARKFileMonitorEnsureFilteringStarted(); // 不改变旧文件监控采集开关。
                if (!NT_SUCCESS(status)) { // 引擎失败时保留原表，返回实际状态。
                    response->status = KSWORD_ARK_REDIRECT_STATUS_OPERATION_FAILED; // 不报告已应用。
                    response->rejectedIndex = ruleIndex; // 标明触发启动的文件规则。
                    response->lastStatus = status; // 保留 FltMgr 返回值。
                    return STATUS_SUCCESS; // 传输成功，操作失败。
                }
                break; // 引擎只需要确保启动一次。
            }
        }
    }

    KswordARKAcquirePushLockExclusive(&runtime->Lock);
    RtlZeroMemory(runtime->Rules, sizeof(runtime->Rules));
    if (Request->action == KSWORD_ARK_REDIRECT_ACTION_REPLACE && appliedCount != 0UL) {
        RtlCopyMemory(runtime->Rules, Request->rules,
            (SIZE_T)Request->ruleCount * sizeof(runtime->Rules[0])); // 全部规则验证后再一次性提交；未使用槽保持前面的清零状态。
    }
    runtime->Generation += 1UL;
    KswordARKRedirectRefreshFlagsLocked(runtime);
    response->runtimeFlags = runtime->RuntimeFlags;
    response->fileRuleCount = runtime->FileRuleCount;
    response->registryRuleCount = runtime->RegistryRuleCount;
    response->generation = runtime->Generation;
    KswordARKReleasePushLockExclusive(&runtime->Lock);

    response->appliedCount = appliedCount;
    if (Request->action == KSWORD_ARK_REDIRECT_ACTION_REPLACE) {
        response->status = KSWORD_ARK_REDIRECT_STATUS_APPLIED;
    }
    else if (Request->action == KSWORD_ARK_REDIRECT_ACTION_DISABLE) {
        response->status = KSWORD_ARK_REDIRECT_STATUS_DISABLED;
    }
    else {
        response->status = KSWORD_ARK_REDIRECT_STATUS_CLEARED;
    }
    response->lastStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKRedirectQueryStatus(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    查询重定向运行时状态。中文说明：返回当前规则快照、命中计数和 Cm callback
    注册状态，供 R3 后续 UI 展示。

Arguments:

    OutputBuffer - 响应缓冲。
    OutputBufferLength - 响应缓冲长度。
    BytesWrittenOut - 返回写入字节数。

Return Value:

    STATUS_SUCCESS 或缓冲区错误。

--*/
{
    KSWORD_ARK_REDIRECT_RUNTIME* runtime = KswordARKRedirectGetRuntime();
    KSWORD_ARK_REDIRECT_STATUS_RESPONSE* response = NULL;

    if (OutputBuffer == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < sizeof(*response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_REDIRECT_STATUS_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_REDIRECT_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_REDIRECT_STATUS_APPLIED;

    KswordARKAcquirePushLockShared(&runtime->Lock);
    response->runtimeFlags = runtime->RuntimeFlags;
    response->fileRuleCount = runtime->FileRuleCount;
    response->registryRuleCount = runtime->RegistryRuleCount;
    response->generation = runtime->Generation;
    response->fileRedirectHits = (ULONG64)runtime->FileRedirectHits;
    response->registryRedirectHits = (ULONG64)runtime->RegistryRedirectHits;
    response->registryRegisterStatus = runtime->RegistryRegisterStatus;
    RtlCopyMemory(response->rules, runtime->Rules, sizeof(response->rules));
    KswordARKReleasePushLockShared(&runtime->Lock);

    *BytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
