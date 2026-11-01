/*++

Module Name:

    network_runtime.c

Abstract:

    KswordARK WFP network rule runtime and status IOCTL backend.

Environment:

    Kernel-mode WFP callout driver

--*/

#include "network_internal.h"

#include <stdarg.h>

static KSWORD_ARK_NETWORK_RUNTIME g_KswordArkNetworkRuntime;

KSWORD_ARK_NETWORK_RUNTIME*
KswordARKNetworkGetRuntime(
    VOID
    )
/*++

Routine Description:

    返回网络运行时全局对象。中文说明：规则表访问必须由调用方持有 Lock，计数器
    可通过 interlocked 操作更新。

Arguments:

    None.

Return Value:

    指向 KSWORD_ARK_NETWORK_RUNTIME 的指针。

--*/
{
    return &g_KswordArkNetworkRuntime;
}

static VOID
KswordARKNetworkIpv4HostOrderToBytes(
    _In_ ULONG AddressHostOrder,
    _Out_writes_(4) UCHAR AddressBytes[4]
    )
/*++

Routine Description:

    将 WFP FWP_UINT32 IPv4 地址转换为稳定的网络序字节数组。中文说明：WFP 的
    FWP_UINT32 地址是主机序，shared/driver 事件行则使用与 InetNtop 兼容的字节序。

Arguments:

    AddressHostOrder - WFP 提供的主机序 IPv4 数值。
    AddressBytes - 接收 4 个网络序地址字节。

Return Value:

    None. 本函数没有返回值。

--*/
{
    // 中文说明：空输出指针不得进入 classify 热路径写入。
    if (AddressBytes == NULL) {
        // 中文说明：无目标缓冲时直接返回。
        return;
    }

    // 中文说明：最高有效字节对应 IPv4 第一段。
    AddressBytes[0] = (UCHAR)((AddressHostOrder >> 24U) & 0xFFUL);
    // 中文说明：次高有效字节对应 IPv4 第二段。
    AddressBytes[1] = (UCHAR)((AddressHostOrder >> 16U) & 0xFFUL);
    // 中文说明：第三个有效字节对应 IPv4 第三段。
    AddressBytes[2] = (UCHAR)((AddressHostOrder >> 8U) & 0xFFUL);
    // 中文说明：最低有效字节对应 IPv4 第四段。
    AddressBytes[3] = (UCHAR)(AddressHostOrder & 0xFFUL);
}

VOID
KswordARKNetworkRecordWfpAleEvent(
    _In_ ULONG Direction,
    _In_ ULONG Protocol,
    _In_ ULONG LocalAddressV4HostOrder,
    _In_ ULONG RemoteAddressV4HostOrder,
    _In_ USHORT LocalPort,
    _In_ USHORT RemotePort,
    _In_ ULONG ProcessId,
    _In_ ULONG Flags
    )
/*++

Routine Description:

    在固定非分页 ring 中记录真实 WFP ALE IPv4 流授权事件。中文说明：本函数只用
    KSPIN_LOCK，允许 classify 在 DISPATCH_LEVEL 调用；事件明确不含 packet payload。

Arguments:

    Direction - 入站或出站方向。
    Protocol - IP 协议号。
    LocalAddressV4HostOrder - 本地 IPv4 主机序数值。
    RemoteAddressV4HostOrder - 远端 IPv4 主机序数值。
    LocalPort - 主机序本地端口。
    RemotePort - 主机序远端端口。
    ProcessId - WFP metadata PID，未知时为 0。
    Flags - ALE layer、阻断与 action-write 状态标志。

Return Value:

    None. 本函数没有返回值。

--*/
{
    // 中文说明：运行时对象位于驱动静态非分页存储。
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    // 中文说明：先在栈上完整构造事件，缩短持有自旋锁的时间。
    KSWORD_ARK_NETWORK_WFP_EVENT_ROW eventRow = { 0 };
    // 中文说明：保存 KeQuerySystemTime 返回的 1601 UTC 100ns 时间。
    LARGE_INTEGER systemTime = { 0 };
    // 中文说明：保存获取事件自旋锁前的 IRQL。
    KIRQL oldIrql = PASSIVE_LEVEL;
    // 中文说明：保存本次写入的 ring 槽位。
    ULONG writeIndex = 0UL;

    // 中文说明：防御性检查静态运行时指针。
    if (runtime == NULL) {
        // 中文说明：运行时不可用时放弃该诊断事件，不影响 WFP 判定。
        return;
    }

    // 中文说明：读取系统 UTC 时间；该内核例程允许在 classify IRQL 调用。
    KeQuerySystemTime(&systemTime);
    // 中文说明：写入事件协议版本，供 R3 独立验证每行 ABI。
    eventRow.version = KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION;
    // 中文说明：写入当前事件行大小，支持后续协议尾部扩展。
    eventRow.size = sizeof(eventRow);
    // 中文说明：序号必须在锁内分配，此处保持 0。
    eventRow.sequence = 0ULL;
    // 中文说明：保存从 1601 UTC 起算的 100ns 时间。
    eventRow.timestamp100ns = (ULONG64)systemTime.QuadPart;
    // 中文说明：保存 connect/recv-accept 推导出的方向。
    eventRow.direction = Direction;
    // 中文说明：保存 WFP FWP_UINT8 协议号。
    eventRow.protocol = Protocol;
    // 中文说明：保存 WFP metadata 进程 ID。
    eventRow.processId = ProcessId;
    // 中文说明：强制声明无 payload 与 IPv4，调用方补充 ALE/action 标志。
    eventRow.flags = Flags |
        KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_NO_PAYLOAD |
        KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_IPV4;
    // 中文说明：保存主机序本地端口。
    eventRow.localPort = LocalPort;
    // 中文说明：保存主机序远端端口。
    eventRow.remotePort = RemotePort;
    // 中文说明：把本地主机序 IPv4 转为网络序字节数组。
    KswordARKNetworkIpv4HostOrderToBytes(LocalAddressV4HostOrder, eventRow.localAddress);
    // 中文说明：把远端主机序 IPv4 转为网络序字节数组。
    KswordARKNetworkIpv4HostOrderToBytes(RemoteAddressV4HostOrder, eventRow.remoteAddress);

    // 中文说明：自旋锁覆盖序号分配、覆盖计数和单槽完整写入。
    KeAcquireSpinLock(&runtime->EventLock, &oldIrql);
    // 中文说明：读取下一写入槽位。
    writeIndex = runtime->EventWriteIndex;
    // 中文说明：在锁内分配严格递增序号。
    eventRow.sequence = runtime->NextEventSequence;
    // 中文说明：推进下一序号；64 位回绕在现实生命周期不可达。
    runtime->NextEventSequence += 1ULL;
    // 中文说明：完整复制已初始化事件，读侧不会观察半写入行。
    RtlCopyMemory(&runtime->EventRing[writeIndex], &eventRow, sizeof(eventRow));
    // 中文说明：推进写指针并在固定容量处回绕。
    runtime->EventWriteIndex = (writeIndex + 1UL) % KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY;
    // 中文说明：未满时增加有效行数。
    if (runtime->EventCount < KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY) {
        // 中文说明：新事件占用一个此前未使用的槽位。
        runtime->EventCount += 1UL;
    }
    else {
        // 中文说明：已满时覆盖最旧行并累计 dropped。
        runtime->DroppedEventCount += 1ULL;
    }
    // 中文说明：事件行与所有 ring 元数据更新完成后恢复 IRQL。
    KeReleaseSpinLock(&runtime->EventLock, oldIrql);
}

NTSTATUS
KswordARKNetworkQueryWfpEvents(
    _In_ const KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST* Request,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    按 afterSequence 增量读取固定 WFP ALE 事件 ring。中文说明：结果按 sequence
    从旧到新排列，并分别报告累计覆盖 dropped 与本次 cursor 缺口。

Arguments:

    Request - 已由 METHOD_BUFFERED handler 复制到局部存储的查询请求。
    OutputBuffer - METHOD_BUFFERED 输出缓冲。
    OutputBufferLength - 输出缓冲实际长度。
    BytesWrittenOut - 返回写入字节数。

Return Value:

    STATUS_SUCCESS 表示已形成版本化响应；参数或输出缓冲非法时返回失败。

--*/
{
    // 中文说明：事件响应头不含占位 entries[1]。
    const size_t responseHeaderSize =
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE) -
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW);
    // 中文说明：运行时对象持有固定非分页 ring。
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    // 中文说明：输出缓冲在基本校验后解释为响应。
    KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE* response = NULL;
    // 中文说明：请求 maxRows 的规范化结果。
    ULONG maxRows = 0UL;
    // 中文说明：输出缓冲可容纳的事件行数。
    ULONG outputRowCapacity = 0UL;
    // 中文说明：先用 size_t 保存除法结果，避免大缓冲收窄为 ULONG 时回绕。
    size_t outputRowCapacitySize = 0U;
    // 中文说明：ring 当前有效行数快照。
    ULONG eventCount = 0UL;
    // 中文说明：ring 当前最旧槽位索引。
    ULONG oldestIndex = 0UL;
    // 中文说明：遍历有效事件的逻辑偏移。
    ULONG scanIndex = 0UL;
    // 中文说明：本次可用但可能因 maxRows 未全部返回的行数。
    ULONG availableCount = 0UL;
    // 中文说明：本次实际复制到响应的行数。
    ULONG returnedCount = 0UL;
    // 中文说明：处理驱动重载 cursor 后的有效 afterSequence。
    ULONG64 effectiveAfterSequence = 0ULL;
    // 中文说明：保存获取事件自旋锁前的 IRQL。
    KIRQL oldIrql = PASSIVE_LEVEL;

    // 中文说明：所有必需参数必须存在。
    if (Request == NULL || OutputBuffer == NULL || BytesWrittenOut == NULL || runtime == NULL) {
        // 中文说明：空参数无法形成安全响应。
        return STATUS_INVALID_PARAMETER;
    }
    // 中文说明：默认没有响应字节，失败路径保持 0。
    *BytesWrittenOut = 0U;
    // 中文说明：输出至少必须容纳不含占位行的响应头。
    if (OutputBufferLength < responseHeaderSize) {
        // 中文说明：让 WDF 返回明确的缓冲不足。
        return STATUS_BUFFER_TOO_SMALL;
    }

    // 中文说明：只清理响应头；每个返回事件行都会被完整覆盖，避免清零 4MB 缓冲。
    RtlZeroMemory(OutputBuffer, responseHeaderSize);
    // 中文说明：绑定版本化响应头。
    response = (KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE*)OutputBuffer;
    // 中文说明：响应始终回报事件子协议版本。
    response->version = KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION;
    // 中文说明：响应行大小是当前稳定事件 ABI。
    response->entrySize = sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW);
    // 中文说明：向 R3 公开驱动固定 ring 容量。
    response->capacity = KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY;
    // 中文说明：未启动 WFP filter 时返回明确能力状态。
    response->status =
        ((runtime->RuntimeFlags & KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED) != 0UL) ?
        KSWORD_ARK_NETWORK_STATUS_APPLIED :
        KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE;
    // 中文说明：WFP 不可用时返回完整 callout/filter 注册结果。
    response->lastStatus =
        (response->status == KSWORD_ARK_NETWORK_STATUS_APPLIED) ?
        STATUS_SUCCESS :
        runtime->RegisterStatus;

    // 中文说明：v1 使用精确固定请求头，拒绝未知版本、尾部扩展、保留位和查询标志。
    if (Request->version != KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->flags != KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_FLAG_NONE ||
        Request->reserved != 0ULL) {
        // 中文说明：协议错误通过固定响应表达，便于 R3 区分传输失败。
        response->status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        // 中文说明：记录稳定的 revision/parameter 错误。
        response->lastStatus =
            (Request->version != KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION) ?
            STATUS_REVISION_MISMATCH :
            STATUS_INVALID_PARAMETER;
        // 中文说明：错误响应只包含头。
        response->size = (ULONG)responseHeaderSize;
        // 中文说明：回报错误响应头长度。
        *BytesWrittenOut = responseHeaderSize;
        // 中文说明：METHOD_BUFFERED 传输本身成功。
        return STATUS_SUCCESS;
    }

    // 中文说明：maxRows=0 使用保守默认预算。
    maxRows = Request->maxRows == 0UL ?
        KSWORD_ARK_NETWORK_WFP_EVENT_DEFAULT_REQUESTED_ROWS :
        Request->maxRows;
    // 中文说明：限制单次持锁复制量。
    if (maxRows > KSWORD_ARK_NETWORK_WFP_EVENT_MAX_REQUESTED_ROWS) {
        // 中文说明：把过大请求钳制到稳定协议上限。
        maxRows = KSWORD_ARK_NETWORK_WFP_EVENT_MAX_REQUESTED_ROWS;
    }
    // 中文说明：按除法计算容量，避免 size_t 乘加溢出。
    outputRowCapacitySize = (OutputBufferLength - responseHeaderSize) /
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW);
    // 中文说明：输出容量不得超过调用方预算。
    if (outputRowCapacitySize > (size_t)maxRows) {
        // 中文说明：收窄为 maxRows。
        outputRowCapacitySize = (size_t)maxRows;
    }
    // 中文说明：maxRows 已小于 ULONG 上限，此处收窄安全。
    outputRowCapacity = (ULONG)outputRowCapacitySize;
    // 中文说明：默认沿用请求 cursor；有返回行时更新为最后行 sequence。
    response->nextSequence = Request->afterSequence;
    // 中文说明：准备在事件自旋锁内读取一致 ring 快照。
    effectiveAfterSequence = Request->afterSequence;

    // 中文说明：读侧与 classify 写侧共用自旋锁，允许并发 CPU 安全快照。
    KeAcquireSpinLock(&runtime->EventLock, &oldIrql);
    // 中文说明：捕获当前有效行数。
    eventCount = runtime->EventCount;
    // 中文说明：捕获累计覆盖数。
    response->droppedEventCount = runtime->DroppedEventCount;
    // 中文说明：空 ring 没有最旧/最新序号。
    if (eventCount != 0UL) {
        // 中文说明：写指针指向下一槽，向后退 eventCount 得到最旧槽。
        oldestIndex =
            (runtime->EventWriteIndex +
                KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY -
                eventCount) %
            KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY;
        // 中文说明：报告当前可恢复窗口的最旧序号。
        response->oldestSequence = runtime->EventRing[oldestIndex].sequence;
        // 中文说明：最后写入槽位位于写指针前一格。
        response->newestSequence =
            runtime->EventRing[
                (runtime->EventWriteIndex +
                    KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY -
                    1UL) %
                KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY].sequence;

        // 中文说明：驱动重载后 R3 cursor 可能大于新 ring 最新序号。
        if (effectiveAfterSequence > response->newestSequence) {
            // 中文说明：标记 cursor 已重置，避免 R3 永久等不到新事件。
            response->flags |= KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_RESET;
            // 中文说明：重置后从当前 ring 最旧行重新读取。
            effectiveAfterSequence = 0ULL;
            // 中文说明：重置响应 cursor，随后由返回行推进。
            response->nextSequence = 0ULL;
        }

        // 中文说明：afterSequence 落后于保留窗口时精确报告不可恢复缺口。
        if (effectiveAfterSequence < response->oldestSequence &&
            (response->oldestSequence - effectiveAfterSequence) > 1ULL) {
            // 中文说明：标记 cursor gap。
            response->flags |= KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_GAP;
            // 中文说明：计算 after 与 oldest 之间被覆盖的序号数。
            response->cursorGapCount =
                response->oldestSequence -
                effectiveAfterSequence -
                1ULL;
        }

        // 中文说明：按 ring 逻辑顺序扫描，确保响应 sequence 严格递增。
        for (scanIndex = 0UL; scanIndex < eventCount; ++scanIndex) {
            // 中文说明：把逻辑偏移映射到物理槽位。
            const ULONG ringIndex =
                (oldestIndex + scanIndex) %
                KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY;
            // 中文说明：读取锁保护下的稳定事件行。
            const KSWORD_ARK_NETWORK_WFP_EVENT_ROW* eventRow =
                &runtime->EventRing[ringIndex];

            // 中文说明：跳过 cursor 已消费的事件。
            if (eventRow->sequence <= effectiveAfterSequence) {
                // 中文说明：继续扫描后续更大序号。
                continue;
            }

            // 中文说明：统计 cursor 后全部可用事件，即使输出预算不足。
            availableCount += 1UL;
            // 中文说明：只复制输出容量允许的前 maxRows 行。
            if (returnedCount < outputRowCapacity) {
                // 中文说明：完整复制稳定事件 ABI，不泄露未初始化 padding。
                RtlCopyMemory(
                    &response->entries[returnedCount],
                    eventRow,
                    sizeof(*eventRow));
                // 中文说明：响应 cursor 推进到最后一个实际返回序号。
                response->nextSequence = eventRow->sequence;
                // 中文说明：增加已返回行数。
                returnedCount += 1UL;
            }
        }
    }
    // 中文说明：ring 快照读取与响应行复制结束，恢复调用 IRQL。
    KeReleaseSpinLock(&runtime->EventLock, oldIrql);

    // 中文说明：记录 cursor 后可用行总数。
    response->availableEventCount = availableCount;
    // 中文说明：记录实际写入行数。
    response->returnedEventCount = returnedCount;
    // 中文说明：有未返回事件时标记 truncated，下一轮从 nextSequence 续读。
    if (availableCount > returnedCount) {
        // 中文说明：响应存在后续页。
        response->flags |= KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_TRUNCATED;
    }
    // 中文说明：乘法上界由 outputRowCapacity 的除法计算保证。
    response->size = (ULONG)(responseHeaderSize +
        ((size_t)returnedCount * sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW)));
    // 中文说明：回报精确响应字节数。
    *BytesWrittenOut = (size_t)response->size;
    // 中文说明：版本化响应已经形成。
    return STATUS_SUCCESS;
}

VOID
KswordARKNetworkLogFormat(
    _In_z_ PCSTR LevelText,
    _In_z_ _Printf_format_string_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    写入网络模块日志。中文说明：WFP classify 热路径只记录规则切换和异常，避免
    高频网络包造成日志通道拥塞。

Arguments:

    LevelText - 日志级别。
    FormatText - printf 风格格式串。
    ... - 格式化参数。

Return Value:

    None. 本函数没有返回值。

--*/
{
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
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

BOOLEAN
KswordARKNetworkRuleMatchesLocked(
    _In_ const KSWORD_ARK_NETWORK_RULE* Rule,
    _In_ ULONG Direction,
    _In_ ULONG Protocol,
    _In_ USHORT LocalPort,
    _In_ USHORT RemotePort,
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    判断网络五元组摘要是否命中规则。中文说明：端口为 0 表示通配，protocol 为
    ANY 表示通配，processId 为 0 表示所有进程。

Arguments:

    Rule - 规则快照项。
    Direction - 当前方向掩码。
    Protocol - IPPROTO_* 协议号。
    LocalPort - 本地端口。
    RemotePort - 远端端口。
    ProcessId - 进程 ID，未知时为 0。

Return Value:

    TRUE 表示命中；FALSE 表示未命中。

--*/
{
    if (Rule == NULL || (Rule->flags & KSWORD_ARK_NETWORK_RULE_FLAG_ENABLED) == 0UL) {
        return FALSE;
    }
    if ((Rule->directionMask & Direction) == 0UL) {
        return FALSE;
    }
    if (Rule->protocol != KSWORD_ARK_NETWORK_PROTOCOL_ANY && Rule->protocol != Protocol) {
        return FALSE;
    }
    if (Rule->processId != 0UL && Rule->processId != ProcessId) {
        return FALSE;
    }
    if (Rule->localPort != 0U && Rule->localPort != LocalPort) {
        return FALSE;
    }
    if (Rule->remotePort != 0U && Rule->remotePort != RemotePort) {
        return FALSE;
    }

    return TRUE;
}

static NTSTATUS
KswordARKNetworkValidateRule(
    _In_ const KSWORD_ARK_NETWORK_RULE* Rule
    )
/*++

Routine Description:

    校验单条网络规则。中文说明：仅接受 allow/block/hide-port，方向必须包含入站
    或出站，协议仅允许 ANY/TCP/UDP。

Arguments:

    Rule - 待校验规则。

Return Value:

    STATUS_SUCCESS 表示规则可用；失败状态表示应拒绝规则。

--*/
{
    if (Rule == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((Rule->flags & KSWORD_ARK_NETWORK_RULE_FLAG_ENABLED) == 0UL) {
        return STATUS_SUCCESS;
    }
    if (Rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_ALLOW &&
        Rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_BLOCK &&
        Rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_HIDE_PORT) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((Rule->directionMask & KSWORD_ARK_NETWORK_DIRECTION_BOTH) == 0UL ||
        (Rule->directionMask & ~KSWORD_ARK_NETWORK_DIRECTION_BOTH) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Rule->protocol != KSWORD_ARK_NETWORK_PROTOCOL_ANY &&
        Rule->protocol != KSWORD_ARK_NETWORK_PROTOCOL_TCP &&
        Rule->protocol != KSWORD_ARK_NETWORK_PROTOCOL_UDP) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static VOID
KswordARKNetworkRefreshCountersLocked(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    )
/*++

Routine Description:

    刷新规则数量与运行时标志。中文说明：WFP 注册状态保留，规则活动状态根据当前
    快照自动计算。

Arguments:

    Runtime - 网络运行时。

Return Value:

    None. 本函数没有返回值。

--*/
{
    ULONG ruleIndex = 0UL;
    ULONG registeredFlags = 0UL;

    if (Runtime == NULL) {
        return;
    }

    registeredFlags = Runtime->RuntimeFlags &
        (KSWORD_ARK_NETWORK_RUNTIME_WFP_REGISTERED |
            KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED |
            KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED);
    Runtime->RuntimeFlags = registeredFlags;
    Runtime->RuleCount = 0UL;
    Runtime->BlockedRuleCount = 0UL;
    Runtime->HiddenPortRuleCount = 0UL;

    for (ruleIndex = 0UL; ruleIndex < KSWORD_ARK_NETWORK_MAX_RULES; ++ruleIndex) {
        const KSWORD_ARK_NETWORK_RULE* rule = &Runtime->Rules[ruleIndex];
        if ((rule->flags & KSWORD_ARK_NETWORK_RULE_FLAG_ENABLED) == 0UL) {
            continue;
        }
        Runtime->RuleCount += 1UL;
        if (rule->action == KSWORD_ARK_NETWORK_RULE_ACTION_BLOCK) {
            Runtime->BlockedRuleCount += 1UL;
        }
        if (rule->action == KSWORD_ARK_NETWORK_RULE_ACTION_HIDE_PORT) {
            Runtime->HiddenPortRuleCount += 1UL;
        }
    }

    if (Runtime->RuleCount != 0UL) {
        Runtime->RuntimeFlags |= KSWORD_ARK_NETWORK_RUNTIME_RULES_ACTIVE;
    }
    if (Runtime->HiddenPortRuleCount != 0UL) {
        Runtime->RuntimeFlags |= KSWORD_ARK_NETWORK_RUNTIME_PORT_HIDE;
    }
}

static VOID
KswordARKNetworkPublishClassifyRulesLocked(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    )
/*++

Routine Description:

    将低频规则状态发布为 DISPATCH_LEVEL 可读取的独立快照。中文说明：调用方持有
    Runtime->Lock；本函数只在短暂 spin-lock 临界区复制固定 32 项规则。

Arguments:

    Runtime - 网络运行时。

Return Value:

    None. 本函数没有返回值。

--*/
{
    KIRQL oldIrql = PASSIVE_LEVEL;

    if (Runtime == NULL) {
        return;
    }

    KeAcquireSpinLock(&Runtime->ClassifyRuleLock, &oldIrql);
    RtlCopyMemory(
        Runtime->ClassifyRules,
        Runtime->Rules,
        sizeof(Runtime->ClassifyRules));
    InterlockedExchange(
        &Runtime->ClassifyRulesActive,
        Runtime->BlockedRuleCount != 0UL ? 1L : 0L);
    KeReleaseSpinLock(&Runtime->ClassifyRuleLock, oldIrql);
}

NTSTATUS
KswordARKNetworkInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_opt_ WDFDEVICE Device
    )
/*++

Routine Description:

    初始化网络运行时并注册 WFP callout。中文说明：WFP 注册失败不应阻塞驱动主
    功能，因此调用方可以记录 warning 后继续加载。

Arguments:

    DriverObject - 驱动对象。
    Device - WDF 控制设备，用于日志。

Return Value:

    STATUS_SUCCESS 或 WFP 注册失败状态。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&g_KswordArkNetworkRuntime, sizeof(g_KswordArkNetworkRuntime));
    ExInitializePushLock(&g_KswordArkNetworkRuntime.Lock);
    // 中文说明：WFP classify 规则快照必须支持 DISPATCH_LEVEL 读取。
    KeInitializeSpinLock(&g_KswordArkNetworkRuntime.ClassifyRuleLock);
    // 中文说明：事件 ring 在 classify 可达的 DISPATCH_LEVEL 使用独立自旋锁。
    KeInitializeSpinLock(&g_KswordArkNetworkRuntime.EventLock);
    // 中文说明：IP packet 逐包 ring 使用独立自旋锁，避免 ALE 规则事件相互阻塞。
    KeInitializeSpinLock(&g_KswordArkNetworkRuntime.TrafficLock);
    // 中文说明：事件序号从 1 开始，0 保留为“没有 cursor”。
    g_KswordArkNetworkRuntime.NextEventSequence = 1ULL;
    // 中文说明：逐包序号同样从 1 开始，0 表示未建立 cursor。
    g_KswordArkNetworkRuntime.NextTrafficSequence = 1ULL;
    g_KswordArkNetworkRuntime.Device = Device;
    g_KswordArkNetworkRuntime.DriverObject = DriverObject;
    if (Device != WDF_NO_HANDLE) {
        g_KswordArkNetworkRuntime.DeviceObject = WdfDeviceWdmGetDeviceObject(Device);
    }
    g_KswordArkNetworkRuntime.RegisterStatus = STATUS_NOT_SUPPORTED;
    g_KswordArkNetworkRuntime.EngineStatus = STATUS_NOT_SUPPORTED;
    // 中文说明：逐包对象尚未注册时回报明确不支持状态。
    g_KswordArkNetworkRuntime.TrafficCaptureStatus = STATUS_NOT_SUPPORTED;
    // 中文说明：逐包 filter 常驻，但默认不复制报文，必须由 R3 显式启用。
    InterlockedExchange(
        &g_KswordArkNetworkRuntime.TrafficCaptureEnabled,
        0L);

    status = KswordARKNetworkWfpRegister(&g_KswordArkNetworkRuntime);
    g_KswordArkNetworkRuntime.RegisterStatus = status;
    if (NT_SUCCESS(status)) {
        g_KswordArkNetworkRuntime.RuntimeFlags |= KSWORD_ARK_NETWORK_RUNTIME_WFP_REGISTERED;
        KswordARKNetworkLogFormat("Info", "Network WFP callouts registered.");
        return STATUS_SUCCESS;
    }

    KswordARKNetworkLogFormat(
        "Warn",
        "Network WFP callout registration failed, status=0x%08X.",
        (unsigned int)status);
    return status;
}

VOID
KswordARKNetworkUninitialize(
    VOID
    )
/*++

Routine Description:

    清理网络运行时。中文说明：先清空规则，再注销 WFP callout 和 filter，避免卸载
    后 classify 继续引用规则表。

Arguments:

    None.

Return Value:

    None. 本函数没有返回值。

--*/
{
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();

    KswordARKNetworkManagedUninitialize();

    if (runtime == NULL) {
        return;
    }

    InterlockedExchange(&runtime->TrafficCaptureEnabled, 0L);

    KswordARKAcquirePushLockExclusive(&runtime->Lock);
    RtlZeroMemory(runtime->Rules, sizeof(runtime->Rules));
    runtime->RuleCount = 0UL;
    runtime->BlockedRuleCount = 0UL;
    runtime->HiddenPortRuleCount = 0UL;
    runtime->RuntimeFlags &=
        (KSWORD_ARK_NETWORK_RUNTIME_WFP_REGISTERED |
            KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED |
            KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED);
    runtime->Generation += 1UL;
    KswordARKNetworkPublishClassifyRulesLocked(runtime);
    KswordARKReleasePushLockExclusive(&runtime->Lock);

    KswordARKNetworkWfpUnregister(runtime);
    runtime->RuntimeFlags = 0UL;
    runtime->RegisterStatus = STATUS_NOT_SUPPORTED;
    runtime->EngineStatus = STATUS_NOT_SUPPORTED;
    runtime->TrafficCaptureStatus = STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKNetworkControlTrafficCapture(
    _In_ const KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_REQUEST* Request,
    _Out_ KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_RESPONSE* Response
    )
/*++

Routine Description:

    显式启停 WFP IP packet 逐包复制。filter/callout 保持注册，禁用态 classify 立即返回，
    因此不会在 UI 停止后继续解析或填充 ring。

--*/
{
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    KIRQL oldIrql = PASSIVE_LEVEL;
    BOOLEAN enable = FALSE;

    if (Request == NULL || Response == NULL || runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    if (Request->version != KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->flags != KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_FLAG_NONE ||
        (Request->action != KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_DISABLE &&
            Request->action != KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_ENABLE)) {
        Response->status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    enable = Request->action == KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_ENABLE;
    if (enable &&
        (runtime->RuntimeFlags &
            KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED) == 0UL) {
        Response->status = KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE;
        Response->lastStatus = runtime->TrafficCaptureStatus;
        Response->generation = (ULONG)InterlockedCompareExchange(
            &runtime->TrafficCaptureGeneration,
            0L,
            0L);
        return STATUS_SUCCESS;
    }

    // 中文说明：先关闭数据面，再等待已越过 classify 快速检查的写入者离开锁。
    InterlockedExchange(&runtime->TrafficCaptureEnabled, 0L);
    KeAcquireSpinLock(&runtime->TrafficLock, &oldIrql);
    runtime->TrafficWriteIndex = 0UL;
    runtime->TrafficCount = 0UL;
    runtime->NextTrafficSequence = 1ULL;
    runtime->DroppedTrafficCount = 0ULL;
    Response->generation = (ULONG)InterlockedIncrement(
        &runtime->TrafficCaptureGeneration);
    KeReleaseSpinLock(&runtime->TrafficLock, oldIrql);

    if (enable) {
        InterlockedExchange(&runtime->TrafficCaptureEnabled, 1L);
    }
    Response->enabled = enable ? 1UL : 0UL;
    Response->status = enable
        ? KSWORD_ARK_NETWORK_STATUS_APPLIED
        : KSWORD_ARK_NETWORK_STATUS_DISABLED;
    Response->lastStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKNetworkSetRules(
    _In_ const KSWORD_ARK_NETWORK_SET_RULES_REQUEST* Request,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    替换网络过滤规则快照。中文说明：规则快照仅在完整校验成功后一次性替换，
    避免 classify 路径观察到半更新内容。

Arguments:

    Request - R3 规则请求。
    OutputBuffer - 响应缓冲。
    OutputBufferLength - 响应缓冲长度。
    BytesWrittenOut - 返回写入字节数。

Return Value:

    STATUS_SUCCESS 表示响应已写入；缓冲错误直接返回失败。

--*/
{
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    KSWORD_ARK_NETWORK_SET_RULES_RESPONSE* response = NULL;
    KSWORD_ARK_NETWORK_RULE newRules[KSWORD_ARK_NETWORK_MAX_RULES] = { 0 };
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
    response = (KSWORD_ARK_NETWORK_SET_RULES_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_NETWORK_STATUS_UNKNOWN;
    response->rejectedIndex = 0xFFFFFFFFUL;
    response->lastStatus = STATUS_SUCCESS;
    *BytesWrittenOut = sizeof(*response);

    if (Request->version != KSWORD_ARK_NETWORK_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }

    if (Request->action == KSWORD_ARK_NETWORK_ACTION_REPLACE) {
        if (Request->ruleCount > KSWORD_ARK_NETWORK_MAX_RULES) {
            response->status = KSWORD_ARK_NETWORK_STATUS_INVALID_RULE;
            response->lastStatus = STATUS_INVALID_PARAMETER;
            return STATUS_SUCCESS;
        }

        for (ruleIndex = 0UL; ruleIndex < Request->ruleCount; ++ruleIndex) {
            status = KswordARKNetworkValidateRule(&Request->rules[ruleIndex]);
            if (!NT_SUCCESS(status)) {
                response->status = KSWORD_ARK_NETWORK_STATUS_INVALID_RULE;
                response->rejectedIndex = ruleIndex;
                response->lastStatus = status;
                return STATUS_SUCCESS;
            }
            RtlCopyMemory(&newRules[ruleIndex], &Request->rules[ruleIndex], sizeof(newRules[ruleIndex]));
            if ((newRules[ruleIndex].flags & KSWORD_ARK_NETWORK_RULE_FLAG_ENABLED) != 0UL) {
                appliedCount += 1UL;
            }
        }
    }
    else if (Request->action != KSWORD_ARK_NETWORK_ACTION_CLEAR &&
        Request->action != KSWORD_ARK_NETWORK_ACTION_DISABLE) {
        response->status = KSWORD_ARK_NETWORK_STATUS_INVALID_RULE;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    KswordARKAcquirePushLockExclusive(&runtime->Lock);
    RtlZeroMemory(runtime->Rules, sizeof(runtime->Rules));
    if (Request->action == KSWORD_ARK_NETWORK_ACTION_REPLACE && appliedCount != 0UL) {
        RtlCopyMemory(runtime->Rules, newRules, sizeof(newRules));
    }
    runtime->Generation += 1UL;
    KswordARKNetworkRefreshCountersLocked(runtime);
    KswordARKNetworkPublishClassifyRulesLocked(runtime);
    response->runtimeFlags = runtime->RuntimeFlags;
    response->appliedCount = runtime->RuleCount;
    response->blockedRuleCount = runtime->BlockedRuleCount;
    response->hiddenPortRuleCount = runtime->HiddenPortRuleCount;
    response->generation = runtime->Generation;
    KswordARKReleasePushLockExclusive(&runtime->Lock);

    if (Request->action == KSWORD_ARK_NETWORK_ACTION_REPLACE) {
        response->status = NT_SUCCESS(runtime->RegisterStatus) ?
            KSWORD_ARK_NETWORK_STATUS_APPLIED :
            KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE;
        response->lastStatus = runtime->RegisterStatus;
    }
    else if (Request->action == KSWORD_ARK_NETWORK_ACTION_DISABLE) {
        response->status = KSWORD_ARK_NETWORK_STATUS_DISABLED;
        response->lastStatus = STATUS_SUCCESS;
    }
    else {
        response->status = KSWORD_ARK_NETWORK_STATUS_CLEARED;
        response->lastStatus = STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKNetworkQueryStatus(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    查询网络过滤运行时。中文说明：返回 WFP 注册状态、规则快照、阻断计数与端口
    隐藏规则数量，R3 后续可据此过滤端口表展示。

Arguments:

    OutputBuffer - 响应缓冲。
    OutputBufferLength - 响应缓冲长度。
    BytesWrittenOut - 返回写入字节数。

Return Value:

    STATUS_SUCCESS 或缓冲区错误。

--*/
{
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    KSWORD_ARK_NETWORK_STATUS_RESPONSE* response = NULL;

    if (OutputBuffer == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < sizeof(*response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_NETWORK_STATUS_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
    response->status = NT_SUCCESS(runtime->RegisterStatus) ?
        KSWORD_ARK_NETWORK_STATUS_APPLIED :
        KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE;

    KswordARKAcquirePushLockShared(&runtime->Lock);
    response->runtimeFlags = runtime->RuntimeFlags;
    response->ruleCount = runtime->RuleCount;
    response->blockedRuleCount = runtime->BlockedRuleCount;
    response->hiddenPortRuleCount = runtime->HiddenPortRuleCount;
    response->generation = runtime->Generation;
    response->classifyCount = (ULONG64)runtime->ClassifyCount;
    response->blockedCount = (ULONG64)runtime->BlockedCount;
    response->registerStatus = runtime->RegisterStatus;
    response->engineStatus = runtime->EngineStatus;
    RtlCopyMemory(response->rules, runtime->Rules, sizeof(response->rules));
    KswordARKReleasePushLockShared(&runtime->Lock);

    *BytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

BOOLEAN
KswordARKNetworkShouldHidePort(
    _In_ ULONG Protocol,
    _In_ USHORT LocalPort,
    _In_ USHORT RemotePort,
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    判断端口是否应在 R3/R0 查询结果中隐藏。中文说明：当前仓库尚未有 R0 TCP 表
    枚举模块，本函数先提供可复用策略入口，后续端口列表查询接入即可生效。

Arguments:

    Protocol - TCP/UDP 协议号。
    LocalPort - 本地端口。
    RemotePort - 远端端口。
    ProcessId - 进程 ID。

Return Value:

    TRUE 表示端口应隐藏；FALSE 表示正常显示。

--*/
{
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    ULONG ruleIndex = 0UL;
    BOOLEAN shouldHide = FALSE;

    if ((runtime->RuntimeFlags & KSWORD_ARK_NETWORK_RUNTIME_PORT_HIDE) == 0UL) {
        return FALSE;
    }

    KswordARKAcquirePushLockShared(&runtime->Lock);
    for (ruleIndex = 0UL; ruleIndex < KSWORD_ARK_NETWORK_MAX_RULES; ++ruleIndex) {
        const KSWORD_ARK_NETWORK_RULE* rule = &runtime->Rules[ruleIndex];
        if (rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_HIDE_PORT) {
            continue;
        }
        if (KswordARKNetworkRuleMatchesLocked(
            rule,
            KSWORD_ARK_NETWORK_DIRECTION_BOTH,
            Protocol,
            LocalPort,
            RemotePort,
            ProcessId)) {
            shouldHide = TRUE;
            break;
        }
    }
    KswordARKReleasePushLockShared(&runtime->Lock);

    return shouldHide;
}
