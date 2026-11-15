/* Backend 3 PoC：HVCI 开启下 DR+IDT 短窗口探针的最小 go/no-go gate 实现。 */
#include "kernel_noattach_probe.h"
/* __sidt / _InterlockedCompareExchange128 等 MSVC x64 intrinsics。 */
#include <intrin.h>

/* R0/R3 结构体必须定宽，一旦漂移立即编译期报错。 */
C_ASSERT(sizeof(KSWORD_ARK_KERNEL_NOATTACH_PROBE_REQUEST) == 32);
/* 响应 72 字节：IdtLimit 之后七个 ULONGLONG，总 16 + 56。 */
C_ASSERT(sizeof(KSWORD_ARK_KERNEL_NOATTACH_PROBE_RESPONSE) == 72);

#if defined(_M_AMD64) || defined(_M_X64)
/* 启用 __sidt intrinsic，仅在 AMD64 架构下存在。 */
#pragma intrinsic(__sidt)
#endif

/* x64 IDTR 内存布局：16 位 limit 后紧跟 64 位 base。 */
#pragma pack(push, 1)
typedef struct _KNAP_IDTR_LAYOUT
{
    /* IDT limit 字段，本机上通常为 0x0FFF。 */
    USHORT Limit;
    /* IDT 虚拟基址，被 CPU 装入 IDTR 后使用。 */
    ULONG_PTR Base;
} KNAP_IDTR_LAYOUT;
/* x64 IDT 单个 gate 固定 16 字节。 */
typedef struct _KNAP_IDT_ENTRY
{
    /* 低 16 位处理函数偏移。 */
    USHORT OffsetLow;
    /* 处理函数的代码段选择子。 */
    USHORT Selector;
    /* IST 与 gate 类型标志。 */
    USHORT IstAndType;
    /* 中 16 位处理函数偏移。 */
    USHORT OffsetMiddle;
    /* 高 32 位处理函数偏移。 */
    ULONG OffsetHigh;
    /* IDT entry 必须补齐 8 字节保留区。 */
    ULONG Reserved;
} KNAP_IDT_ENTRY;
#pragma pack(pop)

/* 对外 descriptor 固定 16 字节，这里再次断言内部布局与硬件一致。 */
C_ASSERT(sizeof(KNAP_IDT_ENTRY) == 16);

/* Phase A 只支持 vector 0..255，拒绝越界请求。 */
#define KNAP_MAX_VECTOR 0x100UL

/* 把两个 64 位半部拼成 128 位 descriptor 副本，供 R3 比对。 */
static VOID
KnapCopyEntryBytes(
    _In_ const KNAP_IDT_ENTRY* Entry,
    _Out_ unsigned long long* Low,
    _Out_ unsigned long long* High)
{
    /* 字节级拷贝，跨不同编译器下仍维持与 descriptor 内存布局一致。 */
    UCHAR raw[16];
    /* 入参守卫，调用点必须保证 Entry 非空。 */
    RtlCopyMemory(raw, Entry, sizeof(raw));
    /* 低 8 字节按小端序组装。 */
    *Low = ((unsigned long long)raw[0]) |
           ((unsigned long long)raw[1] << 8) |
           ((unsigned long long)raw[2] << 16) |
           ((unsigned long long)raw[3] << 24) |
           ((unsigned long long)raw[4] << 32) |
           ((unsigned long long)raw[5] << 40) |
           ((unsigned long long)raw[6] << 48) |
           ((unsigned long long)raw[7] << 56);
    /* 高 8 字节按同样顺序组装。 */
    *High = ((unsigned long long)raw[8]) |
            ((unsigned long long)raw[9] << 8) |
            ((unsigned long long)raw[10] << 16) |
            ((unsigned long long)raw[11] << 24) |
            ((unsigned long long)raw[12] << 32) |
            ((unsigned long long)raw[13] << 40) |
            ((unsigned long long)raw[14] << 48) |
            ((unsigned long long)raw[15] << 56);
}

/* 把当前线程固定到当前处理器组内的 CPU N，保证 __sidt 与后续访问同 CPU。 */
static VOID
KnapPinCurrentCpu(
    _Out_ GROUP_AFFINITY* OriginalAffinity)
{
    /* 运行时读当前 CPU 的 processor number，构造 group affinity。 */
    PROCESSOR_NUMBER proc;
    GROUP_AFFINITY target;
    KeGetCurrentProcessorNumberEx(&proc);
    RtlZeroMemory(&target, sizeof(target));
    target.Group = proc.Group;
    target.Mask = (KAFFINITY)((KAFFINITY)1 << proc.Number);
    /* 保存旧 affinity 以便后续恢复。 */
    KeSetSystemGroupAffinityThread(&target, OriginalAffinity);
}

/* 读本处理器的 IDTR 与指定向量的 16 字节 descriptor，响应字段填充。 */
static NTSTATUS
KnapReadIdtAndEntry(
    _In_ ULONG Vector,
    _Inout_ KSWORD_ARK_KERNEL_NOATTACH_PROBE_RESPONSE* Response)
{
#if defined(_M_AMD64) || defined(_M_X64)
    /* 当前线程旧 affinity，便于读取完成后回退。 */
    GROUP_AFFINITY oldAffinity = {0};
    /* 本地 IDTR 快照占 10 字节（USHORT + ULONG_PTR 打包 pack(1)）。 */
    KNAP_IDTR_LAYOUT idtr = {0};
    /* 指向 IDT entry 的指针，从 IDTR.Base 加 Vector * 16 计算。 */
    const KNAP_IDT_ENTRY* entry = NULL;
    /* 选中向量的 16 字节本地副本。 */
    KNAP_IDT_ENTRY copy = {0};
    /* 读内存可能触发 AV，SEH 仅在 PASSIVE_LEVEL 下可靠生效。 */
    NTSTATUS result = STATUS_SUCCESS;

    /* Vector 越界不读任何内核内存。 */
    if (Vector >= KNAP_MAX_VECTOR) { return STATUS_INVALID_PARAMETER; }
    /* 固定当前 CPU，避免 __sidt 后发生 context switch。 */
    KnapPinCurrentCpu(&oldAffinity);
    /* 把 limit 字段位置传给 intrinsic；intrinsic 会写入 10 字节完整 IDTR。 */
    __sidt(&idtr.Limit);
    /* 越限向量直接告知调用方，无需读内核内存。 */
    if (((ULONG)idtr.Limit + 1U) < (Vector + 1U) * sizeof(KNAP_IDT_ENTRY))
    {
        KeRevertToUserGroupAffinityThread(&oldAffinity);
        return STATUS_INVALID_PARAMETER;
    }
    /* 指针算术全部在 pack(1) 布局内完成。 */
    entry = (const KNAP_IDT_ENTRY*)(idtr.Base + Vector * sizeof(KNAP_IDT_ENTRY));
    /* SEH 包住 IDT 读，捕获可能的 KDP/HVPT 保护触发的 AV。 */
    __try
    {
        /* 使用结构体拷贝而非指针解引，避免额外对齐要求。 */
        RtlCopyMemory(&copy, entry, sizeof(copy));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        /* 读 IDT 若被拦截，返回异常代码；写 flag 后清空读回。 */
        Response->SehCode = GetExceptionCode();
        Response->StatusFlags |= KSWORD_ARK_KERNEL_NOATTACH_PROBE_FLAG_SEH_FIRED;
        result = STATUS_SUCCESS;
        KeRevertToUserGroupAffinityThread(&oldAffinity);
        Response->IdtLimit = (unsigned long)idtr.Limit;
        Response->IdtBase = (unsigned long long)idtr.Base;
        return result;
    }
    /* 恢复 affinity。 */
    KeRevertToUserGroupAffinityThread(&oldAffinity);
    /* 响应字段依次写入。 */
    Response->IdtLimit = (unsigned long)idtr.Limit;
    Response->IdtBase = (unsigned long long)idtr.Base;
    /* 描述子双半部通过字节序构造返回。 */
    KnapCopyEntryBytes(&copy, &Response->EntryLow, &Response->EntryHigh);
    return result;
#else
    /* 非 AMD64 架构直接拒绝；本项目只部署 x64。 */
    UNREFERENCED_PARAMETER(Vector);
    UNREFERENCED_PARAMETER(Response);
    return STATUS_NOT_SUPPORTED;
#endif
}

/* 用 RtlCopyMemory 把原值写回 IDT[vector]，所有访问均被 SEH 包裹。 */
static NTSTATUS
KnapProbeNoopWrite(
    _In_ ULONG Vector,
    _Inout_ KSWORD_ARK_KERNEL_NOATTACH_PROBE_RESPONSE* Response)
{
#if defined(_M_AMD64) || defined(_M_X64)
    /* 保存旧 affinity 用于恢复。 */
    GROUP_AFFINITY oldAffinity = {0};
    /* 本地 IDTR 快照。 */
    KNAP_IDTR_LAYOUT idtr = {0};
    /* 目标 entry 地址。 */
    KNAP_IDT_ENTRY* entry = NULL;
    /* 原值 + 读回值。 */
    KNAP_IDT_ENTRY original = {0};
    KNAP_IDT_ENTRY readback = {0};
    /* 本次写操作是否触发 SEH。 */
    BOOLEAN sehFired = FALSE;
    /* 捕获到的 SEH 异常代码。 */
    ULONG sehCode = 0UL;
    /* 读 IDT 阶段也必须 SEH 包裹，避免 IDT 不可读时直接 crash。 */
    BOOLEAN readOk = FALSE;

    /* Vector 越界立即拒绝。 */
    if (Vector >= KNAP_MAX_VECTOR) { return STATUS_INVALID_PARAMETER; }
    /* 固定当前 CPU 保证 __sidt 读到和写入落在同一 IDT。 */
    KnapPinCurrentCpu(&oldAffinity);
    /* 读取 IDTR 十字节。 */
    __sidt(&idtr.Limit);
    /* 越限向量路径独立拒绝。 */
    if (((ULONG)idtr.Limit + 1U) < (Vector + 1U) * sizeof(KNAP_IDT_ENTRY))
    {
        KeRevertToUserGroupAffinityThread(&oldAffinity);
        return STATUS_INVALID_PARAMETER;
    }
    /* 目标 entry 指针。 */
    entry = (KNAP_IDT_ENTRY*)(idtr.Base + Vector * sizeof(KNAP_IDT_ENTRY));
    /* 读原值到栈：PASSIVE_LEVEL + SEH 捕 AV 可挡 KDP 读保护。 */
    __try
    {
        RtlCopyMemory(&original, entry, sizeof(original));
        readOk = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        sehFired = TRUE;
        sehCode = GetExceptionCode();
    }
    /* 只有读成功才进入写阶段，否则直接记录 SEH。 */
    if (readOk)
    {
        __try
        {
            /* no-op 写：把刚读到的 16 字节原值写回，不改变语义。 */
            RtlCopyMemory(entry, &original, sizeof(original));
            /* 显式读回与再次比对。 */
            RtlCopyMemory(&readback, entry, sizeof(readback));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            /* 捕获到异常：HVCI/KDP/HVPT 把 IDT 页标为 RO。 */
            sehFired = TRUE;
            sehCode = GetExceptionCode();
        }
    }
    /* 恢复 affinity。 */
    KeRevertToUserGroupAffinityThread(&oldAffinity);
    /* IDTR + 原值回填。 */
    Response->IdtLimit = (unsigned long)idtr.Limit;
    Response->IdtBase = (unsigned long long)idtr.Base;
    if (readOk)
    {
        KnapCopyEntryBytes(&original, &Response->EntryLow, &Response->EntryHigh);
    }
    /* 读回字段：若 SEH 已命中，readback 保留零以便 R3 直观识别。 */
    if (!sehFired)
    {
        KnapCopyEntryBytes(&readback, &Response->ReadbackLow, &Response->ReadbackHigh);
        /* 读回与原值一致说明写成功。 */
        if (Response->ReadbackLow == Response->EntryLow &&
            Response->ReadbackHigh == Response->EntryHigh)
        {
            Response->StatusFlags |= KSWORD_ARK_KERNEL_NOATTACH_PROBE_FLAG_READBACK_MATCH;
        }
        Response->StatusFlags |= KSWORD_ARK_KERNEL_NOATTACH_PROBE_FLAG_COMPLETED;
    }
    else
    {
        /* 标记 SEH 命中并把异常代码一并返回。 */
        Response->StatusFlags |= KSWORD_ARK_KERNEL_NOATTACH_PROBE_FLAG_SEH_FIRED;
        Response->SehCode = sehCode;
    }
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Vector);
    UNREFERENCED_PARAMETER(Response);
    return STATUS_NOT_SUPPORTED;
#endif
}

/* 对外 IOCTL handler：校验 WDF 缓冲区，分发到三种操作。 */
NTSTATUS
KswordARKKernelNoAttachProbeIoctl(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    /* 缓冲区快照与指针。 */
    KSWORD_ARK_KERNEL_NOATTACH_PROBE_REQUEST request = {0};
    KSWORD_ARK_KERNEL_NOATTACH_PROBE_RESPONSE response = {0};
    PVOID input = NULL;
    PVOID output = NULL;
    size_t inputBytes = 0U;
    size_t outputBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    /* Device 当前未用，但仍需在 ioctl_registry 签名下接受。 */
    UNREFERENCED_PARAMETER(Device);
    /* 未提供完成计数指针视为 ABI 错误。 */
    if (BytesReturned == NULL) { return STATUS_INVALID_PARAMETER; }
    *BytesReturned = 0U;
    /* 必须由用户态在 PASSIVE_LEVEL 发起。 */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        WdfRequestGetRequestorMode(Request) != UserMode)
    {
        return STATUS_ACCESS_DENIED;
    }
    /* 请求长度必须完整一致。 */
    status = WdfRequestRetrieveInputBuffer(Request, sizeof(request), &input, &inputBytes);
    if (!NT_SUCCESS(status)) { return status; }
    if (InputBufferLength != sizeof(request) || inputBytes < sizeof(request))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    RtlCopyMemory(&request, input, sizeof(request));
    /* 预取输出缓冲区并验证容量。 */
    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(response), &output, &outputBytes);
    if (!NT_SUCCESS(status)) { return status; }
    if (OutputBufferLength < sizeof(response) || outputBytes < sizeof(response))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    /* 协议版本必须精确匹配。 */
    if (request.Version != KSWORD_ARK_KERNEL_NOATTACH_PROBE_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }
    /* 响应基础字段预填。 */
    response.Version = KSWORD_ARK_KERNEL_NOATTACH_PROBE_VERSION;
    response.QueryTick = (unsigned long long)KeQueryInterruptTime();
    /* 分发到具体操作。 */
    switch (request.Operation)
    {
    case KSWORD_ARK_KERNEL_NOATTACH_PROBE_OP_QUERY_IDT:
        /* 只读路径：读 IDTR + IDT entry。 */
        status = KnapReadIdtAndEntry(request.Vector, &response);
        if (NT_SUCCESS(status))
        {
            response.StatusFlags |= KSWORD_ARK_KERNEL_NOATTACH_PROBE_FLAG_COMPLETED;
        }
        break;
    case KSWORD_ARK_KERNEL_NOATTACH_PROBE_OP_PROBE_IDT_NOOP_WRITE:
        /* 关键 go/no-go：必须显式 Confirm=1 才允许触发潜在崩溃路径。 */
        if (request.Confirm != 1UL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        /* 调用自带 SEH 的写探针。 */
        status = KnapProbeNoopWrite(request.Vector, &response);
        break;
    case KSWORD_ARK_KERNEL_NOATTACH_PROBE_OP_STATUS:
        /* STATUS 当前仅再读 IDTR 快照用于 wall-clock 推断。 */
        status = KnapReadIdtAndEntry(request.Vector, &response);
        if (NT_SUCCESS(status))
        {
            response.StatusFlags |= KSWORD_ARK_KERNEL_NOATTACH_PROBE_FLAG_COMPLETED;
        }
        break;
    default:
        /* 未知操作码不触发任何副作用。 */
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    /* 即便业务错误也把已填响应回写，方便 R3 诊断。 */
    RtlCopyMemory(output, &response, sizeof(response));
    *BytesReturned = sizeof(response);
    return status;
}
