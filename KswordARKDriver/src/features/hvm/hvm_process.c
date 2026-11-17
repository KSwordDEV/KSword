/*++

Module Name:

    hvm_process.c

Abstract:

    R-1 层的进程处置。语义见 hvm_process.h 与协议头。

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root dispatch.

--*/

#include "hvm_process.h"
#include "hvm_ept.h"
#include "hvm_ept_switch.h"
#include "hvm_memory.h"

#include "../../platform/pool_compat.h"

#if defined(_M_AMD64)

/* 层次物理页帧掩码。CR3 低位带 PCID 与标志，比较前必须掩掉。 */
#define KSW_HVM_PROCESS_CR3_FRAME_MASK 0x000FFFFFFFFFF000ULL
/* 页对齐掩码。 */
#define KSW_HVM_PROCESS_PAGE_MASK 0xFFFFFFFFFFFFF000ULL

/*
 * 拒绝对这些 PID 动手。
 *
 * 0 是 Idle、4 是 System。冻结或结束这两个里的任何一个都不是"处置了一个进程"，
 * 而是把机器停掉——而且是在 VMX root 里、以一种没有人能救回来的方式。
 */
#define KSW_HVM_PROCESS_PID_IDLE 0UL
#define KSW_HVM_PROCESS_PID_SYSTEM 4UL

/* CR3 归因用的池标签与快照上限。 */
#define KSW_HVM_PROCESS_RESOLVE_POOL_TAG 'RvHK'
/* SystemProcessInformation 的类别号。 */
#define KSW_HVM_PROCESS_INFORMATION_CLASS 5UL
/*
 * 快照上限 16 MiB。
 *
 * 一台跑着几百个进程的机器上这份快照是几百 KiB；给到 16 MiB 是为了不在进程数
 * 异常多的机器上无声地失败，同时仍然有个上限——归因是个可有可无的便利功能，
 * 它没有资格为了跑完而向内核要任意多的非分页内存。
 */
#define KSW_HVM_PROCESS_RESOLVE_SNAPSHOT_LIMIT (16UL * 1024UL * 1024UL)

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

/*
 * SystemProcessInformation 的前缀。
 *
 * 只声明到 UniqueProcessId 为止：后面的字段这里一个都不读，而多声明一个字段
 * 就多一处会随 Windows 版本漂移的偏移。遍历只需要两个东西——下一条在哪、
 * 这一条是谁。
 */
typedef struct _KSW_HVM_PROCESS_INFORMATION_PREFIX
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    UCHAR Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
} KSW_HVM_PROCESS_INFORMATION_PREFIX;

/*
 * 取一份进程快照，带一个有界的重试。
 *
 * 两次查询之间进程数会变，所以第一次问到的长度可能已经不够；重试四次并且每次
 * 多留一点余量。重试用尽就如实失败，而不是拿一份可能被截断的快照继续走——
 * 截断的后果是"扫过了没找到"，与"这个地址空间已经不在了"给出同一个答案。
 */
static NTSTATUS
KswordARKHvmProcessCaptureSnapshot(
    _Outptr_result_maybenull_ PVOID* SnapshotOut,
    _Out_ ULONG* SnapshotBytesOut
    )
{
    ULONG requiredBytes = 0UL;
    ULONG attempt = 0UL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    /* 拒绝不完整的调用契约。 */
    if (SnapshotOut == NULL || SnapshotBytesOut == NULL) {
        /* 返回明确的契约失败。 */
        return STATUS_INVALID_PARAMETER;
    }
    *SnapshotOut = NULL;
    *SnapshotBytesOut = 0UL;
    /* ZwQuerySystemInformation 只能在 PASSIVE_LEVEL 调用。 */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* 返回明确的运行级别失败。 */
        return STATUS_INVALID_DEVICE_STATE;
    }
    (void)ZwQuerySystemInformation(
        KSW_HVM_PROCESS_INFORMATION_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    /* 至少要装得下一条记录。 */
    if (requiredBytes < sizeof(KSW_HVM_PROCESS_INFORMATION_PREFIX)) {
        requiredBytes = sizeof(KSW_HVM_PROCESS_INFORMATION_PREFIX);
    }
    for (attempt = 0UL; attempt < 4UL; ++attempt) {
        PVOID snapshot = NULL;
        ULONG allocationBytes = 0UL;
        ULONG returnedBytes = 0UL;

        /* 留出两次查询之间新起进程的余量。 */
        if (requiredBytes > KSW_HVM_PROCESS_RESOLVE_SNAPSHOT_LIMIT - 65536UL) {
            /* 返回明确的资源上限失败。 */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        allocationBytes = requiredBytes + 65536UL;
        snapshot = KswordARKAllocateNonPagedPool(
            allocationBytes,
            KSW_HVM_PROCESS_RESOLVE_POOL_TAG);
        if (snapshot == NULL) {
            /* 返回明确的分配失败。 */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(snapshot, allocationBytes);
        status = ZwQuerySystemInformation(
            KSW_HVM_PROCESS_INFORMATION_CLASS,
            snapshot,
            allocationBytes,
            &returnedBytes);
        if (NT_SUCCESS(status)) {
            /* 把回报长度钳进实际分配范围，遍历才不会越界。 */
            if (returnedBytes == 0UL || returnedBytes > allocationBytes) {
                returnedBytes = allocationBytes;
            }
            *SnapshotOut = snapshot;
            *SnapshotBytesOut = returnedBytes;
            /* 完成一次完整的快照。 */
            return STATUS_SUCCESS;
        }
        ExFreePoolWithTag(snapshot, KSW_HVM_PROCESS_RESOLVE_POOL_TAG);
        /* 只对"缓冲不够"重试，别的失败原样返回。 */
        if (status != STATUS_INFO_LENGTH_MISMATCH &&
            status != STATUS_BUFFER_TOO_SMALL) {
            /* 返回查询本身的失败。 */
            return status;
        }
        requiredBytes = returnedBytes > allocationBytes
            ? returnedBytes
            : allocationBytes;
    }
    /* 重试用尽，如实回报最后一次的失败。 */
    return status;
}

/*
 * 把一个观测到的 CR3 归到一个 PID 上。
 *
 * 判据只有一条：attach 进那个进程、读回处理器实际在用的 CR3、和给定值比页帧。
 * 不读 EPROCESS 里的任何字段——Windows 不公开 DirectoryTableBase 的稳定偏移，
 * 而读错了字段的后果不是崩溃，是一个照样能走页表、照样能给出物理地址的错值。
 *
 * ScannedOut 单独回报，因为"扫过都不是它"与"一个都没扫成"要人做的事相反。
 */
static NTSTATUS
KswordARKHvmProcessResolveDirectoryBase(
    _In_ ULONGLONG DirectoryBase,
    _Out_ ULONG* ProcessIdOut,
    _Out_ ULONG* ScannedOut
    )
{
    PVOID snapshot = NULL;
    ULONG snapshotBytes = 0UL;
    ULONG offset = 0UL;
    ULONG scanned = 0UL;
    ULONGLONG target = DirectoryBase & KSW_HVM_PROCESS_CR3_FRAME_MASK;
    NTSTATUS status = STATUS_SUCCESS;

    /* 拒绝不完整的调用契约。 */
    if (ProcessIdOut == NULL || ScannedOut == NULL) {
        /* 返回明确的契约失败。 */
        return STATUS_INVALID_PARAMETER;
    }
    *ProcessIdOut = 0UL;
    *ScannedOut = 0UL;
    /* 零不是任何进程的页目录基址，不值得为它扫一遍。 */
    if (target == 0ULL) {
        /* 返回明确的参数失败。 */
        return STATUS_INVALID_PARAMETER;
    }
    status = KswordARKHvmProcessCaptureSnapshot(&snapshot, &snapshotBytes);
    /* 快照拿不到就如实失败，扫描数保持 0。 */
    if (!NT_SUCCESS(status)) {
        /* 返回快照本身的失败。 */
        return status;
    }
    while (offset + sizeof(KSW_HVM_PROCESS_INFORMATION_PREFIX) <= snapshotBytes) {
        const KSW_HVM_PROCESS_INFORMATION_PREFIX* entry =
            (const KSW_HVM_PROCESS_INFORMATION_PREFIX*)
                ((PUCHAR)snapshot + offset);
        ULONG processId = (ULONG)(ULONG_PTR)entry->UniqueProcessId;
        ULONG entryBytes = entry->NextEntryOffset;
        ULONGLONG candidate = 0ULL;

        /* Idle 没有可 attach 的地址空间，跳过而不是让 attach 去失败。 */
        if (processId != KSW_HVM_PROCESS_PID_IDLE) {
            if (NT_SUCCESS(KswordARKHvmMemoryResolveProcessDirectoryBase(
                    processId,
                    &candidate))) {
                ++scanned;
                if ((candidate & KSW_HVM_PROCESS_CR3_FRAME_MASK) == target) {
                    *ProcessIdOut = processId;
                    *ScannedOut = scanned;
                    ExFreePoolWithTag(
                        snapshot,
                        KSW_HVM_PROCESS_RESOLVE_POOL_TAG);
                    /* 完成一次成功的归因。 */
                    return STATUS_SUCCESS;
                }
            }
        }
        /* 偏移为零是链表结尾；不前进就会原地打转。 */
        if (entryBytes == 0UL || entryBytes > snapshotBytes - offset) {
            break;
        }
        offset += entryBytes;
    }
    ExFreePoolWithTag(snapshot, KSW_HVM_PROCESS_RESOLVE_POOL_TAG);
    *ScannedOut = scanned;
    /* 扫完了没有匹配。这不是错误，是一个确定的答案。 */
    return STATUS_NOT_FOUND;
}

/* 找一条命中给定层次基址的处置。退出路径与控制路径共用。 */
static KSW_HVM_PROCESS_SLOT*
KswordARKHvmProcessFindByDirectoryBase(
    _In_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG DirectoryBase
    )
{
    ULONG index = 0UL;

    /* 掩过的零值不是任何真实地址空间，直接不匹配。 */
    if (DirectoryBase == 0ULL) {
        /* 返回未命中。 */
        return NULL;
    }
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        KSW_HVM_PROCESS_SLOT* slot =
            &Runtime->ProcessDispositions[index];

        /* 只比较层次物理页帧，两侧都已在写入时掩过。 */
        if (slot->InUse &&
            slot->DirectoryBase == DirectoryBase) {
            /* 返回命中的那一条。 */
            return slot;
        }
    }
    /* 返回未命中。 */
    return NULL;
}

/* 找一条按 PID 记录的处置。撤销与重复检测用。 */
static KSW_HVM_PROCESS_SLOT*
KswordARKHvmProcessFindByProcessId(
    _In_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG ProcessId
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        KSW_HVM_PROCESS_SLOT* slot =
            &Runtime->ProcessDispositions[index];

        if (slot->InUse && slot->ProcessId == ProcessId) {
            /* 返回命中的那一条。 */
            return slot;
        }
    }
    /* 返回未命中。 */
    return NULL;
}

/* 取一个空槽，满了返回 NULL。 */
static KSW_HVM_PROCESS_SLOT*
KswordARKHvmProcessAllocateSlot(
    _In_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        if (!Runtime->ProcessDispositions[index].InUse) {
            /* 返回第一个可用槽。 */
            return &Runtime->ProcessDispositions[index];
        }
    }
    /* 返回容量耗尽。 */
    return NULL;
}

/* 把一条处置连同它占用的层次一起释放。调用方持运行时锁。 */
static VOID
KswordARKHvmProcessReleaseSlotLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_PROCESS_SLOT* Slot
    )
{
    /* 先放层次台账，再清记录：反过来会丢掉层次序号而泄露一套层次。 */
    if (Slot->HierarchyIndex != 0UL) {
        KswordARKHvmEptSwitchReleaseLeaf(
            Runtime,
            Slot->HierarchyIndex);
    }
    RtlZeroMemory(Slot, sizeof(*Slot));
    /* 计数只在这里与安装处变化，两边都持锁。 */
    if (Runtime->ProcessDispositionCount != 0UL) {
        Runtime->ProcessDispositionCount -= 1UL;
    }
}

/* 把驱动侧记录填进协议行。 */
static VOID
KswordARKHvmProcessFillRow(
    _In_ const KSW_HVM_PROCESS_SLOT* Slot,
    _Out_ KSWORD_ARK_HVM_PROCESS_ROW* Row
    )
{
    RtlZeroMemory(Row, sizeof(*Row));
    Row->processId = Slot->ProcessId;
    Row->disposition = Slot->Disposition;
    Row->directoryBase = Slot->DirectoryBase;
    Row->guestPhysicalAddress = Slot->GuestPhysicalAddress;
    Row->guestLinearAddress = Slot->GuestLinearAddress;
    Row->interceptCount = (ULONGLONG)InterlockedCompareExchange64(
        (volatile LONG64*)&Slot->InterceptCount,
        0LL,
        0LL);
    Row->hierarchyIndex = Slot->HierarchyIndex;
}

/* 把整张表写进响应。 */
static VOID
KswordARKHvmProcessPublishTable(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* Response
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        const KSW_HVM_PROCESS_SLOT* slot =
            &Runtime->ProcessDispositions[index];

        if (!slot->InUse) {
            /* 跳过空槽而不是留一行零，否则调用方分不清空槽与零计数。 */
            continue;
        }
        KswordARKHvmProcessFillRow(
            slot,
            &Response->rows[Response->returnedRows]);
        Response->returnedRows += 1UL;
    }
    Response->rowCount = Runtime->ProcessDispositionCount;
}

/*
 * 安装一条处置。调用方持运行时锁，且已确认常驻停着。
 *
 * 顺序是先算出目标页、再造层次、最后才发布记录：任何一步失败都不留下"记录在
 * 表里但层次没造出来"的中间态——那种中间态在退出路径上会被读成一个合法的
 * 层次序号，然后切到一套不存在的层次上去。
 */
static NTSTATUS
KswordARKHvmProcessArmLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_PROCESS_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* Response
    )
{
    KSW_HVM_PROCESS_SLOT* slot = NULL;
    KSW_HVM_EPT_SPLIT* split = NULL;
    volatile ULONGLONG* entry = NULL;
    ULONGLONG directoryBase = 0ULL;
    ULONGLONG guestPhysical = 0ULL;
    ULONGLONG physicalPage = 0ULL;
    ULONGLONG originalEntry = 0ULL;
    ULONGLONG deniedEntry = 0ULL;
    ULONG hierarchyIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* 拒绝对 Idle 与 System 动手。 */
    if (Request->processId == KSW_HVM_PROCESS_PID_IDLE ||
        Request->processId == KSW_HVM_PROCESS_PID_SYSTEM) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_PROTECTED_TARGET;
        /* 返回明确的目标拒绝。 */
        return STATUS_ACCESS_DENIED;
    }
    /*
     * 拒绝对自己动手。
     *
     * 处置生效时注入的是 #PF 或 #UD，落在发起这次调用的那个进程头上就是把
     * 控制通路自己掐断——之后连撤销都没人能发出来。
     */
    if (Request->processId ==
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId()) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_PROTECTED_TARGET;
        /* 返回明确的目标拒绝。 */
        return STATUS_ACCESS_DENIED;
    }
    /* 作用域完全靠 CR3-load exiting，缺了就拒绝而不是降级成全机器生效。 */
    if ((Runtime->CrPolicyFlags &
            KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3) == 0UL) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_CR3_TRACKING_REQUIRED;
        /* 返回明确的前提缺失。 */
        return STATUS_NOT_SUPPORTED;
    }
    /* 没有第二套层次就没有"受限"可选。 */
    if (!Runtime->EptpSwitchArmed) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED;
        /* 返回明确的前提缺失。 */
        return STATUS_NOT_SUPPORTED;
    }
    /* 同一个进程只允许有一条处置，否则第二条的层次永远选不上。 */
    if (KswordARKHvmProcessFindByProcessId(
            Runtime,
            Request->processId) != NULL) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_ALREADY_ARMED;
        /* 返回明确的重复安装拒绝。 */
        return STATUS_OBJECT_NAME_COLLISION;
    }
    /* 取一个槽，满了就在什么都还没分配时拒绝。 */
    slot = KswordARKHvmProcessAllocateSlot(Runtime);
    if (slot == NULL) {
        Response->status = KSWORD_ARK_HVM_PROCESS_STATUS_TABLE_FULL;
        /* 返回明确的容量耗尽。 */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* 解析目标进程真正在用的层次基址。 */
    status = KswordARKHvmMemoryResolveProcessDirectoryBase(
        Request->processId,
        &directoryBase);
    if (!NT_SUCCESS(status)) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_PROCESS_LOOKUP_FAILED;
        Response->lastStatus = status;
        /* 返回明确的进程解析失败。 */
        return status;
    }
    /* 只留层次物理页帧，退出路径上的比较用的就是这个形态。 */
    directoryBase &= KSW_HVM_PROCESS_CR3_FRAME_MASK;
    /*
     * 把要拒绝执行的那一页翻译成客户物理地址。
     *
     * 调用方没给线性地址时无从选起：驱动这里没有"这个进程的主映像入口"这样一个
     * 便宜的答案，猜一页的后果是拒绝落在一页永远不会被执行的地址上——那等于
     * 什么都没做，而且从外面看和成功一模一样。所以缺这个参数是拒绝。
     */
    if (Request->guestLinearAddress == 0ULL) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST;
        /* 返回明确的参数缺失。 */
        return STATUS_INVALID_PARAMETER;
    }
    status = KswordARKHvmMemoryTranslate(
        directoryBase,
        Request->guestLinearAddress,
        &guestPhysical,
        NULL);
    if (!NT_SUCCESS(status)) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED;
        Response->lastStatus = status;
        /* 返回明确的翻译失败。 */
        return status;
    }
    /* EPT 叶的粒度是页，落到页边界上。 */
    physicalPage = guestPhysical & KSW_HVM_PROCESS_PAGE_MASK;
    /* 切开覆盖这一页的 2 MiB 叶，取得 4 KiB 粒度。 */
    status = KswordARKHvmEptEnsureSplitLocked(
        Runtime,
        physicalPage,
        &split);
    if (!NT_SUCCESS(status)) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED;
        Response->lastStatus = status;
        /* 返回明确的切分失败。 */
        return status;
    }
    /* 取基座里这一页的叶项，受限层次以它为底。 */
    entry = KswordARKHvmEptFindLeafEntry(Runtime, physicalPage);
    if (entry == NULL) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED;
        Response->lastStatus = STATUS_NOT_FOUND;
        /* 返回明确的叶查找失败。 */
        return STATUS_NOT_FOUND;
    }
    originalEntry = *entry;
    /*
     * 受限层次只去掉执行位，读写照旧。
     *
     * 保留读写不是宽容：进程的代码页同时会被内核以数据方式读到（换页、镜像
     * 校验、调试器），把读也拒掉会让那些无关路径也撞上违规，而它们并不在目标
     * 地址空间里，本机制也就没有正当理由动它们。
     */
    deniedEntry = originalEntry & ~KSW_EPT_EXECUTE;
    /*
     * 造这一条自己的受限层次并立刻按处理器走表复核。
     *
     * 复核不是同义反复：写入走的是最后一级，复核从根出发沿被改写的父项往下走。
     * 索引算错一级或父项被重指，得到的层次在结构上仍然合法、处理器会照用不误，
     * 没有别的症状能把它抓出来。
     */
    status = KswordARKHvmEptSwitchBuildLeaf(
        Runtime,
        physicalPage,
        originalEntry,
        deniedEntry,
        (const volatile ULONGLONG*)split->PageTable,
        &hierarchyIndex);
    if (NT_SUCCESS(status)) {
        status = KswordARKHvmEptSwitchVerifyLeaf(
            Runtime,
            hierarchyIndex);
        /* 复核不过就把刚造出来的层次放掉，不留下半装好的记录。 */
        if (!NT_SUCCESS(status)) {
            KswordARKHvmEptSwitchReleaseLeaf(
                Runtime,
                hierarchyIndex);
        }
    }
    if (!NT_SUCCESS(status)) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED;
        Response->lastStatus = status;
        /* 返回明确的层次构造失败。 */
        return status;
    }
    /* 全部就绪之后才发布记录。 */
    slot->ProcessId = Request->processId;
    slot->Disposition = Request->operation;
    slot->HierarchyIndex = hierarchyIndex;
    slot->DirectoryBase = directoryBase;
    slot->GuestPhysicalAddress = physicalPage;
    slot->GuestLinearAddress = Request->guestLinearAddress;
    slot->InterceptCount = 0LL;
    /* InUse 最后置位：退出路径靠它判断这一条是否可用。 */
    slot->InUse = TRUE;
    Runtime->ProcessDispositionCount += 1UL;
    Response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
    /* 返回完整的安装成功。 */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmProcessControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_PROCESS_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* Response
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* 先写完整的响应身份，任何一条返回路径都不留半张响应。 */
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->generation = Runtime->Generation;
    Response->stateFlags = (ULONGLONG)Runtime->StateFlags;
    /*
     * 校验完整的版本化请求契约。
     *
     * directoryBase 只属于 RESOLVE_CR3，而那条操作走在这个函数外面。所以到了
     * 这里它必须是零：带着值进来说明调用方把两种操作的请求搞混了，而那种混淆
     * 在这些操作上恰好不会有任何症状——字段根本不会被读。
     */
    if (Request->version != KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->directoryBase != 0ULL) {
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST;
        /* 返回明确的契约失败。 */
        return STATUS_INVALID_PARAMETER;
    }
    switch (Request->operation) {
    case KSWORD_ARK_HVM_PROCESS_OP_QUERY:
        KswordARKHvmProcessPublishTable(Runtime, Response);
        Response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
        /* 只读操作到此结束。 */
        break;
    case KSWORD_ARK_HVM_PROCESS_OP_FREEZE:
    case KSWORD_ARK_HVM_PROCESS_OP_TERMINATE:
        status = KswordARKHvmProcessArmLocked(
            Runtime,
            Request,
            Response);
        /* 无论成败都把当前表回报出去，调用方一次调用就能看见落点。 */
        KswordARKHvmProcessPublishTable(Runtime, Response);
        break;
    case KSWORD_ARK_HVM_PROCESS_OP_RELEASE: {
        KSW_HVM_PROCESS_SLOT* slot =
            KswordARKHvmProcessFindByProcessId(
                Runtime,
                Request->processId);

        if (slot == NULL) {
            Response->status =
                KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND;
            status = STATUS_NOT_FOUND;
        } else if (InterlockedCompareExchange(
                &Runtime->ResidentProcessorCount,
                0L,
                0L) != 0L) {
            /*
             * 常驻期间只标记，不回收。
             *
             * 层次的页此刻可能正被某个核用着，放掉就是没有症状的内存破坏；而
             * 只把记录清掉又会让正在自旋的那个核永远冻着。标记之后：还没进来的
             * 核不会再选中它，已经卡住的核在下一次违规上自己换回基座。真正的
             * 回收留给常驻停下来时的 Reset。
             */
            slot->Disposition =
                KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED;
            Response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
        } else {
            KswordARKHvmProcessReleaseSlotLocked(Runtime, slot);
            Response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
        }
        KswordARKHvmProcessPublishTable(Runtime, Response);
        break;
    }
    case KSWORD_ARK_HVM_PROCESS_OP_RELEASE_ALL:
        if (InterlockedCompareExchange(
                &Runtime->ResidentProcessorCount,
                0L,
                0L) != 0L) {
            ULONG index = 0UL;

            /* 常驻期间逐条标记，理由与单条撤销完全一样。 */
            for (index = 0UL;
                 index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
                 ++index) {
                KSW_HVM_PROCESS_SLOT* slot =
                    &Runtime->ProcessDispositions[index];

                if (slot->InUse) {
                    slot->Disposition =
                        KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED;
                }
            }
        } else {
            KswordARKHvmProcessResetLocked(Runtime);
        }
        Response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
        KswordARKHvmProcessPublishTable(Runtime, Response);
        break;
    default:
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST;
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    /* 回报最终的表规模与代次。 */
    Response->generation = Runtime->Generation;
    /* 返回完整的操作结果。 */
    return status;
}

NTSTATUS
KswordARKHvmProcessControl(
    _In_ const KSWORD_ARK_HVM_PROCESS_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* Response
    )
{
    KSW_HVM_RUNTIME* runtime = KswordARKHvmGetRuntime();
    BOOLEAN mutating = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    /* 拒绝不完整的调用契约，且在取锁之前。 */
    if (Request == NULL || Response == NULL || runtime == NULL) {
        /* 返回明确的契约失败。 */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * CR3 归因走在锁外面，而且走在 Initialized 检查前面。
     *
     * 两个理由，都不是优化。它一个字节的 HVM 状态都不碰，把它放进临界区意味着
     * 一次几百个进程的 attach 遍历全程压着那把与退出路径共用的锁。而"必须先
     * prepare 才能归因"更是把事情办反了：最需要归因的时刻恰恰是常驻已经停下、
     * 用户正在看命中记录的那一刻。
     */
    if (Request->operation == KSWORD_ARK_HVM_PROCESS_OP_RESOLVE_CR3) {
        ULONG resolvedProcessId = 0UL;
        ULONG scanned = 0UL;

        RtlZeroMemory(Response, sizeof(*Response));
        Response->version = KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        /*
         * 这条路径绕开了 ControlLocked，所以版本与字段契约要在这里自己校验
         * 一遍。绕开检查的分支不会有任何症状——它照样返回一个格式正确的响应。
         */
        if (Request->version != KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION ||
            Request->size != sizeof(*Request) ||
            Request->processId != 0UL ||
            Request->guestLinearAddress != 0ULL) {
            Response->status =
                KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST;
            Response->lastStatus = STATUS_INVALID_PARAMETER;
            /* 协议层成功，语义层拒绝。 */
            return STATUS_SUCCESS;
        }
        status = KswordARKHvmProcessResolveDirectoryBase(
            Request->directoryBase,
            &resolvedProcessId,
            &scanned);
        Response->resolvedProcessId = resolvedProcessId;
        Response->resolvedScannedProcesses = scanned;
        Response->lastStatus = status;
        if (NT_SUCCESS(status)) {
            Response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
        } else if (status == STATUS_NOT_FOUND) {
            /* 扫过了没匹配上。scanned 是这句话的证据。 */
            Response->status = KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND;
        } else if (status == STATUS_INVALID_PARAMETER) {
            Response->status = KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST;
        } else {
            /* 连快照都没拿到。scanned 保持 0，两者由此区分得开。 */
            Response->status =
                KSWORD_ARK_HVM_PROCESS_STATUS_PROCESS_LOOKUP_FAILED;
        }
        /* 协议层恒定成功，语义结果全在 status 与两个计数里。 */
        return STATUS_SUCCESS;
    }
    /*
     * 只有**安装**受"常驻停着"的限制。
     *
     * 安装要分页、切叶、造层次，那些都是退出路径不持锁在读的东西。撤销不碰这些：
     * 常驻期间它只改一个已存在记录里的一个字段，把这条记录变成"不再选中、遇到就
     * 换回基座"。把撤销也一起挡在门外，就等于"解除冻结必须先关掉整个 hypervisor"
     * —— 那样冻结只是半个功能。
     */
    mutating =
        Request->operation == KSWORD_ARK_HVM_PROCESS_OP_FREEZE ||
        Request->operation == KSWORD_ARK_HVM_PROCESS_OP_TERMINATE;
    /* 与其它生命周期与 EPT 操作串行。 */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&runtime->Lock);
    /* 独占不附加会话保留全部 EPT/策略身份，查询仍可读取。 */
    if (KswordARKNoAttachReserved() && Request->operation != KSWORD_ARK_HVM_PROCESS_OP_QUERY) {
        /* 预约检查位于同一运行时锁内，不能与 OPEN 形成检查后写入竞态。 */
        ExReleasePushLockExclusive(&runtime->Lock);
        /* 此拒绝没有修改资源或通用协议台账。 */
        KeLeaveCriticalRegion();
        /* 电源停止后 residentCount=0 也不能接管保留资源。 */
        return STATUS_DEVICE_BUSY;
    }
    if (!runtime->Initialized) {
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version = KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_NOT_PREPARED;
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* 协议层成功，语义层拒绝。 */
        status = STATUS_SUCCESS;
    } else if (mutating &&
        InterlockedCompareExchange(
            &runtime->ResidentProcessorCount,
            0L,
            0L) != 0L) {
        /*
         * 常驻期间退出路径不持这把 PASSIVE_LEVEL 锁就读这张表与它的层次，
         * 所以两者都必须在所有 VCPU 回到客户栈之后才允许变。这与 EPT 规则、
         * 分离视图是同一条规矩，理由也一样——不是保守，是这些表的读者根本
         * 没有办法等锁。
         */
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version = KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        Response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_REQUIRES_RESIDENT_STOPPED;
        Response->lastStatus = STATUS_DEVICE_BUSY;
        /* 没有任何一条记录或层次被改动。 */
        status = STATUS_SUCCESS;
    } else {
        status = KswordARKHvmProcessControlLocked(
            runtime,
            Request,
            Response);
    }
    ExReleasePushLockExclusive(&runtime->Lock);
    KeLeaveCriticalRegion();
    /* 返回完整的操作结果。 */
    return status;
}

BOOLEAN
KswordARKHvmProcessSelectHierarchy(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestCr3,
    _Out_ ULONGLONG* TargetEptp
    )
{
    ULONGLONG frame = GuestCr3 & KSW_HVM_PROCESS_CR3_FRAME_MASK;
    ULONG index = 0UL;

    /* 拒绝不完整的调用契约，退出路径上不接受半个结果。 */
    if (Runtime == NULL || TargetEptp == NULL) {
        /* 返回未命中。 */
        return FALSE;
    }
    *TargetEptp = 0ULL;
    /* 表空时直接返回，省掉常驻期间每次地址空间切换的一次扫描。 */
    if (Runtime->ProcessDispositionCount == 0UL) {
        /* 返回未命中。 */
        return FALSE;
    }
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        const KSW_HVM_PROCESS_SLOT* slot =
            &Runtime->ProcessDispositions[index];

        if (!slot->InUse ||
            slot->Disposition ==
                KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED ||
            slot->DirectoryBase != frame ||
            slot->HierarchyIndex == 0UL ||
            slot->HierarchyIndex >
                (KSWORD_ARK_HVM_MAX_VIEWS + 1UL)) {
            /* 跳过空槽、不命中的地址空间与越界的层次序号。 */
            continue;
        }
        /* 层次没建起来就当未命中：切到 0 等于切到一套不存在的层次。 */
        if (Runtime->EptSwitch.Eptp[slot->HierarchyIndex] == 0ULL) {
            /* 跳过未构造的层次。 */
            continue;
        }
        *TargetEptp =
            Runtime->EptSwitch.Eptp[slot->HierarchyIndex];
        /* 返回命中的受限层次。 */
        return TRUE;
    }
    /* 返回未命中。 */
    return FALSE;
}

KSW_HVM_PROCESS_ACTION
KswordARKHvmProcessHandleViolation(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access
    )
{
    ULONGLONG page = GuestPhysicalAddress & KSW_HVM_PROCESS_PAGE_MASK;
    ULONG index = 0UL;

    /* 拒绝不完整的调用契约。 */
    if (Runtime == NULL) {
        /* 返回不归本模块管。 */
        return KswHvmProcessActionNone;
    }
    /*
     * 只认取指违规。
     *
     * 受限层次只去掉了执行位，所以读写在这套层次下与基座完全一样，不会产生
     * 违规；真出现了读写违规，那是别的机制（规则、视图）的事，认领过来只会
     * 把它们的处理吃掉。
     */
    if ((Access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL) {
        /* 返回不归本模块管。 */
        return KswHvmProcessActionNone;
    }
    if (Runtime->ProcessDispositionCount == 0UL) {
        /* 返回不归本模块管。 */
        return KswHvmProcessActionNone;
    }
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        KSW_HVM_PROCESS_SLOT* slot =
            &Runtime->ProcessDispositions[index];

        if (!slot->InUse ||
            slot->GuestPhysicalAddress != page) {
            /* 跳过空槽与不是这一页的记录。 */
            continue;
        }
        /*
         * 已解除的记录不再拦截：把这个核换回基座、原地继续。
         *
         * 这一条必须排在计数之前。解除之后还继续累加拦截数，会让"解除了吗"这个
         * 问题的唯一外部读数一直在涨，看起来和没解除一模一样。
         */
        if (slot->Disposition ==
                KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED) {
            /* 返回恢复动作。 */
            return KswHvmProcessActionResume;
        }
        /* 记一次拦截。冻结下这个数会一直涨，那正是自旋的证据。 */
        InterlockedIncrement64(&slot->InterceptCount);
        if (slot->Disposition ==
                KSWORD_ARK_HVM_PROCESS_OP_TERMINATE) {
            /* 返回结束动作。 */
            return KswHvmProcessActionTerminate;
        }
        /* 返回冻结动作。 */
        return KswHvmProcessActionFreeze;
    }
    /* 返回不归本模块管。 */
    return KswHvmProcessActionNone;
}

VOID
KswordARKHvmProcessResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;

    /* 容忍空运行时，让每一条失败路径与拆卸路径都不必额外加守卫。 */
    if (Runtime == NULL) {
        /* 无事可做。 */
        return;
    }
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        KSW_HVM_PROCESS_SLOT* slot =
            &Runtime->ProcessDispositions[index];

        if (slot->InUse) {
            KswordARKHvmProcessReleaseSlotLocked(Runtime, slot);
        }
    }
    /* 计数归零，逐条释放已经减到零，这一行只是让它确定。 */
    Runtime->ProcessDispositionCount = 0UL;
}

#endif /* _M_AMD64 */
