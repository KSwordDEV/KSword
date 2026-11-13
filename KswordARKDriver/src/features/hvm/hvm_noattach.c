#include "hvm_noattach.h"
#include "hvm_runtime.h"

/* 固定非分页会话在所有 VM-exit 读者停止前保持原地址。 */
KSW_HVM_NOATTACH g_KswordNoAttach;
/* 会话标识不随关闭归零，防止旧请求命中新会话。 */
static volatile LONG64 g_NoAttachGeneration;
/* 仅在 PASSIVE_LEVEL 解析导出，VMX root 不调用该例程。 */
typedef PVOID(NTAPI *KSW_NA_GET_TEB)(PETHREAD Thread);
/* 线程退出通知先撤销 publication，不能靠 ETHREAD 引用延长 TEB 生命周期。 */
static KSW_NA_GET_TEB g_NoAttachGetTeb;
/* x64 首版明确拒绝 WOW64，不能把 x86 上下文标成 x64。 */
typedef PVOID(NTAPI *KSW_NA_GET_WOW64)(PEPROCESS Process);
/* 只在普通内核绑定目标时调用该公开导出。 */
static KSW_NA_GET_WOW64 g_NoAttachGetWow64;
/* 进程创建时间由引用对象读取，不接受调用者自行声明身份。 */
NTSYSAPI LONGLONG NTAPI PsGetProcessCreateTimeQuadPart(PEPROCESS Process);
/* 所有身份检查都在普通内核控制路径完成。 */
NTSYSAPI NTSTATUS NTAPI PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD *Thread);
/* 进程查询同样只在 PASSIVE_LEVEL 固定身份时使用。 */
NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
/* 比较真实所属进程对象，避免复用的 PID/TID。 */
NTKERNELAPI PEPROCESS PsGetThreadProcess(PETHREAD Thread);
/* 打开后再次检查退出状态，关闭通知安装到引用建立之间的竞态。 */
NTKERNELAPI BOOLEAN PsIsThreadTerminating(PETHREAD Thread);

/* 仅在全部处理器离开 VMX 后释放引用和文件对象。 */
static VOID NaReleaseIdentity(VOID)
{
    /* 只有完整全核退出后才归还全部断点 backing 锁。 */
    KswordARKHvmNoAttachReleasePins();
    /* 文件引用不阻止 Cleanup，但保留回调比较的对象身份。 */
    if (g_KswordNoAttach.File != WDF_NO_HANDLE)
    {
        WdfObjectDereference(g_KswordNoAttach.File);
    }
    /* 目标线程最后一次 VM-exit 读取已由全核停止屏障排空。 */
    if (g_KswordNoAttach.Thread != NULL)
    {
        ObDereferenceObject(g_KswordNoAttach.Thread);
    }
    /* 目标地址空间身份独立持有。 */
    if (g_KswordNoAttach.Process != NULL)
    {
        ObDereferenceObject(g_KswordNoAttach.Process);
    }
    /* 发起者身份同样不按 PID 重绑定。 */
    if (g_KswordNoAttach.Owner != NULL)
    {
        ObDereferenceObject(g_KswordNoAttach.Owner);
    }
    /* 退休后的空指针不能被下一次打开误用。 */
    g_KswordNoAttach.File = WDF_NO_HANDLE;
    /* 清除线程引用的唯一所有者字段。 */
    g_KswordNoAttach.Thread = NULL;
    /* 清除目标进程引用的唯一所有者字段。 */
    g_KswordNoAttach.Process = NULL;
    /* 清除发起进程引用的唯一所有者字段。 */
    g_KswordNoAttach.Owner = NULL;
    /* 清除只用于数值比对的 TEB。 */
    g_KswordNoAttach.Teb = 0ULL;
    /* 关闭以后不会再授权外部调用者修改旧会话。 */
    g_KswordNoAttach.OwnerCreationTime = 0ULL;
}

/* 调用方持普通控制锁；失败时保留所有恢复资源。 */
static NTSTATUS NaCloseLocked(VOID)
{
    /* 预约失败不赋予停止其它 HVM 使用者的权限。 */
    NTSTATUS status = STATUS_SUCCESS;
    /* 先撤销停止发布，让正在退出的处理器能恢复普通映射。 */
    InterlockedExchange(&g_KswordNoAttach.Enabled, 0L);
    /* 只有明确取得的资源才允许经过停止和拆卸。 */
    if (InterlockedCompareExchange(&g_KswordNoAttach.ResourcesOwned, 0L, 0L) != 0L)
    {
        /* 复用现有全核停止与映射保留规则。 */
        status = KswordARKHvmNoAttachLifecycle(FALSE, 0UL);
    }
    /* 不能用释放引用掩盖未完成的硬件退出。 */
    if (!NT_SUCCESS(status))
    {
        /* 旧 sessionId 保留，调用方可明确重试 Close。 */
        InterlockedExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED);
        /* 返回原始退出错误。 */
        return status;
    }
    /* 所有根表与 VM-exit 读者已经排空。 */
    NaReleaseIdentity();
    /* 清除本模块资源所有权，允许后续独立 HVM 工作。 */
    InterlockedExchange(&g_KswordNoAttach.ResourcesOwned, 0L);
    /* 先发布关闭状态，再解除外部 mutation 门禁。 */
    InterlockedExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_CLOSED);
    /* 最后解除生命周期预约。 */
    InterlockedExchange(&g_KswordNoAttach.Owned, 0L);
    /* 不存在残留处理器映射。 */
    return STATUS_SUCCESS;
}

/* 通知和文件 Cleanup 只排队，由普通系统工作线程执行全核停止。 */
static VOID NaCleanupWorker(WDFWORKITEM WorkItem)
{
    /* 工作项只处理全局固定会话，不跟随用户指针。 */
    UNREFERENCED_PARAMETER(WorkItem);
    /* 工作线程可以使用 PASSIVE_LEVEL 控制锁。 */
    KeEnterCriticalRegion();
    /* 与显式 Close/Open 串行，避免两方重复释放引用。 */
    ExAcquirePushLockExclusive(&g_KswordNoAttach.Lock);
    /* 只清理仍属于本模块的生命周期。 */
    if (KswordARKHvmNoAttachOwned())
    {
        (void)NaCloseLocked();
    }
    /* 先完成全部资源退休，再允许下一次排队。 */
    ExReleasePushLockExclusive(&g_KswordNoAttach.Lock);
    /* 恢复调用线程的普通 APC 语义。 */
    KeLeaveCriticalRegion();
    /* 这是工作项最后一次写状态，卸载另用 WdfWorkItemFlush 等回调完整返回。 */
    InterlockedExchange(&g_KswordNoAttach.WorkQueued, 0L);
}

BOOLEAN KswordARKHvmNoAttachOwned(VOID)
{
    /* 原子只读查询在 feature-off 路径不触及硬件。 */
    return InterlockedCompareExchange(&g_KswordNoAttach.Owned, 0L, 0L) != 0L;
}

VOID KswordARKHvmNoAttachResidentLeaving(VOID)
{
    /* 通用失败和正常退出都不能留下已经失去 VMM 的旧 STOPPED。 */
    LONG state;
    /* 未发布执行权的关闭路径已经有自己的退休所有者。 */
    if (!KswordARKHvmNoAttachOwned() || InterlockedExchange(&g_KswordNoAttach.Enabled, 0L) == 0L)
    {
        return;
    }
    /* 不把并发 Close/退出通知覆盖成另一次故障。 */
    state = InterlockedCompareExchange(&g_KswordNoAttach.State, 0L, 0L);
    /* 没有当前停止权以后，普通控制面只能 Query 或 Close 恢复。 */
    if (state != KSWORD_ARK_HVM_NOATTACH_EXITED && state != KSWORD_ARK_HVM_NOATTACH_CLOSED)
    {
        /* CAS 防止撤销后被旧状态写回。 */
        (void)InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED,
                                         state);
    }
}

VOID KswordARKHvmNoAttachRevoke(VOID)
{
    /* 未初始化或未预约的会话没有可以撤销的资源。 */
    if (!g_KswordNoAttach.Initialized || !KswordARKHvmNoAttachOwned())
    {
        return;
    }
    /* 停止发布必须先于目标 TEB 的退出释放。 */
    InterlockedExchange(&g_KswordNoAttach.Enabled, 0L);
    /* CAS 写者不能覆盖此退出状态并复活 STOPPED。 */
    InterlockedExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_EXITED);
    /* 卸载自己同步收尾，不再创建新的异步工作。 */
    if (g_KswordNoAttach.ShuttingDown)
    {
        return;
    }
    /* 固定工作项最多只能有一个排队或运行实例。 */
    if (InterlockedCompareExchange(&g_KswordNoAttach.WorkQueued, 1L, 0L) == 0L)
    {
        /* 系统工作线程负责可阻塞的全核停止。 */
        WdfWorkItemEnqueue(g_KswordNoAttach.Work);
    }
}

/* 线程退出回调在退出线程的 TEB 可以复用前撤销当前会话。 */
static VOID NaThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    /* 数值 ID 只选择已发布且未复用的固定记录。 */
    if (!Create && KswordARKHvmNoAttachOwned() &&
        g_KswordNoAttach.Snapshot.processId == HandleToULong(ProcessId) &&
        g_KswordNoAttach.Snapshot.threadId == HandleToULong(ThreadId))
    {
        /* 引用保留到处理器读者退出，而停止权立即撤销。 */
        KswordARKHvmNoAttachRevoke();
    }
}

/* 进程通知使用对象指针比较，不接受复用的 PID。 */
static VOID NaProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    /* 对象指针已是判据，不需要再解引用进程 ID。 */
    UNREFERENCED_PARAMETER(ProcessId);
    /* 创建通知不会结束旧会话。 */
    if (CreateInfo == NULL && KswordARKHvmNoAttachOwned() &&
        (Process == g_KswordNoAttach.Owner || Process == g_KswordNoAttach.Process))
    {
        /* 不在通知回调中等待其它处理器退出。 */
        KswordARKHvmNoAttachRevoke();
    }
}

NTSTATUS KswordARKHvmNoAttachInitialize(VOID)
{
    /* 所有注册均在驱动普通初始化路径完成。 */
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"PsGetThreadTeb");
    /* 独立取得 WOW64 判据，不猜 EPROCESS 私有字段。 */
    UNICODE_STRING wow64Name = RTL_CONSTANT_STRING(L"PsGetProcessWow64Process");
    /* 保留每一步注册的精确错误。 */
    NTSTATUS status;
    /* 驱动初始化尚无 VM-exit 读者。 */
    RtlZeroMemory(&g_KswordNoAttach, sizeof(g_KswordNoAttach));
    /* 控制面锁从不在 VMX root 获取。 */
    ExInitializePushLock(&g_KswordNoAttach.Lock);
    /* 没有任何处理器持有尚未开始的单步。 */
    g_KswordNoAttach.StepProcessor = -1L;
    /* 只在普通控制路径解析用户 TEB。 */
    g_NoAttachGetTeb = (KSW_NA_GET_TEB)MmGetSystemRoutineAddress(&name);
    /* WOW64 检测缺失也必须明确不支持。 */
    g_NoAttachGetWow64 = (KSW_NA_GET_WOW64)MmGetSystemRoutineAddress(&wow64Name);
    /* 无法建立线程附加判据时不公布功能。 */
    if (g_NoAttachGetTeb == NULL || g_NoAttachGetWow64 == NULL)
    {
        return STATUS_NOT_SUPPORTED;
    }
    /* 先注册目标线程撤销，再允许发布会话。 */
    status = PsSetCreateThreadNotifyRoutine(NaThreadNotify);
    /* 第一项失败时没有任何注册需要回滚。 */
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* owner 和目标进程退出都必须触发撤销。 */
    status = PsSetCreateProcessNotifyRoutineEx(NaProcessNotify, FALSE);
    /* 不留下一半初始化的回调集合。 */
    if (!NT_SUCCESS(status))
    {
        (void)PsRemoveCreateThreadNotifyRoutine(NaThreadNotify);
        return status;
    }
    /* 完整生命周期保护建立后才公开功能。 */
    g_KswordNoAttach.Initialized = TRUE;
    /* 初始化不会准备或启动 hypervisor。 */
    return STATUS_SUCCESS;
}

VOID KswordARKHvmNoAttachFileCleanup(WDFFILEOBJECT File)
{
    /* 记住关句柄状态，防止 Cleanup 早于 OPEN 最后发布。 */
    InterlockedExchange(&KswordARKHvmNoAttachFileContext(File)->Closing, 1L);
    /* 仅撤销由这个确切控制文件持有的会话。 */
    if (KswordARKHvmNoAttachOwned() && g_KswordNoAttach.File == File)
    {
        KswordARKHvmNoAttachRevoke();
    }
}

VOID KswordARKHvmNoAttachShutdown(VOID)
{
    /* 部分初始化失败已经自行撤销先前注册。 */
    if (!g_KswordNoAttach.Initialized)
    {
        return;
    }
    /* 禁止新的异步退休任务。 */
    g_KswordNoAttach.ShuttingDown = TRUE;
    /* 等待在途进程回调排空。 */
    (void)PsSetCreateProcessNotifyRoutineEx(NaProcessNotify, TRUE);
    /* 等待在途线程回调排空。 */
    (void)PsRemoveCreateThreadNotifyRoutine(NaThreadNotify);
    /* 停止新停止事件发布。 */
    KswordARKHvmNoAttachRevoke();
    /* KMDF 保证回调完整返回，不能用工作线程末尾的事件模拟这个屏障。 */
    if (g_KswordNoAttach.Work != WDF_NO_HANDLE)
    {
        WdfWorkItemFlush(g_KswordNoAttach.Work);
    }
    /* 串行处理剩余资源；失败时保留 refs 供现有卸载互锁拒绝卸载。 */
    KeEnterCriticalRegion();
    /* 保护最后一次 Close 与并发控制请求。 */
    ExAcquirePushLockExclusive(&g_KswordNoAttach.Lock);
    /* 重复收尾是幂等操作。 */
    if (KswordARKHvmNoAttachOwned())
    {
        (void)NaCloseLocked();
    }
    /* 只有完整退休才撤销初始化标志。 */
    if (!KswordARKHvmNoAttachOwned())
    {
        /* 回调已排空，此时才能删除工作项对象。 */
        if (g_KswordNoAttach.Work != WDF_NO_HANDLE)
        {
            WdfObjectDelete(g_KswordNoAttach.Work);
            g_KswordNoAttach.Work = WDF_NO_HANDLE;
        }
        /* 没有任何保留会话或回调。 */
        g_KswordNoAttach.Initialized = FALSE;
    }
    /* 释放普通内核控制锁。 */
    ExReleasePushLockExclusive(&g_KswordNoAttach.Lock);
    /* 恢复正常 APC 策略。 */
    KeLeaveCriticalRegion();
}

/* 查询只读取能力寄存器，既不分配页也不进入 VMX。 */
static ULONG NaCapabilities(VOID)
{
    /* 使用已经初始化的通用硬件发现结果。 */
    KSW_HVM_RUNTIME *runtime = KswordARKHvmGetRuntime();
    /* 能力要求包含真实常驻生命周期，而不只是 CPU 有 MBEC。 */
    const ULONGLONG required =
        KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG | KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
        KSWORD_ARK_HVM_FEATURE_EPT | KSWORD_ARK_HVM_FEATURE_EPT_WB | KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
        KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM | KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS |
        KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED;
    /* AMD、未就绪和缺生命周期通知均明确不支持。 */
    if (!g_KswordNoAttach.Initialized || runtime == NULL || !runtime->Initialized ||
        runtime->BackendId != KSWORD_ARK_HVM_BACKEND_VMX ||
        runtime->QueryStatus != KSWORD_ARK_HVM_QUERY_STATUS_OK || !runtime->ResidentStartAllowed)
    {
        return 0UL;
    }
    /* MTF 和 INVEPT 都是这份协议的硬前提。 */
    if ((runtime->FeatureFlags & required) != required)
    {
        return 0UL;
    }
    /* Allowed-1 位确认 MBEC 控制能真正写入，而非只猜 CPU 型号。 */
    if (((__readmsr(KSW_IA32_VMX_PROCBASED_CTLS2) >> 32) & KSW_NOATTACH_MBEC_CONTROL) == 0ULL)
    {
        return 0UL;
    }
    /* 范围只有单一用户线程及 GPR，不宣称全进程或 XSTATE。 */
    return KSWORD_ARK_HVM_NOATTACH_CAP_SINGLE_USER_THREAD | KSWORD_ARK_HVM_NOATTACH_CAP_GPR |
           KSWORD_ARK_HVM_NOATTACH_CAP_EXECUTION | KSWORD_ARK_HVM_NOATTACH_CAP_BREAKPOINT |
           KSWORD_ARK_HVM_NOATTACH_CAP_SET_GPR;
}

/* 在固定次数内取得一份完整快照；不把撕裂读数当停止现场。 */
static BOOLEAN NaCopySnapshot(KSWORD_ARK_HVM_NOATTACH_RESPONSE *Response)
{
    /* 读方在 PASSIVE_LEVEL，但仍不无限等 root 发布。 */
    ULONG attempt;
    /* 每次试读都独立核对前后序号。 */
    for (attempt = 0UL; attempt < 3UL; ++attempt)
    {
        /* 奇数代表写者尚未完成。 */
        LONG before = InterlockedCompareExchange(&g_KswordNoAttach.SnapshotSequence, 0L, 0L);
        /* 在途发布不读取一半寄存器。 */
        if ((before & 1L) != 0L)
        {
            continue;
        }
        /* 序号保护全部协议字段。 */
        *Response = g_KswordNoAttach.Snapshot;
        /* 读完成后再检查写者是否改变了文档。 */
        KeMemoryBarrier();
        /* 相同偶数表示这次复制完整。 */
        /* 状态必须与复制的 stop 文档处于同一次序号核对内。 */
        Response->state = (ULONG)InterlockedCompareExchange(&g_KswordNoAttach.State, 0L, 0L);
        /* 撤销与状态更新之间的窄窗口也不能发布旧的 STOPPED。 */
        if (Response->state == KSWORD_ARK_HVM_NOATTACH_STOPPED &&
            InterlockedCompareExchange(&g_KswordNoAttach.Enabled, 0L, 0L) == 0L)
        {
            Response->state = KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED;
        }
        /* 相同偶数同时证明文档和所配停止状态一致。 */
        if (before == InterlockedCompareExchange(&g_KswordNoAttach.SnapshotSequence, 0L, 0L))
        {
            return TRUE;
        }
    }
    /* 稍后重试比制造当前停止更安全。 */
    return FALSE;
}

/* 在任何资源准备前完成 owner、目标进程和线程的强身份绑定。 */
static NTSTATUS NaBind(const KSWORD_ARK_HVM_NOATTACH_REQUEST *Request, PEPROCESS Owner, WDFFILEOBJECT File)
{
    /* 保留对象查询和退出状态的原始错误。 */
    NTSTATUS status;
    /* 确认目标是真正的其它用户进程。 */
    if (Request->processId <= 4UL || Request->processId == HandleToULong(PsGetProcessId(Owner)) ||
        Request->processCreationTime == 0ULL || Request->threadCreationTime == 0ULL ||
        Request->threadId == 0UL)
    {
        return STATUS_INVALID_CID;
    }
    /* 先固定进程对象，不从 PID 反复查询名称冒充身份。 */
    status = PsLookupProcessByProcessId(ULongToHandle(Request->processId), &g_KswordNoAttach.Process);
    /* 查询失败没有目标线程需要释放。 */
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* 对固定对象核对创建时间与存活状态。 */
    if ((ULONGLONG)PsGetProcessCreateTimeQuadPart(g_KswordNoAttach.Process) != Request->processCreationTime ||
        PsGetProcessExitStatus(g_KswordNoAttach.Process) != STATUS_PENDING)
    {
        return STATUS_INVALID_CID;
    }
    /* 首版只支持 native x64 目标，不接受 WOW64 用户代码。 */
    if (g_NoAttachGetWow64(g_KswordNoAttach.Process) != NULL)
    {
        return STATUS_NOT_SUPPORTED;
    }
    /* 线程对象引用一直保留到全核读者退出。 */
    status = PsLookupThreadByThreadId(ULongToHandle(Request->threadId), &g_KswordNoAttach.Thread);
    /* 调用方统一释放先前建立的进程引用。 */
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* 地址空间归属、线程创建时间和退出状态必须全部一致。 */
    if (PsGetThreadProcess(g_KswordNoAttach.Thread) != g_KswordNoAttach.Process ||
        (ULONGLONG)PsGetThreadCreateTime(g_KswordNoAttach.Thread) != Request->threadCreationTime ||
        PsIsThreadTerminating(g_KswordNoAttach.Thread))
    {
        return STATUS_INVALID_CID;
    }
    /* TEB 仅作体系结构 cross-check，绝不是线程身份本身。 */
    g_KswordNoAttach.Teb = (ULONGLONG)(ULONG_PTR)g_NoAttachGetTeb(g_KswordNoAttach.Thread);
    /* 系统线程没有可控制的用户执行入口。 */
    if (g_KswordNoAttach.Teb == 0ULL)
    {
        return STATUS_NOT_SUPPORTED;
    }
    /* owner 与文件引用独立计数，调用方本地引用可正常释放。 */
    ObReferenceObject(Owner);
    /* 将真实发起对象保存到不可变绑定。 */
    g_KswordNoAttach.Owner = Owner;
    /* 保存明确核对的 owner 创建时间。 */
    g_KswordNoAttach.OwnerCreationTime = Request->ownerCreationTime;
    /* KMDF Cleanup 仍会在最后句柄关闭时触发。 */
    WdfObjectReference(File);
    /* 比较对象身份，拒绝同进程其它句柄抢用正在停止的目标。 */
    g_KswordNoAttach.File = File;
    /* 所有引用已经完整建立。 */
    return STATUS_SUCCESS;
}

NTSTATUS KswordARKHvmNoAttachControl(const KSWORD_ARK_HVM_NOATTACH_REQUEST *Request,
                                     KSWORD_ARK_HVM_NOATTACH_RESPONSE *Response, ULONG OwnerPid,
                                     WDFFILEOBJECT File)
{
    /* 保留真实发起者的本地查询引用。 */
    PEPROCESS owner = NULL;
    /* 通信成功与每个操作的 NTSTATUS 分开返回。 */
    NTSTATUS status = STATUS_SUCCESS;
    /* 状态变更只在同一控制锁内决定。 */
    LONG state;
    /* 先建立可识别的空协议响应。 */
    RtlZeroMemory(Response, sizeof(*Response));
    /* 固定协议版本由新 IOCTL 独立协商。 */
    Response->version = KSWORD_ARK_HVM_NOATTACH_VERSION;
    /* 总是公开实际返回结构大小。 */
    Response->size = sizeof(*Response);
    /* 只读能力查询绝不进入 VMX。 */
    Response->capabilities = NaCapabilities();
    /* 拒绝未定义操作、未知标志、内核发起者和已关闭文件。 */
    if (Request->version != KSWORD_ARK_HVM_NOATTACH_VERSION || Request->size != sizeof(*Request) ||
        Request->operation > KSWORD_ARK_HVM_NOATTACH_SET_GPR ||
        (Request->flags & ~(KSWORD_ARK_HVM_NOATTACH_CONFIRMED | KSWORD_ARK_HVM_NOATTACH_ALLOW_NESTED)) !=
            0UL ||
        OwnerPid <= 4UL || File == WDF_NO_HANDLE || Request->ownerCreationTime == 0ULL)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Complete;
    }
    /* 由 WDF 的真实 requestor PID 解析本次发起进程。 */
    status = PsLookupProcessByProcessId(ULongToHandle(OwnerPid), &owner);
    /* 无法确定调用者时不泄露另一会话的标识。 */
    if (!NT_SUCCESS(status))
    {
        goto Complete;
    }
    /* 核对 owner 创建时间，关闭 PID 复用窗口。 */
    if ((ULONGLONG)PsGetProcessCreateTimeQuadPart(owner) != Request->ownerCreationTime ||
        PsGetProcessExitStatus(owner) != STATUS_PENDING)
    {
        status = STATUS_INVALID_CID;
        goto Complete;
    }
    /* 控制锁从不出现在 VMX root。 */
    KeEnterCriticalRegion();
    /* 串行化 OPEN、命令消费和显式/异步关闭。 */
    ExAcquirePushLockExclusive(&g_KswordNoAttach.Lock);
    /* Cleanup 可能在请求排队以后才发生。 */
    if (g_KswordNoAttach.ShuttingDown || KswordARKHvmNoAttachFileContext(File)->Closing != 0L)
    {
        status = STATUS_DELETE_PENDING;
        goto Unlock;
    }
    /* 新会话只有显式 OPEN 才能取得资源。 */
    if (Request->operation == KSWORD_ARK_HVM_NOATTACH_OPEN)
    {
        /* 既有会话不会被后来的页面替换或接管。 */
        if (KswordARKHvmNoAttachOwned() ||
            InterlockedCompareExchange(&g_KswordNoAttach.WorkQueued, 0L, 0L) != 0L)
        {
            status = STATUS_DEVICE_BUSY;
            goto Unlock;
        }
        /* 只有硬件和回调都已就绪才尝试分配资源。 */
        if ((Response->capabilities & KSWORD_ARK_HVM_NOATTACH_CAP_EXECUTION) == 0UL)
        {
            status = STATUS_NOT_SUPPORTED;
            goto Unlock;
        }
        /* 开启 hypervisor 必须有明确确认，QUERY 或模式切换不能代替。 */
        if ((Request->flags & KSWORD_ARK_HVM_NOATTACH_CONFIRMED) == 0UL || Request->sessionId != 0ULL ||
            Request->stopId != 0ULL)
        {
            status = STATUS_ACCESS_DENIED;
            goto Unlock;
        }
        /* 工作项隶属真实控制设备，其 Flush 契约覆盖驱动卸载。 */
        if (g_KswordNoAttach.Work == WDF_NO_HANDLE)
        {
            /* 本地对象仅存在于可以分配的 PASSIVE_LEVEL OPEN 路径。 */
            WDF_OBJECT_ATTRIBUTES attributes;
            /* 由 KMDF 调度普通内核清理回调。 */
            WDF_WORKITEM_CONFIG configuration;
            /* 工作项父对象保持设备生命周期。 */
            WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
            /* 当前请求的设备就是拥有控制文件的设备。 */
            attributes.ParentObject = WdfFileObjectGetDevice(File);
            /* 本模块自行串行，不引入 KMDF 自动互锁死锁。 */
            WDF_WORKITEM_CONFIG_INIT(&configuration, NaCleanupWorker);
            /* 通知回调只排队，清理回调才获取本模块锁。 */
            configuration.AutomaticSerialization = FALSE;
            /* 创建失败尚未取得任何硬件资源。 */
            status = WdfWorkItemCreate(&configuration, &attributes, &g_KswordNoAttach.Work);
            /* 保留准确的框架分配错误。 */
            if (!NT_SUCCESS(status))
            {
                goto Unlock;
            }
        }
        /* 通知使用新请求身份，先写不可变标识再发布 reservation。 */
        RtlZeroMemory(&g_KswordNoAttach.Snapshot, sizeof(g_KswordNoAttach.Snapshot));
        /* 把强身份写入唯一会话文档。 */
        g_KswordNoAttach.Snapshot = *Response;
        /* 新会话不复用之前的断点 ID 或待提交寄存器命令。 */
        g_KswordNoAttach.NextBreakpointId = 0UL;
        /* 未提交的编辑不能流入新会话。 */
        g_KswordNoAttach.PendingRegisterMask = 0ULL;
        /* 在准备资源之前就分配可恢复的 sessionId。 */
        g_KswordNoAttach.Snapshot.sessionId = (ULONGLONG)InterlockedIncrement64(&g_NoAttachGeneration);
        /* 保存本会话的进程 ID。 */
        g_KswordNoAttach.Snapshot.processId = Request->processId;
        /* 保存本会话的线程 ID。 */
        g_KswordNoAttach.Snapshot.threadId = Request->threadId;
        /* 保存核对前的请求创建时间，NaBind 将逐项证明它们。 */
        g_KswordNoAttach.Snapshot.processCreationTime = Request->processCreationTime;
        /* 线程创建时间独立于进程创建时间。 */
        g_KswordNoAttach.Snapshot.threadCreationTime = Request->threadCreationTime;
        /* 先绑定并核对所有引用，不在根路径读用户身份字段。 */
        status = NaBind(Request, owner, File);
        /* 部分绑定失败只释放本次取得的对象。 */
        if (!NT_SUCCESS(status))
        {
            NaReleaseIdentity();
            goto Unlock;
        }
        /* 初始 OPEN 只建立后端，暂停由独立 PAUSE 请求决定。 */
        InterlockedExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_RUNNING);
        /* 在预约发布之前设置初始停止权，通知不会被后来的置一复活。 */
        InterlockedExchange(&g_KswordNoAttach.Enabled, 1L);
        /* 最后公开可撤销预约；此后 OPEN 不会再次置 Enabled 为一。 */
        InterlockedExchange(&g_KswordNoAttach.Owned, 1L);
        /* 补查建立 publication 之前发生的关闭或退出。 */
        if (KswordARKHvmNoAttachFileContext(File)->Closing != 0L ||
            PsIsThreadTerminating(g_KswordNoAttach.Thread) ||
            PsGetProcessExitStatus(g_KswordNoAttach.Process) != STATUS_PENDING ||
            PsGetProcessExitStatus(owner) != STATUS_PENDING)
        {
            /* 没有硬件资源时普通关闭即可安全退休。 */
            status = STATUS_PROCESS_IS_TERMINATING;
        }
        else
        {
            /* 独占准备接口原子拒绝外部已经准备或常驻的状态。 */
            status = KswordARKHvmNoAttachLifecycle(TRUE, Request->flags);
        }
        /* 通知可能在全核插入期间撤销会话，不能在返回时复活它。 */
        if (NT_SUCCESS(status) && InterlockedCompareExchange(&g_KswordNoAttach.Enabled, 0L, 0L) == 0L)
        {
            status = STATUS_CANCELLED;
        }
        /* 启动失败只能清理明确取得的资源，绝不停止外部 HVM。 */
        if (!NT_SUCCESS(status))
        {
            (void)NaCloseLocked();
        }
    }
    else if (KswordARKHvmNoAttachOwned())
    {
        /* QUERY 也必须先证明 owner，不能借只读请求接管另一页面。 */
        if (owner != g_KswordNoAttach.Owner ||
            Request->ownerCreationTime != g_KswordNoAttach.OwnerCreationTime || File != g_KswordNoAttach.File)
        {
            status = STATUS_ACCESS_DENIED;
            goto Unlock;
        }
        /* OPEN 的 ACK 丢失时，同 owner/目标可用 sessionId=0 QUERY 找回本会话。 */
        if ((Request->operation != KSWORD_ARK_HVM_NOATTACH_QUERY || Request->sessionId != 0ULL) &&
            Request->sessionId != g_KswordNoAttach.Snapshot.sessionId)
        {
            status = STATUS_REVISION_MISMATCH;
            goto Unlock;
        }
        /* 目标身份不符的查询或动作都不返回可采用的 sessionId。 */
        if ((Request->processId != 0UL && Request->processId != g_KswordNoAttach.Snapshot.processId) ||
            (Request->threadId != 0UL && Request->threadId != g_KswordNoAttach.Snapshot.threadId) ||
            (Request->processCreationTime != 0ULL &&
             Request->processCreationTime != g_KswordNoAttach.Snapshot.processCreationTime) ||
            (Request->threadCreationTime != 0ULL &&
             Request->threadCreationTime != g_KswordNoAttach.Snapshot.threadCreationTime))
        {
            status = STATUS_INVALID_CID;
            goto Unlock;
        }
        /* 取得当前原子状态，旧 stopId 不能单独授权执行。 */
        state = InterlockedCompareExchange(&g_KswordNoAttach.State, 0L, 0L);
        /* 硬件已经退出或 owner 被撤销时只保留只读诊断与关闭恢复。 */
        if (InterlockedCompareExchange(&g_KswordNoAttach.Enabled, 0L, 0L) == 0L &&
            Request->operation != KSWORD_ARK_HVM_NOATTACH_QUERY &&
            Request->operation != KSWORD_ARK_HVM_NOATTACH_CLOSE)
        {
            status = STATUS_DEVICE_NOT_READY;
            goto Unlock;
        }
        /* 明确 Close 可重试此前失败的全核退出。 */
        if (Request->operation == KSWORD_ARK_HVM_NOATTACH_CLOSE)
        {
            /* 不让 root 发布竞争中的新停止。 */
            InterlockedExchange(&g_KswordNoAttach.Enabled, 0L);
            /* 与在途 stop writer 竞争时退出状态胜出。 */
            InterlockedExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_EXITED);
            /* 只有硬件确认清理后才释放 refs 与 reservation。 */
            status = NaCloseLocked();
        }
        else if (Request->operation >= KSWORD_ARK_HVM_NOATTACH_ADD_BREAKPOINT)
        {
            /* 断点配置、运行到地址和寄存器写入都核对真实当前停点。 */
            status = KswordARKHvmNoAttachEditStopped(Request);
        }
        else if (Request->operation == KSWORD_ARK_HVM_NOATTACH_PAUSE)
        {
            /* 已停止或已有请求时保持幂等，不重发 stopId。 */
            if (state == KSWORD_ARK_HVM_NOATTACH_RUNNING)
            {
                /* 下一个真实用户取指才会发布 STOPPED。 */
                (void)InterlockedCompareExchange(&g_KswordNoAttach.State,
                                                 KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING, state);
                /* 让所有 resident CPU 及时观察新模式，不等待自然 CR3 切换。 */
                status = KswordARKHvmNoAttachRendezvous(KswordARKHvmGetRuntime());
            }
            /* 只有已停止/已请求暂停才是幂等接受，执行中或恢复态须明确拒绝。 */
            else if (state != KSWORD_ARK_HVM_NOATTACH_STOPPED &&
                     state != KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING &&
                     state != KSWORD_ARK_HVM_NOATTACH_INTERRUPTED)
            {
                status = STATUS_INVALID_DEVICE_STATE;
            }
        }
        else if (Request->operation == KSWORD_ARK_HVM_NOATTACH_STEP ||
                 Request->operation == KSWORD_ARK_HVM_NOATTACH_CONTINUE)
        {
            /* 两种执行动作只接受当前完整停止身份。 */
            if (state != KSWORD_ARK_HVM_NOATTACH_STOPPED || Request->stopId == 0ULL)
            {
                status = STATUS_INVALID_DEVICE_STATE;
                goto Unlock;
            }
            /* 先占用停止状态，再验证 ID，阻止 STOPPED→新停止→STOPPED 的 ABA。 */
            if (InterlockedCompareExchange(&g_KswordNoAttach.State, KSW_NOATTACH_COMMAND_RESERVING,
                                           KSWORD_ARK_HVM_NOATTACH_STOPPED) !=
                KSWORD_ARK_HVM_NOATTACH_STOPPED)
            {
                status = STATUS_RETRY;
                goto Unlock;
            }
            /* 目标上下文刷新不能在此占用态改变 stopId。 */
            if (Request->stopId != g_KswordNoAttach.Snapshot.stopId)
            {
                /* 退出通知若已改变状态，不能恢复旧 STOPPED。 */
                (void)InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_STOPPED,
                                                 KSW_NOATTACH_COMMAND_RESERVING);
                /* 旧 stopId 永远不能授权新停止的动作。 */
                status = STATUS_REVISION_MISMATCH;
                /* 返回明确的代次错误。 */
                goto Unlock;
            }
            /* CAS 单次消费刚才独占并重新核对的停止。 */
            if (InterlockedCompareExchange(&g_KswordNoAttach.State,
                                           Request->operation == KSWORD_ARK_HVM_NOATTACH_STEP
                                               ? KSWORD_ARK_HVM_NOATTACH_STEP_PENDING
                                               : KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING,
                                           KSW_NOATTACH_COMMAND_RESERVING) != KSW_NOATTACH_COMMAND_RESERVING)
            {
                status = STATUS_CANCELLED;
                goto Unlock;
            }
            /* 继续也通过所有 CPU 的真实 VM-exit 解除旧门禁。 */
            status = KswordARKHvmNoAttachRendezvous(KswordARKHvmGetRuntime());
        }
        else if (Request->operation != KSWORD_ARK_HVM_NOATTACH_QUERY)
        {
            /* 未定义状态路径不会被默认为成功动作。 */
            status = STATUS_INVALID_PARAMETER;
        }
    }
    else if (Request->operation != KSWORD_ARK_HVM_NOATTACH_QUERY &&
             Request->operation != KSWORD_ARK_HVM_NOATTACH_CLOSE)
    {
        /* 未打开的会话不能接受执行动作。 */
        status = STATUS_INVALID_DEVICE_STATE;
    }
    /* 同 owner 的 ACK 恢复和当前状态读取共用唯一快照源。 */
    if (KswordARKHvmNoAttachOwned() && owner == g_KswordNoAttach.Owner && File == g_KswordNoAttach.File)
    {
        /* 拒绝不能证明完整性的寄存器文档。 */
        if (!NaCopySnapshot(Response))
        {
            status = STATUS_RETRY;
        }
        /* 原子状态独立于快照历史；非 STOPPED 不宣称寄存器仍是当前停止。 */
        /* NaCopySnapshot 已在序号保护内取得匹配状态，不能在此另读新状态。 */
        /* 在途 writer 对外只表现为等待停止。 */
        if (Response->state >= KSW_NOATTACH_PUBLISHING)
        {
            Response->state = KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING;
        }
        /* 非当前停止不暴露可消费的旧停止序号。 */
        if (Response->state != KSWORD_ARK_HVM_NOATTACH_STOPPED)
        {
            Response->stopReason = 0UL;
            /* 非停止回执不携带可消费的历史 stopId 或伪装为当前的寄存器。 */
            Response->stopId = 0ULL;
            /* 规范上下文区域与 GPR 保存帧连续且固定。 */
            RtlZeroMemory(&Response->rip, FIELD_OFFSET(KSWORD_ARK_HVM_NOATTACH_RESPONSE, breakpointId) -
                                         FIELD_OFFSET(KSWORD_ARK_HVM_NOATTACH_RESPONSE, rip));
            /* 历史命中不能成为当前命中身份。 */
            Response->breakpointId = 0UL;
        }
        /* 配置文档独立于停止现场，所有前端使用同一份真实能力与映射状态。 */
        KswordARKHvmNoAttachQueryBreakpoints(Response);
    }
Unlock:
    /* 同 owner 以外的失败不带其它会话的身份。 */
    ExReleasePushLockExclusive(&g_KswordNoAttach.Lock);
    /* 恢复普通 APC 策略。 */
    KeLeaveCriticalRegion();
Complete:
    /* 释放本请求临时引用，不影响会话持有的独立引用。 */
    if (owner != NULL)
    {
        ObDereferenceObject(owner);
    }
    /* 各种错误都通过固定响应明确传回语义结果。 */
    Response->status = status;
    /* 控制请求通信已完整处理，语义结果位于 status。 */
    return STATUS_SUCCESS;
}
