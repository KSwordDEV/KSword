#include "kernel_noattach.h"
#include "../../platform/pool_compat.h"

/* 单会话固定存储，不借用原生 Titan 或 Windows 调试对象。 */
KNA_SESSION g_Kna;
/* 两种后端共用一个原子预约，避免同时取得停止权。 */
static volatile LONG KnaExecutionOwner;
/* 回调注册一旦伴随永久转接器安装，保留到本次启动结束。 */
static BOOLEAN KnaThreadNotifyRegistered, KnaProcessNotifyRegistered;
/* 创建时间来自引用对象，不信任用户填入的 PID。 */
NTSYSAPI LONGLONG NTAPI PsGetProcessCreateTimeQuadPart(PEPROCESS Process);
/* 线程归属也按对象复核。 */
NTKERNELAPI PEPROCESS PsGetThreadProcess(PETHREAD Thread);

/* 不接管已经由其它 Windows 调试器拥有的进程。 */
static NTSTATUS KnaRequireNoDebugPort(PEPROCESS Process)
{
    /* Zw 入口使用内核句柄，不借用用户句柄或调试对象。 */
    typedef NTSTATUS(NTAPI *QUERY)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    /* 查询例程按名称发现。 */
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
    /* 缺失能力不推断为未被调试。 */
    QUERY query = (QUERY)MmGetSystemRoutineAddress(&name);
    /* 只取得查询所需的私有句柄。 */
    HANDLE handle = NULL;
    /* 此值不作为内核指针暴露给前端。 */
    ULONG_PTR port = 0U;
    /* 固定进程对象已经由绑定阶段引用。 */
    NTSTATUS status;
    /* 没有正式查询入口就拒绝未知状态。 */
    if (query == NULL) { return STATUS_NOT_SUPPORTED; }
    /* 不建立任何 Windows 调试关系。 */
    status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, 0x400UL, *PsProcessType, KernelMode, &handle);
    /* ProcessDebugPort=7 的宽度是 ULONG_PTR。 */
    if (NT_SUCCESS(status)) { status = query(handle, 7UL, &port, sizeof(port), NULL); ZwClose(handle); }
    /* 保留权限或查询失败。 */
    if (!NT_SUCCESS(status)) { return status; }
    /* 非空端口属于外部调试器，不借用其停止。 */
    return port == 0U ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
}

BOOLEAN KswordARKNoAttachTryReserve(LONG Backend)
{
    /* CAS 是两条后端唯一的资源预约入口。 */
    return InterlockedCompareExchange(&KnaExecutionOwner, Backend, 0L) == 0L;
}

VOID KswordARKNoAttachRelease(LONG Backend)
{
    /* 旧后端不能解除另一个新后端的预约。 */
    (void)InterlockedCompareExchange(&KnaExecutionOwner, 0L, Backend);
}

BOOLEAN KswordARKNoAttachReserved(VOID)
{
    /* 通用 HVM 修改入口只读这一个门闩。 */
    return InterlockedCompareExchange(&KnaExecutionOwner, 0L, 0L) != 0L;
}

/* 初始化无外部注册、无虚拟化和内核补丁。 */
static BOOLEAN KnaInitialize(VOID)
{
    /* 第一个普通控制请求初始化锁与事件。 */
    if (InterlockedCompareExchange(&g_Kna.Initialized, 1L, 0L) == 0L)
    {
        /* 控制锁从不被异常处理者持有。 */
        ExInitializePushLock(&g_Kna.ControlLock);
        /* 状态锁只保护短快照和命令提交。 */
        KeInitializeSpinLock(&g_Kna.StateLock);
        /* 命令信号不因快速响应丢失。 */
        KeInitializeEvent(&g_Kna.ContinueEvent, SynchronizationEvent, FALSE);
        /* 没有观察者时立即满足排空条件。 */
        KeInitializeEvent(&g_Kna.ObserverIdle, NotificationEvent, TRUE);
        /* 初始化写入先于 Ready。 */
        KeMemoryBarrier();
        /* 查询本身不注册回调或改变系统状态。 */
        InterlockedExchange(&g_Kna.Initialized, 2L);
    }
    /* 不在初始化竞争中忙等。 */
    return InterlockedCompareExchange(&g_Kna.Initialized, 0L, 0L) == 2L;
}

/* 只有目标状态已恢复、真实观察者排空后才能调用。 */
static VOID KnaReleaseIdentity(VOID)
{
    /* 禁止新的处理者取得即将释放的上下文。 */
    KIRQL irql;
    /* 引用退休与观察者进入同锁。 */
    KeAcquireSpinLock(&g_Kna.StateLock, &irql);
    /* 当前没有任何允许访问旧 Context 的入口。 */
    InterlockedExchange(&g_Kna.Owned, 0L);
    /* 对外状态先成为真正关闭。 */
    g_Kna.State = KSWORD_ARK_HVM_NOATTACH_CLOSED;
    /* 释放会阻塞或回调的对象之前解除短锁。 */
    KeReleaseSpinLock(&g_Kna.StateLock, irql);
    /* 非分页上下文只由本会话分配。 */
    if (g_Kna.Context != NULL) { ExFreePoolWithTag(g_Kna.Context, 'cNkK'); g_Kna.Context = NULL; }
    /* Capture 与异常现场是不同的缓冲区。 */
    if (g_Kna.Capture != NULL) { ExFreePoolWithTag(g_Kna.Capture, 'cNkK'); g_Kna.Capture = NULL; }
    /* 文件引用不代替用户句柄的 Cleanup。 */
    if (g_Kna.File != WDF_NO_HANDLE) { WdfObjectDereference(g_Kna.File); g_Kna.File = WDF_NO_HANDLE; }
    /* 对象释放只能发生在消费者不再使用它们之后。 */
    if (g_Kna.Thread != NULL) { ObDereferenceObject(g_Kna.Thread); g_Kna.Thread = NULL; }
    /* 目标进程与发起进程分别持有引用。 */
    if (g_Kna.Process != NULL) { ObDereferenceObject(g_Kna.Process); g_Kna.Process = NULL; }
    /* PID 重用不能转移旧所有权。 */
    if (g_Kna.Owner != NULL) { ObDereferenceObject(g_Kna.Owner); g_Kna.Owner = NULL; }
    /* 新会话不沿用旧调试基线。 */
    g_Kna.BaselineValid = FALSE;
    /* 最后释放跨后端预约。 */
    KswordARKNoAttachRelease(KNA_OWNER_KERNEL);
}

/* 调用者持普通控制锁。关闭失败保留所有恢复责任。 */
static NTSTATUS KnaCloseLocked(VOID)
{
    /* 有界等待不等于假定目标已完成。 */
    ULONGLONG deadline = KeQueryInterruptTime() + 30000000ULL;
    /* 初始状态需要实际恢复。 */
    NTSTATUS status = STATUS_PENDING;
    /* 用户关闭、所有者退出与租约到期走同一条路径。 */
    InterlockedExchange(&g_Kna.Closing, 1L);
    /* 已经停止的异常线程可立即恢复自己的状态。 */
    KeSetEvent(&g_Kna.ContinueEvent, IO_NO_INCREMENT, FALSE);
    /* 目标退出、TF 完成和原生恢复各有独立确认。 */
    do
    {
        /* 没有活动处理者时才使用普通上下文 API。 */
        if (InterlockedCompareExchange(&g_Kna.Observer, 0L, 0L) == 0L) { status = KnaRestoreThread(); }
        /* STATUS_PENDING 不是完成，不能用 NT_SUCCESS 混淆它。 */
        if (status == STATUS_SUCCESS && g_Kna.Observer == 0L && !g_Kna.OwnTf && !g_Kna.OwnSuspend) { break; }
        /* 原生失败保留引用，交给显式 Close 重试。 */
        if (!NT_SUCCESS(status)) { break; }
        /* 等待不是无限自旋。 */
        LARGE_INTEGER delay;
        /* 每次睡眠只为检查真实进展。 */
        delay.QuadPart = -500000LL;
        /* 控制锁不被目标处理者使用，因此不会互等。 */
        (void)KeDelayExecutionThread(KernelMode, FALSE, &delay);
    } while (KeQueryInterruptTime() < deadline);
    /* 没有硬件/线程确认就不能报告 CLOSED。 */
    if (status != STATUS_SUCCESS || g_Kna.Observer != 0L || g_Kna.OwnTf || g_Kna.OwnSuspend)
    {
        /* 只保留恢复动作，不暴露可消费的旧停止。 */
        g_Kna.State = KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED;
        /* 超时仍然是明确失败，避免正的 STATUS_TIMEOUT 被当作成功。 */
        return status == STATUS_PENDING || status == STATUS_SUCCESS ? STATUS_IO_TIMEOUT : status;
    }
    /* 撤销入口后，转接代码仍承接已退休的旧跳转。 */
    status = KnaDeactivateHook();
    /* 不能覆盖另一方改变的内核入口。 */
    if (!NT_SUCCESS(status)) { g_Kna.State = KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED; return status; }
    /* 全部目标状态已恢复，真实处理者也已排空。 */
    KnaReleaseIdentity();
    /* 启动期模块留驻在公开能力和确认中说明。 */
    return STATUS_SUCCESS;
}

/* 普通系统线程完成可能等待 APC 的收尾。 */
static VOID KnaCleanupWorker(WDFWORKITEM Work)
{
    /* 固定全局会话，不访问已销毁的前端。 */
    UNREFERENCED_PARAMETER(Work);
    /* 控制与清理共享同一把锁。 */
    KeEnterCriticalRegion();
    /* 目标处理者永不获取该锁。 */
    ExAcquirePushLockExclusive(&g_Kna.ControlLock);
    /* 已完成的重复通知保持幂等。 */
    if (g_Kna.Owned) { (void)KnaCloseLocked(); }
    /* 先释放控制锁，再决定是否交接新到达的进展通知。 */
    ExReleasePushLockExclusive(&g_Kna.ControlLock);
    /* 恢复普通 APC 语义。 */
    KeLeaveCriticalRegion();
    /* 2 表示等待期间又到达一次真实完成/退出通知。 */
    if (InterlockedExchange(&g_Kna.WorkQueued, 0L) == 2L && g_Kna.Owned) { KnaRevoke(); }
}

VOID KnaRevoke(VOID)
{
    /* 没有持有会话就不排入新工作。 */
    LONG queued;
    /* 初始化 Ready 之前没有有效事件或工作项。 */
    if (g_Kna.Initialized != 2L || !g_Kna.Owned) { return; }
    /* 关闭不会终止目标或建立 Debug Object。 */
    InterlockedExchange(&g_Kna.Closing, 1L);
    /* 普通异常等待者必须先能离开。 */
    KeSetEvent(&g_Kna.ContinueEvent, IO_NO_INCREMENT, FALSE);
    /* 最多保留一个在途工作项。 */
    queued = InterlockedCompareExchange(&g_Kna.WorkQueued, 1L, 0L);
    /* 新完成通知只触发一次额外收尾机会，不无限自动重试失败。 */
    if (queued == 1L) { (void)InterlockedCompareExchange(&g_Kna.WorkQueued, 2L, 1L); }
    /* OPEN 发布前已创建唯一工作项。 */
    if (queued == 0L) { WdfWorkItemEnqueue(g_Kna.CleanupWork); }
}

VOID KswordARKKernelNoAttachFileCleanup(WDFFILEOBJECT File)
{
    /* 只有确切控制文件关闭才撤销本会话。 */
    if (g_Kna.Owned && g_Kna.File == File) { KnaRevoke(); }
}

/* 线程退出时不再安排依赖其用户帧的动作。 */
static VOID KnaThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    /* 强对象身份优先于可能复用的数值 ID。 */
    UNREFERENCED_PARAMETER(ProcessId);
    /* 当前退出线程就是实际被引用的那个对象。 */
    UNREFERENCED_PARAMETER(ThreadId);
    /* 线程退出不可能再返回用户态执行残留 TF。 */
    if (!Create && g_Kna.Owned && g_Kna.Thread == PsGetCurrentThread())
    { g_Kna.OwnTf = FALSE; KnaRevoke(); }
}

/* 控制器退出也归还目标，不依赖用户态析构。 */
static VOID KnaProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    /* 指针身份已是权威判据。 */
    UNREFERENCED_PARAMETER(ProcessId);
    /* 不把新建或复用的 PID 当作旧会话退出。 */
    if (CreateInfo == NULL && g_Kna.Owned && (Process == g_Kna.Owner || Process == g_Kna.Process)) { KnaRevoke(); }
}

/* 绑定阶段仍未设置目标 TF/DR。 */
static NTSTATUS KnaBind(const KSWORD_ARK_KERNEL_NOATTACH_REQUEST *Request, PEPROCESS Owner, WDFFILEOBJECT File)
{
    /* 只使用目标架构判据，不读取 EPROCESS 私有偏移。 */
    typedef PVOID(NTAPI *WOW64)(PEPROCESS);
    /* 导出缺失必须拒绝未知架构。 */
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"PsGetProcessWow64Process");
    /* 真实进程对象查询。 */
    NTSTATUS status;
    /* 控制器自身和系统进程不是用户调试目标。 */
    if (Request->processId <= 4UL || Request->processId == HandleToULong(PsGetProcessId(Owner)) ||
        Request->threadId == 0UL || Request->processCreationTime == 0ULL || Request->threadCreationTime == 0ULL)
    { return STATUS_INVALID_CID; }
    /* 强引用只在普通控制路径建立。 */
    status = PsLookupProcessByProcessId(ULongToHandle(Request->processId), &g_Kna.Process);
    /* 部分引用由统一失败出口清理。 */
    if (!NT_SUCCESS(status)) { return status; }
    /* 使用对象创建时间防止 PID 重用。 */
    if ((ULONGLONG)PsGetProcessCreateTimeQuadPart(g_Kna.Process) != Request->processCreationTime ||
        PsGetProcessExitStatus(g_Kna.Process) != STATUS_PENDING) { return STATUS_INVALID_CID; }
    /* 无附加不能靠借用外部已经建立的调试端口完成。 */
    status = KnaRequireNoDebugPort(g_Kna.Process);
    /* 已有调试关系不被本后端抢占。 */
    if (!NT_SUCCESS(status)) { return status; }
    /* WOW64 x86 target 由 x64 KiDispatchException 分发器统一接管；32-bit 用户代码的
     * Eip/Eax 等出现在 x64 CONTEXT 低 32 位，执行断点与 GPR 读写在该语义下等效。 */
    WOW64 wow64 = (WOW64)MmGetSystemRoutineAddress(&name);
    /* 需要架构判据来至少区分 WOW64 和其它非 x86/x64 情况；缺失则按最保守拒绝。 */
    if (wow64 == NULL) { return STATUS_NOT_SUPPORTED; }
    /* 固定线程对象直到全部异常消费者排空。 */
    status = PsLookupThreadByThreadId(ULongToHandle(Request->threadId), &g_Kna.Thread);
    /* 无效 TID 不推断成功。 */
    if (!NT_SUCCESS(status)) { return status; }
    /* TID 的进程归属、创建时间和退出状态都必须匹配。 */
    if (PsGetThreadProcess(g_Kna.Thread) != g_Kna.Process ||
        (ULONGLONG)PsGetThreadCreateTime(g_Kna.Thread) != Request->threadCreationTime || PsIsThreadTerminating(g_Kna.Thread))
    { return STATUS_INVALID_CID; }
    /* 保留确切发起进程对象。 */
    ObReferenceObject(Owner);
    /* 文件和进程引用各自计数。 */
    g_Kna.Owner = Owner;
    /* 清理不阻止文件 Cleanup 通知。 */
    WdfObjectReference(File);
    /* 使用真实文件对象而非可复用句柄值。 */
    g_Kna.File = File;
    /* 对齐的非分页 CONTEXT 不占用有限内核栈。 */
    g_Kna.Context = (PCONTEXT)KswordARKAllocateNonPagedPool(sizeof(CONTEXT), 'cNkK');
    /* 原生 API 捕获与活动异常现场分离。 */
    g_Kna.Capture = (PCONTEXT)KswordARKAllocateNonPagedPool(sizeof(CONTEXT), 'cNkK');
    /* 任一缺失都不能进入执行控制。 */
    return g_Kna.Context != NULL && g_Kna.Capture != NULL ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS KswordARKKernelNoAttachControl(const KSWORD_ARK_KERNEL_NOATTACH_REQUEST *Request,
    KSWORD_ARK_KERNEL_NOATTACH_RESPONSE *Response, ULONG OwnerPid, WDFFILEOBJECT File)
{
    /* 请求者不是当前 WDF 工作线程的进程。 */
    PEPROCESS owner = NULL;
    /* 操作结果与 IOCTL 传输结果分开。 */
    NTSTATUS status = STATUS_SUCCESS;
    /* 状态文档由短锁保护。 */
    KIRQL irql;
    /* 返回一份明确的初始协议。 */
    RtlZeroMemory(Response, sizeof(*Response));
    /* 版本区分普通内核后端。 */
    Response->version = KSWORD_ARK_KERNEL_NOATTACH_VERSION;
    /* 固定长度来自唯一共享布局。 */
    Response->size = sizeof(*Response);
    /* QUERY 不注册通知、不安装补丁。 */
    Response->capabilities = KnaCapabilities();
    /* 未支持环境不伪装为可运行。 */
    Response->state = Response->capabilities != 0UL ? KSWORD_ARK_HVM_NOATTACH_CLOSED : KSWORD_ARK_HVM_NOATTACH_UNSUPPORTED;
    /* 请求边界验证在任何引用、注册或修改之前完成。 */
    if (!KnaInitialize() || Request->version != KSWORD_ARK_KERNEL_NOATTACH_VERSION || Request->size != sizeof(*Request) ||
        Request->operation > KSWORD_ARK_HVM_NOATTACH_SET_GPR ||
        (Request->flags & ~(KSWORD_ARK_HVM_NOATTACH_CONFIRMED | KSWORD_ARK_KERNEL_NOATTACH_HOOK_ACK)) != 0UL ||
        OwnerPid <= 4UL || File == WDF_NO_HANDLE || Request->ownerCreationTime == 0ULL)
    { Response->status = STATUS_INVALID_PARAMETER; return STATUS_SUCCESS; }
    /* 按真实 requestor PID 固定所有者。 */
    status = PsLookupProcessByProcessId(ULongToHandle(OwnerPid), &owner);
    /* 失败不泄露别人的会话。 */
    if (!NT_SUCCESS(status)) { goto Complete; }
    /* 发起者创建时间也是协议身份的一部分。 */
    if ((ULONGLONG)PsGetProcessCreateTimeQuadPart(owner) != Request->ownerCreationTime || PsGetProcessExitStatus(owner) != STATUS_PENDING)
    { status = STATUS_INVALID_CID; goto Complete; }
    /* 跨普通控制请求串行。 */
    KeEnterCriticalRegion();
    /* 回调只获取 StateLock，不获取此锁。 */
    ExAcquirePushLockExclusive(&g_Kna.ControlLock);
    /* 排队后文件关闭不能被 OPEN 重新激活。 */
    if (KswordARKHvmNoAttachFileContext(File)->Closing != 0L) { status = STATUS_DELETE_PENDING; goto Unlock; }
    /* 启动必须独立确认，不由下拉选择隐式触发。 */
    if (Request->operation == KSWORD_ARK_HVM_NOATTACH_OPEN)
    {
        /* 不能替换已拥有或正在异步收尾的会话。 */
        if (g_Kna.Owned || g_Kna.WorkQueued != 0L || Request->sessionId != 0ULL || Request->stopId != 0ULL)
        { status = STATUS_DEVICE_BUSY; goto Unlock; }
        /* 两种后端都必须满足自己的真实能力。 */
        if (Response->capabilities == 0UL) { status = STATUS_NOT_SUPPORTED; goto Unlock; }
        /* 明确承认内核热补丁和重启卸载约束。 */
        if ((Request->flags & (KSWORD_ARK_HVM_NOATTACH_CONFIRMED | KSWORD_ARK_KERNEL_NOATTACH_HOOK_ACK)) !=
            (KSWORD_ARK_HVM_NOATTACH_CONFIRMED | KSWORD_ARK_KERNEL_NOATTACH_HOOK_ACK))
        { status = STATUS_ACCESS_DENIED; goto Unlock; }
        /* 不能在其它 HVM 已准备/常驻时修改异常入口。 */
        KSW_HVM_RUNTIME *runtime = KswordARKHvmGetRuntime();
        /* 与 HVM 资源准备在同一锁下核对空闲。 */
        KeEnterCriticalRegion();
        /* 只读取通用生命周期，不执行 VMX。 */
        ExAcquirePushLockExclusive(&runtime->Lock);
        /* 预约使后续其它 HVM 修改全部拒绝。 */
        BOOLEAN reserved = !runtime->Busy && runtime->PreparedProcessorCount == 0UL && runtime->ResidentProcessorCount == 0L &&
                           KswordARKNoAttachTryReserve(KNA_OWNER_KERNEL);
        /* 确定预约以后才能解除运行时锁。 */
        ExReleasePushLockExclusive(&runtime->Lock);
        /* 对称归还临界区计数。 */
        KeLeaveCriticalRegion();
        /* 不停止或释放其它人的 HVM 资源。 */
        if (!reserved) { status = STATUS_DEVICE_BUSY; goto Unlock; }
        /* 新身份与基线不复用上一会话。 */
        RtlZeroMemory(&g_Kna.Snapshot, sizeof(g_Kna.Snapshot));
        /* 保存已经建立的协议与能力。 */
        g_Kna.Snapshot = *Response;
        /* 全宽会话身份仅递增。 */
        g_Kna.Snapshot.sessionId = ++g_Kna.Generation;
        /* 请求时冻结进程身份。 */
        g_Kna.Snapshot.processId = Request->processId; g_Kna.Snapshot.processCreationTime = Request->processCreationTime;
        /* 请求时冻结线程身份。 */
        g_Kna.Snapshot.threadId = Request->threadId; g_Kna.Snapshot.threadCreationTime = Request->threadCreationTime;
        /* 绑定强引用发生在任何内核代码修改之前。 */
        status = KnaBind(Request, owner, File);
        /* 取得已核对的原生线程函数。 */
        if (NT_SUCCESS(status)) { status = KnaResolveThreadApis(); }
        /* 工作项的父级是这个控制文件所属的真实设备。 */
        if (NT_SUCCESS(status) && g_Kna.CleanupWork == WDF_NO_HANDLE)
        {
            /* 普通内核清理，不使用控制器线程。 */
            WDF_WORKITEM_CONFIG config;
            /* KMDF 父对象保证工作项生命周期。 */
            WDF_OBJECT_ATTRIBUTES attributes;
            /* 工作项不引入第二套自动锁。 */
            WDF_WORKITEM_CONFIG_INIT(&config, KnaCleanupWorker); config.AutomaticSerialization = FALSE;
            /* 初始化独立属性。 */
            WDF_OBJECT_ATTRIBUTES_INIT(&attributes); attributes.ParentObject = WdfFileObjectGetDevice(File);
            /* 创建失败不安装入口。 */
            status = WdfWorkItemCreate(&config, &attributes, &g_Kna.CleanupWork);
        }
        /* 安装回调以后，目标退出才能及时撤销刚发布的会话。 */
        if (NT_SUCCESS(status) && !KnaThreadNotifyRegistered)
        { status = PsSetCreateThreadNotifyRoutine(KnaThreadNotify); if (NT_SUCCESS(status)) { KnaThreadNotifyRegistered = TRUE; } }
        /* 所有者退出同样可靠恢复。 */
        if (NT_SUCCESS(status) && !KnaProcessNotifyRegistered)
        { status = PsSetCreateProcessNotifyRoutineEx(KnaProcessNotify, FALSE); if (NT_SUCCESS(status)) { KnaProcessNotifyRegistered = TRUE; } }
        /* OPEN 是唯一安装异常入口的路径。 */
        if (NT_SUCCESS(status)) { status = KnaInstallHook(File); }
        /* 失败只释放本次目标引用，留驻转接器由模块生命周期保护。 */
        if (!NT_SUCCESS(status)) { KnaReleaseIdentity(); goto Unlock; }
        /* 所有字段完整以后才公开新的执行会话。 */
        KeAcquireSpinLock(&g_Kna.StateLock, &irql);
        /* 旧请求或租约不进入新会话。 */
        g_Kna.Action = 0UL; g_Kna.Closing = 0L; g_Kna.OwnTf = FALSE; g_Kna.OwnSuspend = FALSE;
        /* 每个新会话的停止代次独立。 */
        g_Kna.StopCounter = 0ULL; g_Kna.NextId = 0UL; g_Kna.BaselineValid = FALSE;
        /* 新会话的诊断不会沿用上一个目标的异常。 */
        g_Kna.TargetEvents = 0L; g_Kna.LastCode = 0UL; g_Kna.LastFrameDr6 = 0ULL; g_Kna.LastHardwareDr6 = 0ULL;
        /* 无断点状态不伪造安装。 */
        RtlZeroMemory(g_Kna.Rows, sizeof(g_Kna.Rows));
        /* 新会话不复用上一个会话的内存观察配置。 */
        RtlZeroMemory(g_Kna.MemoryWatches, sizeof(g_Kna.MemoryWatches));
        /* 保存文件所有者的准确时间。 */
        g_Kna.OwnerCreation = Request->ownerCreationTime;
        /* OPEN 不立即暂停目标。 */
        g_Kna.State = KSWORD_ARK_HVM_NOATTACH_RUNNING;
        /* 最后发布可撤销的完整会话。 */
        InterlockedExchange(&g_Kna.Owned, 1L);
        /* 生命周期回调此后可以直接撤销。 */
        KeReleaseSpinLock(&g_Kna.StateLock, irql);
        /* 关闭和退出若发生在注册/绑定之间，不能遗漏。 */
        if (KswordARKHvmNoAttachFileContext(File)->Closing != 0L || PsIsThreadTerminating(g_Kna.Thread) ||
            PsGetProcessExitStatus(owner) != STATUS_PENDING || PsGetProcessExitStatus(g_Kna.Process) != STATUS_PENDING)
        { (void)KnaCloseLocked(); status = STATUS_CANCELLED; }
    }
    else if (g_Kna.Owned)
    {
        /* QUERY 也不能接管另一控制文件的会话。 */
        if (owner != g_Kna.Owner || File != g_Kna.File || Request->ownerCreationTime != g_Kna.OwnerCreation)
        { status = STATUS_ACCESS_DENIED; goto Unlock; }
        /* 丢失 OPEN ACK 时允许同文件以零 sessionId 查询找回。 */
        if ((Request->operation != KSWORD_ARK_HVM_NOATTACH_QUERY || Request->sessionId != 0ULL) &&
            Request->sessionId != g_Kna.Snapshot.sessionId) { status = STATUS_REVISION_MISMATCH; goto Unlock; }
        /* 非零目标限制必须仍与本会话匹配。 */
        if ((Request->processId != 0UL && Request->processId != g_Kna.Snapshot.processId) ||
            (Request->threadId != 0UL && Request->threadId != g_Kna.Snapshot.threadId) ||
            (Request->processCreationTime != 0ULL && Request->processCreationTime != g_Kna.Snapshot.processCreationTime) ||
            (Request->threadCreationTime != 0ULL && Request->threadCreationTime != g_Kna.Snapshot.threadCreationTime))
        { status = STATUS_INVALID_CID; goto Unlock; }
        /* 关闭不需要已经过期的 stopId。 */
        if (Request->operation == KSWORD_ARK_HVM_NOATTACH_CLOSE) { status = KnaCloseLocked(); }
        /* 只读续期不执行任何目标指令。 */
        else if (Request->operation == KSWORD_ARK_HVM_NOATTACH_QUERY) { g_Kna.LeaseDeadline = KeQueryInterruptTime() + 300000000ULL; }
        /* 关闭中只保留查询和恢复，不复活执行。 */
        else if (g_Kna.Closing) { status = STATUS_DEVICE_NOT_READY; }
        /* 主动暂停由明确的独立请求触发。 */
        else if (Request->operation == KSWORD_ARK_HVM_NOATTACH_PAUSE) { status = KnaRequestPause(); }
        else
        {
            /* 在同一短锁内占用停点和检查代次，杜绝 ABA。 */
            KeAcquireSpinLock(&g_Kna.StateLock, &irql);
            /* 只有真实停止才能编辑或恢复。 */
            if (g_Kna.State != KSWORD_ARK_HVM_NOATTACH_STOPPED || Request->stopId == 0ULL)
            { status = STATUS_INVALID_DEVICE_STATE; }
            /* 旧 stopId 不授权另一次停止。 */
            else if (Request->stopId != g_Kna.Snapshot.stopId) { status = STATUS_REVISION_MISMATCH; }
            else
            {
                /* 配置验证失败不消费停点。 */
                if (Request->operation >= KSWORD_ARK_HVM_NOATTACH_ADD_BREAKPOINT && Request->operation <= KSWORD_ARK_HVM_NOATTACH_RUN_TO)
                { status = KnaEditBreakpoint(Request); }
                /* 整数修改不允许内核控制地址或未知组。 */
                else if (Request->operation == KSWORD_ARK_HVM_NOATTACH_SET_GPR &&
                    (Request->registerMask == 0ULL || (Request->registerMask & ~KSWORD_ARK_HVM_NOATTACH_GPR_MASK) != 0ULL ||
                     ((Request->registerMask & (1ULL << 15)) != 0ULL && (Request->registers.rip == 0ULL || Request->registers.rip > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress)) ||
                     ((Request->registerMask & (1ULL << 16)) != 0ULL && (Request->registers.rsp == 0ULL || Request->registers.rsp > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress))))
                { status = STATUS_INVALID_PARAMETER; }
                /* 无效命令不能被默认为 Continue。 */
                else if (Request->operation != KSWORD_ARK_HVM_NOATTACH_SET_GPR && Request->operation != KSWORD_ARK_HVM_NOATTACH_STEP &&
                         Request->operation != KSWORD_ARK_HVM_NOATTACH_CONTINUE) { status = STATUS_INVALID_PARAMETER; }
                /* 成功接受后才冻结命令和消费原停点。 */
                if (NT_SUCCESS(status))
                {
                    /* 目标线程不再借用 IOCTL 缓冲区。 */
                    g_Kna.Pending = *Request;
                    /* 一次唤醒只执行一个明确操作。 */
                    g_Kna.Action = Request->operation;
                    /* ContextPending 不能带旧寄存器冒充新停止。 */
                    g_Kna.State = Request->operation == KSWORD_ARK_HVM_NOATTACH_STEP ? KSWORD_ARK_HVM_NOATTACH_STEP_PENDING :
                        (Request->operation == KSWORD_ARK_HVM_NOATTACH_CONTINUE || Request->operation == KSWORD_ARK_HVM_NOATTACH_RUN_TO
                            ? KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING : KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING);
                    /* 目标异常线程在锁释放后提交。 */
                    KeSetEvent(&g_Kna.ContinueEvent, IO_NO_INCREMENT, FALSE);
                }
            }
            /* 不跨等待持有短锁。 */
            KeReleaseSpinLock(&g_Kna.StateLock, irql);
        }
    }
    else if (Request->operation != KSWORD_ARK_HVM_NOATTACH_QUERY && Request->operation != KSWORD_ARK_HVM_NOATTACH_CLOSE)
    { status = STATUS_INVALID_DEVICE_STATE; }
    /* 同一个所有者才可取得当前完整文档。 */
    if (g_Kna.Owned && owner == g_Kna.Owner && File == g_Kna.File)
    {
        /* 快照、状态和配置在同一锁内读取。 */
        KeAcquireSpinLock(&g_Kna.StateLock, &irql);
        /* 唯一寄存器来源是当前真实处理者。 */
        *Response = g_Kna.Snapshot;
        /* 关闭/内部预约不伪装成仍可操作的停点。 */
        Response->state = g_Kna.Closing ? KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED :
            (g_Kna.State == KNA_ARMING ? KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING : g_Kna.State);
        /* 配置按实际槽逐行公开，不重复投影到另一个隐藏列表。 */
        Response->breakpointCount = 0UL;
        /* 完整遍历四个真实槽。 */
        for (ULONG i = 0UL; i < 4UL; ++i) { if (g_Kna.Rows[i].id != 0UL) { Response->breakpoints[Response->breakpointCount++] = g_Kna.Rows[i]; } }
        /* 内存观察以同一个结构投影到响应，id 与 DR 槽使用同一个全局递增序列。 */
        for (ULONG i = 0UL; i < 4UL; ++i) { if (g_Kna.MemoryWatches[i].id != 0UL) { Response->breakpoints[Response->breakpointCount++] = g_Kna.MemoryWatches[i]; } }
        /* 非当前停止绝不泄露可消费的历史寄存器。 */
        if (Response->state != KSWORD_ARK_HVM_NOATTACH_STOPPED)
        {
            /* 旧停点不能授权下一条命令。 */
            Response->stopId = 0ULL; Response->stopReason = 0UL; Response->breakpointId = 0UL;
            /* 连续的公开上下文字段全部清空。 */
            RtlZeroMemory(&Response->rip, FIELD_OFFSET(KSWORD_ARK_KERNEL_NOATTACH_RESPONSE, breakpointId) -
                                         FIELD_OFFSET(KSWORD_ARK_KERNEL_NOATTACH_RESPONSE, rip));
        }
        /* Query 不阻塞实际消费者。 */
        KeReleaseSpinLock(&g_Kna.StateLock, irql);
    }
Unlock:
    /* 没有永久模块门时，失败的 OPEN 不遗留驱动回调。 */
    if (!g_Kna.Owned && Request->operation == KSWORD_ARK_HVM_NOATTACH_OPEN &&
        !KswordARKKernelNoAttachDriverPinned(WdfDeviceWdmGetDeviceObject(WdfFileObjectGetDevice(File))->DriverObject, NULL))
    {
        /* 回调注销会排空在途调用。 */
        if (KnaProcessNotifyRegistered) { (void)PsSetCreateProcessNotifyRoutineEx(KnaProcessNotify, TRUE); KnaProcessNotifyRegistered = FALSE; }
        /* 线程通知同样不能在模块卸载后继续进入。 */
        if (KnaThreadNotifyRegistered) { (void)PsRemoveCreateThreadNotifyRoutine(KnaThreadNotify); KnaThreadNotifyRegistered = FALSE; }
    }
    /* 控制与清理互斥结束。 */
    ExReleasePushLockExclusive(&g_Kna.ControlLock);
    /* 退出临界区。 */
    KeLeaveCriticalRegion();
Complete:
    /* 请求临时引用与会话引用分别归还。 */
    if (owner != NULL) { ObDereferenceObject(owner); }
    /* 返回完整语义错误，不把接受请求当完成单步。 */
    Response->status = status;
    /* 传输成功，固定响应内保留 NTSTATUS。 */
    return STATUS_SUCCESS;
}
