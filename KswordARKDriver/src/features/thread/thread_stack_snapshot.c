#include "thread_stack_snapshot.h" // 读取已保存目标上下文，不使用目标 APC。
#include "../process/structure_sample_profiles.h" // 仅允许完整 PE/RSDS 精确配置。
#include "../../platform/pool_compat.h" // 沿用现有非分页池分配兼容层。
#include "../../platform/runtime_signature_scan.h" // 被动级身份及代码读取复用安全入口。

NTSYSAPI NTSTATUS NTAPI PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD* Thread); // 公开数值身份到真实引用。
NTSYSAPI PEPROCESS NTAPI PsGetThreadProcess(PETHREAD Thread); // 从真实线程引用取得归属。
typedef VOID(NTAPI* KSW_SAVED_GENERIC_DPC)(PKDEFERRED_ROUTINE, PVOID); // 系统同步全处理器 DPC 会合。
typedef BOOLEAN(NTAPI* KSW_SAVED_SYNC_DPC)(PVOID); // 系统会合栅栏，不持有任何调度器私有锁。
typedef VOID(NTAPI* KSW_SAVED_DONE_DPC)(PVOID); // 只表示本轮工作完成，返回退休另由 flush 证明。
typedef LONGLONG(NTAPI* KSW_SAVED_THREAD_TIME)(PETHREAD); // 真实线程创建时间。
typedef LONGLONG(NTAPI* KSW_SAVED_PROCESS_TIME)(PEPROCESS); // 真实进程创建时间。
typedef BOOLEAN(NTAPI* KSW_SAVED_PROCESS_TEST)(PEPROCESS); // 保持完整及轻量保护进程边界。
typedef BOOLEAN(NTAPI* KSW_SAVED_THREAD_TEST)(PETHREAD); // 拒绝退出中的目标，而非读取其旧栈地址。
typedef PVOID(NTAPI* KSW_SAVED_IMAGE_BASE)(PVOID, PVOID*); // 命名系统导出的映像归属查询。

typedef struct _KSW_SAVED_CONTEXT // 同步请求持有，所有 DPC 返回前绝不释放。
{ // 偏移只适用于下方两个独立核验的精确内核。
    PETHREAD Thread; // 真实目标引用由外层请求持有。
    KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE Sample; // DPC 只写私有响应，不访问 WDF 缓冲。
    volatile LONG Running; // 任一处理器当前执行目标时禁止远端栈复制。
    volatile LONG Arrived; // 本轮实际参与会合的处理器数。
    ULONG ExpectedProcessors; // 请求开始时核对的单组处理器数。
    ULONG64 ExpectedReturn; // 精确 KiSwapContext 调用返回点，不调用任何私有例程。
    ULONG64 SavedRbp; // 从确定的切换帧槽位读取的非易失寄存器。
    UCHAR Bytes[KSW_SAVED_STACK_BYTES]; // 完整复制后才允许离开会合阶段。
} KSW_SAVED_CONTEXT; // 不建立常驻线程、队列或目标挂起状态。

static KSW_SAVED_GENERIC_DPC g_SavedGeneric = NULL; // 仅接受系统命名导出。
static KSW_SAVED_SYNC_DPC g_SavedSync = NULL; // 不扫描或调用私有调度器地址。
static KSW_SAVED_DONE_DPC g_SavedDone = NULL; // 不通过伪造回调类型释放本模块引用。
static KSW_SAVED_THREAD_TIME g_SavedThreadTime = NULL; // 在持有引用上校验创建身份。
static KSW_SAVED_PROCESS_TIME g_SavedProcessTime = NULL; // 防止 PID 重用混淆。
static KSW_SAVED_PROCESS_TEST g_SavedProtected = NULL; // 完整保护目标拒绝。
static KSW_SAVED_PROCESS_TEST g_SavedLight = NULL; // 轻量保护目标也拒绝。
static KSW_SAVED_THREAD_TEST g_SavedTerminating = NULL; // 退出后不访问已释放内核栈。
static EX_RUNDOWN_REF g_SavedRequests; // 覆盖同步 DPC、flush 与副本展开。
static volatile LONG g_SavedStopping = 1L; // 初始化前、停止后均拒绝。
static volatile LONG g_SavedPending = 0L; // 同时在途最多十六个非分页副本。
static KSPIN_LOCK g_SavedTopologyLock; // 原子协调处理器加入通知与一轮短会合。
static LONG g_SavedTopologyChanging = 0L; // Start 到 Complete/Failure 期间不启动快照。
static BOOLEAN g_SavedRoundActive = FALSE; // 同时只允许一轮会合，避免并发回调互相等待。
static PVOID g_SavedProcessorRegistration = NULL; // 卸载前必须注销的系统拓扑通知。

static VOID KswSavedProcessorChange(PVOID CallbackContext, PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT Change, PNTSTATUS OperationStatus) // 系统同步处理器加入通知。
{ // 不在通知回调中等待会合或持有系统调度器锁。
    KIRQL oldIrql; // 保存短自旋锁前的实际 IRQL。
    UNREFERENCED_PARAMETER(CallbackContext); // 状态仅归本来源拥有。
    if (Change == NULL || OperationStatus == NULL) return; // 不访问无效的通知描述符。
    KeAcquireSpinLock(&g_SavedTopologyLock, &oldIrql); // Start 与采样准入在同一锁下排序。
    if (Change->State == KeProcessorAddStartNotify) // 新 CPU 尚未激活前系统先发送此通知。
    { // 只有真正处于会合期间才拒绝本轮拓扑改变。
        if (g_SavedRoundActive && NT_SUCCESS(*OperationStatus)) *OperationStatus = STATUS_DEVICE_BUSY; // 自己否决的 Start 不会再收到终态回调，不能留下未归还计数。
        else if (NT_SUCCESS(*OperationStatus)) ++g_SavedTopologyChanging; // 仅成功接受的 Start 才由 Complete/Failure 归还。
    } // 不修改任何现有处理器状态。
    else if (Change->State == KeProcessorAddCompleteNotify || Change->State == KeProcessorAddFailureNotify) // 两种终态均结束同一次 Start。
    { // 拓扑变化期间的所有快照均已拒绝。
        if (g_SavedTopologyChanging > 0L) --g_SavedTopologyChanging; // 不让计数下溢后意外开放采集。
    } // 结束通知终态处理。
    KeReleaseSpinLock(&g_SavedTopologyLock, oldIrql); // 不跨系统回调持有锁。
} // 注销由模块排空路径负责。

static BOOLEAN KswSavedBeginRound(VOID) // 在 PASSIVE_LEVEL 为一次有限 DPC 会合取得独占资格。
{ // 一轮之外不阻止 CPU 加入，也不永久固定处理器拓扑。
    BOOLEAN acquired; // 返回本请求是否真正持有短会合资格。
    KIRQL oldIrql; // 自旋锁前 IRQL。
    KeAcquireSpinLock(&g_SavedTopologyLock, &oldIrql); // 与热加入 Start 原子排序。
    acquired = !g_SavedRoundActive && g_SavedTopologyChanging == 0L && g_SavedStopping == 0L; // 拓扑必须稳定，停止通知优先。
    if (acquired) g_SavedRoundActive = TRUE; // 在任何 DPC 进入之前先发布资格。
    KeReleaseSpinLock(&g_SavedTopologyLock, oldIrql); // 不跨 DPC 持有自旋锁。
    return acquired; // 未取得者仅在被动级预算内重试。
} // 回调不使用本函数。

static VOID KswSavedEndRound(VOID) // 全部 DPC 已返回及 flush 后才可归还资格。
{ // 独占状态覆盖驱动回调的 epilogue。
    KIRQL oldIrql; // 自旋锁前 IRQL。
    KeAcquireSpinLock(&g_SavedTopologyLock, &oldIrql); // 与处理器 Start 通知保持同一顺序。
    g_SavedRoundActive = FALSE; // 后续采样或 CPU 加入现在可以继续。
    KeReleaseSpinLock(&g_SavedTopologyLock, oldIrql); // 无等待地结束短状态更新。
} // 不允许在 DPC 尚未返回时调用。

static PVOID KswSavedResolve(PCWSTR Name) // 输入固定名称，输出系统授权的真实导出或空。
{ // 只在初始化或被动级请求准备阶段调用。
    UNICODE_STRING name; // 常量名称的系统描述符。
    RtlInitUnicodeString(&name, Name); // 不接受用户提供的例程名称。
    return MmGetSystemRoutineAddress(&name); // 由系统自身处理导出及控制流授权。
} // 不使用精确私有 RVA 作为调用目标。

static ULONG64 KswSavedTime(VOID) // 输出当前真实 UTC FILETIME。
{ // 可由短 DPC 在 DISPATCH_LEVEL 调用。
    LARGE_INTEGER now; // 完整系统时间输出。
    KeQuerySystemTime(&now); // 不冒用请求者提交的时刻。
    return (ULONG64)now.QuadPart; // 单位为一百纳秒。
} // 结束时间取证。

static VOID KswSavedCopy(KSW_SAVED_CONTEXT* Context) // 所有受支持处理器均已到达第一道栅栏。
{ // 其他处理器留在第二道栅栏，不会重新调度或释放目标栈。
    KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE* out = &Context->Sample; // 本轮独立证据。
    const UCHAR* thread = (const UCHAR*)Context->Thread; // 仅从已经持有的真实对象读取精确字段。
    ULONG64 low; // 精确 StackLimit。
    ULONG64 high; // 精确 StackBase。
    ULONG64 saved; // 精确 KernelStack。
    ULONG flags; // 精确 ThreadFlags 中的驻留位。
    ULONG_PTR page; // 对整个有限复制区逐页核对驻留，不触发缺页。
    LARGE_INTEGER frequency; // 与采样 QPC 同次取得频率。
    LARGE_INTEGER qpc; // 实际快照时刻。
    out->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_RUNNING; // 默认不读取仍在变化的目标。
    out->capture.status = STATUS_RETRY; // 允许外层在预算内重新会合。
    if (Context->Running != 0L || Context->Arrived != (LONG)Context->ExpectedProcessors) // 没有全核稳定观察就不复制。
    { // 开始运行中或拓扑不符拒绝。
        return; // 不读取目标保存栈，也不以 DPC 自己的栈替代。
    } // 结束运行状态核验。
    out->threadState = thread[388U]; // 两份完整 PDB 均明确 State 位于 0x184。
    RtlCopyMemory(&flags, thread + 120U, sizeof(flags)); // 两份 PDB 均明确 KernelStackResident 为 0x78 的第十七位。
    out->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_STATE; // 退出、未初始化和转换态不冒充可展开。
    if (out->threadState != 1UL && out->threadState != 3UL && out->threadState != 5UL && out->threadState != 7UL && out->threadState != 8UL) // 只接受明确非运行且已建立上下文的状态。
    { // 开始调度状态拒绝。
        return; // 不修改状态，不唤醒、不挂起、不强制线程调度。
    } // 结束已保存上下文状态核验。
    out->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_RESIDENCY; // 缺页栈不能作为已完整读取的数据。
    if ((flags & (1UL << 17U)) == 0UL) // 被换出的内核栈不进行直接读取。
    { // 开始非驻留拒绝。
        return; // 不换入远端栈，也不在高 IRQL 触发缺页。
    } // 结束驻留位检查。
    RtlCopyMemory(&low, thread + 48U, sizeof(low)); // 精确 StackLimit 字段。
    RtlCopyMemory(&high, thread + 56U, sizeof(high)); // 精确 StackBase 字段。
    RtlCopyMemory(&saved, thread + 88U, sizeof(saved)); // 精确 KernelStack 字段。
    if (low < (ULONG64)(ULONG_PTR)MmSystemRangeStart || low >= high || saved < low || saved >= high || // 只接受真实内核栈范围。
        high - low > KSW_SAVED_STACK_BYTES || high - saved < 0x180ULL || (saved & 7ULL) != 0ULL) // 固定预算覆盖完整保存区和第一层寄存器。
    { // 开始范围拒绝。
        out->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_RANGE; // 不截取尾部后谎称完整快照。
        return; // 没有任何目标栈字节被解引用。
    } // 结束栈边界核验。
    for (page = (ULONG_PTR)saved & ~((ULONG_PTR)PAGE_SIZE - 1U); page < (ULONG_PTR)high; page += PAGE_SIZE) // 仅核对有限栈段。
    { // 所有调度处理器仍在会合，栈的释放和换出不能并发发生。
        if (!MmIsAddressValid((PVOID)page)) // 只在本处 DISPATCH_LEVEL 会合区使用，不把检查当普通远端读取锁。
        { // 开始缺页拒绝。
            return; // 未完整驻留时不复制，也不产生零填充伪帧。
        } // 结束页面驻留核验。
    } // 结束整个复制区的驻留检查。
    out->capture.captureStartTime100ns = KswSavedTime(); // 记录真正会合快照时刻。
    qpc = KeQueryPerformanceCounter(&frequency); // 不将请求时刻当实际采样时刻。
    out->capture.captureQpc = (ULONG64)qpc.QuadPart; // 单调采样计数器。
    out->capture.qpcFrequency = (ULONG64)frequency.QuadPart; // 同次计数器频率。
    RtlCopyMemory(Context->Bytes, (const VOID*)(ULONG_PTR)saved, (SIZE_T)(high - saved)); // 只在全核会合下完整复制目标保存栈。
    out->capture.captureEndTime100ns = KswSavedTime(); // 复制结束后即允许处理器恢复。
    out->savedKernelStack = saved; // 保存原始地址，仅作为本次取证。
    out->stackLow = low; // 保留权威下界。
    out->stackHigh = high; // 保留权威上界。
    out->snapshotByteCount = (ULONG)(high - saved); // 实际完整复制的字节数。
    out->processorCount = (ULONG)Context->Arrived; // 采用真实到达数。
    RtlCopyMemory(&Context->SavedRbp, Context->Bytes + 0x30U, sizeof(Context->SavedRbp)); // 精确切换序言 push rbp 后 sub rsp,0x30。
    RtlCopyMemory(&out->initialInstructionPointer, Context->Bytes + 0x38U, sizeof(out->initialInstructionPointer)); // 读取保存的真实调用返回点。
    out->initialStackPointer = saved + 0x40ULL; // 对应退回 KiSwapContext 的真实 RSP。
    out->capture.status = out->initialInstructionPointer == Context->ExpectedReturn ? STATUS_SUCCESS : STATUS_REVISION_MISMATCH; // 必须精确命中已校验调用点。
    out->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_STATE; // 匹配失败不得调用展开器。
    out->capture.captureIrql = (ULONG)KeGetCurrentIrql(); // 实际复制级别为 DISPATCH_LEVEL。
} // 退出本函数不代表 DPC 已返回，外层仍须 flush。

static VOID KswSavedDpc(PKDPC Dpc, PVOID DeferredContext, PVOID Argument1, PVOID Argument2) // 系统同步会合回调。
{ // 回调内无分配、无文件/符号查询、无等待目标事件。
    KSW_SAVED_CONTEXT* context = (KSW_SAVED_CONTEXT*)DeferredContext; // 外层请求保活到全部 DPC 返回。
    UNREFERENCED_PARAMETER(Dpc); // 不重排或重入本 DPC。
    if (PsGetCurrentThread() == context->Thread) // 每个处理器独立观察真实当前线程。
    { // 开始目标正在运行的事实记录。
        (VOID)InterlockedIncrement(&context->Running); // 不能根据 KTHREAD.State 单方面推断远端已停稳。
    } // 结束当前线程检查。
    (VOID)InterlockedIncrement(&context->Arrived); // 栅栏前发布本处理器已到达。
    if (g_SavedSync(Argument2)) // 系统栅栏选出唯一复制者，其他处理器进入第二道栅栏等待。
    { // 开始唯一稳定快照。
        KswSavedCopy(context); // 不展开或扫描处理器回调自己的栈。
    } // 结束唯一复制者工作。
    (VOID)g_SavedSync(Argument2); // 复制完成前没有处理器提前恢复目标调度。
    g_SavedDone(Argument1); // 完成计数不是返回证明，外层 KeFlushQueuedDpcs 之后才释放内存。
} // 驱动 epilogue 仍受外层同步请求引用保护。

VOID KswSavedStackInitialize(VOID) // 随线程栈模块初始化，不创建后台任务。
{ // 仅解析系统导出，不调用私有地址。
    ExInitializeRundownProtection(&g_SavedRequests); // 请求完整覆盖 DPC 回调返回与本地展开。
    KeInitializeSpinLock(&g_SavedTopologyLock); // 注册通知前先建立同步基础。
    g_SavedProcessorRegistration = KeRegisterProcessorChangeCallback(KswSavedProcessorChange, NULL, KE_PROCESSOR_CHANGE_ADD_EXISTING); // 同步枚举现有 CPU 并覆盖后续加入。
    g_SavedGeneric = (KSW_SAVED_GENERIC_DPC)KswSavedResolve(L"KeGenericCallDpc"); // 标准系统全核会合入口。
    g_SavedSync = (KSW_SAVED_SYNC_DPC)KswSavedResolve(L"KeSignalCallDpcSynchronize"); // 标准会合栅栏。
    g_SavedDone = (KSW_SAVED_DONE_DPC)KswSavedResolve(L"KeSignalCallDpcDone"); // 标准工作完成入口。
    g_SavedThreadTime = (KSW_SAVED_THREAD_TIME)KswSavedResolve(L"PsGetThreadCreateTime"); // 公开创建时间。
    g_SavedProcessTime = (KSW_SAVED_PROCESS_TIME)KswSavedResolve(L"PsGetProcessCreateTimeQuadPart"); // 公开进程时间。
    g_SavedProtected = (KSW_SAVED_PROCESS_TEST)KswSavedResolve(L"PsIsProtectedProcess"); // 保持既有保护边界。
    g_SavedLight = (KSW_SAVED_PROCESS_TEST)KswSavedResolve(L"PsIsProtectedProcessLight"); // 不绕过 PPL。
    g_SavedTerminating = (KSW_SAVED_THREAD_TEST)KswSavedResolve(L"PsIsThreadTerminating"); // 退出期间拒绝读取旧栈。
    (VOID)InterlockedExchange(&g_SavedStopping, 0L); // 同步对象完整初始化后才开放。
} // 不依赖 KeRemoveQueueApc。

VOID KswSavedStackBeginStop(VOID) // 在全局请求排空前通知停止。
{ // 已在执行的短会合完整返回，后续重试轮次立即停止。
    (VOID)InterlockedExchange(&g_SavedStopping, 1L); // 不留下待目标未来投递的 APC。
} // 不强制卸载仍在执行的驱动代码。

VOID KswSavedStackUninitialize(VOID) // 请求关闭后排空本来源。
{ // 同步请求负责归还全部副本与对象引用。
    KswSavedStackBeginStop(); // 独立清理调用也先封闭新轮次。
    ExWaitForRundownProtectionRelease(&g_SavedRequests); // 不等待目标线程解除等待或退出。
    if (g_SavedProcessorRegistration != NULL) KeDeregisterProcessorChangeCallback(g_SavedProcessorRegistration); // 回调代码必须在映像卸载前注销。
    g_SavedProcessorRegistration = NULL; // 不保留已注销的系统句柄。
} // 结束同步来源排空。

NTSTATUS KswSavedStackCapture(const KSWORD_ARK_THREAD_STACK_SNAPSHOT_REQUEST* Input, KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE* Output) // 同步身份冻结与目标保存上下文采集。
{ // 非分页副本只存在于当前受保护请求期间。
    KSW_SAVED_CONTEXT* context = NULL; // 成功分配后才拥有私有副本。
    KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID identity; // 实际加载内核的精确身份。
    const KSW_STRUCTURE_SAMPLE_PROFILE* profile = NULL; // 不接受用户配置或邻版偏移。
    PETHREAD thread = NULL; // 独立目标引用。
    PEPROCESS process = NULL; // 独立所属进程引用。
    PVOID base = NULL; // 系统判定的常驻 NT 基址。
    KSW_SAVED_IMAGE_BASE imageBase; // 公开映像归属查询。
    ULONG returnRva; // 精确 KiSwapContext 内部调用的返回位置。
    ULONG internalRva; // 只读检查精确切换序言，绝不调用。
    UCHAR prolog[6]; // 保存 rbp 和 0x30 字节区的确定指令形式。
    static const UCHAR expectedProlog[6] = {0x48U, 0x55U, 0x48U, 0x83U, 0xECU, 0x30U}; // 两份实际 PE 均为 REX.W push rbp；不能由反汇编助记符猜 REX 字节。
    NTSTATUS status; // 真实查找、配置和采样结果。
    BOOLEAN pending = FALSE; // 防止资源上限拒绝后误减计数。
    ULONG64 deadline; // 仅限制重复取样轮次，不提前释放执行中的 DPC。
    LARGE_INTEGER delay; // 两轮之间让出请求者 CPU，不操作目标线程。
    if (Input == NULL || Output == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) // 必须允许同步排空与本地展开。
    { // 开始参数环境拒绝。
        return STATUS_INVALID_PARAMETER; // 不访问无效缓冲。
    } // 结束参数环境检查。
    RtlZeroMemory(Output, sizeof(*Output)); // 任何拒绝默认都没有帧、来源或栈字节。
    Output->capture.size = (ULONG)sizeof(*Output); // 本端点返回独立的完整响应。
    Output->capture.version = KSWORD_ARK_STACK_SNAPSHOT_VERSION; // 不冒充旧 APC wire。
    Output->capture.status = STATUS_INVALID_PARAMETER; // 先验证完整输入。
    Output->capture.processId = Input->processId; // 未验证目标标识的回显。
    Output->capture.threadId = Input->threadId; // 不改为请求者。
    Output->capture.frameLimit = Input->frameLimit; // 保存本次帧预算。
    Output->capture.timeoutMs = Input->timeoutMs; // 保存本次重试预算。
    Output->capture.requestTime100ns = KswSavedTime(); // 真实收到请求的时刻。
    if (Input->size != sizeof(*Input) || Input->version != KSWORD_ARK_STACK_SNAPSHOT_VERSION || Input->processId == 0UL || Input->threadId == 0UL || // 必须使用固定协议。
        Input->expectedProcessCreationTime100ns == 0ULL || Input->expectedThreadCreationTime100ns == 0ULL || Input->frameLimit == 0UL || Input->frameLimit > 64UL || // 两个实例时间都必需。
        Input->timeoutMs == 0UL || Input->timeoutMs > 5000UL || Input->flags != 0UL || Input->reserved != 0UL) // 不接收地址、长度或生命周期豁免。
    { // 开始错误请求拒绝。
        return STATUS_SUCCESS; // 运输成功不等于业务成功。
    } // 结束输入验证。
    Output->capture.status = STATUS_DELETE_PENDING; // 初始化前或停止后不执行会合。
    if (g_SavedStopping != 0L || !ExAcquireRundownProtection(&g_SavedRequests)) // 当前请求必须持有代码和资源生存期。
    { // 开始模块关闭拒绝。
        return STATUS_SUCCESS; // 没有取得的引用不归还。
    } // 结束请求准入。
    Output->capture.status = STATUS_NOT_SUPPORTED; // 能力缺失在读目标保存栈前拒绝。
    if (g_SavedGeneric == NULL || g_SavedSync == NULL || g_SavedDone == NULL || g_SavedThreadTime == NULL || g_SavedProcessTime == NULL || // 所有必要入口均需存在。
        g_SavedProtected == NULL || g_SavedLight == NULL || g_SavedTerminating == NULL || g_SavedProcessorRegistration == NULL || KeQueryActiveGroupCount() != 1U) // 尚未核验多组会合，不冒称已冻结全部处理器。
    { // 开始必要能力拒绝。
        goto Complete; // 只归还已取得的请求引用。
    } // 结束能力检查。
    status = KswStructureSampleResolveProfile(&identity, &profile); // 完整校验实际加载 PE/RSDS，而非磁盘名字。
    Output->capture.status = status; // 不隐藏配置失败。
    if (!NT_SUCCESS(status) || profile == NULL || (profile->ProfileId != 2UL && profile->ProfileId != 3UL)) // 仅已核验的两个客体。
    { // 开始精确配置拒绝。
        if (NT_SUCCESS(status)) Output->capture.status = STATUS_NOT_SUPPORTED; // 已知对象根布局不自动授权保存切换帧布局。
        goto Complete; // 不借用宿主或相邻版本的切换帧。
    } // 结束精确配置检查。
    returnRva = profile->ProfileId == 2UL ? 0x3FBF96UL : 0x6B97B6UL; // 两份精确 PDB 的 KiSwapContext+0x76。
    internalRva = profile->ProfileId == 2UL ? 0x3FC270UL : 0x6B9820UL; // 仅用于读取和核对指令形式。
    imageBase = (KSW_SAVED_IMAGE_BASE)KswSavedResolve(L"RtlPcToFileHeader"); // 不扫描猜测内核基址。
    Output->capture.status = STATUS_REVISION_MISMATCH; // 指令或归属不符时不读目标栈。
    if (imageBase == NULL || imageBase(KswSavedResolve(L"KeBugCheckEx"), &base) == NULL || base == NULL || // 由系统确定实际 NT 基址。
        !KswordARKRuntimeReadMemory((UCHAR*)base + internalRva, prolog, sizeof(prolog)) || RtlCompareMemory(prolog, expectedProlog, sizeof(prolog)) != sizeof(prolog)) // 保存帧定义必须与实际代码一致。
    { // 开始代码身份拒绝。
        goto Complete; // 不将 RVA 当作可调用私有入口。
    } // 结束精确序言核验。
    status = PsLookupThreadByThreadId(ULongToHandle(Input->threadId), &thread); // 从数值身份取得真实线程。
    Output->capture.status = status; // 保留原始查找错误。
    if (!NT_SUCCESS(status)) // 找不到原实例就没有采样对象。
    { // 开始目标缺失拒绝。
        goto Complete; // 不提供请求者替代帧。
    } // 结束线程引用建立。
    process = PsGetThreadProcess(thread); // 归属来自真实线程。
    if (process != NULL) ObReferenceObject(process); // 独立引用覆盖 DPC 与副本展开。
    Output->capture.status = STATUS_RETRY; // 任何身份差异都拒绝。
    Output->capture.result = KSWORD_ARK_THREAD_STACK_RESULT_IDENTITY_MISMATCH; // 不是可用性拒绝。
    if (process == NULL || HandleToULong(PsGetProcessId(process)) != Input->processId || // 真实进程数值身份。
        (ULONG64)g_SavedProcessTime(process) != Input->expectedProcessCreationTime100ns || (ULONG64)g_SavedThreadTime(thread) != Input->expectedThreadCreationTime100ns) // 独立创建身份。
    { // 开始实例拒绝。
        goto Complete; // 不允许旧 PID/TID 指向新实例。
    } // 结束实例身份核验。
    Output->capture.flags = KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED; // 此时仅对象身份成立。
    Output->capture.processCreationTime100ns = Input->expectedProcessCreationTime100ns; // 已与真实对象独立比对。
    Output->capture.threadCreationTime100ns = Input->expectedThreadCreationTime100ns; // 已与真实线程独立比对。
    Output->capture.threadObject = (ULONG64)(ULONG_PTR)thread; // 本次引用的诊断身份。
    Output->capture.processObject = (ULONG64)(ULONG_PTR)process; // 本次进程引用。
    Output->capture.result = KSWORD_ARK_THREAD_STACK_RESULT_UNAVAILABLE; // 后续拒绝不误报身份错误。
    Output->capture.status = STATUS_ACCESS_DENIED; // 保护目标不进行任何会合读取。
    if (g_SavedProtected(process) || g_SavedLight(process) || thread == PsGetCurrentThread() || g_SavedTerminating(thread)) // 不读保护、请求者自身或退出栈。
    { // 开始目标范围拒绝。
        goto Complete; // 不改变目标状态。
    } // 结束保护与退出边界。
    Output->capture.status = STATUS_DEVICE_BUSY; // 资源预算拒绝不是入队或采样成功。
    if (InterlockedIncrement(&g_SavedPending) > 16L) // 非分页内存与同时在途操作受同一硬上限约束。
    { // 开始超限处理。
        (VOID)InterlockedDecrement(&g_SavedPending); // 归还未取得的名额。
        goto Complete; // 不分配更多副本。
    } // 结束资源上限检查。
    pending = TRUE; // 从此由统一清理归还名额。
    context = (KSW_SAVED_CONTEXT*)KswordARKAllocateNonPagedPool(sizeof(*context), 'pSsK'); // DPC 只访问非分页请求状态。
    Output->capture.status = STATUS_INSUFFICIENT_RESOURCES; // 不在目标栈上放置大副本。
    if (context == NULL) goto Complete; // 分配失败无任何回调或读取。
    RtlZeroMemory(context, sizeof(*context)); // 防止任何未读数据解释为帧。
    context->Thread = thread; // 外层引用保活。
    context->Sample = *Output; // 冻结身份和请求预算。
    context->ExpectedReturn = (ULONG64)(ULONG_PTR)base + returnRva; // 实际保存返回点必须精确一致。
    context->ExpectedProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); // 当前已核验只有一组。
    context->Sample.kernelImageBase = (ULONG64)(ULONG_PTR)base; // 系统确定的常驻映像。
    context->Sample.kernelTimeDateStamp = identity.timeDateStamp; // 完整匹配的实际 PE 身份。
    context->Sample.kernelImageSize = identity.sizeOfImage; // 元数据解析严格限制于此范围。
    context->Sample.kernelPdbAge = identity.pdbAge; // 精确 Age。
    RtlCopyMemory(context->Sample.kernelPdbGuid, identity.pdbGuid, sizeof(identity.pdbGuid)); // 不转换 GUID 字节序。
    deadline = KeQueryInterruptTime() + (ULONG64)Input->timeoutMs * 10000ULL; // 预算仅限制后续重试。
    delay.QuadPart = -10000LL; // 两轮之间请求者让出一毫秒，不挂起目标。
    do // 每轮只做一次短稳定复制，不在 DPC 内等待目标变化。
    { // 开始新的独立会合轮次。
        context->Sample.capture.status = STATUS_DEVICE_BUSY; // 未取得会合资格不能沿用上轮状态。
        if (KswSavedBeginRound()) // 并发采集只在被动级等待，不让两轮 DPC 互相等待。
        { // 热加入在本轮结束前会得到明确 busy，而非改变会合参与集。
            context->Running = 0L; // 上轮回调已经 flush 返回。
            context->Arrived = 0L; // 每轮重算真实参与数。
            if (KeQueryActiveGroupCount() == 1U && KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) == context->ExpectedProcessors) // 准入后再核对完整单组拓扑。
            { // 不在 CPU 数变化后启动旧期望数的会合。
                g_SavedGeneric(KswSavedDpc, context); // 由系统完成全处理器 DPC 会合。
                KeFlushQueuedDpcs(); // Done 之后的驱动 epilogue 也必须离开，不能提前释放上下文或代码。
            } // 结束单轮系统会合。
            KswSavedEndRound(); // 所有回调返回后恢复普通拓扑与后续请求准入。
        } // 结束短会合独占范围。
        if (NT_SUCCESS(context->Sample.capture.status) || g_SavedStopping != 0L || g_SavedTerminating(thread)) break; // 有稳定样本或停止事实后不再重发。
        if (KeQueryInterruptTime() >= deadline) break; // 不把等待超时误报为目标没有内核栈。
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &delay); // 普通请求者延时，不修改目标调度状态。
    } while (KeQueryActiveGroupCount() == 1U && KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) == context->ExpectedProcessors); // 拓扑变化立即停止重试。
    if (NT_SUCCESS(context->Sample.capture.status) && g_SavedStopping == 0L && !g_SavedTerminating(thread)) // 仅完整稳定副本才进入原生展开。
    { // 不再读取目标的活动栈内存。
        context->Sample.capture.source = KSWORD_ARK_STACK_SNAPSHOT_SOURCE; // 与 APC 来源明确区分。
        context->Sample.capture.flags |= KSWORD_ARK_STACK_SNAPSHOT_FROZEN; // 全核会合和非运行事实同时成立。
        KswSavedStackUnwind(&context->Sample, context->Bytes, context->SavedRbp); // 在被动级展开私有副本。
    } // 结束稳定副本展开。
    else if (NT_SUCCESS(context->Sample.capture.status)) context->Sample.capture.status = STATUS_THREAD_IS_TERMINATING; // 停止或退出时不能返回成功空帧。
    *Output = context->Sample; // 所有 DPC 均已返回，无并发响应写入。
Complete: // 所有真实回调均在到达此标签前同步完成及 flush。
    if (context != NULL) ExFreePoolWithTag(context, 'pSsK'); // 不留下超时后驻留副本。
    if (pending) (VOID)InterlockedDecrement(&g_SavedPending); // 对称归还资源名额。
    if (process != NULL) ObDereferenceObject(process); // 对象引用覆盖了全部读取。
    if (thread != NULL) ObDereferenceObject(thread); // 不依赖目标未来退出才能清理。
    ExReleaseRundownProtection(&g_SavedRequests); // 最后释放本模块代码生存期。
    return STATUS_SUCCESS; // 消费者必须继续检查业务状态、来源和帧数。
} // 结束不依赖目标 APC 的保存上下文快照。
