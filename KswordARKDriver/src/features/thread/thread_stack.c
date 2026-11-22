#include "thread_stack.h" // 引入唯一的通信协议与固定请求入口。
#include "thread_stack_cancel.h" // 复用具备返回后证明的单实例取消及退休所有权。
#include "thread_stack_snapshot.h" // 同步保存上下文来源不依赖目标 APC 的取消导出。
#include "../../platform/pool_compat.h" // 保持兼容目标系统的非分页池分配路径。

NTSYSAPI NTSTATUS NTAPI PsLookupThreadByThreadId( // 必须引用真实线程，不能使用请求者的历史对象地址。
    _In_ HANDLE ThreadId, // 冻结的目标线程标识。
    _Outptr_ PETHREAD* Thread // 由当前同步请求持有并归还的独立引用。
    ); // 声明与系统导出保持一致。
NTSYSAPI PEPROCESS NTAPI PsGetThreadProcess( // 从真实线程引用取得所属进程。
    _In_ PETHREAD Thread // 不接受未经引用的内核地址。
    ); // 所属进程另外建立独立引用。

#define KSW_STACK_POOL_TAG 'sTsK' // 专用于同步请求持有的非分页采集上下文。
#define KSW_STACK_MAX_PENDING 16L // 同时持有的请求和目标异步过程调用硬上限。
#define KSW_STACK_RAW_FRAMES (KSWORD_ARK_THREAD_STACK_MAX_FRAMES + 1UL) // 多探测一帧只用于证明调用方上限截断。

typedef USHORT(NTAPI* KSW_STACK_CAPTURE_BACKTRACE)(ULONG, ULONG, PVOID*, PULONG); // 系统当前线程有序回溯，不扫描候选地址。
typedef LONGLONG(NTAPI* KSW_STACK_THREAD_CREATE_TIME)(PETHREAD); // 真实线程创建时间公共查询。
typedef LONGLONG(NTAPI* KSW_STACK_PROCESS_CREATE_TIME)(PEPROCESS); // 真实进程创建时间公共查询。
typedef BOOLEAN(NTAPI* KSW_STACK_IS_PROTECTED)(PEPROCESS); // 保护状态缺失时不可放宽采集边界。

typedef struct _KSW_STACK_CONTEXT // 每个同步请求独占且必须在退休后才能释放。
{ // 不保留用户或请求框架缓冲区。
    KSW_STACK_APC_LIFETIME Lifetime; // 操作系统路径唯一引用由正常、退出或成功取消三选一归还。
    KEVENT SampleReady; // 只表示捕获函数已发布样本，不单独作为函数已返回的证明。
    PETHREAD Thread; // 同步请求在整个取消及排空期间持有真实线程引用。
    PEPROCESS Process; // 独立进程引用不能被数值标识复用替换。
    volatile LONG Abandoned; // 超时与停止后回调不再展开目标栈。
    KSWORD_ARK_THREAD_STACK_RESPONSE Sample; // 仅在退休门闩排空后复制给外部请求。
    PVOID RawFrames[KSW_STACK_RAW_FRAMES]; // 系统回溯输出使用非分页固定数组，不占目标栈大块空间。
} KSW_STACK_CONTEXT; // 不存在超时后遗留在全局注册表的上下文。

static EX_RUNDOWN_REF g_StackRequests; // 模块关闭等待当前同步请求完成取消和短回调排空。
static KEVENT g_StackStopEvent; // 关闭时立即打断所有仍在排队等待的请求。
static volatile LONG g_StackReady = 0L; // 全部同步对象初始化前禁止访问。
static volatile LONG g_StackStopping = 1L; // 停止接收后不重新开放。
static volatile LONG g_StackPending = 0L; // 固定并发上限同时限制回调与非分页资源。
static KSW_STACK_CAPTURE_BACKTRACE g_StackCapture = NULL; // 只解析系统命名展开导出。
static KSW_STACK_THREAD_CREATE_TIME g_StackThreadTime = NULL; // 不通过私有对象布局获取时间。
static KSW_STACK_PROCESS_CREATE_TIME g_StackProcessTime = NULL; // 不用请求者提供的时间冒充真实对象时间。
static KSW_STACK_IS_PROTECTED g_StackProtected = NULL; // 完整保护进程检查。
static KSW_STACK_IS_PROTECTED g_StackProtectedLight = NULL; // 轻量保护进程检查。

C_ASSERT(sizeof(KSWORD_ARK_THREAD_STACK_REQUEST) == 48U); // 固定请求保持原有第二版布局。
C_ASSERT(sizeof(KSWORD_ARK_THREAD_STACK_RESPONSE) == 680U); // 新增退休事实只使用标志，不扩张回执。
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_THREAD_STACK_RESPONSE, frames) == 168U); // 固定地址数组仍保持八字节对齐。

static PVOID KswStackResolve( // 仅由初始化阶段调用。
    _In_z_ PCWSTR Name // 名称固定在驱动源码中。
    ) // 不接受调用方指定的函数或模块地址。
{ // 开始命名导出解析。
    UNICODE_STRING name; // 保存常量名称描述符。
    RtlInitUnicodeString(&name, Name); // 由系统解析实际导出与相应控制流授权。
    return MmGetSystemRoutineAddress(&name); // 缺失时保持不可用，不寻找私有替代地址。
} // 结束命名导出解析。

static ULONG64 KswStackTime(VOID) // 分别用于请求、入队和实际采集时刻。
{ // 开始真实系统时间查询。
    LARGE_INTEGER now; // 由系统完整初始化的时间值。
    KeQuerySystemTime(&now); // 协调世界时，单位为百纳秒。
    return (ULONG64)now.QuadPart; // 采用文件时间语义而不是本地时钟字符串。
} // 结束系统时间查询。

static BOOLEAN KswStackVerifyCurrent( // 在系统回溯前后分别核验实际执行身份。
    _Inout_ KSW_STACK_CONTEXT* Context // 上下文始终由同步请求保活。
    ) // 不依赖排队线程或请求者的当前身份。
{ // 开始实际执行上下文取证。
    KSWORD_ARK_THREAD_STACK_RESPONSE* sample = &Context->Sample; // 私有样本不与请求框架缓冲区共享。
    PETHREAD current = PsGetCurrentThread(); // 取得正在本处理器执行的真实线程。
    PEPROCESS owner = PsGetThreadProcess(current); // 独立读取真实所属进程。
    PEPROCESS currentProcess = PsGetCurrentProcess(); // 同时核对当前附加地址空间。
    sample->currentThreadId = HandleToULong(PsGetCurrentThreadId()); // 真实当前线程标识。
    sample->currentProcessId = HandleToULong(PsGetCurrentProcessId()); // 真实当前进程标识。
    sample->currentThreadObject = (ULONG64)(ULONG_PTR)current; // 记录实际执行对象而非请求者对象。
    sample->currentProcessObject = (ULONG64)(ULONG_PTR)currentProcess; // 记录真实当前地址空间对象。
    sample->currentThreadCreationTime100ns = (ULONG64)g_StackThreadTime(current); // 从真实执行线程读取实例时间。
    sample->currentProcessCreationTime100ns = owner != NULL ? (ULONG64)g_StackProcessTime(owner) : 0ULL; // 不解引用推测对象。
    return current == Context->Thread && owner == Context->Process && currentProcess == Context->Process && // 对象归属和附加状态均须一致。
        sample->currentThreadId == sample->threadId && sample->currentProcessId == sample->processId && // 数值标识必须独立一致。
        sample->currentThreadCreationTime100ns == sample->threadCreationTime100ns && // 防止线程实例混淆。
        sample->currentProcessCreationTime100ns == sample->processCreationTime100ns; // 防止进程实例混淆。
} // 结束实际执行上下文取证。

static VOID NTAPI KswStackApcKernel( // 普通内核异步过程调用的真实目标捕获入口。
    _In_ PKAPC Apc, // 只由本模块合法入队的那个实例进入。
    _Inout_ KSW_STACK_NORMAL_ROUTINE* NormalRoutine, // 必须保留初始化时的非空正常尾包装器。
    _Inout_ PVOID* NormalContext, // 必须保留本实例退休门闩。
    _Inout_ PVOID* SystemArgument1, // 无额外目标操作。
    _Inout_ PVOID* SystemArgument2 // 无额外目标操作。
    ) // 正常尾包装器只能在本函数完整返回后才释放回调引用。
{ // 开始短且无等待的目标上下文采集。
    KSW_STACK_APC_LIFETIME* lifetime = CONTAINING_RECORD(Apc, KSW_STACK_APC_LIFETIME, Apc); // 只按本驱动结构定位。
    KSW_STACK_CONTEXT* context = CONTAINING_RECORD(lifetime, KSW_STACK_CONTEXT, Lifetime); // 同步请求在退休前不会释放该对象。
    KSWORD_ARK_THREAD_STACK_RESPONSE* sample = &context->Sample; // 不访问用户或请求框架缓冲区。
    LARGE_INTEGER frequency; // 与采集计数器同次读取的真实频率。
    LARGE_INTEGER qpc; // 真实目标执行时的单调计数器。
    USHORT count; // 真实系统展开器返回的帧数。
    ULONG index; // 固定数组的有界消费索引。
    UNREFERENCED_PARAMETER(NormalRoutine); // 不清空或替换正常例程，保证正常路径归还唯一引用。
    UNREFERENCED_PARAMETER(NormalContext); // 不改变已初始化的退休门闩地址。
    UNREFERENCED_PARAMETER(SystemArgument1); // 不修改传给正常包装器的空参数。
    UNREFERENCED_PARAMETER(SystemArgument2); // 不修改传给正常包装器的空参数。
    if (InterlockedCompareExchange(&context->Abandoned, 0L, 0L) != 0L) // 已超时或关闭的请求不再进行展开。
    { // 开始放弃样本的快速返回分支。
        goto Notify; // 仍保留正常例程负责函数返回后的退休证明。
    } // 结束放弃请求检查。
    sample->captureStartTime100ns = KswStackTime(); // 请求时刻与真正目标采集时刻分开。
    qpc = KeQueryPerformanceCounter(&frequency); // 记录真实目标的采样计数器。
    sample->captureQpc = (ULONG64)qpc.QuadPart; // 不使用请求线程的计数器冒充目标时刻。
    sample->qpcFrequency = (ULONG64)frequency.QuadPart; // 不假定固定硬件频率。
    sample->captureIrql = (ULONG)KeGetCurrentIrql(); // 记录真实内核回调级别。
    if (sample->captureIrql != APC_LEVEL || !KswStackVerifyCurrent(context)) // 拒绝其他线程、所属进程或附加地址空间。
    { // 开始采集前身份拒绝分支。
        sample->status = STATUS_RETRY; // 调用方必须重新核对实例身份。
        sample->result = KSWORD_ARK_THREAD_STACK_RESULT_IDENTITY_MISMATCH; // 身份不符时不调用系统展开器。
        sample->captureEndTime100ns = KswStackTime(); // 保存失败采集尝试的结束时间。
        goto Notify; // 所有帧从初始化开始就保持为零。
    } // 结束采集前身份核验。
    sample->source = KSWORD_ARK_THREAD_STACK_SOURCE_TARGET_NORMAL_APC; // 只有真实目标展开入口才发布该来源。
    count = g_StackCapture(0UL, sample->frameLimit + 1UL, context->RawFrames, NULL); // 系统只展开当前真实目标线程的内核返回地址。
    sample->flags |= KSWORD_ARK_THREAD_STACK_FLAG_APC_ENTRY_FRAMES | KSWORD_ARK_THREAD_STACK_FLAG_COMPLETENESS_UNKNOWN; // 保留采集与分发入口帧，不声称原始栈完整。
    if ((ULONG)count > sample->frameLimit) // 多出的一帧只证明调用方限制确实截断。
    { // 开始帧上限证据记录。
        sample->flags |= KSWORD_ARK_THREAD_STACK_FLAG_FRAME_LIMIT; // 不把未展开部分补成伪帧。
    } // 结束帧上限证据记录。
    if ((ULONG)count > KSW_STACK_RAW_FRAMES) // 不信任异常返回值扩大固定数组范围。
    { // 开始异常系统帧数拒绝分支。
        count = 0U; // 不读取任何越界元素。
    } // 结束固定容量核验。
    for (index = 0UL; index < (ULONG)count && index < sample->frameLimit; ++index) // 保持系统返回顺序，不扫描栈内候选数值。
    { // 开始真实返回地址过滤。
        ULONG_PTR address = (ULONG_PTR)context->RawFrames[index]; // 仅检查数值，不读取帧地址指向的内存。
        if (address < (ULONG_PTR)MmSystemRangeStart || address == MAXULONG_PTR) // 用户地址、空值及全位哨兵都不能当作内核帧。
        { // 开始无效内核地址截断分支。
            sample->flags |= KSWORD_ARK_THREAD_STACK_FLAG_INVALID_FRAME; // 明确标记不可继续信任的帧链。
            break; // 不跳过坏帧拼接看似完整的后续链。
        } // 结束内核地址范围检查。
        sample->frames[sample->frameCount] = (ULONG64)address; // 只保存真实有序返回地址。
        ++sample->frameCount; // 数量始终受调用方限制与固定容量约束。
    } // 结束真实返回地址消费。
    if (!KswStackVerifyCurrent(context)) // 展开后重新核验对象与完整实例时间。
    { // 开始展开后身份变化拒绝分支。
        RtlZeroMemory(sample->frames, sizeof(sample->frames)); // 任一身份不一致都清空全部调用帧。
        sample->frameCount = 0UL; // 不留下可以被误用的帧数。
        sample->status = STATUS_RETRY; // 保留真实身份变化语义。
        sample->result = KSWORD_ARK_THREAD_STACK_RESULT_IDENTITY_MISMATCH; // 不把身份变化误报为一般空栈。
    } // 结束展开后身份变化分支。
    else // 两次身份核验均通过才发布目标执行信任。
    { // 开始可信真实目标样本发布。
        sample->flags |= KSWORD_ARK_THREAD_STACK_FLAG_EXECUTED_IN_TARGET; // 不对请求者线程提供替代路径。
        sample->status = sample->frameCount != 0UL ? STATUS_SUCCESS : STATUS_NOT_FOUND; // 无真实帧时不报采集成功。
        sample->result = sample->frameCount != 0UL ? KSWORD_ARK_THREAD_STACK_RESULT_PARTIAL : KSWORD_ARK_THREAD_STACK_RESULT_UNAVAILABLE; // 非空也始终说明完整度未知。
    } // 结束展开后身份核验。
    sample->captureEndTime100ns = KswStackTime(); // 在发布样本前记录采集结束时刻。
Notify: // 样本通知与函数返回证明严格分开。
    (VOID)KeSetEvent(&context->SampleReady, IO_NO_INCREMENT, FALSE); // 同步方仍须等待正常尾包装器释放退休门闩。
} // 本函数返回后正常例程才会尾跳到系统退休释放例程。

VOID KswordARKThreadStackInitialize(VOID) // 开放控制面之前只调用一次。
{ // 开始请求与合法采集能力初始化。
    KswSavedStackInitialize(); // 在开放任何线程栈来源之前建立同步快照门闩。
    ExInitializeRundownProtection(&g_StackRequests); // 请求引用覆盖整个取消及回调排空过程。
    KeInitializeEvent(&g_StackStopEvent, NotificationEvent, FALSE); // 关闭时共同打断仍在排队等待的请求。
    (VOID)InterlockedExchange(&g_StackPending, 0L); // 初始没有私有采集上下文。
    g_StackCapture = (KSW_STACK_CAPTURE_BACKTRACE)KswStackResolve(L"RtlCaptureStackBackTrace"); // 只解析真实系统展开器。
    g_StackThreadTime = (KSW_STACK_THREAD_CREATE_TIME)KswStackResolve(L"PsGetThreadCreateTime"); // 真实线程时间查询。
    g_StackProcessTime = (KSW_STACK_PROCESS_CREATE_TIME)KswStackResolve(L"PsGetProcessCreateTimeQuadPart"); // 真实进程时间查询。
    g_StackProtected = (KSW_STACK_IS_PROTECTED)KswStackResolve(L"PsIsProtectedProcess"); // 缺失时不放宽保护边界。
    g_StackProtectedLight = (KSW_STACK_IS_PROTECTED)KswStackResolve(L"PsIsProtectedProcessLight"); // 单独保护轻量保护进程。
    (VOID)KswThreadStackApcInitializeBackend(); // 导出或尾跳证明失败只影响此功能，不破坏驱动整体加载。
    (VOID)InterlockedExchange(&g_StackStopping, 0L); // 所有同步状态建立后才允许请求进入。
    (VOID)InterlockedExchange(&g_StackReady, 1L); // 最后发布初始化完成状态。
} // 不建立常驻线程，不固定模块，不提前向任何目标入队。

VOID KswordARKThreadStackBeginStop(VOID) // 在全局请求门闩等待之前调用，不与持有该门闩的采集请求互相等待。
{ // 开始禁止后续入队并唤醒仍在排队的请求。
    if (InterlockedCompareExchange(&g_StackReady, 0L, 0L) == 0L) // 早期初始化失败时没有有效请求门闩。
    { // 开始未初始化退出分支。
        return; // 不访问未初始化的事件或门闩。
    } // 结束初始化状态检查。
    (VOID)InterlockedExchange(&g_StackStopping, 1L); // 后续请求不再取得采集资格。
    KswSavedStackBeginStop(); // 同时禁止保存上下文来源的新会合轮次。
    (VOID)KeSetEvent(&g_StackStopEvent, IO_NO_INCREMENT, FALSE); // 请求立即进入自身的取消及退休路径。
} // 此入口不等待，因此可以安全地位于核心请求门闩之前。

VOID KswordARKThreadStackUninitialize(VOID) // 控制面封闭后、相关依赖销毁前调用。
{ // 开始排空已经收到停止通知的同步请求和短回调。
    if (InterlockedCompareExchange(&g_StackReady, 0L, 0L) == 0L) // 初始化失败时不能等待未初始化门闩。
    { // 开始未初始化快速退出。
        return; // 不访问任何请求同步对象。
    } // 结束初始化状态检查。
    KswordARKThreadStackBeginStop(); // 反初始化独立调用时仍保证先发布停止通知。
    ExWaitForRundownProtectionRelease(&g_StackRequests); // 只等待已经执行的短回调与同步所有者，不等待目标恢复或真实退出。
    KswSavedStackUninitialize(); // 所有同步会合、DPC 返回及副本展开均完成后才能卸载。
} // 不存在仍在队列中阻止卸载的遗留实例，不能用强制截止掩盖尚在执行的内核代码。

NTSTATUS KswordARKThreadStackCapture( // 同步请求拥有所有内存、对象引用和唯一退休责任。
    _In_ const KSWORD_ARK_THREAD_STACK_REQUEST* Input, // 由请求处理器冻结完整实例身份。
    _Out_ KSWORD_ARK_THREAD_STACK_RESPONSE* Output // 只在回调已经退休后发布真实帧。
    ) // 运输成功与业务采集结果必须分别解释。
{ // 开始有界投递等待与真实目标展开请求。
    KSW_STACK_CONTEXT* context = NULL; // 只在真实对象与合法生命周期能力核验后分配。
    PETHREAD thread = NULL; // 当前同步调用持有的真实线程引用。
    PEPROCESS process = NULL; // 当前同步调用持有的独立进程引用。
    LARGE_INTEGER timeout; // 只限制等待目标投递的相对时间。
    PVOID objects[3]; // 样本已发布、真实线程退出或模块停止。
    NTSTATUS status; // 真实查找与等待状态，不把正超时当作成功。
    BOOLEAN pendingOwned = FALSE; // 只有占用名额的请求才能归还计数。
    BOOLEAN removed; // 保存实际取消事实，不与样本完成混淆。
    if (Input == NULL || Output == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) // 只有合法且可以等待的内核调用环境才接受。
    { // 开始调用环境拒绝分支。
        return STATUS_INVALID_PARAMETER; // 不访问无效缓冲区。
    } // 结束调用环境检查。
    RtlZeroMemory(Output, sizeof(*Output)); // 所有失败路径都从零帧、零采集证据开始。
    Output->size = (ULONG)sizeof(*Output); // 发布固定回执大小。
    Output->version = KSWORD_ARK_THREAD_STACK_VERSION; // 保持第二版安全语义。
    Output->status = STATUS_INVALID_PARAMETER; // 完整请求核验前没有业务成功语义。
    Output->processId = Input->processId; // 数值回显不证明对象身份。
    Output->threadId = Input->threadId; // 不能改为请求者线程。
    Output->frameLimit = Input->frameLimit; // 保存本次帧数预算。
    Output->timeoutMs = Input->timeoutMs; // 保存本次排队等待预算。
    Output->requestTime100ns = KswStackTime(); // 即使未入队也保存真实请求时刻。
    if (Input->size != sizeof(*Input) || Input->version != KSWORD_ARK_THREAD_STACK_VERSION || // 布局和语义版本必须精确一致。
        Input->processId == 0UL || Input->threadId == 0UL || Input->expectedProcessCreationTime100ns == 0ULL || // 不能省略目标实例身份。
        Input->expectedThreadCreationTime100ns == 0ULL || Input->frameLimit == 0UL || // 线程实例与预算均须明确。
        Input->frameLimit > KSWORD_ARK_THREAD_STACK_MAX_FRAMES || Input->timeoutMs == 0UL || // 固定容量与非零等待预算。
        Input->timeoutMs > KSWORD_ARK_THREAD_STACK_MAX_TIMEOUT_MS || Input->flags != 0UL || Input->reserved != 0UL) // 禁止旧版无界驻留豁免。
    { // 开始无效固定请求拒绝分支。
        return STATUS_SUCCESS; // 运输成功，但业务回执保留无效参数和零帧。
    } // 结束固定请求检查。
    Output->status = STATUS_DEVICE_NOT_READY; // 初始化前与关闭后均不可入队。
    if (InterlockedCompareExchange(&g_StackReady, 0L, 0L) == 0L || // 初始化前不可访问请求门闩。
        InterlockedCompareExchange(&g_StackStopping, 0L, 0L) != 0L || // 停止接收后拒绝请求。
        !ExAcquireRundownProtection(&g_StackRequests)) // 模块清理等待本次请求的完整退休责任。
    { // 开始未取得请求引用的拒绝分支。
        return STATUS_SUCCESS; // 没有取得的门闩引用不能归还。
    } // 结束请求资格检查。
    if (InterlockedCompareExchange(&g_StackStopping, 0L, 0L) != 0L) // 取得引用后复核关闭竞争。
    { // 开始关闭竞争处理。
        goto Complete; // 统一归还已经取得的请求引用。
    } // 结束关闭竞争复核。
    Output->status = STATUS_PROCEDURE_NOT_FOUND; // 必要身份与保护查询缺失时不尝试采集。
    if (g_StackThreadTime == NULL || g_StackProcessTime == NULL || g_StackProtected == NULL || g_StackProtectedLight == NULL) // 不推测时间或保护状态。
    { // 开始必需查询能力缺失分支。
        goto Complete; // 保留真实不可用状态。
    } // 结束必需查询检查。
    status = PsLookupThreadByThreadId(ULongToHandle(Input->threadId), &thread); // 从真实线程标识取得独立引用。
    if (!NT_SUCCESS(status)) // 对象查找失败不采集请求者的栈。
    { // 开始线程查找失败分支。
        Output->status = status; // 保存真实查找错误。
        goto Complete; // 统一归还请求引用。
    } // 结束线程查找检查。
    process = PsGetThreadProcess(thread); // 所属对象来自真实线程，而不是调用方地址。
    if (process != NULL) // 非空归属才能建立独立引用。
    { // 开始独立进程保活。
        ObReferenceObject(process); // 直到取消或回调退休后才归还。
    } // 结束独立进程保活。
    Output->status = STATUS_RETRY; // 任一对象归属差异都视为身份不符。
    Output->result = KSWORD_ARK_THREAD_STACK_RESULT_IDENTITY_MISMATCH; // 身份失败始终零帧。
    if (process == NULL || HandleToULong(PsGetProcessId(process)) != Input->processId || // 核对真实进程数值身份。
        HandleToULong(PsGetThreadId(thread)) != Input->threadId || // 核对真实线程数值身份。
        HandleToULong(PsGetThreadProcessId(thread)) != Input->processId) // 独立核对线程记录的所属标识。
    { // 开始对象归属拒绝分支。
        goto Complete; // 不改选任何替代目标。
    } // 结束对象归属检查。
    Output->processCreationTime100ns = (ULONG64)g_StackProcessTime(process); // 公共查询在真实进程引用上执行。
    Output->threadCreationTime100ns = (ULONG64)g_StackThreadTime(thread); // 公共查询在真实线程引用上执行。
    Output->threadObject = (ULONG64)(ULONG_PTR)thread; // 仅回执本次真实引用身份。
    Output->processObject = (ULONG64)(ULONG_PTR)process; // 不能用作以后请求的对象访问能力。
    if (Output->processCreationTime100ns != Input->expectedProcessCreationTime100ns || // 进程实例时间必须一致。
        Output->threadCreationTime100ns != Input->expectedThreadCreationTime100ns) // 线程实例时间必须一致。
    { // 开始实例时间拒绝分支。
        goto Complete; // 不将错误实例误报为普通能力缺失。
    } // 结束实例时间检查。
    Output->flags = KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED; // 此位只证明对象实例，不代表已在目标执行。
    Output->result = KSWORD_ARK_THREAD_STACK_RESULT_UNAVAILABLE; // 后续业务失败不保留身份不符分类。
    Output->status = STATUS_ACCESS_DENIED; // 完整与轻量保护目标都拒绝。
    if (g_StackProtected(process) || g_StackProtectedLight(process)) // 不添加任何保护绕过。
    { // 开始保护目标拒绝分支。
        goto Complete; // 不入队、不采集保护对象。
    } // 结束保护边界检查。
    Output->status = STATUS_INVALID_DEVICE_STATE; // 禁止排队请求线程等待自己的目标回调。
    if (thread == PsGetCurrentThread()) // 也不提供当前请求者栈的替代接口。
    { // 开始请求者自身拒绝分支。
        goto Complete; // 不进行任何回溯。
    } // 结束请求者自身检查。
    Output->status = STATUS_PROCEDURE_NOT_FOUND; // 展开器缺失与取消生命周期缺失分开回执。
    if (g_StackCapture == NULL) // 不以线索、事件样本或请求者回溯替代系统展开器。
    { // 开始系统展开能力缺失分支。
        goto Complete; // 保持普通不可用分类和零帧。
    } // 结束系统展开能力检查。
    Output->status = STATUS_NOT_SUPPORTED; // 取消、尾跳或展开能力缺失必须在入队前拒绝。
    Output->result = KSWORD_ARK_THREAD_STACK_RESULT_LIFETIME_UNAVAILABLE; // 包括没有合法取消导出的目标系统。
    if (!KswThreadStackApcAvailable()) // 不根据版本号猜测能力，不调用私有取消地址。
    { // 开始安全生命周期能力缺失分支。
        goto Complete; // 返回零来源、零采集时刻与零帧。
    } // 结束采集能力门禁。
    Output->result = KSWORD_ARK_THREAD_STACK_RESULT_UNAVAILABLE; // 之后失败属于资源或执行阶段。
    Output->status = STATUS_DEVICE_BUSY; // 并发上限失败不假称已入队。
    if (InterlockedIncrement(&g_StackPending) > KSW_STACK_MAX_PENDING) // 原子限制同时存活的目标与非分页上下文。
    { // 开始并发超限处理。
        (VOID)InterlockedDecrement(&g_StackPending); // 归还未取得的名额。
        goto Complete; // 不分配或入队额外目标。
    } // 结束并发上限检查。
    pendingOwned = TRUE; // 后续统一清理才能归还该名额。
    context = (KSW_STACK_CONTEXT*)KswordARKAllocateNonPagedPool(sizeof(*context), KSW_STACK_POOL_TAG); // 所有回调访问状态必须常驻。
    Output->status = STATUS_INSUFFICIENT_RESOURCES; // 不以栈上或用户缓冲区作为后备。
    if (context == NULL) // 分配失败时没有任何目标回调。
    { // 开始分配失败分支。
        goto Complete; // 统一归还已取得名额。
    } // 结束上下文分配检查。
    RtlZeroMemory(context, sizeof(*context)); // 帧与执行证据从确定零状态开始。
    context->Thread = thread; // 借用当前请求直到统一清理才归还的真实引用。
    context->Process = process; // 该引用同样覆盖整个回调退休过程。
    KeInitializeEvent(&context->SampleReady, NotificationEvent, FALSE); // 通知不替代返回后退休证明。
    context->Sample = *Output; // 冻结真实目标身份、请求时刻与预算。
    context->Sample.queuedTime100ns = KswStackTime(); // 紧邻真正入队，失败时不会发布该时间。
    context->Sample.flags |= KSWORD_ARK_THREAD_STACK_FLAG_QUEUED; // 在可能立即执行的回调开始前准备私有样本。
    Output->status = STATUS_UNSUCCESSFUL; // 真实入队失败与生命周期能力缺失分开。
    if (!KswThreadStackApcQueue(&context->Lifetime, (PKTHREAD)thread, KswStackApcKernel)) // 仅普通内核投递，不改变目标禁用状态。
    { // 开始实际入队失败分支。
        goto Complete; // 生命周期模块已归还未转移的唯一引用。
    } // 结束实际入队检查。
    Output->queuedTime100ns = context->Sample.queuedTime100ns; // 此时才可以发布已入队时刻。
    Output->flags |= KSWORD_ARK_THREAD_STACK_FLAG_QUEUED; // 系统确实接受了该实例。
    objects[0] = &context->SampleReady; // 样本发布后仍须执行返回后退休等待。
    objects[1] = thread; // 真实目标退出与仅收到终止请求不同。
    objects[2] = &g_StackStopEvent; // 模块停止立即进入取消路径。
    timeout.QuadPart = -((LONGLONG)Input->timeoutMs * 10000LL); // 负值表示有界相对等待。
    status = KeWaitForMultipleObjects(3UL, objects, WaitAny, Executive, KernelMode, FALSE, &timeout, NULL); // 不挂起目标、不强迫禁用目标投递。
    if (status != STATUS_WAIT_0) // 超时、退出、停止和异常等待均放弃样本。
    { // 开始样本放弃处理。
        (VOID)InterlockedExchange(&context->Abandoned, 1L); // 已分发但尚未展开的回调可以立即走短完成路径。
    } // 结束样本放弃处理。
    removed = KswThreadStackApcRetire(&context->Lifetime); // 排队实例立即取消，已分发或退出清理实例必须尾跳离开驱动。
    Output->flags |= KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED; // 此时才证明外层内存与驱动代码均可安全退休。
    if (removed) // 取消真假必须按系统返回值记录。
    { // 开始实际取消事实记录。
        Output->flags |= KSWORD_ARK_THREAD_STACK_FLAG_OWN_APC_CANCELLED; // 绝不声称移除过其他目标或其他管理器的实例。
    } // 结束实际取消事实记录。
    if (status == STATUS_WAIT_0) // 只有真实样本通知且回调已完整离开驱动才允许复制。
    { // 开始稳定样本发布。
        *Output = context->Sample; // 不存在并发写入或提前释放通知对象的问题。
        Output->flags |= KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED; // 私有样本无法自行伪造退休完成。
    } // 结束稳定样本发布。
    else if (status == STATUS_WAIT_1) // 真实退出不等于采集成功。
    { // 开始目标退出回执。
        Output->status = STATUS_THREAD_IS_TERMINATING; // 保持零帧，不发布任何私有迟到样本。
    } // 结束目标退出回执。
    else if (status == STATUS_WAIT_2) // 模块停止仍必须先完整退休本次实例。
    { // 开始模块停止回执。
        Output->status = STATUS_DELETE_PENDING; // 与排队超时和目标退出分开。
    } // 结束模块停止回执。
    else // 正超时与其他等待状态均不是成功采集。
    { // 开始超时或异常等待回执。
        Output->status = status; // 保存真实等待状态，不能只用成功宏解释正超时。
        Output->result = status == STATUS_TIMEOUT ? KSWORD_ARK_THREAD_STACK_RESULT_TIMEOUT : KSWORD_ARK_THREAD_STACK_RESULT_UNAVAILABLE; // 超时业务结果始终零帧。
    } // 结束等待状态分类。
Complete: // 成功入队之后没有任何跳转会绕过上面的唯一退休调用。
    if (context != NULL) // 仅释放尚未入队或已经证明退休的上下文。
    { // 开始私有非分页内存释放。
        ExFreePoolWithTag(context, KSW_STACK_POOL_TAG); // 真实对象引用仍由当前请求持有。
    } // 结束上下文释放。
    if (pendingOwned) // 只有成功取得名额才对称归还。
    { // 开始并发名额归还。
        (VOID)InterlockedDecrement(&g_StackPending); // 回调已退休，因此此名额可以安全复用。
    } // 结束并发名额归还。
    if (process != NULL) // 进程引用覆盖整个异步过程调用生命周期。
    { // 开始独立进程引用归还。
        ObDereferenceObject(process); // 不残留超时后的进程引用。
    } // 结束进程引用归还。
    if (thread != NULL) // 线程引用同样只由当前同步请求拥有。
    { // 开始独立线程引用归还。
        ObDereferenceObject(thread); // 不依赖目标未来退出才能回收请求内存。
    } // 结束线程引用归还。
    ExReleaseRundownProtection(&g_StackRequests); // 最后释放同步请求，模块卸载随后才可继续。
    return STATUS_SUCCESS; // 消费者仍必须检查业务状态、来源、标志和真实帧数。
} // 结束有界排队等待、合法取消与返回后退休的目标采集请求。
