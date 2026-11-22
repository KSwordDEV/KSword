#include "thread_stack_cancel.h" // 引入本模块唯一的生命周期所有权定义。
#include "../../platform/runtime_signature_scan.h" // 所有代码与间接地址核验都通过共享安全读取器。

#if defined(_AMD64_) || defined(_M_AMD64) // 尾跳证明目前只覆盖明确核验的六十四位指令形式。
typedef VOID(NTAPI* KSW_STACK_RUNDOWN_ROUTINE)(PKAPC); // 线程退出时系统对该实例调用一次的清理签名。
typedef VOID(NTAPI* KSW_STACK_INITIALIZE_APC)( // 系统初始化导出使用精确的内核参数约定。
    PKAPC, PKTHREAD, LONG, KSW_STACK_KERNEL_ROUTINE, KSW_STACK_RUNDOWN_ROUTINE, // 只使用原始环境与本驱动固定回调。
    KSW_STACK_NORMAL_ROUTINE, KPROCESSOR_MODE, PVOID // 非空正常例程使目标遵循普通内核投递条件。
    ); // 不使用特殊异步过程调用绕过普通投递限制。
typedef BOOLEAN(NTAPI* KSW_STACK_INSERT_APC)(PKAPC, PVOID, PVOID, KPRIORITY); // 系统返回真才取得已入队事实。
typedef BOOLEAN(NTAPI* KSW_STACK_REMOVE_APC)(PKAPC); // 仅对本请求持有的那个实例执行合法取消。

static KSW_STACK_INITIALIZE_APC g_StackInitializeApc = NULL; // 只接受命名系统导出。
static KSW_STACK_INSERT_APC g_StackInsertApc = NULL; // 不扫描或推断操作系统代码入口。
static KSW_STACK_REMOVE_APC g_StackRemoveApc = NULL; // 缺失时即使能入队也拒绝功能。
static BOOLEAN g_StackApcAvailable = FALSE; // 尾跳和全部导出同时成立后才发布能力。

static __declspec(noinline) VOID NTAPI KswStackNormalReturn( // 这是正常例程本身，不进行不匹配函数类型的系统回调转换。
    _In_opt_ PVOID NormalContext, // 初始化时固定指向本实例的退休门闩。
    _In_opt_ PVOID SystemArgument1, // 原始请求不携带额外目标操作。
    _In_opt_ PVOID SystemArgument2 // 原始请求不携带额外目标操作。
    ) // 运行时只接受没有返回到本驱动代码的尾跳生成结果。
{ // 开始正常返回证明包装器。
    UNREFERENCED_PARAMETER(SystemArgument1); // 不改变真实目标执行状态。
    UNREFERENCED_PARAMETER(SystemArgument2); // 不进行额外等待或访问外部对象。
    ExReleaseRundownProtection((PEX_RUNDOWN_REF)NormalContext); // 必须生成为经导入表跳向系统例程的最终尾跳。
} // 若编译器在系统调用后生成返回指令，该构建会在任何入队前被拒绝。

static __declspec(noinline) VOID NTAPI KswStackRundownReturn( // 这是退出清理本身，不在其中释放上下文。
    _In_ PKAPC Apc // 只能是本模块成功入队且仍由同步请求持有的实例。
    ) // 调用方与正常路径互斥，唯一引用只能归还一次。
{ // 开始退出返回证明包装器。
    KSW_STACK_APC_LIFETIME* lifetime = CONTAINING_RECORD(Apc, KSW_STACK_APC_LIFETIME, Apc); // 位移只来自本驱动自己的结构。
    ExReleaseRundownProtection(&lifetime->Callback); // 必须先恢复本驱动栈帧再尾跳到导入的系统释放例程。
} // 运行时核验防止任何保留本驱动返回地址的生成结果参与采集。

static PVOID KswStackResolveExport( // 只在初始化的可分页级别调用公开解析器。
    _In_z_ PCWSTR Name // 名称固定在本模块，不接受用户参数。
    ) // 不使用任何私有函数相对地址。
{ // 开始合法导出解析。
    UNICODE_STRING name; // 保存系统导出名称描述符。
    RtlInitUnicodeString(&name, Name); // 系统自行解析当前运行内核或硬件抽象层。
    return MmGetSystemRoutineAddress(&name); // 已核验的目标系统在返回前执行其自身的内核控制流目标授权。
} // 不直接调用内部授权例程，也不访问或修改保护位图。

static BOOLEAN KswStackTailVerified( // 只解释本驱动两个微小包装器，绝不据此寻找操作系统函数。
    _In_ const VOID* Routine, // 编译器与链接器确定的本模块入口。
    _In_ ULONG ContextAdjustment // 零或本驱动生命周期结构中门闩的确定偏移。
    ) // 不接受任何调用方给出的代码、签名或函数地址。
{ // 开始有界尾跳证明。
    UCHAR code[32]; // 固定容量足以覆盖地址调整和导入表尾跳。
    ULONG offset = 0UL; // 只接受从真实函数入口开始的已知指令序列。
    ULONG adjustment = 0UL; // 必须与本驱动结构偏移完全一致。
    ULONG instructionBytes; // 保存最终间接跳转指令的确切长度。
    LONG displacement; // 导入表单元使用带符号的相对寻址。
    LONG64 slot; // 先用有符号地址运算避免负位移被错误扩展。
    PVOID target = NULL; // 只接受实际导入的系统退休释放例程。
    if (!KswordARKRuntimeReadMemory(Routine, code, sizeof(code))) // 即使本模块代码也不依赖异常捕获读取。
    { // 开始读取失败分支。
        return FALSE; // 无法证明就不启用任何目标回调。
    } // 结束有界代码读取检查。
    if (code[0] == 0xF3U && code[1] == 0x0FU && code[2] == 0x1EU && code[3] == 0xFAU) // 允许不改变栈与参数的标准入口标记。
    { // 开始入口标记处理。
        offset = 4UL; // 标记之后仍必须直接进入已知序列。
    } // 结束入口标记处理。
    if (ContextAdjustment != 0UL) // 退出包装器只允许调整第一个参数，不允许建立任何栈帧。
    { // 开始本驱动结构地址调整证明。
        if (code[offset] == 0x48U && code[offset + 1UL] == 0x83U && code[offset + 2UL] == 0xC1U) // 接受加正八位立即数。
        { // 开始短立即数调整。
            adjustment = code[offset + 3UL]; // 高位必须为零，避免有符号立即数产生相反偏移。
            if (adjustment >= 0x80UL) // 本驱动布局不允许负偏移冒充正偏移。
            { // 开始负立即数拒绝分支。
                return FALSE; // 不解释未授权生成形式。
            } // 结束短立即数符号检查。
            offset += 4UL; // 后续只能是最终尾跳。
        } // 结束短立即数调整。
        else if (code[offset] == 0x48U && code[offset + 1UL] == 0x8DU && code[offset + 2UL] == 0x49U) // 接受同等的短位移地址计算。
        { // 开始短地址计算。
            adjustment = code[offset + 3UL]; // 本结构偏移在可验证的正范围内。
            if (adjustment >= 0x80UL) // 拒绝负短位移。
            { // 开始负短位移拒绝分支。
                return FALSE; // 不将负值当作本驱动结构偏移。
            } // 结束短位移符号检查。
            offset += 4UL; // 参数调整后不得执行其他驱动指令。
        } // 结束短地址计算。
        else if (code[offset] == 0x48U && // 长位移也必须只改变第一个参数。
            ((code[offset + 1UL] == 0x81U && code[offset + 2UL] == 0xC1U) || // 接受加三十二位立即数。
             (code[offset + 1UL] == 0x8DU && code[offset + 2UL] == 0x89U))) // 接受同等的长地址计算。
        { // 开始长立即数或位移处理。
            RtlCopyMemory(&adjustment, &code[offset + 3UL], sizeof(adjustment)); // 只读取已经安全复制的本地数组。
            offset += 7UL; // 该指令后面必须紧接导入尾跳。
        } // 结束长地址调整。
        else // 未识别的序言可能含栈帧或其他返回路径。
        { // 开始未知生成代码拒绝分支。
            return FALSE; // 不用启发式扫描尾部来掩盖未知控制流。
        } // 结束未知生成代码拒绝。
        if (adjustment != ContextAdjustment) // 必须准确指向当前实例的退休门闩。
        { // 开始结构位移不符分支。
            return FALSE; // 不接受操作系统布局推断或近似偏移。
        } // 结束结构地址调整核验。
    } // 结束可选的参数调整。
    if (code[offset] == 0x48U && code[offset + 1UL] == 0xFFU && code[offset + 2UL] == 0x25U) // 接受带标准前缀的导入表间接尾跳。
    { // 开始七字节尾跳解码。
        instructionBytes = 7UL; // 前缀不会创建返回地址。
        RtlCopyMemory(&displacement, &code[offset + 3UL], sizeof(displacement)); // 只从本地快照解出相对位移。
    } // 结束带前缀尾跳解码。
    else if (code[offset] == 0xFFU && code[offset + 1UL] == 0x25U) // 接受相同语义的无前缀形式。
    { // 开始六字节尾跳解码。
        instructionBytes = 6UL; // 这仍是跳转，不是调用后再返回。
        RtlCopyMemory(&displacement, &code[offset + 2UL], sizeof(displacement)); // 不解引用任意指令来源地址。
    } // 结束无前缀尾跳解码。
    else // 调用、返回、栈序言、跳板或未知插桩均不能证明安全离开本驱动。
    { // 开始非尾跳生成结果拒绝分支。
        return FALSE; // 此构建仍可正常加载，但目标采集保持生命周期不可用。
    } // 结束最终指令形式检查。
    slot = (LONG64)(ULONG_PTR)Routine + (LONG64)offset + (LONG64)instructionBytes + (LONG64)displacement; // 只计算该指令明确引用的导入单元。
    if ((ULONG_PTR)slot < (ULONG_PTR)MmSystemRangeStart || // 导入单元必须位于系统地址范围。
        !KswordARKRuntimeReadMemory((PVOID)(ULONG_PTR)slot, &target, sizeof(target))) // 通过统一安全读取器取得实际绑定目标。
    { // 开始导入单元读取失败分支。
        return FALSE; // 不回退为直接读取或跳过证明。
    } // 结束导入单元读取检查。
    return target == (PVOID)ExReleaseRundownProtection; // 唯一接受的尾部是本驱动正常导入的系统退休释放例程。
} // 成功意味着引用归还发生时已经没有本包装器的栈帧或驱动返回地址。

BOOLEAN KswThreadStackApcInitializeBackend(VOID) // 必须在开放请求前的可分页级别调用。
{ // 开始合法取消及返回后退休能力检查。
    g_StackInitializeApc = (KSW_STACK_INITIALIZE_APC)KswStackResolveExport(L"KeInitializeApc"); // 解析真实初始化导出。
    g_StackInsertApc = (KSW_STACK_INSERT_APC)KswStackResolveExport(L"KeInsertQueueApc"); // 解析真实入队导出。
    g_StackRemoveApc = (KSW_STACK_REMOVE_APC)KswStackResolveExport(L"KeRemoveQueueApc"); // 无导出时拒绝，不调用精确私有地址。
    g_StackApcAvailable = g_StackInitializeApc != NULL && g_StackInsertApc != NULL && g_StackRemoveApc != NULL && // 必须同时具备合法入队与取消。
        KswStackTailVerified((const VOID*)KswStackNormalReturn, 0UL) && // 正常路径必须在目标捕获回调返回后尾跳回内核。
        KswStackTailVerified((const VOID*)KswStackRundownReturn, (ULONG)FIELD_OFFSET(KSW_STACK_APC_LIFETIME, Callback)); // 退出路径必须同样没有驱动尾部窗口。
    return g_StackApcAvailable; // 任一证明失败都不会排入目标异步过程调用。
} // 不永久固定模块，不关闭控制流保护，不创建后台清理任务。

BOOLEAN KswThreadStackApcAvailable(VOID) // 能力在请求开放前发布，关闭前不修改相关入口。
{ // 开始能力查询。
    return g_StackApcAvailable; // 不把只有入队导出存在当作生命周期可用。
} // 结束能力查询。

BOOLEAN KswThreadStackApcQueue( // 一个实例只调用一次，失败时没有任何回调能够访问该对象。
    _Inout_ KSW_STACK_APC_LIFETIME* Lifetime, // 私有内存由同步请求持有。
    _In_ PKTHREAD Thread, // 真实目标线程仍有独立引用。
    _In_ KSW_STACK_KERNEL_ROUTINE KernelRoutine // 本驱动固定捕获入口，绝不接受用户回调。
    ) // 返回真以后必须由同一同步请求执行一次退休。
{ // 开始单实例引用所有权转移。
    if (!g_StackApcAvailable) // 防止任何内部调用绕过能力门禁。
    { // 开始能力缺失拒绝分支。
        return FALSE; // 此时既没有引用也没有已入队实例。
    } // 结束能力门禁。
    ExInitializeRundownProtection(&Lifetime->Callback); // 每次请求拥有全新的退休门闩。
    if (!ExAcquireRundownProtection(&Lifetime->Callback)) // 在入队之前取得唯一操作系统路径引用。
    { // 开始不应出现的初始引用失败分支。
        return FALSE; // 没有任何目标回调可运行。
    } // 结束初始引用取得检查。
    g_StackInitializeApc(&Lifetime->Apc, Thread, 0L, KernelRoutine, KswStackRundownReturn, // 使用原始环境与固定退出尾包装器。
        KswStackNormalReturn, KernelMode, &Lifetime->Callback); // 非空正常例程保留普通内核投递限制。
    if (!g_StackInsertApc(&Lifetime->Apc, NULL, NULL, IO_NO_INCREMENT)) // 两个系统参数均不携带其他操作。
    { // 开始真实入队失败分支。
        ExReleaseRundownProtection(&Lifetime->Callback); // 从未转移给操作系统的引用由同步请求归还。
        ExWaitForRundownProtectionRelease(&Lifetime->Callback); // 完成门闩退休后才能释放外层对象。
        return FALSE; // 不冒充入队成功或推断具体禁用原因。
    } // 结束真实入队检查。
    return TRUE; // 唯一引用现在由取消、正常或退出路径三选一归还。
} // 同步请求继续保活所有内存及真实对象引用。

BOOLEAN KswThreadStackApcRetire( // 成功入队的实例只能由请求所有者执行一次退休。
    _Inout_ KSW_STACK_APC_LIFETIME* Lifetime // 不允许其他管理器移除该实例。
    ) // 返回时上下文与驱动映像都没有残留回调访问。
{ // 开始取消或已分发短回调排空。
    BOOLEAN removed = g_StackRemoveApc(&Lifetime->Apc); // 只尝试移除本模块自己入队且仍保活的实例。
    if (removed) // 真表示系统已排除分发与退出清理取得该实例的可能。
    { // 开始成功取消的唯一引用归还。
        ExReleaseRundownProtection(&Lifetime->Callback); // 取消方代替互斥的两个操作系统回调路径归还引用。
    } // 假表示已经分发、正在退出清理或已经完成，绝不能再归还第二次引用。
    ExWaitForRundownProtectionRelease(&Lifetime->Callback); // 只等待已经取得的短回调离开驱动，不等待排队目标恢复或线程退出。
    return removed; // 返回真实取消事实，不把已经执行完成冒充取消成功。
} // 任何超时与停止路径都必须先到这里再释放内存。
#else // 未核验的体系结构明确不提供采集能力。
BOOLEAN KswThreadStackApcInitializeBackend(VOID) // 非六十四位构建不能复用指令证明。
{ // 开始不支持体系结构初始化。
    return FALSE; // 不解析或投递目标回调。
} // 结束不支持体系结构初始化。
BOOLEAN KswThreadStackApcAvailable(VOID) // 保留一致的内部查询接口。
{ // 开始不支持体系结构能力查询。
    return FALSE; // 不把未知代码生成当作已证明安全。
} // 结束不支持体系结构能力查询。
BOOLEAN KswThreadStackApcQueue( // 不支持体系结构的请求永远不能入队。
    _Inout_ KSW_STACK_APC_LIFETIME* Lifetime, // 不访问目标实例。
    _In_ PKTHREAD Thread, // 不访问目标线程。
    _In_ KSW_STACK_KERNEL_ROUTINE KernelRoutine // 不调用传入的驱动回调。
    ) // 只为共用调用代码提供安全拒绝入口。
{ // 开始拒绝未核验投递。
    UNREFERENCED_PARAMETER(Lifetime); // 不初始化或取得异步引用。
    UNREFERENCED_PARAMETER(Thread); // 不改变目标状态。
    UNREFERENCED_PARAMETER(KernelRoutine); // 不建立回调生命周期。
    return FALSE; // 同步所有者仍独占其内存。
} // 结束拒绝未核验投递。
BOOLEAN KswThreadStackApcRetire( // 不支持体系结构没有成功入队的实例。
    _Inout_ KSW_STACK_APC_LIFETIME* Lifetime // 调用方不得在入队失败后调用此接口。
    ) // 保持链接接口完整，不伪造任何取消事实。
{ // 开始不支持体系结构的空退休接口。
    UNREFERENCED_PARAMETER(Lifetime); // 没有操作系统引用可以归还。
    return FALSE; // 不声称移除过任何队列项。
} // 结束不支持体系结构的空退休接口。
#endif // 结束尾跳指令证明的体系结构边界。
