#include "hvm_noattach.h"
#include <intrin.h>

/* 这些是 Intel VMCS/MSR 编码，不属于调用方可写的通信协议。 */
#define NA_TF 0x100ULL
/* 自有边界期间拦截外部中断，保持来宾 IF 及栈上标志不变。 */
#define NA_INTERRUPT_EXIT 1ULL
/* NMI 同样必须先退出，不能带着本方 TF 进入来宾中断处理者。 */
#define NA_NMI_EXIT 8ULL

/* root 中所有读取都来自当前 VMCS 或会话已锁定的固定映射。 */
static BOOLEAN NaBoundaryRead(ULONG Field, ULONGLONG *Value)
{
    /* VMREAD 的宿主宽度由既有体系结构入口定义。 */
    SIZE_T result = 0U;
    /* 读取失败不发布猜测值。 */
    if (KswordARKHvmVmcsFieldLoad(Field, &result) != 0U) { return FALSE; }
    /* 成功后才复制完整值。 */
    *Value = (ULONGLONG)result;
    /* 不访问用户指针。 */
    return TRUE;
}

BOOLEAN KswordARKHvmNoAttachTfAvailable(VOID)
{
    /* 调用方已确认实际 VMX 能力，普通查询不会进入 VMX。 */
    ULONGLONG basic = 0ULL, pin = 0ULL, exitControls = 0ULL;
    /* TRUE 控制与旧控制不能混用。 */
    __try
    {
        /* 能力 MSR 读取失败只拒绝此模式，不能使只读查询触发内核异常。 */
        basic = __readmsr(0x480UL);
        /* TRUE 控制与旧控制分别按当前 CPU 广告选择。 */
        pin = __readmsr((basic & (1ULL << 55)) != 0ULL ? 0x48DUL : 0x481UL);
        /* ACK-on-exit 必须能保持关闭，未确认中断由来宾正常接受。 */
        exitControls = __readmsr((basic & (1ULL << 55)) != 0ULL ? 0x48FUL : 0x483UL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
    /* 无法在指令执行前拦截异步投递的平台不开放 TF 路径。 */
    return ((pin >> 32) & (NA_INTERRUPT_EXIT | NA_NMI_EXIT)) == (NA_INTERRUPT_EXIT | NA_NMI_EXIT) &&
        (exitControls & (1ULL << 15)) == 0ULL;
}

/* 保守分类保证本方 TF 不跨越会改变特权级或抑制调试异常的指令。 */
static BOOLEAN NaTfOpcode(const UCHAR *Bytes, ULONG Count)
{
    /* 最大架构指令长度是 15；本函数不读取下一物理页。 */
    ULONG at = 0UL;
    /* 前缀只改变普通操作数、地址及字符串语义。 */
    UCHAR op;
    /* LOCK 可能产生独立的总线锁调试原因，暂不作为自有 TF 放行。 */
    while (at < Count && at < 15UL)
    {
        /* 每次先取得已在范围内的一个字节。 */
        op = Bytes[at];
        /* 不允许特殊 LOCK 原因与自己的 BS 混合。 */
        if (op == 0xF0U) { return FALSE; }
        /* 这些前缀本身不会改变 TF、IF、SS 或特权级。 */
        if ((op >= 0x40U && op <= 0x4FU) || op == 0x66U || op == 0x67U || op == 0xF2U || op == 0xF3U ||
            op == 0x26U || op == 0x2EU || op == 0x36U || op == 0x3EU || op == 0x64U || op == 0x65U)
        { ++at; continue; }
        /* 首个操作码不再当作前缀处理。 */
        break;
    }
    /* 不完整前缀或跨越本页的操作码不能猜测。 */
    if (at >= Count || at >= 15UL) { return FALSE; }
    /* 分类从本页实际 backing 读取，不信任前端传来的指令文本。 */
    op = Bytes[at++];
    /* 内存 XCHG 自带总线锁语义，不能因没有 F0 前缀而混入普通 TF。 */
    if (op == 0x86U || op == 0x87U)
    { return at < Count && at < 15UL && (Bytes[at] & 0xC0U) == 0xC0U; }
    /* 普通算术、整数栈、移动、移位、近控制流及 x87 不改变特权级/TF。 */
    if ((op < 0x40U && (op & 7U) <= 5U) || (op >= 0x50U && op <= 0x5FU) ||
        op == 0x63U || (op >= 0x68U && op <= 0x6BU) || (op >= 0x70U && op <= 0x8DU) ||
        (op >= 0x90U && op <= 0x99U) || op == 0x9BU || op == 0x9CU || op == 0x9EU || op == 0x9FU ||
        (op >= 0xA0U && op <= 0xBFU) || (op >= 0xC0U && op <= 0xC3U) || op == 0xC8U || op == 0xC9U ||
        (op >= 0xD0U && op <= 0xD3U) || op == 0xD7U || (op >= 0xD8U && op <= 0xDFU) ||
        (op >= 0xE0U && op <= 0xE3U) || op == 0xE8U || op == 0xE9U || op == 0xEBU ||
        (op >= 0xF5U && op <= 0xF9U) || op == 0xFCU || op == 0xFDU) { return TRUE; }
    /* VEX/EVEX 类只开放具有完整前缀及操作码的普通向量编码。 */
    if (op == 0xC5U) { return Count - at >= 2UL; }
    /* 三字节 VEX 和四字节 EVEX 的不足部分不向外读取。 */
    if (op == 0xC4U || op == 0x62U) { return Count - at >= (op == 0xC4U ? 3UL : 4UL); }
    /* 这些组中只开放普通近跳转/调用、入栈、移动、增减。 */
    if (op == 0x8FU || op == 0xC6U || op == 0xC7U || op == 0xFEU || op == 0xFFU)
    {
        /* ModRM 必须实际存在；C7 /7 的 XBEGIN 不允许。 */
        ULONG group;
        /* 不把跨页字节当作零。 */
        if (at >= Count || at >= 15UL) { return FALSE; }
        /* 只分类实际编码的组选择位。 */
        group = (Bytes[at] >> 3) & 7UL;
        /* FF /3、/5 为远控制流，不能借近调用路径放行。 */
        return op == 0xFFU ? (group == 0UL || group == 1UL || group == 2UL || group == 4UL || group == 6UL) :
            (op == 0xFEU ? group <= 1UL : group == 0UL);
    }
    /* 系统指令、MOV/POP SS、POPF、IRET、INT/ICEBP 均不在白名单。 */
    if (op != 0x0FU || at >= Count || at >= 15UL) { return FALSE; }
    /* 扩展操作码仍只读取已锁定的本页字节。 */
    op = Bytes[at];
    /* 普通 SSE、条件移动/跳转/置位、位操作及整数扩展。 */
    return (op >= 0x10U && op <= 0x17U) || op == 0x1FU || (op >= 0x28U && op <= 0x2FU) ||
        (op >= 0x40U && op <= 0x76U) || op == 0x7EU || op == 0x7FU || (op >= 0x80U && op <= 0x9FU) ||
        op == 0xA3U || op == 0xA4U || op == 0xA5U || op == 0xABU || op == 0xACU || op == 0xADU || op == 0xAFU ||
        op == 0xB0U || op == 0xB1U || op == 0xB3U || op == 0xB6U || op == 0xB7U || (op >= 0xBAU && op <= 0xBFU) ||
        op == 0xC0U || op == 0xC1U || (op >= 0xC8U && op <= 0xCFU) || (op >= 0xD0U && op <= 0xFEU);
}

/* 指令读取仅使用预先建立的只读、不可执行系统映射。 */
static BOOLEAN NaTfInstruction(VOID)
{
    /* GPA 对应当前真实 EPT 取指退出。 */
    ULONGLONG physical = 0ULL;
    /* 不能凭 RIP 猜测 backing。 */
    ULONG count = g_KswordNoAttach.PinCount;
    /* pin 先写入全部字段，再发布数量。 */
    KeMemoryBarrier();
    /* 防御未初始化或超预算状态。 */
    if (count > KSW_NA_MAX_PINS || !NaBoundaryRead(0x2400UL, &physical)) { return FALSE; }
    /* 数量有明确的会话上限。 */
    for (ULONG i = 0UL; i < count; ++i)
    {
        /* 不读取 MDL，root 只使用已发布的固定映射。 */
        const KSW_NA_PIN *pin = &g_KswordNoAttach.Pins[i];
        /* 物理别名也必须检查真正将执行的相同 backing。 */
        if (pin->Physical == (physical & ~0xFFFULL) && pin->Mapping != NULL)
        {
            /* 本次读取绝不跨出已锁定物理页。 */
            ULONG offset = (ULONG)(physical & 0xFFFULL);
            /* 不在 root 页表中解引用目标用户 VA。 */
            return NaTfOpcode((const UCHAR *)pin->Mapping + offset,
                PAGE_SIZE - offset > 15UL ? 15UL : PAGE_SIZE - offset);
        }
    }
    /* 未锁定的代码不进行推测性 TF 放行。 */
    return FALSE;
}

BOOLEAN KswordARKHvmNoAttachTfDisarm(KSW_HVM_RESIDENT_VCPU *Context)
{
    /* MTF 路径及未武装处理器没有待恢复字段。 */
    ULONGLONG flags = 0ULL, pending = 0ULL;
    /* 已退休状态保持幂等。 */
    if (!Context->NoAttachTfArmed) { return TRUE; }
    /* 算术等正常指令改变的其它标志必须保留。 */
    if (!NaBoundaryRead(0x6820UL, &flags) || !NaBoundaryRead(0x6822UL, &pending)) { return FALSE; }
    /* 武装前已确认没有原 TF 或 pending debug；这里只清本方 BS。 */
    if (KswordARKHvmVmcsFieldStore(0x6820UL, (SIZE_T)(flags & ~NA_TF)) != 0U ||
        KswordARKHvmVmcsFieldStore(0x6822UL, (SIZE_T)(pending & ~(1ULL << 14))) != 0U ||
        KswordARKHvmVmcsFieldStore(0x4004UL, (SIZE_T)Context->NoAttachTfBitmap) != 0U ||
        KswordARKHvmVmcsFieldStore(0x4000UL, (SIZE_T)Context->NoAttachTfPin) != 0U) { return FALSE; }
    /* 所有原控制恢复以后才解除责任。 */
    Context->NoAttachTfArmed = FALSE;
    /* 不写来宾 DR、IF、内存、代码或中断栈。 */
    return TRUE;
}

BOOLEAN KswordARKHvmNoAttachTfEnable(KSW_HVM_RESIDENT_VCPU *Context, BOOLEAN Enable)
{
    /* 关闭与任何其它退出共用同一条恢复路径。 */
    ULONGLONG pin = 0ULL, bitmap = 0ULL, flags = 0ULL, exits = 0ULL;
    /* 事件投递边界不得夹带本方 TF。 */
    ULONGLONG entry = 0ULL, vectoring = 0ULL, pending = 0ULL, blocking = 0ULL, dr7 = 0ULL, debug = 0ULL;
    /* 不把恢复请求误当成重新武装。 */
    if (!Enable) { return KswordARKHvmNoAttachTfDisarm(Context); }
    /* 这一次武装的语义错误必须与既有处理器状态分别记录。 */
    Context->LastStatus = STATUS_SUCCESS;
    /* 同一处理器不能叠加两个临时边界。 */
    if (Context->NoAttachTfArmed) { Context->LastStatus = STATUS_INVALID_DEVICE_STATE; return FALSE; }
    /* 指令拒绝没有修改 TF，可以保持原停点或交还普通运行。 */
    if (!NaTfInstruction()) { g_KswordNoAttach.TfArmStage = 200UL; Context->LastStatus = STATUS_NOT_SUPPORTED; return FALSE; }
    /* 在任何修改之前取得完整恢复文档。 */
    if (!NaBoundaryRead(0x4000UL, &pin) || !NaBoundaryRead(0x4004UL, &bitmap) || !NaBoundaryRead(0x6820UL, &flags) ||
        !NaBoundaryRead(0x400CUL, &exits) || !NaBoundaryRead(0x4016UL, &entry) || !NaBoundaryRead(0x4408UL, &vectoring) ||
        !NaBoundaryRead(0x6822UL, &pending) || !NaBoundaryRead(0x4824UL, &blocking) || !NaBoundaryRead(0x681AUL, &dr7) ||
        !NaBoundaryRead(0x2802UL, &debug)) { Context->LastStatus = STATUS_HV_OPERATION_FAILED; return FALSE; }
    /* 记录的每个字段都来自刚才同一次真实 VMCS 读取。 */
    g_KswordNoAttach.TfBoundary[0] = pin; g_KswordNoAttach.TfBoundary[1] = exits;
    /* 投递信息与 pending debug 是独立条件。 */
    g_KswordNoAttach.TfBoundary[2] = entry; g_KswordNoAttach.TfBoundary[3] = vectoring;
    /* 不从零寄存器值推断没有阻塞。 */
    g_KswordNoAttach.TfBoundary[4] = pending; g_KswordNoAttach.TfBoundary[5] = blocking;
    /* 原始 TF、DR 和分支跟踪分别记录。 */
    g_KswordNoAttach.TfBoundary[6] = flags; g_KswordNoAttach.TfBoundary[7] = dr7; g_KswordNoAttach.TfBoundary[8] = debug;
    /* 原 TF、DR/GD、BTF、投递窗口和自动 ACK 都不被此模式接管。 */
    if ((pin & NA_NMI_EXIT) == 0ULL || (exits & (1ULL << 15)) != 0ULL || (flags & NA_TF) != 0ULL ||
        (entry & 0x80000000ULL) != 0ULL || (vectoring & 0x80000000ULL) != 0ULL || pending != 0ULL || blocking != 0ULL ||
        (dr7 & 0x20FFULL) != 0ULL || (debug & 2ULL) != 0ULL)
    { g_KswordNoAttach.TfArmStage = 203UL; Context->LastStatus = STATUS_NOT_SUPPORTED; return FALSE; }
    /* 先保存恢复责任，部分 VMWRITE 失败也不能遗留 TF。 */
    Context->NoAttachTfPin = pin; Context->NoAttachTfBitmap = bitmap; Context->NoAttachTfArmed = TRUE;
    /* 异步中断和同步异常均先退出，恢复 TF 后才允许原事件进入来宾。 */
    if (KswordARKHvmVmcsFieldStore(0x4000UL, (SIZE_T)(pin | NA_INTERRUPT_EXIT)) != 0U ||
        KswordARKHvmVmcsFieldStore(0x4004UL, 0xFFFFFFFFUL) != 0U ||
        KswordARKHvmVmcsFieldStore(0x6820UL, (SIZE_T)(flags | NA_TF)) != 0U)
    { Context->LastStatus = STATUS_HV_OPERATION_FAILED; (void)KswordARKHvmNoAttachTfDisarm(Context); return FALSE; }
    /* 下一次退出必须先退休这次处理器本地放行。 */
    g_KswordNoAttach.TfArmStage = 204UL;
    /* 审计不等于执行完成，后续仍须真实退出。 */
    return TRUE;
}

BOOLEAN KswordARKHvmNoAttachTfRetire(KSW_HVM_RESIDENT_VCPU *Context, ULONG *Reason,
    ULONGLONG Qualification, BOOLEAN *Forwarded)
{
    /* 不从普通 MTF 退出推断 TF 所有权。 */
    ULONGLONG info = 0ULL, error = 0ULL, length = 0ULL;
    /* 默认让既有处理者继续处理无关退出。 */
    *Forwarded = FALSE;
    /* 未武装时完全不访问新的 VMCS 字段。 */
    if (!Context->NoAttachTfArmed) { return TRUE; }
    /* 每次退休只记录实际退出，不将 ACK 计为完成。 */
    g_KswordNoAttach.TfExitReason = *Reason; g_KswordNoAttach.TfExitQualification = Qualification;
    /* 非异常退出不能保留上一次 #DB 的描述符冒充当前证据。 */
    g_KswordNoAttach.TfExitInfo = 0ULL;
    /* 所有路径均先归还本方 TF 与临时拦截。 */
    if (!KswordARKHvmNoAttachTfDisarm(Context)) { return FALSE; }
    /* ACK 关闭时中断仍待接收；VMRESUME 后由来宾正常投递。 */
    if (*Reason == 1UL) { *Forwarded = TRUE; return TRUE; }
    /* CPUID 等指令退出仍由既有模拟路径处理，不能冒充单步完成。 */
    if (*Reason != 0UL) { return TRUE; }
    /* 退出描述符必须由硬件明确标记有效。 */
    if (!NaBoundaryRead(0x4404UL, &info) || (info & 0x80000000ULL) == 0ULL) { return FALSE; }
    /* 区分真实 #DB、NMI 和其它异常。 */
    g_KswordNoAttach.TfExitInfo = info;
    /* NMI 在 TF 已恢复后交回已有的 NMI 记账和投递。 */
    if (((info >> 8) & 7ULL) == 2ULL) { return TRUE; }
    /* 只有纯自有 BS、硬件 #DB 才作为本次执行边界完成。 */
    if ((info & 0x7FFULL) == 0x301ULL && Qualification == (1ULL << 14))
    { *Reason = 37UL; return TRUE; }
    /* 真实异常按原描述符重新投递，不能被私有单步吞掉。 */
    if ((info & (1ULL << 11)) != 0ULL && !NaBoundaryRead(0x4406UL, &error)) { return FALSE; }
    /* 软件异常投递需要硬件报告的指令长度。 */
    if (((info >> 8) & 7ULL) >= 4ULL && !NaBoundaryRead(0x440CUL, &length)) { return FALSE; }
    /* 被拦截的页故障尚未写 CR2，必须保留真实故障地址。 */
    if ((info & 0xFFULL) == 14ULL) { __writecr2(Qualification); }
    /* 外部 #DB 的状态按 Intel 的退出资格还原，不把它变成自有 BS。 */
    if ((info & 0x7FFULL) == 0x301ULL)
    {
        /* VM-exit 本身不会替来宾更新 DR6。 */
        ULONGLONG dr6 = __readdr(6), dr7 = 0ULL, debug = 0ULL;
        /* 保留保留位，并准确还原实际调试原因和 RTM 的相反极性。 */
        dr6 = (dr6 & ~0x1E00FULL) | (Qualification & 0xE00FULL) | ((Qualification & 0x10000ULL) == 0ULL ? 0x10000ULL : 0ULL);
        /* 未消费的真实异常原因必须对 Windows 可见。 */
        __writedr(6, (ULONG_PTR)dr6);
        /* 硬件 #DB 的普通状态变化也不能遗漏。 */
        if (!NaBoundaryRead(0x681AUL, &dr7) || !NaBoundaryRead(0x2802UL, &debug) ||
            KswordARKHvmVmcsFieldStore(0x681AUL, (SIZE_T)(dr7 & ~0x2000ULL)) != 0U ||
            KswordARKHvmVmcsFieldStore(0x2802UL, (SIZE_T)(debug & ~3ULL)) != 0U) { return FALSE; }
    }
    /* 不复制仅属于 VM-exit 的 NMI-unblocking 等保留位。 */
    if (KswordARKHvmVmcsFieldStore(0x4018UL, (SIZE_T)error) != 0U ||
        KswordARKHvmVmcsFieldStore(0x401AUL, (SIZE_T)length) != 0U ||
        KswordARKHvmVmcsFieldStore(0x4016UL, (SIZE_T)(info & 0x80000FFFULL)) != 0U) { return FALSE; }
    /* 当前事件已真实重新投递，不再交给假定 exception bitmap 为零的通用分支。 */
    *Forwarded = TRUE;
    /* 不提前增加 RIP，不制造合成的调试事件。 */
    return TRUE;
}
