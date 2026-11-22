#if defined(KSW_SAVED_STACK_CHECK_USERMODE) // 合成测试只替换编译环境，算法仍直接编译本生产 C 文件。
#include <Windows.h> // 用户态测试不打开驱动，不调用内核地址。
typedef RUNTIME_FUNCTION IMAGE_RUNTIME_FUNCTION_ENTRY; // Windows SDK 对同一 PE 静态记录的公开名称。
#else // 正式驱动始终使用 WDK 和模块私有接口。
#include "thread_stack_snapshot.h" // 原生展开前验证每个保存槽都位于同一独立副本。
#include <ntimage.h> // 静态展开表结构来自 WDK。
#endif // 编译环境分支不改变任何读取或判断语义。

static BOOLEAN KswCheckRead(ULONG64 Low, ULONG64 High, ULONG64 Address, PVOID Destination, SIZE_T Size) // 有界读取只接受完整落在私有副本内的保存槽。
{ // 此处不读目标活动栈，不把 SEH 当作范围检查。
    if (Address < Low || Address > High || Size > High - Address) return FALSE; // 先减后比较，避免加法溢出。
    RtlCopyMemory(Destination, (const VOID*)(ULONG_PTR)Address, Size); // 范围已证明，实际读取不会越过副本。
    return TRUE; // 完整读取才允许继续模拟。
} // 不存在部分读取后补零。

BOOLEAN KswSavedStackCheck(ULONG64 Image, ULONG ImageSize, const VOID* Entry, PCONTEXT Context, ULONG64 Low, ULONG64 High, PULONG MachineCs) // 在私有 CONTEXT 上计算原生展开将读取的全部栈槽。
{ // 该检查器只实现元数据语义，不从数据中挑选候选代码地址。
    IMAGE_RUNTIME_FUNCTION_ENTRY function = *(const IMAGE_RUNTIME_FUNCTION_ENTRY*)Entry; // 初始项已由调用者核对属于常驻 NT 映像。
    ULONG depth; // 链式展开的固定深度预算。
    ULONG index; // 当前展开代码槽索引。
    ULONG slots; // 当前操作实际占用的双字节槽数。
    ULONG count; // 当前元数据中声明的代码槽总数。
    ULONG operation; // x64 展开操作编号。
    ULONG info; // 操作特定的四位寄存器或规模字段。
    ULONG version; // 当前静态展开记录版本。
    ULONG flags; // 当前记录的 CHAININFO 等标志。
    ULONG relative; // 当前控制地址相对函数起点的位置。
    ULONG shortOffset; // 两字节缩放偏移的安全局部值，避免 Windows RPC 的 small 宏。
    ULONG longOffset; // 四字节非缩放偏移的安全局部值。
    ULONG64 frameBase = 0ULL; // 保存槽相对的原始建帧基准，首记录建立后由链父项复用。
    ULONG64 amount; // 经过校验的分配大小或保存偏移。
    ULONG64 registers[16]; // 由输入 CONTEXT 映射的十六个整数寄存器。
    ULONG64 machine[5]; // RIP、CS、RFLAGS、RSP、SS 的完整机器帧。
    const UCHAR* data; // 常驻 NT 映像内的有限元数据记录。
    const UCHAR* code; // 当前双字节展开槽。
    BOOLEAN machineFrame = FALSE; // 只有真实 PUSH_MACHFRAME 操作才能恢复用户边界证据。
    C_ASSERT(FIELD_OFFSET(CONTEXT, R15) - FIELD_OFFSET(CONTEXT, Rax) == 15U * sizeof(ULONG64)); // WDK 寄存器布局必须完全连续。
    RtlCopyMemory(registers, &Context->Rax, sizeof(registers)); // 不把寄存器结构成员当成越界数组访问。
    *MachineCs = 0UL; // 没有机器帧的普通返回绝不自动恢复用户段。
    for (depth = 0UL; depth < 32UL; ++depth) // 元数据损坏或循环链不得造成无界请求。
    { // 当前项以及其完整代码数组都必须位于权威映像范围。
        if (function.UnwindData > ImageSize || ImageSize - function.UnwindData < 4UL) return FALSE; // 不读取映像外的记录头。
        data = (const UCHAR*)(ULONG_PTR)(Image + function.UnwindData); // 地址仅由已验证的 NT RVA 构成。
        version = data[0] & 7U; // x64 静态展开版本。
        flags = data[0] >> 3U; // 高五位才是记录标志。
        count = data[2]; // 所有代码均为双字节槽。
        if ((version != 1UL && version != 2UL) || 4UL + count * 2UL > ImageSize - function.UnwindData) return FALSE; // 不猜未支持版本。
        if (depth == 0UL) frameBase = registers[4]; // 链父项继续使用同一帧的建帧基准。
        if (depth == 0UL && (data[3] & 15U) != 0U) // 有明确帧寄存器时采用其定义的建帧基准。
        { // 在任何原生解引用前先验证帧寄存器。
            amount = (ULONG64)(data[3] >> 4U) * 16ULL; // x64 建帧偏移以十六字节计。
            if (registers[data[3] & 15U] < amount) return FALSE; // 不允许无符号减法回绕。
            frameBase = registers[data[3] & 15U] - amount; // 与原生展开器同义的 FrameBase。
        } // 结束建帧基准计算。
        if (frameBase < Low || frameBase > High) return FALSE; // 错误 RBP 等寄存器不得引导原生读取别处内存。
        relative = Context->Rip >= Image + function.BeginAddress && Context->Rip - Image - function.BeginAddress <= 0xFFFFFFFFULL ? (ULONG)(Context->Rip - Image - function.BeginAddress) : 0xFFFFFFFFUL; // 链父函数通常处于完整序言之后。
        for (index = 0UL; index < count; index += slots) // 每轮严格消费一个完整合法操作。
        { // 槽宽先校验，参数槽不会再次被当成操作码。
            code = data + 4UL + index * 2UL; // 记录内的当前操作。
            operation = code[1] & 15U; // 低四位是操作编号。
            info = code[1] >> 4U; // 高四位是寄存器或规模字段。
            slots = 1UL; // 无附加参数的操作只占一个槽。
            if (operation == 1UL) slots = info == 0UL ? 2UL : 3UL; // ALLOC_LARGE 的两种编码。
            else if (operation == 4UL || operation == 8UL || operation == 6UL) slots = 2UL; // 短保存偏移及第二版成对 epilog 描述。
            else if (operation == 5UL || operation == 9UL) slots = 3UL; // 长保存偏移。
            if (slots > count - index || operation == 7UL || operation > 10UL || (operation == 1UL && info > 1UL) || (operation == 6UL && version != 2UL)) return FALSE; // 不越界读取参数或执行保留操作。
            if (relative < code[0] || operation == 6UL) continue; // 序言尚未执行的操作以及 epilog 描述不改变还原寄存器。
            amount = 0ULL; // 每轮清除旧参数值。
            shortOffset = 0UL; // 两字节参数采用安全复制，避免未对齐读取。
            longOffset = 0UL; // 长参数也不使用未对齐类型解引用。
            if (slots == 2UL) RtlCopyMemory(&shortOffset, code + 2UL, sizeof(USHORT)); // 先前已证明存在第二个槽。
            if (slots == 3UL) RtlCopyMemory(&longOffset, code + 2UL, sizeof(longOffset)); // 先前已证明存在完整双参数槽。
            switch (operation) // 只模拟 ABI 规定的固定寄存器/栈操作。
            { // 所有栈读取统一经过有限副本检查。
            case 0UL: // PUSH_NONVOL 对应从当前 RSP 恢复指定整数寄存器。
                if (!KswCheckRead(Low, High, registers[4], &registers[info], sizeof(ULONG64))) return FALSE; // 不读活动目标栈。
                registers[4] += 8ULL; // 消费真实保存槽。
                break; // 结束单个寄存器恢复。
            case 1UL: // ALLOC_LARGE 只还原原有栈分配。
                amount = info == 0UL ? (ULONG64)shortOffset * 8ULL : longOffset; // 短编码按八字节缩放。
                if (amount > High - registers[4]) return FALSE; // 原生展开后的 RSP 不得越过副本。
                registers[4] += amount; // 不读取分配区作为帧。
                break; // 结束大块分配撤销。
            case 2UL: // ALLOC_SMALL 还原固定小块栈分配。
                amount = (ULONG64)info * 8ULL + 8ULL; // x64 固定缩放定义。
                if (amount > High - registers[4]) return FALSE; // 不发生无符号越界。
                registers[4] += amount; // 只推进栈指针。
                break; // 结束小块分配撤销。
            case 3UL: // SET_FPREG 使用已校验的固定建帧基准。
                registers[4] = frameBase; // 不读取任意帧指针指向的外部内存。
                break; // 结束帧寄存器还原。
            case 4UL: // SAVE_NONVOL 的短八字节缩放偏移。
            case 5UL: // SAVE_NONVOL_FAR 的长非缩放偏移。
                amount = operation == 4UL ? (ULONG64)shortOffset * 8ULL : longOffset; // 参数只来自常驻 NT 元数据。
                if (amount > High - frameBase || !KswCheckRead(Low, High, frameBase + amount, &registers[info], sizeof(ULONG64))) return FALSE; // 恢复值也只能来自同一副本。
                break; // 结束非易失整数槽检查。
            case 8UL: // SAVE_XMM128 的短十六字节缩放偏移。
            case 9UL: // SAVE_XMM128_FAR 的长非缩放偏移。
                amount = operation == 8UL ? (ULONG64)shortOffset * 16ULL : longOffset; // 只证明原生向量恢复的读取范围。
                if (amount > High - frameBase || High - frameBase - amount < 16ULL) return FALSE; // 不必为地址链投影复制向量值。
                break; // 结束非易失向量槽范围证明。
            case 10UL: // PUSH_MACHFRAME 必须读取真实的五槽硬件帧。
                if (info > 1UL || !KswCheckRead(Low, High, registers[4] + (ULONG64)info * 8ULL, machine, sizeof(machine))) return FALSE; // 有错误码时只跳过那个明确槽。
                Context->Rip = machine[0]; // 真实硬件保存的返回控制位置。
                registers[4] = machine[3]; // 真实硬件保存的调用方 RSP。
                *MachineCs = (ULONG)machine[1]; // 只有此来源才提供用户权限级证据。
                machineFrame = TRUE; // 本轮禁止再模拟普通 ret。
                break; // 结束机器帧恢复。
            default: // 保留、未知或被跳过逻辑以外的操作均不能继续。
                return FALSE; // 不把未知元数据当作零分配。
            } // 结束当前操作模拟。
            if (!machineFrame && (registers[4] < Low || registers[4] > High)) return FALSE; // 每一步都必须保持可读的副本栈指针。
        } // 结束当前记录的所有展开代码。
        if ((flags & 4UL) == 0UL) break; // 没有 CHAININFO 时到达本帧主记录。
        amount = 4ULL + ((count + 1UL) & ~1UL) * 2ULL; // 链父项按四字节对齐位于代码数组之后。
        if (amount > ImageSize - function.UnwindData || sizeof(function) > ImageSize - function.UnwindData - amount) return FALSE; // 链项也必须完整落在同一权威映像。
        RtlCopyMemory(&function, data + (SIZE_T)amount, sizeof(function)); // 父项仅描述元数据，不执行代码。
    } // 结束固定深度链展开。
    if (depth == 32UL) return FALSE; // 循环链或过深元数据拒绝，不能挂住驱动。
    if (!machineFrame) // 普通帧只消费当前 RSP 指定的一个实际返回槽。
    { // 绝不扫描栈内容寻找看似合理的代码地址。
        if (!KswCheckRead(Low, High, registers[4], &Context->Rip, sizeof(Context->Rip))) return FALSE; // 只允许副本内的明确返回槽。
        registers[4] += 8ULL; // 普通 ret 的真实八字节消费。
    } // 机器帧已直接恢复 RIP/RSP，不再弹出返回地址。
    RtlCopyMemory(&Context->Rax, registers, sizeof(registers)); // 输出只用于与原生展开结果交叉比较。
    return TRUE; // 此时原生所需保存槽已经全部验证。
} // 检查失败时不调用可能越界的原生展开器。
