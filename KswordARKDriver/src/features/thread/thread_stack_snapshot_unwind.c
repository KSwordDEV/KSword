#include "thread_stack_snapshot.h" // 在私有副本上原生展开，不访问目标活动栈。
#include <ntimage.h> // 使用 WDK 的 PE 静态展开表定义，不复制内部 ABI 结构。

typedef PIMAGE_RUNTIME_FUNCTION_ENTRY(NTAPI* KSW_SAVED_LOOKUP)(ULONG64, PULONG64, PVOID); // 最后一项为可选缓存，本实现始终传空。
typedef PEXCEPTION_ROUTINE(NTAPI* KSW_SAVED_UNWIND)(ULONG, ULONG64, ULONG64, PIMAGE_RUNTIME_FUNCTION_ENTRY, PCONTEXT, PVOID*, PULONG64, PVOID); // 最后一项为可选非易失指针输出，本实现始终传空。

static PVOID KswUnwindResolve(PCWSTR Name) // 只允许本文件固定的两个系统导出名称。
{ // 此函数只在被动级执行。
    UNICODE_STRING name; // 保存常量名称。
    RtlInitUnicodeString(&name, Name); // 不接受用户给出的函数名称或地址。
    return MmGetSystemRoutineAddress(&name); // 导出缺失时不改用私有例程。
} // 结束公开导出查询。

static ULONG64 KswUnwindRelocate(ULONG64 Value, ULONG64 Original, ULONG64 End, ULONG64 Copy) // 将原栈范围内的指针映射到独立副本。
{ // 只改变副本地址，不修改目标栈内容。
    return Value >= Original && Value <= End ? Copy + (Value - Original) : Value; // 范围外的代码和用户态地址原样保留。
} // 地址映射不是返回地址候选扫描。

VOID KswSavedStackUnwind(KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE* Output, UCHAR* Bytes, ULONG64 SavedRbp) // 输入已完整复制的真实保存栈。
{ // 不在 DPC 内调用元数据查询、异常展开或符号处理。
    CONTEXT context; // 与精确切换帧一致的原始寄存器起点。
    CONTEXT checked; // 有界元数据模拟得到的预期控制上下文，用于核对系统原生展开。
    KSW_SAVED_LOOKUP lookup; // 系统常驻映像的原生元数据查询。
    KSW_SAVED_UNWIND unwind; // 不执行语言异常处理器的原生虚拟展开。
    ULONG offset; // 有界栈副本中的八字节槽。
    ULONG64 value; // 单个副本槽位的地址重定位值。
    ULONG64 copy = (ULONG64)(ULONG_PTR)Bytes; // 本次请求拥有的非分页地址。
    ULONG64 end = copy + Output->snapshotByteCount; // 副本的排他上界。
    ULONG64 original = Output->savedKernelStack; // 与副本第零字节一一对应的原始地址。
    ULONG64 lastRsp; // 防止元数据错误导致栈指针不推进。
    ULONG64 lastRip; // 记录单步前的真实指令地址。
    ULONG64 image; // 系统展开表查询返回的映像基址。
    ULONG64 establisher; // 原生展开器输出，不作为额外返回地址。
    PVOID handlerData; // 不调用处理器，只接收原生 API 必需输出。
    PIMAGE_RUNTIME_FUNCTION_ENTRY function; // 只信任精确常驻 NT 映像内的静态展开表。
    BOOLEAN boundary = FALSE; // 只有真实机器帧恢复用户 CS/RIP/RSP 才能设为真。
    ULONG machineCs = 0UL; // 本帧真实硬件保存的权限段；普通函数返回保持为零。
    RtlZeroMemory(&context, sizeof(context)); // 不使用未初始化寄存器产生栈地址。
    Output->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_METADATA; // 没有展开器时不能声称完整。
    lookup = (KSW_SAVED_LOOKUP)KswUnwindResolve(L"RtlLookupFunctionEntry"); // 只解析命名系统导出。
    unwind = (KSW_SAVED_UNWIND)KswUnwindResolve(L"RtlVirtualUnwind"); // 不使用扫描或手工猜测替代元数据展开。
    if (lookup == NULL || unwind == NULL || Output->snapshotByteCount > KSW_SAVED_STACK_BYTES || Output->snapshotByteCount < 0x180UL) // 固定副本边界必须可信。
    { // 开始展开前拒绝。
        Output->capture.status = STATUS_PROCEDURE_NOT_FOUND; // 保留失败，不伪造成功空栈。
        return; // 不读取副本外地址。
    } // 结束展开能力与副本边界检查。
    for (offset = 0UL; offset + sizeof(value) <= Output->snapshotByteCount; offset += (ULONG)sizeof(value)) // 仅重定位副本内指向同一原栈的地址。
    { // 此循环不挑选、输出或排序任何帧；帧只能由下方原生展开器产生。
        RtlCopyMemory(&value, Bytes + offset, sizeof(value)); // 使用对齐无关的本地读取。
        value = KswUnwindRelocate(value, original, Output->stackHigh, copy); // 保存的 RBP/RSP 等指针必须继续指向副本。
        RtlCopyMemory(Bytes + offset, &value, sizeof(value)); // 绝不写回真实目标栈。
    } // 结束私有副本地址重定位。
    context.ContextFlags = CONTEXT_FULL; // 为系统展开器提供完整的控制与非易失寄存器容器。
    context.Rip = Output->initialInstructionPointer; // 从真实保存帧读取，不构造函数地址冒充帧。
    context.Rsp = copy + (Output->initialStackPointer - original); // 起点与同一保存帧严格对应。
    context.Rbp = KswUnwindRelocate(SavedRbp, original, Output->stackHigh, copy); // KiSwapContext 的保存 RBP 来自精确槽位。
    context.SegCs = 0x10U; // 初始指令必须位于已验证内核函数。
    context.SegSs = 0x18U; // 初始栈为内核数据段，不默认用户边界。
    __try // 本地元数据或展开异常只截断本次结果，不扫描内存补链。
    { // 原生调用均在 PASSIVE_LEVEL 进行。
        for (;;) // 每轮必须消费一帧或明确停止。
        { // 开始单步元数据展开。
            if (context.Rip < (ULONG64)(ULONG_PTR)MmSystemRangeStart) // 原生展开器恢复到了低半区。
            { // 还必须有用户态段和有效用户栈才能接受完整边界。
                boundary = context.Rip >= 0x1000ULL && context.Rip < 0x0000800000000000ULL && context.Rsp >= 0x1000ULL && context.Rsp < 0x0000800000000000ULL && (machineCs & 3U) == 3U; // 单凭一个低地址不算完成。
                Output->unwindStop = boundary ? KSWORD_ARK_STACK_SNAPSHOT_STOP_USER : KSWORD_ARK_STACK_SNAPSHOT_STOP_RANGE; // 错误空地址保持部分结果。
                break; // 不输出用户地址作为内核帧。
            } // 结束真实用户边界检查。
            if (Output->capture.frameCount == Output->capture.frameLimit) // 此时已有实际下一 RIP，才证明帧预算截断。
            { // 开始预算截断。
                Output->capture.flags |= KSWORD_ARK_THREAD_STACK_FLAG_FRAME_LIMIT; // 不补零或复用最后一帧。
                Output->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_LIMIT; // 明确区分预算和元数据缺失。
                break; // 帧数始终不超过协议上限。
            } // 结束帧预算检查。
            Output->capture.frames[Output->capture.frameCount++] = context.Rip; // 唯一帧来源是起点或上轮原生展开输出。
            if (context.Rip < Output->kernelImageBase || context.Rip - Output->kernelImageBase >= Output->kernelImageSize) // 非 NT 映像可能卸载，未建立其元数据引用前不能使用。
            { // 开始不受支持模块元数据截断。
                Output->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_METADATA; // 已取得的真实返回地址仍保留。
                break; // 不使用后来重新映射的模块元数据猜测原始链。
            } // 结束常驻元数据范围检查。
            context.Rsp = KswUnwindRelocate(context.Rsp, original, Output->stackHigh, copy); // 机器帧恢复的栈指针也归一到副本。
            context.Rbp = KswUnwindRelocate(context.Rbp, original, Output->stackHigh, copy); // 保留原生帧指针的同一地址语义。
            if (context.Rsp < copy || context.Rsp > end - sizeof(ULONG64)) // 不允许原生展开器读取真实目标栈或副本外地址。
            { // 开始复制范围截断。
                Output->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_RANGE; // 没有完整输入就不宣称完整展开。
                break; // 不尝试换入或追加远端页。
            } // 结束本轮栈指针范围检查。
            lastRsp = context.Rsp; // 保存严格推进基准。
            lastRip = context.Rip; // 保存原生调用的真实控制位置。
            image = 0ULL; // 不沿用上一映像的归属。
            function = lookup(context.Rip, &image, NULL); // 不依赖 WDK 未公开的历史缓存类型。
            if (function == NULL) // x64 无展开项的真正叶函数按 ABI 弹出一个实际保存返回地址。
            { // 不做候选地址扫描。
                RtlCopyMemory(&context.Rip, (const VOID*)(ULONG_PTR)context.Rsp, sizeof(context.Rip)); // 只读当前 RSP 指定的那个返回槽。
                context.Rsp += sizeof(ULONG64); // 叶返回消费固定八字节。
            } // 结束 ABI 叶函数处理。
            else // 非叶函数必须使用精确常驻 NT 的原生元数据。
            { // 不调用语言处理器或执行目标代码。
                if (image != Output->kernelImageBase || function->BeginAddress >= function->EndAddress || function->EndAddress > Output->kernelImageSize || function->UnwindData >= Output->kernelImageSize) // 拒绝错误归属或越界元数据。
                { // 开始展开表拒绝。
                    Output->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_METADATA; // 不把失败解释成已抵达栈底。
                    break; // 保留之前已展开的真实帧。
                } // 结束静态展开表核验。
                handlerData = NULL; // 本轮独立的未执行处理器数据。
                establisher = 0ULL; // 不将此值当作帧地址。
                checked = context; // 先在独立寄存器容器里验证元数据所有保存槽范围。
                machineCs = 0UL; // 不沿用上一帧的硬件权限证据。
                if (!KswSavedStackCheck(image, Output->kernelImageSize, function, &checked, copy, end, &machineCs)) // 不能把异常处理当作任意指针解引用许可。
                { // 没有完整有界读取证明时不调用原生展开器。
                    Output->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_RANGE; // 保留已得到的真实部分链。
                    break; // 不扫描地址或追加目标活动栈页。
                } // 结束原生调用前的范围证明。
                (VOID)unwind(0UL, image, context.Rip, function, &context, &handlerData, &establisher, NULL); // UNW_FLAG_NHANDLER：只计算上下文，不调用异常处理代码。
                if (context.Rip != checked.Rip || context.Rsp != checked.Rsp || context.Rbp != checked.Rbp) // 任何 epilog/未知语义差异均不能凭模拟器推断完整。
                { // 不将模拟结果覆盖为系统结果或继续拼接。
                    Output->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_METADATA; // 明确保留原生与有界解码不一致。
                    break; // 终点仍为真实系统输出，但完整度未知。
                } // 结束控制上下文交叉检查。
            } // 结束单步原生展开。
            if (context.Rip == lastRip || (context.Rsp >= copy && context.Rsp < end && context.Rsp <= lastRsp)) // 内核栈必须向高地址推进。
            { // 开始循环或不推进拒绝。
                Output->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_RANGE; // 不输出重复帧拼接假链。
                break; // 避免无界展开。
            } // 结束推进核验。
        } // 结束有界帧展开。
    } // 结束原生展开异常保护。
    __except (EXCEPTION_EXECUTE_HANDLER) // 只处理本次副本和元数据读取失败。
    { // 不把异常伪装为正常栈底。
        Output->unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_EXCEPTION; // 调用方可明确看到截断原因。
    } // 结束异常分类。
    Output->terminalInstructionPointer = context.Rip; // 保留真实终点，不编造哨兵。
    Output->terminalCodeSegment = machineCs; // 不依赖 RtlVirtualUnwind 未恢复的 CONTEXT.SegCs。
    Output->terminalStackPointer = context.Rsp >= copy && context.Rsp <= end ? original + (context.Rsp - copy) : context.Rsp; // 输出恢复为原始地址空间的数值。
    Output->capture.status = Output->capture.frameCount != 0UL ? STATUS_SUCCESS : STATUS_NOT_FOUND; // 零帧绝不报成功。
    Output->capture.result = Output->capture.frameCount == 0UL ? KSWORD_ARK_THREAD_STACK_RESULT_UNAVAILABLE : boundary ? KSWORD_ARK_STACK_SNAPSHOT_COMPLETE : KSWORD_ARK_THREAD_STACK_RESULT_PARTIAL; // 只有真实用户机器帧才代表本段内核链完整。
    Output->capture.flags |= boundary ? KSWORD_ARK_STACK_SNAPSHOT_USER_BOUNDARY : KSWORD_ARK_THREAD_STACK_FLAG_COMPLETENESS_UNKNOWN; // 不能由返回帧数推断完整性。
} // 原始目标在复制后可继续调度，展开从不再访问它的活动栈。
