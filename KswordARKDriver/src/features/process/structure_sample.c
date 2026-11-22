// 仅采样有界根对象正文，不跟随指针，不写入、附加、注册回调或保留后台状态。
#include <ntifs.h> // 在使用 ntddk 的头文件之前声明进程、线程引用查询和访问器。
#include "structure_sample_profiles.h" // 根范围仅来自精确身份匹配的不可变内置配置。
#include "../../platform/runtime_signature_scan.h" // 所有现场正文读取都复用完整复制语义的 MmCopyMemory 包装。

// 通过命名 NT 导出取得创建身份，不使用调用方提供的成员偏移。
NTKERNELAPI LONGLONG NTAPI // 导出返回已引用进程的精确创建时间。
PsGetProcessCreateTimeQuadPart( // 声明现有内核导出的调用约定。
    _In_ PEPROCESS Process // 输入生命周期已受引用保护的进程对象。
    ); // 此声明不新增私有内核布局依赖。
NTKERNELAPI PEPROCESS NTAPI // 导出返回线程所属的进程对象身份。
PsGetThreadProcess( // 声明现有内核导出的调用约定。
    _In_ PETHREAD Thread // 输入生命周期已受引用保护的线程对象。
    ); // 此声明不读取调用方指定的地址。

// 对第一版通信布局进行编译期检查，防止打包方式或 Windows 类型位宽意外变化。
C_ASSERT(sizeof(KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST) == 48U); // 用户态和驱动必须使用同一固定请求长度。
C_ASSERT(sizeof(KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID) == 40U); // GUID 为原始字节，不包含隐含指针字段。
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE, valid) == 128U); // 固定响应头后紧接有效位图。
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE, bytes) == 1152U); // 逐字节有效位图之后是正文数据。
C_ASSERT(sizeof(KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE) == 9344U); // 不允许调用方选择可变复制范围。

// 功能：校验身份请求；输入为栈上快照，输出布尔结果，不访问目标对象。
static BOOLEAN // 表示请求是否满足第一版身份约束。
KswStructureRequestValid( // 解析根范围或访问对象之前调用。
    const KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST* Request // 输入只包含预期对象身份，不含地址。
    ) // 调用方拥有完整且稳定的请求副本。
{ // 未来标志或扩展必须通过显式协议版本启用。
    ULONG index; // 遍历固定的四个保留字段。
    if (Request->version != KSWORD_ARK_STRUCTURE_SAMPLE_VERSION || // 未知通信布局不能复用当前协议。
        Request->processId == 0UL || // 所属进程 PID 必须有效。
        Request->processCreationTime100ns == 0ULL) // 必须能够检测 PID 复用。
    { // 创建身份的初次发现由已有详情或枚举接口承担。
        return FALSE; // 拒绝缺少稳定进程身份的请求。
    } // 所属进程已具有冻结的预期身份。
    for (index = 0UL; index < RTL_NUMBER_OF(Request->reserved); ++index) // 不接受未定义的调用方控制行为。
    { // 逐个校验第一版协议保留字段。
        if (Request->reserved[index] != 0UL) // 非零保留值不能解释成配置或成员偏移。
        { // 未知输入不能静默改变读取语义。
            return FALSE; // 拒绝未定义字段，不进行猜测。
        } // 当前保留字段符合第一版协议。
    } // 所有保留字段均已确认置零。
    if (Request->objectType == KSWORD_ARK_STRUCTURE_SAMPLE_EPROCESS) // 进程快照不携带线程身份。
    { // 防止一个请求混入两种对象身份而产生歧义。
        return Request->threadId == 0UL && // 进程快照的线程 ID 必须为零。
            Request->threadCreationTime100ns == 0ULL; // 进程快照的线程创建时间必须为零。
    } // 剩余可接受类型仅为线程根对象。
    return Request->objectType == KSWORD_ARK_STRUCTURE_SAMPLE_ETHREAD && // 不允许任意根类型或内嵌类型选择值。
        Request->threadId != 0UL && // 必须提供非零线程 ID。
        Request->threadCreationTime100ns != 0ULL; // 同时冻结线程及所属进程的创建身份。
} // 请求校验本身不读取内核对象正文。

// 功能：标记完整复制的范围；输入为已验证范围，输出更新有效位图和字节计数。
static VOID // 此辅助函数只更新响应缓冲区，不读取目标内存。
KswStructureMarkCopied( // 调用方已确认范围位于精确根类型之内。
    KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE* Response, // 当前请求拥有的固定响应。
    ULONG Offset, // 已成功复制范围的根内起始偏移。
    ULONG Count // 已完整复制的范围字节数。
    ) // 调用方保证各次标记的复制范围互不重叠。
{ // 即使实际读取粒度较大，有效位图仍精确到每个字节。
    ULONG index; // 下标受内置根范围约束，不单独依赖输出容量。
    for (index = Offset; index < Offset + Count; ++index) // 不会设置 [0, rootSize) 之外的有效位。
    { // 最低有效位表示最低地址处的对应字节。
        Response->valid[index >> 3U] |= (UCHAR)(1UL << (index & 7UL)); // 仅将完整复制的字节标记为可用。
    } // 解码方不会把未读区域的填充零当成真实零值。
    Response->bytesCopied += Count; // 范围互不重叠，此值同时等于有效位的置位总数。
} // 父结构或联合体行不会增加复制字节计数。

// 功能：安全复制精确根正文；输入为已引用对象和响应，输出正文、有效位及读取状态。
static VOID // 读取失败通过响应字段返回，不改写任何目标状态。
KswStructureCopyBody( // 调用期间由上层保持进程和线程引用有效。
    const VOID* Object, // 只能来自已验证引用的根对象地址。
    KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE* Response // 内含由编译配置授权的精确根大小。
    ) // 只读取 [对象基址, 对象基址 + 精确符号 sizeof) 范围。
{ // 优先按六十四字节读取，降低开销且绝不越过根正文末端。
    ULONG offset; // 当前互不重叠正文块的起始偏移。
    for (offset = 0UL; offset < Response->rootSize; offset += 64UL) // 协议容量最多对应一百二十八次主读取。
    { // 每次读取都单独截断到精确根对象末端。
        ULONG count = min(64UL, Response->rootSize - offset); // 最后一块不能进入相邻分配。
        ULONG sub; // 大块复制失败后使用八字节粒度保留仍可读的存储。
        if (KswordARKRuntimeReadMemory( // 所有现场读取都通过共享的 MmCopyMemory 包装。
            (const UCHAR*)Object + offset, // 源地址始终在已授权根范围内。
            Response->bytes + offset, // 目标是当前固定响应内的对应区域。
            count)) // 只有完整复制当前块才算成功。
        { // 主读取成功的块可以独立交给解码方使用。
            KswStructureMarkCopied(Response, offset, count); // 为完整块设置逐字节有效位。
            continue; // 已成功复制的块不再重复采样。
        } // 失败的包装调用可能已写入部分目标数据。
        RtlZeroMemory(Response->bytes + offset, count); // 包装不返回精确部分计数，因此丢弃全部部分数据。
        for (sub = 0UL; sub < count; sub += 8UL) // 回退操作仍严格位于当前根正文块之内。
        { // 对不能整除八的根大小不进行向上取整。
            ULONG small = min(8UL, count - sub); // 当前小块的实际读取长度。
            ULONG at = offset + sub; // 两部分偏移都受内置根大小约束。
            if (KswordARKRuntimeReadMemory( // 继续使用安全读取，不直接解引用或跟随正文中的指针。
                (const UCHAR*)Object + at, // 当前小块的授权源地址。
                Response->bytes + at, // 当前小块在响应内的目标位置。
                small)) // 仅完整复制的小块具备有效性。
            { // 回退读取成功的数据可独立使用。
                KswStructureMarkCopied(Response, at, small); // 仅完整成功的小块贡献有效字节。
            } // 当前小块的成功路径结束。
            else // 部分复制的小块不构成有效字段证据。
            { // 无效输出必须保持确定性的零填充。
                RtlZeroMemory(Response->bytes + at, small); // 清除任何可能已复制的部分数据。
                Response->lastStatus = STATUS_PARTIAL_COPY; // 共享包装仅提供完整成功语义，不能还原原生失败状态。
            } // 不可读区域不影响继续采样独立的其他正文存储。
        } // 当前主块的每个字节都已标记有效或清零。
    } // 没有读取引用对象 rootSize 位置及其之后的任何字节。
} // 对象引用只保护生命周期，不暗示正文内容的一致性。

// 功能：按冻结身份返回固定采样回执；只有无效内部指针才作为传输错误返回。
NTSTATUS // 对象级拒绝及部分读取结果保存在响应中。
KswordARKQueryStructureSample( // 不接受驱动全局配置或调用方目标地址。
    const KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST* Request, // 已捕获的纯身份请求。
    KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE* Response // 完整固定的非分页 WDF 输出缓冲区。
    ) // 调用方负责缓冲区生命周期和最终请求完成。
{ // 对象引用和栈上事实均由当前请求独立拥有。
    KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST captured; // 防止 METHOD_BUFFERED 重叠或内部误用导致输入被覆盖。
    const KSW_STRUCTURE_SAMPLE_PROFILE* profile = NULL; // 精确校验运行中内核身份前始终为空。
    PEPROCESS process = NULL; // 仅能由 PsLookupProcessByProcessId 取得实际引用。
    PETHREAD thread = NULL; // 仅能由 PsLookupThreadByThreadId 取得实际引用。
    const VOID* object = NULL; // 只能从上述已引用对象中选择，不来自通信字节。
    LARGE_INTEGER stamp; // 保存精确 UTC 采样时间，不提供同步保证。
    NTSTATUS status; // 在回执中保留查找或身份校验错误。
    if (Request == NULL || Response == NULL) // 内部接口误用不能通过空输出指针造成崩溃。
    { // 没有完整输出时无法返回有效回执。
        return STATUS_INVALID_PARAMETER; // 返回内部参数错误，不访问目标对象。
    } // 正常适配入口始终提供两个完整缓冲区。
    RtlCopyMemory(&captured, Request, sizeof(captured)); // 必须先捕获全部输入，再初始化可能重叠的输出。
    RtlZeroMemory(Response, sizeof(*Response)); // 响应头、位图、尾部容量及无效数据全部从零开始。
    Response->version = KSWORD_ARK_STRUCTURE_SAMPLE_VERSION; // 客户端据此拒绝不兼容回执。
    Response->size = (ULONG)sizeof(*Response); // 返回固定响应大小，不使用调用方输出容量作为数据范围。
    Response->flags = KSWORD_ARK_STRUCTURE_SAMPLE_NONATOMIC | // 明确不承诺原子快照。
        KSWORD_ARK_STRUCTURE_SAMPLE_BODY_ONLY | // 明确只复制根正文，不读取指向的其他对象。
        KSWORD_ARK_STRUCTURE_SAMPLE_POINTER_VALUES; // 所有形似指针的内容仅作为未解释数值。
    Response->sampleStatus = KSWORD_ARK_STRUCTURE_SAMPLE_INVALID_REQUEST; // 所有提前拒绝路径都有明确状态。
    Response->lastStatus = STATUS_INVALID_PARAMETER; // 未知区域的零值不能被误报为成功采样。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) // 所有查询及现场读取均限制在被动级执行。
    { // 禁止在较不安全的 IRQL 下尝试读取。
        Response->lastStatus = STATUS_INVALID_DEVICE_STATE; // 明确记录执行级别不符合要求。
        return STATUS_SUCCESS; // 返回已初始化的拒绝回执。
    } // 身份解析器还会独立检查 PASSIVE_LEVEL。
    if (!KswStructureRequestValid(&captured)) // 强制校验创建身份和零保留字段。
    { // 请求不合法时不读取内核映像或目标对象。
        return STATUS_SUCCESS; // 将默认的无效请求回执返回客户端。
    } // 仅两种明确命名的 NT 根对象可以继续。
    Response->objectType = captured.objectType; // 只回显已经通过校验的类型值。
    Response->sampleStatus = KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_UNSUPPORTED; // 精确映像匹配前不授权任何根范围。
    status = KswStructureSampleResolveProfile(&Response->kernel, &profile); // 读取实际运行内核的 PE 和 RSDS。
    if (Response->kernel.machine != 0UL) // 解析器只在完整校验后发布身份字段。
    { // 区分无法取得身份与身份已知但尚不支持两种情况。
        Response->flags |= KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID_VALID; // 向客户端公开已验证身份的可用性。
    } // 已知有效身份仍可能不在允许列表内。
    if (!NT_SUCCESS(status) || profile == NULL) // 未知内核或解析失败不提供正文读取回退。
    { // 保留能够解释失败关闭原因的状态。
        Response->lastStatus = NT_SUCCESS(status) ? STATUS_REVISION_MISMATCH : status; // 防止空配置伴随成功状态流出。
        return STATUS_SUCCESS; // 此时尚未查找目标对象或读取正文。
    } // 不可变配置已绑定到当前运行内核的精确身份。
    Response->profileId = profile->ProfileId; // 返回编译配置中的稳定回执标识。
    Response->rootSize = captured.objectType == KSWORD_ARK_STRUCTURE_SAMPLE_EPROCESS ? // 选择对应对象自身的精确范围。
        profile->EprocessSize : profile->EthreadSize; // 不能借用 KPROCESS、KTHREAD 或邻近版本大小。
    if (Response->rootSize == 0UL || // 空根范围不能授权任何读取。
        Response->rootSize > KSWORD_ARK_STRUCTURE_SAMPLE_MAX_BYTES) // 错误生成的配置也不能突破协议容量上限。
    { // 无效配置不能向客户端发布已授权的根范围。
        Response->rootSize = 0UL; // 清除不能使用的正文长度。
        Response->lastStatus = STATUS_INVALID_IMAGE_FORMAT; // 配置生成缺陷必须失败关闭。
        return STATUS_SUCCESS; // 不使用对象类型的池分配费用作为替代界限。
    } // 精确根正文范围现已获得授权。
    Response->sampleStatus = KSWORD_ARK_STRUCTURE_SAMPLE_LOOKUP_FAILED; // 将对象发现失败与正文复制失败分开。
    status = PsLookupProcessByProcessId(ULongToHandle(captured.processId), &process); // 获取实际已引用的 EPROCESS。
    if (!NT_SUCCESS(status)) // 目标退出等情况可能导致 CID 查找失败。
    { // 客户端重试前需要刷新目标身份。
        Response->lastStatus = status; // 保留原始对象查找状态。
        goto Cleanup; // 所有已经取得的引用统一由清理路径释放。
    } // 进程对象在后续全部正文复制期间保持引用。
    Response->processId = HandleToULong(PsGetProcessId(process)); // 记录对象访问器返回的实际进程 ID。
    Response->processCreationTime100ns = (ULONG64)PsGetProcessCreateTimeQuadPart(process); // 记录不可变的实际进程创建身份。
    if (Response->processId != captured.processId || // 不仅依赖 CID 表的查询键。
        Response->processCreationTime100ns != captured.processCreationTime100ns) // 拒绝 PID 复用或过期选择。
    { // 进程身份不符时不能暴露任何正文数据。
        Response->sampleStatus = KSWORD_ARK_STRUCTURE_SAMPLE_IDENTITY_MISMATCH; // 明确返回身份不匹配状态。
        Response->lastStatus = STATUS_OBJECTID_NOT_FOUND; // 查找成功不等于选定对象身份正确。
        goto Cleanup; // 实际查找得到的引用只释放一次。
    } // 请求指定的进程实例已被精确验证。
    object = process; // 默认进程根基址来自已验证引用，不来自调用方地址运算。
    if (captured.objectType == KSWORD_ARK_STRUCTURE_SAMPLE_ETHREAD) // 线程请求还需检查所属进程及创建实例。
    { // 所属进程引用独立于线程引用持有。
        status = PsLookupThreadByThreadId(ULongToHandle(captured.threadId), &thread); // 取得独立引用保护的 ETHREAD。
        if (!NT_SUCCESS(status)) // 线程消失属于目标查找失败。
        { // 不能把线程查找失败伪装成空的成功快照。
            Response->lastStatus = status; // 保留原始线程查找错误。
            goto Cleanup; // 同时释放此前已经取得的进程引用。
        } // 线程及所属进程的生命周期现在分别受到保护。
        Response->threadId = HandleToULong(PsGetThreadId(thread)); // 保存实际线程 ID，而非仅回显输入。
        Response->threadCreationTime100ns = (ULONG64)PsGetThreadCreateTime(thread); // 保存实际线程创建实例。
        if (Response->threadId != captured.threadId || // 查询键和对象访问器返回的 ID 都必须一致。
            HandleToULong(PsGetThreadProcessId(thread)) != captured.processId || // 所属进程 ID 必须符合冻结请求。
            PsGetThreadProcess(thread) != process || // 所属进程对象指针也必须与独立引用完全相同。
            Response->threadCreationTime100ns != captured.threadCreationTime100ns) // 拒绝 TID 复用或过期所属关系。
        { // 不允许采样与请求选择不同的线程实例。
            Response->sampleStatus = KSWORD_ARK_STRUCTURE_SAMPLE_IDENTITY_MISMATCH; // 把线程身份失败与读取失败区分。
            Response->lastStatus = STATUS_OBJECTID_NOT_FOUND; // 客户端必须重新取得线程身份。
            goto Cleanup; // 不读取正文即可平衡释放两个对象引用。
        } // 线程及所属进程都是请求指定的精确创建实例。
        object = thread; // 只有此已验证 ETHREAD 引用能够成为线程根对象。
    } // 进程请求不会获取或读取线程对象。
    if ((ULONG_PTR)object < (ULONG_PTR)MmSystemRangeStart || // 防御性拒绝不可能的非内核根地址。
        (ULONG_PTR)object > MAXULONG_PTR - Response->rootSize) // 分块读取前检查精确根末端的整数加法。
    { // 没有合法对象身份的候选基址不能进入采样阶段。
        Response->sampleStatus = KSWORD_ARK_STRUCTURE_SAMPLE_IDENTITY_MISMATCH; // 保持对象身份失败的回执语义。
        Response->lastStatus = STATUS_INVALID_ADDRESS; // 防止地址环绕后读取其他区域。
        goto Cleanup; // 即使发生不可能状态也必须平衡引用。
    } // 后续所有读取地址都位于编译配置授权的精确正文范围内。
    Response->objectAddress = (ULONG64)(ULONG_PTR)object; // 地址仅作为身份数值返回，协议没有地址输入。
    Response->lastStatus = STATUS_SUCCESS; // 只有全部准入检查通过后才清除默认错误。
    KeQuerySystemTimePrecise(&stamp); // 以精确 UTC 时间标记实际现场读取区间的开始。
    Response->sampleStartTime100ns = (ULONG64)stamp.QuadPart; // 仅到达正文读取阶段时才填入起始时间。
    KswStructureCopyBody(object, Response); // 复制精确根正文，不跟随任何内嵌指针。
    KeQuerySystemTimePrecise(&stamp); // 所有正文读取尝试完成后再次采集时间。
    Response->sampleEndTime100ns = (ULONG64)stamp.QuadPart; // 系统时钟调整也不构成原子一致性保证。
    Response->sampleStatus = Response->bytesCopied == Response->rootSize ? KSWORD_ARK_STRUCTURE_SAMPLE_OK : // 全部字节有效仍不代表同一时刻。
        (Response->bytesCopied != 0UL ? KSWORD_ARK_STRUCTURE_SAMPLE_PARTIAL : KSWORD_ARK_STRUCTURE_SAMPLE_READ_FAILED); // 区分部分成功与完全读取失败。
Cleanup: // 所有成功查找的对象引用统一在此平衡释放。
    if (thread != NULL) // 当前路径已经成功取得线程引用。
    { // 用户态解码不能延长驱动对线程对象的持有。
        ObDereferenceObject(thread); // 不跨请求保留线程引用。
    } // 释放后不再使用任何派生自线程的指针。
    if (process != NULL) // 所属进程查找成功与线程查找成功相互独立。
    { // 单独释放此前取得的进程对象引用。
        ObDereferenceObject(process); // 每个独立进程引用恰好释放一次。
    } // 全程不修改、附加、挂起或恢复进程状态。
    return STATUS_SUCCESS; // 对象级结果及部分读取结果均由响应状态字段表达。
} // 请求完成及其他策略检查仍由调用方分发层拥有。
