#include "kernel_noattach_symbols.h"
#include "../../platform/runtime_signature_scan.h"
#include <intrin.h>
#include <ntimage.h>

#if defined(_M_AMD64) || defined(_M_X64)
#pragma intrinsic(__sidt)
#endif

/* IDT 寄存器快照：10 字节严格打包 (SIDT 填写)。 */
#pragma pack(push, 1)
typedef struct _KNA_IDTR_SNAPSHOT
{
    USHORT Limit;
    ULONG_PTR Base;
} KNA_IDTR_SNAPSHOT;

/* x64 IDT 条目 16 字节；offset 由三段拼成。 */
typedef struct _KNA_IDT_GATE
{
    USHORT OffsetLow;
    USHORT Selector;
    USHORT IstAndType;
    USHORT OffsetMiddle;
    ULONG OffsetHigh;
    ULONG Reserved;
} KNA_IDT_GATE;
#pragma pack(pop)

C_ASSERT(sizeof(KNA_IDTR_SNAPSHOT) == 10);
C_ASSERT(sizeof(KNA_IDT_GATE) == 16);

/* 扫入口前方最多 MaxScanBytes 字节的 0xCC padding 连续段，返回起点和字节数。
 * 现有 KiDispatchException 入口字节由 compiler /hotpatch 生成；它被 CC-padded 到
 * 16 字节边界，正好放一条 6-byte REX.W jmp + 8-byte 绝对目标的 bridge。本函数
 * 让 driver 自适应其它可能的 padding 长度而非写死 16。 */
static VOID KnaDiscoverPadBeforeRoutine(
    const KSW_RUNTIME_IMAGE_VIEW *View,
    PUCHAR EntryAddress,
    ULONG MaxScanBytes,
    PUCHAR *PatchStartOut,
    PULONG PatchBytesOut)
{
    UCHAR buffer[64];
    LONG i;
    ULONG padLength = 0UL;
    *PatchStartOut = NULL;
    *PatchBytesOut = 0UL;
    if (View == NULL || EntryAddress == NULL || MaxScanBytes == 0UL ||
        MaxScanBytes > sizeof(buffer)) { return; }
    /* 入口前方整个窗口必须落在可执行节内；跨界扫描不可信。 */
    if (!KswordARKRuntimeAddressIsExecutable(View, (ULONG_PTR)EntryAddress - MaxScanBytes, MaxScanBytes))
    { return; }
    if (!KswordARKRuntimeReadMemory(EntryAddress - MaxScanBytes, buffer, MaxScanBytes)) { return; }
    /* 从紧挨入口的那个字节反向数连续 0xCC；遇到任何非 0xCC 停止。 */
    for (i = (LONG)MaxScanBytes - 1L; i >= 0L; --i)
    {
        if (buffer[i] != 0xCCU) { break; }
        ++padLength;
    }
    if (padLength > 0UL)
    {
        *PatchStartOut = EntryAddress - padLength;
        *PatchBytesOut = padLength;
    }
}

/* 对两个 call-target 集合各自回查 enclosing routine，再按 routine 维度取交集。
 * 返回交集 routine 入口数量，去重写入 Out。供发现时交叉两条路径使用。 */
static ULONG KnaIntersectCallTargetRoutines(
    const KSW_RUNTIME_IMAGE_VIEW *View,
    const ULONG_PTR *A, ULONG ACount,
    const ULONG_PTR *B, ULONG BCount,
    ULONG_PTR *Out, ULONG OutCapacity)
{
    /* 空输入或零容量直接返回零。 */
    ULONG count = 0UL;
    ULONG i;
    if (View == NULL || Out == NULL || OutCapacity == 0UL) { return 0UL; }
    for (i = 0UL; i < ACount && count < OutCapacity; ++i)
    {
        ULONG_PTR encA = 0U;
        ULONG j;
        /* 回查 A[i] 的 enclosing routine；查不到直接跳过本项。 */
        if (!KswordARKRuntimeFindEnclosingRoutine(View, A[i], &encA, NULL)) { continue; }
        for (j = 0UL; j < BCount; ++j)
        {
            ULONG_PTR encB = 0U;
            ULONG k;
            BOOLEAN duplicate = FALSE;
            if (!KswordARKRuntimeFindEnclosingRoutine(View, B[j], &encB, NULL)) { continue; }
            if (encA != encB) { continue; }
            /* 交集按 routine entry 去重。 */
            for (k = 0UL; k < count; ++k) { if (Out[k] == encA) { duplicate = TRUE; break; } }
            if (!duplicate) { Out[count++] = encA; }
            break;
        }
    }
    return count;
}

/* 在函数体 [RoutineStart, RoutineStart + RoutineBytes) 内扫 E8/E9 rel32 直接调用
 * 目标；去重后写入 Targets。可能有 false positive（jump table 数据与 opcode 字节
 * 混淆）但调用方通常与反向结果取交集，交集自然收敛到真实函数。 */
static ULONG KnaCollectDirectCallTargetsInRange(
    const KSW_RUNTIME_IMAGE_VIEW *View,
    ULONG_PTR RoutineStart,
    ULONG RoutineBytes,
    ULONG_PTR *Targets,
    ULONG TargetCapacity)
{
    /* 预算核对；小于一条 E8/E9 rel32 长度不扫。 */
    ULONG count = 0UL;
    ULONG_PTR cursor;
    ULONG_PTR limit;
    if (View == NULL || Targets == NULL || TargetCapacity == 0UL || RoutineBytes < 5UL) { return 0UL; }
    limit = RoutineStart + RoutineBytes - 5UL;
    for (cursor = RoutineStart; cursor <= limit && count < TargetCapacity; ++cursor)
    {
        UCHAR bytes[5];
        LONG displacement = 0L;
        ULONG_PTR target;
        ULONG i;
        BOOLEAN duplicate = FALSE;
        /* 读 5 字节窗口；读失败跳过（不中断扫描）。 */
        if (!KswordARKRuntimeReadMemory((const VOID *)cursor, bytes, sizeof(bytes))) { continue; }
        if (bytes[0] != 0xE8U && bytes[0] != 0xE9U) { continue; }
        RtlCopyMemory(&displacement, bytes + 1, sizeof(displacement));
        /* 溢出保护；下一指令地址不得越过 ULONG_PTR 上界。 */
        if (cursor > MAXULONG_PTR - 5U) { break; }
        target = cursor + 5U + (ULONG_PTR)(LONG_PTR)displacement;
        /* 丢弃不落在当前映像可执行范围的 target；jump table 数据多在只读区。 */
        if (!KswordARKRuntimeAddressIsExecutable(View, target, 1U)) { continue; }
        for (i = 0UL; i < count; ++i)
        { if (Targets[i] == target) { duplicate = TRUE; break; } }
        if (!duplicate) { Targets[count++] = target; }
    }
    return count;
}

/* 读指定 IDT vector 的 handler 线性地址。成功返回非零线性地址；失败返回 NULL。
 * 不触发任何内核分配或等待，可在任意 IRQL 调用。 */
static PVOID KnaReadIdtHandler(UCHAR Vector)
{
    /* SIDT 在 x64 用户态和内核态都可发；本函数仅在内核调用。 */
    KNA_IDTR_SNAPSHOT snapshot = {0};
    KNA_IDT_GATE gate = {0};
    ULONG_PTR address;
    /* 读 IDT 寄存器；Base 是 IDT 基线的内核线性地址。 */
    __sidt(&snapshot);
    /* 越界 vector 不读；每条 16 字节。 */
    if ((ULONG)(Vector + 1U) * sizeof(KNA_IDT_GATE) > (ULONG)(snapshot.Limit + 1U))
    { return NULL; }
    /* 以安全读接口避免越界访问破坏当前线程。 */
    if (!KswordARKRuntimeReadMemory(
            (PUCHAR)snapshot.Base + (ULONG)Vector * sizeof(KNA_IDT_GATE), &gate, sizeof(gate)))
    { return NULL; }
    /* 拼接 handler 线性地址的三个段。 */
    address = (ULONG_PTR)gate.OffsetLow;
    address |= ((ULONG_PTR)gate.OffsetMiddle) << 16;
    address |= ((ULONG_PTR)gate.OffsetHigh) << 32;
    /* 零 handler 视为未初始化 IDT 槽。 */
    return address != 0 ? (PVOID)address : NULL;
}

/* 解析 ntoskrnl 映像身份：Base/Size/CodeView GUID+Age/Build 号；供后续发现阶段
 * 当作 "已固定" 的映像使用。只读，不修改任何内核映像字节。 */
static NTSTATUS KnaResolveNtImage(KNA_RESOLVED_SYMBOLS *Out)
{
    typedef PVOID (NTAPI *IMAGEBASE_FN)(PVOID, PVOID *);
    UNICODE_STRING nameBugCheck = RTL_CONSTANT_STRING(L"KeBugCheckEx");
    UNICODE_STRING nameImageBase = RTL_CONSTANT_STRING(L"RtlPcToFileHeader");
    PVOID bugCheck;
    IMAGEBASE_FN imageBase;
    PVOID base = NULL;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DEBUG_DIRECTORY debug;
    UCHAR rsds[24];
    ULONG offset;
    RTL_OSVERSIONINFOW version = {0};
    ULONG debugDirRva, debugDirSize;
    /* 两个必备导出：缺一返回 NOT_SUPPORTED 以让 caller 保留旧路径。 */
    bugCheck = MmGetSystemRoutineAddress(&nameBugCheck);
    imageBase = (IMAGEBASE_FN)MmGetSystemRoutineAddress(&nameImageBase);
    if (bugCheck == NULL || imageBase == NULL) { return STATUS_NOT_SUPPORTED; }
    /* 以已导出函数定位 ntoskrnl 基址：RtlPcToFileHeader 的 Out 参数是 DLL base。 */
    if (imageBase(bugCheck, &base) == NULL || base == NULL) { return STATUS_NOT_SUPPORTED; }
    /* PE 头核对：DOS + NT 签名、AMD64 机器码、至少一页大。 */
    if (!KswordARKRuntimeReadMemory(base, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000)
    { return STATUS_NOT_SUPPORTED; }
    if (!KswordARKRuntimeReadMemory((PUCHAR)base + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.SizeOfImage < PAGE_SIZE)
    { return STATUS_NOT_SUPPORTED; }
    Out->KnaNt = (PUCHAR)base;
    Out->KnaNtBytes = nt.OptionalHeader.SizeOfImage;
    /* Windows build 号诊断用；不作判据。 */
    version.dwOSVersionInfoSize = sizeof(version);
    if (NT_SUCCESS(RtlGetVersion(&version))) { Out->BuildNumber = version.dwBuildNumber; }
    /* 调试目录可能不存在；缺失不拒绝，GUID/Age 留 0 由 oracle 比对发现问题。 */
    debugDirRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
    debugDirSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
    if (debugDirRva != 0UL && debugDirSize <= 4096UL && debugDirRva < Out->KnaNtBytes)
    {
        for (offset = 0UL; offset + sizeof(debug) <= debugDirSize; offset += sizeof(debug))
        {
            if (!KswordARKRuntimeReadMemory(
                    (PUCHAR)base + debugDirRva + offset, &debug, sizeof(debug))) { break; }
            /* 只认 CodeView 条目；其它类型跳过。 */
            if (debug.Type != IMAGE_DEBUG_TYPE_CODEVIEW || debug.SizeOfData < sizeof(rsds)) { continue; }
            if (debug.AddressOfRawData > Out->KnaNtBytes - sizeof(rsds)) { continue; }
            /* RSDS 四字节签名 + 16 字节 GUID + 4 字节 Age。 */
            if (!KswordARKRuntimeReadMemory((PUCHAR)base + debug.AddressOfRawData, rsds, sizeof(rsds)))
            { continue; }
            if (rsds[0] != 'R' || rsds[1] != 'S' || rsds[2] != 'D' || rsds[3] != 'S') { continue; }
            /* GUID 以两个 ULONGLONG 存，Age 以 ULONG 存；三者共同构成 PDB 查询 key。 */
            RtlCopyMemory(&Out->CodeViewGuidLow, rsds + 4, sizeof(ULONGLONG));
            RtlCopyMemory(&Out->CodeViewGuidHigh, rsds + 12, sizeof(ULONGLONG));
            RtlCopyMemory(&Out->CodeViewAge, rsds + 20, sizeof(ULONG));
            break;
        }
    }
    return STATUS_SUCCESS;
}

/* 发现结果缓存与状态机：0=idle 1=in-flight 2=success 3=failure。单次解析，多次复用。 */
static KNA_RESOLVED_SYMBOLS g_KnaResolved;
static volatile LONG g_KnaResolvedState;

/* Phase A1：读 IDT vector 1/14 handler，验证它们都落在 ntoskrnl .text 内；若通过
 * 则证明 image lookup + IDT 基础设施可用；具体符号发现 (Phase A2+) 再接入。 */
static NTSTATUS KnaResolveInternal(KNA_RESOLVED_SYMBOLS *Out)
{
    KSW_RUNTIME_IMAGE_VIEW view;
    PVOID handlerPageFault, handlerDebug;
    NTSTATUS status;
    /* 从干净快照起步；partial 结果绝不保留。 */
    RtlZeroMemory(Out, sizeof(*Out));
    status = KnaResolveNtImage(Out);
    if (!NT_SUCCESS(status)) { return status; }
    /* 建立 PE 视图供后续 .text / .pdata 查询。 */
    if (!KswordARKRuntimeInitializeImageView(Out->KnaNt, Out->KnaNtBytes, &view))
    { return STATUS_INVALID_IMAGE_FORMAT; }
    /* #DB (vector 1, KiDebugTrapOrFault) 与 #PF (vector 14, KiPageFault) 都是
     * KiDispatchException 的上游 trap handler，是后续追踪的稳定锚点。 */
    handlerPageFault = KnaReadIdtHandler(14U);
    handlerDebug = KnaReadIdtHandler(1U);
    if (handlerPageFault == NULL || handlerDebug == NULL) { return STATUS_NOT_FOUND; }
    /* Handler 必须落在当前 ntoskrnl 的可执行段内；否则属于第三方 IDT 接管，本后端
     * 不与之共存。 */
    if (!KswordARKRuntimeAddressIsExecutable(&view, (ULONG_PTR)handlerPageFault, 1U) ||
        !KswordARKRuntimeAddressIsExecutable(&view, (ULONG_PTR)handlerDebug, 1U))
    { return STATUS_NOT_FOUND; }
    /* Phase A3 bring-up：对 KeBugCheckEx 做反向两级 call-graph 扫描。KiDispatchException
     * 在 unhandled exception 分支里通过 KiBugCheckDispatch 调 KeBugCheckEx，所以：
     *   L1 = KeBugCheckEx 的直接 callers（含 KiBugCheckDispatch 等 panic wrapper）
     *   L2 = L1 中每个 caller 的 callers（KiDispatchException 应落在此集合）
     * 本阶段只收集并记日志；Phase A4 加 KiPageFault forward trace + prologue 验证
     * 将 L2 narrow 到 KiDispatchException。 */
    {
        UNICODE_STRING nameBugCheck = RTL_CONSTANT_STRING(L"KeBugCheckEx");
        PVOID bugCheck = MmGetSystemRoutineAddress(&nameBugCheck);
        if (bugCheck != NULL)
        {
            KSW_RUNTIME_CALL_SITE l1[32];
            KSW_RUNTIME_CALL_SITE l2[128];
            ULONG l1Count;
            ULONG l2Count = 0UL;
            ULONG l1Index;
            ULONG logIndex;
            /* L1：扫整个 ntoskrnl .text 找 call KeBugCheckEx。 */
            l1Count = KswordARKRuntimeFindCallersOfRoutine(
                &view, (ULONG_PTR)bugCheck, l1, RTL_NUMBER_OF(l1));
            DbgPrint("[KnaResolveSymbols] KeBugCheckEx=%p L1 callers=%u\n", bugCheck, l1Count);
            for (logIndex = 0UL; logIndex < l1Count && logIndex < 5UL; ++logIndex)
            {
                DbgPrint("[KnaResolveSymbols]   L1[%u] routine=%p call@%p opcode=0x%02X\n",
                         logIndex,
                         (PVOID)l1[logIndex].CallerRoutine,
                         (PVOID)l1[logIndex].CallInstruction,
                         l1[logIndex].Opcode);
            }
            /* L2：对每个 L1 caller 再反向 scan，收集它们的 callers，按 routine 去重。 */
            for (l1Index = 0UL;
                 l1Index < l1Count && l2Count < RTL_NUMBER_OF(l2);
                 ++l1Index)
            {
                KSW_RUNTIME_CALL_SITE buffer[32];
                ULONG bufferCount = KswordARKRuntimeFindCallersOfRoutine(
                    &view, l1[l1Index].CallerRoutine, buffer, RTL_NUMBER_OF(buffer));
                ULONG i;
                for (i = 0UL; i < bufferCount && l2Count < RTL_NUMBER_OF(l2); ++i)
                {
                    ULONG j;
                    BOOLEAN duplicate = FALSE;
                    /* L1 caller 本身也可能出现在二级反向结果中（例如彼此调用）；跳过。 */
                    for (j = 0UL; j < l1Count; ++j)
                    {
                        if (l1[j].CallerRoutine == buffer[i].CallerRoutine)
                        { duplicate = TRUE; break; }
                    }
                    if (duplicate) { continue; }
                    for (j = 0UL; j < l2Count; ++j)
                    {
                        if (l2[j].CallerRoutine == buffer[i].CallerRoutine)
                        { duplicate = TRUE; break; }
                    }
                    if (!duplicate) { l2[l2Count++] = buffer[i]; }
                }
            }
            DbgPrint("[KnaResolveSymbols] L2 candidates (reachable to KeBugCheckEx in 2 hops, excl. L1): %u\n",
                     l2Count);
            for (logIndex = 0UL; logIndex < l2Count && logIndex < 10UL; ++logIndex)
            {
                DbgPrint("[KnaResolveSymbols]   L2[%u] routine=%p\n",
                         logIndex, (PVOID)l2[logIndex].CallerRoutine);
            }
            /* Phase A4：从 IDT vector 14 (#PF) handler 所在函数的函数体内采集直接
             * call 目标；与 L2 取交集。KiDispatchException 应在 KiPageFault 的
             * 直接下游 call 目标中（可能经 KiPageFaultHelper 一类小 wrapper），
             * 并同时在 L2 之内。 */
            {
                ULONG_PTR pfBegin = 0U;
                ULONG pfBytes = 0UL;
                if (KswordARKRuntimeFindEnclosingRoutine(&view, (ULONG_PTR)handlerPageFault,
                                                          &pfBegin, &pfBytes) &&
                    pfBytes > 0UL)
                {
                    ULONG_PTR pfTargets[64];
                    ULONG pfTargetCount = KnaCollectDirectCallTargetsInRange(
                        &view, pfBegin, pfBytes, pfTargets, RTL_NUMBER_OF(pfTargets));
                    ULONG intersect = 0UL;
                    ULONG_PTR dispatchCandidate = 0U;
                    ULONG pfIndex;
                    DbgPrint("[KnaResolveSymbols] KiPageFault@%p bytes=%u direct call_targets=%u\n",
                             (PVOID)pfBegin, pfBytes, pfTargetCount);
                    /* 对每个目标回查其 enclosing routine（call 可能指到某函数中段），
                     * 然后与 L2 做 routine 维度交集。 */
                    for (pfIndex = 0UL; pfIndex < pfTargetCount; ++pfIndex)
                    {
                        ULONG_PTR enclosing = 0U;
                        ULONG targetL2;
                        if (!KswordARKRuntimeFindEnclosingRoutine(&view, pfTargets[pfIndex],
                                                                   &enclosing, NULL))
                        { continue; }
                        for (targetL2 = 0UL; targetL2 < l2Count; ++targetL2)
                        {
                            if (l2[targetL2].CallerRoutine == enclosing)
                            {
                                DbgPrint("[KnaResolveSymbols]   intersect: routine=%p\n",
                                         (PVOID)enclosing);
                                ++intersect;
                                if (dispatchCandidate == 0U) { dispatchCandidate = enclosing; }
                                break;
                            }
                        }
                    }
                    DbgPrint("[KnaResolveSymbols] L2 ∩ KiPageFault.call_targets count=%u\n", intersect);
                    /* 唯一交集 = KiDispatchException 候选确认；production 路径仍走
                     * KnaProfiles（Phase A7 再切换）。 */
                    if (intersect == 1UL)
                    {
                        Out->KiDispatchException = (PVOID)dispatchCandidate;
                        DbgPrint("[KnaResolveSymbols] KiDispatchException candidate CONFIRMED: %p\n",
                                 (PVOID)dispatchCandidate);
                    }
                    else
                    {
                        DbgPrint("[KnaResolveSymbols] intersect !=1; need cross-check with KiDebugTrapOrFault path\n");
                    }
                }
            }
        }
    }
    /* Phase A5: 发现另外 6 个符号的候选。所有路径都以导出函数作为锚点，并在可能时
     * 与 KiDispatchException 的 call targets 交叉验证。本阶段只填 Out 字段并记录，
     * production 路径仍走 KnaProfiles；Phase A7 整体切换。 */
    {
        UNICODE_STRING nameGetCtx = RTL_CONSTANT_STRING(L"PsGetContextThread");
        UNICODE_STRING nameSetCtx = RTL_CONSTANT_STRING(L"PsSetContextThread");
        UNICODE_STRING nameSuspend = RTL_CONSTANT_STRING(L"KeSuspendThread");
        UNICODE_STRING nameResume = RTL_CONSTANT_STRING(L"KeResumeThread");
        PVOID psGet = MmGetSystemRoutineAddress(&nameGetCtx);
        PVOID psSet = MmGetSystemRoutineAddress(&nameSetCtx);
        PVOID keS = MmGetSystemRoutineAddress(&nameSuspend);
        PVOID keR = MmGetSystemRoutineAddress(&nameResume);
        ULONG_PTR psGetInternal = 0U;
        ULONG_PTR psSetInternal = 0U;
        ULONG_PTR dispatchBegin = 0U;
        ULONG dispatchBytes = 0UL;
        ULONG_PTR dispatchTargets[128];
        ULONG dispatchTargetCount = 0UL;
        /* KeSuspendThread / KeResumeThread：Win10+ 多数 build 直接导出；缺失按 NULL
         * 保留，由 KnaProfiles 路径兜底直到 Phase A7。 */
        if (keS != NULL)
        { Out->KeSuspendThread = keS; DbgPrint("[KnaResolveSymbols] KeSuspendThread=%p (export)\n", keS); }
        if (keR != NULL)
        { Out->KeResumeThread = keR; DbgPrint("[KnaResolveSymbols] KeResumeThread=%p (export)\n", keR); }
        /* 预采集 KiDispatchException 的 call targets 供两处 cross-check 使用。 */
        if (Out->KiDispatchException != NULL &&
            KswordARKRuntimeFindEnclosingRoutine(&view, (ULONG_PTR)Out->KiDispatchException,
                                                  &dispatchBegin, &dispatchBytes) &&
            dispatchBytes > 0UL)
        {
            dispatchTargetCount = KnaCollectDirectCallTargetsInRange(
                &view, dispatchBegin, dispatchBytes, dispatchTargets, RTL_NUMBER_OF(dispatchTargets));
            DbgPrint("[KnaResolveSymbols] KiDispatchException@%p bytes=%u call_targets=%u\n",
                     (PVOID)dispatchBegin, dispatchBytes, dispatchTargetCount);
        }
        /* PsGet/SetContextInternal：exported wrapper 函数体一般极小（thin shim），其直接
         * call target 中唯一一个即为 Internal 版本。 */
        if (psGet != NULL)
        {
            ULONG_PTR begin = 0U;
            ULONG bytes = 0UL;
            if (KswordARKRuntimeFindEnclosingRoutine(&view, (ULONG_PTR)psGet, &begin, &bytes) && bytes > 0UL)
            {
                ULONG_PTR targets[8];
                ULONG targetCount = KnaCollectDirectCallTargetsInRange(
                    &view, begin, bytes, targets, RTL_NUMBER_OF(targets));
                DbgPrint("[KnaResolveSymbols] PsGetContextThread@%p bytes=%u direct_calls=%u\n",
                         psGet, bytes, targetCount);
                /* 唯一 call target：确认为 Internal。多个目标暂不认定（可能有 ExSystemExceptionFilter 等 wrapper 调用）。 */
                if (targetCount == 1UL)
                {
                    ULONG_PTR enclosing = 0U;
                    if (KswordARKRuntimeFindEnclosingRoutine(&view, targets[0], &enclosing, NULL) &&
                        enclosing != 0U)
                    {
                        psGetInternal = enclosing;
                        Out->PsGetContextInternal = (PVOID)enclosing;
                        DbgPrint("[KnaResolveSymbols] PsGetContextInternal CONFIRMED: %p\n", (PVOID)enclosing);
                    }
                }
            }
        }
        if (psSet != NULL)
        {
            ULONG_PTR begin = 0U;
            ULONG bytes = 0UL;
            if (KswordARKRuntimeFindEnclosingRoutine(&view, (ULONG_PTR)psSet, &begin, &bytes) && bytes > 0UL)
            {
                ULONG_PTR targets[8];
                ULONG targetCount = KnaCollectDirectCallTargetsInRange(
                    &view, begin, bytes, targets, RTL_NUMBER_OF(targets));
                DbgPrint("[KnaResolveSymbols] PsSetContextThread@%p bytes=%u direct_calls=%u\n",
                         psSet, bytes, targetCount);
                if (targetCount == 1UL)
                {
                    ULONG_PTR enclosing = 0U;
                    if (KswordARKRuntimeFindEnclosingRoutine(&view, targets[0], &enclosing, NULL) &&
                        enclosing != 0U)
                    {
                        psSetInternal = enclosing;
                        Out->PsSetContextInternal = (PVOID)enclosing;
                        DbgPrint("[KnaResolveSymbols] PsSetContextInternal CONFIRMED: %p\n", (PVOID)enclosing);
                    }
                }
            }
        }
        /* KeContextFromKframes / KeContextToKframes：在 Internal 的直接 call targets ∩
         * KiDispatchException 的直接 call targets 中。两边都会调同一个 frame 转换
         * 函数（From 在读路径、To 在写路径）。 */
        if (psGetInternal != 0U && dispatchTargetCount > 0UL)
        {
            ULONG_PTR internalBegin = 0U;
            ULONG internalBytes = 0UL;
            if (KswordARKRuntimeFindEnclosingRoutine(&view, psGetInternal,
                                                     &internalBegin, &internalBytes) &&
                internalBytes > 0UL)
            {
                ULONG_PTR internalTargets[32];
                ULONG internalCount = KnaCollectDirectCallTargetsInRange(
                    &view, internalBegin, internalBytes, internalTargets, RTL_NUMBER_OF(internalTargets));
                ULONG_PTR cross[8];
                ULONG crossCount = KnaIntersectCallTargetRoutines(
                    &view, internalTargets, internalCount, dispatchTargets, dispatchTargetCount,
                    cross, RTL_NUMBER_OF(cross));
                DbgPrint("[KnaResolveSymbols] PsGetContextInternal direct_calls=%u ∩ dispatch=%u\n",
                         internalCount, crossCount);
                if (crossCount == 1UL)
                {
                    Out->KeContextFromKframes = (PVOID)cross[0];
                    DbgPrint("[KnaResolveSymbols] KeContextFromKframes CONFIRMED: %p\n", (PVOID)cross[0]);
                }
            }
        }
        if (psSetInternal != 0U && dispatchTargetCount > 0UL)
        {
            ULONG_PTR internalBegin = 0U;
            ULONG internalBytes = 0UL;
            if (KswordARKRuntimeFindEnclosingRoutine(&view, psSetInternal,
                                                     &internalBegin, &internalBytes) &&
                internalBytes > 0UL)
            {
                ULONG_PTR internalTargets[32];
                ULONG internalCount = KnaCollectDirectCallTargetsInRange(
                    &view, internalBegin, internalBytes, internalTargets, RTL_NUMBER_OF(internalTargets));
                ULONG_PTR cross[8];
                ULONG crossCount = KnaIntersectCallTargetRoutines(
                    &view, internalTargets, internalCount, dispatchTargets, dispatchTargetCount,
                    cross, RTL_NUMBER_OF(cross));
                DbgPrint("[KnaResolveSymbols] PsSetContextInternal direct_calls=%u ∩ dispatch=%u\n",
                         internalCount, crossCount);
                if (crossCount == 1UL)
                {
                    Out->KeContextToKframes = (PVOID)cross[0];
                    DbgPrint("[KnaResolveSymbols] KeContextToKframes CONFIRMED: %p\n", (PVOID)cross[0]);
                }
            }
        }
    }
    /* Phase A6: 发现 KiDispatchException 入口字节与前方 0xCC padding 空间。替代原来
     * 硬编码 "前 16 字节必须是 0xCC" + "入口必须是 0x5540" 的组合判定；允许可变
     * 长度 padding 和任意 compiler /hotpatch 兼容入口字节。实际的入口 patching 逻辑
     * 在 Phase A7 一并切换为使用 Out 的字段，当前仅做发现并记日志。 */
    if (Out->KiDispatchException != NULL)
    {
        USHORT entryWord = 0U;
        PUCHAR patchStart = NULL;
        ULONG patchBytes = 0UL;
        /* 入口首 2 字节：当前热补丁原子替换单位。记录此值，让 Phase A7 据实际入口
         * 组合生成 forward 跳转，而不是只接受 0x5540 (push rbp with REX prefix)。 */
        if (KswordARKRuntimeReadMemory(Out->KiDispatchException, &entryWord, sizeof(entryWord)))
        {
            Out->KiDispatchExceptionWord = entryWord;
            DbgPrint("[KnaResolveSymbols] KiDispatchException@%p entry_word=0x%04X\n",
                     Out->KiDispatchException, entryWord);
        }
        /* 搜索入口前方最多 32 字节 0xCC padding。14 字节放 6 字节 FF /4 间接 jmp +
         * 8 字节 absolute target 已足够现有 bridge；不足的 build 由 Phase A7 的
         * trampoline fallback 兜底。 */
        KnaDiscoverPadBeforeRoutine(&view, (PUCHAR)Out->KiDispatchException, 32UL,
                                     &patchStart, &patchBytes);
        if (patchStart != NULL && patchBytes >= 14UL)
        {
            Out->PatchArea = patchStart;
            Out->PatchAreaBytes = patchBytes;
            DbgPrint("[KnaResolveSymbols] KiDispatchException pad bytes=%u start=%p (>=14 OK)\n",
                     patchBytes, patchStart);
        }
        else
        {
            DbgPrint("[KnaResolveSymbols] KiDispatchException pad bytes=%u (need>=14), A7 trampoline fallback required\n",
                     patchBytes);
        }
    }
    /* Phase A6 完成：Out 带 KiDispatchExceptionWord 与 PatchArea / PatchAreaBytes，
     * 覆盖入口字节与 patch space 的两个自适应维度。production 路径仍是 KnaProfiles；
     * Phase A7 做 oracle 验证、trampoline fallback 与 hook 路径切换。 */
    return STATUS_SUCCESS;
}

NTSTATUS KnaResolveSymbols(KNA_RESOLVED_SYMBOLS *Out)
{
    LONG state;
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    /* 首个进入者执行真正解析，其余等缓存。 */
    state = InterlockedCompareExchange(&g_KnaResolvedState, 1L, 0L);
    if (state == 0L)
    {
        status = KnaResolveInternal(&g_KnaResolved);
        InterlockedExchange(&g_KnaResolvedState, NT_SUCCESS(status) ? 2L : 3L);
    }
    else
    {
        /* 最多等 ~16ms（1e6 YieldProcessor），实际解析毫秒级完成。 */
        ULONG budget = 1000000UL;
        while (budget-- != 0UL)
        {
            LONG current = InterlockedCompareExchange(&g_KnaResolvedState, 0L, 0L);
            if (current == 2L || current == 3L) { break; }
            YieldProcessor();
        }
        status = (g_KnaResolvedState == 2L) ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
    }
    /* 失败时不写入 partial 结果，让 caller 显式回退到 KnaProfiles 路径。 */
    if (NT_SUCCESS(status) && Out != NULL) { *Out = g_KnaResolved; }
    return status;
}
