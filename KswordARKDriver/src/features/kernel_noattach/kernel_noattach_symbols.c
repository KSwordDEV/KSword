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
    /* Phase A1 收尾：Image 信息已固定，IDT handler 已经确认在 ntoskrnl 内。七个符号
     * 的 function pointer 全部保留为 NULL，待 Phase A2+ 接入发现逻辑。 */
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
