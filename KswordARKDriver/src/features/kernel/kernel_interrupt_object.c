/*++

Module Name:

    kernel_interrupt_object.c

Abstract:

    IDT 网关之后的二级对象取证。只核对 IDT 网关地址的检测看不到这样一种劫持：网关仍指向
    干净的 nt 内部 thunk（KiIsrThunk+N），被改的是网关之后中断对象（KINTERRUPT）里的
    ServiceRoutine / MessageServiceRoutine / DispatchAddress 字段。本文件沿向量走到中断对象，
    把这些二级指针归属到已加载模块，并判断是否落在模块的可执行节内。

    本仓库里没有任何经过验证的 _KINTERRUPT 偏移，也没有 KPRCB.InterruptObject 的偏移，
    DynData 里同样没有。所以这里不把任何偏移当常量直接信，全部在运行时自验证：

      1. 「形如 KINTERRUPT 的对象」：Type == 0x16、Size 落在 [0x100, 0x400]、
         InterruptListEntry 的 Flink/Blink 自洽（自环 / 双空 / 邻居互指）。
      2. 形态 B（现代，网关指向 nt 里的共享 thunk）：在当前 CPU 的 KPRCB 前 0xC000 字节内，
         把每个 8 字节对齐的内核指针都追一遍，凡指向"形如 KINTERRUPT 的对象"的都记下来；
         再对 KINTERRUPT 内每个 4 字节对齐的候选 Vector 字段偏移 f 做投票：
         对象在窗口里的槽位 p、对象里读到的向量值 v，共同指向数组起点 X = p - v。
         只有 (X, f) 让至少 4 个对象「槽位下标 == 对象自己记的向量号」，且 X 唯一，
         且该数组范围内 >= 90% 的对象都对得上，才接受。0 个解、并列解、混杂都判为未验证。
         （只按"槽位里有几个像样的指针"打分是不够的：数组前面若干槽位为空，
          把起点整体右移几格计数不变，无法唯一。向量号互相印证才能钉死起点。）
      3. 形态 A（老式，网关处理函数就在 KINTERRUPT 内部的 DispatchCode 里）：
         处理函数不在任何模块可执行节里时，在 [handler-0x300, handler] 内按 8 字节对齐往回扫，
         取第一个满足"形如 KINTERRUPT 且 base+Size > handler"的候选；
         这批对象同样要让某个 Vector 字段偏移与网关向量号互相印证（>= 4 个且 >= 90%）。
      4. ServiceRoutine 字段：候选偏移取 InterruptListEntry 之后的第一个指针槽位 (0x08+0x10)，
         对这批已确认的对象要求：至少 2 个非空且非空数 >= 对象数的 1/4，>= 90% 的非空值落在
         某个已加载模块的可执行节里，且非空值不全相同（全相同更像 DispatchAddress）。
         MessageServiceRoutine 取其后一个槽位；DispatchAddress 取候选 0x50：
         >= 90% 的对象非空且 >= 90% 的非空值落在核心内核（nt/hal）可执行节里。
         这两项各自过不了只是"该字段不检查"，不影响 ServiceRoutine 的检查，
         但会产出一行 LAYOUT_UNVERIFIED 说明。

    失败即关闭：布局没能验证，就只产出一行 LAYOUT_UNVERIFIED 说明，绝不产出 HIDDEN_HOOK，
    也不给"干净"的结论。三个字段都验证通过的完整布局缓存在文件级静态里（缓存的是偏移，
    不是结论），每次查询仍逐对象重新读取、重新判定，并且每个对象都要重新通过形状与向量号校验。
    只验证出部分字段的布局不缓存，下次查询重新解析，有机会补全。

    本文件全程只读：所有内核内存读取都走 KswordARKHookReadMemorySafe，只在 PASSIVE_LEVEL 工作。

Environment:

    Kernel mode, PASSIVE_LEVEL。

--*/

#include "kernel_interrupt_object.h"

#include "kernel_image_section_map.h"
#include "src/platform/pool_compat.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#if defined(_M_AMD64) || defined(_M_X64)

// 本模块私有的池标签。
#define KSW_INTOBJ_TAG 'tIsK'

// x64 规范高半区下界。
#define KSW_INTOBJ_KERNEL_BASE 0xFFFF800000000000ULL
// 内核地址空间最顶端的 HAL 堆 / 设备内存映射区。这里的指针不追：
// KPRCB 里偶有指向 APIC/HPET 之类 MMIO 的指针，读它们可能有副作用。
#define KSW_INTOBJ_HAL_REGION_BASE 0xFFFFFFFFFFC00000ULL

// KINTERRUPT 的对象类型编号（InterruptObject = 22）。
#define KSW_INTOBJ_TYPE_VALUE 0x16UL
// KINTERRUPT Size 的合理区间。
#define KSW_INTOBJ_SIZE_MIN 0x100UL
#define KSW_INTOBJ_SIZE_MAX 0x400UL
// 每个对象读取的前缀字节数。所有被检查/被搜索的字段偏移都必须落在其中。
#define KSW_INTOBJ_PREFIX_BYTES 0x100UL
// InterruptListEntry 的候选偏移（由自环 / 邻居互指校验佐证）。
#define KSW_INTOBJ_LIST_OFFSET 0x08UL
// ServiceRoutine 的候选偏移：InterruptListEntry 之后的第一个指针槽位。
#define KSW_INTOBJ_SERVICE_CANDIDATE 0x18UL
// DispatchAddress 的候选偏移。
#define KSW_INTOBJ_DISPATCH_CANDIDATE 0x50UL
// Vector 字段偏移的搜索区间（4 字节步进）。
#define KSW_INTOBJ_VECTOR_SCAN_FIRST 0x20UL
#define KSW_INTOBJ_VECTOR_SCAN_LAST 0xFCUL
#define KSW_INTOBJ_VECTOR_SLOTS 256UL
// 在 KPRCB 内扫描候选数组的窗口。
#define KSW_INTOBJ_PRCB_WINDOW_BYTES 0xC000UL
#define KSW_INTOBJ_PRCB_WINDOW_QWORDS (KSW_INTOBJ_PRCB_WINDOW_BYTES / 8UL)
// 单次读取窗口的块大小（按 VA 对齐，绝不跨页）。
#define KSW_INTOBJ_CHUNK_BYTES 0x200UL
// 一次解析最多记录的对象数。
#define KSW_INTOBJ_MAX_RECORDS 256UL
// 至少要有这么多互相印证的对象才接受一个布局。
#define KSW_INTOBJ_MIN_CONFIRMED 4UL
// 形态 A：从处理函数往回找对象基址的最大回溯字节数。
#define KSW_INTOBJ_FORM_A_BACK_BYTES 0x300UL
// 同一向量上沿 InterruptListEntry 最多走几个对象（共享中断链）。
#define KSW_INTOBJ_CHAIN_LIMIT 8UL

// 上下文状态。
#define KSW_INTOBJ_STATE_IDLE 0UL
#define KSW_INTOBJ_STATE_READY 1UL
#define KSW_INTOBJ_STATE_FAILED 2UL

// 解析步骤的结论码，仅用于生成"哪一步没验证过"的说明。
#define KSW_INTOBJ_STEP_OK 0UL
#define KSW_INTOBJ_STEP_NO_SOURCE 1UL
#define KSW_INTOBJ_STEP_UNREADABLE 2UL
#define KSW_INTOBJ_STEP_TOO_FEW 3UL
#define KSW_INTOBJ_STEP_TOO_MANY 4UL
#define KSW_INTOBJ_STEP_NO_TABLE 5UL
#define KSW_INTOBJ_STEP_AMBIGUOUS 6UL
#define KSW_INTOBJ_STEP_MIXED 7UL
#define KSW_INTOBJ_STEP_SERVICE 8UL
#define KSW_INTOBJ_STEP_NO_MEMORY 9UL

// 说明文本分段缓冲的字符数。
#define KSW_INTOBJ_NOTE_CHARS 64UL

// 未产出任何字段行时的哨兵 ordinal（说明行）。
#define KSW_INTOBJ_ORDINAL_NONE 0xFFFFFFFFUL

// 已读到的 IDT 门描述符（16 字节，自然对齐，无填充）。
typedef struct _KSW_INTOBJ_IDT_GATE
{
    USHORT OffsetLow;
    USHORT Selector;
    USHORT IstAndType;
    USHORT OffsetMiddle;
    ULONG OffsetHigh;
    ULONG Reserved;
} KSW_INTOBJ_IDT_GATE;

// 一个已确认"形如 KINTERRUPT"的对象及其前缀快照。
typedef struct _KSW_INTOBJ_RECORD
{
    // 形态 B：对象指针在 KPRCB 窗口里的槽位下标（按 8 字节计）；形态 A：所在 IDT 向量号。
    ULONG Position;
    // 与布局互相印证之后的向量号（仅 Matched 时有效）。
    ULONG Vector;
    ULONGLONG Address;
    BOOLEAN Matched;
    UCHAR Prefix[KSW_INTOBJ_PREFIX_BYTES];
} KSW_INTOBJ_RECORD;

// 不同取值的统计条目（只对每个不同的值归属一次，省掉重复的节表读取）。
typedef struct _KSW_INTOBJ_DISTINCT
{
    ULONGLONG Value;
    ULONG Count;
    BOOLEAN Executable;
    BOOLEAN CoreExecutable;
} KSW_INTOBJ_DISTINCT;

// 布局解析的工作内存，整块从非分页池借用、解析结束即归还。
typedef struct _KSW_INTOBJ_WORK
{
    ULONG RecordCount;
    USHORT Votes[KSW_INTOBJ_PRCB_WINDOW_QWORDS];
    KSW_INTOBJ_DISTINCT Distinct[KSW_INTOBJ_MAX_RECORDS];
    KSW_INTOBJ_RECORD Records[KSW_INTOBJ_MAX_RECORDS];
} KSW_INTOBJ_WORK;

// 一步解析的结论及其现场数字。
typedef struct _KSW_INTOBJ_STEP
{
    ULONG Code;
    ULONG A;
    ULONG B;
    ULONG C;
    ULONG D;
} KSW_INTOBJ_STEP;

// 两种形态各自的解析结论。
typedef struct _KSW_INTOBJ_DIAG
{
    KSW_INTOBJ_STEP Prcb;
    KSW_INTOBJ_STEP Embedded;
} KSW_INTOBJ_DIAG;

// 单个候选字段偏移在整批对象上的统计。
typedef struct _KSW_INTOBJ_FIELD_STATS
{
    ULONG Objects;
    ULONG NonNull;
    ULONG Executable;
    ULONG CoreExecutable;
    ULONG Distinct;
} KSW_INTOBJ_FIELD_STATS;

// 产出证据行时共用的现场。
typedef struct _KSW_INTOBJ_EMIT
{
    KSW_DRIVER_INTEGRITY_BUILDER* Builder;
    KSW_INTERRUPT_OBJECT_CONTEXT* Context;
    const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo;
    const KSW_INTERRUPT_OBJECT_CPU* Cpu;
    ULONG Vector;
    ULONGLONG GateHandler;
    BOOLEAN GateClean;
} KSW_INTOBJ_EMIT;

// 文件级只读布局缓存：验证过一次的偏移，进程（驱动）生命周期内复用。
// 0 = 空；1 = 正在发布；2 = 已发布。只缓存"偏移"，不缓存任何结论。
static KSW_INTERRUPT_OBJECT_LAYOUT g_KswIntObjLayoutCache;
static volatile LONG g_KswIntObjLayoutCacheState = 0L;

static VOID
KswIntObjFormatDetail(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_z_ PCWSTR FormatText,
    ...
    )
/*++

Routine Description:

    把格式化结果写进有界宽字符串缓冲。

Arguments:

    Destination - 输出缓冲。
    DestinationChars - 输出容量（字符数）。
    FormatText - printf 风格宽格式串。
    ... - 格式化参数。

Return Value:

    None. 输出被截断时保留已写入的前缀。

--*/
{
    va_list arguments;

    if (Destination == NULL || DestinationChars == 0UL || FormatText == NULL) {
        return;
    }
    Destination[0] = L'\0';
    va_start(arguments, FormatText);
    (VOID)RtlStringCbVPrintfW(Destination, (SIZE_T)DestinationChars * sizeof(WCHAR), FormatText, arguments);
    va_end(arguments);
    Destination[DestinationChars - 1UL] = L'\0';
}

static BOOLEAN
KswIntObjIsKernelPointer(
    _In_ ULONGLONG Value
    )
/*++

Routine Description:

    判断一个值是否可能是可以追的内核指针：规范高半区、8 字节对齐、且不在 HAL 设备映射区。

Arguments:

    Value - 待判断的值。

Return Value:

    TRUE 表示可以尝试读取；FALSE 表示不追。

--*/
{
    return (Value >= KSW_INTOBJ_KERNEL_BASE &&
            Value < KSW_INTOBJ_HAL_REGION_BASE &&
            (Value & 7ULL) == 0ULL) ? TRUE : FALSE;
}

static ULONGLONG
KswIntObjQword(
    _In_reads_bytes_(KSW_INTOBJ_PREFIX_BYTES) const UCHAR* Prefix,
    _In_ ULONG Offset
    )
/*++

Routine Description:

    从对象前缀快照里取一个 8 字节值；越界返回 0。

Arguments:

    Prefix - 对象前缀快照。
    Offset - 字节偏移。

Return Value:

    读到的值，或 0。

--*/
{
    ULONGLONG value = 0ULL;

    if (Prefix == NULL || (SIZE_T)Offset > (SIZE_T)KSW_INTOBJ_PREFIX_BYTES - sizeof(value)) {
        return 0ULL;
    }
    RtlCopyMemory(&value, Prefix + Offset, sizeof(value));
    return value;
}

static ULONG
KswIntObjDword(
    _In_reads_bytes_(KSW_INTOBJ_PREFIX_BYTES) const UCHAR* Prefix,
    _In_ ULONG Offset
    )
/*++

Routine Description:

    从对象前缀快照里取一个 4 字节值；越界返回全 1（保证不会被当成合法向量号）。

Arguments:

    Prefix - 对象前缀快照。
    Offset - 字节偏移。

Return Value:

    读到的值，或 0xFFFFFFFF。

--*/
{
    ULONG value = 0xFFFFFFFFUL;

    if (Prefix == NULL || (SIZE_T)Offset > (SIZE_T)KSW_INTOBJ_PREFIX_BYTES - sizeof(value)) {
        return 0xFFFFFFFFUL;
    }
    RtlCopyMemory(&value, Prefix + Offset, sizeof(value));
    return value;
}

static BOOLEAN
KswIntObjReadObject(
    _In_ ULONGLONG Address,
    _Out_writes_bytes_(KSW_INTOBJ_PREFIX_BYTES) UCHAR* Prefix,
    _Inout_opt_ ULONG* ListRejectedCount
    )
/*++

Routine Description:

    读取一个候选对象的前缀，并判断它是否"形如 KINTERRUPT"：
    Type == 0x16、Size 在合理区间、InterruptListEntry 的 Flink/Blink 自洽。
    这只是形状判断，不证明任何字段偏移；字段偏移由上层投票 / 统计另行验证。

Arguments:

    Address - 候选对象地址。
    Prefix - 接收 KSW_INTOBJ_PREFIX_BYTES 字节前缀（读取失败时被清零）。
    ListRejectedCount - 可选。Type / Size 都对、却因 InterruptListEntry 不自洽被拒时加一，
        用来在失败说明里区分"根本没有这类对象"与"链表语义与假设不符"。

Return Value:

    TRUE 表示形如 KINTERRUPT；否则 FALSE。

--*/
{
    USHORT rawType = 0U;
    USHORT rawSize = 0U;
    ULONG typeValue = 0UL;
    ULONG sizeValue = 0UL;
    ULONGLONG selfLink = 0ULL;
    ULONGLONG flink = 0ULL;
    ULONGLONG blink = 0ULL;
    LIST_ENTRY neighbour;

    if (Prefix == NULL) {
        return FALSE;
    }
    RtlZeroMemory(Prefix, KSW_INTOBJ_PREFIX_BYTES);
    if (!KswIntObjIsKernelPointer(Address) ||
        !KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)Address, Prefix, KSW_INTOBJ_PREFIX_BYTES)) {
        return FALSE;
    }
    RtlCopyMemory(&rawType, Prefix, sizeof(rawType));
    RtlCopyMemory(&rawSize, Prefix + sizeof(rawType), sizeof(rawSize));
    typeValue = rawType;
    sizeValue = rawSize;
    if (typeValue != KSW_INTOBJ_TYPE_VALUE ||
        sizeValue < KSW_INTOBJ_SIZE_MIN ||
        sizeValue > KSW_INTOBJ_SIZE_MAX) {
        return FALSE;
    }

    selfLink = Address + KSW_INTOBJ_LIST_OFFSET;
    flink = KswIntObjQword(Prefix, KSW_INTOBJ_LIST_OFFSET);
    blink = KswIntObjQword(Prefix, KSW_INTOBJ_LIST_OFFSET + (ULONG)sizeof(ULONGLONG));

    // 自环：未挂在共享链上。
    if (flink == selfLink && blink == selfLink) {
        return TRUE;
    }
    // 双空：尚未初始化成链表头的对象。
    if (flink == 0ULL && blink == 0ULL) {
        return TRUE;
    }
    // 共享链：邻居的 Blink / Flink 必须互指回本对象。
    if (!KswIntObjIsKernelPointer(flink) || !KswIntObjIsKernelPointer(blink)) {
        goto ListRejected;
    }
    RtlZeroMemory(&neighbour, sizeof(neighbour));
    if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)flink, &neighbour, sizeof(neighbour)) ||
        (ULONGLONG)(ULONG_PTR)neighbour.Blink != selfLink) {
        goto ListRejected;
    }
    RtlZeroMemory(&neighbour, sizeof(neighbour));
    if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)blink, &neighbour, sizeof(neighbour)) ||
        (ULONGLONG)(ULONG_PTR)neighbour.Flink != selfLink) {
        goto ListRejected;
    }
    return TRUE;

ListRejected:
    if (ListRejectedCount != NULL) {
        *ListRejectedCount += 1UL;
    }
    return FALSE;
}

static BOOLEAN
KswIntObjFindEmbeddedBase(
    _In_ ULONGLONG Handler,
    _Out_ ULONGLONG* BaseOut,
    _Out_writes_bytes_(KSW_INTOBJ_PREFIX_BYTES) UCHAR* Prefix
    )
/*++

Routine Description:

    形态 A：网关处理函数落在 KINTERRUPT 内部（DispatchCode）。从 handler 往回，
    在 [handler-0x300, handler] 内按 8 字节对齐找第一个满足
    "Type==0x16 且 Size 合理 且 base+Size > handler 且形如 KINTERRUPT"的候选。

Arguments:

    Handler - IDT 网关解出的处理函数地址。
    BaseOut - 接收对象基址。
    Prefix - 接收该对象的前缀快照。

Return Value:

    TRUE 表示找到；FALSE 表示没有。

--*/
{
    UCHAR window[KSW_INTOBJ_FORM_A_BACK_BYTES + sizeof(ULONGLONG)];
    ULONGLONG start = 0ULL;
    ULONGLONG windowStart = 0ULL;
    ULONG back = 0UL;
    BOOLEAN windowValid = FALSE;

    if (BaseOut == NULL || Prefix == NULL) {
        return FALSE;
    }
    *BaseOut = 0ULL;
    start = Handler & ~7ULL;
    if (start < KSW_INTOBJ_KERNEL_BASE + KSW_INTOBJ_FORM_A_BACK_BYTES || start >= KSW_INTOBJ_HAL_REGION_BASE) {
        return FALSE;
    }
    windowStart = start - KSW_INTOBJ_FORM_A_BACK_BYTES;
    // 一次读完整个回溯窗口；读不全（跨到未映射页）则退回逐候选读取。
    windowValid = KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)windowStart, window, sizeof(window));
    for (back = 0UL; back <= KSW_INTOBJ_FORM_A_BACK_BYTES; back += (ULONG)sizeof(ULONGLONG)) {
        const ULONGLONG candidate = start - back;
        UCHAR header[sizeof(ULONG)];
        USHORT rawType = 0U;
        USHORT rawSize = 0U;
        ULONG typeValue = 0UL;
        ULONG sizeValue = 0UL;

        if (windowValid) {
            RtlCopyMemory(header, window + (KSW_INTOBJ_FORM_A_BACK_BYTES - back), sizeof(header));
        }
        else if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)candidate, header, sizeof(header))) {
            continue;
        }
        RtlCopyMemory(&rawType, header, sizeof(rawType));
        RtlCopyMemory(&rawSize, header + sizeof(rawType), sizeof(rawSize));
        typeValue = rawType;
        sizeValue = rawSize;
        if (typeValue != KSW_INTOBJ_TYPE_VALUE ||
            sizeValue < KSW_INTOBJ_SIZE_MIN ||
            sizeValue > KSW_INTOBJ_SIZE_MAX) {
            continue;
        }
        // 处理函数必须真的落在这个对象里面。
        if ((ULONGLONG)sizeValue <= Handler - candidate) {
            continue;
        }
        if (KswIntObjReadObject(candidate, Prefix, NULL)) {
            *BaseOut = candidate;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
KswIntObjCollectFromPrcb(
    _In_ ULONGLONG PrcbAddress,
    _Inout_ KSW_INTOBJ_WORK* Work,
    _Out_ KSW_INTOBJ_STEP* Step
    )
/*++

Routine Description:

    形态 B 第一步：在 KPRCB 前 KSW_INTOBJ_PRCB_WINDOW_BYTES 字节内，把每个 8 字节对齐的
    内核指针都追一遍，记下所有指向"形如 KINTERRUPT 的对象"的槽位。

Arguments:

    PrcbAddress - 当前 CPU 在绑定亲和性期间取到的 KPRCB 地址。
    Work - 工作内存，记录写入 Work->Records。
    Step - 接收失败原因与现场数字。

Return Value:

    TRUE 表示收集到至少 KSW_INTOBJ_MIN_CONFIRMED 个对象；否则 FALSE。

--*/
{
    ULONGLONG cursor = 0ULL;
    ULONGLONG windowEnd = 0ULL;
    ULONG chunksRead = 0UL;
    ULONG listRejected = 0UL;
    UCHAR probe[KSW_INTOBJ_PREFIX_BYTES];

    RtlZeroMemory(Step, sizeof(*Step));
    Work->RecordCount = 0UL;
    if (!KswIntObjIsKernelPointer(PrcbAddress) ||
        PrcbAddress > MAXULONGLONG - KSW_INTOBJ_PRCB_WINDOW_BYTES) {
        Step->Code = KSW_INTOBJ_STEP_NO_SOURCE;
        return FALSE;
    }
    windowEnd = PrcbAddress + KSW_INTOBJ_PRCB_WINDOW_BYTES;
    cursor = PrcbAddress;
    while (cursor < windowEnd) {
        ULONGLONG slots[KSW_INTOBJ_CHUNK_BYTES / sizeof(ULONGLONG)];
        ULONGLONG chunkEnd = (cursor | (KSW_INTOBJ_CHUNK_BYTES - 1ULL)) + 1ULL;
        ULONG bytes = 0UL;
        ULONG slotCount = 0UL;
        ULONG slotIndex = 0UL;

        if (chunkEnd > windowEnd) {
            chunkEnd = windowEnd;
        }
        bytes = (ULONG)(chunkEnd - cursor);
        slotCount = bytes / (ULONG)sizeof(ULONGLONG);
        // 块按 VA 对齐，绝不跨页；读不了的块直接跳过。
        if (KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)cursor, slots, bytes)) {
            chunksRead += 1UL;
            for (slotIndex = 0UL; slotIndex < slotCount; ++slotIndex) {
                const ULONGLONG value = slots[slotIndex];
                KSW_INTOBJ_RECORD* record = NULL;

                if (!KswIntObjIsKernelPointer(value)) {
                    continue;
                }
                // 窗口内部的指针（嵌入的链表头等）不可能是独立分配的中断对象。
                if (value >= PrcbAddress && value < windowEnd) {
                    continue;
                }
                if (!KswIntObjReadObject(value, probe, &listRejected)) {
                    continue;
                }
                if (Work->RecordCount >= KSW_INTOBJ_MAX_RECORDS) {
                    Step->Code = KSW_INTOBJ_STEP_TOO_MANY;
                    Step->A = KSW_INTOBJ_MAX_RECORDS;
                    return FALSE;
                }
                record = &Work->Records[Work->RecordCount];
                record->Position = (ULONG)((cursor - PrcbAddress) / sizeof(ULONGLONG)) + slotIndex;
                record->Vector = 0UL;
                record->Address = value;
                record->Matched = FALSE;
                RtlCopyMemory(record->Prefix, probe, sizeof(record->Prefix));
                Work->RecordCount += 1UL;
            }
        }
        cursor = chunkEnd;
    }
    if (chunksRead == 0UL) {
        Step->Code = KSW_INTOBJ_STEP_UNREADABLE;
        return FALSE;
    }
    if (Work->RecordCount < KSW_INTOBJ_MIN_CONFIRMED) {
        Step->Code = KSW_INTOBJ_STEP_TOO_FEW;
        Step->A = Work->RecordCount;
        Step->B = listRejected;
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswIntObjVotePrcbArray(
    _Inout_ KSW_INTOBJ_WORK* Work,
    _Out_ ULONG* ArrayIndexOut,
    _Out_ ULONG* VectorOffsetOut,
    _Out_ KSW_INTOBJ_STEP* Step
    )
/*++

Routine Description:

    形态 B 第二步：为每个候选 Vector 字段偏移 f 投票。对象在窗口里的槽位为 p，对象里读到的
    向量值为 v（必须 < 256），则它支持数组起点 X = p - v。要求：最高票的 (X, f) 至少
    KSW_INTOBJ_MIN_CONFIRMED 票、X 唯一（同一 f 内没有并列，跨 f 也没有另一个 X 打平）、
    且数组范围 [X, X+256) 内 >= 90% 的对象都对得上。

Arguments:

    Work - 工作内存，Records 已由 KswIntObjCollectFromPrcb 填好。
    ArrayIndexOut - 接收数组起点 X（按 8 字节计）。
    VectorOffsetOut - 接收印证用的 Vector 字段偏移（同 X 的多个别名偏移取最小者）。
    Step - 接收失败原因与现场数字。

Return Value:

    TRUE 表示得到唯一且互相印证的解（并已把对得上的对象标记为 Matched）。

--*/
{
    ULONG fieldOffset = 0UL;
    ULONG bestCount = 0UL;
    ULONG bestIndex = 0UL;
    ULONG bestField = 0UL;
    ULONG shapedInRange = 0UL;
    ULONG recordIndex = 0UL;
    BOOLEAN ambiguous = FALSE;

    RtlZeroMemory(Step, sizeof(*Step));
    for (fieldOffset = KSW_INTOBJ_VECTOR_SCAN_FIRST;
         fieldOffset <= KSW_INTOBJ_VECTOR_SCAN_LAST;
         fieldOffset += (ULONG)sizeof(ULONG)) {
        ULONG levelCount = 0UL;
        ULONG levelIndex = 0UL;
        ULONG slotIndex = 0UL;
        BOOLEAN levelTie = FALSE;

        RtlZeroMemory(Work->Votes, sizeof(Work->Votes));
        for (recordIndex = 0UL; recordIndex < Work->RecordCount; ++recordIndex) {
            const KSW_INTOBJ_RECORD* record = &Work->Records[recordIndex];
            const ULONG vectorValue = KswIntObjDword(record->Prefix, fieldOffset);
            ULONG arrayIndex = 0UL;

            if (vectorValue >= KSW_INTOBJ_VECTOR_SLOTS || record->Position < vectorValue) {
                continue;
            }
            arrayIndex = record->Position - vectorValue;
            Work->Votes[arrayIndex] = (USHORT)(Work->Votes[arrayIndex] + 1U);
        }
        for (slotIndex = 0UL; slotIndex < KSW_INTOBJ_PRCB_WINDOW_QWORDS; ++slotIndex) {
            const ULONG count = (ULONG)Work->Votes[slotIndex];

            if (count > levelCount) {
                levelCount = count;
                levelIndex = slotIndex;
                levelTie = FALSE;
            }
            else if (count != 0UL && count == levelCount) {
                levelTie = TRUE;
            }
        }
        if (levelCount == 0UL) {
            continue;
        }
        if (levelCount > bestCount) {
            bestCount = levelCount;
            bestIndex = levelIndex;
            bestField = fieldOffset;
            ambiguous = levelTie;
        }
        else if (levelCount == bestCount && (levelTie || levelIndex != bestIndex)) {
            ambiguous = TRUE;
        }
    }

    Step->A = bestCount;
    Step->B = Work->RecordCount;
    if (bestCount < KSW_INTOBJ_MIN_CONFIRMED) {
        Step->Code = KSW_INTOBJ_STEP_NO_TABLE;
        return FALSE;
    }
    if (ambiguous) {
        Step->Code = KSW_INTOBJ_STEP_AMBIGUOUS;
        return FALSE;
    }
    for (recordIndex = 0UL; recordIndex < Work->RecordCount; ++recordIndex) {
        const KSW_INTOBJ_RECORD* record = &Work->Records[recordIndex];

        if (record->Position >= bestIndex && (record->Position - bestIndex) < KSW_INTOBJ_VECTOR_SLOTS) {
            shapedInRange += 1UL;
        }
    }
    Step->A = bestCount;
    Step->B = shapedInRange;
    if (bestCount * 10UL < shapedInRange * 9UL) {
        Step->Code = KSW_INTOBJ_STEP_MIXED;
        return FALSE;
    }
    for (recordIndex = 0UL; recordIndex < Work->RecordCount; ++recordIndex) {
        KSW_INTOBJ_RECORD* record = &Work->Records[recordIndex];
        ULONG slotVector = 0UL;

        record->Matched = FALSE;
        if (record->Position < bestIndex || (record->Position - bestIndex) >= KSW_INTOBJ_VECTOR_SLOTS) {
            continue;
        }
        slotVector = record->Position - bestIndex;
        if (KswIntObjDword(record->Prefix, bestField) == slotVector) {
            record->Matched = TRUE;
            record->Vector = slotVector;
        }
    }
    *ArrayIndexOut = bestIndex;
    *VectorOffsetOut = bestField;
    return TRUE;
}

static BOOLEAN
KswIntObjCollectFromGates(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ const KSW_INTERRUPT_OBJECT_CPU* Cpu,
    _Inout_ KSW_INTOBJ_WORK* Work,
    _Out_ KSW_INTOBJ_STEP* Step
    )
/*++

Routine Description:

    形态 A 第一步：遍历当前 CPU 的 IDT，凡处理函数不在任何模块可执行节里的向量，
    尝试回溯出包含该处理函数的 KINTERRUPT。

Arguments:

    ModuleInfo - 调用方已建好的模块快照。
    Cpu - 当前 CPU 现场（用到 IdtBase / IdtLimit）。
    Work - 工作内存，记录写入 Work->Records。
    Step - 接收失败原因与现场数字。

Return Value:

    TRUE 表示找到至少 KSW_INTOBJ_MIN_CONFIRMED 个对象；否则 FALSE。

--*/
{
    ULONG vectorCount = 0UL;
    ULONG vector = 0UL;
    UCHAR probe[KSW_INTOBJ_PREFIX_BYTES];

    RtlZeroMemory(Step, sizeof(*Step));
    Work->RecordCount = 0UL;
    if (!KswIntObjIsKernelPointer(Cpu->IdtBase)) {
        Step->Code = KSW_INTOBJ_STEP_NO_SOURCE;
        return FALSE;
    }
    vectorCount = (Cpu->IdtLimit + 1UL) / (ULONG)sizeof(KSW_INTOBJ_IDT_GATE);
    if (vectorCount > KSW_INTOBJ_VECTOR_SLOTS) {
        vectorCount = KSW_INTOBJ_VECTOR_SLOTS;
    }
    for (vector = 0UL; vector < vectorCount; ++vector) {
        KSW_INTOBJ_IDT_GATE gate;
        const KSW_HOOK_SYSTEM_MODULE_ENTRY* owner = NULL;
        ULONGLONG handler = 0ULL;
        ULONGLONG base = 0ULL;
        ULONG existing = 0UL;
        BOOLEAN duplicate = FALSE;
        KSW_INTOBJ_RECORD* record = NULL;

        RtlZeroMemory(&gate, sizeof(gate));
        if (!KswordARKHookReadMemorySafe(
                (const VOID*)(ULONG_PTR)(Cpu->IdtBase + ((ULONGLONG)vector * sizeof(gate))),
                &gate,
                sizeof(gate))) {
            continue;
        }
        handler = ((ULONGLONG)gate.OffsetHigh << 32) |
            ((ULONGLONG)gate.OffsetMiddle << 16) |
            (ULONGLONG)gate.OffsetLow;
        if (handler == 0ULL) {
            continue;
        }
        // 处理函数已经落在某个模块的可执行节里：那是形态 B 或普通异常入口，不是内嵌对象。
        owner = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, handler);
        if (owner != NULL &&
            KswordARKImageClassifyAddress(owner, handler, NULL, 0UL, NULL) == KSW_IMAGE_SECTION_RESULT_EXECUTABLE) {
            continue;
        }
        if (!KswIntObjFindEmbeddedBase(handler, &base, probe)) {
            continue;
        }
        for (existing = 0UL; existing < Work->RecordCount; ++existing) {
            if (Work->Records[existing].Address == base) {
                duplicate = TRUE;
                break;
            }
        }
        if (duplicate || Work->RecordCount >= KSW_INTOBJ_MAX_RECORDS) {
            continue;
        }
        record = &Work->Records[Work->RecordCount];
        record->Position = vector;
        record->Vector = 0UL;
        record->Address = base;
        record->Matched = FALSE;
        RtlCopyMemory(record->Prefix, probe, sizeof(record->Prefix));
        Work->RecordCount += 1UL;
    }
    if (Work->RecordCount < KSW_INTOBJ_MIN_CONFIRMED) {
        Step->Code = KSW_INTOBJ_STEP_TOO_FEW;
        Step->A = Work->RecordCount;
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswIntObjVoteEmbedded(
    _Inout_ KSW_INTOBJ_WORK* Work,
    _Out_ ULONG* VectorOffsetOut,
    _Out_ KSW_INTOBJ_STEP* Step
    )
/*++

Routine Description:

    形态 A 第二步：为每个候选 Vector 字段偏移 f 统计"对象里读到的向量值 == 它所在的 IDT
    向量号"的对象数。取最高者（并列取最小偏移，别名偏移对后续检查无影响），要求至少
    KSW_INTOBJ_MIN_CONFIRMED 个且 >= 90% 的对象对得上。

Arguments:

    Work - 工作内存，Records 已由 KswIntObjCollectFromGates 填好。
    VectorOffsetOut - 接收印证用的 Vector 字段偏移。
    Step - 接收失败原因与现场数字。

Return Value:

    TRUE 表示得到互相印证的解（并已把对得上的对象标记为 Matched）。

--*/
{
    ULONG fieldOffset = 0UL;
    ULONG bestCount = 0UL;
    ULONG bestField = 0UL;
    ULONG recordIndex = 0UL;

    RtlZeroMemory(Step, sizeof(*Step));
    for (fieldOffset = KSW_INTOBJ_VECTOR_SCAN_FIRST;
         fieldOffset <= KSW_INTOBJ_VECTOR_SCAN_LAST;
         fieldOffset += (ULONG)sizeof(ULONG)) {
        ULONG matches = 0UL;

        for (recordIndex = 0UL; recordIndex < Work->RecordCount; ++recordIndex) {
            const KSW_INTOBJ_RECORD* record = &Work->Records[recordIndex];

            if (KswIntObjDword(record->Prefix, fieldOffset) == record->Position) {
                matches += 1UL;
            }
        }
        if (matches > bestCount) {
            bestCount = matches;
            bestField = fieldOffset;
        }
    }
    Step->A = bestCount;
    Step->B = Work->RecordCount;
    if (bestCount < KSW_INTOBJ_MIN_CONFIRMED || bestCount * 10UL < Work->RecordCount * 9UL) {
        Step->Code = KSW_INTOBJ_STEP_NO_TABLE;
        return FALSE;
    }
    for (recordIndex = 0UL; recordIndex < Work->RecordCount; ++recordIndex) {
        KSW_INTOBJ_RECORD* record = &Work->Records[recordIndex];

        record->Matched = (KswIntObjDword(record->Prefix, bestField) == record->Position) ? TRUE : FALSE;
        record->Vector = record->Position;
    }
    *VectorOffsetOut = bestField;
    return TRUE;
}

static VOID
KswIntObjMeasureField(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _Inout_ KSW_INTOBJ_WORK* Work,
    _In_ ULONG Offset,
    _Out_ KSW_INTOBJ_FIELD_STATS* Stats
    )
/*++

Routine Description:

    统计一个候选字段偏移在整批已确认对象上的取值：非空数、落在模块可执行节里的数、
    落在核心内核可执行节里的数、不同取值个数。每个不同的值只归属一次。

Arguments:

    ModuleInfo - 调用方已建好的模块快照。
    Work - 工作内存（用到 Records 与 Distinct）。
    Offset - 候选字段偏移。
    Stats - 接收统计结果。

Return Value:

    None.

--*/
{
    ULONG recordIndex = 0UL;
    ULONG distinctIndex = 0UL;

    RtlZeroMemory(Stats, sizeof(*Stats));
    for (recordIndex = 0UL; recordIndex < Work->RecordCount; ++recordIndex) {
        const KSW_INTOBJ_RECORD* record = &Work->Records[recordIndex];
        ULONGLONG value = 0ULL;
        BOOLEAN found = FALSE;

        if (!record->Matched) {
            continue;
        }
        Stats->Objects += 1UL;
        value = KswIntObjQword(record->Prefix, Offset);
        if (value == 0ULL) {
            continue;
        }
        Stats->NonNull += 1UL;
        for (distinctIndex = 0UL; distinctIndex < Stats->Distinct; ++distinctIndex) {
            if (Work->Distinct[distinctIndex].Value == value) {
                Work->Distinct[distinctIndex].Count += 1UL;
                found = TRUE;
                break;
            }
        }
        if (!found && Stats->Distinct < KSW_INTOBJ_MAX_RECORDS) {
            KSW_INTOBJ_DISTINCT* entry = &Work->Distinct[Stats->Distinct];
            const KSW_HOOK_SYSTEM_MODULE_ENTRY* owner = NULL;

            entry->Value = value;
            entry->Count = 1UL;
            entry->Executable = FALSE;
            entry->CoreExecutable = FALSE;
            owner = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, value);
            if (owner != NULL &&
                KswordARKImageClassifyAddress(owner, value, NULL, 0UL, NULL) == KSW_IMAGE_SECTION_RESULT_EXECUTABLE) {
                entry->Executable = TRUE;
                entry->CoreExecutable = KswordARKDriverIntegrityIsCoreKernelModule(owner);
            }
            Stats->Distinct += 1UL;
        }
    }
    for (distinctIndex = 0UL; distinctIndex < Stats->Distinct; ++distinctIndex) {
        if (Work->Distinct[distinctIndex].Executable) {
            Stats->Executable += Work->Distinct[distinctIndex].Count;
        }
        if (Work->Distinct[distinctIndex].CoreExecutable) {
            Stats->CoreExecutable += Work->Distinct[distinctIndex].Count;
        }
    }
}

static BOOLEAN
KswIntObjVerifyFields(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _Inout_ KSW_INTOBJ_WORK* Work,
    _Inout_ KSW_INTERRUPT_OBJECT_LAYOUT* Layout,
    _Out_ KSW_INTOBJ_STEP* Step
    )
/*++

Routine Description:

    对已确认的对象批验证 ServiceRoutine 偏移（必须），并尽力验证 MessageServiceRoutine 与
    DispatchAddress 偏移（各自失败只会让该字段不被检查）。

Arguments:

    ModuleInfo - 调用方已建好的模块快照。
    Work - 工作内存，Records 中 Matched 的对象构成这批样本。
    Layout - 输入已含 Form / Vector 偏移；接收 Service / Message / Dispatch 结论。
    Step - ServiceRoutine 验证失败时接收现场数字。

Return Value:

    TRUE 表示 ServiceRoutine 偏移已验证。

--*/
{
    KSW_INTOBJ_FIELD_STATS stats;

    RtlZeroMemory(Step, sizeof(*Step));

    // ServiceRoutine：>= 2 个非空且 >= 1/4 对象非空，**过半**非空值落在模块可执行节，且取值不全相同。
    // 这里判的是"这个偏移对不对"，必须与"值干不干净"解耦：如果要求 90% 落在可执行节，
    // 在 <= 9 个非空指针的批里，一个被劫持的指针就会让验证失败，检测器反而只会说
    // "布局未验证"，恰好放过它要抓的那个 Hook。过半 + 取值不全相同足以确认偏移，
    // 之后偏离的指针会被逐个判为异常。
    KswIntObjMeasureField(ModuleInfo, Work, KSW_INTOBJ_SERVICE_CANDIDATE, &stats);
    Step->A = stats.NonNull;
    Step->B = stats.Executable;
    Step->C = stats.Distinct;
    Step->D = stats.Objects;
    if (stats.Objects < KSW_INTOBJ_MIN_CONFIRMED ||
        stats.NonNull < 2UL ||
        stats.NonNull * 4UL < stats.Objects ||
        stats.Executable * 2UL <= stats.NonNull ||
        stats.Distinct < 2UL) {
        Step->Code = KSW_INTOBJ_STEP_SERVICE;
        return FALSE;
    }
    Layout->ServiceOffset = KSW_INTOBJ_SERVICE_CANDIDATE;

    // MessageServiceRoutine：紧随其后的指针槽位；全空则没有可验证的数据。
    Layout->MessageOffset = 0UL;
    KswIntObjMeasureField(ModuleInfo, Work, KSW_INTOBJ_SERVICE_CANDIDATE + (ULONG)sizeof(ULONGLONG), &stats);
    // 单个样本不足以确认一个偏移：至少 3 个非空、取值不全相同，才允许把它当成
    // MessageServiceRoutine 去逐对象判定（否则某个碰巧含代码指针的字段会被永久缓存成"已验证"，
    // 之后每个 CPU 上的合法数据都被标成隐藏行为）。样本不够就当没有可验证的数据。
    if (stats.NonNull < 3UL || stats.Distinct < 2UL) {
        Layout->MessageState = KSW_INTOBJ_FIELD_NO_SAMPLE;
    }
    else if (stats.Executable * 10UL >= stats.NonNull * 8UL) {
        Layout->MessageState = KSW_INTOBJ_FIELD_VERIFIED;
        Layout->MessageOffset = KSW_INTOBJ_SERVICE_CANDIDATE + (ULONG)sizeof(ULONGLONG);
    }
    else {
        Layout->MessageState = KSW_INTOBJ_FIELD_VALUES_REJECTED;
    }

    // DispatchAddress：>= 90% 对象非空，且 >= 90% 的非空值落在核心内核（nt/hal）可执行节里。
    // 与 ServiceRoutine 同一档容忍度：批里若恰好混进个别被改的对象，验证仍能通过，
    // 那几个对象随后会被逐个判为异常，而不是把整个字段吞成"未验证"。
    Layout->DispatchOffset = 0UL;
    KswIntObjMeasureField(ModuleInfo, Work, KSW_INTOBJ_DISPATCH_CANDIDATE, &stats);
    if (stats.NonNull == 0UL) {
        Layout->DispatchState = KSW_INTOBJ_FIELD_NO_SAMPLE;
    }
    else if (stats.NonNull >= KSW_INTOBJ_MIN_CONFIRMED &&
             stats.NonNull * 10UL >= stats.Objects * 9UL &&
             stats.CoreExecutable * 10UL >= stats.NonNull * 9UL) {
        Layout->DispatchState = KSW_INTOBJ_FIELD_VERIFIED;
        Layout->DispatchOffset = KSW_INTOBJ_DISPATCH_CANDIDATE;
    }
    else {
        Layout->DispatchState = KSW_INTOBJ_FIELD_VALUES_REJECTED;
    }
    return TRUE;
}

static BOOLEAN
KswIntObjResolveLayout(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ const KSW_INTERRUPT_OBJECT_CPU* Cpu,
    _Out_ KSW_INTERRUPT_OBJECT_LAYOUT* Layout,
    _Out_ KSW_INTOBJ_DIAG* Diag
    )
/*++

Routine Description:

    先试形态 B（KPRCB 里的向量索引数组），不成再试形态 A（网关处理函数内嵌在对象里）。
    每一形态都必须：找到互相印证的对象批，再验证 ServiceRoutine 偏移。

Arguments:

    ModuleInfo - 调用方已建好的模块快照。
    Cpu - 当前 CPU 现场。
    Layout - 成功时接收布局。
    Diag - 接收两种形态各自的结论（用于失败说明）。

Return Value:

    TRUE 表示布局已验证。

--*/
{
    KSW_INTOBJ_WORK* work = NULL;
    ULONG arrayIndex = 0UL;
    ULONG vectorOffset = 0UL;
    BOOLEAN resolved = FALSE;

    RtlZeroMemory(Layout, sizeof(*Layout));
    RtlZeroMemory(Diag, sizeof(*Diag));
    work = (KSW_INTOBJ_WORK*)KswordARKAllocateNonPagedPool(sizeof(*work), KSW_INTOBJ_TAG);
    if (work == NULL) {
        Diag->Prcb.Code = KSW_INTOBJ_STEP_NO_MEMORY;
        Diag->Embedded.Code = KSW_INTOBJ_STEP_NO_MEMORY;
        return FALSE;
    }

    // 形态 B。
    RtlZeroMemory(work, sizeof(*work));
    if (KswIntObjCollectFromPrcb(Cpu->PrcbAddress, work, &Diag->Prcb) &&
        KswIntObjVotePrcbArray(work, &arrayIndex, &vectorOffset, &Diag->Prcb)) {
        Layout->Form = KSW_INTOBJ_FORM_PRCB_ARRAY;
        Layout->PrcbArrayOffset = arrayIndex * (ULONG)sizeof(ULONGLONG);
        Layout->VectorFieldOffset = vectorOffset;
        if (KswIntObjVerifyFields(ModuleInfo, work, Layout, &Diag->Prcb)) {
            resolved = TRUE;
        }
    }

    // 形态 A：只在形态 B 没能验证时才尝试。
    if (!resolved) {
        RtlZeroMemory(Layout, sizeof(*Layout));
        RtlZeroMemory(work, sizeof(*work));
        if (KswIntObjCollectFromGates(ModuleInfo, Cpu, work, &Diag->Embedded) &&
            KswIntObjVoteEmbedded(work, &vectorOffset, &Diag->Embedded)) {
            Layout->Form = KSW_INTOBJ_FORM_EMBEDDED;
            Layout->VectorFieldOffset = vectorOffset;
            if (KswIntObjVerifyFields(ModuleInfo, work, Layout, &Diag->Embedded)) {
                resolved = TRUE;
            }
        }
    }

    ExFreePoolWithTag(work, KSW_INTOBJ_TAG);
    if (!resolved) {
        RtlZeroMemory(Layout, sizeof(*Layout));
    }
    return resolved;
}

static BOOLEAN
KswIntObjLoadCache(
    _Out_ KSW_INTERRUPT_OBJECT_LAYOUT* LayoutOut
    )
/*++

Routine Description:

    读取文件级布局缓存（只在已发布时命中）。

Arguments:

    LayoutOut - 命中时接收缓存的布局。

Return Value:

    TRUE 表示命中。

--*/
{
    if (InterlockedCompareExchange(&g_KswIntObjLayoutCacheState, 2L, 2L) != 2L) {
        return FALSE;
    }
    *LayoutOut = g_KswIntObjLayoutCache;
    return TRUE;
}

static VOID
KswIntObjPublishCache(
    _In_ const KSW_INTERRUPT_OBJECT_LAYOUT* Layout
    )
/*++

Routine Description:

    一次性发布验证过的布局；已有人在发布或已发布时静默放弃。

Arguments:

    Layout - 已验证的布局。

Return Value:

    None.

--*/
{
    if (InterlockedCompareExchange(&g_KswIntObjLayoutCacheState, 1L, 0L) != 0L) {
        return;
    }
    g_KswIntObjLayoutCache = *Layout;
    (VOID)InterlockedExchange(&g_KswIntObjLayoutCacheState, 2L);
}

static VOID
KswIntObjDescribeStep(
    _Out_writes_(Chars) PWCHAR Output,
    _In_ ULONG Chars,
    _In_ BOOLEAN Embedded,
    _In_ const KSW_INTOBJ_STEP* Step
    )
/*++

Routine Description:

    把一步解析的结论写成一小段英文说明（每段不超过 KSW_INTOBJ_NOTE_CHARS - 1 个字符）。

Arguments:

    Output - 输出缓冲。
    Chars - 输出容量（字符数）。
    Embedded - TRUE 表示这是形态 A 的结论。
    Step - 待描述的结论。

Return Value:

    None.

--*/
{
    switch (Step->Code) {
    case KSW_INTOBJ_STEP_NO_SOURCE:
        KswordARKDriverIntegrityCopyWide(Output, Chars, Embedded ? L"IDT not readable" : L"PRCB pointer unusable");
        break;
    case KSW_INTOBJ_STEP_UNREADABLE:
        KswordARKDriverIntegrityCopyWide(Output, Chars, L"PRCB window not readable");
        break;
    case KSW_INTOBJ_STEP_TOO_FEW:
        KswIntObjFormatDetail(Output, Chars, L"only %lu KINTERRUPT-like objects, %lu list-rejected", Step->A, Step->B);
        break;
    case KSW_INTOBJ_STEP_TOO_MANY:
        KswIntObjFormatDetail(Output, Chars, L"more than %lu candidate objects", Step->A);
        break;
    case KSW_INTOBJ_STEP_NO_TABLE:
        KswIntObjFormatDetail(Output, Chars, L"no vector-corroborated table (best %lu/%lu)", Step->A, Step->B);
        break;
    case KSW_INTOBJ_STEP_AMBIGUOUS:
        KswIntObjFormatDetail(Output, Chars, L"table start not unique (best %lu)", Step->A);
        break;
    case KSW_INTOBJ_STEP_MIXED:
        KswIntObjFormatDetail(Output, Chars, L"table mixed (%lu of %lu match)", Step->A, Step->B);
        break;
    case KSW_INTOBJ_STEP_SERVICE:
        KswIntObjFormatDetail(Output, Chars, L"ServiceRoutine unproven nn=%lu ex=%lu dist=%lu n=%lu", Step->A, Step->B, Step->C, Step->D);
        break;
    case KSW_INTOBJ_STEP_NO_MEMORY:
        KswordARKDriverIntegrityCopyWide(Output, Chars, L"out of memory");
        break;
    case KSW_INTOBJ_STEP_OK:
    default:
        KswordARKDriverIntegrityCopyWide(Output, Chars, L"not tried");
        break;
    }
}

static PCWSTR
KswIntObjFieldStateText(
    _In_ ULONG State
    )
/*++

Routine Description:

    把附加字段的验证结论转成英文短语。

Arguments:

    State - KSW_INTOBJ_FIELD_* 之一。

Return Value:

    静态英文短语。

--*/
{
    if (State == KSW_INTOBJ_FIELD_VERIFIED) {
        return L"verified";
    }
    if (State == KSW_INTOBJ_FIELD_NO_SAMPLE) {
        return L"not verified (no non-null sample)";
    }
    return L"not verified (values outside module code)";
}

static VOID
KswIntObjEmitInfoRow(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ const KSW_INTERRUPT_OBJECT_CPU* Cpu,
    _In_z_ PCWSTR Detail
    )
/*++

Routine Description:

    产出一行说明性证据：LAYOUT_UNVERIFIED，非 CPU 行，ordinal 为 ~0UL。
    这一行只是参考信息，绝不当作"被劫持"的证据。

Arguments:

    Builder - 响应构建器。
    Cpu - 尝试解析时所在的 CPU 现场（PRCB 地址作为取证线索）。
    Detail - 英文说明。

Return Value:

    None.

--*/
{
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;

    row = KswordARKDriverIntegrityAddEvidence(
        Builder,
        KSWORD_ARK_DRIVER_INTEGRITY_CLASS_INTERRUPT_OBJECT,
        Cpu->PrcbAddress,
        0ULL,
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_LAYOUT_UNVERIFIED,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT,
        40UL,
        ~0UL,
        ~0UL,
        ~0UL,
        NULL,
        Detail);
    if (row != NULL) {
        row->ordinal = KSW_INTOBJ_ORDINAL_NONE;
    }
}

static VOID
KswIntObjPrepareContext(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _Inout_ KSW_INTERRUPT_OBJECT_CONTEXT* Context,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ const KSW_INTERRUPT_OBJECT_CPU* Cpu
    )
/*++

Routine Description:

    首次使用时确定布局：先看文件级缓存，未命中再运行时解析并验证。
    验证不过就把上下文置为 FAILED 并产出唯一一行说明；验证通过但附加字段没能验证时，
    另产出一行"部分可用"的说明。

Arguments:

    Builder - 响应构建器。
    Context - 本次查询的共享状态。
    ModuleInfo - 调用方已建好的模块快照。
    Cpu - 触发解析的 CPU 现场。

Return Value:

    None.

--*/
{
    KSW_INTERRUPT_OBJECT_LAYOUT layout;
    KSW_INTOBJ_DIAG diag;
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    WCHAR prcbText[KSW_INTOBJ_NOTE_CHARS] = { 0 };
    WCHAR embeddedText[KSW_INTOBJ_NOTE_CHARS] = { 0 };

    RtlZeroMemory(&layout, sizeof(layout));
    RtlZeroMemory(&diag, sizeof(diag));
    if (KswIntObjLoadCache(&layout)) {
        Context->Layout = layout;
        Context->State = KSW_INTOBJ_STATE_READY;
    }
    else if (KswIntObjResolveLayout(ModuleInfo, Cpu, &layout, &diag)) {
        Context->Layout = layout;
        Context->State = KSW_INTOBJ_STATE_READY;
        // 只缓存三个字段都验证过的完整布局。附加字段这次没验证出来（批里恰好没有 MSI 对象、
        // 或混进了被改的对象）不该被永久定格，下次查询重新解析还有机会补全。
        if (layout.MessageState == KSW_INTOBJ_FIELD_VERIFIED &&
            layout.DispatchState == KSW_INTOBJ_FIELD_VERIFIED) {
            KswIntObjPublishCache(&layout);
        }
    }
    else {
        // 失败即关闭：只产出这一行，此后的调用一律静默。
        Context->State = KSW_INTOBJ_STATE_FAILED;
        KswIntObjDescribeStep(prcbText, RTL_NUMBER_OF(prcbText), FALSE, &diag.Prcb);
        KswIntObjDescribeStep(embeddedText, RTL_NUMBER_OF(embeddedText), TRUE, &diag.Embedded);
        KswIntObjFormatDetail(
            detail,
            RTL_NUMBER_OF(detail),
            L"Interrupt-object secondary check unavailable: layout not verified, no hijack verdict. PRCB table: %ls; embedded: %ls.",
            prcbText,
            embeddedText);
        KswIntObjEmitInfoRow(Builder, Cpu, detail);
        return;
    }

    if (Context->Layout.MessageState != KSW_INTOBJ_FIELD_VERIFIED ||
        Context->Layout.DispatchState != KSW_INTOBJ_FIELD_VERIFIED) {
        KswIntObjFormatDetail(
            detail,
            RTL_NUMBER_OF(detail),
            L"Interrupt-object check is partial: MessageServiceRoutine offset %ls; DispatchAddress offset %ls.",
            KswIntObjFieldStateText(Context->Layout.MessageState),
            KswIntObjFieldStateText(Context->Layout.DispatchState));
        KswIntObjEmitInfoRow(Builder, Cpu, detail);
    }
}

static VOID
KswIntObjEmitFieldRow(
    _In_ const KSW_INTOBJ_EMIT* Emit,
    _In_ ULONGLONG ObjectAddress,
    _In_ ULONG ChainIndex,
    _In_ ULONG Ordinal,
    _In_z_ PCWSTR FieldName,
    _In_ ULONGLONG Pointer
    )
/*++

Routine Description:

    产出 ServiceRoutine / MessageServiceRoutine 的证据行。判定不用"必须在 nt"：
    ISR 合法地可以在任何驱动里。指针不在任何已加载模块内 -> MODULE_UNRESOLVED|HIDDEN_HOOK；
    落在模块内但不在其可执行节 -> TARGET_NON_EXEC|HIDDEN_HOOK；其余为干净。
    节归类结果为 UNKNOWN（PE 头读不到）时无法下结论，按干净处理并在 detail 里如实写 n/a。

Arguments:

    Emit - 产出现场。
    ObjectAddress - 中断对象地址。
    ChainIndex - 该对象在同向量共享链上的序号。
    Ordinal - 0 = ServiceRoutine，1 = MessageServiceRoutine。
    FieldName - 字段英文名。
    Pointer - 该字段的值（非空）。

Return Value:

    None.

--*/
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* owner = NULL;
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    ULONG sectionResult = KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    PCWSTR note = NULL;
    WCHAR sectionName[KSW_IMAGE_SECTION_NAME_CHARS] = { 0 };
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };

    Emit->Context->CheckedPointers += 1UL;
    owner = KswordARKDriverIntegrityFindModuleForAddress(Emit->ModuleInfo, Pointer);
    if (owner == NULL) {
        riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED | KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK;
    }
    else {
        sectionResult = KswordARKImageClassifyAddress(
            owner, Pointer, sectionName, RTL_NUMBER_OF(sectionName), NULL);
        if (sectionResult == KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE ||
            sectionResult == KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS) {
            riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC | KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK;
        }
        else if (sectionResult == KSW_IMAGE_SECTION_RESULT_UNKNOWN) {
            /* 节归类不出来（PE 头读不到）：既不能指控，也不能算"干净"，标成无法判断。 */
            riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE;
        }
    }
    if (riskFlags == KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE) {
        /* 干净的指针不占证据行预算，计入整次查询的汇总行。 */
        return;
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK) != 0UL) {
        Emit->Context->AnomalousPointers += 1UL;
    }
    else {
        Emit->Context->UnclassifiedPointers += 1UL;
    }
    if (riskFlags == KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE) {
        note = L"Section class unavailable (PE headers unreadable); not judged.";
    }
    else if (Emit->GateClean) {
        // 一级看起来干净、二级被改：这正是"隐藏行为"。
        note = L"HIDDEN: gate looks clean but the secondary pointer is hijacked.";
    }
    else {
        note = L"Secondary pointer is anomalous; the gate is flagged too.";
    }
    KswIntObjFormatDetail(
        detail,
        RTL_NUMBER_OF(detail),
        L"INTOBJ vec=%lu kint=0x%llX chain=%lu %ls=0x%llX section=%ls(%lu) gate=0x%llX %ls. %ls",
        Emit->Vector,
        ObjectAddress,
        ChainIndex,
        FieldName,
        Pointer,
        (sectionName[0] != L'\0') ? sectionName : L"n/a",
        sectionResult,
        Emit->GateHandler,
        Emit->GateClean ? L"clean" : L"flagged",
        note);
    row = KswordARKDriverIntegrityAddEvidence(
        Emit->Builder,
        KSWORD_ARK_DRIVER_INTEGRITY_CLASS_INTERRUPT_OBJECT,
        ObjectAddress,
        Pointer,
        riskFlags,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
        80UL,
        Emit->Cpu->ProcessorGroup,
        Emit->Cpu->ProcessorNumber,
        Emit->Vector,
        owner,
        detail);
    if (row != NULL) {
        row->ordinal = Ordinal;
    }
}

static VOID
KswIntObjEmitDispatchRow(
    _In_ const KSW_INTOBJ_EMIT* Emit,
    _In_ ULONGLONG ObjectAddress,
    _In_ ULONG ChainIndex,
    _In_ ULONGLONG Pointer
    )
/*++

Routine Description:

    DispatchAddress（ordinal 2）：它应该落在核心内核（nt/hal）的可执行节里。
    只在异常或无法判断时产出一行，别制造 256 x CPU 数的噪声行——但"无法判断"不等于"干净"，
    节归类 UNKNOWN（PE 头读不到）时必须像 KswIntObjEmitFieldRow 那样标 UNAVAILABLE 并出一行，
    不能悄悄地把"读不出所在节"和"验证过确实在可执行节"归成同一个"不出行"的结果。

Arguments:

    Emit - 产出现场。
    ObjectAddress - 中断对象地址。
    ChainIndex - 该对象在同向量共享链上的序号。
    Pointer - DispatchAddress 的值（非空）。

Return Value:

    None.

--*/
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* owner = NULL;
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    ULONG sectionResult = KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    PCWSTR note = NULL;
    WCHAR sectionName[KSW_IMAGE_SECTION_NAME_CHARS] = { 0 };
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };

    // 每个被实际读取并分类过的 DispatchAddress 都要计数——不管结论是异常、无法判断还是干净，
    // 汇总行的"核对过 N 个二级指针"必须反映真实核对量，不能只数 ServiceRoutine/Message 两种。
    Emit->Context->CheckedPointers += 1UL;
    owner = KswordARKDriverIntegrityFindModuleForAddress(Emit->ModuleInfo, Pointer);
    if (owner == NULL) {
        riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH |
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED |
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK;
    }
    else {
        sectionResult = KswordARKImageClassifyAddress(
            owner, Pointer, sectionName, RTL_NUMBER_OF(sectionName), NULL);
        if (!KswordARKDriverIntegrityIsCoreKernelModule(owner) ||
            sectionResult == KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE ||
            sectionResult == KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS) {
            riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH | KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK;
        }
        else if (sectionResult == KSW_IMAGE_SECTION_RESULT_UNKNOWN) {
            /* 落在核心模块内，但节归类读不出来：不能算验证过在可执行节，标"无法判断"。 */
            riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE;
        }
    }
    if (riskFlags == KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE) {
        return;
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK) != 0UL) {
        Emit->Context->AnomalousPointers += 1UL;
    }
    else {
        Emit->Context->UnclassifiedPointers += 1UL;
    }
    if (riskFlags == KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE) {
        note = L"Section class unavailable (PE headers unreadable); not judged.";
    }
    else {
        note = Emit->GateClean
            ? L"HIDDEN: gate looks clean but DispatchAddress is outside core kernel code."
            : L"DispatchAddress is outside core kernel code; the gate is flagged too.";
    }
    KswIntObjFormatDetail(
        detail,
        RTL_NUMBER_OF(detail),
        L"INTOBJ vec=%lu kint=0x%llX chain=%lu DispatchAddress=0x%llX section=%ls(%lu) gate=0x%llX %ls. %ls",
        Emit->Vector,
        ObjectAddress,
        ChainIndex,
        Pointer,
        (sectionName[0] != L'\0') ? sectionName : L"n/a",
        sectionResult,
        Emit->GateHandler,
        Emit->GateClean ? L"clean" : L"flagged",
        note);
    row = KswordARKDriverIntegrityAddEvidence(
        Emit->Builder,
        KSWORD_ARK_DRIVER_INTEGRITY_CLASS_INTERRUPT_OBJECT,
        ObjectAddress,
        Pointer,
        riskFlags,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
        80UL,
        Emit->Cpu->ProcessorGroup,
        Emit->Cpu->ProcessorNumber,
        Emit->Vector,
        owner,
        detail);
    if (row != NULL) {
        row->ordinal = 2UL;
    }
}

#endif

VOID
KswordARKInterruptObjectContextInitialize(
    _Out_ KSW_INTERRUPT_OBJECT_CONTEXT* Context
    )
/*++

Routine Description:

    把一次查询共享的上下文清零（状态 IDLE，尚未尝试解析布局）。

Arguments:

    Context - 待初始化的上下文。

Return Value:

    None.

--*/
{
    if (Context == NULL) {
        return;
    }
    RtlZeroMemory(Context, sizeof(*Context));
}

VOID
KswordARKInterruptObjectEmitForVector(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _Inout_ KSW_INTERRUPT_OBJECT_CONTEXT* Context,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ const KSW_INTERRUPT_OBJECT_CPU* Cpu,
    _In_ ULONG Vector,
    _In_ ULONGLONG GateHandler,
    _In_ ULONG GateRiskFlags
    )
/*++

Routine Description:

    沿一个 IDT 向量走到它的中断对象，读出二级指针并产出证据行。首次调用时按需解析并
    验证布局；布局没验证过就只产出一行说明，之后静默返回。每个对象都要重新通过形状
    与向量号校验才会被读取；不满足的槽位静默跳过（不下结论）。
    同一向量上沿 InterruptListEntry 走共享链（最多 KSW_INTOBJ_CHAIN_LIMIT 个，且每个邻居
    自己记的向量号必须与本向量相同，否则视为链表并不表示同向量共享，立即停止）。

Arguments:

    Builder - 响应构建器。
    Context - 本次查询的共享状态。
    ModuleInfo - 调用方已建好的模块快照（不重建）。
    Cpu - 该 CPU 在绑定亲和性期间取到的现场。
    Vector - IDT 向量号。
    GateHandler - 该向量 IDT 网关解出的处理函数地址。
    GateRiskFlags - 该向量网关行的风险位。

Return Value:

    None.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    KSW_INTERRUPT_OBJECT_LAYOUT layout;
    KSW_INTOBJ_EMIT emit;
    UCHAR prefix[KSW_INTOBJ_PREFIX_BYTES];
    ULONGLONG head = 0ULL;
    ULONGLONG current = 0ULL;
    ULONG chainIndex = 0UL;

    if (Builder == NULL || Context == NULL || Cpu == NULL || Vector >= KSW_INTOBJ_VECTOR_SLOTS) {
        return;
    }
    /*
     * 没有模块快照就没法把任何 ISR 指针归属到模块：这时逐个判会把每个非空指针都当成
     * "不在任何模块里"，在干净的机器上制造满屏的隐藏行为。缺证据就不下结论。
     */
    if (ModuleInfo == NULL || ModuleInfo->NumberOfModules == 0UL) {
        return;
    }
    if (Context->State == KSW_INTOBJ_STATE_FAILED) {
        return;
    }
    if (Context->State == KSW_INTOBJ_STATE_IDLE) {
        KswIntObjPrepareContext(Builder, Context, ModuleInfo, Cpu);
        if (Context->State != KSW_INTOBJ_STATE_READY) {
            return;
        }
    }
    layout = Context->Layout;

    RtlZeroMemory(&emit, sizeof(emit));
    emit.Builder = Builder;
    emit.Context = Context;
    emit.ModuleInfo = ModuleInfo;
    emit.Cpu = Cpu;
    emit.Vector = Vector;
    emit.GateHandler = GateHandler;
    // 一级是否干净：网关行没有任何一级风险位。
    emit.GateClean = ((GateRiskFlags &
        (KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED |
         KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED |
         KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER |
         KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID |
         KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_BASELINE_CHANGED |
         KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC)) == 0UL) ? TRUE : FALSE;

    if (layout.Form == KSW_INTOBJ_FORM_PRCB_ARRAY) {
        ULONGLONG slotAddress = 0ULL;

        if (!KswIntObjIsKernelPointer(Cpu->PrcbAddress) ||
            Cpu->PrcbAddress > MAXULONGLONG - ((ULONGLONG)layout.PrcbArrayOffset + (KSW_INTOBJ_VECTOR_SLOTS * sizeof(ULONGLONG)))) {
            return;
        }
        slotAddress = Cpu->PrcbAddress + (ULONGLONG)layout.PrcbArrayOffset + ((ULONGLONG)Vector * sizeof(ULONGLONG));
        if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)slotAddress, &head, sizeof(head))) {
            return;
        }
    }
    else if (layout.Form == KSW_INTOBJ_FORM_EMBEDDED) {
        const KSW_HOOK_SYSTEM_MODULE_ENTRY* gateOwner = NULL;

        if (GateHandler == 0ULL) {
            return;
        }
        // 处理函数已落在模块可执行节里的向量不是内嵌对象。
        gateOwner = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, GateHandler);
        if (gateOwner != NULL &&
            KswordARKImageClassifyAddress(gateOwner, GateHandler, NULL, 0UL, NULL) == KSW_IMAGE_SECTION_RESULT_EXECUTABLE) {
            return;
        }
        if (!KswIntObjFindEmbeddedBase(GateHandler, &head, prefix)) {
            return;
        }
    }
    else {
        return;
    }
    if (head == 0ULL) {
        return;
    }

    current = head;
    for (chainIndex = 0UL; chainIndex < KSW_INTOBJ_CHAIN_LIMIT; ++chainIndex) {
        ULONGLONG service = 0ULL;
        ULONGLONG flink = 0ULL;
        ULONGLONG next = 0ULL;

        // 不满足形状或向量号的槽位不下结论，静默跳过。
        if (!KswIntObjReadObject(current, prefix, NULL) ||
            KswIntObjDword(prefix, layout.VectorFieldOffset) != Vector) {
            break;
        }
        if (chainIndex == 0UL) {
            Context->CheckedVectors += 1UL;
        }
        service = KswIntObjQword(prefix, layout.ServiceOffset);
        if (service != 0ULL) {
            KswIntObjEmitFieldRow(&emit, current, chainIndex, 0UL, L"ServiceRoutine", service);
        }
        if (layout.MessageState == KSW_INTOBJ_FIELD_VERIFIED) {
            const ULONGLONG message = KswIntObjQword(prefix, layout.MessageOffset);

            if (message != 0ULL) {
                KswIntObjEmitFieldRow(&emit, current, chainIndex, 1UL, L"MessageServiceRoutine", message);
            }
        }
        if (layout.DispatchState == KSW_INTOBJ_FIELD_VERIFIED) {
            const ULONGLONG dispatch = KswIntObjQword(prefix, layout.DispatchOffset);

            if (dispatch != 0ULL) {
                KswIntObjEmitDispatchRow(&emit, current, chainIndex, dispatch);
            }
        }

        // 共享链：自环 / 空链到此为止；绕回链头也停。
        flink = KswIntObjQword(prefix, KSW_INTOBJ_LIST_OFFSET);
        if (flink == 0ULL || flink == current + KSW_INTOBJ_LIST_OFFSET || flink < KSW_INTOBJ_LIST_OFFSET) {
            break;
        }
        next = flink - KSW_INTOBJ_LIST_OFFSET;
        if (next == head) {
            break;
        }
        current = next;
    }
#else
    UNREFERENCED_PARAMETER(Builder);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ModuleInfo);
    UNREFERENCED_PARAMETER(Cpu);
    UNREFERENCED_PARAMETER(Vector);
    UNREFERENCED_PARAMETER(GateHandler);
    UNREFERENCED_PARAMETER(GateRiskFlags);
#endif
}

VOID
KswordARKInterruptObjectEmitSummary(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ const KSW_INTERRUPT_OBJECT_CONTEXT* Context
    )
/*++

Routine Description:

    整次查询收尾时产出一行汇总（ordinal 3）。这是"没发现隐藏行为"这个结论的证据：
    干净的二级指针不再各占一行，否则每 CPU 每向量一行会把 4096 行预算挤光，
    让靠后的 CPU 上的劫持行被截断。布局没验证过、或一个向量都没核对到，就不产出——
    没做过检查，就不能出一行看起来像"检查过了、干净"的证据。

Arguments:

    Builder - 响应构建器。
    Context - 本次查询的共享状态。

Return Value:

    None.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;

    if (Builder == NULL || Context == NULL ||
        Context->State != KSW_INTOBJ_STATE_READY || Context->CheckedVectors == 0UL) {
        return;
    }
    KswIntObjFormatDetail(
        detail,
        RTL_NUMBER_OF(detail),
        L"INTOBJ summary: checked %lu vectors, %lu secondary pointers; hidden-hook anomalies=%lu, unclassified=%lu.",
        Context->CheckedVectors,
        Context->CheckedPointers,
        Context->AnomalousPointers,
        Context->UnclassifiedPointers);
    row = KswordARKDriverIntegrityAddEvidence(
        Builder,
        KSWORD_ARK_DRIVER_INTEGRITY_CLASS_INTERRUPT_OBJECT,
        0ULL,
        0ULL,
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
        80UL,
        ~0UL,
        ~0UL,
        ~0UL,
        NULL,
        detail);
    if (row != NULL) {
        row->ordinal = 3UL;
    }
#else
    UNREFERENCED_PARAMETER(Builder);
    UNREFERENCED_PARAMETER(Context);
#endif
}
