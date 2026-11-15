#include "kernel_noattach.h"
#include "kernel_noattach_symbols.h"
#include "../../platform/runtime_signature_scan.h"
#include <ntimage.h>
#include <intrin.h>

/* 每个私有入口都属于一个完整映像身份，不能只按 Windows build 选择。 */
typedef struct _KNA_IMAGE_PROFILE
{
    /* PE 时间戳与映像长度首先约束候选。 */
    ULONG Stamp, Bytes;
    /* CodeView GUID 和 age 共同阻止跨修订号误用。 */
    UCHAR Rsds[20];
    /* 五参异常入口、三参读取和五参写回均分别核对。 */
    ULONG Dispatch, From, To;
    /* 两个线程计数例程的对象参数和返回值均已核对。 */
    ULONG Suspend, Resume;
    /* 缓冲区访问模式与所需现场模式必须分别传入已验证的五参内部入口。 */
    ULONG GetContext, SetContext;
} KNA_IMAGE_PROFILE;
/* 9711 由精确 PDB 与调用点核对；9974 由完整函数及全部直接被调函数差分核对。 */
static const KNA_IMAGE_PROFILE KnaProfiles[] = {
    /* OS 26300 / ntoskrnl 26100.9711：PDB B661C6FE72991D160FE37C48B8BC5470 age 1。 */
    {2952155935UL, 21299200UL,
     {0xFE,0xC6,0x61,0xB6,0x99,0x72,0x16,0x1D,0x0F,0xE3,0x7C,0x48,0xB8,0xBC,0x54,0x70,1,0,0,0},
     0x3D7650UL, 0x3D9380UL, 0x4FD790UL, 0xA110D0UL, 0xA4A920UL, 0x8D4770UL, 0x8D4420UL},
    /* OS 26300 / ntoskrnl 26100.9974：PDB CE884F70F5A9025D53DB35D8BE8BFF79 age 1。 */
    {1718926174UL, 21299200UL,
     {0x70,0x4F,0x88,0xCE,0xA9,0xF5,0x5D,0x02,0x53,0xDB,0x35,0xD8,0xBE,0x8B,0xFF,0x79,1,0,0,0},
     0x3E0270UL, 0x3E1FA0UL, 0x4FEDF0UL, 0x8A7210UL, 0xA49600UL, 0x90CA70UL, 0x90C720UL}
};
/* 已核对的当前映像配置在同次启动内不可更换。 */
static const KNA_IMAGE_PROFILE *KnaProfile;
/* 版本核对在普通内核执行，从不在候选地址上直接 memcpy。 */
static PUCHAR KnaNt;
/* 转接器保留到本次启动结束，不能用固定延时假定晚到调用已经消失。 */
static KNA_DISPATCH KnaOriginal;
/* 记录准确的 KMDF 卸载所有者，供共享 HVM 卸载门复用。 */
static PDRIVER_OBJECT KnaDriver;
/* 永久留驻只能移除自己观察到的那个槽位。 */
static PDRIVER_UNLOAD KnaUnload;
/* 明确的留驻和入口安装状态。 */
static volatile LONG KnaPinned, KnaInstalled, KnaBridgeReady;
/* 入口只原子替换一个完整指令，前方转接区从未包含活跃指令。 */
static const USHORT KnaOriginalWord = 0x5540;
/* EB EE 从入口跳到入口之前十六字节的已验证填充区。 */
static const USHORT KnaHookWord = 0xEEEB;

/* 从命名导出取得指针，绝不接受用户提供的内核函数地址。 */
static PVOID KnaExport(PCWSTR Name)
{
    /* 导出名称在调用期间始终有效。 */
    UNICODE_STRING name;
    /* 绑定准确的例程名称。 */
    RtlInitUnicodeString(&name, Name);
    /* 缺失以能力不可用返回。 */
    return MmGetSystemRoutineAddress(&name);
}

/* 函数地址以当前内核基址和已匹配的映像身份共同约束。 */
static BOOLEAN KnaImage(VOID)
{
    /* 查询正式的已加载映像归属。 */
    PVOID base = NULL;
    /* 系统完整性查询只读，不修改启动策略。 */
    typedef NTSTATUS(NTAPI *QUERY)(ULONG, PVOID, ULONG, PULONG);
    /* 该命名导出的两参 ABI 不增加静态 WDK 导入依赖。 */
    typedef PVOID(NTAPI *IMAGEBASE)(PVOID, PVOID *);
    /* 原生长度和代码完整性选项。 */
    struct { ULONG Length, Options; } ci = {8UL, 0UL};
    /* 版本来自实际运行的系统。 */
    RTL_OSVERSIONINFOW version = {0};
    /* 解析 PE 时使用固定大小副本。 */
    IMAGE_DOS_HEADER dos;
    /* 候选 NT 头也必须完整复制。 */
    IMAGE_NT_HEADERS64 nt;
    /* 调试目录的遍历明确受映像范围约束。 */
    IMAGE_DEBUG_DIRECTORY debug;
    /* 校验完整 RSDS 签名。 */
    UCHAR rsds[24];
    /* 所有循环保持固定预算。 */
    ULONG offset;
    /* 配置选择必须同时通过 PE 和 RSDS，不由调用方指定。 */
    const KNA_IMAGE_PROFILE *profile = NULL;
    /* 该名称是 Windows 正式导出。 */
    QUERY query = (QUERY)KnaExport(L"ZwQuerySystemInformation");
    /* 实际例程缺失时不猜测内核基址。 */
    IMAGEBASE imageBase = (IMAGEBASE)KnaExport(L"RtlPcToFileHeader");
    /* 首次能力发现也必须具备已确认的安全前提。 */
    if (query == NULL || !NT_SUCCESS(query(103UL, &ci, sizeof(ci), NULL)) ||
        (ci.Options & 2UL) == 0UL || (ci.Options & 0x400UL) != 0UL) { return FALSE; }
    /* 不跨 build 借用私有 ABI；后续映像需单独核对并登记。 */
    version.dwOSVersionInfoSize = sizeof(version);
    /* 暂不声称覆盖其它 build 或多 Processor Group 安装。 */
    if (!NT_SUCCESS(RtlGetVersion(&version)) || version.dwBuildNumber != 26300UL || KeQueryActiveGroupCount() != 1U)
    { return FALSE; }
    /* 以内核自身的已导出例程定位当前映像。 */
    if (imageBase == NULL || imageBase(KnaExport(L"KeBugCheckEx"), &base) == NULL || base == NULL) { return FALSE; }
    /* PE 边界不从用户输入读取。 */
    if (!KswordARKRuntimeReadMemory(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000) { return FALSE; }
    /* 读取并核对当前加载映像的关键身份。 */
    if (!KswordARKRuntimeReadMemory((PUCHAR)base + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.SizeOfImage < PAGE_SIZE)
    { return FALSE; }
    /* 表项只覆盖已经离线核对的两个完整映像。 */
    for (ULONG i = 0UL; i < RTL_NUMBER_OF(KnaProfiles); ++i)
    {
        /* 时间戳本身不是最终身份。 */
        if (nt.FileHeader.TimeDateStamp == KnaProfiles[i].Stamp && nt.OptionalHeader.SizeOfImage == KnaProfiles[i].Bytes)
        { profile = &KnaProfiles[i]; break; }
    }
    /* 不把相近修订号解释成同一个私有 ABI。 */
    if (profile == NULL) { return FALSE; }
    /* 调试目录必须落在已验证映像内。 */
    if (nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress >= profile->Bytes ||
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size > 4096UL ||
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size >
            profile->Bytes - nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress) { return FALSE; }
    /* 同一映像可以有多个调试目录，但不接受未匹配的 PDB。 */
    for (offset = 0UL; offset + sizeof(debug) <= nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
         offset += sizeof(debug))
    {
        /* 每一跳分别安全读取。 */
        if (!KswordARKRuntimeReadMemory((PUCHAR)base + nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + offset,
                                       &debug, sizeof(debug))) { return FALSE; }
        /* 忽略非 CodeView 条目，不把它们猜作 RSDS。 */
        if (debug.Type != IMAGE_DEBUG_TYPE_CODEVIEW || debug.SizeOfData < sizeof(rsds) ||
            debug.AddressOfRawData > profile->Bytes - sizeof(rsds)) { continue; }
        /* 复制后才比较签名和 GUID/age。 */
        if (KswordARKRuntimeReadMemory((PUCHAR)base + debug.AddressOfRawData, rsds, sizeof(rsds)) &&
            rsds[0] == 'R' && rsds[1] == 'S' && rsds[2] == 'D' && rsds[3] == 'S' &&
            RtlCompareMemory(rsds + 4, profile->Rsds, sizeof(profile->Rsds)) == sizeof(profile->Rsds))
        {
            /* 完整身份匹配后才能发布基址。 */
            KnaNt = (PUCHAR)base;
            /* 所有私有函数一起取自该已匹配配置。 */
            KnaProfile = profile;
            /* 此处不写内核，也不启动虚拟化。 */
            return TRUE;
        }
    }
    /* 没有权威身份时明确不支持。 */
    return FALSE;
}

ULONG KnaCapabilities(VOID)
{
    /* Phase A1 bring-up：预热动态符号发现。当前只填 Image 身份和 IDT handler 验证，
     * 结果尚未被 production 路径消费；仅用来确认 driver load + 查询链路下 helper 不
     * 产生副作用。后续阶段才会替代下面的 KnaImage() 匹配。 */
    (void)KnaResolveSymbols(NULL);
    /* 查询只验证身份与前提，不安装转接器。 */
    if (!KnaImage() || KnaExport(L"PsGetContextThread") == NULL || KnaExport(L"PsSetContextThread") == NULL)
    { return 0UL; }
    /* 明确报告 TF、四槽 DR 和启动期留驻，绝不冒充 MTF/EPT。 */
    return 31UL | KSWORD_ARK_KERNEL_NOATTACH_CAP_DR | KSWORD_ARK_KERNEL_NOATTACH_CAP_TF |
           KSWORD_ARK_KERNEL_NOATTACH_CAP_EXCEPTION | KSWORD_ARK_KERNEL_NOATTACH_CAP_BOOT_RESIDENT;
}

BOOLEAN KnaLookupProfileAddresses(KNA_RESOLVED_SYMBOLS *Expected)
{
    /* oracle 比对接口：把当前 build 匹配到的 profile 7 个 RVA 投影成线性地址
     * 返回给 symbols.c。filtering + match 逻辑完全复用 KnaImage()，因此每台机器
     * 只会返回与 KnaProfiles 表精确匹配的 PE/RSDS 条目对应的地址。 */
    if (Expected == NULL) { return FALSE; }
    /* 保守清零；失败时不残留任何字段。 */
    RtlZeroMemory(Expected, sizeof(*Expected));
    /* 第一次调用触发 KnaProfile/KnaNt 的解析；idempotent。 */
    if (!KnaImage() || KnaNt == NULL || KnaProfile == NULL) { return FALSE; }
    /* 各字段逐一从 profile 投影；顺序与 KNA_RESOLVED_SYMBOLS 字段匹配。 */
    Expected->KnaNt = KnaNt;
    Expected->KiDispatchException = KnaNt + KnaProfile->Dispatch;
    Expected->KeContextFromKframes = KnaNt + KnaProfile->From;
    Expected->KeContextToKframes = KnaNt + KnaProfile->To;
    Expected->KeSuspendThread = KnaNt + KnaProfile->Suspend;
    Expected->KeResumeThread = KnaNt + KnaProfile->Resume;
    Expected->PsGetContextInternal = KnaNt + KnaProfile->GetContext;
    Expected->PsSetContextInternal = KnaNt + KnaProfile->SetContext;
    return TRUE;
}

/* PsGetContextThread 的公开包装会把同一 mode 同时用于缓冲区和现场。 */
typedef NTSTATUS(NTAPI *KNA_CONTEXT_INTERNAL)(PETHREAD Thread, PCONTEXT Context,
    KPROCESSOR_MODE BufferMode, KPROCESSOR_MODE ContextMode, ULONG Flags);

/* 内核非分页缓冲区必须配 KernelMode；本调试器需要的现场仍明确为 UserMode。 */
static NTSTATUS NTAPI KnaGetUserContext(PETHREAD Thread, PCONTEXT Context, KPROCESSOR_MODE BufferMode)
{
    /* 两个已登记映像的完整内部函数体均已逐指令核对；不读取 KTHREAD 私有字段。 */
    return ((KNA_CONTEXT_INTERNAL)(KnaNt + KnaProfile->GetContext))(Thread, Context, BufferMode, UserMode, 1UL);
}

/* 设置同样分离两个模式，保留 Windows 自己的用户现场合法性验证。 */
static NTSTATUS NTAPI KnaSetUserContext(PETHREAD Thread, PCONTEXT Context, KPROCESSOR_MODE BufferMode)
{
    /* 不使用 UserMode 探测内核缓冲区，也不把目标当作内核现场修改。 */
    return ((KNA_CONTEXT_INTERNAL)(KnaNt + KnaProfile->SetContext))(Thread, Context, BufferMode, UserMode, 1UL);
}

NTSTATUS KnaResolveThreadApis(VOID)
{
    /* 只有精确身份匹配后才能组成私有函数指针。 */
    if (!KnaImage()) { return STATUS_NOT_SUPPORTED; }
    /* 两个 NTSTATUS ABI 由该映像的实际调用和返回路径核对。 */
    g_Kna.Suspend = (KNA_THREAD_COUNT)(KnaNt + KnaProfile->Suspend);
    /* 不把旧版本的 HANDLE ABI 误用成线程对象 ABI。 */
    g_Kna.Resume = (KNA_THREAD_COUNT)(KnaNt + KnaProfile->Resume);
    /* 缺失导出不回退到无消费者的用户态单步。 */
    g_Kna.GetContext = KnaGetUserContext;
    /* SET 使用 KernelMode 缓冲区与 UserMode 现场的独立包装。 */
    g_Kna.SetContext = KnaSetUserContext;
    /* 完整控制链才算可用。 */
    return g_Kna.GetContext != NULL && g_Kna.SetContext != NULL ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

VOID KnaReadFrames(PVOID Trap, PVOID Exception, PCONTEXT Context)
{
    /* 三参版本不借用另一个 build 的帧偏移。 */
    ((KNA_FROM_FRAMES)(KnaNt + KnaProfile->From))(Trap, Exception, Context);
    /* 保留 Windows 实际投影值，诊断必须能区分帧与硬件来源。 */
    g_Kna.LastFrameDr6 = Context->Dr6; g_Kna.LastFlags = Context->EFlags;
    /* 纯 TF 未启用地址槽时 Windows 不保存帧 DR6，但进入分发器时硬件 BS 仍真实存在。 */
    if ((Context->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS)
    {
        /* 值在同一目标线程的分发入口取得，不从缺失字段推断 BS，也不读取陷阱帧私有偏移。 */
        Context->Dr6 = g_Kna.LastHardwareDr6;
    }
}

VOID KnaWriteFrames(PVOID Trap, PVOID Exception, PCONTEXT Context, ULONG Flags, KPROCESSOR_MODE Mode)
{
    /* 不回写未声明的 SIMD/XSTATE 内容。 */
    ((KNA_TO_FRAMES)(KnaNt + KnaProfile->To))(Trap, Exception, Context, Flags, Mode);
    /* 无地址槽时返回路径不会恢复帧 DR6；当前异常线程仍须实际退休自己消费的状态位。 */
    if ((Flags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS)
    {
        /* Context 保留所有未由本会话消费的硬件原因，不能一律写零。 */
        __writedr(6, (ULONG_PTR)Context->Dr6);
    }
}

/* 只有本模块验证并拥有的转接地址能够绕过编译器的间接调用检查。 */
__declspec(noinline) __declspec(guard(nocf)) static VOID KnaForward(PEXCEPTION_RECORD Record, PVOID Exception, PVOID Trap,
                                             KPROCESSOR_MODE Mode, BOOLEAN FirstChance)
{
    /* 原入口的完整首指令先执行，再返回原函数的下一个边界。 */
    KnaOriginal(Record, Exception, Trap, Mode, FirstChance);
}

/* 该回调只消费已绑定会话自己产生的调试事件。 */
static VOID NTAPI KnaDispatch(PEXCEPTION_RECORD Record, PVOID Exception, PVOID Trap,
                            KPROCESSOR_MODE Mode, BOOLEAN FirstChance)
{
    /* 记录范围严格限制为强身份匹配的自有目标线程。 */
    if (g_Kna.Owned && g_Kna.Thread == PsGetCurrentThread() && Record != NULL)
    {
        /* 当前线程的真实调试寄存器不由帧转换或历史状态合成。 */
        g_Kna.LastHardwareDr6 = __readdr(6);
        /* 固定字段记录不在异常处理路径分配内存或输出日志。 */
        g_Kna.LastCode = (ULONG)Record->ExceptionCode; g_Kna.LastMode = (ULONG)Mode;
        /* 第一机会与入口 IRQL 是是否允许等待的实际前提。 */
        g_Kna.LastChance = (ULONG)FirstChance; g_Kna.LastIrql = (ULONG)KeGetCurrentIrql();
        /* 最后发布本次观察计数。 */
        InterlockedIncrement(&g_Kna.TargetEvents);
    }
    /* 无关异常保留 Windows 原分发，不能跨线程吞异常。 */
    if (!KnaObserve(Record, Exception, Trap, Mode, FirstChance)) { KnaForward(Record, Exception, Trap, Mode, FirstChance); }
}

/* 一个原子字提交与所有 CPU 的指令流串行化。 */
typedef struct _KNA_PATCH
{
    /* 已在 PASSIVE_LEVEL 准备的只写别名。 */
    volatile SHORT *Alias;
    /* CAS 只替换自己验证的那个入口字。 */
    SHORT Expected, Desired;
    /* 串行化前后的有界同步。 */
    volatile LONG Arrived, Done, Leader;
    /* 当前在线处理器数量。 */
    LONG Count;
    /* 原子提交是否成功。 */
    volatile LONG Success;
} KNA_PATCH;

/* 不等待 GUI，不分配内存，不访问分页业务对象。 */
static ULONG_PTR KnaPatchIpi(ULONG_PTR Parameter)
{
    /* 同步对象在 KeIpiGenericCall 返回前保持存活。 */
    KNA_PATCH *patch = (KNA_PATCH *)Parameter;
    /* 每个处理器都进入同一个提交边界。 */
    LONG arrived = InterlockedIncrement(&patch->Arrived);
    /* CPUID 是本处理器指令流串行化点。 */
    int registers[4];
    /* 选第一个进入的处理器作为唯一写者。 */
    if (InterlockedCompareExchange(&patch->Leader, 1L, 0L) == 0L)
    {
        /* 有界自旋只等待其它 IPI 回调，不等待普通线程。 */
        ULONG budget = 10000000UL;
        /* 拓扑变化或被阻塞的 vCPU 不能导致无限自旋。 */
        while (patch->Arrived != patch->Count && --budget != 0UL) { YieldProcessor(); }
        /* 未达到全核边界时完全不修改入口。 */
        if (patch->Arrived == patch->Count)
        {
            /* 首指令完整为两字节，旧 RIP+2 仍指向未改动的原代码。 */
            patch->Success = InterlockedCompareExchange16(patch->Alias, patch->Desired, patch->Expected) == patch->Expected;
        }
        /* 失败也必须放行所有到达的处理器。 */
        InterlockedExchange(&patch->Done, 1L);
    }
    else
    {
        /* 写者有同样的固定预算，所有回调都会返回。 */
        while (InterlockedCompareExchange(&patch->Done, 0L, 0L) == 0L) { YieldProcessor(); }
    }
    /* 处理器返回被中断代码之前清除旧的预取/解码状态。 */
    __cpuid(registers, 0);
    /* arrived 仅用于调试器可检查的回调结果。 */
    return (ULONG_PTR)arrived;
}

/* 内核代码页的映射和锁页只在普通控制面处理。 */
static NTSTATUS KnaPatchEntry(USHORT Expected, USHORT Desired)
{
    /* 描述符只覆盖当前已验证内核中的入口字。 */
    PMDL mdl = IoAllocateMdl(KnaNt + KnaProfile->Dispatch, sizeof(USHORT), FALSE, FALSE, NULL);
    /* 保存映射失败的准确原因。 */
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    /* 只释放成功取得的锁页引用。 */
    BOOLEAN locked = FALSE;
    /* 别名从不执行。 */
    PVOID alias = NULL;
    /* IPI 参数不包含调用方指针。 */
    KNA_PATCH patch = {0};
    /* 分配失败没有副作用。 */
    if (mdl == NULL) { return status; }
    /* 内核探测仍可能报告异常，不能泄漏 MDL。 */
    __try { MmProbeAndLockPages(mdl, KernelMode, IoReadAccess); locked = TRUE; status = STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    /* 只有完整锁定之后才能创建别名。 */
    if (locked) { alias = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute); }
    /* 普通 HVCI 环境会被能力门拒绝，映射失败也不会强行写 CR0.WP。 */
    if (alias != NULL) { status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE); }
    else if (NT_SUCCESS(status)) { status = STATUS_INSUFFICIENT_RESOURCES; }
    /* 全部前提满足后才进入全核原子边界。 */
    if (NT_SUCCESS(status))
    {
        /* 自旋对象只记录已经映射的内核入口字。 */
        patch.Alias = (volatile SHORT *)alias;
        /* 原始值由精确映像核对。 */
        patch.Expected = (SHORT)Expected;
        /* 两字节短跳或原始完整指令。 */
        patch.Desired = (SHORT)Desired;
        /* 首次安装仅支持一个处理器组。 */
        patch.Count = (LONG)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        /* 同步所有处理器后才允许执行新入口。 */
        (void)KeIpiGenericCall(KnaPatchIpi, (ULONG_PTR)&patch);
        /* 不把没有完整提交的补丁报告为成功。 */
        status = patch.Success ? STATUS_SUCCESS : STATUS_RETRY;
    }
    /* 映射与 MDL 的生命周期严格配平。 */
    if (alias != NULL) { MmUnmapLockedPages(alias, mdl); }
    /* 失败的 probe 没有锁页引用。 */
    if (locked) { MmUnlockPages(mdl); }
    /* 释放唯一描述符。 */
    IoFreeMdl(mdl);
    /* 返回实际提交结果。 */
    return status;
}

BOOLEAN KswordARKKernelNoAttachDriverPinned(PDRIVER_OBJECT Driver, PDRIVER_UNLOAD *Original)
{
    /* 只认自己的永久留驻，不接管未知 NULL 槽位。 */
    if (!KnaPinned || Driver != KnaDriver || Driver->DriverUnload != NULL) { return FALSE; }
    /* 供 HVM 的同模块卸载租约借用准确的原入口。 */
    if (Original != NULL) { *Original = KnaUnload; }
    /* 不更改任何生命周期状态。 */
    return TRUE;
}

/* 准备失败可以重试，不能将只分配了转接器误当作桥已经写入。 */
static NTSTATUS KnaPrepareBridge(const UCHAR *Bridge)
{
    /* 描述符只覆盖已核对的十四字节填充。 */
    PMDL mdl = IoAllocateMdl(KnaNt + KnaProfile->Dispatch - 16UL, 14UL, FALSE, FALSE, NULL);
    /* 映射与锁页有独立所有权。 */
    PVOID alias = NULL;
    /* 失败 probe 不拥有页面锁。 */
    BOOLEAN locked = FALSE;
    /* 初始化准确失败状态。 */
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    /* 未分配不做任何修改。 */
    if (mdl == NULL) { return status; }
    /* 资源不足也可能由 probe 抛出，必须配平描述符。 */
    __try { MmProbeAndLockPages(mdl, KernelMode, IoReadAccess); locked = TRUE; status = STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    /* 只为成功锁定的页创建不可执行别名。 */
    if (locked) { alias = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute); }
    /* 不通过写 CR0.WP 降级绕过失败。 */
    if (alias != NULL) { status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE); }
    else if (NT_SUCCESS(status)) { status = STATUS_INSUFFICIENT_RESOURCES; }
    /* 此时入口尚未发布，填充区不可达。 */
    if (NT_SUCCESS(status)) { RtlCopyMemory(alias, Bridge, 14UL); KeMemoryBarrier(); InterlockedExchange(&KnaBridgeReady, 1L); }
    /* 临时映射不留到真实异常路径。 */
    if (alias != NULL) { MmUnmapLockedPages(alias, mdl); }
    /* 只释放成功取得的锁。 */
    if (locked) { MmUnlockPages(mdl); }
    /* 描述符始终配平。 */
    IoFreeMdl(mdl);
    /* 返回真实结果。 */
    return status;
}

NTSTATUS KnaInstallHook(WDFFILEOBJECT File)
{
    /* 转接空间的原始值必须确实是当前映像的未执行填充。 */
    UCHAR padding[16], bridge[14] = {0xFF,0x25,0,0,0,0};
    /* 该映像的首指令只有两字节，完整复制后不需要 RIP 相对重定位。 */
    USHORT original;
    /* 内核分配由固定导出解析，不增加旧系统的强制导入。 */
    typedef PVOID(NTAPI *ALLOCATE)(POOL_FLAGS, SIZE_T, ULONG);
    /* 一页转接器直到重启都由留驻模块拥有。 */
    PUCHAR trampoline;
    /* 只在普通内核申请可执行池，能力门已拒绝 HVCI。 */
    ALLOCATE allocate = (ALLOCATE)KnaExport(L"ExAllocatePool2");
    /* 保存模块卸载槽位的精确所有者。 */
    PDRIVER_OBJECT driver = WdfDeviceWdmGetDeviceObject(WdfFileObjectGetDevice(File))->DriverObject;
    /* 每一步都保留真实错误。 */
    NTSTATUS status;
    /* 安装前先核对映像，禁止盲写候选地址。 */
    if (!KnaImage() || allocate == NULL) { return STATUS_NOT_SUPPORTED; }
    /* 本模块已经拥有的入口可重复开启会话。 */
    if (KnaInstalled) { return STATUS_SUCCESS; }
    /* 当前代码必须仍是原始的完整两字节首指令。 */
    if (!KswordARKRuntimeReadMemory(KnaNt + KnaProfile->Dispatch, &original, sizeof(original)) || original != KnaOriginalWord)
    { return STATUS_OBJECT_NAME_COLLISION; }
    /* 再次开启只重装入口，不重分配或改变永久转接器。 */
    if (KnaOriginal != NULL)
    {
        /* 已有模块留驻所有权仍必须完整。 */
        if (!KswordARKKernelNoAttachDriverPinned(driver, NULL)) { return STATUS_INVALID_DEVICE_STATE; }
        /* 上一次映射失败时，先完整准备桥再考虑发布入口。 */
        if (!KnaBridgeReady)
        {
            /* 绝对目标由本模块固定，不来自调用方。 */
            *(PVOID *)(bridge + 6) = (PVOID)KnaDispatch;
            /* 准备失败仍不执行内核入口修改。 */
            status = KnaPrepareBridge(bridge);
            /* 不将失败降级为可调用入口。 */
            if (!NT_SUCCESS(status)) { return status; }
        }
        /* 只改回自己完整验证过的那个入口字。 */
        status = KnaPatchEntry(KnaOriginalWord, KnaHookWord);
        /* 实际成功之后才公开安装状态。 */
        if (NT_SUCCESS(status)) { InterlockedExchange(&KnaInstalled, 1L); }
        /* 返回硬件同步结果。 */
        return status;
    }
    /* 此填充区由本次 PDB/PE 的函数边界核对，不是全内核代码洞扫描。 */
    if (!KswordARKRuntimeReadMemory(KnaNt + KnaProfile->Dispatch - 16UL, padding, sizeof(padding))) { return STATUS_DATA_ERROR; }
    /* 所有十六字节必须保持原始 INT3 填充。 */
    for (ULONG i = 0UL; i < sizeof(padding); ++i) { if (padding[i] != 0xCCU) { return STATUS_OBJECT_NAME_COLLISION; } }
    /* 先准备完整转接器，入口仍然未修改。 */
    trampoline = (PUCHAR)allocate(POOL_FLAG_NON_PAGED_EXECUTE, PAGE_SIZE, 'aNkK');
    /* 分配失败不修改内核。 */
    if (trampoline == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* 执行原始 PUSH RBP 后转回下一个完整指令。 */
    RtlCopyMemory(trampoline, &original, sizeof(original));
    /* 绝对转移与寄存器无关，不破坏 Windows 参数。 */
    RtlCopyMemory(trampoline + 2, bridge, 6);
    /* 转回首指令之后的原始分发路径。 */
    *(PVOID *)(trampoline + 8) = KnaNt + KnaProfile->Dispatch + 2UL;
    /* 进入新入口之前必须阻止模块被卸载。 */
    KnaUnload = driver->DriverUnload;
    /* 不接管未知的外部卸载门。 */
    if (KnaUnload == NULL || InterlockedCompareExchangePointer((PVOID volatile *)&driver->DriverUnload, NULL, (PVOID)KnaUnload) != (PVOID)KnaUnload)
    { ExFreePoolWithTag(trampoline, 'aNkK'); return STATUS_DEVICE_BUSY; }
    /* 从此保留代码与模块，关闭会话不会假称可以立即卸载。 */
    KnaDriver = driver;
    /* 永久转接器在首次入口发布前已经可调用。 */
    KnaOriginal = (KNA_DISPATCH)trampoline;
    /* 保留精确的生命周期所有权。 */
    InterlockedExchange(&KnaPinned, 1L);
    /* 把绝对目标写入尚未可达的填充区转接器。 */
    *(PVOID *)(bridge + 6) = (PVOID)KnaDispatch;
    /* 桥的完整准备状态与内存分配状态分别记账。 */
    status = KnaPrepareBridge(bridge);
    /* 转接器完整以后才允许任何处理器进入。 */
    if (NT_SUCCESS(status)) { status = KnaPatchEntry(KnaOriginalWord, KnaHookWord); }
    /* 实际提交成功才公布安装状态。 */
    if (NT_SUCCESS(status)) { InterlockedExchange(&KnaInstalled, 1L); }
    /* 永久门在失败时也不能盲目释放已发布的转接地址。 */
    return status;
}

NTSTATUS KnaDeactivateHook(VOID)
{
    /* 未安装入口没有可撤销的代码。 */
    NTSTATUS status;
    /* 已关闭时保持幂等。 */
    if (!KnaInstalled) { return STATUS_SUCCESS; }
    /* 原子恢复完整首指令，转接区继续承接可能晚到的旧跳转。 */
    status = KnaPatchEntry(KnaHookWord, KnaOriginalWord);
    /* 未成功恢复入口不能伪报关闭成功。 */
    if (NT_SUCCESS(status)) { InterlockedExchange(&KnaInstalled, 0L); }
    /* 模块与转接区保持到重启，杜绝晚到指令落入释放内存。 */
    return status;
}
