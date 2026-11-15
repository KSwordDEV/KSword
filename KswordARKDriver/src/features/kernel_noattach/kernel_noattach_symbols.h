#pragma once

#include <ntddk.h>

EXTERN_C_START

/* Phase A 动态符号发现接口。成功填充 Out 的全部字段并返回 STATUS_SUCCESS；
 * 任何一个符号发现失败均返回明确 NTSTATUS，不写入部分结果。
 *
 * 发现策略为"两条独立路径交叉验证"：每个符号至少从两个结构性锚点（IDT 入口、
 * 导出函数的 call target、PE 异常目录的函数边界）出发得到候选地址，候选相同
 * 才接受；不同则拒绝加载并记录全部候选，方便之后对比哪条路径坏了。
 *
 * 发现过程只读内核映像，不写入；验证时与保留的 KnaProfiles oracle 对比（dev
 * build 下 #ifdef 启用）。
 */
typedef struct _KNA_RESOLVED_SYMBOLS
{
    /* 已核对身份的 ntoskrnl 映像基址与大小，之后一切函数指针都落在其中。 */
    PUCHAR KnaNt;
    ULONG KnaNtBytes;
    /* Windows build 号与 CodeView GUID+Age；只作日志与 oracle 对齐，不作分支依据。 */
    ULONG BuildNumber;
    ULONGLONG CodeViewGuidLow;
    ULONGLONG CodeViewGuidHigh;
    ULONG CodeViewAge;
    /* 五参异常入口；hook word 原子替换首指令。 */
    PVOID KiDispatchException;
    /* 三参/五参 trap 帧转换，分别用于读/写。 */
    PVOID KeContextFromKframes;
    PVOID KeContextToKframes;
    /* 两个线程上下文内部入口，buffer 与 context 的 KPROCESSOR_MODE 分开。 */
    PVOID PsGetContextInternal;
    PVOID PsSetContextInternal;
    /* 两个挂起/恢复计数例程，返回 NTSTATUS。 */
    PVOID KeSuspendThread;
    PVOID KeResumeThread;
    /* KiDispatchException 入口首 2 字节与 patch 空间。 */
    USHORT KiDispatchExceptionWord;
    PUCHAR PatchArea;
    ULONG PatchAreaBytes;
} KNA_RESOLVED_SYMBOLS;

/* 当前实现为 Phase A0 骨架，直接返回 STATUS_NOT_SUPPORTED；后续阶段逐步填入
 * IDT 读取、call graph 反向追踪、.pdata 函数边界确认等能力。 */
NTSTATUS KnaResolveSymbols(KNA_RESOLVED_SYMBOLS *Out);

/* 查询 hook.c 内 KnaProfiles 对当前映像匹配到的"预期"地址集合；当尚未匹配到任何
 * profile 时返回 FALSE。供 symbols.c 的 bring-up 对比 runtime 发现与硬编码表。
 * 返回 TRUE 时填 Expected->KnaNt + 七个函数地址（Expected 其余字段保持零）。 */
BOOLEAN KnaLookupProfileAddresses(KNA_RESOLVED_SYMBOLS *Expected);

EXTERN_C_END
