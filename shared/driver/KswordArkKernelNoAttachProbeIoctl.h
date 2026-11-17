/* Backend 3 PoC 协议头：HVCI 开启下 DR+IDT 短窗口探针的最小 go/no-go gate。 */
#pragma once
/* 复用主项目的设备类型与常用 CTL_CODE 宏。 */
#include "KswordArkProcessIoctl.h"

/* 协议版本固定为 1，R0 与 R3 必须严格一致。 */
#define KSWORD_ARK_KERNEL_NOATTACH_PROBE_VERSION 1UL

/* 分配空闲功能号 0x940，避开已占用的 0x938/0x924/0x925 等相邻区段。 */
#define KSWORD_ARK_IOCTL_FUNCTION_KERNEL_NOATTACH_PROBE 0x940UL

/* 探针写 IDT 内核数据，必须要求 FILE_WRITE_ACCESS。 */
#define IOCTL_KSWORD_ARK_KERNEL_NOATTACH_PROBE \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_KERNEL_NOATTACH_PROBE, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

/* 只读 IDT 布局：取 IDTR 基址/界限、IDT[vector] 原始 16 字节 descriptor。 */
#define KSWORD_ARK_KERNEL_NOATTACH_PROBE_OP_QUERY_IDT 0UL
/* v1 直写 IDT：Windows 11 26300 本 VA 的 PTE 已 RO → BugCheck 0xBE，SEH 挡不住。 */
#define KSWORD_ARK_KERNEL_NOATTACH_PROBE_OP_PROBE_IDT_NOOP_WRITE 1UL
/* 只读 KiInterruptDescriptorTable（如 Phase A 已解析），不执行副作用。 */
#define KSWORD_ARK_KERNEL_NOATTACH_PROBE_OP_STATUS 2UL
/* v3 PFN alias 变体：MDL + MmMapLockedPagesSpecifyCache 建立独立 RW 别名 VA，走别名写。 */
#define KSWORD_ARK_KERNEL_NOATTACH_PROBE_OP_PROBE_IDT_ALIAS_WRITE 3UL
/* v4 destructive：alias 写 IDT[vector] 的 IstAndType ^= 0x0100，Type 从 0xE 翻到 0xF 让 PG checksum 失配。 */
#define KSWORD_ARK_KERNEL_NOATTACH_PROBE_OP_PROBE_IDT_CHECKSUM_TRIP 4UL
/* v5 destructive broadcast：遍历所有 CPU 各自 pin + MDL alias + IstAndType 翻位，验证 PG 是否只覆盖子集核。 */
#define KSWORD_ARK_KERNEL_NOATTACH_PROBE_OP_PROBE_IDT_CHECKSUM_TRIP_ALL 5UL

/* 探针状态位：操作已完成且未触发 SEH。 */
#define KSWORD_ARK_KERNEL_NOATTACH_PROBE_FLAG_COMPLETED 0x00000001UL
/* 写尝试触发了 SEH 异常，调用方据此判定 HVCI 是否已拦截。 */
#define KSWORD_ARK_KERNEL_NOATTACH_PROBE_FLAG_SEH_FIRED 0x00000002UL
/* 内容读回与原值相等，证明写入字节落地而非被 silently reverted。 */
#define KSWORD_ARK_KERNEL_NOATTACH_PROBE_FLAG_READBACK_MATCH 0x00000004UL

/* 请求结构体固定 32 字节，禁止扩展，R0 严格断言。 */
#pragma pack(push, 8)
typedef struct _KSWORD_ARK_KERNEL_NOATTACH_PROBE_REQUEST
{
    /* 协议版本，必须与 KSWORD_ARK_KERNEL_NOATTACH_PROBE_VERSION 一致。 */
    unsigned long Version;
    /* 操作码，仅接受已定义常量。 */
    unsigned long Operation;
    /* 操作向量号，默认 1 (#DB)，允许 0x2F 等保留向量作低风险校准。 */
    unsigned long Vector;
    /* 显式确认位，设 1 才允许执行 PROBE_IDT_NOOP_WRITE。 */
    unsigned long Confirm;
    /* 请求上下文保留给未来广播 DR 地址等扩展，PoC 阶段必须填零。 */
    unsigned long long Reserved[2];
} KSWORD_ARK_KERNEL_NOATTACH_PROBE_REQUEST;
#pragma pack(pop)

/* 响应结构体固定 96 字节，承载 IDTR、IDT entry、读回副本、SEH 信号、时间戳。 */
#pragma pack(push, 8)
typedef struct _KSWORD_ARK_KERNEL_NOATTACH_PROBE_RESPONSE
{
    /* 协议版本回填。 */
    unsigned long Version;
    /* 本次操作完成状态字，组合 KSWORD_ARK_KERNEL_NOATTACH_PROBE_FLAG_*。 */
    unsigned long StatusFlags;
    /* 若 SEH 命中，记录实际异常代码；否则为 0。 */
    unsigned long SehCode;
    /* 本机 IDT limit（通常为 0x0FFF）。 */
    unsigned long IdtLimit;
    /* 本机 IDTR 的 Base 字段，当前 CPU 的实际 IDT 虚拟地址。 */
    unsigned long long IdtBase;
    /* IDT[Vector] 的 16 字节 descriptor，读入为两个 64 位半部。 */
    unsigned long long EntryLow;
    unsigned long long EntryHigh;
    /* 写后读回的 16 字节副本，用于与原值比对。 */
    unsigned long long ReadbackLow;
    unsigned long long ReadbackHigh;
    /* install 到当前查询的 100ns 时间戳（KeQueryInterruptTime），用于 wall-clock 推断。 */
    unsigned long long QueryTick;
    /* PROBE_IDT_ALIAS_WRITE 回填的 alias VA（0 表示未分配或已释放），其它操作保持 0。 */
    unsigned long long AliasVa;
} KSWORD_ARK_KERNEL_NOATTACH_PROBE_RESPONSE;
#pragma pack(pop)
