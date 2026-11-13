#pragma once

#include "hvm_exit.h"
#include "hvm_resident.h"

#include "driver/KswordArkHvmNoAttachIoctl.h"

/* 内部发布状态绝不对外表示为已完成停止。 */
#define KSW_NOATTACH_PUBLISHING 32L
/* 命令先占用停止，再检查 stopId，防止 STOPPED 状态 ABA。 */
#define KSW_NOATTACH_COMMAND_RESERVING 33L
/* Intel 将 MBEC 定义为次级处理器控制的第 22 位。 */
#define KSW_NOATTACH_MBEC_CONTROL (1UL << 22)
/* 启用 MBEC 后，此 EPT 位允许用户态指令取指。 */
#define KSW_NOATTACH_USER_EXECUTE (1ULL << 10)
/* 每个地址最多复制三层子表；两个 bank 在进入常驻前全部预分配。 */
#define KSW_NA_BANK_PAGES (1UL + 3UL * KSWORD_ARK_HVM_NOATTACH_MAX_BREAKPOINTS)
/* 失效旧映射仍保留 pin 到全核退出，容量明确有界。 */
#define KSW_NA_MAX_PINS 64UL

/* 活动 bank 的表与行在下一次全核屏障前都不可重用。 */
typedef struct _KSW_NA_BANK
{
    /* 表页面统一由运行时 EPT 分配台账退休。 */
    KSW_HVM_EPT_PAGE Pages[KSW_NA_BANK_PAGES];
    /* 重建只使用已分配的页面，不在 VMX root 分配。 */
    ULONG Used;
    /* 配置行数量包含已消费的一次性记录。 */
    ULONG Count;
    /* 每次 bank 重建都推进代次，逐核 INVEPT 后才能使用。 */
    ULONGLONG Generation;
    /* 已消费与失效的行只以原子位掩码撤销资格。 */
    volatile LONG Disabled;
    /* 失效掩码用于区别正常的一次性消费。 */
    volatile LONG Stale;
    /* EPTP 不随此 bank 的重复使用改变。 */
    ULONGLONG Eptp;
    /* 不可变精确地址、物理页和栈深过滤。 */
    KSWORD_ARK_HVM_NOATTACH_BREAKPOINT Rows[KSWORD_ARK_HVM_NOATTACH_MAX_BREAKPOINTS];
} KSW_NA_BANK;

/* 普通控制路径持有的页面锁，从不在 VMX root 解引用 MDL。 */
typedef struct _KSW_NA_PIN
{
    /* pin 在整个会话保留，避免旧 EPT/并发取指引用被释放。 */
    PMDL Mdl;
    /* 保存安装时的虚拟页。 */
    ULONGLONG Address;
    /* 保存安装时的真实 backing 页。 */
    ULONGLONG Physical;
} KSW_NA_PIN;

/* 保留一份不可变目标绑定，直到全部常驻读者排空。 */
typedef struct _KSW_HVM_NOATTACH
{
    /* 仅串行化 PASSIVE_LEVEL 控制与延后退休。 */
    EX_PUSH_LOCK Lock;
    /* 本生命周期被预约期间，禁止所有外部 HVM 修改。 */
    volatile LONG Owned;
    /* 取得预约不代表获准停止其它客户端的资源。 */
    volatile LONG ResourcesOwned;
    /* 退出回调必须在 TEB 可被复用前撤销发布。 */
    volatile LONG Enabled;
    /* 当前状态独立于不可变身份字段发布。 */
    volatile LONG State;
    /* 保护有界快照复制，避免与根模式写者并发撕裂。 */
    volatile LONG SnapshotSequence;
    /* 标识唯一获准完成在途 MTF 请求的处理器。 */
    volatile LONG StepProcessor;
    /* 防止重复排入清理工作项。 */
    volatile LONG WorkQueued;
    /* 发布回调初始化成功状态。 */
    BOOLEAN Initialized;
    /* 驱动卸载排空回调前，停止排入新工作。 */
    BOOLEAN ShuttingDown;
    /* 在驱动生命周期内保留异步关闭工作项。 */
    WDFWORKITEM Work;
    /* 绑定真实请求方对象，不信任调用方提供的 PID。 */
    PEPROCESS Owner;
    /* 目标进程身份不依赖可能复用的 PID。 */
    PEPROCESS Process;
    /* 直接比较当前 ETHREAD 指针；单独的 TEB 不是身份。 */
    PETHREAD Thread;
    /* 所属控制句柄关闭时撤销该会话。 */
    WDFFILEOBJECT File;
    /* 保留已核对的所有者创建时间，用于 ACK 恢复。 */
    ULONGLONG OwnerCreationTime;
    /* 目标 TEB 仅保留为数值交叉判据，绝不解引用。 */
    ULONGLONG Teb;
    /* 使用预先构建的不可变根表；VM-exit 路径不修改 EPT 表。 */
    ULONGLONG NormalEptp;
    /* 禁止用户取指，同时允许监督态执行。 */
    ULONGLONG UserGateEptp;
    /* 禁止监督态取指，以截获每次返回用户态。 */
    ULONGLONG KernelGateEptp;
    /* 双缓冲发布完整配置，避免全局临时放宽权限。 */
    KSW_NA_BANK Banks[2];
    /* 活动 bank 的索引以 acquire/release 原子操作发布。 */
    volatile LONG ActiveBank;
    /* 后续配置变更和 CPU 缓存分别核对该代次。 */
    ULONGLONG BankGeneration;
    /* 断点 ID 在同一会话内只递增。 */
    ULONG NextBreakpointId;
    /* 所有锁页引用在完整全核退出后统一清理。 */
    KSW_NA_PIN Pins[KSW_NA_MAX_PINS];
    /* 明确限制会话累计锁页资源。 */
    ULONG PinCount;
    /* 待提交寄存器只在命令占用态由控制面写入。 */
    KSWORD_ARK_HVM_NOATTACH_GPR PendingRegisters;
    /* 根模式只提交用户请求的整数寄存器位。 */
    ULONGLONG PendingRegisterMask;
    /* 当前停止证据与历史 HVM 事件环分开保存。 */
    KSWORD_ARK_HVM_NOATTACH_RESPONSE Snapshot;
} KSW_HVM_NOATTACH;

/* 即使句柄清理与 OPEN 请求并发，也保留正在关闭的状态。 */
typedef struct _KSW_HVM_NOATTACH_FILE_CONTEXT
{
    /* KMDF 在接收请求前将上下文初始化为零。 */
    volatile LONG Closing;
} KSW_HVM_NOATTACH_FILE_CONTEXT;
/* 只有主控制设备安装此私有文件上下文。 */
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(KSW_HVM_NOATTACH_FILE_CONTEXT, KswordARKHvmNoAttachFileContext);

/* 单会话存储位于非分页内存，地址在驱动生命周期内固定。 */
extern KSW_HVM_NOATTACH g_KswordNoAttach;
/* 初始化生命周期回调，不进入 VMX。 */
NTSTATUS KswordARKHvmNoAttachInitialize(VOID);
/* 既有运行时销毁前，先撤销、排空并退休本会话。 */
VOID KswordARKHvmNoAttachShutdown(VOID);
/* 查询资源修改是否由本子系统独占。 */
BOOLEAN KswordARKHvmNoAttachOwned(VOID);
/* 撤销发布，并排入有界的 PASSIVE_LEVEL 清理。 */
VOID KswordARKHvmNoAttachRevoke(VOID);
/* 即使调用方仍存活，KMDF 也会关闭此确切会话。 */
VOID KswordARKHvmNoAttachFileCleanup(WDFFILEOBJECT File);
/* 在 PASSIVE_LEVEL 验证并执行一次固定协议操作。 */
NTSTATUS KswordARKHvmNoAttachControl(const KSWORD_ARK_HVM_NOATTACH_REQUEST *Request,
                                     KSWORD_ARK_HVM_NOATTACH_RESPONSE *Response, ULONG OwnerPid,
                                     WDFFILEOBJECT File);
/* 持运行时锁的封装复用既有全处理器生命周期。 */
NTSTATUS KswordARKHvmNoAttachLifecycle(BOOLEAN Start, ULONG Flags);
/* 常驻插入前构建 MBEC 根表；所有页面纳入运行时台账。 */
NTSTATUS KswordARKHvmNoAttachBuildRootsLocked(KSW_HVM_RUNTIME *Runtime);
/* 每个处理器首次进入前失效两个专用根；任何失败都拒绝 VM-entry。 */
NTSTATUS KswordARKHvmNoAttachInvalidateRootsForEntry(KSW_HVM_RUNTIME *Runtime);
/* 常驻处理器数量归零后才撤销根表指针。 */
VOID KswordARKHvmNoAttachResetRootsLocked(KSW_HVM_RUNTIME *Runtime);
/* 仅处理本方会话的模式门禁和 MTF 退出。 */
BOOLEAN KswordARKHvmNoAttachHandleExit(KSW_HVM_RESIDENT_VCPU *Context, KSW_HVM_GPR_FRAME *Frame, ULONG Reason,
                                       ULONGLONG Qualification, ULONG *Action);
/* 在每个 CPU 请求一次无副作用的超调用，使 PAUSE 和 CONTINUE 生效。 */
NTSTATUS KswordARKHvmNoAttachRendezvous(KSW_HVM_RUNTIME *Runtime);
/* 以下函数由持有独立控制锁的 PASSIVE_LEVEL 路径调用。 */
NTSTATUS KswordARKHvmNoAttachPrepareBanks(KSW_HVM_RUNTIME *Runtime);
/* 配置变更发布后执行全核屏障；失败保留全部资源进入恢复。 */
NTSTATUS KswordARKHvmNoAttachEditBreakpoint(const KSWORD_ARK_HVM_NOATTACH_REQUEST *Request);
/* 每次状态查询重新核对有效行的 VA/PFN，不静默迁移断点。 */
VOID KswordARKHvmNoAttachQueryBreakpoints(KSWORD_ARK_HVM_NOATTACH_RESPONSE *Response);
/* 完整全核退出以后才解除锁页引用。 */
VOID KswordARKHvmNoAttachReleasePins(VOID);
/* 停点编辑与运行到地址共享一次性 stopId 的占用和提交规则。 */
NTSTATUS KswordARKHvmNoAttachEditStopped(const KSWORD_ARK_HVM_NOATTACH_REQUEST *Request);
