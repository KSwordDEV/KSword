#pragma once
#include <ntifs.h>
#include "../hvm/hvm_noattach.h"
#include "driver/KswordArkKernelNoAttachIoctl.h"
#include "../debugger/noattach_ownership.h"

/* 本次启动中的两种执行后端共用一个显式资源预约。 */
/* 普通异常后端不允许与 VMX 执行控制同时拥有目标。 */
/* 仅内部短暂状态，对外映射为等待真实停止。 */
#define KNA_ARMING 32UL
/* 私有线程控制 ABI 只对已核对的映像启用。 */
typedef NTSTATUS(NTAPI *KNA_THREAD_COUNT)(PETHREAD Thread, PULONG Previous);
/* Get/Set 使用 Windows 原生上下文例程，不访问 KTHREAD 私有偏移。 */
typedef NTSTATUS(NTAPI *KNA_THREAD_CONTEXT)(PETHREAD Thread, PCONTEXT Context, KPROCESSOR_MODE Mode);
/* 由精确映像的异常辅助例程完成帧转换。 */
typedef VOID(NTAPI *KNA_FROM_FRAMES)(PVOID Trap, PVOID Exception, PCONTEXT Context);
/* 该映像会转发第四个 flags 和栈上的第五个 PreviousMode 参数。 */
typedef VOID(NTAPI *KNA_TO_FRAMES)(PVOID Trap, PVOID Exception, PCONTEXT Context, ULONG Flags, KPROCESSOR_MODE Mode);
/* KiDispatchException 的五个实参由调用点与展开表共同核对。 */
typedef VOID(NTAPI *KNA_DISPATCH)(PEXCEPTION_RECORD Record, PVOID Exception, PVOID Trap, KPROCESSOR_MODE Mode, BOOLEAN FirstChance);

/* 固定非分页会话；目标退出和控制文件关闭均通过强身份撤销。 */
typedef struct _KNA_SESSION
{
    /* 控制面序列化，不跨目标的异常等待持有。 */
    EX_PUSH_LOCK ControlLock;
    /* 根本身是普通内核，不在持有自旋锁时等待或调用上下文 API。 */
    KSPIN_LOCK StateLock;
    /* 一次明确命令唤醒一个受控线程。 */
    KEVENT ContinueEvent;
    /* 控制面等待真实异常处理者退出，不能用固定延时假定排空。 */
    KEVENT ObserverIdle;
    /* 生命周期异步收尾只使用 PASSIVE_LEVEL 工作项。 */
    WDFWORKITEM CleanupWork;
    /* 初始化预约不是执行能力。 */
    volatile LONG Initialized, Owned, Closing, Observer, WorkQueued;
    /* 当前对外状态与命令分别保存。 */
    ULONG State, Action;
    /* 当前会话的全宽不可复用身份。 */
    ULONGLONG Generation, OwnerCreation, StopCounter, LeaseDeadline;
    /* 强引用一直保留到目标状态恢复并且观察者排空。 */
    PEPROCESS Owner, Process;
    /* 只控制一个原生 x64 用户线程（primary）。 */
    PETHREAD Thread;
    /* 附加线程挂起列表：OS 层 suspend，不参与 KnaObserve 分发。 */
    PETHREAD AdditionalThreads[7];
    /* 已挂起的附加线程计数；primary 不计入。 */
    ULONG AdditionalThreadCount;
    /* 唯一控制文件的关闭会撤销停止。 */
    WDFFILEOBJECT File;
    /* 接管、恢复和能力读取均来自已核对的实际函数。 */
    KNA_THREAD_COUNT Suspend, Resume;
    /* 两个上下文 API 只在普通控制路径调用。 */
    KNA_THREAD_CONTEXT GetContext, SetContext;
    /* 控制面保留最近的原生阶段，失败日志不能只剩一个无来源状态码。 */
    PCSTR NativePhase;
    /* 只供普通控制路径诊断；异常入口只写固定字段，不格式化日志。 */
    volatile LONG TargetEvents;
    /* 最后一次真实目标异常的元数据不能从 UI 状态推断。 */
    ULONG LastCode, LastMode, LastChance, LastIrql;
    /* 比较体系结构状态与 Windows 帧投影，定位未消费事件。 */
    ULONGLONG LastHardwareDr6, LastFrameDr6, LastFlags;
    /* 异常处理者唯一写入其活动上下文。 */
    PCONTEXT Context;
    /* 普通捕获不得覆盖同时进入的异常现场。 */
    PCONTEXT Capture;
    /* 请求本会话自己增加的一次挂起必须有独立记账。 */
    BOOLEAN OwnSuspend, OwnTf, BaselineValid;
    /* 只保存并恢复本会话拥有的调试状态。 */
    ULONGLONG BaselineDr[6];
    /* 硬件槽位与公开 ID 的映射不依赖首行选择。 */
    KSWORD_ARK_HVM_NOATTACH_BREAKPOINT Rows[4];
    /* 页级内存观察，通过异常分发器接管用户态 AV；独立于 DR 槽。 */
    KSWORD_ARK_HVM_NOATTACH_BREAKPOINT MemoryWatches[4];
    /* 零 ID 表示未占用，公开序号只递增。 */
    ULONG NextId;
    /* 当前命令在请求时冻结，不借用已完成的 IOCTL 内存。 */
    KSWORD_ARK_KERNEL_NOATTACH_REQUEST Pending;
    /* 唯一权威停止文档。 */
    KSWORD_ARK_KERNEL_NOATTACH_RESPONSE Snapshot;
} KNA_SESSION;

/* 固定全局由模块生命周期管理。 */
extern KNA_SESSION g_Kna;
/* 全局预约互斥，两条后端都不能接管对方。 */
/* 只有实际持有者能解除预约。 */
/* 普通 HVM 修改入口使用此门闩。 */
/* 模块留驻是明确的卸载所有权，而不是未知第三方 NULL。 */
/* 查询与绑定都不凭调用方给出的内核地址定位。 */
ULONG KnaCapabilities(VOID);
/* 原子热补丁只安装已核对映像的一个完整首指令入口。 */
NTSTATUS KnaInstallHook(WDFFILEOBJECT File);
/* 关闭恢复入口；转接区和模块保持到本次系统重启。 */
NTSTATUS KnaDeactivateHook(VOID);
/* 辅助例程只在当前目标线程中转换异常帧。 */
VOID KnaReadFrames(PVOID Trap, PVOID Exception, PCONTEXT Context);
/* 只回写明确声明的寄存器组。 */
VOID KnaWriteFrames(PVOID Trap, PVOID Exception, PCONTEXT Context, ULONG Flags, KPROCESSOR_MODE Mode);
/* 安装前取得可核对的线程 API。 */
NTSTATUS KnaResolveThreadApis(VOID);
/* 首次暂停安排自有 TF，并配平自己的挂起计数。 */
NTSTATUS KnaRequestPause(VOID);
/* 关闭只恢复仍由本会话拥有的状态。 */
NTSTATUS KnaRestoreThread(VOID);
/* 当前异常是否由本会话产生；其它异常保持原分发。 */
BOOLEAN KnaObserve(PEXCEPTION_RECORD Record, PVOID Exception, PVOID Trap, KPROCESSOR_MODE Mode, BOOLEAN FirstChance);
/* 上下文到规范文档的唯一投影。 */
VOID KnaPublish(PCONTEXT Context, ULONG Reason, ULONG BreakpointId);
/* 生命周期回调只标记关闭并通知异步收尾。 */
VOID KnaRevoke(VOID);
/* 断点配置仅在真实停点接受。 */
NTSTATUS KnaEditBreakpoint(const KSWORD_ARK_KERNEL_NOATTACH_REQUEST *Request);
/* 寄存器与配置由当前目标线程提交。 */
VOID KnaApplyDebug(PCONTEXT Context, BOOLEAN Restore);
/* 清除本会话自己生成的调试原因，不清除外部异常。 */
ULONG KnaHit(PCONTEXT Context);
/* 将指定线程纳入附加挂起列表；调用方持 ControlLock，且已核对线程属于本会话进程。 */
NTSTATUS KnaAttachThread(ULONG ThreadId, ULONGLONG ThreadCreationTime);
/* 撤销附加线程的挂起并归还引用；调用方持 ControlLock。 */
NTSTATUS KnaDetachThread(ULONG ThreadId);
/* 批量释放所有附加线程；退出会话前复用。 */
VOID KnaDetachAllThreads(VOID);
/* 控制文件关闭立即通知真实异常消费者。 */
VOID KswordARKKernelNoAttachFileCleanup(WDFFILEOBJECT File);
/* 固定协议的控制面。 */
NTSTATUS KswordARKKernelNoAttachControl(const KSWORD_ARK_KERNEL_NOATTACH_REQUEST *Request,
    KSWORD_ARK_KERNEL_NOATTACH_RESPONSE *Response, ULONG OwnerPid, WDFFILEOBJECT File);
