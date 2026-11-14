#pragma once

#include "KswordArkHvmIoctl.h"

/* 第一版只控制一个选定的 x64 用户线程，不创建调试对象。 */
#define KSWORD_ARK_HVM_NOATTACH_VERSION 2UL
/* 新操作独立于既有附加调试器协议。 */
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_NOATTACH 0x924UL
/* 所有操作均要求特权；QUERY 绝不进入 VMX。 */
#define IOCTL_KSWORD_ARK_HVM_NOATTACH                                                                        \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_NOATTACH, METHOD_BUFFERED,          \
             FILE_WRITE_ACCESS)
/* 读取当前能力或本方拥有的会话。 */
#define KSWORD_ARK_HVM_NOATTACH_QUERY 0UL
/* 显式准备并启动本模块独占的 HVM 会话。 */
#define KSWORD_ARK_HVM_NOATTACH_OPEN 1UL
/* 请求在选定线程的下一次用户指令取指处停止。 */
#define KSWORD_ARK_HVM_NOATTACH_PAUSE 2UL
/* 消费停止身份，请求真实 MTF 或明确报告的 VMX TF 执行边界。 */
#define KSWORD_ARK_HVM_NOATTACH_STEP 3UL
/* 消费一次停止身份，并允许正常执行。 */
#define KSWORD_ARK_HVM_NOATTACH_CONTINUE 4UL
/* 撤销执行控制，仅释放本方拥有的 HVM 生命周期。 */
#define KSWORD_ARK_HVM_NOATTACH_CLOSE 5UL
/* 断点变更只接受当前 stopId，不在运行期间重绑地址。 */
#define KSWORD_ARK_HVM_NOATTACH_ADD_BREAKPOINT 6UL
/* 按驱动分配的非零 ID 删除当前会话自己的断点。 */
#define KSWORD_ARK_HVM_NOATTACH_REMOVE_BREAKPOINT 7UL
/* 安装一次性执行断点并原子消费当前停点。 */
#define KSWORD_ARK_HVM_NOATTACH_RUN_TO 8UL
/* 在下一次匹配取指处提交整数寄存器修改，再产生新停点。 */
#define KSWORD_ARK_HVM_NOATTACH_SET_GPR 9UL
/* OPEN 要求调用方明确确认执行实验操作。 */
#define KSWORD_ARK_HVM_NOATTACH_CONFIRMED 1UL
/* 不能因裸机能力缺失而推断允许嵌套运行。 */
#define KSWORD_ARK_HVM_NOATTACH_ALLOW_NESTED 2UL
/* 当前不存在本方拥有的会话。 */
#define KSWORD_ARK_HVM_NOATTACH_CLOSED 0UL
/* 选定线程可正常运行。 */
#define KSWORD_ARK_HVM_NOATTACH_RUNNING 1UL
/* 已请求暂停，但尚未捕获真实的用户取指。 */
#define KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING 2UL
/* 选定线程停留在真实用户取指或匹配的执行边界。 */
#define KSWORD_ARK_HVM_NOATTACH_STOPPED 3UL
/* 停止身份已被消费，正在等待该线程的下一次取指。 */
#define KSWORD_ARK_HVM_NOATTACH_STEP_PENDING 4UL
/* 一个处理器拥有正在执行的单步请求。 */
#define KSWORD_ARK_HVM_NOATTACH_STEPPING 5UL
/* 中途发生其它退出，不能认定单条指令已完成。 */
#define KSWORD_ARK_HVM_NOATTACH_INTERRUPTED 6UL
/* 所有者或目标生命周期已结束，控制权已撤销。 */
#define KSWORD_ARK_HVM_NOATTACH_EXITED 7UL
/* 处理器回滚失败，保留资源供显式恢复。 */
#define KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED 8UL
/* 当前平台无法实现本协议的执行语义。 */
#define KSWORD_ARK_HVM_NOATTACH_UNSUPPORTED 9UL
/* 继续请求已消费旧停止，须在下一次真实取指重新核对现场。 */
#define KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING 10UL
/* 寄存器修改尚未在匹配的真实取指处提交。 */
#define KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING 11UL
/* 停止快照来自选定线程的用户取指。 */
#define KSWORD_ARK_HVM_NOATTACH_STOP_FETCH 1UL
/* 停止快照来自匹配的真实 MTF/VMX TF 完成边界。 */
#define KSWORD_ARK_HVM_NOATTACH_STOP_STEP 2UL
/* EPT 页执行违规经目标线程和精确 RIP 筛选后的停点。 */
#define KSWORD_ARK_HVM_NOATTACH_STOP_BREAKPOINT 3UL
/* 整数寄存器修改已提交的新停点，不代表执行了指令。 */
#define KSWORD_ARK_HVM_NOATTACH_STOP_CONTEXT 4UL
/* 此能力不表示支持整个进程或内核态停止。 */
#define KSWORD_ARK_HVM_NOATTACH_CAP_SINGLE_USER_THREAD 1UL
/* 仅表示 GPR、RIP、RSP 和 RFLAGS；明确不包含 XSTATE。 */
#define KSWORD_ARK_HVM_NOATTACH_CAP_GPR 2UL
/* 要求 Intel MBEC、单上下文 INVEPT 以及 MTF 或显式 VMX TF 边界。 */
#define KSWORD_ARK_HVM_NOATTACH_CAP_EXECUTION 4UL
/* 页权限触发、精确地址/线程筛选，临时放行使用处理器本地 EPTP。 */
#define KSWORD_ARK_HVM_NOATTACH_CAP_BREAKPOINT 8UL
/* 仅整数寄存器；没有 SIMD、XSTATE 或调试寄存器编辑。 */
#define KSWORD_ARK_HVM_NOATTACH_CAP_SET_GPR 16UL
/* 无 MTF 时由 VMX 拦截自有 TF/#DB；TF 可观察，指令类别受保守检查。 */
#define KSWORD_ARK_HVM_NOATTACH_CAP_VMX_TF 32UL
/* 诊断位独立于 EXECUTION，缺少某一前提也能说明实际拒绝原因。 */
#define KSWORD_ARK_HVM_NOATTACH_DIAG_MBEC 0x10000UL
/* 此位只表示 MTF 硬件控制实际可用，不等于会话已经启动。 */
#define KSWORD_ARK_HVM_NOATTACH_DIAG_MTF 0x20000UL
/* 明确公开容量，不映射为 DR0–DR3。 */
#define KSWORD_ARK_HVM_NOATTACH_MAX_BREAKPOINTS 8UL
/* 命中后不再次停止；移除在普通控制路径完成。 */
#define KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT 1UL
/* 栈已展开到请求深度才命中，供调用步过使用。 */
#define KSWORD_ARK_HVM_NOATTACH_BP_STACK_FILTER 2UL
/* 查询显示该断点已消费，不再具备执行资格。 */
#define KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED 0x100UL
/* 查询发现 VA/PFN 改变；必须删除后重新安装。 */
#define KSWORD_ARK_HVM_NOATTACH_BP_STALE 0x200UL
/* 位 0..14 为保存帧顺序的 GPR，位 15/16 为 RIP/RSP。 */
#define KSWORD_ARK_HVM_NOATTACH_GPR_MASK 0x1FFFFULL

/* 与汇编保存帧相同的十五个通用寄存器，随后为用户 RIP/RSP。 */
typedef struct _KSWORD_ARK_HVM_NOATTACH_GPR
{
    unsigned long long rax, rcx, rdx, rbx, rbp, rsi, rdi;
    unsigned long long r8, r9, r10, r11, r12, r13, r14, r15;
    unsigned long long rip, rsp;
} KSWORD_ARK_HVM_NOATTACH_GPR;

/* 配置与命中 ID 都来自驱动，physicalPage 仅作为映射诊断。 */
typedef struct _KSWORD_ARK_HVM_NOATTACH_BREAKPOINT
{
    unsigned long id;
    unsigned long flags;
    unsigned long long address;
    unsigned long long physicalPage;
    unsigned long long minimumRsp;
} KSWORD_ARK_HVM_NOATTACH_BREAKPOINT;

/* 使用已引用的内核对象重新核对定宽请求身份。 */
typedef struct _KSWORD_ARK_HVM_NOATTACH_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long processId;
    unsigned long threadId;
    unsigned long long processCreationTime;
    unsigned long long threadCreationTime;
    unsigned long long ownerCreationTime;
    unsigned long long sessionId;
    unsigned long long stopId;
    unsigned long long address;
    unsigned long breakpointId;
    unsigned long breakpointFlags;
    unsigned long long minimumRsp;
    unsigned long long registerMask;
    KSWORD_ARK_HVM_NOATTACH_GPR registers;
} KSWORD_ARK_HVM_NOATTACH_REQUEST;

/* 这是停止现场的唯一权威文档；绝不将历史遥测复制到此处。 */
typedef struct _KSWORD_ARK_HVM_NOATTACH_RESPONSE
{
    unsigned long version;
    unsigned long size;
    long status;
    unsigned long state;
    unsigned long capabilities;
    unsigned long stopReason;
    unsigned long processId;
    unsigned long threadId;
    unsigned long long sessionId;
    unsigned long long stopId;
    unsigned long long processCreationTime;
    unsigned long long threadCreationTime;
    unsigned long long rip;
    unsigned long long rsp;
    unsigned long long rflags;
    unsigned long long cr3;
    unsigned long long rax;
    unsigned long long rcx;
    unsigned long long rdx;
    unsigned long long rbx;
    unsigned long long rbp;
    unsigned long long rsi;
    unsigned long long rdi;
    unsigned long long r8;
    unsigned long long r9;
    unsigned long long r10;
    unsigned long long r11;
    unsigned long long r12;
    unsigned long long r13;
    unsigned long long r14;
    unsigned long long r15;
    unsigned long breakpointId;
    unsigned long breakpointCount;
    KSWORD_ARK_HVM_NOATTACH_BREAKPOINT breakpoints[KSWORD_ARK_HVM_NOATTACH_MAX_BREAKPOINTS];
} KSWORD_ARK_HVM_NOATTACH_RESPONSE;

#ifdef __cplusplus
static_assert(sizeof(KSWORD_ARK_HVM_NOATTACH_REQUEST) == 232, "No-attach v2 request ABI");
static_assert(sizeof(KSWORD_ARK_HVM_NOATTACH_RESPONSE) == 480, "No-attach v2 response ABI");
#endif
