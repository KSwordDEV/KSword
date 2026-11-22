#pragma once // 保存上下文快照协议只在本共享头中定义。
#include "KswordArkThreadStackIoctl.h" // 复用已有身份请求和通用帧字段，不复制通信布局。

#define KSWORD_ARK_IOCTL_FUNCTION_SNAPSHOT_THREAD_STACK 0x8D7UL // 与普通 APC 诊断端点严格区分。
#define IOCTL_KSWORD_ARK_SNAPSHOT_THREAD_STACK CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_SNAPSHOT_THREAD_STACK, METHOD_BUFFERED, FILE_READ_ACCESS) // 管理员只读快照。
#define KSWORD_ARK_STACK_SNAPSHOT_VERSION 1UL // 本端点独立版本，不修改旧 APC 协议。
#define KSWORD_ARK_STACK_SNAPSHOT_SOURCE 2UL // 全处理器会合期间复制真实目标已保存的内核栈。
#define KSWORD_ARK_STACK_SNAPSHOT_COMPLETE 5UL // 仅展开到有证据的用户态机器帧边界才成立。
#define KSWORD_ARK_STACK_SNAPSHOT_FROZEN 0x00000400UL // 所有受支持处理器已在同一轮会合，目标不在运行。
#define KSWORD_ARK_STACK_SNAPSHOT_USER_BOUNDARY 0x00000800UL // 原生展开器恢复了用户态 RIP、RSP 和 CS。
#define KSWORD_ARK_STACK_SNAPSHOT_STOP_NONE 0UL // 尚无可展开快照。
#define KSWORD_ARK_STACK_SNAPSHOT_STOP_USER 1UL // 真实机器帧到达用户态边界。
#define KSWORD_ARK_STACK_SNAPSHOT_STOP_LIMIT 2UL // 实际仍有下一帧，但已达到帧预算。
#define KSWORD_ARK_STACK_SNAPSHOT_STOP_RANGE 3UL // 下一帧超出已复制栈范围。
#define KSWORD_ARK_STACK_SNAPSHOT_STOP_METADATA 4UL // 缺少已验证常驻内核映像的展开元数据。
#define KSWORD_ARK_STACK_SNAPSHOT_STOP_EXCEPTION 5UL // 原生展开失败，不扫描地址补帧。
#define KSWORD_ARK_STACK_SNAPSHOT_STOP_RUNNING 6UL // 本轮目标仍在某处理器运行，没有读取变化中的远端栈。
#define KSWORD_ARK_STACK_SNAPSHOT_STOP_RESIDENCY 7UL // 目标栈未驻留，不触发换入或解引用无效页。
#define KSWORD_ARK_STACK_SNAPSHOT_STOP_STATE 8UL // 目标调度状态或已保存返回点不符合精确配置。

#pragma pack(push, 8) // 与原身份包统一八字节对齐。
typedef KSWORD_ARK_THREAD_STACK_REQUEST KSWORD_ARK_THREAD_STACK_SNAPSHOT_REQUEST; // size=48，version 使用本端点独立版本。
typedef struct _KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE // 原始响应同时保存帧与展开来源证据。
{ // capture 是公共字段投影；size 为整个响应大小，version 为本端点版本。
    KSWORD_ARK_THREAD_STACK_RESPONSE capture; // source=2 时不声称 APC 入队、在目标执行或 APC 退休。
    unsigned long long savedKernelStack; // 全核会合时 KTHREAD.KernelStack 的真实值。
    unsigned long long initialInstructionPointer; // 从精确已保存切换帧读取的原始返回地址。
    unsigned long long initialStackPointer; // 对应原始返回地址的栈指针，不是本驱动请求者栈。
    unsigned long long stackLow; // 精确 KTHREAD.StackLimit，只用于本次范围核对。
    unsigned long long stackHigh; // 精确 KTHREAD.StackBase，复制绝不越过此边界。
    unsigned long long terminalInstructionPointer; // 原生展开停止时的实际 RIP，不能补造。
    unsigned long long terminalStackPointer; // 原生展开停止时的原始地址空间 RSP。
    unsigned long long kernelImageBase; // 由系统导出归属查询取得的常驻 NT 映像基址。
    unsigned long snapshotByteCount; // 本轮实际完整复制的栈字节数。
    unsigned long threadState; // 全核会合时实际读取的调度状态。
    unsigned long processorCount; // 实际参加会合的处理器数，不等于请求者的猜测。
    unsigned long unwindStop; // 明确区分完整边界、预算、元数据和拒绝。
    unsigned long kernelTimeDateStamp; // 与编译允许列表完全匹配的实际内核时间戳。
    unsigned long kernelImageSize; // 与精确 PE/RSDS 同次核验的映像范围。
    unsigned char kernelPdbGuid[16]; // 原始 GUID 字节顺序，不使用邻近布局。
    unsigned long kernelPdbAge; // 实际加载映像的 RSDS Age。
    unsigned long terminalCodeSegment; // 从已验证 PUSH_MACHFRAME 槽读取，不由低半区 RIP 推断用户态。
} KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE; // 792 字节，不向用户公开任意内核栈字节。
#pragma pack(pop) // 恢复包含者的对齐。
