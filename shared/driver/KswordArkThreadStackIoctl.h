#pragma once // 本文件是在线目标线程内核栈协议的唯一声明源。

#include "KswordArkThreadIoctl.h" // 复用设备类型和基础 Windows IOCTL 定义。

#define KSWORD_ARK_IOCTL_FUNCTION_CAPTURE_THREAD_STACK 0x8D6UL // 独立编号防止旧驱动忽略新增身份字段。
#define IOCTL_KSWORD_ARK_CAPTURE_THREAD_STACK CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_CAPTURE_THREAD_STACK, METHOD_BUFFERED, FILE_READ_ACCESS) // 只读管理员设备请求。
#define KSWORD_ARK_THREAD_STACK_VERSION 2UL // 拒绝兼容曾允许无界驻留的第一版语义，固定结构大小不变。
#define KSWORD_ARK_THREAD_STACK_MAX_FRAMES 64UL // 内核展开帧数的硬上限。
#define KSWORD_ARK_THREAD_STACK_MAX_TIMEOUT_MS 5000UL // 投递等待的硬上限；已经分发的短回调仍须安全退休后才能释放。
#define KSWORD_ARK_THREAD_STACK_ALLOW_DEFERRED_RUNDOWN 0x00000001UL // 仅保留旧位名称供识别，第二版请求禁止设置此位。

#define KSWORD_ARK_THREAD_STACK_SOURCE_NONE 0UL // 未执行真实目标上下文采集。
#define KSWORD_ARK_THREAD_STACK_SOURCE_TARGET_NORMAL_APC 1UL // 目标线程普通内核 APC 的 KernelRoutine 中调用 RtlCaptureStackBackTrace。
#define KSWORD_ARK_THREAD_STACK_RESULT_UNAVAILABLE 0UL // 没有可用调用帧。
#define KSWORD_ARK_THREAD_STACK_RESULT_PARTIAL 1UL // 真实有界展开，但不证明已经覆盖完整原始调用链。
#define KSWORD_ARK_THREAD_STACK_RESULT_IDENTITY_MISMATCH 2UL // 任一身份不一致均返回零帧。
#define KSWORD_ARK_THREAD_STACK_RESULT_TIMEOUT 3UL // 请求等待超时；不是 APC 已取消或目标拒绝 APC 的证据。
#define KSWORD_ARK_THREAD_STACK_RESULT_LIFETIME_UNAVAILABLE 4UL // 合法取消导出或回调尾跳证明不可用，在入队前拒绝采集。
#define KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED 0x00000001UL // 已从持有引用的进程和线程对象核对完整实例身份。
#define KSWORD_ARK_THREAD_STACK_FLAG_QUEUED 0x00000002UL // 内核确实接受了 APC 入队。
#define KSWORD_ARK_THREAD_STACK_FLAG_EXECUTED_IN_TARGET 0x00000004UL // 采集前后当前 ETHREAD、EPROCESS、PID/TID 和创建时间均一致。
#define KSWORD_ARK_THREAD_STACK_FLAG_APC_ENTRY_FRAMES 0x00000008UL // 帧链保留采集包装层与 APC 分发层，不冒充投递前原始栈。
#define KSWORD_ARK_THREAD_STACK_FLAG_COMPLETENESS_UNKNOWN 0x00000010UL // 系统展开器结束不能证明栈已完整展开。
#define KSWORD_ARK_THREAD_STACK_FLAG_FRAME_LIMIT 0x00000020UL // 额外探测到至少一个超出调用方上限的帧。
#define KSWORD_ARK_THREAD_STACK_FLAG_RETAINED_AFTER_TIMEOUT 0x00000040UL // 仅保留旧位名称供识别，第二版响应禁止设置此位。
#define KSWORD_ARK_THREAD_STACK_FLAG_INVALID_FRAME 0x00000080UL // 展开器出现非内核地址，拒绝该帧及其后续帧。
#define KSWORD_ARK_THREAD_STACK_FLAG_OWN_APC_CANCELLED 0x00000100UL // 合法取消例程确实移除了本次请求自己入队的唯一实例。
#define KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED 0x00000200UL // 已取消或回调已尾跳回内核，并通过独立退休门闩完成排空。

// 重要：本协议不是离线转储、ETW、栈指针查询，也不提供线程挂起或 APC 禁用绕过。
// 普通内核 APC 只有在目标允许正常投递时才执行；投递时态不等于请求时态。
// 第一版的超时驻留与无界卸载设计已经撤除；第二版不接受调用方豁免生命周期约束。
// 只有命名导出取消与本驱动回调尾跳证明都成立时才允许入队；缺失时返回 LIFETIME_UNAVAILABLE 和零帧。
// 超时先取消自己的排队实例；取消失败只能等待已经分发或退出清理的短回调退休，不能提前释放或强制卸载。
// 该最后排空不是可强制兑现的实时截止期限；不操作调度器，不唤醒或修改禁用 APC 的目标。
// 不得改用请求者栈、线索、转储或事件栈冒充真实目标采集。
#pragma pack(push, 8) // R0/R3 以及不同编译器选项统一八字节对齐。
typedef struct _KSWORD_ARK_THREAD_STACK_REQUEST { // 不接受用户提供的内核对象地址或任意回调地址。
    unsigned long size; // 必须等于当前请求结构大小。
    unsigned long version; // 必须等于当前协议版本。
    unsigned long processId; // 必须明确指定目标 PID。
    unsigned long threadId; // 必须明确指定目标 TID。
    unsigned long long expectedProcessCreationTime100ns; // 必须匹配持有引用的 EPROCESS 创建时间。
    unsigned long long expectedThreadCreationTime100ns; // 必须匹配持有引用的 ETHREAD 创建时间。
    unsigned long frameLimit; // 一至 MAX_FRAMES，不能靠零表示默认。
    unsigned long timeoutMs; // 一至 MAX_TIMEOUT_MS，限制排队等待，不豁免已经执行回调的安全排空。
    unsigned long flags; // 第二版必须为零，旧版延迟退休确认位也必须拒绝。
    unsigned long reserved; // 必须为零，禁止不明确的向前兼容。
} KSWORD_ARK_THREAD_STACK_REQUEST; // 共四十八字节，无体系结构相关指针。

typedef struct _KSWORD_ARK_THREAD_STACK_RESPONSE { // 固定响应始终以全零初始化，业务失败仍返回诊断回执。
    unsigned long size; // 当前固定响应的字节数。
    unsigned long version; // 当前响应协议版本。
    long status; // 真实 NTSTATUS；TIMEOUT 是正值，消费者不能仅用 NT_SUCCESS 判断采集成功。
    unsigned long result; // 明确区分部分真实帧、身份不符、超时和不可用。
    unsigned long source; // 只有真实执行目标上下文采集后才发布 TARGET_NORMAL_APC。
    unsigned long flags; // 身份、投递、帧来源和完整度证据。
    unsigned long processId; // 请求冻结的目标 PID，不表示实际身份已经验证。
    unsigned long threadId; // 请求冻结的目标 TID，不表示实际身份已经验证。
    unsigned long long processCreationTime100ns; // 从独立持有引用的 EPROCESS 读取的实际创建时间。
    unsigned long long threadCreationTime100ns; // 从独立持有引用的 ETHREAD 读取的实际创建时间。
    unsigned long long threadObject; // 已核验目标对象的诊断身份，不是用户可回传的对象能力。
    unsigned long long processObject; // 已核验目标进程对象的诊断身份。
    unsigned long currentProcessId; // 采集回调实际执行时的当前进程 ID。
    unsigned long currentThreadId; // 采集回调实际执行时的当前线程 ID。
    unsigned long long currentThreadObject; // 采集回调实际执行时的 ETHREAD。
    unsigned long long currentProcessObject; // 采集回调实际执行时的当前地址空间 EPROCESS。
    unsigned long long currentProcessCreationTime100ns; // 采集时当前归属进程的实际创建时间。
    unsigned long long currentThreadCreationTime100ns; // 采集时当前线程的实际创建时间。
    unsigned long long requestTime100ns; // 内核接收本次请求的 UTC 系统时间。
    unsigned long long queuedTime100ns; // 紧邻实际入队前的 UTC 系统时间。
    unsigned long long captureStartTime100ns; // 真正进入目标采集回调的 UTC 系统时间。
    unsigned long long captureEndTime100ns; // 完成目标展开与身份复核的 UTC 系统时间。
    unsigned long long captureQpc; // 目标采集开始时的性能计数器值。
    unsigned long long qpcFrequency; // 与 captureQpc 同次查询的计数器频率。
    unsigned long frameCount; // 仅真实展开且经内核地址过滤后的帧数。
    unsigned long frameLimit; // 本次请求的帧数上限。
    unsigned long captureIrql; // 真实展开所在 IRQL，当前应为 APC_LEVEL。
    unsigned long timeoutMs; // 本次调用方等待上限，便于保存证据。
    unsigned long long frames[KSWORD_ARK_THREAD_STACK_MAX_FRAMES]; // 仅内核返回地址；未使用项、身份不符与超时均为零。
} KSWORD_ARK_THREAD_STACK_RESPONSE; // 不包含栈字节、用户地址或伪造哨兵帧。
#pragma pack(pop) // 恢复调用方原对齐设置。
