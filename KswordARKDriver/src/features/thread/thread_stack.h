#pragma once // 真实目标线程普通内核异步过程调用采集入口。
#include <ntddk.h> // 使用真实对象引用、事件与系统退休门闩。
#include <wdf.h> // 固定请求处理器沿用现有框架。
#include "driver/KswordArkThreadStackIoctl.h" // 通信布局只能来自共享协议。

// 集成：开放请求前调用初始化；核心请求封闭后、依赖销毁前调用反初始化。
// 集成：登记 thread_stack.c、thread_stack_cancel.c、thread_stack_ioctl.c、两个模块头及共享协议头。
// 集成：注册处理器、工程文件、持续集成处置与命令行帮助文档由父会话统一修改，本模块不越界。
// 第二版请求保持四十八字节、回执保持六百八十字节；请求标志为零，不接受旧版延迟退休豁免。
// 仅使用命名系统导出；没有 KeRemoveQueueApc 时返回 LIFETIME_UNAVAILABLE、STATUS_NOT_SUPPORTED 和零帧。
// 两份精确磁盘内核均未导出 MmGetSystemRoutineAddressEx，不能假定这个入口在桌面系统存在。
// 两份精确 PDB 均证明普通 MmGetSystemRoutineAddress 的成功出口调用系统自己的 MiMarkKernelCfgTarget。
// 本模块只调用公开解析器；不直接调用该内部授权例程，不访问保护位图，不使用私有函数相对地址。
// Win10 内核 19041.631 的 RSDS 为 F923DA2D238E7C7CE180B962B19A37811，实际 PDB DBI Age 为一。
// 其 KeRemoveQueueApc 存在于 PDB，但没有导出，入口及对应十六字节槽不在有效函数表，本模块不调用它。
// Win11 内核 26100.9711 的 RSDS 为 B661C6FE72991D160FE37C48B8BC54701，实际 PDB DBI Age 为一。
// 其 KeRemoveQueueApc 具有真实导出；是否启用还要由实际导出解析与本驱动尾包装器验证共同决定。
// 普通与退出包装器必须从入口起仅包含确定的本驱动结构参数调整和导入表尾跳；未知生成代码在入队前拒绝。
// 正常包装器在捕获函数返回后尾跳，退出包装器直接尾跳；唯一回调引用因此只在已离开驱动代码后归还。
// 已成功取消的实例不会再进入两种互斥回调，故只由取消方归还该唯一引用；取消失败绝不归还第二次。
// 每次请求都在返回前等待独立回调退休门闩；系统契约允许该等待完成后删除包含门闩的对象。
// 样本事件本身不证明回调返回，必须在退休完成后才复制样本或释放事件及其上下文。
// 超时、停止、线程退出都先取消自己的实例；取消失败只排空已经分发或退出清理的短回调，不等待目标未来恢复。
// 默认最多十六个并发请求，单次排队等待最多五秒；已经执行的内核代码排空不承诺可强制兑现的实时硬截止。
// 不永久固定驱动，不创建常驻清理器，不强迫禁用目标投递，不操作调度器，不采集请求者自己的栈。
// 非空样本仍是部分展开，保留采集与分发入口帧，不能宣称取得请求时刻的完整投递前调用链。
// 系统展开器可能因当前不可缺页上下文而给出空结果；不修改 DisablePagingExecutive 或其他全局内存策略来强迫成功。
// 公开解析器说明：https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmgetsystemroutineaddress。
// 退休内存契约：https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exwaitforrundownprotectionrelease。
// 系统展开限制：https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcapturestackbacktrace。
// 取消所有权参考：https://raw.githubusercontent.com/winsiderss/systeminformer/master/KSystemInformer/ksidll.c，本实现未复制其常驻模块方案。
VOID KswordARKThreadStackInitialize(VOID); // 初始化同步状态、命名导出和回调尾跳能力。
VOID KswordARKThreadStackBeginStop(VOID); // 核心请求门闩排空前先禁止入队并通知已接收请求取消，不在此等待。
VOID KswordARKThreadStackUninitialize(VOID); // 打断排队等待并排空同步请求的取消及短回调退休。
NTSTATUS KswordARKThreadStackCapture( // 同步调用必须覆盖全部目标回调生命周期。
    _In_ const KSWORD_ARK_THREAD_STACK_REQUEST* Input, // 冻结目标实例与预算。
    _Out_ KSWORD_ARK_THREAD_STACK_RESPONSE* Output // 真实帧只在退休已验证后发布。
    ); // 运输成功不能代替业务采集成功。
NTSTATUS KswordARKThreadIoctlCaptureStack( // 固定包处理器只负责共享缓冲区校验与转发。
    _In_ WDFDEVICE Device, // 不改变设备状态。
    _In_ WDFREQUEST Request, // 不向异步回调转交请求或用户缓冲区。
    _In_ size_t InputBufferLength, // 真实容量仍由共享校验器取得。
    _In_ size_t OutputBufferLength, // 必须容纳完整固定回执。
    _Out_ size_t* BytesReturned // 运输成功时返回固定字节数。
    ); // 父会话统一登记处理器与后端运输路径。
