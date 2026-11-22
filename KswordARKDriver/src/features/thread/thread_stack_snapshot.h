#pragma once // 只读保存上下文快照的驱动内部接口。
#include "thread_stack.h" // 沿用现有线程模块的 NT 与 WDF 定义。
#include "driver/KswordArkThreadStackSnapshotIoctl.h" // 唯一通信定义来自共享目录。

#define KSW_SAVED_STACK_BYTES 65536UL // 单次非分页复制硬上限，不接收用户指定长度。
VOID KswSavedStackInitialize(VOID); // 在请求开放前初始化停止和排空门闩。
VOID KswSavedStackBeginStop(VOID); // 禁止后续快照轮次，不遗留任何目标 APC。
VOID KswSavedStackUninitialize(VOID); // 等待同步会合、DPC 返回和复制后展开完成。
NTSTATUS KswSavedStackCapture( // 请求只含冻结身份和预算，不接受目标内核地址。
    const KSWORD_ARK_THREAD_STACK_SNAPSHOT_REQUEST* Input, // handler 已冻结的固定输入。
    KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE* Output); // 所有失败均从零帧初始化。
VOID KswSavedStackUnwind( // 仅在 PASSIVE_LEVEL 消费独立非分页副本，不再读取目标栈。
    KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE* Output, // 帧、终点和完整度写回同一响应。
    UCHAR* Bytes, // 可重定位的私有栈副本，不是目标内存。
    ULONG64 SavedRbp); // 从已验证切换帧读取的原始非易失 RBP。
BOOLEAN KswSavedStackCheck( // 原生展开前的有界读取证明与独立机器帧权限证据。
    ULONG64 Image, ULONG ImageSize, const VOID* Entry, // 仅接受已核验的常驻 NT 元数据项。
    PCONTEXT Context, ULONG64 Low, ULONG64 High, PULONG MachineCs); // 输入私有副本上下界，输出预期控制位置和真实 CS。
NTSTATUS KswordARKThreadIoctlSnapshotStack( // 与统一 registry handler 保持相同签名。
    WDFDEVICE Device, WDFREQUEST Request, // 设备与请求由现有调度器持有。
    size_t InputBufferLength, size_t OutputBufferLength, // 实际容量仍由 WDF 校验。
    size_t* BytesReturned); // 只在完整响应存在时返回固定长度。
