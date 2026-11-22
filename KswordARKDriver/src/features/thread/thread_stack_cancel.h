#pragma once // 普通内核异步过程调用的私有取消与返回后退休接口。
#include <ntddk.h> // 只使用系统定义的异步过程调用对象和退休门闩。

typedef VOID(NTAPI* KSW_STACK_NORMAL_ROUTINE)(PVOID, PVOID, PVOID); // 与正常例程的三个参数完全匹配。
typedef VOID(NTAPI* KSW_STACK_KERNEL_ROUTINE)( // 目标捕获回调由内核在目标上下文调用。
    PKAPC, KSW_STACK_NORMAL_ROUTINE*, PVOID*, PVOID*, PVOID* // 参数沿用原始内核分发约定。
    ); // 不提供任何调用方指定的函数地址。

typedef struct _KSW_STACK_APC_LIFETIME // 每个同步请求独占一个生命周期对象。
{ // 此结构不是通信协议，也不描述操作系统私有对象布局。
    KAPC Apc; // 只有本模块能够将该实例加入或移出目标队列。
    EX_RUNDOWN_REF Callback; // 唯一引用由成功取消方或正常与退出尾包装器三选一归还。
} KSW_STACK_APC_LIFETIME; // 外层上下文在退休等待完成前始终由同步请求保活。

BOOLEAN KswThreadStackApcInitializeBackend(VOID); // 解析合法导出并核验本模块两个尾包装器的实际生成代码。
BOOLEAN KswThreadStackApcAvailable(VOID); // 不具备合法取消及返回后退休能力时禁止入队。
BOOLEAN KswThreadStackApcQueue( // 仅允许在被同步请求保活的上下文中初始化并入队一次。
    _Inout_ KSW_STACK_APC_LIFETIME* Lifetime, // 调用方清零且尚未入队的私有内存。
    _In_ PKTHREAD Thread, // 调用方在请求期间始终持有真实线程引用。
    _In_ KSW_STACK_KERNEL_ROUTINE KernelRoutine // 本驱动固定的真实目标捕获入口。
    ); // 失败时本函数已归还唯一引用，调用方可以直接释放上下文。
BOOLEAN KswThreadStackApcRetire( // 成功入队的实例必须且只能调用一次。
    _Inout_ KSW_STACK_APC_LIFETIME* Lifetime // 返回后没有任何回调会再访问上下文或返回本驱动尾部。
    ); // 真表示实际移除了本实例；假表示由分发或退出回调完成了退休。
