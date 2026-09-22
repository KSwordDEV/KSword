#pragma once

//
// kernel_interrupt_object.h
//
// IDT 网关之后的二级对象取证：沿 IDT 向量走到中断对象（KINTERRUPT），读出
// ServiceRoutine / MessageServiceRoutine / DispatchAddress，并归属到已加载模块。
// 只核对 IDT 网关地址的检测看不到「网关仍指向干净的 nt thunk，被改的是网关之后
// 二级对象里的字段」这一类劫持，本模块补上这一层。
//
// 本仓库里没有任何经过验证的 _KINTERRUPT / KPRCB.InterruptObject 偏移，所以本模块
// 不把任何偏移当常量直接信：布局在运行时自验证（唯一且互相印证的解），验证不过就
// 失败即关闭——只产出一行 LAYOUT_UNVERIFIED 说明，绝不给出「被劫持」或「干净」的结论。
//
// 全程只读：所有内核内存读取都走 KswordARKHookReadMemorySafe，只在 PASSIVE_LEVEL 工作。
//

#include "driver_integrity.h"

EXTERN_C_START

// 布局形态：网关处理函数就在 KINTERRUPT 内部（老式 DispatchCode），或经当前 CPU 的
// KPRCB 里按向量索引的指针数组取到对象（现代 KiIsrThunk 形态）。
#define KSW_INTOBJ_FORM_NONE        0UL
#define KSW_INTOBJ_FORM_PRCB_ARRAY  1UL
#define KSW_INTOBJ_FORM_EMBEDDED    2UL

// 单个附加字段（MessageServiceRoutine / DispatchAddress）的验证结论。
#define KSW_INTOBJ_FIELD_VERIFIED         0UL
// 批量样本里该字段全为空：没有可验证的数据，不能当作"已验证"。
#define KSW_INTOBJ_FIELD_NO_SAMPLE        1UL
// 样本里该字段的值不满足预期（不在模块可执行节 / 不在核心内核里）：偏移不成立。
#define KSW_INTOBJ_FIELD_VALUES_REJECTED  2UL

// 验证过的布局。缓存的是「偏移」，不是「结论」：每次查询仍逐对象重新读取与判定。
typedef struct _KSW_INTERRUPT_OBJECT_LAYOUT
{
    ULONG Form;
    // 仅 FORM_PRCB_ARRAY：InterruptObject[0] 相对 KPRCB 起点的字节偏移。
    ULONG PrcbArrayOffset;
    // KINTERRUPT 内 Vector 字段的偏移（用来把对象与向量号互相印证）。
    ULONG VectorFieldOffset;
    ULONG ServiceOffset;
    // 仅在 MessageState == KSW_INTOBJ_FIELD_VERIFIED 时有效。
    ULONG MessageOffset;
    // 仅在 DispatchState == KSW_INTOBJ_FIELD_VERIFIED 时有效。
    ULONG DispatchOffset;
    ULONG MessageState;
    ULONG DispatchState;
} KSW_INTERRUPT_OBJECT_LAYOUT, *PKSW_INTERRUPT_OBJECT_LAYOUT;

// 单次查询（KswordARKCpuIntegrityCollect 一次调用）内共享的状态。调用方零成本持有，
// 不需要释放：布局解析用的工作内存在解析函数内部分配并归还。
typedef struct _KSW_INTERRUPT_OBJECT_CONTEXT
{
    // 0 = 尚未尝试；1 = 布局已验证；2 = 布局未验证（说明行已产出，此后一律静默）。
    ULONG State;
    KSW_INTERRUPT_OBJECT_LAYOUT Layout;
    // 整次查询的核对计数。干净的二级指针不再各占一行证据（每 CPU 每向量一行会把
    // 4096 行预算挤光，导致靠后的 CPU 上的劫持行被截断），只在异常时出行，
    // 干净的部分由 KswordARKInterruptObjectEmitSummary 用一行汇总。
    ULONG CheckedVectors;
    ULONG CheckedPointers;
    ULONG AnomalousPointers;
    ULONG UnclassifiedPointers;
} KSW_INTERRUPT_OBJECT_CONTEXT, *PKSW_INTERRUPT_OBJECT_CONTEXT;

// 一个 CPU 在「绑定亲和性的那段」里取到的现场。PrcbAddress 必须在绑定期间取
// （KeGetPcr() 只在绑定期间对得上），其余字段来自同一份采样。
typedef struct _KSW_INTERRUPT_OBJECT_CPU
{
    ULONG ProcessorGroup;
    ULONG ProcessorNumber;
    ULONGLONG PrcbAddress;
    ULONGLONG IdtBase;
    ULONG IdtLimit;
} KSW_INTERRUPT_OBJECT_CPU, *PKSW_INTERRUPT_OBJECT_CPU;

VOID
KswordARKInterruptObjectContextInitialize(
    _Out_ KSW_INTERRUPT_OBJECT_CONTEXT* Context
    );

// 在某个 IDT 处理函数行之后调用：沿该向量走到中断对象并产出二级指针证据行
// （类 KSWORD_ARK_DRIVER_INTEGRITY_CLASS_INTERRUPT_OBJECT）。
//   ordinal 0 = ServiceRoutine，1 = MessageServiceRoutine，2 = DispatchAddress —— 三者都
//   **只在异常（或无法归类）时产出**；ordinal 3 = 整次查询的汇总行（干净时的证据，
//   见 KswordARKInterruptObjectEmitSummary）；布局未验证的说明行 ordinal 为 ~0UL。
// 首次调用时按需解析并验证布局；验证不过则只产出一行 LAYOUT_UNVERIFIED，
// 之后的调用直接返回，绝不产出任何 HIDDEN_HOOK。
//   GateHandler   - 该向量 IDT 网关解出的处理函数地址（形态 A 用它回溯对象基址）。
//   GateRiskFlags - 该向量网关行的风险位，用来在 detail 里写明"一级是否干净"。
VOID
KswordARKInterruptObjectEmitForVector(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _Inout_ KSW_INTERRUPT_OBJECT_CONTEXT* Context,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ const KSW_INTERRUPT_OBJECT_CPU* Cpu,
    _In_ ULONG Vector,
    _In_ ULONGLONG GateHandler,
    _In_ ULONG GateRiskFlags
    );

// 整次查询收尾时调用一次：布局已验证时产出一行汇总（ordinal 3，riskFlags 恒为 0），
// 写明核对了多少向量/指针、异常多少、无法归类多少。布局未验证或一个都没核对到时不产出。
VOID
KswordARKInterruptObjectEmitSummary(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ const KSW_INTERRUPT_OBJECT_CONTEXT* Context
    );

EXTERN_C_END
