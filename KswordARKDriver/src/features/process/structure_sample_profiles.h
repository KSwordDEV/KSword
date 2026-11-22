#pragma once // 布局授权仅来自编译内置配置，不接受调用方上传配置。
#include "structure_sample.h" // 复用驱动私有 NT 类型和唯一的共享通信协议。

// 每项都必须来自同一精确 PE/RSDS 配对及其 PDB 中的两种根类型。
typedef struct _KSW_STRUCTURE_SAMPLE_PROFILE // 不推断成员偏移、相邻版本布局或池分配费用。
{ // 此描述只保存精确身份与两种对象各自的根范围。
    KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID Kernel; // 准入必须匹配的完整内核身份。
    ULONG ProfileId; // 稳定且非零的回执标识，不是调用方选择配置的参数。
    ULONG EprocessSize; // 权威 PDB 的 sizeof(_EPROCESS)，不是分配费用。
    ULONG EthreadSize; // 权威 PDB 的 sizeof(_ETHREAD)，不能用 sizeof(_KTHREAD) 替代。
} KSW_STRUCTURE_SAMPLE_PROFILE; // 配置只读且永久有效，借用指针无需单独管理生命周期。

// 解析器自行读取运行中的内核身份，两个参数都不接受输入地址。
NTSTATUS // 未知内核身份在访问对象之前即失败关闭。
KswStructureSampleResolveProfile( // 输出实际身份和可选的精确匹配配置。
    _Out_ KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID* Kernel, // 用于解码和诊断的实际 PE/RSDS 信息。
    _Outptr_result_maybenull_ const KSW_STRUCTURE_SAMPLE_PROFILE** Profile // 仅精确匹配时返回非空配置。
    ); // 调用方不得把输出缓冲区误作布局输入。

// 将已校验的加载身份与生成的不可变允许列表逐项精确比较。
const KSW_STRUCTURE_SAMPLE_PROFILE* // 返回借用的只读配置，未知身份返回空指针。
KswStructureSampleFindProfile( // 不回退到邻近版本，也不借用 DynData 布局。
    _In_ const KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID* Kernel // 所有 PE 和 RSDS 字段必须完全一致。
    ); // 此查找不会读取目标对象正文。
