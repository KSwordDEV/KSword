#pragma once // 此文件是有界结构快照唯一的 R0/R3 通信协议定义。
#include "KswordArkProcessIoctl.h" // 复用现有设备类型和 CTL_CODE 定义。

// 只有编译内置且精确匹配 PE/RSDS 身份的配置才能授权读取对象正文。
#define KSWORD_ARK_STRUCTURE_SAMPLE_VERSION 1UL // 不兼容的通信布局变更必须递增版本。
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_STRUCTURE_SAMPLE 0x941UL // 为只读结构采样分配独立功能号。
#define IOCTL_KSWORD_ARK_QUERY_STRUCTURE_SAMPLE CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_QUERY_STRUCTURE_SAMPLE, METHOD_BUFFERED, FILE_READ_ACCESS) // 请求不接受调用方地址或布局。
#define KSWORD_ARK_STRUCTURE_SAMPLE_MAX_BYTES 8192UL // 仅限定输出容量，不能据此授权对象读取范围。
#define KSWORD_ARK_STRUCTURE_SAMPLE_VALID_BYTES (KSWORD_ARK_STRUCTURE_SAMPLE_MAX_BYTES / 8UL) // 每个正文数据字节对应一个有效位。
#define KSWORD_ARK_STRUCTURE_SAMPLE_EPROCESS 1UL // 选择已引用进程对象的正文。
#define KSWORD_ARK_STRUCTURE_SAMPLE_ETHREAD 2UL // 选择已引用线程对象的正文。
#define KSWORD_ARK_STRUCTURE_SAMPLE_OK 1UL // 精确根类型正文的全部字节均已复制。
#define KSWORD_ARK_STRUCTURE_SAMPLE_PARTIAL 2UL // 部分复制成功，可用字节由有效位图确定。
#define KSWORD_ARK_STRUCTURE_SAMPLE_INVALID_REQUEST 3UL // 请求身份或保留字段不符合协议要求。
#define KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_UNSUPPORTED 4UL // 没有匹配内置的精确映像和类型配置。
#define KSWORD_ARK_STRUCTURE_SAMPLE_LOOKUP_FAILED 5UL // 查找并引用请求对象失败。
#define KSWORD_ARK_STRUCTURE_SAMPLE_IDENTITY_MISMATCH 6UL // PID、TID 或创建时间与实际对象不匹配。
#define KSWORD_ARK_STRUCTURE_SAMPLE_READ_FAILED 7UL // 没有成功复制任何正文数据字节。
#define KSWORD_ARK_STRUCTURE_SAMPLE_NONATOMIC 0x1UL // 对象内容在整个采样区间内均可能变化。
#define KSWORD_ARK_STRUCTURE_SAMPLE_BODY_ONLY 0x2UL // 不读取对象头、相邻分配或指针指向的对象。
#define KSWORD_ARK_STRUCTURE_SAMPLE_POINTER_VALUES 0x4UL // 形似指针的字节仅作为数值返回，绝不跟随读取。
#define KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID_VALID 0x8UL // 响应包含已校验的运行中内核 PE/RSDS 身份。

// GUID 保存 CodeView 内存中的原始字节顺序，不使用 GUID 文本的排列顺序。
typedef struct _KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID // 所有成员均采用 Windows ABI 定义的位宽。
{ // 精确内核身份供驱动准入和用户态解码共同校验。
    unsigned long machine; // 当前支持配置的架构值为 IMAGE_FILE_MACHINE_AMD64。
    unsigned long timeDateStamp; // 已加载 PE 映像的 COFF 时间戳。
    unsigned long sizeOfImage; // 已加载 PE 映像声明的 SizeOfImage。
    unsigned long checkSum; // 已加载 PE 可选头中的 CheckSum。
    unsigned char pdbGuid[16]; // 精确 RSDS GUID，保留 Windows GUID 原始字节顺序。
    unsigned long pdbAge; // 精确 RSDS Age，不使用 PDB 摘要或 DBI 的诊断 Age。
    unsigned long reserved; // 第一版协议始终置零。
} KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID; // 客户端必须匹配此身份后才能解释正文数据。

// 必须提供创建时间，以冻结发出请求前选定的对象身份。
typedef struct _KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST // 请求长度固定，不包含偏移、长度、句柄或地址。
{ // 此请求只描述目标身份，不赋予任意内核读取能力。
    unsigned long version; // 协议版本必须为 KSWORD_ARK_STRUCTURE_SAMPLE_VERSION。
    unsigned long objectType; // 仅允许 EPROCESS 或 ETHREAD 根类型。
    unsigned long processId; // 两种根类型都必须提供所属进程 PID。
    unsigned long threadId; // ETHREAD 必须提供 TID，EPROCESS 必须置零。
    unsigned __int64 processCreationTime100ns; // 必须提供非零的精确 PsGetProcessCreateTimeQuadPart 返回值。
    unsigned __int64 threadCreationTime100ns; // 提供精确 PsGetThreadCreateTime 返回值，EPROCESS 必须置零。
    unsigned long reserved[4]; // 全部保留字段必须置零，不静默启用未来扩展行为。
} KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST; // 正常 Windows ABI 下请求大小固定为 48 字节。

// 只有精确符号存储范围内的每个字节都有效时，该字段才能用于解码。
typedef struct _KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE // 固定响应避免变长范围和计数歧义。
{ // 响应分别记录对象身份、读取状态和实际可用字节。
    unsigned long version; // 响应协议版本为 KSWORD_ARK_STRUCTURE_SAMPLE_VERSION。
    unsigned long size; // 响应长度为 sizeof(KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE)。
    unsigned long sampleStatus; // 快照级回执状态，不代表字段覆盖率百分比。
    long lastStatus; // 保存失败操作的 NTSTATUS，无失败时为 STATUS_SUCCESS。
    unsigned long objectType; // 回显通过校验的根类型选择值。
    unsigned long profileId; // 精确匹配时返回非零的内置配置标识。
    unsigned long flags; // 标识非原子、仅正文、指针仅作数值以及可选的内核身份有效状态。
    unsigned long atomic; // 始终为零，不声称整个对象是同一时刻的一致快照。
    unsigned long processId; // 已引用对象的实际进程身份。
    unsigned long threadId; // 已引用对象的实际线程身份，进程快照为零。
    unsigned long rootSize; // 仅由内置配置选出的精确符号 sizeof。
    unsigned long bytesCopied; // 表示 [0, rootSize) 内置位的有效位数量，不是尝试读取的字节数。
    unsigned __int64 processCreationTime100ns; // 已引用进程对象的实际创建时间。
    unsigned __int64 threadCreationTime100ns; // 已引用线程对象的实际创建时间，进程快照为零。
    unsigned __int64 objectAddress; // 作为身份数值返回已引用根对象的地址，绝不作为请求输入。
    unsigned __int64 sampleStartTime100ns; // 读取对象正文之前采集的精确系统 UTC 时间。
    unsigned __int64 sampleEndTime100ns; // 读取对象正文之后采集的精确系统 UTC 时间。
    KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID kernel; // 实际加载的内核身份，也用于解释拒绝原因。
    unsigned char valid[KSWORD_ARK_STRUCTURE_SAMPLE_VALID_BYTES]; // valid[i >> 3] 的第 (i & 7) 位表示 bytes[i] 是否已完整复制。
    unsigned char bytes[KSWORD_ARK_STRUCTURE_SAMPLE_MAX_BYTES]; // 仅暴露有效的根对象字节，其余容量始终保持零。
} KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE; // 父结构和联合体不能额外计为已成功采样的标量行。
