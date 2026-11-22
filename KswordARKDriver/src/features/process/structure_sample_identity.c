// 自行定位运行中的 NT 映像，不信任任何用户提供的地址或大小。
#include "structure_sample_profiles.h" // 引入编译内置的布局授权和共享身份字段。
#include "../bugcheck/bugcheck_identity.h" // 复用现有的有界 PE/RSDS 身份解析器。
#include "../../platform/runtime_signature_scan.h" // 所有候选读取均通过共享包装调用 MmCopyMemory。
#include <ntimage.h> // 使用系统 PE 头定义，避免依赖私有加载器布局。

// 功能：由命名内核导出取得程序地址所属映像；输入为可信导出地址，输出为映像基址。
typedef PVOID (NTAPI* KSW_STRUCTURE_IMAGE_BASE)( // 动态解析保持现有驱动导入兼容基线。
    _In_ PVOID PcValue, // 只能传入本文件通过名称取得的内核导出地址。
    _Out_ PVOID* BaseOfImage // 外部调用方不能提供此目标缓冲区或候选基址。
    ); // 明确采用内核导出的双参数调用约定。

// 功能：验证当前内核的完整身份并选择根配置；输入为输出缓冲区，失败不授权任何根范围。
NTSTATUS // 返回身份读取或精确匹配的结果状态。
KswStructureSampleResolveProfile( // 仅由 PASSIVE_LEVEL 后端调用。
    KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID* Kernel, // 内核拥有的固定身份输出。
    const KSW_STRUCTURE_SAMPLE_PROFILE** Profile // 成功时借用不可变配置指针。
    ) // 参数不包含任何调用方指定的映像地址。
{ // 全部事实保存在局部副本中，并发请求互不干扰。
    UNICODE_STRING name; // 保存本函数拥有的常量导出名称。
    KSW_STRUCTURE_IMAGE_BASE imageBase; // 保存精确的双参数映像定位导出入口。
    PVOID kernelExport; // KeBugCheckEx 仅作为程序地址锚点，绝不执行。
    PVOID base = NULL; // 运行中内核自行决定其映像基址。
    ULONG_PTR address; // 形成候选指针前先检查整数地址运算。
    IMAGE_DOS_HEADER dos; // 通过有界安全读取取得的 DOS 头副本。
    IMAGE_NT_HEADERS64 nt; // 在检查前先完整复制的 NT 头副本。
    KSWORD_BUGCHECK_IMAGE_ID identity; // 现有解析器记录 PE、GUID、Age 和失败状态。
    RtlZeroMemory(Kernel, sizeof(*Kernel)); // 拒绝路径不泄漏之前的身份内容。
    *Profile = NULL; // 精确比较成功前不授权任何对象读取范围。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) // 映像发现不能在较高 IRQL 执行。
    { // 执行级别不符合要求时直接拒绝。
        return STATUS_INVALID_DEVICE_STATE; // 不回退到不安全的内存读取。
    } // 适配入口正常在被动级队列执行，后端仍独立复核。
    RtlInitUnicodeString(&name, L"RtlPcToFileHeader"); // 解析 NT 现有的映像定位导出。
    imageBase = (KSW_STRUCTURE_IMAGE_BASE)MmGetSystemRoutineAddress(&name); // 导出缺失时明确不支持。
    RtlInitUnicodeString(&name, L"KeBugCheckEx"); // 此命名导出必须属于实际运行的 NT 映像。
    kernelExport = MmGetSystemRoutineAddress(&name); // 仅取得身份锚点，不执行任何蓝屏动作。
    if (imageBase == NULL || // 映像定位例程必须存在。
        kernelExport == NULL || // 身份锚点也必须来自真实的已加载导出。
        imageBase(kernelExport, &base) == NULL || // 由操作系统判定导出地址所属映像。
        base == NULL) // 不允许用户输入或猜测值替代映像基址。
    { // 无法取得权威基址时不继续读取头部。
        return STATUS_PROCEDURE_NOT_FOUND; // 不扫描猜测基址，也不提供地址运算回退。
    } // 映像定位成功后仍必须验证头部读取范围。
    address = (ULONG_PTR)base; // 仅转换操作系统返回的映像基址。
    if (address < (ULONG_PTR)MmSystemRangeStart || // 映像基址必须位于内核地址空间。
        address > MAXULONG_PTR - PAGE_SIZE || // 首次读取所在页的地址加法不能溢出。
        !KswordARKRuntimeReadMemory(base, &dos, sizeof(dos)) || // 不直接解引用现场映像头。
        dos.e_magic != IMAGE_DOS_SIGNATURE || // 必须存在有效的 DOS 签名。
        dos.e_lfanew <= 0L || // NT 头偏移必须为正。
        (ULONG)dos.e_lfanew > PAGE_SIZE - (ULONG)sizeof(nt) || // 首次完整 NT 头必须位于初始页内。
        !KswordARKRuntimeReadMemory( // 安全复制后才能检查完整 NT 头。
            (const VOID*)(address + (ULONG)dos.e_lfanew), // 偏移已受初始页范围约束。
            &nt, // 将读取结果保存到局部副本。
            sizeof(nt))) // 不读取固定 NT 头之外的数据。
    { // PE 初始事实不完整时不能选择任何根配置。
        return STATUS_INVALID_IMAGE_FORMAT; // 拒绝损坏或不可读的映像头。
    } // 固定初始页读取不信任映像自行声明的 SizeOfImage。
    if (nt.Signature != IMAGE_NT_SIGNATURE || // 要求完整 NT 签名。
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || // 仅支持明确配置的 x64 NT 映像。
        nt.FileHeader.SizeOfOptionalHeader < sizeof(nt.OptionalHeader) || // 被检查的可选头字段必须全部存在。
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || // 拒绝 PE32 或错误的可选头格式。
        nt.OptionalHeader.SizeOfImage < PAGE_SIZE || // 映像范围至少覆盖初始页。
        nt.OptionalHeader.SizeOfImage > 0x10000000UL || // 同时限制解析预算和候选地址范围。
        address > MAXULONG_PTR - nt.OptionalHeader.SizeOfImage || // 防止映像末端地址溢出。
        (ULONG_PTR)kernelExport < address || // 身份锚点不能位于映像基址之前。
        (ULONG_PTR)kernelExport - address >= nt.OptionalHeader.SizeOfImage) // 身份锚点必须位于此映像内部。
    { // 单凭声明的映像大小不能授权对象正文读取。
        return STATUS_INVALID_IMAGE_FORMAT; // 拒绝错误或自相矛盾的映像范围。
    } // 共享解析器现在接收已通过初步验证的映像范围。
    KswordARKBugcheckIdentityRead( // 复用现有有界 PE/RSDS 身份读取。
        address, // 基址来自系统对可信导出的归属查询。
        nt.OptionalHeader.SizeOfImage, // 使用初步验证过的映像范围。
        NULL, // 此路径不需要额外的文件路径信息。
        &identity); // 完整结果保存在当前请求的局部副本中。
    if (!NT_SUCCESS(identity.Status) || // 保留共享解析器的失败，不能接受部分身份。
        (identity.Flags & (KSWORD_BUGCHECK_ID_PE | KSWORD_BUGCHECK_ID_RSDS)) != // PE 和 RSDS 身份必须同时有效。
        (KSWORD_BUGCHECK_ID_PE | KSWORD_BUGCHECK_ID_RSDS) || // 文件名和系统版本号不能替代 RSDS。
        identity.ImageSize != nt.OptionalHeader.SizeOfImage || // 交叉核对两次读取的映像大小。
        identity.TimeDateStamp != nt.FileHeader.TimeDateStamp || // 交叉核对两次读取的 COFF 时间戳。
        identity.Checksum != nt.OptionalHeader.CheckSum) // 拒绝不完整或互不一致的身份事实。
    { // 没有完整权威身份时不能返回准入成功。
        return NT_SUCCESS(identity.Status) ? STATUS_INVALID_IMAGE_FORMAT : identity.Status; // 优先保留原始解析失败状态。
    } // 两次读取对实际运行映像的身份事实一致。
    Kernel->machine = (ULONG)nt.FileHeader.Machine; // 发布实际加载架构。
    Kernel->timeDateStamp = identity.TimeDateStamp; // 发布实际 COFF 时间戳。
    Kernel->sizeOfImage = identity.ImageSize; // 发布已验证的加载映像大小。
    Kernel->checkSum = identity.Checksum; // 发布实际 PE 校验和。
    RtlCopyMemory(Kernel->pdbGuid, identity.PdbGuid, sizeof(Kernel->pdbGuid)); // 保留原始 CodeView GUID 字节顺序。
    Kernel->pdbAge = identity.PdbAge; // 发布 RSDS Age，不使用提取器的摘要 Age。
    *Profile = KswStructureSampleFindProfile(Kernel); // 此配置是对象正文读取大小的唯一授权来源。
    return *Profile != NULL ? STATUS_SUCCESS : STATUS_REVISION_MISMATCH; // 未知内核绝不借用相邻版本布局。
} // 身份发现只读执行，不保留全局状态或调用方状态。
