/*++

Module Name:

    runtime_signature_scan.c

Abstract:

    Shared x64 runtime-signature support.  The scanner begins at stable PE
    exports, follows a bounded number of direct relative calls or jumps, and
    records only RIP-relative references that resolve into the same loaded
    image.  It deliberately does not publish a candidate: feature-specific
    callers must still require a unique match and validate the live structure.

Environment:

    Kernel mode, PASSIVE_LEVEL initialization or read-only query paths.

--*/

#include "runtime_signature_scan.h"
#include <ntimage.h>

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID ImageBase,
    _In_ PCCH RoutineName
    );

typedef struct _KSW_RUNTIME_ROUTINE_WORK
{
    ULONG_PTR Address;
    ULONG Depth;
} KSW_RUNTIME_ROUTINE_WORK, *PKSW_RUNTIME_ROUTINE_WORK;

BOOLEAN
KswordARKRuntimeReadMemory(
    _In_ const VOID* Address,
    _Out_writes_bytes_(Size) VOID* Buffer,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    Copy a bounded kernel-memory range while containing invalid candidates.

Return Value:

    TRUE only when the complete range was readable.

--*/
{
    MM_COPY_ADDRESS sourceAddress;
    SIZE_T bytesTransferred = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (Address == NULL || Buffer == NULL || Size == 0U) {
        return FALSE;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }
    RtlZeroMemory(&sourceAddress, sizeof(sourceAddress));
    sourceAddress.VirtualAddress = (PVOID)Address;
    status = MmCopyMemory(
        Buffer,
        sourceAddress,
        Size,
        MM_COPY_MEMORY_VIRTUAL,
        &bytesTransferred);
    return NT_SUCCESS(status) && bytesTransferred == Size;
}

BOOLEAN
KswordARKRuntimeAddressInImage(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T RequiredBytes
    )
/*++

Routine Description:

    Validate a non-wrapping address range against the loaded image interval.

Return Value:

    TRUE when every requested byte is contained by the image.

--*/
{
    ULONG_PTR imageEnd = 0U;

    if (View == NULL || View->Base == 0U || View->Size == 0UL ||
        RequiredBytes == 0U || View->Base > MAXULONG_PTR - View->Size) {
        return FALSE;
    }
    imageEnd = View->Base + View->Size;
    return Address >= View->Base && Address < imageEnd &&
        RequiredBytes <= imageEnd - Address;
}

static BOOLEAN
KswordARKRuntimeRangeInSection(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T RequiredBytes,
    _In_ ULONG RequiredCharacteristics,
    _In_ ULONG RejectedCharacteristics
    )
/*++

Routine Description:

    Match one range against a PE section with required and rejected flags.

Return Value:

    TRUE when one complete section range satisfies the policy.

--*/
{
    ULONG index = 0UL;

    if (!KswordARKRuntimeAddressInImage(View, Address, RequiredBytes)) {
        return FALSE;
    }
    for (index = 0UL; index < View->SectionCount; ++index) {
        const KSW_RUNTIME_IMAGE_SECTION* section = &View->Sections[index];

        if ((section->Characteristics & RequiredCharacteristics) !=
                RequiredCharacteristics ||
            (section->Characteristics & RejectedCharacteristics) != 0UL ||
            Address < section->Start || Address >= section->End ||
            RequiredBytes > section->End - Address) {
            continue;
        }
        return TRUE;
    }
    return FALSE;
}

BOOLEAN
KswordARKRuntimeAddressIsExecutable(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T RequiredBytes
    )
{
    return KswordARKRuntimeRangeInSection(
        View,
        Address,
        RequiredBytes,
        IMAGE_SCN_MEM_EXECUTE,
        0UL);
}

BOOLEAN
KswordARKRuntimeAddressIsWritableData(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T RequiredBytes
    )
{
    return KswordARKRuntimeRangeInSection(
        View,
        Address,
        RequiredBytes,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        IMAGE_SCN_MEM_EXECUTE);
}

BOOLEAN
KswordARKRuntimeInitializeImageView(
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize,
    _Out_ PKSW_RUNTIME_IMAGE_VIEW ViewOut
    )
/*++

Routine Description:

    Parse a loaded PE image and retain bounded virtual section intervals.

Return Value:

    TRUE when DOS, NT, optional, and section headers are internally consistent.

--*/
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    ULONG_PTR base = (ULONG_PTR)ImageBase;
    ULONG_PTR ntAddress = 0U;
    ULONG_PTR sectionAddress = 0U;
    ULONG sectionCount = 0UL;
    ULONG index = 0UL;

    if (ViewOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(ViewOut, sizeof(*ViewOut));
    if (ImageBase == NULL || ImageSize < sizeof(dosHeader) ||
        !KswordARKRuntimeReadMemory(ImageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0 ||
        (ULONG)dosHeader.e_lfanew > ImageSize - sizeof(ntHeaders) ||
        base > MAXULONG_PTR - (ULONG)dosHeader.e_lfanew) {
        return FALSE;
    }

    ntAddress = base + (ULONG)dosHeader.e_lfanew;
    if (!KswordARKRuntimeReadMemory(
            (const VOID*)ntAddress,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > KSW_RUNTIME_IMAGE_MAX_SECTIONS ||
        ntHeaders.OptionalHeader.SizeOfImage == 0UL ||
        ntHeaders.OptionalHeader.SizeOfImage > ImageSize) {
        return FALSE;
    }

    sectionCount = ntHeaders.FileHeader.NumberOfSections;
    sectionAddress = ntAddress + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    if (sectionAddress < ntAddress || sectionAddress < base ||
        sectionCount > (ImageSize / sizeof(IMAGE_SECTION_HEADER)) ||
        sectionAddress - base >= ImageSize ||
        (SIZE_T)sectionCount * sizeof(IMAGE_SECTION_HEADER) >
            ImageSize - (sectionAddress - base)) {
        return FALSE;
    }

    ViewOut->Base = base;
    ViewOut->Size = ntHeaders.OptionalHeader.SizeOfImage;
    for (index = 0UL; index < sectionCount; ++index) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG virtualBytes = 0UL;
        ULONG_PTR start = 0U;
        ULONG_PTR end = 0U;

        if (!KswordARKRuntimeReadMemory(
                (const VOID*)(sectionAddress +
                    ((ULONG_PTR)index * sizeof(sectionHeader))),
                &sectionHeader,
                sizeof(sectionHeader))) {
            RtlZeroMemory(ViewOut, sizeof(*ViewOut));
            return FALSE;
        }
        virtualBytes = max(sectionHeader.Misc.VirtualSize, sectionHeader.SizeOfRawData);
        if (virtualBytes == 0UL || sectionHeader.VirtualAddress >= ViewOut->Size ||
            virtualBytes > ViewOut->Size - sectionHeader.VirtualAddress ||
            base > MAXULONG_PTR - sectionHeader.VirtualAddress) {
            continue;
        }
        start = base + sectionHeader.VirtualAddress;
        if (start > MAXULONG_PTR - virtualBytes) {
            continue;
        }
        end = start + virtualBytes;
        ViewOut->Sections[ViewOut->SectionCount].Start = start;
        ViewOut->Sections[ViewOut->SectionCount].End = end;
        ViewOut->Sections[ViewOut->SectionCount].Characteristics =
            sectionHeader.Characteristics;
        ViewOut->SectionCount += 1UL;
    }

    if (ViewOut->SectionCount == 0UL) {
        RtlZeroMemory(ViewOut, sizeof(*ViewOut));
        return FALSE;
    }
    return TRUE;
}

PVOID
KswordARKRuntimeFindExport(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_z_ PCSTR ExportName
    )
/*++

Routine Description:

    Resolve one export and require its address to remain in the supplied image.

Return Value:

    Export address or NULL.

--*/
{
    PVOID address = NULL;

    if (View == NULL || ExportName == NULL || View->Base == 0U) {
        return NULL;
    }
    address = RtlFindExportedRoutineByName((PVOID)View->Base, ExportName);
    return KswordARKRuntimeAddressInImage(View, (ULONG_PTR)address, 1U)
        ? address
        : NULL;
}

static BOOLEAN
KswordARKRuntimeResolveRelativeTarget(
    _In_ ULONG_PTR NextInstruction,
    _In_ LONG Displacement,
    _Out_ ULONG_PTR* TargetOut
    )
{
    ULONG_PTR magnitude = 0U;

    if (TargetOut == NULL) {
        return FALSE;
    }
    if (Displacement >= 0) {
        if (NextInstruction > MAXULONG_PTR - (ULONG)Displacement) {
            return FALSE;
        }
        *TargetOut = NextInstruction + (ULONG)Displacement;
        return TRUE;
    }
    magnitude = (ULONG_PTR)(-(LONGLONG)Displacement);
    if (NextInstruction < magnitude) {
        return FALSE;
    }
    *TargetOut = NextInstruction - magnitude;
    return TRUE;
}

static BOOLEAN
KswordARKRuntimeDecodeRipReference(
    _In_ ULONG_PTR InstructionAddress,
    _Out_ ULONG_PTR* TargetOut,
    _Out_opt_ ULONG* InstructionBytesOut
    )
/*++

Routine Description:

    Decode the small x64 instruction subset used for RIP-relative data access.
    Unsupported encodings are ignored instead of guessed.

Return Value:

    TRUE when a complete supported instruction resolved safely.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    UCHAR bytes[16];
    ULONG cursor = 0UL;
    ULONG modRmOffset = 0UL;
    ULONG displacementOffset = 0UL;
    ULONG instructionBytes = 0UL;
    BOOLEAN supportedOpcode = FALSE;
    LONG displacement = 0L;

    if (TargetOut == NULL ||
        !KswordARKRuntimeReadMemory(
            (const VOID*)InstructionAddress,
            bytes,
            sizeof(bytes))) {
        return FALSE;
    }

    while (cursor < 4UL &&
           (bytes[cursor] == 0x66U || bytes[cursor] == 0xF2U ||
            bytes[cursor] == 0xF3U ||
            (bytes[cursor] >= 0x40U && bytes[cursor] <= 0x4FU))) {
        cursor += 1UL;
    }
    if (cursor >= sizeof(bytes)) {
        return FALSE;
    }

    if (bytes[cursor] == 0x0FU) {
        cursor += 1UL;
        if (cursor >= sizeof(bytes)) {
            return FALSE;
        }
        supportedOpcode = bytes[cursor] == 0xB6U || bytes[cursor] == 0xB7U ||
            bytes[cursor] == 0xBEU || bytes[cursor] == 0xBFU;
    }
    else {
        supportedOpcode = bytes[cursor] == 0x8BU || bytes[cursor] == 0x8DU ||
            bytes[cursor] == 0x89U || bytes[cursor] == 0x39U ||
            bytes[cursor] == 0x3BU || bytes[cursor] == 0x63U ||
            bytes[cursor] == 0x85U || bytes[cursor] == 0xFFU;
    }
    if (!supportedOpcode) {
        return FALSE;
    }

    modRmOffset = cursor + 1UL;
    if (modRmOffset >= sizeof(bytes) || (bytes[modRmOffset] & 0xC7U) != 0x05U) {
        return FALSE;
    }
    displacementOffset = modRmOffset + 1UL;
    instructionBytes = displacementOffset + sizeof(displacement);
    if (instructionBytes > sizeof(bytes)) {
        return FALSE;
    }
    RtlCopyMemory(&displacement, bytes + displacementOffset, sizeof(displacement));
    if (!KswordARKRuntimeResolveRelativeTarget(
            InstructionAddress + instructionBytes,
            displacement,
            TargetOut)) {
        return FALSE;
    }
    if (InstructionBytesOut != NULL) {
        *InstructionBytesOut = instructionBytes;
    }
    return TRUE;
#else
    UNREFERENCED_PARAMETER(InstructionAddress);
    UNREFERENCED_PARAMETER(TargetOut);
    UNREFERENCED_PARAMETER(InstructionBytesOut);
    return FALSE;
#endif
}

static BOOLEAN
KswordARKRuntimeDecodeDirectBranch(
    _In_ ULONG_PTR InstructionAddress,
    _Out_ ULONG_PTR* TargetOut,
    _Out_ ULONG* InstructionBytesOut
    )
{
    UCHAR bytes[5]; // 保存完整的 rel8 或 rel32 分支指令。
    LONG displacement = 0L; // 有符号位移用于安全计算前向或后向目标。
    ULONG instructionBytes = 0UL; // 输出真实长度，禁止分支跨越已确认的函数边界。

    if (TargetOut == NULL || InstructionBytesOut == NULL ||
        !KswordARKRuntimeReadMemory(
            (const VOID*)InstructionAddress,
            bytes,
            1U)) { // 先读 opcode，短跳转无需假定后面还有五字节。
        return FALSE;
    }
    if (bytes[0] == 0xEBU) { // EB rel8 是导出短跳板和尾跳转的明确编码。
        instructionBytes = 2UL; // rel8 指令总长为两字节。
    }
    else if (bytes[0] == 0xE8U || bytes[0] == 0xE9U) { // 保留已有直接 call/jmp 支持。
        instructionBytes = 5UL; // rel32 指令总长为五字节。
    }
    else {
        return FALSE; // 间接调用和未知编码不能推测目的地址。
    }
    if (!KswordARKRuntimeReadMemory(
            (const VOID*)InstructionAddress, bytes, instructionBytes) ||
        InstructionAddress > MAXULONG_PTR - instructionBytes) {
        return FALSE; // 不完整读取或下一指令地址溢出时拒绝候选。
    }
    if (instructionBytes == 2UL) {
        displacement = (LONG)(CHAR)bytes[1]; // 显式符号扩展后向 rel8。
    }
    else {
        RtlCopyMemory(&displacement, bytes + 1UL, sizeof(displacement)); // 仅复制本地快照。
    }
    *InstructionBytesOut = instructionBytes; // 调用方用此值验证完整指令范围。
    return KswordARKRuntimeResolveRelativeTarget(
        InstructionAddress + instructionBytes,
        displacement,
        TargetOut);
}

static BOOLEAN
KswordARKRuntimeAppendReference(
    _Inout_updates_(Capacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG Capacity,
    _Inout_ ULONG* Count,
    _In_ ULONG_PTR Address,
    _In_ ULONG_PTR RoutineAddress,
    _In_ ULONG_PTR InstructionAddress
    )
{
    ULONG index = 0UL;

    if (References == NULL || Count == NULL || *Count > Capacity) {
        return FALSE;
    }
    for (index = 0UL; index < *Count; ++index) {
        if (References[index].Address == Address &&
            References[index].RoutineAddress == RoutineAddress) {
            return TRUE;
        }
    }
    if (*Count >= Capacity) {
        return FALSE;
    }
    References[*Count].Address = Address;
    References[*Count].RoutineAddress = RoutineAddress;
    References[*Count].InstructionAddress = InstructionAddress;
    *Count += 1UL;
    return TRUE;
}

static ULONG
KswordARKRuntimeFunctionScanBytes(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR RoutineAddress,
    _In_ ULONG Limit
    )
{
    IMAGE_DOS_HEADER dos; // 通过安全读取定位当前 PE 的 NT 头。
    IMAGE_NT_HEADERS64 nt; // x64 函数表由异常目录提供，无需符号文件。
    IMAGE_DATA_DIRECTORY directory; // 每个函数条目包含起止 RVA。
    ULONG left = 0UL; // 在有界函数表内二分查找。
    ULONG right = 0UL; // 右端为不包含的条目下标。
    ULONG rva = 0UL; // 查找地址必须属于当前映像。

    // 拒绝缺失映像、越界地址和不可执行的入口。
    if (View == NULL || Limit == 0UL ||
        !KswordARKRuntimeAddressIsExecutable(View, RoutineAddress, 1U) ||
        !KswordARKRuntimeReadMemory((const VOID*)View->Base, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0L ||
        !KswordARKRuntimeAddressInImage(View, View->Base + (ULONG)dos.e_lfanew, sizeof(nt)) ||
        !KswordARKRuntimeReadMemory((const VOID*)(View->Base + (ULONG)dos.e_lfanew), &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        return 0UL; // 缺少可信函数表时不猜测相邻代码边界。
    }
    directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]; // 读取异常目录描述。
    // 整张函数表必须完整位于当前映像且长度为条目大小的倍数。
    if (directory.VirtualAddress == 0UL || directory.Size == 0UL ||
        directory.Size % sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) != 0UL ||
        !KswordARKRuntimeAddressInImage(View, View->Base + directory.VirtualAddress, directory.Size)) {
        return 0UL; // 不扫描损坏或截断的函数表。
    }
    rva = (ULONG)(RoutineAddress - View->Base); // 已检查入口范围，转换不会截断。
    right = directory.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY); // 限定查找规模。
    // PE x64 函数表按 BeginAddress 排序；每步严格缩小搜索区间。
    while (left < right) {
        ULONG middle = left + (right - left) / 2UL; // 避免下标相加溢出。
        IMAGE_RUNTIME_FUNCTION_ENTRY entry; // 只读取本轮所需的条目。
        ULONG_PTR address = View->Base + directory.VirtualAddress +
            (SIZE_T)middle * sizeof(entry); // 整体目录范围已验证。

        // 拒绝不可读条目和错误的起止范围。
        if (!KswordARKRuntimeReadMemory((const VOID*)address, &entry, sizeof(entry)) ||
            entry.BeginAddress >= entry.EndAddress || entry.EndAddress > View->Size) {
            return 0UL; // 目录损坏时不回退到固定长度猜测。
        }
        if (rva < entry.BeginAddress) { // 入口在当前条目之前。
            right = middle; // 收缩搜索上界。
        }
        else if (rva >= entry.EndAddress) { // 入口在当前条目之后。
            left = middle + 1UL; // 收缩搜索下界。
        }
        else { // 已找到包含该入口的函数范围。
            ULONG bytes = min(Limit, entry.EndAddress - rva); // 保留原有单函数扫描预算。
            return KswordARKRuntimeAddressIsExecutable(View, RoutineAddress, bytes)
                ? bytes : 0UL; // 整段扫描范围也必须属于一个可执行节。
        }
    }
    return 0UL; // 没有函数表条目的叶函数不作为继续遍历的依据。
}

static ULONG
KswordARKRuntimeScanRoutine(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR RoutineAddress,
    _In_ ULONG ScanBytes,
    _In_ BOOLEAN FunctionBounds,
    _Inout_updates_(ReferenceCapacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCapacity,
    _Inout_ ULONG* ReferenceCount,
    _Out_writes_opt_(BranchCapacity) ULONG_PTR* BranchTargets,
    _In_ ULONG BranchCapacity
    )
{
    ULONG offset = 0UL;
    ULONG branchCount = 0UL;

    if (View == NULL || References == NULL || ReferenceCount == NULL ||
        !KswordARKRuntimeAddressIsExecutable(View, RoutineAddress, 1U)) {
        return 0UL;
    }

    if (FunctionBounds) { // 私有全局扫描必须受 PE 自带函数边界限制。
        ScanBytes = KswordARKRuntimeFunctionScanBytes(View, RoutineAddress, ScanBytes); // 不扫描相邻函数。
        if (ScanBytes == 0UL) { // 简单导出跳板可能没有 x64 unwind 条目。
            UCHAR opcode = 0U; // 只认可入口处明确的无条件跳转，不扫描未知叶函数。
            ULONG_PTR target = 0U; // 跳板的目标仍须位于当前模块可执行节。
            ULONG instructionBytes = 0UL; // 校验整个跳板指令的映像边界。
            if (BranchTargets != NULL && BranchCapacity != 0UL &&
                KswordARKRuntimeReadMemory((const VOID*)RoutineAddress, &opcode, sizeof(opcode)) &&
                (opcode == 0xE9U || opcode == 0xEBU) &&
                KswordARKRuntimeDecodeDirectBranch(RoutineAddress, &target, &instructionBytes) &&
                KswordARKRuntimeAddressIsExecutable(View, RoutineAddress, instructionBytes) &&
                KswordARKRuntimeAddressIsExecutable(View, target, 1U)) {
                BranchTargets[0] = target; // 后续轮次仍以目标函数的 PE 条目限定扫描。
                return 1UL; // 当前跳板只提供一个跳转目标，不发布数据候选。
            }
            return 0UL; // 无法确认函数或跳板时保留不可用状态。
        }
    }
    for (offset = 0UL; offset < ScanBytes; ++offset) {
        ULONG_PTR instructionAddress = RoutineAddress + offset;
        ULONG_PTR target = 0U;
        ULONG instructionBytes = 0UL; // 有函数边界时禁止使用跨界指令产生的候选。

        if (!KswordARKRuntimeAddressIsExecutable(View, instructionAddress, 1U)) {
            break;
        }
        if (KswordARKRuntimeDecodeRipReference(instructionAddress, &target, &instructionBytes) &&
            (!FunctionBounds || instructionBytes <= ScanBytes - offset) && // 指令整体必须位于扫描范围。
            KswordARKRuntimeAddressInImage(View, target, 1U) &&
            !KswordARKRuntimeAddressIsExecutable(View, target, 1U)) {
            if (!KswordARKRuntimeAppendReference(
                    References,
                    ReferenceCapacity,
                    ReferenceCount,
                    target,
                    RoutineAddress,
                    instructionAddress)) {
                break;
            }
        }
        if (BranchTargets != NULL && branchCount < BranchCapacity &&
            KswordARKRuntimeDecodeDirectBranch(instructionAddress, &target, &instructionBytes) &&
            (instructionBytes == 5UL || (FunctionBounds && // 保持旧固定窗口扫描器的 rel32 行为。
             (target < RoutineAddress || target - RoutineAddress >= ScanBytes))) && // 只跟踪离开当前扫描范围的 rel8，避免重复加入内部短分支。
            (!FunctionBounds || instructionBytes <= ScanBytes - offset) && // rel8/rel32 均不得跨函数边界。
            KswordARKRuntimeAddressIsExecutable(View, target, 1U)) {
            ULONG branchIndex = 0UL;
            BOOLEAN duplicate = FALSE;

            for (branchIndex = 0UL; branchIndex < branchCount; ++branchIndex) {
                if (BranchTargets[branchIndex] == target) {
                    duplicate = TRUE;
                    break;
                }
            }
            if (!duplicate) {
                BranchTargets[branchCount++] = target;
            }
        }
    }
    return branchCount;
}

static ULONG
KswordARKRuntimeCollectAnchoredReferencesInternal(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_reads_(AnchorCount) PCSTR const* AnchorNames,
    _In_ ULONG AnchorCount,
    _In_ ULONG MaxCallDepth,
    _In_ ULONG RoutineScanBytes,
    _In_ BOOLEAN FunctionBounds,
    _Out_writes_(ReferenceCapacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCapacity
    )
/*++

Routine Description:

    Scan stable exports and a bounded direct-call graph for image data references.

Return Value:

    Number of unique address/routine pairs stored in References.

--*/
{
    KSW_RUNTIME_ROUTINE_WORK work[KSW_RUNTIME_SIGNATURE_MAX_ROUTINES];
    ULONG workCount = 0UL;
    ULONG workIndex = 0UL;
    ULONG referenceCount = 0UL;
    ULONG anchorIndex = 0UL;

    if (View == NULL || AnchorNames == NULL || AnchorCount == 0UL ||
        RoutineScanBytes == 0UL || References == NULL || ReferenceCapacity == 0UL) {
        return 0UL;
    }
    RtlZeroMemory(References, (SIZE_T)ReferenceCapacity * sizeof(*References));
    RtlZeroMemory(work, sizeof(work));

    for (anchorIndex = 0UL;
         anchorIndex < AnchorCount && workCount < RTL_NUMBER_OF(work);
         ++anchorIndex) {
        ULONG_PTR address = (ULONG_PTR)KswordARKRuntimeFindExport(
            View,
            AnchorNames[anchorIndex]);
        ULONG index = 0UL;
        BOOLEAN duplicate = FALSE;

        if (address == 0U || !KswordARKRuntimeAddressIsExecutable(View, address, 1U)) {
            continue;
        }
        for (index = 0UL; index < workCount; ++index) {
            if (work[index].Address == address) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate) {
            work[workCount].Address = address;
            work[workCount].Depth = 0UL;
            workCount += 1UL;
        }
    }

    while (workIndex < workCount && referenceCount < ReferenceCapacity) {
        ULONG_PTR branches[KSW_RUNTIME_SIGNATURE_MAX_ROUTINES];
        ULONG branchCount = 0UL;
        ULONG branchIndex = 0UL;

        RtlZeroMemory(branches, sizeof(branches));
        branchCount = KswordARKRuntimeScanRoutine(
            View,
            work[workIndex].Address,
            RoutineScanBytes,
            FunctionBounds, // 由调用者选择是否强制使用 PE 函数范围。
            References,
            ReferenceCapacity,
            &referenceCount,
            branches,
            RTL_NUMBER_OF(branches));
        if (work[workIndex].Depth < MaxCallDepth) {
            for (branchIndex = 0UL;
                 branchIndex < branchCount && workCount < RTL_NUMBER_OF(work);
                 ++branchIndex) {
                ULONG existingIndex = 0UL;
                BOOLEAN duplicate = FALSE;

                for (existingIndex = 0UL; existingIndex < workCount; ++existingIndex) {
                    if (work[existingIndex].Address == branches[branchIndex]) {
                        duplicate = TRUE;
                        break;
                    }
                }
                if (!duplicate) {
                    work[workCount].Address = branches[branchIndex];
                    work[workCount].Depth = work[workIndex].Depth + 1UL;
                    workCount += 1UL;
                }
            }
        }
        workIndex += 1UL;
    }
    return referenceCount;
}

ULONG
KswordARKRuntimeCollectAnchoredDataReferences(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_reads_(AnchorCount) PCSTR const* AnchorNames,
    _In_ ULONG AnchorCount,
    _In_ ULONG MaxCallDepth,
    _In_ ULONG RoutineScanBytes,
    _Out_writes_(ReferenceCapacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCapacity
    )
{
    return KswordARKRuntimeCollectAnchoredReferencesInternal(View, AnchorNames,
        AnchorCount, MaxCallDepth, RoutineScanBytes, FALSE, References, ReferenceCapacity); // 保持其它使用者现有扫描语义。
}

ULONG
KswordARKRuntimeCollectFunctionDataReferences(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_reads_(AnchorCount) PCSTR const* AnchorNames,
    _In_ ULONG AnchorCount,
    _In_ ULONG MaxCallDepth,
    _In_ ULONG RoutineScanBytes,
    _Out_writes_(ReferenceCapacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCapacity
    )
{
    return KswordARKRuntimeCollectAnchoredReferencesInternal(View, AnchorNames,
        AnchorCount, MaxCallDepth, RoutineScanBytes, TRUE, References, ReferenceCapacity); // 以无 PDB 的函数表限制遍历范围。
}

ULONG
KswordARKRuntimeCollectExecutableDataReferences(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG ScanByteBudget,
    _Out_writes_(ReferenceCapacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCapacity
    )
/*++

Routine Description:

    Scan executable PE sections when a module exposes no stable public anchor.
    The caller supplies a global byte budget and must still perform unique,
    feature-specific live validation before using any reference.

Return Value:

    Number of stored unique address/section-start pairs.

--*/
{
    ULONG referenceCount = 0UL;
    ULONG scannedBytes = 0UL;
    ULONG sectionIndex = 0UL;

    if (View == NULL || ScanByteBudget == 0UL || References == NULL ||
        ReferenceCapacity == 0UL) {
        return 0UL;
    }
    RtlZeroMemory(References, (SIZE_T)ReferenceCapacity * sizeof(*References));
    for (sectionIndex = 0UL;
         sectionIndex < View->SectionCount && scannedBytes < ScanByteBudget &&
             referenceCount < ReferenceCapacity;
         ++sectionIndex) {
        const KSW_RUNTIME_IMAGE_SECTION* section = &View->Sections[sectionIndex];
        ULONG sectionBytes = 0UL;
        ULONG remainingBudget = ScanByteBudget - scannedBytes;

        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0UL ||
            section->End <= section->Start) {
            continue;
        }
        sectionBytes = (ULONG)min(
            section->End - section->Start,
            (ULONG_PTR)remainingBudget);
        (VOID)KswordARKRuntimeScanRoutine(
            View,
            section->Start,
            sectionBytes,
            FALSE, // 整节扫描不使用单函数边界。
            References,
            ReferenceCapacity,
            &referenceCount,
            NULL,
            0UL);
        scannedBytes += sectionBytes;
    }
    return referenceCount;
}

ULONG
KswordARKRuntimeCollectExecutableDataReferenceBatch(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG ScanByteBudget,
    _Inout_ ULONG* CursorRva,
    _Out_writes_(ReferenceCapacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCapacity,
    _Out_ ULONG* ScannedBytesOut
    )
{
    ULONG referenceCount = 0UL;
    ULONG sectionIndex = 0UL;

    if (ScannedBytesOut != NULL) {
        *ScannedBytesOut = 0UL;
    }
    if (View == NULL || CursorRva == NULL || ScannedBytesOut == NULL ||
        References == NULL || ReferenceCapacity == 0UL || ScanByteBudget == 0UL ||
        *CursorRva >= View->Size) {
        return 0UL;
    }
    RtlZeroMemory(References, (SIZE_T)ReferenceCapacity * sizeof(*References));
    for (sectionIndex = 0UL; sectionIndex < View->SectionCount; ++sectionIndex) {
        const KSW_RUNTIME_IMAGE_SECTION* section = &View->Sections[sectionIndex];
        ULONG_PTR cursor;

        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0UL ||
            section->End <= section->Start || section->End <= View->Base + *CursorRva) {
            continue;
        }
        cursor = max(section->Start, View->Base + *CursorRva);
        while (cursor < section->End && *ScannedBytesOut < ScanByteBudget &&
            referenceCount < ReferenceCapacity) {
            ULONG_PTR target = 0U;
            ULONG instructionBytes = 0UL;

            if (KswordARKRuntimeDecodeRipReference(cursor, &target, &instructionBytes) &&
                instructionBytes <= section->End - cursor &&
                KswordARKRuntimeAddressInImage(View, target, 1U) &&
                !KswordARKRuntimeAddressIsExecutable(View, target, 1U)) {
                (VOID)KswordARKRuntimeAppendReference(References, ReferenceCapacity,
                    &referenceCount, target, section->Start, cursor);
            }
            ++cursor;
            ++*ScannedBytesOut;
        }
        *CursorRva = (ULONG)(cursor - View->Base);
        if (*ScannedBytesOut >= ScanByteBudget || referenceCount >= ReferenceCapacity) {
            return referenceCount;
        }
    }
    *CursorRva = View->Size;
    return referenceCount;
}

BOOLEAN
KswordARKRuntimeFindEnclosingRoutine(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR InstructionAddress,
    _Out_ PULONG_PTR RoutineEntryOut
    )
/*++

Routine Description:

    Locate the RUNTIME_FUNCTION entry whose [BeginAddress, EndAddress) RVA
    range contains InstructionAddress. Uses the PE exception directory, so
    it works on any x64 image without needing symbols.

Return Value:

    TRUE iff a matching function entry exists; FALSE otherwise. On success
    *RoutineEntryOut is the linear address of the enclosing function's entry.

--*/
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY directory;
    ULONG rva = 0UL;
    ULONG left = 0UL;
    ULONG right = 0UL;

    if (View == NULL || RoutineEntryOut == NULL) {
        return FALSE;
    }
    *RoutineEntryOut = 0U;
    if (!KswordARKRuntimeAddressIsExecutable(View, InstructionAddress, 1U) ||
        !KswordARKRuntimeReadMemory((const VOID*)View->Base, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0L ||
        !KswordARKRuntimeAddressInImage(View, View->Base + (ULONG)dos.e_lfanew, sizeof(nt)) ||
        !KswordARKRuntimeReadMemory((const VOID*)(View->Base + (ULONG)dos.e_lfanew), &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        return FALSE;
    }
    directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (directory.VirtualAddress == 0UL || directory.Size == 0UL ||
        directory.Size % sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) != 0UL ||
        !KswordARKRuntimeAddressInImage(View, View->Base + directory.VirtualAddress, directory.Size)) {
        return FALSE;
    }
    rva = (ULONG)(InstructionAddress - View->Base);
    right = directory.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    while (left < right) {
        ULONG middle = left + (right - left) / 2UL;
        IMAGE_RUNTIME_FUNCTION_ENTRY entry;
        ULONG_PTR address = View->Base + directory.VirtualAddress +
            (SIZE_T)middle * sizeof(entry);

        if (!KswordARKRuntimeReadMemory((const VOID*)address, &entry, sizeof(entry)) ||
            entry.BeginAddress >= entry.EndAddress || entry.EndAddress > View->Size) {
            return FALSE;
        }
        if (rva < entry.BeginAddress) {
            right = middle;
        }
        else if (rva >= entry.EndAddress) {
            left = middle + 1UL;
        }
        else {
            *RoutineEntryOut = View->Base + entry.BeginAddress;
            return TRUE;
        }
    }
    return FALSE;
}

ULONG
KswordARKRuntimeFindCallersOfRoutine(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR TargetAddress,
    _Out_writes_(CallerCapacity) KSW_RUNTIME_CALL_SITE* Callers,
    _In_ ULONG CallerCapacity
    )
/*++

Routine Description:

    Scan every executable section of View for direct E8/E9 rel32 instructions
    whose decoded target equals TargetAddress. Each site is collapsed to its
    enclosing RUNTIME_FUNCTION entry via the PE exception directory and added
    to Callers, de-duplicated by (CallerRoutine). Returns the number of
    unique callers recorded (capped at CallerCapacity).

    This is a byte-level scan, not a disassembly; a false positive is possible
    when a data byte in an executable section happens to be 0xE8 or 0xE9 and
    the following four bytes resolve to TargetAddress. Callers are expected
    to validate candidates downstream (e.g. by inspecting the enclosing
    function's prologue or its own call targets).

Return Value:

    Number of unique caller routines recorded (0..CallerCapacity).

--*/
{
    ULONG sectionIndex = 0UL;
    ULONG count = 0UL;

    if (View == NULL || Callers == NULL || CallerCapacity == 0UL) {
        return 0UL;
    }
    for (sectionIndex = 0UL;
         sectionIndex < View->SectionCount && count < CallerCapacity;
         ++sectionIndex) {
        const KSW_RUNTIME_IMAGE_SECTION* section = &View->Sections[sectionIndex];
        ULONG_PTR cursor;

        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0UL ||
            section->End <= section->Start) {
            continue;
        }
        /* Scan window holds a full E8/E9 rel32 (5 bytes). */
        if (section->End < section->Start + 5U) {
            continue;
        }
        cursor = section->Start;
        while (cursor <= section->End - 5U && count < CallerCapacity) {
            UCHAR opcode = 0U;
            UCHAR bytes[5];
            LONG displacement = 0L;
            ULONG_PTR target = 0U;
            ULONG_PTR enclosing = 0U;
            ULONG duplicateIndex = 0UL;
            BOOLEAN duplicate = FALSE;

            if (!KswordARKRuntimeReadMemory((const VOID*)cursor, &opcode, sizeof(opcode))) {
                ++cursor;
                continue;
            }
            if (opcode != 0xE8U && opcode != 0xE9U) {
                ++cursor;
                continue;
            }
            if (!KswordARKRuntimeReadMemory((const VOID*)cursor, bytes, sizeof(bytes))) {
                ++cursor;
                continue;
            }
            RtlCopyMemory(&displacement, bytes + 1UL, sizeof(displacement));
            /* Overflow-safe target computation: cursor + 5 + sign-extended rel32. */
            if (cursor > MAXULONG_PTR - 5U) {
                break;
            }
            target = cursor + 5U + (ULONG_PTR)(LONG_PTR)displacement;
            if (target != TargetAddress) {
                ++cursor;
                continue;
            }
            if (!KswordARKRuntimeFindEnclosingRoutine(View, cursor, &enclosing) ||
                enclosing == 0U) {
                ++cursor;
                continue;
            }
            for (duplicateIndex = 0UL; duplicateIndex < count; ++duplicateIndex) {
                if (Callers[duplicateIndex].CallerRoutine == enclosing) {
                    duplicate = TRUE;
                    break;
                }
            }
            if (!duplicate) {
                Callers[count].CallerRoutine = enclosing;
                Callers[count].CallInstruction = cursor;
                Callers[count].Opcode = opcode;
                ++count;
            }
            ++cursor;
        }
    }
    return count;
}
