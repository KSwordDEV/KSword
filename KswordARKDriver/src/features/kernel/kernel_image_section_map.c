/*++

Module Name:

    kernel_image_section_map.c

Abstract:

    只读地把一个内核虚拟地址归类到所属映像的 PE 节，供描述符表/钩子类证据判断
    目标指针是否真的位于模块的可执行节内。本文件不写内存、不改页保护。

Environment:

    Kernel mode, <= DISPATCH_LEVEL（所有映像访问都经 MmCopyMemory 保护路径）。

--*/

#include "kernel_image_section_map.h"

// 每个映像最多遍历的节数量上限，防止被伪造的 NumberOfSections 拖死循环。
#define KSW_IMAGE_SECTION_MAX_SECTIONS 96UL

static VOID
KswordARKImageCopySectionName(
    _In_reads_bytes_(IMAGE_SIZEOF_SHORT_NAME) const UCHAR* RawName,
    _Out_writes_opt_z_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars
    )
/*++

Routine Description:

    把 PE 节名的 8 字节 ANSI 原始值转成有界宽字符串。

Arguments:

    RawName - IMAGE_SECTION_HEADER::Name 的原始字节。
    Destination - 可选输出缓冲区。
    DestinationChars - 输出容量（字符数）。

Return Value:

    None. 没有提供缓冲区时直接返回。

--*/
{
    ULONG index = 0UL;

    /* 调用方可能不关心节名，此时无需任何拷贝。 */
    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }

    /* 先写终止符，保证任何提前返回路径都留下合法字符串。 */
    Destination[0] = L'\0';

    /* 逐字节转换，遇到 NUL 或缓冲区末尾即停止。 */
    for (index = 0UL; index < IMAGE_SIZEOF_SHORT_NAME && (index + 1UL) < DestinationChars; ++index) {
        /* 节名允许不以 NUL 结尾，因此显式检查每个字节。 */
        if (RawName[index] == 0U) {
            break;
        }
        /* 非可打印字节统一替换为 '?'，避免把二进制噪声塞进 UI。 */
        Destination[index] = (RawName[index] >= 0x20U && RawName[index] < 0x7FU)
            ? (WCHAR)RawName[index]
            : L'?';
    }

    /* 按实际写入长度补终止符。 */
    Destination[index] = L'\0';
}

ULONG
KswordARKImageClassifyAddress(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* ModuleEntry,
    _In_ ULONGLONG Address,
    _Out_writes_opt_z_(SectionNameChars) PWCHAR SectionName,
    _In_ ULONG SectionNameChars,
    _Out_opt_ ULONG* SectionCharacteristicsOut
    )
/*++

Routine Description:

    判断地址落在所属映像的哪个 PE 节内，并返回该节是否可执行。

Arguments:

    ModuleEntry - 地址所属的已加载模块快照条目。
    Address - 待归类的内核虚拟地址。
    SectionName - 可选，接收命中节的名字。
    SectionNameChars - SectionName 的容量。
    SectionCharacteristicsOut - 可选，接收命中节的 Characteristics。

Return Value:

    KSW_IMAGE_SECTION_RESULT_* 之一。

--*/
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG sectionTableRva = 0UL;
    ULONG sectionCount = 0UL;
    ULONG sectionIndex = 0UL;
    ULONG targetRva = 0UL;
    ULONGLONG imageBase = 0ULL;

    /* 统一初始化可选输出，调用方无需在失败路径上重复清零。 */
    if (SectionName != NULL && SectionNameChars != 0UL) {
        SectionName[0] = L'\0';
    }
    if (SectionCharacteristicsOut != NULL) {
        *SectionCharacteristicsOut = 0UL;
    }

    /* 没有模块条目或映像大小为零时无法做任何 RVA 推算。 */
    if (ModuleEntry == NULL || ModuleEntry->ImageSize == 0UL) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* 取出映像基址，后续用它把 VA 换算成 RVA。 */
    imageBase = (ULONGLONG)(ULONG_PTR)ModuleEntry->ImageBase;

    /* 地址必须真的落在该映像区间内，否则本次归类没有意义。 */
    if (imageBase == 0ULL ||
        Address < imageBase ||
        (Address - imageBase) >= (ULONGLONG)ModuleEntry->ImageSize) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* 到这里差值一定小于 ImageSize（ULONG），转换不会截断。 */
    targetRva = (ULONG)(Address - imageBase);

    /* 读取 DOS 头只是为了拿到 e_lfanew，用于定位节表。 */
    RtlZeroMemory(&dosHeader, sizeof(dosHeader));
    if (!KswordARKHookReadImageBytes(ModuleEntry, 0UL, &dosHeader, sizeof(dosHeader))) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* DOS 签名或 PE 偏移非法时按不可归类处理，不做任何猜测。 */
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* NT 头由公共帮助函数读取，它同时校验 PE/OptionalHeader 签名。 */
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    if (!KswordARKHookReadImageNtHeaders(ModuleEntry, &ntHeaders)) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* 节数量为零或异常大时拒绝遍历，避免被构造的头部拖住。 */
    sectionCount = ntHeaders.FileHeader.NumberOfSections;
    if (sectionCount == 0UL || sectionCount > KSW_IMAGE_SECTION_MAX_SECTIONS) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* 节表紧跟在可选头之后：e_lfanew + 4(Signature) + FileHeader + SizeOfOptionalHeader。 */
    sectionTableRva = (ULONG)dosHeader.e_lfanew;
    if (!KswordARKHookAddRvaOffset(sectionTableRva, 1UL, sizeof(ULONG), &sectionTableRva) ||
        !KswordARKHookAddRvaOffset(sectionTableRva, 1UL, sizeof(IMAGE_FILE_HEADER), &sectionTableRva) ||
        !KswordARKHookAddRvaOffset(sectionTableRva, 1UL, ntHeaders.FileHeader.SizeOfOptionalHeader, &sectionTableRva)) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* 逐节比较目标 RVA 是否落在 [VirtualAddress, VirtualAddress + 节长) 内。 */
    for (sectionIndex = 0UL; sectionIndex < sectionCount; ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG sectionHeaderRva = 0UL;
        ULONG sectionLength = 0UL;

        /*
         * 计算第 sectionIndex 个节头的 RVA，溢出即终止遍历。
         * 节表没走完就不知道目标到底在哪个节，必须返回 UNKNOWN（无法判断）：
         * 若在这里 break 后落到末尾的 OUTSIDE_SECTIONS，一个合法函数只因为它之前的某个
         * 节头页恰好读失败，就会被当成"落在节外"，进而被上层升级成最高危的隐藏行为。
         */
        if (!KswordARKHookAddRvaOffset(sectionTableRva, sectionIndex, sizeof(IMAGE_SECTION_HEADER), &sectionHeaderRva)) {
            return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
        }

        /* 节头必须完整落在映像内才允许读取；读失败同样是"无法判断"，不是"节外"。 */
        RtlZeroMemory(&sectionHeader, sizeof(sectionHeader));
        if (!KswordARKHookReadImageBytes(ModuleEntry, sectionHeaderRva, &sectionHeader, sizeof(sectionHeader))) {
            return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
        }

        /* 内存中的节长度取 VirtualSize 与 SizeOfRawData 的较大值，兼容两种对齐写法。 */
        sectionLength = sectionHeader.Misc.VirtualSize;
        if (sectionLength < sectionHeader.SizeOfRawData) {
            sectionLength = sectionHeader.SizeOfRawData;
        }

        /* 长度为零的节不占地址空间，直接跳过。 */
        if (sectionLength == 0UL) {
            continue;
        }

        /* 目标 RVA 落在本节区间内则完成归类。 */
        if (targetRva >= sectionHeader.VirtualAddress &&
            (targetRva - sectionHeader.VirtualAddress) < sectionLength) {
            /* 回填节名与 Characteristics，供上层生成可读证据。 */
            KswordARKImageCopySectionName(sectionHeader.Name, SectionName, SectionNameChars);
            if (SectionCharacteristicsOut != NULL) {
                *SectionCharacteristicsOut = sectionHeader.Characteristics;
            }
            /* 只有带 MEM_EXECUTE 的节才算合法的代码落点。 */
            return ((sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0UL)
                ? KSW_IMAGE_SECTION_RESULT_EXECUTABLE
                : KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE;
        }
    }

    /* 遍历完仍未命中，说明地址位于 PE 头区或节间空洞。 */
    return KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS;
}
