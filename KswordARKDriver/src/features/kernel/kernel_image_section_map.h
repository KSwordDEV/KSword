#pragma once

//
// kernel_image_section_map.h
//
// 将内核虚拟地址归类到所属映像的 PE 节（section）。只读诊断用途：调用方用它
// 判断一个函数指针是否真的落在模块的可执行节内，而不是仅仅落在映像地址区间里。
//

#include "ark/ark_driver.h"

#include "hook_scan_support.h"

EXTERN_C_START

// 节名副本的最大字符数。PE 节名固定 8 字节，留一位写终止符。
#define KSW_IMAGE_SECTION_NAME_CHARS 9UL

// 地址无法归类：PE 头不可读或模块条目缺失。
#define KSW_IMAGE_SECTION_RESULT_UNKNOWN 0UL
// 地址落在带 IMAGE_SCN_MEM_EXECUTE 的节内。
#define KSW_IMAGE_SECTION_RESULT_EXECUTABLE 1UL
// 地址落在节内，但该节不可执行。
#define KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE 2UL
// 地址在映像范围内却不属于任何节（PE 头区或节间空洞）。
#define KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS 3UL

ULONG
KswordARKImageClassifyAddress(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* ModuleEntry,
    _In_ ULONGLONG Address,
    _Out_writes_opt_z_(SectionNameChars) PWCHAR SectionName,
    _In_ ULONG SectionNameChars,
    _Out_opt_ ULONG* SectionCharacteristicsOut
    );

// Prove a complete static LIST_ENTRY lies inside a resident writable, non-executable .data section.
BOOLEAN KswordARKImageContainsStaticWritableList(_In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _In_ ULONGLONG Address);

EXTERN_C_END
