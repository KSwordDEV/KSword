#pragma once

#include "KswordArkSafetyIoctl.h"

// ============================================================
// KswordArkMemoryIoctl.h
// 作用：
// - 定义 Phase-11 进程虚拟内存查询、读取和差异写入协议；
// - 定义 R0 物理内存读取、受控写入和 x64 页表解析协议；
// - 定义 R0 内核可执行页只读扫描协议，v2 增加预算、归属、保护和哈希证据；
// - R3/R0 共享本文件中的结构，不在 UI 或 Client 侧重复定义；
// - 写入协议只承载已编辑的差异块，不提供分配、释放或保护修改；
// - 页表协议只做只读解析，不默认提供 PTE/PDE 修改能力。
// ============================================================

#define KSWORD_ARK_MEMORY_PROTOCOL_VERSION_V1 1UL
#define KSWORD_ARK_MEMORY_PROTOCOL_VERSION_V2 2UL
#define KSWORD_ARK_MEMORY_PROTOCOL_VERSION KSWORD_ARK_MEMORY_PROTOCOL_VERSION_V2

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_VIRTUAL_MEMORY 0x813UL
#define KSWORD_ARK_IOCTL_FUNCTION_READ_VIRTUAL_MEMORY 0x814UL
// 独立功能号保证旧驱动不会忽略创建时间后执行普通 PID 读取。
#define KSWORD_ARK_IOCTL_FUNCTION_READ_VIRTUAL_MEMORY_VERIFIED 0x936UL
#define KSWORD_ARK_IOCTL_FUNCTION_WRITE_VIRTUAL_MEMORY 0x81DUL
#define KSWORD_ARK_IOCTL_FUNCTION_READ_PHYSICAL_MEMORY 0x82BUL
#define KSWORD_ARK_IOCTL_FUNCTION_WRITE_PHYSICAL_MEMORY 0x82CUL
#define KSWORD_ARK_IOCTL_FUNCTION_TRANSLATE_VIRTUAL_ADDRESS 0x82DUL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PAGE_TABLE_ENTRY 0x82EUL
#define KSWORD_ARK_IOCTL_FUNCTION_SCAN_KERNEL_EXECUTABLE_MEMORY 0x831UL
#define KSWORD_ARK_IOCTL_FUNCTION_SCAN_KERNEL_MEMORY_EVIDENCE 0x832UL

#define IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_VIRTUAL_MEMORY, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_READ_VIRTUAL_MEMORY, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY_VERIFIED \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_READ_VIRTUAL_MEMORY_VERIFIED, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_WRITE_VIRTUAL_MEMORY, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_READ_PHYSICAL_MEMORY, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_WRITE_PHYSICAL_MEMORY, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_TRANSLATE_VIRTUAL_ADDRESS, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_PAGE_TABLE_ENTRY, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SCAN_KERNEL_EXECUTABLE_MEMORY, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SCAN_KERNEL_MEMORY_EVIDENCE, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_MAPPED_FILE_NAME 0x00000001UL
#define KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_MAPPED_FILE_NAME)

#define KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE 0x00000001UL
// KERNEL_ADDRESS switches READ_VIRTUAL_MEMORY from target-process user VA to
// system/kernel virtual address reading. processId is ignored in this mode.
#define KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS       0x00000002UL

#define KSWORD_ARK_MEMORY_WRITE_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE        0x00000002UL
// KERNEL_ADDRESS switches WRITE_VIRTUAL_MEMORY from target-process user VA to
// system/kernel virtual address writing. processId is ignored in this mode.
#define KSWORD_ARK_MEMORY_WRITE_FLAG_KERNEL_ADDRESS 0x00000004UL

#define KSWORD_ARK_MEMORY_FIELD_BASIC_PRESENT             0x00000001UL
#define KSWORD_ARK_MEMORY_FIELD_MAPPED_FILE_NAME_PRESENT  0x00000002UL
#define KSWORD_ARK_MEMORY_FIELD_MAPPED_FILE_NAME_TRUNCATED 0x00000004UL
#define KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY              0x00000008UL
#define KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT         0x00000010UL
#define KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE        0x00000020UL
#define KSWORD_ARK_MEMORY_FIELD_ZERO_FILLED_UNREADABLE    0x00000040UL
#define KSWORD_ARK_MEMORY_FIELD_WRITE_DATA_PRESENT        0x00000080UL
#define KSWORD_ARK_MEMORY_FIELD_FORCE_WRITE_REQUIRED      0x00000100UL
#define KSWORD_ARK_MEMORY_FIELD_FORCE_WRITE_USED          0x00000200UL
#define KSWORD_ARK_MEMORY_FIELD_PHYSICAL_ADDRESS_PRESENT  0x00000400UL
#define KSWORD_ARK_MEMORY_FIELD_PAGE_TABLE_PRESENT        0x00000800UL
#define KSWORD_ARK_MEMORY_FIELD_PML4E_PRESENT             0x00001000UL
#define KSWORD_ARK_MEMORY_FIELD_PDPTE_PRESENT             0x00002000UL
#define KSWORD_ARK_MEMORY_FIELD_PDE_PRESENT               0x00004000UL
#define KSWORD_ARK_MEMORY_FIELD_PTE_PRESENT               0x00008000UL
#define KSWORD_ARK_MEMORY_FIELD_LARGE_PAGE_1GB            0x00010000UL
#define KSWORD_ARK_MEMORY_FIELD_LARGE_PAGE_2MB            0x00020000UL
#define KSWORD_ARK_MEMORY_FIELD_PAGE_TABLE_WALK_COMPLETE  0x00040000UL
#define KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE      0x00080000UL

#define KSWORD_ARK_MEMORY_QUERY_STATUS_UNAVAILABLE        0UL
#define KSWORD_ARK_MEMORY_QUERY_STATUS_OK                 1UL
#define KSWORD_ARK_MEMORY_QUERY_STATUS_PARTIAL            2UL
#define KSWORD_ARK_MEMORY_QUERY_STATUS_PROCESS_OPEN_FAILED 3UL
#define KSWORD_ARK_MEMORY_QUERY_STATUS_QUERY_FAILED       4UL
#define KSWORD_ARK_MEMORY_QUERY_STATUS_NAME_FAILED        5UL
#define KSWORD_ARK_MEMORY_QUERY_STATUS_BUFFER_TOO_SMALL   6UL

#define KSWORD_ARK_MEMORY_READ_STATUS_UNAVAILABLE         0UL
#define KSWORD_ARK_MEMORY_READ_STATUS_OK                  1UL
#define KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY        2UL
#define KSWORD_ARK_MEMORY_READ_STATUS_PROCESS_LOOKUP_FAILED 3UL
#define KSWORD_ARK_MEMORY_READ_STATUS_COPY_FAILED         4UL
#define KSWORD_ARK_MEMORY_READ_STATUS_RANGE_REJECTED      5UL
#define KSWORD_ARK_MEMORY_READ_STATUS_BUFFER_TOO_SMALL    6UL
#define KSWORD_ARK_MEMORY_READ_STATUS_ZERO_FILLED         7UL

#define KSWORD_ARK_MEMORY_WRITE_STATUS_UNAVAILABLE        0UL
#define KSWORD_ARK_MEMORY_WRITE_STATUS_OK                 1UL
#define KSWORD_ARK_MEMORY_WRITE_STATUS_PARTIAL_COPY       2UL
#define KSWORD_ARK_MEMORY_WRITE_STATUS_PROCESS_LOOKUP_FAILED 3UL
#define KSWORD_ARK_MEMORY_WRITE_STATUS_COPY_FAILED        4UL
#define KSWORD_ARK_MEMORY_WRITE_STATUS_RANGE_REJECTED     5UL
#define KSWORD_ARK_MEMORY_WRITE_STATUS_BUFFER_TOO_SMALL   6UL
#define KSWORD_ARK_MEMORY_WRITE_STATUS_ACCESS_DENIED      7UL
#define KSWORD_ARK_MEMORY_WRITE_STATUS_FORCE_REQUIRED     8UL

#define KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_OK          1UL
#define KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_PARTIAL     2UL
#define KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_COPY_FAILED 3UL
#define KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_RANGE_REJECTED 4UL
#define KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_BUFFER_TOO_SMALL 5UL
#define KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_IRQL_REJECTED 6UL

#define KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_OK          1UL
#define KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_MAP_FAILED  2UL
#define KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_COPY_FAILED 3UL
#define KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_RANGE_REJECTED 4UL
#define KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_BUFFER_TOO_SMALL 5UL
#define KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_ACCESS_DENIED 6UL
#define KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED 7UL
#define KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_IRQL_REJECTED 8UL

#define KSWORD_ARK_MEMORY_TRANSLATE_STATUS_UNAVAILABLE      0UL
#define KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK               1UL
#define KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_PRESENT      2UL
#define KSWORD_ARK_MEMORY_TRANSLATE_STATUS_PROCESS_LOOKUP_FAILED 3UL
#define KSWORD_ARK_MEMORY_TRANSLATE_STATUS_READ_FAILED      4UL
#define KSWORD_ARK_MEMORY_TRANSLATE_STATUS_INVALID_ADDRESS  5UL
#define KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_SUPPORTED    6UL
#define KSWORD_ARK_MEMORY_TRANSLATE_STATUS_IRQL_REJECTED    7UL

#define KSWORD_ARK_MEMORY_SOURCE_R0_ZW_QUERY_VIRTUAL_MEMORY 1UL
#define KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_VIRTUAL_MEMORY  2UL
#define KSWORD_ARK_MEMORY_SOURCE_R0_MM_WRITE_VIRTUAL_MEMORY 3UL
#define KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_PHYSICAL_MEMORY 4UL
#define KSWORD_ARK_MEMORY_SOURCE_R0_MM_MAP_PHYSICAL_MEMORY  5UL
#define KSWORD_ARK_MEMORY_SOURCE_R0_PAGE_TABLE_WALK         6UL
#define KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_KERNEL_VIRTUAL  7UL

#define KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_CHARS 512U
#define KSWORD_ARK_MEMORY_READ_MAX_BYTES (1024UL * 1024UL)
#define KSWORD_ARK_MEMORY_WRITE_MAX_BYTES (256UL * 1024UL)
#define KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES (64UL * 1024UL)
#define KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES (4UL * 1024UL)

#define KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE        0x00000002UL

#define KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT       0x00000001UL
#define KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE      0x00000002UL
#define KSWORD_ARK_PAGE_TABLE_FLAG_USER          0x00000004UL
#define KSWORD_ARK_PAGE_TABLE_FLAG_WRITE_THROUGH 0x00000008UL
#define KSWORD_ARK_PAGE_TABLE_FLAG_CACHE_DISABLE 0x00000010UL
#define KSWORD_ARK_PAGE_TABLE_FLAG_ACCESSED      0x00000020UL
#define KSWORD_ARK_PAGE_TABLE_FLAG_DIRTY         0x00000040UL
#define KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE    0x00000080UL
#define KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL        0x00000100UL
#define KSWORD_ARK_PAGE_TABLE_FLAG_NX            0x00000200UL

#define KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_NONE 0UL
#define KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_2MB  1UL
#define KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_1GB  2UL

#define KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_4KB (4UL * 1024UL)
#define KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_2MB (2UL * 1024UL * 1024UL)
#define KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_1GB (1024UL * 1024UL * 1024UL)

// Page-table confidence values. The backend derives these from whether the
// read-only walk reached a valid terminal mapping, stopped at a not-present
// entry, or failed before the requested address could be trusted.
#define KSWORD_ARK_PAGE_TABLE_CONFIDENCE_UNKNOWN 0UL
#define KSWORD_ARK_PAGE_TABLE_CONFIDENCE_LOW     35UL
#define KSWORD_ARK_PAGE_TABLE_CONFIDENCE_MEDIUM  65UL
#define KSWORD_ARK_PAGE_TABLE_CONFIDENCE_HIGH    90UL

// Compact protection summary used by VA translation, PTE query, and executable
// scan rows. These bits are derived from PTE flags only; they never request or
// imply a PTE write.
#define KSWORD_ARK_MEMORY_PROTECTION_PRESENT 0x00000001UL
#define KSWORD_ARK_MEMORY_PROTECTION_READ    0x00000002UL
#define KSWORD_ARK_MEMORY_PROTECTION_WRITE   0x00000004UL
#define KSWORD_ARK_MEMORY_PROTECTION_EXECUTE 0x00000008UL
#define KSWORD_ARK_MEMORY_PROTECTION_NX      0x00000010UL
#define KSWORD_ARK_MEMORY_PROTECTION_LARGE   0x00000020UL
#define KSWORD_ARK_MEMORY_PROTECTION_GLOBAL  0x00000040UL
#define KSWORD_ARK_MEMORY_PROTECTION_USER    0x00000080UL

// 内核可执行页扫描请求 flags。中文说明：flags 为 0 时返回所有已识别的模块
// executable 页；设置过滤位时仅返回对应分类，未知位由 R0 handler 拒绝。
#define KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_MODULE_TEXT 0x00000001UL
#define KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_MODULE_NON_TEXT 0x00000002UL
#define KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_WRITABLE_EXECUTABLE 0x00000004UL
#define KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_UNKNOWN_EXECUTABLE 0x00000008UL
// 让扫描不再跳过「已经不可执行」的页。代码节被改成 RW 之后页表上会带 NX，
// 只扫可执行页会完全看不到这种状态，因此需要单独开关把它们带回来。
#define KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_SECTION_ANOMALY 0x00000010UL
#define KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_MODULE_TEXT | \
     KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_MODULE_NON_TEXT | \
     KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_WRITABLE_EXECUTABLE | \
     KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_UNKNOWN_EXECUTABLE | \
     KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_SECTION_ANOMALY)

// 内核可执行页扫描响应状态。中文说明：v1 不做全内核地址空间枚举，成功扫描
// 也返回 CONSERVATIVE/PARTIAL_CONSERVATIVE，避免 R3 误解为完整内核覆盖。
#define KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_CONSERVATIVE 1UL
#define KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_PARTIAL_CONSERVATIVE 2UL
#define KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_QUERY_FAILED 3UL
#define KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_INVALID_RANGE 4UL
#define KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_IRQL_REJECTED 5UL

// 内核可执行页 ownerKind。中文说明：ownerKind 表示 R0 对该页所在模块区域的
// 保守归类；WRITABLE_EXECUTABLE 优先级最高，随后才区分 text/non-text。
#define KSWORD_ARK_KERNEL_EXEC_OWNER_UNKNOWN 0UL
#define KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_TEXT 1UL
#define KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_NON_TEXT 2UL
#define KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_WRITABLE_EXECUTABLE 3UL
#define KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_UNKNOWN_SECTION 4UL

// 内核可执行页 riskFlags。中文说明：这些位只描述扫描观察到的风险信号，
// 不表示 R0 已经修改页面属性或尝试修复。
#define KSWORD_ARK_KERNEL_EXEC_RISK_NONE 0x00000000UL
#define KSWORD_ARK_KERNEL_EXEC_RISK_WRITABLE_EXECUTABLE 0x00000001UL
#define KSWORD_ARK_KERNEL_EXEC_RISK_MODULE_NON_TEXT_EXECUTABLE 0x00000002UL
#define KSWORD_ARK_KERNEL_EXEC_RISK_SECTION_WRITABLE 0x00000004UL
#define KSWORD_ARK_KERNEL_EXEC_RISK_LARGE_PAGE 0x00000008UL
#define KSWORD_ARK_KERNEL_EXEC_RISK_UNKNOWN_EXECUTABLE 0x00000010UL
#define KSWORD_ARK_KERNEL_EXEC_RISK_FIRST_BYTES_UNREADABLE 0x00000020UL
// 页属于模块的代码节，但页表上已经带 NX：这一页现在不可执行了。
#define KSWORD_ARK_KERNEL_EXEC_RISK_CODE_PAGE_NOT_EXECUTABLE 0x00000040UL
// 页属于模块的代码节，但页表上可写：正常情况下代码节页应当是只读可执行。
#define KSWORD_ARK_KERNEL_EXEC_RISK_CODE_PAGE_WRITABLE 0x00000080UL

// 内核 executable scan response flags。中文说明：这些位解释 partial status 的
// 直接原因，尤其是输出行容量和 maxBytes 预算命中。
#define KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_FLAG_TRUNCATED 0x00000001UL
#define KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_FLAG_BUDGET_EXHAUSTED 0x00000002UL

// 内核 executable first-bytes hash metadata。中文说明：R0 只返回哈希和状态，
// 默认不回传原始字节，避免把内核内容当作敏感转储暴露给 UI。
#define KSWORD_ARK_KERNEL_EXEC_HASH_NONE 0UL
#define KSWORD_ARK_KERNEL_EXEC_HASH_FNV1A64 1UL
#define KSWORD_ARK_KERNEL_EXEC_HASH_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_KERNEL_EXEC_HASH_STATUS_OK 1UL
#define KSWORD_ARK_KERNEL_EXEC_HASH_STATUS_READ_FAILED 2UL
#define KSWORD_ARK_KERNEL_EXEC_FIRST_BYTES_DEFAULT 16UL
#define KSWORD_ARK_KERNEL_EXEC_FIRST_BYTES_HARD_MAX 64UL

#define KSWORD_ARK_KERNEL_EXEC_MODULE_PATH_CHARS 260U
#define KSWORD_ARK_KERNEL_EXEC_SECTION_NAME_BYTES 8U
#define KSWORD_ARK_KERNEL_EXEC_SCAN_DEFAULT_MAX_BYTES (64ULL * 1024ULL * 1024ULL)
#define KSWORD_ARK_KERNEL_EXEC_SCAN_HARD_MAX_BYTES (256ULL * 1024ULL * 1024ULL)

// Kernel memory evidence scan request flags. The R0 side is read-only and every
// enabled source is still constrained by maxRows and maxBytes. flags==0 uses a
// conservative default that excludes NONMODULE_EXECUTABLE_RANGES; callers must
// explicitly set that flag with a bounded startAddress/endAddress range.
#define KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE 0x00000001UL
#define KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES 0x00000002UL
#define KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL 0x00000004UL
#define KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES 0x00000008UL
#define KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL 0x00000010UL
#define KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE | \
     KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES | \
     KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL | \
     KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES | \
     KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL)

// Kernel memory evidence response status values. Partial means at least one
// source, row capacity, or scan-cost budget prevented full coverage.
#define KSWORD_ARK_MEMORY_EVIDENCE_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_MEMORY_EVIDENCE_STATUS_OK 1UL
#define KSWORD_ARK_MEMORY_EVIDENCE_STATUS_PARTIAL 2UL
#define KSWORD_ARK_MEMORY_EVIDENCE_STATUS_QUERY_FAILED 3UL
#define KSWORD_ARK_MEMORY_EVIDENCE_STATUS_INVALID_REQUEST 4UL
#define KSWORD_ARK_MEMORY_EVIDENCE_STATUS_IRQL_REJECTED 5UL

// Response-level flags summarize truncation and cost-limit decisions.
#define KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_FLAG_TRUNCATED 0x00000001UL
#define KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_FLAG_BUDGET_EXHAUSTED 0x00000002UL
#define KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_FLAG_BIGPOOL_TRUNCATED 0x00000004UL
#define KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_FLAG_RANGE_REQUIRED 0x00000008UL

// Unified evidence row kinds. R3 can use these as rendering groups while still
// relying on ownerKind/riskFlags for risk scoring.
#define KSWORD_ARK_MEMORY_EVIDENCE_KIND_UNKNOWN 0UL
#define KSWORD_ARK_MEMORY_EVIDENCE_KIND_EXECUTABLE_RANGE 1UL
#define KSWORD_ARK_MEMORY_EVIDENCE_KIND_BIGPOOL 2UL
#define KSWORD_ARK_MEMORY_EVIDENCE_KIND_TEXT_SECTION_MEMORY 3UL

// Unified permission flags derived from read-only page-table observations.
#define KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_PRESENT 0x00000001UL
#define KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_READ 0x00000002UL
#define KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE 0x00000004UL
#define KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE 0x00000008UL
#define KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_NX 0x00000010UL
#define KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_LARGE 0x00000020UL
#define KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_GLOBAL 0x00000040UL
#define KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_USER 0x00000080UL

// Unified owner classes. SystemPte and MdlLike are conservative heuristics for
// BigPool rows and never imply that R0 has modified those allocations.
#define KSWORD_ARK_MEMORY_EVIDENCE_OWNER_UNKNOWN 0UL
#define KSWORD_ARK_MEMORY_EVIDENCE_OWNER_LOADED_MODULE 1UL
#define KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NONMODULE 2UL
#define KSWORD_ARK_MEMORY_EVIDENCE_OWNER_BIGPOOL 3UL
#define KSWORD_ARK_MEMORY_EVIDENCE_OWNER_SYSTEM_PTE 4UL
#define KSWORD_ARK_MEMORY_EVIDENCE_OWNER_MDL_LIKE 5UL

// Unified risk flags. These bits describe observations only; they never request
// repair, quarantine, PTE writes, CR0 writes, or kernel memory writes.
#define KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX 0x00000001UL
#define KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE 0x00000002UL
#define KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE 0x00000004UL
#define KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL 0x00000008UL
#define KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE 0x00000010UL
#define KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING 0x00000020UL
#define KSWORD_ARK_MEMORY_EVIDENCE_RISK_RX_PRIVATE 0x00000040UL
#define KSWORD_ARK_MEMORY_EVIDENCE_RISK_IMAGE_LIKE_MEMORY 0x00000080UL
#define KSWORD_ARK_MEMORY_EVIDENCE_RISK_DELETED_FILE_MAPPED_HINT 0x00000100UL

// Row-level evidence flags describe backing and enrichment signals. These bits
// are factual observations or conservative hints; they do not trigger repair.
#define KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_RWX_PRIVATE 0x00000001UL
#define KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_RX_PRIVATE 0x00000002UL
#define KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_NONMODULE_EXECUTABLE 0x00000004UL
#define KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_IMAGE_LIKE_MEMORY 0x00000008UL
#define KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_SECTION_OBJECT_PRESENT 0x00000010UL
#define KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_CONTROL_AREA_PRESENT 0x00000020UL
#define KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_DELETED_FILE_MAPPED_HINT 0x00000040UL
#define KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_SECTION_HINT_UNAVAILABLE 0x00000080UL

// Backing classifications are intentionally conservative. PRIVATE is used for
// executable ranges outside SystemModuleInformation or executable BigPool rows
// when no file-backed Section/ControlArea evidence is available.
#define KSWORD_ARK_MEMORY_EVIDENCE_BACKING_UNKNOWN 0UL
#define KSWORD_ARK_MEMORY_EVIDENCE_BACKING_LOADED_MODULE 1UL
#define KSWORD_ARK_MEMORY_EVIDENCE_BACKING_PRIVATE 2UL
#define KSWORD_ARK_MEMORY_EVIDENCE_BACKING_BIGPOOL 3UL

// Section/ControlArea hint status. PRESENT only means an address-like Section
// owner was available; DELETED_FILE_HINT is reserved for future ControlArea file
// checks and is never guessed when private fields are unavailable.
#define KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_UNAVAILABLE 0UL
#define KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_NOT_APPLICABLE 1UL
#define KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_SECTION_PRESENT 2UL
#define KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_DELETED_FILE_HINT 3UL

// BigPool row flags. The executable/suspected bits are separated so R3 can keep
// hard page-table evidence distinct from conservative NonPaged pool suspicion.
#define KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_NON_PAGED 0x00000001UL
#define KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_EXECUTABLE 0x00000002UL
#define KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_EXECUTABLE_SUSPECTED 0x00000004UL
#define KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_SCAN_TRUNCATED 0x00000008UL
#define KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_TAG_SYSTEM_PTE_LIKE 0x00000010UL
#define KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_TAG_MDL_LIKE 0x00000020UL

// Hash metadata for text diff support. R0 hashes memory only; R3 owns disk
// lookup and disk-vs-memory comparison.
#define KSWORD_ARK_MEMORY_EVIDENCE_HASH_NONE 0UL
#define KSWORD_ARK_MEMORY_EVIDENCE_HASH_FNV1A64 1UL

#define KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_UNKNOWN 0UL
#define KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_LOW 35UL
#define KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_MEDIUM 65UL
#define KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_HIGH 90UL

#define KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS 260U
#define KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS 160U
#define KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES 8U
#define KSWORD_ARK_MEMORY_EVIDENCE_SECTION_SAMPLE_BYTES 64U
#define KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS 256UL
#define KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS 4096UL
#define KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES (16ULL * 1024ULL * 1024ULL)
#define KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BYTES (64ULL * 1024ULL * 1024ULL)
#define KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS 256UL
#define KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BIGPOOL_ROWS 1024UL
#define KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES 0UL
#define KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_SAMPLE_BYTES \
    KSWORD_ARK_MEMORY_EVIDENCE_SECTION_SAMPLE_BYTES

typedef struct _KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST
{
    unsigned long flags;
    unsigned long processId;
    unsigned long long baseAddress;
    unsigned long reserved;
} KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST;

typedef struct _KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long processId;
    unsigned long fieldFlags;
    unsigned long queryStatus;
    long openStatus;
    long basicStatus;
    long mappedFileNameStatus;
    unsigned long source;
    unsigned long mappedFileNameLengthChars;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long long requestedBaseAddress;
    unsigned long long baseAddress;
    unsigned long long allocationBase;
    unsigned long long regionSize;
    unsigned long allocationProtect;
    unsigned long state;
    unsigned long protect;
    unsigned long type;
    wchar_t mappedFileName[KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_CHARS];
} KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE;

typedef struct _KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST
{
    unsigned long flags;
    unsigned long processId;
    unsigned long long baseAddress;
    unsigned long bytesToRead;
    unsigned long reserved;
} KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST;

// V1 校验读取只允许用户地址和真实非零进程创建时间。
#define KSWORD_ARK_VERIFIED_MEMORY_READ_VERSION 1UL
typedef struct _KSWORD_ARK_READ_VIRTUAL_MEMORY_VERIFIED_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long flags;
    unsigned long processId;
    unsigned long long expectedCreationTime100ns;
    unsigned long long baseAddress;
    unsigned long bytesToRead;
    unsigned long reserved;
} KSWORD_ARK_READ_VIRTUAL_MEMORY_VERIFIED_REQUEST;

typedef struct _KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE
{
    unsigned long version;
    unsigned long headerSize;
    unsigned long processId;
    unsigned long fieldFlags;
    unsigned long readStatus;
    long lookupStatus;
    long copyStatus;
    unsigned long source;
    unsigned long long requestedBaseAddress;
    unsigned long requestedBytes;
    unsigned long bytesRead;
    unsigned long maxBytesPerRequest;
    unsigned char data[1];
} KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE;

typedef struct _KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST
{
    unsigned long flags;
    unsigned long processId;
    unsigned long long baseAddress;
    unsigned long bytesToWrite;
    unsigned long reserved;
    unsigned char data[1];
} KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST;

typedef struct _KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long processId;
    unsigned long fieldFlags;
    unsigned long writeStatus;
    long lookupStatus;
    long copyStatus;
    unsigned long source;
    unsigned long long requestedBaseAddress;
    unsigned long requestedBytes;
    unsigned long bytesWritten;
    unsigned long maxBytesPerRequest;
} KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE;

typedef struct _KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST
{
    unsigned long flags;
    unsigned long reserved;
    unsigned long long physicalAddress;
    unsigned long bytesToRead;
    unsigned long reserved2;
} KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST;

typedef struct _KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE
{
    unsigned long version;
    unsigned long headerSize;
    unsigned long fieldFlags;
    unsigned long readStatus;
    long copyStatus;
    unsigned long source;
    unsigned long requestedBytes;
    unsigned long bytesRead;
    unsigned long maxBytesPerRequest;
    unsigned long reserved;
    unsigned long long requestedPhysicalAddress;
    unsigned char data[1];
} KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE;

typedef struct _KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST
{
    unsigned long flags;
    unsigned long reserved;
    unsigned long long physicalAddress;
    unsigned long bytesToWrite;
    unsigned long reserved2;
    unsigned char data[1];
} KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST;

typedef struct _KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long fieldFlags;
    unsigned long writeStatus;
    long mapStatus;
    long copyStatus;
    unsigned long source;
    unsigned long requestedBytes;
    unsigned long bytesWritten;
    unsigned long maxBytesPerRequest;
    unsigned long reserved;
    unsigned long long requestedPhysicalAddress;
} KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE;

typedef struct _KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST
{
    unsigned long flags;
    unsigned long processId;
    unsigned long long virtualAddress;
    unsigned long reserved;
} KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST;

typedef struct _KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST
{
    unsigned long flags;
    unsigned long processId;
    unsigned long long virtualAddress;
    unsigned long reserved;
} KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST;

typedef struct _KSWORD_ARK_PAGE_TABLE_ENTRY_INFO
{
    unsigned long version;
    unsigned long size;
    unsigned long processId;
    unsigned long fieldFlags;
    unsigned long queryStatus;
    long lookupStatus;
    long walkStatus;
    unsigned long source;
    unsigned long pml4Index;
    unsigned long pdptIndex;
    unsigned long pdIndex;
    unsigned long ptIndex;
    unsigned long pml4eFlags;
    unsigned long pdpteFlags;
    unsigned long pdeFlags;
    unsigned long pteFlags;
    unsigned long effectiveFlags;
    unsigned long largePageType;
    unsigned long pageSize;
    unsigned long resolved;
    unsigned long confidence;
    unsigned long protection;
    unsigned long nxFlag;
    unsigned long writeFlag;
    unsigned long userFlag;
    unsigned long globalFlag;
    unsigned long largePageFlag;
    unsigned long reserved0;
    unsigned long long virtualAddress;
    unsigned long long physicalAddress;
    unsigned long long cr3PhysicalAddress;
    unsigned long long pml4ePhysicalAddress;
    unsigned long long pdptePhysicalAddress;
    unsigned long long pdePhysicalAddress;
    unsigned long long ptePhysicalAddress;
    unsigned long long pml4eValue;
    unsigned long long pdpteValue;
    unsigned long long pdeValue;
    unsigned long long pteValue;
} KSWORD_ARK_PAGE_TABLE_ENTRY_INFO;

typedef struct _KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE
{
    KSWORD_ARK_PAGE_TABLE_ENTRY_INFO info;
} KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE;

typedef struct _KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE
{
    KSWORD_ARK_PAGE_TABLE_ENTRY_INFO info;
} KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE;

// 内核可执行页扫描请求。中文说明：flags 控制返回分类，maxEntries 限制 entries
// 写回数量，startAddress/endAddress 提供可选半开地址过滤区间；该请求不携带
// 写入、修复或页表修改参数。
typedef struct _KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST
{
    unsigned long flags;
    unsigned long maxEntries;
    unsigned long long startAddress;
    unsigned long long endAddress;
    unsigned long long maxBytes;
    unsigned long hashBytes;
    unsigned long reserved0;
} KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST;

// 单条内核可执行页扫描结果。中文说明：pageCount 表示连续合并后的页数量，
// modulePath 保存该条目所属已加载模块路径或文件名，R3 仅用于展示与过滤。
typedef struct _KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY
{
    unsigned long long virtualAddress;
    unsigned long long regionSize;
    unsigned long long sectionOwnerBase;
    unsigned long long contentHash;
    unsigned long pageCount;
    unsigned long pageSize;
    unsigned long effectiveFlags;
    unsigned long protection;
    unsigned long long moduleBase;
    unsigned long moduleSize;
    unsigned long riskFlags;
    unsigned long ownerKind;
    unsigned long sectionRva;
    unsigned long sectionSize;
    unsigned long hashAlgorithm;
    unsigned long hashStatus;
    unsigned long firstBytesHashed;
    unsigned long unknownExecutable;
    unsigned char sectionName[KSWORD_ARK_KERNEL_EXEC_SECTION_NAME_BYTES];
    wchar_t modulePath[KSWORD_ARK_KERNEL_EXEC_MODULE_PATH_CHARS];
} KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY;

// 内核可执行页扫描响应头。中文说明：status 汇总本次扫描是保守成功、部分成功
// 还是失败；lastStatus 保留最近一次底层 NTSTATUS，entries[] 为变长结果区。
typedef struct _KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long responseFlags;
    unsigned long sourceFlags;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long moduleCount;
    unsigned long entrySize;
    unsigned long maxEntries;
    unsigned long reserved0;
    unsigned long long maxBytes;
    unsigned long long bytesScanned;
    long lastStatus;
    KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY entries[1];
} KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE;

// Kernel memory evidence request. flags selects read-only sources, maxRows caps
// rows returned, maxBytes caps page/section bytes inspected, and maxBigPoolRows
// caps SystemBigPoolInformation rows visited. startAddress/endAddress are a
// half-open filter; non-module executable range scanning requires an explicit
// bounded range to avoid walking the whole kernel address space.
typedef struct _KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST
{
    unsigned long flags;
    unsigned long maxRows;
    unsigned long long startAddress;
    unsigned long long endAddress;
    unsigned long long maxBytes;
    unsigned long maxBigPoolRows;
    unsigned long sampleBytes;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST;

// Unified evidence row. The fixed row keeps executable range, BigPool, PTE, MDL
// heuristic, and text-section memory sample data in one R3-friendly format.
typedef struct _KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW
{
    unsigned long rowSize;
    unsigned long evidenceKind;
    unsigned long long virtualAddress;
    unsigned long long regionSize;
    unsigned long pageSize;
    unsigned long permissionFlags;
    unsigned long ownerKind;
    unsigned long riskFlags;
    unsigned long long moduleBase;
    unsigned long moduleSize;
    unsigned long confidence;
    unsigned long rowFlags;
    unsigned long backingKind;
    unsigned long sectionHintStatus;
    unsigned long long ownerAddress;
    unsigned long long sectionObjectAddress;
    unsigned long long controlAreaAddress;
    long lastStatus;
    unsigned long bigPoolTag;
    unsigned long bigPoolFlags;
    unsigned long sectionRva;
    unsigned long sectionSize;
    unsigned char sectionName[KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES];
    unsigned long hashAlgorithm;
    unsigned long sampleSize;
    unsigned long long contentHash;
    unsigned char sample[KSWORD_ARK_MEMORY_EVIDENCE_SECTION_SAMPLE_BYTES];
    wchar_t ownerName[KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS];
    wchar_t detail[KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS];
} KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW;

// Kernel memory evidence response. status/responseFlags describe scan
// completeness; rows[] is a variable-length array of rowSize entries.
typedef struct _KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long responseFlags;
    unsigned long sourceFlags;
    unsigned long totalRows;
    unsigned long returnedRows;
    unsigned long rowSize;
    unsigned long maxRows;
    unsigned long long maxBytes;
    unsigned long long bytesScanned;
    unsigned long moduleCount;
    unsigned long bigPoolRowsSeen;
    long lastStatus;
    unsigned long reserved;
    KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW rows[1];
} KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE;

// ============================================================
// MDL-based page protection change (research / HVCI experiment)
// ============================================================
#define KSWORD_ARK_IOCTL_FUNCTION_CHANGE_MAPPED_PAGE_PROTECTION 0x920UL

#define IOCTL_KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CHANGE_MAPPED_PAGE_PROTECTION, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_CHANGE_PROTECTION_FLAG_WRITE_TEST 0x00000001UL

typedef struct _KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION_REQUEST
{
    unsigned long long targetVirtualAddress;
    unsigned long newProtection;
    unsigned long flags;
} KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION_REQUEST;

typedef struct _KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION_RESPONSE
{
    unsigned long version;
    unsigned long size;
    long mdlAllocStatus;
    long lockStatus;
    long mapStatus;
    long protectStatus;
    long writeTestStatus;
    unsigned long reserved0;
    unsigned long long mappedVa;
    unsigned long long originalPte;
    unsigned long long afterProtectPte;
} KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION_RESPONSE;

/* ================================================================
 * HVCI 研究实验: MmChangeImageProtection
 *
 * 在内核映像页上调用未导出的 MmChangeImageProtection，
 * 并测试 VTL1 对映像保护变更的安全调用响应。
 * 签名扫描在运行时定位函数，不依赖特定 build profile。
 * ================================================================ */

#define KSWORD_ARK_IOCTL_FUNCTION_CHANGE_IMAGE_PAGE_PROTECTION 0x922UL

#define IOCTL_KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CHANGE_IMAGE_PAGE_PROTECTION, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_IMAGE_PROT_FLAG_WRITE_TEST          0x00000001UL
#define KSWORD_ARK_IMAGE_PROT_FLAG_RESTORE             0x00000002UL
#define KSWORD_ARK_IMAGE_PROT_FLAG_UNMAP_BEFORE_RESTORE 0x00000004UL

#define KSWORD_ARK_IMAGE_PROT_OP_RX          1UL
#define KSWORD_ARK_IMAGE_PROT_OP_READONLY_NX 2UL

typedef struct _KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION_REQUEST
{
    unsigned long long targetVirtualAddress;
    unsigned long operation;
    unsigned long flags;
    unsigned long long functionAddressOverride;
} KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION_REQUEST;

typedef struct _KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION_RESPONSE
{
    unsigned long version;
    unsigned long size;
    long resolverStatus;
    long mdlAllocStatus;
    long lockStatus;
    long imageProtectStatus;
    long aliasMapStatus;
    long writeTestStatus;
    long restoreStatus;
    unsigned long reserved0;
    unsigned long long resolvedFunctionVa;
    unsigned long long originalPte;
    unsigned long long afterImageProtectPte;
    unsigned long long aliasVa;
    unsigned long long afterRestorePte;
} KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION_RESPONSE;
