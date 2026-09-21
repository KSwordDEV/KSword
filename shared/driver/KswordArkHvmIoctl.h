#pragma once

#include "KswordArkProcessIoctl.h"

/*
 * The HVM protocol separates capability discovery from implementation state.
 * A capability-only or partial result must never be interpreted as a resident
 * hypervisor.  ACTIVE is published only after every selected processor has
 * entered VMX non-root operation and the rollback rendezvous is available.
 */
#define KSWORD_ARK_HVM_PROTOCOL_VERSION 6UL

/* V6 reports why SVM discovery stopped without interpreting missing values as zero. */
#define KSWORD_ARK_SVM_REJECT_NONE 0UL
#define KSWORD_ARK_SVM_REJECT_CPUID_RANGE 1UL
#define KSWORD_ARK_SVM_REJECT_SVM_NPT_ASID 2UL
#define KSWORD_ARK_SVM_REJECT_NRIP 3UL
#define KSWORD_ARK_SVM_REJECT_MSR_READ 4UL
#define KSWORD_ARK_SVM_REJECT_FIRMWARE 5UL
#define KSWORD_ARK_SVM_REJECT_SVME 6UL
#define KSWORD_ARK_SVM_REJECT_HSAVE 7UL
#define KSWORD_ARK_SVM_REJECT_CR4 8UL
#define KSWORD_ARK_SVM_REJECT_XSAVE 9UL
#define KSWORD_ARK_SVM_REJECT_XSTATE_READ 10UL
#define KSWORD_ARK_SVM_REJECT_XSS 11UL
#define KSWORD_ARK_SVM_REJECT_PHYSICAL_WIDTH 12UL
/* V6 additive reason: no structure size or existing field interpretation changes. */
#define KSWORD_ARK_SVM_REJECT_CET_STATE 13UL
/* Independent validity bits for the extended state observations. */
#define KSWORD_ARK_SVM_VALID_CR4 1UL
#define KSWORD_ARK_SVM_VALID_CPUID1 2UL
#define KSWORD_ARK_SVM_VALID_CPUID_D1 4UL
#define KSWORD_ARK_SVM_VALID_XCR0 8UL
#define KSWORD_ARK_SVM_VALID_XSS 16UL

/* V5 describes architecture independently from capability flags. */
#define KSWORD_ARK_HVM_BACKEND_NONE 0UL
#define KSWORD_ARK_HVM_BACKEND_VMX 1UL
#define KSWORD_ARK_HVM_BACKEND_SVM 2UL
/* Translation type must not mislabel AMD NPT as EPT. */
#define KSWORD_ARK_HVM_SLAT_NONE 0UL
#define KSWORD_ARK_HVM_SLAT_EPT 1UL
#define KSWORD_ARK_HVM_SLAT_NPT 2UL
/* Generic execution stage, independent of VMX instruction result codes. */
#define KSWORD_ARK_HVM_STAGE_NONE 0UL
#define KSWORD_ARK_HVM_STAGE_PREPARED 1UL
#define KSWORD_ARK_HVM_STAGE_TESTED 2UL
#define KSWORD_ARK_HVM_STAGE_ENTERING 3UL
#define KSWORD_ARK_HVM_STAGE_ENTERED 4UL
#define KSWORD_ARK_HVM_STAGE_EXIT 5UL
#define KSWORD_ARK_HVM_STAGE_STOPPED 6UL
#define KSWORD_ARK_HVM_STAGE_FAILED 7UL

/*
 * VMCS 配置失败的判别码，承载在既有的 lastVmInstructionError 字段里。
 *
 * 存在的理由：VMCS 编程阶段有**至少八个**不同的返回点会让 START_RESIDENT 以
 * 完全相同的现象失败 —— 每处理器行一律是
 * vmxInstructionResult=3（汇编包装器的 "never-attempted VM entry"）、
 * stateFlags=0x27、lastStatus=STATUS_HV_OPERATION_FAILED、
 * lastVmInstructionError=0。从协议面**分不出**是哪一个。
 *
 * 尤其要注意 lastVmInstructionError=0 **不能**用来排除 VMWRITE 失败：
 * 那个 0 有三个来源（没走到写、VMfailInvalid 不带错误码、以及 VMfailValid
 * 但随后读 VMCS 0x4400 自身也失败）。把 0 当成"没有 VMWRITE 失败"是错的。
 *
 * 编码（bit 31 是判别标记，为 0 时整个值仍是架构 VM-instruction error，
 * 旧语义不变，因此这不是协议破坏性变更、不需要版本号）：
 *
 *   bits 31    : 1 = KSword 判别码
 *   bits 30-24 : 站点号 KSWORD_ARK_HVM_VMCS_DIAG_SITE_*
 *   bits 23-8  : 细节（VMCS 字段编码 / 缺失能力位掩码 / 异常码低 16 位）
 *   bits  7-0  : 架构 VM-instruction error，取不到时为 0
 */
#define KSWORD_ARK_HVM_VMCS_DIAG_FLAG 0x80000000UL

#define KSWORD_ARK_HVM_VMCS_DIAG_MAKE(site, detail, arch)      \
    (KSWORD_ARK_HVM_VMCS_DIAG_FLAG |                           \
     (((unsigned long)(site)   & 0x7FUL)   << 24) |            \
     (((unsigned long)(detail) & 0xFFFFUL) <<  8) |            \
      ((unsigned long)(arch)   & 0xFFUL))

#define KSWORD_ARK_HVM_VMCS_DIAG_IS(v)     (((v) & KSWORD_ARK_HVM_VMCS_DIAG_FLAG) != 0UL)
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE(v)   (((v) >> 24) & 0x7FUL)
#define KSWORD_ARK_HVM_VMCS_DIAG_DETAIL(v) (((v) >>  8) & 0xFFFFUL)
#define KSWORD_ARK_HVM_VMCS_DIAG_ARCH(v)    ((v)        & 0xFFUL)

/* VMWRITE 被拒。detail = VMCS 字段编码，arch = 架构错误码（0 = 未取到）。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_VMWRITE            1UL
/* 已启用的可选 CR4 状态没有 VMCS 传输能力。detail = 下面的 STATE_* 掩码。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_NO_TRANSFER  2UL
/* 提供了 MSR bitmap 页但 primary 控制没拿到 USE_MSR_BITMAPS。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_MSR_BITMAP         3UL
/* CR3/DR 拦截被请求但对应 primary 控制没拿到。detail: 1=TrackCr3 2=InterceptDr。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_CR_POLICY          4UL
/* 必需的 primary/secondary/exit/entry 控制缺失。detail = 下面的 CTL_* 掩码。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_REQUIRED_CONTROLS  5UL
/* 调试状态的保存与加载控制不成对。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_DEBUG_PAIRING      6UL
/* 可选状态的 exit/entry 控制不成对。detail = STATE_* 掩码。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_PAIRING      7UL
/* 必需的 secondary 指令控制缺失。detail = 最低缺失位的位号(0-31)。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_INSTRUCTION_CTL    8UL
/* 读可选状态 MSR 时抛异常并被就地吞掉。detail = 异常码低 16 位。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_MSR_EXCEPTION      16UL
/* 读能力 MSR 时抛异常并被就地吞掉。detail = 异常码低 16 位。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_CAP_EXCEPTION      17UL
/* 诊断用的无条件 I/O 退出被请求但能力 MSR 不允许，判据会静默失效。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_DIAG_IO_EXITING    18UL
/* 主机页目录基址为零；装上去会三重故障且既无蓝屏也无转储。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_HOST_CR3           19UL

/* STATE_* 掩码：哪一个可选处理器状态出的问题。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_STATE_CET   0x0001UL
#define KSWORD_ARK_HVM_VMCS_DIAG_STATE_PKS   0x0002UL
#define KSWORD_ARK_HVM_VMCS_DIAG_STATE_UINTR 0x0004UL
#define KSWORD_ARK_HVM_VMCS_DIAG_STATE_FRED  0x0008UL

/* CTL_* 掩码：REQUIRED_CONTROLS 站点具体缺哪一类。 */
#define KSWORD_ARK_HVM_VMCS_DIAG_CTL_SECONDARY_ACTIVATE 0x0001UL
#define KSWORD_ARK_HVM_VMCS_DIAG_CTL_EPT                0x0002UL
#define KSWORD_ARK_HVM_VMCS_DIAG_CTL_HOST_64            0x0004UL
#define KSWORD_ARK_HVM_VMCS_DIAG_CTL_ENTRY_IA32E        0x0008UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_HVM   0x8CAUL
#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_HVM 0x8CBUL
// 0x8CC-0x8CD are occupied by driver-dispatch and SLAT/IOMMU on main.
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_EPT_RULE 0x8B8UL
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_EVENTS   0x8B9UL
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_MEMORY   0x8BAUL

#define IOCTL_KSWORD_ARK_QUERY_HVM \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_QUERY_HVM, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KSWORD_ARK_CONTROL_HVM \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_CONTROL_HVM, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KSWORD_ARK_HVM_EPT_RULE \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_EPT_RULE, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KSWORD_ARK_HVM_EVENTS \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_EVENTS, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/*
 * Ring -1 memory access.  Reads are as privileged as writes here because the
 * access path deliberately avoids the documented memory-manager entry points,
 * so the whole interface requires write access rather than only the mutating
 * half of it.
 */
#define IOCTL_KSWORD_ARK_HVM_MEMORY \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_MEMORY, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_VENDOR_CHARS 16U
#define KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS 16U
#define KSWORD_ARK_HVM_MAX_PROCESSORS 256UL
/*
 * Slots in the per-reason exit histogram.
 *
 * Intel basic exit reasons are a dense small integer space; this is sized past
 * every reason currently defined so that a processor running on newer silicon
 * counts its exits somewhere rather than nowhere.  A reason at or beyond this
 * bound is simply not counted - never folded into a neighbouring slot, which
 * would turn an unknown exit into a plausible-looking one.
 */
#define KSWORD_ARK_HVM_EXIT_REASON_SLOTS 96UL
#define KSWORD_ARK_HVM_MAX_EPT_RULES 128UL
#define KSWORD_ARK_HVM_MAX_EVENT_ROWS 64UL

#define KSWORD_ARK_HVM_FEATURE_INTEL                  0x0000000000000001ULL
#define KSWORD_ARK_HVM_FEATURE_VMX                    0x0000000000000002ULL
#define KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED 0x0000000000000004ULL
#define KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX        0x0000000000000008ULL
#define KSWORD_ARK_HVM_FEATURE_TRUE_CONTROLS          0x0000000000000010ULL
#define KSWORD_ARK_HVM_FEATURE_EPT                    0x0000000000000020ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_WB                 0x0000000000000040ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL            0x0000000000000080ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_2MB                0x0000000000000100ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_AD                 0x0000000000000200ULL
#define KSWORD_ARK_HVM_FEATURE_INVEPT                 0x0000000000000400ULL
#define KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE          0x0000000000000800ULL
#define KSWORD_ARK_HVM_FEATURE_INVEPT_ALL             0x0000000000001000ULL
#define KSWORD_ARK_HVM_FEATURE_VPID                   0x0000000000002000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT     0x0000000000004000ULL
#define KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED     0x0000000000008000ULL
#define KSWORD_ARK_HVM_FEATURE_ONE_SHOT_GUEST          0x0000000000010000ULL
#define KSWORD_ARK_HVM_FEATURE_VMEXIT_TELEMETRY        0x0000000000020000ULL
#define KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM            0x0000000000040000ULL
#define KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS     0x0000000000080000ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_4KB_SPLIT            0x0000000000100000ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_RULES                0x0000000000200000ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_EVENT_RING           0x0000000000400000ULL
#define KSWORD_ARK_HVM_FEATURE_MTRR_AWARE_EPT           0x0000000000800000ULL
#define KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG        0x0000000001000000ULL
#define KSWORD_ARK_HVM_FEATURE_NESTED_VMX_DISPATCH      0x0000000002000000ULL
#define KSWORD_ARK_HVM_FEATURE_NESTED_VMX_ACTIVE        0x0000000004000000ULL
#define KSWORD_ARK_HVM_FEATURE_SHADOW_EPT               0x0000000008000000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_CAPABLE     0x0000000010000000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_V1          0x0000000020000000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_ACTIVE      0x0000000040000000ULL
#define KSWORD_ARK_HVM_FEATURE_VMX_INSTRUCTION_EMULATION 0x0000000080000000ULL
#define KSWORD_ARK_HVM_FEATURE_POWER_STATE_GUARD         0x0000000100000000ULL
#define KSWORD_ARK_HVM_FEATURE_PROCESSOR_TOPOLOGY_GUARD  0x0000000200000000ULL
#define KSWORD_ARK_HVM_FEATURE_DRIVER_UNLOAD_GUARD       0x0000000400000000ULL
#define KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED 0x0000000800000000ULL
/*
 * The MSR bitmap is what makes residency survivable: without it every RDMSR
 * and WRMSR exits unconditionally into a dispatcher that cannot complete them.
 */
#define KSWORD_ARK_HVM_FEATURE_MSR_BITMAP                 0x0000001000000000ULL
/* The dispatcher completes every unconditional exit instead of devirtualizing. */
#define KSWORD_ARK_HVM_FEATURE_EXIT_EMULATION             0x0000002000000000ULL
/* A timed soak proved residency survives ordinary system activity. */
#define KSWORD_ARK_HVM_FEATURE_RESIDENT_SUSTAINED         0x0000004000000000ULL
/*
 * AMD capability evidence.  These bits report what the processor can do, not
 * whether the software can start or has actually passed a hardware round trip.
 * Backend status and per-CPU execution evidence carry those separate results.
 */
#define KSWORD_ARK_HVM_FEATURE_AMD                        0x0000008000000000ULL
#define KSWORD_ARK_HVM_FEATURE_SVM                        0x0000010000000000ULL
#define KSWORD_ARK_HVM_FEATURE_NPT                        0x0000020000000000ULL
#define KSWORD_ARK_HVM_FEATURE_SVM_NRIP                   0x0000040000000000ULL
#define KSWORD_ARK_HVM_FEATURE_SVM_DECODE_ASSISTS         0x0000080000000000ULL
#define KSWORD_ARK_HVM_FEATURE_SVM_FLUSH_BY_ASID          0x0000100000000000ULL
/* The firmware disabled SVM through VM_CR.SVMDIS. */
#define KSWORD_ARK_HVM_FEATURE_SVM_FIRMWARE_DISABLED      0x0000200000000000ULL
/*
 * Virtualization exception (#VE) support.
 *
 * Reported because the hardware has it, NOT because it is safe to turn on
 * here.  In this product the guest being virtualized is the running Windows
 * itself, and its IDT[20] is KiVirtualizationException - it does not expect a
 * #VE we manufacture.  Worse, the architectural default is inverted: an EPT
 * leaf with bit 63 clear is *convertible*, so enabling the control without
 * first setting suppress-#VE on every leaf reflects ordinary EPT violations
 * into a guest that cannot handle them, which is #GP -> #DF -> triple fault.
 *
 * The driver therefore always sets suppress-#VE on every leaf it builds, and
 * the conversion control itself stays off unless the caller opts in per start.
 */
#define KSWORD_ARK_HVM_FEATURE_EPT_VIOLATION_VE           0x0000400000000000ULL
/* Per-processor virtualization-exception information areas are allocated. */
#define KSWORD_ARK_HVM_FEATURE_VE_INFO_READY              0x0000800000000000ULL
/* Every EPT leaf this build installs carries suppress-#VE. */
#define KSWORD_ARK_HVM_FEATURE_VE_SUPPRESSED_BY_DEFAULT   0x0001000000000000ULL

/*
 * VM functions (VMFUNC) and EPTP switching.
 *
 * The single most important property of VMFUNC is that it performs NO CPL
 * check.  Any ring-3 code in the guest can execute it and switch the active
 * EPTP to any entry in the list, without a VM exit and without the driver
 * being told.  An EPTP list is therefore not a private hypervisor mechanism -
 * it is an interface published to every thread in the system.
 *
 * The consequence for design: a domain reachable through the list must never
 * grant a permission the default view does not already grant.  Otherwise the
 * list becomes a privilege-escalation primitive that costs an attacker one
 * instruction.  The driver enforces that as an install-time check, and the
 * whole mechanism stays off unless a caller opts in per start.
 */
#define KSWORD_ARK_HVM_FEATURE_VM_FUNCTIONS               0x0002000000000000ULL
/* EPTP switching (VM function 0) is available on this processor. */
#define KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING             0x0004000000000000ULL
/* The EPTP list page is allocated and every unused slot reads as invalid. */
#define KSWORD_ARK_HVM_FEATURE_EPTP_LIST_READY            0x0008000000000000ULL

/*
 * Per-processor private EPT hierarchies.
 *
 * Both flip mechanisms in this driver - the allow-once transient grant and
 * the CLOAK/HOOK split view - work by writing one EPT leaf and letting the
 * guest retire a single instruction.  With one shared hierarchy that write is
 * visible to every other processor for the whole window, which is why both
 * features refuse to run unless the topology is exactly one processor.
 *
 * Armed, each processor walks its own copy of the few tables on the path to a
 * flippable leaf, and everything else stays shared.  A flip then reaches only
 * the processor that took the exit, and the refusal can be lifted.
 */
#define KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED            0x0010000000000000ULL
/*
 * The EPTP-switching split-view backend is armed for this runtime.
 *
 * Published only when the caller opted in with ENABLE_EPTP_SWITCH *and* both
 * capabilities it depends on are present.  Absent means the MTF backend is in
 * force, which is also what an unarmed runtime reports - so read this bit,
 * not the request flags, to know which backend a given residency is using.
 */
#define KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED          0x0020000000000000ULL

#define KSWORD_ARK_HVM_STATE_INITIALIZED      0x00000001UL
#define KSWORD_ARK_HVM_STATE_RESOURCES_READY  0x00000002UL
#define KSWORD_ARK_HVM_STATE_EPT_READY        0x00000004UL
#define KSWORD_ARK_HVM_STATE_SELF_TESTED      0x00000008UL
#define KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED 0x00000010UL
#define KSWORD_ARK_HVM_STATE_BUSY             0x00000020UL
#define KSWORD_ARK_HVM_STATE_FAULTED          0x00000040UL
#define KSWORD_ARK_HVM_STATE_EPT_TRUNCATED    0x00000080UL
#define KSWORD_ARK_HVM_STATE_GUEST_READY      0x00000100UL
#define KSWORD_ARK_HVM_STATE_GUEST_RUNNING    0x00000200UL
#define KSWORD_ARK_HVM_STATE_GUEST_EXITED     0x00000400UL
#define KSWORD_ARK_HVM_STATE_NESTED_ACTIVE    0x00000800UL
#define KSWORD_ARK_HVM_STATE_NESTED_VALIDATED 0x00001000UL
#define KSWORD_ARK_HVM_STATE_RESIDENT_STARTING 0x00002000UL
#define KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE   0x00004000UL
#define KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING 0x00008000UL
#define KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE  0x00010000UL
#define KSWORD_ARK_HVM_STATE_EVENTS_AVAILABLE  0x00020000UL
#define KSWORD_ARK_HVM_STATE_NESTED_PARTIAL    0x00040000UL
#define KSWORD_ARK_HVM_STATE_EVMCS_PARTIAL     0x00080000UL
#define KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED 0x00100000UL
#define KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING 0x00200000UL
#define KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED       0x00400000UL
/*
 * Residency is running underneath another hypervisor - we are L1, not L0.
 * This is a degraded mode, not a failure: every VMX operation is emulated
 * by the outer hypervisor, so exits cost far more and the capability set is
 * whatever the outer one chose to expose.  It is published so the UI never
 * presents nested residency as equivalent to bare-metal residency.
 */
#define KSWORD_ARK_HVM_STATE_RESIDENT_NESTED         0x00800000UL
/* EPT-violation-to-#VE conversion is armed on every resident processor. */
#define KSWORD_ARK_HVM_STATE_VE_ACTIVE              0x01000000UL
/* EPTP switching is armed: guest code can switch views with one VMFUNC. */
#define KSWORD_ARK_HVM_STATE_VMFUNC_ACTIVE          0x02000000UL

#define KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY  0x00000001UL
#define KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED     0x00000002UL
#define KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED 0x00000004UL
#define KSWORD_ARK_HVM_CPU_STATE_EXCEPTION       0x00000008UL
#define KSWORD_ARK_HVM_CPU_STATE_CONFLICT        0x00000010UL
#define KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED      0x00000020UL
#define KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED   0x00000040UL
#define KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED   0x00000080UL
#define KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE  0x00000100UL
#define KSWORD_ARK_HVM_CPU_STATE_STOP_REQUESTED   0x00000200UL
#define KSWORD_ARK_HVM_CPU_STATE_DEVIRTUALIZED    0x00000400UL
#define KSWORD_ARK_HVM_CPU_STATE_NESTED_PARTIAL   0x00000800UL
#define KSWORD_ARK_HVM_CPU_STATE_EVMCS_PARTIAL    0x00001000UL

#define KSWORD_ARK_HVM_QUERY_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU       1UL
#define KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED     2UL
#define KSWORD_ARK_HVM_QUERY_STATUS_HYPERVISOR_CONFLICT   3UL
#define KSWORD_ARK_HVM_QUERY_STATUS_RESOURCES_UNAVAILABLE 4UL
#define KSWORD_ARK_HVM_QUERY_STATUS_SELF_TEST_FAILED      5UL
#define KSWORD_ARK_HVM_QUERY_STATUS_BUSY                  6UL
/*
 * The processor supports hardware virtualization, but this build has no
 * backend for it.  Distinct from UNSUPPORTED_CPU on purpose: the user should
 * know the machine is capable and the software is what is missing.
 */
#define KSWORD_ARK_HVM_QUERY_STATUS_BACKEND_NOT_IMPLEMENTED 7UL
#define KSWORD_ARK_HVM_QUERY_STATUS_PARTIAL               7UL
#define KSWORD_ARK_HVM_QUERY_STATUS_ROLLBACK_REQUIRED     8UL

#define KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED     0UL
#define KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY 1UL
#define KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL         2UL
#define KSWORD_ARK_HVM_IMPLEMENTATION_ACTIVE          3UL

#define KSWORD_ARK_HVM_CONTROL_PREPARE   1UL
#define KSWORD_ARK_HVM_CONTROL_SELF_TEST 2UL
#define KSWORD_ARK_HVM_CONTROL_TEARDOWN  3UL
#define KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST 4UL
/*
 * START_RESIDENT is available only when the driver publishes the guarded
 * resident-lifecycle feature.  The driver must stop every VCPU before a power
 * transition and must prevent image unload while any VCPU remains resident.
 */
#define KSWORD_ARK_HVM_CONTROL_START_RESIDENT 5UL
#define KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT  6UL
#define KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED 7UL
#define KSWORD_ARK_HVM_CONTROL_RESET_FAULT     8UL
/*
 * SOAK starts residency, holds it for the requested bounded window, and stops
 * it again.  It is the only control that proves residency survives ordinary
 * system activity rather than merely entering and leaving VMX non-root once.
 */
#define KSWORD_ARK_HVM_CONTROL_SOAK            9UL

/* Bound one soak window so a stuck request can never hold VMX indefinitely. */
#define KSWORD_ARK_HVM_SOAK_MAX_MILLISECONDS 30000UL
/* Keep a soak long enough for scheduler, timer and MSR activity to occur. */
#define KSWORD_ARK_HVM_SOAK_MIN_MILLISECONDS 100UL

#define KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_FORCE        0x00000002UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED 0x00000004UL
/* AMD-only bounded nested VMRUN probe; accepted by prepare/self-test, never resident. */
#define KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE 0x00008000UL
/* AMD-only experimental general SVM dispatch; requires matching prepared resources. */
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_SVM 0x00010000UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST 0x00000008UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPT_EVENTS 0x00000010UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX 0x00000020UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS      0x00000040UL
/*
 * Turn on EPT-violation-to-#VE conversion for this residency.
 *
 * DANGEROUS AND OFF BY DEFAULT.  The guest here is the running Windows, whose
 * IDT[20] handler is not prepared for a #VE the hypervisor invented.  Even with
 * suppress-#VE set on every leaf, any page whose bit 63 is later cleared will
 * deliver a real #VE into that handler.  Enabling this is only meaningful when
 * something inside the guest is known to handle vector 20.
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VE         0x00000080UL
/*
 * Turn on VM functions and EPTP switching for this residency.
 *
 * OFF BY DEFAULT.  VMFUNC has no CPL check, so arming this publishes every
 * domain in the EPTP list to unprivileged guest code.  Only meaningful when
 * every listed domain has been checked to grant no more than the default view.
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC   0x00000100UL
/*
 * Give every processor its own EPT hierarchy for this residency.
 *
 * OFF BY DEFAULT, and refused rather than silently downgraded: a caller that
 * asked for per-processor isolation and got a shared hierarchy would install
 * views on a multicore box believing each flip is local, which is precisely
 * the corruption the flag exists to prevent.
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT 0x00000200UL
/*
 * Select the EPTP-switching split-view backend for this runtime.
 *
 * OFF BY DEFAULT.  With the flag absent nothing changes: the driver keeps the
 * existing "write the leaf, single-step under the Monitor Trap Flag, write it
 * back" backend, byte for byte.
 *
 * The two backends answer the same question with different machinery, and the
 * difference is not performance - it is which capability they require:
 *
 *   write-leaf + MTF   needs INVEPT_SINGLE and MONITOR_TRAP_FLAG.
 *   switch EPTP        needs INVEPT_SINGLE and execute-only EPT leaves
 *                      (IA32_VMX_EPT_VPID_CAP bit 0).  It needs NEITHER the
 *                      Monitor Trap Flag NOR VM functions.
 *
 * That is the whole reason this flag exists: a nested Hyper-V guest is not
 * offered the Monitor Trap Flag, so the MTF backend cannot install a single
 * view there, while execute-only leaves are available and measured.
 *
 * Refused rather than silently downgraded, for the same reason as
 * ENABLE_LOCAL_EPT: a caller that asked for a backend which never writes an
 * EPT leaf at run time, and silently got one that does, would reason about
 * cross-processor visibility on a false premise.
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPTP_SWITCH 0x00000400UL
/*
 * 测量用：每次 VM exit 额外执行一批 VMREAD，结果丢弃。
 *
 * 存在的理由是一个没人量过的数：在嵌套之下，L1 执行 VMREAD 到底贵不贵。它决定
 * 「把 VMCS 字段访问改成读共享页」值不值得做 —— 那是个要映射一百多个字段、而且
 * 会丢掉几个较新字段（中断影子栈表、PKRS、UINV）的工程，收益不明就不该开工。
 *
 * 直接测单条指令的周期数需要在退出路径上取时间戳，本身就有观测代价；改成**加负载**
 * 反而干净：多读 N 次，看退出吞吐掉多少，单次成本就出来了，而且完全不改变任何一条
 * 退出的语义 —— 读出来的值直接丢弃，正常遥测照旧。
 *
 * 只在需要这个读数时置位。置位期间退出会变慢，这正是它要量的东西。
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_VMREAD_BENCH 0x00000800UL
/*
 * 请求里不给次数时用的默认值。
 *
 * 取 512 而不是几十：实测 32 次的效应完全淹没在噪声里（三轮交替得到
 * +18.1% / -13.5% / -6%，符号都不一致，基线自身极差就有 14%），那只说明
 * 「效应 < 噪声」，并不说明 VMREAD 便宜。**要得出结论就得把信号加大到测得出为止**，
 * 否则测不出和不存在分不开。512 次给出了干净信号（四轮 -42% ~ -43.9%）。
 */
#define KSWORD_ARK_HVM_VMREAD_BENCH_DEFAULT 512UL
/*
 * 次数上限。
 *
 * 每次退出都要跑这么多遍，取值过大等于把 guest 拖停；而这条路径在 VMX root、
 * 关中断、拿着退出栈，停在这里没有人能把它救回来。上限让一个手滑的数字变成
 * 一次被夹住的测量，而不是一台需要重启的机器。
 */
#define KSWORD_ARK_HVM_VMREAD_BENCH_MAX 4096UL
/*
 * 把每一条普通退出也逐条写进事件环。默认关闭。
 *
 * 关掉它不是为了省开销，是为了让环还能装得下证据。实测（2026-09-07，2 vCPU、
 * 30 秒常驻）：发布 682829 条、抢槽失败 0 条、被环回挤掉 681805 条。也就是说
 * 环从来没有写不进去的问题，它的问题是**一秒钟轮空二十二次** —— 1024 个槽在
 * 22750 次/秒的退出率下 45 毫秒就翻一遍。
 *
 * 而这 68 万条几乎全是同一类：普通退出（type VMEXIT）。它们的聚合答案退出原因
 * 直方图已经免费给了，逐条留着只做一件事——把 EPT 违例、嵌套 VMX、致命退出、
 * 生命周期这四类真正稀有的证据在 45 毫秒内挤出去。查一次罕见事件要求轮询快过
 * 环的翻转速度，这个条件在实机上没法成立。
 *
 * 所以默认只留那四类，普通退出交给直方图与 lastExit* 字段。需要逐条轨迹时置位
 * 本位，行为回到原来的样子——**能力没有被删掉，只是不再是默认**。
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_TRACE_ROUTINE_EXITS 0x00001000UL

/*
 * 对**用户态**的 CPUID 隐藏"有 hypervisor 在下面"这件事。
 *
 * 为什么需要这一位：真机上量到的第一个拦路读数不是能力不够，是**身份**。
 * VMware Workstation 17.6 在初始化时先用 CPUID 认出外层是 Hyper-V，然后去要
 * Windows Hypervisor Platform；这台来宾里没装 WHP，两边对不上，它就在装载
 * 任何虚拟机之前拒绝启动：
 *
 *     IOPL_Init: Hyper-V detected by CPUID
 *     WHP_CanBeInstalled: Hyper-V is not present, function should not be called.
 *     [msg.vmx.nestedHyperV] ... not compatible ...
 *     Module 'IOPL' initialization failed.
 *
 * 它看到的那个身份不是我们选的 —— 是 L0 的 Hyper-V 透过我们传上去的。常驻起来
 * 之后 CPUID 每一条都退出到我们手里，报什么由我们决定，而"把外层的身份原样转
 * 给我们自己的来宾"本来就谈不上正确。
 *
 * 影响面被刻意压到最小：**只在来宾 CPL=3 时改**。Windows 内核自己的 Hyper-V
 * enlightenment 走的是 CPL=0 的 CPUID 与 hypercall 页，那条路一个位都不动。
 * 做这个区分不是优化，是因为开机时就绑定了外层 hypervisor 的内核如果中途被告知
 * "没有 hypervisor"，后果无法预期，而我们要骗的那一个（vmware-vmx.exe）恰好
 * 完全在用户态。
 *
 * 这不是"完美伪装成裸机"，也不打算是：它只解决按身份拒绝这一件事。任何在内核
 * 里做同样检查的软件都仍然会看到真相 —— 那时读数会直接告诉我们，再谈要不要放宽。
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_HIDE_HYPERVISOR 0x00002000UL
/* Same-binary performance reference: retain unused CPUID diagnostic VMREADs. */
#define KSWORD_ARK_HVM_CONTROL_FLAG_FULL_EXIT_SNAPSHOT 0x00004000UL

#define KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN 0x48564D43UL

#define KSWORD_ARK_HVM_CONTROL_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU       3UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_FIRMWARE_DISABLED     4UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_HYPERVISOR_CONFLICT   5UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_ALREADY_PREPARED      6UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED          7UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED       8UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_SELF_TEST_FAILED      9UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED         10UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_BUSY                  11UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_GUEST_LAUNCH_FAILED   12UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_UNEXPECTED_VMEXIT     13UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_PARTIAL_IMPLEMENTATION 14UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_RENDEZVOUS_FAILED      15UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_ROLLBACK_REQUIRED      16UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_NESTED_UNSUPPORTED     17UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_EVMCS_UNSUPPORTED      18UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_POWER_TRANSITION_BLOCKED 19UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_LIFECYCLE_GUARD_FAILED   20UL
/* Per-processor EPT was requested but the runtime never armed the capability. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_NOT_ARMED      21UL
/* More flippable leaves than one private hierarchy is allowed to mirror. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_LEAF_SET_TOO_LARGE 22UL
/* The private hierarchies would not fit the reserved page budget. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_PAGE_BUDGET_EXHAUSTED 23UL
/* A flippable leaf had no live split to mirror; the caller must add it first. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_SPLIT_MISSING  24UL
/* The independent post-build walk disagreed with what the build published. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_VERIFY_FAILED  25UL
/* VMFUNC publishes one EPTP list to every processor; the two cannot coexist. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_VMFUNC 26UL
/* Nested VMX composes its own EPT pointer and cannot share this mechanism. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_NESTED 27UL
/*
 * 这台机器的客户物理地址空间比这一版能建的身份映射窗口大。
 *
 * 与 UNSUPPORTED_CPU 分家，因为它们要人做的事**相反**：那个说"换一台机器"，
 * 这个说"这台机器什么都支持，是我们的窗口太小"。
 *
 * 两者混在一起的代价是实测过的：一台 Intel Core Ultra 报 CPUID.80000008H:EAX
 * 的物理地址宽度是 45 位（32 TiB），而当时的窗口是 8 TiB，于是构建器截断、
 * 置 EPT_TRUNCATED、常驻拒绝，一路翻译成"处理器不支持"——由一台每一项能力
 * 都齐备的处理器说出来。用户只能去查 CPU 和 BIOS，而那两处都没有问题。
 *
 * 界面看到这个码时要说出三个数：本机的物理地址宽度（用户态一条 CPUID 就读得
 * 到）、这一版实际映射到哪里（查询响应里的 highestMappedPhysicalAddress）、
 * 以及需要多少个 PML4 项。
 */
#define KSWORD_ARK_HVM_CONTROL_STATUS_EPT_WINDOW_TOO_SMALL 28UL

#define KSWORD_ARK_HVM_EXIT_REASON_NONE   0xFFFFFFFFUL
#define KSWORD_ARK_HVM_EXIT_REASON_VMCALL 18UL
#define KSWORD_ARK_HVM_EXIT_REASON_EPT_VIOLATION 48UL
#define KSWORD_ARK_HVM_EXIT_REASON_EPT_MISCONFIGURATION 49UL
#define KSWORD_ARK_HVM_EXIT_REASON_INVEPT 50UL
#define KSWORD_ARK_HVM_EXIT_REASON_INVVPID 53UL
#define KSWORD_ARK_HVM_EXIT_REASON_MONITOR_TRAP 37UL

#define KSWORD_ARK_HVM_EPT_ACCESS_READ    0x00000001UL
#define KSWORD_ARK_HVM_EPT_ACCESS_WRITE   0x00000002UL
#define KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE 0x00000004UL

#define KSWORD_ARK_HVM_EPT_RULE_ADD    1UL
#define KSWORD_ARK_HVM_EPT_RULE_REMOVE 2UL
#define KSWORD_ARK_HVM_EPT_RULE_CLEAR  3UL
#define KSWORD_ARK_HVM_EPT_RULE_QUERY  4UL
/*
 * 把一条已经命中过的 WATCH_ONCE 规则重新武装。
 *
 * 不是"再 ADD 一条"：watchId 要保持不变，历史命中计数也要留着，否则用户在
 * 界面上看到的是一条新记录，而"同一个目标被动过几次"正是这个功能要回答的。
 */
#define KSWORD_ARK_HVM_EPT_RULE_REARM  5UL
/* 读回整张 watch 表。普通 QUERY 一次只回一条，列表页要的是全部。 */
#define KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY 6UL

#define KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG          0x00000001UL
#define KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE   0x00000002UL
#define KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED 0x00000004UL
/*
 * ENFORCE turns a rule from a tripwire into durable denial: the access is
 * refused with an injected #PF and residency continues, instead of recording
 * the hit and devirtualizing.  Unlike ALLOW_ONCE it never edits the shared EPT
 * leaf, so it is safe on any processor count.
 *
 * The guest sees a page fault at an address its own page tables map, which is
 * exactly what denial means here.  Kernel-mode targets can therefore bugcheck
 * the moment a driver touches the protected page - that is the intended
 * behavior of a deny rule, not a defect, and it is why the flag requires
 * explicit confirmation.
 *
 * A rule can only deny an access whose guest-linear address the CPU reported,
 * because CR2 has to be set for the injected fault to mean anything.  When it
 * is unavailable the rule falls back to tripwire behavior.
 */
#define KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE      0x00000008UL
/*
 * WATCH_ONCE：首次访问归因（first-touch attribution）。
 *
 * 与同一页上的另外三种处置都不同，值得逐条对照：
 *
 * - 严格 tripwire 命中后**退出虚拟化**。作为安全兜底是对的——它保证 guest 最终
 *   一定能完成那次访问——但作为用户层的"看看下次是谁动它"就完全不能用：抓到
 *   一次访问的代价是整台机器的 VMM 没了。
 * - ALLOW_ONCE 放行一条指令再用 monitor-trap 把权限收回来。它要 MTF，而嵌套
 *   Hyper-V 实测不给 MTF，所以在靶机上恒不可用；多核共享层次下那个放宽窗口
 *   还是全机可见的。
 * - ENFORCE 是持久拒绝，注 #PF —— 已被判 UNIMPLEMENTED（活锁）。
 *
 * WATCH_ONCE 正好是"ALLOW_ONCE 去掉收回那一步"：
 *
 *     EPT violation
 *         ↓
 *     原子 ARMED → TRIGGERED（只有一个 CPU 赢）
 *         ↓
 *     把这一页的权限**永久**恢复（这条规则从此不再拒绝）
 *         ↓
 *     INVEPT
 *         ↓
 *     RIP 不推进，VMRESUME
 *         ↓
 *     原指令重执行并正常完成；常驻继续
 *
 * 因为没有"再收回来"这一步，它**不需要 MTF**，也就不需要那道"单核或私有层次"
 * 的门：权限是朝放开方向单向变化的，别的处理器提前看到放开的权限，结果只是
 * 它们那次访问也正常完成——而这条 watch 本来就已经决定不再拦了。
 *
 * 语义上它**不是**安全边界：它不阻止访问，只记录一次现场然后让路。
 */
#define KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE   0x00000010UL

/*
 * Watch 生命周期。
 *
 * 单靠"规则在不在表里"表达不了这条时间线：命中之后规则必须留在表里（要报
 * hitCount 和最近一次命中的现场），但它已经不拦任何访问了。两件事必须分开。
 */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_NONE        0UL
/* 已装上并正在拦截，等待第一次访问。 */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED       1UL
/* 某个 CPU 赢下了原子转换，正在恢复权限。瞬时态。 */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_TRIGGERED   2UL
/* 已命中并解除，权限已恢复。要再看下一次必须显式 REARM。 */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED    3UL
/*
 * 常驻停过/释放过/故障过，这条 watch 绑定的那一代已经不存在了。
 *
 * 与 DISARMED 分开是因为两者对用户意味着完全不同的事：DISARMED 是"目标被动过
 * 了，证据在这儿"，INVALIDATED 是"我什么都没看到，因为中途没人在看"。把后者
 * 显示成前者，等于报告一次不存在的观测结果。
 */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED 4UL
/* 安装期就失败，没有进入过拦截。 */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_FAULTED     5UL

/* 命中时事件成功发布。 */
#define KSWORD_ARK_HVM_EPT_WATCH_HIT_NONE      0UL
#define KSWORD_ARK_HVM_EPT_WATCH_HIT_PUBLISHED 1UL
/*
 * 命中了，但事件环没接住。
 *
 * 必须与"从未命中"分开：两者在事件列表里长得一模一样（都是没有事件），而
 * 结论正好相反——一个是目标没被动过，一个是目标被动过但证据丢了。
 */
#define KSWORD_ARK_HVM_EPT_WATCH_HIT_EVENT_LOST 2UL

#define KSWORD_ARK_HVM_EPT_RULE_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_PREPARED          3UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND             4UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_TABLE_FULL            5UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_SPLIT_FAILED          6UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL               7UL
/*
 * 请求的处置在当前机制下无法实现，安装期就拒绝。
 *
 * 目前只有一个来源：ENFORCE。它的语义是"持久拒绝"，实现是往 guest 注 #PF ——
 * 而拒绝发生在 EPT 层，guest 的页表说那一页好好的，缺页处理器什么都不修就
 * 返回、重执行、再违规、再注 #PF。实测是无限活锁，把整台机器挂在那里，
 * 而且异常从没交付到用户态，SEH 也接不住。
 *
 * 在 guest 看不见 EPT 的前提下，注入一个 guest 能自己解决的 fault 是做不到的；
 * 真正的"读到假页"要靠分离视图重定向，不是靠拒绝。所以宁可在这里挡住，
 * 也不要装上一条一旦命中就挂机器的规则。
 */
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_UNIMPLEMENTED         8UL
/*
 * 这台机器上这条规则的处置无法安全实现，安装期就拒绝。
 *
 * 目前只有一个来源：多核机器上的 ALLOW_ONCE。它的实现是把 EPT 叶临时放宽一条
 * 指令再用 monitor-trap 复原，而在**共享**层次上那个窗口是全机可见的 —— 别的
 * 处理器在同一瞬间也拿到了放宽后的权限。所以运行期有一道门（hvm_ept.c 的
 * allAllowOnce 分支）要求"独占一个处理器，或者走私有层次"，两者都不满足就
 * 判 fail-closed。
 *
 * 问题不在那道门，在于**它太晚了**：规则装得上，看上去是成功的，直到某次真的
 * 命中 —— 然后整台机器退出 VMX（fail-closed 现在是全机停机，不再只停当前核，
 * 见 hvm_internal.h 的 ResidentFaultStopRequested）。用户得到的是"装好了"然后
 * 某个时刻虚拟化悄悄没了，中间没有任何东西把这两件事联系起来。
 *
 * 私有层次这条出路在嵌套下走不通：它要 LocalEptArmed，而那要求 INVEPT_SINGLE
 * **和** MONITOR_TRAP_FLAG，嵌套 Hyper-V 不给 MTF。所以在嵌套靶机上"多核 +
 * ALLOW_ONCE"是恒不可用的组合，更该在安装期说清楚。
 *
 * 这不是"ALLOW_ONCE 做不到"，是"这台机器上做不到"：单核、或者武装了私有 EPT
 * 的多核，都照旧放行。
 */
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_MULTIPROCESSOR_UNSAFE 9UL
/*
 * 这一页已经被别的 EPT 机制占着（分离视图、执行域、或另一条 watch）。
 *
 * 不做自动合并，也不静默覆盖：两套机制对同一个叶项的期望值不同，谁后写谁赢，
 * 而赢的那一方会在对方毫不知情的情况下把对方的功能改掉。一页一个明确的主人，
 * 冲突时直接说清楚是谁占着，让用户自己决定先撤哪一个。
 */
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT         10UL
/*
 * 常驻正在跑，而规则表在整个常驻期间是冻结的。
 *
 * 这不是"部分成功"：一个字段都没改过。它原先复用 PARTIAL（"部分处理器未能完成
 * 失效"）上报，而那句话描述的是一件根本没发生的事，还把用户引向失效机制去查。
 *
 * 冻结本身不是保守，是必需的：常驻期间的 VM-exit 路径不取 PASSIVE 级别的锁就
 * 扫规则表与 split 叶，PASSIVE 侧同时改它就是一场没有诊断面的竞争。
 *
 * 所以所有 EPT 规则（含内存监视）的安装、重新武装、移除都在常驻停着时做，
 * 启动常驻后生效——这与分离视图、MSR 策略、CR 策略的窗口期是同一个。
 */
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN       11UL

#define KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT          1UL
#define KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION   2UL
#define KSWORD_ARK_HVM_EVENT_TYPE_NESTED_VMX      3UL
#define KSWORD_ARK_HVM_EVENT_TYPE_FATAL_EXIT      4UL
#define KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE       5UL
/* Page-control stages use ruleId as operation id, not an EPT rule id. */
#define KSWORD_ARK_HVM_EVENT_TYPE_NESTED_PAGE     6UL

#define KSWORD_ARK_HVM_EVENT_QUERY_READ  1UL
#define KSWORD_ARK_HVM_EVENT_QUERY_CLEAR 2UL

#define KSWORD_ARK_HVM_NESTED_STATE_DISABLED        0UL
#define KSWORD_ARK_HVM_NESTED_STATE_CAPABILITY_ONLY 1UL
#define KSWORD_ARK_HVM_NESTED_STATE_DISPATCH_READY  2UL
#define KSWORD_ARK_HVM_NESTED_STATE_L1_VMXON        3UL
#define KSWORD_ARK_HVM_NESTED_STATE_VMCS12_CURRENT  4UL
#define KSWORD_ARK_HVM_NESTED_STATE_L2_PARTIAL      5UL
/*
 * L2 is executing under a composed hierarchy.
 *
 * Distinct from L2_PARTIAL, which means an L2 entry was attempted and refused.
 * This one means the processor is actually running L1's guest, so a reader
 * that sees it can conclude the merge and the shadow hierarchy both held.
 */
#define KSWORD_ARK_HVM_NESTED_STATE_L2_ACTIVE       6UL

#define KSWORD_ARK_HVM_EVMCS_STATE_UNAVAILABLE     0UL
#define KSWORD_ARK_HVM_EVMCS_STATE_CAPABILITY_ONLY 1UL
#define KSWORD_ARK_HVM_EVMCS_STATE_V1_PARTIAL       2UL
#define KSWORD_ARK_HVM_EVMCS_STATE_ACTIVE           3UL

#define KSWORD_ARK_HVM_EVMCS_FLAG_ROOT_PARTITION      0x00000001UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_VP_ASSIST_READABLE  0x00000002UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_VP_ASSIST_ENABLED   0x00000004UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_OWNERSHIP_CONFLICT  0x00000008UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_CLEAN_FIELDS        0x00000010UL

typedef struct _KSWORD_ARK_HVM_CPU_ROW
{
    unsigned short processorGroup;
    unsigned char processorNumber;
    unsigned char vmxInstructionResult;
    unsigned long stateFlags;
    long lastStatus;
    unsigned long lastExitReason;
    unsigned long long vmExitCount;
    unsigned long nestedState;
    unsigned short evmcsVersion;
    unsigned short reserved;
    /* Architecture-specific instruction evidence is never overloaded. */
    unsigned long backend;
    /* Common stage used by the AMD execution path. */
    unsigned long executionStage;
    /* Raw SVM EXITCODE is 64-bit and sparse; zero if not valid. */
    unsigned long long svmExitCode;
} KSWORD_ARK_HVM_CPU_ROW;

typedef struct _KSWORD_ARK_QUERY_HVM_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_QUERY_HVM_REQUEST;

/* AMD probe evidence remains available even when resource preparation is refused. */
typedef struct _KSWORD_ARK_HVM_SVM_CAPABILITIES {
    /* MSR validity: VM_CR=1, EFER=2, VM_HSAVE_PA=4, PAT=8. */
    unsigned long maxLeaf, features, asidCount, physicalBits, msrValidMask, exceptionStatus;
    /* Raw observations are meaningful only with the matching valid bit. */
    unsigned long long vmCr, efer, hsave, pat;
    /* V6 admission diagnostics; raw XSS=0 is evidence only when its valid bit is set. */
    unsigned long rejectReason, stateValidMask, cpuid1Ecx, xsaveFeatures;
    /* Read-only observations; discovery never changes these registers. */
    unsigned long long cr4, xcr0, xss;
} KSWORD_ARK_HVM_SVM_CAPABILITIES;

typedef struct _KSWORD_ARK_QUERY_HVM_RESPONSE
{
    unsigned long version;
    unsigned long size;
    /* V5 backend identity, independent of the CPU vendor string. */
    unsigned long backend;
    /* NONE/EPT/NPT; NPT is not represented by an EPT-ready feature bit. */
    unsigned long slatType;
    /* Common translation readiness independent of EPT implementation. */
    unsigned long slatReady;
    /* Actual AMD control/save backend status; zero on VMX. */
    unsigned long backendStatus;
    /* Power epoch is separate from the command-by-command generation counter. */
    unsigned long powerGeneration;
    /* Captured probe evidence, independent of allocation and execution. */
    KSWORD_ARK_HVM_SVM_CAPABILITIES svmCapabilities;
    unsigned long queryStatus;
    unsigned long stateFlags;
    unsigned long generation;
    unsigned long processorCount;
    unsigned long preparedProcessorCount;
    unsigned long selfTestPassedProcessorCount;
    unsigned long residentProcessorCount;
    unsigned long residentImplementation;
    unsigned long eptImplementation;
    unsigned long nestedImplementation;
    unsigned long evmcsImplementation;
    /*
     * 有多少个处理器备好了退出安全的物理映射窗口。
     *
     * 单独报，因为窗口的准备期自检**在外面完全看不见**：过不了只会让需要它的
     * 路径（嵌套 L2 进入、影子 EPT 合成）安静地拒绝，而状态位、实现成熟度、
     * 处理器计数没有一个会变。一个验不出结果的自检和没有自检，从读数上分不开。
     *
     * 比对的分母**不是 processorCount**。那是"已准备的处理器数"，准备资源之前
     * 是 0；而窗口在**驱动初始化**时就建好了。拿它当分母，刚加载完驱动去读会得
     * 到「N / 0」，把一台好机器报成坏的。
     *
     * 正确的分母是调用方自己查到的逻辑处理器数（GetActiveProcessorCount /
     * KeQueryActiveProcessorCountEx，ALL_PROCESSOR_GROUPS）：相等才说明每个核
     * 都有。驱动初始化之前本字段为零。
     */
    unsigned long physWindowReadyCount;
    unsigned long eptRuleCount;
    unsigned long eventCount;
    /*
     * Events a VM exit tried to publish and could not - the only real loss.
     *
     * A publisher in VMX root never waits, so when it finds its slot owned by
     * another processor it discards the event and counts it here.  A nonzero
     * value is contention: two processors mapped to the same slot at the same
     * moment.  This is the number that justifies changing the ring's shape.
     *
     * This field used to carry max(displacement, publication loss), which made
     * it unreadable - displacement dominates by three orders of magnitude and
     * is not necessarily a loss at all, so the combined number always looked
     * catastrophic and never distinguished the two causes.
     */
    unsigned long droppedEventCount;
    /*
     * Events pushed out of the ring by wrap since residency started.
     *
     * Not a loss on its own: a consumer polling faster than the ring fills has
     * already read them.  It becomes a loss exactly when it grows between two
     * consecutive reads by more than the ring capacity, which is a comparison
     * only the caller can make because only the caller knows its own interval.
     */
    unsigned long overwrittenEventCount;
    /*
     * Total events ever published, as the denominator for the two above.
     *
     * Full width rather than 32-bit: at the exit rates measured under nested
     * virtualization a 32-bit total wraps within hours, and a wrapped total
     * silently turns both ratios above into nonsense.
     */
    unsigned long long publishedEventCount;
    unsigned long nestedState;
    unsigned long evmcsState;
    unsigned short evmcsVersion;
    /*
     * 最后一次 L2 进入被哪一处拒绝，1..7；0 表示没有拒绝过。
     *
     * 占用原先的 reservedVersion 槽位（没有任何读写方），结构大小不变。
     *
     * 存在的理由：七处不同的条件返回**同一个**架构错误码 7（invalid control
     * field），因为架构只有这一个号码、没有第二个字段说明是哪一处。L1 拿到 7、
     * 报出 7，从外面看七种情况一模一样 —— 而唯一真正需要知道的就是哪一处。
     * 编号的含义见 hvm_nested_l2.c 里各个赋值点。
     */
    unsigned short nestedLastRefusalSite;
    unsigned long evmcsFlags;
    /*
     * 无进展熔断跳闸的次数，整机累计。
     *
     * 熔断本身在别处**看不见**：它的读数一直只在嵌套探针的行里，而真正的 L1
     * （VMware 的 VMM、别人的 hypervisor）不会去跑我们的探针。于是"L2 打转被我们
     * 拦下来了"这件事，在真实场景里没有任何地方读得到 —— 而那恰恰是最需要知道的
     * 时候：机器没挂，但某个 hypervisor 的来宾被我们停了。
     *
     * 占用原先的 reservedEvmcs 槽位（没有任何读写方），结构大小不变，旧 GUI 读到的
     * 每个字段都不移位。
     */
    unsigned long nestedFuseTripCount;
    unsigned long long evmcsVpAssistMsr;
    unsigned long eptPageCount;
    unsigned long eptPml4Entries;
    unsigned long eptPdptEntries;
    unsigned long eptLargePageEntries;
    unsigned long long featureFlags;
    unsigned long long vmxBasic;
    unsigned long long vmxEptVpidCapabilities;
    unsigned long long featureControl;
    unsigned long long cr0Fixed0;
    unsigned long long cr0Fixed1;
    unsigned long long cr4Fixed0;
    unsigned long long cr4Fixed1;
    unsigned long long eptPointer;
    unsigned long long mappedRamBytes;
    unsigned long long highestMappedPhysicalAddress;
    unsigned long long vmExitCount;
    unsigned long long lastExitQualification;
    unsigned long long lastGuestRip;
    unsigned long long lastGuestRsp;
    unsigned long lastExitReason;
    unsigned long lastExitInstructionLength;
    unsigned long lastVmInstructionError;
    unsigned short lastLaunchProcessorGroup;
    unsigned char lastLaunchProcessorNumber;
    unsigned char lastLaunchWasNested;
    long lastStatus;
    /*
     * Times an L1 guest asked us to launch an L2 and we refused.
     *
     * This has to be a monotonic counter and not a state, because nestedState
     * is transient: it reaches L2_PARTIAL at the refused VMLAUNCH and is reset
     * to DISPATCH_READY on the next VMXOFF, so a two-second poll almost always
     * misses it.  A nonzero value here is the only durable evidence that some
     * other hypervisor on this machine - VMware, VirtualBox, WSL2, Docker -
     * tried to start a VM underneath us and could not.  Without it the user
     * sees "my VM stopped working" and nothing points at us.
     *
     * Occupies the former reserved slot, so the structure size is unchanged
     * and the protocol version does not move.
     */
    unsigned long nestedL2LaunchRefusedCount;
    char cpuVendor[KSWORD_ARK_HVM_VENDOR_CHARS];
    char hypervisorVendor[KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS];
    /*
     * Exits so far by Intel basic exit reason, summed over every processor.
     *
     * `vmExitCount` says how many exits happened and `lastExitReason` says what
     * the most recent one was; neither says where the exits go, which is the
     * question that actually comes up.  Reading "lastExitReason 18" a hundred
     * times does not distinguish VMCALL being 99% of the traffic from VMCALL
     * being rare and merely last.
     *
     * Summed rather than reported per processor because the per-processor form
     * would add this array 256 times over.  The driver keeps it per processor
     * internally - that is what makes it free of interlocked access - and adds
     * the columns up here.
     *
     * Indexes past the last reason Intel defines stay zero.  A processor's own
     * counter is 32-bit and wraps after roughly five days at ten thousand exits
     * a second; this sum is 64-bit, so it only inherits a wrap that already
     * happened rather than adding one.
     */
    unsigned long long exitReasonCount[KSWORD_ARK_HVM_EXIT_REASON_SLOTS];
    /*
     * The execution controls actually enforced, and the capability MSR each was
     * adjusted against.
     *
     * Reported because "which exits does this machine take" and "which of them
     * did we ask for" are different questions.  A control bit set in the active
     * value that the driver's request did not contain is one the capability
     * MSR's allowed-0 half made mandatory - which is how an outer hypervisor's
     * demand is told apart from a mistake in our own control computation.
     * Without this the distinction is only reachable by reading source.
     *
     * Zero until residency has been configured at least once.
     */
    unsigned long activePinControls;
    unsigned long activePrimaryControls;
    unsigned long activeSecondaryControls;
    unsigned long activeExitControls;
    unsigned long activeEntryControls;
    /*
     * 有多少份 vmcs12 因为每处理器的池满了而被丢掉。
     *
     * 一个 L1 手里的 VMCS 常常不止一份，它会不停 VMPTRLD 在其中切换。被驱逐的
     * 那一份下次 VMPTRLD 回来时字段全是零 —— 在 L1 看来，跟"这个 hypervisor
     * 只建模了一份 vmcs12"那个缺陷一模一样。所以真出了问题，这个数是唯一能把
     * 两者分开的东西：非零就是池太小，零就得往别处查。
     *
     * 放在运行时而不是每处理器：池在退虚拟化时就释放了，一个跟着被测对象一起
     * 消失的计数器只能回答"现在有没有在发生"，而问题是"有没有发生过"。
     *
     * 占用原先的 activeControlsReserved 槽位（它只是显式化的对齐填充，没有任何
     * 读写方），结构大小不变，协议版本不动 —— 旧 GUI 读到的每一个字段都不移位。
     */
    unsigned long nestedVmcs12EvictionCount;
    unsigned long long pinCapability;
    unsigned long long primaryCapability;
    unsigned long long secondaryCapability;
    unsigned long long exitCapability;
    unsigned long long entryCapability;
    KSWORD_ARK_HVM_CPU_ROW processors[KSWORD_ARK_HVM_MAX_PROCESSORS];
} KSWORD_ARK_QUERY_HVM_RESPONSE;

typedef struct _KSWORD_ARK_CONTROL_HVM_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long command;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    /* Requested soak window in milliseconds; only SOAK reads this field. */
    unsigned long soakMilliseconds;
    /*
     * 每次 VM exit 额外执行多少次结果丢弃的 VMREAD。
     *
     * 只有 START_RESIDENT 且带 VMREAD_BENCH 位时读这个字段；0 表示用默认值。
     *
     * 做成可配置而不是编译期常量，是因为**这个数必须能当场调**：取 32 时三轮交替
     * 的符号都不一致（+18.1% / -13.5% / -6%），完全淹没在噪声里；取 512 才有干净
     * 信号（四轮 -42% ~ -43.9%）。"测不出"和"不存在"只能靠加大信号来区分，而每
     * 换一个数就重编译一次驱动，会让人倾向于接受第一个读数 —— 那正是得出错误
     * 结论的路径。
     *
     * 占用原先的 reserved 槽位，结构大小不变，协议版本不动。
     */
    unsigned long vmreadBenchIterations;
} KSWORD_ARK_CONTROL_HVM_REQUEST;

typedef struct _KSWORD_ARK_CONTROL_HVM_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long oldStateFlags;
    unsigned long newStateFlags;
    unsigned long oldGeneration;
    unsigned long newGeneration;
    unsigned long preparedProcessorCount;
    unsigned long selfTestPassedProcessorCount;
    unsigned long failedProcessorCount;
    unsigned long residentProcessorCount;
    unsigned long residentImplementation;
    unsigned long eptImplementation;
    unsigned long nestedImplementation;
    unsigned long evmcsImplementation;
    unsigned long eptRuleCount;
    unsigned long eventCount;
    unsigned long eptPageCount;
    unsigned long lastExitReason;
    unsigned long long eptPointer;
    unsigned long long mappedRamBytes;
    unsigned long long vmExitCount;
    unsigned long long lastExitQualification;
    unsigned long long lastGuestRip;
    unsigned long long lastGuestRsp;
    unsigned long lastExitInstructionLength;
    unsigned long lastVmInstructionError;
    unsigned short launchProcessorGroup;
    unsigned char launchProcessorNumber;
    unsigned char launchWasNested;
    long lastStatus;
    /*
     * 本驱动的身份映射窗口有多少个 PML4 项，每项 512 GiB。
     *
     * 占用原先的 reserved2 槽位（没有任何读写方），结构大小不变，协议版本不动。
     *
     * 存在的理由只有一个：配 EPT_WINDOW_TOO_SMALL 时，界面要说得出"本机需要多少
     * 项、这一版有多少项"。前者界面自己用一条 CPUID 就算得出来，后者算不出——
     * 它是**这个驱动**编译时的常量，而一个从旧头文件构建的界面手里的那个值正好
     * 是错的。恰恰在版本不齐时这条消息最需要准确。
     *
     * 每次控制调用都填，不只在失败时填：一个只在出事时才有值的字段，没出事的
     * 时候没有任何地方能确认它是对的。
     */
    unsigned long eptPml4EntryBudget;
    /* Milliseconds residency actually held during the last soak. */
    unsigned long soakElapsedMilliseconds;
    /*
     * Processors that left VMX non-root on their own during the soak.  Any
     * nonzero value means an exit reason reached the fail-closed path, so the
     * soak did not prove sustained residency.
     */
    unsigned long soakUnexpectedDevirtualizations;
} KSWORD_ARK_CONTROL_HVM_RESPONSE;

typedef struct _KSWORD_ARK_HVM_EPT_RULE_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    unsigned long ruleId;
    /*
     * EPT permissions removed while resident.  This is a tripwire mask, not a
     * durable access-control guarantee: a strict hit records and devirtualizes
     * without injecting an exception, so the same native access may retry and
     * succeed after VMXOFF.  Removing READ also removes WRITE; when execute-only
     * EPT is unsupported it removes EXECUTE as well.
     */
    unsigned long deniedAccess;
    unsigned long long physicalAddress;
    unsigned long long pageCount;
    /*
     * ——— 以下字段只服务于 WATCH_ONCE，其余处置一律忽略 ———
     *
     * 它们记录的是**用户请求的东西**，而不是硬件实际监视的东西。这两者在 EPT
     * 上永远不相等：EPT 权限是 4 KiB 页粒度，而用户往往是从一个 8 字节的
     * DriverObject->MajorFunction[14] 建的 watch。驱动不会因为存了这两个值就
     * 监视得更细；存它们是为了让命中之后能回答"这次访问落没落在你真正关心的
     * 那几个字节上"，以及让界面能如实地把两套数字并排显示出来。
     *
     * 把它们丢掉、只留页地址，界面就只能把一次页内其它偏移的访问说成"你的
     * 目标被访问了"——那是一句读起来完全正确、实际上可能完全不相干的话。
     */
    unsigned long long requestedAddress;
    unsigned long long requestedLength;
    /*
     * 用户勾的那几项，未经架构归一化。
     *
     * deniedAccess 是归一化之后的**实际**生效掩码（去掉 READ 必然连带去掉
     * WRITE，没有 execute-only 时还要连带去掉 EXECUTE）。两者必须都留着：
     * 只留归一化后的值，界面就会把"你要求监视读"显示成"你要求监视读写"，
     * 那是替用户改了他的请求；只留请求值，界面又会谎称只监视了读。
     */
    unsigned long requestedAccess;
    /* 请求用的地址种类，见 KSWORD_ARK_HVM_WATCH_ADDRESS_*。仅作回显。 */
    unsigned long addressKind;
} KSWORD_ARK_HVM_EPT_RULE_REQUEST;

/* requestedAddress 是内核虚拟地址，安装时由驱动翻译成物理页。 */
#define KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL  0UL
/* requestedAddress 就是物理地址，不做翻译。 */
#define KSWORD_ARK_HVM_WATCH_ADDRESS_PHYSICAL 1UL

/* 一次 watch 表快照里最多回报多少条。 */
#define KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS 32UL

/* 一条 watch 的完整协议快照。 */
typedef struct _KSWORD_ARK_HVM_EPT_WATCH_ROW
{
    /* 与 ruleId 同一个值：watch 就是一条带 WATCH_ONCE 处置的 EPT 规则。 */
    unsigned long watchId;
    /* 见 KSWORD_ARK_HVM_EPT_WATCH_STATE_*。 */
    unsigned long state;
    /* 用户请求的访问类型，未归一化。 */
    unsigned long requestedAccess;
    /* 实际装到 EPT 上的访问类型，已归一化。 */
    unsigned long effectiveAccess;
    /* 安装时的地址种类。 */
    unsigned long addressKind;
    /*
     * 累计命中次数。
     *
     * 一条 one-shot watch 正常只会到 1；REARM 之后继续累加，所以它回答的是
     * "这个目标一共被动过几次"，而不是"当前这一轮有没有命中"。
     */
    unsigned long hitCount;
    /* 最近一次命中的事件序号；配合 lastHitStatus 判断证据在不在。 */
    unsigned long long lastHitSequence;
    /* 见 KSWORD_ARK_HVM_EPT_WATCH_HIT_*。 */
    unsigned long lastHitStatus;
    /*
     * 武装这一轮时的 HVM 代次。
     *
     * 常驻停过、释放过、故障过都会推进代次；代次对不上就说明这条 watch 跨过了
     * 一次"没有人在看"的空档，此时它报的任何"未命中"都不成立。
     */
    unsigned long armedGeneration;
    /* 用户请求的地址与长度，原样回显。 */
    unsigned long long requestedAddress;
    unsigned long long requestedLength;
    /* 实际监视的物理页与页内偏移。 */
    unsigned long long physicalPage;
    unsigned long long pageCount;
    /* 最近一次命中的现场，够界面直接列出来而不必再去翻事件环。 */
    unsigned long long lastHitRip;
    unsigned long long lastHitGuestLinearAddress;
    unsigned long long lastHitGuestPhysicalAddress;
    unsigned long long lastHitCr3;
    unsigned long long lastHitRsp;
    unsigned long long lastHitTimestamp;
    unsigned short lastHitProcessorGroup;
    unsigned char lastHitProcessorNumber;
    /* 命中时 CPU 是否报告了有效的客户线性地址。 */
    unsigned char lastHitGuestLinearValid;
    /* 命中的 GLA 是否落在 requestedAddress/Length 之内。 */
    unsigned long lastHitRangeMatch;
} KSWORD_ARK_HVM_EPT_WATCH_ROW;

typedef struct _KSWORD_ARK_HVM_EPT_RULE_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long ruleId;
    unsigned long ruleCount;
    unsigned long generation;
    unsigned long implementation;
    /* Effective tripwire mask after architectural permission normalization. */
    unsigned long deniedAccess;
    unsigned long flags;
    unsigned long reserved;
    unsigned long long physicalAddress;
    unsigned long long pageCount;
    long lastStatus;
    unsigned long reserved2;
    /*
     * ——— 以下字段服务于 WATCH_ONCE ———
     *
     * 追加在结构尾部而不是插进中间：中间插字段会让所有既有字段的偏移平移，
     * 而增量构建出来的 .sys 与 GUI 只要有一边没重建，读到的就是错位的值——
     * 那种故障没有任何编译期或运行期提示。
     */
    /* 占着这一页的另一个机制的标识，仅在 LEAF_CONFLICT 时有意义。 */
    unsigned long conflictOwnerId;
    /* 见 KSWORD_ARK_HVM_WATCH_CONFLICT_*。 */
    unsigned long conflictOwnerKind;
    /* WATCH_QUERY 回报的条数，以及表内总条数。 */
    unsigned long returnedWatchRows;
    unsigned long watchRowCount;
    /* 单条操作（ADD / REARM / QUERY）回报的那一条 watch 的完整快照。 */
    KSWORD_ARK_HVM_EPT_WATCH_ROW watch;
    /* WATCH_QUERY 专用。 */
    KSWORD_ARK_HVM_EPT_WATCH_ROW watchRows[KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS];
} KSWORD_ARK_HVM_EPT_RULE_RESPONSE;

/* 这一页没有别的主人。 */
#define KSWORD_ARK_HVM_WATCH_CONFLICT_NONE   0UL
/* 被一条 EPT 分离视图（CLOAK / HOOK）占着。 */
#define KSWORD_ARK_HVM_WATCH_CONFLICT_VIEW   1UL
/* 被另一条 EPT 规则占着。 */
#define KSWORD_ARK_HVM_WATCH_CONFLICT_RULE   2UL
/* 被另一条 watch 占着。 */
#define KSWORD_ARK_HVM_WATCH_CONFLICT_WATCH  3UL

typedef struct _KSWORD_ARK_HVM_EVENT_ROW
{
    unsigned long long sequence;
    unsigned long long timestamp;
    unsigned long long guestPhysicalAddress;
    unsigned long long guestLinearAddress;
    unsigned long long guestRip;
    unsigned long long qualification;
    unsigned short processorGroup;
    unsigned char processorNumber;
    unsigned char reserved0;
    unsigned long type;
    unsigned long exitReason;
    unsigned long access;
    unsigned long ruleId;
    long status;
    unsigned long reserved1;
    /*
     * ——— 以下字段追加于 2026-09-19，服务于 watch 命中归因 ———
     *
     * 追加在尾部，既有字段的偏移一个都不动。
     *
     * 这三样是**必须在 VM-exit 现场取**的：RSP 和 CR3 一旦 VMRESUME 回去就
     * 不再是命中那一刻的值，事后从 R0 去问只会得到另一个线程的答案。相对地，
     * 模块名、符号、PID 这些都**不在**这里——在 VMX root 里解析 Windows 对象
     * 是拿整台机器冒险，那些留给 R0 普通上下文和 R3 做后处理。
     */
    unsigned long long guestRsp;
    /*
     * 命中那一刻的 guest CR3。
     *
     * 它是"当时处于哪个地址空间"的唯一可信来源，也是 PID 归因的输入。但它只是
     * 一个观测值：KVA shadow、系统地址空间、内核工作线程、CR3 复用都会让
     * CR3 → PID 这一步不成立，所以协议只回报观测到的 CR3，把"解析成了哪个
     * 进程"和"有多大把握"留给上层各自标注。
     */
    unsigned long long guestCr3;
    /* 命中后这条 watch 的状态，见 KSWORD_ARK_HVM_EPT_WATCH_STATE_*。 */
    unsigned long watchState;
    /* 见 KSWORD_ARK_HVM_EVENT_FLAG_*。 */
    unsigned long eventFlags;
} KSWORD_ARK_HVM_EVENT_ROW;

/* CPU 报告了有效的客户线性地址（EPT violation qualification 位 7）。 */
#define KSWORD_ARK_HVM_EVENT_FLAG_GLA_VALID   0x00000001UL
/* 该 GLA 落在用户请求的那一段字节范围内，而不只是落在同一页上。 */
#define KSWORD_ARK_HVM_EVENT_FLAG_RANGE_MATCH 0x00000002UL
/* 这一条是 watch 的首次命中。 */
#define KSWORD_ARK_HVM_EVENT_FLAG_WATCH_HIT   0x00000004UL

typedef struct _KSWORD_ARK_HVM_EVENT_QUERY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long maxRows;
    unsigned long long afterSequence;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_HVM_EVENT_QUERY_REQUEST;

typedef struct _KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long returnedRows;
    unsigned long availableRows;
    /* Rows overwritten or unavailable in this nonblocking sequence snapshot. */
    unsigned long droppedRows;
    unsigned long reserved;
    unsigned long long newestSequence;
    KSWORD_ARK_HVM_EVENT_ROW rows[KSWORD_ARK_HVM_MAX_EVENT_ROWS];
} KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE;

/*
 * Ring -1 memory access.
 *
 * The point of this interface is not that it can read memory - the kernel can
 * already do that - but that it reaches memory without calling the documented
 * memory-manager routines an attacker or a competing product may have hooked.
 * It rewrites a private page-table entry and reads through its own window.
 *
 * When the self-map discovery that window depends on fails, the driver falls
 * back to MmCopyMemory and says so in usedDirectWindow, so a caller can always
 * tell whether the hook-free path was actually taken.
 */
/*
 * Version 2 adds processId.  The layout changed, so the version had to move
 * with it: a v1 caller and a v2 driver would disagree about where address
 * begins, and a silent disagreement about a memory-write target is the worst
 * kind there is.
 */
#define KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION 2UL

/* Bound one transfer so METHOD_BUFFERED request snapshots stay small. */
#define KSWORD_ARK_HVM_MEMORY_MAX_BYTES 1024UL

#define KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL  1UL
#define KSWORD_ARK_HVM_MEMORY_OP_WRITE_PHYSICAL 2UL
#define KSWORD_ARK_HVM_MEMORY_OP_READ_VIRTUAL   3UL
#define KSWORD_ARK_HVM_MEMORY_OP_WRITE_VIRTUAL  4UL
#define KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE      5UL
/* Report whether the private window is available without touching memory. */
#define KSWORD_ARK_HVM_MEMORY_OP_QUERY_WINDOW   6UL

#define KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED 0x00000001UL
/* Refuse the request outright when the private window is unavailable. */
#define KSWORD_ARK_HVM_MEMORY_FLAG_REQUIRE_WINDOW 0x00000002UL

/* Reuse the HVM control token so one confirmation vocabulary covers the area. */
#define KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN 0x48564D43UL

#define KSWORD_ARK_HVM_MEMORY_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_WINDOW_UNAVAILABLE    3UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_ADDRESS_INVALID       4UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_TRANSLATION_FAILED    5UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_ACCESS_FAILED         6UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_PARTIAL               7UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_BUSY                  8UL
/* The requested process could not be looked up or has already exited. */
#define KSWORD_ARK_HVM_MEMORY_STATUS_PROCESS_LOOKUP_FAILED 9UL

typedef struct _KSWORD_ARK_HVM_MEMORY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long length;
    /*
     * Target process for virtual operations.  Zero keeps the historical
     * behavior: resolve through directoryBase, or through the calling thread
     * when that is zero too.
     *
     * The driver resolves the process to a page-directory base internally and
     * never reports it back.  Handing a caller another process CR3 would be
     * handing it a ready-made argument for a page-table walk from user mode,
     * which is a capability this interface has no reason to grant.
     */
    unsigned long processId;
    /* Keep the 64-bit fields naturally aligned without undefined padding. */
    unsigned long reserved0;
    /* Physical address for physical operations, virtual for the rest. */
    unsigned long long address;
    /*
     * Target page-directory base for virtual operations.  Ignored when
     * processId is nonzero.  Zero means the address is resolved through the
     * page tables of the current process.
     */
    unsigned long long directoryBase;
    unsigned char data[KSWORD_ARK_HVM_MEMORY_MAX_BYTES];
} KSWORD_ARK_HVM_MEMORY_REQUEST;

typedef struct _KSWORD_ARK_HVM_MEMORY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long bytesTransferred;
    /* Physical address the access actually resolved to. */
    unsigned long long physicalAddress;
    /* Nonzero when the private page-table window carried the access. */
    unsigned char usedDirectWindow;
    /* Nonzero when the private window exists at all on this system. */
    unsigned char windowReady;
    unsigned short reserved0;
    long ntStatus;
    unsigned char data[KSWORD_ARK_HVM_MEMORY_MAX_BYTES];
} KSWORD_ARK_HVM_MEMORY_RESPONSE;

/*
 * EPT split views: one guest-physical page backed by two different frames
 * depending on how it is accessed.
 *
 * CLOAK backs execution with the real page and every read or write with a
 * shadow, so code keeps running while memory scanners see whatever the shadow
 * holds.  HOOK is the mirror image: reads and writes see the real page while
 * execution is redirected into a shadow that carries the patched instructions,
 * which is a breakpoint no byte comparison can find.
 *
 * Both are implemented by flipping the shared EPT leaf on violation and
 * restoring it on the following monitor-trap exit, exactly like an allow-once
 * rule.  That makes them subject to the same constraint: the leaf is shared by
 * every processor, so a view is only safe while exactly one VCPU is resident.
 * Multi-processor views need per-processor EPT hierarchies, which this
 * protocol version does not provide.
 */
#define KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION 1UL

/* Bound the number of simultaneously installed views. */
#define KSWORD_ARK_HVM_MAX_VIEWS 32UL
/* One view covers exactly one four-KiB page, which is the shadow's size. */
#define KSWORD_ARK_HVM_VIEW_PAGE_BYTES 4096UL

#define KSWORD_ARK_IOCTL_FUNCTION_HVM_VIEW 0x8BBUL
#define IOCTL_KSWORD_ARK_HVM_VIEW \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_VIEW, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_VIEW_OP_ADD    1UL
#define KSWORD_ARK_HVM_VIEW_OP_REMOVE 2UL
#define KSWORD_ARK_HVM_VIEW_OP_CLEAR  3UL
#define KSWORD_ARK_HVM_VIEW_OP_QUERY  4UL

/* Execution sees the real page; reads and writes see the shadow. */
#define KSWORD_ARK_HVM_VIEW_KIND_CLOAK 1UL
/* Reads and writes see the real page; execution runs from the shadow. */
#define KSWORD_ARK_HVM_VIEW_KIND_HOOK  2UL

#define KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED 0x00000001UL
/* Seed the shadow from the target page instead of the supplied bytes. */
#define KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET 0x00000002UL
/* Seed the shadow with zeroes instead of the supplied bytes. */
#define KSWORD_ARK_HVM_VIEW_FLAG_SEED_ZERO 0x00000004UL
/* Record every view flip in the HVM event ring. */
#define KSWORD_ARK_HVM_VIEW_FLAG_LOG 0x00000008UL

#define KSWORD_ARK_HVM_VIEW_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED          3UL
#define KSWORD_ARK_HVM_VIEW_STATUS_NOT_FOUND             4UL
#define KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL            5UL
#define KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED          6UL
/* The page already carries a view or an EPT rule; they cannot share a leaf. */
#define KSWORD_ARK_HVM_VIEW_STATUS_LEAF_CONFLICT         7UL
/* CLOAK needs execute-only EPT leaves, which this processor cannot encode. */
#define KSWORD_ARK_HVM_VIEW_STATUS_EXECUTE_ONLY_UNSUPPORTED 8UL
/* Views flip the shared leaf, so more than one resident VCPU is refused. */
#define KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE 9UL
#define KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED       10UL

typedef struct _KSWORD_ARK_HVM_VIEW_ROW
{
    unsigned long viewId;
    unsigned long kind;
    unsigned long flags;
    unsigned long reserved;
    unsigned long long physicalAddress;
    unsigned long long shadowPhysicalAddress;
    /* Times the leaf flipped to the secondary view since installation. */
    unsigned long long flipCount;
} KSWORD_ARK_HVM_VIEW_ROW;

typedef struct _KSWORD_ARK_HVM_VIEW_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long kind;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long viewId;
    unsigned long expectedGeneration;
    unsigned long long physicalAddress;
    unsigned char shadow[KSWORD_ARK_HVM_VIEW_PAGE_BYTES];
} KSWORD_ARK_HVM_VIEW_REQUEST;

typedef struct _KSWORD_ARK_HVM_VIEW_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long viewId;
    unsigned long viewCount;
    unsigned long generation;
    unsigned long returnedRows;
    unsigned long reserved;
    long lastStatus;
    unsigned long reserved2;
    KSWORD_ARK_HVM_VIEW_ROW rows[KSWORD_ARK_HVM_MAX_VIEWS];
} KSWORD_ARK_HVM_VIEW_RESPONSE;

/*
 * MSR policy.
 *
 * The MSR bitmap installed by P0 passes every MSR through natively, which is
 * what makes residency survivable.  A policy punches a hole in it: the named
 * MSR starts exiting again, and the dispatcher applies the configured action
 * instead of the native access.
 *
 * Writes are deliberately more restricted than reads.  Replaying an arbitrary
 * WRMSR in VMX root would fault on the host IDT with no continuation if the
 * value were illegal, so a write policy can only deny the access or swallow
 * it - never "log it and let it through".  Reads are replayed under structured
 * exception handling and fall back to an injected #GP.
 *
 * Only indices the bitmap actually covers can carry a policy: 0x00000000-
 * 0x00001FFF and 0xC0000000-0xC0001FFF.  Anything outside those ranges exits
 * unconditionally and is handled as an undefined MSR.
 */
#define KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION 1UL

/* Bound the number of simultaneously installed MSR policies. */
#define KSWORD_ARK_HVM_MAX_MSR_POLICIES 64UL

#define KSWORD_ARK_IOCTL_FUNCTION_HVM_MSR_POLICY 0x8BCUL
#define IOCTL_KSWORD_ARK_HVM_MSR_POLICY \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_MSR_POLICY, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_MSR_POLICY_OP_ADD    1UL
#define KSWORD_ARK_HVM_MSR_POLICY_OP_REMOVE 2UL
#define KSWORD_ARK_HVM_MSR_POLICY_OP_CLEAR  3UL
#define KSWORD_ARK_HVM_MSR_POLICY_OP_QUERY  4UL

/* Intercept guest reads of the MSR. */
#define KSWORD_ARK_HVM_MSR_ACCESS_READ  0x00000001UL
/* Intercept guest writes of the MSR. */
#define KSWORD_ARK_HVM_MSR_ACCESS_WRITE 0x00000002UL

/* Record the access and then perform it natively. Reads only. */
#define KSWORD_ARK_HVM_MSR_ACTION_LOG    1UL
/* Refuse the access by injecting #GP, exactly as an undefined index would. */
#define KSWORD_ARK_HVM_MSR_ACTION_DENY   2UL
/* Return the configured value for reads; discard the value for writes. */
#define KSWORD_ARK_HVM_MSR_ACTION_FAKE   3UL

#define KSWORD_ARK_HVM_MSR_POLICY_FLAG_UI_CONFIRMED 0x00000001UL

#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_PREPARED          3UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_FOUND             4UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_TABLE_FULL            5UL
/* The index falls outside the two ranges the architectural bitmap covers. */
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_INDEX_UNCOVERED       6UL
/* A write policy cannot replay the access, so LOG is refused for writes. */
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_WRITE_LOG_UNSAFE      7UL
/* Policies edit the shared bitmap, so they are refused while resident. */
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_RESIDENT_BUSY         8UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_DUPLICATE             9UL

typedef struct _KSWORD_ARK_HVM_MSR_POLICY_ROW
{
    unsigned long policyId;
    unsigned long msrIndex;
    unsigned long access;
    unsigned long action;
    unsigned long long fakeValue;
    /* Times the dispatcher applied this policy since installation. */
    unsigned long long hitCount;
} KSWORD_ARK_HVM_MSR_POLICY_ROW;

typedef struct _KSWORD_ARK_HVM_MSR_POLICY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long policyId;
    unsigned long msrIndex;
    unsigned long access;
    unsigned long action;
    unsigned long expectedGeneration;
    unsigned long long fakeValue;
} KSWORD_ARK_HVM_MSR_POLICY_REQUEST;

typedef struct _KSWORD_ARK_HVM_MSR_POLICY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long policyId;
    unsigned long policyCount;
    unsigned long returnedRows;
    unsigned long generation;
    unsigned long reserved;
    long lastStatus;
    unsigned long reserved2;
    KSWORD_ARK_HVM_MSR_POLICY_ROW rows[KSWORD_ARK_HVM_MAX_MSR_POLICIES];
} KSWORD_ARK_HVM_MSR_POLICY_RESPONSE;

/*
 * Control- and debug-register policy.
 *
 * CR0 and CR4 protection works through the VMCS guest/host masks: a masked bit
 * is owned by the hypervisor, the guest reads it from a shadow, and any attempt
 * to change it exits.  That is how CR0.WP or CR4.SMEP can be pinned against a
 * rootkit that would otherwise just clear them.
 *
 * CR3-load exiting is the only way to observe every address-space switch, and
 * it is also the most expensive control in this protocol: Windows switches CR3
 * thousands of times per second, and each switch becomes a VM exit.  It is off
 * by default and the UI says what it costs.
 *
 * Like MSR policy and EPT views, this configuration is consumed when the VMCS
 * is built, so it must be set before residency starts.
 */
#define KSWORD_ARK_HVM_CR_POLICY_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_HVM_CR_POLICY 0x8BDUL
#define IOCTL_KSWORD_ARK_HVM_CR_POLICY \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_CR_POLICY, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_CR_POLICY_OP_SET   1UL
#define KSWORD_ARK_HVM_CR_POLICY_OP_CLEAR 2UL
#define KSWORD_ARK_HVM_CR_POLICY_OP_QUERY 3UL

#define KSWORD_ARK_HVM_CR_POLICY_FLAG_UI_CONFIRMED 0x00000001UL
/*
 * Observe every address-space switch.  Expensive: each CR3 load becomes a VM
 * exit, and Windows performs thousands per second.
 */
#define KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3 0x00000002UL
/* Intercept guest access to the debug registers. */
#define KSWORD_ARK_HVM_CR_POLICY_FLAG_INTERCEPT_DR 0x00000004UL
/* Record every intercepted control-register access in the event ring. */
#define KSWORD_ARK_HVM_CR_POLICY_FLAG_LOG 0x00000008UL

#define KSWORD_ARK_HVM_CR_POLICY_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_CR_POLICY_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_CR_POLICY_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_CR_POLICY_STATUS_NOT_PREPARED          3UL
/* The masks are consumed when the VMCS is built, so residency blocks changes. */
#define KSWORD_ARK_HVM_CR_POLICY_STATUS_RESIDENT_BUSY         4UL
/* A pinned bit must be one the fixed-bit MSRs allow the guest to hold. */
#define KSWORD_ARK_HVM_CR_POLICY_STATUS_BIT_NOT_PINNABLE      5UL

typedef struct _KSWORD_ARK_HVM_CR_POLICY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    /* Bits the guest must not change; it reads them from the shadow. */
    unsigned long long cr0PinnedMask;
    unsigned long long cr4PinnedMask;
} KSWORD_ARK_HVM_CR_POLICY_REQUEST;

typedef struct _KSWORD_ARK_HVM_CR_POLICY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long flags;
    unsigned long generation;
    unsigned long reserved;
    unsigned long long cr0PinnedMask;
    unsigned long long cr4PinnedMask;
    /* Value each pinned register held when the policy was installed. */
    unsigned long long cr0PinnedValue;
    unsigned long long cr4PinnedValue;
    /* Times a guest write to a pinned bit was refused. */
    unsigned long long refusedWriteCount;
    /* Times an address-space switch was observed. */
    unsigned long long cr3SwitchCount;
    /* Times debug-register access was intercepted. */
    unsigned long long debugAccessCount;
    long lastStatus;
    unsigned long reserved2;
} KSWORD_ARK_HVM_CR_POLICY_RESPONSE;

/*
 * EPT execution domains.
 *
 * A domain is a fork of the default identity view, published in the EPTP list
 * so guest code can switch onto it with one VMFUNC.  That last part is the
 * whole design constraint: VMFUNC performs no CPL check, so every domain in
 * the list is reachable by unprivileged code in any process, without a VM exit
 * and without the driver being notified.
 *
 * The interface therefore offers exactly one editing direction.  A domain is
 * born byte-for-byte identical to the default view and can only have
 * permissions REMOVED.  There is no operation that grants anything, so a
 * thread that switches into a domain can never end up with access it did not
 * already have - the worst it can do to itself is take an EPT violation.
 *
 * Domains are also inert until residency is started with ENABLE_VMFUNC.
 * Building the list costs a page and changes nothing on its own.
 */
#define KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION 1UL

/* Bound the domains a caller may enumerate in one response. */
#define KSWORD_ARK_HVM_MAX_DOMAIN_ROWS 8UL

/*
 * 只读平台探针。
 *
 * 存在的理由很窄：有三个量各自能独立否决"让退虚拟化返回用户态"这条路，
 * 而仓库里从没记录过它们在靶机上的实测值 —— CR4.CET（影子栈开着的话
 * ring-3 的 IRET 有自己的协议，`IA32_U_CET`/`IA32_PL3_SSP` 都不是 VMCS 字段）、
 * KVA shadow（开着的话用户态退出时 GUEST_CR3 是用户影子 PML4，
 * VMXOFF 之后写回去等于把内核抹掉）、以及 GS base 到底是不是我们以为的东西。
 *
 * 这个 IOCTL **只读**：不进 VMX、不改任何执行路径、不分配、不加锁。
 * 每个值都配一个"读到了没"的位，因为 0 恰好是很多东西的合法值 ——
 * 一个读失败被当成 0 用出去，比读不到更糟。
 */
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_PLATFORM 0x8BFUL
#define IOCTL_KSWORD_ARK_HVM_PLATFORM \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_PLATFORM, METHOD_BUFFERED, FILE_READ_ACCESS)

#define KSWORD_ARK_HVM_PLATFORM_PROTOCOL_VERSION 1UL

/* 每个 valid 位对应一个字段读成功；一位一个字段，不设总开关。 */
#define KSWORD_ARK_HVM_PLATFORM_VALID_CR4        0x00000001UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_S_CET      0x00000002UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_U_CET      0x00000004UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_FS_BASE    0x00000008UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_GS_BASE    0x00000010UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_KERNEL_GS  0x00000020UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_CPUID7     0x00000040UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_EFER       0x00000080UL
/* 八项全读到才算标定完成；少一项这一轮就没有达成它存在的目的。 */
#define KSW_PLATFORM_VALID_ALL                   0x000000FFUL

typedef struct _KSWORD_ARK_HVM_PLATFORM_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_HVM_PLATFORM_REQUEST;

typedef struct _KSWORD_ARK_HVM_PLATFORM_RESPONSE
{
    unsigned long version;
    unsigned long size;
    /* 哪些字段真的读到了。见 KSWORD_ARK_HVM_PLATFORM_VALID_*。 */
    unsigned long validMask;
    /* 读某个字段时抛出的异常码；没抛就是 0。 */
    unsigned long exceptionCode;
    /* CR4；bit23 = CET。 */
    unsigned long long cr4;
    /* IA32_S_CET (0x6A2)：内核影子栈控制。 */
    unsigned long long supervisorCet;
    /* IA32_U_CET (0x6A0)：用户影子栈控制。 */
    unsigned long long userCet;
    /* IA32_FS_BASE (0xC0000100)。 */
    unsigned long long fsBase;
    /* IA32_GS_BASE (0xC0000101)：内核态下应当是 KPCR。 */
    unsigned long long gsBase;
    /* IA32_KERNEL_GS_BASE (0xC0000102)：内核态下应当是用户 TEB。 */
    unsigned long long kernelGsBase;
    /* IA32_EFER (0xC0000080)。 */
    unsigned long long efer;
    /* CPUID.(EAX=7,ECX=0)：ECX bit7 = CET_SS，EDX bit20 = CET_IBT。 */
    unsigned long cpuid7Ecx;
    unsigned long cpuid7Edx;
    /* 采样时的 IRQL，用来确认这确实是 PASSIVE_LEVEL 的读数。 */
    unsigned long irql;
    unsigned long reserved2;
} KSWORD_ARK_HVM_PLATFORM_RESPONSE;

#define KSWORD_ARK_IOCTL_FUNCTION_HVM_DOMAIN 0x8BEUL
#define IOCTL_KSWORD_ARK_HVM_DOMAIN \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_DOMAIN, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* Fork one domain from the default view. */
#define KSWORD_ARK_HVM_DOMAIN_OP_CREATE   1UL
/* Remove permissions from one physical range inside one domain. */
#define KSWORD_ARK_HVM_DOMAIN_OP_RESTRICT 2UL
/* Release every domain and unpublish the whole list. */
#define KSWORD_ARK_HVM_DOMAIN_OP_RESET    3UL
/* Report the current domains without changing anything. */
#define KSWORD_ARK_HVM_DOMAIN_OP_QUERY    4UL

#define KSWORD_ARK_HVM_DOMAIN_FLAG_UI_CONFIRMED 0x00000001UL

#define KSWORD_ARK_HVM_DOMAIN_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_PREPARED          3UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_FOUND             4UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_TABLE_FULL            5UL
/* Denying read requires execute-only translation the processor lacks. */
#define KSWORD_ARK_HVM_DOMAIN_STATUS_EXECUTE_ONLY_UNSUPPORTED 6UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED       7UL
/* The processor does not offer EPTP switching, so a list would be inert. */
#define KSWORD_ARK_HVM_DOMAIN_STATUS_UNSUPPORTED           8UL
/* Domains cannot be edited while residency holds the tables live. */
#define KSWORD_ARK_HVM_DOMAIN_STATUS_RESIDENT_ACTIVE       9UL

typedef struct _KSWORD_ARK_HVM_DOMAIN_ROW
{
    unsigned long domainIndex;
    /* Nonzero when the slot holds a live domain. */
    unsigned long active;
    /* Paging structures this domain forked away from the shared hierarchy. */
    unsigned long privateTableCount;
    unsigned long reserved;
    /* EPT pointer published in the list slot; zero when the slot is unused. */
    unsigned long long eptPointer;
} KSWORD_ARK_HVM_DOMAIN_ROW;

typedef struct _KSWORD_ARK_HVM_DOMAIN_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    unsigned long domainIndex;
    /* Permissions to remove, using the EPT_ACCESS bits. */
    unsigned long deniedAccess;
    unsigned long long physicalAddress;
    unsigned long long byteCount;
} KSWORD_ARK_HVM_DOMAIN_REQUEST;

typedef struct _KSWORD_ARK_HVM_DOMAIN_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long domainIndex;
    unsigned long domainCount;
    unsigned long generation;
    unsigned long returnedRows;
    unsigned long reserved;
    long lastStatus;
    unsigned long reserved2;
    unsigned long long featureFlags;
    unsigned long long stateFlags;
    KSWORD_ARK_HVM_DOMAIN_ROW rows[KSWORD_ARK_HVM_MAX_DOMAIN_ROWS];
} KSWORD_ARK_HVM_DOMAIN_RESPONSE;

/*
 * R-1 层的进程处置。
 *
 * 名字里的"进程"要小心读：hypervisor 不认识进程，它只看得见 CR3 与客户物理页。
 * 这条通路做的事是——**在目标地址空间里拒绝执行**，再决定拒绝时给客户机什么。
 * 两个操作的差别只在注入哪个向量：
 *
 *   冻结  注入 #PF(present=1)。故障指令永不退休，进程状态一个字节都没变，
 *         撤掉规则它就从原地继续。这是真正意义上的挂起——**可逆**是它与
 *         结束的本质区别，而不是程度差别。代价明写在这里：被冻结的线程会在
 *         故障上自旋，占着自己的时间片；机器不会挂，但那个核在空转。
 *   结束  注入 #UD。用户态未处理异常，Windows 走它自己的进程拆除路径。
 *         我们不调用任何内核 API，进程是被客户机自己收掉的。
 *
 * 作用域靠 CR3 而不是逐页判权限：常驻打开 CR3-load exiting，地址空间切进来时
 * 选受限层次、切出去时选基础层次。这样非目标进程从来不在受限层次下运行，
 * 也就不存在"拒绝一次再放行一次"那套需要 MTF 的翻转——嵌套靶机上没有 MTF，
 * 走逐页判权限这条路在那里根本跑不起来。
 *
 * **这不是安全边界。** 与隐蔽 Hook 同源的性质：失败即放行。目标进程若能让
 * 自己的代码页换一个客户物理页（重定位、自改写、换映射），它就不在被拒绝的
 * 那一页上了；能改 CR3 的代码也不受本机制约束。它是一条 R0 之外的处置通路，
 * 用来在内核 API 被挡住时仍然能动手，不是用来对抗一个知道它存在的对手。
 */
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_PROCESS 0x90FUL
#define IOCTL_KSWORD_ARK_HVM_PROCESS \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_PROCESS, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/*
 * 版本 2 加入 CR3 归因（OP_RESOLVE_CR3）。
 *
 * 请求与响应都长了，所以版本必须跟着动：旧界面配新驱动会因为 size 对不上被
 * 当场拒掉，而那正是想要的结果 —— 这两个结构里装的是进程身份，一次"谁多谁少
 * 几个字节"的静默误读，换来的是把一次访问归到另一个进程头上。
 */
#define KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION 2UL

/* 只读当前处置表。 */
#define KSWORD_ARK_HVM_PROCESS_OP_QUERY     0UL
/* 冻结：拒绝执行 + 注入 #PF，可逆。 */
#define KSWORD_ARK_HVM_PROCESS_OP_FREEZE    1UL
/* 结束：拒绝执行 + 注入 #UD，不可逆。 */
#define KSWORD_ARK_HVM_PROCESS_OP_TERMINATE 2UL
/*
 * 撤销一条处置。
 *
 * 常驻停着时是完整撤销：清记录、放层次。常驻期间是**解除**：记录留着、层次也
 * 留着，但不再有人会切进去，而已经卡在受限层次里自旋的那个核会在自己的下一次
 * 违规上把 EPT_POINTER 换回基座、继续执行。
 *
 * 分两种不是保守：常驻期间真把层次的页放掉，而某个核此刻正指着它，那是没有任何
 * 症状可循的内存破坏。而只清记录不管正在自旋的核，被冻结的线程会永远冻着——
 * 于是"解除冻结"要求先关掉整个 hypervisor，那样它就只是半个功能。
 */
#define KSWORD_ARK_HVM_PROCESS_OP_RELEASE   3UL
/*
 * 已解除但层次还没回收。只会出现在常驻期间被撤销的记录上。
 *
 * 作为一个显式状态而不是直接清掉记录：退出路径要靠"这一页属于一条已解除的
 * 处置"才知道该把指针换回基座，记录一清它就什么都不知道了。
 */
#define KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED 3UL
/* 清空整张表。 */
#define KSWORD_ARK_HVM_PROCESS_OP_RELEASE_ALL 4UL
/*
 * 把一个观测到的 CR3 归到一个进程头上。只读，不碰任何 HVM 状态。
 *
 * 存在的理由是内存监视：命中现场记下来的是 CR3，而 CR3 本身对用户没有意义。
 * 但这件事**只能在驱动里做**——判据是"attach 进去读回来的那个寄存器值"，
 * 用户态既读不到别的进程的 CR3，也没有别的办法得到同一个判据。
 *
 * 这条通路不回报任何进程的 CR3，只回报"哪个 PID 的 CR3 等于你给的这个"。
 * 方向是单向的：调用方必须先有一个 CR3 才问得出东西来，而 CR3 的唯一来源是
 * 一次它自己装的监视命中。
 *
 * 结果一定是 best-effort，§十一列的每一条都成立：PID 会被回收、地址空间会在
 * 事件与解析之间消失、内核工作线程借用别人的地址空间跑、KVA Shadow 下用户态
 * 与内核态用的根本不是同一个 CR3。所以协议只回报"扫了多少个"与"匹配到谁"，
 * 由界面把它标成推断而不是事实。
 */
#define KSWORD_ARK_HVM_PROCESS_OP_RESOLVE_CR3 5UL

#define KSWORD_ARK_HVM_PROCESS_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_CONFIRMATION_REQUIRED 2UL
/*
 * 常驻正在跑，而安装要求它停着。
 *
 * 占 3 号不是随意的：这个码原先叫 NOT_RESIDENT，两种条件共用，而实际发生的
 * 几乎总是这一种（常驻起来之后才想起来处置某个进程）。把它留在 3 号，新界面
 * 配旧驱动时给出的建议仍然是对的；反过来编号，那段窗口里界面会说"还没
 * prepare"——与实情正好相反，照着做只会越走越远。
 */
#define KSWORD_ARK_HVM_PROCESS_STATUS_REQUIRES_RESIDENT_STOPPED 3UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_PROCESS_LOOKUP_FAILED 4UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_TABLE_FULL            5UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND             6UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_ALREADY_ARMED         7UL
/*
 * 缺 CR3-load exiting。作用域完全依赖它：没有它就没法知道哪个地址空间正在跑，
 * 拒绝就会落到全机器而不是一个进程头上——那是必须拒绝执行的情形，不是降级。
 */
#define KSWORD_ARK_HVM_PROCESS_STATUS_CR3_TRACKING_REQUIRED 8UL
/* 缺 EPTP 切换后端；没有第二个层次就没有"受限"可选。 */
#define KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED  9UL
/* 目标地址空间里那一页翻译不出客户物理地址。 */
#define KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED    10UL
/* 拒绝对自己或系统进程动手。 */
#define KSWORD_ARK_HVM_PROCESS_STATUS_PROTECTED_TARGET      11UL
/*
 * 驱动还没 prepare 过，运行时里什么都没有。
 *
 * 与上面那个分成两个码，是因为它们要人做的事**相反**：一个是"还没起来，先
 * prepare"，一个是"正在跑，先停下"。原先合用一个叫 NOT_RESIDENT 的码更糟——
 * 那个名字描述的条件恰恰是实际条件的反面，照着它排查会一路走反方向。
 */
#define KSWORD_ARK_HVM_PROCESS_STATUS_NOT_PREPARED          12UL

/* 表的上限。每条占一个 EPT 受限层次，层次数由 EPTP 列表容量决定。 */
#define KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS 8UL

typedef struct _KSWORD_ARK_HVM_PROCESS_ROW
{
    /* 下达处置时的 PID。PID 会被回收，所以判据是 directoryBase 不是它。 */
    unsigned long processId;
    /* 本条的处置类型，取 OP_FREEZE / OP_TERMINATE。 */
    unsigned long disposition;
    /* 目标地址空间。低位的 PCID/标志已经掩掉，只留层次物理页帧。 */
    unsigned long long directoryBase;
    /* 被拒绝执行的那一页的客户物理地址。 */
    unsigned long long guestPhysicalAddress;
    /* 下达时给的客户线性地址，用来回溯这一页是怎么选出来的。 */
    unsigned long long guestLinearAddress;
    /* 本条已经拦下多少次执行。冻结下会持续增长，那正是自旋的证据。 */
    unsigned long long interceptCount;
    /* 本条占用的受限层次序号。 */
    unsigned long hierarchyIndex;
    unsigned long reserved;
} KSWORD_ARK_HVM_PROCESS_ROW;

typedef struct _KSWORD_ARK_HVM_PROCESS_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long processId;
    /*
     * 要拒绝执行的客户线性地址。给 0 表示由驱动取该进程主映像的入口页。
     *
     * 允许调用方指定是因为"哪一页代表这个进程"没有普适答案：入口页对刚起来的
     * 进程有效，对已经跑进消息循环的进程则未必会再被执行到，而没被执行到的
     * 拒绝等于什么都没做。
     */
    unsigned long long guestLinearAddress;
    /*
     * OP_RESOLVE_CR3 要归因的那个 CR3。其余操作必须留零。
     *
     * 单独一个字段而不是借 guestLinearAddress：那个字段在别的操作里是线性
     * 地址，两者都是 64 位、都像地址、互相传错了谁也不会报错——一个指望拿
     * 页目录基址的比较会安静地永远不匹配，看起来就像"这个进程已经退出了"。
     */
    unsigned long long directoryBase;
} KSWORD_ARK_HVM_PROCESS_REQUEST;

typedef struct _KSWORD_ARK_HVM_PROCESS_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long returnedRows;
    unsigned long rowCount;
    unsigned long generation;
    long lastStatus;
    unsigned long reserved;
    unsigned long long stateFlags;
    KSWORD_ARK_HVM_PROCESS_ROW rows[KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS];
    /*
     * OP_RESOLVE_CR3 的结果。放在 rows 后面，所以前面每个字段的偏移都没动。
     *
     * resolvedProcessId 为 0 表示没有匹配上（0 是 Idle 进程，永远不会是答案）。
     */
    unsigned long resolvedProcessId;
    /*
     * 这次实际问过 CR3 的进程数。
     *
     * 必须和"匹配到谁"分开回报，否则"扫了 180 个都不是它"与"一个都没扫成"
     * 在界面上长得一模一样，而这两者要人做的事相反：前者说明那个地址空间已经
     * 不在了，后者说明这次归因根本没跑起来。
     */
    unsigned long resolvedScannedProcesses;
} KSWORD_ARK_HVM_PROCESS_RESPONSE;

/*
 * R-1 层的进程注入。
 *
 * 与 R0 那条注入（ZwAllocateVirtualMemory + ZwCreateThreadEx，见
 * process_inject.c）是**两条不同的通路**，不是同一件事换个标签：R0 那条的每一
 * 步都要调内核 API，每一步都能被进程/线程创建回调、镜像加载回调、PatchGuard
 * 与 EDR 看见；这一条一个内核 API 都不调，目标进程里也不会多出线程或内存区域。
 *
 * 机制是**分离视图 + 线程劫持**，四步：
 *
 *   1. 选目标地址空间里一页已经可执行、且会被执行到的页；
 *   2. 建一张影子页 = 真页的完整副本 + 载荷写进它的空隙（节尾填充、code cave）；
 *   3. 装一张 KIND_HOOK 视图：**读写看真页，执行跑影子**。载荷因此只存在于
 *      执行视图里——任何读这一页的东西（完整性校验、内存转储、进程自查）看到
 *      的都是未改动的原始字节；
 *   4. 在一次受控的 VM exit 上把 RIP 指向影子里载荷的位置，载荷执行完跳回原
 *      来那条指令。
 *
 * **不新建映射，也不改客户页表。** 那条路会和 Windows 的内存管理器竞争同一份
 * 页表：我们塞进去的 PTE 随时可能被回收，而回收发生在我们看不见的地方，症状是
 * 目标在某个不确定的时刻崩掉。写进已有可执行页的空隙则不碰任何管理结构。
 *
 * ## 载荷的硬约束
 *
 * 载荷跑在**一个任意线程的任意指令边界上**——不是新线程，是把某个正在跑的线程
 * 借用一小段时间。这不是实现偷懒，是这条通路的本质：R-1 没有"创建线程"这个
 * 概念，它只能在已有的执行流里插队。由此：
 *
 *   - 必须位置无关，必须可重入，必须短。被借用的线程可能正持有锁、正在系统调用
 *     的中途；在里面做任何会阻塞或会重入同一把锁的事都会死锁；
 *   - 不要用 ret 返回。这台机器上 CET 影子栈是开着的，由 hypervisor 压进去的
 *     返回地址与影子栈对不上，会直接吃一个 #CP。驱动自己包的外壳用绝对跳转
 *     回去，不走 ret；
 *   - 寄存器与标志位由驱动包的外壳负责保存和恢复，载荷本体不必自己做，但也
 *     **不能**假设外壳之外还有别的保护。
 *
 * ## 这不是隐蔽性保证
 *
 * 与隐蔽 Hook 同源的性质：执行视图能被同样的手段拆掉（见隐蔽Hook安全边界决策）。
 * 它躲开的是"读这一页"这类检查，不是一个知道这套机制存在的对手。
 */
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_INJECT 0x910UL
#define IOCTL_KSWORD_ARK_HVM_INJECT \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_INJECT, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION 1UL

/* 只读当前注入表。 */
#define KSWORD_ARK_HVM_INJECT_OP_QUERY   0UL
/* 装一次注入：建影子、装视图、武装触发。 */
#define KSWORD_ARK_HVM_INJECT_OP_ARM     1UL
/* 撤销一条：摘视图、解除触发。已经执行过的载荷不会被撤回。 */
#define KSWORD_ARK_HVM_INJECT_OP_RELEASE 2UL
/* 清空整张表。 */
#define KSWORD_ARK_HVM_INJECT_OP_RELEASE_ALL 3UL

/*
 * 载荷本体的上限。
 *
 * 影子只有一页，而外壳（保存/恢复寄存器与标志位、绝对跳转回去）要占掉几十字节，
 * 页里还得留下真页原有的内容不动——能用的只有空隙。给 1024 而不是"剩下多少算
 * 多少"：一个会随目标页内容浮动的上限，会让同一份载荷在这个进程装得上、在那个
 * 进程装不上，而失败原因看起来与载荷无关。
 */
#define KSWORD_ARK_HVM_INJECT_MAX_PAYLOAD_BYTES 1024UL

/*
 * 两种载荷，与 R0 那条注入保持同样的分法。
 *
 * SHELLCODE 是这条通路的原语：一段位置无关的机器码，跑在被借用的线程上。
 * DLL_PATH 是它上面的一层：外壳把路径地址放进 RCX，再 call 调用方给出的
 * LoadLibraryW。分成两种而不是只留 shellcode，是因为"注入一个 DLL"是实际要做
 * 的事，而让每个调用方自己拼一段调用 LoadLibraryW 的机器码，等于把同一段容易
 * 出错的代码复制很多份。
 */
#define KSWORD_ARK_HVM_INJECT_TYPE_SHELLCODE 1UL
#define KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH  2UL

/*
 * 空隙至少要这么长才认。
 *
 * 太短的"空隙"多半不是填充而是真代码里恰好连续的零字节，写进去就是把目标打死。
 */
#define KSWORD_ARK_HVM_INJECT_MIN_CAVE_BYTES 64UL

#define KSWORD_ARK_HVM_INJECT_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_INJECT_STATUS_NOT_PREPARED          2UL
#define KSWORD_ARK_HVM_INJECT_STATUS_REQUIRES_RESIDENT_STOPPED 3UL
#define KSWORD_ARK_HVM_INJECT_STATUS_PROCESS_LOOKUP_FAILED 4UL
#define KSWORD_ARK_HVM_INJECT_STATUS_TRANSLATION_FAILED    5UL
#define KSWORD_ARK_HVM_INJECT_STATUS_TABLE_FULL            6UL
#define KSWORD_ARK_HVM_INJECT_STATUS_NOT_FOUND             7UL
#define KSWORD_ARK_HVM_INJECT_STATUS_ALREADY_ARMED         8UL
#define KSWORD_ARK_HVM_INJECT_STATUS_PROTECTED_TARGET      9UL
/* 前提：作用域靠 CR3-load exiting，缺了拒绝落到全机器而不是一个进程头上。 */
#define KSWORD_ARK_HVM_INJECT_STATUS_CR3_TRACKING_REQUIRED 10UL
/* 前提：执行视图与受限层次都由 EPTP 切换后端提供。 */
#define KSWORD_ARK_HVM_INJECT_STATUS_EPTP_SWITCH_REQUIRED  11UL
/* 这一页里找不到足够长的空隙来放外壳加载荷。 */
#define KSWORD_ARK_HVM_INJECT_STATUS_NO_CAVE               12UL
/* 装执行视图失败。 */
#define KSWORD_ARK_HVM_INJECT_STATUS_VIEW_FAILED           13UL
/* 目标页不可执行——把载荷放在一页永远不会被执行的地方等于什么都没做。 */
#define KSWORD_ARK_HVM_INJECT_STATUS_PAGE_NOT_EXECUTABLE   14UL

#define KSWORD_ARK_HVM_MAX_INJECTIONS 4UL

typedef struct _KSWORD_ARK_HVM_INJECT_ROW
{
    /* 下达时的 PID。PID 会被回收，判据是 directoryBase。 */
    unsigned long processId;
    /* 载荷本体长度。 */
    unsigned long payloadBytes;
    /* 目标地址空间，低位的 PCID 与标志已掩掉。 */
    unsigned long long directoryBase;
    /* 被劫持那一页的客户线性地址（页对齐）。 */
    unsigned long long guestLinearAddress;
    /* 该页的客户物理地址。 */
    unsigned long long guestPhysicalAddress;
    /* 外壳在页内的偏移，也就是 RIP 会被指向的位置。 */
    unsigned long caveOffset;
    /* 外壳加载荷占掉的总字节数。 */
    unsigned long caveBytes;
    /* 载荷已经被执行了多少次。一次性注入完成后应为 1。 */
    unsigned long long executionCount;
    /* 这次注入占用的执行视图标识。 */
    unsigned long viewId;
    /*
     * 这段空隙是由哪种填充字节构成的：0x00 / 0xCC / 0x90。
     *
     * 回报它是为了归因：0xCC 与 0x90 是编译器在函数之间放的对齐填充，0x00 多半
     * 是节尾或未初始化区域。出问题时"用的是哪一种"决定了该怀疑什么——比如在
     * 一段本该是填充的 0xCC 上出事，要查的是那里是不是其实嵌着数据。
     */
    unsigned long caveFiller;
} KSWORD_ARK_HVM_INJECT_ROW;

typedef struct _KSWORD_ARK_HVM_INJECT_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long processId;
    /*
     * 要劫持的那一页里的任意一个客户线性地址。**必填**。
     *
     * 驱动不猜这一页。"哪一页会被执行到"没有普适答案，而猜错的表现是载荷装上了
     * 却永远不执行——从外面看和成功完全一样。调用方能答得比驱动好：取目标某个
     * 线程此刻正在执行的位置，那一页**按定义**会被执行到。
     *
     * 驱动侧拿不到这个答案：用户态 RIP 要从线程的陷阱帧里取，而那是调用方在
     * PASSIVE 上下文里顺手能做、驱动要绕一大圈的事。
     */
    unsigned long long guestLinearAddress;
    /* 见 KSWORD_ARK_HVM_INJECT_TYPE_*。 */
    unsigned long injectType;
    /* 载荷本体长度，不含驱动包的外壳。 */
    unsigned long payloadBytes;
    /*
     * DLL 类型专用：目标进程里 LoadLibraryW 的客户线性地址。
     *
     * 由调用方解析而不是驱动：同一个 DLL 在不同进程里的基址不同，而调用方本来
     * 就在枚举目标的模块表。驱动去解析等于把同一件事做第二遍，还容易与调用方
     * 看到的不一致。
     */
    unsigned long long loadLibraryAddress;
    /*
     * 载荷本体。
     *
     * SHELLCODE：位置无关、可重入的机器码，寄存器与标志位由外壳保存恢复。
     * DLL_PATH：以零结尾的 UTF-16 路径，外壳会把它的地址放进 RCX 再 call
     *           loadLibraryAddress。这里的 call 与它自己的 ret 是配对的，
     *           因此不会踩 CET 影子栈——只有"压一个没有对应 call 的返回地址"
     *           才会。
     */
    unsigned char payload[KSWORD_ARK_HVM_INJECT_MAX_PAYLOAD_BYTES];
} KSWORD_ARK_HVM_INJECT_REQUEST;

typedef struct _KSWORD_ARK_HVM_INJECT_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long returnedRows;
    unsigned long rowCount;
    unsigned long generation;
    long lastStatus;
    unsigned long reserved;
    unsigned long long stateFlags;
    KSWORD_ARK_HVM_INJECT_ROW rows[KSWORD_ARK_HVM_MAX_INJECTIONS];
} KSWORD_ARK_HVM_INJECT_RESPONSE;

/*
 * 嵌套 VMX 自检。
 *
 * ## 为什么必须在驱动里做
 *
 * VMX 指令只能在 CPL 0 执行，所以这一段无法像 probe-xonly 那样在工具里用现成
 * IOCTL 组合出来。而它要验的恰恰是"客户机执行 VMX 指令时，我们的嵌套派发有没有
 * 按架构语义服务它" —— 那就需要有人在**客户机上下文**里真的执行一次。
 *
 * 驱动自己来做这件事并不矛盾：驱动的 L0 部分跑在 VMX root，而这条 IOCTL 路径跑
 * 在客户机里。客户机执行 VMXON 必定产生 VM 退出，退出落到我们自己的派发上 ——
 * 这正是被测对象。
 *
 * ## 前提是硬的
 *
 * 嵌套派发没开时，`KswordARKHvmNestedHandleExit` 返回不处理，退出路径会注 #UD ——
 * 而那个 #UD 落在**我们自己的内核代码**上，直接蓝屏。所以这条命令在嵌套未启用或
 * 本处理器未常驻时必须拒绝，而不是"试试看"。
 *
 * 同理，CR4.VMXE 没能置上就执行 VMXON 会吃 #UD。必须回读确认之后才往下走。
 */
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_NESTED_PROBE 0x911UL
#define IOCTL_KSWORD_ARK_HVM_NESTED_PROBE \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_NESTED_PROBE, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_NESTED_PROBE_PROTOCOL_VERSION 1UL

/* 整段自检成功完成（每一步的结果仍要逐条看）。 */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_OK 0UL
/* 请求本身不合契约。 */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_INVALID_REQUEST 1UL
/* 缺 UI_CONFIRMED。 */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_CONFIRMATION_REQUIRED 2UL
/* 本处理器没有常驻，或嵌套派发没开——执行下去会把自己打死。 */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NOT_ARMED 3UL
/* 自检要用的两页分配不出来。 */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NO_RESOURCES 4UL
/* CR4.VMXE 置不上，后续每一步都不执行。 */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_VMXE_REFUSED 5UL
/* A required VMCS12 configuration write failed; L2 was not entered. */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_CONFIGURATION_FAILED 6UL

/* 这一步根本没有执行到。 */
#define KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED 3UL

/*
 * 在**每个**处理器上并发跑一遍，而不是只在当前这个上跑一遍。
 *
 * 单核跑通不能推出多核跑通：每核有自己的 vmcs02、影子层次与映射窗口，它们**结构上**
 * 互不干涉 —— 而这个仓库里"结构上互不干涉"已经栽过不止一次（共享 EPT 根的陈旧标签、
 * fail-closed 只停下一个核）。并发是唯一能把这句话变成读数的办法。
 */
#define KSWORD_ARK_HVM_NESTED_PROBE_FLAG_ALL_PROCESSORS 0x00010000UL
/*
 * 让探针的 L1 在 EPT12 指针里请求 accessed/dirty 位，用来验证**拒绝**。
 *
 * 这是一条负向用例：A/D 必须被挡在影子层次武装的那一步，而不是放行之后由
 * 硬件把位置在我们的影子叶上、让 L1 读回自己的 EPT12 发现全是零。后者没有
 * 任何读数会变，而 L1 会据此跳过它的来宾真正改过的页。
 *
 * 期望结果是 VMLAUNCH 拿到 Intel 错误 7（控制字段非法），且「L2 跑过」为否。
 */
#define KSWORD_ARK_HVM_NESTED_PROBE_FLAG_REQUEST_AD 0x00020000UL
/*
 * 让 L1 虚拟化**正在跑的这个上下文**，而不是一页玩具代码。
 *
 * 这是"能不能托住一个真 hypervisor"与"能不能托住我们写的那个 L2 小程序"之间的
 * 分界线。真 hypervisor（我们自己的常驻路径、VMware 的 VMM）做的都是同一件事：
 * 捕获当前处理器状态、把 vmcs 的 guest RIP 指回自己紧接着的那条指令、VMLAUNCH，
 * 于是**它自己**变成了来宾。玩具 L2 用的是合成的 RIP、合成的栈和一页恒等映射的
 * 代码，段/CR3/页表全都不必当真。
 *
 * 单独一个 flag 而不是替换原来的 L2：MSR 路由那条判据依赖 L2 程序里确定的指令
 * 偏移，换掉它等于把一条已经绿的、来之不易的判据拆掉去换一条新的。
 */
#define KSWORD_ARK_HVM_NESTED_PROBE_FLAG_SELF_VIRTUALIZE 0x00040000UL

/*
 * L2 那段程序里三个有意义的停靠点，按距代码页起点的字节偏移。
 *
 * 放在协议头里而不是各自写死，是因为**一边造程序、另一边判结果**：驱动按这些
 * 偏移排指令，工具按同样的偏移判读 `l2RipOffset`。分开写的话，哪天程序的编码
 * 改一个字节，判据不会报错，只会开始判错。
 *
 *   TRAPPED  = 第二条 RDMSR。停这儿说明处理器查的确实是 L1 那张位图。
 *   OPEN     = 第一条 RDMSR。本该放行却停这儿，说明查的是"全部拦截"的回退页。
 *   FALLBACK = CPUID。走到这儿说明 MSR 拦截根本没发生。
 */
#define KSWORD_ARK_HVM_NESTED_PROBE_RIP_OPEN_MSR 5ULL
#define KSWORD_ARK_HVM_NESTED_PROBE_RIP_TRAPPED_MSR 12ULL
#define KSWORD_ARK_HVM_NESTED_PROBE_RIP_CPUID 14ULL

/* 逐核结果的行数上限。 */
#define KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS 64UL

typedef struct _KSWORD_ARK_HVM_NESTED_PROBE_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long confirmationToken;
} KSWORD_ARK_HVM_NESTED_PROBE_REQUEST;

/* 一个处理器上一次完整自检的全部读数。 */
typedef struct _KSWORD_ARK_HVM_NESTED_PROBE_ROW
{
    unsigned long status;
    unsigned long processorIndex;
    /*
     * 每一步的架构结果：0=成功，1=VMfailValid，2=VMfailInvalid，3=没执行到。
     *
     * 用架构值而不是布尔，是因为"失败"分两种而它们含义不同：VMfailValid 说明
     * 我们认下了这条指令并给了错误号，VMfailInvalid 说明连当前 VMCS 都没有。
     * 合并成一个布尔就把"派发到了但拒绝"和"根本没派发"混成一样。
     */
    unsigned long vmxonResult;
    unsigned long vmptrldResult;
    unsigned long vmwriteResult;
    unsigned long vmreadResult;
    unsigned long vmptrstResult;
    unsigned long vmxoffResult;
    /* 写进去又读回来的那个字段是否逐位相同。 */
    unsigned long vmreadMatched;
    /* VMPTRST 取回的指针是否等于刚 VMPTRLD 的那个。 */
    unsigned long vmptrstMatched;
    /* 读回来的实际值，不匹配时用它归因。 */
    unsigned long long vmreadValue;
    /* 写进去的值。 */
    unsigned long long vmwriteValue;
    /* 自检期间这个处理器派发了多少条嵌套 VMX 指令。 */
    unsigned long long dispatchedInstructions;
    /* 自检结束时本处理器的嵌套状态。 */
    unsigned long nestedStateAfter;
    /* 最后一次 VMfailValid 的 Intel 错误号。 */
    unsigned long lastInstructionError;
    /* VMLAUNCH 的架构结果；0 也可能是"进去过又回来了"，看 l2Reached。 */
    unsigned long vmlaunchResult;
    /*
     * L2 真的跑起来过并且退出被反射回了 L1。
     *
     * 这一位是整条链路唯一的正向判据：它为 1 意味着 vmcs02 合并被硬件接受、
     * L2 执行了指令、退出落到我们手上、我们把它投递给了 L1，而 L1 的宿主
     * 处理器真的拿到了控制权。中间任何一环断掉，它都是 0。
     */
    unsigned long l2Reached;
    /* L1 从 vmcs12 里读到的退出原因；0x80000021 表示客户状态非法。 */
    unsigned long long l2ExitReason;
    /* 同上的 qualification。 */
    unsigned long long l2Qualification;
    /* L2 停在哪条指令上。 */
    unsigned long long l2GuestRip;
    /*
     * 这次 L2 是跑在 L1 自带的 EPT12 上（1）还是我们自己的层次上（0）。
     *
     * 分开报，是因为两条分支验的是不同的东西：为 1 时 L2 的每一次访问都要过
     * EPT12 再过 EPT01，走的是影子层次的合成路径；为 0 时那条路径根本没参与。
     * 不报这一位的话，一次"L2 跑通了"读数说不清到底验没验到合成。
     */
    unsigned long ept12Armed;
    /* 影子层次为这次运行合成了多少张叶。 */
    unsigned long shadowFillCount;
    /* 因 EPT12 自己拒绝而交给 L1 的违规数。 */
    unsigned long shadowDenyCount;
    /* 因表页用尽而没能合成的次数。 */
    unsigned long shadowExhaustionCount;
    /*
     * L1 发一次 INVEPT 的架构结果。
     *
     * 单独记，是因为它验的东西与别处都不同：L1 发 INVEPT 是在通知"我装的某个映射
     * 已经作废"，而那是它唯一的通知渠道 —— 我们的影子只在 EPT 指针本身变化时才丢。
     * 这一格报失败，等于告诉 L1 通知没送到。
     */
    unsigned long inveptResult;
    /* INVEPT 之后影子的代次有没有真的往前走。 */
    unsigned long shadowGenerationAdvanced;
    /*
     * vmcs02 在 VM entry 那一刻实际携带的控制位与三个位图地址。
     *
     * 这一组是**读回来的**，不是合并过程算出来的——两者只在"某个字段根本没被
     * 写过"时才不同，而那正是它要暴露的故障。控制位是 L1 的与我们的并集，所以
     * `USE_MSR_BITMAPS`（bit 28）会因为我们需要它而恒定活下来；如果配套的
     * `msrBitmap` 是 0，处理器就会拿物理页 0 当 MSR 位图用。
     *
     * 那种状态下没有任何别的读数会变：VM entry 成功、L2 照跑、退出照来。只有
     * 把这两格摆在一起看，才说得清 L2 的 MSR/IO 拦截到底由谁决定。
     */
    unsigned long vmcs02PrimaryControls;
    unsigned long vmcs02SecondaryControls;
    unsigned long long vmcs02MsrBitmap;
    unsigned long long vmcs02IoBitmapA;
    unsigned long long vmcs02IoBitmapB;
    /*
     * L2 停下来时距代码页起点的偏移。
     *
     * 这一格自己就是 MSR 位图合并的判据，不需要别的佐证。L2 的程序是两条
     * RDMSR：第一条 L1 的位图里是清的（不该退出），第二条是置的（该退出）。
     *
     *   12 = 停在第二条 —— 处理器查的确实是 L1 那张位图
     *    5 = 停在第一条 —— 查的是"全部拦截"的回退页，说明 L1 的页没读到
     *   14 = 走到了 CPUID —— MSR 拦截根本没发生
     *
     * 三种结局都产生退出、都能反射成功，只有停在哪里能把它们分开。
     */
    unsigned long long l2RipOffset;
    /* L2 的 MSR 退出各有多少条投递给了 L1、多少条由我们就地服务。 */
    unsigned long long l2MsrExitsReflected;
    unsigned long long l2MsrExitsHandled;
    /* 同上，端口退出。 */
    unsigned long long l2IoExitsReflected;
    unsigned long long l2IoExitsHandled;
    /* 上一次合并是否把需要的每一页都读到了。 */
    unsigned long bitmapMergeComplete;
    /* L1 自己有没有要求 MSR 位图过滤（决定归属判定走哪条分支）。 */
    unsigned long l1UsesMsrBitmap;
    /*
     * L1 在 EPT12 指针里请求了 accessed/dirty，因而被拒。
     *
     * 单独报，因为拒绝到了 L1 那里只剩一个通用的"控制字段非法"——架构上是对的，
     * 但它不说是哪一个控制。没有这一格的话，"L2 起不来"就分不清是能力不支持
     * 还是 EPT 指针本身写坏了。
     */
    unsigned long l1RequestedAccessedDirty;
    /*
     * A/D 真的在被维护并折回 L1 的表了没有，以及折了多少条。
     *
     * 与上一格分开：上一格是 L1 **要了什么**，这两格是我们**做到了什么**。
     * 两者只在处理器不支持、或记录表溢出时才不同，而那正是读者最需要分清的
     * 情形 —— 半套传播比完全没有更糟，L1 会读到"这些页写过、那些没写过"，
     * 而后半句是假的且它无从察觉。
     */
    /*
     * 两份 vmcs12 交替之后，各自的字段还在不在。
     *
     * 单份 VMCS 问不出这件事：派发器只建模一份 vmcs12 也能把上面每一项都跑过。
     * 而真 hypervisor（VMware、VirtualBox、Hyper-V）每个 vCPU 至少一份 VMCS 并
     * 不断 VMPTRLD 切换 —— 字段能不能活过一次切换，是能不能托住它们的前提。
     *
     * 序列是最小可失败的那一个：写 A、写 B、读 A、读 B。只建模一份的派发器会
     * 把 B 的值（或零）当成 A 的还回来。
     */
    unsigned long vmcsSwitchResult;
    unsigned long vmcsSwitchMatched;
    unsigned long long vmcsSwitchValueA;
    unsigned long long vmcsSwitchValueB;
    unsigned long accessedDirtyActive;
    unsigned long adPropagatedCount;
    unsigned long adOverflowCount;
    /*
     * 位图合并的周期数，与整个 L2 进入的周期数。
     *
     * 两个数一起报，因为合并的代价只有作为**份额**才有意义。"每次进入拷三页"
     * 是个形状不是测量值，照着形状决定要不要加缓存就是在赌。
     *
     * 都是累计值，除以 l2EntryCount 得均值。RDTSC 在外层 hypervisor 下是它愿意
     * 暴露的那个值 —— 同一次进入内取比例够用，当绝对时间不行。
     */
    unsigned long long l2MergeCycles;
    unsigned long long l2EntryCycles;
    unsigned long long l2EntryCount;
    /*
     * 池子实际装得下几份 vmcs12，以及装不下的那些有没有真的被记一笔。
     *
     * 上面那组"两份交替"只证明了**不止一份**。真 hypervisor 手里往往有十几份，
     * 而"我们能存 N 份"到此为止一直是写在头文件注释里的断言，没有任何读数支持。
     *
     * 做法：给比池子深度多两份的区域各写一个互不相同的值，然后**从最近用过的
     * 那份倒着读回来**。倒着读是必须的 —— 顺着读，每读一份就把更旧的一份挤掉，
     * 测量本身会毁掉被测量的东西，最后全读成零，看起来像池子根本不存在。
     *
     * mask 的第 k 位表示第 k 份读回来了。只报个数不够：LRU、FIFO、随机驱逐能
     * 给出同样的存活**个数**，但存活的是哪几份完全不同，而这决定了一个正在被
     * L1 频繁使用的 vmcs12 会不会被挤掉。
     *
     * evictionDelta 是**这一个处理器**在这段窗口里的驱逐数，取自它自己的记录而
     * 不是运行时那个全局总数 —— 探针在每个处理器上同时跑一个工作线程，从共享
     * 计数器取差值会把别的核干的事算进这一行，看着精确，说的是另一回事。
     * 它存在的唯一理由是：这个计数器在别处永远读到 0，而一个从没被人见过动的
     * 计数器等于没有验证过。
     */
    unsigned long long vmcs12DepthMask;
    unsigned long vmcs12DepthRegions;
    unsigned long vmcs12DepthSurvived;
    unsigned long vmcs12EvictionDelta;
    unsigned long vmcs12DepthReserved;
    /*
     * 来宾**此刻**读到的 VMX 能力，取自来宾上下文里的 RDMSR。
     *
     * 这是能力过滤唯一能被证伪的地方。查询接口报的是驱动加载时采的原始值（走
     * IOCTL，不经过 MSR 位图），所以它永远是硬件真相；而这两格走的是 RDMSR，
     * 常驻起来之后就会退出到我们手里被收窄。两个数不一样，才说明过滤是活的。
     *
     * 没有这一格的话，"我们过滤了能力"就只是一句代码读起来是对的断言 —— 而
     * 位图里少设一个位、或者退出路由没走到过滤函数，表现都是**什么都不变**。
     */
    unsigned long long guestVmxProcbased2;
    unsigned long long guestVmxEptVpidCap;
    /*
     * L1 写了、我们此前从不往 vmcs02 里拷的那几个字段，进 entry 前从**加载着的
     * vmcs02 里读回来**的值。
     *
     * 跟 msr 位图那组是同一个手法，也是同一个理由：算出来的值与处理器真正会用的
     * 值，只在"这个字段根本没被写过"的时候才不一样，而那恰恰是不留任何痕迹的
     * 那种失败。
     *
     * MSR 区比位图更隐蔽一层：位图至少还有个控制位，理论上可以不宣告；而 MSR
     * 区的**计数字段是无条件生效的**，没有任何能力位可以用来表示"我不支持"。
     * L1 让我们在进 L2 时装一批 MSR，我们就是不装，L2 于是拿着我们的 MSR 值跑，
     * 而 L1 以为是它自己那批。
     */
    unsigned long long vmcs02TscOffset;
    unsigned long long vmcs02EntryMsrLoadAddress;
    unsigned long long vmcs02ExitMsrStoreAddress;
    unsigned long vmcs02EntryMsrLoadCount;
    unsigned long vmcs02ExitMsrStoreCount;
    /*
     * 自虚拟化：L1 把**自己**变成来宾，跑完一圈再回来。
     *
     * 三格分别是三次到达同一个捕获点，缺一不可：
     *   reachedL2   —— VM entry 成功了，我们现在是以 L2 的身份在执行自己的代码
     *   exitReason  —— L2 里那条 CPUID 退出之后，**L1 从 vmcs12 里读到的**原因，
     *                  应当是 10。这一格才证明退出被正确投递给了 L1，而不是被
     *                  外层自己吃掉
     *   returnedToL1 —— L1 的宿主处理器跑完、VMXOFF、把上下文还了回来
     *
     * 只看 reachedL2 不够：进得去出不来，和根本进不去，对一个真 hypervisor 来说
     * 一样是死的。
     */
    unsigned long selfVirtAttempted;
    unsigned long selfVirtReachedL2;
    unsigned long selfVirtReturnedToL1;
    unsigned long selfVirtCpuidPassedThrough;
    /*
     * L2 通过**自己找到的**槽位写的标记，与上面那个全局标记分开报。
     *
     * 两个见证者问的是两件事：全局标记问"L2 的存储到底有没有进内存"（RIP 相对
     * 寻址，不依赖任何继承来的东西）；这一格问"L2 靠 GS 找自己那个槽位这条路
     * 通不通"。合成一格的话，两种完全不同的失败会塌成同一个 0。
     */
    unsigned long selfVirtSlotMarker;
    unsigned long long selfVirtExitReason;
    unsigned long long selfVirtGuestRip;
    /*
     * L1 写进 vmcs12 的那个入口 RIP，和退出 RIP 放在一起报。
     *
     * 必须是**同一轮之内**的比较。驱动每次加载基址都不一样，所以跨两次运行去比
     * 绝对地址什么也证明不了 —— 我就是这么误判过一次，把"地址随我改代码而移动"
     * 当成了"L2 在跑我们的代码"。
     *
     * 两者之差才是答案：差几十字节说明 L2 确实从我们指的地方开始、走到了那条
     * CPUID；差得离谱说明它根本没从那儿开始。
     */
    unsigned long long selfVirtEntryRip;
    /*
     * 这一轮里 L2 进了几次、又有几次退出被投递给 L1。
     *
     * "退出原因是 10 且回到了 L1"说不出**发生了几次退出**。一次干净的往返和
     * "先被我们自己吃掉一次、L2 接着跑、后来才有一次被反射"，在单个退出原因上
     * 读起来一模一样，而两者含义相反。
     */
    unsigned long selfVirtEntryCount;
    unsigned long selfVirtReflectCount;
    /*
     * L2 的**全部**退出次数，以及 L1 把 L2 放回去的次数。
     *
     * 全部退出与被投递的退出之差，正是"有多少条退出被我们自己消化掉、L1 从不知道
     * 它的来宾问过"。那是嵌套正确性的全部要害：我们替 L1 回答它自己的来宾，L1 无从
     * 察觉。只数被投递的那些，永远看不见这个差。
     *
     * resume 次数单列：回程走的是 VMRESUME 而不是 VMLAUNCH —— 不同指令、不同的
     * launch-state 检查。一个能通过首次进入的 vmcs12，完全可能在这里失败。
     */
    unsigned long selfVirtTotalExitCount;
    unsigned long selfVirtResumeCount;
    /*
     * 无进展熔断：L2 一直在同一条指令上以同样的原因退出。
     *
     * 这三格是**挂死唯一会留下的东西**。实测过：这种挂死没有蓝屏、没有转储、
     * 宿主 Hyper-V 日志里也没有任何事件 —— 处理器一直很忙，所以什么超时都不会
     * 触发，机器只是不再应答。熔断把它变成一条可读的记录。
     *
     * 进展的判定键是 RIP + 退出原因 + RCX 三者。只看 RIP 是错的：带 I/O 拦截的
     * REP 串指令每迭代一次就在同一个 RIP 上退出一次，完全合法，而 RCX 正是把
     * 那种情况和"真的没往前走"分开的东西。
     */
    unsigned long l2FuseTripped;
    unsigned long l2FuseReason;
    unsigned long l2FuseCount;
    /* Formerly reserved: host bits 0..4, memory operands bit 5, L2 SSE bit 6. */
    unsigned long hostStateChecks;
    unsigned long long l2FuseRip;
} KSWORD_ARK_HVM_NESTED_PROBE_ROW;

/*
 * 探针写进 vmcs12 的 TSC 偏移。
 *
 * 值本身没有架构含义，只要求一眼认得出、且不可能是"字段没写"留下的 0。判据两侧
 * 共用这一个定义，免得一边改了另一边还在比旧值 —— 那会变成一条永远为真的判据。
 */
#define KSWORD_ARK_HVM_NESTED_PROBE_TSC_OFFSET 0x0000ABCD00000000ULL

typedef struct _KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE
{
    unsigned long version;
    unsigned long size;
    /* 整体结果：任何一行不达标就不是 OK。 */
    unsigned long status;
    /* 本次实际跑了几个处理器。 */
    unsigned long returnedRows;
    unsigned long long stateFlags;
    KSWORD_ARK_HVM_NESTED_PROBE_ROW rows[
        KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS];
} KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE;

/* One live L2 page override, keyed by EPT12 root and L2 GPA. */
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_NESTED_PAGE 0x915UL
#define IOCTL_KSWORD_ARK_HVM_NESTED_PAGE \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_NESTED_PAGE, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* Version 4 adds leafShift/stagePageIndex and the STAGE operation. */
#define KSWORD_ARK_HVM_NESTED_PAGE_VERSION 4UL
/* Leaf granularities an override may be published at: 4 KiB, 2 MiB, 1 GiB.
   A leaf larger than 4 KiB applies one permission set to every page beneath it,
   so it is admitted only where EPT12's own leaf already covers the whole region.
   A request that cannot be honoured at the granularity asked for is refused; it
   is never narrowed to a smaller leaf, because a caller that asked to own a
   region must not silently receive one page of it. */
#define KSWORD_ARK_HVM_NESTED_PAGE_SHIFT_4K 12UL
#define KSWORD_ARK_HVM_NESTED_PAGE_SHIFT_2M 21UL
#define KSWORD_ARK_HVM_NESTED_PAGE_SHIFT_1G 30UL
/* Revocation withdraws the policy; backing still requires an acknowledged drain. */
#define KSWORD_ARK_HVM_PAGE_LEASE_VALID 0UL
#define KSWORD_ARK_HVM_PAGE_LEASE_OWNER_EXITED 1UL
#define KSWORD_ARK_HVM_PAGE_LEASE_TRANSLATION_CHANGED 2UL
#define KSWORD_ARK_HVM_PAGE_LEASE_SOURCE_UNREADABLE 3UL
/* A region admitted by scanning stopped meeting the condition it was admitted
   on: one of its source leaves now grants different access or a different memory
   type than the rest. Detected by sampling rather than at every composition, so
   the region may have been serving for a short while after the change. */
#define KSWORD_ARK_HVM_PAGE_LEASE_REGION_DRIFTED 4UL
#define KSWORD_ARK_HVM_NESTED_PAGE_QUERY 0UL
#define KSWORD_ARK_HVM_NESTED_PAGE_MAP 1UL
#define KSWORD_ARK_HVM_NESTED_PAGE_REMOVE 2UL
/* Overwrite one 4-KiB page of the published region's replacement backing.
   MAP initializes the whole region from the original bytes, so a freshly mapped
   region is indistinguishable from the source until a stage changes part of it.
   This exists because the request carries one page inline and a 2-MiB region is
   512 of them; sending them all through one buffer would make the structure
   larger than the thing it configures. */
#define KSWORD_ARK_HVM_NESTED_PAGE_STAGE 3UL
#define KSWORD_ARK_HVM_NESTED_PAGE_CONFIRMED 1UL
/*
 * Admit a large leaf by reading every source entry under the region instead of
 * by requiring the source's own leaf to be at least as coarse.
 *
 * Off by default, and deliberately not implied by asking for a large leaf,
 * because what it buys is paid for with a weaker lease. The coarse-source rule
 * leaves one source entry to watch, and the existing per-fill validation watches
 * it. A region admitted by scanning has up to 512, and re-reading 512 physical
 * entries inside the exit path is not affordable: the measured composition rate
 * on the evaluated machine is roughly 8.2e4 fills per second per the evaluation,
 * so immediate detection would cost tens of millions of reads per second.
 *
 * So a scanned region's lease still detects drift on the first page's path
 * immediately, and does not immediately detect a change to the other entries.
 * That is a real reduction in what the lease proves, which is why it is a flag
 * the caller has to set rather than a silent fallback, and why the response
 * reports which rule admitted the region.
 */
#define KSWORD_ARK_HVM_NESTED_PAGE_SCAN_SOURCE 2UL
/*
 * Report a digest of the published region and of the source it was cloned from.
 *
 * Verifying what a region actually contains needs some way to read it back, and
 * the alternative - a general "read this physical address" request - would be a
 * far larger surface than the question deserves, reachable by every caller that
 * can reach this device. A digest answers the questions that matter (is the
 * clone still identical to the source, did a staged write change exactly the
 * page it named) without handing out the bytes.
 *
 * Off by default because it reads the whole region twice: 2 MiB per side is
 * cheap once and wasteful on every status poll.
 */
#define KSWORD_ARK_HVM_NESTED_PAGE_DIGEST 4UL
/* Explicit lab faults are local to this one request and never remain armed. */
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_SHIFT 8UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_MASK 0x700UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_ALLOCATE 1UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_CANCEL 2UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_ROLLBACK 3UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_COMMIT_FLUSH 4UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH 5UL
/* Stage ids are carried in the NESTED_PAGE event's exitReason field. */
#define KSW_HVM_PAGE_BEGIN 1UL
#define KSW_HVM_PAGE_ALLOCATE_BEGIN 2UL
#define KSW_HVM_PAGE_ALLOCATE_END 3UL
#define KSW_HVM_PAGE_PUBLISHED 4UL
#define KSW_HVM_PAGE_FLUSH_BEGIN 5UL
#define KSW_HVM_PAGE_FLUSH_END 6UL
#define KSW_HVM_PAGE_UNPUBLISHED 7UL
#define KSW_HVM_PAGE_ROLLBACK_BEGIN 8UL
#define KSW_HVM_PAGE_ROLLBACK_END 9UL
#define KSW_HVM_PAGE_RECLAIMED 10UL
#define KSW_HVM_PAGE_END 11UL
typedef struct _KSWORD_ARK_HVM_NESTED_PAGE_REQUEST {
    unsigned long version, size, operation, flags;
    unsigned long long confirmationToken;
    unsigned long long ept12Pointer, guestPhysicalPage;
    unsigned long expectedGeneration, ownerProcessId;
    unsigned char shadow[4096];
    /* Exact Windows process creation time; prevents PID reuse at map admission. */
    unsigned long long ownerCreationTime;
    /* Granularity to publish the override at. Zero is read as 4 KiB so that a
       caller written against version 3 keeps its exact previous meaning. */
    unsigned long leafShift;
    /* MAP: unused. STAGE: which 4-KiB page of the region `shadow` replaces. */
    unsigned long stagePageIndex;
} KSWORD_ARK_HVM_NESTED_PAGE_REQUEST;
typedef struct _KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE {
    unsigned long version, size, status, lastStatus;
    unsigned long generation, active, retired, residentProcessors;
    unsigned long long ept12Pointer, guestPhysicalPage, shadowPhysicalPage;
    unsigned long long originalPhysicalPage, composedCount;
    unsigned long rootCount, operationId;
    unsigned long long ept12Roots[KSWORD_ARK_HVM_MAX_PROCESSORS];
    /* Process exit revokes the lease; explicit removal drains and frees backing. */
    unsigned long ownerProcessId, ownerExited;
    unsigned long long ownerCreationTime;
    /* A revoked lease is retained until removal acknowledges every CPU. */
    unsigned long leaseRevocationReason, sourceEntryCount;
    /* Source backing and normalized path captured before publication. */
    unsigned long long sourcePhysicalPage;
    unsigned long long sourceEntryAddress[4], sourceEntryValue[4];
    /* Granularity actually published, the region it owns, and the granularity
       EPT12's own leaf terminated on. The last is what limits the first, so a
       refusal can be read without walking the source tables again. */
    unsigned long leafShift, sourceLeafShift;
    unsigned long long regionBytes, regionPageCount;
    /* Count of STAGE operations applied to the live region since publication. */
    unsigned long long stagedPageCount;
    /* Which rule admitted the region: 0 the source's own leaf was coarse enough,
       1 every source entry was read and found to agree. A caller that did not
       ask for the scan can never see 1 here. */
    unsigned long admittedByScan;
    /* Source leaves examined by that scan, and the access bits they shared. */
    unsigned long long scannedLeafCount, scannedSharedBits;
    /* Digests of the source region and of the replacement serving in its place,
       zero unless the digest flag was set. Equal means the clone still matches;
       a staged write is expected to make exactly the backing digest differ. */
    unsigned long long sourceDigest, backingDigest, digestBytes;
} KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE;
