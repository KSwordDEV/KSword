#pragma once

#include "KswordArkProcessIoctl.h"

/*
 * The HVM protocol separates capability discovery from implementation state.
 * A capability-only or partial result must never be interpreted as a resident
 * hypervisor.  ACTIVE is published only after every selected processor has
 * entered VMX non-root operation and the rollback rendezvous is available.
 */
#define KSWORD_ARK_HVM_PROTOCOL_VERSION 4UL

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
 * what this build can drive: the SVM backend is not implemented, so an AMD
 * machine reports BACKEND_NOT_IMPLEMENTED rather than pretending to be ready.
 * Reporting the hardware honestly is the point - "unsupported CPU" would be a
 * lie on a part that supports SVM perfectly well.
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

#define KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT          1UL
#define KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION   2UL
#define KSWORD_ARK_HVM_EVENT_TYPE_NESTED_VMX      3UL
#define KSWORD_ARK_HVM_EVENT_TYPE_FATAL_EXIT      4UL
#define KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE       5UL

#define KSWORD_ARK_HVM_EVENT_QUERY_READ  1UL
#define KSWORD_ARK_HVM_EVENT_QUERY_CLEAR 2UL

#define KSWORD_ARK_HVM_NESTED_STATE_DISABLED        0UL
#define KSWORD_ARK_HVM_NESTED_STATE_CAPABILITY_ONLY 1UL
#define KSWORD_ARK_HVM_NESTED_STATE_DISPATCH_READY  2UL
#define KSWORD_ARK_HVM_NESTED_STATE_L1_VMXON        3UL
#define KSWORD_ARK_HVM_NESTED_STATE_VMCS12_CURRENT  4UL
#define KSWORD_ARK_HVM_NESTED_STATE_L2_PARTIAL      5UL

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
} KSWORD_ARK_HVM_CPU_ROW;

typedef struct _KSWORD_ARK_QUERY_HVM_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_QUERY_HVM_REQUEST;

typedef struct _KSWORD_ARK_QUERY_HVM_RESPONSE
{
    unsigned long version;
    unsigned long size;
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
    unsigned long eptRuleCount;
    unsigned long eventCount;
    unsigned long droppedEventCount;
    unsigned long nestedState;
    unsigned long evmcsState;
    unsigned short evmcsVersion;
    unsigned short reservedVersion;
    unsigned long evmcsFlags;
    unsigned long reservedEvmcs;
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
    unsigned long activeControlsReserved;
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
    unsigned long reserved;
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
    unsigned long reserved2;
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
} KSWORD_ARK_HVM_EPT_RULE_REQUEST;

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
} KSWORD_ARK_HVM_EPT_RULE_RESPONSE;

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
} KSWORD_ARK_HVM_EVENT_ROW;

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
