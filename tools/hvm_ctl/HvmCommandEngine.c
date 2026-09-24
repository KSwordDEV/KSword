/*
 * hvm_ctl —— KSword HVM 控制与状态的最小命令行工具（无 Qt 依赖）。
 *
 * 存在的理由：KswordCLI 只提供只读的 hvm-status / hvm-events，启动 HVM 要走
 * IOCTL_KSWORD_ARK_CONTROL_HVM，而那条路平时由 Qt 主程序的内核页发起。
 * 在没有图形界面的测试机上需要一个不依赖 Qt 的入口。
 *
 * **协议结构不再手抄。** 上一版把请求/响应结构和命令号在本文件里重新声明了一
 * 遍，结果是每处理器标志集合与 hvm_runtime.c 的 allowedFlags 对不上：SELF_TEST
 * 缺 FORCE 位，驱动一律回 CONFIRMATION_REQUIRED，而那个状态码看上去像"安全策
 * 略没开"，把排查引到了完全无关的方向。现在直接包含 shared/driver 的权威头，
 * 结构漂移这一类错误在编译期就不可能发生。
 *
 * 每条命令接受的标志集合必须与 hvm_runtime.c 的 allowedFlags switch 逐位一致：
 * 多一位是 INVALID_REQUEST（`flags & ~allowedFlags`），少 FORCE 是
 * CONFIRMATION_REQUIRED。两种拒绝都发生在真正做事之前，看不出区别，所以本文件
 * 用一张显式表把它钉死，并在注释里标注对应的驱动行号出处。
 *
 * 分级很重要，不要跳步：
 *   status      只读查询，不改状态。自动化脚本应该先跑它再决定下一步。
 *   prepare     分配每处理器资源，不进 VMX。失败只是资源问题。
 *   self-test   **逐处理器 VMXON 然后 VMXOFF**。这是第一次真的进 VMX root，
 *               但不常驻，退出即恢复。嵌套环境下先跑它。
 *   resident    全处理器常驻 VMM + EPT 激活。这一步之后系统一直跑在 VMX non-root。
 *   soak        常驻一段有界时间再停，用来证明常驻能扛住正常系统活动。
 *   stop        停止常驻。
 *   teardown    释放资源。
 *   reset-fault 清 FAULTED / ROLLBACK_REQUIRED。**重复 prepare 会把状态打成
 *               FAULTED**（已就绪时返回 STATUS_ALREADY_REGISTERED，是 NT_ERROR，
 *               落进 hvm_runtime.c 的 FAULTED 分支），而 FAULTED 会让
 *               START_RESIDENT 直接被拒（hvm_resident.c 的 INVALID_DEVICE_STATE）。
 *               自动化必须能自己走出这个坑。
 *
 * 退出码：0 = 协议 status OK；2 = 协议 status 非 OK（值见 --json 的 status）；
 *         1 = 传输层失败（设备打不开、DeviceIoControl 失败、缓冲太短）。
 *
 * 编译： cl /nologo /W4 /WX /O2 hvm_ctl.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <tlhelp32.h>
/* __cpuid：tlb-probe-exit 用它强制一次无条件 VM exit。 */
#include <intrin.h>

/* 协议的唯一真值来源。手抄一份就等于给自己埋一个静默的漂移。 */
#include "../../shared/driver/KswordArkHvmIoctl.h"
#include "../../shared/driver/KswordArkHvmMetricsIoctl.h"
/* 能力过滤的白名单常量，判据与驱动引用同一份。 */
#include "../../shared/driver/KswordArkHvmControls.h"
/* acl-probe 要对这两条破坏性 IOCTL 验访问位闸门，取它们的控制码。 */
#include "../../shared/driver/KswordArkProcessIoctl.h"
#include "../../shared/driver/KswordArkMemoryIoctl.h"
/* Reuse the main program's R0 descriptor protocol for gdt-dump. */
#include "../../shared/driver/KswordArkKernelIoctl.h"

#define KSW_DEVICE_PATH L"\\\\.\\KswordARKLog"

#include "HvmCommandCatalog.h"
#include "../../shared/driver/KswordArkHvmRequest.h"
typedef HVM_COMMAND_SPEC HVM_CTL_VERB;

static const char* ControlStatusName(unsigned long s)
{
    switch (s) {
    case KSWORD_ARK_HVM_CONTROL_STATUS_OK:                    return "OK";
    case KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST:       return "INVALID_REQUEST";
    case KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED: return "CONFIRMATION_REQUIRED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU:       return "UNSUPPORTED_CPU";
    case KSWORD_ARK_HVM_CONTROL_STATUS_FIRMWARE_DISABLED:     return "FIRMWARE_DISABLED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_HYPERVISOR_CONFLICT:   return "HYPERVISOR_CONFLICT";
    case KSWORD_ARK_HVM_CONTROL_STATUS_ALREADY_PREPARED:      return "ALREADY_PREPARED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED:          return "NOT_PREPARED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED:       return "RESOURCE_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_SELF_TEST_FAILED:      return "SELF_TEST_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED:         return "VERIFY_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_BUSY:                  return "BUSY";
    case KSWORD_ARK_HVM_CONTROL_STATUS_GUEST_LAUNCH_FAILED:   return "GUEST_LAUNCH_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_UNEXPECTED_VMEXIT:     return "UNEXPECTED_VMEXIT";
    case KSWORD_ARK_HVM_CONTROL_STATUS_PARTIAL_IMPLEMENTATION: return "PARTIAL_IMPLEMENTATION";
    case KSWORD_ARK_HVM_CONTROL_STATUS_RENDEZVOUS_FAILED:     return "RENDEZVOUS_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_ROLLBACK_REQUIRED:     return "ROLLBACK_REQUIRED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_NESTED_UNSUPPORTED:    return "NESTED_UNSUPPORTED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_EVMCS_UNSUPPORTED:     return "EVMCS_UNSUPPORTED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_POWER_TRANSITION_BLOCKED:
        return "POWER_TRANSITION_BLOCKED";
    /*
     * 20 以上这一段上一版漏了，于是 START_RESIDENT 的真实失败被印成 "UNKNOWN"，
     * 把「协议里有确切名字的失败」伪装成「没见过的状态码」。
     * LIFECYCLE_GUARD_FAILED 尤其要命：它是 STATUS_INVALID_DEVICE_STATE 的唯一
     * 映射目标（hvm_runtime.c 的 KswordARKHvmControlStatusFromNtStatus），
     * 名字本身就指向 KswordARKHvmArmUnloadGuard，看到它就不必再猜是哪一道门。
     */
    case KSWORD_ARK_HVM_CONTROL_STATUS_LIFECYCLE_GUARD_FAILED:
        return "LIFECYCLE_GUARD_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_NOT_ARMED:
        return "LOCAL_EPT_NOT_ARMED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_LEAF_SET_TOO_LARGE:
        return "LOCAL_EPT_LEAF_SET_TOO_LARGE";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_PAGE_BUDGET_EXHAUSTED:
        return "LOCAL_EPT_PAGE_BUDGET_EXHAUSTED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_SPLIT_MISSING:
        return "LOCAL_EPT_SPLIT_MISSING";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_VERIFY_FAILED:
        return "LOCAL_EPT_VERIFY_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_VMFUNC:
        return "LOCAL_EPT_CONFLICTS_WITH_VMFUNC";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_NESTED:
        return "LOCAL_EPT_CONFLICTS_WITH_NESTED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_EPT_WINDOW_TOO_SMALL:
        return "EPT_WINDOW_TOO_SMALL";
    default: return "UNKNOWN";
    }
}

static const char* ImplementationName(unsigned long v)
{
    switch (v) {
    case KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED:     return "UNSUPPORTED";
    case KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY: return "CAPABILITY_ONLY";
    case KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL:         return "PARTIAL";
    case KSWORD_ARK_HVM_IMPLEMENTATION_ACTIVE:          return "ACTIVE";
    default: return "UNKNOWN";
    }
}

/* 状态位逐位展开。名字比十六进制好读，也让日志能被 grep。 */
typedef struct _HVM_STATE_BIT { unsigned long bit; const char* name; } HVM_STATE_BIT;

static const HVM_STATE_BIT g_StateBits[] = {
    { KSWORD_ARK_HVM_STATE_INITIALIZED,      "INITIALIZED" },
    { KSWORD_ARK_HVM_STATE_RESOURCES_READY,  "RESOURCES_READY" },
    { KSWORD_ARK_HVM_STATE_EPT_READY,        "EPT_READY" },
    { KSWORD_ARK_HVM_STATE_SELF_TESTED,      "SELF_TESTED" },
    { KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED, "SELF_TEST_PASSED" },
    { KSWORD_ARK_HVM_STATE_BUSY,             "BUSY" },
    { KSWORD_ARK_HVM_STATE_FAULTED,          "FAULTED" },
    { KSWORD_ARK_HVM_STATE_EPT_TRUNCATED,    "EPT_TRUNCATED" },
    { KSWORD_ARK_HVM_STATE_GUEST_READY,      "GUEST_READY" },
    { KSWORD_ARK_HVM_STATE_GUEST_RUNNING,    "GUEST_RUNNING" },
    { KSWORD_ARK_HVM_STATE_GUEST_EXITED,     "GUEST_EXITED" },
    { KSWORD_ARK_HVM_STATE_NESTED_ACTIVE,    "NESTED_ACTIVE" },
    { KSWORD_ARK_HVM_STATE_NESTED_VALIDATED, "NESTED_VALIDATED" },
    { KSWORD_ARK_HVM_STATE_RESIDENT_STARTING, "RESIDENT_STARTING" },
    { KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE,   "RESIDENT_ACTIVE" },
    { KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING, "RESIDENT_STOPPING" },
    { KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE,  "EPT_RULES_ACTIVE" },
    { KSWORD_ARK_HVM_STATE_EVENTS_AVAILABLE,  "EVENTS_AVAILABLE" },
    { KSWORD_ARK_HVM_STATE_NESTED_PARTIAL,    "NESTED_PARTIAL" },
    { KSWORD_ARK_HVM_STATE_EVMCS_PARTIAL,     "EVMCS_PARTIAL" },
    { KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED, "ROLLBACK_REQUIRED" },
    { KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING, "POWER_TRANSITION_PENDING" },
    { KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED,       "UNLOAD_GUARD_ARMED" },
    { KSWORD_ARK_HVM_STATE_RESIDENT_NESTED,          "RESIDENT_NESTED" },
    { KSWORD_ARK_HVM_STATE_VE_ACTIVE,                "VE_ACTIVE" },
    { KSWORD_ARK_HVM_STATE_VMFUNC_ACTIVE,            "VMFUNC_ACTIVE" },
};

static void PrintStateBits(const char* prefix, unsigned long flags)
{
    size_t i;
    unsigned long known = 0UL;
    printf("%s0x%08lX =", prefix, flags);
    for (i = 0U; i < sizeof(g_StateBits) / sizeof(g_StateBits[0]); ++i) {
        known |= g_StateBits[i].bit;
        if ((flags & g_StateBits[i].bit) != 0UL) {
            printf(" %s", g_StateBits[i].name);
        }
    }
    if ((flags & ~known) != 0UL) {
        /* 未知位必须显式报出来。悄悄丢掉等于把新状态当成没有。 */
        printf("  (未知位 0x%08lX)", flags & ~known);
    }
    if (flags == 0UL) { printf(" <无>"); }
    printf("\n");
}

/* JSON 里的状态位名字数组。字段用于机器判据，不做人类可读的对齐。 */
static void PrintStateBitsJson(unsigned long flags)
{
    size_t i;
    int first = 1;
    printf("[");
    for (i = 0U; i < sizeof(g_StateBits) / sizeof(g_StateBits[0]); ++i) {
        if ((flags & g_StateBits[i].bit) != 0UL) {
            printf("%s\"%s\"", first ? "" : ",", g_StateBits[i].name);
            first = 0;
        }
    }
    printf("]");
}

/*
 * IA32_VMX_EPT_VPID_CAP（MSR 0x48C）的逐位展开。
 *
 * **bit 0（execute-only）是分离视图后端的 make-or-break 前提**，而它
 * 没有对应的 KSWORD_ARK_HVM_FEATURE_* 位 —— featureFlags 再全也回答不了它。
 * KswordArkHvmEptSwDecide 在 kind 分派之前就检查它，为 0 时对 CLOAK 与 HOOK
 * 一视同仁地拒绝一切，也就是说一次切换都不会发生。所以它必须被单独打出来。
 *
 * 位定义出自 SDM Appendix A.10。
 */
typedef struct _EPT_CAP_BIT { unsigned bit; const char* name; const char* note; } EPT_CAP_BIT;

static const EPT_CAP_BIT g_EptCapBits[] = {
    {  0, "EXECUTE_ONLY",     "**分离视图后端的硬前提**" },
    {  6, "PAGE_WALK_4",      "4 级页遍历" },
    {  8, "MEMORY_TYPE_UC",   "EPTP 可用 UC" },
    { 14, "MEMORY_TYPE_WB",   "EPTP 可用 WB" },
    { 16, "PDE_2MB",          "2MiB 大叶" },
    { 17, "PDPTE_1GB",        "1GiB 大叶" },
    { 20, "INVEPT",           "支持 INVEPT" },
    { 21, "ACCESSED_DIRTY",   "叶 A/D 位" },
    { 22, "ADVANCED_VE_INFO", "#VE 信息页扩展" },
    { 25, "INVEPT_SINGLE",    "single-context" },
    { 26, "INVEPT_ALL",       "all-context" },
    { 32, "INVVPID",          "支持 INVVPID" },
};

static void PrintEptVpidCapability(const char* indent, unsigned long long cap)
{
    size_t i;
    printf("%sEPT/VPID cap : 0x%016llX\n", indent, cap);
    if (cap == 0ULL) {
        printf("%s  （为 0：驱动未采集或本机不支持 EPT）\n", indent);
        return;
    }
    for (i = 0U; i < sizeof(g_EptCapBits) / sizeof(g_EptCapBits[0]); ++i) {
        const int on = ((cap >> g_EptCapBits[i].bit) & 1ULL) != 0ULL;
        printf("%s  [%s] bit %-2u %-16s %s\n",
               indent, on ? "X" : " ", g_EptCapBits[i].bit,
               g_EptCapBits[i].name, g_EptCapBits[i].note);
    }
}

/*
 * featureFlags 的逐位展开。
 *
 * 以前这里只打一个 64 位十六进制。分离视图的硬前提
 * MONITOR_TRAP_FLAG 就藏在 bit24 里，于是「靶机到底缺不缺 MTF」这个
 * 决定整条 HOOK 路线的问题，在机器上**连个名字都读不到**，只能靠人肉
 * 换算十六进制 —— 而那正是最容易看错、且看错了不会有任何提示的地方。
 */
typedef struct _HVM_FEATURE_BIT
{
    unsigned long long bit;
    const char* name;
} HVM_FEATURE_BIT;

static const HVM_FEATURE_BIT g_FeatureBits[] = {
    { KSWORD_ARK_HVM_FEATURE_INTEL,                     "INTEL" },
    { KSWORD_ARK_HVM_FEATURE_VMX,                       "VMX" },
    { KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED,    "FEATURE_CONTROL_LOCKED" },
    { KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX,           "VMX_OUTSIDE_SMX" },
    { KSWORD_ARK_HVM_FEATURE_TRUE_CONTROLS,             "TRUE_CONTROLS" },
    { KSWORD_ARK_HVM_FEATURE_EPT,                       "EPT" },
    { KSWORD_ARK_HVM_FEATURE_EPT_WB,                    "EPT_WB" },
    { KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL,               "EPT_4_LEVEL" },
    { KSWORD_ARK_HVM_FEATURE_EPT_2MB,                   "EPT_2MB" },
    { KSWORD_ARK_HVM_FEATURE_EPT_AD,                    "EPT_AD" },
    { KSWORD_ARK_HVM_FEATURE_INVEPT,                    "INVEPT" },
    { KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE,             "INVEPT_SINGLE" },
    { KSWORD_ARK_HVM_FEATURE_INVEPT_ALL,                "INVEPT_ALL" },
    { KSWORD_ARK_HVM_FEATURE_VPID,                      "VPID" },
    { KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT,        "HYPERVISOR_PRESENT" },
    { KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED,        "NESTED_VMX_EXPOSED" },
    { KSWORD_ARK_HVM_FEATURE_ONE_SHOT_GUEST,            "ONE_SHOT_GUEST" },
    { KSWORD_ARK_HVM_FEATURE_VMEXIT_TELEMETRY,          "VMEXIT_TELEMETRY" },
    { KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM,              "RESIDENT_VMM" },
    { KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS,      "MULTICORE_RENDEZVOUS" },
    { KSWORD_ARK_HVM_FEATURE_EPT_4KB_SPLIT,             "EPT_4KB_SPLIT" },
    { KSWORD_ARK_HVM_FEATURE_EPT_RULES,                 "EPT_RULES" },
    { KSWORD_ARK_HVM_FEATURE_EPT_EVENT_RING,            "EPT_EVENT_RING" },
    { KSWORD_ARK_HVM_FEATURE_MTRR_AWARE_EPT,            "MTRR_AWARE_EPT" },
    { KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG,         "MONITOR_TRAP_FLAG" },
    { KSWORD_ARK_HVM_FEATURE_NESTED_VMX_DISPATCH,       "NESTED_VMX_DISPATCH" },
    { KSWORD_ARK_HVM_FEATURE_NESTED_VMX_ACTIVE,         "NESTED_VMX_ACTIVE" },
    { KSWORD_ARK_HVM_FEATURE_SHADOW_EPT,                "SHADOW_EPT" },
    { KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_CAPABLE,      "HYPERV_EVMCS_CAPABLE" },
    { KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_V1,           "HYPERV_EVMCS_V1" },
    { KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_ACTIVE,       "HYPERV_EVMCS_ACTIVE" },
    { KSWORD_ARK_HVM_FEATURE_VMX_INSTRUCTION_EMULATION, "VMX_INSTRUCTION_EMULATION" },
    { KSWORD_ARK_HVM_FEATURE_POWER_STATE_GUARD,         "POWER_STATE_GUARD" },
    { KSWORD_ARK_HVM_FEATURE_PROCESSOR_TOPOLOGY_GUARD,  "PROCESSOR_TOPOLOGY_GUARD" },
    { KSWORD_ARK_HVM_FEATURE_DRIVER_UNLOAD_GUARD,       "DRIVER_UNLOAD_GUARD" },
    { KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED, "RESIDENT_LIFECYCLE_GUARDED" },
    { KSWORD_ARK_HVM_FEATURE_MSR_BITMAP,                "MSR_BITMAP" },
    { KSWORD_ARK_HVM_FEATURE_EXIT_EMULATION,            "EXIT_EMULATION" },
    { KSWORD_ARK_HVM_FEATURE_RESIDENT_SUSTAINED,        "RESIDENT_SUSTAINED" },
    { KSWORD_ARK_HVM_FEATURE_AMD,                       "AMD" },
    { KSWORD_ARK_HVM_FEATURE_SVM,                       "SVM" },
    { KSWORD_ARK_HVM_FEATURE_NPT,                       "NPT" },
    { KSWORD_ARK_HVM_FEATURE_SVM_NRIP,                  "SVM_NRIP" },
    { KSWORD_ARK_HVM_FEATURE_SVM_DECODE_ASSISTS,        "SVM_DECODE_ASSISTS" },
    { KSWORD_ARK_HVM_FEATURE_SVM_FLUSH_BY_ASID,         "SVM_FLUSH_BY_ASID" },
    { KSWORD_ARK_HVM_FEATURE_SVM_FIRMWARE_DISABLED,     "SVM_FIRMWARE_DISABLED" },
    { KSWORD_ARK_HVM_FEATURE_EPT_VIOLATION_VE,          "EPT_VIOLATION_VE" },
    { KSWORD_ARK_HVM_FEATURE_VE_INFO_READY,             "VE_INFO_READY" },
    { KSWORD_ARK_HVM_FEATURE_VE_SUPPRESSED_BY_DEFAULT,  "VE_SUPPRESSED_BY_DEFAULT" },
    { KSWORD_ARK_HVM_FEATURE_VM_FUNCTIONS,              "VM_FUNCTIONS" },
    { KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING,            "EPTP_SWITCHING" },
    { KSWORD_ARK_HVM_FEATURE_EPTP_LIST_READY,           "EPTP_LIST_READY" },
    { KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED,           "LOCAL_EPT_ARMED" },
    { KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED,         "EPTP_SWITCH_ARMED" },
};

/*
 * 分离视图安装期真正被检查的那几位，**不管置没置都要打出来**。
 * 只列置位的位会让「缺某个能力」变成一条看不见的信息 —— 而缺位恰恰
 * 是这条线上最需要一眼看到的东西。
 */
static void PrintViewPrerequisites(const char* indent, unsigned long long flags)
{
    static const HVM_FEATURE_BIT required[] = {
        { KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE,     "INVEPT_SINGLE" },
        { KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG, "MONITOR_TRAP_FLAG" },
        { KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED,   "LOCAL_EPT_ARMED" },
    };
    const int eptpSwitch =
        (flags & KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED) != 0ULL;
    size_t i;
    /*
     * 先说清当前是哪个后端。两个后端要求的能力**不是同一组**，
     * 不点明后端就去看下面那几项，会得出「缺 MTF 所以装不上」这种
     * 在 EPTP 切换下根本不成立的结论。
     */
    printf("%s分离视图后端 : %s\n", indent,
           eptpSwitch ? "EPTP 切换（不需要 MTF）"
                      : "写叶 + monitor-trap（默认）");
    printf("%s分离视图前提 :\n", indent);
    for (i = 0U; i < sizeof(required) / sizeof(required[0]); ++i) {
        const int on = (flags & required[i].bit) != 0ULL;
        const char* note = "";
        if (on == 0) {
            if (required[i].bit == KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED) {
                note = "（多核才需要；1 vCPU 上不影响安装）";
            } else if (required[i].bit ==
                           KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG &&
                       eptpSwitch != 0) {
                note = "（EPTP 切换后端不需要它）";
            } else {
                note = "**缺这一位，view add 必被拒**";
            }
        }
        printf("%s  [%s] %-18s %s\n", indent, on ? "X" : " ",
               required[i].name, note);
    }
}

static void PrintFeatureBits(const char* indent, unsigned long long flags)
{
    size_t i;
    unsigned long long known = 0ULL;
    int printed = 0;
    printf("%s能力位       : 0x%016llX =", indent, flags);
    for (i = 0U; i < sizeof(g_FeatureBits) / sizeof(g_FeatureBits[0]); ++i) {
        known |= g_FeatureBits[i].bit;
        if ((flags & g_FeatureBits[i].bit) != 0ULL) {
            /* 一行铺不下，按每行四个折行，但保持可 grep 的单词形式。 */
            if (printed != 0 && (printed % 4) == 0) {
                printf("\n%s               ", indent);
            }
            printf(" %s", g_FeatureBits[i].name);
            printed += 1;
        }
    }
    if (flags == 0ULL) { printf(" <无>"); }
    printf("\n");
    if ((flags & ~known) != 0ULL) {
        /* 未知位必须显式报出来，悄悄丢掉等于把新能力当成没有。 */
        printf("%s               (未知位 0x%016llX)\n", indent, flags & ~known);
    }
    PrintViewPrerequisites(indent, flags);
}

static void PrintFeatureBitsJson(unsigned long long flags)
{
    size_t i;
    int first = 1;
    printf("[");
    for (i = 0U; i < sizeof(g_FeatureBits) / sizeof(g_FeatureBits[0]); ++i) {
        if ((flags & g_FeatureBits[i].bit) != 0ULL) {
            printf("%s\"%s\"", first ? "" : ",", g_FeatureBits[i].name);
            first = 0;
        }
    }
    printf("]");
}

/*
 * 每处理器行。这是唯一能回答「哪个核、卡在哪条 VMX 指令」的地方。
 *
 * worker（hvm_resident.c 的 KswordARKHvmResidentStartCurrent）在 VMXON /
 * VMCLEAR / VMPTRLD / VMWRITE / VMLAUNCH 每一步失败时都统一返回
 * STATUS_HV_OPERATION_FAILED，汇总到协议层只剩一个 RENDEZVOUS_FAILED ——
 * 从响应里完全看不出是哪一步。但每一步失败前都会把 VMX 指令结果写进
 * Row.vmxInstructionResult，并按进度累加 Row.stateFlags，两者合起来就能定位。
 *
 * vmxInstructionResult 的取值出自 SDM 30.2：
 *   0 = 成功；1 = VMfailValid（VMCS 有效，错误码在 VMCS 字段 0x4400）；
 *   2 = VMfailInvalid（没有当前 VMCS，拿不到错误码）。
 */
static const HVM_STATE_BIT g_CpuStateBits[] = {
    { KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY,  "RESOURCE_READY" },
    { KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED,     "SELF_TESTED" },
    { KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED, "VMXON_SUCCEEDED" },
    { KSWORD_ARK_HVM_CPU_STATE_EXCEPTION,       "EXCEPTION" },
    { KSWORD_ARK_HVM_CPU_STATE_CONFLICT,        "CONFLICT" },
    { KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED,     "VMCS_LOADED" },
    { KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED,  "GUEST_LAUNCHED" },
    { KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED,  "VMEXIT_HANDLED" },
    { KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE, "RESIDENT_ACTIVE" },
    { KSWORD_ARK_HVM_CPU_STATE_STOP_REQUESTED,  "STOP_REQUESTED" },
    { KSWORD_ARK_HVM_CPU_STATE_DEVIRTUALIZED,   "DEVIRTUALIZED" },
    { KSWORD_ARK_HVM_CPU_STATE_NESTED_PARTIAL,  "NESTED_PARTIAL" },
    { KSWORD_ARK_HVM_CPU_STATE_EVMCS_PARTIAL,   "EVMCS_PARTIAL" },
};

static const char* VmxResultName(unsigned char r)
{
    switch (r) {
    case 0U:    return "成功";
    case 1U:    return "VMfailValid（错误码见 VMCS 0x4400）";
    case 2U:    return "VMfailInvalid（无当前 VMCS）";
    case 0xFFU: return "未执行";
    default:    return "?";
    }
}

static void PrintCpuRows(const KSWORD_ARK_QUERY_HVM_RESPONSE* rsp, int asJson)
{
    unsigned long i;
    unsigned long count = rsp->processorCount;
    size_t b;

    if (count > KSWORD_ARK_HVM_MAX_PROCESSORS) {
        count = KSWORD_ARK_HVM_MAX_PROCESSORS;
    }
    if (asJson) {
        printf(",\"processors\":[");
        for (i = 0UL; i < count; ++i) {
            const KSWORD_ARK_HVM_CPU_ROW* row = &rsp->processors[i];
            int first = 1;
            printf("%s{\"index\":%lu,\"group\":%u,\"number\":%u,"
                   "\"backend\":%lu,\"executionStage\":%lu,\"svmExitCode\":\"0x%016llX\",\"vmxInstructionResult\":%u,\"stateFlags\":%lu,"
                   "\"stateHex\":\"0x%08lX\",\"lastStatus\":\"0x%08lX\","
                   "\"lastExitReason\":%lu,\"vmExitCount\":%llu,\"stateNames\":[",
                   (i == 0UL) ? "" : ",", i,
                   (unsigned)row->processorGroup, (unsigned)row->processorNumber,
                   row->backend, row->executionStage, row->svmExitCode, (unsigned)row->vmxInstructionResult, row->stateFlags,
                   row->stateFlags, (unsigned long)row->lastStatus,
                   row->lastExitReason, row->vmExitCount);
            for (b = 0U; b < sizeof(g_CpuStateBits) / sizeof(g_CpuStateBits[0]); ++b) {
                if ((row->stateFlags & g_CpuStateBits[b].bit) != 0UL) {
                    printf("%s\"%s\"", first ? "" : ",", g_CpuStateBits[b].name);
                    first = 0;
                }
            }
            printf("]}");
        }
        printf("]");
        return;
    }

    printf("\n  --- 每处理器 ---\n");
    for (i = 0UL; i < count; ++i) {
        const KSWORD_ARK_HVM_CPU_ROW* row = &rsp->processors[i];
        printf("  CPU %lu (组 %u 号 %u): vmxResult=%u (%s)  lastStatus=0x%08lX\n",
               i, (unsigned)row->processorGroup, (unsigned)row->processorNumber,
               (unsigned)row->vmxInstructionResult,
               VmxResultName(row->vmxInstructionResult),
               (unsigned long)row->lastStatus);
        printf("      状态 0x%08lX =", row->stateFlags);
        for (b = 0U; b < sizeof(g_CpuStateBits) / sizeof(g_CpuStateBits[0]); ++b) {
            if ((row->stateFlags & g_CpuStateBits[b].bit) != 0UL) {
                printf(" %s", g_CpuStateBits[b].name);
            }
        }
        if (row->stateFlags == 0UL) { printf(" <无>"); }
        printf("\n");
        if (row->vmExitCount != 0ULL || row->lastExitReason != 0UL) {
            printf("      退出 count=%llu lastReason=%lu\n",
                   row->vmExitCount, row->lastExitReason);
        }
    }
}

/*
 * lastVmInstructionError 的解码。
 *
 * bit 31 为 0 时它就是架构 VM-instruction error（SDM Table 30-1）。
 * bit 31 为 1 时它是驱动写的判别码 —— 因为 VMCS 配置阶段有至少八个不同的
 * 返回点会以完全相同的现象失败（每处理器行一律 result=3 / stateFlags=0x27），
 * 光看协议面分不出是哪一个。编码定义在 shared/driver/KswordArkHvmIoctl.h。
 */
static const char* ArchVmInstructionErrorName(unsigned long e)
{
    switch (e) {
    case 0UL:  return "（无）";
    case 7UL:  return "VM entry with invalid control fields";
    case 8UL:  return "VM entry with invalid host-state fields";
    case 12UL: return "VMWRITE to read-only / unsupported component";
    case 26UL: return "VM entry with events blocked by MOV SS";
    default:   return "见 SDM Table 30-1";
    }
}

static const char* DiagSiteName(unsigned long site)
{
    switch (site) {
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_VMWRITE:
        return "VMWRITE 被拒（detail = VMCS 字段编码）";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_NO_TRANSFER:
        return "CR4 里启用的可选状态没有 VMCS 传输能力";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_MSR_BITMAP:
        return "给了 MSR bitmap 页但没拿到 USE_MSR_BITMAPS";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_CR_POLICY:
        return "CR3/DR 拦截被请求但对应控制没拿到";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_REQUIRED_CONTROLS:
        return "必需的 primary/secondary/exit/entry 控制缺失";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_DEBUG_PAIRING:
        return "调试状态的保存与加载控制不成对";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_PAIRING:
        return "可选状态的 exit/entry 控制不成对";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_INSTRUCTION_CTL:
        return "必需的 secondary 指令控制缺失（detail = 最低缺失位号）";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_MSR_EXCEPTION:
        return "读可选状态 MSR 抛异常（detail = 异常码低 16 位）";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_CAP_EXCEPTION:
        return "读能力/主机 MSR 抛异常（detail = 异常码低 16 位）";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_DIAG_IO_EXITING:
        return "诊断用的无条件 I/O 退出被能力 MSR 夹掉（判据会静默失效）";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_HOST_CR3:
        return "主机页目录基址为零（装上去会三重故障，无蓝屏无转储）";
    default:
        return "未知站点";
    }
}

static void PrintStateMask(unsigned long mask)
{
    if ((mask & KSWORD_ARK_HVM_VMCS_DIAG_STATE_CET) != 0UL)   { printf(" CET"); }
    if ((mask & KSWORD_ARK_HVM_VMCS_DIAG_STATE_PKS) != 0UL)   { printf(" PKS"); }
    if ((mask & KSWORD_ARK_HVM_VMCS_DIAG_STATE_UINTR) != 0UL) { printf(" UINTR"); }
    if ((mask & KSWORD_ARK_HVM_VMCS_DIAG_STATE_FRED) != 0UL)  { printf(" FRED"); }
}

static void PrintVmInstructionError(const char* indent, unsigned long v)
{
    unsigned long site;
    unsigned long detail;

    if (v == 0UL) {
        printf("%svmInstrError : 0（无）\n", indent);
        return;
    }
    if (!KSWORD_ARK_HVM_VMCS_DIAG_IS(v)) {
        printf("%svmInstrError : %lu  %s\n", indent, v, ArchVmInstructionErrorName(v));
        return;
    }
    site = KSWORD_ARK_HVM_VMCS_DIAG_SITE(v);
    detail = KSWORD_ARK_HVM_VMCS_DIAG_DETAIL(v);
    printf("%svmInstrError : 0x%08lX  【驱动判别码】\n", indent, v);
    printf("%s  站点 %lu : %s\n", indent, site, DiagSiteName(site));
    printf("%s  detail 0x%04lX (%lu)", indent, detail, detail);
    if (site == KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_NO_TRANSFER ||
        site == KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_PAIRING) {
        printf("  ->");
        PrintStateMask(detail);
    } else if (site == KSWORD_ARK_HVM_VMCS_DIAG_SITE_REQUIRED_CONTROLS) {
        printf("  ->");
        if ((detail & KSWORD_ARK_HVM_VMCS_DIAG_CTL_SECONDARY_ACTIVATE) != 0UL) {
            printf(" 无 SECONDARY_CONTROLS");
        }
        if ((detail & KSWORD_ARK_HVM_VMCS_DIAG_CTL_EPT) != 0UL) { printf(" 无 EPT"); }
        if ((detail & KSWORD_ARK_HVM_VMCS_DIAG_CTL_HOST_64) != 0UL) {
            printf(" 无 HOST_64_BIT");
        }
        if ((detail & KSWORD_ARK_HVM_VMCS_DIAG_CTL_ENTRY_IA32E) != 0UL) {
            printf(" 无 ENTRY_IA32E");
        }
    }
    printf("\n");
    printf("%s  架构错误码 %lu  %s\n", indent,
           KSWORD_ARK_HVM_VMCS_DIAG_ARCH(v),
           ArchVmInstructionErrorName(KSWORD_ARK_HVM_VMCS_DIAG_ARCH(v)));
}

/* ------------------------------------------------------------------------ */
/* 退出遥测：reason + qualification 的解码                                    */
/* ------------------------------------------------------------------------ */

/*
 * 这几个值（lastExitReason / lastExitQualification / lastGuestRip /
 * lastGuestRsp / lastExitInstructionLength）协议里一直有，只是从来没打印过。
 * 它们是目前唯一一条**不经过串口**的退出观测面 —— 内核调试器的报告通道自己
 * 就是端口 I/O，而端口 I/O 正是待查的现象，"kd 没打印" 与 "那条指令没执行"
 * 之间没有任何蕴含关系。
 */
static const char* ExitReasonName(unsigned long r)
{
    switch (r) {
    case 0UL:  return "EXCEPTION_OR_NMI";
    case 1UL:  return "EXTERNAL_INTERRUPT";
    case 2UL:  return "TRIPLE_FAULT";
    case 3UL:  return "INIT_SIGNAL";
    case 4UL:  return "SIPI";
    case 7UL:  return "INTERRUPT_WINDOW";
    case 8UL:  return "NMI_WINDOW";
    case 9UL:  return "TASK_SWITCH";
    case 10UL: return "CPUID";
    case 11UL: return "GETSEC";
    case 12UL: return "HLT";
    case 13UL: return "INVD";
    case 14UL: return "INVLPG";
    case 15UL: return "RDPMC";
    case 16UL: return "RDTSC";
    case 17UL: return "RSM";
    case 18UL: return "VMCALL";
    /*
     * 19..27 是**另一个 hypervisor 在我们下面跑**时产生的那一族。
     * 编号与 hvm_nested.c 的 KSW_VMX_EXIT_* 保持一致（那边是派发侧的权威
     * 定义），改任何一边都要对着另一边核。写这一段是因为在真机上看 VMware
     * 的第一份直方图时，这九个原因原本全打印成"见 SDM Appendix C"，
     * 而它们恰恰是唯一要看的那几行。
     */
    case 19UL: return "VMCLEAR";
    case 20UL: return "VMLAUNCH";
    case 21UL: return "VMPTRLD";
    case 22UL: return "VMPTRST";
    case 23UL: return "VMREAD";
    case 24UL: return "VMRESUME";
    case 25UL: return "VMWRITE";
    case 26UL: return "VMXOFF";
    case 27UL: return "VMXON";
    case 28UL: return "MOV_CR";
    case 29UL: return "MOV_DR";
    case 30UL: return "IO_INSTRUCTION";
    case 31UL: return "RDMSR";
    case 32UL: return "WRMSR";
    case 33UL: return "VM_ENTRY_FAILURE_GUEST_STATE";
    case 34UL: return "VM_ENTRY_FAILURE_MSR_LOADING";
    case 36UL: return "MWAIT";
    case 37UL: return "MONITOR_TRAP_FLAG";
    case 39UL: return "MONITOR";
    case 40UL: return "PAUSE";
    case 48UL: return "EPT_VIOLATION";
    case 49UL: return "EPT_MISCONFIGURATION";
    case 50UL: return "INVEPT";
    case 51UL: return "RDTSCP";
    case 52UL: return "VMX_PREEMPTION_TIMER";
    case 53UL: return "INVVPID";
    case 54UL: return "WBINVD";
    case 55UL: return "XSETBV";
    case 58UL: return "INVPCID";
    case 59UL: return "VMFUNC";
    default:   return "见 SDM Appendix C";
    }
}

/*
 * exit reason 30 的退出限定符布局（SDM Table 28-5）：
 *   bits 2:0  访问宽度  0=1B 1=2B 3=4B
 *   bit  3    方向      1=IN
 *   bit  4    字符串指令
 *   bit  5    REP 前缀
 *   bit  6    操作数编码 1=DX 0=立即数
 *   bits31:16 端口号
 */
static void PrintIoQualification(const char* indent, unsigned long long q)
{
    static const unsigned int sizes[8] = { 1U, 2U, 0U, 4U, 0U, 0U, 0U, 0U };
    unsigned int width = sizes[(unsigned int)(q & 0x7ULL)];
    unsigned int port = (unsigned int)((q >> 16) & 0xFFFFULL);

    printf("%s  端口         : 0x%04X (%u)\n", indent, port, port);
    printf("%s  方向/宽度    : %s  %u 字节%s%s  操作数=%s\n", indent,
           ((q >> 3) & 1ULL) ? "IN " : "OUT",
           width,
           ((q >> 4) & 1ULL) ? "  字符串" : "",
           ((q >> 5) & 1ULL) ? "  REP" : "",
           ((q >> 6) & 1ULL) ? "DX" : "立即数");
}

/*
 * 执行控制：实际生效的值，以及其中哪些位是**被强制的**。
 *
 * 能力 MSR 的低 32 位是 allowed-0：位为 1 表示那一位必须为 1，不管请求方要不要。
 * 所以 `强制 = 低32位`，而"我们主动要的"就是 `生效 & ~强制`。
 *
 * 这个区分是本函数存在的全部理由：只看生效值，分不清一条退出是我们自己要拦的，
 * 还是外层 hypervisor 逼我们拦的 —— 前者可以优化掉，后者不能。
 */
static void PrintControlLine(const char* name,
                             unsigned long active,
                             unsigned long long capability)
{
    unsigned long forced = (unsigned long)(capability & 0xFFFFFFFFULL);
    unsigned long forcedActive = active & forced;
    unsigned long requested = active & ~forced;

    printf("  %-10s: 0x%08lX   被强制 0x%08lX   自选 0x%08lX\n",
           name, active, forcedActive, requested);
}

static void PrintActiveControls(const KSWORD_ARK_QUERY_HVM_RESPONSE* rsp)
{
    if (rsp->activePinControls == 0UL &&
        rsp->activePrimaryControls == 0UL &&
        rsp->activeExitControls == 0UL) {
        printf("  执行控制     : （尚未配置过常驻，无记录）\n");
        return;
    }
    printf("  执行控制     : 生效值 / 能力 MSR 的 allowed-0 强制位\n");
    PrintControlLine("pin", rsp->activePinControls, rsp->pinCapability);
    PrintControlLine("primary", rsp->activePrimaryControls,
                     rsp->primaryCapability);
    PrintControlLine("secondary", rsp->activeSecondaryControls,
                     rsp->secondaryCapability);
    PrintControlLine("exit", rsp->activeExitControls, rsp->exitCapability);
    PrintControlLine("entry", rsp->activeEntryControls, rsp->entryCapability);
    /*
     * HLT exiting 单独点名：退出直方图上它是最大的一项，而常驻模式并不请求它，
     * 所以它到底是不是被强制的，直接决定那一大块开销能不能动。
     */
    {
        unsigned long hlt = 1UL << 7;
        unsigned long forced =
            (unsigned long)(rsp->primaryCapability & 0xFFFFFFFFULL);

        if ((rsp->activePrimaryControls & hlt) != 0UL) {
            printf("    HLT exiting: 生效%s\n",
                   ((forced & hlt) != 0UL)
                       ? "，且**被能力 MSR 强制**（外层要求，我们关不掉）"
                       : "，但**没有被强制** —— 是我们自己请求的");
        } else {
            printf("    HLT exiting: 未生效\n");
        }
    }
}

/*
 * 按退出原因的直方图：退出到底花在哪。
 *
 * `count` 和 `lastExitReason` 合起来答不了这个问题 —— 把 "reason=18" 读一百遍，
 * 也分不清 VMCALL 是占了 99% 还是只是碰巧排在最后一个。
 *
 * 只打非零项，并按次数从多到少排，因为有意义的是**头部**：占住绝大多数退出的那
 * 一两种原因就是这台机器的性能与行为画像，尾部的一次两次通常是噪声。
 */
static void PrintExitReasonHistogram(
    const char* indent,
    const KSWORD_ARK_QUERY_HVM_RESPONSE* rsp)
{
    unsigned long order[KSWORD_ARK_HVM_EXIT_REASON_SLOTS];
    unsigned long nonZero = 0UL;
    unsigned long i = 0UL;
    unsigned long j = 0UL;
    unsigned long long total = 0ULL;

    for (i = 0UL; i < KSWORD_ARK_HVM_EXIT_REASON_SLOTS; ++i) {
        if (rsp->exitReasonCount[i] != 0ULL) {
            order[nonZero++] = i;
            total += rsp->exitReasonCount[i];
        }
    }
    if (nonZero == 0UL) {
        return;
    }
    /* 插入排序：最多 96 项，且几乎总是个位数。 */
    for (i = 1UL; i < nonZero; ++i) {
        unsigned long key = order[i];
        j = i;
        while (j > 0UL &&
               rsp->exitReasonCount[order[j - 1UL]] <
                   rsp->exitReasonCount[key]) {
            order[j] = order[j - 1UL];
            --j;
        }
        order[j] = key;
    }
    printf("%s退出分布     : 合计 %llu，%lu 种原因\n", indent, total, nonZero);
    for (i = 0UL; i < nonZero; ++i) {
        unsigned long reason = order[i];
        unsigned long long value = rsp->exitReasonCount[reason];

        printf("%s  %5.1f%%  %10llu  reason=%-3lu %s\n",
               indent,
               (double)value * 100.0 / (double)total,
               value,
               reason,
               ExitReasonName(reason));
    }
}

static void PrintExitTelemetry(const char* indent,
                               unsigned long long count,
                               unsigned long reason,
                               unsigned long long qualification,
                               unsigned long long guestRip,
                               unsigned long long guestRsp,
                               unsigned long instructionLength)
{
    printf("%s退出         : count=%llu  reason=%lu (%s)  instrLen=%lu\n",
           indent, count, reason, ExitReasonName(reason), instructionLength);
    if (count == 0ULL && reason == 0UL && qualification == 0ULL &&
        guestRip == 0ULL) {
        printf("%s  （尚无退出记录）\n", indent);
        return;
    }
    printf("%s  qualification: 0x%016llX\n", indent, qualification);
    printf("%s  guestRip     : 0x%016llX   guestRsp: 0x%016llX\n",
           indent, guestRip, guestRsp);
    if (reason == 30UL) {
        PrintIoQualification(indent, qualification);
    }
}

static HANDLE OpenDevice(void)
{
    HANDLE h = CreateFileW(KSW_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "打不开 %ls：win32=%lu\n", KSW_DEVICE_PATH, GetLastError());
        fprintf(stderr, "  2 = 设备不存在（驱动没加载）；5 = 拒绝访问（需要管理员）\n");
    }
    return h;
}

/* ------------------------------------------------------------------------ */
/* 只读查询                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * 从**用户态**执行 CPUID，报告来宾看到的 hypervisor 身份。
 *
 * 这是 resident-nested-hidehv 的判据，而且是比任何状态字段都近的一个：它走的就是
 * VMware 判断"下面有没有 hypervisor"时走的那条路 —— 同一个特权级、同一个叶。
 * 状态里多一个"隐藏=开"的标志只能证明请求被接受了，证明不了退出派发器真的改了
 * 返回值；而这里读到的四个寄存器就是改没改本身。
 *
 * 不需要驱动句柄：常驻在跑的时候，这条 CPUID 本身就会退出到我们手里。
 */
/*
 * Name which of the entry path's refusals stopped the last L2 launch.
 *
 * The numbers are assigned in hvm_nested_l2.c at the refusal sites themselves.
 * They exist because all seven report the same architectural error to L1 —
 * Intel has one number for "invalid control field" and no field to say which —
 * so from outside, seven different problems produce one indistinguishable
 * symptom.
 */
static const char* RefusalSiteName(unsigned short site)
{
    switch (site) {
    case 0U: return "没有拒绝过";
    case 1U: return "熔断已跳闸，拒绝再次进入同一个 L2";
    case 2U: return "缺资源（vmcs02 页 / 物理窗口）";
    case 3U: return "L1 的 EPT12 指针不可用（影子层次装不起来）";
    case 4U: return "没有可用的 EPT 指针";
    case 5U: return "位图页缺失（MSR / IO 位图合并没产出页）";
    case 6U: return "virtual-APIC 页地址读回来是零（该校验默认**关闭**，见 KSW_L2_ENFORCE_VIRTUAL_APIC_PAGE）";
    case 7U: return "vmcs02 的 VMPTRLD 失败";
    case 8U: return "virtual-APIC 页地址非零但未页对齐（同上，默认关闭）";
    default: return "未知编号";
    }
}

static int DoCpuidView(int asJson)
{
    int leaf1[4] = { 0, 0, 0, 0 };
    int hv[4] = { 0, 0, 0, 0 };
    int hvVendor[4] = { 0, 0, 0, 0 };
    char vendor[13];
    int present = 0;

    __cpuidex(leaf1, 1, 0);
    __cpuidex(hv, 0x40000000, 0);
    /* 保留一份未改写的副本用于拼厂商串。 */
    hvVendor[0] = hv[0];
    hvVendor[1] = hv[1];
    hvVendor[2] = hv[2];
    hvVendor[3] = hv[3];
    /* CPUID.1:ECX bit 31 —— 架构上专留给"有 hypervisor"的那一位。 */
    present = ((unsigned int)leaf1[2] & 0x80000000U) != 0U ? 1 : 0;
    /* 厂商串按 EBX、ECX、EDX 的顺序，12 个字节。 */
    memcpy(vendor + 0, &hvVendor[1], 4);
    memcpy(vendor + 4, &hvVendor[2], 4);
    memcpy(vendor + 8, &hvVendor[3], 4);
    vendor[12] = '\0';
    {
        size_t i = 0;
        /* 非可打印字节一律换成点，免得控制字符把输出弄乱。 */
        for (i = 0; i < 12; ++i) {
            if (vendor[i] < 0x20 || vendor[i] > 0x7E) {
                vendor[i] = (vendor[i] == '\0') ? '\0' : '.';
            }
        }
    }

    if (asJson) {
        printf("{\"kind\":\"cpuidView\",\"hypervisorPresent\":%s,"
               "\"leaf1Ecx\":\"0x%08X\","
               "\"hvLeafEax\":\"0x%08X\",\"hvVendor\":",
               present ? "true" : "false",
               (unsigned int)leaf1[2],
               (unsigned int)hvVendor[0]);
        KswordHvmPrintJsonString(vendor);
        printf(",\"hidden\":%s}\n",
               (!present && hvVendor[0] == 0) ? "true" : "false");
        return 0;
    }

    printf("\n=== 来宾用户态看到的 CPUID ===\n");
    printf("  CPUID.1:ECX          : 0x%08X\n", (unsigned int)leaf1[2]);
    printf("  bit31 hypervisor 位  : %s\n", present ? "**有**" : "无");
    printf("  CPUID.40000000:EAX   : 0x%08X\n", (unsigned int)hvVendor[0]);
    printf("  hypervisor 厂商      : \"%s\"\n", vendor);
    printf("  结论                 : %s\n",
           (!present && hvVendor[0] == 0)
               ? "用户态问不出下面有 hypervisor（隐藏生效）"
               : "用户态能看出下面有 hypervisor");
    printf("\n  这两个值就是 VMware 的 IOPL_Init 用来判断的那两个。它认出外层是\n"
           "  别人家的 hypervisor 就会去要 WHP，要不到就在装载任何虚拟机之前拒绝。\n");
    return 0;
}

static const char* SvmProbeRejectName(unsigned long reason)
{
    switch (reason) {
    case KSWORD_ARK_SVM_REJECT_NONE: return "NONE";
    case KSWORD_ARK_SVM_REJECT_CPUID_RANGE: return "CPUID_RANGE";
    case KSWORD_ARK_SVM_REJECT_SVM_NPT_ASID: return "SVM_NPT_ASID";
    case KSWORD_ARK_SVM_REJECT_NRIP: return "NRIP_REQUIRED";
    case KSWORD_ARK_SVM_REJECT_MSR_READ: return "MSR_READ_FAILED";
    case KSWORD_ARK_SVM_REJECT_FIRMWARE: return "FIRMWARE_DISABLED";
    case KSWORD_ARK_SVM_REJECT_SVME: return "SVME_ALREADY_ENABLED";
    case KSWORD_ARK_SVM_REJECT_HSAVE: return "HSAVE_NONZERO";
    case KSWORD_ARK_SVM_REJECT_CR4: return "CR4_UNSUPPORTED_STATE";
    case KSWORD_ARK_SVM_REJECT_XSAVE: return "XSAVE_OSXSAVE_REQUIRED";
    case KSWORD_ARK_SVM_REJECT_XSTATE_READ: return "XSTATE_READ_FAILED";
    case KSWORD_ARK_SVM_REJECT_XSS: return "XSS_NONZERO";
    case KSWORD_ARK_SVM_REJECT_PHYSICAL_WIDTH: return "PHYSICAL_WIDTH_UNSUPPORTED";
    case KSWORD_ARK_SVM_REJECT_CET_STATE: return "CET_STATE_UNSUPPORTED";
    default: return "UNKNOWN";
    }
}

static int DoQuery(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST req;
    KSWORD_ARK_QUERY_HVM_RESPONSE rsp;
    DWORD returned = 0;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);

    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (returned < sizeof(rsp)) {
        fprintf(stderr, "QUERY_HVM 响应过短：%lu 字节（需要 %zu）\n",
                returned, sizeof(rsp));
        return 1;
    }

    if (asJson) {
        printf("{\"kind\":\"query\",\"queryStatus\":%lu,\"stateFlags\":%lu,"
               "\"stateFlagsHex\":\"0x%08lX\",\"stateNames\":",
               rsp.queryStatus, rsp.stateFlags, rsp.stateFlags);
        PrintStateBitsJson(rsp.stateFlags);
        printf(",\"backend\":%lu,\"slatType\":%lu,\"slatReady\":%lu,\"backendStatus\":\"0x%08lX\",\"powerGeneration\":%lu",
               rsp.backend, rsp.slatType, rsp.slatReady, rsp.backendStatus, rsp.powerGeneration);
        printf(",\"svmProbe\":{\"maxLeaf\":%lu,\"features\":%lu,\"asidCount\":%lu,\"physicalBits\":%lu,\"msrValidMask\":%lu,\"exceptionStatus\":\"0x%08lX\",\"vmCr\":\"0x%016llX\",\"efer\":\"0x%016llX\",\"hsave\":\"0x%016llX\",\"pat\":\"0x%016llX\"",
               rsp.svmCapabilities.maxLeaf, rsp.svmCapabilities.features, rsp.svmCapabilities.asidCount, rsp.svmCapabilities.physicalBits,
               rsp.svmCapabilities.msrValidMask, rsp.svmCapabilities.exceptionStatus, rsp.svmCapabilities.vmCr,
               rsp.svmCapabilities.efer, rsp.svmCapabilities.hsave, rsp.svmCapabilities.pat);
        printf(",\"rejectReason\":%lu,\"rejectReasonName\":\"%s\",\"stateValidMask\":%lu,\"cpuid1Ecx\":\"0x%08lX\",\"xsaveFeatures\":\"0x%08lX\",\"cr4\":\"0x%016llX\",\"xcr0\":\"0x%016llX\",\"xss\":\"0x%016llX\"}",
               rsp.svmCapabilities.rejectReason, SvmProbeRejectName(rsp.svmCapabilities.rejectReason),
               rsp.svmCapabilities.stateValidMask, rsp.svmCapabilities.cpuid1Ecx, rsp.svmCapabilities.xsaveFeatures,
               rsp.svmCapabilities.cr4, rsp.svmCapabilities.xcr0, rsp.svmCapabilities.xss);
        printf(",\"featureNames\":");
        PrintFeatureBitsJson(rsp.featureFlags);
        printf(",\"generation\":%lu,\"processorCount\":%lu,"
               "\"preparedProcessorCount\":%lu,\"selfTestPassedProcessorCount\":%lu,"
               "\"residentProcessorCount\":%lu,"
               "\"residentImplementation\":\"%s\",\"eptImplementation\":\"%s\","
               "\"nestedImplementation\":\"%s\",\"evmcsImplementation\":\"%s\","
               "\"featureFlags\":\"0x%016llX\","
               "\"vmxEptVpidCapabilities\":\"0x%016llX\","
               "\"eptExecuteOnly\":%s,"
               "\"eptPointer\":\"0x%016llX\","
               /*
                * 身份映射的形状：窗口覆盖到哪里、各级各有多少项。
                *
                * 界面一直显示这几个数，命令行却没有——于是"这台机器的映射建成
                * 什么样"只能靠界面回答，而排查这件事的时候恰恰常常没有界面。
                */
               "\"highestMappedPhysicalAddress\":\"0x%016llX\","
               "\"eptPml4Entries\":%lu,\"eptPdptEntries\":%lu,"
               "\"eptLargePageEntries\":%lu,"
               "\"eptPageCount\":%lu,\"mappedRamMiB\":%llu,\"vmExitCount\":%llu,"
               "\"lastExitReason\":%lu,\"lastExitQualification\":\"0x%016llX\","
               "\"lastGuestRip\":\"0x%016llX\",\"lastGuestRsp\":\"0x%016llX\","
               "\"lastExitInstructionLength\":%lu,"
               "\"lastStatus\":\"0x%08lX\","
               "\"vmxBasic\":\"0x%016llX\","
               "\"cr0Fixed0\":\"0x%016llX\",\"cr0Fixed1\":\"0x%016llX\","
               "\"cr4Fixed0\":\"0x%016llX\",\"cr4Fixed1\":\"0x%016llX\","
               "\"lastVmInstructionError\":%lu,"
               "\"eventCount\":%lu,"
               "\"droppedEventCount\":%lu,"
               "\"overwrittenEventCount\":%lu,"
               "\"publishedEventCount\":%llu,"
               "\"nestedL2LaunchRefusedCount\":%lu,"
               "\"nestedVmcs12EvictionCount\":%lu,"
               "\"nestedFuseTripCount\":%lu,"
               "\"nestedLastRefusalSite\":%u,"
               "\"nestedLastRefusalSiteText\":",
               rsp.generation, rsp.processorCount,
               rsp.preparedProcessorCount, rsp.selfTestPassedProcessorCount,
               rsp.residentProcessorCount,
               ImplementationName(rsp.residentImplementation),
               ImplementationName(rsp.eptImplementation),
               ImplementationName(rsp.nestedImplementation),
               ImplementationName(rsp.evmcsImplementation),
               rsp.featureFlags,
               rsp.vmxEptVpidCapabilities,
               ((rsp.vmxEptVpidCapabilities & 1ULL) != 0ULL) ? "true" : "false",
               rsp.eptPointer,
               rsp.highestMappedPhysicalAddress,
               rsp.eptPml4Entries, rsp.eptPdptEntries,
               rsp.eptLargePageEntries,
               rsp.eptPageCount, rsp.mappedRamBytes / (1024ULL * 1024ULL),
               rsp.vmExitCount,
               rsp.lastExitReason, rsp.lastExitQualification,
               rsp.lastGuestRip, rsp.lastGuestRsp,
               rsp.lastExitInstructionLength,
               (unsigned long)rsp.lastStatus,
               rsp.vmxBasic,
               rsp.cr0Fixed0, rsp.cr0Fixed1,
               rsp.cr4Fixed0, rsp.cr4Fixed1,
               rsp.lastVmInstructionError,
               rsp.eventCount, rsp.droppedEventCount,
               rsp.overwrittenEventCount, rsp.publishedEventCount,
               rsp.nestedL2LaunchRefusedCount,
               rsp.nestedVmcs12EvictionCount,
               rsp.nestedFuseTripCount,
               (unsigned)rsp.nestedLastRefusalSite);
        KswordHvmPrintJsonString(RefusalSiteName(rsp.nestedLastRefusalSite));
        /*
         * 只发非零项，键是退出原因编号。
         *
         * 96 项里绝大多数恒为零，全发出去会让每次 status 的 JSON 里多出一大片
         * 没有信息的 "0"，而脚本要的是"这一轮退出都花在哪"。
         */
        {
            unsigned long slot = 0UL;
            int emitted = 0;

            printf(",\"exitReasonCount\":{");
            for (slot = 0UL;
                 slot < KSWORD_ARK_HVM_EXIT_REASON_SLOTS;
                 ++slot) {
                if (rsp.exitReasonCount[slot] == 0ULL) {
                    continue;
                }
                printf("%s\"%lu\":%llu",
                       emitted ? "," : "",
                       slot,
                       rsp.exitReasonCount[slot]);
                emitted = 1;
            }
            printf("}");
        }
        PrintCpuRows(&rsp, 1);
        printf("}\n");
        return 0;
    }

    printf("\n=== HVM 状态（只读）===\n");
    printf("  queryStatus  : %lu\n", rsp.queryStatus);
    PrintStateBits("  状态位       : ", rsp.stateFlags);
    printf("  代次         : %lu\n", rsp.generation);
    printf("  处理器       : total=%lu prepared=%lu selfTestPassed=%lu resident=%lu\n",
           rsp.processorCount, rsp.preparedProcessorCount,
           rsp.selfTestPassedProcessorCount, rsp.residentProcessorCount);
    printf("  实现         : resident=%s ept=%s nested=%s evmcs=%s\n",
           ImplementationName(rsp.residentImplementation),
           ImplementationName(rsp.eptImplementation),
           ImplementationName(rsp.nestedImplementation),
           ImplementationName(rsp.evmcsImplementation));
    /*
     * 两个耐久的嵌套计数器：拒绝过多少次 L2 启动，丢过多少份 vmcs12。
     *
     * 无条件打印，不做"非零才显示"。零本身就是要读的那个值，而缺这一行分不清
     * 是"没发生过"还是"这个工具还不认识这个字段"——后者恰恰在换协议的时候出现，
     * 也正是最需要相信读数的时候。
     *
     * 驱逐非零的含义很具体：某个 L1 手里的 VMCS 比池子能装的多。被驱逐那份下次
     * VMPTRLD 回来字段全零，在 L1 看来就跟"只建模一份 vmcs12"那个缺陷一样，
     * 所以这个数是事后唯一能把两者分开的东西。
     */
    printf("  嵌套计数     : 拒绝 L2 启动 %lu 次   vmcs12 驱逐 %lu 份%s\n",
           rsp.nestedL2LaunchRefusedCount,
           rsp.nestedVmcs12EvictionCount,
           (rsp.nestedVmcs12EvictionCount != 0UL)
               ? "  **池子装不下这个 L1 的 VMCS**"
               : "");
    printf("                 无进展熔断跳闸 %lu 次%s\n",
           rsp.nestedFuseTripCount,
           (rsp.nestedFuseTripCount != 0UL)
               ? "  **我们停掉过某个 L1 的来宾：它在原地打转**"
               : "");
    printf("                 末次拒绝原因 : %u = %s\n",
           (unsigned)rsp.nestedLastRefusalSite,
           RefusalSiteName(rsp.nestedLastRefusalSite));
    /*
     * 退出安全物理窗口的就绪数。
     *
     * 它的准备期自检在别处一个字都看不见：过不了只会让嵌套 L2 进入和影子 EPT
     * 合成安静地拒绝，而状态位、成熟度、处理器计数没有一个会变——一个验不出
     * 结果的自检和根本没有自检，从读数上分不开。
     *
     * 拿 processorCount 比对不对：窗口是在**驱动初始化**时建的，不是准备资源
     * 时建的，所以什么都还没准备的时候它也应该是满的。这里改用逻辑处理器数做
     * 分母，否则刚加载完驱动去看，会看到 "N / 0" 这种读不出意思的东西。
     */
    printf("  退出安全窗口 : %lu / %lu 个处理器已就绪%s\n",
           rsp.physWindowReadyCount,
           (unsigned long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS),
           rsp.physWindowReadyCount >=
                   (unsigned long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)
               ? ""
               : "  **不足：缺窗口的核上嵌套 L2 与影子 EPT 会被拒**");
    PrintFeatureBits("  ", rsp.featureFlags);
    PrintEptVpidCapability("  ", rsp.vmxEptVpidCapabilities);
    printf("  EPT          : pointer=0x%016llX pages=%lu mappedRam=%llu MiB\n",
           rsp.eptPointer, rsp.eptPageCount,
           rsp.mappedRamBytes / (1024ULL * 1024ULL));
    printf("  lastStatus   : 0x%08lX\n", (unsigned long)rsp.lastStatus);
    /*
     * 这五个值查询早就返回了，只是一直没打印。CR0/CR4 的固定位是判断
     * "L0 允许什么" 的第一手依据 —— 嵌套下它们由 L0 合成，与裸机可能不同。
     */
    printf("  vmxBasic     : 0x%016llX\n", rsp.vmxBasic);
    printf("  CR0 fixed    : fixed0=0x%016llX fixed1=0x%016llX\n",
           rsp.cr0Fixed0, rsp.cr0Fixed1);
    printf("  CR4 fixed    : fixed0=0x%016llX fixed1=0x%016llX\n",
           rsp.cr4Fixed0, rsp.cr4Fixed1);
    PrintVmInstructionError("  ", rsp.lastVmInstructionError);
    PrintExitTelemetry("  ", rsp.vmExitCount, rsp.lastExitReason,
                       rsp.lastExitQualification, rsp.lastGuestRip,
                       rsp.lastGuestRsp, rsp.lastExitInstructionLength);
    PrintExitReasonHistogram("  ", &rsp);
    PrintActiveControls(&rsp);
    printf("  CPU / HV     : %.12s / %.12s\n", rsp.cpuVendor, rsp.hypervisorVendor);
    PrintCpuRows(&rsp, 0);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* 生命周期控制                                                              */
/* ------------------------------------------------------------------------ */

static int DoControl(HANDLE h, const HVM_CTL_VERB* verb,
                     unsigned long soakMs, int asJson)
{
    KSWORD_ARK_CONTROL_HVM_REQUEST req;
    KSWORD_ARK_CONTROL_HVM_RESPONSE rsp;
    DWORD returned = 0;

    KSWORD_ARK_QUERY_HVM_RESPONSE snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    KSWORD_ARK_QUERY_HVM_REQUEST query;
    memset(&query, 0, sizeof(query));
    query.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    query.size = sizeof(query);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &query, sizeof(query),
                         &snapshot, sizeof(snapshot), &returned, NULL) || returned != sizeof(snapshot)) {
        fprintf(stderr, "HVM state query failed before control: Win32 %lu\n", GetLastError());
        return 1;
    }
    if (snapshot.queryStatus != 0) {
        /* A capability refusal must be distinguishable from an empty/crashed CLI. */
        if (asJson) {
            printf("{\"kind\":\"control\",\"command\":\"%s\",\"stage\":\"capability-query\","
                   "\"controlSubmitted\":false,\"queryStatus\":%lu,\"lastStatus\":\"0x%08lX\","
                   "\"generation\":%lu,\"stateFlags\":%lu}\n", verb->name,
                   snapshot.queryStatus, (unsigned long)snapshot.lastStatus,
                   snapshot.generation, snapshot.stateFlags);
        } else {
            fprintf(stderr, "HVM control refused before submission: queryStatus=%lu NTSTATUS=0x%08lX\n",
                    snapshot.queryStatus, (unsigned long)snapshot.lastStatus);
        }
        return 2;
    }
    memset(&rsp, 0, sizeof(rsp));
    KswordArkHvmBuildControlRequest(&req, verb->command, verb->flags,
                                   snapshot.generation, soakMs);

    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_CONTROL_HVM, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL)) {
        /*
         * 安全策略拒绝走的是"返回非成功 NTSTATUS"那条路，DeviceIoControl 会失败，
         * 但响应缓冲仍然被填过。所以这里不能直接放弃 —— 先看够不够长。
         */
        DWORD win32 = GetLastError();
        if (returned < sizeof(rsp)) {
            if (asJson) {
                printf("{\"kind\":\"control\",\"command\":\"%s\",\"transport\":\"failed\","
                       "\"win32\":%lu,\"bytesReturned\":%lu}\n",
                       verb->name, win32, returned);
            } else {
                fprintf(stderr, "  DeviceIoControl 失败：win32=%lu，返回 %lu 字节\n",
                        win32, returned);
            }
            return 1;
        }
        /* 缓冲完整：继续按协议结果解读，下面会打印 status 与 lastStatus。 */
    }
    if (returned < sizeof(rsp)) {
        if (asJson) {
            printf("{\"kind\":\"control\",\"command\":\"%s\",\"transport\":\"short\","
                   "\"bytesReturned\":%lu}\n", verb->name, returned);
        } else {
            fprintf(stderr, "  响应过短：%lu 字节（需要 %zu）\n",
                    returned, sizeof(rsp));
        }
        return 1;
    }

    if (asJson) {
        printf("{\"kind\":\"control\",\"command\":\"%s\",\"status\":%lu,"
               "\"statusName\":\"%s\",\"lastStatus\":\"0x%08lX\","
               "\"oldStateFlags\":%lu,\"newStateFlags\":%lu,"
               "\"oldStateHex\":\"0x%08lX\",\"newStateHex\":\"0x%08lX\","
               "\"newStateNames\":",
               verb->name, rsp.status, ControlStatusName(rsp.status),
               (unsigned long)rsp.lastStatus,
               rsp.oldStateFlags, rsp.newStateFlags,
               rsp.oldStateFlags, rsp.newStateFlags);
        PrintStateBitsJson(rsp.newStateFlags);
        printf(",\"oldGeneration\":%lu,\"newGeneration\":%lu,"
               "\"preparedProcessorCount\":%lu,\"selfTestPassedProcessorCount\":%lu,"
               "\"failedProcessorCount\":%lu,\"residentProcessorCount\":%lu,"
               "\"residentImplementation\":\"%s\",\"eptImplementation\":\"%s\","
               "\"nestedImplementation\":\"%s\",\"evmcsImplementation\":\"%s\","
               "\"eptPointer\":\"0x%016llX\",\"eptPageCount\":%lu,"
               "\"eptPml4EntryBudget\":%lu,"
               "\"eptRuleCount\":%lu,\"mappedRamMiB\":%llu,"
               "\"vmExitCount\":%llu,\"lastExitReason\":%lu,"
               "\"lastExitQualification\":\"0x%016llX\","
               "\"lastGuestRip\":\"0x%016llX\",\"lastGuestRsp\":\"0x%016llX\","
               "\"lastExitInstructionLength\":%lu,"
               "\"lastVmInstructionError\":%lu,"
               "\"soakElapsedMilliseconds\":%lu,"
               "\"soakUnexpectedDevirtualizations\":%lu}\n",
               rsp.oldGeneration, rsp.newGeneration,
               rsp.preparedProcessorCount, rsp.selfTestPassedProcessorCount,
               rsp.failedProcessorCount, rsp.residentProcessorCount,
               ImplementationName(rsp.residentImplementation),
               ImplementationName(rsp.eptImplementation),
               ImplementationName(rsp.nestedImplementation),
               ImplementationName(rsp.evmcsImplementation),
               rsp.eptPointer, rsp.eptPageCount, rsp.eptPml4EntryBudget,
               rsp.eptRuleCount,
               rsp.mappedRamBytes / (1024ULL * 1024ULL),
               rsp.vmExitCount, rsp.lastExitReason,
               rsp.lastExitQualification, rsp.lastGuestRip,
               rsp.lastGuestRsp, rsp.lastExitInstructionLength,
               rsp.lastVmInstructionError,
               rsp.soakElapsedMilliseconds,
               rsp.soakUnexpectedDevirtualizations);
        return (rsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK) ? 0 : 2;
    }

    printf("\n=== %s（command=%lu，flags=0x%lX）===\n",
           verb->description, verb->command, verb->flags);
    printf("  status       : %lu (%s)   lastStatus=0x%08lX\n",
           rsp.status, ControlStatusName(rsp.status),
           (unsigned long)rsp.lastStatus);
    PrintStateBits("  旧状态位     : ", rsp.oldStateFlags);
    PrintStateBits("  新状态位     : ", rsp.newStateFlags);
    printf("  代次         : %lu -> %lu\n", rsp.oldGeneration, rsp.newGeneration);
    /*
     * failedProcessorCount 是 hvm_runtime.c 现算的 ProcessorCount -
     * SelfTestPassedProcessorCount，**不是**失败计数。PREPARE 之后它必然等于
     * 处理器总数，那只表示"还没有处理器通过自检"。这里如实标注，免得又把它
     * 当成四个核都挂了。
     */
    printf("  处理器       : prepared=%lu selfTestPassed=%lu resident=%lu\n",
           rsp.preparedProcessorCount, rsp.selfTestPassedProcessorCount,
           rsp.residentProcessorCount);
    printf("               （未通过自检 = %lu，注意这不是失败计数）\n",
           rsp.failedProcessorCount);
    printf("  实现         : resident=%s ept=%s nested=%s evmcs=%s\n",
           ImplementationName(rsp.residentImplementation),
           ImplementationName(rsp.eptImplementation),
           ImplementationName(rsp.nestedImplementation),
           ImplementationName(rsp.evmcsImplementation));
    printf("  EPT          : pointer=0x%016llX pages=%lu rules=%lu mappedRam=%llu MiB\n",
           rsp.eptPointer, rsp.eptPageCount, rsp.eptRuleCount,
           rsp.mappedRamBytes / (1024ULL * 1024ULL));
    /*
     * 窗口大小是这个驱动编译时的常量，本工具自己的头文件里那份在版本不齐时
     * 正好是错的 —— 而恰恰是版本不齐时最需要知道它。
     */
    printf("               （身份映射窗口 = %lu 个 PML4 项 = %llu TiB）\n",
           rsp.eptPml4EntryBudget,
           ((unsigned long long)rsp.eptPml4EntryBudget * 512ULL) / 1024ULL);
    PrintExitTelemetry("  ", rsp.vmExitCount, rsp.lastExitReason,
                       rsp.lastExitQualification, rsp.lastGuestRip,
                       rsp.lastGuestRsp, rsp.lastExitInstructionLength);
    PrintVmInstructionError("  ", rsp.lastVmInstructionError);
    if (verb->command == KSWORD_ARK_HVM_CONTROL_SOAK) {
        printf("  soak         : elapsed=%lu ms  意外退虚拟化=%lu\n",
               rsp.soakElapsedMilliseconds,
               rsp.soakUnexpectedDevirtualizations);
    }
    /*
     * NOT_PREPARED 这个名字会骗人，所以拿到它就必须把缺的那一位指出来。
     *
     * 进入常驻要求**四个**状态位齐备（hvm_runtime.c:1920-1928）：
     * RESOURCES_READY | EPT_READY | SELF_TEST_PASSED | GUEST_READY。
     * 缺任何一个都回同一个 STATUS_DEVICE_NOT_READY，被映射成 NOT_PREPARED
     * （hvm_runtime.c:2086-2088）。于是资源明明准备好了、只差一次 self-test，
     * 报出来的却是"未准备"——字面意思把人引向"去 prepare"，而重复 prepare
     * 会返回 ALREADY_PREPARED 并把状态打成 FAULTED，越修越远。
     *
     * 这四种缺失在协议上不可分辨（一个码），但在**状态位**上完全可分辨，
     * 而响应里就带着 newStateFlags。所以这里不猜，直接读它。
     */
    if (rsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED) {
        const unsigned long f = rsp.newStateFlags;
        printf("  ** NOT_PREPARED 拆解 **：进入常驻要求四个位齐备，"
               "缺哪一个都报这同一个码。\n");
        printf("     RESOURCES_READY  : %s\n",
               (f & KSWORD_ARK_HVM_STATE_RESOURCES_READY) ? "有" : "**缺** -> prepare");
        printf("     EPT_READY        : %s\n",
               (f & KSWORD_ARK_HVM_STATE_EPT_READY) ? "有" : "**缺** -> prepare");
        printf("     SELF_TEST_PASSED : %s\n",
               (f & KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED) ? "有" : "**缺** -> self-test");
        printf("     GUEST_READY      : %s\n",
               (f & KSWORD_ARK_HVM_STATE_GUEST_READY) ? "有" : "**缺** -> self-test");
        if ((f & KSWORD_ARK_HVM_STATE_FAULTED) != 0UL ||
            (f & KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED) != 0UL) {
            printf("     另外 FAULTED/ROLLBACK_REQUIRED 已置位，"
                   "先 reset-fault，否则后续命令还会被拒。\n");
        }
    }
    return (rsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK) ? 0 : 2;
}

/* ------------------------------------------------------------------------ */
/* 平台探针：三个能否决"退虚拟化返回用户态"的量                              */
/* ------------------------------------------------------------------------ */

/*
 * KVA shadow 在用户态就查得到，不需要驱动去猜 nt!KiKvaShadow 的地址：
 * SystemKernelVaShadowInformation 是 NtQuerySystemInformation 的一个类，
 * 直接把 KvaShadowEnabled 这些位交出来。硬找符号既脆又没必要。
 */
#define KSW_SYSTEM_KERNEL_VA_SHADOW_INFORMATION 196

typedef struct _KSW_KVA_SHADOW_INFO
{
    unsigned long Flags;
} KSW_KVA_SHADOW_INFO;

typedef LONG (__stdcall* KSW_NT_QUERY_SYSTEM_INFORMATION)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

/* 返回 0 = 查到了（*Flags 有效）；非 0 = 没查到，原因写进 stderr。 */
static int QueryKvaShadow(unsigned long* Flags)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    KSW_NT_QUERY_SYSTEM_INFORMATION fn = NULL;
    KSW_KVA_SHADOW_INFO info;
    ULONG returned = 0;
    LONG st = 0;

    if (ntdll == NULL) { return 1; }
    fn = (KSW_NT_QUERY_SYSTEM_INFORMATION)(void*)
        GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (fn == NULL) { return 2; }
    memset(&info, 0, sizeof(info));
    st = fn(KSW_SYSTEM_KERNEL_VA_SHADOW_INFORMATION,
            &info, (ULONG)sizeof(info), &returned);
    if (st < 0) {
        fprintf(stderr, "NtQuerySystemInformation(196) 失败：0x%08lX\n",
                (unsigned long)st);
        return 3;
    }
    *Flags = info.Flags;
    return 0;
}

static int DoProbePlatform(HANDLE h, int asJson)
{
    KSWORD_ARK_HVM_PLATFORM_REQUEST req;
    KSWORD_ARK_HVM_PLATFORM_RESPONSE rsp;
    DWORD returned = 0;
    unsigned long kva = 0UL;
    int kvaOk = 0;
    int cetActive = 0;
    int cetSupported = 0;
    int incomplete = 0;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.version = KSWORD_ARK_HVM_PLATFORM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_PLATFORM, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL)) {
        fprintf(stderr, "PLATFORM 探针失败：win32=%lu\n", GetLastError());
        return 1;
    }
    kvaOk = (QueryKvaShadow(&kva) == 0);

    /*
     * 探针"跑完了"不等于"标定到了"。八个字段任何一个没读到、或 KVA 查询失败，
     * 这一轮就没有完成它存在的目的 —— 必须让退出码非零，否则控制脚本记 OK、
     * 验收记 PASS，而实际上什么都没标定。这条线上已经吃过一次同型的亏。
     */
    if (rsp.validMask != KSW_PLATFORM_VALID_ALL || !kvaOk) {
        incomplete = 1;
    }

    /* CR4.CET 是 bit23；CPUID.(7,0).ECX bit7 是 CET_SS 的存在性。 */
    cetActive = ((rsp.validMask & KSWORD_ARK_HVM_PLATFORM_VALID_CR4) != 0UL) &&
                ((rsp.cr4 & (1ULL << 23)) != 0ULL);
    cetSupported =
        ((rsp.validMask & KSWORD_ARK_HVM_PLATFORM_VALID_CPUID7) != 0UL) &&
        ((rsp.cpuid7Ecx & (1UL << 7)) != 0UL);

    if (asJson) {
        printf("{\"kind\":\"probe-platform\",\"validMask\":\"0x%08lX\","
               "\"exceptionCode\":\"0x%08lX\",\"irql\":%lu,"
               "\"cr4\":\"0x%016llX\",\"cetActive\":%s,\"cetSupported\":%s,"
               "\"supervisorCet\":\"0x%016llX\",\"userCet\":\"0x%016llX\","
               "\"efer\":\"0x%016llX\",\"fsBase\":\"0x%016llX\","
               "\"gsBase\":\"0x%016llX\",\"kernelGsBase\":\"0x%016llX\","
               "\"cpuid7Ecx\":\"0x%08lX\",\"cpuid7Edx\":\"0x%08lX\","
               "\"kvaQueryOk\":%s,\"kvaFlags\":\"0x%08lX\","
               "\"kvaShadowEnabled\":%s}\n",
               rsp.validMask, rsp.exceptionCode, rsp.irql,
               rsp.cr4, cetActive ? "true" : "false",
               cetSupported ? "true" : "false",
               rsp.supervisorCet, rsp.userCet, rsp.efer,
               rsp.fsBase, rsp.gsBase, rsp.kernelGsBase,
               rsp.cpuid7Ecx, rsp.cpuid7Edx,
               kvaOk ? "true" : "false", kva,
               (kvaOk && (kva & 1UL)) ? "true" : "false");
        return incomplete ? 3 : 0;
    }

    printf("\n=== 平台探针（只读，不进 VMX）===\n");
    printf("  采样 IRQL    : %lu %s\n", rsp.irql,
           rsp.irql == 0UL ? "(PASSIVE_LEVEL，符合预期)" : "(**不是 PASSIVE**)");
    printf("  有效位       : 0x%08lX", rsp.validMask);
    if (rsp.exceptionCode != 0UL) {
        printf("   最后一次读异常 0x%08lX", rsp.exceptionCode);
    }
    printf("\n\n");

    printf("  [1] 影子栈 (CET)\n");
    printf("      CPUID.(7,0).ECX bit7 : %s\n",
           cetSupported ? "支持 CET_SS" : "不支持");
    printf("      CR4.CET(bit23)       : %s   (CR4 = 0x%016llX)\n",
           cetActive ? "**开着**" : "关着", rsp.cr4);
    if ((rsp.validMask & KSWORD_ARK_HVM_PLATFORM_VALID_S_CET) != 0UL) {
        printf("      IA32_S_CET           : 0x%016llX\n", rsp.supervisorCet);
    } else {
        printf("      IA32_S_CET           : 读不到（这台机器没有这个 MSR）\n");
    }
    if ((rsp.validMask & KSWORD_ARK_HVM_PLATFORM_VALID_U_CET) != 0UL) {
        printf("      IA32_U_CET           : 0x%016llX\n", rsp.userCet);
    } else {
        printf("      IA32_U_CET           : 读不到\n");
    }
    /*
     * CR4.CET 与"真的有影子栈在用"是两件事，别混。
     * CR4.CET=1 只说明这台机器把 CET 打开了；实际有没有影子栈要看
     * IA32_S_CET（内核）与 IA32_U_CET（用户）的 SH_STK_EN。
     * 而且 U_CET 是**每线程**由操作系统换进换出的 —— 在这里读到 0，
     * 只说明**当前这个线程**没有用户影子栈，说明不了别的线程。
     */
    if (!cetActive) {
        printf("      => 不构成阻碍\n");
    } else if ((rsp.supervisorCet & 1ULL) != 0ULL) {
        printf("      => 内核影子栈**在用**（S_CET.SH_STK_EN=1）：退虚拟化要回到\n"
               "         内核态本身就得管影子栈 —— 这是硬阻碍\n");
    } else {
        printf("      => CET 在 CR4 里开着，但内核影子栈没启用（S_CET=0）。\n"
               "         ring-3 的 IRET 只在目标线程有用户影子栈时才走那套协议，\n"
               "         而 U_CET 是每线程的、这里读到的 0 只代表当前线程 ——\n"
               "         **算复杂度而不是硬阻碍，且未标定**。\n");
    }

    printf("\n  [2] 内核地址空间隔离 (KVA shadow)\n");
    if (!kvaOk) {
        printf("      查询失败 —— **不要当成\"没开\"**，这一项算未标定\n");
    } else {
        printf("      Flags                : 0x%08lX\n", kva);
        printf("      KvaShadowEnabled     : %s\n",
               (kva & 1UL) ? "**开着**" : "关着");
        printf("      => %s\n", (kva & 1UL)
            ? "用户态退出时 GUEST_CR3 是用户影子 PML4；VMXOFF 之后写回去"
              "\n         等于把内核从地址空间里抹掉 —— **三重故障**"
            : "不构成阻碍");
    }

    printf("\n  [3] GS base\n");
    printf("      IA32_GS_BASE         : 0x%016llX  (内核态下应当是 KPCR)\n",
           rsp.gsBase);
    printf("      IA32_KERNEL_GS_BASE  : 0x%016llX  (应当是用户 TEB)\n",
           rsp.kernelGsBase);
    printf("      IA32_FS_BASE         : 0x%016llX\n", rsp.fsBase);
    printf("      IA32_EFER            : 0x%016llX\n", rsp.efer);

    printf("\n  判定：");
    if (!kvaOk) {
        printf("KVA shadow 未标定，不下结论。\n");
    } else if ((kva & 1UL) != 0UL) {
        printf("**KVA shadow 开着** —— 用户态退出时写回 guest CR3 会抹掉内核，\n");
        printf("        跨特权级返回这条路不成立，而且现有的 CR3 恢复也有隐患。\n");
    } else if (cetActive && (rsp.supervisorCet & 1ULL) != 0ULL) {
        printf("**内核影子栈在用** —— 跨特权级返回这条路不成立。\n");
    } else {
        printf("两个否决理由都**不成立**（KVA shadow 关、内核影子栈没启用）。\n");
        printf("        顺带：现有的 `__writecr3(GuestCr3)` 在这台机器上没有隐患。\n");
        printf("        但 fail-open 那条**承重**理由不受影响，仍然拦着 ——\n");
        printf("        见 docs/next/用户态退虚拟化决策.md。\n");
    }
    if (incomplete) {
        printf("\n  ** 本轮没有标定完 **  validMask=0x%08lX（期望 0x%08lX）%s\n",
               rsp.validMask, (unsigned long)KSW_PLATFORM_VALID_ALL,
               kvaOk ? "" : "，且 KVA 查询失败");
        printf("     上面的判定只能当参考，不要拿它下结论。\n");
    }
    return incomplete ? 3 : 0;
}

/* ------------------------------------------------------------------------ */
/* 负向探针：验"应该拒绝"的那几条真的拒绝了                                  */
/* ------------------------------------------------------------------------ */

/* 定义在下面的 execute-only 探针一节，两处共用。 */
static int ProbeControl(HANDLE h, unsigned long command, unsigned long flags,
                        const char* what);

/*
 * 这一组全是**负向**判据 —— 每一条都期望被拒绝，而且期望被拒绝在**具体的
 * 那个地方**。正路好测，负路容易只看"反正失败了"就算过，那正是这条线上
 * 反复吃亏的地方：一个笼统的 INVALID_REQUEST 和一个精确的能力拒绝，
 * 现象一样、含义完全不同。
 *
 * 全部只发请求、不改任何状态。每条独立判定，一条失败不影响其余。
 */

/*
 * 三态，不是两态。
 *
 * "拒绝了"和"在**该拒绝的地方**拒绝了"是两回事。前置没建立时驱动会先返回
 * NOT_PREPARED，那时任何 `status != 某个值` 的断言都会**空过** —— 报 PASS
 * 而什么都没测到。这类静默空过比 FAIL 危险得多，所以单独一态。
 */
#define NEG_PASS 0
#define NEG_FAIL 1
#define NEG_VOID 2   /* 无区分力：前置没建立，这一条这次没测到 */

typedef struct _NEG_CASE
{
    const char* name;
    int verdict;
    unsigned long observed;
    long observedNt;
    const char* expectation;
    const char* remark;   /* 可为 NULL */
} NEG_CASE;

static const char* NegName(int v)
{
    return (v == NEG_PASS) ? "PASS" : ((v == NEG_FAIL) ? "FAIL" : "空过");
}

static void NegReport(const NEG_CASE* c, int asJson, int first)
{
    if (asJson) {
        printf("%s{\"name\":\"%s\",\"verdict\":\"%s\",\"status\":%lu,"
               "\"lastStatus\":\"0x%08lX\",\"expected\":\"%s\"",
               first ? "" : ",", c->name, NegName(c->verdict),
               c->observed, (unsigned long)c->observedNt, c->expectation);
        if (c->remark != NULL) { printf(",\"remark\":\"%s\"", c->remark); }
        printf("}");
        return;
    }
    printf("  [%-4s] %-34s status=%-2lu nt=0x%08lX\n",
           NegName(c->verdict), c->name, c->observed,
           (unsigned long)c->observedNt);
    if (c->verdict != NEG_PASS) {
        printf("          期望：%s\n", c->expectation);
    }
    if (c->remark != NULL) {
        printf("          注：%s\n", c->remark);
    }
}

static int DoProbeFlags(HANDLE h, int asJson)
{
    KSWORD_ARK_HVM_EPT_RULE_REQUEST rreq;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rrsp;
    KSWORD_ARK_CONTROL_HVM_REQUEST creq;
    KSWORD_ARK_CONTROL_HVM_RESPONSE crsp;
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    DWORD returned = 0;
    NEG_CASE cases[4];
    unsigned int n = 0U;
    unsigned int i = 0U;
    int failed = 0;
    int voided = 0;

    memset(cases, 0, sizeof(cases));

    /* --- 1. ENFORCE 必须在安装期就被拒，且是 UNIMPLEMENTED 不是别的 --- */
    memset(&rreq, 0, sizeof(rreq));
    memset(&rrsp, 0, sizeof(rrsp));
    rreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    rreq.size = (unsigned long)sizeof(rreq);
    rreq.operation = KSWORD_ARK_HVM_EPT_RULE_ADD;
    rreq.flags = KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE;
    rreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    rreq.deniedAccess = KSWORD_ARK_HVM_EPT_ACCESS_READ;
    rreq.physicalAddress = 0x1000ULL;
    rreq.pageCount = 1ULL;
    (void)DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &rreq, sizeof(rreq),
                          &rrsp, (DWORD)sizeof(rrsp), &returned, NULL);
    cases[n].name = "ENFORCE 安装期拒绝";
    cases[n].observed = rrsp.status;
    cases[n].observedNt = rrsp.lastStatus;
    cases[n].expectation = "status=8 UNIMPLEMENTED（不是 0，也不是笼统的 1）";
    /*
     * 这一条与 prepare 状态无关：拒绝点在锁外、在 Initialized 检查之前，
     * 所以任何时候都有完整区分力。
     */
    cases[n].verdict =
        (rrsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_UNIMPLEMENTED)
            ? NEG_PASS : NEG_FAIL;
    ++n;

    /* --- 2. ENABLE_VE 必须进得了白名单，然后被**能力**拒绝 --- */
    memset(&creq, 0, sizeof(creq));
    memset(&crsp, 0, sizeof(crsp));
    creq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    creq.size = (unsigned long)sizeof(creq);
    creq.command = KSWORD_ARK_HVM_CONTROL_START_RESIDENT;
    creq.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                 KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
                 KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VE;
    creq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    (void)DeviceIoControl(h, IOCTL_KSWORD_ARK_CONTROL_HVM, &creq, sizeof(creq),
                          &crsp, (DWORD)sizeof(crsp), &returned, NULL);
    cases[n].name = "ENABLE_VE 死在能力门而非白名单";
    cases[n].observed = crsp.status;
    cases[n].observedNt = crsp.lastStatus;
    cases[n].expectation =
        "status=3 UNSUPPORTED_CPU（过了白名单、死在 #VE 能力判定）";
    /*
     * 三态在这里是必须的。驱动的前置检查
     * （RESOURCES_READY|EPT_READY|SELF_TEST_PASSED 三个齐）排在**所有能力门
     * 之前**，没齐就先返回 NOT_PREPARED。那时写成 `status != 1` 会当场空过 ——
     * 报 PASS 而白名单到底放没放行根本没被检验。
     */
    if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST) {
        cases[n].verdict = NEG_FAIL;
        cases[n].remark = "白名单回归了：请求在门口就被拒，没到能力判定";
    } else if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED) {
        cases[n].verdict = NEG_VOID;
        cases[n].remark =
            "前置未建立（要 prepare + self-test 都过），本条这次无区分力";
    } else if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU) {
        cases[n].verdict = NEG_PASS;
    } else if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK) {
        cases[n].verdict = NEG_FAIL;
        cases[n].remark = "**常驻被真的起起来了** —— 靶机居然有 #VE，需要停掉";
    } else {
        cases[n].verdict = NEG_VOID;
        cases[n].remark = "拒绝了，但不是在 #VE 能力门上，判不出白名单";
    }
    ++n;

    /*
     * 用例之间必须清 FAULTED，否则后面的用例是"因为错误的理由通过"的。
     *
     * 实测：用例 2 那次被拒的 START_RESIDENT 会把状态打成 FAULTED，
     * 于是用例 3 撞上 hvm_resident.c 的 FAULTED/ROLLBACK/UNLOAD_GUARD 门
     * （返回 STATUS_INVALID_DEVICE_STATE，协议 status=20 LIFECYCLE_GUARD_FAILED）
     * —— 它确实被拒了，但拒它的根本不是互斥判定。报成"互斥门 PASS"是假的。
     */
    (void)ProbeControl(h, KSWORD_ARK_HVM_CONTROL_RESET_FAULT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE,
                       "RESET_FAULT(用例间清场)");

    /* --- 3. LOCAL_EPT + VMFUNC 互斥，必须被拒 --- */
    memset(&creq, 0, sizeof(creq));
    memset(&crsp, 0, sizeof(crsp));
    creq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    creq.size = (unsigned long)sizeof(creq);
    creq.command = KSWORD_ARK_HVM_CONTROL_START_RESIDENT;
    creq.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                 KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
                 KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT |
                 KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC;
    creq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    (void)DeviceIoControl(h, IOCTL_KSWORD_ARK_CONTROL_HVM, &creq, sizeof(creq),
                          &crsp, (DWORD)sizeof(crsp), &returned, NULL);
    cases[n].name = "LOCAL_EPT + VMFUNC 被拒";
    cases[n].observed = crsp.status;
    cases[n].observedNt = crsp.lastStatus;
    cases[n].expectation = "被拒；但在嵌套靶机上拒它的是 VMFUNC 能力门，不是互斥门";
    /*
     * 说清楚这一条**测不到互斥门**：VMFUNC 的能力判定排在互斥判定之前，
     * 而嵌套 Hyper-V 不暴露 EPTP switching，所以永远轮不到互斥那一条。
     * 报成"互斥门 PASS"是不诚实的。
     */
    if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK) {
        cases[n].verdict = NEG_FAIL;
        cases[n].remark = "**没拒绝** —— 两个互斥的能力被同时接受了";
    } else if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED) {
        cases[n].verdict = NEG_VOID;
        cases[n].remark = "前置未建立，本条这次无区分力";
    } else if (crsp.status ==
                   KSWORD_ARK_HVM_CONTROL_STATUS_LIFECYCLE_GUARD_FAILED) {
        /*
         * 拒它的是 FAULTED/ROLLBACK/UNLOAD_GUARD 那道门，不是能力门也不是
         * 互斥门 —— 上一条用例的残留没清干净。算空过，不算通过。
         */
        cases[n].verdict = NEG_VOID;
        cases[n].remark =
            "拒在生命周期守卫（状态里还带 FAULTED/ROLLBACK）——"
            "用例间清场没生效，本条无区分力";
    } else if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU) {
        cases[n].verdict = NEG_PASS;
        cases[n].remark =
            "拒在 VMFUNC 能力门（靶机不暴露 EPTP switching）——"
            "**互斥门本身在这台机器上测不到**";
    } else {
        cases[n].verdict = NEG_PASS;
        cases[n].remark = "被拒了，但不是在能力门也不是在互斥门上";
    }
    ++n;

    /* --- 4. 上面三条都不该把常驻启起来 --- */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    (void)DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                          &qrsp, (DWORD)sizeof(qrsp), &returned, NULL);
    cases[n].name = "负向用例没有留下常驻";
    cases[n].observed = qrsp.residentProcessorCount;
    cases[n].observedNt = qrsp.lastStatus;
    cases[n].expectation = "residentProcessorCount = 0";
    cases[n].verdict =
        (qrsp.residentProcessorCount == 0UL) ? NEG_PASS : NEG_FAIL;
    ++n;

    for (i = 0U; i < n; ++i) {
        if (cases[i].verdict == NEG_FAIL) { failed = 1; }
        if (cases[i].verdict == NEG_VOID) { voided = 1; }
    }

    if (asJson) {
        printf("{\"kind\":\"probe-flags\",\"failed\":%s,\"inconclusive\":%s,"
               "\"cases\":[",
               failed ? "true" : "false", voided ? "true" : "false");
        for (i = 0U; i < n; ++i) { NegReport(&cases[i], 1, i == 0U); }
        printf("]}\n");
        return failed ? 2 : (voided ? 3 : 0);
    }

    printf("\n=== 负向探针（全部期望被拒绝）===\n");
    for (i = 0U; i < n; ++i) { NegReport(&cases[i], 0, i == 0U); }
    if (failed) {
        printf("\n  判定：**有用例没有按预期被拒绝** —— 看上面标 FAIL 的那几条\n");
    } else if (voided) {
        printf("\n  判定：没有 FAIL，但**有用例空过** —— 前置没建立，那几条这次\n");
        printf("        什么都没测到。先 prepare + self-test 再跑，否则等于没测。\n");
    } else {
        printf("\n  判定：四条全部在**该拒绝的地方**拒绝了\n");
    }
    /* 空过与失败分开返回，脚本才能把"没测到"和"测出问题"区分开。 */
    return failed ? 2 : (voided ? 3 : 0);
}

/* ------------------------------------------------------------------------ */
/* execute-only 探针                                                         */
/* ------------------------------------------------------------------------ */

/*
 * 回答两个不同的问题，两者都不需要改动驱动：
 *
 *   Q1 驱动认为 execute-only 可用吗？
 *      ADD 一条只拒 READ 的规则，回读**归一化之后**的 deniedAccess。
 *      协议注释写得很清楚：拒 READ 必然连带拒 WRITE；而 execute-only
 *      不被支持时会**连 EXECUTE 一起拒**。所以回读 0x3 = 保住了 X，
 *      回读 0x7 = 这台机器上根本编码不出 execute-only 叶。
 *
 *   Q2 下面那个 hypervisor 认这个权限吗？
 *      这才是嵌套下的真问题：L0 为 L1 合成影子 EPT 时，可能把 X-only
 *      提升成 RX。真提升了的话 CLOAK 会**静默失效** —— 无错误码、无事件、
 *      无蓝屏，只是藏不住。所以只能实测：真的去读那一页，看会不会挨打。
 *
 * 观测量是**常驻掉没掉**，不是"读有没有抛异常"。
 *
 * 曾经用过 ENFORCE（命中注 #PF，指望 SEH 接住），那是死循环：注进去的 #PF
 * 落到 guest 自己的缺页处理器上，而 guest 的页表说那一页好好的 —— 拒绝发生
 * 在 EPT 层，guest 完全看不见 —— 于是它什么都不修就返回、重执行那条指令、
 * 再次 EPT 违规、再次 #PF，永远出不来，SEH 根本没机会介入。实测把整个脚本
 * 挂在那里。
 *
 * 不带 ENFORCE 的严格命中走的是另一条路：派发器 return FALSE ⇒ 退虚拟化
 * （hvm_ept.c 的"Unruled accesses and any strict overlapping rule
 * devirtualize"）。VMXOFF 之后那条指令原生重执行，**读会正常完成**，
 * 而 residentProcessorCount 掉到 0。这条路会终止，而且判据是一个整数
 * 不是一个异常。代价是常驻被打掉 —— 反正探针跑完也要停。
 *
 * 顺序被驱动钉死了，不能随便改：**常驻运行期间任何改动规则的操作都被拒绝**
 * （hvm_runtime.c 的 ResidentProcessorCount != 0 分支，返回 PARTIAL /
 * STATUS_DEVICE_BUSY）。理由是退出路径不加 PASSIVE_LEVEL 锁就扫规则表，
 * 所以规则表与每一张分裂叶必须在常驻期间保持不可变。
 * 于是只能是：装规则 → 起常驻 → 读 → 停常驻 → 清规则。
 *
 * 而那一页是本进程的内存，必须活到常驻起来 —— 所以整件事只能在**同一个
 * 进程**里做完，包括由这个工具自己发 START_RESIDENT 与 STOP_RESIDENT。
 */

/* 发一条生命周期控制命令，只关心成功与否。 */
static int ProbeControl(HANDLE h, unsigned long command, unsigned long flags,
                        const char* what)
{
    KSWORD_ARK_CONTROL_HVM_REQUEST req;
    KSWORD_ARK_CONTROL_HVM_RESPONSE rsp;
    DWORD returned = 0;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.command = command;
    req.flags = flags;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_CONTROL_HVM, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL) ||
        rsp.status != KSWORD_ARK_HVM_CONTROL_STATUS_OK) {
        fprintf(stderr, "%s 失败：status=%lu (%s) nt=0x%08lX win32=%lu\n",
                what, rsp.status, ControlStatusName(rsp.status),
                (unsigned long)rsp.lastStatus, GetLastError());
        return 0;
    }
    return 1;
}
/*
 * tlb-probe：直接测"跨处理器 TLB 失效在常驻下还灵不灵"。
 *
 * 要回答的是 hvm_exit.c 转发段那条标着 unmeasured 的隐患：我们把 guest 的
 * HvCallFlushVirtualAddressSpace/List 原样转发给 L0，而**兄弟逻辑处理器此刻正
 * 作为我们的 guest 在跑**，L0 的失效是否覆盖到嵌套 guest 上下文是未知的。
 * 注释预言的形状是"静默数据损坏、随机符号的 bugcheck、需要两个以上虚拟处理器"，
 * 与 2026-09-07 那次 0x139 逐条对上。
 *
 * 注释建议的测法是"单处理器对多处理器的长时间对照"，但那是统计实验：靠撞低概率
 * 崩溃取证，跑完没崩什么也证明不了。这里换一条**确定性**判据。
 *
 * VirtualProtect 返回的语义就是"所有处理器都已经看到新保护"，而它内部正是靠
 * 跨核 TLB shootdown 兑现这个语义，那条 shootdown 在 Hyper-V 来宾里走的就是被
 * 我们转发的那个 hypercall。所以：
 *
 *   1. 主线程把一页改成 PAGE_NOACCESS，**等 VirtualProtect 返回**
 *   2. 返回之后才把 epoch 推成奇数，宣告"从现在起谁读到内容都是违规"
 *   3. 绑在别的处理器上的工作线程在奇数 epoch 里读这一页
 *   4. 读**成功**就是陈旧翻译 —— 它用的是一条本该已被失效的映射
 *
 * epoch 前后各读一次、要求两次相同，是为了排掉"读之前窗口就已经关了"那种情况：
 * 窗口一变就不计入，宁可漏计也不误判。
 *
 * 判据不是"崩没崩"，是 violations 这个数。跑之前/之后各在常驻起与不起两种状态
 * 下各跑一轮，就是那个单核/多核对照的确定性版本：常驻没起时违规必须是 0
 * （那是基线，证明探针本身没毛病），常驻起了还是 0 才说明转发没有丢失效。
 *
 * 纯用户态，不碰任何 IOCTL（只在开头查一次常驻状态用于报告），不改页表，
 * 不动驱动。跑崩不了机器。
 */
typedef struct _KSW_TLB_WORKER
{
    volatile unsigned char* page;
    volatile LONG* epoch;
    volatile LONG* stop;
    unsigned long processorIndex;
    /*
     * 置位时，每次读之前先执行一条 CPUID。
     *
     * CPUID 是**无条件** VM exit，所以这是从用户态强制本处理器退出一次的最便宜
     * 办法。它验证的是修法的前提：未启用 VPID 时 VM entry 会失效与 VPID 0000H
     * 关联的线性映射，因此"把兄弟核打出去一次"就应当足以刷掉陈旧翻译。
     *
     * 前提成立 ⇒ 违规数应当塌到 0，那时去实现"转发 flush 时发 NMI 把兄弟核打
     * 出来"才有意义。前提不成立 ⇒ 违规照旧，那条修法从根上就不通，省下整个实现。
     */
    int forceExit;
    unsigned long long reads;
    unsigned long long violations;
    unsigned long long faults;
} KSW_TLB_WORKER;

static DWORD WINAPI TlbProbeWorker(LPVOID param)
{
    KSW_TLB_WORKER* w = (KSW_TLB_WORKER*)param;
    DWORD_PTR mask = (DWORD_PTR)1 << (w->processorIndex & 63U);

    /* 绑核。绑不上就照跑 —— 少一个核的覆盖，不是错误。 */
    (void)SetThreadAffinityMask(GetCurrentThread(), mask);

    while (InterlockedCompareExchange((LONG*)w->stop, 0L, 0L) == 0L) {
        LONG e1 = InterlockedCompareExchange((LONG*)w->epoch, 0L, 0L);
        LONG e2 = 0L;
        int ok = 0;

        /* 只在"禁止访问"窗口里测；偶数 epoch 期间读到内容是正常的。 */
        if ((e1 & 1L) == 0L) {
            YieldProcessor();
            continue;
        }
        if (w->forceExit) {
            int regs[4];
            /* 无条件 VM exit。退出+进入应当刷掉本核的线性映射缓存。 */
            __cpuid(regs, 0);
        }
        __try {
            /* volatile 保证这次访问真的发出去，不被优化掉。 */
            (void)w->page[0];
            ok = 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ok = 0;
        }
        e2 = InterlockedCompareExchange((LONG*)w->epoch, 0L, 0L);
        w->reads += 1ULL;
        if (!ok) {
            /* 拿到 AV，这是**正确**结果：失效生效了。 */
            w->faults += 1ULL;
        } else if (e2 == e1) {
            /*
             * 整个读都发生在同一个奇数 epoch 里，也就是完全落在
             * VirtualProtect(NOACCESS) 已返回之后、还没放开之前，
             * 却读成功了 —— 这条翻译本该已经被失效掉。
             */
            w->violations += 1ULL;
        }
    }
    return 0;
}

static int DoTlbProbe(HANDLE h, int asJson, unsigned long durationMs,
                      int forceExit)
{
    KSW_TLB_WORKER workers[64];
    HANDLE threads[64];
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    DWORD returned = 0;
    SYSTEM_INFO si;
    volatile unsigned char* page = NULL;
    volatile LONG epoch = 0L;
    volatile LONG stop = 0L;
    unsigned long processorCount = 0UL;
    unsigned long residentBefore = 0UL;
    unsigned long residentAfter = 0UL;
    unsigned long workerCount = 0UL;
    unsigned long i = 0UL;
    unsigned long long totalReads = 0ULL;
    unsigned long long totalViolations = 0ULL;
    unsigned long long totalFaults = 0ULL;
    unsigned long long cycles = 0ULL;
    DWORD startTick = 0;
    DWORD oldProtect = 0;
    int rc = 1;

    memset(workers, 0, sizeof(workers));
    memset(threads, 0, sizeof(threads));

    if (durationMs == 0UL) {
        durationMs = 5000UL;
    }

    /* 只读一次状态，用于报告 —— 起停常驻由调用方负责。 */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                        &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        residentBefore = qrsp.residentProcessorCount;
        processorCount = qrsp.processorCount;
    }

    GetSystemInfo(&si);
    if (processorCount == 0UL) {
        processorCount = (unsigned long)si.dwNumberOfProcessors;
    }

    /*
     * 每个处理器一个工作线程，主线程另算。单核上也照跑 —— 那一轮的意义正是
     * 基线：没有兄弟处理器，违规必须是 0。
     */
    workerCount = (unsigned long)si.dwNumberOfProcessors;
    if (workerCount == 0UL) {
        workerCount = 1UL;
    }
    if (workerCount > 64UL) {
        workerCount = 64UL;
    }

    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    page[0] = 0xA5U;

    for (i = 0UL; i < workerCount; ++i) {
        workers[i].page = page;
        workers[i].epoch = &epoch;
        workers[i].stop = &stop;
        workers[i].processorIndex = i;
        workers[i].forceExit = forceExit;
        threads[i] = CreateThread(NULL, 0, TlbProbeWorker,
                                  &workers[i], 0, NULL);
        if (threads[i] == NULL) {
            fprintf(stderr, "CreateThread 失败：win32=%lu\n", GetLastError());
            InterlockedExchange((LONG*)&stop, 1L);
            goto cleanup;
        }
    }

    startTick = GetTickCount();
    for (;;) {
        unsigned long spin = 0UL;

        if ((GetTickCount() - startTick) >= durationMs) {
            break;
        }
        /* 关门。VirtualProtect 返回即代表所有处理器都该看到新保护了。 */
        if (!VirtualProtect((LPVOID)page, 4096, PAGE_NOACCESS, &oldProtect)) {
            fprintf(stderr, "VirtualProtect(NOACCESS) 失败：win32=%lu\n",
                    GetLastError());
            break;
        }
        /* 返回之后才宣告窗口开始 —— 顺序反了会把正常读记成违规。 */
        InterlockedIncrement((LONG*)&epoch);
        for (spin = 0UL; spin < 20000UL; ++spin) {
            YieldProcessor();
        }
        /* 先关窗口，再放开保护，同样是为了不误判。 */
        InterlockedIncrement((LONG*)&epoch);
        if (!VirtualProtect((LPVOID)page, 4096, PAGE_READWRITE, &oldProtect)) {
            fprintf(stderr, "VirtualProtect(READWRITE) 失败：win32=%lu\n",
                    GetLastError());
            break;
        }
        page[0] = 0xA5U;
        cycles += 1ULL;
    }
    InterlockedExchange((LONG*)&stop, 1L);
    rc = 0;

cleanup:
    for (i = 0UL; i < workerCount; ++i) {
        if (threads[i] != NULL) {
            (void)WaitForSingleObject(threads[i], 10000);
            (void)CloseHandle(threads[i]);
        }
    }
    /* 保护可能停在 NOACCESS 上，先放开再释放。 */
    (void)VirtualProtect((LPVOID)page, 4096, PAGE_READWRITE, &oldProtect);

    for (i = 0UL; i < workerCount; ++i) {
        totalReads += workers[i].reads;
        totalViolations += workers[i].violations;
        totalFaults += workers[i].faults;
    }

    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                        &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        residentAfter = qrsp.residentProcessorCount;
    }

    if (asJson) {
        printf("{\"kind\":\"%s\",\"durationMs\":%lu,"
               "\"processorCount\":%lu,\"workerThreads\":%lu,"
               "\"residentBefore\":%lu,\"residentAfter\":%lu,"
               "\"protectCycles\":%llu,\"windowedReads\":%llu,"
               "\"faults\":%llu,\"violations\":%llu,\"verdict\":\"%s\"}\n",
               forceExit ? "tlb-probe-exit" : "tlb-probe",
               durationMs, processorCount, workerCount,
               residentBefore, residentAfter,
               cycles, totalReads, totalFaults, totalViolations,
               totalViolations != 0ULL
                   ? "stale-translation-observed"
                   : (totalReads == 0ULL ? "no-samples" : "coherent"));
    } else {
        printf("\n=== 跨处理器 TLB 失效探针 ===\n");
        printf("  时长/处理器数 : %lu ms / %lu（工作线程 %lu）\n",
               durationMs, processorCount, workerCount);
        printf("  常驻核数      : %lu -> %lu\n", residentBefore, residentAfter);
        printf("  保护翻转      : %llu 轮\n", cycles);
        printf("  窗口内取样    : %llu 次   AV %llu 次\n",
               totalReads, totalFaults);
        printf("  **违规**      : %llu 次\n", totalViolations);
        if (totalViolations != 0ULL) {
            printf("  判定          : stale-translation-observed\n");
            printf("    有处理器在 VirtualProtect(NOACCESS) 已经返回之后，仍然\n"
                   "    用一条本该失效的映射读到了内容。这正是转发段注释里那条\n"
                   "    unmeasured 隐患的形状。\n");
        } else if (totalReads == 0ULL) {
            printf("  判定          : no-samples（窗口没被取到，加长时长或核数）\n");
        } else {
            printf("  判定          : coherent（本轮没观察到陈旧翻译）\n");
            printf("    注意这是**没观察到**，不是证明不存在。要有说服力，\n"
                   "    常驻不起那一轮必须也是 0（基线），且取样数要足够大。\n");
        }
    }
    (void)VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    return rc;
}

/*
 * rule-allowonce：装一条 ALLOW_ONCE 规则，看安装期的门放不放行。
 *
 * 为什么值得单独一个动词：ALLOW_ONCE 把 EPT 叶临时放宽一条指令再用
 * monitor-trap 复原，在**共享**层次上那个窗口全机可见。运行期有门挡着
 * （不满足就 fail-closed），但那太晚 —— 规则装上了、报成功了，直到某次真的
 * 命中，整台机器才退出 VMX。安装期该拒的就在安装期拒。
 *
 * 这条路径在产品里是可达的：GUI 的 KernelHvmTab 行为下拉第二项就是它，
 * 而工具里此前没有任何动词会设这个位 —— 于是这道门装上也没法验。
 *
 * 本动词只报**事实**，不替调用方判对错：处理器数、两个相关能力位、
 * 安装返回的 status。判据留给外面 —— 多核且没武装私有 EPT 时应当是
 * gate-refused，其余情况 installed 才对。装上了就当场删掉，不留脏。
 */
static int DoRuleAllowOnceGate(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    KSWORD_ARK_HVM_EPT_RULE_REQUEST rreq;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rrsp;
    DWORD returned = 0;
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;
    unsigned long processorCount = 0UL;
    unsigned long long features = 0ULL;
    int hasInveptSingle = 0;
    int hasMonitorTrap = 0;
    int removed = 0;
    const char* verdict = "unknown";
    int rc = 1;

    /* --- 0. 常驻必须没在跑：常驻期间规则表不可变 --- */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (qrsp.residentProcessorCount != 0UL) {
        fprintf(stderr,
                "常驻正在跑（residentProcessorCount=%lu）。\n"
                "常驻期间规则表是不可变的，装不上规则。先 hvm_ctl stop。\n",
                qrsp.residentProcessorCount);
        return 1;
    }
    processorCount = qrsp.processorCount;
    features = qrsp.featureFlags;
    hasInveptSingle =
        (features & KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) != 0ULL;
    hasMonitorTrap =
        (features & KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) != 0ULL;

    /* --- 1. 拿一页自己的内存并落地成真实物理页 --- */
    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    (void)VirtualLock((LPVOID)page, 4096);
    page[0] = 0xA5U;

    /* --- 2. VA -> PA。这个 IOCTL 有自己的版本号和 UI_CONFIRMED 位 --- */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = (unsigned long long)(ULONG_PTR)page;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK) {
        fprintf(stderr, "TRANSLATE 失败：status=%lu nt=0x%08lX win32=%lu\n",
                mrsp.status, (unsigned long)mrsp.ntStatus, GetLastError());
        goto cleanup;
    }
    physical = mrsp.physicalAddress;

    /* --- 3. 装一条 ALLOW_ONCE 规则，看门放不放行 --- */
    memset(&rreq, 0, sizeof(rreq));
    memset(&rrsp, 0, sizeof(rrsp));
    rreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    rreq.size = (unsigned long)sizeof(rreq);
    rreq.operation = KSWORD_ARK_HVM_EPT_RULE_ADD;
    /* ENFORCE 会被更早的门判 UNIMPLEMENTED，而且存储时会丢掉 ALLOW_ONCE。 */
    rreq.flags = KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE;
    rreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    rreq.deniedAccess = KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
    rreq.physicalAddress = physical & ~0xFFFULL;
    rreq.pageCount = 1ULL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &rreq, sizeof(rreq),
                         &rrsp, (DWORD)sizeof(rrsp), &returned, NULL)) {
        fprintf(stderr, "EPT_RULE ADD 下发失败：win32=%lu\n", GetLastError());
        goto cleanup;
    }

    if (rrsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_MULTIPROCESSOR_UNSAFE) {
        verdict = "gate-refused";
    } else if (rrsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        verdict = "installed";
        /* 装上了就当场删掉 —— 这个动词只探门，不留规则。 */
        memset(&rreq, 0, sizeof(rreq));
        rreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        rreq.size = (unsigned long)sizeof(rreq);
        rreq.operation = KSWORD_ARK_HVM_EPT_RULE_REMOVE;
        rreq.flags = KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
        rreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        rreq.ruleId = rrsp.ruleId;
        {
            KSWORD_ARK_HVM_EPT_RULE_RESPONSE drsp;
            memset(&drsp, 0, sizeof(drsp));
            removed = DeviceIoControl(
                h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &rreq, sizeof(rreq),
                &drsp, (DWORD)sizeof(drsp), &returned, NULL) &&
                drsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK;
        }
    } else {
        verdict = "other-status";
    }
    rc = 0;

    if (asJson) {
        printf("{\"kind\":\"rule-allowonce\",\"processorCount\":%lu,"
               "\"inveptSingle\":%s,\"monitorTrapFlag\":%s,"
               "\"status\":%lu,\"lastStatus\":\"0x%08lX\","
               "\"ruleRemoved\":%s,\"verdict\":\"%s\"}\n",
               processorCount,
               hasInveptSingle ? "true" : "false",
               hasMonitorTrap ? "true" : "false",
               rrsp.status, (unsigned long)rrsp.lastStatus,
               removed ? "true" : "false",
               verdict);
    } else {
        printf("处理器数        : %lu\n", processorCount);
        printf("INVEPT_SINGLE   : %s\n", hasInveptSingle ? "有" : "无");
        printf("MONITOR_TRAP    : %s\n", hasMonitorTrap ? "有" : "无");
        printf("ALLOW_ONCE 安装 : status=%lu nt=0x%08lX\n",
               rrsp.status, (unsigned long)rrsp.lastStatus);
        printf("判定            : %s\n", verdict);
        if (strcmp(verdict, "gate-refused") == 0) {
            printf("  安装期的门拒了这条规则 —— 这台机器上 ALLOW_ONCE 无法安全\n"
                   "  实现（多核共享层次，放宽窗口全机可见），拒在安装期而不是\n"
                   "  等它某次命中把整机退出 VMX。\n");
        } else if (strcmp(verdict, "installed") == 0) {
            printf("  规则装上了（已删除）。只有单核、或者武装了私有 EPT 的多核\n"
                   "  才应该走到这里。\n");
        }
    }

cleanup:
    if (page != NULL) {
        (void)VirtualUnlock((LPVOID)page, 4096);
        (void)VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    }
    return rc;
}

static int DoProbeExecuteOnly(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    KSWORD_ARK_HVM_EPT_RULE_REQUEST rreq;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rrsp;
    DWORD returned = 0;
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;
    unsigned long effectiveDenied = 0UL;
    unsigned long ruleId = 0UL;
    int faulted = 0;
    int started = 0;
    int probed = 0;
    int enforced = 0;
    unsigned long residentAfter = 0UL;
    /* 读之前的常驻核数。判据是"降下来了"，不是"降到 0"——见起常驻处的注释。 */
    unsigned long residentBefore = 0UL;
    /* 等了多久其余处理器才自退。0 表示第一次采样就已经降完。 */
    unsigned long residentSettleMs = 0UL;
    unsigned char observed = 0U;
    int rc = 1;

    /* --- 0. 常驻必须**没有**在跑：装规则要求规则表可变 --- */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (qrsp.residentProcessorCount != 0UL) {
        fprintf(stderr,
                "常驻正在跑（residentProcessorCount=%lu）。\n"
                "常驻期间规则表是不可变的，装不上规则。先 hvm_ctl stop。\n",
                qrsp.residentProcessorCount);
        return 1;
    }

    /* --- 1. 拿一页自己的内存，写上标记 --- */
    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    /* 先落地成一个真实的物理页，TRANSLATE 才有东西可翻译。 */
    (void)VirtualLock((LPVOID)page, 4096);
    page[0] = 0xA5U;

    /* --- 2. VA -> PA --- */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    /*
     * 这个 IOCTL 有**自己的**协议版本号，不是通用的那个 —— 用错了会被
     * hvm_memory.c 的版本检查打成 status=1 / STATUS_INVALID_PARAMETER，
     * 和"参数真的不对"长得一模一样。踩过一次。
     * 同理它也有自己的 UI_CONFIRMED 位，光给 token 不够。
     */
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = (unsigned long long)(ULONG_PTR)page;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK) {
        fprintf(stderr, "TRANSLATE 失败：status=%lu (%s) nt=0x%08lX win32=%lu\n",
                mrsp.status,
                mrsp.status == KSWORD_ARK_HVM_MEMORY_STATUS_INVALID_REQUEST
                    ? "INVALID_REQUEST，多半是 version/size/reserved0"
                    : (mrsp.status ==
                       KSWORD_ARK_HVM_MEMORY_STATUS_CONFIRMATION_REQUIRED
                          ? "CONFIRMATION_REQUIRED，缺 UI_CONFIRMED 位或 token"
                          : "见 KswordArkHvmIoctl.h 的 MEMORY_STATUS_*"),
                (unsigned long)mrsp.ntStatus, GetLastError());
        goto cleanup;
    }
    physical = mrsp.physicalAddress;

    /* --- 3. 装一条只拒 READ 的 ENFORCE 规则，回读有效掩码（Q1）--- */
    memset(&rreq, 0, sizeof(rreq));
    memset(&rrsp, 0, sizeof(rrsp));
    rreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    rreq.size = (unsigned long)sizeof(rreq);
    rreq.operation = KSWORD_ARK_HVM_EPT_RULE_ADD;
    /* 不要 ENFORCE —— 见函数头注释，那条路是死循环。 */
    rreq.flags = KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
    rreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    rreq.deniedAccess = KSWORD_ARK_HVM_EPT_ACCESS_READ;
    rreq.physicalAddress = physical & ~0xFFFULL;
    rreq.pageCount = 1ULL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &rreq, sizeof(rreq),
                         &rrsp, (DWORD)sizeof(rrsp), &returned, NULL) ||
        rrsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        fprintf(stderr, "EPT_RULE ADD 失败：status=%lu nt=0x%08lX win32=%lu\n",
                rrsp.status, (unsigned long)rrsp.lastStatus, GetLastError());
        goto cleanup;
    }
    effectiveDenied = rrsp.deniedAccess;
    ruleId = rrsp.ruleId;

    /* --- 4. 起常驻。规则已经装好，现在才轮到 EPT 真正开始强制 --- */
    if (!ProbeControl(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED,
                      "START_RESIDENT")) {
        goto cleanup_rules;
    }
    started = 1;

    /*
     * 读之前先记下常驻核数 —— 判据要的是**降下来了**，不是**降到 0**。
     *
     * 这条判据的由来：fail-closed 当初只退**当前这一个**处理器，
     * KeIpiGenericCall 那套会合只服务计划内的起停/失效，不服务 fail-closed ——
     * 那条路身处 VMX root、IRQL 不确定，本来就发不了 IPI。于是 1 vCPU 上
     * 「退当前核」与「全停」不可区分，residentAfter==0 恰好成立；2 vCPU 上
     * 同样的正确行为会留下另一个核仍在常驻，residentAfter==1，旧判据据此判
     * 「未强制」——**驱动没变，判据把核数当成了常量**。
     * 2026-09-07 实测：1 vCPU 报 execute-only-enforced，2 vCPU 报 not-enforced。
     *
     * **驱动侧后来修了**：失败关闭的那个核会置位 ResidentFaultStopRequested，
     * 其余处理器在各自下一次 VM exit 时看到并自退，现在是真正的全机停机
     * （同日实测 2 vCPU：residentBefore=2 -> residentAfter=0）。
     *
     * 判据仍然保持 before -> after 的形式，**故意不改回 ==0**：它对两种行为
     * 都成立，而 ==0 只对其中一种成立。把一条更宽的判据收紧到刚好贴合当前
     * 实现，等于把下一次行为变化变成一次假红。
     */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                        &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        residentBefore = qrsp.residentProcessorCount;
    }

    /*
     * --- 5. 读那一页，但**必须让驱动去读**，不能在这里直接碰 page[0] ---
     *
     * 严格命中的处置是 fail-closed 退虚拟化，而退虚拟化路径
     * （hvm_entry.asm 的 ResidentDevirtualize）是**同特权级返回**：
     * 它把 DevirtualizeRsp 装进 RSP、把 RIP/RFLAGS 压上去再 ret。
     * 那条路只在 guest 处于内核态时成立。用户态读触发的违规会让它带着
     * 一个 ring-3 的 RSP/RIP 在 ring 0 上返回 —— 实测直接蓝屏。
     *
     * 走 OP_READ_PHYSICAL 就干净了：真正的访问发生在驱动的私有窗口里、
     * 内核态、同一个物理页，照样撞规则，而退虚拟化回到的是内核上下文。
     */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = physical;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL)) {
        fprintf(stderr, "READ_PHYSICAL 未返回：win32=%lu\n", GetLastError());
        goto cleanup_rules;
    }
    if (mrsp.status == KSWORD_ARK_HVM_MEMORY_STATUS_OK &&
        mrsp.bytesTransferred >= 1UL) {
        /* 读成功，记下读回的字节。 */
        observed = mrsp.data[0];
    } else {
        /* 读失败本身也是"被挡住了"的一种表现，记下来。 */
        faulted = 1;
    }
    /* 这次读确实发生过，判定才有依据。 */
    probed = 1;

    /*
     * --- 5b. 回读常驻状态，这才是判据 ---
     *
     * **有界轮询，不是立刻读一次。** 全机停机是**最终一致**的，不是即时的：
     * 失败关闭的那个核当场退出并置位 ResidentFaultStopRequested，其余处理器
     * 要等**各自的下一次 VM exit** 才看到标志并自退 —— 从 VMX root 发不了 IPI，
     * 这是唯一能把请求送到它们那里的通道。
     *
     * 于是"读完立刻采样"量到的是竞态而不是机制。2026-09-07 实测，2 vCPU 上
     * 连跑 5 次立刻采样：4 次 residentAfter=1，1 次 =0 —— 同一个驱动、同一条
     * 代码路径，读数却在 0 和 1 之间跳。拿其中任何一次单独下结论都是错的。
     *
     * 实际延迟很短：soak 量到约 5500 次退出/秒，另一个核通常在毫秒内就会撞上
     * 一次退出。所以给一个几百毫秒的上界足够宽，同时又能把"最终退不下来"
     * 这种真故障暴露出来。
     *
     * 报 waitedMs 而不是把等待藏起来：判据是"降到 0，且用了多久"，
     * 一个悄悄重试到成功的探针跟一个假绿没有区别。
     */
    {
        const unsigned long kSettleBudgetMs = 500UL;
        const unsigned long kSettleStepMs = 10UL;
        unsigned long waited = 0UL;

        for (;;) {
            memset(&qreq, 0, sizeof(qreq));
            memset(&qrsp, 0, sizeof(qrsp));
            qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
            qreq.size = (unsigned long)sizeof(qreq);
            if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM,
                                 &qreq, sizeof(qreq),
                                 &qrsp, (DWORD)sizeof(qrsp),
                                 &returned, NULL)) {
                fprintf(stderr, "读后 QUERY_HVM 失败：win32=%lu\n",
                        GetLastError());
                probed = 0;
                goto cleanup_rules;
            }
            residentAfter = qrsp.residentProcessorCount;
            /* 降到 0 就是终态，没有必要再等。 */
            if (residentAfter == 0UL) {
                break;
            }
            /* 预算用尽就如实报当前值，不再等。 */
            if (waited >= kSettleBudgetMs) {
                break;
            }
            Sleep(kSettleStepMs);
            waited += kSettleStepMs;
        }
        residentSettleMs = waited;
    }

    /* --- 6. 先停常驻，否则下面清规则会被拒 --- */
    (void)ProbeControl(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED,
                       "STOP_RESIDENT");
    started = 0;

cleanup_rules:
    /* 停常驻之后才清得掉规则。 */
    if (started) {
        (void)ProbeControl(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                           KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED,
                           "STOP_RESIDENT");
        started = 0;
    }
    memset(&rreq, 0, sizeof(rreq));
    rreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    rreq.size = (unsigned long)sizeof(rreq);
    rreq.operation = KSWORD_ARK_HVM_EPT_RULE_CLEAR;
    rreq.flags = KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
    rreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    (void)DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &rreq, sizeof(rreq),
                          &rrsp, (DWORD)sizeof(rrsp), &returned, NULL);

    /*
     * 没有真正做过那次读就绝不打印判定。faulted==0 有两个来源 ——
     * "读了没挨打"和"根本没读到那一步" —— 混在一起就是一个假阴性，
     * 而这条线上的假阴性正好会得出最坏的结论（"L0 不兑现权限"）。
     */
    if (!probed) {
        fprintf(stderr, "探针没有跑到读那一步，不输出判定。\n");
        rc = 1;
        goto cleanup;
    }

    /*
     * 判据：读**之后**常驻核数比读之前少了。
     *
     * 少了 = 严格命中走了 fail-closed 退虚拟化 = 权限被真正强制。
     * 一个没少 = 那次读根本没产生 EPT 违规 = L0 没兑现被移除的权限。
     *
     * **不能写成 residentAfter == 0**，有两层理由：
     *
     * 一是历史的：fail-closed 当初只退当前那一个处理器，N 核上正确行为留下的
     * 是 N-1 不是 0，旧判据在 1 vCPU 上碰巧成立，一上多核就把正确行为判成失败
     * （2026-09-07 实测）。
     *
     * 二是现在仍然成立的：驱动改成全机停机之后，"降到 0"是**最终**成立而不是
     * 立刻成立的（其余核要等各自下次 VM exit）。上面那段有界轮询把这件事测成
     * 终态，但即使轮询超时，"少了"依然证明了 EPT 真的强制过一次 —— 那才是本
     * 探针要回答的问题。把判据收紧到 ==0 会让一次调度抖动变成假红。
     * 全机停机是否真的完成，看 residentAfterRead 与 residentSettleMs。
     *
     * residentBefore == 0 说明读之前那次 QUERY 就没成功，此时"少了"无从谈起，
     * 退回只看 faulted —— 缺读数时宁可判不出，也不要拿一个没有基准的差值下结论。
     */
    enforced = faulted ||
        (residentBefore > 0UL && residentAfter < residentBefore);
    rc = enforced ? 0 : 2;

    if (asJson) {
        printf("{\"kind\":\"probe-xonly\",\"physicalAddress\":\"0x%016llX\","
               "\"ruleId\":%lu,\"requestedDenied\":1,\"effectiveDenied\":%lu,"
               "\"executeOnlyEncodable\":%s,\"residentBeforeRead\":%lu,"
               "\"residentAfterRead\":%lu,\"residentSettleMs\":%lu,"
               "\"readFaulted\":%s,\"observedByte\":%u,\"enforced\":%s,"
               "\"verdict\":\"%s\"}\n",
               physical, ruleId, effectiveDenied,
               ((effectiveDenied & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL)
                   ? "true" : "false",
               residentBefore,
               residentAfter,
               residentSettleMs,
               faulted ? "true" : "false",
               (unsigned)observed,
               enforced ? "true" : "false",
               enforced
                   ? (((effectiveDenied &
                        KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL)
                          ? "execute-only-enforced" : "enforced-without-x-only")
                   : "not-enforced");
        goto cleanup;
    }

    printf("\n=== execute-only 探针 ===\n");
    printf("  目标物理页   : 0x%016llX   ruleId=%lu\n",
           physical & ~0xFFFULL, ruleId);
    printf("  请求拒绝     : READ\n");
    printf("  有效拒绝     : 0x%lX  (%s%s%s)\n", effectiveDenied,
           (effectiveDenied & KSWORD_ARK_HVM_EPT_ACCESS_READ) ? "R" : "-",
           (effectiveDenied & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) ? "W" : "-",
           (effectiveDenied & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) ? "X" : "-");
    if ((effectiveDenied & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL) {
        printf("  Q1 驱动侧   : EXECUTE 被保住了 => 能编码出 execute-only 叶\n");
    } else {
        printf("  Q1 驱动侧   : EXECUTE 也被拒了 => 这台机器编码不出 "
               "execute-only，CLOAK 无从谈起\n");
    }
    printf("  读回字节     : 0x%02X   常驻核数 %lu -> %lu（等了 %lu ms）%s\n",
           (unsigned)observed, residentBefore, residentAfter,
           residentSettleMs,
           faulted ? "   （读本身抛了异常）" : "");
    printf("  判据         : 常驻核数**降下来了**即视为强制生效，"
           "不是「降到 0」。\n");
    printf("                 失败关闭的核当场退出并置位全机停机请求，其余核要\n");
    printf("                 等各自下次 VM exit 才自退 —— 从 VMX root 发不了\n");
    printf("                 IPI，那是唯一的通道。所以「降到 0」是**最终**成立，\n");
    printf("                 上面的毫秒数就是等它成立花的时间（0 = 一读就已降完）。\n");
    if (enforced) {
        printf("  Q2 L0 侧    : 那次读**产生了 EPT 违规**（常驻被 fail-closed "
               "打回原生）\n");
        printf("\n  判定：EPT 权限在嵌套下被真正强制。\n");
    } else {
        printf("  Q2 L0 侧    : 那次读**什么都没触发**，常驻原样还在\n");
        printf("\n  判定：**L0 没有兑现被移除的权限。**\n");
        printf("  CLOAK/HOOK 在这台机器上会静默失效（无错误码、无事件、"
               "无蓝屏，只是藏不住）。\n");
        printf("  换 EPTP 切换后端**解决不了**这个问题 —— 那是分离视图怎么切，\n");
        printf("  不是切过去之后权限算不算数。\n");
    }

cleanup:
    if (page != NULL) {
        (void)VirtualUnlock((LPVOID)page, 4096);
        (void)VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    }
    return rc;
}

/* ------------------------------------------------------------------------ */
/* EPT 分离视图（CLOAK / HOOK）                                              */
/* ------------------------------------------------------------------------ */

static const char* ViewStatusName(unsigned long s)
{
    switch (s) {
    case KSWORD_ARK_HVM_VIEW_STATUS_OK:                    return "OK";
    case KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST:       return "INVALID_REQUEST";
    case KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED: return "CONFIRMATION_REQUIRED";
    case KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED:          return "NOT_PREPARED";
    case KSWORD_ARK_HVM_VIEW_STATUS_NOT_FOUND:             return "NOT_FOUND";
    case KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL:            return "TABLE_FULL";
    case KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED:          return "SPLIT_FAILED";
    case KSWORD_ARK_HVM_VIEW_STATUS_LEAF_CONFLICT:         return "LEAF_CONFLICT";
    case KSWORD_ARK_HVM_VIEW_STATUS_EXECUTE_ONLY_UNSUPPORTED:
        return "EXECUTE_ONLY_UNSUPPORTED";
    case KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE:
        return "MULTIPROCESSOR_UNSAFE";
    case KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED:       return "RESOURCE_FAILED";
    default:                                               return "<未知>";
    }
}

static const char* ViewKindName(unsigned long k)
{
    return (k == KSWORD_ARK_HVM_VIEW_KIND_CLOAK) ? "CLOAK"
         : ((k == KSWORD_ARK_HVM_VIEW_KIND_HOOK) ? "HOOK" : "<未知>");
}

static const char* EventTypeName(unsigned long t)
{
    switch (t) {
    case KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT:        return "VMEXIT";
    case KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION: return "EPT_VIOLATION";
    case KSWORD_ARK_HVM_EVENT_TYPE_NESTED_VMX:    return "NESTED_VMX";
    case KSWORD_ARK_HVM_EVENT_TYPE_FATAL_EXIT:    return "FATAL_EXIT";
    case KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE:     return "LIFECYCLE";
    case KSWORD_ARK_HVM_EVENT_TYPE_NESTED_PAGE:   return "NESTED_PAGE";
    default:                                      return "<未知>";
    }
}

/* 把 access 位掩码写成 rwx 形状，缺哪一位就是 '-'。 */
static void EventAccessText(unsigned long access, char out[4])
{
    out[0] = (access & KSWORD_ARK_HVM_EPT_ACCESS_READ)    ? 'r' : '-';
    out[1] = (access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE)   ? 'w' : '-';
    out[2] = (access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) ? 'x' : '-';
    out[3] = '\0';
}

/*
 * events：把事件环逐行读出来。
 *
 * **为什么必须有这个动词**：后端 (b)（EPTP 切换）上 flipCount 结构性恒为 0 ——
 * 唯一的递增点在 hvm_ept_view.c:903，而该后端在 :821 就提前 return 了。于是
 * 「这条视图有没有被硬件真的碰过」在这个后端上原本一个可读的数字都没有。
 *
 * 而事件环里有：每一次 EPT 违规都留一行，带 access 位与 ruleId（视图翻转承载
 * 的就是 viewId）。**access 含 x 且 ruleId == 某条 HOOK 视图的编号，就是
 * 「取指落在这一页上并触发了重定向」的第一手正向证据** —— 那正是路线图里
 * 「HOOK 方向未实测」欠的那条读数。
 *
 * 在此之前 hvm_ctl 只打两个聚合整数（eventCount / droppedEventCount），
 * 知道"有多少条"，不知道"是哪几条"。
 *
 * **事件环是消费型的**：游标推进之后旧行读不回来。所以 afterSequence 要由调用方
 * 自己推进，别指望重跑一次能读到同一批。droppedRows 非零说明环被覆盖过，
 * 那时"没读到某条"不构成"它没发生"——这两者必须分开，否则就是又一条假判据。
 */
static int DoEvents(HANDLE h, unsigned long long afterSequence, unsigned long maxRows, int asJson)
{
    KSWORD_ARK_HVM_EVENT_QUERY_REQUEST req;
    KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;
    unsigned long i;
    unsigned long execRows = 0UL;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    /*
     * operation 必须显式置 READ。
     *
     * READ 是 1，不是 0 —— memset 之后不写这一个字段，发出去的是未知操作码，
     * 驱动按契约回 STATUS_INVALID_PARAMETER（hvm_event.c:186-192，同时校验
     * version 与 size）。那是一次干净的拒绝，不是崩溃，但调用方看到的现象是
     * 「一行都读不到」，很容易被当成"事件环是空的"。这两者必须分开。
     */
    req.operation = KSWORD_ARK_HVM_EVENT_QUERY_READ;
    req.maxRows = maxRows;
    req.afterSequence = afterSequence;

    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EVENTS,
                         &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp)) {
        /* 打到 stdout 而不是 stderr：调用方常常只看 stdout，把失败写进 stderr
         * 等于让"IOCTL 被拒"长得和"事件环是空的"一模一样。 */
        printf("\n=== 事件环：读取失败 ===\n");
        printf("  IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
               (int)ok, returned, GetLastError());
        printf("  这是**读不到**，不是**没有事件**。两者不能混为一谈。\n");
        return 1;
    }

    for (i = 0UL; i < rsp.returnedRows && i < KSWORD_ARK_HVM_MAX_EVENT_ROWS; ++i) {
        if ((rsp.rows[i].access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL) {
            ++execRows;
        }
    }

    if (asJson) {
        printf("{\"kind\":\"events\",\"returnedRows\":%lu,\"availableRows\":%lu,"
               "\"droppedRows\":%lu,\"newestSequence\":%llu,"
               "\"afterSequence\":%llu,\"executeRows\":%lu,\"rows\":[",
               rsp.returnedRows, rsp.availableRows, rsp.droppedRows,
               rsp.newestSequence, afterSequence, execRows);
        for (i = 0UL; i < rsp.returnedRows && i < KSWORD_ARK_HVM_MAX_EVENT_ROWS; ++i) {
            char acc[4];
            EventAccessText(rsp.rows[i].access, acc);
            printf("%s{\"sequence\":%llu,\"type\":%lu,\"typeName\":\"%s\","
                   "\"exitReason\":%lu,\"access\":%lu,\"accessText\":\"%s\","
                   "\"ruleId\":%lu,\"guestPhysicalAddress\":\"0x%016llX\","
                   "\"guestLinearAddress\":\"0x%016llX\",\"guestRip\":\"0x%016llX\","
                   "\"qualification\":\"0x%016llX\",\"status\":\"0x%08lX\","
                   "\"processor\":%u,\"processorGroup\":%u,\"timestampQpc\":%llu",
                   (i == 0UL) ? "" : ",",
                   rsp.rows[i].sequence, rsp.rows[i].type,
                   EventTypeName(rsp.rows[i].type),
                   rsp.rows[i].exitReason, rsp.rows[i].access, acc,
                   rsp.rows[i].ruleId, rsp.rows[i].guestPhysicalAddress,
                   rsp.rows[i].guestLinearAddress, rsp.rows[i].guestRip,
                   rsp.rows[i].qualification, (unsigned long)rsp.rows[i].status,
                   (unsigned)rsp.rows[i].processorNumber,
                   (unsigned)rsp.rows[i].processorGroup, rsp.rows[i].timestamp);
            if (rsp.rows[i].type == KSWORD_ARK_HVM_EVENT_TYPE_NESTED_PAGE) {
                /* Typed aliases disambiguate fields reused by the fixed event ABI. */
                printf(",\"pageOperationId\":%lu,\"pageStage\":%lu,\"pageOperation\":%lu,"
                       "\"faultMode\":%llu,\"ept12Pointer\":\"0x%016llX\","
                       "\"replacementBacking\":\"0x%016llX\"",
                       rsp.rows[i].ruleId, rsp.rows[i].exitReason, rsp.rows[i].access,
                       (rsp.rows[i].qualification & KSWORD_ARK_HVM_NESTED_PAGE_FAULT_MASK) >> KSWORD_ARK_HVM_NESTED_PAGE_FAULT_SHIFT,
                       rsp.rows[i].guestLinearAddress, rsp.rows[i].guestRip);
            }
            putchar('}');
        }
        printf("]}\n");
        return 0;
    }

    printf("\n=== 事件环（afterSequence=%llu）===\n", afterSequence);
    printf("  本次读回 %lu 行；环里可读 %lu 行；最新序号 %llu\n",
           rsp.returnedRows, rsp.availableRows, rsp.newestSequence);
    if (rsp.droppedRows != 0UL) {
        printf("  **丢弃 %lu 行**：环被覆盖过。此时「没读到某条」不等于「它没发生」。\n",
               rsp.droppedRows);
    }
    if (rsp.returnedRows == 0UL) {
        printf("  （这一段没有新事件）\n");
        return 0;
    }
    printf("  %-8s %-14s %-4s %-6s %-18s %-18s %s\n",
           "序号", "类型", "访问", "ruleId", "GPA", "GuestRIP", "exitReason");
    for (i = 0UL; i < rsp.returnedRows && i < KSWORD_ARK_HVM_MAX_EVENT_ROWS; ++i) {
        char acc[4];
        EventAccessText(rsp.rows[i].access, acc);
        printf("  %-8llu %-14s %-4s %-6lu 0x%016llX 0x%016llX %lu\n",
               rsp.rows[i].sequence, EventTypeName(rsp.rows[i].type), acc,
               rsp.rows[i].ruleId, rsp.rows[i].guestPhysicalAddress,
               rsp.rows[i].guestRip, rsp.rows[i].exitReason);
    }
    printf("\n  其中 access 含 x 的 %lu 行。\n", execRows);
    printf("  含 x 且 ruleId 等于某条 HOOK 视图编号的行 = 取指落在该页并触发了重定向，\n"
           "  那是「HOOK 方向」的正向证据；一行都没有则是**无读数**（那一页没被执行过），\n"
           "  既不是成功也不是失败。\n");
    return 0;
}

/*
 * 发一次视图 IOCTL。
 *
 * **返回 FALSE 不等于没有响应。** 安全策略闸门（hvm_ioctl.c）在拒绝时
 * 会先把完整响应写进输出缓冲，然后返回一个失败的 NTSTATUS ——
 * 于是 DeviceIoControl 返回 FALSE，而 status/lastStatus 是有效的。
 * 只看返回值就会把一次「策略拒绝」误报成「传输层失败」。
 */
static int ViewIoctl(HANDLE h,
                     KSWORD_ARK_HVM_VIEW_REQUEST* req,
                     KSWORD_ARK_HVM_VIEW_RESPONSE* rsp)
{
    DWORD returned = 0;
    BOOL ok;

    req->version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
    req->size = (unsigned long)sizeof(*req);
    memset(rsp, 0, sizeof(*rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_VIEW, req, (DWORD)sizeof(*req),
                         rsp, (DWORD)sizeof(*rsp), &returned, NULL);
    if (returned >= sizeof(*rsp)) {
        /* 响应完整就用响应，无论 ok 是真是假。 */
        return 0;
    }
    fprintf(stderr, "VIEW IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
            (int)ok, returned, GetLastError());
    return 1;
}

static int DoViewQuery(HANDLE h, int asJson)
{
    KSWORD_ARK_HVM_VIEW_REQUEST req;
    KSWORD_ARK_HVM_VIEW_RESPONSE rsp;
    unsigned long i;

    memset(&req, 0, sizeof(req));
    /* QUERY 在确认闸门**之前**被应答，所以不需要 token，也不改任何状态。 */
    req.operation = KSWORD_ARK_HVM_VIEW_OP_QUERY;
    if (ViewIoctl(h, &req, &rsp) != 0) { return 1; }

    if (asJson) {
        printf("{\"kind\":\"view-query\",\"status\":%lu,\"statusName\":\"%s\","
               "\"lastStatus\":\"0x%08lX\",\"viewCount\":%lu,\"generation\":%lu,"
               "\"rows\":[",
               rsp.status, ViewStatusName(rsp.status),
               (unsigned long)rsp.lastStatus, rsp.viewCount, rsp.generation);
        for (i = 0UL; i < rsp.returnedRows && i < KSWORD_ARK_HVM_MAX_VIEWS; ++i) {
            printf("%s{\"viewId\":%lu,\"kind\":\"%s\",\"flags\":%lu,"
                   "\"physicalAddress\":\"0x%016llX\","
                   "\"shadowPhysicalAddress\":\"0x%016llX\",\"flipCount\":%llu}",
                   (i == 0UL) ? "" : ",",
                   rsp.rows[i].viewId, ViewKindName(rsp.rows[i].kind),
                   rsp.rows[i].flags, rsp.rows[i].physicalAddress,
                   rsp.rows[i].shadowPhysicalAddress, rsp.rows[i].flipCount);
        }
        printf("]}\n");
        return (rsp.status == KSWORD_ARK_HVM_VIEW_STATUS_OK) ? 0 : 2;
    }

    printf("\n=== EPT 分离视图（只读）===\n");
    printf("  status       : %lu (%s)  lastStatus=0x%08lX\n",
           rsp.status, ViewStatusName(rsp.status),
           (unsigned long)rsp.lastStatus);
    printf("  已装视图数   : %lu   代次=%lu\n", rsp.viewCount, rsp.generation);
    if (rsp.returnedRows == 0UL) {
        printf("  （没有任何已安装的视图）\n");
    }
    for (i = 0UL; i < rsp.returnedRows && i < KSWORD_ARK_HVM_MAX_VIEWS; ++i) {
        printf("  #%-3lu %-5s pa=0x%016llX shadow=0x%016llX flips=%llu flags=0x%lX\n",
               rsp.rows[i].viewId, ViewKindName(rsp.rows[i].kind),
               rsp.rows[i].physicalAddress, rsp.rows[i].shadowPhysicalAddress,
               rsp.rows[i].flipCount, rsp.rows[i].flags);
    }
    return (rsp.status == KSWORD_ARK_HVM_VIEW_STATUS_OK) ? 0 : 2;
}

/*
 * view-probe：**归因**探针，不是「试试能不能装」。
 *
 * 安装期有三道不同的门返回**同一个** MULTIPROCESSOR_UNSAFE(9)：
 *   外层「常驻在跑」（hvm_ept_view.c:850）、
 *   第九道「多核且没武装 LOCAL_EPT」（:633）、
 *   第十道「缺 INVEPT_SINGLE / MONITOR_TRAP_FLAG」（:645）。
 * 于是裸看 status=9 **说明不了任何事** —— 这正是 probe-flags 那一轮踩过的
 * 「静默空过」形状：报告全绿而什么都没测到。
 *
 * 所以这里先查一次状态，判定这一次到底**测不测得到**能力门；测不到就报
 * 第三态「空过」并说明差什么，绝不把它算成通过。
 */
static int DoViewProbe(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    KSWORD_ARK_HVM_VIEW_REQUEST vreq;
    KSWORD_ARK_HVM_VIEW_RESPONSE vrsp;
    DWORD returned = 0;
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;
    int verdict = NEG_VOID;
    const char* reason = "未判定";
    const char* expectation = "";
    int haveCaps = 0;
    int eptpSwitch = 0;
    int installed = 0;
    int attempted = 0;
    /*
     * 这一次空过是"这台机器上问不出"还是"这次没准备好"。
     *
     * 两者都不算通过，但只有后者有东西可修。前者若也记成 BLOCKED，套件在这类
     * 机器上就永远判 PARTIAL —— 而一份永远不绿的报告下次真出问题时没人会注意。
     */
    int notApplicable = 0;
    unsigned long installedId = 0UL;
    int rc = 3;

    /*
     * 空过路径会 goto 过安装那一步，那时 vrsp 从没被写过。
     * 不清零就会打出 status=0 —— 而 0 正好是 OK，一次「什么都没测」
     * 会长成一次「通过」。这一行就是防这个。
     */
    memset(&vrsp, 0, sizeof(vrsp));

    /* --- 0. 先拿状态，判定这次能不能归因 --- */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }

    /*
     * 能力齐不齐要**按后端问**，两个后端要的不是同一组。
     * 照旧只看 MTF 的话，在 EPTP 切换后端上会把一次正常安装判成 FAIL ——
     * 判据比被测对象老，是这条线上另一种形式的假判据。
     */
    eptpSwitch =
        (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED) != 0ULL;
    haveCaps =
        ((qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) != 0ULL) &&
        (eptpSwitch != 0 ||
         (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) != 0ULL);

    if (qrsp.residentProcessorCount != 0UL) {
        reason = "常驻正在跑：外层门会先返回同一个 MULTIPROCESSOR_UNSAFE，"
                 "这一次测不到能力门。先 hvm_ctl stop。";
        goto report;
    }
    if ((qrsp.stateFlags & KSWORD_ARK_HVM_STATE_EPT_READY) == 0UL) {
        reason = "EPT_READY 没置位：会先命中 NOT_PREPARED。先 hvm_ctl prepare。";
        goto report;
    }
    if (qrsp.processorCount != 1UL &&
        (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED) == 0ULL) {
        /*
         * 两种"武装不了"，后果完全不同，必须分开。
         *
         * 驱动武装私有 EPT 要 INVEPT_SINGLE **与** MONITOR_TRAP_FLAG 两者齐备
         * （hvm_runtime.c 的 LocalEptArmed 赋值）。缺 MTF 的机器上——嵌套
         * Hyper-V 客户机全都缺——这一位**永远**武装不上，于是多核安全门永远
         * 先命中，这条用例在这类机器上结构性地不可能有归因能力。
         *
         * 那不是"这次没准备好"，是"这台机器上问不出这个问题"。记成 BLOCKED
         * 会让套件永远判 PARTIAL，而一份永远不绿的报告等于没有报告：下次真出
         * 问题时没人会注意到多了一行。
         *
         * 反过来，MTF 在场却没武装，是调用方少发了一位，那确实该 BLOCKED ——
         * 有东西可修，而且不修就测不到。
         */
        if ((qrsp.featureFlags &
                KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) == 0ULL) {
            reason = "多核 + 本机无 Monitor Trap Flag：私有 EPT 永远武装不上，"
                     "多核安全门必先命中且与能力门同码 —— "
                     "**这台机器上问不出这个问题**，不是这次没准备好。";
            notApplicable = 1;
            goto report;
        }
        reason = "多核且 LOCAL_EPT 未武装（本机有 MTF，可以武装）："
                 "第九道门会先命中，与能力门**同码**，无法归因。"
                 "先跑 prepare-localept。";
        goto report;
    }

    /* --- 1. 一页自己的内存，落地成真实物理页 --- */
    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    (void)VirtualLock((LPVOID)page, 4096);
    page[0] = 0xA5U;

    /* --- 2. VA -> PA（这个 IOCTL 有自己的协议版本号与确认位）--- */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = (unsigned long long)(ULONG_PTR)page;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK) {
        fprintf(stderr, "TRANSLATE 失败：status=%lu nt=0x%08lX win32=%lu\n",
                mrsp.status, (unsigned long)mrsp.ntStatus, GetLastError());
        rc = 1;
        goto cleanup;
    }
    physical = mrsp.physicalAddress & ~0xFFFULL;

    /* --- 3. 发一次 HOOK 视图安装 --- */
    memset(&vreq, 0, sizeof(vreq));
    vreq.operation = KSWORD_ARK_HVM_VIEW_OP_ADD;
    vreq.kind = KSWORD_ARK_HVM_VIEW_KIND_HOOK;
    /* SEED_FROM_TARGET：影子从目标页拷，不必自己填 4 KiB。 */
    vreq.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET;
    vreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    vreq.physicalAddress = physical;
    attempted = 1;
    if (ViewIoctl(h, &vreq, &vrsp) != 0) { rc = 1; goto cleanup; }

    /* --- 4. 判定 --- */
    if (haveCaps == 0) {
        /* 缺能力：唯一可能命中的就是能力门，status=9 可归因。 */
        expectation = "status=9 MULTIPROCESSOR_UNSAFE（能力门）";
        if (vrsp.status == KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE) {
            verdict = NEG_PASS;
            reason = "能力门确实是拦路的那一道：既没有 MONITOR_TRAP_FLAG，"
                     "也没有武装 EPTP 切换后端，两个后端都装不上。";
            rc = 0;
        } else {
            verdict = NEG_FAIL;
            reason = "缺能力却没被能力门拒 —— 门序与预期不符，先查代码再下结论。";
            rc = 2;
        }
    } else {
        /* 能力齐全：这台机器应该真的能装上。 */
        expectation = "status=0 OK（能力齐全，视图应当装得上）";
        if (vrsp.status == KSWORD_ARK_HVM_VIEW_STATUS_OK) {
            verdict = NEG_PASS;
            installed = 1;
            installedId = vrsp.viewId;
            reason = eptpSwitch
                ? "**EPTP 切换后端在缺 MTF 的机器上把 HOOK 视图装上了。**"
                  "次层次已构造并逐级复核通过。已立即移除。"
                : "**本机不缺 MTF，HOOK 视图真的装上了。**已立即移除。";
            rc = 0;
        } else {
            verdict = NEG_FAIL;
            reason = "能力齐全却装不上 —— 看 status 名字定位是哪一道门。";
            rc = 2;
        }
    }

    /* --- 5. 装上了就立刻卸掉，探针不留状态 --- */
    if (installed != 0) {
        KSWORD_ARK_HVM_VIEW_REQUEST rreq2;
        KSWORD_ARK_HVM_VIEW_RESPONSE rrsp2;
        memset(&rreq2, 0, sizeof(rreq2));
        rreq2.operation = KSWORD_ARK_HVM_VIEW_OP_REMOVE;
        rreq2.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED;
        rreq2.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        rreq2.viewId = installedId;
        if (ViewIoctl(h, &rreq2, &rrsp2) != 0 ||
            rrsp2.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
            /* 没卸干净必须响亮地说，别让下一次探针撞上 LEAF_CONFLICT。 */
            fprintf(stderr,
                    "**视图没能移除**：status=%lu (%s)。请手动 view-query 核对。\n",
                    rrsp2.status, ViewStatusName(rrsp2.status));
            rc = 2;
        }
    }

report:
    if (asJson) {
        /*
         * attempted 必须在场。空过时下面那些 status 字段是清零值，
         * 机器判据若只看 status 会把「根本没发过请求」读成「返回了 OK」。
         */
        printf("{\"kind\":\"view-probe\",\"verdict\":\"%s\",\"attempted\":%s,"
               "\"notApplicable\":%s,"
               "\"processorCount\":%lu,\"residentProcessorCount\":%lu,"
               "\"eptReady\":%s,\"monitorTrapFlag\":%s,\"inveptSingle\":%s,"
               "\"localEptArmed\":%s,\"status\":%lu,\"statusName\":\"%s\","
               "\"lastStatus\":\"0x%08lX\",\"installed\":%s,"
               "\"expected\":\"%s\",\"reason\":\"%s\"}\n",
               NegName(verdict), attempted ? "true" : "false",
               notApplicable ? "true" : "false",
               qrsp.processorCount, qrsp.residentProcessorCount,
               ((qrsp.stateFlags & KSWORD_ARK_HVM_STATE_EPT_READY) != 0UL)
                   ? "true" : "false",
               ((qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) != 0ULL)
                   ? "true" : "false",
               ((qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) != 0ULL)
                   ? "true" : "false",
               ((qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED) != 0ULL)
                   ? "true" : "false",
               vrsp.status, ViewStatusName(vrsp.status),
               (unsigned long)vrsp.lastStatus,
               installed ? "true" : "false",
               expectation, reason);
    } else {
        printf("\n=== view-probe（分离视图安装期归因）===\n");
        printf("  处理器       : total=%lu resident=%lu\n",
               qrsp.processorCount, qrsp.residentProcessorCount);
        PrintViewPrerequisites("  ", qrsp.featureFlags);
        if (verdict == NEG_VOID && notApplicable) {
            printf("  [不适用] 这台机器上**问不出**这个问题\n");
            printf("         %s\n", reason);
        } else if (verdict == NEG_VOID) {
            printf("  [空过] 这一次**测不到**能力门\n");
            printf("         %s\n", reason);
        } else {
            printf("  [%-4s] status=%lu (%s) lastStatus=0x%08lX\n",
                   NegName(verdict), vrsp.status, ViewStatusName(vrsp.status),
                   (unsigned long)vrsp.lastStatus);
            printf("         期望：%s\n", expectation);
            printf("         %s\n", reason);
        }
    }

cleanup:
    if (page != NULL) {
        (void)VirtualUnlock((LPVOID)page, 4096);
        (void)VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    }
    /*
     * 退出码 4 = 这台机器上问不出这个问题，与 3（这次没准备好）分开。
     *
     * 分开的理由不是好看：3 是"有东西要修"，4 是"没东西可修"。两者合成一个的
     * 后果是套件在缺 MTF 的机器上永远判 PARTIAL，而永远不绿的报告与没有报告
     * 等价 —— 下次真出问题时多出的那一行不会有人看。
     */
    if (rc == 3 && notApplicable) {
        rc = 4;
    }
    return rc;
}

/*
 * view-effect：分离视图**是否真的生效**的端到端判据。
 *
 * 前面所有的探针回答的都是「装不装得上」。这一个回答「装上之后，一次真实访问
 * 拿到的是不是影子内容」—— 那才是 CLOAK/HOOK 存在的意义，也是唯一一个
 * 「装上了但其实没用」骗不过去的读数。
 *
 * 做法：真页写 0xA5，装一张 **CLOAK** 视图并把影子填零（CLOAK 的语义是执行看
 * 真页、读写看影子），起常驻，然后**让驱动去读**那一页的物理地址。
 *
 *   读到 0x00  → 切换发生了，视图生效；
 *   读到 0xA5  → 读到了真页，切换没发生（装上了但没用）；
 *   常驻掉了   → 走了 fail-closed（规划器拒绝，或前进性台账判它不前进）。
 *
 * 为什么必须让驱动去读、不能在这里直接碰 page[0]：与 probe-xonly 同一个理由 ——
 * fail-closed 的退虚拟化是**同特权级返回**，用户态触发会带着 ring-3 的 RSP/RIP
 * 在 ring 0 上返回，实测直接蓝屏。走 OP_READ_PHYSICAL 时真正的访问发生在驱动的
 * 内核态窗口里，撞的是同一张叶，而退虚拟化回到的是内核上下文。
 *
 * 前置：调用方必须先跑 prepare-eptpsw 与 self-test。常驻由本命令自己起停，
 * 因为那一页是本进程的内存、必须活到常驻起来为止。
 */
/* 定义在后面；view-effect 装完视图之后要立刻用它把叶打出来。 */
static int DoEptLeaf(HANDLE h, unsigned long long target, int asJson);
/*
 * 同样定义在后面。view-effect 会在**视图仍装着、常驻在跑**的那一刻顺带跑一次
 * 添加后自检 —— 那是唯一能把 view-verify 的两层都真正测到的窗口，而从 CLI 装
 * 一条持久视图是不安全的（进程退出后那一页被释放，视图就指向已释放内存）。
 */
static int DoViewVerify(HANDLE h, int asJson);

static int DoViewEffect(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    KSWORD_ARK_HVM_VIEW_REQUEST vreq;
    KSWORD_ARK_HVM_VIEW_RESPONSE vrsp;
    DWORD returned = 0;
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;
    unsigned long viewId = 0UL;
    unsigned long residentAfter = 0UL;
    unsigned char observed = 0U;
    int installed = 0;
    int started = 0;
    int probed = 0;
    int readFailed = 0;
    int eptpSwitch = 0;
    const char* verdictText = "未判定";
    int rc = 3;

    memset(&vrsp, 0, sizeof(vrsp));
    /* --- 0. 前置：必须已经 prepare 且常驻没在跑 --- */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    eptpSwitch =
        (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED) != 0ULL;
    if (qrsp.residentProcessorCount != 0UL) {
        verdictText = "常驻正在跑：视图表不可变，装不上。先 stop。";
        goto report;
    }
    if ((qrsp.stateFlags & KSWORD_ARK_HVM_STATE_EPT_READY) == 0UL) {
        verdictText = "EPT_READY 没置位。先 prepare-eptpsw。";
        goto report;
    }

    /* --- 1. 真页写标记 --- */
    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    (void)VirtualLock((LPVOID)page, 4096);
    page[0] = 0xA5U;

    /* --- 2. VA -> PA --- */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = (unsigned long long)(ULONG_PTR)page;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK) {
        fprintf(stderr, "TRANSLATE 失败：status=%lu nt=0x%08lX\n",
                mrsp.status, (unsigned long)mrsp.ntStatus);
        rc = 1;
        goto cleanup;
    }
    physical = mrsp.physicalAddress & ~0xFFFULL;

    /* --- 3. 装 CLOAK 视图，影子填零 --- */
    memset(&vreq, 0, sizeof(vreq));
    vreq.operation = KSWORD_ARK_HVM_VIEW_OP_ADD;
    vreq.kind = KSWORD_ARK_HVM_VIEW_KIND_CLOAK;
    vreq.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_VIEW_FLAG_SEED_ZERO;
    vreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    vreq.physicalAddress = physical;
    if (ViewIoctl(h, &vreq, &vrsp) != 0) { rc = 1; goto cleanup; }
    if (vrsp.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
        verdictText = "视图装不上，这一项测不到生效与否。";
        rc = 3;
        goto report;
    }
    installed = 1;
    viewId = vrsp.viewId;
    /*
     * 装完立刻把基座里那张叶打出来。
     *
     * 这一步回答的是别处都回答不了的那个问题：ADD 说成功了，**叶到底变了没有**。
     * 「装上了但没生效」这个故障有两种完全不同的成因（叶压根没被限制 / 叶被限制
     * 了但那次访问没走到它），而它们在最终读数上长得一模一样。
     */
    if (!asJson) {
        (void)DoEptLeaf(h, physical, 0);
    }

    /* --- 4. 起常驻：装好视图之后 EPT 才开始强制 --- */
    if (!ProbeControl(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED,
                      "START_RESIDENT")) {
        verdictText = "常驻起不来，这一项测不到生效与否。";
        rc = 3;
        goto cleanup_view;
    }
    started = 1;

    /* --- 5. 让驱动去读那一页 --- */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = physical;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL)) {
        fprintf(stderr, "READ_PHYSICAL 未返回：win32=%lu\n", GetLastError());
        goto cleanup_view;
    }
    if (mrsp.status == KSWORD_ARK_HVM_MEMORY_STATUS_OK &&
        mrsp.bytesTransferred >= 1UL) {
        observed = mrsp.data[0];
    } else {
        readFailed = 1;
    }
    probed = 1;
    /* 视图仍装着、常驻在跑 —— 添加后自检唯一能两层都测到的窗口。 */
    if (!asJson) {
        (void)DoViewVerify(h, 0);
    }
    /*
     * 这两个字段决定这次读到底有没有经过我们改的那张叶。
     *
     * resolvedPhysical 与目标不同 ⇒ 读的根本是别的页；
     * usedDirectWindow ⇒ 走的是驱动的私有页表窗口，那条路的映射方式与普通
     * 内核访问不同，「没触发违规」就可能只是说明它绕开了这张叶，而不是说明
     * EPT 没生效。缺了这两个读数，两种成因在最终结果上完全同形。
     */
    if (!asJson) {
        printf("  读实际解析到 : 0x%016llX   （目标 0x%016llX）\n",
               mrsp.physicalAddress, physical);
        printf("  私有窗口     : usedDirectWindow=%u windowReady=%u\n",
               (unsigned)mrsp.usedDirectWindow, (unsigned)mrsp.windowReady);
    }

    /* --- 6. 常驻还在不在，是与读回值同等重要的判据 --- */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                        &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        residentAfter = qrsp.residentProcessorCount;
    } else {
        probed = 0;
    }

    /* --- 7. 判定 --- */
    if (!probed) {
        verdictText = "读后查询失败，无法判定。";
        rc = 3;
    } else if (residentAfter == 0UL) {
        verdictText = "**常驻掉了** —— 走了 fail-closed："
                      "规划器拒绝，或前进性台账判这次切换不前进。";
        rc = 2;
    } else if (readFailed) {
        verdictText = "常驻还在但读失败了，语义不明，按未通过处理。";
        rc = 2;
    } else if (observed == 0x00U) {
        verdictText = "**视图生效**：读回影子内容（0x00），真页的 0xA5 没有泄露，"
                      "且常驻全程未掉 —— EPTP 切换真的服务了这次违规。";
        rc = 0;
    } else if (observed == 0xA5U) {
        verdictText = "**视图没生效**：读回真页的 0xA5。"
                      "装上了但那次读没有被重定向到影子。";
        rc = 2;
    } else {
        verdictText = "读回一个既不是影子也不是真页的值，判未通过。";
        rc = 2;
    }

cleanup_view:
    if (started) {
        (void)ProbeControl(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                           KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED,
                           "STOP_RESIDENT");
        started = 0;
    }
    if (installed) {
        KSWORD_ARK_HVM_VIEW_REQUEST rreq2;
        KSWORD_ARK_HVM_VIEW_RESPONSE rrsp2;
        memset(&rreq2, 0, sizeof(rreq2));
        rreq2.operation = KSWORD_ARK_HVM_VIEW_OP_REMOVE;
        rreq2.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED;
        rreq2.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        rreq2.viewId = viewId;
        if (ViewIoctl(h, &rreq2, &rrsp2) != 0 ||
            rrsp2.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
            fprintf(stderr, "**视图没能移除**：status=%lu (%s)\n",
                    rrsp2.status, ViewStatusName(rrsp2.status));
            rc = 2;
        }
        installed = 0;
    }

report:
    if (asJson) {
        printf("{\"kind\":\"view-effect\",\"eptpSwitchArmed\":%s,"
               "\"installed\":%s,\"probed\":%s,\"readFailed\":%s,"
               "\"observedByte\":%u,\"residentAfter\":%lu,"
               "\"physicalAddress\":\"0x%016llX\",\"exitCode\":%d,"
               "\"verdict\":\"%s\"}\n",
               eptpSwitch ? "true" : "false",
               probed ? "true" : "false",
               probed ? "true" : "false",
               readFailed ? "true" : "false",
               (unsigned)observed, residentAfter, physical, rc, verdictText);
    } else {
        printf("\n=== view-effect（分离视图是否真的生效）===\n");
        printf("  后端         : %s\n",
               eptpSwitch ? "EPTP 切换" : "写叶 + monitor-trap");
        printf("  物理页       : 0x%016llX\n", physical);
        printf("  读回字节     : 0x%02X   （影子=0x00，真页=0xA5）\n",
               (unsigned)observed);
        printf("  读后常驻数   : %lu   （0 表示走了 fail-closed）\n",
               residentAfter);
        printf("  判定         : %s\n", verdictText);
    }

cleanup:
    if (page != NULL) {
        (void)VirtualUnlock((LPVOID)page, 4096);
        (void)VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    }
    return rc;
}

/*
 * ept-leaf <物理地址>：从用户态走一遍 EPT，把四级项逐个打出来。
 *
 * 存在的理由是这条线上反复缺同一个读数：「规则/视图装上了」与「那张叶真的被
 * 限制了」是两件事，而协议只回答前者（ADD 响应里的 deniedAccess 是**归一化后的
 * 请求**，不是叶的现值）。缺了这个读数，「装上了但没生效」只能靠猜。
 *
 * 做法不需要改驱动：EPT 表本身是我们自己分配的普通客户机物理内存、被身份映射成
 * RWX，所以用现成的 OP_READ_PHYSICAL 就能读。根地址从 status 的 eptPointer 取。
 *
 * 读到的是**基座**层次。EPTP 切换后端的次层次不在这条链上（那正是它的设计），
 * 所以这个命令回答的是「基座里这一页此刻允许什么」。
 */
static int DoEptLeaf(HANDLE h, unsigned long long target, int asJson)
{
    static const char* const kLevelName[4] = { "PML4", "PDPT", "PD  ", "PT  " };
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    DWORD returned = 0;
    unsigned long long table = 0ULL;
    unsigned long long entry = 0ULL;
    unsigned long long entries[4];
    unsigned long indices[4];
    int level = 0;
    int large = 0;
    int ok = 1;

    memset(entries, 0, sizeof(entries));
    memset(indices, 0, sizeof(indices));
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (qrsp.eptPointer == 0ULL) {
        fprintf(stderr, "eptPointer 为零：EPT 还没建好，先 prepare。\n");
        return 3;
    }
    /* 只取根地址，低 12 位是内存类型/级数/AD 等字段。 */
    table = qrsp.eptPointer & 0x000FFFFFFFFFF000ULL;
    indices[0] = (unsigned long)((target >> 39) & 0x1FFULL);
    indices[1] = (unsigned long)((target >> 30) & 0x1FFULL);
    indices[2] = (unsigned long)((target >> 21) & 0x1FFULL);
    indices[3] = (unsigned long)((target >> 12) & 0x1FFULL);

    for (level = 0; level < 4; ++level) {
        memset(&mreq, 0, sizeof(mreq));
        memset(&mrsp, 0, sizeof(mrsp));
        mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
        mreq.size = (unsigned long)sizeof(mreq);
        mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL;
        mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
        mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
        mreq.address = table + ((unsigned long long)indices[level] * 8ULL);
        mreq.length = 8UL;
        if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                             &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
            mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
            mrsp.bytesTransferred < 8UL) {
            fprintf(stderr, "读第 %d 级失败：status=%lu nt=0x%08lX\n",
                    level, mrsp.status, (unsigned long)mrsp.ntStatus);
            ok = 0;
            break;
        }
        entry = 0ULL;
        {
            int b = 0;
            for (b = 7; b >= 0; --b) {
                entry = (entry << 8) | (unsigned long long)mrsp.data[b];
            }
        }
        entries[level] = entry;
        /* 项为零表示这一级没有映射，再往下走没有意义。 */
        if (entry == 0ULL) { break; }
        /* 大页在 PDPT/PD 上以 bit7 标记，命中就到此为止。 */
        if (level >= 1 && level <= 2 && (entry & 0x80ULL) != 0ULL) {
            large = 1;
            break;
        }
        table = entry & 0x000FFFFFFFFFF000ULL;
    }

    if (asJson) {
        printf("{\"kind\":\"ept-leaf\",\"target\":\"0x%016llX\","
               "\"eptPointer\":\"0x%016llX\",\"largePage\":%s,\"levels\":[",
               target, qrsp.eptPointer, large ? "true" : "false");
        for (level = 0; level < 4; ++level) {
            printf("%s{\"level\":\"%s\",\"index\":%lu,\"entry\":\"0x%016llX\","
                   "\"r\":%s,\"w\":%s,\"x\":%s}",
                   level == 0 ? "" : ",",
                   kLevelName[level], indices[level], entries[level],
                   (entries[level] & 1ULL) ? "true" : "false",
                   (entries[level] & 2ULL) ? "true" : "false",
                   (entries[level] & 4ULL) ? "true" : "false");
        }
        printf("],\"ok\":%s}\n", ok ? "true" : "false");
        return ok ? 0 : 1;
    }
    printf("\n=== EPT 叶（基座层次）===\n");
    printf("  目标 GPA     : 0x%016llX\n", target);
    printf("  eptPointer   : 0x%016llX\n", qrsp.eptPointer);
    for (level = 0; level < 4; ++level) {
        printf("  %s [%3lu] = 0x%016llX   R=%d W=%d X=%d%s\n",
               kLevelName[level], indices[level], entries[level],
               (entries[level] & 1ULL) ? 1 : 0,
               (entries[level] & 2ULL) ? 1 : 0,
               (entries[level] & 4ULL) ? 1 : 0,
               (level >= 1 && level <= 2 && (entries[level] & 0x80ULL))
                   ? "   <大页，到此为止>" : "");
        if (entries[level] == 0ULL) { break; }
        if (level >= 1 && level <= 2 && (entries[level] & 0x80ULL)) { break; }
    }
    return ok ? 0 : 1;
}

/*
 * 取一页在**基座**层次里的叶项值。DoEptLeaf 的无输出版本。
 *
 * 走的是 OP_READ_PHYSICAL：EPT 表是驱动自己分配、被身份映射成 RWX 的普通客户机
 * 物理内存，所以用户态读得到。返回 0 表示读到了。
 */
static int EptLeafEntry(HANDLE h, unsigned long long target,
                        unsigned long long* entry)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    DWORD returned = 0;
    unsigned long long table = 0ULL;
    unsigned long long value = 0ULL;
    unsigned long idx[4];
    int level = 0;

    if (entry == NULL) { return 1; }
    *entry = 0ULL;
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL) ||
        qrsp.eptPointer == 0ULL) {
        return 1;
    }
    table = qrsp.eptPointer & 0x000FFFFFFFFFF000ULL;
    idx[0] = (unsigned long)((target >> 39) & 0x1FFULL);
    idx[1] = (unsigned long)((target >> 30) & 0x1FFULL);
    idx[2] = (unsigned long)((target >> 21) & 0x1FFULL);
    idx[3] = (unsigned long)((target >> 12) & 0x1FFULL);
    for (level = 0; level < 4; ++level) {
        int b = 0;
        memset(&mreq, 0, sizeof(mreq));
        memset(&mrsp, 0, sizeof(mrsp));
        mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
        mreq.size = (unsigned long)sizeof(mreq);
        mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL;
        mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
        mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
        mreq.address = table + ((unsigned long long)idx[level] * 8ULL);
        mreq.length = 8UL;
        if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                             &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
            mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
            mrsp.bytesTransferred < 8UL) {
            return 1;
        }
        value = 0ULL;
        for (b = 7; b >= 0; --b) {
            value = (value << 8) | (unsigned long long)mrsp.data[b];
        }
        if (value == 0ULL) { return 1; }
        /* 大页：这一页不是四级叶，调用方的期望不成立。 */
        if (level >= 1 && level <= 2 && (value & 0x80ULL) != 0ULL) { return 1; }
        if (level == 3) { break; }
        table = value & 0x000FFFFFFFFFF000ULL;
    }
    *entry = value;
    return 0;
}

/* 读一页的第一个字节，返回 0 表示读到了。 */
static int ReadPhysicalByte(HANDLE h, unsigned long long physical,
                            unsigned char* value)
{
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    DWORD returned = 0;

    if (value == NULL) { return 1; }
    *value = 0U;
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = physical;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
        mrsp.bytesTransferred < 1UL) {
        return 1;
    }
    *value = mrsp.data[0];
    return 0;
}

/* ------------------------------------------------------------------------ */
/* 自检                                                                       */
/* ------------------------------------------------------------------------ */

/*
 * 三态，和别处一致：能力齐 / 不满足 / **无区分力**。
 *
 * 第三态是这里的重点。一条自检项如果在「前提没建立」时也报 OK，
 * 那它给出的全绿只说明它自己没被问到 —— 这条线上反复吃这个亏。
 */
#define SC_OK    0
#define SC_BLOCK 1
#define SC_VOID  2
/*
 * 第四态：**信息**。既不是通过也不是失败，是一个「决定怎么走」的事实。
 *
 * 加它是因为把 Monitor Trap Flag 硬塞进通过/失败两态本身就是造假判据：
 * 这台机器缺 MTF，但 EPTP 切换后端把视图装上并实测生效了。报成「阻塞」会让
 * 一台完全可用的机器显示成不能用 —— 而「看着不能用其实能用」和
 * 「看着能用其实不能用」是同一种病的两面。
 */
#define SC_INFO  3

typedef struct _SC_ITEM
{
    const char* name;
    int state;
    const char* detail;   /* 为什么，以及能做什么。不许只给状态码。 */
} SC_ITEM;

static const char* ScName(int s)
{
    switch (s) {
    case SC_OK:    return "OK";
    case SC_BLOCK: return "阻塞";
    case SC_VOID:  return "未标定";
    default:       return "信息";
    }
}

/*
 * 使用前自检：回答「这台机器能不能做我要做的事，现在状态干不干净」。
 *
 * 只读：QUERY_HVM + PLATFORM，两个都不进 VMX、不分配、不改任何执行路径。
 * 分两组 —— 能力（机器给不给）与状态（现在能不能开工）—— 因为两者的补救方式
 * 完全不同：能力不足只能换机器或换后端，状态不干净是 stop/teardown 就能修的。
 */
static int DoSelfCheck(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_PLATFORM_REQUEST preq;
    KSWORD_ARK_HVM_PLATFORM_RESPONSE prsp;
    DWORD returned = 0;
    SC_ITEM items[16];
    unsigned long count = 0UL;
    unsigned long blocked = 0UL;
    unsigned long voided = 0UL;
    unsigned long i = 0UL;
    int platformOk = 0;
    int mtf = 0;
    int execOnly = 0;
    int inveptSingle = 0;
    int eptpArmed = 0;
    const char* backend = "两个后端都不可用";

    memset(items, 0, sizeof(items));
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu —— 驱动没加载？\n",
                GetLastError());
        return 1;
    }
    if (qrsp.backend == KSWORD_ARK_HVM_BACKEND_SVM) {
        int ready = qrsp.queryStatus == KSWORD_ARK_HVM_QUERY_STATUS_OK &&
            (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED) != 0;
        if (asJson) {
            printf("{\"kind\":\"selfcheck\",\"backend\":\"SVM\",\"capabilityReady\":%s,\"prepared\":%lu,\"tested\":%lu,\"resident\":%lu,\"lastStatus\":\"0x%08lX\"}\n",
                   ready ? "true" : "false", qrsp.preparedProcessorCount, qrsp.selfTestPassedProcessorCount,
                   qrsp.residentProcessorCount, qrsp.backendStatus);
        } else {
            printf("Experimental SVM/NPT: capability=%d prepared=%lu tested=%lu resident=%lu status=0x%08lX\n",
                   ready, qrsp.preparedProcessorCount, qrsp.selfTestPassedProcessorCount, qrsp.residentProcessorCount, qrsp.backendStatus);
        }
        return ready ? 0 : 2;
    }
    memset(&preq, 0, sizeof(preq));
    memset(&prsp, 0, sizeof(prsp));
    /*
     * PLATFORM 有**自己的**协议版本号，不是通用的那个。用错会被版本检查打成
     * 失败，而那和「读不到寄存器」长得一模一样。MEMORY IOCTL 也有同样的坑，
     * 这里已经踩过一次。
     */
    preq.version = KSWORD_ARK_HVM_PLATFORM_PROTOCOL_VERSION;
    preq.size = (unsigned long)sizeof(preq);
    platformOk =
        DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_PLATFORM, &preq, sizeof(preq),
                        &prsp, (DWORD)sizeof(prsp), &returned, NULL) &&
        returned >= sizeof(prsp);

    mtf = (qrsp.featureFlags &
           KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) != 0ULL;
    inveptSingle = (qrsp.featureFlags &
           KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) != 0ULL;
    execOnly = (qrsp.vmxEptVpidCapabilities & 1ULL) != 0ULL;
    eptpArmed = (qrsp.featureFlags &
           KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED) != 0ULL;

    /* ---- 第一组：能力（机器给不给）---- */
    items[count].name = "VMX 可用";
    items[count].state = (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_VMX)
        ? SC_OK : SC_BLOCK;
    items[count].detail = (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_VMX)
        ? "CPUID 报告 VT-x"
        : "CPUID 里没有 VT-x。注意：常驻期间驱动会按设计抹掉这一位，"
          "所以先确认常驻没在跑（本自检下面有这一项）";
    count++;

    items[count].name = "EPT + 四级页遍历";
    items[count].state =
        ((qrsp.featureFlags & (KSWORD_ARK_HVM_FEATURE_EPT |
                               KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL)) ==
         (KSWORD_ARK_HVM_FEATURE_EPT | KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL))
        ? SC_OK : SC_BLOCK;
    items[count].detail = "分离视图与 EPT 规则都建立在四级 EPT 上";
    count++;

    items[count].name = "INVEPT single-context";
    items[count].state = inveptSingle ? SC_OK : SC_BLOCK;
    items[count].detail = inveptSingle
        ? "两个分离视图后端都需要它，用来丢弃被换掉那一侧的翻译"
        : "缺它则任何一个后端都无法保证换过去之后旧翻译不再被使用";
    count++;

    items[count].name = "execute-only EPT 叶";
    items[count].state = execOnly ? SC_OK : SC_BLOCK;
    items[count].detail = execOnly
        ? "IA32_VMX_EPT_VPID_CAP bit0 置位：CLOAK 可编码，EPTP 切换后端可用"
        : "缺它 CLOAK 的主值不得不放开读，什么也藏不住；"
          "EPTP 切换后端也整体不可用（它对 CLOAK 与 HOOK 一视同仁地要求这一位）";
    count++;

    /*
     * MTF 是**信息**不是判据：它决定用哪个后端，不决定能不能用。
     * 真正的门是下面那条「可用的分离视图后端」。
     */
    items[count].name = "Monitor Trap Flag";
    items[count].state = SC_INFO;
    items[count].detail = mtf
        ? "有：默认「写叶 + 单步」后端可用"
        : "没有（嵌套 Hyper-V 不向客户机通告它）。**这不阻塞** —— "
          "EPTP 切换后端不需要 MTF，用 prepare 时请求那个后端即可";
    count++;

    /* ---- 后端可用性：把上面几项合成一个可执行的结论 ---- */
    if (inveptSingle && mtf) { backend = "写叶 + monitor-trap（默认）"; }
    if (inveptSingle && execOnly) {
        backend = mtf ? "两个都可用（默认后端 / EPTP 切换）" : "仅 EPTP 切换";
    }
    items[count].name = "可用的分离视图后端";
    items[count].state = (inveptSingle && (mtf || execOnly)) ? SC_OK : SC_BLOCK;
    items[count].detail = backend;
    count++;

    items[count].name = "当前武装的后端";
    items[count].state = SC_OK;
    items[count].detail = eptpArmed
        ? "EPTP 切换（已武装）"
        : "写叶 + monitor-trap（默认）。要换成 EPTP 切换必须在 PREPARE 时请求 —— "
          "已经 prepare 过的运行时改开关不会生效，要先 teardown";
    count++;

    /* ---- 第二组：状态（现在能不能开工）---- */
    {
        const int faulted =
            (qrsp.stateFlags & KSWORD_ARK_HVM_STATE_FAULTED) != 0UL;
        const int rollback =
            (qrsp.stateFlags & KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED) != 0UL;
        items[count].name = "无 FAULTED / ROLLBACK_REQUIRED";
        items[count].state = (faulted || rollback) ? SC_BLOCK : SC_OK;
        items[count].detail = (faulted || rollback)
            ? "状态里带故障位，START_RESIDENT 会被直接拒。先 reset-fault"
            : "状态干净";
        count++;
    }

    items[count].name = "常驻未在跑";
    items[count].state = (qrsp.residentProcessorCount == 0UL)
        ? SC_OK : SC_BLOCK;
    items[count].detail = (qrsp.residentProcessorCount == 0UL)
        ? "视图表与规则表可改"
        : "常驻期间视图表与规则表**不可变**（退出路径不取那把锁就读它们）。"
          "装视图/规则的顺序只能是 prepare → 装 → START_RESIDENT。先 stop";
    count++;

    /*
     * processorCount 在 PREPARE **之前**是 0 —— 驱动那时还没数处理器。
     * 拿一个还没填的字段去判 `!= 1` 会把「还没测」报成「阻塞」，
     * 而那正是这条线上反复出现的空过/误报形状。所以先分清「测没测到」。
     */
    items[count].name = "单处理器拓扑或已武装私有 EPT";
    if (qrsp.processorCount == 0UL) {
        items[count].state = SC_VOID;
        items[count].detail = "PREPARE 之前驱动还没数处理器，这一项**这次没测到**。"
                              "prepare 之后再跑一次自检";
    } else if (qrsp.processorCount == 1UL ||
               (qrsp.featureFlags &
                    KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED) != 0ULL) {
        items[count].state = SC_OK;
        items[count].detail = (qrsp.processorCount == 1UL)
            ? "1 vCPU：多核安全门不触发"
            : "多核，但私有 EPT 层次已武装";
    } else {
        items[count].state = SC_BLOCK;
        items[count].detail = "多核且没有私有 EPT 层次：视图安装会被拒"
                              "（翻转窗口对别的处理器可见）";
    }
    count++;

    /* ---- 第三组：平台标定（读不到就报未标定，不猜）---- */
    if (!platformOk || prsp.validMask != KSW_PLATFORM_VALID_ALL) {
        items[count].name = "平台标定（CET / KVA shadow / GS base）";
        items[count].state = SC_VOID;
        items[count].detail = "PLATFORM 探针没能读全八个字段。"
            "这一项**不算通过也不算失败** —— 没标定的量不能拿来下结论";
        count++;
    } else {
        const int cet = (prsp.cr4 & (1ULL << 23)) != 0ULL;
        items[count].name = "CET（CR4 bit23）";
        items[count].state = SC_OK;
        items[count].detail = cet
            ? "开着。注意：CR4.CET=1 时任何清 CR0.WP 的老式改内存写法都会吃 #GP"
            : "关着";
        count++;
    }

    /* ---- 汇总 ---- */
    for (i = 0UL; i < count; ++i) {
        if (items[i].state == SC_BLOCK) { blocked++; }
        if (items[i].state == SC_VOID)  { voided++; }
    }

    if (asJson) {
        printf("{\"kind\":\"selfcheck\",\"blocked\":%lu,\"void\":%lu,"
               "\"backend\":\"%s\",\"items\":[", blocked, voided, backend);
        for (i = 0UL; i < count; ++i) {
            printf("%s{\"name\":\"%s\",\"state\":\"%s\",\"detail\":\"%s\"}",
                   (i == 0UL) ? "" : ",",
                   items[i].name, ScName(items[i].state), items[i].detail);
        }
        printf("]}\n");
    } else {
        printf("\n=== 使用前自检（只读，不进 VMX）===\n");
        for (i = 0UL; i < count; ++i) {
            printf("  [%-6s] %s\n", ScName(items[i].state), items[i].name);
            printf("           %s\n", items[i].detail);
        }
        printf("\n  阻塞 %lu 项，未标定 %lu 项。\n", blocked, voided);
        if (blocked == 0UL) {
            printf("  可以开工。分离视图后端：%s\n", backend);
        }
    }
    /* 有阻塞退 2；只有未标定退 3；全好退 0。 */
    return (blocked != 0UL) ? 2 : ((voided != 0UL) ? 3 : 0);
}

/*
 * 添加后自检：逐条已安装的视图，回答两个**不同**的问题。
 *
 * 分两层不是为了细致，是因为今天实测到它们可以给出相反的答案：
 * 共享 EPT 根跨 residency 边界不失效时，叶被正确写成主值（结构对）而处理器
 * 沿用旧翻译（完全不生效），两者同时成立。把它们合成一句「视图正常」，
 * 就恰好造出这个项目最坏的那种故障 —— 装上了、报绿了、什么用没有。
 *
 *   结构：基座里那张叶是不是被写成了这种视图的主值？常驻停着也能查。
 *   生效：一次真实访问是不是真被重定向了？**必须常驻在跑**才有意义。
 *
 * 生效这一层只对 CLOAK 有区分力：CLOAK 把**读**重定向到影子，而我们只能发起读。
 * HOOK 重定向的是**取指**，读本来就该看到真页 —— 用读去验 HOOK 会得到
 * 「没生效」的假结论，所以这里显式报「无区分力」而不是给一个错的判定。
 */
static int DoViewVerify(HANDLE h, int asJson)
{
    KSWORD_ARK_HVM_VIEW_REQUEST vreq;
    KSWORD_ARK_HVM_VIEW_RESPONSE vrsp;
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    DWORD returned = 0;
    unsigned long i = 0UL;
    unsigned long bad = 0UL;
    unsigned long voidCount = 0UL;
    int residentRunning = 0;

    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    residentRunning = (qrsp.residentProcessorCount != 0UL);

    memset(&vreq, 0, sizeof(vreq));
    vreq.operation = KSWORD_ARK_HVM_VIEW_OP_QUERY;
    if (ViewIoctl(h, &vreq, &vrsp) != 0) { return 1; }
    if (vrsp.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
        fprintf(stderr, "VIEW QUERY 返回 %lu (%s)\n",
                vrsp.status, ViewStatusName(vrsp.status));
        return 1;
    }

    if (!asJson) {
        printf("\n=== 添加后自检：已安装视图 %lu 条 ===\n", vrsp.returnedRows);
        printf("  常驻状态 : %s\n", residentRunning
            ? "在跑 —— 生效层可测"
            : "**没在跑** —— 生效层这次无区分力（没有 EPT 强制，读当然看到真页）");
    } else {
        printf("{\"kind\":\"view-verify\",\"resident\":%s,\"rows\":[",
               residentRunning ? "true" : "false");
    }

    for (i = 0UL; i < vrsp.returnedRows && i < KSWORD_ARK_HVM_MAX_VIEWS; ++i) {
        const KSWORD_ARK_HVM_VIEW_ROW* row = &vrsp.rows[i];
        unsigned long long leaf = 0ULL;
        int structOk = 0;
        int structKnown = (EptLeafEntry(h, row->physicalAddress, &leaf) == 0);
        const char* structText = "叶读不到（页可能仍是 2MiB 大页，或表已变）";
        const char* effectText = "";
        int effectState = SC_VOID;
        unsigned char viaEpt = 0U;
        unsigned char viaShadow = 0U;

        if (structKnown) {
            const int r = (leaf & 1ULL) != 0ULL;
            const int w = (leaf & 2ULL) != 0ULL;
            const int x = (leaf & 4ULL) != 0ULL;
            const unsigned long long frame = leaf & 0x000FFFFFFFFFF000ULL;
            if (row->kind == KSWORD_ARK_HVM_VIEW_KIND_CLOAK) {
                structOk = (!r && !w && x &&
                            frame == (row->physicalAddress &
                                      0x000FFFFFFFFFF000ULL));
                structText = structOk
                    ? "叶 = execute-only 指向真页：CLOAK 主值，正确"
                    : "叶不是 CLOAK 的主值（应为 execute-only 指向真页）";
            } else {
                structOk = (r && w && !x &&
                            frame == (row->physicalAddress &
                                      0x000FFFFFFFFFF000ULL));
                structText = structOk
                    ? "叶 = RW 指向真页、拒绝执行：HOOK 主值，正确"
                    : "叶不是 HOOK 的主值（应为 RW 指向真页且不可执行）";
            }
        }

        /* ---- 生效层 ---- */
        if (!residentRunning) {
            effectState = SC_VOID;
            effectText = "常驻没在跑，没有 EPT 强制 —— 这次测不到";
        } else if (row->kind != KSWORD_ARK_HVM_VIEW_KIND_CLOAK) {
            effectState = SC_VOID;
            effectText = "HOOK 重定向的是取指，用读验不出来 —— **无区分力**，"
                         "不是没生效";
        } else if (ReadPhysicalByte(h, row->physicalAddress, &viaEpt) != 0 ||
                   ReadPhysicalByte(h, row->shadowPhysicalAddress,
                                    &viaShadow) != 0) {
            effectState = SC_VOID;
            effectText = "读失败，判不了";
        } else if (viaEpt == viaShadow) {
            /*
             * 相等只在「影子与真页内容本来就不同」时才是证据。
             * 影子若是从目标页拷来的（SEED_FROM_TARGET），两边天生相同，
             * 这时相等什么都不证明 —— 必须报无区分力而不是通过。
             */
            if ((row->flags &
                 KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET) != 0UL) {
                effectState = SC_VOID;
                effectText = "读回值与影子相同，但影子是从目标页拷来的，"
                             "两者本就一样 —— **无区分力**";
            } else {
                effectState = SC_OK;
                effectText = "读被重定向到影子（读回值 == 影子内容）";
            }
        } else {
            effectState = SC_BLOCK;
            effectText = "读回的**不是**影子内容 —— 重定向没有发生";
        }

        if (!structOk) { bad++; }
        if (effectState == SC_BLOCK) { bad++; }
        if (effectState == SC_VOID) { voidCount++; }

        if (asJson) {
            printf("%s{\"viewId\":%lu,\"kind\":\"%s\","
                   "\"physicalAddress\":\"0x%016llX\",\"leaf\":\"0x%016llX\","
                   "\"structOk\":%s,\"effect\":\"%s\",\"flips\":%llu}",
                   (i == 0UL) ? "" : ",",
                   row->viewId, ViewKindName(row->kind),
                   row->physicalAddress, leaf,
                   structOk ? "true" : "false",
                   ScName(effectState), row->flipCount);
        } else {
            printf("\n  #%-3lu %-5s pa=0x%016llX flips=%llu\n",
                   row->viewId, ViewKindName(row->kind),
                   row->physicalAddress, row->flipCount);
            printf("    结构 [%-6s] %s\n",
                   structKnown ? (structOk ? "OK" : "阻塞") : "未标定",
                   structText);
            printf("    生效 [%-6s] %s\n", ScName(effectState), effectText);
        }
    }

    if (asJson) {
        printf("],\"bad\":%lu,\"void\":%lu}\n", bad, voidCount);
    } else {
        if (vrsp.returnedRows == 0UL) {
            printf("  （没有已安装的视图，这次什么都没测到）\n");
        }
        printf("\n  不合格 %lu 项，无区分力 %lu 项。\n", bad, voidCount);
    }
    if (vrsp.returnedRows == 0UL) { return 3; }
    return (bad != 0UL) ? 2 : ((voidCount != 0UL) ? 3 : 0);
}

/*
 * CR 策略：这里只做 R-1 进程处置需要的那一件事——打开 / 关掉 CR3 追踪。
 *
 * 不做钉位（cr0/cr4 pinning）：那是另一类操作，掩码写错的后果是客户机再也改不了
 * 某个控制位，而这个工具的用途是在靶机上一条命令走完一次验证，不是配策略。
 */
static const char* CrPolicyStatusName(unsigned long s)
{
    switch (s) {
    case 0UL:  return "OK";
    default:   return "NOT_OK";
    }
}

static int DoCrTrackCr3(HANDLE h, int enable, int asJson)
{
    KSWORD_ARK_HVM_CR_POLICY_REQUEST req;
    KSWORD_ARK_HVM_CR_POLICY_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;

    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_HVM_CR_POLICY_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.operation = enable
        ? KSWORD_ARK_HVM_CR_POLICY_OP_SET
        : KSWORD_ARK_HVM_CR_POLICY_OP_CLEAR;
    req.flags = KSWORD_ARK_HVM_CR_POLICY_FLAG_UI_CONFIRMED |
        (enable ? KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3 : 0UL);
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    memset(&rsp, 0, sizeof(rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_CR_POLICY, &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp)) {
        fprintf(stderr, "CR_POLICY IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
                (int)ok, returned, GetLastError());
        return 1;
    }
    if (asJson) {
        printf("{\"kind\":\"cr-track-cr3\",\"enable\":%d,\"status\":%lu,"
               "\"flags\":%lu,\"generation\":%lu,\"cr3SwitchCount\":%llu}\n",
               enable, rsp.status, rsp.flags, rsp.generation, rsp.cr3SwitchCount);
        return (rsp.status == 0UL) ? 0 : 2;
    }
    printf("\n=== CR3 追踪 %s ===\n", enable ? "打开" : "关闭");
    printf("  status       : %lu (%s)\n", rsp.status, CrPolicyStatusName(rsp.status));
    printf("  策略位       : 0x%lX  TRACK_CR3=%s\n", rsp.flags,
           ((rsp.flags & KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3) != 0UL)
               ? "是" : "否");
    printf("  代次         : %lu   已观察地址空间切换 %llu 次\n",
           rsp.generation, rsp.cr3SwitchCount);
    printf("  注意：这一位在**常驻启动时**写进 VMCS，常驻起来之后再改不生效。\n");
    return (rsp.status == 0UL) ? 0 : 2;
}

static const char* InjectStatusName(unsigned long s)
{
    switch (s) {
    case KSWORD_ARK_HVM_INJECT_STATUS_OK:                    return "OK";
    case KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST:       return "INVALID_REQUEST";
    case KSWORD_ARK_HVM_INJECT_STATUS_NOT_PREPARED:          return "NOT_PREPARED";
    case KSWORD_ARK_HVM_INJECT_STATUS_REQUIRES_RESIDENT_STOPPED:
        return "REQUIRES_RESIDENT_STOPPED";
    case KSWORD_ARK_HVM_INJECT_STATUS_PROCESS_LOOKUP_FAILED: return "PROCESS_LOOKUP_FAILED";
    case KSWORD_ARK_HVM_INJECT_STATUS_TRANSLATION_FAILED:    return "TRANSLATION_FAILED";
    case KSWORD_ARK_HVM_INJECT_STATUS_TABLE_FULL:            return "TABLE_FULL";
    case KSWORD_ARK_HVM_INJECT_STATUS_NOT_FOUND:             return "NOT_FOUND";
    case KSWORD_ARK_HVM_INJECT_STATUS_ALREADY_ARMED:         return "ALREADY_ARMED";
    case KSWORD_ARK_HVM_INJECT_STATUS_PROTECTED_TARGET:      return "PROTECTED_TARGET";
    case KSWORD_ARK_HVM_INJECT_STATUS_CR3_TRACKING_REQUIRED: return "CR3_TRACKING_REQUIRED";
    case KSWORD_ARK_HVM_INJECT_STATUS_EPTP_SWITCH_REQUIRED:  return "EPTP_SWITCH_REQUIRED";
    case KSWORD_ARK_HVM_INJECT_STATUS_NO_CAVE:               return "NO_CAVE";
    case KSWORD_ARK_HVM_INJECT_STATUS_VIEW_FAILED:           return "VIEW_FAILED";
    case KSWORD_ARK_HVM_INJECT_STATUS_PAGE_NOT_EXECUTABLE:   return "PAGE_NOT_EXECUTABLE";
    default:                                                 return "UNKNOWN";
    }
}

static int InjectIoctl(HANDLE h,
                       KSWORD_ARK_HVM_INJECT_REQUEST* req,
                       KSWORD_ARK_HVM_INJECT_RESPONSE* rsp)
{
    DWORD returned = 0;
    BOOL ok;

    req->version = KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION;
    req->size = (unsigned long)sizeof(*req);
    memset(rsp, 0, sizeof(*rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_INJECT, req, (DWORD)sizeof(*req),
                         rsp, (DWORD)sizeof(*rsp), &returned, NULL);
    if (returned >= sizeof(*rsp)) {
        /* 响应完整就用响应，无论 ok 是真是假。 */
        return 0;
    }
    fprintf(stderr, "INJECT IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
            (int)ok, returned, GetLastError());
    return 1;
}

static void PrintInjectTable(const KSWORD_ARK_HVM_INJECT_RESPONSE* rsp, int asJson)
{
    unsigned long i;

    if (asJson) {
        printf("{\"kind\":\"hvm-inject\",\"status\":%lu,\"statusName\":\"%s\","
               "\"lastStatus\":\"0x%08lX\",\"rowCount\":%lu,\"generation\":%lu,"
               "\"rows\":[",
               rsp->status, InjectStatusName(rsp->status),
               (unsigned long)rsp->lastStatus, rsp->rowCount, rsp->generation);
        for (i = 0UL; i < rsp->returnedRows &&
                      i < KSWORD_ARK_HVM_MAX_INJECTIONS; ++i) {
            printf("%s{\"processId\":%lu,\"payloadBytes\":%lu,"
                   "\"directoryBase\":\"0x%016llX\","
                   "\"guestLinearAddress\":\"0x%016llX\","
                   "\"guestPhysicalAddress\":\"0x%016llX\","
                   "\"caveOffset\":%lu,\"caveBytes\":%lu,\"caveFiller\":%lu,"
                   "\"executionCount\":%llu,\"viewId\":%lu}",
                   (i == 0UL) ? "" : ",",
                   rsp->rows[i].processId, rsp->rows[i].payloadBytes,
                   rsp->rows[i].directoryBase, rsp->rows[i].guestLinearAddress,
                   rsp->rows[i].guestPhysicalAddress,
                   rsp->rows[i].caveOffset, rsp->rows[i].caveBytes,
                   rsp->rows[i].caveFiller,
                   rsp->rows[i].executionCount, rsp->rows[i].viewId);
        }
        printf("]}\n");
        return;
    }
    printf("\n=== R-1 进程注入 ===\n");
    printf("  status       : %lu (%s)  lastStatus=0x%08lX\n",
           rsp->status, InjectStatusName(rsp->status),
           (unsigned long)rsp->lastStatus);
    printf("  表内条数     : %lu   代次=%lu\n", rsp->rowCount, rsp->generation);
    if (rsp->returnedRows == 0UL) {
        printf("  （表里没有任何注入）\n");
    }
    for (i = 0UL; i < rsp->returnedRows &&
                  i < KSWORD_ARK_HVM_MAX_INJECTIONS; ++i) {
        printf("  pid=%-6lu cr3=0x%016llX gpa=0x%016llX gla=0x%016llX\n",
               rsp->rows[i].processId, rsp->rows[i].directoryBase,
               rsp->rows[i].guestPhysicalAddress,
               rsp->rows[i].guestLinearAddress);
        printf("           空隙偏移=%lu 长度=%lu 填充=0x%02lX 载荷=%lu 执行=%llu 视图#%lu\n",
               rsp->rows[i].caveOffset, rsp->rows[i].caveBytes,
               rsp->rows[i].caveFiller,
               rsp->rows[i].payloadBytes, rsp->rows[i].executionCount,
               rsp->rows[i].viewId);
    }
    if (rsp->status == KSWORD_ARK_HVM_INJECT_STATUS_NO_CAVE) {
        printf("  ** 这一页没有足够长的空隙 **：外壳加载荷放不下。换一页，或用\n");
        printf("     hvm_target 打印的 probe 页（整页空白，专为首次验证准备）。\n");
    }
    if (rsp->status == KSWORD_ARK_HVM_INJECT_STATUS_REQUIRES_RESIDENT_STOPPED) {
        printf("  ** 常驻正在跑 **：装注入要在常驻停着时做。\n");
        printf("     顺序：stop -> inject-test -> self-test -> resident。\n");
    }
}

/*
 * inject-test：最小可观测载荷 —— 往一个已知地址写一个常数。
 *
 * 选它做首次验证是因为判据干净：标记值从 0 变成这个常数，就证明外壳跑通了；
 * 而心跳继续推进，证明被借用的线程被完好地还了回来。两条缺一不可——只看
 * "进程没崩"证明不了载荷跑过，只看"标记变了"证明不了线程还能用。
 *
 *   48 B8 <imm64>   mov rax, markerAddress
 *   C7 00 <imm32>   mov dword ptr [rax], value
 *
 * 用绝对地址而不是 RIP 相对：外壳在页里的落点由驱动找空隙决定，调用方这边算不出
 * 相对距离。rax 由外壳负责保存恢复。
 */
static int DoInjectTest(HANDLE h, unsigned long pid,
                        unsigned long long gla,
                        unsigned long long markerAddress,
                        unsigned long value, int asJson)
{
    KSWORD_ARK_HVM_INJECT_REQUEST req;
    KSWORD_ARK_HVM_INJECT_RESPONSE rsp;
    unsigned long cursor = 0UL;
    unsigned long i;

    memset(&req, 0, sizeof(req));
    req.operation = KSWORD_ARK_HVM_INJECT_OP_ARM;
    req.injectType = KSWORD_ARK_HVM_INJECT_TYPE_SHELLCODE;
    req.processId = pid;
    req.guestLinearAddress = gla;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;

    req.payload[cursor++] = 0x48U;
    req.payload[cursor++] = 0xB8U;
    for (i = 0UL; i < 8UL; ++i) {
        req.payload[cursor++] =
            (unsigned char)((markerAddress >> (i * 8U)) & 0xFFULL);
    }
    req.payload[cursor++] = 0xC7U;
    req.payload[cursor++] = 0x00U;
    for (i = 0UL; i < 4UL; ++i) {
        req.payload[cursor++] =
            (unsigned char)((value >> (i * 8U)) & 0xFFUL);
    }
    req.payloadBytes = cursor;

    if (InjectIoctl(h, &req, &rsp) != 0) { return 1; }
    PrintInjectTable(&rsp, asJson);
    return (rsp.status == KSWORD_ARK_HVM_INJECT_STATUS_OK) ? 0 : 2;
}

/*
 * inject-dll：把一个 DLL 路径交给目标进程里的 LoadLibraryW。
 *
 * loadLibraryAddress 由调用方给，不由驱动解析：同一个模块在不同进程里基址不同，
 * 而调用方本来就在枚举目标的模块表。驱动再解析一遍等于把同一件事做两遍，还容易
 * 与调用方看到的不一致。
 *
 * 路径按 UTF-16 传（LoadLibraryW），长度不含结尾的零——驱动那边把超出长度的部分
 * 补零，结尾符因此是白来的。
 */
static int DoInjectDll(HANDLE h, unsigned long pid,
                       unsigned long long gla,
                       unsigned long long loadLibrary,
                       const char* path, int asJson)
{
    KSWORD_ARK_HVM_INJECT_REQUEST req;
    KSWORD_ARK_HVM_INJECT_RESPONSE rsp;
    int wideChars;

    /*
     * 给 0 就地解析。
     *
     * kernel32 在同一次启动内对所有进程是同一个基址（系统 DLL 的 ASLR 每次启动
     * 重定一次，不是每进程一次），所以在本进程里解析出来的 LoadLibraryW 对靶子
     * 同样成立。让这个原生程序自己解析，省掉调用方绕 PowerShell 互操作那一圈——
     * 那一圈的失败方式是**静默返回 0**，而 0 传进去只会换来一条"参数无效"。
     */
    if (loadLibrary == 0ULL) {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC resolved = (kernel32 != NULL)
            ? GetProcAddress(kernel32, "LoadLibraryW")
            : NULL;

        if (resolved == NULL) {
            fprintf(stderr, "解析 LoadLibraryW 失败：win32=%lu\n", GetLastError());
            return 1;
        }
        loadLibrary = (unsigned long long)(ULONG_PTR)resolved;
        fprintf(stderr, "LoadLibraryW = 0x%016llX（就地解析）\n", loadLibrary);
    }

    memset(&req, 0, sizeof(req));
    req.operation = KSWORD_ARK_HVM_INJECT_OP_ARM;
    req.injectType = KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH;
    req.processId = pid;
    req.guestLinearAddress = gla;
    req.loadLibraryAddress = loadLibrary;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;

    /* 不含结尾零：驱动补零，且补出来的零正好是字符串终止符。 */
    wideChars = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
        (wchar_t*)req.payload,
        (int)(KSWORD_ARK_HVM_INJECT_MAX_PAYLOAD_BYTES / sizeof(wchar_t)));
    if (wideChars <= 1) {
        fprintf(stderr, "路径转换失败或为空：%s\n", path);
        return 1;
    }
    req.payloadBytes = (unsigned long)((wideChars - 1) * (int)sizeof(wchar_t));

    if (InjectIoctl(h, &req, &rsp) != 0) { return 1; }
    PrintInjectTable(&rsp, asJson);
    return (rsp.status == KSWORD_ARK_HVM_INJECT_STATUS_OK) ? 0 : 2;
}

static int DoInjectSimple(HANDLE h, unsigned long op, unsigned long pid, int asJson)
{
    KSWORD_ARK_HVM_INJECT_REQUEST req;
    KSWORD_ARK_HVM_INJECT_RESPONSE rsp;

    memset(&req, 0, sizeof(req));
    req.operation = op;
    req.processId = pid;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;
    if (InjectIoctl(h, &req, &rsp) != 0) { return 1; }
    PrintInjectTable(&rsp, asJson);
    return (rsp.status == KSWORD_ARK_HVM_INJECT_STATUS_OK) ? 0 : 2;
}

/* 把一条 VMX 指令的架构结果译成能直接读的判据。 */
static const char* NestedProbeStepName(unsigned long r)
{
    switch (r) {
    case 0UL: return "成功";
    case 1UL: return "VMfailValid";
    case 2UL: return "VMfailInvalid";
    case KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED: return "**没执行到**";
    default:  return "?";
    }
}

static const char* NestedProbeStatusName(unsigned long s)
{
    switch (s) {
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_OK: return "OK";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_INVALID_REQUEST:
        return "INVALID_REQUEST";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_CONFIRMATION_REQUIRED:
        return "CONFIRMATION_REQUIRED";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NOT_ARMED:
        return "NOT_ARMED（本核没常驻，或嵌套派发没开）";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NO_RESOURCES:
        return "NO_RESOURCES";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_VMXE_REFUSED:
        return "VMXE_REFUSED（CR4.VMXE 置不上）";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_CONFIGURATION_FAILED:
        return "CONFIGURATION_FAILED（VMCS12 配置未通过，未进入 L2）";
    default: return "UNKNOWN";
    }
}

/*
 * 用**只读句柄**去调破坏性 IOCTL，看 I/O 管理器挡不挡。
 *
 * 这是访问位那次修复唯一算数的判据。光看头文件里写着 FILE_WRITE_ACCESS 证明不了
 * 什么 —— 访问位是 CTL_CODE 的一部分，驱动和客户端如果版本不一致，控制码根本对不上，
 * 那时"调不通"的原因与权限无关，而两者从外面看一模一样。所以这里同时验两面：
 * 只读句柄必须被拒（win32=5），读写句柄必须能走到驱动（拿到的是驱动的语义结果，
 * 不是 5）。只有两面都成立，才说明是闸门在起作用而不是控制码错位。
 */
/* Read the selected CPU's complete GDT through the existing R0 descriptor API.
 * CPL3 SGDT is not the kernel's table view on every Windows configuration.
 * The R0 collector performs and restores its own group affinity; this command
 * must not leave the GUI worker pinned or allocate executable user memory.
 */
static int DoGdtDump(HANDLE h, int asJson, int cpu)
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST req;
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* rsp = NULL;
    GROUP_AFFINITY group = { 0 };
    unsigned char data[4096] = { 0 };
    unsigned char covered[4096] = { 0 };
    const DWORD header = (DWORD)FIELD_OFFSET(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE, entries);
    const DWORD capacity = header + KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS *
        (DWORD)sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE);
    DWORD returned = 0, win32Error = 0;
    unsigned long long base = 0ULL;
    unsigned long limit = 0UL, want = 0UL, i;
    const char* failure = "GDT_INCOMPLETE";
    int result = 1;

    /* Preserve the existing CPU-within-current-group command meaning. */
    if (cpu < 0 || cpu >= (int)(sizeof(KAFFINITY) * 8U)) {
        fprintf(stderr, "GDT: CPU_OR_GROUP_INVALID (%lu)\n", (unsigned long)ERROR_INVALID_PARAMETER);
        return 1;
    }
    if (!GetThreadGroupAffinity(GetCurrentThread(), &group)) {
        fprintf(stderr, "GDT: CPU_OR_GROUP_INVALID (%lu)\n", GetLastError());
        return 1;
    }
    rsp = (KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*)calloc(1, capacity);
    if (rsp == NULL) {
        fprintf(stderr, "GDT: ALLOCATION_FAILED (%lu)\n", (unsigned long)ERROR_NOT_ENOUGH_MEMORY);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
    req.requestSize = (unsigned long)sizeof(req);
    req.flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU |
        KSWORD_ARK_DRIVER_INTEGRITY_FLAG_GDT_ENTRIES;
    req.maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY,
                         &req, (DWORD)sizeof(req), rsp, capacity, &returned, NULL)) {
        failure = "R0_QUERY_FAILED";
        win32Error = GetLastError();
        goto done;
    }
    /* Never parse another protocol layout or rows outside the returned buffer. */
    if (returned < header || returned > capacity ||
        rsp->version != KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION ||
        rsp->entrySize != sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE) ||
        rsp->returnedCount > (returned - header) / sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE)) {
        failure = "R0_RESPONSE_INVALID";
        goto done;
    }
    /* Broader integrity rows may be partial; require complete selected-table data. */
    for (i = 0UL; i < rsp->returnedCount; ++i) {
        const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = &rsp->entries[i];
        unsigned long offset, bytes, j;
        if (row->evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR ||
            row->processorGroup != group.Group || row->processorNumber != (unsigned long)cpu) {
            continue;
        }
        if ((row->fieldMask & KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DESCRIPTOR) == 0UL ||
            (row->descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_READ_FAILED) != 0UL ||
            row->descriptorTableBase == 0ULL || row->descriptorTableLimit >= sizeof(data)) {
            goto done;
        }
        if (want == 0UL) {
            base = row->descriptorTableBase;
            limit = row->descriptorTableLimit;
            want = limit + 1UL;
        }
        offset = row->descriptorSelector;
        bytes = row->descriptorSize;
        if (row->descriptorTableBase != base || row->descriptorTableLimit != limit ||
            (bytes != 8UL && bytes != 16UL) || offset > want || bytes > want - offset ||
            row->objectAddress != base + offset) {
            goto done;
        }
        /* Reject overlapping or missing slots instead of inventing zero bytes. */
        for (j = 0UL; j < bytes; ++j) {
            if (covered[offset + j] != 0U) { goto done; }
            covered[offset + j] = 1U;
        }
        memcpy(data + offset, &row->descriptorRawLow, 8U);
        if (bytes == 16UL) { memcpy(data + offset + 8UL, &row->descriptorRawHigh, 8U); }
    }
    if (want == 0UL) { goto done; }
    for (i = 0UL; i < want; ++i) {
        if (covered[i] == 0U) { goto done; }
    }
    if (asJson) {
        printf("{\"kind\":\"gdt-dump\",\"cpu\":%d,\"base\":\"0x%016llX\","
               "\"limit\":\"0x%04lX\",\"bytes\":%lu,\"processorGroup\":%u,\"source\":\"R0\",\"data\":\"",
               cpu, base, limit, want, (unsigned)group.Group);
        for (i = 0UL; i < want; ++i) { printf("%02X", data[i]); }
        printf("\"}\n");
    } else {
        printf("=== GDT（CPU %d）===\n", cpu);
        printf("  base=0x%016llX  limit=0x%04X  读回 %lu 字节\n",
               base, (unsigned)limit, want);
        for (i = 0UL; i + 8UL <= want; i += 8UL) {
            printf("  [%02lX] %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   i, data[i], data[i+1], data[i+2], data[i+3],
                   data[i+4], data[i+5], data[i+6], data[i+7]);
        }
    }
    result = 0;
done:
    if (result != 0) { fprintf(stderr, "GDT: %s (%lu)\n", failure, win32Error); }
    free(rsp);
    return result;
}

static int DoAclProbe(HANDLE rw, int asJson)
{
    static const struct { const char* name; DWORD code; } probes[] = {
        { "TERMINATE_PROCESS",    IOCTL_KSWORD_ARK_TERMINATE_PROCESS },
        { "SUSPEND_PROCESS",      IOCTL_KSWORD_ARK_SUSPEND_PROCESS },
        { "READ_PHYSICAL_MEMORY", IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY },
        { "READ_VIRTUAL_MEMORY",  IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY },
    };
    unsigned char scratch[512];
    HANDLE ro;
    size_t i;
    int failed = 0;

    ro = CreateFileW(KSW_DEVICE_PATH, GENERIC_READ,
                     FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ro == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "只读句柄都打不开：win32=%lu —— 这一项测不了\n",
                GetLastError());
        return 1;
    }
    if (!asJson) {
        printf("\n=== 访问位闸门（只读句柄 vs 读写句柄）===\n");
    }
    for (i = 0; i < sizeof(probes) / sizeof(probes[0]); ++i) {
        DWORD returned = 0;
        DWORD roErr, rwErr;

        memset(scratch, 0, sizeof(scratch));
        SetLastError(0);
        (void)DeviceIoControl(ro, probes[i].code, scratch, (DWORD)sizeof(scratch),
                              scratch, (DWORD)sizeof(scratch), &returned, NULL);
        roErr = GetLastError();
        memset(scratch, 0, sizeof(scratch));
        SetLastError(0);
        (void)DeviceIoControl(rw, probes[i].code, scratch, (DWORD)sizeof(scratch),
                              scratch, (DWORD)sizeof(scratch), &returned, NULL);
        rwErr = GetLastError();
        /*
         * 只读必须是 5（拒绝访问）；读写必须**不是** 5。
         *
         * 读写那一侧返回什么语义错误都算通过 —— 我们喂的是一片零，驱动多半会
         * 判无效参数，那恰恰说明请求到达了驱动。
         */
        {
            const int pass = (roErr == ERROR_ACCESS_DENIED) &&
                             (rwErr != ERROR_ACCESS_DENIED);
            if (!pass) { failed = 1; }
            if (asJson) {
                printf("%s{\"kind\":\"acl-probe\",\"ioctl\":\"%s\","
                       "\"readOnlyWin32\":%lu,\"readWriteWin32\":%lu,"
                       "\"pass\":%d}\n",
                       "", probes[i].name, roErr, rwErr, pass);
            } else {
                printf("  %-22s 只读 win32=%-5lu  读写 win32=%-5lu  => %s\n",
                       probes[i].name, roErr, rwErr,
                       pass ? "**PASS**" : "FAIL");
            }
        }
    }
    CloseHandle(ro);
    if (!asJson) {
        printf("\n  判据：只读句柄必须 win32=5（被 I/O 管理器挡在驱动之外），\n"
               "        且同一条在读写句柄上**不是** 5 —— 后者排除\"控制码对不上\"\n"
               "        这个与权限无关却长得一样的原因。\n");
    }
    return failed ? 2 : 0;
}

/* 判定一行是否达到正向判据。 */
static int NestedProbeRowPassed(const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r)
{
    return (r->status == KSWORD_ARK_HVM_NESTED_PROBE_STATUS_OK &&
            r->vmxonResult == 0UL && r->vmptrldResult == 0UL &&
            r->vmwriteResult == 0UL && r->vmreadResult == 0UL &&
            r->vmreadMatched == 1UL && r->vmptrstMatched == 1UL &&
            r->l2Reached == 1UL &&
            /*
             * 终止退出是第二条 RDMSR，不再是 CPUID。
             *
             * L2 的程序是两条 RDMSR：第一条 L1 的位图里是清的、必须放行，
             * 第二条是置的、必须退出。两条都产生"某个退出"，只有**停在哪里**
             * 能区分处理器查的是 L1 那张位图还是"全部拦截"的回退页。所以判据
             * 是原因与偏移一起，缺一格就退化成"反射链路通了"而已。
             */
            (r->l2ExitReason & 0xFFFFULL) == 31ULL &&
            r->l2RipOffset ==
                KSWORD_ARK_HVM_NESTED_PROBE_RIP_TRAPPED_MSR &&
            /*
             * 两份 vmcs12 各自的字段都得活过切换。
             *
             * 这一格此前不在判据里，因为当时它必然失败。现在它是门：任何把
             * vmcs12 退回"只建模一份"的改动，都会在这里立刻变红，而不是等到
             * 有人拿真 hypervisor 去试才发现。
             */
            r->vmcsSwitchMatched == 1UL &&
            /*
             * Cache eviction must preserve every region in its backing page.
             * The probe writes distinct values to more regions than the pool
             * holds and reloads all of them. Losing even an evicted region is
             * a failure; the eviction count proves the cache overflow ran.
             */
            r->vmcs12DepthRegions > 2UL &&
            r->vmcs12DepthRegions <= 64UL &&
            r->vmcs12DepthSurvived == r->vmcs12DepthRegions &&
            r->vmcs12DepthMask ==
                (~0ULL >> (64UL - r->vmcs12DepthRegions)) &&
            r->vmcs12EvictionDelta >= 1UL &&
            /*
             * 我们宣告的能力必须等于我们实现了的能力。
             *
             * 这三位是"L1 最可能去开、而我们最没实现"的：VPID、VMFUNC、
             * VMCS shadowing，它们各自的 vmcs02 字段我们一个都不拷。不过滤的话
             * L1 读到宿主真值就会去开，然后我们静默地不兑现 —— 整条路上没有
             * 任何一处报错，这正是 MSR 位图那个缺陷的同一族。
             *
             * 读数取自来宾上下文的 RDMSR，所以这一格同时也验了两件事：位图里
             * 那几位真的设上了，退出真的走到了过滤函数。少了任何一件，这里读到
             * 的就是宿主真值，VPID 位会亮着。
             *
             * 非零要求单列：全零意味着这一格根本没填（旧驱动、或者读发生在常驻
             * 起来之前），而"全零"恰好也能让下面三个判断成立 —— 一个没跑过的
             * 检查不能看起来像通过了。
             */
            /*
             * L1 写进 vmcs12 的字段必须真的到 vmcs02 里。
             *
             * TSC 偏移比的是一个具体常量，不是"非零"：非零只能说明有人写过，
             * 而这里要问的是**写进去的是不是 L1 那个值**。
             *
             * MSR 载入表更进一步 —— 这一行能 PASS 就意味着 vmlaunch 成功且
             * l2Reached 为真（上面已经要求），而表是真表、计数为 1，所以处理器
             * 确实走了 L1 那张表，不只是我们把字段填上了。
             */
            r->vmcs02TscOffset ==
                KSWORD_ARK_HVM_NESTED_PROBE_TSC_OFFSET &&
            r->vmcs02EntryMsrLoadAddress != 0ULL &&
            r->vmcs02EntryMsrLoadCount == 1UL &&
            r->vmcs02ExitMsrStoreAddress != 0ULL &&
            r->guestVmxEptVpidCap != 0ULL &&
            (r->guestVmxEptVpidCap &
                ~KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED) == 0ULL &&
            ((r->guestVmxProcbased2 >> 32) &
                ((1ULL << 5) | (1ULL << 13) | (1ULL << 14))) == 0ULL &&
            r->l1UsesMsrBitmap == 1UL &&
            r->bitmapMergeComplete == 1UL &&
            /* 那一条 RDMSR 是投递给 L1 的，不是我们就地吃掉的。 */
            r->l2MsrExitsReflected >= 1ULL &&
            /* 位图地址必须真的写进了 vmcs02。 */
            r->vmcs02MsrBitmap != 0ULL &&
            r->inveptResult == 0UL &&
            r->shadowGenerationAdvanced == 1UL &&
            r->hostStateChecks == 0x3FUL) ? 1 : 0;
}

static void PrintNestedProbeRow(const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r)
{
    printf("  L1 host 状态与内存操作数实测：0x%02lX（完整通过 = 0x3F）\n", r->hostStateChecks);
    printf("  --- CPU %lu ---   status %lu (%s)\n",
           r->processorIndex, r->status,
           NestedProbeStatusName(r->status));
    printf("    VMXON %s  VMPTRLD %s  VMWRITE %s  VMREAD %s  VMPTRST %s  VMXOFF %s\n",
           NestedProbeStepName(r->vmxonResult),
           NestedProbeStepName(r->vmptrldResult),
           NestedProbeStepName(r->vmwriteResult),
           NestedProbeStepName(r->vmreadResult),
           NestedProbeStepName(r->vmptrstResult),
           NestedProbeStepName(r->vmxoffResult));
    printf("    读回 0x%016llX %s   指针 %s\n",
           r->vmreadValue,
           r->vmreadMatched ? "**逐位相同**" : "不相同",
           r->vmptrstMatched ? "**相符**" : "不符");
    printf("    EPT12 %s   影子叶 %lu 张  拒绝 %lu  耗尽 %lu\n",
           r->ept12Armed ? "**已装**" : "未装",
           r->shadowFillCount, r->shadowDenyCount,
           r->shadowExhaustionCount);
    printf("    VMLAUNCH %s   L2 跑过 %s   退出原因 0x%llX%s   停在 0x%llX\n",
           NestedProbeStepName(r->vmlaunchResult),
           r->l2Reached ? "**是**" : "否",
           r->l2ExitReason,
           ((r->l2ExitReason & 0x80000000ULL) != 0ULL)
               ? "(entry 失败)"
               : (((r->l2ExitReason & 0xFFFFULL) == 10ULL) ? "(CPUID)" : ""),
           r->l2GuestRip);
    printf("    INVEPT %s   影子代次 %s\n",
           NestedProbeStepName(r->inveptResult),
           r->shadowGenerationAdvanced ? "**真的前进了**" : "没变");
    /*
     * vmcs02 进入那一刻的控制位与位图地址。
     *
     * 控制位是 L1 的与我们的并集，所以 USE_MSR_BITMAPS（bit 28）恒定活着；
     * 配套地址为 0 就意味着处理器拿物理页 0 当位图用。两格分开看都正常，
     * 只有摆在一起才看得出 L2 的 MSR/IO 拦截归谁管。
     */
    printf("    vmcs02 控制  primary=0x%08lX%s  secondary=0x%08lX\n",
           r->vmcs02PrimaryControls,
           ((r->vmcs02PrimaryControls & (1UL << 28)) != 0UL)
               ? " [USE_MSR_BITMAPS]"
               : "",
           r->vmcs02SecondaryControls);
    printf("    vmcs02 位图  msr=0x%016llX%s  io_a=0x%016llX  io_b=0x%016llX\n",
           r->vmcs02MsrBitmap,
           (((r->vmcs02PrimaryControls & (1UL << 28)) != 0UL) &&
            r->vmcs02MsrBitmap == 0ULL)
               ? "  **位开着而地址为 0：处理器会读物理页 0**"
               : "",
           r->vmcs02IoBitmapA,
           r->vmcs02IoBitmapB);
    /*
     * L1 写了、我们此前从不拷的那几个字段。
     *
     * MSR 区比位图更隐蔽：它的计数字段无条件生效，没有任何能力位可以用来表示
     * "我不支持"。所以不拷就是 L1 让装的那批 MSR 根本没装，而 L2 拿着我们的值
     * 在跑，两边都不会有任何报错。
     */
    printf("    vmcs02 透传  tsc_offset=0x%016llX%s  "
           "entry_msr=0x%016llX x%lu  exit_msr=0x%016llX x%lu\n",
           r->vmcs02TscOffset,
           (r->vmcs02TscOffset == KSWORD_ARK_HVM_NESTED_PROBE_TSC_OFFSET)
               ? " **L1 的值到位了**"
               : ((r->vmcs02TscOffset == 0ULL)
                      ? " **是 0 —— 字段没写过**"
                      : " **不是 L1 写的值**"),
           r->vmcs02EntryMsrLoadAddress, r->vmcs02EntryMsrLoadCount,
           r->vmcs02ExitMsrStoreAddress, r->vmcs02ExitMsrStoreCount);
    /*
     * MSR 路由的判据行。停在哪里就是答案，三种结局各有确定的偏移。
     */
    /*
     * 两份 vmcs12 的切换。单份 VMCS 问不出这件事，而真 hypervisor 一定会切。
     */
    printf("    vmcs12 切换  %s   A 读回 0x%016llX   B 读回 0x%016llX\n",
           (r->vmcsSwitchResult == KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED)
               ? "**没执行到**"
               : (r->vmcsSwitchMatched
                      ? "**两份各自的字段都还在**"
                      : "**字段丢了 —— 只建模了一份 vmcs12**"),
           r->vmcsSwitchValueA, r->vmcsSwitchValueB);
    /* Cache overflow must keep every VMCS recoverable from its region. */
    if (r->vmcs12DepthRegions != 0UL) {
        unsigned long slot = 0UL;

        printf("    vmcs12 深度  测 %lu 份，活下来 %lu 份   驱逐 %lu 次%s\n",
               r->vmcs12DepthRegions, r->vmcs12DepthSurvived,
               r->vmcs12EvictionDelta,
               (r->vmcs12EvictionDelta == 0UL)
                   ? "  **一次都没驱逐 —— 计数器没动，或者池子根本没满**"
                   : "");
        printf("                 存活位图 ");
        /* 最旧的在左边，最新的在右边，跟写入顺序一致。 */
        for (slot = 0UL; slot < r->vmcs12DepthRegions; ++slot) {
            printf("%c", ((r->vmcs12DepthMask >> slot) & 1ULL) ? '#' : '.');
        }
        printf("   （左=最先写，右=最后写；'.' 是丢失的字段，全部应为 '#'）\n");
    }
    /*
     * 来宾读到的 VMX 能力 —— 能力过滤唯一能被证伪的地方。
     *
     * 列出来的三位是"L1 最可能去开、而我们最没实现"的：VPID 要 VPID 字段与
     * INVVPID、VMFUNC 要 0x2018、VMCS shadowing 要 0x2026/0x2028，三者的字段
     * 我们一个都不往 vmcs02 里拷。它们还亮着，就说明过滤没生效。
     */
    if (r->guestVmxProcbased2 != 0ULL || r->guestVmxEptVpidCap != 0ULL) {
        const unsigned long long secondary = r->guestVmxProcbased2 >> 32;
        const unsigned long long vpidBits =
            r->guestVmxEptVpidCap &
            ((1ULL << 32) | (0xFULL << 40));

        printf("    来宾看到的   secondary 可置位=0x%08llX  "
               "ept_vpid=0x%016llX\n",
               secondary, r->guestVmxEptVpidCap);
        printf("                 VPID %s   VMFUNC %s   VMCS影子 %s   "
               "INVVPID %s\n",
               ((secondary >> 5) & 1ULL) ? "**还宣告着**" : "已收",
               ((secondary >> 13) & 1ULL) ? "**还宣告着**" : "已收",
               ((secondary >> 14) & 1ULL) ? "**还宣告着**" : "已收",
               (vpidBits & (1ULL << 43)) != 0ULL
                   ? "**错误宣告类型 3**" : "类型 0/1/2 按能力保留");
    }
    printf("    MSR 路由     L1 用位图 %s   合并 %s   L2 停在 +%llu %s\n",
           r->l1UsesMsrBitmap ? "是" : "否",
           r->bitmapMergeComplete ? "完整" : "**不完整（回退成全部拦截）**",
           r->l2RipOffset,
           (r->l2RipOffset == KSWORD_ARK_HVM_NESTED_PROBE_RIP_TRAPPED_MSR)
               ? "**第二条 RDMSR —— 查的确实是 L1 那张位图**"
               : ((r->l2RipOffset == KSWORD_ARK_HVM_NESTED_PROBE_RIP_OPEN_MSR)
                      ? "**第一条 RDMSR —— 本该放行却拦了，查的不是 L1 的页**"
                      : ((r->l2RipOffset ==
                              KSWORD_ARK_HVM_NESTED_PROBE_RIP_CPUID)
                             ? "**走到了 CPUID —— MSR 拦截根本没发生**"
                             : "（预期之外的位置）")));
    printf("    MSR/IO 归属  MSR 投递 %llu / 就地 %llu   IO 投递 %llu / 就地 %llu\n",
           r->l2MsrExitsReflected, r->l2MsrExitsHandled,
           r->l2IoExitsReflected, r->l2IoExitsHandled);
    /*
     * 合并代价只以份额报，不报孤立的周期数。
     *
     * 单看"合并花了 N 个周期"决定不了要不要加缓存 —— 那要看它在一次 L2 进入里
     * 占多大。份额很小就说明缓存省不下什么，再快也是白做。
     */
    if (r->l2EntryCount != 0ULL && r->l2EntryCycles != 0ULL) {
        printf("    合并代价     %llu / %llu 周期 = **%.1f%%** 的 L2 进入成本"
               "（%llu 次进入，均摊 %llu 周期/次）\n",
               r->l2MergeCycles, r->l2EntryCycles,
               (double)r->l2MergeCycles * 100.0 / (double)r->l2EntryCycles,
               r->l2EntryCount,
               r->l2MergeCycles / r->l2EntryCount);
    }
    printf("    派发 %llu 条   嵌套状态 %lu   末次错误号 %lu   => %s\n",
           r->dispatchedInstructions, r->nestedStateAfter,
           r->lastInstructionError,
           NestedProbeRowPassed(r) ? "**PASS**" : "FAIL");
}

/*
 * 装一条「拦截该 MSR 的读，然后原生执行」策略。
 *
 * 存在的理由只有一个：嵌套路由里「这次退出是我们的、还得有人服务它」那条分支
 * 没有别的办法触发。L1 的位图由探针自己造，我们这一侧的位图默认全零——两边都
 * 不拦，合并出来的位就是清的，那条分支一次都跑不到。而它恰恰是出错时**静默
 * 挂死**的那一条：没人模拟指令，RIP 不前进，L2 原地重执行到天荒地老。
 *
 * LOG 动作的语义正好是「记一笔再原生执行」，与就地服务要做的事一致。
 * 策略要改共享位图，所以驱动只在常驻停着时接受——必须在 resident 之前装。
 */
static int DoMsrPolicy(HANDLE h, unsigned long operation,
                       unsigned long msrIndex, int asJson)
{
    KSWORD_ARK_HVM_MSR_POLICY_REQUEST req;
    KSWORD_ARK_HVM_MSR_POLICY_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;

    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.operation = operation;
    req.flags = KSWORD_ARK_HVM_MSR_POLICY_FLAG_UI_CONFIRMED;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    req.msrIndex = msrIndex;
    req.access = KSWORD_ARK_HVM_MSR_ACCESS_READ;
    req.action = KSWORD_ARK_HVM_MSR_ACTION_LOG;
    memset(&rsp, 0, sizeof(rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MSR_POLICY,
                         &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp)) {
        fprintf(stderr,
                "MSR_POLICY IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
                (int)ok, returned, GetLastError());
        return 1;
    }
    if (asJson) {
        printf("{\"kind\":\"msr-policy\",\"op\":%lu,\"msr\":\"0x%lX\","
               "\"status\":%lu,\"policyId\":%lu,\"count\":%lu}\n",
               operation, msrIndex, rsp.status, rsp.policyId,
               rsp.policyCount);
    } else {
        printf("=== MSR 策略 ===\n");
        printf("  操作     : %lu   MSR 0x%lX   访问=读   动作=LOG（记一笔再原生执行）\n",
               operation, msrIndex);
        printf("  status   : %lu%s\n", rsp.status,
               (rsp.status == 8UL)
                   ? "  **RESIDENT_BUSY：策略要改共享位图，先停常驻**"
                   : "");
        printf("  策略 id  : %lu   当前条数 %lu\n",
               rsp.policyId, rsp.policyCount);
    }
    return (rsp.status == KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK) ? 0 : 2;
}

/*
 * L1 在 EPT12 指针里请求 accessed/dirty：现在应当**被接受并真的传播**。
 *
 * 这条用例原先验的是"必须被拒"。拒绝是当时唯一诚实的选择——放行而不传播，
 * 硬件会把位置在我们的影子叶上，L1 读回自己的 EPT12 全是零，据此跳过它的来宾
 * 真正改过的页，沿途没有任何读数会变。现在传播实现了，判据跟着反过来。
 *
 * 期望：L2 真的跑起来（VMLAUNCH 成功、l2Reached），且驱动报 A/D 处于**在维护**
 * 状态。只看"跑起来了"不够 —— 不维护也一样跑得起来，区别全在那一格。
 */
/*
 * 自虚拟化：让 L1 把**它自己正在跑的那个上下文**变成来宾。
 *
 * 这是"托住一个 hypervisor"与"托住一段测试程序"之间的分界线。之前那个 L2 跑在
 * 一页合成代码上、用合成的 RIP 与栈，段/CR3/页表都不必当真；而我们自己的常驻
 * 路径、以及 VMware 的 VMM，做的都是同一件事 —— 捕获当前状态、把 guest RIP
 * 指回自己下一条指令、VMLAUNCH，于是自己成了自己的来宾。
 *
 * 判据要三格齐全：进得去（reachedL2）、L2 里的退出被**投递给 L1**（exitReason
 * 是 10，从 vmcs12 读出来的）、以及 L1 拿回控制权并收尾（returnedToL1）。
 * 只看第一格是不够的：进得去出不来，对一个真 hypervisor 来说跟进不去一样是死的。
 */
/* 判定一行自虚拟化结果。多核模式下每一行都要过。 */
static int SelfVirtRowPassed(const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r)
{
    return (r->selfVirtAttempted == 1UL &&
            r->selfVirtReachedL2 == 1UL &&
            r->selfVirtSlotMarker == 1UL &&
            r->selfVirtReturnedToL1 == 1UL &&
            r->hostStateChecks == 0x7FUL &&
            r->selfVirtCpuidPassedThrough == 0UL &&
            (r->selfVirtExitReason & 0xFFFFULL) == 10ULL &&
            /*
             * 往返不止一次，而且 L1 armed 的退出全部到达。
             *
             * 一次进入一次退出不是 hypervisor —— 回程走 VMRESUME，是另一条指令、
             * 另一套 launch-state 检查，首次进入通过推不出它通过。
             *
             * 判的是**每一条 CPUID 都到了 L1**（投递数 = 往返数），不是"全部退出
             * 都到 L1"。后者我先写错过：实测 29 条退出只投递了 9 条，差出来的 20
             * 条是影子 EPT 填叶 —— L1 的 EPT12 授权了那些访问，合成叶子本来就该
             * 是我们的活，L1 从没要求看见。要求它们也投递，等于让每一次**正确**
             * 的运行都判 FAIL。
             */
            r->selfVirtResumeCount >= 1UL &&
            r->selfVirtEntryCount == r->selfVirtResumeCount + 1UL &&
            r->selfVirtReflectCount ==
                r->selfVirtResumeCount + 1UL) ? 1 : 0;
}

static int DoNestedSelfVirtualize(HANDLE h, int asJson, int allProcessors)
{
    KSWORD_ARK_HVM_NESTED_PROBE_REQUEST req;
    KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;
    const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r;
    int passed;

    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_HVM_NESTED_PROBE_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                KSWORD_ARK_HVM_NESTED_PROBE_FLAG_SELF_VIRTUALIZE;
    if (allProcessors) {
        req.flags |= KSWORD_ARK_HVM_NESTED_PROBE_FLAG_ALL_PROCESSORS;
    }
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    memset(&rsp, 0, sizeof(rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_NESTED_PROBE,
                         &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp) || rsp.returnedRows == 0UL) {
        fprintf(stderr,
                "NESTED_PROBE(self) 无完整响应：ok=%d returned=%lu win32=%lu\n",
                (int)ok, returned, GetLastError());
        return 1;
    }
    r = &rsp.rows[0];
    /* 前置没建立就不算测到，跟 A/D 那条同一个道理。 */
    if (r->vmxonResult != 0UL || r->vmptrldResult != 0UL) {
        if (!asJson) {
            printf("=== 嵌套自虚拟化 ===\n");
            printf("  **空过**：VMXON/VMPTRLD 没成功，这一轮没走到进入那道门。\n");
        }
        return 3;
    }
    /*
     * 五格，缺一不可。
     *
     * slotMarker 单列而不是并进 reachedL2：前者问的是 L2 继承的 GS 基址对不对
     * （找槽位要走 GS），后者问的是 L2 的存储到不到内存（RIP 相对寻址）。两种
     * 失败原因完全不同，合成一格就会塌成同一个 0。
     */
    passed = SelfVirtRowPassed(r);
    /*
     * 多核模式下逐行判，**任一行 FAIL 即整体 FAIL**。
     *
     * 每个处理器有自己的 vmcs02、自己的影子层次、自己的映射窗口，结构上互不干涉 ——
     * 而这个仓库里"单核跑通推不出多核跑通"已经栽过不止一次。
     */
    if (allProcessors) {
        unsigned long row = 0UL;

        for (row = 0UL; row < rsp.returnedRows &&
                        row < KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS; ++row) {
            if (!SelfVirtRowPassed(&rsp.rows[row])) { passed = 0; }
        }
        if (!asJson) {
            printf("\n=== 嵌套自虚拟化（多核，%lu 个处理器各起一个线程）===\n",
                   rsp.returnedRows);
            for (row = 0UL; row < rsp.returnedRows &&
                            row < KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS; ++row) {
                const KSWORD_ARK_HVM_NESTED_PROBE_ROW* q = &rsp.rows[row];

                printf("  CPU %lu: 进 L2 %s  写入 %s/%s  往返 %lu  "
                       "投递 %lu/%lu  原因 %llu  状态/SSE 0x%02lX  => %s\n",
                       q->processorIndex,
                       q->selfVirtReachedL2 ? "是" : "**否**",
                       q->selfVirtReachedL2 ? "到" : "**丢**",
                       q->selfVirtSlotMarker ? "到" : "**丢**",
                       q->selfVirtResumeCount,
                       q->selfVirtReflectCount, q->selfVirtTotalExitCount,
                       q->selfVirtExitReason & 0xFFFFULL,
                       q->hostStateChecks,
                       SelfVirtRowPassed(q) ? "**PASS**" : "FAIL");
            }
            printf("\n  判据：每一行都要过。每核有自己的 vmcs02、影子层次与映射窗口，\n"
                   "        结构上互不干涉 —— 单核跑通推不出多核跑通。\n");
            printf("  => %s\n", passed ? "**PASS**" : "FAIL");
            return passed ? 0 : 2;
        }
    }
    if (asJson) {
        printf("{\"kind\":\"nested-selfvirt\",\"attempted\":%lu,"
               "\"reachedL2\":%lu,\"returnedToL1\":%lu,"
               "\"cpuidPassedThrough\":%lu,\"slotMarker\":%lu,"
               "\"exitReason\":%llu,\"guestRip\":\"0x%016llX\","
               "\"entryRip\":\"0x%016llX\","
               "\"entryCount\":%lu,\"reflectCount\":%lu,"
               "\"totalExitCount\":%lu,\"resumeCount\":%lu,"
               "\"vmlaunch\":%lu,\"lastInstructionError\":%lu,"
               "\"fuseTripped\":%lu,\"fuseReason\":%lu,\"fuseCount\":%lu,"
               "\"fuseRip\":\"0x%016llX\","
               "\"hostStateChecks\":%lu,"
               "\"pass\":%d}\n",
               r->selfVirtAttempted, r->selfVirtReachedL2,
               r->selfVirtReturnedToL1, r->selfVirtCpuidPassedThrough,
               r->selfVirtSlotMarker,
               r->selfVirtExitReason & 0xFFFFULL, r->selfVirtGuestRip,
               r->selfVirtEntryRip,
               r->selfVirtEntryCount, r->selfVirtReflectCount,
               r->selfVirtTotalExitCount, r->selfVirtResumeCount,
               r->vmlaunchResult, r->lastInstructionError,
               r->l2FuseTripped, r->l2FuseReason, r->l2FuseCount,
               r->l2FuseRip, r->hostStateChecks, passed);
    } else {
        printf("\n=== 嵌套自虚拟化（L1 把自己变成来宾）===\n");
        printf("  L2 的写入   : 全局标记 %s   经槽位 %s\n",
               r->selfVirtReachedL2 ? "**到了**" : "**没到**",
               r->selfVirtSlotMarker ? "**到了**" : "**没到**");
        printf("  进入 L2     : %s%s\n",
               r->selfVirtReachedL2 ? "**是**" : "**否**",
               r->selfVirtReachedL2
                   ? "  —— 同一段代码，低一个特权域在跑"
                   : "  —— L2 的存储没有回到 L1 眼里（两者含义不同，见上一行）");
        if (!r->selfVirtReachedL2) {
            printf("  VMLAUNCH    : 结果 %lu   指令错误号 %lu\n",
                   r->vmlaunchResult, r->lastInstructionError);
            PrintVmInstructionError("  ", r->lastInstructionError);
        }
        /*
         * 入口与退出 RIP 的差值 —— 同一轮之内的比较，不受加载基址影响。
         */
        if (r->selfVirtEntryRip != 0ULL) {
            const long long delta =
                (long long)(r->selfVirtGuestRip - r->selfVirtEntryRip);

            /*
             * 两个 RIP 只并排报，不做差值判据。
             *
             * L2 现在从汇编 launcher 里那个 resume 桩开始，而退出发生在 C 里，
             * 两者本来就在不同函数，差值必然很大 —— 我拿差值做过判据，于是它对一次
             * **完全正确**的运行打出了"L2 没从我们指的地方开始"。一条只在某种代码
             * 布局下成立的判据，布局一变就变成假否定。
             *
             * "L2 有没有真的在跑"这个问题现在由 launcher 的返回值回答，不需要靠
             * 地址推断。
             */
            (void)delta;
            printf("  入口/退出   : 0x%016llX -> 0x%016llX"
                   "（resume 桩与退出点本就不同函数，不比差值）\n",
                   r->selfVirtEntryRip, r->selfVirtGuestRip);
        }
        /*
         * 退出原因在这里是一个**一位的答复**，不只是诊断。
         *
         * L2 没法用内存回话 —— "L2 的写 L1 看不看得见"正是被问的那件事，所以任何
         * 写在内存里的答复，恰好在它有意义的时候不可读。退出原因这条路两个方向都
         * 验过是通的：CPUID 表示 L2 读回了自己写的值，VMCALL 表示读不回来。
         */
        printf("  L2 的退出   : 原因 %llu %s   停在 0x%016llX\n",
               r->selfVirtExitReason & 0xFFFFULL,
               ((r->selfVirtExitReason & 0xFFFFULL) == 10ULL)
                   ? "**CPUID —— L2 读回了自己写的值**"
                   : (((r->selfVirtExitReason & 0xFFFFULL) == 18ULL)
                          ? "**VMCALL —— L2 连自己刚写的值都读不回来**"
                          : "**既不是 CPUID 也不是 VMCALL —— 走到了别处**"),
               r->selfVirtGuestRip);
        printf("  回到 L1     : %s\n",
               r->selfVirtReturnedToL1
                   ? "**是** —— L1 的宿主处理器跑完并交还了上下文"
                   : "**否** —— 进去了没回来");
        /*
         * 进入次数 = 1 + resume 次数：首次 VMLAUNCH 加上每次 VMRESUME。
         *
         * 全部退出与被投递的退出必须相等 —— 差出来的那些是**我们替 L1 回答了它自己
         * 的来宾**，而 L1 永远不知道被问过。只看被投递的数，这个差永远不可见。
         */
        printf("  往返        : 进入 %lu 次（VMLAUNCH 1 + VMRESUME %lu）\n",
               r->selfVirtEntryCount, r->selfVirtResumeCount);
        printf("  退出归属    : 共 %lu 次   投递给 L1 %lu 次   我们自己处理 %lu 次\n",
               r->selfVirtTotalExitCount, r->selfVirtReflectCount,
               (r->selfVirtTotalExitCount >= r->selfVirtReflectCount)
                   ? (r->selfVirtTotalExitCount - r->selfVirtReflectCount)
                   : 0UL);
        printf("                 %s\n",
               (r->selfVirtReflectCount == r->selfVirtResumeCount + 1UL)
                   ? "每一条 CPUID 都到了 L1；自己处理的那些是影子 EPT 填叶，"
                     "本就该是我们的"
                   : "**L1 armed 的退出没有全部到达 —— 我们替它回答了它的来宾**");
        /*
         * 熔断的读数。这是挂死唯一会留下的东西 —— 没有它，同样的失败在来宾里
         * 读不到、在宿主日志里也读不到。
         */
        if (r->l2FuseTripped) {
            printf("  **熔断跳闸** : L2 在同一条指令上以同样的原因退出了 %lu 次\n",
                   r->l2FuseCount);
            printf("                 退出原因 %lu   停在 0x%016llX\n",
                   r->l2FuseReason, r->l2FuseRip);
            printf("                 —— 这就是之前那次挂死的样子，只是这回被拦住了\n");
        } else {
            printf("  熔断        : 未跳闸（L2 一直在往前走）\n");
        }
        if (r->selfVirtCpuidPassedThrough) {
            printf("  **CPUID 没有退出** —— 架构上不该发生，记下来而不是当它没发生\n");
        }
        printf("\n  判据：进得去、L2 的退出被投递给 L1（原因 10）、L1 拿回控制权，\n"
               "        三格缺一不可。进得去出不来，对一个真 hypervisor 来说\n"
               "        跟进不去一样是死的。\n");
        printf("  => %s\n", passed ? "**PASS**" : "FAIL");
    }
    return passed ? 0 : 2;
}

static int DoNestedProbeAdRefusal(HANDLE h, int asJson)
{
    KSWORD_ARK_HVM_NESTED_PROBE_REQUEST req;
    KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;
    const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r;
    int passed;

    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_HVM_NESTED_PROBE_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                KSWORD_ARK_HVM_NESTED_PROBE_FLAG_REQUEST_AD;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    memset(&rsp, 0, sizeof(rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_NESTED_PROBE,
                         &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp) || rsp.returnedRows == 0UL) {
        fprintf(stderr,
                "NESTED_PROBE(AD) 无完整响应：ok=%d returned=%lu win32=%lu\n",
                (int)ok, returned, GetLastError());
        return 1;
    }
    r = &rsp.rows[0];
    /*
     * 前置没建立就不算测到。VMXON 都没成功的话，这一轮根本没走到 A/D 那道门，
     * 报通过就是空过。
     */
    if (r->vmxonResult != 0UL || r->vmptrldResult != 0UL) {
        if (!asJson) {
            printf("=== 嵌套 A/D 拒绝（负向）===\n");
            printf("  **空过**：VMXON/VMPTRLD 没成功，这一轮没走到 A/D 那道门。\n");
        }
        return 3;
    }
    /*
     * 两格分开看，因为它们是两种编码。
     *
     * vmlaunchResult 是**步骤结果**（0 成功 / 1 VMfailValid / 2 VMfailInvalid），
     * lastInstructionError 才是 Intel 错误号。要的是「以 VMfailValid 的方式失败」
     * **并且**「错误号是 7（控制字段非法）」—— 只看前者的话，任何一种失败都能
     * 蒙混过去；只看后者的话，VMfailInvalid 根本不带错误号，读到的会是上一条
     * 指令留下的陈值。
     */
    /*
     * 三格缺一不可。
     *
     * l2Reached 只说明 L2 跑起来了 —— 不维护 A/D 也一样跑得起来。
     * l1RequestedAccessedDirty 只说明请求到达了驱动。
     * accessedDirtyActive 才是"我们真的在维护并会折回去"，也是这条用例
     * 唯一要问的东西。
     */
    passed = (r->l2Reached == 1UL &&
              r->l1RequestedAccessedDirty == 1UL &&
              r->accessedDirtyActive == 1UL) ? 1 : 0;
    if (asJson) {
        printf("{\"kind\":\"nested-ad\",\"l2Reached\":%lu,"
               "\"requested\":%lu,\"active\":%lu,\"propagated\":%lu,"
               "\"overflow\":%lu,\"pass\":%d}\n",
               r->l2Reached, r->l1RequestedAccessedDirty,
               r->accessedDirtyActive, r->adPropagatedCount,
               r->adOverflowCount, passed);
    } else {
        printf("=== 嵌套 accessed/dirty ===\n");
        printf("  L1 的 EPT12 指针带上了 accessed/dirty 位（EPTP bit 6）。\n");
        printf("  L2 跑过      : %s\n",
               r->l2Reached ? "是" : "**否 —— 带上 A/D 之后进不去了**");
        printf("  请求到达     : %s\n",
               r->l1RequestedAccessedDirty ? "是" : "**否**");
        printf("  正在维护     : %s\n",
               r->accessedDirtyActive
                   ? "是（EPTP bit 6 已置，退出时折回 EPT12）"
                   : "**否 —— 处理器不支持，或记录表溢出**");
        printf("  已折回条数   : %lu   溢出次数 : %lu%s\n",
               r->adPropagatedCount, r->adOverflowCount,
               (r->adOverflowCount != 0UL)
                   ? "  **溢出后已关闭维护：半套传播比没有更糟**"
                   : "");
        printf("  => %s\n", passed ? "**PASS**" : "FAIL");
        printf("\n  判据：三格缺一不可。「L2 跑过」不够 —— 不维护 A/D 也一样跑得\n"
               "        起来；「请求到达」也不够 —— 那只说明请求进了驱动。只有\n"
               "        「正在维护」为是，才意味着硬件在置位而我们会把它折回 L1\n"
               "        自己的表。折不回去时 L1 读回全零，会跳过来宾真正写过的页。\n");
    }
    return passed ? 0 : 2;
}

static int DoNestedProbe(HANDLE h, int asJson, int allProcessors)
{
    KSWORD_ARK_HVM_NESTED_PROBE_REQUEST req;
    KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;
    unsigned long i;
    int failed = 0;

    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_HVM_NESTED_PROBE_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;
    if (allProcessors) {
        req.flags |= KSWORD_ARK_HVM_NESTED_PROBE_FLAG_ALL_PROCESSORS;
    }
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    memset(&rsp, 0, sizeof(rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_NESTED_PROBE,
                         &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp)) {
        fprintf(stderr,
                "NESTED_PROBE IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
                (int)ok, returned, GetLastError());
        return 1;
    }
    if (asJson) {
        printf("{\"kind\":\"nested-probe\",\"status\":%lu,\"rows\":%lu,\"row\":[",
               rsp.status, rsp.returnedRows);
        for (i = 0; i < rsp.returnedRows &&
                    i < KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS; ++i) {
            const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r = &rsp.rows[i];
            printf("%s{\"cpu\":%lu,\"status\":%lu,\"vmxon\":%lu,"
                   "\"vmptrld\":%lu,\"vmwrite\":%lu,\"vmread\":%lu,"
                   "\"vmptrst\":%lu,\"vmxoff\":%lu,\"vmreadMatched\":%lu,"
                   "\"vmptrstMatched\":%lu,\"vmlaunch\":%lu,\"l2Reached\":%lu,"
                   "\"ept12Armed\":%lu,\"shadowFill\":%lu,\"shadowDeny\":%lu,"
                   "\"shadowExhaustion\":%lu,\"dispatched\":%llu,"
                   "\"l2ExitReason\":\"0x%llX\",\"l2GuestRip\":\"0x%llX\","
                   "\"lastInstructionError\":%lu,"
                   /*
                    * 判据依据的那几格必须跟着进记录。
                    *
                    * 少了它们，归档下来的就只是一个 pass=1 —— 而这一轮判 PASS
                    * 靠的是"L2 停在 +12"和"位图地址非零"。事后想复核一份旧记录
                    * 时，没有这些格子就只能重跑。
                    */
                   "\"l2RipOffset\":%llu,\"vmcs02MsrBitmap\":\"0x%llX\","
                   "\"vmcs02Primary\":\"0x%08lX\",\"mergeComplete\":%lu,"
                   "\"l1UsesMsrBitmap\":%lu,\"msrReflected\":%llu,"
                   "\"msrHandled\":%llu,\"ioReflected\":%llu,"
                   "\"ioHandled\":%llu,"
                   /* 同理：两份 vmcs12 的切换现在也是判据的一格。 */
                   "\"vmcsSwitchResult\":%lu,\"vmcsSwitchMatched\":%lu,"
                   "\"vmcsSwitchValueA\":\"0x%llX\","
                   "\"vmcsSwitchValueB\":\"0x%llX\","
                   "\"vmcs12DepthRegions\":%lu,"
                   "\"vmcs12DepthSurvived\":%lu,"
                   "\"vmcs12DepthMask\":\"0x%llX\","
                   "\"vmcs12EvictionDelta\":%lu,"
                   /* 能力过滤：来宾此刻读到的值，判据依赖它。 */
                   "\"guestVmxProcbased2\":\"0x%016llX\","
                   "\"guestVmxEptVpidCap\":\"0x%016llX\","
                   /* 新补的字段透传：判据依赖这几格。 */
                   "\"vmcs02TscOffset\":\"0x%016llX\","
                   "\"vmcs02EntryMsrLoadAddress\":\"0x%016llX\","
                   "\"vmcs02EntryMsrLoadCount\":%lu,"
                   "\"vmcs02ExitMsrStoreAddress\":\"0x%016llX\","
                   "\"vmcs02ExitMsrStoreCount\":%lu,"
                   "\"inveptResult\":%lu,\"shadowGenerationAdvanced\":%lu,"
                   "\"hostStateChecks\":%lu,"
                   "\"pass\":%d}",
                   (i == 0) ? "" : ",",
                   r->processorIndex, r->status, r->vmxonResult,
                   r->vmptrldResult, r->vmwriteResult, r->vmreadResult,
                   r->vmptrstResult, r->vmxoffResult, r->vmreadMatched,
                   r->vmptrstMatched, r->vmlaunchResult, r->l2Reached,
                   r->ept12Armed, r->shadowFillCount, r->shadowDenyCount,
                   r->shadowExhaustionCount, r->dispatchedInstructions,
                   r->l2ExitReason, r->l2GuestRip,
                   r->lastInstructionError,
                   r->l2RipOffset, r->vmcs02MsrBitmap,
                   r->vmcs02PrimaryControls, r->bitmapMergeComplete,
                   r->l1UsesMsrBitmap, r->l2MsrExitsReflected,
                   r->l2MsrExitsHandled, r->l2IoExitsReflected,
                   r->l2IoExitsHandled,
                   r->vmcsSwitchResult, r->vmcsSwitchMatched,
                   r->vmcsSwitchValueA, r->vmcsSwitchValueB,
                   r->vmcs12DepthRegions, r->vmcs12DepthSurvived,
                   r->vmcs12DepthMask, r->vmcs12EvictionDelta,
                   r->guestVmxProcbased2, r->guestVmxEptVpidCap,
                   r->vmcs02TscOffset,
                   r->vmcs02EntryMsrLoadAddress, r->vmcs02EntryMsrLoadCount,
                   r->vmcs02ExitMsrStoreAddress, r->vmcs02ExitMsrStoreCount,
                   r->inveptResult, r->shadowGenerationAdvanced, r->hostStateChecks,
                   NestedProbeRowPassed(r));
        }
        printf("]}\n");
    } else {
        printf("\n=== 嵌套 VMX 自检（客户机上下文里真的执行 VMX 指令）===\n");
        printf("  整体 status : %lu (%s)   跑了 %lu 个处理器\n",
               rsp.status, NestedProbeStatusName(rsp.status),
               rsp.returnedRows);
        for (i = 0; i < rsp.returnedRows &&
                    i < KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS; ++i) {
            PrintNestedProbeRow(&rsp.rows[i]);
        }
        printf("\n  判据：每一行都要 VMXON/VMPTRLD/VMWRITE/VMREAD/VMPTRST 全成功、\n"
               "        读回逐位相同、指针相符、「L2 跑过」为是，且终止退出是\n"
               "        **第二条 RDMSR（原因 31，停在 +12）并被投递给 L1**。\n"
               "        L2 先读一个 L1 位图里清着的 MSR（必须放行），再读一个置着的\n"
               "        （必须退出）；两种结局都产生退出，只有停在哪里能区分处理器\n"
               "        查的是 L1 那张位图还是\"全部拦截\"的回退页。停在 +5 就是回退，\n"
               "        走到 +14 就是 MSR 拦截根本没发生。\n"
               "        还要求**两份 vmcs12 交替之后各自的字段都还在**：写 A、写 B、\n"
               "        读 A、读 B，只建模一份的派发器会把 B 的值或零当成 A 的还回来。\n"
               "        真 hypervisor 每个 vCPU 至少一份 VMCS 且不停 VMPTRLD 切换，\n"
               "        字段活不过一次切换就托不住它们。\n"
               "        还要超出缓存容量并逐份读回：缓存挤出计数必须增长，所有区域的\n"
               "        独有字段都必须保留，存活掩码全部置位。区域页负责保存状态，\n"
               "        缓存被挤出不能让 VMCS 的字段丢失。\n"
               "        最后一格是**能力过滤**：来宾自己 RDMSR 读回来的能力里，VPID、\n"
               "        VMFUNC、VMCS shadowing 必须已经收掉 —— 这三样的 vmcs02 字段我们\n"
               "        一个都不拷，宣告了就是答应做不到的事，而 L1 照着开之后整条路\n"
               "        上不会有任何一处报错。对照 status 里的 EPT/VPID cap（那是驱动\n"
               "        加载时采的硬件真值），两个数不一样才说明过滤是活的。\n"
               "        INVVPID 指令的类型 0/1/2 按白名单保留，与 enable-VPID 控制位\n"
               "        分开判定；类型 3 和白名单以外的 EPT 能力不得宣告。\n"
               "        还要求 L1 写进 vmcs12 的 **TSC 偏移与 MSR 载入表真的到了\n"
               "        vmcs02**：偏移比的是具体常量而非非零，载入表是真表且计数为 1\n"
               "        ——这一行 PASS 就意味着 VM entry 带着这张表成功了，也就是处理器\n"
               "        确实走了 L1 那张表。MSR 区的计数字段无条件生效，没有任何能力位\n"
               "        能表示「我不支持」，所以不拷就是**静默地不装**。\n"
               "        多核模式下，**任何一行 FAIL 就是整体 FAIL** —— 这正是它要验的东西。\n");
    }
    for (i = 0; i < rsp.returnedRows &&
                i < KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS; ++i) {
        if (!NestedProbeRowPassed(&rsp.rows[i])) { failed = 1; }
    }
    return (rsp.returnedRows > 0 && !failed) ? 0 : 2;
}

static const char* ProcessStatusName(unsigned long s)
{
    switch (s) {
    case KSWORD_ARK_HVM_PROCESS_STATUS_OK:                    return "OK";
    case KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST:       return "INVALID_REQUEST";
    case KSWORD_ARK_HVM_PROCESS_STATUS_CONFIRMATION_REQUIRED: return "CONFIRMATION_REQUIRED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_NOT_PREPARED:          return "NOT_PREPARED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_REQUIRES_RESIDENT_STOPPED:
        return "REQUIRES_RESIDENT_STOPPED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_PROCESS_LOOKUP_FAILED: return "PROCESS_LOOKUP_FAILED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_TABLE_FULL:            return "TABLE_FULL";
    case KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND:             return "NOT_FOUND";
    case KSWORD_ARK_HVM_PROCESS_STATUS_ALREADY_ARMED:         return "ALREADY_ARMED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_CR3_TRACKING_REQUIRED: return "CR3_TRACKING_REQUIRED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED:  return "EPTP_SWITCH_REQUIRED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED:    return "TRANSLATION_FAILED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_PROTECTED_TARGET:      return "PROTECTED_TARGET";
    default:                                                  return "UNKNOWN";
    }
}

static const char* ProcessDispositionName(unsigned long d)
{
    switch (d) {
    case KSWORD_ARK_HVM_PROCESS_OP_FREEZE:    return "冻结";
    case KSWORD_ARK_HVM_PROCESS_OP_TERMINATE: return "结束";
    /* 已解除、层次尚未回收：常驻停下来时才真正清掉。 */
    case KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED: return "已解除";
    default:                                  return "?";
    }
}

static int ProcessIoctl(HANDLE h,
                        KSWORD_ARK_HVM_PROCESS_REQUEST* req,
                        KSWORD_ARK_HVM_PROCESS_RESPONSE* rsp)
{
    DWORD returned = 0;
    BOOL ok;

    req->version = KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION;
    req->size = (unsigned long)sizeof(*req);
    memset(rsp, 0, sizeof(*rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_PROCESS, req, (DWORD)sizeof(*req),
                         rsp, (DWORD)sizeof(*rsp), &returned, NULL);
    if (returned >= sizeof(*rsp)) {
        /* 响应完整就用响应，无论 ok 是真是假。 */
        return 0;
    }
    fprintf(stderr, "PROCESS IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
            (int)ok, returned, GetLastError());
    return 1;
}

/* ——— 内存监视（首次访问归因） ——— */

static const char* WatchStateName(unsigned long state)
{
    switch (state) {
    case KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED: return "armed";
    case KSWORD_ARK_HVM_EPT_WATCH_STATE_TRIGGERED: return "triggered";
    case KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED: return "disarmed";
    case KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED: return "invalidated";
    case KSWORD_ARK_HVM_EPT_WATCH_STATE_FAULTED: return "faulted";
    default: break;
    }
    return "none";
}

static const char* WatchHitStatusName(unsigned long status)
{
    switch (status) {
    case KSWORD_ARK_HVM_EPT_WATCH_HIT_PUBLISHED: return "published";
    /*
     * "命中了但事件丢了" 与 "从未命中" 在事件列表里长得一模一样，而结论正好
     * 相反。自动化判据要能分开这两种，所以它是一个独立的名字而不是空值。
     */
    case KSWORD_ARK_HVM_EPT_WATCH_HIT_EVENT_LOST: return "event-lost";
    default: break;
    }
    return "none";
}

static const char* WatchRuleStatusName(unsigned long status)
{
    switch (status) {
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_OK: return "ok";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST: return "invalid-request";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_CONFIRMATION_REQUIRED: return "confirmation-required";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_PREPARED: return "not-prepared";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND: return "not-found";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_TABLE_FULL: return "table-full";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_SPLIT_FAILED: return "split-failed";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL: return "partial";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_UNIMPLEMENTED: return "unimplemented";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_MULTIPROCESSOR_UNSAFE: return "multiprocessor-unsafe";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT: return "leaf-conflict";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN: return "resident-frozen";
    default: break;
    }
    return "unknown";
}

static const char* WatchConflictName(unsigned long kind)
{
    switch (kind) {
    case KSWORD_ARK_HVM_WATCH_CONFLICT_VIEW: return "view";
    case KSWORD_ARK_HVM_WATCH_CONFLICT_RULE: return "rule";
    case KSWORD_ARK_HVM_WATCH_CONFLICT_WATCH: return "watch";
    default: break;
    }
    return "none";
}

/* 把访问掩码写成 rwx 形式，未置位处写 '-'。 */
static void WatchAccessText(unsigned long access, char out[4])
{
    out[0] = (access & KSWORD_ARK_HVM_EPT_ACCESS_READ) ? 'r' : '-';
    out[1] = (access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) ? 'w' : '-';
    out[2] = (access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) ? 'x' : '-';
    out[3] = '\0';
}

static void PrintWatchRow(const KSWORD_ARK_HVM_EPT_WATCH_ROW* row, int asJson)
{
    char requested[4];
    char effective[4];

    WatchAccessText(row->requestedAccess, requested);
    WatchAccessText(row->effectiveAccess, effective);
    if (asJson) {
        printf("{\"watchId\":%lu,\"state\":\"%s\",\"addressKind\":\"%s\","
               "\"requestedAddress\":\"0x%016llX\",\"requestedLength\":%llu,"
               "\"physicalPage\":\"0x%016llX\",\"effectiveBytes\":4096,"
               "\"requestedAccess\":\"%s\",\"effectiveAccess\":\"%s\","
               "\"hitCount\":%lu,\"lastHitSequence\":%llu,"
               "\"lastHitStatus\":\"%s\",\"armedGeneration\":%lu,"
               "\"lastHitRip\":\"0x%016llX\",\"lastHitRsp\":\"0x%016llX\","
               "\"lastHitCr3\":\"0x%016llX\",\"lastHitGpa\":\"0x%016llX\","
               "\"lastHitGla\":\"0x%016llX\",\"lastHitGlaValid\":%s,"
               "\"lastHitRangeMatch\":%s,\"lastHitCpu\":\"%u:%u\"}",
               row->watchId, WatchStateName(row->state),
               row->addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL
                   ? "virtual" : "physical",
               row->requestedAddress, row->requestedLength,
               row->physicalPage, requested, effective,
               row->hitCount, row->lastHitSequence,
               WatchHitStatusName(row->lastHitStatus), row->armedGeneration,
               row->lastHitRip, row->lastHitRsp, row->lastHitCr3,
               row->lastHitGuestPhysicalAddress, row->lastHitGuestLinearAddress,
               row->lastHitGuestLinearValid ? "true" : "false",
               row->lastHitRangeMatch ? "true" : "false",
               (unsigned)row->lastHitProcessorGroup,
               (unsigned)row->lastHitProcessorNumber);
        return;
    }
    printf("  #%-4lu %-11s  %s 0x%016llX (%llu B)  页=0x%016llX(4096 B)"
           "  请求=%s 实际=%s  命中=%lu(%s)\n",
           row->watchId, WatchStateName(row->state),
           row->addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL
               ? "VA" : "PA",
           row->requestedAddress, row->requestedLength, row->physicalPage,
           requested, effective, row->hitCount,
           WatchHitStatusName(row->lastHitStatus));
    if (row->hitCount != 0UL) {
        printf("        rip=0x%016llX rsp=0x%016llX cr3=0x%016llX cpu=%u:%u seq=%llu\n",
               row->lastHitRip, row->lastHitRsp, row->lastHitCr3,
               (unsigned)row->lastHitProcessorGroup,
               (unsigned)row->lastHitProcessorNumber,
               row->lastHitSequence);
        printf("        gpa=0x%016llX gla=0x%016llX(%s) 落在请求范围内=%s\n",
               row->lastHitGuestPhysicalAddress,
               row->lastHitGuestLinearAddress,
               row->lastHitGuestLinearValid ? "有效" : "处理器未报告",
               row->lastHitGuestLinearValid
                   ? (row->lastHitRangeMatch ? "是" : "否")
                   : "无法判断");
    }
}

/* 下发一次 watch 操作并把结果打印出来。 */
static int DoWatch(HANDLE h, unsigned long op, unsigned long watchId,
                   unsigned long long physicalPage,
                   unsigned long long requestedAddress,
                   unsigned long long requestedLength,
                   unsigned long access, unsigned long addressKind, int asJson)
{
    KSWORD_ARK_HVM_EPT_RULE_REQUEST req;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    DWORD returned = 0;
    unsigned long i = 0UL;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.operation = op;
    /*
     * 每种操作**只**填它自己那几个字段，其余一律留零。
     *
     * 驱动侧对 REMOVE / REARM / WATCH_QUERY 都有"字段必须为空"的契约：带了值
     * 就说明调用方把它当成了别的操作，整条请求被判参数非法。无条件填满看着更
     * 简单，代价是三种操作恒定被拒，而用户看到的只有一个 win32=87。
     */
    if (op == KSWORD_ARK_HVM_EPT_RULE_ADD) {
        req.deniedAccess = access;
        req.physicalAddress = physicalPage;
        /* 一条监视恒定一页：驱动侧同样拒绝其它值。 */
        req.pageCount = 1ULL;
        req.requestedAddress = requestedAddress;
        req.requestedLength = requestedLength;
        req.requestedAccess = access;
        req.addressKind = addressKind;
        req.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE;
    } else if (op == KSWORD_ARK_HVM_EPT_RULE_REARM ||
               op == KSWORD_ARK_HVM_EPT_RULE_REMOVE) {
        req.ruleId = watchId;
    }
    if (op != KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY) {
        req.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
        req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    }
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL)) {
        fprintf(stderr, "EPT_RULE 下发失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (asJson) {
        printf("{\"kind\":\"watch\",\"operation\":%lu,\"status\":%lu,"
               "\"statusName\":\"%s\",\"lastStatus\":\"0x%08lX\","
               "\"generation\":%lu,\"watchCount\":%lu,"
               "\"conflictOwnerKind\":\"%s\",\"conflictOwnerId\":%lu,"
               "\"watches\":[",
               op, rsp.status, WatchRuleStatusName(rsp.status),
               (unsigned long)rsp.lastStatus, rsp.generation,
               rsp.watchRowCount,
               WatchConflictName(rsp.conflictOwnerKind), rsp.conflictOwnerId);
        if (rsp.returnedWatchRows != 0UL) {
            for (i = 0UL; i < rsp.returnedWatchRows &&
                          i < KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS; ++i) {
                if (i != 0UL) { printf(","); }
                PrintWatchRow(&rsp.watchRows[i], 1);
            }
        } else if (rsp.watch.watchId != 0UL) {
            PrintWatchRow(&rsp.watch, 1);
        }
        printf("]}\n");
    } else {
        printf("\n=== R-1 内存监视 ===\n");
        printf("  status       : %lu (%s)  lastStatus=0x%08lX  代次=%lu\n",
               rsp.status, WatchRuleStatusName(rsp.status),
               (unsigned long)rsp.lastStatus, rsp.generation);
        if (rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT) {
            printf("  ** 这一页已经被 %s #%lu 占着 **：一页只能有一个主人。\n",
                   WatchConflictName(rsp.conflictOwnerKind), rsp.conflictOwnerId);
            printf("     先把它撤掉再装监视；这里不会静默覆盖别人的叶项。\n");
        }
        if (rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN) {
            printf("  ** 常驻运行中 **：退出路径不取 PASSIVE 锁就扫规则表，所以\n");
            printf("     整张表在常驻期间冻结。先 stop，装完监视再 resident。\n");
        }
        if (rsp.returnedWatchRows != 0UL) {
            printf("  表内条数     : %lu\n", rsp.watchRowCount);
            for (i = 0UL; i < rsp.returnedWatchRows &&
                          i < KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS; ++i) {
                PrintWatchRow(&rsp.watchRows[i], 0);
            }
        } else if (rsp.watch.watchId != 0UL) {
            PrintWatchRow(&rsp.watch, 0);
        } else if (op == KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY) {
            printf("  （表里没有任何监视）\n");
        }
        printf("\n  监视单位是 4 KiB 物理页，不是上面的请求长度；命中不阻止访问。\n");
    }
    return rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK ? 0 : 2;
}

/* 把一个内核虚拟地址翻译成物理地址。失败返回非零。 */
static int WatchTranslate(HANDLE h, unsigned long long virtualAddress,
                          unsigned long long* physicalOut)
{
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    DWORD returned = 0;

    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = virtualAddress;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
        mrsp.physicalAddress == 0ULL) {
        fprintf(stderr, "翻译失败：status=%lu nt=0x%08lX win32=%lu\n",
                mrsp.status, (unsigned long)mrsp.ntStatus, GetLastError());
        return 1;
    }
    *physicalOut = mrsp.physicalAddress;
    return 0;
}

/*
 * 首次访问监视的端到端自检。
 *
 * 一个进程里跑完 issue #195 第二十二节第 1 项（WRITE First-touch）的全部检查，
 * 不需要另写一个测试驱动：自己分配并锁住一页，自己写它，自己核对命中现场。
 *
 * 为什么必须是同一个进程：RIP 判据。要证明"记下来的 RIP 就是那条写指令"，就得
 * 有一个已知的写指令地址可比；跨进程做这件事只能比到模块粒度，而模块粒度答不出
 * "是不是记错了一条指令"。
 *
 * 判定用四态而不是布尔：
 *   PASS     实跑通过，有执行证据
 *   FAIL     逻辑错了
 *   BLOCKED  这台机器上问不出来（没常驻、页拆不开、能力不够）——不是代码的问题，
 *            但也不能记成通过
 * "问不出来"与"跑失败"必须分开，否则 BLOCKED 会被当成 FAIL 拖着永远不绿，
 * 或者被当成 PASS 掩盖掉一个真问题。
 */

/*
 * 用例上限。
 *
 * 写成 12 的那一版实际填了 13 条，于是 WatchCase 写进了数组末尾之外，进程在
 * 靶机上直接 0xC0000005。留出余量并在 WatchCase 里挡一道：这段代码的全部意义
 * 是产出可信判据，而一个会自己崩掉的自检产出的是"没有读数"，不是"失败"。
 */
#define KSW_WATCH_SELFTEST_CASES 16U

typedef struct _KSW_WATCH_CASE
{
    const char* name;
    const char* expectation;
    const char* verdict;
    const char* remark;
    unsigned long long observed;
} KSW_WATCH_CASE;

/*
 * 自检跑的是哪一种访问。
 *
 * 三条自检的 JSON 里 kind 都是 "watch-selftest"，所以验收脚本只看 kind 分不出
 * 跑的是第 1 项还是第 3 项。把访问类型显式打进输出里，一条记录自己就说得清
 * 它是哪一项的证据 —— 否则三份结果并排贴出来完全一样，等于没有证据。
 */
static const char* WatchSelfTestAccessName(unsigned long access)
{
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL) { return "execute"; }
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) { return "write"; }
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL) { return "read"; }
    return "none";
}

static void WatchCase(KSW_WATCH_CASE* slot, const char* name,
                      const char* expectation, int ok,
                      unsigned long long observed, const char* remark)
{
    /* 越界写比任何一条判据都糟：它换来的是没有读数，而不是一个失败的读数。 */
    if (slot == NULL) { return; }
    slot->name = name;
    slot->expectation = expectation;
    slot->verdict = ok ? "PASS" : "FAIL";
    slot->observed = observed;
    slot->remark = remark;
}

/* 读一次常驻处理器数。失败时回报 0xFFFFFFFF，让调用方看得出是没问到而不是零。 */
static unsigned long WatchResidentCount(HANDLE h)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    DWORD returned = 0;

    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        return 0xFFFFFFFFUL;
    }
    return qrsp.residentProcessorCount;
}

/* 下发一次 watch 操作，把响应原样交回调用方。返回 0 表示 IOCTL 本身成功。 */
static int WatchIoctl(HANDLE h, unsigned long op, unsigned long watchId,
                      unsigned long long physicalPage,
                      unsigned long long requestedAddress,
                      unsigned long long requestedLength,
                      unsigned long access,
                      KSWORD_ARK_HVM_EPT_RULE_RESPONSE* rsp)
{
    KSWORD_ARK_HVM_EPT_RULE_REQUEST req;
    DWORD returned = 0;

    memset(&req, 0, sizeof(req));
    memset(rsp, 0, sizeof(*rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.operation = op;
    /* 与 DoWatch 同理：只填本操作允许的字段，其余留零。 */
    if (op == KSWORD_ARK_HVM_EPT_RULE_ADD) {
        req.deniedAccess = access;
        req.physicalAddress = physicalPage;
        req.pageCount = 1ULL;
        req.requestedAddress = requestedAddress;
        req.requestedLength = requestedLength;
        req.requestedAccess = access;
        req.addressKind = KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL;
        req.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE;
    } else if (op == KSWORD_ARK_HVM_EPT_RULE_REARM ||
               op == KSWORD_ARK_HVM_EPT_RULE_REMOVE) {
        req.ruleId = watchId;
    }
    if (op != KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY) {
        req.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
        req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    }
    return DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &req, sizeof(req),
                           rsp, (DWORD)sizeof(*rsp), &returned, NULL) ? 0 : 1;
}

/* 在整张表里找一条 watch。找不到返回 NULL。 */
static const KSWORD_ARK_HVM_EPT_WATCH_ROW* WatchFindRow(
    const KSWORD_ARK_HVM_EPT_RULE_RESPONSE* rsp, unsigned long watchId)
{
    unsigned long i;

    for (i = 0UL; i < rsp->returnedWatchRows &&
                  i < KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS; ++i) {
        if (rsp->watchRows[i].watchId == watchId) {
            return &rsp->watchRows[i];
        }
    }
    return NULL;
}

/*
 * 在自检内部推进一步生命周期。
 *
 * 自检必须自己起停常驻：watch 与其余 EPT 规则一样只能在常驻停着时装（退出路径
 * 不取 PASSIVE 锁就扫规则表，所以整张表在常驻期间冻结），而命中又只发生在常驻
 * 跑着的时候。把这两件事交给调用方手工穿插，等于让判据依赖一串没人核对的前置
 * 步骤——而漏掉其中任何一步，得到的都是一个看起来像"功能没生效"的结果。
 */
static int WatchLifecycle(HANDLE h, unsigned long command, unsigned long flags)
{
    KSWORD_ARK_CONTROL_HVM_REQUEST req;
    KSWORD_ARK_CONTROL_HVM_RESPONSE rsp;
    DWORD returned = 0;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    KswordArkHvmBuildControlRequest(&req, command, flags, 0UL, 0UL);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_CONTROL_HVM, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL)) {
        return 1;
    }
    return rsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK ? 0 : 2;
}

/*
 * 端到端自检，按访问类型参数化。
 *
 * issue #195 第二十二节的 1 / 2 / 3 项（WRITE / READ / EXECUTE 首次访问）是
 * 同一条流程换一个访问类型，所以共用一份实现而不是抄三遍：抄三遍的结果是三份
 * 会各自演化，而它们本该逐条对齐 —— 尤其是"命中不阻止访问"与"命中不结束常驻"
 * 这两条分界判据，三种访问类型下必须完全一样。
 *
 * Access 取 KSWORD_ARK_HVM_EPT_ACCESS_*。EXECUTE 走可执行页，其余走数据页；
 * 触发方式随之不同（写一个字节 / 读一个字节 / 调用一次），但判据表是同一张。
 */
static int DoWatchSelfTestAccess(HANDLE h, int asJson, unsigned long access)
{
    KSW_WATCH_CASE cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long residentBefore = 0UL;
    unsigned long residentAfter = 0UL;
    unsigned long watchId = 0UL;
    unsigned long firstHitCount = 0UL;
    unsigned long secondHitCount = 0UL;
    unsigned long n = 0UL;
    unsigned long i = 0UL;
    int failures = 0;
    int blocked = 0;
    int executeWatch = 0;
    /* volatile：触发读的那一次访问绝不能被优化掉，否则根本不会有命中。 */
    volatile unsigned char observed = 0U;
    DWORD returned = 0;

    memset(cases, 0, sizeof(cases));

    /*
     * --- 0. 先把常驻停下 ---
     *
     * 顺序是被机制逼出来的，不是偏好：规则表在常驻期间冻结，所以 watch 只能
     * 在停着时装；而命中只发生在跑着的时候，所以装完必须再起来。自检自己走完
     * 这一圈，判据才不依赖调用方记不记得穿插这几步。
     */
    if (WatchResidentCount(h) != 0UL) {
        (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                             KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    }
    /* 资源与逐核自检是启动常驻的前置；已经做过时它们是幂等的。 */
    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_PREPARE,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED);
    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_SELF_TEST,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED);

    /* --- 1. 拿一页自己的内存并落地成真实物理页 --- */
    executeWatch = (access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL;
    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE,
        executeWatch ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    (void)VirtualLock((LPVOID)page, 4096);
    /* 先写一次把页真正落地，这一次**在装监视之前**，不该被记成命中。 */
    page[0] = 0xA5U;
    if (executeWatch) {
        /*
         * 0xC3 = ret。执行监视要有个真能被调用的目标，而"最短的合法函数"
         * 正好是一条 ret —— 它不碰任何寄存器，调回来之后状态与调用前完全一样，
         * 于是"原执行最终正常完成"这条判据不会被别的副作用污染。
         */
        page[0] = 0xC3U;
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)page, 4096);
    }

    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = (unsigned long long)(ULONG_PTR)page;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
        mrsp.physicalAddress == 0ULL) {
        fprintf(stderr, "TRANSLATE 失败：status=%lu win32=%lu\n",
                mrsp.status, GetLastError());
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 1;
    }
    physical = mrsp.physicalAddress;
    physicalPage = physical & ~0xFFFULL;

    /* --- 2. 装一条写监视 --- */
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 8ULL,
                   access, &rsp) != 0) {
        fprintf(stderr, "watch ADD 下发失败：win32=%lu\n", GetLastError());
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 1;
    }
    if (rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        /*
         * 装不上分两类：能力/占用类是 BLOCKED（这台机器上问不出来），
         * 其余是 FAIL。把两者混成一个"失败"会让一台本来就装不上的机器
         * 永远绿不了，或者让一个真缺陷被当成环境问题放过去。
         */
        blocked = rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN ||
                  rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT ||
                  rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_SPLIT_FAILED ||
                  rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_PREPARED;
        if (asJson) {
            printf("{\"kind\":\"watch-selftest\",\"access\":\"%s\","
                   "\"verdict\":\"%s\",\"reason\":\"add-refused\",\"status\":%lu,"
                   "\"statusName\":\"%s\",\"cases\":[]}\n",
                   WatchSelfTestAccessName(access),
                   blocked ? "BLOCKED" : "FAIL", rsp.status,
                   WatchRuleStatusName(rsp.status));
        } else {
            printf("\n=== 内存监视端到端自检（%s）===\n",
                   WatchSelfTestAccessName(access));
            printf("  %s：装不上监视，status=%lu (%s)\n",
                   blocked ? "BLOCKED" : "FAIL", rsp.status,
                   WatchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return blocked ? 3 : 2;
    }
    watchId = rsp.ruleId;

    WatchCase(&cases[n++], "安装成功并分配了非零编号",
              "status=OK 且 watchId != 0",
              watchId != 0UL, watchId, NULL);
    /*
     * 归一化判据分两种，因为架构本来就分两种。
     *
     * 拒绝读必然连带拒绝写（EPT 不存在可写不可读的叶），没有仅执行能力时还要
     * 连带拒绝执行；写与执行则各自合法、不触发任何放宽。把两者写成同一条断言，
     * 要么 READ 恒失败，要么 WRITE 的放宽被放过去 —— 而后者正是"监视范围悄悄
     * 比用户以为的大"那类无症状缺陷。
     */
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL) {
        WatchCase(&cases[n++], "请求读时实际掩码必然连带写",
                  "effective 包含 READ|WRITE，且是 requested 的超集",
                  (rsp.watch.effectiveAccess &
                      (KSWORD_ARK_HVM_EPT_ACCESS_READ |
                       KSWORD_ARK_HVM_EPT_ACCESS_WRITE)) ==
                      (KSWORD_ARK_HVM_EPT_ACCESS_READ |
                       KSWORD_ARK_HVM_EPT_ACCESS_WRITE) &&
                  (rsp.watch.effectiveAccess & access) == access,
                  rsp.watch.effectiveAccess,
                  "EPT 不存在可写不可读的叶 —— 界面必须把请求与实际两栏都摆出来");
    } else {
        WatchCase(&cases[n++], "实际生效的访问掩码等于请求的",
                  "写/执行监视不触发架构归一化（只有拒绝读才会）",
                  rsp.watch.effectiveAccess == access,
                  rsp.watch.effectiveAccess, NULL);
    }
    WatchCase(&cases[n++], "武装后状态为 ARMED",
              "state = 1 (armed)",
              rsp.watch.state == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED,
              rsp.watch.state, NULL);
    WatchCase(&cases[n++], "装监视之前的那次访问没有被记成命中",
              "hitCount = 0",
              rsp.watch.hitCount == 0UL, rsp.watch.hitCount, NULL);

    /*
     * --- 3. 起常驻，然后触发一次写 ---
     *
     * residentBefore 在这里取，而不是自检一开始：验收要问的是"命中有没有让
     * 处理器掉出虚拟化"，那就必须拿命中前后两个读数比，而不是拿自检开始时的
     * 读数比 —— 后者会把自检自己做的那次停机算进差值里。
     */
    if (WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) != 0) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest\",\"access\":\"%s\","
                   "\"verdict\":\"BLOCKED\","
                   "\"reason\":\"resident-start-refused\",\"cases\":[]}\n",
                   WatchSelfTestAccessName(access));
        } else {
            printf("\n=== 内存监视端到端自检（%s）===\n",
                   WatchSelfTestAccessName(access));
            printf("  BLOCKED：监视装上了，但这台机器起不了常驻，命中路径问不出来。\n");
        }
        (void)WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, watchId, 0ULL,
                         0ULL, 0ULL, 0UL, &rsp);
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    residentBefore = WatchResidentCount(h);
    /* 触发那一条指令的地址就是 RIP 判据。 */
    if (executeWatch) {
        ((void (*)(void))(void*)page)();
    } else if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
        page[0] = 0x5AU;
    } else {
        observed = page[0];
    }

    /* --- 4. 读回并逐项核对 --- */
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) != 0) {
        fprintf(stderr, "watch QUERY 下发失败：win32=%lu\n", GetLastError());
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 1;
    }
    row = WatchFindRow(&rsp, watchId);
    if (row == NULL) {
        fprintf(stderr, "读不回刚装上的监视 #%lu\n", watchId);
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 2;
    }
    firstHitCount = row->hitCount;

    WatchCase(&cases[n++], "被监视的访问触发了一次命中",
              "hitCount = 1",
              row->hitCount == 1UL, row->hitCount, NULL);
    WatchCase(&cases[n++], "命中后自动解除",
              "state = 3 (disarmed)",
              row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED,
              row->state, NULL);
    WatchCase(&cases[n++], "命中的客户物理地址落在被监视的那一页里",
              "gpa & ~0xFFF = 被监视页",
              (row->lastHitGuestPhysicalAddress & ~0xFFFULL) == physicalPage,
              row->lastHitGuestPhysicalAddress, NULL);
    WatchCase(&cases[n++], "命中现场记下了非零的 RIP",
              "rip != 0",
              row->lastHitRip != 0ULL, row->lastHitRip, NULL);
    /*
     * GLA 判据分两态。
     *
     * 处理器**可以**不报告线性地址，那时既不能说它指对了，也不能说它指错了。
     * 把"没报告"判成 FAIL，会让一台架构上就不提供该信息的机器永远绿不了；
     * 判成 PASS 则等于凭空承认了一个没观测到的事实。所以分开记。
     */
    if (row->lastHitGuestLinearValid) {
        WatchCase(&cases[n++], "有效的客户线性地址指向实际被访问的地址",
                  "gla = &page[0]",
                  row->lastHitGuestLinearAddress ==
                      (unsigned long long)(ULONG_PTR)page,
                  row->lastHitGuestLinearAddress, NULL);
    } else {
        cases[n].name = "有效的客户线性地址指向实际被访问的地址";
        cases[n].expectation = "gla = &page[0]";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = 0ULL;
        cases[n].remark = "处理器这次没报告客户线性地址 —— 问不出来，不是错";
        ++n;
    }
    WatchCase(&cases[n++], "事件证据没有丢",
              "lastHitStatus = 1 (published)",
              row->lastHitStatus == KSWORD_ARK_HVM_EPT_WATCH_HIT_PUBLISHED,
              row->lastHitStatus,
              "丢了说明事件环被别的退出挤爆，与监视本身是否命中无关");

    /* --- 5. 第二次访问不该再产生命中 --- */
    if (executeWatch) {
        ((void (*)(void))(void*)page)();
    } else if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
        page[0] = 0xB2U;
    } else {
        observed = page[0];
    }
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = WatchFindRow(&rsp, watchId);
        secondHitCount = row != NULL ? row->hitCount : 0xFFFFFFFFUL;
    } else {
        secondHitCount = 0xFFFFFFFFUL;
    }
    WatchCase(&cases[n++], "第二次访问不再产生命中",
              "hitCount 不变",
              secondHitCount == firstHitCount, secondHitCount,
              "一次性监视命中后已经不再拦截，再访问应当完全无感");

    /* --- 6. 访问确实完成了，而且常驻没掉核 --- */
    if (executeWatch) {
        /* 调用返回到了这里，就是"执行最终完成"的证据。 */
        WatchCase(&cases[n++], "被监视的执行最终真的完成了",
                  "两次调用都正常返回",
                  page[0] == 0xC3U, (unsigned long long)page[0],
                  "命中不阻止访问 —— 这正是它与 ENFORCE 的分界");
    } else if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
        WatchCase(&cases[n++], "被监视的写最终真的完成了",
                  "page[0] = 0xB2",
                  page[0] == 0xB2U, (unsigned long long)page[0],
                  "命中不阻止访问 —— 这正是它与 ENFORCE 的分界");
    } else {
        WatchCase(&cases[n++], "被监视的读最终真的完成了",
                  "读回装监视前写下的 0xA5",
                  observed == 0xA5U, (unsigned long long)observed,
                  "命中不阻止访问 —— 这正是它与 ENFORCE 的分界");
    }
    residentAfter = WatchResidentCount(h);
    WatchCase(&cases[n++], "命中没有让任何处理器退出虚拟化",
              "residentAfter = residentBefore",
              residentAfter == residentBefore, residentAfter,
              "这是 WATCH_ONCE 与严格 tripwire 的**根本**区别");

    /*
     * --- 7. 收尾：先停常驻再撤监视，不给机器留状态 ---
     *
     * 顺序不能反：规则表在常驻期间冻结，常驻还跑着时的撤销会被直接拒绝，
     * 于是监视留在表里，下一次自检撞上 LEAF_CONFLICT 而看不出前因。
     */
    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    (void)WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, watchId, 0ULL, 0ULL,
                     0ULL, 0UL, &rsp);
    VirtualFree((LPVOID)page, 0, MEM_RELEASE);

    for (i = 0UL; i < n; ++i) {
        if (cases[i].verdict[0] == 'F') { ++failures; }
        if (cases[i].verdict[0] == 'B') { ++blocked; }
    }
    if (asJson) {
        printf("{\"kind\":\"watch-selftest\",\"access\":\"%s\",\"verdict\":\"%s\","
               "\"watchId\":%lu,\"residentBefore\":%lu,\"residentAfter\":%lu,"
               "\"physicalPage\":\"0x%016llX\",\"failures\":%d,\"blocked\":%d,"
               "\"cases\":[",
               WatchSelfTestAccessName(access),
               failures != 0 ? "FAIL" : (blocked != 0 ? "PASS-WITH-BLOCKED" : "PASS"),
               watchId, residentBefore, residentAfter, physicalPage,
               failures, blocked);
        for (i = 0UL; i < n; ++i) {
            printf("%s{\"name\":", i != 0UL ? "," : "");
            KswordHvmPrintJsonString(cases[i].name);
            printf(",\"expectation\":");
            KswordHvmPrintJsonString(cases[i].expectation);
            printf(",\"verdict\":\"%s\",\"observed\":\"0x%016llX\"",
                   cases[i].verdict, cases[i].observed);
            if (cases[i].remark != NULL) {
                printf(",\"remark\":");
                KswordHvmPrintJsonString(cases[i].remark);
            }
            printf("}");
        }
        printf("]}\n");
    } else {
        printf("\n=== 内存监视端到端自检（%s，watch #%lu，页 0x%016llX）===\n",
               WatchSelfTestAccessName(access), watchId, physicalPage);
        printf("  常驻处理器：命中前 %lu，命中后 %lu\n",
               residentBefore, residentAfter);
        for (i = 0UL; i < n; ++i) {
            printf("  [%-7s] %-34s  期望：%s\n", cases[i].verdict,
                   cases[i].name, cases[i].expectation);
            printf("            实测 0x%016llX%s%s\n", cases[i].observed,
                   cases[i].remark != NULL ? "  — " : "",
                   cases[i].remark != NULL ? cases[i].remark : "");
        }
        printf("\n  结论：%s（失败 %d，问不出来 %d，共 %lu 条）\n",
               failures != 0 ? "FAIL" : (blocked != 0 ? "PASS（含问不出来的项）" : "PASS"),
               failures, blocked, n);
    }
    /* 退出码：0 全过、2 有失败、3 有问不出来的项但没有失败。 */
    return failures != 0 ? 2 : (blocked != 0 ? 3 : 0);
}

/* 读一批事件。返回 0 表示 IOCTL 本身成功。 */
static int WatchEventQuery(HANDLE h, unsigned long long afterSequence,
                           KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE* rsp)
{
    KSWORD_ARK_HVM_EVENT_QUERY_REQUEST req;
    DWORD returned = 0;

    memset(&req, 0, sizeof(req));
    memset(rsp, 0, sizeof(*rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.operation = KSWORD_ARK_HVM_EVENT_QUERY_READ;
    req.maxRows = KSWORD_ARK_HVM_MAX_EVENT_ROWS;
    req.afterSequence = afterSequence;
    return DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EVENTS, &req, sizeof(req),
                           rsp, (DWORD)sizeof(*rsp), &returned, NULL) ? 0 : 1;
}

/* 把一批用例结果统一打印出来，三条扩展自检共用。 */
static int WatchReportCases(const char* kind, const char* title,
                            const KSW_WATCH_CASE* cases, unsigned long n,
                            int asJson, const char* extraJson)
{
    int failures = 0;
    int blocked = 0;
    unsigned long i;

    for (i = 0UL; i < n; ++i) {
        if (cases[i].verdict[0] == 'F') { ++failures; }
        if (cases[i].verdict[0] == 'B') { ++blocked; }
    }
    if (asJson) {
        printf("{\"kind\":\"%s\",\"verdict\":\"%s\",\"failures\":%d,"
               "\"blocked\":%d%s,\"cases\":[", kind,
               failures != 0 ? "FAIL" : (blocked != 0 ? "PASS-WITH-BLOCKED" : "PASS"),
               failures, blocked, extraJson != NULL ? extraJson : "");
        for (i = 0UL; i < n; ++i) {
            printf("%s{\"name\":", i != 0UL ? "," : "");
            KswordHvmPrintJsonString(cases[i].name);
            printf(",\"expectation\":");
            KswordHvmPrintJsonString(cases[i].expectation);
            printf(",\"verdict\":\"%s\",\"observed\":\"0x%016llX\"",
                   cases[i].verdict, cases[i].observed);
            if (cases[i].remark != NULL) {
                printf(",\"remark\":");
                KswordHvmPrintJsonString(cases[i].remark);
            }
            printf("}");
        }
        printf("]}\n");
    } else {
        printf("\n=== %s ===\n", title);
        for (i = 0UL; i < n; ++i) {
            printf("  [%-7s] %-38s  期望：%s\n", cases[i].verdict,
                   cases[i].name, cases[i].expectation);
            printf("            实测 0x%016llX%s%s\n", cases[i].observed,
                   cases[i].remark != NULL ? "  — " : "",
                   cases[i].remark != NULL ? cases[i].remark : "");
        }
        printf("\n  结论：%s（失败 %d，问不出来 %d，共 %lu 条）\n",
               failures != 0 ? "FAIL" : (blocked != 0 ? "PASS（含问不出来的项）" : "PASS"),
               failures, blocked, n);
    }
    return failures != 0 ? 2 : (blocked != 0 ? 3 : 0);
}

/* 停常驻、撤监视、放页，三条扩展自检的统一收尾。顺序不能反：表在常驻期间冻结。 */
static void WatchTeardown(HANDLE h, unsigned long watchId, volatile unsigned char* page)
{
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;

    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    if (watchId != 0UL) {
        (void)WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, watchId, 0ULL,
                         0ULL, 0ULL, 0UL, &rsp);
    }
    if (page != NULL) {
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    }
}

/* 把常驻停下并做好起常驻的前置。三条扩展自检开头都要走一遍。 */
static void WatchPrepareResidency(HANDLE h)
{
    if (WatchResidentCount(h) != 0UL) {
        (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                             KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    }
    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_PREPARE,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED);
    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_SELF_TEST,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED);
}

/*
 * 分配一页、落地、锁住，并翻译出它的物理页。失败返回非零。
 *
 * "落地"这一步不能省：VirtualAlloc 只是提交，没有任何字节被写过的页在翻译时
 * 可能还没有物理页框，翻出来的地址装上监视就是在盯一个与该 VA 无关的页 ——
 * 而那种错误装得上、读得回、就是永远不命中。
 */
static int WatchAllocatePage(HANDLE h, volatile unsigned char** pageOut,
                             unsigned long long* physicalPageOut)
{
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;

    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) { return 1; }
    (void)VirtualLock((LPVOID)page, 4096);
    page[0] = 0xA5U;
    if (WatchTranslate(h, (unsigned long long)(ULONG_PTR)page, &physical) != 0) {
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 1;
    }
    *pageOut = page;
    *physicalPageOut = physical & ~0xFFFULL;
    return 0;
}

/* SMP 自检的线程共享状态。 */
typedef struct _KSW_WATCH_SMP_THREAD
{
    volatile unsigned char* Page;
    /* 全部线程都就位之后主线程才置 1，用来把两次写挤到尽可能近的时刻。 */
    volatile LONG* Go;
    volatile LONG* Ready;
    unsigned long Index;
    unsigned char Value;
    /* 线程自己写完之后置 1；主线程用它区分"没跑"与"跑了但值不对"。 */
    volatile LONG Completed;
} KSW_WATCH_SMP_THREAD;

static DWORD WINAPI WatchSmpThread(LPVOID parameter)
{
    KSW_WATCH_SMP_THREAD* self = (KSW_WATCH_SMP_THREAD*)parameter;

    /* 报到，然后自旋等发令。自旋而不是等内核对象：要的是尽量小的时间差。 */
    InterlockedIncrement(self->Ready);
    while (InterlockedCompareExchange(self->Go, 0L, 0L) == 0L) {
        YieldProcessor();
    }
    /* 每个线程写自己那一格，这样"谁写过"与"写对没有"都能单独核对。 */
    self->Page[self->Index] = self->Value;
    InterlockedExchange(&self->Completed, 1L);
    return 0;
}

/*
 * 验收第 5 项：SMP 同时命中。
 *
 * 要问的不是"能不能命中"（第 1 项已经答过），而是**两个处理器几乎同时撞上同一页
 * 时会不会各算一次第一次**。所以判据集中在三件事上：只有一个逻辑首命中；两个
 * 处理器都活着继续跑完；页权限最终恢复到两边都能访问。
 *
 * 线程亲和性只覆盖第 0 处理器组。跨组要用 SetThreadGroupAffinity，而这台靶机
 * 是 2 vCPU 单组 —— 与其写一段永远跑不到的代码，不如在组数大于一时如实记
 * BLOCKED：没覆盖到的情况说成覆盖了，比没覆盖更糟。
 */
static int DoWatchSelfTestSmp(HANDLE h, int asJson)
{
    KSW_WATCH_CASE cases[KSW_WATCH_SELFTEST_CASES];
    KSW_WATCH_SMP_THREAD threads[8];
    HANDLE handles[8];
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    volatile unsigned char* page = NULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long residentBefore = 0UL;
    unsigned long residentAfter = 0UL;
    unsigned long watchId = 0UL;
    unsigned long n = 0UL;
    unsigned long i = 0UL;
    unsigned long threadCount = 0UL;
    unsigned long completed = 0UL;
    unsigned long correct = 0UL;
    DWORD_PTR processAffinity = 0;
    DWORD_PTR systemAffinity = 0;
    volatile LONG go = 0L;
    volatile LONG ready = 0L;
    DWORD waitResult = 0;
    int blocked = 0;

    memset(cases, 0, sizeof(cases));
    memset(threads, 0, sizeof(threads));
    memset(handles, 0, sizeof(handles));

    if (GetActiveProcessorGroupCount() > 1) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-smp\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"multi-processor-group\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视 SMP 同时命中自检 ===\n");
            printf("  BLOCKED：本机有多个处理器组，这段只安排得了第 0 组的亲和性。\n");
        }
        return 3;
    }
    if (!GetProcessAffinityMask(GetCurrentProcess(), &processAffinity,
                                &systemAffinity) || processAffinity == 0) {
        fprintf(stderr, "读不到进程亲和性掩码：win32=%lu\n", GetLastError());
        return 1;
    }
    /* 一个处理器安排不出"同时"，那是条件不具备而不是功能有问题。 */
    for (i = 0UL; i < 64UL; ++i) {
        if ((processAffinity & ((DWORD_PTR)1 << i)) != 0 && threadCount < 8UL) {
            threads[threadCount].Index = i;
            ++threadCount;
        }
    }
    if (threadCount < 2UL) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-smp\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"single-processor\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视 SMP 同时命中自检 ===\n");
            printf("  BLOCKED：只有一个可用处理器，安排不出同时访问。\n");
        }
        return 3;
    }

    WatchPrepareResidency(h);
    if (WatchAllocatePage(h, &page, &physicalPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 4096ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0 ||
        rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-smp\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"add-refused\",\"status\":%lu,\"cases\":[]}\n",
                   rsp.status);
        } else {
            printf("\n=== 内存监视 SMP 同时命中自检 ===\n");
            printf("  BLOCKED：装不上监视，status=%lu (%s)\n",
                   rsp.status, WatchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    watchId = rsp.ruleId;

    if (WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) != 0) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-smp\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"resident-start-refused\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视 SMP 同时命中自检 ===\n");
            printf("  BLOCKED：起不了常驻，命中路径问不出来。\n");
        }
        WatchTeardown(h, watchId, page);
        return 3;
    }
    residentBefore = WatchResidentCount(h);

    for (i = 0UL; i < threadCount; ++i) {
        threads[i].Page = page;
        threads[i].Go = &go;
        threads[i].Ready = &ready;
        threads[i].Value = (unsigned char)(0x40U + i);
        handles[i] = CreateThread(NULL, 0, WatchSmpThread, &threads[i],
                                  CREATE_SUSPENDED, NULL);
        if (handles[i] == NULL) { break; }
        /* 绑核是"同时"的前提：都落在一个核上就变成先后两次访问。 */
        (void)SetThreadAffinityMask(handles[i],
                                    (DWORD_PTR)1 << threads[i].Index);
        (void)ResumeThread(handles[i]);
    }
    if (i != threadCount) {
        /* 起线程失败：把已起的放掉再说，不留悬着的线程。 */
        InterlockedExchange(&go, 1L);
        (void)WaitForMultipleObjects((DWORD)i, handles, TRUE, 5000);
        for (n = 0UL; n < i; ++n) { CloseHandle(handles[n]); }
        fprintf(stderr, "起线程失败：win32=%lu\n", GetLastError());
        WatchTeardown(h, watchId, page);
        return 1;
    }
    /* 等全部线程报到，再一起发令。 */
    for (i = 0UL; i < 20000UL; ++i) {
        if ((unsigned long)InterlockedCompareExchange(&ready, 0L, 0L) >=
            threadCount) { break; }
        Sleep(1);
    }
    InterlockedExchange(&go, 1L);
    /*
     * 五秒。命中路径本身是微秒级的，等这么久唯一的用途是把"死锁"与"慢"分开：
     * 超时即判 FAIL，因为这条路径没有任何理由需要秒级时间。
     */
    waitResult = WaitForMultipleObjects((DWORD)threadCount, handles, TRUE, 5000);
    for (i = 0UL; i < threadCount; ++i) {
        if (InterlockedCompareExchange(&threads[i].Completed, 0L, 0L) != 0L) {
            ++completed;
        }
    }
    n = 0UL;
    WatchCase(&cases[n++], "全部参与线程都跑完了，没有卡住",
              "WaitForMultipleObjects 不超时",
              waitResult != WAIT_TIMEOUT, (unsigned long long)waitResult,
              "超时就是死锁 —— 这条路径没有任何理由需要秒级时间");
    WatchCase(&cases[n++], "每个处理器上的写都完成了",
              "completed = 线程数",
              completed == threadCount, completed, NULL);

    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = WatchFindRow(&rsp, watchId);
    }
    if (row == NULL) {
        fprintf(stderr, "读不回刚装上的监视 #%lu\n", watchId);
        for (i = 0UL; i < threadCount; ++i) { CloseHandle(handles[i]); }
        WatchTeardown(h, watchId, page);
        return 2;
    }
    /*
     * 这是整条自检的核心判据。
     *
     * hitCount 必须恰好是 1：多核竞争下"各算一次第一次"正是 ARMED->TRIGGERED
     * 原子转换要挡住的事，而它失败时表现得完全正常 —— 页恢复了、线程跑完了、
     * 机器没崩，只是同一个第一次被记了两遍。
     */
    WatchCase(&cases[n++], "只有一个逻辑首命中",
              "hitCount = 1",
              row->hitCount == 1UL, row->hitCount,
              "多核竞争下各算一次第一次的错误不会有任何其它症状");
    WatchCase(&cases[n++], "命中后自动解除",
              "state = 3 (disarmed)",
              row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED,
              row->state, NULL);
    WatchCase(&cases[n++], "首命中记在一个具体处理器上",
              "命中的处理器号在参与集合内",
              row->lastHitProcessorNumber < 64U &&
                  (processAffinity &
                   ((DWORD_PTR)1 << row->lastHitProcessorNumber)) != 0,
              (unsigned long long)row->lastHitProcessorNumber, NULL);

    /* 每个线程写自己那一格，所以权限恢复得对不对可以逐格核对。 */
    for (i = 0UL; i < threadCount; ++i) {
        if (page[threads[i].Index] == threads[i].Value) { ++correct; }
    }
    WatchCase(&cases[n++], "所有被监视的写最终都落了盘",
              "每个线程写下的字节都读得回来",
              correct == threadCount, correct,
              "少一格说明权限恢复只对某一个处理器生效");
    residentAfter = WatchResidentCount(h);
    WatchCase(&cases[n++], "两个处理器都还在虚拟化里",
              "residentAfter = residentBefore",
              residentAfter == residentBefore && residentBefore >= 2UL,
              ((unsigned long long)residentBefore << 32) | residentAfter,
              "高 32 位是命中前，低 32 位是命中后");

    for (i = 0UL; i < threadCount; ++i) { CloseHandle(handles[i]); }
    WatchTeardown(h, watchId, page);
    (void)blocked;
    return WatchReportCases("watch-selftest-smp",
                            "内存监视 SMP 同时命中自检", cases, n, asJson, NULL);
}

/*
 * 验收第 7 项：VA 映射变化。
 *
 * 第一版明确**不**跟踪 VA 重映射。那不是遗漏，是承诺：监视在装的那一刻绑定了
 * 一个物理页，之后这个 VA 指向哪里与它无关。所以这条自检要证的是"没跟过去"，
 * 而不是"跟过去了"——把 decommit / recommit 后的新页写一遍，命中数必须**还是
 * 零**，同时监视自己仍如实报告它盯的是原来那个物理页。
 *
 * 拿不到不同的物理页时记 BLOCKED：内存管理器完全可以把同一个页框还回来，那时
 * 这台机器上问不出这个问题，不是功能错了。
 */
static int DoWatchSelfTestRemap(HANDLE h, int asJson)
{
    KSW_WATCH_CASE cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    volatile unsigned char* page = NULL;
    unsigned long long armedPage = 0ULL;
    unsigned long long currentPage = 0ULL;
    unsigned long long virtualAddress = 0ULL;
    unsigned long watchId = 0UL;
    unsigned long n = 0UL;
    unsigned long attempt = 0UL;
    char extra[192];

    memset(cases, 0, sizeof(cases));

    WatchPrepareResidency(h);
    if (WatchAllocatePage(h, &page, &armedPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        return 1;
    }
    virtualAddress = (unsigned long long)(ULONG_PTR)page;
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, armedPage,
                   virtualAddress, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0 ||
        rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-remap\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"add-refused\",\"status\":%lu,\"cases\":[]}\n",
                   rsp.status);
        } else {
            printf("\n=== 内存监视 VA 重映射自检 ===\n");
            printf("  BLOCKED：装不上监视，status=%lu (%s)\n",
                   rsp.status, WatchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    watchId = rsp.ruleId;

    /*
     * 换页：解提交再提交同一个 VA。内存管理器不保证给出不同的页框，所以试几次，
     * 并且**只有真的换到别的页**才继续往下判。
     */
    currentPage = armedPage;
    for (attempt = 0UL; attempt < 16UL && currentPage == armedPage; ++attempt) {
        (void)VirtualUnlock((LPVOID)page, 4096);
        if (!VirtualFree((LPVOID)page, 4096, MEM_DECOMMIT)) { break; }
        if (VirtualAlloc((LPVOID)page, 4096, MEM_COMMIT, PAGE_READWRITE) == NULL) {
            break;
        }
        (void)VirtualLock((LPVOID)page, 4096);
        page[0] = 0x3CU;
        if (WatchTranslate(h, virtualAddress, &currentPage) != 0) { break; }
        currentPage &= ~0xFFFULL;
    }
    if (currentPage == armedPage) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-remap\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"backing-page-unchanged\","
                   "\"armedPage\":\"0x%016llX\",\"cases\":[]}\n", armedPage);
        } else {
            printf("\n=== 内存监视 VA 重映射自检 ===\n");
            printf("  BLOCKED：解提交再提交后拿回了同一个页框，制造不出重映射。\n");
        }
        WatchTeardown(h, watchId, page);
        return 3;
    }

    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = WatchFindRow(&rsp, watchId);
    }
    if (row == NULL) {
        fprintf(stderr, "读不回刚装上的监视 #%lu\n", watchId);
        WatchTeardown(h, watchId, page);
        return 2;
    }
    WatchCase(&cases[n++], "监视仍绑定在装它时那个物理页上",
              "physicalPage = Arm 时的页",
              row->physicalPage == armedPage, row->physicalPage,
              "第一版不跟踪重映射 —— 这是承诺，不是遗漏");
    WatchCase(&cases[n++], "监视如实报告它当初解析的那个虚拟地址",
              "requestedAddress = 原 VA",
              row->requestedAddress == virtualAddress, row->requestedAddress,
              "两栏都留着，界面才判得出当前映射已经不是这一页");
    WatchCase(&cases[n++], "当前 VA 已经指向另一个物理页",
              "当前翻译 != Arm 时的页",
              currentPage != armedPage, currentPage, NULL);
    WatchCase(&cases[n++], "重映射没有把监视状态改掉",
              "state = 1 (armed)",
              row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED, row->state,
              NULL);

    /* 起常驻，写新页。它不该命中 —— 命中才说明监视悄悄跟过去了。 */
    if (WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0) {
        page[0] = 0x71U;
        if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                       0ULL, 0UL, &rsp) == 0) {
            row = WatchFindRow(&rsp, watchId);
        }
        WatchCase(&cases[n++], "写新映射不会命中原监视",
                  "hitCount 仍为 0",
                  row != NULL && row->hitCount == 0UL,
                  row != NULL ? row->hitCount : 0xFFFFFFFFULL,
                  "命中了才说明监视悄悄跟着 VA 跑了");
    } else {
        cases[n].name = "写新映射不会命中原监视";
        cases[n].expectation = "hitCount 仍为 0";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = 0ULL;
        cases[n].remark = "这台机器起不了常驻，命中路径问不出来";
        ++n;
    }

    WatchTeardown(h, watchId, page);
    (void)_snprintf_s(extra, sizeof(extra), _TRUNCATE,
                      ",\"armedPage\":\"0x%016llX\",\"currentPage\":\"0x%016llX\"",
                      armedPage, currentPage);
    return WatchReportCases("watch-selftest-remap",
                            "内存监视 VA 重映射自检", cases, n, asJson, extra);
}

/*
 * 验收第 9 项：事件证据丢失。
 *
 * 这一项要防的错误只有一个形状：命中发生了，但承载现场的那一行被环冲掉，于是
 * 界面上"没有事件"，用户读成"目标没被动过"——结论恰好相反。
 *
 * 所以自检不去制造并发丢包（那不可控），而是用**环回绕**这条确定路径：开着
 * TRACE_ROUTINE_EXITS 起常驻，环每秒周转约二十次，命中那一行几十毫秒就被推出去。
 * 随后并排看两件事：事件查询已经取不回那一行（droppedRows 非零、最老序号已经
 * 越过它），而监视自己仍然报得出命中过、以及现场的 RIP/RSP/CR3。
 *
 * 表里同时留一条从没被碰过的监视作为对照：只有两者读数不同，"区分得开"这句话
 * 才有证据，否则一条全零的记录既能解释成没命中也能解释成丢了。
 */
static int DoWatchSelfTestEvidence(HANDLE h, int asJson)
{
    KSW_WATCH_CASE cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE erspBefore;
    KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE erspAfter;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* control = NULL;
    volatile unsigned char* page = NULL;
    volatile unsigned char* quiet = NULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long long quietPage = 0ULL;
    unsigned long long hitSequence = 0ULL;
    unsigned long watchId = 0UL;
    unsigned long quietId = 0UL;
    unsigned long n = 0UL;
    unsigned long i = 0UL;
    int foundBefore = 0;
    int foundAfter = 0;
    char extra[192];

    memset(cases, 0, sizeof(cases));
    memset(&erspBefore, 0, sizeof(erspBefore));
    memset(&erspAfter, 0, sizeof(erspAfter));

    WatchPrepareResidency(h);
    if (WatchAllocatePage(h, &page, &physicalPage) != 0 ||
        WatchAllocatePage(h, &quiet, &quietPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        if (page != NULL) { VirtualFree((LPVOID)page, 0, MEM_RELEASE); }
        return 1;
    }
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0 ||
        rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-evidence\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"add-refused\",\"status\":%lu,\"cases\":[]}\n",
                   rsp.status);
        } else {
            printf("\n=== 内存监视事件丢失自检 ===\n");
            printf("  BLOCKED：装不上监视，status=%lu (%s)\n",
                   rsp.status, WatchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        VirtualFree((LPVOID)quiet, 0, MEM_RELEASE);
        return 3;
    }
    watchId = rsp.ruleId;
    /* 对照组：装上但永远不碰。 */
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, quietPage,
                   (unsigned long long)(ULONG_PTR)quiet, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) == 0 &&
        rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        quietId = rsp.ruleId;
    }

    /*
     * 带 TRACE_ROUTINE_EXITS 起常驻。这个标志平时是关着的，正因为它开着时环
     * 每秒周转二十几次 —— 那正是这条自检需要的压力源，用不着另造一个。
     */
    if (WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_TRACE_ROUTINE_EXITS) != 0) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-evidence\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"resident-start-refused\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视事件丢失自检 ===\n");
            printf("  BLOCKED：起不了常驻，命中路径问不出来。\n");
        }
        if (quietId != 0UL) {
            (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                                 KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
            (void)WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, quietId, 0ULL,
                             0ULL, 0ULL, 0UL, &rsp);
        }
        WatchTeardown(h, watchId, page);
        VirtualFree((LPVOID)quiet, 0, MEM_RELEASE);
        return 3;
    }

    page[0] = 0x5AU;

    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = WatchFindRow(&rsp, watchId);
    }
    if (row == NULL) {
        fprintf(stderr, "读不回刚装上的监视 #%lu\n", watchId);
        WatchTeardown(h, watchId, page);
        VirtualFree((LPVOID)quiet, 0, MEM_RELEASE);
        return 2;
    }
    hitSequence = row->lastHitSequence;
    WatchCase(&cases[n++], "命中确实发生了",
              "hitCount = 1 且 state = 3 (disarmed)",
              row->hitCount == 1UL &&
                  row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED,
              ((unsigned long long)row->hitCount << 32) | row->state, NULL);
    WatchCase(&cases[n++], "命中现场记在监视自己身上",
              "rip / cr3 非零",
              row->lastHitRip != 0ULL && row->lastHitCr3 != 0ULL,
              row->lastHitRip,
              "环会回绕，只存在事件行里的现场等于没存");

    /* 刚命中，这一行应该还在环里。 */
    if (hitSequence > 0ULL &&
        WatchEventQuery(h, hitSequence - 1ULL, &erspBefore) == 0) {
        for (i = 0UL; i < erspBefore.returnedRows &&
                      i < KSWORD_ARK_HVM_MAX_EVENT_ROWS; ++i) {
            if (erspBefore.rows[i].sequence == hitSequence) { foundBefore = 1; }
        }
    }
    WatchCase(&cases[n++], "命中事件先是取得回来的",
              "环里能按序号找到那一行",
              foundBefore, hitSequence,
              "取不回来说明它一开始就没发布，那是另一个问题");

    /*
     * 让环转过去。实测 2 vCPU 上开着追踪时约每秒周转二十次，8192 个槽位几十毫秒
     * 就换一遍；两秒是留给慢机器的余量，不是需要两秒。
     */
    Sleep(2000);

    if (hitSequence > 0ULL &&
        WatchEventQuery(h, hitSequence - 1ULL, &erspAfter) == 0) {
        for (i = 0UL; i < erspAfter.returnedRows &&
                      i < KSWORD_ARK_HVM_MAX_EVENT_ROWS; ++i) {
            if (erspAfter.rows[i].sequence == hitSequence) { foundAfter = 1; }
        }
    }
    if (foundAfter) {
        /* 环没转过去：压力没造出来，这台机器上问不出这个问题。 */
        cases[n].name = "命中事件被环挤掉之后仍能证明命中过";
        cases[n].expectation = "按序号已经取不回那一行";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = erspAfter.newestSequence;
        cases[n].remark = "两秒里环没有转过去，造不出丢失条件";
        ++n;
    } else {
        WatchCase(&cases[n++], "命中事件被环挤掉之后仍能证明命中过",
                  "droppedRows 非零且按序号取不回那一行",
                  erspAfter.droppedRows != 0UL,
                  (unsigned long long)erspAfter.droppedRows,
                  "这正是界面绝不能显示成\"没有事件\"的那一刻");
    }

    /* 重新读一次监视：证据丢了，但命中过这件事没丢。 */
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = WatchFindRow(&rsp, watchId);
        control = quietId != 0UL ? WatchFindRow(&rsp, quietId) : NULL;
    }
    WatchCase(&cases[n++], "事件没了，监视仍然报得出命中过",
              "hitCount = 1 且 state = 3 (disarmed)",
              row != NULL && row->hitCount == 1UL &&
                  row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED,
              row != NULL
                  ? (((unsigned long long)row->hitCount << 32) | row->state)
                  : 0ULL,
              "命中状态不依赖事件是否发布成功");
    if (control != NULL) {
        WatchCase(&cases[n++], "与从没被碰过的监视读数不同",
                  "对照组 hitCount = 0 且 state = 1 (armed)",
                  control->hitCount == 0UL &&
                      control->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED,
                  ((unsigned long long)control->hitCount << 32) | control->state,
                  "两者读数相同的话，\"区分得开\"就没有证据");
    } else {
        cases[n].name = "与从没被碰过的监视读数不同";
        cases[n].expectation = "对照组 hitCount = 0 且 state = 1 (armed)";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = 0ULL;
        cases[n].remark = "对照监视没装上（第二页可能与别的规则冲突）";
        ++n;
    }

    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    if (quietId != 0UL) {
        (void)WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, quietId, 0ULL,
                         0ULL, 0ULL, 0UL, &rsp);
    }
    (void)WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, watchId, 0ULL,
                     0ULL, 0ULL, 0UL, &rsp);
    VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    VirtualFree((LPVOID)quiet, 0, MEM_RELEASE);

    (void)_snprintf_s(extra, sizeof(extra), _TRUNCATE,
                      ",\"hitSequence\":%llu,\"newestSequence\":%llu,"
                      "\"droppedRows\":%lu",
                      hitSequence, erspAfter.newestSequence,
                      erspAfter.droppedRows);
    return WatchReportCases("watch-selftest-evidence",
                            "内存监视事件丢失自检", cases, n, asJson, extra);
}

/*
 * P1 的进程归因：把命中现场的 CR3 归回一个 PID。
 *
 * 自检跑在自己身上，所以"对不对"有一个精确判据可比：归出来的必须是**本进程**
 * 的 PID。这一点很重要，因为归因的两种失败方式后果完全不同——归不出来是一条
 * 限制（写进界面就行），归到**别的进程**上是一条会把人引到错误目标上的假证据。
 *
 * 归不出来在这台机器上完全可能是正常的：命中来自用户态代码，而 KVA Shadow
 * 打开时用户态跑的是用户 CR3，驱动 attach 进去读回来的是内核 CR3，两者天生
 * 不相等。所以"没匹配上"记 BLOCKED 并把扫描数摆出来，"匹配到别人"才记 FAIL。
 *
 * 顺带说明为什么这不削弱这个功能：它真正要归因的是内核写（SSDT、DriverObject、
 * 回调），那些命中记下的就是内核 CR3。
 */
static int DoWatchSelfTestProcess(HANDLE h, int asJson)
{
    KSW_WATCH_CASE cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_PROCESS_REQUEST preq;
    KSWORD_ARK_HVM_PROCESS_RESPONSE prsp;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    volatile unsigned char* page = NULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long long hitCr3 = 0ULL;
    unsigned long watchId = 0UL;
    unsigned long ownPid = (unsigned long)GetCurrentProcessId();
    unsigned long n = 0UL;
    char extra[192];

    memset(cases, 0, sizeof(cases));
    memset(&prsp, 0, sizeof(prsp));

    WatchPrepareResidency(h);
    if (WatchAllocatePage(h, &page, &physicalPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0 ||
        rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-process\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"add-refused\",\"status\":%lu,\"cases\":[]}\n",
                   rsp.status);
        } else {
            printf("\n=== 内存监视进程归因自检 ===\n");
            printf("  BLOCKED：装不上监视，status=%lu (%s)\n",
                   rsp.status, WatchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    watchId = rsp.ruleId;

    if (WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) != 0) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-process\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"resident-start-refused\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视进程归因自检 ===\n");
            printf("  BLOCKED：起不了常驻，命中路径问不出来。\n");
        }
        WatchTeardown(h, watchId, page);
        return 3;
    }
    page[0] = 0x5AU;
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = WatchFindRow(&rsp, watchId);
    }
    hitCr3 = row != NULL ? row->lastHitCr3 : 0ULL;
    WatchCase(&cases[n++], "命中现场记下了非零的 CR3",
              "cr3 != 0",
              hitCr3 != 0ULL, hitCr3,
              "没有 CR3 就没有归因的输入，后面几条都无从谈起");

    /* 停常驻再归因：归因是后处理，不该要求常驻还跑着。 */
    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);

    memset(&preq, 0, sizeof(preq));
    preq.operation = KSWORD_ARK_HVM_PROCESS_OP_RESOLVE_CR3;
    preq.directoryBase = hitCr3;
    if (ProcessIoctl(h, &preq, &prsp) != 0) {
        fprintf(stderr, "归因下发失败：win32=%lu\n", GetLastError());
        WatchTeardown(h, watchId, page);
        return 1;
    }
    WatchCase(&cases[n++], "归因扫描真的跑起来了",
              "scanned > 0",
              prsp.resolvedScannedProcesses != 0UL,
              prsp.resolvedScannedProcesses,
              "扫描数为零说明一个进程都没问成，那与「扫过都不是它」是两回事");
    if (prsp.resolvedProcessId != 0UL) {
        WatchCase(&cases[n++], "归出来的就是本进程",
                  "resolvedProcessId = GetCurrentProcessId()",
                  prsp.resolvedProcessId == ownPid,
                  ((unsigned long long)prsp.resolvedProcessId << 32) | ownPid,
                  "归到别的进程上是假证据，比归不出来坏得多");
    } else {
        cases[n].name = "归出来的就是本进程";
        cases[n].expectation = "resolvedProcessId = GetCurrentProcessId()";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = (unsigned long long)prsp.resolvedScannedProcesses;
        cases[n].remark = "没匹配上。命中来自用户态，而 KVA Shadow 下用户 CR3 "
                          "与驱动读回的内核 CR3 天生不等——内核写的归因不受影响";
        ++n;
    }
    /* 拿一个绝不可能属于任何进程的值去问，必须干净地答"没有"。 */
    memset(&preq, 0, sizeof(preq));
    preq.operation = KSWORD_ARK_HVM_PROCESS_OP_RESOLVE_CR3;
    preq.directoryBase = 0x0000FFFFFFFFF000ULL;
    if (ProcessIoctl(h, &preq, &prsp) == 0) {
        WatchCase(&cases[n++], "问一个不存在的地址空间会干净地答没有",
                  "status = 6 (not-found) 且 pid = 0",
                  prsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND &&
                      prsp.resolvedProcessId == 0UL,
                  ((unsigned long long)prsp.status << 32) |
                      prsp.resolvedProcessId,
                  "随便匹配一个出来才是最坏的失败方式");
    }

    WatchTeardown(h, watchId, page);
    (void)_snprintf_s(extra, sizeof(extra), _TRUNCATE,
                      ",\"hitCr3\":\"0x%016llX\",\"ownPid\":%lu",
                      hitCr3, ownPid);
    return WatchReportCases("watch-selftest-process",
                            "内存监视进程归因自检", cases, n, asJson, extra);
}

/*
 * 验收第 6 项：视图冲突。
 *
 * 一页只能有一个主人。这条自检把一页先交给 CLOAK 视图，再让监视去要同一页，
 * 要证的有三件：装不上、说得清是谁占着、原来的视图一根毫毛没动。
 *
 * 第三件最容易被漏掉，也最要紧：一个"拒绝了但顺手把别人的叶项改了"的实现，
 * 从返回值上看与正确实现完全一样，症状要等到那条视图下一次被用到时才出现，
 * 而那时已经没人会把它和这次安装联系起来。
 */
static int DoWatchSelfTestConflict(HANDLE h, int asJson)
{
    KSW_WATCH_CASE cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_VIEW_REQUEST vreq;
    KSWORD_ARK_HVM_VIEW_RESPONSE vrsp;
    KSWORD_ARK_HVM_VIEW_RESPONSE vafter;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    volatile unsigned char* page = NULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long viewId = 0UL;
    unsigned long n = 0UL;
    unsigned long i = 0UL;
    int viewInstalled = 0;
    char extra[128];

    memset(cases, 0, sizeof(cases));
    memset(&vrsp, 0, sizeof(vrsp));
    memset(&vafter, 0, sizeof(vafter));

    /*
     * 这条自检要先装上一条**真的**分离视图，所以 prepare 必须带 EPTP 切换。
     *
     * 普通 prepare 也能过，但随后视图安装会撞上能力门（status=9），于是整条
     * 自检记 BLOCKED —— 而那个 BLOCKED 说的是"这台机器装不上视图"，与事实
     * 不符：装不上只是因为我们没要那个后端。一个由自己造成的 BLOCKED 比 FAIL
     * 更坏，它会让人去查机器。
     */
    if (WatchResidentCount(h) != 0UL) {
        (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                             KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    }
    /*
     * 先 teardown 再 prepare。
     *
     * 资源已经准备过时，带着别的标志再 prepare 一次回的是 ALREADY_PREPARED
     * 而不是"按新标志重配"——后端选型是在 prepare 那一刻定下的。不 teardown
     * 就换不掉它，而换不掉的表现是视图安装被能力门拒，看起来像机器不支持。
     *
     * 代价要说清楚：teardown 会清掉运行时里现有的一切，包括别处装着的监视与
     * 视图。这是个自检命令，不是日常命令。
     */
    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_TEARDOWN,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_PREPARE,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPTP_SWITCH);
    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_SELF_TEST,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED);
    if (WatchAllocatePage(h, &page, &physicalPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        return 1;
    }

    /* --- 1. 先把这一页交给一条 CLOAK 视图 --- */
    memset(&vreq, 0, sizeof(vreq));
    vreq.operation = KSWORD_ARK_HVM_VIEW_OP_ADD;
    vreq.kind = KSWORD_ARK_HVM_VIEW_KIND_CLOAK;
    /* SEED_FROM_TARGET：影子从目标页拷，不必自己填 4 KiB。 */
    vreq.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET;
    vreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    vreq.physicalAddress = physicalPage;
    if (ViewIoctl(h, &vreq, &vrsp) != 0) {
        fprintf(stderr, "视图安装下发失败：win32=%lu\n", GetLastError());
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 1;
    }
    if (vrsp.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
        /*
         * 装不上视图 ⇒ 这台机器上问不出"视图占着时监视会怎样"。
         * 这是条件不具备，不是监视的缺陷。
         */
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-conflict\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"view-add-refused\",\"viewStatus\":%lu,"
                   "\"cases\":[]}\n", vrsp.status);
        } else {
            printf("\n=== 内存监视视图冲突自检 ===\n");
            printf("  BLOCKED：这台机器装不上分离视图，status=%lu。\n", vrsp.status);
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    viewInstalled = 1;
    viewId = vrsp.viewId;
    WatchCase(&cases[n++], "对照用的分离视图装上了",
              "status=OK 且 viewId != 0",
              viewId != 0UL, viewId, NULL);

    /* --- 2. 让监视去要同一页 --- */
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0) {
        fprintf(stderr, "watch ADD 下发失败：win32=%lu\n", GetLastError());
        goto cleanup;
    }
    WatchCase(&cases[n++], "监视没装上",
              "status = 10 (leaf-conflict)",
              rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT,
              rsp.status,
              "静默覆盖别人的叶项才是最坏的结果，而它从返回值上看是成功");
    WatchCase(&cases[n++], "说得清是谁占着这一页",
              "conflictOwnerKind = 1 (view) 且 conflictOwnerId = 该视图",
              rsp.conflictOwnerKind == KSWORD_ARK_HVM_WATCH_CONFLICT_VIEW &&
                  rsp.conflictOwnerId == viewId,
              ((unsigned long long)rsp.conflictOwnerKind << 32) |
                  rsp.conflictOwnerId,
              "高 32 位是占有者类型，低 32 位是它的编号");
    /* 被拒的那条不该在表里留下任何东西。 */
    WatchCase(&cases[n++], "被拒的监视没有留下编号",
              "ruleId = 0",
              rsp.ruleId == 0UL, rsp.ruleId, NULL);

    /* --- 3. 原来的视图必须原封不动 --- */
    memset(&vreq, 0, sizeof(vreq));
    vreq.operation = KSWORD_ARK_HVM_VIEW_OP_QUERY;
    if (ViewIoctl(h, &vreq, &vafter) == 0) {
        const KSWORD_ARK_HVM_VIEW_ROW* row = NULL;

        for (i = 0UL; i < vafter.returnedRows &&
                      i < KSWORD_ARK_HVM_MAX_VIEWS; ++i) {
            if (vafter.rows[i].viewId == viewId) { row = &vafter.rows[i]; }
        }
        WatchCase(&cases[n++], "原视图还在，物理页没变",
                  "同一个 viewId 仍在表里且指向同一页",
                  row != NULL && row->physicalAddress == physicalPage,
                  row != NULL ? row->physicalAddress : 0ULL, NULL);
        WatchCase(&cases[n++], "原视图的类型没被改掉",
                  "kind 仍是 CLOAK",
                  row != NULL && row->kind == KSWORD_ARK_HVM_VIEW_KIND_CLOAK,
                  row != NULL ? row->kind : 0xFFFFFFFFULL,
                  "被拒的安装顺手改了别人的叶项，返回值上完全看不出来");
    } else {
        cases[n].name = "原视图还在，物理页没变";
        cases[n].expectation = "同一个 viewId 仍在表里且指向同一页";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = 0ULL;
        cases[n].remark = "视图查询下发失败，核对不了";
        ++n;
    }

cleanup:
    if (viewInstalled) {
        memset(&vreq, 0, sizeof(vreq));
        vreq.operation = KSWORD_ARK_HVM_VIEW_OP_REMOVE;
        vreq.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED;
        vreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        vreq.viewId = viewId;
        (void)ViewIoctl(h, &vreq, &vrsp);
    }
    VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    (void)_snprintf_s(extra, sizeof(extra), _TRUNCATE,
                      ",\"viewId\":%lu,\"physicalPage\":\"0x%016llX\"",
                      viewId, physicalPage);
    return WatchReportCases("watch-selftest-conflict",
                            "内存监视视图冲突自检", cases, n, asJson, extra);
}

/*
 * 验收第 8 项：常驻重启。
 *
 * 这一条要防的是"旧监视在下一次常驻里悄悄继续生效"。悄悄继续的后果不是多一条
 * 事件，是**一条用户以为已经失效的监视仍然在改 EPT 叶项**——而它对应的目标页
 * 可能早就被回收给别人用了。
 *
 * 判据分三段：停常驻后状态必须变成 INVALIDATED（不是留在 ARMED）、再起常驻不会
 * 自己变回 ARMED、显式 REARM 之后才重新武装。
 */
static int DoWatchSelfTestRestart(HANDLE h, int asJson)
{
    KSW_WATCH_CASE cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    volatile unsigned char* page = NULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long armedGeneration = 0UL;
    unsigned long watchId = 0UL;
    unsigned long n = 0UL;

    memset(cases, 0, sizeof(cases));

    WatchPrepareResidency(h);
    if (WatchAllocatePage(h, &page, &physicalPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0 ||
        rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-restart\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"add-refused\",\"status\":%lu,\"cases\":[]}\n",
                   rsp.status);
        } else {
            printf("\n=== 内存监视常驻重启自检 ===\n");
            printf("  BLOCKED：装不上监视，status=%lu (%s)\n",
                   rsp.status, WatchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    watchId = rsp.ruleId;
    armedGeneration = rsp.watch.armedGeneration;

    if (WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) != 0) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-restart\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"resident-start-refused\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视常驻重启自检 ===\n");
            printf("  BLOCKED：起不了常驻，这条路径问不出来。\n");
        }
        WatchTeardown(h, watchId, page);
        return 3;
    }
    /* --- 停常驻 --- */
    (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = WatchFindRow(&rsp, watchId);
    }
    WatchCase(&cases[n++], "停常驻之后监视被标成已失效",
              "state = 4 (invalidated)",
              row != NULL &&
                  row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED,
              row != NULL ? row->state : 0xFFFFFFFFULL,
              "留在 ARMED 就等于宣称它还在盯着，而那时它一条叶项都没装");

    /* --- 再起一次常驻：不能自己变回 ARMED --- */
    if (WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0) {
        row = NULL;
        if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                       0ULL, 0UL, &rsp) == 0) {
            row = WatchFindRow(&rsp, watchId);
        }
        WatchCase(&cases[n++], "下一次常驻不会静默恢复旧监视",
                  "state 仍为 4 (invalidated)",
                  row != NULL &&
                      row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED,
                  row != NULL ? row->state : 0xFFFFFFFFULL, NULL);
        /* 写一次：既然已经失效，就不该命中。 */
        page[0] = 0x6EU;
        row = NULL;
        if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                       0ULL, 0UL, &rsp) == 0) {
            row = WatchFindRow(&rsp, watchId);
        }
        WatchCase(&cases[n++], "失效的监视不再命中",
                  "hitCount 仍为 0",
                  row != NULL && row->hitCount == 0UL,
                  row != NULL ? row->hitCount : 0xFFFFFFFFULL,
                  "命中了说明叶项其实还装着，只是状态位说它失效了");
        (void)WatchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                             KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    } else {
        cases[n].name = "下一次常驻不会静默恢复旧监视";
        cases[n].expectation = "state 仍为 4 (invalidated)";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = 0ULL;
        cases[n].remark = "第二次起常驻被拒，这一段问不出来";
        ++n;
    }

    /* --- 显式重新武装 --- */
    row = NULL;
    if (WatchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REARM, watchId, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0 &&
        rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        row = &rsp.watch;
    }
    WatchCase(&cases[n++], "显式重新武装之后回到 ARMED",
              "state = 1 (armed)",
              row != NULL &&
                  row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED,
              row != NULL ? row->state : 0xFFFFFFFFULL, NULL);
    WatchCase(&cases[n++], "重新武装换了一个新的武装代次",
              "armedGeneration != 安装时的那个",
              row != NULL && row->armedGeneration != armedGeneration,
              row != NULL ? row->armedGeneration : 0ULL,
              "代次不变就分不出这条证据来自哪一次常驻");

    WatchTeardown(h, watchId, page);
    return WatchReportCases("watch-selftest-restart",
                            "内存监视常驻重启自检", cases, n, asJson, NULL);
}

/*
 * R-1 进程处置。
 *
 * op 为 QUERY 时其余参数全忽略；FREEZE / TERMINATE 需要 pid 与**十六进制**的
 * 客户线性地址——驱动不猜这一页，猜错的后果是拒绝落在一页永远不会被执行的
 * 地址上，那从外面看和成功一模一样。
 */
static int DoProcess(HANDLE h, unsigned long op, unsigned long pid,
                     unsigned long long gla, int asJson)
{
    KSWORD_ARK_HVM_PROCESS_REQUEST req;
    KSWORD_ARK_HVM_PROCESS_RESPONSE rsp;
    unsigned long i;

    memset(&req, 0, sizeof(req));
    req.operation = op;
    req.processId = pid;
    req.guestLinearAddress = gla;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;
    if (ProcessIoctl(h, &req, &rsp) != 0) { return 1; }

    if (asJson) {
        printf("{\"kind\":\"hvm-process\",\"status\":%lu,\"statusName\":\"%s\","
               "\"lastStatus\":\"0x%08lX\",\"rowCount\":%lu,\"generation\":%lu,"
               "\"rows\":[",
               rsp.status, ProcessStatusName(rsp.status),
               (unsigned long)rsp.lastStatus, rsp.rowCount, rsp.generation);
        for (i = 0UL; i < rsp.returnedRows &&
                      i < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS; ++i) {
            printf("%s{\"processId\":%lu,\"disposition\":%lu,"
                   "\"directoryBase\":\"0x%016llX\","
                   "\"guestPhysicalAddress\":\"0x%016llX\","
                   "\"guestLinearAddress\":\"0x%016llX\","
                   "\"interceptCount\":%llu,\"hierarchyIndex\":%lu}",
                   (i == 0UL) ? "" : ",",
                   rsp.rows[i].processId, rsp.rows[i].disposition,
                   rsp.rows[i].directoryBase, rsp.rows[i].guestPhysicalAddress,
                   rsp.rows[i].guestLinearAddress, rsp.rows[i].interceptCount,
                   rsp.rows[i].hierarchyIndex);
        }
        printf("]}\n");
        return (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_OK) ? 0 : 2;
    }

    printf("\n=== R-1 进程处置 ===\n");
    printf("  status       : %lu (%s)  lastStatus=0x%08lX\n",
           rsp.status, ProcessStatusName(rsp.status),
           (unsigned long)rsp.lastStatus);
    printf("  表内条数     : %lu   代次=%lu\n", rsp.rowCount, rsp.generation);
    if (rsp.returnedRows == 0UL) {
        printf("  （表里没有任何处置）\n");
    }
    for (i = 0UL; i < rsp.returnedRows &&
                  i < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS; ++i) {
        printf("  pid=%-6lu %s  cr3=0x%016llX gpa=0x%016llX gla=0x%016llX 拦截=%llu 层次#%lu\n",
               rsp.rows[i].processId,
               ProcessDispositionName(rsp.rows[i].disposition),
               rsp.rows[i].directoryBase, rsp.rows[i].guestPhysicalAddress,
               rsp.rows[i].guestLinearAddress, rsp.rows[i].interceptCount,
               rsp.rows[i].hierarchyIndex);
    }
    if (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_CR3_TRACKING_REQUIRED) {
        printf("  ** 缺 CR3 追踪 **：作用域完全靠它。先用 cr-policy 打开 TRACK_CR3，\n");
        printf("     再起常驻——这一位在常驻启动时写进 VMCS，起来之后改不了。\n");
    }
    if (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED) {
        printf("  ** 缺 EPTP 切换后端 **：没有第二套层次就没有\"受限\"可选。\n");
        printf("     prepare 时带 ENABLE_EPTP_SWITCH。\n");
    }
    if (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_REQUIRES_RESIDENT_STOPPED) {
        printf("  ** 常驻正在跑 **：安装要在常驻**停着**时做——常驻期间退出路径\n");
        printf("     不持锁读这张表与它的层次。与 EPT 规则、分离视图同一条规矩。\n");
        printf("     顺序：stop -> proc-freeze/terminate -> self-test -> resident。\n");
    }
    if (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_NOT_PREPARED) {
        printf("  ** 还没 prepare **：运行时里什么都没有。先 prepare-eptpsw。\n");
    }
    return (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_OK) ? 0 : 2;
}

/* Flight data is already copied by the driver; printing never changes the recorder. */
/* Emit exact bounded counters; consumers must reject invalid or saturated snapshots. */
static void PrintNptCacheJson(const KSWORD_ARK_HVM_SVM_GENERAL_METRICS* general)
{
    static const char* const reasons[KSW_HVM_NPT_CACHE_REASONS] = {
        "reuseDisabled", "cold", "epochChanged", "ownerChanged", "tlbRequested",
        "vmcbHpa", "ncr3", "asid", "l1Cr0", "l1Cr3", "l1Cr4", "l1Efer", "l1Pat",
        "outerRoot", "outerPat", "hardwarePat", "outerCapabilities", "innerCapabilities"
    };
    const KSWORD_HVM_NPT_CACHE_STATS* stats = &general->nptCache;
    unsigned i;
    printf(",\"nptCache\":{\"valid\":%lu,\"sequence\":\"%llu\",\"saturated\":%lu,"
        "\"lookups\":\"%llu\",\"hits\":\"%llu\",\"resets\":\"%llu\",\"resetFailures\":\"%llu\","
        "\"lastMissMask\":\"0x%08lX\",\"invlpgaCount\":\"%llu\",\"poolRecycles\":\"%llu\","
        "\"shadowEpoch\":\"%llu\",\"reasons\":{",
        general->valid, general->sequence, stats->saturated, stats->lookups, stats->hits,
        stats->resets, stats->resetFailures, stats->lastMissMask, general->invlpgaCount,
        general->cacheRecycles, general->shadowEpoch);
    for (i = 0; i < KSW_HVM_NPT_CACHE_REASONS; ++i) {
        printf("%s\"%s\":\"%llu\"", i ? "," : "", reasons[i], stats->reasons[i]);
    }
    printf("}}");
}

static void PrintHotspotsJson(const KSWORD_HVM_HOTSPOTS* hot)
{
    unsigned int level, code, slot;
    printf(",\"hotspots\":{\"valid\":%lu,\"saturated\":%lu,\"sequence\":\"%llu\",\"invalidLevel\":\"%llu\",\"levels\":[",
        hot->valid, hot->saturated, hot->sequence, hot->invalidLevel);
    for (level = 0; level < 2; ++level) {
        const KSWORD_HVM_HOT_LEVEL* row = &hot->levels[level];
        int comma = 0;
        printf("%s{\"level\":%u,\"total\":\"%llu\",\"npf\":\"%llu\",\"invalid\":\"%llu\",\"other\":\"%llu\","
            "\"lastCode\":\"0x%016llX\",\"lastRip\":\"0x%016llX\",\"lastInfo1\":\"0x%016llX\",\"lastInfo2\":\"0x%016llX\","
            "\"lastMsr\":\"0x%08lX\",\"msrOverflow\":\"%llu\",\"invalidMsrDirection\":\"%llu\",\"codes\":{",
            level ? "," : "", level + 1, row->total, row->npf, row->invalid, row->other,
            row->lastCode, row->lastRip, row->lastInfo1, row->lastInfo2, row->lastMsr,
            row->msrOverflow, row->invalidMsrDirection);
        for (code = 0; code < 256; ++code) {
            if (row->codes[code]) {
                printf("%s\"0x%02X\":\"%llu\"", comma ? "," : "", code, row->codes[code]); comma = 1;
            }
        }
        printf("},\"msrs\":[");
        for (slot = 0; slot < row->msrUsed && slot < KSW_HVM_HOT_MSR_SLOTS; ++slot) {
            const KSWORD_HVM_HOT_MSR* msr = &row->msrs[slot];
            printf("%s{\"number\":\"0x%08lX\",\"reads\":\"%llu\",\"writes\":\"%llu\",\"invalidDirection\":\"%llu\"}",
                slot ? "," : "", msr->number, msr->reads, msr->writes, msr->invalidDirection);
        }
        printf("]}");
    }
    printf("]}");
}

static void PrintFlightJson(const KSWORD_HVM_FLIGHT_RECORDER* f)
{
    unsigned i, j;
    printf(",\"flight\":{\"coherent\":%u", f->coherent);
    if (!f->coherent) { printf("}"); return; }
    printf(",\"latched\":%u,\"reason\":%u,\"captureTiming\":%u,\"vmcb12Valid\":%u,\"total\":\"%llu\",\"rows\":[",
        f->latched, f->reason, f->captureTiming, f->vmcb12Valid, f->total);
    for (i = 0; i < f->count && i < KSW_HVM_FLIGHT_ROWS; ++i) {
        const KSWORD_HVM_FLIGHT_ROW* r = &f->rows[(f->next + KSW_HVM_FLIGHT_ROWS - f->count + i) % KSW_HVM_FLIGHT_ROWS];
        printf("%s{\"ordinal\":\"%llu\",\"tsc\":\"%llu\",\"kind\":%u,\"phase\":%u,\"action\":%u,\"generation\":%u,"
            "\"operandPa\":\"0x%016llX\",\"leaseToken\":\"%llu\",\"exitCode\":\"0x%016llX\","
            "\"info1\":\"0x%016llX\",\"info2\":\"0x%016llX\",\"rip\":\"0x%016llX\",\"rsp\":\"0x%016llX\","
            "\"cr2\":\"0x%016llX\",\"cr3\":\"0x%016llX\",\"event\":\"0x%016llX\",\"exitIntInfo\":\"0x%016llX\",\"nrip\":\"0x%016llX\"}",
            i ? "," : "", r->ordinal, r->tsc, r->kind, r->phase, r->action, r->generation,
            r->operandPa, r->leaseToken, r->exitCode, r->info1, r->info2, r->rip, r->rsp,
            r->cr2, r->cr3, r->event, r->exitIntInfo, r->nrip);
    }
    printf("]");
    if (f->latched) {
        const unsigned char* pages[2] = { f->vmcb12, f->currentVmcb };
        const char* names[2] = { "vmcb12Hex", "currentVmcbHex" };
        for (i = 0; i < 2; ++i) {
            printf(",\"%s\":\"", names[i]);
            for (j = 0; j < KSW_HVM_FLIGHT_PAGE_BYTES; ++j) { printf("%02X", (unsigned)pages[i][j]); }
            printf("\"");
        }
    }
    printf("}");
}

static int DoMetrics(HANDLE h, int asJson)
{
    static const char* const globalNames[KSW_HVM_TIME_GLOBAL_STAGES] = {
        "resourcesBegin", "resourcesEnd", "eptBegin", "eptEnd", "rendezvousBegin", "rendezvousEnd"
    };
    static const char* const cpuNames[KSW_HVM_TIME_CPU_STAGES] = {
        "ipiEnter", "ipiLeave", "vmcsBegin", "stateCaptured", "vmcsWritten", "entryBefore", "entryAfter"
    };
    KSWORD_ARK_HVM_METRICS_REQUEST request = { 0 };
    KSWORD_ARK_HVM_METRICS_RESPONSE* response;
    DWORD returned = 0;
    unsigned long i, j;
    response = (KSWORD_ARK_HVM_METRICS_RESPONSE*)calloc(1, sizeof(*response));
    if (!response) { fprintf(stderr, "metrics: allocation failed\n"); return 1; }
    request.version = KSWORD_ARK_HVM_METRICS_VERSION;
    request.size = sizeof(request);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_METRICS,
                         &request, (DWORD)sizeof(request), response, (DWORD)sizeof(*response),
                         &returned, NULL)) {
        fprintf(stderr, "metrics query failed: Win32 %lu\n", GetLastError());
        free(response);
        return 1;
    }
    if (returned != sizeof(*response) || response->size != sizeof(*response) ||
        response->version != KSWORD_ARK_HVM_METRICS_VERSION ||
        response->processorCount > KSWORD_ARK_HVM_MAX_PROCESSORS || response->qpcFrequency == 0) {
        fprintf(stderr, "metrics: incompatible or incomplete response\n");
        free(response);
        return 1;
    }
    if (asJson) {
        /* Decimal strings preserve every bit in JavaScript and JSON consumers. */
        printf("{\"kind\":\"hvm-metrics\",\"version\":%lu,\"transitionCoherent\":%s,"
               "\"transitionSequence\":%lu,\"command\":%lu,\"lastStatus\":\"0x%08lX\","
               "\"processorCount\":%lu,\"qpcFrequency\":\"%llu\","
               "\"snapshotBeginQpc\":\"%llu\",\"snapshotEndQpc\":\"%llu\","
               "\"commandBeginQpc\":\"%llu\",\"commandEndQpc\":\"%llu\","
               "\"inveptAttempts\":\"%llu\",\"inveptSucceeded\":\"%llu\",\"inveptFailed\":\"%llu\","
               "\"ruleAllocations\":\"%llu\",\"ruleFrees\":\"%llu\","
               "\"replacementAllocations\":\"%llu\",\"replacementFrees\":\"%llu\","
               "\"globalValidMask\":%lu,\"globalQpc\":{",
               response->version, response->transitionCoherent ? "true" : "false",
               response->transitionSequence, response->command, response->lastStatus,
               response->processorCount, response->qpcFrequency,
               response->snapshotBeginQpc, response->snapshotEndQpc,
               response->commandBeginQpc, response->commandEndQpc,
               response->inveptAttempts, response->inveptSucceeded, response->inveptFailed,
               response->ruleAllocations, response->ruleFrees,
               response->replacementAllocations, response->replacementFrees,
               response->globalValidMask);
    } else {
        printf("metrics version=%lu coherent=%lu sequence=%lu command=%lu nt=0x%08lX cpus=%lu\n"
               "QPC frequency=%llu snapshot=[%llu,%llu] command=[%llu,%llu]\n"
               "INVEPT attempts=%llu success=%llu failure=%llu\n"
               "nested-page objects allocated=%llu freed=%llu; replacement pages allocated=%llu freed=%llu\n"
               "global validMask=0x%lX\n",
               response->version, response->transitionCoherent, response->transitionSequence,
               response->command, response->lastStatus, response->processorCount,
               response->qpcFrequency, response->snapshotBeginQpc, response->snapshotEndQpc,
               response->commandBeginQpc, response->commandEndQpc,
               response->inveptAttempts, response->inveptSucceeded, response->inveptFailed,
               response->ruleAllocations, response->ruleFrees,
               response->replacementAllocations, response->replacementFrees, response->globalValidMask);
    }
    for (i = 0; i < KSW_HVM_TIME_GLOBAL_STAGES; ++i) {
        if (asJson) { printf("%s\"%s\":\"%llu\"", i ? "," : "", globalNames[i], response->globalQpc[i]); }
        else { printf("  %s=%llu\n", globalNames[i], response->globalQpc[i]); }
    }
    if (asJson) { printf("},\"processors\":["); }
    for (i = 0; i < response->processorCount; ++i) {
        const KSWORD_ARK_HVM_METRICS_CPU* cpu = &response->processors[i];
        if (asJson) { printf("%s{\"group\":%u,\"number\":%u,\"validMask\":%lu,\"qpc\":{",
                            i ? "," : "", (unsigned)cpu->group, (unsigned)cpu->number, cpu->validMask); }
        else { printf("cpu=%u:%u validMask=0x%lX\n", (unsigned)cpu->group, (unsigned)cpu->number, cpu->validMask); }
        for (j = 0; j < KSW_HVM_TIME_CPU_STAGES; ++j) {
            if (asJson) { printf("%s\"%s\":\"%llu\"", j ? "," : "", cpuNames[j], cpu->qpc[j]); }
            else { printf("  %s=%llu\n", cpuNames[j], cpu->qpc[j]); }
        }
        if (asJson) { printf("}}"); }
    }
    if (asJson) { printf("],\"shadowEpt\":["); }
    for (i = 0; i < response->shadowProcessorCount && i < KSWORD_ARK_HVM_MAX_PROCESSORS; ++i) {
        const KSWORD_ARK_HVM_SHADOW_METRICS* row = &response->shadowProcessors[i];
        if (asJson) {
            printf("%s{\"index\":%lu,\"pagesUsed\":%lu,\"trackedPages\":%lu,\"trackedOverflow\":%lu,"
                   "\"fills\":%lu,\"denied\":%lu,\"exhausted\":%lu,\"kept\":%lu,\"dropped\":%lu,"
                   "\"adPending\":%lu,\"adPropagated\":%lu,\"adOverflow\":%lu,\"verifyMismatch\":%lu}",
                   i ? "," : "", row->index, row->pagesUsed, row->trackedPages, row->trackedOverflow,
                   row->fills, row->denied, row->exhausted, row->kept, row->dropped,
                   row->adPending, row->adPropagated, row->adOverflow, row->verifyMismatch);
        } else {
            printf("shadow cpu=%lu fills=%lu kept=%lu dropped=%lu pages=%lu tracked=%lu overflow=%lu "
                   "adPending=%lu adOverflow=%lu mismatch=%lu\n", row->index, row->fills,
                   row->kept, row->dropped, row->pagesUsed, row->trackedPages, row->trackedOverflow,
                   row->adPending, row->adOverflow, row->verifyMismatch);
        }
    }
    if (asJson) { printf("],\"backend\":%lu,\"svmProcessors\":[", response->backend); }
    for (i = 0; i < response->svmProcessorCount && i < KSWORD_ARK_HVM_MAX_PROCESSORS; ++i) {
        const KSWORD_ARK_HVM_SVM_METRICS* row = &response->svmProcessors[i];
        if (asJson) {
            printf("%s{\"group\":%u,\"number\":%u,\"valid\":%lu,\"sequence\":%lu,\"stage\":%lu,\"asid\":%lu,\"generation\":%lu,"
                   "\"exitCode\":\"0x%016llX\",\"exitInfo1\":\"0x%016llX\",\"exitInfo2\":\"0x%016llX\","
                   "\"rip\":\"0x%016llX\",\"rsp\":\"0x%016llX\",\"cr3\":\"0x%016llX\",\"nrip\":\"0x%016llX\","
                   "\"event\":\"0x%016llX\",\"tsc\":\"%llu\",\"vmcbPa\":\"0x%016llX\",\"hsavePa\":\"0x%016llX\","
                   "\"nptRootPa\":\"0x%016llX\",\"tlbRequests\":\"%llu\",\"ringPosition\":%lu,\"ringOverwritten\":%lu,\"msrValidMask\":%lu,\"svmFeatures\":%lu,\"asidCount\":%lu,\"physicalBits\":%lu,\"observedVmCr\":\"0x%016llX\",\"observedEfer\":\"0x%016llX\",\"observedHsave\":\"0x%016llX\",\"failureStatus\":\"0x%08lX\",\"failureStage\":%lu,",
                   i ? "," : "", (unsigned)row->group, (unsigned)row->number, row->valid, row->sequence,
                   row->stage, row->asid, row->generation, row->exitCode, row->exitInfo1, row->exitInfo2,
                   row->rip, row->rsp, row->cr3, row->nrip, row->event, row->tsc, row->vmcbPa, row->hsavePa,
                   row->nptRootPa, row->tlbRequests, row->ringPosition, row->ringOverwritten, row->msrValidMask, row->svmFeatures, row->asidCount, row->physicalBits, row->observedVmCr, row->observedEfer, row->observedHsave, row->failureStatus, row->failureStage);
            printf("\"nestedProbe\":{\"valid\":%lu,\"sequence\":%lu,\"status\":\"0x%08lX\",\"entries\":%lu,\"reflections\":%lu,\"faults\":%lu,\"exit\":\"0x%016llX\",\"marker\":\"0x%016llX\"},",
                   row->nestedProbeValid, row->nestedProbeSequence, row->nestedProbeStatus,
                   row->nestedProbeEntries, row->nestedProbeReflections, row->nestedProbeFaults,
                   row->nestedProbeExit, row->nestedProbeMarker);
            printf("\"general\":{\"valid\":%lu,\"initialized\":%lu,\"enabled\":%lu,\"phase\":%lu,\"action\":%lu,\"gif\":%lu,"
                   "\"pending\":%lu,\"nmiCaptured\":%lu,\"instructionStatus\":%lu,\"instructionLength\":%lu,\"operandAddressBits\":%lu,\"shadowPages\":%lu,"
                   "\"sequence\":\"%llu\",\"preparedEntries\":\"%llu\",\"hardwareExits\":\"%llu\",\"exitCode\":\"0x%016llX\","
                   "\"leaseToken\":\"%llu\",\"operandHostPa\":\"0x%016llX\",\"armedToken\":\"%llu\",\"retryToken\":\"%llu\","
                   "\"delivered\":\"%llu\",\"retried\":\"%llu\",\"cacheRecycles\":\"%llu\",\"virtualEfer\":\"0x%016llX\","
                   "\"virtualHsave\":\"0x%016llX\",\"guestXcr0\":\"0x%016llX\",\"guestXss\":\"0x%016llX\"}",
                   row->general.valid, row->general.initialized, row->general.enabled, row->general.phase, row->general.action, row->general.gif,
                   row->general.pending, row->general.nmiCaptured, row->general.instructionStatus, row->general.instructionLength,
                   row->general.operandAddressBits, row->general.shadowPages, row->general.sequence, row->general.preparedEntries,
                   row->general.hardwareExits, row->general.exitCode, row->general.leaseToken, row->general.operandHostPa,
                   row->general.armedToken, row->general.retryToken, row->general.delivered, row->general.retried,
                   row->general.cacheRecycles, row->general.virtualEfer, row->general.virtualHsave, row->general.guestXcr0, row->general.guestXss);
            PrintNptCacheJson(&row->general);
            PrintFlightJson(&row->flight); PrintHotspotsJson(&row->hotspots); printf("}");
        } else {
            printf("SVM cpu=%u:%u stage=%lu valid=%lu exit=0x%016llX info1=0x%016llX info2=0x%016llX flush=%llu\n",
                   (unsigned)row->group, (unsigned)row->number, row->stage, row->valid,
                   row->exitCode, row->exitInfo1, row->exitInfo2, row->tlbRequests);
        }
    }
    if (asJson) { printf("]}\n"); }
    free(response);
    return 0;
}

/* Resolve a process lease through Windows APIs, without calling the VMM. */
static int ResolveNestedPageOwner(DWORD requested, DWORD* owner, ULONGLONG* created)
{
    HANDLE process;
    FILETIME birth, exited, kernel, user;
    ULARGE_INTEGER value;
    if (requested == 0UL) {
        PROCESSENTRY32W entry = { 0 };
        DWORD count = 0UL;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) { return 0; }
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, L"vmware-vmx.exe") == 0) {
                    requested = entry.th32ProcessID;
                    ++count;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        if (count != 1UL) {
            fprintf(stderr, "Select an explicit VMM owner PID when there is not exactly one vmware-vmx process.\n");
            return 0;
        }
    }
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, requested);
    if (process == NULL) { return 0; }
    if (!GetProcessTimes(process, &birth, &exited, &kernel, &user)) {
        CloseHandle(process);
        return 0;
    }
    CloseHandle(process);
    value.LowPart = birth.dwLowDateTime;
    value.HighPart = birth.dwHighDateTime;
    *owner = requested;
    *created = value.QuadPart;
    return 1;
}

static int DoNestedPageEx(HANDLE h, int asJson, unsigned long operation,
                          unsigned long long eptp, unsigned long long gpa,
                          unsigned char fill, unsigned long faultMode, unsigned long ownerPid,
                          unsigned long leafShift, unsigned long stagePageIndex,
                          unsigned long extraFlags)
{
    KSWORD_ARK_HVM_NESTED_PAGE_REQUEST request = { 0 };
    KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE response = { 0 };
    DWORD returned = 0;
    unsigned long index;
    request.version = KSWORD_ARK_HVM_NESTED_PAGE_VERSION;
    request.size = sizeof(request);
    /*
     * A query issues only the first request, so a flag meant for it has to be
     * set here. Only for a query, though: the other operations use this first
     * request to read the generation, and a flag the driver accepts only on the
     * real operation would make that read a rejected request.
     */
    request.flags = (operation == KSWORD_ARK_HVM_NESTED_PAGE_QUERY) ? extraFlags : 0UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_NESTED_PAGE,
                         &request, sizeof(request), &response, sizeof(response),
                         &returned, NULL) || returned != sizeof(response)) {
        fprintf(stderr, "nested-page query failed: Win32 %lu\n", GetLastError());
        return 1;
    }
    if (operation != KSWORD_ARK_HVM_NESTED_PAGE_QUERY) {
        if (response.status != 0UL) { return 2; }
        request.operation = operation;
        request.flags = KSWORD_ARK_HVM_NESTED_PAGE_CONFIRMED | extraFlags |
            (faultMode << KSWORD_ARK_HVM_NESTED_PAGE_FAULT_SHIFT);
        request.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        request.expectedGeneration = response.generation;
        request.ept12Pointer = eptp;
        request.guestPhysicalPage = gpa;
        /* Zero keeps the driver's version-3 meaning; only MAP carries either. */
        request.leafShift = (operation == KSWORD_ARK_HVM_NESTED_PAGE_MAP) ? leafShift : 0UL;
        request.stagePageIndex =
            (operation == KSWORD_ARK_HVM_NESTED_PAGE_STAGE) ? stagePageIndex : 0UL;
        memset(request.shadow, fill, sizeof(request.shadow));
        if (operation == KSWORD_ARK_HVM_NESTED_PAGE_MAP &&
            !ResolveNestedPageOwner(ownerPid, &request.ownerProcessId, &request.ownerCreationTime)) {
            fprintf(stderr, "Cannot establish a VMM process lifetime lease.\n");
            return 1;
        }
        if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_NESTED_PAGE,
                             &request, sizeof(request), &response, sizeof(response),
                             &returned, NULL) || returned != sizeof(response)) {
            fprintf(stderr, "nested-page operation failed: Win32 %lu\n", GetLastError());
            return 1;
        }
    }
    if (asJson) {
        printf("{\"kind\":\"nested-page\",\"operationId\":%lu,\"faultMode\":%lu,\"status\":%lu,\"lastStatus\":\"0x%08lX\","
               "\"generation\":%lu,\"active\":%lu,\"retired\":%lu,\"residentProcessors\":%lu,"
               "\"ept12Pointer\":\"0x%016llX\",\"guestPhysicalPage\":\"0x%016llX\","
               "\"shadowPhysicalPage\":\"0x%016llX\",\"originalPhysicalPage\":\"0x%016llX\","
               "\"composedCount\":%llu,\"ownerProcessId\":%lu,\"ownerExited\":%lu,\"ownerCreationTime\":\"%llu\","
               "\"leafShift\":%lu,\"sourceLeafShift\":%lu,\"regionBytes\":%llu,\"regionPageCount\":%llu,\"stagedPageCount\":%llu,"
               "\"admittedByScan\":%lu,\"scannedLeafCount\":%llu,\"scannedSharedBits\":\"0x%016llX\","
               "\"sourceDigest\":\"0x%016llX\",\"backingDigest\":\"0x%016llX\",\"digestBytes\":%llu,"
               "\"leaseRevocationReason\":%lu,\"sourcePhysicalPage\":\"0x%016llX\",\"sourceEntryCount\":%lu,\"sourcePath\":[",
               response.operationId, faultMode, response.status, response.lastStatus, response.generation, response.active,
               response.retired, response.residentProcessors, response.ept12Pointer,
               response.guestPhysicalPage, response.shadowPhysicalPage,
               response.originalPhysicalPage, response.composedCount, response.ownerProcessId,
               response.ownerExited, response.ownerCreationTime,
               response.leafShift, response.sourceLeafShift, response.regionBytes,
               response.regionPageCount, response.stagedPageCount,
               response.admittedByScan, response.scannedLeafCount,
               response.scannedSharedBits,
               response.sourceDigest, response.backingDigest, response.digestBytes,
               response.leaseRevocationReason,
               response.sourcePhysicalPage, response.sourceEntryCount);
        for (index = 0; index < response.sourceEntryCount && index < 4; ++index) {
            printf("%s{\"address\":\"0x%016llX\",\"value\":\"0x%016llX\"}", index ? "," : "",
                   response.sourceEntryAddress[index], response.sourceEntryValue[index]);
        }
        printf("],\"roots\":[");
    } else {
        printf("nested-page status=%lu nt=0x%08lX generation=%lu active=%lu retired=%lu cpus=%lu\n"
               "leaf=%lu source-leaf=%lu region=%llu bytes (%llu pages) staged=%llu\n"
               "EPT12=0x%016llX GPA=0x%016llX shadow=0x%016llX original=0x%016llX composed=%llu\n",
               response.status, response.lastStatus, response.generation, response.active,
               response.retired, response.residentProcessors,
               response.leafShift, response.sourceLeafShift, response.regionBytes,
               response.regionPageCount, response.stagedPageCount,
               response.ept12Pointer,
               response.guestPhysicalPage, response.shadowPhysicalPage,
               response.originalPhysicalPage, response.composedCount);
        printf("ownerPid=%lu ownerCreated=%llu ownerExited=%lu\n", response.ownerProcessId,
               response.ownerCreationTime, response.ownerExited);
        printf("leaseRevocationReason=%lu sourcePhysicalPage=0x%016llX sourceEntryCount=%lu\n",
               response.leaseRevocationReason, response.sourcePhysicalPage, response.sourceEntryCount);
    }
    for (index = 0UL; index < response.rootCount && index < KSWORD_ARK_HVM_MAX_PROCESSORS; ++index) {
        if (asJson) { printf("%s\"0x%016llX\"", index ? "," : "", response.ept12Roots[index]); }
        else { printf("EPT12 root[%lu]=0x%016llX\n", index, response.ept12Roots[index]); }
    }
    if (asJson) { printf("]}\n"); }
    return response.status == 0UL ? 0 : 2;
}

/* Every command except the scanning one sets no extra request flags. */
static int DoNestedPage(HANDLE h, int asJson, unsigned long operation,
                        unsigned long long eptp, unsigned long long gpa,
                        unsigned char fill, unsigned long faultMode, unsigned long ownerPid,
                        unsigned long leafShift, unsigned long stagePageIndex)
{
    return DoNestedPageEx(h, asJson, operation, eptp, gpa, fill, faultMode,
                          ownerPid, leafShift, stagePageIndex, 0UL);
}


int KswordHvmCommandMain(int argc, char** argv)
{
    const HVM_COMMAND_SPEC* spec;
    const char* name;
    unsigned long long v[KSW_HVM_COMMAND_MAX_ARGS];
    char error[256];
    int argi = 1, asJson = 0, validateOnly = 0, rc = 0;
    HANDLE h;
    (void)SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    while (argi < argc) {
        if (strcmp(argv[argi], "--json") == 0) { asJson = 1; ++argi; }
        else if (strcmp(argv[argi], "--validate") == 0) { validateOnly = 1; ++argi; }
        else { break; }
    }
    name = argi < argc ? argv[argi++] : "status";
    spec = KswordHvmFindCommand(name);
    if (!spec) {
        fprintf(stderr, "Unknown HVM command: %s\n", name);
        return 2;
    }
    if (KswordHvmValidateArguments(spec, argc - argi, (const char* const*)(argv + argi),
                                   v, error, sizeof(error)) != 0) {
        fprintf(stderr, "Invalid or missing argument: %s (%s)\n", error, spec->name);
        return 2;
    }
    if (validateOnly) {
        unsigned int i;
        printf("{\"kind\":\"validated\",\"command\":\"%s\",\"operation\":%lu,\"flags\":%lu,\"values\":[",
               spec->name, spec->command, spec->flags);
        for (i = 0; i < spec->argumentCount; ++i) { printf("%s\"0x%016llX\"", i ? "," : "", v[i]); }
        printf("],\"arguments\":[");
        for (i = 0; i < spec->argumentCount; ++i) {
            if (i) { putchar(','); }
            KswordHvmPrintJsonString((int)i < argc - argi ? argv[argi + i] : spec->arguments[i].defaultValue);
        }
        putchar(']');
        if (spec->handler == HvmControl) {
            KSWORD_ARK_CONTROL_HVM_REQUEST request;
            KswordArkHvmBuildControlRequest(&request, spec->command, spec->flags, 0, (unsigned long)v[0]);
            printf(",\"controlRequest\":{\"version\":%lu,\"size\":%lu,\"command\":%lu,\"flags\":%lu,"
                   "\"expectedGeneration\":%lu,\"soakMilliseconds\":%lu,\"vmreadBenchIterations\":%lu}",
                   request.version, request.size, request.command, request.flags,
                   request.expectedGeneration, request.soakMilliseconds, request.vmreadBenchIterations);
        }
        printf("}\n");
        return 0;
    }
    if (spec->handler == HvmHelp || spec->handler == HvmCommands) {
        KswordHvmPrintCommands(asJson);
        return 0;
    }
    if (spec->handler == HvmCpuid) { return DoCpuidView(asJson); }
    h = OpenDevice();
    if (h == INVALID_HANDLE_VALUE) {
        if (asJson) { printf("{\"kind\":\"error\",\"reason\":\"device-open-failed\"}\n"); }
        return 1;
    }
    switch (spec->handler) {
    case HvmControl: rc = DoControl(h, spec, (unsigned long)v[0], asJson); break;
    case HvmStatus: rc = DoQuery(h, asJson); break;
    case HvmMetrics: rc = DoMetrics(h, asJson); break;
    case HvmPageQuery: rc = DoNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_QUERY, 0, 0, 0, 0, 0, 0, 0); break;
    case HvmPageMap: rc = DoNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_MAP, v[0], v[1], (unsigned char)v[2], 0, (unsigned long)v[3], 0, 0); break;
    /* Fill is zero and unused: a region map clones the original, and the driver
       ignores the inline page whenever the granularity is larger than 4 KiB. */
    case HvmPageMapRegion: rc = DoNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_MAP, v[0], v[1], 0, 0, (unsigned long)v[3], (unsigned long)v[2], 0); break;
    case HvmPageMapRegionScan: rc = DoNestedPageEx(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_MAP, v[0], v[1], 0, 0, (unsigned long)v[3], (unsigned long)v[2], 0, KSWORD_ARK_HVM_NESTED_PAGE_SCAN_SOURCE); break;
    case HvmPageDigest: rc = DoNestedPageEx(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_QUERY, 0, 0, 0, 0, 0, 0, 0, KSWORD_ARK_HVM_NESTED_PAGE_DIGEST); break;
    case HvmPageStage: rc = DoNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_STAGE, 0, 0, (unsigned char)v[1], 0, 0, 0, (unsigned long)v[0]); break;
    case HvmPageMapTest: rc = DoNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_MAP, v[0], v[1], (unsigned char)v[2], (unsigned long)v[3], 0, 0, 0); break;
    case HvmPageRemove: rc = DoNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_REMOVE, 0, 0, 0, 0, 0, 0, 0); break;
    case HvmPageRemoveTest: rc = DoNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_REMOVE, 0, 0, 0, KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH, 0, 0, 0); break;
    case HvmAcl: rc = DoAclProbe(h, asJson); break;
    case HvmNestedProbe: rc = DoNestedProbe(h, asJson, 0); break;
    case HvmNestedProbeAll: rc = DoNestedProbe(h, asJson, 1); break;
    case HvmNestedAd: rc = DoNestedProbeAdRefusal(h, asJson); break;
    case HvmSelfvirt: rc = DoNestedSelfVirtualize(h, asJson, 0); break;
    case HvmSelfvirtAll: rc = DoNestedSelfVirtualize(h, asJson, 1); break;
    case HvmGdt: rc = DoGdtDump(h, asJson, (int)v[0]); break;
    case HvmMsrLog: rc = DoMsrPolicy(h, KSWORD_ARK_HVM_MSR_POLICY_OP_ADD, (unsigned long)v[0], asJson); break;
    case HvmMsrClear: rc = DoMsrPolicy(h, KSWORD_ARK_HVM_MSR_POLICY_OP_CLEAR, 0, asJson); break;
    case HvmXonly: rc = DoProbeExecuteOnly(h, asJson); break;
    case HvmAllowOnce: rc = DoRuleAllowOnceGate(h, asJson); break;
    case HvmTlb: rc = DoTlbProbe(h, asJson, (unsigned long)v[0], 0); break;
    case HvmTlbExit: rc = DoTlbProbe(h, asJson, (unsigned long)v[0], 1); break;
    case HvmPlatform: rc = DoProbePlatform(h, asJson); break;
    case HvmFlags: rc = DoProbeFlags(h, asJson); break;
    case HvmViewQuery: rc = DoViewQuery(h, asJson); break;
    case HvmViewProbe: rc = DoViewProbe(h, asJson); break;
    case HvmViewEffect: rc = DoViewEffect(h, asJson); break;
    case HvmSelfcheck: rc = DoSelfCheck(h, asJson); break;
    case HvmViewVerify: rc = DoViewVerify(h, asJson); break;
    case HvmEvents: rc = DoEvents(h, v[0], (unsigned long)v[1], asJson); break;
    case HvmEptLeaf: rc = DoEptLeaf(h, v[0], asJson); break;
    case HvmCrOn: rc = DoCrTrackCr3(h, 1, asJson); break;
    case HvmCrOff: rc = DoCrTrackCr3(h, 0, asJson); break;
    case HvmInjectQuery: rc = DoInjectSimple(h, KSWORD_ARK_HVM_INJECT_OP_QUERY, 0, asJson); break;
    case HvmInjectClear: rc = DoInjectSimple(h, KSWORD_ARK_HVM_INJECT_OP_RELEASE_ALL, 0, asJson); break;
    case HvmInjectRelease: rc = DoInjectSimple(h, KSWORD_ARK_HVM_INJECT_OP_RELEASE, (unsigned long)v[0], asJson); break;
    case HvmInjectTest: rc = DoInjectTest(h, (unsigned long)v[0], v[1], v[2], (unsigned long)v[3], asJson); break;
    case HvmInjectDll: rc = DoInjectDll(h, (unsigned long)v[0], v[1], v[2], argv[argi + 3], asJson); break;
    case HvmProcQuery: rc = DoProcess(h, KSWORD_ARK_HVM_PROCESS_OP_QUERY, 0, 0, asJson); break;
    case HvmProcClear: rc = DoProcess(h, KSWORD_ARK_HVM_PROCESS_OP_RELEASE_ALL, 0, 0, asJson); break;
    case HvmProcRelease: rc = DoProcess(h, KSWORD_ARK_HVM_PROCESS_OP_RELEASE, (unsigned long)v[0], 0, asJson); break;
    case HvmProcFreeze: rc = DoProcess(h, KSWORD_ARK_HVM_PROCESS_OP_FREEZE, (unsigned long)v[0], v[1], asJson); break;
    case HvmProcTerminate: rc = DoProcess(h, KSWORD_ARK_HVM_PROCESS_OP_TERMINATE, (unsigned long)v[0], v[1], asJson); break;
    case HvmWatchAddVa: {
        unsigned long long physical = 0ULL;

        /*
         * 翻译一次并就此绑定。
         *
         * 之后来宾把同一个虚拟地址重映射到别的物理页，这条监视也不会跟过去；
         * 这里把翻译结果原样打在输出里，正是为了让自动化判据能核对"我监视的
         * 到底是哪一页"，而不是只看一个虚拟地址就以为绑定关系恒成立。
         */
        rc = WatchTranslate(h, v[0], &physical);
        if (rc == 0) {
            rc = DoWatch(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL,
                         physical & ~0xFFFULL, v[0], v[1],
                         (unsigned long)v[2],
                         KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL, asJson);
        }
        break;
    }
    case HvmWatchAddPa:
        rc = DoWatch(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL,
                     v[0] & ~0xFFFULL, v[0], v[1], (unsigned long)v[2],
                     KSWORD_ARK_HVM_WATCH_ADDRESS_PHYSICAL, asJson);
        break;
    case HvmWatchList:
        rc = DoWatch(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL,
                     0ULL, 0ULL, 0ULL, 0UL, 0UL, asJson);
        break;
    case HvmWatchRearm:
        rc = DoWatch(h, KSWORD_ARK_HVM_EPT_RULE_REARM, (unsigned long)v[0],
                     0ULL, 0ULL, 0ULL, 0UL, 0UL, asJson);
        break;
    case HvmWatchRemove:
        rc = DoWatch(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, (unsigned long)v[0],
                     0ULL, 0ULL, 0ULL, 0UL, 0UL, asJson);
        break;
    case HvmWatchSelfTest:
        rc = DoWatchSelfTestAccess(h, asJson, KSWORD_ARK_HVM_EPT_ACCESS_WRITE);
        break;
    case HvmWatchSelfTestRead:
        rc = DoWatchSelfTestAccess(h, asJson, KSWORD_ARK_HVM_EPT_ACCESS_READ);
        break;
    case HvmWatchSelfTestExec:
        rc = DoWatchSelfTestAccess(h, asJson, KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE);
        break;
    case HvmWatchSelfTestSmp:
        rc = DoWatchSelfTestSmp(h, asJson);
        break;
    case HvmWatchSelfTestRemap:
        rc = DoWatchSelfTestRemap(h, asJson);
        break;
    case HvmWatchSelfTestEvidence:
        rc = DoWatchSelfTestEvidence(h, asJson);
        break;
    case HvmWatchSelfTestConflict:
        rc = DoWatchSelfTestConflict(h, asJson);
        break;
    case HvmWatchSelfTestRestart:
        rc = DoWatchSelfTestRestart(h, asJson);
        break;
    case HvmWatchSelfTestProcess:
        rc = DoWatchSelfTestProcess(h, asJson);
        break;
    default: rc = 2; break;
    }
    CloseHandle(h);
    return rc;
}

int KswordHvmCommandMainWide(int argc, wchar_t** argv)
{
    char** utf8;
    int i, result = 1;
    if (argc < 1) { return 2; }
    utf8 = (char**)calloc((size_t)argc + 1, sizeof(*utf8));
    if (utf8 == NULL) { return 1; }
    for (i = 0; i < argc; ++i) {
        int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, NULL, 0, NULL, NULL);
        if (length <= 0) { goto cleanup; }
        utf8[i] = (char*)malloc((size_t)length);
        if (utf8[i] == NULL || !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            argv[i], -1, utf8[i], length, NULL, NULL)) { goto cleanup; }
    }
    result = KswordHvmCommandMain(argc, utf8);
cleanup:
    for (i = 0; i < argc; ++i) { free(utf8[i]); }
    free(utf8);
    return result;
}
