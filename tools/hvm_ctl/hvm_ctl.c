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
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
/* __cpuid：tlb-probe-exit 用它强制一次无条件 VM exit。 */
#include <intrin.h>

/* 协议的唯一真值来源。手抄一份就等于给自己埋一个静默的漂移。 */
#include "../../shared/driver/KswordArkHvmIoctl.h"

#define KSW_DEVICE_PATH L"\\\\.\\KswordARKLog"

/* 本工具支持的命令，和它们各自被驱动接受的标志集合。 */
typedef struct _HVM_CTL_VERB {
    const char*   name;
    unsigned long command;
    /* 必须与 hvm_runtime.c 的 allowedFlags switch 逐位一致。 */
    unsigned long flags;
    const char*   description;
} HVM_CTL_VERB;

/*
 * UI_CONFIRMED 是所有命令的硬性前提（hvm_runtime.c 无条件检查）。
 * FORCE 是 SELF_TEST / LAUNCH_TEST_GUEST / START_RESIDENT / VALIDATE_NESTED /
 * SOAK / RESET_FAULT 的额外前提，缺了就是 CONFIRMATION_REQUIRED。
 * ALLOW_NESTED 是"我知道自己跑在别的 hypervisor 之下"的显式选择；TEARDOWN 与
 * STOP_RESIDENT **不接受**它，多带一位会被判 INVALID_REQUEST。
 */
static const HVM_CTL_VERB g_Verbs[] = {
    { "prepare",     KSWORD_ARK_HVM_CONTROL_PREPARE,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED,
      "分配每处理器资源，不进 VMX" },
    /*
     * 单独一个动词，而不是给 prepare 加参数 —— 现有 prepare 的字节序列
     * 必须一个位都不变，否则「关掉新后端时行为不变」就没法用同一条命令验。
     */
    { "prepare-eptpsw", KSWORD_ARK_HVM_CONTROL_PREPARE,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPTP_SWITCH,
      "同 prepare，但请求 EPTP 切换分离视图后端（需 execute-only + INVEPT_SINGLE）" },
    { "self-test",   KSWORD_ARK_HVM_CONTROL_SELF_TEST,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED,
      "逐处理器 VMXON/VMXOFF" },
    { "resident",    KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED,
      "全处理器常驻 VMM + EPT" },
    /*
     * 与 resident 逐位相同，只多一个测量位 —— 单独一个动词而不是给 resident 加
     * 参数，理由和 prepare-eptpsw 一样：正常那条命令的字节序列必须一个位都不变，
     * 否则"没测量时行为不变"就没法用同一条命令验。
     */
    { "resident-vmreadbench", KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_VMREAD_BENCH,
      "同 resident，但每次退出多做 32 次 VMREAD（只为测量，会变慢）" },
    { "soak",        KSWORD_ARK_HVM_CONTROL_SOAK,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED,
      "有界常驻，毫秒数由第二个参数给出" },
    { "stop",        KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED,
      "停止常驻" },
    { "teardown",    KSWORD_ARK_HVM_CONTROL_TEARDOWN,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED,
      "释放全部可逆资源" },
    { "reset-fault", KSWORD_ARK_HVM_CONTROL_RESET_FAULT,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE,
      "清 FAULTED / ROLLBACK_REQUIRED" },
    /*
     * 一次性受控 guest：真写 VMCS、真装 EPTP、真 VMLAUNCH，进一个只执行 VMCALL
     * 的 guest 然后退出。爆炸半径是一个 4KiB guest 栈。
     *
     * 它存在的理由是 SELF_TEST **证明不了**的那一块：SELF_TEST 只做 VMXON →
     * 立刻 VMXOFF，没有 VMCLEAR/VMPTRLD/VMWRITE/VMLAUNCH。所以 "self-test 4/4"
     * 对 "L0 是否接受我们的 VMCS 构造、是否为 L1 供给的 EPTP 建影子 EPT、
     * VMLAUNCH 与 exit 分派在嵌套下是否工作" 零证据。这条命令一次把那块问掉。
     *
     * ONE_SHOT_GUEST 是它的语义标记，缺了会被判 INVALID_REQUEST。
     */
    { "launch-test-guest", KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST,
      "一次性 VMLAUNCH + VMCALL 受控 guest" },
    { "validate-nested", KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX |
      KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS,
      "嵌套 VMX 与 eVMCS 的部分能力校验" },
};

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
                   "\"vmxInstructionResult\":%u,\"stateFlags\":%lu,"
                   "\"stateHex\":\"0x%08lX\",\"lastStatus\":\"0x%08lX\","
                   "\"lastExitReason\":%lu,\"vmExitCount\":%llu,\"stateNames\":[",
                   (i == 0UL) ? "" : ",", i,
                   (unsigned)row->processorGroup, (unsigned)row->processorNumber,
                   (unsigned)row->vmxInstructionResult, row->stateFlags,
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
    case 7UL:  return "INTERRUPT_WINDOW";
    case 10UL: return "CPUID";
    case 12UL: return "HLT";
    case 13UL: return "INVD";
    case 18UL: return "VMCALL";
    case 28UL: return "MOV_CR";
    case 29UL: return "MOV_DR";
    case 30UL: return "IO_INSTRUCTION";
    case 31UL: return "RDMSR";
    case 32UL: return "WRMSR";
    case 33UL: return "VM_ENTRY_FAILURE_GUEST_STATE";
    case 34UL: return "VM_ENTRY_FAILURE_MSR_LOADING";
    case 37UL: return "MONITOR_TRAP_FLAG";
    case 48UL: return "EPT_VIOLATION";
    case 49UL: return "EPT_MISCONFIGURATION";
    case 55UL: return "XSETBV";
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
               "\"droppedEventCount\":%lu",
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
               rsp.eventCount, rsp.droppedEventCount);
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

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.command = verb->command;
    req.flags = verb->flags;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    /* soakMilliseconds 对非 SOAK 命令必须为 0，否则驱动判 INVALID_REQUEST。 */
    req.soakMilliseconds =
        (verb->command == KSWORD_ARK_HVM_CONTROL_SOAK) ? soakMs : 0UL;

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
               rsp.eptPointer, rsp.eptPageCount, rsp.eptRuleCount,
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
static int DoEvents(HANDLE h, unsigned long long afterSequence, int asJson)
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
    req.maxRows = KSWORD_ARK_HVM_MAX_EVENT_ROWS;
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
                   "\"processor\":%u}",
                   (i == 0UL) ? "" : ",",
                   rsp.rows[i].sequence, rsp.rows[i].type,
                   EventTypeName(rsp.rows[i].type),
                   rsp.rows[i].exitReason, rsp.rows[i].access, acc,
                   rsp.rows[i].ruleId, rsp.rows[i].guestPhysicalAddress,
                   rsp.rows[i].guestLinearAddress, rsp.rows[i].guestRip,
                   rsp.rows[i].qualification, (unsigned long)rsp.rows[i].status,
                   (unsigned)rsp.rows[i].processorNumber);
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
        reason = "多核且 LOCAL_EPT 未武装：第九道门会先命中，"
                 "与能力门**同码**，无法归因。";
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
               "\"processorCount\":%lu,\"residentProcessorCount\":%lu,"
               "\"eptReady\":%s,\"monitorTrapFlag\":%s,\"inveptSingle\":%s,"
               "\"localEptArmed\":%s,\"status\":%lu,\"statusName\":\"%s\","
               "\"lastStatus\":\"0x%08lX\",\"installed\":%s,"
               "\"expected\":\"%s\",\"reason\":\"%s\"}\n",
               NegName(verdict), attempted ? "true" : "false",
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
        if (verdict == NEG_VOID) {
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

static void PrintUsage(void)
{
    size_t i;
    printf("用法: hvm_ctl.exe [--json] <命令> [参数]\n\n");
    printf("  status           只读查询，不改状态\n");
    printf("  probe-platform   平台探针（只读，不进 VMX：CET / KVA shadow / "
           "GS base）\n");
    printf("  probe-flags      负向探针（ENFORCE、能力 flag、互斥组合是否被"
           "**正确地**拒绝）\n");
    printf("  probe-xonly      execute-only 探针（要求常驻**没在跑**；自己走完 "
           "装规则→起常驻→读→停→清）\n");
    printf("  rule-allowonce   ALLOW_ONCE 规则**安装期**的门（要求常驻没在跑；"
           "装上会立刻删掉）\n");
    printf("  tlb-probe        跨处理器 TLB 失效探针，毫秒数由第二个参数给出"
           "（纯用户态，起停常驻由外面控制）\n");
    printf("  tlb-probe-exit   同上，但每次读之前先执行 CPUID 强制一次 VM exit"
           "（验证「打出去一次就够」这个前提）\n");
    printf("  view-query       列出已安装的 EPT 分离视图（只读，无需确认）\n");
    printf("  view-probe       分离视图安装期**归因**探针（前提：prepare 过、"
           "常驻没在跑；装上会立刻卸掉）\n");
    printf("  view-effect      分离视图**是否真的生效**（装 CLOAK→起常驻→"
           "内核态读→比对影子；前提：prepare-eptpsw + self-test）\n");
    printf("  selfcheck        使用前自检（只读，不进 VMX）：能力 / 后端可用性 / "
           "状态是否干净，每项都给可操作的解释\n");
    printf("  view-verify      添加后自检：逐条已装视图分别验**结构**（叶是不是"
           "主值）与**生效**（读是否真被重定向），两层分开报\n");
    printf("  ept-leaf <PA>    走一遍基座 EPT，打出四级项与 R/W/X（十六进制地址）\n");
    printf("  events [after]   逐行读事件环（十进制序号，只读大于它的行）\n");
    for (i = 0U; i < sizeof(g_Verbs) / sizeof(g_Verbs[0]); ++i) {
        printf("  %-16s %s\n", g_Verbs[i].name, g_Verbs[i].description);
    }
    printf("\n分级推进，不要跳步：status -> prepare -> self-test -> resident\n");
    printf("退出码：0=协议 OK，2=协议非 OK，1=传输层失败，"
           "3=**空过**（前提没建立，这次什么都没测到）\n");
}

int main(int argc, char** argv)
{
    HANDLE h;
    int rc = 0;
    int asJson = 0;
    int argi = 1;
    unsigned long soakMs = 1000UL;
    const char* cmd = NULL;
    size_t i;

    (void)SetConsoleOutputCP(CP_UTF8);

    if (argi < argc && strcmp(argv[argi], "--json") == 0) {
        asJson = 1;
        ++argi;
    }
    cmd = (argi < argc) ? argv[argi++] : "status";
    if (argi < argc) {
        soakMs = (unsigned long)strtoul(argv[argi], NULL, 10);
    }

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0) {
        PrintUsage();
        return 0;
    }

    h = OpenDevice();
    if (h == INVALID_HANDLE_VALUE) {
        if (asJson) {
            printf("{\"kind\":\"error\",\"reason\":\"device-open-failed\"}\n");
        }
        return 1;
    }

    if (strcmp(cmd, "status") == 0) {
        rc = DoQuery(h, asJson);
    } else if (strcmp(cmd, "probe-xonly") == 0) {
        rc = DoProbeExecuteOnly(h, asJson);
    } else if (strcmp(cmd, "rule-allowonce") == 0) {
        rc = DoRuleAllowOnceGate(h, asJson);
    } else if (strcmp(cmd, "tlb-probe") == 0) {
        rc = DoTlbProbe(h, asJson, soakMs, 0);
    } else if (strcmp(cmd, "tlb-probe-exit") == 0) {
        rc = DoTlbProbe(h, asJson, soakMs, 1);
    } else if (strcmp(cmd, "probe-platform") == 0) {
        rc = DoProbePlatform(h, asJson);
    } else if (strcmp(cmd, "probe-flags") == 0) {
        rc = DoProbeFlags(h, asJson);
    } else if (strcmp(cmd, "view-query") == 0) {
        rc = DoViewQuery(h, asJson);
    } else if (strcmp(cmd, "view-probe") == 0) {
        rc = DoViewProbe(h, asJson);
    } else if (strcmp(cmd, "view-effect") == 0) {
        rc = DoViewEffect(h, asJson);
    } else if (strcmp(cmd, "selfcheck") == 0) {
        rc = DoSelfCheck(h, asJson);
    } else if (strcmp(cmd, "view-verify") == 0) {
        rc = DoViewVerify(h, asJson);
    } else if (strcmp(cmd, "events") == 0) {
        /* 可选参数：只读序号大于它的行。十进制，默认 0 = 环里现存的全部。 */
        unsigned long long after = 0ULL;
        if (argi < argc) {
            after = _strtoui64(argv[argi], NULL, 10);
        }
        rc = DoEvents(h, after, asJson);
    } else if (strcmp(cmd, "ept-leaf") == 0) {
        /* 第二个参数是**十六进制**物理地址（main 里那个 soakMs 按十进制解析，
         * 这里不能复用它）。没给就是 0，会打出 GPA 0 的那一条链。 */
        unsigned long long target = 0ULL;
        if (argi < argc) {
            target = _strtoui64(argv[argi], NULL, 16);
        }
        rc = DoEptLeaf(h, target, asJson);
    } else {
        const HVM_CTL_VERB* verb = NULL;
        for (i = 0U; i < sizeof(g_Verbs) / sizeof(g_Verbs[0]); ++i) {
            if (strcmp(cmd, g_Verbs[i].name) == 0) { verb = &g_Verbs[i]; break; }
        }
        if (verb == NULL) {
            PrintUsage();
            rc = 1;
        } else {
            rc = DoControl(h, verb, soakMs, asJson);
        }
    }

    CloseHandle(h);
    return rc;
}
