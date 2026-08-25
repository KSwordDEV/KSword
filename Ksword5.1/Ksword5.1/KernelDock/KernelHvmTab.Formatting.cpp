#include "KernelHvmTab.h"

#include "KernelDock.h"

#include <QStringList>

#include <array>

using ksword::kernel_dock_internal::kernelText;

QString KernelHvmTab::buildDetail(
    const KSWORD_ARK_QUERY_HVM_RESPONSE& response) const
{
    QString detail = kernelText(
        "kernel.hvm.detail",
        QStringLiteral(
            "协议版本：%1\n"
            "查询状态：%2\n"
            "生命周期：%3\n"
            "代次：%4\n"
            "CPU 能力：%5\n"
            "IA32_FEATURE_CONTROL：0x%6\n"
            "IA32_VMX_BASIC：0x%7\n"
            "IA32_VMX_EPT_VPID_CAP：0x%8\n"
            "CR0 fixed0/fixed1：0x%9 / 0x%10\n"
            "CR4 fixed0/fixed1：0x%11 / 0x%12\n"
            "EPTP：0x%13\n"
            "EPT PML4/PDPT/2MiB leaf：%14 / %15 / %16\n"
            "映射 RAM：%17 bytes\n"
            "最高映射物理地址：0x%18\n"
            "最近 NTSTATUS：%19\n"
            "VM-exit 次数：%20\n"
            "最近退出原因：%21\n"
            "退出 qualification：0x%22\n"
            "来宾 RIP / RSP：0x%23 / 0x%24\n"
            "退出指令长度：%25\n"
            "VM-instruction error：%26\n"
            "最近启动 CPU：%27\n"
            "最近启动使用嵌套 VMX：%28\n\n"
            "边界：一次性来宾仍会在 VMCALL 后 VMCLEAR/VMXOFF。驻留 VMM 仅在 GenuineIntel、完整 VT-x/EPT/INVEPT、无现有 Hypervisor、全 CPU 自检以及电源/处理器拓扑/驱动卸载保护全部通过后开放；离开 S0 前会同步全核 VMXOFF，驻留期间 DriverUnload 被临时移除。AMD 与其它非 Intel CPU 会在驱动端拒绝；"
            "未知退出、EPT misconfiguration 和未实现强制退出会 fail-closed 去虚拟化。"
            "EPT 恒等映射覆盖 [0, min(CPUID MAXPHYADDR, 8 TiB))，"
            "RAM 叶按 MTRR 定型，固件、PCI/ReBAR 与其它物理空洞保守使用 UC；"
            "MAXPHYADDR 超出 8 TiB 时会标记 EPT 截断并禁止驻留。"
            "严格 EPT 规则只是取证 tripwire：命中后记录并去虚拟化，不注入异常，"
            "原访问可能从同一 RIP 在原生模式重试并成功。"))
        .arg(response.version)
        .arg(response.queryStatus)
        .arg(stateText(response.stateFlags))
        .arg(response.generation)
        .arg(featureText(response.featureFlags))
        .arg(QString::number(response.featureControl, 16).toUpper())
        .arg(QString::number(response.vmxBasic, 16).toUpper())
        .arg(QString::number(response.vmxEptVpidCapabilities, 16).toUpper())
        .arg(QString::number(response.cr0Fixed0, 16).toUpper())
        .arg(QString::number(response.cr0Fixed1, 16).toUpper())
        .arg(QString::number(response.cr4Fixed0, 16).toUpper())
        .arg(QString::number(response.cr4Fixed1, 16).toUpper())
        .arg(QString::number(response.eptPointer, 16).toUpper())
        .arg(response.eptPml4Entries)
        .arg(response.eptPdptEntries)
        .arg(response.eptLargePageEntries)
        .arg(response.mappedRamBytes)
        .arg(QString::number(
            response.highestMappedPhysicalAddress,
            16).toUpper())
        .arg(ntStatusText(response.lastStatus))
        .arg(response.vmExitCount)
        .arg(
            response.lastExitReason ==
                    KSWORD_ARK_HVM_EXIT_REASON_NONE
                ? QStringLiteral("-")
                : QString::number(response.lastExitReason))
        .arg(QString::number(
            response.lastExitQualification,
            16).toUpper())
        .arg(QString::number(response.lastGuestRip, 16).toUpper())
        .arg(QString::number(response.lastGuestRsp, 16).toUpper())
        .arg(response.lastExitInstructionLength)
        .arg(response.lastVmInstructionError)
        .arg(
            response.lastLaunchProcessorGroup == 0xFFFFU
                ? QStringLiteral("-")
                : QStringLiteral("%1:%2")
                      .arg(response.lastLaunchProcessorGroup)
                      .arg(response.lastLaunchProcessorNumber))
        .arg(
            response.lastLaunchWasNested != 0U
                ? kernelText("kernel.hvm.yes.simple", QStringLiteral("是"))
                : kernelText("kernel.hvm.no.simple", QStringLiteral("否")));
    detail += kernelText(
        "kernel.hvm.detail.experimental",
        QStringLiteral(
            "\n\nResident 实现：%1（CPU %2）"
            "\nEPT 实现：%3；规则 %4；事件 %5；丢弃 %6"
            "\nNested 实现：%7；状态 %8"
            "\neVMCS 实现：%9；状态 %10；版本 %11；标志 0x%12"
            "\nVP-assist MSR：0x%13"
            "\n\n实验边界：Nested 的 VMXON/VMCS 操作数解码、完整 vmcs02、"
            "L2 exit reflection 与 shadow EPT 尚未完成；当前仅提供失败语义的"
            " partial 指令分派。eVMCS 仅按 TLFS 探测来宾分区能力与所有权，"
            "未接管 VP-assist 页面或 clean fields，因此二者均不得解释为 active。Resident 的 capability-only 表示生命周期保护已就绪；只有全 CPU rendezvous 成功后才报告 active。"))
        .arg(implementationText(
            response.residentImplementation))
        .arg(response.residentProcessorCount)
        .arg(implementationText(
            response.eptImplementation))
        .arg(response.eptRuleCount)
        .arg(response.eventCount)
        .arg(response.droppedEventCount)
        .arg(implementationText(
            response.nestedImplementation))
        .arg(response.nestedState)
        .arg(implementationText(
            response.evmcsImplementation))
        .arg(response.evmcsState)
        .arg(response.evmcsVersion)
        .arg(QString::number(response.evmcsFlags, 16).toUpper())
        .arg(QString::number(
            response.evmcsVpAssistMsr,
            16).toUpper());
    return detail;
}

QString KernelHvmTab::featureText(const std::uint64_t flags)
{
    struct FeatureName
    {
        std::uint64_t flag;
        const char* name;
    };
    static constexpr std::array<FeatureName, 33> names{{
        { KSWORD_ARK_HVM_FEATURE_INTEL, "Intel" },
        { KSWORD_ARK_HVM_FEATURE_VMX, "VMX" },
        { KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED, "FeatureControlLocked" },
        { KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX, "VmxOutsideSmx" },
        { KSWORD_ARK_HVM_FEATURE_TRUE_CONTROLS, "TrueControls" },
        { KSWORD_ARK_HVM_FEATURE_EPT, "EPT" },
        { KSWORD_ARK_HVM_FEATURE_EPT_WB, "EPT-WB" },
        { KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL, "EPT-4Level" },
        { KSWORD_ARK_HVM_FEATURE_EPT_2MB, "EPT-2MiB" },
        { KSWORD_ARK_HVM_FEATURE_EPT_AD, "EPT-A/D" },
        { KSWORD_ARK_HVM_FEATURE_INVEPT, "INVEPT" },
        { KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE, "INVEPT-Single" },
        { KSWORD_ARK_HVM_FEATURE_INVEPT_ALL, "INVEPT-All" },
        { KSWORD_ARK_HVM_FEATURE_VPID, "VPID" },
        { KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT, "HypervisorPresent" },
        { KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED, "NestedVmxExposed" },
        { KSWORD_ARK_HVM_FEATURE_ONE_SHOT_GUEST, "OneShotGuest" },
        { KSWORD_ARK_HVM_FEATURE_VMEXIT_TELEMETRY, "VmExitTelemetry" },
        { KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM, "ResidentVmm" },
        { KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS, "MulticoreRendezvous" },
        { KSWORD_ARK_HVM_FEATURE_EPT_4KB_SPLIT, "Ept4KiBSplit" },
        { KSWORD_ARK_HVM_FEATURE_EPT_RULES, "EptRules" },
        { KSWORD_ARK_HVM_FEATURE_EPT_EVENT_RING, "EptEventRing" },
        { KSWORD_ARK_HVM_FEATURE_MTRR_AWARE_EPT, "MtrrAwareEpt" },
        { KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG, "MonitorTrapFlag" },
        { KSWORD_ARK_HVM_FEATURE_NESTED_VMX_DISPATCH, "NestedVmxPartialDispatch" },
        { KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_CAPABLE, "HyperVEvmcsCapable" },
        { KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_V1, "HyperVEvmcsV1" },
        { KSWORD_ARK_HVM_FEATURE_VMX_INSTRUCTION_EMULATION, "VmxFailureSemantics" },
        { KSWORD_ARK_HVM_FEATURE_POWER_STATE_GUARD, "PowerStateGuard" },
        { KSWORD_ARK_HVM_FEATURE_PROCESSOR_TOPOLOGY_GUARD, "ProcessorTopologyGuard" },
        { KSWORD_ARK_HVM_FEATURE_DRIVER_UNLOAD_GUARD, "DriverUnloadGuard" },
        { KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED, "ResidentLifecycleGuarded" }
    }};
    QStringList values;
    for (const auto& value : names)
    {
        if ((flags & value.flag) != 0ULL)
        {
            values.push_back(QString::fromLatin1(value.name));
        }
    }
    return values.isEmpty() ? QStringLiteral("-") : values.join(QStringLiteral(", "));
}

QString KernelHvmTab::stateText(const std::uint32_t flags)
{
    QStringList values;
    if ((flags & KSWORD_ARK_HVM_STATE_INITIALIZED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.initialized", QStringLiteral("已初始化")));
    if ((flags & KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0U)
        values.push_back(kernelText("kernel.hvm.state.resources", QStringLiteral("资源已准备")));
    if ((flags & KSWORD_ARK_HVM_STATE_EPT_READY) != 0U)
        values.push_back(kernelText("kernel.hvm.state.ept", QStringLiteral("EPT 已准备")));
    if ((flags & KSWORD_ARK_HVM_STATE_SELF_TESTED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.tested", QStringLiteral("已自检")));
    if ((flags & KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.passed", QStringLiteral("自检通过")));
    if ((flags & KSWORD_ARK_HVM_STATE_BUSY) != 0U)
        values.push_back(kernelText("kernel.hvm.state.busy", QStringLiteral("操作中")));
    if ((flags & KSWORD_ARK_HVM_STATE_FAULTED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.faulted", QStringLiteral("存在失败")));
    if ((flags & KSWORD_ARK_HVM_STATE_EPT_TRUNCATED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.truncated", QStringLiteral("EPT 映射已截断")));
    if ((flags & KSWORD_ARK_HVM_STATE_GUEST_READY) != 0U)
        values.push_back(kernelText("kernel.hvm.state.guest_ready", QStringLiteral("来宾可启动")));
    if ((flags & KSWORD_ARK_HVM_STATE_GUEST_RUNNING) != 0U)
        values.push_back(kernelText("kernel.hvm.state.guest_running", QStringLiteral("来宾运行中")));
    if ((flags & KSWORD_ARK_HVM_STATE_GUEST_EXITED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.guest_exited", QStringLiteral("来宾已退出")));
    if ((flags & KSWORD_ARK_HVM_STATE_NESTED_ACTIVE) != 0U)
        values.push_back(kernelText("kernel.hvm.state.nested_active", QStringLiteral("嵌套 VMX 活动")));
    if ((flags & KSWORD_ARK_HVM_STATE_NESTED_VALIDATED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.nested_validated", QStringLiteral("一次性嵌套来宾已验证")));
    if ((flags & KSWORD_ARK_HVM_STATE_RESIDENT_STARTING) != 0U)
        values.push_back(kernelText("kernel.hvm.state.resident_starting", QStringLiteral("驻留启动中")));
    if ((flags & KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE) != 0U)
        values.push_back(kernelText("kernel.hvm.state.resident_active", QStringLiteral("驻留 active")));
    if ((flags & KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING) != 0U)
        values.push_back(kernelText("kernel.hvm.state.resident_stopping", QStringLiteral("驻留停止中")));
    if ((flags & KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE) != 0U)
        values.push_back(kernelText("kernel.hvm.state.ept_rules", QStringLiteral("EPT 规则活动")));
    if ((flags & KSWORD_ARK_HVM_STATE_EVENTS_AVAILABLE) != 0U)
        values.push_back(kernelText("kernel.hvm.state.events", QStringLiteral("存在事件")));
    if ((flags & KSWORD_ARK_HVM_STATE_NESTED_PARTIAL) != 0U)
        values.push_back(kernelText("kernel.hvm.state.nested_partial", QStringLiteral("Nested partial")));
    if ((flags & KSWORD_ARK_HVM_STATE_EVMCS_PARTIAL) != 0U)
        values.push_back(kernelText("kernel.hvm.state.evmcs_partial", QStringLiteral("eVMCS partial")));
    if ((flags & KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.rollback", QStringLiteral("需要回滚")));
    if ((flags & KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING) != 0U)
        values.push_back(kernelText("kernel.hvm.state.power_transition", QStringLiteral("电源转换中")));
    if ((flags & KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.unload_guard", QStringLiteral("驱动卸载已锁定")));
    return values.isEmpty() ? QStringLiteral("-") : values.join(QStringLiteral(" / "));
}

QString KernelHvmTab::implementationText(
    const std::uint32_t implementation)
{
    switch (implementation)
    {
    case KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED:
        return kernelText(
            "kernel.hvm.implementation.unsupported",
            QStringLiteral("unsupported"));
    case KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY:
        return kernelText(
            "kernel.hvm.implementation.capability_only",
            QStringLiteral("capability-only"));
    case KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL:
        return kernelText(
            "kernel.hvm.implementation.partial",
            QStringLiteral("partial"));
    case KSWORD_ARK_HVM_IMPLEMENTATION_ACTIVE:
        return kernelText(
            "kernel.hvm.implementation.active",
            QStringLiteral("active"));
    default:
        return kernelText(
            "kernel.hvm.implementation.unknown",
            QStringLiteral("unknown"));
    }
}

QString KernelHvmTab::ntStatusText(const long status)
{
    return QStringLiteral("0x%1")
        .arg(
            static_cast<quint32>(status),
            8,
            16,
            QLatin1Char('0'))
        .toUpper();
}

QString KernelHvmTab::fixedAscii(const char* text, const int capacity)
{
    if (text == nullptr || capacity <= 0)
    {
        return {};
    }
    int length = 0;
    while (length < capacity && text[length] != '\0')
    {
        ++length;
    }
    return QString::fromLatin1(text, length);
}
