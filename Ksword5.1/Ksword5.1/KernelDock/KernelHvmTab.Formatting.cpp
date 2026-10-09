#include "../UI/StructuredFieldView.h"
#include "KernelHvmTab.h"

#include "KernelDock.h"
#include "../UI/HvmControl.h"
#include <QTableWidget>
#include <QTableWidgetItem>
#include "../UI/CodeEditorWidget.h"
#include <QTextEdit>

#include <QStringList>

#include <array>

using ksword::kernel_dock_internal::kernelText;

ks::ui::FieldDocument KernelHvmTab::buildDetail(
    const KSWORD_ARK_QUERY_HVM_RESPONSE& response) const
{
    if (response.backend == KSWORD_ARK_HVM_BACKEND_SVM)
    {
        ks::ui::FieldDocument detail;
        detail.note(QStringLiteral("实验性 AMD SVM / VMCB / NPT"));
        detail.field(QStringLiteral("协议"), QStringLiteral("%1　代次：%2").arg(QStringLiteral("%1").arg(response.version)).arg(QStringLiteral("%1").arg(response.generation)));
        detail.field(QStringLiteral("CPU 准备 / 自检 / 常驻"), QStringLiteral("%1 / %2 / %3").arg(QStringLiteral("%1").arg(response.preparedProcessorCount)).arg(QStringLiteral("%1").arg(response.selfTestPassedProcessorCount)).arg(QStringLiteral("%1").arg(response.residentProcessorCount)));
        detail.field(QStringLiteral("NPT 就绪"), QStringLiteral("%1").arg(response.slatReady));
        detail.field(QStringLiteral("状态"), QStringLiteral("%1").arg(stateText(response.stateFlags)));
        detail.field(QStringLiteral("最近 NTSTATUS"), QStringLiteral("%1").arg(ntStatusText(response.backendStatus)));
        detail.note(QStringLiteral("嵌套 SVM 已接入；内层操作系统启动尚未验收，Intel EPT 扩展不适用。"));
        const QString unavailable = kernelText("kernel.hvm.amd.unavailable", QStringLiteral("暂不可用"));
        const auto raw = [&unavailable](unsigned long mask, unsigned long bit, unsigned long long value) {
            return (mask & bit) ? QStringLiteral("0x%1").arg(value, 0, 16) : unavailable;
        };
        const auto& caps = response.svmCapabilities;
        detail.field(QStringLiteral("SVM / NPT / NRIP"), QStringLiteral("%1 / %2 / %3").arg(QStringLiteral("%1").arg((response.featureFlags & KSWORD_ARK_HVM_FEATURE_SVM) != 0)).arg(QStringLiteral("%1").arg((response.featureFlags & KSWORD_ARK_HVM_FEATURE_NPT) != 0)).arg(QStringLiteral("%1").arg((response.featureFlags & KSWORD_ARK_HVM_FEATURE_SVM_NRIP) != 0)));
        detail.field(QStringLiteral("ASID"), QStringLiteral("%1").arg(response.svmCapabilities.asidCount));
        detail.field(QStringLiteral("物理地址宽度"), QStringLiteral("%1").arg(response.svmCapabilities.physicalBits));
        detail.field(QStringLiteral("准入拒绝代码"), QStringLiteral("%1").arg(response.svmCapabilities.rejectReason));
        detail.field(QStringLiteral("MSR 有效掩码"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(response.svmCapabilities.msrValidMask, 0, 16)));
        detail.field(QStringLiteral("状态有效掩码"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(response.svmCapabilities.stateValidMask, 0, 16)));
        detail.field(QStringLiteral("VM_CR / EFER / HSAVE"), QStringLiteral("%1 / %2 / %3").arg(QStringLiteral("%1").arg(raw(caps.msrValidMask, 1UL, caps.vmCr))).arg(QStringLiteral("%1").arg(raw(caps.msrValidMask, 2UL, caps.efer))).arg(QStringLiteral("%1").arg(raw(caps.msrValidMask, 4UL, caps.hsave))));
        detail.field(QStringLiteral("CR4 / XCR0 / XSS"), QStringLiteral("%1 / %2 / %3").arg(QStringLiteral("%1").arg(raw(caps.stateValidMask, KSWORD_ARK_SVM_VALID_CR4, caps.cr4))).arg(QStringLiteral("%1").arg(raw(caps.stateValidMask, KSWORD_ARK_SVM_VALID_XCR0, caps.xcr0))).arg(QStringLiteral("%1").arg(raw(caps.stateValidMask, KSWORD_ARK_SVM_VALID_XSS, caps.xss))));
        ksword::ark::HvmStatusResult result{};
        result.io.ok = true;
        result.response = response;
        const auto state = ksword::hvm::stateFromStatus(result);
        detail.note(state.detail);
        return detail;
    }
    ks::ui::FieldDocument detail;
    detail.field(QStringLiteral("协议版本"), QStringLiteral("%1").arg(response.version));
    detail.field(QStringLiteral("查询状态"), QStringLiteral("%1").arg(response.queryStatus));
    detail.field(QStringLiteral("生命周期"), QStringLiteral("%1").arg(stateText(response.stateFlags)));
    detail.field(QStringLiteral("代次"), QStringLiteral("%1").arg(response.generation));
    detail.field(QStringLiteral("CPU 能力"), QStringLiteral("%1").arg(featureText(response.featureFlags)));
    detail.field(QStringLiteral("IA32_FEATURE_CONTROL"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(QString::number(response.featureControl, 16).toUpper())));
    detail.field(QStringLiteral("IA32_VMX_BASIC"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(QString::number(response.vmxBasic, 16).toUpper())));
    detail.field(QStringLiteral("IA32_VMX_EPT_VPID_CAP"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(QString::number(response.vmxEptVpidCapabilities, 16).toUpper())));
    detail.field(QStringLiteral("CR0 fixed0/fixed1"), QStringLiteral("0x%1 / 0x%2").arg(QStringLiteral("%1").arg(QString::number(response.cr0Fixed0, 16).toUpper())).arg(QStringLiteral("%1").arg(QString::number(response.cr0Fixed1, 16).toUpper())));
    detail.field(QStringLiteral("CR4 fixed0/fixed1"), QStringLiteral("0x%1 / 0x%2").arg(QStringLiteral("%1").arg(QString::number(response.cr4Fixed0, 16).toUpper())).arg(QStringLiteral("%1").arg(QString::number(response.cr4Fixed1, 16).toUpper())));
    detail.field(QStringLiteral("EPTP"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(QString::number(response.eptPointer, 16).toUpper())));
    detail.field(QStringLiteral("EPT PML4 项 / PDPT 项 / 2MiB 叶"), QStringLiteral("%1 / %2 / %3").arg(QStringLiteral("%1").arg(response.eptPml4Entries)).arg(QStringLiteral("%1").arg(response.eptPdptEntries)).arg(QStringLiteral("%1").arg(response.eptLargePageEntries)));
    detail.field(QStringLiteral("映射 RAM"), QStringLiteral("%1 bytes").arg(QStringLiteral("%1").arg(response.mappedRamBytes)));
    detail.field(QStringLiteral("最高映射物理地址"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(QString::number(
            response.highestMappedPhysicalAddress,
            16).toUpper())));
    detail.field(QStringLiteral("最近 NTSTATUS"), QStringLiteral("%1").arg(ntStatusText(response.lastStatus)));
    detail.field(QStringLiteral("VM-exit 次数"), QStringLiteral("%1").arg(response.vmExitCount));
    detail.field(QStringLiteral("最近退出原因"), QStringLiteral("%1").arg(response.lastExitReason ==
                    KSWORD_ARK_HVM_EXIT_REASON_NONE
                ? QStringLiteral("-")
                : QString::number(response.lastExitReason)));
    detail.field(QStringLiteral("退出 qualification"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(QString::number(
            response.lastExitQualification,
            16).toUpper())));
    detail.field(QStringLiteral("来宾 RIP / RSP"), QStringLiteral("0x%1 / 0x%2").arg(QStringLiteral("%1").arg(QString::number(response.lastGuestRip, 16).toUpper())).arg(QStringLiteral("%1").arg(QString::number(response.lastGuestRsp, 16).toUpper())));
    detail.field(QStringLiteral("退出指令长度"), QStringLiteral("%1").arg(response.lastExitInstructionLength));
    detail.field(QStringLiteral("VM-instruction error"), QStringLiteral("%1").arg(response.lastVmInstructionError));
    detail.field(QStringLiteral("最近启动 CPU"), QStringLiteral("%1").arg(response.lastLaunchProcessorGroup == 0xFFFFU
                ? QStringLiteral("-")
                : QStringLiteral("%1:%2")
                      .arg(response.lastLaunchProcessorGroup)
                      .arg(response.lastLaunchProcessorNumber)));
    detail.field(QStringLiteral("最近启动使用嵌套 VMX"), QStringLiteral("%1").arg(response.lastLaunchWasNested != 0U
                ? kernelText("kernel.hvm.yes.simple", QStringLiteral("是"))
                : kernelText("kernel.hvm.no.simple", QStringLiteral("否"))));
    detail.field(QStringLiteral("边界"), QStringLiteral("一次性来宾仍会在 VMCALL 后 VMCLEAR/VMXOFF。驻留 VMM 仅在 GenuineIntel、完整 VT-x/EPT/INVEPT、无现有 Hypervisor、全 CPU 自检以及电源/处理器拓扑/驱动卸载保护全部通过后开放；离开 S0 前会同步全核 VMXOFF，驻留期间 DriverUnload 被临时移除。AMD 与其它非 Intel CPU 会在驱动端拒绝；未知退出、EPT misconfiguration 和未实现强制退出会 fail-closed 去虚拟化。EPT 恒等映射覆盖 [0, min(CPUID MAXPHYADDR, 本驱动窗口))；实际覆盖到哪里看上面的「最高映射物理地址」，窗口随驱动版本变，这里不写死数字。含已装 RAM 的 1 GiB 窗口按 MTRR 定型并保持 2 MiB 粒度（规则、视图与内存监视都从 2 MiB 叶往下拆）；不含 RAM 的窗口是固件/PCI/ReBAR 一类，统一 UC 并用单个 1 GiB 叶发布——所以「2MiB 叶」这个数不覆盖整个窗口，别拿它乘 2 MiB 对账。MAXPHYADDR 超出窗口时标记 EPT 截断并禁止驻留，报的是「映射窗口不够」而不是「处理器不支持」。严格 EPT 规则只是取证 tripwire：命中后记录并去虚拟化，不注入异常，原访问可能从同一 RIP 在原生模式重试并成功。"), true);
    detail.note(kernelText(
        "kernel.hvm.detail.experimental",
        QStringLiteral(
            "\n\nResident 实现：%1（CPU %2）"
            "\nEPT 实现：%3；规则 %4；事件 %5；丢失 %6；环回 %14；累计 %15"
            "\nNested 实现：%7；状态 %8"
            "\neVMCS 实现：%9；状态 %10；版本 %11；标志 0x%12"
            "\nVP-assist MSR：0x%13"
            "\n\n实验边界：Nested 的 VMXON/VMCS 操作数解码、vmcs02 合并、L2 exit reflection 与 shadow EPT 都已实现并在硬件上验证过；L2 的 MSR 与 I/O 位图按 L1 自己的那份合并并路由，每次进入 L2 重算一遍、不缓存。EPT 的 accessed/dirty 位传播尚未实现；L1 若在 EPT12 指针里请求它，会被**明确拒绝**（VMfailValid，Intel 错误 7），而不是静默降级。eVMCS 仍只按 TLFS 探测来宾分区能力与所有权，未接管 VP-assist 页面或 clean fields，因此不得解释为 active。Resident 的 capability-only 表示生命周期保护已就绪；只有全 CPU rendezvous 成功后才报告 active。"))
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
            16).toUpper())
        // 环回与累计排在最后：QString::arg 按占位符编号消费，与文本位置无关，
        // 插在中间会逼着后面十个占位符全部重编号。
        .arg(response.overwrittenEventCount)
        .arg(response.publishedEventCount));
    return detail;
}

void KernelHvmTab::applyMetrics(ksword::ark::HvmMetricsResult result)
{
    if (m_snapshot.backend != KSWORD_ARK_HVM_BACKEND_SVM) { return; }
    const QString unavailable = kernelText("kernel.hvm.amd.unavailable", QStringLiteral("暂不可用"));
    if (!result.io.ok || !result.response || result.response->backend != KSWORD_ARK_HVM_BACKEND_SVM ||
        result.response->svmProcessorCount != m_snapshot.processorCount)
    {
        { auto document = m_detailEdit->document(); document.note(kernelText("kernel.hvm.amd.metrics_unavailable", QStringLiteral("AMD metrics 暂不可用；未将缺失或不兼容的快照解释为零次退出。"))); m_detailEdit->setDocument(document); };
        return;
    }
    const auto& metrics = *result.response;
    for (unsigned long i = 0; i < metrics.svmProcessorCount; ++i)
    {
        const auto& row = metrics.svmProcessors[i];
        if (row.generation != m_snapshot.generation || row.group != m_snapshot.processors[i].processorGroup ||
            row.number != m_snapshot.processors[i].processorNumber)
        {
            { auto document = m_detailEdit->document(); document.note(kernelText("kernel.hvm.amd.metrics_changed", QStringLiteral("AMD metrics 与状态的代次或处理器集合不同，请刷新；未合并两次运行的证据。"))); m_detailEdit->setDocument(document); };
            return;
        }
    }
    m_cpuTable->setColumnCount(9);
    m_cpuTable->setHorizontalHeaderLabels({
        kernelText("kernel.hvm.cpu.processor", QStringLiteral("处理器")),
        kernelText("kernel.hvm.cpu.vmx_result", QStringLiteral("执行状态")),
        kernelText("kernel.hvm.amd.raw_exit", QStringLiteral("SVM 原始退出码")),
        QStringLiteral("VMCB PA"), QStringLiteral("HSAVE PA"), QStringLiteral("NPT PA"),
        kernelText("kernel.hvm.amd.general", QStringLiteral("嵌套实际启用")),
        kernelText("kernel.hvm.amd.l2_exits", QStringLiteral("L2 硬件退出")),
        kernelText("kernel.hvm.amd.npf", QStringLiteral("NPF / 影子页")) });
    ks::ui::FieldDocument details;
    for (unsigned long i = 0; i < metrics.svmProcessorCount; ++i)
    {
        const auto& cpu = metrics.svmProcessors[i];
        const auto& general = cpu.general;
        const bool rawValid = cpu.valid && cpu.sequence && !(cpu.sequence & 1U);
        const bool generalValid = general.valid && general.sequence && !(general.sequence & 1ULL);
        const auto hex = [](unsigned long long value) { return QStringLiteral("0x%1").arg(value, 0, 16); };
        const QString npf = cpu.hotspots.valid && cpu.hotspots.sequence && !(cpu.hotspots.sequence & 1ULL)
            ? QString::number(cpu.hotspots.levels[1].npf) : unavailable;
        const QStringList cells = {
            QStringLiteral("%1:%2").arg(cpu.group).arg(cpu.number), executionStageText(cpu.stage),
            rawValid ? hex(cpu.exitCode) : unavailable, hex(cpu.vmcbPa), hex(cpu.hsavePa), hex(cpu.nptRootPa),
            generalValid ? QString::number(general.enabled) : unavailable,
            generalValid ? QString::number(general.hardwareExits) : unavailable,
            npf + QStringLiteral(" / ") + (generalValid ? QString::number(general.shadowPages) : unavailable) };
        for (int column = 0; column < cells.size(); ++column)
        {
            m_cpuTable->setItem(static_cast<int>(i), column, new QTableWidgetItem(cells[column]));
        }
        if (generalValid)
        {
            details.field(QStringLiteral("CPU"), QStringLiteral("CPU %1:%2：嵌套 phase/action/GIF：%3/%4/%5").arg(QStringLiteral("%1").arg(cpu.group)).arg(QStringLiteral("%1").arg(cpu.number)).arg(QStringLiteral("%1").arg(general.phase)).arg(QStringLiteral("%1").arg(general.action)).arg(QStringLiteral("%1").arg(general.gif)));
            details.field(QStringLiteral("L2 退出"), QStringLiteral("%1").arg(general.hardwareExits));
            details.field(QStringLiteral("NPF"), QStringLiteral("%1").arg(npf));
            details.field(QStringLiteral("影子页"), QStringLiteral("%1").arg(general.shadowPages));
            details.field(QStringLiteral("NPT 缓存查找 / 命中 / 重置 / 失败"), QStringLiteral("%1 / %2 / %3 / %4").arg(QStringLiteral("%1").arg(general.nptCache.lookups)).arg(QStringLiteral("%1").arg(general.nptCache.hits)).arg(QStringLiteral("%1").arg(general.nptCache.resets)).arg(QStringLiteral("%1").arg(general.nptCache.resetFailures)));
            details.field(QStringLiteral("INVLPGA"), QStringLiteral("%1").arg(general.invlpgaCount));
            details.field(QStringLiteral("epoch"), QStringLiteral("%1").arg(general.shadowEpoch));
        }
    }
    // 新共享控件以纯文本追加证据，不沿用 QTextEdit 的富文本 append 接口。
    { auto document = m_detailEdit->document(); document.nodes += details.nodes; m_detailEdit->setDocument(document); };
}

QString KernelHvmTab::featureText(const std::uint64_t flags)
{
    struct FeatureName
    {
        std::uint64_t flag;
        const char* name;
    };
    static constexpr std::array<FeatureName, 48> names{{
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
        { KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED, "ResidentLifecycleGuarded" },
        { KSWORD_ARK_HVM_FEATURE_MSR_BITMAP, "MsrBitmap" },
        { KSWORD_ARK_HVM_FEATURE_EXIT_EMULATION, "ExitEmulation" },
        { KSWORD_ARK_HVM_FEATURE_RESIDENT_SUSTAINED, "ResidentSustained" },
        { KSWORD_ARK_HVM_FEATURE_AMD, "AMD" },
        { KSWORD_ARK_HVM_FEATURE_SVM, "SVM" },
        { KSWORD_ARK_HVM_FEATURE_NPT, "NPT" },
        { KSWORD_ARK_HVM_FEATURE_SVM_NRIP, "SvmNextRip" },
        { KSWORD_ARK_HVM_FEATURE_SVM_DECODE_ASSISTS, "SvmDecodeAssists" },
        { KSWORD_ARK_HVM_FEATURE_SVM_FLUSH_BY_ASID, "SvmFlushByAsid" },
        { KSWORD_ARK_HVM_FEATURE_SVM_FIRMWARE_DISABLED, "SvmFirmwareDisabled" },
        { KSWORD_ARK_HVM_FEATURE_NESTED_SVM_DISPATCH, "NestedSvmDispatch" },
        { KSWORD_ARK_HVM_FEATURE_NESTED_SVM_PREPARED, "NestedSvmPrepared" },
        { KSWORD_ARK_HVM_FEATURE_NESTED_SVM_ARMED, "NestedSvmArmed" },
        { KSWORD_ARK_HVM_FEATURE_NESTED_VMX_ARMED, "NestedVmxArmed" },
        { KSWORD_ARK_HVM_FEATURE_HYPERVISOR_IDENTITY_HIDDEN, "HypervisorIdentityHidden" }
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

/*
 * 把嵌套阶梯的当前档位翻成人话。
 *
 * 这个字段一直在查询响应里，界面上却一个字都没有——嵌套跑到哪一步，只有
 * 命令行工具看得见。于是"我按了启动常驻，嵌套到底开没开"这个问题，在图形
 * 界面里**无法回答**，而它恰恰是这个功能唯一需要天天看的读数。
 *
 * 阶梯是单调的，但**不是持久的**：L2_ACTIVE 只在 L2 真正在跑的那一瞬成立，
 * 下一次 VMXOFF 就退回 DISPATCH_READY。所以一次轮询读到 DISPATCH_READY，
 * 说明的是"这一刻没在跑 L2"，不是"从来没跑起来过"——后者要看那个单调计数。
 */
QString KernelHvmTab::nestedStateText(const std::uint32_t state)
{
    switch (state)
    {
    case KSWORD_ARK_HVM_NESTED_STATE_DISABLED:
        return kernelText(
            "kernel.hvm.nested.state.disabled",
            QStringLiteral("未启用（VMX 指令注 #UD）"));
    case KSWORD_ARK_HVM_NESTED_STATE_CAPABILITY_ONLY:
        return kernelText(
            "kernel.hvm.nested.state.capability_only",
            QStringLiteral("仅能力位"));
    case KSWORD_ARK_HVM_NESTED_STATE_DISPATCH_READY:
        return kernelText(
            "kernel.hvm.nested.state.dispatch_ready",
            QStringLiteral("已就绪，等待来宾 VMXON"));
    case KSWORD_ARK_HVM_NESTED_STATE_L1_VMXON:
        return kernelText(
            "kernel.hvm.nested.state.l1_vmxon",
            QStringLiteral("来宾已 VMXON"));
    case KSWORD_ARK_HVM_NESTED_STATE_VMCS12_CURRENT:
        return kernelText(
            "kernel.hvm.nested.state.vmcs12_current",
            QStringLiteral("来宾已载入 vmcs12"));
    case KSWORD_ARK_HVM_NESTED_STATE_L2_PARTIAL:
        return kernelText(
            "kernel.hvm.nested.state.l2_partial",
            QStringLiteral("L2 进入被拒"));
    case KSWORD_ARK_HVM_NESTED_STATE_L2_ACTIVE:
        return kernelText(
            "kernel.hvm.nested.state.l2_active",
            QStringLiteral("L2 正在运行"));
    default:
        return kernelText(
            "kernel.hvm.nested.state.unknown",
            QStringLiteral("未知"));
    }
}

QString KernelHvmTab::executionStageText(const std::uint32_t stage)
{
    switch (stage)
    {
    case KSWORD_ARK_HVM_STAGE_NONE:
        return kernelText("kernel.hvm.stage.none", QStringLiteral("未执行"));
    case KSWORD_ARK_HVM_STAGE_PREPARED:
        return kernelText("kernel.hvm.stage.prepared", QStringLiteral("已准备"));
    case KSWORD_ARK_HVM_STAGE_TESTED:
        return kernelText("kernel.hvm.stage.tested", QStringLiteral("自检完成"));
    case KSWORD_ARK_HVM_STAGE_ENTERING:
        return kernelText("kernel.hvm.stage.entering", QStringLiteral("正在进入"));
    case KSWORD_ARK_HVM_STAGE_ENTERED:
        return kernelText("kernel.hvm.stage.entered", QStringLiteral("已进入来宾"));
    case KSWORD_ARK_HVM_STAGE_EXIT:
        return kernelText("kernel.hvm.stage.exit", QStringLiteral("已从来宾退出"));
    case KSWORD_ARK_HVM_STAGE_STOPPED:
        return kernelText("kernel.hvm.stage.stopped", QStringLiteral("已停止"));
    case KSWORD_ARK_HVM_STAGE_FAILED:
        return kernelText("kernel.hvm.stage.failed", QStringLiteral("失败"));
    default:
        break;
    }
    // 不把未知序号折成"未知"：新驱动加了阶段而界面还没跟上时，那个数字是
    // 唯一能把现象对回驱动改动的线索，折掉它等于把排查起点删了。
    return kernelText("kernel.hvm.stage.unknown", QStringLiteral("未知阶段（%1）"))
        .arg(stage);
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
