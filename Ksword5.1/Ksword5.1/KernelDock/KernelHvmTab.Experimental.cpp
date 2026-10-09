#include "KernelHvmTab.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
// isNestedDispatchEnabled：嵌套派发开关的权威来源，与虚拟化菜单同一处。
#include "../UI/HvmControl.h"
#include "../../../shared/evidence/MemoryAddressInput.h"

#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include "../UI/CodeEditorWidget.h"
#include <QStringList>
#include <QTextEdit>

#include <algorithm>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    bool parsePhysicalAddress(
        const QString& text,
        std::uint64_t& value)
    {
        const QByteArray normalized = text.trimmed().toLatin1();
        return Ksword::Evidence::ParseHexAddress(
            std::string_view(normalized.constData(), static_cast<std::size_t>(normalized.size())), value);
    }

    QString eventTypeText(const unsigned long type)
    {
        switch (type)
        {
        case KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT:
            return QStringLiteral("VM-exit");
        case KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION:
            return QStringLiteral("EPT violation");
        case KSWORD_ARK_HVM_EVENT_TYPE_NESTED_VMX:
            return QStringLiteral("Nested VMX");
        case KSWORD_ARK_HVM_EVENT_TYPE_FATAL_EXIT:
            return QStringLiteral("Fatal/fail-closed");
        case KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE:
            return QStringLiteral("Lifecycle");
        default:
            return QStringLiteral("Unknown");
        }
    }
}

void KernelHvmTab::startResident()
{
    /*
     * 嵌套派发这一位取自开关，不再由"当前在哪个功能页"决定。
     *
     * 原先它是 `m_featureArea == FeatureArea::NestedVmx`，于是这一位既没有开
     * 关也关不掉：站在嵌套页上按启动，必然暴露嵌套派发；站在别的页上按，必然
     * 不暴露——哪怕用户明确想要。而 ALLOW_NESTED 在同一条请求上已经改成读
     * ksword::hvm::isNestedAllowed() 了，两位取自两个来源，正是上一轮修掉的
     * 那类分歧的剩下一半。
     *
     * 开关关着时**不静默**：确认框里说清这次不会暴露嵌套，以及开关在哪。反过
     * 来更重要——在非嵌套页上开着开关按启动，确认框同样会说它会暴露。哪边都
     * 不靠"你在哪一页"来猜。
     */
    const bool nestedDispatch = ksword::hvm::isNestedDispatchEnabled();
    const bool onNestedPage =
        m_featureArea == FeatureArea::NestedVmx;
    /*
     * 互斥要在这里也拦一次。
     *
     * 这条路径现在会同时发出私有 EPT 和嵌套派发两位（前者刚补上，见
     * runControlAsync），于是驱动的 STATUS_INVALID_PARAMETER 变得够得着了。
     * 而那条回答只说"请求不合法"，不指是哪一位——菜单那侧已经按方向各拦了
     * 一次，这一侧不拦的话就留下一个绕过去的入口。
     */
    if (m_snapshot.backend == KSWORD_ARK_HVM_BACKEND_VMX && nestedDispatch && ksword::hvm::isLocalEptEnabled())
    {
        QMessageBox::warning(
            this,
            kernelText(
                "kernel.hvm.resident.start.nested_local_ept_title",
                QStringLiteral("嵌套派发与私有 EPT 互斥")),
            kernelText(
                "kernel.hvm.resident.start.nested_local_ept_body",
                QStringLiteral("嵌套要把来宾的 EPT 层次和我们的合成成一个 EPT 指针，而私有 EPT 要给每个处理器各自一份层次，那会让这个合成变成处理器相关的。驱动会拒绝同时请求。请在虚拟化菜单里关掉其中一个。")));
        return;
    }
    QString warning = kernelText(
        "kernel.hvm.resident.start.warning",
        QStringLiteral(
            "全 CPU 自检和生命周期保护通过后，驱动尝试让全部 CPU 进入常驻；任一核失败会回滚已进入的核。AMD SVM/NPT 与嵌套 SVM 仍为实验性，内层系统启动尚未验收。常驻期间驱动不可卸载；无法证明退出完整时保留资源和卸载保护。硬件异常仍可能需要重启。"));
    if (nestedDispatch && !ksword::hvm::isWriteAccessEnabled())
    {
        QMessageBox::warning(this, QStringLiteral("HVM"), ks::i18n::sourceText(QStringLiteral("请先开启允许 R-1 写操作，再启用来宾嵌套。")));
        return;
    }
    if (nestedDispatch && m_snapshot.backend == KSWORD_ARK_HVM_BACKEND_SVM)
    {
        warning += ks::i18n::sourceText(QStringLiteral("\n\n本次使用实验性嵌套 SVM 分派、VMCB 退出反射与 NPT 合成；需要已按嵌套模式准备资源。"));
    }
    else if (nestedDispatch)
    {
        /*
         * 这段文案原先写着"仅实现 VMfail 失败语义；不会成功 VMXON、不会进入
         * L2，也没有完整 vmcs02/exit reflection/shadow EPT" —— 四条现在全是假的。
         *
         * 在一个危险操作的确认框里说错，比不说更糟：它让人以为勾上这一项只是
         * 打开一个恒定失败的桩，于是不会去想"底下真的会跑起一个我看不见的
         * 客户机"。
         */
        warning += kernelText(
            "kernel.hvm.resident.start.nested_enabled",
            QStringLiteral("\n\n本次还会打开 Nested VMX 指令分派。它不再是失败桩：来宾里的驱动可以真的 VMXON、维护自己的 vmcs12、并把 L2 跑起来——退出会先落到我们手上，按所有权决定自己处理还是投递给它；L1 要 EPT 时由影子层次（EPT01 ∘ EPT12）按需合成。也就是说，勾上它之后，这台机器上任何 ring 0 代码都能在你底下起一台虚拟机。关掉它时 VMX 指令会被注 #UD——在 CPUID 不报 VMX 的前提下那是架构正确的行为。L2 的 MSR 与 I/O 拦截按 L1 自己的位图路由：L1 要的退出投递给它，只有我们要的就地服务掉。EPT 的 accessed/dirty 位传播尚未实现；L1 若在 EPT12 指针里请求它，会被**明确拒绝**（VMfailValid，Intel 错误 7），而不是静默降级。"));
    }
    else if (onNestedPage)
    {
        /*
         * 站在嵌套页上而开关关着，是这里唯一会让人误判的组合：页面名字说的
         * 是嵌套，按下去却不暴露嵌套。所以这一句必须出现——不出现的话，用户
         * 事后只会看到状态面板报"未启用"，而没有任何东西说明那是他自己没开。
         */
        warning += kernelText(
            "kernel.hvm.resident.start.nested_disabled",
            QStringLiteral("\n\n注意：本次不会暴露 Nested VMX 指令分派，来宾执行 VMX 指令仍会被注 #UD。这一页的名字是嵌套，但开关不在这里——在虚拟化菜单的「允许来宾嵌套（我们作为宿主）」。"));
    }
    if (confirmTyped(
            warning,
            kernelText("kernel.hvm.resident.start", QStringLiteral("启动驻留 VMM"))))
    {
        runControlAsync(
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
            true,
            m_snapshot.backend != KSWORD_ARK_HVM_BACKEND_SVM,
            nestedDispatch,
            false);
    }
}

void KernelHvmTab::stopResident()
{
    const QString warning = kernelText(
        "kernel.hvm.resident.stop.warning",
        QStringLiteral(
            "在每个仍常驻的 CPU 上发出当前后端的停止请求，恢复 Windows 当前执行状态。任一核无法完成时保留 rollback-required、控制结构、宿主栈和卸载保护。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.resident.stop", QStringLiteral("停止驻留 VMM"))))
    {
        runControlAsync(
            KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
            false);
    }
}

void KernelHvmTab::validateNested()
{
    /*
     * 和 startResident 里那段一样的过期文案，同一种错法。
     *
     * 原文写着"VMXON、VMPTRLD、VMREAD/VMWRITE 等需要操作数解码的指令当前返回
     * VMfailInvalid；VMLAUNCH/VMRESUME 不会运行 L2"，三条现在都不成立——这三
     * 类指令都能成功，L2 也真的会跑。按原文的说法，用户会以为自己点的只是一次
     * 能力探测，结果点出来的是一条真能跑起客户机的路径。
     *
     * 这条命令本身的定位没变：它只探测并报告，不会让常驻带上嵌套派发。那一位
     * 由虚拟化菜单里的开关决定，与这里无关。
     */
    const QString warning = kernelText(
        "kernel.hvm.nested.validate.warning",
        QStringLiteral("该检查探测并报告 Nested VMX 分派能力。分派本身已经不是失败桩：VMXON、VMPTRLD、VMREAD/VMWRITE 都能成功，VMLAUNCH 会真的把 L2 跑起来，退出反射与影子 EPT（EPT01 ∘ EPT12）都已实现。但这条命令只做探测，不会让常驻带上嵌套派发——那一位由虚拟化菜单的「允许来宾嵌套（我们作为宿主）」决定。L2 的 MSR 与 I/O 拦截也已按 L1 自己的位图路由。EPT 的 accessed/dirty 位传播尚未实现；L1 若在 EPT12 指针里请求它，会被**明确拒绝**（VMfailValid，Intel 错误 7），而不是静默降级。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.nested.validate", QStringLiteral("验证 Nested VMX 分派能力"))))
    {
        runControlAsync(
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED,
            true,
            false,
            true,
            false);
    }
}

void KernelHvmTab::validateEvmcs()
{
    const QString warning = kernelText(
        "kernel.hvm.evmcs.validate.warning",
        QStringLiteral(
            "该检查依据 Hyper-V TLFS 的 CPUID 叶 0x4000000A 和 VP-assist MSR "
            "判断 eVMCS v1、根/来宾分区及所有权冲突。当前实现不会替换 "
            "VP-assist 页面、不会维护 clean fields，也不会启动 eVMCS；"
            "结果只能是 unsupported、capability-only 或 partial。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.evmcs.validate", QStringLiteral("验证 Hyper-V eVMCS（partial）"))))
    {
        runControlAsync(
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED,
            true,
            false,
            false,
            true);
    }
}

void KernelHvmTab::addEptRule()
{
    bool accepted = false;
    const QString addressText = QInputDialog::getText(
        this,
        kernelText(
            "kernel.hvm.ept.add.title",
            QStringLiteral("添加 EPT 物理页规则")),
        kernelText(
            "kernel.hvm.ept.address.prompt",
            QStringLiteral("物理起始地址（十六进制，自动取所在 4 KiB 页）：")),
        QLineEdit::Normal,
        QStringLiteral("0x0"),
        &accepted);
    if (!accepted)
    {
        return;
    }

    std::uint64_t physicalAddress = 0;
    constexpr std::uint64_t maxMappedPhysical = 0x400000000000ULL;
    if (!parsePhysicalAddress(addressText, physicalAddress) || physicalAddress >= maxMappedPhysical)
    {
        QMessageBox::critical(
            this,
            kernelText(
                "kernel.hvm.ept.add.title",
                QStringLiteral("添加 EPT 物理页规则")),
            kernelText(
                "kernel.hvm.ept.address.invalid",
                QStringLiteral("地址必须是小于 64 TiB 的有效十六进制数。")));
        return;
    }
    const std::uint64_t requestedAddress = physicalAddress;
    physicalAddress &= ~0xFFFULL;

    const int pageCount = QInputDialog::getInt(
        this,
        kernelText(
            "kernel.hvm.ept.pages.title",
            QStringLiteral("EPT 范围")),
        kernelText(
            "kernel.hvm.ept.pages.prompt",
            QStringLiteral("从地址所在页开始的连续 4 KiB 页数：")),
        1,
        1,
        1048576,
        1,
        &accepted);
    if (!accepted)
    {
        return;
    }

    if (static_cast<std::uint64_t>(pageCount) > (maxMappedPhysical - physicalAddress) / 0x1000ULL)
    {
        QMessageBox::critical(this,
            kernelText("kernel.hvm.ept.add.title", QStringLiteral("添加 EPT 物理页规则")),
            ks::i18n::sourceText(QStringLiteral("规则范围超出 64 TiB 映射上界。")));
        return;
    }

    const QStringList accessChoices{
        kernelText(
            "kernel.hvm.ept.access.write",
            QStringLiteral("移除写权限（写访问触发 tripwire）")),
        kernelText(
            "kernel.hvm.ept.access.execute",
            QStringLiteral("移除执行权限（取指触发 tripwire）")),
        kernelText(
            "kernel.hvm.ept.access.read",
            QStringLiteral(
                "移除读权限（同时移除写；必要时也移除执行）")),
        kernelText(
            "kernel.hvm.ept.access.write_execute",
            QStringLiteral("移除写和执行权限（访问触发 tripwire）")),
        kernelText(
            "kernel.hvm.ept.access.all",
            QStringLiteral("移除读、写和执行权限（访问触发 tripwire）"))
    };
    const QString accessChoice = QInputDialog::getItem(
        this,
        kernelText(
            "kernel.hvm.ept.access.title",
            QStringLiteral("EPT 权限")),
        kernelText(
            "kernel.hvm.ept.access.prompt",
            QStringLiteral("选择要从 EPT 叶中移除的权限：")),
        accessChoices,
        0,
        false,
        &accepted);
    if (!accepted)
    {
        return;
    }

    unsigned long deniedAccess = KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
    if (accessChoice == accessChoices[1])
    {
        deniedAccess = KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
    }
    else if (accessChoice == accessChoices[2])
    {
        deniedAccess = KSWORD_ARK_HVM_EPT_ACCESS_READ;
    }
    else if (accessChoice == accessChoices[3])
    {
        deniedAccess =
            KSWORD_ARK_HVM_EPT_ACCESS_WRITE |
            KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
    }
    else if (accessChoice == accessChoices[4])
    {
        deniedAccess =
            KSWORD_ARK_HVM_EPT_ACCESS_READ |
            KSWORD_ARK_HVM_EPT_ACCESS_WRITE |
            KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
    }

    const QStringList behaviorChoices{
        kernelText(
            "kernel.hvm.ept.behavior.fail_closed",
            QStringLiteral(
                "严格 tripwire：记录并去虚拟化（原访问可能重试）")),
        kernelText(
            "kernel.hvm.ept.behavior.allow_once",
            QStringLiteral(
                "单 VCPU 临时放行一次，并用 MTF + INVEPT 还原"))
    };
    const QString behaviorChoice = QInputDialog::getItem(
        this,
        kernelText(
            "kernel.hvm.ept.behavior.title",
            QStringLiteral("EPT 命中行为")),
        kernelText(
            "kernel.hvm.ept.behavior.prompt",
            QStringLiteral("选择命中规则后的处理方式：")),
        behaviorChoices,
        0,
        false,
        &accepted);
    if (!accepted)
    {
        return;
    }
    const bool allowOnce = behaviorChoice == behaviorChoices[1];

    const QString warning = ks::i18n::sourceText(QStringLiteral(
        "输入地址 0x%1，规则将覆盖物理页范围 [0x%2, 0x%3)，共 %4 页。\n\n"))
        .arg(requestedAddress, 0, 16).arg(physicalAddress, 0, 16)
        .arg(physicalAddress + static_cast<std::uint64_t>(pageCount) * 0x1000ULL, 0, 16)
        .arg(pageCount) + kernelText(
        "kernel.hvm.ept.add.warning",
        QStringLiteral(
            "该操作会把指定物理页对应的 2 MiB EPT 大页拆成 4 KiB 叶并移除"
            "权限。它是取证 tripwire，不是可靠访问控制：严格命中只记录事件并"
            "去虚拟化，不注入异常；CPU 会从同一 RIP 返回原生执行，因此原访问"
            "仍可能重试并成功。读权限不能单独移除而保留写；不支持 execute-only "
            "EPT 时还会同时移除执行。重叠范围中任一严格规则都会覆盖临时放行。"
            "临时放行只允许单 VCPU，并依赖 MTF 与 single-context INVEPT；多 CPU 驻留只能使用严格 tripwire 规则。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.ept.add", QStringLiteral("添加物理页规则..."))))
    {
        runEptRuleAsync(
            KSWORD_ARK_HVM_EPT_RULE_ADD,
            0,
            deniedAccess,
            physicalAddress,
            static_cast<std::uint64_t>(pageCount),
            true,
            allowOnce);
    }
}

void KernelHvmTab::queryEptRule()
{
    bool accepted = false;
    const int ruleId = QInputDialog::getInt(
        this,
        kernelText(
            "kernel.hvm.ept.query.title",
            QStringLiteral("查询 EPT 规则")),
        kernelText(
            "kernel.hvm.ept.rule_id.query",
            QStringLiteral("规则 ID（0 表示第一条活动规则）：")),
        0,
        0,
        2147483647,
        1,
        &accepted);
    if (accepted)
    {
        runEptRuleAsync(
            KSWORD_ARK_HVM_EPT_RULE_QUERY,
            static_cast<unsigned long>(ruleId),
            0,
            0,
            0,
            false,
            false);
    }
}

void KernelHvmTab::removeEptRule()
{
    bool accepted = false;
    const int ruleId = QInputDialog::getInt(
        this,
        kernelText(
            "kernel.hvm.ept.remove.title",
            QStringLiteral("移除 EPT 规则")),
        kernelText(
            "kernel.hvm.ept.rule_id.remove",
            QStringLiteral("要移除的规则 ID：")),
        1,
        1,
        2147483647,
        1,
        &accepted);
    if (!accepted)
    {
        return;
    }
    const QString warning = kernelText(
        "kernel.hvm.ept.remove.warning",
        QStringLiteral(
            "移除会重算该物理范围上的所有重叠 tripwire。为避免 VM-exit 与规则"
            "表/EPT 叶并发，存在任一驻留 CPU 时驱动会返回 DEVICE_BUSY；必须"
            "先完整停止驻留，再修改规则。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.ept.remove", QStringLiteral("移除规则..."))))
    {
        runEptRuleAsync(
            KSWORD_ARK_HVM_EPT_RULE_REMOVE,
            static_cast<unsigned long>(ruleId),
            0,
            0,
            0,
            false,
            false);
    }
}

void KernelHvmTab::clearEptRules()
{
    const QString warning = kernelText(
        "kernel.hvm.ept.clear.warning",
        QStringLiteral(
            "清空会恢复所有拆分叶的基线权限并删除全部 tripwire。存在任一驻留 "
            "CPU 时驱动会返回 DEVICE_BUSY，不会边运行边修改共享规则或 EPT 叶；"
            "必须先完整停止驻留。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.ept.clear", QStringLiteral("清空全部规则..."))))
    {
        runEptRuleAsync(
            KSWORD_ARK_HVM_EPT_RULE_CLEAR,
            0,
            0,
            0,
            0,
            false,
            false);
    }
}

void KernelHvmTab::queryEvents()
{
    runEventQueryAsync(false);
}

void KernelHvmTab::clearEvents()
{
    const QString warning = kernelText(
        "kernel.hvm.events.clear.warning",
        QStringLiteral(
            "事件环只能在所有驻留 CPU 停止后清空；清空不会改变 EPT 规则，"
            "但会永久丢弃当前保留的 VM-exit 取证记录。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.events.clear", QStringLiteral("清空已停止的事件环..."))))
    {
        runEventQueryAsync(true);
    }
}

void KernelHvmTab::runEptRuleAsync(
    const unsigned long operation,
    const unsigned long ruleId,
    const unsigned long deniedAccess,
    const std::uint64_t physicalAddress,
    const std::uint64_t pageCount,
    const bool log,
    const bool allowOnce)
{
    if (m_operationRunning)
    {
        return;
    }
    m_operationRunning = true;
    m_statusLabel->setText(
        kernelText(
            "kernel.hvm.status.ept_operating",
            QStringLiteral("正在执行 EPT 规则操作...")));
    updateButtons();
    const unsigned long generation =
        operation == KSWORD_ARK_HVM_EPT_RULE_QUERY
            ? 0UL
            : m_snapshot.generation;
    QPointer<KernelHvmTab> safeThis(this);
    std::thread([
        safeThis,
        operation,
        generation,
        ruleId,
        deniedAccess,
        physicalAddress,
        pageCount,
        log,
        allowOnce]() {
        ksword::ark::DriverClient client;
        auto result = client.controlHvmEptRule(
            operation,
            generation,
            ruleId,
            deniedAccess,
            physicalAddress,
            pageCount,
            log,
            allowOnce,
            true);
        auto status = client.queryHvmStatus();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [
                safeThis,
                operation,
                result = std::move(result),
                status = std::move(status)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyEptRule(
                        operation,
                        std::move(result),
                        std::move(status));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelHvmTab::applyEptRule(
    const unsigned long operation,
    ksword::ark::HvmEptRuleResult result,
    ksword::ark::HvmStatusResult status)
{
    m_operationRunning = false;
    if (!result.io.ok ||
        (result.response.status !=
             KSWORD_ARK_HVM_EPT_RULE_STATUS_OK &&
         result.response.status !=
             KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL))
    {
        QMessageBox::critical(
            this,
            kernelText(
                "kernel.hvm.ept.operation.title",
                QStringLiteral("EPT 规则操作")),
            kernelText(
                "kernel.hvm.ept.operation.failed",
                QStringLiteral(
                    "EPT 操作未完成。\n协议状态：%1\nNTSTATUS：%2\n%3"))
                .arg(result.response.status)
                .arg(ntStatusText(result.response.lastStatus))
                .arg(QString::fromStdString(result.io.message)));
    }
    else
    {
        const QString detail = kernelText(
            "kernel.hvm.ept.operation.result",
            QStringLiteral(
                "操作：%1\n结果：%2\n实现：%3\n规则 ID：%4\n"
                "规则总数：%5\n代次：%6\n物理地址：0x%7\n页数：%8\n"
                "有效 tripwire 权限掩码：0x%9\n行为标志：0x%10\n"
                "NTSTATUS：%11\n"
                "严格命中仅记录并去虚拟化；原访问可能在原生模式重试/成功。"))
            .arg(operation)
            .arg(result.response.status ==
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL
                ? QStringLiteral("partial")
                : QStringLiteral("ok"))
            .arg(implementationText(
                result.response.implementation))
            .arg(result.response.ruleId)
            .arg(result.response.ruleCount)
            .arg(result.response.generation)
            .arg(QString::number(
                result.response.physicalAddress,
                16).toUpper())
            .arg(result.response.pageCount)
            .arg(QString::number(
                result.response.deniedAccess,
                16).toUpper())
            .arg(QString::number(
                result.response.flags,
                16).toUpper())
            .arg(ntStatusText(result.response.lastStatus));
        if (result.response.status ==
            KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL)
        {
            QMessageBox::warning(
                this,
                kernelText(
                    "kernel.hvm.ept.operation.title",
                    QStringLiteral("EPT 规则操作")),
                detail);
        }
        else
        {
            QMessageBox::information(
                this,
                kernelText(
                    "kernel.hvm.ept.operation.title",
                    QStringLiteral("EPT 规则操作")),
                detail);
        }
    }
    applyStatus(std::move(status));
}

void KernelHvmTab::runEventQueryAsync(const bool clear)
{
    if (m_operationRunning)
    {
        return;
    }
    m_operationRunning = true;
    m_statusLabel->setText(
        clear
            ? kernelText(
                "kernel.hvm.status.events_clearing",
                QStringLiteral("正在清空已停止的 HVM 事件环..."))
            : kernelText(
                "kernel.hvm.status.events_reading",
                QStringLiteral("正在读取 HVM 事件环...")));
    updateButtons();
    QPointer<KernelHvmTab> safeThis(this);
    std::thread([safeThis, clear]() {
        ksword::ark::DriverClient client;
        auto result = client.queryHvmEvents(
            0,
            KSWORD_ARK_HVM_MAX_EVENT_ROWS,
            clear);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [
                safeThis,
                clear,
                result = std::move(result)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyEvents(
                        clear,
                        std::move(result));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelHvmTab::applyEvents(
    const bool clear,
    ksword::ark::HvmEventResult result)
{
    m_operationRunning = false;
    if (!result.io.ok)
    {
        QMessageBox::critical(
            this,
            kernelText(
                "kernel.hvm.events.title",
                QStringLiteral("HVM 事件")),
            kernelText(
                "kernel.hvm.events.failed",
                QStringLiteral("事件操作失败：%1"))
                .arg(QString::fromStdString(result.io.message)));
        updateButtons();
        return;
    }
    if (clear)
    {
        QMessageBox::information(
            this,
            kernelText(
                "kernel.hvm.events.title",
                QStringLiteral("HVM 事件")),
            kernelText(
                "kernel.hvm.events.cleared",
                QStringLiteral("已清空停止状态下的 HVM 事件环。")));
        refreshAsync();
        return;
    }

    QStringList lines;
    lines.push_back(kernelText(
        "kernel.hvm.events.summary",
        QStringLiteral(
            "返回 %1 / 分配序号范围内可用 %2，覆盖或本快照不可用 %3，"
            "最新序号 %4"))
        .arg(result.response.returnedRows)
        .arg(result.response.availableRows)
        .arg(result.response.droppedRows)
        .arg(result.response.newestSequence));
    const unsigned long rowCount = (std::min)(
        result.response.returnedRows,
        static_cast<unsigned long>(
            KSWORD_ARK_HVM_MAX_EVENT_ROWS));
    for (unsigned long index = 0; index < rowCount; ++index)
    {
        const auto& row = result.response.rows[index];
        lines.push_back(QStringLiteral(
            "#%1  CPU %2:%3  %4  reason=%5  RIP=0x%6  "
            "GPA=0x%7  access=0x%8  rule=%9  status=%10")
            .arg(row.sequence)
            .arg(row.processorGroup)
            .arg(row.processorNumber)
            .arg(eventTypeText(row.type))
            .arg(row.exitReason)
            .arg(QString::number(row.guestRip, 16).toUpper())
            .arg(QString::number(
                row.guestPhysicalAddress,
                16).toUpper())
            .arg(QString::number(row.access, 16).toUpper())
            .arg(row.ruleId)
            .arg(ntStatusText(row.status)));
    }
    m_detailEdit->setReportText(lines.join(QLatin1Char('\n')));
    m_statusLabel->setText(
        kernelText(
            "kernel.hvm.status.events_ready",
            QStringLiteral("状态：事件已读取")));
    updateButtons();
}
