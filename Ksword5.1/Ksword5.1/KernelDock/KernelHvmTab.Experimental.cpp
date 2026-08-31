#include "KernelHvmTab.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"

#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
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
        QString normalized = text.trimmed();
        bool ok = false;

        if (normalized.startsWith(
                QStringLiteral("0x"),
                Qt::CaseInsensitive))
        {
            normalized.remove(0, 2);
            value = normalized.toULongLong(&ok, 16);
        }
        else
        {
            value = normalized.toULongLong(&ok, 16);
        }
        return ok && (value & 0xFFFULL) == 0ULL;
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
    const bool nestedPartial =
        m_featureArea == FeatureArea::NestedVmx;
    QString warning = kernelText(
        "kernel.hvm.resident.start.warning",
        QStringLiteral(
            "常驻 VMM 会让所有已准备 CPU 进入 VMX non-root，并持续拦截受支持的退出。驱动仅在 GenuineIntel、VT-x/EPT/INVEPT 完整、无现有 Hypervisor、全 CPU 自检通过且电源/处理器拓扑/驱动卸载保护均已就绪时允许启动；AMD 及其它非 Intel 设备会被驱动端拒绝。驻留期间驱动不可卸载；S3/S4/Modern Standby 等离开 S0 的转换会先同步停止所有 VCPU。VMX/EPT 或回滚异常仍可能导致蓝屏或必须重启。"));
    if (nestedPartial)
    {
        warning += kernelText(
            "kernel.hvm.resident.start.nested_partial",
            QStringLiteral(
                "\n本次还会暴露实验性 Nested VMX 指令分派，但仅实现 VMfail "
                "失败语义；不会成功 VMXON、不会进入 L2，也没有完整 vmcs02/"
                "exit reflection/shadow EPT。"));
    }
    if (confirmTyped(
            warning,
            kernelText("kernel.hvm.resident.start", QStringLiteral("启动驻留 VMM"))))
    {
        runControlAsync(
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
            true,
            true,
            nestedPartial,
            false);
    }
}

void KernelHvmTab::stopResident()
{
    const QString warning = kernelText(
        "kernel.hvm.resident.stop.warning",
        QStringLiteral(
            "停止操作会在每个仍驻留的 CPU 上发出私有 VMCALL，执行 VMCLEAR、"
            "VMXOFF 并恢复启动前 CR4。若任何 CPU 无法完成，驱动会保留"
            "rollback-required 状态和宿主栈，不能假装已经安全停止。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.resident.stop", QStringLiteral("停止驻留 VMM"))))
    {
        runControlAsync(
            KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
            false);
    }
}

void KernelHvmTab::validateNested()
{
    const QString warning = kernelText(
        "kernel.hvm.nested.validate.warning",
        QStringLiteral(
            "该检查只启用并报告实验性 Nested VMX partial 分派。VMXON、"
            "VMPTRLD、VMREAD/VMWRITE 等需要操作数解码的指令当前返回 "
            "VMfailInvalid；VMLAUNCH/VMRESUME 不会运行 L2。继续仅表示接受"
            "能力探测和失败语义验证，不代表存在可用嵌套虚拟机。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.nested.validate", QStringLiteral("验证 Nested VMX（partial）"))))
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
            QStringLiteral("物理起始地址（十六进制，必须 4 KiB 对齐）：")),
        QLineEdit::Normal,
        QStringLiteral("0x0"),
        &accepted);
    if (!accepted)
    {
        return;
    }

    std::uint64_t physicalAddress = 0;
    if (!parsePhysicalAddress(addressText, physicalAddress))
    {
        QMessageBox::critical(
            this,
            kernelText(
                "kernel.hvm.ept.add.title",
                QStringLiteral("添加 EPT 物理页规则")),
            kernelText(
                "kernel.hvm.ept.address.invalid",
                QStringLiteral("地址必须是有效十六进制数并按 4 KiB 对齐。")));
        return;
    }

    const int pageCount = QInputDialog::getInt(
        this,
        kernelText(
            "kernel.hvm.ept.pages.title",
            QStringLiteral("EPT 范围")),
        kernelText(
            "kernel.hvm.ept.pages.prompt",
            QStringLiteral("连续 4 KiB 页数：")),
        1,
        1,
        1048576,
        1,
        &accepted);
    if (!accepted)
    {
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

    const QString warning = kernelText(
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
    m_detailEdit->setPlainText(lines.join(QLatin1Char('\n')));
    m_statusLabel->setText(
        kernelText(
            "kernel.hvm.status.events_ready",
            QStringLiteral("状态：事件已读取")));
    updateButtons();
}
