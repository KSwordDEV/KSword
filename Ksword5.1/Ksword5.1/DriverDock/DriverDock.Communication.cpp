#include "DriverDock.Internal.h"

// 说明：Issue #47 的通信致盲异步流程独立于强制卸载，避免继续扩大 Operation 聚合文件。
using namespace ksword::driver_dock_internal;

namespace
{
    // driverCommunicationActionText：
    // - 输入：shared 协议 action；
    // - 处理：映射为当前语言下的短动作名；
    // - 返回：未知值保留数值，避免日志丢失诊断。
    QString driverCommunicationActionText(const std::uint32_t action)
    {
        switch (action)
        {
        case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_QUERY:
            return driverText(
                "driver.operation.communication.action.query",
                QStringLiteral("查询 IRP 通信状态"));
        case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_BLIND:
            return driverText(
                "driver.operation.communication.action.blind",
                QStringLiteral("致盲 IRP 通信"));
        case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_RESTORE:
            return driverText(
                "driver.operation.communication.action.restore",
                QStringLiteral("恢复 IRP 通信"));
        default:
            return driverText(
                "driver.operation.communication.action.unknown",
                QStringLiteral("未知动作(%1)"))
                .arg(action);
        }
    }

    // driverCommunicationStateText：
    // - 输入：R0 通信控制状态；
    // - 处理：区分未致盲、活动和第三方改写冲突；
    // - 返回：用于操作日志的本地化文本。
    QString driverCommunicationStateText(const std::uint32_t state)
    {
        switch (state)
        {
        case KSWORD_ARK_DRIVER_COMMUNICATION_STATE_INACTIVE:
            return driverText(
                "driver.operation.communication.state.inactive",
                QStringLiteral("未致盲"));
        case KSWORD_ARK_DRIVER_COMMUNICATION_STATE_ACTIVE:
            return driverText(
                "driver.operation.communication.state.active",
                QStringLiteral("通信已致盲"));
        case KSWORD_ARK_DRIVER_COMMUNICATION_STATE_CONFLICT:
            return driverText(
                "driver.operation.communication.state.conflict",
                QStringLiteral("恢复冲突"));
        default:
            return driverText(
                "driver.operation.communication.state.unknown",
                QStringLiteral("未知状态(%1)"))
                .arg(state);
        }
    }
}

void DriverDock::controlDriverCommunication(
    const std::uint64_t moduleBaseValue,
    const QString& moduleName,
    const QString& driverObjectName,
    const std::uint64_t expectedDriverObjectAddress,
    const bool restoreCommunication)
{
    // 输入：确认弹窗出现前复制的不可变目标身份和动作方向。
    // 处理：致盲要求 canonical 名称与 DriverObject 地址；恢复只依赖 R0 保存的基址记录。
    // 返回：无，后台结果通过 UI 线程写入操作日志。
    const QString moduleNameText = moduleName.trimmed();
    QString driverObjectNameText = driverObjectName.trimmed();
    const bool exactTargetReady =
        !driverObjectNameText.isEmpty() &&
        expectedDriverObjectAddress != 0U;

    if (moduleBaseValue == 0U ||
        (!restoreCommunication && !exactTargetReady))
    {
        appendOperateLogLine(
            driverText(
                "driver.operation.communication.target_unresolved",
                QStringLiteral(
                    "IRP 通信操作已拒绝：需要已解析的 canonical DriverObject、对象地址，且 DriverStart 必须与模块基址一致。")));
        return;
    }
    if (driverObjectNameText.isEmpty())
    {
        driverObjectNameText = moduleNameText;
    }

    const std::uint32_t requestedAction =
        restoreCommunication
        ? KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_RESTORE
        : KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_BLIND;
    appendOperateLogLine(
        driverText(
            "driver.operation.communication.starting",
            QStringLiteral("开始 R0 %1：%2 | DriverObject=%3 | Base=%4"))
            .arg(
                driverCommunicationActionText(requestedAction),
                moduleNameText,
                driverObjectNameText,
                formatCompactAddress(moduleBaseValue)));

    QPointer<DriverDock> guardThis(this);
    const std::wstring canonicalDriverNameWide =
        driverObjectNameText.toStdWString();
    auto* controlTask = QRunnable::create(
        [guardThis,
            moduleNameText,
            moduleBaseValue,
            canonicalDriverNameWide,
            expectedDriverObjectAddress,
            restoreCommunication]()
        {
            const ksword::ark::DriverClient driverClient;
            const ksword::ark::DriverCommunicationControlResult result =
                restoreCommunication
                ? driverClient.restoreDriverCommunication(
                    moduleBaseValue,
                    canonicalDriverNameWide)
                : driverClient.blindDriverCommunication(
                    moduleBaseValue,
                    canonicalDriverNameWide,
                    expectedDriverObjectAddress);

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, moduleNameText, moduleBaseValue, result]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    const QString lastStatusText = result.io.ok
                        ? formatNtStatusText(result.lastStatus)
                        : driverText(
                            "driver.operation.communication.last_status_unavailable",
                            QStringLiteral("<传输失败，R0 状态不可用>"));
                    guardThis->appendOperateLogLine(
                        driverText(
                            "driver.operation.communication.result",
                            QStringLiteral(
                                "IRP 通信操作完成：%1 | Base=%2 | Action=%3 | State=%4 | IO说明=%5 | Last=%6 | Targeted=%7 | Changed=%8 | Active=%9 | Owned=%10 | Conflict=%11 | Generation=%12 | Object=%13 | DriverStart=%14 | Reject=%15 | Name=%16"))
                            .arg(moduleNameText)
                            .arg(formatCompactAddress(moduleBaseValue))
                            .arg(driverCommunicationActionText(result.action))
                            .arg(driverCommunicationStateText(result.state))
                            .arg(describeDriverCollection(result.io))
                            .arg(lastStatusText)
                            .arg(formatHex32(result.targetedMask))
                            .arg(formatHex32(result.changedMask))
                            .arg(formatHex32(result.activeMask))
                            .arg(formatHex32(result.ownedMask))
                            .arg(formatHex32(result.conflictMask))
                            .arg(result.generation)
                            .arg(formatCompactAddress(result.driverObjectAddress))
                            .arg(formatCompactAddress(result.driverStart))
                            .arg(formatCompactAddress(result.rejectDispatchAddress))
                            .arg(QString::fromStdWString(result.driverName)));
                    if ((result.responseFlags &
                        KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE_FLAG_FOREIGN_CHANGE) != 0U)
                    {
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.operation.communication.foreign_change",
                                QStringLiteral(
                                    "恢复检测到第三方 MajorFunction 改写；冲突槽未被覆盖，恢复入口仍可重试。")));
                    }
                    if (result.io.ok)
                    {
                        guardThis->refreshLoadedModuleEvidenceAsync();
                    }
                },
                Qt::QueuedConnection);
        });
    controlTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(controlTask);
}
