#include "ServiceDock.Internal.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../theme.h"

#include <chrono>
#include <QCoreApplication>
#include <QFileDialog>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRunnable>
#include <QSaveFile>
#include <QSet>
#include <QStringConverter>
#include <QTextStream>
#include <QThreadPool>

#include <Shellapi.h>

using namespace service_dock_detail;

namespace
{
    // kServiceActionTimeoutMs 作用：
    // - 服务启停/暂停动作等待目标状态的最长毫秒数；
    // - 这段轮询等待已经搬到后台线程，UI 线程不再被它阻塞。
    constexpr std::uint32_t kServiceActionTimeoutMs = 6000;

    // pendingServiceOperationKeySet 作用：
    // - 记录“已经派发到后台、尚未回投结果”的服务操作；
    // - ServiceDock.h 不在本次可改范围内，因此这份在途状态收敛到文件级；
    // - 只在 UI 线程读写（派发点与回投点都在 UI 线程），无需额外加锁。
    // 入参：无。
    // 返回：在途操作键集合引用。
    QSet<QString>& pendingServiceOperationKeySet()
    {
        static QSet<QString> pendingKeySet;
        return pendingKeySet;
    }

    // buildServiceOperationKey 作用：为“操作类型 + 服务”生成在途去重键。
    // 入参：operationTagText 为操作标识；serviceNameText 为服务短名。
    // 返回：大小写无关的去重键。
    QString buildServiceOperationKey(const QString& operationTagText, const QString& serviceNameText)
    {
        return operationTagText + QLatin1Char('|') + serviceNameText.trimmed().toLower();
    }

    // buildServiceRegistryPath 作用：生成服务对应注册表路径文本。
    QString buildServiceRegistryPath(const QString& serviceNameText)
    {
        return QStringLiteral("HKLM\\SYSTEM\\CurrentControlSet\\Services\\%1").arg(serviceNameText);
    }

    // openFilePropertiesByPath 作用：打开文件属性对话框。
    bool openFilePropertiesByPath(const QString& filePathText, QString* errorTextOut)
    {
        if (filePathText.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("文件路径为空。");
            }
            return false;
        }

        const HINSTANCE shellResult = ::ShellExecuteW(
            nullptr,
            L"properties",
            reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(filePathText).utf16()),
            nullptr,
            nullptr,
            SW_SHOW);
        if (reinterpret_cast<INT_PTR>(shellResult) <= 32)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("ShellExecute(properties) 失败，返回值=%1")
                    .arg(reinterpret_cast<INT_PTR>(shellResult));
            }
            return false;
        }
        return true;
    }
}



void ServiceDock::showServiceContextMenu(const QPoint& localPos)
{
    if (m_serviceTable == nullptr)
    {
        return;
    }

    QTableWidgetItem* clickedItem = m_serviceTable->itemAt(localPos);
    if (clickedItem == nullptr)
    {
        return;
    }
    if (clickedItem->row() >= 0)
    {
        m_serviceTable->selectRow(clickedItem->row());
    }

    QMenu contextMenu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* refreshAction = contextMenu.addAction(createBlueIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新当前服务"));
    QAction* startAction = contextMenu.addAction(createBlueIcon(":/Icon/process_start.svg"), QStringLiteral("启动服务"));
    QAction* stopAction = contextMenu.addAction(createBlueIcon(":/Icon/process_terminate.svg"), QStringLiteral("停止服务"));
    QAction* pauseAction = contextMenu.addAction(createBlueIcon(":/Icon/process_pause.svg"), QStringLiteral("暂停服务"));
    QAction* continueAction = contextMenu.addAction(createBlueIcon(":/Icon/process_resume.svg"), QStringLiteral("继续服务"));
    contextMenu.addSeparator();
    QAction* deleteServiceAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_clear.svg"),
        QStringLiteral("删除服务"));
    QAction* deleteServiceAndFileAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_clear.svg"),
        QStringLiteral("删除服务并删除其文件"));
    deleteServiceAction->setToolTip(QStringLiteral("删除 SCM 服务注册；SCM 不可见时删除对应注册表服务键"));
    deleteServiceAndFileAction->setToolTip(QStringLiteral("复核停止状态和文件独占引用后，删除服务注册与服务文件"));
    contextMenu.addSeparator();
    QAction* jumpProcessAction = contextMenu.addAction(createBlueIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
    QAction* jumpHandleAction = contextMenu.addAction(createBlueIcon(":/Icon/process_list.svg"), QStringLiteral("跳转句柄筛选"));
    contextMenu.addSeparator();
    QAction* copyNameAction = contextMenu.addAction(createBlueIcon(":/Icon/log_copy.svg"), QStringLiteral("复制服务名"));
    QAction* openRegistryAction = contextMenu.addAction(createBlueIcon(":/Icon/file_find.svg"), QStringLiteral("打开服务注册表位置"));
    QAction* openBinaryLocationAction = contextMenu.addAction(createBlueIcon(":/Icon/process_open_folder.svg"), QStringLiteral("打开 BinaryPath 文件位置"));
    QAction* openServiceDllLocationAction = contextMenu.addAction(createBlueIcon(":/Icon/process_open_folder.svg"), QStringLiteral("打开 ServiceDll 文件位置"));
    QAction* openBinaryPropertiesAction = contextMenu.addAction(createBlueIcon(":/Icon/process_details.svg"), QStringLiteral("查看 BinaryPath 文件属性"));
    QAction* jumpFileDockBinaryAction = contextMenu.addAction(createBlueIcon(":/Icon/file_find.svg"), QStringLiteral("转到 FileDock 分析 BinaryPath"));
    QAction* jumpFileDockServiceDllAction = contextMenu.addAction(createBlueIcon(":/Icon/file_find.svg"), QStringLiteral("转到 FileDock 分析 ServiceDll"));
    contextMenu.addSeparator();
    QAction* exportListAction = contextMenu.addAction(createBlueIcon(":/Icon/log_export.svg"), QStringLiteral("导出当前列表 TSV"));
    QAction* exportServiceJsonAction = contextMenu.addAction(createBlueIcon(":/Icon/log_export.svg"), QStringLiteral("导出当前服务 JSON"));

    startAction->setEnabled(m_startButton != nullptr && m_startButton->isEnabled());
    stopAction->setEnabled(m_stopButton != nullptr && m_stopButton->isEnabled());
    pauseAction->setEnabled(m_pauseButton != nullptr && m_pauseButton->isEnabled());
    continueAction->setEnabled(m_continueButton != nullptr && m_continueButton->isEnabled());
    refreshAction->setEnabled(m_refreshCurrentButton != nullptr && m_refreshCurrentButton->isEnabled());
    copyNameAction->setEnabled(!selectedServiceName().isEmpty());
    const int selectedIndex = findServiceIndexByName(selectedServiceName());
    const bool hasSelectedEntry = selectedIndex >= 0
        && selectedIndex < static_cast<int>(m_serviceList.size());
    deleteServiceAction->setEnabled(hasSelectedEntry);
    deleteServiceAndFileAction->setEnabled(
        hasSelectedEntry
        && !m_serviceList[static_cast<std::size_t>(selectedIndex)].imagePathText.trimmed().isEmpty());
    openRegistryAction->setEnabled(!selectedServiceName().isEmpty());
    jumpProcessAction->setEnabled(!selectedServiceName().isEmpty());
    jumpHandleAction->setEnabled(!selectedServiceName().isEmpty());
    openBinaryLocationAction->setEnabled(!selectedServiceName().isEmpty());
    openServiceDllLocationAction->setEnabled(!selectedServiceName().isEmpty());
    openBinaryPropertiesAction->setEnabled(!selectedServiceName().isEmpty());
    jumpFileDockBinaryAction->setEnabled(!selectedServiceName().isEmpty());
    jumpFileDockServiceDllAction->setEnabled(!selectedServiceName().isEmpty());
    exportListAction->setEnabled(m_serviceTable != nullptr && m_serviceTable->rowCount() > 0);
    exportServiceJsonAction->setEnabled(!selectedServiceName().isEmpty());

    QAction* selectedAction = contextMenu.exec(m_serviceTable->viewport()->mapToGlobal(localPos));
    if (selectedAction == refreshAction)
    {
        refreshSelectedService();
    }
    else if (selectedAction == startAction)
    {
        startSelectedService();
    }
    else if (selectedAction == stopAction)
    {
        stopSelectedService();
    }
    else if (selectedAction == pauseAction)
    {
        pauseSelectedService();
    }
    else if (selectedAction == continueAction)
    {
        continueSelectedService();
    }
    else if (selectedAction == deleteServiceAction)
    {
        deleteSelectedService();
    }
    else if (selectedAction == deleteServiceAndFileAction)
    {
        deleteSelectedServiceAndFile();
    }
    else if (selectedAction == jumpProcessAction)
    {
        jumpToSelectedProcessDetail();
    }
    else if (selectedAction == jumpHandleAction)
    {
        jumpToSelectedHandleFilter();
    }
    else if (selectedAction == copyNameAction)
    {
        copySelectedServiceName();
    }
    else if (selectedAction == openRegistryAction)
    {
        openSelectedServiceRegistryPath();
    }
    else if (selectedAction == openBinaryLocationAction)
    {
        openSelectedBinaryLocation();
    }
    else if (selectedAction == openServiceDllLocationAction)
    {
        openSelectedServiceDllLocation();
    }
    else if (selectedAction == openBinaryPropertiesAction)
    {
        openSelectedBinaryProperties();
    }
    else if (selectedAction == jumpFileDockBinaryAction)
    {
        jumpToFileDockBinaryDetail();
    }
    else if (selectedAction == jumpFileDockServiceDllAction)
    {
        jumpToFileDockServiceDllDetail();
    }
    else if (selectedAction == exportListAction)
    {
        exportCurrentListAsTsv();
    }
    else if (selectedAction == exportServiceJsonAction)
    {
        exportSelectedServiceAsJson();
    }
}

void ServiceDock::refreshSelectedService()
{
    const QString serviceNameText = selectedServiceName();
    if (serviceNameText.isEmpty())
    {
        return;
    }

    // 单条刷新会做 WinVerifyTrust 数字签名校验（目录签名要搜 CatRoot 并哈希文件），
    // 单个文件几十到数百毫秒，必须和全量刷新一样走后台线程。
    const QString operationKeyText = buildServiceOperationKey(QStringLiteral("refresh"), serviceNameText);
    if (pendingServiceOperationKeySet().contains(operationKeyText))
    {
        return;
    }

    const kLogEvent refreshEvent;
    info << refreshEvent
        << "[ServiceDock] 刷新单服务详情, service="
        << serviceNameText.toStdString()
        << eol;

    const int progressPid = kPro.add(this, "服务管理", "刷新单服务详情");
    kPro.set(progressPid, "读取服务配置", 0, 45.0f);
    pendingServiceOperationKeySet().insert(operationKeyText);

    const int selectedIndex = findServiceIndexByName(serviceNameText);
    const bool sourceScmRecordPresent = selectedIndex >= 0
        && selectedIndex < static_cast<int>(m_serviceList.size())
        ? m_serviceList[static_cast<std::size_t>(selectedIndex)].scmRecordPresent
        : true;
    const bool sourceRegistryScanCompleted = selectedIndex >= 0
        && selectedIndex < static_cast<int>(m_serviceList.size())
        ? m_serviceList[static_cast<std::size_t>(selectedIndex)].registryScanCompleted
        : true;

    // guardedSelf 用途：后台采集可能晚于页面销毁，回投前必须验证生命周期。
    const QPointer<ServiceDock> guardedSelf(this);
    QRunnable* const refreshTask = QRunnable::create(
        [guardedSelf,
            serviceNameText,
            operationKeyText,
            progressPid,
            refreshEvent,
            sourceScmRecordPresent,
            sourceRegistryScanCompleted]()
        {
            // 后台只做纯数据采集，产出值类型 ServiceEntry / QString。
            ServiceEntry updatedEntry;
            QString errorText;
            const bool querySucceeded = service_dock_detail::querySingleServiceSnapshot(
                serviceNameText,
                sourceScmRecordPresent,
                sourceRegistryScanCompleted,
                &updatedEntry,
                &errorText);

            QCoreApplication* const appInstance = QCoreApplication::instance();
            if (appInstance == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                appInstance,
                [guardedSelf,
                    serviceNameText,
                    operationKeyText,
                    progressPid,
                    refreshEvent,
                    querySucceeded,
                    updatedEntry,
                    errorText]()
                {
                    // 无论页面是否仍存活，都要先摘掉在途标记，避免残留导致后续刷新被永久拒绝。
                    pendingServiceOperationKeySet().remove(operationKeyText);
                    if (guardedSelf == nullptr)
                    {
                        return;
                    }

                    if (!querySucceeded)
                    {
                        kPro.finish(progressPid, kProgressState::Failure, "刷新失败");
                        err << refreshEvent
                            << "[ServiceDock] 刷新单服务详情失败, service="
                            << serviceNameText.toStdString()
                            << ", error="
                            << errorText.toStdString()
                            << eol;
                        QMessageBox::warning(
                            guardedSelf.data(),
                            QStringLiteral("服务管理"),
                            QStringLiteral("刷新服务详情失败：\n%1").arg(errorText));
                        return;
                    }

                    guardedSelf->applyServiceUpdateToCache(updatedEntry);
                    guardedSelf->rebuildServiceTable();
                    kPro.finish(progressPid, kProgressState::Success, "刷新完成");
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void ServiceDock::startSelectedService()
{
    controlSelectedService(
        SERVICE_START,
        QStringLiteral("启动服务"),
        0,
        true,
        SERVICE_RUNNING,
        false);
}

void ServiceDock::stopSelectedService()
{
    controlSelectedService(
        SERVICE_STOP,
        QStringLiteral("停止服务"),
        SERVICE_CONTROL_STOP,
        false,
        SERVICE_STOPPED,
        true);
}

void ServiceDock::pauseSelectedService()
{
    controlSelectedService(
        SERVICE_PAUSE_CONTINUE,
        QStringLiteral("暂停服务"),
        SERVICE_CONTROL_PAUSE,
        false,
        SERVICE_PAUSED,
        false);
}

void ServiceDock::continueSelectedService()
{
    controlSelectedService(
        SERVICE_PAUSE_CONTINUE,
        QStringLiteral("继续服务"),
        SERVICE_CONTROL_CONTINUE,
        false,
        SERVICE_RUNNING,
        false);
}

bool ServiceDock::controlSelectedService(
    const DWORD desiredAccess,
    const QString& actionText,
    const DWORD controlCode,
    const bool useStartService,
    const DWORD expectedState,
    const bool highRiskAction)
{
    const QString serviceNameText = selectedServiceName();
    if (serviceNameText.isEmpty())
    {
        return false;
    }

    const int selectedIndex = findServiceIndexByName(serviceNameText);
    if (selectedIndex < 0 || selectedIndex >= static_cast<int>(m_serviceList.size()))
    {
        return false;
    }

    const ServiceEntry& selectedEntry = m_serviceList[static_cast<std::size_t>(selectedIndex)];
    if (isServiceStatePending(selectedEntry.currentState))
    {
        QMessageBox::information(
            this,
            QStringLiteral("服务管理"),
            QStringLiteral("当前服务处于状态切换中，请稍后再试。"));
        return false;
    }

    // 控制动作现在异步执行，同一个服务在结果回投前不允许重复下发。
    const QString operationKeyText = buildServiceOperationKey(QStringLiteral("control"), serviceNameText);
    if (pendingServiceOperationKeySet().contains(operationKeyText))
    {
        QMessageBox::information(
            this,
            QStringLiteral("服务管理"),
            QStringLiteral("当前服务处于状态切换中，请稍后再试。"));
        return false;
    }

    if (highRiskAction)
    {
        const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
            this,
            QStringLiteral("高风险动作确认"),
            QStringLiteral("确认执行“%1”？\n\n服务：%2").arg(actionText).arg(serviceNameText),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (confirmButton != QMessageBox::Yes)
        {
            return false;
        }
    }

    const kLogEvent actionEvent;
    info << actionEvent
        << "[ServiceDock] 开始执行服务动作, action="
        << actionText.toStdString()
        << ", service="
        << serviceNameText.toStdString()
        << eol;

    const int progressPid = kPro.add(this, "服务管理", actionText.toStdString() + std::string(" - ") + serviceNameText.toStdString());
    kPro.set(progressPid, "下发服务控制指令", 0, 55.0f);
    pendingServiceOperationKeySet().insert(operationKeyText);

    // 下发期间先把控制按钮置灰，给出“正在执行”的直观反馈；
    // 结果回投时统一用 syncToolbarStateWithSelection() 依据最新状态重算可用性。
    if (m_startButton != nullptr) { m_startButton->setEnabled(false); }
    if (m_stopButton != nullptr) { m_stopButton->setEnabled(false); }
    if (m_pauseButton != nullptr) { m_pauseButton->setEnabled(false); }
    if (m_continueButton != nullptr) { m_continueButton->setEnabled(false); }
    if (m_generalStartButton != nullptr) { m_generalStartButton->setEnabled(false); }
    if (m_generalStopButton != nullptr) { m_generalStopButton->setEnabled(false); }
    if (m_generalPauseButton != nullptr) { m_generalPauseButton->setEnabled(false); }
    if (m_generalContinueButton != nullptr) { m_generalContinueButton->setEnabled(false); }

    // UI layer only selects the action; ks::service owns SCM handles and Start/ControlService calls.
    // ks::service 内部会按 180ms 粒度轮询到期望状态或 kServiceActionTimeoutMs 超时，
    // 停 spooler/WSearch 这类服务经常打满超时，因此整段下发 + 等待都放到后台线程。
    // guardedSelf 用途：后台任务可能晚于页面销毁，回投前必须验证生命周期。
    const QPointer<ServiceDock> guardedSelf(this);
    const std::wstring serviceNameWide = serviceNameText.toStdWString();
    QRunnable* const controlTask = QRunnable::create(
        [guardedSelf,
            serviceNameText,
            serviceNameWide,
            actionText,
            operationKeyText,
            progressPid,
            actionEvent,
            desiredAccess,
            controlCode,
            useStartService,
            expectedState]()
        {
            // 后台只做 SCM 下发与状态轮询，产出值类型结果。
            ks::service::ServiceStatus finalStatus;
            std::string errorText;
            std::uint32_t errorCode = 0;
            const bool actionOk = useStartService
                ? ks::service::StartServiceByName(
                    serviceNameWide,
                    kServiceActionTimeoutMs,
                    expectedState,
                    &finalStatus,
                    &errorText,
                    &errorCode)
                : ks::service::ControlServiceByName(
                    serviceNameWide,
                    desiredAccess,
                    controlCode,
                    kServiceActionTimeoutMs,
                    expectedState,
                    &finalStatus,
                    &errorText,
                    &errorCode);

            const DWORD finalStateValue = static_cast<DWORD>(finalStatus.currentState);

            QCoreApplication* const appInstance = QCoreApplication::instance();
            if (appInstance == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                appInstance,
                [guardedSelf,
                    serviceNameText,
                    actionText,
                    operationKeyText,
                    progressPid,
                    actionEvent,
                    expectedState,
                    actionOk,
                    finalStateValue,
                    errorText,
                    errorCode]()
                {
                    // 无论页面是否仍存活，都要先摘掉在途标记，避免残留导致后续动作被永久拒绝。
                    pendingServiceOperationKeySet().remove(operationKeyText);
                    if (guardedSelf == nullptr)
                    {
                        return;
                    }

                    if (!actionOk)
                    {
                        // privilegePromptHandled：权限恢复提示已展示时不再弹出通用服务失败框。
                        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                            guardedSelf.data(),
                            actionText,
                            errorCode);
                        err << actionEvent
                            << "[ServiceDock] 服务动作执行失败, action="
                            << actionText.toStdString()
                            << ", service="
                            << serviceNameText.toStdString()
                            << ", error="
                            << errorCode
                            << ", detail="
                            << errorText
                            << eol;
                        kPro.finish(progressPid, kProgressState::Failure, "执行失败");
                        guardedSelf->syncToolbarStateWithSelection();
                        if (!privilegePromptHandled)
                        {
                            QMessageBox::warning(
                                guardedSelf.data(),
                                QStringLiteral("服务管理"),
                                QStringLiteral("操作失败：\n%1").arg(QString::fromUtf8(errorText.c_str())));
                        }
                        return;
                    }

                    kPro.set(progressPid, "等待状态稳定", 0, 80.0f);
                    const bool waitOk = (expectedState == 0) || (finalStateValue == expectedState);
                    if (!waitOk)
                    {
                        warn << actionEvent
                            << "[ServiceDock] 服务动作已下发但状态未在超时内到达期望, action="
                            << actionText.toStdString()
                            << ", service="
                            << serviceNameText.toStdString()
                            << ", finalState="
                            << finalStateValue
                            << eol;
                    }
                    else
                    {
                        info << actionEvent
                            << "[ServiceDock] 服务动作执行成功, action="
                            << actionText.toStdString()
                            << ", service="
                            << serviceNameText.toStdString()
                            << eol;
                    }

                    kPro.set(progressPid, "刷新列表", 0, 92.0f);
                    guardedSelf->syncToolbarStateWithSelection();
                    guardedSelf->requestAsyncRefresh(true);
                    kPro.finish(progressPid, kProgressState::Success, "执行完成");
                },
                Qt::QueuedConnection);
        });
    controlTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(controlTask);

    // 返回值语义从“动作已完成”收敛为“动作已受理并派发到后台”。
    return true;
}


void ServiceDock::applySelectedStartType()
{
    const QString serviceNameText = selectedServiceName();
    if (serviceNameText.isEmpty())
    {
        return;
    }

    const int selectedIndex = findServiceIndexByName(serviceNameText);
    if (selectedIndex < 0 || selectedIndex >= static_cast<int>(m_serviceList.size()))
    {
        return;
    }

    const ServiceEntry& selectedEntry = m_serviceList[static_cast<std::size_t>(selectedIndex)];
    if (isServiceStatePending(selectedEntry.currentState))
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务处于过渡态，请稍后再改启动类型。"));
        return;
    }

    const DWORD targetStartType = static_cast<DWORD>(m_startTypeCombo->currentData(Qt::UserRole).toULongLong());
    const bool targetDelayedAutoStart = m_startTypeCombo->currentData(Qt::UserRole + 1).toBool();
    const QString targetStartTypeText = m_startTypeCombo->currentText();

    if (targetStartType == SERVICE_DISABLED)
    {
        const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
            this,
            QStringLiteral("高风险动作确认"),
            QStringLiteral("确认将服务“%1”设置为禁用吗？").arg(serviceNameText),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (confirmButton != QMessageBox::Yes)
        {
            return;
        }
    }

    const kLogEvent changeEvent;
    info << changeEvent
        << "[ServiceDock] 开始修改启动类型, service="
        << serviceNameText.toStdString()
        << ", target="
        << targetStartTypeText.toStdString()
        << eol;

    const int progressPid = kPro.add(this, "服务管理", "修改启动类型");
    kPro.set(progressPid, "写入启动类型", 0, 60.0f);

    ks::service::ServiceConfigUpdate update;
    update.changeStartType = true;
    update.startType = targetStartType;

    std::string errorText;
    std::uint32_t errorCode = 0;
    if (!ks::service::ChangeServiceConfiguration(
        serviceNameText.toStdWString(),
        update,
        &errorText,
        &errorCode))
    {
        // privilegePromptHandled：权限恢复提示已展示时不再弹出通用服务失败框。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("修改服务启动类型"),
            errorCode);
        err << changeEvent
            << "[ServiceDock] 修改启动类型失败, error="
            << errorCode
            << ", detail="
            << errorText
            << eol;
        kPro.finish(progressPid, kProgressState::Failure, "执行失败");
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("服务管理"),
                QStringLiteral("修改启动类型失败：\n%1").arg(QString::fromUtf8(errorText.c_str())));
        }
        return;
    }

    const bool delayedTarget = (targetStartType == SERVICE_AUTO_START && targetDelayedAutoStart);
    std::string delayedErrorText;
    std::uint32_t delayedErrorCode = 0;
    if (!ks::service::SetDelayedAutoStart(
        serviceNameText.toStdWString(),
        delayedTarget,
        &delayedErrorText,
        &delayedErrorCode))
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("修改服务延迟启动"),
            delayedErrorCode);
        warn << changeEvent
            << "[ServiceDock] 设置 DelayedAutoStart 失败，继续后续流程, error="
            << delayedErrorCode
            << ", detail="
            << delayedErrorText
            << eol;
    }

    kPro.set(progressPid, "刷新列表", 0, 90.0f);
    requestAsyncRefresh(true);
    kPro.finish(progressPid, kProgressState::Success, "修改完成");
}


void ServiceDock::copySelectedServiceName()
{
    const QString serviceNameText = selectedServiceName();
    if (serviceNameText.isEmpty())
    {
        return;
    }

    QApplication::clipboard()->setText(serviceNameText);
}

void ServiceDock::openSelectedServiceRegistryPath()
{
    const QString serviceNameText = selectedServiceName();
    if (serviceNameText.isEmpty())
    {
        return;
    }

    const QString registryPathText = buildServiceRegistryPath(serviceNameText);
    QApplication::clipboard()->setText(registryPathText);
    QProcess::startDetached(QStringLiteral("regedit.exe"), {});
    QMessageBox::information(
        this,
        QStringLiteral("服务管理"),
        QStringLiteral("已复制注册表路径到剪贴板：\n%1\n\n并尝试打开 regedit。").arg(registryPathText));
}

void ServiceDock::openSelectedBinaryLocation()
{
    const int selectedIndex = findServiceIndexByName(selectedServiceName());
    if (selectedIndex < 0 || selectedIndex >= static_cast<int>(m_serviceList.size()))
    {
        return;
    }

    const QString filePathText = m_serviceList[static_cast<std::size_t>(selectedIndex)].imagePathText.trimmed();
    if (filePathText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务没有可定位的 BinaryPath 文件。"));
        return;
    }

    QProcess::startDetached(
        QStringLiteral("explorer.exe"),
        { QStringLiteral("/select,%1").arg(QDir::toNativeSeparators(filePathText)) });
}

void ServiceDock::openSelectedServiceDllLocation()
{
    const int selectedIndex = findServiceIndexByName(selectedServiceName());
    if (selectedIndex < 0 || selectedIndex >= static_cast<int>(m_serviceList.size()))
    {
        return;
    }

    const QString filePathText = m_serviceList[static_cast<std::size_t>(selectedIndex)].serviceDllPathText.trimmed();
    if (filePathText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务未配置 ServiceDll。"));
        return;
    }

    QProcess::startDetached(
        QStringLiteral("explorer.exe"),
        { QStringLiteral("/select,%1").arg(QDir::toNativeSeparators(filePathText)) });
}

void ServiceDock::openSelectedBinaryProperties()
{
    const int selectedIndex = findServiceIndexByName(selectedServiceName());
    if (selectedIndex < 0 || selectedIndex >= static_cast<int>(m_serviceList.size()))
    {
        return;
    }

    const QString filePathText = m_serviceList[static_cast<std::size_t>(selectedIndex)].imagePathText.trimmed();
    if (filePathText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务没有可查看属性的 BinaryPath 文件。"));
        return;
    }

    QString errorText;
    if (!openFilePropertiesByPath(filePathText, &errorText))
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("打开文件属性失败：\n%1").arg(errorText));
    }
}

void ServiceDock::jumpToSelectedProcessDetail()
{
    const int selectedIndex = findServiceIndexByName(selectedServiceName());
    if (selectedIndex < 0 || selectedIndex >= static_cast<int>(m_serviceList.size()))
    {
        return;
    }

    const std::uint32_t processIdValue = m_serviceList[static_cast<std::size_t>(selectedIndex)].processId;
    if (processIdValue == 0)
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务没有关联运行中 PID。"));
        return;
    }

    QWidget* mainWindowWidget = window();
    if (mainWindowWidget == nullptr)
    {
        return;
    }

    QMetaObject::invokeMethod(
        mainWindowWidget,
        "openProcessDetailByPid",
        Qt::QueuedConnection,
        Q_ARG(quint32, static_cast<quint32>(processIdValue)));
}

void ServiceDock::jumpToSelectedHandleFilter()
{
    const int selectedIndex = findServiceIndexByName(selectedServiceName());
    if (selectedIndex < 0 || selectedIndex >= static_cast<int>(m_serviceList.size()))
    {
        return;
    }

    const std::uint32_t processIdValue = m_serviceList[static_cast<std::size_t>(selectedIndex)].processId;
    if (processIdValue == 0)
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务没有关联运行中 PID。"));
        return;
    }

    QWidget* mainWindowWidget = window();
    if (mainWindowWidget == nullptr)
    {
        return;
    }

    QMetaObject::invokeMethod(
        mainWindowWidget,
        "focusHandleDockByPid",
        Qt::QueuedConnection,
        Q_ARG(quint32, static_cast<quint32>(processIdValue)));
}

void ServiceDock::exportCurrentListAsTsv()
{
    const QString outputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出服务列表"),
        QStringLiteral("ServiceList.tsv"),
        QStringLiteral("TSV Files (*.tsv);;All Files (*.*)"));
    if (outputPath.trimmed().isEmpty())
    {
        return;
    }

    QSaveFile outputFile(outputPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("打开导出文件失败：\n%1").arg(outputFile.errorString()));
        return;
    }

    QTextStream outputStream(&outputFile);
    outputStream.setEncoding(QStringConverter::Utf8);
    outputStream << "服务名\t显示名\t状态\t启动类型\tPID\t账户\tBinaryPath\tServiceDll\t来源\t风险\n";

    for (int rowIndex = 0; rowIndex < m_serviceTable->rowCount(); ++rowIndex)
    {
        QTableWidgetItem* nameItem = m_serviceTable->item(rowIndex, toServiceColumn(ServiceColumn::Name));
        if (nameItem == nullptr)
        {
            continue;
        }

        const QString serviceNameText = nameItem->data(kServiceNameRole).toString();
        const int serviceIndex = findServiceIndexByName(serviceNameText);
        if (serviceIndex < 0 || serviceIndex >= static_cast<int>(m_serviceList.size()))
        {
            continue;
        }

        const ServiceEntry& entry = m_serviceList[static_cast<std::size_t>(serviceIndex)];
        outputStream
            << entry.serviceNameText << '\t'
            << entry.displayNameText << '\t'
            << entry.stateText << '\t'
            << entry.startTypeText << '\t'
            << entry.processId << '\t'
            << entry.accountText << '\t'
            << entry.commandLineText << '\t'
            << entry.serviceDllPathText << '\t'
            << entry.sourceStatusText << '\t'
            << entry.riskSummaryText << '\n';
    }

    if (!outputFile.commit())
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("写入导出文件失败。"));
        return;
    }
}

void ServiceDock::exportSelectedServiceAsJson()
{
    const int selectedIndex = findServiceIndexByName(selectedServiceName());
    if (selectedIndex < 0 || selectedIndex >= static_cast<int>(m_serviceList.size()))
    {
        return;
    }

    const ServiceEntry& entry = m_serviceList[static_cast<std::size_t>(selectedIndex)];
    const QString outputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出当前服务 JSON"),
        QStringLiteral("%1.json").arg(entry.serviceNameText),
        QStringLiteral("JSON Files (*.json);;All Files (*.*)"));
    if (outputPath.trimmed().isEmpty())
    {
        return;
    }

    QJsonObject rootObject;
    rootObject.insert(QStringLiteral("service_name"), entry.serviceNameText);
    rootObject.insert(QStringLiteral("display_name"), entry.displayNameText);
    rootObject.insert(QStringLiteral("description"), entry.descriptionText);
    rootObject.insert(QStringLiteral("state_text"), entry.stateText);
    rootObject.insert(QStringLiteral("start_type_text"), entry.startTypeText);
    rootObject.insert(QStringLiteral("service_type_text"), entry.serviceTypeText);
    rootObject.insert(QStringLiteral("error_control_text"), entry.errorControlText);
    rootObject.insert(QStringLiteral("binary_path"), entry.commandLineText);
    rootObject.insert(QStringLiteral("image_path"), entry.imagePathText);
    rootObject.insert(QStringLiteral("service_dll_path"), entry.serviceDllPathText);
    rootObject.insert(QStringLiteral("account"), entry.accountText);
    rootObject.insert(QStringLiteral("pid"), static_cast<int>(entry.processId));
    rootObject.insert(QStringLiteral("current_state"), static_cast<int>(entry.currentState));
    rootObject.insert(QStringLiteral("start_type"), static_cast<int>(entry.startTypeValue));
    rootObject.insert(QStringLiteral("service_type"), static_cast<int>(entry.serviceTypeValue));
    rootObject.insert(QStringLiteral("error_control"), static_cast<int>(entry.errorControlValue));
    rootObject.insert(QStringLiteral("delayed_auto_start"), entry.delayedAutoStart);
    rootObject.insert(QStringLiteral("source_status"), entry.sourceStatusText);
    rootObject.insert(QStringLiteral("scm_record_present"), entry.scmRecordPresent);
    rootObject.insert(QStringLiteral("registry_key_present"), entry.registryKeyPresent);
    rootObject.insert(QStringLiteral("registry_scan_completed"), entry.registryScanCompleted);
    rootObject.insert(QStringLiteral("risk_summary"), entry.riskSummaryText);

    QJsonArray riskArray;
    for (const QString& riskTagText : entry.riskTagList)
    {
        riskArray.push_back(riskTagText);
    }
    rootObject.insert(QStringLiteral("risk_tags"), riskArray);

    QSaveFile outputFile(outputPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("打开导出文件失败：\n%1").arg(outputFile.errorString()));
        return;
    }

    const QJsonDocument jsonDocument(rootObject);
    outputFile.write(jsonDocument.toJson(QJsonDocument::Indented));
    if (!outputFile.commit())
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("写入导出文件失败。"));
    }
}

void ServiceDock::jumpToFileDockBinaryDetail()
{
    const int selectedIndex = findServiceIndexByName(selectedServiceName());
    if (selectedIndex < 0 || selectedIndex >= static_cast<int>(m_serviceList.size()))
    {
        return;
    }

    const QString filePathText = m_serviceList[static_cast<std::size_t>(selectedIndex)].imagePathText.trimmed();
    if (filePathText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务没有可分析的 BinaryPath 文件。"));
        return;
    }

    QWidget* mainWindowWidget = window();
    if (mainWindowWidget == nullptr)
    {
        return;
    }

    QMetaObject::invokeMethod(
        mainWindowWidget,
        "openFileDetailDockByPath",
        Qt::QueuedConnection,
        Q_ARG(QString, filePathText));
}

void ServiceDock::jumpToFileDockServiceDllDetail()
{
    const int selectedIndex = findServiceIndexByName(selectedServiceName());
    if (selectedIndex < 0 || selectedIndex >= static_cast<int>(m_serviceList.size()))
    {
        return;
    }

    const QString filePathText = m_serviceList[static_cast<std::size_t>(selectedIndex)].serviceDllPathText.trimmed();
    if (filePathText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务未配置 ServiceDll。"));
        return;
    }

    QWidget* mainWindowWidget = window();
    if (mainWindowWidget == nullptr)
    {
        return;
    }

    QMetaObject::invokeMethod(
        mainWindowWidget,
        "openFileDetailDockByPath",
        Qt::QueuedConnection,
        Q_ARG(QString, filePathText));
}
