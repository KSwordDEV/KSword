#include "ProcessDetailWindow.InternalCommon.h"
#include "ProcessAffinityUtils.h"
#include "ProcessAffinityPersistence.h"

using namespace process_detail_window_internal;

namespace
{
    class ScopedDetailProcessIdentityHandle final
    {
    public:
        explicit ScopedDetailProcessIdentityHandle(HANDLE handleValue) : m_handle(handleValue) {}
        ~ScopedDetailProcessIdentityHandle()
        {
            if (m_handle != nullptr)
            {
                ::CloseHandle(m_handle);
            }
        }
        ScopedDetailProcessIdentityHandle(const ScopedDetailProcessIdentityHandle&) = delete;
        ScopedDetailProcessIdentityHandle& operator=(const ScopedDetailProcessIdentityHandle&) = delete;
    private:
        HANDLE m_handle = nullptr;
    };

    // invokeProcessActionForIdentity keeps a verified query handle open until
    // the synchronous R3 operation returns. Windows does not reuse the PID while
    // that process object is still referenced, so a stale detail window cannot
    // modify a later process instance.
    bool invokeProcessActionForIdentity(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        const std::function<bool(std::string*)>& actionInvoker,
        std::string* const detailTextOut)
    {
        if (!actionInvoker)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process action invoker is unavailable";
            }
            return false;
        }
        if (pid == 0U || expectedCreationTime100ns == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process identity is unavailable; action skipped";
            }
            return false;
        }

        HANDLE rawProcessHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (rawProcessHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed, error=" +
                    std::to_string(::GetLastError());
            }
            return false;
        }
        ScopedDetailProcessIdentityHandle processHandle(rawProcessHandle);

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (!::GetProcessTimes(
                rawProcessHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "GetProcessTimes failed, error=" + std::to_string(::GetLastError());
            }
            return false;
        }
        const std::uint64_t actualCreationTime100ns =
            (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U) |
            static_cast<std::uint64_t>(creationTime.dwLowDateTime);
        if (actualCreationTime100ns == 0U || actualCreationTime100ns != expectedCreationTime100ns)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process identity changed (PID was reused); action skipped";
            }
            return false;
        }

        return actionInvoker(detailTextOut);
    }
}

// ============================================================
// ProcessDetailWindow.ActionAndUtil.cpp
// 作用：
// - 负责操作页动作（终止/挂起/优先级/注入）与通用工具函数。
// - 聚焦“执行动作 + 结果反馈 + 辅助格式化/查找”逻辑。
// ============================================================

void ProcessDetailWindow::submitDetailAction(const QString& title, const kLogEvent& actionEvent,
    std::function<DetailActionResult()> action, const bool refreshModules,
    std::function<void(const DetailActionResult&)> completed)
{
    if (!m_detailActionOperation)
    {
        m_detailActionOperation = std::make_unique<ks::ui::AsyncOperation>(this);
        m_detailActionOperation->setStateChangedCallback([this]
        {
            const bool busy = m_detailActionOperation->isBusy();
            const QPointer<ProcessDetailWindow> alive(this);
            const QList<QPointer<QPushButton>> buttons{m_executeTerminateActionButton, m_injectDllButton, m_injectShellcodeButton};
            for (const auto& button : buttons)
            {
                if (button) button->setEnabled(!busy);
                if (!alive) return;
            }
            if (m_refreshHotkeyButton) m_refreshHotkeyButton->setEnabled(!busy && !m_hotkeyRefreshing && !m_keyboardRefreshing);
            if (!alive) return;
            if (m_refreshKeyboardButton) m_refreshKeyboardButton->setEnabled(!busy && !m_hotkeyRefreshing && !m_keyboardRefreshing);
            if (!alive) return;
            const bool canEdit = !busy && !m_hotkeyRefreshing && !m_keyboardRefreshing && m_hotkeyTable &&
                m_hotkeyTable->isEnabled() && !m_hotkeyTable->isPreparing() && m_hotkeyTable->currentRow() >= 0;
            if (m_editHotkeyButton) m_editHotkeyButton->setEnabled(canEdit);
            if (!alive) return;
            if (m_deleteHotkeyButton) m_deleteHotkeyButton->setEnabled(canEdit);
        });
    }
    if (m_detailActionOperation->isBusy()) return;
    const auto pid = m_baseRecord.pid;
    const auto creationTime = m_baseRecord.creationTime100ns;
    const auto titleValue = title.toStdString();
    const auto exceptionText = ks::i18n::sourceText(QStringLiteral("后台任务发生异常。")).toStdString();
    m_detailActionOperation->submitTransaction<std::function<DetailActionResult()>, DetailActionResult>(std::move(action),
        [actionEvent, titleValue, pid, exceptionText](const std::function<DetailActionResult()>& work)
        {
            DetailActionResult result;
            try { result = work(); }
            catch (const std::exception& error) { result.detail = error.what(); }
            catch (...) { result.detail = exceptionText; }
            // Accepted effects keep their complete receipt even if the window closes.
            (result.ok ? info : err) << actionEvent << "[ProcessDetailWindow] action completed, pid=" << pid
                << ", action=" << titleValue << ", ok=" << result.ok << ", detail=" << result.detail << eol;
            return result;
        },
        [this, title, actionEvent, pid, creationTime, refreshModules, completed = std::move(completed)](const DetailActionResult& result, std::uint64_t)
        {
            if (pid != m_baseRecord.pid || creationTime != m_baseRecord.creationTime100ns) return true;
            const QPointer<ProcessDetailWindow> alive(this);
            // 清除请求可能已生效但读回未知时，由热键页单独给出警告，避免当作确定失败提权/报错。
            if (!result.outcomeUncertain)
                showActionResultMessage(title, result.ok, result.detail, actionEvent);
            if (alive && completed) completed(result);
            if (alive && refreshModules && result.ok) requestAsyncModuleRefresh(true);
            return true;
        },
        [this, title, actionEvent, exceptionText](std::exception_ptr)
        { showActionResultMessage(title, false, exceptionText, actionEvent); },
        [actionEvent, titleValue](ks::ui::AsyncOperationOutcome outcome)
        { info << actionEvent << "[ProcessDetailWindow] action cleanup, action=" << titleValue << ", outcome=" << static_cast<int>(outcome) << eol; });
}

void ProcessDetailWindow::executeSingleTerminateMethodAction(const std::size_t methodIndex)
{
    const auto& methods = ks::process::TerminateMethodTable();
    if (methodIndex >= methods.size()) return;
    const auto targetPid = m_baseRecord.pid;
    const auto creationTime = m_baseRecord.creationTime100ns;
    const QString title = QString::fromUtf8(methods[methodIndex].methodName);
    const kLogEvent actionEvent;
    submitDetailAction(title, actionEvent, [targetPid, creationTime, methodIndex]
    {
        DetailActionResult result;
        result.ok = invokeProcessActionForIdentity(targetPid, creationTime,
            [targetPid, methodIndex](std::string* detail)
            { return ks::process::TerminateMethodTable()[methodIndex].invokeMethod(targetPid, detail); }, &result.detail);
        return result;
    });
}

void ProcessDetailWindow::executeR0SuspendSelectedThreadAction()
{
    if (!m_threadInspectTable || m_threadInspectRefreshing || m_threadInspectTable->isPreparing()) return;
    if (m_threadInspectTable == nullptr || !m_threadInspectPublishedRows)
    {
        return;
    }

    const int currentRow = m_threadInspectTable->currentRow();
    const QModelIndex threadIdItem = currentRow >= 0
        ? m_threadInspectTable->model()->index(currentRow, toThreadColumnIndex(ThreadRowColumn::ThreadId))
        : QModelIndex();
    const std::size_t cacheIndex = threadIdItem.isValid()
        ? static_cast<std::size_t>(threadIdItem.data(Qt::UserRole).toULongLong())
        : static_cast<std::size_t>(m_threadInspectPublishedRows->size());
    if (cacheIndex >= m_threadInspectPublishedRows->size())
    {
        return;
    }

    const ThreadInspectItem selectedThread = (*m_threadInspectPublishedRows)[cacheIndex];
    const std::uint32_t processId = selectedThread.processId != 0U
        ? selectedThread.processId
        : m_baseRecord.pid;
    if (processId <= 4U || selectedThread.threadId == 0U)
    {
        return;
    }

    const QMessageBox::StandardButton confirmation = QMessageBox::warning(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.confirm.title"),
            QStringLiteral("R0挂起线程")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.confirm.body"),
            QStringLiteral("将通过 R0 挂起 PID %2 的线程 %1。目标程序可能失去响应，是否继续？"))
            .arg(selectedThread.threadId)
            .arg(processId),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmation != QMessageBox::Yes)
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.setThreadSuspended(
        selectedThread.threadId,
        processId,
        true);
    (result.ok ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeR0SuspendSelectedThreadAction: pid="
        << processId
        << ", tid="
        << selectedThread.threadId
        << ", actionOk="
        << (result.ok ? "true" : "false")
        << ", detail="
        << result.message
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.result.title"),
            QStringLiteral("R0挂起线程")),
        result.ok,
        result.message,
        actionEvent);
    requestAsyncThreadInspectRefresh();
}

void ProcessDetailWindow::executeR0ResumeSelectedThreadAction()
{
    if (!m_threadInspectTable || m_threadInspectRefreshing || m_threadInspectTable->isPreparing()) return;
    if (m_threadInspectTable == nullptr || !m_threadInspectPublishedRows)
    {
        return;
    }

    const int currentRow = m_threadInspectTable->currentRow();
    const QModelIndex threadIdItem = currentRow >= 0
        ? m_threadInspectTable->model()->index(currentRow, toThreadColumnIndex(ThreadRowColumn::ThreadId))
        : QModelIndex();
    const std::size_t cacheIndex = threadIdItem.isValid()
        ? static_cast<std::size_t>(threadIdItem.data(Qt::UserRole).toULongLong())
        : static_cast<std::size_t>(m_threadInspectPublishedRows->size());
    if (cacheIndex >= m_threadInspectPublishedRows->size())
    {
        return;
    }

    const ThreadInspectItem selectedThread = (*m_threadInspectPublishedRows)[cacheIndex];
    const std::uint32_t processId = selectedThread.processId != 0U
        ? selectedThread.processId
        : m_baseRecord.pid;
    if (processId <= 4U || selectedThread.threadId == 0U)
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.setThreadSuspended(
        selectedThread.threadId,
        processId,
        false);
    (result.ok ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeR0ResumeSelectedThreadAction: pid="
        << processId
        << ", tid="
        << selectedThread.threadId
        << ", actionOk="
        << (result.ok ? "true" : "false")
        << ", detail="
        << result.message
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_resume.result.title"),
            QStringLiteral("R0恢复线程")),
        result.ok,
        result.message,
        actionEvent);
    requestAsyncThreadInspectRefresh();
}

void ProcessDetailWindow::executeDriverThreadAction(
    const unsigned long action,
    const unsigned long terminateMethod)
{
    if (!m_threadInspectTable || m_threadInspectRefreshing || m_threadInspectTable->isPreparing()) return;
    if (m_threadInspectTable == nullptr || !m_threadInspectPublishedRows)
    {
        return;
    }

    const int currentRow = m_threadInspectTable->currentRow();
    const QModelIndex threadIdItem = currentRow >= 0
        ? m_threadInspectTable->model()->index(currentRow, toThreadColumnIndex(ThreadRowColumn::ThreadId))
        : QModelIndex();
    const std::size_t cacheIndex = threadIdItem.isValid()
        ? static_cast<std::size_t>(threadIdItem.data(Qt::UserRole).toULongLong())
        : static_cast<std::size_t>(m_threadInspectPublishedRows->size());
    if (cacheIndex >= m_threadInspectPublishedRows->size())
    {
        return;
    }

    const ThreadInspectItem selectedThread = (*m_threadInspectPublishedRows)[cacheIndex];
    const std::uint64_t startAddress = selectedThread.startAddress != 0ULL
        ? selectedThread.startAddress
        : selectedThread.win32StartAddress;
    if (m_baseRecord.pid != 4U || selectedThread.threadId == 0U ||
        startAddress == 0ULL || selectedThread.createTime100ns == 0ULL)
    {
        return;
    }

    QString resultTitle;
    if (action == KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND)
    {
        resultTitle = ks::i18n::contextText(
            QStringLiteral("process.thread.driver_suspend.result.title"),
            QStringLiteral("挂起驱动线程"));
        const QMessageBox::StandardButton confirmation = QMessageBox::critical(
            this,
            ks::i18n::contextText(
                QStringLiteral("process.thread.driver_suspend.confirm.title"),
                QStringLiteral("挂起驱动线程")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.driver_suspend.confirm.body"),
                QStringLiteral("即将挂起 System(PID 4) 的驱动线程 %1。此操作可能冻结磁盘、网络或安全组件，并可能导致系统死锁或蓝屏。仅在已保存工作且可强制重启时继续。"))
                .arg(selectedThread.threadId),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (confirmation != QMessageBox::Yes)
        {
            return;
        }
    }
    else if (action == KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME)
    {
        resultTitle = ks::i18n::contextText(
            QStringLiteral("process.thread.driver_resume.result.title"),
            QStringLiteral("恢复驱动线程"));
    }
    else if (action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE)
    {
        switch (terminateMethod)
        {
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER:
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT:
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC:
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC:
            break;
        default:
            return;
        }
        resultTitle = ks::i18n::contextText(
            QStringLiteral("process.thread.driver_terminate.result.title"),
            QStringLiteral("强制结束驱动线程"));
    }
    else
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.controlDriverThread(
        selectedThread.threadId,
        startAddress,
        selectedThread.createTime100ns,
        action,
        terminateMethod,
        action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME);
    (result.ok ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeDriverThreadAction: tid="
        << selectedThread.threadId
        << ", action="
        << action
        << ", terminateMethod="
        << terminateMethod
        << ", actionOk="
        << (result.ok ? "true" : "false")
        << ", detail="
        << result.message
        << eol;
    showActionResultMessage(resultTitle, result.ok, result.message, actionEvent);
    requestAsyncThreadInspectRefresh();
}

void ProcessDetailWindow::executeExperimentalFirmwareRebootAction()
{
    const QMessageBox::StandardButton firstConfirmation = QMessageBox::critical(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.confirm.title"),
            QStringLiteral("HalReturnToFirmware 实验性整机动作")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.confirm.body"),
            QStringLiteral("HalReturnToFirmware(HalRebootRoutine) 不是线程终止 API，而是不受支持的整机固件返回动作。它会绕过所选线程和进程保护，可能立即重启、丢失所有未保存数据，或在当前平台失败/崩溃。是否进入最终确认？")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (firstConfirmation != QMessageBox::Yes)
    {
        return;
    }
    const QMessageBox::StandardButton finalConfirmation = QMessageBox::critical(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.final.title"),
            QStringLiteral("最终确认：立即调用原始 API")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.final.body"),
            QStringLiteral("最后确认：立即调用 HalReturnToFirmware(HalRebootRoutine)。成功时系统不会返回本程序。")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (finalConfirmation != QMessageBox::Yes)
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.experimentalReturnToFirmware();
    (result.ok ? warn : err) << actionEvent
        << "[ProcessDetailWindow] executeExperimentalFirmwareRebootAction: actionOk="
        << (result.ok ? "true" : "false")
        << ", detail=" << result.message
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.result.title"),
            QStringLiteral("HalReturnToFirmware 实验性整机动作")),
        result.ok,
        result.message,
        actionEvent);
}

void ProcessDetailWindow::executeR0TerminateSelectedThreadAction()
{
    if (!m_threadInspectTable || m_threadInspectRefreshing || m_threadInspectTable->isPreparing()) return;
    if (m_threadInspectTable == nullptr || !m_threadInspectPublishedRows)
    {
        return;
    }

    const int currentRow = m_threadInspectTable->currentRow();
    const QModelIndex threadIdItem = currentRow >= 0
        ? m_threadInspectTable->model()->index(currentRow, toThreadColumnIndex(ThreadRowColumn::ThreadId))
        : QModelIndex();
    const std::size_t cacheIndex = threadIdItem.isValid()
        ? static_cast<std::size_t>(threadIdItem.data(Qt::UserRole).toULongLong())
        : static_cast<std::size_t>(m_threadInspectPublishedRows->size());
    if (cacheIndex >= m_threadInspectPublishedRows->size())
    {
        return;
    }

    const ThreadInspectItem selectedThread = (*m_threadInspectPublishedRows)[cacheIndex];
    const std::uint32_t processId = selectedThread.processId != 0U
        ? selectedThread.processId
        : m_baseRecord.pid;
    if (processId <= 4U || selectedThread.threadId == 0U)
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.terminateThread(
        selectedThread.threadId,
        processId,
        static_cast<long>(0xC0000005u));
    (result.ok ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeR0TerminateSelectedThreadAction: pid="
        << processId
        << ", tid="
        << selectedThread.threadId
        << ", actionOk="
        << (result.ok ? "true" : "false")
        << ", detail="
        << result.message
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_terminate.result.title"),
            QStringLiteral("R0结束线程")),
        result.ok,
        result.message,
        actionEvent);
    requestAsyncThreadInspectRefresh();
}

void ProcessDetailWindow::executeSelectedTerminateAction()
{
    if (m_terminateActionCombo == nullptr)
    {
        kLogEvent terminateComboNullEvent;
        err << terminateComboNullEvent
            << "[ProcessDetailWindow] executeSelectedTerminateAction: m_terminateActionCombo 为空。"
            << eol;
        return;
    }

    const int actionId = m_terminateActionCombo->currentData().toInt();
    if (actionId >= 0 && actionId < static_cast<int>(ks::process::TerminateMethodTable().size()))
    {
        executeSingleTerminateMethodAction(static_cast<std::size_t>(actionId));
    }
    else if (actionId == static_cast<int>(ks::process::TerminateMethodTable().size()))
    {
        executeR0TerminateProcessAction();
    }
    else if (actionId == static_cast<int>(ks::process::TerminateMethodTable().size()) + 1)
    {
        // 组合选项复用共享方法表与详情页身份校验，不改变单方法/R0 路由。
        executeTerminateProcessComboAction();
    }
    else
    {
        kLogEvent invalidTerminateActionEvent;
        warn << invalidTerminateActionEvent
            << "[ProcessDetailWindow] executeSelectedTerminateAction: 未知 actionId="
            << actionId << eol;
    }
}

void ProcessDetailWindow::executeSuspendProcessAction()
{
    // 挂起进程日志：同一动作只使用一个 kLogEvent，保证调用链可追踪。
    kLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeSuspendProcessAction: pid="
        << m_baseRecord.pid
        << eol;

    std::string detailText;
    const bool actionOk = ks::process::SuspendProcessIfCreationTimeMatches(m_baseRecord.pid, m_baseRecord.creationTime100ns, &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeSuspendProcessAction: actionOk="
        << (actionOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage("挂起进程", actionOk, detailText, actionEvent);
}

void ProcessDetailWindow::executeResumeProcessAction()
{
    // 恢复进程日志：同一动作只使用一个 kLogEvent，保证调用链可追踪。
    kLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeResumeProcessAction: pid="
        << m_baseRecord.pid
        << eol;

    std::string detailText;
    const bool actionOk = ks::process::ResumeProcessIfCreationTimeMatches(m_baseRecord.pid, m_baseRecord.creationTime100ns, &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeResumeProcessAction: actionOk="
        << (actionOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage("恢复进程", actionOk, detailText, actionEvent);
}

void ProcessDetailWindow::executeSetCriticalAction(const bool enableCritical)
{
    // 关键进程标记变更日志：同一动作只使用一个 kLogEvent，保证调用链可追踪。
    kLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeSetCriticalAction: pid="
        << m_baseRecord.pid
        << ", enableCritical="
        << (enableCritical ? "true" : "false")
        << eol;

    std::string detailText;
    const std::uint32_t targetPid = m_baseRecord.pid;
    const bool actionOk = invokeProcessActionForIdentity(
        targetPid,
        m_baseRecord.creationTime100ns,
        [targetPid, enableCritical](std::string* detailTextOut)
        {
            return ks::process::SetProcessCriticalFlag(targetPid, enableCritical, detailTextOut);
        },
        &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeSetCriticalAction: actionOk="
        << (actionOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage(enableCritical ? "设为关键进程" : "取消关键进程", actionOk, detailText, actionEvent);
}

void ProcessDetailWindow::executeSetPriorityAction()
{
    if (m_priorityCombo == nullptr)
    {
        kLogEvent priorityComboNullEvent;
        err << priorityComboNullEvent
            << "[ProcessDetailWindow] executeSetPriorityAction: m_priorityCombo 为空。"
            << eol;
        return;
    }

    const int actionId = m_priorityCombo->currentData().toInt();
    ks::process::ProcessPriorityLevel priorityLevel = ks::process::ProcessPriorityLevel::Normal;
    switch (actionId)
    {
    case 0: priorityLevel = ks::process::ProcessPriorityLevel::Idle; break;
    case 1: priorityLevel = ks::process::ProcessPriorityLevel::BelowNormal; break;
    case 2: priorityLevel = ks::process::ProcessPriorityLevel::Normal; break;
    case 3: priorityLevel = ks::process::ProcessPriorityLevel::AboveNormal; break;
    case 4: priorityLevel = ks::process::ProcessPriorityLevel::High; break;
    case 5: priorityLevel = ks::process::ProcessPriorityLevel::Realtime; break;
    default: priorityLevel = ks::process::ProcessPriorityLevel::Normal; break;
    }

    // 优先级设置日志：同一动作只使用一个 kLogEvent，保证调用链可追踪。
    kLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeSetPriorityAction: pid="
        << m_baseRecord.pid
        << ", actionId="
        << actionId
        << eol;

    std::string detailText;
    const std::uint32_t targetPid = m_baseRecord.pid;
    const bool actionOk = invokeProcessActionForIdentity(
        targetPid,
        m_baseRecord.creationTime100ns,
        [targetPid, priorityLevel](std::string* detailTextOut)
        {
            return ks::process::SetProcessPriority(targetPid, priorityLevel, detailTextOut);
        },
        &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeSetPriorityAction: actionOk="
        << (actionOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage("设置进程优先级", actionOk, detailText, actionEvent);
}

void ProcessDetailWindow::refreshActionAffinityControls()
{
    // 亲和性读取只在操作页按需进行，并统一使用跨组 CPU Set 快照。
    ks::process::ProcessAffinitySnapshot affinitySnapshot;
    std::string detailText;
    const bool queryOk = ks::process::QueryProcessAffinityState(
        static_cast<DWORD>(m_baseRecord.pid),
        &affinitySnapshot,
        &detailText);
    m_actionAffinityReadable = queryOk;
    m_actionAffinitySnapshot = queryOk
        ? std::move(affinitySnapshot)
        : ks::process::ProcessAffinitySnapshot{};
    rebuildActionAffinityCoreButtons();
    updateActionAffinityCoreButtons();
    refreshActionAffinityPersistenceControl();

    if (m_affinityStatusLabel == nullptr)
    {
        return;
    }

    if (!queryOk)
    {
        kLogEvent queryEvent;
        warn << queryEvent
            << "[ProcessDetailWindow] CPU affinity query failed, pid="
            << m_baseRecord.pid
            << ", detail="
            << (detailText.empty() ? "none" : detailText)
            << eol;
        m_affinityStatusLabel->setText(
            ks::i18n::text(
                QStringLiteral("process.detail.affinity.status.unavailable"),
                QString()));
        m_affinityStatusLabel->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        return;
    }

    std::size_t availableProcessorCount = 0U;
    std::size_t selectedProcessorCount = 0U;
    std::size_t constrainedProcessorCount = 0U;
    for (const ks::process::LogicalProcessorState& processor :
         m_actionAffinitySnapshot.processors)
    {
        if (processor.available)
        {
            ++availableProcessorCount;
            if (processor.selected)
            {
                ++selectedProcessorCount;
            }
        }
        if (processor.constrainedByHardAffinity)
        {
            ++constrainedProcessorCount;
        }
    }
    const QString modeText = ks::i18n::text(
        m_actionAffinitySnapshot.usesCpuSets
            ? QStringLiteral("process.detail.affinity.mode.cpu_sets")
            : QStringLiteral("process.detail.affinity.mode.legacy"),
        QString());
    QString affinityStatusText = ks::i18n::text(
            QStringLiteral("process.detail.affinity.status.current"),
            QString())
            .arg(modeText)
            .arg(selectedProcessorCount)
            .arg(availableProcessorCount);
    if (constrainedProcessorCount != 0U)
    {
        affinityStatusText += ks::i18n::text(
            QStringLiteral(
                "process.detail.affinity.status.constraint_suffix"),
            QString())
            .arg(constrainedProcessorCount);
    }
    m_affinityStatusLabel->setText(affinityStatusText);
    m_affinityStatusLabel->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
}

bool ProcessDetailWindow::confirmActionAffinityRisk(
    const bool persistenceSave)
{
    const QMessageBox::StandardButton confirmation =
        QMessageBox::warning(
            this,
            ks::i18n::text(
                QStringLiteral("process.affinity.risk.title"),
                QString()),
            ks::i18n::text(
                persistenceSave
                    ? QStringLiteral("process.affinity.risk.save")
                    : QStringLiteral("process.affinity.risk.apply"),
                QString()),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
    return confirmation == QMessageBox::Yes;
}

void ProcessDetailWindow::applyActionAffinityRule(
    const ks::process::ProcessAffinityRule& affinityRule)
{
    if (!m_actionAffinityReadable ||
        (!affinityRule.selectAllAvailable &&
            affinityRule.processors.empty()))
    {
        refreshActionAffinityControls();
        return;
    }
    const bool persistenceEnabled =
        m_affinityPersistenceCheckBox != nullptr &&
        m_affinityPersistenceCheckBox->isChecked();
    if (!confirmActionAffinityRisk(persistenceEnabled))
    {
        updateActionAffinityCoreButtons();
        return;
    }

    QStringList requestedProcessorTexts;
    if (affinityRule.selectAllAvailable)
    {
        requestedProcessorTexts <<
            ks::i18n::text(
                QStringLiteral("process.detail.affinity.all_cores"),
                QString());
    }
    else
    {
        for (const ks::process::LogicalProcessorCoordinate& coordinate :
             affinityRule.processors)
        {
            requestedProcessorTexts <<
                QString::fromStdString(
                    ks::process::processorIdentityText(coordinate));
        }
    }

    std::string detailText;
    const std::uint32_t targetPid = m_baseRecord.pid;
    const bool setOk = invokeProcessActionForIdentity(
        targetPid,
        m_baseRecord.creationTime100ns,
        [targetPid, &affinityRule](std::string* detailTextOut)
        {
            return ks::process::SetProcessAffinityRuleByPid(
                static_cast<DWORD>(targetPid),
                affinityRule,
                detailTextOut);
        },
        &detailText);
    kLogEvent actionEvent;
    (setOk ? info : warn) << actionEvent
        << "[ProcessDetailWindow] CPU affinity update, pid="
        << m_baseRecord.pid
        << ", requested="
        << requestedProcessorTexts.join(',').toStdString()
        << ", ok="
        << (setOk ? "true" : "false")
        << ", detail="
        << (detailText.empty() ? "none" : detailText)
        << eol;

    if (!setOk)
    {
        if (m_affinityStatusLabel != nullptr)
        {
            m_affinityStatusLabel->setText(
                ks::i18n::text(
                    QStringLiteral("process.detail.affinity.status.update_failed"),
                    QString()));
            m_affinityStatusLabel->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        updateActionAffinityCoreButtons();
        return;
    }

    bool persistenceOk = true;
    std::string persistenceDetailText;
    if (persistenceEnabled)
    {
        persistenceOk = ks::process::savePersistedProcessAffinityRule(
                m_baseRecord.imagePath,
                affinityRule,
                &persistenceDetailText);
        if (!persistenceOk)
        {
            const QSignalBlocker signalBlocker(m_affinityPersistenceCheckBox);
            m_affinityPersistenceCheckBox->setChecked(false);
            kLogEvent persistenceEvent;
            warn << persistenceEvent
                << "[ProcessDetailWindow] CPU affinity persistence update failed, pid="
                << m_baseRecord.pid
                << ", detail=" << persistenceDetailText << eol;
        }
    }
    refreshActionAffinityControls();
    if (m_affinityStatusLabel != nullptr)
    {
        m_affinityStatusLabel->setText(
            persistenceOk
                ? ks::i18n::text(
                    QStringLiteral("process.detail.affinity.status.updated"),
                    QString())
                : ks::i18n::text(
                    QStringLiteral(
                        "process.detail.affinity.persistence.save_failed"),
                    QString()));
        m_affinityStatusLabel->setStyleSheet(buildStateLabelStyle(
            persistenceOk ? statusIdleColor() : statusWarningColor(),
            persistenceOk ? 600 : 700));
    }
}

void ProcessDetailWindow::refreshActionAffinityPersistenceControl()
{
    if (m_affinityPersistenceCheckBox == nullptr)
    {
        return;
    }

    ks::process::ProcessAffinityRule storedRule;
    bool ruleFound = false;
    std::string detailText;
    const std::uint16_t legacyGroupHint =
        m_actionAffinityReadable
            ? ks::process::inferLegacyAffinityGroup(
                m_actionAffinitySnapshot)
            : 0U;
    const bool readOk =
        ks::process::loadPersistedProcessAffinityRule(
        m_baseRecord.imagePath,
        &storedRule,
        &ruleFound,
        &detailText,
        legacyGroupHint);
    const QSignalBlocker signalBlocker(m_affinityPersistenceCheckBox);
    m_affinityPersistenceCheckBox->setEnabled(
        readOk &&
        m_actionAffinityReadable &&
        !m_baseRecord.imagePath.empty());
    m_affinityPersistenceCheckBox->setChecked(readOk && ruleFound);
    m_affinityPersistenceCheckBox->setToolTip(
        ks::i18n::text(
            QStringLiteral("process.detail.affinity.persistence.tooltip"),
            QString()));
    if (!readOk)
    {
        kLogEvent persistenceReadEvent;
        warn << persistenceReadEvent
            << "[ProcessDetailWindow] CPU affinity persistence query failed, pid="
            << m_baseRecord.pid
            << ", detail="
            << (detailText.empty() ? "none" : detailText)
            << eol;
    }
}

void ProcessDetailWindow::toggleActionAffinityCore(
    const ks::process::LogicalProcessorCoordinate& coordinate,
    const bool enabled)
{
    if (!m_actionAffinityReadable)
    {
        refreshActionAffinityControls();
        return;
    }

    const auto targetProcessorIt = std::find_if(
        m_actionAffinitySnapshot.processors.begin(),
        m_actionAffinitySnapshot.processors.end(),
        [&coordinate](const ks::process::LogicalProcessorState& processor)
        {
            return processor.coordinate == coordinate &&
                processor.available;
        });
    if (targetProcessorIt ==
        m_actionAffinitySnapshot.processors.end())
    {
        updateActionAffinityCoreButtons();
        return;
    }

    ks::process::ProcessAffinityRule nextRule;
    if (m_actionAffinitySnapshot.unrestricted)
    {
        for (const ks::process::LogicalProcessorState& processor :
             m_actionAffinitySnapshot.processors)
        {
            if (processor.available)
            {
                nextRule.processors.push_back(
                    processor.coordinate);
            }
        }
    }
    else
    {
        nextRule = ks::process::affinityRuleFromSnapshot(
            m_actionAffinitySnapshot);
    }

    if (enabled)
    {
        nextRule.processors.push_back(coordinate);
    }
    else
    {
        nextRule.processors.erase(
            std::remove(
                nextRule.processors.begin(),
                nextRule.processors.end(),
                coordinate),
            nextRule.processors.end());
    }
    nextRule.selectAllAvailable = false;
    ks::process::normalizeLogicalProcessorCoordinates(
        &nextRule.processors);
    if (nextRule.processors.empty())
    {
        updateActionAffinityCoreButtons();
        if (m_affinityStatusLabel != nullptr)
        {
            m_affinityStatusLabel->setText(
                ks::i18n::text(QStringLiteral("process.detail.affinity.status.last_core"), QString()));
            m_affinityStatusLabel->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        return;
    }
    applyActionAffinityRule(nextRule);
}

void ProcessDetailWindow::updateActionAffinityCoreButtons()
{
    const std::size_t processorCount = std::min(
        m_affinityCoreButtons.size(),
        m_actionAffinitySnapshot.processors.size());
    for (std::size_t processorIndex = 0U;
         processorIndex < processorCount;
         ++processorIndex)
    {
        QToolButton* const coreButton =
            m_affinityCoreButtons[processorIndex];
        if (coreButton == nullptr)
        {
            continue;
        }
        const ks::process::LogicalProcessorState& processor =
            m_actionAffinitySnapshot.processors[processorIndex];
        const bool available =
            m_actionAffinityReadable && processor.available;
        const QSignalBlocker signalBlocker(coreButton);
        coreButton->setEnabled(available);
        coreButton->setChecked(
            available && processor.selected);
    }
    if (m_affinityAllCoresButton != nullptr)
    {
        const bool hasAvailableProcessor = std::any_of(
            m_actionAffinitySnapshot.processors.begin(),
            m_actionAffinitySnapshot.processors.end(),
            [](const ks::process::LogicalProcessorState& processor)
            {
                return processor.available;
            });
        m_affinityAllCoresButton->setEnabled(
            m_actionAffinityReadable && hasAvailableProcessor);
    }
}

void ProcessDetailWindow::executeInjectDllAction()
{
    const QString dllPath = m_dllPathLineEdit->text().trimmed();
    const bool useR0Injection = m_injectionModeCombo != nullptr && m_injectionModeCombo->currentData().toInt() == 1;
    if (dllPath.isEmpty())
    {
        QMessageBox::warning(this, "DLL 注入", "请先选择 DLL 文件。");
        return;
    }
    const auto pid = m_baseRecord.pid;
    const auto creationTime = m_baseRecord.creationTime100ns;
    const kLogEvent actionEvent;
    submitDetailAction(useR0Injection ? QStringLiteral("DLL 注入(R0)") : QStringLiteral("DLL 注入"), actionEvent,
        [pid, creationTime, useR0Injection, dllPath]
    {
        DetailActionResult result;
        if (useR0Injection)
        {
            const auto injected = ksword::ark::DriverClient().injectProcessDll(pid, dllPath.toStdWString());
            result.detail = injected.io.message;
            result.ok = injected.io.ok && injected.status == KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED;
        }
        else
        {
            result.ok = invokeProcessActionForIdentity(pid, creationTime,
                [pid, dllPath](std::string* detail) { return ks::process::InjectDllByPath(pid, dllPath.toStdString(), detail); }, &result.detail);
        }
        return result;
    }, true);
}

void ProcessDetailWindow::executeInjectShellcodeAction()
{
    const QString shellcodePath = m_shellcodePathLineEdit->text().trimmed();
    const bool useR0Injection = m_injectionModeCombo != nullptr && m_injectionModeCombo->currentData().toInt() == 1;
    if (shellcodePath.isEmpty())
    {
        QMessageBox::warning(this, "Shellcode 注入", "请先选择 shellcode 文件。");
        return;
    }
    const auto pid = m_baseRecord.pid;
    const auto creationTime = m_baseRecord.creationTime100ns;
    const kLogEvent actionEvent;
    submitDetailAction(useR0Injection ? QStringLiteral("Shellcode 注入(R0)") : QStringLiteral("Shellcode 注入"), actionEvent,
        [pid, creationTime, useR0Injection, shellcodePath, actionEvent]
    {
        DetailActionResult result;
        const auto execute = [pid, useR0Injection, shellcodePath, actionEvent](std::string* detail)
        {
            std::vector<std::uint8_t> bytes;
            if (!readBinaryFile(shellcodePath, bytes, *detail, actionEvent,
                useR0Injection ? KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES : 0U)) return false;
            if (useR0Injection)
            {
                const auto injected = ksword::ark::DriverClient().injectProcessShellcode(pid, bytes);
                *detail = injected.io.message;
                return injected.io.ok && injected.status == KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED;
            }
            return ks::process::InjectShellcodeBuffer(pid, bytes, detail);
        };
        // R3 identity is held across both payload reading and the entire remote wait.
        result.ok = useR0Injection ? execute(&result.detail)
            : invokeProcessActionForIdentity(pid, creationTime, execute, &result.detail);
        return result;
    });
}

QIcon ProcessDetailWindow::resolveProcessIcon(const std::string& processPath, const int iconPixelSize)
{
    Q_UNUSED(iconPixelSize);

    // 优先使用传入路径；为空时按当前 PID 兜底查询一次。
    QString pathText = QString::fromStdString(processPath);
    if (pathText.trimmed().isEmpty() && m_baseRecord.pid != 0)
    {
        pathText = QString::fromStdString(ks::process::QueryProcessPathByPid(m_baseRecord.pid));
    }
    if (pathText.isEmpty())
    {
        kLogEvent resolveIconFallbackEvent;
        dbg << resolveIconFallbackEvent
            << "[ProcessDetailWindow] resolveProcessIcon: 路径为空，返回默认图标。"
            << eol;
        return QIcon(":/Icon/process_main.svg");
    }

    auto iconIt = m_iconCacheByPath.find(pathText);
    if (iconIt != m_iconCacheByPath.end())
    {
        kLogEvent resolveIconCacheHitEvent;
        dbg << resolveIconCacheHitEvent
            << "[ProcessDetailWindow] resolveProcessIcon: 命中图标缓存, path="
            << pathText.toStdString()
            << eol;
        return iconIt.value();
    }

    // 先尝试直接按 EXE 路径加载图标；失败再回退 QFileIconProvider。
    QIcon processIcon(pathText);
    if (processIcon.isNull())
    {
        QFileIconProvider iconProvider;
        processIcon = iconProvider.icon(QFileInfo(pathText));
    }
    if (processIcon.isNull())
    {
        processIcon = QIcon(":/Icon/process_main.svg");
    }
    m_iconCacheByPath.insert(pathText, processIcon);
    kLogEvent resolveIconCacheStoreEvent;
    dbg << resolveIconCacheStoreEvent
        << "[ProcessDetailWindow] resolveProcessIcon: 缓存图标, path="
        << pathText.toStdString()
        << eol;
    return processIcon;
}

QString ProcessDetailWindow::formatModuleSizeText(const std::uint32_t moduleSizeBytes) const
{
    const double sizeKb = static_cast<double>(moduleSizeBytes) / 1024.0;
    if (sizeKb < 1024.0)
    {
        return QString("%1 KB").arg(QString::number(sizeKb, 'f', 1));
    }
    const double sizeMb = sizeKb / 1024.0;
    return QString("%1 MB").arg(QString::number(sizeMb, 'f', 2));
}

QString ProcessDetailWindow::formatHexText(const std::uint64_t value) const
{
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << value;
    return QString::fromStdString(stream.str());
}

bool ProcessDetailWindow::readBinaryFile(const QString& filePath,
    std::vector<std::uint8_t>& bufferOut, std::string& errorTextOut,
    const kLogEvent& actionEvent, const std::size_t maxBytes)
{
    bufferOut.clear();
    errorTextOut.clear();
    QFile fileObject(filePath);
    if (!fileObject.open(QIODevice::ReadOnly))
    {
        errorTextOut = "Open file failed: " + fileObject.errorString().toStdString();
        return false;
    }
    const qint64 size = fileObject.size();
    if (maxBytes != 0U && size > static_cast<qint64>(maxBytes))
    {
        errorTextOut = "shellcode payload is larger than R0 inject payload limit";
        return false;
    }
    if (size > 0) bufferOut.reserve(static_cast<std::size_t>(size));
    while (!fileObject.atEnd())
    {
        const QByteArray chunk = fileObject.read(64 * 1024);
        if (chunk.isEmpty())
        {
            if (fileObject.error() != QFileDevice::NoError)
            {
                errorTextOut = fileObject.errorString().toStdString();
                return false;
            }
            break;
        }
        const auto count = static_cast<std::size_t>(chunk.size());
        if (maxBytes != 0U && (count > maxBytes || bufferOut.size() > maxBytes - count))
        {
            errorTextOut = "shellcode payload is larger than R0 inject payload limit";
            return false;
        }
        const auto* begin = reinterpret_cast<const std::uint8_t*>(chunk.constData());
        bufferOut.insert(bufferOut.end(), begin, begin + count);
    }
    if (bufferOut.empty())
    {
        errorTextOut = "File is empty.";
        return false;
    }
    info << actionEvent << "[ProcessDetailWindow] readBinaryFile: size=" << bufferOut.size() << eol;
    return true;
}

void ProcessDetailWindow::showActionResultMessage(
    const QString& title,
    const bool actionOk,
    const std::string& detailText,
    const kLogEvent& actionEvent)
{
    if (!actionOk)
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            title,
            QString::fromStdString(detailText));
    }
    // 动作反馈日志：按照规范不再弹窗，只输出日志，避免打断用户流程。
    const std::string normalizedDetailText = detailText.empty() ? "无附加信息" : detailText;
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] showActionResultMessage: title="
        << title.toStdString()
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << ", detail="
        << normalizedDetailText
        << eol;
}

const ks::process::ProcessModuleRecord* ProcessDetailWindow::selectedModuleRecord()
{
    if (m_moduleTable == nullptr || m_moduleTable->currentRow() < 0 || !m_moduleRecords) return nullptr;
    const auto path = m_moduleTable->currentCell(toModuleColumnIndex(ModuleColumn::Path), Qt::UserRole).toString().toStdString();
    const auto base = m_moduleTable->currentCell(toModuleColumnIndex(ModuleColumn::Path), Qt::UserRole + 1).toULongLong();
    const auto found = std::find_if(m_moduleRecords->cbegin(), m_moduleRecords->cend(),
        [&](const ModuleRowValue& value) { return value.record.moduleBaseAddress == base && value.record.modulePath == path; });
    return found == m_moduleRecords->cend() ? nullptr : &found->record;
}

void ProcessDetailWindow::openSelectedThreadStackWindow(const bool openDetails)
{
    if (!m_threadInspectTable || m_threadInspectRefreshing || m_threadInspectTable->isPreparing()) return;
    // 调用栈窗口入口：
    // - 当前表格行可能经过排序，因此优先读取 ThreadID 单元格保存的缓存索引；
    // - 缓存索引失效时按 TID 兜底查找，避免排序/刷新边界导致无法打开。
    if (m_threadInspectTable == nullptr || !m_threadInspectPublishedRows)
    {
        return;
    }

    const int currentRow = m_threadInspectTable->currentRow();
    if (currentRow < 0)
    {
        updateThreadInspectStatusLabel(QStringLiteral("● 请先选择一个线程。"), false);
        return;
    }

    const QModelIndex threadIdItem = m_threadInspectTable->model()->index(
        currentRow,
        toThreadColumnIndex(ThreadRowColumn::ThreadId));
    if (!threadIdItem.isValid())
    {
        updateThreadInspectStatusLabel(QStringLiteral("● 当前线程行缺少 ThreadID。"), false);
        return;
    }

    const std::size_t cacheIndex =
        static_cast<std::size_t>(threadIdItem.data(Qt::UserRole).toULongLong());
    const ThreadInspectItem* selectedThread = nullptr;
    if (cacheIndex < m_threadInspectPublishedRows->size())
    {
        selectedThread = &(*m_threadInspectPublishedRows)[cacheIndex];
    }

    const std::uint32_t selectedTid =
        static_cast<std::uint32_t>(threadIdItem.data(Qt::UserRole + 1).toUInt());
    if (selectedThread == nullptr || selectedThread->threadId != selectedTid)
    {
        const auto foundIt = std::find_if(
            m_threadInspectPublishedRows->begin(),
            m_threadInspectPublishedRows->end(),
            [selectedTid](const ThreadInspectItem& rowItem)
            {
                return rowItem.threadId == selectedTid;
            });
        if (foundIt != m_threadInspectPublishedRows->end())
        {
            selectedThread = &(*foundIt);
        }
    }

    if (selectedThread == nullptr)
    {
        updateThreadInspectStatusLabel(QStringLiteral("● 线程缓存已过期，请先刷新线程列表。"), false);
        return;
    }

    ThreadStackTarget target{};
    target.processId = selectedThread->processId != 0 ? selectedThread->processId : m_baseRecord.pid;
    target.threadId = selectedThread->threadId;
    target.threadCreationTime100ns = selectedThread->createTime100ns;
    target.processCreationTime100ns = m_baseRecord.creationTime100ns;
    target.processName = QString::fromStdString(
        m_baseRecord.processName.empty() ? std::string("Unknown") : m_baseRecord.processName);
    target.processPath = QString::fromStdString(m_baseRecord.imagePath);
    target.startAddress = selectedThread->startAddress;
    target.win32StartAddress = selectedThread->win32StartAddress;
    target.tebBaseAddress = selectedThread->tebAddress;
    target.userStackBase = selectedThread->userStackBase;
    target.userStackLimit = selectedThread->userStackLimit;
    target.r0KernelStack = selectedThread->r0KernelStack;
    target.r0StackBase = selectedThread->r0StackBase;
    target.r0StackLimit = selectedThread->r0StackLimit;
    target.r0InitialStack = selectedThread->r0InitialStack;
    target.r0ThreadStatus = selectedThread->r0ThreadStatus;
    target.r0CapabilityMask = selectedThread->r0CapabilityMask;

    if (openDetails)
    {
        ShowThreadDetailWindow(this, target);
        return;
    }
    auto* stackWindow = new ThreadStackWindow(target, this);
    stackWindow->setAttribute(Qt::WA_DeleteOnClose, true);
    stackWindow->show();
    stackWindow->raise();
    stackWindow->activateWindow();

    kLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] openSelectedThreadStackWindow: pid="
        << target.processId
        << ", tid="
        << target.threadId
        << eol;
}

QString ProcessDetailWindow::resolveSelectedThreadModulePathForUpload(QString* errorTextOut) const
{
    // 输入：线程表当前行和最近一次线程/模块刷新缓存。
    // 处理：从 ThreadInspectItem 取 startAddress/win32StartAddress，按模块基址+大小做范围匹配。
    // 返回：命中的模块路径；失败时返回空字符串且 errorTextOut 包含给用户看的原因。
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    if (m_threadInspectTable == nullptr || !m_threadInspectPublishedRows)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("线程表尚未初始化。");
        }
        return QString();
    }

    const int currentRow = m_threadInspectTable->currentRow();
    if (currentRow < 0)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("请先选择一个线程。");
        }
        return QString();
    }

    const QModelIndex threadIdItem = m_threadInspectTable->model()->index(
        currentRow,
        toThreadColumnIndex(ThreadRowColumn::ThreadId));
    if (!threadIdItem.isValid())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("当前线程行缺少 ThreadID。");
        }
        return QString();
    }

    const std::size_t cacheIndex = static_cast<std::size_t>(threadIdItem.data(Qt::UserRole).toULongLong());
    const std::uint32_t selectedTid = static_cast<std::uint32_t>(threadIdItem.data(Qt::UserRole + 1).toUInt());
    const ThreadInspectItem* selectedThread = nullptr;
    if (cacheIndex < m_threadInspectPublishedRows->size())
    {
        selectedThread = &(*m_threadInspectPublishedRows)[cacheIndex];
    }
    if (selectedThread == nullptr || selectedThread->threadId != selectedTid)
    {
        const auto foundIt = std::find_if(
            m_threadInspectPublishedRows->begin(),
            m_threadInspectPublishedRows->end(),
            [selectedTid](const ThreadInspectItem& rowItem)
            {
                return rowItem.threadId == selectedTid;
            });
        if (foundIt != m_threadInspectPublishedRows->end())
        {
            selectedThread = &(*foundIt);
        }
    }
    if (selectedThread == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("线程缓存已过期，请先刷新线程列表。");
        }
        return QString();
    }
    if ((!m_moduleRecords || m_moduleRecords->empty()))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("模块缓存为空，请先刷新“模块”页后再上传线程模块。");
        }
        return QString();
    }

    const std::uint64_t addressCandidates[] =
    {
        selectedThread->win32StartAddress,
        selectedThread->startAddress
    };
    for (const std::uint64_t addressValue : addressCandidates)
    {
        if (addressValue == 0)
        {
            continue;
        }

        for (const ModuleRowValue& moduleValue : *m_moduleRecords)
        {
            const auto& moduleRecord = moduleValue.record;
            if (moduleRecord.moduleBaseAddress == 0 || moduleRecord.moduleSizeBytes == 0)
            {
                continue;
            }

            const std::uint64_t moduleEnd =
                moduleRecord.moduleBaseAddress + static_cast<std::uint64_t>(moduleRecord.moduleSizeBytes);
            if (addressValue >= moduleRecord.moduleBaseAddress && addressValue < moduleEnd)
            {
                const QString modulePath = QString::fromStdString(moduleRecord.modulePath).trimmed();
                if (!modulePath.isEmpty())
                {
                    return modulePath;
                }
            }
        }
    }

    if (errorTextOut != nullptr)
    {
        *errorTextOut = QStringLiteral("无法根据线程起始地址解析所属模块；不会回退上传进程 EXE。");
    }
    return QString();
}
