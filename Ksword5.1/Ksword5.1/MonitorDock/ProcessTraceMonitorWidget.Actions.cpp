#include "../UI/KeyboardItemActivation.h"
#include "MonitorEventFilterProjection.h"
#include "ProcessTraceMonitorWidget.h"
#include "../UI/TableContextMenu.h"
#include "../UI/TableSearchSupport.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/ThemeStatusRole.h"

// ============================================================
// ProcessTraceMonitorWidget.Actions.cpp
// 作用：
// 1) 实现进程目标选择、事件筛选、导出与右键菜单；
// 2) 把所有 UI 交互集中在独立文件，避免与 ETW 采集逻辑耦合；
// 3) 统一在主线程更新表格与状态文本，保证界面稳定。
// ============================================================

#include <QApplication>
#include <QAbstractItemModel>
#include <QBrush>
#include <QCheckBox>
#include <QColor>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSet>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <set>
#include <tuple>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    // 事件行缓存角色：
    // - 作用：把筛选常用的拼接文本缓存到首列 item，减少每轮筛选重复拼接字符串；
    // - 调用：appendEventRow 写入，applyEventFilter 读取。
    constexpr int kEventRoleGlobalSearchText = Qt::UserRole;
    constexpr int kEventRoleProcessSearchText = Qt::UserRole + 1;
    constexpr int kEventRoleEventSearchText = Qt::UserRole + 2;
    constexpr int kEventRoleTime100nsValue = Qt::UserRole + 3;

    // tableRowAsTsv：
    // - 作用：把任意只读表格的一行转换成 TSV 文本；
    // - 入参 tableWidget/rowIndex：目标表格与行号；
    // - 返回：行号非法时返回空串，合法时返回当前可见列文本。
    QString tableRowAsTsv(const QTableWidget* tableWidget, const int rowIndex)
    {
        if (tableWidget == nullptr || rowIndex < 0 || rowIndex >= tableWidget->rowCount())
        {
            return QString();
        }

        QStringList cellTextList;
        cellTextList.reserve(tableWidget->columnCount());
        for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* itemPointer = tableWidget->item(rowIndex, columnIndex);
            cellTextList << (itemPointer != nullptr ? itemPointer->text() : QString());
        }
        return cellTextList.join('\t');
    }

    // selectedTableRows：
    // - 作用：从 QTableWidget 当前选择中提取唯一行号；
    // - 入参 tableWidget：目标表格；
    // - 返回：升序行号列表，用于复制多行或判断菜单启用状态。
    std::vector<int> selectedTableRows(const QTableWidget* tableWidget)
    {
        std::vector<int> rowList;
        if (tableWidget == nullptr)
        {
            return rowList;
        }

        std::set<int> rowSet;
        const QList<QTableWidgetItem*> itemList = tableWidget->selectedItems();
        for (const QTableWidgetItem* itemPointer : itemList)
        {
            if (itemPointer != nullptr)
            {
                rowSet.insert(itemPointer->row());
            }
        }

        rowList.assign(rowSet.begin(), rowSet.end());
        return rowList;
    }

    // copyTableRowsToClipboard：
    // - 作用：把若干表格行复制到系统剪贴板；
    // - 入参 tableWidget/rowList：目标表格与待复制行；
    // - 返回：无。空列表时保持剪贴板不变，避免误清用户内容。
    void copyTableRowsToClipboard(const QTableWidget* tableWidget, const std::vector<int>& rowList)
    {
        if (tableWidget == nullptr || rowList.empty())
        {
            return;
        }

        QStringList lineList;
        for (const int rowIndex : rowList)
        {
            const QString rowText = tableRowAsTsv(tableWidget, rowIndex);
            if (!rowText.isEmpty())
            {
                lineList << rowText;
            }
        }

        if (!lineList.isEmpty())
        {
            QApplication::clipboard()->setText(lineList.join('\n'));
        }
    }

    // queryLightweightProcessPath：
    // - 作用：只查询当前页面展示需要的进程路径；
    // - 与完整静态详情不同，这里不读取命令行/签名等高成本字段。
    QString queryLightweightProcessPath(const HANDLE processHandle)
    {
        std::vector<wchar_t> pathBuffer(32768, L'\0');
        DWORD pathLength = static_cast<DWORD>(pathBuffer.size());
        if (::QueryFullProcessImageNameW(processHandle, 0, pathBuffer.data(), &pathLength) == FALSE
            || pathLength == 0)
        {
            return QString();
        }

        return QString::fromWCharArray(pathBuffer.data(), static_cast<int>(pathLength));
    }

    // queryLightweightProcessUser：
    // - 作用：以最小权限读取进程所属用户；
    // - 仅服务于监控页表格展示，不做额外令牌分析。
    QString queryLightweightProcessUser(const HANDLE processHandle)
    {
        HANDLE processToken = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &processToken) == FALSE)
        {
            return QString();
        }

        DWORD requiredLength = 0;
        ::GetTokenInformation(processToken, TokenUser, nullptr, 0, &requiredLength);
        if (requiredLength == 0)
        {
            ::CloseHandle(processToken);
            return QString();
        }

        std::vector<BYTE> tokenBuffer(requiredLength, 0);
        if (::GetTokenInformation(
            processToken,
            TokenUser,
            tokenBuffer.data(),
            requiredLength,
            &requiredLength) == FALSE)
        {
            ::CloseHandle(processToken);
            return QString();
        }
        ::CloseHandle(processToken);

        const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.data());
        if (tokenUser == nullptr || tokenUser->User.Sid == nullptr)
        {
            return QString();
        }

        DWORD nameLength = 0;
        DWORD domainLength = 0;
        SID_NAME_USE sidType = SidTypeUnknown;
        ::LookupAccountSidW(nullptr, tokenUser->User.Sid, nullptr, &nameLength, nullptr, &domainLength, &sidType);
        if (nameLength == 0)
        {
            return QString();
        }

        std::vector<wchar_t> nameBuffer(nameLength, L'\0');
        std::vector<wchar_t> domainBuffer(domainLength > 0 ? domainLength : 1, L'\0');
        if (::LookupAccountSidW(
            nullptr,
            tokenUser->User.Sid,
            nameBuffer.data(),
            &nameLength,
            domainBuffer.data(),
            &domainLength,
            &sidType) == FALSE)
        {
            return QString();
        }

        const QString accountName = QString::fromWCharArray(nameBuffer.data());
        const QString domainName = domainLength > 0
            ? QString::fromWCharArray(domainBuffer.data())
            : QString();
        if (accountName.isEmpty())
        {
            return QString();
        }

        return domainName.isEmpty()
            ? accountName
            : QStringLiteral("%1\\%2").arg(domainName, accountName);
    }

    // fillLightweightMonitorProcessRecord：
    // - 作用：给监控页所需的轻量字段补值；
    // - 只补路径/用户/创建时间/名称，不触发完整静态详情查询。
    bool fillLightweightMonitorProcessRecord(ks::process::ProcessRecord* recordPointer)
    {
        if (recordPointer == nullptr || recordPointer->pid == 0)
        {
            return false;
        }

        if (!recordPointer->imagePath.empty()
            && !recordPointer->userName.empty()
            && recordPointer->creationTime100ns != 0)
        {
            return true;
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(recordPointer->pid));
        if (processHandle == nullptr)
        {
            return false;
        }

        if (recordPointer->imagePath.empty())
        {
            recordPointer->imagePath = queryLightweightProcessPath(processHandle).toUtf8().toStdString();
        }
        if (recordPointer->userName.empty())
        {
            recordPointer->userName = queryLightweightProcessUser(processHandle).toUtf8().toStdString();
        }
        if (recordPointer->creationTime100ns == 0)
        {
            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE)
            {
                ULARGE_INTEGER creationTimeValue{};
                creationTimeValue.LowPart = creationTime.dwLowDateTime;
                creationTimeValue.HighPart = creationTime.dwHighDateTime;
                recordPointer->creationTime100ns = static_cast<std::uint64_t>(creationTimeValue.QuadPart);
            }
        }
        ::CloseHandle(processHandle);

        if (recordPointer->processName.empty() && !recordPointer->imagePath.empty())
        {
            const QString pathText = QString::fromUtf8(recordPointer->imagePath.c_str());
            const int slashIndex = std::max(pathText.lastIndexOf('/'), pathText.lastIndexOf('\\'));
            const QString fileNameText = slashIndex >= 0 ? pathText.mid(slashIndex + 1) : pathText;
            recordPointer->processName = fileNameText.toUtf8().toStdString();
        }

        return !recordPointer->imagePath.empty()
            || !recordPointer->userName.empty()
            || recordPointer->creationTime100ns != 0;
    }

    // buildLightweightMonitorProcessRecord：
    // - 作用：按 PID 构造监控页可展示的最小进程记录；
    // - 若无法访问，则至少保留 PID 文本占位。
    ks::process::ProcessRecord buildLightweightMonitorProcessRecord(const std::uint32_t pidValue)
    {
        ks::process::ProcessRecord record;
        record.pid = pidValue;
        fillLightweightMonitorProcessRecord(&record);
        if (record.processName.empty())
        {
            record.processName = "PID_" + std::to_string(pidValue);
        }
        return record;
    }

    // SuspendedTargetDialogInput：创建并挂起监控目标弹窗的收集结果。
    struct SuspendedTargetDialogInput
    {
        QString imagePath;
        QString argumentText;
        bool runAsAdministrator = false;
    };

    // showSuspendedTargetDialog：显示程序路径、原样参数和管理员选项。
    // 返回 true 表示用户确认创建，false 表示取消，不产生任何进程副作用。
    bool showSuspendedTargetDialog(
        QWidget* const parentWidget,
        SuspendedTargetDialogInput* const inputOut)
    {
        if (inputOut == nullptr)
        {
            return false;
        }

        QDialog dialog(parentWidget);
        dialog.setWindowTitle(QStringLiteral("创建并挂起监控目标"));
        dialog.setModal(true);
        dialog.setMinimumWidth(560);

        QVBoxLayout* rootLayout = new QVBoxLayout(&dialog);
        ks::ui::StyleSecondaryWindow(&dialog);
        ks::ui::StyleSecondaryContentLayout(rootLayout);

        QFormLayout* formLayout = new QFormLayout();
        formLayout->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        formLayout->setHorizontalSpacing(10);
        formLayout->setVerticalSpacing(8);

        QLineEdit* imagePathEdit = new QLineEdit(&dialog);
        imagePathEdit->setPlaceholderText(QStringLiteral("选择要创建的可执行文件"));
        imagePathEdit->setClearButtonEnabled(true);

        QPushButton* browseButton = new QPushButton(QStringLiteral("浏览…"), &dialog);
        QHBoxLayout* imagePathLayout = new QHBoxLayout();
        imagePathLayout->setContentsMargins(0, 0, 0, 0);
        imagePathLayout->setSpacing(6);
        imagePathLayout->addWidget(imagePathEdit, 1);
        imagePathLayout->addWidget(browseButton, 0);

        QWidget* imagePathWidget = new QWidget(&dialog);
        imagePathWidget->setLayout(imagePathLayout);
        formLayout->addRow(QStringLiteral("程序路径:"), imagePathWidget);

        QLineEdit* argumentEdit = new QLineEdit(&dialog);
        argumentEdit->setPlaceholderText(QStringLiteral("将按原样传递给目标进程"));
        argumentEdit->setClearButtonEnabled(true);
        formLayout->addRow(QStringLiteral("进程参数（可选）"), argumentEdit);

        QCheckBox* runAsAdministratorCheck = new QCheckBox(QStringLiteral("以管理员运行"), &dialog);
        formLayout->addRow(QString(), runAsAdministratorCheck);
        rootLayout->addLayout(formLayout);
        ks::ui::StyleSecondaryForm(formLayout);
        ks::ui::NormalizeToolbarRow(imagePathLayout);
        rootLayout->addStretch(1);

        QDialogButtonBox* buttonBox = new QDialogButtonBox(&dialog);
        QPushButton* createButton = buttonBox->addButton(
            QStringLiteral("创建并挂起"),
            QDialogButtonBox::AcceptRole);
        buttonBox->addButton(QStringLiteral("取消"), QDialogButtonBox::RejectRole);
        rootLayout->addWidget(buttonBox);
        ks::ui::StyleSecondaryButtonBox(buttonBox);

        QObject::connect(browseButton, &QPushButton::clicked, &dialog, [&dialog, imagePathEdit]() {
            const QString imagePath = QFileDialog::getOpenFileName(
                &dialog,
                QStringLiteral("选择可执行文件"),
                imagePathEdit->text().trimmed(),
                QStringLiteral("可执行文件 (*.exe);;所有文件 (*.*)"));
            if (!imagePath.isEmpty())
            {
                imagePathEdit->setText(QDir::toNativeSeparators(imagePath));
            }
        });
        QObject::connect(createButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

        if (dialog.exec() != QDialog::Accepted)
        {
            return false;
        }

        inputOut->imagePath = imagePathEdit->text().trimmed();
        inputOut->argumentText = argumentEdit->text();
        inputOut->runAsAdministrator = runAsAdministratorCheck->isChecked();
        return true;
    }
}

void ProcessTraceMonitorWidget::initializeConnections()
{
    // 可选进程区交互：
    // - 支持关键词过滤、刷新进程快照、双击添加和手动 PID 添加；
    // - 这些动作仅在未运行监控时允许变更目标集合。
    if (m_availableFilterEdit != nullptr)
    {
        connect(m_availableFilterEdit, &QLineEdit::textChanged, this, [this]() {
            applyAvailableProcessFilter();
        });
    }

    if (m_availableRefreshButton != nullptr)
    {
        connect(m_availableRefreshButton, &QPushButton::clicked, this, [this]() {
            kLogEvent event;
            info << event << "[ProcessTraceMonitorWidget] 用户请求刷新可选进程列表。" << eol;
            refreshAvailableProcessListAsync();
        });
    }

    if (m_createTargetButton != nullptr)
    {
        connect(m_createTargetButton, &QPushButton::clicked, this, [this]() {
            createSuspendedTargetProcess();
        });
    }

    if (m_addSelectedButton != nullptr)
    {
        connect(m_addSelectedButton, &QPushButton::clicked, this, [this]() {
            addSelectedAvailableProcesses();
        });
    }

    if (m_addManualPidButton != nullptr)
    {
        connect(m_addManualPidButton, &QPushButton::clicked, this, [this]() {
            addManualProcessByPid();
        });
    }

    if (m_manualPidEdit != nullptr)
    {
        connect(m_manualPidEdit, &QLineEdit::returnPressed, this, [this]() {
            addManualProcessByPid();
        });
    }

    if (m_availableTable != nullptr)
    {
        connect(m_availableTable, &QTableWidget::itemSelectionChanged, this, [this]() {
            updateActionState();
        });
        ks::ui::InstallKeyboardItemActivation(m_availableTable);
        connect(m_availableTable, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem*) {
            addSelectedAvailableProcesses();
        });
        connect(m_availableTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
            showAvailableContextMenu(position);
        });
    }

    // 监控目标区交互：
    // - 允许移除选中项或一次性清空；
    // - 每次变更目标列表后都会刷新目标表与总状态栏。
    if (m_removeTargetButton != nullptr)
    {
        connect(m_removeTargetButton, &QPushButton::clicked, this, [this]() {
            removeSelectedTargetProcesses();
        });
    }

    if (m_clearTargetButton != nullptr)
    {
        connect(m_clearTargetButton, &QPushButton::clicked, this, [this]() {
            clearTargetProcesses();
        });
    }

    if (m_targetTable != nullptr)
    {
        connect(m_targetTable, &QTableWidget::itemSelectionChanged, this, [this]() {
            updateActionState();
        });
        connect(m_targetTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
            showTargetContextMenu(position);
        });
    }

    // 控制栏交互：
    // - 开始/停止/暂停均走独立方法，便于后续插入日志与线程控制；
    // - 导出按钮只导出当前可见结果，方便围绕筛选结果做落盘。
    if (m_startButton != nullptr)
    {
        connect(m_startButton, &QPushButton::clicked, this, [this]() {
            startMonitoring();
        });
    }

    if (m_stopButton != nullptr)
    {
        connect(m_stopButton, &QPushButton::clicked, this, [this]() {
            stopMonitoring();
        });
    }

    if (m_pauseButton != nullptr)
    {
        connect(m_pauseButton, &QPushButton::clicked, this, [this]() {
            if (!m_capture->m_capturePaused.load())
            {
                setMonitoringPaused(true);
            }
        });
    }

    if (m_exportButton != nullptr)
    {
        connect(m_exportButton, &QPushButton::clicked, this, [this]() {
            exportVisibleRowsToTsv();
        });
    }

    // 事件筛选交互：
    // - 类型下拉与各文本框变化后统一实时重算可见行；
    // - 正则/大小写/反向也复用同一筛选入口。
    if (m_eventTypeCombo != nullptr)
    {
        connect(m_eventTypeCombo, &QComboBox::currentTextChanged, this, [this]() {
            scheduleEventFilterApply();
        });
    }

    const auto bindEventFilterEdit = [this](QLineEdit* editPointer) {
        if (editPointer == nullptr)
        {
            return;
        }
        connect(editPointer, &QLineEdit::textChanged, this, [this]() {
            scheduleEventFilterApply();
        });
    };
    bindEventFilterEdit(m_eventProviderFilterEdit);
    bindEventFilterEdit(m_eventProcessFilterEdit);
    bindEventFilterEdit(m_eventNameFilterEdit);
    bindEventFilterEdit(m_eventDetailFilterEdit);
    bindEventFilterEdit(m_eventGlobalFilterEdit);

    if (m_eventRegexCheck != nullptr)
    {
        connect(m_eventRegexCheck, &QCheckBox::toggled, this, [this]() {
            scheduleEventFilterApply();
        });
    }
    if (m_eventCaseCheck != nullptr)
    {
        connect(m_eventCaseCheck, &QCheckBox::toggled, this, [this]() {
            scheduleEventFilterApply();
        });
    }
    if (m_eventInvertCheck != nullptr)
    {
        connect(m_eventInvertCheck, &QCheckBox::toggled, this, [this]() {
            scheduleEventFilterApply();
        });
    }
    if (m_eventClearFilterButton != nullptr)
    {
        connect(m_eventClearFilterButton, &QPushButton::clicked, this, [this]() {
            clearEventFilter();
        });
    }

    if (m_eventTable != nullptr)
    {
        connect(m_eventTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
            showEventContextMenu(position);
        });
        ks::ui::InstallKeyboardItemActivation(m_eventTable);
        connect(m_eventTable, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* itemPointer) {
            if (itemPointer == nullptr)
            {
                return;
            }
            openEventDetailViewerForRow(itemPointer->row());
        });
    }

    if (m_eventTimelineWidget != nullptr)
    {
        m_eventTimelineWidget->setSelectionChangedCallback(
            [this](const std::uint64_t start100ns, const std::uint64_t end100ns) {
                applyTimelineSelection(start100ns, end100ns);
            });
    }

    // 定时器：
    // - UI 刷新定时器把后台采集线程积攒的事件批量刷入表格；
    // - 运行期快照定时器用于补做进程树修正，是 ETW 之外的辅助链路。
    if (m_uiUpdateTimer != nullptr)
    {
        connect(m_uiUpdateTimer, &QTimer::timeout, this, [this]() {
            flushPendingRows();
        });
    }

    if (m_eventFilterDebounceTimer != nullptr)
    {
        connect(m_eventFilterDebounceTimer, &QTimer::timeout, this, [this]() {
            applyEventFilter();
        });
    }

    if (m_runtimeRefreshTimer != nullptr)
    {
        connect(m_runtimeRefreshTimer, &QTimer::timeout, this, [this]() {
            refreshTrackedProcessSnapshotAsync();
        });
    }
}

void ProcessTraceMonitorWidget::refreshAvailableProcessListAsync()
{
    if (m_availableRefreshPending.exchange(true))
    {
        return;
    }

    if (m_availableStatusLabel != nullptr)
    {
        m_availableStatusLabel->setText(QStringLiteral("● 正在刷新当前系统进程快照..."));
        ks::ui::ApplyStatusRole(m_availableStatusLabel, ks::ui::StatusRole::Info);
    }
    updateActionState();

    QPointer<ProcessTraceMonitorWidget> guardThis(this);
    const auto dispatcher = m_uiDispatcher;
    std::thread([guardThis, dispatcher]() {
        std::vector<ks::process::ProcessRecord> processList = ks::process::EnumerateProcesses(
            ks::process::ProcessEnumStrategy::Auto);

        for (ks::process::ProcessRecord& record : processList)
        {
            fillLightweightMonitorProcessRecord(&record);
        }

        std::sort(
            processList.begin(),
            processList.end(),
            [](const ks::process::ProcessRecord& left, const ks::process::ProcessRecord& right) {
                return left.pid < right.pid;
            });

        dispatcher->post([guardThis, processList = std::move(processList)]() {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->m_availableRefreshPending.store(false);
            guardThis->populateAvailableProcessTable(processList);
            guardThis->updateActionState();
        });
    }).detach();
}

void ProcessTraceMonitorWidget::populateAvailableProcessTable(const std::vector<ks::process::ProcessRecord>& processList)
{
    m_availableProcessList = processList;
    if (m_availableTable == nullptr)
    {
        return;
    }

    m_availableTable->setSortingEnabled(false);
    m_availableTable->clearContents();
    m_availableTable->setRowCount(static_cast<int>(m_availableProcessList.size()));

    for (int row = 0; row < static_cast<int>(m_availableProcessList.size()); ++row)
    {
        const ks::process::ProcessRecord& record = m_availableProcessList[static_cast<std::size_t>(row)];
        m_availableTable->setItem(row, AvailableProcessColumnPid, createReadOnlyItem(QString::number(record.pid)));
        m_availableTable->setItem(
            row,
            AvailableProcessColumnName,
            createReadOnlyItem(QString::fromStdString(record.processName.empty() ? std::string("<Unknown>") : record.processName)));
        m_availableTable->setItem(
            row,
            AvailableProcessColumnPath,
            createReadOnlyItem(QString::fromStdString(record.imagePath)));
        m_availableTable->setItem(
            row,
            AvailableProcessColumnUser,
            createReadOnlyItem(QString::fromStdString(record.userName)));
    }

    m_availableTable->setSortingEnabled(true);
    applyAvailableProcessFilter();

    if (m_availableStatusLabel != nullptr)
    {
        m_availableStatusLabel->setText(QStringLiteral("● 已刷新 %1 个进程").arg(m_availableProcessList.size()));
        ks::ui::ApplyStatusRole(m_availableStatusLabel, ks::ui::StatusRole::Success);
    }
}

void ProcessTraceMonitorWidget::applyAvailableProcessFilter()
{
    if (m_availableTable == nullptr)
    {
        return;
    }

    const QString keywordText = m_availableFilterEdit != nullptr
        ? m_availableFilterEdit->text().trimmed()
        : QString();

    int visibleRowCount = 0;
    QSet<QPersistentModelIndex> excluded;
    for (int row = 0; row < m_availableTable->rowCount(); ++row)
    {
        QStringList rowTextList;
        for (int column = 0; column < AvailableProcessColumnCount; ++column)
        {
            QTableWidgetItem* itemPointer = m_availableTable->item(row, column);
            rowTextList << (itemPointer != nullptr ? itemPointer->text() : QString());
        }

        const QString mergedText = rowTextList.join(QStringLiteral(" | "));
        const bool visible = keywordText.isEmpty()
            || mergedText.contains(keywordText, Qt::CaseInsensitive);
        if (!visible) excluded.insert(QPersistentModelIndex(m_availableTable->model()->index(row, 0, m_availableTable->rootIndex())));
        if (visible)
        {
            ++visibleRowCount;
        }
    }

    if (m_availableStatusLabel != nullptr)
    {
        m_availableStatusLabel->setText(
            QStringLiteral("● 可见 %1 / %2 个进程")
            .arg(visibleRowCount)
            .arg(m_availableTable->rowCount()));
        ks::ui::ApplyStatusRole(m_availableStatusLabel, ks::ui::StatusRole::Idle);
    }
    ks::ui::ApplyTableRowFilterIncrementally(m_availableTable, excluded);
}

void ProcessTraceMonitorWidget::addSelectedAvailableProcesses()
{
    if (m_availableTable == nullptr)
    {
        return;
    }

    std::set<int> selectedRowSet;
    const QList<QTableWidgetItem*> itemList = m_availableTable->selectedItems();
    for (QTableWidgetItem* itemPointer : itemList)
    {
        if (itemPointer != nullptr)
        {
            selectedRowSet.insert(itemPointer->row());
        }
    }

    if (selectedRowSet.empty())
    {
        return;
    }

    int addedCount = 0;
    for (const int row : selectedRowSet)
    {
        QTableWidgetItem* pidItem = m_availableTable->item(row, AvailableProcessColumnPid);
        std::uint32_t pidValue = 0;
        if (pidItem == nullptr || !tryParseUint32Text(pidItem->text(), &pidValue))
        {
            continue;
        }

        const std::size_t beforeSize = m_targetProcessList.size();
        addTargetProcessByPid(pidValue, QStringLiteral("来自可选进程列表"));
        if (m_targetProcessList.size() > beforeSize)
        {
            ++addedCount;
        }
    }

    kLogEvent event;
    info << event
        << "[ProcessTraceMonitorWidget] 批量添加监控目标完成, selectedRows="
        << selectedRowSet.size()
        << ", addedCount="
        << addedCount
        << eol;
}

void ProcessTraceMonitorWidget::addManualProcessByPid()
{
    if (m_manualPidEdit == nullptr)
    {
        return;
    }

    std::uint32_t pidValue = 0;
    if (!tryParseUint32Text(m_manualPidEdit->text(), &pidValue))
    {
        QMessageBox::information(this, QStringLiteral("添加监控目标"), QStringLiteral("请输入有效的 PID。"));
        return;
    }

    addTargetProcessByPid(pidValue, QStringLiteral("手动输入 PID"));
}

void ProcessTraceMonitorWidget::createSuspendedTargetProcess()
{
    // 运行期不接受修改根目标集合，和现有“手动添加 / 批量添加”保持同一约束。
    if (m_capture->m_captureRunning.load())
    {
        return;
    }

    SuspendedTargetDialogInput dialogInput;
    if (!showSuspendedTargetDialog(this, &dialogInput))
    {
        return;
    }

    if (dialogInput.imagePath.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("创建并挂起监控目标"), QStringLiteral("程序路径不能为空。"));
        return;
    }

    const QFileInfo imageInfo(dialogInput.imagePath);
    if (!imageInfo.exists() || !imageInfo.isFile())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("创建并挂起监控目标"),
            QStringLiteral("程序路径无效或不是文件：%1").arg(dialogInput.imagePath));
        return;
    }

    const auto launchTarget = [this, &dialogInput, &imageInfo](const bool allowElevatedFallback) {
        ks::process::SuspendedProcessLaunchRequest request;
        request.imagePath = QDir::toNativeSeparators(imageInfo.absoluteFilePath()).toUtf8().toStdString();
        request.argumentText = dialogInput.argumentText.toUtf8().toStdString();
        request.workingDirectory = QDir::toNativeSeparators(imageInfo.absolutePath()).toUtf8().toStdString();
        request.runAsAdministrator = dialogInput.runAsAdministrator;
        request.allowElevatedFallback = allowElevatedFallback;

        ks::process::SuspendedProcessLaunchResult launchResult;
        const bool launchOk = ks::process::LaunchSuspendedProcess(request, &launchResult);
        return std::pair<bool, ks::process::SuspendedProcessLaunchResult>(launchOk, std::move(launchResult));
    };

    auto [launchOk, launchResult] = launchTarget(false);
    if (!launchOk && launchResult.failure == ks::process::SuspendedProcessLaunchFailure::AdministratorRequired)
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("以管理员权限创建并挂起监控目标"));
        return;
    }

    if (!launchOk && launchResult.failure == ks::process::SuspendedProcessLaunchFailure::UnelevatedTokenUnavailable)
    {
        QMessageBox fallbackDialog(this);
        fallbackDialog.setWindowTitle(QStringLiteral("普通权限令牌不可用"));
        fallbackDialog.setIcon(QMessageBox::Warning);
        fallbackDialog.setText(
            QStringLiteral("无法将目标降级为普通权限：%1\n\n是否继续以管理员权限创建？")
            .arg(QString::fromUtf8(launchResult.detailText.c_str())));
        QPushButton* continueButton = fallbackDialog.addButton(
            QStringLiteral("继续以管理员权限创建"),
            QMessageBox::AcceptRole);
        fallbackDialog.addButton(QStringLiteral("取消"), QMessageBox::RejectRole);
        fallbackDialog.exec();
        if (fallbackDialog.clickedButton() != continueButton)
        {
            return;
        }

        std::tie(launchOk, launchResult) = launchTarget(true);
    }

    if (!launchOk)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("创建进程失败"),
            QStringLiteral("创建并挂起目标进程失败：%1")
            .arg(QString::fromUtf8(launchResult.detailText.c_str())));
        return;
    }

    const QString processName = imageInfo.fileName().isEmpty()
        ? QStringLiteral("<Unknown>")
        : imageInfo.fileName();
    const QString privilegeText = launchResult.usedUnelevatedToken
        || (!dialogInput.runAsAdministrator && !launchResult.usedElevatedFallback)
        ? QStringLiteral("普通权限")
        : QStringLiteral("管理员权限");
    const QString initialRemark = QStringLiteral("定向创建（已挂起，%1）").arg(privilegeText);
    addTargetProcessByPid(launchResult.processId, initialRemark);

    const int progressTaskId = kPro.add(
        this,
        QStringLiteral("创建并挂起目标进程").toUtf8().toStdString(),
        QStringLiteral("已加入监控目标，等待选择").toUtf8().toStdString());
    kPro.set(
        progressTaskId,
        QStringLiteral("目标 PID=%1，%2 已创建并保持挂起").arg(launchResult.processId).arg(processName).toUtf8().toStdString(),
        0,
        40.0f);

    QString choicePrompt = QStringLiteral(
        "对于进程 pid:%1，%2，请明确选择恢复进程并继续追踪，或终止进程并放弃追踪。关闭窗口只会取消本次选择，不会丢失恢复句柄。")
        .arg(launchResult.processId)
        .arg(processName);
    const std::string resumeOptionText =
        QStringLiteral("选项 1：恢复进程并继续追踪").toUtf8().toStdString();
    const std::string terminateOptionText =
        QStringLiteral("选项 2：终止进程并放弃追踪").toUtf8().toStdString();

    // 初始线程句柄所有权：
    // - 只有 ResumeThread 或 TerminateProcess 成功后才关闭；
    // - 关闭选项窗口、恢复失败或终止失败都返回选择循环，保证仍可重试；
    // - 因此任何正常 UI 退出路径都不会留下失去恢复句柄的 CREATE_SUSPENDED 进程。
    for (;;)
    {
        const int selectedOption = kPro.UI(
            progressTaskId,
            choicePrompt.toUtf8().toStdString(),
            resumeOptionText,
            terminateOptionText);

        if (selectedOption == 0)
        {
            updateTargetProcessRemarkByPid(
                launchResult.processId,
                QStringLiteral("选择已取消，目标仍挂起且恢复句柄已保留"));
            kPro.set(
                progressTaskId,
                QStringLiteral("已取消本次选择；目标仍挂起，可继续选择恢复或终止").toUtf8().toStdString(),
                0,
                40.0f);
            choicePrompt = QStringLiteral(
                "已取消关闭选项窗口。进程 pid:%1 仍处于挂起状态，恢复句柄已保留；请选择恢复进程或终止进程。")
                .arg(launchResult.processId);
            continue;
        }

        if (selectedOption == 1)
        {
            std::string resumeError;
            const bool resumeOk = ks::process::ResumeSuspendedProcessInitialThread(
                launchResult.initialThreadHandle,
                &resumeError);
            if (!resumeOk)
            {
                const QString errorText = QString::fromUtf8(resumeError.c_str());
                updateTargetProcessRemarkByPid(
                    launchResult.processId,
                    QStringLiteral("恢复失败，目标仍挂起且句柄已保留：%1").arg(errorText));
                kPro.set(
                    progressTaskId,
                    QStringLiteral("恢复失败；句柄已保留，可重试恢复或终止").toUtf8().toStdString(),
                    0,
                    90.0f);
                choicePrompt = QStringLiteral(
                    "恢复进程 pid:%1 失败：%2\n\n目标仍处于挂起状态，恢复句柄已保留；请选择重试恢复或终止进程。")
                    .arg(launchResult.processId)
                    .arg(errorText);
                QMessageBox::warning(
                    this,
                    QStringLiteral("恢复新建目标失败"),
                    choicePrompt);
                continue;
            }

            ks::process::CloseSuspendedProcessInitialThreadHandle(
                launchResult.initialThreadHandle);
            ks::process::CloseSuspendedProcessHandle(
                launchResult.processHandle);
            updateTargetProcessRemarkByPid(
                launchResult.processId,
                QStringLiteral("已恢复，等待手动开始监听"));
            kPro.set(
                progressTaskId,
                QStringLiteral("已取消挂起，等待手动开始监听").toUtf8().toStdString(),
                0,
                100.0f);
            kLogEvent event;
            info << event
                << "[ProcessTraceMonitorWidget] 已创建并恢复监控目标, pid="
                << launchResult.processId
                << ", process="
                << processName.toStdString()
                << eol;
            break;
        }

        if (selectedOption == 2)
        {
            std::string terminateError;
            const bool terminateOk = ks::process::TerminateSuspendedProcessByHandle(
                launchResult.processHandle,
                &terminateError);
            if (!terminateOk)
            {
                const QString errorText = QString::fromUtf8(terminateError.c_str());
                updateTargetProcessRemarkByPid(
                    launchResult.processId,
                    QStringLiteral("终止失败，目标仍挂起且句柄已保留：%1").arg(errorText));
                kPro.set(
                    progressTaskId,
                    QStringLiteral("终止失败；句柄已保留，可重试恢复或终止").toUtf8().toStdString(),
                    0,
                    90.0f);
                choicePrompt = QStringLiteral(
                    "终止进程 pid:%1 失败：%2\n\n目标仍处于挂起状态，恢复句柄已保留；请选择恢复进程或重试终止。")
                    .arg(launchResult.processId)
                    .arg(errorText);
                QMessageBox::warning(
                    this,
                    QStringLiteral("终止新建目标失败"),
                    choicePrompt);
                continue;
            }

            ks::process::CloseSuspendedProcessInitialThreadHandle(
                launchResult.initialThreadHandle);
            ks::process::CloseSuspendedProcessHandle(
                launchResult.processHandle);
            removeTrackedProcessFromTargetListByPid(
                launchResult.processId,
                QStringLiteral("用户终止进程并放弃追踪"));
            updateActionState();
            kPro.set(
                progressTaskId,
                QStringLiteral("已终止进程并放弃追踪").toUtf8().toStdString(),
                0,
                100.0f);

            kLogEvent event;
            info << event
                << "[ProcessTraceMonitorWidget] 用户终止新建目标并放弃追踪, pid="
                << launchResult.processId
                << ", process="
                << processName.toStdString()
                << eol;
            break;
        }

        // 未知返回值与关闭窗口同样按取消处理，绝不释放句柄或移除目标。
        kPro.set(
            progressTaskId,
            QStringLiteral("选项返回值无效；目标仍挂起，可继续选择恢复或终止").toUtf8().toStdString(),
            0,
            40.0f);
    }
}

void ProcessTraceMonitorWidget::addTargetProcessByPid(const std::uint32_t pidValue, const QString& sourceText)
{
    if (pidValue == 0)
    {
        return;
    }

    const auto duplicateFound = std::find_if(
        m_targetProcessList.begin(),
        m_targetProcessList.end(),
        [pidValue](const TargetProcessEntry& entry) {
            return entry.pid == pidValue;
        });
    if (duplicateFound != m_targetProcessList.end())
    {
        QMessageBox::information(
            this,
            QStringLiteral("添加监控目标"),
            QStringLiteral("PID=%1 已经在监控目标列表中。").arg(pidValue));
        return;
    }

    TargetProcessEntry targetEntry;
    targetEntry.pid = pidValue;
    targetEntry.remarkText = sourceText;

    const auto found = std::find_if(
        m_availableProcessList.begin(),
        m_availableProcessList.end(),
        [pidValue](const ks::process::ProcessRecord& record) {
            return record.pid == pidValue;
        });

    if (found != m_availableProcessList.end())
    {
        targetEntry.processName = QString::fromStdString(found->processName);
        targetEntry.imagePath = QString::fromStdString(found->imagePath);
        targetEntry.userName = QString::fromStdString(found->userName);
        targetEntry.creationTime100ns = found->creationTime100ns;
        targetEntry.alive = true;
    }
    else
    {
        if (!m_targetLookup) m_targetLookup = new ks::ui::AsyncOperation(this);
        const auto epoch = m_capture;
        const auto ticket = m_targetLookup->submitTransaction<TargetProcessEntry, TargetProcessEntry>(targetEntry,
            [](const TargetProcessEntry& input)
            {
                auto result = input;
                const auto detail = buildLightweightMonitorProcessRecord(input.pid);
                result.processName = QString::fromStdString(detail.processName);
                result.imagePath = QString::fromStdString(detail.imagePath);
                result.userName = QString::fromStdString(detail.userName);
                result.creationTime100ns = detail.creationTime100ns;
                result.alive = !detail.imagePath.empty() || !detail.userName.empty() || detail.creationTime100ns != 0;
                if (!result.alive) result.remarkText += QStringLiteral("；无法读取静态详情");
                return result;
            },
            [this, epoch](const TargetProcessEntry& result, std::uint64_t)
            {
                QTimer::singleShot(0, this, [this]() { updateActionState(); updateStatusLabel(); });
                if (m_capture != epoch || m_capture->m_captureRunning.load()) return true;
                const auto found = std::find_if(m_targetProcessList.begin(), m_targetProcessList.end(), [&result](const auto& value) { return value.pid == result.pid; });
                if (found == m_targetProcessList.end()) m_targetProcessList.push_back(result);
                syncTargetEditsToCapture(); refreshTargetTable(); updateActionState(); updateStatusLabel();
                return true;
            }, [this](std::exception_ptr) { QTimer::singleShot(0, this, [this]() { updateActionState(); updateStatusLabel(); }); });
        if (ticket) updateActionState();
        return;
    }

    m_targetProcessList.push_back(targetEntry);
    syncTargetEditsToCapture(); refreshTargetTable();
    updateActionState();
    updateStatusLabel();

    kLogEvent event;
    info << event
        << "[ProcessTraceMonitorWidget] 添加监控目标, pid="
        << pidValue
        << ", source="
        << sourceText.toStdString()
        << eol;
}

void ProcessTraceMonitorWidget::updateTargetProcessRemarkByPid(
    const std::uint32_t pidValue,
    const QString& remarkText)
{
    const auto found = std::find_if(
        m_targetProcessList.begin(),
        m_targetProcessList.end(),
        [pidValue](const TargetProcessEntry& entry) {
            return entry.pid == pidValue;
        });
    if (found == m_targetProcessList.end())
    {
        return;
    }

    found->remarkText = remarkText;
    syncTargetEditsToCapture(); refreshTargetTable();
    updateActionState();
    updateStatusLabel();
}

void ProcessTraceMonitorWidget::removeTrackedProcessFromTargetListByPid(
    const std::uint32_t pidValue,
    const QString& reasonText)
{
    if (pidValue == 0 || m_targetProcessList.empty())
    {
        return;
    }

    // removeBegin：指向第一个需要删除的条目，用于批量擦除同 PID 记录。
    const auto removeBegin = std::remove_if(
        m_targetProcessList.begin(),
        m_targetProcessList.end(),
        [pidValue](const TargetProcessEntry& entry) {
            return entry.pid == pidValue;
        });
    if (removeBegin == m_targetProcessList.end())
    {
        return;
    }

    const std::size_t removedCount = static_cast<std::size_t>(m_targetProcessList.end() - removeBegin);
    m_targetProcessList.erase(removeBegin, m_targetProcessList.end());

    syncTargetEditsToCapture(); refreshTargetTable();
    updateStatusLabel();

    kLogEvent autoRemoveEvent;
    info << autoRemoveEvent
        << "[ProcessTraceMonitorWidget] 自动取消追踪, pid="
        << pidValue
        << ", removedCount="
        << removedCount
        << ", reason="
        << reasonText.toStdString()
        << eol;
}

void ProcessTraceMonitorWidget::refreshTargetTable()
{
    if (!m_targetTable) return;
    if (!m_targetTable->isVisible()) { m_targetProjectionDirty = true; return; }
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(this, QStringLiteral("process-trace-target-projection"), { m_targetTable }, [this]() { refreshTargetTable(); }))
    { m_targetProjectionDirty = true; return; }
    m_targetProjectionDirty = false;
    constexpr int identityRole = Qt::UserRole + 42;
    const auto identity = [](const TargetProcessEntry& entry) { return QStringLiteral("%1:%2").arg(entry.pid).arg(entry.creationTime100ns); };
    QSet<QString> selectedIdentities;
    for (const auto* item : m_targetTable->selectedItems())
        if (const auto* first = m_targetTable->item(item->row(), 0)) selectedIdentities.insert(first->data(identityRole).toString());
    const bool sorting = m_targetTable->isSortingEnabled();
    m_targetTable->setSortingEnabled(false);
    QSet<QString> retainedKeys;
    for (const auto& entry : m_targetProcessList) retainedKeys.insert(identity(entry));
    // Remove obsolete identities first. A single exit must not move every survivor row.
    for (int row = m_targetTable->rowCount() - 1; row >= 0; --row)
    {
        const auto* first = m_targetTable->item(row, 0);
        if (!first || !retainedKeys.contains(first->data(identityRole).toString())) m_targetTable->removeRow(row);
    }
    int aliveCount = 0;
    for (int row = 0; row < static_cast<int>(m_targetProcessList.size()); ++row)
    {
        const auto& entry = m_targetProcessList[static_cast<std::size_t>(row)];
        const QString key = identity(entry);
        if (row >= m_targetTable->rowCount() || !m_targetTable->item(row, 0) || m_targetTable->item(row, 0)->data(identityRole).toString() != key)
        {
            int sourceRow = row;
            while (sourceRow < m_targetTable->rowCount() && (!m_targetTable->item(sourceRow, 0) || m_targetTable->item(sourceRow, 0)->data(identityRole).toString() != key)) ++sourceRow;
            m_targetTable->insertRow(row);
            if (sourceRow + 1 < m_targetTable->rowCount())
            {
                for (int column = 0; column < TargetProcessColumnCount; ++column)
                    m_targetTable->setItem(row, column, m_targetTable->takeItem(sourceRow + 1, column));
                m_targetTable->removeRow(sourceRow + 1);
            }
        }
        const QStringList cells{ (entry.identityLookupPending || entry.identityLookupInFlight) ? QStringLiteral("核验中") : (entry.alive ? QStringLiteral("运行中") : QStringLiteral("未知/已退出")), QString::number(entry.pid), entry.processName, entry.imagePath, entry.userName, entry.remarkText };
        for (int column = 0; column < TargetProcessColumnCount; ++column)
        {
            auto* item = m_targetTable->item(row, column);
            if (!item) { item = createReadOnlyItem(cells[column]); m_targetTable->setItem(row, column, item); }
            else if (item->text() != cells[column]) item->setText(cells[column]);
            if (selectedIdentities.contains(key)) item->setSelected(true);
        }
        auto* first = m_targetTable->item(row, 0);
        first->setData(identityRole, key);
        const QBrush foreground(entry.alive ? KswordTheme::SuccessColor() : KswordTheme::TextSecondaryColor());
        if (first->foreground() != foreground) first->setForeground(foreground);
        if (entry.alive) ++aliveCount;
    }
    while (m_targetTable->rowCount() > static_cast<int>(m_targetProcessList.size())) m_targetTable->removeRow(m_targetTable->rowCount()-1);
    m_targetTable->setSortingEnabled(sorting);
    if (m_targetStatusLabel != nullptr)
    {
        m_targetStatusLabel->setText(
            QStringLiteral("● 目标 %1 个，其中存活 %2 个")
            .arg(m_targetProcessList.size())
            .arg(aliveCount));
        ks::ui::ApplyStatusRole(m_targetStatusLabel,
            m_targetProcessList.empty()
            ? ks::ui::StatusRole::Idle
            : ks::ui::StatusRole::Success);
    }
}

void ProcessTraceMonitorWidget::removeSelectedTargetProcesses()
{
    if (m_targetTable == nullptr || m_targetProcessList.empty())
    {
        return;
    }

    QSet<QString> selectedKeys;
    for (const auto* item : m_targetTable->selectedItems())
        if (const auto* first = m_targetTable->item(item->row(), 0)) selectedKeys.insert(first->data(Qt::UserRole + 42).toString());
    if (selectedKeys.isEmpty()) return;
    const auto oldSize = m_targetProcessList.size();
    m_targetProcessList.erase(std::remove_if(m_targetProcessList.begin(), m_targetProcessList.end(), [&selectedKeys](const auto& entry)
    { return selectedKeys.contains(QStringLiteral("%1:%2").arg(entry.pid).arg(entry.creationTime100ns)); }), m_targetProcessList.end());
    const auto removedCount = oldSize - m_targetProcessList.size();

    syncTargetEditsToCapture(); refreshTargetTable();
    updateActionState();
    updateStatusLabel();

    kLogEvent event;
    info << event
        << "[ProcessTraceMonitorWidget] 已移除选中监控目标, removedCount="
        << removedCount
        << eol;
}

void ProcessTraceMonitorWidget::clearTargetProcesses()
{
    if (m_targetProcessList.empty())
    {
        return;
    }

    m_targetProcessList.clear();
    syncTargetEditsToCapture(); refreshTargetTable();
    updateActionState();
    updateStatusLabel();

    kLogEvent event;
    info << event << "[ProcessTraceMonitorWidget] 已清空全部监控目标。" << eol;
}

void ProcessTraceMonitorWidget::showAvailableContextMenu(const QPoint& position)
{
    // showAvailableContextMenu：
    // - 输入 position：可选进程表 viewport 坐标；
    // - 处理：同步右键行选择，提供加入目标、复制当前行、复制选中行；
    // - 返回：无。复制动作只写剪贴板，加入目标复用既有业务函数。
    if (m_availableTable == nullptr)
    {
        return;
    }

    const QModelIndex index = m_availableTable->indexAt(position);
    if (index.isValid())
    {
        const int row = index.row();
        if (!m_availableTable->selectionModel()->isRowSelected(row, QModelIndex()))
        {
            m_availableTable->clearSelection();
            m_availableTable->selectRow(row);
        }
        // 右键当前行同步：
        // - 输入：鼠标所在的可选进程行；
        // - 处理：selectRow 只保证选择状态，显式 setCurrentCell 才能让“复制当前行”稳定复制右键行；
        // - 返回：无，后续菜单动作继续走既有只读/加入目标逻辑。
        m_availableTable->setCurrentCell(row, 0);
    }

    const std::vector<int> selectedRows = selectedTableRows(m_availableTable);
    const int currentRow = m_availableTable->currentRow();
    const bool running = m_capture->m_captureRunning.load();

    QMenu menu(this);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* addSelectedAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_start.svg")),
        QStringLiteral("加入监控目标"));
    menu.addSeparator();
    QAction* copyCurrentAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制当前行"));
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copyCurrentAction, ks::ui::TableContextActionRole::CopyRows);
    QAction* copySelectedAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_clipboard.svg")),
        QStringLiteral("复制选中行"));
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copySelectedAction, ks::ui::TableContextActionRole::CopyRows);

    addSelectedAction->setEnabled(!running && !selectedRows.empty());
    copyCurrentAction->setEnabled(currentRow >= 0);
    copySelectedAction->setEnabled(!selectedRows.empty());

    QAction* selectedAction = menu.exec(m_availableTable->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == addSelectedAction)
    {
        addSelectedAvailableProcesses();
        return;
    }

    if (selectedAction == copyCurrentAction)
    {
        copyTableRowsToClipboard(m_availableTable, std::vector<int>{ currentRow });
        return;
    }

    if (selectedAction == copySelectedAction)
    {
        copyTableRowsToClipboard(m_availableTable, selectedRows);
    }
}

void ProcessTraceMonitorWidget::showTargetContextMenu(const QPoint& position)
{
    if (m_targetTable == nullptr)
    {
        return;
    }

    const QModelIndex index = m_targetTable->indexAt(position);
    if (index.isValid())
    {
        const int row = index.row();
        if (!m_targetTable->selectionModel()->isRowSelected(row, QModelIndex()))
        {
            m_targetTable->clearSelection();
            m_targetTable->selectRow(row);
        }
        // 右键当前行同步：
        // - 输入：鼠标所在的监控目标行；
        // - 处理：显式同步 current cell，避免复制当前行时沿用旧焦点行；
        // - 返回：无，不改变监控状态。
        m_targetTable->setCurrentCell(row, 0);
    }

    const std::vector<int> selectedRows = selectedTableRows(m_targetTable);
    const int currentRow = m_targetTable->currentRow();

    QMenu menu(this);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* copyCurrentAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制当前行"));
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copyCurrentAction, ks::ui::TableContextActionRole::CopyRows);
    QAction* copySelectedAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_clipboard.svg")),
        QStringLiteral("复制选中行"));
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copySelectedAction, ks::ui::TableContextActionRole::CopyRows);
    menu.addSeparator();
    QAction* removeSelectedAction = menu.addAction(
        QIcon(":/Icon/process_pause.svg"),
        QStringLiteral("移除选中目标"));
    QAction* clearAllAction = menu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        QStringLiteral("清空全部目标"));

    const bool running = m_capture->m_captureRunning.load();
    copyCurrentAction->setEnabled(currentRow >= 0);
    copySelectedAction->setEnabled(!selectedRows.empty());
    removeSelectedAction->setEnabled(!running && !m_targetTable->selectedItems().isEmpty());
    clearAllAction->setEnabled(!running && !m_targetProcessList.empty());

    QAction* selectedAction = menu.exec(m_targetTable->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == copyCurrentAction)
    {
        copyTableRowsToClipboard(m_targetTable, std::vector<int>{ currentRow });
        return;
    }

    if (selectedAction == copySelectedAction)
    {
        copyTableRowsToClipboard(m_targetTable, selectedRows);
        return;
    }

    if (selectedAction == removeSelectedAction)
    {
        removeSelectedTargetProcesses();
        return;
    }

    if (selectedAction == clearAllAction)
    {
        clearTargetProcesses();
    }
}

void ProcessTraceMonitorWidget::scheduleEventFilterApply()
{
    if (m_eventFilterDebounceTimer == nullptr)
    {
        applyEventFilter();
        return;
    }

    m_eventFilterDebounceTimer->start();
}

bool ProcessTraceMonitorWidget::hasAnyEventFilterActive() const
{
    const bool typeFilterActive = m_eventTypeCombo != nullptr
        && m_eventTypeCombo->currentText().trimmed() != QStringLiteral("全部类型");
    const bool providerFilterActive = m_eventProviderFilterEdit != nullptr
        && !m_eventProviderFilterEdit->text().trimmed().isEmpty();
    const bool processFilterActive = m_eventProcessFilterEdit != nullptr
        && !m_eventProcessFilterEdit->text().trimmed().isEmpty();
    const bool eventNameFilterActive = m_eventNameFilterEdit != nullptr
        && !m_eventNameFilterEdit->text().trimmed().isEmpty();
    const bool detailFilterActive = m_eventDetailFilterEdit != nullptr
        && !m_eventDetailFilterEdit->text().trimmed().isEmpty();
    const bool globalFilterActive = m_eventGlobalFilterEdit != nullptr
        && !m_eventGlobalFilterEdit->text().trimmed().isEmpty();
    const bool anyTextPatternActive = providerFilterActive
        || processFilterActive
        || eventNameFilterActive
        || detailFilterActive
        || globalFilterActive;
    const bool regexFilterActive = anyTextPatternActive
        && m_eventRegexCheck != nullptr
        && m_eventRegexCheck->isChecked();
    const bool caseFilterActive = anyTextPatternActive
        && m_eventCaseCheck != nullptr
        && m_eventCaseCheck->isChecked();
    const bool invertFilterActive = m_eventInvertCheck != nullptr && m_eventInvertCheck->isChecked();

    return typeFilterActive
        || providerFilterActive
        || processFilterActive
        || eventNameFilterActive
        || detailFilterActive
        || globalFilterActive
        || regexFilterActive
        || caseFilterActive
        || invertFilterActive
        || isTimelineFilterActive();
}

void ProcessTraceMonitorWidget::updateEventFilterStatusText(const int visibleCount, const int totalCount)
{
    if (m_eventFilterStatusLabel == nullptr)
    {
        return;
    }

    m_eventFilterStatusLabel->setText(
        QStringLiteral("筛选结果：%1 / %2")
        .arg(visibleCount)
        .arg(totalCount));
    ks::ui::ApplyStatusRole(m_eventFilterStatusLabel,
        visibleCount > 0 ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Idle);
}

void ProcessTraceMonitorWidget::applyTimelineSelection(
    const std::uint64_t start100ns,
    const std::uint64_t end100ns)
{
    // 时间轴负责解释鼠标动作，事件表负责执行筛选。
    // 这里存储绝对时间戳，确保图形选区与表格行通过数据关联，而不是通过屏幕坐标关联。
    m_timelineSelectionStart100ns = std::min(start100ns, end100ns);
    m_timelineSelectionEnd100ns = std::max(start100ns, end100ns);
    m_timelineUserSelectionActive = m_eventTimelineWidget != nullptr
        && m_eventTimelineWidget->hasUserAdjustedSelection();
    applyEventFilter();
}

void ProcessTraceMonitorWidget::refreshTimelineRange(const bool captureFinished)
{
    if (!m_eventTable || !m_eventTable->isVisible() || m_eventTimelineWidget == nullptr || m_captureStartTime100ns == 0)
    {
        return;
    }

    // captureEnd100ns：
    // - 采集中使用当前系统时间，让时间轴右侧实时扩展；
    // - 停止后使用记录的停止时间，让右侧固定。
    std::uint64_t captureEnd100ns = captureFinished && m_captureStopTime100ns != 0
        ? m_captureStopTime100ns
        : currentSystemTime100ns();

    if (captureEnd100ns <= m_captureStartTime100ns)
    {
        captureEnd100ns = m_captureStartTime100ns + 1;
    }

    m_eventTimelineWidget->setCaptureRange(m_captureStartTime100ns, captureEnd100ns);
    m_timelineSelectionStart100ns = m_eventTimelineWidget->selectionStart100ns();
    m_timelineSelectionEnd100ns = m_eventTimelineWidget->selectionEnd100ns();
}

void ProcessTraceMonitorWidget::refreshTimelinePoints()
{
    if (!m_eventTable || !m_eventTable->isVisible() || !m_eventTimelineWidget
        || !m_eventTimelineWidget->isVisible() || m_timelineArchiveRevision == m_eventArchive.revision()) return;
    std::vector<ProcessTraceTimelineEventPoint> points;
    points.reserve(m_eventArchive.size());
    for (const auto& record : m_eventArchive.snapshot())
    {
        ProcessTraceTimelineEventPoint point;
        point.time100ns = record->value.time100ns;
        point.typeText = record->value.typeText;
        point.categoryId = ks::ui::TimelineCategoryForEtwProvider(record->value.providerText, record->value.eventName);
        points.push_back(std::move(point));
    }
    m_eventTimelineWidget->setEventPoints(points);
    m_timelineArchiveRevision = m_eventArchive.revision();
}

bool ProcessTraceMonitorWidget::isTimelineFilterActive() const
{
    if (m_captureStartTime100ns == 0
        || !m_timelineUserSelectionActive
        || m_timelineSelectionStart100ns == 0
        || m_timelineSelectionEnd100ns == 0
        || m_timelineSelectionEnd100ns <= m_timelineSelectionStart100ns)
    {
        return false;
    }

    const std::uint64_t effectiveEnd100ns = m_captureStopTime100ns != 0
        ? m_captureStopTime100ns
        : currentSystemTime100ns();
    if (effectiveEnd100ns <= m_captureStartTime100ns)
    {
        return false;
    }

    // 全范围选区不视为额外筛选，避免默认自动跟随状态下隐藏新追加事件。
    return m_timelineSelectionStart100ns > m_captureStartTime100ns
        || m_timelineSelectionEnd100ns < effectiveEnd100ns;
}

void ProcessTraceMonitorWidget::applyEventFilter()
{
    if (!m_eventTable) return;
    if (!m_eventFilterProjection)
        m_eventFilterProjection = new ks::monitor::EventFilterProjection(m_eventTable,
            [this](int row) {
                ks::monitor::EventFilterRow values;
                const auto* time = m_eventTable->item(row, EventColumnTime100ns);
                auto text = [this, row](int column) { const auto* item = m_eventTable->item(row,column); return item ? item->text() : QString(); };
                values.fields = {text(EventColumnProvider),time ? time->data(kEventRoleProcessSearchText).toString() : QString(),
                    time ? time->data(kEventRoleEventSearchText).toString() : QString(),text(EventColumnDetail),
                    time ? time->data(kEventRoleGlobalSearchText).toString() : QString()};
                values.type = text(EventColumnType);
                values.time100ns = time ? time->data(kEventRoleTime100nsValue).toULongLong() : 0;
                return values;
            },
            [this](int visible, int total, bool pending) {
                updateEventFilterStatusText(visible,total);
                if (pending && m_eventFilterStatusLabel) ks::ui::ApplyStatusRole(m_eventFilterStatusLabel,ks::ui::StatusRole::Info);
                updateActionState();
            });
    ks::monitor::EventFilterSpec spec;
    spec.patterns = {m_eventProviderFilterEdit ? m_eventProviderFilterEdit->text() : QString(),
        m_eventProcessFilterEdit ? m_eventProcessFilterEdit->text() : QString(),m_eventNameFilterEdit ? m_eventNameFilterEdit->text() : QString(),
        m_eventDetailFilterEdit ? m_eventDetailFilterEdit->text() : QString(),m_eventGlobalFilterEdit ? m_eventGlobalFilterEdit->text() : QString()};
    spec.fieldIndexes = {0,1,2,3,4};
    spec.type = m_eventTypeCombo ? m_eventTypeCombo->currentText().trimmed() : QString();
    if (spec.type == QStringLiteral("全部类型")) spec.type.clear();
    spec.regex = m_eventRegexCheck && m_eventRegexCheck->isChecked();
    spec.invert = m_eventInvertCheck && m_eventInvertCheck->isChecked();
    spec.sensitivity = m_eventCaseCheck && m_eventCaseCheck->isChecked() ? Qt::CaseSensitive : Qt::CaseInsensitive;
    spec.timeline = isTimelineFilterActive();
    if (spec.timeline) { spec.start100ns = m_timelineSelectionStart100ns; spec.end100ns = m_timelineSelectionEnd100ns; }
    m_eventFilterProjection->setSuspended(!m_eventTable->isVisible());
    m_eventFilterProjection->setFilter(std::move(spec));
}

void ProcessTraceMonitorWidget::clearEventFilter()
{
    const QSignalBlocker typeBlocker(m_eventTypeCombo);
    const QSignalBlocker providerBlocker(m_eventProviderFilterEdit);
    const QSignalBlocker processBlocker(m_eventProcessFilterEdit);
    const QSignalBlocker eventNameBlocker(m_eventNameFilterEdit);
    const QSignalBlocker detailBlocker(m_eventDetailFilterEdit);
    const QSignalBlocker globalBlocker(m_eventGlobalFilterEdit);
    const QSignalBlocker regexBlocker(m_eventRegexCheck);
    const QSignalBlocker caseBlocker(m_eventCaseCheck);
    const QSignalBlocker invertBlocker(m_eventInvertCheck);

    if (m_eventTypeCombo != nullptr)
    {
        m_eventTypeCombo->setCurrentIndex(0);
    }
    if (m_eventProviderFilterEdit != nullptr)
    {
        m_eventProviderFilterEdit->clear();
    }
    if (m_eventProcessFilterEdit != nullptr)
    {
        m_eventProcessFilterEdit->clear();
    }
    if (m_eventNameFilterEdit != nullptr)
    {
        m_eventNameFilterEdit->clear();
    }
    if (m_eventDetailFilterEdit != nullptr)
    {
        m_eventDetailFilterEdit->clear();
    }
    if (m_eventGlobalFilterEdit != nullptr)
    {
        m_eventGlobalFilterEdit->clear();
    }
    if (m_eventRegexCheck != nullptr)
    {
        m_eventRegexCheck->setChecked(false);
    }
    if (m_eventCaseCheck != nullptr)
    {
        m_eventCaseCheck->setChecked(false);
    }
    if (m_eventInvertCheck != nullptr)
    {
        m_eventInvertCheck->setChecked(false);
    }
    if (m_eventTimelineWidget != nullptr)
    {
        m_eventTimelineWidget->resetSelectionToFullRange();
        m_timelineSelectionStart100ns = m_eventTimelineWidget->selectionStart100ns();
        m_timelineSelectionEnd100ns = m_eventTimelineWidget->selectionEnd100ns();
        m_timelineUserSelectionActive = false;
    }

    applyEventFilter();

    kLogEvent event;
    info << event << "[ProcessTraceMonitorWidget] 已清空事件筛选条件。" << eol;
}

void ProcessTraceMonitorWidget::acceptPendingEventRows()
{
    std::deque<EventRef> accepted;
    { const std::lock_guard<std::mutex> lock(m_capture->m_pendingMutex); accepted.swap(m_capture->m_pendingRows); }
    const bool visible = m_eventTable && m_eventTable->isVisible();
    if (!visible) { m_eventProjectionStale = true; m_eventProjectionQueue.clear(); m_expiredEventProjection.clear(); }
    const auto language = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
    for (auto& record : accepted)
    {
        // Hidden acceptance moves refs and binds a frozen language value only.
        // It never formats a document, creates table items or evaluates a filter.
        record->prepareForArchive(language);
        auto evicted = m_eventArchive.append(record);
        if (evicted && visible && !m_eventProjectionStale && m_projectedEvents.contains(evicted.get()))
            m_expiredEventProjection.push_back(std::move(evicted));
        if (visible && !m_eventProjectionStale) m_eventProjectionQueue.push_back(std::move(record));
    }
    // Coalesce only obsolete display plans; the canonical window is unchanged.
    if (m_eventProjectionQueue.size() > ks::monitor::ProcessTraceEventArchive::capacity)
    { m_eventProjectionStale = true; m_eventProjectionQueue.clear(); m_expiredEventProjection.clear(); }
}

ProcessTraceMonitorWidget::EventRef ProcessTraceMonitorWidget::eventRecordAt(const int row) const
{
    if (!m_eventTable || row < 0) return {};
    const auto* item = m_eventTable->item(row, EventColumnTime100ns);
    if (!item) return {};
    const auto key = reinterpret_cast<const ks::monitor::ProcessTraceEventRecord*>(item->data(Qt::UserRole + 5).value<quintptr>());
    const auto found = m_projectedEvents.find(key);
    return found != m_projectedEvents.end() ? found->second.record : EventRef{};
}

bool ProcessTraceMonitorWidget::eventProjectionPending() const
{
    return !m_eventTable || !m_eventTable->isVisible() || m_eventProjectionStale
        || !m_eventProjectionQueue.empty() || !m_expiredEventProjection.empty();
}

void ProcessTraceMonitorWidget::flushPendingRows()
{
    pollCaptureState();
    acceptPendingEventRows(); // Canonical admission precedes visibility/menu barriers.
    const bool visible = m_eventTable && m_eventTable->isVisible();
    if (m_eventFilterProjection) m_eventFilterProjection->setSuspended(!visible);
    m_eventProjectionWasVisible = visible;
    if (!visible)
    {
        updateActionState(); updateStatusLabel();
        if (!m_capture->m_captureRunning.load() && (!m_captureCleanup || m_captureCleanup->isComplete()) && m_uiUpdateTimer)
            m_uiUpdateTimer->stop();
        return;
    }
    const QPointer<ProcessTraceMonitorWidget> guard(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(this, QStringLiteral("process-trace-event-flush"), {m_eventTable},
        [guard]() { if (guard) guard->flushPendingRows(); }))
    { m_eventProjectionStale = true; m_eventProjectionQueue.clear(); m_expiredEventProjection.clear(); return; }
    projectEventRows();
    refreshTimelineRange(!m_capture->m_captureRunning.load());
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    if (!m_capture->m_captureRunning.load() || nowMs - m_lastTimelineRefreshMs >= 250)
    { refreshTimelinePoints(); m_lastTimelineRefreshMs = nowMs; }
    if (hasAnyEventFilterActive()) applyEventFilter();
    else updateEventFilterStatusText(m_eventTable->rowCount(), m_eventTable->rowCount());
    updateActionState(); updateStatusLabel();
    if (!m_capture->m_captureRunning.load() && (!m_captureCleanup || m_captureCleanup->isComplete())
        && !eventProjectionPending() && m_uiUpdateTimer) m_uiUpdateTimer->stop();
}

void ProcessTraceMonitorWidget::projectEventRows()
{
    if (!m_eventTable || !m_eventTable->isVisible()) return;
    if (m_eventProjectionStale)
    {
        m_eventProjectionQueue.clear(); m_expiredEventProjection.clear();
        for (const auto& [key, projected] : m_projectedEvents)
            if (!m_eventArchive.contains(projected.record)) m_expiredEventProjection.push_back(projected.record);
        for (const auto& record : m_eventArchive.snapshot())
            if (!m_projectedEvents.contains(record.get())) m_eventProjectionQueue.push_back(record);
        m_eventProjectionStale = false;
    }
    if (m_expiredEventProjection.empty() && m_eventProjectionQueue.empty()
        && m_restoreSelectedEvents.empty() && !m_restoreCurrentEvent && !m_restoreTopEvent) return;
    QElapsedTimer budget; budget.start();
    const bool updates = m_eventTable->updatesEnabled(); m_eventTable->setUpdatesEnabled(false);
    const bool sorting = m_eventTable->isSortingEnabled();
    if (sorting) m_eventTable->setSortingEnabled(false);
    const auto top = m_restoreTopEvent ? m_restoreTopEvent : eventRecordAt(m_eventTable->indexAt(QPoint(0,0)).row());
    std::vector<int> removed;
    std::size_t mutations = 0;
    while (!m_expiredEventProjection.empty() && mutations < kUiFlushRowLimit && budget.elapsed() < kUiFlushBudgetMs)
    {
        auto record = std::move(m_expiredEventProjection.front()); m_expiredEventProjection.pop_front();
        const auto found = m_projectedEvents.find(record.get());
        if (found == m_projectedEvents.end()) continue;
        if (found->second.index.isValid()) { removed.push_back(found->second.index.row()); ++mutations; }
        m_projectedEvents.erase(found);
    }
    std::sort(removed.begin(), removed.end(), std::greater<int>());
    removed.erase(std::unique(removed.begin(), removed.end()), removed.end());
    for (std::size_t i = 0; i < removed.size();)
    {
        const int last = removed[i]; int first = last;
        while (++i < removed.size() && removed[i] == first - 1) first = removed[i];
        m_eventTable->model()->removeRows(first, last-first+1);
    }
    std::size_t appended = 0;
    while (!m_eventProjectionQueue.empty() && mutations < kUiFlushRowLimit && budget.elapsed() < kUiFlushBudgetMs)
    {
        auto record = std::move(m_eventProjectionQueue.front()); m_eventProjectionQueue.pop_front();
        if (!m_eventArchive.contains(record) || m_projectedEvents.contains(record.get())) continue;
        materializeEventRow(record); ++appended; ++mutations;
    }
    if (sorting) m_eventTable->setSortingEnabled(true);
    for (auto it = m_restoreSelectedEvents.begin(); it != m_restoreSelectedEvents.end();)
    {
        const auto found = m_projectedEvents.find(it->get());
        if (!m_eventArchive.contains(*it)) it = m_restoreSelectedEvents.erase(it);
        else if (found != m_projectedEvents.end() && found->second.index.isValid())
        {
            m_eventTable->selectionModel()->select(found->second.index, QItemSelectionModel::Select | QItemSelectionModel::Rows);
            it = m_restoreSelectedEvents.erase(it);
        }
        else ++it;
    }
    if (m_restoreCurrentEvent)
    {
        const auto found = m_projectedEvents.find(m_restoreCurrentEvent.get());
        if (!m_eventArchive.contains(m_restoreCurrentEvent)) m_restoreCurrentEvent.reset();
        else if (found != m_projectedEvents.end() && found->second.index.isValid())
        { m_eventTable->selectionModel()->setCurrentIndex(found->second.index, QItemSelectionModel::NoUpdate); m_restoreCurrentEvent.reset(); }
    }
    if (m_eventKeepBottomCheck && m_eventKeepBottomCheck->isChecked())
    { m_eventTable->scrollToBottom(); m_restoreTopEvent.reset(); }
    else if ((m_restoreTopEvent || !removed.empty()) && top && m_eventArchive.contains(top))
    {
        const auto found = m_projectedEvents.find(top.get());
        if (found != m_projectedEvents.end() && found->second.index.isValid())
        { m_eventTable->scrollTo(found->second.index, QAbstractItemView::PositionAtTop); m_restoreTopEvent.reset(); }
    }
    if (top && !m_eventArchive.contains(top)) m_restoreTopEvent.reset();
    m_eventTable->setUpdatesEnabled(updates);
    if (updates && (appended || !removed.empty())) m_eventTable->viewport()->update();
    if ((!m_eventProjectionQueue.empty() || !m_expiredEventProjection.empty()) && !m_eventProjectionPumpScheduled)
    {
        m_eventProjectionPumpScheduled = true;
        QTimer::singleShot(0, this, [this]() { m_eventProjectionPumpScheduled = false; flushPendingRows(); });
    }
}

void ProcessTraceMonitorWidget::materializeEventRow(const EventRef& record)
{
    if (!m_eventTable || !record) return;
    const auto& value = record->value;
    const auto& cache = record->searchCache();
    const int row = m_eventTable->rowCount(); m_eventTable->insertRow(row);
    const auto cells = record->rawCells();
    for (int column = 0; column < EventColumnCount; ++column)
        m_eventTable->setItem(row, column, createReadOnlyItem(cells.value(column)));
    auto* time = m_eventTable->item(row, EventColumnTime100ns);
    time->setData(Qt::UserRole + 4, QVariant::fromValue(value.detailDocument));
    time->setData(kEventRoleTime100nsValue, QVariant::fromValue<qulonglong>(value.time100ns));
    time->setData(kEventRoleProcessSearchText, cache.processText);
    time->setData(kEventRoleEventSearchText, cache.eventText);
    time->setData(kEventRoleGlobalSearchText, cache.globalText);
    time->setData(Qt::UserRole + 5, QVariant::fromValue<quintptr>(reinterpret_cast<quintptr>(record.get())));
    const QPersistentModelIndex identity(m_eventTable->model()->index(row, 0));
    m_projectedEvents.emplace(record.get(), ProjectedEvent{record, identity});
    if (!m_eventFilterProjection) applyEventFilter();
    if (identity.isValid()) m_eventFilterProjection->trackRow(identity.row());
}

void ProcessTraceMonitorWidget::clearCanonicalEvents()
{
    m_eventArchive.clear(); m_eventProjectionQueue.clear(); m_expiredEventProjection.clear(); m_projectedEvents.clear();
    m_restoreSelectedEvents.clear(); m_restoreCurrentEvent.reset(); m_restoreTopEvent.reset();
    m_eventProjectionStale = true; ++m_eventSessionGeneration; m_timelineArchiveRevision = 0;
    if (m_eventTable) { m_eventTable->clearContents(); m_eventTable->setRowCount(0); }
}

ProcessTraceMonitorWidget::EventExportSnapshot ProcessTraceMonitorWidget::freezeVisibleEventRowsForExport()
{
    acceptPendingEventRows(); // Freeze accepted values even if the widget projection is hidden or behind.
    applyEventFilter(); // Publishes a condition; regex evaluation remains in the value worker.
    EventExportSnapshot snapshot;
    const auto canonical = m_eventArchive.snapshot();
    std::vector<EventRef> projected(m_eventTable ? m_eventTable->rowCount() : 0);
    std::unordered_set<const ks::monitor::ProcessTraceEventRecord*> represented;
    for (const auto& [key, row] : m_projectedEvents)
    {
        if (!row.index.isValid() || !m_eventArchive.contains(row.record)) continue;
        const int index = row.index.row();
        if (index >= 0 && static_cast<std::size_t>(index) < projected.size())
        { projected[static_cast<std::size_t>(index)] = row.record; represented.insert(key); }
    }
    snapshot.rows.reserve(canonical.size());
    for (auto& row : projected) if (row) snapshot.rows.push_back(std::move(row));
    for (const auto& row : canonical) if (!represented.contains(row.get())) snapshot.rows.push_back(row);
    snapshot.businessFilter = m_eventFilterProjection ? m_eventFilterProjection->currentCompiledFilter() : nullptr;
    snapshot.search = ks::ui::CaptureTableSearchResultFilterSpec(m_eventTable);
    snapshot.language = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
    snapshot.sessionGeneration = m_eventSessionGeneration; snapshot.archiveRevision = m_eventArchive.revision();
    snapshot.evictedRows = m_eventArchive.evicted();
    { const std::lock_guard<std::mutex> lock(m_capture->m_pendingMutex); snapshot.pendingDroppedRows = m_capture->m_pendingDroppedRows; }
    if (m_eventTable && m_eventTable->horizontalHeader())
    {
        snapshot.continuousSort = m_eventTable->isSortingEnabled();
        snapshot.sortColumn = m_eventTable->horizontalHeader()->sortIndicatorSection();
        snapshot.sortOrder = m_eventTable->horizontalHeader()->sortIndicatorOrder();
    }
    for (int column = 0; column < EventColumnCount; ++column)
    {
        const auto* header = m_eventTable ? m_eventTable->horizontalHeaderItem(column) : nullptr;
        snapshot.headers.push_back(header ? snapshot.language.displayText(header->text()) : QString());
    }
    return snapshot;
}

void ProcessTraceMonitorWidget::syncTargetEditsToCapture()
{
    std::lock_guard<std::mutex> lock(m_capture->m_runtimeMutex);
    m_capture->targets = m_targetProcessList;
    m_appliedTargetVersion = ++m_capture->targetVersion;
}
