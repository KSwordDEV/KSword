#include "ProcessTraceMonitorWidget.h"
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
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
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
            if (!m_capturePaused.load())
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
        m_availableTable->setRowHidden(row, !visible);
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
    if (m_captureRunning.load())
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
        ks::process::ProcessRecord detailRecord = buildLightweightMonitorProcessRecord(pidValue);
        targetEntry.processName = QString::fromStdString(detailRecord.processName);
        targetEntry.imagePath = QString::fromStdString(detailRecord.imagePath);
        targetEntry.userName = QString::fromStdString(detailRecord.userName);
        targetEntry.creationTime100ns = detailRecord.creationTime100ns;
        targetEntry.alive = !detailRecord.imagePath.empty()
            || !detailRecord.userName.empty()
            || detailRecord.creationTime100ns != 0;

        if (!targetEntry.alive)
        {
            targetEntry.processName = targetEntry.processName.trimmed().isEmpty()
                ? QStringLiteral("<Unknown>")
                : targetEntry.processName;
            targetEntry.remarkText += QStringLiteral("；无法读取静态详情");
        }
    }

    m_targetProcessList.push_back(targetEntry);
    refreshTargetTable();
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
    refreshTargetTable();
    updateActionState();
    updateStatusLabel();
}

void ProcessTraceMonitorWidget::upsertAutoTrackedProcessInTargetList(
    const std::uint32_t pidValue,
    const std::uint32_t parentPidValue,
    const QString& processNameText,
    const QString& processPathText,
    const std::uint64_t creationTime100ns)
{
    if (pidValue == 0)
    {
        return;
    }

    // normalizedProcessName/normalizedProcessPath：清理 ETW 事件中可能携带的空白文本。
    const QString normalizedProcessName = processNameText.trimmed();
    const QString normalizedProcessPath = processPathText.trimmed();
    // autoRemarkText：用于明确标记“该条目是 ETW 自动加入”。
    const QString autoRemarkText = QStringLiteral("ETW 自动加入（父PID=%1）").arg(parentPidValue);

    auto targetIt = std::find_if(
        m_targetProcessList.begin(),
        m_targetProcessList.end(),
        [pidValue](const TargetProcessEntry& entry) {
            return entry.pid == pidValue;
        });

    bool targetAdded = false;
    if (targetIt == m_targetProcessList.end())
    {
        TargetProcessEntry targetEntry;
        targetEntry.pid = pidValue;
        targetEntry.processName = normalizedProcessName;
        targetEntry.imagePath = normalizedProcessPath;
        targetEntry.creationTime100ns = creationTime100ns;
        targetEntry.alive = true;
        targetEntry.remarkText = autoRemarkText;
        m_targetProcessList.push_back(targetEntry);
        targetIt = std::prev(m_targetProcessList.end());
        targetAdded = true;
    }
    else
    {
        targetIt->alive = true;
        if (!normalizedProcessName.isEmpty())
        {
            targetIt->processName = normalizedProcessName;
        }
        if (!normalizedProcessPath.isEmpty())
        {
            targetIt->imagePath = normalizedProcessPath;
        }
        if (creationTime100ns != 0)
        {
            targetIt->creationTime100ns = creationTime100ns;
        }

        const bool canRewriteRemark = targetIt->remarkText.trimmed().isEmpty()
            || targetIt->remarkText.contains(QStringLiteral("ETW 自动加入"), Qt::CaseInsensitive);
        if (canRewriteRemark)
        {
            targetIt->remarkText = autoRemarkText;
        }
    }

    // needDetailLookup：当 ETW 没带全字段时，按 PID 补一轮轻量静态详情。
    const bool needDetailLookup = targetIt->processName.trimmed().isEmpty()
        || targetIt->imagePath.trimmed().isEmpty()
        || targetIt->userName.trimmed().isEmpty()
        || targetIt->creationTime100ns == 0;
    if (needDetailLookup)
    {
        const ks::process::ProcessRecord detailRecord = buildLightweightMonitorProcessRecord(pidValue);
        if (targetIt->processName.trimmed().isEmpty())
        {
            targetIt->processName = QString::fromStdString(detailRecord.processName);
        }
        if (targetIt->imagePath.trimmed().isEmpty())
        {
            targetIt->imagePath = QString::fromStdString(detailRecord.imagePath);
        }
        if (targetIt->userName.trimmed().isEmpty())
        {
            targetIt->userName = QString::fromStdString(detailRecord.userName);
        }
        if (targetIt->creationTime100ns == 0)
        {
            targetIt->creationTime100ns = detailRecord.creationTime100ns;
        }

        // 这里保持 alive=true：
        // - 触发来源是“ETW 进程创建事件”，说明该 PID 在事件时刻可达；
        // - 即便轻量详情补全失败，也不应把其误判成已退出。
        targetIt->alive = true;
    }

    refreshTargetTable();
    updateStatusLabel();

    kLogEvent autoAddEvent;
    info << autoAddEvent
        << "[ProcessTraceMonitorWidget] ETW自动同步监控目标, pid="
        << pidValue
        << ", parentPid="
        << parentPidValue
        << ", action="
        << (targetAdded ? "add" : "update")
        << eol;
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

    refreshTargetTable();
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
    if (m_targetTable == nullptr)
    {
        return;
    }

    m_targetTable->clearContents();
    m_targetTable->setRowCount(static_cast<int>(m_targetProcessList.size()));

    int aliveCount = 0;
    for (int row = 0; row < static_cast<int>(m_targetProcessList.size()); ++row)
    {
        const TargetProcessEntry& entry = m_targetProcessList[static_cast<std::size_t>(row)];

        QTableWidgetItem* stateItem = createReadOnlyItem(entry.alive
            ? QStringLiteral("运行中")
            : QStringLiteral("未知/已退出"));
        if (entry.alive)
        {
            ++aliveCount;
            stateItem->setForeground(QBrush(KswordTheme::SuccessColor()));
        }
        else
        {
            stateItem->setForeground(QBrush(KswordTheme::TextSecondaryColor()));
        }

        m_targetTable->setItem(row, TargetProcessColumnState, stateItem);
        m_targetTable->setItem(row, TargetProcessColumnPid, createReadOnlyItem(QString::number(entry.pid)));
        m_targetTable->setItem(row, TargetProcessColumnName, createReadOnlyItem(entry.processName));
        m_targetTable->setItem(row, TargetProcessColumnPath, createReadOnlyItem(entry.imagePath));
        m_targetTable->setItem(row, TargetProcessColumnUser, createReadOnlyItem(entry.userName));
        m_targetTable->setItem(row, TargetProcessColumnRemark, createReadOnlyItem(entry.remarkText));
    }

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

    std::set<int, std::greater<int>> selectedRowSet;
    const QList<QTableWidgetItem*> itemList = m_targetTable->selectedItems();
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

    for (const int row : selectedRowSet)
    {
        if (row >= 0 && row < static_cast<int>(m_targetProcessList.size()))
        {
            m_targetProcessList.erase(m_targetProcessList.begin() + row);
        }
    }

    refreshTargetTable();
    updateActionState();
    updateStatusLabel();

    kLogEvent event;
    info << event
        << "[ProcessTraceMonitorWidget] 已移除选中监控目标, removedCount="
        << selectedRowSet.size()
        << eol;
}

void ProcessTraceMonitorWidget::clearTargetProcesses()
{
    if (m_targetProcessList.empty())
    {
        return;
    }

    m_targetProcessList.clear();
    refreshTargetTable();
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
    const bool running = m_captureRunning.load();

    QMenu menu(this);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* addSelectedAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_start.svg")),
        QStringLiteral("加入监控目标"));
    menu.addSeparator();
    QAction* copyCurrentAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制当前行"));
    QAction* copySelectedAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_clipboard.svg")),
        QStringLiteral("复制选中行"));

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
    QAction* copySelectedAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_clipboard.svg")),
        QStringLiteral("复制选中行"));
    menu.addSeparator();
    QAction* removeSelectedAction = menu.addAction(
        QIcon(":/Icon/process_pause.svg"),
        QStringLiteral("移除选中目标"));
    QAction* clearAllAction = menu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        QStringLiteral("清空全部目标"));

    const bool running = m_captureRunning.load();
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
    m_timelineUserSelectionActive = true;
    applyEventFilter();
}

void ProcessTraceMonitorWidget::refreshTimelineRange(const bool captureFinished)
{
    if (m_eventTimelineWidget == nullptr || m_captureStartTime100ns == 0)
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
    if (m_eventTimelineWidget == nullptr)
    {
        return;
    }

    m_eventTimelineWidget->setEventPoints(m_timelineEventPoints);
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
    if (m_eventTable == nullptr)
    {
        return;
    }

    const QString typeText = m_eventTypeCombo != nullptr ? m_eventTypeCombo->currentText().trimmed() : QString();
    const QString providerText = m_eventProviderFilterEdit != nullptr ? m_eventProviderFilterEdit->text() : QString();
    const QString processText = m_eventProcessFilterEdit != nullptr ? m_eventProcessFilterEdit->text() : QString();
    const QString eventNameText = m_eventNameFilterEdit != nullptr ? m_eventNameFilterEdit->text() : QString();
    const QString detailText = m_eventDetailFilterEdit != nullptr ? m_eventDetailFilterEdit->text() : QString();
    const QString globalText = m_eventGlobalFilterEdit != nullptr ? m_eventGlobalFilterEdit->text() : QString();
    const bool useRegex = m_eventRegexCheck != nullptr && m_eventRegexCheck->isChecked();
    const bool invertMatch = m_eventInvertCheck != nullptr && m_eventInvertCheck->isChecked();
    const bool timelineFilterActive = isTimelineFilterActive();
    const Qt::CaseSensitivity caseSensitivity =
        (m_eventCaseCheck != nullptr && m_eventCaseCheck->isChecked())
        ? Qt::CaseSensitive
        : Qt::CaseInsensitive;

    const bool anyFilterActive = hasAnyEventFilterActive();
    if (!anyFilterActive)
    {
        for (int row = 0; row < m_eventTable->rowCount(); ++row)
        {
            m_eventTable->setRowHidden(row, false);
        }
        updateEventFilterStatusText(m_eventTable->rowCount(), m_eventTable->rowCount());
        updateActionState();
        updateStatusLabel();
        return;
    }

    int visibleCount = 0;
    for (int row = 0; row < m_eventTable->rowCount(); ++row)
    {
        QTableWidgetItem* timeItem = m_eventTable->item(row, EventColumnTime100ns);
        const QString rowType = m_eventTable->item(row, EventColumnType) != nullptr
            ? m_eventTable->item(row, EventColumnType)->text()
            : QString();
        const QString rowProvider = m_eventTable->item(row, EventColumnProvider) != nullptr
            ? m_eventTable->item(row, EventColumnProvider)->text()
            : QString();
        const QString rowDetail = m_eventTable->item(row, EventColumnDetail) != nullptr
            ? m_eventTable->item(row, EventColumnDetail)->text()
            : QString();
        const QString processMergedText = timeItem != nullptr
            ? timeItem->data(kEventRoleProcessSearchText).toString()
            : QString();
        const QString eventMergedText = timeItem != nullptr
            ? timeItem->data(kEventRoleEventSearchText).toString()
            : QString();
        const QString globalMergedText = timeItem != nullptr
            ? timeItem->data(kEventRoleGlobalSearchText).toString()
            : QString();

        // timelineMatched：
        // - 时间窗口始终是外层约束；
        // - 现有“反向”选项不能把它反转为“时间框外”，否则会破坏框选时间的语义。
        bool timelineMatched = true;
        if (timelineFilterActive)
        {
            const std::uint64_t rowTime100ns = timeItem != nullptr
                ? timeItem->data(kEventRoleTime100nsValue).toULongLong()
                : 0;
            timelineMatched = rowTime100ns >= m_timelineSelectionStart100ns
                && rowTime100ns <= m_timelineSelectionEnd100ns;
        }

        bool matched = true;
        if (!typeText.isEmpty() && typeText != QStringLiteral("全部类型"))
        {
            matched = matched && (QString::compare(rowType, typeText, Qt::CaseInsensitive) == 0);
        }

        matched = matched && textMatch(rowProvider, providerText, useRegex, caseSensitivity);
        matched = matched && textMatch(processMergedText, processText, useRegex, caseSensitivity);
        matched = matched && textMatch(eventMergedText, eventNameText, useRegex, caseSensitivity);
        matched = matched && textMatch(rowDetail, detailText, useRegex, caseSensitivity);
        matched = matched && textMatch(globalMergedText, globalText, useRegex, caseSensitivity);

        if (invertMatch)
        {
            matched = !matched;
        }
        matched = matched && timelineMatched;

        m_eventTable->setRowHidden(row, !matched);
        if (matched)
        {
            ++visibleCount;
        }
    }

    updateEventFilterStatusText(visibleCount, m_eventTable->rowCount());

    updateActionState();
    updateStatusLabel();
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

void ProcessTraceMonitorWidget::flushPendingRows()
{
    if (m_eventTable == nullptr)
    {
        return;
    }

    // 在 drain 前延后整个 UI 提交；同键 timeout 只保留一次重试，原始事件仍留在
    // m_pendingRows 中，因此菜单关闭后不会丢批次，也不会让头部裁剪改变动作目标。
    const QPointer<ProcessTraceMonitorWidget> guardThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("process-trace-event-flush"),
        { m_eventTable },
        [guardThis]()
        {
            if (!guardThis.isNull())
            {
                guardThis->flushPendingRows();
            }
        }))
    {
        return;
    }

    std::vector<CapturedEventRow> rowList;
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        const std::size_t takeCount = std::min(kUiFlushRowLimit, m_pendingRows.size());
        rowList.reserve(takeCount);
        for (std::size_t index = 0; index < takeCount; ++index)
        {
            rowList.push_back(std::move(m_pendingRows.front()));
            m_pendingRows.pop_front();
        }
    }

    if (rowList.empty())
    {
        refreshTimelineRange(false);
        if (!m_captureRunning.load() && m_uiUpdateTimer != nullptr)
        {
            m_uiUpdateTimer->stop();
        }
        return;
    }

    const bool updatesEnabled = m_eventTable->updatesEnabled();
    m_eventTable->setUpdatesEnabled(false);
    QElapsedTimer budgetTimer;
    budgetTimer.start();
    std::size_t renderedCount = 0;
    for (const CapturedEventRow& rowValue : rowList)
    {
        appendEventRow(rowValue);
        ++renderedCount;
        if (budgetTimer.elapsed() >= kUiFlushBudgetMs)
        {
            break;
        }
    }

    const int removeCount = std::max(0, m_eventTable->rowCount() - 12000);
    if (removeCount > 0 && m_eventTable->model() != nullptr)
    {
        m_eventTable->model()->removeRows(0, removeCount);
        const std::size_t timelineEraseCount = std::min(
            static_cast<std::size_t>(removeCount),
            m_timelineEventPoints.size());
        m_timelineEventPoints.erase(
            m_timelineEventPoints.begin(),
            m_timelineEventPoints.begin() + static_cast<std::ptrdiff_t>(timelineEraseCount));
    }

    m_eventTable->setUpdatesEnabled(updatesEnabled);
    if (updatesEnabled && m_eventTable->viewport() != nullptr)
    {
        m_eventTable->viewport()->update();
    }

    if (renderedCount < rowList.size())
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        for (std::size_t index = rowList.size(); index > renderedCount; --index)
        {
            m_pendingRows.push_front(std::move(rowList[index - 1]));
        }
        while (m_pendingRows.size() > kPendingRowCapacity)
        {
            m_pendingRows.pop_back();
            ++m_pendingDroppedRows;
        }
    }

    refreshTimelineRange(false);
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    if (!m_captureRunning.load() || (nowMs - m_lastTimelineRefreshMs) >= 250)
    {
        refreshTimelinePoints();
        m_lastTimelineRefreshMs = nowMs;
    }

    if (hasAnyEventFilterActive())
    {
        applyEventFilter();
    }
    else
    {
        updateEventFilterStatusText(m_eventTable->rowCount(), m_eventTable->rowCount());
    }
    updateActionState();
    updateStatusLabel();

    if (m_eventKeepBottomCheck != nullptr
        && m_eventKeepBottomCheck->isChecked()
        && m_eventTable != nullptr)
    {
        m_eventTable->scrollToBottom();
    }
}

void ProcessTraceMonitorWidget::appendEventRow(const CapturedEventRow& rowValue)
{
    if (m_eventTable == nullptr)
    {
        return;
    }

    const int row = m_eventTable->rowCount();
    m_eventTable->insertRow(row);

    QTableWidgetItem* timeItem = createReadOnlyItem(rowValue.time100nsText);
    timeItem->setData(Qt::UserRole + 4, QVariant::fromValue(rowValue.detailDocument));
    timeItem->setData(kEventRoleTime100nsValue, QVariant::fromValue<qulonglong>(
        static_cast<qulonglong>(rowValue.time100ns)));
    timeItem->setData(
        kEventRoleProcessSearchText,
        QStringLiteral("%1 | %2 | %3 | %4")
        .arg(rowValue.pidText, rowValue.processText, rowValue.rootPidText, rowValue.relationText));
    timeItem->setData(
        kEventRoleEventSearchText,
        QStringLiteral("%1 | %2").arg(rowValue.eventName, QString::number(rowValue.eventId)));
    timeItem->setData(
        kEventRoleGlobalSearchText,
        QStringLiteral("%1 | %2 | %3 | %4 | %5 | %6 | %7 | %8 | %9 | %10")
        .arg(
            rowValue.typeText,
            rowValue.providerText,
            QString::number(rowValue.eventId),
            rowValue.eventName,
            rowValue.pidText,
            rowValue.processText,
            rowValue.rootPidText,
            rowValue.relationText,
            rowValue.detailDocument.toPlainText(true).simplified().left(6000),
            rowValue.activityIdText));

    m_eventTable->setItem(row, EventColumnTime100ns, timeItem);
    m_eventTable->setItem(row, EventColumnType, createReadOnlyItem(rowValue.typeText));
    m_eventTable->setItem(row, EventColumnProvider, createReadOnlyItem(rowValue.providerText));
    m_eventTable->setItem(row, EventColumnEventId, createReadOnlyItem(QString::number(rowValue.eventId)));
    m_eventTable->setItem(row, EventColumnEventName, createReadOnlyItem(rowValue.eventName));
    m_eventTable->setItem(row, EventColumnPidTid, createReadOnlyItem(rowValue.pidText));
    m_eventTable->setItem(row, EventColumnProcess, createReadOnlyItem(rowValue.processText));
    m_eventTable->setItem(row, EventColumnRootPid, createReadOnlyItem(rowValue.rootPidText));
    m_eventTable->setItem(row, EventColumnRelation, createReadOnlyItem(rowValue.relationText));
    m_eventTable->setItem(row, EventColumnDetail, createReadOnlyItem(rowValue.detailDocument.toPlainText(true).simplified().left(6000)));
    m_eventTable->setItem(row, EventColumnActivityId, createReadOnlyItem(rowValue.activityIdText));

    ProcessTraceTimelineEventPoint pointValue;
    pointValue.time100ns = rowValue.time100ns;
    pointValue.typeText = rowValue.typeText;
    // Provider 是未翻译的 ETW 机器身份；类别标签换语言不会改变事件所在轨道。
    pointValue.categoryId = ks::ui::TimelineCategoryForEtwProvider(rowValue.providerText, rowValue.eventName);
    m_timelineEventPoints.push_back(std::move(pointValue));
}
