#include "WinAPIDock.h"
#include "../UI/CodeEditorWidget.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../UI/TableInteractionSupport.h"
#include "../theme.h"

// ============================================================
// WinAPIDock.Actions.cpp
// 作用：
// 1) 实现 WinAPI Dock 的交互逻辑、会话控制和导出能力；
// 2) 把按钮动作、过滤与配置文件写入集中管理；
// 3) 与 Pipe 读取逻辑拆开，降低并发代码与 UI 代码耦合。
// ============================================================

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCompleter>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QPointer>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSaveFile>
#include <QSet>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>

#include <algorithm>
#include <cerrno>
#include <cwchar>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <TlHelp32.h>

namespace
{
    // normalizeRawListForSessionConfig：
    // - 输入：Raw 配置的多行编辑文本；
    // - 处理：把换行替换为分号，保持会话 INI 每项只有一行，同时保留 Agent 支持的列表分隔语义；
    // - 返回：可安全写入 raw_modules 或 raw_denylist 的规范化文本。
    QString normalizeRawListForSessionConfig(QString textValue)
    {
        textValue.replace(QStringLiteral("\r\n"), QStringLiteral(";"));
        textValue.replace(u'\r', u';');
        textValue.replace(u'\n', u';');
        return textValue.trimmed();
    }

    // toUtf8StdString：
    // - 作用：把 Qt 宽字符文本转成 UTF-8 std::string；
    // - 调用：Toolhelp 返回的进程名需要桥接到 ks::process::ProcessRecord。
    std::string toUtf8StdString(const QString& textValue)
    {
        return textValue.toUtf8().toStdString();
    }

    // collectProcessListLikeMemoryDock：
    // - 作用：复用内存页同款 Toolhelp 快照遍历，避免逐进程重型静态详情查询；
    // - 调用：WinAPI 页面进入或手动刷新时在后台线程调用。
    std::vector<ks::process::ProcessRecord> collectProcessListLikeMemoryDock()
    {
        std::vector<ks::process::ProcessRecord> processList;

        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return processList;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(snapshotHandle, &processEntry) == FALSE)
        {
            ::CloseHandle(snapshotHandle);
            return processList;
        }

        do
        {
            ks::process::ProcessRecord record;
            record.pid = static_cast<std::uint32_t>(processEntry.th32ProcessID);
            record.parentPid = static_cast<std::uint32_t>(processEntry.th32ParentProcessID);
            record.threadCount = static_cast<std::uint32_t>(processEntry.cntThreads);
            record.processName = toUtf8StdString(QString::fromWCharArray(processEntry.szExeFile));
            record.imagePath = ks::process::QueryProcessPathByPid(record.pid);

            DWORD sessionId = 0;
            if (::ProcessIdToSessionId(static_cast<DWORD>(record.pid), &sessionId) != FALSE)
            {
                record.sessionId = static_cast<std::uint32_t>(sessionId);
            }

            processList.push_back(std::move(record));
        } while (::Process32NextW(snapshotHandle, &processEntry) != FALSE);

        ::CloseHandle(snapshotHandle);
        std::sort(
            processList.begin(),
            processList.end(),
            [](const ks::process::ProcessRecord& left, const ks::process::ProcessRecord& right) {
                return left.pid < right.pid;
            });
        return processList;
    }

    // processIconForPath：
    // - 作用：为进程下拉框解析系统文件图标；
    // - 处理：优先按 imagePath 获取 shell 图标，失败时回退项目内置进程图标；
    // - 返回：可直接设置到 QComboBox item 的 QIcon。
    QIcon processIconForPath(const QString& imagePathText)
    {
        static QFileIconProvider iconProvider;
        if (!imagePathText.trimmed().isEmpty())
        {
            const QIcon fileIcon = iconProvider.icon(QFileInfo(imagePathText));
            if (!fileIcon.isNull())
            {
                return fileIcon;
            }
        }
        return QIcon(QStringLiteral(":/Icon/process_main.svg"));
    }

    // processDisplayName：
    // - 作用：把进程快照转换成下拉框主显示文本；
    // - 处理：保留 PID、进程名和路径，用户输入任意片段都能被 QCompleter/手动匹配命中；
    // - 返回：面向用户的单行候选文本。
    QString processDisplayName(const ks::process::ProcessRecord& record)
    {
        const QString processName = QString::fromStdString(
            record.processName.empty() ? std::string("<Unknown>") : record.processName);
        const QString imagePathText = QString::fromStdString(record.imagePath);
        if (imagePathText.trimmed().isEmpty())
        {
            return QStringLiteral("%1  [PID %2]").arg(processName).arg(record.pid);
        }
        return QStringLiteral("%1  [PID %2]  %3").arg(processName).arg(record.pid).arg(imagePathText);
    }

    // comboIndexForPid：
    // - 作用：根据 PID 在进程下拉框中定位候选行；
    // - 处理：读取 Qt::UserRole 中保存的 PID；
    // - 返回：命中的 item index，未命中返回 -1。
    int comboIndexForPid(QComboBox* comboPointer, const std::uint32_t pidValue)
    {
        if (comboPointer == nullptr || pidValue == 0)
        {
            return -1;
        }
        for (int index = 0; index < comboPointer->count(); ++index)
        {
            if (comboPointer->itemData(index, Qt::UserRole).toUInt() == pidValue)
            {
                return index;
            }
        }
        return -1;
    }

    QString tableCellText(QTableWidget* const tablePointer, const int rowValue, const int columnValue)
    {
        // tableCellText:
        // - Input: a table pointer plus row/column coordinates.
        // - Processing: safely reads the item text and trims user-visible whitespace.
        // - Return: an empty string when the table/item is missing.
        if (tablePointer == nullptr)
        {
            return QString();
        }
        QTableWidgetItem* const itemPointer = tablePointer->item(rowValue, columnValue);
        return itemPointer != nullptr ? itemPointer->text().trimmed() : QString();
    }

    bool containsFakeRuleDelimiter(const QString& textValue)
    {
        // containsFakeRuleDelimiter:
        // - Input: a field that will be serialized into fake_success_rules.
        // - Processing: checks the delimiters used by the Agent parser.
        // - Return: true when the field would corrupt the single-line INI format.
        return textValue.contains('|')
            || textValue.contains(';')
            || textValue.contains(',')
            || textValue.contains('\r')
            || textValue.contains('\n');
    }

    bool parseFakeUnsigned64(const QString& textValue, quint64* valueOut)
    {
        // parseFakeUnsigned64:
        // - Input: decimal or 0x-prefixed integer text; negative values are accepted for two's-complement masks.
        // - Processing: uses wcstoull/wcstoll so 0xFFFFFFFFFFFFFFFF and -1 both become stable uint64 values.
        // - Return: true on full-string parse success, false on empty/invalid text.
        if (valueOut == nullptr)
        {
            return false;
        }

        const QString normalizedText = textValue.trimmed();
        if (normalizedText.isEmpty())
        {
            return false;
        }

        const std::wstring wideText = normalizedText.toStdWString();
        wchar_t* endPointer = nullptr;
        errno = 0;
        if (wideText.front() == L'-')
        {
            const long long parsedValue = std::wcstoll(wideText.c_str(), &endPointer, 0);
            if (errno != 0 || endPointer == wideText.c_str() || (endPointer != nullptr && *endPointer != L'\0'))
            {
                return false;
            }
            *valueOut = static_cast<quint64>(parsedValue);
            return true;
        }

        const unsigned long long parsedValue = std::wcstoull(wideText.c_str(), &endPointer, 0);
        if (errno != 0 || endPointer == wideText.c_str() || (endPointer != nullptr && *endPointer != L'\0'))
        {
            return false;
        }
        *valueOut = static_cast<quint64>(parsedValue);
        return true;
    }

    QString normalizeFakeIntegerText(const QString& textValue)
    {
        // normalizeFakeIntegerText:
        // - Input: user-entered integer text.
        // - Processing: parses through parseFakeUnsigned64 and emits a canonical decimal uint64 string.
        // - Return: canonical decimal text, or the trimmed original text if parsing unexpectedly fails.
        quint64 parsedValue = 0;
        if (!parseFakeUnsigned64(textValue, &parsedValue))
        {
            return textValue.trimmed();
        }
        return QString::number(parsedValue);
    }

    QString comboCurrentDataText(QComboBox* const comboPointer, const QString& fallbackText)
    {
        // comboCurrentDataText:
        // - Input: a combo box and fallback token.
        // - Processing: returns item data first, then visible text if no data exists.
        // - Return: a stable lower-case token for INI serialization.
        if (comboPointer == nullptr)
        {
            return fallbackText;
        }
        const QString dataText = comboPointer->currentData().toString().trimmed();
        if (!dataText.isEmpty())
        {
            return dataText;
        }
        return comboPointer->currentText().trimmed().toLower();
    }
}

void WinAPIDock::initializeConnections()
{
    if (m_processCombo != nullptr)
    {
        connect(m_processCombo, &QComboBox::currentIndexChanged, this, [this](const int) {
            updateProcessSelectorStatus();
            updateActionState();
        });
        if (m_processCombo->lineEdit() != nullptr)
        {
            connect(m_processCombo->lineEdit(), &QLineEdit::textChanged, this, [this]() {
                updateProcessSelectorStatus();
                updateActionState();
            });
            connect(m_processCombo->lineEdit(), &QLineEdit::returnPressed, this, [this]() {
                if (!m_pipeRunning.load())
                {
                    startMonitoring();
                }
            });
        }
        connect(m_processCombo, QOverload<int>::of(&QComboBox::activated), this, [this](const int) {
            updateProcessSelectorStatus();
            updateActionState();
        });
    }
    if (m_processRefreshButton != nullptr)
    {
        connect(m_processRefreshButton, &QPushButton::clicked, this, [this]() {
            refreshProcessListAsync();
        });
    }
    if (m_browseAgentDllButton != nullptr)
    {
        connect(m_browseAgentDllButton, &QPushButton::clicked, this, [this]() {
            browseAgentDllPath();
        });
    }
    if (m_agentDllPathEdit != nullptr)
    {
        connect(m_agentDllPathEdit, &QLineEdit::textChanged, this, [this]() {
            updateActionState();
        });
    }
    if (m_manualPidEdit != nullptr)
    {
        connect(m_manualPidEdit, &QLineEdit::textChanged, this, [this]() {
            updateActionState();
        });
        connect(m_manualPidEdit, &QLineEdit::returnPressed, this, [this]() {
            startMonitoring();
        });
    }
    if (m_rawFallbackCheck != nullptr)
    {
        connect(m_rawFallbackCheck, &QCheckBox::toggled, this, [this]() {
            updateActionState();
        });
    }
    if (m_fakeAddRuleButton != nullptr)
    {
        connect(m_fakeAddRuleButton, &QPushButton::clicked, this, [this]() {
            addFakeSuccessRuleFromInputs();
        });
    }
    if (m_fakeRemoveRuleButton != nullptr)
    {
        connect(m_fakeRemoveRuleButton, &QPushButton::clicked, this, [this]() {
            removeSelectedFakeSuccessRule();
        });
    }
    if (m_fakeApplyRuleButton != nullptr)
    {
        connect(m_fakeApplyRuleButton, &QPushButton::clicked, this, [this]() {
            if (m_pipeRunning.load())
            {
                QMessageBox::information(
                    this,
                    QStringLiteral("Fake Success"),
                    QStringLiteral("当前 Agent 会话已运行。Fake Success 第一版不做热更新，请先停止会话后再应用规则。"));
                return;
            }
            QString errorText;
            if (!validateFakeSuccessRules(&errorText))
            {
                QMessageBox::warning(this, QStringLiteral("Fake Success"), errorText);
                return;
            }
            startMonitoring();
        });
    }
    if (m_fakeStopRuleButton != nullptr)
    {
        connect(m_fakeStopRuleButton, &QPushButton::clicked, this, [this]() {
            stopMonitoring();
        });
    }
    if (m_fakeRuleTable != nullptr)
    {
        connect(m_fakeRuleTable, &QTableWidget::itemSelectionChanged, this, [this]() {
            updateActionState();
        });
    }
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
    if (m_terminateHookButton != nullptr)
    {
        connect(m_terminateHookButton, &QPushButton::clicked, this, [this]() {
            terminateHooksForSelectedProcess();
        });
    }
    if (m_exportButton != nullptr)
    {
        connect(m_exportButton, &QPushButton::clicked, this, [this]() {
            exportVisibleRowsToTsv();
        });
    }
    if (m_clearEventButton != nullptr)
    {
        connect(m_clearEventButton, &QPushButton::clicked, this, [this]() {
            if (m_eventTable != nullptr && !m_pipeRunning.load())
            {
                m_eventTable->clearContents();
                m_eventTable->setRowCount(0);
                applyEventFilter();
                updateActionState();
                updateStatusLabel();
            }
        });
    }

    if (m_eventFilterEdit != nullptr)
    {
        connect(m_eventFilterEdit, &QLineEdit::textChanged, this, [this]() {
            applyEventFilter();
        });
    }
    if (m_eventFilterClearButton != nullptr)
    {
        connect(m_eventFilterClearButton, &QPushButton::clicked, this, [this]() {
            clearEventFilter();
        });
    }
    if (m_eventTable != nullptr)
    {
        connect(m_eventTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
            showEventContextMenu(position);
        });
        connect(m_eventTable, &QTableWidget::cellDoubleClicked, this, [this](const int row, const int) {
            showEventDetailDialog(row);
        });
    }
    if (m_uiFlushTimer != nullptr)
    {
        connect(m_uiFlushTimer, &QTimer::timeout, this, [this]() {
            flushPendingRows();
        });
        m_uiFlushTimer->start();
    }
}

void WinAPIDock::refreshProcessListAsync()
{
    if (m_processRefreshPending.exchange(true))
    {
        return;
    }

    if (m_processStatusLabel != nullptr)
    {
        m_processStatusLabel->setText(QStringLiteral("● 正在刷新系统进程快照..."));
        m_processStatusLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));
    }
    updateActionState();

    QPointer<WinAPIDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<ks::process::ProcessRecord> processList = collectProcessListLikeMemoryDock();

        QMetaObject::invokeMethod(qApp, [guardThis, processList = std::move(processList)]() {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->m_processRefreshPending.store(false);
            guardThis->m_lastProcessRefreshMs = QDateTime::currentMSecsSinceEpoch();
            guardThis->populateProcessSelector(processList);
            guardThis->updateActionState();
        }, Qt::QueuedConnection);
    }).detach();
}

void WinAPIDock::populateProcessSelector(const std::vector<ks::process::ProcessRecord>& processList)
{
    if (m_processCombo == nullptr)
    {
        m_processList = processList;
        return;
    }

    // 弹层展开期间清空重填下拉框，会让弹层继续抓着鼠标键盘但内容失效，
    // 用户看到的就是“点开进程下拉框之后界面点不动”；推迟到弹层收起后再落地。
    // 缓存也一起推迟：进程缓存与下拉项必须保持同一份快照。
    {
        const QPointer<WinAPIDock> guardedSelf(this);
        if (ks::ui::DeferUiCommitIfComboBoxPopupOpen(
                this,
                QStringLiteral("winapi-dock-process-selector-apply"),
                [guardedSelf, processList]()
                {
                    if (!guardedSelf.isNull())
                    {
                        guardedSelf->populateProcessSelector(processList);
                    }
                }))
        {
            return;
        }
    }

    m_processList = processList;

    std::uint32_t previousPid = 0;
    (void)currentSelectedPid(&previousPid);
    const QString previousInputText = m_processCombo->currentText();

    {
        const QSignalBlocker comboBlocker(m_processCombo);
        QSignalBlocker lineEditBlocker(m_processCombo->lineEdit());
        m_processCombo->clear();

        for (const ks::process::ProcessRecord& record : m_processList)
        {
            const QString processName = QString::fromStdString(
                record.processName.empty() ? std::string("<Unknown>") : record.processName);
            const QString imagePathText = QString::fromStdString(record.imagePath);
            const QIcon processIcon = processIconForPath(imagePathText);
            const QString displayText = processDisplayName(record);
            m_processCombo->addItem(processIcon, displayText, QVariant::fromValue(static_cast<quint32>(record.pid)));

            const int itemIndex = m_processCombo->count() - 1;
            m_processCombo->setItemData(itemIndex, processName, Qt::UserRole + 1);
            m_processCombo->setItemData(itemIndex, imagePathText, Qt::UserRole + 2);
            m_processCombo->setItemData(itemIndex, displayText, Qt::ToolTipRole);
        }

        const int previousIndex = comboIndexForPid(m_processCombo, previousPid);
        if (previousIndex >= 0)
        {
            m_processCombo->setCurrentIndex(previousIndex);
        }
        else
        {
            m_processCombo->setCurrentIndex(-1);
            if (m_processCombo->lineEdit() != nullptr)
            {
                m_processCombo->lineEdit()->setText(previousInputText);
            }
        }
    }

    if (m_processCombo->completer() != nullptr)
    {
        m_processCombo->completer()->setCaseSensitivity(Qt::CaseInsensitive);
        m_processCombo->completer()->setFilterMode(Qt::MatchContains);
        m_processCombo->completer()->setCompletionMode(QCompleter::PopupCompletion);
    }

    if (m_processStatusLabel != nullptr)
    {
        m_processStatusLabel->setText(QStringLiteral("● 已刷新 %1 个进程").arg(m_processList.size()));
        m_processStatusLabel->setStyleSheet(buildStatusStyle(monitorSuccessColorHex()));
    }
    updateProcessSelectorStatus();
}

void WinAPIDock::updateProcessSelectorStatus()
{
    if (m_processCombo == nullptr)
    {
        return;
    }

    std::uint32_t pidValue = 0;
    const bool hasPid = currentSelectedPid(&pidValue);
    const int selectedIndex = comboIndexForPid(m_processCombo, pidValue);
    if (m_processIconLabel != nullptr)
    {
        QIcon displayIcon(QStringLiteral(":/Icon/process_main.svg"));
        if (selectedIndex >= 0)
        {
            const QIcon itemIcon = m_processCombo->itemIcon(selectedIndex);
            if (!itemIcon.isNull())
            {
                displayIcon = itemIcon;
            }
        }
        m_processIconLabel->setPixmap(displayIcon.pixmap(20, 20));
    }

    if (m_processStatusLabel == nullptr)
    {
        return;
    }

    if (hasPid)
    {
        if (selectedIndex >= 0)
        {
            const QString processName = m_processCombo->itemData(selectedIndex, Qt::UserRole + 1).toString();
            m_processStatusLabel->setText(QStringLiteral("● 已选择 PID=%1 %2").arg(pidValue).arg(processName));
            m_processStatusLabel->setStyleSheet(buildStatusStyle(monitorSuccessColorHex()));
        }
        else
        {
            m_processStatusLabel->setText(QStringLiteral("● 使用手动 PID=%1").arg(pidValue));
            m_processStatusLabel->setStyleSheet(buildStatusStyle(monitorWarningColorHex()));
        }
        return;
    }

    const QString inputText = m_processCombo->currentText().trimmed();
    if (inputText.isEmpty())
    {
        m_processStatusLabel->setText(QStringLiteral("● 候选 %1 个；输入进程名/PID 选择目标").arg(m_processCombo->count()));
        m_processStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));
        return;
    }
    m_processStatusLabel->setText(QStringLiteral("● 未明确选中目标；请从下拉候选选择或输入数字 PID"));
    m_processStatusLabel->setStyleSheet(buildStatusStyle(monitorWarningColorHex()));
}

bool WinAPIDock::currentSelectedPid(std::uint32_t* pidOut) const
{
    if (pidOut == nullptr)
    {
        return false;
    }
    *pidOut = 0;

    if (m_manualPidEdit != nullptr)
    {
        const QString manualPidText = m_manualPidEdit->text().trimmed();
        if (!manualPidText.isEmpty())
        {
            return tryParseUint32Text(manualPidText, pidOut);
        }
    }

    if (m_processCombo == nullptr)
    {
        return false;
    }

    const QString inputText = m_processCombo->currentText().trimmed();
    const int comboIndex = m_processCombo->currentIndex();
    if (comboIndex >= 0 && m_processCombo->itemText(comboIndex).trimmed().compare(inputText, Qt::CaseInsensitive) == 0)
    {
        const std::uint32_t pidValue = static_cast<std::uint32_t>(
            m_processCombo->itemData(comboIndex, Qt::UserRole).toUInt());
        if (pidValue != 0)
        {
            *pidOut = pidValue;
            return true;
        }
    }

    if (inputText.isEmpty())
    {
        return false;
    }

    if (tryParseUint32Text(inputText, pidOut))
    {
        return true;
    }

    int matchedIndex = -1;
    const QString normalizedInput = inputText.toLower();
    int exactMatchCount = 0;
    for (int index = 0; index < m_processCombo->count(); ++index)
    {
        const QString displayText = m_processCombo->itemText(index).trimmed().toLower();
        const QString nameText = m_processCombo->itemData(index, Qt::UserRole + 1).toString().trimmed().toLower();
        if (displayText == normalizedInput || nameText == normalizedInput)
        {
            matchedIndex = index;
            ++exactMatchCount;
            if (exactMatchCount > 1)
            {
                matchedIndex = -1;
                break;
            }
        }
    }

    if (matchedIndex < 0)
    {
        int containsMatchCount = 0;
        for (int index = 0; index < m_processCombo->count(); ++index)
        {
            const QString displayText = m_processCombo->itemText(index).trimmed().toLower();
            const QString nameText = m_processCombo->itemData(index, Qt::UserRole + 1).toString().trimmed().toLower();
            const QString pathText = m_processCombo->itemData(index, Qt::UserRole + 2).toString().trimmed().toLower();
            if (displayText.contains(normalizedInput)
                || nameText.contains(normalizedInput)
                || pathText.contains(normalizedInput))
            {
                matchedIndex = index;
                ++containsMatchCount;
                if (containsMatchCount > 1)
                {
                    matchedIndex = -1;
                    break;
                }
            }
        }
    }

    if (matchedIndex < 0)
    {
        return false;
    }

    const std::uint32_t pidValue = static_cast<std::uint32_t>(
        m_processCombo->itemData(matchedIndex, Qt::UserRole).toUInt());
    if (pidValue == 0)
    {
        return false;
    }

    *pidOut = pidValue;
    return true;
}

void WinAPIDock::browseAgentDllPath()
{
    const QString defaultPath = m_agentDllPathEdit != nullptr
        ? m_agentDllPathEdit->text().trimmed()
        : defaultDllPathHint();

    const QString selectedPath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("选择 APIMonitor_x64.dll"),
        defaultPath,
        QStringLiteral("DLL 文件 (*.dll)"));
    if (selectedPath.trimmed().isEmpty())
    {
        return;
    }

    if (m_agentDllPathEdit != nullptr)
    {
        m_agentDllPathEdit->setText(QDir::cleanPath(selectedPath));
    }
}

bool WinAPIDock::prepareSessionArtifacts(const std::uint32_t pidValue, QString* errorTextOut)
{
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    const QString sessionDirectory = QString::fromStdWString(ks::winapi_monitor::buildSessionDirectory());
    QDir sessionDir;
    if (!sessionDir.mkpath(sessionDirectory))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("无法创建会话目录：%1").arg(sessionDirectory);
        }
        return false;
    }

    m_currentSessionPid = pidValue;
    m_currentPipeName = QString::fromStdWString(ks::winapi_monitor::buildPipeNameForPid(pidValue));
    m_currentConfigPath = QString::fromStdWString(ks::winapi_monitor::buildConfigPathForPid(pidValue));
    m_currentStopFlagPath = QString::fromStdWString(ks::winapi_monitor::buildStopFlagPathForPid(pidValue));
    m_currentSessionId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    return true;
}

bool WinAPIDock::hasResidentAgentForProcess(const std::uint32_t pidValue)
{
    // hasResidentAgentForProcess：
    // - 输入：pidValue 为准备启动会话的目标 PID；
    // - 处理：用 PID 和进程创建时间确认同一实例仍保留此前已注入的常驻 Agent；
    // - 返回：确认可复用时为 true，身份无法确认或 PID 已复用时清除缓存并返回 false。
    if (pidValue == 0 || pidValue != m_residentAgentPid || m_residentAgentCreationTime100ns == 0)
    {
        return false;
    }

    std::uint64_t observedCreationTime100ns = 0;
    if (!ks::process::QueryProcessCreationTimeByPid(pidValue, &observedCreationTime100ns, nullptr)
        || observedCreationTime100ns != m_residentAgentCreationTime100ns)
    {
        m_residentAgentPid = 0;
        m_residentAgentCreationTime100ns = 0;
        return false;
    }
    return true;
}

void WinAPIDock::rememberResidentAgentForProcess(const std::uint32_t pidValue)
{
    // rememberResidentAgentForProcess：
    // - 输入：pidValue 为刚刚完成 DLL 注入的目标 PID；
    // - 处理：记录 PID 和创建时间，后续同一进程实例的 start-stop-start 复用正在等待的 Agent worker；
    // - 返回：无返回值，无法读取身份时主动放弃缓存，下一会话将保守地重新执行注入。
    std::uint64_t creationTime100ns = 0;
    if (!ks::process::QueryProcessCreationTimeByPid(pidValue, &creationTime100ns, nullptr)
        || creationTime100ns == 0)
    {
        m_residentAgentPid = 0;
        m_residentAgentCreationTime100ns = 0;
        return;
    }

    m_residentAgentPid = pidValue;
    m_residentAgentCreationTime100ns = creationTime100ns;
}

QString WinAPIDock::fakeSuccessRulesIniText() const
{
    // fakeSuccessRulesIniText:
    // - Input: the current Fake Success rule table.
    // - Processing: serializes each exact rule as module|api|returnType|returnValue|lastErrorKind|lastErrorValue.
    // - Return: a single INI-safe line; empty means Fake Success is disabled for the session.
    if (m_fakeRuleTable == nullptr || m_fakeRuleTable->rowCount() == 0)
    {
        return QString();
    }

    const auto cellToken = [this](const int rowValue, const int columnValue) -> QString {
        QTableWidgetItem* const itemPointer = m_fakeRuleTable->item(rowValue, columnValue);
        if (itemPointer == nullptr)
        {
            return QString();
        }
        const QString dataText = itemPointer->data(Qt::UserRole).toString().trimmed();
        return dataText.isEmpty() ? itemPointer->text().trimmed() : dataText;
    };

    QStringList serializedRuleList;
    for (int row = 0; row < m_fakeRuleTable->rowCount(); ++row)
    {
        serializedRuleList << QStringList{
            cellToken(row, FakeRuleColumnModule),
            cellToken(row, FakeRuleColumnApi),
            cellToken(row, FakeRuleColumnReturnType),
            cellToken(row, FakeRuleColumnReturnValue),
            cellToken(row, FakeRuleColumnLastErrorKind),
            cellToken(row, FakeRuleColumnLastErrorValue)
        }.join('|');
    }
    return serializedRuleList.join(QStringLiteral(";;"));
}

bool WinAPIDock::validateFakeSuccessRules(QString* errorTextOut) const
{
    // validateFakeSuccessRules:
    // - Input: current table rows that will be serialized into the Agent INI.
    // - Processing: checks required fields, delimiter safety, numeric ranges, and duplicate exact module!api keys.
    // - Return: true when all rows can be parsed by APIMonitor_x64; false and an error message otherwise.
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    if (m_fakeRuleTable == nullptr || m_fakeRuleTable->rowCount() == 0)
    {
        return true;
    }

    const auto normalizedKey = [](QString moduleText, QString apiText) -> QString {
        moduleText = moduleText.trimmed().toLower();
        apiText = apiText.trimmed().toLower();
        if (moduleText.endsWith(QStringLiteral(".dll")))
        {
            moduleText.chop(4);
        }
        return moduleText + QLatin1Char('!') + apiText;
    };

    QSet<QString> seenRuleKeys;
    for (int row = 0; row < m_fakeRuleTable->rowCount(); ++row)
    {
        const QString moduleText = tableCellText(m_fakeRuleTable, row, FakeRuleColumnModule);
        const QString apiText = tableCellText(m_fakeRuleTable, row, FakeRuleColumnApi);
        const QString returnTypeText = tableCellText(m_fakeRuleTable, row, FakeRuleColumnReturnType);
        const QString returnValueText = tableCellText(m_fakeRuleTable, row, FakeRuleColumnReturnValue);
        const QString lastErrorKindText = tableCellText(m_fakeRuleTable, row, FakeRuleColumnLastErrorKind);
        const QString lastErrorValueText = tableCellText(m_fakeRuleTable, row, FakeRuleColumnLastErrorValue);

        if (moduleText.isEmpty() || apiText.isEmpty() || returnTypeText.isEmpty()
            || returnValueText.isEmpty() || lastErrorKindText.isEmpty() || lastErrorValueText.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Fake Success 第 %1 行存在空字段。").arg(row + 1);
            }
            return false;
        }
        if (containsFakeRuleDelimiter(moduleText)
            || containsFakeRuleDelimiter(apiText)
            || containsFakeRuleDelimiter(returnTypeText)
            || containsFakeRuleDelimiter(returnValueText)
            || containsFakeRuleDelimiter(lastErrorKindText)
            || containsFakeRuleDelimiter(lastErrorValueText))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Fake Success 第 %1 行包含非法分隔符（| ; , 或换行）。").arg(row + 1);
            }
            return false;
        }

        quint64 parsedReturnValue = 0;
        if (!parseFakeUnsigned64(returnValueText, &parsedReturnValue))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Fake Success 第 %1 行返回值不是有效整数。").arg(row + 1);
            }
            return false;
        }

        quint64 parsedLastErrorValue = 0;
        if (!parseFakeUnsigned64(lastErrorValueText, &parsedLastErrorValue) || parsedLastErrorValue > 0xFFFFFFFFULL)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Fake Success 第 %1 行错误码必须是 0 到 0xFFFFFFFF。").arg(row + 1);
            }
            return false;
        }

        const QString ruleKey = normalizedKey(moduleText, apiText);
        if (seenRuleKeys.contains(ruleKey))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Fake Success 存在重复规则：%1!%2。").arg(moduleText, apiText);
            }
            return false;
        }
        seenRuleKeys.insert(ruleKey);
    }
    return true;
}

void WinAPIDock::addFakeSuccessRuleFromInputs()
{
    // addFakeSuccessRuleFromInputs:
    // - Input: module/API/return/error widgets in the Fake Success panel.
    // - Processing: validates a single exact rule, rejects duplicates, then appends it to the rule table.
    // - Return: no return value; user-facing errors are shown with QMessageBox.
    if (m_fakeRuleTable == nullptr || m_pipeRunning.load())
    {
        return;
    }

    const QString moduleText = m_fakeModuleEdit != nullptr ? m_fakeModuleEdit->text().trimmed() : QString();
    const QString apiText = m_fakeApiEdit != nullptr ? m_fakeApiEdit->text().trimmed() : QString();
    const QString returnTypeToken = comboCurrentDataText(m_fakeReturnTypeCombo, QStringLiteral("scalar"));
    const QString returnTypeDisplay = m_fakeReturnTypeCombo != nullptr
        ? m_fakeReturnTypeCombo->currentText().trimmed()
        : returnTypeToken;
    const QString returnValueText = m_fakeReturnValueEdit != nullptr ? m_fakeReturnValueEdit->text().trimmed() : QString();
    const QString lastErrorKindToken = comboCurrentDataText(m_fakeLastErrorKindCombo, QStringLiteral("none"));
    const QString lastErrorKindDisplay = m_fakeLastErrorKindCombo != nullptr
        ? m_fakeLastErrorKindCombo->currentText().trimmed()
        : lastErrorKindToken;
    const QString lastErrorValueText = m_fakeLastErrorValueEdit != nullptr ? m_fakeLastErrorValueEdit->text().trimmed() : QStringLiteral("0");

    if (moduleText.isEmpty() || apiText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("Fake Success"), QStringLiteral("请填写模块名和 API 导出名。"));
        return;
    }
    if (containsFakeRuleDelimiter(moduleText) || containsFakeRuleDelimiter(apiText))
    {
        QMessageBox::warning(this, QStringLiteral("Fake Success"), QStringLiteral("模块名和 API 名不能包含 | ; , 或换行。"));
        return;
    }

    quint64 parsedReturnValue = 0;
    if (!parseFakeUnsigned64(returnValueText, &parsedReturnValue))
    {
        QMessageBox::warning(this, QStringLiteral("Fake Success"), QStringLiteral("返回值不是有效整数。支持十进制、0x 十六进制和 -1。"));
        return;
    }

    quint64 parsedLastErrorValue = 0;
    if (!parseFakeUnsigned64(lastErrorValueText, &parsedLastErrorValue) || parsedLastErrorValue > 0xFFFFFFFFULL)
    {
        QMessageBox::warning(this, QStringLiteral("Fake Success"), QStringLiteral("错误码必须是 0 到 0xFFFFFFFF。"));
        return;
    }

    const auto normalizedKey = [](QString moduleValue, QString apiValue) -> QString {
        moduleValue = moduleValue.trimmed().toLower();
        apiValue = apiValue.trimmed().toLower();
        if (moduleValue.endsWith(QStringLiteral(".dll")))
        {
            moduleValue.chop(4);
        }
        return moduleValue + QLatin1Char('!') + apiValue;
    };
    const QString newRuleKey = normalizedKey(moduleText, apiText);
    for (int row = 0; row < m_fakeRuleTable->rowCount(); ++row)
    {
        if (normalizedKey(
            tableCellText(m_fakeRuleTable, row, FakeRuleColumnModule),
            tableCellText(m_fakeRuleTable, row, FakeRuleColumnApi)) == newRuleKey)
        {
            QMessageBox::warning(this, QStringLiteral("Fake Success"), QStringLiteral("已存在相同 module!api 的规则。"));
            return;
        }
    }

    const int row = m_fakeRuleTable->rowCount();
    m_fakeRuleTable->insertRow(row);

    QTableWidgetItem* moduleItem = createReadOnlyItem(moduleText);
    QTableWidgetItem* apiItem = createReadOnlyItem(apiText);
    QTableWidgetItem* returnTypeItem = createReadOnlyItem(returnTypeDisplay);
    QTableWidgetItem* returnValueItem = createReadOnlyItem(QString::number(parsedReturnValue));
    QTableWidgetItem* lastErrorKindItem = createReadOnlyItem(lastErrorKindDisplay);
    QTableWidgetItem* lastErrorValueItem = createReadOnlyItem(QString::number(parsedLastErrorValue));

    returnTypeItem->setData(Qt::UserRole, returnTypeToken);
    returnValueItem->setData(Qt::UserRole, QString::number(parsedReturnValue));
    lastErrorKindItem->setData(Qt::UserRole, lastErrorKindToken);
    lastErrorValueItem->setData(Qt::UserRole, QString::number(parsedLastErrorValue));

    m_fakeRuleTable->setItem(row, FakeRuleColumnModule, moduleItem);
    m_fakeRuleTable->setItem(row, FakeRuleColumnApi, apiItem);
    m_fakeRuleTable->setItem(row, FakeRuleColumnReturnType, returnTypeItem);
    m_fakeRuleTable->setItem(row, FakeRuleColumnReturnValue, returnValueItem);
    m_fakeRuleTable->setItem(row, FakeRuleColumnLastErrorKind, lastErrorKindItem);
    m_fakeRuleTable->setItem(row, FakeRuleColumnLastErrorValue, lastErrorValueItem);
    m_fakeRuleTable->selectRow(row);

    if (m_fakeRuleStatusLabel != nullptr)
    {
        m_fakeRuleStatusLabel->setText(QStringLiteral("规则：%1 条；启动会话时应用。").arg(m_fakeRuleTable->rowCount()));
        m_fakeRuleStatusLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));
    }
    updateActionState();
}

void WinAPIDock::removeSelectedFakeSuccessRule()
{
    // removeSelectedFakeSuccessRule:
    // - Input: the current selected row in the Fake Success rule table.
    // - Processing: removes the selected rule while monitoring is stopped.
    // - Return: no return value; silently skips when no row is selected.
    if (m_fakeRuleTable == nullptr || m_pipeRunning.load())
    {
        return;
    }

    const QList<QTableWidgetItem*> selectedItems = m_fakeRuleTable->selectedItems();
    if (selectedItems.isEmpty())
    {
        return;
    }

    m_fakeRuleTable->removeRow(selectedItems.front()->row());
    if (m_fakeRuleStatusLabel != nullptr)
    {
        m_fakeRuleStatusLabel->setText(QStringLiteral("规则：%1 条；启动会话时应用。").arg(m_fakeRuleTable->rowCount()));
        m_fakeRuleStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));
    }
    updateActionState();
}

bool WinAPIDock::writeSessionConfigFile(QString* errorTextOut) const
{
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    if (!validateFakeSuccessRules(errorTextOut))
    {
        return false;
    }

    QSaveFile configFile(m_currentConfigPath);
    if (!configFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("无法写入会话配置：%1").arg(m_currentConfigPath);
        }
        return false;
    }

    QTextStream outputStream(&configFile);
    outputStream << "[monitor]\n";
    outputStream << "pipe_name=" << m_currentPipeName << '\n';
    outputStream << "stop_flag_path=" << m_currentStopFlagPath << '\n';
    outputStream << "session_id=" << m_currentSessionId << '\n';
    outputStream << "agent_dll_path=" << (m_agentDllPathEdit != nullptr ? QDir::cleanPath(m_agentDllPathEdit->text().trimmed()) : QString()) << '\n';
    outputStream << "enable_file=" << ((m_hookFileCheck != nullptr && m_hookFileCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_registry=" << ((m_hookRegistryCheck != nullptr && m_hookRegistryCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_network=" << ((m_hookNetworkCheck != nullptr && m_hookNetworkCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_process=" << ((m_hookProcessCheck != nullptr && m_hookProcessCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_loader=" << ((m_hookLoaderCheck != nullptr && m_hookLoaderCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "auto_inject_child=" << ((m_autoInjectChildCheck != nullptr && m_autoInjectChildCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_raw_fallback=" << ((m_rawFallbackCheck != nullptr && m_rawFallbackCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "raw_use_default_denylist=" << ((m_rawDefaultDenyListCheck != nullptr && m_rawDefaultDenyListCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "raw_modules=" << normalizeRawListForSessionConfig(
        m_rawModuleListEdit != nullptr ? m_rawModuleListEdit->toPlainText() : defaultRawHookModulesText()) << '\n';
    outputStream << "raw_denylist=" << normalizeRawListForSessionConfig(
        m_rawDenyListEdit != nullptr ? m_rawDenyListEdit->toPlainText() : QString()) << '\n';
    outputStream << "fake_success_enabled=" << ((m_fakeRuleTable != nullptr && m_fakeRuleTable->rowCount() > 0) ? 1 : 0) << '\n';
    outputStream << "fake_success_raw_fallback=" << ((m_fakeRawFallbackCheck != nullptr && m_fakeRawFallbackCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "fake_success_rules=" << fakeSuccessRulesIniText() << '\n';
    outputStream << "detail_limit=" << static_cast<int>(ks::winapi_monitor::kMaxDetailChars - 1) << '\n';
    outputStream.flush();
    if (outputStream.status() != QTextStream::Ok || !configFile.commit())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("无法原子提交会话配置：%1").arg(m_currentConfigPath);
        }
        return false;
    }

    // 只有完整新配置已经可见后才撤销停止标记，避免常驻 Agent 在半写入 INI 上启动下一会话。
    if (QFile::exists(m_currentStopFlagPath) && !QFile::remove(m_currentStopFlagPath))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("会话配置已写入，但无法撤销停止标记：%1").arg(m_currentStopFlagPath);
        }
        return false;
    }
    return true;
}

void WinAPIDock::appendInternalEvent(const QString& categoryText, const QString& apiText, const QString& detailText)
{
    EventRow rowValue;
    rowValue.time100nsText = now100nsText();
    rowValue.categoryText = categoryText;
    rowValue.apiText = apiText;
    rowValue.resultText = QStringLiteral("OK");
    rowValue.pidTidText = m_currentSessionPid == 0 ? QStringLiteral("-") : QStringLiteral("%1 / -").arg(m_currentSessionPid);
    rowValue.detailText = detailText;
    rowValue.internalEvent = true;
    appendEventRow(rowValue);
    applyEventFilter();
    updateActionState();
    updateStatusLabel();
}

void WinAPIDock::showEventDetailDialog(const int rowValue)
{
    // showEventDetailDialog 作用：
    // - 输入：rowValue 为事件表中的物理行号；
    // - 处理：读取该行所有列，拼成可复制的多行详情文本并用模态窗口展示；
    // - 返回：无返回值，行号无效或表格不存在时直接返回。
    if (m_eventTable == nullptr || rowValue < 0 || rowValue >= m_eventTable->rowCount())
    {
        return;
    }

    const auto columnText = [this, rowValue](const int columnValue) -> QString {
        QTableWidgetItem* const itemPointer = m_eventTable->item(rowValue, columnValue);
        return itemPointer != nullptr ? itemPointer->text() : QString();
    };

    const QString detailText = QStringLiteral(
        "时间(100ns): %1\n"
        "分类: %2\n"
        "API: %3\n"
        "结果: %4\n"
        "PID/TID: %5\n\n"
        "详情:\n%6")
        .arg(columnText(EventColumnTime100ns),
            columnText(EventColumnCategory),
            columnText(EventColumnApi),
            columnText(EventColumnResult),
            columnText(EventColumnPidTid),
            columnText(EventColumnDetail));

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("WinAPI 事件详情"));
    dialog.resize(760, 420);

    QVBoxLayout* const layout = new QVBoxLayout(&dialog);
    layout->setContentsMargins(10, 10, 10, 10);
    layout->setSpacing(8);

    // 事件详情由本页拼装，使用统一编辑器以便英语模式即时重绘固定字段名。
    CodeEditorWidget* const detailEdit = new CodeEditorWidget(&dialog);
    detailEdit->setReadOnly(true);
    detailEdit->setLocalizedText(detailText);
    layout->addWidget(detailEdit, 1);

    QDialogButtonBox* const buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok, &dialog);
    buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("关闭"));
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    layout->addWidget(buttonBox, 0);

    dialog.exec();
}

void WinAPIDock::startMonitoring()
{
    if (m_pipeRunning.load())
    {
        return;
    }

    std::uint32_t pidValue = 0;
    if (!currentSelectedPid(&pidValue))
    {
        QMessageBox::information(this, QStringLiteral("WinAPI 监控"), QStringLiteral("请先选择目标进程或手动输入 PID。"));
        return;
    }

    if (m_agentDllPathEdit == nullptr)
    {
        return;
    }

    const QString dllPathText = QDir::cleanPath(m_agentDllPathEdit->text().trimmed());
    const QFileInfo dllFileInfo(dllPathText);
    if (!dllFileInfo.exists() || !dllFileInfo.isFile())
    {
        QMessageBox::warning(this, QStringLiteral("WinAPI 监控"), QStringLiteral("Agent DLL 不存在：%1").arg(dllPathText));
        return;
    }

    QString errorText;
    if (!prepareSessionArtifacts(pidValue, &errorText))
    {
        QMessageBox::warning(this, QStringLiteral("WinAPI 监控"), errorText);
        return;
    }
    if (!writeSessionConfigFile(&errorText))
    {
        QMessageBox::warning(this, QStringLiteral("WinAPI 监控"), errorText);
        return;
    }

    // 同一进程实例停止后 Agent worker 会驻留等待下一份配置；复用它避免重复 LoadLibraryW 增加模块引用计数。
    const bool reuseResidentAgent = hasResidentAgentForProcess(pidValue);

    if (m_eventTable != nullptr)
    {
        m_eventTable->clearContents();
        m_eventTable->setRowCount(0);
    }
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        m_pendingRows.clear();
        m_pendingDroppedRows = 0;
    }

    m_pipeStopFlag.store(false);
    m_pipeRunning.store(true);
    m_pipeConnected.store(false);
    m_pipeReconnectAttempts.store(0);
    {
        std::lock_guard<std::mutex> lock(m_childPipeMutex);
        m_childSessionPids.clear();
        m_childPipeHandleValues.clear();
    }

    if (m_sessionProgressPid == 0)
    {
        m_sessionProgressPid = kPro.addReusable(this, "WinAPI", "准备会话");
    }
    kPro.set(m_sessionProgressPid, "准备命名管道连接", 0, 20.0f);

    startPipeReadThread();

    std::string detailText;
    const bool injectOk = reuseResidentAgent
        || ks::process::InjectDllByPath(pidValue, dllPathText.toStdString(), &detailText);
    if (!injectOk)
    {
        const QString injectErrorText = QString::fromStdString(detailText);
        // privilegePromptHandled：权限恢复提示已处理时只保留内部日志与会话清理。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("注入 API 监控 DLL"),
            injectErrorText);
        appendInternalEvent(QStringLiteral("内部"), QStringLiteral("InjectDllByPath"), QString::fromStdString(detailText));
        stopMonitoringInternal(false);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("WinAPI 监控"),
                QStringLiteral("DLL 注入失败：%1").arg(injectErrorText));
        }
        return;
    }

    if (!reuseResidentAgent)
    {
        rememberResidentAgentForProcess(pidValue);
    }

    appendInternalEvent(
        QStringLiteral("内部"),
        QStringLiteral("会话已启动"),
        reuseResidentAgent
            ? QStringLiteral("已原子写入配置并复用常驻 Agent，等待其重新创建命名管道。")
            : QStringLiteral("已原子写入配置并完成 DLL 注入，等待 Agent 创建命名管道。"));

    kPro.set(
        m_sessionProgressPid,
        reuseResidentAgent ? "复用常驻 Agent，等待握手" : "DLL 已注入，等待 Agent 握手",
        0,
        45.0f);
    updateActionState();
    updateStatusLabel();
}

void WinAPIDock::stopMonitoring()
{
    stopMonitoringInternal(false);
}

void WinAPIDock::stopMonitoringInternal(const bool waitForThread)
{
    if (!m_pipeRunning.load() && (m_pipeThread == nullptr || !m_pipeThread->joinable()))
    {
        return;
    }

    m_pipeStopFlag.store(true);
    writeChildStopFlags();

    if (!m_currentStopFlagPath.trimmed().isEmpty())
    {
        QFile stopFile(m_currentStopFlagPath);
        if (stopFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
        {
            stopFile.write("stop");
            stopFile.close();
        }
    }

    if (m_pipeThread != nullptr && m_pipeThread->joinable())
    {
        // The reader owns a synchronous ReadFile, so cancel it before joining.
        (void)::CancelSynchronousIo(m_pipeThread->native_handle());
        m_pipeThread->join();
    }
    m_pipeThread.reset();

    const std::uintptr_t pipeHandleValue = m_pipeHandleValue.exchange(0);
    if (pipeHandleValue != 0)
    {
        ::CloseHandle(reinterpret_cast<HANDLE>(pipeHandleValue));
    }
    joinChildPipeThreads();
    closeChildPipeHandles();

    m_pipeRunning.store(false);
    m_pipeConnected.store(false);
    kPro.set(m_sessionProgressPid, "WinAPI 监控已停止", 0, 100.0f);

    if (!waitForThread)
    {
        appendInternalEvent(QStringLiteral("内部"), QStringLiteral("停止监控"), QStringLiteral("已发出停止标记并回收本地管道线程。"));
    }

    updateActionState();
    updateStatusLabel();
}

void WinAPIDock::terminateHooksForSelectedProcess()
{
    std::uint32_t pidValue = 0;
    if (!currentSelectedPid(&pidValue))
    {
        QMessageBox::information(this, QStringLiteral("终止 Hook"), QStringLiteral("请先选择目标进程或手动输入 PID。"));
        return;
    }

    const QString sessionDirectory = QString::fromStdWString(ks::winapi_monitor::buildSessionDirectory());
    QDir sessionDir;
    if (!sessionDir.mkpath(sessionDirectory))
    {
        QMessageBox::warning(this, QStringLiteral("终止 Hook"), QStringLiteral("无法创建会话目录：%1").arg(sessionDirectory));
        return;
    }

    const QString stopFlagPath = QString::fromStdWString(ks::winapi_monitor::buildStopFlagPathForPid(pidValue));
    QFile stopFile(stopFlagPath);
    if (!stopFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(this, QStringLiteral("终止 Hook"), QStringLiteral("无法写入停止标记：%1").arg(stopFlagPath));
        return;
    }
    stopFile.write("stop");
    stopFile.close();

    if (m_pipeRunning.load() && m_currentSessionPid == pidValue)
    {
        stopMonitoringInternal(false);
    }
    else
    {
        appendInternalEvent(
            QStringLiteral("内部"),
            QStringLiteral("手动终止 Hook"),
            QStringLiteral("已为 PID=%1 写入停止标记。").arg(pidValue));
        updateActionState();
        updateStatusLabel();
    }
}

void WinAPIDock::applyEventFilter()
{
    if (m_eventTable == nullptr)
    {
        return;
    }

    const QString keywordText = m_eventFilterEdit != nullptr ? m_eventFilterEdit->text().trimmed() : QString();
    if (keywordText.isEmpty())
    {
        if (m_eventFilterActive)
        {
            for (int row = 0; row < m_eventTable->rowCount(); ++row)
            {
                m_eventTable->setRowHidden(row, false);
            }
        }
        m_eventFilterActive = false;
        if (m_eventFilterStatusLabel != nullptr)
        {
            m_eventFilterStatusLabel->setText(
                QStringLiteral("筛选结果：%1 / %2")
                    .arg(m_eventTable->rowCount())
                    .arg(m_eventTable->rowCount()));
            m_eventFilterStatusLabel->setStyleSheet(buildStatusStyle(
                m_eventTable->rowCount() > 0 ? monitorSuccessColorHex() : monitorIdleColorHex()));
        }
        return;
    }

    m_eventFilterActive = true;
    int visibleCount = 0;

    for (int row = 0; row < m_eventTable->rowCount(); ++row)
    {
        QStringList rowTextList;
        for (int column = 0; column < EventColumnCount; ++column)
        {
            QTableWidgetItem* itemPointer = m_eventTable->item(row, column);
            rowTextList << (itemPointer != nullptr ? itemPointer->text() : QString());
        }

        const QString mergedText = rowTextList.join(QStringLiteral(" | "));
        const bool visible = keywordText.isEmpty() || mergedText.contains(keywordText, Qt::CaseInsensitive);
        m_eventTable->setRowHidden(row, !visible);
        if (visible)
        {
            ++visibleCount;
        }
    }

    if (m_eventFilterStatusLabel != nullptr)
    {
        m_eventFilterStatusLabel->setText(
            QStringLiteral("筛选结果：%1 / %2").arg(visibleCount).arg(m_eventTable->rowCount()));
        m_eventFilterStatusLabel->setStyleSheet(buildStatusStyle(
            visibleCount > 0 ? monitorSuccessColorHex() : monitorIdleColorHex()));
    }
}

void WinAPIDock::clearEventFilter()
{
    if (m_eventFilterEdit != nullptr)
    {
        m_eventFilterEdit->clear();
    }
    applyEventFilter();
}

void WinAPIDock::exportVisibleRowsToTsv()
{
    if (m_eventTable == nullptr || m_eventTable->rowCount() == 0)
    {
        QMessageBox::information(this, QStringLiteral("导出 WinAPI 事件"), QStringLiteral("当前没有可导出的事件。"));
        return;
    }

    int visibleCount = 0;
    for (int row = 0; row < m_eventTable->rowCount(); ++row)
    {
        if (!m_eventTable->isRowHidden(row))
        {
            ++visibleCount;
        }
    }
    if (visibleCount == 0)
    {
        QMessageBox::information(this, QStringLiteral("导出 WinAPI 事件"), QStringLiteral("当前筛选结果为空。"));
        return;
    }

    const QString defaultFileName = QStringLiteral("winapi_events_%1.tsv")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    const QString exportPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出 WinAPI 事件"),
        defaultFileName,
        QStringLiteral("TSV 文件 (*.tsv);;文本文件 (*.txt)"));
    if (exportPath.trimmed().isEmpty())
    {
        return;
    }

    QFile exportFile(exportPath);
    if (!exportFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        QMessageBox::warning(this, QStringLiteral("导出 WinAPI 事件"), QStringLiteral("无法写入文件：%1").arg(exportPath));
        return;
    }

    QTextStream outputStream(&exportFile);
    QStringList headerTextList;
    for (int column = 0; column < EventColumnCount; ++column)
    {
        QTableWidgetItem* headerItem = m_eventTable->horizontalHeaderItem(column);
        headerTextList << (headerItem != nullptr ? headerItem->text() : QString());
    }
    outputStream << headerTextList.join('\t') << '\n';

    for (int row = 0; row < m_eventTable->rowCount(); ++row)
    {
        if (m_eventTable->isRowHidden(row))
        {
            continue;
        }

        QStringList rowTextList;
        for (int column = 0; column < EventColumnCount; ++column)
        {
            QTableWidgetItem* itemPointer = m_eventTable->item(row, column);
            rowTextList << (itemPointer != nullptr ? itemPointer->text().replace('\t', ' ') : QString());
        }
        outputStream << rowTextList.join('\t') << '\n';
    }
    exportFile.close();
}

void WinAPIDock::showEventContextMenu(const QPoint& position)
{
    if (m_eventTable == nullptr)
    {
        return;
    }

    const QModelIndex indexValue = m_eventTable->indexAt(position);
    if (!indexValue.isValid())
    {
        return;
    }

    const int row = indexValue.row();
    const int column = indexValue.column();

    QMenu menu(this);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* copyCellAction = menu.addAction(QStringLiteral("复制单元格"));
    QAction* copyRowAction = menu.addAction(QStringLiteral("复制整行"));
    const QTableWidgetItem* processIdItem = m_eventTable->item(row, EventColumnPidTid);
    std::uint32_t processId = 0;
    const bool hasProcessId = processIdItem != nullptr &&
        ks::online_scan::tryParsePidFromText(processIdItem->text(), &processId) &&
        processId != 0U;
    QAction* openProcessDetailAction = menu.addAction(QStringLiteral("转到进程详细信息"));
    openProcessDetailAction->setEnabled(hasProcessId);
    menu.addSeparator();
    ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [this, row]() -> ks::online_scan::SandboxUploadTarget {
            // 输入：WinAPI 监控事件表当前右键行。
            // 处理：从 PID/TID 列解析进程 PID，再解析进程镜像路径。
            // 返回：VT 上传目标；解析失败时返回 errorText 交给统一 helper 弹窗。
            QTableWidgetItem* pidItem = m_eventTable != nullptr
                ? m_eventTable->item(row, EventColumnPidTid)
                : nullptr;
            std::uint32_t pidValue = 0;
            if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &pidValue))
            {
                return {
                    QString(),
                    QStringLiteral("WinAPI 监控事件"),
                    QStringLiteral("当前事件行未解析出有效 PID，无法上传发起进程文件。")
                };
            }

            const QString processPath = QString::fromStdString(ks::process::QueryProcessPathByPid(pidValue)).trimmed();
            if (processPath.isEmpty())
            {
                return {
                    QString(),
                    QStringLiteral("WinAPI 监控事件 PID=%1").arg(pidValue),
                    QStringLiteral("无法解析 PID=%1 的进程镜像路径。进程可能已退出，或当前权限不足。").arg(pidValue)
                };
            }

            return {
                processPath,
                QStringLiteral("WinAPI 监控事件 PID=%1").arg(pidValue),
                QString()
            };
        });

    QAction* selectedAction = menu.exec(m_eventTable->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == copyCellAction)
    {
        QTableWidgetItem* itemPointer = m_eventTable->item(row, column);
        if (itemPointer != nullptr)
        {
            QApplication::clipboard()->setText(itemPointer->text());
        }
        return;
    }

    if (selectedAction == openProcessDetailAction)
    {
        ks::ui::OpenProcessDetailByPid(processId);
        return;
    }

    if (selectedAction == copyRowAction)
    {
        QStringList rowTextList;
        for (int currentColumn = 0; currentColumn < EventColumnCount; ++currentColumn)
        {
            QTableWidgetItem* itemPointer = m_eventTable->item(row, currentColumn);
            rowTextList << (itemPointer != nullptr ? itemPointer->text() : QString());
        }
        QApplication::clipboard()->setText(rowTextList.join('\t'));
    }
}
