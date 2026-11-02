#include "MonitorCanonicalExport.h"
#include <QPushButton>
#include "../UI/StructuredFieldView.h"
#include "../UI/TableContextMenu.h"
#include "../UI/DetailDialogChrome.h"
#include "WinAPIDock.h"
#include "WinAPIEventTableModel.h"
#include "../UI/CodeEditorWidget.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/AsyncUiDispatcher.h"
#include "../UI/AsyncCleanupRegistry.h"
#include "../UI/ThemeStatusRole.h"
#include "../theme.h"

// ============================================================
// WinAPIDock.Actions.cpp
// 作用：
// 1) 实现 WinAPI Dock 的交互逻辑、会话控制和导出能力；
// 2) 把按钮动作、过滤与配置文件写入集中管理；
// 3) 与 Pipe 读取逻辑拆开，降低并发代码与 UI 代码耦合。
// ============================================================

#include <QApplication>
#include <QAbstractItemView>
#include <QImage>
#include <objbase.h>
#include <QPersistentModelIndex>
#include <QPixmap>
#include <QQueue>
#include <QRunnable>
#include <QScrollBar>
#include <QThreadPool>
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
#include <QTabWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QStringConverter>
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
#include <Shellapi.h>

#pragma comment(lib, "Shell32.lib")
#include "../../../shared/ApiMonitorInjection.h"

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

    // Pure value scheduler: at most two Shell requests and one bounded visible demand.
    // Completed failures also stay cached, so an unreadable path is not retried on every paint.
    struct ProcessIconDemandState
    {
        static constexpr int MaximumInFlight = 2;
        static constexpr qsizetype MaximumDemand = 129;
        static constexpr qsizetype MaximumCached = 512;
        QStringList demand;
        QSet<QString> inFlight;
        QSet<QString> completed;
        QQueue<QString> completedOrder;

        void replaceDemand(const QStringList& paths)
        {
            demand.clear();
            QSet<QString> seen;
            for (const QString& path : paths)
            {
                if (path.isEmpty() || seen.contains(path)) continue;
                seen.insert(path);
                demand.append(path);
                if (demand.size() == MaximumDemand) break;
            }
        }

        QString takeNext()
        {
            if (inFlight.size() >= MaximumInFlight) return {};
            for (const QString& path : demand)
            {
                if (!inFlight.contains(path) && !completed.contains(path))
                {
                    inFlight.insert(path);
                    return path;
                }
            }
            return {};
        }

        QString complete(const QString& path)
        {
            inFlight.remove(path);
            if (completed.contains(path)) return {};
            completed.insert(path);
            completedOrder.enqueue(path);
            if (completedOrder.size() <= MaximumCached) return {};
            const QString evicted = completedOrder.dequeue();
            completed.remove(evicted);
            return evicted;
        }
    };

    const QIcon& processPlaceholderIcon()
    {
        static const QIcon icon(QStringLiteral(":/Icon/process_main.svg"));
        return icon;
    }

    QString processIconPathKey(const QString& path)
    {
        return QDir::fromNativeSeparators(path.trimmed()).toCaseFolded();
    }

    QImage extractProcessSelectorIcon(const QString& path)
    {
        const HRESULT initialized = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        struct ComScope { HRESULT result; ~ComScope() { if (SUCCEEDED(result)) ::CoUninitialize(); } } com{initialized};
        if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) return {};
        SHFILEINFOW shellInfo{};
        struct IconScope { SHFILEINFOW& value; ~IconScope() { if (value.hIcon) ::DestroyIcon(value.hIcon); } } icon{shellInfo};
        const auto result = ::SHGetFileInfoW(reinterpret_cast<const wchar_t*>(path.utf16()),
            0, &shellInfo, sizeof(shellInfo), SHGFI_ICON | SHGFI_LARGEICON);
        return result == 0 || !shellInfo.hIcon ? QImage{} : QImage::fromHICON(shellInfo.hIcon);
    }

    // QObject owns only projection/cache state. Workers own values and a closeable dispatcher;
    // neither closing this page nor refreshing its candidate model waits for Shell.
    class ProcessSelectorIconLoader final : public QObject
    {
    public:
        explicit ProcessSelectorIconLoader(QComboBox* combo, QLabel* selectedIcon)
            : QObject(combo), m_combo(combo), m_selectedIcon(selectedIcon), m_dispatcher(std::make_shared<ks::ui::AsyncUiDispatcher>(this))
        {
            setObjectName(QStringLiteral("winapi-process-icon-loader"));
            m_timer.setSingleShot(true);
            m_timer.setInterval(0);
            connect(&m_timer, &QTimer::timeout, this, [this]() { refreshDemand(); });
            combo->installEventFilter(this);
            combo->view()->installEventFilter(this);
            combo->view()->viewport()->installEventFilter(this);
            connect(combo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this]() { schedule(); });
            connect(combo->view()->verticalScrollBar(), &QScrollBar::valueChanged,
                this, [this]() { schedule(); });
        }

        ~ProcessSelectorIconLoader() override { m_dispatcher->close(); }

        void schedule() { if (!m_timer.isActive()) m_timer.start(); }

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            switch (event->type())
            {
            case QEvent::Show:
            case QEvent::Hide:
            case QEvent::Resize:
            case QEvent::Wheel:
            case QEvent::KeyRelease:
                schedule();
                break;
            default: break;
            }
            return QObject::eventFilter(watched, event);
        }

    private:
        static QThreadPool& extractionPool()
        {
            static QThreadPool pool;
            static const bool configured = []() {
                pool.setMaxThreadCount(ProcessIconDemandState::MaximumInFlight);
                pool.setExpiryTimeout(1000);
                return true;
            }();
            (void)configured;
            return pool;
        }

        struct Completion { QString key; QImage image; std::atomic_bool done{false}; };
        void refreshDemand()
        {
            for (auto item = m_completions.begin(); item != m_completions.end(); ) {
                if (!(*item)->done.load(std::memory_order_acquire)) { ++item; continue; }
                const auto result = std::move(*item); item = m_completions.erase(item);
                const QString evicted = m_state.complete(result->key);
                if (!evicted.isEmpty()) m_icons.remove(evicted);
                m_icons.insert(result->key, result->image.isNull() ? processPlaceholderIcon() : QIcon(QPixmap::fromImage(result->image)));
            }
            QStringList paths;
            QHash<QString, QString> originalPaths;
            QVector<QPersistentModelIndex> indexes;
            auto addRow = [this, &paths, &originalPaths, &indexes](const int row) {
                if (row < 0 || row >= m_combo->count()) return;
                const QModelIndex index = m_combo->model()->index(row, m_combo->modelColumn(), m_combo->rootModelIndex());
                const QString path = index.data(Qt::UserRole + 2).toString().trimmed();
                const QString key = processIconPathKey(path);
                if (key.isEmpty()) return;
                indexes.append(QPersistentModelIndex(index));
                paths.append(key);
                originalPaths.insert(key, path);
            };
            // The selected candidate gets first priority; unopened/hidden candidates do no work.
            if (m_combo->isVisible()) addRow(m_combo->currentIndex());
            QAbstractItemView* view = m_combo->view();
            if (m_combo->isVisible() && view->isVisible())
            {
                const QModelIndex first = view->indexAt(QPoint(2, 2));
                const QModelIndex last = view->indexAt(QPoint(2, std::max(2, view->viewport()->height() - 2)));
                const int firstRow = first.isValid() ? first.row() : 0;
                const int lastRow = last.isValid() ? last.row() : firstRow + 127;
                for (int row = firstRow; row <= lastRow && row < firstRow + 128; ++row) addRow(row);
            }
            m_state.replaceDemand(paths);
            for (const QPersistentModelIndex& index : indexes)
            {
                if (!index.isValid()) continue;
                const QString key = processIconPathKey(index.data(Qt::UserRole + 2).toString());
                const auto cached = m_icons.constFind(key);
                if (cached != m_icons.constEnd())
                {
                    const QIcon current = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
                    if (current.cacheKey() != cached->cacheKey())
                        m_combo->model()->setData(index, *cached, Qt::DecorationRole);
                }
            }
            if (m_selectedIcon != nullptr && m_combo->currentIndex() >= 0)
                m_selectedIcon->setPixmap(m_combo->itemIcon(m_combo->currentIndex()).pixmap(20, 20));
            for (QString key = m_state.takeNext(); !key.isEmpty(); key = m_state.takeNext())
            {
                const auto cleanupLease = ks::ui::AsyncCleanupRegistry::global().acquire();
                if (!cleanupLease) { m_state.inFlight.remove(key); break; }
                const QString path = originalPaths.value(key);
                const auto dispatcher = m_dispatcher;
                const auto completion = std::make_shared<Completion>(); completion->key = key;
                m_completions.push_back(completion);
                extractionPool().start(QRunnable::create([this, dispatcher, path, completion, cleanupLease]() {
                    (void)cleanupLease; // Accepted native work stays visible to final shutdown.
                    try { completion->image = extractProcessSelectorIcon(path); } catch (...) {}
                    completion->done.store(true, std::memory_order_release);
                    // Physical completion survives a rejected/dropped wake. The
                    // next existing show/scroll/selection refresh consumes it.
                    dispatcher->post([this]() { schedule(); });
                }));
            }
        }

        QComboBox* m_combo;
        QPointer<QLabel> m_selectedIcon;
        QTimer m_timer;
        ProcessIconDemandState m_state;
        std::vector<std::shared_ptr<Completion>> m_completions;
        QHash<QString, QIcon> m_icons;
        std::shared_ptr<ks::ui::AsyncUiDispatcher> m_dispatcher;
    };

    ProcessSelectorIconLoader* processIconLoader(QComboBox* combo, QLabel* selectedIcon)
    {
        auto* existing = combo->findChild<QObject*>(QStringLiteral("winapi-process-icon-loader"), Qt::FindDirectChildrenOnly);
        return existing != nullptr ? static_cast<ProcessSelectorIconLoader*>(existing) : new ProcessSelectorIconLoader(combo, selectedIcon);
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
                pollSessionBackend(); acceptPendingEventRows(); clearCanonicalEvents();
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
        connect(m_eventTable, &QTableView::customContextMenuRequested, this, [this](const QPoint& position) {
            showEventContextMenu(position);
        });
        connect(m_eventTable, &QTableView::doubleClicked, this, [this](const QModelIndex& index) {
            showEventDetailDialog(index.row());
        });
    }
    if (m_resultTabs)
    {
        connect(m_resultTabs, &QTabWidget::currentChanged, this, [this](int) {
            QTimer::singleShot(0, this, [this]() { flushPendingRows(); });
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
        ks::ui::ApplyStatusRole(m_processStatusLabel, ks::ui::StatusRole::Info);
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
            const QIcon processIcon = processPlaceholderIcon();
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
        ks::ui::ApplyStatusRole(m_processStatusLabel, ks::ui::StatusRole::Success);
    }
    processIconLoader(m_processCombo, m_processIconLabel)->schedule();
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
            ks::ui::ApplyStatusRole(m_processStatusLabel, ks::ui::StatusRole::Success);
        }
        else
        {
            m_processStatusLabel->setText(QStringLiteral("● 使用手动 PID=%1").arg(pidValue));
            ks::ui::ApplyStatusRole(m_processStatusLabel, ks::ui::StatusRole::Warning);
        }
        return;
    }

    const QString inputText = m_processCombo->currentText().trimmed();
    if (inputText.isEmpty())
    {
        m_processStatusLabel->setText(QStringLiteral("● 候选 %1 个；输入进程名/PID 选择目标").arg(m_processCombo->count()));
        ks::ui::ApplyStatusRole(m_processStatusLabel, ks::ui::StatusRole::Idle);
        return;
    }
    m_processStatusLabel->setText(QStringLiteral("● 未明确选中目标；请从下拉候选选择或输入数字 PID"));
    ks::ui::ApplyStatusRole(m_processStatusLabel, ks::ui::StatusRole::Warning);
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
        QStringLiteral("选择 API 监控 DLL"),
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

QString WinAPIDock::fakeSuccessRulesIniText() const
{
    // fakeSuccessRulesIniText:
    // - Input: the current Fake Success rule table.
    // - Processing: serializes each exact rule as module|api|returnType|returnValue|lastErrorKind|lastErrorValue|x86StackBytes.
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
            cellToken(row, FakeRuleColumnLastErrorValue),
            cellToken(row, FakeRuleColumnX86StackBytes)
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
        const QString stackBytesText = tableCellText(m_fakeRuleTable, row, FakeRuleColumnX86StackBytes);

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

        quint64 parsedStackBytes = 0;
        if (!stackBytesText.isEmpty() && (!parseFakeUnsigned64(stackBytesText, &parsedStackBytes)
                || parsedStackBytes > 65532 || parsedStackBytes % 4 != 0))
        {
            if (errorTextOut) *errorTextOut = QStringLiteral("32 位栈清理字节数必须留空，或填写 0 到 65532 的 4 的倍数。");
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
    const QString stackBytesText = m_fakeX86StackBytesEdit != nullptr ? m_fakeX86StackBytesEdit->text().trimmed() : QString();

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

    quint64 parsedStackBytes = 0;
    if (!stackBytesText.isEmpty() && (!parseFakeUnsigned64(stackBytesText, &parsedStackBytes)
            || parsedStackBytes > 65532 || parsedStackBytes % 4 != 0))
    {
        QMessageBox::warning(this, QStringLiteral("Fake Success"), QStringLiteral("32 位栈清理字节数必须留空，或填写 0 到 65532 的 4 的倍数。"));
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
    m_fakeRuleTable->setItem(row, FakeRuleColumnX86StackBytes,
        createReadOnlyItem(stackBytesText.isEmpty() ? QString() : QString::number(parsedStackBytes)));
    m_fakeRuleTable->selectRow(row);

    if (m_fakeRuleStatusLabel != nullptr)
    {
        m_fakeRuleStatusLabel->setText(QStringLiteral("规则：%1 条；启动会话时应用。").arg(m_fakeRuleTable->rowCount()));
        ks::ui::ApplyStatusRole(m_fakeRuleStatusLabel, ks::ui::StatusRole::Info);
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
        ks::ui::ApplyStatusRole(m_fakeRuleStatusLabel, ks::ui::StatusRole::Idle);
    }
    updateActionState();
}

QString WinAPIDock::freezeSessionOptions() const
{
    QString options;
    QTextStream outputStream(&options);
    outputStream << "enable_file=" << ((m_hookFileCheck != nullptr && m_hookFileCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_registry=" << ((m_hookRegistryCheck != nullptr && m_hookRegistryCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_network=" << ((m_hookNetworkCheck != nullptr && m_hookNetworkCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_process=" << ((m_hookProcessCheck != nullptr && m_hookProcessCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_loader=" << ((m_hookLoaderCheck != nullptr && m_hookLoaderCheck->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_clipboard=" << ((m_hookClipboardCheck != nullptr && m_hookClipboardCheck->isChecked()) ? 1 : 0) << '\n';
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
    return options;
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
    if (m_sessionBackend) m_sessionBackend->enqueue(std::move(rowValue));
    else
    {
        auto record = std::make_shared<WinAPIEventRecord>();
        record->searchText = WinAPIEventFields(rowValue).join(QStringLiteral(" | "));
        record->value = std::move(rowValue);
        m_eventArchive.append(std::move(record)); m_evictedRows = m_eventArchive.evictedCount();
        m_eventProjectionStale = true;
    }
    updateActionState();
    updateStatusLabel();
}

void WinAPIDock::showEventDetailDialog(const int rowValue)
{
    // showEventDetailDialog 作用：
    // - 输入：rowValue 为事件表中的物理行号；
    // - 处理：读取该行所有列，拼成可复制的多行详情文本并用模态窗口展示；
    // - 返回：无返回值，行号无效或表格不存在时直接返回。
    if (m_eventTable == nullptr || rowValue < 0 || rowValue >= m_eventTable->model()->rowCount())
    {
        return;
    }

    const auto columnText = [this, rowValue](const int columnValue) -> QString {
        return m_eventTable->model()->index(rowValue, columnValue).data().toString();
    };

    ks::ui::FieldDocument detailText;
    detailText.field(QStringLiteral("时间(100ns)"), QStringLiteral("%1").arg(columnText(EventColumnTime100ns)));
    detailText.field(QStringLiteral("分类"), QStringLiteral("%1").arg(columnText(EventColumnCategory)));
    detailText.field(QStringLiteral("API"), QStringLiteral("%1").arg(columnText(EventColumnApi)));
    detailText.field(QStringLiteral("结果"), QStringLiteral("%1").arg(columnText(EventColumnResult)));
    detailText.field(QStringLiteral("PID/TID"), QStringLiteral("%1").arg(columnText(EventColumnPidTid)));
    detailText.field(QStringLiteral("详情"), QStringLiteral("%1").arg(columnText(EventColumnDetail)));

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("WinAPI 事件详情"));
    dialog.resize(760, 420);

    QVBoxLayout* const layout = new QVBoxLayout(&dialog);
    layout->setContentsMargins(10, 10, 10, 10);
    layout->setSpacing(8);

    // 事件详情由本页拼装，使用统一编辑器以便英语模式即时重绘固定字段名。
    ks::ui::StructuredFieldView* const detailEdit = new ks::ui::StructuredFieldView(&dialog);

    detailEdit->setDocument(detailText);
    layout->addWidget(detailEdit, 1);

    QDialogButtonBox* const buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok, &dialog);
    buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("关闭"));
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    layout->addWidget(buttonBox, 0);

    ks::ui::ApplyDetailDialogChrome(&dialog);
    dialog.exec();
}

void WinAPIDock::startMonitoring()
{
    if (m_pipeRunning.load() || (m_sessionCleanup && !m_sessionCleanup->isComplete())
        || (m_sessionOperation && m_sessionOperation->isBusy())) return;
    std::uint32_t pid = 0;
    if (!currentSelectedPid(&pid))
    {
        QMessageBox::information(this, QStringLiteral("WinAPI 监控"), QStringLiteral("请先选择目标进程或手动输入 PID。"));
        return;
    }
    if (!m_agentDllPathEdit) return;
    QString error;
    if (!validateFakeSuccessRules(&error))
    { QMessageBox::warning(this, QStringLiteral("WinAPI 监控"), error); return; }
    WinAPISessionConfig config;
    config.pid = pid;
    config.generation = m_sessionGeneration.load() + 1;
    config.requestedAgentPath = m_agentDllPathEdit->text().trimmed();
    config.sessionId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    config.options = freezeSessionOptions(); // Last GUI access; workers receive only values.
    config.residentPid = m_residentAgentPid;
    config.residentCreation = m_residentAgentCreationTime100ns;
    config.autoInjectChildren = m_autoInjectChildCheck && m_autoInjectChildCheck->isChecked();
    auto backend = std::make_shared<WinAPISessionBackend>(std::move(config));
    auto cleanup = ks::ui::RetainedCleanupJob::create([backend]() { return backend->cleanup(); }, 0,
        [backend]() { backend->requestStop(); });
    if (!cleanup || cleanup->isCleanupRequested()) return; // An old shutdown epoch is never reopened.
    m_sessionBackend = backend; m_sessionCleanup = cleanup;
    m_currentSessionPid = pid; m_currentSessionId = backend->config.sessionId;
    m_sessionGeneration.store(backend->config.generation);
    m_startupReported = false; m_stopReported = false; m_stopping = false; m_reportedCleanupAttempt = 0;
    clearCanonicalEvents();
    {
        const std::lock_guard<std::mutex> lock(m_pendingMutex);
        m_pendingRows.clear(); m_pendingDroppedRows = 0; m_agentDroppedRows.clear(); m_evictedRows = 0;
    }
    m_hookState = HookState::Waiting; m_definitionMismatch = false;
    resetCoverageView(); m_pipeRunning.store(true); m_pipeConnected.store(false);
    if (!m_sessionProgressPid) m_sessionProgressPid = kPro.addReusable(this, "WinAPI", "准备会话");
    kPro.set(m_sessionProgressPid, "准备命名管道连接", 0, 20.0f);
    updateActionState(); updateStatusLabel();
    // Accepted startup is never latest-only. The retained backend serializes its
    // terminal result with STOP, even if delivery or the page disappears.
    const auto ticket = m_sessionOperation->submitTransaction<std::shared_ptr<WinAPISessionBackend>, bool>(backend,
        [cleanup](const auto& value)
        {
            const bool started = value->start();
            if (!started && !cleanup->isCleanupRequested()) cleanup->requestCleanup();
            return started;
        },
        [this](const bool&, std::uint64_t) { pollSessionBackend(); return true; },
        [this](std::exception_ptr)
        {
            m_stopping = true;
            if (m_sessionBackend) m_sessionBackend->requestStop();
            if (m_sessionCleanup && !m_sessionCleanup->isCleanupRequested()) m_sessionCleanup->requestCleanup();
            updateActionState(); updateStatusLabel();
        },
        [backend, cleanup](ks::ui::AsyncOperationOutcome outcome)
        {
            if (outcome != ks::ui::AsyncOperationOutcome::Applied)
            { backend->requestStop(); if (!cleanup->isCleanupRequested()) cleanup->requestCleanup(); }
        });
    if (!ticket) { backend->requestStop(); if (!cleanup->isCleanupRequested()) cleanup->requestCleanup(); m_stopping = true; }
}

void WinAPIDock::stopMonitoring() { stopMonitoringInternal(false); }

void WinAPIDock::stopMonitoringInternal(const bool ownerClosing)
{
    if (!m_sessionBackend || !m_sessionCleanup) return;
    m_sessionBackend->requestStop(); // No file IO, broker destruction or join on GUI.
    m_stopping = true;
    if (!m_sessionCleanup->isCleanupRequested() || !ownerClosing)
        m_sessionCleanup->requestCleanup(); // Only an explicit Stop/Retry retries a failed attempt.
    if (!ownerClosing) { updateActionState(); updateStatusLabel(); }
}

void WinAPIDock::terminateHooksForSelectedProcess()
{
    std::uint32_t pid = 0;
    if (!currentSelectedPid(&pid))
    {
        QMessageBox::information(this, QStringLiteral("终止 Hook"), QStringLiteral("请先选择目标进程或手动输入 PID。"));
        return;
    }
    if (m_sessionCleanup && !m_sessionCleanup->isComplete())
    {
        if (m_currentSessionPid == pid) stopMonitoringInternal(false);
        return;
    }
    if (m_sessionOperation && m_sessionOperation->isBusy()) return;
    pollSessionBackend(); // Preserve the prior session's final accepted inbox before replacing its owner.
    WinAPISessionConfig config;
    config.pid = pid; config.stopOnly = true;
    config.generation = m_sessionGeneration.load() + 1;
    auto backend = std::make_shared<WinAPISessionBackend>(std::move(config));
    auto cleanup = ks::ui::RetainedCleanupJob::create([backend]() { return backend->cleanup(); }, 0,
        [backend]() { backend->requestStop(); });
    if (!cleanup) return;
    m_sessionBackend = backend; m_sessionCleanup = cleanup;
    m_currentSessionPid = pid; m_sessionGeneration.store(backend->config.generation);
    m_startupReported = true; m_stopReported = false; m_stopping = true; m_reportedCleanupAttempt = 0;
    m_pipeRunning.store(true); m_pipeConnected.store(false);
    cleanup->requestCleanup();
    updateActionState(); updateStatusLabel();
}

void WinAPIDock::initializeEventProjection()
{
    initializeEventTailFollow();
    m_eventModel->filterStateChanged = [this]() {
        m_visibleEventCount = m_eventProxy->rowCount();
        if (m_eventFilterStatusLabel) {
            m_eventFilterStatusLabel->setText(QStringLiteral("筛选结果：%1 / %2").arg(m_visibleEventCount).arg(m_eventModel->rowCount()));
            ks::ui::ApplyStatusRole(m_eventFilterStatusLabel, (m_eventModel->filterPending() || m_eventModel->filterFailed()) ? ks::ui::StatusRole::Warning
                : m_visibleEventCount > 0 ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Idle);
        }
    };
    applyEventFilter();
}

void WinAPIDock::applyEventFilter()
{
    m_eventFilterKeyword = m_eventFilterEdit ? m_eventFilterEdit->text().trimmed() : QString();
    if (!m_eventModel) return;
    m_eventModel->setKeyword(m_eventFilterKeyword);
    if (m_eventModel->filterStateChanged) m_eventModel->filterStateChanged();
}

void WinAPIDock::clearEventFilter()
{
    if (m_eventFilterEdit != nullptr)
    {
        m_eventFilterEdit->clear();
    }
    applyEventFilter();
}

void WinAPIDock::updateEventExportAction()
{
    if (!m_exportButton) return;
    const bool preparing = m_eventExport && m_eventExport->isPreparing();
    const bool busy = m_eventExport && m_eventExport->isBusy();
    m_exportButton->setEnabled(preparing || (!busy && m_eventArchive.size() > 0));
    auto& language = ks::i18n::LanguageManager::instance();
    m_exportButton->setToolTip(preparing
        ? language.text(QStringLiteral("monitor.export.preparing_hint"), QStringLiteral("正在准备完整导出；再次点击可取消准备。"))
        : busy ? language.text(QStringLiteral("monitor.export.in_progress"), QStringLiteral("导出进行中"))
        : ks::i18n::sourceText(QStringLiteral("导出当前可见事件为 TSV")));
}

void WinAPIDock::exportVisibleRowsToTsv()
{
    const QPointer<WinAPIDock> guard(this);
    if (m_eventExport) m_eventExport->reconcile();
    if (!guard) return;
    if (m_eventExport && m_eventExport->isPreparing()) { m_eventExport->cancelPreparation(); return; }
    if (m_eventExport && m_eventExport->isBusy()) return;
    const QString defaultFileName = QStringLiteral("winapi_events_%1.tsv")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("导出 WinAPI 事件"), defaultFileName,
        QStringLiteral("TSV 文件 (*.tsv);;文本文件 (*.txt)"));
    if (!guard || path.trimmed().isEmpty() || (m_eventExport && m_eventExport->isBusy())) return;
    try {
        const auto snapshot = ks::monitor::MakeCanonicalExportSnapshot(freezeVisibleEventRowsForExport());
        if (!guard) return;
        if (snapshot->rows.empty()) {
            QMessageBox::information(this, QStringLiteral("导出 WinAPI 事件"), QStringLiteral("当前没有可导出的事件。")); return;
        }
        if (!m_eventExport) {
            m_eventExport = new ks::monitor::MonitorCanonicalExport(this);
            m_eventExport->setStateChangedCallback([guard]() { if (guard) guard->updateEventExportAction(); });
        }
        const bool started = m_eventExport->start(snapshot, QStringLiteral("monitor/winapi/session-%1/pid-%2/retained-events").arg(snapshot->sessionGeneration).arg(snapshot->targetPid), path, QStringLiteral("# 仅导出当前表格中的可见记录；这不是完整调用轨迹。%1").arg(snapshot->lossSummary),
            [guard](const ks::monitor::CanonicalExportOutcome& result) {
                if (!guard || result.kind == ks::monitor::CanonicalExportOutcomeKind::Canceled) return;
                auto& language = ks::i18n::LanguageManager::instance();
                if (result.kind == ks::monitor::CanonicalExportOutcomeKind::Empty) {
                    QMessageBox::information(guard, QStringLiteral("导出 WinAPI 事件"), QStringLiteral("当前筛选结果为空。")); return;
                }
                if (result.kind != ks::monitor::CanonicalExportOutcomeKind::FileFinished) {
                    QMessageBox::warning(guard, QStringLiteral("导出 WinAPI 事件"), language.text(QStringLiteral("monitor.export.not_accepted"),
                        QStringLiteral("未开始写入文件，请重试导出。"))); return;
                }
                const auto& receipt = result.receipt;
                if (receipt.phase == ks::ui::CompleteExportPhase::OutcomeUnavailable) {
                    QMessageBox::warning(guard, language.text(QStringLiteral("monitor.export.result_unconfirmed_title"), QStringLiteral("导出结果待确认")),
                        language.text(QStringLiteral("monitor.export.result_unconfirmed"), QStringLiteral("导出结果尚未确认，请核对目标文件：%1")).arg(receipt.outputPath)); return;
                }
                if (!receipt.succeeded()) QMessageBox::warning(guard, QStringLiteral("导出 WinAPI 事件"),
                    language.text(QStringLiteral("monitor.export.write_failed"), QStringLiteral("导出失败：%1")).arg(receipt.nativeError));
            });
        if (!guard) return;
        if (!started) QMessageBox::information(this, QStringLiteral("导出 WinAPI 事件"),
            ks::i18n::LanguageManager::instance().text(QStringLiteral("monitor.export.not_accepted"), QStringLiteral("未开始写入文件，请重试导出。")));
    } catch (...) {
        if (guard) QMessageBox::warning(guard, QStringLiteral("导出 WinAPI 事件"),
            ks::i18n::LanguageManager::instance().text(QStringLiteral("monitor.export.not_accepted"), QStringLiteral("未开始写入文件，请重试导出。")));
    }
    if (guard) updateEventExportAction();
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
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copyCellAction, ks::ui::TableContextActionRole::CopyCell);
    QAction* copyRowAction = menu.addAction(QStringLiteral("复制整行"));
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);
    const QString processIdText = indexValue.siblingAtColumn(EventColumnPidTid).data().toString();
    std::uint32_t processId = 0;
    const bool hasProcessId = ks::online_scan::tryParsePidFromText(processIdText, &processId) &&
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
            const QString pidText = m_eventTable->model()->index(row, EventColumnPidTid).data().toString();
            std::uint32_t pidValue = 0;
            if (!ks::online_scan::tryParsePidFromText(pidText, &pidValue))
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
        QApplication::clipboard()->setText(m_eventTable->model()->index(row, column).data().toString());
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
            rowTextList << m_eventTable->model()->index(row, currentColumn).data().toString();
        }
        QApplication::clipboard()->setText(rowTextList.join('\t'));
    }
}
