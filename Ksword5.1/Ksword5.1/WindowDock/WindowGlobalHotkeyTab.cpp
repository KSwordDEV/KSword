#include "WindowGlobalHotkeyTab.h"
#include "../UI/FlatButtonTheme.h"

#include "../Framework.h"
#include "../Internationalization/LanguageManager.h"
#include "../ProcessDock/ProcessHotkeyEnumerator.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../ksword/process/process.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{
    // MaxRowsPerUiFlush：单次最多创建 128 行表格项，保证极端结果集也不会形成一次超长 UI 任务。
    constexpr qsizetype MaxRowsPerUiFlush = 128;

    enum AllHotkeyColumn : int
    {
        ColumnHotkey = 0,
        ColumnProcess,
        ColumnPid,
        ColumnTid,
        ColumnSource,
        ColumnHotkeyId,
        ColumnVkModifiers,
        ColumnObject,
        ColumnDetail,
        ColumnCount
    };

    QString allHotkeyText(const char* contextKey, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(contextKey), sourceText);
    }

    QString hex32(const std::uint32_t value, const int width = 0)
    {
        return QStringLiteral("0x%1")
            .arg(value, width, 16, QLatin1Char('0'))
            .toUpper();
    }

    QVector<QStringList> formatRows(const std::vector<ks::process::UserModeHotkeyRecord>& records)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<qsizetype>(records.size()));
        for (const ks::process::UserModeHotkeyRecord& record : records)
        {
            rows.push_back(QStringList{
                record.hotkeyText,
                record.processName,
                QString::number(record.processId),
                record.threadId == 0U ? QStringLiteral("-") : QString::number(record.threadId),
                record.sourceText,
                record.hotkeyId == 0U ? QStringLiteral("0") : hex32(record.hotkeyId),
                QStringLiteral("VK=0x%1 MOD=0x%2")
                    .arg(record.virtualKey, 2, 16, QLatin1Char('0'))
                    .arg(record.modifiers, 4, 16, QLatin1Char('0'))
                    .toUpper(),
                record.objectText,
                record.detailText });
        }
        return rows;
    }

    std::vector<ks::process::UserModeHotkeyProcessTarget> collectProcessTargets()
    {
        const std::vector<ks::process::ProcessRecord> processRecords =
            ks::process::EnumerateProcesses(ks::process::ProcessEnumStrategy::Auto);

        std::unordered_set<std::uint32_t> processIds;
        std::vector<ks::process::UserModeHotkeyProcessTarget> targets;
        targets.reserve(processRecords.size());
        for (const ks::process::ProcessRecord& processRecord : processRecords)
        {
            if (processRecord.pid == 0U || !processIds.insert(processRecord.pid).second)
            {
                continue;
            }

            targets.push_back(ks::process::UserModeHotkeyProcessTarget{
                processRecord.pid,
                QString::fromStdString(processRecord.processName),
                QString::fromStdString(processRecord.imagePath) });
        }
        return targets;
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setToolTip(text);
        return item;
    }
}

// PendingRefreshState：工作线程只写入该缓冲，UI 定时批量取走结果，避免逐进程事件淹没主线程。
struct WindowGlobalHotkeyTab::PendingRefreshState
{
    // mutex：保护下列跨线程共享字段，调用方只能在短临界区内持有。
    std::mutex mutex;
    // pendingRows：尚未合并到表格的数据行，由 UI 刷新定时器批量取走。
    std::deque<QStringList> pendingRows;
    // currentProcessName：最近完成扫描的进程名，用于展示实时进度。
    QString currentProcessName;
    // ticket：绑定发起本轮刷新的编号，防止旧任务结果污染新任务。
    std::uint64_t ticket = 0;
    // revision：每次后台状态变化时递增，避免 UI 重复处理同一快照。
    std::uint64_t revision = 0;
    // completedProcessCount：后台已经完成扫描的进程总数。
    std::uint32_t completedProcessCount = 0;
    // totalProcessCount：本轮枚举到的进程总数。
    std::uint32_t totalProcessCount = 0;
    // diagnosticProcessCount：包含诊断信息的进程累计数量。
    std::uint32_t diagnosticProcessCount = 0;
    // enumerationReady：表示进程枚举已经完成，可以展示总进度。
    bool enumerationReady = false;
    // completed：表示所有扫描线程都已退出，UI 可执行最终收尾。
    bool completed = false;
    // elapsedMs：整轮后台扫描耗时，仅在 completed 为 true 时有效。
    qint64 elapsedMs = 0;
};

WindowGlobalHotkeyTab::WindowGlobalHotkeyTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void WindowGlobalHotkeyTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!m_firstRefreshStarted)
    {
        m_firstRefreshStarted = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void WindowGlobalHotkeyTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        allHotkeyText("window.global_hotkey.refresh", QStringLiteral("刷新全部热键")),
        this);
    m_filterEdit = new QLineEdit(this);
    ks::ui::StyleSearchField(m_filterEdit);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setPlaceholderText(allHotkeyText(
        "window.global_hotkey.filter.placeholder",
        QStringLiteral("按热键、进程、PID/TID、来源、对象或详情筛选")));
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_filterEdit, 1);
    toolbar->setSpacing(8);
    ks::ui::NormalizeToolbarRow(toolbar);
    rootLayout->addLayout(toolbar);

    m_statusLabel = new QLabel(
        allHotkeyText("window.global_hotkey.summary.waiting", QStringLiteral("状态：等待刷新")),
        this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(m_statusLabel);

    m_table = new ks::ui::VisibleTableWidget(this);
    // 全部热键是可重复采集的主清单，保留快照和比较。
    ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::Full);
    m_table->setColumnCount(ColumnCount);
    m_table->setHorizontalHeaderLabels({
        allHotkeyText("window.global_hotkey.header.hotkey", QStringLiteral("热键")),
        allHotkeyText("window.global_hotkey.header.process", QStringLiteral("进程")),
        allHotkeyText("window.global_hotkey.header.pid", QStringLiteral("PID")),
        allHotkeyText("window.global_hotkey.header.tid", QStringLiteral("TID")),
        allHotkeyText("window.global_hotkey.header.source", QStringLiteral("来源")),
        allHotkeyText("window.global_hotkey.header.id", QStringLiteral("热键 ID")),
        allHotkeyText("window.global_hotkey.header.vk_mod", QStringLiteral("VK / Mod")),
        allHotkeyText("window.global_hotkey.header.object", QStringLiteral("热键对象")),
        allHotkeyText("window.global_hotkey.header.detail", QStringLiteral("详情")) });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(true);
    // 限制自动列宽只采样少量行，避免大结果集在扫描完成时再次长时间占用 UI。
    m_table->horizontalHeader()->setResizeContentsPrecision(100);
    rootLayout->addWidget(m_table, 1);

    // m_flushTimer：以固定节奏合并后台结果，使主线程每次处理的工作量保持有界。
    m_flushTimer = new QTimer(this);
    m_flushTimer->setInterval(100);
    m_flushTimer->setTimerType(Qt::CoarseTimer);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString&) { rebuildTable(); });
    connect(m_table, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) { showCopyMenu(position); });
    connect(m_flushTimer, &QTimer::timeout, this, [this]() { flushPendingSnapshot(); });
}

void WindowGlobalHotkeyTab::refreshAsync()
{
    if (m_refreshing)
    {
        return;
    }

    // 启动刷新会立即清空缓存并重建表格，菜单打开时连启动阶段一起延后。
    const QPointer<WindowGlobalHotkeyTab> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("window-global-hotkey-refresh-start"),
        { m_table },
        [safeThis]()
        {
            if (!safeThis.isNull())
            {
                safeThis->refreshAsync();
            }
        }))
    {
        return;
    }

    m_refreshing = true;
    m_firstRefreshStarted = true;
    const std::uint64_t ticket = ++m_refreshTicket;
    m_rows.clear();
    m_scannedProcessCount = 0U;
    m_totalProcessCount = 0U;
    m_diagnosticProcessCount = 0U;
    m_appliedRefreshRevision = 0U;
    // 扫描期间暂停自动排序，避免每批增量插入都触发一次全表重排。
    m_sortingEnabledBeforeRefresh = m_table->isSortingEnabled();
    m_table->setSortingEnabled(false);
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(allHotkeyText(
        "window.global_hotkey.summary.refreshing",
        QStringLiteral("状态：正在扫描全部进程的热键...")));
    rebuildTable();

    m_progressTaskId = kPro.add(
        this,
        allHotkeyText("window.global_hotkey.tab", QStringLiteral("全部热键")).toStdString(),
        allHotkeyText(
            "window.global_hotkey.progress.enumerating",
            QStringLiteral("正在枚举进程")).toStdString());
    kPro.set(m_progressTaskId, allHotkeyText(
        "window.global_hotkey.progress.enumerating",
        QStringLiteral("正在枚举进程")).toStdString(), 0, 0.0f);

    // refreshState：后台只持有独立共享状态，页面销毁后不会再访问 QWidget。
    const std::shared_ptr<PendingRefreshState> refreshState = std::make_shared<PendingRefreshState>();
    refreshState->ticket = ticket;
    m_refreshState = refreshState;
    m_flushTimer->start();

    std::thread([refreshState]()
    {
        // beginTime：统计完整的进程枚举、快捷方式索引和热键扫描耗时。
        const auto beginTime = std::chrono::steady_clock::now();
        const std::vector<ks::process::UserModeHotkeyProcessTarget> targets = collectProcessTargets();

        {
            // stateLock：发布进程总数，UI 会在下一次定时刷新时读取。
            const std::lock_guard<std::mutex> stateLock(refreshState->mutex);
            refreshState->totalProcessCount = static_cast<std::uint32_t>(targets.size());
            refreshState->enumerationReady = true;
            ++refreshState->revision;
        }

        ks::process::EnumerateUserModeHotkeysForProcesses(
            targets,
            [refreshState](ks::process::UserModeHotkeyBatchProgress progress)
            {
                // rows：在工作线程完成字符串格式化，避免把转换成本转移给 UI。
                QVector<QStringList> rows = formatRows(progress.records);
                const bool hasDiagnostic = progress.diagnosticText.contains(QLatin1Char('|'));

                // stateLock：一次性合并本进程结果和进度，临界区内不执行任何 UI 操作。
                const std::lock_guard<std::mutex> stateLock(refreshState->mutex);
                for (QStringList& row : rows)
                {
                    refreshState->pendingRows.push_back(std::move(row));
                }
                refreshState->completedProcessCount = std::max(
                    refreshState->completedProcessCount,
                    progress.completedProcessCount);
                refreshState->totalProcessCount = std::max(
                    refreshState->totalProcessCount,
                    progress.totalProcessCount);
                refreshState->currentProcessName = std::move(progress.processName);
                if (hasDiagnostic)
                {
                    ++refreshState->diagnosticProcessCount;
                }
                ++refreshState->revision;
            });

        // elapsedMs：所有扫描工作线程退出后再记录，保证完成状态对应完整结果。
        const qint64 elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - beginTime).count();
        {
            // stateLock：最终状态和剩余结果一起由 UI 定时器读取，确保完成事件不会越过结果事件。
            const std::lock_guard<std::mutex> stateLock(refreshState->mutex);
            refreshState->completed = true;
            refreshState->elapsedMs = elapsedMs;
            ++refreshState->revision;
        }
    }).detach();
}

void WindowGlobalHotkeyTab::flushPendingSnapshot()
{
    // refreshState：在锁外保留共享状态，避免 finishRefresh 释放成员后对象提前销毁。
    const std::shared_ptr<PendingRefreshState> refreshState = m_refreshState;
    if (!m_refreshing || refreshState == nullptr)
    {
        m_flushTimer->stop();
        return;
    }

    // 必须先于 stateLock 下的 pendingRows.pop_front() 延迟；同键 timeout 合并后，
    // 后台结果仍完整保留在共享队列，菜单关闭再按有界批次刷入。
    const QPointer<WindowGlobalHotkeyTab> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("window-global-hotkey-stream-flush"),
        { m_table },
        [safeThis]()
        {
            if (!safeThis.isNull())
            {
                safeThis->flushPendingSnapshot();
            }
        }))
    {
        return;
    }

    QVector<QStringList> rows;
    QString currentProcessName;
    std::uint64_t ticket = 0;
    std::uint64_t revision = 0;
    std::uint32_t completedProcessCount = 0;
    std::uint32_t totalProcessCount = 0;
    std::uint32_t diagnosticProcessCount = 0;
    bool enumerationReady = false;
    bool completed = false;
    qint64 elapsedMs = 0;

    {
        // stateLock：读取一致快照并取走待显示行，后台可立即继续写入下一批。
        const std::lock_guard<std::mutex> stateLock(refreshState->mutex);
        ticket = refreshState->ticket;
        revision = refreshState->revision;
        const bool hasPendingRows = !refreshState->pendingRows.empty();
        if (ticket != m_refreshTicket ||
            (revision == m_appliedRefreshRevision && !hasPendingRows))
        {
            return;
        }

        // batchRowCount：只取走有界数量的行，剩余数据由下一次定时刷新继续处理。
        const qsizetype batchRowCount = std::min(
            MaxRowsPerUiFlush,
            static_cast<qsizetype>(refreshState->pendingRows.size()));
        rows.reserve(batchRowCount);
        for (qsizetype rowIndex = 0; rowIndex < batchRowCount; ++rowIndex)
        {
            rows.push_back(std::move(refreshState->pendingRows.front()));
            refreshState->pendingRows.pop_front();
        }
        currentProcessName = refreshState->currentProcessName;
        completedProcessCount = refreshState->completedProcessCount;
        totalProcessCount = refreshState->totalProcessCount;
        diagnosticProcessCount = refreshState->diagnosticProcessCount;
        enumerationReady = refreshState->enumerationReady;
        // 后台完成且缓冲已经排空时才结束，避免最终状态越过尚未显示的结果。
        completed = refreshState->completed && refreshState->pendingRows.empty();
        elapsedMs = refreshState->elapsedMs;
    }

    m_appliedRefreshRevision = revision;
    if (enumerationReady && completedProcessCount == 0U)
    {
        m_totalProcessCount = totalProcessCount;
        m_statusLabel->setText(allHotkeyText(
            "window.global_hotkey.summary.indexing_shortcuts",
            QStringLiteral("状态：已找到 %1 个进程，正在读取快捷方式索引...")).arg(totalProcessCount));
        if (m_progressTaskId != 0)
        {
            kPro.set(
                m_progressTaskId,
                allHotkeyText(
                    "window.global_hotkey.progress.indexing_shortcuts",
                    QStringLiteral("正在读取快捷方式索引")).toStdString(),
                0,
                0.0f);
        }
    }

    if (completedProcessCount > 0U || !rows.isEmpty())
    {
        appendSnapshotRows(
            ticket,
            std::move(rows),
            completedProcessCount,
            totalProcessCount,
            currentProcessName,
            diagnosticProcessCount);
    }
    if (completed)
    {
        finishRefresh(ticket, elapsedMs);
    }
}

void WindowGlobalHotkeyTab::appendSnapshotRows(
    const std::uint64_t ticket,
    QVector<QStringList> rows,
    const std::uint32_t completedProcessCount,
    const std::uint32_t totalProcessCount,
    const QString& processName,
    const std::uint32_t diagnosticProcessCount)
{
    if (ticket != m_refreshTicket || !m_refreshing)
    {
        return;
    }

    m_scannedProcessCount = std::max(m_scannedProcessCount, completedProcessCount);
    m_totalProcessCount = std::max(m_totalProcessCount, totalProcessCount);
    m_diagnosticProcessCount = std::max(m_diagnosticProcessCount, diagnosticProcessCount);

    if (!rows.isEmpty())
    {
        // 新数据只追加到当前视图；筛选变化时仍可依据 m_rows 重建完整结果。
        appendVisibleRows(rows);
        m_rows += std::move(rows);
    }

    const QString currentProcessName = processName.trimmed().isEmpty()
        ? allHotkeyText("window.global_hotkey.process.unknown", QStringLiteral("<未知进程>"))
        : processName;
    m_statusLabel->setText(allHotkeyText(
        "window.global_hotkey.summary.progress",
        QStringLiteral("状态：已扫描 %1 / %2 个进程，已发现 %3 条热键。"))
        .arg(m_scannedProcessCount)
        .arg(m_totalProcessCount)
        .arg(m_rows.size()));
    if (m_progressTaskId != 0)
    {
        const float rawProgress = m_totalProcessCount == 0U
            ? 0.0f
            : static_cast<float>(m_scannedProcessCount) / static_cast<float>(m_totalProcessCount);
        // kProgress 在 1.0 时会隐藏任务；最终一批 UI 数据落表前最多只报告 99%。
        const float progress = std::min(rawProgress, 0.99f);
        kPro.set(
            m_progressTaskId,
            allHotkeyText(
                "window.global_hotkey.progress.scanning",
                QStringLiteral("正在扫描 %1（%2/%3）"))
                .arg(currentProcessName)
                .arg(m_scannedProcessCount)
                .arg(m_totalProcessCount)
                .toStdString(),
            static_cast<int>(m_scannedProcessCount),
            progress);
    }
}

void WindowGlobalHotkeyTab::finishRefresh(const std::uint64_t ticket, const qint64 elapsedMs)
{
    if (ticket != m_refreshTicket)
    {
        return;
    }

    m_refreshing = false;
    m_flushTimer->stop();
    m_refreshButton->setEnabled(true);
    // 扫描结束后恢复用户原有排序状态，仅触发这一次全表排序。
    m_table->setSortingEnabled(m_sortingEnabledBeforeRefresh);
    // 扫描期间不反复测量列宽；完成后仅基于有界样本调整一次。
    m_table->resizeColumnsToContents();
    m_statusLabel->setText(allHotkeyText(
        "window.global_hotkey.summary.completed",
        QStringLiteral("状态：已扫描 %1 个进程，发现 %2 条热键，耗时 %3 ms。%4"))
        .arg(m_scannedProcessCount)
        .arg(m_rows.size())
        .arg(elapsedMs)
        .arg(m_diagnosticProcessCount == 0U
            ? QString()
            : allHotkeyText(
                "window.global_hotkey.summary.diagnostics",
                QStringLiteral("%1 个进程的扫描包含诊断信息。")).arg(m_diagnosticProcessCount)));

    const int progressTaskId = m_progressTaskId;
    m_progressTaskId = 0;
    if (progressTaskId != 0)
    {
        kPro.set(
            progressTaskId,
            allHotkeyText(
                "window.global_hotkey.progress.completed",
                QStringLiteral("全部热键扫描完成")).toStdString(),
            100,
            1.0f);
    }
    m_refreshState.reset();
}

void WindowGlobalHotkeyTab::appendVisibleRows(const QVector<QStringList>& rows)
{
    // keyword：沿用当前筛选条件，只把匹配的新行增量插入表格。
    const QString keyword = m_filterEdit->text().trimmed();
    const bool sortingEnabled = m_table->isSortingEnabled();
    m_table->setUpdatesEnabled(false);
    m_table->setSortingEnabled(false);

    for (const QStringList& sourceRow : rows)
    {
        if (sourceRow.size() < ColumnCount ||
            (!keyword.isEmpty() && !sourceRow.join(QLatin1Char(' ')).contains(keyword, Qt::CaseInsensitive)))
        {
            continue;
        }

        const int tableRow = m_table->rowCount();
        m_table->insertRow(tableRow);
        for (int column = 0; column < ColumnCount; ++column)
        {
            m_table->setItem(tableRow, column, readOnlyItem(sourceRow.at(column)));
        }
    }

    m_table->setSortingEnabled(sortingEnabled);
    m_table->setUpdatesEnabled(true);
    m_table->viewport()->update();
}

void WindowGlobalHotkeyTab::rebuildTable()
{
    const QString keyword = m_filterEdit->text().trimmed();
    const bool sortingEnabled = m_table->isSortingEnabled();
    m_table->setUpdatesEnabled(false);
    m_table->setSortingEnabled(false);
    m_table->setRowCount(0);
    for (const QStringList& sourceRow : m_rows)
    {
        if (sourceRow.size() < ColumnCount ||
            (!keyword.isEmpty() && !sourceRow.join(QLatin1Char(' ')).contains(keyword, Qt::CaseInsensitive)))
        {
            continue;
        }

        const int tableRow = m_table->rowCount();
        m_table->insertRow(tableRow);
        for (int column = 0; column < ColumnCount; ++column)
        {
            m_table->setItem(tableRow, column, readOnlyItem(sourceRow.at(column)));
        }
    }
    m_table->setSortingEnabled(sortingEnabled);
    m_table->resizeColumnsToContents();
    m_table->setUpdatesEnabled(true);
    m_table->viewport()->update();
}

QString WindowGlobalHotkeyTab::rowClipboardText(
    QTableWidget* table,
    const int row,
    const bool includeHeader)
{
    if (table == nullptr || row < 0 || row >= table->rowCount())
    {
        return {};
    }

    QStringList lines;
    if (includeHeader)
    {
        QStringList headers;
        for (int column = 0; column < table->columnCount(); ++column)
        {
            headers << (table->horizontalHeaderItem(column) == nullptr
                ? QString()
                : table->horizontalHeaderItem(column)->text());
        }
        lines << headers.join(QLatin1Char('\t'));
    }

    QStringList values;
    for (int column = 0; column < table->columnCount(); ++column)
    {
        values << (table->item(row, column) == nullptr ? QString() : table->item(row, column)->text());
    }
    lines << values.join(QLatin1Char('\t'));
    return lines.join(QLatin1Char('\n'));
}

void WindowGlobalHotkeyTab::showCopyMenu(const QPoint& position)
{
    const QModelIndex index = m_table->indexAt(position);
    const int row = index.isValid() ? index.row() : m_table->currentRow();
    QMenu menu(this);
    QAction* copyCell = menu.addAction(allHotkeyText("window.global_hotkey.copy.cell", QStringLiteral("复制单元格")));
    QAction* copyRow = menu.addAction(allHotkeyText("window.global_hotkey.copy.row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(allHotkeyText("window.global_hotkey.copy.all", QStringLiteral("复制全部行")));
    const QTableWidgetItem* processIdItem = row >= 0 ? m_table->item(row, ColumnPid) : nullptr;
    bool processIdOk = false;
    const quint32 processId = processIdItem != nullptr
        ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
        : 0U;
    QAction* openProcessAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        allHotkeyText("window.global_hotkey.open_process", QStringLiteral("转到进程详细信息")));
    copyCell->setEnabled(index.isValid());
    copyRow->setEnabled(row >= 0);
    copyAll->setEnabled(m_table->rowCount() > 0);
    openProcessAction->setEnabled(processIdOk && processId != 0U);

    QAction* selected = menu.exec(m_table->viewport()->mapToGlobal(position));
    if (selected == copyCell && index.isValid())
    {
        const QTableWidgetItem* item = m_table->item(index.row(), index.column());
        QApplication::clipboard()->setText(item == nullptr ? QString() : item->text());
    }
    else if (selected == copyRow)
    {
        QApplication::clipboard()->setText(rowClipboardText(m_table, row, true));
    }
    else if (selected == copyAll)
    {
        QStringList lines;
        for (int tableRow = 0; tableRow < m_table->rowCount(); ++tableRow)
        {
            lines << rowClipboardText(m_table, tableRow, tableRow == 0);
        }
        QApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
    }
    else if (selected == openProcessAction)
    {
        ks::ui::OpenProcessDetailByPid(processId);
    }
}
