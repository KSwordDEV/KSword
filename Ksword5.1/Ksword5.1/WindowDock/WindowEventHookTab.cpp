#include "WindowEventHookTab.h"
#include "WindowSnapshotSupport.h"
#include "../UI/TableCompleteExport.h"
#include "WindowImmutableTableSupport.h"
#include "WindowFailureLog.h"
#include "../UI/AsyncOperation.h"
#include "../UI/TableContextMenu.h"
#include "../UI/FlatButtonTheme.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QVBoxLayout>

#include <cstdint>
#include <iterator>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>

namespace
{
    enum EventHookColumn : int
    {
        ColumnHandle = 0,
        ColumnObject,
        ColumnEventMin,
        ColumnEventMax,
        ColumnFlags,
        ColumnCallback,
        ColumnModule,
        ColumnPid,
        ColumnTid,
        ColumnPath,
        ColumnTarget,
        ColumnModuleAtom,
        ColumnCallbackOffset,
        ColumnThreadInfo,
        ColumnNext,
        ColumnStatus,
        ColumnCount
    };

    struct ModuleRange
    {
        std::uint64_t baseAddress = 0;
        std::uint64_t size = 0;
        QString moduleName;
        QString modulePath;
    };

    struct ProcessMetadata
    {
        QString imagePath;
        std::vector<ModuleRange> modules;
    };

    struct EventHookSnapshot
    {
        QVector<QStringList> rows;
        QString statusText;
        ks::ui::ImmutableTableSource tableValues;
    };

    QString eventHookText(const char* contextKey, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(contextKey), sourceText);
    }

    QString hex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0')).toUpper();
    }

    QString hex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0')).toUpper();
    }

    QString layoutSourceText(const std::uint32_t source, const ks::window::SnapshotTexts& texts)
    {
        switch (source)
        {
        case KSWORD_ARK_WIN32K_EVENT_HOOK_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY:
            return texts.value(QStringLiteral("window.event_hook.layout.exact"), QStringLiteral("精确 PE 身份"));
        case KSWORD_ARK_WIN32K_EVENT_HOOK_LAYOUT_SOURCE_NEAREST_PREVIOUS:
            return texts.value(QStringLiteral("window.event_hook.layout.previous"), QStringLiteral("最近旧版回退"));
        default:
            return texts.value(QStringLiteral("window.event_hook.layout.unknown"), QStringLiteral("未知"));
        }
    }

    QString handleText(const std::uint64_t value)
    {
        return value <= 0xFFFFFFFFULL ? hex32(static_cast<std::uint32_t>(value)) : hex64(value);
    }

    ProcessMetadata queryProcessMetadata(const DWORD processId)
    {
        ProcessMetadata metadata;
        if (processId == 0U)
        {
            return metadata;
        }

        const HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (processHandle != nullptr)
        {
            std::wstring pathBuffer(32768U, L'\0');
            DWORD pathChars = static_cast<DWORD>(pathBuffer.size());
            if (::QueryFullProcessImageNameW(processHandle, 0U, pathBuffer.data(), &pathChars) != FALSE)
            {
                pathBuffer.resize(pathChars);
                metadata.imagePath = QString::fromStdWString(pathBuffer);
            }
            ::CloseHandle(processHandle);
        }

        const HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            processId);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return metadata;
        }
        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        if (::Module32FirstW(snapshotHandle, &moduleEntry) != FALSE)
        {
            do
            {
                ModuleRange range;
                range.baseAddress = static_cast<std::uint64_t>(
                    reinterpret_cast<std::uintptr_t>(moduleEntry.modBaseAddr));
                range.size = moduleEntry.modBaseSize;
                range.moduleName = QString::fromWCharArray(moduleEntry.szModule);
                range.modulePath = QString::fromWCharArray(moduleEntry.szExePath);
                metadata.modules.push_back(std::move(range));
                moduleEntry.dwSize = sizeof(moduleEntry);
            } while (::Module32NextW(snapshotHandle, &moduleEntry) != FALSE);
        }
        ::CloseHandle(snapshotHandle);
        return metadata;
    }

    const ModuleRange* findModuleForAddress(
        const ProcessMetadata& metadata,
        const std::uint64_t address)
    {
        for (const ModuleRange& module : metadata.modules)
        {
            if (module.baseAddress <= address && address - module.baseAddress < module.size)
            {
                return &module;
            }
        }
        return nullptr;
    }

    const ModuleRange* findModuleByName(
        const ProcessMetadata& metadata,
        const QString& atomName)
    {
        const QString fileName = QFileInfo(atomName).fileName();
        for (const ModuleRange& module : metadata.modules)
        {
            if (module.moduleName.compare(fileName, Qt::CaseInsensitive) == 0 ||
                QFileInfo(module.modulePath).fileName().compare(fileName, Qt::CaseInsensitive) == 0)
            {
                return &module;
            }
        }
        return nullptr;
    }

    QString globalAtomName(const std::uint32_t atomValue)
    {
        if (atomValue == 0U || atomValue > 0xFFFFU)
        {
            return {};
        }
        wchar_t buffer[512]{};
        const UINT chars = ::GlobalGetAtomNameW(
            static_cast<ATOM>(atomValue),
            buffer,
            static_cast<int>(std::size(buffer)));
        return chars == 0U ? QString() : QString::fromWCharArray(buffer, static_cast<qsizetype>(chars));
    }

    QString flagsText(const std::uint32_t flags)
    {
        QStringList names;
        names << ((flags & KSWORD_ARK_WIN32K_EVENT_HOOK_FLAG_IN_CONTEXT) != 0U
            ? QStringLiteral("INCONTEXT")
            : QStringLiteral("OUTOFCONTEXT"));
        if ((flags & KSWORD_ARK_WIN32K_EVENT_HOOK_FLAG_SKIP_OWN_THREAD) != 0U)
        {
            names << QStringLiteral("SKIPOWNTHREAD");
        }
        if ((flags & KSWORD_ARK_WIN32K_EVENT_HOOK_FLAG_SKIP_OWN_PROCESS) != 0U)
        {
            names << QStringLiteral("SKIPOWNPROCESS");
        }
        const std::uint32_t unknown = flags & ~0x7U;
        if (unknown != 0U)
        {
            names << hex32(unknown);
        }
        return names.join(QStringLiteral(" | "));
    }

    QString statusName(const std::uint32_t status, const ks::window::SnapshotTexts& texts)
    {
        switch (status)
        {
        case KSWORD_ARK_WIN32K_STATUS_OK:
            return texts.value(QStringLiteral("window.event_hook.row.ok"), QStringLiteral("完整"));
        case KSWORD_ARK_WIN32K_STATUS_PARTIAL:
            return texts.value(QStringLiteral("window.event_hook.row.partial"), QStringLiteral("部分"));
        default:
            return texts.value(QStringLiteral("window.event_hook.row.status_code"), QStringLiteral("状态 %1")).arg(status);
        }
    }

    // 工作线程传入冻结文本与本轮日志 trace，返回 Event Hook 快照并记录查询失败。
    EventHookSnapshot collectEventHooks(const ks::window::SnapshotTexts& texts, kLogEvent& trace)
    {
        EventHookSnapshot snapshot;
        const ksword::ark::Win32kEventHooksResult result =
            ksword::ark::DriverClient().queryWin32kEventHooks();
        if (!result.io.ok)
        {
            snapshot.statusText = texts.value(QStringLiteral("window.event_hook.status.io_failed"), QStringLiteral("状态：事件 Hook 查询失败，Win32=%1，%2"))
                .arg(result.io.win32Error)
                .arg(QString::fromStdString(result.io.message));
            ks::window::LogWindowFailure(trace, "EVENT_HOOK", "IOCTL", QStringList{
                QString::number(result.io.win32Error), QString::fromStdString(result.io.message)}.join(QLatin1Char('|')));
            return snapshot;
        }

        const QString detailText = QString::fromStdWString(result.detail);
        if (result.status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED || result.unsupported)
        {
            snapshot.statusText = texts.value(QStringLiteral("window.event_hook.status.unsupported"), QStringLiteral("状态：当前 win32k 版本没有精确或可用的最近旧版 tagEVENTHOOK 布局；base=%1/%2，full=%3/%4。%5"))
                .arg(hex32(result.win32kbaseTimeDateStamp))
                .arg(hex32(result.win32kbaseImageSize))
                .arg(hex32(result.win32kfullTimeDateStamp))
                .arg(hex32(result.win32kfullImageSize))
                .arg(detailText);
            ks::window::LogWindowFailure(trace, "EVENT_HOOK", "LAYOUT_UNSUPPORTED", detailText);
            return snapshot;
        }
        if (result.status == KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND)
        {
            snapshot.statusText = texts.value(QStringLiteral("window.event_hook.status.win32k_missing"), QStringLiteral("状态：未定位 win32kbase/win32kfull，无法读取事件 Hook。%1"))
                .arg(detailText);
            ks::window::LogWindowFailure(trace, "EVENT_HOOK", "WIN32K_NOT_FOUND", detailText);
            return snapshot;
        }

        std::unordered_map<DWORD, ProcessMetadata> processCache;
        snapshot.rows.reserve(static_cast<qsizetype>(result.entries.size()));
        for (const KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY& entry : result.entries)
        {
            auto processIterator = processCache.find(entry.processId);
            if (processIterator == processCache.end())
            {
                processIterator = processCache.emplace(
                    entry.processId,
                    queryProcessMetadata(entry.processId)).first;
            }
            const ProcessMetadata& metadata = processIterator->second;
            const QString atomName = globalAtomName(entry.moduleAtom);
            std::uint64_t callbackAddress = entry.callbackAddress;
            const ModuleRange* module = nullptr;
            if ((entry.flags & KSWORD_ARK_WIN32K_EVENT_HOOK_FLAG_IN_CONTEXT) != 0U)
            {
                module = findModuleByName(metadata, atomName);
                if (module != nullptr && entry.callbackOffset < module->size)
                {
                    callbackAddress = module->baseAddress + entry.callbackOffset;
                }
            }
            else
            {
                module = findModuleForAddress(metadata, callbackAddress);
            }

            const QString moduleName = module != nullptr
                ? module->moduleName
                : atomName;
            const QString targetText = QStringLiteral("%1 / %2")
                .arg(entry.targetProcessId == 0U ? QStringLiteral("*") : QString::number(entry.targetProcessId))
                .arg(entry.targetThreadId == 0U ? QStringLiteral("*") : QString::number(entry.targetThreadId));
            snapshot.rows.push_back(QStringList{
                handleText(entry.hookHandle),
                hex64(entry.hookObject),
                hex32(entry.eventMin),
                hex32(entry.eventMax),
                flagsText(entry.flags),
                hex64(callbackAddress),
                moduleName,
                entry.processId == 0U ? QString() : QString::number(entry.processId),
                entry.threadId == 0U ? QString() : QString::number(entry.threadId),
                metadata.imagePath,
                targetText,
                entry.moduleAtom == 0U ? QString() : QStringLiteral("%1 (%2)").arg(hex32(entry.moduleAtom), atomName),
                hex64(entry.callbackOffset),
                hex64(entry.ownerThreadInfo),
                hex64(entry.nextHookObject),
                QStringLiteral("%1 | %2").arg(statusName(entry.status, texts), QString::fromWCharArray(entry.detail)) });
        }

        snapshot.statusText = texts.value(QStringLiteral("window.event_hook.status.completed"), QStringLiteral("状态：Event Hook %1/%2，访问节点 %3，读取失败 %4，损坏链 %5，重复 %6；gpWinEventHooks=%7 -> %8，tagEVENTHOOK=0x%9，布局来源=%10。%11"))
            .arg(result.returnedCount)
            .arg(result.totalCount)
            .arg(result.visitedNodeCount)
            .arg(result.readFailureCount)
            .arg(result.corruptLinkCount)
            .arg(result.duplicateCount)
            .arg(hex64(result.hookListPointer))
            .arg(hex64(result.hookListHead))
            .arg(result.layout.objectSize, 0, 16)
            .arg(layoutSourceText(result.layout.source, texts))
            .arg(detailText);
        if (result.status != KSWORD_ARK_WIN32K_STATUS_OK || result.readFailureCount != 0U ||
            result.corruptLinkCount != 0U || result.duplicateCount != 0U)
        {
            ks::window::LogWindowFailure(trace, "EVENT_HOOK", "PARTIAL", QStringList{
                QString::number(result.status), QString::number(result.returnedCount),
                QString::number(result.totalCount), QString::number(result.visitedNodeCount),
                QString::number(result.readFailureCount), QString::number(result.corruptLinkCount),
                QString::number(result.duplicateCount), detailText}.join(QLatin1Char('|')));
        }
        return snapshot;
    }

    ks::window::SnapshotTexts freezeSnapshotTexts()
    {
        return {
            {QStringLiteral("window.event_hook.layout.exact"), eventHookText("window.event_hook.layout.exact", QStringLiteral("精确 PE 身份"))},
            {QStringLiteral("window.event_hook.layout.previous"), eventHookText("window.event_hook.layout.previous", QStringLiteral("最近旧版回退"))},
            {QStringLiteral("window.event_hook.layout.unknown"), eventHookText("window.event_hook.layout.unknown", QStringLiteral("未知"))},
            {QStringLiteral("window.event_hook.row.ok"), eventHookText("window.event_hook.row.ok", QStringLiteral("完整"))},
            {QStringLiteral("window.event_hook.row.partial"), eventHookText("window.event_hook.row.partial", QStringLiteral("部分"))},
            {QStringLiteral("window.event_hook.row.status_code"), eventHookText("window.event_hook.row.status_code", QStringLiteral("状态 %1"))},
            {QStringLiteral("window.event_hook.status.io_failed"), eventHookText("window.event_hook.status.io_failed", QStringLiteral("状态：事件 Hook 查询失败，Win32=%1，%2"))},
            {QStringLiteral("window.event_hook.status.unsupported"), eventHookText("window.event_hook.status.unsupported", QStringLiteral("状态：当前 win32k 版本没有精确或可用的最近旧版 tagEVENTHOOK 布局；base=%1/%2，full=%3/%4。%5"))},
            {QStringLiteral("window.event_hook.status.win32k_missing"), eventHookText("window.event_hook.status.win32k_missing", QStringLiteral("状态：未定位 win32kbase/win32kfull，无法读取事件 Hook。%1"))},
            {QStringLiteral("window.event_hook.status.completed"), eventHookText("window.event_hook.status.completed", QStringLiteral("状态：Event Hook %1/%2，访问节点 %3，读取失败 %4，损坏链 %5，重复 %6；gpWinEventHooks=%7 -> %8，tagEVENTHOOK=0x%9，布局来源=%10。%11"))} };
    }


}

WindowEventHookTab::WindowEventHookTab(QWidget* parent)
    : QWidget(parent)
{
    m_refreshOperation = new ks::ui::AsyncOperation(this);
    initializeUi();
    m_refreshOperation->setStateChangedCallback([this] { reconcileRefreshState(); });
}

WindowEventHookTab::~WindowEventHookTab()
{
    m_refreshOperation->close();
    ks::window::retireSnapshotValues(std::move(m_rows));
}

void WindowEventHookTab::showEvent(QShowEvent* event)
{
    const QPointer<WindowEventHookTab> alive(this);
    QWidget::showEvent(event);
    if (!alive) return;
    reconcileRefreshState();
    if (!alive) return;
    if (!m_firstRefreshStarted)
    {
        m_firstRefreshStarted = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void WindowEventHookTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        eventHookText("window.event_hook.refresh", QStringLiteral("刷新事件 Hook")),
        this);
    m_filterEdit = new QLineEdit(this);
    ks::ui::StyleSearchField(m_filterEdit);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setPlaceholderText(eventHookText(
        "window.event_hook.filter.placeholder",
        QStringLiteral("按句柄、事件范围、Flags、回调、模块、PID/TID 或路径筛选")));
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_filterEdit, 1);
    toolbar->setSpacing(8);
    ks::ui::NormalizeToolbarRow(toolbar);
    rootLayout->addLayout(toolbar);

    m_statusLabel = new QLabel(
        eventHookText("window.event_hook.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(m_statusLabel);

    m_table = new ks::ui::ImmutableValueTable(this, {
        {QStringLiteral("window.event_hook.header.handle"), QStringLiteral("句柄")},
        {QStringLiteral("window.event_hook.header.object"), QStringLiteral("Hook 对象")},
        {QStringLiteral("window.event_hook.header.event_min"), QStringLiteral("EventMin")},
        {QStringLiteral("window.event_hook.header.event_max"), QStringLiteral("EventMax")},
        {QStringLiteral("window.event_hook.header.flags"), QStringLiteral("Flag")},
        {QStringLiteral("window.event_hook.header.callback"), QStringLiteral("函数地址")},
        {QStringLiteral("window.event_hook.header.module"), QStringLiteral("模块名")},
        {QStringLiteral("window.event_hook.header.pid"), QStringLiteral("PID")},
        {QStringLiteral("window.event_hook.header.tid"), QStringLiteral("TID")},
        {QStringLiteral("window.event_hook.header.path"), QStringLiteral("进程路径")},
        {QStringLiteral("window.event_hook.header.target"), QStringLiteral("目标 PID / TID")},
        {QStringLiteral("window.event_hook.header.module_atom"), QStringLiteral("模块 Atom")},
        {QStringLiteral("window.event_hook.header.callback_offset"), QStringLiteral("回调偏移")},
        {QStringLiteral("window.event_hook.header.thread_info"), QStringLiteral("ThreadInfo")},
        {QStringLiteral("window.event_hook.header.next"), QStringLiteral("下一个 Hook")},
        {QStringLiteral("window.event_hook.header.status"), QStringLiteral("状态")} });
    ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::Full);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(true);
    // Measure a bounded visible-source sample only when canonical data changes, never per key.
    m_table->horizontalHeader()->setResizeContentsPrecision(100);
    m_table->sourceReady = [this] { m_table->resizeColumnsToContents(); };
    rootLayout->addWidget(m_table, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString&) { rebuildTable(); });
    connect(m_table, &QTableView::customContextMenuRequested, this, [this](const QPoint& position) { showCopyMenu(position); });
}

void WindowEventHookTab::reconcileRefreshState()
{
    if (!m_refreshing || m_refreshOperation->isBusy() || m_refreshOperation->isInFlight()) return;
    const QPointer<WindowEventHookTab> alive(this);
    m_refreshing = false;
    m_refreshButton->setEnabled(true);
    if (alive && !m_refreshOperation->isBusy() && !m_refreshOperation->isInFlight())
    {
        kLogEvent trace; // 丢弃的 worker 投递已无活动 trace 可复用。
        ks::window::LogWindowFailure(trace, "EVENT_HOOK", "ASYNC_STATE", QString::number(m_refreshOperation->generation()));
        m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral("后台任务发生异常。")));
    }
}

void WindowEventHookTab::refreshAsync()
{
    const QPointer<WindowEventHookTab> refreshOwner(this);
    reconcileRefreshState();
    if (!refreshOwner) return;
    if (m_refreshing)
    {
        return;
    }
    const QPointer<WindowEventHookTab> alive(this);
    m_refreshing = true;
    m_firstRefreshStarted = true;
    m_refreshButton->setEnabled(false);
    if (!alive) return;
    m_statusLabel->setText(eventHookText(
        "window.event_hook.status.refreshing",
        QStringLiteral("状态：正在通过 R0 读取 gpWinEventHooks...")));
    if (!alive) return;
    const auto trace = std::make_shared<kLogEvent>(); // 本轮采集与异常回调共享事件 GUID。
    m_refreshOperation->submit<ks::window::SnapshotTexts, std::shared_ptr<const EventHookSnapshot>>(
        freezeSnapshotTexts(),
        [trace](const ks::window::SnapshotTexts& texts, const ks::ui::AsyncOperationToken&) {
            auto snapshot = collectEventHooks(texts, *trace);
            snapshot.tableValues = ks::window::makeWindowTableSource(std::move(snapshot.rows), {ColumnHandle, ColumnObject, ColumnPid, ColumnTid});
            return ks::window::makeSnapshotValue<EventHookSnapshot>(std::move(snapshot));
        },
        [this](const std::shared_ptr<const EventHookSnapshot>& snapshot, std::uint64_t ticket) {
            return applySnapshot(snapshot->tableValues, snapshot->statusText, ticket);
        },
        [this, trace](std::exception_ptr failure) {
            const QPointer<WindowEventHookTab> alive(this);
            const auto failedGeneration = m_refreshOperation->generation();
            m_refreshing = false;
            m_refreshButton->setEnabled(true);
            if (alive && m_refreshOperation->isCurrent(failedGeneration))
            {
                ks::window::LogWindowException(*trace, "EVENT_HOOK", failure);
                m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral("后台任务发生异常。")));
            }
        });
}

bool WindowEventHookTab::applySnapshot(ks::ui::ImmutableTableSource rows, const QString& statusText, std::uint64_t ticket)
{
    if (!m_refreshOperation->isCurrent(ticket)) return true;
    const QPointer<WindowEventHookTab> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("window-event-hook-snapshot-apply"),
        { m_table },
        [safeThis, rows, statusText, ticket]() mutable
        {
            if (!safeThis || !safeThis->m_refreshOperation->isCurrent(ticket)) return;
            if (safeThis->applySnapshot(std::move(rows), statusText, ticket) && safeThis)
                safeThis->m_refreshOperation->completeDeferred(ticket);
        }))
    {
        return false;
    }
    if (!safeThis || !safeThis->m_refreshOperation->isCurrent(ticket)) return true;

    m_refreshing = false;
    m_refreshButton->setEnabled(true);
    if (!safeThis || !safeThis->m_refreshOperation->isCurrent(ticket)) return true;
    ks::window::retireSnapshotValues(std::move(m_rows));
    m_rows = std::move(rows);
    m_statusLabel->setText(statusText);
    if (!safeThis || !safeThis->m_refreshOperation->isCurrent(ticket)) return true;
    const auto source = m_rows;
    m_table->setSourceFactory([source](const auto& translator) { return ks::window::formatWindowTableSource(source, translator); });
    if (!safeThis) return true;
    rebuildTable();
    return true;
}

void WindowEventHookTab::rebuildTable()
{
    m_table->setQuery(m_filterEdit->text().trimmed());
}

QString WindowEventHookTab::rowClipboardText(ks::ui::ImmutableValueTable* table, const int row, const bool includeHeader)
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
            headers << table->model()->headerData(column, Qt::Horizontal, Qt::DisplayRole).toString();
        }
        lines << headers.join(QLatin1Char('\t'));
    }
    QStringList values;
    for (int column = 0; column < table->columnCount(); ++column)
    {
        values << table->cell(row, column).toString();
    }
    lines << values.join(QLatin1Char('\t'));
    return lines.join(QLatin1Char('\n'));
}

void WindowEventHookTab::showCopyMenu(const QPoint& position)
{
    const QModelIndex index = m_table->indexAt(position);
    const int row = index.isValid() ? index.row() : m_table->currentRow();
    QMenu menu(this);
    QAction* copyCell = menu.addAction(eventHookText("window.event_hook.copy.cell", QStringLiteral("复制单元格")));
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copyCell, ks::ui::TableContextActionRole::CopyCell);
    QAction* copyRow = menu.addAction(eventHookText("window.event_hook.copy.row", QStringLiteral("复制当前行")));
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copyRow, ks::ui::TableContextActionRole::CopyRows);
    QAction* copyAll = menu.addAction(eventHookText("window.event_hook.copy.all", QStringLiteral("复制全部行")));
    bool processIdOk = false;
    const quint32 processId = row >= 0 ? m_table->cell(row, ColumnPid).toString().trimmed().toUInt(&processIdOk, 10) : 0U;
    QAction* openProcessAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("转到进程详细信息"));
    copyCell->setEnabled(index.isValid());
    copyRow->setEnabled(row >= 0);
    copyAll->setEnabled(m_table->rowCount() > 0);
    openProcessAction->setEnabled(processIdOk && processId != 0U);
    QAction* selected = menu.exec(m_table->viewport()->mapToGlobal(position));
    if (selected == copyCell && index.isValid())
    {
        QApplication::clipboard()->setText(m_table->cell(index.row(), index.column()).toString());
    }
    else if (selected == copyRow)
    {
        QApplication::clipboard()->setText(rowClipboardText(m_table, row, true));
    }
    else if (selected == copyAll)
    {
        ks::ui::CopyCompleteTableRows(m_table, ks::ui::CompleteTableScope::All, ks::ui::CompleteTableColumns::All);
    }
    else if (selected == openProcessAction)
    {
        ks::ui::OpenProcessDetailByPid(processId);
    }
}
