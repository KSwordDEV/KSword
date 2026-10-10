#include "WindowGuiHandleTab.h"
#include "../UI/FlatButtonTheme.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
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
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QVariant>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    constexpr std::uint32_t kMaxUserHandles = 0x10000U;
    constexpr std::uint32_t kMaximumKnownUserType = 21U;

    enum GuiHandleColumn : int
    {
        ColumnHandle = 0,
        ColumnType,
        ColumnTypeId,
        ColumnFlags,
        ColumnUnique,
        ColumnObjectRaw,
        ColumnObjectMapped,
        ColumnOwnerRaw,
        ColumnOwnerMapped,
        ColumnPid,
        ColumnTid,
        ColumnProcess,
        ColumnPath,
        ColumnLayout,
        ColumnStatus,
        ColumnCount
    };

    struct SharedInfoPrefix
    {
        std::uintptr_t serverInfo = 0U;
        std::uintptr_t handleEntries = 0U;
        std::uint32_t handleEntrySize = 0U;
        std::uint32_t reserved = 0U;
        std::uintptr_t displayInfo = 0U;
        std::uintptr_t sharedDelta = 0U;
    };

    struct HandleEntryLayout
    {
        std::size_t typeOffset = 0U;
        std::size_t flagsOffset = 0U;
        std::size_t uniqueOffset = 0U;
        QString name;
    };

    struct GuiHandleSnapshot
    {
        QVector<QStringList> rows;
        QString statusText;
    };

    QString guiHandleText(const char* contextKey, const QString& sourceText)
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

    bool readCurrentProcessMemory(const std::uintptr_t address, void* const destination, const std::size_t bytes)
    {
        if (address == 0U || destination == nullptr || bytes == 0U)
        {
            return false;
        }
        SIZE_T bytesRead = 0U;
        return ReadProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(address),
            destination,
            bytes,
            &bytesRead) != FALSE && bytesRead == bytes;
    }

    bool addressIsReadable(const std::uintptr_t address)
    {
        if (address == 0U)
        {
            return false;
        }
        MEMORY_BASIC_INFORMATION information{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &information, sizeof(information)) != sizeof(information))
        {
            return false;
        }
        const DWORD blockedProtection = PAGE_NOACCESS | PAGE_GUARD;
        return information.State == MEM_COMMIT && (information.Protect & blockedProtection) == 0U;
    }

    template <typename ValueType>
    ValueType readValue(const std::uint8_t* const entryBytes, const std::size_t entrySize, const std::size_t offset)
    {
        ValueType value{};
        if (entryBytes != nullptr && offset <= entrySize && sizeof(value) <= entrySize - offset)
        {
            std::memcpy(&value, entryBytes + offset, sizeof(value));
        }
        return value;
    }

    QString guiObjectTypeText(const std::uint8_t type)
    {
        switch (type)
        {
        case 1U: return QStringLiteral("Window");
        case 2U: return QStringLiteral("Menu");
        case 3U: return QStringLiteral("Cursor/Icon");
        case 4U: return QStringLiteral("SetWindowPos");
        case 5U: return QStringLiteral("Hook");
        case 6U: return QStringLiteral("ClipData");
        case 7U: return QStringLiteral("CallProc");
        case 8U: return QStringLiteral("AccelTable");
        case 9U: return QStringLiteral("DDEAccess");
        case 10U: return QStringLiteral("DDEConv");
        case 11U: return QStringLiteral("DDEExact");
        case 12U: return QStringLiteral("Monitor");
        case 13U: return QStringLiteral("KbdLayout");
        case 14U: return QStringLiteral("KbdFile");
        case 15U: return QStringLiteral("WinEventHook");
        case 16U: return QStringLiteral("Timer");
        case 17U: return QStringLiteral("InputContext");
        case 18U: return QStringLiteral("HidData");
        case 19U: return QStringLiteral("DeviceInfo");
        case 20U: return QStringLiteral("Touch");
        case 21U: return QStringLiteral("Gesture");
        default:
            return guiHandleText("window.gui_handle.type.unknown", QStringLiteral("未知类型 %1")).arg(type);
        }
    }

    BOOL CALLBACK collectWindowHandle(HWND windowHandle, LPARAM contextValue)
    {
        auto* handles = reinterpret_cast<std::vector<std::uint32_t>*>(contextValue);
        if (handles == nullptr)
        {
            return FALSE;
        }
        handles->push_back(static_cast<std::uint32_t>(reinterpret_cast<ULONG_PTR>(windowHandle)));
        return handles->size() < 64U ? TRUE : FALSE;
    }

    std::vector<std::uint32_t> knownWindowHandles()
    {
        std::vector<std::uint32_t> handles;
        handles.reserve(66U);
        const HWND foregroundWindow = GetForegroundWindow();
        const HWND desktopWindow = GetDesktopWindow();
        if (foregroundWindow != nullptr)
        {
            handles.push_back(static_cast<std::uint32_t>(reinterpret_cast<ULONG_PTR>(foregroundWindow)));
        }
        if (desktopWindow != nullptr)
        {
            handles.push_back(static_cast<std::uint32_t>(reinterpret_cast<ULONG_PTR>(desktopWindow)));
        }
        (VOID)EnumWindows(collectWindowHandle, reinterpret_cast<LPARAM>(&handles));
        std::sort(handles.begin(), handles.end());
        handles.erase(std::unique(handles.begin(), handles.end()), handles.end());
        return handles;
    }

    std::uint32_t selectHandleCount(
        const std::array<std::uint32_t, 2U>& candidates,
        const std::vector<std::uint32_t>& windowHandles)
    {
        std::uint32_t largestKnownIndex = 0U;
        for (const std::uint32_t handleValue : windowHandles)
        {
            largestKnownIndex = (std::max)(largestKnownIndex, handleValue & 0xFFFFU);
        }
        std::uint32_t selected = 0U;
        for (const std::uint32_t candidate : candidates)
        {
            if (candidate == 0U || candidate > kMaxUserHandles || candidate <= largestKnownIndex)
            {
                continue;
            }
            // SERVERINFO has used both the first and second DWORD for the
            // handle count across Windows generations. If both look numeric,
            // prefer the smaller safe bound instead of mistaking flags for a
            // larger table length and crossing the shared mapping boundary.
            if (selected == 0U || candidate < selected)
            {
                selected = candidate;
            }
        }
        return selected;
    }

    HandleEntryLayout detectHandleEntryLayout(
        const std::vector<std::uint8_t>& tableBytes,
        const std::uint32_t handleCount,
        const std::uint32_t entrySize,
        const std::vector<std::uint32_t>& windowHandles)
    {
        std::vector<HandleEntryLayout> candidates;
        if (entrySize >= 28U)
        {
            candidates.push_back({ 24U, 25U, 26U, QStringLiteral("Win10+ / 32-byte") });
        }
        if (entrySize >= 20U)
        {
            candidates.push_back({ 16U, 17U, 18U, QStringLiteral("Legacy / pointer") });
        }
        int bestScore = std::numeric_limits<int>::min();
        HandleEntryLayout bestLayout{};
        for (const HandleEntryLayout& candidate : candidates)
        {
            int score = 0;
            for (const std::uint32_t handleValue : windowHandles)
            {
                const std::uint32_t index = handleValue & 0xFFFFU;
                if (index >= handleCount)
                {
                    continue;
                }
                const std::size_t entryOffset = static_cast<std::size_t>(index) * entrySize;
                const std::uint8_t* entry = tableBytes.data() + entryOffset;
                const std::uint8_t type = readValue<std::uint8_t>(entry, entrySize, candidate.typeOffset);
                const std::uint16_t unique = readValue<std::uint16_t>(entry, entrySize, candidate.uniqueOffset);
                if (type == 1U)
                {
                    score += 4;
                }
                if (unique == static_cast<std::uint16_t>((handleValue >> 16U) & 0xFFFFU))
                {
                    score += 5;
                }
                if (readValue<std::uintptr_t>(entry, entrySize, 0U) != 0U)
                {
                    score += 1;
                }
            }
            if (score > bestScore)
            {
                bestScore = score;
                bestLayout = candidate;
            }
        }
        return bestLayout;
    }

    std::uintptr_t mapSharedObjectAddress(const std::uintptr_t rawAddress, const std::uintptr_t sharedDelta)
    {
        if (rawAddress == 0U)
        {
            return 0U;
        }
        if (rawAddress < 0x100000000ULL && sharedDelta >= 0x100000000ULL &&
            rawAddress <= (std::numeric_limits<std::uintptr_t>::max)() - sharedDelta)
        {
            const std::uintptr_t mappedAddress = sharedDelta + rawAddress;
            return addressIsReadable(mappedAddress) ? mappedAddress : 0U;
        }
        if (addressIsReadable(rawAddress))
        {
            return rawAddress;
        }
        if (sharedDelta != 0U && rawAddress > sharedDelta)
        {
            const std::uintptr_t mappedAddress = rawAddress - sharedDelta;
            return addressIsReadable(mappedAddress) ? mappedAddress : 0U;
        }
        return 0U;
    }

    std::pair<QString, QString> queryProcessIdentity(const DWORD processId)
    {
        HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (processHandle == nullptr)
        {
            return {};
        }
        std::wstring pathBuffer(32768U, L'\0');
        DWORD pathChars = static_cast<DWORD>(pathBuffer.size());
        QString pathText;
        if (QueryFullProcessImageNameW(processHandle, 0U, pathBuffer.data(), &pathChars) != FALSE)
        {
            pathBuffer.resize(pathChars);
            pathText = QString::fromStdWString(pathBuffer);
        }
        CloseHandle(processHandle);
        return { QFileInfo(pathText).fileName(), pathText };
    }

    GuiHandleSnapshot collectGuiHandles()
    {
        GuiHandleSnapshot snapshot;
#if !defined(_WIN64)
        snapshot.statusText = guiHandleText(
            "window.gui_handle.status.x64_only",
            QStringLiteral("状态：当前 GUI Handle 枚举仅支持 x64 构建"));
        return snapshot;
#else
        HMODULE user32Module = GetModuleHandleW(L"user32.dll");
        if (user32Module == nullptr)
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.user32_missing",
                QStringLiteral("状态：user32.dll 未加载"));
            return snapshot;
        }
        const FARPROC sharedInfoExport = GetProcAddress(user32Module, "gSharedInfo");
        if (sharedInfoExport == nullptr)
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.export_missing",
                QStringLiteral("状态：当前 user32.dll 未导出 gSharedInfo"));
            return snapshot;
        }
        SharedInfoPrefix sharedInfo{};
        if (!readCurrentProcessMemory(
                reinterpret_cast<std::uintptr_t>(sharedInfoExport),
                &sharedInfo,
                sizeof(sharedInfo)))
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.shared_read_failed",
                QStringLiteral("状态：读取 gSharedInfo 失败"));
            return snapshot;
        }
        if (sharedInfo.serverInfo == 0U || sharedInfo.handleEntries == 0U ||
            sharedInfo.handleEntrySize < 20U || sharedInfo.handleEntrySize > 0x100U)
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.shared_invalid",
                QStringLiteral("状态：gSharedInfo 指针或 HandleEntrySize 无效"));
            return snapshot;
        }
        std::array<std::uint32_t, 2U> serverInfoPrefix{};
        if (!readCurrentProcessMemory(
                sharedInfo.serverInfo,
                serverInfoPrefix.data(),
                sizeof(serverInfoPrefix)))
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.server_read_failed",
                QStringLiteral("状态：读取 SERVERINFO 失败"));
            return snapshot;
        }
        const std::vector<std::uint32_t> windowHandles = knownWindowHandles();
        const std::uint32_t handleCount = selectHandleCount(serverInfoPrefix, windowHandles);
        if (handleCount == 0U)
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.count_invalid",
                QStringLiteral("状态：SERVERINFO Handle 数量无效"));
            return snapshot;
        }
        const std::size_t totalBytes = static_cast<std::size_t>(handleCount) * sharedInfo.handleEntrySize;
        std::vector<std::uint8_t> handleTable(totalBytes, 0U);
        std::uint32_t readableEntryCount = 0U;
        for (std::uint32_t index = 0U; index < handleCount; ++index)
        {
            const std::size_t entryOffset = static_cast<std::size_t>(index) * sharedInfo.handleEntrySize;
            if (entryOffset > (std::numeric_limits<std::uintptr_t>::max)() - sharedInfo.handleEntries)
            {
                break;
            }
            if (readCurrentProcessMemory(
                    sharedInfo.handleEntries + entryOffset,
                    handleTable.data() + entryOffset,
                    sharedInfo.handleEntrySize))
            {
                ++readableEntryCount;
            }
        }
        if (readableEntryCount == 0U)
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.table_read_failed",
                QStringLiteral("状态：读取 USER Handle 共享表失败"));
            return snapshot;
        }
        const HandleEntryLayout layout = detectHandleEntryLayout(
            handleTable,
            handleCount,
            sharedInfo.handleEntrySize,
            windowHandles);
        if (layout.name.isEmpty())
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.layout_failed",
                QStringLiteral("状态：无法识别 USER HandleEntry 布局"));
            return snapshot;
        }

        std::unordered_map<DWORD, std::pair<QString, QString>> processCache;
        snapshot.rows.reserve(static_cast<qsizetype>(handleCount));
        std::uint32_t visibleCount = 0U;
        for (std::uint32_t index = 0U; index < handleCount; ++index)
        {
            const std::size_t entryOffset = static_cast<std::size_t>(index) * sharedInfo.handleEntrySize;
            const std::uint8_t* entry = handleTable.data() + entryOffset;
            const std::uintptr_t rawObject = readValue<std::uintptr_t>(entry, sharedInfo.handleEntrySize, 0U);
            const std::uintptr_t rawOwner = readValue<std::uintptr_t>(entry, sharedInfo.handleEntrySize, sizeof(std::uintptr_t));
            const std::uint8_t type = readValue<std::uint8_t>(entry, sharedInfo.handleEntrySize, layout.typeOffset);
            const std::uint8_t flags = readValue<std::uint8_t>(entry, sharedInfo.handleEntrySize, layout.flagsOffset);
            const std::uint16_t unique = readValue<std::uint16_t>(entry, sharedInfo.handleEntrySize, layout.uniqueOffset);
            if (type == 0U && rawObject == 0U)
            {
                continue;
            }
            const std::uint32_t handleValue = (static_cast<std::uint32_t>(unique) << 16U) | index;
            const std::uintptr_t mappedObject = mapSharedObjectAddress(rawObject, sharedInfo.sharedDelta);
            const std::uintptr_t mappedOwner = mapSharedObjectAddress(rawOwner, sharedInfo.sharedDelta);
            DWORD processId = 0U;
            DWORD threadId = 0U;
            QString processName;
            QString processPath;
            QString rowStatus = guiHandleText(
                "window.gui_handle.status.shared_entry",
                QStringLiteral("共享 USER Handle"));
            if (type == 1U)
            {
                const HWND windowHandle = reinterpret_cast<HWND>(static_cast<ULONG_PTR>(handleValue));
                if (IsWindow(windowHandle) != FALSE)
                {
                    threadId = GetWindowThreadProcessId(windowHandle, &processId);
                    auto cacheIterator = processCache.find(processId);
                    if (cacheIterator == processCache.end())
                    {
                        cacheIterator = processCache.emplace(processId, queryProcessIdentity(processId)).first;
                    }
                    processName = cacheIterator->second.first;
                    processPath = cacheIterator->second.second;
                    rowStatus = guiHandleText(
                        "window.gui_handle.status.hwnd_verified",
                        QStringLiteral("HWND 已验证"));
                }
            }
            if (type > kMaximumKnownUserType)
            {
                rowStatus = guiHandleText(
                    "window.gui_handle.status.unknown_type",
                    QStringLiteral("未知 USER 类型"));
            }
            if (rawObject != 0U && mappedObject == 0U)
            {
                rowStatus += guiHandleText(
                    "window.gui_handle.status.raw_only",
                    QStringLiteral("；对象仅有原始值"));
            }
            snapshot.rows.push_back(QStringList{
                hex32(handleValue),
                guiObjectTypeText(type),
                QString::number(type),
                QStringLiteral("0x%1").arg(flags, 2, 16, QLatin1Char('0')).toUpper(),
                QStringLiteral("0x%1").arg(unique, 4, 16, QLatin1Char('0')).toUpper(),
                hex64(rawObject),
                hex64(mappedObject),
                hex64(rawOwner),
                hex64(mappedOwner),
                processId == 0U ? QString() : QString::number(processId),
                threadId == 0U ? QString() : QString::number(threadId),
                processName,
                processPath,
                layout.name,
                rowStatus });
            ++visibleCount;
        }
        snapshot.statusText = guiHandleText(
            "window.gui_handle.status.completed",
            QStringLiteral("状态：USER Handle %1，非空对象 %2，EntrySize %3，布局 %4，gSharedInfo %5，aheList %6"))
            .arg(handleCount)
            .arg(visibleCount)
            .arg(sharedInfo.handleEntrySize)
            .arg(layout.name)
            .arg(hex64(reinterpret_cast<std::uintptr_t>(sharedInfoExport)))
            .arg(hex64(sharedInfo.handleEntries));
        return snapshot;
#endif
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

WindowGuiHandleTab::WindowGuiHandleTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void WindowGuiHandleTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!m_firstRefreshStarted)
    {
        m_firstRefreshStarted = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void WindowGuiHandleTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        guiHandleText("window.gui_handle.refresh", QStringLiteral("刷新 GUI 句柄")),
        this);
    m_typeFilterCombo = new QComboBox(this);
    // 类型筛选与旁边搜索框保持同一控件层次，选项及过滤信号不变。
    ks::ui::StylePrimaryCombo(m_typeFilterCombo);
    m_typeFilterCombo->addItem(guiHandleText("window.gui_handle.filter.all", QStringLiteral("全部类型")), -1);
    m_typeFilterCombo->addItem(QStringLiteral("Window"), 1);
    m_typeFilterCombo->addItem(QStringLiteral("Menu"), 2);
    m_typeFilterCombo->addItem(QStringLiteral("Cursor/Icon"), 3);
    m_typeFilterCombo->addItem(QStringLiteral("Hook"), 5);
    m_typeFilterCombo->addItem(QStringLiteral("WinEventHook"), 15);
    m_typeFilterCombo->addItem(QStringLiteral("Timer"), 16);
    m_typeFilterCombo->addItem(QStringLiteral("InputContext"), 17);
    m_filterEdit = new QLineEdit(this);
    ks::ui::StyleSearchField(m_filterEdit);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setPlaceholderText(guiHandleText(
        "window.gui_handle.filter.placeholder",
        QStringLiteral("按句柄、类型、对象、PID/TID、进程和路径筛选")));
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_typeFilterCombo);
    toolbar->addWidget(m_filterEdit, 1);
    toolbar->setSpacing(8);
    ks::ui::NormalizeToolbarRow(toolbar);
    rootLayout->addLayout(toolbar);

    m_statusLabel = new QLabel(
        guiHandleText("window.gui_handle.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(m_statusLabel);

    m_table = new ks::ui::VisibleTableWidget(this);
    // USER 句柄主清单保留快照比较，避免隐藏现场变化能力。
    ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::Full);
    m_table->setColumnCount(ColumnCount);
    m_table->setHorizontalHeaderLabels({
        guiHandleText("window.gui_handle.header.handle", QStringLiteral("句柄")),
        guiHandleText("window.gui_handle.header.type", QStringLiteral("类型")),
        QStringLiteral("TypeId"),
        QStringLiteral("Flags"),
        QStringLiteral("Uniq"),
        guiHandleText("window.gui_handle.header.object_raw", QStringLiteral("对象原始值")),
        guiHandleText("window.gui_handle.header.object_mapped", QStringLiteral("对象共享映射")),
        guiHandleText("window.gui_handle.header.owner_raw", QStringLiteral("所有者原始值")),
        guiHandleText("window.gui_handle.header.owner_mapped", QStringLiteral("所有者共享映射")),
        QStringLiteral("PID"),
        QStringLiteral("TID"),
        guiHandleText("window.gui_handle.header.process", QStringLiteral("进程")),
        guiHandleText("window.gui_handle.header.path", QStringLiteral("路径")),
        guiHandleText("window.gui_handle.header.layout", QStringLiteral("布局")),
        guiHandleText("window.gui_handle.header.status", QStringLiteral("状态")) });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(true);
    rootLayout->addWidget(m_table, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(m_typeFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { rebuildTable(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString&) { rebuildTable(); });
    connect(m_table, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) { showCopyMenu(position); });
}

void WindowGuiHandleTab::refreshAsync()
{
    if (m_refreshing)
    {
        return;
    }
    m_refreshing = true;
    m_firstRefreshStarted = true;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(guiHandleText(
        "window.gui_handle.status.refreshing",
        QStringLiteral("状态：正在读取 gSharedInfo 与 USER Handle 共享表...")));
    QPointer<WindowGuiHandleTab> safeThis(this);
    std::thread([safeThis]() {
        GuiHandleSnapshot snapshot = collectGuiHandles();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(safeThis, [safeThis, snapshot = std::move(snapshot)]() mutable {
            if (safeThis != nullptr)
            {
                safeThis->applySnapshot(std::move(snapshot.rows), snapshot.statusText);
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void WindowGuiHandleTab::applySnapshot(QVector<QStringList> rows, const QString& statusText)
{
    const QPointer<WindowGuiHandleTab> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("window-gui-handle-snapshot-apply"),
        { m_table },
        [safeThis, rows, statusText]() mutable
        {
            if (!safeThis.isNull())
            {
                safeThis->applySnapshot(std::move(rows), statusText);
            }
        }))
    {
        return;
    }

    m_refreshing = false;
    m_refreshButton->setEnabled(true);
    m_rows = std::move(rows);
    m_statusLabel->setText(statusText);
    rebuildTable();
}

void WindowGuiHandleTab::rebuildTable()
{
    const int selectedType = m_typeFilterCombo->currentData().toInt();
    const QString keyword = m_filterEdit->text().trimmed();
    m_table->setSortingEnabled(false);
    m_table->setRowCount(0);
    for (const QStringList& sourceRow : m_rows)
    {
        if (sourceRow.size() < ColumnCount)
        {
            continue;
        }
        if (selectedType >= 0 && sourceRow.at(ColumnTypeId).toInt() != selectedType)
        {
            continue;
        }
        if (!keyword.isEmpty() && !sourceRow.join(QLatin1Char(' ')).contains(keyword, Qt::CaseInsensitive))
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
    m_table->setSortingEnabled(true);
    m_table->resizeColumnsToContents();
}

QString WindowGuiHandleTab::rowClipboardText(QTableWidget* table, const int row, const bool includeHeader)
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
            headers << (table->horizontalHeaderItem(column) == nullptr ? QString() : table->horizontalHeaderItem(column)->text());
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

void WindowGuiHandleTab::showCopyMenu(const QPoint& position)
{
    const QModelIndex index = m_table->indexAt(position);
    const int row = index.isValid() ? index.row() : m_table->currentRow();
    QMenu menu(this);
    QAction* copyCell = menu.addAction(guiHandleText("window.gui_handle.copy.cell", QStringLiteral("复制单元格")));
    QAction* copyRow = menu.addAction(guiHandleText("window.gui_handle.copy.row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(guiHandleText("window.gui_handle.copy.all", QStringLiteral("复制全部行")));
    const QTableWidgetItem* processIdItem = row >= 0 ? m_table->item(row, ColumnPid) : nullptr;
    bool processIdOk = false;
    const quint32 processId = processIdItem != nullptr
        ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
        : 0U;
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
