#include "NetworkDock.InternalCommon.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/VisibleTableWidget.h"

#include <QCompleter>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHash>
#include <QHeaderView>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPixmap>
#include <QRegularExpression>
#include <QSet>
#include <QSignalBlocker>
#include <QStandardItem>
#include <QStandardItemModel>

#include <algorithm>
#include <string>
#include <unordered_map>
#include <utility>

#include <objbase.h>
#include <Shellapi.h>

using namespace network_dock_detail;

namespace
{
    // kMaxMonitorProcessIconExtractPerRound：
    // - 单轮后台补图标的上限；
    // - 首次刷新时系统里可能有 300+ 进程，一次全量冷查 Shell 图标会长时间占用线程池，
    //   超出的部分留给后续刷新轮次继续补齐。
    constexpr int kMaxMonitorProcessIconExtractPerRound = 128;

    // MonitorProcessCandidateSnapshotItem：
    // - 后台线程产出的进程候选原始数据，只包含可跨线程传递的值类型；
    // - QIcon/QPixmap 一律不出现在这里，图标由 UI 线程按位图构造。
    struct MonitorProcessCandidateSnapshotItem
    {
        std::uint32_t pid = 0; // 进程 PID。
        QString processName;   // 进程名（已去空白）。
    };

    // MonitorProcessCandidateRefreshState：
    // - 进程候选缓存的异步刷新调度状态；
    // - latestRequestGeneration 用于淘汰被新请求取代的旧结果；
    // - refreshInFlight 保证同一时刻只有一个后台枚举任务在跑。
    struct MonitorProcessCandidateRefreshState
    {
        quint64 latestRequestGeneration = 0;
        bool refreshInFlight = false;
    };

    // g_monitorProcessCandidateRefreshStateMap：
    // - 按 NetworkDock 实例保存上面的调度状态；
    // - 只在 UI 线程读写（派发点与回投点都在 UI 线程），因此不需要加锁；
    // - 键仅作为身份标识，永不解引用，宿主析构后由回投分支按键清理。
    std::unordered_map<const NetworkDock*, MonitorProcessCandidateRefreshState>
        g_monitorProcessCandidateRefreshStateMap;

    // monitorProcessPlaceholderIcon 作用：
    // - 返回进程候选下拉的统一占位图标，真实图标解析完成前先顶上；
    // - 入参：无；
    // - 返回：共享 QIcon 引用，只能在 UI 线程使用。
    const QIcon& monitorProcessPlaceholderIcon()
    {
        static const QIcon placeholderIcon(QStringLiteral(":/Icon/process_main.svg"));
        return placeholderIcon;
    }

    // collectMonitorProcessCandidateSnapshot 作用：
    // - 在线程池工作线程里做一次系统进程枚举，只产出 PID 与进程名；
    // - EnumerateProcesses 内部会拉全局句柄快照与 PDH GPU 计数器，必须远离 UI 线程；
    // - 入参：无；
    // - 返回：可跨线程传递的候选原始数据列表。
    std::vector<MonitorProcessCandidateSnapshotItem> collectMonitorProcessCandidateSnapshot()
    {
        const std::vector<ks::process::ProcessRecord> processList =
            ks::process::EnumerateProcesses(ks::process::ProcessEnumStrategy::Auto);

        std::vector<MonitorProcessCandidateSnapshotItem> snapshotList;
        snapshotList.reserve(processList.size());
        for (const ks::process::ProcessRecord& processRecord : processList)
        {
            if (processRecord.pid == 0)
            {
                continue;
            }

            MonitorProcessCandidateSnapshotItem snapshotItem;
            snapshotItem.pid = processRecord.pid;
            snapshotItem.processName = toQString(processRecord.processName).trimmed();
            snapshotList.push_back(std::move(snapshotItem));
        }
        return snapshotList;
    }

    // collectMonitorProcessIconImages 作用：
    // - 在线程池工作线程里为“尚无图标缓存”的 PID 提取 Shell 小图标位图；
    // - 同一可执行路径只查询一次，并限制单轮提取数量，避免首次刷新长时间占用线程池；
    // - SHGetFileInfoW 依赖 COM，工作线程必须自己成对 CoInitializeEx / CoUninitialize；
    // - 入参 candidateSnapshotList：本轮枚举到的候选列表；
    // - 入参 cachedIconPidSet：UI 线程已缓存图标的 PID 快照，命中的直接跳过；
    // - 返回：PID -> 图标位图；位图为空表示解析失败，由 UI 线程回退占位图标。
    QHash<quint32, QImage> collectMonitorProcessIconImages(
        const std::vector<MonitorProcessCandidateSnapshotItem>& candidateSnapshotList,
        const QSet<quint32>& cachedIconPidSet)
    {
        QHash<quint32, QImage> iconImageByPid;

        const HRESULT comInitializeResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const bool comInitializedHere = SUCCEEDED(comInitializeResult);

        QHash<QString, QImage> iconImageByExecutablePath;
        int extractedCount = 0;
        for (const MonitorProcessCandidateSnapshotItem& snapshotItem : candidateSnapshotList)
        {
            const quint32 processIdKey = static_cast<quint32>(snapshotItem.pid);
            if (cachedIconPidSet.contains(processIdKey))
            {
                continue;
            }
            if (extractedCount >= kMaxMonitorProcessIconExtractPerRound)
            {
                break;
            }
            ++extractedCount;

            const std::string processPath = ks::process::QueryProcessPathByPid(snapshotItem.pid);
            if (processPath.empty())
            {
                iconImageByPid.insert(processIdKey, QImage());
                continue;
            }

            const QString processPathText = QString::fromUtf8(processPath.c_str());
            const auto pathIterator = iconImageByExecutablePath.constFind(processPathText);
            if (pathIterator != iconImageByExecutablePath.constEnd())
            {
                iconImageByPid.insert(processIdKey, pathIterator.value());
                continue;
            }

            SHFILEINFOW shellFileInfo{};
            const DWORD_PTR shellQueryResult = ::SHGetFileInfoW(
                reinterpret_cast<const wchar_t*>(processPathText.utf16()),
                0,
                &shellFileInfo,
                sizeof(shellFileInfo),
                SHGFI_ICON | SHGFI_SMALLICON);

            QImage processIconImage;
            if (shellQueryResult != 0 && shellFileInfo.hIcon != nullptr)
            {
                // QImage::fromHICON 会复制像素数据，转换完成后必须归还 Shell 分配的 HICON。
                processIconImage = QImage::fromHICON(shellFileInfo.hIcon);
                ::DestroyIcon(shellFileInfo.hIcon);
            }
            iconImageByExecutablePath.insert(processPathText, processIconImage);
            iconImageByPid.insert(processIdKey, processIconImage);
        }

        if (comInitializedHere)
        {
            ::CoUninitialize();
        }
        return iconImageByPid;
    }

    constexpr const char* kMonitorFilterConfigRelativePath = "config/wireshark.cfg";
    constexpr const char* kMonitorFilterJsonVersionKey = "version";
    constexpr const char* kMonitorFilterJsonGroupsKey = "groups";
    constexpr const char* kMonitorFilterJsonEnabledKey = "enabled";
    constexpr const char* kMonitorFilterJsonProcessesKey = "processes";
    constexpr const char* kMonitorFilterJsonPidKey = "pid";
    constexpr const char* kMonitorFilterJsonProcessNameKey = "name";
    constexpr const char* kMonitorFilterJsonLocalAddressesKey = "local_addresses";
    constexpr const char* kMonitorFilterJsonRemoteAddressesKey = "remote_addresses";
    constexpr const char* kMonitorFilterJsonLocalPortsKey = "local_ports";
    constexpr const char* kMonitorFilterJsonRemotePortsKey = "remote_ports";
    constexpr const char* kMonitorFilterJsonPacketSizesKey = "packet_sizes";

    constexpr int kProcessSuggestPidRole = Qt::UserRole + 1;
    constexpr int kProcessSuggestNameRole = Qt::UserRole + 2;

    QStringList jsonArrayToStringList(const QJsonValue& value)
    {
        QStringList outputList;
        const QJsonArray arrayValue = value.toArray();
        outputList.reserve(arrayValue.size());
        for (const QJsonValue& itemValue : arrayValue)
        {
            const QString text = itemValue.toString().trimmed();
            if (!text.isEmpty())
            {
                outputList.push_back(text);
            }
        }
        return outputList;
    }

    void configureRuleValueTable(
        QTableWidget* tableWidget,
        const QStringList& headers,
        const int processIdColumn = -1)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        ks::ui::SetTableActionBarMode(tableWidget, ks::ui::TableActionBarMode::None);
        tableWidget->setColumnCount(headers.size());
        tableWidget->setHorizontalHeaderLabels(headers);
        tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableWidget->verticalHeader()->setVisible(false);
        tableWidget->horizontalHeader()->setStretchLastSection(true);
        tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        tableWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        installCopyCurrentRowMenu(
            tableWidget,
            QStringLiteral("复制当前行"),
            processIdColumn);
    }

    QTableWidgetItem* createReadonlyItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

QStringList NetworkDock::splitMonitorFilterTokens(const QString& inputText)
{
    static const QRegularExpression separatorRegex(QStringLiteral("[,;\\s]+"));
    return inputText.split(separatorRegex, Qt::SkipEmptyParts);
}

bool NetworkDock::tryParsePacketSizeToken(
    const QString& tokenText,
    UInt32Range& rangeOut,
    QString& normalizeTextOut)
{
    const QString trimmedText = tokenText.trimmed();
    if (trimmedText.isEmpty())
    {
        return false;
    }

    const auto parseUInt32 = [](const QString& text, std::uint32_t& valueOut) -> bool
        {
            bool parseOk = false;
            const qulonglong parsedValue = text.trimmed().toULongLong(&parseOk, 10);
            if (!parseOk || parsedValue > 0xFFFFFFFFULL)
            {
                return false;
            }
            valueOut = static_cast<std::uint32_t>(parsedValue);
            return true;
        };

    const int dashIndex = trimmedText.indexOf('-');
    if (dashIndex > 0)
    {
        const QString beginText = trimmedText.left(dashIndex).trimmed();
        const QString endText = trimmedText.mid(dashIndex + 1).trimmed();

        std::uint32_t beginValue = 0;
        std::uint32_t endValue = 0;
        if (!parseUInt32(beginText, beginValue) || !parseUInt32(endText, endValue))
        {
            return false;
        }

        const std::uint32_t normalizedBegin = std::min(beginValue, endValue);
        const std::uint32_t normalizedEnd = std::max(beginValue, endValue);
        rangeOut = { normalizedBegin, normalizedEnd };
        normalizeTextOut = (normalizedBegin == normalizedEnd)
            ? QString::number(normalizedBegin)
            : QStringLiteral("%1-%2").arg(normalizedBegin).arg(normalizedEnd);
        return true;
    }

    std::uint32_t singleValue = 0;
    if (!parseUInt32(trimmedText, singleValue))
    {
        return false;
    }

    rangeOut = { singleValue, singleValue };
    normalizeTextOut = QString::number(singleValue);
    return true;
}

NetworkDock::MonitorFilterRuleGroupUiState* NetworkDock::findMonitorFilterRuleGroupById(const int groupId)
{
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : m_monitorFilterRuleGroupUiList)
    {
        if (groupState != nullptr && groupState->groupId == groupId)
        {
            return groupState.get();
        }
    }
    return nullptr;
}

const NetworkDock::MonitorFilterRuleGroupUiState* NetworkDock::findMonitorFilterRuleGroupById(const int groupId) const
{
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : m_monitorFilterRuleGroupUiList)
    {
        if (groupState != nullptr && groupState->groupId == groupId)
        {
            return groupState.get();
        }
    }
    return nullptr;
}

NetworkDock::MonitorTextRuleFieldUiState* NetworkDock::findTextRuleField(
    MonitorFilterRuleGroupUiState& groupState,
    const MonitorTextRuleFieldKind fieldKind)
{
    switch (fieldKind)
    {
    case MonitorTextRuleFieldKind::LocalAddress:
        return &groupState.localAddressField;
    case MonitorTextRuleFieldKind::RemoteAddress:
        return &groupState.remoteAddressField;
    case MonitorTextRuleFieldKind::LocalPort:
        return &groupState.localPortField;
    case MonitorTextRuleFieldKind::RemotePort:
        return &groupState.remotePortField;
    case MonitorTextRuleFieldKind::PacketSize:
        return &groupState.packetSizeField;
    default:
        return nullptr;
    }
}

const NetworkDock::MonitorTextRuleFieldUiState* NetworkDock::findTextRuleField(
    const MonitorFilterRuleGroupUiState& groupState,
    const MonitorTextRuleFieldKind fieldKind) const
{
    switch (fieldKind)
    {
    case MonitorTextRuleFieldKind::LocalAddress:
        return &groupState.localAddressField;
    case MonitorTextRuleFieldKind::RemoteAddress:
        return &groupState.remoteAddressField;
    case MonitorTextRuleFieldKind::LocalPort:
        return &groupState.localPortField;
    case MonitorTextRuleFieldKind::RemotePort:
        return &groupState.remotePortField;
    case MonitorTextRuleFieldKind::PacketSize:
        return &groupState.packetSizeField;
    default:
        return nullptr;
    }
}

QString NetworkDock::monitorFilterConfigPath() const
{
    return QDir(QCoreApplication::applicationDirPath())
        .absoluteFilePath(QString::fromLatin1(kMonitorFilterConfigRelativePath));
}

void NetworkDock::refreshMonitorProcessCandidateList(const bool forceRefresh)
{
    // 该函数已由“同步全量枚举 + 逐进程图标提取”改成纯调度：
    // - UI 线程只判节流并派发任务，绝不再在这里做 EnumerateProcesses / Shell 图标提取；
    // - 后台任务分两段回投：先回投 PID+进程名让下拉立刻可用，再回投图标位图补齐显示；
    // - 调用方本次拿到的仍是上一轮已缓存的 m_monitorProcessCandidateList。
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    constexpr qint64 kRefreshIntervalMs = 1200;
    if (!forceRefresh &&
        !m_monitorProcessCandidateList.empty() &&
        nowMs - m_monitorProcessCandidateLastRefreshMs < kRefreshIntervalMs)
    {
        return;
    }

    MonitorProcessCandidateRefreshState& refreshState =
        g_monitorProcessCandidateRefreshStateMap[this];
    if (refreshState.refreshInFlight)
    {
        return;
    }
    refreshState.refreshInFlight = true;
    ++refreshState.latestRequestGeneration;
    const quint64 requestGeneration = refreshState.latestRequestGeneration;

    // 已缓存图标的 PID 快照随任务一起下发，后台只为新出现的进程做 Shell 图标提取。
    QSet<quint32> cachedIconPidSet;
    cachedIconPidSet.reserve(m_processIconCacheByPid.size());
    for (auto iconCacheIterator = m_processIconCacheByPid.constBegin();
        iconCacheIterator != m_processIconCacheByPid.constEnd();
        ++iconCacheIterator)
    {
        cachedIconPidSet.insert(iconCacheIterator.key());
    }

    // refreshFocusedProcessSuggestionModels 作用：
    // - 候选缓存或图标更新后，只为“当前正在输入的规则组”重建补全下拉；
    // - 入参 dockInstance：宿主 NetworkDock；
    // - 返回：无。
    const auto refreshFocusedProcessSuggestionModels = [](NetworkDock* const dockInstance)
        {
            for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState :
                dockInstance->m_monitorFilterRuleGroupUiList)
            {
                if (groupState == nullptr ||
                    groupState->processInputEdit == nullptr ||
                    !groupState->processInputEdit->hasFocus())
                {
                    continue;
                }
                dockInstance->refreshProcessSuggestionModelForGroup(
                    groupState->groupId,
                    groupState->processInputEdit->text());
            }
        };

    // ownerKey 只当身份标识用（绝不解引用），保证宿主析构后仍能定位并清理调度状态。
    const QPointer<NetworkDock> guardedSelf(this);
    const NetworkDock* const ownerKey = this;
    QThreadPool::globalInstance()->start(
        [guardedSelf, ownerKey, requestGeneration, cachedIconPidSet, refreshFocusedProcessSuggestionModels]()
        {
            // 第一段：只做进程枚举，尽快让下拉候选可用。
            const std::vector<MonitorProcessCandidateSnapshotItem> candidateSnapshotList =
                collectMonitorProcessCandidateSnapshot();

            QCoreApplication* const nameStageAppInstance = QCoreApplication::instance();
            if (nameStageAppInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                nameStageAppInstance,
                [guardedSelf,
                    ownerKey,
                    requestGeneration,
                    candidateSnapshotList,
                    refreshFocusedProcessSuggestionModels]()
                {
                    const auto stateIterator = g_monitorProcessCandidateRefreshStateMap.find(ownerKey);
                    if (stateIterator == g_monitorProcessCandidateRefreshStateMap.end() ||
                        stateIterator->second.latestRequestGeneration != requestGeneration ||
                        guardedSelf == nullptr)
                    {
                        return;
                    }

                    std::vector<MonitorProcessCandidate> candidateList;
                    candidateList.reserve(candidateSnapshotList.size());
                    for (const MonitorProcessCandidateSnapshotItem& snapshotItem : candidateSnapshotList)
                    {
                        MonitorProcessCandidate candidate;
                        candidate.pid = snapshotItem.pid;
                        candidate.processName = snapshotItem.processName;
                        if (candidate.processName.isEmpty())
                        {
                            candidate.processName = QStringLiteral("PID_%1").arg(snapshotItem.pid);
                        }

                        // 图标只从缓存取，缓存未命中时先用占位图标，等第二段回投再补齐。
                        const auto iconCacheIterator = guardedSelf->m_processIconCacheByPid.constFind(
                            static_cast<quint32>(snapshotItem.pid));
                        candidate.processIcon =
                            iconCacheIterator != guardedSelf->m_processIconCacheByPid.constEnd()
                            ? iconCacheIterator.value()
                            : monitorProcessPlaceholderIcon();
                        candidate.displayText = QStringLiteral("%1 (%2)")
                            .arg(candidate.processName)
                            .arg(candidate.pid);
                        candidate.searchText = QStringLiteral("%1 %2")
                            .arg(candidate.processName.toLower())
                            .arg(QString::number(candidate.pid));
                        candidateList.push_back(std::move(candidate));
                    }

                    std::sort(
                        candidateList.begin(),
                        candidateList.end(),
                        [](const MonitorProcessCandidate& left, const MonitorProcessCandidate& right)
                        {
                            if (left.processName.compare(right.processName, Qt::CaseInsensitive) == 0)
                            {
                                return left.pid < right.pid;
                            }
                            return left.processName.compare(right.processName, Qt::CaseInsensitive) < 0;
                        });

                    guardedSelf->m_monitorProcessCandidateList = std::move(candidateList);
                    guardedSelf->m_monitorProcessCandidateLastRefreshMs =
                        QDateTime::currentMSecsSinceEpoch();
                    refreshFocusedProcessSuggestionModels(guardedSelf.data());
                },
                Qt::QueuedConnection);

            // 第二段：补齐尚无缓存的 PID 图标，同样全部在后台完成。
            const QHash<quint32, QImage> iconImageByPid =
                collectMonitorProcessIconImages(candidateSnapshotList, cachedIconPidSet);

            QCoreApplication* const iconStageAppInstance = QCoreApplication::instance();
            if (iconStageAppInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                iconStageAppInstance,
                [guardedSelf,
                    ownerKey,
                    requestGeneration,
                    iconImageByPid,
                    refreshFocusedProcessSuggestionModels]()
                {
                    // 本轮任务结束：先释放调度位，让后续输入还能继续刷新候选。
                    const auto stateIterator = g_monitorProcessCandidateRefreshStateMap.find(ownerKey);
                    if (stateIterator == g_monitorProcessCandidateRefreshStateMap.end())
                    {
                        return;
                    }
                    if (stateIterator->second.latestRequestGeneration != requestGeneration)
                    {
                        return;
                    }
                    stateIterator->second.refreshInFlight = false;
                    if (guardedSelf == nullptr)
                    {
                        g_monitorProcessCandidateRefreshStateMap.erase(stateIterator);
                        return;
                    }
                    if (iconImageByPid.isEmpty())
                    {
                        return;
                    }

                    // QPixmap/QIcon 只能在 UI 线程构造；解析失败也写入缓存，避免同一 PID 反复冷查。
                    for (auto iconImageIterator = iconImageByPid.constBegin();
                        iconImageIterator != iconImageByPid.constEnd();
                        ++iconImageIterator)
                    {
                        const QIcon resolvedIcon = iconImageIterator.value().isNull()
                            ? monitorProcessPlaceholderIcon()
                            : QIcon(QPixmap::fromImage(iconImageIterator.value()));
                        guardedSelf->m_processIconCacheByPid.insert(iconImageIterator.key(), resolvedIcon);
                    }

                    for (MonitorProcessCandidate& candidate : guardedSelf->m_monitorProcessCandidateList)
                    {
                        const auto iconCacheIterator = guardedSelf->m_processIconCacheByPid.constFind(
                            static_cast<quint32>(candidate.pid));
                        if (iconCacheIterator != guardedSelf->m_processIconCacheByPid.constEnd())
                        {
                            candidate.processIcon = iconCacheIterator.value();
                        }
                    }
                    refreshFocusedProcessSuggestionModels(guardedSelf.data());
                },
                Qt::QueuedConnection);
        });
}

void NetworkDock::refreshProcessSuggestionModelForGroup(const int groupId, const QString& keywordText)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr ||
        groupState->processSuggestionModel == nullptr ||
        groupState->processInputEdit == nullptr)
    {
        return;
    }

    // 只负责“调度一次后台刷新”，本次筛选仍在已缓存的候选列表上做纯字符串匹配；
    // 后台结果回投后会再次为当前聚焦的输入框重建下拉，不需要用户重复敲键。
    refreshMonitorProcessCandidateList(false);

    const QString keyword = keywordText.trimmed().toLower();
    groupState->processSuggestionModel->clear();

    constexpr int kMaxSuggestCount = 200;
    int addedCount = 0;
    for (const MonitorProcessCandidate& candidate : m_monitorProcessCandidateList)
    {
        if (!keyword.isEmpty() && !candidate.searchText.contains(keyword))
        {
            continue;
        }

        auto* item = new QStandardItem(candidate.processIcon, candidate.displayText);
        item->setData(static_cast<qulonglong>(candidate.pid), kProcessSuggestPidRole);
        item->setData(candidate.processName, kProcessSuggestNameRole);
        groupState->processSuggestionModel->appendRow(item);

        ++addedCount;
        if (addedCount >= kMaxSuggestCount)
        {
            break;
        }
    }

    if (groupState->processCompleter != nullptr)
    {
        groupState->processCompleter->setCompletionPrefix(keywordText.trimmed());
        if (groupState->processInputEdit->hasFocus() && addedCount > 0)
        {
            groupState->processCompleter->complete();
        }
    }
}

void NetworkDock::rebuildMonitorFilterRuleGroupUi()
{
    if (m_monitorFilterGroupHostLayout == nullptr)
    {
        return;
    }

    while (m_monitorFilterGroupHostLayout->count() > 0)
    {
        QLayoutItem* item = m_monitorFilterGroupHostLayout->takeAt(0);
        delete item;
    }

    const bool canRemoveGroup = m_monitorFilterRuleGroupUiList.size() > 1;
    int displayIndex = 1;
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : m_monitorFilterRuleGroupUiList)
    {
        if (groupState == nullptr || groupState->containerWidget == nullptr)
        {
            continue;
        }

        if (groupState->titleLabel != nullptr)
        {
            groupState->titleLabel->setText(QStringLiteral("规则组%1").arg(displayIndex));
        }
        if (groupState->removeGroupButton != nullptr)
        {
            groupState->removeGroupButton->setEnabled(canRemoveGroup);
        }

        m_monitorFilterGroupHostLayout->addWidget(groupState->containerWidget);
        ++displayIndex;
    }

    m_monitorFilterGroupHostLayout->addStretch(1);
}

void NetworkDock::addMonitorFilterRuleGroup()
{
    if (m_monitorFilterGroupHostWidget == nullptr || m_monitorFilterGroupHostLayout == nullptr)
    {
        return;
    }

    std::unique_ptr<MonitorFilterRuleGroupUiState> groupState = std::make_unique<MonitorFilterRuleGroupUiState>();
    groupState->groupId = m_monitorFilterNextGroupId++;

    groupState->containerWidget = new QWidget(m_monitorFilterGroupHostWidget);
    auto* rootLayout = new QVBoxLayout(groupState->containerWidget);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(6);

    auto* headerLayout = new QHBoxLayout();
    headerLayout->setSpacing(6);
    groupState->titleLabel = new QLabel(QStringLiteral("规则组"), groupState->containerWidget);
    groupState->enabledCheck = new QCheckBox(QStringLiteral("启用"), groupState->containerWidget);
    groupState->enabledCheck->setChecked(true);
    groupState->removeGroupButton = new QPushButton(groupState->containerWidget);
    groupState->removeGroupButton->setIcon(QIcon(":/Icon/log_cancel_track.svg"));
    groupState->removeGroupButton->setToolTip(QStringLiteral("删除当前规则组"));

    headerLayout->addWidget(groupState->titleLabel);
    headerLayout->addWidget(groupState->enabledCheck);
    headerLayout->addStretch(1);
    headerLayout->addWidget(groupState->removeGroupButton);
    ks::ui::NormalizeToolbarRow(headerLayout);
    rootLayout->addLayout(headerLayout);

    QFrame* separatorLine = new QFrame(groupState->containerWidget);
    separatorLine->setFrameShape(QFrame::HLine);
    separatorLine->setFrameShadow(QFrame::Sunken);
    rootLayout->addWidget(separatorLine);

    auto* fieldRowLayout = new QHBoxLayout();
    fieldRowLayout->setSpacing(8);

    QWidget* processBlock = new QWidget(groupState->containerWidget);
    processBlock->setMinimumWidth(340);
    auto* processBlockLayout = new QVBoxLayout(processBlock);
    processBlockLayout->setContentsMargins(0, 0, 0, 0);
    processBlockLayout->setSpacing(4);

    auto* processTopLayout = new QHBoxLayout();
    processTopLayout->setSpacing(4);
    QLabel* processLabel = new QLabel(QStringLiteral("进程"), processBlock);
    groupState->processInputEdit = new QLineEdit(processBlock);
    groupState->processInputEdit->setPlaceholderText(QStringLiteral("输入 PID 或进程名"));
    groupState->processInputEdit->setToolTip(QStringLiteral("输入后自动匹配系统进程，支持 PID/进程名。"));
    groupState->addProcessButton = new QPushButton(QStringLiteral("+"), processBlock);
    groupState->addProcessButton->setText(QString());
    groupState->addProcessButton->setIcon(QIcon(QStringLiteral(":/Icon/plus.svg")));
    groupState->addProcessButton->setToolTip(
        QStringLiteral("把上方输入框中的进程加入本规则组的进程过滤列表"));
    groupState->removeInvalidProcessButton = new QPushButton(QStringLiteral("清除失效"), processBlock);
    groupState->removeInvalidProcessButton->setToolTip(
        QStringLiteral("移除列表中已经关闭或不存在的进程"));
    groupState->clearProcessButton = new QPushButton(processBlock);
    groupState->clearProcessButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    groupState->clearProcessButton->setToolTip(QStringLiteral("清空进程列表"));

    groupState->processSuggestionModel = new QStandardItemModel(groupState->processInputEdit);
    groupState->processCompleter = new QCompleter(groupState->processSuggestionModel, groupState->processInputEdit);
    groupState->processCompleter->setCaseSensitivity(Qt::CaseInsensitive);
    groupState->processCompleter->setCompletionMode(QCompleter::PopupCompletion);
    groupState->processCompleter->setFilterMode(Qt::MatchContains);
    groupState->processInputEdit->setCompleter(groupState->processCompleter);

    processTopLayout->addWidget(processLabel);
    processTopLayout->addWidget(groupState->processInputEdit, 1);
    processTopLayout->addWidget(groupState->addProcessButton);
    processTopLayout->addWidget(groupState->removeInvalidProcessButton);
    processTopLayout->addWidget(groupState->clearProcessButton);
    ks::ui::NormalizeToolbarRow(processTopLayout);

    groupState->processTable = new ks::ui::VisibleTableWidget(processBlock);
    groupState->processTable->setMinimumHeight(56);
    groupState->processTable->setMaximumHeight(86);
    configureRuleValueTable(groupState->processTable, {
        QStringLiteral("进程"),
        QStringLiteral("PID"),
        QStringLiteral("操作")
        }, 1);

    processBlockLayout->addLayout(processTopLayout);
    processBlockLayout->addWidget(groupState->processTable);
    fieldRowLayout->addWidget(processBlock);

    const auto buildTextFieldBlock = [this, &fieldRowLayout, groupStatePtr = groupState.get()](
        MonitorTextRuleFieldUiState& fieldState,
        const QString& labelText,
        const QString& placeholderText,
        const MonitorTextRuleFieldKind fieldKind,
        const int minimumWidth)
        {
            fieldState.labelText = labelText;

            QWidget* block = new QWidget(groupStatePtr->containerWidget);
            block->setMinimumWidth(minimumWidth);
            auto* blockLayout = new QVBoxLayout(block);
            blockLayout->setContentsMargins(0, 0, 0, 0);
            blockLayout->setSpacing(4);

            auto* topLayout = new QHBoxLayout();
            topLayout->setSpacing(4);
            QLabel* label = new QLabel(labelText, block);
            fieldState.inputEdit = new QLineEdit(block);
            fieldState.inputEdit->setPlaceholderText(placeholderText);
            fieldState.addButton = new QPushButton(QStringLiteral("+"), block);
            fieldState.addButton->setText(QString());
            fieldState.addButton->setIcon(QIcon(QStringLiteral(":/Icon/plus.svg")));
            fieldState.addButton->setToolTip(
                QStringLiteral("把上方输入的地址或端口加入本条件的过滤列表"));
            fieldState.clearButton = new QPushButton(QStringLiteral("清空"), block);
            fieldState.clearButton->setToolTip(
                QStringLiteral("清空本条件已添加的所有过滤项"));

            topLayout->addWidget(label);
            topLayout->addWidget(fieldState.inputEdit, 1);
            topLayout->addWidget(fieldState.addButton);
            topLayout->addWidget(fieldState.clearButton);
            ks::ui::NormalizeToolbarRow(topLayout);

            fieldState.tableWidget = new ks::ui::VisibleTableWidget(block);
            fieldState.tableWidget->setMinimumHeight(56);
            fieldState.tableWidget->setMaximumHeight(86);
            configureRuleValueTable(fieldState.tableWidget, {
                labelText,
                QStringLiteral("操作")
                });

            blockLayout->addLayout(topLayout);
            blockLayout->addWidget(fieldState.tableWidget);
            fieldRowLayout->addWidget(block);

            connect(fieldState.addButton, &QPushButton::clicked, this, [this, groupId = groupStatePtr->groupId, fieldKind]()
                {
                    addTextFilterItemsByInput(groupId, fieldKind);
                });
            connect(fieldState.clearButton, &QPushButton::clicked, this, [this, groupId = groupStatePtr->groupId, fieldKind]()
                {
                    clearTextFilterItems(groupId, fieldKind);
                });
            connect(fieldState.inputEdit, &QLineEdit::returnPressed, this, [this, groupId = groupStatePtr->groupId, fieldKind]()
                {
                    addTextFilterItemsByInput(groupId, fieldKind);
                });
        };

    buildTextFieldBlock(
        groupState->localAddressField,
        QStringLiteral("本地地址"),
        QStringLiteral("如 192.168.1.0/24"),
        MonitorTextRuleFieldKind::LocalAddress,
        240);
    buildTextFieldBlock(
        groupState->remoteAddressField,
        QStringLiteral("远程地址"),
        QStringLiteral("如 8.8.8.8 或 10.0.0.1-10.0.0.20"),
        MonitorTextRuleFieldKind::RemoteAddress,
        260);
    buildTextFieldBlock(
        groupState->localPortField,
        QStringLiteral("本地端口"),
        QStringLiteral("如 80 或 1000-2000"),
        MonitorTextRuleFieldKind::LocalPort,
        220);
    buildTextFieldBlock(
        groupState->remotePortField,
        QStringLiteral("远程端口"),
        QStringLiteral("如 443 或 5000-6000"),
        MonitorTextRuleFieldKind::RemotePort,
        220);
    buildTextFieldBlock(
        groupState->packetSizeField,
        QStringLiteral("包长"),
        QStringLiteral("如 40,60-80"),
        MonitorTextRuleFieldKind::PacketSize,
        220);

    rootLayout->addLayout(fieldRowLayout);

    QFrame* bottomLine = new QFrame(groupState->containerWidget);
    bottomLine->setFrameShape(QFrame::HLine);
    bottomLine->setFrameShadow(QFrame::Sunken);
    rootLayout->addWidget(bottomLine);

    connect(groupState->enabledCheck, &QCheckBox::toggled, this, [this]()
        {
            applyMonitorFilters();
        });
    connect(groupState->removeGroupButton, &QPushButton::clicked, this, [this, groupId = groupState->groupId]()
        {
            removeMonitorFilterRuleGroup(groupId);
        });

    connect(groupState->processInputEdit, &QLineEdit::textEdited, this, [this, groupId = groupState->groupId](const QString& text)
        {
            MonitorFilterRuleGroupUiState* state = findMonitorFilterRuleGroupById(groupId);
            if (state != nullptr && state->processInputEdit != nullptr)
            {
                state->processInputEdit->setProperty("selected_pid", QVariant());
                state->processInputEdit->setProperty("selected_process_name", QVariant());
            }
            refreshProcessSuggestionModelForGroup(groupId, text);
        });
    connect(groupState->processInputEdit, &QLineEdit::returnPressed, this, [this, groupId = groupState->groupId]()
        {
            addProcessTargetByInput(groupId);
        });
    connect(groupState->addProcessButton, &QPushButton::clicked, this, [this, groupId = groupState->groupId]()
        {
            addProcessTargetByInput(groupId);
        });
    connect(groupState->removeInvalidProcessButton, &QPushButton::clicked, this, [this, groupId = groupState->groupId]()
        {
            removeInvalidProcessTargets(groupId);
        });
    connect(groupState->clearProcessButton, &QPushButton::clicked, this, [this, groupId = groupState->groupId]()
        {
            clearProcessTargetList(groupId);
        });
    connect(groupState->processCompleter,
        QOverload<const QModelIndex&>::of(&QCompleter::activated),
        this,
        [this, groupId = groupState->groupId](const QModelIndex& modelIndex)
        {
            MonitorFilterRuleGroupUiState* state = findMonitorFilterRuleGroupById(groupId);
            if (state == nullptr || state->processInputEdit == nullptr || !modelIndex.isValid())
            {
                return;
            }

            const QVariant pidVariant = modelIndex.data(kProcessSuggestPidRole);
            const QVariant nameVariant = modelIndex.data(kProcessSuggestNameRole);
            state->processInputEdit->setProperty("selected_pid", pidVariant);
            state->processInputEdit->setProperty("selected_process_name", nameVariant);
            state->processInputEdit->setText(modelIndex.data(Qt::DisplayRole).toString());
        });

    m_monitorFilterRuleGroupUiList.push_back(std::move(groupState));

    rebuildMonitorFilterRuleGroupUi();
    refreshProcessTableForGroup(m_monitorFilterRuleGroupUiList.back()->groupId);
    refreshTextTableForGroup(m_monitorFilterRuleGroupUiList.back()->groupId, MonitorTextRuleFieldKind::LocalAddress);
    refreshTextTableForGroup(m_monitorFilterRuleGroupUiList.back()->groupId, MonitorTextRuleFieldKind::RemoteAddress);
    refreshTextTableForGroup(m_monitorFilterRuleGroupUiList.back()->groupId, MonitorTextRuleFieldKind::LocalPort);
    refreshTextTableForGroup(m_monitorFilterRuleGroupUiList.back()->groupId, MonitorTextRuleFieldKind::RemotePort);
    refreshTextTableForGroup(m_monitorFilterRuleGroupUiList.back()->groupId, MonitorTextRuleFieldKind::PacketSize);
}

void NetworkDock::removeMonitorFilterRuleGroup(const int groupId)
{
    auto iterator = std::find_if(
        m_monitorFilterRuleGroupUiList.begin(),
        m_monitorFilterRuleGroupUiList.end(),
        [groupId](const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState)
        {
            return groupState != nullptr && groupState->groupId == groupId;
        });

    if (iterator == m_monitorFilterRuleGroupUiList.end())
    {
        return;
    }

    if ((*iterator)->containerWidget != nullptr)
    {
        delete (*iterator)->containerWidget;
        (*iterator)->containerWidget = nullptr;
    }

    m_monitorFilterRuleGroupUiList.erase(iterator);

    if (m_monitorFilterRuleGroupUiList.empty())
    {
        addMonitorFilterRuleGroup();
    }

    rebuildMonitorFilterRuleGroupUi();
    applyMonitorFilters();
}

void NetworkDock::refreshProcessTableForGroup(const int groupId)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr || groupState->processTable == nullptr)
    {
        return;
    }

    QTableWidget* processTable = groupState->processTable;
    processTable->setRowCount(static_cast<int>(groupState->processTargetList.size()));

    for (int row = 0; row < processTable->rowCount(); ++row)
    {
        const MonitorProcessTarget& target = groupState->processTargetList[static_cast<std::size_t>(row)];

        QTableWidgetItem* processItem = createReadonlyItem(target.processName);
        processItem->setIcon(target.processIcon);
        processTable->setItem(row, 0, processItem);
        processTable->setItem(row, 1, createReadonlyItem(QString::number(target.pid)));

        QPushButton* removeButton = new QPushButton(QStringLiteral("移除"), processTable);
        connect(removeButton, &QPushButton::clicked, this, [this, groupId, pid = target.pid]()
            {
                removeProcessTarget(groupId, pid);
            });
        processTable->setCellWidget(row, 2, removeButton);
    }
}

void NetworkDock::refreshTextTableForGroup(const int groupId, const MonitorTextRuleFieldKind fieldKind)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
    if (fieldState == nullptr || fieldState->tableWidget == nullptr)
    {
        return;
    }

    QTableWidget* tableWidget = fieldState->tableWidget;
    tableWidget->setRowCount(fieldState->valueList.size());

    for (int row = 0; row < tableWidget->rowCount(); ++row)
    {
        tableWidget->setItem(row, 0, createReadonlyItem(fieldState->valueList[row]));
        QPushButton* removeButton = new QPushButton(QStringLiteral("移除"), tableWidget);
        connect(removeButton, &QPushButton::clicked, this, [this, groupId, fieldKind, row]()
            {
                removeTextFilterItem(groupId, fieldKind, row);
            });
        tableWidget->setCellWidget(row, 1, removeButton);
    }
}

void NetworkDock::addProcessTargetByInput(const int groupId)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr || groupState->processInputEdit == nullptr)
    {
        return;
    }

    // 这里只触发一次后台刷新（不阻塞点击）：候选缓存在用户输入阶段就已经在后台建好，
    // 本次解析仍走“已缓存候选 -> PID 文本 -> GetProcessNameByPID”三级回退。
    refreshMonitorProcessCandidateList(true);

    const QString inputText = groupState->processInputEdit->text().trimmed();
    if (inputText.isEmpty())
    {
        return;
    }

    std::uint32_t resolvedPid = 0;
    QString resolvedName;
    QIcon resolvedIcon;

    const QVariant selectedPidVariant = groupState->processInputEdit->property("selected_pid");
    const QVariant selectedNameVariant = groupState->processInputEdit->property("selected_process_name");
    if (selectedPidVariant.isValid())
    {
        resolvedPid = static_cast<std::uint32_t>(selectedPidVariant.toULongLong());
        resolvedName = selectedNameVariant.toString().trimmed();
    }

    if (resolvedPid == 0)
    {
        std::uint32_t parsedPid = 0;
        if (tryParsePidText(inputText, parsedPid))
        {
            resolvedPid = parsedPid;
        }
        else
        {
            const QString loweredInput = inputText.toLower();
            for (const MonitorProcessCandidate& candidate : m_monitorProcessCandidateList)
            {
                if (candidate.processName.compare(loweredInput, Qt::CaseInsensitive) == 0 ||
                    candidate.searchText.contains(loweredInput))
                {
                    resolvedPid = candidate.pid;
                    resolvedName = candidate.processName;
                    resolvedIcon = candidate.processIcon;
                    break;
                }
            }
        }
    }

    if (resolvedPid == 0)
    {
        QMessageBox::warning(this, QStringLiteral("流量筛选"), QStringLiteral("未匹配到目标进程，请重新输入 PID 或进程名。"));
        return;
    }

    if (resolvedName.isEmpty())
    {
        for (const MonitorProcessCandidate& candidate : m_monitorProcessCandidateList)
        {
            if (candidate.pid == resolvedPid)
            {
                resolvedName = candidate.processName;
                resolvedIcon = candidate.processIcon;
                break;
            }
        }
    }
    if (resolvedName.isEmpty())
    {
        resolvedName = toQString(ks::process::GetProcessNameByPID(resolvedPid));
    }
    if (resolvedName.isEmpty())
    {
        resolvedName = QStringLiteral("PID_%1").arg(resolvedPid);
    }
    if (resolvedIcon.isNull())
    {
        resolvedIcon = resolveProcessIconByPid(resolvedPid, resolvedName.toStdString());
    }

    const bool existed = std::any_of(
        groupState->processTargetList.begin(),
        groupState->processTargetList.end(),
        [resolvedPid](const MonitorProcessTarget& target)
        {
            return target.pid == resolvedPid;
        });
    if (existed)
    {
        return;
    }

    MonitorProcessTarget target;
    target.pid = resolvedPid;
    target.processName = resolvedName;
    target.processIcon = resolvedIcon;
    groupState->processTargetList.push_back(std::move(target));

    groupState->processInputEdit->clear();
    groupState->processInputEdit->setProperty("selected_pid", QVariant());
    groupState->processInputEdit->setProperty("selected_process_name", QVariant());

    refreshProcessTableForGroup(groupId);
    applyMonitorFilters();
}

void NetworkDock::removeProcessTarget(const int groupId, const std::uint32_t pidValue)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    const auto eraseBegin = std::remove_if(
        groupState->processTargetList.begin(),
        groupState->processTargetList.end(),
        [pidValue](const MonitorProcessTarget& target)
        {
            return target.pid == pidValue;
        });
    if (eraseBegin == groupState->processTargetList.end())
    {
        return;
    }

    groupState->processTargetList.erase(eraseBegin, groupState->processTargetList.end());
    refreshProcessTableForGroup(groupId);
    applyMonitorFilters();
}

void NetworkDock::clearProcessTargetList(const int groupId)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    groupState->processTargetList.clear();
    refreshProcessTableForGroup(groupId);
    applyMonitorFilters();
}

void NetworkDock::removeInvalidProcessTargets(const int groupId)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr || groupState->processTargetList.empty())
    {
        return;
    }

    std::vector<ks::process::ProcessRecord> latestProcessList = ks::process::EnumerateProcesses(
        ks::process::ProcessEnumStrategy::Auto);
    std::unordered_map<std::uint32_t, QString> processNameMap;
    processNameMap.reserve(latestProcessList.size());
    for (const ks::process::ProcessRecord& processRecord : latestProcessList)
    {
        processNameMap[processRecord.pid] = toQString(processRecord.processName);
    }

    const std::size_t beforeCount = groupState->processTargetList.size();
    const auto eraseBegin = std::remove_if(
        groupState->processTargetList.begin(),
        groupState->processTargetList.end(),
        [&processNameMap](const MonitorProcessTarget& target)
        {
            const auto iterator = processNameMap.find(target.pid);
            if (iterator == processNameMap.end())
            {
                return true;
            }

            const QString currentName = iterator->second.trimmed();
            return currentName.isEmpty() ||
                currentName.compare(target.processName.trimmed(), Qt::CaseInsensitive) != 0;
        });
    groupState->processTargetList.erase(eraseBegin, groupState->processTargetList.end());

    const std::size_t removedCount = beforeCount - groupState->processTargetList.size();
    refreshProcessTableForGroup(groupId);
    applyMonitorFilters();

    if (removedCount > 0)
    {
        QMessageBox::information(this,
            QStringLiteral("流量筛选"),
            QStringLiteral("已移除 %1 条失效进程项。").arg(static_cast<qulonglong>(removedCount)));
    }
}

void NetworkDock::addTextFilterItemsByInput(const int groupId, const MonitorTextRuleFieldKind fieldKind)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
    if (fieldState == nullptr || fieldState->inputEdit == nullptr)
    {
        return;
    }

    const QString inputText = fieldState->inputEdit->text().trimmed();
    if (inputText.isEmpty())
    {
        return;
    }

    const QStringList tokenList = splitMonitorFilterTokens(inputText);
    if (tokenList.isEmpty())
    {
        return;
    }

    for (const QString& token : tokenList)
    {
        QString normalizedText;
        bool parseOk = false;

        if (fieldKind == MonitorTextRuleFieldKind::LocalAddress || fieldKind == MonitorTextRuleFieldKind::RemoteAddress)
        {
            UInt32Range ipv4Range{};
            parseOk = tryParseIpv4RangeText(token, ipv4Range, normalizedText);
        }
        else if (fieldKind == MonitorTextRuleFieldKind::LocalPort || fieldKind == MonitorTextRuleFieldKind::RemotePort)
        {
            UInt16Range portRange{};
            parseOk = tryParsePortRangeText(token, portRange, normalizedText);
        }
        else
        {
            UInt32Range sizeRange{};
            parseOk = tryParsePacketSizeToken(token, sizeRange, normalizedText);
        }

        if (!parseOk)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("流量筛选"),
                QStringLiteral("规则组输入无效：%1（%2）")
                .arg(fieldState->labelText)
                .arg(token));
            return;
        }

        if (!fieldState->valueList.contains(normalizedText, Qt::CaseInsensitive))
        {
            fieldState->valueList.push_back(normalizedText);
        }
    }

    fieldState->inputEdit->clear();
    refreshTextTableForGroup(groupId, fieldKind);
    applyMonitorFilters();
}

void NetworkDock::removeTextFilterItem(const int groupId, const MonitorTextRuleFieldKind fieldKind, const int itemIndex)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
    if (fieldState == nullptr || itemIndex < 0 || itemIndex >= fieldState->valueList.size())
    {
        return;
    }

    fieldState->valueList.removeAt(itemIndex);
    refreshTextTableForGroup(groupId, fieldKind);
    applyMonitorFilters();
}

void NetworkDock::clearTextFilterItems(const int groupId, const MonitorTextRuleFieldKind fieldKind)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
    if (fieldState == nullptr)
    {
        return;
    }

    fieldState->valueList.clear();
    refreshTextTableForGroup(groupId, fieldKind);
    applyMonitorFilters();
}

void NetworkDock::clearAllMonitorFilterConfigurations()
{
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : m_monitorFilterRuleGroupUiList)
    {
        if (groupState != nullptr && groupState->containerWidget != nullptr)
        {
            delete groupState->containerWidget;
        }
    }

    m_monitorFilterRuleGroupUiList.clear();
    m_monitorFilterNextGroupId = 1;
    addMonitorFilterRuleGroup();
    rebuildMonitorFilterRuleGroupUi();
    resetPacketTimelineToCurrentRange();
    applyMonitorFilters();
}

void NetworkDock::addOrTrackProcessPid(const std::uint32_t pidValue)
{
    if (pidValue == 0)
    {
        return;
    }

    if (m_monitorFilterRuleGroupUiList.empty())
    {
        addMonitorFilterRuleGroup();
    }

    MonitorFilterRuleGroupUiState* groupState = m_monitorFilterRuleGroupUiList.empty()
        ? nullptr
        : m_monitorFilterRuleGroupUiList.front().get();
    if (groupState == nullptr)
    {
        return;
    }

    const bool existed = std::any_of(
        groupState->processTargetList.begin(),
        groupState->processTargetList.end(),
        [pidValue](const MonitorProcessTarget& target)
        {
            return target.pid == pidValue;
        });
    if (!existed)
    {
        refreshMonitorProcessCandidateList(true);

        MonitorProcessTarget target;
        target.pid = pidValue;
        target.processName = toQString(ks::process::GetProcessNameByPID(pidValue)).trimmed();
        if (target.processName.isEmpty())
        {
            target.processName = QStringLiteral("PID_%1").arg(pidValue);
        }
        target.processIcon = resolveProcessIconByPid(pidValue, target.processName.toStdString());
        groupState->processTargetList.push_back(std::move(target));
        refreshProcessTableForGroup(groupState->groupId);
    }

    if (groupState->enabledCheck != nullptr)
    {
        groupState->enabledCheck->setChecked(true);
    }

    applyMonitorFilters();
}

bool NetworkDock::tryCompileMonitorFilterGroups(
    std::vector<MonitorFilterRuleGroupCompiled>& compiledGroupsOut,
    QString& errorTextOut) const
{
    compiledGroupsOut.clear();
    errorTextOut.clear();

    int displayIndex = 1;
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : m_monitorFilterRuleGroupUiList)
    {
        if (groupState == nullptr)
        {
            continue;
        }

        const bool enabled = (groupState->enabledCheck == nullptr) ? true : groupState->enabledCheck->isChecked();
        if (!enabled)
        {
            ++displayIndex;
            continue;
        }

        MonitorFilterRuleGroupCompiled compiledGroup;
        compiledGroup.groupId = groupState->groupId;
        compiledGroup.enabled = true;

        for (const MonitorProcessTarget& target : groupState->processTargetList)
        {
            if (target.pid != 0)
            {
                compiledGroup.processIdList.push_back(target.pid);
            }
        }

        const auto parseFieldList = [&](const MonitorTextRuleFieldKind fieldKind) -> bool
            {
                const MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
                if (fieldState == nullptr)
                {
                    return true;
                }

                for (const QString& ruleText : fieldState->valueList)
                {
                    if (fieldKind == MonitorTextRuleFieldKind::LocalAddress ||
                        fieldKind == MonitorTextRuleFieldKind::RemoteAddress)
                    {
                        UInt32Range range{};
                        QString normalizedText;
                        if (!tryParseIpv4RangeText(ruleText, range, normalizedText))
                        {
                            errorTextOut = QStringLiteral("规则组%1 中 %2 条目无效：%3")
                                .arg(displayIndex)
                                .arg(fieldState->labelText)
                                .arg(ruleText);
                            return false;
                        }
                        if (fieldKind == MonitorTextRuleFieldKind::LocalAddress)
                        {
                            compiledGroup.localAddressRangeList.push_back(range);
                        }
                        else
                        {
                            compiledGroup.remoteAddressRangeList.push_back(range);
                        }
                    }
                    else if (fieldKind == MonitorTextRuleFieldKind::LocalPort ||
                        fieldKind == MonitorTextRuleFieldKind::RemotePort)
                    {
                        UInt16Range range{};
                        QString normalizedText;
                        if (!tryParsePortRangeText(ruleText, range, normalizedText))
                        {
                            errorTextOut = QStringLiteral("规则组%1 中 %2 条目无效：%3")
                                .arg(displayIndex)
                                .arg(fieldState->labelText)
                                .arg(ruleText);
                            return false;
                        }
                        if (fieldKind == MonitorTextRuleFieldKind::LocalPort)
                        {
                            compiledGroup.localPortRangeList.push_back(range);
                        }
                        else
                        {
                            compiledGroup.remotePortRangeList.push_back(range);
                        }
                    }
                    else
                    {
                        UInt32Range range{};
                        QString normalizedText;
                        if (!tryParsePacketSizeToken(ruleText, range, normalizedText))
                        {
                            errorTextOut = QStringLiteral("规则组%1 中 %2 条目无效：%3")
                                .arg(displayIndex)
                                .arg(fieldState->labelText)
                                .arg(ruleText);
                            return false;
                        }
                        compiledGroup.packetSizeRangeList.push_back(range);
                    }
                }

                return true;
            };

        if (!parseFieldList(MonitorTextRuleFieldKind::LocalAddress) ||
            !parseFieldList(MonitorTextRuleFieldKind::RemoteAddress) ||
            !parseFieldList(MonitorTextRuleFieldKind::LocalPort) ||
            !parseFieldList(MonitorTextRuleFieldKind::RemotePort) ||
            !parseFieldList(MonitorTextRuleFieldKind::PacketSize))
        {
            return false;
        }

        if (compiledGroup.hasAnyCondition())
        {
            compiledGroupsOut.push_back(std::move(compiledGroup));
        }

        ++displayIndex;
    }

    return true;
}

void NetworkDock::applyMonitorFilters()
{
    std::vector<MonitorFilterRuleGroupCompiled> compiledGroupList;
    QString compileErrorText;
    if (!tryCompileMonitorFilterGroups(compiledGroupList, compileErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("流量筛选"), compileErrorText);
        return;
    }

    m_activeMonitorFilterGroupList = std::move(compiledGroupList);

    updateMonitorFilterStateLabel();
    rebuildMonitorTableByFilter();

    kLogEvent filterApplyEvent;
    info << filterApplyEvent
        << "[NetworkDock] 应用规则组过滤, activeGroupCount="
        << m_activeMonitorFilterGroupList.size()
        << eol;
}

void NetworkDock::clearMonitorFilters()
{
    clearAllMonitorFilterConfigurations();

    kLogEvent clearFilterEvent;
    info << clearFilterEvent << "[NetworkDock] 已清空全部流量筛选条件。" << eol;
}

void NetworkDock::updateMonitorFilterStateLabel()
{
    if (m_monitorFilterStateLabel == nullptr)
    {
        return;
    }

    const bool timelineFilterActive = isPacketTimelineFilterActive();
    if (m_activeMonitorFilterGroupList.empty())
    {
        m_monitorFilterStateLabel->setText(timelineFilterActive
            ? QStringLiteral("当前过滤：时间轴已筛选")
            : QStringLiteral("当前过滤：无"));
        return;
    }

    QStringList groupSummaryList;
    groupSummaryList.reserve(static_cast<int>(m_activeMonitorFilterGroupList.size()));
    int displayIndex = 1;
    for (const MonitorFilterRuleGroupCompiled& groupFilter : m_activeMonitorFilterGroupList)
    {
        QStringList conditionList;
        if (!groupFilter.processIdList.empty())
        {
            conditionList.push_back(QStringLiteral("进程%1项").arg(groupFilter.processIdList.size()));
        }
        if (!groupFilter.localAddressRangeList.empty())
        {
            conditionList.push_back(QStringLiteral("本地地址%1项").arg(groupFilter.localAddressRangeList.size()));
        }
        if (!groupFilter.remoteAddressRangeList.empty())
        {
            conditionList.push_back(QStringLiteral("远程地址%1项").arg(groupFilter.remoteAddressRangeList.size()));
        }
        if (!groupFilter.localPortRangeList.empty())
        {
            conditionList.push_back(QStringLiteral("本地端口%1项").arg(groupFilter.localPortRangeList.size()));
        }
        if (!groupFilter.remotePortRangeList.empty())
        {
            conditionList.push_back(QStringLiteral("远程端口%1项").arg(groupFilter.remotePortRangeList.size()));
        }
        if (!groupFilter.packetSizeRangeList.empty())
        {
            conditionList.push_back(QStringLiteral("包长%1项").arg(groupFilter.packetSizeRangeList.size()));
        }

        groupSummaryList.push_back(QStringLiteral("规则组%1[%2]")
            .arg(displayIndex)
            .arg(conditionList.join(QStringLiteral(" | "))));
        ++displayIndex;
    }

    QString summaryText = QStringLiteral("当前过滤：%1").arg(groupSummaryList.join(QStringLiteral("  OR  ")));
    if (timelineFilterActive)
    {
        // 时间轴是独立于规则组的外层时间窗口，这里追加提示，避免用户误以为只剩规则组过滤。
        summaryText += QStringLiteral(" | 时间轴已筛选");
    }
    m_monitorFilterStateLabel->setText(summaryText);
}

bool NetworkDock::packetMatchesMonitorFilterGroup(
    const ks::network::PacketRecord& packetRecord,
    const MonitorFilterRuleGroupCompiled& groupFilter) const
{
    if (!groupFilter.processIdList.empty())
    {
        const bool processMatched = std::find(
            groupFilter.processIdList.begin(),
            groupFilter.processIdList.end(),
            packetRecord.processId) != groupFilter.processIdList.end();
        if (!processMatched)
        {
            return false;
        }
    }

    if (!groupFilter.localAddressRangeList.empty())
    {
        std::uint32_t localIpHostOrder = 0;
        if (!tryParseIpv4Text(toQString(packetRecord.localAddress), localIpHostOrder))
        {
            return false;
        }

        const bool matched = std::any_of(
            groupFilter.localAddressRangeList.begin(),
            groupFilter.localAddressRangeList.end(),
            [localIpHostOrder](const UInt32Range& range)
            {
                return localIpHostOrder >= range.first && localIpHostOrder <= range.second;
            });
        if (!matched)
        {
            return false;
        }
    }

    if (!groupFilter.remoteAddressRangeList.empty())
    {
        std::uint32_t remoteIpHostOrder = 0;
        if (!tryParseIpv4Text(toQString(packetRecord.remoteAddress), remoteIpHostOrder))
        {
            return false;
        }

        const bool matched = std::any_of(
            groupFilter.remoteAddressRangeList.begin(),
            groupFilter.remoteAddressRangeList.end(),
            [remoteIpHostOrder](const UInt32Range& range)
            {
                return remoteIpHostOrder >= range.first && remoteIpHostOrder <= range.second;
            });
        if (!matched)
        {
            return false;
        }
    }

    if (!groupFilter.localPortRangeList.empty())
    {
        const bool matched = std::any_of(
            groupFilter.localPortRangeList.begin(),
            groupFilter.localPortRangeList.end(),
            [localPort = packetRecord.localPort](const UInt16Range& range)
            {
                return localPort >= range.first && localPort <= range.second;
            });
        if (!matched)
        {
            return false;
        }
    }

    if (!groupFilter.remotePortRangeList.empty())
    {
        const bool matched = std::any_of(
            groupFilter.remotePortRangeList.begin(),
            groupFilter.remotePortRangeList.end(),
            [remotePort = packetRecord.remotePort](const UInt16Range& range)
            {
                return remotePort >= range.first && remotePort <= range.second;
            });
        if (!matched)
        {
            return false;
        }
    }

    if (!groupFilter.packetSizeRangeList.empty())
    {
        const bool matched = std::any_of(
            groupFilter.packetSizeRangeList.begin(),
            groupFilter.packetSizeRangeList.end(),
            [packetSize = packetRecord.totalPacketSize](const UInt32Range& range)
            {
                return packetSize >= range.first && packetSize <= range.second;
            });
        if (!matched)
        {
            return false;
        }
    }

    return true;
}

bool NetworkDock::saveMonitorFilterConfigToPath(const QString& filePath, const bool showErrorDialog) const
{
    const QString normalizedPath = QFileInfo(filePath).absoluteFilePath();
    if (normalizedPath.trimmed().isEmpty())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(nullptr, QStringLiteral("流量筛选"), QStringLiteral("配置保存路径无效。"));
        }
        return false;
    }

    QJsonObject rootObject;
    rootObject.insert(QString::fromLatin1(kMonitorFilterJsonVersionKey), 1);

    QJsonArray groupsArray;
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : m_monitorFilterRuleGroupUiList)
    {
        if (groupState == nullptr)
        {
            continue;
        }

        QJsonObject groupObject;
        groupObject.insert(
            QString::fromLatin1(kMonitorFilterJsonEnabledKey),
            (groupState->enabledCheck == nullptr) ? true : groupState->enabledCheck->isChecked());

        QJsonArray processArray;
        for (const MonitorProcessTarget& target : groupState->processTargetList)
        {
            if (target.pid == 0)
            {
                continue;
            }

            QJsonObject processObject;
            processObject.insert(QString::fromLatin1(kMonitorFilterJsonPidKey), static_cast<qint64>(target.pid));
            processObject.insert(QString::fromLatin1(kMonitorFilterJsonProcessNameKey), target.processName);
            processArray.push_back(processObject);
        }
        groupObject.insert(QString::fromLatin1(kMonitorFilterJsonProcessesKey), processArray);

        const auto appendTextFieldArray = [this, &groupObject, &groupState](
            const MonitorTextRuleFieldKind fieldKind,
            const char* jsonKey)
            {
                const MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
                QJsonArray array;
                if (fieldState != nullptr)
                {
                    for (const QString& text : fieldState->valueList)
                    {
                        array.push_back(text);
                    }
                }
                groupObject.insert(QString::fromLatin1(jsonKey), array);
            };

        appendTextFieldArray(MonitorTextRuleFieldKind::LocalAddress, kMonitorFilterJsonLocalAddressesKey);
        appendTextFieldArray(MonitorTextRuleFieldKind::RemoteAddress, kMonitorFilterJsonRemoteAddressesKey);
        appendTextFieldArray(MonitorTextRuleFieldKind::LocalPort, kMonitorFilterJsonLocalPortsKey);
        appendTextFieldArray(MonitorTextRuleFieldKind::RemotePort, kMonitorFilterJsonRemotePortsKey);
        appendTextFieldArray(MonitorTextRuleFieldKind::PacketSize, kMonitorFilterJsonPacketSizesKey);

        groupsArray.push_back(groupObject);
    }

    rootObject.insert(QString::fromLatin1(kMonitorFilterJsonGroupsKey), groupsArray);

    const QFileInfo fileInfo(normalizedPath);
    QDir outputDirectory(fileInfo.absolutePath());
    if (!outputDirectory.exists() && !outputDirectory.mkpath(QStringLiteral(".")))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(
                nullptr,
                QStringLiteral("流量筛选"),
                QStringLiteral("创建配置目录失败：%1").arg(outputDirectory.absolutePath()));
        }
        return false;
    }

    QFile outputFile(normalizedPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(
                nullptr,
                QStringLiteral("流量筛选"),
                QStringLiteral("打开配置文件失败：%1").arg(normalizedPath));
        }
        return false;
    }

    outputFile.write(QJsonDocument(rootObject).toJson(QJsonDocument::Indented));
    outputFile.close();

    return true;
}

bool NetworkDock::loadMonitorFilterConfigFromPath(const QString& filePath, const bool showErrorDialog)
{
    const QString normalizedPath = QFileInfo(filePath).absoluteFilePath();
    QFile inputFile(normalizedPath);
    if (!inputFile.exists())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("流量筛选"), QStringLiteral("配置文件不存在：%1").arg(normalizedPath));
        }
        return false;
    }

    if (!inputFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("流量筛选"), QStringLiteral("读取配置文件失败：%1").arg(normalizedPath));
        }
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument jsonDocument = QJsonDocument::fromJson(inputFile.readAll(), &parseError);
    inputFile.close();

    if (parseError.error != QJsonParseError::NoError || !jsonDocument.isObject())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("流量筛选"), QStringLiteral("配置文件格式无效：%1").arg(normalizedPath));
        }
        return false;
    }

    const QJsonObject rootObject = jsonDocument.object();
    const QJsonArray groupArray = rootObject.value(QString::fromLatin1(kMonitorFilterJsonGroupsKey)).toArray();

    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : m_monitorFilterRuleGroupUiList)
    {
        if (groupState != nullptr && groupState->containerWidget != nullptr)
        {
            delete groupState->containerWidget;
        }
    }
    m_monitorFilterRuleGroupUiList.clear();
    m_monitorFilterNextGroupId = 1;

    if (groupArray.isEmpty())
    {
        addMonitorFilterRuleGroup();
        applyMonitorFilters();
        return true;
    }

    for (const QJsonValue& groupValue : groupArray)
    {
        if (!groupValue.isObject())
        {
            continue;
        }

        addMonitorFilterRuleGroup();
        MonitorFilterRuleGroupUiState* groupState = m_monitorFilterRuleGroupUiList.back().get();
        if (groupState == nullptr)
        {
            continue;
        }

        const QJsonObject groupObject = groupValue.toObject();
        if (groupState->enabledCheck != nullptr)
        {
            const QSignalBlocker blocker(groupState->enabledCheck);
            groupState->enabledCheck->setChecked(groupObject.value(QString::fromLatin1(kMonitorFilterJsonEnabledKey)).toBool(true));
        }

        groupState->processTargetList.clear();
        const QJsonArray processArray = groupObject.value(QString::fromLatin1(kMonitorFilterJsonProcessesKey)).toArray();
        for (const QJsonValue& processValue : processArray)
        {
            if (!processValue.isObject())
            {
                continue;
            }

            const QJsonObject processObject = processValue.toObject();
            const std::uint32_t pid = static_cast<std::uint32_t>(
                processObject.value(QString::fromLatin1(kMonitorFilterJsonPidKey)).toVariant().toULongLong());
            if (pid == 0)
            {
                continue;
            }

            MonitorProcessTarget target;
            target.pid = pid;
            target.processName = processObject.value(QString::fromLatin1(kMonitorFilterJsonProcessNameKey)).toString().trimmed();
            if (target.processName.isEmpty())
            {
                target.processName = toQString(ks::process::GetProcessNameByPID(pid));
            }
            if (target.processName.isEmpty())
            {
                target.processName = QStringLiteral("PID_%1").arg(pid);
            }
            target.processIcon = resolveProcessIconByPid(pid, target.processName.toStdString());
            groupState->processTargetList.push_back(std::move(target));
        }

        const auto loadTextField = [this, &groupObject, groupState](
            const MonitorTextRuleFieldKind fieldKind,
            const char* jsonKey)
            {
                MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
                if (fieldState == nullptr)
                {
                    return;
                }

                fieldState->valueList.clear();
                const QStringList rawList = jsonArrayToStringList(groupObject.value(QString::fromLatin1(jsonKey)));
                for (const QString& token : rawList)
                {
                    QString normalizedText;
                    bool parseOk = false;

                    if (fieldKind == MonitorTextRuleFieldKind::LocalAddress ||
                        fieldKind == MonitorTextRuleFieldKind::RemoteAddress)
                    {
                        UInt32Range range{};
                        parseOk = tryParseIpv4RangeText(token, range, normalizedText);
                    }
                    else if (fieldKind == MonitorTextRuleFieldKind::LocalPort ||
                        fieldKind == MonitorTextRuleFieldKind::RemotePort)
                    {
                        UInt16Range range{};
                        parseOk = tryParsePortRangeText(token, range, normalizedText);
                    }
                    else
                    {
                        UInt32Range range{};
                        parseOk = tryParsePacketSizeToken(token, range, normalizedText);
                    }

                    if (parseOk && !fieldState->valueList.contains(normalizedText, Qt::CaseInsensitive))
                    {
                        fieldState->valueList.push_back(normalizedText);
                    }
                }
            };

        loadTextField(MonitorTextRuleFieldKind::LocalAddress, kMonitorFilterJsonLocalAddressesKey);
        loadTextField(MonitorTextRuleFieldKind::RemoteAddress, kMonitorFilterJsonRemoteAddressesKey);
        loadTextField(MonitorTextRuleFieldKind::LocalPort, kMonitorFilterJsonLocalPortsKey);
        loadTextField(MonitorTextRuleFieldKind::RemotePort, kMonitorFilterJsonRemotePortsKey);
        loadTextField(MonitorTextRuleFieldKind::PacketSize, kMonitorFilterJsonPacketSizesKey);

        refreshProcessTableForGroup(groupState->groupId);
        refreshTextTableForGroup(groupState->groupId, MonitorTextRuleFieldKind::LocalAddress);
        refreshTextTableForGroup(groupState->groupId, MonitorTextRuleFieldKind::RemoteAddress);
        refreshTextTableForGroup(groupState->groupId, MonitorTextRuleFieldKind::LocalPort);
        refreshTextTableForGroup(groupState->groupId, MonitorTextRuleFieldKind::RemotePort);
        refreshTextTableForGroup(groupState->groupId, MonitorTextRuleFieldKind::PacketSize);
    }

    if (m_monitorFilterRuleGroupUiList.empty())
    {
        addMonitorFilterRuleGroup();
    }

    rebuildMonitorFilterRuleGroupUi();
    applyMonitorFilters();
    return true;
}

void NetworkDock::loadMonitorFilterConfigFromDefaultPath()
{
    const QString defaultPath = monitorFilterConfigPath();
    const bool loadedOk = loadMonitorFilterConfigFromPath(defaultPath, false);
    if (!loadedOk && m_monitorFilterRuleGroupUiList.empty())
    {
        addMonitorFilterRuleGroup();
        applyMonitorFilters();
    }
}

void NetworkDock::saveMonitorFilterConfigToDefaultPath() const
{
    const QString defaultPath = monitorFilterConfigPath();
    if (saveMonitorFilterConfigToPath(defaultPath, true))
    {
        QMessageBox::information(const_cast<NetworkDock*>(this),
            QStringLiteral("流量筛选"),
            QStringLiteral("筛选配置已保存到：%1").arg(defaultPath));
    }
}

void NetworkDock::importMonitorFilterConfigFromUserSelectedPath()
{
    const QString selectedPath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("导入流量筛选配置"),
        QFileInfo(monitorFilterConfigPath()).absolutePath(),
        QStringLiteral("Wireshark Config (*.cfg *.json);;All Files (*.*)"));
    if (selectedPath.trimmed().isEmpty())
    {
        return;
    }

    if (loadMonitorFilterConfigFromPath(selectedPath, true))
    {
        saveMonitorFilterConfigToPath(monitorFilterConfigPath(), false);
        QMessageBox::information(this,
            QStringLiteral("流量筛选"),
            QStringLiteral("已导入配置：%1").arg(QFileInfo(selectedPath).absoluteFilePath()));
    }
}

void NetworkDock::exportMonitorFilterConfigToUserSelectedPath() const
{
    const QString defaultPath = monitorFilterConfigPath();
    QWidget* parentWidget = const_cast<NetworkDock*>(this);
    const QString selectedPath = QFileDialog::getSaveFileName(
        parentWidget,
        QStringLiteral("导出流量筛选配置"),
        defaultPath,
        QStringLiteral("Wireshark Config (*.cfg);;JSON (*.json);;All Files (*.*)"));
    if (selectedPath.trimmed().isEmpty())
    {
        return;
    }

    if (saveMonitorFilterConfigToPath(selectedPath, true))
    {
        QMessageBox::information(parentWidget,
            QStringLiteral("流量筛选"),
            QStringLiteral("已导出配置：%1").arg(QFileInfo(selectedPath).absoluteFilePath()));
    }
}

void NetworkDock::trackProcessByTableRow(const int row)
{
    if (m_packetTable == nullptr || row < 0 || row >= m_packetTable->rowCount())
    {
        return;
    }

    QTableWidgetItem* pidItem = m_packetTable->item(row, toPacketColumn(PacketTableColumn::Pid));
    if (pidItem == nullptr)
    {
        return;
    }

    std::uint32_t targetPid = 0;
    if (!tryParsePidText(pidItem->text(), targetPid))
    {
        QMessageBox::information(this, QStringLiteral("跟踪进程"), QStringLiteral("该行 PID 无效，无法跟踪。"));
        return;
    }

    addOrTrackProcessPid(targetPid);

    kLogEvent trackEvent;
    info << trackEvent << "[NetworkDock] 跟踪此进程触发, pid=" << targetPid << eol;
}

void NetworkDock::gotoProcessDetailByTableRow(const int row)
{
    if (m_packetTable == nullptr || row < 0 || row >= m_packetTable->rowCount())
    {
        return;
    }

    QTableWidgetItem* pidItem = m_packetTable->item(row, toPacketColumn(PacketTableColumn::Pid));
    if (pidItem == nullptr)
    {
        return;
    }

    std::uint32_t targetPid = 0;
    if (!tryParsePidText(pidItem->text(), targetPid))
    {
        QMessageBox::information(this, QStringLiteral("进程详情"), QStringLiteral("该行 PID 无效，无法打开进程详情。"));
        return;
    }

    // 网络表跳转只创建轻量记录：
    // - 完整静态详情和签名校验放到 ProcessDetailWindow 后台执行；
    // - 避免右键菜单动作在 UI 线程等待进程令牌/证书链查询。
    ks::process::ProcessRecord processRecord;
    processRecord.pid = targetPid;
    processRecord.processName = ks::process::GetProcessNameByPID(targetPid);
    if (processRecord.processName.empty())
    {
        processRecord.processName = "PID_" + std::to_string(targetPid);
    }

    ProcessDetailWindow* detailWindow = new ProcessDetailWindow(processRecord, nullptr);
    detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
    detailWindow->setWindowFlag(Qt::Window, true);
    detailWindow->show();
    detailWindow->raise();
    detailWindow->activateWindow();

    kLogEvent processDetailEvent;
    info << processDetailEvent
        << "[NetworkDock] 打开进程详情窗口, pid=" << targetPid
        << eol;
}
