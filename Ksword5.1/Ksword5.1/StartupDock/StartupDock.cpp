#include "StartupDock.Internal.h"
#include "../UI/TableInteractionSupport.h"

using namespace startup_dock_detail;

StartupDock::StartupDock(QWidget* parent)
    : QWidget(parent)
{
    // 初始化顺序：
    // - 先创建 UI；
    // - 再连接交互；
    // - 启动项全量枚举改为“首次显示时懒加载”，避免拖慢主窗口启动。
    initializeUi();
    initializeConnections();

    kLogEvent initEvent;
    info << initEvent
        << startupText("startup.log.initialized", QStringLiteral("[StartupDock] 启动项页初始化完成。"))
               .toStdString()
        << eol;
}

StartupDock::~StartupDock()
{
    m_destroying.store(true);
    if (m_tableRebuildTimer != nullptr)
    {
        m_tableRebuildTimer->stop();
    }
    if (m_actionThread != nullptr && m_actionThread->joinable())
    {
        m_actionThread->join();
    }
    if (m_refreshThread != nullptr && m_refreshThread->joinable())
    {
        m_refreshThread->join();
    }
    if (m_refreshTimer != nullptr)
    {
        m_refreshTimer->stop();
    }

    kLogEvent destroyEvent;
    info << destroyEvent
        << startupText("startup.log.destroyed", QStringLiteral("[StartupDock] 启动项页已析构。"))
               .toStdString()
        << eol;
}

void StartupDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr || event->type() != QEvent::LanguageChange)
    {
        return;
    }

    applyTranslatedHeaders();
    rebuildAllTables();
    if (m_tableRebuildInProgress)
    {
        return;
    }
    if (m_statusLabel == nullptr)
    {
        return;
    }
    if (m_refreshInProgress.load())
    {
        m_statusLabel->setText(
            m_refreshQueued.load()
                ? startupText(
                    "startup.status.refresh_queued",
                    QStringLiteral("状态：后台刷新进行中，已记录新的刷新请求"))
                : startupText(
                    "startup.status.refreshing",
                    QStringLiteral("状态：后台正在枚举启动项...")));
    }
    else if (!m_initialRefreshDone)
    {
        m_statusLabel->setText(
            startupText(
                "startup.status.initial",
                QStringLiteral("状态：首次打开该页时加载启动项")));
    }
    else
    {
        m_statusLabel->setText(
            startupText(
                "startup.status.summary",
                QStringLiteral("状态：共 %1 条，当前分类 %2"))
                .arg(m_entryList.size())
                .arg(categoryToText(currentCategory())));
    }
}

int StartupDock::toStartupColumn(const StartupColumn column)
{
    return static_cast<int>(column);
}

QString StartupDock::categoryToText(const StartupCategory category)
{
    switch (category)
    {
    case StartupCategory::All:
        return startupText("startup.category.overview", QStringLiteral("总览"));
    case StartupCategory::Logon:
        return startupText("startup.category.logon", QStringLiteral("登录"));
    case StartupCategory::Services:
        return startupText("startup.category.services", QStringLiteral("服务"));
    case StartupCategory::Drivers:
        return startupText("startup.category.drivers", QStringLiteral("驱动"));
    case StartupCategory::Tasks:
        return startupText("startup.category.tasks", QStringLiteral("计划任务"));
    case StartupCategory::ImageHijack:
        return startupText("startup.category.image_hijack", QStringLiteral("映像劫持"));
    case StartupCategory::Registry:
        return startupText("startup.category.registry", QStringLiteral("高级注册表"));
    case StartupCategory::Wmi:
        return startupText("startup.category.wmi", QStringLiteral("WMI"));
    case StartupCategory::Hidden:
        return startupText("startup.category.hidden", QStringLiteral("隐藏项"));
    default:
        return startupText("startup.category.unknown", QStringLiteral("未知"));
    }
}

void StartupDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (m_initialRefreshDone)
    {
        return;
    }

    m_initialRefreshDone = true;
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(
            startupText("startup.status.first_load", QStringLiteral("状态：首次打开，正在加载启动项...")));
    }

    // 延迟到事件循环末尾再发起首次后台枚举：
    // - 先把页签本身显示出来，避免用户感知为“点击无响应”；
    // - 同时把重活移出主窗口构造阶段，优化启动速度。
    QTimer::singleShot(0, this, [this]()
        {
            requestAsyncRefresh(true);
        });
}

StartupDock::StartupCategory StartupDock::currentCategory() const
{
    if (m_sideTabWidget == nullptr)
    {
        return StartupCategory::All;
    }

    switch (m_sideTabWidget->currentIndex())
    {
    case 0:
        return StartupCategory::All;
    case 1:
        return StartupCategory::Logon;
    case 2:
        return StartupCategory::Services;
    case 3:
        return StartupCategory::Drivers;
    case 4:
        return StartupCategory::Tasks;
    case 5:
        return StartupCategory::ImageHijack;
    case 6:
        return StartupCategory::Registry;
    case 7:
        return StartupCategory::Wmi;
    case 8:
        return StartupCategory::Hidden;
    default:
        return StartupCategory::All;
    }
}

QTableWidget* StartupDock::currentCategoryTable() const
{
    switch (currentCategory())
    {
    case StartupCategory::All:
        return m_allTable;
    case StartupCategory::Logon:
        return m_logonTable;
    case StartupCategory::Services:
        return m_servicesTable;
    case StartupCategory::Drivers:
        return m_driversTable;
    case StartupCategory::Tasks:
        return m_tasksTable;
    case StartupCategory::ImageHijack:
        return m_imageHijackTable;
    case StartupCategory::Registry:
        return nullptr;
    case StartupCategory::Wmi:
        return m_wmiTable;
    case StartupCategory::Hidden:
        return m_hiddenTable;
    default:
        return m_allTable;
    }
}

QIcon StartupDock::resolveEntryIcon(const StartupEntry& entry)
{
    // 图标解析留在 UI 线程：
    // - 避免后台线程构造 QIcon / QFileIconProvider；
    // - 同一路径走缓存，降低表格重建开销。
    const QString cacheKeyText =
        entry.imagePathText.trimmed().isEmpty()
        ? QStringLiteral("type:%1").arg(entry.sourceTypeText)
        : QStringLiteral("path:%1").arg(QDir::toNativeSeparators(entry.imagePathText));

    const auto cacheIt = m_iconCache.constFind(cacheKeyText);
    if (cacheIt != m_iconCache.constEnd())
    {
        return cacheIt.value();
    }

    QIcon resolvedIcon;
    if (!entry.imagePathText.trimmed().isEmpty())
    {
        const QFileInfo fileInfo(entry.imagePathText);
        if (fileInfo.exists())
        {
            static QFileIconProvider fileIconProvider;
            resolvedIcon = fileIconProvider.icon(fileInfo);
        }
    }

    if (resolvedIcon.isNull())
    {
        if (entry.category == StartupCategory::Services)
        {
            resolvedIcon = createBlueIcon(":/Icon/process_start.svg");
        }
        else if (entry.category == StartupCategory::Drivers)
        {
            resolvedIcon = createBlueIcon(":/Icon/process_details.svg");
        }
        else if (entry.category == StartupCategory::Tasks)
        {
            resolvedIcon = createBlueIcon(":/Icon/process_refresh.svg");
        }
        else if (entry.category == StartupCategory::ImageHijack)
        {
            resolvedIcon = createBlueIcon(":/Icon/startup_image_hijack.svg");
        }
        else if (entry.category == StartupCategory::Registry)
        {
            resolvedIcon = createBlueIcon(":/Icon/file_find.svg");
        }
        else if (entry.category == StartupCategory::Hidden)
        {
            resolvedIcon = createBlueIcon(":/Icon/startup_hidden.svg");
        }
        else
        {
            resolvedIcon = createBlueIcon(":/Icon/process_main.svg");
        }
    }

    m_iconCache.insert(cacheKeyText, resolvedIcon);
    return resolvedIcon;
}

void StartupDock::requestAsyncRefresh(const bool forceRefresh)
{
    if (m_refreshInProgress)
    {
        if (forceRefresh)
        {
            m_refreshQueued = true;
        }
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(
                startupText(
                    "startup.status.refresh_queued",
                    QStringLiteral("状态：后台刷新进行中，已记录新的刷新请求")));
        }
        return;
    }

    if (m_refreshThread != nullptr && m_refreshThread->joinable())
    {
        m_refreshThread->join();
    }

    m_refreshInProgress = true;
    m_refreshQueued = false;
    m_pendingRefreshStageResults.clear();
    m_backendEnumerationCompleted = false;
    m_refreshSnapshotStarted = false;
    m_activeRefreshStageIndex = 0;
    m_activeRefreshStageCount = 0;
    m_activeRefreshStageEntryCount = 0;
    m_appliedRefreshStageCount = 0;
    m_progressPid = kPro.add(
        this,
        startupText("startup.progress.title", QStringLiteral("启动项")).toStdString(),
        startupText("startup.progress.enumerate", QStringLiteral("枚举自启动项")).toStdString());
    kPro.set(
        m_progressPid,
        startupText("startup.progress.prepare_logon", QStringLiteral("准备枚举登录项")).toStdString(),
        0,
        3.0f);
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(
            startupText("startup.status.refreshing", QStringLiteral("状态：后台正在枚举启动项...")));
    }

    const int progressPid = m_progressPid;
    // LanguageManager 的当前语言由 UI 线程切换。先在此处取得进度文案，
    // 避免后台枚举线程与语言切换并发访问翻译状态。
    const std::array<std::string, 9> enumerationProgressTexts{
        startupText("startup.progress.enumerate_logon", QStringLiteral("正在枚举登录项")).toStdString(),
        startupText("startup.progress.enumerate_services", QStringLiteral("正在枚举服务启动项")).toStdString(),
        startupText("startup.progress.enumerate_drivers", QStringLiteral("正在枚举驱动启动项")).toStdString(),
        startupText("startup.progress.enumerate_tasks", QStringLiteral("正在枚举计划任务")).toStdString(),
        startupText("startup.progress.enumerate_image_hijacks", QStringLiteral("正在检查映像劫持项")).toStdString(),
        startupText("startup.progress.enumerate_registry", QStringLiteral("正在枚举高级注册表启动项")).toStdString(),
        startupText("startup.progress.enumerate_winsock", QStringLiteral("正在枚举 Winsock 启动项")).toStdString(),
        startupText("startup.progress.enumerate_wmi", QStringLiteral("正在枚举 WMI 持久化项")).toStdString(),
        startupText("startup.progress.enumerate_hidden", QStringLiteral("正在交叉检查隐藏启动项")).toStdString()
    };
    const std::string backendCompletedProgressText = startupText(
        "startup.progress.backend_completed",
        QStringLiteral("ks::startup 后端枚举完成")).toStdString();
    m_refreshThread = std::make_unique<std::thread>(
        [this,
         progressPid,
         enumerationProgressTexts,
         backendCompletedProgressText]()
        {
            if (m_destroying.load())
            {
                return;
            }

            (void)ks::startup::EnumerateAllStartupEntries(
                [progressPid, &enumerationProgressTexts](
                    const ks::startup::StartupEnumerationStage,
                    const std::size_t stageIndex,
                    const std::size_t stageCount)
                {
                    constexpr std::array<float, 9> progressValues{
                        5.0f,
                        13.0f,
                        21.0f,
                        29.0f,
                        44.0f,
                        52.0f,
                        63.0f,
                        70.0f,
                        80.0f
                    };
                    if (stageIndex >= stageCount
                        || stageIndex >= enumerationProgressTexts.size()
                        || stageIndex >= progressValues.size())
                    {
                        return;
                    }
                    kPro.set(
                        progressPid,
                        enumerationProgressTexts[stageIndex],
                        0,
                        progressValues[stageIndex]);
                },
                [this](
                    const ks::startup::StartupEnumerationStage,
                    const std::size_t stageIndex,
                    const std::size_t stageCount,
                    const std::vector<ks::startup::StartupEntry>& backendStageEntries)
                {
                    if (m_destroying.load())
                    {
                        return;
                    }

                    std::vector<StartupEntry> stageEntryList;
                    stageEntryList.reserve(backendStageEntries.size());
                    appendBackendStartupEntries(&stageEntryList, backendStageEntries);
                    std::sort(
                        stageEntryList.begin(),
                        stageEntryList.end(),
                        [](const StartupEntry& left, const StartupEntry& right)
                        {
                            if (left.category != right.category)
                            {
                                return static_cast<int>(left.category) < static_cast<int>(right.category);
                            }
                            if (left.itemNameText.compare(right.itemNameText, Qt::CaseInsensitive) != 0)
                            {
                                return left.itemNameText.compare(right.itemNameText, Qt::CaseInsensitive) < 0;
                            }
                            return left.locationText.compare(right.locationText, Qt::CaseInsensitive) < 0;
                        });

                    QMetaObject::invokeMethod(
                        this,
                        [this,
                         stageIndex,
                         stageCount,
                         stageEntryList = std::move(stageEntryList)]() mutable
                        {
                            if (!m_destroying.load())
                            {
                                enqueueRefreshStageResult(
                                    stageIndex,
                                    stageCount,
                                    std::move(stageEntryList));
                            }
                        },
                        Qt::QueuedConnection);
                });
            kPro.set(
                progressPid,
                backendCompletedProgressText,
                0,
                93.0f);

            if (m_destroying.load())
            {
                return;
            }

            QMetaObject::invokeMethod(
                this,
                [this]()
                {
                    if (!m_destroying.load())
                    {
                        markBackendEnumerationCompleted();
                    }
                },
                Qt::QueuedConnection);
        });
}

void StartupDock::enqueueRefreshStageResult(
    const std::size_t stageIndex,
    const std::size_t stageCount,
    std::vector<StartupEntry> entryList)
{
    if (m_destroying.load()
        || !m_refreshInProgress.load()
        || stageCount == 0U
        || stageIndex >= stageCount)
    {
        return;
    }

    RefreshStageResult stageResult;
    stageResult.stageIndex = stageIndex;
    stageResult.stageCount = stageCount;
    stageResult.entryList = std::move(entryList);
    m_pendingRefreshStageResults.push_back(std::move(stageResult));
    processNextRefreshStageResult();
}

void StartupDock::processNextRefreshStageResult()
{
    if (m_destroying.load()
        || !m_refreshInProgress.load()
        || m_tableRebuildInProgress)
    {
        return;
    }

    if (m_pendingRefreshStageResults.empty())
    {
        if (m_backendEnumerationCompleted)
        {
            completeRefreshAfterUiCommit();
        }
        return;
    }

    const QList<QAbstractItemView*> startupViews = {
        m_allTable,
        m_logonTable,
        m_servicesTable,
        m_driversTable,
        m_tasksTable,
        m_imageHijackTable,
        m_wmiTable,
        m_hiddenTable,
        m_registryTree
    };
    if (ks::ui::IsItemViewUiCommitBlockedByContextMenu(startupViews))
    {
        // 八张分类表和注册表树共享同一 m_entryList 索引。菜单关闭后才能追加下一批，
        // 避免当前菜单持有的行索引在共享缓存切换时失效。
        const QPointer<StartupDock> safeThis(this);
        ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("startup-tables-stage-result-apply"),
            startupViews,
            [safeThis]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->processNextRefreshStageResult();
                }
            });
        return;
    }

    RefreshStageResult stageResult = std::move(m_pendingRefreshStageResults.front());
    m_pendingRefreshStageResults.pop_front();

    // 首批结果到达时才切换离开旧快照；之后每个后端阶段都只向累计结果追加。
    // 每批落表完成前不处理下一批，保证用户看到的顺序与后端枚举顺序一致。
    if (!m_refreshSnapshotStarted)
    {
        m_entryList.clear();
        m_refreshSnapshotStarted = true;
    }
    const std::size_t stageEntryCount = stageResult.entryList.size();
    m_entryList.reserve(m_entryList.size() + stageEntryCount);
    for (StartupEntry& entry : stageResult.entryList)
    {
        m_entryList.push_back(std::move(entry));
    }

    m_activeRefreshStageIndex = stageResult.stageIndex;
    m_activeRefreshStageCount = stageResult.stageCount;
    m_activeRefreshStageEntryCount = stageEntryCount;
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(
            startupText(
                "startup.status.applying_stage_results",
                QStringLiteral("状态：正在添加第 %1/%2 阶段结果，本阶段 %3 条..."))
                .arg(m_activeRefreshStageIndex + 1U)
                .arg(m_activeRefreshStageCount)
                .arg(stageEntryCount));
    }
    rebuildAllTables(true);
}

void StartupDock::markBackendEnumerationCompleted()
{
    if (m_destroying.load() || !m_refreshInProgress.load())
    {
        return;
    }

    m_backendEnumerationCompleted = true;
    processNextRefreshStageResult();
}

void StartupDock::completeRefreshAfterUiCommit()
{
    if (m_destroying.load()
        || !m_refreshInProgress.load()
        || !m_backendEnumerationCompleted
        || !m_pendingRefreshStageResults.empty()
        || m_tableRebuildInProgress)
    {
        return;
    }

    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(
            startupText("startup.status.summary", QStringLiteral("状态：共 %1 条，当前分类 %2"))
            .arg(m_entryList.size())
            .arg(categoryToText(currentCategory())));
    }

    const int completedProgressPid = m_progressPid;
    m_progressPid = 0;
    if (completedProgressPid != 0)
    {
        kPro.set(
            completedProgressPid,
            startupText("startup.progress.completed", QStringLiteral("启动项刷新完成")).toStdString(),
            0,
            100.0f);
    }

    m_refreshInProgress = false;

    kLogEvent refreshEvent;
    info << refreshEvent
        << startupText("startup.log.refresh.completed", QStringLiteral("[StartupDock] 后台刷新完成, count="))
               .toStdString()
        << m_entryList.size()
        << eol;

    if (m_refreshQueued)
    {
        requestAsyncRefresh(false);
    }
}
