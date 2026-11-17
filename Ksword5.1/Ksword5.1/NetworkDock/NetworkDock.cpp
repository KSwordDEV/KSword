#include "../Framework/BackgroundTaskRegistry.h"
#include "NetworkDock.NavigationData.h"
#include "../UI/ThemeBinding.h"
#include "../UI/AsyncUiDispatcher.h"
#include "NetworkDock.InternalCommon.h"
#include "HttpsProxyService.h"
#include "NetworkAuditPage.h"
#include "NetworkFirewallPage.h"
#include "../ArkDriverClient/ArkDriverClient.h"

#include <QMessageBox>
#include "../UI/AsyncOperation.h"
#include "../UI/RetainedCleanupJob.h"

bool network_dock_detail::TrafficCaptureLifetime::reserve()
{
    std::lock_guard<std::mutex> lock(gate);
    if (closing) return false;
    ++inFlight;
    return true;
}

void network_dock_detail::TrafficCaptureLifetime::release(
    const std::shared_ptr<ks::ui::RetainedCleanupJob>& job)
{
    { std::lock_guard<std::mutex> lock(gate); --inFlight; }
    if (job) job->notifyReadyToAttempt();
}

void network_dock_detail::TrafficCaptureLifetime::requestStop()
{
    std::lock_guard<std::mutex> lock(gate);
    closing = true;
    service->RequestStopCapture();
}

bool network_dock_detail::TrafficCaptureLifetime::ready()
{
    std::lock_guard<std::mutex> lock(gate);
    return closing && inFlight == 0;
}

bool network_dock_detail::TrafficCaptureLifetime::stopR0(QString* error, bool rememberFailure)
{
    if (!r0Touched.load()) return true;
    const ksword::ark::DriverClient driverClient;
    const auto stopped = driverClient.controlNetworkTrafficCapture(false);
    const bool confirmed = stopped.unsupported || (stopped.io.ok
        && stopped.response.status == KSWORD_ARK_NETWORK_STATUS_DISABLED
        && stopped.response.enabled == 0UL);
    if (confirmed) r0Touched.store(false);
    else
    {
        if (rememberFailure)
        {
            r0FailurePending = true;
            r0Failure = QString::fromStdString(stopped.io.message);
        }
        if (error) *error = QString::fromStdString(stopped.io.message);
        kLogEvent failure;
        warn << failure << "[NetworkDock] R0 逐包数据面停用失败: " << stopped.io.message << eol;
    }
    return confirmed;
}

bool network_dock_detail::TrafficCaptureLifetime::finish(QString* error)
{
    const bool r3Stopped = service->StopCapture();
    bool r0Stopped = false;
    if (r0FailurePending)
    {
        r0FailurePending = false;
        if (error) *error = r0Failure;
    }
    else r0Stopped = stopR0(error, false);
    const bool succeeded = r3Stopped && r0Stopped;
    finished.store(succeeded);
    return succeeded;
}

bool NetworkDock::ensureTrafficCaptureLifetime()
{
    if (m_trafficCleanup && !m_trafficCleanup->isComplete()
        && (!m_trafficLifetime || !m_trafficLifetime->finished.load()))
        return !m_trafficCleanup->isCleanupRequested();
    const auto lifetime = std::make_shared<network_dock_detail::TrafficCaptureLifetime>(m_trafficService);
    const auto dispatcher = m_trafficDispatcher;
    const auto completed = [this, lifetime](const QString& error, bool succeeded)
    {
        if (m_trafficLifetime != lifetime) return;
        m_monitorRunning = false;
        m_monitorSource = TrafficMonitorSource::Stopped;
        m_monitorStopInProgress.store(!succeeded);
        if (m_r0TrafficRefreshTimer) m_r0TrafficRefreshTimer->stop();
        if (m_packetTimelineSessionActive) endPacketTimelineMonitorSession();
        if (m_monitorStatusLabel)
            m_monitorStatusLabel->setText(!succeeded && error.isEmpty()
                ? QStringLiteral("状态：停止中，请稍候...") : error.isEmpty()
                ? QStringLiteral("状态：已停止")
                : QStringLiteral("状态：界面已停止，但 R0 数据面停用失败：%1").arg(error));
        updateMonitorButtonState();
    };
    const auto job = ks::ui::RetainedCleanupJob::create(
        [lifetime, dispatcher, completed]()
        {
            QString error;
            const bool succeeded = lifetime->finish(&error);
            if (succeeded)
            {
                kLogEvent stopFinishedEvent;
                info << stopFinishedEvent << "[NetworkDock] 后台停止流程完成，抓包线程已退出。" << eol;
            }
            dispatcher->post([completed, error, succeeded]() { completed(error, succeeded); });
            return succeeded;
        }, 0, [lifetime]() { lifetime->requestStop(); },
        [lifetime]() { return lifetime->ready(); });
    if (!job)
    {
        // create(null) can already own this old epoch's cleanup. Never reuse it.
        m_trafficService.reset();
        return false;
    }
    m_trafficLifetime = lifetime;
    m_trafficCleanup = job;
    return true;
}

// ============================================================
// NetworkDock.cpp
// 作用：
// 1) 保留 NetworkDock 构造/析构和后台回调接线；
// 2) 具体 UI 与业务函数分拆在各独立 .cpp；
// 3) 在不改变功能前提下替换旧的 .inc 聚合结构。
// ============================================================

NetworkDock::NetworkDock(QWidget* parent, const ConstructScope scope)
    : QWidget(parent), m_constructScope(scope)
{
    if (m_constructScope == ConstructScope::ProcessConnections)
    {
        initializeUi();
        setProcessDetailConnectionScope();
        return;
    }

    // 在任何网络页初始化和新代理应用之前，先恢复上次崩溃/强杀遗留的代理事务。
    bool recoveredPreviousProxy = false;
    QString recoveryErrorText;
    const bool recoveryOk = recoverPendingHttpsSystemProxyTransaction(
        &recoveredPreviousProxy,
        &recoveryErrorText);

    // 创建后台服务对象：负责抓包、PID 映射、限速逻辑。
    m_trafficService = std::make_shared<ks::network::TrafficMonitorService>();
    m_trafficDispatcher = std::make_shared<ks::ui::AsyncUiDispatcher>(this);
    // A startup recovery failure still owns the inherited durable transaction;
    // preserve the former destructor's restore attempt under an exit lease.
    if (m_httpsSystemProxySnapshotCaptured) (void)ensureHttpsProxyRecoveryCleanup();

    // 初始化界面和连接逻辑。
    initializeUi();
    loadMultiThreadDownloadCaptureSettings();
    initializeConnections();
    loadMonitorFilterConfigFromDefaultPath();

    if (recoveredPreviousProxy)
    {
        appendHttpsProxyLogLine(QStringLiteral(
            "检测到上次异常退出遗留的 HTTPS 系统代理，已自动恢复原配置。"));
        kLogEvent recoveryEvent;
        info << recoveryEvent
            << "[NetworkDock] 已从持久化事务恢复上次 HTTPS 系统代理配置。"
            << eol;
    }
    else if (!recoveryOk)
    {
        appendHttpsProxyLogLine(
            QStringLiteral("自动恢复上次 HTTPS 系统代理失败：%1")
                .arg(recoveryErrorText));
        kLogEvent recoveryEvent;
        warn << recoveryEvent
            << "[NetworkDock] 启动时恢复 HTTPS 系统代理失败："
            << recoveryErrorText
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("HTTPS 系统代理恢复失败"),
            QStringLiteral(
                "检测到未完成的 HTTPS 代理恢复事务，但自动恢复失败：\n%1\n\n"
                "在恢复成功前将禁止再次应用 HTTPS 系统代理，以免覆盖原始配置。")
                .arg(recoveryErrorText));
    }

    // “进程限速”页当前不暴露给用户，因此不创建该页专用的轮询刷新定时器。
    // 处理逻辑：
    // - 输入为空：无用户可见的限速页，不需要定时拉取规则快照；
    // - 处理：保持 m_rateLimitRefreshTimer 为 nullptr；
    // - 返回：构造函数继续初始化其它网络功能页。

    // 报文批量刷新定时器：
    // - 由 UI 线程周期性批量消费后台队列；
    // - 避免“每包一个 invokeMethod”把事件循环塞爆。
    m_packetFlushTimer = new QTimer(this);
    m_packetFlushTimer->setInterval(50);
    ks::ui::BackgroundTaskRegistry::Policy taskPolicy_network_packet_drain;
    taskPolicy_network_packet_drain.canPause = false;
    taskPolicy_network_packet_drain.canChangeInterval = false;
    taskPolicy_network_packet_drain.allowMultipleInstances = false;
    taskPolicy_network_packet_drain.minimumIntervalMs = 50;
    taskPolicy_network_packet_drain.restriction = QStringLiteral("此任务维持事件排空或窗口生命周期，请使用所属功能的停止入口。");
    ks::ui::BackgroundTaskRegistry::instance().addTimer(QStringLiteral("network.packet_drain"),
        QStringLiteral("报文队列排空"), QStringLiteral("网络"), m_packetFlushTimer, std::move(taskPolicy_network_packet_drain));
    connect(m_packetFlushTimer, &QTimer::timeout, this, [this]()
        {
            flushPendingPacketsToUi();
            synchronizeVisibleHttpsProjection();
        });
    m_packetFlushTimer->start();

    // R0 流量模式轮询：
    // - 仅在 R0 模式运行时按 sequence cursor 查询新增 WFP IPv4/IPv6 逐包记录；
    // - 查询失败会在 refreshR0TrafficSnapshotAsync 中无缝回退 R3；
    // - 独立“连接管理”页已移除，不再创建其旧轮询器。
    m_r0TrafficRefreshTimer = new QTimer(this);
    m_r0TrafficRefreshTimer->setInterval(250);
    ks::ui::BackgroundTaskRegistry::Policy taskPolicy_network_r0_traffic;
    taskPolicy_network_r0_traffic.canPause = false;
    taskPolicy_network_r0_traffic.canChangeInterval = false;
    taskPolicy_network_r0_traffic.allowMultipleInstances = false;
    taskPolicy_network_r0_traffic.minimumIntervalMs = 50;
    taskPolicy_network_r0_traffic.restriction = QStringLiteral("此任务维持事件排空或窗口生命周期，请使用所属功能的停止入口。");
    ks::ui::BackgroundTaskRegistry::instance().addTimer(QStringLiteral("network.r0_traffic"),
        QStringLiteral("内核流量采集"), QStringLiteral("网络"), m_r0TrafficRefreshTimer, std::move(taskPolicy_network_r0_traffic));
    connect(m_r0TrafficRefreshTimer, &QTimer::timeout, this, [this]()
        {
            if (!m_monitorRunning || m_monitorSource != TrafficMonitorSource::R0)
            {
                return;
            }
            refreshR0TrafficSnapshotAsync(m_monitorGeneration.load(), false);
        });

    // 多线程下载刷新定时器：
    // - 周期刷新任务表/分段表/总进度条；
    // - 下载后台独立运行；只有下载页实际可见时才构造任务表和分段表。
    m_multiDownloadRefreshTimer = new QTimer(this);
    m_multiDownloadRefreshTimer->setInterval(180);
    ks::ui::BackgroundTaskRegistry::Policy taskPolicy_network_download_view;
    taskPolicy_network_download_view.canPause = true;
    taskPolicy_network_download_view.canChangeInterval = true;
    taskPolicy_network_download_view.allowMultipleInstances = false;
    taskPolicy_network_download_view.minimumIntervalMs = 50;
    ks::ui::BackgroundTaskRegistry::instance().addTimer(QStringLiteral("network.download_view"),
        QStringLiteral("下载进度展示"), QStringLiteral("网络"), m_multiDownloadRefreshTimer, std::move(taskPolicy_network_download_view));
    connect(m_multiDownloadRefreshTimer, &QTimer::timeout, this, [this]()
        {
            if (!isVisible() || m_sideTabWidget == nullptr
                || m_sideTabWidget->currentWidget() != m_multiThreadDownloadPage)
            {
                return;
            }
            refreshMultiThreadDownloadUi();
        });
    m_multiDownloadRefreshTimer->start();

    // 把后台线程回调转发到 UI 线程，保证表格操作线程安全。
    m_trafficService->SetPacketCallback([mailbox = m_packetMailbox](const ks::network::PacketRecord& packetRecord)
        {
            // 抓包线程仅执行“入队”轻量动作，不直接碰 UI 控件。
            std::lock_guard<std::mutex> guard(mailbox->mutex);
            if (mailbox->closed) return;
            if (mailbox->packets.size() >= kMaxPendingPacketQueueCount)
            {
                // 队列满时丢弃最旧报文，保持系统持续可用。
                mailbox->packets.pop_front();
                ++mailbox->dropped;
            }
            mailbox->packets.push_back(packetRecord);
        });

    const auto deliverStatus = [this](const std::string& text) { onStatusMessageArrived(text); };
    m_trafficService->SetStatusCallback([dispatcher = m_trafficDispatcher, deliverStatus](const std::string& statusText)
        {
            dispatcher->post([deliverStatus, statusText]()
                {
                    deliverStatus(statusText);
                });
        });

    const auto deliverAction = [this](const ks::network::RateLimitActionEvent& event) { onRateLimitActionArrived(event); };
    m_trafficService->SetRateLimitActionCallback([dispatcher = m_trafficDispatcher, deliverAction](const ks::network::RateLimitActionEvent& actionEvent)
        {
            dispatcher->post([deliverAction, actionEvent]()
                {
                    deliverAction(actionEvent);
                });
        });

    // 初始化日志。
    kLogEvent initializeEvent;
    info << initializeEvent << "[NetworkDock] 网络面板初始化完成。" << eol;

}

NetworkDock::~NetworkDock()
{
    // A scoped audit host never owned capture/proxy/download services. In
    // particular its teardown must not disable the global driver's capture.
    if (m_constructScope == ConstructScope::ProcessConnections) return;
    retireHttpsProxyRecovery();
    if (m_trafficDispatcher) m_trafficDispatcher->close();
    { std::lock_guard<std::mutex> lock(m_packetMailbox->mutex); m_packetMailbox->closed = true; }
    if (m_trafficCleanup && !m_trafficCleanup->isCleanupRequested()) m_trafficCleanup->requestCleanup();
    ++m_packetTableProjection.generation;
    if (m_packetTableProjectionOperation != nullptr) m_packetTableProjectionOperation->close();
    if (m_packetTimelineProjectionOperation != nullptr) m_packetTimelineProjectionOperation->close();
    if (m_nidsIconOperation != nullptr) m_nidsIconOperation->close();
    if (m_nidsAnalysisOperation != nullptr) m_nidsAnalysisOperation->close();
    retireNidsAnalysisSession();
    // Detach the GUI consumer before any service teardown can deliver callbacks.
    if (m_httpsProxyService != nullptr)
    {
        m_httpsProxyService->setParsedCallback({});
    }
    if (m_multiDownloadDispatcher != nullptr)
    {
        m_multiDownloadDispatcher->close();
    }
    // Close delivery before member teardown; read workers only retain value state.
    if (m_routeReadOperation != nullptr) m_routeReadOperation->close();
    if (m_routeMutationOperation != nullptr) m_routeMutationOperation->close();
    if (m_arpReadOperation != nullptr) m_arpReadOperation->close();
    if (m_dnsReadOperation != nullptr) m_dnsReadOperation->close();
    m_monitorGeneration.fetch_add(1);
    m_monitorSource = TrafficMonitorSource::Stopped;
    if (m_r0TrafficRefreshTimer != nullptr)
    {
        m_r0TrafficRefreshTimer->stop();
    }

    // Close receiver borrowing before cancellation; remaining ICMP calls only
    // own copied targets, cancellation state and native handle lifetime.
    if (m_aliveScanDispatcher) m_aliveScanDispatcher->close();
    cancelAliveHostScan();

    // 析构前请求取消全部下载任务，避免窗口释放后继续长期下载。
    {
        std::lock_guard<std::mutex> guard(m_multiDownloadTaskMutex);
        for (const std::shared_ptr<MultiThreadDownloadTaskState>& taskState : m_multiDownloadTaskList)
        {
            if (taskState != nullptr)
            {
                taskState->canceled.store(true);
                taskState->cancelRequested.store(true);
                taskState->pauseRequested.store(false);
            }
        }
    }

    // The accepted capture epoch owns service/join/native STOP until completion.
    m_trafficService.reset();
    // The service closes its QObject listener here and transfers only its
    // existing independent session registry to bounded background cleanup.
    m_httpsProxyService.reset();

    if (!m_trafficLifetime || m_trafficLifetime->finished.load())
    {
        kLogEvent destroyEvent;
        info << destroyEvent << "[NetworkDock] 网络面板已析构，抓包线程已停止。" << eol;
    }
}

void NetworkDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (m_constructScope == ConstructScope::ProcessConnections)
    {
        if (m_networkAuditPage != nullptr) m_networkAuditPage->requestInitialRefresh();
        return;
    }
    const QPointer<NetworkDock> owner(this);
    ensureVisibleNetworkToolPage();
    if (!owner) return;
    QWidget* const currentPage = m_sideTabWidget ? m_sideTabWidget->currentWidget() : nullptr;
    if (currentPage == m_firewallTabPage && m_firewallPage) m_firewallPage->requestInitialRefresh();
    else if (currentPage == m_networkAuditTabPage && m_networkAuditPage) m_networkAuditPage->requestInitialRefresh();
    if (!owner) return;
    initializeVisibleDiagnosticPage();
    synchronizeVisiblePacketProjection();
    synchronizeVisibleNidsProjection();
    synchronizeVisibleHttpsProjection();

    if (m_httpsProxyServiceInitialized)
    {
        return;
    }

    m_httpsProxyServiceInitialized = true;
    m_httpsProxyService = std::make_unique<ks::network::HttpsMitmProxyService>();
    if (m_httpsProxyService != nullptr)
    {
        m_httpsProxyService->setParsedCallback([this](const ks::network::HttpsProxyParsedEntry& parsedEntry)
            {
                // The service dispatcher already delivers on this GUI thread.
                // A second queued hop copies the event and adds avoidable backlog.
                onHttpsProxyParsedEntryArrived(parsedEntry);
            });
        m_httpsProxyService->setStatusCallback([this](const QString& statusText)
            {
                QMetaObject::invokeMethod(this, [this, statusText]()
                    {
                        const QPointer<NetworkDock> owner(this);
                        appendHttpsProxyLogLine(statusText);
                        if (!owner) return;
                        if (!statusText.isEmpty())
                        {
                            if (m_httpsProxyService && !m_httpsProxyService->isRunning())
                                m_httpsProxyRunning = false;
                            updateHttpsProxyStatusLabel(statusText);
                        }
                    }, Qt::QueuedConnection);
            });
    }
}

void NetworkDock::registerNavigationTab(const QString& id, QTabWidget* tabs, QWidget* page)
{
    if (network_navigation_detail::Find(id) != nullptr && tabs != nullptr && page != nullptr)
        m_navigationTargets.insert(id, {tabs, page});
}

ks::ui::PageNavigationCatalog NetworkDock::navigationCatalog(const NetworkDock* existing)
{
    ks::ui::PageNavigationCatalog catalog;
    catalog.reserve(static_cast<int>(std::size(network_navigation_detail::Definitions)));
    for (const auto& definition : network_navigation_detail::Definitions)
    {
        ks::ui::PageNavigationDescriptor page;
        page.id = QString::fromLatin1(definition.id);
        page.parentId = QString::fromLatin1(definition.parent);
        page.title = network_navigation_detail::Title(definition);
        page.searchTexts = {QString::fromWCharArray(definition.sourceTitle), page.id};
        page.visible = definition.exposed;
        if (existing != nullptr)
        {
            auto target = existing->m_navigationTargets.constFind(page.id);
            bool inheritedColdHost = false;
            if (target == existing->m_navigationTargets.cend() || !target->tabs || !target->page)
            {
                // A cold descendant remains a real catalog entry. Resolve only
                // its existing shell's visibility; catalog reads never build UI.
                const auto* parent = network_navigation_detail::Find(page.parentId);
                while (parent != nullptr)
                {
                    const auto ancestor = existing->m_navigationTargets.constFind(QString::fromLatin1(parent->id));
                    if (ancestor != existing->m_navigationTargets.cend() && ancestor->tabs && ancestor->page
                        && existing->m_coldNetworkToolFactories.contains(ancestor->page))
                    {
                        target = ancestor;
                        inheritedColdHost = true;
                        break;
                    }
                    parent = network_navigation_detail::Find(QString::fromLatin1(parent->parent));
                }
            }
            if (target == existing->m_navigationTargets.cend() || !target->tabs || !target->page)
            {
                page.visible = false;
                page.enabled = false;
            }
            else
            {
                const int index = target->tabs->indexOf(target->page);
                page.visible = definition.exposed && index >= 0 && target->tabs->isTabVisible(index);
                page.enabled = definition.exposed && index >= 0 && target->tabs->isTabEnabled(index);
                page.current = !inheritedColdHost && index >= 0 && target->tabs->currentIndex() == index;
                if (!inheritedColdHost && index >= 0) page.title = target->tabs->tabText(index);
            }
        }
        catalog.push_back(std::move(page));
    }
    return catalog;
}

QWidget* NetworkDock::activateNavigationDescriptor(const QString& id)
{
    const QPointer<NetworkDock> guard(this);
    const auto* definition = network_navigation_detail::Find(id);
    if (definition == nullptr || !definition->exposed) return nullptr;
    QVector<QString> ids;
    while (definition != nullptr)
    {
        ids.prepend(QString::fromLatin1(definition->id));
        if (*definition->parent == '\0') definition = nullptr;
        else
        {
            definition = network_navigation_detail::Find(QString::fromLatin1(definition->parent));
            if (definition == nullptr || !definition->exposed) return nullptr;
        }
    }
    QVector<NavigationTarget> path;
    QPointer<QWidget> targetPage;
    for (const auto& targetId : ids)
    {
        if (!guard) return nullptr;
        // Resolve after the previous actual ancestor factory has registered its
        // children; never retain a QHash iterator through a factory callback.
        const auto found = m_navigationTargets.constFind(targetId);
        if (found == m_navigationTargets.cend()) return nullptr;
        const NavigationTarget target = *found;
        if (!guard || !target.tabs || !target.page) return nullptr;
        const int index = target.tabs->indexOf(target.page);
        if (index < 0 || !target.tabs->isTabVisible(index) || !target.tabs->isTabEnabled(index)) return nullptr;
        target.tabs->setCurrentWidget(target.page);
        if (!guard || !target.tabs || !target.page) return nullptr;
        if (!ensureNetworkToolPage(target.page) || !guard || !target.tabs || !target.page) return nullptr;
        ks::ui::PrepareWidgetThemeBindingsForShow(target.page);
        if (!guard || !target.tabs || !target.page || target.tabs->currentWidget() != target.page) return nullptr;
        path.push_back(target);
        targetPage = target.page;
    }
    for (const auto& target : path)
    {
        if (!guard || !target.tabs || !target.page) return nullptr;
        const int index = target.tabs->indexOf(target.page);
        if (index < 0 || !target.tabs->isTabVisible(index) || !target.tabs->isTabEnabled(index)
            || target.tabs->currentWidget() != target.page) return nullptr;
    }
    return guard ? targetPage.data() : nullptr;
}

namespace
{
    const bool kRegisterNetworkNavigationCatalog =
        ks::ui::RegisterTypedPageNavigationCatalog<NetworkDock>(QStringLiteral("network"));
}
