#include "NetworkDock.NavigationData.h"
#include "NetworkDock.InternalCommon.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/CodeTextEdit.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ThemeBinding.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/FlowLayout.h"
#include "NetworkFirewallPage.h"
#include "NetworkAuditPage.h"
#include "NetworkQosPage.h"
#include "./PortDiagnosticsPage.h"
#include "../Internationalization/LanguageManager.h"

#include <QFrame>
#include <QScrollArea>
#include <QSignalBlocker>

using namespace network_dock_detail;
void NetworkDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    // 根层只有一个导航控件，去除额外外边距，使网络与进程页签保持同一接缝。
    m_rootLayout->setContentsMargins(0, 0, 0, 0);
    m_rootLayout->setSpacing(0);

    // 顶部横排 Tab：
    // - 网络功能页签数量已较多，改成顶部横排后避免左侧竖排标签挤出纵向滚动条；
    // - 保留统一 QTabWidget 结构，不改变各功能页内部实现。
    m_sideTabWidget = new QTabWidget(this);
    // 网络主Tab直接占满方形工作区，页内连接/审计结果Tab不重复补外角。
    ks::ui::StyleSquarePageTabsFrame(m_sideTabWidget);
    m_sideTabWidget->setTabPosition(QTabWidget::North);
    m_sideTabWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_rootLayout->addWidget(m_sideTabWidget, 1);

    if (m_constructScope == ConstructScope::ProcessConnections)
    {
        initializeNetworkAuditTab();
        return;
    }
    initializeTrafficMonitorTab();
    // The process rate-limit page is intentionally not exposed in the UI.
    // Its current implementation throttles by suspending/resuming the whole
    // target process, which is too coarse for a user-facing network dock tab.
    // Keep initializeRateLimitTab() compiled for now so the backend/UI code can
    // be restored later if a cleaner enforcement model replaces it.
    // Canonical background capture/NIDS/download/proxy owners remain alive.
    // Every cold tab keeps one stable QWidget shell/index; first materialization
    // adds content to that shell before its diagnostic query or user action.
    const auto cold = [this](QWidget*& page, const QString& id, const QIcon& icon, std::function<void()> factory)
    {
        page = new QWidget(m_sideTabWidget);
        m_coldNetworkToolFactories.insert(page, std::move(factory));
        network_navigation_detail::AddTab(m_sideTabWidget, page, id, icon);
    };
    cold(m_nidsPage, QStringLiteral("nids"), QIcon(QStringLiteral(":/Icon/process_critical.svg")),
        [this]() { initializeNidsTab(); initializeNidsConnections(); });
    auto* qosPage = new QWidget(m_sideTabWidget);
    m_coldNetworkToolFactories.insert(qosPage, [qosPage] {
        auto* layout = new QVBoxLayout(qosPage); layout->setContentsMargins(0, 0, 0, 0);
        layout->addWidget(new NetworkQosPage(qosPage));
    });
    network_navigation_detail::AddTab(m_sideTabWidget, qosPage, QStringLiteral("qos"), QIcon(QStringLiteral(":/Icon/process_main.svg")));
    cold(m_firewallTabPage, QStringLiteral("firewall"), QIcon(QStringLiteral(":/Icon/process_critical.svg")),
        [this]() { initializeFirewallTab(); });
    cold(m_networkAuditTabPage, QStringLiteral("audit"), QIcon(QStringLiteral(":/Icon/process_details.svg")),
        [this]() { initializeNetworkAuditTab(); });
    QWidget* portPage = nullptr;
    cold(portPage, QStringLiteral("port-diagnostics"), QIcon(QStringLiteral(":/Icon/process_details.svg")), {});
    m_coldNetworkToolFactories[portPage] = [portPage]()
    {
        auto* layout = new QVBoxLayout(portPage);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->addWidget(new PortDiagnosticsPage(portPage));
    };
    cold(m_manualRequestPage, QStringLiteral("manual-request"), QIcon(QStringLiteral(":/Icon/process_main.svg")),
        [this]() { initializeManualRequestTab(); initializeManualRequestConnections(); });
    cold(m_multiThreadDownloadPage, QStringLiteral("download"), QIcon(QStringLiteral(":/Icon/process_start.svg")),
        [this]() { initializeMultiThreadDownloadTab(); initializeMultiThreadDownloadConnections(); });
    cold(m_httpsAnalyzePage, QStringLiteral("https"), QIcon(QStringLiteral(":/Icon/process_details.svg")),
        [this]() { initializeHttpsAnalyzeTab(); initializeHttpsAnalyzeConnections(); });
    cold(m_routeTablePage, QStringLiteral("route"), QIcon(QStringLiteral(":/Icon/process_tree.svg")), [this]() { initializeRouteTableTab(); });
    cold(m_arpCachePage, QStringLiteral("arp"), QIcon(QStringLiteral(":/Icon/process_tree.svg")), [this]() { initializeArpCacheTab(); initializeArpCacheConnections(); });
    cold(m_dnsCachePage, QStringLiteral("dns"), QIcon(QStringLiteral(":/Icon/process_list.svg")), [this]() { initializeDnsCacheTab(); initializeDnsCacheConnections(); });
    cold(m_aliveScanPage, QStringLiteral("alive-hosts"), QIcon(QStringLiteral(":/Icon/process_main.svg")), [this]() { initializeAliveHostScanTab(); initializeAliveHostScanConnections(); });
    cold(m_hostsFileEditorPage, QStringLiteral("hosts-editor"), QIcon(QStringLiteral(":/Icon/codeeditor_open.svg")), [this]() { initializeHostsFileEditorTab(); });
}

void NetworkDock::initializeTrafficMonitorTab()
{
    m_trafficMonitorPage = new QWidget(this);
    m_trafficMonitorLayout = new QVBoxLayout(m_trafficMonitorPage);
    m_trafficMonitorLayout->setContentsMargins(0, 0, 0, 0);
    m_trafficMonitorLayout->setSpacing(6);
    ks::ui::StyleWorkspacePage(m_trafficMonitorPage, 0);
    ks::ui::StyleWorkspaceContentFrame(m_trafficMonitorPage, 6);
    auto* workspace = new ks::ui::ParameterWorkspace(m_trafficMonitorPage, 480);
    m_trafficMonitorWorkspace = workspace;
    workspace->enableHorizontalParameterScroll();
    m_trafficMonitorLayout->addWidget(workspace, 1);

    // 采集与筛选属于一个操作区，使用两条紧凑行并与时间轴留出层次。
    QWidget* const captureToolbar = new QWidget(m_trafficMonitorPage);
    ks::ui::StylePrimaryToolbar(captureToolbar);
    QVBoxLayout* const captureToolbarLayout = new QVBoxLayout(captureToolbar);
    captureToolbarLayout->setContentsMargins(8, 4, 8, 4);
    captureToolbarLayout->setSpacing(8);
    m_monitorControlLayout = new QHBoxLayout();
    m_monitorControlLayout->setSpacing(6);

    m_startMonitorButton = new QPushButton(m_trafficMonitorPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_startMonitorButton, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_startMonitorButton, QIcon(":/Icon/process_start.svg"));
    m_startMonitorButton->setText(ks::i18n::sourceText(QStringLiteral("开始监控")));
    m_startMonitorButton->setToolTip(QStringLiteral("启动网络流量监控"));

    m_stopMonitorButton = new QPushButton(m_trafficMonitorPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_stopMonitorButton, ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_stopMonitorButton, QIcon(":/Icon/process_pause.svg"));
    m_stopMonitorButton->setText(ks::i18n::sourceText(QStringLiteral("停止监控")));
    m_stopMonitorButton->setToolTip(QStringLiteral("停止网络流量监控"));

    m_clearPacketButton = new QPushButton(m_trafficMonitorPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_clearPacketButton, ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_clearPacketButton, QIcon(":/Icon/log_clear.svg"));
    KswordTheme::ApplyCompactIconButtonMetrics(m_clearPacketButton);
    m_clearPacketButton->setToolTip(QStringLiteral("清空当前流量列表"));

    m_networkPluginButton = new QPushButton(QStringLiteral("插件"), m_trafficMonitorPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_networkPluginButton, ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_networkPluginButton, QIcon(":/Icon/process_start.svg"));
    m_networkPluginButton->setToolTip(QStringLiteral("运行声明支持网络目标的独立插件"));
    m_networkPluginMenu = new QMenu(m_networkPluginButton);
    m_networkPluginButton->setMenu(m_networkPluginMenu);

    m_monitorStatusLabel = new QLabel(QStringLiteral("状态：未启动"), m_trafficMonitorPage);
    // 状态标签不再设置较大最小宽度，避免窗口变窄时挤出横向滚动条。
    m_monitorStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    workspace->actions()->addWidget(m_startMonitorButton);
    workspace->actions()->addWidget(m_stopMonitorButton);
    m_monitorControlLayout->addWidget(m_clearPacketButton);
    m_clearTrafficFocusButton = new QPushButton(m_trafficMonitorPage);
    ks::i18n::LanguageManager::instance().bindText(m_clearTrafficFocusButton, QStringLiteral("network.traffic.scope.back"), QStringLiteral("返回规则组筛选"));
    m_clearTrafficFocusButton->setVisible(false);
    connect(m_clearTrafficFocusButton, &QPushButton::clicked, this, [this] {
        m_trafficFocusPid = 0; m_clearTrafficFocusButton->hide(); updateMonitorFilterStateLabel(); rebuildMonitorTableByFilter();
    });
    m_monitorControlLayout->addWidget(m_clearTrafficFocusButton);
    m_monitorControlLayout->addWidget(m_networkPluginButton);
    m_monitorControlLayout->addWidget(m_monitorStatusLabel);
    m_monitorControlLayout->addStretch(1);
    ks::ui::NormalizeToolbarRow(m_monitorControlLayout);

    captureToolbarLayout->addLayout(m_monitorControlLayout);

    // 新过滤标题栏：漏斗按钮 + 规则组管理 + 导入导出保存。
    m_monitorFilterHeaderLayout = new QHBoxLayout();
    m_monitorFilterHeaderLayout->setSpacing(6);

    m_monitorFilterToggleButton = new QPushButton(m_trafficMonitorPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_monitorFilterToggleButton, ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
    m_monitorFilterToggleButton->setCheckable(true);
    m_monitorFilterToggleButton->setChecked(true);
    ks::ui::SetThemeButtonIcon(m_monitorFilterToggleButton, QIcon(":/Icon/filter_funnel.svg"));
    KswordTheme::ApplyCompactIconButtonMetrics(m_monitorFilterToggleButton);
    m_monitorFilterToggleButton->setToolTip(QStringLiteral("展开/收起网络筛选器配置"));

    QLabel* filterTitleLabel = new QLabel(QStringLiteral("网络筛选器"), m_trafficMonitorPage);
    filterTitleLabel->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);
    ks::ui::StylePrimarySectionTitle(filterTitleLabel);

    m_addMonitorFilterGroupButton = new QPushButton(QStringLiteral("新增规则组"), m_trafficMonitorPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_addMonitorFilterGroupButton, ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_addMonitorFilterGroupButton, QIcon(":/Icon/plus.svg"));
    m_addMonitorFilterGroupButton->setToolTip(QStringLiteral("新增一个 OR 规则组"));

    m_applyMonitorFilterButton = new QPushButton(QStringLiteral("应用"), m_trafficMonitorPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_applyMonitorFilterButton, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_applyMonitorFilterButton, QIcon(":/Icon/log_track.svg"));
    m_applyMonitorFilterButton->setToolTip(QStringLiteral("应用当前全部规则组过滤条件"));

    m_saveMonitorFilterButton = new QPushButton(QStringLiteral("保存"), m_trafficMonitorPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_saveMonitorFilterButton, ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_saveMonitorFilterButton, QIcon(":/Icon/codeeditor_save.svg"));
    m_saveMonitorFilterButton->setToolTip(QStringLiteral("保存到 exe 目录下 config/wireshark.cfg"));

    m_importMonitorFilterButton = new QPushButton(QStringLiteral("导入"), m_trafficMonitorPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_importMonitorFilterButton, ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_importMonitorFilterButton, QIcon(":/Icon/codeeditor_open.svg"));
    m_importMonitorFilterButton->setToolTip(QStringLiteral("从配置文件导入规则组"));

    m_exportMonitorFilterButton = new QPushButton(QStringLiteral("导出"), m_trafficMonitorPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_exportMonitorFilterButton, ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_exportMonitorFilterButton, QIcon(":/Icon/log_export.svg"));
    m_exportMonitorFilterButton->setToolTip(QStringLiteral("导出当前规则组到配置文件"));

    m_clearMonitorFilterButton = new QPushButton(QStringLiteral("一键清空"), m_trafficMonitorPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_clearMonitorFilterButton, ks::ui::FlatButtonTone::Danger, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_clearMonitorFilterButton, QIcon(":/Icon/log_clear.svg"));
    m_clearMonitorFilterButton->setToolTip(QStringLiteral("清空全部规则组配置"));

    m_monitorFilterHeaderLayout->addWidget(m_monitorFilterToggleButton);
    m_monitorFilterHeaderLayout->addWidget(filterTitleLabel);
    m_monitorFilterHeaderLayout->addWidget(m_addMonitorFilterGroupButton);
    workspace->actions()->addWidget(m_applyMonitorFilterButton);
    ks::ui::NormalizeToolbarRow(workspace->actions());
    m_monitorFilterHeaderLayout->addStretch(1);
    ks::ui::NormalizeToolbarRow(m_monitorFilterHeaderLayout);
    workspace->parameterHeader()->addLayout(m_monitorFilterHeaderLayout);
    auto* filterFiles = new ks::ui::FlowLayout(nullptr, 0, 8, 6);
    for (auto* button : {m_saveMonitorFilterButton, m_importMonitorFilterButton, m_exportMonitorFilterButton, m_clearMonitorFilterButton}) {
        filterFiles->addWidget(button); ks::ui::NormalizeToolbarControl(button);
    }
    workspace->parameterHeader()->addLayout(filterFiles);
    workspace->results()->addWidget(captureToolbar);

    // 只有规则列进入同一个横纵滚动视口，管理动作与状态不随列滚走。
    m_monitorFilterPanel = new QWidget(m_trafficMonitorPage);
    m_monitorFilterPanel->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Maximum);
    m_monitorFilterGroupHostWidget = m_monitorFilterPanel;
    ks::ui::StyleParameterCanvas(m_monitorFilterGroupHostWidget);
    m_monitorFilterGroupHostLayout = new QHBoxLayout(m_monitorFilterGroupHostWidget);
    m_monitorFilterGroupHostLayout->setContentsMargins(0, 0, 0, 0);
    m_monitorFilterGroupHostLayout->setSpacing(16);
    m_monitorFilterGroupHostLayout->setSizeConstraint(QLayout::SetMinimumSize);

    m_monitorFilterStateLabel = new QLabel(QStringLiteral("当前过滤：无"), m_trafficMonitorPage);
    m_monitorFilterStateLabel->setWordWrap(true);
    m_monitorFilterStateLabel->setMinimumWidth(0);
    m_monitorFilterStateLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    workspace->parameterHeader()->addWidget(m_monitorFilterStateLabel);

    workspace->parameters()->addWidget(m_monitorFilterPanel);
    workspace->parameters()->addStretch();
    m_monitorFilterPanel->setVisible(true);

    addMonitorFilterRuleGroup();
    updateMonitorFilterStateLabel();

    // 流量时间轴：
    // - 复用 ETW 监控页下方的框选式时间轴控件，而不是进程页的“时间点滑块”；
    // - 用户可拖动矩形整体移动时间窗口，也可拖动左右边缘调整边界；
    // - 控件只负责时间选择，实际报文显示仍由 NetworkDock 的过滤链统一重建。
    m_packetTimelineWidget = new ProcessTraceTimelineWidget(m_trafficMonitorPage);
    m_packetTimelineWidget->setTracks(ks::ui::PacketTimelineTracks());
    m_packetTimelineWidget->setToolTip(QStringLiteral(
        "流量时间轴：横轴只统计监控开启时长，停机间隔不计入；绿色折线为上传速率，蓝色折线为下载速率；拖动矩形移动时间窗口，拖动左右边调整边界，滚轮向上放大窗口、向下缩小窗口。清空报文会重置时间轴。"));
    workspace->results()->addWidget(m_packetTimelineWidget, 0);

    // 报文主表：展示“全部发送 UDP/TCP 包”。
    m_packetTable = new PacketMonitorTable(m_trafficMonitorPage);
    // 报文是实时主证据，保留冻结、导出和快照对比。
    ks::ui::SetTableActionBarMode(m_packetTable, ks::ui::TableActionBarMode::Full);
    m_packetTable->setHorizontalHeaderLabels({
        QStringLiteral("时间"),
        QStringLiteral("协议"),
        QStringLiteral("方向"),
        QStringLiteral("来源"),
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点"),
        QStringLiteral("远端端点"),
        QStringLiteral("域名"),
        QStringLiteral("总长度"),
        QStringLiteral("负载"),
        QStringLiteral("内容预览")
        });
    m_packetTable->sortRequested = [this](int column, Qt::SortOrder order)
    {
        m_packetTableProjection.sortColumn = column;
        m_packetTableProjection.sortOrder = order;
        rebuildMonitorTableByFilter();
    };
    m_packetTable->processIcon = [this](quint32 pid)
    {
        const auto found = m_processIconCacheByPid.constFind(pid);
        static const QIcon placeholder(QStringLiteral(":/Icon/process_main.svg"));
        return found == m_processIconCacheByPid.constEnd() ? placeholder : found.value();
    };
    m_packetTable->requestMetadata = [this](std::uint64_t sequence)
    {
        const auto found = m_packetBySequence.find(sequence);
        if (isPacketProjectionVisible() && found != m_packetBySequence.end()) requestPacketMetadata(*found->second);
    };
    // Uniform natural row height avoids per-record section measurements during
    // an atomic batch insertion, including the final tail-follow layout.
    m_packetTable->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    m_packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    // 抓包列表改为支持多选，便于批量复制报文 ASCII / 十六进制内容。
    m_packetTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_packetTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_packetTable->verticalHeader()->setVisible(false);
    // 性能与自适应说明：
    // 1) 改为 Stretch，避免 ResizeToContents 在高频插入时反复全表测量导致卡顿；
    // 2) 不强制隐藏横向滚动条，后续由全局列宽自适应器压缩默认列宽。
    m_packetTable->horizontalHeader()->setStretchLastSection(true);
    m_packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    workspace->results()->addWidget(m_packetTable, 1);
    workspace->finish();
    network_navigation_detail::AddTab(m_sideTabWidget, m_trafficMonitorPage, QStringLiteral("traffic"), QIcon(":/Icon/process_main.svg"));

}

void NetworkDock::initializeRateLimitTab()
{
    m_rateLimitPage = new QWidget(this);
    m_rateLimitLayout = new QVBoxLayout(m_rateLimitPage);
    m_rateLimitLayout->setContentsMargins(6, 6, 6, 6);
    m_rateLimitLayout->setSpacing(6);

    // 控制栏：输入规则参数并管理规则。
    m_rateLimitControlLayout = new QHBoxLayout();
    m_rateLimitControlLayout->setSpacing(6);

    QLabel* pidLabel = new QLabel(QStringLiteral("PID:"), m_rateLimitPage);
    m_rateLimitPidEdit = new QLineEdit(m_rateLimitPage);
    m_rateLimitPidEdit->setPlaceholderText(QStringLiteral("进程 PID"));
    m_rateLimitPidEdit->setMaximumWidth(110);
    m_rateLimitPidEdit->setMinimumWidth(66);

    QLabel* kbpsLabel = new QLabel(QStringLiteral("限速KB/s:"), m_rateLimitPage);
    m_rateLimitKBpsSpin = new QSpinBox(m_rateLimitPage);
    m_rateLimitKBpsSpin->setRange(1, 1024 * 1024);
    m_rateLimitKBpsSpin->setValue(256);
    m_rateLimitKBpsSpin->setToolTip(QStringLiteral("每秒允许发送流量上限"));

    QLabel* suspendMsLabel = new QLabel(QStringLiteral("挂起时长ms:"), m_rateLimitPage);
    m_rateLimitSuspendMsSpin = new QSpinBox(m_rateLimitPage);
    m_rateLimitSuspendMsSpin->setRange(50, 2000);
    m_rateLimitSuspendMsSpin->setValue(250);
    m_rateLimitSuspendMsSpin->setToolTip(QStringLiteral("超限后挂起时长"));

    m_applyRateLimitButton = new QPushButton(m_rateLimitPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_applyRateLimitButton, ks::ui::FlatButtonTone::Accent);
    m_applyRateLimitButton->setIcon(QIcon(":/Icon/process_priority.svg"));
    m_applyRateLimitButton->setToolTip(QStringLiteral("新增或更新限速规则"));

    m_removeRateLimitButton = new QPushButton(m_rateLimitPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_removeRateLimitButton, ks::ui::FlatButtonTone::Danger);
    m_removeRateLimitButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_removeRateLimitButton->setToolTip(QStringLiteral("删除选中的限速规则"));

    m_clearRateLimitButton = new QPushButton(m_rateLimitPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_clearRateLimitButton, ks::ui::FlatButtonTone::Danger);
    m_clearRateLimitButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_clearRateLimitButton->setToolTip(QStringLiteral("清空全部限速规则"));

    m_rateLimitControlLayout->addWidget(pidLabel);
    m_rateLimitControlLayout->addWidget(m_rateLimitPidEdit);
    m_rateLimitControlLayout->addWidget(kbpsLabel);
    m_rateLimitControlLayout->addWidget(m_rateLimitKBpsSpin);
    m_rateLimitControlLayout->addWidget(suspendMsLabel);
    m_rateLimitControlLayout->addWidget(m_rateLimitSuspendMsSpin);
    m_rateLimitControlLayout->addWidget(m_applyRateLimitButton);
    m_rateLimitControlLayout->addWidget(m_removeRateLimitButton);
    m_rateLimitControlLayout->addWidget(m_clearRateLimitButton);
    m_rateLimitControlLayout->addStretch(1);
    ks::ui::NormalizeToolbarRow(m_rateLimitControlLayout);

    m_rateLimitLayout->addLayout(m_rateLimitControlLayout);

    // 规则表：展示 PID、阈值、触发计数、当前状态。
    m_rateLimitTable = new ks::ui::VisibleTableWidget(m_rateLimitPage);
    // 规则编辑表由页面自有动作管理，紧凑复制/导出即可。
    ks::ui::SetTableActionBarMode(m_rateLimitTable, ks::ui::TableActionBarMode::Compact);
    m_rateLimitTable->setColumnCount(toRateLimitColumn(RateLimitTableColumn::Count));
    m_rateLimitTable->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("限速KB/s"),
        QStringLiteral("挂起ms"),
        QStringLiteral("触发次数"),
        QStringLiteral("窗口字节"),
        QStringLiteral("状态")
        });
    m_rateLimitTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_rateLimitTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_rateLimitTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_rateLimitTable->verticalHeader()->setVisible(false);
    // 限速表也使用 Stretch，降低定时刷新时的 UI 重排开销。
    m_rateLimitTable->horizontalHeader()->setStretchLastSection(true);
    m_rateLimitTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    installCopyCurrentRowMenu(
        m_rateLimitTable,
        QStringLiteral("复制当前行"),
        toRateLimitColumn(RateLimitTableColumn::Pid));
    m_rateLimitLayout->addWidget(m_rateLimitTable, 1);

    // 限速动作日志：便于查看挂起/恢复执行结果。
    m_rateLimitLogOutput = new CodeTextEdit(m_rateLimitPage);
    static_cast<CodeTextEdit*>(m_rateLimitLogOutput)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
    m_rateLimitLogOutput->setReadOnly(true);
    m_rateLimitLogOutput->setMaximumBlockCount(400);
    // 日志框使用按控件宽度自动换行，避免窄窗口出现横向滚动条。
    m_rateLimitLogOutput->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    m_rateLimitLogOutput->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_rateLimitLogOutput->setPlaceholderText(QStringLiteral("限速动作日志将显示在这里..."));
    m_rateLimitLayout->addWidget(m_rateLimitLogOutput, 1);

    network_navigation_detail::AddTab(m_sideTabWidget, m_rateLimitPage, QStringLiteral("rate-limit"), QIcon(":/Icon/process_priority.svg"));

}

void NetworkDock::initializeConnectionManageTab()
{
    // 连接管理页职责：
    // 1) 展示 TCP 连接表；
    // 2) 展示 UDP 端点表；
    // 3) 提供终止 TCP 连接与刷新控制能力。
    m_connectionManagePage = new QWidget(this);
    m_connectionManageLayout = new QVBoxLayout(m_connectionManagePage);
    m_connectionManageLayout->setContentsMargins(6, 6, 6, 6);
    m_connectionManageLayout->setSpacing(6);

    // 顶部控制栏：手动刷新 / 自动刷新开关 / 终止连接按钮 / 状态标签。
    m_connectionControlLayout = new QHBoxLayout();
    m_connectionControlLayout->setSpacing(6);

    m_refreshConnectionButton = new QPushButton(m_connectionManagePage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_refreshConnectionButton, ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
    m_refreshConnectionButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_refreshConnectionButton->setToolTip(QStringLiteral("立即刷新 TCP/UDP 连接快照"));

    m_autoRefreshConnectionButton = new QPushButton(m_connectionManagePage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_autoRefreshConnectionButton, ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
    m_autoRefreshConnectionButton->setCheckable(true);
    m_autoRefreshConnectionButton->setChecked(true);
    m_autoRefreshConnectionButton->setIcon(QIcon(":/Icon/process_pause.svg"));
    m_autoRefreshConnectionButton->setToolTip(QStringLiteral("自动刷新已开启，点击暂停"));

    m_terminateTcpButton = new QPushButton(m_connectionManagePage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_terminateTcpButton, ks::ui::FlatButtonTone::Danger, ks::ui::FlatButtonAppearance::Solid);
    m_terminateTcpButton->setIcon(QIcon(":/Icon/process_terminate.svg"));
    m_terminateTcpButton->setToolTip(QStringLiteral("终止当前选中的 TCP 连接（DELETE_TCB）"));

    m_clearConnectionPidFilterButton = new QPushButton(m_connectionManagePage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_clearConnectionPidFilterButton, ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
    m_clearConnectionPidFilterButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_clearConnectionPidFilterButton->setToolTip(QStringLiteral("清除进程页跳转带入的 PID 筛选"));
    m_clearConnectionPidFilterButton->setEnabled(false);

    m_connectionStatusLabel = new QLabel(QStringLiteral("状态：等待刷新"), m_connectionManagePage);
    m_connectionStatusLabel->setWordWrap(true);
    m_connectionStatusLabel->setMinimumWidth(0);
    m_connectionStatusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);

    m_connectionControlLayout->addWidget(m_refreshConnectionButton);
    m_connectionControlLayout->addWidget(m_autoRefreshConnectionButton);
    m_connectionControlLayout->addWidget(m_terminateTcpButton);
    m_connectionControlLayout->addWidget(m_clearConnectionPidFilterButton);
    m_connectionControlLayout->addWidget(m_connectionStatusLabel, 1);
    m_connectionManageLayout->addLayout(m_connectionControlLayout);
    ks::ui::NormalizeToolbarRow(m_connectionControlLayout);

    // 子页签：分别展示 TCP 与 UDP。
    m_connectionSubTabWidget = new QTabWidget(m_connectionManagePage);
    ks::ui::StylePageTabsContentFrame(m_connectionSubTabWidget);
    m_connectionSubTabWidget->setTabPosition(QTabWidget::North);
    m_connectionSubTabWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_connectionManageLayout->addWidget(m_connectionSubTabWidget, 1);

    // TCP 表：状态、PID、进程、本地端点、远端端点。
    m_tcpConnectionTable = new ks::ui::VisibleTableWidget(m_connectionManagePage);
    ks::ui::SetTableActionBarMode(m_tcpConnectionTable, ks::ui::TableActionBarMode::Compact);
    m_tcpConnectionTable->setColumnCount(toTcpConnectionColumn(TcpConnectionTableColumn::Count));
    m_tcpConnectionTable->setHorizontalHeaderLabels({
        QStringLiteral("状态"),
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点"),
        QStringLiteral("远端端点")
        });
    m_tcpConnectionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tcpConnectionTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tcpConnectionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tcpConnectionTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_tcpConnectionTable->verticalHeader()->setVisible(false);
    m_tcpConnectionTable->horizontalHeader()->setStretchLastSection(true);
    m_tcpConnectionTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    network_navigation_detail::AddTab(m_connectionSubTabWidget, m_tcpConnectionTable, QStringLiteral("connections.tcp"), QIcon(":/Icon/process_main.svg"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_connectionSubTabWidget,
        m_tcpConnectionTable,
        QStringLiteral("network.tab.tcp"),
        QStringLiteral("TCP"));

    // UDP 表：PID、进程、本地端点。
    m_udpEndpointTable = new ks::ui::VisibleTableWidget(m_connectionManagePage);
    ks::ui::SetTableActionBarMode(m_udpEndpointTable, ks::ui::TableActionBarMode::Compact);
    m_udpEndpointTable->setColumnCount(toUdpEndpointColumn(UdpEndpointTableColumn::Count));
    m_udpEndpointTable->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点")
        });
    m_udpEndpointTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_udpEndpointTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_udpEndpointTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_udpEndpointTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_udpEndpointTable->verticalHeader()->setVisible(false);
    m_udpEndpointTable->horizontalHeader()->setStretchLastSection(true);
    m_udpEndpointTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    network_navigation_detail::AddTab(m_connectionSubTabWidget, m_udpEndpointTable, QStringLiteral("connections.udp"), QIcon(":/Icon/process_main.svg"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_connectionSubTabWidget,
        m_udpEndpointTable,
        QStringLiteral("network.tab.udp"),
        QStringLiteral("UDP"));

    network_navigation_detail::AddTab(m_sideTabWidget, m_connectionManagePage, QStringLiteral("connections"), QIcon(":/Icon/process_details.svg"));


    kLogEvent initConnectionTabEvent;
    info << initConnectionTabEvent << "[NetworkDock] 连接管理页初始化完成（TCP/UDP）。" << eol;
}

void NetworkDock::initializeFirewallTab()
{
    // 防火墙页：
    // - 输入：无，页面内部动态加载 fwpuclnt.dll 并管理 WFP engine；
    // - 处理：独立展示历史/实时防火墙事件，不复用流量抓包管线；
    // - 返回：无，作为 NetworkDock 顶层 Tab 呈现。
    if (m_firewallPage != nullptr) return;
    if (m_firewallTabPage == nullptr)
    {
        m_firewallTabPage = new QWidget(m_sideTabWidget);
        network_navigation_detail::AddTab(m_sideTabWidget, m_firewallTabPage,
            QStringLiteral("firewall"), QIcon(QStringLiteral(":/Icon/process_critical.svg")));
    }
    auto* layout = new QVBoxLayout(m_firewallTabPage);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    m_firewallPage = new NetworkFirewallPage(m_firewallTabPage);
    layout->addWidget(m_firewallPage);

}

void NetworkDock::initializeNetworkAuditTab()
{
    // 网络审计页：
    // - TCP/UDP Cross-View 接管原连接管理页的操作能力；
    // - AFD、WFP、NDIS 和 NSI 分区仍保持只读；
    // - 独立“连接管理”顶层入口不再创建，避免功能重复。
    if (m_networkAuditPage != nullptr) return;
    if (m_networkAuditTabPage == nullptr)
    {
        m_networkAuditTabPage = new QWidget(m_sideTabWidget);
        network_navigation_detail::AddTab(m_sideTabWidget, m_networkAuditTabPage,
            QStringLiteral("audit"), QIcon(QStringLiteral(":/Icon/process_details.svg")));
    }
    auto* layout = new QVBoxLayout(m_networkAuditTabPage);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    m_networkAuditPage = new NetworkAuditPage(m_networkAuditTabPage);
    layout->addWidget(m_networkAuditPage);
    m_networkAuditPage->setTrackProcessHandler([this](const std::uint32_t processId)
    {
        // The explicit action retains the old hidden monitor-filter behavior;
        // it does not force every embedded audit host to build that page.
        if (m_constructScope == ConstructScope::ProcessConnections && m_trafficMonitorPage == nullptr)
        {
            const QSignalBlocker blockTabs(m_sideTabWidget);
            initializeTrafficMonitorTab();
            m_sideTabWidget->setTabVisible(m_sideTabWidget->indexOf(m_trafficMonitorPage), false);
            loadMonitorFilterConfigFromDefaultPath();
        }
        addOrTrackProcessPid(processId);

        kLogEvent trackEvent;
        info << trackEvent
            << "[NetworkDock] 跟踪此进程触发, pid=" << processId
            << eol;
    });
    m_networkAuditPage->setOpenProcessDetailHandler([this](const std::uint32_t processId)
    {
        ks::process::ProcessRecord processRecord;
        processRecord.pid = processId;
        processRecord.processName = ks::process::GetProcessNameByPID(processId);
        if (processRecord.processName.empty())
        {
            processRecord.processName = "PID_" + std::to_string(processId);
        }

        ProcessDetailWindow* detailWindow = new ProcessDetailWindow(processRecord, nullptr);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
        detailWindow->setWindowFlag(Qt::Window, true);
        detailWindow->show();
        detailWindow->raise();
        detailWindow->activateWindow();

        kLogEvent detailEvent;
        info << detailEvent
            << "[NetworkDock] 打开进程详情窗口, pid=" << processId
            << eol;
    });
    m_networkAuditPage->setUdpEndpointBlockRuleHandler(
        [this](const std::uint32_t processId, const QString& localEndpointText)
    {
        // Rule prefill remains available on explicit request, using the same
        // existing firewall page/controller rather than a second implementation.
        const QPointer<NetworkDock> owner(this);
        if (m_firewallPage == nullptr)
        {
            if (m_constructScope == ConstructScope::ProcessConnections)
            {
                const QSignalBlocker blockTabs(m_sideTabWidget);
                ks::ui::ScopedWidgetThemePreparation prepare(this);
                initializeFirewallTab();
                m_sideTabWidget->setTabVisible(m_sideTabWidget->indexOf(m_firewallTabPage), false);
            }
            else if (!ensureNetworkToolPage(m_firewallTabPage)) return;
        }
        if (!owner) return;
        if (m_firewallPage != nullptr)
        {
            m_firewallPage->addUdpEndpointBlockRuleFromEvidence(localEndpointText, processId);
        }
    });

}

void NetworkDock::initializeManualRequestTab()
{
    // 请求构造页采用“分组参数 + 执行结果”布局，风格对齐 CreateProcess 页。
    if (m_manualRequestPage == nullptr) m_manualRequestPage = new QWidget(this);
    m_manualRequestLayout = new QVBoxLayout(m_manualRequestPage);
    m_manualRequestLayout->setContentsMargins(6, 6, 6, 6);
    m_manualRequestLayout->setSpacing(6);

    // 参数独立滚动，结果单独展示，操作固定在参数栏底部。
    auto* workspace = new ks::ui::ParameterWorkspace(m_manualRequestPage, 480);
    workspace->useWideParameterLayout(60);
    m_manualRequestLayout->addWidget(workspace);
    QVBoxLayout* contentLayout = workspace->parameters();
    QWidget* contentWidget = contentLayout->parentWidget();

    // 1) API 与 socket 参数分组：支持模式切换和手动覆盖底层参数。
    QGroupBox* apiGroup = new QGroupBox(QStringLiteral("API 与 Socket 参数"), contentWidget);
    ks::ui::StyleParameterSection(apiGroup);
    QFormLayout* apiLayout = new QFormLayout(apiGroup);
    apiLayout->setHorizontalSpacing(8);
    apiLayout->setVerticalSpacing(6);

    m_manualApiCombo = new QComboBox(apiGroup);
    ks::ui::StylePrimaryCombo(m_manualApiCombo);
    m_manualApiCombo->addItem(QStringLiteral("WinSock TCP 请求"), static_cast<int>(ks::network::ManualNetworkApiKind::WinSockTcp));
    m_manualApiCombo->addItem(QStringLiteral("WinSock UDP 请求"), static_cast<int>(ks::network::ManualNetworkApiKind::WinSockUdp));
    m_manualApiCombo->setToolTip(QStringLiteral("切换请求模式：TCP（connect/send/recv）或 UDP。"));

    m_manualOverrideSocketParameterCheck = new QCheckBox(QStringLiteral("手动覆盖 socket 参数"), apiGroup);
    m_manualOverrideSocketParameterCheck->setToolTip(
        QStringLiteral("关闭时按模式自动填充 socketType/protocol；开启后使用你填写的底层参数。"));

    m_manualAddressFamilyEdit = new QLineEdit(QStringLiteral("2"), apiGroup);     // AF_INET
    m_manualSocketTypeEdit = new QLineEdit(QStringLiteral("1"), apiGroup);        // SOCK_STREAM
    m_manualProtocolEdit = new QLineEdit(QStringLiteral("6"), apiGroup);          // IPPROTO_TCP
    m_manualSocketFlagsEdit = new QLineEdit(QStringLiteral("0x1"), apiGroup);     // WSA_FLAG_OVERLAPPED
    m_manualAddressFamilyEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_manualSocketTypeEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_manualProtocolEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_manualSocketFlagsEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    apiLayout->addRow(new QLabel(QStringLiteral("请求模式:"), apiGroup), m_manualApiCombo);
    // 宽屏为参数留出足够空间，底层参数默认可见，仍可由用户折叠。
    auto* socketGroup = new QGroupBox(QStringLiteral("手动覆盖 socket 参数"), apiGroup);
    auto* socketLayout = new QFormLayout(socketGroup);
    socketLayout->addRow(m_manualOverrideSocketParameterCheck);
    socketLayout->addRow(new QLabel(QStringLiteral("addressFamily:"), socketGroup), m_manualAddressFamilyEdit);
    socketLayout->addRow(new QLabel(QStringLiteral("socketType:"), socketGroup), m_manualSocketTypeEdit);
    socketLayout->addRow(new QLabel(QStringLiteral("protocol:"), socketGroup), m_manualProtocolEdit);
    socketLayout->addRow(new QLabel(QStringLiteral("socketFlags:"), socketGroup), m_manualSocketFlagsEdit);
    apiLayout->addRow(ks::ui::FoldParameterSection(socketGroup, true));
    contentLayout->addWidget(apiGroup);

    // 2) 端点与行为参数分组：覆盖 bind/connect/超时/选项等细节。
    QGroupBox* endpointGroup = new QGroupBox(QStringLiteral("端点与行为参数"), contentWidget);
    ks::ui::StyleParameterSection(endpointGroup);
    QFormLayout* endpointLayout = new QFormLayout(endpointGroup);
    endpointLayout->setHorizontalSpacing(8);
    endpointLayout->setVerticalSpacing(6);

    m_manualEnableBindCheck = new QCheckBox(QStringLiteral("启用本地 bind"), endpointGroup);
    m_manualEnableBindCheck->setToolTip(QStringLiteral("勾选后先 bind(localAddress:localPort) 再执行连接/发送。"));
    m_manualLocalAddressEdit = new QLineEdit(QStringLiteral("0.0.0.0"), endpointGroup);
    m_manualLocalAddressEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_manualLocalPortSpin = new QSpinBox(endpointGroup);
    m_manualLocalPortSpin->setRange(0, 65535);
    m_manualLocalPortSpin->setValue(0);

    m_manualRemoteAddressEdit = new QLineEdit(QStringLiteral("127.0.0.1"), endpointGroup);
    m_manualRemoteAddressEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_manualRemotePortSpin = new QSpinBox(endpointGroup);
    m_manualRemotePortSpin->setRange(0, 65535);
    m_manualRemotePortSpin->setValue(80);

    m_manualConnectBeforeSendCheck = new QCheckBox(QStringLiteral("发送前 connect"), endpointGroup);
    m_manualConnectBeforeSendCheck->setChecked(true);
    m_manualConnectBeforeSendCheck->setToolTip(QStringLiteral("UDP 关闭该项时会改用 sendto/recvfrom。"));

    m_manualReuseAddressCheck = new QCheckBox(QStringLiteral("SO_REUSEADDR"), endpointGroup);
    m_manualNoDelayCheck = new QCheckBox(QStringLiteral("TCP_NODELAY"), endpointGroup);

    m_manualSendTimeoutSpin = new QSpinBox(endpointGroup);
    m_manualSendTimeoutSpin->setRange(0, 60 * 60 * 1000);
    m_manualSendTimeoutSpin->setValue(3000);
    m_manualRecvTimeoutSpin = new QSpinBox(endpointGroup);
    m_manualRecvTimeoutSpin->setRange(0, 60 * 60 * 1000);
    m_manualRecvTimeoutSpin->setValue(3000);

    m_manualSendFlagsEdit = new QLineEdit(QStringLiteral("0"), endpointGroup);
    m_manualReceiveFlagsEdit = new QLineEdit(QStringLiteral("0"), endpointGroup);
    m_manualSendFlagsEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_manualReceiveFlagsEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    endpointLayout->addRow(new QLabel(QStringLiteral("远端地址:"), endpointGroup), m_manualRemoteAddressEdit);
    endpointLayout->addRow(new QLabel(QStringLiteral("远端端口:"), endpointGroup), m_manualRemotePortSpin);
    endpointLayout->addRow(m_manualConnectBeforeSendCheck);
    auto* transportGroup = new QGroupBox(QStringLiteral("高级"), endpointGroup);
    auto* transportLayout = new QFormLayout(transportGroup);
    transportLayout->addRow(m_manualEnableBindCheck);
    transportLayout->addRow(new QLabel(QStringLiteral("本地地址:"), transportGroup), m_manualLocalAddressEdit);
    transportLayout->addRow(new QLabel(QStringLiteral("本地端口:"), transportGroup), m_manualLocalPortSpin);
    transportLayout->addRow(new QLabel(QStringLiteral("发送超时(ms):"), transportGroup), m_manualSendTimeoutSpin);
    transportLayout->addRow(new QLabel(QStringLiteral("接收超时(ms):"), transportGroup), m_manualRecvTimeoutSpin);
    transportLayout->addRow(new QLabel(QStringLiteral("sendFlags:"), transportGroup), m_manualSendFlagsEdit);
    transportLayout->addRow(new QLabel(QStringLiteral("recvFlags:"), transportGroup), m_manualReceiveFlagsEdit);
    transportLayout->addRow(m_manualReuseAddressCheck);
    transportLayout->addRow(m_manualNoDelayCheck);
    endpointLayout->addRow(ks::ui::FoldParameterSection(transportGroup, true));
    contentLayout->addWidget(endpointGroup);

    // 3) 载荷与接收参数分组：支持文本/HEX 输入与响应读取开关。
    QGroupBox* payloadGroup = new QGroupBox(QStringLiteral("载荷与响应读取"), contentWidget);
    ks::ui::StyleParameterSection(payloadGroup);
    QFormLayout* payloadLayout = new QFormLayout(payloadGroup);
    payloadLayout->setHorizontalSpacing(8);
    payloadLayout->setVerticalSpacing(6);

    m_manualPayloadFormatCombo = new QComboBox(payloadGroup);
    m_manualPayloadFormatCombo->addItem(QStringLiteral("ASCII 文本"), static_cast<int>(ks::network::ManualPayloadFormat::AsciiText));
    m_manualPayloadFormatCombo->addItem(QStringLiteral("十六进制字节"), static_cast<int>(ks::network::ManualPayloadFormat::HexBytes));
    m_manualPayloadFormatCombo->setToolTip(QStringLiteral("十六进制模式示例：48 65 6C 6C 6F"));

    auto* payloadEditor = new CodeTextEdit(payloadGroup);
    payloadEditor->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
    payloadEditor->setLineNumbersVisible(false);
    payloadEditor->setCompactMode(true);
    m_manualPayloadEditor = payloadEditor;
    m_manualPayloadEditor->setPlaceholderText(QStringLiteral("在此输入请求载荷。"));
    m_manualPayloadEditor->setMinimumHeight(150);
    m_manualPayloadEditor->setMaximumHeight(240);
    m_manualPayloadEditor->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    m_manualPayloadEditor->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    m_manualReceiveAfterSendCheck = new QCheckBox(QStringLiteral("发送后读取响应"), payloadGroup);
    m_manualReceiveAfterSendCheck->setChecked(true);
    m_manualReceiveMaxBytesSpin = new QSpinBox(payloadGroup);
    m_manualReceiveMaxBytesSpin->setRange(1, 1024 * 1024);
    m_manualReceiveMaxBytesSpin->setValue(4096);
    m_manualShutdownSendCheck = new QCheckBox(QStringLiteral("发送后 shutdown(SD_SEND)"), payloadGroup);
    m_manualShutdownSendCheck->setChecked(false);

    payloadLayout->addRow(new QLabel(QStringLiteral("载荷格式:"), payloadGroup), m_manualPayloadFormatCombo);
    payloadLayout->addRow(m_manualPayloadEditor);
    payloadLayout->addRow(m_manualReceiveAfterSendCheck);
    payloadLayout->addRow(new QLabel(QStringLiteral("最大读取字节:"), payloadGroup), m_manualReceiveMaxBytesSpin);
    payloadLayout->addRow(m_manualShutdownSendCheck);
    contentLayout->addWidget(payloadGroup);

    // API/载荷和端点/行为各自自然排列；参数栏不足两列时恢复 API→端点→载荷顺序。
    ks::ui::ArrangeParameterColumns(contentLayout, {apiGroup, payloadGroup}, {endpointGroup}, 300);

    // 4) 执行与结果分组：执行请求、重置参数、输出结果日志。
    QGroupBox* actionGroup = new QGroupBox(QStringLiteral("执行与结果"), contentWidget);
    ks::ui::StyleParameterSection(actionGroup);
    QVBoxLayout* actionLayout = new QVBoxLayout(actionGroup);
    QHBoxLayout* actionButtonLayout = workspace->actions();

    m_manualExecuteButton = new QPushButton(QStringLiteral("执行请求"), actionGroup);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_manualExecuteButton, ks::ui::FlatButtonTone::Accent,
        ks::ui::FlatButtonAppearance::Solid);
    m_manualExecuteButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_manualExecuteButton->setToolTip(QStringLiteral("按上方参数立即执行一次网络请求。"));

    m_manualResetButton = new QPushButton(QStringLiteral("恢复默认参数"), actionGroup);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_manualResetButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
    m_manualResetButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_manualResetButton->setToolTip(QStringLiteral("重置请求构造页全部参数。"));

    actionButtonLayout->addWidget(m_manualExecuteButton);
    actionButtonLayout->addWidget(m_manualResetButton);
    actionButtonLayout->addStretch(1);
    ks::ui::NormalizeToolbarRow(actionButtonLayout);

    m_manualResultOutput = new CodeTextEdit(actionGroup);
    static_cast<CodeTextEdit*>(m_manualResultOutput)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
    m_manualResultOutput->setReadOnly(true);
    m_manualResultOutput->setMaximumBlockCount(800);
    m_manualResultOutput->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    m_manualResultOutput->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_manualResultOutput->setPlaceholderText(QStringLiteral("执行结果、响应摘要和错误码会显示在这里。"));

    actionLayout->addWidget(m_manualResultOutput, 1);
    workspace->results()->addWidget(actionGroup, 1);
    workspace->finish();

    // 构建完成后先按默认模式回填一组“可直接执行”的参数。
    resetManualRequestForm();

    network_navigation_detail::AddTab(m_sideTabWidget, m_manualRequestPage, QStringLiteral("manual-request"), QIcon(":/Icon/process_main.svg"));


    kLogEvent initManualTabEvent;
    info << initManualTabEvent << "[NetworkDock] 请求构造页初始化完成。" << eol;
}




bool NetworkDock::ensureNetworkToolPage(QWidget* page)
{
    if (m_constructScope != ConstructScope::Full || page == nullptr) return true;
    auto factory = m_coldNetworkToolFactories.take(page);
    if (!factory) return true;
    const QPointer<NetworkDock> guard(this);
    {
        ks::ui::ScopedWidgetThemePreparation prepare(page);
        factory();
    }
    return !guard.isNull();
}

void NetworkDock::ensureVisibleNetworkToolPage()
{
    if (!isVisible() || m_sideTabWidget == nullptr) return;
    const QPointer<NetworkDock> guard(this);
    QWidget* selected = m_sideTabWidget->currentWidget();
    while (selected != nullptr)
    {
        if (!ensureNetworkToolPage(selected) || !guard || !isVisible()) return;
        ks::ui::PrepareWidgetThemeBindingsForShow(selected);
        if (!guard || !isVisible()) return;
        QWidget* current = m_sideTabWidget->currentWidget();
        if (current == selected) return;
        selected = current;
    }
}
