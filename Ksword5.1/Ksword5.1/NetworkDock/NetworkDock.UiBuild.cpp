#include "NetworkDock.InternalCommon.h"
#include "../UI/VisibleTableWidget.h"
#include "NetworkFirewallPage.h"
#include "NetworkAuditPage.h"
#include "../Internationalization/LanguageManager.h"

#include <QFrame>
#include <QScrollArea>

using namespace network_dock_detail;
void NetworkDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(4, 4, 4, 4);
    m_rootLayout->setSpacing(4);

    // 顶部横排 Tab：
    // - 网络功能页签数量已较多，改成顶部横排后避免左侧竖排标签挤出纵向滚动条；
    // - 保留统一 QTabWidget 结构，不改变各功能页内部实现。
    m_sideTabWidget = new QTabWidget(this);
    m_sideTabWidget->setTabPosition(QTabWidget::North);
    m_sideTabWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_rootLayout->addWidget(m_sideTabWidget, 1);

    initializeTrafficMonitorTab();
    initializeNidsTab();
    // The process rate-limit page is intentionally not exposed in the UI.
    // Its current implementation throttles by suspending/resuming the whole
    // target process, which is too coarse for a user-facing network dock tab.
    // Keep initializeRateLimitTab() compiled for now so the backend/UI code can
    // be restored later if a cleaner enforcement model replaces it.
    initializeFirewallTab();
    initializeNetworkAuditTab();
    initializeManualRequestTab();
    initializeMultiThreadDownloadTab();
    initializeHttpsAnalyzeTab();
    initializeRouteTableTab();
    initializeArpCacheTab();
    initializeDnsCacheTab();
    initializeAliveHostScanTab();
    initializeHostsFileEditorTab();
}

void NetworkDock::initializeTrafficMonitorTab()
{
    m_trafficMonitorPage = new QWidget(this);
    m_trafficMonitorLayout = new QVBoxLayout(m_trafficMonitorPage);
    m_trafficMonitorLayout->setContentsMargins(6, 6, 6, 6);
    m_trafficMonitorLayout->setSpacing(6);

    // 控制栏：启动/停止/清空 + 状态提示。
    m_monitorControlLayout = new QHBoxLayout();
    m_monitorControlLayout->setSpacing(6);

    m_startMonitorButton = new QPushButton(m_trafficMonitorPage);
    m_startMonitorButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_startMonitorButton->setToolTip(QStringLiteral("启动网络流量监控"));

    m_stopMonitorButton = new QPushButton(m_trafficMonitorPage);
    m_stopMonitorButton->setIcon(QIcon(":/Icon/process_pause.svg"));
    m_stopMonitorButton->setToolTip(QStringLiteral("停止网络流量监控"));

    m_clearPacketButton = new QPushButton(m_trafficMonitorPage);
    m_clearPacketButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_clearPacketButton->setToolTip(QStringLiteral("清空当前流量列表"));

    m_networkPluginButton = new QPushButton(QStringLiteral("插件"), m_trafficMonitorPage);
    m_networkPluginButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_networkPluginButton->setToolTip(QStringLiteral("运行声明支持网络目标的独立插件"));
    m_networkPluginMenu = new QMenu(m_networkPluginButton);
    m_networkPluginButton->setMenu(m_networkPluginMenu);

    m_monitorStatusLabel = new QLabel(QStringLiteral("状态：未启动"), m_trafficMonitorPage);
    // 状态标签不再设置较大最小宽度，避免窗口变窄时挤出横向滚动条。
    m_monitorStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    m_monitorControlLayout->addWidget(m_startMonitorButton);
    m_monitorControlLayout->addWidget(m_stopMonitorButton);
    m_monitorControlLayout->addWidget(m_clearPacketButton);
    m_monitorControlLayout->addWidget(m_networkPluginButton);
    m_monitorControlLayout->addWidget(m_monitorStatusLabel);
    m_monitorControlLayout->addStretch(1);

    m_trafficMonitorLayout->addLayout(m_monitorControlLayout);

    // 新过滤标题栏：漏斗按钮 + 规则组管理 + 导入导出保存。
    m_monitorFilterHeaderLayout = new QHBoxLayout();
    m_monitorFilterHeaderLayout->setSpacing(6);

    m_monitorFilterToggleButton = new QPushButton(m_trafficMonitorPage);
    m_monitorFilterToggleButton->setCheckable(true);
    m_monitorFilterToggleButton->setChecked(false);
    m_monitorFilterToggleButton->setIcon(QIcon(":/Icon/filter_funnel.svg"));
    m_monitorFilterToggleButton->setToolTip(QStringLiteral("展开/收起网络筛选器配置"));

    QLabel* filterTitleLabel = new QLabel(QStringLiteral("网络筛选器"), m_trafficMonitorPage);
    filterTitleLabel->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);

    m_addMonitorFilterGroupButton = new QPushButton(QStringLiteral("新增规则组"), m_trafficMonitorPage);
    m_addMonitorFilterGroupButton->setIcon(QIcon(":/Icon/plus.svg"));
    m_addMonitorFilterGroupButton->setToolTip(QStringLiteral("新增一个 OR 规则组"));

    m_applyMonitorFilterButton = new QPushButton(QStringLiteral("应用"), m_trafficMonitorPage);
    m_applyMonitorFilterButton->setIcon(QIcon(":/Icon/log_track.svg"));
    m_applyMonitorFilterButton->setToolTip(QStringLiteral("应用当前全部规则组过滤条件"));

    m_saveMonitorFilterButton = new QPushButton(QStringLiteral("保存"), m_trafficMonitorPage);
    m_saveMonitorFilterButton->setIcon(QIcon(":/Icon/codeeditor_save.svg"));
    m_saveMonitorFilterButton->setToolTip(QStringLiteral("保存到 exe 目录下 config/wireshark.cfg"));

    m_importMonitorFilterButton = new QPushButton(QStringLiteral("导入"), m_trafficMonitorPage);
    m_importMonitorFilterButton->setIcon(QIcon(":/Icon/codeeditor_open.svg"));
    m_importMonitorFilterButton->setToolTip(QStringLiteral("从配置文件导入规则组"));

    m_exportMonitorFilterButton = new QPushButton(QStringLiteral("导出"), m_trafficMonitorPage);
    m_exportMonitorFilterButton->setIcon(QIcon(":/Icon/log_export.svg"));
    m_exportMonitorFilterButton->setToolTip(QStringLiteral("导出当前规则组到配置文件"));

    m_clearMonitorFilterButton = new QPushButton(QStringLiteral("一键清空"), m_trafficMonitorPage);
    m_clearMonitorFilterButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_clearMonitorFilterButton->setToolTip(QStringLiteral("清空全部规则组配置"));

    m_monitorFilterHeaderLayout->addWidget(m_monitorFilterToggleButton);
    m_monitorFilterHeaderLayout->addWidget(filterTitleLabel);
    m_monitorFilterHeaderLayout->addSpacing(4);
    m_monitorFilterHeaderLayout->addWidget(m_addMonitorFilterGroupButton);
    m_monitorFilterHeaderLayout->addWidget(m_applyMonitorFilterButton);
    m_monitorFilterHeaderLayout->addWidget(m_saveMonitorFilterButton);
    m_monitorFilterHeaderLayout->addWidget(m_importMonitorFilterButton);
    m_monitorFilterHeaderLayout->addWidget(m_exportMonitorFilterButton);
    m_monitorFilterHeaderLayout->addWidget(m_clearMonitorFilterButton);
    m_monitorFilterHeaderLayout->addStretch(1);
    m_trafficMonitorLayout->addLayout(m_monitorFilterHeaderLayout);

    // 过滤折叠面板：标题分隔线 + 规则组滚动区 + 状态标签。
    m_monitorFilterPanel = new QWidget(m_trafficMonitorPage);
    m_monitorFilterPanel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
    // 过滤面板采用“受限高度 + 内部滚动”策略，避免撑高整个 Dock 出现外层滚动条。
    m_monitorFilterPanel->setMaximumHeight(240);
    m_monitorFilterPanelLayout = new QVBoxLayout(m_monitorFilterPanel);
    m_monitorFilterPanelLayout->setContentsMargins(2, 0, 2, 0);
    m_monitorFilterPanelLayout->setSpacing(6);

    QFrame* filterSeparatorLine = new QFrame(m_monitorFilterPanel);
    filterSeparatorLine->setFrameShape(QFrame::HLine);
    filterSeparatorLine->setFrameShadow(QFrame::Sunken);
    m_monitorFilterPanelLayout->addWidget(filterSeparatorLine);

    m_monitorFilterScrollArea = new QScrollArea(m_monitorFilterPanel);
    m_monitorFilterScrollArea->setWidgetResizable(true);
    m_monitorFilterScrollArea->setFrameShape(QFrame::NoFrame);
    m_monitorFilterScrollArea->setMinimumHeight(0);
    m_monitorFilterScrollArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_monitorFilterScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_monitorFilterScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    m_monitorFilterGroupHostWidget = new QWidget(m_monitorFilterScrollArea);
    m_monitorFilterGroupHostLayout = new QVBoxLayout(m_monitorFilterGroupHostWidget);
    m_monitorFilterGroupHostLayout->setContentsMargins(0, 0, 0, 0);
    m_monitorFilterGroupHostLayout->setSpacing(8);
    m_monitorFilterScrollArea->setWidget(m_monitorFilterGroupHostWidget);
    m_monitorFilterPanelLayout->addWidget(m_monitorFilterScrollArea, 1);

    m_monitorFilterStateLabel = new QLabel(QStringLiteral("当前过滤：无"), m_monitorFilterPanel);
    m_monitorFilterStateLabel->setWordWrap(true);
    m_monitorFilterStateLabel->setMinimumWidth(0);
    m_monitorFilterStateLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_monitorFilterPanelLayout->addWidget(m_monitorFilterStateLabel);

    m_trafficMonitorLayout->addWidget(m_monitorFilterPanel);
    m_monitorFilterPanel->setVisible(false);

    addMonitorFilterRuleGroup();
    updateMonitorFilterStateLabel();

    // 流量时间轴：
    // - 复用 ETW 监控页下方的框选式时间轴控件，而不是进程页的“时间点滑块”；
    // - 用户可拖动矩形整体移动时间窗口，也可拖动左右边缘调整边界；
    // - 控件只负责时间选择，实际报文显示仍由 NetworkDock 的过滤链统一重建。
    m_packetTimelineWidget = new ProcessTraceTimelineWidget(m_trafficMonitorPage);
    m_packetTimelineWidget->setToolTip(QStringLiteral(
        "流量时间轴：横轴只统计监控开启时长，停机间隔不计入；绿色折线为上传速率，蓝色折线为下载速率；拖动矩形移动时间窗口，拖动左右边调整边界，滚轮向上放大窗口、向下缩小窗口。清空报文会重置时间轴。"));
    m_trafficMonitorLayout->addWidget(m_packetTimelineWidget, 0);

    // 报文主表：展示“全部发送 UDP/TCP 包”。
    m_packetTable = new ks::ui::VisibleTableWidget(m_trafficMonitorPage);
    m_packetTable->setColumnCount(toPacketColumn(PacketTableColumn::Count));
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

    m_trafficMonitorLayout->addWidget(m_packetTable, 1);
    m_sideTabWidget->addTab(m_trafficMonitorPage, QIcon(":/Icon/process_main.svg"), QStringLiteral("流量监控"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_trafficMonitorPage, QStringLiteral("network.tab.traffic"), QStringLiteral("流量监控"));
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
    m_applyRateLimitButton->setIcon(QIcon(":/Icon/process_priority.svg"));
    m_applyRateLimitButton->setToolTip(QStringLiteral("新增或更新限速规则"));

    m_removeRateLimitButton = new QPushButton(m_rateLimitPage);
    m_removeRateLimitButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_removeRateLimitButton->setToolTip(QStringLiteral("删除选中的限速规则"));

    m_clearRateLimitButton = new QPushButton(m_rateLimitPage);
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

    m_rateLimitLayout->addLayout(m_rateLimitControlLayout);

    // 规则表：展示 PID、阈值、触发计数、当前状态。
    m_rateLimitTable = new ks::ui::VisibleTableWidget(m_rateLimitPage);
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
    m_rateLimitLogOutput = new QPlainTextEdit(m_rateLimitPage);
    m_rateLimitLogOutput->setReadOnly(true);
    m_rateLimitLogOutput->setMaximumBlockCount(400);
    // 日志框使用按控件宽度自动换行，避免窄窗口出现横向滚动条。
    m_rateLimitLogOutput->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    m_rateLimitLogOutput->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_rateLimitLogOutput->setPlaceholderText(QStringLiteral("限速动作日志将显示在这里..."));
    m_rateLimitLayout->addWidget(m_rateLimitLogOutput, 1);

    m_sideTabWidget->addTab(m_rateLimitPage, QIcon(":/Icon/process_priority.svg"), QStringLiteral("进程限速"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_rateLimitPage, QStringLiteral("network.tab.rate_limit"), QStringLiteral("进程限速"));
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
    m_refreshConnectionButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_refreshConnectionButton->setToolTip(QStringLiteral("立即刷新 TCP/UDP 连接快照"));

    m_autoRefreshConnectionButton = new QPushButton(m_connectionManagePage);
    m_autoRefreshConnectionButton->setCheckable(true);
    m_autoRefreshConnectionButton->setChecked(true);
    m_autoRefreshConnectionButton->setIcon(QIcon(":/Icon/process_pause.svg"));
    m_autoRefreshConnectionButton->setToolTip(QStringLiteral("自动刷新已开启，点击暂停"));

    m_terminateTcpButton = new QPushButton(m_connectionManagePage);
    m_terminateTcpButton->setIcon(QIcon(":/Icon/process_terminate.svg"));
    m_terminateTcpButton->setToolTip(QStringLiteral("终止当前选中的 TCP 连接（DELETE_TCB）"));

    m_clearConnectionPidFilterButton = new QPushButton(m_connectionManagePage);
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

    // 子页签：分别展示 TCP 与 UDP。
    m_connectionSubTabWidget = new QTabWidget(m_connectionManagePage);
    m_connectionSubTabWidget->setTabPosition(QTabWidget::North);
    m_connectionSubTabWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_connectionManageLayout->addWidget(m_connectionSubTabWidget, 1);

    // TCP 表：状态、PID、进程、本地端点、远端端点。
    m_tcpConnectionTable = new ks::ui::VisibleTableWidget(m_connectionManagePage);
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
    m_connectionSubTabWidget->addTab(m_tcpConnectionTable, QIcon(":/Icon/process_main.svg"), QStringLiteral("TCP"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_connectionSubTabWidget,
        m_tcpConnectionTable,
        QStringLiteral("network.tab.tcp"),
        QStringLiteral("TCP"));

    // UDP 表：PID、进程、本地端点。
    m_udpEndpointTable = new ks::ui::VisibleTableWidget(m_connectionManagePage);
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
    m_connectionSubTabWidget->addTab(m_udpEndpointTable, QIcon(":/Icon/process_main.svg"), QStringLiteral("UDP"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_connectionSubTabWidget,
        m_udpEndpointTable,
        QStringLiteral("network.tab.udp"),
        QStringLiteral("UDP"));

    m_sideTabWidget->addTab(m_connectionManagePage, QIcon(":/Icon/process_details.svg"), QStringLiteral("连接管理"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_connectionManagePage, QStringLiteral("network.tab.connections"), QStringLiteral("连接管理"));

    kLogEvent initConnectionTabEvent;
    info << initConnectionTabEvent << "[NetworkDock] 连接管理页初始化完成（TCP/UDP）。" << eol;
}

void NetworkDock::initializeFirewallTab()
{
    // 防火墙页：
    // - 输入：无，页面内部动态加载 fwpuclnt.dll 并管理 WFP engine；
    // - 处理：独立展示历史/实时防火墙事件，不复用流量抓包管线；
    // - 返回：无，作为 NetworkDock 顶层 Tab 呈现。
    m_firewallPage = new NetworkFirewallPage(this);
    m_sideTabWidget->addTab(
        m_firewallPage,
        QIcon(QStringLiteral(":/Icon/process_critical.svg")),
        QStringLiteral("防火墙"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_firewallPage, QStringLiteral("network.tab.firewall"), QStringLiteral("防火墙"));
}

void NetworkDock::initializeNetworkAuditTab()
{
    // 网络审计页：
    // - TCP/UDP Cross-View 接管原连接管理页的操作能力；
    // - AFD、WFP、NDIS 和 NSI 分区仍保持只读；
    // - 独立“连接管理”顶层入口不再创建，避免功能重复。
    m_networkAuditPage = new NetworkAuditPage(this);
    m_networkAuditPage->setTrackProcessHandler([this](const std::uint32_t processId)
    {
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
        if (m_firewallPage != nullptr)
        {
            m_firewallPage->addUdpEndpointBlockRuleFromEvidence(localEndpointText, processId);
        }
    });
    m_sideTabWidget->addTab(
        m_networkAuditPage,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("网络审计"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_networkAuditPage, QStringLiteral("network.tab.audit"), QStringLiteral("网络审计"));
}

void NetworkDock::initializeManualRequestTab()
{
    // 请求构造页采用“分组参数 + 执行结果”布局，风格对齐 CreateProcess 页。
    m_manualRequestPage = new QWidget(this);
    m_manualRequestLayout = new QVBoxLayout(m_manualRequestPage);
    m_manualRequestLayout->setContentsMargins(6, 6, 6, 6);
    m_manualRequestLayout->setSpacing(6);

    // 关键改动（响应“窄窗口不出现滚动条”）：
    // 1) 移除外层 QScrollArea，避免页面在宽度变化时出现额外滚动条；
    // 2) 改为直接把各功能分组挂到页面主布局，交给布局系统自适应压缩。
    QWidget* contentWidget = m_manualRequestPage;
    QVBoxLayout* contentLayout = m_manualRequestLayout;
    contentLayout->setContentsMargins(2, 2, 2, 2);
    contentLayout->setSpacing(8);

    // 1) API 与 socket 参数分组：支持模式切换和手动覆盖底层参数。
    QGroupBox* apiGroup = new QGroupBox(QStringLiteral("API 与 Socket 参数"), contentWidget);
    QGridLayout* apiLayout = new QGridLayout(apiGroup);
    apiLayout->setHorizontalSpacing(8);
    apiLayout->setVerticalSpacing(6);
    apiLayout->setColumnStretch(1, 1);
    apiLayout->setColumnStretch(3, 1);

    m_manualApiCombo = new QComboBox(apiGroup);
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

    apiLayout->addWidget(new QLabel(QStringLiteral("请求模式:"), apiGroup), 0, 0);
    apiLayout->addWidget(m_manualApiCombo, 0, 1, 1, 3);
    apiLayout->addWidget(m_manualOverrideSocketParameterCheck, 1, 0, 1, 4);
    apiLayout->addWidget(new QLabel(QStringLiteral("addressFamily:"), apiGroup), 2, 0);
    apiLayout->addWidget(m_manualAddressFamilyEdit, 2, 1);
    apiLayout->addWidget(new QLabel(QStringLiteral("socketType:"), apiGroup), 2, 2);
    apiLayout->addWidget(m_manualSocketTypeEdit, 2, 3);
    apiLayout->addWidget(new QLabel(QStringLiteral("protocol:"), apiGroup), 3, 0);
    apiLayout->addWidget(m_manualProtocolEdit, 3, 1);
    apiLayout->addWidget(new QLabel(QStringLiteral("socketFlags:"), apiGroup), 3, 2);
    apiLayout->addWidget(m_manualSocketFlagsEdit, 3, 3);
    contentLayout->addWidget(apiGroup);

    // 2) 端点与行为参数分组：覆盖 bind/connect/超时/选项等细节。
    QGroupBox* endpointGroup = new QGroupBox(QStringLiteral("端点与行为参数"), contentWidget);
    QGridLayout* endpointLayout = new QGridLayout(endpointGroup);
    endpointLayout->setHorizontalSpacing(8);
    endpointLayout->setVerticalSpacing(6);
    endpointLayout->setColumnStretch(1, 1);
    endpointLayout->setColumnStretch(3, 1);

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

    endpointLayout->addWidget(m_manualEnableBindCheck, 0, 0, 1, 2);
    endpointLayout->addWidget(new QLabel(QStringLiteral("本地地址:"), endpointGroup), 1, 0);
    endpointLayout->addWidget(m_manualLocalAddressEdit, 1, 1);
    endpointLayout->addWidget(new QLabel(QStringLiteral("本地端口:"), endpointGroup), 1, 2);
    endpointLayout->addWidget(m_manualLocalPortSpin, 1, 3);
    endpointLayout->addWidget(new QLabel(QStringLiteral("远端地址:"), endpointGroup), 2, 0);
    endpointLayout->addWidget(m_manualRemoteAddressEdit, 2, 1);
    endpointLayout->addWidget(new QLabel(QStringLiteral("远端端口:"), endpointGroup), 2, 2);
    endpointLayout->addWidget(m_manualRemotePortSpin, 2, 3);
    endpointLayout->addWidget(m_manualConnectBeforeSendCheck, 3, 0, 1, 2);
    endpointLayout->addWidget(m_manualReuseAddressCheck, 3, 2);
    endpointLayout->addWidget(m_manualNoDelayCheck, 3, 3);
    endpointLayout->addWidget(new QLabel(QStringLiteral("发送超时(ms):"), endpointGroup), 4, 0);
    endpointLayout->addWidget(m_manualSendTimeoutSpin, 4, 1);
    endpointLayout->addWidget(new QLabel(QStringLiteral("接收超时(ms):"), endpointGroup), 4, 2);
    endpointLayout->addWidget(m_manualRecvTimeoutSpin, 4, 3);
    endpointLayout->addWidget(new QLabel(QStringLiteral("sendFlags:"), endpointGroup), 5, 0);
    endpointLayout->addWidget(m_manualSendFlagsEdit, 5, 1);
    endpointLayout->addWidget(new QLabel(QStringLiteral("recvFlags:"), endpointGroup), 5, 2);
    endpointLayout->addWidget(m_manualReceiveFlagsEdit, 5, 3);
    contentLayout->addWidget(endpointGroup);

    // 3) 载荷与接收参数分组：支持文本/HEX 输入与响应读取开关。
    QGroupBox* payloadGroup = new QGroupBox(QStringLiteral("载荷与响应读取"), contentWidget);
    QGridLayout* payloadLayout = new QGridLayout(payloadGroup);
    payloadLayout->setHorizontalSpacing(8);
    payloadLayout->setVerticalSpacing(6);
    payloadLayout->setColumnStretch(1, 1);
    payloadLayout->setColumnStretch(4, 1);

    m_manualPayloadFormatCombo = new QComboBox(payloadGroup);
    m_manualPayloadFormatCombo->addItem(QStringLiteral("ASCII 文本"), static_cast<int>(ks::network::ManualPayloadFormat::AsciiText));
    m_manualPayloadFormatCombo->addItem(QStringLiteral("十六进制字节"), static_cast<int>(ks::network::ManualPayloadFormat::HexBytes));
    m_manualPayloadFormatCombo->setToolTip(QStringLiteral("十六进制模式示例：48 65 6C 6C 6F"));

    m_manualPayloadEditor = new QPlainTextEdit(payloadGroup);
    m_manualPayloadEditor->setPlaceholderText(QStringLiteral("在此输入请求载荷。"));
    m_manualPayloadEditor->setFixedHeight(96);
    m_manualPayloadEditor->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    m_manualPayloadEditor->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    m_manualReceiveAfterSendCheck = new QCheckBox(QStringLiteral("发送后读取响应"), payloadGroup);
    m_manualReceiveAfterSendCheck->setChecked(true);
    m_manualReceiveMaxBytesSpin = new QSpinBox(payloadGroup);
    m_manualReceiveMaxBytesSpin->setRange(1, 1024 * 1024);
    m_manualReceiveMaxBytesSpin->setValue(4096);
    m_manualShutdownSendCheck = new QCheckBox(QStringLiteral("发送后 shutdown(SD_SEND)"), payloadGroup);
    m_manualShutdownSendCheck->setChecked(false);

    payloadLayout->addWidget(new QLabel(QStringLiteral("载荷格式:"), payloadGroup), 0, 0);
    payloadLayout->addWidget(m_manualPayloadFormatCombo, 0, 1);
    payloadLayout->addWidget(m_manualReceiveAfterSendCheck, 0, 2);
    payloadLayout->addWidget(new QLabel(QStringLiteral("最大读取字节:"), payloadGroup), 0, 3);
    payloadLayout->addWidget(m_manualReceiveMaxBytesSpin, 0, 4);
    payloadLayout->addWidget(m_manualShutdownSendCheck, 1, 0, 1, 2);
    payloadLayout->addWidget(m_manualPayloadEditor, 2, 0, 1, 5);
    contentLayout->addWidget(payloadGroup);

    // 4) 执行与结果分组：执行请求、重置参数、输出结果日志。
    QGroupBox* actionGroup = new QGroupBox(QStringLiteral("执行与结果"), contentWidget);
    QVBoxLayout* actionLayout = new QVBoxLayout(actionGroup);
    QHBoxLayout* actionButtonLayout = new QHBoxLayout();

    m_manualExecuteButton = new QPushButton(QStringLiteral("执行请求"), actionGroup);
    m_manualExecuteButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_manualExecuteButton->setToolTip(QStringLiteral("按上方参数立即执行一次网络请求。"));

    m_manualResetButton = new QPushButton(QStringLiteral("恢复默认参数"), actionGroup);
    m_manualResetButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_manualResetButton->setToolTip(QStringLiteral("重置请求构造页全部参数。"));

    actionButtonLayout->addWidget(m_manualExecuteButton);
    actionButtonLayout->addWidget(m_manualResetButton);
    actionButtonLayout->addStretch(1);

    m_manualResultOutput = new QPlainTextEdit(actionGroup);
    m_manualResultOutput->setReadOnly(true);
    m_manualResultOutput->setMaximumBlockCount(800);
    m_manualResultOutput->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    m_manualResultOutput->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_manualResultOutput->setPlaceholderText(QStringLiteral("执行结果、响应摘要和错误码会显示在这里。"));

    actionLayout->addLayout(actionButtonLayout);
    actionLayout->addWidget(m_manualResultOutput, 1);
    contentLayout->addWidget(actionGroup, 1);

    // 构建完成后先按默认模式回填一组“可直接执行”的参数。
    resetManualRequestForm();

    m_sideTabWidget->addTab(m_manualRequestPage, QIcon(":/Icon/process_main.svg"), QStringLiteral("请求构造"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_manualRequestPage, QStringLiteral("network.tab.manual_request"), QStringLiteral("请求构造"));

    kLogEvent initManualTabEvent;
    info << initManualTabEvent << "[NetworkDock] 请求构造页初始化完成。" << eol;
}



