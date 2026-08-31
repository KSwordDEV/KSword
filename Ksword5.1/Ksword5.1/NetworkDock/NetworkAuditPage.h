#pragma once

// ============================================================
// NetworkAuditPage.h
// 作用：
// 1) 提供网络审计页，集中展示 TCP/UDP cross-view、AFD、WFP、NDIS 和 NSI 摘要；
// 2) TCP/UDP cross-view 合并原“连接管理”页的刷新、筛选、复制、进程动作、扫描与终止动作；
// 3) 其余审计分区保持只读，不提供 disable / detach / bypass 动作。
// ============================================================

#include "../Framework.h"
#include "../ksword/network/network_connection_tools.h"

#include <QHash>
#include <QIcon>
#include <QWidget>
#include <QJsonValue>
#include <QSet>

#include <atomic> // std::atomic_bool：防止并发刷新重入。
#include <functional> // std::function：把原连接管理页的进程动作回调给 NetworkDock。
#include <memory> // std::unique_ptr：异步快照对象托管。
#include <vector> // std::vector：批量快照行缓存。

class QImage;
class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QSplitter;
class QTabWidget;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class QVBoxLayout;
class QHBoxLayout;
struct NetworkAuditAsyncState;

class NetworkAuditPage final : public QWidget
{
public:
    // ProcessActionHandler：
    // - 输入：Cross-View 当前行的 PID；
    // - 处理：由 NetworkDock 注入“跟踪进程/打开进程详情”的既有实现；
    // - 返回：无。
    using ProcessActionHandler = std::function<void(std::uint32_t)>;
    using UdpEndpointBlockRuleHandler = std::function<void(std::uint32_t, const QString&)>;

    // 构造函数：
    // - 输入 parent：Qt 父控件，可为空；
    // - 处理：构建只读审计页 UI；首轮异步刷新在页面首次显示时触发；
    // - 返回：无。
    explicit NetworkAuditPage(QWidget* parent = nullptr);

    // 析构函数：
    // - 处理：先撤销异步 worker 的 owner，再由 Qt 释放子控件；
    // - 返回：无。
    ~NetworkAuditPage() override;

    // requestInitialRefresh 作用：
    // - 在页面首次成为当前页时启动首轮只读审计；
    // - 重复调用不会启动并发任务；
    // - 无返回值。
    void requestInitialRefresh();

    // focusProcessIds 作用：
    // - 合并原连接管理页的“按进程跳转”能力；
    // - 传入空集合表示清除过滤，并切换到 TCP/UDP Cross-View；
    // - 返回：无。
    void focusProcessIds(const QSet<quint32>& processIds);

    // activateCrossView 作用：
    // - 切换到 TCP/UDP Cross-View；
    // - 供进程详情中的网络子页复用；
    // - 返回：无。
    void activateCrossView();

    // setTrackProcessHandler 作用：
    // - 合并原连接管理页“跟踪此进程”动作；
    // - handler 为空时右键菜单会禁用该动作；
    // - 返回：无。
    void setTrackProcessHandler(ProcessActionHandler handler);

    // setOpenProcessDetailHandler 作用：
    // - 合并原连接管理页“转到进程详细信息”动作；
    // - handler 为空时右键菜单会禁用该动作；
    // - 返回：无。
    void setOpenProcessDetailHandler(ProcessActionHandler handler);

    // setUdpEndpointBlockRuleHandler：
    // - 作用：由 NetworkDock 注入“NSI UDP endpoint -> 防火墙阻断规则”的预填动作；
    // - handler 为空时 UDP 菜单不显示该写操作。
    void setUdpEndpointBlockRuleHandler(UdpEndpointBlockRuleHandler handler);

private:
    // CrossViewRow：TCP/UDP 交叉视图的一行聚合结果。
    struct CrossViewRow
    {
        std::uint32_t processId = 0;
        QString processName;
        std::uint32_t tcpCount = 0;
        std::uint32_t udpCount = 0;
        QString tcpSummary;
        QString udpSummary;
    };

    // TcpEndpointRow：TCP 明细表的一行，合并 R3 连接表与 R0 endpoint 审计行。
    struct TcpEndpointRow
    {
        std::uint32_t processId = 0; // processId：连接拥有者 PID，未知时为 0。
        QString processName;         // processName：R3 进程名或 R0 PID 提示。
        QString localEndpointText;   // localEndpointText：本地 IP:Port。
        QString remoteEndpointText;  // remoteEndpointText：远端 IP:Port。
        QString stateText;           // stateText：TCP 状态或协议状态。
        QString detailText;          // detailText：来源、对象地址、字段掩码等可复制明细。
        bool isR0Snapshot = false;    // isR0Snapshot：true 表示驱动只读快照行。
        bool canTerminate = false;    // canTerminate：仅 R3 IPv4 活动连接允许 DELETE_TCB。
        ks::network::TcpConnectionRecord connectionRecord; // connectionRecord：终止动作使用的原始四元组。
    };

    // UdpEndpointRow：UDP 明细表的一行，展示本地端点与来源诊断。
    struct UdpEndpointRow
    {
        std::uint32_t processId = 0; // processId：端点拥有者 PID，未知时为 0。
        QString processName;         // processName：R3 进程名或 R0 PID 提示。
        QString localEndpointText;   // localEndpointText：本地 IP:Port。
        QString sourceText;          // sourceText：R3/R0 数据来源。
        QString detailText;          // detailText：对象地址、字段掩码等可复制明细。
    };

    // AfdHandleRow：AFD 关联句柄的一行展示结果。
    struct AfdHandleRow
    {
        std::uint32_t processId = 0;
        QString processName;
        QString handleValueText;
        QString typeName;
        QString objectName;
        QString sourceText;
        QString diffText;
        QString accessText;
        QString detailText;
    };

    // WfpProviderRow：WFP provider 一行展示结果。
    struct WfpProviderRow
    {
        QString nameText;
        QString descriptionText;
        QString guidText;
        QString flagsText;
        QString serviceNameText;
        QString dataSizeText;
    };

    // WfpSubLayerRow：WFP sublayer 一行展示结果。
    struct WfpSubLayerRow
    {
        QString nameText;
        QString descriptionText;
        QString guidText;
        QString flagsText;
        QString providerGuidText;
        QString weightText;
    };

    // WfpCalloutRow：WFP callout 一行展示结果。
    struct WfpCalloutRow
    {
        QString nameText;
        QString descriptionText;
        QString guidText;
        QString flagsText;
        QString providerGuidText;
        QString layerGuidText;
        QString calloutIdText;
    };

    // WfpFilterRow：WFP filter 一行展示结果。
    struct WfpFilterRow
    {
        QString nameText;
        QString descriptionText;
        QString guidText;
        QString flagsText;
        QString providerGuidText;
        QString layerGuidText;
        QString subLayerGuidText;
        QString weightText;
        QString actionText;
        QString conditionText;
        QString filterIdText;
    };

    // NdisAdapterRow：NDIS miniport/adapter 一行展示结果。
    struct NdisAdapterRow
    {
        QString nameText;
        QString descriptionText;
        QString ifIndexText;
        QString statusText;
        QString macText;
        QString linkSpeedText;
        QString connectionStateText;
    };

    // NdisBindingRow：NDIS binding 一行展示结果。
    struct NdisBindingRow
    {
        QString adapterNameText;
        QString displayNameText;
        QString componentIdText;
        QString enabledText;
        QString instanceIdText;
    };

    // NdisProtocolRow：NDIS protocol / interface 一行展示结果。
    struct NdisProtocolRow
    {
        QString interfaceAliasText;
        QString ifIndexText;
        QString addressFamilyText;
        QString connectionStateText;
        QString interfaceMetricText;
        QString mtuText;
    };

    // NdisUnknownRow：驱动无法证明具体 NDIS 对象边界时保留的降级证据。
    // 这类行不得投影成 Miniport/Filter/Protocol/Binding 中的任意一种。
    struct NdisUnknownRow
    {
        QString kindText;
        QString componentText;
        QString ownerModuleText;
        QString objectAddressText;
        QString detailText;
    };

    // NsiSummaryRow：NSI 摘要的一行展示结果。
    struct NsiSummaryRow
    {
        QString metricText;
        QString valueText;
    };

    // R0NetworkSummaryRow：R0 网络审计 wrapper 的一行摘要。
    // 输入：由 buildAuditSnapshot 调用 ArkDriverClient 后填充。
    // 处理：UI 只展示 ok/unsupported/unavailable、计数、截断和 message。
    // 返回：结构体无函数返回，refreshNsiSummaryTable 会把它转换成表格行。
    struct R0NetworkSummaryRow
    {
        QString nameText;
        QString statusText;
        QString countText;
        QString truncatedText;
        QString messageText;
    };

    // AuditSnapshot：一次刷新需要的全部只读审计快照。
    struct AuditSnapshot
    {
        std::vector<TcpEndpointRow> tcpEndpointRows;
        std::vector<UdpEndpointRow> udpEndpointRows;
        std::vector<CrossViewRow> crossViewRows;
        std::vector<AfdHandleRow> afdRows;
        std::vector<WfpProviderRow> wfpProviderRows;
        std::vector<WfpSubLayerRow> wfpSubLayerRows;
        std::vector<WfpCalloutRow> wfpCalloutRows;
        std::vector<WfpFilterRow> wfpFilterRows;
        std::vector<NdisAdapterRow> ndisAdapterRows;
        std::vector<NdisBindingRow> ndisBindingRows;
        std::vector<NdisProtocolRow> ndisProtocolRows;
        std::vector<NdisUnknownRow> ndisUnknownRows;
        std::vector<NsiSummaryRow> nsiSummaryRows;
        std::vector<R0NetworkSummaryRow> r0SummaryRows;
        QString r0TcpStatusText;
        QString r0UdpStatusText;
        QString statusText;
        QString detailText;
    };

    // initializeUi 作用：
    // - 构建顶部控制栏和四个审计分区；
    // - 输入：无；
    // - 返回：无。
    void initializeUi();

    // initializeConnections 作用：
    // - 连接刷新按钮和表格交互；
    // - 输入：无；
    // - 返回：无。
    void initializeConnections();

    // refreshAllSnapshotsAsync 作用：
    // - 后台一次性采集全部只读审计快照；
    // - forceRefresh 表示用户主动刷新；
    // - 返回：无，结果通过 UI 线程回投。
    void refreshAllSnapshotsAsync(bool forceRefresh);

    // refreshCrossViewAsync 作用：
    // - 原连接管理页的 2.2 秒自动刷新只枚举 R3 TCP/UDP；
    // - 保留最近一次完整审计取得的 R0 行，避免反复采集 AFD/WFP/NDIS；
    // - 返回：无。
    void refreshCrossViewAsync();

    // applySnapshot 作用：
    // - 将后台采集完成的全部快照写回各个表格；
    // - 输入 snapshot：后台线程采集结果；
    // - 返回：无。
    void applySnapshot(const AuditSnapshot& snapshot);

    // refreshCrossViewTable 作用：
    // - 重建 TCP/UDP 明细表和进程维度交叉视图表格；
    // - 输入 snapshot：来自后台的完整网络快照；
    // - 返回：无。
    void refreshCrossViewTable(const AuditSnapshot& snapshot);

    // terminateSelectedTcpConnection 作用：
    // - 终止 Cross-View 中选中的 R3 IPv4 TCP 活动连接；
    // - R0 快照行、IPv6、LISTEN 等会给出明确不可用原因；
    // - 返回：无。
    void terminateSelectedTcpConnection();

    // showCrossViewContextMenu 作用：
    // - 为 TCP/UDP 表提供复制、刷新、进程跟踪、进程详情、扫描、终止和清除 PID 筛选；
    // - 菜单显式应用主题样式；
    // - 返回：无。
    void showCrossViewContextMenu(QTableWidget* tableWidget, const QPoint& localPosition);

    // resolveProcessIcon 作用：
    // - 只读取 PID 图标缓存，绝不在建表主链路里做 OpenProcess / Shell 图标提取；
    // - 缓存未命中时先返回占位图标，并提交一次后台解析任务；
    // - 输入 processId：目标进程 PID；
    // - 返回：缓存图标或占位图标。
    QIcon resolveProcessIcon(std::uint32_t processId);

    // scheduleProcessIconResolution 作用：
    // - 把某个 PID 的可执行路径查询与 Shell 图标提取提交到全局线程池；
    // - 同一 PID 通过 m_processIconPendingPidSet 去重，避免建表三张表重复投递；
    // - 输入 processId：目标进程 PID；
    // - 返回：无。只能在 UI 线程调用。
    void scheduleProcessIconResolution(std::uint32_t processId);

    // applyProcessIconResolutionResult 作用：
    // - 接收后台线程回投的图标位图，构造 QIcon 写入缓存并补齐已经落表的同 PID 行；
    // - 输入 processId：目标进程 PID；
    // - 输入 iconImage：后台提取到的位图，空位图表示解析失败并回退占位图标；
    // - 返回：无。只能在 UI 线程调用。
    void applyProcessIconResolutionResult(std::uint32_t processId, QImage iconImage);

    // updateCrossViewActionState 作用：
    // - 按 TCP 选择与 PID 筛选状态更新按钮；
    // - 返回：无。
    void updateCrossViewActionState();

    // refreshAfdTable 作用：
    // - 重建 AFD 相关句柄表格；
    // - 输入 snapshot：来自后台的 AFD 句柄结果；
    // - 返回：无。
    void refreshAfdTable(const std::vector<AfdHandleRow>& snapshot);

    // refreshWfpTables 作用：
    // - 重建 WFP provider / sublayer / callout / filter 四张只读表；
    // - 输入 snapshot：来自后台的 WFP 目录结果；
    // - 返回：无。
    void refreshWfpTables(const AuditSnapshot& snapshot);

    // refreshNdisTables 作用：
    // - 重建 NDIS miniport / binding / protocol 表；
    // - 输入 snapshot：来自后台的 NDIS 结果；
    // - 返回：无。
    void refreshNdisTables(const AuditSnapshot& snapshot);

    // refreshNsiSummaryTable 作用：
    // - 重建 NSI 与 R0 网络审计摘要表；
    // - 输入 snapshot：来自后台的完整快照；
    // - 返回：无。
    void refreshNsiSummaryTable(const AuditSnapshot& snapshot);

    // buildAuditSnapshot 作用：
    // - 在后台线程中采集所有只读审计数据；
    // - 返回：完整快照与状态文本。
    static AuditSnapshot buildAuditSnapshot(bool crossViewOnly = false);

    // runPowerShellTextSync 作用：
    // - 同步执行 PowerShell 并返回 stdout 文本；
    // - scriptText 为要执行的脚本；
    // - timeoutMs 为等待超时时间；
    // - 返回：stdout；失败时返回诊断文本。
    static QString runPowerShellTextSync(const QString& scriptText, int timeoutMs, QString* errorTextOut = nullptr);

    // createCell 作用：
    // - 创建统一的只读表格单元格；
    // - 输入 cellText：单元格文本；
    // - 返回：可直接写入表格的 item。
    static QTableWidgetItem* createCell(const QString& cellText);

    // guidToText 作用：
    // - 把 GUID 格式化为可读字符串；
    // - 输入 guid：Windows GUID；
    // - 返回：字符串化 GUID。
    static QString guidToText(const GUID& guid);

    // bytesToHexText 作用：
    // - 把一段字节数格式化为十六进制显示；
    // - 输入 value：待格式化数值；
    // - 返回：十六进制字符串。
    static QString bytesToHexText(std::uint64_t value);

    // objectToText 作用：
    // - 把 PowerShell JSON 值转换为稳定文本；
    // - 输入 value：JSON 值；
    // - 返回：稳定展示文本。
    static QString objectToText(const QJsonValue& value);

    // compareContainsAfd 作用：
    // - 判断对象名称是否属于 AFD 相关对象；
    // - 输入 objectNameText：对象名；
    // - 返回：true=命中 AFD。
    static bool compareContainsAfd(const QString& objectNameText);

    // top-level tabs / controls.
    QVBoxLayout* m_rootLayout = nullptr;
    QHBoxLayout* m_headerLayout = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTabWidget* m_sectionTabWidget = nullptr;

    // TCP / UDP cross-view.
    QWidget* m_crossViewPage = nullptr;
    QSplitter* m_crossViewSplitter = nullptr;
    QSplitter* m_crossViewTopSplitter = nullptr;
    QHBoxLayout* m_crossControlLayout = nullptr;
    QPushButton* m_crossAutoRefreshButton = nullptr;
    QPushButton* m_crossTerminateButton = nullptr;
    QPushButton* m_clearProcessFilterButton = nullptr;
    QLabel* m_crossFilterLabel = nullptr;
    QTableWidget* m_tcpTable = nullptr;
    QTableWidget* m_udpTable = nullptr;
    QTableWidget* m_crossSummaryTable = nullptr;

    // AFD view.
    QWidget* m_afdPage = nullptr;
    QTableWidget* m_afdTable = nullptr;

    // WFP view.
    QWidget* m_wfpPage = nullptr;
    QTabWidget* m_wfpTabWidget = nullptr;
    QTableWidget* m_wfpProviderTable = nullptr;
    QTableWidget* m_wfpSubLayerTable = nullptr;
    QTableWidget* m_wfpCalloutTable = nullptr;
    QTableWidget* m_wfpFilterTable = nullptr;

    // NDIS view.
    QWidget* m_ndisPage = nullptr;
    QTabWidget* m_ndisTabWidget = nullptr;
    QTableWidget* m_ndisAdapterTable = nullptr;
    QTableWidget* m_ndisBindingTable = nullptr;
    QTableWidget* m_ndisProtocolTable = nullptr;
    QTableWidget* m_ndisUnknownTable = nullptr;

    // NSI summary.
    QWidget* m_nsiPage = nullptr;
    QTableWidget* m_nsiSummaryTable = nullptr;

    QTimer* m_crossAutoRefreshTimer = nullptr; // 原连接管理页自动刷新能力。
    QSet<quint32> m_processFilterSet; // 进程页带入的独立 PID 筛选。
    std::vector<TcpEndpointRow> m_tcpEndpointCache; // UI 行通过 UserRole 回查终止参数。
    std::vector<UdpEndpointRow> m_udpEndpointCache; // 最近一次 UDP 快照，保留 R0 行使用。
    QString m_r0TcpStatusText; // 最近一次完整 R0 TCP 查询的协议状态，不把零行误报为成功。
    QString m_r0UdpStatusText; // 最近一次完整 R0 UDP 查询的协议状态。
    QHash<quint32, QIcon> m_processIconCache; // PID -> 真实进程图标缓存。
    QSet<quint32> m_processIconPendingPidSet; // 正在后台解析图标的 PID，避免重复投递。
    ProcessActionHandler m_trackProcessHandler; // 原连接页“跟踪此进程”实现。
    ProcessActionHandler m_openProcessDetailHandler; // 原连接页“转到进程详细信息”实现。
    UdpEndpointBlockRuleHandler m_udpEndpointBlockRuleHandler; // NSI UDP endpoint 的未来流量阻断预填。
    std::shared_ptr<NetworkAuditAsyncState> m_asyncState; // 跨线程回投共享状态；析构先清空 owner。
    std::atomic_bool m_refreshInProgress{ false };
    std::atomic_bool m_initialRefreshRequested{ false };
};
