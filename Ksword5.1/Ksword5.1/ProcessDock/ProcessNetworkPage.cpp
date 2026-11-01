#include "ProcessNetworkPage.h"
#include "ProcessNetworkController.h"
#include "../../../shared/usermode/backend/network/NetworkPolicy.h"
#include "../ArkDriverClient/ArkDriverNetworkPolicy.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/FlowLayout.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ResultTableHost.h"
#include "../UI/TablePresentation.h"
#include "../UI/ToolbarMetrics.h"
#include <QAbstractTableModel>
#include <QCheckBox>
#include <QCryptographicHash>
#include <QComboBox>
#include <QDateTime>
#include <QEvent>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QStandardItemModel>
#include <QSplitter>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <deque>
#include <array>
#include <cmath>

namespace {
using Controller = ks::network::ProcessNetworkController;
using Packet = ks::network::PacketRecord;
using Target = ks::network::ProcessNetworkTarget;
using Connection = ks::r3::network::ConnectionEntry;
using Result = ks::network::ProcessNetworkResult;
QString T(const char* source) { return ks::i18n::sourceText(QString::fromUtf8(source)); }
QString messageText(const QString& value) {
    const auto language = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
    return language.packedSourceText(language.displayText(value));
}
QString sourceKey(const char* source) { return QStringLiteral("source.") + QString::fromLatin1(QCryptographicHash::hash(QByteArray(source), QCryptographicHash::Sha1).toHex().left(16)); }
template<class Widget> Widget* translated(Widget* widget, const char* source) {
    ks::i18n::LanguageManager::instance().bindText(widget, sourceKey(source), QString::fromUtf8(source)); return widget;
}
QString endpointText(QString address, std::uint16_t port) { return (address.contains(QLatin1Char(':')) ? QLatin1Char('[') + address + QLatin1Char(']') : address) + QLatin1Char(':') + QString::number(port); }
QString endpoint(const std::string& address, std::uint16_t port) { return endpointText(QString::fromStdString(address), port); }
QString endpoint(const std::wstring& address, std::uint16_t port) { return endpointText(QString::fromStdWString(address), port); }
QString direction(ks::network::PacketDirection value) {
    return value == ks::network::PacketDirection::Outbound ? T("上行") : value == ks::network::PacketDirection::Inbound ? T("下行") : T("方向未知");
}
class PacketModel final : public QAbstractTableModel {
public:
    explicit PacketModel(QObject* parent) : QAbstractTableModel(parent) {}
    std::deque<Packet> rows;
    std::uint64_t evicted = 0;
    int rowCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : static_cast<int>(rows.size()); }
    int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : 8; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole || section < 0 || section >= 8) return {};
        const char* labels[] = {"时间", "方向", "协议", "本地地址", "远端地址", "报文长度", "已保留字节", "远端主机"}; return T(labels[section]);
    }
    QVariant data(const QModelIndex& index, int role) const override {
        if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() || role != Qt::DisplayRole) return {};
        const auto& packet = rows[static_cast<std::size_t>(index.row())];
        switch (index.column()) {
        case 0: return QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(packet.captureTimestampMs)).toString(QStringLiteral("HH:mm:ss.zzz"));
        case 1: return direction(packet.direction);
        case 2: return QString::fromStdString(ks::network::PacketProtocolToString(packet.protocol));
        case 3: return endpoint(packet.localAddress, packet.localPort);
        case 4: return endpoint(packet.remoteAddress, packet.remotePort);
        case 5: return packet.totalPacketSize;
        case 6: return static_cast<qulonglong>(packet.packetBytes.size());
        case 7: return QString::fromStdString(packet.remoteDomain);
        default: return {};
        }
    }
    void append(std::vector<Packet> packets) {
        if (packets.empty()) return;
        constexpr std::size_t maximum = 2000;
        if (packets.size() > maximum) { evicted += packets.size() - maximum; packets.erase(packets.begin(), packets.end() - maximum); }
        const auto removed = rows.size() + packets.size() > maximum ? rows.size() + packets.size() - maximum : 0;
        if (removed) { beginRemoveRows({}, 0, static_cast<int>(removed) - 1); for (std::size_t i = 0; i < removed; ++i) rows.pop_front(); evicted += removed; endRemoveRows(); }
        const int first = rowCount(); beginInsertRows({}, first, first + static_cast<int>(packets.size()) - 1);
        for (auto& packet : packets) rows.push_back(std::move(packet)); endInsertRows();
    }
    void changedLanguage() { emit headerDataChanged(Qt::Horizontal, 0, 7); if (rowCount()) emit dataChanged(index(0, 0), index(rowCount() - 1, 7)); }
};
class ConnectionModel final : public QAbstractTableModel {
public:
    explicit ConnectionModel(QObject* parent) : QAbstractTableModel(parent) {}
    std::vector<Connection> rows;
    int rowCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : static_cast<int>(rows.size()); }
    int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : 4; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole || section < 0 || section >= 4) return {};
        const char* labels[] = {"协议", "本地地址", "远端地址", "连接状态"}; return T(labels[section]);
    }
    QVariant data(const QModelIndex& index, int role) const override {
        if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() || role != Qt::DisplayRole) return {};
        const auto& row = rows[static_cast<std::size_t>(index.row())];
        switch (index.column()) {
        case 0: return row.protocol == ks::r3::network::ConnectionProtocol::Tcp4 ? QStringLiteral("TCP4") : row.protocol == ks::r3::network::ConnectionProtocol::Tcp6 ? QStringLiteral("TCP6") : row.protocol == ks::r3::network::ConnectionProtocol::Udp4 ? QStringLiteral("UDP4") : QStringLiteral("UDP6");
        case 1: return endpoint(row.localAddress, row.localPort);
        case 2: return endpoint(row.remoteAddress, row.remotePort);
        case 3: return row.hasState ? QString::fromStdString(ks::network::connection_detail::TcpStateCodeToText(row.state)) : T("UDP 端点");
        default: return {};
        }
    }
    void publish(std::vector<Connection> value) { beginResetModel(); rows = std::move(value); endResetModel(); }
    void changedLanguage() { emit headerDataChanged(Qt::Horizontal, 0, 3); if (rowCount()) emit dataChanged(index(0, 0), index(rowCount() - 1, 3)); }
};
struct RuleRow { std::wstring id; bool qos = false; QString kind, scope, host, state; };
class RuleModel final : public QAbstractTableModel {
public:
    explicit RuleModel(QObject* parent) : QAbstractTableModel(parent) {}
    std::vector<RuleRow> rows;
    int rowCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : static_cast<int>(rows.size()); }
    int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : 4; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole || section < 0 || section >= 4) return {};
        const char* labels[] = {"策略类型", "作用范围", "主机或上限", "状态"}; return T(labels[section]);
    }
    QVariant data(const QModelIndex& index, int role) const override {
        if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() || role != Qt::DisplayRole) return {};
        const auto& row = rows[static_cast<std::size_t>(index.row())];
        switch (index.column()) { case 0: return ks::i18n::LanguageManager::instance().displayText(row.kind); case 1: return ks::i18n::LanguageManager::instance().displayText(row.scope); case 2: return row.host; case 3: return ks::i18n::LanguageManager::instance().displayText(row.state); default: return {}; }
    }
    void publish(std::vector<RuleRow> value) { beginResetModel(); rows = std::move(value); endResetModel(); }
    void changedLanguage() { emit headerDataChanged(Qt::Horizontal, 0, 3); if (rowCount()) emit dataChanged(index(0, 0), index(rowCount() - 1, 3)); }
};
QTableView* table(QWidget* parent, QAbstractItemModel* model, const QStringList& keys) {
    auto* view = new ks::ui::TableActionTableView(parent); view->setModel(model); view->setSelectionBehavior(QAbstractItemView::SelectRows); view->setSelectionMode(QAbstractItemView::SingleSelection);
    view->setEditTriggers(QAbstractItemView::NoEditTriggers); view->verticalHeader()->hide(); view->setWordWrap(false);
    view->horizontalHeader()->setStretchLastSection(true); QList<ks::ui::ResultTableColumn> columns;
    for (int i = 0; i < keys.size(); ++i) columns.append({i, keys[i]});
    ks::ui::ResultTableCapabilities capabilities; capabilities.actionBar = ks::ui::TableActionBarMode::Compact; capabilities.headerClickSorting = false;
    ks::ui::ResultTableHost::ensure(view)->bindModel(model, columns, capabilities); ks::ui::ApplyTablePresentation(view); return view;
}
}

struct ProcessNetworkPage::State {
    Target target;
    std::shared_ptr<Controller> controller;
    ks::ui::AsyncOperation *captureOperation = nullptr, *connectionOperation = nullptr, *policyOperation = nullptr, *policyListOperation = nullptr, *exportOperation = nullptr;
    QPushButton *start = nullptr, *stop = nullptr, *fullMonitor = nullptr, *refresh = nullptr, *disconnect = nullptr, *pcap = nullptr, *dump = nullptr, *hostBlock = nullptr, *internetBlock = nullptr, *applyLimit = nullptr, *refreshRules = nullptr, *removeRule = nullptr;
    QComboBox* backend = nullptr;
    QLineEdit* host = nullptr;
    QCheckBox* globalHost = nullptr;
    QSpinBox* rateLimit = nullptr;
    QLabel *targetLabel = nullptr, *rateLabel = nullptr, *captureStatus = nullptr, *connectionStatus = nullptr, *policyStatus = nullptr, *actionStatus = nullptr;
    QTabWidget* tabs = nullptr;
    QTableView *packets = nullptr, *connections = nullptr, *rules = nullptr;
    PacketModel* packetModel = nullptr;
    ConnectionModel* connectionModel = nullptr;
    RuleModel* ruleModel = nullptr;
    CodeEditorWidget *payload = nullptr, *logs = nullptr;
    QTimer* timer = nullptr;
    std::uint64_t ticks = 0;
    bool captureRequested = false;
    double receivedRate = 0, sentRate = 0;
    bool rateKnown = false;
    bool firewallAvailable = false, driverAvailable = false, qosAvailable = false;
    std::vector<Packet> pendingPackets;
    std::uint64_t pendingDropped = 0;
};
ProcessNetworkPage::ProcessNetworkPage(const ks::process::ProcessRecord& target, QWidget* parent) : QWidget(parent), m_state(std::make_unique<State>())
{
    setObjectName(QStringLiteral("process_network_page"));
    setProperty("ksword_detail_keep_layout", true); // The shared parameter workspace owns this embedded monitor.
    auto& s = *m_state;
    s.target = {target.pid, target.creationTime100ns, QString::fromStdString(target.imagePath).toStdWString()};
    s.controller = std::make_shared<Controller>(s.target);
    s.captureOperation = new ks::ui::AsyncOperation(this); s.connectionOperation = new ks::ui::AsyncOperation(this);
    s.policyOperation = new ks::ui::AsyncOperation(this); s.policyListOperation = new ks::ui::AsyncOperation(this); s.exportOperation = new ks::ui::AsyncOperation(this);
    auto* root = new QVBoxLayout(this); root->setContentsMargins(0, 0, 0, 0);
    auto* workspace = new ks::ui::ParameterWorkspace(this, 360); root->addWidget(workspace);
    ks::ui::StyleWorkspacePage(this, 0); ks::ui::StyleWorkspaceContentFrame(this, 6);
    auto* scope = translated(new QGroupBox(this), "当前进程"); auto* scopeLayout = new QVBoxLayout(scope);
    s.targetLabel = new QLabel(scope); s.targetLabel->setWordWrap(true); s.targetLabel->setTextFormat(Qt::PlainText);
    s.targetLabel->setText(QStringLiteral("%1 · PID %2\n%3").arg(QString::fromStdString(target.processName)).arg(target.pid).arg(QString::fromStdString(target.imagePath)));
    scopeLayout->addWidget(s.targetLabel);
    auto* scopeNote = translated(new QLabel(scope), "速率来自进程采样；报文和连接均限定当前进程实例。开始捕获后可切换页面，停止或关闭本页会释放本页的捕获订阅。"); scopeNote->setWordWrap(true); scopeLayout->addWidget(scopeNote);
    s.fullMonitor = translated(new QPushButton(scope), "打开完整网络监控"); scopeLayout->addWidget(s.fullMonitor);
    ks::ui::StyleParameterSection(scope); workspace->parameters()->addWidget(scope);
    auto* policy = translated(new QGroupBox(this), "主机屏蔽与联网控制"); auto* policyLayout = new QVBoxLayout(policy);
    s.backend = new QComboBox(policy); s.backend->addItems({T("防火墙"), T("驱动 WFP")}); policyLayout->addWidget(s.backend);
    ks::i18n::LanguageManager::instance().bindComboBoxItem(s.backend, 0, sourceKey("防火墙"), QStringLiteral("防火墙"));
    ks::i18n::LanguageManager::instance().bindComboBoxItem(s.backend, 1, sourceKey("驱动 WFP"), QStringLiteral("驱动 WFP"));
    auto* policyNote = translated(new QLabel(policy), "防火墙按程序路径匹配同映像全部实例；驱动规则按当前进程实例匹配。全局主机规则会影响所有程序。"); policyNote->setWordWrap(true); policyLayout->addWidget(policyNote);
    s.host = new QLineEdit(policy); s.host->setPlaceholderText(T("主机名、IP 或 CIDR")); policyLayout->addWidget(s.host);
    ks::i18n::LanguageManager::instance().bindPlaceholder(s.host, sourceKey("主机名、IP 或 CIDR"), QStringLiteral("主机名、IP 或 CIDR"));
    s.globalHost = translated(new QCheckBox(policy), "对所有程序屏蔽该主机"); policyLayout->addWidget(s.globalHost);
    s.hostBlock = translated(new QPushButton(policy), "屏蔽主机"); policyLayout->addWidget(s.hostBlock);
    s.internetBlock = translated(new QPushButton(policy), "阻止当前程序联网"); policyLayout->addWidget(s.internetBlock);
    ks::ui::ApplyFlatButtonTheme(s.hostBlock, ks::ui::FlatButtonTone::Danger); ks::ui::ApplyFlatButtonTheme(s.internetBlock, ks::ui::FlatButtonTone::Danger);
    ks::ui::StyleParameterSection(policy); workspace->parameters()->addWidget(policy);
    auto* limit = translated(new QGroupBox(this), "带宽限制"); auto* limitLayout = new QVBoxLayout(limit);
    auto* limitLabel = translated(new QLabel(limit), "上行上限（KiB/s）："); limitLayout->addWidget(limitLabel);
    s.rateLimit = new QSpinBox(limit); s.rateLimit->setRange(1, 1000000); s.rateLimit->setValue(1024); limitLabel->setBuddy(s.rateLimit); limitLayout->addWidget(s.rateLimit);
    auto* limitNote = translated(new QLabel(limit), "Windows QoS 对同一路径的程序实例限制上行，不挂起进程，也不限制下行。可在策略页移除限制。"); limitNote->setWordWrap(true); limitLayout->addWidget(limitNote);
    s.applyLimit = translated(new QPushButton(limit), "应用上行限制"); limitLayout->addWidget(s.applyLimit);
    ks::ui::StyleParameterSection(limit); workspace->parameters()->addWidget(limit); workspace->parameters()->addStretch();
    s.start = translated(new QPushButton(this), "开始捕获"); s.stop = translated(new QPushButton(this), "停止捕获");
    ks::ui::ApplyFlatButtonTheme(s.start, ks::ui::FlatButtonTone::Accent); workspace->actions()->addWidget(s.start); workspace->actions()->addWidget(s.stop); ks::ui::NormalizeToolbarRow(workspace->actions());
    auto* header = new QWidget(this); auto* headerLayout = new QVBoxLayout(header); headerLayout->setContentsMargins(8, 4, 8, 4);
    s.rateLabel = new QLabel(header); s.rateLabel->setWordWrap(true); headerLayout->addWidget(s.rateLabel);
    s.captureStatus = new QLabel(header); s.captureStatus->setText(T("尚未开始捕获。")); s.captureStatus->setWordWrap(true); headerLayout->addWidget(s.captureStatus);
    s.actionStatus = new QLabel(header); s.actionStatus->setWordWrap(true); s.actionStatus->setTextFormat(Qt::PlainText); s.actionStatus->hide(); headerLayout->addWidget(s.actionStatus);
    workspace->results()->addWidget(header);
    s.tabs = new QTabWidget(this); ks::ui::StyleJoinedResultTabs(s.tabs, header); workspace->results()->addWidget(s.tabs, 1);
    auto* packetPage = new QWidget(s.tabs); auto* packetLayout = new QVBoxLayout(packetPage); packetLayout->setContentsMargins(0, 0, 0, 0); packetLayout->setSpacing(6);
    auto* packetToolbar = new QWidget(packetPage); ks::ui::StylePrimaryToolbar(packetToolbar); auto* packetTools = new ks::ui::FlowLayout(packetToolbar, 0, 8, 6);
    s.pcap = translated(new QPushButton(packetToolbar), "导出 PCAP"); s.dump = translated(new QPushButton(packetToolbar), "导出数据 Dump"); packetTools->addWidget(s.pcap); packetTools->addWidget(s.dump); ks::ui::NormalizeToolbarControl(s.pcap); ks::ui::NormalizeToolbarControl(s.dump); packetLayout->addWidget(packetToolbar);
    auto* split = new QSplitter(Qt::Vertical, packetPage); s.packetModel = new PacketModel(this); s.packets = table(split, s.packetModel, {"time", "direction", "protocol", "local", "remote", "wire", "retained", "host"}); s.packets->setColumnWidth(3, 200); s.packets->setColumnWidth(4, 200);
    s.payload = new CodeEditorWidget(split); s.payload->setReadOnly(true); s.payload->setReadOnlyExportEnabled(true); split->setStretchFactor(0, 2); split->setStretchFactor(1, 1); packetLayout->addWidget(split, 1); s.tabs->addTab(packetPage, T("报文与内容"));
    auto* connectionPage = new QWidget(s.tabs); auto* connectionLayout = new QVBoxLayout(connectionPage); connectionLayout->setContentsMargins(0, 0, 0, 0); connectionLayout->setSpacing(6);
    auto* connectionToolbar = new QWidget(connectionPage); ks::ui::StylePrimaryToolbar(connectionToolbar); auto* connectionTools = new ks::ui::FlowLayout(connectionToolbar, 0, 8, 6);
    s.refresh = translated(new QPushButton(connectionToolbar), "刷新连接"); s.disconnect = translated(new QPushButton(connectionToolbar), "断开所选连接"); connectionTools->addWidget(s.refresh); connectionTools->addWidget(s.disconnect); ks::ui::NormalizeToolbarControl(s.refresh); ks::ui::NormalizeToolbarControl(s.disconnect); ks::ui::ApplyFlatButtonTheme(s.disconnect, ks::ui::FlatButtonTone::Danger); connectionLayout->addWidget(connectionToolbar);
    s.connectionStatus = new QLabel(connectionPage); s.connectionStatus->setWordWrap(true); connectionLayout->addWidget(s.connectionStatus);
    s.connectionModel = new ConnectionModel(this); s.connections = table(connectionPage, s.connectionModel, {"protocol", "local", "remote", "state"}); connectionLayout->addWidget(s.connections, 1); s.tabs->addTab(connectionPage, T("连接"));
    auto* rulePage = new QWidget(s.tabs); auto* ruleLayout = new QVBoxLayout(rulePage); ruleLayout->setContentsMargins(0, 0, 0, 0); ruleLayout->setSpacing(6);
    auto* ruleToolbar = new QWidget(rulePage); ks::ui::StylePrimaryToolbar(ruleToolbar); auto* ruleTools = new ks::ui::FlowLayout(ruleToolbar, 0, 8, 6);
    s.refreshRules = translated(new QPushButton(ruleToolbar), "刷新策略"); s.removeRule = translated(new QPushButton(ruleToolbar), "移除所选策略"); ruleTools->addWidget(s.refreshRules); ruleTools->addWidget(s.removeRule); ks::ui::NormalizeToolbarControl(s.refreshRules); ks::ui::NormalizeToolbarControl(s.removeRule); ruleLayout->addWidget(ruleToolbar);
    s.policyStatus = new QLabel(rulePage); s.policyStatus->setWordWrap(true); ruleLayout->addWidget(s.policyStatus); s.ruleModel = new RuleModel(this); s.rules = table(rulePage, s.ruleModel, {"kind", "scope", "host", "state"}); ruleLayout->addWidget(s.rules, 1); s.tabs->addTab(rulePage, T("策略"));
    s.logs = new CodeEditorWidget(this); s.logs->setReadOnly(true); s.logs->setReadOnlyExportEnabled(true); s.logs->setMaximumBlockCount(2000); s.tabs->addTab(s.logs, T("操作记录"));
    for (const auto& entry : std::array<std::pair<QWidget*, const char*>, 4>{{{packetPage, "报文与内容"}, {connectionPage, "连接"}, {rulePage, "策略"}, {s.logs, "操作记录"}}})
        ks::i18n::LanguageManager::instance().bindTab(s.tabs, entry.first, sourceKey(entry.second), QString::fromUtf8(entry.second));
    workspace->finish();
    connect(s.start, &QPushButton::clicked, this, [this] { startCapture(); }); connect(s.stop, &QPushButton::clicked, this, [this] { stopCapture(); });
    connect(s.fullMonitor, &QPushButton::clicked, this, [this] { const auto callback = openFullMonitorRequested; if (callback) callback(m_state->target.pid); });
    connect(s.refresh, &QPushButton::clicked, this, [this] { refreshConnections(); }); connect(s.disconnect, &QPushButton::clicked, this, [this] { disconnectSelected(); });
    connect(s.pcap, &QPushButton::clicked, this, [this] { exportPackets(true); }); connect(s.dump, &QPushButton::clicked, this, [this] { exportPackets(false); });
    connect(s.hostBlock, &QPushButton::clicked, this, [this] { applyHostBlock(false); }); connect(s.internetBlock, &QPushButton::clicked, this, [this] { applyHostBlock(true); });
    connect(s.applyLimit, &QPushButton::clicked, this, [this] { applyRateLimit(); }); connect(s.refreshRules, &QPushButton::clicked, this, [this] { refreshPolicies(); }); connect(s.removeRule, &QPushButton::clicked, this, [this] { removeSelectedPolicy(); });
    connect(s.packets->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this] { showPacket(); });
    connect(s.connections->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this] {
        const int row = m_state->connections->currentIndex().row();
        if (row >= 0 && row < m_state->connectionModel->rowCount()) m_state->host->setText(QString::fromStdWString(m_state->connectionModel->rows[static_cast<std::size_t>(row)].remoteAddress));
        updateButtons();
    });
    connect(s.rules->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this] { updateButtons(); });
    connect(s.globalHost, &QCheckBox::toggled, this, [this] { updateButtons(); });
    connect(s.backend, &QComboBox::currentIndexChanged, this, [this] { updateButtons(); });
    connect(s.host, &QLineEdit::textChanged, this, [this] { updateButtons(); });
    for (auto* operation : {s.captureOperation, s.connectionOperation, s.policyOperation, s.policyListOperation, s.exportOperation}) operation->setStateChangedCallback([this] { updateButtons(); });
    s.timer = new QTimer(this); s.timer->setInterval(200); connect(s.timer, &QTimer::timeout, this, [this] {
        pollPackets();
        if (++m_state->ticks % 5 == 0 && isVisible()) refreshConnections();
    }); s.timer->start();
    updateRateSnapshot(target); updateButtons(); refreshConnections(); refreshPolicies();
}
ProcessNetworkPage::~ProcessNetworkPage()
{
    shutdown();
}
void ProcessNetworkPage::shutdown()
{
    auto& s = *m_state; s.timer->stop(); s.controller->stopCapture(); s.captureRequested = false;
    for (auto* operation : {s.captureOperation, s.connectionOperation, s.policyOperation, s.policyListOperation, s.exportOperation}) operation->close();
    setEnabled(false);
}
void ProcessNetworkPage::updateRateSnapshot(const ks::process::ProcessRecord& record)
{
    auto& s = *m_state; if (record.pid != s.target.pid || record.creationTime100ns != s.target.creationTime100ns) return;
    setRates(record.netRxKBps, record.netTxKBps, record.networkUsageKnown);
}
void ProcessNetworkPage::setRates(const double receivedKiBps, const double sentKiBps, const bool known)
{
    auto& s = *m_state; s.receivedRate = receivedKiBps; s.sentRate = sentKiBps; s.rateKnown = known;
    s.rateLabel->setText(known && std::isfinite(receivedKiBps) && std::isfinite(sentKiBps) && receivedKiBps >= 0 && sentKiBps >= 0 && std::isfinite(sentKiBps + receivedKiBps) ? T("上行 %1 KiB/s    下行 %2 KiB/s    合计 %3 KiB/s")
        .arg(sentKiBps, 0, 'f', 2).arg(receivedKiBps, 0, 'f', 2).arg(sentKiBps + receivedKiBps, 0, 'f', 2)
        : T("上行 N/A    下行 N/A    合计 N/A；等待有效网络采样。"));
}
void ProcessNetworkPage::startCapture()
{
    auto& s = *m_state; if (s.captureOperation->isBusy()) return; s.captureRequested = true;
    s.captureStatus->setText(T("正在启动捕获…"));
    struct Request { std::shared_ptr<Controller> controller; std::uint64_t generation; };
    s.captureOperation->submit<Request, Result>({s.controller, s.controller->beginStartRequest()},
        [](const Request& request, const ks::ui::AsyncOperationToken&) { return request.controller->startCapture(request.generation); },
        [this](const Result& result, std::uint64_t) { m_state->captureRequested = result.success; log(result.message); m_state->captureStatus->setText(messageText(result.message)); updateButtons(); return true; },
        [this](std::exception_ptr) { m_state->captureRequested = false; m_state->controller->stopCapture(); log(T("捕获启动失败。")); updateButtons(); });
}
void ProcessNetworkPage::stopCapture()
{
    auto& s = *m_state; s.captureRequested = false; s.controller->stopCapture(); s.captureOperation->cancel(); s.captureStatus->setText(T("捕获已停止；已保留报文仍可查看和导出。")); updateButtons();
}
void ProcessNetworkPage::pollPackets()
{
    auto& s = *m_state; if (!s.captureRequested || s.captureOperation->isBusy()) return; auto batch = s.controller->takePackets();
    for (auto& packet : batch.packets) s.pendingPackets.push_back(std::move(packet));
    if (s.pendingPackets.size() > 1024) {
        const auto dropped = s.pendingPackets.size() - 1024;
        s.pendingPackets.erase(s.pendingPackets.begin(), s.pendingPackets.begin() + static_cast<std::ptrdiff_t>(dropped)); s.pendingDropped += dropped;
    }
    if (!s.pendingPackets.empty()) ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("process-network-packets"), {ks::ui::ResultTableHost::ensure(s.packets)}, [this] {
        m_state->packetModel->append(std::exchange(m_state->pendingPackets, {})); updateButtons();
    });
    if (!batch.targetAlive || !batch.active) { s.captureRequested = false; s.controller->stopCapture(); s.captureStatus->setText(T("目标进程已退出或捕获已停止；保留当前报文。")); }
    else if (!batch.serviceRunning) { s.captureRequested = false; s.controller->stopCapture(); s.captureStatus->setText(T("捕获服务已停止：%1。可点击“开始捕获”重试。").arg(messageText(batch.status))); }
    else s.captureStatus->setText(T("已保留 %1 个报文；队列丢弃 %2；历史淘汰 %3。%4")
        .arg(s.packetModel->rowCount()).arg(batch.dropped + s.pendingDropped).arg(s.packetModel->evicted).arg(messageText(batch.status)));
    updateButtons();
}
void ProcessNetworkPage::refreshConnections()
{
    auto& s = *m_state; if (s.connectionOperation->isBusy()) return;
    s.connectionOperation->submit<Target, ks::r3::network::ConnectionEnumerationResult>(s.target,
        [](const Target& target, const ks::ui::AsyncOperationToken&) { return Controller::connections(target); },
        [this](const auto& result, std::uint64_t generation) {
            const auto snapshot = std::make_shared<const ks::r3::network::ConnectionEnumerationResult>(result);
            const auto submission = ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("process-network-connections"), {ks::ui::ResultTableHost::ensure(m_state->connections)}, [this, snapshot, generation] {
                if (!m_state->connectionOperation->isCurrent(generation)) return;
                if (snapshot->success) m_state->connectionModel->publish(snapshot->entries);
                const auto diagnostic = ks::i18n::LanguageManager::instance().displayText(QString::fromStdWString(snapshot->diagnosticText));
                m_state->connectionStatus->setText(snapshot->success ? T("当前连接：%1。%2").arg(snapshot->entries.size()).arg(diagnostic) : diagnostic);
                updateButtons(); m_state->connectionOperation->completeDeferred(generation);
            });
            return submission != ks::ui::UiCommitSubmission::Deferred;
        }, [this](std::exception_ptr) { m_state->connectionStatus->setText(T("连接读取失败，请刷新重试。")); });
}
void ProcessNetworkPage::disconnectSelected()
{
    auto& s = *m_state; const int row = s.connections->currentIndex().row();
    if (s.policyOperation->isBusy() || row < 0 || row >= s.connectionModel->rowCount()) return;
    struct Request { Target target; Connection connection; };
    s.policyOperation->submitTransaction<Request, Result>({s.target, s.connectionModel->rows[static_cast<std::size_t>(row)]},
        [](const Request& request) { return Controller::disconnect(request.target, request.connection); },
        [this](const Result& result, std::uint64_t) { log(result.message); refreshConnections(); return true; }, [this](std::exception_ptr) { log(T("断开连接失败。")); });
}
void ProcessNetworkPage::exportPackets(const bool pcap)
{
    auto& s = *m_state; if (s.exportOperation->isBusy() || s.packetModel->rows.empty()) return;
    const QPointer<ProcessNetworkPage> owner(this);
    const std::vector<Packet> frozen(s.packetModel->rows.cbegin(), s.packetModel->rows.cend());
    const QString path = QFileDialog::getSaveFileName(this, pcap ? T("导出 PCAP") : T("导出数据 Dump"), pcap ? QStringLiteral("process-network.pcap") : QStringLiteral("process-network.jsonl"), pcap ? QStringLiteral("PCAP (*.pcap)") : QStringLiteral("JSONL (*.jsonl)"));
    if (!owner || path.isEmpty()) return;
    struct Request { QString path; std::vector<Packet> packets; bool pcap; };
    Request request{path, frozen, pcap};
    s.exportOperation->submitTransaction<Request, Result>(std::move(request),
        [](const Request& request) { return request.pcap ? Controller::exportPcap(request.path, request.packets) : Controller::exportDump(request.path, request.packets); },
        [this](const Result& result, std::uint64_t) { log(result.message); return true; }, [this](std::exception_ptr) { log(T("报文导出失败。")); });
}
void ProcessNetworkPage::applyHostBlock(const bool wholeProcess)
{
    auto& s = *m_state; if (s.policyOperation->isBusy()) return;
    struct Request { Target target; QString host; bool all, whole, driver; };
    const Request request{s.target, s.host->text().trimmed(), s.globalHost->isChecked() && !wholeProcess, wholeProcess, s.backend->currentIndex() == 1};
    s.policyOperation->submitTransaction<Request, Result>(request,
        [](const Request& value) {
            using namespace ks::r3::network;
            ksword::ark::InstallDriverNetworkPolicies();
            NetworkBlockRequest block; block.backend = value.driver ? PolicyBackend::Driver : PolicyBackend::Firewall;
            block.scope = value.all ? PolicyScope::AllApplications : value.driver ? PolicyScope::ProcessInstance : PolicyScope::ApplicationImage;
            block.target = {value.target.pid, value.target.creationTime100ns, value.target.imagePath};
            if (!value.whole) {
                const auto resolved = ResolveNetworkHost(value.host.toStdWString());
                if (!resolved.success) return Result{false, QString::fromStdWString(resolved.diagnostic)};
                block.remotePrefixes = resolved.remotePrefixes;
            }
            const auto result = CreateNetworkBlock(block);
            return Result{result.success, QString::fromStdWString(result.diagnostic)};
        }, [this](const Result& result, std::uint64_t) { log(result.message); refreshPolicies(); return true; }, [this](std::exception_ptr) { log(T("网络阻断策略应用失败。")); });
}
void ProcessNetworkPage::applyRateLimit()
{
    auto& s = *m_state; if (s.policyOperation->isBusy()) return;
    struct Request { Target target; std::uint64_t bytes; };
    s.policyOperation->submitTransaction<Request, Result>({s.target, static_cast<std::uint64_t>(s.rateLimit->value()) * 1024},
        [](const Request& request) {
            const auto valid = Controller::validateTarget(request.target); if (!valid.success) return valid;
            ks::r3::network::QosPolicy policy; policy.applicationPath = request.target.imagePath; policy.outboundBytesPerSecond = request.bytes;
            const auto result = ks::r3::network::SaveQosPolicy(policy); return Result{result.success, QString::fromStdWString(result.diagnostic)};
        }, [this](const Result& result, std::uint64_t) { log(result.message); refreshPolicies(); return true; }, [this](std::exception_ptr) { log(T("带宽限制应用失败。")); });
}
void ProcessNetworkPage::refreshPolicies()
{
    auto& s = *m_state; if (s.policyListOperation->isBusy()) return;
    struct PolicyList { std::vector<RuleRow> rows; QString status; bool firewall = false, driver = false, qos = false; };
    s.policyListOperation->submit<int, PolicyList>(0,
        [](int, const ks::ui::AsyncOperationToken&) {
            using namespace ks::r3::network; PolicyList result;
            ksword::ark::InstallDriverNetworkPolicies();
            const auto blocks = ListNetworkBlocks(); const auto limits = ListQosPolicies();
            result.firewall = blocks.firewallAvailable; result.driver = blocks.driverAvailable; result.qos = limits.success;
            for (const auto& block : blocks.entries) {
                QStringList hosts; for (const auto& host : block.remotePrefixes) hosts.append(QString::fromStdWString(host));
                result.rows.push_back({block.policyId, false, block.backend == PolicyBackend::Driver ? QStringLiteral("驱动阻断") : QStringLiteral("防火墙阻断"),
                    block.scope == PolicyScope::AllApplications ? QStringLiteral("所有程序") : block.scope == PolicyScope::ProcessInstance
                        ? QStringLiteral("PID %1 · %2").arg(block.processId).arg(block.creationTime100ns) : QString::fromStdWString(block.applicationPath),
                    hosts.isEmpty() ? QStringLiteral("全部远端地址") : hosts.join(QStringLiteral(", ")), block.enabled && block.complete ? QStringLiteral("已启用") : QStringLiteral("未完整启用")});
            }
            for (const auto& limit : limits.entries) result.rows.push_back({limit.policyId, true, QStringLiteral("QoS"), QString::fromStdWString(limit.applicationPath), QStringLiteral("%1 KiB/s").arg(static_cast<double>(limit.outboundBytesPerSecond) / 1024.0, 0, 'f', 2), limit.enabled ? QStringLiteral("已启用") : QStringLiteral("已停用")});
            result.status = QString::fromStdWString(blocks.diagnostic + L" " + limits.diagnostic); return result;
        }, [this](const PolicyList& result, std::uint64_t generation) {
            const auto snapshot = std::make_shared<const PolicyList>(result);
            const auto submission = ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("process-network-policies"), {ks::ui::ResultTableHost::ensure(m_state->rules)}, [this, snapshot, generation] {
                if (!m_state->policyListOperation->isCurrent(generation)) return;
                m_state->firewallAvailable = snapshot->firewall; m_state->driverAvailable = snapshot->driver; m_state->qosAvailable = snapshot->qos;
                m_state->ruleModel->publish(snapshot->rows); m_state->policyStatus->setText(ks::i18n::LanguageManager::instance().displayText(snapshot->status)); updateButtons(); m_state->policyListOperation->completeDeferred(generation);
            });
            return submission != ks::ui::UiCommitSubmission::Deferred;
        },
        [this](std::exception_ptr) { m_state->policyStatus->setText(T("策略列表读取失败，请刷新重试。")); });
}
void ProcessNetworkPage::removeSelectedPolicy()
{
    auto& s = *m_state; const int row = s.rules->currentIndex().row(); if (s.policyOperation->isBusy() || row < 0 || row >= s.ruleModel->rowCount()) return;
    s.policyOperation->submitTransaction<RuleRow, Result>(s.ruleModel->rows[static_cast<std::size_t>(row)],
        [](const RuleRow& rule) { const auto result = rule.qos ? ks::r3::network::RemoveQosPolicy(rule.id) : ks::r3::network::RemoveNetworkBlock(rule.id); return Result{result.success, QString::fromStdWString(result.diagnostic)}; },
        [this](const Result& result, std::uint64_t) { log(result.message); refreshPolicies(); return true; }, [this](std::exception_ptr) { log(T("策略移除失败。")); });
}
void ProcessNetworkPage::showPacket()
{
    auto& s = *m_state; const int row = s.packets->currentIndex().row(); if (row < 0 || row >= s.packetModel->rowCount()) { s.payload->clear(); return; }
    const auto& packet = s.packetModel->rows[static_cast<std::size_t>(row)];
    s.host->setText(QString::fromStdString(packet.remoteDomain.empty() ? packet.remoteAddress : packet.remoteDomain));
    QString value = T("真实保留字节：%1 / 报文长度：%2；截断：%3；仅元数据：%4\n")
        .arg(packet.packetBytes.size()).arg(packet.totalPacketSize).arg(packet.packetBytesTruncated ? T("是") : T("否")).arg(packet.wfpAleEventNoPayload ? T("是") : T("否"));
    for (std::size_t at = 0; at < packet.packetBytes.size(); at += 16) {
        value += QStringLiteral("%1  ").arg(at, 6, 16, QLatin1Char('0'));
        for (std::size_t i = at; i < (std::min)(at + 16, packet.packetBytes.size()); ++i) value += QStringLiteral("%1 ").arg(packet.packetBytes[i], 2, 16, QLatin1Char('0'));
        value += QLatin1Char('\n');
    }
    s.payload->setRawText(value);
}
void ProcessNetworkPage::log(const QString& text)
{
    const auto message = messageText(text);
    m_state->actionStatus->setText(message); m_state->actionStatus->show();
    m_state->logs->appendRawText(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss ")) + message + QLatin1Char('\n'));
}
void ProcessNetworkPage::updateButtons()
{
    auto& s = *m_state; const bool busy = s.policyOperation->isBusy();
    const bool identified = s.target.pid && s.target.creationTime100ns;
    s.start->setEnabled(identified && !s.captureRequested && !s.captureOperation->isBusy()); s.stop->setEnabled(s.captureRequested || s.captureOperation->isBusy());
    s.refresh->setEnabled(!s.connectionOperation->isBusy());
    const bool policyTarget = identified && (s.backend->currentIndex() == 1 || !s.target.imagePath.empty());
    const bool backendAvailable = s.backend->currentIndex() == 1 ? s.driverAvailable : s.firewallAvailable;
    if (auto* model = qobject_cast<QStandardItemModel*>(s.backend->model())) {
        if (auto* item = model->item(0)) item->setEnabled(s.firewallAvailable);
        if (auto* item = model->item(1)) item->setEnabled(s.driverAvailable);
    }
    s.backend->setToolTip(backendAvailable ? QString() : T("所选策略后端当前不可用，请检查管理员权限、服务或驱动状态后刷新策略。"));
    s.hostBlock->setEnabled(!busy && backendAvailable && !s.host->text().trimmed().isEmpty() && (s.globalHost->isChecked() || policyTarget)); s.internetBlock->setEnabled(!busy && backendAvailable && policyTarget); s.applyLimit->setEnabled(!busy && s.qosAvailable && identified && !s.target.imagePath.empty());
    const int selected = s.connections->currentIndex().row();
    const bool closeable = selected >= 0 && selected < s.connectionModel->rowCount() && ks::r3::network::ConnectionCanClose(s.connectionModel->rows[static_cast<std::size_t>(selected)]);
    s.disconnect->setEnabled(!busy && closeable); s.disconnect->setToolTip(closeable ? QString() : T("选择可关闭的 IPv4 TCP 连接。IPv6 或 UDP 可通过主机屏蔽或联网阻断控制。"));
    s.pcap->setEnabled(!s.exportOperation->isBusy() && !s.packetModel->rows.empty()); s.dump->setEnabled(s.pcap->isEnabled());
    s.refreshRules->setEnabled(!s.policyListOperation->isBusy()); const int rule = s.rules->currentIndex().row(); s.removeRule->setEnabled(!busy && rule >= 0 && rule < s.ruleModel->rowCount());
}
void ProcessNetworkPage::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event); if (event->type() == QEvent::LanguageChange && m_state) retranslate();
}
void ProcessNetworkPage::retranslate()
{
    // Model data and selected packet bytes are retained across language changes.
    auto& s = *m_state; s.packetModel->changedLanguage(); s.connectionModel->changedLanguage(); s.ruleModel->changedLanguage(); setRates(s.receivedRate, s.sentRate, s.rateKnown); updateButtons();
}
