#include "NetworkQosPage.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/FlowLayout.h"
#include "../UI/MetricAreaWindow.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ResultTableHost.h"
#include "../UI/SegmentedControl.h"
#include "../UI/TablePresentation.h"
#include "../UI/ToolbarMetrics.h"
#include <QAbstractTableModel>
#include <QCheckBox>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSaveFile>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTableView>
#include <QVBoxLayout>
#include <algorithm>
#include <cmath>
namespace
{
using namespace ks::r3::network;
QString L(const char *s)
{
    return ks::i18n::sourceText(QString::fromUtf8(s));
}
QString policyMessage(const std::wstring &value)
{
    const auto language = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
    return language.packedSourceText(language.displayText(QString::fromStdWString(value)));
}
void bind(QObject *object, const char *key, const char *source)
{
    ks::i18n::LanguageManager::instance().bindText(object, QString::fromLatin1(key), QString::fromUtf8(source));
}
QString rate(const QosPolicy &p)
{
    if (!p.outboundBytesPerSecond)
        return L("未配置带宽上限");
    if (p.outboundBytesPerSecond < 1024)
        return QStringLiteral("%1 B/s").arg(p.outboundBytesPerSecond);
    return QStringLiteral("%1 KiB/s").arg(static_cast<double>(p.outboundBytesPerSecond) / 1024.0, 0, 'f', 2);
}
// KiB is binary: ten fractional decimal digits retain every integer byte.
// Trim presentation zeros without reducing the editor's stored precision.
class ByteRateSpinBox final : public QDoubleSpinBox
{
  public:
    using QDoubleSpinBox::QDoubleSpinBox;

  protected:
    QString textFromValue(double value) const override
    {
        auto numericLocale = locale();
        if (!isGroupSeparatorShown())
            numericLocale.setNumberOptions(numericLocale.numberOptions() | QLocale::OmitGroupSeparator);
        QString text = numericLocale.toString(value, 'f', 10);
        while (text.endsWith(QLatin1Char('0')))
            text.chop(1);
        if (text.endsWith(locale().decimalPoint()))
            text.chop(locale().decimalPoint().size());
        return text;
    }
};
bool parseQosDraft(const QJsonObject &row, QosPolicy &policy)
{
    const auto string = [&](const char *name, std::wstring &output, bool required = false) {
        const auto value = row.value(QString::fromLatin1(name));
        if (value.isUndefined() && !required)
        {
            output.clear();
            return true;
        }
        if (!value.isString())
            return false;
        output = value.toString().toStdWString();
        return true;
    };
    const auto integer = [&](const char *name, int fallback, int minimum, int maximum, int &output) {
        const auto value = row.value(QString::fromLatin1(name));
        if (value.isUndefined())
        {
            output = fallback;
            return true;
        }
        if (!value.isDouble() || !std::isfinite(value.toDouble()) || std::floor(value.toDouble()) != value.toDouble() ||
            value.toDouble() < minimum || value.toDouble() > maximum)
            return false;
        output = value.toInt();
        return true;
    };
    QosPolicy candidate;
    const auto rateValue = row.value(QStringLiteral("outboundBytesPerSecond"));
    if (!rateValue.isString())
        return false;
    const auto rateText = rateValue.toString();
    if (rateText.isEmpty() || !std::all_of(rateText.cbegin(), rateText.cend(),
                                           [](QChar ch) { return ch >= QLatin1Char('0') && ch <= QLatin1Char('9'); }))
        return false;
    bool parsed = false;
    candidate.outboundBytesPerSecond = rateText.toULongLong(&parsed);
    int sourceStart = 0, sourceEnd = 0, destStart = 0, destEnd = 0, protocol = 0, precedence = 127;
    if (!parsed || candidate.outboundBytesPerSecond > 1024000000000ULL ||
        !string("application", candidate.applicationPath, true) || !string("sourcePrefix", candidate.sourcePrefix) ||
        !string("destinationPrefix", candidate.destinationPrefix) || !integer("dscp", -1, -1, 63, candidate.dscp) ||
        !integer("priority8021", -1, -1, 7, candidate.priority8021) ||
        !integer("sourcePortStart", 0, 0, 65535, sourceStart) || !integer("sourcePortEnd", 0, 0, 65535, sourceEnd) ||
        !integer("destinationPortStart", 0, 0, 65535, destStart) ||
        !integer("destinationPortEnd", 0, 0, 65535, destEnd) || !integer("protocol", 0, 0, 3, protocol) ||
        !integer("precedence", 127, 0, 255, precedence))
        return false;
    const auto validPorts = [](int first, int last) {
        return (first == 0 && last == 0) || (first > 0 && last >= first);
    };
    const auto enabled = row.value(QStringLiteral("enabled"));
    if ((!enabled.isUndefined() && !enabled.isBool()) || !validPorts(sourceStart, sourceEnd) ||
        !validPorts(destStart, destEnd))
        return false;
    candidate.enabled = enabled.isUndefined() || enabled.toBool();
    candidate.sourcePortStart = static_cast<std::uint16_t>(sourceStart);
    candidate.sourcePortEnd = static_cast<std::uint16_t>(sourceEnd);
    candidate.destinationPortStart = static_cast<std::uint16_t>(destStart);
    candidate.destinationPortEnd = static_cast<std::uint16_t>(destEnd);
    candidate.protocol = static_cast<QosProtocol>(protocol);
    candidate.precedence = static_cast<std::uint32_t>(precedence);
    candidate.scope = candidate.applicationPath.empty() ? PolicyScope::AllApplications : PolicyScope::ApplicationImage;
    candidate.managed = true; // A draft never inherits the provider's writable identity.
    policy = std::move(candidate);
    return true;
}
} // namespace
class NetworkQosPage::Model final : public QAbstractTableModel
{
  public:
    explicit Model(QObject *parent) : QAbstractTableModel(parent)
    {
    }
    std::vector<QosPolicy> values;
    int rowCount(const QModelIndex &p = {}) const override
    {
        return p.isValid() ? 0 : static_cast<int>(values.size());
    }
    int columnCount(const QModelIndex &p = {}) const override
    {
        return p.isValid() ? 0 : 8;
    }
    QVariant headerData(int c, Qt::Orientation o, int role) const override
    {
        if (o != Qt::Horizontal || role != Qt::DisplayRole || c < 0 || c >= 8)
            return {};
        const char *labels[] = {"策略", "应用路径", "上行上限", "DSCP", "802.1 优先级", "状态", "协议", "策略来源"};
        return L(labels[c]);
    }
    QVariant data(const QModelIndex &i, int role = Qt::DisplayRole) const override
    {
        if (!i.isValid() || i.row() < 0 || i.row() >= rowCount())
            return {};
        const auto &p = values[static_cast<std::size_t>(i.row())];
        if (role == Qt::UserRole)
            return QString::fromStdWString(p.policyId);
        if (role != Qt::DisplayRole && role != Qt::ToolTipRole)
            return {};
        switch (i.column())
        {
        case 0:
            return QString::fromStdWString(p.policyId);
        case 1:
            return p.applicationPath.empty() ? L("全部应用") : QString::fromStdWString(p.applicationPath);
        case 2:
            return rate(p);
        case 3:
            return p.dscp < 0 ? QStringLiteral("-") : QString::number(p.dscp);
        case 4:
            return p.priority8021 < 0 ? QStringLiteral("-") : QString::number(p.priority8021);
        case 5:
            return p.enabled ? L("启用") : L("禁用");
        case 6:
            return p.protocol == QosProtocol::Any   ? L("提供者默认协议")
                   : p.protocol == QosProtocol::Tcp ? QStringLiteral("TCP")
                   : p.protocol == QosProtocol::Udp ? QStringLiteral("UDP")
                                                    : QStringLiteral("TCP + UDP");
        case 7:
            return p.managed ? L("KSword 管理") : QString::fromStdWString(p.providerOwner);
        default:
            return {};
        }
    }
    void set(std::vector<QosPolicy> input)
    {
        const QPointer<Model> owner(this);
        beginResetModel();
        if (!owner)
            return;
        values = std::move(input);
        endResetModel();
    }
    void retranslate()
    {
        emit headerDataChanged(Qt::Horizontal, 0, 7);
        if (rowCount())
            emit dataChanged(index(0, 0), index(rowCount() - 1, 7));
    }
};
NetworkQosPage::NetworkQosPage(QWidget *parent) : QWidget(parent)
{
    m_operation = new ks::ui::AsyncOperation(this);
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    ks::ui::StyleWorkspacePage(this, 0);
    ks::ui::StyleWorkspaceContentFrame(this, 6);
    auto *work = new ks::ui::ParameterWorkspace(this, 440);
    root->addWidget(work);
    auto *section = new QGroupBox(this);
    bind(section, "network.qos.target", "QoS 策略与动作");
    auto *fields = new QFormLayout(section);
    fields->setRowWrapPolicy(QFormLayout::WrapLongRows);
    const auto label = [&](const char *key, const char *source) {
        auto *l = new QLabel(section);
        bind(l, key, source);
        return l;
    };
    m_scope = new QComboBox(section);
    m_scope->addItems({L("指定应用映像（所有实例）"), L("全部应用")});
    fields->addRow(label("network.qos.scope", "应用范围："), m_scope);
    m_path = new QLineEdit(section);
    auto* pathRow = new QHBoxLayout;
    pathRow->addWidget(m_path, 1);
    m_browse = new QPushButton(section); bind(m_browse, "network.qos.browse_program", "选择程序…");
    pathRow->addWidget(m_browse); ks::ui::NormalizeToolbarRow(pathRow);
    fields->addRow(label("network.qos.path", "应用完整路径："), pathRow);
    connect(m_browse, &QPushButton::clicked, this, [this] {
        const QPointer<NetworkQosPage> owner(this);
        const QString path = QFileDialog::getOpenFileName(this, L("选择 QoS 应用程序"), m_path->text(), L("程序文件 (*.exe);;所有文件 (*)"));
        if (owner && !path.isEmpty()) m_path->setText(QDir::toNativeSeparators(path));
    });
    m_rate = new ByteRateSpinBox(section);
    m_rate->setRange(0, 1000000000);
    m_rate->setDecimals(10);
    m_rate->setSuffix(QStringLiteral(" KiB/s"));
    fields->addRow(label("network.qos.rate", "上行上限（0 不限制）："), m_rate);
    m_dscp = new QSpinBox(section);
    m_dscp->setRange(-1, 63);
    m_dscp->setSpecialValueText(L("不修改"));
    m_dscp->setValue(-1);
    fields->addRow(label("network.qos.dscp", "DSCP 标记："), m_dscp);
    m_priority = new QSpinBox(section);
    m_priority->setRange(-1, 7);
    m_priority->setSpecialValueText(L("不修改"));
    m_priority->setValue(-1);
    fields->addRow(label("network.qos.priority", "802.1 优先级："), m_priority);
    m_precedence = new QSpinBox(section);
    m_precedence->setRange(0, 255);
    m_precedence->setValue(127);
    fields->addRow(label("network.qos.precedence", "策略优先顺序："), m_precedence);
    m_enabled = new QCheckBox(section);
    m_enabled->setChecked(true);
    bind(m_enabled, "network.qos.enabled", "启用策略");
    fields->addRow(m_enabled);
    ks::ui::StyleParameterSection(section);
    work->parameters()->addWidget(section);
    auto *conditions = new QGroupBox(this);
    bind(conditions, "network.qos.conditions", "匹配条件");
    auto *formLayout = new QFormLayout(conditions);
    formLayout->setRowWrapPolicy(QFormLayout::WrapLongRows);
    const auto row = [&](const char *key, const char *text, QWidget *w) {
        auto *l = new QLabel(conditions);
        bind(l, key, text);
        formLayout->addRow(l, w);
    };
    m_protocol = new QComboBox(conditions);
    m_protocol->addItems(
        {L("提供者默认协议"), QStringLiteral("TCP"), QStringLiteral("UDP"), QStringLiteral("TCP + UDP")});
    row("network.qos.protocol", "协议：", m_protocol);
    m_source = new QLineEdit(conditions);
    row("network.qos.src_prefix", "源 IP / CIDR：", m_source);
    m_destination = new QLineEdit(conditions);
    row("network.qos.dst_prefix", "目标 IP / CIDR：", m_destination);
    const auto port = [&](const char *key, const char *text) {
        auto *p = new QSpinBox(conditions);
        p->setRange(0, 65535);
        p->setSpecialValueText(L("不限"));
        row(key, text, p);
        return p;
    };
    m_sourceStart = port("network.qos.src_port_start", "源端口起始：");
    m_sourceEnd = port("network.qos.src_port_end", "源端口结束：");
    m_destStart = port("network.qos.dst_port_start", "目标端口起始：");
    m_destEnd = port("network.qos.dst_port_end", "目标端口结束：");
    ks::ui::StyleParameterSection(conditions);
    work->parameters()->addWidget(ks::ui::FoldParameterSection(conditions));
    auto *note = new QLabel(this);
    bind(note, "network.qos.note",
         "Windows QoS 按应用映像匹配所有实例，带宽整形作用于上行。空 IP 和端口表示不额外限制；DSCP "
         "与优先级是标记，不是实测网速。系统或组策略来源在此只读。");
    note->setWordWrap(true);
    work->parameters()->addWidget(note);
    m_identity = new QLabel(this);
    m_identity->setWordWrap(true);
    m_identity->setTextFormat(Qt::PlainText);
    work->parameters()->addWidget(m_identity);
    work->parameters()->addStretch();
    m_save = new QPushButton(this);
    bind(m_save, "network.qos.save", "保存策略");
    ks::ui::ApplyFlatButtonTheme(m_save, ks::ui::FlatButtonTone::Accent);
    auto *fresh = new QPushButton(this);
    m_new = fresh;
    bind(fresh, "network.qos.new", "新建");
    work->actions()->addWidget(m_save);
    work->actions()->addWidget(fresh);
    ks::ui::NormalizeToolbarRow(work->actions());
    auto *tools = new ks::ui::FlowLayout(nullptr, 0, 8, 6);
    m_refresh = new QPushButton(this);
    m_remove = new QPushButton(this);
    m_toggle = new QPushButton(this);
    m_edit = new QPushButton(this); bind(m_edit, "network.qos.load_selected", "载入所选策略");
    m_edit->setToolTip(L("将所选策略载入编辑区并替换当前草稿；载入不会应用策略。"));
    fresh->setToolTip(L("清空编辑区并新建草稿；保存后才会应用。"));
    bind(m_refresh, "network.qos.refresh", "刷新策略");
    bind(m_remove, "network.qos.remove", "删除所选");
    bind(m_toggle, "network.qos.toggle", "启用 / 禁用");
    auto *area = new QPushButton(this);
    bind(area, "network.qos.area", "矩形面积视图");
    auto *exportButton = new QPushButton(this);
    bind(exportButton, "network.qos.export", "导出策略");
    auto *importButton = new QPushButton(this);
    bind(importButton, "network.qos.import", "导入为草稿");
    for (auto *b : {m_refresh, m_edit, m_toggle, m_remove, area, exportButton, importButton})
    {
        tools->addWidget(b);
        ks::ui::NormalizeToolbarControl(b);
    }
    work->results()->addLayout(tools);
    m_table = new QTableView(this);
    m_model = new Model(m_table);
    m_table->setModel(m_model);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->horizontalHeader()->setStretchLastSection(true);
    ks::ui::ApplyTablePresentation(m_table);
    ks::ui::ResultTableCapabilities capabilities;
    capabilities.headerClickSorting = false;
    capabilities.actionBar = ks::ui::TableActionBarMode::Compact;
    QList<ks::ui::ResultTableColumn> columns;
    for (int c = 0; c < 8; ++c)
        columns.append({c, QString::number(c)});
    ks::ui::ResultTableHost::ensure(m_table)->bindModel(m_model, columns, capabilities);
    work->results()->addWidget(m_table, 1);
    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    m_status->setTextFormat(Qt::PlainText);
    work->results()->addWidget(m_status);
    work->finish();
    connect(m_refresh, &QPushButton::clicked, this, [this] { refresh(); });
    connect(m_save, &QPushButton::clicked, this, [this] { save(); });
    connect(fresh, &QPushButton::clicked, this, [this] { reset(); });
    connect(m_remove, &QPushButton::clicked, this, [this] { remove(); });
    connect(m_toggle, &QPushButton::clicked, this, [this] { toggle(); });
    connect(exportButton, &QPushButton::clicked, this, [this] { exportPolicies(); });
    connect(importButton, &QPushButton::clicked, this, [this] {
        if (!m_operation->isBusy())
            importPolicy();
    });
    connect(m_table->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this] { selected(); });
    connect(m_edit, &QPushButton::clicked, this, [this] { if (const auto* policy = selectedPolicy()) setForm(*policy); });
    connect(m_scope, &QComboBox::currentIndexChanged, this, [this] { updateButtons(); });
    connect(area, &QPushButton::clicked, this, [this] {
        if (!m_area)
        {
            m_area = new ks::ui::MetricAreaWindow(this);
            m_area->appearanceChanged = [this] { refreshArea(); };
        }
        refreshArea();
        m_area->show();
        m_area->raise();
    });
    m_operation->setStateChangedCallback([this] { updateButtons(); });
    reset();
    refresh();
}
NetworkQosPage::~NetworkQosPage()
{
    m_operation->close();
}
void NetworkQosPage::updateButtons()
{
    const bool idle = !m_operation->isBusy();
    m_save->setEnabled(idle && m_managed);
    const auto* selected = selectedPolicy();
    m_edit->setEnabled(idle && selected);
    m_remove->setEnabled(idle && selected && selected->managed);
    m_toggle->setEnabled(m_remove->isEnabled());
    m_refresh->setEnabled(idle);
    m_new->setEnabled(idle);
    m_table->setEnabled(idle);
    for (auto *w :
         std::initializer_list<QWidget *>{m_scope, m_protocol, m_source, m_destination, m_rate, m_dscp, m_priority,
                                          m_precedence, m_sourceStart, m_sourceEnd, m_destStart, m_destEnd, m_enabled})
        w->setEnabled(idle && m_managed);
    m_path->setEnabled(idle && m_managed && m_scope->currentIndex() == 0);
    m_browse->setEnabled(m_path->isEnabled());
}
void NetworkQosPage::reset()
{
    {
        const QSignalBlocker selection(m_table->selectionModel());
        m_table->clearSelection();
        m_table->setCurrentIndex({});
    }
    m_editingId.clear();
    m_managed = true;
    m_path->clear();
    m_scope->setCurrentIndex(0);
    m_rate->setMaximum(1000000000.0);
    m_rate->setValue(0);
    m_originalRateBytes = 0;
    m_originalRateDisplay = 0;
    m_dscp->setValue(-1);
    m_priority->setValue(-1);
    m_precedence->setValue(127);
    m_source->clear();
    m_destination->clear();
    for (auto *p : {m_sourceStart, m_sourceEnd, m_destStart, m_destEnd})
        p->setValue(0);
    m_protocol->setCurrentIndex(0);
    m_enabled->setChecked(true);
    m_identity->setText(L("新建 QoS 策略草稿；保存后才会应用。"));
    updateButtons();
}
QosPolicy NetworkQosPage::form() const
{
    QosPolicy p;
    p.policyId = m_editingId.toStdWString();
    p.scope = m_scope->currentIndex() == 0 ? PolicyScope::ApplicationImage : PolicyScope::AllApplications;
    p.applicationPath = m_path->text().trimmed().toStdWString();
    if (p.scope == PolicyScope::AllApplications)
        p.applicationPath.clear();
    p.outboundBytesPerSecond = m_rate->value() == m_originalRateDisplay
                                   ? m_originalRateBytes
                                   : static_cast<std::uint64_t>(std::llround(m_rate->value() * 1024.0));
    p.dscp = m_dscp->value();
    p.priority8021 = m_priority->value();
    p.precedence = static_cast<std::uint32_t>(m_precedence->value());
    p.protocol = static_cast<QosProtocol>(m_protocol->currentIndex());
    p.sourcePrefix = m_source->text().trimmed().toStdWString();
    p.destinationPrefix = m_destination->text().trimmed().toStdWString();
    p.sourcePortStart = static_cast<std::uint16_t>(m_sourceStart->value());
    p.sourcePortEnd = static_cast<std::uint16_t>(m_sourceEnd->value());
    p.destinationPortStart = static_cast<std::uint16_t>(m_destStart->value());
    p.destinationPortEnd = static_cast<std::uint16_t>(m_destEnd->value());
    p.enabled = m_enabled->isChecked();
    return p;
}
void NetworkQosPage::selected()
{
    // Selection targets row actions. Loading an editable draft is explicit.
    updateButtons();
}
const QosPolicy* NetworkQosPage::selectedPolicy() const
{
    const auto selection = m_table->selectionModel()->selectedRows(0);
    if (selection.size() != 1) return nullptr;
    const auto identity = selection.first().data(Qt::UserRole).toString();
    const auto found = std::find_if(m_policies.cbegin(), m_policies.cend(), [&](const auto &policy) {
        return QString::fromStdWString(policy.policyId) == identity;
    });
    return !identity.isEmpty() && found != m_policies.cend() ? &*found : nullptr;
}
void NetworkQosPage::setForm(const QosPolicy &p)
{
    if (p.policyId.empty())
    {
        const QSignalBlocker selection(m_table->selectionModel());
        m_table->clearSelection();
        m_table->setCurrentIndex({});
    }
    m_editingId = QString::fromStdWString(p.policyId);
    m_managed = p.managed;
    m_scope->setCurrentIndex(p.applicationPath.empty() ? 1 : 0);
    m_path->setText(QString::fromStdWString(p.applicationPath));
    m_rate->setMaximum((std::max)(1000000000.0, static_cast<double>(p.outboundBytesPerSecond) / 1024.0));
    m_rate->setValue(static_cast<double>(p.outboundBytesPerSecond) / 1024.0);
    m_originalRateBytes = p.outboundBytesPerSecond;
    m_originalRateDisplay = m_rate->value();
    m_dscp->setValue(p.dscp);
    m_priority->setValue(p.priority8021);
    m_precedence->setValue(static_cast<int>(p.precedence));
    m_protocol->setCurrentIndex(static_cast<int>(p.protocol));
    m_source->setText(QString::fromStdWString(p.sourcePrefix));
    m_destination->setText(QString::fromStdWString(p.destinationPrefix));
    m_sourceStart->setValue(p.sourcePortStart);
    m_sourceEnd->setValue(p.sourcePortEnd);
    m_destStart->setValue(p.destinationPortStart);
    m_destEnd->setValue(p.destinationPortEnd);
    m_enabled->setChecked(p.enabled);
    m_identity->setText(m_managed ? L("编辑策略草稿：%1；保存后才会应用。").arg(m_editingId)
                                : L("系统 / 提供者策略（只读）") + QStringLiteral("\n") + m_editingId);
    updateButtons();
}
void NetworkQosPage::importPolicy()
{
    const QPointer<NetworkQosPage> owner(this);
    const QString path =
        QFileDialog::getOpenFileName(this, L("导入 QoS 草稿"), QString(), QStringLiteral("JSON (*.json)"));
    if (!owner || path.isEmpty())
        return;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 2 * 1024 * 1024)
    {
        m_status->setText(L("无法读取策略文件，或文件超过 2 MiB。"));
        return;
    }
    QJsonParseError parse{};
    const auto document = QJsonDocument::fromJson(file.readAll(), &parse);
    const auto object = document.object();
    const auto policies = object.value(QStringLiteral("policies")).toArray();
    if (parse.error != QJsonParseError::NoError ||
        object.value(QStringLiteral("schema")).toString() != QStringLiteral("ksword-qos-policies") ||
        policies.isEmpty() || policies.size() > 1000)
    {
        m_status->setText(L("QoS 策略文件格式无效。"));
        return;
    }
    QStringList labels;
    for (qsizetype i = 0; i < policies.size(); ++i)
        labels.append(QString::number(i + 1) + QStringLiteral(" · ") +
                      policies[i].toObject().value(QStringLiteral("application")).toString());
    bool ok = false;
    const auto selected = QInputDialog::getItem(this, L("选择要导入的策略"), L("策略："), labels, 0, false, &ok);
    if (!owner || !ok || labels.indexOf(selected) < 0)
        return;
    const auto row = policies[labels.indexOf(selected)].toObject();
    QosPolicy p;
    if (!parseQosDraft(row, p))
    {
        m_status->setText(L("QoS 策略文件格式无效。"));
        return;
    }
    setForm(p);
    m_identity->setText(L("已导入草稿；点击“保存策略”后才会应用。"));
    m_status->setText(L("草稿已载入，尚未应用。"));
}
void NetworkQosPage::refresh()
{
    if (m_operation->isBusy())
        return;
    m_status->setText(L("正在读取 QoS 策略…"));
    const auto* selection = selectedPolicy();
    const QString selectedId = selection ? QString::fromStdWString(selection->policyId) : QString();
    m_operation->submit<int, QosPolicyList>(
        0, [](int, const ks::ui::AsyncOperationToken &) { return ListQosPolicies(); },
        [this, selectedId](const QosPolicyList &r, std::uint64_t generation) {
            if (!r.success)
            {
                m_status->setText(policyMessage(r.diagnostic));
                return true;
            }
            const auto snapshot = std::make_shared<const QosPolicyList>(r);
            const auto submission = ks::ui::ResultTableHost::submitGroup(
                this, QStringLiteral("network-qos"), {ks::ui::ResultTableHost::ensure(m_table)},
                [this, snapshot, generation, selectedId] {
                    if (!m_operation->isCurrent(generation))
                        return;
                    publishPolicies(snapshot->entries, selectedId);
                    m_status->setText(L("QoS 策略：%1 项").arg(m_policies.size()));
                    m_operation->completeDeferred(generation);
                });
            return submission != ks::ui::UiCommitSubmission::Deferred;
        },
        [this](std::exception_ptr) { m_status->setText(L("QoS 策略读取失败")); });
}
void NetworkQosPage::mutate(std::function<NetworkPolicyResult()> operation, bool updateEditor)
{
    if (m_operation->isBusy())
        return;
    m_status->setText(L("正在应用 QoS 策略…"));
    struct Result
    {
        NetworkPolicyResult action;
        QosPolicyList list;
    };
    m_operation->submitTransaction<int, Result>(
        0,
        [operation = std::move(operation)](int) {
            Result r;
            r.action = operation();
            if (r.action.success)
                r.list = ListQosPolicies();
            return r;
        },
        [this, updateEditor](const Result &r, std::uint64_t generation) {
            if (updateEditor && r.action.success && !r.action.policyId.empty()) {
                m_editingId = QString::fromStdWString(r.action.policyId);
                m_identity->setText(m_editingId);
            }
            m_status->setText(policyMessage(r.action.diagnostic));
            if (r.action.success)
            {
                if (r.list.success)
                {
                    const auto snapshot = std::make_shared<const Result>(r);
                    const auto submission = ks::ui::ResultTableHost::submitGroup(
                        this, QStringLiteral("network-qos"), {ks::ui::ResultTableHost::ensure(m_table)},
                        [this, snapshot, generation, updateEditor] {
                            if (!m_operation->isCurrent(generation))
                                return;
                            publishPolicies(snapshot->list.entries, QString::fromStdWString(snapshot->action.policyId));
                            if (updateEditor) {
                                const auto found = std::find_if(m_policies.cbegin(), m_policies.cend(), [&](const auto& policy) { return policy.policyId == snapshot->action.policyId; });
                                if (found != m_policies.cend()) setForm(*found);
                            }
                            m_operation->completeDeferred(generation);
                        });
                    return submission != ks::ui::UiCommitSubmission::Deferred;
                }
                else
                {
                    if (updateEditor && !r.action.policyId.empty())
                        m_editingId = QString::fromStdWString(r.action.policyId);
                    m_status->setText(L("操作已执行，但策略列表刷新失败：%1")
                                          .arg(ks::i18n::LanguageManager::instance().displayText(
                                              QString::fromStdWString(r.list.diagnostic))));
                }
            }
            return true;
        },
        [this](std::exception_ptr) { m_status->setText(L("QoS 操作失败")); });
}
void NetworkQosPage::publishPolicies(std::vector<QosPolicy> policies, const QString &selectedId)
{
    const QString identity = selectedId;
    const QPointer<NetworkQosPage> owner(this);
    {
        const QPointer<QItemSelectionModel> selectionModel(m_table->selectionModel());
        QSignalBlocker selection(selectionModel);
        m_policies = std::move(policies);
        m_model->set(m_policies);
        if (!selectionModel)
            selection.dismiss();
        if (!owner)
            return;
    }
    if (!owner)
        return;
    if (!identity.isEmpty())
    {
        const auto found = std::find_if(m_policies.cbegin(), m_policies.cend(), [&](const auto &policy) {
            return QString::fromStdWString(policy.policyId) == identity;
        });
        if (found != m_policies.cend())
        {
            const int row = static_cast<int>(found - m_policies.cbegin());
            {
                const QPointer<QItemSelectionModel> selectionModel(m_table->selectionModel());
                QSignalBlocker selection(selectionModel);
                m_table->selectRow(row);
                if (!selectionModel)
                    selection.dismiss();
                if (!owner)
                    return;
            }
        }
    }
    if (owner)
    {
        if (m_managed && !m_editingId.isEmpty() && std::none_of(m_policies.cbegin(), m_policies.cend(),
                [this](const auto& policy) { return QString::fromStdWString(policy.policyId) == m_editingId; })) {
            m_editingId.clear();
            m_identity->setText(L("原策略已不在列表；编辑内容保留为新建草稿，保存后创建新策略。"));
        }
        updateButtons();
        if (owner)
            refreshArea();
    }
}
void NetworkQosPage::save()
{
    if (!m_managed)
        return;
    const auto p = form();
    mutate([p] { return SaveQosPolicy(p); }, true);
}
void NetworkQosPage::remove()
{
    const auto* selected = selectedPolicy();
    if (!selected || !selected->managed) return;
    const auto id = selected->policyId;
    mutate([id] { return RemoveQosPolicy(id); });
}
void NetworkQosPage::toggle()
{
    const auto* selected = selectedPolicy();
    if (!selected || !selected->managed) return;
    mutate([id = selected->policyId, enabled = selected->enabled] { return SetQosPolicyEnabled(id, !enabled); });
}
void NetworkQosPage::refreshArea()
{
    if (!m_area)
        return;
    std::vector<ks::ui::MetricAreaNode> nodes;
    for (const auto &p : m_policies)
    {
        ks::ui::MetricAreaNode n;
        n.key = QString::fromStdWString(p.policyId);
        n.name = p.applicationPath.empty() ? L("全部应用") : QString::fromStdWString(p.applicationPath);
        n.known = p.enabled && p.outboundBytesPerSecond > 0;
        n.weight = static_cast<double>(p.outboundBytesPerSecond);
        n.value = p.enabled ? rate(p) : L("禁用");
        n.tooltip = n.key + QStringLiteral("\n") + n.name + QStringLiteral("\n") + n.value;
        nodes.push_back(std::move(n));
    }
    m_area->setSubject(L("全部策略"), L("应用 / 策略"), QString(),
                       L("面积比较已启用策略的上行配置上限，不代表实际吞吐；多个策略的匹配范围可能重叠。"));
    m_area->setPresentation(L("QoS 配置上限"), L("无带宽上限或已禁用的策略不参与面积比较。"), std::move(nodes));
}
void NetworkQosPage::exportPolicies()
{
    if (m_operation->isBusy())
        return;
    const QPointer<NetworkQosPage> owner(this);
    const auto snapshot = m_policies;
    const QString path =
        QFileDialog::getSaveFileName(this, L("导出 QoS 策略"), QString(), QStringLiteral("JSON (*.json)"));
    if (!owner || path.isEmpty())
        return;
    struct Request
    {
        QString path;
        std::vector<QosPolicy> policies;
    };
    struct Result
    {
        bool success = false;
        QString message;
    };
    m_operation->submitTransaction<Request, Result>(
        {path, snapshot},
        [](const Request &request) {
            QJsonArray rows;
            for (const auto &p : request.policies)
                rows.append(
                    QJsonObject{{QStringLiteral("id"), QString::fromStdWString(p.policyId)},
                                {QStringLiteral("application"), QString::fromStdWString(p.applicationPath)},
                                {QStringLiteral("outboundBytesPerSecond"), QString::number(p.outboundBytesPerSecond)},
                                {QStringLiteral("dscp"), p.dscp},
                                {QStringLiteral("priority8021"), p.priority8021},
                                {QStringLiteral("enabled"), p.enabled},
                                {QStringLiteral("managed"), p.managed},
                                {QStringLiteral("sourcePrefix"), QString::fromStdWString(p.sourcePrefix)},
                                {QStringLiteral("destinationPrefix"), QString::fromStdWString(p.destinationPrefix)},
                                {QStringLiteral("sourcePortStart"), p.sourcePortStart},
                                {QStringLiteral("sourcePortEnd"), p.sourcePortEnd},
                                {QStringLiteral("destinationPortStart"), p.destinationPortStart},
                                {QStringLiteral("destinationPortEnd"), p.destinationPortEnd},
                                {QStringLiteral("protocol"), static_cast<int>(p.protocol)},
                                {QStringLiteral("precedence"), static_cast<int>(p.precedence)}});
            QSaveFile file(request.path);
            const auto bytes =
                QJsonDocument(QJsonObject{{QStringLiteral("schema"), QStringLiteral("ksword-qos-policies")},
                                          {QStringLiteral("policies"), rows}})
                    .toJson();
            if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit())
                return Result{false, file.errorString()};
            return Result{true, QStringLiteral("策略已导出")};
        },
        [this](const Result &result, std::uint64_t) {
            m_status->setText(ks::i18n::LanguageManager::instance().displayText(result.message));
            return true;
        },
        [this](std::exception_ptr) { m_status->setText(L("QoS 操作失败")); });
}
void NetworkQosPage::changeEvent(QEvent *e)
{
    QWidget::changeEvent(e);
    if (e->type() == QEvent::LanguageChange && m_model)
    {
        m_model->retranslate();
        m_scope->setItemText(0, L("指定应用映像（所有实例）"));
        m_scope->setItemText(1, L("全部应用"));
        m_protocol->setItemText(0, L("提供者默认协议"));
        m_dscp->setSpecialValueText(L("不修改"));
        m_priority->setSpecialValueText(L("不修改"));
        for (auto *p : {m_sourceStart, m_sourceEnd, m_destStart, m_destEnd})
            p->setSpecialValueText(L("不限"));
        refreshArea();
    }
}
