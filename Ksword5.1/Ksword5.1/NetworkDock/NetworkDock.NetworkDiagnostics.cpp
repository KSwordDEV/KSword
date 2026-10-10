#include "NetworkDock.InternalCommon.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/SecondaryPageLayout.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"
#include "../Internationalization/LanguageManager.h"

#include "../UI/CodeEditorWidget.h"
#include <QDir>

using namespace network_dock_detail;

namespace
{
    constexpr quint32 kInfiniteRouteLifetime = std::numeric_limits<quint32>::max();

    QString routeAddressText(const SOCKADDR_INET& address)
    {
        wchar_t textBuffer[INET6_ADDRSTRLEN]{};
        if (address.si_family == AF_INET &&
            InetNtopW(AF_INET, &address.Ipv4.sin_addr, textBuffer, ARRAYSIZE(textBuffer)) != nullptr)
        {
            return QString::fromWCharArray(textBuffer);
        }
        if (address.si_family == AF_INET6 &&
            InetNtopW(AF_INET6, &address.Ipv6.sin6_addr, textBuffer, ARRAYSIZE(textBuffer)) != nullptr)
        {
            return QString::fromWCharArray(textBuffer);
        }
        return QString();
    }

    bool routeAddressFromText(const int addressFamily, const QString& text, SOCKADDR_INET* addressOut)
    {
        if (addressOut == nullptr || (addressFamily != AF_INET && addressFamily != AF_INET6))
        {
            return false;
        }
        *addressOut = SOCKADDR_INET{};
        addressOut->si_family = static_cast<ADDRESS_FAMILY>(addressFamily);
        const QString normalizedText = text.trimmed();
        if (normalizedText.isEmpty())
        {
            return true;
        }
        const std::wstring wideText = normalizedText.toStdWString();
        if (addressFamily == AF_INET)
        {
            return InetPtonW(AF_INET, wideText.c_str(), &addressOut->Ipv4.sin_addr) == 1;
        }
        return InetPtonW(AF_INET6, wideText.c_str(), &addressOut->Ipv6.sin6_addr) == 1;
    }

    QString routeInterfaceName(const quint32 interfaceIndex)
    {
        MIB_IF_ROW2 interfaceRow{};
        interfaceRow.InterfaceIndex = interfaceIndex;
        if (GetIfEntry2(&interfaceRow) == NO_ERROR)
        {
            const QString alias = QString::fromWCharArray(interfaceRow.Alias).trimmed();
            if (!alias.isEmpty())
            {
                return alias;
            }
            const QString description = QString::fromWCharArray(interfaceRow.Description).trimmed();
            if (!description.isEmpty())
            {
                return description;
            }
        }
        return QStringLiteral("ifIndex %1").arg(interfaceIndex);
    }

    QString routeProtocolText(const quint32 protocol)
    {
        switch (protocol)
        {
        case MIB_IPPROTO_LOCAL: return QStringLiteral("本地");
        case MIB_IPPROTO_NETMGMT: return QStringLiteral("手动");
        case MIB_IPPROTO_NT_STATIC: return QStringLiteral("NT 静态");
        case MIB_IPPROTO_NT_AUTOSTATIC: return QStringLiteral("NT 自动静态");
        default: return QStringLiteral("协议 %1").arg(protocol);
        }
    }

    QString routeOriginText(const quint32 origin)
    {
        switch (static_cast<NL_ROUTE_ORIGIN>(origin))
        {
        case NlroManual: return QStringLiteral("手动");
        case NlroWellKnown: return QStringLiteral("系统");
        case NlroDHCP: return QStringLiteral("DHCP");
        case NlroRouterAdvertisement: return QStringLiteral("路由通告");
        case Nlro6to4: return QStringLiteral("6to4");
        default: return QStringLiteral("来源 %1").arg(origin);
        }
    }

    QString routeLifetimeText(const quint32 lifetime)
    {
        return lifetime == kInfiniteRouteLifetime ? QStringLiteral("无限") : QString::number(lifetime);
    }

    bool parseRouteLifetime(const QString& text, quint32* lifetimeOut)
    {
        if (lifetimeOut == nullptr)
        {
            return false;
        }
        const QString normalizedText = text.trimmed();
        if (normalizedText.compare(QStringLiteral("infinite"), Qt::CaseInsensitive) == 0 ||
            normalizedText == QStringLiteral("无限"))
        {
            *lifetimeOut = kInfiniteRouteLifetime;
            return true;
        }
        bool parseOk = false;
        const quint32 lifetime = normalizedText.toUInt(&parseOk, 10);
        if (!parseOk)
        {
            return false;
        }
        *lifetimeOut = lifetime;
        return true;
    }

    bool routeRecordToNativeRow(
        const NetworkDock::RouteRecord& record,
        MIB_IPFORWARD_ROW2* rowOut,
        QString* errorTextOut)
    {
        if (rowOut == nullptr || (record.addressFamily != AF_INET && record.addressFamily != AF_INET6) ||
            record.interfaceIndex == 0U || record.prefixLength < 0 ||
            record.prefixLength > (record.addressFamily == AF_INET ? 32 : 128))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("地址族、前缀长度或接口索引无效。");
            }
            return false;
        }

        if (record.destinationAddress.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("目的网络或下一跳地址格式不正确。");
            }
            return false;
        }

        SOCKADDR_INET destination{};
        SOCKADDR_INET nextHop{};
        if (!routeAddressFromText(record.addressFamily, record.destinationAddress, &destination) ||
            !routeAddressFromText(record.addressFamily, record.nextHopAddress, &nextHop))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("目的网络或下一跳地址格式不正确。");
            }
            return false;
        }

        InitializeIpForwardEntry(rowOut);
        rowOut->InterfaceIndex = record.interfaceIndex;
        const DWORD luidStatus = ConvertInterfaceIndexToLuid(record.interfaceIndex, &rowOut->InterfaceLuid);
        if (luidStatus != NO_ERROR)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("接口索引 %1 无法转换为 LUID，错误码=%2。")
                    .arg(record.interfaceIndex).arg(luidStatus);
            }
            return false;
        }
        rowOut->DestinationPrefix.Prefix = destination;
        rowOut->DestinationPrefix.PrefixLength = static_cast<UINT8>(record.prefixLength);
        rowOut->NextHop = nextHop;
        rowOut->SitePrefixLength = record.sitePrefixLength;
        rowOut->Metric = record.metric;
        rowOut->Protocol = static_cast<NL_ROUTE_PROTOCOL>(record.protocol == 0U ? MIB_IPPROTO_NETMGMT : record.protocol);
        rowOut->Origin = static_cast<NL_ROUTE_ORIGIN>(record.origin == 0U ? NlroManual : record.origin);
        rowOut->Publish = record.publish;
        rowOut->Immortal = record.immortal;
        rowOut->ValidLifetime = record.validLifetime;
        rowOut->PreferredLifetime = record.preferredLifetime;
        return true;
    }

    NetworkDock::RouteRecord routeRecordFromNativeRow(const MIB_IPFORWARD_ROW2& row)
    {
        NetworkDock::RouteRecord record;
        record.addressFamily = row.DestinationPrefix.Prefix.si_family;
        record.destinationAddress = routeAddressText(row.DestinationPrefix.Prefix);
        record.prefixLength = row.DestinationPrefix.PrefixLength;
        record.nextHopAddress = routeAddressText(row.NextHop);
        record.interfaceIndex = row.InterfaceIndex;
        record.interfaceName = routeInterfaceName(row.InterfaceIndex);
        record.metric = row.Metric;
        record.protocol = static_cast<quint32>(row.Protocol);
        record.origin = static_cast<quint32>(row.Origin);
        record.publish = row.Publish != FALSE;
        record.immortal = row.Immortal != FALSE;
        record.age = row.Age;
        record.validLifetime = row.ValidLifetime;
        record.preferredLifetime = row.PreferredLifetime;
        record.sitePrefixLength = row.SitePrefixLength;
        return record;
    }

    bool sameRouteIdentity(const NetworkDock::RouteRecord& left, const NetworkDock::RouteRecord& right)
    {
        return left.addressFamily == right.addressFamily &&
            left.destinationAddress.compare(right.destinationAddress, Qt::CaseInsensitive) == 0 &&
            left.prefixLength == right.prefixLength &&
            left.nextHopAddress.compare(right.nextHopAddress, Qt::CaseInsensitive) == 0 &&
            left.interfaceIndex == right.interfaceIndex;
    }

    bool isHighRiskRoute(const NetworkDock::RouteRecord& record)
    {
        return record.prefixLength == 0 ||
            record.origin != static_cast<quint32>(NlroManual) ||
            record.protocol == static_cast<quint32>(MIB_IPPROTO_LOCAL);
    }

    QString routeSummaryText(const NetworkDock::RouteRecord& record)
    {
        return QStringLiteral("%1/%2\n下一跳：%3\n接口：%4 (%5)\nMetric：%6\n协议：%7\n来源：%8")
            .arg(record.destinationAddress)
            .arg(record.prefixLength)
            .arg(record.nextHopAddress.isEmpty() ? QStringLiteral("On-link") : record.nextHopAddress)
            .arg(record.interfaceName)
            .arg(record.interfaceIndex)
            .arg(record.metric)
            .arg(routeProtocolText(record.protocol))
            .arg(routeOriginText(record.origin));
    }

    bool runNetshRouteCommand(
        const QString& verb,
        const NetworkDock::RouteRecord& record,
        QString* errorTextOut)
    {
        const QString familyToken = record.addressFamily == AF_INET ? QStringLiteral("ipv4") : QStringLiteral("ipv6");
        QProcess process;
        process.setProgram(QStringLiteral("netsh.exe"));
        process.setProcessChannelMode(QProcess::MergedChannels);
        QStringList arguments{
            QStringLiteral("interface"), familyToken, verb,
            QStringLiteral("prefix=%1/%2").arg(record.destinationAddress).arg(record.prefixLength),
            QStringLiteral("interface=%1").arg(record.interfaceIndex)
        };
        if (!record.nextHopAddress.trimmed().isEmpty())
        {
            arguments.push_back(QStringLiteral("nexthop=%1").arg(record.nextHopAddress));
        }
        if (verb != QStringLiteral("delete"))
        {
            arguments.push_back(QStringLiteral("metric=%1").arg(record.metric));
            arguments.push_back(QStringLiteral("publish=%1").arg(record.publish ? QStringLiteral("yes") : QStringLiteral("no")));
            arguments.push_back(QStringLiteral("validlifetime=%1").arg(routeLifetimeText(record.validLifetime).replace(QStringLiteral("无限"), QStringLiteral("infinite"))));
            arguments.push_back(QStringLiteral("preferredlifetime=%1").arg(routeLifetimeText(record.preferredLifetime).replace(QStringLiteral("无限"), QStringLiteral("infinite"))));
        }
        arguments.push_back(QStringLiteral("store=persistent"));
        process.setArguments(arguments);
        process.start();
        if (!process.waitForStarted(2000) || !process.waitForFinished(8000) ||
            process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
        {
            if (errorTextOut != nullptr)
            {
                const QString output = QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
                *errorTextOut = QStringLiteral("netsh %1 失败：%2")
                    .arg(verb, output.isEmpty()
                        ? (process.error() == QProcess::UnknownError
                            ? QStringLiteral("退出码=%1").arg(process.exitCode())
                            : process.errorString())
                        : output);
            }
            return false;
        }
        return true;
    }

    bool editRouteRecordDialog(
        QWidget* parent,
        NetworkDock::RouteRecord* recordInOut,
        bool* persistentOut,
        const bool editing)
    {
        if (recordInOut == nullptr || persistentOut == nullptr)
        {
            return false;
        }
        QDialog dialog(parent);
        dialog.setWindowTitle(editing ? QStringLiteral("编辑路由") : QStringLiteral("新增路由"));
        QVBoxLayout* rootLayout = new QVBoxLayout(&dialog);
        ks::ui::StyleSecondaryWindow(&dialog);
        ks::ui::StyleSecondaryContentLayout(rootLayout);
        QFormLayout* formLayout = new QFormLayout();
        QComboBox* familyCombo = new QComboBox(&dialog);
        familyCombo->addItem(QStringLiteral("IPv4"), AF_INET);
        familyCombo->addItem(QStringLiteral("IPv6"), AF_INET6);
        familyCombo->setCurrentIndex(recordInOut->addressFamily == AF_INET6 ? 1 : 0);
        QLineEdit* destinationEdit = new QLineEdit(recordInOut->destinationAddress, &dialog);
        QSpinBox* prefixSpin = new QSpinBox(&dialog);
        prefixSpin->setRange(0, recordInOut->addressFamily == AF_INET6 ? 128 : 32);
        prefixSpin->setValue(recordInOut->prefixLength);
        QLineEdit* nextHopEdit = new QLineEdit(recordInOut->nextHopAddress, &dialog);
        QComboBox* interfaceCombo = new QComboBox(&dialog);
        PMIB_IF_TABLE2 interfaceTable = nullptr;
        if (GetIfTable2(&interfaceTable) == NO_ERROR && interfaceTable != nullptr)
        {
            for (ULONG index = 0; index < interfaceTable->NumEntries; ++index)
            {
                const MIB_IF_ROW2& interfaceRow = interfaceTable->Table[index];
                const QString alias = QString::fromWCharArray(interfaceRow.Alias).trimmed();
                interfaceCombo->addItem(
                    QStringLiteral("%1 (%2)").arg(alias.isEmpty() ? routeInterfaceName(interfaceRow.InterfaceIndex) : alias).arg(interfaceRow.InterfaceIndex),
                    static_cast<quint32>(interfaceRow.InterfaceIndex));
            }
            FreeMibTable(interfaceTable);
        }
        const int interfaceIndex = interfaceCombo->findData(recordInOut->interfaceIndex);
        if (interfaceIndex >= 0)
        {
            interfaceCombo->setCurrentIndex(interfaceIndex);
        }
        QSpinBox* metricSpin = new QSpinBox(&dialog);
        metricSpin->setRange(0, std::numeric_limits<int>::max());
        metricSpin->setValue(static_cast<int>(std::min<quint32>(recordInOut->metric, std::numeric_limits<int>::max())));
        QLineEdit* validLifetimeEdit = new QLineEdit(routeLifetimeText(recordInOut->validLifetime), &dialog);
        QLineEdit* preferredLifetimeEdit = new QLineEdit(routeLifetimeText(recordInOut->preferredLifetime), &dialog);
        QCheckBox* publishCheck = new QCheckBox(QStringLiteral("发布路由"), &dialog);
        publishCheck->setChecked(recordInOut->publish);
        QCheckBox* immortalCheck = new QCheckBox(QStringLiteral("Immortal"), &dialog);
        immortalCheck->setChecked(recordInOut->immortal);
        QCheckBox* persistentCheck = new QCheckBox(QStringLiteral("同步写入持久路由"), &dialog);
        persistentCheck->setChecked(false);
        persistentCheck->setToolTip(QStringLiteral("默认仅写入活动路由表；勾选后同时调用 Windows netsh 写入持久存储。"));
        formLayout->addRow(QStringLiteral("地址族"), familyCombo);
        formLayout->addRow(QStringLiteral("目的网络"), destinationEdit);
        formLayout->addRow(QStringLiteral("前缀长度"), prefixSpin);
        formLayout->addRow(QStringLiteral("下一跳（空=On-link）"), nextHopEdit);
        formLayout->addRow(QStringLiteral("接口"), interfaceCombo);
        formLayout->addRow(QStringLiteral("Metric"), metricSpin);
        formLayout->addRow(QStringLiteral("有效期（秒或 infinite）"), validLifetimeEdit);
        formLayout->addRow(QStringLiteral("首选期（秒或 infinite）"), preferredLifetimeEdit);
        formLayout->addRow(publishCheck);
        formLayout->addRow(immortalCheck);
        formLayout->addRow(persistentCheck);
        rootLayout->addLayout(formLayout);
        ks::ui::StyleSecondaryForm(formLayout, 190);
        rootLayout->addStretch(1);
        QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        rootLayout->addWidget(buttons);
        ks::ui::StyleSecondaryButtonBox(buttons);
        dialog.resize(600, 510);
        QObject::connect(familyCombo, qOverload<int>(&QComboBox::currentIndexChanged), &dialog, [familyCombo, prefixSpin](int) {
            prefixSpin->setMaximum(familyCombo->currentData().toInt() == AF_INET6 ? 128 : 32);
        });
        QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted)
        {
            return false;
        }
        quint32 validLifetime = 0;
        quint32 preferredLifetime = 0;
        if (!parseRouteLifetime(validLifetimeEdit->text(), &validLifetime) ||
            !parseRouteLifetime(preferredLifetimeEdit->text(), &preferredLifetime))
        {
            QMessageBox::warning(parent, QStringLiteral("路由"), QStringLiteral("有效期和首选期必须是秒数或 infinite。"));
            return false;
        }
        recordInOut->addressFamily = familyCombo->currentData().toInt();
        recordInOut->destinationAddress = destinationEdit->text().trimmed();
        recordInOut->prefixLength = prefixSpin->value();
        recordInOut->nextHopAddress = nextHopEdit->text().trimmed();
        recordInOut->interfaceIndex = interfaceCombo->currentData().toUInt();
        recordInOut->interfaceName = interfaceCombo->currentText();
        recordInOut->metric = static_cast<quint32>(metricSpin->value());
        recordInOut->publish = publishCheck->isChecked();
        recordInOut->immortal = immortalCheck->isChecked();
        recordInOut->validLifetime = validLifetime;
        recordInOut->preferredLifetime = preferredLifetime;
        *persistentOut = persistentCheck->isChecked();
        return true;
    }
}
// ============================================================
// NetworkDock.NetworkDiagnostics.cpp
// 作用：
// - ARP 缓存展示与编辑；
// - DNS 缓存展示与编辑；
// - 存活主机发现（ICMP 扫描）。
// - hosts 文件编辑。
// ============================================================

void NetworkDock::initializeRouteTableTab()
{
    m_routeTablePage = new QWidget(this);
    m_routeTableLayout = new QVBoxLayout(m_routeTablePage);
    m_routeTableLayout->setContentsMargins(6, 6, 6, 6);
    m_routeTableLayout->setSpacing(6);
    m_routeTableControlLayout = new QHBoxLayout();
    m_routeTableControlLayout->setSpacing(6);

    m_refreshRouteButton = new QPushButton(m_routeTablePage);
    m_refreshRouteButton->setIcon(QIcon(":/Icon/process_refresh.svg"));
    m_refreshRouteButton->setToolTip(QStringLiteral("刷新 IPv4/IPv6 路由表"));
    m_addRouteButton = new QPushButton(m_routeTablePage);
    m_addRouteButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_addRouteButton->setToolTip(QStringLiteral("新增路由，默认仅在本次启动有效"));
    m_editRouteButton = new QPushButton(m_routeTablePage);
    m_editRouteButton->setIcon(QIcon(":/Icon/process_details.svg"));
    m_editRouteButton->setToolTip(QStringLiteral("编辑选中路由"));
    m_removeRouteButton = new QPushButton(m_routeTablePage);
    m_removeRouteButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_removeRouteButton->setToolTip(QStringLiteral("删除选中活动路由及其同名持久副本"));
    m_routeStatusLabel = new QLabel(QStringLiteral("状态：等待刷新"), m_routeTablePage);
    m_routeStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    m_routeTableControlLayout->addWidget(m_refreshRouteButton);
    m_routeTableControlLayout->addWidget(m_addRouteButton);
    m_routeTableControlLayout->addWidget(m_editRouteButton);
    m_routeTableControlLayout->addWidget(m_removeRouteButton);
    m_routeTableControlLayout->addWidget(m_routeStatusLabel, 1);
    m_routeTableLayout->addLayout(m_routeTableControlLayout);
    ks::ui::NormalizeToolbarRow(m_routeTableControlLayout);

    m_routeTable = new ks::ui::VisibleTableWidget(m_routeTablePage);
    // 路由可能被增删改，保留现场快照与修改前后对比。
    ks::ui::SetTableActionBarMode(m_routeTable, ks::ui::TableActionBarMode::Full);
    m_routeTable->setColumnCount(13);
    m_routeTable->setHorizontalHeaderLabels({
        QStringLiteral("地址族"), QStringLiteral("目的网络"), QStringLiteral("下一跳"),
        QStringLiteral("接口"), QStringLiteral("Metric"), QStringLiteral("协议"),
        QStringLiteral("来源"), QStringLiteral("发布"), QStringLiteral("Immortal"),
        QStringLiteral("Age"), QStringLiteral("有效期"), QStringLiteral("首选期"),
        QStringLiteral("站点前缀")
        });
    m_routeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_routeTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_routeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_routeTable->verticalHeader()->setVisible(false);
    m_routeTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_routeTable->horizontalHeader()->setStretchLastSection(true);
    installCopyCurrentRowMenu(m_routeTable);
    m_routeTableLayout->addWidget(m_routeTable, 1);
    m_sideTabWidget->addTab(m_routeTablePage, QIcon(":/Icon/process_tree.svg"), QStringLiteral("路由表"));

    connect(m_refreshRouteButton, &QPushButton::clicked, this, [this]() { refreshRouteTable(); });
    connect(m_addRouteButton, &QPushButton::clicked, this, [this]() { addRouteEntry(); });
    connect(m_editRouteButton, &QPushButton::clicked, this, [this]() { editSelectedRouteEntry(); });
    connect(m_removeRouteButton, &QPushButton::clicked, this, [this]() { deleteSelectedRouteEntry(); });
    refreshRouteTable();
}

void NetworkDock::refreshRouteTable()
{
    if (m_routeTable == nullptr)
    {
        return;
    }
    PMIB_IPFORWARD_TABLE2 routeTable = nullptr;
    const DWORD queryStatus = GetIpForwardTable2(AF_UNSPEC, &routeTable);
    if (queryStatus != NO_ERROR || routeTable == nullptr)
    {
        if (m_routeStatusLabel != nullptr)
        {
            m_routeStatusLabel->setText(QStringLiteral("状态：读取路由表失败，错误码=%1").arg(queryStatus));
        }
        return;
    }

    m_routeRecordCache.clear();
    m_routeRecordCache.reserve(routeTable->NumEntries);
    m_routeTable->setUpdatesEnabled(false);
    m_routeTable->setRowCount(0);
    for (ULONG index = 0; index < routeTable->NumEntries; ++index)
    {
        const RouteRecord record = routeRecordFromNativeRow(routeTable->Table[index]);
        if (record.addressFamily != AF_INET && record.addressFamily != AF_INET6)
        {
            continue;
        }
        const int cacheIndex = static_cast<int>(m_routeRecordCache.size());
        m_routeRecordCache.push_back(record);
        const int row = m_routeTable->rowCount();
        m_routeTable->insertRow(row);
        const QStringList fields{
            record.addressFamily == AF_INET ? QStringLiteral("IPv4") : QStringLiteral("IPv6"),
            QStringLiteral("%1/%2").arg(record.destinationAddress).arg(record.prefixLength),
            record.nextHopAddress.isEmpty() ? QStringLiteral("On-link") : record.nextHopAddress,
            QStringLiteral("%1 (%2)").arg(record.interfaceName).arg(record.interfaceIndex),
            QString::number(record.metric), routeProtocolText(record.protocol), routeOriginText(record.origin),
            record.publish ? QStringLiteral("是") : QStringLiteral("否"),
            record.immortal ? QStringLiteral("是") : QStringLiteral("否"),
            QString::number(record.age), routeLifetimeText(record.validLifetime),
            routeLifetimeText(record.preferredLifetime), QString::number(record.sitePrefixLength)
        };
        for (int column = 0; column < fields.size(); ++column)
        {
            QTableWidgetItem* item = new QTableWidgetItem(fields.at(column));
            item->setData(Qt::UserRole, cacheIndex);
            m_routeTable->setItem(row, column, item);
        }
    }
    m_routeTable->setUpdatesEnabled(true);
    FreeMibTable(routeTable);
    if (m_routeStatusLabel != nullptr)
    {
        m_routeStatusLabel->setText(QStringLiteral("状态：路由项 %1").arg(m_routeRecordCache.size()));
    }
}

void NetworkDock::addRouteEntry()
{
    RouteRecord record;
    record.addressFamily = AF_INET;
    record.prefixLength = 24;
    record.protocol = MIB_IPPROTO_NETMGMT;
    record.origin = NlroManual;
    record.validLifetime = kInfiniteRouteLifetime;
    record.preferredLifetime = kInfiniteRouteLifetime;
    bool persistent = false;
    if (!editRouteRecordDialog(this, &record, &persistent, false))
    {
        return;
    }
    MIB_IPFORWARD_ROW2 nativeRow{};
    QString errorText;
    if (!routeRecordToNativeRow(record, &nativeRow, &errorText))
    {
        QMessageBox::warning(this, QStringLiteral("新增路由"), errorText);
        return;
    }
    if (isHighRiskRoute(record) && QMessageBox::question(
        this, QStringLiteral("新增高风险路由"),
        QStringLiteral("将新增以下路由：\n%1\n\n该路由可能影响系统网络连接，是否继续？").arg(routeSummaryText(record)),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }
    const DWORD createStatus = CreateIpForwardEntry2(&nativeRow);
    if (createStatus != NO_ERROR)
    {
        // privilegePromptHandled：结构化错误已触发恢复提示时跳过旧错误框。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("新增系统路由"),
            createStatus);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("新增路由"),
                QStringLiteral("CreateIpForwardEntry2 失败，错误码=%1").arg(createStatus));
        }
        return;
    }
    if (persistent && !runNetshRouteCommand(QStringLiteral("add"), record, &errorText))
    {
        // privilegePromptHandled：活动路由仍需回滚，但权限提示后不再重复弹窗。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("持久化新增路由"),
            errorText);
        (void)DeleteIpForwardEntry2(&nativeRow);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("新增路由"),
                QStringLiteral("持久化写入失败，已回滚活动路由。\n%1").arg(errorText));
        }
        return;
    }
    refreshRouteTable();
}

void NetworkDock::editSelectedRouteEntry()
{
    if (m_routeTable == nullptr || m_routeTable->currentRow() < 0)
    {
        QMessageBox::information(this, QStringLiteral("编辑路由"), QStringLiteral("请先选择一条路由。"));
        return;
    }
    QTableWidgetItem* sourceItem = m_routeTable->item(m_routeTable->currentRow(), 0);
    const int cacheIndex = sourceItem != nullptr ? sourceItem->data(Qt::UserRole).toInt() : -1;
    if (cacheIndex < 0 || cacheIndex >= static_cast<int>(m_routeRecordCache.size()))
    {
        return;
    }
    const RouteRecord original = m_routeRecordCache.at(static_cast<std::size_t>(cacheIndex));
    RouteRecord target = original;
    bool persistent = false;
    if (!editRouteRecordDialog(this, &target, &persistent, true))
    {
        return;
    }
    if (isHighRiskRoute(original) || isHighRiskRoute(target))
    {
        const QString confirmationText = QStringLiteral("原路由：\n%1\n\n修改后：\n%2\n\n是否继续？")
            .arg(routeSummaryText(original), routeSummaryText(target));
        if (QMessageBox::question(this, QStringLiteral("修改高风险路由"), confirmationText,
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        {
            return;
        }
    }
    MIB_IPFORWARD_ROW2 originalRow{};
    MIB_IPFORWARD_ROW2 targetRow{};
    QString errorText;
    if (!routeRecordToNativeRow(original, &originalRow, &errorText) || !routeRecordToNativeRow(target, &targetRow, &errorText))
    {
        QMessageBox::warning(this, QStringLiteral("编辑路由"), errorText);
        return;
    }
    DWORD operationStatus = NO_ERROR;
    if (sameRouteIdentity(original, target))
    {
        operationStatus = SetIpForwardEntry2(&targetRow);
    }
    else
    {
        operationStatus = CreateIpForwardEntry2(&targetRow);
        if (operationStatus == NO_ERROR)
        {
            operationStatus = DeleteIpForwardEntry2(&originalRow);
        }
    }
    if (operationStatus != NO_ERROR)
    {
        // privilegePromptHandled：结构化错误已触发恢复提示时跳过旧错误框。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("编辑系统路由"),
            operationStatus);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("编辑路由"),
                QStringLiteral("更新活动路由失败，错误码=%1").arg(operationStatus));
        }
        return;
    }
    if (persistent)
    {
        if (!sameRouteIdentity(original, target))
        {
            (void)runNetshRouteCommand(QStringLiteral("delete"), original, nullptr);
            if (!runNetshRouteCommand(QStringLiteral("add"), target, &errorText))
            {
                // privilegePromptHandled：页面继续刷新，但不叠加旧通用失败框。
                const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    this,
                    QStringLiteral("持久化编辑路由"),
                    errorText);
                if (!privilegePromptHandled)
                {
                    QMessageBox::warning(
                        this,
                        QStringLiteral("编辑路由"),
                        QStringLiteral("活动路由已更新，但持久化写入失败：%1").arg(errorText));
                }
            }
        }
        else if (!runNetshRouteCommand(QStringLiteral("set"), target, &errorText) &&
                 !runNetshRouteCommand(QStringLiteral("add"), target, &errorText))
        {
            // privilegePromptHandled：页面继续刷新，但不叠加旧通用失败框。
            const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                this,
                QStringLiteral("持久化编辑路由"),
                errorText);
            if (!privilegePromptHandled)
            {
                QMessageBox::warning(
                    this,
                    QStringLiteral("编辑路由"),
                    QStringLiteral("活动路由已更新，但持久化写入失败：%1").arg(errorText));
            }
        }
    }
    else
    {
        (void)runNetshRouteCommand(QStringLiteral("delete"), original, nullptr);
    }
    refreshRouteTable();
}

void NetworkDock::deleteSelectedRouteEntry()
{
    if (m_routeTable == nullptr || m_routeTable->currentRow() < 0)
    {
        QMessageBox::information(this, QStringLiteral("删除路由"), QStringLiteral("请先选择一条路由。"));
        return;
    }
    QTableWidgetItem* sourceItem = m_routeTable->item(m_routeTable->currentRow(), 0);
    const int cacheIndex = sourceItem != nullptr ? sourceItem->data(Qt::UserRole).toInt() : -1;
    if (cacheIndex < 0 || cacheIndex >= static_cast<int>(m_routeRecordCache.size()))
    {
        return;
    }
    const RouteRecord record = m_routeRecordCache.at(static_cast<std::size_t>(cacheIndex));
    if (isHighRiskRoute(record) && QMessageBox::question(
        this, QStringLiteral("删除高风险路由"),
        QStringLiteral("将删除活动路由及同名持久副本：\n%1\n\n是否继续？").arg(routeSummaryText(record)),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }
    MIB_IPFORWARD_ROW2 nativeRow{};
    QString errorText;
    if (!routeRecordToNativeRow(record, &nativeRow, &errorText))
    {
        QMessageBox::warning(this, QStringLiteral("删除路由"), errorText);
        return;
    }
    const DWORD deleteStatus = DeleteIpForwardEntry2(&nativeRow);
    if (deleteStatus != NO_ERROR)
    {
        // privilegePromptHandled：结构化错误已触发恢复提示时跳过旧错误框。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("删除系统路由"),
            deleteStatus);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("删除路由"),
                QStringLiteral("DeleteIpForwardEntry2 失败，错误码=%1").arg(deleteStatus));
        }
        return;
    }
    (void)runNetshRouteCommand(QStringLiteral("delete"), record, nullptr);
    refreshRouteTable();
}

void NetworkDock::initializeArpCacheTab()
{
    m_arpCachePage = new QWidget(this);
    m_arpCacheLayout = new QVBoxLayout(m_arpCachePage);
    m_arpCacheLayout->setContentsMargins(6, 6, 6, 6);
    m_arpCacheLayout->setSpacing(6);

    m_arpCacheControlLayout = new QHBoxLayout();
    m_arpCacheControlLayout->setSpacing(6);

    m_refreshArpButton = new QPushButton(m_arpCachePage);
    m_refreshArpButton->setIcon(QIcon(":/Icon/process_refresh.svg"));
    m_refreshArpButton->setToolTip(QStringLiteral("刷新 ARP 缓存列表"));

    m_addArpButton = new QPushButton(m_arpCachePage);
    m_addArpButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_addArpButton->setToolTip(QStringLiteral("新增静态 ARP 缓存项"));

    m_removeArpButton = new QPushButton(m_arpCachePage);
    m_removeArpButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_removeArpButton->setToolTip(QStringLiteral("删除选中的 ARP 缓存项"));

    m_flushArpButton = new QPushButton(m_arpCachePage);
    m_flushArpButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_flushArpButton->setToolTip(QStringLiteral("清空全部 ARP 缓存"));

    m_arpStatusLabel = new QLabel(QStringLiteral("状态：等待刷新"), m_arpCachePage);
    m_arpStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    m_arpCacheControlLayout->addWidget(m_refreshArpButton);
    m_arpCacheControlLayout->addWidget(m_addArpButton);
    m_arpCacheControlLayout->addWidget(m_removeArpButton);
    m_arpCacheControlLayout->addWidget(m_flushArpButton);
    m_arpCacheControlLayout->addWidget(m_arpStatusLabel, 1);
    m_arpCacheLayout->addLayout(m_arpCacheControlLayout);
    ks::ui::NormalizeToolbarRow(m_arpCacheControlLayout);

    m_arpTable = new ks::ui::VisibleTableWidget(m_arpCachePage);
    // 四列缓存页主要用于查看和删除条目，紧凑复制/导出足够。
    ks::ui::SetTableActionBarMode(m_arpTable, ks::ui::TableActionBarMode::Compact);
    m_arpTable->setColumnCount(4);
    m_arpTable->setHorizontalHeaderLabels({
        QStringLiteral("IPv4地址"),
        QStringLiteral("MAC地址"),
        QStringLiteral("类型"),
        QStringLiteral("接口索引")
        });
    m_arpTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_arpTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_arpTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_arpTable->verticalHeader()->setVisible(false);
    m_arpTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // 横向滚动条不强制关闭：默认由全局列宽自适应压入 viewport，用户拖宽列后按需出现。
    installCopyCurrentRowMenu(m_arpTable);
    m_arpCacheLayout->addWidget(m_arpTable, 1);

    m_sideTabWidget->addTab(m_arpCachePage, QIcon(":/Icon/process_tree.svg"), QStringLiteral("ARP缓存"));
}

void NetworkDock::initializeDnsCacheTab()
{
    m_dnsCachePage = new QWidget(this);
    m_dnsCacheLayout = new QVBoxLayout(m_dnsCachePage);
    m_dnsCacheLayout->setContentsMargins(6, 6, 6, 6);
    m_dnsCacheLayout->setSpacing(6);

    m_dnsCacheControlLayout = new QHBoxLayout();
    m_dnsCacheControlLayout->setSpacing(6);

    m_refreshDnsButton = new QPushButton(QStringLiteral("刷新"), m_dnsCachePage);
    m_refreshDnsButton->setIcon(QIcon(":/Icon/process_refresh.svg"));
    m_refreshDnsButton->setToolTip(QStringLiteral("刷新 DNS 缓存列表"));

    m_dnsEntryEdit = new QLineEdit(m_dnsCachePage);
    m_dnsEntryEdit->setPlaceholderText(QStringLiteral("输入要删除的 DNS 域名，或先在表格里选择"));
    m_dnsEntryEdit->setToolTip(QStringLiteral("删除指定域名的 DNS 缓存条目"));

    m_removeDnsButton = new QPushButton(QStringLiteral("删除"), m_dnsCachePage);
    m_removeDnsButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_removeDnsButton->setToolTip(QStringLiteral("删除输入框域名或表格选中的 DNS 缓存条目，支持多选"));

    m_flushDnsButton = new QPushButton(QStringLiteral("清空"), m_dnsCachePage);
    m_flushDnsButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_flushDnsButton->setToolTip(QStringLiteral("清空 DNS 缓存"));

    m_dnsStatusLabel = new QLabel(QStringLiteral("状态：等待刷新"), m_dnsCachePage);
    m_dnsStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    m_dnsCacheControlLayout->addWidget(m_refreshDnsButton);
    m_dnsCacheControlLayout->addWidget(m_dnsEntryEdit, 1);
    m_dnsCacheControlLayout->addWidget(m_removeDnsButton);
    m_dnsCacheControlLayout->addWidget(m_flushDnsButton);
    m_dnsCacheControlLayout->addWidget(m_dnsStatusLabel, 1);
    m_dnsCacheLayout->addLayout(m_dnsCacheControlLayout);
    ks::ui::NormalizeToolbarRow(m_dnsCacheControlLayout);

    m_dnsTable = new ks::ui::VisibleTableWidget(m_dnsCachePage);
    ks::ui::SetTableActionBarMode(m_dnsTable, ks::ui::TableActionBarMode::Compact);
    m_dnsTable->setColumnCount(3);
    m_dnsTable->setHorizontalHeaderLabels({
        QStringLiteral("域名"),
        QStringLiteral("记录类型"),
        QStringLiteral("标志")
        });
    m_dnsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_dnsTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_dnsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_dnsTable->verticalHeader()->setVisible(false);
    m_dnsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // 横向滚动条不强制关闭：默认由全局列宽自适应压入 viewport，用户拖宽列后按需出现。
    installCopyCurrentRowMenu(m_dnsTable);
    m_dnsCacheLayout->addWidget(m_dnsTable, 1);

    m_sideTabWidget->addTab(m_dnsCachePage, QIcon(":/Icon/process_list.svg"), QStringLiteral("DNS缓存"));
}

void NetworkDock::initializeAliveHostScanTab()
{
    m_aliveScanPage = new QWidget(this);
    m_aliveScanLayout = new QVBoxLayout(m_aliveScanPage);
    m_aliveScanLayout->setContentsMargins(6, 6, 6, 6);
    m_aliveScanLayout->setSpacing(6);

    m_aliveScanControlLayout = new QHBoxLayout();
    m_aliveScanControlLayout->setSpacing(6);

    QLabel* startIpLabel = new QLabel(QStringLiteral("起始IP:"), m_aliveScanPage);
    m_aliveScanStartIpEdit = new QLineEdit(m_aliveScanPage);
    m_aliveScanStartIpEdit->setPlaceholderText(QStringLiteral("例如 192.168.1.1"));
    m_aliveScanStartIpEdit->setText(QStringLiteral("192.168.1.1"));

    QLabel* endIpLabel = new QLabel(QStringLiteral("结束IP:"), m_aliveScanPage);
    m_aliveScanEndIpEdit = new QLineEdit(m_aliveScanPage);
    m_aliveScanEndIpEdit->setPlaceholderText(QStringLiteral("例如 192.168.1.254"));
    m_aliveScanEndIpEdit->setText(QStringLiteral("192.168.1.254"));

    QLabel* timeoutLabel = new QLabel(QStringLiteral("超时ms:"), m_aliveScanPage);
    m_aliveScanTimeoutSpin = new QSpinBox(m_aliveScanPage);
    m_aliveScanTimeoutSpin->setRange(50, 3000);
    m_aliveScanTimeoutSpin->setValue(220);

    m_startAliveScanButton = new QPushButton(m_aliveScanPage);
    m_startAliveScanButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_startAliveScanButton->setToolTip(QStringLiteral("开始扫描指定 IP 段的存活主机"));

    m_stopAliveScanButton = new QPushButton(m_aliveScanPage);
    m_stopAliveScanButton->setIcon(QIcon(":/Icon/process_pause.svg"));
    m_stopAliveScanButton->setToolTip(QStringLiteral("停止当前主机扫描任务"));
    m_stopAliveScanButton->setEnabled(false);

    m_aliveScanControlLayout->addWidget(startIpLabel);
    m_aliveScanControlLayout->addWidget(m_aliveScanStartIpEdit);
    m_aliveScanControlLayout->addWidget(endIpLabel);
    m_aliveScanControlLayout->addWidget(m_aliveScanEndIpEdit);
    m_aliveScanControlLayout->addWidget(timeoutLabel);
    m_aliveScanControlLayout->addWidget(m_aliveScanTimeoutSpin);
    m_aliveScanControlLayout->addWidget(m_startAliveScanButton);
    m_aliveScanControlLayout->addWidget(m_stopAliveScanButton);
    m_aliveScanLayout->addLayout(m_aliveScanControlLayout);
    ks::ui::NormalizeToolbarRow(m_aliveScanControlLayout);

    m_aliveScanProgressBar = new QProgressBar(m_aliveScanPage);
    m_aliveScanProgressBar->setRange(0, 100);
    m_aliveScanProgressBar->setValue(0);
    m_aliveScanProgressBar->setFormat(QStringLiteral("0%"));
    m_aliveScanLayout->addWidget(m_aliveScanProgressBar);

    m_aliveScanStatusLabel = new QLabel(QStringLiteral("状态：待机"), m_aliveScanPage);
    m_aliveScanLayout->addWidget(m_aliveScanStatusLabel);

    m_aliveScanTable = new ks::ui::VisibleTableWidget(m_aliveScanPage);
    // 单次发现结果需要导出，不需要每个结果表的冻结/对比操作。
    ks::ui::SetTableActionBarMode(m_aliveScanTable, ks::ui::TableActionBarMode::Compact);
    m_aliveScanTable->setColumnCount(4);
    m_aliveScanTable->setHorizontalHeaderLabels({
        QStringLiteral("IP"),
        QStringLiteral("状态"),
        QStringLiteral("RTT(ms)"),
        QStringLiteral("详情")
        });
    m_aliveScanTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_aliveScanTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_aliveScanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_aliveScanTable->verticalHeader()->setVisible(false);
    m_aliveScanTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // 横向滚动条不强制关闭：默认由全局列宽自适应压入 viewport，用户拖宽列后按需出现。
    installCopyCurrentRowMenu(m_aliveScanTable);
    m_aliveScanLayout->addWidget(m_aliveScanTable, 1);

    m_sideTabWidget->addTab(m_aliveScanPage, QIcon(":/Icon/process_main.svg"), QStringLiteral("存活主机"));
}

void NetworkDock::initializeHostsFileEditorTab()
{
    m_hostsFileEditorPage = new QWidget(this);
    m_hostsFileEditorLayout = new QVBoxLayout(m_hostsFileEditorPage);
    m_hostsFileEditorLayout->setContentsMargins(0, 0, 0, 0);
    m_hostsFileEditorLayout->setSpacing(0);

    m_hostsFileEditor = new CodeEditorWidget(m_hostsFileEditorPage);
    m_hostsFileEditor->setReadOnly(false);
    m_hostsFileEditorLayout->addWidget(m_hostsFileEditor, 1);

    QString windowsDirectory = qEnvironmentVariable("WINDIR").trimmed();
    if (windowsDirectory.isEmpty())
    {
        windowsDirectory = QStringLiteral("C:/Windows");
    }
    const QString hostsFilePath = QDir(windowsDirectory)
        .absoluteFilePath(QStringLiteral("System32/drivers/etc/hosts"));

    if (m_hostsFileEditor->openLocalFile(hostsFilePath))
    {
        kLogEvent openHostsEvent;
        info << openHostsEvent
            << "[NetworkDock] hosts文件编辑页已加载, path="
            << hostsFilePath.toStdString()
            << eol;
    }
    else
    {
        m_hostsFileEditor->setCurrentFilePath(hostsFilePath);
        // hosts 正文必须保持原文；这里只翻译本程序生成的读取失败说明。
        const QString hostsReadFailureText =
            ks::i18n::sourceText(QStringLiteral("# hosts 文件读取失败。\n"))
            + ks::i18n::sourceText(QStringLiteral("# 目标路径: %1\n")).arg(hostsFilePath)
            + ks::i18n::sourceText(QStringLiteral("# 如需直接保存系统 hosts，请以管理员权限运行程序。"));
        m_hostsFileEditor->setRawText(hostsReadFailureText);

        kLogEvent openHostsFailEvent;
        warn << openHostsFailEvent
            << "[NetworkDock] hosts文件编辑页加载失败, path="
            << hostsFilePath.toStdString()
            << eol;
    }

    m_sideTabWidget->addTab(m_hostsFileEditorPage, QIcon(":/Icon/codeeditor_open.svg"), QStringLiteral("hosts文件编辑"));
}

void NetworkDock::refreshArpCacheTable()
{
    if (m_arpTable == nullptr)
    {
        return;
    }

    {
        kLogEvent event;
        info << event
            << "[NetworkDock] 开始刷新ARP缓存表。"
            << eol;
    }

    ULONG tableSize = 0;
    if (GetIpNetTable(nullptr, &tableSize, FALSE) != ERROR_INSUFFICIENT_BUFFER)
    {
        m_arpStatusLabel->setText(QStringLiteral("状态：读取ARP缓存失败"));
        kLogEvent event;
        err << event
            << "[NetworkDock] ARP缓存刷新失败：首次获取缓冲区大小失败。"
            << eol;
        return;
    }

    std::vector<std::uint8_t> buffer(tableSize, 0);
    PMIB_IPNETTABLE netTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());
    if (GetIpNetTable(netTable, &tableSize, FALSE) != NO_ERROR)
    {
        m_arpStatusLabel->setText(QStringLiteral("状态：读取ARP缓存失败"));
        kLogEvent event;
        err << event
            << "[NetworkDock] ARP缓存刷新失败：GetIpNetTable读取失败。"
            << eol;
        return;
    }

    m_arpTable->setRowCount(0);
    for (DWORD index = 0; index < netTable->dwNumEntries; ++index)
    {
        const MIB_IPNETROW& row = netTable->table[index];
        const QString ipText = toQString(ks::network::FormatIpv4HostOrder(ntohl(row.dwAddr)));
        const QString macText = toQString(ks::network::FormatHardwareAddress(
            reinterpret_cast<const std::uint8_t*>(row.bPhysAddr),
            static_cast<std::size_t>(row.dwPhysAddrLen)));
        const QString typeText = toQString(ks::network::ArpEntryTypeToString(row.dwType));

        const int tableRow = m_arpTable->rowCount();
        m_arpTable->insertRow(tableRow);
        m_arpTable->setItem(tableRow, 0, new QTableWidgetItem(ipText));
        m_arpTable->setItem(tableRow, 1, new QTableWidgetItem(macText));
        m_arpTable->setItem(tableRow, 2, new QTableWidgetItem(typeText));
        m_arpTable->setItem(tableRow, 3, new QTableWidgetItem(QString::number(row.dwIndex)));
    }

    m_arpStatusLabel->setText(QString("状态：ARP缓存项 %1").arg(m_arpTable->rowCount()));

    kLogEvent event;
    info << event
        << "[NetworkDock] ARP缓存刷新完成, rowCount="
        << m_arpTable->rowCount()
        << eol;
}

void NetworkDock::addArpCacheEntry()
{
    kLogEvent startEvent;
    info << startEvent
        << "[NetworkDock] 用户触发新增ARP缓存项。"
        << eol;

    bool ok = false;
    const QString ipText = QInputDialog::getText(
        this,
        QStringLiteral("新增ARP"),
        QStringLiteral("IPv4地址:"),
        QLineEdit::Normal,
        QString(),
        &ok).trimmed();
    if (!ok || ipText.isEmpty())
    {
        kLogEvent event;
        dbg << event
            << "[NetworkDock] 新增ARP取消：未输入IPv4地址。"
            << eol;
        return;
    }

    const QString macText = QInputDialog::getText(
        this,
        QStringLiteral("新增ARP"),
        QStringLiteral("MAC地址(AA-BB-CC-DD-EE-FF):"),
        QLineEdit::Normal,
        QString(),
        &ok).trimmed();
    if (!ok || macText.isEmpty())
    {
        kLogEvent event;
        dbg << event
            << "[NetworkDock] 新增ARP取消：未输入MAC地址。"
            << eol;
        return;
    }

    const int interfaceIndex = QInputDialog::getInt(
        this,
        QStringLiteral("新增ARP"),
        QStringLiteral("接口索引(ifIndex):"),
        1,
        1,
        INT_MAX,
        1,
        &ok);
    if (!ok)
    {
        kLogEvent event;
        dbg << event
            << "[NetworkDock] 新增ARP取消：未输入接口索引。"
            << eol;
        return;
    }

    std::uint32_t ipHostOrder = 0;
    if (!tryParseIpv4Text(ipText, ipHostOrder))
    {
        kLogEvent event;
        warn << event
            << "[NetworkDock] 新增ARP失败：IPv4格式非法, ip="
            << ipText.toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("新增ARP"), QStringLiteral("IPv4 地址格式不正确。"));
        return;
    }

    std::vector<std::uint8_t> macBytes;
    std::string macParseErrorText;
    if (!ks::network::TryParseMacAddressText(macText.toStdString(), &macBytes, &macParseErrorText))
    {
        kLogEvent event;
        warn << event
            << "[NetworkDock] 新增ARP失败：MAC格式非法, mac="
            << macText.toStdString()
            << ", reason="
            << macParseErrorText
            << eol;
        QMessageBox::warning(this, QStringLiteral("新增ARP"), QStringLiteral("MAC 地址格式不正确。"));
        return;
    }

    MIB_IPNETROW row{};
    row.dwIndex = static_cast<DWORD>(interfaceIndex);
    row.dwAddr = htonl(ipHostOrder);
    row.dwType = MIB_IPNET_TYPE_STATIC;
    row.dwPhysAddrLen = static_cast<DWORD>(macBytes.size());
    for (std::size_t segmentIndex = 0; segmentIndex < macBytes.size(); ++segmentIndex)
    {
        row.bPhysAddr[segmentIndex] = static_cast<BYTE>(macBytes[segmentIndex]);
    }

    const DWORD createResult = CreateIpNetEntry(&row);
    if (createResult != NO_ERROR)
    {
        // privilegePromptHandled：权限恢复提示已展示时仅保留错误日志。
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新增 ARP 项"), createResult);
        kLogEvent event;
        err << event
            << "[NetworkDock] 新增ARP失败, errorCode="
            << createResult
            << eol;
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("新增ARP"),
                QString("CreateIpNetEntry 失败，错误码=%1").arg(createResult));
        }
        return;
    }

    kLogEvent event;
    info << event
        << "[NetworkDock] 新增ARP成功, ip="
        << ipText.toStdString()
        << ", interfaceIndex="
        << interfaceIndex
        << eol;

    refreshArpCacheTable();
}

void NetworkDock::removeSelectedArpCacheEntry()
{
    if (m_arpTable == nullptr || m_arpTable->currentRow() < 0)
    {
        kLogEvent event;
        dbg << event
            << "[NetworkDock] 删除ARP取消：未选中行。"
            << eol;
        return;
    }

    const int selectedRow = m_arpTable->currentRow();
    const QString ipText = m_arpTable->item(selectedRow, 0) != nullptr
        ? m_arpTable->item(selectedRow, 0)->text().trimmed()
        : QString();
    const QString indexText = m_arpTable->item(selectedRow, 3) != nullptr
        ? m_arpTable->item(selectedRow, 3)->text().trimmed()
        : QString();

    std::uint32_t ipHostOrder = 0;
    bool indexOk = false;
    const DWORD interfaceIndex = static_cast<DWORD>(indexText.toUInt(&indexOk));
    if (!tryParseIpv4Text(ipText, ipHostOrder) || !indexOk)
    {
        kLogEvent event;
        warn << event
            << "[NetworkDock] 删除ARP失败：选中行解析失败, ip="
            << ipText.toStdString()
            << ", index="
            << indexText.toStdString()
            << eol;
        return;
    }

    MIB_IPNETROW deleteRow{};
    deleteRow.dwAddr = htonl(ipHostOrder);
    deleteRow.dwIndex = interfaceIndex;
    const DWORD deleteResult = DeleteIpNetEntry(&deleteRow);
    if (deleteResult != NO_ERROR)
    {
        // privilegePromptHandled：权限恢复提示已展示时仅保留错误日志。
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除 ARP 项"), deleteResult);
        kLogEvent event;
        err << event
            << "[NetworkDock] 删除ARP失败, ip="
            << ipText.toStdString()
            << ", errorCode="
            << deleteResult
            << eol;
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("删除ARP"),
                QString("DeleteIpNetEntry 失败，错误码=%1").arg(deleteResult));
        }
        return;
    }

    kLogEvent event;
    info << event
        << "[NetworkDock] 删除ARP成功, ip="
        << ipText.toStdString()
        << ", interfaceIndex="
        << interfaceIndex
        << eol;
    refreshArpCacheTable();
}

void NetworkDock::flushArpCache()
{
    if (m_arpTable == nullptr)
    {
        return;
    }

    kLogEvent startEvent;
    info << startEvent
        << "[NetworkDock] 开始清空ARP缓存。"
        << eol;

    std::unordered_set<DWORD> interfaceIndexSet;
    for (int row = 0; row < m_arpTable->rowCount(); ++row)
    {
        bool indexOk = false;
        const DWORD interfaceIndex = static_cast<DWORD>(
            m_arpTable->item(row, 3)->text().toUInt(&indexOk));
        if (indexOk)
        {
            interfaceIndexSet.insert(interfaceIndex);
        }
    }

    for (DWORD interfaceIndex : interfaceIndexSet)
    {
        FlushIpNetTable(interfaceIndex);
    }

    kLogEvent event;
    info << event
        << "[NetworkDock] 清空ARP缓存完成, interfaceCount="
        << interfaceIndexSet.size()
        << eol;
    refreshArpCacheTable();
}

void NetworkDock::refreshDnsCacheTable()
{
    if (m_dnsTable == nullptr)
    {
        return;
    }

    {
        kLogEvent event;
        info << event
            << "[NetworkDock] 开始刷新DNS缓存表。"
            << eol;
    }

    using DnsGetCacheDataTableFn = BOOL(WINAPI*)(PVOID);
    struct DnsCacheEntryRecord
    {
        DnsCacheEntryRecord* next = nullptr;
        PWSTR name = nullptr;
        WORD type = 0;
        WORD dataLength = 0;
        DWORD flags = 0;
    };

    HMODULE dnsapiModule = GetModuleHandleW(L"dnsapi.dll");
    if (dnsapiModule == nullptr)
    {
        dnsapiModule = LoadLibraryW(L"dnsapi.dll");
    }
    if (dnsapiModule == nullptr)
    {
        m_dnsStatusLabel->setText(QStringLiteral("状态：dnsapi.dll 不可用"));
        kLogEvent event;
        err << event
            << "[NetworkDock] DNS缓存刷新失败：dnsapi.dll不可用。"
            << eol;
        return;
    }

    auto dnsGetCacheDataTable = reinterpret_cast<DnsGetCacheDataTableFn>(
        GetProcAddress(dnsapiModule, "DnsGetCacheDataTable"));
    if (dnsGetCacheDataTable == nullptr)
    {
        m_dnsStatusLabel->setText(QStringLiteral("状态：DnsGetCacheDataTable 不可用"));
        kLogEvent event;
        err << event
            << "[NetworkDock] DNS缓存刷新失败：DnsGetCacheDataTable不可用。"
            << eol;
        return;
    }

    DnsCacheEntryRecord rootEntry{};
    const BOOL queryOk = dnsGetCacheDataTable(&rootEntry);
    if (queryOk == FALSE)
    {
        m_dnsStatusLabel->setText(QStringLiteral("状态：读取DNS缓存失败"));
        kLogEvent event;
        err << event
            << "[NetworkDock] DNS缓存刷新失败：读取缓存表失败。"
            << eol;
        return;
    }

    m_dnsTable->setRowCount(0);
    int count = 0;
    for (DnsCacheEntryRecord* node = rootEntry.next; node != nullptr; node = node->next)
    {
        const int row = m_dnsTable->rowCount();
        m_dnsTable->insertRow(row);
        const QString nameText = node->name != nullptr ? QString::fromWCharArray(node->name) : QStringLiteral("<null>");
        m_dnsTable->setItem(row, 0, new QTableWidgetItem(nameText));
        m_dnsTable->setItem(row, 1, new QTableWidgetItem(QString::number(node->type)));
        m_dnsTable->setItem(row, 2, new QTableWidgetItem(toQString(ks::network::FormatDnsFlags(node->flags))));
        ++count;
    }

    m_dnsStatusLabel->setText(QString("状态：DNS缓存项 %1").arg(count));

    kLogEvent event;
    info << event
        << "[NetworkDock] DNS缓存刷新完成, rowCount="
        << count
        << eol;
}

void NetworkDock::removeDnsCacheEntry()
{
    QStringList entryNameList;
    const QString typedEntryName = m_dnsEntryEdit != nullptr ? m_dnsEntryEdit->text().trimmed() : QString();
    if (m_dnsEntryEdit != nullptr && m_dnsEntryEdit->hasFocus() && !typedEntryName.isEmpty())
    {
        entryNameList.push_back(typedEntryName);
    }
    if (entryNameList.isEmpty() && m_dnsTable != nullptr)
    {
        // 删除优先使用表格选中集合：
        // - 多选删除时，输入框通常会被 selectionChanged 同步成第一行域名；
        // - 如果这里仍优先读取输入框，就会退化成只能删除一个条目。
        // - 例外：用户焦点仍在输入框内时，优先尊重手动输入的单个域名。
        const QList<QTableWidgetItem*> selectedItems = m_dnsTable->selectedItems();
        std::set<int> selectedRowSet;
        for (QTableWidgetItem* item : selectedItems)
        {
            if (item != nullptr)
            {
                selectedRowSet.insert(item->row());
            }
        }
        if (selectedRowSet.empty() && m_dnsTable->currentRow() >= 0)
        {
            selectedRowSet.insert(m_dnsTable->currentRow());
        }

        for (const int row : selectedRowSet)
        {
            QTableWidgetItem* hostItem = m_dnsTable->item(row, 0);
            if (hostItem == nullptr)
            {
                continue;
            }

            const QString rowEntryName = hostItem->text().trimmed();
            if (!rowEntryName.isEmpty() && !entryNameList.contains(rowEntryName, Qt::CaseInsensitive))
            {
                entryNameList.push_back(rowEntryName);
            }
        }
    }
    if (entryNameList.isEmpty())
    {
        if (!typedEntryName.isEmpty())
        {
            entryNameList.push_back(typedEntryName);
        }
    }
    if (entryNameList.isEmpty())
    {
        kLogEvent event;
        dbg << event
            << "[NetworkDock] 删除DNS缓存取消：未指定域名。"
            << eol;
        return;
    }

    {
        kLogEvent event;
        info << event
            << "[NetworkDock] 尝试删除DNS缓存项, count="
            << entryNameList.size()
            << eol;
    }

    using DnsFlushResolverCacheEntryFn = DNS_STATUS(WINAPI*)(PCWSTR);
    HMODULE dnsapiModule = GetModuleHandleW(L"dnsapi.dll");
    if (dnsapiModule == nullptr)
    {
        dnsapiModule = LoadLibraryW(L"dnsapi.dll");
    }
    if (dnsapiModule == nullptr)
    {
        kLogEvent event;
        err << event
            << "[NetworkDock] 删除DNS缓存失败：dnsapi.dll不可用。"
            << eol;
        QMessageBox::warning(this, QStringLiteral("删除DNS缓存"), QStringLiteral("dnsapi.dll 不可用。"));
        return;
    }

    auto dnsFlushResolverCacheEntry = reinterpret_cast<DnsFlushResolverCacheEntryFn>(
        GetProcAddress(dnsapiModule, "DnsFlushResolverCacheEntry_W"));
    if (dnsFlushResolverCacheEntry == nullptr)
    {
        kLogEvent event;
        err << event
            << "[NetworkDock] 删除DNS缓存失败：按项删除API不可用。"
            << eol;
        QMessageBox::warning(this, QStringLiteral("删除DNS缓存"), QStringLiteral("当前系统不支持按项删除 DNS 缓存。"));
        return;
    }

    QStringList failedEntryList;
    for (const QString& entryName : entryNameList)
    {
        const DNS_STATUS flushStatus = dnsFlushResolverCacheEntry(reinterpret_cast<PCWSTR>(entryName.utf16()));
        if (flushStatus != 0)
        {
            failedEntryList.push_back(QStringLiteral("%1（错误码=%2）").arg(entryName).arg(flushStatus));
        }
    }

    kLogEvent event;
    if (!failedEntryList.isEmpty())
    {
        warn << event
            << "[NetworkDock] 删除DNS缓存部分失败, requestCount="
            << entryNameList.size()
            << ", failedCount="
            << failedEntryList.size()
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("删除DNS缓存"),
            QStringLiteral("部分 DNS 缓存删除失败：\n%1").arg(failedEntryList.join(QStringLiteral("\n"))));
    }
    else
    {
        info << event
            << "[NetworkDock] 删除DNS缓存成功, count="
            << entryNameList.size()
            << eol;
    }
    refreshDnsCacheTable();
}

void NetworkDock::flushDnsCache()
{
    kLogEvent startEvent;
    info << startEvent
        << "[NetworkDock] 尝试清空DNS缓存。"
        << eol;

    using DnsFlushResolverCacheFn = BOOL(WINAPI*)();
    HMODULE dnsapiModule = GetModuleHandleW(L"dnsapi.dll");
    if (dnsapiModule == nullptr)
    {
        dnsapiModule = LoadLibraryW(L"dnsapi.dll");
    }
    if (dnsapiModule == nullptr)
    {
        kLogEvent event;
        err << event
            << "[NetworkDock] 清空DNS缓存失败：dnsapi.dll不可用。"
            << eol;
        QMessageBox::warning(this, QStringLiteral("清空DNS缓存"), QStringLiteral("dnsapi.dll 不可用。"));
        return;
    }

    auto dnsFlushResolverCache = reinterpret_cast<DnsFlushResolverCacheFn>(
        GetProcAddress(dnsapiModule, "DnsFlushResolverCache"));
    if (dnsFlushResolverCache == nullptr)
    {
        kLogEvent event;
        err << event
            << "[NetworkDock] 清空DNS缓存失败：API不可用。"
            << eol;
        QMessageBox::warning(this, QStringLiteral("清空DNS缓存"), QStringLiteral("当前系统不支持清空 DNS 缓存 API。"));
        return;
    }

    // DnsFlushResolverCache 返回 BOOL：非 0 表示成功，0 表示失败。
    // 旧代码把返回值当成 DNS_STATUS，导致成功时进入“清空失败”分支，看起来按钮无效。
    const BOOL flushOk = dnsFlushResolverCache();
    if (flushOk == FALSE)
    {
        const DWORD lastError = GetLastError();
        kLogEvent event;
        err << event
            << "[NetworkDock] 清空DNS缓存失败, errorCode="
            << lastError
            << eol;
        QMessageBox::warning(this, QStringLiteral("清空DNS缓存"), QString("清空失败，错误码=%1").arg(lastError));
        return;
    }

    kLogEvent event;
    info << event
        << "[NetworkDock] 清空DNS缓存成功。"
        << eol;
    refreshDnsCacheTable();
}

void NetworkDock::startAliveHostScan()
{
    if (m_aliveScanRunning.load())
    {
        kLogEvent event;
        dbg << event
            << "[NetworkDock] 忽略存活主机扫描启动：扫描已在进行中。"
            << eol;
        return;
    }

    std::uint32_t startIpHostOrder = 0;
    std::uint32_t endIpHostOrder = 0;
    if (!tryParseIpv4Text(m_aliveScanStartIpEdit->text().trimmed(), startIpHostOrder) ||
        !tryParseIpv4Text(m_aliveScanEndIpEdit->text().trimmed(), endIpHostOrder))
    {
        kLogEvent event;
        warn << event
            << "[NetworkDock] 启动存活主机扫描失败：IP地址格式非法, start="
            << m_aliveScanStartIpEdit->text().trimmed().toStdString()
            << ", end="
            << m_aliveScanEndIpEdit->text().trimmed().toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("存活主机扫描"), QStringLiteral("请输入正确的起止 IPv4 地址。"));
        return;
    }
    const ks::network::Ipv4ScanRange scanRange =
        ks::network::NormalizeIpv4ScanRange(startIpHostOrder, endIpHostOrder, 4096);
    startIpHostOrder = scanRange.beginHostOrder;
    endIpHostOrder = scanRange.endHostOrder;
    const std::uint64_t hostCount = scanRange.hostCount;
    if (!scanRange.withinLimit)
    {
        kLogEvent event;
        warn << event
            << "[NetworkDock] 启动存活主机扫描失败：扫描范围过大, hostCount="
            << hostCount
            << eol;
        QMessageBox::warning(this, QStringLiteral("存活主机扫描"), QStringLiteral("扫描范围过大，请控制在 4096 个主机以内。"));
        return;
    }

    m_aliveScanTable->setRowCount(0);
    m_aliveScanProgressBar->setValue(0);
    m_aliveScanStatusLabel->setText(QString("状态：正在扫描 %1 个主机").arg(hostCount));
    m_startAliveScanButton->setEnabled(false);
    m_stopAliveScanButton->setEnabled(true);

    if (m_aliveScanProgressPid == 0)
    {
        m_aliveScanProgressPid = kPro.addReusable(this, "网络", "存活主机扫描");
    }
    kPro.set(m_aliveScanProgressPid, "开始ICMP探测", 0, 0.0f);

    m_aliveScanRunning.store(true);
    m_aliveScanCancel.store(false);
    const std::shared_ptr<AliveScanTaskState> taskState = m_aliveScanTaskState;
    taskState->cancelRequested.store(false);
    {
        std::lock_guard<std::mutex> lock(taskState->mutex);
        ++taskState->activeTaskCount;
    }
    const int timeoutMs = m_aliveScanTimeoutSpin->value();

    {
        kLogEvent event;
        info << event
            << "[NetworkDock] 开始存活主机扫描, startIp="
            << formatIpv4HostOrder(startIpHostOrder).toStdString()
            << ", endIp="
            << formatIpv4HostOrder(endIpHostOrder).toStdString()
            << ", hostCount="
            << hostCount
            << ", timeoutMs="
            << timeoutMs
            << eol;
    }

    QPointer<NetworkDock> guardThis(this);
    auto* scanTask = QRunnable::create([guardThis, taskState, startIpHostOrder, endIpHostOrder, timeoutMs]()
        {
            const auto finishAliveScanTask = [taskState]()
            {
                std::lock_guard<std::mutex> lock(taskState->mutex);
                if (taskState->activeTaskCount > 0)
                {
                    --taskState->activeTaskCount;
                }
                if (taskState->activeTaskCount == 0)
                {
                    taskState->completion.notify_all();
                }
            };
            const std::uint64_t totalCount =
                static_cast<std::uint64_t>(endIpHostOrder) - startIpHostOrder + 1;
            std::atomic<std::uint64_t> nextIpHostOrder{ startIpHostOrder };
            std::atomic<std::uint64_t> finishedCount{ 0 };
            std::atomic<std::uint64_t> aliveCount{ 0 };
            std::atomic<std::uint32_t> icmpHandleFailCount{ 0 };

            unsigned int workerCount = std::thread::hardware_concurrency();
            if (workerCount == 0)
            {
                workerCount = 8;
            }
            workerCount = std::clamp(workerCount, 2u, 32u);

            std::vector<std::thread> workers;
            workers.reserve(workerCount);
            for (unsigned int workerIndex = 0; workerIndex < workerCount; ++workerIndex)
            {
                workers.emplace_back([guardThis,
                    taskState,
                    endIpHostOrder,
                    timeoutMs,
                    totalCount,
                    &nextIpHostOrder,
                    &finishedCount,
                    &aliveCount,
                    &icmpHandleFailCount]()
                    {
                        HANDLE icmpHandle = IcmpCreateFile();
                        if (icmpHandle == INVALID_HANDLE_VALUE)
                        {
                            ++icmpHandleFailCount;
                            return;
                        }

                        char sendData[] = "KSWORD";
                        while (true)
                        {
                            if (guardThis == nullptr || taskState->cancelRequested.load())
                            {
                                break;
                            }

                            const std::uint64_t currentIpTicket = nextIpHostOrder.fetch_add(1);
                            if (currentIpTicket > endIpHostOrder)
                            {
                                break;
                            }
                            const std::uint32_t currentIpHostOrder = static_cast<std::uint32_t>(currentIpTicket);

                            std::uint8_t replyBuffer[sizeof(ICMP_ECHO_REPLY) + 64] = {};
                            const DWORD replyCount = IcmpSendEcho(
                                icmpHandle,
                                htonl(currentIpHostOrder),
                                sendData,
                                static_cast<WORD>(sizeof(sendData)),
                                nullptr,
                                replyBuffer,
                                static_cast<DWORD>(sizeof(replyBuffer)),
                                static_cast<DWORD>(timeoutMs));

                            bool alive = false;
                            std::uint32_t rttMs = 0;
                            QString detailText = QStringLiteral("Timeout");
                            if (replyCount > 0)
                            {
                                const auto* echoReply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuffer);
                                alive = (echoReply->Status == IP_SUCCESS);
                                rttMs = echoReply->RoundTripTime;
                                detailText = toQString(ks::network::FormatIcmpEchoDetail(
                                    alive,
                                    echoReply->Status,
                                    echoReply->Options.Ttl));
                            }

                            const std::uint64_t doneCount = finishedCount.fetch_add(1) + 1;
                            const std::uint64_t aliveNow = alive
                                ? (aliveCount.fetch_add(1) + 1)
                                : aliveCount.load();
                            const QString ipText = toQString(ks::network::FormatIpv4HostOrder(currentIpHostOrder));
                            QMetaObject::invokeMethod(
                                guardThis,
                                [guardThis, taskState, ipText, alive, rttMs, detailText, doneCount, totalCount, aliveNow]()
                                {
                                    if (guardThis == nullptr || taskState->cancelRequested.load())
                                    {
                                        return;
                                    }
                                    // 结果列表只展示存活主机，Down 主机不入表。
                                    if (alive)
                                    {
                                        guardThis->appendAliveHostRow(ipText, true, rttMs, detailText);
                                    }
                                    const int progressValue = ks::network::CalculateIntegerProgressPercent(doneCount, totalCount);
                                    guardThis->m_aliveScanProgressBar->setValue(progressValue);
                                    guardThis->m_aliveScanProgressBar->setFormat(QString("%1%").arg(progressValue));
                                    guardThis->m_aliveScanStatusLabel->setText(
                                        QString("状态：扫描中 %1/%2，存活 %3")
                                        .arg(doneCount)
                                        .arg(totalCount)
                                        .arg(aliveNow));
                                    kPro.set(guardThis->m_aliveScanProgressPid, "ICMP探测中", 0, static_cast<float>(progressValue));
                                },
                                Qt::QueuedConnection);
                        }

                        IcmpCloseHandle(icmpHandle);
                    });
            }

            for (std::thread& workerThread : workers)
            {
                if (workerThread.joinable())
                {
                    workerThread.join();
                }
            }

            const std::uint64_t finishedCountValue = finishedCount.load();
            const std::uint64_t aliveCountValue = aliveCount.load();
            const std::uint32_t icmpHandleFailCountValue = icmpHandleFailCount.load();

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, taskState, totalCount, finishedCountValue, aliveCountValue, icmpHandleFailCountValue, workerCount]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->m_aliveScanRunning.store(false);
                    guardThis->m_startAliveScanButton->setEnabled(true);
                    guardThis->m_stopAliveScanButton->setEnabled(false);
                    const bool canceled = taskState->cancelRequested.load() || guardThis->m_aliveScanCancel.load();
                    const int progressValue = ks::network::CalculateIntegerProgressPercent(
                        finishedCountValue,
                        totalCount);
                    guardThis->m_aliveScanProgressBar->setValue(progressValue);
                    guardThis->m_aliveScanProgressBar->setFormat(QString("%1%").arg(progressValue));

                    QString statusText;
                    if (icmpHandleFailCountValue >= workerCount)
                    {
                        statusText = QStringLiteral("状态：ICMP句柄创建失败，扫描未执行");
                    }
                    else if (canceled)
                    {
                        statusText = QString("状态：已停止，已探测 %1/%2，存活 %3")
                            .arg(finishedCountValue)
                            .arg(totalCount)
                            .arg(aliveCountValue);
                    }
                    else
                    {
                        statusText = QString("状态：扫描完成，存活 %1 台").arg(aliveCountValue);
                    }
                    guardThis->m_aliveScanStatusLabel->setText(statusText);
                    kPro.set(
                        guardThis->m_aliveScanProgressPid,
                        canceled ? "ICMP扫描已停止" : "ICMP扫描完成",
                        0,
                        canceled ? static_cast<float>(progressValue) : 100.0f);

                    kLogEvent event;
                    info << event
                        << "[NetworkDock] 存活主机扫描结束, resultRowCount="
                        << guardThis->m_aliveScanTable->rowCount()
                        << ", finished="
                        << finishedCountValue
                        << ", total="
                        << totalCount
                        << ", alive="
                        << aliveCountValue
                        << ", icmpHandleFailCount="
                        << icmpHandleFailCountValue
                        << ", canceled="
                        << (canceled ? "true" : "false")
                        << eol;
                },
                Qt::QueuedConnection);
            finishAliveScanTask();
        });
    m_aliveScanThreadPool.start(scanTask);
}

void NetworkDock::stopAliveHostScan()
{
    m_aliveScanCancel.store(true);
    m_aliveScanTaskState->cancelRequested.store(true);
    m_aliveScanStatusLabel->setText(QStringLiteral("状态：正在停止扫描..."));

    kLogEvent event;
    info << event
        << "[NetworkDock] 用户请求停止存活主机扫描。"
        << eol;
}

void NetworkDock::cancelAndWaitForAliveHostScan()
{
    m_aliveScanCancel.store(true);
    const std::shared_ptr<AliveScanTaskState> taskState = m_aliveScanTaskState;
    taskState->cancelRequested.store(true);

    std::unique_lock<std::mutex> lock(taskState->mutex);
    taskState->completion.wait(lock, [taskState]()
    {
        return taskState->activeTaskCount == 0;
    });
}

void NetworkDock::appendAliveHostRow(
    const QString& ipText,
    const bool alive,
    const std::uint32_t rttMs,
    const QString& detailText)
{
    if (m_aliveScanTable == nullptr)
    {
        return;
    }
    if (!alive)
    {
        // 结果表仅保留 Alive 项，Down/Timeout 不写入列表。
        return;
    }

    const int row = m_aliveScanTable->rowCount();
    m_aliveScanTable->insertRow(row);
    m_aliveScanTable->setItem(row, 0, new QTableWidgetItem(ipText));
    auto* stateItem = new QTableWidgetItem(QStringLiteral("Alive"));
    stateItem->setForeground(KswordTheme::SuccessColor());
    stateItem->setTextAlignment(Qt::AlignCenter);
    m_aliveScanTable->setItem(row, 1, stateItem);
    m_aliveScanTable->setItem(row, 2, new QTableWidgetItem(QString::number(rttMs)));
    m_aliveScanTable->setItem(row, 3, new QTableWidgetItem(detailText));
}


