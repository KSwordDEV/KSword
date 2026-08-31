#include "NetworkDock.InternalCommon.h"
#include "NetworkAuditPage.h"
#include "NetworkFirewallPage.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../PluginHost.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../UI/TableInteractionSupport.h"
#include "../theme.h"

#include <QCoreApplication>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

using namespace network_dock_detail;

namespace
{
    // r0WfpPacketAddressText 作用：
    // - 把 shared/driver WFP packet row 的 IPv4/IPv6 网络序地址转成标准文本；
    // - 转换失败时返回对应未指定地址，避免读取协议行以外的字节；
    // - 返回：可写入 PacketRecord 的 UTF-8 地址。
    std::string r0WfpPacketAddressText(
        const unsigned long addressFamily,
        const unsigned char addressBytes[16])
    {
        const int nativeAddressFamily =
            addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6
            ? AF_INET6
            : AF_INET;
        char addressBuffer[INET6_ADDRSTRLEN] = {};
        if (addressBytes == nullptr ||
            InetNtopA(
                nativeAddressFamily,
                addressBytes,
                addressBuffer,
                static_cast<DWORD>(std::size(addressBuffer))) == nullptr)
        {
            return nativeAddressFamily == AF_INET6
                ? std::string("::")
                : std::string("0.0.0.0");
        }
        return std::string(addressBuffer);
    }

    // resolveR0WfpPacketProcessId 作用：
    // - 优先使用 R0 metadata PID；IPPACKET 层未提供时按本地端点表解析；
    // - IPv4/IPv6 均使用 network.h 中已有的 250ms 节流 resolver；
    // - 返回：PID，无法归属时为 0。
    std::uint32_t resolveR0WfpPacketProcessId(
        const KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW& packetRow,
        ks::network::detail::ConnectionPidResolver& pidResolver)
    {
        if (packetRow.processId != 0UL)
        {
            return packetRow.processId;
        }

        const auto protocol =
            static_cast<ks::network::PacketTransportProtocol>(packetRow.protocol);
        if (packetRow.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4)
        {
            std::uint32_t localAddressNetworkOrder = 0U;
            std::uint32_t remoteAddressNetworkOrder = 0U;
            std::memcpy(
                &localAddressNetworkOrder,
                packetRow.localAddress,
                sizeof(localAddressNetworkOrder));
            std::memcpy(
                &remoteAddressNetworkOrder,
                packetRow.remoteAddress,
                sizeof(remoteAddressNetworkOrder));
            return pidResolver.ResolveProcessId(
                protocol,
                ntohl(localAddressNetworkOrder),
                packetRow.localPort,
                ntohl(remoteAddressNetworkOrder),
                packetRow.remotePort);
        }

        ks::network::detail::Ipv6Bytes localAddress{};
        ks::network::detail::Ipv6Bytes remoteAddress{};
        std::memcpy(localAddress.data(), packetRow.localAddress, localAddress.size());
        std::memcpy(remoteAddress.data(), packetRow.remoteAddress, remoteAddress.size());
        return pidResolver.ResolveProcessIdV6(
            protocol,
            localAddress,
            packetRow.localPort,
            remoteAddress,
            packetRow.remotePort);
    }

    // buildR0WfpPacketRecord 作用：
    // - 把真实 R0 WFP IPv4/IPv6 IP packet 层记录转换为流量监控统一模型；
    // - 保留完整包长/payload 边界和受限原始前缀，PID 缺失时在 R3 侧补全；
    // - 返回：可直接写入 NetworkDock 缓存的逐包记录。
    ks::network::PacketRecord buildR0WfpPacketRecord(
        const KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW& packetRow,
        ks::network::detail::ConnectionPidResolver& pidResolver,
        ks::network::detail::ProcessNameResolver& processNameResolver)
    {
        constexpr std::uint64_t windowsEpochToUnixEpoch100ns = 116444736000000000ULL;
        ks::network::PacketRecord packetRecord;
        packetRecord.captureTimestampMs =
            packetRow.timestamp100ns >= windowsEpochToUnixEpoch100ns
            ? (packetRow.timestamp100ns - windowsEpochToUnixEpoch100ns) / 10000ULL
            : 0ULL;
        packetRecord.protocol =
            static_cast<ks::network::PacketTransportProtocol>(packetRow.protocol);
        packetRecord.direction =
            packetRow.direction == KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND
            ? ks::network::PacketDirection::Outbound
            : ks::network::PacketDirection::Inbound;
        packetRecord.processId = resolveR0WfpPacketProcessId(packetRow, pidResolver);
        packetRecord.processName = processNameResolver.ResolveProcessName(packetRecord.processId);
        packetRecord.sourceSequenceId = packetRow.sequence;
        packetRecord.sourceFlags = packetRow.flags;
        packetRecord.sourceText = "R0-WFP-PACKET";
        packetRecord.localAddress = r0WfpPacketAddressText(packetRow.addressFamily, packetRow.localAddress);
        packetRecord.localPort = packetRow.localPort;
        packetRecord.remoteAddress = r0WfpPacketAddressText(packetRow.addressFamily, packetRow.remoteAddress);
        packetRecord.remotePort = packetRow.remotePort;
        packetRecord.totalPacketSize = packetRow.totalPacketLength;
        packetRecord.payloadSize = packetRow.payloadLength;
        packetRecord.payloadOffset = packetRow.payloadOffset;
        packetRecord.packetBytesTruncated =
            (packetRow.flags & KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_TRUNCATED) != 0UL;
        const std::size_t capturedLength = std::min<std::size_t>(
            packetRow.capturedLength,
            KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES);
        packetRecord.packetBytes.assign(
            packetRow.capturedBytes,
            packetRow.capturedBytes + capturedLength);
        return packetRecord;
    }

    // disableNetworkTrafficCaptureAsync 作用：
    // - 把“关闭 R0 逐包数据面”的同步 IOCTL 丢到后台线程执行；
    //   CreateFileW + DeviceIoControl 没有 OVERLAPPED，内核侧要注销 WFP callout，
    //   在 UI 线程直接下发会造成可感知卡顿；
    // - 入参：无（该控制面只有“启用/停用”两个幂等指令，这里固定下发停用）；
    // - 返回：无，停用失败只写警告日志，不再回投 UI。
    void disableNetworkTrafficCaptureAsync()
    {
        std::thread([]()
            {
                const ksword::ark::DriverClient driverClient;
                const ksword::ark::NetworkTrafficCaptureControlResult captureControl =
                    driverClient.controlNetworkTrafficCapture(false);
                if (!captureControl.io.ok ||
                    captureControl.response.status != KSWORD_ARK_NETWORK_STATUS_DISABLED)
                {
                    kLogEvent disableEvent;
                    warn << disableEvent
                         << "[NetworkDock] R0 逐包数据面停用失败: "
                         << captureControl.io.message << eol;
                }
            }).detach();
    }
}

void NetworkDock::initializeConnections()
{
    connect(m_sideTabWidget, &QTabWidget::currentChanged, this, [this](const int /*index*/)
        {
            QWidget* currentPage = m_sideTabWidget != nullptr ? m_sideTabWidget->currentWidget() : nullptr;
            if (currentPage == m_firewallPage && m_firewallPage != nullptr)
            {
                m_firewallPage->requestInitialRefresh();
            }
            else if (currentPage == m_networkAuditPage && m_networkAuditPage != nullptr)
            {
                m_networkAuditPage->requestInitialRefresh();
            }
        });

    // 启停抓包与清空表格按钮连接。
    connect(m_startMonitorButton, &QPushButton::clicked, this, [this]()
        {
            startTrafficMonitor();
        });
    connect(m_stopMonitorButton, &QPushButton::clicked, this, [this]()
        {
            stopTrafficMonitor();
        });
    connect(m_clearPacketButton, &QPushButton::clicked, this, [this]()
        {
            clearAllPacketRows();
        });
    connect(m_networkPluginMenu, &QMenu::aboutToShow, this, [this]()
        {
            ks::plugin_host::InvocationContext context;
            context.targetKind = ks::plugin_host::TargetKind::Network;
            ks::plugin_host::populateTargetMenu(m_networkPluginMenu, this, context);
        });

    // NIDS 控制连接：实时检测开关、等级过滤和清空。
    connect(m_nidsEnableCheck, &QCheckBox::toggled, this, [this](const bool checked)
        {
            if (!checked)
            {
                m_nidsEngine.Reset();
            }
            updateNidsStatusLabel();
        });
    connect(m_nidsSeverityFilterCombo, static_cast<void(QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, [this](const int /*index*/)
        {
            rebuildNidsAlertTable();
            updateNidsStatusLabel();
        });
    connect(m_nidsClearButton, &QPushButton::clicked, this, [this]()
        {
            clearNidsAlerts();
        });
    const auto nidsAlertSequenceForRow = [this](const int row, std::uint64_t& sequenceIdOut) -> bool
        {
            if (m_nidsAlertTable == nullptr || row < 0 || row >= m_nidsAlertTable->rowCount())
            {
                return false;
            }

            QTableWidgetItem* timeItem = m_nidsAlertTable->item(row, toNidsAlertColumn(NidsAlertTableColumn::Time));
            if (timeItem == nullptr)
            {
                return false;
            }

            const QVariant sequenceVariant = timeItem->data(Qt::UserRole);
            if (!sequenceVariant.isValid())
            {
                return false;
            }
            sequenceIdOut = static_cast<std::uint64_t>(sequenceVariant.toULongLong());
            return sequenceIdOut != 0;
        };
    connect(m_nidsAlertTable, &QTableWidget::cellDoubleClicked, this,
        [this, nidsAlertSequenceForRow](const int row, const int /*column*/)
        {
            std::uint64_t sequenceId = 0;
            if (nidsAlertSequenceForRow(row, sequenceId))
            {
                openPacketDetailWindowBySequenceId(sequenceId);
            }
        });
    // NIDS 告警表右键菜单说明：
    // - 该菜单此前在这里和 initializeNidsTab() 各注册过一次，两个槽都会 QMenu::exec()；
    // - Qt 按连接顺序依次调用槽，于是一次右键先弹“复制类”菜单，关掉后又立刻弹出“详情类”菜单，
    //   表现为连续右键两次看到的菜单内容不一致；
    // - 现统一由 NetworkDock.Nids.cpp 的 initializeNidsTab() 注册唯一一份合并后的菜单，此处不再注册。

    // 流量时间轴连接：
    // - ProcessTraceTimelineWidget 内部复用了 ETW 页的框选、拖拽和滚轮缩放工具；
    // - 这里仅接收最终时间范围，并把它叠加到现有规则组过滤与表格重建流程。
    if (m_packetTimelineWidget != nullptr)
    {
        m_packetTimelineWidget->setSelectionChangedCallback(
            [this](const std::uint64_t start100ns, const std::uint64_t end100ns)
            {
                applyPacketTimelineSelection(start100ns, end100ns);
            });
    }

    // 组合过滤控制连接：
    // - 漏斗按钮控制折叠面板显隐；
    // - 规则组支持新增、应用、导入、导出、默认保存、一键清空。
    connect(m_monitorFilterToggleButton, &QPushButton::toggled, this, [this](const bool checked)
        {
            if (m_monitorFilterPanel != nullptr)
            {
                m_monitorFilterPanel->setVisible(checked);
            }
        });

    connect(m_addMonitorFilterGroupButton, &QPushButton::clicked, this, [this]()
        {
            addMonitorFilterRuleGroup();
        });

    connect(m_applyMonitorFilterButton, &QPushButton::clicked, this, [this]()
        {
            applyMonitorFilters();
        });
    connect(m_clearMonitorFilterButton, &QPushButton::clicked, this, [this]()
        {
            clearAllMonitorFilterConfigurations();
        });
    connect(m_saveMonitorFilterButton, &QPushButton::clicked, this, [this]()
        {
            saveMonitorFilterConfigToDefaultPath();
        });
    connect(m_importMonitorFilterButton, &QPushButton::clicked, this, [this]()
        {
            importMonitorFilterConfigFromUserSelectedPath();
        });
    connect(m_exportMonitorFilterButton, &QPushButton::clicked, this, [this]()
        {
            exportMonitorFilterConfigToUserSelectedPath();
        });

    // 限速规则控制连接。
    // 说明：
    // - 当前版本隐藏“进程限速”页，因此这些按钮通常不会被创建；
    // - 保留空指针保护，避免未来临时恢复 initializeRateLimitTab() 以外的路径时
    //   出现 QObject::connect(nullptr, ...) 的启动期崩溃；
    // - 函数无返回值，只在对应按钮存在时建立 UI 到业务函数的连接。
    if (m_applyRateLimitButton != nullptr)
    {
        connect(m_applyRateLimitButton, &QPushButton::clicked, this, [this]()
            {
                applyOrUpdateRateLimitRule();
            });
    }
    if (m_removeRateLimitButton != nullptr)
    {
        connect(m_removeRateLimitButton, &QPushButton::clicked, this, [this]()
            {
                removeSelectedRateLimitRule();
            });
    }
    if (m_clearRateLimitButton != nullptr)
    {
        connect(m_clearRateLimitButton, &QPushButton::clicked, this, [this]()
            {
                clearAllRateLimitRules();
            });
    }

    // 旧连接管理页不再创建；保留实现供回滚，但禁止对空控件建立连接。
    if (m_refreshConnectionButton != nullptr)
    {
        connect(m_refreshConnectionButton, &QPushButton::clicked, this, [this]()
        {
            kLogEvent refreshClickEvent;
            info << refreshClickEvent << "[NetworkDock] 用户触发连接快照手动刷新。" << eol;
            refreshConnectionTables();
        });
    }
    if (m_autoRefreshConnectionButton != nullptr)
    {
        connect(m_autoRefreshConnectionButton, &QPushButton::toggled, this, [this](const bool checked)
        {
            if (m_autoRefreshConnectionButton != nullptr)
            {
                // 图标必须跟随状态：开着时显示“暂停”表示可点击暂停，
                // 关掉后显示“继续”。否则一个按下态的暂停图标会被读成
                // “当前已暂停，点我恢复”，用户反而把正在工作的自动刷新关掉。
                m_autoRefreshConnectionButton->setIcon(QIcon(
                    checked ? QStringLiteral(":/Icon/process_pause.svg")
                    : QStringLiteral(":/Icon/process_resume.svg")));
                m_autoRefreshConnectionButton->setToolTip(
                    checked ? QStringLiteral("自动刷新已开启，点击暂停")
                    : QStringLiteral("自动刷新已关闭，点击继续"));
            }
            if (m_connectionStatusLabel != nullptr)
            {
                m_connectionStatusLabel->setText(
                    checked ? QStringLiteral("状态：自动刷新已开启")
                    : QStringLiteral("状态：自动刷新已关闭"));
            }

            kLogEvent autoRefreshEvent;
            info << autoRefreshEvent
                << "[NetworkDock] 连接自动刷新开关变更, enabled="
                << (checked ? "true" : "false")
                << eol;
        });
    }
    if (m_terminateTcpButton != nullptr)
    {
        connect(m_terminateTcpButton, &QPushButton::clicked, this, [this]()
        {
            terminateSelectedTcpConnection();
        });
    }
    if (m_clearConnectionPidFilterButton != nullptr)
    {
        connect(m_clearConnectionPidFilterButton, &QPushButton::clicked, this, [this]()
        {
            m_connectionPidFilterSet.clear();
            if (m_clearConnectionPidFilterButton != nullptr)
            {
                m_clearConnectionPidFilterButton->setEnabled(false);
            }
            refreshConnectionTables();
        });
    }

    // HTTPS 解析控制连接。
    connect(m_httpsStartProxyButton, &QPushButton::clicked, this, [this]()
        {
            startHttpsProxyService();
        });
    connect(m_httpsStopProxyButton, &QPushButton::clicked, this, [this]()
        {
            stopHttpsProxyService();
        });
    connect(m_httpsTrustCertButton, &QPushButton::clicked, this, [this]()
        {
            ensureHttpsRootCertificateTrusted();
        });
    connect(m_httpsApplyProxyButton, &QPushButton::clicked, this, [this]()
        {
            applyHttpsSystemProxy();
        });
    connect(m_httpsClearProxyButton, &QPushButton::clicked, this, [this]()
        {
            clearHttpsSystemProxy();
        });

    // 连接表 PID 解析辅助：
    // - 从任意连接表（TCP/UDP）指定列提取 PID；
    // - 失败时统一弹窗并记录日志，减少重复代码。
    const auto parsePidFromConnectionRow = [this](
        QTableWidget* tableWidget,
        const int row,
        const int pidColumn,
        std::uint32_t& pidOut,
        const QString& sourceTag) -> bool
        {
            if (tableWidget == nullptr || row < 0 || row >= tableWidget->rowCount())
            {
                return false;
            }

            QTableWidgetItem* pidItem = tableWidget->item(row, pidColumn);
            if (pidItem == nullptr)
            {
                return false;
            }

            if (!tryParsePidText(pidItem->text(), pidOut))
            {
                QMessageBox::information(
                    this,
                    QStringLiteral("连接管理"),
                    QStringLiteral("当前行 PID 无效，无法执行该操作。"));

                kLogEvent parsePidFailEvent;
                warn << parsePidFailEvent
                    << "[NetworkDock] 连接表 PID 解析失败, source="
                    << sourceTag.toStdString()
                    << ", row=" << row
                    << ", pidText=" << pidItem->text().toStdString()
                    << eol;
                return false;
            }
            return true;
        };

    // 打开进程详情辅助：
    // - 连接表与流量表都复用同一套“按 PID 打开详情窗口”逻辑；
    // - 统一维护日志与错误提示格式。
    const auto openProcessDetailByPid = [this](const std::uint32_t targetPid, const QString& sourceTag) -> void
        {
            // 连接表跳转必须避免同步完整静态查询：
            // - QueryProcessStaticDetailByPid 内部默认包含签名校验；
            // - 详情窗口负责后台补齐字段并懒加载高级页面。
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
                << "[NetworkDock] 连接表打开进程详情, source=" << sourceTag.toStdString()
                << ", pid=" << targetPid
                << eol;
        };

    // TCP 表右键菜单：
    // - 支持“终止连接、复制行、跟踪此进程、转到进程详细信息”；
    // - “跟踪此进程”语义为写入 PID 过滤并立即应用。
    if (m_tcpConnectionTable != nullptr)
    {
        connect(
            m_tcpConnectionTable,
            &QWidget::customContextMenuRequested,
            this,
            [this, parsePidFromConnectionRow, openProcessDetailByPid](const QPoint& position)
            {
            const QModelIndex index = m_tcpConnectionTable->indexAt(position);
            if (!index.isValid())
            {
                return;
            }

            QMenu contextMenu(this);
            contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* terminateAction = contextMenu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("终止此 TCP 连接"));
            QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制行"));
            QAction* trackProcessAction = contextMenu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("跟踪此进程"));
            QAction* gotoProcessDetailAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
            QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
                &contextMenu,
                this,
                [this, index, parsePidFromConnectionRow]() -> ks::online_scan::SandboxUploadTarget
                {
                    // 输入：TCP 连接表当前行。
                    // 处理：解析 PID 并查询发起进程 EXE。
                    // 返回：待上传路径和来源说明。
                    ks::online_scan::SandboxUploadTarget uploadTarget;
                    std::uint32_t targetPid = 0;
                    if (!parsePidFromConnectionRow(
                        m_tcpConnectionTable,
                        index.row(),
                        toTcpConnectionColumn(TcpConnectionTableColumn::Pid),
                        targetPid,
                        QStringLiteral("tcp_table_upload")))
                    {
                        uploadTarget.errorText = QStringLiteral("当前 TCP 行没有可解析 PID。");
                        return uploadTarget;
                    }
                    uploadTarget.filePath = QString::fromStdString(ks::process::QueryProcessPathByPid(targetPid));
                    uploadTarget.sourceText = QStringLiteral("网络 TCP 连接 PID=%1").arg(targetPid);
                    return uploadTarget;
                });
            QAction* selectedAction = contextMenu.exec(m_tcpConnectionTable->viewport()->mapToGlobal(position));
            if (selectedAction == terminateAction)
            {
                m_tcpConnectionTable->selectRow(index.row());
                terminateSelectedTcpConnection();
            }
            else if (selectedAction == copyRowAction)
            {
                m_tcpConnectionTable->selectRow(index.row());
                copySelectedConnectionRowToClipboard(m_tcpConnectionTable);
            }
            else if (selectedAction == trackProcessAction)
            {
                m_tcpConnectionTable->selectRow(index.row());

                std::uint32_t targetPid = 0;
                if (!parsePidFromConnectionRow(
                    m_tcpConnectionTable,
                    index.row(),
                    toTcpConnectionColumn(TcpConnectionTableColumn::Pid),
                    targetPid,
                    QStringLiteral("tcp_table")))
                {
                    return;
                }

                addOrTrackProcessPid(targetPid);

                kLogEvent trackEvent;
                info << trackEvent
                    << "[NetworkDock] TCP 连接右键触发进程跟踪, pid=" << targetPid
                    << eol;
            }
            else if (selectedAction == gotoProcessDetailAction)
            {
                m_tcpConnectionTable->selectRow(index.row());

                std::uint32_t targetPid = 0;
                if (!parsePidFromConnectionRow(
                    m_tcpConnectionTable,
                    index.row(),
                    toTcpConnectionColumn(TcpConnectionTableColumn::Pid),
                    targetPid,
                    QStringLiteral("tcp_table")))
                {
                    return;
                }
                openProcessDetailByPid(targetPid, QStringLiteral("tcp_table"));
            }
            else if (selectedAction == uploadVirusTotalAction)
            {
                return;
            }
            });
    }

    // UDP 表右键菜单：
    // - UDP 无标准“按连接终止”API，因此不提供 terminate；
    // - 仍支持复制行、跟踪此进程、转到进程详情。
    if (m_udpEndpointTable != nullptr)
    {
        connect(
            m_udpEndpointTable,
            &QWidget::customContextMenuRequested,
            this,
            [this, parsePidFromConnectionRow, openProcessDetailByPid](const QPoint& position)
            {
            const QModelIndex index = m_udpEndpointTable->indexAt(position);
            if (!index.isValid())
            {
                return;
            }

            QMenu contextMenu(this);
            contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制行"));
            QAction* trackProcessAction = contextMenu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("跟踪此进程"));
            QAction* gotoProcessDetailAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
            QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
                &contextMenu,
                this,
                [this, index, parsePidFromConnectionRow]() -> ks::online_scan::SandboxUploadTarget
                {
                    // 输入：UDP 端点表当前行。
                    // 处理：解析 PID 并查询发起进程 EXE。
                    // 返回：待上传路径和来源说明。
                    ks::online_scan::SandboxUploadTarget uploadTarget;
                    std::uint32_t targetPid = 0;
                    if (!parsePidFromConnectionRow(
                        m_udpEndpointTable,
                        index.row(),
                        toUdpEndpointColumn(UdpEndpointTableColumn::Pid),
                        targetPid,
                        QStringLiteral("udp_table_upload")))
                    {
                        uploadTarget.errorText = QStringLiteral("当前 UDP 行没有可解析 PID。");
                        return uploadTarget;
                    }
                    uploadTarget.filePath = QString::fromStdString(ks::process::QueryProcessPathByPid(targetPid));
                    uploadTarget.sourceText = QStringLiteral("网络 UDP 端点 PID=%1").arg(targetPid);
                    return uploadTarget;
                });
            QAction* selectedAction = contextMenu.exec(m_udpEndpointTable->viewport()->mapToGlobal(position));
            if (selectedAction == copyRowAction)
            {
                m_udpEndpointTable->selectRow(index.row());
                copySelectedConnectionRowToClipboard(m_udpEndpointTable);
            }
            else if (selectedAction == trackProcessAction)
            {
                m_udpEndpointTable->selectRow(index.row());

                std::uint32_t targetPid = 0;
                if (!parsePidFromConnectionRow(
                    m_udpEndpointTable,
                    index.row(),
                    toUdpEndpointColumn(UdpEndpointTableColumn::Pid),
                    targetPid,
                    QStringLiteral("udp_table")))
                {
                    return;
                }

                addOrTrackProcessPid(targetPid);

                kLogEvent trackEvent;
                info << trackEvent
                    << "[NetworkDock] UDP 端点右键触发进程跟踪, pid=" << targetPid
                    << eol;
            }
            else if (selectedAction == gotoProcessDetailAction)
            {
                m_udpEndpointTable->selectRow(index.row());

                std::uint32_t targetPid = 0;
                if (!parsePidFromConnectionRow(
                    m_udpEndpointTable,
                    index.row(),
                    toUdpEndpointColumn(UdpEndpointTableColumn::Pid),
                    targetPid,
                    QStringLiteral("udp_table")))
                {
                    return;
                }
                openProcessDetailByPid(targetPid, QStringLiteral("udp_table"));
            }
            else if (selectedAction == uploadVirusTotalAction)
            {
                return;
            }
            });
    }

    // 请求构造控制连接：执行请求、重置表单、模式切换自动调整默认参数。
    connect(m_manualExecuteButton, &QPushButton::clicked, this, [this]()
        {
            executeManualRequest();
        });
    connect(m_manualResetButton, &QPushButton::clicked, this, [this]()
        {
            kLogEvent resetClickEvent;
            info << resetClickEvent << "[NetworkDock] 用户点击请求构造重置按钮。" << eol;
            resetManualRequestForm();
        });
    connect(m_manualApiCombo, static_cast<void(QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, [this](const int /*index*/)
        {
            if (m_manualApiCombo == nullptr)
            {
                return;
            }

            const ks::network::ManualNetworkApiKind apiKind =
                static_cast<ks::network::ManualNetworkApiKind>(m_manualApiCombo->currentData().toInt());

            // 模式切换时只更新推荐默认参数，不强行覆盖用户已勾选的“手动覆盖”语义。
            if (m_manualOverrideSocketParameterCheck != nullptr &&
                m_manualOverrideSocketParameterCheck->isChecked())
            {
                kLogEvent switchApiEvent;
                dbg << switchApiEvent
                    << "[NetworkDock] 请求构造 API 模式切换（保留手工参数）, api="
                    << ks::network::ManualNetworkApiKindToString(apiKind)
                    << eol;
                return;
            }

            if (m_manualSocketTypeEdit == nullptr || m_manualProtocolEdit == nullptr)
            {
                return;
            }

            if (apiKind == ks::network::ManualNetworkApiKind::WinSockTcp)
            {
                m_manualSocketTypeEdit->setText(QStringLiteral("1")); // SOCK_STREAM
                m_manualProtocolEdit->setText(QStringLiteral("6"));   // IPPROTO_TCP
                if (m_manualConnectBeforeSendCheck != nullptr)
                {
                    m_manualConnectBeforeSendCheck->setChecked(true);
                }
            }
            else
            {
                m_manualSocketTypeEdit->setText(QStringLiteral("2")); // SOCK_DGRAM
                m_manualProtocolEdit->setText(QStringLiteral("17"));  // IPPROTO_UDP
            }

            const bool overrideSocketParameters = m_manualOverrideSocketParameterCheck != nullptr
                && m_manualOverrideSocketParameterCheck->isChecked();
            kLogEvent switchApiEvent;
            dbg << switchApiEvent
                << "[NetworkDock] 请求构造 API 模式切换, api="
                << ks::network::ManualNetworkApiKindToString(apiKind)
                << ", overrideSocket="
                << (overrideSocketParameters ? "true" : "false")
                << eol;
        });

    // 多线程下载页连接：开始下载、选择目录、URL回车触发。
    connect(m_multiDownloadStartButton, &QPushButton::clicked, this, [this]()
        {
            startMultiThreadDownloadTask();
        });
    connect(m_multiDownloadBrowseDirButton, &QPushButton::clicked, this, [this]()
        {
            browseMultiThreadDownloadDirectory();
        });
    connect(m_multiDownloadUrlEdit, &QLineEdit::returnPressed, this, [this]()
        {
            startMultiThreadDownloadTask();
        });

    // 下载捕获设置连接：开关/后缀变化后写入 JSON。
    connect(m_multiDownloadAutoCaptureClipboardCheck, &QCheckBox::toggled, this, [this](const bool checked)
        {
            m_multiDownloadAutoCaptureClipboardEnabled = checked;
            saveMultiThreadDownloadCaptureSettings();
        });
    connect(m_multiDownloadCaptureSuffixEdit, &QLineEdit::editingFinished, this, [this]()
        {
            saveMultiThreadDownloadCaptureSettings();
        });
    connect(m_multiDownloadSaveCaptureSettingsButton, &QPushButton::clicked, this, [this]()
        {
            saveMultiThreadDownloadCaptureSettings();
        });

    // 剪贴板监听连接：
    // - 仅处理主剪贴板文本变化；
    // - 自动捕获开关关闭时，检测函数会快速返回。
    QClipboard* clipboardObject = QGuiApplication::clipboard(); // clipboardObject：系统主剪贴板对象。
    if (clipboardObject != nullptr)
    {
        connect(clipboardObject, &QClipboard::changed, this, [this](const QClipboard::Mode mode)
            {
                if (mode != QClipboard::Clipboard)
                {
                    return;
                }
                onMultiThreadDownloadClipboardChanged();
            });
    }

    // 多线程下载任务选中变化：切换右侧分段详情与总进度条绑定任务。
    connect(m_multiDownloadTaskTable, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            if (m_multiDownloadTaskTable == nullptr)
            {
                return;
            }

            const QList<QTableWidgetItem*> selectedItemList = m_multiDownloadTaskTable->selectedItems();
            if (selectedItemList.isEmpty())
            {
                m_multiDownloadSelectedTaskId = 0;
                refreshMultiThreadDownloadUi();
                return;
            }

            const int selectedRow = selectedItemList.first()->row();
            QTableWidgetItem* idItem = m_multiDownloadTaskTable->item(selectedRow, 0);
            if (idItem == nullptr)
            {
                m_multiDownloadSelectedTaskId = 0;
                refreshMultiThreadDownloadUi();
                return;
            }

            bool parseOk = false;
            const int selectedTaskId = idItem->text().toInt(&parseOk, 10);
            m_multiDownloadSelectedTaskId = parseOk ? selectedTaskId : 0;
            refreshMultiThreadDownloadUi();
        });

    // 双击报文行：打开独立详情窗口（非阻塞）。
    connect(m_packetTable, &QTableWidget::cellDoubleClicked, this,
        [this](const int row, const int /*column*/)
        {
            openPacketDetailWindowFromTableRow(m_packetTable, row);
        });

    // 右键菜单：查看详情 / 预填阻断规则 / 复制行 / 批量复制ASCII/HEX / 重放到请求构造 / 跟踪此进程 / 转到进程详细信息。
    connect(m_packetTable, &QWidget::customContextMenuRequested, this,
        [this](const QPoint& position)
        {
            if (m_packetTable == nullptr)
            {
                return;
            }

            const QModelIndex index = m_packetTable->indexAt(position);
            const bool hasSelection =
                (m_packetTable->selectionModel() != nullptr && m_packetTable->selectionModel()->hasSelection());
            if (!index.isValid() && !hasSelection)
            {
                return;
            }
            if (index.isValid() && !hasSelection)
            {
                // 单行右键锚定：
                // - 输入：当前鼠标所在报文行；
                // - 处理：没有多选时把右键行设为当前行，复制/详情/跟踪都使用同一个 anchor；
                // - 返回：无；已有多选时不破坏用户选择。
                m_packetTable->setCurrentCell(index.row(), index.column());
                m_packetTable->selectRow(index.row());
            }

            // collectTargetRows 作用：
            // - 收集本次右键动作要处理的行号集合；
            // - 若已有多选则优先用多选结果；否则回退到当前右键行。
            const auto collectTargetRows = [this, index]() -> std::vector<int>
                {
                    std::vector<int> rowList;
                    if (m_packetTable != nullptr && m_packetTable->selectionModel() != nullptr)
                    {
                        const QModelIndexList selectedRowIndexList =
                            m_packetTable->selectionModel()->selectedRows(toPacketColumn(PacketTableColumn::Time));
                        rowList.reserve(static_cast<std::size_t>(selectedRowIndexList.size()));
                        for (const QModelIndex& selectedRowIndex : selectedRowIndexList)
                        {
                            rowList.push_back(selectedRowIndex.row());
                        }
                    }
                    if (rowList.empty() && index.isValid())
                    {
                        rowList.push_back(index.row());
                    }

                    std::sort(rowList.begin(), rowList.end());
                    rowList.erase(std::unique(rowList.begin(), rowList.end()), rowList.end());
                    return rowList;
                };

            // collectSequenceListByRows 作用：
            // - 按行号提取报文 sequenceId（存于“时间列 UserRole”）；
            // - 后续复制 ASCII/HEX 与打开详情都依赖该序号回查缓存实体。
            const auto collectSequenceListByRows = [this](const std::vector<int>& rowList) -> std::vector<std::uint64_t>
                {
                    std::vector<std::uint64_t> sequenceList;
                    sequenceList.reserve(rowList.size());
                    for (const int row : rowList)
                    {
                        if (m_packetTable == nullptr || row < 0 || row >= m_packetTable->rowCount())
                        {
                            continue;
                        }

                        QTableWidgetItem* timeItem = m_packetTable->item(row, toPacketColumn(PacketTableColumn::Time));
                        if (timeItem == nullptr)
                        {
                            continue;
                        }

                        const QVariant sequenceVariant = timeItem->data(Qt::UserRole);
                        if (!sequenceVariant.isValid())
                        {
                            continue;
                        }
                        sequenceList.push_back(static_cast<std::uint64_t>(sequenceVariant.toULongLong()));
                    }
                    std::sort(sequenceList.begin(), sequenceList.end());
                    sequenceList.erase(std::unique(sequenceList.begin(), sequenceList.end()), sequenceList.end());
                    return sequenceList;
                };

            QMenu contextMenu(this);
            contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* detailAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("查看报文详情"));
            QAction* addBlockRuleAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
                QStringLiteral("预填阻断规则"));
            addBlockRuleAction->setEnabled(m_firewallPage != nullptr);
            QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制行"));
            QAction* copyAsciiAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制选中报文ASCII"));
            // 仅正文复制动作：不拼接报文头部元信息，只输出 payload 的 ASCII 文本。
            QAction* copyPayloadAsciiOnlyAction = contextMenu.addAction(
                QIcon(":/Icon/process_copy_row.svg"),
                QStringLiteral("复制选中payload ASCII（仅正文）"));
            QAction* copyHexAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制选中报文16进制"));
            // 报文重放动作：把单条报文自动填充到“请求构造”页，用户可二次编辑再执行。
            QAction* replayToManualRequestAction = contextMenu.addAction(
                QIcon(":/Icon/codeeditor_paste.svg"),
                QStringLiteral("重放到请求构造"));
            replayToManualRequestAction->setToolTip(QStringLiteral("将当前报文填充到请求构造页，便于快速重放。"));
            contextMenu.addSeparator();
            QAction* trackProcessAction = contextMenu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("跟踪此进程"));
            QAction* gotoProcessDetailAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
            QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
                &contextMenu,
                this,
                [this, index]() -> ks::online_scan::SandboxUploadTarget
                {
                    // 输入：报文表右键锚定行或当前多选首行。
                    // 处理：读取 PID 列并查询发起进程 EXE。
                    // 返回：待上传路径和来源说明。
                    ks::online_scan::SandboxUploadTarget uploadTarget;
                    int rowIndex = -1;
                    if (m_packetTable != nullptr && m_packetTable->selectionModel() != nullptr)
                    {
                        const QModelIndexList selectedRows =
                            m_packetTable->selectionModel()->selectedRows(toPacketColumn(PacketTableColumn::Time));
                        if (!selectedRows.isEmpty())
                        {
                            rowIndex = selectedRows.front().row();
                        }
                    }
                    if (rowIndex < 0 && index.isValid())
                    {
                        rowIndex = index.row();
                    }
                    if (rowIndex < 0)
                    {
                        uploadTarget.errorText = QStringLiteral("当前报文选择为空，无法解析 PID。");
                        return uploadTarget;
                    }
                    const QTableWidgetItem* pidItem =
                        (m_packetTable != nullptr && rowIndex >= 0)
                        ? m_packetTable->item(rowIndex, toPacketColumn(PacketTableColumn::Pid))
                        : nullptr;
                    std::uint32_t targetPid = 0;
                    if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &targetPid))
                    {
                        uploadTarget.errorText = QStringLiteral("当前报文行没有可解析 PID。");
                        return uploadTarget;
                    }
                    uploadTarget.filePath = QString::fromStdString(ks::process::QueryProcessPathByPid(targetPid));
                    uploadTarget.sourceText = QStringLiteral("网络报文 PID=%1").arg(targetPid);
                    return uploadTarget;
                });

            QAction* selectedAction = contextMenu.exec(m_packetTable->viewport()->mapToGlobal(position));
            if (selectedAction == nullptr)
            {
                return;
            }

            const std::vector<int> targetRows = collectTargetRows();
            const int anchorRow = index.isValid() ? index.row() : (targetRows.empty() ? -1 : targetRows.front());
            if (selectedAction == detailAction)
            {
                if (anchorRow >= 0)
                {
                    openPacketDetailWindowFromTableRow(m_packetTable, anchorRow);
                }
            }
            else if (selectedAction == addBlockRuleAction)
            {
                const std::vector<std::uint64_t> sequenceList = collectSequenceListByRows(
                    anchorRow >= 0 ? std::vector<int>{ anchorRow } : std::vector<int>{});
                if (sequenceList.empty() || m_firewallPage == nullptr)
                {
                    return;
                }

                const auto packetIt = m_packetBySequence.find(sequenceList.front());
                if (packetIt == m_packetBySequence.end())
                {
                    return;
                }

                const ks::network::PacketRecord& packetRecord = packetIt->second;
                m_firewallPage->addBlockRuleFromEvidence(
                    QString::fromUtf8(packetRecord.remoteAddress.c_str()),
                    QString::number(packetRecord.remotePort),
                    toQString(ks::network::PacketProtocolToString(packetRecord.protocol)),
                    toQString(ks::network::PacketDirectionToString(packetRecord.direction)),
                    QStringLiteral("流量报文"));
            }
            else if (selectedAction == copyRowAction)
            {
                if (anchorRow < 0)
                {
                    return;
                }

                QStringList rowTextList;
                rowTextList.reserve(m_packetTable->columnCount());
                for (int columnIndex = 0; columnIndex < m_packetTable->columnCount(); ++columnIndex)
                {
                    QTableWidgetItem* item = m_packetTable->item(anchorRow, columnIndex);
                    rowTextList.push_back(item == nullptr ? QString() : item->text());
                }
                if (QGuiApplication::clipboard() != nullptr)
                {
                    QGuiApplication::clipboard()->setText(rowTextList.join('\t'));
                }

                kLogEvent copyPacketRowEvent;
                dbg << copyPacketRowEvent
                    << "[NetworkDock] 已复制报文行, row=" << anchorRow
                    << ", columnCount=" << m_packetTable->columnCount()
                    << eol;
            }

            else if (
                selectedAction == copyAsciiAction ||
                selectedAction == copyPayloadAsciiOnlyAction ||
                selectedAction == copyHexAction)
            {
                const std::vector<std::uint64_t> sequenceList = collectSequenceListByRows(targetRows);
                if (sequenceList.empty())
                {
                    return;
                }

                // copyAsciiWithHeaderMode 用途：是否复制“含报文头元信息”的 ASCII 模式。
                const bool copyAsciiWithHeaderMode = (selectedAction == copyAsciiAction);
                // copyPayloadAsciiOnlyMode 用途：是否复制“仅 payload 正文”的 ASCII 模式。
                const bool copyPayloadAsciiOnlyMode = (selectedAction == copyPayloadAsciiOnlyAction);
                // copyHexMode 用途：是否复制十六进制模式。
                const bool copyHexMode = (selectedAction == copyHexAction);

                // blockTextList 用途：按“每个报文一个文本块”拼接复制结果。
                QStringList blockTextList;
                blockTextList.reserve(static_cast<int>(sequenceList.size()));
                for (const std::uint64_t sequenceId : sequenceList)
                {
                    const auto iterator = m_packetBySequence.find(sequenceId);
                    if (iterator == m_packetBySequence.end())
                    {
                        continue;
                    }

                    const ks::network::PacketRecord& packetRecord = iterator->second;
                    if (copyHexMode)
                    {
                        // 十六进制模式：始终保留报文头元信息，方便回溯上下文。
                        blockTextList.push_back(QStringLiteral("%1\n%2")
                            .arg(buildPacketCopyHeaderLine(packetRecord))
                            .arg(buildPacketHexAsciiDumpText(packetRecord)));
                        continue;
                    }

                    const QString payloadAsciiText = buildPayloadAsciiFullText(packetRecord);
                    if (copyPayloadAsciiOnlyMode)
                    {
                        // 仅正文模式：不拼接任何报文头字段，只保留 payload ASCII。
                        blockTextList.push_back(payloadAsciiText);
                        continue;
                    }

                    if (copyAsciiWithHeaderMode)
                    {
                        // ASCII 标准模式：保留报文头元信息 + payload ASCII 正文。
                        blockTextList.push_back(QStringLiteral("%1\n%2")
                            .arg(buildPacketCopyHeaderLine(packetRecord))
                            .arg(payloadAsciiText));
                    }
                }

                if (blockTextList.isEmpty())
                {
                    return;
                }

                // blockJoinSeparator 用途：统一多报文块分隔符，避免复制后粘连难读。
                const QString blockJoinSeparator = copyPayloadAsciiOnlyMode
                    ? QStringLiteral("\n\n")
                    : QStringLiteral("\n\n============================================================\n\n");
                const QString finalText = blockTextList.join(blockJoinSeparator);
                if (QGuiApplication::clipboard() != nullptr)
                {
                    QGuiApplication::clipboard()->setText(finalText);
                }

                // copyModeText 用途：日志输出的模式标识，便于后续问题定位。
                const std::string copyModeText = copyHexMode
                    ? "hex"
                    : (copyPayloadAsciiOnlyMode ? "ascii_payload_only" : "ascii");

                kLogEvent copyPacketBatchEvent;
                info << copyPacketBatchEvent
                    << "[NetworkDock] 批量复制报文内容, mode=" << copyModeText
                    << ", packetCount=" << sequenceList.size()
                    << ", outputChars=" << finalText.size()
                    << eol;
            }
            else if (selectedAction == replayToManualRequestAction)
            {
                if (anchorRow >= 0)
                {
                    replayPacketToManualRequestByTableRow(anchorRow);
                }
            }
            else if (selectedAction == trackProcessAction)
            {
                if (anchorRow >= 0)
                {
                    trackProcessByTableRow(anchorRow);
                }
            }
            else if (selectedAction == gotoProcessDetailAction)
            {
                if (anchorRow >= 0)
                {
                    gotoProcessDetailByTableRow(anchorRow);
                }
            }
            else if (selectedAction == uploadVirusTotalAction)
            {
                return;
            }
        });

    // ARP 缓存页控制连接。
    connect(m_refreshArpButton, &QPushButton::clicked, this, [this]()
        {
            refreshArpCacheTable();
        });
    connect(m_addArpButton, &QPushButton::clicked, this, [this]()
        {
            addArpCacheEntry();
        });
    connect(m_removeArpButton, &QPushButton::clicked, this, [this]()
        {
            removeSelectedArpCacheEntry();
        });
    connect(m_flushArpButton, &QPushButton::clicked, this, [this]()
        {
            flushArpCache();
        });

    // DNS 缓存页控制连接。
    connect(m_refreshDnsButton, &QPushButton::clicked, this, [this]()
        {
            refreshDnsCacheTable();
        });
    connect(m_removeDnsButton, &QPushButton::clicked, this, [this]()
        {
            removeDnsCacheEntry();
        });
    connect(m_flushDnsButton, &QPushButton::clicked, this, [this]()
        {
            flushDnsCache();
        });
    connect(m_dnsTable, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            if (m_dnsEntryEdit == nullptr || m_dnsTable == nullptr)
            {
                return;
            }

            const QList<QTableWidgetItem*> selectedItemList = m_dnsTable->selectedItems();
            if (selectedItemList.isEmpty())
            {
                return;
            }

            const int row = selectedItemList.first()->row();
            QTableWidgetItem* hostItem = m_dnsTable->item(row, 0);
            if (hostItem != nullptr)
            {
                m_dnsEntryEdit->setText(hostItem->text());
            }
        });

    // 存活主机扫描页连接。
    connect(m_startAliveScanButton, &QPushButton::clicked, this, [this]()
        {
            startAliveHostScan();
        });
    connect(m_stopAliveScanButton, &QPushButton::clicked, this, [this]()
        {
            stopAliveHostScan();
        });

    // 初始化按钮可用状态。
    updateMonitorButtonState();

    // 初始化新增页首屏数据。
    refreshMultiThreadDownloadUi();
    refreshArpCacheTable();
    refreshDnsCacheTable();
}

void NetworkDock::startTrafficMonitor()
{
    if (m_trafficService == nullptr)
    {
        return;
    }

    // 正在停止时不允许立刻重启，避免服务线程状态在“停/启”间抖动。
    if (m_monitorStopInProgress.load())
    {
        if (m_monitorStatusLabel != nullptr)
        {
            m_monitorStatusLabel->setText(QStringLiteral("状态：停止中，请稍候..."));
        }
        return;
    }

    // 若上次停止线程对象仍残留（通常已结束），这里做一次回收，避免线程句柄泄漏。
    if (m_monitorStopThread != nullptr && m_monitorStopThread->joinable())
    {
        m_monitorStopThread->join();
    }
    m_monitorStopThread.reset();

    // 每次启动前清零“后台队列丢包计数”，便于观察本次运行状态。
    {
        std::lock_guard<std::mutex> guard(m_pendingPacketMutex);
        m_droppedPacketCount = 0;
    }

    // 先探测版本化 R0 WFP IP packet IOCTL；旧驱动或逐包数据面不可用时立即回退 R3。
    // 后台探测失败会自动调用 startR3TrafficMonitor，不需要用户二次点击。
    const std::uint64_t generation = m_monitorGeneration.fetch_add(1) + 1ULL;
    m_monitorSource = TrafficMonitorSource::Starting;
    m_monitorRunning = true;

    // 启用 R0 数据面是一次同步 IOCTL（CreateFileW + DeviceIoControl，无 OVERLAPPED），
    // 内核侧要注册 WFP callout/filter 并初始化 ring buffer，因此整段控制流放到后台线程；
    // UI 线程只先把按钮状态与“正在探测”提示落地，结果回投后再决定进 R0 还是回退 R3。
    if (m_monitorStatusLabel != nullptr)
    {
        m_monitorStatusLabel->setText(QStringLiteral("状态：正在探测 R0 WFP IPv4/IPv6 逐包数据源..."));
    }
    updateMonitorButtonState();

    const QPointer<NetworkDock> guardedSelf(this);
    std::thread([guardedSelf, generation]()
        {
            const ksword::ark::DriverClient driverClient;
            const ksword::ark::NetworkTrafficCaptureControlResult captureControl =
                driverClient.controlNetworkTrafficCapture(true);
            const bool r0CaptureEnabled =
                captureControl.io.ok &&
                !captureControl.unsupported &&
                captureControl.response.status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                captureControl.response.enabled == 1UL;
            if (!r0CaptureEnabled)
            {
                // 控制响应损坏或启用后业务拒绝时也做一次幂等停用，避免未知半成功状态。
                // 该停用与启用在同一后台线程内串行完成，不会再占用 UI 线程。
                (void)driverClient.controlNetworkTrafficCapture(false);
            }

            const QString captureMessageText = QString::fromStdString(captureControl.io.message);
            const std::string captureMessageLogText = captureControl.io.message;
            QCoreApplication* const appInstance = QCoreApplication::instance();
            if (appInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                appInstance,
                [guardedSelf, generation, r0CaptureEnabled, captureMessageText, captureMessageLogText]()
                {
                    if (guardedSelf == nullptr)
                    {
                        return;
                    }

                    // 用户可能在探测返回前就点了停止或重新开始，此时本轮结果整体作废；
                    // 若本轮确实把数据面打开了，还要再补一次异步幂等停用。
                    if (guardedSelf->m_monitorGeneration.load() != generation ||
                        guardedSelf->m_monitorSource != TrafficMonitorSource::Starting)
                    {
                        if (r0CaptureEnabled)
                        {
                            disableNetworkTrafficCaptureAsync();
                        }
                        return;
                    }

                    if (!r0CaptureEnabled)
                    {
                        guardedSelf->startR3TrafficMonitor(captureMessageText);
                        kLogEvent fallbackEvent;
                        warn << fallbackEvent
                             << "[NetworkDock] R0 逐包数据面启用失败，已回退 R3: "
                             << captureMessageLogText << eol;
                        return;
                    }

                    // 新捕获会话由 R0 清空 ring 并从 sequence=1 重新计数，R3 cursor 必须同步归零。
                    guardedSelf->m_r0LastEventSequence = 0ULL;
                    guardedSelf->m_r0LastDroppedEventCount = 0ULL;
                    guardedSelf->refreshR0TrafficSnapshotAsync(generation, true);
                    guardedSelf->updateMonitorButtonState();
                },
                Qt::QueuedConnection);
        }).detach();

    kLogEvent startEvent;
    info << startEvent << "[NetworkDock] 用户触发网络监控启动。" << eol;
}

void NetworkDock::stopTrafficMonitor()
{
    if (m_trafficService == nullptr)
    {
        return;
    }

    // 线程正在停机时直接返回，避免重复点击导致多个 stop 线程并发。
    if (m_monitorStopInProgress.exchange(true))
    {
        return;
    }

    const TrafficMonitorSource sourceBeforeStop = m_monitorSource;
    m_monitorGeneration.fetch_add(1);
    m_monitorSource = TrafficMonitorSource::Stopped;
    if (m_r0TrafficRefreshTimer != nullptr)
    {
        m_r0TrafficRefreshTimer->stop();
    }

    // 停用 R0 数据面同样是一次同步 IOCTL，放到后台线程执行，界面按“停用成功”乐观推进；
    // m_monitorStopInProgress 保持置位直到停用回投，这样用户无法在停用尚未落地时抢先重启，
    // 避免“启用/停用”两条后台控制流互相插队把数据面留在错误状态。
    const bool r0DisableDispatched =
        sourceBeforeStop == TrafficMonitorSource::R0 ||
        sourceBeforeStop == TrafficMonitorSource::Starting;
    if (r0DisableDispatched)
    {
        const QPointer<NetworkDock> guardedSelf(this);
        const std::uint64_t stopGeneration = m_monitorGeneration.load();
        std::thread([guardedSelf, stopGeneration]()
            {
                const ksword::ark::DriverClient driverClient;
                const ksword::ark::NetworkTrafficCaptureControlResult captureControl =
                    driverClient.controlNetworkTrafficCapture(false);
                const bool r0StopConfirmed =
                    captureControl.io.ok &&
                    !captureControl.unsupported &&
                    captureControl.response.status == KSWORD_ARK_NETWORK_STATUS_DISABLED &&
                    captureControl.response.enabled == 0UL;
                if (!r0StopConfirmed)
                {
                    kLogEvent stopFailureEvent;
                    warn << stopFailureEvent
                         << "[NetworkDock] R0 逐包数据面停用失败: "
                         << captureControl.io.message << eol;
                }

                const QString r0StopFailure = r0StopConfirmed
                    ? QString()
                    : QString::fromStdString(captureControl.io.message);
                QCoreApplication* const appInstance = QCoreApplication::instance();
                if (appInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    appInstance,
                    [guardedSelf, stopGeneration, r0StopFailure]()
                    {
                        if (guardedSelf == nullptr)
                        {
                            return;
                        }

                        // 停用已经落地，释放“停止中”闸门，按钮恢复可点。
                        guardedSelf->m_monitorStopInProgress.store(false);
                        guardedSelf->updateMonitorButtonState();
                        if (r0StopFailure.isEmpty() ||
                            guardedSelf->m_monitorStatusLabel == nullptr)
                        {
                            return;
                        }

                        // 停用失败提示只对“仍停在本轮停止结果上”的界面有效，
                        // 用户已经重新开始抓包时不覆盖新的运行状态文本。
                        if (guardedSelf->m_monitorGeneration.load() != stopGeneration ||
                            guardedSelf->m_monitorSource != TrafficMonitorSource::Stopped)
                        {
                            return;
                        }
                        guardedSelf->m_monitorStatusLabel->setText(
                            QStringLiteral("状态：界面已停止，但 R0 数据面停用失败：%1")
                                .arg(r0StopFailure));
                    },
                    Qt::QueuedConnection);
            }).detach();
    }

    // UI 立即切换到“停止中”，给用户及时反馈，避免误判“按钮没反应”。
    m_monitorRunning = false;
    if (m_monitorStatusLabel != nullptr)
    {
        m_monitorStatusLabel->setText(QStringLiteral("状态：停止中..."));
    }
    updateMonitorButtonState();

    // R0/探测模式没有 R3 抓包线程需要 join，可在 UI 线程立即完成停止。
    if (sourceBeforeStop != TrafficMonitorSource::R3 || !m_trafficService->IsRunning())
    {
        // 已经派发异步停用时，停止闸门由停用回投负责释放，这里不能提前放开。
        if (!r0DisableDispatched)
        {
            m_monitorStopInProgress.store(false);
        }
        if (m_packetTimelineSessionActive)
        {
            endPacketTimelineMonitorSession();
        }
        if (m_monitorStatusLabel != nullptr)
        {
            m_monitorStatusLabel->setText(QStringLiteral("状态：已停止（来源：无）"));
        }
        updateMonitorButtonState();
        return;
    }

    // 先回收上一次 stop 线程对象，确保本轮只保留一个 stop worker。
    if (m_monitorStopThread != nullptr && m_monitorStopThread->joinable())
    {
        m_monitorStopThread->join();
    }
    m_monitorStopThread.reset();

    // 把 StopCapture 放到后台线程，避免主线程 join 导致界面卡顿。
    QPointer<NetworkDock> guardThis(this);
    ks::network::TrafficMonitorService* trafficServicePtr = m_trafficService.get();
    m_monitorStopThread = std::make_unique<std::thread>([guardThis, trafficServicePtr]() {
        if (trafficServicePtr != nullptr)
        {
            trafficServicePtr->StopCapture();
        }

        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }

            // stop 线程退出后再 join，保证不会在 UI 线程长时间阻塞。
            if (guardThis->m_monitorStopThread != nullptr && guardThis->m_monitorStopThread->joinable())
            {
                guardThis->m_monitorStopThread->join();
            }
            guardThis->m_monitorStopThread.reset();
            guardThis->m_monitorStopInProgress.store(false);
            guardThis->m_monitorRunning = false;
            guardThis->m_monitorSource = TrafficMonitorSource::Stopped;
            guardThis->endPacketTimelineMonitorSession();
            if (guardThis->m_monitorStatusLabel != nullptr)
            {
                guardThis->m_monitorStatusLabel->setText(QStringLiteral("状态：已停止"));
            }
            guardThis->updateMonitorButtonState();

            kLogEvent stopFinishedEvent;
            info << stopFinishedEvent << "[NetworkDock] 后台停止流程完成，抓包线程已退出。" << eol;
        }, Qt::QueuedConnection);
    });

    kLogEvent stopEvent;
    info << stopEvent << "[NetworkDock] 用户触发网络监控停止（异步）。" << eol;
}

void NetworkDock::refreshR0TrafficSnapshotAsync(
    const std::uint64_t generation,
    const bool initialProbe)
{
    if (m_r0TrafficRefreshPending.exchange(true))
    {
        // 用户可能在上一代 R0 查询尚未返回时停止并立即重启。
        // 初始探测不能静默丢弃，否则新一代会永久停在 Starting 状态。
        if (initialProbe)
        {
            QTimer::singleShot(120, this, [this, generation]()
            {
                if (m_monitorGeneration.load() == generation
                    && m_monitorSource == TrafficMonitorSource::Starting)
                {
                    refreshR0TrafficSnapshotAsync(generation, true);
                }
            });
        }
        return;
    }

    const std::uint64_t afterSequence = m_r0LastEventSequence;
    QPointer<NetworkDock> safeThis(this);
    std::thread([safeThis, generation, initialProbe, afterSequence]()
    {
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::NetworkTrafficPacketResult packetResult =
            driverClient.queryNetworkTrafficPackets(
                afterSequence,
                KSWORD_ARK_NETWORK_TRAFFIC_MAX_REQUESTED_ROWS);
        const bool r0Usable =
            packetResult.io.ok &&
            !packetResult.unsupported &&
            packetResult.status == KSWORD_ARK_NETWORK_STATUS_APPLIED;

        std::vector<ks::network::PacketRecord> packetRecords;
        if (r0Usable)
        {
            ks::network::detail::ConnectionPidResolver pidResolver;
            ks::network::detail::ProcessNameResolver processNameResolver;
            packetRecords.reserve(packetResult.entries.size());
            for (const KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW& packetRow : packetResult.entries)
            {
                packetRecords.push_back(buildR0WfpPacketRecord(
                    packetRow,
                    pidResolver,
                    processNameResolver));
            }
        }

        const QString diagnosticText = r0Usable
            ? QStringLiteral("新增=%1/%2，cursor=%3，ring覆盖=%4，cursor缺口=%5")
                .arg(static_cast<qulonglong>(packetRecords.size()))
                .arg(packetResult.returnedCount)
                .arg(static_cast<qulonglong>(packetResult.nextSequence))
                .arg(static_cast<qulonglong>(packetResult.droppedPacketCount))
                .arg(static_cast<qulonglong>(packetResult.cursorGapCount))
            : QStringLiteral("packet=%1；status=%2；lastStatus=0x%3")
                .arg(QString::fromUtf8(packetResult.io.message.c_str()))
                .arg(packetResult.status)
                .arg(static_cast<quint32>(packetResult.lastStatus), 8, 16, QChar('0'));

        if (safeThis.isNull())
        {
            (void)driverClient.controlNetworkTrafficCapture(false);
            return;
        }
        QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis,
                generation,
                initialProbe,
                r0Usable,
                diagnosticText,
                nextSequence = packetResult.nextSequence,
                droppedPacketCount = packetResult.droppedPacketCount,
                packetRecords = std::move(packetRecords)]() mutable
            {
                if (safeThis.isNull())
                {
                    return;
                }
                safeThis->m_r0TrafficRefreshPending.store(false);
                if (safeThis->m_monitorGeneration.load() != generation
                    || safeThis->m_monitorSource == TrafficMonitorSource::Stopped)
                {
                    if (safeThis->m_monitorSource == TrafficMonitorSource::Stopped)
                    {
                        // 纯兜底停用，没有后续步骤依赖它的完成顺序，直接丢后台执行，
                        // 避免在 UI 线程的回投 lambda 里再下发一次同步 IOCTL。
                        disableNetworkTrafficCaptureAsync();
                    }
                    return;
                }

                if (!r0Usable)
                {
                    const ksword::ark::DriverClient driverClient;
                    const auto captureControl =
                        driverClient.controlNetworkTrafficCapture(false);
                    if (!captureControl.io.ok ||
                        captureControl.response.status != KSWORD_ARK_NETWORK_STATUS_DISABLED)
                    {
                        kLogEvent disableEvent;
                        warn << disableEvent
                             << "[NetworkDock] R0 查询失败后的数据面停用失败: "
                             << captureControl.io.message << eol;
                    }
                    safeThis->startR3TrafficMonitor(diagnosticText);
                    return;
                }

                if (initialProbe)
                {
                    safeThis->m_monitorSource = TrafficMonitorSource::R0;
                    safeThis->m_monitorRunning = true;
                    if (!safeThis->m_packetTimelineSessionActive)
                    {
                        safeThis->beginPacketTimelineMonitorSession();
                    }
                    if (safeThis->m_r0TrafficRefreshTimer != nullptr)
                    {
                        safeThis->m_r0TrafficRefreshTimer->start();
                    }
                }

                safeThis->m_r0LastEventSequence = nextSequence;
                safeThis->m_r0LastDroppedEventCount = droppedPacketCount;
                for (ks::network::PacketRecord& packetRecord : packetRecords)
                {
                    packetRecord.sequenceId = safeThis->m_r0SyntheticSequence++;
                    safeThis->onPacketCaptured(packetRecord);
                }

                if (safeThis->m_monitorStatusLabel != nullptr)
                {
                    safeThis->m_monitorStatusLabel->setText(
                        QStringLiteral("状态：运行中；来源：R0 WFP IPv4/IPv6 逐包捕获（报文前缀最长 %1 字节；%2）")
                            .arg(KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES)
                            .arg(diagnosticText));
                }
                safeThis->updateMonitorButtonState();
            },
            Qt::QueuedConnection);
    }).detach();
}

void NetworkDock::startR3TrafficMonitor(const QString& fallbackReason)
{
    if (m_monitorSource == TrafficMonitorSource::Stopped || m_trafficService == nullptr)
    {
        return;
    }
    if (m_r0TrafficRefreshTimer != nullptr)
    {
        m_r0TrafficRefreshTimer->stop();
    }
    m_monitorSource = TrafficMonitorSource::R3;

    const bool startIssued = m_trafficService->StartCapture();
    m_monitorRunning = startIssued && m_trafficService->IsRunning();
    if (!m_monitorRunning)
    {
        m_monitorSource = TrafficMonitorSource::Stopped;
        if (m_packetTimelineSessionActive)
        {
            endPacketTimelineMonitorSession();
        }
        if (m_monitorStatusLabel != nullptr)
        {
            m_monitorStatusLabel->setText(QStringLiteral("状态：R0 不可用，R3 回退启动失败"));
        }
    }
    else
    {
        if (!m_packetTimelineSessionActive)
        {
            beginPacketTimelineMonitorSession();
        }
        if (m_monitorStatusLabel != nullptr)
        {
            m_monitorStatusLabel->setText(
                QStringLiteral("状态：运行中；来源：R3 用户态抓包（R0 不可用：%1）")
                    .arg(fallbackReason));
        }
    }
    updateMonitorButtonState();
}

void NetworkDock::updateMonitorButtonState()
{
    const bool stopping = m_monitorStopInProgress.load();
    if (m_startMonitorButton != nullptr)
    {
        m_startMonitorButton->setEnabled(!m_monitorRunning && !stopping);
    }
    if (m_stopMonitorButton != nullptr)
    {
        m_stopMonitorButton->setEnabled(m_monitorRunning && !stopping);
    }
}



