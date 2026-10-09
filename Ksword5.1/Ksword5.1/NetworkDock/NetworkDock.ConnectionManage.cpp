#include "NetworkDock.InternalCommon.h"
#include "NetworkAuditPage.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../UI/ResultTableHost.h"

using namespace network_dock_detail;

void NetworkDock::focusConnectionsByPids(const QVector<quint32>& processIds)
{
    QSet<quint32> processFilterSet;
    for (const quint32 processId : processIds)
    {
        if (processId != 0U)
        {
            processFilterSet.insert(processId);
        }
    }

    if (m_sideTabWidget != nullptr && m_networkAuditPage != nullptr)
    {
        m_sideTabWidget->setCurrentWidget(m_networkAuditPage);
    }
    if (m_networkAuditPage != nullptr)
    {
        m_networkAuditPage->focusProcessIds(processFilterSet);
    }
}

void NetworkDock::setProcessDetailConnectionScope()
{
    // 进程详情只提供网络审计中的 TCP/UDP Cross-View。
    // 抓包、防火墙、诊断等全局网络功能继续保留在独立网络 Dock。
    if (m_sideTabWidget == nullptr)
    {
        return;
    }

    for (int tabIndex = 0; tabIndex < m_sideTabWidget->count(); ++tabIndex)
    {
        m_sideTabWidget->setTabVisible(
            tabIndex,
            m_sideTabWidget->widget(tabIndex) == m_networkAuditPage);
    }

    if (m_networkAuditPage != nullptr)
    {
        m_sideTabWidget->setCurrentWidget(m_networkAuditPage);
        m_networkAuditPage->activateCrossView();
    }
}

void NetworkDock::refreshConnectionTables()
{
    // 连接快照枚举是相对昂贵操作：
    // - 当连接管理页不可见时，直接跳过；
    // - 避免后台定时器在隐藏页持续抢占 UI 线程。
    if (m_sideTabWidget != nullptr &&
        m_connectionManagePage != nullptr &&
        m_sideTabWidget->currentWidget() != m_connectionManagePage)
    {
        return;
    }

    if (m_connectionRefreshPending.exchange(true))
    {
        return;
    }

    // IP Helper 枚举和进程路径解析都可能阻塞。后台生成完整快照，
    // GUI 线程只负责应用已完成的数据，避免页面切换和滚动卡顿。
    QPointer<NetworkDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<ks::network::TcpConnectionRecord> tcpSnapshot;
        std::vector<ks::network::UdpEndpointRecord> udpSnapshot;
        std::string tcpErrorText;
        std::string udpErrorText;
        const bool tcpOk = ks::network::EnumerateTcpConnectionRecords(tcpSnapshot, &tcpErrorText);
        const bool udpOk = ks::network::EnumerateUdpEndpointRecords(udpSnapshot, &udpErrorText);
        QMetaObject::invokeMethod(qApp, [guardThis,
            tcpSnapshot = std::move(tcpSnapshot),
            udpSnapshot = std::move(udpSnapshot),
            tcpOk,
            udpOk,
            tcpErrorText = std::move(tcpErrorText),
            udpErrorText = std::move(udpErrorText)]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->m_connectionRefreshPending.store(false);
            guardThis->applyConnectionSnapshot(
                std::move(tcpSnapshot),
                std::move(udpSnapshot),
                tcpOk,
                udpOk,
                std::move(tcpErrorText),
                std::move(udpErrorText));
        }, Qt::QueuedConnection);
    }).detach();
}

void NetworkDock::applyConnectionSnapshot(
    std::vector<ks::network::TcpConnectionRecord> tcpSnapshot,
    std::vector<ks::network::UdpEndpointRecord> udpSnapshot,
    const bool tcpOk,
    const bool udpOk,
    std::string tcpErrorText,
    std::string udpErrorText)
{
    if (m_sideTabWidget != nullptr
        && m_connectionManagePage != nullptr
        && m_sideTabWidget->currentWidget() != m_connectionManagePage)
    {
        return;
    }

    // TCP/UDP 共享一份后台快照；稳定列身份与整组提交由结果表宿主管理。
    ks::ui::ResultTableHost* const tcpHost = ks::ui::ResultTableHost::ensure(m_tcpConnectionTable);
    ks::ui::ResultTableHost* const udpHost = ks::ui::ResultTableHost::ensure(m_udpEndpointTable);
    if (tcpHost != nullptr && !tcpHost->hasExplicitColumns())
    {
        tcpHost->bindModel(m_tcpConnectionTable->model(), {
            {toTcpConnectionColumn(TcpConnectionTableColumn::State), QStringLiteral("tcp_state")},
            {toTcpConnectionColumn(TcpConnectionTableColumn::Pid), QStringLiteral("process_id")},
            {toTcpConnectionColumn(TcpConnectionTableColumn::ProcessName), QStringLiteral("process_name")},
            {toTcpConnectionColumn(TcpConnectionTableColumn::LocalEndpoint), QStringLiteral("local_endpoint")},
            {toTcpConnectionColumn(TcpConnectionTableColumn::RemoteEndpoint), QStringLiteral("remote_endpoint")}
        });
    }
    if (udpHost != nullptr && !udpHost->hasExplicitColumns())
    {
        udpHost->bindModel(m_udpEndpointTable->model(), {
            {toUdpEndpointColumn(UdpEndpointTableColumn::Pid), QStringLiteral("process_id")},
            {toUdpEndpointColumn(UdpEndpointTableColumn::ProcessName), QStringLiteral("process_name")},
            {toUdpEndpointColumn(UdpEndpointTableColumn::LocalEndpoint), QStringLiteral("local_endpoint")}
        });
    }
    const QPointer<NetworkDock> safeThis(this); // 页面关闭后自动丢弃整份快照。
    ks::ui::ResultTableHost::submitGroup(
        this,
        QStringLiteral("network-connection-snapshot"),
        {tcpHost, udpHost},
        [this, safeThis,
            tcpSnapshot = std::move(tcpSnapshot),
            udpSnapshot = std::move(udpSnapshot),
            tcpOk,
            udpOk,
            tcpErrorText = std::move(tcpErrorText),
            udpErrorText = std::move(udpErrorText)]() mutable
        {
            // 延迟回投时重新确认页面仍存在且仍显示连接页，保持原有隐藏页边界。
            if (safeThis.isNull() || (m_sideTabWidget != nullptr
                && m_connectionManagePage != nullptr
                && m_sideTabWidget->currentWidget() != m_connectionManagePage))
            {
                return;
            }
            if (!tcpOk || !udpOk)
            {
                if (m_connectionStatusLabel != nullptr)
                {
                    m_connectionStatusLabel->setText(
                        tcpOk ? QStringLiteral("状态：UDP 刷新失败") : QStringLiteral("状态：TCP 刷新失败"));
                }

                kLogEvent refreshFailEvent;
                if (!tcpOk)
                {
                    warn << refreshFailEvent
                        << "[NetworkDock] 枚举 TCP 连接失败, detail=" << tcpErrorText
                        << eol;
                }
                if (!udpOk)
                {
                    warn << refreshFailEvent
                        << "[NetworkDock] 枚举 UDP 端点失败, detail=" << udpErrorText
                        << eol;
                }
                return;
            }

            if (!m_connectionPidFilterSet.isEmpty())
            {
                const auto pidMatches = [this](const std::uint32_t processId)
                    {
                        return m_connectionPidFilterSet.contains(static_cast<quint32>(processId));
                    };
                tcpSnapshot.erase(
                    std::remove_if(tcpSnapshot.begin(), tcpSnapshot.end(),
                        [&pidMatches](const ks::network::TcpConnectionRecord& record)
                        {
                            return !pidMatches(record.processId);
                        }),
                    tcpSnapshot.end());
                udpSnapshot.erase(
                    std::remove_if(udpSnapshot.begin(), udpSnapshot.end(),
                        [&pidMatches](const ks::network::UdpEndpointRecord& record)
                        {
                            return !pidMatches(record.processId);
                        }),
                    udpSnapshot.end());
            }

            m_tcpConnectionCache = std::move(tcpSnapshot);
            m_udpEndpointCache = std::move(udpSnapshot);

            if (m_tcpConnectionTable != nullptr)
            {
                const bool updatesEnabled = m_tcpConnectionTable->updatesEnabled();
                m_tcpConnectionTable->setUpdatesEnabled(false);
                m_tcpConnectionTable->setRowCount(static_cast<int>(m_tcpConnectionCache.size()));
                for (int rowIndex = 0; rowIndex < static_cast<int>(m_tcpConnectionCache.size()); ++rowIndex)
                {
                    const ks::network::TcpConnectionRecord& connectionRecord = m_tcpConnectionCache[static_cast<std::size_t>(rowIndex)];
                    QTableWidgetItem* stateItem = createPacketCell(toQString(connectionRecord.tcpStateText));
                    stateItem->setData(Qt::UserRole, rowIndex);
                    m_tcpConnectionTable->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::State), stateItem);
                    m_tcpConnectionTable->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::Pid), createPacketCell(QString::number(connectionRecord.processId)));
                    QTableWidgetItem* processItem = createPacketCell(toQString(connectionRecord.processName));
                    processItem->setIcon(resolveProcessIconByPid(connectionRecord.processId, connectionRecord.processName));
                    m_tcpConnectionTable->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::ProcessName), processItem);
                    m_tcpConnectionTable->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::LocalEndpoint), createPacketCell(formatEndpointText(connectionRecord.localAddressText, connectionRecord.localPort)));
                    m_tcpConnectionTable->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::RemoteEndpoint), createPacketCell(formatEndpointText(connectionRecord.remoteAddressText, connectionRecord.remotePort)));
                }
                m_tcpConnectionTable->setUpdatesEnabled(updatesEnabled);
                if (updatesEnabled && m_tcpConnectionTable->viewport() != nullptr)
                {
                    m_tcpConnectionTable->viewport()->update();
                }
            }

            if (m_udpEndpointTable != nullptr)
            {
                const bool updatesEnabled = m_udpEndpointTable->updatesEnabled();
                m_udpEndpointTable->setUpdatesEnabled(false);
                m_udpEndpointTable->setRowCount(static_cast<int>(m_udpEndpointCache.size()));
                for (int rowIndex = 0; rowIndex < static_cast<int>(m_udpEndpointCache.size()); ++rowIndex)
                {
                    const ks::network::UdpEndpointRecord& endpointRecord = m_udpEndpointCache[static_cast<std::size_t>(rowIndex)];
                    m_udpEndpointTable->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::Pid), createPacketCell(QString::number(endpointRecord.processId)));
                    QTableWidgetItem* processItem = createPacketCell(toQString(endpointRecord.processName));
                    processItem->setIcon(resolveProcessIconByPid(endpointRecord.processId, endpointRecord.processName));
                    m_udpEndpointTable->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::ProcessName), processItem);
                    m_udpEndpointTable->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::LocalEndpoint), createPacketCell(formatEndpointText(endpointRecord.localAddressText, endpointRecord.localPort)));
                }
                m_udpEndpointTable->setUpdatesEnabled(updatesEnabled);
                if (updatesEnabled && m_udpEndpointTable->viewport() != nullptr)
                {
                    m_udpEndpointTable->viewport()->update();
                }
            }

            if (m_connectionStatusLabel != nullptr)
            {
                const QString nowText = QDateTime::currentDateTime().toString("HH:mm:ss");
                QString filterText;
                if (!m_connectionPidFilterSet.isEmpty())
                {
                    QStringList pidTextList;
                    for (const quint32 processId : std::as_const(m_connectionPidFilterSet))
                    {
                        pidTextList.push_back(QString::number(processId));
                    }
                    std::sort(pidTextList.begin(), pidTextList.end(), [](const QString& left, const QString& right) {
                        return left.toULongLong() < right.toULongLong();
                    });
                    filterText = QStringLiteral("，PID筛选=%1 个进程")
                        .arg(m_connectionPidFilterSet.size());
                    m_connectionStatusLabel->setToolTip(
                        QStringLiteral("PID：%1").arg(pidTextList.join(',')));
                }
                else
                {
                    m_connectionStatusLabel->setToolTip(QString());
                }
                m_connectionStatusLabel->setText(
                    QStringLiteral("状态：TCP=%1 条, UDP=%2 条%3, 刷新于 %4")
                    .arg(static_cast<int>(m_tcpConnectionCache.size()))
                    .arg(static_cast<int>(m_udpEndpointCache.size()))
                    .arg(filterText)
                    .arg(nowText));
            }

            // 刷新频率较高，这里使用 dbg 级别避免 info 日志过于密集。
            kLogEvent refreshEvent;
            dbg << refreshEvent
                << "[NetworkDock] 刷新连接快照完成, tcpCount=" << m_tcpConnectionCache.size()
                << ", udpCount=" << m_udpEndpointCache.size()
                << eol;
        });
}

void NetworkDock::refreshTcpConnectionTable()
{
    if (m_tcpConnectionTable == nullptr)
    {
        return;
    }

    const QPointer<NetworkDock> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-tcp-connection-refresh"),
        {m_tcpConnectionTable},
        [safeThis]()
        {
            if (!safeThis.isNull())
            {
                safeThis->refreshTcpConnectionTable();
            }
        }))
    {
        return;
    }

    std::vector<ks::network::TcpConnectionRecord> tcpSnapshot;
    std::string errorText;
    if (!ks::network::EnumerateTcpConnectionRecords(tcpSnapshot, &errorText))
    {
        if (m_connectionStatusLabel != nullptr)
        {
            m_connectionStatusLabel->setText(QStringLiteral("状态：TCP 刷新失败"));
        }

        kLogEvent refreshFailEvent;
        warn << refreshFailEvent
            << "[NetworkDock] 枚举 TCP 连接失败, detail=" << errorText
            << eol;
        return;
    }

    // 刷新缓存：终止连接时会通过行索引回查该缓存。
    m_tcpConnectionCache = std::move(tcpSnapshot);

    m_tcpConnectionTable->setUpdatesEnabled(false);
    m_tcpConnectionTable->setRowCount(static_cast<int>(m_tcpConnectionCache.size()));

    int rowIndex = 0;
    for (const ks::network::TcpConnectionRecord& connectionRecord : m_tcpConnectionCache)
    {
        const int cacheIndex = rowIndex;
        const QString stateText = toQString(connectionRecord.tcpStateText);
        const QString pidText = QString::number(connectionRecord.processId);
        const QString processNameText = toQString(connectionRecord.processName);
        const QString localEndpointText = formatEndpointText(connectionRecord.localAddressText, connectionRecord.localPort);
        const QString remoteEndpointText = formatEndpointText(connectionRecord.remoteAddressText, connectionRecord.remotePort);

        QTableWidgetItem* stateItem = createPacketCell(stateText);
        stateItem->setData(Qt::UserRole, cacheIndex);
        m_tcpConnectionTable->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::State), stateItem);
        m_tcpConnectionTable->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::Pid), createPacketCell(pidText));
        QTableWidgetItem* processItem = createPacketCell(processNameText);
        processItem->setIcon(resolveProcessIconByPid(connectionRecord.processId, connectionRecord.processName));
        m_tcpConnectionTable->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::ProcessName), processItem);
        m_tcpConnectionTable->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::LocalEndpoint), createPacketCell(localEndpointText));
        m_tcpConnectionTable->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::RemoteEndpoint), createPacketCell(remoteEndpointText));
        ++rowIndex;
    }

    m_tcpConnectionTable->setUpdatesEnabled(true);
    m_tcpConnectionTable->viewport()->update();
}

void NetworkDock::refreshUdpEndpointTable()
{
    if (m_udpEndpointTable == nullptr)
    {
        return;
    }

    const QPointer<NetworkDock> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-udp-endpoint-refresh"),
        {m_udpEndpointTable},
        [safeThis]()
        {
            if (!safeThis.isNull())
            {
                safeThis->refreshUdpEndpointTable();
            }
        }))
    {
        return;
    }

    std::vector<ks::network::UdpEndpointRecord> udpSnapshot;
    std::string errorText;
    if (!ks::network::EnumerateUdpEndpointRecords(udpSnapshot, &errorText))
    {
        if (m_connectionStatusLabel != nullptr)
        {
            m_connectionStatusLabel->setText(QStringLiteral("状态：UDP 刷新失败"));
        }

        kLogEvent refreshFailEvent;
        warn << refreshFailEvent
            << "[NetworkDock] 枚举 UDP 端点失败, detail=" << errorText
            << eol;
        return;
    }

    m_udpEndpointCache = std::move(udpSnapshot);

    m_udpEndpointTable->setUpdatesEnabled(false);
    m_udpEndpointTable->setRowCount(static_cast<int>(m_udpEndpointCache.size()));

    int rowIndex = 0;
    for (const ks::network::UdpEndpointRecord& endpointRecord : m_udpEndpointCache)
    {
        const QString pidText = QString::number(endpointRecord.processId);
        const QString processNameText = toQString(endpointRecord.processName);
        const QString localEndpointText = formatEndpointText(endpointRecord.localAddressText, endpointRecord.localPort);

        m_udpEndpointTable->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::Pid), createPacketCell(pidText));
        QTableWidgetItem* processItem = createPacketCell(processNameText);
        processItem->setIcon(resolveProcessIconByPid(endpointRecord.processId, endpointRecord.processName));
        m_udpEndpointTable->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::ProcessName), processItem);
        m_udpEndpointTable->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::LocalEndpoint), createPacketCell(localEndpointText));
        ++rowIndex;
    }

    m_udpEndpointTable->setUpdatesEnabled(true);
    m_udpEndpointTable->viewport()->update();
}

void NetworkDock::terminateSelectedTcpConnection()
{
    if (m_tcpConnectionTable == nullptr)
    {
        return;
    }

    // 表格行与缓存索引显式绑定：
    // - 当前未启用排序时 row == cacheIndex；
    // - 后续若增加表头排序，也不会因为显示行变化而关闭错误连接。
    const int selectedRow = m_tcpConnectionTable->currentRow();
    int cacheIndex = selectedRow;
    if (selectedRow >= 0)
    {
        QTableWidgetItem* stateItem = m_tcpConnectionTable->item(
            selectedRow,
            toTcpConnectionColumn(TcpConnectionTableColumn::State));
        if (stateItem != nullptr)
        {
            const QVariant cacheIndexVariant = stateItem->data(Qt::UserRole);
            bool parseOk = false;
            const int parsedCacheIndex = cacheIndexVariant.toInt(&parseOk);
            if (parseOk)
            {
                cacheIndex = parsedCacheIndex;
            }
        }
    }

    if (cacheIndex < 0 || cacheIndex >= static_cast<int>(m_tcpConnectionCache.size()))
    {
        QMessageBox::information(this, QStringLiteral("连接管理"), QStringLiteral("请先选中一条 TCP 连接。"));
        return;
    }

    // 复制目标记录而不是持有缓存引用：
    // - QMessageBox::question 会进入嵌套事件循环；
    // - 自动刷新定时器可能在确认框打开期间重建 m_tcpConnectionCache；
    // - 若继续使用引用，用户点击确认后可能访问悬空对象并导致关闭请求参数错误。
    const ks::network::TcpConnectionRecord targetConnection = m_tcpConnectionCache[static_cast<std::size_t>(cacheIndex)];
    // DELETE_TCB 只适用于 IPv4 活动连接：
    // - LISTEN 行是监听 socket，不是已建立连接；
    // - IPv6 行不能传给 IPv4-only 的 SetTcpEntry；
    // - 在弹确认框前拦截这些场景，避免把系统返回的 317 误提示成权限不足。
    const std::string unsupportedReason = ks::network::GetTcpTerminationUnsupportedReason(targetConnection);
    if (!unsupportedReason.empty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("连接管理"),
            QStringLiteral("当前 TCP 行不能通过 DELETE_TCB 终止：%1").arg(toQString(unsupportedReason)));

        kLogEvent unsupportedTerminateEvent;
        info << unsupportedTerminateEvent
            << "[NetworkDock] 跳过不支持的 TCP 终止请求, pid=" << targetConnection.processId
            << ", state=" << targetConnection.tcpStateText
            << ", local=" << targetConnection.localAddressText << ":" << targetConnection.localPort
            << ", remote=" << targetConnection.remoteAddressText << ":" << targetConnection.remotePort
            << ", reason=" << unsupportedReason
            << eol;
        return;
    }

    const int userChoice = QMessageBox::question(
        this,
        QStringLiteral("终止 TCP 连接"),
        QStringLiteral("确认终止连接？\nPID=%1\n本地=%2:%3\n远端=%4:%5")
        .arg(targetConnection.processId)
        .arg(toQString(targetConnection.localAddressText))
        .arg(targetConnection.localPort)
        .arg(toQString(targetConnection.remoteAddressText))
        .arg(targetConnection.remotePort),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (userChoice != QMessageBox::Yes)
    {
        return;
    }

    std::string detailText;
    const bool terminateOk = ks::network::TerminateTcpConnectionByRecord(targetConnection, &detailText);
    if (terminateOk)
    {
        QMessageBox::information(this, QStringLiteral("连接管理"), QStringLiteral("连接终止请求已提交。"));

        kLogEvent terminateEvent;
        info << terminateEvent
            << "[NetworkDock] 终止 TCP 连接成功, pid=" << targetConnection.processId
            << ", local=" << targetConnection.localAddressText << ":" << targetConnection.localPort
            << ", remote=" << targetConnection.remoteAddressText << ":" << targetConnection.remotePort
            << ", detail=" << detailText
            << eol;
    }
    else
    {
        // privilegePromptHandled：提权恢复提示已解释失败时不再显示通用连接错误。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("终止 TCP 连接"),
            QString::fromStdString(detailText));
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("连接管理"),
                QStringLiteral("终止连接失败：%1").arg(toQString(detailText)));
        }

        kLogEvent terminateFailEvent;
        warn << terminateFailEvent
            << "[NetworkDock] 终止 TCP 连接失败, pid=" << targetConnection.processId
            << ", detail=" << detailText
            << eol;
    }

    refreshConnectionTables();
}

void NetworkDock::copySelectedConnectionRowToClipboard(QTableWidget* tableWidget)
{
    if (tableWidget == nullptr)
    {
        return;
    }

    const int selectedRow = tableWidget->currentRow();
    if (selectedRow < 0)
    {
        return;
    }

    QStringList rowTextList;
    rowTextList.reserve(tableWidget->columnCount());
    for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
    {
        QTableWidgetItem* item = tableWidget->item(selectedRow, columnIndex);
        rowTextList.push_back(item == nullptr ? QString() : item->text());
    }

    if (QGuiApplication::clipboard() != nullptr)
    {
        QGuiApplication::clipboard()->setText(rowTextList.join('\t'));
    }

    kLogEvent copyRowEvent;
    dbg << copyRowEvent
        << "[NetworkDock] 已复制连接表行到剪贴板, tableColumns=" << tableWidget->columnCount()
        << ", row=" << selectedRow
        << eol;
}
