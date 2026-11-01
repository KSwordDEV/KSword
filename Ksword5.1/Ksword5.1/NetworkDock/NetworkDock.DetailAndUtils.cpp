#include "NetworkDock.InternalCommon.h"

using namespace network_dock_detail;
void NetworkDock::openPacketDetailWindowFromTableRow(QTableWidget* tableWidget, const int row)
{
    if (tableWidget == nullptr || row < 0)
    {
        return;
    }

    QTableWidgetItem* firstItem = tableWidget->item(row, toPacketColumn(PacketTableColumn::Time));
    if (firstItem == nullptr)
    {
        return;
    }

    const QVariant sequenceVariant = firstItem->data(Qt::UserRole);
    if (!sequenceVariant.isValid())
    {
        return;
    }

    const std::uint64_t sequenceId = static_cast<std::uint64_t>(sequenceVariant.toULongLong());
    openPacketDetailWindowBySequenceId(sequenceId);
}

void NetworkDock::openPacketDetailWindowBySequenceId(const std::uint64_t sequenceId)
{
    const auto iterator = m_packetBySequence.find(sequenceId);
    if (iterator == m_packetBySequence.end())
    {
        QMessageBox::information(this, QStringLiteral("报文详情"), QStringLiteral("该报文已被清理，无法查看详情。"));
        return;
    }

    // 详情窗口通过统一辅助函数弹出，保证行为与旧结构一致。
    showPacketDetailWindow(*iterator->second);

    kLogEvent detailWindowEvent;
    info << detailWindowEvent
        << "[NetworkDock] 打开报文详情窗口, sequenceId=" << sequenceId
        << ", pid=" << iterator->second->processId
        << eol;
}

QIcon NetworkDock::resolveProcessIconByPid(const std::uint32_t processId, const std::string& processName)
{
    if (processId == 0)
    {
        return QIcon(":/Icon/process_main.svg");
    }

    const quint32 pidKey = static_cast<quint32>(processId);
    const auto cacheIterator = m_processIconCacheByPid.constFind(pidKey);
    if (cacheIterator != m_processIconCacheByPid.constEnd())
    {
        return cacheIterator.value();
    }

    QIcon processIcon;

    // 先尝试按可执行路径提取系统文件图标。
    const std::string processPath = ks::process::QueryProcessPathByPid(processId);
    if (!processPath.empty())
    {
        static QFileIconProvider fileIconProvider;
        const QString processPathText = QString::fromUtf8(processPath.c_str());
        processIcon = fileIconProvider.icon(QFileInfo(processPathText));
    }

    // 如果路径不可用，则回退到统一图标，保证列内始终有可视图标。
    if (processIcon.isNull())
    {
        processIcon = QIcon(":/Icon/process_main.svg");
    }

    m_processIconCacheByPid.insert(pidKey, processIcon);

    // 对于名称为空的异常条目，也在日志记录一次，方便定位来源。
    if (processName.empty())
    {
        kLogEvent iconEvent;
        warn << iconEvent << "[NetworkDock] 进程名为空，使用默认图标, pid=" << processId << eol;
    }
    return processIcon;
}

bool NetworkDock::packetPassesMonitorFilter(const ks::network::PacketRecord& packetRecord) const
{
    if (!packetPassesTimelineFilter(packetRecord))
    {
        return false;
    }

    if (m_trafficFocusPid) return packetRecord.processId == m_trafficFocusPid;
    if (m_activeMonitorFilterGroupList.empty())
    {
        return true;
    }

    for (const MonitorFilterRuleGroupCompiled& groupFilter : m_activeMonitorFilterGroupList)
    {
        if (!groupFilter.enabled)
        {
            continue;
        }

        if (packetMatchesMonitorFilterGroup(packetRecord, groupFilter))
        {
            return true;
        }
    }

    return false;
}

bool NetworkDock::packetPassesMonitorFilter(
    const std::uint64_t sequenceId,
    const ks::network::PacketRecord& packetRecord) const
{
    // 序号版本用于历史缓存重建：
    // - 时间轴过滤需要使用报文首次入库时缓存的压缩时间；
    // - 其余规则仍复用原来的进程/IP/端口/包长匹配逻辑。
    if (!packetPassesTimelineFilter(sequenceId, packetRecord))
    {
        return false;
    }

    if (m_trafficFocusPid) return packetRecord.processId == m_trafficFocusPid;
    if (m_activeMonitorFilterGroupList.empty())
    {
        return true;
    }

    for (const MonitorFilterRuleGroupCompiled& groupFilter : m_activeMonitorFilterGroupList)
    {
        if (!groupFilter.enabled)
        {
            continue;
        }

        if (packetMatchesMonitorFilterGroup(packetRecord, groupFilter))
        {
            return true;
        }
    }

    return false;
}

int NetworkDock::toPacketColumn(const PacketTableColumn column)
{
    return static_cast<int>(column);
}

int NetworkDock::toRateLimitColumn(const RateLimitTableColumn column)
{
    return static_cast<int>(column);
}

int NetworkDock::toTcpConnectionColumn(const TcpConnectionTableColumn column)
{
    return static_cast<int>(column);
}

int NetworkDock::toUdpEndpointColumn(const UdpEndpointTableColumn column)
{
    return static_cast<int>(column);
}

int NetworkDock::toNidsAlertColumn(const NidsAlertTableColumn column)
{
    return static_cast<int>(column);
}

bool NetworkDock::tryParsePidText(const QString& pidText, std::uint32_t& pidOut)
{
    bool parseOk = false;
    const unsigned long pidValue = pidText.trimmed().toULong(&parseOk, 10);
    if (!parseOk || pidValue == 0 || pidValue > 0xFFFFFFFFUL)
    {
        return false;
    }

    pidOut = static_cast<std::uint32_t>(pidValue);
    return true;
}

bool NetworkDock::tryParseUnsignedIntegerText(const QString& integerText, std::uint32_t& valueOut)
{
    const QString trimmedText = integerText.trimmed();
    if (trimmedText.isEmpty())
    {
        return false;
    }

    bool parseOk = false;
    qulonglong parsedValue = 0;

    // 优先识别 0x 前缀十六进制输入。
    if (trimmedText.startsWith("0x", Qt::CaseInsensitive))
    {
        parsedValue = trimmedText.mid(2).toULongLong(&parseOk, 16);
    }
    else
    {
        // 无前缀时先尝试十进制，失败再尝试十六进制。
        parsedValue = trimmedText.toULongLong(&parseOk, 10);
        if (!parseOk)
        {
            parsedValue = trimmedText.toULongLong(&parseOk, 16);
        }
    }

    if (!parseOk || parsedValue > static_cast<qulonglong>(0xFFFFFFFFULL))
    {
        return false;
    }

    valueOut = static_cast<std::uint32_t>(parsedValue);
    return true;
}


