#include "NetworkDock.InternalHelpers.h"

#include "../UI/MemoryWorkbench/HexView.h"
#include "../UI/TableInteractionSupport.h"
#include "../ksword/network/network_format_tools.h"
#include "../theme.h"
#include "../../../shared/driver/KswordArkNetworkIoctl.h"

#include <QAction>
#include <QClipboard>
#include <QGuiApplication>
#include <QMenu>
#include <QModelIndex>
#include <QLabel>
#include <QPainter>
#include <QPlainTextEdit>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QWidget>

namespace network_dock_detail
{
    // packetSourceDisplayText 作用：
    // - 把内部数据源和 WFP event flags 转成可本地化的明确来源文本；
    // - R0 事件始终声明无 packet payload，避免被误认成逐包抓包。
    static QString packetSourceDisplayText(const ks::network::PacketRecord& packetRecord)
    {
        if (!packetRecord.wfpAleEventNoPayload)
        {
            return packetRecord.sourceText.empty()
                ? QStringLiteral("R3")
                : toQString(packetRecord.sourceText);
        }
        if ((packetRecord.sourceFlags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_BLOCKED) != 0UL)
        {
            return QStringLiteral("R0 WFP ALE 流事件（已阻断；无 packet payload）");
        }
        if ((packetRecord.sourceFlags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ACTION_WRITE_UNAVAILABLE) != 0UL)
        {
            return QStringLiteral("R0 WFP ALE 流事件（仅观察；无 packet payload）");
        }
        return QStringLiteral("R0 WFP ALE 流事件（已放行；无 packet payload）");
    }

    void installCopyCurrentRowMenu(
        QTableWidget* tableWidget,
        const QString& actionText,
        const int processIdColumn)
    {
        // installCopyCurrentRowMenu 作用：
        // - 输入：任意 NetworkDock 表格和菜单项文本；
        // - 处理：选中右键点击行，并复制所有可见列为 TSV；
        // - 返回：无。失败时静默返回，保持监控页稳定。
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            tableWidget,
            &QTableWidget::customContextMenuRequested,
            tableWidget,
            [tableWidget, actionText, processIdColumn](const QPoint& localPosition)
            {
                const QModelIndex clickedIndex = tableWidget->indexAt(localPosition);
                if (clickedIndex.isValid())
                {
                    tableWidget->setCurrentCell(clickedIndex.row(), clickedIndex.column());
                }

                QMenu contextMenu(tableWidget);
                contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
                QAction* copyRowAction = contextMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                    actionText);
                copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
                quint32 processId = 0;
                if (processIdColumn >= 0 && processIdColumn < tableWidget->columnCount() &&
                    tableWidget->currentRow() >= 0 && tableWidget->currentRow() < tableWidget->rowCount())
                {
                    const QTableWidgetItem* processIdItem = tableWidget->item(
                        tableWidget->currentRow(),
                        processIdColumn);
                    bool parseOk = false;
                    const uint parsedProcessId = processIdItem != nullptr
                        ? processIdItem->text().toUInt(&parseOk, 10)
                        : 0U;
                    if (parseOk && parsedProcessId != 0U)
                    {
                        processId = static_cast<quint32>(parsedProcessId);
                    }
                }
                QAction* openProcessDetailAction = nullptr;
                if (processIdColumn >= 0)
                {
                    openProcessDetailAction = contextMenu.addAction(
                        QIcon(QStringLiteral(":/Icon/process_details.svg")),
                        QStringLiteral("转到进程详细信息"));
                    openProcessDetailAction->setEnabled(processId != 0U);
                }

                const QAction* selectedAction = contextMenu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
                if (selectedAction == openProcessDetailAction)
                {
                    ks::ui::OpenProcessDetailByPid(processId);
                    return;
                }
                if (selectedAction != copyRowAction)
                {
                    return;
                }

                QClipboard* clipboardObject = QGuiApplication::clipboard();
                const int rowIndex = tableWidget->currentRow();
                if (clipboardObject == nullptr || rowIndex < 0 || rowIndex >= tableWidget->rowCount())
                {
                    return;
                }

                QStringList rowFields;
                rowFields.reserve(tableWidget->columnCount());
                for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* item = tableWidget->item(rowIndex, columnIndex);
                    rowFields.push_back(item != nullptr ? item->text() : QString());
                }
                clipboardObject->setText(rowFields.join(QLatin1Char('\t')));
            });
    }

    namespace
    {
        // buildPacketDetailWindowStyle 作用：
        // - 为“流量监控 -> 报文详情”窗口生成独立主题样式；
        // - 重点覆盖 QPlainTextEdit/QTabWidget/Page，修复深色模式下白底残留。
        QString buildPacketDetailWindowStyle()
        {
            const QString windowBackground = KswordTheme::SurfaceHex();
            const QString panelBackground = KswordTheme::SurfaceAltHex();
            const QString inputBackground = KswordTheme::SurfaceMutedColorHex();
            const QString borderColor = KswordTheme::BorderHex();
            const QString textColor = KswordTheme::TextPrimaryHex();
            const QString secondaryTextColor = KswordTheme::TextSecondaryHex();
            const QString accentColor = KswordTheme::AccentHex(KswordTheme::AccentRole::Blue);

            return QStringLiteral(
                "QWidget{"
                "  background:%1;"
                "  color:%2;"
                "}"
                "QLabel{"
                "  background:transparent;"
                "  color:%2;"
                "}"
                "QTabWidget::pane{"
                "  background:%3;"
                "  border:1px solid %4;"
                "  border-radius:4px;"
                "}"
                "QTabBar::tab{"
                "  background:%1;"
                "  color:%5;"
                "  border:1px solid %4;"
                "  padding:6px 12px;"
                "  margin-right:2px;"
                "  border-top-left-radius:4px;"
                "  border-top-right-radius:4px;"
                "}"
                "QTabBar::tab:selected{"
                "  background:%3;"
                "  color:%2;"
                "  border-bottom-color:%3;"
                "}"
                "QPlainTextEdit{"
                "  background:%6;"
                "  color:%2;"
                "  border:1px solid %4;"
                "  selection-background-color:%7;"
                "  selection-color:%8;"
                "}"
                "QMenu{"
                "  background:%6;"
                "  color:%2;"
                "  border:1px solid %4;"
                "}"
                "QMenu::item:selected{"
                "  background:%7;"
                "  color:%8;"
                "}"
                "QMenu::separator{"
                "  height:1px;"
                "  background:%4;"
                "  margin:2px 6px;"
                "}"
                "QScrollBar:vertical,QScrollBar:horizontal{"
                "  background:%3;"
                "}"
                "QScrollBar::handle:vertical,QScrollBar::handle:horizontal{"
                "  background:%7;"
                "}")
                .arg(windowBackground)
                .arg(textColor)
                .arg(panelBackground)
                .arg(borderColor)
                .arg(secondaryTextColor)
                .arg(inputBackground)
                .arg(accentColor)
                .arg(KswordTheme::OnAccentDynamicHex());
        }

        // PacketDetailWindow：
        // - 报文详情独立窗口（show 非阻塞，不阻塞主 UI）；
        // - 十六进制区使用纯文本编辑器，支持像文本一样跨行连续选择复制。
        class PacketDetailWindow final : public QWidget
        {
        public:
            explicit PacketDetailWindow(const ks::network::PacketRecord& packetRecord, QWidget* parent = nullptr)
                : QWidget(parent)
            {
                setAttribute(Qt::WA_DeleteOnClose, true);
                setWindowFlag(Qt::Window, true);
                setAttribute(Qt::WA_StyledBackground, true);
                setAutoFillBackground(true);
                setWindowTitle(
                    packetRecord.wfpAleEventNoPayload
                        ? QStringLiteral("R0 WFP ALE 流事件详情 - #%1").arg(packetRecord.sequenceId)
                        : QStringLiteral("报文详情 - #%1").arg(packetRecord.sequenceId));
                resize(1120, 760);
                setStyleSheet(buildPacketDetailWindowStyle());

                QVBoxLayout* rootLayout = new QVBoxLayout(this);
                rootLayout->setContentsMargins(8, 8, 8, 8);
                rootLayout->setSpacing(6);

                // 元信息区域：时间、协议、方向、PID、端点、长度。
                QLabel* metaLabel = new QLabel(this);
                const QString timeText = toQString(
                    ks::network::FormatUnixTimestampMs(packetRecord.captureTimestampMs, true));
                if (packetRecord.wfpAleEventNoPayload)
                {
                    metaLabel->setText(QStringLiteral(
                        "来源: %1\n驱动事件序号: %2  标志: 0x%3\n时间: %4\n协议: %5  方向: %6\nPID: %7  进程: %8\n本地: %9\n远端: %10\n总长度: -（ALE 元数据）, 负载: -（ALE 无 payload）")
                        .arg(packetSourceDisplayText(packetRecord))
                        .arg(packetRecord.sourceSequenceId)
                        .arg(packetRecord.sourceFlags, 8, 16, QChar('0'))
                        .arg(timeText)
                        .arg(toQString(ks::network::PacketProtocolToString(packetRecord.protocol)))
                        .arg(toQString(ks::network::PacketDirectionToString(packetRecord.direction)))
                        .arg(packetRecord.processId)
                        .arg(toQString(packetRecord.processName))
                        .arg(formatEndpointText(packetRecord.localAddress, packetRecord.localPort))
                        .arg(formatEndpointText(packetRecord.remoteAddress, packetRecord.remotePort)));
                }
                else
                {
                    metaLabel->setText(QStringLiteral(
                        "时间: %1\n协议: %2  方向: %3\nPID: %4  进程: %5\n本地: %6\n远端: %7\n总长度: %8 bytes, 负载: %9 bytes")
                        .arg(timeText)
                        .arg(toQString(ks::network::PacketProtocolToString(packetRecord.protocol)))
                        .arg(toQString(ks::network::PacketDirectionToString(packetRecord.direction)))
                        .arg(packetRecord.processId)
                        .arg(toQString(packetRecord.processName))
                        .arg(formatEndpointText(packetRecord.localAddress, packetRecord.localPort))
                        .arg(formatEndpointText(packetRecord.remoteAddress, packetRecord.remotePort))
                        .arg(packetRecord.totalPacketSize)
                        .arg(packetRecord.payloadSize));
                }
                metaLabel->setWordWrap(true);
                metaLabel->setStyleSheet(QStringLiteral("padding:6px 8px;border:1px solid %1;border-radius:4px;")
                    .arg(KswordTheme::BorderHex()));
                rootLayout->addWidget(metaLabel);

                // 可读摘要：先展示“内容预览列同款”的语义化 ASCII 摘要，便于快速判断协议文本。
                QLabel* readablePreviewLabel = new QLabel(this);
                const QString readablePreviewText =
                    packetRecord.wfpAleEventNoPayload
                        ? QStringLiteral("R0 WFP ALE 流事件不包含 packet payload")
                        : buildPayloadAsciiPreviewText(packetRecord);
                readablePreviewLabel->setText(
                    QStringLiteral("可读ASCII摘要: %1").arg(readablePreviewText));
                readablePreviewLabel->setWordWrap(true);
                readablePreviewLabel->setToolTip(
                    packetRecord.wfpAleEventNoPayload
                        ? QStringLiteral("该记录来自内核 WFP ALE 流授权层，不包含逐包长度、报文字节或 payload。")
                        : QStringLiteral("该摘要优先提取 payload 中可读 ASCII 片段。"));
                readablePreviewLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
                rootLayout->addWidget(readablePreviewLabel);

                // 详情页签：当前仅保留十六进制视图页。
                QTabWidget* detailTabWidget = new QTabWidget(this);
                rootLayout->addWidget(detailTabWidget, 1);

                // 十六进制页：统一复用 ks::ui::HexView，功能与内存/文件模块保持一致。
                QWidget* hexPage = new QWidget(detailTabWidget);
                QVBoxLayout* hexPageLayout = new QVBoxLayout(hexPage);
                hexPageLayout->setContentsMargins(0, 0, 0, 0);
                hexPageLayout->setSpacing(4);

                QLabel* hexHintLabel = new QLabel(
                    packetRecord.wfpAleEventNoPayload
                        ? QStringLiteral("R0 WFP ALE 流事件没有报文字节；十六进制区域保持为空。")
                        : QStringLiteral("十六进制区域支持 Ctrl+F 异步查找、Ctrl+G 跳转、批量复制与导出。"),
                    hexPage);
                hexHintLabel->setWordWrap(true);
                hexHintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
                hexPageLayout->addWidget(hexHintLabel);

                ks::ui::HexView* hexEditorWidget = new ks::ui::HexView(hexPage);
                hexEditorWidget->setEditable(false);
                hexEditorWidget->setBytesPerRow(16);
                if (!packetRecord.packetBytes.empty())
                {
                    const QByteArray packetBytes(
                        reinterpret_cast<const char*>(packetRecord.packetBytes.data()),
                        static_cast<int>(packetRecord.packetBytes.size()));
                    hexEditorWidget->setBuffer(0, packetBytes);
                }
                else
                {
                    hexEditorWidget->clearBuffer();
                }
                hexPageLayout->addWidget(hexEditorWidget, 1);

                detailTabWidget->addTab(hexPage, QStringLiteral("十六进制"));
            }
        };
    }

    QString toQString(const std::string& textValue)
    {
        return QString::fromUtf8(textValue.c_str());
    }

    QString formatEndpointText(const std::string& ipAddress, const std::uint16_t portNumber)
    {
        return toQString(ks::network::FormatEndpointText(ipAddress, portNumber));
    }

    QString formatBytesToHexText(const std::vector<std::uint8_t>& byteArray, const std::size_t maxBytesToRender)
    {
        return toQString(ks::network::FormatBytesToHexPreview(byteArray, maxBytesToRender));
    }

    std::pair<std::size_t, std::size_t> buildPayloadByteRange(const ks::network::PacketRecord& packetRecord)
    {
        const ks::network::PayloadByteRange payloadRange =
            ks::network::BuildPayloadByteRange(packetRecord);
        return { payloadRange.offset, payloadRange.length };
    }

    QString buildPayloadAsciiPreviewText(const ks::network::PacketRecord& packetRecord)
    {
        return toQString(ks::network::BuildPayloadAsciiPreviewText(packetRecord));
    }

    QString buildPayloadAsciiFullText(const ks::network::PacketRecord& packetRecord)
    {
        return toQString(ks::network::BuildPayloadAsciiFullText(packetRecord));
    }

    QString buildPayloadHexFullText(const ks::network::PacketRecord& packetRecord)
    {
        return toQString(ks::network::BuildPayloadHexFullText(packetRecord));
    }

    QString buildPacketHexAsciiDumpText(const ks::network::PacketRecord& packetRecord)
    {
        return toQString(ks::network::BuildPacketHexAsciiDumpText(packetRecord));
    }

    QString buildPacketCopyHeaderLine(const ks::network::PacketRecord& packetRecord)
    {
        return toQString(ks::network::BuildPacketCopyHeaderLine(packetRecord));
    }

    QString formatIpv4HostOrder(const std::uint32_t ipv4HostOrder)
    {
        return toQString(ks::network::FormatIpv4HostOrder(ipv4HostOrder));
    }

    bool tryParseIpv4Text(const QString& ipv4Text, std::uint32_t& ipv4HostOrderOut)
    {
        return ks::network::TryParseIpv4Text(ipv4Text.trimmed().toStdString(), &ipv4HostOrderOut);
    }

    bool tryParseIpv4RangeText(
        const QString& rangeText,
        std::pair<std::uint32_t, std::uint32_t>& rangeOut,
        QString& normalizeTextOut)
    {
        std::string normalizedText;
        const bool parseOk = ks::network::TryParseIpv4RangeText(
            rangeText.trimmed().toStdString(),
            &rangeOut,
            &normalizedText);
        normalizeTextOut = toQString(normalizedText);
        return parseOk;
    }

    bool tryParsePortRangeText(
        const QString& rangeText,
        std::pair<std::uint16_t, std::uint16_t>& rangeOut,
        QString& normalizeTextOut)
    {
        std::string normalizedText;
        const bool parseOk = ks::network::TryParsePortRangeText(
            rangeText.trimmed().toStdString(),
            &rangeOut,
            &normalizedText);
        normalizeTextOut = toQString(normalizedText);
        return parseOk;
    }

    QTableWidgetItem* createPacketCell(const QString& cellText)
    {
        QTableWidgetItem* tableItem = new QTableWidgetItem(cellText);
        tableItem->setFlags(tableItem->flags() & ~Qt::ItemIsEditable);
        return tableItem;
    }

    void populatePacketRow(
        QTableWidget* tableWidget,
        const int rowIndex,
        const ks::network::PacketRecord& packetRecord,
        const std::uint64_t sequenceId,
        const QIcon& processIcon)
    {
        if (tableWidget == nullptr || rowIndex < 0)
        {
            return;
        }

        const QString timeText = toQString(
            ks::network::FormatUnixTimestampMs(packetRecord.captureTimestampMs, false));
        const QString protocolText = toQString(ks::network::PacketProtocolToString(packetRecord.protocol));
        const QString directionText = toQString(ks::network::PacketDirectionToString(packetRecord.direction));
        const QString sourceText = packetSourceDisplayText(packetRecord);
        const QString pidText = QString::number(packetRecord.processId);
        const QString processNameText = toQString(packetRecord.processName);
        const QString localEndpointText = formatEndpointText(packetRecord.localAddress, packetRecord.localPort);
        const QString remoteEndpointText = formatEndpointText(packetRecord.remoteAddress, packetRecord.remotePort);
        const QString remoteDomainText = packetRecord.remoteDomain.empty()
            ? QStringLiteral("解析中…")
            : toQString(packetRecord.remoteDomain);
        const QString packetSizeText = packetRecord.wfpAleEventNoPayload
            ? QStringLiteral("-")
            : QString::number(packetRecord.totalPacketSize);
        const QString payloadSizeText = packetRecord.wfpAleEventNoPayload
            ? QStringLiteral("-")
            : QString::number(packetRecord.payloadSize);
        const QString previewText = packetRecord.wfpAleEventNoPayload
            ? QStringLiteral("R0 WFP ALE 流事件不包含 packet payload")
            : buildPayloadAsciiPreviewText(packetRecord);

        QTableWidgetItem* timeItem = createPacketCell(timeText);
        timeItem->setData(Qt::UserRole, static_cast<qulonglong>(sequenceId));
        tableWidget->setItem(rowIndex, 0, timeItem);
        tableWidget->setItem(rowIndex, 1, createPacketCell(protocolText));
        tableWidget->setItem(rowIndex, 2, createPacketCell(directionText));
        tableWidget->setItem(rowIndex, 3, createPacketCell(sourceText));
        tableWidget->setItem(rowIndex, 4, createPacketCell(pidText));
        QTableWidgetItem* processNameItem = createPacketCell(processNameText);
        processNameItem->setIcon(processIcon);
        tableWidget->setItem(rowIndex, 5, processNameItem);
        tableWidget->setItem(rowIndex, 6, createPacketCell(localEndpointText));
        tableWidget->setItem(rowIndex, 7, createPacketCell(remoteEndpointText));
        QTableWidgetItem* remoteDomainItem = createPacketCell(remoteDomainText);
        remoteDomainItem->setData(Qt::UserRole, toQString(packetRecord.remoteAddress));
        tableWidget->setItem(rowIndex, 8, remoteDomainItem);
        tableWidget->setItem(rowIndex, 9, createPacketCell(packetSizeText));
        tableWidget->setItem(rowIndex, 10, createPacketCell(payloadSizeText));
        tableWidget->setItem(rowIndex, 11, createPacketCell(previewText));
    }

    void showPacketDetailWindow(const ks::network::PacketRecord& packetRecord)
    {
        // 详情窗口使用 show() 非模态弹出，不阻塞主 UI。
        // 独立窗口：不挂在 Dock 下，避免主窗口布局变化影响详情窗口。
        PacketDetailWindow* detailWindow = new PacketDetailWindow(packetRecord, nullptr);
        detailWindow->setWindowFlag(Qt::Window, true);
        detailWindow->show();
        detailWindow->raise();
        detailWindow->activateWindow();
    }
}


