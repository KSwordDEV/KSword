
#include "MonitorDock.h"
#include "../../../shared/ui/KsPainterChart.h"
#include <MonitorDock/EtwArchiveCompression.h>
#include "../UI/VisibleTableWidget.h"
#include "DirectKernelCallMonitorWidget.h"
#include "KernelCallbackMonitorWidget.h"
#include "MonitorTextViewer.h"
#include "ProcessTraceMonitorWidget.h"
#include "WinAPIDock.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/TableInteractionSupport.h"

// 监控页实现：包含 WMI/ETW 两个标签页，所有重活走异步线程。
#include "../OnlineScan/SandboxUploadActions.h"
#include "../ProcessDock/ProcessDetailWindow.h"
#include "../theme.h"

#include <QApplication>
#include <QAbstractItemModel>
#include <QBuffer>
#include <QByteArray>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QEasingCurve>
#include <QDataStream>
#include <QDir>
#include <QEvent>
#include <QFileInfo>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLayoutItem>
#include <QLineEdit>
#include <QListWidget>
#include <QJsonArray>
#include <QList>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QPainter>
#include <QRegularExpression>
#include <QSaveFile>
#include <QScrollArea>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSortFilterProxyModel>
#include <QSpinBox>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QStandardPaths>
#include <QTabWidget>
#include <QTableView>
#include <QTableWidget>
#include <QTextStream>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <QtEndian>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <set>
#include <span>
#include <thread>
#include <unordered_map>
#include <limits>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Wbemidl.h>
#include <Objbase.h>
#include <comdef.h>
#include <atlbase.h>
#include <evntrace.h>
#include <evntcons.h>
#include <sddl.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <Pdh.h>
#include <pdhmsg.h>
#include <tdh.h>

#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace
{
    constexpr char kEtwArchiveMagic[] = "KSWETW1";
    constexpr std::uint32_t kEtwArchiveLegacyFileVersion = 1;
    constexpr std::uint32_t kEtwArchiveFileVersion = 2;
    constexpr std::uint32_t kEtwArchiveRowVersion = 2;
    constexpr std::uint32_t kEtwArchiveMaximumRecordBytes = 64U * 1024U * 1024U;
    constexpr qsizetype kEtwArchiveWriteBufferBytes = 1024 * 1024;
    constexpr std::uint32_t kEtwArchiveMaximumBlockBytes =
        kEtwArchiveMaximumRecordBytes + static_cast<std::uint32_t>(kEtwArchiveWriteBufferBytes)
        + static_cast<std::uint32_t>(sizeof(quint32));
    constexpr std::uint32_t kEtwArchiveMaximumStoredBlockBytes =
        kEtwArchiveMaximumBlockBytes + 1024U * 1024U;

    QByteArray serializeEtwArchiveRow(const MonitorDock::EtwCapturedEventRow& row)
    {
        const QByteArray detailJsonUtf8 = row.detailJson.toUtf8();
        QByteArray payload;
        payload.reserve(detailJsonUtf8.size() + 4096);
        QDataStream stream(&payload, QIODevice::WriteOnly);
        stream.setByteOrder(QDataStream::LittleEndian);
        stream.setVersion(QDataStream::Qt_6_0);
        stream
            << static_cast<quint32>(kEtwArchiveRowVersion)
            << static_cast<quint64>(row.archiveSequence)
            << row.decodedReady
            << row.timestampText
            << static_cast<quint64>(row.timestampValue)
            << row.providerName << row.providerGuid << row.providerCategory
            << static_cast<qint32>(row.eventId) << row.eventName
            << static_cast<qint32>(row.task) << row.taskName
            << static_cast<qint32>(row.opcode) << row.opcodeName
            << static_cast<qint32>(row.level) << row.levelText
            << static_cast<quint64>(row.keywordMaskValue) << row.keywordMaskText
            << static_cast<quint32>(row.headerPid) << static_cast<quint32>(row.headerTid)
            << row.activityId << row.pidTidText
            << row.detailSummary << detailJsonUtf8
            << row.resourceTypeText << row.actionText << row.targetText << row.statusText
            << static_cast<quint32>(row.targetPid) << row.targetPidValid
            << static_cast<quint32>(row.parentPid) << row.parentPidValid
            << static_cast<quint32>(row.targetTid) << row.targetTidValid
            << row.processNameText << row.imagePathText << row.commandLineText
            << row.filePathText << row.fileOldPathText << row.fileNewPathText
            << row.fileOperationText << row.fileStatusCodeText << row.fileAccessMaskText
            << row.registryKeyPathText << row.registryValueNameText << row.registryHiveText
            << row.registryOperationText << row.registryStatusText
            << row.sourceIpText << static_cast<quint32>(row.sourceIpValue) << row.sourceIpValid
            << static_cast<quint16>(row.sourcePort) << row.sourcePortValid
            << row.destinationIpText << static_cast<quint32>(row.destinationIpValue) << row.destinationIpValid
            << static_cast<quint16>(row.destinationPort) << row.destinationPortValid
            << row.protocolText << row.directionText << row.domainText << row.hostText
            << row.auditResultText << row.userText << row.sidText
            << static_cast<quint32>(row.securityPid) << row.securityPidValid
            << static_cast<quint32>(row.securityTid) << row.securityTidValid
            << row.securityLevelText
            << row.scriptHostProcessText << row.scriptKeywordText << row.scriptTaskNameText
            << row.wmiClassNameText << row.wmiNamespaceText;
        return stream.status() == QDataStream::Ok ? payload : QByteArray();
    }

    bool deserializeEtwArchiveRow(
        const QByteArray& payload,
        MonitorDock::EtwCapturedEventRow* rowOut)
    {
        if (payload.isEmpty() || rowOut == nullptr)
        {
            return false;
        }

        QBuffer buffer;
        buffer.setData(payload);
        if (!buffer.open(QIODevice::ReadOnly))
        {
            return false;
        }

        QDataStream stream(&buffer);
        stream.setByteOrder(QDataStream::LittleEndian);
        stream.setVersion(QDataStream::Qt_6_0);

        quint32 rowVersion = 0;
        quint64 archiveSequence = 0;
        quint64 timestampValue = 0;
        qint32 eventId = 0;
        qint32 task = 0;
        qint32 opcode = 0;
        qint32 level = 0;
        quint64 keywordMaskValue = 0;
        quint32 headerPid = 0;
        quint32 headerTid = 0;
        quint32 targetPid = 0;
        quint32 parentPid = 0;
        quint32 targetTid = 0;
        quint32 sourceIpValue = 0;
        quint16 sourcePort = 0;
        quint32 destinationIpValue = 0;
        quint16 destinationPort = 0;
        quint32 securityPid = 0;
        quint32 securityTid = 0;
        QByteArray detailJsonUtf8;

        MonitorDock::EtwCapturedEventRow row;
        stream
            >> rowVersion
            >> archiveSequence
            >> row.decodedReady
            >> row.timestampText
            >> timestampValue
            >> row.providerName >> row.providerGuid >> row.providerCategory
            >> eventId >> row.eventName
            >> task >> row.taskName
            >> opcode >> row.opcodeName
            >> level >> row.levelText
            >> keywordMaskValue >> row.keywordMaskText
            >> headerPid >> headerTid
            >> row.activityId >> row.pidTidText
            >> row.detailSummary >> detailJsonUtf8
            >> row.resourceTypeText >> row.actionText >> row.targetText >> row.statusText
            >> targetPid >> row.targetPidValid
            >> parentPid >> row.parentPidValid
            >> targetTid >> row.targetTidValid
            >> row.processNameText >> row.imagePathText >> row.commandLineText
            >> row.filePathText >> row.fileOldPathText >> row.fileNewPathText
            >> row.fileOperationText >> row.fileStatusCodeText >> row.fileAccessMaskText
            >> row.registryKeyPathText >> row.registryValueNameText >> row.registryHiveText
            >> row.registryOperationText >> row.registryStatusText
            >> row.sourceIpText >> sourceIpValue >> row.sourceIpValid
            >> sourcePort >> row.sourcePortValid
            >> row.destinationIpText >> destinationIpValue >> row.destinationIpValid
            >> destinationPort >> row.destinationPortValid
            >> row.protocolText >> row.directionText >> row.domainText >> row.hostText
            >> row.auditResultText >> row.userText >> row.sidText
            >> securityPid >> row.securityPidValid
            >> securityTid >> row.securityTidValid
            >> row.securityLevelText
            >> row.scriptHostProcessText >> row.scriptKeywordText >> row.scriptTaskNameText
            >> row.wmiClassNameText >> row.wmiNamespaceText;

        if (stream.status() != QDataStream::Ok || rowVersion != kEtwArchiveRowVersion)
        {
            return false;
        }

        row.archiveSequence = static_cast<std::uint64_t>(archiveSequence);
        row.timestampValue = static_cast<std::uint64_t>(timestampValue);
        row.eventId = static_cast<int>(eventId);
        row.task = static_cast<int>(task);
        row.opcode = static_cast<int>(opcode);
        row.level = static_cast<int>(level);
        row.keywordMaskValue = static_cast<std::uint64_t>(keywordMaskValue);
        row.headerPid = static_cast<std::uint32_t>(headerPid);
        row.headerTid = static_cast<std::uint32_t>(headerTid);
        row.targetPid = static_cast<std::uint32_t>(targetPid);
        row.parentPid = static_cast<std::uint32_t>(parentPid);
        row.targetTid = static_cast<std::uint32_t>(targetTid);
        row.sourceIpValue = static_cast<std::uint32_t>(sourceIpValue);
        row.sourcePort = static_cast<std::uint16_t>(sourcePort);
        row.destinationIpValue = static_cast<std::uint32_t>(destinationIpValue);
        row.destinationPort = static_cast<std::uint16_t>(destinationPort);
        row.securityPid = static_cast<std::uint32_t>(securityPid);
        row.securityTid = static_cast<std::uint32_t>(securityTid);
        row.detailJson = QString::fromUtf8(detailJsonUtf8);
        row.detailVisibleText = QStringLiteral("%1 %2 %3 %4 %5 %6 %7")
            .arg(row.timestampText)
            .arg(row.providerName)
            .arg(row.eventId)
            .arg(row.eventName)
            .arg(row.pidTidText)
            .arg(row.detailSummary)
            .arg(row.activityId);
        row.detailAllText = QStringLiteral("%1 %2 %3 %4 %5 %6 %7 %8 %9 %10")
            .arg(row.detailVisibleText)
            .arg(row.resourceTypeText)
            .arg(row.actionText)
            .arg(row.targetText)
            .arg(row.statusText)
            .arg(row.processNameText)
            .arg(row.filePathText)
            .arg(row.registryKeyPathText)
            .arg(row.scriptKeywordText)
            .arg(row.detailJson);
        row.detailAllText.replace(QChar(u'\r'), QChar(u' '));
        row.detailAllText.replace(QChar(u'\n'), QChar(u' '));
        row.detailAllText = row.detailAllText.simplified();
        *rowOut = std::move(row);
        return true;
    }

    QByteArray buildEtwArchiveFileHeader()
    {
        QByteArray header;
        QDataStream stream(&header, QIODevice::WriteOnly);
        stream.setByteOrder(QDataStream::LittleEndian);
        stream.writeRawData(kEtwArchiveMagic, static_cast<int>(sizeof(kEtwArchiveMagic) - 1));
        stream << static_cast<quint32>(kEtwArchiveFileVersion);
        return header;
    }

    bool writeAllToHandle(const HANDLE fileHandle, const QByteArray& data)
    {
        if (fileHandle == nullptr || fileHandle == INVALID_HANDLE_VALUE || data.isEmpty())
        {
            return data.isEmpty();
        }

        qsizetype writtenTotal = 0;
        while (writtenTotal < data.size())
        {
            const qsizetype remaining = data.size() - writtenTotal;
            const DWORD requestBytes = static_cast<DWORD>(std::min<qsizetype>(
                remaining,
                static_cast<qsizetype>(std::numeric_limits<DWORD>::max())));
            DWORD writtenBytes = 0;
            if (::WriteFile(
                fileHandle,
                data.constData() + writtenTotal,
                requestBytes,
                &writtenBytes,
                nullptr) == FALSE
                || writtenBytes == 0)
            {
                return false;
            }
            writtenTotal += static_cast<qsizetype>(writtenBytes);
        }
        return true;
    }

    bool writeEtwArchiveBlockToHandle(const HANDLE fileHandle, const QByteArray& uncompressedData)
    {
        if (uncompressedData.isEmpty())
        {
            return true;
        }
        if (uncompressedData.size() > static_cast<qsizetype>(kEtwArchiveMaximumBlockBytes))
        {
            return false;
        }

        KswordEtwArchiveCompression::EncodedBlock encodedBlock;
        if (!KswordEtwArchiveCompression::compressBlock(
            std::span<const char>(
                uncompressedData.constData(),
                static_cast<std::size_t>(uncompressedData.size())),
            &encodedBlock)
            || encodedBlock.payload.empty()
            || encodedBlock.payload.size() > kEtwArchiveMaximumStoredBlockBytes)
        {
            return false;
        }

        QByteArray blockHeader;
        blockHeader.reserve(static_cast<qsizetype>(sizeof(quint32) * 3));
        const quint32 methodLittleEndian = qToLittleEndian(
            static_cast<quint32>(encodedBlock.method));
        const quint32 uncompressedSizeLittleEndian = qToLittleEndian(
            static_cast<quint32>(uncompressedData.size()));
        const quint32 storedSizeLittleEndian = qToLittleEndian(
            static_cast<quint32>(encodedBlock.payload.size()));
        blockHeader.append(
            reinterpret_cast<const char*>(&methodLittleEndian),
            static_cast<qsizetype>(sizeof(methodLittleEndian)));
        blockHeader.append(
            reinterpret_cast<const char*>(&uncompressedSizeLittleEndian),
            static_cast<qsizetype>(sizeof(uncompressedSizeLittleEndian)));
        blockHeader.append(
            reinterpret_cast<const char*>(&storedSizeLittleEndian),
            static_cast<qsizetype>(sizeof(storedSizeLittleEndian)));

        const QByteArray storedData = QByteArray::fromRawData(
            encodedBlock.payload.data(),
            static_cast<qsizetype>(encodedBlock.payload.size()));
        return writeAllToHandle(fileHandle, blockHeader)
            && writeAllToHandle(fileHandle, storedData);
    }

    bool scanEtwArchiveFile(
        const QString& filePath,
        const std::function<bool(const MonitorDock::EtwCapturedEventRow&)>& rowVisitor,
        const std::function<bool()>& shouldCancel,
        std::uint64_t* scannedRowsInOut,
        std::uint64_t* maxSequenceInOut,
        QString* errorTextOut)
    {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法读取 ETW 归档分段：%1").arg(filePath);
            }
            return false;
        }

        constexpr qint64 kMagicBytes = static_cast<qint64>(sizeof(kEtwArchiveMagic) - 1);
        constexpr qint64 kHeaderBytes = kMagicBytes + static_cast<qint64>(sizeof(quint32));
        const qint64 fileSize = file.size();
        if (fileSize < kHeaderBytes)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("ETW 归档分段格式无效：%1").arg(filePath);
            }
            return false;
        }

        uchar* mappedData = file.map(0, fileSize);
        if (mappedData == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法读取 ETW 归档分段：%1").arg(filePath);
            }
            return false;
        }
        const auto mappedGuard = std::unique_ptr<uchar, std::function<void(uchar*)>>(
            mappedData,
            [&file](uchar* data) {
                file.unmap(data);
            });

        const quint32 fileVersion = qFromLittleEndian<quint32>(mappedData + kMagicBytes);
        if (std::memcmp(mappedData, kEtwArchiveMagic, static_cast<std::size_t>(kMagicBytes)) != 0
            || (fileVersion != kEtwArchiveLegacyFileVersion
                && fileVersion != kEtwArchiveFileVersion))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("ETW 归档分段格式无效：%1").arg(filePath);
            }
            return false;
        }

        bool stopRequested = false;
        const auto scanRecordBuffer = [&](
            const char* recordData,
            const qint64 recordBytes) -> bool {
            qint64 recordOffset = 0;
            while (recordOffset < recordBytes)
            {
                if (shouldCancel && shouldCancel())
                {
                    stopRequested = true;
                    return true;
                }
                if (recordBytes - recordOffset < static_cast<qint64>(sizeof(quint32)))
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("ETW 归档分段尾部不完整：%1").arg(filePath);
                    }
                    return false;
                }

                const quint32 payloadSize = qFromLittleEndian<quint32>(
                    reinterpret_cast<const uchar*>(recordData + recordOffset));
                recordOffset += static_cast<qint64>(sizeof(quint32));
                if (payloadSize == 0 || payloadSize > kEtwArchiveMaximumRecordBytes)
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("ETW 归档记录长度无效：%1").arg(filePath);
                    }
                    return false;
                }
                if (static_cast<qint64>(payloadSize) > recordBytes - recordOffset)
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("ETW 归档记录内容不完整：%1").arg(filePath);
                    }
                    return false;
                }

                const QByteArray payload = QByteArray::fromRawData(
                    recordData + recordOffset,
                    static_cast<qsizetype>(payloadSize));
                recordOffset += static_cast<qint64>(payloadSize);
                MonitorDock::EtwCapturedEventRow row;
                if (!deserializeEtwArchiveRow(payload, &row))
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("ETW 归档记录解析失败：%1").arg(filePath);
                    }
                    return false;
                }

                if (scannedRowsInOut != nullptr)
                {
                    ++(*scannedRowsInOut);
                }
                if (maxSequenceInOut != nullptr)
                {
                    *maxSequenceInOut = std::max(*maxSequenceInOut, row.archiveSequence);
                }
                if (rowVisitor && !rowVisitor(row))
                {
                    stopRequested = true;
                    return true;
                }
            }
            return true;
        };

        if (fileVersion == kEtwArchiveLegacyFileVersion)
        {
            return scanRecordBuffer(
                reinterpret_cast<const char*>(mappedData + kHeaderBytes),
                fileSize - kHeaderBytes);
        }

        qint64 blockOffset = kHeaderBytes;
        constexpr qint64 kBlockHeaderBytes = static_cast<qint64>(sizeof(quint32) * 3);
        while (blockOffset < fileSize)
        {
            if (shouldCancel && shouldCancel())
            {
                return true;
            }
            if (fileSize - blockOffset < kBlockHeaderBytes)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("ETW 归档分段尾部不完整：%1").arg(filePath);
                }
                return false;
            }

            const quint32 methodValue = qFromLittleEndian<quint32>(mappedData + blockOffset);
            blockOffset += static_cast<qint64>(sizeof(quint32));
            const quint32 uncompressedSize = qFromLittleEndian<quint32>(mappedData + blockOffset);
            blockOffset += static_cast<qint64>(sizeof(quint32));
            const quint32 storedSize = qFromLittleEndian<quint32>(mappedData + blockOffset);
            blockOffset += static_cast<qint64>(sizeof(quint32));

            if (uncompressedSize == 0
                || uncompressedSize > kEtwArchiveMaximumBlockBytes
                || storedSize == 0
                || storedSize > kEtwArchiveMaximumStoredBlockBytes
                || static_cast<qint64>(storedSize) > fileSize - blockOffset)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("ETW 归档分段格式无效：%1").arg(filePath);
                }
                return false;
            }

            std::vector<char> decodedBlock;
            if (!KswordEtwArchiveCompression::decompressBlock(
                static_cast<KswordEtwArchiveCompression::BlockMethod>(methodValue),
                std::span<const char>(
                    reinterpret_cast<const char*>(mappedData + blockOffset),
                    static_cast<std::size_t>(storedSize)),
                static_cast<std::size_t>(uncompressedSize),
                &decodedBlock))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("ETW 归档分段格式无效：%1").arg(filePath);
                }
                return false;
            }
            blockOffset += static_cast<qint64>(storedSize);

            if (!scanRecordBuffer(
                decodedBlock.data(),
                static_cast<qint64>(decodedBlock.size())))
            {
                return false;
            }
            if (stopRequested)
            {
                return true;
            }
        }
        return true;
    }

    // 按主题统一按钮风格。
    QString blueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    // 输入框统一样式。
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QPlainTextEdit,QSpinBox{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus,QPlainTextEdit:focus,QSpinBox:focus{border:1px solid %1;}")
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            + KswordTheme::ThemedComboBoxStyle();
    }

    void installMonitorTableCopyMenu(QTableWidget* tableWidget)
    {
        // installMonitorTableCopyMenu：
        // - 输入：监控页内只读/选择型表格；
        // - 处理：右键定位当前行，并复制该行所有列为 TSV；
        // - 返回：无。只复制现有 UI 文本，不启动/停止 WMI 或 ETW 会话。
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tableWidget, &QTableWidget::customContextMenuRequested, tableWidget, [tableWidget](const QPoint& localPosition)
        {
            const auto clickedIndex = tableWidget->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                tableWidget->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            }

            QMenu menu(tableWidget);
            // 右键菜单必须显式使用不透明主题，避免背景图/透明样式造成黑底黑字。
            menu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/log_clipboard.svg")),
                QStringLiteral("复制整行"));
            copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
            if (menu.exec(tableWidget->viewport()->mapToGlobal(localPosition)) != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            const int rowIndex = tableWidget->currentRow();
            if (clipboardObject == nullptr || rowIndex < 0 || rowIndex >= tableWidget->rowCount())
            {
                return;
            }

            QStringList values;
            values.reserve(tableWidget->columnCount());
            for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* item = tableWidget->item(rowIndex, columnIndex);
                values << (item != nullptr ? item->text() : QString());
            }
            clipboardObject->setText(values.join(QLatin1Char('\t')));
        });
    }

    void installMonitorTableViewCopyMenu(QTableView* tableView)
    {
        // installMonitorTableViewCopyMenu：
        // - 输入：使用 QAbstractItemModel/QSortFilterProxyModel 的只读表格视图；
        // - 处理：右键定位当前 proxy 行，并按当前显示顺序复制整行 TSV；
        // - 返回：无。仅复制 WMI Provider 等审计列表，不启动/停止任何监控会话。
        if (tableView == nullptr)
        {
            return;
        }

        tableView->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tableView, &QTableView::customContextMenuRequested, tableView, [tableView](const QPoint& localPosition)
        {
            const QModelIndex clickedIndex = tableView->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                tableView->setCurrentIndex(clickedIndex);
                tableView->selectRow(clickedIndex.row());
            }

            QMenu menu(tableView);
            // QTableView 同样必须显式使用不透明菜单样式，避免继承父级透明背景。
            menu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/log_clipboard.svg")),
                QStringLiteral("复制整行"));
            copyRowAction->setEnabled(tableView->currentIndex().isValid());
            if (menu.exec(tableView->viewport()->mapToGlobal(localPosition)) != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            QAbstractItemModel* modelObject = tableView->model();
            const QModelIndex currentIndex = tableView->currentIndex();
            if (clipboardObject == nullptr || modelObject == nullptr || !currentIndex.isValid())
            {
                return;
            }

            QStringList values;
            values.reserve(modelObject->columnCount(currentIndex.parent()));
            for (int columnIndex = 0; columnIndex < modelObject->columnCount(currentIndex.parent()); ++columnIndex)
            {
                const QModelIndex cellIndex = modelObject->index(currentIndex.row(), columnIndex, currentIndex.parent());
                values << modelObject->data(cellIndex, Qt::DisplayRole).toString();
            }
            clipboardObject->setText(values.join(QLatin1Char('\t')));
        });
    }

    // createMonitorDeferredPlaceholder 作用：
    // - 输入：父控件、标题文本和提示文本；
    // - 处理：创建轻量占位页，避免重监控子页压在 MonitorDock 首次点击路径上；
    // - 返回：占位 QWidget 指针，调用方加入对应宿主布局。
    QWidget* createMonitorDeferredPlaceholder(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& hintText)
    {
        QWidget* placeholderWidget = new QWidget(parentWidget);
        placeholderWidget->setAutoFillBackground(false);
        placeholderWidget->setAttribute(Qt::WA_StyledBackground, false);

        QVBoxLayout* placeholderLayout = new QVBoxLayout(placeholderWidget);
        placeholderLayout->setContentsMargins(24, 24, 24, 24);
        placeholderLayout->setSpacing(8);
        placeholderLayout->addStretch(1);

        QLabel* titleLabel = new QLabel(titleText, placeholderWidget);
        titleLabel->setAlignment(Qt::AlignCenter);
        titleLabel->setStyleSheet(
            QStringLiteral("font-size:16px;font-weight:700;color:%1;")
            .arg(KswordTheme::TextPrimaryHex()));
        placeholderLayout->addWidget(titleLabel, 0);

        QLabel* hintLabel = new QLabel(hintText, placeholderWidget);
        hintLabel->setAlignment(Qt::AlignCenter);
        hintLabel->setWordWrap(true);
        hintLabel->setStyleSheet(
            QStringLiteral("font-size:12px;color:%1;")
            .arg(KswordTheme::TextSecondaryHex()));
        placeholderLayout->addWidget(hintLabel, 0);
        placeholderLayout->addStretch(1);
        return placeholderWidget;
    }

    // 表头统一样式。
    QString blueHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;padding:4px;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex());
    }

    // collapsePanelStyle 作用：
    // - 为 WMI/ETW 顶部独立折叠面板提供主题自适应边框与背景；
    // - 返回：可直接应用到折叠面板宿主 QWidget 的样式表。
    QString collapsePanelStyle()
    {
        return QStringLiteral(
            "QWidget[kswordCollapsePanel=\"true\"]{"
            "  background:transparent;"
            "  background-color:transparent;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:5px;"
            "}"
            "QWidget[kswordCollapseContent=\"true\"]{"
            "  background:transparent;"
            "  background-color:transparent;"
            "  color:%2;"
            "  border:none;"
            "}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex());
    }

    // collapseHeaderButtonStyle 作用：
    // - 重写折叠头按钮主题，避免继承旧 Collapse/QToolBox 的固定配色；
    // - 返回：可直接应用到 QToolButton 的样式表。
    QString collapseHeaderButtonStyle()
    {
        return QStringLiteral(
            "QToolButton{"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:5px;"
            "  padding:5px 8px;"
            "  font-weight:600;"
            "  text-align:left;"
            "}"
            "QToolButton:hover{"
            "  background:%4;"
            "  color:%2;"
            "  border-color:%5;"
            "}"
            "QToolButton:checked{"
            "  background:%4;"
            "  color:%2;"
            "  border-color:%5;"
            "}")
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::PrimaryBlueSubtleHex())
            .arg(KswordTheme::PrimaryBlueHex);
    }

    // createIndependentCollapseSection 作用：
    // - 构造一个不互斥的折叠段，允许所有段同时收起；
    // - 入参 parent：父控件；titleText：标题；contentWidget：已有内容页；expanded：初始展开状态；
    // - 返回：外层折叠段 QWidget，内部 header/content 均随父对象释放。
    QWidget* createIndependentCollapseSection(
        QWidget* parent,
        const QString& titleText,
        QWidget* contentWidget,
        const bool expanded)
    {
        QWidget* sectionWidget = new QWidget(parent);
        sectionWidget->setProperty("kswordCollapsePanel", QStringLiteral("true"));
        sectionWidget->setStyleSheet(collapsePanelStyle());
        sectionWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);

        QVBoxLayout* sectionLayout = new QVBoxLayout(sectionWidget);
        sectionLayout->setContentsMargins(0, 0, 0, 0);
        sectionLayout->setSpacing(0);

        QToolButton* headerButton = new QToolButton(sectionWidget);
        headerButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        headerButton->setText(titleText);
        headerButton->setCheckable(true);
        headerButton->setChecked(expanded);
        headerButton->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
        headerButton->setStyleSheet(collapseHeaderButtonStyle());
        headerButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

        QWidget* contentHostWidget = new QWidget(sectionWidget);
        contentHostWidget->setProperty("kswordCollapseContent", QStringLiteral("true"));
        contentHostWidget->setStyleSheet(collapsePanelStyle());
        contentHostWidget->setVisible(expanded);
        contentHostWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);

        QVBoxLayout* contentHostLayout = new QVBoxLayout(contentHostWidget);
        contentHostLayout->setContentsMargins(4, 4, 4, 4);
        contentHostLayout->setSpacing(4);
        contentHostLayout->addWidget(contentWidget);

        sectionLayout->addWidget(headerButton, 0);
        sectionLayout->addWidget(contentHostWidget, 0);

        QObject::connect(headerButton, &QToolButton::toggled, sectionWidget,
            [headerButton, contentHostWidget, sectionWidget](const bool checked) {
                // 每个折叠段只控制自己的内容区，不影响兄弟段展开状态。
                headerButton->setArrowType(checked ? Qt::DownArrow : Qt::RightArrow);
                contentHostWidget->setVisible(checked);
                sectionWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
                sectionWidget->updateGeometry();
                QWidget* parentWidget = sectionWidget->parentWidget();
                while (parentWidget != nullptr)
                {
                    parentWidget->updateGeometry();
                    parentWidget = parentWidget->parentWidget();
                }
            });

        return sectionWidget;
    }

    // refreshIndependentCollapseTheme 作用：
    // - 递归刷新独立折叠段样式，响应深浅主题切换；
    // - 入参 rootWidget：需要扫描的根控件；
    // - 返回：无返回值。
    void refreshIndependentCollapseTheme(QWidget* rootWidget)
    {
        if (rootWidget == nullptr)
        {
            return;
        }

        const QList<QWidget*> widgetList = rootWidget->findChildren<QWidget*>();
        for (QWidget* widgetPointer : widgetList)
        {
            if (widgetPointer == nullptr)
            {
                continue;
            }
            if (widgetPointer->property("kswordCollapsePanel").toString() == QStringLiteral("true")
                || widgetPointer->property("kswordCollapseContent").toString() == QStringLiteral("true"))
            {
                widgetPointer->setStyleSheet(collapsePanelStyle());
            }
        }

        const QList<QToolButton*> headerButtonList = rootWidget->findChildren<QToolButton*>();
        for (QToolButton* buttonPointer : headerButtonList)
        {
            if (buttonPointer != nullptr
                && buttonPointer->parentWidget() != nullptr
                && buttonPointer->parentWidget()->property("kswordCollapsePanel").toString() == QStringLiteral("true"))
            {
                buttonPointer->setStyleSheet(collapseHeaderButtonStyle());
            }
        }
    }

    // buildStatusStyle 作用：
    // - 统一监控页状态标签配色，深浅色模式下都保持可读。
    // 参数 colorHex：状态文字颜色。
    // 返回：完整样式字符串。
    QString buildStatusStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    void stopActiveKswordTraceSessionsByPrefix(const QStringList& sessionPrefixList)
    {
        constexpr ULONG kQuerySessionCapacity = 96;
        constexpr ULONG kTraceNameChars = 1024;
        constexpr ULONG kLogFileChars = 1024;
        constexpr ULONG kPropertyBufferSize =
            sizeof(EVENT_TRACE_PROPERTIES)
            + (kTraceNameChars + kLogFileChars) * sizeof(wchar_t);

        std::vector<std::vector<unsigned char>> propertyBufferList(
            kQuerySessionCapacity,
            std::vector<unsigned char>(kPropertyBufferSize, 0));
        std::vector<EVENT_TRACE_PROPERTIES*> propertyPointerList(kQuerySessionCapacity, nullptr);

        for (ULONG indexValue = 0; indexValue < kQuerySessionCapacity; ++indexValue)
        {
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBufferList[indexValue].data());
            properties->Wnode.BufferSize = kPropertyBufferSize;
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            properties->LogFileNameOffset =
                sizeof(EVENT_TRACE_PROPERTIES) + kTraceNameChars * sizeof(wchar_t);
            propertyPointerList[indexValue] = properties;
        }

        ULONG sessionCount = kQuerySessionCapacity;
        const ULONG queryStatus = ::QueryAllTracesW(
            propertyPointerList.data(),
            kQuerySessionCapacity,
            &sessionCount);
        if (queryStatus != ERROR_SUCCESS && queryStatus != ERROR_MORE_DATA)
        {
            return;
        }

        for (ULONG indexValue = 0; indexValue < sessionCount && indexValue < kQuerySessionCapacity; ++indexValue)
        {
            const EVENT_TRACE_PROPERTIES* properties = propertyPointerList[indexValue];
            if (properties == nullptr || properties->LoggerNameOffset == 0)
            {
                continue;
            }

            const wchar_t* loggerNamePointer = reinterpret_cast<const wchar_t*>(
                propertyBufferList[indexValue].data() + properties->LoggerNameOffset);
            const QString loggerNameText = QString::fromWCharArray(loggerNamePointer).trimmed();
            if (loggerNameText.isEmpty())
            {
                continue;
            }

            const bool shouldStop = std::any_of(
                sessionPrefixList.begin(),
                sessionPrefixList.end(),
                [&loggerNameText](const QString& prefixText) {
                    return !prefixText.trimmed().isEmpty()
                        && loggerNameText.startsWith(prefixText, Qt::CaseInsensitive);
                });
            if (!shouldStop)
            {
                continue;
            }

            const std::wstring loggerNameWide = loggerNameText.toStdWString();
            std::vector<unsigned char> stopBuffer(
                sizeof(EVENT_TRACE_PROPERTIES) + (loggerNameWide.size() + 1) * sizeof(wchar_t),
                0);
            auto* stopProperties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stopBuffer.data());
            stopProperties->Wnode.BufferSize = static_cast<ULONG>(stopBuffer.size());
            stopProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            wchar_t* stopLoggerNamePointer = reinterpret_cast<wchar_t*>(
                stopBuffer.data() + stopProperties->LoggerNameOffset);
            ::wcscpy_s(stopLoggerNamePointer, loggerNameWide.size() + 1, loggerNameWide.c_str());
            ::ControlTraceW(0, stopLoggerNamePointer, stopProperties, EVENT_TRACE_CONTROL_STOP);
        }
    }

    // monitorInfoColorHex 作用：返回“信息态”颜色。
    QString monitorInfoColorHex()
    {
        return KswordTheme::InfoColor().name(QColor::HexRgb);
    }

    // monitorSuccessColorHex 作用：返回“成功态”颜色。
    QString monitorSuccessColorHex()
    {
        return KswordTheme::SuccessColor().name(QColor::HexRgb);
    }

    // monitorWarningColorHex 作用：返回“警告态”颜色。
    QString monitorWarningColorHex()
    {
        return KswordTheme::WarningColor().name(QColor::HexRgb);
    }

    // monitorErrorColorHex 作用：返回“错误态”颜色。
    QString monitorErrorColorHex()
    {
        return KswordTheme::ErrorColor().name(QColor::HexRgb);
    }

    // monitorIdleColorHex 作用：返回“空闲态”颜色。
    QString monitorIdleColorHex()
    {
        return KswordTheme::TextSecondaryHex();
    }

    // bytesPerSecondToText 作用：
    // - 把字节速率转换为可读文本（B/s、KB/s、MB/s、GB/s）；
    // - 用于图表标题展示实时数值。
    QString bytesPerSecondToText(const double bytesPerSecondValue)
    {
        const double absValue = std::max(0.0, bytesPerSecondValue);
        if (absValue < 1024.0)
        {
            return QStringLiteral("%1 B/s").arg(absValue, 0, 'f', 1);
        }
        if (absValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB/s").arg(absValue / 1024.0, 0, 'f', 1);
        }
        if (absValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB/s").arg(absValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB/s").arg(absValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // fileTimeToUint64 作用：
    // - 把 FILETIME 合并为 64 位整数，便于计算时间差；
    // - 用于 CPU 占用率采样。
    std::uint64_t fileTimeToUint64(const FILETIME& fileTimeValue)
    {
        ULARGE_INTEGER largeIntValue{};
        largeIntValue.LowPart = fileTimeValue.dwLowDateTime;
        largeIntValue.HighPart = fileTimeValue.dwHighDateTime;
        return static_cast<std::uint64_t>(largeIntValue.QuadPart);
    }

    // 线程内 COM 初始化。
    bool initCom(QString* errorOut)
    {
        if (errorOut != nullptr)
        {
            errorOut->clear();
        }

        const HRESULT initResult = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(initResult) && initResult != RPC_E_CHANGED_MODE)
        {
            if (errorOut != nullptr)
            {
                *errorOut = QString("CoInitializeEx失败:0x%1").arg(static_cast<unsigned long>(initResult), 0, 16);
            }
            return false;
        }

        const HRESULT secResult = ::CoInitializeSecurity(
            nullptr,
            -1,
            nullptr,
            nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE,
            nullptr);

        if (FAILED(secResult) && secResult != RPC_E_TOO_LATE)
        {
            if (errorOut != nullptr)
            {
                *errorOut = QString("CoInitializeSecurity失败:0x%1").arg(static_cast<unsigned long>(secResult), 0, 16);
            }
            return false;
        }

        return true;
    }

    // VARIANT 转 QString。
    QString variantToText(const VARIANT& value)
    {
        switch (value.vt)
        {
        case VT_BSTR:
            return value.bstrVal != nullptr ? QString::fromWCharArray(value.bstrVal) : QString();
        case VT_I4:
        case VT_INT:
            return QString::number(value.intVal);
        case VT_UI4:
        case VT_UINT:
            return QString::number(value.uintVal);
        case VT_I8:
            return QString::number(static_cast<qint64>(value.llVal));
        case VT_UI8:
            return QString::number(static_cast<qulonglong>(value.ullVal));
        case VT_BOOL:
            return value.boolVal == VARIANT_TRUE ? QStringLiteral("true") : QStringLiteral("false");
        case VT_NULL:
        case VT_EMPTY:
            return QStringLiteral("<null>");
        default:
            return QString("<vt=%1>").arg(value.vt);
        }
    }

    // 文本匹配辅助：
    // - 支持普通 contains 与正则匹配两种模式；
    // - 支持大小写敏感切换；
    // - pattern 为空时视为“匹配通过”。
    bool textMatch(
        const QString& sourceText,
        const QString& patternText,
        const bool useRegex,
        const Qt::CaseSensitivity caseSensitivity)
    {
        if (patternText.trimmed().isEmpty())
        {
            return true;
        }

        if (!useRegex)
        {
            return sourceText.contains(patternText, caseSensitivity);
        }

        QRegularExpression::PatternOptions options = QRegularExpression::NoPatternOption;
        if (caseSensitivity == Qt::CaseInsensitive)
        {
            options |= QRegularExpression::CaseInsensitiveOption;
        }
        const QRegularExpression regex(patternText, options);
        if (!regex.isValid())
        {
            return false;
        }
        return regex.match(sourceText).hasMatch();
    }

    // 连接 ROOT\\CIMV2。
    bool connectWmi(IWbemServices** serviceOut, QString* errorOut)
    {
        if (serviceOut == nullptr)
        {
            return false;
        }
        *serviceOut = nullptr;

        CComPtr<IWbemLocator> locator;
        const HRESULT createResult = ::CoCreateInstance(
            CLSID_WbemLocator,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            reinterpret_cast<void**>(&locator));

        if (FAILED(createResult) || locator == nullptr)
        {
            if (errorOut != nullptr)
            {
                *errorOut = QString("创建WbemLocator失败:0x%1").arg(static_cast<unsigned long>(createResult), 0, 16);
            }
            return false;
        }

        CComPtr<IWbemServices> service;
        const HRESULT connectResult = locator->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            nullptr,
            nullptr,
            nullptr,
            WBEM_FLAG_CONNECT_USE_MAX_WAIT,
            nullptr,
            nullptr,
            &service);

        if (FAILED(connectResult) || service == nullptr)
        {
            if (errorOut != nullptr)
            {
                *errorOut = QString("连接ROOT\\CIMV2失败:0x%1").arg(static_cast<unsigned long>(connectResult), 0, 16);
            }
            return false;
        }

        const HRESULT blanketResult = ::CoSetProxyBlanket(
            service,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            nullptr,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE);

        if (FAILED(blanketResult))
        {
            if (errorOut != nullptr)
            {
                *errorOut = QString("CoSetProxyBlanket失败:0x%1").arg(static_cast<unsigned long>(blanketResult), 0, 16);
            }
            return false;
        }

        *serviceOut = service.Detach();
        return true;
    }

    // GUID 转文本。
    QString guidToText(const GUID& guidValue)
    {
        wchar_t buffer[64] = {};
        if (::StringFromGUID2(guidValue, buffer, static_cast<int>(std::size(buffer))) <= 0)
        {
            return QStringLiteral("{00000000-0000-0000-0000-000000000000}");
        }
        return QString::fromWCharArray(buffer);
    }

    // 从 "pid/name" 文本里提取 PID。
    bool parsePid(const QString& text, std::uint32_t& pidOut)
    {
        pidOut = 0;
        const QRegularExpression regex(QStringLiteral("(\\d+)"));
        const QRegularExpressionMatch match = regex.match(text);
        if (!match.hasMatch())
        {
            return false;
        }

        bool ok = false;
        const std::uint32_t pid = match.captured(1).toUInt(&ok);
        if (!ok || pid == 0)
        {
            return false;
        }

        pidOut = pid;
        return true;
    }

    // 打开进程详情窗口。
    void openProcessDetail(QWidget* parent, std::uint32_t pid)
    {
        if (pid == 0)
        {
            return;
        }

        ks::process::ProcessRecord record;
        bool ok = ks::process::QueryProcessStaticDetailByPid(pid, record);

        if (!ok)
        {
            std::vector<ks::process::ProcessRecord> list = ks::process::EnumerateProcesses(
                ks::process::ProcessEnumStrategy::Auto);
            const auto foundIt = std::find_if(
                list.begin(),
                list.end(),
                [pid](const ks::process::ProcessRecord& item) {
                    return item.pid == pid;
                });
            if (foundIt != list.end())
            {
                record = *foundIt;
                ok = true;
            }
        }

        if (!ok)
        {
            QMessageBox::warning(parent, QStringLiteral("进程详情"), QStringLiteral("未找到 PID=%1").arg(pid));
            return;
        }

        ProcessDetailWindow* window = new ProcessDetailWindow(record, nullptr);
        window->setAttribute(Qt::WA_DeleteOnClose, true);
        window->show();
        window->raise();
        window->activateWindow();
    }

    // currentSystemTime100ns：
    // - 作用：把当前系统时间读取为 FILETIME 兼容的 100ns 时间戳；
    // - 调用：ETW 监听开始/停止、时间轴实时右边界与兜底时间戳复用；
    // - 返回：自 1601-01-01 UTC 起算的 100ns 单位整数。
    std::uint64_t currentSystemTime100ns()
    {
        FILETIME fileTime{};
        ::GetSystemTimeAsFileTime(&fileTime);

        ULARGE_INTEGER value{};
        value.LowPart = fileTime.dwLowDateTime;
        value.HighPart = fileTime.dwHighDateTime;
        return static_cast<std::uint64_t>(value.QuadPart);
    }

    // 当前时间转 100ns 文本。
    QString now100nsText()
    {
        return QString::number(static_cast<qulonglong>(currentSystemTime100ns()));
    }

    // 文本 GUID 转结构 GUID：支持 "{...}" 或 "..." 两种输入。
    bool parseGuidText(const QString& text, GUID& guidOut)
    {
        QString normalized = text.trimmed();
        if (normalized.isEmpty())
        {
            return false;
        }
        if (!normalized.startsWith('{'))
        {
            normalized = QStringLiteral("{%1}").arg(normalized);
        }

        const std::wstring guidTextWide = normalized.toStdWString();
        HRESULT hr = ::CLSIDFromString(
            const_cast<LPOLESTR>(guidTextWide.c_str()),
            &guidOut);
        return SUCCEEDED(hr);
    }

    // ETW 级别文本映射到 TRACE_LEVEL_*。
    UCHAR etwLevelFromText(const QString& levelText)
    {
        if (levelText.contains(QStringLiteral("Critical"), Qt::CaseInsensitive))
        {
            return TRACE_LEVEL_CRITICAL;
        }
        if (levelText.contains(QStringLiteral("Error"), Qt::CaseInsensitive))
        {
            return TRACE_LEVEL_ERROR;
        }
        if (levelText.contains(QStringLiteral("Warning"), Qt::CaseInsensitive))
        {
            return TRACE_LEVEL_WARNING;
        }
        if (levelText.contains(QStringLiteral("Verbose"), Qt::CaseInsensitive))
        {
            return TRACE_LEVEL_VERBOSE;
        }
        return TRACE_LEVEL_INFORMATION;
    }

    // 关键字掩码解析：支持 "0x..." 与十进制文本。
    ULONGLONG parseKeywordMaskText(const QString& maskText)
    {
        const QString trimmed = maskText.trimmed();
        if (trimmed.isEmpty())
        {
            return 0ULL;
        }

        bool ok = false;
        ULONGLONG mask = 0ULL;
        if (trimmed.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            mask = trimmed.mid(2).toULongLong(&ok, 16);
        }
        else
        {
            mask = trimmed.toULongLong(&ok, 16);
            if (!ok)
            {
                mask = trimmed.toULongLong(&ok, 10);
            }
        }
        return ok ? mask : 0ULL;
    }

    using EtwFilterFieldId = MonitorDock::EtwFilterFieldId;
    using EtwFilterFieldType = MonitorDock::EtwFilterFieldType;
    using EtwStringMatchMode = MonitorDock::EtwStringMatchMode;
    using EtwFilterStage = MonitorDock::EtwFilterStage;

    struct EtwFilterFieldDescriptor
    {
        EtwFilterFieldId fieldId = EtwFilterFieldId::ProviderName;
        const char* key = "";
        const char* label = "";
        const char* placeholder = "";
        EtwFilterFieldType fieldType = EtwFilterFieldType::Text;
        bool requiresDecodedPayload = false;
    };

    constexpr const char* kEtwFilterConfigRelativePath = "config/etw_filter.cfg";
    constexpr const char* kEtwFilterJsonVersionKey = "version";
    constexpr const char* kEtwFilterJsonPreGroupsKey = "pre_groups";
    constexpr const char* kEtwFilterJsonPostGroupsKey = "post_groups";
    constexpr const char* kEtwFilterJsonEnabledKey = "enabled";
    constexpr const char* kEtwFilterJsonStringModeKey = "string_mode";
    constexpr const char* kEtwFilterJsonCaseSensitiveKey = "case_sensitive";
    constexpr const char* kEtwFilterJsonInvertKey = "invert";
    constexpr const char* kEtwFilterJsonDetailVisibleOnlyKey = "detail_visible_only";
    constexpr const char* kEtwFilterJsonDetailAllFieldsKey = "detail_all_fields";
    constexpr const char* kEtwFilterJsonFieldsKey = "fields";
    constexpr const char* kEtwFilterJsonFieldKey = "key";
    constexpr const char* kEtwFilterJsonFieldValue = "value";
    constexpr const char* kEtwFilterJsonProviderCategoriesKey = "provider_categories";
    constexpr const char* kEtwFilterJsonSimplePreKey = "simple_pre";
    constexpr const char* kEtwFilterJsonSimplePostKey = "simple_post";
    constexpr const char* kEtwFilterJsonSimplePidKey = "pid";
    constexpr const char* kEtwFilterJsonSimpleProcessNameKey = "process_name";
    constexpr const char* kEtwFilterJsonSimpleFilePathKey = "file_path";
    constexpr const char* kEtwFilterJsonSimpleEventIdKey = "event_id";
    constexpr const char* kEtwFilterJsonSimpleEventNameKey = "event_name";
    constexpr const char* kEtwFilterJsonSimpleRegistryPathKey = "registry_path";
    constexpr const char* kEtwFilterJsonSimpleNetworkAddressKey = "network_address";
    constexpr const char* kEtwFilterJsonSimpleNetworkPortKey = "network_port";
    constexpr const char* kEtwFilterJsonSimpleStatusKey = "status";
    constexpr const char* kEtwFilterJsonSimpleCustomProviderKey = "custom_provider";
    constexpr const char* kEtwFilterJsonSimpleCustomActionKey = "custom_action";
    constexpr const char* kEtwFilterJsonSimpleProvidersKey = "providers";
    constexpr const char* kEtwFilterJsonSimpleActionsKey = "actions";

    struct EtwPresetProviderDescriptor
    {
        QString categoryText;
        QString providerNameText;
        ULONG legacyKernelEnableFlags = 0;
    };

    constexpr GUID kKswordEtwKernelSessionGuid =
        { 0x0c3225e0, 0x7f4b, 0x4c2a, { 0x96, 0xae, 0x18, 0x23, 0x47, 0x42, 0xe6, 0xca } };
    constexpr GUID kWindowsKernelTraceProviderGuid =
        { 0x9e814aad, 0x3204, 0x11d2, { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };

    const std::vector<EtwPresetProviderDescriptor>& etwPresetProviderDescriptorList()
    {
        static const std::vector<EtwPresetProviderDescriptor> kProviderList{
            { QStringLiteral("进程线程"), QStringLiteral("Microsoft-Windows-Kernel-Process") },
            { QStringLiteral("进程线程"), QStringLiteral("Microsoft-Windows-Kernel-Thread"), EVENT_TRACE_FLAG_THREAD },
            { QStringLiteral("进程线程"), QStringLiteral("Microsoft-Windows-Kernel-Image"), EVENT_TRACE_FLAG_IMAGE_LOAD },
            { QStringLiteral("文件注册表"), QStringLiteral("Microsoft-Windows-Kernel-File") },
            { QStringLiteral("文件注册表"), QStringLiteral("Microsoft-Windows-Kernel-Registry") },
            { QStringLiteral("网络通信"), QStringLiteral("Microsoft-Windows-TCPIP") },
            { QStringLiteral("网络通信"), QStringLiteral("Microsoft-Windows-DNS-Client") },
            { QStringLiteral("网络通信"), QStringLiteral("Microsoft-Windows-Winsock-AFD") },
            { QStringLiteral("安全审计"), QStringLiteral("Microsoft-Windows-Security-Auditing") },
            { QStringLiteral("安全审计"), QStringLiteral("Microsoft-Windows-Windows Defender") },
            { QStringLiteral("脚本管理"), QStringLiteral("Microsoft-Windows-PowerShell") },
            { QStringLiteral("脚本管理"), QStringLiteral("Microsoft-Windows-WMI-Activity") },
            { QStringLiteral("脚本管理"), QStringLiteral("Microsoft-Windows-TaskScheduler") }
        };
        return kProviderList;
    }

    const EtwPresetProviderDescriptor* findEtwPresetProviderDescriptor(const QString& providerNameText)
    {
        const std::vector<EtwPresetProviderDescriptor>& descriptorList = etwPresetProviderDescriptorList();
        const auto found = std::find_if(
            descriptorList.cbegin(),
            descriptorList.cend(),
            [&providerNameText](const EtwPresetProviderDescriptor& descriptor) {
                return descriptor.providerNameText.compare(providerNameText, Qt::CaseInsensitive) == 0;
            });
        return found == descriptorList.cend() ? nullptr : &*found;
    }

    const QStringList& etwSimpleActionList()
    {
        static const QStringList kActionList{
            QStringLiteral("创建/启动"),
            QStringLiteral("打开"),
            QStringLiteral("关闭"),
            QStringLiteral("读取/查询"),
            QStringLiteral("写入/设置"),
            QStringLiteral("删除"),
            QStringLiteral("重命名"),
            QStringLiteral("连接"),
            QStringLiteral("发送"),
            QStringLiteral("接收")
        };
        return kActionList;
    }

    QString etwFilterStageText(const EtwFilterStage stage)
    {
        return stage == EtwFilterStage::Pre
            ? QStringLiteral("前置筛选")
            : QStringLiteral("后置筛选");
    }

    QStringList etwFilterProviderCategoryList()
    {
        return QStringList{
            QStringLiteral("进程线程"),
            QStringLiteral("文件注册表"),
            QStringLiteral("网络通信"),
            QStringLiteral("安全审计"),
            QStringLiteral("脚本管理"),
            QStringLiteral("自定义/其他")
        };
    }

    QString etwInferProviderCategory(const QString& providerNameText)
    {
        const QString lower = providerNameText.toLower();
        if (lower.contains(QStringLiteral("kernel-process"))
            || lower.contains(QStringLiteral("kernel-thread"))
            || lower.contains(QStringLiteral("kernel-image"))
            || lower.contains(QStringLiteral("windows kernel trace")))
        {
            return QStringLiteral("进程线程");
        }
        if (lower.contains(QStringLiteral("kernel-file"))
            || lower.contains(QStringLiteral("kernel-registry")))
        {
            return QStringLiteral("文件注册表");
        }
        if (lower.contains(QStringLiteral("tcpip"))
            || lower.contains(QStringLiteral("dns-client"))
            || lower.contains(QStringLiteral("winsock-afd")))
        {
            return QStringLiteral("网络通信");
        }
        if (lower.contains(QStringLiteral("security-auditing"))
            || lower.contains(QStringLiteral("defender")))
        {
            return QStringLiteral("安全审计");
        }
        if (lower.contains(QStringLiteral("powershell"))
            || lower.contains(QStringLiteral("wmi-activity"))
            || lower.contains(QStringLiteral("taskscheduler")))
        {
            return QStringLiteral("脚本管理");
        }
        return QStringLiteral("自定义/其他");
    }

    // etwTimelineTypeFromCapturedRow：
    // - 作用：把 ETW 捕获行归一化为时间轴控件已支持的颜色/泳道类型；
    // - 处理：优先按 Provider 名细分进程、线程、镜像等事件，再用语义资源类型兜底；
    // - 返回：时间轴点的 typeText，未知时返回“其他”。
    QString etwTimelineTypeFromCapturedRow(const MonitorDock::EtwCapturedEventRow& rowData)
    {
        const QString providerNameText = rowData.providerName.trimmed();
        if (providerNameText.contains(QStringLiteral("Kernel-Process"), Qt::CaseInsensitive))
        {
            return QStringLiteral("进程");
        }
        if (providerNameText.contains(QStringLiteral("Kernel-Thread"), Qt::CaseInsensitive))
        {
            return QStringLiteral("线程");
        }
        if (providerNameText.contains(QStringLiteral("Kernel-Image"), Qt::CaseInsensitive))
        {
            return QStringLiteral("镜像");
        }
        if (providerNameText.contains(QStringLiteral("Kernel-File"), Qt::CaseInsensitive)
            || rowData.resourceTypeText.compare(QStringLiteral("文件"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("文件");
        }
        if (providerNameText.contains(QStringLiteral("Kernel-Registry"), Qt::CaseInsensitive)
            || rowData.resourceTypeText.compare(QStringLiteral("注册表"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("注册表");
        }
        if (providerNameText.contains(QStringLiteral("DNS-Client"), Qt::CaseInsensitive))
        {
            return QStringLiteral("DNS");
        }
        if (providerNameText.contains(QStringLiteral("TCPIP"), Qt::CaseInsensitive)
            || providerNameText.contains(QStringLiteral("AFD"), Qt::CaseInsensitive)
            || providerNameText.contains(QStringLiteral("Winsock"), Qt::CaseInsensitive)
            || rowData.resourceTypeText.compare(QStringLiteral("网络"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("网络");
        }
        if (providerNameText.contains(QStringLiteral("PowerShell"), Qt::CaseInsensitive))
        {
            return QStringLiteral("PowerShell");
        }
        if (providerNameText.contains(QStringLiteral("WMI-Activity"), Qt::CaseInsensitive))
        {
            return QStringLiteral("WMI");
        }
        if (providerNameText.contains(QStringLiteral("TaskScheduler"), Qt::CaseInsensitive))
        {
            return QStringLiteral("计划任务");
        }
        if (providerNameText.contains(QStringLiteral("Security-Auditing"), Qt::CaseInsensitive))
        {
            return QStringLiteral("安全审计");
        }
        if (providerNameText.contains(QStringLiteral("Defender"), Qt::CaseInsensitive))
        {
            return QStringLiteral("Defender");
        }
        if (rowData.providerCategory.compare(QStringLiteral("进程线程"), Qt::CaseInsensitive) == 0
            || rowData.resourceTypeText.compare(QStringLiteral("进程线程"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("进程");
        }
        return QStringLiteral("其他");
    }

    const std::vector<EtwFilterFieldDescriptor>& etwFilterFieldDescriptorList()
    {
        static const std::vector<EtwFilterFieldDescriptor> kFieldList{
            { EtwFilterFieldId::ProviderName, "provider_name", "ProviderName", "Provider 名（支持多值）", EtwFilterFieldType::Text, false },
            { EtwFilterFieldId::ProviderGuid, "provider_guid", "ProviderGuid", "Provider GUID（支持多值）", EtwFilterFieldType::Text, false },
            { EtwFilterFieldId::ProviderCategory, "provider_category", "ProviderCategory", "Provider 分类（支持多值）", EtwFilterFieldType::Text, false },
            { EtwFilterFieldId::EventId, "event_id", "EventId", "事件ID（单值/区间）", EtwFilterFieldType::Number, false },
            { EtwFilterFieldId::EventName, "event_name", "EventName", "事件名（支持多值）", EtwFilterFieldType::Text, false },
            { EtwFilterFieldId::Task, "task", "Task", "Task（数字区间或名称）", EtwFilterFieldType::NumberOrText, false },
            { EtwFilterFieldId::Opcode, "opcode", "Opcode", "Opcode（数字区间或名称）", EtwFilterFieldType::NumberOrText, false },
            { EtwFilterFieldId::Level, "level", "Level", "Level（数字区间或等级名）", EtwFilterFieldType::NumberOrText, false },
            { EtwFilterFieldId::KeywordMask, "keyword_mask", "KeywordMask", "KeywordMask（十六进制/区间）", EtwFilterFieldType::Number, false },
            { EtwFilterFieldId::HeaderPid, "header_pid", "HeaderPID", "发起PID（单值/区间）", EtwFilterFieldType::Number, false },
            { EtwFilterFieldId::HeaderTid, "header_tid", "HeaderTID", "发起TID（单值/区间）", EtwFilterFieldType::Number, false },
            { EtwFilterFieldId::ActivityId, "activity_id", "ActivityId", "ActivityId（支持多值）", EtwFilterFieldType::Text, false },
            { EtwFilterFieldId::TimestampRange, "timestamp", "TimeRange100ns", "100ns 时间戳（单值/区间）", EtwFilterFieldType::TimeRange, false },
            { EtwFilterFieldId::ResourceType, "resource_type", "resourceType", "语义资源类型", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::Action, "action", "action", "语义动作", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::Target, "target", "target", "语义目标", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::Status, "status", "status", "语义状态", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::DetailKeyword, "detail_keyword", "DetailKeyword", "Detail 关键字", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::TargetPid, "target_pid", "TargetPID", "目标PID（ProcessId/TargetProcessId）", EtwFilterFieldType::Number, true },
            { EtwFilterFieldId::ParentPid, "parent_pid", "ParentPID", "父PID（ParentProcessId/PPID）", EtwFilterFieldType::Number, true },
            { EtwFilterFieldId::TargetTid, "target_tid", "TargetTID", "目标TID（ThreadId/TargetThreadId）", EtwFilterFieldType::Number, true },
            { EtwFilterFieldId::ProcessName, "process_name", "ProcessName", "进程名", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::ImagePath, "image_path", "ImagePath", "映像路径", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::CommandLine, "command_line", "CommandLine", "命令行", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::FilePath, "file_path", "FilePath", "文件路径", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::FileOldPath, "file_old_path", "OldPath", "旧路径", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::FileNewPath, "file_new_path", "NewPath", "新路径", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::FileOperation, "file_operation", "FileOperation", "文件操作类型", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::FileStatusCode, "file_status_code", "FileStatusCode", "文件状态码", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::FileAccessMask, "file_access_mask", "FileAccessMask", "文件访问掩码", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::RegistryKeyPath, "registry_key_path", "RegistryKeyPath", "KeyPath", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::RegistryValueName, "registry_value_name", "RegistryValueName", "ValueName", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::RegistryHive, "registry_hive", "RegistryHive", "Hive", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::RegistryOperation, "registry_operation", "RegistryOperation", "注册表操作类型", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::RegistryStatus, "registry_status", "RegistryStatus", "注册表状态码", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::SourceIp, "source_ip", "SourceIP", "源IP（单值/CIDR/范围）", EtwFilterFieldType::Ip, true },
            { EtwFilterFieldId::SourcePort, "source_port", "SourcePort", "源端口（单值/范围）", EtwFilterFieldType::Port, true },
            { EtwFilterFieldId::DestinationIp, "destination_ip", "DestinationIP", "目的IP（单值/CIDR/范围）", EtwFilterFieldType::Ip, true },
            { EtwFilterFieldId::DestinationPort, "destination_port", "DestinationPort", "目的端口（单值/范围）", EtwFilterFieldType::Port, true },
            { EtwFilterFieldId::Protocol, "protocol", "Protocol", "协议", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::Direction, "direction", "Direction", "方向", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::Domain, "domain", "Domain", "域名", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::Host, "host", "Host", "主机名", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::AuditResult, "audit_result", "AuditResult", "审计结果", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::UserText, "user", "User", "用户", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::SidText, "sid", "SID", "SID", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::SecurityPid, "security_pid", "SecurityPID", "安全相关PID（单值/范围）", EtwFilterFieldType::Number, true },
            { EtwFilterFieldId::SecurityTid, "security_tid", "SecurityTID", "安全相关TID（单值/范围）", EtwFilterFieldType::Number, true },
            { EtwFilterFieldId::SecurityLevel, "security_level", "SecurityLevel", "安全事件等级", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::ScriptHostProcess, "script_host", "ScriptHostProcess", "脚本宿主进程", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::ScriptKeyword, "script_keyword", "ScriptKeyword", "脚本关键字", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::ScriptTaskName, "script_task", "ScriptTaskName", "任务名", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::WmiClassName, "wmi_class", "WMIClassName", "WMI 类名", EtwFilterFieldType::Text, true },
            { EtwFilterFieldId::WmiNamespace, "wmi_namespace", "WMINamespace", "WMI 命名空间", EtwFilterFieldType::Text, true }
        };
        return kFieldList;
    }

    const EtwFilterFieldDescriptor* findEtwFilterFieldDescriptorById(const EtwFilterFieldId fieldId)
    {
        const std::vector<EtwFilterFieldDescriptor>& fieldList = etwFilterFieldDescriptorList();
        const auto found = std::find_if(
            fieldList.begin(),
            fieldList.end(),
            [fieldId](const EtwFilterFieldDescriptor& descriptor) {
                return descriptor.fieldId == fieldId;
            });
        return found == fieldList.end() ? nullptr : &(*found);
    }

    const EtwFilterFieldDescriptor* findEtwFilterFieldDescriptorByKey(const QString& keyText)
    {
        const QString normalizedKey = keyText.trimmed().toLower();
        if (normalizedKey.isEmpty())
        {
            return nullptr;
        }

        const std::vector<EtwFilterFieldDescriptor>& fieldList = etwFilterFieldDescriptorList();
        const auto found = std::find_if(
            fieldList.begin(),
            fieldList.end(),
            [&normalizedKey](const EtwFilterFieldDescriptor& descriptor) {
                return QString::fromLatin1(descriptor.key).compare(normalizedKey, Qt::CaseInsensitive) == 0;
            });
        return found == fieldList.end() ? nullptr : &(*found);
    }

    QStringList splitEtwFilterTokens(const QString& inputText)
    {
        static const QRegularExpression separatorRegex(QStringLiteral("[,;\\s]+"));
        return inputText.split(separatorRegex, Qt::SkipEmptyParts);
    }

    bool tryParseUInt64Text(const QString& text, std::uint64_t& valueOut)
    {
        QString trimmed = text.trimmed();
        if (trimmed.isEmpty())
        {
            return false;
        }

        bool parseOk = false;
        std::uint64_t parsedValue = 0;
        if (trimmed.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            parsedValue = trimmed.mid(2).toULongLong(&parseOk, 16);
        }
        else
        {
            parsedValue = trimmed.toULongLong(&parseOk, 10);
            if (!parseOk)
            {
                parsedValue = trimmed.toULongLong(&parseOk, 16);
            }
        }
        if (!parseOk)
        {
            return false;
        }
        valueOut = parsedValue;
        return true;
    }

    bool tryParseUInt64RangeToken(
        const QString& tokenText,
        MonitorDock::EtwFilterNumericRange& rangeOut)
    {
        const QString trimmed = tokenText.trimmed();
        if (trimmed.isEmpty())
        {
            return false;
        }

        const int dashIndex = trimmed.indexOf('-');
        if (dashIndex > 0)
        {
            const QString beginText = trimmed.left(dashIndex).trimmed();
            const QString endText = trimmed.mid(dashIndex + 1).trimmed();
            std::uint64_t beginValue = 0;
            std::uint64_t endValue = 0;
            if (!tryParseUInt64Text(beginText, beginValue) || !tryParseUInt64Text(endText, endValue))
            {
                return false;
            }
            rangeOut.minValue = std::min(beginValue, endValue);
            rangeOut.maxValue = std::max(beginValue, endValue);
            return true;
        }

        std::uint64_t singleValue = 0;
        if (!tryParseUInt64Text(trimmed, singleValue))
        {
            return false;
        }
        rangeOut.minValue = singleValue;
        rangeOut.maxValue = singleValue;
        return true;
    }

    bool tryParsePortRangeToken(
        const QString& tokenText,
        MonitorDock::EtwFilterPortRange& rangeOut)
    {
        MonitorDock::EtwFilterNumericRange numericRange;
        if (!tryParseUInt64RangeToken(tokenText, numericRange))
        {
            return false;
        }
        if (numericRange.minValue > 65535ULL || numericRange.maxValue > 65535ULL)
        {
            return false;
        }
        rangeOut.minValue = static_cast<std::uint16_t>(numericRange.minValue);
        rangeOut.maxValue = static_cast<std::uint16_t>(numericRange.maxValue);
        return true;
    }

    bool tryParseIpv4Text(const QString& text, std::uint32_t& valueOut)
    {
        const QString trimmed = text.trimmed();
        const QStringList partList = trimmed.split('.', Qt::KeepEmptyParts);
        if (partList.size() != 4)
        {
            return false;
        }

        std::uint32_t value = 0;
        for (const QString& partText : partList)
        {
            bool parseOk = false;
            const int partValue = partText.toInt(&parseOk, 10);
            if (!parseOk || partValue < 0 || partValue > 255)
            {
                return false;
            }
            value = (value << 8) | static_cast<std::uint32_t>(partValue);
        }

        valueOut = value;
        return true;
    }

    bool tryParseIpv4RangeToken(
        const QString& tokenText,
        MonitorDock::EtwFilterIpRange& rangeOut)
    {
        const QString trimmed = tokenText.trimmed();
        if (trimmed.isEmpty())
        {
            return false;
        }

        const int slashIndex = trimmed.indexOf('/');
        if (slashIndex > 0)
        {
            const QString ipText = trimmed.left(slashIndex).trimmed();
            const QString maskText = trimmed.mid(slashIndex + 1).trimmed();
            std::uint32_t baseIp = 0;
            if (!tryParseIpv4Text(ipText, baseIp))
            {
                return false;
            }

            bool parseOk = false;
            const int prefixLength = maskText.toInt(&parseOk, 10);
            if (!parseOk || prefixLength < 0 || prefixLength > 32)
            {
                return false;
            }

            const std::uint32_t mask = prefixLength == 0
                ? 0U
                : (prefixLength == 32 ? 0xFFFFFFFFU : (0xFFFFFFFFU << (32 - prefixLength)));
            const std::uint32_t network = baseIp & mask;
            const std::uint32_t broadcast = network | (~mask);
            rangeOut.minValue = std::min(network, broadcast);
            rangeOut.maxValue = std::max(network, broadcast);
            return true;
        }

        const int dashIndex = trimmed.indexOf('-');
        if (dashIndex > 0)
        {
            const QString beginText = trimmed.left(dashIndex).trimmed();
            const QString endText = trimmed.mid(dashIndex + 1).trimmed();
            std::uint32_t beginIp = 0;
            std::uint32_t endIp = 0;
            if (!tryParseIpv4Text(beginText, beginIp) || !tryParseIpv4Text(endText, endIp))
            {
                return false;
            }
            rangeOut.minValue = std::min(beginIp, endIp);
            rangeOut.maxValue = std::max(beginIp, endIp);
            return true;
        }

        std::uint32_t singleIp = 0;
        if (!tryParseIpv4Text(trimmed, singleIp))
        {
            return false;
        }
        rangeOut.minValue = singleIp;
        rangeOut.maxValue = singleIp;
        return true;
    }

    QString etwFilterRegexPatternFromToken(const QString& tokenText, const EtwStringMatchMode mode)
    {
        const QString escapedText = QRegularExpression::escape(tokenText);
        switch (mode)
        {
        case EtwStringMatchMode::Exact:
            return QStringLiteral("^%1$").arg(escapedText);
        case EtwStringMatchMode::Contains:
            return escapedText;
        case EtwStringMatchMode::Prefix:
            return QStringLiteral("^%1").arg(escapedText);
        case EtwStringMatchMode::Suffix:
            return QStringLiteral("%1$").arg(escapedText);
        case EtwStringMatchMode::Regex:
        default:
            return tokenText;
        }
    }

    QString etwFilterStringModeToText(const EtwStringMatchMode mode)
    {
        switch (mode)
        {
        case EtwStringMatchMode::Exact: return QStringLiteral("exact");
        case EtwStringMatchMode::Contains: return QStringLiteral("contains");
        case EtwStringMatchMode::Prefix: return QStringLiteral("prefix");
        case EtwStringMatchMode::Suffix: return QStringLiteral("suffix");
        case EtwStringMatchMode::Regex:
        default:
            return QStringLiteral("regex");
        }
    }

    EtwStringMatchMode etwFilterStringModeFromText(const QString& modeText)
    {
        const QString normalized = modeText.trimmed().toLower();
        if (normalized == QStringLiteral("exact"))
        {
            return EtwStringMatchMode::Exact;
        }
        if (normalized == QStringLiteral("contains"))
        {
            return EtwStringMatchMode::Contains;
        }
        if (normalized == QStringLiteral("prefix"))
        {
            return EtwStringMatchMode::Prefix;
        }
        if (normalized == QStringLiteral("suffix"))
        {
            return EtwStringMatchMode::Suffix;
        }
        return EtwStringMatchMode::Regex;
    }

    QString etwFilterLevelTextFromValue(const int levelValue)
    {
        switch (levelValue)
        {
        case 1: return QStringLiteral("Critical");
        case 2: return QStringLiteral("Error");
        case 3: return QStringLiteral("Warning");
        case 4: return QStringLiteral("Information");
        case 5: return QStringLiteral("Verbose");
        default: return QStringLiteral("Level_%1").arg(levelValue);
        }
    }

    bool etwRegexAnyMatch(
        const QString& valueText,
        const std::vector<QRegularExpression>& regexList)
    {
        if (regexList.empty())
        {
            return true;
        }
        for (const QRegularExpression& regex : regexList)
        {
            if (regex.isValid() && regex.match(valueText).hasMatch())
            {
                return true;
            }
        }
        return false;
    }

    bool etwNumericInRanges(
        const std::uint64_t value,
        const std::vector<MonitorDock::EtwFilterNumericRange>& rangeList)
    {
        if (rangeList.empty())
        {
            return true;
        }
        return std::any_of(
            rangeList.begin(),
            rangeList.end(),
            [value](const MonitorDock::EtwFilterNumericRange& rangeValue) {
                return value >= rangeValue.minValue && value <= rangeValue.maxValue;
            });
    }

    bool etwIpInRanges(
        const std::uint32_t value,
        const std::vector<MonitorDock::EtwFilterIpRange>& rangeList)
    {
        if (rangeList.empty())
        {
            return true;
        }
        return std::any_of(
            rangeList.begin(),
            rangeList.end(),
            [value](const MonitorDock::EtwFilterIpRange& rangeValue) {
                return value >= rangeValue.minValue && value <= rangeValue.maxValue;
            });
    }

    bool etwPortInRanges(
        const std::uint16_t value,
        const std::vector<MonitorDock::EtwFilterPortRange>& rangeList)
    {
        if (rangeList.empty())
        {
            return true;
        }
        return std::any_of(
            rangeList.begin(),
            rangeList.end(),
            [value](const MonitorDock::EtwFilterPortRange& rangeValue) {
                return value >= rangeValue.minValue && value <= rangeValue.maxValue;
            });
    }

    QString etwSingleLineOrEmpty(const QString& valueText)
    {
        QString normalizedText = valueText;
        normalizedText.replace(QChar(u'\r'), QChar(u' '));
        normalizedText.replace(QChar(u'\n'), QChar(u' '));
        return normalizedText.simplified();
    }

    QString etwFieldTextValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        const bool detailVisibleOnly,
        const bool detailAllFields)
    {
        switch (fieldId)
        {
        case MonitorDock::EtwFilterFieldId::ProviderName: return rowData.providerName;
        case MonitorDock::EtwFilterFieldId::ProviderGuid: return rowData.providerGuid;
        case MonitorDock::EtwFilterFieldId::ProviderCategory: return rowData.providerCategory;
        case MonitorDock::EtwFilterFieldId::EventName: return rowData.eventName;
        case MonitorDock::EtwFilterFieldId::Task:
            return rowData.taskName.trimmed().isEmpty()
                ? QString::number(rowData.task)
                : QStringLiteral("%1 (%2)").arg(rowData.taskName, QString::number(rowData.task));
        case MonitorDock::EtwFilterFieldId::Opcode:
            return rowData.opcodeName.trimmed().isEmpty()
                ? QString::number(rowData.opcode)
                : QStringLiteral("%1 (%2)").arg(rowData.opcodeName, QString::number(rowData.opcode));
        case MonitorDock::EtwFilterFieldId::Level:
            return rowData.levelText.trimmed().isEmpty()
                ? QString::number(rowData.level)
                : QStringLiteral("%1 (%2)").arg(rowData.levelText, QString::number(rowData.level));
        case MonitorDock::EtwFilterFieldId::KeywordMask: return rowData.keywordMaskText;
        case MonitorDock::EtwFilterFieldId::ActivityId: return rowData.activityId;
        case MonitorDock::EtwFilterFieldId::ResourceType: return rowData.resourceTypeText;
        case MonitorDock::EtwFilterFieldId::Action: return rowData.actionText;
        case MonitorDock::EtwFilterFieldId::Target: return rowData.targetText;
        case MonitorDock::EtwFilterFieldId::Status: return rowData.statusText;
        case MonitorDock::EtwFilterFieldId::DetailKeyword:
            if (detailVisibleOnly)
            {
                return rowData.detailVisibleText;
            }
            return detailAllFields ? rowData.detailAllText : rowData.detailSummary;
        case MonitorDock::EtwFilterFieldId::ProcessName: return rowData.processNameText;
        case MonitorDock::EtwFilterFieldId::ImagePath: return rowData.imagePathText;
        case MonitorDock::EtwFilterFieldId::CommandLine: return rowData.commandLineText;
        case MonitorDock::EtwFilterFieldId::FilePath: return rowData.filePathText;
        case MonitorDock::EtwFilterFieldId::FileOldPath: return rowData.fileOldPathText;
        case MonitorDock::EtwFilterFieldId::FileNewPath: return rowData.fileNewPathText;
        case MonitorDock::EtwFilterFieldId::FileOperation: return rowData.fileOperationText;
        case MonitorDock::EtwFilterFieldId::FileStatusCode: return rowData.fileStatusCodeText;
        case MonitorDock::EtwFilterFieldId::FileAccessMask: return rowData.fileAccessMaskText;
        case MonitorDock::EtwFilterFieldId::RegistryKeyPath: return rowData.registryKeyPathText;
        case MonitorDock::EtwFilterFieldId::RegistryValueName: return rowData.registryValueNameText;
        case MonitorDock::EtwFilterFieldId::RegistryHive: return rowData.registryHiveText;
        case MonitorDock::EtwFilterFieldId::RegistryOperation: return rowData.registryOperationText;
        case MonitorDock::EtwFilterFieldId::RegistryStatus: return rowData.registryStatusText;
        case MonitorDock::EtwFilterFieldId::SourceIp: return rowData.sourceIpText;
        case MonitorDock::EtwFilterFieldId::DestinationIp: return rowData.destinationIpText;
        case MonitorDock::EtwFilterFieldId::Protocol: return rowData.protocolText;
        case MonitorDock::EtwFilterFieldId::Direction: return rowData.directionText;
        case MonitorDock::EtwFilterFieldId::Domain: return rowData.domainText;
        case MonitorDock::EtwFilterFieldId::Host: return rowData.hostText;
        case MonitorDock::EtwFilterFieldId::AuditResult: return rowData.auditResultText;
        case MonitorDock::EtwFilterFieldId::UserText: return rowData.userText;
        case MonitorDock::EtwFilterFieldId::SidText: return rowData.sidText;
        case MonitorDock::EtwFilterFieldId::SecurityLevel: return rowData.securityLevelText;
        case MonitorDock::EtwFilterFieldId::ScriptHostProcess: return rowData.scriptHostProcessText;
        case MonitorDock::EtwFilterFieldId::ScriptKeyword: return rowData.scriptKeywordText;
        case MonitorDock::EtwFilterFieldId::ScriptTaskName: return rowData.scriptTaskNameText;
        case MonitorDock::EtwFilterFieldId::WmiClassName: return rowData.wmiClassNameText;
        case MonitorDock::EtwFilterFieldId::WmiNamespace: return rowData.wmiNamespaceText;
        default:
            break;
        }
        return QString();
    }

    bool etwFieldNumericValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        std::uint64_t* valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }

        switch (fieldId)
        {
        case MonitorDock::EtwFilterFieldId::EventId:
            *valueOut = static_cast<std::uint64_t>(rowData.eventId);
            return true;
        case MonitorDock::EtwFilterFieldId::Task:
            *valueOut = static_cast<std::uint64_t>(rowData.task);
            return true;
        case MonitorDock::EtwFilterFieldId::Opcode:
            *valueOut = static_cast<std::uint64_t>(rowData.opcode);
            return true;
        case MonitorDock::EtwFilterFieldId::Level:
            *valueOut = static_cast<std::uint64_t>(rowData.level);
            return true;
        case MonitorDock::EtwFilterFieldId::KeywordMask:
            *valueOut = rowData.keywordMaskValue;
            return true;
        case MonitorDock::EtwFilterFieldId::HeaderPid:
            *valueOut = static_cast<std::uint64_t>(rowData.headerPid);
            return true;
        case MonitorDock::EtwFilterFieldId::HeaderTid:
            *valueOut = static_cast<std::uint64_t>(rowData.headerTid);
            return true;
        case MonitorDock::EtwFilterFieldId::TimestampRange:
            *valueOut = rowData.timestampValue;
            return true;
        case MonitorDock::EtwFilterFieldId::TargetPid:
            if (!rowData.targetPidValid)
            {
                return false;
            }
            *valueOut = static_cast<std::uint64_t>(rowData.targetPid);
            return true;
        case MonitorDock::EtwFilterFieldId::ParentPid:
            if (!rowData.parentPidValid)
            {
                return false;
            }
            *valueOut = static_cast<std::uint64_t>(rowData.parentPid);
            return true;
        case MonitorDock::EtwFilterFieldId::TargetTid:
            if (!rowData.targetTidValid)
            {
                return false;
            }
            *valueOut = static_cast<std::uint64_t>(rowData.targetTid);
            return true;
        case MonitorDock::EtwFilterFieldId::SecurityPid:
            if (!rowData.securityPidValid)
            {
                return false;
            }
            *valueOut = static_cast<std::uint64_t>(rowData.securityPid);
            return true;
        case MonitorDock::EtwFilterFieldId::SecurityTid:
            if (!rowData.securityTidValid)
            {
                return false;
            }
            *valueOut = static_cast<std::uint64_t>(rowData.securityTid);
            return true;
        default:
            break;
        }

        return false;
    }

    bool etwFieldIpValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        std::uint32_t* valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }
        if (fieldId == MonitorDock::EtwFilterFieldId::SourceIp && rowData.sourceIpValid)
        {
            *valueOut = rowData.sourceIpValue;
            return true;
        }
        if (fieldId == MonitorDock::EtwFilterFieldId::DestinationIp && rowData.destinationIpValid)
        {
            *valueOut = rowData.destinationIpValue;
            return true;
        }
        return false;
    }

    bool etwFieldPortValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        std::uint16_t* valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }
        if (fieldId == MonitorDock::EtwFilterFieldId::SourcePort && rowData.sourcePortValid)
        {
            *valueOut = rowData.sourcePort;
            return true;
        }
        if (fieldId == MonitorDock::EtwFilterFieldId::DestinationPort && rowData.destinationPortValid)
        {
            *valueOut = rowData.destinationPort;
            return true;
        }
        return false;
    }

    bool etwFilterFieldMatches(
        const MonitorDock::EtwFilterRuleFieldCompiled& fieldRule,
        const MonitorDock::EtwCapturedEventRow& rowData,
        const bool detailVisibleOnly,
        const bool detailAllFields)
    {
        if (fieldRule.fieldType == MonitorDock::EtwFilterFieldType::Ip)
        {
            std::uint32_t value = 0;
            if (!etwFieldIpValue(rowData, fieldRule.fieldId, &value))
            {
                return false;
            }
            return etwIpInRanges(value, fieldRule.ipRangeList);
        }

        if (fieldRule.fieldType == MonitorDock::EtwFilterFieldType::Port)
        {
            std::uint16_t value = 0;
            if (!etwFieldPortValue(rowData, fieldRule.fieldId, &value))
            {
                return false;
            }
            return etwPortInRanges(value, fieldRule.portRangeList);
        }

        if (fieldRule.fieldType == MonitorDock::EtwFilterFieldType::Number
            || fieldRule.fieldType == MonitorDock::EtwFilterFieldType::TimeRange)
        {
            std::uint64_t numericValue = 0;
            if (!etwFieldNumericValue(rowData, fieldRule.fieldId, &numericValue))
            {
                return false;
            }
            return etwNumericInRanges(numericValue, fieldRule.numericRangeList);
        }

        if (fieldRule.fieldType == MonitorDock::EtwFilterFieldType::NumberOrText)
        {
            bool numericMatched = false;
            bool numericChecked = false;
            if (!fieldRule.numericRangeList.empty())
            {
                numericChecked = true;
                std::uint64_t numericValue = 0;
                if (etwFieldNumericValue(rowData, fieldRule.fieldId, &numericValue))
                {
                    numericMatched = etwNumericInRanges(numericValue, fieldRule.numericRangeList);
                }
            }

            bool textMatched = false;
            bool textChecked = false;
            if (!fieldRule.regexRuleList.empty())
            {
                textChecked = true;
                const QString textValue = etwFieldTextValue(
                    rowData,
                    fieldRule.fieldId,
                    detailVisibleOnly,
                    detailAllFields);
                textMatched = etwRegexAnyMatch(textValue, fieldRule.regexRuleList);
            }

            if (numericChecked && textChecked)
            {
                return numericMatched || textMatched;
            }
            if (numericChecked)
            {
                return numericMatched;
            }
            if (textChecked)
            {
                return textMatched;
            }
            return true;
        }

        const QString textValue = etwFieldTextValue(
            rowData,
            fieldRule.fieldId,
            detailVisibleOnly,
            detailAllFields);
        return etwRegexAnyMatch(textValue, fieldRule.regexRuleList);
    }

    bool etwFilterGroupMatches(
        const MonitorDock::EtwFilterRuleGroupCompiled& groupRule,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        bool matched = true;
        for (const MonitorDock::EtwFilterRuleFieldCompiled& fieldRule : groupRule.fieldList)
        {
            if (!etwFilterFieldMatches(
                fieldRule,
                rowData,
                groupRule.detailVisibleColumnsOnly,
                groupRule.detailMatchAllFields))
            {
                matched = false;
                break;
            }
        }

        if (groupRule.invertMatch)
        {
            matched = !matched;
        }
        return matched;
    }

    QStringList splitEtwSimpleFilterTokens(const QString& inputText)
    {
        static const QRegularExpression separatorRegex(QStringLiteral("[,;]+"));
        QStringList result;
        for (const QString& tokenText : inputText.split(separatorRegex, Qt::SkipEmptyParts))
        {
            const QString trimmed = tokenText.trimmed();
            if (!trimmed.isEmpty())
            {
                result.push_back(trimmed);
            }
        }
        return result;
    }

    bool etwTextContainsAnyToken(const QString& valueText, const QStringList& tokenList)
    {
        if (tokenList.isEmpty())
        {
            return true;
        }
        return std::any_of(
            tokenList.begin(),
            tokenList.end(),
            [&valueText](const QString& tokenText) {
                return valueText.contains(tokenText, Qt::CaseInsensitive);
            });
    }

    bool etwAnyTextValueContainsAnyToken(
        const std::initializer_list<const QString*> valueList,
        const QStringList& tokenList)
    {
        if (tokenList.isEmpty())
        {
            return true;
        }
        for (const QString& tokenText : tokenList)
        {
            for (const QString* valuePointer : valueList)
            {
                if (valuePointer != nullptr
                    && valuePointer->contains(tokenText, Qt::CaseInsensitive))
                {
                    return true;
                }
            }
        }
        return false;
    }

    bool etwSimpleProviderMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        if (simpleFilter.providerPresetNameList.isEmpty()
            && simpleFilter.providerCustomTokenList.isEmpty())
        {
            return true;
        }

        for (const QString& presetName : simpleFilter.providerPresetNameList)
        {
            if (rowData.providerName.compare(presetName, Qt::CaseInsensitive) == 0)
            {
                return true;
            }
        }
        if (simpleFilter.providerCustomTokenList.isEmpty())
        {
            return false;
        }
        return etwAnyTextValueContainsAnyToken(
            { &rowData.providerName, &rowData.providerGuid },
            simpleFilter.providerCustomTokenList);
    }

    bool etwSimplePidMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        if (simpleFilter.pidRangeList.empty())
        {
            return true;
        }
        if (etwNumericInRanges(rowData.headerPid, simpleFilter.pidRangeList))
        {
            return true;
        }
        return (rowData.targetPidValid && etwNumericInRanges(rowData.targetPid, simpleFilter.pidRangeList))
            || (rowData.parentPidValid && etwNumericInRanges(rowData.parentPid, simpleFilter.pidRangeList))
            || (rowData.securityPidValid && etwNumericInRanges(rowData.securityPid, simpleFilter.pidRangeList));
    }

    bool etwSimpleFilterMatchesHeaderFields(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData,
        bool* decodedPayloadRequiredOut)
    {
        if (decodedPayloadRequiredOut != nullptr)
        {
            *decodedPayloadRequiredOut = false;
        }
        if (!simpleFilter.hasAnyCondition())
        {
            return true;
        }
        if (!etwSimpleProviderMatches(simpleFilter, rowData))
        {
            return false;
        }
        if (!simpleFilter.eventIdRangeList.empty()
            && !etwNumericInRanges(static_cast<std::uint64_t>(rowData.eventId), simpleFilter.eventIdRangeList))
        {
            return false;
        }
        if (!etwTextContainsAnyToken(rowData.eventName, simpleFilter.eventNameTokenList))
        {
            return false;
        }

        bool decodedPayloadRequired = false;
        if (!simpleFilter.pidRangeList.empty()
            && !etwNumericInRanges(rowData.headerPid, simpleFilter.pidRangeList))
        {
            decodedPayloadRequired = true;
        }
        decodedPayloadRequired = decodedPayloadRequired
            || !simpleFilter.networkAddressRangeList.empty()
            || !simpleFilter.networkPortRangeList.empty()
            || !simpleFilter.actionPresetList.empty()
            || !simpleFilter.actionCustomTokenList.empty()
            || !simpleFilter.processNameTokenList.empty()
            || !simpleFilter.filePathTokenList.empty()
            || !simpleFilter.registryPathTokenList.empty()
            || !simpleFilter.statusTokenList.empty();
        if (decodedPayloadRequiredOut != nullptr)
        {
            *decodedPayloadRequiredOut = decodedPayloadRequired;
        }
        return true;
    }

    bool etwSimpleFilterMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        if (!simpleFilter.hasAnyCondition())
        {
            return true;
        }
        if (!etwSimpleProviderMatches(simpleFilter, rowData)
            || (!simpleFilter.eventIdRangeList.empty()
                && !etwNumericInRanges(
                    static_cast<std::uint64_t>(rowData.eventId),
                    simpleFilter.eventIdRangeList))
            || !etwTextContainsAnyToken(rowData.eventName, simpleFilter.eventNameTokenList)
            || !etwSimplePidMatches(simpleFilter, rowData)
            || !etwTextContainsAnyToken(rowData.processNameText, simpleFilter.processNameTokenList)
            || !etwAnyTextValueContainsAnyToken(
                { &rowData.filePathText, &rowData.fileOldPathText, &rowData.fileNewPathText },
                simpleFilter.filePathTokenList)
            || !etwAnyTextValueContainsAnyToken(
                { &rowData.registryKeyPathText, &rowData.registryValueNameText },
                simpleFilter.registryPathTokenList)
            || !etwAnyTextValueContainsAnyToken(
                { &rowData.statusText, &rowData.fileStatusCodeText, &rowData.registryStatusText,
                  &rowData.auditResultText },
                simpleFilter.statusTokenList))
        {
            return false;
        }

        if (!simpleFilter.networkAddressRangeList.empty())
        {
            const bool addressMatched = (rowData.sourceIpValid
                    && etwIpInRanges(rowData.sourceIpValue, simpleFilter.networkAddressRangeList))
                || (rowData.destinationIpValid
                    && etwIpInRanges(rowData.destinationIpValue, simpleFilter.networkAddressRangeList));
            if (!addressMatched)
            {
                return false;
            }
        }
        if (!simpleFilter.networkPortRangeList.empty())
        {
            const bool portMatched = (rowData.sourcePortValid
                    && etwPortInRanges(rowData.sourcePort, simpleFilter.networkPortRangeList))
                || (rowData.destinationPortValid
                    && etwPortInRanges(rowData.destinationPort, simpleFilter.networkPortRangeList));
            if (!portMatched)
            {
                return false;
            }
        }

        if (!simpleFilter.actionPresetList.isEmpty()
            || !simpleFilter.actionCustomTokenList.isEmpty())
        {
            bool actionMatched = false;
            for (const QString& actionText : simpleFilter.actionPresetList)
            {
                if (rowData.actionText.compare(actionText, Qt::CaseInsensitive) == 0)
                {
                    actionMatched = true;
                    break;
                }
            }
            if (!actionMatched && !simpleFilter.actionCustomTokenList.isEmpty())
            {
                actionMatched = etwTextContainsAnyToken(
                    rowData.actionText,
                    simpleFilter.actionCustomTokenList);
            }
            if (!actionMatched)
            {
                return false;
            }
        }
        return true;
    }

    bool etwDetailedFilterMatches(
        const std::vector<MonitorDock::EtwFilterRuleGroupCompiled>& groupList,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        if (groupList.empty())
        {
            return true;
        }
        return std::any_of(
            groupList.begin(),
            groupList.end(),
            [&rowData](const MonitorDock::EtwFilterRuleGroupCompiled& groupRule) {
                return etwFilterGroupMatches(groupRule, rowData);
            });
    }

    bool etwFilterStageMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const std::vector<MonitorDock::EtwFilterRuleGroupCompiled>& detailedGroupList,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        return etwSimpleFilterMatches(simpleFilter, rowData)
            && etwDetailedFilterMatches(detailedGroupList, rowData);
    }

    // EtwSchemaPropertyEntry：
    // - 作用：缓存一个 ETW 顶层属性的类型、长度策略和语义说明；
    // - 调用：首次命中某个事件类型时由 TDH 构建一次，后续直接复用。
    struct EtwSchemaPropertyEntry
    {
        ULONG propertyIndex = 0;               // propertyIndex：属性索引，供 ParamLength/ParamCount 引用。
        QString propertyNameText;              // propertyNameText：原始属性名。
        QString normalizedNameText;            // normalizedNameText：归一化属性名（仅字母数字小写）。
        QString meaningText;                   // meaningText：常见属性的人类语义。
        USHORT inType = TDH_INTYPE_NULL;       // inType：TDH 输入类型。
        USHORT outType = TDH_OUTTYPE_NULL;     // outType：TDH 输出类型。
        USHORT fixedLength = 0;                // fixedLength：属性固定长度（若有）。
        USHORT fixedCount = 0;                 // fixedCount：属性固定数组数量（若有）。
        ULONG flags = 0;                       // flags：PropertyFlags 位集合。
        bool isStruct = false;                 // isStruct：是否结构体属性。
        bool useLengthProperty = false;        // useLengthProperty：长度是否来自前置属性。
        bool useCountProperty = false;         // useCountProperty：计数是否来自前置属性。
        ULONG lengthPropertyIndex = 0;         // lengthPropertyIndex：长度来源属性索引。
        ULONG countPropertyIndex = 0;          // countPropertyIndex：数量来源属性索引。
    };

    // EtwSchemaEntry：
    // - 作用：缓存“Provider + EventId + Version + Task + Opcode”对应的事件元数据；
    // - 调用：ETW 回调里先查该缓存，命中后不再重复调用 TdhGetEventInformation。
    struct EtwSchemaEntry
    {
        QString cacheKeyText;                               // cacheKeyText：事件类型缓存键。
        QString eventNameText;                              // eventNameText：事件名。
        QString taskNameText;                               // taskNameText：任务名。
        QString opcodeNameText;                             // opcodeNameText：操作码名。
        std::vector<EtwSchemaPropertyEntry> propertyList;   // propertyList：顶层属性布局与语义缓存。
    };

    // EtwDecodedPropertyEntry：
    // - 作用：保存单条事件中某个属性的解码结果；
    // - 调用：用于构造“事件数据(JSON)”和“查看返回详情”窗口内容。
    struct EtwDecodedPropertyEntry
    {
        QString propertyNameText;              // propertyNameText：属性名。
        QString normalizedNameText;            // normalizedNameText：归一化属性名。
        QString meaningText;                   // meaningText：属性语义。
        QString inTypeText;                    // inTypeText：类型文本。
        QString valueText;                     // valueText：可读值。
        QString hexPreviewText;                // hexPreviewText：原始字节十六进制预览。
        ULONG beginOffset = 0;                 // beginOffset：属性起始偏移（相对 UserData）。
        ULONG endOffset = 0;                   // endOffset：属性结束偏移（不含）。
        bool numericAvailable = false;         // numericAvailable：是否解析出数值。
        std::uint64_t numericValue = 0;        // numericValue：数值形式，供长度引用/语义分析。
        bool parseFallback = false;            // parseFallback：是否走了兜底解析。
    };

    // EtwSemanticSummary：
    // - 作用：聚合“资源类型 / 动作 / 目标 / 状态”等常见语义信息；
    // - 调用：展示在 ETW 详情 JSON 顶层，便于快速阅读。
    struct EtwSemanticSummary
    {
        QString resourceTypeText;              // resourceTypeText：资源类型（文件/注册表/网络等）。
        QString actionText;                    // actionText：行为动作（打开/创建/删除等）。
        QString targetText;                    // targetText：目标对象（路径/键名/端点等）。
        QString statusText;                    // statusText：状态码或结果文本。
    };

    // ETW schema 全局缓存：
    // - 作用：避免每条事件都重复调用 TdhGetEventInformation；
    // - 生命周期：开始监听时主动清空，后续按事件类型懒加载。
    std::mutex g_etwSchemaCacheMutex;
    std::unordered_map<std::string, EtwSchemaEntry> g_etwSchemaCacheByKey;

    // normalizeEtwPropertyName：
    // - 作用：把属性名归一化为小写字母数字，便于做跨 Provider 的启发式匹配。
    QString normalizeEtwPropertyName(const QString& propertyNameText)
    {
        QString normalizedText;
        normalizedText.reserve(propertyNameText.size());
        for (const QChar currentChar : propertyNameText.toLower())
        {
            if (currentChar.isLetterOrNumber())
            {
                normalizedText.push_back(currentChar);
            }
        }
        return normalizedText;
    }

    // etwPropertyMeaningText：
    // - 作用：给常见属性名提供中文语义说明；
    // - 调用：构建 schema 时写入缓存，避免后续重复判断。
    QString etwPropertyMeaningText(const QString& normalizedNameText)
    {
        static const std::unordered_map<std::string, QString> kMeaningMap{
            {"processid", QStringLiteral("进程ID")},
            {"threadid", QStringLiteral("线程ID")},
            {"parentprocessid", QStringLiteral("父进程ID")},
            {"imagename", QStringLiteral("映像路径")},
            {"imagefilename", QStringLiteral("映像文件")},
            {"commandline", QStringLiteral("命令行")},
            {"processname", QStringLiteral("进程名称")},
            {"pid", QStringLiteral("进程ID")},
            {"parentid", QStringLiteral("父进程ID")},
            {"filename", QStringLiteral("文件路径")},
            {"filepath", QStringLiteral("文件路径")},
            {"pathname", QStringLiteral("路径")},
            {"targetfilename", QStringLiteral("目标文件路径")},
            {"targetname", QStringLiteral("目标名称")},
            {"relativefilename", QStringLiteral("相对文件名")},
            {"oldfilename", QStringLiteral("源文件路径")},
            {"newfilename", QStringLiteral("新文件路径")},
            {"fileobject", QStringLiteral("文件对象指针")},
            {"keyname", QStringLiteral("注册表键路径")},
            {"keypath", QStringLiteral("注册表键路径")},
            {"hive", QStringLiteral("注册表根键")},
            {"valuename", QStringLiteral("注册表值名称")},
            {"objectname", QStringLiteral("对象路径")},
            {"path", QStringLiteral("对象路径")},
            {"operation", QStringLiteral("操作类型")},
            {"disposition", QStringLiteral("处置结果")},
            {"desiredaccess", QStringLiteral("目标访问权限")},
            {"shareaccess", QStringLiteral("共享访问权限")},
            {"status", QStringLiteral("状态码")},
            {"ntstatus", QStringLiteral("NT状态码")},
            {"result", QStringLiteral("结果码")},
            {"opcode", QStringLiteral("操作码")},
            {"informationclass", QStringLiteral("信息类")},
            {"hostname", QStringLiteral("主机名")},
            {"url", QStringLiteral("URL")},
            {"domainname", QStringLiteral("域名")},
            {"daddr", QStringLiteral("目标IP")},
            {"saddr", QStringLiteral("源IP")},
            {"dport", QStringLiteral("目标端口")},
            {"sport", QStringLiteral("源端口")}
        };

        const auto found = kMeaningMap.find(normalizedNameText.toStdString());
        if (found == kMeaningMap.end())
        {
            return QString();
        }
        return found->second;
    }

    // etwTypeText：
    // - 作用：把 TDH InType 转成可读类型名；
    // - 调用：在 JSON 中输出每个属性的类型说明。
    QString etwTypeText(const USHORT inTypeValue)
    {
        switch (inTypeValue)
        {
        case TDH_INTYPE_UNICODESTRING: return QStringLiteral("UnicodeString");
        case TDH_INTYPE_ANSISTRING: return QStringLiteral("AnsiString");
        case TDH_INTYPE_INT8: return QStringLiteral("Int8");
        case TDH_INTYPE_UINT8: return QStringLiteral("UInt8");
        case TDH_INTYPE_INT16: return QStringLiteral("Int16");
        case TDH_INTYPE_UINT16: return QStringLiteral("UInt16");
        case TDH_INTYPE_INT32: return QStringLiteral("Int32");
        case TDH_INTYPE_UINT32: return QStringLiteral("UInt32");
        case TDH_INTYPE_HEXINT32: return QStringLiteral("HexInt32");
        case TDH_INTYPE_INT64: return QStringLiteral("Int64");
        case TDH_INTYPE_UINT64: return QStringLiteral("UInt64");
        case TDH_INTYPE_HEXINT64: return QStringLiteral("HexInt64");
        case TDH_INTYPE_FLOAT: return QStringLiteral("Float32");
        case TDH_INTYPE_DOUBLE: return QStringLiteral("Float64");
        case TDH_INTYPE_BOOLEAN: return QStringLiteral("Boolean");
        case TDH_INTYPE_BINARY: return QStringLiteral("Binary");
        case TDH_INTYPE_GUID: return QStringLiteral("Guid");
        case TDH_INTYPE_POINTER: return QStringLiteral("Pointer");
        case TDH_INTYPE_FILETIME: return QStringLiteral("FileTime");
        case TDH_INTYPE_SYSTEMTIME: return QStringLiteral("SystemTime");
        case TDH_INTYPE_SID: return QStringLiteral("Sid");
        case TDH_INTYPE_HEXDUMP: return QStringLiteral("HexDump");
        default: return QStringLiteral("Type_%1").arg(static_cast<int>(inTypeValue));
        }
    }

    // etwTextAtOffset：
    // - 作用：读取 TRACE_EVENT_INFO 中按偏移保存的 UTF-16 文本；
    // - 调用：解析事件名、任务名、操作码名与属性名。
    QString etwTextAtOffset(const unsigned char* infoBufferPointer, const ULONG offsetValue)
    {
        if (infoBufferPointer == nullptr || offsetValue == 0)
        {
            return QString();
        }

        const wchar_t* textPointer = reinterpret_cast<const wchar_t*>(infoBufferPointer + offsetValue);
        if (textPointer == nullptr || *textPointer == L'\0')
        {
            return QString();
        }
        return QString::fromWCharArray(textPointer).trimmed();
    }

    // etwHexPreview：
    // - 作用：把字节缓冲格式化成单行十六进制预览；
    // - 调用：属性无法完全解析时输出原始字节摘要。
    QString etwHexPreview(const unsigned char* dataPointer, const ULONG dataSize, const ULONG maxBytes = 64)
    {
        if (dataPointer == nullptr || dataSize == 0)
        {
            return QStringLiteral("<empty>");
        }

        const ULONG visibleBytes = std::min(dataSize, maxBytes);
        QStringList byteTextList;
        byteTextList.reserve(static_cast<int>(visibleBytes));
        for (ULONG indexValue = 0; indexValue < visibleBytes; ++indexValue)
        {
            byteTextList << QStringLiteral("%1").arg(dataPointer[indexValue], 2, 16, QChar(u'0')).toUpper();
        }

        QString previewText = byteTextList.join(' ');
        if (dataSize > visibleBytes)
        {
            previewText += QStringLiteral(" ... (%1 bytes)").arg(dataSize);
        }
        return previewText;
    }

    // etwHexDump：
    // - 作用：把字节缓冲格式化为多行十六进制查看器文本；
    // - 调用：未知字段和尾部未解析字节的兜底展示。
    QString etwHexDump(const unsigned char* dataPointer, const ULONG dataSize, const ULONG maxBytes = 512)
    {
        if (dataPointer == nullptr || dataSize == 0)
        {
            return QStringLiteral("<empty>");
        }

        const ULONG visibleBytes = std::min(dataSize, maxBytes);
        QStringList lineList;
        for (ULONG offsetValue = 0; offsetValue < visibleBytes; offsetValue += 16)
        {
            const ULONG lineBytes = std::min<ULONG>(16, visibleBytes - offsetValue);
            QStringList hexCellList;
            hexCellList.reserve(16);

            QString asciiText;
            asciiText.reserve(16);
            for (ULONG columnIndex = 0; columnIndex < lineBytes; ++columnIndex)
            {
                const unsigned char byteValue = dataPointer[offsetValue + columnIndex];
                hexCellList << QStringLiteral("%1").arg(byteValue, 2, 16, QChar(u'0')).toUpper();
                asciiText.push_back((byteValue >= 32 && byteValue <= 126) ? QChar(byteValue) : QChar(u'.'));
            }
            for (ULONG columnIndex = lineBytes; columnIndex < 16; ++columnIndex)
            {
                hexCellList << QStringLiteral("  ");
                asciiText.push_back(QChar(u' '));
            }

            lineList << QStringLiteral("%1  %2  |%3|")
                .arg(offsetValue, 4, 16, QChar(u'0'))
                .arg(hexCellList.join(' '))
                .arg(asciiText);
        }

        if (dataSize > visibleBytes)
        {
            lineList << QStringLiteral("... 已截断，原始长度=%1 bytes，展示=%2 bytes")
                .arg(dataSize)
                .arg(visibleBytes);
        }

        return lineList.join('\n');
    }

    // etwSchemaKeyFromRecord：
    // - 作用：生成事件类型缓存键；
    // - 组成：ProviderGuid + EventId + Version + Task + Opcode。
    std::string etwSchemaKeyFromRecord(const EVENT_RECORD* eventRecord)
    {
        if (eventRecord == nullptr)
        {
            return std::string();
        }

        const QString keyText = QStringLiteral("%1|%2|%3|%4|%5")
            .arg(guidToText(eventRecord->EventHeader.ProviderId))
            .arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Id))
            .arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Version))
            .arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Task))
            .arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Opcode));
        return keyText.toStdString();
    }

    // clearEtwSchemaCache：
    // - 作用：清空 ETW schema 缓存；
    // - 调用：每轮开始监听前调用一次，保证缓存与本轮会话一致。
    void clearEtwSchemaCache()
    {
        std::lock_guard<std::mutex> lock(g_etwSchemaCacheMutex);
        g_etwSchemaCacheByKey.clear();
    }

    // tryBuildEtwSchemaByTdh：
    // - 作用：用 TDH 构建单个事件类型的 schema；
    // - 调用：仅在缓存未命中时触发，避免每条事件重复查询。
    bool tryBuildEtwSchemaByTdh(const EVENT_RECORD* eventRecord, EtwSchemaEntry* schemaOut)
    {
        if (eventRecord == nullptr || schemaOut == nullptr)
        {
            return false;
        }

        DWORD infoBufferSize = 0;
        ULONG status = ::TdhGetEventInformation(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            nullptr,
            &infoBufferSize);
        if (status != ERROR_INSUFFICIENT_BUFFER || infoBufferSize == 0)
        {
            return false;
        }

        std::vector<unsigned char> infoBuffer(infoBufferSize, 0);
        auto* eventInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
        status = ::TdhGetEventInformation(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            eventInfo,
            &infoBufferSize);
        if (status != ERROR_SUCCESS || eventInfo == nullptr)
        {
            return false;
        }

        EtwSchemaEntry localSchema;
        const unsigned char* rawInfoBuffer = reinterpret_cast<const unsigned char*>(eventInfo);
        localSchema.cacheKeyText = QString::fromStdString(etwSchemaKeyFromRecord(eventRecord));
        localSchema.eventNameText = etwTextAtOffset(rawInfoBuffer, eventInfo->EventNameOffset);
        localSchema.taskNameText = etwTextAtOffset(rawInfoBuffer, eventInfo->TaskNameOffset);
        localSchema.opcodeNameText = etwTextAtOffset(rawInfoBuffer, eventInfo->OpcodeNameOffset);

        localSchema.propertyList.reserve(eventInfo->TopLevelPropertyCount);
        for (ULONG propertyIndex = 0; propertyIndex < eventInfo->TopLevelPropertyCount; ++propertyIndex)
        {
            const EVENT_PROPERTY_INFO& propertyInfo = eventInfo->EventPropertyInfoArray[propertyIndex];

            EtwSchemaPropertyEntry propertyEntry;
            propertyEntry.propertyIndex = propertyIndex;
            propertyEntry.propertyNameText = etwTextAtOffset(rawInfoBuffer, propertyInfo.NameOffset);
            if (propertyEntry.propertyNameText.isEmpty())
            {
                propertyEntry.propertyNameText = QStringLiteral("Property_%1").arg(propertyIndex);
            }
            propertyEntry.normalizedNameText = normalizeEtwPropertyName(propertyEntry.propertyNameText);
            propertyEntry.meaningText = etwPropertyMeaningText(propertyEntry.normalizedNameText);
            propertyEntry.flags = static_cast<ULONG>(propertyInfo.Flags);
            propertyEntry.isStruct = (propertyInfo.Flags & PropertyStruct) != 0;

            if (!propertyEntry.isStruct)
            {
                propertyEntry.inType = propertyInfo.nonStructType.InType;
                propertyEntry.outType = propertyInfo.nonStructType.OutType;
                propertyEntry.fixedLength = propertyInfo.length;
                propertyEntry.fixedCount = propertyInfo.count;
                propertyEntry.useLengthProperty = (propertyInfo.Flags & PropertyParamLength) != 0;
                propertyEntry.useCountProperty = (propertyInfo.Flags & PropertyParamCount) != 0;
                if (propertyEntry.useLengthProperty)
                {
                    propertyEntry.lengthPropertyIndex = propertyInfo.lengthPropertyIndex;
                }
                if (propertyEntry.useCountProperty)
                {
                    propertyEntry.countPropertyIndex = propertyInfo.countPropertyIndex;
                }
            }

            localSchema.propertyList.push_back(std::move(propertyEntry));
        }

        *schemaOut = std::move(localSchema);
        return true;
    }

    // tryGetEtwSchemaCached：
    // - 作用：优先从缓存拿 schema，未命中时仅构建一次并写回缓存；
    // - 调用：每条事件回调入口会调用，但 TDH 查询仅发生在首次命中。
    bool tryGetEtwSchemaCached(const EVENT_RECORD* eventRecord, EtwSchemaEntry* schemaOut)
    {
        if (eventRecord == nullptr || schemaOut == nullptr)
        {
            return false;
        }

        const std::string cacheKey = etwSchemaKeyFromRecord(eventRecord);
        if (cacheKey.empty())
        {
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(g_etwSchemaCacheMutex);
            const auto found = g_etwSchemaCacheByKey.find(cacheKey);
            if (found != g_etwSchemaCacheByKey.end())
            {
                *schemaOut = found->second;
                return true;
            }
        }

        EtwSchemaEntry builtSchema;
        if (!tryBuildEtwSchemaByTdh(eventRecord, &builtSchema))
        {
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(g_etwSchemaCacheMutex);
            auto [iter, inserted] = g_etwSchemaCacheByKey.emplace(cacheKey, builtSchema);
            if (!inserted)
            {
                iter->second = builtSchema;
            }
            *schemaOut = iter->second;
        }
        return true;
    }

    // etwReadScalar：
    // - 作用：从字节缓冲中安全读取固定宽度标量；
    // - 调用：属性数值解码与长度参数读取。
    template <typename TValue>
    bool etwReadScalar(const unsigned char* dataPointer, const ULONG dataSize, TValue* valueOut)
    {
        if (dataPointer == nullptr || valueOut == nullptr || dataSize < sizeof(TValue))
        {
            return false;
        }

        TValue localValue{};
        std::memcpy(&localValue, dataPointer, sizeof(TValue));
        *valueOut = localValue;
        return true;
    }

    // etwPointerSizeByHeader：
    // - 作用：根据事件头位宽标记推导指针长度；
    // - 调用：Pointer 类型属性解码。
    ULONG etwPointerSizeByHeader(const EVENT_RECORD* eventRecord)
    {
        if (eventRecord == nullptr)
        {
            return static_cast<ULONG>(sizeof(void*));
        }
        return (eventRecord->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0 ? 4UL : 8UL;
    }

    // etwFixedTypeSize：
    // - 作用：返回常见 InType 的固定字节长度；
    // - 返回 0 表示“可变长度或未知长度”。
    ULONG etwFixedTypeSize(const USHORT inTypeValue, const ULONG pointerSize)
    {
        switch (inTypeValue)
        {
        case TDH_INTYPE_INT8:
        case TDH_INTYPE_UINT8:
        case TDH_INTYPE_ANSICHAR:
            return 1;
        case TDH_INTYPE_INT16:
        case TDH_INTYPE_UINT16:
        case TDH_INTYPE_UNICODECHAR:
            return 2;
        case TDH_INTYPE_INT32:
        case TDH_INTYPE_UINT32:
        case TDH_INTYPE_HEXINT32:
        case TDH_INTYPE_FLOAT:
        case TDH_INTYPE_BOOLEAN:
            return 4;
        case TDH_INTYPE_INT64:
        case TDH_INTYPE_UINT64:
        case TDH_INTYPE_HEXINT64:
        case TDH_INTYPE_DOUBLE:
        case TDH_INTYPE_FILETIME:
            return 8;
        case TDH_INTYPE_GUID:
            return 16;
        case TDH_INTYPE_POINTER:
            return pointerSize == 4 || pointerSize == 8 ? pointerSize : static_cast<ULONG>(sizeof(void*));
        default:
            return 0;
        }
    }

    // etwUnicodeBytesToText：
    // - 作用：把 UTF-16LE 字节缓冲转成 QString，并裁掉尾部 NUL；
    // - 调用：UnicodeString 类属性解码。
    QString etwUnicodeBytesToText(const unsigned char* dataPointer, const ULONG dataSize)
    {
        if (dataPointer == nullptr || dataSize < sizeof(wchar_t))
        {
            return QString();
        }

        const ULONG alignedBytes = dataSize - (dataSize % sizeof(wchar_t));
        if (alignedBytes == 0)
        {
            return QString();
        }

        std::wstring tempWideText(static_cast<std::size_t>(alignedBytes / sizeof(wchar_t)), L'\0');
        std::memcpy(tempWideText.data(), dataPointer, alignedBytes);
        QString textValue = QString::fromWCharArray(tempWideText.c_str(), static_cast<int>(tempWideText.size()));

        const int nullPosition = textValue.indexOf(QChar(u'\0'));
        if (nullPosition >= 0)
        {
            textValue.truncate(nullPosition);
        }
        return textValue.trimmed();
    }

    // etwAnsiBytesToText：
    // - 作用：把 ANSI 字节缓冲转成 QString，并裁掉尾部 NUL；
    // - 调用：AnsiString 类属性解码。
    QString etwAnsiBytesToText(const unsigned char* dataPointer, const ULONG dataSize)
    {
        if (dataPointer == nullptr || dataSize == 0)
        {
            return QString();
        }

        QByteArray byteArray(reinterpret_cast<const char*>(dataPointer), static_cast<int>(dataSize));
        const int nullPosition = byteArray.indexOf('\0');
        if (nullPosition >= 0)
        {
            byteArray.truncate(nullPosition);
        }
        return QString::fromLocal8Bit(byteArray).trimmed();
    }

    // tryConsumeUnicodeString：
    // - 作用：按“显式长度优先，否则扫描 NUL 终止”的规则读取 Unicode 字符串；
    // - 调用：TDH_INTYPE_UNICODESTRING 解码。
    bool tryConsumeUnicodeString(
        const unsigned char* dataPointer,
        const ULONG availableBytes,
        const ULONG explicitLengthBytes,
        QString* textOut,
        ULONG* consumedOut)
    {
        if (textOut != nullptr)
        {
            *textOut = QString();
        }
        if (consumedOut != nullptr)
        {
            *consumedOut = 0;
        }
        if (dataPointer == nullptr || availableBytes == 0)
        {
            return false;
        }

        ULONG consumeBytes = 0;
        if (explicitLengthBytes > 0)
        {
            consumeBytes = std::min(explicitLengthBytes, availableBytes);
        }
        else
        {
            for (ULONG offsetValue = 0; offsetValue + 1 < availableBytes; offsetValue += 2)
            {
                if (dataPointer[offsetValue] == 0 && dataPointer[offsetValue + 1] == 0)
                {
                    consumeBytes = offsetValue + 2;
                    break;
                }
            }
            if (consumeBytes == 0)
            {
                consumeBytes = availableBytes;
            }
        }

        if (consumeBytes == 0)
        {
            return false;
        }
        if ((consumeBytes % 2) != 0)
        {
            --consumeBytes;
        }
        if (consumeBytes == 0)
        {
            return false;
        }

        if (textOut != nullptr)
        {
            *textOut = etwUnicodeBytesToText(dataPointer, consumeBytes);
        }
        if (consumedOut != nullptr)
        {
            *consumedOut = consumeBytes;
        }
        return true;
    }

    // tryConsumeAnsiString：
    // - 作用：按“显式长度优先，否则扫描 NUL 终止”的规则读取 ANSI 字符串；
    // - 调用：TDH_INTYPE_ANSISTRING 解码。
    bool tryConsumeAnsiString(
        const unsigned char* dataPointer,
        const ULONG availableBytes,
        const ULONG explicitLengthBytes,
        QString* textOut,
        ULONG* consumedOut)
    {
        if (textOut != nullptr)
        {
            *textOut = QString();
        }
        if (consumedOut != nullptr)
        {
            *consumedOut = 0;
        }
        if (dataPointer == nullptr || availableBytes == 0)
        {
            return false;
        }

        ULONG consumeBytes = 0;
        if (explicitLengthBytes > 0)
        {
            consumeBytes = std::min(explicitLengthBytes, availableBytes);
        }
        else
        {
            for (ULONG offsetValue = 0; offsetValue < availableBytes; ++offsetValue)
            {
                if (dataPointer[offsetValue] == 0)
                {
                    consumeBytes = offsetValue + 1;
                    break;
                }
            }
            if (consumeBytes == 0)
            {
                consumeBytes = availableBytes;
            }
        }

        if (consumeBytes == 0)
        {
            return false;
        }
        if (textOut != nullptr)
        {
            *textOut = etwAnsiBytesToText(dataPointer, consumeBytes);
        }
        if (consumedOut != nullptr)
        {
            *consumedOut = consumeBytes;
        }
        return true;
    }

    // decodeEtwPropertiesBySchema：
    // - 作用：按缓存 schema 顺序解析 UserData，并记录每个字段偏移；
    // - 要点：长度/数量引用属性从前面数值字段读取，不再逐字段调用 TDH 查询。
    bool decodeEtwPropertiesBySchema(
        const EVENT_RECORD* eventRecord,
        const EtwSchemaEntry& schemaEntry,
        std::vector<EtwDecodedPropertyEntry>* decodedPropertyListOut,
        ULONG* parsedBytesOut,
        QString* unparsedTailHexOut)
    {
        if (decodedPropertyListOut == nullptr || parsedBytesOut == nullptr)
        {
            return false;
        }

        decodedPropertyListOut->clear();
        *parsedBytesOut = 0;
        if (unparsedTailHexOut != nullptr)
        {
            unparsedTailHexOut->clear();
        }

        if (eventRecord == nullptr)
        {
            return false;
        }

        const unsigned char* userDataPointer = reinterpret_cast<const unsigned char*>(eventRecord->UserData);
        const ULONG userDataLength = eventRecord->UserDataLength;
        if (userDataPointer == nullptr || userDataLength == 0)
        {
            return true;
        }

        const ULONG pointerSize = etwPointerSizeByHeader(eventRecord);
        ULONG cursorOffset = 0;
        std::unordered_map<ULONG, std::uint64_t> numericValueMap;
        decodedPropertyListOut->reserve(schemaEntry.propertyList.size());

        for (const EtwSchemaPropertyEntry& propertySchema : schemaEntry.propertyList)
        {
            EtwDecodedPropertyEntry decodedEntry;
            decodedEntry.propertyNameText = propertySchema.propertyNameText;
            decodedEntry.normalizedNameText = propertySchema.normalizedNameText;
            decodedEntry.meaningText = propertySchema.meaningText;
            decodedEntry.inTypeText = etwTypeText(propertySchema.inType);
            decodedEntry.beginOffset = cursorOffset;

            if (cursorOffset >= userDataLength)
            {
                decodedEntry.valueText = QStringLiteral("<无更多数据>");
                decodedEntry.parseFallback = true;
                decodedEntry.endOffset = cursorOffset;
                decodedPropertyListOut->push_back(std::move(decodedEntry));
                continue;
            }

            const ULONG availableBytes = userDataLength - cursorOffset;
            const unsigned char* fieldDataPointer = userDataPointer + cursorOffset;

            ULONG resolvedLength = propertySchema.fixedLength;
            ULONG resolvedCount = propertySchema.fixedCount == 0 ? 1UL : static_cast<ULONG>(propertySchema.fixedCount);
            if (propertySchema.useLengthProperty)
            {
                const auto found = numericValueMap.find(propertySchema.lengthPropertyIndex);
                if (found != numericValueMap.end())
                {
                    resolvedLength = static_cast<ULONG>(std::min<std::uint64_t>(found->second, 0xFFFFFFFFULL));
                }
            }
            if (propertySchema.useCountProperty)
            {
                const auto found = numericValueMap.find(propertySchema.countPropertyIndex);
                if (found != numericValueMap.end())
                {
                    resolvedCount = static_cast<ULONG>(std::max<std::uint64_t>(1ULL, found->second));
                }
            }

            ULONG consumeBytes = 0;
            bool parsedAsKnownType = true;

            if (propertySchema.isStruct)
            {
                // 结构体字段存在嵌套与动态布局，这里保留十六进制预览。
                decodedEntry.valueText = QStringLiteral("<Struct: 当前版本未展开，已保留十六进制预览>");
                consumeBytes = std::min<ULONG>(availableBytes, resolvedLength > 0 ? resolvedLength : 32UL);
                decodedEntry.parseFallback = true;
            }
            else
            {
                const ULONG fixedTypeSize = etwFixedTypeSize(propertySchema.inType, pointerSize);
                ULONG expectedBytes = 0;
                if (resolvedLength > 0)
                {
                    expectedBytes = resolvedLength * std::max<ULONG>(1, resolvedCount);
                }
                else if (fixedTypeSize > 0)
                {
                    expectedBytes = fixedTypeSize * std::max<ULONG>(1, resolvedCount);
                }

                switch (propertySchema.inType)
                {
                case TDH_INTYPE_UNICODESTRING:
                {
                    QString textValue;
                    if (tryConsumeUnicodeString(fieldDataPointer, availableBytes, expectedBytes, &textValue, &consumeBytes))
                    {
                        decodedEntry.valueText = textValue;
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_ANSISTRING:
                {
                    QString textValue;
                    if (tryConsumeAnsiString(fieldDataPointer, availableBytes, expectedBytes, &textValue, &consumeBytes))
                    {
                        decodedEntry.valueText = textValue;
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_GUID:
                {
                    GUID guidValue{};
                    consumeBytes = std::min<ULONG>(availableBytes, 16);
                    if (etwReadScalar(fieldDataPointer, availableBytes, &guidValue))
                    {
                        decodedEntry.valueText = guidToText(guidValue);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_INT8:
                {
                    std::int8_t value = 0;
                    consumeBytes = 1;
                    if (etwReadScalar(fieldDataPointer, availableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = static_cast<std::uint64_t>(value);
                        decodedEntry.valueText = QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_UINT8:
                {
                    std::uint8_t value = 0;
                    consumeBytes = 1;
                    if (etwReadScalar(fieldDataPointer, availableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = value;
                        decodedEntry.valueText = QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_BOOLEAN:
                {
                    const ULONG boolBytes = expectedBytes > 0 ? std::min(expectedBytes, availableBytes) : 4UL;
                    consumeBytes = std::max<ULONG>(1, boolBytes);

                    std::uint32_t value32 = 0;
                    if (consumeBytes >= 4 && etwReadScalar(fieldDataPointer, availableBytes, &value32))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = value32;
                        decodedEntry.valueText = value32 == 0 ? QStringLiteral("false") : QStringLiteral("true");
                    }
                    else
                    {
                        std::uint8_t value8 = 0;
                        if (etwReadScalar(fieldDataPointer, availableBytes, &value8))
                        {
                            decodedEntry.numericAvailable = true;
                            decodedEntry.numericValue = value8;
                            decodedEntry.valueText = value8 == 0 ? QStringLiteral("false") : QStringLiteral("true");
                        }
                        else
                        {
                            parsedAsKnownType = false;
                        }
                    }
                    break;
                }
                case TDH_INTYPE_INT16:
                {
                    std::int16_t value = 0;
                    consumeBytes = 2;
                    if (etwReadScalar(fieldDataPointer, availableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = static_cast<std::uint64_t>(value);
                        decodedEntry.valueText = QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_UINT16:
                {
                    std::uint16_t value = 0;
                    consumeBytes = 2;
                    if (etwReadScalar(fieldDataPointer, availableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = value;
                        decodedEntry.valueText = QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_INT32:
                {
                    std::int32_t value = 0;
                    consumeBytes = 4;
                    if (etwReadScalar(fieldDataPointer, availableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = static_cast<std::uint64_t>(value);
                        decodedEntry.valueText = QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_UINT32:
                case TDH_INTYPE_HEXINT32:
                {
                    std::uint32_t value = 0;
                    consumeBytes = 4;
                    if (etwReadScalar(fieldDataPointer, availableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = value;
                        decodedEntry.valueText = propertySchema.inType == TDH_INTYPE_HEXINT32
                            ? QStringLiteral("0x%1").arg(value, 8, 16, QChar(u'0')).toUpper()
                            : QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_INT64:
                {
                    std::int64_t value = 0;
                    consumeBytes = 8;
                    if (etwReadScalar(fieldDataPointer, availableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = static_cast<std::uint64_t>(value);
                        decodedEntry.valueText = QString::number(static_cast<qlonglong>(value));
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_FLOAT:
                {
                    float value = 0.0f;
                    consumeBytes = 4;
                    if (etwReadScalar(fieldDataPointer, availableBytes, &value))
                    {
                        decodedEntry.valueText = QString::number(value, 'f', 6);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_DOUBLE:
                {
                    double value = 0.0;
                    consumeBytes = 8;
                    if (etwReadScalar(fieldDataPointer, availableBytes, &value))
                    {
                        decodedEntry.valueText = QString::number(value, 'f', 6);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_UINT64:
                case TDH_INTYPE_HEXINT64:
                case TDH_INTYPE_POINTER:
                case TDH_INTYPE_FILETIME:
                {
                    std::uint64_t value = 0;
                    consumeBytes = propertySchema.inType == TDH_INTYPE_POINTER ? pointerSize : 8;
                    if (consumeBytes == 4)
                    {
                        std::uint32_t value32 = 0;
                        if (etwReadScalar(fieldDataPointer, availableBytes, &value32))
                        {
                            value = value32;
                        }
                    }
                    else
                    {
                        etwReadScalar(fieldDataPointer, availableBytes, &value);
                    }

                    if (value == 0 && availableBytes < consumeBytes)
                    {
                        parsedAsKnownType = false;
                        break;
                    }

                    decodedEntry.numericAvailable = true;
                    decodedEntry.numericValue = value;
                    if (propertySchema.inType == TDH_INTYPE_POINTER
                        || propertySchema.inType == TDH_INTYPE_HEXINT64)
                    {
                        decodedEntry.valueText = QStringLiteral("0x%1")
                            .arg(static_cast<qulonglong>(value), consumeBytes * 2, 16, QChar(u'0'))
                            .toUpper();
                    }
                    else
                    {
                        decodedEntry.valueText = QString::number(static_cast<qulonglong>(value));
                    }
                    break;
                }
                case TDH_INTYPE_SID:
                {
                    PSID sidPointer = reinterpret_cast<PSID>(const_cast<unsigned char*>(fieldDataPointer));
                    if (sidPointer != nullptr && ::IsValidSid(sidPointer) != FALSE)
                    {
                        consumeBytes = ::GetLengthSid(sidPointer);
                        consumeBytes = std::min(consumeBytes, availableBytes);
                        LPWSTR sidTextPointer = nullptr;
                        if (::ConvertSidToStringSidW(sidPointer, &sidTextPointer) != FALSE && sidTextPointer != nullptr)
                        {
                            decodedEntry.valueText = QString::fromWCharArray(sidTextPointer);
                            ::LocalFree(sidTextPointer);
                        }
                        else
                        {
                            decodedEntry.valueText = QStringLiteral("<SID转换失败>");
                            decodedEntry.parseFallback = true;
                        }
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_SYSTEMTIME:
                {
                    SYSTEMTIME systemTimeValue{};
                    consumeBytes = static_cast<ULONG>(sizeof(SYSTEMTIME));
                    if (etwReadScalar(fieldDataPointer, availableBytes, &systemTimeValue))
                    {
                        decodedEntry.valueText = QStringLiteral("%1-%2-%3 %4:%5:%6.%7")
                            .arg(systemTimeValue.wYear, 4, 10, QChar(u'0'))
                            .arg(systemTimeValue.wMonth, 2, 10, QChar(u'0'))
                            .arg(systemTimeValue.wDay, 2, 10, QChar(u'0'))
                            .arg(systemTimeValue.wHour, 2, 10, QChar(u'0'))
                            .arg(systemTimeValue.wMinute, 2, 10, QChar(u'0'))
                            .arg(systemTimeValue.wSecond, 2, 10, QChar(u'0'))
                            .arg(systemTimeValue.wMilliseconds, 3, 10, QChar(u'0'));
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_BINARY:
                case TDH_INTYPE_HEXDUMP:
                {
                    consumeBytes = expectedBytes > 0
                        ? std::min(expectedBytes, availableBytes)
                        : std::min<ULONG>(availableBytes, 64);
                    decodedEntry.valueText = QStringLiteral("<二进制数据>");
                    decodedEntry.parseFallback = true;
                    break;
                }
                default:
                    parsedAsKnownType = false;
                    break;
                }
            }

            if (!parsedAsKnownType)
            {
                // 无法确定类型时，用“长度策略 > 剩余全部”的顺序兜底。
                ULONG fallbackBytes = 0;
                if (resolvedLength > 0)
                {
                    fallbackBytes = std::min<ULONG>(availableBytes, resolvedLength * std::max<ULONG>(1, resolvedCount));
                }
                else if (propertySchema.fixedLength > 0)
                {
                    fallbackBytes = std::min<ULONG>(availableBytes, propertySchema.fixedLength);
                }
                else
                {
                    fallbackBytes = std::min<ULONG>(availableBytes, 32);
                }

                consumeBytes = std::max<ULONG>(1, fallbackBytes);
                decodedEntry.valueText = QStringLiteral("<未识别类型，已按十六进制保留>");
                decodedEntry.parseFallback = true;
            }

            consumeBytes = std::min(consumeBytes, availableBytes);
            decodedEntry.endOffset = cursorOffset + consumeBytes;
            decodedEntry.hexPreviewText = etwHexPreview(fieldDataPointer, consumeBytes);

            if (decodedEntry.numericAvailable)
            {
                numericValueMap[propertySchema.propertyIndex] = decodedEntry.numericValue;
            }

            decodedPropertyListOut->push_back(std::move(decodedEntry));
            cursorOffset += consumeBytes;
        }

        *parsedBytesOut = cursorOffset;
        if (cursorOffset < userDataLength && unparsedTailHexOut != nullptr)
        {
            const unsigned char* tailPointer = userDataPointer + cursorOffset;
            *unparsedTailHexOut = etwHexDump(tailPointer, userDataLength - cursorOffset);
        }
        return true;
    }

    // etwPropertyValueMeaningful：
    // - 作用：过滤空值/占位值，避免语义提取误判。
    bool etwPropertyValueMeaningful(const QString& valueText)
    {
        const QString trimmed = valueText.trimmed();
        if (trimmed.isEmpty())
        {
            return false;
        }
        return !trimmed.startsWith('<');
    }

    // findFirstEtwProperty：
    // - 作用：按候选属性名列表查找第一条有效属性值；
    // - 调用：提取目标路径、状态码、端口等常见语义。
    const EtwDecodedPropertyEntry* findFirstEtwProperty(
        const std::vector<EtwDecodedPropertyEntry>& propertyList,
        const QStringList& normalizedNameList)
    {
        for (const QString& normalizedName : normalizedNameList)
        {
            for (const EtwDecodedPropertyEntry& property : propertyList)
            {
                if (property.normalizedNameText == normalizedName
                    && etwPropertyValueMeaningful(property.valueText))
                {
                    return &property;
                }
            }
        }
        return nullptr;
    }

    // inferEtwResourceType：
    // - 作用：根据 Provider 与事件名推断资源大类；
    // - 调用：写入 JSON semantic.resourceType。
    QString inferEtwResourceType(const QString& providerNameText, const QString& eventNameText)
    {
        const QString providerLower = providerNameText.toLower();
        const QString eventLower = eventNameText.toLower();

        if (providerLower.contains(QStringLiteral("registry")) || eventLower.contains(QStringLiteral("reg")))
        {
            return QStringLiteral("注册表");
        }
        if (providerLower.contains(QStringLiteral("file")) || providerLower.contains(QStringLiteral("ntfs"))
            || eventLower.contains(QStringLiteral("file")) || eventLower.contains(QStringLiteral("createfile")))
        {
            return QStringLiteral("文件");
        }
        if (providerLower.contains(QStringLiteral("tcp")) || providerLower.contains(QStringLiteral("udp"))
            || providerLower.contains(QStringLiteral("network")) || providerLower.contains(QStringLiteral("winsock"))
            || eventLower.contains(QStringLiteral("connect")) || eventLower.contains(QStringLiteral("send"))
            || eventLower.contains(QStringLiteral("recv")))
        {
            return QStringLiteral("网络");
        }
        if (providerLower.contains(QStringLiteral("process")) || providerLower.contains(QStringLiteral("thread"))
            || eventLower.contains(QStringLiteral("process")) || eventLower.contains(QStringLiteral("thread")))
        {
            return QStringLiteral("进程线程");
        }
        return QStringLiteral("通用");
    }

    // inferEtwActionText：
    // - 作用：根据事件名和操作码名提取动作语义；
    // - 调用：写入 JSON semantic.action。
    QString inferEtwActionText(const QString& eventNameText, const QString& opcodeNameText)
    {
        const QString actionProbe = (eventNameText + QLatin1Char(' ') + opcodeNameText).toLower();

        if (actionProbe.contains(QStringLiteral("create")) || actionProbe.contains(QStringLiteral("start")))
        {
            return QStringLiteral("创建/启动");
        }
        if (actionProbe.contains(QStringLiteral("open")))
        {
            return QStringLiteral("打开");
        }
        if (actionProbe.contains(QStringLiteral("close")) || actionProbe.contains(QStringLiteral("cleanup")))
        {
            return QStringLiteral("关闭");
        }
        if (actionProbe.contains(QStringLiteral("read")) || actionProbe.contains(QStringLiteral("query")))
        {
            return QStringLiteral("读取/查询");
        }
        if (actionProbe.contains(QStringLiteral("write")) || actionProbe.contains(QStringLiteral("set")))
        {
            return QStringLiteral("写入/设置");
        }
        if (actionProbe.contains(QStringLiteral("delete")) || actionProbe.contains(QStringLiteral("remove")))
        {
            return QStringLiteral("删除");
        }
        if (actionProbe.contains(QStringLiteral("rename")))
        {
            return QStringLiteral("重命名");
        }
        if (actionProbe.contains(QStringLiteral("connect")))
        {
            return QStringLiteral("连接");
        }
        if (actionProbe.contains(QStringLiteral("send")))
        {
            return QStringLiteral("发送");
        }
        if (actionProbe.contains(QStringLiteral("recv")) || actionProbe.contains(QStringLiteral("receive")))
        {
            return QStringLiteral("接收");
        }
        if (!eventNameText.trimmed().isEmpty())
        {
            return eventNameText.trimmed();
        }
        if (!opcodeNameText.trimmed().isEmpty())
        {
            return opcodeNameText.trimmed();
        }
        return QStringLiteral("未知动作");
    }

    // etwIpv4TextFromNumeric：
    // - 作用：把 32 位地址值按 IPv4 文本展示；
    // - 调用：网络事件目标端点拼接。
    QString etwIpv4TextFromNumeric(const std::uint32_t addressValue)
    {
        const std::uint8_t byte1 = static_cast<std::uint8_t>((addressValue >> 0) & 0xFF);
        const std::uint8_t byte2 = static_cast<std::uint8_t>((addressValue >> 8) & 0xFF);
        const std::uint8_t byte3 = static_cast<std::uint8_t>((addressValue >> 16) & 0xFF);
        const std::uint8_t byte4 = static_cast<std::uint8_t>((addressValue >> 24) & 0xFF);
        return QStringLiteral("%1.%2.%3.%4").arg(byte1).arg(byte2).arg(byte3).arg(byte4);
    }

    // etwToSingleLine：
    // - 作用：把多行文本压成单行，便于表格摘要展示。
    QString etwToSingleLine(const QString& valueText)
    {
        QString normalizedText = valueText;
        normalizedText.replace(QChar(u'\r'), QChar(u' '));
        normalizedText.replace(QChar(u'\n'), QChar(u' '));
        return normalizedText.simplified();
    }

    // appendEtwStatusSummary：
    // - 作用：按需在摘要尾部补上状态文本。
    QString appendEtwStatusSummary(const QString& summaryText, const QString& statusText)
    {
        const QString normalizedStatusText = etwToSingleLine(statusText);
        if (normalizedStatusText.isEmpty())
        {
            return summaryText;
        }
        return QStringLiteral("%1 | 状态=%2").arg(summaryText, normalizedStatusText);
    }

    // inferEtwSemanticSummary：
    // - 作用：聚合文件/注册表/网络等常见场景的目标对象和状态；
    // - 调用：作为 ETW 详情 JSON 的语义摘要区块。
    EtwSemanticSummary inferEtwSemanticSummary(
        const QString& providerNameText,
        const QString& eventNameText,
        const QString& opcodeNameText,
        const std::vector<EtwDecodedPropertyEntry>& propertyList)
    {
        EtwSemanticSummary summary;
        summary.resourceTypeText = inferEtwResourceType(providerNameText, eventNameText);
        summary.actionText = inferEtwActionText(eventNameText, opcodeNameText);

        const EtwDecodedPropertyEntry* filePathProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("filename"), QStringLiteral("filepath"), QStringLiteral("targetfilename"),
            QStringLiteral("newfilename"), QStringLiteral("oldfilename"), QStringLiteral("pathname"),
            QStringLiteral("targetname"), QStringLiteral("relativefilename"), QStringLiteral("fileobject") });
        const EtwDecodedPropertyEntry* oldFileProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("oldfilename") });
        const EtwDecodedPropertyEntry* newFileProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("newfilename"), QStringLiteral("targetfilename") });
        const EtwDecodedPropertyEntry* regKeyProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("keyname"), QStringLiteral("keypath"), QStringLiteral("hive"),
            QStringLiteral("objectname"), QStringLiteral("path") });
        const EtwDecodedPropertyEntry* regValueProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("valuename") });
        const EtwDecodedPropertyEntry* imageProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("imagename"), QStringLiteral("imagefilename"), QStringLiteral("commandline") });
        const EtwDecodedPropertyEntry* sourceAddressProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("saddr"), QStringLiteral("sourceaddress"), QStringLiteral("srcaddr") });
        const EtwDecodedPropertyEntry* targetAddressProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("daddr"), QStringLiteral("destaddress"), QStringLiteral("dstaddr") });
        const EtwDecodedPropertyEntry* sourcePortProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("sport"), QStringLiteral("sourceport"), QStringLiteral("srcport") });
        const EtwDecodedPropertyEntry* targetPortProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("dport"), QStringLiteral("destport"), QStringLiteral("dstport") });
        const EtwDecodedPropertyEntry* operationProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("operation"), QStringLiteral("opcode") });

        if (summary.actionText == QStringLiteral("未知动作")
            && operationProperty != nullptr
            && !operationProperty->valueText.trimmed().isEmpty())
        {
            summary.actionText = operationProperty->valueText.trimmed();
        }

        if (summary.resourceTypeText == QStringLiteral("文件") && filePathProperty != nullptr)
        {
            if (summary.actionText.contains(QStringLiteral("重命名"))
                && oldFileProperty != nullptr
                && newFileProperty != nullptr)
            {
                summary.targetText = QStringLiteral("%1 -> %2")
                    .arg(oldFileProperty->valueText, newFileProperty->valueText);
            }
            else
            {
                summary.targetText = filePathProperty->valueText;
            }
        }
        else if (summary.resourceTypeText == QStringLiteral("注册表") && regKeyProperty != nullptr)
        {
            summary.targetText = regKeyProperty->valueText;
            if (regValueProperty != nullptr && !regValueProperty->valueText.isEmpty())
            {
                summary.targetText += QStringLiteral("\\") + regValueProperty->valueText;
            }
        }
        else if (summary.resourceTypeText == QStringLiteral("进程线程") && imageProperty != nullptr)
        {
            summary.targetText = imageProperty->valueText;
        }
        else if (summary.resourceTypeText == QStringLiteral("网络"))
        {
            QString sourceAddressText;
            QString targetAddressText;
            if (sourceAddressProperty != nullptr)
            {
                if (sourceAddressProperty->numericAvailable)
                {
                    sourceAddressText = etwIpv4TextFromNumeric(
                        static_cast<std::uint32_t>(sourceAddressProperty->numericValue));
                }
                else
                {
                    sourceAddressText = sourceAddressProperty->valueText;
                }
            }
            if (targetAddressProperty != nullptr)
            {
                if (targetAddressProperty->numericAvailable)
                {
                    targetAddressText = etwIpv4TextFromNumeric(
                        static_cast<std::uint32_t>(targetAddressProperty->numericValue));
                }
                else
                {
                    targetAddressText = targetAddressProperty->valueText;
                }
            }

            const QString sourcePortText = sourcePortProperty != nullptr
                ? sourcePortProperty->valueText
                : QString();
            const QString targetPortText = targetPortProperty != nullptr
                ? targetPortProperty->valueText
                : QString();

            if (!sourceAddressText.isEmpty() || !targetAddressText.isEmpty())
            {
                const QString sourceEndpointText = sourcePortText.isEmpty()
                    ? sourceAddressText
                    : QStringLiteral("%1:%2").arg(sourceAddressText, sourcePortText);
                const QString targetEndpointText = targetPortText.isEmpty()
                    ? targetAddressText
                    : QStringLiteral("%1:%2").arg(targetAddressText, targetPortText);
                if (!sourceEndpointText.isEmpty() && !targetEndpointText.isEmpty())
                {
                    summary.targetText = QStringLiteral("%1 -> %2")
                        .arg(sourceEndpointText, targetEndpointText);
                }
                else if (!targetEndpointText.isEmpty())
                {
                    summary.targetText = targetEndpointText;
                }
                else
                {
                    summary.targetText = sourceEndpointText;
                }
            }
        }
        else
        {
            const EtwDecodedPropertyEntry* genericTarget = findFirstEtwProperty(
                propertyList,
                QStringList{ QStringLiteral("objectname"), QStringLiteral("path"), QStringLiteral("targetname"),
                QStringLiteral("filename"), QStringLiteral("keyname"), QStringLiteral("keypath"),
                QStringLiteral("imagename"), QStringLiteral("pathname") });
            if (genericTarget != nullptr)
            {
                summary.targetText = genericTarget->valueText;
            }
        }

        const EtwDecodedPropertyEntry* statusProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("status"), QStringLiteral("ntstatus"), QStringLiteral("result"),
            QStringLiteral("hresult"), QStringLiteral("errorcode"), QStringLiteral("error"),
            QStringLiteral("win32error"), QStringLiteral("win32status") });
        if (statusProperty != nullptr)
        {
            if (statusProperty->numericAvailable)
            {
                const std::uint64_t statusValue = statusProperty->numericValue;
                summary.statusText = statusValue == 0
                    ? QStringLiteral("成功")
                    : QStringLiteral("0x%1").arg(static_cast<qulonglong>(statusValue), 8, 16, QChar(u'0')).toUpper();
            }
            else
            {
                summary.statusText = statusProperty->valueText;
            }
        }
        return summary;
    }

    // buildEtwSummaryText：
    // - 作用：生成 ETW 表格“单行关键摘要”；常见类型做特判。
    QString buildEtwSummaryText(
        const QString& providerNameText,
        const QString& eventNameText,
        const QString& opcodeNameText,
        const std::uint32_t pidValue,
        const std::uint32_t tidValue,
        const EtwSemanticSummary& semanticSummary,
        const std::vector<EtwDecodedPropertyEntry>& propertyList)
    {
        const QString resourceTypeText = etwToSingleLine(semanticSummary.resourceTypeText);
        QString actionText = etwToSingleLine(semanticSummary.actionText);
        QString targetText = etwToSingleLine(semanticSummary.targetText);
        const QString statusText = etwToSingleLine(semanticSummary.statusText);

        if (actionText.isEmpty())
        {
            actionText = etwToSingleLine(eventNameText);
        }
        if (actionText.isEmpty())
        {
            actionText = etwToSingleLine(opcodeNameText);
        }
        if (actionText.isEmpty())
        {
            actionText = QStringLiteral("事件");
        }

        const QString probeText = (providerNameText + QLatin1Char(' ') + eventNameText + QLatin1Char(' ') + opcodeNameText).toLower();
        const bool isThreadEvent = probeText.contains(QStringLiteral("thread"));

        if (resourceTypeText == QStringLiteral("文件"))
        {
            if (targetText.isEmpty())
            {
                const EtwDecodedPropertyEntry* filePathProperty = findFirstEtwProperty(
                    propertyList,
                    QStringList{ QStringLiteral("filename"), QStringLiteral("filepath"),
                    QStringLiteral("targetfilename"), QStringLiteral("newfilename"),
                    QStringLiteral("oldfilename"), QStringLiteral("pathname"),
                    QStringLiteral("targetname"), QStringLiteral("relativefilename") });
                if (filePathProperty != nullptr)
                {
                    targetText = etwToSingleLine(filePathProperty->valueText);
                }
            }
            if (targetText.isEmpty())
            {
                targetText = QStringLiteral("<未知路径>");
            }
            const QString summaryText = QStringLiteral("文件 %1 | %2 | PID=%3 TID=%4")
                .arg(actionText, targetText)
                .arg(pidValue)
                .arg(tidValue);
            return appendEtwStatusSummary(summaryText, statusText);
        }

        if (resourceTypeText == QStringLiteral("注册表"))
        {
            if (targetText.isEmpty())
            {
                const EtwDecodedPropertyEntry* keyProperty = findFirstEtwProperty(
                    propertyList,
                    QStringList{ QStringLiteral("keyname"), QStringLiteral("keypath"),
                    QStringLiteral("hive"), QStringLiteral("objectname"), QStringLiteral("path") });
                const EtwDecodedPropertyEntry* valueProperty = findFirstEtwProperty(
                    propertyList,
                    QStringList{ QStringLiteral("valuename") });
                if (keyProperty != nullptr)
                {
                    targetText = etwToSingleLine(keyProperty->valueText);
                    if (valueProperty != nullptr)
                    {
                        const QString valueNameText = etwToSingleLine(valueProperty->valueText);
                        if (!valueNameText.isEmpty())
                        {
                            targetText += QStringLiteral("\\") + valueNameText;
                        }
                    }
                }
            }
            if (targetText.isEmpty())
            {
                targetText = QStringLiteral("<未知路径>");
            }
            const QString summaryText = QStringLiteral("注册表 %1 | %2 | PID=%3 TID=%4")
                .arg(actionText, targetText)
                .arg(pidValue)
                .arg(tidValue);
            return appendEtwStatusSummary(summaryText, statusText);
        }

        if (resourceTypeText == QStringLiteral("进程线程"))
        {
            const EtwDecodedPropertyEntry* processIdProperty = findFirstEtwProperty(
                propertyList,
                QStringList{ QStringLiteral("processid"), QStringLiteral("pid"),
                QStringLiteral("targetprocessid") });
            const EtwDecodedPropertyEntry* threadIdProperty = findFirstEtwProperty(
                propertyList,
                QStringList{ QStringLiteral("threadid"), QStringLiteral("tid"),
                QStringLiteral("targetthreadid") });
            const EtwDecodedPropertyEntry* parentPidProperty = findFirstEtwProperty(
                propertyList,
                QStringList{ QStringLiteral("parentprocessid"), QStringLiteral("parentid"), QStringLiteral("ppid") });
            const EtwDecodedPropertyEntry* imageProperty = findFirstEtwProperty(
                propertyList,
                QStringList{ QStringLiteral("imagename"), QStringLiteral("imagefilename"),
                QStringLiteral("processname"), QStringLiteral("commandline") });

            const QString processIdText = processIdProperty != nullptr
                ? etwToSingleLine(processIdProperty->valueText)
                : QString::number(pidValue);
            const QString threadIdText = threadIdProperty != nullptr
                ? etwToSingleLine(threadIdProperty->valueText)
                : QString::number(tidValue);

            QString processDisplayText = targetText;
            if (processDisplayText.isEmpty() && imageProperty != nullptr)
            {
                processDisplayText = etwToSingleLine(imageProperty->valueText);
            }

            QString summaryText;
            if (isThreadEvent)
            {
                summaryText = QStringLiteral("线程 %1 | PID=%2 TID=%3")
                    .arg(actionText, processIdText, threadIdText);
                if (!processDisplayText.isEmpty())
                {
                    summaryText += QStringLiteral(" | 进程=%1").arg(processDisplayText);
                }
            }
            else
            {
                summaryText = QStringLiteral("进程 %1 | PID=%2 | TID=%3")
                    .arg(actionText, processIdText, threadIdText);
                if (!processDisplayText.isEmpty())
                {
                    summaryText += QStringLiteral(" | %1").arg(processDisplayText);
                }
                if (parentPidProperty != nullptr)
                {
                    const QString parentPidText = etwToSingleLine(parentPidProperty->valueText);
                    if (!parentPidText.isEmpty())
                    {
                        summaryText += QStringLiteral(" | 父PID=%1").arg(parentPidText);
                    }
                }
            }
            return appendEtwStatusSummary(summaryText, statusText);
        }

        QString targetDisplayText = targetText;
        if (targetDisplayText.isEmpty())
        {
            targetDisplayText = etwToSingleLine(providerNameText);
        }
        if (targetDisplayText.isEmpty())
        {
            targetDisplayText = QStringLiteral("<无目标>");
        }

        QString summaryText = QStringLiteral("%1 | %2 | PID=%3 TID=%4")
            .arg(actionText, targetDisplayText)
            .arg(pidValue)
            .arg(tidValue);
        if (!resourceTypeText.isEmpty() && resourceTypeText != QStringLiteral("通用"))
        {
            summaryText = QStringLiteral("%1 %2").arg(resourceTypeText, summaryText);
        }
        return appendEtwStatusSummary(summaryText, statusText);
    }

    // buildEtwSummaryFromDetailJson：
    // - 作用：从详情 JSON 回推单行摘要（兜底路径，保证旧调用也可显示摘要）。
    QString buildEtwSummaryFromDetailJson(
        const QString& detailJsonText,
        const QString& providerNameText,
        const QString& eventNameText,
        const std::uint32_t pidValue,
        const std::uint32_t tidValue)
    {
        QJsonParseError parseError;
        const QJsonDocument jsonDocument = QJsonDocument::fromJson(detailJsonText.toUtf8(), &parseError);
        if (jsonDocument.isNull() || !jsonDocument.isObject())
        {
            const QString normalizedEventName = etwToSingleLine(eventNameText).isEmpty()
                ? QStringLiteral("事件")
                : etwToSingleLine(eventNameText);
            return QStringLiteral("%1 | PID=%2 TID=%3")
                .arg(normalizedEventName)
                .arg(pidValue)
                .arg(tidValue);
        }

        const QJsonObject rootObject = jsonDocument.object();
        const QJsonObject semanticObject = rootObject.value(QStringLiteral("semantic")).toObject();
        const QJsonObject metaObject = rootObject.value(QStringLiteral("meta")).toObject();

        EtwSemanticSummary semanticSummary;
        semanticSummary.resourceTypeText = semanticObject.value(QStringLiteral("resourceType")).toString();
        semanticSummary.actionText = semanticObject.value(QStringLiteral("action")).toString();
        semanticSummary.targetText = semanticObject.value(QStringLiteral("target")).toString();
        semanticSummary.statusText = semanticObject.value(QStringLiteral("status")).toString();

        const QString opcodeNameText = metaObject.value(QStringLiteral("opcodeName")).toString();
        return buildEtwSummaryText(
            providerNameText,
            eventNameText,
            opcodeNameText,
            pidValue,
            tidValue,
            semanticSummary,
            std::vector<EtwDecodedPropertyEntry>{});
    }

    // buildEtwDetailJson：
    // - 作用：把元信息、语义摘要、属性列表、尾部十六进制兜底打包成 JSON；
    // - 调用：enqueueEtwEventFromRecord 构造“查看返回详情”所需的原始数据。
    QString buildEtwDetailJson(
        const EVENT_RECORD* eventRecord,
        const QString& providerGuidText,
        const QString& providerNameText,
        const EtwSchemaEntry& schemaEntry,
        const EtwSemanticSummary& semanticSummary,
        const std::vector<EtwDecodedPropertyEntry>& propertyList,
        const ULONG parsedBytes,
        const QString& unparsedTailHexText)
    {
        QJsonObject rootObject;

        QJsonObject metaObject;
        QString eventNameText = schemaEntry.eventNameText.trimmed();
        if (eventNameText.isEmpty())
        {
            eventNameText = schemaEntry.taskNameText.trimmed();
        }
        if (eventNameText.isEmpty())
        {
            eventNameText = schemaEntry.opcodeNameText.trimmed();
        }
        if (eventNameText.isEmpty())
        {
            eventNameText = QStringLiteral("Event_%1")
                .arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Id));
        }

        metaObject.insert(QStringLiteral("providerGuid"), providerGuidText);
        metaObject.insert(QStringLiteral("providerName"), providerNameText);
        metaObject.insert(QStringLiteral("eventId"), static_cast<int>(eventRecord->EventHeader.EventDescriptor.Id));
        metaObject.insert(QStringLiteral("eventName"), eventNameText);
        metaObject.insert(QStringLiteral("task"), static_cast<int>(eventRecord->EventHeader.EventDescriptor.Task));
        metaObject.insert(QStringLiteral("taskName"), schemaEntry.taskNameText);
        metaObject.insert(QStringLiteral("opcode"), static_cast<int>(eventRecord->EventHeader.EventDescriptor.Opcode));
        metaObject.insert(QStringLiteral("opcodeName"), schemaEntry.opcodeNameText);
        metaObject.insert(QStringLiteral("level"), static_cast<int>(eventRecord->EventHeader.EventDescriptor.Level));
        metaObject.insert(
            QStringLiteral("keyword"),
            QStringLiteral("0x%1").arg(
                static_cast<qulonglong>(eventRecord->EventHeader.EventDescriptor.Keyword),
                16,
                16,
                QChar(u'0')).toUpper());
        metaObject.insert(QStringLiteral("version"), static_cast<int>(eventRecord->EventHeader.EventDescriptor.Version));
        metaObject.insert(QStringLiteral("userDataLength"), static_cast<int>(eventRecord->UserDataLength));
        metaObject.insert(QStringLiteral("parsedBytes"), static_cast<int>(parsedBytes));
        rootObject.insert(QStringLiteral("meta"), metaObject);

        QJsonObject semanticObject;
        semanticObject.insert(QStringLiteral("resourceType"), semanticSummary.resourceTypeText);
        semanticObject.insert(QStringLiteral("action"), semanticSummary.actionText);
        semanticObject.insert(QStringLiteral("target"), semanticSummary.targetText);
        semanticObject.insert(QStringLiteral("status"), semanticSummary.statusText);
        rootObject.insert(QStringLiteral("semantic"), semanticObject);

        QJsonArray propertyArray;
        for (const EtwDecodedPropertyEntry& property : propertyList)
        {
            QJsonObject propertyObject;
            propertyObject.insert(QStringLiteral("name"), property.propertyNameText);
            propertyObject.insert(QStringLiteral("normalized"), property.normalizedNameText);
            propertyObject.insert(QStringLiteral("meaning"), property.meaningText);
            propertyObject.insert(QStringLiteral("type"), property.inTypeText);
            propertyObject.insert(QStringLiteral("value"), property.valueText);
            propertyObject.insert(
                QStringLiteral("offset"),
                QStringLiteral("0x%1-0x%2")
                .arg(property.beginOffset, 4, 16, QChar(u'0'))
                .arg(property.endOffset, 4, 16, QChar(u'0')));
            propertyObject.insert(QStringLiteral("hexPreview"), property.hexPreviewText);
            propertyObject.insert(QStringLiteral("fallback"), property.parseFallback);
            propertyArray.append(propertyObject);
        }
        rootObject.insert(QStringLiteral("properties"), propertyArray);

        if (!unparsedTailHexText.trimmed().isEmpty())
        {
            QJsonObject rawFallbackObject;
            rawFallbackObject.insert(QStringLiteral("note"), QStringLiteral("存在未解析尾部字节，已按十六进制保留"));
            rawFallbackObject.insert(QStringLiteral("hexDump"), unparsedTailHexText);
            rootObject.insert(QStringLiteral("rawFallback"), rawFallbackObject);
        }

        return QString::fromUtf8(QJsonDocument(rootObject).toJson(QJsonDocument::Compact));
    }

    QString etwPropertySingleLineValue(const EtwDecodedPropertyEntry* propertyPointer)
    {
        if (propertyPointer == nullptr)
        {
            return QString();
        }
        return etwSingleLineOrEmpty(propertyPointer->valueText);
    }

    bool etwPropertyToUInt32(const EtwDecodedPropertyEntry* propertyPointer, std::uint32_t* valueOut)
    {
        if (propertyPointer == nullptr || valueOut == nullptr)
        {
            return false;
        }
        if (propertyPointer->numericAvailable)
        {
            *valueOut = static_cast<std::uint32_t>(propertyPointer->numericValue);
            return true;
        }
        std::uint64_t parsedValue = 0;
        if (!tryParseUInt64Text(propertyPointer->valueText, parsedValue))
        {
            return false;
        }
        *valueOut = static_cast<std::uint32_t>(parsedValue & 0xFFFFFFFFULL);
        return true;
    }

    bool etwPropertyToUInt16(const EtwDecodedPropertyEntry* propertyPointer, std::uint16_t* valueOut)
    {
        std::uint32_t value32 = 0;
        if (!etwPropertyToUInt32(propertyPointer, &value32) || valueOut == nullptr || value32 > 65535U)
        {
            return false;
        }
        *valueOut = static_cast<std::uint16_t>(value32);
        return true;
    }

    void etwAssignIpFieldFromProperty(
        const EtwDecodedPropertyEntry* propertyPointer,
        QString* textOut,
        std::uint32_t* numericOut,
        bool* validOut)
    {
        if (textOut == nullptr || numericOut == nullptr || validOut == nullptr)
        {
            return;
        }
        *textOut = QString();
        *numericOut = 0;
        *validOut = false;
        if (propertyPointer == nullptr)
        {
            return;
        }

        QString ipText;
        if (propertyPointer->numericAvailable)
        {
            ipText = etwIpv4TextFromNumeric(static_cast<std::uint32_t>(propertyPointer->numericValue));
        }
        else
        {
            ipText = etwSingleLineOrEmpty(propertyPointer->valueText);
        }
        *textOut = ipText;
        std::uint32_t parsedIp = 0;
        if (tryParseIpv4Text(ipText, parsedIp))
        {
            *numericOut = parsedIp;
            *validOut = true;
        }
    }

    QString etwInferNetworkProtocol(
        const QString& providerNameText,
        const QString& eventNameText,
        const EtwDecodedPropertyEntry* protocolProperty)
    {
        const QString propertyText = etwPropertySingleLineValue(protocolProperty);
        if (!propertyText.isEmpty())
        {
            return propertyText;
        }

        const QString probe = (providerNameText + QLatin1Char(' ') + eventNameText).toLower();
        if (probe.contains(QStringLiteral("tcp")))
        {
            return QStringLiteral("TCP");
        }
        if (probe.contains(QStringLiteral("udp")))
        {
            return QStringLiteral("UDP");
        }
        if (probe.contains(QStringLiteral("dns")))
        {
            return QStringLiteral("DNS");
        }
        return QString();
    }

    QString etwInferNetworkDirection(
        const QString& eventNameText,
        const EtwDecodedPropertyEntry* directionProperty,
        const EtwDecodedPropertyEntry* opcodeProperty)
    {
        QString directionText = etwPropertySingleLineValue(directionProperty);
        if (!directionText.isEmpty())
        {
            return directionText;
        }

        directionText = etwPropertySingleLineValue(opcodeProperty);
        if (!directionText.isEmpty())
        {
            const QString lower = directionText.toLower();
            if (lower.contains(QStringLiteral("send")) || lower.contains(QStringLiteral("out")))
            {
                return QStringLiteral("Outbound");
            }
            if (lower.contains(QStringLiteral("recv")) || lower.contains(QStringLiteral("in")))
            {
                return QStringLiteral("Inbound");
            }
        }

        const QString eventLower = eventNameText.toLower();
        if (eventLower.contains(QStringLiteral("send")) || eventLower.contains(QStringLiteral("connect")))
        {
            return QStringLiteral("Outbound");
        }
        if (eventLower.contains(QStringLiteral("recv")) || eventLower.contains(QStringLiteral("accept")))
        {
            return QStringLiteral("Inbound");
        }
        return QString();
    }

    void fillEtwCapturedRowDecodedFields(
        MonitorDock::EtwCapturedEventRow* rowOut,
        const QString& providerNameText,
        const QString& eventNameText,
        const EtwSemanticSummary& semanticSummary,
        const std::vector<EtwDecodedPropertyEntry>& propertyList)
    {
        if (rowOut == nullptr)
        {
            return;
        }

        rowOut->resourceTypeText = etwSingleLineOrEmpty(semanticSummary.resourceTypeText);
        rowOut->actionText = etwSingleLineOrEmpty(semanticSummary.actionText);
        rowOut->targetText = etwSingleLineOrEmpty(semanticSummary.targetText);
        rowOut->statusText = etwSingleLineOrEmpty(semanticSummary.statusText);

        const EtwDecodedPropertyEntry* targetPidProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("targetprocessid"), QStringLiteral("processid"), QStringLiteral("pid") });
        rowOut->targetPidValid = etwPropertyToUInt32(targetPidProperty, &rowOut->targetPid);

        const EtwDecodedPropertyEntry* parentPidProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("parentprocessid"), QStringLiteral("parentid"), QStringLiteral("ppid") });
        rowOut->parentPidValid = etwPropertyToUInt32(parentPidProperty, &rowOut->parentPid);

        const EtwDecodedPropertyEntry* targetTidProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("targetthreadid"), QStringLiteral("threadid"), QStringLiteral("tid") });
        rowOut->targetTidValid = etwPropertyToUInt32(targetTidProperty, &rowOut->targetTid);

        rowOut->processNameText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("processname"), QStringLiteral("imagename"), QStringLiteral("imagefilename") }));
        rowOut->imagePathText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("imagename"), QStringLiteral("imagefilename"), QStringLiteral("path") }));
        rowOut->commandLineText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("commandline"), QStringLiteral("scriptblocktext") }));

        rowOut->filePathText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("filename"), QStringLiteral("filepath"), QStringLiteral("pathname"),
            QStringLiteral("targetfilename"), QStringLiteral("relativefilename"), QStringLiteral("targetname") }));
        if (rowOut->filePathText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("文件"))
        {
            rowOut->filePathText = rowOut->targetText;
        }
        rowOut->fileOldPathText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("oldfilename") }));
        rowOut->fileNewPathText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("newfilename"), QStringLiteral("targetfilename") }));
        rowOut->fileOperationText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("operation"), QStringLiteral("opcode") }));
        if (rowOut->fileOperationText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("文件"))
        {
            rowOut->fileOperationText = rowOut->actionText;
        }
        rowOut->fileStatusCodeText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("status"), QStringLiteral("ntstatus"), QStringLiteral("result"),
            QStringLiteral("hresult"), QStringLiteral("errorcode"), QStringLiteral("win32error") }));
        if (rowOut->fileStatusCodeText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("文件"))
        {
            rowOut->fileStatusCodeText = rowOut->statusText;
        }
        rowOut->fileAccessMaskText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("desiredaccess"), QStringLiteral("accessmask"), QStringLiteral("shareaccess") }));

        rowOut->registryKeyPathText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("keypath"), QStringLiteral("keyname"), QStringLiteral("hive"),
            QStringLiteral("objectname"), QStringLiteral("path") }));
        if (rowOut->registryKeyPathText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("注册表"))
        {
            rowOut->registryKeyPathText = rowOut->targetText;
        }
        rowOut->registryValueNameText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("valuename") }));
        rowOut->registryHiveText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("hive") }));
        rowOut->registryOperationText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("operation"), QStringLiteral("opcode") }));
        if (rowOut->registryOperationText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("注册表"))
        {
            rowOut->registryOperationText = rowOut->actionText;
        }
        rowOut->registryStatusText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("status"), QStringLiteral("ntstatus"), QStringLiteral("result"),
            QStringLiteral("hresult"), QStringLiteral("errorcode"), QStringLiteral("win32status") }));
        if (rowOut->registryStatusText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("注册表"))
        {
            rowOut->registryStatusText = rowOut->statusText;
        }

        const EtwDecodedPropertyEntry* sourceIpProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("sourceaddress"), QStringLiteral("saddr"), QStringLiteral("srcaddr") });
        const EtwDecodedPropertyEntry* destinationIpProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("destaddress"), QStringLiteral("daddr"), QStringLiteral("dstaddr") });
        etwAssignIpFieldFromProperty(
            sourceIpProperty,
            &rowOut->sourceIpText,
            &rowOut->sourceIpValue,
            &rowOut->sourceIpValid);
        etwAssignIpFieldFromProperty(
            destinationIpProperty,
            &rowOut->destinationIpText,
            &rowOut->destinationIpValue,
            &rowOut->destinationIpValid);

        rowOut->sourcePortValid = etwPropertyToUInt16(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("sourceport"), QStringLiteral("sport"), QStringLiteral("srcport") }),
            &rowOut->sourcePort);
        rowOut->destinationPortValid = etwPropertyToUInt16(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("destport"), QStringLiteral("dport"), QStringLiteral("dstport") }),
            &rowOut->destinationPort);

        rowOut->protocolText = etwInferNetworkProtocol(
            providerNameText,
            eventNameText,
            findFirstEtwProperty(propertyList, QStringList{ QStringLiteral("protocol"), QStringLiteral("ipprotocol") }));
        rowOut->directionText = etwInferNetworkDirection(
            eventNameText,
            findFirstEtwProperty(propertyList, QStringList{ QStringLiteral("direction") }),
            findFirstEtwProperty(propertyList, QStringList{ QStringLiteral("opcode"), QStringLiteral("operation") }));
        rowOut->domainText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("domainname"), QStringLiteral("queryname"), QStringLiteral("fqdn"), QStringLiteral("url") }));
        rowOut->hostText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("hostname"), QStringLiteral("host"), QStringLiteral("server") }));

        rowOut->auditResultText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("auditresult"), QStringLiteral("result"), QStringLiteral("status"),
            QStringLiteral("outcome"), QStringLiteral("ntstatus") }));
        if (rowOut->auditResultText.isEmpty())
        {
            rowOut->auditResultText = rowOut->statusText;
        }
        rowOut->userText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("username"), QStringLiteral("accountname"), QStringLiteral("user"),
            QStringLiteral("userid"), QStringLiteral("subjectusername") }));
        rowOut->sidText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("sid"), QStringLiteral("usersid"), QStringLiteral("subjectusersid") }));
        rowOut->securityPidValid = etwPropertyToUInt32(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("subjectprocessid"), QStringLiteral("processid"), QStringLiteral("pid") }),
            &rowOut->securityPid);
        if (!rowOut->securityPidValid && rowOut->headerPid != 0)
        {
            rowOut->securityPid = rowOut->headerPid;
            rowOut->securityPidValid = true;
        }
        rowOut->securityTidValid = etwPropertyToUInt32(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("threadid"), QStringLiteral("tid"), QStringLiteral("subjectthreadid") }),
            &rowOut->securityTid);
        if (!rowOut->securityTidValid && rowOut->headerTid != 0)
        {
            rowOut->securityTid = rowOut->headerTid;
            rowOut->securityTidValid = true;
        }
        rowOut->securityLevelText = rowOut->levelText;

        rowOut->scriptHostProcessText = rowOut->processNameText;
        if (rowOut->scriptHostProcessText.isEmpty())
        {
            rowOut->scriptHostProcessText = rowOut->imagePathText;
        }
        rowOut->scriptKeywordText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("scriptblocktext"), QStringLiteral("commandline"),
            QStringLiteral("query"), QStringLiteral("querytext") }));
        rowOut->scriptTaskNameText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("taskname"), QStringLiteral("scheduledtaskname"), QStringLiteral("task") }));
        rowOut->wmiClassNameText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("classname"), QStringLiteral("class"), QStringLiteral("wmiclass") }));
        rowOut->wmiNamespaceText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("namespace"), QStringLiteral("wminamespace") }));

        rowOut->decodedReady = true;
    }

    // 100ns 时间戳文本格式化：直接输出 FILETIME 基准整数，满足计划要求。
    QString etwTimestamp100nsText(const EVENT_RECORD* eventRecord)
    {
        if (eventRecord == nullptr)
        {
            return now100nsText();
        }
        return QString::number(static_cast<qulonglong>(eventRecord->EventHeader.TimeStamp.QuadPart));
    }

    // buildEtwRowDetailText：
    // - 作用：把 ETW 事件表某一行格式化为可读详情文本；
    // - 调用：右键“查看返回详情”和双击事件行时复用。
    QString buildEtwRowDetailText(QTableWidget* eventTable, const int row)
    {
        if (eventTable == nullptr || row < 0 || row >= eventTable->rowCount())
        {
            return QString();
        }

        const auto itemTextAt = [eventTable, row](const int column) -> QString {
            QTableWidgetItem* itemPointer = eventTable->item(row, column);
            return itemPointer != nullptr ? itemPointer->text() : QString();
        };

        QString detailJsonText;
        QTableWidgetItem* detailItem = eventTable->item(row, 5);
        if (detailItem != nullptr)
        {
            const QString detailFromRole = detailItem->data(Qt::UserRole).toString();
            detailJsonText = detailFromRole.trimmed().isEmpty() ? detailItem->text() : detailFromRole;
        }
        QString normalizedDetailText = detailJsonText;
        QString semanticResourceText;
        QString semanticActionText;
        QString semanticTargetText;
        QString semanticStatusText;
        if (!detailJsonText.trimmed().isEmpty())
        {
            QJsonParseError parseError;
            const QJsonDocument jsonDocument = QJsonDocument::fromJson(detailJsonText.toUtf8(), &parseError);
            if (!jsonDocument.isNull() && jsonDocument.isObject())
            {
                normalizedDetailText = QString::fromUtf8(jsonDocument.toJson(QJsonDocument::Indented));

                const QJsonObject rootObject = jsonDocument.object();
                const QJsonObject semanticObject = rootObject.value(QStringLiteral("semantic")).toObject();
                semanticResourceText = semanticObject.value(QStringLiteral("resourceType")).toString();
                semanticActionText = semanticObject.value(QStringLiteral("action")).toString();
                semanticTargetText = semanticObject.value(QStringLiteral("target")).toString();
                semanticStatusText = semanticObject.value(QStringLiteral("status")).toString();
            }
        }

        QString contentText;
        contentText += QStringLiteral("时间(100ns)：%1\n").arg(itemTextAt(0));
        contentText += QStringLiteral("Provider：%1\n").arg(itemTextAt(1));
        contentText += QStringLiteral("事件ID：%1\n").arg(itemTextAt(2));
        contentText += QStringLiteral("事件名：%1\n").arg(itemTextAt(3));
        contentText += QStringLiteral("PID / TID：%1\n").arg(itemTextAt(4));
        contentText += QStringLiteral("ActivityId：%1\n").arg(itemTextAt(6));
        if (!semanticResourceText.trimmed().isEmpty()
            || !semanticActionText.trimmed().isEmpty()
            || !semanticTargetText.trimmed().isEmpty()
            || !semanticStatusText.trimmed().isEmpty())
        {
            contentText += QStringLiteral("\n========== 语义摘要 ==========\n");
            contentText += QStringLiteral("资源类型：%1\n").arg(
                semanticResourceText.trimmed().isEmpty() ? QStringLiteral("<未知>") : semanticResourceText);
            contentText += QStringLiteral("动作：%1\n").arg(
                semanticActionText.trimmed().isEmpty() ? QStringLiteral("<未知>") : semanticActionText);
            contentText += QStringLiteral("目标：%1\n").arg(
                semanticTargetText.trimmed().isEmpty() ? QStringLiteral("<未知>") : semanticTargetText);
            contentText += QStringLiteral("状态：%1\n").arg(
                semanticStatusText.trimmed().isEmpty() ? QStringLiteral("<未知>") : semanticStatusText);
        }
        contentText += QStringLiteral("\n========== 返回详情 ==========\n");
        contentText += normalizedDetailText.trimmed().isEmpty() ? QStringLiteral("<空>") : normalizedDetailText;
        return contentText;
    }

    // buildWmiRowDetailText：
    // - 作用：把 WMI 结果表某一行格式化为可读详情文本；
    // - 调用：右键“查看返回详情”、双击事件行和文本查看窗口复用。
    QString buildWmiRowDetailText(QTableWidget* eventTable, const int row)
    {
        if (eventTable == nullptr || row < 0 || row >= eventTable->rowCount())
        {
            return QString();
        }

        const auto itemTextAt = [eventTable, row](const int column) -> QString {
            QTableWidgetItem* itemPointer = eventTable->item(row, column);
            return itemPointer != nullptr ? itemPointer->text() : QString();
        };

        QString contentText;
        contentText += QStringLiteral("时间戳：%1\n").arg(itemTextAt(0));
        contentText += QStringLiteral("事件来源：%1\n").arg(itemTextAt(1));
        contentText += QStringLiteral("事件类：%1\n").arg(itemTextAt(2));
        contentText += QStringLiteral("PID / 进程：%1\n").arg(itemTextAt(3));
        contentText += QStringLiteral("\n========== 返回详情 ==========\n");
        contentText += itemTextAt(4).trimmed().isEmpty() ? QStringLiteral("<空>") : itemTextAt(4);
        return contentText;
    }
}

MonitorDock::MonitorDock(QWidget* parent)
    : QWidget(parent)
{
    kLogEvent event;
    info << event << "[MonitorDock] 构造开始。" << eol;

    initializeUi();
    initializeConnections();

    // 顶部四宫格性能图已迁移到“监视面板”Dock（MonitorPanelWidget），
    // 当前 MonitorDock 仅负责 WMI/ETW 实时监控逻辑。

    // WMI 事件表刷新节流：后台线程先入队，主线程按 100ms 批量刷入，避免事件风暴卡 UI。
    m_wmiUiUpdateTimer = new QTimer(this);
    m_wmiUiUpdateTimer->setInterval(100);
    connect(m_wmiUiUpdateTimer, &QTimer::timeout, this, [this]() {
        flushWmiPendingRows();
    });

    kLogEvent finishEvent;
    info << finishEvent << "[MonitorDock] 构造完成。" << eol;
}

void MonitorDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    // 首次显示只触发当前子页所需的发现任务：
    // - 默认停留在“进程定向”时不拉起 WMI/ETW 枚举；
    // - 用户切到 WMI/ETW 页时再后台刷新，避免首次点击 MonitorDock 后并发启动四路发现。
    QTimer::singleShot(80, this, [this]()
    {
        triggerDeferredDiscoveryForCurrentTab();
    });
}

bool MonitorDock::event(QEvent* eventPointer)
{
    // 主题切换会更新全局 palette，折叠面板使用动态样式表，需要在事件到达时重新拼接。
    const bool handled = QWidget::event(eventPointer);
    if (eventPointer != nullptr
        && (eventPointer->type() == QEvent::PaletteChange
            || eventPointer->type() == QEvent::ApplicationPaletteChange
            || eventPointer->type() == QEvent::StyleChange))
    {
        refreshIndependentCollapseTheme(m_wmiPage);
        refreshIndependentCollapseTheme(m_etwPage);
        updateEtwCollapseHeight();
    }
    return handled;
}

void MonitorDock::ensureDirectKernelCallTabInitialized()
{
    if (m_directKernelCallWidget != nullptr || m_directKernelCallHostPage == nullptr)
    {
        return;
    }

    QVBoxLayout* hostLayout = qobject_cast<QVBoxLayout*>(m_directKernelCallHostPage->layout());
    if (hostLayout == nullptr)
    {
        hostLayout = new QVBoxLayout(m_directKernelCallHostPage);
        hostLayout->setContentsMargins(0, 0, 0, 0);
        hostLayout->setSpacing(0);
    }

    // 清理占位控件：直接内核调用页会在构造时解析 syscall 映射，按需创建可避开 MonitorDock 首次点击。
    while (QLayoutItem* itemPointer = hostLayout->takeAt(0))
    {
        QWidget* itemWidget = itemPointer->widget();
        if (itemWidget != nullptr)
        {
            itemWidget->deleteLater();
        }
        delete itemPointer;
    }

    m_directKernelCallWidget = new DirectKernelCallMonitorWidget(m_directKernelCallHostPage);
    hostLayout->addWidget(m_directKernelCallWidget, 1);
}

void MonitorDock::ensureKernelCallbackTabInitialized()
{
    if (m_kernelCallbackWidget != nullptr || m_kernelCallbackHostPage == nullptr)
    {
        return;
    }

    QVBoxLayout* hostLayout = qobject_cast<QVBoxLayout*>(m_kernelCallbackHostPage->layout());
    if (hostLayout == nullptr)
    {
        hostLayout = new QVBoxLayout(m_kernelCallbackHostPage);
        hostLayout->setContentsMargins(0, 0, 0, 0);
        hostLayout->setSpacing(0);
    }
    while (QLayoutItem* itemPointer = hostLayout->takeAt(0))
    {
        if (QWidget* itemWidget = itemPointer->widget(); itemWidget != nullptr)
        {
            itemWidget->deleteLater();
        }
        delete itemPointer;
    }

    m_kernelCallbackWidget = new KernelCallbackMonitorWidget(m_kernelCallbackHostPage);
    hostLayout->addWidget(m_kernelCallbackWidget, 1);
}

void MonitorDock::ensureWinApiTabInitialized()
{
    if (m_winApiPage == nullptr)
    {
        return;
    }

    if (m_winApiWidget == nullptr)
    {
        QVBoxLayout* hostLayout = qobject_cast<QVBoxLayout*>(m_winApiPage->layout());
        if (hostLayout == nullptr)
        {
            hostLayout = new QVBoxLayout(m_winApiPage);
            hostLayout->setContentsMargins(0, 0, 0, 0);
            hostLayout->setSpacing(0);
        }

        m_winApiWidget = new WinAPIDock(m_winApiPage);
        hostLayout->addWidget(m_winApiWidget, 1);
    }

    m_winApiWidget->notifyPageActivated();
}

void MonitorDock::triggerDeferredDiscoveryForCurrentTab()
{
    if (m_sideTabWidget == nullptr)
    {
        return;
    }

    QWidget* currentPage = m_sideTabWidget->currentWidget();
    if (currentPage == m_wmiPage && !m_wmiInitialDiscoveryDone)
    {
        m_wmiInitialDiscoveryDone = true;
        refreshWmiProvidersAsync();
        refreshWmiEventClassesAsync();
        return;
    }

    if (currentPage == m_etwPage && !m_etwInitialDiscoveryDone)
    {
        m_etwInitialDiscoveryDone = true;
        refreshEtwProvidersAsync();
        refreshEtwSessionsAsync();
        return;
    }

    if (currentPage == m_arkRiskCenterPage && !m_arkRiskCenterInitialDiscoveryDone)
    {
        m_arkRiskCenterInitialDiscoveryDone = true;
        refreshArkRiskCenterAsync();
    }
}

void MonitorDock::activateMonitorTab(const QString& tabKey)
{
    if (m_sideTabWidget == nullptr)
    {
        return;
    }

    const QString normalizedKey = tabKey.trimmed().toLower();
    if (normalizedKey == QStringLiteral("kernel-callback")
        || normalizedKey == QStringLiteral("kernelcallback")
        || normalizedKey == QStringLiteral("callback"))
    {
        if (m_kernelCallbackHostPage != nullptr)
        {
            m_sideTabWidget->setCurrentWidget(m_kernelCallbackHostPage);
            QTimer::singleShot(0, this, [this]()
            {
                ensureKernelCallbackTabInitialized();
            });
        }
        return;
    }
    if (normalizedKey == QStringLiteral("direct-kernel-call")
        || normalizedKey == QStringLiteral("directkernelcall")
        || normalizedKey == QStringLiteral("syscall"))
    {
        if (m_directKernelCallHostPage != nullptr)
        {
            m_sideTabWidget->setCurrentWidget(m_directKernelCallHostPage);
            // 程序化跳转也保持“先切页、后加载”，避免启动默认页配置为 syscall 时阻塞主窗口。
            QTimer::singleShot(0, this, [this]()
            {
                ensureDirectKernelCallTabInitialized();
            });
        }
        return;
    }
    if (normalizedKey == QStringLiteral("winapi"))
    {
        ensureWinApiTabInitialized();
        if (m_winApiPage != nullptr)
        {
            m_sideTabWidget->setCurrentWidget(m_winApiPage);
        }
        return;
    }
    if (normalizedKey == QStringLiteral("wmi"))
    {
        if (m_wmiPage != nullptr)
        {
            m_sideTabWidget->setCurrentWidget(m_wmiPage);
        }
        return;
    }
    if (normalizedKey == QStringLiteral("etw"))
    {
        if (m_etwPage != nullptr)
        {
            m_sideTabWidget->setCurrentWidget(m_etwPage);
        }
        return;
    }
    if (normalizedKey == QStringLiteral("ark-risk") ||
        normalizedKey == QStringLiteral("risk") ||
        normalizedKey == QStringLiteral("ark-risk-center"))
    {
        if (m_arkRiskCenterPage != nullptr)
        {
            m_sideTabWidget->setCurrentWidget(m_arkRiskCenterPage);
        }
        return;
    }

    if (m_processTraceWidget != nullptr)
    {
        m_sideTabWidget->setCurrentWidget(m_processTraceWidget);
    }
}

MonitorDock::~MonitorDock()
{
    // 析构阶段必须同步等待线程退出，防止对象释放后后台线程仍访问成员。
    stopWmiSubscriptionInternal(true);
    stopEtwCaptureInternal(true);
    cancelAndWaitEtwArchiveBackgroundTasks();

    if (m_wmiUiUpdateTimer != nullptr)
    {
        m_wmiUiUpdateTimer->stop();
    }

    if (m_etwUiUpdateTimer != nullptr)
    {
        m_etwUiUpdateTimer->stop();
    }

    if (m_perfUpdateTimer != nullptr)
    {
        m_perfUpdateTimer->stop();
    }

    // 析构时释放 PDH 查询句柄，避免系统计数器句柄泄漏。
    if (m_diskPerfQueryHandle != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_diskPerfQueryHandle));
        m_diskPerfQueryHandle = nullptr;
        m_diskReadCounterHandle = nullptr;
        m_diskWriteCounterHandle = nullptr;
    }
}

void MonitorDock::initializeUi()
{
    // 根布局和总 Tab：
    // - 监控页本体包含“进程定向 / WinAPI / WMI / ETW”四个标签；
    // - 性能四宫格图已经独立到左下角“监视面板”Dock。
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(6);

    m_sideTabWidget = new QTabWidget(this);
    m_rootLayout->addWidget(m_sideTabWidget, 1);

    m_processTraceWidget = new ProcessTraceMonitorWidget(m_sideTabWidget);
    m_sideTabWidget->addTab(
        m_processTraceWidget,
        QIcon(QStringLiteral(":/Icon/process_main.svg")),
        QStringLiteral("进程定向"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_processTraceWidget, QStringLiteral("monitor.tab.process_trace"), QStringLiteral("进程定向"));

    m_kernelCallbackHostPage = new QWidget(m_sideTabWidget);
    QVBoxLayout* kernelCallbackHostLayout = new QVBoxLayout(m_kernelCallbackHostPage);
    kernelCallbackHostLayout->setContentsMargins(0, 0, 0, 0);
    kernelCallbackHostLayout->setSpacing(0);
    kernelCallbackHostLayout->addWidget(
        createMonitorDeferredPlaceholder(
            m_kernelCallbackHostPage,
            QStringLiteral("内核回调监控待加载"),
            QStringLiteral("切换到本页后再连接驱动并创建回调事件界面。")),
        1);
    m_sideTabWidget->addTab(
        m_kernelCallbackHostPage,
        QIcon(QStringLiteral(":/Icon/process_threads.svg")),
        QStringLiteral("内核回调"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget,
        m_kernelCallbackHostPage,
        QStringLiteral("monitor.tab.kernel_callback"),
        QStringLiteral("内核回调"));

    m_directKernelCallHostPage = new QWidget(m_sideTabWidget);
    QVBoxLayout* directKernelCallHostLayout = new QVBoxLayout(m_directKernelCallHostPage);
    directKernelCallHostLayout->setContentsMargins(0, 0, 0, 0);
    directKernelCallHostLayout->setSpacing(0);
    directKernelCallHostLayout->addWidget(
        createMonitorDeferredPlaceholder(
            m_directKernelCallHostPage,
            QStringLiteral("直接内核调用待加载"),
            QStringLiteral("切换到本页后再解析 syscall 映射并创建 ETW 采集界面。")),
        1);
    m_sideTabWidget->addTab(
        m_directKernelCallHostPage,
        QIcon(QStringLiteral(":/Icon/process_threads.svg")),
        QStringLiteral("直接内核调用"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget,
        m_directKernelCallHostPage,
        QStringLiteral("monitor.tab.direct_kernel_call"),
        QStringLiteral("直接内核调用"));

    m_winApiPage = new QWidget(m_sideTabWidget);
    QVBoxLayout* winApiPageLayout = new QVBoxLayout(m_winApiPage);
    winApiPageLayout->setContentsMargins(0, 0, 0, 0);
    winApiPageLayout->setSpacing(0);
    m_sideTabWidget->addTab(
        m_winApiPage,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("WinAPI"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_winApiPage, QStringLiteral("monitor.tab.winapi"), QStringLiteral("WinAPI"));

    initializeWmiTab();
    initializeEtwTab();
    initializeArkRiskCenterTab();
}

void MonitorDock::initializePerformancePanel()
{
    // 顶部性能面板：2x2 布局展示 CPU/内存条形图 + 磁盘/网络折线图。
    m_perfPanel = new QWidget(this);
    m_perfPanelLayout = new QGridLayout(m_perfPanel);
    m_perfPanelLayout->setContentsMargins(0, 0, 0, 0);
    m_perfPanelLayout->setHorizontalSpacing(6);
    m_perfPanelLayout->setVerticalSpacing(6);
    m_rootLayout->addWidget(m_perfPanel, 0);

    auto createBarChartView = [this](const QString& titleText, const QColor& barColor, QBarSet** barSetOut, QChartView** chartViewOut) {
        QBarSet* barSet = new QBarSet(QStringLiteral("Usage"));
        barSet->append(0.0);
        barSet->setColor(barColor);
        barSet->setBorderColor(barColor);

        QBarSeries* barSeries = new QBarSeries();
        barSeries->append(barSet);

        QChart* chart = new QChart();
        chart->addSeries(barSeries);
        chart->setTitle(titleText);
        chart->legend()->hide();
        chart->setBackgroundRoundness(0);
        chart->setBackgroundVisible(false);
        chart->setMargins(QMargins(0, 0, 0, 0));

        QBarCategoryAxis* axisX = new QBarCategoryAxis(chart);
        axisX->append(QStringList{ ks::i18n::sourceText(QStringLiteral("当前")) });
        axisX->setLabelsVisible(false);
        axisX->setGridLineVisible(false);

        QValueAxis* axisY = new QValueAxis(chart);
        axisY->setRange(0.0, 100.0);
        axisY->setLabelsVisible(false);
        axisY->setGridLineVisible(false);
        axisY->setMinorGridLineVisible(false);

        chart->addAxis(axisX, Qt::AlignBottom);
        chart->addAxis(axisY, Qt::AlignLeft);
        barSeries->attachAxis(axisX);
        barSeries->attachAxis(axisY);

        QChartView* chartView = new QChartView(chart, m_perfPanel);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setMinimumHeight(140);
        chartView->setFrameShape(QFrame::NoFrame);

        if (barSetOut != nullptr)
        {
            *barSetOut = barSet;
        }
        if (chartViewOut != nullptr)
        {
            *chartViewOut = chartView;
        }
    };

    auto createLineChartView =
        [this](const QString& titleText,
            const QColor& firstColor,
            const QColor& secondColor,
            const QString& firstSeriesName,
            const QString& secondSeriesName,
            QLineSeries** firstSeriesOut,
            QLineSeries** secondSeriesOut,
            QValueAxis** axisXOut,
            QValueAxis** axisYOut,
            QChartView** chartViewOut) {
        QLineSeries* firstSeries = new QLineSeries();
        firstSeries->setName(firstSeriesName);
        firstSeries->setColor(firstColor);

        QLineSeries* secondSeries = new QLineSeries();
        secondSeries->setName(secondSeriesName);
        secondSeries->setColor(secondColor);

        QChart* chart = new QChart();
        chart->addSeries(firstSeries);
        chart->addSeries(secondSeries);
        chart->setAnimationOptions(QChart::AllAnimations);
        chart->setAnimationDuration(260);
        chart->setAnimationEasingCurve(QEasingCurve::OutCubic);
        chart->setTitle(titleText);
        chart->legend()->setVisible(true);
        chart->legend()->setAlignment(Qt::AlignTop);
        chart->setBackgroundRoundness(0);
        chart->setBackgroundVisible(false);
        chart->setMargins(QMargins(0, 0, 0, 0));

        QValueAxis* axisX = new QValueAxis(chart);
        axisX->setRange(0, m_perfHistoryLength - 1);
        axisX->setLabelFormat(QStringLiteral("%d"));
        axisX->setLabelsVisible(false);
        axisX->setGridLineVisible(false);
        axisX->setMinorGridLineVisible(false);

        QValueAxis* axisY = new QValueAxis(chart);
        axisY->setRange(0.0, 1.0);
        axisY->setLabelFormat(QStringLiteral("%.0f"));
        axisY->setLabelsVisible(false);
        axisY->setGridLineVisible(false);
        axisY->setMinorGridLineVisible(false);

        chart->addAxis(axisX, Qt::AlignBottom);
        chart->addAxis(axisY, Qt::AlignLeft);
        firstSeries->attachAxis(axisX);
        firstSeries->attachAxis(axisY);
        secondSeries->attachAxis(axisX);
        secondSeries->attachAxis(axisY);

        QChartView* chartView = new QChartView(chart, m_perfPanel);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setMinimumHeight(140);
        chartView->setFrameShape(QFrame::NoFrame);

        if (firstSeriesOut != nullptr)
        {
            *firstSeriesOut = firstSeries;
        }
        if (secondSeriesOut != nullptr)
        {
            *secondSeriesOut = secondSeries;
        }
        if (axisXOut != nullptr)
        {
            *axisXOut = axisX;
        }
        if (axisYOut != nullptr)
        {
            *axisYOut = axisY;
        }
        if (chartViewOut != nullptr)
        {
            *chartViewOut = chartView;
        }
    };

    createBarChartView(
        ks::i18n::sourceText(QStringLiteral("CPU 占用率")),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Cpu),
        &m_cpuBarSet,
        &m_cpuChartView);
    createBarChartView(
        ks::i18n::sourceText(QStringLiteral("内存利用率")),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Memory),
        &m_memoryBarSet,
        &m_memoryChartView);
    createLineChartView(
        ks::i18n::sourceText(QStringLiteral("系统盘读写速率")),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Read),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Write),
        ks::i18n::sourceText(QStringLiteral("读取")),
        ks::i18n::sourceText(QStringLiteral("写入")),
        &m_diskReadSeries,
        &m_diskWriteSeries,
        &m_diskAxisX,
        &m_diskAxisY,
        &m_diskChartView);
    createLineChartView(
        ks::i18n::sourceText(QStringLiteral("网络收发速率")),
        KswordTheme::SuccessColor(),
        KswordTheme::ErrorColor(),
        ks::i18n::sourceText(QStringLiteral("下载")),
        ks::i18n::sourceText(QStringLiteral("上传")),
        &m_networkRxSeries,
        &m_networkTxSeries,
        &m_networkAxisX,
        &m_networkAxisY,
        &m_networkChartView);

    // 折线图预填 0 值，启动后曲线从左到右平滑滚动。
    for (int indexValue = 0; indexValue < m_perfHistoryLength; ++indexValue)
    {
        m_diskReadSeries->append(indexValue, 0.0);
        m_diskWriteSeries->append(indexValue, 0.0);
        m_networkRxSeries->append(indexValue, 0.0);
        m_networkTxSeries->append(indexValue, 0.0);
    }

    m_perfPanelLayout->addWidget(m_cpuChartView, 0, 0);
    m_perfPanelLayout->addWidget(m_memoryChartView, 0, 1);
    m_perfPanelLayout->addWidget(m_diskChartView, 1, 0);
    m_perfPanelLayout->addWidget(m_networkChartView, 1, 1);
}

void MonitorDock::appendLineSample(
    QLineSeries* series,
    QValueAxis* axisX,
    QValueAxis* axisY,
    const double value)
{
    if (series == nullptr || axisX == nullptr || axisY == nullptr)
    {
        return;
    }

    series->append(m_perfSampleCounter, value);
    while (series->count() > m_perfHistoryLength)
    {
        series->remove(0);
    }

    const QList<QPointF> pointList = series->points();
    if (pointList.isEmpty())
    {
        return;
    }

    const double minX = pointList.first().x();
    const double maxX = pointList.last().x();
    axisX->setRange(minX, std::max(maxX, minX + 1.0));

    double yMaxValue = 1.0;
    for (const QPointF& pointValue : pointList)
    {
        yMaxValue = std::max(yMaxValue, pointValue.y());
    }
    axisY->setRange(0.0, yMaxValue * 1.2);
}

bool MonitorDock::sampleCpuUsage(double* cpuUsageOut)
{
    if (cpuUsageOut == nullptr)
    {
        return false;
    }

    FILETIME idleTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (::GetSystemTimes(&idleTime, &kernelTime, &userTime) == FALSE)
    {
        return false;
    }

    const std::uint64_t idleValue = fileTimeToUint64(idleTime);
    const std::uint64_t kernelValue = fileTimeToUint64(kernelTime);
    const std::uint64_t userValue = fileTimeToUint64(userTime);

    if (!m_cpuSampleValid)
    {
        m_lastCpuIdleTime = idleValue;
        m_lastCpuKernelTime = kernelValue;
        m_lastCpuUserTime = userValue;
        m_cpuSampleValid = true;
        *cpuUsageOut = 0.0;
        return true;
    }

    const std::uint64_t deltaIdle = idleValue - m_lastCpuIdleTime;
    const std::uint64_t deltaKernel = kernelValue - m_lastCpuKernelTime;
    const std::uint64_t deltaUser = userValue - m_lastCpuUserTime;
    const std::uint64_t deltaTotal = deltaKernel + deltaUser;

    m_lastCpuIdleTime = idleValue;
    m_lastCpuKernelTime = kernelValue;
    m_lastCpuUserTime = userValue;

    if (deltaTotal == 0)
    {
        *cpuUsageOut = 0.0;
        return true;
    }

    const double usagePercent = (1.0 - static_cast<double>(deltaIdle) / static_cast<double>(deltaTotal)) * 100.0;
    *cpuUsageOut = std::clamp(usagePercent, 0.0, 100.0);
    return true;
}

bool MonitorDock::sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut)
{
    if (readBytesPerSecOut == nullptr || writeBytesPerSecOut == nullptr)
    {
        return false;
    }

    if (m_diskPerfQueryHandle == nullptr)
    {
        PDH_HQUERY queryHandle = nullptr;
        if (::PdhOpenQueryW(nullptr, 0, &queryHandle) != ERROR_SUCCESS || queryHandle == nullptr)
        {
            return false;
        }

        PDH_HCOUNTER readCounter = nullptr;
        PDH_HCOUNTER writeCounter = nullptr;
        const PDH_STATUS addReadStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
            0,
            &readCounter);
        const PDH_STATUS addWriteStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
            0,
            &writeCounter);

        if (addReadStatus != ERROR_SUCCESS || addWriteStatus != ERROR_SUCCESS)
        {
            ::PdhCloseQuery(queryHandle);
            return false;
        }

        m_diskPerfQueryHandle = queryHandle;
        m_diskReadCounterHandle = readCounter;
        m_diskWriteCounterHandle = writeCounter;

        // 首次采样先 collect 一次，下一次再取稳定数据。
        ::PdhCollectQueryData(queryHandle);
        return false;
    }

    const PDH_HQUERY queryHandle = reinterpret_cast<PDH_HQUERY>(m_diskPerfQueryHandle);
    const PDH_STATUS collectStatus = ::PdhCollectQueryData(queryHandle);
    if (collectStatus != ERROR_SUCCESS)
    {
        return false;
    }

    PDH_FMT_COUNTERVALUE readValue{};
    PDH_FMT_COUNTERVALUE writeValue{};
    const PDH_STATUS readStatus = ::PdhGetFormattedCounterValue(
        reinterpret_cast<PDH_HCOUNTER>(m_diskReadCounterHandle),
        PDH_FMT_DOUBLE,
        nullptr,
        &readValue);
    const PDH_STATUS writeStatus = ::PdhGetFormattedCounterValue(
        reinterpret_cast<PDH_HCOUNTER>(m_diskWriteCounterHandle),
        PDH_FMT_DOUBLE,
        nullptr,
        &writeValue);

    if (readStatus != ERROR_SUCCESS || writeStatus != ERROR_SUCCESS)
    {
        return false;
    }

    *readBytesPerSecOut = std::max(0.0, readValue.doubleValue);
    *writeBytesPerSecOut = std::max(0.0, writeValue.doubleValue);
    return true;
}

bool MonitorDock::sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut)
{
    if (rxBytesPerSecOut == nullptr || txBytesPerSecOut == nullptr)
    {
        return false;
    }

    MIB_IF_TABLE2* tablePointer = nullptr;
    const DWORD tableStatus = ::GetIfTable2(&tablePointer);
    if (tableStatus != NO_ERROR || tablePointer == nullptr)
    {
        return false;
    }

    std::uint64_t totalRxBytes = 0;
    std::uint64_t totalTxBytes = 0;
    for (ULONG rowIndex = 0; rowIndex < tablePointer->NumEntries; ++rowIndex)
    {
        const MIB_IF_ROW2& rowValue = tablePointer->Table[rowIndex];
        if (rowValue.OperStatus != IfOperStatusUp)
        {
            continue;
        }
        if (rowValue.Type == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            continue;
        }
        totalRxBytes += static_cast<std::uint64_t>(rowValue.InOctets);
        totalTxBytes += static_cast<std::uint64_t>(rowValue.OutOctets);
    }
    ::FreeMibTable(tablePointer);

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    if (m_lastNetworkSampleMs <= 0)
    {
        m_lastNetworkSampleMs = nowMs;
        m_lastNetworkRxBytes = totalRxBytes;
        m_lastNetworkTxBytes = totalTxBytes;
        *rxBytesPerSecOut = 0.0;
        *txBytesPerSecOut = 0.0;
        return true;
    }

    const qint64 elapsedMs = nowMs - m_lastNetworkSampleMs;
    if (elapsedMs <= 0)
    {
        return false;
    }

    const std::uint64_t deltaRx = totalRxBytes >= m_lastNetworkRxBytes
        ? (totalRxBytes - m_lastNetworkRxBytes)
        : 0;
    const std::uint64_t deltaTx = totalTxBytes >= m_lastNetworkTxBytes
        ? (totalTxBytes - m_lastNetworkTxBytes)
        : 0;

    m_lastNetworkSampleMs = nowMs;
    m_lastNetworkRxBytes = totalRxBytes;
    m_lastNetworkTxBytes = totalTxBytes;

    *rxBytesPerSecOut = static_cast<double>(deltaRx) * 1000.0 / static_cast<double>(elapsedMs);
    *txBytesPerSecOut = static_cast<double>(deltaTx) * 1000.0 / static_cast<double>(elapsedMs);
    return true;
}

void MonitorDock::refreshPerformanceCharts()
{
    // 采样 CPU 与内存：条形图只展示当前瞬时值。
    double cpuUsagePercent = 0.0;
    if (!sampleCpuUsage(&cpuUsagePercent))
    {
        cpuUsagePercent = 0.0;
    }
    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    const bool memoryOk = ::GlobalMemoryStatusEx(&memoryStatus) != FALSE;
    const double memoryUsagePercent = memoryOk ? static_cast<double>(memoryStatus.dwMemoryLoad) : 0.0;

    if (m_cpuBarSet != nullptr)
    {
        m_cpuBarSet->replace(0, cpuUsagePercent);
    }
    if (m_memoryBarSet != nullptr)
    {
        m_memoryBarSet->replace(0, memoryUsagePercent);
    }

    if (m_cpuChartView != nullptr && m_cpuChartView->chart() != nullptr)
    {
        m_cpuChartView->chart()->setTitle(
            ks::i18n::sourceText(QStringLiteral("CPU 占用率 %1%"))
                .arg(cpuUsagePercent, 0, 'f', 1));
    }
    if (m_memoryChartView != nullptr && m_memoryChartView->chart() != nullptr)
    {
        m_memoryChartView->chart()->setTitle(
            ks::i18n::sourceText(QStringLiteral("内存利用率 %1%"))
                .arg(memoryUsagePercent, 0, 'f', 1));
    }

    // 图例不属于 QWidget 翻译树，在每轮采样时按当前语言重写。
    if (m_diskReadSeries != nullptr)
    {
        m_diskReadSeries->setName(ks::i18n::sourceText(QStringLiteral("读取")));
    }
    if (m_diskWriteSeries != nullptr)
    {
        m_diskWriteSeries->setName(ks::i18n::sourceText(QStringLiteral("写入")));
    }
    if (m_networkRxSeries != nullptr)
    {
        m_networkRxSeries->setName(ks::i18n::sourceText(QStringLiteral("下载")));
    }
    if (m_networkTxSeries != nullptr)
    {
        m_networkTxSeries->setName(ks::i18n::sourceText(QStringLiteral("上传")));
    }

    // 采样磁盘与网络：折线图展示最近 m_perfHistoryLength 个采样点。
    double diskReadBytesPerSec = 0.0;
    double diskWriteBytesPerSec = 0.0;
    if (!sampleDiskRate(&diskReadBytesPerSec, &diskWriteBytesPerSec))
    {
        diskReadBytesPerSec = 0.0;
        diskWriteBytesPerSec = 0.0;
    }

    double networkRxBytesPerSec = 0.0;
    double networkTxBytesPerSec = 0.0;
    if (!sampleNetworkRate(&networkRxBytesPerSec, &networkTxBytesPerSec))
    {
        networkRxBytesPerSec = 0.0;
        networkTxBytesPerSec = 0.0;
    }

    ++m_perfSampleCounter;
    appendLineSample(m_diskReadSeries, m_diskAxisX, m_diskAxisY, diskReadBytesPerSec);
    appendLineSample(m_diskWriteSeries, m_diskAxisX, m_diskAxisY, diskWriteBytesPerSec);
    appendLineSample(m_networkRxSeries, m_networkAxisX, m_networkAxisY, networkRxBytesPerSec);
    appendLineSample(m_networkTxSeries, m_networkAxisX, m_networkAxisY, networkTxBytesPerSec);

    // 轴范围取两条线最大值，确保读/写、上/下行都完整显示。
    auto updateAxisRangeByPair = [this](QLineSeries* firstSeries, QLineSeries* secondSeries, QValueAxis* axisY) {
        if (firstSeries == nullptr || secondSeries == nullptr || axisY == nullptr)
        {
            return;
        }
        double maxValue = 1.0;
        const QList<QPointF> firstPoints = firstSeries->points();
        const QList<QPointF> secondPoints = secondSeries->points();
        for (const QPointF& pointValue : firstPoints)
        {
            maxValue = std::max(maxValue, pointValue.y());
        }
        for (const QPointF& pointValue : secondPoints)
        {
            maxValue = std::max(maxValue, pointValue.y());
        }
        axisY->setRange(0.0, maxValue * 1.2);
    };
    updateAxisRangeByPair(m_diskReadSeries, m_diskWriteSeries, m_diskAxisY);
    updateAxisRangeByPair(m_networkRxSeries, m_networkTxSeries, m_networkAxisY);

    if (m_diskChartView != nullptr && m_diskChartView->chart() != nullptr)
    {
        m_diskChartView->chart()->setTitle(ks::i18n::sourceText(
            QStringLiteral("系统盘读写速率  读:%1  写:%2"))
            .arg(bytesPerSecondToText(diskReadBytesPerSec))
            .arg(bytesPerSecondToText(diskWriteBytesPerSec)));
    }
    if (m_networkChartView != nullptr && m_networkChartView->chart() != nullptr)
    {
        m_networkChartView->chart()->setTitle(ks::i18n::sourceText(
            QStringLiteral("网络收发速率  下:%1  上:%2"))
            .arg(bytesPerSecondToText(networkRxBytesPerSec))
            .arg(bytesPerSecondToText(networkTxBytesPerSec)));
    }
}

void MonitorDock::initializeWmiTab()
{
    m_wmiPage = new QWidget(m_sideTabWidget);
    m_wmiLayout = new QVBoxLayout(m_wmiPage);
    m_wmiLayout->setContentsMargins(3, 3, 3, 3);
    m_wmiLayout->setSpacing(4);

    // WMI 顶部配置区改为独立折叠段：
    // - 左侧：Provider 枚举与过滤；
    // - 右侧：订阅类选择、WHERE 模板与订阅控制；
    // - 折叠段之间不互斥，允许用户把所有配置区同时收起。
    m_wmiTopConfigPanel = new QWidget(m_wmiPage);
    m_wmiTopConfigLayout = new QHBoxLayout(m_wmiTopConfigPanel);
    m_wmiTopConfigLayout->setContentsMargins(0, 0, 0, 0);
    m_wmiTopConfigLayout->setSpacing(4);
    m_wmiTopConfigPanel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);

    // Provider 左侧面板。
    m_wmiProviderPanel = new QWidget(m_wmiTopConfigPanel);
    m_wmiProviderPanelLayout = new QVBoxLayout(m_wmiProviderPanel);
    m_wmiProviderPanelLayout->setContentsMargins(3, 3, 3, 3);
    m_wmiProviderPanelLayout->setSpacing(4);

    m_wmiProviderControlLayout = new QHBoxLayout();
    m_wmiProviderControlLayout->setContentsMargins(0, 0, 0, 0);
    m_wmiProviderControlLayout->setSpacing(4);

    m_wmiProviderFilterEdit = new QLineEdit(m_wmiProviderPanel);
    m_wmiProviderFilterEdit->setPlaceholderText(QStringLiteral("按Provider或命名空间过滤"));
    m_wmiProviderFilterEdit->setStyleSheet(blueInputStyle());

    m_wmiProviderRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_wmiProviderPanel);
    m_wmiProviderRefreshButton->setToolTip(QStringLiteral("刷新WMI Provider"));
    m_wmiProviderRefreshButton->setStyleSheet(blueButtonStyle());
    m_wmiProviderRefreshButton->setFixedWidth(32);

    m_wmiProviderStatusLabel = new QLabel(QStringLiteral("● 待刷新"), m_wmiProviderPanel);
    m_wmiProviderStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));

    m_wmiProviderControlLayout->addWidget(m_wmiProviderFilterEdit, 1);
    m_wmiProviderControlLayout->addWidget(m_wmiProviderRefreshButton);
    m_wmiProviderControlLayout->addWidget(m_wmiProviderStatusLabel);

    m_wmiProviderModel = new QStandardItemModel(0, 5, m_wmiProviderPanel);
    m_wmiProviderModel->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("Provider名称"),
        QStringLiteral("Namespace"),
        QStringLiteral("CLSID"),
        QStringLiteral("EventClass数量"),
        QStringLiteral("状态")
    });

    m_wmiProviderProxyModel = new QSortFilterProxyModel(m_wmiProviderPanel);
    m_wmiProviderProxyModel->setSourceModel(m_wmiProviderModel);
    m_wmiProviderProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_wmiProviderProxyModel->setFilterKeyColumn(-1);

    m_wmiProviderTableView = new ks::ui::TableActionTableView(m_wmiProviderPanel);
    m_wmiProviderTableView->setModel(m_wmiProviderProxyModel);
    m_wmiProviderTableView->setSortingEnabled(true);
    m_wmiProviderTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_wmiProviderTableView->setSelectionMode(QAbstractItemView::SingleSelection);
    m_wmiProviderTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_wmiProviderTableView->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    m_wmiProviderTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_wmiProviderTableView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_wmiProviderTableView->verticalHeader()->setDefaultSectionSize(20);
    installMonitorTableViewCopyMenu(m_wmiProviderTableView);
    // Provider 列表控制为较窄高度，给监听结果腾出更多可视空间。
    m_wmiProviderTableView->setMinimumHeight(120);
    m_wmiProviderTableView->setMaximumHeight(160);

    m_wmiProviderPanelLayout->addLayout(m_wmiProviderControlLayout);
    m_wmiProviderPanelLayout->addWidget(m_wmiProviderTableView, 1);
    m_wmiTopConfigLayout->addWidget(createIndependentCollapseSection(
        m_wmiTopConfigPanel,
        QStringLiteral("WMI Providers"),
        m_wmiProviderPanel,
        true), 1);

    // 订阅右侧面板。
    m_wmiSubscribePanel = new QWidget(m_wmiTopConfigPanel);
    m_wmiSubscribeLayout = new QVBoxLayout(m_wmiSubscribePanel);
    m_wmiSubscribeLayout->setContentsMargins(3, 3, 3, 3);
    m_wmiSubscribeLayout->setSpacing(4);

    m_wmiEventClassControlLayout = new QHBoxLayout();
    m_wmiEventClassControlLayout->setContentsMargins(0, 0, 0, 0);
    m_wmiEventClassControlLayout->setSpacing(4);

    // 这三个是“选择辅助”而非流程控制：原先用 ▶/⏸ 会与同一面板的
    // “开始订阅/暂停订阅”按钮视觉完全相同，用户想全选却启动了订阅。
    // 播放类图标只保留给真正的流程控制，这里改用短文字，语义无歧义。
    m_wmiSelectAllClassesButton = new QPushButton(QStringLiteral("全选"), m_wmiSubscribePanel);
    m_wmiSelectAllClassesButton->setToolTip(QStringLiteral("全选事件类"));
    m_wmiSelectAllClassesButton->setStyleSheet(blueButtonStyle());

    m_wmiSelectNoneClassesButton = new QPushButton(QStringLiteral("全不选"), m_wmiSubscribePanel);
    m_wmiSelectNoneClassesButton->setToolTip(QStringLiteral("全不选事件类"));
    m_wmiSelectNoneClassesButton->setStyleSheet(blueButtonStyle());

    m_wmiSelectWin32ClassesButton = new QPushButton(
        QIcon(":/Icon/filter_funnel.svg"),
        QStringLiteral("仅 Win32"),
        m_wmiSubscribePanel);
    m_wmiSelectWin32ClassesButton->setToolTip(QStringLiteral("仅选择Win32_*"));
    m_wmiSelectWin32ClassesButton->setStyleSheet(blueButtonStyle());

    m_wmiEventClassControlLayout->addWidget(new QLabel(QStringLiteral("事件类"), m_wmiSubscribePanel));
    m_wmiEventClassControlLayout->addStretch(1);
    m_wmiEventClassControlLayout->addWidget(m_wmiSelectAllClassesButton);
    m_wmiEventClassControlLayout->addWidget(m_wmiSelectNoneClassesButton);
    m_wmiEventClassControlLayout->addWidget(m_wmiSelectWin32ClassesButton);

    m_wmiEventClassTable = new ks::ui::VisibleTableWidget(m_wmiSubscribePanel);
    m_wmiEventClassTable->setColumnCount(3);
    m_wmiEventClassTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("启用"),
        QStringLiteral("事件类"),
        QStringLiteral("匹配")
    });
    m_wmiEventClassTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_wmiEventClassTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_wmiEventClassTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // 关闭角按钮，避免左上角出现系统默认白色块。
    m_wmiEventClassTable->setCornerButtonEnabled(false);
    // 右侧事件类表改为无表头紧凑模式，减少高度占用并提升可见行数。
    m_wmiEventClassTable->horizontalHeader()->setVisible(false);
    m_wmiEventClassTable->verticalHeader()->setVisible(false);
    m_wmiEventClassTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    m_wmiEventClassTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_wmiEventClassTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_wmiEventClassTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_wmiEventClassTable->verticalHeader()->setDefaultSectionSize(20);
    installMonitorTableCopyMenu(m_wmiEventClassTable);
    // 事件类表先设置为可收敛尺寸策略，具体高度由 updateWmiSubscribePanelCompactLayout 动态计算。
    m_wmiEventClassTable->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    QHBoxLayout* whereLayout = new QHBoxLayout();
    whereLayout->setContentsMargins(0, 0, 0, 0);
    whereLayout->setSpacing(4);
    whereLayout->addWidget(new QLabel(QStringLiteral("WHERE模板"), m_wmiSubscribePanel));

    m_wmiWhereTemplateCombo = new QComboBox(m_wmiSubscribePanel);
    m_wmiWhereTemplateCombo->setStyleSheet(blueInputStyle());
    m_wmiWhereTemplateCombo->addItem(QStringLiteral("空模板"), QString());
    m_wmiWhereTemplateCombo->addItem(QStringLiteral("powershell"), QStringLiteral("TargetInstance.Name LIKE '%powershell%'"));
    m_wmiWhereTemplateCombo->addItem(QStringLiteral("PID>1000"), QStringLiteral("TargetInstance.ProcessId > 1000"));
    m_wmiWhereTemplateCombo->addItem(QStringLiteral("Session=0"), QStringLiteral("TargetInstance.SessionId = 0"));
    whereLayout->addWidget(m_wmiWhereTemplateCombo, 1);

    m_wmiWhereEditor = new QPlainTextEdit(m_wmiSubscribePanel);
    m_wmiWhereEditor->setPlaceholderText(QStringLiteral("可选：输入WQL WHERE子句"));
    // WHERE 子句改为单行输入体验，降低右侧订阅区高度并避免多行占位。
    m_wmiWhereEditor->setMaximumBlockCount(1);
    m_wmiWhereEditor->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_wmiWhereEditor->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_wmiWhereEditor->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_wmiWhereEditor->setStyleSheet(blueInputStyle());
    // 保持单行输入并压缩高度，给类列表与结果表留出更多可视行。
    m_wmiWhereEditor->setFixedHeight(24);

    m_wmiSubscribeControlLayout = new QHBoxLayout();
    m_wmiSubscribeControlLayout->setContentsMargins(0, 0, 0, 0);
    m_wmiSubscribeControlLayout->setSpacing(4);

    // 订阅控制保留在右侧面板内，形成“配置+控制”一体区，减少纵向重复占位。
    m_wmiStartSubscribeButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), m_wmiSubscribePanel);
    m_wmiStartSubscribeButton->setToolTip(QStringLiteral("开始订阅"));
    m_wmiStartSubscribeButton->setStyleSheet(blueButtonStyle());
    m_wmiStartSubscribeButton->setFixedWidth(32);

    m_wmiStopSubscribeButton = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), m_wmiSubscribePanel);
    m_wmiStopSubscribeButton->setToolTip(QStringLiteral("停止订阅"));
    m_wmiStopSubscribeButton->setStyleSheet(blueButtonStyle());
    m_wmiStopSubscribeButton->setFixedWidth(32);

    m_wmiPauseSubscribeButton = new QPushButton(QIcon(":/Icon/process_pause.svg"), QString(), m_wmiSubscribePanel);
    m_wmiPauseSubscribeButton->setToolTip(QStringLiteral("暂停/继续订阅"));
    m_wmiPauseSubscribeButton->setStyleSheet(blueButtonStyle());
    m_wmiPauseSubscribeButton->setFixedWidth(32);

    m_wmiExportButton = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), m_wmiSubscribePanel);
    m_wmiExportButton->setToolTip(QStringLiteral("导出当前WMI结果到文件"));
    m_wmiExportButton->setStyleSheet(blueButtonStyle());
    m_wmiExportButton->setFixedWidth(32);

    m_wmiSubscribeStatusLabel = new QLabel(QStringLiteral("● 未订阅"), m_wmiSubscribePanel);
    m_wmiSubscribeStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));

    m_wmiSubscribeControlLayout->addWidget(new QLabel(QStringLiteral("WMI订阅控制"), m_wmiSubscribePanel));
    m_wmiSubscribeControlLayout->addStretch(1);
    m_wmiSubscribeControlLayout->addWidget(m_wmiStartSubscribeButton);
    m_wmiSubscribeControlLayout->addWidget(m_wmiStopSubscribeButton);
    m_wmiSubscribeControlLayout->addWidget(m_wmiPauseSubscribeButton);
    m_wmiSubscribeControlLayout->addWidget(m_wmiExportButton);
    m_wmiSubscribeControlLayout->addWidget(m_wmiSubscribeStatusLabel);

    m_wmiSubscribeLayout->addLayout(m_wmiEventClassControlLayout);
    m_wmiSubscribeLayout->addWidget(m_wmiEventClassTable, 1);
    m_wmiSubscribeLayout->addLayout(whereLayout);
    m_wmiSubscribeLayout->addWidget(m_wmiWhereEditor, 0);
    m_wmiSubscribeLayout->addLayout(m_wmiSubscribeControlLayout, 0);
    // 初始化时先按“紧凑高度”收敛事件类表，防止首帧就出现多余滚动条。
    updateWmiSubscribePanelCompactLayout();

    m_wmiTopConfigLayout->addWidget(createIndependentCollapseSection(
        m_wmiTopConfigPanel,
        QStringLiteral("WMI订阅配置"),
        m_wmiSubscribePanel,
        true), 1);

    // 顶部两个配置块各自拥有折叠头，互不排斥，可同时收起。
    m_wmiLayout->addWidget(m_wmiTopConfigPanel, 0);

    // 结果表。
    m_wmiEventTable = new ks::ui::VisibleTableWidget(m_wmiPage);
    m_wmiEventTable->setColumnCount(5);
    m_wmiEventTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("时间戳(ms)"),
        QStringLiteral("事件来源"),
        QStringLiteral("事件类"),
        QStringLiteral("PID/进程"),
        QStringLiteral("事件详情")
    });
    m_wmiEventTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_wmiEventTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_wmiEventTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_wmiEventTable->setAlternatingRowColors(true);
    m_wmiEventTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_wmiEventTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    m_wmiEventTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_wmiEventTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_wmiEventTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_wmiEventTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_wmiEventTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);

    // 结果筛选条：提供全字段/分字段/正则/大小写/反向匹配与贴底滚动控制。
    QWidget* wmiFilterWidget = new QWidget(m_wmiPage);
    QVBoxLayout* wmiFilterLayout = new QVBoxLayout(wmiFilterWidget);
    wmiFilterLayout->setContentsMargins(0, 0, 0, 0);
    wmiFilterLayout->setSpacing(4);

    QHBoxLayout* wmiFilterTopRow = new QHBoxLayout();
    wmiFilterTopRow->setContentsMargins(0, 0, 0, 0);
    wmiFilterTopRow->setSpacing(6);
    m_wmiEventGlobalFilterEdit = new QLineEdit(wmiFilterWidget);
    m_wmiEventGlobalFilterEdit->setPlaceholderText(QStringLiteral("全字段筛选（时间/来源/类/PID/详情）"));
    m_wmiEventGlobalFilterEdit->setStyleSheet(blueInputStyle());
    m_wmiEventProviderFilterEdit = new QLineEdit(wmiFilterWidget);
    m_wmiEventProviderFilterEdit->setPlaceholderText(QStringLiteral("来源筛选"));
    m_wmiEventProviderFilterEdit->setStyleSheet(blueInputStyle());
    m_wmiEventClassFilterEdit = new QLineEdit(wmiFilterWidget);
    m_wmiEventClassFilterEdit->setPlaceholderText(QStringLiteral("事件类筛选"));
    m_wmiEventClassFilterEdit->setStyleSheet(blueInputStyle());
    wmiFilterTopRow->addWidget(new QLabel(QStringLiteral("筛选"), wmiFilterWidget));
    wmiFilterTopRow->addWidget(m_wmiEventGlobalFilterEdit, 2);
    wmiFilterTopRow->addWidget(m_wmiEventProviderFilterEdit, 1);
    wmiFilterTopRow->addWidget(m_wmiEventClassFilterEdit, 1);

    QHBoxLayout* wmiFilterBottomRow = new QHBoxLayout();
    wmiFilterBottomRow->setContentsMargins(0, 0, 0, 0);
    wmiFilterBottomRow->setSpacing(6);
    m_wmiEventPidFilterEdit = new QLineEdit(wmiFilterWidget);
    m_wmiEventPidFilterEdit->setPlaceholderText(QStringLiteral("PID/进程筛选"));
    m_wmiEventPidFilterEdit->setStyleSheet(blueInputStyle());
    m_wmiEventDetailFilterEdit = new QLineEdit(wmiFilterWidget);
    m_wmiEventDetailFilterEdit->setPlaceholderText(QStringLiteral("详情筛选"));
    m_wmiEventDetailFilterEdit->setStyleSheet(blueInputStyle());
    m_wmiEventRegexCheck = new QCheckBox(QStringLiteral("正则"), wmiFilterWidget);
    m_wmiEventCaseCheck = new QCheckBox(QStringLiteral("区分大小写"), wmiFilterWidget);
    m_wmiEventInvertCheck = new QCheckBox(QStringLiteral("反向筛选"), wmiFilterWidget);
    m_wmiEventKeepBottomCheck = new QCheckBox(QStringLiteral("保持表格在底部"), wmiFilterWidget);
    m_wmiEventKeepBottomCheck->setChecked(true);
    m_wmiEventFilterClearButton = new QPushButton(QIcon(":/Icon/log_clear.svg"), QString(), wmiFilterWidget);
    m_wmiEventFilterClearButton->setStyleSheet(blueButtonStyle());
    m_wmiEventFilterClearButton->setToolTip(QStringLiteral("清空所有WMI筛选条件"));
    m_wmiEventFilterClearButton->setFixedWidth(34);
    m_wmiEventFilterStatusLabel = new QLabel(QStringLiteral("可见: 0 / 0"), wmiFilterWidget);
    m_wmiEventFilterStatusLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));

    wmiFilterBottomRow->addWidget(m_wmiEventPidFilterEdit, 1);
    wmiFilterBottomRow->addWidget(m_wmiEventDetailFilterEdit, 2);
    wmiFilterBottomRow->addWidget(m_wmiEventRegexCheck, 0);
    wmiFilterBottomRow->addWidget(m_wmiEventCaseCheck, 0);
    wmiFilterBottomRow->addWidget(m_wmiEventInvertCheck, 0);
    wmiFilterBottomRow->addWidget(m_wmiEventKeepBottomCheck, 0);
    wmiFilterBottomRow->addWidget(m_wmiEventFilterClearButton, 0);
    wmiFilterBottomRow->addWidget(m_wmiEventFilterStatusLabel, 0);

    wmiFilterLayout->addLayout(wmiFilterTopRow);
    wmiFilterLayout->addLayout(wmiFilterBottomRow);

    m_wmiLayout->addWidget(wmiFilterWidget, 0);
    m_wmiLayout->addWidget(m_wmiEventTable, 1);
    // 调整 WMI 页面纵向占比：
    // - 顶部左右配置区保持紧凑；
    // - 事件结果表优先占用剩余空间。
    m_wmiLayout->setStretch(0, 0);
    m_wmiLayout->setStretch(1, 0);
    m_wmiLayout->setStretch(2, 1);
    m_sideTabWidget->addTab(m_wmiPage, QStringLiteral("WMI"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_wmiPage, QStringLiteral("monitor.tab.wmi"), QStringLiteral("WMI"));
}

void MonitorDock::updateWmiSubscribePanelCompactLayout()
{
    if (m_wmiEventClassTable == nullptr)
    {
        return;
    }

    // fallbackVisibleRowCount 用途：事件类尚未加载时先预留少量行，保持右侧区域紧凑。
    const int fallbackVisibleRowCount = 2;
    // maxVisibleRowCount 用途：限制事件类表高度，确保 WHERE 模板区始终在表格下方可见。
    const int maxVisibleRowCount = 4;
    // currentRowCount 用途：记录当前事件类表总行数，作为可视高度计算输入。
    const int currentRowCount = m_wmiEventClassTable->rowCount();
    // visibleRowCount 用途：将可视行数夹在 [fallbackVisibleRowCount, maxVisibleRowCount] 区间内。
    const int visibleRowCount = std::clamp(
        currentRowCount > 0 ? currentRowCount : fallbackVisibleRowCount,
        fallbackVisibleRowCount,
        maxVisibleRowCount);

    // headerHeight 用途：记录事件类表头高度；若表头为空则使用默认值避免高度为 0。
    int headerHeight = 0;
    QHeaderView* headerView = m_wmiEventClassTable->horizontalHeader();
    if (headerView != nullptr && !headerView->isHidden())
    {
        headerHeight = std::max(16, headerView->height());
    }

    // rowHeight 用途：记录单行默认高度，参与表格总高度估算。
    int rowHeight = 20;
    QHeaderView* verticalHeader = m_wmiEventClassTable->verticalHeader();
    if (verticalHeader != nullptr)
    {
        rowHeight = std::max(16, verticalHeader->defaultSectionSize());
    }

    // framePixels 用途：补偿表格边框占用像素，防止最底行被裁切。
    const int framePixels = m_wmiEventClassTable->frameWidth() * 2;
    // safetyPadding 用途：额外留白，吸收不同系统样式下的高度浮动。
    const int safetyPadding = 4;
    // tableTargetHeight 用途：最终写回到事件类表的紧凑高度。
    const int tableTargetHeight =
        headerHeight + (visibleRowCount * rowHeight) + framePixels + safetyPadding;
    m_wmiEventClassTable->setMinimumHeight(tableTargetHeight);
    m_wmiEventClassTable->setMaximumHeight(tableTargetHeight);
}

void MonitorDock::updateEtwCollapseHeight()
{
    if (m_etwCollapseHostWidget == nullptr)
    {
        return;
    }

    if (m_etwCollapseHostLayout != nullptr)
    {
        m_etwCollapseHostLayout->activate();
    }

    // 自定义折叠区允许全部收起，因此只通知布局重算，不再按“当前页”钳制高度。
    m_etwCollapseHostWidget->setMinimumHeight(0);
    m_etwCollapseHostWidget->setMaximumHeight(QWIDGETSIZE_MAX);
    m_etwCollapseHostWidget->updateGeometry();
    if (m_etwPage != nullptr)
    {
        m_etwPage->updateGeometry();
    }
}

void MonitorDock::initializeEtwTab()
{
    m_etwPage = new QWidget(m_sideTabWidget);
    m_etwLayout = new QVBoxLayout(m_etwPage);
    m_etwLayout->setContentsMargins(4, 4, 4, 4);
    m_etwLayout->setSpacing(6);

    // ETW 顶部配置区使用自定义独立折叠段：
    // - 替换 QToolBox，解除“必须保留一个展开页”的限制；
    // - 每个段只控制自己的内容，用户可以把所有配置段全部收起。
    m_etwCollapseHostWidget = new QWidget(m_etwPage);
    m_etwCollapseHostWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
    m_etwCollapseHostLayout = new QVBoxLayout(m_etwCollapseHostWidget);
    m_etwCollapseHostLayout->setContentsMargins(0, 0, 0, 0);
    m_etwCollapseHostLayout->setSpacing(4);
    m_etwLayout->addWidget(m_etwCollapseHostWidget, 0);

    // Providers + 会话共用一个折叠页，并在页内左右并排布局。
    QWidget* etwProviderSessionPanel = new QWidget(m_etwCollapseHostWidget);
    QHBoxLayout* etwProviderSessionLayout = new QHBoxLayout(etwProviderSessionPanel);
    etwProviderSessionLayout->setContentsMargins(4, 4, 4, 4);
    etwProviderSessionLayout->setSpacing(6);

    m_etwProviderPanel = new QWidget(etwProviderSessionPanel);
    m_etwProviderPanelLayout = new QVBoxLayout(m_etwProviderPanel);
    m_etwProviderPanelLayout->setContentsMargins(4, 4, 4, 4);
    m_etwProviderPanelLayout->setSpacing(6);

    m_etwProviderControlLayout = new QHBoxLayout();
    m_etwProviderControlLayout->setContentsMargins(0, 0, 0, 0);
    m_etwProviderControlLayout->setSpacing(6);

    m_etwProviderRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_etwProviderPanel);
    m_etwProviderRefreshButton->setToolTip(QStringLiteral("刷新ETW Provider"));
    m_etwProviderRefreshButton->setStyleSheet(blueButtonStyle());
    m_etwProviderRefreshButton->setFixedWidth(34);

    m_etwProviderStatusLabel = new QLabel(QStringLiteral("● 待刷新"), m_etwProviderPanel);
    m_etwProviderStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));

    m_etwProviderControlLayout->addWidget(new QLabel(QStringLiteral("ETW Providers"), m_etwProviderPanel));
    m_etwProviderControlLayout->addStretch(1);
    m_etwProviderControlLayout->addWidget(m_etwProviderRefreshButton);
    m_etwProviderControlLayout->addWidget(m_etwProviderStatusLabel);

    // Provider 区改为左右分栏：
    // - 左侧：预置常用 Provider 模板（含分类筛选）；
    // - 右侧：系统枚举出的全部 Provider 勾选列表。
    QHBoxLayout* etwProviderSplitLayout = new QHBoxLayout();
    etwProviderSplitLayout->setContentsMargins(0, 0, 0, 0);
    etwProviderSplitLayout->setSpacing(6);

    QWidget* etwPresetWidget = new QWidget(m_etwProviderPanel);
    QVBoxLayout* etwPresetLayout = new QVBoxLayout(etwPresetWidget);
    etwPresetLayout->setContentsMargins(0, 0, 0, 0);
    etwPresetLayout->setSpacing(4);

    QHBoxLayout* etwPresetHeaderLayout = new QHBoxLayout();
    etwPresetHeaderLayout->setContentsMargins(0, 0, 0, 0);
    etwPresetHeaderLayout->setSpacing(6);
    etwPresetHeaderLayout->addWidget(new QLabel(QStringLiteral("常用模板"), etwPresetWidget));

    m_etwPresetCategoryCombo = new QComboBox(etwPresetWidget);
    m_etwPresetCategoryCombo->setStyleSheet(blueInputStyle());
    m_etwPresetCategoryCombo->addItems(QStringList{
        QStringLiteral("全部分类"),
        QStringLiteral("进程线程"),
        QStringLiteral("文件注册表"),
        QStringLiteral("网络通信"),
        QStringLiteral("安全审计"),
        QStringLiteral("脚本管理")
    });
    etwPresetHeaderLayout->addWidget(m_etwPresetCategoryCombo, 1);
    etwPresetLayout->addLayout(etwPresetHeaderLayout);

    m_etwPresetProviderList = new QListWidget(etwPresetWidget);
    m_etwPresetProviderList->setAlternatingRowColors(true);
    m_etwPresetProviderList->setMinimumHeight(180);
    etwPresetLayout->addWidget(m_etwPresetProviderList, 1);

    // 捕获选择与简易筛选复用同一份常用 Provider 描述，避免两处列表逐渐不一致。
    for (const EtwPresetProviderDescriptor& preset : etwPresetProviderDescriptorList())
    {
        QListWidgetItem* item = new QListWidgetItem(
            QStringLiteral("[%1] %2").arg(preset.categoryText, preset.providerNameText),
            m_etwPresetProviderList);
        item->setData(Qt::UserRole, preset.providerNameText);
        item->setData(Qt::UserRole + 1, preset.categoryText);
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
        item->setCheckState(Qt::Checked);
    }

    QWidget* etwAllProviderWidget = new QWidget(m_etwProviderPanel);
    QVBoxLayout* etwAllProviderLayout = new QVBoxLayout(etwAllProviderWidget);
    etwAllProviderLayout->setContentsMargins(0, 0, 0, 0);
    etwAllProviderLayout->setSpacing(4);
    etwAllProviderLayout->addWidget(new QLabel(QStringLiteral("系统Providers"), etwAllProviderWidget));

    m_etwProviderList = new QListWidget(etwAllProviderWidget);
    m_etwProviderList->setAlternatingRowColors(true);
    m_etwProviderList->setMinimumHeight(180);
    etwAllProviderLayout->addWidget(m_etwProviderList, 1);

    etwProviderSplitLayout->addWidget(etwPresetWidget, 1);
    etwProviderSplitLayout->addWidget(etwAllProviderWidget, 2);

    m_etwProviderPanelLayout->addLayout(m_etwProviderControlLayout);
    m_etwProviderPanelLayout->addLayout(etwProviderSplitLayout, 1);

    m_etwSessionPanel = new QWidget(etwProviderSessionPanel);
    m_etwSessionPanelLayout = new QVBoxLayout(m_etwSessionPanel);
    m_etwSessionPanelLayout->setContentsMargins(4, 4, 4, 4);
    m_etwSessionPanelLayout->setSpacing(6);

    m_etwSessionControlLayout = new QHBoxLayout();
    m_etwSessionControlLayout->setContentsMargins(0, 0, 0, 0);
    m_etwSessionControlLayout->setSpacing(6);

    m_etwSessionRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_etwSessionPanel);
    m_etwSessionRefreshButton->setToolTip(QStringLiteral("枚举系统活动 ETW 会话"));
    m_etwSessionRefreshButton->setStyleSheet(blueButtonStyle());
    m_etwSessionRefreshButton->setFixedWidth(34);

    m_etwSessionStopButton = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), m_etwSessionPanel);
    m_etwSessionStopButton->setToolTip(QStringLiteral("结束选中的 ETW 会话"));
    m_etwSessionStopButton->setStyleSheet(blueButtonStyle());
    m_etwSessionStopButton->setFixedWidth(34);
    m_etwSessionStopButton->setEnabled(false);

    m_etwSessionStatusLabel = new QLabel(QStringLiteral("● 待刷新"), m_etwSessionPanel);
    m_etwSessionStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));

    m_etwSessionControlLayout->addWidget(new QLabel(QStringLiteral("ETW会话"), m_etwSessionPanel));
    m_etwSessionControlLayout->addStretch(1);
    m_etwSessionControlLayout->addWidget(m_etwSessionRefreshButton);
    m_etwSessionControlLayout->addWidget(m_etwSessionStopButton);
    m_etwSessionControlLayout->addWidget(m_etwSessionStatusLabel);
    m_etwSessionPanelLayout->addLayout(m_etwSessionControlLayout);

    m_etwSessionTable = new ks::ui::VisibleTableWidget(m_etwSessionPanel);
    m_etwSessionTable->setColumnCount(5);
    m_etwSessionTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("会话名"),
        QStringLiteral("模式"),
        QStringLiteral("缓冲区"),
        QStringLiteral("丢失事件"),
        QStringLiteral("日志文件")
    });
    m_etwSessionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_etwSessionTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_etwSessionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_etwSessionTable->setAlternatingRowColors(true);
    m_etwSessionTable->verticalHeader()->setVisible(false);
    m_etwSessionTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    m_etwSessionTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_etwSessionTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_etwSessionTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_etwSessionTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_etwSessionTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    m_etwSessionTable->setMinimumHeight(180);
    installMonitorTableCopyMenu(m_etwSessionTable);
    m_etwSessionPanelLayout->addWidget(m_etwSessionTable, 1);

    etwProviderSessionLayout->addWidget(m_etwProviderPanel, 3);
    etwProviderSessionLayout->addWidget(m_etwSessionPanel, 2);
    m_etwCollapseHostLayout->addWidget(createIndependentCollapseSection(
        m_etwCollapseHostWidget,
        QStringLiteral("ETW Providers / 会话"),
        etwProviderSessionPanel,
        true), 0);

    // 参数折叠页。
    QWidget* capturePanel = new QWidget(m_etwCollapseHostWidget);
    QVBoxLayout* captureLayout = new QVBoxLayout(capturePanel);
    captureLayout->setContentsMargins(4, 4, 4, 4);
    captureLayout->setSpacing(6);

    QFormLayout* formLayout = new QFormLayout();
    formLayout->setContentsMargins(0, 0, 0, 0);
    formLayout->setSpacing(6);

    m_etwManualProviderEdit = new QLineEdit(capturePanel);
    m_etwManualProviderEdit->setPlaceholderText(QStringLiteral("可选：手动输入Provider"));
    m_etwManualProviderEdit->setStyleSheet(blueInputStyle());

    m_etwLevelCombo = new QComboBox(capturePanel);
    m_etwLevelCombo->setStyleSheet(blueInputStyle());
    m_etwLevelCombo->addItems(QStringList{
        QStringLiteral("Critical"),
        QStringLiteral("Error"),
        QStringLiteral("Warning"),
        QStringLiteral("Information"),
        QStringLiteral("Verbose")
    });
    m_etwLevelCombo->setCurrentIndex(3);

    m_etwKeywordMaskEdit = new QLineEdit(capturePanel);
    m_etwKeywordMaskEdit->setStyleSheet(blueInputStyle());
    m_etwKeywordMaskEdit->setText(QStringLiteral("0xFFFFFFFFFFFFFFFF"));

    m_etwBufferSizeSpin = new QSpinBox(capturePanel);
    m_etwBufferSizeSpin->setRange(64, 4096);
    m_etwBufferSizeSpin->setValue(256);
    m_etwBufferSizeSpin->setStyleSheet(blueInputStyle());

    m_etwMinBufferSpin = new QSpinBox(capturePanel);
    m_etwMinBufferSpin->setRange(2, 128);
    m_etwMinBufferSpin->setValue(16);
    m_etwMinBufferSpin->setStyleSheet(blueInputStyle());

    m_etwMaxBufferSpin = new QSpinBox(capturePanel);
    m_etwMaxBufferSpin->setRange(4, 256);
    m_etwMaxBufferSpin->setValue(64);
    m_etwMaxBufferSpin->setStyleSheet(blueInputStyle());

    formLayout->addRow(QStringLiteral("手动Provider"), m_etwManualProviderEdit);
    formLayout->addRow(QStringLiteral("级别"), m_etwLevelCombo);
    formLayout->addRow(QStringLiteral("关键字掩码"), m_etwKeywordMaskEdit);
    formLayout->addRow(QStringLiteral("缓冲区大小(KB)"), m_etwBufferSizeSpin);
    formLayout->addRow(QStringLiteral("最小缓冲区"), m_etwMinBufferSpin);
    formLayout->addRow(QStringLiteral("最大缓冲区"), m_etwMaxBufferSpin);

    m_etwCaptureControlLayout = new QHBoxLayout();
    m_etwCaptureControlLayout->setContentsMargins(0, 0, 0, 0);
    m_etwCaptureControlLayout->setSpacing(6);

    // ETW 控制按钮挪到折叠栏外（父控件改为 m_etwPage），避免折叠页过高。
    m_etwStartButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), m_etwPage);
    m_etwStartButton->setToolTip(QStringLiteral("开始监听"));
    m_etwStartButton->setStyleSheet(blueButtonStyle());
    m_etwStartButton->setFixedWidth(34);

    m_etwStopButton = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), m_etwPage);
    m_etwStopButton->setToolTip(QStringLiteral("停止监听"));
    m_etwStopButton->setStyleSheet(blueButtonStyle());
    m_etwStopButton->setFixedWidth(34);

    m_etwPauseButton = new QPushButton(QIcon(":/Icon/process_pause.svg"), QString(), m_etwPage);
    m_etwPauseButton->setToolTip(QStringLiteral("暂停/继续"));
    m_etwPauseButton->setStyleSheet(blueButtonStyle());
    m_etwPauseButton->setFixedWidth(34);

    m_etwExportButton = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), m_etwPage);
    m_etwExportButton->setToolTip(QStringLiteral("导出TSV"));
    m_etwExportButton->setStyleSheet(blueButtonStyle());
    m_etwExportButton->setFixedWidth(34);

    m_etwCaptureStatusLabel = new QLabel(QStringLiteral("● 未监听"), m_etwPage);
    m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));

    m_etwCaptureControlLayout->addWidget(new QLabel(QStringLiteral("ETW控制"), m_etwPage));
    m_etwCaptureControlLayout->addStretch(1);
    m_etwCaptureControlLayout->addWidget(m_etwStartButton);
    m_etwCaptureControlLayout->addWidget(m_etwStopButton);
    m_etwCaptureControlLayout->addWidget(m_etwPauseButton);
    m_etwCaptureControlLayout->addWidget(m_etwExportButton);
    m_etwCaptureControlLayout->addWidget(m_etwCaptureStatusLabel);

    captureLayout->addLayout(formLayout);
    m_etwCollapseHostLayout->addWidget(createIndependentCollapseSection(
        m_etwCollapseHostWidget,
        QStringLiteral("ETW捕获"),
        capturePanel,
        false), 0);

    initializeEtwFilterPanels();

    // 把 ETW 控制栏放在折叠栏外，统一和 WMI 的操作区布局。
    m_etwLayout->addLayout(m_etwCaptureControlLayout, 0);

    // ETW 时间轴：
    // - 复用“进程定向”页的紧凑瀑布流控件，保证两个监控页的交互语义一致；
    // - 时间轴只保存轻量时间点，实际显示/隐藏仍由 ETW 后置筛选统一执行；
    // - 默认全范围选区不产生过滤，用户拖动或滚轮缩放后才叠加时间窗口。
    m_etwTimelineWidget = new ProcessTraceTimelineWidget(m_etwPage);
    m_etwTimelineWidget->setToolTip(QStringLiteral(
        "ETW 事件瀑布流时间轴：拖动矩形移动时间窗口；拖动左右边调整边界；滚轮向上放大窗口、向下缩小窗口。"));
    m_etwLayout->addWidget(m_etwTimelineWidget, 0);

    // 结果表。
    m_etwEventTable = new ks::ui::VisibleTableWidget(m_etwPage);
    m_etwEventTable->setColumnCount(7);
    m_etwEventTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("时间戳(100ns)"),
        QStringLiteral("Provider"),
        QStringLiteral("事件ID"),
        QStringLiteral("事件名称"),
        QStringLiteral("PID/TID"),
        QStringLiteral("事件摘要"),
        QStringLiteral("ActivityId")
    });
    m_etwEventTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_etwEventTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_etwEventTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_etwEventTable->setAlternatingRowColors(true);
    m_etwEventTable->setWordWrap(false);
    m_etwEventTable->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    m_etwEventTable->verticalHeader()->setDefaultSectionSize(22);
    m_etwEventTable->verticalHeader()->setMinimumWidth(78);
    m_etwEventTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_etwEventTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    // 高频追加时禁止 ResizeToContents：该模式会反复扫描已有行计算列宽，
    // 大量 ETW 事件到达时会放大每次 insert/setItem 的布局成本。
    m_etwEventTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Interactive);
    m_etwEventTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Interactive);
    m_etwEventTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Interactive);
    m_etwEventTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Interactive);
    m_etwEventTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Interactive);
    m_etwEventTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    m_etwEventTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Interactive);
    m_etwEventTable->setColumnWidth(0, 190);
    m_etwEventTable->setColumnWidth(1, 240);
    m_etwEventTable->setColumnWidth(2, 80);
    m_etwEventTable->setColumnWidth(3, 190);
    m_etwEventTable->setColumnWidth(4, 110);
    m_etwEventTable->setColumnWidth(6, 300);

    m_etwLayout->addWidget(m_etwEventTable, 1);

    m_etwUiUpdateTimer = new QTimer(this);
    m_etwUiUpdateTimer->setInterval(50);

    // 规则编辑和时间轴拖动可能连续触发几十次变更。只在输入稳定后启动一次磁盘扫描。
    m_etwArchiveFilterDebounceTimer = new QTimer(this);
    m_etwArchiveFilterDebounceTimer->setSingleShot(true);
    m_etwArchiveFilterDebounceTimer->setInterval(250);
    connect(m_etwArchiveFilterDebounceTimer, &QTimer::timeout, this, [this]() {
        rebuildEtwArchiveFilterAsync();
    });
    updateEtwCaptureActionState();
    updateEtwCollapseHeight();

    m_sideTabWidget->addTab(m_etwPage, QStringLiteral("ETW监控"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_etwPage, QStringLiteral("monitor.tab.etw"), QStringLiteral("ETW监控"));
}

MonitorDock::EtwSimpleFilterUiState& MonitorDock::etwSimpleFilterUi(const EtwFilterStage stage)
{
    return stage == EtwFilterStage::Pre ? m_etwPreSimpleFilterUi : m_etwPostSimpleFilterUi;
}

const MonitorDock::EtwSimpleFilterUiState& MonitorDock::etwSimpleFilterUi(const EtwFilterStage stage) const
{
    return stage == EtwFilterStage::Pre ? m_etwPreSimpleFilterUi : m_etwPostSimpleFilterUi;
}

QWidget* MonitorDock::createEtwSimpleFilterPanel(const EtwFilterStage stage, QWidget* parentWidget)
{
    EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
    uiState.panelWidget = new QWidget(parentWidget);
    QVBoxLayout* rootLayout = new QVBoxLayout(uiState.panelWidget);
    rootLayout->setContentsMargins(4, 4, 4, 4);
    rootLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(6);
    QLabel* titleLabel = new QLabel(
        stage == EtwFilterStage::Pre ? QStringLiteral("简易前置筛选") : QStringLiteral("简易后置筛选"),
        uiState.panelWidget);
    titleLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::PrimaryBlueHex));
    uiState.enabledCheck = new QCheckBox(QStringLiteral("启用"), uiState.panelWidget);
    uiState.enabledCheck->setChecked(true);
    uiState.clearButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/log_clear.svg")),
        QStringLiteral("清空"),
        uiState.panelWidget);
    uiState.clearButton->setStyleSheet(blueButtonStyle());
    headerLayout->addWidget(titleLabel);
    headerLayout->addWidget(uiState.enabledCheck);
    headerLayout->addStretch(1);
    headerLayout->addWidget(uiState.clearButton);
    rootLayout->addLayout(headerLayout);

    QLabel* semanticHintLabel = new QLabel(uiState.panelWidget);
    semanticHintLabel->setWordWrap(true);
    semanticHintLabel->setText(stage == EtwFilterStage::Pre
        ? QStringLiteral("前置筛选会主动排除未命中事件；这些事件不会进入全量归档或表格。")
        : QStringLiteral("后置筛选只改变显示结果；完整事件仍保留在磁盘归档中。"));
    semanticHintLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:12px;").arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(semanticHintLabel);

    QGridLayout* fieldGrid = new QGridLayout();
    fieldGrid->setContentsMargins(0, 0, 0, 0);
    fieldGrid->setHorizontalSpacing(8);
    fieldGrid->setVerticalSpacing(4);
    int fieldIndex = 0;
    const auto addTextField = [this, &fieldGrid, &fieldIndex, &uiState](
        const QString& labelText,
        const QString& placeholderText,
        QLineEdit*& editOut) {
        QWidget* cellWidget = new QWidget(uiState.panelWidget);
        QVBoxLayout* cellLayout = new QVBoxLayout(cellWidget);
        cellLayout->setContentsMargins(0, 0, 0, 0);
        cellLayout->setSpacing(2);
        QLabel* label = new QLabel(labelText, cellWidget);
        editOut = new QLineEdit(cellWidget);
        editOut->setPlaceholderText(placeholderText);
        editOut->setStyleSheet(blueInputStyle());
        cellLayout->addWidget(label);
        cellLayout->addWidget(editOut);
        fieldGrid->addWidget(cellWidget, fieldIndex / 2, fieldIndex % 2);
        ++fieldIndex;
    };

    addTextField(QStringLiteral("PID"), QStringLiteral("多个PID用逗号或分号分隔"), uiState.pidEdit);
    addTextField(QStringLiteral("进程名"), QStringLiteral("不区分大小写，包含匹配"), uiState.processNameEdit);
    addTextField(QStringLiteral("文件路径"), QStringLiteral("当前/旧/新路径，允许空格"), uiState.filePathEdit);
    addTextField(QStringLiteral("事件ID"), QStringLiteral("多个ID用逗号或分号分隔"), uiState.eventIdEdit);
    addTextField(QStringLiteral("事件名"), QStringLiteral("不区分大小写，包含匹配"), uiState.eventNameEdit);
    addTextField(QStringLiteral("注册表路径"), QStringLiteral("键路径或值名"), uiState.registryPathEdit);
    addTextField(QStringLiteral("网络地址"), QStringLiteral("IPv4、CIDR或地址范围"), uiState.networkAddressEdit);
    addTextField(QStringLiteral("网络端口"), QStringLiteral("端口或端口范围"), uiState.networkPortEdit);
    addTextField(QStringLiteral("状态"), QStringLiteral("状态码或结果文本"), uiState.statusEdit);
    fieldGrid->setColumnStretch(0, 1);
    fieldGrid->setColumnStretch(1, 1);
    rootLayout->addLayout(fieldGrid);

    QLabel* providerLabel = new QLabel(QStringLiteral("Provider来源"), uiState.panelWidget);
    providerLabel->setStyleSheet(QStringLiteral("font-weight:600;"));
    rootLayout->addWidget(providerLabel);
    QGridLayout* providerGrid = new QGridLayout();
    providerGrid->setContentsMargins(0, 0, 0, 0);
    providerGrid->setHorizontalSpacing(8);
    providerGrid->setVerticalSpacing(2);
    int providerIndex = 0;
    for (const EtwPresetProviderDescriptor& descriptor : etwPresetProviderDescriptorList())
    {
        QCheckBox* checkBox = new QCheckBox(descriptor.providerNameText, uiState.panelWidget);
        checkBox->setToolTip(QStringLiteral("[%1] %2").arg(
            descriptor.categoryText,
            descriptor.providerNameText));
        uiState.providerCheckList.push_back({ descriptor.providerNameText, checkBox });
        providerGrid->addWidget(checkBox, providerIndex / 2, providerIndex % 2);
        ++providerIndex;
    }
    providerGrid->setColumnStretch(0, 1);
    providerGrid->setColumnStretch(1, 1);
    rootLayout->addLayout(providerGrid);
    uiState.customProviderEdit = new QLineEdit(uiState.panelWidget);
    uiState.customProviderEdit->setPlaceholderText(
        QStringLiteral("自定义Provider：名称或GUID，多值用逗号/分号分隔"));
    uiState.customProviderEdit->setStyleSheet(blueInputStyle());
    rootLayout->addWidget(uiState.customProviderEdit);

    QLabel* actionLabel = new QLabel(QStringLiteral("行为"), uiState.panelWidget);
    actionLabel->setStyleSheet(QStringLiteral("font-weight:600;"));
    rootLayout->addWidget(actionLabel);
    QGridLayout* actionGrid = new QGridLayout();
    actionGrid->setContentsMargins(0, 0, 0, 0);
    actionGrid->setHorizontalSpacing(8);
    actionGrid->setVerticalSpacing(2);
    int actionIndex = 0;
    for (const QString& actionText : etwSimpleActionList())
    {
        QCheckBox* checkBox = new QCheckBox(actionText, uiState.panelWidget);
        uiState.actionCheckList.push_back({ actionText, checkBox });
        actionGrid->addWidget(checkBox, actionIndex / 5, actionIndex % 5);
        ++actionIndex;
    }
    for (int column = 0; column < 5; ++column)
    {
        actionGrid->setColumnStretch(column, 1);
    }
    rootLayout->addLayout(actionGrid);
    uiState.customActionEdit = new QLineEdit(uiState.panelWidget);
    uiState.customActionEdit->setPlaceholderText(
        QStringLiteral("自定义行为，多值用逗号/分号分隔"));
    uiState.customActionEdit->setStyleSheet(blueInputStyle());
    rootLayout->addWidget(uiState.customActionEdit);

    uiState.stateLabel = new QLabel(QStringLiteral("简易筛选：无条件"), uiState.panelWidget);
    uiState.stateLabel->setWordWrap(true);
    uiState.stateLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));
    rootLayout->addWidget(uiState.stateLabel);

    uiState.applyDebounceTimer = new QTimer(this);
    uiState.applyDebounceTimer->setSingleShot(true);
    uiState.applyDebounceTimer->setInterval(250);
    connect(uiState.applyDebounceTimer, &QTimer::timeout, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(uiState.enabledCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(uiState.clearButton, &QPushButton::clicked, this, [this, stage]() {
        clearEtwSimpleFilter(stage);
    });

    const std::initializer_list<QLineEdit*> editList{
        uiState.pidEdit,
        uiState.processNameEdit,
        uiState.filePathEdit,
        uiState.eventIdEdit,
        uiState.eventNameEdit,
        uiState.registryPathEdit,
        uiState.networkAddressEdit,
        uiState.networkPortEdit,
        uiState.statusEdit,
        uiState.customProviderEdit,
        uiState.customActionEdit
    };
    for (QLineEdit* edit : editList)
    {
        connect(edit, &QLineEdit::textChanged, this, [this, stage](const QString&) {
            scheduleEtwSimpleFilterApply(stage);
        });
    }
    for (const EtwSimpleFilterCheckUiState& checkState : uiState.providerCheckList)
    {
        connect(checkState.checkBox, &QCheckBox::toggled, this, [this, stage]() {
            applyEtwFilterRules(stage);
        });
    }
    for (const EtwSimpleFilterCheckUiState& checkState : uiState.actionCheckList)
    {
        connect(checkState.checkBox, &QCheckBox::toggled, this, [this, stage]() {
            applyEtwFilterRules(stage);
        });
    }
    return uiState.panelWidget;
}

void MonitorDock::scheduleEtwSimpleFilterApply(const EtwFilterStage stage)
{
    EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
    if (uiState.applyDebounceTimer != nullptr)
    {
        uiState.applyDebounceTimer->start();
    }
}

void MonitorDock::clearEtwSimpleFilter(const EtwFilterStage stage, const bool applyRules)
{
    EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
    if (uiState.applyDebounceTimer != nullptr)
    {
        uiState.applyDebounceTimer->stop();
    }
    const std::initializer_list<QLineEdit*> editList{
        uiState.pidEdit,
        uiState.processNameEdit,
        uiState.filePathEdit,
        uiState.eventIdEdit,
        uiState.eventNameEdit,
        uiState.registryPathEdit,
        uiState.networkAddressEdit,
        uiState.networkPortEdit,
        uiState.statusEdit,
        uiState.customProviderEdit,
        uiState.customActionEdit
    };
    for (QLineEdit* edit : editList)
    {
        if (edit != nullptr)
        {
            const QSignalBlocker blocker(edit);
            edit->clear();
        }
    }
    for (const EtwSimpleFilterCheckUiState& checkState : uiState.providerCheckList)
    {
        if (checkState.checkBox != nullptr)
        {
            const QSignalBlocker blocker(checkState.checkBox);
            checkState.checkBox->setChecked(false);
        }
    }
    for (const EtwSimpleFilterCheckUiState& checkState : uiState.actionCheckList)
    {
        if (checkState.checkBox != nullptr)
        {
            const QSignalBlocker blocker(checkState.checkBox);
            checkState.checkBox->setChecked(false);
        }
    }
    if (applyRules)
    {
        applyEtwFilterRules(stage);
    }
}

void MonitorDock::updateEtwSimpleFilterStateLabel(const EtwFilterStage stage)
{
    EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
    if (uiState.stateLabel == nullptr)
    {
        return;
    }
    const EtwSimpleFilterCompiled& compiledFilter = stage == EtwFilterStage::Pre
        ? m_etwPreSimpleFilterCompiled
        : m_etwPostSimpleFilterCompiled;
    if (!compiledFilter.enabled)
    {
        uiState.stateLabel->setText(QStringLiteral("简易筛选：已停用"));
        uiState.stateLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));
        return;
    }
    int conditionCount = 0;
    conditionCount += !compiledFilter.pidRangeList.empty();
    conditionCount += !compiledFilter.eventIdRangeList.empty();
    conditionCount += !compiledFilter.networkAddressRangeList.empty();
    conditionCount += !compiledFilter.networkPortRangeList.empty();
    conditionCount += !compiledFilter.providerPresetNameList.isEmpty()
        || !compiledFilter.providerCustomTokenList.isEmpty();
    conditionCount += !compiledFilter.actionPresetList.isEmpty()
        || !compiledFilter.actionCustomTokenList.isEmpty();
    conditionCount += !compiledFilter.processNameTokenList.isEmpty();
    conditionCount += !compiledFilter.filePathTokenList.isEmpty();
    conditionCount += !compiledFilter.eventNameTokenList.isEmpty();
    conditionCount += !compiledFilter.registryPathTokenList.isEmpty();
    conditionCount += !compiledFilter.statusTokenList.isEmpty();
    if (conditionCount == 0)
    {
        uiState.stateLabel->setText(stage == EtwFilterStage::Pre
            ? QStringLiteral("简易筛选：无条件（全部捕获）")
            : QStringLiteral("简易筛选：无条件（全部显示）"));
        uiState.stateLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));
        return;
    }
    uiState.stateLabel->setText(QStringLiteral("简易筛选：已应用 %1 项条件").arg(conditionCount));
    uiState.stateLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));
}

void MonitorDock::initializeEtwFilterPanels()
{
    QWidget* outerFilterPanel = new QWidget(m_etwCollapseHostWidget);
    QVBoxLayout* outerFilterLayout = new QVBoxLayout(outerFilterPanel);
    outerFilterLayout->setContentsMargins(4, 4, 4, 4);
    outerFilterLayout->setSpacing(6);

    QWidget* simpleFilterPanel = new QWidget(outerFilterPanel);
    QHBoxLayout* simpleFilterLayout = new QHBoxLayout(simpleFilterPanel);
    simpleFilterLayout->setContentsMargins(0, 0, 0, 0);
    simpleFilterLayout->setSpacing(6);
    simpleFilterLayout->addWidget(createEtwSimpleFilterPanel(EtwFilterStage::Pre, simpleFilterPanel), 1);
    simpleFilterLayout->addWidget(createEtwSimpleFilterPanel(EtwFilterStage::Post, simpleFilterPanel), 1);
    outerFilterLayout->addWidget(simpleFilterPanel);

    QWidget* etwFilterPanel = new QWidget(outerFilterPanel);
    QHBoxLayout* etwFilterPanelLayout = new QHBoxLayout(etwFilterPanel);
    etwFilterPanelLayout->setContentsMargins(4, 4, 4, 4);
    etwFilterPanelLayout->setSpacing(6);

    const auto initStagePanel = [this](
        const EtwFilterStage stage,
        QWidget*& panelOut,
        QVBoxLayout*& panelLayoutOut,
        QPushButton*& addGroupButtonOut,
        QPushButton*& applyButtonOut,
        QPushButton*& clearButtonOut,
        QPushButton*& loadDefaultButtonOut,
        QPushButton*& saveDefaultButtonOut,
        QPushButton*& importButtonOut,
        QPushButton*& exportButtonOut,
        QLabel*& stateLabelOut,
        QScrollArea*& scrollAreaOut,
        QWidget*& hostWidgetOut,
        QVBoxLayout*& hostLayoutOut)
        {
            panelOut = new QWidget();
            panelLayoutOut = new QVBoxLayout(panelOut);
            panelLayoutOut->setContentsMargins(4, 4, 4, 4);
            panelLayoutOut->setSpacing(6);

            QLabel* stageTitleLabel = new QLabel(
                stage == EtwFilterStage::Pre ? QStringLiteral("ETW前置筛选") : QStringLiteral("ETW后置筛选"),
                panelOut);
            stageTitleLabel->setStyleSheet(
                QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::PrimaryBlueHex));
            panelLayoutOut->addWidget(stageTitleLabel, 0);

            QLabel* semanticHintLabel = new QLabel(panelOut);
            semanticHintLabel->setWordWrap(true);
            semanticHintLabel->setText(stage == EtwFilterStage::Pre
                ? QStringLiteral("前置筛选 = 不捕获：未命中事件不会入队、不会进入表格、不会参与导出。")
                : QStringLiteral("后置筛选 = 仅改变显示：完整事件仍保留在磁盘归档中，可随时恢复显示。"));
            semanticHintLabel->setStyleSheet(
                QStringLiteral("color:%1;font-size:12px;").arg(KswordTheme::TextSecondaryHex()));
            panelLayoutOut->addWidget(semanticHintLabel, 0);

            QHBoxLayout* actionLayout = new QHBoxLayout();
            actionLayout->setContentsMargins(0, 0, 0, 0);
            actionLayout->setSpacing(6);

            addGroupButtonOut = new QPushButton(QIcon(":/Icon/plus.svg"), QStringLiteral("新增规则组"), panelOut);
            addGroupButtonOut->setStyleSheet(blueButtonStyle());
            applyButtonOut = new QPushButton(QIcon(":/Icon/log_track.svg"), QStringLiteral("应用"), panelOut);
            applyButtonOut->setStyleSheet(blueButtonStyle());
            clearButtonOut = new QPushButton(QIcon(":/Icon/log_clear.svg"), QStringLiteral("清空"), panelOut);
            clearButtonOut->setStyleSheet(blueButtonStyle());
            loadDefaultButtonOut = new QPushButton(QIcon(":/Icon/codeeditor_open.svg"), QStringLiteral("加载默认"), panelOut);
            loadDefaultButtonOut->setStyleSheet(blueButtonStyle());
            saveDefaultButtonOut = new QPushButton(QIcon(":/Icon/log_export.svg"), QStringLiteral("保存默认"), panelOut);
            saveDefaultButtonOut->setStyleSheet(blueButtonStyle());
            importButtonOut = new QPushButton(QIcon(":/Icon/codeeditor_open.svg"), QStringLiteral("导入"), panelOut);
            importButtonOut->setStyleSheet(blueButtonStyle());
            exportButtonOut = new QPushButton(QIcon(":/Icon/log_export.svg"), QStringLiteral("导出"), panelOut);
            exportButtonOut->setStyleSheet(blueButtonStyle());

            actionLayout->addWidget(addGroupButtonOut);
            actionLayout->addWidget(applyButtonOut);
            actionLayout->addWidget(clearButtonOut);
            actionLayout->addWidget(loadDefaultButtonOut);
            actionLayout->addWidget(saveDefaultButtonOut);
            actionLayout->addWidget(importButtonOut);
            actionLayout->addWidget(exportButtonOut);
            actionLayout->addStretch(1);
            panelLayoutOut->addLayout(actionLayout, 0);

            stateLabelOut = new QLabel(QStringLiteral("当前规则：无"), panelOut);
            stateLabelOut->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));
            stateLabelOut->setWordWrap(true);
            panelLayoutOut->addWidget(stateLabelOut, 0);

            // 筛选区不再使用内部滚动，避免折叠页内容被二次压缩。
            scrollAreaOut = nullptr;
            hostWidgetOut = new QWidget(panelOut);
            hostLayoutOut = new QVBoxLayout(hostWidgetOut);
            hostLayoutOut->setContentsMargins(0, 0, 0, 0);
            hostLayoutOut->setSpacing(6);
            panelLayoutOut->addWidget(hostWidgetOut, 0);
        };

    initStagePanel(
        EtwFilterStage::Pre,
        m_etwPreFilterPanel,
        m_etwPreFilterPanelLayout,
        m_etwPreFilterAddGroupButton,
        m_etwPreFilterApplyButton,
        m_etwPreFilterClearButton,
        m_etwPreFilterLoadDefaultButton,
        m_etwPreFilterSaveDefaultButton,
        m_etwPreFilterImportButton,
        m_etwPreFilterExportButton,
        m_etwPreFilterStateLabel,
        m_etwPreFilterScrollArea,
        m_etwPreFilterGroupHostWidget,
        m_etwPreFilterGroupHostLayout);

    initStagePanel(
        EtwFilterStage::Post,
        m_etwPostFilterPanel,
        m_etwPostFilterPanelLayout,
        m_etwPostFilterAddGroupButton,
        m_etwPostFilterApplyButton,
        m_etwPostFilterClearButton,
        m_etwPostFilterLoadDefaultButton,
        m_etwPostFilterSaveDefaultButton,
        m_etwPostFilterImportButton,
        m_etwPostFilterExportButton,
        m_etwPostFilterStateLabel,
        m_etwPostFilterScrollArea,
        m_etwPostFilterGroupHostWidget,
        m_etwPostFilterGroupHostLayout);

    etwFilterPanelLayout->addWidget(m_etwPreFilterPanel, 1);
    etwFilterPanelLayout->addWidget(m_etwPostFilterPanel, 1);
    outerFilterLayout->addWidget(createIndependentCollapseSection(
        outerFilterPanel,
        QStringLiteral("ETW筛选器详细配置"),
        etwFilterPanel,
        false));
    if (m_etwCollapseHostLayout != nullptr)
    {
        m_etwCollapseHostLayout->addWidget(createIndependentCollapseSection(
            m_etwCollapseHostWidget,
            QStringLiteral("ETW筛选器"),
            outerFilterPanel,
            false), 0);
    }

    addEtwFilterRuleGroup(EtwFilterStage::Pre);
    addEtwFilterRuleGroup(EtwFilterStage::Post);
    // 必须先加载配置再应用。旧流程会在启动时先保存空规则，从而覆盖用户的默认配置。
    loadEtwFilterConfigFromDefaultPath(false);
    updateEtwCollapseHeight();
}

void MonitorDock::initializeConnections()
{
    connect(m_sideTabWidget, &QTabWidget::currentChanged, this, [this](const int index) {
        if (index < 0 || m_sideTabWidget == nullptr)
        {
            return;
        }

        QWidget* currentPage = m_sideTabWidget->widget(index);
        if (currentPage == m_kernelCallbackHostPage)
        {
            QTimer::singleShot(0, this, [this]()
            {
                ensureKernelCallbackTabInitialized();
            });
        }
        if (currentPage == m_directKernelCallHostPage)
        {
            // 直接内核调用页按需创建，避免 syscall 映射解析拖慢 MonitorDock 首次打开。
            QTimer::singleShot(0, this, [this]()
            {
                ensureDirectKernelCallTabInitialized();
            });
        }
        if (currentPage == m_winApiPage)
        {
            ensureWinApiTabInitialized();
        }

        triggerDeferredDiscoveryForCurrentTab();
    });
    if (m_etwTimelineWidget != nullptr)
    {
        m_etwTimelineWidget->setSelectionChangedCallback(
            [this](const std::uint64_t start100ns, const std::uint64_t end100ns) {
                applyEtwTimelineSelection(start100ns, end100ns);
            });
    }

    // WMI 基础交互。
    connect(m_wmiProviderFilterEdit, &QLineEdit::textChanged, this, [this](const QString& text) {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] WMI Provider过滤词变更, keyword="
            << text.toStdString()
            << eol;
        applyWmiProviderFilter();
    });

    connect(m_wmiProviderRefreshButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击刷新WMI Provider与事件类。"
            << eol;
        refreshWmiProvidersAsync();
        refreshWmiEventClassesAsync();
    });

    connect(m_wmiSelectAllClassesButton, &QPushButton::clicked, this, [this]() {
        for (int row = 0; row < m_wmiEventClassTable->rowCount(); ++row)
        {
            QTableWidgetItem* item = m_wmiEventClassTable->item(row, 0);
            if (item != nullptr)
            {
                item->setCheckState(Qt::Checked);
            }
        }
        kLogEvent event;
        info << event
            << "[MonitorDock] WMI事件类操作：全选。"
            << eol;
    });

    connect(m_wmiSelectNoneClassesButton, &QPushButton::clicked, this, [this]() {
        for (int row = 0; row < m_wmiEventClassTable->rowCount(); ++row)
        {
            QTableWidgetItem* item = m_wmiEventClassTable->item(row, 0);
            if (item != nullptr)
            {
                item->setCheckState(Qt::Unchecked);
            }
        }
        kLogEvent event;
        info << event
            << "[MonitorDock] WMI事件类操作：全不选。"
            << eol;
    });

    connect(m_wmiSelectWin32ClassesButton, &QPushButton::clicked, this, [this]() {
        int checkedCount = 0;
        for (int row = 0; row < m_wmiEventClassTable->rowCount(); ++row)
        {
            QTableWidgetItem* checkItem = m_wmiEventClassTable->item(row, 0);
            QTableWidgetItem* classItem = m_wmiEventClassTable->item(row, 1);
            if (checkItem == nullptr || classItem == nullptr)
            {
                continue;
            }
            checkItem->setCheckState(classItem->text().startsWith(QStringLiteral("Win32_"), Qt::CaseInsensitive)
                ? Qt::Checked
                : Qt::Unchecked);
            if (checkItem->checkState() == Qt::Checked)
            {
                ++checkedCount;
            }
        }
        kLogEvent event;
        info << event
            << "[MonitorDock] WMI事件类操作：仅选Win32_*, selectedCount="
            << checkedCount
            << eol;
    });

    connect(m_wmiWhereTemplateCombo, &QComboBox::currentIndexChanged, this, [this](int index) {
        if (index < 0)
        {
            return;
        }
        const QString text = m_wmiWhereTemplateCombo->itemData(index).toString().trimmed();
        if (text.isEmpty())
        {
            return;
        }
        // 单行 WHERE 输入框逻辑：
        // - 空内容时直接填模板；
        // - 非空时在同一行用 AND 拼接，避免 appendPlainText 产生换行。
        const QString existingWhere = m_wmiWhereEditor->toPlainText().trimmed();
        if (existingWhere.isEmpty())
        {
            m_wmiWhereEditor->setPlainText(text);
        }
        else
        {
            m_wmiWhereEditor->setPlainText(existingWhere + QStringLiteral(" AND ") + text);
        }

        kLogEvent event;
        info << event
            << "[MonitorDock] 追加WMI WHERE模板, template="
            << text.toStdString()
            << eol;
    });

    connect(m_wmiStartSubscribeButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击开始WMI订阅。"
            << eol;
        startWmiSubscription();
    });

    connect(m_wmiStopSubscribeButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击停止WMI订阅。"
            << eol;
        stopWmiSubscription();
    });

    connect(m_wmiPauseSubscribeButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击切换WMI暂停状态。"
            << eol;
        setWmiSubscriptionPaused(!m_wmiSubscribePaused.load());
    });

    connect(m_wmiExportButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击导出WMI事件。"
            << eol;
        exportWmiRowsToTsv();
    });

    connect(m_wmiEventTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        showWmiEventContextMenu(pos);
    });
    connect(m_wmiEventTable, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* itemPointer) {
        if (itemPointer == nullptr)
        {
            return;
        }
        openWmiEventDetailViewerForRow(itemPointer->row());
    });

    // WMI 结果筛选交互：任一条件变化后实时重算可见行。
    const auto bindWmiFilter = [this](QLineEdit* edit) {
        if (edit == nullptr)
        {
            return;
        }
        connect(edit, &QLineEdit::textChanged, this, [this]() {
            applyWmiEventFilter();
        });
    };
    bindWmiFilter(m_wmiEventGlobalFilterEdit);
    bindWmiFilter(m_wmiEventProviderFilterEdit);
    bindWmiFilter(m_wmiEventClassFilterEdit);
    bindWmiFilter(m_wmiEventPidFilterEdit);
    bindWmiFilter(m_wmiEventDetailFilterEdit);

    if (m_wmiEventRegexCheck != nullptr)
    {
        connect(m_wmiEventRegexCheck, &QCheckBox::toggled, this, [this]() {
            applyWmiEventFilter();
        });
    }
    if (m_wmiEventCaseCheck != nullptr)
    {
        connect(m_wmiEventCaseCheck, &QCheckBox::toggled, this, [this]() {
            applyWmiEventFilter();
        });
    }
    if (m_wmiEventInvertCheck != nullptr)
    {
        connect(m_wmiEventInvertCheck, &QCheckBox::toggled, this, [this]() {
            applyWmiEventFilter();
        });
    }
    if (m_wmiEventFilterClearButton != nullptr)
    {
        connect(m_wmiEventFilterClearButton, &QPushButton::clicked, this, [this]() {
            clearWmiEventFilter();
        });
    }

    // ETW 基础交互。
    if (m_etwPresetCategoryCombo != nullptr && m_etwPresetProviderList != nullptr)
    {
        const auto applyPresetCategoryFilter = [this](const QString& categoryText) {
            const QString normalizedCategory = categoryText.trimmed();
            int visibleCount = 0;
            for (int row = 0; row < m_etwPresetProviderList->count(); ++row)
            {
                QListWidgetItem* item = m_etwPresetProviderList->item(row);
                if (item == nullptr)
                {
                    continue;
                }
                const QString itemCategory = item->data(Qt::UserRole + 1).toString();
                const bool isVisible = normalizedCategory.isEmpty()
                    || normalizedCategory == QStringLiteral("全部分类")
                    || itemCategory.compare(normalizedCategory, Qt::CaseInsensitive) == 0;
                item->setHidden(!isVisible);
                if (isVisible)
                {
                    ++visibleCount;
                }
            }

            kLogEvent event;
            dbg << event
                << "[MonitorDock] ETW预置模板分类筛选, category="
                << normalizedCategory.toStdString()
                << ", visibleCount="
                << visibleCount
                << eol;
        };

        connect(m_etwPresetCategoryCombo, &QComboBox::currentTextChanged, this, [applyPresetCategoryFilter](const QString& text) {
            applyPresetCategoryFilter(text);
        });
        applyPresetCategoryFilter(m_etwPresetCategoryCombo->currentText());
    }

    if (m_etwPreFilterAddGroupButton != nullptr)
    {
        connect(m_etwPreFilterAddGroupButton, &QPushButton::clicked, this, [this]() {
            addEtwFilterRuleGroup(EtwFilterStage::Pre);
            applyEtwFilterRules(EtwFilterStage::Pre);
        });
    }
    if (m_etwPreFilterApplyButton != nullptr)
    {
        connect(m_etwPreFilterApplyButton, &QPushButton::clicked, this, [this]() {
            applyEtwFilterRules(EtwFilterStage::Pre);
        });
    }
    if (m_etwPreFilterClearButton != nullptr)
    {
        connect(m_etwPreFilterClearButton, &QPushButton::clicked, this, [this]() {
            clearEtwFilterGroups(EtwFilterStage::Pre);
            applyEtwFilterRules(EtwFilterStage::Pre);
        });
    }
    if (m_etwPreFilterLoadDefaultButton != nullptr)
    {
        connect(m_etwPreFilterLoadDefaultButton, &QPushButton::clicked, this, [this]() {
            loadEtwFilterConfigFromDefaultPath(true);
        });
    }
    if (m_etwPreFilterSaveDefaultButton != nullptr)
    {
        connect(m_etwPreFilterSaveDefaultButton, &QPushButton::clicked, this, [this]() {
            saveEtwFilterConfigToDefaultPath(true);
        });
    }
    if (m_etwPreFilterImportButton != nullptr)
    {
        connect(m_etwPreFilterImportButton, &QPushButton::clicked, this, [this]() {
            importEtwFilterConfigFromUserSelectedPath();
        });
    }
    if (m_etwPreFilterExportButton != nullptr)
    {
        connect(m_etwPreFilterExportButton, &QPushButton::clicked, this, [this]() {
            exportEtwFilterConfigToUserSelectedPath();
        });
    }

    if (m_etwPostFilterAddGroupButton != nullptr)
    {
        connect(m_etwPostFilterAddGroupButton, &QPushButton::clicked, this, [this]() {
            addEtwFilterRuleGroup(EtwFilterStage::Post);
            applyEtwFilterRules(EtwFilterStage::Post);
        });
    }
    if (m_etwPostFilterApplyButton != nullptr)
    {
        connect(m_etwPostFilterApplyButton, &QPushButton::clicked, this, [this]() {
            applyEtwFilterRules(EtwFilterStage::Post);
        });
    }
    if (m_etwPostFilterClearButton != nullptr)
    {
        connect(m_etwPostFilterClearButton, &QPushButton::clicked, this, [this]() {
            clearEtwFilterGroups(EtwFilterStage::Post, true);
            applyEtwFilterRules(EtwFilterStage::Post);
        });
    }
    if (m_etwPostFilterLoadDefaultButton != nullptr)
    {
        connect(m_etwPostFilterLoadDefaultButton, &QPushButton::clicked, this, [this]() {
            loadEtwFilterConfigFromDefaultPath(true);
        });
    }
    if (m_etwPostFilterSaveDefaultButton != nullptr)
    {
        connect(m_etwPostFilterSaveDefaultButton, &QPushButton::clicked, this, [this]() {
            saveEtwFilterConfigToDefaultPath(true);
        });
    }
    if (m_etwPostFilterImportButton != nullptr)
    {
        connect(m_etwPostFilterImportButton, &QPushButton::clicked, this, [this]() {
            importEtwFilterConfigFromUserSelectedPath();
        });
    }
    if (m_etwPostFilterExportButton != nullptr)
    {
        connect(m_etwPostFilterExportButton, &QPushButton::clicked, this, [this]() {
            exportEtwFilterConfigToUserSelectedPath();
        });
    }

    connect(m_etwProviderRefreshButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击刷新ETW Provider。"
            << eol;
        refreshEtwProvidersAsync();
    });

    connect(m_etwSessionRefreshButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击刷新ETW会话。"
            << eol;
        refreshEtwSessionsAsync();
    });

    connect(m_etwSessionStopButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击结束选中ETW会话。"
            << eol;
        stopSelectedEtwSessions();
    });

    connect(m_etwSessionTable, &QTableWidget::itemSelectionChanged, this, [this]() {
        if (m_etwSessionStopButton != nullptr && m_etwSessionTable != nullptr)
        {
            m_etwSessionStopButton->setEnabled(!m_etwSessionTable->selectedItems().isEmpty());
        }
    });

    connect(m_etwStartButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击开始ETW监听。"
            << eol;
        startEtwCapture();
    });

    connect(m_etwStopButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击停止ETW监听。"
            << eol;
        stopEtwCapture();
    });

    connect(m_etwPauseButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击切换ETW暂停状态。"
            << eol;
        if (!m_etwCapturePaused.load())
        {
            setEtwCapturePaused(true);
        }
    });

    connect(m_etwExportButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[MonitorDock] 用户点击导出ETW事件。"
            << eol;
        exportEtwRowsToTsv();
    });

    connect(m_etwUiUpdateTimer, &QTimer::timeout, this, [this]() {
        flushEtwPendingRows(!m_etwCaptureRunning.load());
    });

    connect(m_etwEventTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        showEtwEventContextMenu(pos);
    });
    connect(m_etwEventTable, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* itemPointer) {
        if (itemPointer == nullptr)
        {
            return;
        }
        openEtwEventDetailViewerForRow(itemPointer->row());
    });
}

MonitorDock::EtwFilterRuleGroupUiState* MonitorDock::findEtwFilterRuleGroupById(
    const EtwFilterStage stage,
    const int groupId)
{
    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::Pre ? m_etwPreFilterRuleGroupUiList : m_etwPostFilterRuleGroupUiList;
    for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : groupList)
    {
        if (groupState != nullptr && groupState->groupId == groupId)
        {
            return groupState.get();
        }
    }
    return nullptr;
}

const MonitorDock::EtwFilterRuleGroupUiState* MonitorDock::findEtwFilterRuleGroupById(
    const EtwFilterStage stage,
    const int groupId) const
{
    const std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::Pre ? m_etwPreFilterRuleGroupUiList : m_etwPostFilterRuleGroupUiList;
    for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : groupList)
    {
        if (groupState != nullptr && groupState->groupId == groupId)
        {
            return groupState.get();
        }
    }
    return nullptr;
}

void MonitorDock::rebuildEtwFilterRuleGroupUi(const EtwFilterStage stage)
{
    QVBoxLayout* hostLayout = stage == EtwFilterStage::Pre
        ? m_etwPreFilterGroupHostLayout
        : m_etwPostFilterGroupHostLayout;
    if (hostLayout == nullptr)
    {
        return;
    }

    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::Pre ? m_etwPreFilterRuleGroupUiList : m_etwPostFilterRuleGroupUiList;

    while (hostLayout->count() > 0)
    {
        QLayoutItem* item = hostLayout->takeAt(0);
        delete item;
    }

    const bool canRemove = groupList.size() > 1;
    int displayIndex = 1;
    for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : groupList)
    {
        if (groupState == nullptr || groupState->containerWidget == nullptr)
        {
            continue;
        }
        if (groupState->titleLabel != nullptr)
        {
            groupState->titleLabel->setText(QStringLiteral("规则组%1").arg(displayIndex));
        }
        if (groupState->removeGroupButton != nullptr)
        {
            groupState->removeGroupButton->setEnabled(canRemove);
        }
        hostLayout->addWidget(groupState->containerWidget);
        ++displayIndex;
    }
    hostLayout->addStretch(1);
    updateEtwCollapseHeight();
}

void MonitorDock::addEtwFilterRuleGroup(const EtwFilterStage stage)
{
    QWidget* hostWidget = stage == EtwFilterStage::Pre
        ? m_etwPreFilterGroupHostWidget
        : m_etwPostFilterGroupHostWidget;
    if (hostWidget == nullptr)
    {
        return;
    }

    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::Pre ? m_etwPreFilterRuleGroupUiList : m_etwPostFilterRuleGroupUiList;
    int& nextGroupId = stage == EtwFilterStage::Pre ? m_etwPreFilterNextGroupId : m_etwPostFilterNextGroupId;

    std::unique_ptr<EtwFilterRuleGroupUiState> groupState = std::make_unique<EtwFilterRuleGroupUiState>();
    groupState->groupId = nextGroupId++;
    groupState->containerWidget = new QWidget(hostWidget);

    QVBoxLayout* rootLayout = new QVBoxLayout(groupState->containerWidget);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(6);
    groupState->titleLabel = new QLabel(QStringLiteral("规则组"), groupState->containerWidget);
    groupState->enabledCheck = new QCheckBox(QStringLiteral("启用"), groupState->containerWidget);
    groupState->enabledCheck->setChecked(true);
    groupState->removeGroupButton = new QPushButton(QIcon(":/Icon/log_cancel_track.svg"), QString(), groupState->containerWidget);
    groupState->removeGroupButton->setToolTip(QStringLiteral("删除当前规则组"));
    groupState->removeGroupButton->setStyleSheet(blueButtonStyle());
    groupState->removeGroupButton->setFixedWidth(32);
    headerLayout->addWidget(groupState->titleLabel);
    headerLayout->addWidget(groupState->enabledCheck);
    headerLayout->addStretch(1);
    headerLayout->addWidget(groupState->removeGroupButton);
    rootLayout->addLayout(headerLayout);

    QFrame* separatorLine = new QFrame(groupState->containerWidget);
    separatorLine->setFrameShape(QFrame::HLine);
    separatorLine->setFrameShadow(QFrame::Sunken);
    rootLayout->addWidget(separatorLine);

    QHBoxLayout* optionLayout = new QHBoxLayout();
    optionLayout->setContentsMargins(0, 0, 0, 0);
    optionLayout->setSpacing(6);
    optionLayout->addWidget(new QLabel(QStringLiteral("字符串匹配"), groupState->containerWidget));
    groupState->stringModeCombo = new QComboBox(groupState->containerWidget);
    groupState->stringModeCombo->setStyleSheet(blueInputStyle());
    groupState->stringModeCombo->addItem(QStringLiteral("正则"), QStringLiteral("regex"));
    groupState->stringModeCombo->addItem(QStringLiteral("精确"), QStringLiteral("exact"));
    groupState->stringModeCombo->addItem(QStringLiteral("包含"), QStringLiteral("contains"));
    groupState->stringModeCombo->addItem(QStringLiteral("前缀"), QStringLiteral("prefix"));
    groupState->stringModeCombo->addItem(QStringLiteral("后缀"), QStringLiteral("suffix"));
    groupState->caseSensitiveCheck = new QCheckBox(QStringLiteral("区分大小写"), groupState->containerWidget);
    groupState->invertCheck = new QCheckBox(QStringLiteral("反向"), groupState->containerWidget);
    groupState->detailVisibleColumnsCheck = new QCheckBox(QStringLiteral("仅匹配可见列"), groupState->containerWidget);
    groupState->detailMatchAllFieldsCheck = new QCheckBox(QStringLiteral("Detail匹配全字段"), groupState->containerWidget);
    groupState->detailMatchAllFieldsCheck->setChecked(true);
    optionLayout->addWidget(groupState->stringModeCombo, 0);
    optionLayout->addWidget(groupState->caseSensitiveCheck, 0);
    optionLayout->addWidget(groupState->invertCheck, 0);
    optionLayout->addWidget(groupState->detailVisibleColumnsCheck, 0);
    optionLayout->addWidget(groupState->detailMatchAllFieldsCheck, 0);
    optionLayout->addStretch(1);
    rootLayout->addLayout(optionLayout);

    QHBoxLayout* categoryLayout = new QHBoxLayout();
    categoryLayout->setContentsMargins(0, 0, 0, 0);
    categoryLayout->setSpacing(6);
    categoryLayout->addWidget(new QLabel(QStringLiteral("Provider分类开关"), groupState->containerWidget));
    for (const QString& categoryText : etwFilterProviderCategoryList())
    {
        QCheckBox* checkBox = new QCheckBox(categoryText, groupState->containerWidget);
        groupState->categoryCheckList.push_back({ categoryText, checkBox });
        categoryLayout->addWidget(checkBox, 0);
    }
    categoryLayout->addStretch(1);
    rootLayout->addLayout(categoryLayout);

    QGridLayout* fieldLayout = new QGridLayout();
    fieldLayout->setContentsMargins(0, 0, 0, 0);
    fieldLayout->setHorizontalSpacing(8);
    fieldLayout->setVerticalSpacing(4);

    const std::vector<EtwFilterFieldDescriptor>& fieldDescriptorList = etwFilterFieldDescriptorList();
    constexpr int kColumnCount = 2;
    int fieldIndex = 0;
    for (const EtwFilterFieldDescriptor& descriptor : fieldDescriptorList)
    {
        QLabel* fieldLabel = new QLabel(QString::fromUtf8(descriptor.label), groupState->containerWidget);
        QLineEdit* fieldEdit = new QLineEdit(groupState->containerWidget);
        fieldEdit->setStyleSheet(blueInputStyle());
        fieldEdit->setPlaceholderText(
            QStringLiteral("%1（逗号/分号/空白分隔）").arg(QString::fromUtf8(descriptor.placeholder)));

        const int row = fieldIndex / kColumnCount;
        const int col = fieldIndex % kColumnCount;
        QWidget* fieldCellWidget = new QWidget(groupState->containerWidget);
        QVBoxLayout* fieldCellLayout = new QVBoxLayout(fieldCellWidget);
        fieldCellLayout->setContentsMargins(0, 0, 0, 0);
        fieldCellLayout->setSpacing(2);
        fieldCellLayout->addWidget(fieldLabel);
        fieldCellLayout->addWidget(fieldEdit);
        fieldLayout->addWidget(fieldCellWidget, row, col);

        EtwFilterFieldUiState fieldUi;
        fieldUi.fieldId = descriptor.fieldId;
        fieldUi.fieldKey = QString::fromLatin1(descriptor.key);
        fieldUi.fieldLabel = QString::fromUtf8(descriptor.label);
        fieldUi.inputEdit = fieldEdit;
        groupState->fieldList.push_back(std::move(fieldUi));

        ++fieldIndex;
    }

    rootLayout->addLayout(fieldLayout);

    const int groupId = groupState->groupId;
    connect(groupState->enabledCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(groupState->removeGroupButton, &QPushButton::clicked, this, [this, stage, groupId]() {
        removeEtwFilterRuleGroup(stage, groupId);
    });
    connect(groupState->stringModeCombo, &QComboBox::currentIndexChanged, this, [this, stage](int) {
        applyEtwFilterRules(stage);
    });
    connect(groupState->caseSensitiveCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(groupState->invertCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(groupState->detailVisibleColumnsCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(groupState->detailMatchAllFieldsCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    for (const EtwFilterFieldUiState& fieldUi : groupState->fieldList)
    {
        if (fieldUi.inputEdit != nullptr)
        {
            connect(fieldUi.inputEdit, &QLineEdit::editingFinished, this, [this, stage]() {
                applyEtwFilterRules(stage);
            });
        }
    }
    for (const EtwFilterCategoryCheckUiState& categoryUi : groupState->categoryCheckList)
    {
        if (categoryUi.checkBox != nullptr)
        {
            connect(categoryUi.checkBox, &QCheckBox::toggled, this, [this, stage]() {
                applyEtwFilterRules(stage);
            });
        }
    }

    groupList.push_back(std::move(groupState));
    rebuildEtwFilterRuleGroupUi(stage);
}

void MonitorDock::removeEtwFilterRuleGroup(const EtwFilterStage stage, const int groupId)
{
    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::Pre ? m_etwPreFilterRuleGroupUiList : m_etwPostFilterRuleGroupUiList;
    const auto iterator = std::find_if(
        groupList.begin(),
        groupList.end(),
        [groupId](const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState) {
            return groupState != nullptr && groupState->groupId == groupId;
        });
    if (iterator == groupList.end())
    {
        return;
    }

    if ((*iterator) != nullptr && (*iterator)->containerWidget != nullptr)
    {
        delete (*iterator)->containerWidget;
    }
    groupList.erase(iterator);
    if (groupList.empty())
    {
        addEtwFilterRuleGroup(stage);
    }
    rebuildEtwFilterRuleGroupUi(stage);
    applyEtwFilterRules(stage);
}

void MonitorDock::clearEtwFilterGroups(const EtwFilterStage stage, const bool resetTimelineSelection)
{
    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::Pre ? m_etwPreFilterRuleGroupUiList : m_etwPostFilterRuleGroupUiList;
    for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : groupList)
    {
        if (groupState != nullptr && groupState->containerWidget != nullptr)
        {
            delete groupState->containerWidget;
        }
    }
    groupList.clear();
    if (stage == EtwFilterStage::Pre)
    {
        m_etwPreFilterNextGroupId = 1;
    }
    else
    {
        m_etwPostFilterNextGroupId = 1;
    }
    if (stage == EtwFilterStage::Post && resetTimelineSelection && m_etwTimelineWidget != nullptr)
    {
        // 后置筛选的“清空”语义覆盖显示层过滤，时间轴选区也一并恢复为完整范围。
        m_etwTimelineWidget->resetSelectionToFullRange();
        m_etwTimelineSelectionStart100ns = m_etwTimelineWidget->selectionStart100ns();
        m_etwTimelineSelectionEnd100ns = m_etwTimelineWidget->selectionEnd100ns();
        m_etwTimelineUserSelectionActive = false;
    }
    addEtwFilterRuleGroup(stage);
    rebuildEtwFilterRuleGroupUi(stage);
}

MonitorDock::EtwSimpleFilterModel MonitorDock::captureEtwSimpleFilterModel(
    const EtwFilterStage stage) const
{
    const EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
    const auto editText = [](QLineEdit* edit) {
        return edit == nullptr ? QString() : edit->text().trimmed();
    };

    EtwSimpleFilterModel filterModel;
    filterModel.enabled = uiState.enabledCheck == nullptr || uiState.enabledCheck->isChecked();
    filterModel.pidText = editText(uiState.pidEdit);
    filterModel.processNameText = editText(uiState.processNameEdit);
    filterModel.filePathText = editText(uiState.filePathEdit);
    filterModel.eventIdText = editText(uiState.eventIdEdit);
    filterModel.eventNameText = editText(uiState.eventNameEdit);
    filterModel.registryPathText = editText(uiState.registryPathEdit);
    filterModel.networkAddressText = editText(uiState.networkAddressEdit);
    filterModel.networkPortText = editText(uiState.networkPortEdit);
    filterModel.statusText = editText(uiState.statusEdit);
    filterModel.customProviderText = editText(uiState.customProviderEdit);
    filterModel.customActionText = editText(uiState.customActionEdit);

    for (const EtwSimpleFilterCheckUiState& checkState : uiState.providerCheckList)
    {
        if (checkState.checkBox != nullptr && checkState.checkBox->isChecked())
        {
            filterModel.providerPresetNameList.push_back(checkState.valueText);
        }
    }
    for (const EtwSimpleFilterCheckUiState& checkState : uiState.actionCheckList)
    {
        if (checkState.checkBox != nullptr && checkState.checkBox->isChecked())
        {
            filterModel.actionPresetList.push_back(checkState.valueText);
        }
    }
    return filterModel;
}

std::vector<MonitorDock::EtwFilterRuleGroupModel> MonitorDock::captureEtwFilterGroupModels(
    const EtwFilterStage stage) const
{
    const std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::Pre ? m_etwPreFilterRuleGroupUiList : m_etwPostFilterRuleGroupUiList;
    std::vector<EtwFilterRuleGroupModel> groupModelList;
    groupModelList.reserve(groupList.size());

    for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : groupList)
    {
        if (groupState == nullptr)
        {
            continue;
        }

        EtwFilterRuleGroupModel groupModel;
        groupModel.groupId = groupState->groupId;
        groupModel.enabled = groupState->enabledCheck == nullptr || groupState->enabledCheck->isChecked();
        groupModel.stringMode = etwFilterStringModeFromText(
            groupState->stringModeCombo == nullptr
                ? QStringLiteral("regex")
                : groupState->stringModeCombo->currentData().toString());
        groupModel.caseSensitive = groupState->caseSensitiveCheck != nullptr
            && groupState->caseSensitiveCheck->isChecked();
        groupModel.invertMatch = groupState->invertCheck != nullptr
            && groupState->invertCheck->isChecked();
        groupModel.detailVisibleColumnsOnly = groupState->detailVisibleColumnsCheck != nullptr
            && groupState->detailVisibleColumnsCheck->isChecked();
        groupModel.detailMatchAllFields = groupState->detailMatchAllFieldsCheck == nullptr
            || groupState->detailMatchAllFieldsCheck->isChecked();

        for (const EtwFilterCategoryCheckUiState& categoryUi : groupState->categoryCheckList)
        {
            if (categoryUi.checkBox != nullptr && categoryUi.checkBox->isChecked())
            {
                groupModel.providerCategoryList.push_back(categoryUi.categoryText);
            }
        }
        for (const EtwFilterFieldUiState& fieldUi : groupState->fieldList)
        {
            if (fieldUi.inputEdit == nullptr)
            {
                continue;
            }

            const QString inputText = fieldUi.inputEdit->text().trimmed();
            if (inputText.isEmpty())
            {
                continue;
            }

            EtwFilterRuleFieldModel fieldModel;
            fieldModel.fieldId = fieldUi.fieldId;
            fieldModel.fieldKey = fieldUi.fieldKey;
            fieldModel.fieldLabel = fieldUi.fieldLabel;
            fieldModel.inputText = inputText;
            groupModel.fieldList.push_back(std::move(fieldModel));
        }
        groupModelList.push_back(std::move(groupModel));
    }
    return groupModelList;
}

MonitorDock::EtwFilterConfigModel MonitorDock::captureEtwFilterConfigModel() const
{
    EtwFilterConfigModel filterModel;
    filterModel.preSimpleFilter = captureEtwSimpleFilterModel(EtwFilterStage::Pre);
    filterModel.postSimpleFilter = captureEtwSimpleFilterModel(EtwFilterStage::Post);
    filterModel.preGroupList = captureEtwFilterGroupModels(EtwFilterStage::Pre);
    filterModel.postGroupList = captureEtwFilterGroupModels(EtwFilterStage::Post);
    return filterModel;
}

bool MonitorDock::tryCompileEtwSimpleFilterModel(
    const EtwFilterStage stage,
    const EtwSimpleFilterModel& filterModel,
    EtwSimpleFilterCompiled& compiledFilterOut,
    QString& errorTextOut) const
{
    compiledFilterOut = EtwSimpleFilterCompiled{};
    errorTextOut.clear();
    compiledFilterOut.enabled = filterModel.enabled;

    const auto compileNumericRanges = [stage, &errorTextOut](
        const QString& inputText,
        const QString& fieldLabel,
        std::vector<EtwFilterNumericRange>& rangesOut,
        const std::uint64_t maximumValue) {
        for (const QString& tokenText : splitEtwSimpleFilterTokens(inputText))
        {
            EtwFilterNumericRange rangeValue;
            if (!tryParseUInt64RangeToken(tokenText, rangeValue)
                || rangeValue.maxValue > maximumValue)
            {
                errorTextOut = QStringLiteral("%1简易筛选字段[%2]无效值：%3")
                    .arg(etwFilterStageText(stage), fieldLabel, tokenText);
                return false;
            }
            rangesOut.push_back(rangeValue);
        }
        return true;
    };

    if (!compileNumericRanges(
            filterModel.pidText,
            QStringLiteral("PID"),
            compiledFilterOut.pidRangeList,
            std::numeric_limits<std::uint32_t>::max())
        || !compileNumericRanges(
            filterModel.eventIdText,
            QStringLiteral("事件ID"),
            compiledFilterOut.eventIdRangeList,
            std::numeric_limits<std::uint16_t>::max()))
    {
        return false;
    }

    for (const QString& tokenText : splitEtwSimpleFilterTokens(filterModel.networkAddressText))
    {
        EtwFilterIpRange rangeValue;
        if (!tryParseIpv4RangeToken(tokenText, rangeValue))
        {
            errorTextOut = QStringLiteral("%1简易筛选字段[网络地址]无效值：%2")
                .arg(etwFilterStageText(stage), tokenText);
            return false;
        }
        compiledFilterOut.networkAddressRangeList.push_back(rangeValue);
    }
    for (const QString& tokenText : splitEtwSimpleFilterTokens(filterModel.networkPortText))
    {
        EtwFilterPortRange rangeValue;
        if (!tryParsePortRangeToken(tokenText, rangeValue))
        {
            errorTextOut = QStringLiteral("%1简易筛选字段[网络端口]无效值：%2")
                .arg(etwFilterStageText(stage), tokenText);
            return false;
        }
        compiledFilterOut.networkPortRangeList.push_back(rangeValue);
    }

    compiledFilterOut.providerPresetNameList = filterModel.providerPresetNameList;
    compiledFilterOut.actionPresetList = filterModel.actionPresetList;
    compiledFilterOut.providerCustomTokenList =
        splitEtwSimpleFilterTokens(filterModel.customProviderText);
    compiledFilterOut.actionCustomTokenList =
        splitEtwSimpleFilterTokens(filterModel.customActionText);
    compiledFilterOut.processNameTokenList =
        splitEtwSimpleFilterTokens(filterModel.processNameText);
    compiledFilterOut.filePathTokenList =
        splitEtwSimpleFilterTokens(filterModel.filePathText);
    compiledFilterOut.eventNameTokenList =
        splitEtwSimpleFilterTokens(filterModel.eventNameText);
    compiledFilterOut.registryPathTokenList =
        splitEtwSimpleFilterTokens(filterModel.registryPathText);
    compiledFilterOut.statusTokenList =
        splitEtwSimpleFilterTokens(filterModel.statusText);
    return true;
}

bool MonitorDock::tryCompileEtwFilterGroupModels(
    const EtwFilterStage stage,
    const std::vector<EtwFilterRuleGroupModel>& groupModelList,
    std::vector<EtwFilterRuleGroupCompiled>& compiledGroupsOut,
    QString& errorTextOut) const
{
    compiledGroupsOut.clear();
    errorTextOut.clear();

    int displayIndex = 1;
    for (const EtwFilterRuleGroupModel& groupModel : groupModelList)
    {
        EtwFilterRuleGroupCompiled compiledGroup;
        compiledGroup.groupId = groupModel.groupId;
        compiledGroup.displayIndex = displayIndex;
        compiledGroup.enabled = groupModel.enabled;
        compiledGroup.stringMode = groupModel.stringMode;
        compiledGroup.caseSensitive = groupModel.caseSensitive;
        compiledGroup.invertMatch = groupModel.invertMatch;
        compiledGroup.detailVisibleColumnsOnly = groupModel.detailVisibleColumnsOnly;
        compiledGroup.detailMatchAllFields = groupModel.detailMatchAllFields;

        std::vector<EtwFilterRuleFieldModel> fieldModelList = groupModel.fieldList;
        const auto providerCategoryField = std::find_if(
            fieldModelList.begin(),
            fieldModelList.end(),
            [](const EtwFilterRuleFieldModel& fieldModel) {
                return fieldModel.fieldId == EtwFilterFieldId::ProviderCategory;
            });
        if (providerCategoryField == fieldModelList.end()
            && !groupModel.providerCategoryList.isEmpty())
        {
            const EtwFilterFieldDescriptor* descriptor =
                findEtwFilterFieldDescriptorById(EtwFilterFieldId::ProviderCategory);
            if (descriptor != nullptr)
            {
                EtwFilterRuleFieldModel fieldModel;
                fieldModel.fieldId = descriptor->fieldId;
                fieldModel.fieldKey = QString::fromLatin1(descriptor->key);
                fieldModel.fieldLabel = QString::fromUtf8(descriptor->label);
                fieldModelList.push_back(std::move(fieldModel));
            }
        }

        for (const EtwFilterRuleFieldModel& fieldModel : fieldModelList)
        {
            const EtwFilterFieldDescriptor* descriptor =
                findEtwFilterFieldDescriptorById(fieldModel.fieldId);
            if (descriptor == nullptr)
            {
                continue;
            }

            QString inputText = fieldModel.inputText.trimmed();
            if (fieldModel.fieldId == EtwFilterFieldId::ProviderCategory
                && !groupModel.providerCategoryList.isEmpty())
            {
                inputText = inputText.isEmpty()
                    ? groupModel.providerCategoryList.join(QStringLiteral(","))
                    : inputText + QStringLiteral(",")
                        + groupModel.providerCategoryList.join(QStringLiteral(","));
            }

            if (inputText.isEmpty())
            {
                continue;
            }

            const QStringList tokenList = splitEtwFilterTokens(inputText);
            if (tokenList.isEmpty())
            {
                continue;
            }

            EtwFilterRuleFieldCompiled compiledField;
            compiledField.fieldId = fieldModel.fieldId;
            compiledField.fieldKey = fieldModel.fieldKey;
            compiledField.fieldLabel = fieldModel.fieldLabel;
            compiledField.fieldType = descriptor->fieldType;
            compiledField.requiresDecodedPayload = descriptor->requiresDecodedPayload;

            const QRegularExpression::PatternOptions regexOptions = compiledGroup.caseSensitive
                ? QRegularExpression::NoPatternOption
                : QRegularExpression::CaseInsensitiveOption;

            for (const QString& tokenTextRaw : tokenList)
            {
                const QString tokenText = tokenTextRaw.trimmed();
                if (tokenText.isEmpty())
                {
                    continue;
                }

                if (descriptor->fieldType == EtwFilterFieldType::Text)
                {
                    const QString regexPattern = etwFilterRegexPatternFromToken(tokenText, compiledGroup.stringMode);
                    const QRegularExpression regex(regexPattern, regexOptions);
                    if (!regex.isValid())
                    {
                        errorTextOut = QStringLiteral("%1 规则组%2 字段[%3] 无效值：%4")
                            .arg(etwFilterStageText(stage))
                            .arg(displayIndex)
                            .arg(fieldModel.fieldLabel)
                            .arg(tokenText);
                        return false;
                    }
                    compiledField.regexRuleList.push_back(regex);
                    continue;
                }

                if (descriptor->fieldType == EtwFilterFieldType::Number
                    || descriptor->fieldType == EtwFilterFieldType::TimeRange)
                {
                    EtwFilterNumericRange range;
                    if (!tryParseUInt64RangeToken(tokenText, range))
                    {
                        errorTextOut = QStringLiteral("%1 规则组%2 字段[%3] 无效值：%4")
                            .arg(etwFilterStageText(stage))
                            .arg(displayIndex)
                            .arg(fieldModel.fieldLabel)
                            .arg(tokenText);
                        return false;
                    }
                    compiledField.numericRangeList.push_back(range);
                    continue;
                }

                if (descriptor->fieldType == EtwFilterFieldType::NumberOrText)
                {
                    EtwFilterNumericRange range;
                    if (tryParseUInt64RangeToken(tokenText, range))
                    {
                        compiledField.numericRangeList.push_back(range);
                        continue;
                    }

                    const QString regexPattern = etwFilterRegexPatternFromToken(tokenText, compiledGroup.stringMode);
                    const QRegularExpression regex(regexPattern, regexOptions);
                    if (!regex.isValid())
                    {
                        errorTextOut = QStringLiteral("%1 规则组%2 字段[%3] 无效值：%4")
                            .arg(etwFilterStageText(stage))
                            .arg(displayIndex)
                            .arg(fieldModel.fieldLabel)
                            .arg(tokenText);
                        return false;
                    }
                    compiledField.regexRuleList.push_back(regex);
                    continue;
                }

                if (descriptor->fieldType == EtwFilterFieldType::Ip)
                {
                    EtwFilterIpRange range;
                    if (!tryParseIpv4RangeToken(tokenText, range))
                    {
                        errorTextOut = QStringLiteral("%1 规则组%2 字段[%3] 无效值：%4")
                            .arg(etwFilterStageText(stage))
                            .arg(displayIndex)
                            .arg(fieldModel.fieldLabel)
                            .arg(tokenText);
                        return false;
                    }
                    compiledField.ipRangeList.push_back(range);
                    continue;
                }

                if (descriptor->fieldType == EtwFilterFieldType::Port)
                {
                    EtwFilterPortRange range;
                    if (!tryParsePortRangeToken(tokenText, range))
                    {
                        errorTextOut = QStringLiteral("%1 规则组%2 字段[%3] 无效值：%4")
                            .arg(etwFilterStageText(stage))
                            .arg(displayIndex)
                            .arg(fieldModel.fieldLabel)
                            .arg(tokenText);
                        return false;
                    }
                    compiledField.portRangeList.push_back(range);
                    continue;
                }
            }

            if (compiledField.regexRuleList.empty()
                && compiledField.numericRangeList.empty()
                && compiledField.ipRangeList.empty()
                && compiledField.portRangeList.empty())
            {
                continue;
            }

            if (compiledField.requiresDecodedPayload)
            {
                compiledGroup.requiresDecodedPayload = true;
            }
            compiledGroup.fieldList.push_back(std::move(compiledField));
        }

        if (compiledGroup.enabled && compiledGroup.hasAnyCondition())
        {
            compiledGroupsOut.push_back(std::move(compiledGroup));
        }

        ++displayIndex;
    }

    return true;
}

bool MonitorDock::tryCompileEtwFilterConfigModel(
    const EtwFilterConfigModel& filterModel,
    EtwFilterConfigCompiledModel& compiledModelOut,
    QString& errorTextOut) const
{
    compiledModelOut = EtwFilterConfigCompiledModel{};
    errorTextOut.clear();
    return tryCompileEtwSimpleFilterModel(
            EtwFilterStage::Pre,
            filterModel.preSimpleFilter,
            compiledModelOut.preSimpleFilter,
            errorTextOut)
        && tryCompileEtwFilterGroupModels(
            EtwFilterStage::Pre,
            filterModel.preGroupList,
            compiledModelOut.preGroupList,
            errorTextOut)
        && tryCompileEtwSimpleFilterModel(
            EtwFilterStage::Post,
            filterModel.postSimpleFilter,
            compiledModelOut.postSimpleFilter,
            errorTextOut)
        && tryCompileEtwFilterGroupModels(
            EtwFilterStage::Post,
            filterModel.postGroupList,
            compiledModelOut.postGroupList,
            errorTextOut);
}

bool MonitorDock::tryCompileEtwSimpleFilter(
    const EtwFilterStage stage,
    EtwSimpleFilterCompiled& compiledFilterOut,
    QString& errorTextOut) const
{
    const EtwSimpleFilterModel filterModel = captureEtwSimpleFilterModel(stage);
    return tryCompileEtwSimpleFilterModel(
        stage,
        filterModel,
        compiledFilterOut,
        errorTextOut);
}

bool MonitorDock::tryCompileEtwFilterGroups(
    const EtwFilterStage stage,
    std::vector<EtwFilterRuleGroupCompiled>& compiledGroupsOut,
    QString& errorTextOut) const
{
    const std::vector<EtwFilterRuleGroupModel> groupModelList =
        captureEtwFilterGroupModels(stage);
    return tryCompileEtwFilterGroupModels(
        stage,
        groupModelList,
        compiledGroupsOut,
        errorTextOut);
}

void MonitorDock::updateEtwFilterStateLabel(const EtwFilterStage stage)
{
    QLabel* stateLabel = stage == EtwFilterStage::Pre ? m_etwPreFilterStateLabel : m_etwPostFilterStateLabel;
    if (stateLabel == nullptr)
    {
        return;
    }

    const std::vector<EtwFilterRuleGroupCompiled>& compiledGroupList =
        stage == EtwFilterStage::Pre ? m_etwPreFilterCompiledGroupList : m_etwPostFilterCompiledGroupList;
    bool archiveAvailable = false;
    if (stage == EtwFilterStage::Post)
    {
        std::lock_guard<std::mutex> lock(m_etwArchiveMutex);
        archiveAvailable = !m_etwArchiveDirectory.trimmed().isEmpty();
    }

    if (compiledGroupList.empty())
    {
        const QString tailText = stage == EtwFilterStage::Pre
            ? QStringLiteral("前置筛选当前无规则（全部捕获）")
            : QStringLiteral("后置筛选当前无规则（全部显示）");
        if (stage == EtwFilterStage::Post
            && !archiveAvailable
            && m_etwEventTable != nullptr
            && isEtwTimelineFilterActive())
        {
            int visibleCount = 0;
            for (int row = 0; row < m_etwEventTable->rowCount(); ++row)
            {
                if (!m_etwEventTable->isRowHidden(row))
                {
                    ++visibleCount;
                }
            }
            stateLabel->setText(QStringLiteral("%1 | 可见: %2 / %3 | 时间轴已筛选")
                .arg(QStringLiteral("后置筛选当前无规则"))
                .arg(visibleCount)
                .arg(m_etwEventTable->rowCount()));
            stateLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));
        }
        else
        {
            stateLabel->setText(tailText);
            stateLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));
        }
        return;
    }

    QStringList groupSummaryList;
    for (const EtwFilterRuleGroupCompiled& groupRule : compiledGroupList)
    {
        groupSummaryList.push_back(QStringLiteral("规则组%1[%2项]")
            .arg(groupRule.displayIndex)
            .arg(groupRule.fieldList.size()));
    }

    QString summaryText = QStringLiteral("%1：%2")
        .arg(etwFilterStageText(stage))
        .arg(groupSummaryList.join(QStringLiteral(" OR ")));
    if (stage == EtwFilterStage::Post && !archiveAvailable && m_etwEventTable != nullptr)
    {
        int visibleCount = 0;
        for (int row = 0; row < m_etwEventTable->rowCount(); ++row)
        {
            if (!m_etwEventTable->isRowHidden(row))
            {
                ++visibleCount;
            }
        }
        summaryText += QStringLiteral(" | 可见: %1 / %2").arg(visibleCount).arg(m_etwEventTable->rowCount());
        if (isEtwTimelineFilterActive())
        {
            summaryText += QStringLiteral(" | 时间轴已筛选");
        }
    }

    stateLabel->setText(summaryText);
    stateLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));
}

void MonitorDock::applyEtwPostFilterToTable(const int firstRow, const bool updateStateLabel)
{
    if (m_etwEventTable == nullptr)
    {
        return;
    }

    const int rowCount = std::min(
        m_etwEventTable->rowCount(),
        static_cast<int>(m_etwCapturedRows.size()));

    const bool hasPostRules = m_etwPostSimpleFilterCompiled.hasAnyCondition()
        || !m_etwPostFilterCompiledGroupList.empty();
    const bool timelineFilterActive = isEtwTimelineFilterActive();
    const int firstRowToApply = std::clamp(firstRow, 0, rowCount);

    // 实时追加时只计算新行。规则变更、时间轴选区变化仍走 firstRow=0 的全表重算。
    // 这避免监听过程中每个批次重复遍历最多 6000 条历史事件。
    for (int row = firstRowToApply; row < rowCount; ++row)
    {
        bool visible = true;
        const EtwCapturedEventRow& rowData = m_etwCapturedRows[static_cast<std::size_t>(row)];
        if (hasPostRules)
        {
            visible = etwFilterStageMatches(
                m_etwPostSimpleFilterCompiled,
                m_etwPostFilterCompiledGroupList,
                rowData);
        }
        if (visible && timelineFilterActive)
        {
            // 时间轴是外层有效运行时间窗口约束，中间暂停段不参与坐标比较。
            const std::uint64_t rowTimelineTimestamp100ns =
                etwRawTimestampToTimelineTimestamp(rowData.timestampValue);
            visible = rowTimelineTimestamp100ns >= m_etwTimelineSelectionStart100ns
                && rowTimelineTimestamp100ns <= m_etwTimelineSelectionEnd100ns;
        }
        m_etwEventTable->setRowHidden(row, !visible);
    }
    for (int row = std::max(rowCount, firstRowToApply); row < m_etwEventTable->rowCount(); ++row)
    {
        m_etwEventTable->setRowHidden(row, false);
    }

    if (updateStateLabel)
    {
        updateEtwFilterStateLabel(EtwFilterStage::Post);
    }
}

void MonitorDock::applyEtwFilterRules(const EtwFilterStage stage)
{
    EtwSimpleFilterCompiled simpleFilter;
    QString compileErrorText;
    if (!tryCompileEtwSimpleFilter(stage, simpleFilter, compileErrorText))
    {
        EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
        if (uiState.stateLabel != nullptr)
        {
            uiState.stateLabel->setText(compileErrorText);
            uiState.stateLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
        }
        return;
    }

    std::vector<EtwFilterRuleGroupCompiled> compiledGroupList;
    if (!tryCompileEtwFilterGroups(stage, compiledGroupList, compileErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("ETW筛选器"), compileErrorText);
        return;
    }

    if (stage == EtwFilterStage::Pre)
    {
        m_etwPreSimpleFilterCompiled = simpleFilter;
        m_etwPreFilterCompiledGroupList = std::move(compiledGroupList);
        EtwFilterStageCompiledSnapshot stageSnapshot;
        stageSnapshot.simpleFilter = m_etwPreSimpleFilterCompiled;
        stageSnapshot.detailedGroupList = m_etwPreFilterCompiledGroupList;
        {
            std::lock_guard<std::mutex> lock(m_etwPreFilterSnapshotMutex);
            m_etwPreFilterCompiledSnapshot =
                std::make_shared<const EtwFilterStageCompiledSnapshot>(std::move(stageSnapshot));
        }
    }
    else
    {
        m_etwPostSimpleFilterCompiled = simpleFilter;
        m_etwPostFilterCompiledGroupList = std::move(compiledGroupList);
        QString archiveDirectory;
        {
            std::lock_guard<std::mutex> lock(m_etwArchiveMutex);
            archiveDirectory = m_etwArchiveDirectory;
        }
        if (archiveDirectory.trimmed().isEmpty())
        {
            applyEtwPostFilterToTable();
        }
        else
        {
            scheduleEtwArchiveFilterRebuild();
        }
    }

    updateEtwSimpleFilterStateLabel(stage);
    updateEtwFilterStateLabel(stage);
    saveEtwFilterConfigToPath(etwFilterConfigPath(), false);
    updateEtwCollapseHeight();

    kLogEvent event;
    info << event
        << "[MonitorDock] 应用ETW筛选规则, stage="
        << (stage == EtwFilterStage::Pre ? "pre" : "post")
        << ", activeGroupCount="
        << (stage == EtwFilterStage::Pre
            ? m_etwPreFilterCompiledGroupList.size()
            : m_etwPostFilterCompiledGroupList.size())
        << ", simpleActive="
        << (simpleFilter.hasAnyCondition() ? 1 : 0)
        << eol;
}

QString MonitorDock::etwFilterConfigPath() const
{
    return QDir(QCoreApplication::applicationDirPath())
        .absoluteFilePath(QString::fromLatin1(kEtwFilterConfigRelativePath));
}

bool MonitorDock::tryParseEtwFilterConfigModel(
    const QByteArray& jsonData,
    EtwFilterConfigModel& filterModelOut) const
{
    QJsonParseError parseError;
    const QJsonDocument jsonDocument = QJsonDocument::fromJson(jsonData, &parseError);
    if (parseError.error != QJsonParseError::NoError || !jsonDocument.isObject())
    {
        return false;
    }

    const QJsonObject rootObject = jsonDocument.object();
    const QJsonValue versionValue =
        rootObject.value(QString::fromLatin1(kEtwFilterJsonVersionKey));
    if (!versionValue.isUndefined())
    {
        if (!versionValue.isDouble())
        {
            return false;
        }
        const double versionNumber = versionValue.toDouble(-1.0);
        const int version = versionValue.toInt(-1);
        if (versionNumber != static_cast<double>(version)
            || (version != 1 && version != 2))
        {
            return false;
        }
    }

    const auto readBoolean = [](
        const QJsonObject& object,
        const char* key,
        const bool defaultValue,
        bool& valueOut) {
        const QJsonValue value = object.value(QString::fromLatin1(key));
        if (value.isUndefined())
        {
            valueOut = defaultValue;
            return true;
        }
        if (!value.isBool())
        {
            return false;
        }
        valueOut = value.toBool(defaultValue);
        return true;
    };
    const auto readString = [](
        const QJsonObject& object,
        const char* key,
        QString& valueOut) {
        const QJsonValue value = object.value(QString::fromLatin1(key));
        if (value.isUndefined())
        {
            valueOut.clear();
            return true;
        }
        if (!value.isString())
        {
            return false;
        }
        valueOut = value.toString().trimmed();
        return true;
    };
    const auto readStringList = [](
        const QJsonObject& object,
        const char* key,
        QStringList& valueListOut) {
        valueListOut.clear();
        const QJsonValue value = object.value(QString::fromLatin1(key));
        if (value.isUndefined())
        {
            return true;
        }
        if (!value.isArray())
        {
            return false;
        }
        for (const QJsonValue& itemValue : value.toArray())
        {
            if (!itemValue.isString())
            {
                return false;
            }
            const QString itemText = itemValue.toString().trimmed();
            if (!itemText.isEmpty())
            {
                valueListOut.push_back(itemText);
            }
        }
        return true;
    };
    const auto normalizeKnownStringList = [](
        QStringList& valueList,
        const QStringList& knownValueList) {
        QStringList normalizedValueList;
        for (const QString& valueText : valueList)
        {
            const auto found = std::find_if(
                knownValueList.cbegin(),
                knownValueList.cend(),
                [&valueText](const QString& knownValue) {
                    return knownValue.compare(valueText, Qt::CaseInsensitive) == 0;
                });
            if (found == knownValueList.cend())
            {
                return false;
            }
            if (!normalizedValueList.contains(*found, Qt::CaseInsensitive))
            {
                normalizedValueList.push_back(*found);
            }
        }
        valueList = std::move(normalizedValueList);
        return true;
    };

    EtwFilterConfigModel candidateModel;
    const auto parseSimpleFilter = [
        this,
        &rootObject,
        &readBoolean,
        &readString,
        &readStringList,
        &normalizeKnownStringList](
        const EtwFilterStage stage,
        const char* objectKey,
        EtwSimpleFilterModel& simpleModelOut) {
        const QJsonValue simpleValue = rootObject.value(QString::fromLatin1(objectKey));
        if (simpleValue.isUndefined())
        {
            simpleModelOut = EtwSimpleFilterModel{};
            return true;
        }
        if (!simpleValue.isObject())
        {
            return false;
        }

        const QJsonObject simpleObject = simpleValue.toObject();
        if (!readBoolean(
                simpleObject,
                kEtwFilterJsonEnabledKey,
                true,
                simpleModelOut.enabled)
            || !readString(simpleObject, kEtwFilterJsonSimplePidKey, simpleModelOut.pidText)
            || !readString(
                simpleObject,
                kEtwFilterJsonSimpleProcessNameKey,
                simpleModelOut.processNameText)
            || !readString(
                simpleObject,
                kEtwFilterJsonSimpleFilePathKey,
                simpleModelOut.filePathText)
            || !readString(
                simpleObject,
                kEtwFilterJsonSimpleEventIdKey,
                simpleModelOut.eventIdText)
            || !readString(
                simpleObject,
                kEtwFilterJsonSimpleEventNameKey,
                simpleModelOut.eventNameText)
            || !readString(
                simpleObject,
                kEtwFilterJsonSimpleRegistryPathKey,
                simpleModelOut.registryPathText)
            || !readString(
                simpleObject,
                kEtwFilterJsonSimpleNetworkAddressKey,
                simpleModelOut.networkAddressText)
            || !readString(
                simpleObject,
                kEtwFilterJsonSimpleNetworkPortKey,
                simpleModelOut.networkPortText)
            || !readString(
                simpleObject,
                kEtwFilterJsonSimpleStatusKey,
                simpleModelOut.statusText)
            || !readString(
                simpleObject,
                kEtwFilterJsonSimpleCustomProviderKey,
                simpleModelOut.customProviderText)
            || !readString(
                simpleObject,
                kEtwFilterJsonSimpleCustomActionKey,
                simpleModelOut.customActionText)
            || !readStringList(
                simpleObject,
                kEtwFilterJsonSimpleProvidersKey,
                simpleModelOut.providerPresetNameList)
            || !readStringList(
                simpleObject,
                kEtwFilterJsonSimpleActionsKey,
                simpleModelOut.actionPresetList))
        {
            return false;
        }

        QStringList knownProviderList;
        QStringList knownActionList;
        const EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
        for (const EtwSimpleFilterCheckUiState& checkState : uiState.providerCheckList)
        {
            knownProviderList.push_back(checkState.valueText);
        }
        for (const EtwSimpleFilterCheckUiState& checkState : uiState.actionCheckList)
        {
            knownActionList.push_back(checkState.valueText);
        }
        return normalizeKnownStringList(
                simpleModelOut.providerPresetNameList,
                knownProviderList)
            && normalizeKnownStringList(
                simpleModelOut.actionPresetList,
                knownActionList);
    };

    if (!parseSimpleFilter(
            EtwFilterStage::Pre,
            kEtwFilterJsonSimplePreKey,
            candidateModel.preSimpleFilter)
        || !parseSimpleFilter(
            EtwFilterStage::Post,
            kEtwFilterJsonSimplePostKey,
            candidateModel.postSimpleFilter))
    {
        return false;
    }

    const auto parseGroupList = [
        &rootObject,
        &readBoolean,
        &readStringList,
        &normalizeKnownStringList](
        const char* arrayKey,
        std::vector<EtwFilterRuleGroupModel>& groupModelListOut) {
        groupModelListOut.clear();
        const QJsonValue groupListValue = rootObject.value(QString::fromLatin1(arrayKey));
        if (groupListValue.isUndefined())
        {
            return true;
        }
        if (!groupListValue.isArray())
        {
            return false;
        }

        const QStringList knownCategoryList = etwFilterProviderCategoryList();
        const QStringList knownStringModeList{
            QStringLiteral("regex"),
            QStringLiteral("exact"),
            QStringLiteral("contains"),
            QStringLiteral("prefix"),
            QStringLiteral("suffix")
        };
        const QJsonArray groupArray = groupListValue.toArray();
        groupModelListOut.reserve(static_cast<std::size_t>(groupArray.size()));
        for (const QJsonValue& groupValue : groupArray)
        {
            if (!groupValue.isObject())
            {
                return false;
            }

            const QJsonObject groupObject = groupValue.toObject();
            EtwFilterRuleGroupModel groupModel;
            groupModel.groupId = static_cast<int>(groupModelListOut.size()) + 1;
            if (!readBoolean(
                    groupObject,
                    kEtwFilterJsonEnabledKey,
                    true,
                    groupModel.enabled)
                || !readBoolean(
                    groupObject,
                    kEtwFilterJsonCaseSensitiveKey,
                    false,
                    groupModel.caseSensitive)
                || !readBoolean(
                    groupObject,
                    kEtwFilterJsonInvertKey,
                    false,
                    groupModel.invertMatch)
                || !readBoolean(
                    groupObject,
                    kEtwFilterJsonDetailVisibleOnlyKey,
                    false,
                    groupModel.detailVisibleColumnsOnly)
                || !readBoolean(
                    groupObject,
                    kEtwFilterJsonDetailAllFieldsKey,
                    true,
                    groupModel.detailMatchAllFields)
                || !readStringList(
                    groupObject,
                    kEtwFilterJsonProviderCategoriesKey,
                    groupModel.providerCategoryList)
                || !normalizeKnownStringList(
                    groupModel.providerCategoryList,
                    knownCategoryList))
            {
                return false;
            }

            const QJsonValue modeValue =
                groupObject.value(QString::fromLatin1(kEtwFilterJsonStringModeKey));
            QString modeText = QStringLiteral("regex");
            if (!modeValue.isUndefined())
            {
                if (!modeValue.isString())
                {
                    return false;
                }
                modeText = modeValue.toString().trimmed().toLower();
            }
            if (!knownStringModeList.contains(modeText, Qt::CaseInsensitive))
            {
                return false;
            }
            groupModel.stringMode = etwFilterStringModeFromText(modeText);

            const QJsonValue fieldListValue =
                groupObject.value(QString::fromLatin1(kEtwFilterJsonFieldsKey));
            if (!fieldListValue.isUndefined() && !fieldListValue.isArray())
            {
                return false;
            }
            const QJsonArray fieldArray = fieldListValue.toArray();
            QStringList loadedFieldKeyList;
            groupModel.fieldList.reserve(static_cast<std::size_t>(fieldArray.size()));
            for (const QJsonValue& fieldValue : fieldArray)
            {
                if (!fieldValue.isObject())
                {
                    return false;
                }
                const QJsonObject fieldObject = fieldValue.toObject();
                const QJsonValue fieldKeyValue =
                    fieldObject.value(QString::fromLatin1(kEtwFilterJsonFieldKey));
                const QJsonValue fieldTextValue =
                    fieldObject.value(QString::fromLatin1(kEtwFilterJsonFieldValue));
                if (!fieldKeyValue.isString() || !fieldTextValue.isString())
                {
                    return false;
                }

                const QString fieldKey = fieldKeyValue.toString().trimmed().toLower();
                const EtwFilterFieldDescriptor* descriptor =
                    findEtwFilterFieldDescriptorByKey(fieldKey);
                if (descriptor == nullptr
                    || loadedFieldKeyList.contains(fieldKey, Qt::CaseInsensitive))
                {
                    return false;
                }
                loadedFieldKeyList.push_back(fieldKey);

                const QString fieldText = fieldTextValue.toString().trimmed();
                if (fieldText.isEmpty())
                {
                    continue;
                }
                EtwFilterRuleFieldModel fieldModel;
                fieldModel.fieldId = descriptor->fieldId;
                fieldModel.fieldKey = QString::fromLatin1(descriptor->key);
                fieldModel.fieldLabel = QString::fromUtf8(descriptor->label);
                fieldModel.inputText = fieldText;
                groupModel.fieldList.push_back(std::move(fieldModel));
            }
            groupModelListOut.push_back(std::move(groupModel));
        }
        return true;
    };

    if (!parseGroupList(kEtwFilterJsonPreGroupsKey, candidateModel.preGroupList)
        || !parseGroupList(kEtwFilterJsonPostGroupsKey, candidateModel.postGroupList))
    {
        return false;
    }

    filterModelOut = std::move(candidateModel);
    return true;
}

QJsonObject MonitorDock::serializeEtwFilterConfigModel(
    const EtwFilterConfigModel& filterModel) const
{
    const auto serializeSimpleFilter = [](const EtwSimpleFilterModel& simpleModel) {
        QJsonObject simpleObject;
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonEnabledKey),
            simpleModel.enabled);
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimplePidKey),
            simpleModel.pidText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleProcessNameKey),
            simpleModel.processNameText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleFilePathKey),
            simpleModel.filePathText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleEventIdKey),
            simpleModel.eventIdText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleEventNameKey),
            simpleModel.eventNameText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleRegistryPathKey),
            simpleModel.registryPathText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleNetworkAddressKey),
            simpleModel.networkAddressText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleNetworkPortKey),
            simpleModel.networkPortText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleStatusKey),
            simpleModel.statusText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleCustomProviderKey),
            simpleModel.customProviderText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleCustomActionKey),
            simpleModel.customActionText.trimmed());

        QJsonArray providerArray;
        for (const QString& providerName : simpleModel.providerPresetNameList)
        {
            providerArray.append(providerName);
        }
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleProvidersKey),
            providerArray);

        QJsonArray actionArray;
        for (const QString& actionText : simpleModel.actionPresetList)
        {
            actionArray.append(actionText);
        }
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleActionsKey),
            actionArray);
        return simpleObject;
    };
    const auto serializeGroupList = [](
        const std::vector<EtwFilterRuleGroupModel>& groupModelList) {
        QJsonArray groupArray;
        for (const EtwFilterRuleGroupModel& groupModel : groupModelList)
        {
            QJsonObject groupObject;
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonEnabledKey),
                groupModel.enabled);
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonStringModeKey),
                etwFilterStringModeToText(groupModel.stringMode));
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonCaseSensitiveKey),
                groupModel.caseSensitive);
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonInvertKey),
                groupModel.invertMatch);
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonDetailVisibleOnlyKey),
                groupModel.detailVisibleColumnsOnly);
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonDetailAllFieldsKey),
                groupModel.detailMatchAllFields);

            QJsonArray categoryArray;
            for (const QString& categoryText : groupModel.providerCategoryList)
            {
                categoryArray.append(categoryText);
            }
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonProviderCategoriesKey),
                categoryArray);

            QJsonArray fieldArray;
            for (const EtwFilterRuleFieldModel& fieldModel : groupModel.fieldList)
            {
                const QString inputText = fieldModel.inputText.trimmed();
                if (inputText.isEmpty())
                {
                    continue;
                }
                QJsonObject fieldObject;
                fieldObject.insert(
                    QString::fromLatin1(kEtwFilterJsonFieldKey),
                    fieldModel.fieldKey);
                fieldObject.insert(
                    QString::fromLatin1(kEtwFilterJsonFieldValue),
                    inputText);
                fieldArray.append(fieldObject);
            }
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonFieldsKey),
                fieldArray);
            groupArray.append(groupObject);
        }
        return groupArray;
    };

    QJsonObject rootObject;
    rootObject.insert(QString::fromLatin1(kEtwFilterJsonVersionKey), 2);
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonSimplePreKey),
        serializeSimpleFilter(filterModel.preSimpleFilter));
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonSimplePostKey),
        serializeSimpleFilter(filterModel.postSimpleFilter));
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonPreGroupsKey),
        serializeGroupList(filterModel.preGroupList));
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonPostGroupsKey),
        serializeGroupList(filterModel.postGroupList));
    return rootObject;
}

bool MonitorDock::saveEtwFilterConfigModelToPath(
    const EtwFilterConfigModel& filterModel,
    const QString& filePath,
    const bool showErrorDialog) const
{
    const QString normalizedPath = QFileInfo(filePath).absoluteFilePath();
    if (normalizedPath.trimmed().isEmpty())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(nullptr, QStringLiteral("ETW筛选"), QStringLiteral("配置保存路径无效。"));
        }
        return false;
    }

    const QFileInfo fileInfo(normalizedPath);
    QDir outputDirectory(fileInfo.absolutePath());
    if (!outputDirectory.exists() && !outputDirectory.mkpath(QStringLiteral(".")))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(
                nullptr,
                QStringLiteral("ETW筛选"),
                QStringLiteral("创建配置目录失败：%1").arg(outputDirectory.absolutePath()));
        }
        return false;
    }

    const QByteArray serializedData =
        QJsonDocument(serializeEtwFilterConfigModel(filterModel))
            .toJson(QJsonDocument::Indented);
    QSaveFile outputFile(normalizedPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text)
        || outputFile.write(serializedData) != serializedData.size()
        || !outputFile.commit())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(
                nullptr,
                QStringLiteral("ETW筛选"),
                QStringLiteral("打开配置文件失败：%1").arg(normalizedPath));
        }
        return false;
    }
    return true;
}

void MonitorDock::commitEtwFilterConfigModel(
    const EtwFilterConfigModel& filterModel,
    EtwFilterConfigCompiledModel compiledModel)
{
    EtwFilterStageCompiledSnapshot preStageSnapshot;
    preStageSnapshot.simpleFilter = compiledModel.preSimpleFilter;
    preStageSnapshot.detailedGroupList = compiledModel.preGroupList;
    const std::shared_ptr<const EtwFilterStageCompiledSnapshot> preSnapshotPointer =
        std::make_shared<const EtwFilterStageCompiledSnapshot>(std::move(preStageSnapshot));

    const auto applySimpleModel = [this](
        const EtwFilterStage stage,
        const EtwSimpleFilterModel& simpleModel) {
        EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
        if (uiState.applyDebounceTimer != nullptr)
        {
            uiState.applyDebounceTimer->stop();
        }
        if (uiState.enabledCheck != nullptr)
        {
            const QSignalBlocker blocker(uiState.enabledCheck);
            uiState.enabledCheck->setChecked(simpleModel.enabled);
        }
        const auto setEditText = [](QLineEdit* edit, const QString& text) {
            if (edit == nullptr)
            {
                return;
            }
            const QSignalBlocker blocker(edit);
            edit->setText(text);
        };
        setEditText(uiState.pidEdit, simpleModel.pidText);
        setEditText(uiState.processNameEdit, simpleModel.processNameText);
        setEditText(uiState.filePathEdit, simpleModel.filePathText);
        setEditText(uiState.eventIdEdit, simpleModel.eventIdText);
        setEditText(uiState.eventNameEdit, simpleModel.eventNameText);
        setEditText(uiState.registryPathEdit, simpleModel.registryPathText);
        setEditText(uiState.networkAddressEdit, simpleModel.networkAddressText);
        setEditText(uiState.networkPortEdit, simpleModel.networkPortText);
        setEditText(uiState.statusEdit, simpleModel.statusText);
        setEditText(uiState.customProviderEdit, simpleModel.customProviderText);
        setEditText(uiState.customActionEdit, simpleModel.customActionText);

        for (EtwSimpleFilterCheckUiState& checkState : uiState.providerCheckList)
        {
            if (checkState.checkBox == nullptr)
            {
                continue;
            }
            const QSignalBlocker blocker(checkState.checkBox);
            checkState.checkBox->setChecked(
                simpleModel.providerPresetNameList.contains(
                    checkState.valueText,
                    Qt::CaseInsensitive));
        }
        for (EtwSimpleFilterCheckUiState& checkState : uiState.actionCheckList)
        {
            if (checkState.checkBox == nullptr)
            {
                continue;
            }
            const QSignalBlocker blocker(checkState.checkBox);
            checkState.checkBox->setChecked(
                simpleModel.actionPresetList.contains(
                    checkState.valueText,
                    Qt::CaseInsensitive));
        }
    };
    const auto applyGroupModels = [this](
        const EtwFilterStage stage,
        const std::vector<EtwFilterRuleGroupModel>& groupModelList) {
        std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& targetGroupList =
            stage == EtwFilterStage::Pre
                ? m_etwPreFilterRuleGroupUiList
                : m_etwPostFilterRuleGroupUiList;
        for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : targetGroupList)
        {
            if (groupState != nullptr && groupState->containerWidget != nullptr)
            {
                delete groupState->containerWidget;
            }
        }
        targetGroupList.clear();
        if (stage == EtwFilterStage::Pre)
        {
            m_etwPreFilterNextGroupId = 1;
        }
        else
        {
            m_etwPostFilterNextGroupId = 1;
        }

        const std::size_t groupCount = std::max<std::size_t>(groupModelList.size(), 1U);
        for (std::size_t groupIndex = 0; groupIndex < groupCount; ++groupIndex)
        {
            addEtwFilterRuleGroup(stage);
            if (groupIndex >= groupModelList.size() || targetGroupList.empty())
            {
                continue;
            }

            EtwFilterRuleGroupUiState* groupState = targetGroupList.back().get();
            if (groupState == nullptr)
            {
                continue;
            }
            const EtwFilterRuleGroupModel& groupModel = groupModelList[groupIndex];
            if (groupState->enabledCheck != nullptr)
            {
                const QSignalBlocker blocker(groupState->enabledCheck);
                groupState->enabledCheck->setChecked(groupModel.enabled);
            }
            if (groupState->stringModeCombo != nullptr)
            {
                const QString modeText = etwFilterStringModeToText(groupModel.stringMode);
                const QSignalBlocker blocker(groupState->stringModeCombo);
                for (int index = 0; index < groupState->stringModeCombo->count(); ++index)
                {
                    if (groupState->stringModeCombo->itemData(index).toString()
                            .compare(modeText, Qt::CaseInsensitive) == 0)
                    {
                        groupState->stringModeCombo->setCurrentIndex(index);
                        break;
                    }
                }
            }
            if (groupState->caseSensitiveCheck != nullptr)
            {
                const QSignalBlocker blocker(groupState->caseSensitiveCheck);
                groupState->caseSensitiveCheck->setChecked(groupModel.caseSensitive);
            }
            if (groupState->invertCheck != nullptr)
            {
                const QSignalBlocker blocker(groupState->invertCheck);
                groupState->invertCheck->setChecked(groupModel.invertMatch);
            }
            if (groupState->detailVisibleColumnsCheck != nullptr)
            {
                const QSignalBlocker blocker(groupState->detailVisibleColumnsCheck);
                groupState->detailVisibleColumnsCheck->setChecked(
                    groupModel.detailVisibleColumnsOnly);
            }
            if (groupState->detailMatchAllFieldsCheck != nullptr)
            {
                const QSignalBlocker blocker(groupState->detailMatchAllFieldsCheck);
                groupState->detailMatchAllFieldsCheck->setChecked(
                    groupModel.detailMatchAllFields);
            }

            for (EtwFilterCategoryCheckUiState& categoryUi : groupState->categoryCheckList)
            {
                if (categoryUi.checkBox == nullptr)
                {
                    continue;
                }
                const QSignalBlocker blocker(categoryUi.checkBox);
                categoryUi.checkBox->setChecked(
                    groupModel.providerCategoryList.contains(
                        categoryUi.categoryText,
                        Qt::CaseInsensitive));
            }
            for (EtwFilterFieldUiState& fieldUi : groupState->fieldList)
            {
                if (fieldUi.inputEdit == nullptr)
                {
                    continue;
                }
                const auto found = std::find_if(
                    groupModel.fieldList.cbegin(),
                    groupModel.fieldList.cend(),
                    [&fieldUi](const EtwFilterRuleFieldModel& fieldModel) {
                        return fieldModel.fieldId == fieldUi.fieldId;
                    });
                const QSignalBlocker blocker(fieldUi.inputEdit);
                fieldUi.inputEdit->setText(
                    found == groupModel.fieldList.cend()
                        ? QString()
                        : found->inputText);
            }
        }
        rebuildEtwFilterRuleGroupUi(stage);
    };

    applySimpleModel(EtwFilterStage::Pre, filterModel.preSimpleFilter);
    applySimpleModel(EtwFilterStage::Post, filterModel.postSimpleFilter);
    applyGroupModels(EtwFilterStage::Pre, filterModel.preGroupList);
    applyGroupModels(EtwFilterStage::Post, filterModel.postGroupList);

    m_etwPreSimpleFilterCompiled = std::move(compiledModel.preSimpleFilter);
    m_etwPreFilterCompiledGroupList = std::move(compiledModel.preGroupList);
    m_etwPostSimpleFilterCompiled = std::move(compiledModel.postSimpleFilter);
    m_etwPostFilterCompiledGroupList = std::move(compiledModel.postGroupList);
    {
        std::lock_guard<std::mutex> lock(m_etwPreFilterSnapshotMutex);
        m_etwPreFilterCompiledSnapshot = preSnapshotPointer;
    }

    QString archiveDirectory;
    {
        std::lock_guard<std::mutex> lock(m_etwArchiveMutex);
        archiveDirectory = m_etwArchiveDirectory;
    }
    if (archiveDirectory.trimmed().isEmpty())
    {
        applyEtwPostFilterToTable(0, false);
    }
    else
    {
        scheduleEtwArchiveFilterRebuild();
    }

    updateEtwSimpleFilterStateLabel(EtwFilterStage::Pre);
    updateEtwSimpleFilterStateLabel(EtwFilterStage::Post);
    updateEtwFilterStateLabel(EtwFilterStage::Pre);
    updateEtwFilterStateLabel(EtwFilterStage::Post);
    updateEtwCollapseHeight();
}

bool MonitorDock::saveEtwFilterConfigToPath(const QString& filePath, const bool showErrorDialog) const
{
    const QString normalizedPath = QFileInfo(filePath).absoluteFilePath();
    if (normalizedPath.trimmed().isEmpty())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(nullptr, QStringLiteral("ETW筛选"), QStringLiteral("配置保存路径无效。"));
        }
        return false;
    }

    const auto serializeStageGroups = [](const std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList) {
        QJsonArray groupsArray;
        for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : groupList)
        {
            if (groupState == nullptr)
            {
                continue;
            }

            QJsonObject groupObject;
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonEnabledKey),
                groupState->enabledCheck == nullptr ? true : groupState->enabledCheck->isChecked());
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonStringModeKey),
                groupState->stringModeCombo != nullptr
                ? groupState->stringModeCombo->currentData().toString()
                : QStringLiteral("regex"));
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonCaseSensitiveKey),
                groupState->caseSensitiveCheck != nullptr && groupState->caseSensitiveCheck->isChecked());
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonInvertKey),
                groupState->invertCheck != nullptr && groupState->invertCheck->isChecked());
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonDetailVisibleOnlyKey),
                groupState->detailVisibleColumnsCheck != nullptr && groupState->detailVisibleColumnsCheck->isChecked());
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonDetailAllFieldsKey),
                groupState->detailMatchAllFieldsCheck == nullptr || groupState->detailMatchAllFieldsCheck->isChecked());

            QJsonArray categoryArray;
            for (const EtwFilterCategoryCheckUiState& categoryUi : groupState->categoryCheckList)
            {
                if (categoryUi.checkBox != nullptr && categoryUi.checkBox->isChecked())
                {
                    categoryArray.append(categoryUi.categoryText);
                }
            }
            groupObject.insert(QString::fromLatin1(kEtwFilterJsonProviderCategoriesKey), categoryArray);

            QJsonArray fieldArray;
            for (const EtwFilterFieldUiState& fieldUi : groupState->fieldList)
            {
                if (fieldUi.inputEdit == nullptr)
                {
                    continue;
                }
                const QString inputText = fieldUi.inputEdit->text().trimmed();
                if (inputText.isEmpty())
                {
                    continue;
                }

                QJsonObject fieldObject;
                fieldObject.insert(QString::fromLatin1(kEtwFilterJsonFieldKey), fieldUi.fieldKey);
                fieldObject.insert(QString::fromLatin1(kEtwFilterJsonFieldValue), inputText);
                fieldArray.append(fieldObject);
            }
            groupObject.insert(QString::fromLatin1(kEtwFilterJsonFieldsKey), fieldArray);
            groupsArray.append(groupObject);
        }
        return groupsArray;
    };

    const auto serializeSimpleFilter = [](const EtwSimpleFilterUiState& uiState) {
        const auto editText = [](QLineEdit* edit) {
            return edit == nullptr ? QString() : edit->text().trimmed();
        };
        QJsonObject simpleObject;
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonEnabledKey),
            uiState.enabledCheck == nullptr || uiState.enabledCheck->isChecked());
        simpleObject.insert(QString::fromLatin1(kEtwFilterJsonSimplePidKey), editText(uiState.pidEdit));
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleProcessNameKey),
            editText(uiState.processNameEdit));
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleFilePathKey),
            editText(uiState.filePathEdit));
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleEventIdKey),
            editText(uiState.eventIdEdit));
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleEventNameKey),
            editText(uiState.eventNameEdit));
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleRegistryPathKey),
            editText(uiState.registryPathEdit));
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleNetworkAddressKey),
            editText(uiState.networkAddressEdit));
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleNetworkPortKey),
            editText(uiState.networkPortEdit));
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleStatusKey),
            editText(uiState.statusEdit));
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleCustomProviderKey),
            editText(uiState.customProviderEdit));
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleCustomActionKey),
            editText(uiState.customActionEdit));

        QJsonArray providerArray;
        for (const EtwSimpleFilterCheckUiState& checkState : uiState.providerCheckList)
        {
            if (checkState.checkBox != nullptr && checkState.checkBox->isChecked())
            {
                providerArray.append(checkState.valueText);
            }
        }
        simpleObject.insert(QString::fromLatin1(kEtwFilterJsonSimpleProvidersKey), providerArray);

        QJsonArray actionArray;
        for (const EtwSimpleFilterCheckUiState& checkState : uiState.actionCheckList)
        {
            if (checkState.checkBox != nullptr && checkState.checkBox->isChecked())
            {
                actionArray.append(checkState.valueText);
            }
        }
        simpleObject.insert(QString::fromLatin1(kEtwFilterJsonSimpleActionsKey), actionArray);
        return simpleObject;
    };

    QJsonObject rootObject;
    rootObject.insert(QString::fromLatin1(kEtwFilterJsonVersionKey), 2);
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonSimplePreKey),
        serializeSimpleFilter(m_etwPreSimpleFilterUi));
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonSimplePostKey),
        serializeSimpleFilter(m_etwPostSimpleFilterUi));
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonPreGroupsKey),
        serializeStageGroups(m_etwPreFilterRuleGroupUiList));
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonPostGroupsKey),
        serializeStageGroups(m_etwPostFilterRuleGroupUiList));

    const QFileInfo fileInfo(normalizedPath);
    QDir outputDirectory(fileInfo.absolutePath());
    if (!outputDirectory.exists() && !outputDirectory.mkpath(QStringLiteral(".")))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(
                nullptr,
                QStringLiteral("ETW筛选"),
                QStringLiteral("创建配置目录失败：%1").arg(outputDirectory.absolutePath()));
        }
        return false;
    }

    const QByteArray serializedData =
        QJsonDocument(rootObject).toJson(QJsonDocument::Indented);
    QSaveFile outputFile(normalizedPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text)
        || outputFile.write(serializedData) != serializedData.size()
        || !outputFile.commit())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(
                nullptr,
                QStringLiteral("ETW筛选"),
                QStringLiteral("打开配置文件失败：%1").arg(normalizedPath));
        }
        return false;
    }
    return true;
}

bool MonitorDock::loadEtwFilterConfigFromPath(
    const QString& filePath,
    const bool showErrorDialog,
    const bool persistAsDefault)
{
    const QString normalizedPath = QFileInfo(filePath).absoluteFilePath();
    QFile inputFile(normalizedPath);
    if (!inputFile.exists())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("ETW筛选"), QStringLiteral("配置文件不存在：%1").arg(normalizedPath));
        }
        return false;
    }

    if (!inputFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("ETW筛选"), QStringLiteral("读取配置文件失败：%1").arg(normalizedPath));
        }
        return false;
    }

    const QByteArray jsonData = inputFile.readAll();
    inputFile.close();
    EtwFilterConfigModel candidateModel;
    if (!tryParseEtwFilterConfigModel(jsonData, candidateModel))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("ETW筛选"), QStringLiteral("配置文件格式无效：%1").arg(normalizedPath));
        }
        return false;
    }

    EtwFilterConfigCompiledModel compiledModel;
    QString compileErrorText;
    if (!tryCompileEtwFilterConfigModel(
            candidateModel,
            compiledModel,
            compileErrorText))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("ETW筛选器"), compileErrorText);
        }
        return false;
    }

    // 用户导入时先原子写入默认配置。持久化失败则不触碰 UI 和运行时筛选器。
    if (persistAsDefault
        && !saveEtwFilterConfigModelToPath(
            candidateModel,
            etwFilterConfigPath(),
            showErrorDialog))
    {
        return false;
    }

    commitEtwFilterConfigModel(candidateModel, std::move(compiledModel));
    return true;
}

void MonitorDock::saveEtwFilterConfigToDefaultPath(const bool showDialog) const
{
    const QString defaultPath = etwFilterConfigPath();
    const bool saved = saveEtwFilterConfigToPath(defaultPath, showDialog);
    if (saved && showDialog)
    {
        QMessageBox::information(
            const_cast<MonitorDock*>(this),
            QStringLiteral("ETW筛选"),
            QStringLiteral("筛选配置已保存到：%1").arg(defaultPath));
    }
}

void MonitorDock::loadEtwFilterConfigFromDefaultPath(const bool showDialog)
{
    const QString defaultPath = etwFilterConfigPath();
    const bool loaded = loadEtwFilterConfigFromPath(defaultPath, showDialog, false);
    if (!loaded)
    {
        // 默认文件缺失或无效时只编译当前 UI 默认值，不回写并覆盖原文件。
        const EtwFilterConfigModel currentModel = captureEtwFilterConfigModel();
        EtwFilterConfigCompiledModel compiledModel;
        QString compileErrorText;
        if (tryCompileEtwFilterConfigModel(
                currentModel,
                compiledModel,
                compileErrorText))
        {
            commitEtwFilterConfigModel(currentModel, std::move(compiledModel));
        }
    }
}

void MonitorDock::importEtwFilterConfigFromUserSelectedPath()
{
    const QString selectedPath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("导入ETW筛选配置"),
        QFileInfo(etwFilterConfigPath()).absolutePath(),
        QStringLiteral("ETW Config (*.cfg *.json);;All Files (*.*)"));
    if (selectedPath.trimmed().isEmpty())
    {
        return;
    }

    if (loadEtwFilterConfigFromPath(selectedPath, true, true))
    {
        QMessageBox::information(
            this,
            QStringLiteral("ETW筛选"),
            QStringLiteral("已导入配置：%1").arg(QFileInfo(selectedPath).absoluteFilePath()));
    }
}

void MonitorDock::exportEtwFilterConfigToUserSelectedPath() const
{
    const QString selectedPath = QFileDialog::getSaveFileName(
        const_cast<MonitorDock*>(this),
        QStringLiteral("导出ETW筛选配置"),
        etwFilterConfigPath(),
        QStringLiteral("ETW Config (*.cfg);;JSON (*.json);;All Files (*.*)"));
    if (selectedPath.trimmed().isEmpty())
    {
        return;
    }

    if (saveEtwFilterConfigToPath(selectedPath, true))
    {
        QMessageBox::information(
            const_cast<MonitorDock*>(this),
            QStringLiteral("ETW筛选"),
            QStringLiteral("已导出配置：%1").arg(QFileInfo(selectedPath).absoluteFilePath()));
    }
}

void MonitorDock::refreshWmiProvidersAsync()
{
    kLogEvent startEvent;
    info << startEvent
        << "[MonitorDock] 开始异步刷新WMI Provider。"
        << eol;

    m_wmiProviderStatusLabel->setText(QStringLiteral("● 刷新中..."));
    m_wmiProviderStatusLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));

    if (m_wmiProviderRefreshProgressPid == 0)
    {
        m_wmiProviderRefreshProgressPid = kPro.addReusable(this, "监控", "刷新WMI Provider");
    }
    kPro.set(m_wmiProviderRefreshProgressPid, "开始枚举WMI Provider", 0, 10.0f);

    QPointer<MonitorDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<WmiProviderEntry> providers;
        QString errorText;

        if (!initCom(&errorText))
        {
            QMetaObject::invokeMethod(qApp, [guardThis, errorText]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->m_wmiProviderStatusLabel->setText(QStringLiteral("● 初始化失败"));
                guardThis->m_wmiProviderStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
                if (guardThis->m_wmiProviderRefreshProgressPid != 0)
                {
                    kPro.set(guardThis->m_wmiProviderRefreshProgressPid, "WMI Provider刷新失败", 0, 100.0f);
                    guardThis->m_wmiProviderRefreshProgressPid = 0;
                }

                kLogEvent event;
                err << event << "[MonitorDock] WMI Provider初始化失败:" << errorText.toStdString() << eol;
            }, Qt::QueuedConnection);
            return;
        }

        CComPtr<IWbemServices> service;
        if (!connectWmi(&service, &errorText) || service == nullptr)
        {
            ::CoUninitialize();
            QMetaObject::invokeMethod(qApp, [guardThis, errorText]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->m_wmiProviderStatusLabel->setText(QStringLiteral("● 连接失败"));
                guardThis->m_wmiProviderStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
                if (guardThis->m_wmiProviderRefreshProgressPid != 0)
                {
                    kPro.set(guardThis->m_wmiProviderRefreshProgressPid, "WMI Provider刷新失败", 0, 100.0f);
                    guardThis->m_wmiProviderRefreshProgressPid = 0;
                }

                kLogEvent event;
                err << event << "[MonitorDock] WMI连接失败:" << errorText.toStdString() << eol;
            }, Qt::QueuedConnection);
            return;
        }

        CComPtr<IEnumWbemClassObject> enumerator;
        const HRESULT queryResult = service->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM __Win32Provider"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,
            &enumerator);

        if (SUCCEEDED(queryResult) && enumerator != nullptr)
        {
            while (true)
            {
                CComPtr<IWbemClassObject> item;
                ULONG count = 0;
                const HRESULT nextResult = enumerator->Next(100, 1, &item, &count);
                if (FAILED(nextResult) || count == 0 || item == nullptr)
                {
                    break;
                }

                VARIANT nameValue;
                VARIANT clsidValue;
                VARIANT hostingValue;
                ::VariantInit(&nameValue);
                ::VariantInit(&clsidValue);
                ::VariantInit(&hostingValue);

                item->Get(L"Name", 0, &nameValue, nullptr, nullptr);
                item->Get(L"CLSID", 0, &clsidValue, nullptr, nullptr);
                item->Get(L"HostingModel", 0, &hostingValue, nullptr, nullptr);

                WmiProviderEntry entry;
                entry.providerName = variantToText(nameValue);
                entry.nameSpaceText = QStringLiteral("ROOT\\CIMV2");
                entry.clsidText = variantToText(clsidValue);
                entry.eventClassCount = 0;
                entry.subscribable = !entry.providerName.trimmed().isEmpty()
                    && !variantToText(hostingValue).contains(QStringLiteral("Decoupled"), Qt::CaseInsensitive);

                providers.push_back(entry);

                ::VariantClear(&nameValue);
                ::VariantClear(&clsidValue);
                ::VariantClear(&hostingValue);
            }
        }

        int classCount = 0;
        CComPtr<IEnumWbemClassObject> classEnum;
        const HRESULT classQueryResult = service->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM meta_class WHERE __CLASS LIKE 'Win32\\_%Event'"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,
            &classEnum);
        if (SUCCEEDED(classQueryResult) && classEnum != nullptr)
        {
            while (true)
            {
                CComPtr<IWbemClassObject> item;
                ULONG count = 0;
                const HRESULT nextResult = classEnum->Next(100, 1, &item, &count);
                if (FAILED(nextResult) || count == 0 || item == nullptr)
                {
                    break;
                }
                ++classCount;
            }
        }

        for (WmiProviderEntry& entry : providers)
        {
            entry.eventClassCount = classCount;
        }

        ::CoUninitialize();

        QMetaObject::invokeMethod(qApp, [guardThis, providers]() {
            const auto commitProviders = [guardThis, providers]()
            {
                if (guardThis == nullptr)
                {
                    return;
                }

                guardThis->m_wmiProviders = providers;
                guardThis->m_wmiProviderModel->removeRows(0, guardThis->m_wmiProviderModel->rowCount());

                for (const WmiProviderEntry& entry : guardThis->m_wmiProviders)
                {
                    QList<QStandardItem*> rowItems;
                    rowItems << new QStandardItem(entry.providerName)
                        << new QStandardItem(entry.nameSpaceText)
                        << new QStandardItem(entry.clsidText)
                        << new QStandardItem(QString::number(entry.eventClassCount))
                        << new QStandardItem(ks::i18n::sourceText(entry.subscribable
                            ? QStringLiteral("可订阅")
                            : QStringLiteral("受限")));
                    guardThis->m_wmiProviderModel->appendRow(rowItems);
                }

                guardThis->applyWmiProviderFilter();
                guardThis->m_wmiProviderStatusLabel->setText(
                    QStringLiteral("● 已刷新 %1 项").arg(guardThis->m_wmiProviders.size()));
                guardThis->m_wmiProviderStatusLabel->setStyleSheet(buildStatusStyle(monitorSuccessColorHex()));
                if (guardThis->m_wmiProviderRefreshProgressPid != 0)
                {
                    kPro.set(guardThis->m_wmiProviderRefreshProgressPid, "WMI Provider完成", 0, 100.0f);
                    guardThis->m_wmiProviderRefreshProgressPid = 0;
                }

                kLogEvent event;
                info << event
                    << "[MonitorDock] WMI Provider刷新完成, providerCount="
                    << guardThis->m_wmiProviders.size()
                    << eol;
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("monitor-wmi-provider-apply"),
                { guardThis->m_wmiProviderTableView },
                commitProviders))
            {
                return;
            }
            commitProviders();
        }, Qt::QueuedConnection);
    }).detach();
}

void MonitorDock::refreshWmiEventClassesAsync()
{
    // 该刷新会先清空表格，再由后台结果整表回填；菜单打开时连启动阶段也延后。
    const QPointer<MonitorDock> deferredGuard(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("monitor-wmi-event-class-refresh-start"),
        { m_wmiEventClassTable },
        [deferredGuard]()
        {
            if (!deferredGuard.isNull())
            {
                deferredGuard->refreshWmiEventClassesAsync();
            }
        }))
    {
        return;
    }

    kLogEvent startEvent;
    info << startEvent
        << "[MonitorDock] 开始异步刷新WMI事件类。"
        << eol;

    m_wmiEventClassTable->setRowCount(0);

    QPointer<MonitorDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<QString> classes;
        QString errorText;

        if (!initCom(&errorText))
        {
            kLogEvent event;
            err << event
                << "[MonitorDock] WMI事件类刷新失败：COM初始化失败, error="
                << errorText.toStdString()
                << eol;
            return;
        }

        CComPtr<IWbemServices> service;
        if (!connectWmi(&service, &errorText) || service == nullptr)
        {
            ::CoUninitialize();
            kLogEvent event;
            err << event
                << "[MonitorDock] WMI事件类刷新失败：连接失败, error="
                << errorText.toStdString()
                << eol;
            return;
        }

        CComPtr<IEnumWbemClassObject> classEnum;
        const HRESULT enumResult = service->CreateClassEnum(
            _bstr_t(L"__Event"),
            WBEM_FLAG_DEEP | WBEM_FLAG_FORWARD_ONLY,
            nullptr,
            &classEnum);

        if (SUCCEEDED(enumResult) && classEnum != nullptr)
        {
            while (true)
            {
                CComPtr<IWbemClassObject> item;
                ULONG count = 0;
                const HRESULT nextResult = classEnum->Next(100, 1, &item, &count);
                if (FAILED(nextResult) || count == 0 || item == nullptr)
                {
                    break;
                }

                VARIANT classValue;
                ::VariantInit(&classValue);
                item->Get(L"__CLASS", 0, &classValue, nullptr, nullptr);
                const QString classText = variantToText(classValue).trimmed();
                ::VariantClear(&classValue);

                if (!classText.isEmpty())
                {
                    classes.push_back(classText);
                }
            }
        }

        std::sort(classes.begin(), classes.end(), [](const QString& a, const QString& b) {
            return QString::compare(a, b, Qt::CaseInsensitive) < 0;
        });
        classes.erase(
            std::unique(classes.begin(), classes.end(), [](const QString& a, const QString& b) {
                return QString::compare(a, b, Qt::CaseInsensitive) == 0;
            }),
            classes.end());

        ::CoUninitialize();

        QMetaObject::invokeMethod(qApp, [guardThis, classes]() {
            const auto commitClasses = [guardThis, classes]()
            {
                if (guardThis == nullptr)
                {
                    return;
                }

                guardThis->m_wmiEventClassTable->setRowCount(static_cast<int>(classes.size()));
                for (int row = 0; row < static_cast<int>(classes.size()); ++row)
                {
                    const QString className = classes[static_cast<std::size_t>(row)];

                    QTableWidgetItem* checkItem = new QTableWidgetItem();
                    checkItem->setFlags(checkItem->flags() | Qt::ItemIsUserCheckable);
                    checkItem->setCheckState(className.startsWith(QStringLiteral("Win32_"), Qt::CaseInsensitive)
                        ? Qt::Checked
                        : Qt::Unchecked);

                    guardThis->m_wmiEventClassTable->setItem(row, 0, checkItem);
                    guardThis->m_wmiEventClassTable->setItem(row, 1, new QTableWidgetItem(className));
                    guardThis->m_wmiEventClassTable->setItem(
                        row,
                        2,
                        new QTableWidgetItem(className.startsWith(
                            QStringLiteral("Win32_"), Qt::CaseInsensitive)
                            ? QStringLiteral("Win32")
                            : ks::i18n::sourceText(QStringLiteral("其他"))));
                }
                // 事件类刷新后重新计算折叠页目标高度，确保“WMI订阅”页不会因为行数变化撑爆折叠栏。
                guardThis->updateWmiSubscribePanelCompactLayout();

                kLogEvent event;
                info << event
                    << "[MonitorDock] WMI事件类刷新完成, classCount="
                    << classes.size()
                    << eol;
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("monitor-wmi-event-class-apply"),
                { guardThis->m_wmiEventClassTable },
                commitClasses))
            {
                return;
            }
            commitClasses();
        }, Qt::QueuedConnection);
    }).detach();
}

void MonitorDock::applyWmiProviderFilter()
{
    const QString keyword = m_wmiProviderFilterEdit->text().trimmed();
    m_wmiProviderProxyModel->setFilterFixedString(keyword);

    kLogEvent event;
    dbg << event
        << "[MonitorDock] 应用WMI Provider过滤, keyword="
        << keyword.toStdString()
        << eol;
}

void MonitorDock::applyWmiEventFilter()
{
    if (m_wmiEventTable == nullptr)
    {
        return;
    }

    const QString globalKeyword = m_wmiEventGlobalFilterEdit != nullptr
        ? m_wmiEventGlobalFilterEdit->text().trimmed()
        : QString();
    const QString providerKeyword = m_wmiEventProviderFilterEdit != nullptr
        ? m_wmiEventProviderFilterEdit->text().trimmed()
        : QString();
    const QString classKeyword = m_wmiEventClassFilterEdit != nullptr
        ? m_wmiEventClassFilterEdit->text().trimmed()
        : QString();
    const QString pidKeyword = m_wmiEventPidFilterEdit != nullptr
        ? m_wmiEventPidFilterEdit->text().trimmed()
        : QString();
    const QString detailKeyword = m_wmiEventDetailFilterEdit != nullptr
        ? m_wmiEventDetailFilterEdit->text().trimmed()
        : QString();
    const bool useRegex = m_wmiEventRegexCheck != nullptr && m_wmiEventRegexCheck->isChecked();
    const bool invertMatch = m_wmiEventInvertCheck != nullptr && m_wmiEventInvertCheck->isChecked();
    const Qt::CaseSensitivity caseSensitivity =
        (m_wmiEventCaseCheck != nullptr && m_wmiEventCaseCheck->isChecked())
        ? Qt::CaseSensitive
        : Qt::CaseInsensitive;

    int visibleCount = 0;
    const int totalCount = m_wmiEventTable->rowCount();
    for (int row = 0; row < totalCount; ++row)
    {
        const QString tsText = m_wmiEventTable->item(row, 0) != nullptr
            ? m_wmiEventTable->item(row, 0)->text()
            : QString();
        const QString providerText = m_wmiEventTable->item(row, 1) != nullptr
            ? m_wmiEventTable->item(row, 1)->text()
            : QString();
        const QString classText = m_wmiEventTable->item(row, 2) != nullptr
            ? m_wmiEventTable->item(row, 2)->text()
            : QString();
        const QString pidText = m_wmiEventTable->item(row, 3) != nullptr
            ? m_wmiEventTable->item(row, 3)->text()
            : QString();
        const QString detailText = m_wmiEventTable->item(row, 4) != nullptr
            ? m_wmiEventTable->item(row, 4)->text()
            : QString();

        const QString mergedText = QStringLiteral("%1 %2 %3 %4 %5")
            .arg(tsText, providerText, classText, pidText, detailText);
        const bool globalMatch = textMatch(mergedText, globalKeyword, useRegex, caseSensitivity);
        const bool providerMatch = textMatch(providerText, providerKeyword, useRegex, caseSensitivity);
        const bool classMatch = textMatch(classText, classKeyword, useRegex, caseSensitivity);
        const bool pidMatch = textMatch(pidText, pidKeyword, useRegex, caseSensitivity);
        const bool detailMatch = textMatch(detailText, detailKeyword, useRegex, caseSensitivity);
        bool showRow = globalMatch && providerMatch && classMatch && pidMatch && detailMatch;
        if (invertMatch)
        {
            showRow = !showRow;
        }

        m_wmiEventTable->setRowHidden(row, !showRow);
        if (showRow)
        {
            ++visibleCount;
        }
    }

    if (m_wmiEventFilterStatusLabel != nullptr)
    {
        m_wmiEventFilterStatusLabel->setText(QStringLiteral("可见: %1 / %2").arg(visibleCount).arg(totalCount));
    }
    if (m_wmiEventKeepBottomCheck != nullptr && m_wmiEventKeepBottomCheck->isChecked())
    {
        m_wmiEventTable->scrollToBottom();
    }

    kLogEvent event;
    dbg << event
        << "[MonitorDock] 应用WMI事件筛选, total="
        << totalCount
        << ", visible="
        << visibleCount
        << ", regex="
        << (useRegex ? "true" : "false")
        << ", invert="
        << (invertMatch ? "true" : "false")
        << eol;
}

void MonitorDock::clearWmiEventFilter()
{
    if (m_wmiEventGlobalFilterEdit != nullptr) m_wmiEventGlobalFilterEdit->clear();
    if (m_wmiEventProviderFilterEdit != nullptr) m_wmiEventProviderFilterEdit->clear();
    if (m_wmiEventClassFilterEdit != nullptr) m_wmiEventClassFilterEdit->clear();
    if (m_wmiEventPidFilterEdit != nullptr) m_wmiEventPidFilterEdit->clear();
    if (m_wmiEventDetailFilterEdit != nullptr) m_wmiEventDetailFilterEdit->clear();
    if (m_wmiEventRegexCheck != nullptr) m_wmiEventRegexCheck->setChecked(false);
    if (m_wmiEventCaseCheck != nullptr) m_wmiEventCaseCheck->setChecked(false);
    if (m_wmiEventInvertCheck != nullptr) m_wmiEventInvertCheck->setChecked(false);

    applyWmiEventFilter();

    kLogEvent event;
    info << event
        << "[MonitorDock] 已清空WMI事件筛选条件。"
        << eol;
}

void MonitorDock::startWmiSubscription()
{
    if (m_wmiSubscribeRunning.load())
    {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] 忽略启动WMI订阅：当前已在运行。"
            << eol;
        return;
    }

    // 上一轮线程即使已经自然退出，std::thread 仍必须先 join；否则覆盖
    // unique_ptr 会析构一个 joinable thread 并触发 std::terminate。
    if (m_wmiSubscribeThread != nullptr && m_wmiSubscribeThread->joinable())
    {
        m_wmiSubscribeThread->join();
        m_wmiSubscribeThread.reset();
    }

    std::vector<QString> classList;
    for (int row = 0; row < m_wmiEventClassTable->rowCount(); ++row)
    {
        QTableWidgetItem* checkItem = m_wmiEventClassTable->item(row, 0);
        QTableWidgetItem* classItem = m_wmiEventClassTable->item(row, 1);
        if (checkItem != nullptr && classItem != nullptr && checkItem->checkState() == Qt::Checked)
        {
            classList.push_back(classItem->text().trimmed());
        }
    }

    if (classList.empty())
    {
        kLogEvent event;
        warn << event
            << "[MonitorDock] 启动WMI订阅失败：未选择事件类。"
            << eol;
        QMessageBox::information(this, QStringLiteral("WMI订阅"), QStringLiteral("请至少选择一个事件类。"));
        return;
    }

    const QString whereClause = m_wmiWhereEditor->toPlainText().trimmed();

    {
        kLogEvent event;
        info << event
            << "[MonitorDock] 启动WMI订阅, classCount="
            << classList.size()
            << ", whereClause="
            << whereClause.toStdString()
            << eol;
    }

    m_wmiSubscribeRunning.store(true);
    m_wmiSubscribePaused.store(false);
    m_wmiSubscribeStopFlag.store(false);

    if (m_wmiSubscribeProgressPid == 0)
    {
        m_wmiSubscribeProgressPid = kPro.addReusable(this, "监控", "WMI订阅");
    }
    kPro.set(m_wmiSubscribeProgressPid, "建立WMI订阅", 0, 10.0f);

    m_wmiSubscribeStatusLabel->setText(QStringLiteral("● 订阅中"));
    m_wmiSubscribeStatusLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));
    if (m_wmiUiUpdateTimer != nullptr && !m_wmiUiUpdateTimer->isActive())
    {
        m_wmiUiUpdateTimer->start();
    }
    {
        // 启动新一轮订阅前清空待刷队列，避免残留事件混入新会话。
        std::lock_guard<std::mutex> lock(m_wmiPendingMutex);
        m_wmiPendingRows.clear();
    }

    QPointer<MonitorDock> guardThis(this);
    m_wmiSubscribeThread = std::make_unique<std::thread>([guardThis, classList, whereClause]() {
        QString errorText;
        if (!initCom(&errorText))
        {
            QMetaObject::invokeMethod(qApp, [guardThis, errorText]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->m_wmiSubscribeRunning.store(false);
                guardThis->m_wmiSubscribeStatusLabel->setText(QString("● 初始化失败: %1").arg(errorText));
                guardThis->m_wmiSubscribeStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
                if (guardThis->m_wmiSubscribeProgressPid != 0)
                {
                    kPro.set(guardThis->m_wmiSubscribeProgressPid, "WMI订阅失败", 0, 100.0f);
                    guardThis->m_wmiSubscribeProgressPid = 0;
                }
            }, Qt::QueuedConnection);
            return;
        }

        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }
            kPro.set(guardThis->m_wmiSubscribeProgressPid, "WMI COM初始化完成", 0, 20.0f);
        }, Qt::QueuedConnection);

        CComPtr<IWbemServices> service;
        if (!connectWmi(&service, &errorText) || service == nullptr)
        {
            ::CoUninitialize();
            QMetaObject::invokeMethod(qApp, [guardThis, errorText]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->m_wmiSubscribeRunning.store(false);
                guardThis->m_wmiSubscribeStatusLabel->setText(QString("● 连接失败: %1").arg(errorText));
                guardThis->m_wmiSubscribeStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
                if (guardThis->m_wmiSubscribeProgressPid != 0)
                {
                    kPro.set(guardThis->m_wmiSubscribeProgressPid, "WMI连接失败", 0, 100.0f);
                    guardThis->m_wmiSubscribeProgressPid = 0;
                }
            }, Qt::QueuedConnection);
            return;
        }

        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }
            kPro.set(guardThis->m_wmiSubscribeProgressPid, "WMI服务连接成功", 0, 30.0f);
        }, Qt::QueuedConnection);

        struct ClassEnum
        {
            QString className;
            CComPtr<IEnumWbemClassObject> enumerator;
        };

        std::vector<ClassEnum> enums;
        for (std::size_t classIndex = 0; classIndex < classList.size(); ++classIndex)
        {
            const QString className = classList[classIndex];
            if (guardThis == nullptr || guardThis->m_wmiSubscribeStopFlag.load())
            {
                break;
            }

            const float setupProgressValue = 30.0f
                + (classList.empty()
                    ? 0.0f
                    : (static_cast<float>(classIndex + 1) * 15.0f / static_cast<float>(classList.size())));
            QMetaObject::invokeMethod(qApp, [guardThis, setupProgressValue, className]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                kPro.set(
                    guardThis->m_wmiSubscribeProgressPid,
                    QString("建立订阅: %1").arg(className).toStdString(),
                    0,
                    setupProgressValue);
            }, Qt::QueuedConnection);

            QString query = QStringLiteral("SELECT * FROM %1").arg(className);
            if (!whereClause.isEmpty())
            {
                query += QStringLiteral(" WHERE ") + whereClause;
            }

            CComPtr<IEnumWbemClassObject> enumerator;
            const HRESULT subResult = service->ExecNotificationQuery(
                bstr_t("WQL"),
                bstr_t(query.toStdWString().c_str()),
                WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY,
                nullptr,
                &enumerator);

            if (SUCCEEDED(subResult) && enumerator != nullptr)
            {
                enums.push_back(ClassEnum{ className, enumerator });
            }
            else
            {
                kLogEvent event;
                warn << event
                    << "[MonitorDock] WMI订阅类创建失败, className="
                    << className.toStdString()
                    << ", query="
                    << query.toStdString()
                    << ", hr="
                    << static_cast<unsigned long>(subResult)
                    << eol;
            }
        }

        if (enums.empty())
        {
            ::CoUninitialize();
            QMetaObject::invokeMethod(qApp, [guardThis]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->m_wmiSubscribeRunning.store(false);
                guardThis->m_wmiSubscribeStatusLabel->setText(QStringLiteral("● 未建立任何有效订阅"));
                guardThis->m_wmiSubscribeStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
                if (guardThis->m_wmiSubscribeProgressPid != 0)
                {
                    kPro.set(guardThis->m_wmiSubscribeProgressPid, "WMI订阅失败(无有效类)", 0, 100.0f);
                    guardThis->m_wmiSubscribeProgressPid = 0;
                }
            }, Qt::QueuedConnection);
            return;
        }

        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }
            kPro.set(guardThis->m_wmiSubscribeProgressPid, "WMI订阅已建立", 0, 45.0f);
        }, Qt::QueuedConnection);

        std::size_t eventCount = 0;
        while (guardThis != nullptr && !guardThis->m_wmiSubscribeStopFlag.load())
        {
            if (guardThis->m_wmiSubscribePaused.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(120));
                continue;
            }

            bool hasEvent = false;
            for (ClassEnum& classEnum : enums)
            {
                if (guardThis == nullptr || guardThis->m_wmiSubscribeStopFlag.load())
                {
                    break;
                }

                CComPtr<IWbemClassObject> eventObject;
                ULONG count = 0;
                const HRESULT nextResult = classEnum.enumerator->Next(100, 1, &eventObject, &count);
                if (FAILED(nextResult) || count == 0 || eventObject == nullptr)
                {
                    continue;
                }

                hasEvent = true;
                ++eventCount;

                QString pidText = QStringLiteral("-");
                QString detailText;

                VARIANT targetValue;
                ::VariantInit(&targetValue);
                if (SUCCEEDED(eventObject->Get(L"TargetInstance", 0, &targetValue, nullptr, nullptr))
                    && targetValue.vt == VT_UNKNOWN
                    && targetValue.punkVal != nullptr)
                {
                    CComPtr<IWbemClassObject> targetObject;
                    targetValue.punkVal->QueryInterface(IID_IWbemClassObject, reinterpret_cast<void**>(&targetObject));
                    if (targetObject != nullptr)
                    {
                        VARIANT processIdValue;
                        VARIANT nameValue;
                        ::VariantInit(&processIdValue);
                        ::VariantInit(&nameValue);
                        targetObject->Get(L"ProcessId", 0, &processIdValue, nullptr, nullptr);
                        targetObject->Get(L"Name", 0, &nameValue, nullptr, nullptr);

                        const QString pidPart = variantToText(processIdValue);
                        const QString namePart = variantToText(nameValue);
                        if (!pidPart.isEmpty() || !namePart.isEmpty())
                        {
                            pidText = QStringLiteral("%1 / %2").arg(pidPart, namePart);
                        }

                        ::VariantClear(&processIdValue);
                        ::VariantClear(&nameValue);
                    }
                }
                ::VariantClear(&targetValue);

                eventObject->BeginEnumeration(0);
                int propertyCount = 0;
                while (propertyCount < 8)
                {
                    BSTR propertyName = nullptr;
                    VARIANT propertyValue;
                    CIMTYPE typeValue = 0;
                    LONG flavor = 0;
                    ::VariantInit(&propertyValue);

                    const HRESULT nextProperty = eventObject->Next(0, &propertyName, &propertyValue, &typeValue, &flavor);
                    if (nextProperty == WBEM_S_NO_MORE_DATA)
                    {
                        ::VariantClear(&propertyValue);
                        break;
                    }

                    if (SUCCEEDED(nextProperty) && propertyName != nullptr)
                    {
                        if (!detailText.isEmpty())
                        {
                            detailText += QStringLiteral("; ");
                        }
                        detailText += QString::fromWCharArray(propertyName) + QStringLiteral("=") + variantToText(propertyValue);
                        ++propertyCount;
                    }

                    if (propertyName != nullptr)
                    {
                        ::SysFreeString(propertyName);
                    }
                    ::VariantClear(&propertyValue);
                }
                eventObject->EndEnumeration();

                if (detailText.isEmpty())
                {
                    detailText = QStringLiteral("<无详情>");
                }

                if (guardThis != nullptr)
                {
                    // 高频事件先入队，交由 UI 节流器批量刷新，避免每条事件都触发表格重排。
                    guardThis->enqueueWmiEventRow(classEnum.className, classEnum.className, pidText, detailText);
                }
            }

            if (!hasEvent)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(40));
            }

            if (guardThis != nullptr && eventCount % 20 == 0)
            {
                const float progressValue = 45.0f + static_cast<float>(std::min<std::size_t>(eventCount, 200)) * 0.25f;
                QMetaObject::invokeMethod(qApp, [guardThis, progressValue]() {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    kPro.set(guardThis->m_wmiSubscribeProgressPid, "WMI事件接收中", 0, std::min(progressValue, 95.0f));
                }, Qt::QueuedConnection);
            }
        }

        ::CoUninitialize();

        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->flushWmiPendingRows();
            if (guardThis->m_wmiUiUpdateTimer != nullptr)
            {
                guardThis->m_wmiUiUpdateTimer->stop();
            }
            guardThis->m_wmiSubscribeRunning.store(false);
            guardThis->m_wmiSubscribePaused.store(false);
            guardThis->m_wmiSubscribeStatusLabel->setText(QStringLiteral("● 已停止"));
            guardThis->m_wmiSubscribeStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));
            if (guardThis->m_wmiSubscribeProgressPid != 0)
            {
                kPro.set(guardThis->m_wmiSubscribeProgressPid, "WMI订阅结束", 0, 100.0f);
                guardThis->m_wmiSubscribeProgressPid = 0;
            }

            kLogEvent event;
            info << event
                << "[MonitorDock] WMI订阅线程已退出。"
                << eol;
        }, Qt::QueuedConnection);
    });
}

void MonitorDock::stopWmiSubscription()
{
    stopWmiSubscriptionInternal(false);
}

void MonitorDock::stopWmiSubscriptionInternal(bool waitForThread)
{
    {
        kLogEvent event;
        info << event
            << "[MonitorDock] 停止WMI订阅请求, waitForThread="
            << (waitForThread ? "true" : "false")
            << eol;
    }

    m_wmiSubscribeStopFlag.store(true);

    if (m_wmiSubscribeStatusLabel != nullptr)
    {
        m_wmiSubscribeStatusLabel->setText(QStringLiteral("● 停止中..."));
        m_wmiSubscribeStatusLabel->setStyleSheet(buildStatusStyle(monitorWarningColorHex()));
    }

    if (m_wmiSubscribeThread == nullptr || !m_wmiSubscribeThread->joinable())
    {
        m_wmiSubscribeThread.reset();
        m_wmiSubscribeRunning.store(false);
        m_wmiSubscribePaused.store(false);
        if (m_wmiUiUpdateTimer != nullptr)
        {
            m_wmiUiUpdateTimer->stop();
        }
        if (m_wmiSubscribeProgressPid != 0)
        {
            kPro.set(m_wmiSubscribeProgressPid, "WMI订阅结束", 0, 100.0f);
            m_wmiSubscribeProgressPid = 0;
        }
        kLogEvent event;
        dbg << event
            << "[MonitorDock] 停止WMI订阅：当前无活动线程。"
            << eol;
        return;
    }

    if (waitForThread)
    {
        // 析构路径：同步等待线程退出，确保对象销毁时无并发访问。
        m_wmiSubscribeThread->join();
        m_wmiSubscribeThread.reset();
        m_wmiSubscribeRunning.store(false);
        m_wmiSubscribePaused.store(false);
        if (m_wmiUiUpdateTimer != nullptr)
        {
            m_wmiUiUpdateTimer->stop();
        }
        if (m_wmiSubscribeProgressPid != 0)
        {
            kPro.set(m_wmiSubscribeProgressPid, "WMI订阅结束", 0, 100.0f);
            m_wmiSubscribeProgressPid = 0;
        }
        kLogEvent event;
        info << event
            << "[MonitorDock] 停止WMI订阅：同步等待线程结束完成。"
            << eol;
        return;
    }

    // 保留 m_wmiSubscribeThread 的所有权，析构函数才能等待 COM/WMI
    // 查询循环真正退出，避免后台线程在 MonitorDock 释放后访问成员。
}

void MonitorDock::setWmiSubscriptionPaused(bool paused)
{
    if (!m_wmiSubscribeRunning.load())
    {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] 忽略WMI暂停操作：订阅未运行。"
            << eol;
        return;
    }

    m_wmiSubscribePaused.store(paused);
    if (paused)
    {
        m_wmiSubscribeStatusLabel->setText(QStringLiteral("● 已暂停"));
        m_wmiSubscribeStatusLabel->setStyleSheet(buildStatusStyle(monitorWarningColorHex()));
    }
    else
    {
        m_wmiSubscribeStatusLabel->setText(QStringLiteral("● 订阅中"));
        m_wmiSubscribeStatusLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));
    }

    kLogEvent event;
    info << event
        << "[MonitorDock] WMI订阅暂停状态变更, paused="
        << (paused ? "true" : "false")
        << eol;
}

void MonitorDock::enqueueWmiEventRow(
    const QString& providerName,
    const QString& className,
    const QString& pidAndName,
    const QString& detailText)
{
    // 后台线程仅负责写入待处理队列，避免直接触发表格重绘造成主线程抖动。
    QStringList rowValues;
    rowValues.reserve(5);
    rowValues << QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"))
        << providerName
        << className
        << pidAndName
        << detailText;

    std::lock_guard<std::mutex> lock(m_wmiPendingMutex);
    m_wmiPendingRows.push_back(std::move(rowValues));
}

void MonitorDock::flushWmiPendingRows()
{
    // 先进入菜单提交门，再从共享队列移走事件；latest-wins 仅合并 timeout，
    // 不会覆盖已经取出的 WMI 数据。
    const QPointer<MonitorDock> guardThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("monitor-wmi-event-flush"),
        { m_wmiEventTable },
        [guardThis]()
        {
            if (!guardThis.isNull())
            {
                guardThis->flushWmiPendingRows();
            }
        }))
    {
        return;
    }

    // 主线程批量刷入：每个周期限制条数，防止一次性插入过多行阻塞 UI。
    std::vector<QStringList> rowsToFlush;
    {
        std::lock_guard<std::mutex> lock(m_wmiPendingMutex);
        if (m_wmiPendingRows.empty())
        {
            return;
        }

        constexpr std::size_t kMaxRowsPerFlush = 240;
        const std::size_t flushCount = std::min<std::size_t>(kMaxRowsPerFlush, m_wmiPendingRows.size());
        rowsToFlush.reserve(flushCount);
        for (std::size_t rowIndex = 0; rowIndex < flushCount; ++rowIndex)
        {
            rowsToFlush.push_back(std::move(m_wmiPendingRows[rowIndex]));
        }
        using DiffType = std::vector<QStringList>::difference_type;
        m_wmiPendingRows.erase(
            m_wmiPendingRows.begin(),
            m_wmiPendingRows.begin() + static_cast<DiffType>(flushCount));
    }

    for (const QStringList& rowValues : rowsToFlush)
    {
        if (rowValues.size() < 5)
        {
            continue;
        }
        appendWmiEventRow(rowValues[1], rowValues[2], rowValues[3], rowValues[4]);

        QTableWidgetItem* tsItem = m_wmiEventTable->item(m_wmiEventTable->rowCount() - 1, 0);
        if (tsItem != nullptr)
        {
            tsItem->setText(rowValues[0]);
            tsItem->setToolTip(rowValues[0]);
        }
    }

    // 每批次刷入完成后统一应用筛选，避免逐行重算造成 UI 抖动。
    applyWmiEventFilter();

    kLogEvent event;
    dbg << event
        << "[MonitorDock] 批量刷新WMI事件到UI, flushCount="
        << rowsToFlush.size()
        << ", tableRowCount="
        << m_wmiEventTable->rowCount()
        << eol;
}

void MonitorDock::appendWmiEventRow(
    const QString& providerName,
    const QString& className,
    const QString& pidAndName,
    const QString& detailText)
{
    const int row = m_wmiEventTable->rowCount();
    m_wmiEventTable->insertRow(row);

    const QString ts = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));

    QTableWidgetItem* tsItem = new QTableWidgetItem(ts);
    QTableWidgetItem* providerItem = new QTableWidgetItem(providerName);
    QTableWidgetItem* classItem = new QTableWidgetItem(className);
    QTableWidgetItem* pidItem = new QTableWidgetItem(pidAndName);
    QTableWidgetItem* detailItem = new QTableWidgetItem(detailText);

    tsItem->setToolTip(ts);
    providerItem->setToolTip(providerName);
    classItem->setToolTip(className);
    pidItem->setToolTip(pidAndName);
    detailItem->setToolTip(detailText);

    m_wmiEventTable->setItem(row, 0, tsItem);
    m_wmiEventTable->setItem(row, 1, providerItem);
    m_wmiEventTable->setItem(row, 2, classItem);
    m_wmiEventTable->setItem(row, 3, pidItem);
    m_wmiEventTable->setItem(row, 4, detailItem);

    while (m_wmiEventTable->rowCount() > 6000)
    {
        m_wmiEventTable->removeRow(0);
    }
}

void MonitorDock::exportWmiRowsToTsv()
{
    if (m_wmiEventTable == nullptr || m_wmiEventTable->rowCount() == 0)
    {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] WMI导出取消：无可导出事件。"
            << eol;
        QMessageBox::information(this, QStringLiteral("导出WMI"), QStringLiteral("当前没有可导出的WMI事件。"));
        return;
    }

    int visibleCount = 0;
    for (int row = 0; row < m_wmiEventTable->rowCount(); ++row)
    {
        if (!m_wmiEventTable->isRowHidden(row))
        {
            ++visibleCount;
        }
    }
    if (visibleCount == 0)
    {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] WMI导出取消：当前筛选后无可见事件。"
            << eol;
        QMessageBox::information(this, QStringLiteral("导出WMI"), QStringLiteral("当前筛选结果为空，没有可导出的WMI事件。"));
        return;
    }

    const QString defaultName = QStringLiteral("wmi_events_%1.tsv")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));

    const QString path = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出WMI结果"),
        defaultName,
        QStringLiteral("TSV文件 (*.tsv);;文本文件 (*.txt)"));

    if (path.trimmed().isEmpty())
    {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] WMI导出取消：用户未选择路径。"
            << eol;
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        kLogEvent event;
        err << event
            << "[MonitorDock] WMI导出失败：无法写入文件, path="
            << path.toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("导出WMI"), QStringLiteral("无法写入文件：%1").arg(path));
        return;
    }

    QTextStream out(&file);

    QStringList header;
    for (int col = 0; col < m_wmiEventTable->columnCount(); ++col)
    {
        QTableWidgetItem* item = m_wmiEventTable->horizontalHeaderItem(col);
        header << (item != nullptr ? item->text() : QString());
    }
    out << header.join('\t') << '\n';

    for (int row = 0; row < m_wmiEventTable->rowCount(); ++row)
    {
        if (m_wmiEventTable->isRowHidden(row))
        {
            continue;
        }

        QStringList values;
        for (int col = 0; col < m_wmiEventTable->columnCount(); ++col)
        {
            QTableWidgetItem* item = m_wmiEventTable->item(row, col);
            values << (item != nullptr ? item->text().replace('\t', ' ') : QString());
        }
        out << values.join('\t') << '\n';
    }

    file.close();

    kLogEvent event;
    info << event
        << "[MonitorDock] WMI导出完成:"
        << path.toStdString()
        << ", visibleRows="
        << visibleCount
        << eol;
    QMessageBox::information(this, QStringLiteral("导出WMI"), QStringLiteral("导出完成：%1").arg(path));
}

void MonitorDock::openWmiEventDetailViewerForRow(const int row) const
{
    const QString detailText = buildWmiRowDetailText(m_wmiEventTable, row);
    if (detailText.trimmed().isEmpty())
    {
        return;
    }

    QString classText;
    if (m_wmiEventTable != nullptr)
    {
        QTableWidgetItem* classItem = m_wmiEventTable->item(row, 2);
        if (classItem != nullptr)
        {
            classText = classItem->text().trimmed();
        }
    }

    monitor_text_viewer::showReadOnlyTextWindow(
        const_cast<MonitorDock*>(this),
        QStringLiteral("WMI 返回详情 - %1").arg(classText.isEmpty() ? QStringLiteral("事件") : classText),
        detailText,
        QStringLiteral("monitor://wmi/row-%1.txt").arg(row + 1));
}

void MonitorDock::showWmiEventContextMenu(const QPoint& position)
{
    const QModelIndex index = m_wmiEventTable->indexAt(position);
    if (!index.isValid())
    {
        return;
    }

    const int row = index.row();
    const int col = index.column();

    QMenu menu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* viewDetailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("查看返回详情"));
    menu.addSeparator();
    QAction* copyDetailAction = menu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制返回详情文本"));
    QAction* copyCellAction = menu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制单元格"));
    QAction* copyRowAction = menu.addAction(QIcon(":/Icon/log_clipboard.svg"), QStringLiteral("复制整行"));
    menu.addSeparator();
    QAction* gotoProcessAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
    ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [this, row]() -> ks::online_scan::SandboxUploadTarget {
            // 输入：WMI 事件表当前右键行。
            // 处理：从 PID/TID 列解析 PID，并查询该进程 EXE 路径。
            // 返回：VT 上传目标；解析失败时返回 errorText，避免重复弹窗逻辑散落各处。
            QTableWidgetItem* pidItem = m_wmiEventTable != nullptr
                ? m_wmiEventTable->item(row, 3)
                : nullptr;
            std::uint32_t pidValue = 0;
            if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &pidValue))
            {
                return {
                    QString(),
                    QStringLiteral("WMI 事件"),
                    QStringLiteral("当前 WMI 事件行未解析出有效 PID，无法上传发起进程文件。")
                };
            }

            const QString processPath = QString::fromStdString(ks::process::QueryProcessPathByPid(pidValue)).trimmed();
            if (processPath.isEmpty())
            {
                return {
                    QString(),
                    QStringLiteral("WMI 事件 PID=%1").arg(pidValue),
                    QStringLiteral("无法解析 PID=%1 的进程镜像路径。进程可能已退出，或当前权限不足。").arg(pidValue)
                };
            }

            return {
                processPath,
                QStringLiteral("WMI 事件 PID=%1").arg(pidValue),
                QString()
            };
        });

    QAction* action = menu.exec(m_wmiEventTable->viewport()->mapToGlobal(position));
    if (action == nullptr)
    {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] WMI事件右键菜单取消。"
            << eol;
        return;
    }

    if (action == viewDetailAction)
    {
        kLogEvent event;
        info << event
            << "[MonitorDock] WMI事件右键操作：查看返回详情, row="
            << row
            << eol;
        openWmiEventDetailViewerForRow(row);
        return;
    }

    if (action == copyDetailAction)
    {
        const QString detailText = buildWmiRowDetailText(m_wmiEventTable, row);
        QApplication::clipboard()->setText(detailText);
        kLogEvent event;
        dbg << event
            << "[MonitorDock] WMI事件右键操作：复制返回详情文本, row="
            << row
            << eol;
        return;
    }

    if (action == copyCellAction)
    {
        QTableWidgetItem* item = m_wmiEventTable->item(row, col);
        if (item != nullptr)
        {
            QApplication::clipboard()->setText(item->text());
        }
        kLogEvent event;
        dbg << event
            << "[MonitorDock] WMI事件右键操作：复制单元格, row="
            << row
            << ", col="
            << col
            << eol;
        return;
    }

    if (action == copyRowAction)
    {
        QStringList values;
        for (int i = 0; i < m_wmiEventTable->columnCount(); ++i)
        {
            QTableWidgetItem* item = m_wmiEventTable->item(row, i);
            values << (item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(values.join('\t'));
        kLogEvent event;
        dbg << event
            << "[MonitorDock] WMI事件右键操作：复制整行, row="
            << row
            << eol;
        return;
    }

    if (action == gotoProcessAction)
    {
        QTableWidgetItem* pidItem = m_wmiEventTable->item(row, 3);
        if (pidItem == nullptr)
        {
            return;
        }

        std::uint32_t pid = 0;
        if (!parsePid(pidItem->text(), pid))
        {
            kLogEvent event;
            warn << event
                << "[MonitorDock] WMI事件右键操作失败：PID解析失败, text="
                << pidItem->text().toStdString()
                << eol;
            QMessageBox::information(this, QStringLiteral("WMI事件"), QStringLiteral("未解析到有效PID。"));
            return;
        }
        kLogEvent event;
        info << event
            << "[MonitorDock] WMI事件右键操作：转到进程详情, pid="
            << pid
            << eol;
        openProcessDetail(this, pid);
    }
}

void MonitorDock::refreshEtwProvidersAsync()
{
    kLogEvent startEvent;
    info << startEvent
        << "[MonitorDock] 开始异步刷新ETW Provider。"
        << eol;

    m_etwProviderStatusLabel->setText(QStringLiteral("● 刷新中..."));
    m_etwProviderStatusLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));

    if (m_etwCaptureProgressPid == 0)
    {
        m_etwCaptureProgressPid = kPro.addReusable(this, "监控", "刷新ETW Provider");
    }
    kPro.set(m_etwCaptureProgressPid, "调用TdhEnumerateProviders", 0, 10.0f);

    QPointer<MonitorDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<EtwProviderEntry> providers;

        ULONG bufferSize = 0;
        ULONG status = ::TdhEnumerateProviders(nullptr, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER && bufferSize > 0)
        {
            std::vector<unsigned char> buffer(bufferSize, 0);
            auto* info = reinterpret_cast<PROVIDER_ENUMERATION_INFO*>(buffer.data());
            status = ::TdhEnumerateProviders(info, &bufferSize);
            if (status == ERROR_SUCCESS && info != nullptr)
            {
                providers.reserve(info->NumberOfProviders);
                for (ULONG i = 0; i < info->NumberOfProviders; ++i)
                {
                    const TRACE_PROVIDER_INFO& item = info->TraceProviderInfoArray[i];
                    const wchar_t* namePtr = reinterpret_cast<const wchar_t*>(buffer.data() + item.ProviderNameOffset);

                    EtwProviderEntry entry;
                    entry.providerName = namePtr != nullptr ? QString::fromWCharArray(namePtr) : QStringLiteral("<Unknown>");
                    entry.providerGuidText = guidToText(item.ProviderGuid);
                    providers.push_back(entry);
                }
            }
        }

        QMetaObject::invokeMethod(qApp, [guardThis, providers, status]() {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->m_etwProviders = providers;
            guardThis->m_etwProviderList->clear();

            for (const EtwProviderEntry& entry : guardThis->m_etwProviders)
            {
                QListWidgetItem* item = new QListWidgetItem(
                    QStringLiteral("%1 (%2)").arg(entry.providerName, entry.providerGuidText),
                    guardThis->m_etwProviderList);
                item->setData(Qt::UserRole, entry.providerName);
                item->setData(Qt::UserRole + 1, entry.providerGuidText);
                item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
                item->setCheckState(Qt::Unchecked);
            }

            if (status == ERROR_SUCCESS)
            {
                guardThis->m_etwProviderStatusLabel->setText(
                    QStringLiteral("● 已刷新 %1 项").arg(guardThis->m_etwProviders.size()));
                guardThis->m_etwProviderStatusLabel->setStyleSheet(buildStatusStyle(monitorSuccessColorHex()));
                kPro.set(guardThis->m_etwCaptureProgressPid, "ETW Provider完成", 0, 100.0f);

                kLogEvent event;
                info << event
                    << "[MonitorDock] ETW Provider刷新完成, providerCount="
                    << guardThis->m_etwProviders.size()
                    << eol;
            }
            else
            {
                guardThis->m_etwProviderStatusLabel->setText(QStringLiteral("● 刷新失败:%1").arg(status));
                guardThis->m_etwProviderStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
                kPro.set(guardThis->m_etwCaptureProgressPid, "ETW Provider失败", 0, 100.0f);

                kLogEvent event;
                err << event
                    << "[MonitorDock] ETW Provider刷新失败, status="
                    << status
                    << eol;
            }

            guardThis->updateEtwCollapseHeight();
        }, Qt::QueuedConnection);
    }).detach();
}

void MonitorDock::refreshEtwSessionsAsync()
{
    const std::uint64_t requestTicket = m_etwSessionRefreshTicket.fetch_add(
        1,
        std::memory_order_relaxed) + 1;

    if (m_etwSessionStatusLabel != nullptr)
    {
        m_etwSessionStatusLabel->setText(QStringLiteral("● 刷新中..."));
        m_etwSessionStatusLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));
    }
    if (m_etwSessionStopButton != nullptr)
    {
        m_etwSessionStopButton->setEnabled(false);
    }

    if (m_etwSessionRefreshProgressPid == 0)
    {
        m_etwSessionRefreshProgressPid = kPro.addReusable(this, "监控", "刷新ETW会话");
    }
    kPro.set(m_etwSessionRefreshProgressPid, "枚举系统活动 ETW 会话", 0, 10.0f);

    QPointer<MonitorDock> guardThis(this);
    std::thread([guardThis, requestTicket]() {
        std::vector<EtwSessionEntry> sessionList;
        constexpr ULONG querySessionCapacity = 128;
        constexpr ULONG traceNameChars = 1024;
        constexpr ULONG logFileChars = 1024;
        constexpr ULONG propertyBufferSize =
            sizeof(EVENT_TRACE_PROPERTIES)
            + (traceNameChars + logFileChars) * sizeof(wchar_t);

        std::vector<std::vector<unsigned char>> propertyBufferList(
            querySessionCapacity,
            std::vector<unsigned char>(propertyBufferSize, 0));
        std::vector<EVENT_TRACE_PROPERTIES*> propertyPointerList(querySessionCapacity, nullptr);

        for (ULONG indexValue = 0; indexValue < querySessionCapacity; ++indexValue)
        {
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBufferList[indexValue].data());
            properties->Wnode.BufferSize = propertyBufferSize;
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            properties->LogFileNameOffset =
                sizeof(EVENT_TRACE_PROPERTIES) + traceNameChars * sizeof(wchar_t);
            propertyPointerList[indexValue] = properties;
        }

        ULONG sessionCount = querySessionCapacity;
        const ULONG queryStatus = ::QueryAllTracesW(
            propertyPointerList.data(),
            querySessionCapacity,
            &sessionCount);
        if (queryStatus == ERROR_SUCCESS || queryStatus == ERROR_MORE_DATA)
        {
            sessionList.reserve(sessionCount);
            for (ULONG indexValue = 0; indexValue < sessionCount && indexValue < querySessionCapacity; ++indexValue)
            {
                const EVENT_TRACE_PROPERTIES* properties = propertyPointerList[indexValue];
                if (properties == nullptr || properties->LoggerNameOffset == 0)
                {
                    continue;
                }

                const wchar_t* loggerNamePointer = reinterpret_cast<const wchar_t*>(
                    propertyBufferList[indexValue].data() + properties->LoggerNameOffset);
                const QString sessionNameText = QString::fromWCharArray(loggerNamePointer).trimmed();
                if (sessionNameText.isEmpty())
                {
                    continue;
                }

                const wchar_t* logFileNamePointer = properties->LogFileNameOffset == 0
                    ? nullptr
                    : reinterpret_cast<const wchar_t*>(
                        propertyBufferList[indexValue].data() + properties->LogFileNameOffset);
                const QString logFileNameText = logFileNamePointer != nullptr
                    ? QString::fromWCharArray(logFileNamePointer).trimmed()
                    : QString();

                QStringList modeTextList;
                if ((properties->LogFileMode & EVENT_TRACE_REAL_TIME_MODE) != 0)
                {
                    modeTextList << QStringLiteral("实时");
                }
                if ((properties->LogFileMode & EVENT_TRACE_FILE_MODE_SEQUENTIAL) != 0
                    || (properties->LogFileMode & EVENT_TRACE_FILE_MODE_CIRCULAR) != 0
                    || (properties->LogFileMode & EVENT_TRACE_FILE_MODE_APPEND) != 0
                    || !logFileNameText.isEmpty())
                {
                    modeTextList << QStringLiteral("文件");
                }
                if (modeTextList.isEmpty())
                {
                    modeTextList << QStringLiteral("未知");
                }

                EtwSessionEntry entry;
                entry.sessionName = sessionNameText;
                entry.modeText = modeTextList.join(QStringLiteral(" + "));
                entry.bufferText = QStringLiteral("%1KB | %2/%3/%4")
                    .arg(properties->BufferSize)
                    .arg(properties->NumberOfBuffers)
                    .arg(properties->MinimumBuffers)
                    .arg(properties->MaximumBuffers);
                entry.eventsLost = properties->EventsLost;
                entry.logFilePath = logFileNameText;
                sessionList.push_back(std::move(entry));
            }
        }

        QMetaObject::invokeMethod(qApp, [guardThis, requestTicket, sessionList = std::move(sessionList), queryStatus]() {
            if (guardThis == nullptr ||
                guardThis->m_etwSessionRefreshTicket.load(std::memory_order_relaxed) != requestTicket)
            {
                return;
            }

            const auto commitSessions = [guardThis, requestTicket, sessionList, queryStatus]()
            {
                if (guardThis == nullptr ||
                    guardThis->m_etwSessionRefreshTicket.load(std::memory_order_relaxed) != requestTicket)
                {
                    return;
                }

                guardThis->m_etwSessions = sessionList;
                if (guardThis->m_etwSessionTable != nullptr)
                {
                    guardThis->m_etwSessionTable->clearContents();
                    guardThis->m_etwSessionTable->setRowCount(static_cast<int>(guardThis->m_etwSessions.size()));
                    for (int row = 0; row < static_cast<int>(guardThis->m_etwSessions.size()); ++row)
                    {
                        const EtwSessionEntry& entry = guardThis->m_etwSessions[static_cast<std::size_t>(row)];
                        QTableWidgetItem* nameItem = new QTableWidgetItem(entry.sessionName);
                        nameItem->setToolTip(entry.sessionName);
                        guardThis->m_etwSessionTable->setItem(row, 0, nameItem);

                        QTableWidgetItem* modeItem = new QTableWidgetItem(entry.modeText);
                        modeItem->setToolTip(entry.modeText);
                        guardThis->m_etwSessionTable->setItem(row, 1, modeItem);

                        QTableWidgetItem* bufferItem = new QTableWidgetItem(entry.bufferText);
                        bufferItem->setToolTip(entry.bufferText);
                        guardThis->m_etwSessionTable->setItem(row, 2, bufferItem);

                        QTableWidgetItem* lostItem = new QTableWidgetItem(QString::number(entry.eventsLost));
                        lostItem->setToolTip(lostItem->text());
                        guardThis->m_etwSessionTable->setItem(row, 3, lostItem);

                        QTableWidgetItem* logItem = new QTableWidgetItem(entry.logFilePath);
                        logItem->setToolTip(entry.logFilePath);
                        guardThis->m_etwSessionTable->setItem(row, 4, logItem);
                    }
                }

                if (guardThis->m_etwSessionStatusLabel != nullptr)
                {
                    if (queryStatus == ERROR_SUCCESS || queryStatus == ERROR_MORE_DATA)
                    {
                        guardThis->m_etwSessionStatusLabel->setText(
                            QStringLiteral("● 已刷新 %1 项").arg(guardThis->m_etwSessions.size()));
                        guardThis->m_etwSessionStatusLabel->setStyleSheet(buildStatusStyle(monitorSuccessColorHex()));
                        kPro.set(guardThis->m_etwSessionRefreshProgressPid, "ETW会话刷新完成", 0, 100.0f);
                    }
                    else
                    {
                        guardThis->m_etwSessionStatusLabel->setText(
                            QStringLiteral("● 刷新失败:%1").arg(queryStatus));
                        guardThis->m_etwSessionStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
                        kPro.set(guardThis->m_etwSessionRefreshProgressPid, "ETW会话刷新失败", 0, 100.0f);
                    }
                }

                guardThis->updateEtwCollapseHeight();
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("monitor-etw-session-apply"),
                { guardThis->m_etwSessionTable },
                commitSessions))
            {
                return;
            }
            commitSessions();
        }, Qt::QueuedConnection);
    }).detach();
}

void MonitorDock::stopSelectedEtwSessions()
{
    if (m_etwSessionTable == nullptr)
    {
        return;
    }

    std::set<int> selectedRowSet;
    const QList<QTableWidgetItem*> itemList = m_etwSessionTable->selectedItems();
    for (QTableWidgetItem* itemPointer : itemList)
    {
        if (itemPointer != nullptr)
        {
            selectedRowSet.insert(itemPointer->row());
        }
    }

    if (selectedRowSet.empty())
    {
        return;
    }

    QStringList sessionNameList;
    for (const int row : selectedRowSet)
    {
        if (row < 0 || row >= static_cast<int>(m_etwSessions.size()))
        {
            continue;
        }
        const QString sessionNameText = m_etwSessions[static_cast<std::size_t>(row)].sessionName.trimmed();
        if (!sessionNameText.isEmpty())
        {
            sessionNameList << sessionNameText;
        }
    }
    sessionNameList.removeDuplicates();
    if (sessionNameList.isEmpty())
    {
        return;
    }

    if (m_etwSessionStatusLabel != nullptr)
    {
        m_etwSessionStatusLabel->setText(QStringLiteral("● 正在结束会话..."));
        m_etwSessionStatusLabel->setStyleSheet(buildStatusStyle(monitorWarningColorHex()));
    }
    if (m_etwSessionStopButton != nullptr)
    {
        m_etwSessionStopButton->setEnabled(false);
    }

    if (m_etwSessionRefreshProgressPid == 0)
    {
        m_etwSessionRefreshProgressPid = kPro.addReusable(this, "监控", "结束ETW会话");
    }
    kPro.set(m_etwSessionRefreshProgressPid, "停止选中的 ETW 会话", 0, 10.0f);

    QPointer<MonitorDock> guardThis(this);
    std::thread([guardThis, sessionNameList]() {
        int successCount = 0;
        QStringList failureTextList;

        for (const QString& sessionNameText : sessionNameList)
        {
            const std::wstring sessionNameWide = sessionNameText.toStdWString();
            std::vector<unsigned char> propertyBuffer(
                sizeof(EVENT_TRACE_PROPERTIES) + (sessionNameWide.size() + 1) * sizeof(wchar_t),
                0);
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
            properties->Wnode.BufferSize = static_cast<ULONG>(propertyBuffer.size());
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(
                propertyBuffer.data() + properties->LoggerNameOffset);
            ::wcscpy_s(loggerNamePointer, sessionNameWide.size() + 1, sessionNameWide.c_str());

            const ULONG stopStatus = ::ControlTraceW(0, loggerNamePointer, properties, EVENT_TRACE_CONTROL_STOP);
            if (stopStatus == ERROR_SUCCESS)
            {
                ++successCount;
            }
            else
            {
                failureTextList << QStringLiteral("%1(%2)").arg(sessionNameText).arg(stopStatus);
            }
        }

        QMetaObject::invokeMethod(qApp, [guardThis, sessionNameList, successCount, failureTextList]() {
            if (guardThis == nullptr)
            {
                return;
            }

            if (guardThis->m_etwSessionStatusLabel != nullptr)
            {
                if (failureTextList.isEmpty())
                {
                    guardThis->m_etwSessionStatusLabel->setText(
                        QStringLiteral("● 已结束 %1 项").arg(successCount));
                    guardThis->m_etwSessionStatusLabel->setStyleSheet(buildStatusStyle(monitorSuccessColorHex()));
                    kPro.set(guardThis->m_etwSessionRefreshProgressPid, "结束ETW会话完成", 0, 100.0f);
                }
                else
                {
                    guardThis->m_etwSessionStatusLabel->setText(
                        QStringLiteral(
                            "● 已结束 %1 项，%2 项失败；详情已写入日志。")
                            .arg(successCount)
                            .arg(failureTextList.size()));
                    guardThis->m_etwSessionStatusLabel->setStyleSheet(buildStatusStyle(monitorWarningColorHex()));
                    kPro.set(guardThis->m_etwSessionRefreshProgressPid, "结束ETW会话部分失败", 0, 100.0f);
                }
            }

            kLogEvent event;
            (failureTextList.isEmpty() ? info : warn) << event
                << "[MonitorDock] ETW会话停止完成, requestedCount="
                << sessionNameList.size()
                << ", successCount="
                << successCount
                << ", failureCount="
                << failureTextList.size()
                << ", failureDetails="
                << (failureTextList.isEmpty()
                    ? "none"
                    : failureTextList
                        .join(QStringLiteral(" | "))
                        .toStdString())
                << eol;

            guardThis->refreshEtwSessionsAsync();
        }, Qt::QueuedConnection);
    }).detach();
}

bool MonitorDock::beginEtwArchiveBackgroundTask()
{
    std::lock_guard<std::mutex> lock(m_etwArchiveTaskMutex);
    if (m_etwArchiveTaskShutdown)
    {
        return false;
    }
    ++m_etwArchiveBackgroundTaskCount;
    return true;
}

void MonitorDock::endEtwArchiveBackgroundTask()
{
    std::lock_guard<std::mutex> lock(m_etwArchiveTaskMutex);
    if (m_etwArchiveBackgroundTaskCount > 0)
    {
        --m_etwArchiveBackgroundTaskCount;
    }
    if (m_etwArchiveBackgroundTaskCount == 0)
    {
        m_etwArchiveTaskCondition.notify_all();
    }
}

void MonitorDock::cancelAndWaitEtwArchiveBackgroundTasks()
{
    m_etwArchiveFilterTicket.fetch_add(1, std::memory_order_relaxed);
    m_etwArchiveSessionGeneration.fetch_add(1, std::memory_order_relaxed);
    if (m_etwArchiveFilterDebounceTimer != nullptr)
    {
        m_etwArchiveFilterDebounceTimer->stop();
    }

    std::unique_lock<std::mutex> lock(m_etwArchiveTaskMutex);
    m_etwArchiveTaskShutdown = true;
    m_etwArchiveTaskCondition.wait(lock, [this]() {
        return m_etwArchiveBackgroundTaskCount == 0;
    });
}

void MonitorDock::scheduleEtwArchiveFilterRebuild()
{
    QString archiveDirectory;
    {
        std::lock_guard<std::mutex> lock(m_etwArchiveMutex);
        archiveDirectory = m_etwArchiveDirectory;
    }
    if (archiveDirectory.trimmed().isEmpty())
    {
        applyEtwPostFilterToTable();
        return;
    }

    // 立即取消旧扫描，再防抖启动新扫描。连续拖动时间轴时不会叠加磁盘 I/O。
    m_etwArchiveFilterTicket.fetch_add(1, std::memory_order_relaxed);
    if (m_etwArchiveFilterDebounceTimer != nullptr)
    {
        m_etwArchiveFilterDebounceTimer->start();
    }
}

bool MonitorDock::prepareEtwArchiveSession(QString* errorTextOut)
{
    m_etwArchiveFilterTicket.fetch_add(1, std::memory_order_relaxed);
    m_etwArchiveSessionGeneration.fetch_add(1, std::memory_order_relaxed);
    if (m_etwArchiveFilterDebounceTimer != nullptr)
    {
        m_etwArchiveFilterDebounceTimer->stop();
    }
    finishEtwArchiveSession();

    QString baseDirectory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (baseDirectory.trimmed().isEmpty())
    {
        baseDirectory = QCoreApplication::applicationDirPath();
    }

    const QString sessionDirectory = QDir(baseDirectory).filePath(
        QString::fromLatin1("etw_archive/KswordEtw_%1_%2")
            .arg(QDateTime::currentDateTime().toString(QString::fromLatin1("yyyyMMdd_HHmmss_zzz")))
            .arg(QCoreApplication::applicationPid()));
    if (!QDir().mkpath(sessionDirectory))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("无法创建 ETW 全量归档目录：%1").arg(sessionDirectory);
        }
        return false;
    }

    std::lock_guard<std::mutex> lock(m_etwArchiveMutex);
    m_etwArchiveDirectory = QDir::cleanPath(sessionDirectory);
    m_etwArchiveActiveSegmentPath.clear();
    m_etwArchiveClosedSegmentPaths.clear();
    m_etwArchiveWriteBuffer.clear();
    m_etwArchiveWriteBuffer.reserve(kEtwArchiveWriteBufferBytes);
    m_etwArchiveFileHandle = 0;
    m_etwArchiveSegmentStart100ns = 0;
    m_etwArchiveNextSequence = 0;
    m_etwArchiveSegmentIndex = 0;
    m_etwArchiveWriteFailed = false;
    return true;
}

bool MonitorDock::archiveEtwCapturedRow(EtwCapturedEventRow* rowData)
{
    if (rowData == nullptr)
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_etwArchiveMutex);
    if (m_etwArchiveWriteFailed || m_etwArchiveDirectory.trimmed().isEmpty())
    {
        return false;
    }

    rowData->archiveSequence = ++m_etwArchiveNextSequence;
    const QByteArray payload = serializeEtwArchiveRow(*rowData);
    if (payload.isEmpty()
        || payload.size() > static_cast<qsizetype>(kEtwArchiveMaximumRecordBytes))
    {
        m_etwArchiveWriteFailed = true;
        return false;
    }

    const auto closeActiveSegment = [this]() -> bool {
        if (m_etwArchiveFileHandle == 0)
        {
            return true;
        }

        HANDLE fileHandle = reinterpret_cast<HANDLE>(m_etwArchiveFileHandle);
        bool success = writeEtwArchiveBlockToHandle(fileHandle, m_etwArchiveWriteBuffer);
        m_etwArchiveWriteBuffer.clear();
        if (success)
        {
            success = ::FlushFileBuffers(fileHandle) != FALSE;
        }
        ::CloseHandle(fileHandle);
        m_etwArchiveFileHandle = 0;
        m_etwArchiveSegmentStart100ns = 0;
        if (!m_etwArchiveActiveSegmentPath.isEmpty())
        {
            m_etwArchiveClosedSegmentPaths.push_back(m_etwArchiveActiveSegmentPath);
            m_etwArchiveActiveSegmentPath.clear();
        }
        return success;
    };

    constexpr std::uint64_t kSegmentDuration100ns = 10ULL * 1000ULL * 1000ULL * 10ULL;
    const bool needsRotation = m_etwArchiveFileHandle != 0
        && m_etwArchiveSegmentStart100ns != 0
        && rowData->timestampValue >= m_etwArchiveSegmentStart100ns + kSegmentDuration100ns;
    if (needsRotation && !closeActiveSegment())
    {
        m_etwArchiveWriteFailed = true;
        return false;
    }

    if (m_etwArchiveFileHandle == 0)
    {
        const QString segmentPath = QDir(m_etwArchiveDirectory).filePath(
            QString::fromLatin1("segment_%1.ketw")
                .arg(m_etwArchiveSegmentIndex++, 6, 10, QChar(u'0')));
        HANDLE fileHandle = ::CreateFileW(
            reinterpret_cast<LPCWSTR>(segmentPath.utf16()),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            m_etwArchiveWriteFailed = true;
            return false;
        }

        const QByteArray fileHeader = buildEtwArchiveFileHeader();
        if (!writeAllToHandle(fileHandle, fileHeader))
        {
            ::CloseHandle(fileHandle);
            m_etwArchiveWriteFailed = true;
            return false;
        }

        m_etwArchiveFileHandle = reinterpret_cast<std::uintptr_t>(fileHandle);
        m_etwArchiveActiveSegmentPath = QDir::cleanPath(segmentPath);
        m_etwArchiveSegmentStart100ns = rowData->timestampValue;
    }

    const quint32 payloadSizeLittleEndian = qToLittleEndian(static_cast<quint32>(payload.size()));
    m_etwArchiveWriteBuffer.append(
        reinterpret_cast<const char*>(&payloadSizeLittleEndian),
        static_cast<qsizetype>(sizeof(payloadSizeLittleEndian)));
    m_etwArchiveWriteBuffer.append(payload);
    if (m_etwArchiveWriteBuffer.size() >= kEtwArchiveWriteBufferBytes)
    {
        HANDLE fileHandle = reinterpret_cast<HANDLE>(m_etwArchiveFileHandle);
        if (!writeEtwArchiveBlockToHandle(fileHandle, m_etwArchiveWriteBuffer))
        {
            m_etwArchiveWriteFailed = true;
            return false;
        }
        m_etwArchiveWriteBuffer.clear();
    }
    return true;
}

void MonitorDock::finishEtwArchiveSession(const bool flushToPhysicalDisk)
{
    HANDLE fileHandle = nullptr;
    bool success = true;
    {
        std::lock_guard<std::mutex> lock(m_etwArchiveMutex);
        if (m_etwArchiveFileHandle == 0)
        {
            return;
        }

        fileHandle = reinterpret_cast<HANDLE>(m_etwArchiveFileHandle);
        const bool alreadyFailed = m_etwArchiveWriteFailed.load(std::memory_order_relaxed);
        success = !alreadyFailed
            && writeEtwArchiveBlockToHandle(fileHandle, m_etwArchiveWriteBuffer);
        m_etwArchiveWriteBuffer.clear();
        m_etwArchiveFileHandle = 0;
        m_etwArchiveSegmentStart100ns = 0;
        if (!m_etwArchiveActiveSegmentPath.isEmpty())
        {
            m_etwArchiveClosedSegmentPaths.push_back(m_etwArchiveActiveSegmentPath);
            m_etwArchiveActiveSegmentPath.clear();
        }
    }

    if (success && flushToPhysicalDisk)
    {
        success = ::FlushFileBuffers(fileHandle) != FALSE;
    }
    ::CloseHandle(fileHandle);
    if (!success)
    {
        m_etwArchiveWriteFailed.store(true, std::memory_order_relaxed);
    }
}

void MonitorDock::rebuildEtwArchiveFilterAsync()
{
    QString archiveDirectory;
    {
        std::lock_guard<std::mutex> lock(m_etwArchiveMutex);
        archiveDirectory = m_etwArchiveDirectory;
    }
    if (archiveDirectory.trimmed().isEmpty() || !beginEtwArchiveBackgroundTask())
    {
        return;
    }

    const std::uint64_t ticket = m_etwArchiveFilterTicket.fetch_add(
        1,
        std::memory_order_relaxed) + 1;
    const std::uint64_t sessionGeneration = m_etwArchiveSessionGeneration.load(
        std::memory_order_relaxed);
    const EtwSimpleFilterCompiled postSimpleFilter = m_etwPostSimpleFilterCompiled;
    const std::vector<EtwFilterRuleGroupCompiled> postFilterGroups = m_etwPostFilterCompiledGroupList;
    const bool timelineFilterActive = isEtwTimelineFilterActive();
    const std::uint64_t captureStart100ns = m_etwCaptureStartTime100ns;
    const std::uint64_t selectionStart100ns = m_etwTimelineSelectionStart100ns;
    const std::uint64_t selectionEnd100ns = m_etwTimelineSelectionEnd100ns;
    const std::vector<std::pair<std::uint64_t, std::uint64_t>> pauseIntervals =
        m_etwTimelinePauseIntervals;
    const bool capturePaused = m_etwCapturePaused.load();
    const std::uint64_t activePauseStart100ns = m_etwTimelinePauseTime100ns;

    MonitorDock* taskOwner = this;
    const auto taskCompletion = std::shared_ptr<void>(
        reinterpret_cast<void*>(1),
        [taskOwner](void*) {
            taskOwner->endEtwArchiveBackgroundTask();
        });
    QPointer<MonitorDock> guardThis(this);
    std::thread([
        taskOwner,
        taskCompletion,
        guardThis,
        ticket,
        sessionGeneration,
        postSimpleFilter,
        postFilterGroups,
        timelineFilterActive,
        captureStart100ns,
        selectionStart100ns,
        selectionEnd100ns,
        pauseIntervals,
        capturePaused,
        activePauseStart100ns]() mutable {
        const auto shouldCancel = [taskOwner, ticket, sessionGeneration]() {
            return taskOwner->m_etwArchiveFilterTicket.load(std::memory_order_relaxed) != ticket
                || taskOwner->m_etwArchiveSessionGeneration.load(std::memory_order_relaxed) != sessionGeneration;
        };
        if (shouldCancel())
        {
            return;
        }

        // 封存当前不足 10 秒的活动分段，使本次筛选拥有明确且完整的磁盘快照。
        taskOwner->finishEtwArchiveSession();
        if (shouldCancel())
        {
            return;
        }

        QStringList segmentPaths;
        {
            std::lock_guard<std::mutex> lock(taskOwner->m_etwArchiveMutex);
            segmentPaths = taskOwner->m_etwArchiveClosedSegmentPaths;
        }
        const auto rawToTimelineTimestamp = [
            captureStart100ns,
            pauseIntervals,
            capturePaused,
            activePauseStart100ns](const std::uint64_t rawTimestamp100ns) {
            if (captureStart100ns == 0 || rawTimestamp100ns <= captureStart100ns)
            {
                return captureStart100ns;
            }

            std::uint64_t pausedDuration100ns = 0;
            for (const auto& pauseInterval : pauseIntervals)
            {
                if (pauseInterval.second <= pauseInterval.first
                    || rawTimestamp100ns <= pauseInterval.first)
                {
                    continue;
                }
                pausedDuration100ns += std::min(rawTimestamp100ns, pauseInterval.second)
                    - pauseInterval.first;
            }
            if (capturePaused
                && activePauseStart100ns != 0
                && rawTimestamp100ns > activePauseStart100ns)
            {
                pausedDuration100ns += rawTimestamp100ns - activePauseStart100ns;
            }

            const std::uint64_t elapsed100ns = rawTimestamp100ns - captureStart100ns;
            return captureStart100ns
                + (elapsed100ns > pausedDuration100ns
                    ? elapsed100ns - pausedDuration100ns
                    : 0);
        };

        std::deque<EtwCapturedEventRow> matchingRows;
        std::uint64_t totalMatchCount = 0;
        std::uint64_t scannedRowCount = 0;
        std::uint64_t scannedMaxSequence = 0;
        QString scanErrorText;
        constexpr std::size_t kMaximumVisibleRows = 6000;

        const auto rowVisitor = [&](const EtwCapturedEventRow& row) {
            bool matches = etwFilterStageMatches(postSimpleFilter, postFilterGroups, row);
            if (matches && timelineFilterActive)
            {
                const std::uint64_t timelineTimestamp100ns = rawToTimelineTimestamp(row.timestampValue);
                matches = timelineTimestamp100ns >= selectionStart100ns
                    && timelineTimestamp100ns <= selectionEnd100ns;
            }
            if (!matches)
            {
                return true;
            }

            ++totalMatchCount;
            matchingRows.push_back(row);
            if (matchingRows.size() > kMaximumVisibleRows)
            {
                matchingRows.pop_front();
            }
            return true;
        };

        std::size_t scannedSegmentCount = 0;
        const auto scanNewSegments = [&]() -> bool {
            while (scannedSegmentCount < static_cast<std::size_t>(segmentPaths.size()))
            {
                if (shouldCancel())
                {
                    return false;
                }
                const QString segmentPath = segmentPaths.at(static_cast<qsizetype>(scannedSegmentCount));
                ++scannedSegmentCount;
                if (!scanEtwArchiveFile(
                    segmentPath,
                    rowVisitor,
                    shouldCancel,
                    &scannedRowCount,
                    &scannedMaxSequence,
                    &scanErrorText))
                {
                    return false;
                }
            }
            return true;
        };

        if (!scanNewSegments() && scanErrorText.isEmpty())
        {
            return;
        }

        // 初次全量扫描可能持续较久。最多再追三轮仅包含新增事件的分段，
        // 让最终 UI 窗口尽量贴近扫描完成时刻，同时避免持续监听导致扫描永不结束。
        for (int catchUpPass = 0;
             catchUpPass < 3 && scanErrorText.isEmpty() && taskOwner->m_etwCaptureRunning.load();
             ++catchUpPass)
        {
            taskOwner->finishEtwArchiveSession();
            if (shouldCancel())
            {
                return;
            }

            QStringList latestSegmentPaths;
            {
                std::lock_guard<std::mutex> lock(taskOwner->m_etwArchiveMutex);
                latestSegmentPaths = taskOwner->m_etwArchiveClosedSegmentPaths;
            }
            if (latestSegmentPaths.size() <= static_cast<qsizetype>(scannedSegmentCount))
            {
                break;
            }
            segmentPaths = std::move(latestSegmentPaths);
            if (!scanNewSegments() && scanErrorText.isEmpty())
            {
                return;
            }
        }

        if (shouldCancel())
        {
            return;
        }

        QMetaObject::invokeMethod(qApp, [
            guardThis,
            ticket,
            sessionGeneration,
            rows = std::move(matchingRows),
            totalMatchCount,
            scannedRowCount,
            scannedMaxSequence,
            scanErrorText]() mutable {
            if (guardThis == nullptr
                || guardThis->m_etwArchiveFilterTicket.load(std::memory_order_relaxed) != ticket
                || guardThis->m_etwArchiveSessionGeneration.load(std::memory_order_relaxed) != sessionGeneration)
            {
                return;
            }
            if (!scanErrorText.isEmpty())
            {
                if (guardThis->m_etwPostSimpleFilterUi.stateLabel != nullptr)
                {
                    guardThis->m_etwPostSimpleFilterUi.stateLabel->setText(scanErrorText);
                    guardThis->m_etwPostSimpleFilterUi.stateLabel->setStyleSheet(
                        buildStatusStyle(monitorErrorColorHex()));
                }
                return;
            }
            guardThis->replaceEtwRowsWithSnapshot(
                std::move(rows),
                totalMatchCount,
                scannedRowCount,
                scannedMaxSequence);
        }, Qt::QueuedConnection);
    }).detach();
}

void MonitorDock::replaceEtwRowsWithSnapshot(
    std::deque<EtwCapturedEventRow> rows,
    const std::uint64_t totalMatchCount,
    const std::uint64_t scannedRowCount,
    const std::uint64_t scannedMaxSequence)
{
    if (m_etwEventTable == nullptr)
    {
        return;
    }

    // 后台归档扫描会整表替换。使用共享快照避免“未延后”路径额外复制数千行，
    // 并确保菜单打开时连 pending 队列裁剪也不会提前发生。
    const QPointer<MonitorDock> guardThis(this);
    const std::uint64_t filterTicketSnapshot =
        m_etwArchiveFilterTicket.load(std::memory_order_relaxed);
    const std::uint64_t sessionGenerationSnapshot =
        m_etwArchiveSessionGeneration.load(std::memory_order_relaxed);
    const auto deferredRows =
        std::make_shared<std::deque<EtwCapturedEventRow>>(std::move(rows));
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("monitor-etw-snapshot-replace"),
        { m_etwEventTable },
        [
            guardThis,
            deferredRows,
            totalMatchCount,
            scannedRowCount,
            scannedMaxSequence,
            filterTicketSnapshot,
            sessionGenerationSnapshot]() mutable
        {
            if (!guardThis.isNull()
                && guardThis->m_etwArchiveFilterTicket.load(std::memory_order_relaxed)
                    == filterTicketSnapshot
                && guardThis->m_etwArchiveSessionGeneration.load(std::memory_order_relaxed)
                    == sessionGenerationSnapshot)
            {
                guardThis->replaceEtwRowsWithSnapshot(
                    std::move(*deferredRows),
                    totalMatchCount,
                    scannedRowCount,
                    scannedMaxSequence);
            }
        }))
    {
        return;
    }
    rows = std::move(*deferredRows);

    constexpr std::size_t kMaximumVisibleRows = 6000;
    for (const EtwCapturedEventRow& liveRow : m_etwCapturedRows)
    {
        if (liveRow.archiveSequence <= scannedMaxSequence)
        {
            continue;
        }

        bool matches = etwFilterStageMatches(
            m_etwPostSimpleFilterCompiled,
            m_etwPostFilterCompiledGroupList,
            liveRow);
        if (matches && isEtwTimelineFilterActive())
        {
            const std::uint64_t timestamp100ns = etwRawTimestampToTimelineTimestamp(liveRow.timestampValue);
            matches = timestamp100ns >= m_etwTimelineSelectionStart100ns
                && timestamp100ns <= m_etwTimelineSelectionEnd100ns;
        }
        if (matches)
        {
            rows.push_back(liveRow);
            if (rows.size() > kMaximumVisibleRows)
            {
                rows.pop_front();
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(m_etwPendingMutex);
        while (!m_etwPendingRows.empty()
            && m_etwPendingRows.front().archiveSequence <= scannedMaxSequence)
        {
            m_etwPendingRows.pop_front();
        }
    }

    const bool hasPostRules = m_etwPostSimpleFilterCompiled.hasAnyCondition()
        || !m_etwPostFilterCompiledGroupList.empty();
    const bool timelineFilterActive = isEtwTimelineFilterActive();
    if (hasPostRules || timelineFilterActive)
    {
        rows.erase(
            std::remove_if(
                rows.begin(),
                rows.end(),
                [this, timelineFilterActive](const EtwCapturedEventRow& rowData) {
                    bool matches = etwFilterStageMatches(
                        m_etwPostSimpleFilterCompiled,
                        m_etwPostFilterCompiledGroupList,
                        rowData);
                    if (matches && timelineFilterActive)
                    {
                        const std::uint64_t timestamp100ns = etwRawTimestampToTimelineTimestamp(
                            rowData.timestampValue);
                        matches = timestamp100ns >= m_etwTimelineSelectionStart100ns
                            && timestamp100ns <= m_etwTimelineSelectionEnd100ns;
                    }
                    return !matches;
                }),
            rows.end());
    }

    m_etwEventTable->setUpdatesEnabled(false);
    m_etwEventTable->clearContents();
    m_etwEventTable->setRowCount(static_cast<int>(rows.size()));
    m_etwCapturedRows.clear();
    m_etwTimelineEventPoints.clear();

    int tableRow = 0;
    for (EtwCapturedEventRow& rowData : rows)
    {
        m_etwCapturedRows.push_back(std::move(rowData));
        const EtwCapturedEventRow& captured = m_etwCapturedRows.back();
        QTableWidgetItem* sequenceItem = new QTableWidgetItem(QString::number(
            static_cast<qulonglong>(captured.archiveSequence != 0
                ? captured.archiveSequence
                : static_cast<std::uint64_t>(tableRow + 1))));
        sequenceItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        m_etwEventTable->setVerticalHeaderItem(tableRow, sequenceItem);
        const QStringList rowTextList{
            captured.timestampText,
            captured.providerName,
            QString::number(captured.eventId),
            captured.eventName,
            captured.pidTidText,
            captured.detailSummary,
            captured.activityId
        };
        for (int column = 0; column < rowTextList.size(); ++column)
        {
            QTableWidgetItem* item = new QTableWidgetItem(rowTextList.at(column));
            item->setToolTip(rowTextList.at(column));
            if (column == 5)
            {
                item->setData(Qt::UserRole, captured.detailJson);
            }
            m_etwEventTable->setItem(tableRow, column, item);
        }

        ProcessTraceTimelineEventPoint timelinePoint;
        timelinePoint.time100ns = etwRawTimestampToTimelineTimestamp(captured.timestampValue);
        timelinePoint.typeText = etwTimelineTypeFromCapturedRow(captured);
        m_etwTimelineEventPoints.push_back(std::move(timelinePoint));
        ++tableRow;
    }

    refreshEtwTimelineRange(!m_etwCaptureRunning.load());
    refreshEtwTimelinePoints();
    m_etwEventTable->setUpdatesEnabled(true);
    m_etwEventTable->scrollToBottom();
    m_etwEventTable->viewport()->update();

    if (m_etwPostSimpleFilterUi.stateLabel != nullptr)
    {
        m_etwPostSimpleFilterUi.stateLabel->setText(
            QStringLiteral("全量匹配: %1 | 当前显示最近: %2 | 已扫描: %3 | UI镜像跳过: %4（已归档）")
                .arg(static_cast<qulonglong>(totalMatchCount))
                .arg(m_etwEventTable->rowCount())
                .arg(static_cast<qulonglong>(scannedRowCount))
                .arg(static_cast<qulonglong>(m_etwUiSkippedRows.load(std::memory_order_relaxed))));
        m_etwPostSimpleFilterUi.stateLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));
    }
}

void WINAPI MonitorDock::etwEventRecordCallback(struct _EVENT_RECORD* eventRecordPtr)
{
    if (eventRecordPtr == nullptr)
    {
        return;
    }

    EVENT_RECORD* eventRecord = reinterpret_cast<EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr || eventRecord->UserContext == nullptr)
    {
        return;
    }

    auto* monitorDock = reinterpret_cast<MonitorDock*>(eventRecord->UserContext);
    monitorDock->enqueueEtwEventFromRecord(eventRecordPtr);
}

void MonitorDock::enqueueEtwEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr)
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr)
    {
        return;
    }

    if (m_etwCaptureStopFlag.load() || m_etwCapturePaused.load())
    {
        return;
    }

    const QString providerGuidText = guidToText(eventRecord->EventHeader.ProviderId);
    QString providerNameText = providerGuidText;
    const auto providerNameIt = m_etwCaptureProviderNames.constFind(providerGuidText);
    if (providerNameIt != m_etwCaptureProviderNames.cend())
    {
        providerNameText = providerNameIt.value();
    }

    EtwCapturedEventRow rowData;
    rowData.timestampText = etwTimestamp100nsText(eventRecord);
    rowData.timestampValue = static_cast<std::uint64_t>(eventRecord->EventHeader.TimeStamp.QuadPart);
    rowData.providerName = providerNameText;
    rowData.providerGuid = providerGuidText;
    rowData.providerCategory = etwInferProviderCategory(providerNameText);
    rowData.eventId = static_cast<int>(eventRecord->EventHeader.EventDescriptor.Id);
    rowData.eventName = QStringLiteral("Event_%1").arg(rowData.eventId);
    rowData.task = static_cast<int>(eventRecord->EventHeader.EventDescriptor.Task);
    rowData.opcode = static_cast<int>(eventRecord->EventHeader.EventDescriptor.Opcode);
    rowData.level = static_cast<int>(eventRecord->EventHeader.EventDescriptor.Level);
    rowData.levelText = etwFilterLevelTextFromValue(rowData.level);
    rowData.keywordMaskValue = static_cast<std::uint64_t>(eventRecord->EventHeader.EventDescriptor.Keyword);
    rowData.keywordMaskText = QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(rowData.keywordMaskValue), 16, 16, QChar(u'0'))
        .toUpper();
    rowData.headerPid = static_cast<std::uint32_t>(eventRecord->EventHeader.ProcessId);
    rowData.headerTid = static_cast<std::uint32_t>(eventRecord->EventHeader.ThreadId);
    rowData.activityId = guidToText(eventRecord->EventHeader.ActivityId);
    rowData.pidTidText = QStringLiteral("%1 / %2").arg(rowData.headerPid).arg(rowData.headerTid);

    EtwSchemaEntry schemaEntry;
    const bool schemaReady = tryGetEtwSchemaCached(eventRecord, &schemaEntry);
    if (schemaReady)
    {
        rowData.taskName = schemaEntry.taskNameText.trimmed();
        rowData.opcodeName = schemaEntry.opcodeNameText.trimmed();
        if (!schemaEntry.eventNameText.trimmed().isEmpty())
        {
            rowData.eventName = schemaEntry.eventNameText.trimmed();
        }
        else if (!schemaEntry.taskNameText.trimmed().isEmpty())
        {
            rowData.eventName = schemaEntry.taskNameText.trimmed();
        }
        else if (!schemaEntry.opcodeNameText.trimmed().isEmpty())
        {
            rowData.eventName = schemaEntry.opcodeNameText.trimmed();
        }
    }

    std::vector<EtwDecodedPropertyEntry> decodedPropertyList;
    QString unparsedTailHexText;
    ULONG parsedBytes = 0;
    bool decodeAttempted = false;
    auto ensureDecodedPayload = [&]() -> bool {
        if (rowData.decodedReady)
        {
            return true;
        }
        if (decodeAttempted && !rowData.decodedReady)
        {
            return false;
        }
        decodeAttempted = true;

        if (schemaReady)
        {
            decodeEtwPropertiesBySchema(
                eventRecord,
                schemaEntry,
                &decodedPropertyList,
                &parsedBytes,
                &unparsedTailHexText);

            const EtwSemanticSummary semanticSummary = inferEtwSemanticSummary(
                providerNameText,
                rowData.eventName,
                rowData.opcodeName,
                decodedPropertyList);
            rowData.detailJson = buildEtwDetailJson(
                eventRecord,
                providerGuidText,
                providerNameText,
                schemaEntry,
                semanticSummary,
                decodedPropertyList,
                parsedBytes,
                unparsedTailHexText);
            rowData.detailSummary = buildEtwSummaryText(
                providerNameText,
                rowData.eventName,
                rowData.opcodeName,
                rowData.headerPid,
                rowData.headerTid,
                semanticSummary,
                decodedPropertyList);
            fillEtwCapturedRowDecodedFields(
                &rowData,
                providerNameText,
                rowData.eventName,
                semanticSummary,
                decodedPropertyList);
        }
        else
        {
            if (eventRecord->UserData != nullptr && eventRecord->UserDataLength > 0)
            {
                const unsigned char* rawUserDataPointer = reinterpret_cast<const unsigned char*>(eventRecord->UserData);
                parsedBytes = 0;
                unparsedTailHexText = etwHexDump(rawUserDataPointer, eventRecord->UserDataLength);
            }

            QJsonObject fallbackMeta;
            fallbackMeta.insert(QStringLiteral("providerGuid"), providerGuidText);
            fallbackMeta.insert(QStringLiteral("providerName"), providerNameText);
            fallbackMeta.insert(QStringLiteral("eventId"), rowData.eventId);
            fallbackMeta.insert(QStringLiteral("eventName"), rowData.eventName);
            fallbackMeta.insert(QStringLiteral("task"), rowData.task);
            fallbackMeta.insert(QStringLiteral("opcode"), rowData.opcode);
            fallbackMeta.insert(QStringLiteral("level"), rowData.level);
            fallbackMeta.insert(QStringLiteral("keyword"), rowData.keywordMaskText);
            fallbackMeta.insert(QStringLiteral("note"), QStringLiteral("未获取到TDH schema，已保留原始十六进制数据"));
            fallbackMeta.insert(QStringLiteral("userDataLength"), static_cast<int>(eventRecord->UserDataLength));

            QJsonObject fallbackSemantic;
            fallbackSemantic.insert(QStringLiteral("resourceType"), inferEtwResourceType(providerNameText, rowData.eventName));
            fallbackSemantic.insert(QStringLiteral("action"), inferEtwActionText(rowData.eventName, rowData.opcodeName));
            fallbackSemantic.insert(QStringLiteral("target"), QString());
            fallbackSemantic.insert(QStringLiteral("status"), QString());

            QJsonObject fallbackRoot;
            fallbackRoot.insert(QStringLiteral("meta"), fallbackMeta);
            fallbackRoot.insert(QStringLiteral("semantic"), fallbackSemantic);
            if (!unparsedTailHexText.trimmed().isEmpty())
            {
                fallbackRoot.insert(QStringLiteral("rawFallback"), unparsedTailHexText);
            }
            rowData.detailJson = QString::fromUtf8(QJsonDocument(fallbackRoot).toJson(QJsonDocument::Compact));
            rowData.resourceTypeText = fallbackSemantic.value(QStringLiteral("resourceType")).toString();
            rowData.actionText = fallbackSemantic.value(QStringLiteral("action")).toString();
            rowData.targetText.clear();
            rowData.statusText.clear();
            rowData.detailSummary = QStringLiteral("%1 | PID=%2 TID=%3 | 原始数据=%4字节")
                .arg(etwToSingleLine(rowData.eventName).isEmpty() ? QStringLiteral("事件") : etwToSingleLine(rowData.eventName))
                .arg(rowData.headerPid)
                .arg(rowData.headerTid)
                .arg(static_cast<int>(eventRecord->UserDataLength));
            rowData.decodedReady = true;
        }

        if (rowData.detailSummary.trimmed().isEmpty())
        {
            rowData.detailSummary = QStringLiteral("%1 | PID=%2 TID=%3")
                .arg(etwToSingleLine(rowData.eventName).isEmpty() ? QStringLiteral("事件") : etwToSingleLine(rowData.eventName))
                .arg(rowData.headerPid)
                .arg(rowData.headerTid);
        }

        rowData.detailVisibleText = QStringLiteral("%1 %2 %3 %4 %5 %6 %7")
            .arg(rowData.timestampText)
            .arg(rowData.providerName)
            .arg(rowData.eventId)
            .arg(rowData.eventName)
            .arg(rowData.pidTidText)
            .arg(rowData.detailSummary)
            .arg(rowData.activityId);

        rowData.detailAllText = QStringLiteral("%1 %2 %3 %4 %5 %6 %7 %8 %9 %10")
            .arg(rowData.detailVisibleText)
            .arg(rowData.resourceTypeText)
            .arg(rowData.actionText)
            .arg(rowData.targetText)
            .arg(rowData.statusText)
            .arg(rowData.processNameText)
            .arg(rowData.filePathText)
            .arg(rowData.registryKeyPathText)
            .arg(rowData.scriptKeywordText)
            .arg(rowData.detailJson);
        rowData.detailAllText = etwSingleLineOrEmpty(rowData.detailAllText);

        rowData.decodedReady = true;
        return true;
    };

    std::shared_ptr<const EtwFilterStageCompiledSnapshot> preFilterSnapshot;
    {
        std::lock_guard<std::mutex> lock(m_etwPreFilterSnapshotMutex);
        preFilterSnapshot = m_etwPreFilterCompiledSnapshot;
    }

    bool preMatched = true;
    if (preFilterSnapshot != nullptr)
    {
        bool simpleRequiresDecodedPayload = false;
        preMatched = etwSimpleFilterMatchesHeaderFields(
            preFilterSnapshot->simpleFilter,
            rowData,
            &simpleRequiresDecodedPayload);
        if (preMatched && simpleRequiresDecodedPayload && !rowData.decodedReady)
        {
            ensureDecodedPayload();
        }
        if (preMatched)
        {
            preMatched = etwSimpleFilterMatches(preFilterSnapshot->simpleFilter, rowData);
        }

        if (preMatched && !preFilterSnapshot->detailedGroupList.empty())
        {
            preMatched = false;
            for (const EtwFilterRuleGroupCompiled& groupRule : preFilterSnapshot->detailedGroupList)
            {
                bool groupMatched = true;
                for (const EtwFilterRuleFieldCompiled& fieldRule : groupRule.fieldList)
                {
                    if (fieldRule.requiresDecodedPayload && !rowData.decodedReady)
                    {
                        ensureDecodedPayload();
                    }
                    if (!etwFilterFieldMatches(
                        fieldRule,
                        rowData,
                        groupRule.detailVisibleColumnsOnly,
                        groupRule.detailMatchAllFields))
                    {
                        groupMatched = false;
                        break;
                    }
                }
                if (groupRule.invertMatch)
                {
                    groupMatched = !groupMatched;
                }
                if (groupMatched)
                {
                    preMatched = true;
                    break;
                }
            }
        }
    }

    if (!preMatched)
    {
        return;
    }

    ensureDecodedPayload();

    // 全量归档先于 UI 镜像入队。后续即使 UI 追不上事件洪峰，磁盘记录仍完整。
    if (!archiveEtwCapturedRow(&rowData))
    {
        m_etwCaptureStopFlag.store(true);
        QPointer<MonitorDock> guardThis(this);
        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }
            if (guardThis->m_etwCaptureStatusLabel != nullptr)
            {
                guardThis->m_etwCaptureStatusLabel->setText(
                    QStringLiteral("● 处理结束:%1").arg(ERROR_WRITE_FAULT));
                guardThis->m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
            }
            guardThis->stopEtwCaptureInternal(false);
        }, Qt::QueuedConnection);
        return;
    }

    constexpr std::size_t kMaxEtwUiPendingRows = 2048;
    {
        std::unique_lock<std::mutex> lock(m_etwPendingMutex, std::try_to_lock);
        if (!lock.owns_lock())
        {
            m_etwUiSkippedRows.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (m_etwPendingRows.size() >= kMaxEtwUiPendingRows)
        {
            m_etwPendingRows.pop_front();
            m_etwUiSkippedRows.fetch_add(1, std::memory_order_relaxed);
        }
        m_etwPendingRows.push_back(std::move(rowData));
    }
}

void MonitorDock::startEtwCapture()
{
    if (m_etwCaptureRunning.load())
    {
        if (m_etwCapturePaused.load())
        {
            setEtwCapturePaused(false);
        }
        else
        {
            kLogEvent event;
            dbg << event
                << "[MonitorDock] 忽略启动ETW：当前已在监听。"
                << eol;
        }
        return;
    }

    if (m_etwCaptureThread != nullptr && m_etwCaptureThread->joinable())
    {
        m_etwCaptureThread->join();
        m_etwCaptureThread.reset();
    }

    EtwSimpleFilterCompiled preSimpleCheck;
    EtwSimpleFilterCompiled postSimpleCheck;
    std::vector<EtwFilterRuleGroupCompiled> preCheckGroupList;
    std::vector<EtwFilterRuleGroupCompiled> postCheckGroupList;
    QString filterCompileError;
    if (!tryCompileEtwSimpleFilter(EtwFilterStage::Pre, preSimpleCheck, filterCompileError)
        || !tryCompileEtwFilterGroups(EtwFilterStage::Pre, preCheckGroupList, filterCompileError))
    {
        QMessageBox::warning(this, QStringLiteral("ETW前置筛选"), filterCompileError);
        return;
    }
    if (!tryCompileEtwSimpleFilter(EtwFilterStage::Post, postSimpleCheck, filterCompileError)
        || !tryCompileEtwFilterGroups(EtwFilterStage::Post, postCheckGroupList, filterCompileError))
    {
        QMessageBox::warning(this, QStringLiteral("ETW后置筛选"), filterCompileError);
        return;
    }

    applyEtwFilterRules(EtwFilterStage::Pre);
    applyEtwFilterRules(EtwFilterStage::Post);

    // 收集勾选的 Provider，并解析 GUID。
    struct ProviderSelection
    {
        QString name; // Provider 名称，用于日志/显示。
        GUID guid{};  // Provider GUID，用于 EnableTraceEx2。
    };

    std::vector<ProviderSelection> selectedProviders;
    selectedProviders.reserve(static_cast<std::size_t>(
        m_etwProviderList->count()
        + (m_etwPresetProviderList != nullptr ? m_etwPresetProviderList->count() : 0)
        + 1));

    auto tryAppendProvider = [&selectedProviders](const QString& providerName, const QString& guidText) {
        GUID guidValue{};
        if (!parseGuidText(guidText, guidValue))
        {
            return false;
        }

        const bool duplicate = std::any_of(
            selectedProviders.begin(),
            selectedProviders.end(),
            [&guidValue](const ProviderSelection& item) {
                return ::IsEqualGUID(item.guid, guidValue) != FALSE;
            });
        if (duplicate)
        {
            return true;
        }

        ProviderSelection selection;
        selection.name = providerName;
        selection.guid = guidValue;
        selectedProviders.push_back(selection);
        return true;
    };

    for (int i = 0; i < m_etwProviderList->count(); ++i)
    {
        QListWidgetItem* item = m_etwProviderList->item(i);
        if (item == nullptr || item->checkState() != Qt::Checked)
        {
            continue;
        }
        const QString providerName = item->data(Qt::UserRole).toString();
        const QString providerGuid = item->data(Qt::UserRole + 1).toString();
        tryAppendProvider(providerName, providerGuid);
    }

    // 预置模板勾选项：普通 Provider 按名称映射 GUID；线程/镜像使用经典内核标志。
    int presetCheckedCount = 0;
    int presetMatchedCount = 0;
    ULONG legacyKernelEnableFlags = 0;
    if (m_etwPresetProviderList != nullptr)
    {
        for (int i = 0; i < m_etwPresetProviderList->count(); ++i)
        {
            QListWidgetItem* item = m_etwPresetProviderList->item(i);
            if (item == nullptr || item->checkState() != Qt::Checked)
            {
                continue;
            }
            ++presetCheckedCount;

            const QString presetProviderName = item->data(Qt::UserRole).toString().trimmed();
            if (presetProviderName.isEmpty())
            {
                continue;
            }

            const EtwPresetProviderDescriptor* presetDescriptor =
                findEtwPresetProviderDescriptor(presetProviderName);
            if (presetDescriptor != nullptr && presetDescriptor->legacyKernelEnableFlags != 0)
            {
                legacyKernelEnableFlags |= presetDescriptor->legacyKernelEnableFlags;
                ++presetMatchedCount;
                continue;
            }

            const auto exactFound = std::find_if(
                m_etwProviders.begin(),
                m_etwProviders.end(),
                [presetProviderName](const EtwProviderEntry& entry) {
                    return entry.providerName.compare(presetProviderName, Qt::CaseInsensitive) == 0;
                });

            bool matched = false;
            if (exactFound != m_etwProviders.end())
            {
                matched = tryAppendProvider(exactFound->providerName, exactFound->providerGuidText);
            }
            else
            {
                // 模糊回退：允许模板名与系统 Provider 名称存在后缀差异。
                const auto fuzzyFound = std::find_if(
                    m_etwProviders.begin(),
                    m_etwProviders.end(),
                    [presetProviderName](const EtwProviderEntry& entry) {
                        return entry.providerName.contains(presetProviderName, Qt::CaseInsensitive)
                            || presetProviderName.contains(entry.providerName, Qt::CaseInsensitive);
                    });
                if (fuzzyFound != m_etwProviders.end())
                {
                    matched = tryAppendProvider(fuzzyFound->providerName, fuzzyFound->providerGuidText);
                }
            }

            if (matched)
            {
                ++presetMatchedCount;
            }
            else
            {
                kLogEvent event;
                warn << event
                    << "[MonitorDock] ETW预置模板未命中系统Provider, template="
                    << presetProviderName.toStdString()
                    << eol;
            }
        }
    }

    // 手动输入既支持 GUID，也支持 Provider 名称。
    const QString manualText = m_etwManualProviderEdit->text().trimmed();
    if (!manualText.isEmpty())
    {
        if (!tryAppendProvider(manualText, manualText))
        {
            const auto found = std::find_if(
                m_etwProviders.begin(),
                m_etwProviders.end(),
                [manualText](const EtwProviderEntry& entry) {
                    return entry.providerName.compare(manualText, Qt::CaseInsensitive) == 0;
                });
            if (found != m_etwProviders.end())
            {
                tryAppendProvider(found->providerName, found->providerGuidText);
            }
        }
    }

    {
        kLogEvent event;
        info << event
            << "[MonitorDock] ETW预置模板统计, checked="
            << presetCheckedCount
            << ", matched="
            << presetMatchedCount
            << eol;
    }

    if (selectedProviders.empty() && legacyKernelEnableFlags == 0)
    {
        kLogEvent event;
        warn << event
            << "[MonitorDock] 启动ETW失败：未选择可用Provider。"
            << eol;
        QMessageBox::information(this, QStringLiteral("ETW监听"), QStringLiteral("请至少选择一个可解析 GUID 的 Provider。"));
        return;
    }

    // 捕获回调只读取这份本轮会话快照，Provider 刷新不再与回调线程并发访问 m_etwProviders。
    m_etwCaptureProviderNames.clear();
    for (const ProviderSelection& provider : selectedProviders)
    {
        m_etwCaptureProviderNames.insert(guidToText(provider.guid), provider.name);
    }
    if (legacyKernelEnableFlags != 0)
    {
        m_etwCaptureProviderNames.insert(
            guidToText(kWindowsKernelTraceProviderGuid),
            QStringLiteral("Windows Kernel Trace"));
    }

    QString archiveErrorText;
    if (!prepareEtwArchiveSession(&archiveErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("ETW监听"), archiveErrorText);
        return;
    }

    // 新一轮 ETW 监听开始前清空旧结果：
    // - 表格、后置缓存与时间轴点必须同步归零；
    // - 时间轴起点使用启动瞬间的 100ns 时间戳，后续右边界实时跟随。
    if (m_etwEventTable != nullptr)
    {
        m_etwEventTable->clearContents();
        m_etwEventTable->setRowCount(0);
    }
    m_etwCapturedRows.clear();
    m_etwTimelineEventPoints.clear();
    m_etwTimelinePauseIntervals.clear();
    m_etwCaptureStartTime100ns = currentSystemTime100ns();
    m_etwCaptureStopTime100ns = 0;
    m_etwTimelinePauseTime100ns = 0;
    m_etwTimelineSelectionStart100ns = m_etwCaptureStartTime100ns;
    m_etwTimelineSelectionEnd100ns = m_etwCaptureStartTime100ns;
    m_etwTimelineUserSelectionActive = false;
    if (m_etwTimelineWidget != nullptr)
    {
        m_etwTimelineWidget->resetTimeline(m_etwCaptureStartTime100ns);
        m_etwTimelineSelectionStart100ns = m_etwTimelineWidget->selectionStart100ns();
        m_etwTimelineSelectionEnd100ns = m_etwTimelineWidget->selectionEnd100ns();
    }
    applyEtwPostFilterToTable();

    // 清空待刷新队列，避免把上一轮数据混入本轮。
    {
        std::lock_guard<std::mutex> lock(m_etwPendingMutex);
        m_etwPendingRows.clear();
    }
    m_etwUiSkippedRows.store(0, std::memory_order_relaxed);
    m_etwSourceEventsLost.store(0, std::memory_order_relaxed);

    // 每轮监听开始前刷新一次 schema 缓存：
    // - 这样可以保证本轮会话基于最新事件布局重新建模；
    // - 后续同类型事件直接走缓存，不再重复调用 TDH。
    clearEtwSchemaCache();

    m_etwCaptureRunning.store(true);
    m_etwCapturePaused.store(false);
    m_etwTimelinePauseTime100ns = 0;
    m_etwCaptureStopFlag.store(false);
    m_etwSessionHandle.store(0);
    m_etwTraceHandle.store(0);
    stopActiveKswordTraceSessionsByPrefix(QStringList{ QStringLiteral("KswordEtw") });
    m_etwSessionName = QStringLiteral("KswordEtw");

    if (m_etwCaptureProgressPid == 0)
    {
        m_etwCaptureProgressPid = kPro.addReusable(this, "监控", "ETW监听");
    }
    kPro.set(m_etwCaptureProgressPid, "准备ETW实时会话", 0, 10.0f);

    m_etwCaptureStatusLabel->setText(QStringLiteral("● 监听中"));
    m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));
    updateEtwCaptureActionState();

    if (m_etwUiUpdateTimer != nullptr && !m_etwUiUpdateTimer->isActive())
    {
        m_etwUiUpdateTimer->start();
    }

    const UCHAR traceLevel = etwLevelFromText(m_etwLevelCombo->currentText());
    const ULONGLONG keywordMask = parseKeywordMaskText(m_etwKeywordMaskEdit->text());
    const ULONG bufferSizeKb = static_cast<ULONG>(m_etwBufferSizeSpin->value());
    const ULONG minBuffer = static_cast<ULONG>(m_etwMinBufferSpin->value());
    const ULONG maxBuffer = static_cast<ULONG>(m_etwMaxBufferSpin->value());

    {
        kLogEvent event;
        info << event
            << "[MonitorDock] 启动ETW监听, providerCount="
            << selectedProviders.size()
            << ", level="
            << static_cast<int>(traceLevel)
            << ", keywordMask=0x"
            << QString::number(static_cast<qulonglong>(keywordMask), 16).toUpper().toStdString()
            << ", bufferSizeKb="
            << bufferSizeKb
            << ", minBuffer="
            << minBuffer
            << ", maxBuffer="
            << maxBuffer
            << eol;
    }

    QPointer<MonitorDock> guardThis(this);
    m_etwCaptureThread = std::make_unique<std::thread>(
        [guardThis, selectedProviders, legacyKernelEnableFlags, traceLevel, keywordMask, bufferSizeKb, minBuffer, maxBuffer]() {
        if (guardThis == nullptr)
        {
            return;
        }

        const auto reportStopped = [guardThis]()
        {
            QMetaObject::invokeMethod(qApp, [guardThis]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                const bool wasPaused = guardThis->m_etwCapturePaused.load();
                const std::uint64_t pauseEnd100ns = guardThis->m_etwTimelinePauseTime100ns;
                guardThis->m_etwCaptureRunning.store(false);
                guardThis->m_etwCapturePaused.store(false);
                if (guardThis->m_etwCaptureStopTime100ns == 0)
                {
                    guardThis->m_etwCaptureStopTime100ns = wasPaused && pauseEnd100ns != 0
                        ? pauseEnd100ns
                        : currentSystemTime100ns();
                }
                if (wasPaused && pauseEnd100ns != 0)
                {
                    guardThis->closeEtwTimelinePauseInterval(pauseEnd100ns);
                }
                guardThis->m_etwTimelinePauseTime100ns = 0;

                const std::uint64_t eventsLost = guardThis->m_etwSourceEventsLost.load(std::memory_order_relaxed);
                const bool archiveFailed = guardThis->m_etwArchiveWriteFailed.load(std::memory_order_relaxed);
                if (guardThis->m_etwCaptureStatusLabel != nullptr)
                {
                    guardThis->m_etwCaptureStatusLabel->setText(archiveFailed
                        ? QStringLiteral("● ETW归档写入失败")
                        : (eventsLost == 0
                            ? QStringLiteral("● 已停止")
                            : QStringLiteral("● ETW源事件丢失:%1").arg(static_cast<qulonglong>(eventsLost))));
                    guardThis->m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(
                        !archiveFailed && eventsLost == 0 ? monitorIdleColorHex() : monitorErrorColorHex()));
                }
                guardThis->updateEtwCaptureActionState();
                if (guardThis->m_etwUiUpdateTimer != nullptr && guardThis->m_etwUiUpdateTimer->isActive())
                {
                    guardThis->m_etwUiUpdateTimer->stop();
                }
                guardThis->flushEtwPendingRows(true);
                guardThis->scheduleEtwArchiveFilterRebuild();
                kPro.set(guardThis->m_etwCaptureProgressPid, "ETW监听结束", 0, 100.0f);
            }, Qt::QueuedConnection);
        };

        const std::wstring sessionNameWide = guardThis->m_etwSessionName.toStdWString();
        const ULONG propertyBufferSize = static_cast<ULONG>(
            sizeof(EVENT_TRACE_PROPERTIES) + (sessionNameWide.size() + 1) * sizeof(wchar_t));
        std::vector<unsigned char> propertyBuffer(propertyBufferSize, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());

        properties->Wnode.BufferSize = propertyBufferSize;
        properties->Wnode.ClientContext = 2; // 2=SystemTime（100ns）。
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        if (legacyKernelEnableFlags != 0)
        {
            // Kernel-Thread 与 Kernel-Image 是经典内核事件，不会出现在
            // TdhEnumerateProviders 的清单中。以私有 SystemTraceProvider 会话启用它们，
            // 同时保留普通 manifest Provider 的 EnableTraceEx2 订阅能力。
            properties->Wnode.Guid = kKswordEtwKernelSessionGuid;
            properties->LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
            properties->EnableFlags = legacyKernelEnableFlags;
        }
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        properties->BufferSize = bufferSizeKb;
        properties->MinimumBuffers = minBuffer;
        properties->MaximumBuffers = maxBuffer;

        wchar_t* loggerNamePtr = reinterpret_cast<wchar_t*>(propertyBuffer.data() + properties->LoggerNameOffset);
        if (!sessionNameWide.empty())
        {
            ::wcscpy_s(loggerNamePtr, sessionNameWide.size() + 1, sessionNameWide.c_str());
        }

        TRACEHANDLE sessionHandle = 0;
        ULONG startStatus = ::StartTraceW(&sessionHandle, loggerNamePtr, properties);
        if (startStatus == ERROR_ALREADY_EXISTS)
        {
            ::ControlTraceW(0, loggerNamePtr, properties, EVENT_TRACE_CONTROL_STOP);
            startStatus = ::StartTraceW(&sessionHandle, loggerNamePtr, properties);
        }

        if (startStatus != ERROR_SUCCESS)
        {
            guardThis->finishEtwArchiveSession();
            QMetaObject::invokeMethod(qApp, [guardThis, startStatus]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->m_etwCaptureRunning.store(false);
                guardThis->m_etwCapturePaused.store(false);
                guardThis->m_etwTimelinePauseTime100ns = 0;
                guardThis->m_etwCaptureStatusLabel->setText(QStringLiteral("● 启动失败:%1").arg(startStatus));
                guardThis->m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
                guardThis->updateEtwCaptureActionState();
                kPro.set(guardThis->m_etwCaptureProgressPid, "ETW会话启动失败", 0, 100.0f);
            }, Qt::QueuedConnection);
            return;
        }

        guardThis->m_etwSessionHandle.store(static_cast<std::uint64_t>(sessionHandle));
        if (guardThis->m_etwCaptureStopFlag.load())
        {
            const std::uint64_t ownedSessionHandle = guardThis->m_etwSessionHandle.exchange(0);
            if (ownedSessionHandle != 0)
            {
                ::ControlTraceW(
                    static_cast<TRACEHANDLE>(ownedSessionHandle),
                    loggerNamePtr,
                    properties,
                    EVENT_TRACE_CONTROL_STOP);
            }
            guardThis->finishEtwArchiveSession();
            reportStopped();
            return;
        }
        kPro.set(guardThis->m_etwCaptureProgressPid, "启用Provider", 0, 30.0f);

        int enableSuccessCount = legacyKernelEnableFlags != 0 ? 1 : 0;
        for (const ProviderSelection& provider : selectedProviders)
        {
            if (guardThis == nullptr || guardThis->m_etwCaptureStopFlag.load())
            {
                break;
            }

            const ULONG enableStatus = ::EnableTraceEx2(
                sessionHandle,
                &provider.guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                traceLevel,
                keywordMask,
                0,
                0,
                nullptr);

            if (enableStatus == ERROR_SUCCESS)
            {
                ++enableSuccessCount;
            }
            else
            {
                kLogEvent enableEvent;
                warn << enableEvent
                    << "[MonitorDock] EnableTraceEx2失败 provider="
                    << provider.name.toStdString()
                    << ", status="
                    << enableStatus
                    << eol;
            }
        }

        if (enableSuccessCount == 0)
        {
            ::ControlTraceW(sessionHandle, loggerNamePtr, properties, EVENT_TRACE_CONTROL_STOP);
            guardThis->m_etwSessionHandle.store(0);
            guardThis->finishEtwArchiveSession();
            QMetaObject::invokeMethod(qApp, [guardThis]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->m_etwCaptureRunning.store(false);
                guardThis->m_etwCapturePaused.store(false);
                guardThis->m_etwTimelinePauseTime100ns = 0;
                guardThis->m_etwCaptureStatusLabel->setText(QStringLiteral("● 无可用Provider"));
                guardThis->m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
                guardThis->updateEtwCaptureActionState();
                kPro.set(guardThis->m_etwCaptureProgressPid, "Provider启用失败", 0, 100.0f);
            }, Qt::QueuedConnection);
            return;
        }

        // 打开实时消费句柄并进入 ProcessTrace 阻塞读取。
        EVENT_TRACE_LOGFILEW logFile{};
        logFile.LoggerName = loggerNamePtr;
        logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logFile.EventRecordCallback = &MonitorDock::etwEventRecordCallback;
        logFile.Context = guardThis.data();

        TRACEHANDLE traceHandle = ::OpenTraceW(&logFile);
        if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            ::ControlTraceW(sessionHandle, loggerNamePtr, properties, EVENT_TRACE_CONTROL_STOP);
            guardThis->m_etwSessionHandle.store(0);
            guardThis->finishEtwArchiveSession();

            const ULONG lastError = ::GetLastError();
            QMetaObject::invokeMethod(qApp, [guardThis, lastError]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->m_etwCaptureRunning.store(false);
                guardThis->m_etwCapturePaused.store(false);
                guardThis->m_etwTimelinePauseTime100ns = 0;
                guardThis->m_etwCaptureStatusLabel->setText(QStringLiteral("● OpenTrace失败:%1").arg(lastError));
                guardThis->m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
                guardThis->updateEtwCaptureActionState();
                kPro.set(guardThis->m_etwCaptureProgressPid, "OpenTrace失败", 0, 100.0f);
            }, Qt::QueuedConnection);
            return;
        }

        guardThis->m_etwTraceHandle.store(static_cast<std::uint64_t>(traceHandle));
        if (guardThis->m_etwCaptureStopFlag.load())
        {
            const std::uint64_t ownedTraceHandle = guardThis->m_etwTraceHandle.exchange(0);
            if (ownedTraceHandle != 0)
            {
                ::CloseTrace(static_cast<TRACEHANDLE>(ownedTraceHandle));
            }
            const std::uint64_t ownedSessionHandle = guardThis->m_etwSessionHandle.exchange(0);
            if (ownedSessionHandle != 0)
            {
                ::ControlTraceW(
                    static_cast<TRACEHANDLE>(ownedSessionHandle),
                    loggerNamePtr,
                    properties,
                    EVENT_TRACE_CONTROL_STOP);
            }
            guardThis->finishEtwArchiveSession();
            reportStopped();
            return;
        }
        kPro.set(guardThis->m_etwCaptureProgressPid, "ETW事件接收中", 0, 55.0f);

        const ULONG processStatus = ::ProcessTrace(&traceHandle, 1, nullptr, nullptr);
        const ULONG eventsLost = logFile.EventsLost;
        guardThis->m_etwSourceEventsLost.store(eventsLost, std::memory_order_relaxed);
        guardThis->finishEtwArchiveSession();
        const std::uint64_t ownedTraceHandle = guardThis->m_etwTraceHandle.exchange(0);
        if (ownedTraceHandle != 0)
        {
            ::CloseTrace(static_cast<TRACEHANDLE>(ownedTraceHandle));
        }

        const std::uint64_t ownedSessionHandle = guardThis->m_etwSessionHandle.exchange(0);
        if (ownedSessionHandle != 0)
        {
            ::ControlTraceW(
                static_cast<TRACEHANDLE>(ownedSessionHandle),
                loggerNamePtr,
                properties,
                EVENT_TRACE_CONTROL_STOP);
        }

        QMetaObject::invokeMethod(qApp, [guardThis, processStatus, eventsLost]() {
            if (guardThis == nullptr)
            {
                return;
            }
            const bool wasPaused = guardThis->m_etwCapturePaused.load();
            const std::uint64_t pauseEnd100ns = guardThis->m_etwTimelinePauseTime100ns;
            guardThis->m_etwCaptureRunning.store(false);
            guardThis->m_etwCapturePaused.store(false);
            if (guardThis->m_etwCaptureStopTime100ns == 0)
            {
                guardThis->m_etwCaptureStopTime100ns = wasPaused && pauseEnd100ns != 0
                    ? pauseEnd100ns
                    : currentSystemTime100ns();
            }
            if (wasPaused && pauseEnd100ns != 0)
            {
                guardThis->closeEtwTimelinePauseInterval(pauseEnd100ns);
            }
            guardThis->m_etwTimelinePauseTime100ns = 0;

            if (guardThis->m_etwArchiveWriteFailed.load(std::memory_order_relaxed))
            {
                guardThis->m_etwCaptureStatusLabel->setText(QStringLiteral("● ETW归档写入失败"));
                guardThis->m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
            }
            else if (eventsLost != 0)
            {
                guardThis->m_etwCaptureStatusLabel->setText(
                    QStringLiteral("● ETW源事件丢失:%1").arg(eventsLost));
                guardThis->m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorErrorColorHex()));
            }
            else if (processStatus == ERROR_SUCCESS)
            {
                guardThis->m_etwCaptureStatusLabel->setText(QStringLiteral("● 已停止"));
                guardThis->m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));
            }
            else
            {
                guardThis->m_etwCaptureStatusLabel->setText(QStringLiteral("● 处理结束:%1").arg(processStatus));
                guardThis->m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorWarningColorHex()));
            }
            guardThis->updateEtwCaptureActionState();
            if (guardThis->m_etwUiUpdateTimer != nullptr && guardThis->m_etwUiUpdateTimer->isActive())
            {
                guardThis->m_etwUiUpdateTimer->stop();
            }
            guardThis->flushEtwPendingRows(true);
            guardThis->scheduleEtwArchiveFilterRebuild();
            if (eventsLost != 0)
            {
                kLogEvent lostEvent;
                err << lostEvent
                    << "[MonitorDock] ETW源报告事件丢失, eventsLost="
                    << eventsLost
                    << eol;
            }
            kPro.set(guardThis->m_etwCaptureProgressPid, "ETW监听结束", 0, 100.0f);
        }, Qt::QueuedConnection);
    });
}

void MonitorDock::stopEtwCapture()
{
    stopEtwCaptureInternal(false);
}

void MonitorDock::stopEtwCaptureInternal(bool waitForThread)
{
    {
        kLogEvent event;
        info << event
            << "[MonitorDock] 停止ETW请求, waitForThread="
            << (waitForThread ? "true" : "false")
            << eol;
    }

    m_etwCaptureStopFlag.store(true);
    if (m_etwCaptureRunning.load() && m_etwCaptureStopTime100ns == 0)
    {
        // 停止按钮按下时立即冻结时间轴右边界，避免等待后台线程退出期间继续扩大窗口。
        m_etwCaptureStopTime100ns = m_etwCapturePaused.load() && m_etwTimelinePauseTime100ns != 0
            ? m_etwTimelinePauseTime100ns
            : currentSystemTime100ns();
        refreshEtwTimelineRange(true);
    }

    // 先关闭消费句柄，打断 ProcessTrace 阻塞。
    const std::uint64_t ownedTraceHandle = m_etwTraceHandle.exchange(0);
    if (ownedTraceHandle != 0)
    {
        ::CloseTrace(static_cast<TRACEHANDLE>(ownedTraceHandle));
    }

    // 再停止会话，确保 ETW 内核资源被释放。
    const std::uint64_t ownedSessionHandle = m_etwSessionHandle.exchange(0);
    if (ownedSessionHandle != 0)
    {
        const std::wstring sessionNameWide = m_etwSessionName.toStdWString();
        const ULONG propertyBufferSize = static_cast<ULONG>(
            sizeof(EVENT_TRACE_PROPERTIES) + (sessionNameWide.size() + 1) * sizeof(wchar_t));
        std::vector<unsigned char> propertyBuffer(propertyBufferSize, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
        properties->Wnode.BufferSize = propertyBufferSize;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wchar_t* loggerNamePtr = reinterpret_cast<wchar_t*>(propertyBuffer.data() + properties->LoggerNameOffset);
        if (!sessionNameWide.empty())
        {
            ::wcscpy_s(loggerNamePtr, sessionNameWide.size() + 1, sessionNameWide.c_str());
        }

        ::ControlTraceW(
            static_cast<TRACEHANDLE>(ownedSessionHandle),
            loggerNamePtr,
            properties,
            EVENT_TRACE_CONTROL_STOP);
    }

    if (m_etwCaptureThread == nullptr || !m_etwCaptureThread->joinable())
    {
        // 没有后台线程时也可能处于暂停状态，停止边界应沿用暂停冻结点。
        const bool wasPaused = m_etwCapturePaused.load();
        const std::uint64_t pauseEnd100ns = m_etwTimelinePauseTime100ns;
        if (m_etwCaptureStopTime100ns == 0 && wasPaused && pauseEnd100ns != 0)
        {
            m_etwCaptureStopTime100ns = pauseEnd100ns;
        }
        if (wasPaused && pauseEnd100ns != 0)
        {
            closeEtwTimelinePauseInterval(pauseEnd100ns);
        }
        m_etwCaptureThread.reset();
        m_etwCaptureRunning.store(false);
        m_etwCapturePaused.store(false);
        m_etwTimelinePauseTime100ns = 0;
        if (m_etwCaptureStatusLabel != nullptr)
        {
            const std::uint64_t eventsLost = m_etwSourceEventsLost.load(std::memory_order_relaxed);
            const bool archiveFailed = m_etwArchiveWriteFailed.load(std::memory_order_relaxed);
            m_etwCaptureStatusLabel->setText(archiveFailed
                ? QStringLiteral("● ETW归档写入失败")
                : (eventsLost == 0
                    ? QStringLiteral("● 已停止")
                    : QStringLiteral("● ETW源事件丢失:%1").arg(static_cast<qulonglong>(eventsLost))));
            m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(
                !archiveFailed && eventsLost == 0 ? monitorIdleColorHex() : monitorErrorColorHex()));
        }
        if (m_etwUiUpdateTimer != nullptr && m_etwUiUpdateTimer->isActive())
        {
            m_etwUiUpdateTimer->stop();
        }
        flushEtwPendingRows(true);
        scheduleEtwArchiveFilterRebuild();
        updateEtwCaptureActionState();
        kLogEvent event;
        dbg << event
            << "[MonitorDock] 停止ETW：当前无活动线程。"
            << eol;
        return;
    }

    if (waitForThread)
    {
        // 同步停止可能来自析构路径，先保存暂停边界再清除暂停状态。
        const bool wasPaused = m_etwCapturePaused.load();
        const std::uint64_t pauseEnd100ns = m_etwTimelinePauseTime100ns;
        if (m_etwCaptureStopTime100ns == 0 && wasPaused && pauseEnd100ns != 0)
        {
            m_etwCaptureStopTime100ns = pauseEnd100ns;
        }
        if (wasPaused && pauseEnd100ns != 0)
        {
            closeEtwTimelinePauseInterval(pauseEnd100ns);
        }
        // 析构路径：同步等待线程退出，确保对象销毁前完全回收 ETW 线程。
        m_etwCaptureThread->join();
        m_etwCaptureThread.reset();
        m_etwCaptureRunning.store(false);
        m_etwCapturePaused.store(false);
        m_etwTimelinePauseTime100ns = 0;
        if (m_etwCaptureStatusLabel != nullptr)
        {
            const std::uint64_t eventsLost = m_etwSourceEventsLost.load(std::memory_order_relaxed);
            const bool archiveFailed = m_etwArchiveWriteFailed.load(std::memory_order_relaxed);
            m_etwCaptureStatusLabel->setText(archiveFailed
                ? QStringLiteral("● ETW归档写入失败")
                : (eventsLost == 0
                    ? QStringLiteral("● 已停止")
                    : QStringLiteral("● ETW源事件丢失:%1").arg(static_cast<qulonglong>(eventsLost))));
            m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(
                !archiveFailed && eventsLost == 0 ? monitorIdleColorHex() : monitorErrorColorHex()));
        }
        if (m_etwUiUpdateTimer != nullptr && m_etwUiUpdateTimer->isActive())
        {
            m_etwUiUpdateTimer->stop();
        }
        flushEtwPendingRows(true);
        scheduleEtwArchiveFilterRebuild();
        updateEtwCaptureActionState();
        kLogEvent event;
        info << event
            << "[MonitorDock] 停止ETW：同步等待线程结束完成。"
            << eol;
        return;
    }

    // 交互路径只请求停止，线程所有权必须保留给析构路径。
    if (m_etwCaptureStatusLabel != nullptr)
    {
        m_etwCaptureStatusLabel->setText(QStringLiteral("● 停止中..."));
        m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorWarningColorHex()));
    }
    if (m_etwUiUpdateTimer != nullptr && m_etwUiUpdateTimer->isActive())
    {
        m_etwUiUpdateTimer->stop();
    }
    updateEtwCaptureActionState();
}

void MonitorDock::setEtwCapturePaused(bool paused)
{
    if (!m_etwCaptureRunning.load())
    {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] 忽略ETW暂停操作：监听未运行。"
            << eol;
        return;
    }

    if (paused)
    {
        if (m_etwCapturePaused.load() && m_etwTimelinePauseTime100ns != 0)
        {
            return;
        }
        // 暂停时记录原始时间点，时间轴坐标会在映射时扣除这段等待时间。
        m_etwTimelinePauseTime100ns = currentSystemTime100ns();
        if (m_etwTimelinePauseTime100ns <= m_etwCaptureStartTime100ns)
        {
            m_etwTimelinePauseTime100ns = m_etwCaptureStartTime100ns + 1;
        }
        m_etwCapturePaused.store(true);
        // 立即冻结 UI 镜像。待刷新队列完整保留，继续监听后再恢复分批显示。
        if (m_etwUiUpdateTimer != nullptr && m_etwUiUpdateTimer->isActive())
        {
            m_etwUiUpdateTimer->stop();
        }
        m_etwArchiveFilterTicket.fetch_add(1, std::memory_order_relaxed);
        if (m_etwArchiveFilterDebounceTimer != nullptr)
        {
            m_etwArchiveFilterDebounceTimer->stop();
        }
        refreshEtwTimelineRange(false);
        m_etwCaptureStatusLabel->setText(QStringLiteral("● 已暂停"));
        m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorWarningColorHex()));
    }
    else
    {
        // 继续监听时固化暂停区间；后续时间轴把该区间从可见时长中扣除。
        const std::uint64_t resumeTime100ns = currentSystemTime100ns();
        closeEtwTimelinePauseInterval(resumeTime100ns);
        m_etwCapturePaused.store(false);
        m_etwTimelinePauseTime100ns = 0;
        if (m_etwUiUpdateTimer != nullptr && !m_etwUiUpdateTimer->isActive())
        {
            m_etwUiUpdateTimer->start();
        }
        refreshEtwTimelineRange(false);
        refreshEtwTimelinePoints();
        if (m_etwPostSimpleFilterCompiled.hasAnyCondition()
            || !m_etwPostFilterCompiledGroupList.empty()
            || isEtwTimelineFilterActive())
        {
            scheduleEtwArchiveFilterRebuild();
        }
        m_etwCaptureStatusLabel->setText(QStringLiteral("● 监听中"));
        m_etwCaptureStatusLabel->setStyleSheet(buildStatusStyle(monitorInfoColorHex()));
    }
    updateEtwCaptureActionState();

    kLogEvent event;
    info << event
        << "[MonitorDock] ETW暂停状态变更, paused="
        << (paused ? "true" : "false")
        << eol;
}

void MonitorDock::updateEtwCaptureActionState()
{
    const bool running = m_etwCaptureRunning.load();
    const bool paused = m_etwCapturePaused.load();

    if (m_etwStartButton != nullptr)
    {
        m_etwStartButton->setEnabled(!running || paused);
        m_etwStartButton->setIcon(QIcon(paused
            ? QStringLiteral(":/Icon/process_resume.svg")
            : QStringLiteral(":/Icon/process_start.svg")));
        m_etwStartButton->setToolTip(paused
            ? QStringLiteral("继续监听")
            : QStringLiteral("开始监听"));
    }

    if (m_etwStopButton != nullptr)
    {
        m_etwStopButton->setEnabled(running);
    }

    if (m_etwPauseButton != nullptr)
    {
        m_etwPauseButton->setEnabled(running && !paused);
        m_etwPauseButton->setIcon(QIcon(QStringLiteral(":/Icon/process_pause.svg")));
        m_etwPauseButton->setToolTip(QStringLiteral("暂停监听"));
    }
}

void MonitorDock::flushEtwPendingRows(const bool captureFinished)
{
    if (m_etwEventTable == nullptr)
    {
        return;
    }
    if (!captureFinished && m_etwCapturePaused.load())
    {
        // 防止暂停前已经投递到事件循环的最后一次 timeout 继续排空队列。
        return;
    }

    // 菜单屏障必须位于 pending drain 和时间轴/表格任何变更之前。周期 timeout
    // 只保留最新重试；captureFinished 也随最后一次重试传递。
    const QPointer<MonitorDock> guardThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        captureFinished
            ? QStringLiteral("monitor-etw-event-flush-final")
            : QStringLiteral("monitor-etw-event-flush-periodic"),
        { m_etwEventTable },
        [guardThis, captureFinished]()
        {
            if (!guardThis.isNull())
            {
                guardThis->flushEtwPendingRows(captureFinished);
            }
        }))
    {
        return;
    }

    // 每 50ms 最多创建 32 行（224 个 QTableWidgetItem），将主线程表格构造控制在约 640 行/秒。
    // UI 队列只承担实时镜像，未显示事件仍完整保存在磁盘归档中。
    constexpr std::size_t kMaxRowsPerFlush = 32;
    constexpr int kMaxCapturedRows = 6000;
    constexpr int kTrimThresholdRows = 6200;
    constexpr qint64 kTimelineRefreshIntervalMs = 250;

    std::vector<EtwCapturedEventRow> rows;
    {
        std::lock_guard<std::mutex> lock(m_etwPendingMutex);
        const std::size_t flushCount = std::min(kMaxRowsPerFlush, m_etwPendingRows.size());
        rows.reserve(flushCount);
        for (std::size_t rowIndex = 0; rowIndex < flushCount; ++rowIndex)
        {
            rows.push_back(std::move(m_etwPendingRows.front()));
            m_etwPendingRows.pop_front();
        }
    }

    // 当前规则可能在事件进入 UI 队列后发生变化。只筛选本帧的少量镜像行，
    // 全量结果仍由后台归档扫描负责，避免在主线程反复遍历历史表格。
    const bool hasPostRules = m_etwPostSimpleFilterCompiled.hasAnyCondition()
        || !m_etwPostFilterCompiledGroupList.empty();
    const bool timelineFilterActive = isEtwTimelineFilterActive();
    if (hasPostRules || timelineFilterActive)
    {
        rows.erase(
            std::remove_if(
                rows.begin(),
                rows.end(),
                [this, timelineFilterActive](const EtwCapturedEventRow& rowData) {
                    bool matches = etwFilterStageMatches(
                        m_etwPostSimpleFilterCompiled,
                        m_etwPostFilterCompiledGroupList,
                        rowData);
                    if (matches && timelineFilterActive)
                    {
                        const std::uint64_t timestamp100ns = etwRawTimestampToTimelineTimestamp(
                            rowData.timestampValue);
                        matches = timestamp100ns >= m_etwTimelineSelectionStart100ns
                            && timestamp100ns <= m_etwTimelineSelectionEnd100ns;
                    }
                    return !matches;
                }),
            rows.end());
    }

    const bool refreshTimeline = captureFinished
        || !m_etwTimelineRefreshTimer.isValid()
        || m_etwTimelineRefreshTimer.hasExpired(kTimelineRefreshIntervalMs);

    if (rows.empty())
    {
        // 空刷新在暂停时不推进范围、不重推点集，防止瀑布流右边界持续压缩既有事件。
        const bool paused = m_etwCapturePaused.load();
        if (refreshTimeline && (captureFinished || !paused))
        {
            refreshEtwTimelineRange(captureFinished);
            refreshEtwTimelinePoints();
            m_etwTimelineRefreshTimer.restart();
        }
        if (captureFinished || (!paused && isEtwTimelineFilterActive()))
        {
            applyEtwPostFilterToTable();
        }

        if (captureFinished && m_etwUiUpdateTimer != nullptr && m_etwUiUpdateTimer->isActive())
        {
            m_etwUiUpdateTimer->stop();
        }
        return;
    }

    // 一次只追加受限批次。setUpdatesEnabled 仅抑制重绘，真正的限流由 kMaxRowsPerFlush 完成。
    m_etwEventTable->setUpdatesEnabled(false);

    // 先腾出固定结果窗口空间，再批量扩展行数，避免 insertRow/removeRow 循环触发大量模型和布局更新。
    const int projectedRowCount = m_etwEventTable->rowCount() + static_cast<int>(rows.size());
    const int overflowCount = projectedRowCount > kTrimThresholdRows
        ? projectedRowCount - kMaxCapturedRows
        : 0;
    if (overflowCount > 0)
    {
        if (!m_etwEventTable->model()->removeRows(0, overflowCount))
        {
            for (int rowIndex = 0; rowIndex < overflowCount; ++rowIndex)
            {
                m_etwEventTable->removeRow(0);
            }
        }
        for (int rowIndex = 0; rowIndex < overflowCount && !m_etwCapturedRows.empty(); ++rowIndex)
        {
            m_etwCapturedRows.pop_front();
        }
        for (int rowIndex = 0; rowIndex < overflowCount && !m_etwTimelineEventPoints.empty(); ++rowIndex)
        {
            m_etwTimelineEventPoints.pop_front();
        }
    }

    const int firstInsertedRow = m_etwEventTable->rowCount();
    m_etwEventTable->setRowCount(firstInsertedRow + static_cast<int>(rows.size()));
    for (std::size_t rowIndex = 0; rowIndex < rows.size(); ++rowIndex)
    {
        EtwCapturedEventRow& rowData = rows[rowIndex];
        m_etwCapturedRows.push_back(std::move(rowData));
        EtwCapturedEventRow& captured = m_etwCapturedRows.back();

        const int row = firstInsertedRow + static_cast<int>(rowIndex);
        QTableWidgetItem* sequenceItem = new QTableWidgetItem(QString::number(
            static_cast<qulonglong>(captured.archiveSequence != 0
                ? captured.archiveSequence
                : static_cast<std::uint64_t>(row + 1))));
        sequenceItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        m_etwEventTable->setVerticalHeaderItem(row, sequenceItem);

        const QStringList rowTextList{
            captured.timestampText,
            captured.providerName,
            QString::number(captured.eventId),
            captured.eventName,
            captured.pidTidText,
            captured.detailSummary,
            captured.activityId
        };

        for (int col = 0; col < rowTextList.size(); ++col)
        {
            const QString cellText = rowTextList.at(col);
            QTableWidgetItem* item = new QTableWidgetItem(cellText);
            item->setToolTip(cellText);
            if (col == 5)
            {
                // Detail 列的 UserRole 保存完整 JSON，表格文本只显示摘要。
                item->setData(Qt::UserRole, captured.detailJson);
            }
            m_etwEventTable->setItem(row, col, item);
        }

        ProcessTraceTimelineEventPoint pointValue;
        // 时间轴使用“有效运行时间”坐标，暂停区间不会占用横向宽度。
        pointValue.time100ns = etwRawTimestampToTimelineTimestamp(captured.timestampValue);
        pointValue.typeText = etwTimelineTypeFromCapturedRow(captured);
        m_etwTimelineEventPoints.push_back(std::move(pointValue));
    }

    // m_etwCapturedRows 与 m_etwTimelineEventPoints 已在追加前同步批量裁剪，
    // 行号仍能一一对应，无需逐行 erase(begin())。
    if (refreshTimeline)
    {
        refreshEtwTimelineRange(captureFinished);
        refreshEtwTimelinePoints();
        m_etwTimelineRefreshTimer.restart();
    }
    m_etwEventTable->setUpdatesEnabled(true);
    m_etwEventTable->scrollToBottom();
    m_etwEventTable->viewport()->update();

    if (captureFinished)
    {
        bool hasPendingRows = false;
        {
            std::lock_guard<std::mutex> lock(m_etwPendingMutex);
            hasPendingRows = !m_etwPendingRows.empty();
        }

        // 停止监听后仍可能有一个批次在队列中。分帧排空，避免“停止”操作再次卡住 UI。
        if (hasPendingRows && !m_etwCaptureRunning.load())
        {
            QTimer::singleShot(16, this, [this]() {
                if (!m_etwCaptureRunning.load())
                {
                    flushEtwPendingRows(true);
                }
            });
        }
        else if (!hasPendingRows && m_etwUiUpdateTimer != nullptr && m_etwUiUpdateTimer->isActive())
        {
            m_etwUiUpdateTimer->stop();
        }
    }
}

void MonitorDock::applyEtwTimelineSelection(
    const std::uint64_t start100ns,
    const std::uint64_t end100ns)
{
    // 时间轴控件只解释鼠标/滚轮动作，表格可见性仍交给 ETW 后置筛选统一处理。
    // 这里保存的是“扣除暂停段后的有效时间戳”，表格筛选时会把事件原始时间映射后比较。
    m_etwTimelineSelectionStart100ns = std::min(start100ns, end100ns);
    m_etwTimelineSelectionEnd100ns = std::max(start100ns, end100ns);
    m_etwTimelineUserSelectionActive = true;
    scheduleEtwArchiveFilterRebuild();
}

std::uint64_t MonitorDock::etwRawTimestampToTimelineTimestamp(const std::uint64_t rawTimestamp100ns) const
{
    if (m_etwCaptureStartTime100ns == 0 || rawTimestamp100ns <= m_etwCaptureStartTime100ns)
    {
        return m_etwCaptureStartTime100ns;
    }

    // pausedDuration100ns 统计 rawTimestamp100ns 之前已经消耗在暂停状态里的时长。
    std::uint64_t pausedDuration100ns = 0;
    for (const auto& pauseInterval : m_etwTimelinePauseIntervals)
    {
        const std::uint64_t pauseStart100ns = pauseInterval.first;
        const std::uint64_t pauseEnd100ns = pauseInterval.second;
        if (pauseEnd100ns <= pauseStart100ns || rawTimestamp100ns <= pauseStart100ns)
        {
            continue;
        }

        const std::uint64_t effectivePauseEnd100ns = std::min(rawTimestamp100ns, pauseEnd100ns);
        pausedDuration100ns += effectivePauseEnd100ns - pauseStart100ns;
    }

    // 当前仍处于暂停时，把暂停起点到当前边界这段也从右边界显示时间里扣掉。
    if (m_etwCapturePaused.load() && m_etwTimelinePauseTime100ns != 0 && rawTimestamp100ns > m_etwTimelinePauseTime100ns)
    {
        pausedDuration100ns += rawTimestamp100ns - m_etwTimelinePauseTime100ns;
    }

    const std::uint64_t rawElapsed100ns = rawTimestamp100ns - m_etwCaptureStartTime100ns;
    const std::uint64_t effectiveElapsed100ns = rawElapsed100ns > pausedDuration100ns
        ? rawElapsed100ns - pausedDuration100ns
        : 0;
    return m_etwCaptureStartTime100ns + effectiveElapsed100ns;
}

void MonitorDock::closeEtwTimelinePauseInterval(const std::uint64_t resumeTime100ns)
{
    if (m_etwTimelinePauseTime100ns == 0 || resumeTime100ns <= m_etwTimelinePauseTime100ns)
    {
        return;
    }

    // 区间保存原始 ETW 绝对时间，映射函数统一把其换算为有效运行时间。
    m_etwTimelinePauseIntervals.emplace_back(m_etwTimelinePauseTime100ns, resumeTime100ns);
}

void MonitorDock::refreshEtwTimelineRange(const bool captureFinished)
{
    if (m_etwTimelineWidget == nullptr || m_etwCaptureStartTime100ns == 0)
    {
        return;
    }

    // captureEndRaw100ns：
    // - 停止后固定到停止瞬间，避免用户复查时选区继续漂移；
    // - 暂停时固定到暂停瞬间，避免瀑布流在无新事件时被不断压缩；
    // - 正常监听时才使用当前系统时间推进右边界。
    std::uint64_t captureEndRaw100ns = currentSystemTime100ns();
    if (captureFinished && m_etwCaptureStopTime100ns != 0)
    {
        captureEndRaw100ns = m_etwCaptureStopTime100ns;
    }
    else if (m_etwCapturePaused.load() && m_etwTimelinePauseTime100ns != 0)
    {
        captureEndRaw100ns = m_etwTimelinePauseTime100ns;
    }
    if (captureEndRaw100ns <= m_etwCaptureStartTime100ns)
    {
        captureEndRaw100ns = m_etwCaptureStartTime100ns + 1;
    }

    std::uint64_t captureEnd100ns = etwRawTimestampToTimelineTimestamp(captureEndRaw100ns);
    if (captureEnd100ns <= m_etwCaptureStartTime100ns)
    {
        captureEnd100ns = m_etwCaptureStartTime100ns + 1;
    }

    m_etwTimelineWidget->setCaptureRange(m_etwCaptureStartTime100ns, captureEnd100ns);
    m_etwTimelineSelectionStart100ns = m_etwTimelineWidget->selectionStart100ns();
    m_etwTimelineSelectionEnd100ns = m_etwTimelineWidget->selectionEnd100ns();
}

void MonitorDock::refreshEtwTimelinePoints()
{
    if (m_etwTimelineWidget == nullptr)
    {
        return;
    }

    // 控件保留 vector API，ETW 侧使用 deque 以便 O(1) 淘汰最旧事件。
    // 时间轴按节流周期刷新，避免每个 UI 批次复制并重绘完整点集。
    std::vector<ProcessTraceTimelineEventPoint> pointSnapshot;
    pointSnapshot.reserve(m_etwTimelineEventPoints.size());
    pointSnapshot.insert(
        pointSnapshot.end(),
        m_etwTimelineEventPoints.begin(),
        m_etwTimelineEventPoints.end());
    m_etwTimelineWidget->setEventPoints(pointSnapshot);
}

bool MonitorDock::isEtwTimelineFilterActive() const
{
    if (m_etwCaptureStartTime100ns == 0
        || !m_etwTimelineUserSelectionActive
        || m_etwTimelineSelectionStart100ns == 0
        || m_etwTimelineSelectionEnd100ns == 0
        || m_etwTimelineSelectionEnd100ns <= m_etwTimelineSelectionStart100ns)
    {
        return false;
    }

    std::uint64_t effectiveEndRaw100ns = currentSystemTime100ns();
    if (m_etwCaptureStopTime100ns != 0)
    {
        effectiveEndRaw100ns = m_etwCaptureStopTime100ns;
    }
    else if (m_etwCapturePaused.load() && m_etwTimelinePauseTime100ns != 0)
    {
        effectiveEndRaw100ns = m_etwTimelinePauseTime100ns;
    }
    std::uint64_t effectiveEnd100ns = etwRawTimestampToTimelineTimestamp(effectiveEndRaw100ns);
    if (effectiveEnd100ns <= m_etwCaptureStartTime100ns)
    {
        return false;
    }

    // 全范围选区不是筛选条件；只有用户主动缩小或平移窗口后才隐藏时间窗口外的事件。
    return m_etwTimelineSelectionStart100ns > m_etwCaptureStartTime100ns
        || m_etwTimelineSelectionEnd100ns < effectiveEnd100ns;
}

void MonitorDock::appendEtwEventRow(
    const QString& providerName,
    int eventId,
    const QString& eventName,
    std::uint32_t pidValue,
    std::uint32_t tidValue,
    const QString& detailJson,
    const QString& activityIdText)
{
    const int row = m_etwEventTable->rowCount();
    m_etwEventTable->insertRow(row);

    const QString detailSummaryText = buildEtwSummaryFromDetailJson(
        detailJson,
        providerName,
        eventName,
        pidValue,
        tidValue);

    const QStringList values{
        now100nsText(),
        providerName,
        QString::number(eventId),
        eventName,
        QStringLiteral("%1 / %2").arg(pidValue).arg(tidValue),
        detailSummaryText,
        activityIdText
    };

    for (int i = 0; i < values.size(); ++i)
    {
        QTableWidgetItem* item = new QTableWidgetItem(values.at(i));
        item->setToolTip(values.at(i));
        if (i == 5)
        {
            item->setData(Qt::UserRole, detailJson);
        }
        m_etwEventTable->setItem(row, i, item);
    }
}

void MonitorDock::exportEtwRowsToTsv(const bool visibleOnly)
{
    bool hasArchiveRows = false;
    {
        std::lock_guard<std::mutex> lock(m_etwArchiveMutex);
        hasArchiveRows = !m_etwArchiveDirectory.trimmed().isEmpty()
            && m_etwArchiveNextSequence != 0;
    }

    if (hasArchiveRows)
    {
        const QString defaultName = QStringLiteral("etw_events_%1.tsv")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
        const QString path = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("导出ETW结果"),
            defaultName,
            QStringLiteral("TSV文件 (*.tsv);;文本文件 (*.txt)"));
        if (path.trimmed().isEmpty())
        {
            return;
        }

        QStringList header;
        if (m_etwEventTable != nullptr)
        {
            for (int col = 0; col < m_etwEventTable->columnCount(); ++col)
            {
                QTableWidgetItem* item = m_etwEventTable->horizontalHeaderItem(col);
                header << (item != nullptr ? item->text() : QString());
            }
        }
        if (header.isEmpty())
        {
            header = QStringList{
                QStringLiteral("时间"), QStringLiteral("Provider"), QStringLiteral("事件ID"),
                QStringLiteral("事件名称"), QStringLiteral("PID/TID"), QStringLiteral("详情"),
                QStringLiteral("ActivityId")
            };
        }

        const EtwSimpleFilterCompiled postSimpleFilter = m_etwPostSimpleFilterCompiled;
        const std::vector<EtwFilterRuleGroupCompiled> postFilterGroups = m_etwPostFilterCompiledGroupList;
        const bool timelineFilterActive = visibleOnly && isEtwTimelineFilterActive();
        const std::uint64_t captureStart100ns = m_etwCaptureStartTime100ns;
        const std::uint64_t selectionStart100ns = m_etwTimelineSelectionStart100ns;
        const std::uint64_t selectionEnd100ns = m_etwTimelineSelectionEnd100ns;
        const std::vector<std::pair<std::uint64_t, std::uint64_t>> pauseIntervals =
            m_etwTimelinePauseIntervals;
        const bool capturePaused = m_etwCapturePaused.load();
        const std::uint64_t activePauseStart100ns = m_etwTimelinePauseTime100ns;
        const std::uint64_t sessionGeneration = m_etwArchiveSessionGeneration.load(
            std::memory_order_relaxed);

        if (!beginEtwArchiveBackgroundTask())
        {
            return;
        }
        MonitorDock* taskOwner = this;
        const auto taskCompletion = std::shared_ptr<void>(
            reinterpret_cast<void*>(1),
            [taskOwner](void*) {
                taskOwner->endEtwArchiveBackgroundTask();
            });
        QPointer<MonitorDock> guardThis(this);
        std::thread([
            taskOwner,
            taskCompletion,
            guardThis,
            path,
            header,
            visibleOnly,
            postSimpleFilter,
            postFilterGroups,
            timelineFilterActive,
            captureStart100ns,
            selectionStart100ns,
            selectionEnd100ns,
            pauseIntervals,
            capturePaused,
            activePauseStart100ns,
            sessionGeneration]() {
            const auto shouldCancel = [taskOwner, sessionGeneration]() {
                return taskOwner->m_etwArchiveSessionGeneration.load(std::memory_order_relaxed)
                    != sessionGeneration;
            };
            const auto rawToTimelineTimestamp = [
                captureStart100ns,
                pauseIntervals,
                capturePaused,
                activePauseStart100ns](const std::uint64_t rawTimestamp100ns) {
                if (captureStart100ns == 0 || rawTimestamp100ns <= captureStart100ns)
                {
                    return captureStart100ns;
                }
                std::uint64_t pausedDuration100ns = 0;
                for (const auto& pauseInterval : pauseIntervals)
                {
                    if (pauseInterval.second <= pauseInterval.first
                        || rawTimestamp100ns <= pauseInterval.first)
                    {
                        continue;
                    }
                    pausedDuration100ns += std::min(rawTimestamp100ns, pauseInterval.second)
                        - pauseInterval.first;
                }
                if (capturePaused
                    && activePauseStart100ns != 0
                    && rawTimestamp100ns > activePauseStart100ns)
                {
                    pausedDuration100ns += rawTimestamp100ns - activePauseStart100ns;
                }
                const std::uint64_t elapsed100ns = rawTimestamp100ns - captureStart100ns;
                return captureStart100ns
                    + (elapsed100ns > pausedDuration100ns
                        ? elapsed100ns - pausedDuration100ns
                        : 0);
            };

            if (shouldCancel())
            {
                return;
            }
            taskOwner->finishEtwArchiveSession();
            if (shouldCancel())
            {
                return;
            }

            QStringList segmentPaths;
            bool archiveWriteFailed = false;
            {
                std::lock_guard<std::mutex> lock(taskOwner->m_etwArchiveMutex);
                segmentPaths = taskOwner->m_etwArchiveClosedSegmentPaths;
                archiveWriteFailed = taskOwner->m_etwArchiveWriteFailed;
            }

            QString errorText;
            std::uint64_t exportedRows = 0;
            std::uint64_t scannedRows = 0;
            std::uint64_t maxSequence = 0;
            QSaveFile file(path);
            if (archiveWriteFailed)
            {
                errorText = QStringLiteral("ETW 全量归档写入失败，无法保证导出完整性。");
            }
            else if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
            {
                errorText = QStringLiteral("无法写入文件：%1").arg(path);
            }

            bool streamWriteFailed = false;
            if (errorText.isEmpty())
            {
                QTextStream out(&file);
                out << header.join(QChar(u'\t')) << QChar(u'\n');
                const auto cleanTsvField = [](QString value) {
                    value.replace(QChar(u'\t'), QChar(u' '));
                    value.replace(QChar(u'\r'), QChar(u' '));
                    value.replace(QChar(u'\n'), QChar(u' '));
                    return value;
                };
                const auto rowVisitor = [&](const EtwCapturedEventRow& row) {
                    bool matches = !visibleOnly
                        || etwFilterStageMatches(postSimpleFilter, postFilterGroups, row);
                    if (matches && timelineFilterActive)
                    {
                        const std::uint64_t timelineTimestamp100ns = rawToTimelineTimestamp(row.timestampValue);
                        matches = timelineTimestamp100ns >= selectionStart100ns
                            && timelineTimestamp100ns <= selectionEnd100ns;
                    }
                    if (!matches)
                    {
                        return true;
                    }

                    const QStringList values{
                        cleanTsvField(row.timestampText),
                        cleanTsvField(row.providerName),
                        QString::number(row.eventId),
                        cleanTsvField(row.eventName),
                        cleanTsvField(row.pidTidText),
                        cleanTsvField(row.detailSummary),
                        cleanTsvField(row.activityId)
                    };
                    out << values.join(QChar(u'\t')) << QChar(u'\n');
                    ++exportedRows;
                    if (out.status() != QTextStream::Ok)
                    {
                        streamWriteFailed = true;
                        return false;
                    }
                    return true;
                };

                for (const QString& segmentPath : segmentPaths)
                {
                    if (shouldCancel())
                    {
                        break;
                    }
                    if (!scanEtwArchiveFile(
                        segmentPath,
                        rowVisitor,
                        shouldCancel,
                        &scannedRows,
                        &maxSequence,
                        &errorText))
                    {
                        break;
                    }
                    if (streamWriteFailed)
                    {
                        errorText = QStringLiteral("写入 ETW 导出文件失败：%1").arg(path);
                        break;
                    }
                }
                out.flush();
                if (out.status() != QTextStream::Ok)
                {
                    errorText = QStringLiteral("写入 ETW 导出文件失败：%1").arg(path);
                }
            }

            bool committed = false;
            if (!shouldCancel() && errorText.isEmpty())
            {
                committed = file.commit();
                if (!committed)
                {
                    errorText = QStringLiteral("提交 ETW 导出文件失败：%1").arg(path);
                }
            }
            else
            {
                file.cancelWriting();
            }
            if (shouldCancel())
            {
                return;
            }

            QMetaObject::invokeMethod(qApp, [
                guardThis,
                path,
                exportedRows,
                scannedRows,
                committed,
                errorText]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                if (!committed)
                {
                    QMessageBox::warning(
                        guardThis,
                        QStringLiteral("导出ETW"),
                        errorText.isEmpty() ? QStringLiteral("ETW 导出失败。") : errorText);
                    return;
                }

                kLogEvent event;
                info << event
                    << "[MonitorDock] ETW全量归档导出完成, path="
                    << path.toStdString()
                    << ", exportedRows="
                    << exportedRows
                    << ", scannedRows="
                    << scannedRows
                    << eol;
                QMessageBox::information(
                    guardThis,
                    QStringLiteral("导出ETW"),
                    QStringLiteral("导出完成：%1 条事件 -> %2")
                        .arg(static_cast<qulonglong>(exportedRows))
                        .arg(path));
            }, Qt::QueuedConnection);
        }).detach();
        return;
    }

    if (m_etwEventTable == nullptr || m_etwEventTable->rowCount() == 0)
    {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] ETW导出取消：无可导出事件。"
            << eol;
        QMessageBox::information(this, QStringLiteral("导出ETW"), QStringLiteral("当前没有可导出的事件。"));
        return;
    }

    int exportableCount = 0;
    for (int row = 0; row < m_etwEventTable->rowCount(); ++row)
    {
        if (!visibleOnly || !m_etwEventTable->isRowHidden(row))
        {
            ++exportableCount;
        }
    }
    if (exportableCount == 0)
    {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] ETW导出取消：当前导出范围为空。"
            << eol;
        QMessageBox::information(this, QStringLiteral("导出ETW"), QStringLiteral("当前导出范围为空，没有可导出的ETW事件。"));
        return;
    }

    const QString defaultName = QStringLiteral("etw_events_%1.tsv")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));

    const QString path = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出ETW结果"),
        defaultName,
        QStringLiteral("TSV文件 (*.tsv);;文本文件 (*.txt)"));

    if (path.trimmed().isEmpty())
    {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] ETW导出取消：用户未选择路径。"
            << eol;
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        kLogEvent event;
        err << event
            << "[MonitorDock] ETW导出失败：无法写入文件, path="
            << path.toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("导出ETW"), QStringLiteral("无法写入文件：%1").arg(path));
        return;
    }

    QTextStream out(&file);

    QStringList header;
    for (int col = 0; col < m_etwEventTable->columnCount(); ++col)
    {
        QTableWidgetItem* item = m_etwEventTable->horizontalHeaderItem(col);
        header << (item != nullptr ? item->text() : QString());
    }
    out << header.join('\t') << '\n';

    for (int row = 0; row < m_etwEventTable->rowCount(); ++row)
    {
        if (visibleOnly && m_etwEventTable->isRowHidden(row))
        {
            continue;
        }

        QStringList values;
        for (int col = 0; col < m_etwEventTable->columnCount(); ++col)
        {
            QTableWidgetItem* item = m_etwEventTable->item(row, col);
            values << (item != nullptr ? item->text().replace('\t', ' ') : QString());
        }
        out << values.join('\t') << '\n';
    }

    file.close();

    kLogEvent event;
    info << event
        << "[MonitorDock] ETW导出完成:"
        << path.toStdString()
        << ", exportedRows="
        << exportableCount
        << ", visibleOnly="
        << (visibleOnly ? "true" : "false")
        << eol;
    QMessageBox::information(this, QStringLiteral("导出ETW"), QStringLiteral("导出完成：%1").arg(path));
}

void MonitorDock::openEtwEventDetailViewerForRow(const int row) const
{
    const QString detailText = buildEtwRowDetailText(m_etwEventTable, row);
    if (detailText.trimmed().isEmpty())
    {
        return;
    }

    QString eventNameText;
    if (m_etwEventTable != nullptr)
    {
        QTableWidgetItem* eventNameItem = m_etwEventTable->item(row, 3);
        if (eventNameItem != nullptr)
        {
            eventNameText = eventNameItem->text().trimmed();
        }
    }

    monitor_text_viewer::showReadOnlyTextWindow(
        const_cast<MonitorDock*>(this),
        QStringLiteral("ETW 返回详情 - %1").arg(eventNameText.isEmpty() ? QStringLiteral("事件") : eventNameText),
        detailText,
        QStringLiteral("monitor://etw/row-%1.txt").arg(row + 1));
}

void MonitorDock::showEtwEventContextMenu(const QPoint& position)
{
    const QModelIndex index = m_etwEventTable->indexAt(position);
    if (!index.isValid())
    {
        return;
    }

    const int row = index.row();
    const int col = index.column();

    QMenu menu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* viewDetailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("查看返回详情"));
    menu.addSeparator();
    QAction* copyDetailAction = menu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制返回详情文本"));
    QAction* copyCellAction = menu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制单元格"));
    QAction* copyRowAction = menu.addAction(QIcon(":/Icon/log_clipboard.svg"), QStringLiteral("复制整行"));
    menu.addSeparator();
    QAction* gotoProcessAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
    ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [this, row]() -> ks::online_scan::SandboxUploadTarget {
            // 输入：ETW 事件表当前右键行。
            // 处理：从 PID/TID 列解析 PID，并查询该进程 EXE 路径。
            // 返回：VT 上传目标；解析失败时由统一 helper 显示错误。
            QTableWidgetItem* pidItem = m_etwEventTable != nullptr
                ? m_etwEventTable->item(row, 4)
                : nullptr;
            std::uint32_t pidValue = 0;
            if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &pidValue))
            {
                return {
                    QString(),
                    QStringLiteral("ETW 事件"),
                    QStringLiteral("当前 ETW 事件行未解析出有效 PID，无法上传发起进程文件。")
                };
            }

            const QString processPath = QString::fromStdString(ks::process::QueryProcessPathByPid(pidValue)).trimmed();
            if (processPath.isEmpty())
            {
                return {
                    QString(),
                    QStringLiteral("ETW 事件 PID=%1").arg(pidValue),
                    QStringLiteral("无法解析 PID=%1 的进程镜像路径。进程可能已退出，或当前权限不足。").arg(pidValue)
                };
            }

            return {
                processPath,
                QStringLiteral("ETW 事件 PID=%1").arg(pidValue),
                QString()
            };
        });

    QAction* action = menu.exec(m_etwEventTable->viewport()->mapToGlobal(position));
    if (action == nullptr)
    {
        kLogEvent event;
        dbg << event
            << "[MonitorDock] ETW事件右键菜单取消。"
            << eol;
        return;
    }

    if (action == viewDetailAction)
    {
        kLogEvent event;
        info << event
            << "[MonitorDock] ETW事件右键操作：查看返回详情, row="
            << row
            << eol;
        openEtwEventDetailViewerForRow(row);
        return;
    }

    if (action == copyDetailAction)
    {
        const QString detailText = buildEtwRowDetailText(m_etwEventTable, row);
        QApplication::clipboard()->setText(detailText);
        kLogEvent event;
        dbg << event
            << "[MonitorDock] ETW事件右键操作：复制返回详情文本, row="
            << row
            << eol;
        return;
    }

    if (action == copyCellAction)
    {
        QTableWidgetItem* item = m_etwEventTable->item(row, col);
        if (item != nullptr)
        {
            QApplication::clipboard()->setText(item->text());
        }
        kLogEvent event;
        dbg << event
            << "[MonitorDock] ETW事件右键操作：复制单元格, row="
            << row
            << ", col="
            << col
            << eol;
        return;
    }

    if (action == copyRowAction)
    {
        QStringList values;
        for (int i = 0; i < m_etwEventTable->columnCount(); ++i)
        {
            QTableWidgetItem* item = m_etwEventTable->item(row, i);
            values << (item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(values.join('\t'));
        kLogEvent event;
        dbg << event
            << "[MonitorDock] ETW事件右键操作：复制整行, row="
            << row
            << eol;
        return;
    }

    if (action == gotoProcessAction)
    {
        QTableWidgetItem* pidItem = m_etwEventTable->item(row, 4);
        if (pidItem == nullptr)
        {
            return;
        }

        std::uint32_t pid = 0;
        if (!parsePid(pidItem->text(), pid))
        {
            kLogEvent event;
            warn << event
                << "[MonitorDock] ETW事件右键操作失败：PID解析失败, text="
                << pidItem->text().toStdString()
                << eol;
            QMessageBox::information(this, QStringLiteral("ETW事件"), QStringLiteral("未解析到有效PID。"));
            return;
        }
        kLogEvent event;
        info << event
            << "[MonitorDock] ETW事件右键操作：转到进程详情, pid="
            << pid
            << eol;
        openProcessDetail(this, pid);
    }
}
