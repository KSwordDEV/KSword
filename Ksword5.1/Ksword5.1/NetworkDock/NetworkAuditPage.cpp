#include "NetworkAuditPage.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"

// ============================================================
// NetworkAuditPage.cpp
// 作用：
// 1) 提供网络审计页的 UI 与快照刷新逻辑；
// 2) TCP/UDP Cross-View 合并连接刷新、PID 筛选、复制与 TCP 终止动作；
// 3) AFD/WFP/NDIS/NSI 保持只读审计边界。
// ============================================================

#include "../theme.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../ksword/file/file_handle_tools.h"
#include "../ksword/network/network.h"
#include "../ksword/network/network_connection_tools.h"
#include "../ksword/process/process.h"
#include "../ksword/log/log.h"
#include "../OnlineScan/SandboxUploadActions.h"

#include <QDateTime>
#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QJsonParseError>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QPixmap>
#include <QProcess>
#include <QPushButton>
#include <QSizePolicy>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThread>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <objbase.h>
#include <Rpc.h>
#include <Shellapi.h>
#include <fwpmu.h>

#pragma comment(lib, "Ws2_32.lib")

// NetworkAuditAsyncState 把 detached worker 的回投目标放在共享互斥状态中。
// 析构先清空 owner；worker 只有在同一把锁保护下才能提交 queued 调用，
// GUI 回调再复核 owner，并在调用页面成员前释放锁。
struct NetworkAuditAsyncState
{
    std::mutex mutex;
    NetworkAuditPage* owner = nullptr;
};

namespace
{
    // kAuditProcessIdColumn / kAuditProcessNameColumn：
    // - TCP、UDP 与 Cross-View 三张表都把 PID 放在第 0 列、进程名放在第 1 列；
    // - 图标异步回补时按这两个列号定位单元格。
    constexpr int kAuditProcessIdColumn = 0;
    constexpr int kAuditProcessNameColumn = 1;

    // auditProcessPlaceholderIcon 作用：
    // - 返回审计页统一的进程占位图标，图标未解析完成或解析失败时顶上；
    // - 入参：无；
    // - 返回：共享 QIcon 引用，只能在 UI 线程使用。
    const QIcon& auditProcessPlaceholderIcon()
    {
        static const QIcon placeholderIcon(QStringLiteral(":/Icon/process_main.svg"));
        return placeholderIcon;
    }

    // extractProcessIconImageForPid 作用：
    // - 在线程池工作线程里按 PID 解析可执行路径并向 Shell 查询小图标；
    // - SHGetFileInfoW 依赖 COM，工作线程必须自己成对 CoInitializeEx / CoUninitialize；
    // - 入参 processId：目标进程 PID；
    // - 返回：可跨线程传递的 QImage，失败时返回空 QImage（调用方回退占位图标）。
    QImage extractProcessIconImageForPid(const quint32 processId)
    {
        const std::string processPath = ks::process::QueryProcessPathByPid(processId);
        if (processPath.empty())
        {
            return QImage();
        }

        const HRESULT comInitializeResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const bool comInitializedHere = SUCCEEDED(comInitializeResult);

        const QString processPathText = QString::fromUtf8(processPath.c_str());
        SHFILEINFOW shellFileInfo{};
        const DWORD_PTR shellQueryResult = ::SHGetFileInfoW(
            reinterpret_cast<const wchar_t*>(processPathText.utf16()),
            0,
            &shellFileInfo,
            sizeof(shellFileInfo),
            SHGFI_ICON | SHGFI_SMALLICON);

        QImage processIconImage;
        if (shellQueryResult != 0 && shellFileInfo.hIcon != nullptr)
        {
            // QImage::fromHICON 会复制像素数据，转换完成后必须归还 Shell 分配的 HICON。
            processIconImage = QImage::fromHICON(shellFileInfo.hIcon);
            ::DestroyIcon(shellFileInfo.hIcon);
        }

        if (comInitializedHere)
        {
            ::CoUninitialize();
        }
        return processIconImage;
    }

    // applyResolvedIconToAuditTableRows 作用：
    // - 把异步解析完成的进程图标补到指定表中所有同 PID 的行上；
    // - 入参 tableWidget：TCP / UDP / Cross-View 三张表之一，可为空；
    // - 入参 processId：本次解析完成的 PID；
    // - 入参 resolvedIcon：解析结果或占位图标；
    // - 返回：无。该函数只能在 UI 线程调用。
    void applyResolvedIconToAuditTableRows(
        QTableWidget* const tableWidget,
        const quint32 processId,
        const QIcon& resolvedIcon)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        const QString processIdText = QString::number(processId);
        for (int rowIndex = 0; rowIndex < tableWidget->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* const processIdItem =
                tableWidget->item(rowIndex, kAuditProcessIdColumn);
            if (processIdItem == nullptr || processIdItem->text() != processIdText)
            {
                continue;
            }

            QTableWidgetItem* const processNameItem =
                tableWidget->item(rowIndex, kAuditProcessNameColumn);
            if (processNameItem != nullptr)
            {
                processNameItem->setIcon(resolvedIcon);
            }
        }
    }

    // createReadOnlyCell 作用：
    // - 创建不可编辑的表格单元格；
    // - 输入 cellText 为待显示文本；
    // - 返回可直接写入表格的 item 指针。
    QTableWidgetItem* createReadOnlyCell(const QString& cellText)
    {
        QTableWidgetItem* item = new QTableWidgetItem(cellText);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // tableMenuStyle 作用：
    // - 为网络审计页新增右键菜单提供不透明背景；
    // - 输入：无；
    // - 返回：QMenu 样式表，避免浅色模式黑底黑字。
    QString tableMenuStyle()
    {
        // 网络审计页菜单：
        // - 输入：无；
        // - 处理：统一复用全局不透明菜单样式，避免 palette role 在 Dock 透明背景下被错误继承；
        // - 返回：可直接应用到 QMenu 的样式文本。
        return KswordTheme::ContextMenuStyle();
    }

    // copyCurrentTableRow 作用：
    // - 把当前 QTableWidget 行复制为 TSV；
    // - 输入 table：目标表格；
    // - 返回：无，剪贴板不可用或未选中时直接返回。
    void copyCurrentTableRow(QTableWidget* table)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int rowIndex = table->currentRow();
        if (rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(fields.join('\t'));
    }

    // installCopyMenu 作用：
    // - 给只读审计表格安装“复制当前行”菜单；
    // - processIdColumn 为显式指定的 PID 列，-1 表示该表没有 PID；
    // - 返回：无，菜单只读，不改变网络栈状态。
    void installCopyMenu(QTableWidget* table, const int processIdColumn = -1)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table, processIdColumn](const QPoint& localPosition)
        {
            const QModelIndex clickedIndex = table->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                table->setCurrentCell(clickedIndex.row(), clickedIndex.column());
                table->selectRow(clickedIndex.row());
            }

            QMenu menu(table);
            menu.setStyleSheet(tableMenuStyle());
            QAction* copyRowAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            quint32 processId = 0;
            if (processIdColumn >= 0 && processIdColumn < table->columnCount() &&
                table->currentRow() >= 0 && table->currentRow() < table->rowCount())
            {
                const QTableWidgetItem* processIdItem = table->item(table->currentRow(), processIdColumn);
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
                openProcessDetailAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessDetailAction->setEnabled(processId != 0U);
            }

            const QAction* selectedAction = menu.exec(table->viewport()->mapToGlobal(localPosition));
            if (selectedAction == copyRowAction)
            {
                copyCurrentTableRow(table);
            }
            else if (selectedAction == openProcessDetailAction)
            {
                ks::ui::OpenProcessDetailByPid(processId);
            }
        });
    }

    // joinCompactLines 作用：
    // - 把若干短文本合并成单行摘要；
    // - 适合用于 cross-view 和 summary 页。
    QString joinCompactLines(const QStringList& lines)
    {
        QStringList filteredLines;
        filteredLines.reserve(lines.size());
        for (const QString& line : lines)
        {
            if (!line.trimmed().isEmpty())
            {
                filteredLines.push_back(line.trimmed());
            }
        }
        return filteredLines.join(QStringLiteral(" | "));
    }

    // ioMessageToText 作用：
    // - 把 ArkDriverClient 的 UTF-8 message 转为 Qt 文本；
    // - 输入 messageText：IoResult::message；
    // - 返回：可展示的 QString，空消息会归一化为“无附加信息”。
    QString ioMessageToText(const std::string& messageText)
    {
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息");
        }
        const QString rawText = QString::fromUtf8(messageText.c_str()).trimmed();
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该网络审计入口");
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            // 旧驱动兼容：
            // - 输入：ArkDriverClient 返回的 unsupported/not supported 文本；
            // - 处理：折叠为网络审计页统一的人读状态；
            // - 返回：不暴露底层 IOCTL 名称，方便用户直接判断需要更新驱动。
            return QStringLiteral("当前驱动不支持网络审计，请更新为匹配版本");
        }
        if (rawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("profile"), Qt::CaseInsensitive))
        {
            // 动态偏移诊断：
            // - 输入：驱动返回的 capability/DynData/profile 相关说明；
            // - 处理：转换成用户能理解的偏移能力缺口；
            // - 返回：指向内核 DynData 页继续排查。
            return QStringLiteral("当前驱动缺少网络审计所需能力，请更新驱动或相关数据文件");
        }
        if (rawText.contains(QStringLiteral("access denied"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("privilege"), Qt::CaseInsensitive))
        {
            return QStringLiteral("权限不足，无法完成网络审计查询");
        }
        if (rawText.contains(QStringLiteral("invalid parameter"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("version mismatch"), Qt::CaseInsensitive))
        {
            return QStringLiteral("R0/R3 网络审计协议参数不兼容，请同步 shared 协议与驱动版本");
        }
        if (rawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("entrySize"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("buffer"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动返回数据格式不完整，已保留 R3 审计结果");
        }
        if (rawText.contains(QStringLiteral("timeout"), Qt::CaseInsensitive))
        {
            return QStringLiteral("R0 网络审计查询超时，已保留现有 R3 审计结果");
        }
        if (rawText.contains(QStringLiteral("invalid response"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("invalid endpoint row"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("invalid WFP row"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("invalid NDIS row"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("returned rows exceed"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动返回的网络审计响应未通过协议校验，已丢弃 R0 数据");
        }
        if (rawText.contains(QStringLiteral("protocolStatus="), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动已返回并通过校验的结构化网络审计数据");
        }
        if (rawText.startsWith(QStringLiteral("version="), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动已返回结构化网络审计数据");
        }
        return rawText;
    }

    // r0AuditStatusText 作用：
    // - 将 R0 wrapper 的 ok/partial/unsupported/unavailable 状态转成 UI 文本；
    // - 输入 result：任意带 io/unsupported 字段的 ArkDriverClient 审计结果；
    // - 返回：验收要求中的 ok / partial / unsupported / unavailable。
    template <typename TResult>
    QString r0AuditStatusText(const TResult& result)
    {
        if (!result.io.ok)
        {
            return result.unsupported
                ? QStringLiteral("unsupported")
                : QStringLiteral("unavailable");
        }

        // DeviceIoControl 成功只代表拿到了结构化响应头；只有 APPLIED 且 total==returned 才是完整快照。
        // ArkDriverClient 已严格筛选 partial，其他 OPERATION_FAILED 不保留明细行。
        if (result.partial ||
            result.truncated ||
            result.totalCount > result.returnedCount)
        {
            return QStringLiteral("partial");
        }
        if (result.status != KSWORD_ARK_NETWORK_STATUS_APPLIED)
        {
            return QStringLiteral("unavailable");
        }
        return result.sourceFlags != KSWORD_ARK_NETWORK_AUDIT_SOURCE_NONE
            ? QStringLiteral("ok")
            : QStringLiteral("unavailable");
    }

    // r0AuditTruncatedText 作用：
    // - 根据 wrapper completeness 与 total/returned 判断 R0 结果是否被截断；
    // - 输入 result：任意 VariableAuditResultBase 派生结果；
    // - 返回：true/false 文本，方便摘要表直接展示。
    template <typename TResult>
    QString r0AuditTruncatedText(const TResult& result)
    {
        return result.truncated || result.totalCount > result.returnedCount
            ? QStringLiteral("true")
            : QStringLiteral("false");
    }

    // r0Hex32 作用：
    // - 输入 value：R0 协议中的 32 位 flags/status/fieldMask；
    // - 处理：统一补零十六进制展示；
    // - 返回：适合表格详情列复制的文本。
    QString r0Hex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 8, 16, QChar('0'))
            .toUpper();
    }

    // r0Hex64 作用：
    // - 输入 value：R0 协议中的对象地址、LUID 或 image base；
    // - 处理：统一补零十六进制展示；
    // - 返回：适合表格详情列复制的文本。
    QString r0Hex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    // fixedNetworkWideText 作用：
    // - 输入 buffer/maxChars：shared/driver 固定长度 wchar_t 字符串；
    // - 处理：遇到 NUL 终止，避免把填充区显示到 UI；
    // - 返回：可读文本，空字符串用 fallback 兜底。
    QString fixedNetworkWideText(const wchar_t* buffer, const std::size_t maxChars, const QString& fallback = QStringLiteral("<空>"))
    {
        if (buffer == nullptr || maxChars == 0U)
        {
            return fallback;
        }

        std::size_t length = 0U;
        while (length < maxChars && buffer[length] != L'\0')
        {
            ++length;
        }
        if (length == 0U)
        {
            return fallback;
        }
        return QString::fromWCharArray(buffer, static_cast<int>(length));
    }

    // r0AddressText 作用：
    // - 输入 family/address：R0 endpoint 行中的原始地址族和 16 字节地址；
    // - 处理：IPv4 按点分十进制，IPv6 按 8 组十六进制展示；
    // - 返回：可读 IP 地址，未知地址族保留诊断。
    QString r0AddressText(const unsigned long family, const unsigned char address[16])
    {
        if (address == nullptr)
        {
            return QStringLiteral("<无地址>");
        }
        if (family == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4)
        {
            return QStringLiteral("%1.%2.%3.%4")
                .arg(static_cast<unsigned int>(address[0]))
                .arg(static_cast<unsigned int>(address[1]))
                .arg(static_cast<unsigned int>(address[2]))
                .arg(static_cast<unsigned int>(address[3]));
        }
        if (family == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6)
        {
            QStringList groups;
            groups.reserve(8);
            for (int index = 0; index < 16; index += 2)
            {
                const unsigned int groupValue =
                    (static_cast<unsigned int>(address[index]) << 8U) |
                    static_cast<unsigned int>(address[index + 1]);
                groups.push_back(QStringLiteral("%1").arg(groupValue, 4, 16, QChar('0')));
            }
            return groups.join(':').toUpper();
        }
        return QStringLiteral("<AF=%1>").arg(family);
    }

    // r0EndpointText 作用：
    // - 输入 family/address/port：R0 endpoint 的地址和端口；
    // - 处理：把地址和端口合并为单个端点文本；
    // - 返回：IPv6 地址自动加方括号，便于和端口区分。
    QString r0EndpointText(const unsigned long family, const unsigned char address[16], const unsigned short port)
    {
        const QString addressText = r0AddressText(family, address);
        if (family == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6)
        {
            return QStringLiteral("[%1]:%2").arg(addressText).arg(port);
        }
        return QStringLiteral("%1:%2").arg(addressText).arg(port);
    }

    // r0TcpStateText 作用：
    // - 输入 state：KSWORD_ARK_NETWORK_TCP_STATE_*；
    // - 处理：常见 TCP 状态转为英文枚举名，未知值保留数字；
    // - 返回：TCP 明细表“状态”列文本。
    QString r0TcpStateText(const unsigned long state)
    {
        switch (state)
        {
        case KSWORD_ARK_NETWORK_TCP_STATE_CLOSED: return QStringLiteral("CLOSED");
        case KSWORD_ARK_NETWORK_TCP_STATE_LISTEN: return QStringLiteral("LISTEN");
        case KSWORD_ARK_NETWORK_TCP_STATE_SYN_SENT: return QStringLiteral("SYN_SENT");
        case KSWORD_ARK_NETWORK_TCP_STATE_SYN_RCVD: return QStringLiteral("SYN_RCVD");
        case KSWORD_ARK_NETWORK_TCP_STATE_ESTABLISHED: return QStringLiteral("ESTABLISHED");
        case KSWORD_ARK_NETWORK_TCP_STATE_FIN_WAIT_1: return QStringLiteral("FIN_WAIT_1");
        case KSWORD_ARK_NETWORK_TCP_STATE_FIN_WAIT_2: return QStringLiteral("FIN_WAIT_2");
        case KSWORD_ARK_NETWORK_TCP_STATE_CLOSE_WAIT: return QStringLiteral("CLOSE_WAIT");
        case KSWORD_ARK_NETWORK_TCP_STATE_CLOSING: return QStringLiteral("CLOSING");
        case KSWORD_ARK_NETWORK_TCP_STATE_LAST_ACK: return QStringLiteral("LAST_ACK");
        case KSWORD_ARK_NETWORK_TCP_STATE_TIME_WAIT: return QStringLiteral("TIME_WAIT");
        case KSWORD_ARK_NETWORK_TCP_STATE_DELETE_TCB: return QStringLiteral("DELETE_TCB");
        default: return QStringLiteral("STATE(%1)").arg(state);
        }
    }

    // r0GuidText 作用：
    // - 输入 bytes：R0 WFP 行中的 16 字节 GUID；
    // - 处理：复制到 GUID 后复用 Qt/Windows 格式化路径；
    // - 返回：标准 GUID 文本。
    QString r0GuidText(const unsigned char bytes[16])
    {
        if (bytes == nullptr)
        {
            return QStringLiteral("<无GUID>");
        }
        GUID guid{};
        std::memcpy(&guid, bytes, sizeof(guid));
        return QStringLiteral("{%1-%2-%3-%4%5-%6%7%8%9%10%11}")
            .arg(guid.Data1, 8, 16, QChar('0'))
            .arg(guid.Data2, 4, 16, QChar('0'))
            .arg(guid.Data3, 4, 16, QChar('0'))
            .arg(guid.Data4[0], 2, 16, QChar('0'))
            .arg(guid.Data4[1], 2, 16, QChar('0'))
            .arg(guid.Data4[2], 2, 16, QChar('0'))
            .arg(guid.Data4[3], 2, 16, QChar('0'))
            .arg(guid.Data4[4], 2, 16, QChar('0'))
            .arg(guid.Data4[5], 2, 16, QChar('0'))
            .arg(guid.Data4[6], 2, 16, QChar('0'))
            .arg(guid.Data4[7], 2, 16, QChar('0'))
            .toUpper();
    }

    // r0WfpObjectKindText 作用：
    // - 输入 kind：R0 WFP objectKind；
    // - 返回：Provider/Sublayer/Filter/Callout 等可读分类。
    QString r0WfpObjectKindText(const unsigned long kind)
    {
        switch (kind)
        {
        case KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER: return QStringLiteral("Provider");
        case KSWORD_ARK_NETWORK_WFP_OBJECT_SUBLAYER: return QStringLiteral("Sublayer");
        case KSWORD_ARK_NETWORK_WFP_OBJECT_FILTER: return QStringLiteral("Filter");
        case KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT: return QStringLiteral("Callout");
        default: return QStringLiteral("WFP(%1)").arg(kind);
        }
    }

    // r0NdisObjectKindText 作用：
    // - 输入 kind：R0 NDIS objectKind；
    // - 返回：未知对象明确标为 Unknown/Unproven，不把公开 device-stack 证据伪装成 LWF。
    QString r0NdisObjectKindText(const unsigned long kind)
    {
        switch (kind)
        {
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_UNKNOWN:
            return QStringLiteral("未知/未证明");
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_MINIPORT: return QStringLiteral("Miniport");
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_FILTER: return QStringLiteral("Filter");
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_PROTOCOL: return QStringLiteral("Protocol");
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_BINDING: return QStringLiteral("Binding");
        default: return QStringLiteral("NDIS(%1)").arg(kind);
        }
    }

    // WfpApi：保存动态解析到的 WFP 只读枚举入口。
    struct WfpApi
    {
        using FwpmEngineOpen0Fn = DWORD(WINAPI*)(const wchar_t*, UINT32, SEC_WINNT_AUTH_IDENTITY_W*, const FWPM_SESSION0*, HANDLE*);
        using FwpmEngineClose0Fn = DWORD(WINAPI*)(HANDLE);
        using FwpmFreeMemory0Fn = void(WINAPI*)(void**);
        using FwpmProviderCreateEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, const FWPM_PROVIDER_ENUM_TEMPLATE0*, HANDLE*);
        using FwpmProviderEnum0Fn = DWORD(WINAPI*)(HANDLE, HANDLE, UINT32, FWPM_PROVIDER0***, UINT32*);
        using FwpmProviderDestroyEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);
        using FwpmSubLayerCreateEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, const FWPM_SUBLAYER_ENUM_TEMPLATE0*, HANDLE*);
        using FwpmSubLayerEnum0Fn = DWORD(WINAPI*)(HANDLE, HANDLE, UINT32, FWPM_SUBLAYER0***, UINT32*);
        using FwpmSubLayerDestroyEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);
        using FwpmCalloutCreateEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, const FWPM_CALLOUT_ENUM_TEMPLATE0*, HANDLE*);
        using FwpmCalloutEnum0Fn = DWORD(WINAPI*)(HANDLE, HANDLE, UINT32, FWPM_CALLOUT0***, UINT32*);
        using FwpmCalloutDestroyEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);
        using FwpmFilterCreateEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, const FWPM_FILTER_ENUM_TEMPLATE0*, HANDLE*);
        using FwpmFilterEnum0Fn = DWORD(WINAPI*)(HANDLE, HANDLE, UINT32, FWPM_FILTER0***, UINT32*);
        using FwpmFilterDestroyEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);

        HMODULE moduleHandle = nullptr;
        FwpmEngineOpen0Fn engineOpen = nullptr;
        FwpmEngineClose0Fn engineClose = nullptr;
        FwpmFreeMemory0Fn freeMemory = nullptr;
        FwpmProviderCreateEnumHandle0Fn providerCreateEnumHandle = nullptr;
        FwpmProviderEnum0Fn providerEnum = nullptr;
        FwpmProviderDestroyEnumHandle0Fn providerDestroyEnumHandle = nullptr;
        FwpmSubLayerCreateEnumHandle0Fn subLayerCreateEnumHandle = nullptr;
        FwpmSubLayerEnum0Fn subLayerEnum = nullptr;
        FwpmSubLayerDestroyEnumHandle0Fn subLayerDestroyEnumHandle = nullptr;
        FwpmCalloutCreateEnumHandle0Fn calloutCreateEnumHandle = nullptr;
        FwpmCalloutEnum0Fn calloutEnum = nullptr;
        FwpmCalloutDestroyEnumHandle0Fn calloutDestroyEnumHandle = nullptr;
        FwpmFilterCreateEnumHandle0Fn filterCreateEnumHandle = nullptr;
        FwpmFilterEnum0Fn filterEnum = nullptr;
        FwpmFilterDestroyEnumHandle0Fn filterDestroyEnumHandle = nullptr;
    };

    WfpApi& wfpApi()
    {
        static WfpApi api;
        return api;
    }

    // loadWfpApi 作用：
    // - 只读加载 fwpuclnt.dll 并解析 WFP 枚举入口；
    // - errorTextOut 记录失败原因；
    // - 返回 true 表示可继续枚举。
    bool loadWfpApi(QString* errorTextOut)
    {
        WfpApi& api = wfpApi();
        if (api.moduleHandle == nullptr)
        {
            api.moduleHandle = ::LoadLibraryW(L"fwpuclnt.dll");
        }
        if (api.moduleHandle == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法加载 fwpuclnt.dll。");
            }
            return false;
        }

        auto procAddress = [moduleHandle = api.moduleHandle](const char* nameText) -> FARPROC
        {
            return ::GetProcAddress(moduleHandle, nameText);
        };

        api.engineOpen = reinterpret_cast<WfpApi::FwpmEngineOpen0Fn>(procAddress("FwpmEngineOpen0"));
        api.engineClose = reinterpret_cast<WfpApi::FwpmEngineClose0Fn>(procAddress("FwpmEngineClose0"));
        api.freeMemory = reinterpret_cast<WfpApi::FwpmFreeMemory0Fn>(procAddress("FwpmFreeMemory0"));
        api.providerCreateEnumHandle = reinterpret_cast<WfpApi::FwpmProviderCreateEnumHandle0Fn>(procAddress("FwpmProviderCreateEnumHandle0"));
        api.providerEnum = reinterpret_cast<WfpApi::FwpmProviderEnum0Fn>(procAddress("FwpmProviderEnum0"));
        api.providerDestroyEnumHandle = reinterpret_cast<WfpApi::FwpmProviderDestroyEnumHandle0Fn>(procAddress("FwpmProviderDestroyEnumHandle0"));
        api.subLayerCreateEnumHandle = reinterpret_cast<WfpApi::FwpmSubLayerCreateEnumHandle0Fn>(procAddress("FwpmSubLayerCreateEnumHandle0"));
        api.subLayerEnum = reinterpret_cast<WfpApi::FwpmSubLayerEnum0Fn>(procAddress("FwpmSubLayerEnum0"));
        api.subLayerDestroyEnumHandle = reinterpret_cast<WfpApi::FwpmSubLayerDestroyEnumHandle0Fn>(procAddress("FwpmSubLayerDestroyEnumHandle0"));
        api.calloutCreateEnumHandle = reinterpret_cast<WfpApi::FwpmCalloutCreateEnumHandle0Fn>(procAddress("FwpmCalloutCreateEnumHandle0"));
        api.calloutEnum = reinterpret_cast<WfpApi::FwpmCalloutEnum0Fn>(procAddress("FwpmCalloutEnum0"));
        api.calloutDestroyEnumHandle = reinterpret_cast<WfpApi::FwpmCalloutDestroyEnumHandle0Fn>(procAddress("FwpmCalloutDestroyEnumHandle0"));
        api.filterCreateEnumHandle = reinterpret_cast<WfpApi::FwpmFilterCreateEnumHandle0Fn>(procAddress("FwpmFilterCreateEnumHandle0"));
        api.filterEnum = reinterpret_cast<WfpApi::FwpmFilterEnum0Fn>(procAddress("FwpmFilterEnum0"));
        api.filterDestroyEnumHandle = reinterpret_cast<WfpApi::FwpmFilterDestroyEnumHandle0Fn>(procAddress("FwpmFilterDestroyEnumHandle0"));

        if (api.engineOpen == nullptr || api.engineClose == nullptr || api.freeMemory == nullptr ||
            api.providerCreateEnumHandle == nullptr || api.providerEnum == nullptr || api.providerDestroyEnumHandle == nullptr ||
            api.subLayerCreateEnumHandle == nullptr || api.subLayerEnum == nullptr || api.subLayerDestroyEnumHandle == nullptr ||
            api.calloutCreateEnumHandle == nullptr || api.calloutEnum == nullptr || api.calloutDestroyEnumHandle == nullptr ||
            api.filterCreateEnumHandle == nullptr || api.filterEnum == nullptr || api.filterDestroyEnumHandle == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("fwpuclnt.dll 缺少必要导出。");
            }
            return false;
        }

        return true;
    }

    // openWfpEngine 作用：
    // - 打开一个只读 WFP engine 会话；
    // - 失败时返回 false，并写入错误文本。
    bool openWfpEngine(HANDLE& engineHandleOut, QString* errorTextOut)
    {
        engineHandleOut = nullptr;
        if (!loadWfpApi(errorTextOut))
        {
            return false;
        }

        FWPM_SESSION0 session{};
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData.name = const_cast<wchar_t*>(L"KswordNetworkAudit");
        session.displayData.description = const_cast<wchar_t*>(L"Ksword network readonly audit session");

        const DWORD status = wfpApi().engineOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &engineHandleOut);
        if (status != ERROR_SUCCESS)
        {
            engineHandleOut = nullptr;
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("FwpmEngineOpen0 失败：%1").arg(status);
            }
            return false;
        }

        return true;
    }

    QString displayDataText(const FWPM_DISPLAY_DATA0* displayData)
    {
        if (displayData == nullptr)
        {
            return QString();
        }
        QStringList list;
        if (displayData->name != nullptr)
        {
            list.push_back(QString::fromWCharArray(displayData->name));
        }
        if (displayData->description != nullptr)
        {
            list.push_back(QString::fromWCharArray(displayData->description));
        }
        return joinCompactLines(list);
    }

    QString wfpFlagsText(const std::uint64_t flags)
    {
        return QStringLiteral("0x%1").arg(QString::number(flags, 16));
    }

    // normalizeJsonArray 作用：
    // - 把 PowerShell ConvertTo-Json 的“单对象/数组”两种输出统一成数组；
    // - 返回的数组可直接遍历。
    QJsonArray normalizeJsonArray(const QJsonValue& value)
    {
        if (value.isArray())
        {
            return value.toArray();
        }
        if (value.isObject())
        {
            QJsonArray array;
            array.push_back(value.toObject());
            return array;
        }
        return {};
    }
}

NetworkAuditPage::NetworkAuditPage(QWidget* parent)
    : QWidget(parent),
      m_asyncState(std::make_shared<NetworkAuditAsyncState>())
{
    m_asyncState->owner = this;
    initializeUi();
    m_crossAutoRefreshTimer = new QTimer(this);
    m_crossAutoRefreshTimer->setInterval(2200);
    initializeConnections();
}

NetworkAuditPage::~NetworkAuditPage()
{
    if (m_asyncState)
    {
        std::lock_guard<std::mutex> lock(m_asyncState->mutex);
        m_asyncState->owner = nullptr;
    }
}

void NetworkAuditPage::requestInitialRefresh()
{
    bool expected = false;
    if (m_initialRefreshRequested.compare_exchange_strong(expected, true))
    {
        refreshAllSnapshotsAsync(false);
    }
}

void NetworkAuditPage::focusProcessIds(const QSet<quint32>& processIds)
{
    m_processFilterSet = processIds;
    activateCrossView();
    if (m_crossFilterLabel != nullptr)
    {
        QStringList processIdTextList;
        processIdTextList.reserve(m_processFilterSet.size());
        for (const quint32 processId : m_processFilterSet)
        {
            processIdTextList.push_back(QString::number(processId));
        }
        processIdTextList.sort();
        m_crossFilterLabel->setText(
            m_processFilterSet.isEmpty()
                ? QStringLiteral("PID 筛选：无")
                : QStringLiteral("PID 筛选：%1 个进程")
                    .arg(m_processFilterSet.size()));
        m_crossFilterLabel->setToolTip(
            m_processFilterSet.isEmpty()
                ? QString()
                : QStringLiteral("PID：%1")
                    .arg(processIdTextList.join(',')));
    }
    updateCrossViewActionState();
    refreshAllSnapshotsAsync(true);
}

void NetworkAuditPage::activateCrossView()
{
    if (m_sectionTabWidget != nullptr && m_crossViewPage != nullptr)
    {
        m_sectionTabWidget->setCurrentWidget(m_crossViewPage);
    }
}

void NetworkAuditPage::setTrackProcessHandler(ProcessActionHandler handler)
{
    m_trackProcessHandler = std::move(handler);
}

void NetworkAuditPage::setOpenProcessDetailHandler(ProcessActionHandler handler)
{
    m_openProcessDetailHandler = std::move(handler);
}

void NetworkAuditPage::setUdpEndpointBlockRuleHandler(UdpEndpointBlockRuleHandler handler)
{
    m_udpEndpointBlockRuleHandler = std::move(handler);
}

void NetworkAuditPage::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(6);

    m_headerLayout = new QHBoxLayout();
    m_headerLayout->setContentsMargins(0, 0, 0, 0);
    m_headerLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(QStringLiteral("网络只读审计"), this);
    titleLabel->setStyleSheet(QStringLiteral("font-size:16px;font-weight:700;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    m_headerLayout->addWidget(titleLabel);

    m_statusLabel = new QLabel(QStringLiteral("状态：等待刷新"), this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setMinimumWidth(0);
    m_statusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_headerLayout->addWidget(m_statusLabel, 1);

    m_refreshButton = new QPushButton(QStringLiteral("刷新"), this);
    m_refreshButton->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    m_headerLayout->addWidget(m_refreshButton);

    m_rootLayout->addLayout(m_headerLayout);

    m_sectionTabWidget = new QTabWidget(this);
    m_sectionTabWidget->setTabPosition(QTabWidget::North);
    m_rootLayout->addWidget(m_sectionTabWidget, 1);

    // TCP/UDP cross-view。
    m_crossViewPage = new QWidget(this);
    QVBoxLayout* crossLayout = new QVBoxLayout(m_crossViewPage);
    crossLayout->setContentsMargins(4, 4, 4, 4);
    crossLayout->setSpacing(6);

    // 连接管理动作已合并到 Cross-View，不再单独占用顶层 Tab。
    m_crossControlLayout = new QHBoxLayout();
    m_crossControlLayout->setContentsMargins(0, 0, 0, 0);
    m_crossControlLayout->setSpacing(6);

    m_crossAutoRefreshButton = new QPushButton(QStringLiteral("自动刷新"), m_crossViewPage);
    m_crossAutoRefreshButton->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    m_crossAutoRefreshButton->setToolTip(QStringLiteral("每 2.2 秒自动刷新 TCP/UDP Cross-View"));
    m_crossAutoRefreshButton->setCheckable(true);
    m_crossAutoRefreshButton->setChecked(true);
    m_crossControlLayout->addWidget(m_crossAutoRefreshButton);

    m_crossTerminateButton = new QPushButton(QStringLiteral("终止 TCP"), m_crossViewPage);
    m_crossTerminateButton->setIcon(QIcon(QStringLiteral(":/Icon/process_terminate.svg")));
    m_crossTerminateButton->setToolTip(QStringLiteral("终止选中的 R3 IPv4 TCP 活动连接"));
    m_crossTerminateButton->setEnabled(false);
    m_crossControlLayout->addWidget(m_crossTerminateButton);

    m_clearProcessFilterButton = new QPushButton(QStringLiteral("清除 PID 筛选"), m_crossViewPage);
    m_clearProcessFilterButton->setIcon(QIcon(QStringLiteral(":/Icon/log_clear.svg")));
    m_clearProcessFilterButton->setToolTip(QStringLiteral("显示全部进程的 TCP/UDP 连接"));
    m_clearProcessFilterButton->setEnabled(false);
    m_crossControlLayout->addWidget(m_clearProcessFilterButton);

    m_crossFilterLabel = new QLabel(QStringLiteral("PID 筛选：无"), m_crossViewPage);
    m_crossFilterLabel->setMinimumWidth(0);
    m_crossFilterLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_crossControlLayout->addWidget(m_crossFilterLabel, 1);
    crossLayout->addLayout(m_crossControlLayout);

    m_crossViewSplitter = new QSplitter(Qt::Vertical, m_crossViewPage);
    m_crossViewTopSplitter = new QSplitter(Qt::Horizontal, m_crossViewSplitter);

    m_tcpTable = new ks::ui::VisibleTableWidget(m_crossViewTopSplitter);
    m_tcpTable->setColumnCount(6);
    m_tcpTable->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点"),
        QStringLiteral("远端端点"),
        QStringLiteral("状态"),
        QStringLiteral("来源/明细")
    });
    m_tcpTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tcpTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tcpTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tcpTable->verticalHeader()->setVisible(false);
    m_tcpTable->horizontalHeader()->setStretchLastSection(true);
    m_tcpTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_tcpTable->setContextMenuPolicy(Qt::CustomContextMenu);

    m_udpTable = new ks::ui::VisibleTableWidget(m_crossViewTopSplitter);
    m_udpTable->setColumnCount(5);
    m_udpTable->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点"),
        QStringLiteral("来源"),
        QStringLiteral("明细")
    });
    m_udpTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_udpTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_udpTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_udpTable->verticalHeader()->setVisible(false);
    m_udpTable->horizontalHeader()->setStretchLastSection(true);
    m_udpTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_udpTable->setContextMenuPolicy(Qt::CustomContextMenu);

    m_crossSummaryTable = new ks::ui::VisibleTableWidget(m_crossViewSplitter);
    m_crossSummaryTable->setColumnCount(5);
    m_crossSummaryTable->setHorizontalHeaderLabels({ QStringLiteral("PID"), QStringLiteral("进程"), QStringLiteral("TCP"), QStringLiteral("UDP"), QStringLiteral("摘要") });
    m_crossSummaryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_crossSummaryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_crossSummaryTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_crossSummaryTable->verticalHeader()->setVisible(false);
    m_crossSummaryTable->horizontalHeader()->setStretchLastSection(true);
    m_crossSummaryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    installCopyMenu(m_crossSummaryTable, 0);

    m_crossViewSplitter->addWidget(m_crossViewTopSplitter);
    m_crossViewSplitter->addWidget(m_crossSummaryTable);
    m_crossViewSplitter->setStretchFactor(0, 3);
    m_crossViewSplitter->setStretchFactor(1, 2);
    crossLayout->addWidget(m_crossViewSplitter, 1);
    m_sectionTabWidget->addTab(m_crossViewPage, QStringLiteral("TCP/UDP Cross-View"));

    // AFD。
    m_afdPage = new QWidget(this);
    QVBoxLayout* afdLayout = new QVBoxLayout(m_afdPage);
    afdLayout->setContentsMargins(4, 4, 4, 4);
    afdLayout->setSpacing(6);
    m_afdTable = new ks::ui::VisibleTableWidget(m_afdPage);
    m_afdTable->setColumnCount(8);
    m_afdTable->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("句柄"),
        QStringLiteral("类型"),
        QStringLiteral("对象名"),
        QStringLiteral("来源"),
        QStringLiteral("交叉视图"),
        QStringLiteral("详情")
    });
    m_afdTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_afdTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_afdTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_afdTable->verticalHeader()->setVisible(false);
    m_afdTable->horizontalHeader()->setStretchLastSection(true);
    m_afdTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    installCopyMenu(m_afdTable, 0);
    afdLayout->addWidget(m_afdTable, 1);
    m_sectionTabWidget->addTab(m_afdPage, QStringLiteral("AFD"));

    // WFP。
    m_wfpPage = new QWidget(this);
    QVBoxLayout* wfpLayout = new QVBoxLayout(m_wfpPage);
    wfpLayout->setContentsMargins(4, 4, 4, 4);
    wfpLayout->setSpacing(6);
    m_wfpTabWidget = new QTabWidget(m_wfpPage);
    m_wfpTabWidget->setTabPosition(QTabWidget::North);
    wfpLayout->addWidget(m_wfpTabWidget, 1);

    auto buildWfpTable = [](QWidget* parent, const QStringList& headers) -> QTableWidget*
    {
        QTableWidget* table = new ks::ui::VisibleTableWidget(parent);
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setStretchLastSection(true);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        installCopyMenu(table);
        return table;
    };
    m_wfpProviderTable = buildWfpTable(m_wfpPage, { QStringLiteral("名称"), QStringLiteral("描述"), QStringLiteral("GUID"), QStringLiteral("Flags"), QStringLiteral("Service"), QStringLiteral("数据大小") });
    m_wfpSubLayerTable = buildWfpTable(m_wfpPage, { QStringLiteral("名称"), QStringLiteral("描述"), QStringLiteral("GUID"), QStringLiteral("Flags"), QStringLiteral("Provider"), QStringLiteral("Weight") });
    m_wfpCalloutTable = buildWfpTable(m_wfpPage, { QStringLiteral("名称"), QStringLiteral("描述"), QStringLiteral("GUID"), QStringLiteral("Flags"), QStringLiteral("Provider"), QStringLiteral("Layer"), QStringLiteral("CalloutId") });
    m_wfpFilterTable = buildWfpTable(m_wfpPage, { QStringLiteral("名称"), QStringLiteral("描述"), QStringLiteral("GUID"), QStringLiteral("Flags"), QStringLiteral("Provider"), QStringLiteral("Layer"), QStringLiteral("Sublayer"), QStringLiteral("Weight"), QStringLiteral("Action"), QStringLiteral("Conditions"), QStringLiteral("FilterId") });
    m_wfpTabWidget->addTab(m_wfpProviderTable, QStringLiteral("Provider"));
    m_wfpTabWidget->addTab(m_wfpSubLayerTable, QStringLiteral("Sublayer"));
    m_wfpTabWidget->addTab(m_wfpCalloutTable, QStringLiteral("Callout"));
    m_wfpTabWidget->addTab(m_wfpFilterTable, QStringLiteral("Filter"));
    m_sectionTabWidget->addTab(m_wfpPage, QStringLiteral("WFP"));

    // NDIS。
    m_ndisPage = new QWidget(this);
    QVBoxLayout* ndisLayout = new QVBoxLayout(m_ndisPage);
    ndisLayout->setContentsMargins(4, 4, 4, 4);
    ndisLayout->setSpacing(6);
    m_ndisTabWidget = new QTabWidget(m_ndisPage);
    m_ndisTabWidget->setTabPosition(QTabWidget::North);
    ndisLayout->addWidget(m_ndisTabWidget, 1);
    m_ndisAdapterTable = buildWfpTable(m_ndisPage, { QStringLiteral("名称"), QStringLiteral("描述"), QStringLiteral("IfIndex"), QStringLiteral("状态"), QStringLiteral("MAC"), QStringLiteral("速率"), QStringLiteral("连接") });
    m_ndisBindingTable = buildWfpTable(m_ndisPage, { QStringLiteral("网卡"), QStringLiteral("显示名"), QStringLiteral("ComponentId"), QStringLiteral("启用"), QStringLiteral("InstanceId") });
    m_ndisProtocolTable = buildWfpTable(m_ndisPage, { QStringLiteral("别名"), QStringLiteral("IfIndex"), QStringLiteral("地址族"), QStringLiteral("连接"), QStringLiteral("Metric"), QStringLiteral("MTU") });
    m_ndisUnknownTable = buildWfpTable(m_ndisPage, { QStringLiteral("类型"), QStringLiteral("组件"), QStringLiteral("所属模块"), QStringLiteral("对象地址"), QStringLiteral("详情") });
    m_ndisTabWidget->addTab(m_ndisAdapterTable, QStringLiteral("Miniport"));
    m_ndisTabWidget->addTab(m_ndisBindingTable, QStringLiteral("Binding"));
    m_ndisTabWidget->addTab(m_ndisProtocolTable, QStringLiteral("Protocol"));
    m_ndisTabWidget->addTab(
        m_ndisUnknownTable,
        QStringLiteral("未知/未证明"));
    m_sectionTabWidget->addTab(m_ndisPage, QStringLiteral("NDIS"));

    // NSI。
    m_nsiPage = new QWidget(this);
    QVBoxLayout* nsiLayout = new QVBoxLayout(m_nsiPage);
    nsiLayout->setContentsMargins(4, 4, 4, 4);
    nsiLayout->setSpacing(6);
    m_nsiSummaryTable = new ks::ui::VisibleTableWidget(m_nsiPage);
    m_nsiSummaryTable->setColumnCount(5);
    m_nsiSummaryTable->setHorizontalHeaderLabels({
        QStringLiteral("指标"),
        QStringLiteral("状态/数值"),
        QStringLiteral("返回情况"),
        QStringLiteral("是否截断"),
        QStringLiteral("说明")
    });
    m_nsiSummaryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_nsiSummaryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_nsiSummaryTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_nsiSummaryTable->verticalHeader()->setVisible(false);
    m_nsiSummaryTable->horizontalHeader()->setStretchLastSection(true);
    m_nsiSummaryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    installCopyMenu(m_nsiSummaryTable);
    nsiLayout->addWidget(m_nsiSummaryTable, 1);
    m_sectionTabWidget->addTab(m_nsiPage, QStringLiteral("NSI"));
}

void NetworkAuditPage::initializeConnections()
{
    connect(m_refreshButton, &QPushButton::clicked, this, [this]()
    {
        refreshAllSnapshotsAsync(true);
    });

    connect(m_crossAutoRefreshButton, &QPushButton::toggled, this, [this](const bool enabled)
    {
        if (m_crossAutoRefreshTimer == nullptr)
        {
            return;
        }
        enabled ? m_crossAutoRefreshTimer->start() : m_crossAutoRefreshTimer->stop();
    });
    connect(m_crossAutoRefreshTimer, &QTimer::timeout, this, [this]()
    {
        if (isVisible()
            && m_sectionTabWidget != nullptr
            && m_sectionTabWidget->currentWidget() == m_crossViewPage)
        {
            refreshCrossViewAsync();
        }
    });
    if (m_crossAutoRefreshButton != nullptr && m_crossAutoRefreshButton->isChecked())
    {
        m_crossAutoRefreshTimer->start();
    }

    connect(m_crossTerminateButton, &QPushButton::clicked, this, [this]()
    {
        terminateSelectedTcpConnection();
    });
    connect(m_clearProcessFilterButton, &QPushButton::clicked, this, [this]()
    {
        focusProcessIds({});
    });
    connect(m_tcpTable, &QTableWidget::itemSelectionChanged, this, [this]()
    {
        updateCrossViewActionState();
    });
    connect(m_tcpTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position)
    {
        showCrossViewContextMenu(m_tcpTable, position);
    });
    connect(m_udpTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position)
    {
        showCrossViewContextMenu(m_udpTable, position);
    });
}

void NetworkAuditPage::refreshAllSnapshotsAsync(const bool forceRefresh)
{
    bool expected = false;
    if (!m_refreshInProgress.compare_exchange_strong(expected, true))
    {
        if (forceRefresh && m_statusLabel != nullptr)
        {
            m_statusLabel->setText(QStringLiteral("状态：已有刷新任务在运行"));
        }
        return;
    }

    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(false);
    }
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(forceRefresh ? QStringLiteral("状态：正在重新采集...") : QStringLiteral("状态：正在采集..."));
    }

    const std::shared_ptr<NetworkAuditAsyncState> asyncState = m_asyncState;
    std::thread([asyncState]()
    {
        AuditSnapshot snapshot;
        QString failureText;
        try
        {
            snapshot = buildAuditSnapshot();
        }
        catch (const std::exception& exception)
        {
            failureText = QStringLiteral("刷新失败：%1").arg(QString::fromUtf8(exception.what()));
        }
        catch (...)
        {
            failureText = QStringLiteral("刷新失败");
        }

        std::lock_guard<std::mutex> dispatchLock(asyncState->mutex);
        NetworkAuditPage* const receiver = asyncState->owner;
        if (receiver == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(receiver, [asyncState, snapshot = std::move(snapshot), failureText]() mutable
        {
            NetworkAuditPage* page = nullptr;
            {
                std::lock_guard<std::mutex> stateLock(asyncState->mutex);
                page = asyncState->owner;
            }
            if (page == nullptr)
            {
                return;
            }
            if (failureText.isEmpty())
            {
                page->applySnapshot(snapshot);
            }
            else
            {
                kLogEvent failureEvent;
                warn << failureEvent
                    << "[NetworkAuditPage] refresh failed, detail="
                    << failureText.toStdString()
                    << eol;
                if (page->m_statusLabel != nullptr)
                {
                    page->m_statusLabel->setText(QStringLiteral(
                        "状态：刷新失败；详情已写入日志。"));
                }
            }
            if (page->m_refreshButton != nullptr)
            {
                page->m_refreshButton->setEnabled(true);
            }
            page->m_refreshInProgress.store(false);
        }, Qt::QueuedConnection);
    }).detach();
}

void NetworkAuditPage::refreshCrossViewAsync()
{
    bool expected = false;
    if (!m_refreshInProgress.compare_exchange_strong(expected, true))
    {
        return;
    }

    const std::shared_ptr<NetworkAuditAsyncState> asyncState = m_asyncState;
    std::thread([asyncState]()
    {
        AuditSnapshot snapshot;
        QString failureText;
        try
        {
            snapshot = buildAuditSnapshot(true);
        }
        catch (const std::exception& exception)
        {
            failureText = QStringLiteral("刷新失败：%1").arg(QString::fromUtf8(exception.what()));
        }
        catch (...)
        {
            failureText = QStringLiteral("刷新失败");
        }

        std::lock_guard<std::mutex> dispatchLock(asyncState->mutex);
        NetworkAuditPage* const receiver = asyncState->owner;
        if (receiver == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            receiver,
            [asyncState, snapshot = std::move(snapshot), failureText]() mutable
            {
                NetworkAuditPage* page = nullptr;
                {
                    std::lock_guard<std::mutex> stateLock(asyncState->mutex);
                    page = asyncState->owner;
                }
                if (page == nullptr)
                {
                    return;
                }

                if (failureText.isEmpty())
                {
                    // R0 行由完整审计采集；高频连接刷新只替换 R3 行。
                    for (const TcpEndpointRow& cachedRow : page->m_tcpEndpointCache)
                    {
                        if (cachedRow.isR0Snapshot)
                        {
                            snapshot.tcpEndpointRows.push_back(cachedRow);
                        }
                    }
                    for (const UdpEndpointRow& cachedRow : page->m_udpEndpointCache)
                    {
                        if (cachedRow.sourceText.startsWith(QStringLiteral("R0")))
                        {
                            snapshot.udpEndpointRows.push_back(cachedRow);
                        }
                    }
                    page->refreshCrossViewTable(snapshot);
                }
                else
                {
                    kLogEvent failureEvent;
                    warn << failureEvent
                        << "[NetworkAuditPage] cross-view refresh failed, detail="
                        << failureText.toStdString()
                        << eol;
                    if (page->m_statusLabel != nullptr)
                    {
                        page->m_statusLabel->setText(QStringLiteral(
                            "状态：刷新失败；详情已写入日志。"));
                    }
                }
                page->m_refreshInProgress.store(false);
            },
            Qt::QueuedConnection);
    }).detach();
}

NetworkAuditPage::AuditSnapshot NetworkAuditPage::buildAuditSnapshot(const bool crossViewOnly)
{
    AuditSnapshot snapshot;

    // TCP/UDP cross-view：先分别枚举，再按 PID 聚合。
    std::vector<ks::network::TcpConnectionRecord> tcpRecords;
    std::vector<ks::network::UdpEndpointRecord> udpRecords;
    std::string tcpError;
    std::string udpError;
    const bool tcpOk = ks::network::EnumerateTcpConnectionRecords(tcpRecords, &tcpError);
    const bool udpOk = ks::network::EnumerateUdpEndpointRecords(udpRecords, &udpError);

    std::unordered_map<std::uint32_t, CrossViewRow> crossMap;
    snapshot.tcpEndpointRows.reserve(tcpRecords.size());
    for (const ks::network::TcpConnectionRecord& tcpRecord : tcpRecords)
    {
        CrossViewRow& row = crossMap[tcpRecord.processId];
        row.processId = tcpRecord.processId;
        row.processName = QString::fromUtf8(tcpRecord.processName.c_str());
        ++row.tcpCount;
        row.tcpSummary = joinCompactLines({
            row.tcpSummary,
            QStringLiteral("%1:%2 -> %3:%4 (%5)")
            .arg(QString::fromUtf8(tcpRecord.localAddressText.c_str()))
            .arg(tcpRecord.localPort)
            .arg(QString::fromUtf8(tcpRecord.remoteAddressText.c_str()))
            .arg(tcpRecord.remotePort)
            .arg(QString::fromUtf8(tcpRecord.tcpStateText.c_str()))
        });

        TcpEndpointRow endpointRow;
        endpointRow.processId = tcpRecord.processId;
        endpointRow.processName = QString::fromUtf8(tcpRecord.processName.c_str());
        endpointRow.localEndpointText = QStringLiteral("%1:%2")
            .arg(QString::fromUtf8(tcpRecord.localAddressText.c_str()))
            .arg(tcpRecord.localPort);
        endpointRow.remoteEndpointText = QStringLiteral("%1:%2")
            .arg(QString::fromUtf8(tcpRecord.remoteAddressText.c_str()))
            .arg(tcpRecord.remotePort);
        endpointRow.stateText = QString::fromUtf8(tcpRecord.tcpStateText.c_str());
        endpointRow.detailText = QStringLiteral("来源=R3 TCP table；PID=%1；状态=%2")
            .arg(tcpRecord.processId)
            .arg(endpointRow.stateText);
        endpointRow.canTerminate = true;
        endpointRow.connectionRecord = tcpRecord;
        snapshot.tcpEndpointRows.push_back(std::move(endpointRow));
    }
    snapshot.udpEndpointRows.reserve(udpRecords.size());
    for (const ks::network::UdpEndpointRecord& udpRecord : udpRecords)
    {
        CrossViewRow& row = crossMap[udpRecord.processId];
        row.processId = udpRecord.processId;
        row.processName = QString::fromUtf8(udpRecord.processName.c_str());
        ++row.udpCount;
        row.udpSummary = joinCompactLines({
            row.udpSummary,
            QStringLiteral("%1:%2")
            .arg(QString::fromUtf8(udpRecord.localAddressText.c_str()))
            .arg(udpRecord.localPort)
        });

        UdpEndpointRow endpointRow;
        endpointRow.processId = udpRecord.processId;
        endpointRow.processName = QString::fromUtf8(udpRecord.processName.c_str());
        endpointRow.localEndpointText = QStringLiteral("%1:%2")
            .arg(QString::fromUtf8(udpRecord.localAddressText.c_str()))
            .arg(udpRecord.localPort);
        endpointRow.sourceText = QStringLiteral("R3 UDP table");
        endpointRow.detailText = QStringLiteral("来源=R3 UDP endpoint；PID=%1").arg(udpRecord.processId);
        snapshot.udpEndpointRows.push_back(std::move(endpointRow));
    }
    snapshot.crossViewRows.reserve(crossMap.size());
    for (auto& pair : crossMap)
    {
        snapshot.crossViewRows.push_back(pair.second);
    }
    std::sort(snapshot.crossViewRows.begin(), snapshot.crossViewRows.end(), [](const CrossViewRow& left, const CrossViewRow& right)
    {
        if (left.processId != right.processId)
        {
            return left.processId < right.processId;
        }
        return left.processName < right.processName;
    });

    if (crossViewOnly)
    {
        return snapshot;
    }

    // AFD：先基于系统句柄做只读枚举，再筛选 AFD 相关对象。
    ks::file::HandleSnapshotOptions handleOptions;
    handleOptions.resolveObjectName = true;
    handleOptions.nameResolveBudget = 220;
    handleOptions.basicInfoQueryBudget = 220;
    handleOptions.enumMode = ks::file::HandleEnumMode::DuplicateHandle;
    const ks::file::HandleSnapshotResult handleSnapshot = ks::file::BuildHandleSnapshot(handleOptions);
    snapshot.afdRows.reserve(handleSnapshot.rows.size());
    for (const ks::file::HandleSnapshotRow& handleRow : handleSnapshot.rows)
    {
        if (handleRow.objectName.empty())
        {
            continue;
        }
        const QString objectNameText = QString::fromWCharArray(handleRow.objectName.c_str());
        if (!compareContainsAfd(objectNameText))
        {
            continue;
        }

        AfdHandleRow row;
        row.processId = handleRow.processId;
        row.processName = QString::fromWCharArray(handleRow.processName.c_str());
        row.handleValueText = QStringLiteral("0x%1").arg(QString::number(handleRow.handleValue, 16));
        row.typeName = QString::fromWCharArray(handleRow.typeName.c_str());
        row.objectName = objectNameText;
        row.sourceText = QStringLiteral("R3 Handle Snapshot");
        row.diffText = handleRow.diffStatus == ks::file::HandleDiffStatus::NotCompared ? QStringLiteral("未对比") : QStringLiteral("已对比");
        row.accessText = QStringLiteral("0x%1").arg(QString::number(handleRow.grantedAccess, 16));
        row.detailText = QStringLiteral("handleCount=%1 pointerCount=%2")
            .arg(handleRow.handleCount)
            .arg(handleRow.pointerCount);
        snapshot.afdRows.push_back(std::move(row));
    }

    // WFP：动态加载 fwpuclnt.dll，直接枚举 provider / sublayer / callout / filter。
    HANDLE wfpEngineHandle = nullptr;
    QString wfpErrorText;
    if (openWfpEngine(wfpEngineHandle, &wfpErrorText))
    {
        auto& api = wfpApi();
        auto enumProviders = [&snapshot, &api, wfpEngineHandle]()
        {
            HANDLE enumHandle = nullptr;
            FWPM_PROVIDER_ENUM_TEMPLATE0 enumTemplate{};
            if (api.providerCreateEnumHandle(wfpEngineHandle, &enumTemplate, &enumHandle) != ERROR_SUCCESS || enumHandle == nullptr)
            {
                return;
            }

            while (true)
            {
                FWPM_PROVIDER0** entries = nullptr;
                UINT32 count = 0;
                const DWORD status = api.providerEnum(wfpEngineHandle, enumHandle, 128, &entries, &count);
                if (status != ERROR_SUCCESS)
                {
                    break;
                }
                if (entries == nullptr || count == 0)
                {
                    if (entries != nullptr)
                    {
                        api.freeMemory(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 index = 0; index < count; ++index)
                {
                    const FWPM_PROVIDER0* provider = entries[index];
                    if (provider == nullptr)
                    {
                        continue;
                    }
                    WfpProviderRow row;
                    row.nameText = displayDataText(&provider->displayData);
                    row.descriptionText = provider->displayData.description != nullptr ? QString::fromWCharArray(provider->displayData.description) : QString();
                    row.guidText = guidToText(provider->providerKey);
                    row.flagsText = wfpFlagsText(provider->flags);
                    row.serviceNameText = provider->serviceName != nullptr ? QString::fromWCharArray(provider->serviceName) : QString();
                    row.dataSizeText = provider->providerData.size > 0 ? QString::number(provider->providerData.size) : QStringLiteral("0");
                    snapshot.wfpProviderRows.push_back(std::move(row));
                }
                api.freeMemory(reinterpret_cast<void**>(&entries));
                if (snapshot.wfpProviderRows.size() >= 256)
                {
                    break;
                }
            }

            api.providerDestroyEnumHandle(wfpEngineHandle, enumHandle);
        };

        auto enumSubLayers = [&snapshot, &api, wfpEngineHandle]()
        {
            HANDLE enumHandle = nullptr;
            FWPM_SUBLAYER_ENUM_TEMPLATE0 enumTemplate{};
            if (api.subLayerCreateEnumHandle(wfpEngineHandle, &enumTemplate, &enumHandle) != ERROR_SUCCESS || enumHandle == nullptr)
            {
                return;
            }

            while (true)
            {
                FWPM_SUBLAYER0** entries = nullptr;
                UINT32 count = 0;
                const DWORD status = api.subLayerEnum(wfpEngineHandle, enumHandle, 128, &entries, &count);
                if (status != ERROR_SUCCESS)
                {
                    break;
                }
                if (entries == nullptr || count == 0)
                {
                    if (entries != nullptr)
                    {
                        api.freeMemory(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 index = 0; index < count; ++index)
                {
                    const FWPM_SUBLAYER0* subLayer = entries[index];
                    if (subLayer == nullptr)
                    {
                        continue;
                    }
                    WfpSubLayerRow row;
                    row.nameText = displayDataText(&subLayer->displayData);
                    row.descriptionText = subLayer->displayData.description != nullptr ? QString::fromWCharArray(subLayer->displayData.description) : QString();
                    row.guidText = guidToText(subLayer->subLayerKey);
                    row.flagsText = wfpFlagsText(subLayer->flags);
                    row.providerGuidText = subLayer->providerKey != nullptr ? guidToText(*subLayer->providerKey) : QString();
                    row.weightText = QString::number(subLayer->weight);
                    snapshot.wfpSubLayerRows.push_back(std::move(row));
                }
                api.freeMemory(reinterpret_cast<void**>(&entries));
                if (snapshot.wfpSubLayerRows.size() >= 256)
                {
                    break;
                }
            }

            api.subLayerDestroyEnumHandle(wfpEngineHandle, enumHandle);
        };

        auto enumCallouts = [&snapshot, &api, wfpEngineHandle]()
        {
            HANDLE enumHandle = nullptr;
            FWPM_CALLOUT_ENUM_TEMPLATE0 enumTemplate{};
            if (api.calloutCreateEnumHandle(wfpEngineHandle, &enumTemplate, &enumHandle) != ERROR_SUCCESS || enumHandle == nullptr)
            {
                return;
            }

            while (true)
            {
                FWPM_CALLOUT0** entries = nullptr;
                UINT32 count = 0;
                const DWORD status = api.calloutEnum(wfpEngineHandle, enumHandle, 128, &entries, &count);
                if (status != ERROR_SUCCESS)
                {
                    break;
                }
                if (entries == nullptr || count == 0)
                {
                    if (entries != nullptr)
                    {
                        api.freeMemory(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 index = 0; index < count; ++index)
                {
                    const FWPM_CALLOUT0* callout = entries[index];
                    if (callout == nullptr)
                    {
                        continue;
                    }
                    WfpCalloutRow row;
                    row.nameText = displayDataText(&callout->displayData);
                    row.descriptionText = callout->displayData.description != nullptr ? QString::fromWCharArray(callout->displayData.description) : QString();
                    row.guidText = guidToText(callout->calloutKey);
                    row.flagsText = wfpFlagsText(callout->flags);
                    row.providerGuidText = callout->providerKey != nullptr ? guidToText(*callout->providerKey) : QString();
                    row.layerGuidText = guidToText(callout->applicableLayer);
                    row.calloutIdText = QString::number(callout->calloutId);
                    snapshot.wfpCalloutRows.push_back(std::move(row));
                }
                api.freeMemory(reinterpret_cast<void**>(&entries));
                if (snapshot.wfpCalloutRows.size() >= 256)
                {
                    break;
                }
            }

            api.calloutDestroyEnumHandle(wfpEngineHandle, enumHandle);
        };

        auto enumFilters = [&snapshot, &api, wfpEngineHandle]()
        {
            HANDLE enumHandle = nullptr;
            FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate{};
            if (api.filterCreateEnumHandle(wfpEngineHandle, &enumTemplate, &enumHandle) != ERROR_SUCCESS || enumHandle == nullptr)
            {
                return;
            }

            while (true)
            {
                FWPM_FILTER0** entries = nullptr;
                UINT32 count = 0;
                const DWORD status = api.filterEnum(wfpEngineHandle, enumHandle, 128, &entries, &count);
                if (status != ERROR_SUCCESS)
                {
                    break;
                }
                if (entries == nullptr || count == 0)
                {
                    if (entries != nullptr)
                    {
                        api.freeMemory(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 index = 0; index < count; ++index)
                {
                    const FWPM_FILTER0* filter = entries[index];
                    if (filter == nullptr)
                    {
                        continue;
                    }
                    WfpFilterRow row;
                    row.nameText = displayDataText(&filter->displayData);
                    row.descriptionText = filter->displayData.description != nullptr ? QString::fromWCharArray(filter->displayData.description) : QString();
                    row.guidText = guidToText(filter->filterKey);
                    row.flagsText = wfpFlagsText(filter->flags);
                    row.providerGuidText = filter->providerKey != nullptr ? guidToText(*filter->providerKey) : QString();
                    row.layerGuidText = guidToText(filter->layerKey);
                    row.subLayerGuidText = guidToText(filter->subLayerKey);
                    row.weightText = QStringLiteral("type=%1").arg(static_cast<int>(filter->weight.type));
                    row.actionText = QStringLiteral("type=%1").arg(static_cast<int>(filter->action.type));
                    row.conditionText = QStringLiteral("conditions=%1").arg(filter->numFilterConditions);
                    row.filterIdText = QString::number(filter->filterId);
                    snapshot.wfpFilterRows.push_back(std::move(row));
                }
                api.freeMemory(reinterpret_cast<void**>(&entries));
                if (snapshot.wfpFilterRows.size() >= 400)
                {
                    break;
                }
            }

            api.filterDestroyEnumHandle(wfpEngineHandle, enumHandle);
        };

        enumProviders();
        enumSubLayers();
        enumCallouts();
        enumFilters();
        api.engineClose(wfpEngineHandle);
    }
    else
    {
        snapshot.wfpProviderRows.push_back({ QStringLiteral("WFP"), wfpErrorText, QString(), QString(), QString(), QString() });
    }

    QString ndisScript = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "$adapters = Get-NetAdapter | Select-Object -First 200 Name,InterfaceDescription,ifIndex,Status,MacAddress,LinkSpeed; "
        "$bindings = Get-NetAdapterBinding | Select-Object -First 200 Name,DisplayName,ComponentID,Enabled,InstanceID; "
        "$ifaces = Get-NetIPInterface | Select-Object -First 200 InterfaceAlias,ifIndex,AddressFamily,ConnectionState,InterfaceMetric,NlMtu; "
        "[pscustomobject]@{ adapters=$adapters; bindings=$bindings; ifaces=$ifaces } | ConvertTo-Json -Depth 4 -Compress");
    QString ndisErrorText;
    QString ndisJson = runPowerShellTextSync(ndisScript, 12000, &ndisErrorText);
    QJsonParseError parseError{};
    const QJsonDocument ndisDoc = QJsonDocument::fromJson(ndisJson.toUtf8(), &parseError);
    if (parseError.error == QJsonParseError::NoError && ndisDoc.isObject())
    {
        const QJsonArray adaptersArray = normalizeJsonArray(ndisDoc.object().value(QStringLiteral("adapters")));
        for (const QJsonValue& value : adaptersArray)
        {
            const QJsonObject object = value.toObject();
            NdisAdapterRow row;
            row.nameText = object.value(QStringLiteral("Name")).toString();
            row.descriptionText = object.value(QStringLiteral("InterfaceDescription")).toString();
            row.ifIndexText = object.value(QStringLiteral("ifIndex")).toVariant().toString();
            row.statusText = object.value(QStringLiteral("Status")).toString();
            row.macText = object.value(QStringLiteral("MacAddress")).toString();
            row.linkSpeedText = object.value(QStringLiteral("LinkSpeed")).toString();
            row.connectionStateText = QStringLiteral("已枚举");
            snapshot.ndisAdapterRows.push_back(std::move(row));
        }

        const QJsonArray bindingsArray = normalizeJsonArray(ndisDoc.object().value(QStringLiteral("bindings")));
        for (const QJsonValue& value : bindingsArray)
        {
            const QJsonObject object = value.toObject();
            NdisBindingRow row;
            row.adapterNameText = object.value(QStringLiteral("Name")).toString();
            row.displayNameText = object.value(QStringLiteral("DisplayName")).toString();
            row.componentIdText = object.value(QStringLiteral("ComponentID")).toString();
            row.enabledText = object.value(QStringLiteral("Enabled")).toVariant().toString();
            row.instanceIdText = object.value(QStringLiteral("InstanceID")).toString();
            snapshot.ndisBindingRows.push_back(std::move(row));
        }

        const QJsonArray ifacesArray = normalizeJsonArray(ndisDoc.object().value(QStringLiteral("ifaces")));
        for (const QJsonValue& value : ifacesArray)
        {
            const QJsonObject object = value.toObject();
            NdisProtocolRow row;
            row.interfaceAliasText = object.value(QStringLiteral("InterfaceAlias")).toString();
            row.ifIndexText = object.value(QStringLiteral("ifIndex")).toVariant().toString();
            row.addressFamilyText = object.value(QStringLiteral("AddressFamily")).toString();
            row.connectionStateText = object.value(QStringLiteral("ConnectionState")).toString();
            row.interfaceMetricText = object.value(QStringLiteral("InterfaceMetric")).toVariant().toString();
            row.mtuText = object.value(QStringLiteral("NlMtu")).toVariant().toString();
            snapshot.ndisProtocolRows.push_back(std::move(row));
        }
    }
    else
    {
        NdisAdapterRow row;
        row.nameText = QStringLiteral("NDIS");
        row.descriptionText = ndisErrorText;
        snapshot.ndisAdapterRows.push_back(std::move(row));
    }

    // R0 网络审计：
    // - 输入：ArkDriverClient 四个只读 wrapper；
    // - 处理：先采集 ok/unsupported/count/truncated/message 摘要，再把 R0 明细追加到原有表；
    // - 返回：写入 snapshot.r0SummaryRows 与各明细行集合，供 UI 追加展示。
    {
        const ksword::ark::DriverClient driverClient;
        const auto tcpR0 = driverClient.queryNetworkTcpEndpoints();
        const auto udpR0 = driverClient.queryNetworkUdpEndpoints();
        const auto wfpR0 = driverClient.queryNetworkWfpInventory();
        const auto ndisR0 = driverClient.queryNetworkNdisChain();
        snapshot.r0TcpStatusText = r0AuditStatusText(tcpR0);
        snapshot.r0UdpStatusText = r0AuditStatusText(udpR0);

        auto appendR0Summary = [&snapshot](const QString& nameText, const auto& result)
        {
            R0NetworkSummaryRow row;
            row.nameText = nameText;
            row.statusText = r0AuditStatusText(result);
            // returned/total 来自 R0 响应头，parsed 用于提示 ArkDriverClient 实际解析出的行数。
            // 这三个数字并列展示，便于区分“驱动返回数量”和“用户态解析数量”。
            row.countText = QStringLiteral("已解析 %3 行；驱动报告 %1/%2 行")
                .arg(result.returnedCount)
                .arg(result.totalCount)
                .arg(static_cast<qulonglong>(result.entries.size()));
            if (result.partial)
            {
                if (result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                    result.totalCount > result.returnedCount)
                {
                    row.truncatedText =
                        QStringLiteral("是，达到返回预算（仅展示驱动返回子集）");
                }
                else
                {
                    row.truncatedText =
                        static_cast<std::uint32_t>(result.lastStatus) == 0x80000005UL
                        ? QStringLiteral("是，部分结果（达到遍历或缓冲上限，合法行已保留）")
                        : QStringLiteral("部分结果（部分枚举失败，合法行已保留）");
                }
            }
            else
            {
                row.truncatedText =
                    r0AuditTruncatedText(result) == QStringLiteral("true")
                    ? QStringLiteral("是，结果可能未完整返回")
                    : QStringLiteral("否");
            }
            row.messageText = QStringLiteral("%1；protocolStatus=%2；lastStatus=%3；sourceFlags=%4；generation=%5；partial=%6；truncated=%7；retainedRows=%8")
                .arg(ioMessageToText(result.io.message))
                .arg(result.status)
                .arg(r0Hex32(static_cast<std::uint32_t>(result.lastStatus)))
                .arg(r0Hex32(result.sourceFlags))
                .arg(result.generation)
                .arg(result.partial ? QStringLiteral("true") : QStringLiteral("false"))
                .arg(result.truncated ? QStringLiteral("true") : QStringLiteral("false"))
                .arg(static_cast<qulonglong>(result.entries.size()));
            snapshot.r0SummaryRows.push_back(std::move(row));
        };

        appendR0Summary(QStringLiteral("R0 TCP"), tcpR0);
        appendR0Summary(QStringLiteral("R0 UDP"), udpR0);
        appendR0Summary(QStringLiteral("R0 WFP"), wfpR0);
        appendR0Summary(QStringLiteral("R0 NDIS"), ndisR0);

        // R0 明细展开：
        // - 输入：四个 ArkDriverClient wrapper 的 entries；
        // - 处理：把 endpoint/WFP/NDIS 行追加到既有明细表，不替换 R3 枚举结果；
        // - 返回：无，所有文本仅用于只读审计展示。
        auto appendR0Endpoints = [&snapshot](const ksword::ark::NetworkEndpointAuditResult& result, const bool tcpRows)
        {
            const QString completenessText = result.partial || result.truncated
                ? QStringLiteral("部分/截断子集")
                : QStringLiteral("完整结果");
            for (const KSWORD_ARK_NETWORK_ENDPOINT_ROW& entry : result.entries)
            {
                const QString detailText = QStringLiteral("来源=R0 endpoint；快照=%1；rowId=%2；protocol=%3；AF=%4；compartment=%5；ifIndex=%6；flags=%7；sourceFlags=%8；fieldMask=%9；endpointObject=%10；owningProcessObject=%11；transportObject=%12；interfaceLuid=%13")
                    .arg(completenessText)
                    .arg(entry.rowId)
                    .arg(entry.protocol)
                    .arg(entry.addressFamily)
                    .arg(entry.compartmentId)
                    .arg(entry.interfaceIndex)
                    .arg(r0Hex32(entry.flags))
                    .arg(r0Hex32(entry.sourceFlags))
                    .arg(r0Hex32(entry.fieldMask))
                    .arg(r0Hex64(entry.endpointObject))
                    .arg(r0Hex64(entry.owningProcessObject))
                    .arg(r0Hex64(entry.transportObject))
                    .arg(r0Hex64(entry.interfaceLuid));

                if (tcpRows)
                {
                    TcpEndpointRow row;
                    row.processId = entry.owningPid;
                    row.processName = QStringLiteral("R0 PID %1").arg(entry.owningPid);
                    row.localEndpointText = r0EndpointText(entry.addressFamily, entry.localAddress, entry.localPort);
                    row.remoteEndpointText = r0EndpointText(entry.addressFamily, entry.remoteAddress, entry.remotePort);
                    row.stateText = r0TcpStateText(entry.state);
                    row.detailText = detailText;
                    row.isR0Snapshot = true;
                    snapshot.tcpEndpointRows.push_back(std::move(row));
                }
                else
                {
                    UdpEndpointRow row;
                    row.processId = entry.owningPid;
                    row.processName = QStringLiteral("R0 PID %1").arg(entry.owningPid);
                    row.localEndpointText = r0EndpointText(entry.addressFamily, entry.localAddress, entry.localPort);
                    row.sourceText = QStringLiteral("R0 UDP endpoint");
                    row.detailText = detailText;
                    snapshot.udpEndpointRows.push_back(std::move(row));
                }
            }
        };

        auto appendR0WfpRows = [&snapshot](const ksword::ark::NetworkWfpInventoryResult& result)
        {
            const QString completenessText = result.partial || result.truncated
                ? QStringLiteral("部分/截断子集")
                : QStringLiteral("完整结果");
            for (const KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW& entry : result.entries)
            {
                const QString ownerModuleText = fixedNetworkWideText(entry.ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS, QStringLiteral("<owner unknown>"));
                const QString detailText = QStringLiteral("来源=R0 WFP；快照=%1；kind=%2；rowId=%3；flags=%4；fieldMask=%5；layerId=%6；calloutId=%7；object=%8；classify=%9；notify=%10；flowDelete=%11；ownerBase=%12；ownerModule=%13")
                    .arg(completenessText)
                    .arg(r0WfpObjectKindText(entry.objectKind))
                    .arg(entry.rowId)
                    .arg(r0Hex32(entry.flags))
                    .arg(r0Hex32(entry.fieldMask))
                    .arg(entry.layerId)
                    .arg(entry.calloutId)
                    .arg(r0Hex64(entry.objectAddress))
                    .arg(r0Hex64(entry.classifyAddress))
                    .arg(r0Hex64(entry.notifyAddress))
                    .arg(r0Hex64(entry.flowDeleteAddress))
                    .arg(r0Hex64(entry.ownerImageBase))
                    .arg(ownerModuleText);

                if (entry.objectKind == KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER)
                {
                    WfpProviderRow row;
                    row.nameText = QStringLiteral("R0 Provider #%1").arg(entry.rowId);
                    row.descriptionText = detailText;
                    row.guidText = r0GuidText(entry.objectKey);
                    row.flagsText = r0Hex32(entry.flags);
                    row.serviceNameText = ownerModuleText;
                    row.dataSizeText = QStringLiteral("fieldMask=%1").arg(r0Hex32(entry.fieldMask));
                    snapshot.wfpProviderRows.push_back(std::move(row));
                }
                else if (entry.objectKind == KSWORD_ARK_NETWORK_WFP_OBJECT_SUBLAYER)
                {
                    WfpSubLayerRow row;
                    row.nameText = QStringLiteral("R0 Sublayer #%1").arg(entry.rowId);
                    row.descriptionText = detailText;
                    row.guidText = r0GuidText(entry.objectKey);
                    row.flagsText = r0Hex32(entry.flags);
                    row.providerGuidText = r0GuidText(entry.providerKey);
                    row.weightText = QString::number(entry.weight);
                    snapshot.wfpSubLayerRows.push_back(std::move(row));
                }
                else if (entry.objectKind == KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT)
                {
                    WfpCalloutRow row;
                    row.nameText = QStringLiteral("R0 Callout #%1").arg(entry.rowId);
                    row.descriptionText = detailText;
                    row.guidText = r0GuidText(entry.objectKey);
                    row.flagsText = r0Hex32(entry.flags);
                    row.providerGuidText = r0GuidText(entry.providerKey);
                    row.layerGuidText = QStringLiteral("layerId=%1").arg(entry.layerId);
                    row.calloutIdText = QString::number(entry.calloutId);
                    snapshot.wfpCalloutRows.push_back(std::move(row));
                }
                else
                {
                    WfpFilterRow row;
                    row.nameText = QStringLiteral("R0 Filter #%1").arg(entry.rowId);
                    row.descriptionText = detailText;
                    row.guidText = r0GuidText(entry.objectKey);
                    row.flagsText = r0Hex32(entry.flags);
                    row.providerGuidText = r0GuidText(entry.providerKey);
                    row.layerGuidText = QStringLiteral("layerId=%1").arg(entry.layerId);
                    row.subLayerGuidText = r0GuidText(entry.subLayerKey);
                    row.weightText = QString::number(entry.weight);
                    row.actionText = QStringLiteral("calloutId=%1").arg(entry.calloutId);
                    row.conditionText = detailText;
                    row.filterIdText = QString::number(entry.filterId);
                    snapshot.wfpFilterRows.push_back(std::move(row));
                }
            }
        };

        auto appendR0NdisRows = [&snapshot](const ksword::ark::NetworkNdisChainResult& result)
        {
            const QString completenessText = result.partial || result.truncated
                ? QStringLiteral("部分/截断子集")
                : QStringLiteral("完整结果");
            for (const KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW& entry : result.entries)
            {
                const QString componentText = fixedNetworkWideText(entry.componentName, KSWORD_ARK_NETWORK_NAME_CHARS, QStringLiteral("<component unknown>"));
                const QString ownerModuleText = fixedNetworkWideText(entry.ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS, QStringLiteral("<owner unknown>"));
                const QString kindText = r0NdisObjectKindText(entry.objectKind);
                const QString detailText = QStringLiteral("来源=R0 NDIS；快照=%1；kind=%2；rowId=%3；flags=%4；fieldMask=%5；ifIndex=%6；filterOrder=%7；adapterLuid=%8；object=%9；parent=%10；driverObject=%11；imageBase=%12；ownerModule=%13")
                    .arg(completenessText)
                    .arg(kindText)
                    .arg(entry.rowId)
                    .arg(r0Hex32(entry.flags))
                    .arg(r0Hex32(entry.fieldMask))
                    .arg(entry.ifIndex)
                    .arg(entry.filterOrder)
                    .arg(r0Hex64(entry.adapterLuid))
                    .arg(r0Hex64(entry.objectAddress))
                    .arg(r0Hex64(entry.parentObjectAddress))
                    .arg(r0Hex64(entry.driverObject))
                    .arg(r0Hex64(entry.imageBase))
                    .arg(ownerModuleText);

                if (entry.objectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_MINIPORT)
                {
                    NdisAdapterRow row;
                    row.nameText = componentText;
                    row.descriptionText = detailText;
                    row.ifIndexText = QString::number(entry.ifIndex);
                    row.statusText = kindText;
                    row.macText = QStringLiteral("R0");
                    row.linkSpeedText = QStringLiteral("object=%1").arg(r0Hex64(entry.objectAddress));
                    row.connectionStateText = ownerModuleText;
                    snapshot.ndisAdapterRows.push_back(std::move(row));
                }
                else if (entry.objectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_PROTOCOL)
                {
                    NdisProtocolRow row;
                    row.interfaceAliasText = componentText;
                    row.ifIndexText = QString::number(entry.ifIndex);
                    row.addressFamilyText = kindText;
                    row.connectionStateText = ownerModuleText;
                    row.interfaceMetricText = QStringLiteral("flags=%1").arg(r0Hex32(entry.flags));
                    row.mtuText = detailText;
                    snapshot.ndisProtocolRows.push_back(std::move(row));
                }
                else if (
                    entry.objectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_FILTER ||
                    entry.objectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_BINDING)
                {
                    NdisBindingRow row;
                    row.adapterNameText = componentText;
                    row.displayNameText = kindText;
                    row.componentIdText = ownerModuleText;
                    row.enabledText = QStringLiteral("flags=%1").arg(r0Hex32(entry.flags));
                    row.instanceIdText = detailText;
                    snapshot.ndisBindingRows.push_back(std::move(row));
                }
                else
                {
                    NdisUnknownRow row;
                    row.kindText = QStringLiteral("未知/未证明（kind=%1）")
                        .arg(entry.objectKind);
                    row.componentText = componentText;
                    row.ownerModuleText = ownerModuleText;
                    row.objectAddressText = r0Hex64(entry.objectAddress);
                    row.detailText = detailText;
                    snapshot.ndisUnknownRows.push_back(std::move(row));
                }
            }
        };

        appendR0Endpoints(tcpR0, true);
        appendR0Endpoints(udpR0, false);
        appendR0WfpRows(wfpR0);
        appendR0NdisRows(ndisR0);
    }

    snapshot.nsiSummaryRows = {
        { QStringLiteral("TCP 条目"), QString::number(tcpRecords.size()) },
        { QStringLiteral("UDP 端点"), QString::number(udpRecords.size()) },
        { QStringLiteral("AFD 候选句柄"), QString::number(snapshot.afdRows.size()) },
        { QStringLiteral("WFP Provider"), QString::number(snapshot.wfpProviderRows.size()) },
        { QStringLiteral("NDIS Adapter"), QString::number(snapshot.ndisAdapterRows.size()) }
    };

    snapshot.statusText = QStringLiteral("完成：TCP=%1, UDP=%2, AFD=%3, WFP=%4, NDIS=%5")
        .arg(tcpRecords.size())
        .arg(udpRecords.size())
        .arg(snapshot.afdRows.size())
        .arg(snapshot.wfpProviderRows.size())
        .arg(snapshot.ndisAdapterRows.size());
    snapshot.detailText = QStringLiteral("TCP:%1 | UDP:%2")
        .arg(tcpOk ? QStringLiteral("ok") : QString::fromUtf8(tcpError.c_str()))
        .arg(udpOk ? QStringLiteral("ok") : QString::fromUtf8(udpError.c_str()));
    for (const R0NetworkSummaryRow& row : snapshot.r0SummaryRows)
    {
        snapshot.detailText += QStringLiteral(" | %1：%2，%3，截断：%4，说明：%5")
            .arg(row.nameText)
            .arg(row.statusText)
            .arg(row.countText)
            .arg(row.truncatedText)
            .arg(row.messageText);
    }

    return snapshot;
}

void NetworkAuditPage::applySnapshot(const AuditSnapshot& snapshot)
{
    // 完整审计会重建多个关联表格；任一右键菜单打开时必须整体延后提交，
    // 否则同一快照只更新部分表格，也可能让菜单行号指向下一轮数据。
    const QPointer<NetworkAuditPage> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-audit-full-snapshot"),
        {
            m_tcpTable,
            m_udpTable,
            m_crossSummaryTable,
            m_afdTable,
            m_wfpProviderTable,
            m_wfpSubLayerTable,
            m_wfpCalloutTable,
            m_wfpFilterTable,
            m_ndisAdapterTable,
            m_ndisBindingTable,
            m_ndisProtocolTable,
            m_nsiSummaryTable
        },
        [safeThis, snapshot]()
        {
            if (!safeThis.isNull())
            {
                safeThis->applySnapshot(snapshot);
            }
        }))
    {
        return;
    }

    refreshCrossViewTable(snapshot);
    refreshAfdTable(snapshot.afdRows);
    refreshWfpTables(snapshot);
    refreshNdisTables(snapshot);
    refreshNsiSummaryTable(snapshot);

    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(snapshot.statusText);
        m_statusLabel->setToolTip(snapshot.detailText);
    }
}

void NetworkAuditPage::refreshCrossViewTable(const AuditSnapshot& snapshot)
{
    // 高频 TCP/UDP 自动刷新只重建交叉视图三表；菜单打开期间合并为最新快照。
    const QPointer<NetworkAuditPage> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-audit-cross-view"),
        { m_tcpTable, m_udpTable, m_crossSummaryTable },
        [safeThis, snapshot]()
        {
            if (!safeThis.isNull())
            {
                safeThis->refreshCrossViewTable(snapshot);
            }
        }))
    {
        return;
    }

    m_tcpEndpointCache = snapshot.tcpEndpointRows;
    m_udpEndpointCache = snapshot.udpEndpointRows;
    if (!snapshot.r0TcpStatusText.isEmpty())
    {
        m_r0TcpStatusText = snapshot.r0TcpStatusText;
    }
    if (!snapshot.r0UdpStatusText.isEmpty())
    {
        m_r0UdpStatusText = snapshot.r0UdpStatusText;
    }

    // Cross-View 必须按来源重新聚合当前缓存。完整刷新提供 R0 行，高频刷新替换
    // R3 行并保留最近一次 R0 行；在这里重算可以避免自动刷新后汇总表退化成 R3-only。
    struct CrossViewAggregate
    {
        CrossViewRow row;
        std::size_t tcpR0Count = 0U;
        std::size_t udpR0Count = 0U;
        QString tcpR0Summary;
        QString udpR0Summary;
    };
    std::unordered_map<std::uint32_t, CrossViewAggregate> crossMap;
    for (const TcpEndpointRow& endpointRow : m_tcpEndpointCache)
    {
        CrossViewAggregate& aggregate = crossMap[endpointRow.processId];
        aggregate.row.processId = endpointRow.processId;
        if (!endpointRow.isR0Snapshot || aggregate.row.processName.isEmpty())
        {
            aggregate.row.processName = endpointRow.processName;
        }
        const QString endpointSummary = QStringLiteral("%1 -> %2 (%3)")
            .arg(endpointRow.localEndpointText)
            .arg(endpointRow.remoteEndpointText)
            .arg(endpointRow.stateText);
        if (endpointRow.isR0Snapshot)
        {
            ++aggregate.tcpR0Count;
            aggregate.tcpR0Summary = joinCompactLines({ aggregate.tcpR0Summary, endpointSummary });
        }
        else
        {
            ++aggregate.row.tcpCount;
            aggregate.row.tcpSummary = joinCompactLines({ aggregate.row.tcpSummary, endpointSummary });
        }
    }
    for (const UdpEndpointRow& endpointRow : m_udpEndpointCache)
    {
        CrossViewAggregate& aggregate = crossMap[endpointRow.processId];
        aggregate.row.processId = endpointRow.processId;
        const bool isR0Snapshot = endpointRow.sourceText.startsWith(QStringLiteral("R0"));
        if (!isR0Snapshot || aggregate.row.processName.isEmpty())
        {
            aggregate.row.processName = endpointRow.processName;
        }
        if (isR0Snapshot)
        {
            ++aggregate.udpR0Count;
            aggregate.udpR0Summary = joinCompactLines({ aggregate.udpR0Summary, endpointRow.localEndpointText });
        }
        else
        {
            ++aggregate.row.udpCount;
            aggregate.row.udpSummary = joinCompactLines({ aggregate.row.udpSummary, endpointRow.localEndpointText });
        }
    }
    std::vector<CrossViewAggregate> effectiveCrossRows;
    effectiveCrossRows.reserve(crossMap.size());
    for (auto& pair : crossMap)
    {
        effectiveCrossRows.push_back(std::move(pair.second));
    }
    std::sort(effectiveCrossRows.begin(), effectiveCrossRows.end(), [](const CrossViewAggregate& left, const CrossViewAggregate& right)
    {
        if (left.row.processId != right.row.processId)
        {
            return left.row.processId < right.row.processId;
        }
        return left.row.processName < right.row.processName;
    });

    if (m_tcpTable != nullptr)
    {
        m_tcpTable->setRowCount(0);
        for (std::size_t cacheIndex = 0; cacheIndex < m_tcpEndpointCache.size(); ++cacheIndex)
        {
            const TcpEndpointRow& row = m_tcpEndpointCache[cacheIndex];
            if (!m_processFilterSet.isEmpty()
                && !m_processFilterSet.contains(static_cast<quint32>(row.processId)))
            {
                continue;
            }

            const int rowIndex = m_tcpTable->rowCount();
            m_tcpTable->insertRow(rowIndex);
            QTableWidgetItem* pidItem = createReadOnlyCell(QString::number(row.processId));
            pidItem->setData(Qt::UserRole, static_cast<qulonglong>(cacheIndex));
            m_tcpTable->setItem(rowIndex, 0, pidItem);
            QTableWidgetItem* processItem = createReadOnlyCell(row.processName);
            processItem->setIcon(resolveProcessIcon(row.processId));
            m_tcpTable->setItem(rowIndex, 1, processItem);
            m_tcpTable->setItem(rowIndex, 2, createReadOnlyCell(row.localEndpointText));
            m_tcpTable->setItem(rowIndex, 3, createReadOnlyCell(row.remoteEndpointText));
            m_tcpTable->setItem(rowIndex, 4, createReadOnlyCell(row.stateText));
            m_tcpTable->setItem(rowIndex, 5, createReadOnlyCell(row.detailText));
        }
    }

    if (m_udpTable != nullptr)
    {
        m_udpTable->setRowCount(0);
        for (const UdpEndpointRow& row : snapshot.udpEndpointRows)
        {
            if (!m_processFilterSet.isEmpty()
                && !m_processFilterSet.contains(static_cast<quint32>(row.processId)))
            {
                continue;
            }

            const int rowIndex = m_udpTable->rowCount();
            m_udpTable->insertRow(rowIndex);
            m_udpTable->setItem(rowIndex, 0, createReadOnlyCell(QString::number(row.processId)));
            QTableWidgetItem* processItem = createReadOnlyCell(row.processName);
            processItem->setIcon(resolveProcessIcon(row.processId));
            m_udpTable->setItem(rowIndex, 1, processItem);
            m_udpTable->setItem(rowIndex, 2, createReadOnlyCell(row.localEndpointText));
            m_udpTable->setItem(rowIndex, 3, createReadOnlyCell(row.sourceText));
            m_udpTable->setItem(rowIndex, 4, createReadOnlyCell(row.detailText));
        }
    }

    if (m_crossSummaryTable != nullptr)
    {
        m_crossSummaryTable->setRowCount(0);
        for (const CrossViewAggregate& aggregate : effectiveCrossRows)
        {
            const CrossViewRow& row = aggregate.row;
            if (!m_processFilterSet.isEmpty()
                && !m_processFilterSet.contains(static_cast<quint32>(row.processId)))
            {
                continue;
            }

            const int rowIndex = m_crossSummaryTable->rowCount();
            m_crossSummaryTable->insertRow(rowIndex);
            m_crossSummaryTable->setItem(rowIndex, 0, createReadOnlyCell(QString::number(row.processId)));
            QTableWidgetItem* processItem = createReadOnlyCell(row.processName);
            processItem->setIcon(resolveProcessIcon(row.processId));
            m_crossSummaryTable->setItem(rowIndex, 1, processItem);
            const auto r0CountText = [](const std::size_t count, const QString& statusText)
            {
                if (statusText == QStringLiteral("ok"))
                {
                    return QString::number(static_cast<qulonglong>(count));
                }
                if (count != 0U)
                {
                    return QStringLiteral("%1:%2")
                        .arg(statusText.isEmpty() ? QStringLiteral("?") : statusText)
                        .arg(static_cast<qulonglong>(count));
                }
                return statusText.isEmpty() ? QStringLiteral("?") : statusText;
            };
            m_crossSummaryTable->setItem(rowIndex, 2, createReadOnlyCell(
                QStringLiteral("R3:%1 / R0:%2")
                .arg(static_cast<qulonglong>(row.tcpCount))
                .arg(r0CountText(aggregate.tcpR0Count, m_r0TcpStatusText))));
            m_crossSummaryTable->setItem(rowIndex, 3, createReadOnlyCell(
                QStringLiteral("R3:%1 / R0:%2")
                .arg(static_cast<qulonglong>(row.udpCount))
                .arg(r0CountText(aggregate.udpR0Count, m_r0UdpStatusText))));
            m_crossSummaryTable->setItem(rowIndex, 4, createReadOnlyCell(
                QStringLiteral("R3 TCP: %1 | R0 TCP: %2 | R3 UDP: %3 | R0 UDP: %4")
                .arg(row.tcpSummary.isEmpty() ? QStringLiteral("<无>") : row.tcpSummary)
                .arg(aggregate.tcpR0Summary.isEmpty() ? QStringLiteral("<无>") : aggregate.tcpR0Summary)
                .arg(row.udpSummary.isEmpty() ? QStringLiteral("<无>") : row.udpSummary)
                .arg(aggregate.udpR0Summary.isEmpty() ? QStringLiteral("<无>") : aggregate.udpR0Summary)));
        }
    }
    updateCrossViewActionState();
}

QIcon NetworkAuditPage::resolveProcessIcon(const std::uint32_t processId)
{
    if (processId == 0U)
    {
        return auditProcessPlaceholderIcon();
    }

    const quint32 processIdKey = static_cast<quint32>(processId);
    const auto cachedIterator = m_processIconCache.constFind(processIdKey);
    if (cachedIterator != m_processIconCache.constEnd())
    {
        return cachedIterator.value();
    }

    // 建表链路只允许做缓存查询：首屏有连接的进程常有上百个，
    // 逐个 OpenProcess + Shell 图标提取会把整段建表拖到秒级。
    scheduleProcessIconResolution(processId);
    return auditProcessPlaceholderIcon();
}

void NetworkAuditPage::scheduleProcessIconResolution(const std::uint32_t processId)
{
    const quint32 processIdKey = static_cast<quint32>(processId);
    if (processIdKey == 0U ||
        m_processIconCache.contains(processIdKey) ||
        m_processIconPendingPidSet.contains(processIdKey))
    {
        return;
    }
    m_processIconPendingPidSet.insert(processIdKey);

    // 复用本页既有的“共享状态 + owner 复核”回投模式：
    // 页面析构时 owner 已置空，工作线程不会向已销毁的 QWidget 投递调用。
    const std::shared_ptr<NetworkAuditAsyncState> asyncState = m_asyncState;
    QThreadPool::globalInstance()->start([asyncState, processIdKey]()
        {
            QImage processIconImage = extractProcessIconImageForPid(processIdKey);

            std::lock_guard<std::mutex> dispatchLock(asyncState->mutex);
            NetworkAuditPage* const receiver = asyncState->owner;
            if (receiver == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                receiver,
                [asyncState, processIdKey, processIconImage = std::move(processIconImage)]() mutable
                {
                    NetworkAuditPage* page = nullptr;
                    {
                        std::lock_guard<std::mutex> stateLock(asyncState->mutex);
                        page = asyncState->owner;
                    }
                    if (page == nullptr)
                    {
                        return;
                    }
                    page->applyProcessIconResolutionResult(processIdKey, std::move(processIconImage));
                },
                Qt::QueuedConnection);
        });
}

void NetworkAuditPage::applyProcessIconResolutionResult(
    const std::uint32_t processId,
    QImage iconImage)
{
    const quint32 processIdKey = static_cast<quint32>(processId);
    m_processIconPendingPidSet.remove(processIdKey);

    // QPixmap/QIcon 只能在 UI 线程构造；解析失败也写入缓存，避免同一 PID 反复冷查。
    const QIcon resolvedIcon = iconImage.isNull()
        ? auditProcessPlaceholderIcon()
        : QIcon(QPixmap::fromImage(iconImage));
    m_processIconCache.insert(processIdKey, resolvedIcon);

    // 三张表的 PID 都在第 0 列、进程名都在第 1 列，直接按文本回补已落表的行。
    applyResolvedIconToAuditTableRows(m_tcpTable, processIdKey, resolvedIcon);
    applyResolvedIconToAuditTableRows(m_udpTable, processIdKey, resolvedIcon);
    applyResolvedIconToAuditTableRows(m_crossSummaryTable, processIdKey, resolvedIcon);
}

void NetworkAuditPage::updateCrossViewActionState()
{
    bool canTerminateSelection = false;
    if (m_tcpTable != nullptr && m_tcpTable->currentRow() >= 0)
    {
        const QTableWidgetItem* pidItem = m_tcpTable->item(m_tcpTable->currentRow(), 0);
        bool cacheIndexOk = false;
        const qulonglong cacheIndexValue = pidItem != nullptr
            ? pidItem->data(Qt::UserRole).toULongLong(&cacheIndexOk)
            : 0ULL;
        canTerminateSelection =
            cacheIndexOk
            && cacheIndexValue < m_tcpEndpointCache.size()
            && m_tcpEndpointCache[static_cast<std::size_t>(cacheIndexValue)].canTerminate;
    }
    if (m_crossTerminateButton != nullptr)
    {
        m_crossTerminateButton->setEnabled(canTerminateSelection);
    }
    if (m_clearProcessFilterButton != nullptr)
    {
        m_clearProcessFilterButton->setEnabled(!m_processFilterSet.isEmpty());
    }
}

void NetworkAuditPage::terminateSelectedTcpConnection()
{
    if (m_tcpTable == nullptr || m_tcpTable->currentRow() < 0)
    {
        QMessageBox::information(this, QStringLiteral("网络审计"), QStringLiteral("请先选中一条 TCP 连接。"));
        return;
    }

    const QTableWidgetItem* pidItem = m_tcpTable->item(m_tcpTable->currentRow(), 0);
    bool cacheIndexOk = false;
    const qulonglong cacheIndexValue = pidItem != nullptr
        ? pidItem->data(Qt::UserRole).toULongLong(&cacheIndexOk)
        : 0ULL;
    if (!cacheIndexOk || cacheIndexValue >= m_tcpEndpointCache.size())
    {
        QMessageBox::warning(this, QStringLiteral("网络审计"), QStringLiteral("所选连接已过期，请刷新后重试。"));
        return;
    }

    const TcpEndpointRow endpointRow = m_tcpEndpointCache[static_cast<std::size_t>(cacheIndexValue)];
    if (!endpointRow.canTerminate)
    {
        QMessageBox::information(
            this,
            QStringLiteral("网络审计"),
            QStringLiteral("该行来自 R0 只读快照；请选中对应的 R3 TCP 行执行终止。"));
        return;
    }

    const std::string unsupportedReason =
        ks::network::GetTcpTerminationUnsupportedReason(endpointRow.connectionRecord);
    if (!unsupportedReason.empty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("网络审计"),
            QStringLiteral("当前 TCP 行不能终止：%1")
                .arg(QString::fromUtf8(unsupportedReason.c_str())));
        return;
    }

    const int confirmation = QMessageBox::question(
        this,
        QStringLiteral("终止 TCP 连接"),
        QStringLiteral("确认终止连接？\nPID=%1\n本地=%2\n远端=%3")
            .arg(endpointRow.processId)
            .arg(endpointRow.localEndpointText)
            .arg(endpointRow.remoteEndpointText),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmation != QMessageBox::Yes)
    {
        return;
    }

    std::string detailText;
    const bool terminateOk =
        ks::network::TerminateTcpConnectionByRecord(endpointRow.connectionRecord, &detailText);
    if (terminateOk)
    {
        QMessageBox::information(this, QStringLiteral("网络审计"), QStringLiteral("连接终止请求已提交。"));
        refreshAllSnapshotsAsync(true);
        return;
    }

    const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
        this,
        QStringLiteral("终止 TCP 连接"),
        QString::fromUtf8(detailText.c_str()));
    if (!privilegePromptHandled)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("网络审计"),
            QStringLiteral("终止连接失败：%1").arg(QString::fromUtf8(detailText.c_str())));
    }
}

void NetworkAuditPage::showCrossViewContextMenu(
    QTableWidget* tableWidget,
    const QPoint& localPosition)
{
    if (tableWidget == nullptr)
    {
        return;
    }

    const QModelIndex clickedIndex = tableWidget->indexAt(localPosition);
    if (clickedIndex.isValid())
    {
        tableWidget->setCurrentCell(clickedIndex.row(), clickedIndex.column());
        tableWidget->selectRow(clickedIndex.row());
    }

    const int selectedRow = tableWidget->currentRow();
    bool processIdOk = false;
    const QTableWidgetItem* processIdItem =
        selectedRow >= 0 ? tableWidget->item(selectedRow, 0) : nullptr;
    const quint32 selectedProcessId = processIdItem != nullptr
        ? processIdItem->text().toUInt(&processIdOk)
        : 0U;
    const bool hasProcess = processIdOk && selectedProcessId != 0U;

    bool canTerminateSelection = false;
    if (tableWidget == m_tcpTable && processIdItem != nullptr)
    {
        bool cacheIndexOk = false;
        const qulonglong cacheIndexValue =
            processIdItem->data(Qt::UserRole).toULongLong(&cacheIndexOk);
        canTerminateSelection =
            cacheIndexOk
            && cacheIndexValue < m_tcpEndpointCache.size()
            && m_tcpEndpointCache[static_cast<std::size_t>(cacheIndexValue)].canTerminate;
    }

    QMenu menu(tableWidget);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* terminateAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
        QStringLiteral("终止此 TCP 连接"));
    terminateAction->setVisible(tableWidget == m_tcpTable);
    terminateAction->setEnabled(canTerminateSelection);
    QAction* copyAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制行"));
    copyAction->setEnabled(selectedRow >= 0);
    QAction* trackProcessAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_track.svg")),
        QStringLiteral("跟踪此进程"));
    trackProcessAction->setEnabled(hasProcess && static_cast<bool>(m_trackProcessHandler));
    QAction* openProcessDetailAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("转到进程详细信息"));
    openProcessDetailAction->setEnabled(
        hasProcess && static_cast<bool>(m_openProcessDetailHandler));
    const QTableWidgetItem* localEndpointItem = selectedRow >= 0
        ? tableWidget->item(selectedRow, 2)
        : nullptr;
    const bool canPrefillUdpBlockRule =
        tableWidget == m_udpTable &&
        localEndpointItem != nullptr &&
        !localEndpointItem->text().trimmed().isEmpty() &&
        static_cast<bool>(m_udpEndpointBlockRuleHandler);
    QAction* addUdpBlockRuleAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
        QStringLiteral("预填 UDP 阻断规则"));
    addUdpBlockRuleAction->setVisible(tableWidget == m_udpTable);
    addUdpBlockRuleAction->setEnabled(canPrefillUdpBlockRule);
    const bool isTcpTable = tableWidget == m_tcpTable;
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [isTcpTable, selectedProcessId, hasProcess]() -> ks::online_scan::SandboxUploadTarget
        {
            ks::online_scan::SandboxUploadTarget uploadTarget;
            if (!hasProcess)
            {
                uploadTarget.errorText = isTcpTable
                    ? QStringLiteral("当前 TCP 行没有可解析 PID。")
                    : QStringLiteral("当前 UDP 行没有可解析 PID。");
                return uploadTarget;
            }
            uploadTarget.filePath = QString::fromStdString(
                ks::process::QueryProcessPathByPid(selectedProcessId));
            uploadTarget.sourceText = isTcpTable
                ? QStringLiteral("网络 TCP 连接 PID=%1").arg(selectedProcessId)
                : QStringLiteral("网络 UDP 端点 PID=%1").arg(selectedProcessId);
            return uploadTarget;
        });
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(hasProcess);
    }
    menu.addSeparator();
    QAction* refreshAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
        QStringLiteral("刷新 TCP/UDP"));
    QAction* clearFilterAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_clear.svg")),
        QStringLiteral("清除 PID 筛选"));
    clearFilterAction->setEnabled(!m_processFilterSet.isEmpty());

    const QAction* selectedAction = menu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
    if (selectedAction == terminateAction)
    {
        terminateSelectedTcpConnection();
    }
    else if (selectedAction == copyAction)
    {
        copyCurrentTableRow(tableWidget);
    }
    else if (selectedAction == trackProcessAction)
    {
        m_trackProcessHandler(selectedProcessId);
    }
    else if (selectedAction == openProcessDetailAction)
    {
        m_openProcessDetailHandler(selectedProcessId);
    }
    else if (selectedAction == addUdpBlockRuleAction && canPrefillUdpBlockRule)
    {
        m_udpEndpointBlockRuleHandler(selectedProcessId, localEndpointItem->text());
    }
    else if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    else if (selectedAction == refreshAction)
    {
        refreshAllSnapshotsAsync(true);
    }
    else if (selectedAction == clearFilterAction)
    {
        focusProcessIds({});
    }
}

void NetworkAuditPage::refreshAfdTable(const std::vector<AfdHandleRow>& snapshot)
{
    if (m_afdTable == nullptr)
    {
        return;
    }
    m_afdTable->setRowCount(static_cast<int>(snapshot.size()));
    int rowIndex = 0;
    for (const AfdHandleRow& row : snapshot)
    {
        m_afdTable->setItem(rowIndex, 0, createReadOnlyCell(QString::number(row.processId)));
        m_afdTable->setItem(rowIndex, 1, createReadOnlyCell(row.processName));
        m_afdTable->setItem(rowIndex, 2, createReadOnlyCell(row.handleValueText));
        m_afdTable->setItem(rowIndex, 3, createReadOnlyCell(row.typeName));
        m_afdTable->setItem(rowIndex, 4, createReadOnlyCell(row.objectName));
        m_afdTable->setItem(rowIndex, 5, createReadOnlyCell(row.sourceText));
        m_afdTable->setItem(rowIndex, 6, createReadOnlyCell(row.diffText));
        m_afdTable->setItem(rowIndex, 7, createReadOnlyCell(row.detailText + QStringLiteral(" | access=") + row.accessText));
        ++rowIndex;
    }
}

void NetworkAuditPage::refreshWfpTables(const AuditSnapshot& snapshot)
{
    auto fillTable = [](QTableWidget* tableWidget, const auto& rows, const auto& writer)
    {
        if (tableWidget == nullptr)
        {
            return;
        }
        tableWidget->setRowCount(static_cast<int>(rows.size()));
        int rowIndex = 0;
        for (const auto& row : rows)
        {
            writer(tableWidget, rowIndex, row);
            ++rowIndex;
        }
    };

    fillTable(m_wfpProviderTable, snapshot.wfpProviderRows, [](QTableWidget* tableWidget, int rowIndex, const WfpProviderRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.descriptionText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.guidText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.flagsText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.serviceNameText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.dataSizeText));
    });

    fillTable(m_wfpSubLayerTable, snapshot.wfpSubLayerRows, [](QTableWidget* tableWidget, int rowIndex, const WfpSubLayerRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.descriptionText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.guidText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.flagsText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.providerGuidText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.weightText));
    });

    fillTable(m_wfpCalloutTable, snapshot.wfpCalloutRows, [](QTableWidget* tableWidget, int rowIndex, const WfpCalloutRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.descriptionText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.guidText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.flagsText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.providerGuidText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.layerGuidText));
        tableWidget->setItem(rowIndex, 6, createReadOnlyCell(row.calloutIdText));
    });

    fillTable(m_wfpFilterTable, snapshot.wfpFilterRows, [](QTableWidget* tableWidget, int rowIndex, const WfpFilterRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.descriptionText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.guidText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.flagsText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.providerGuidText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.layerGuidText));
        tableWidget->setItem(rowIndex, 6, createReadOnlyCell(row.subLayerGuidText));
        tableWidget->setItem(rowIndex, 7, createReadOnlyCell(row.weightText));
        tableWidget->setItem(rowIndex, 8, createReadOnlyCell(row.actionText));
        tableWidget->setItem(rowIndex, 9, createReadOnlyCell(row.conditionText));
        tableWidget->setItem(rowIndex, 10, createReadOnlyCell(row.filterIdText));
    });
}

void NetworkAuditPage::refreshNdisTables(const AuditSnapshot& snapshot)
{
    auto fillTable = [](QTableWidget* tableWidget, const auto& rows, const auto& writer)
    {
        if (tableWidget == nullptr)
        {
            return;
        }
        tableWidget->setRowCount(static_cast<int>(rows.size()));
        int rowIndex = 0;
        for (const auto& row : rows)
        {
            writer(tableWidget, rowIndex, row);
            ++rowIndex;
        }
    };

    fillTable(m_ndisAdapterTable, snapshot.ndisAdapterRows, [](QTableWidget* tableWidget, int rowIndex, const NdisAdapterRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.descriptionText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.ifIndexText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.statusText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.macText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.linkSpeedText));
        tableWidget->setItem(rowIndex, 6, createReadOnlyCell(row.connectionStateText));
    });

    fillTable(m_ndisBindingTable, snapshot.ndisBindingRows, [](QTableWidget* tableWidget, int rowIndex, const NdisBindingRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.adapterNameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.displayNameText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.componentIdText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.enabledText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.instanceIdText));
    });

    fillTable(m_ndisProtocolTable, snapshot.ndisProtocolRows, [](QTableWidget* tableWidget, int rowIndex, const NdisProtocolRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.interfaceAliasText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.ifIndexText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.addressFamilyText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.connectionStateText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.interfaceMetricText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.mtuText));
    });

    fillTable(m_ndisUnknownTable, snapshot.ndisUnknownRows, [](QTableWidget* tableWidget, int rowIndex, const NdisUnknownRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.kindText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.componentText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.ownerModuleText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.objectAddressText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.detailText));
    });
}

void NetworkAuditPage::refreshNsiSummaryTable(const AuditSnapshot& snapshot)
{
    if (m_nsiSummaryTable == nullptr)
    {
        return;
    }
    const int r3RowCount = static_cast<int>(snapshot.nsiSummaryRows.size());
    const int r0RowCount = static_cast<int>(snapshot.r0SummaryRows.size());
    m_nsiSummaryTable->setRowCount(r3RowCount + r0RowCount);
    int rowIndex = 0;
    for (const NsiSummaryRow& row : snapshot.nsiSummaryRows)
    {
        m_nsiSummaryTable->setItem(rowIndex, 0, createReadOnlyCell(row.metricText));
        m_nsiSummaryTable->setItem(rowIndex, 1, createReadOnlyCell(row.valueText));
        m_nsiSummaryTable->setItem(rowIndex, 2, createReadOnlyCell(QStringLiteral("-")));
        m_nsiSummaryTable->setItem(rowIndex, 3, createReadOnlyCell(QStringLiteral("-")));
        m_nsiSummaryTable->setItem(rowIndex, 4, createReadOnlyCell(QStringLiteral("R3 summary")));
        ++rowIndex;
    }
    for (const R0NetworkSummaryRow& row : snapshot.r0SummaryRows)
    {
        m_nsiSummaryTable->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        m_nsiSummaryTable->setItem(rowIndex, 1, createReadOnlyCell(row.statusText));
        m_nsiSummaryTable->setItem(rowIndex, 2, createReadOnlyCell(row.countText));
        m_nsiSummaryTable->setItem(rowIndex, 3, createReadOnlyCell(row.truncatedText));
        m_nsiSummaryTable->setItem(rowIndex, 4, createReadOnlyCell(row.messageText));
        ++rowIndex;
    }
}

QString NetworkAuditPage::runPowerShellTextSync(const QString& scriptText, const int timeoutMs, QString* errorTextOut)
{
    QProcess process;
    process.setProgram(QStringLiteral("powershell.exe"));
    process.setArguments({
        QStringLiteral("-NoProfile"),
        QStringLiteral("-ExecutionPolicy"),
        QStringLiteral("Bypass"),
        QStringLiteral("-Command"),
        scriptText
    });
    process.start();

    if (!process.waitForStarted(2000))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("PowerShell 启动失败：%1").arg(process.errorString());
        }
        return QString();
    }

    if (!process.waitForFinished(timeoutMs))
    {
        process.kill();
        process.waitForFinished(500);
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("PowerShell 执行超时：%1 ms").arg(timeoutMs);
        }
        return QString();
    }

    const QString stdoutText = QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
    const QString stderrText = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("PowerShell 退出异常：%1 / %2").arg(process.exitCode()).arg(stderrText);
        }
        return stdoutText;
    }
    return stdoutText;
}

QTableWidgetItem* NetworkAuditPage::createCell(const QString& cellText)
{
    return createReadOnlyCell(cellText);
}

QString NetworkAuditPage::guidToText(const GUID& guid)
{
    return QStringLiteral("{%1-%2-%3-%4%5%6%7%8%9%10%11}")
        .arg(guid.Data1, 8, 16, QLatin1Char('0'))
        .arg(guid.Data2, 4, 16, QLatin1Char('0'))
        .arg(guid.Data3, 4, 16, QLatin1Char('0'))
        .arg(guid.Data4[0], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[1], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[2], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[3], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[4], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[5], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[6], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[7], 2, 16, QLatin1Char('0'));
}

QString NetworkAuditPage::bytesToHexText(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(QString::number(value, 16));
}

QString NetworkAuditPage::objectToText(const QJsonValue& value)
{
    if (value.isString())
    {
        return value.toString();
    }
    if (value.isBool())
    {
        return value.toBool() ? QStringLiteral("true") : QStringLiteral("false");
    }
    if (value.isDouble())
    {
        return QString::number(value.toDouble());
    }
    if (value.isArray() || value.isObject())
    {
        if (value.isObject())
        {
            return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact));
        }
        return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Compact));
    }
    return QString();
}

bool NetworkAuditPage::compareContainsAfd(const QString& objectNameText)
{
    const QString lowered = objectNameText.toLower();
    return lowered.contains(QStringLiteral("\\device\\afd")) || lowered.contains(QStringLiteral("\\device\\winsock"));
}
