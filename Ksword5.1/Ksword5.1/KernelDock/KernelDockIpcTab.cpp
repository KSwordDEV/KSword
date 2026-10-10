#include "../UI/StructuredFieldView.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "KernelDockIpcTab.h"
#include "KernelDock.h"
#include "../UI/VisibleTableWidget.h"

// ============================================================
// KernelDockIpcTab.cpp
// 作用说明：
// 1) 聚合 NamedPipe、ALPC 和通信对象枚举的只读页面；
// 2) ALPC 页面通过 DriverClient::queryAlpcPort 查询单个端口关系；
// 3) NamedPipe 与通信对象页复用现有独立只读组件。
// ============================================================

#include "KernelCommunicationEndpointTab.h"
#include "KernelNamedPipeTab.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/TableInteractionSupport.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPoint>
#include <QPointer>
#include <QPushButton>
#include <QSize>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <thread>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum class AlpcColumn : int
    {
        Role = 0,
        Relation,
        OwnerProcessId,
        Flags,
        State,
        SequenceNo,
        ObjectAddress,
        PortContext,
        PortName,
        Status,
        Count
    };

    enum class IpcSummaryColumn : int
    {
        Category = 0,
        Status,
        Count,
        Source,
        Detail,
        CountColumn
    };

    QString blueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:2px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    QString headerStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:%2;border:0;border-bottom:1px solid %3;font-weight:500;padding:4px 8px;}")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::BorderHex());
    }

    QString itemSelectionStyle()
    {
        return QString();
    }

    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.ipc.placeholder.empty", QStringLiteral("<空>")));
    }

    QString formatRelationText(std::uint32_t relation)
    {
        switch (relation)
        {
        case KSWORD_ARK_ALPC_PORT_RELATION_QUERY: return QStringLiteral("Query");
        case KSWORD_ARK_ALPC_PORT_RELATION_CONNECTION: return QStringLiteral("Connection");
        case KSWORD_ARK_ALPC_PORT_RELATION_SERVER: return QStringLiteral("Server");
        case KSWORD_ARK_ALPC_PORT_RELATION_CLIENT: return QStringLiteral("Client");
        default: return QStringLiteral("Relation(%1)").arg(relation);
        }
    }

    QString ipcSummaryStatusText(const unsigned long statusValue)
    {
        // ipcSummaryStatusText：
        // - 作用：把 IPC summary 协议状态转换为界面可读文本；
        // - 输入：KSWORD_ARK_IPC_SUMMARY_STATUS_* 数值；
        // - 返回：状态名称，未知值保留原始数字，避免把未知状态渲染成正常。
        switch (statusValue)
        {
        case KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE: return QStringLiteral("Unavailable");
        case KSWORD_ARK_IPC_SUMMARY_STATUS_OK: return QStringLiteral("OK");
        case KSWORD_ARK_IPC_SUMMARY_STATUS_PARTIAL: return QStringLiteral("Partial");
        case KSWORD_ARK_IPC_SUMMARY_STATUS_STUB: return kernelText("kernel.ipc.status.legacy_stub", QStringLiteral("LegacyStub（旧驱动占位）"));
        case KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED: return QStringLiteral("Failed");
        default: return QStringLiteral("Status(%1)").arg(statusValue);
        }
    }

    QString stdStringToQString(const std::string& valueText)
    {
        // stdStringToQString：
        // - 作用：把 ArkDriverClient 的 UTF-8/窄字符串诊断转成 QString；
        // - 输入：io.message 等 std::string；
        // - 返回：可直接放入 QLabel/QTableWidget 的 QString。
        return QString::fromUtf8(valueText.data(), static_cast<int>(valueText.size()));
    }

    QString friendlyIpcIoMessage(const QString& messageText)
    {
        // friendlyIpcIoMessage：
        // - 作用：把底层 ArkDriverClient/IOCTL 消息转换成用户可读提示；
        // - 输入：原始 io.message 文本；
        // - 返回：适合表格“详情”列的短说明。
        const QString trimmedText = messageText.trimmed();
        if (trimmedText.isEmpty())
        {
            return kernelText("kernel.ipc.message.no_driver_message", QStringLiteral("无额外驱动消息。"));
        }
        if (trimmedText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.device_io_failure", QStringLiteral("驱动接口调用失败或当前驱动版本不支持该 IPC 摘要入口。"));
        }
        if (trimmedText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            trimmedText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.unsupported", QStringLiteral("当前驱动不支持该 IPC/ALPC 只读查询入口。"));
        }
        if (trimmedText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            trimmedText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.capability", QStringLiteral("动态偏移能力未满足，IPC/ALPC 详情暂不可用。"));
        }
        if (trimmedText.contains(QStringLiteral("version mismatch"), Qt::CaseInsensitive) ||
            trimmedText.contains(QStringLiteral("invalid parameter"), Qt::CaseInsensitive))
        {
            // 协议兼容提示：
            // - 输入：R0/R3 参数或版本不匹配的底层消息；
            // - 处理：转换为同步 shared/driver/client 的操作建议；
            // - 返回：详情列可直接展示的中文说明。
            return kernelText("kernel.ipc.message.protocol_mismatch", QStringLiteral("驱动与主程序版本不兼容，请更新为匹配版本。"));
        }
        if (trimmedText.contains(QStringLiteral("buffer"), Qt::CaseInsensitive) ||
            trimmedText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
            trimmedText.contains(QStringLiteral("trunc"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.incomplete_buffer", QStringLiteral("IPC/ALPC 返回缓冲区不完整，当前只展示已解析到的证据。"));
        }
        if (trimmedText.contains(QStringLiteral("access denied"), Qt::CaseInsensitive) ||
            trimmedText.contains(QStringLiteral("privilege"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.access_denied", QStringLiteral("权限不足，当前进程无法完成 IPC/ALPC 只读查询。"));
        }
        if (trimmedText.contains(QStringLiteral("skipped"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.skipped_incomplete_target", QStringLiteral("未输入完整 PID/Handle，因此只显示全局 IPC 摘要。"));
        }
        return trimmedText;
    }

    QString fixedWideText(const wchar_t* buffer, const int maxChars)
    {
        // fixedWideText：
        // - 作用：读取 R0 固定宽字符数组，遇到 NUL 提前截断；
        // - 输入：固定数组指针和最大字符数；
        // - 返回：不包含尾部 NUL 填充的 QString。
        if (buffer == nullptr || maxChars <= 0)
        {
            return QString();
        }
        int length = 0;
        while (length < maxChars && buffer[length] != L'\0')
        {
            ++length;
        }
        return QString::fromWCharArray(buffer, length);
    }

    ks::ui::FieldDocument buildPortDetail(const QString& roleText, const ksword::ark::AlpcPortInfo& portInfo)
    {
        { ks::ui::FieldDocument document;
        document.field(QStringLiteral("Role"), QStringLiteral("%1").arg(roleText));
        document.field(QStringLiteral("Relation"), QStringLiteral("%1").arg(formatRelationText(portInfo.relation)));
        document.field(QStringLiteral("OwnerProcessId"), QStringLiteral("%1").arg(portInfo.ownerProcessId));
        document.field(QStringLiteral("Flags"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(portInfo.flags, 8, 16, QChar('0')).toUpper()));
        document.field(QStringLiteral("State"), QStringLiteral("%1").arg(portInfo.state));
        document.field(QStringLiteral("SequenceNo"), QStringLiteral("%1").arg(portInfo.sequenceNo));
        document.field(QStringLiteral("BasicStatus"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(portInfo.basicStatus), 8, 16, QChar('0')).toUpper()));
        document.field(QStringLiteral("NameStatus"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(portInfo.nameStatus), 8, 16, QChar('0')).toUpper()));
        document.field(QStringLiteral("ObjectAddress"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(portInfo.objectAddress), 16, 16, QChar('0')).toUpper()));
        document.field(QStringLiteral("PortContext"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(portInfo.portContext), 16, 16, QChar('0')).toUpper()));
        document.field(QStringLiteral("PortName"), QStringLiteral("%1").arg(safeText(QString::fromWCharArray(portInfo.portName.c_str(), static_cast<int>(portInfo.portName.size())))));
        return document; }
    }
}

KernelDockIpcTab::KernelDockIpcTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    QMetaObject::invokeMethod(this, [this]() {
        refreshAlpcQuery();
    }, Qt::QueuedConnection);
}

void KernelDockIpcTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(6);

    m_innerTabWidget = new QTabWidget(this);
    ks::ui::StylePageTabs(m_innerTabWidget);
    m_innerTabWidget->setIconSize(QSize(16, 16));
    rootLayout->addWidget(m_innerTabWidget, 1);

    m_innerTabWidget->addTab(
        new KernelNamedPipeTab(m_innerTabWidget),
        QIcon(QStringLiteral(":/Icon/process_list.svg")),
        QStringLiteral("NamedPipe"));
    m_innerTabWidget->setTabToolTip(0, kernelText("kernel.ipc.tab.named_pipe.tooltip", QStringLiteral("只读 NPFS NamedPipe 目录枚举")));

    initializeAlpcPage();
    m_innerTabWidget->addTab(
        m_alpcPage,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("ALPC"));
    m_innerTabWidget->setTabToolTip(1, kernelText("kernel.ipc.tab.alpc.tooltip", QStringLiteral("只读 ALPC 端口关系查询")));

    m_innerTabWidget->addTab(
        new KernelCommunicationEndpointTab(m_innerTabWidget),
        QIcon(QStringLiteral(":/Icon/process_critical.svg")),
        kernelText("kernel.ipc.tab.communication.title", QStringLiteral("通信对象")));
    m_innerTabWidget->setTabToolTip(2, kernelText("kernel.ipc.tab.communication.tooltip", QStringLiteral("只读 ALPC/RPC 通信端点聚合")));
}

void KernelDockIpcTab::initializeConnections()
{
    if (m_alpcRefreshButton != nullptr)
    {
        connect(m_alpcRefreshButton, &QPushButton::clicked, this, [this]() {
            refreshAlpcQuery();
        });
    }
    if (m_alpcProcessIdEdit != nullptr)
    {
        connect(m_alpcProcessIdEdit, &QLineEdit::textChanged, this, [this]() {
            m_alpcProcessId = m_alpcProcessIdEdit->text().trimmed().toUInt();
        });
    }
    if (m_alpcHandleEdit != nullptr)
    {
        connect(m_alpcHandleEdit, &QLineEdit::textChanged, this, [this]() {
            bool ok = false;
            m_alpcHandleValue = m_alpcHandleEdit->text().trimmed().toULongLong(&ok, 16);
            if (!ok)
            {
                m_alpcHandleValue = 0;
            }
        });
    }
}

void KernelDockIpcTab::initializeAlpcPage()
{
    if (m_alpcPage != nullptr)
    {
        return;
    }

    m_alpcPage = new QWidget(m_innerTabWidget);
    auto* layout = new QVBoxLayout(m_alpcPage);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(6);

    m_alpcToolbarLayout = new QHBoxLayout();
    m_alpcToolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_alpcToolbarLayout->setSpacing(6);

    m_alpcRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_alpcPage);
    KswordTheme::ApplyCompactIconButtonMetrics(m_alpcRefreshButton);
    m_alpcRefreshButton->setToolTip(kernelText("kernel.ipc.toolbar.refresh.tooltip", QStringLiteral("刷新 ALPC 端口查询")));
    m_alpcRefreshButton->setStyleSheet(blueButtonStyle());

    m_alpcProcessIdEdit = new QLineEdit(m_alpcPage);
    m_alpcProcessIdEdit->setPlaceholderText(QStringLiteral("PID"));
    m_alpcProcessIdEdit->setClearButtonEnabled(true);
    m_alpcProcessIdEdit->setStyleSheet(blueInputStyle());

    m_alpcHandleEdit = new QLineEdit(m_alpcPage);
    m_alpcHandleEdit->setPlaceholderText(kernelText("kernel.ipc.toolbar.handle.placeholder", QStringLiteral("句柄值（十六进制）")));
    m_alpcHandleEdit->setClearButtonEnabled(true);
    m_alpcHandleEdit->setStyleSheet(blueInputStyle());

    m_alpcStatusLabel = new QLabel(kernelText("kernel.ipc.status.waiting", QStringLiteral("状态：等待查询")), m_alpcPage);
    m_alpcStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::TextSecondaryHex()));

    m_alpcToolbarLayout->addWidget(m_alpcRefreshButton, 0);
    m_alpcToolbarLayout->addWidget(m_alpcProcessIdEdit, 0);
    m_alpcToolbarLayout->addWidget(m_alpcHandleEdit, 1);
    m_alpcToolbarLayout->addWidget(m_alpcStatusLabel, 0);
    ks::ui::NormalizeToolbarRow(m_alpcToolbarLayout);
    layout->addLayout(m_alpcToolbarLayout);

    m_ipcSummaryTable = new ks::ui::VisibleTableWidget(m_alpcPage);
    // IPC 分类计数小表已有详情，不挤占 ALPC 端口空间。
    ks::ui::SetTableActionBarMode(m_ipcSummaryTable, ks::ui::TableActionBarMode::None);
    m_ipcSummaryTable->setColumnCount(static_cast<int>(IpcSummaryColumn::CountColumn));
    m_ipcSummaryTable->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.ipc.header.category", QStringLiteral("类别")),
        kernelText("kernel.ipc.header.status", QStringLiteral("状态")),
        QStringLiteral("Count"),
        kernelText("kernel.ipc.header.source", QStringLiteral("来源")),
        kernelText("kernel.ipc.header.detail", QStringLiteral("详情"))
        });
    m_ipcSummaryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_ipcSummaryTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_ipcSummaryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_ipcSummaryTable->setAlternatingRowColors(true);
    m_ipcSummaryTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_ipcSummaryTable->setStyleSheet(itemSelectionStyle());
    m_ipcSummaryTable->verticalHeader()->setVisible(false);
    m_ipcSummaryTable->horizontalHeader()->setStyleSheet(headerStyle());
    m_ipcSummaryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_ipcSummaryTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(IpcSummaryColumn::Detail), QHeaderView::Stretch);
    m_ipcSummaryTable->setToolTip(kernelText("kernel.ipc.summary.tooltip", QStringLiteral("只读查询进程或全局 IPC 摘要；可使用上方 PID/句柄筛选。")));
    layout->addWidget(m_ipcSummaryTable, 0);

    m_alpcTable = new ks::ui::VisibleTableWidget(m_alpcPage);
    // 单句柄关系下钻结果较少，保留复制导出并收拢快照条。
    ks::ui::SetTableActionBarMode(m_alpcTable, ks::ui::TableActionBarMode::Compact);
    m_alpcTable->setColumnCount(static_cast<int>(AlpcColumn::Count));
    m_alpcTable->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.ipc.header.role", QStringLiteral("角色")),
        QStringLiteral("Relation"),
        QStringLiteral("Owner PID"),
        QStringLiteral("Flags"),
        QStringLiteral("State"),
        QStringLiteral("Seq"),
        QStringLiteral("Object"),
        QStringLiteral("Context"),
        QStringLiteral("Port Name"),
        QStringLiteral("Status")
        });
    m_alpcTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_alpcTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_alpcTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_alpcTable->setAlternatingRowColors(true);
    m_alpcTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_alpcTable->setStyleSheet(itemSelectionStyle());
    m_alpcTable->verticalHeader()->setVisible(false);
    m_alpcTable->horizontalHeader()->setStyleSheet(headerStyle());
    m_alpcTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_alpcTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(AlpcColumn::PortName), QHeaderView::Stretch);
    m_alpcTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(AlpcColumn::Status), QHeaderView::Stretch);
    layout->addWidget(m_alpcTable, 1);

    m_alpcDetailEditor = new ks::ui::StructuredFieldView(m_alpcPage);

    m_alpcDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.ipc.detail.initial", QStringLiteral("输入 PID + ALPC 句柄后查询，或刷新后查看结果。"))));
    layout->addWidget(m_alpcDetailEditor, 1);

    connect(m_alpcTable, &QTableWidget::currentCellChanged, this, [this](const int currentRow, int, int, int) {
        // ALPC 行选择：
        // - 输入：当前 ALPC 表格行号；
        // - 处理：只刷新详情文本，不重新查询、不重建表格；
        // - 返回：无，避免选中行触发递归重绘。
        updateAlpcDetailForRow(currentRow);
    });
    connect(m_ipcSummaryTable, &QTableWidget::currentCellChanged, this, [this](const int currentRow, int, int, int) {
        // IPC summary 行选择：
        // - 输入：当前表格行号，列号在这里不参与业务判断；
        // - 处理：把固定 summary 响应展开成详情文本；
        // - 返回：无，详情区只读展示，不触发任何 R0 调用。
        updateIpcSummaryDetailForRow(currentRow);
    });
    connect(m_ipcSummaryTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        // 右键菜单：
        // - 输入：用户在 IPC summary 表中的点击位置；
        // - 处理：定位当前行并复制 TSV；
        // - 返回：无，菜单只读，不触发任何 IPC 修改动作。
        const QModelIndex clickedIndex = m_ipcSummaryTable->indexAt(localPosition);
        if (clickedIndex.isValid())
        {
            m_ipcSummaryTable->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            m_ipcSummaryTable->selectRow(clickedIndex.row());
        }
        QMenu menu(this);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        QAction* copyRowAction = menu.addAction(kernelText("kernel.ipc.menu.copy_row", QStringLiteral("复制当前行")));
        copyRowAction->setEnabled(m_ipcSummaryTable->currentRow() >= 0);
        if (menu.exec(m_ipcSummaryTable->viewport()->mapToGlobal(localPosition)) == copyRowAction)
        {
            copyIpcSummaryCurrentRow();
        }
    });
    connect(m_alpcTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        const QModelIndex clickedIndex = m_alpcTable->indexAt(localPosition);
        if (clickedIndex.isValid())
        {
            m_alpcTable->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            m_alpcTable->selectRow(clickedIndex.row());
        }
        QMenu menu(this);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        QAction* copyRowAction = menu.addAction(kernelText("kernel.ipc.menu.copy_row", QStringLiteral("复制当前行")));
        copyRowAction->setEnabled(m_alpcTable->currentRow() >= 0);
        const QTableWidgetItem* ownerProcessIdItem = m_alpcTable->currentRow() >= 0
            ? m_alpcTable->item(m_alpcTable->currentRow(), static_cast<int>(AlpcColumn::OwnerProcessId))
            : nullptr;
        bool processIdOk = false;
        const quint32 processId = ownerProcessIdItem != nullptr
            ? ownerProcessIdItem->text().trimmed().toUInt(&processIdOk, 10)
            : 0U;
        QAction* openProcessAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QStringLiteral("转到进程详细信息"));
        openProcessAction->setEnabled(processIdOk && processId != 0U);
        QAction* selectedAction = menu.exec(m_alpcTable->viewport()->mapToGlobal(localPosition));
        if (selectedAction == copyRowAction)
        {
            copyAlpcCurrentRow();
        }
        else if (selectedAction == openProcessAction)
        {
            ks::ui::OpenProcessDetailByPid(processId);
        }
    });
}

void KernelDockIpcTab::refreshAlpcQuery()
{
    if (m_alpcRefreshButton == nullptr || m_alpcPage == nullptr)
    {
        return;
    }

    m_alpcRefreshButton->setEnabled(false);
    m_alpcStatusLabel->setText(kernelText("kernel.ipc.status.querying", QStringLiteral("状态：查询中...")));
    m_alpcStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::PrimaryBlueHex));

    const std::uint32_t pid = m_alpcProcessIdEdit != nullptr ? m_alpcProcessIdEdit->text().trimmed().toUInt() : 0U;
    const QString handleText = m_alpcHandleEdit != nullptr ? m_alpcHandleEdit->text().trimmed() : QString();
    bool ok = false;
    const std::uint64_t handleValue = handleText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)
        ? handleText.mid(2).toULongLong(&ok, 16)
        : handleText.toULongLong(&ok, 16);
    const bool hasAlpcTarget = ok && pid != 0U && handleValue != 0ULL;
    if (!hasAlpcTarget)
    {
        m_alpcStatusLabel->setText(kernelText("kernel.ipc.status.global_query", QStringLiteral("状态：查询全局 R0 IPC summary；ALPC 详情需输入 PID 与十六进制句柄")));
        m_alpcStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::WarningHex()));
    }

    QPointer<KernelDockIpcTab> guardThis(this);
    std::thread([guardThis, pid, handleValue, hasAlpcTarget]() {
        const ksword::ark::DriverClient client;
        const std::uint32_t summaryPid = hasAlpcTarget ? pid : 0U;
        const std::uint64_t summaryHandle = hasAlpcTarget ? handleValue : 0ULL;
        const ksword::ark::IpcSummaryAuditResult summaryResult = client.queryIpcSummary(summaryPid, summaryHandle);
        ksword::ark::AlpcPortQueryResult alpcResult{};
        if (hasAlpcTarget)
        {
            alpcResult = client.queryAlpcPort(pid, handleValue);
        }
        else
        {
            alpcResult.io.ok = false;
            alpcResult.io.message = "ALPC detail skipped because PID/handle input is incomplete; IPC summary used global defaults.";
        }
        KernelDockIpcTab* const contextObject = guardThis.data();
        if (contextObject == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(contextObject, [guardThis, summaryResult, alpcResult, hasAlpcTarget]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-ipc-alpc-snapshot"),
                { guardThis->m_ipcSummaryTable, guardThis->m_alpcTable },
                [guardThis, summaryResult, alpcResult, hasAlpcTarget]() mutable
                {
                    if (guardThis.isNull())
                    {
                        return;
                    }

                    guardThis->m_lastIpcSummaryResult = summaryResult;
                    guardThis->m_lastAlpcResult = alpcResult;
                    guardThis->m_alpcRefreshButton->setEnabled(true);
                    guardThis->applyIpcSummaryResult();
                    guardThis->applyAlpcQueryResult();
                    if (!hasAlpcTarget)
                    {
                        guardThis->m_alpcStatusLabel->setText(kernelText(
                            "kernel.ipc.status.global_refreshed",
                            QStringLiteral("状态：已刷新 R0 IPC summary；ALPC 详情等待 PID/Handle")));
                        guardThis->m_alpcStatusLabel->setStyleSheet(
                            statusLabelStyle(KswordTheme::WarningHex()));
                    }
                }))
            {
                return;
            }

            guardThis->m_lastIpcSummaryResult = summaryResult;
            guardThis->m_lastAlpcResult = alpcResult;
            guardThis->m_alpcRefreshButton->setEnabled(true);
            guardThis->applyIpcSummaryResult();
            guardThis->applyAlpcQueryResult();
            if (!hasAlpcTarget)
            {
                guardThis->m_alpcStatusLabel->setText(kernelText("kernel.ipc.status.global_refreshed", QStringLiteral("状态：已刷新 R0 IPC summary；ALPC 详情等待 PID/Handle")));
                guardThis->m_alpcStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::WarningHex()));
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDockIpcTab::applyIpcSummaryResult()
{
    // applyIpcSummaryResult：
    // - 作用：把 ArkDriverClient::queryIpcSummary 的固定响应追加到 ALPC/IPC 页面；
    // - 输入：成员 m_lastIpcSummaryResult，来源于后台线程；
    // - 输出：更新 m_ipcSummaryTable；无返回值，不直接访问 DeviceIoControl。
    if (m_ipcSummaryTable == nullptr)
    {
        return;
    }

    auto setSummaryItem = [this](const int rowIndex, const IpcSummaryColumn column, const QString& valueText) {
        // setSummaryItem：
        // - 作用：写入 IPC summary 表格单元格；
        // - 输入：行号、列枚举和值；
        // - 输出：表格项归 m_ipcSummaryTable 所有。
        auto* item = new QTableWidgetItem(valueText);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        m_ipcSummaryTable->setItem(rowIndex, static_cast<int>(column), item);
    };

    auto appendSummaryRow = [&](const QString& categoryText, const QString& statusTextValue, const QString& countText, const QString& sourceText, const QString& detailText) {
        // appendSummaryRow：
        // - 作用：追加一行 R0 IPC summary；
        // - 输入：类别、状态、计数、来源和详情；
        // - 输出：增加一行表格，无返回值。
        const int rowIndex = m_ipcSummaryTable->rowCount();
        m_ipcSummaryTable->insertRow(rowIndex);
        setSummaryItem(rowIndex, IpcSummaryColumn::Category, categoryText);
        setSummaryItem(rowIndex, IpcSummaryColumn::Status, statusTextValue);
        setSummaryItem(rowIndex, IpcSummaryColumn::Count, countText);
        setSummaryItem(rowIndex, IpcSummaryColumn::Source, sourceText);
        setSummaryItem(rowIndex, IpcSummaryColumn::Detail, detailText);
    };

    m_ipcSummaryTable->setSortingEnabled(false);
    m_ipcSummaryTable->setRowCount(0);

    const QString ioMessage = stdStringToQString(m_lastIpcSummaryResult.io.message);
    const QString readableIoMessage = friendlyIpcIoMessage(ioMessage);
    if (!m_lastIpcSummaryResult.io.ok)
    {
        appendSummaryRow(
            QStringLiteral("R0 IPC Summary"),
            m_lastIpcSummaryResult.unsupported ? QStringLiteral("Unsupported") : QStringLiteral("Unavailable"),
            QStringLiteral("N/A"),
            QStringLiteral("驱动查询"),
            kernelText("kernel.ipc.summary.error_detail", QStringLiteral("IPC 摘要暂不可用。Win32=%1；驱动返回字节=%2；%3"))
                .arg(m_lastIpcSummaryResult.io.win32Error)
                .arg(m_lastIpcSummaryResult.io.bytesReturned)
                .arg(readableIoMessage));
        m_ipcSummaryTable->setSortingEnabled(true);
        if (m_ipcSummaryTable->rowCount() > 0)
        {
            m_ipcSummaryTable->setCurrentCell(0, 0);
            updateIpcSummaryDetailForRow(0);
        }
        return;
    }

    const auto& response = m_lastIpcSummaryResult.response;
    const QString countUnavailableText = kernelText("kernel.ipc.summary.count_unavailable", QStringLiteral("未提供"));
    const QString commonSourceText = QStringLiteral("内核查询 PID=%1 Handle=%2")
        .arg(response.processId)
        .arg(formatHex64(response.handleValue));
    const QString responseDetailText = safeText(
        fixedWideText(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS),
        kernelText("kernel.ipc.summary.object_detail_unavailable", QStringLiteral("驱动未提供额外对象详情")));
    const QString commonDetailText = kernelText("kernel.ipc.summary.common_detail", QStringLiteral(
        "IPC 摘要状态：%1；字段覆盖：%2；最近状态：%3；驱动返回字节：%4；%5；对象说明：%6")
        .arg(ipcSummaryStatusText(response.status))
        .arg(formatHex32(response.fieldFlags))
        .arg(statusText(response.lastStatus))
        .arg(m_lastIpcSummaryResult.io.bytesReturned)
        .arg(readableIoMessage)
        .arg(responseDetailText));

    appendSummaryRow(
        QStringLiteral("ALPC"),
        ipcSummaryStatusText(response.alpcStatus),
        countUnavailableText,
        commonSourceText,
        kernelText("kernel.ipc.summary.alpc_detail", QStringLiteral("ALPC 对象地址：%1；对象类型：%2；DynData 能力：%3；%4"))
            .arg(formatHex64(response.alpcObjectAddress))
            .arg(safeText(fixedWideText(response.alpcTypeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS)))
            .arg(formatHex64(response.dynDataCapabilityMask))
            .arg(commonDetailText));
    appendSummaryRow(
        QStringLiteral("NamedPipe"),
        ipcSummaryStatusText(response.namedPipeStatus),
        countUnavailableText,
        commonSourceText,
        commonDetailText);
    appendSummaryRow(
        QStringLiteral("Mailslot"),
        ipcSummaryStatusText(response.mailslotStatus),
        countUnavailableText,
        commonSourceText,
        commonDetailText);
    appendSummaryRow(
        QStringLiteral("SMB/IPC"),
        kernelText("kernel.ipc.summary.smb_hint_title", QStringLiteral("提示")),
        QStringLiteral("N/A"),
        QStringLiteral("功能限制"),
        kernelText("kernel.ipc.summary.smb_hint", QStringLiteral("当前版本未提供 SMB 命名管道或 IPC$ 的归因详情。")));
    appendSummaryRow(
        QStringLiteral("Transport"),
        QStringLiteral("OK"),
        kernelText("kernel.ipc.summary.transport_count", QStringLiteral("已返回")),
        QStringLiteral("内核驱动"),
        kernelText("kernel.ipc.summary.transport_detail", QStringLiteral("驱动 IPC 摘要调用成功；返回字节=%1；%2"))
            .arg(m_lastIpcSummaryResult.io.bytesReturned)
            .arg(readableIoMessage));

    m_ipcSummaryTable->setSortingEnabled(true);
    if (m_ipcSummaryTable->rowCount() > 0)
    {
        const int targetRow = m_ipcSummaryTable->currentRow() >= 0 ? m_ipcSummaryTable->currentRow() : 0;
        m_ipcSummaryTable->setCurrentCell(targetRow, 0);
        updateIpcSummaryDetailForRow(targetRow);
    }
}

void KernelDockIpcTab::applyAlpcQueryResult()
{
    if (m_alpcTable == nullptr || m_alpcDetailEditor == nullptr)
    {
        return;
    }

    m_alpcTable->setSortingEnabled(false);
    m_alpcTable->setRowCount(0);

    if (!m_lastAlpcResult.io.ok)
    {
        const QString alpcMessage = stdStringToQString(m_lastAlpcResult.io.message);
        const QString readableAlpcMessage = friendlyIpcIoMessage(alpcMessage);
        const bool skippedByInput = alpcMessage.contains(QStringLiteral("skipped"), Qt::CaseInsensitive);

        auto setDiagnosticItem = [this](const AlpcColumn column, const QString& valueText) {
            // setDiagnosticItem：
            // - 输入：ALPC 表列枚举和诊断文本；
            // - 处理：写入一格只读占位；
            // - 返回：无，单元格生命周期交给 QTableWidget。
            auto* item = new QTableWidgetItem(valueText);
            item->setFlags(item->flags() & ~Qt::ItemIsEditable);
            m_alpcTable->setItem(0, static_cast<int>(column), item);
        };

        // ALPC 诊断行：
        // - 输入：ALPC 查询失败或被跳过的原因；
        // - 处理：保留一行可复制的表格证据，避免 IPC 页某个表格完全空白；
        // - 返回：无返回值，详情区仍按 summary/错误文本展示。
        m_alpcTable->setRowCount(1);
        setDiagnosticItem(AlpcColumn::Role, skippedByInput
            ? kernelText("kernel.ipc.alpc.diagnostic.not_requested", QStringLiteral("ALPC 未请求"))
            : kernelText("kernel.ipc.alpc.diagnostic.query_failed", QStringLiteral("ALPC 查询失败")));
        setDiagnosticItem(AlpcColumn::Relation, QStringLiteral("Diagnostic"));
        setDiagnosticItem(AlpcColumn::OwnerProcessId, m_alpcProcessIdEdit != nullptr
            ? safeText(m_alpcProcessIdEdit->text().trimmed(), kernelText("kernel.ipc.alpc.placeholder.pid", QStringLiteral("<未输入>")))
            : kernelText("kernel.ipc.alpc.placeholder.unknown", QStringLiteral("<未知>")));
        setDiagnosticItem(AlpcColumn::Flags, QStringLiteral("-"));
        setDiagnosticItem(AlpcColumn::State, QStringLiteral("-"));
        setDiagnosticItem(AlpcColumn::SequenceNo, QStringLiteral("-"));
        setDiagnosticItem(AlpcColumn::ObjectAddress, QStringLiteral("0x0000000000000000"));
        setDiagnosticItem(AlpcColumn::PortContext, QStringLiteral("0x0000000000000000"));
        setDiagnosticItem(AlpcColumn::PortName, skippedByInput
            ? kernelText("kernel.ipc.alpc.diagnostic.handle_hint", QStringLiteral("请输入 PID + 十六进制 ALPC 句柄"))
            : kernelText("kernel.ipc.alpc.placeholder.unavailable", QStringLiteral("<不可用>")));
        setDiagnosticItem(AlpcColumn::Status, readableAlpcMessage);
        m_alpcTable->setSortingEnabled(true);
        m_alpcTable->setCurrentCell(0, static_cast<int>(AlpcColumn::Role));

        m_alpcStatusLabel->setText(skippedByInput
            ? kernelText("kernel.ipc.alpc.status.not_requested", QStringLiteral("状态：R0 IPC summary 已刷新；ALPC 详情未请求"))
            : kernelText("kernel.ipc.alpc.status.query_failed", QStringLiteral("状态：ALPC 查询失败 - %1")).arg(readableAlpcMessage));
        m_alpcStatusLabel->setStyleSheet(statusLabelStyle(skippedByInput ? KswordTheme::WarningHex() : KswordTheme::ErrorHex()));
        if (skippedByInput)
        {
            // 无 ALPC 目标时：
            // - 输入：summary 表当前行，缺省选择第一行；
            // - 处理：继续展示 IPC summary 的结构化详情，而不是覆盖成一句短提示；
            // - 返回：无，保持页面有可读的审计展开内容。
            const int summaryRow = (m_ipcSummaryTable != nullptr && m_ipcSummaryTable->currentRow() >= 0)
                ? m_ipcSummaryTable->currentRow()
                : 0;
            if (m_ipcSummaryTable != nullptr && m_ipcSummaryTable->rowCount() > 0)
            {
                m_ipcSummaryTable->setCurrentCell(summaryRow, 0);
            }
            updateIpcSummaryDetailForRow(summaryRow);
        }
        else
        {
            m_alpcDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.ipc.alpc.detail.query_failed", QStringLiteral("ALPC 查询失败。\n%1")).arg(readableAlpcMessage)));
        }
        return;
    }

    struct EntryView
    {
        QString role;
        const ksword::ark::AlpcPortInfo* port = nullptr;
    };
    const EntryView views[] = {
        { QStringLiteral("Query"), &m_lastAlpcResult.queryPort },
        { QStringLiteral("Connection"), &m_lastAlpcResult.connectionPort },
        { QStringLiteral("Server"), &m_lastAlpcResult.serverPort },
        { QStringLiteral("Client"), &m_lastAlpcResult.clientPort },
    };

    for (const EntryView& view : views)
    {
        const int rowIndex = m_alpcTable->rowCount();
        m_alpcTable->insertRow(rowIndex);

        auto* roleItem = new QTableWidgetItem(view.role);
        auto* relationItem = new QTableWidgetItem(view.port != nullptr ? formatRelationText(view.port->relation) : kernelText("kernel.ipc.placeholder.empty", QStringLiteral("<空>")));
        auto* ownerItem = new QTableWidgetItem(view.port != nullptr ? QString::number(view.port->ownerProcessId) : QString());
        auto* flagsItem = new QTableWidgetItem(view.port != nullptr ? formatHex32(view.port->flags) : QString());
        auto* stateItem = new QTableWidgetItem(view.port != nullptr ? QString::number(view.port->state) : QString());
        auto* seqItem = new QTableWidgetItem(view.port != nullptr ? QString::number(view.port->sequenceNo) : QString());
        auto* objectItem = new QTableWidgetItem(view.port != nullptr ? formatHex64(view.port->objectAddress) : QString());
        auto* contextItem = new QTableWidgetItem(view.port != nullptr ? formatHex64(view.port->portContext) : QString());
        auto* nameItem = new QTableWidgetItem(view.port != nullptr ? safeText(QString::fromWCharArray(view.port->portName.c_str(), static_cast<int>(view.port->portName.size()))) : QString());
        auto* statusItem = new QTableWidgetItem(view.port != nullptr ? statusText(view.port->basicStatus) : QString());

        roleItem->setFlags(roleItem->flags() & ~Qt::ItemIsEditable);
        relationItem->setFlags(relationItem->flags() & ~Qt::ItemIsEditable);
        ownerItem->setFlags(ownerItem->flags() & ~Qt::ItemIsEditable);
        flagsItem->setFlags(flagsItem->flags() & ~Qt::ItemIsEditable);
        stateItem->setFlags(stateItem->flags() & ~Qt::ItemIsEditable);
        seqItem->setFlags(seqItem->flags() & ~Qt::ItemIsEditable);
        objectItem->setFlags(objectItem->flags() & ~Qt::ItemIsEditable);
        contextItem->setFlags(contextItem->flags() & ~Qt::ItemIsEditable);
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        statusItem->setFlags(statusItem->flags() & ~Qt::ItemIsEditable);

        m_alpcTable->setItem(rowIndex, static_cast<int>(AlpcColumn::Role), roleItem);
        m_alpcTable->setItem(rowIndex, static_cast<int>(AlpcColumn::Relation), relationItem);
        m_alpcTable->setItem(rowIndex, static_cast<int>(AlpcColumn::OwnerProcessId), ownerItem);
        m_alpcTable->setItem(rowIndex, static_cast<int>(AlpcColumn::Flags), flagsItem);
        m_alpcTable->setItem(rowIndex, static_cast<int>(AlpcColumn::State), stateItem);
        m_alpcTable->setItem(rowIndex, static_cast<int>(AlpcColumn::SequenceNo), seqItem);
        m_alpcTable->setItem(rowIndex, static_cast<int>(AlpcColumn::ObjectAddress), objectItem);
        m_alpcTable->setItem(rowIndex, static_cast<int>(AlpcColumn::PortContext), contextItem);
        m_alpcTable->setItem(rowIndex, static_cast<int>(AlpcColumn::PortName), nameItem);
        m_alpcTable->setItem(rowIndex, static_cast<int>(AlpcColumn::Status), statusItem);
    }

    m_alpcTable->setSortingEnabled(true);
    m_alpcStatusLabel->setText(kernelText("kernel.ipc.alpc.status.success", QStringLiteral("状态：PID=%1 Handle=%2 | Query=%3 Connection=%4 Server=%5 Client=%6"))
        .arg(m_lastAlpcResult.processId)
        .arg(formatHex64(m_lastAlpcResult.handleValue))
        .arg(statusText(m_lastAlpcResult.queryStatus))
        .arg(statusText(m_lastAlpcResult.communicationStatus))
        .arg(statusText(m_lastAlpcResult.basicStatus))
        .arg(statusText(m_lastAlpcResult.nameStatus)));
    m_alpcStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::SuccessHex()));

    const int currentRow = m_alpcTable->currentRow();
    const QTableWidgetItem* roleItem = currentRow >= 0 ? m_alpcTable->item(currentRow, static_cast<int>(AlpcColumn::Role)) : nullptr;
    if (roleItem == nullptr && m_alpcTable->rowCount() > 0)
    {
        m_alpcTable->setCurrentCell(0, 0);
        roleItem = m_alpcTable->item(0, static_cast<int>(AlpcColumn::Role));
    }

    updateAlpcDetailForRow(m_alpcTable->currentRow());
}

ks::ui::FieldDocument KernelDockIpcTab::buildAlpcDetail(const int rowIndex) const
{
    // buildAlpcDetail：
    // - 作用：把 ALPC 查询结果转换为详情区文本；
    // - 输入：当前选中的 ALPC 行号；
    // - 返回：QString，多行说明当前行端口、状态和动态偏移。
    if (!m_lastAlpcResult.io.ok)
    {
        return ks::ui::FieldDocument{}.note(kernelText("kernel.ipc.alpc.detail.unavailable", QStringLiteral("ALPC 查询暂不可用。\n%1")).arg(friendlyIpcIoMessage(stdStringToQString(m_lastAlpcResult.io.message))));
    }

    QString selectedRoleText = kernelText("kernel.ipc.placeholder.unselected", QStringLiteral("<未选择>"));
    ks::ui::FieldDocument selectedPortDetailText = ks::ui::FieldDocument{}.note(kernelText("kernel.ipc.alpc.detail.select_row", QStringLiteral("请在 ALPC 表中选择一行查看端口详情。")));
    if (m_alpcTable != nullptr && rowIndex >= 0 && rowIndex < m_alpcTable->rowCount())
    {
        // 当前行解析：
        // - 输入：表格角色列文本；
        // - 处理：映射到 ArkDriverClient 返回的四个端口快照；
        // - 返回：当前行的单端口详情。
        const QTableWidgetItem* roleItem = m_alpcTable->item(rowIndex, static_cast<int>(AlpcColumn::Role));
        selectedRoleText = roleItem != nullptr ? roleItem->text() : kernelText("kernel.ipc.alpc.placeholder.unknown_role", QStringLiteral("<未知角色>"));
        if (selectedRoleText == QStringLiteral("Query"))
        {
            selectedPortDetailText = buildPortDetail(selectedRoleText, m_lastAlpcResult.queryPort);
        }
        else if (selectedRoleText == QStringLiteral("Connection"))
        {
            selectedPortDetailText = buildPortDetail(selectedRoleText, m_lastAlpcResult.connectionPort);
        }
        else if (selectedRoleText == QStringLiteral("Server"))
        {
            selectedPortDetailText = buildPortDetail(selectedRoleText, m_lastAlpcResult.serverPort);
        }
        else if (selectedRoleText == QStringLiteral("Client"))
        {
            selectedPortDetailText = buildPortDetail(selectedRoleText, m_lastAlpcResult.clientPort);
        }
    }

    ks::ui::FieldDocument document;
    document.note(QStringLiteral("ALPC Port Detail"));
    document.field(QStringLiteral("当前角色"), QStringLiteral("%1").arg(selectedRoleText));
    document.section(QStringLiteral("Selected"));
    document.nodes += selectedPortDetailText.nodes;
    document.section(QStringLiteral("Status"));
    document.field(QStringLiteral("QueryStatus"), QStringLiteral("%1").arg(statusText(m_lastAlpcResult.queryStatus)));
    document.field(QStringLiteral("ObjectReferenceStatus"), QStringLiteral("%1").arg(statusText(m_lastAlpcResult.objectReferenceStatus)));
    document.field(QStringLiteral("TypeStatus"), QStringLiteral("%1").arg(statusText(m_lastAlpcResult.typeStatus)));
    document.field(QStringLiteral("BasicStatus"), QStringLiteral("%1").arg(statusText(m_lastAlpcResult.basicStatus)));
    document.field(QStringLiteral("CommunicationStatus"), QStringLiteral("%1").arg(statusText(m_lastAlpcResult.communicationStatus)));
    document.field(QStringLiteral("NameStatus"), QStringLiteral("%1").arg(statusText(m_lastAlpcResult.nameStatus)));
    document.field(QStringLiteral("DynDataCapabilityMask"), QStringLiteral("%1").arg(formatHex64(m_lastAlpcResult.dynDataCapabilityMask)));
    document.field(QStringLiteral("Offsets"), QStringLiteral("CommunicationInfo=%1 OwnerProcess=%2 ConnectionPort=%3 ServerCommunicationPort=%4 ClientCommunicationPort=%5 HandleTable=%6 HandleTableLock=%7 Attributes=%8 AttributesFlags=%9 PortContext=%10 PortObjectLock=%11 SequenceNo=%12 State=%13").arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcCommunicationInfoOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcOwnerProcessOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcConnectionPortOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcServerCommunicationPortOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcClientCommunicationPortOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcHandleTableOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcHandleTableLockOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcAttributesOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcAttributesFlagsOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcPortContextOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcPortObjectLockOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcSequenceNoOffset)).arg(QStringLiteral("%1").arg(m_lastAlpcResult.alpcStateOffset)));
    document.section(QStringLiteral("All Ports"));
    document.section(QStringLiteral("Query"));
    document.nodes += buildPortDetail(QStringLiteral("Query"), m_lastAlpcResult.queryPort).nodes;
    document.section(QStringLiteral("Connection"));
    document.nodes += buildPortDetail(QStringLiteral("Connection"), m_lastAlpcResult.connectionPort).nodes;
    document.section(QStringLiteral("Server"));
    document.nodes += buildPortDetail(QStringLiteral("Server"), m_lastAlpcResult.serverPort).nodes;
    document.section(QStringLiteral("Client"));
    document.nodes += buildPortDetail(QStringLiteral("Client"), m_lastAlpcResult.clientPort).nodes;
    return document;
}

void KernelDockIpcTab::updateAlpcDetailForRow(const int rowIndex)
{
    // updateAlpcDetailForRow：
    // - 作用：响应 ALPC 表选择变化，刷新 CodeEditorWidget；
    // - 输入：ALPC 表当前行号；
    // - 输出：更新只读详情文本；无返回值。
    if (m_alpcDetailEditor == nullptr || !m_lastAlpcResult.io.ok)
    {
        return;
    }

    m_alpcDetailEditor->setDocument(buildAlpcDetail(rowIndex));
}

ks::ui::FieldDocument KernelDockIpcTab::buildIpcSummaryDetail(const int rowIndex) const
{
    // buildIpcSummaryDetail：
    // - 作用：把固定 IPC summary 响应和表格当前行组合成详情区文本；
    // - 输入：summary 表当前行号，-1 或越界时仅输出响应级信息；
    // - 返回：QString，多行只读文本，不触发任何驱动查询。
    QString categoryText = kernelText("kernel.ipc.placeholder.unselected", QStringLiteral("<未选择>"));
    QString statusTextValue = kernelText("kernel.ipc.placeholder.unselected", QStringLiteral("<未选择>"));
    QString countText = kernelText("kernel.ipc.placeholder.unselected", QStringLiteral("<未选择>"));
    QString sourceText = kernelText("kernel.ipc.placeholder.unselected", QStringLiteral("<未选择>"));
    QString rowDetailText = kernelText("kernel.ipc.summary.placeholder.unselected_row", QStringLiteral("<未选择 IPC summary 行>"));

    if (m_ipcSummaryTable != nullptr && rowIndex >= 0 && rowIndex < m_ipcSummaryTable->rowCount())
    {
        // 表格行快照：
        // - 输入：当前行的五个可见列；
        // - 处理：空指针单元格转为空字符串；
        // - 返回：用于详情区的行级摘要字段。
        const QTableWidgetItem* categoryItem = m_ipcSummaryTable->item(rowIndex, static_cast<int>(IpcSummaryColumn::Category));
        const QTableWidgetItem* statusItem = m_ipcSummaryTable->item(rowIndex, static_cast<int>(IpcSummaryColumn::Status));
        const QTableWidgetItem* countItem = m_ipcSummaryTable->item(rowIndex, static_cast<int>(IpcSummaryColumn::Count));
        const QTableWidgetItem* sourceItem = m_ipcSummaryTable->item(rowIndex, static_cast<int>(IpcSummaryColumn::Source));
        const QTableWidgetItem* detailItem = m_ipcSummaryTable->item(rowIndex, static_cast<int>(IpcSummaryColumn::Detail));

        categoryText = categoryItem != nullptr ? categoryItem->text() : QString();
        statusTextValue = statusItem != nullptr ? statusItem->text() : QString();
        countText = countItem != nullptr ? countItem->text() : QString();
        sourceText = sourceItem != nullptr ? sourceItem->text() : QString();
        rowDetailText = detailItem != nullptr ? detailItem->text() : QString();
    }

    const QString readableIoMessage = friendlyIpcIoMessage(stdStringToQString(m_lastIpcSummaryResult.io.message));
    if (!m_lastIpcSummaryResult.io.ok)
    {
        // 失败详情：
        // - 输入：ArkDriverClient 的 IO 结果；
        // - 处理：转换为用户可读状态，不直接展示底层 DeviceIoControl 噪声；
        // - 返回：包含 Win32/字节数/unsupported 的诊断文本。
        { ks::ui::FieldDocument document;
        document.note(QStringLiteral("IPC Summary Detail"));
        document.field(QStringLiteral("当前行"), QStringLiteral("%1").arg(categoryText));
        document.field(QStringLiteral("行状态"), QStringLiteral("%1").arg(statusTextValue));
        document.field(QStringLiteral("行计数"), QStringLiteral("%1").arg(countText));
        document.field(QStringLiteral("来源"), QStringLiteral("%1").arg(sourceText));
        document.field(QStringLiteral("行详情"), QStringLiteral("%1").arg(rowDetailText));
        document.field(QStringLiteral("查询结果"), QStringLiteral("%1").arg(m_lastIpcSummaryResult.io.ok ? QStringLiteral("OK") : QStringLiteral("Unavailable")));
        document.field(QStringLiteral("Unsupported"), QStringLiteral("%1").arg(m_lastIpcSummaryResult.unsupported
                ? kernelText("kernel.ipc.value.yes", QStringLiteral("是"))
                : kernelText("kernel.ipc.value.no", QStringLiteral("否"))));
        document.field(QStringLiteral("Win32Error"), QStringLiteral("%1").arg(m_lastIpcSummaryResult.io.win32Error));
        document.field(QStringLiteral("BytesReturned"), QStringLiteral("%1").arg(m_lastIpcSummaryResult.io.bytesReturned));
        document.field(QStringLiteral("说明"), QStringLiteral("%1").arg(readableIoMessage));
        return document; }
    }

    const auto& response = m_lastIpcSummaryResult.response;
    const QString objectDetailText = safeText(
        fixedWideText(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS),
        kernelText("kernel.ipc.summary.object_detail_unavailable", QStringLiteral("驱动未提供额外对象详情")));
    const QString alpcTypeText = safeText(
        fixedWideText(response.alpcTypeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS),
        kernelText("kernel.ipc.summary.placeholder.type_name", QStringLiteral("<未返回类型名>")));

    // 成功详情：
    // - 输入：R0 固定 summary 响应、当前表格行和友好化 IO 文本；
    // - 处理：把摘要行扩展为 response/status/identity/dyndata 四组信息；
    // - 返回：详情区文本，避免用户只能看到一行摘要。
    { ks::ui::FieldDocument document;
        document.note(QStringLiteral("IPC Summary Detail"));
        document.field(QStringLiteral("当前行"), QStringLiteral("%1").arg(categoryText));
        document.field(QStringLiteral("行状态"), QStringLiteral("%1").arg(statusTextValue));
        document.field(QStringLiteral("行计数"), QStringLiteral("%1").arg(countText));
        document.field(QStringLiteral("来源"), QStringLiteral("%1").arg(sourceText));
        document.field(QStringLiteral("行详情"), QStringLiteral("%1").arg(rowDetailText));
        document.section(QStringLiteral("Response"));
        document.field(QStringLiteral("SummaryStatus"), QStringLiteral("%1").arg(ipcSummaryStatusText(response.status)));
        document.field(QStringLiteral("ALPCStatus"), QStringLiteral("%1").arg(ipcSummaryStatusText(response.alpcStatus)));
        document.field(QStringLiteral("NamedPipeStatus"), QStringLiteral("%1").arg(ipcSummaryStatusText(response.namedPipeStatus)));
        document.field(QStringLiteral("MailslotStatus"), QStringLiteral("%1").arg(ipcSummaryStatusText(response.mailslotStatus)));
        document.field(QStringLiteral("FieldFlags"), QStringLiteral("%1").arg(formatHex32(response.fieldFlags)));
        document.field(QStringLiteral("LastStatus"), QStringLiteral("%1").arg(statusText(response.lastStatus)));
        document.field(QStringLiteral("BytesReturned"), QStringLiteral("%1").arg(m_lastIpcSummaryResult.io.bytesReturned));
        document.field(QStringLiteral("说明"), QStringLiteral("%1").arg(readableIoMessage));
        document.section(QStringLiteral("Target"));
        document.field(QStringLiteral("ProcessId"), QStringLiteral("%1").arg(response.processId));
        document.field(QStringLiteral("HandleValue"), QStringLiteral("%1").arg(formatHex64(response.handleValue)));
        document.field(QStringLiteral("AlpcObjectAddress"), QStringLiteral("%1").arg(formatHex64(response.alpcObjectAddress)));
        document.field(QStringLiteral("AlpcTypeName"), QStringLiteral("%1").arg(alpcTypeText));
        document.field(QStringLiteral("DynDataCapabilityMask"), QStringLiteral("%1").arg(formatHex64(response.dynDataCapabilityMask)));
        document.section(QStringLiteral("ObjectDetail"));
        document.note(QStringLiteral("%1").arg(objectDetailText));
        return document; }
}

void KernelDockIpcTab::updateIpcSummaryDetailForRow(const int rowIndex)
{
    // updateIpcSummaryDetailForRow：
    // - 作用：响应 summary 表选择变化，把当前行展开到 CodeEditorWidget；
    // - 输入：summary 表行号；
    // - 输出：更新 m_alpcDetailEditor；无返回值，不修改任何系统对象。
    if (m_alpcDetailEditor == nullptr)
    {
        return;
    }

    m_alpcDetailEditor->setDocument(buildIpcSummaryDetail(rowIndex));
}

void KernelDockIpcTab::copyAlpcCurrentRow() const
{
    if (m_alpcTable == nullptr || QApplication::clipboard() == nullptr)
    {
        return;
    }

    const int rowIndex = m_alpcTable->currentRow();
    if (rowIndex < 0)
    {
        return;
    }

    QStringList fields;
    for (int columnIndex = 0; columnIndex < m_alpcTable->columnCount(); ++columnIndex)
    {
        const QTableWidgetItem* item = m_alpcTable->item(rowIndex, columnIndex);
        fields.push_back(item != nullptr ? item->text() : QString());
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

void KernelDockIpcTab::copyIpcSummaryCurrentRow() const
{
    // copyIpcSummaryCurrentRow：
    // - 输入：当前 IPC summary 表选中行；
    // - 处理：把可见列按 Tab 拼接写入剪贴板；
    // - 返回：无；空表或无剪贴板时直接返回，避免 UI 弹错。
    if (m_ipcSummaryTable == nullptr || QApplication::clipboard() == nullptr)
    {
        return;
    }

    const int rowIndex = m_ipcSummaryTable->currentRow();
    if (rowIndex < 0)
    {
        return;
    }

    QStringList fields;
    for (int columnIndex = 0; columnIndex < m_ipcSummaryTable->columnCount(); ++columnIndex)
    {
        const QTableWidgetItem* item = m_ipcSummaryTable->item(rowIndex, columnIndex);
        fields.push_back(item != nullptr ? item->text() : QString());
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

QString KernelDockIpcTab::formatHex32(const std::uint32_t value)
{
    return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')).toUpper();
}

QString KernelDockIpcTab::formatHex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 16, 16, QChar('0')).toUpper();
}

QString KernelDockIpcTab::statusText(long statusValue)
{
    return formatHex32(static_cast<std::uint32_t>(statusValue));
}
