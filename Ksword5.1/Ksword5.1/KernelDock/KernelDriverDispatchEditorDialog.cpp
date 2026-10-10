#include "KernelDriverDispatchEditorDialog.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/VisibleTableWidget.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum Column : int
    {
        ColumnMajor = 0,
        ColumnSymbol,
        ColumnCurrent,
        ColumnOwner,
        ColumnTransaction,
        ColumnOriginal,
        ColumnApplied,
        ColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString ioMessageText(const std::string& text)
    {
        return QString::fromUtf8(text.c_str(), static_cast<int>(text.size()));
    }
}

KernelDriverDispatchEditorDialog::KernelDriverDispatchEditorDialog(
    const QString& driverObjectName,
    QWidget* parent)
    : QDialog(parent),
      m_requestedDriverName(driverObjectName.trimmed())
{
    initializeUi();
    QTimer::singleShot(0, this, [this]() { refreshDriverSnapshot(); });
}

void KernelDriverDispatchEditorDialog::initializeUi()
{
    setWindowTitle(kernelText(
        "kernel.driver_dispatch.title",
        QStringLiteral("IRP / MajorFunction 编辑器")));
    resize(1180, 760);
    setModal(true);

    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(10, 10, 10, 10);
    rootLayout->setSpacing(7);

    m_riskLabel = new QLabel(
        kernelText(
            "kernel.driver_dispatch.risk",
            QStringLiteral("高风险：这里允许把任意 MajorFunction 槽写成任意指针，不校验地址归属或可执行性。错误值可能立即蓝屏、破坏文件系统或安全产品；修改 KSword 自身 IRP_MJ_DEVICE_CONTROL 会切断后续查询与恢复通道。")),
        this);
    m_riskLabel->setWordWrap(true);
    m_riskLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:700;border:1px solid %1;padding:7px;")
            .arg(KswordTheme::ErrorHex()));
    rootLayout->addWidget(m_riskLabel);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        kernelText("kernel.driver_dispatch.refresh", QStringLiteral("刷新 DriverObject")),
        this);
    m_querySlotButton = new QPushButton(
        kernelText("kernel.driver_dispatch.query_slot", QStringLiteral("查询选中槽事务")),
        this);
    m_refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    m_querySlotButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    m_identityLabel = new QLabel(this);
    m_identityLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_identityLabel->setWordWrap(true);
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_querySlotButton);
    toolbar->addWidget(m_identityLabel, 1);
    ks::ui::NormalizeToolbarRow(toolbar);
    rootLayout->addLayout(toolbar);

    m_table = new QTableWidget(this);
    // 派遣事务表已有按记录恢复机制，隐藏无关全局快照栏。
    ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::None);
    m_table->setColumnCount(ColumnCount);
    m_table->setHorizontalHeaderLabels({
        kernelText("kernel.driver_dispatch.header.major", QStringLiteral("Major")),
        kernelText("kernel.driver_dispatch.header.symbol", QStringLiteral("IRP_MJ_*")),
        kernelText("kernel.driver_dispatch.header.current", QStringLiteral("当前入口")),
        kernelText("kernel.driver_dispatch.header.owner", QStringLiteral("当前归属模块")),
        kernelText("kernel.driver_dispatch.header.transaction", QStringLiteral("事务状态")),
        kernelText("kernel.driver_dispatch.header.original", QStringLiteral("记录原值")),
        kernelText("kernel.driver_dispatch.header.applied", QStringLiteral("已应用值")),
    });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setStyleSheet(
        QStringLiteral(
            "QTableWidget{background:transparent;color:%1;}"
            "QHeaderView::section{color:%2;background:transparent;border:1px solid %3;font-weight:600;}")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex()));
    m_table->setColumnWidth(ColumnMajor, 82);
    m_table->setColumnWidth(ColumnSymbol, 230);
    m_table->setColumnWidth(ColumnCurrent, 185);
    m_table->setColumnWidth(ColumnOwner, 180);
    m_table->setColumnWidth(ColumnTransaction, 135);
    m_table->setColumnWidth(ColumnOriginal, 185);
    rootLayout->addWidget(m_table, 1);

    auto* actionLayout = new QGridLayout();
    auto* desiredLabel = new QLabel(
        kernelText(
            "kernel.driver_dispatch.desired.label",
            QStringLiteral("目标指针（支持 0、十进制或 0x 十六进制）：")),
        this);
    m_desiredAddressEdit = new QLineEdit(this);
    m_desiredAddressEdit->setPlaceholderText(QStringLiteral("0xFFFFF80000000000"));
    m_applyButton = new QPushButton(
        kernelText("kernel.driver_dispatch.apply", QStringLiteral("原子应用")),
        this);
    m_restoreButton = new QPushButton(
        kernelText("kernel.driver_dispatch.restore", QStringLiteral("按记录恢复")),
        this);
    m_abandonButton = new QPushButton(
        kernelText("kernel.driver_dispatch.abandon", QStringLiteral("放弃恢复记录")),
        this);
    m_refreshButton->setToolTip(
        kernelText(
            "kernel.driver_dispatch.refresh.tooltip",
            QStringLiteral("重新读取该驱动对象当前的各个处理函数入口")));
    m_querySlotButton->setToolTip(
        kernelText(
            "kernel.driver_dispatch.query_slot.tooltip",
            QStringLiteral("查看选中项的历史修改记录与当前事务状态")));
    m_applyButton->setToolTip(
        kernelText(
            "kernel.driver_dispatch.apply.tooltip",
            QStringLiteral("把上面填写的地址一次性写入选中项（会改变驱动的处理流程，可能导致系统不稳定或蓝屏）")));
    m_restoreButton->setToolTip(
        kernelText(
            "kernel.driver_dispatch.restore.tooltip",
            QStringLiteral("按之前保存的记录把该项恢复为原始入口")));
    m_abandonButton->setToolTip(
        kernelText(
            "kernel.driver_dispatch.abandon.tooltip",
            QStringLiteral("丢弃保存的恢复记录；丢弃后将无法再自动还原该项")));
    for (QPushButton* button : { m_applyButton, m_restoreButton, m_abandonButton })
    {
        button->setStyleSheet(KswordTheme::ThemedButtonStyle());
    }
    actionLayout->addWidget(desiredLabel, 0, 0);
    actionLayout->addWidget(m_desiredAddressEdit, 0, 1);
    actionLayout->addWidget(m_applyButton, 0, 2);
    actionLayout->addWidget(m_restoreButton, 0, 3);
    actionLayout->addWidget(m_abandonButton, 0, 4);
    actionLayout->setColumnStretch(1, 1);
    actionLayout->setHorizontalSpacing(8);
    // 事务输入行保留原栅格，只对明确的单行编辑控件统一尺寸。
    ks::ui::NormalizeToolbarControl(m_desiredAddressEdit);
    ks::ui::NormalizeToolbarControl(m_applyButton);
    ks::ui::NormalizeToolbarControl(m_restoreButton);
    ks::ui::NormalizeToolbarControl(m_abandonButton);
    rootLayout->addLayout(actionLayout);

    m_statusLabel = new QLabel(
        kernelText("kernel.driver_dispatch.status.waiting", QStringLiteral("状态：等待查询")),
        this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rootLayout->addWidget(m_statusLabel);

    auto* closeLayout = new QHBoxLayout();
    closeLayout->addStretch(1);
    auto* closeButton = new QPushButton(
        kernelText("kernel.driver_dispatch.close", QStringLiteral("关闭")),
        this);
    closeButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    closeLayout->addWidget(closeButton);
    ks::ui::NormalizeToolbarRow(closeLayout);
    rootLayout->addLayout(closeLayout);

    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        refreshDriverSnapshot();
    });
    connect(m_querySlotButton, &QPushButton::clicked, this, [this]() {
        refreshSelectedTransaction();
    });
    connect(m_applyButton, &QPushButton::clicked, this, [this]() {
        applySelectedDispatch();
    });
    connect(m_restoreButton, &QPushButton::clicked, this, [this]() {
        restoreSelectedDispatch();
    });
    connect(m_abandonButton, &QPushButton::clicked, this, [this]() {
        abandonSelectedRecord();
    });
    connect(m_table, &QTableWidget::itemSelectionChanged, this, [this]() {
        const int row = selectedRow();
        if (row >= 0)
        {
            const QTableWidgetItem* currentItem = m_table->item(row, ColumnCurrent);
            m_desiredAddressEdit->setText(currentItem != nullptr
                ? currentItem->text()
                : QString());
            refreshSelectedTransaction();
        }
    });
    setActionsEnabled(false);
}

void KernelDriverDispatchEditorDialog::refreshDriverSnapshot()
{
    setActionsEnabled(false);
    setStatus(
        kernelText("kernel.driver_dispatch.status.querying", QStringLiteral("状态：正在查询 DriverObject...")),
        KswordTheme::PrimaryBlueHex);

    const ksword::ark::DriverClient client;
    const auto result = client.queryDriverObject(m_requestedDriverName.toStdWString());
    if (!result.io.ok)
    {
        setStatus(
            kernelText(
                "kernel.driver_dispatch.status.driver_query_failed",
                QStringLiteral("状态：DriverObject 查询失败：%1"))
                .arg(ioMessageText(result.io.message)),
            KswordTheme::ErrorHex());
        return;
    }
    if (result.lastStatus < 0 || result.driverObjectAddress == 0U || result.driverStart == 0U)
    {
        setStatus(
            kernelText(
                "kernel.driver_dispatch.status.driver_unavailable",
                QStringLiteral("状态：R0 未返回可编辑身份，NTSTATUS=%1"))
                .arg(ntStatusText(result.lastStatus)),
            KswordTheme::ErrorHex());
        return;
    }

    m_canonicalDriverName = result.driverName.empty()
        ? m_requestedDriverName
        : QString::fromStdWString(result.driverName);
    m_moduleBase = result.driverStart;
    m_driverObjectAddress = result.driverObjectAddress;
    m_identityLabel->setText(
        kernelText(
            "kernel.driver_dispatch.identity",
            QStringLiteral("对象：%1    DriverObject=%2    ImageBase=%3"))
            .arg(
                m_canonicalDriverName,
                pointerText(m_driverObjectAddress),
                pointerText(m_moduleBase)));

    {
        const QSignalBlocker blocker(m_table);
        const std::uint32_t previousMajor = selectedMajorFunction();
        m_table->setRowCount(0);
        for (const auto& entry : result.majorFunctions)
        {
            const int row = m_table->rowCount();
            m_table->insertRow(row);
            auto* majorItem = readOnlyItem(
                QStringLiteral("0x%1").arg(entry.majorFunction, 2, 16, QChar('0')).toUpper());
            majorItem->setData(Qt::UserRole, entry.majorFunction);
            m_table->setItem(row, ColumnMajor, majorItem);
            m_table->setItem(row, ColumnSymbol, readOnlyItem(majorFunctionName(entry.majorFunction)));
            m_table->setItem(row, ColumnCurrent, readOnlyItem(pointerText(entry.dispatchAddress)));
            m_table->setItem(row, ColumnOwner, readOnlyItem(
                entry.moduleName.empty()
                    ? pointerText(entry.moduleBase)
                    : QString::fromStdWString(entry.moduleName)));
            m_table->setItem(row, ColumnTransaction, readOnlyItem(
                kernelText("kernel.driver_dispatch.state.unqueried", QStringLiteral("未查询"))));
            m_table->setItem(row, ColumnOriginal, readOnlyItem(QStringLiteral("-")));
            m_table->setItem(row, ColumnApplied, readOnlyItem(QStringLiteral("-")));
        }

        int selectRow = 0;
        for (int row = 0; row < m_table->rowCount(); ++row)
        {
            const QTableWidgetItem* item = m_table->item(row, ColumnMajor);
            if (item != nullptr && item->data(Qt::UserRole).toUInt() == previousMajor)
            {
                selectRow = row;
                break;
            }
        }
        if (m_table->rowCount() > 0)
        {
            m_table->selectRow(selectRow);
        }
    }
    setActionsEnabled(m_table->rowCount() > 0);
    setStatus(
        kernelText(
            "kernel.driver_dispatch.status.driver_ready",
            QStringLiteral("状态：已读取 %1 个 MajorFunction 槽；请选择槽位查询事务状态。"))
            .arg(m_table->rowCount()),
        KswordTheme::SuccessHex());
    if (m_table->rowCount() > 0)
    {
        (void)refreshSelectedTransaction();
    }
}

bool KernelDriverDispatchEditorDialog::refreshSelectedTransaction()
{
    const int row = selectedRow();
    if (row < 0 || m_moduleBase == 0U || m_driverObjectAddress == 0U)
    {
        return false;
    }

    const std::uint32_t major = selectedMajorFunction();
    const ksword::ark::DriverClient client;
    const auto result = client.queryDriverDispatch(
        m_moduleBase,
        m_canonicalDriverName.toStdWString(),
        major,
        m_driverObjectAddress);
    if (!result.io.ok)
    {
        setStatus(
            kernelText(
                "kernel.driver_dispatch.status.slot_query_failed",
                QStringLiteral("状态：槽位事务查询失败：%1"))
                .arg(ioMessageText(result.io.message)),
            KswordTheme::ErrorHex());
        return false;
    }

    m_currentDispatchAddress = result.currentDispatchAddress;
    m_generation = result.generation;
    m_responseFlags = result.responseFlags;
    m_table->setItem(row, ColumnCurrent, readOnlyItem(pointerText(result.currentDispatchAddress)));
    m_table->setItem(row, ColumnOriginal, readOnlyItem(
        (result.responseFlags & KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_RECORD_PRESENT) != 0U
            ? pointerText(result.originalDispatchAddress)
            : QStringLiteral("-")));
    m_table->setItem(row, ColumnApplied, readOnlyItem(
        (result.responseFlags & KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_RECORD_PRESENT) != 0U
            ? pointerText(result.appliedDispatchAddress)
            : QStringLiteral("-")));

    QString stateText;
    if (result.state == KSWORD_ARK_DRIVER_DISPATCH_STATE_CONFLICT)
    {
        stateText = kernelText("kernel.driver_dispatch.state.conflict", QStringLiteral("外部冲突"));
    }
    else if (result.state == KSWORD_ARK_DRIVER_DISPATCH_STATE_ACTIVE)
    {
        stateText = kernelText("kernel.driver_dispatch.state.active", QStringLiteral("已接管"));
    }
    else
    {
        stateText = kernelText("kernel.driver_dispatch.state.inactive", QStringLiteral("无活动修改"));
    }
    m_table->setItem(row, ColumnTransaction, readOnlyItem(stateText));
    m_desiredAddressEdit->setText(pointerText(result.currentDispatchAddress));
    setStatus(
        kernelText(
            "kernel.driver_dispatch.status.slot_ready",
            QStringLiteral("状态：Major=0x%1，%2，generation=%3，NTSTATUS=%4"))
            .arg(major, 2, 16, QChar('0'))
            .arg(stateText)
            .arg(result.generation)
            .arg(ntStatusText(result.lastStatus)),
        result.lastStatus < 0 ? KswordTheme::ErrorHex() : KswordTheme::SuccessHex());
    const bool querySucceeded = result.lastStatus >= 0;
    const bool recordPresent =
        (result.responseFlags &
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_RECORD_PRESENT) != 0U;
    m_querySlotButton->setEnabled(true);
    m_desiredAddressEdit->setEnabled(querySucceeded);
    m_applyButton->setEnabled(querySucceeded);
    m_restoreButton->setEnabled(querySucceeded && recordPresent);
    m_abandonButton->setEnabled(querySucceeded && recordPresent);
    return querySucceeded;
}

void KernelDriverDispatchEditorDialog::applySelectedDispatch()
{
    std::uint64_t desiredAddress = 0;
    const std::uint32_t major = selectedMajorFunction();
    if (selectedRow() < 0 || !parsePointer(m_desiredAddressEdit->text(), desiredAddress))
    {
        QMessageBox::warning(
            this,
            windowTitle(),
            kernelText(
                "kernel.driver_dispatch.invalid_pointer",
                QStringLiteral("目标指针格式无效。允许值包括 0、十进制和 0x 十六进制。")));
        return;
    }

    if (!refreshSelectedTransaction())
    {
        return;
    }
    const bool selfControlChannel =
        (m_responseFlags &
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_SELF_CONTROL_CHANNEL) != 0U;
    QString warningText = kernelText(
        "kernel.driver_dispatch.apply.warning",
        QStringLiteral("即将把 %1 的 %2 从 %3 原子替换为 %4。\n\nR0 不会检查目标地址是否映射、可执行、ABI 匹配或属于目标驱动。目标下一次收到该 IRP 时可能立即蓝屏或损坏数据。是否继续？"))
        .arg(
            m_canonicalDriverName,
            majorFunctionName(major),
            pointerText(m_currentDispatchAddress),
            pointerText(desiredAddress));
    if (selfControlChannel)
    {
        warningText += kernelText(
            "kernel.driver_dispatch.apply.self_channel_warning",
            QStringLiteral(
                "\n\n这是 KSword 自身 IRP_MJ_DEVICE_CONTROL：写入成功后当前程序通常无法再发送查询、恢复或放弃请求，只能依赖外部恢复或重新加载驱动。"));
    }
    if (QMessageBox::warning(
        this,
        windowTitle(),
        warningText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    const ksword::ark::DriverClient client;
    const auto result = client.applyDriverDispatch(
        m_moduleBase,
        m_canonicalDriverName.toStdWString(),
        major,
        m_driverObjectAddress,
        m_currentDispatchAddress,
        desiredAddress,
        m_generation);
    if (!result.io.ok)
    {
        setStatus(ioMessageText(result.io.message), KswordTheme::ErrorHex());
        return;
    }
    const QString resultText = kernelText(
        "kernel.driver_dispatch.status.apply_result",
        QStringLiteral("状态：应用完成，NTSTATUS=%1；current=%2；generation=%3"))
        .arg(ntStatusText(result.lastStatus))
        .arg(pointerText(result.currentDispatchAddress))
        .arg(result.generation);
    if (!selfControlChannel && result.lastStatus >= 0)
    {
        refreshDriverSnapshot();
    }
    setStatus(
        resultText,
        result.lastStatus >= 0
            ? KswordTheme::WarningHex()
            : KswordTheme::ErrorHex());
}

void KernelDriverDispatchEditorDialog::restoreSelectedDispatch()
{
    if (selectedRow() < 0)
    {
        return;
    }
    if (!refreshSelectedTransaction())
    {
        return;
    }
    const ksword::ark::DriverClient client;
    const auto result = client.restoreDriverDispatch(
        m_moduleBase,
        m_canonicalDriverName.toStdWString(),
        selectedMajorFunction(),
        m_driverObjectAddress,
        m_generation);
    if (!result.io.ok)
    {
        setStatus(ioMessageText(result.io.message), KswordTheme::ErrorHex());
        return;
    }
    const QString resultText = kernelText(
        "kernel.driver_dispatch.status.restore_result",
        QStringLiteral("状态：恢复请求完成，NTSTATUS=%1；current=%2；generation=%3"))
        .arg(ntStatusText(result.lastStatus))
        .arg(pointerText(result.currentDispatchAddress))
        .arg(result.generation);
    if (result.lastStatus >= 0)
    {
        refreshDriverSnapshot();
    }
    setStatus(
        resultText,
        result.lastStatus >= 0
            ? KswordTheme::SuccessHex()
            : KswordTheme::ErrorHex());
}

void KernelDriverDispatchEditorDialog::abandonSelectedRecord()
{
    if (selectedRow() < 0)
    {
        return;
    }
    if (!refreshSelectedTransaction())
    {
        return;
    }
    if (QMessageBox::warning(
        this,
        windowTitle(),
        kernelText(
            "kernel.driver_dispatch.abandon.warning",
            QStringLiteral("放弃记录不会修改当前 MajorFunction 指针，但会永久丢弃 KSword 保存的原值和自动恢复资格。仅在外部冲突已由你人工处理，或你明确希望保留当前指针时使用。")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }
    const ksword::ark::DriverClient client;
    const auto result = client.abandonDriverDispatch(
        m_moduleBase,
        m_canonicalDriverName.toStdWString(),
        selectedMajorFunction(),
        m_driverObjectAddress,
        m_generation);
    if (!result.io.ok)
    {
        setStatus(ioMessageText(result.io.message), KswordTheme::ErrorHex());
        return;
    }
    const QString resultText = kernelText(
        "kernel.driver_dispatch.status.abandon_result",
        QStringLiteral("状态：放弃记录完成，NTSTATUS=%1；当前指针保持 %2"))
        .arg(ntStatusText(result.lastStatus))
        .arg(pointerText(result.currentDispatchAddress));
    if (result.lastStatus >= 0)
    {
        refreshDriverSnapshot();
    }
    setStatus(
        resultText,
        result.lastStatus >= 0
            ? KswordTheme::WarningHex()
            : KswordTheme::ErrorHex());
}

void KernelDriverDispatchEditorDialog::setActionsEnabled(const bool enabled)
{
    m_querySlotButton->setEnabled(enabled);
    m_applyButton->setEnabled(enabled);
    m_restoreButton->setEnabled(enabled);
    m_abandonButton->setEnabled(enabled);
    m_desiredAddressEdit->setEnabled(enabled);
}

void KernelDriverDispatchEditorDialog::setStatus(
    const QString& text,
    const QString& colorHex)
{
    m_statusLabel->setText(text);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(colorHex));
}

int KernelDriverDispatchEditorDialog::selectedRow() const
{
    return m_table != nullptr ? m_table->currentRow() : -1;
}

std::uint32_t KernelDriverDispatchEditorDialog::selectedMajorFunction() const
{
    const int row = selectedRow();
    const QTableWidgetItem* item =
        row >= 0 && m_table != nullptr ? m_table->item(row, ColumnMajor) : nullptr;
    return item != nullptr ? item->data(Qt::UserRole).toUInt() : 0U;
}

QString KernelDriverDispatchEditorDialog::pointerText(const std::uint64_t address)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(address), 16, 16, QChar('0'))
        .toUpper();
}

QString KernelDriverDispatchEditorDialog::ntStatusText(const long status)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(status)), 8, 16, QChar('0'))
        .toUpper();
}

QString KernelDriverDispatchEditorDialog::majorFunctionName(
    const std::uint32_t majorFunction)
{
    static const char* const names[] = {
        "IRP_MJ_CREATE", "IRP_MJ_CREATE_NAMED_PIPE", "IRP_MJ_CLOSE",
        "IRP_MJ_READ", "IRP_MJ_WRITE", "IRP_MJ_QUERY_INFORMATION",
        "IRP_MJ_SET_INFORMATION", "IRP_MJ_QUERY_EA", "IRP_MJ_SET_EA",
        "IRP_MJ_FLUSH_BUFFERS", "IRP_MJ_QUERY_VOLUME_INFORMATION",
        "IRP_MJ_SET_VOLUME_INFORMATION", "IRP_MJ_DIRECTORY_CONTROL",
        "IRP_MJ_FILE_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CONTROL",
        "IRP_MJ_INTERNAL_DEVICE_CONTROL", "IRP_MJ_SHUTDOWN",
        "IRP_MJ_LOCK_CONTROL", "IRP_MJ_CLEANUP", "IRP_MJ_CREATE_MAILSLOT",
        "IRP_MJ_QUERY_SECURITY", "IRP_MJ_SET_SECURITY", "IRP_MJ_POWER",
        "IRP_MJ_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CHANGE", "IRP_MJ_QUERY_QUOTA",
        "IRP_MJ_SET_QUOTA", "IRP_MJ_PNP"
    };
    return majorFunction < (sizeof(names) / sizeof(names[0]))
        ? QString::fromLatin1(names[majorFunction])
        : QStringLiteral("IRP_MJ_0x%1").arg(majorFunction, 2, 16, QChar('0')).toUpper();
}

bool KernelDriverDispatchEditorDialog::parsePointer(
    const QString& text,
    std::uint64_t& addressOut)
{
    bool ok = false;
    const qulonglong value = text.trimmed().toULongLong(&ok, 0);
    if (!ok)
    {
        return false;
    }
    addressOut = static_cast<std::uint64_t>(value);
    return true;
}
