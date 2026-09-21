#include "KernelIoctlAuditTab.h"

#include "KernelDeviceDriverObjectsWorker.h"
#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <sstream>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    QString buttonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    QString headerStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;background:transparent;border:1px solid %2;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex());
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

KernelIoctlAuditTab::KernelIoctlAuditTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelIoctlAuditTab::requestInitialRefresh()
{
    if (m_initialRefreshRequested)
    {
        return;
    }

    m_initialRefreshRequested = true;
    refreshAsync();
}

void KernelIoctlAuditTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(kernelText("kernel.ioctl_audit.refresh", QStringLiteral("刷新派遣表")), this);
    m_refreshButton->setStyleSheet(buttonStyle());
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setPlaceholderText(kernelText(
        "kernel.ioctl_audit.filter.placeholder",
        QStringLiteral("筛选驱动、设备、MajorFunction 或地址...")));
    m_filterEdit->setMinimumWidth(280);
    m_clearFilterButton = new QPushButton(
        kernelText("kernel.ioctl_audit.filter.clear", QStringLiteral("清除筛选")),
        this);
    m_clearFilterButton->setStyleSheet(buttonStyle());
    m_statusLabel = new QLabel(kernelText("kernel.ioctl_audit.loading", QStringLiteral("正在加载全局 DriverObject 与 KswordARK IOCTL registry...")), this);
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_filterEdit);
    toolbar->addWidget(m_clearFilterButton);
    toolbar->addWidget(m_statusLabel, 1);
    rootLayout->addLayout(toolbar);

    m_innerTabs = new QTabWidget(this);
    m_driverPage = new QWidget(m_innerTabs);
    m_devicePage = new QWidget(m_innerTabs);
    m_dispatchPage = new QWidget(m_innerTabs);
    m_registryPage = new QWidget(m_innerTabs);
    m_driverTable = new ks::ui::VisibleTableWidget(m_driverPage);
    m_deviceTable = new ks::ui::VisibleTableWidget(m_devicePage);
    m_dispatchTable = new ks::ui::VisibleTableWidget(m_dispatchPage);
    m_registryTable = new ks::ui::VisibleTableWidget(m_registryPage);
    for (QTableWidget* table : {m_driverTable, m_deviceTable, m_dispatchTable, m_registryTable})
    {
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setContextMenuPolicy(Qt::CustomContextMenu);
        table->setStyleSheet(QStringLiteral("QTableWidget{background:transparent;color:%1;}" ).arg(KswordTheme::TextPrimaryHex()));
        table->horizontalHeader()->setStyleSheet(headerStyle());
        table->horizontalHeader()->setStretchLastSection(true);
        table->verticalHeader()->setVisible(false);
    }
    m_driverTable->setColumnCount(9);
    m_driverTable->setHorizontalHeaderLabels({
        kernelText("kernel.ioctl_audit.header.driver", QStringLiteral("DriverObject")),
        kernelText("kernel.ioctl_audit.header.object_address", QStringLiteral("对象地址")),
        QStringLiteral("DriverStart"),
        kernelText("kernel.ioctl_audit.header.image_size", QStringLiteral("镜像大小")),
        kernelText("kernel.ioctl_audit.header.flags", QStringLiteral("Flags")),
        kernelText("kernel.ioctl_audit.header.devices", QStringLiteral("设备数")),
        kernelText("kernel.ioctl_audit.header.major_count", QStringLiteral("MajorFunction 数")),
        kernelText("kernel.ioctl_audit.header.query_status", QStringLiteral("查询状态")),
        QStringLiteral("NTSTATUS")});
    m_deviceTable->setColumnCount(13);
    m_deviceTable->setHorizontalHeaderLabels({
        kernelText("kernel.ioctl_audit.header.driver", QStringLiteral("DriverObject")),
        kernelText("kernel.ioctl_audit.header.relation", QStringLiteral("关系")),
        QStringLiteral("DeviceObject"),
        kernelText("kernel.ioctl_audit.header.device_name", QStringLiteral("设备名称")),
        kernelText("kernel.ioctl_audit.header.device_type", QStringLiteral("设备类型")),
        kernelText("kernel.ioctl_audit.header.flags", QStringLiteral("Flags")),
        QStringLiteral("Characteristics"),
        QStringLiteral("StackSize"),
        QStringLiteral("RootDevice"),
        QStringLiteral("NextDevice"),
        QStringLiteral("AttachedDevice"),
        kernelText("kernel.ioctl_audit.header.owner_driver", QStringLiteral("归属 DriverObject")),
        QStringLiteral("NameStatus")});
    m_dispatchTable->setColumnCount(9);
    m_dispatchTable->setHorizontalHeaderLabels({
        kernelText("kernel.ioctl_audit.header.driver", QStringLiteral("DriverObject")),
        kernelText("kernel.ioctl_audit.header.object_address", QStringLiteral("对象地址")),
        kernelText("kernel.ioctl_audit.header.major", QStringLiteral("MajorFunction")),
        kernelText("kernel.ioctl_audit.header.index", QStringLiteral("编号")),
        kernelText("kernel.ioctl_audit.header.dispatch", QStringLiteral("派遣地址")),
        kernelText("kernel.ioctl_audit.header.module_base", QStringLiteral("模块基址")),
        kernelText("kernel.ioctl_audit.header.module", QStringLiteral("归属模块")),
        kernelText("kernel.ioctl_audit.header.flags", QStringLiteral("Flags")),
        kernelText("kernel.ioctl_audit.header.status", QStringLiteral("状态"))});
    m_registryTable->setColumnCount(7);
    m_registryTable->setHorizontalHeaderLabels({
        kernelText("kernel.ioctl_audit.header.code", QStringLiteral("控制码")),
        kernelText("kernel.ioctl_audit.header.function", QStringLiteral("Function")),
        kernelText("kernel.ioctl_audit.header.method_access", QStringLiteral("Method/Access")),
        kernelText("kernel.ioctl_audit.header.capability", QStringLiteral("能力门槛")),
        kernelText("kernel.ioctl_audit.header.handler", QStringLiteral("Handler")),
        kernelText("kernel.ioctl_audit.header.name", QStringLiteral("名称")),
        kernelText("kernel.ioctl_audit.header.flags", QStringLiteral("Flags"))});

    auto* driverLayout = new QVBoxLayout(m_driverPage);
    driverLayout->setContentsMargins(2, 2, 2, 2);
    driverLayout->addWidget(m_driverTable);
    auto* deviceLayout = new QVBoxLayout(m_devicePage);
    deviceLayout->setContentsMargins(2, 2, 2, 2);
    deviceLayout->addWidget(m_deviceTable);
    auto* dispatchLayout = new QVBoxLayout(m_dispatchPage);
    dispatchLayout->setContentsMargins(2, 2, 2, 2);
    dispatchLayout->addWidget(m_dispatchTable);
    auto* registryLayout = new QVBoxLayout(m_registryPage);
    registryLayout->setContentsMargins(2, 2, 2, 2);
    registryLayout->addWidget(m_registryTable);
    m_innerTabs->addTab(m_driverPage, kernelText("kernel.ioctl_audit.tab.drivers", QStringLiteral("驱动概览")));
    m_innerTabs->addTab(m_devicePage, kernelText("kernel.ioctl_audit.tab.devices", QStringLiteral("设备对象")));
    m_innerTabs->addTab(m_dispatchPage, kernelText("kernel.ioctl_audit.tab.dispatch", QStringLiteral("MajorFunction")));
    m_innerTabs->addTab(m_registryPage, kernelText("kernel.ioctl_audit.tab.registry", QStringLiteral("KswordARK IOCTL 注册表")));
    rootLayout->addWidget(m_innerTabs, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this]() { applyFilter(); });
    connect(m_clearFilterButton, &QPushButton::clicked, m_filterEdit, &QLineEdit::clear);
    connect(m_driverTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showCopyMenu(m_driverTable, position);
    });
    connect(m_deviceTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showCopyMenu(m_deviceTable, position);
    });
    connect(m_dispatchTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showCopyMenu(m_dispatchTable, position);
    });
    connect(m_registryTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showCopyMenu(m_registryTable, position);
    });
}

void KernelIoctlAuditTab::refreshAsync()
{
    if (m_refreshRunning)
    {
        return;
    }
    m_refreshRunning = true;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(kernelText("kernel.ioctl_audit.refreshing", QStringLiteral("正在枚举 DriverObject 派遣入口并读取 IOCTL registry...")));
    QPointer<KernelIoctlAuditTab> safeThis(this);
    std::thread([safeThis]() {
        Snapshot snapshot;
        std::vector<KernelDeviceDriverObjectEntry> objectRows;
        QString workerError;
        const bool workerOk = runKernelDeviceDriverObjectsSnapshotTask(objectRows, workerError);
        if (!workerOk)
        {
            snapshot.errorText = workerError;
        }

        ksword::ark::DriverClient client;
        if (workerOk)
        {
            QSet<QString> seenDriverNames;
            for (const KernelDeviceDriverObjectEntry& objectRow : objectRows)
            {
                if (objectRow.isScopeEntry || objectRow.objectTypeText.compare(QStringLiteral("Driver"), Qt::CaseInsensitive) != 0)
                {
                    continue;
                }
                const QString driverPath = objectRow.fullPathText.trimmed();
                const QString normalizedDriverPath = driverPath.toCaseFolded();
                if (driverPath.isEmpty() || seenDriverNames.contains(normalizedDriverPath))
                {
                    continue;
                }
                seenDriverNames.insert(normalizedDriverPath);

                DriverRow driverRow;
                driverRow.driverName = driverPath;
                const std::wstring driverName = driverPath.toStdWString();
                const ksword::ark::DriverObjectQueryResult query = client.queryDriverObject(driverName);
                if (!query.io.ok)
                {
                    ++snapshot.queryFailureCount;
                    driverRow.lastStatus = static_cast<std::int32_t>(query.lastStatus);
                    driverRow.status = query.io.message.empty()
                        ? QStringLiteral("DriverObject 查询失败")
                        : QString::fromStdString(query.io.message);
                    snapshot.driverRows.push_back(std::move(driverRow));
                    continue;
                }

                driverRow.driverObjectAddress = query.driverObjectAddress;
                driverRow.driverStart = query.driverStart;
                driverRow.driverSize = query.driverSize;
                driverRow.driverFlags = query.driverFlags;
                driverRow.majorFunctionCount = query.majorFunctionCount;
                driverRow.returnedDeviceCount = query.returnedDeviceCount;
                driverRow.totalDeviceCount = query.totalDeviceCount;
                driverRow.queryStatus = query.queryStatus;
                driverRow.lastStatus = static_cast<std::int32_t>(query.lastStatus);
                if (query.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL)
                {
                    ++snapshot.partialDriverCount;
                }
                snapshot.driverRows.push_back(std::move(driverRow));

                for (const ksword::ark::DriverDeviceEntry& device : query.devices)
                {
                    DeviceRow row;
                    row.driverName = driverPath;
                    row.deviceName = QString::fromStdWString(device.deviceName);
                    row.relationDepth = device.relationDepth;
                    row.deviceType = device.deviceType;
                    row.flags = device.flags;
                    row.characteristics = device.characteristics;
                    row.stackSize = device.stackSize;
                    row.nameStatus = static_cast<std::int32_t>(device.nameStatus);
                    row.rootDeviceObjectAddress = device.rootDeviceObjectAddress;
                    row.deviceObjectAddress = device.deviceObjectAddress;
                    row.nextDeviceObjectAddress = device.nextDeviceObjectAddress;
                    row.attachedDeviceObjectAddress = device.attachedDeviceObjectAddress;
                    row.ownerDriverObjectAddress = device.driverObjectAddress;
                    snapshot.deviceRows.push_back(std::move(row));
                }
                for (const ksword::ark::DriverMajorFunctionEntry& major : query.majorFunctions)
                {
                    DispatchRow row;
                    row.driverName = driverPath;
                    row.driverObjectAddress = query.driverObjectAddress;
                    row.majorFunction = major.majorFunction;
                    row.dispatchAddress = major.dispatchAddress;
                    row.moduleBase = major.moduleBase;
                    row.moduleName = QString::fromStdWString(major.moduleName);
                    row.flags = major.flags;
                    snapshot.dispatchRows.push_back(std::move(row));
                }
                if (query.startIo.state != KSWORD_ARK_DRIVER_START_IO_STATE_NOT_QUERIED)
                {
                    DispatchRow row;
                    row.driverName = driverPath;
                    row.driverObjectAddress = query.driverObjectAddress;
                    row.dispatchAddress = query.startIo.address;
                    row.moduleBase = query.startIo.moduleBase;
                    row.moduleName = QString::fromStdWString(query.startIo.moduleName);
                    row.flags = query.startIo.flags;
                    row.isStartIo = true;
                    row.startIoState = query.startIo.state;
                    snapshot.dispatchRows.push_back(std::move(row));
                }
            }
        }

        const ksword::ark::IoctlRegistryQueryResult registry = client.queryIoctlRegistry();
        snapshot.registryOk = registry.io.ok;
        snapshot.registryTotal = registry.totalCount;
        snapshot.registryDuplicate = registry.duplicateCount;
        snapshot.registryRows = registry.entries;
        if (!registry.io.ok && snapshot.errorText.isEmpty())
        {
            snapshot.errorText = registry.io.message.empty()
                ? QStringLiteral("KswordARK IOCTL registry 查询失败")
                : QString::fromStdString(registry.io.message);
        }

        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(safeThis, [safeThis, snapshot = std::move(snapshot)]() mutable {
            if (safeThis != nullptr)
            {
                safeThis->applySnapshot(std::move(snapshot));
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelIoctlAuditTab::applySnapshot(Snapshot snapshot)
{
    const QPointer<KernelIoctlAuditTab> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-ioctl-audit-snapshot"),
        { m_driverTable, m_deviceTable, m_dispatchTable, m_registryTable },
        [safeThis, snapshot]() mutable
        {
            if (!safeThis.isNull())
            {
                safeThis->applySnapshot(std::move(snapshot));
            }
        }))
    {
        return;
    }

    m_refreshRunning = false;
    m_refreshButton->setEnabled(true);
    m_driverRows = std::move(snapshot.driverRows);
    m_deviceRows = std::move(snapshot.deviceRows);
    m_dispatchRows = std::move(snapshot.dispatchRows);
    m_registryRows = std::move(snapshot.registryRows);
    m_queryFailureCount = snapshot.queryFailureCount;
    m_partialDriverCount = snapshot.partialDriverCount;
    m_registryTotal = snapshot.registryTotal;
    m_registryDuplicate = snapshot.registryDuplicate;
    m_registryOk = snapshot.registryOk;
    m_errorText = std::move(snapshot.errorText);
    populateTables();
}

QString KernelIoctlAuditTab::hex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0'));
}

QString KernelIoctlAuditTab::hex32(const std::uint32_t value)
{
    return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0'));
}

QString KernelIoctlAuditTab::majorFunctionName(const std::uint32_t value)
{
    switch (value)
    {
    case 0x00: return QStringLiteral("IRP_MJ_CREATE");
    case 0x01: return QStringLiteral("IRP_MJ_CREATE_NAMED_PIPE");
    case 0x02: return QStringLiteral("IRP_MJ_CLOSE");
    case 0x03: return QStringLiteral("IRP_MJ_READ");
    case 0x04: return QStringLiteral("IRP_MJ_WRITE");
    case 0x05: return QStringLiteral("IRP_MJ_QUERY_INFORMATION");
    case 0x06: return QStringLiteral("IRP_MJ_SET_INFORMATION");
    case 0x07: return QStringLiteral("IRP_MJ_QUERY_EA");
    case 0x08: return QStringLiteral("IRP_MJ_SET_EA");
    case 0x09: return QStringLiteral("IRP_MJ_FLUSH_BUFFERS");
    case 0x0A: return QStringLiteral("IRP_MJ_QUERY_VOLUME_INFORMATION");
    case 0x0B: return QStringLiteral("IRP_MJ_SET_VOLUME_INFORMATION");
    case 0x0C: return QStringLiteral("IRP_MJ_DIRECTORY_CONTROL");
    case 0x0D: return QStringLiteral("IRP_MJ_FILE_SYSTEM_CONTROL");
    case 0x0E: return QStringLiteral("IRP_MJ_DEVICE_CONTROL");
    case 0x0F: return QStringLiteral("IRP_MJ_INTERNAL_DEVICE_CONTROL");
    case 0x10: return QStringLiteral("IRP_MJ_SHUTDOWN");
    case 0x11: return QStringLiteral("IRP_MJ_LOCK_CONTROL");
    case 0x12: return QStringLiteral("IRP_MJ_CLEANUP");
    case 0x13: return QStringLiteral("IRP_MJ_CREATE_MAILSLOT");
    case 0x14: return QStringLiteral("IRP_MJ_QUERY_SECURITY");
    case 0x15: return QStringLiteral("IRP_MJ_SET_SECURITY");
    case 0x16: return QStringLiteral("IRP_MJ_POWER");
    case 0x17: return QStringLiteral("IRP_MJ_SYSTEM_CONTROL");
    case 0x18: return QStringLiteral("IRP_MJ_DEVICE_CHANGE");
    case 0x19: return QStringLiteral("IRP_MJ_QUERY_QUOTA");
    case 0x1A: return QStringLiteral("IRP_MJ_SET_QUOTA");
    case 0x1B: return QStringLiteral("IRP_MJ_PNP");
    default: return QStringLiteral("IRP_MJ_%1").arg(value);
    }
}

void KernelIoctlAuditTab::populateTables()
{
    m_driverTable->setRowCount(0);
    for (const DriverRow& row : m_driverRows)
    {
        const int tableRow = m_driverTable->rowCount();
        m_driverTable->insertRow(tableRow);
        QString statusText;
        if (!row.status.isEmpty())
        {
            statusText = kernelText(
                "kernel.ioctl_audit.query.failed",
                QStringLiteral("查询失败：%1")).arg(row.status);
        }
        else if (row.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL)
        {
            statusText = kernelText("kernel.ioctl_audit.query.partial", QStringLiteral("部分结果"));
        }
        else if (row.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK)
        {
            statusText = kernelText("kernel.ioctl_audit.query.ok", QStringLiteral("正常"));
        }
        else
        {
            statusText = QStringLiteral("QueryStatus=%1").arg(row.queryStatus);
        }
        m_driverTable->setItem(tableRow, 0, readOnlyItem(row.driverName));
        m_driverTable->setItem(tableRow, 1, readOnlyItem(hex64(row.driverObjectAddress)));
        m_driverTable->setItem(tableRow, 2, readOnlyItem(hex64(row.driverStart)));
        m_driverTable->setItem(tableRow, 3, readOnlyItem(hex32(row.driverSize)));
        m_driverTable->setItem(tableRow, 4, readOnlyItem(hex32(row.driverFlags)));
        m_driverTable->setItem(tableRow, 5, readOnlyItem(
            QStringLiteral("%1/%2").arg(row.returnedDeviceCount).arg(row.totalDeviceCount)));
        m_driverTable->setItem(tableRow, 6, readOnlyItem(QString::number(row.majorFunctionCount)));
        m_driverTable->setItem(tableRow, 7, readOnlyItem(statusText));
        m_driverTable->setItem(tableRow, 8, readOnlyItem(hex32(static_cast<std::uint32_t>(row.lastStatus))));
    }

    m_deviceTable->setRowCount(0);
    for (const DeviceRow& row : m_deviceRows)
    {
        const int tableRow = m_deviceTable->rowCount();
        m_deviceTable->insertRow(tableRow);
        const QString relation = row.relationDepth == 0
            ? kernelText("kernel.ioctl_audit.device.root", QStringLiteral("根设备"))
            : kernelText("kernel.ioctl_audit.device.attached", QStringLiteral("附加 +%1")).arg(row.relationDepth);
        m_deviceTable->setItem(tableRow, 0, readOnlyItem(row.driverName));
        m_deviceTable->setItem(tableRow, 1, readOnlyItem(relation));
        m_deviceTable->setItem(tableRow, 2, readOnlyItem(hex64(row.deviceObjectAddress)));
        m_deviceTable->setItem(tableRow, 3, readOnlyItem(row.deviceName.isEmpty()
            ? kernelText("kernel.ioctl_audit.device.unnamed", QStringLiteral("（未命名）"))
            : row.deviceName));
        m_deviceTable->setItem(tableRow, 4, readOnlyItem(hex32(row.deviceType)));
        m_deviceTable->setItem(tableRow, 5, readOnlyItem(hex32(row.flags)));
        m_deviceTable->setItem(tableRow, 6, readOnlyItem(hex32(row.characteristics)));
        m_deviceTable->setItem(tableRow, 7, readOnlyItem(QString::number(row.stackSize)));
        m_deviceTable->setItem(tableRow, 8, readOnlyItem(hex64(row.rootDeviceObjectAddress)));
        m_deviceTable->setItem(tableRow, 9, readOnlyItem(hex64(row.nextDeviceObjectAddress)));
        m_deviceTable->setItem(tableRow, 10, readOnlyItem(hex64(row.attachedDeviceObjectAddress)));
        m_deviceTable->setItem(tableRow, 11, readOnlyItem(hex64(row.ownerDriverObjectAddress)));
        m_deviceTable->setItem(tableRow, 12, readOnlyItem(hex32(static_cast<std::uint32_t>(row.nameStatus))));
    }

    m_dispatchTable->setRowCount(0);
    for (const DispatchRow& row : m_dispatchRows)
    {
        const int tableRow = m_dispatchTable->rowCount();
        m_dispatchTable->insertRow(tableRow);
        QString dispatchStatus = (row.flags & 0x00000002U) != 0U
            ? kernelText("kernel.ioctl_audit.dispatch.own_image", QStringLiteral("本驱动镜像"))
            : ((row.flags & 0x00000001U) != 0U
                ? kernelText("kernel.ioctl_audit.dispatch.external_module", QStringLiteral("外部模块"))
                : kernelText("kernel.ioctl_audit.dispatch.unresolved", QStringLiteral("模块未解析")));
        if (row.isStartIo && row.startIoState == KSWORD_ARK_DRIVER_START_IO_STATE_NULL)
        {
            dispatchStatus = kernelText("kernel.ioctl_audit.dispatch.start_io_null", QStringLiteral("空值（未使用 StartIo）"));
        }
        else if (row.isStartIo && row.startIoState == KSWORD_ARK_DRIVER_START_IO_STATE_READ_FAILED)
        {
            dispatchStatus = kernelText("kernel.ioctl_audit.dispatch.start_io_read_failed", QStringLiteral("读取失败"));
        }
        const bool hasStartIoAddress = row.isStartIo && row.startIoState == KSWORD_ARK_DRIVER_START_IO_STATE_PRESENT;
        m_dispatchTable->setItem(tableRow, 0, readOnlyItem(row.driverName));
        m_dispatchTable->setItem(tableRow, 1, readOnlyItem(hex64(row.driverObjectAddress)));
        m_dispatchTable->setItem(tableRow, 2, readOnlyItem(row.isStartIo
            ? QStringLiteral("DriverStartIo")
            : majorFunctionName(row.majorFunction)));
        m_dispatchTable->setItem(tableRow, 3, readOnlyItem(row.isStartIo
            ? QStringLiteral("-")
            : QString::number(row.majorFunction)));
        m_dispatchTable->setItem(tableRow, 4, readOnlyItem(row.isStartIo && !hasStartIoAddress
            ? QStringLiteral("-")
            : hex64(row.dispatchAddress)));
        m_dispatchTable->setItem(tableRow, 5, readOnlyItem(row.isStartIo && !hasStartIoAddress
            ? QStringLiteral("-")
            : hex64(row.moduleBase)));
        m_dispatchTable->setItem(tableRow, 6, readOnlyItem(row.moduleName.isEmpty() ? QStringLiteral("-") : row.moduleName));
        m_dispatchTable->setItem(tableRow, 7, readOnlyItem(hex32(row.flags)));
        m_dispatchTable->setItem(tableRow, 8, readOnlyItem(dispatchStatus));
    }

    m_registryTable->setRowCount(0);
    for (const ksword::ark::IoctlRegistryEntry& row : m_registryRows)
    {
        const int tableRow = m_registryTable->rowCount();
        m_registryTable->insertRow(tableRow);
        m_registryTable->setItem(tableRow, 0, readOnlyItem(hex32(row.ioControlCode)));
        m_registryTable->setItem(tableRow, 1, readOnlyItem(QString::number(row.functionNumber)));
        m_registryTable->setItem(tableRow, 2, readOnlyItem(QStringLiteral("%1 / %2").arg(row.method).arg(row.access)));
        m_registryTable->setItem(tableRow, 3, readOnlyItem(hex64(row.requiredCapability)));
        m_registryTable->setItem(tableRow, 4, readOnlyItem(hex64(row.handlerAddress)));
        m_registryTable->setItem(tableRow, 5, readOnlyItem(QString::fromStdString(row.name)));
        m_registryTable->setItem(tableRow, 6, readOnlyItem(hex32(row.flags)));
    }
    m_driverTable->resizeColumnsToContents();
    m_deviceTable->resizeColumnsToContents();
    m_dispatchTable->resizeColumnsToContents();
    m_registryTable->resizeColumnsToContents();
    applyFilter();
    const QString summary = kernelText(
        "kernel.ioctl_audit.summary.detailed",
        QStringLiteral("驱动 %1 个（失败 %2，部分 %3），设备 %4 行，MajorFunction %5 行，KswordARK registry %6/%7 行，重复控制码 %8。"))
        .arg(static_cast<qulonglong>(m_driverRows.size()))
        .arg(m_queryFailureCount)
        .arg(m_partialDriverCount)
        .arg(static_cast<qulonglong>(m_deviceRows.size()))
        .arg(static_cast<qulonglong>(m_dispatchRows.size()))
        .arg(static_cast<qulonglong>(m_registryRows.size()))
        .arg(m_registryTotal)
        .arg(m_registryDuplicate);
    m_statusLabel->setText(m_errorText.isEmpty() ? summary : summary + QStringLiteral(" ") + m_errorText);
}

void KernelIoctlAuditTab::applyFilter()
{
    const QString filterText = m_filterEdit == nullptr ? QString() : m_filterEdit->text().trimmed();
    const bool hasFilter = !filterText.isEmpty();
    for (QTableWidget* table : {m_driverTable, m_deviceTable, m_dispatchTable, m_registryTable})
    {
        if (table == nullptr)
        {
            continue;
        }
        for (int row = 0; row < table->rowCount(); ++row)
        {
            bool matched = !hasFilter;
            for (int column = 0; !matched && column < table->columnCount(); ++column)
            {
                const QTableWidgetItem* item = table->item(row, column);
                matched = item != nullptr && item->text().contains(filterText, Qt::CaseInsensitive);
            }
            table->setRowHidden(row, !matched);
        }
    }
    if (m_clearFilterButton != nullptr)
    {
        m_clearFilterButton->setEnabled(hasFilter);
    }
}

QString KernelIoctlAuditTab::tableRowText(QTableWidget* table, const int row, const bool includeHeader)
{
    if (table == nullptr || row < 0 || row >= table->rowCount())
    {
        return {};
    }
    QStringList values;
    if (includeHeader)
    {
        for (int column = 0; column < table->columnCount(); ++column)
        {
            values << table->horizontalHeaderItem(column)->text();
        }
    }
    QStringList rowValues;
    for (int column = 0; column < table->columnCount(); ++column)
    {
        rowValues << (table->item(row, column) == nullptr ? QString() : table->item(row, column)->text());
    }
    values << rowValues.join(QLatin1Char('\t'));
    return values.join(QLatin1Char('\n'));
}

void KernelIoctlAuditTab::showCopyMenu(QTableWidget* table, const QPoint& position)
{
    if (table == nullptr)
    {
        return;
    }
    const QModelIndex index = table->indexAt(position);
    const int row = index.isValid() ? index.row() : -1;
    QMenu menu(this);
    QAction* copyRow = menu.addAction(kernelText("kernel.ioctl_audit.copy_row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(kernelText("kernel.ioctl_audit.copy_all", QStringLiteral("复制全部行")));
    copyRow->setEnabled(row >= 0);
    copyAll->setEnabled(table->rowCount() > 0);
    QAction* selected = menu.exec(table->viewport()->mapToGlobal(position));
    if (selected == copyRow)
    {
        QApplication::clipboard()->setText(tableRowText(table, row, true));
    }
    else if (selected == copyAll)
    {
        QStringList lines;
        for (int rowIndex = 0; rowIndex < table->rowCount(); ++rowIndex)
        {
            lines << tableRowText(table, rowIndex, rowIndex == 0);
        }
        QApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
    }
}
