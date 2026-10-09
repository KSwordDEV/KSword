#include "KernelIoTimerTab.h"

#include "KernelDeviceDriverObjectsWorker.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QCoreApplication>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QVBoxLayout>

#include <algorithm>
#include <memory>
#include <set>
#include <utility>

namespace
{
    // ioTimerText：所有可见文本使用稳定语境键，中文为源码回退。
    QString ioTimerText(const char* const key, const QString& fallbackText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), fallbackText);
    }

    // makeReadOnlyItem：统一创建不可编辑表格项，并保留完整 tooltip。
    QTableWidgetItem* makeReadOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setToolTip(text);
        return item;
    }

    // driverObjectQueryStatusText：把共享协议状态转成诊断文本。
    QString driverObjectQueryStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK:
            return ioTimerText("kernel.iotimer.query.ok", QStringLiteral("完整"));
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL:
            return ioTimerText("kernel.iotimer.query.partial", QStringLiteral("部分结果"));
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NOT_FOUND:
            return ioTimerText("kernel.iotimer.query.not_found", QStringLiteral("对象已消失"));
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_REFERENCE_FAILED:
            return ioTimerText("kernel.iotimer.query.reference_failed", QStringLiteral("引用失败"));
        default:
            return ioTimerText("kernel.iotimer.query.failed", QStringLiteral("查询失败(%1)"))
                .arg(status);
        }
    }

    // ioTimerControlStatusText：把 R0 语义状态转成可操作诊断。
    QString ioTimerControlStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_OK:
            return ioTimerText("kernel.iotimer.control.status.ok", QStringLiteral("已调用公开 WDM API"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_INVALID_REQUEST:
            return ioTimerText("kernel.iotimer.control.status.invalid_request", QStringLiteral("请求或确认令牌无效"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DRIVER_NOT_FOUND:
            return ioTimerText("kernel.iotimer.control.status.driver_not_found", QStringLiteral("DriverObject 已消失"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DRIVER_IDENTITY_CHANGED:
            return ioTimerText("kernel.iotimer.control.status.driver_changed", QStringLiteral("DriverObject 身份已变化"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DEVICE_NOT_FOUND:
            return ioTimerText("kernel.iotimer.control.status.device_not_found", QStringLiteral("DeviceObject 已消失"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DEVICE_IDENTITY_CHANGED:
            return ioTimerText("kernel.iotimer.control.status.device_changed", QStringLiteral("DeviceObject 归属已变化"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_TIMER_NOT_PRESENT:
            return ioTimerText("kernel.iotimer.control.status.timer_missing", QStringLiteral("DEVICE_OBJECT.Timer 已为空"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_TIMER_IDENTITY_CHANGED:
            return ioTimerText("kernel.iotimer.control.status.timer_changed", QStringLiteral("PIO_TIMER 身份已变化"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_ENUMERATION_FAILED:
            return ioTimerText("kernel.iotimer.control.status.enumeration_failed", QStringLiteral("带引用设备快照枚举失败"));
        default:
            return ioTimerText("kernel.iotimer.control.status.unknown", QStringLiteral("未知状态(%1)"))
                .arg(status);
        }
    }

    // isDriverObjectEntry：仅选择真实 Driver 类型对象，跳过范围说明与错误占位行。
    bool isDriverObjectEntry(const KernelDeviceDriverObjectEntry& entry)
    {
        return entry.querySucceeded
            && !entry.isScopeEntry
            && entry.objectTypeText.compare(QStringLiteral("Driver"), Qt::CaseInsensitive) == 0
            && !entry.fullPathText.trimmed().isEmpty();
    }
}

KernelIoTimerTab::KernelIoTimerTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    applyTranslatedText();
}

void KernelIoTimerTab::requestInitialRefresh()
{
    if (m_initialRefreshRequested)
    {
        return;
    }
    m_initialRefreshRequested = true;
    refreshAsync();
}

void KernelIoTimerTab::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        applyTranslatedText();
        rebuildTable();
        updateDetail();
    }
}

void KernelIoTimerTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);

    m_refreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), this);
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshButton);
    m_startButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_resume.svg")), QString(), this);
    m_startButton->setMinimumHeight(30);
    m_stopButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_suspend.svg")), QString(), this);
    m_stopButton->setMinimumHeight(30);
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setClearButtonEnabled(true);
    m_statusLabel = new QLabel(this);
    m_statusLabel->setStyleSheet(
        QStringLiteral("QLabel{color:%1;font-weight:600;}").arg(KswordTheme::TextSecondaryHex()));

    toolbarLayout->addWidget(m_refreshButton);
    toolbarLayout->addWidget(m_startButton);
    toolbarLayout->addWidget(m_stopButton);
    toolbarLayout->addWidget(m_filterEdit, 1);
    toolbarLayout->addWidget(m_statusLabel);
    rootLayout->addLayout(toolbarLayout);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    m_table = new QTableWidget(splitter);
    m_table->setColumnCount(static_cast<int>(Column::Count));
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(
        static_cast<int>(Column::NamespacePath),
        QHeaderView::Stretch);

    m_detailEditor = new ks::ui::StructuredFieldView(splitter);

    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 2);
    rootLayout->addWidget(splitter, 1);

    ks::ui::DetailLayoutRegistry::registerStructuredHost(m_table, m_detailEditor, this);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        m_initialRefreshRequested = true;
        refreshAsync();
    });
    connect(m_startButton, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_IO_TIMER_CONTROL_ACTION_START);
    });
    connect(m_stopButton, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_IO_TIMER_CONTROL_ACTION_STOP);
    });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this]() {
        rebuildTable();
    });
    connect(m_table, &QTableWidget::itemSelectionChanged, this, [this]() {
        updateDetail();
        updateControlActions();
    });
    connect(m_table, &QTableWidget::customContextMenuRequested, this,
        [this](const QPoint& localPosition) {
            showContextMenu(localPosition);
        });
    updateControlActions();
}

void KernelIoTimerTab::applyTranslatedText()
{
    m_refreshButton->setToolTip(
        ioTimerText("kernel.iotimer.refresh.tooltip", QStringLiteral("重新枚举全部 DriverObject 的 IoTimer")));
    m_startButton->setText(
        ioTimerText("kernel.iotimer.control.start", QStringLiteral("启动 IoTimer")));
    m_startButton->setToolTip(
        ioTimerText(
            "kernel.iotimer.control.start.tooltip",
            QStringLiteral("身份重验后调用 IoStartTimer；已注册回调通常每秒执行一次")));
    m_stopButton->setText(
        ioTimerText("kernel.iotimer.control.stop", QStringLiteral("停止 IoTimer")));
    m_stopButton->setToolTip(
        ioTimerText(
            "kernel.iotimer.control.stop.tooltip",
            QStringLiteral("身份重验后调用 IoStopTimer；可能破坏目标驱动的超时和状态机")));
    m_filterEdit->setPlaceholderText(
        ioTimerText("kernel.iotimer.filter.placeholder", QStringLiteral("按地址、驱动、设备或对象路径筛选")));
    m_filterEdit->setToolTip(
        ioTimerText("kernel.iotimer.filter.tooltip", QStringLiteral("只过滤当前快照，不重新访问驱动")));
    m_table->setHorizontalHeaderLabels(QStringList{
        ioTimerText("kernel.iotimer.header.timer", QStringLiteral("IoTimer 地址")),
        ioTimerText("kernel.iotimer.header.device_object", QStringLiteral("DeviceObject")),
        ioTimerText("kernel.iotimer.header.driver_object", QStringLiteral("DriverObject")),
        ioTimerText("kernel.iotimer.header.driver", QStringLiteral("驱动名")),
        ioTimerText("kernel.iotimer.header.device", QStringLiteral("设备名")),
        ioTimerText("kernel.iotimer.header.namespace", QStringLiteral("对象路径")),
        ioTimerText("kernel.iotimer.header.status", QStringLiteral("查询状态"))
    });

    if (!m_initialRefreshRequested && !m_refreshRunning.load(std::memory_order_relaxed))
    {
        m_statusLabel->setText(
            ioTimerText("kernel.iotimer.status.waiting", QStringLiteral("状态：切换到本页后开始查询")));
        m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(ioTimerText(
                "kernel.iotimer.detail.initial",
                QStringLiteral("本页展示 DEVICE_OBJECT.Timer，并提供经三重身份重验的启动/停止。请选择一行查看完整证据。"))));
    }
    updateControlActions();
}

void KernelIoTimerTab::refreshAsync()
{
    bool expected = false;
    if (!m_refreshRunning.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        return;
    }

    const std::uint64_t refreshTicket = ++m_refreshTicket;
    m_refreshButton->setEnabled(false);
    updateControlActions();
    m_statusLabel->setText(
        ioTimerText("kernel.iotimer.status.refreshing", QStringLiteral("状态：正在枚举 DriverObject / DeviceObject...")));

    QPointer<KernelIoTimerTab> guardThis(this);
    QThreadPool::globalInstance()->start([guardThis, refreshTicket]() {
        auto snapshot = std::make_shared<Snapshot>(collectSnapshot());
        QMetaObject::invokeMethod(
            QCoreApplication::instance(),
            [guardThis, refreshTicket, snapshot]() {
                if (guardThis == nullptr || refreshTicket != guardThis->m_refreshTicket)
                {
                    return;
                }
                guardThis->applySnapshot(*snapshot);
            },
            Qt::QueuedConnection);
    });
}

KernelIoTimerTab::Snapshot KernelIoTimerTab::collectSnapshot()
{
    Snapshot snapshot;
    std::vector<KernelDeviceDriverObjectEntry> namespaceRows;
    QString namespaceError;
    if (!runKernelDeviceDriverObjectsSnapshotTask(namespaceRows, namespaceError))
    {
        snapshot.namespaceError = namespaceError;
        return snapshot;
    }
    snapshot.namespaceError = namespaceError;

    std::set<QString, std::less<>> driverObjectPaths;
    for (const KernelDeviceDriverObjectEntry& namespaceRow : namespaceRows)
    {
        if (isDriverObjectEntry(namespaceRow))
        {
            driverObjectPaths.insert(namespaceRow.fullPathText.trimmed());
        }
    }
    snapshot.driverObjectsDiscovered = static_cast<std::uint32_t>(driverObjectPaths.size());

    ksword::ark::DriverClient driverClient;
    std::set<std::uint64_t> seenTimerAddresses;
    for (const QString& driverObjectPath : driverObjectPaths)
    {
        const ksword::ark::DriverObjectQueryResult queryResult = driverClient.queryDriverObject(
            driverObjectPath.toStdWString(),
            KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_DEVICES |
                KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_NAMES,
            KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT,
            0UL);
        ++snapshot.driverObjectsQueried;

        if (!queryResult.io.ok)
        {
            ++snapshot.queryFailures;
            continue;
        }
        if (queryResult.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL)
        {
            ++snapshot.partialQueries;
        }
        else if (queryResult.queryStatus != KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK)
        {
            ++snapshot.queryFailures;
        }

        const QString driverDisplayName = queryResult.driverName.empty()
            ? driverObjectPath
            : QString::fromStdWString(queryResult.driverName);
        const QString imagePath = QString::fromStdWString(queryResult.imagePath);
        const QString queryStatus = driverObjectQueryStatusText(queryResult.queryStatus);
        for (const ksword::ark::DriverDeviceEntry& deviceEntry : queryResult.devices)
        {
            if (deviceEntry.ioTimerAddress == 0U)
            {
                continue;
            }
            if (!seenTimerAddresses.insert(deviceEntry.ioTimerAddress).second)
            {
                ++snapshot.duplicateTimersSkipped;
                continue;
            }

            IoTimerRow row;
            row.timerAddress = deviceEntry.ioTimerAddress;
            row.deviceObjectAddress = deviceEntry.deviceObjectAddress;
            row.driverObjectAddress = deviceEntry.driverObjectAddress;
            row.driverName = driverDisplayName;
            row.deviceName = QString::fromStdWString(deviceEntry.deviceName);
            row.namespacePath = driverObjectPath;
            row.imagePath = imagePath;
            row.queryStatus = queryStatus;
            row.queryProtocolVersion = queryResult.version;
            row.queryFieldFlags = queryResult.fieldFlags;
            snapshot.rows.push_back(std::move(row));
        }
    }

    std::sort(snapshot.rows.begin(), snapshot.rows.end(), [](const IoTimerRow& left, const IoTimerRow& right) {
        if (left.driverName.compare(right.driverName, Qt::CaseInsensitive) != 0)
        {
            return left.driverName.compare(right.driverName, Qt::CaseInsensitive) < 0;
        }
        if (left.deviceObjectAddress != right.deviceObjectAddress)
        {
            return left.deviceObjectAddress < right.deviceObjectAddress;
        }
        return left.timerAddress < right.timerAddress;
    });
    return snapshot;
}

void KernelIoTimerTab::applySnapshot(const Snapshot& snapshot)
{
    m_rows = snapshot.rows;
    m_lastSnapshot = snapshot;
    m_refreshRunning.store(false, std::memory_order_release);
    m_refreshButton->setEnabled(true);
    rebuildTable();
    updateControlActions();

    if (!snapshot.namespaceError.isEmpty() && snapshot.driverObjectsQueried == 0U)
    {
        m_statusLabel->setText(
            ioTimerText("kernel.iotimer.status.failed", QStringLiteral("状态：查询失败；%1"))
                .arg(snapshot.namespaceError));
        return;
    }

    m_statusLabel->setText(
        ioTimerText(
            "kernel.iotimer.status.completed",
            QStringLiteral("状态：%1 条；DriverObject=%2/%3；失败=%4；部分=%5；去重=%6"))
            .arg(static_cast<qulonglong>(snapshot.rows.size()))
            .arg(snapshot.driverObjectsQueried)
            .arg(snapshot.driverObjectsDiscovered)
            .arg(snapshot.queryFailures)
            .arg(snapshot.partialQueries)
            .arg(snapshot.duplicateTimersSkipped));
}

void KernelIoTimerTab::rebuildTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_detailEditor);
    const QString filterText = m_filterEdit != nullptr ? m_filterEdit->text().trimmed() : QString();
    m_table->setSortingEnabled(false);
    m_table->setRowCount(0);

    for (std::size_t sourceIndex = 0; sourceIndex < m_rows.size(); ++sourceIndex)
    {
        const IoTimerRow& row = m_rows[sourceIndex];
        const QStringList searchableFields{
            pointerText(row.timerAddress),
            pointerText(row.deviceObjectAddress),
            pointerText(row.driverObjectAddress),
            row.driverName,
            row.deviceName,
            row.namespacePath,
            row.imagePath,
            row.queryStatus
        };
        if (!filterText.isEmpty() && !searchableFields.join(QLatin1Char('\n')).contains(filterText, Qt::CaseInsensitive))
        {
            continue;
        }

        const int tableRow = m_table->rowCount();
        m_table->insertRow(tableRow);
        const QStringList cells{
            pointerText(row.timerAddress),
            pointerText(row.deviceObjectAddress),
            pointerText(row.driverObjectAddress),
            row.driverName,
            row.deviceName.isEmpty()
                ? ioTimerText("kernel.iotimer.value.unnamed", QStringLiteral("<未命名设备>"))
                : row.deviceName,
            row.namespacePath,
            row.queryStatus
        };
        for (int column = 0; column < cells.size(); ++column)
        {
            QTableWidgetItem* item = makeReadOnlyItem(cells[column]);
            item->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
            if (column <= static_cast<int>(Column::DriverObject))
            {
                item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            }
            m_table->setItem(tableRow, column, item);
        }
    }

    m_table->setSortingEnabled(true);
    if (m_table->rowCount() > 0)
    {
        m_table->selectRow(0);
    }
    else
    {
        m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(ioTimerText("kernel.iotimer.detail.empty", QStringLiteral("当前筛选条件下没有 IoTimer 记录。"))));
    }
    updateControlActions();
}

void KernelIoTimerTab::updateDetail()
{
    const int currentRow = m_table->currentRow();
    QTableWidgetItem* sourceItem = currentRow >= 0 ? m_table->item(currentRow, 0) : nullptr;
    if (sourceItem == nullptr)
    {
        return;
    }
    const std::size_t sourceIndex = static_cast<std::size_t>(sourceItem->data(Qt::UserRole).toULongLong());
    if (sourceIndex >= m_rows.size())
    {
        return;
    }

    const IoTimerRow& row = m_rows[sourceIndex];
    ks::ui::FieldDocument detailText;
    detailText.field(QStringLiteral("IoTimer 地址"), QStringLiteral("%1").arg(pointerText(row.timerAddress)));
    detailText.field(QStringLiteral("DeviceObject"), QStringLiteral("%1").arg(pointerText(row.deviceObjectAddress)));
    detailText.field(QStringLiteral("DriverObject"), QStringLiteral("%1").arg(pointerText(row.driverObjectAddress)));
    detailText.field(QStringLiteral("驱动名"), QStringLiteral("%1").arg(row.driverName));
    detailText.field(QStringLiteral("设备名"), QStringLiteral("%1").arg(row.deviceName.isEmpty()
            ? ioTimerText("kernel.iotimer.value.unnamed", QStringLiteral("<未命名设备>"))
            : row.deviceName));
    detailText.field(QStringLiteral("对象路径"), QStringLiteral("%1").arg(row.namespacePath));
    detailText.field(QStringLiteral("映像路径"), QStringLiteral("%1").arg(row.imagePath.isEmpty() ? QStringLiteral("<empty>") : row.imagePath));
    detailText.field(QStringLiteral("协议版本"), QStringLiteral("%1").arg(row.queryProtocolVersion));
    detailText.field(QStringLiteral("字段标志"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(row.queryFieldFlags, 8, 16, QChar('0'))));
    detailText.field(QStringLiteral("查询状态"), QStringLiteral("%1").arg(row.queryStatus));
    detailText.field(QStringLiteral("安全边界"), QStringLiteral("地址来自 WDK 公开 DEVICE_OBJECT.Timer 字段。启动/停止时，R0 会按对象名重新引用 DriverObject，通过带引用设备快照核对 DeviceObject，并比较 PIO_TIMER；只调用 IoStartTimer/IoStopTimer，不解引用或写入私有 IO_TIMER。"), true);
    detailText.field(QStringLiteral("限制"), QStringLiteral("WDM API 返回 VOID，Windows 没有公开查询 IoTimer 当前启停状态的接口；成功仅表示公开控制 API 已被调用。"), true);
    m_detailEditor->setDocument(detailText);
}

const KernelIoTimerTab::IoTimerRow* KernelIoTimerTab::selectedRow() const
{
    if (m_table == nullptr || m_table->currentRow() < 0)
    {
        return nullptr;
    }
    const QTableWidgetItem* sourceItem = m_table->item(m_table->currentRow(), 0);
    if (sourceItem == nullptr)
    {
        return nullptr;
    }
    const std::size_t sourceIndex =
        static_cast<std::size_t>(sourceItem->data(Qt::UserRole).toULongLong());
    return sourceIndex < m_rows.size() ? &m_rows[sourceIndex] : nullptr;
}

void KernelIoTimerTab::updateControlActions()
{
    const bool enabled =
        !m_refreshRunning.load(std::memory_order_relaxed) && selectedRow() != nullptr;
    if (m_startButton != nullptr)
    {
        m_startButton->setEnabled(enabled);
    }
    if (m_stopButton != nullptr)
    {
        m_stopButton->setEnabled(enabled);
    }
}

void KernelIoTimerTab::runControlAction(const std::uint32_t action)
{
    const IoTimerRow* selected = selectedRow();
    if (selected == nullptr)
    {
        return;
    }
    const IoTimerRow row = *selected;
    const bool isStart = action == KSWORD_ARK_IO_TIMER_CONTROL_ACTION_START;
    if (!isStart && action != KSWORD_ARK_IO_TIMER_CONTROL_ACTION_STOP)
    {
        return;
    }

    const QString actionTitle = isStart
        ? ioTimerText("kernel.iotimer.control.start", QStringLiteral("启动 IoTimer"))
        : ioTimerText("kernel.iotimer.control.stop", QStringLiteral("停止 IoTimer"));
    const QString riskText = isStart
        ? ioTimerText(
            "kernel.iotimer.control.start.risk",
            QStringLiteral(
                "IoStartTimer 会启用目标驱动已注册的 IoTimerRoutine，其通常每秒执行一次。"
                "对未预期重复启动的驱动操作，可能导致重入、设备异常或系统崩溃。"))
        : ioTimerText(
            "kernel.iotimer.control.stop.risk",
            QStringLiteral(
                "IoStopTimer 会停止目标驱动的设备计时回调。该回调可能负责超时、轮询、"
                "故障恢复或硬件保活；停止后可能导致设备卡死、数据丢失或系统崩溃。"));
    const QString targetText = ioTimerText(
        "kernel.iotimer.control.target",
        QStringLiteral("驱动：%1\n设备：%2\nIoTimer：%3"))
        .arg(row.namespacePath)
        .arg(pointerText(row.deviceObjectAddress))
        .arg(pointerText(row.timerAddress));

    QMessageBox warningBox(this);
    warningBox.setIcon(QMessageBox::Critical);
    warningBox.setWindowTitle(
        ioTimerText("kernel.iotimer.control.warning_title", QStringLiteral("关键风险：控制外部驱动 IoTimer")));
    warningBox.setText(
        ioTimerText(
            "kernel.iotimer.control.warning_text",
            QStringLiteral("即将执行“%1”。KSword 只告知风险，不按高级模式或风险等级限制修改；继续后仍会核验目标身份。"))
            .arg(actionTitle));
    warningBox.setInformativeText(targetText + QStringLiteral("\n\n") + riskText);
    warningBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    warningBox.setDefaultButton(QMessageBox::No);
    warningBox.setEscapeButton(QMessageBox::No);
    if (warningBox.exec() != QMessageBox::Yes)
    {
        return;
    }

    // 二次确认改为直接点击：动作名与按钮文案保持一致，不使用英文口令。
    const QString confirmationPhrase = QStringLiteral("%1 %2")
        .arg(isStart
            ? ioTimerText("kernel.iotimer.control.start", QStringLiteral("启动定时器"))
            : ioTimerText("kernel.iotimer.control.stop", QStringLiteral("停止定时器")))
        .arg(pointerText(row.timerAddress));
    const auto typedConfirmation = QMessageBox::warning(
        this,
        ioTimerText("kernel.iotimer.control.confirm_title", QStringLiteral("二次确认 IoTimer 控制")),
        ioTimerText(
            "kernel.iotimer.control.confirm_final",
            QStringLiteral("确认执行 %1？"))
            .arg(confirmationPhrase),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (typedConfirmation != QMessageBox::Yes)
    {
        return;
    }

    ksword::ark::DriverClient driverClient;
    const ksword::ark::IoTimerControlResult result = driverClient.controlIoTimer(
        action,
        row.namespacePath.toStdWString(),
        row.driverObjectAddress,
        row.deviceObjectAddress,
        row.timerAddress,
        true);
    if (!result.io.ok)
    {
        const QString transportText = result.unsupported
            ? ioTimerText(
                "kernel.iotimer.control.unsupported",
                QStringLiteral("当前 KswordARK 驱动过旧，尚未注册 IoTimer 控制 IOCTL。请更新并重载驱动。"))
            : ioTimerText(
                "kernel.iotimer.control.transport_failed",
                QStringLiteral("IoTimer 控制 IOCTL 失败。\n%1"))
                .arg(QString::fromStdString(result.io.message));
        QMessageBox::critical(this, actionTitle, transportText);
        return;
    }

    if (result.status != KSWORD_ARK_IO_TIMER_CONTROL_STATUS_OK)
    {
        QMessageBox::critical(
            this,
            actionTitle,
            ioTimerText(
                "kernel.iotimer.control.failed",
                QStringLiteral(
                    "R0 已拒绝操作：%1\n语义状态：%2\nNTSTATUS：0x%3\n"
                    "重新观察：Driver=%4，Device=%5，Timer=%6\n\n"
                    "对象身份变化或目标无效时请刷新后重新确认。"))
                .arg(ioTimerControlStatusText(result.status))
                .arg(result.status)
                .arg(static_cast<std::uint32_t>(result.lastStatus), 8, 16, QChar('0'))
                .arg(pointerText(result.observedDriverObjectAddress))
                .arg(pointerText(result.observedDeviceObjectAddress))
                .arg(pointerText(result.observedTimerAddress)));
        refreshAsync();
        return;
    }

    QMessageBox::information(
        this,
        actionTitle,
        ioTimerText(
            "kernel.iotimer.control.completed",
            QStringLiteral(
                "%1 已在三重身份校验后调用。\n\n"
                "Windows 的 IoStartTimer/IoStopTimer 返回 VOID，且没有公开运行状态查询接口；"
                "因此此结果表示 API 已接受调用，不伪造“已验证运行态”。"))
            .arg(isStart ? QStringLiteral("IoStartTimer") : QStringLiteral("IoStopTimer")));
    refreshAsync();
}

void KernelIoTimerTab::showContextMenu(const QPoint& localPosition)
{
    const QModelIndex clickedIndex = m_table->indexAt(localPosition);
    if (clickedIndex.isValid())
    {
        m_table->setCurrentCell(clickedIndex.row(), clickedIndex.column());
    }

    QMenu menu(m_table);
    menu.setStyleSheet(QStringLiteral(
        "QMenu{background:%1;color:%2;border:1px solid %3;}"
        "QMenu::item{padding:5px 22px 5px 8px;}"
        "QMenu::item:selected{background:%4;color:%5;}")
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::BorderHex())
        .arg(KswordTheme::PrimaryBlueHex)
        .arg(KswordTheme::OnAccentHex()));
    QAction* startAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_resume.svg")),
        ioTimerText("kernel.iotimer.control.start", QStringLiteral("启动 IoTimer")));
    QAction* stopAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_suspend.svg")),
        ioTimerText("kernel.iotimer.control.stop", QStringLiteral("停止 IoTimer")));
    menu.addSeparator();
    QAction* copyCellAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_cell.svg")),
        ioTimerText("kernel.iotimer.menu.copy_cell", QStringLiteral("复制单元格")));
    QAction* copyRowAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        ioTimerText("kernel.iotimer.menu.copy_row", QStringLiteral("复制当前行")));
    const bool canControl =
        !m_refreshRunning.load(std::memory_order_relaxed) && selectedRow() != nullptr;
    startAction->setEnabled(canControl);
    stopAction->setEnabled(canControl);
    copyCellAction->setEnabled(clickedIndex.isValid());
    copyRowAction->setEnabled(m_table->currentRow() >= 0);

    const QAction* selectedAction = menu.exec(m_table->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == startAction)
    {
        runControlAction(KSWORD_ARK_IO_TIMER_CONTROL_ACTION_START);
        return;
    }
    if (selectedAction == stopAction)
    {
        runControlAction(KSWORD_ARK_IO_TIMER_CONTROL_ACTION_STOP);
        return;
    }

    QString clipboardText;
    if (selectedAction == copyCellAction && clickedIndex.isValid())
    {
        const QTableWidgetItem* item = m_table->item(clickedIndex.row(), clickedIndex.column());
        clipboardText = item != nullptr ? item->text() : QString();
    }
    else if (selectedAction == copyRowAction && m_table->currentRow() >= 0)
    {
        QStringList fields;
        for (int column = 0; column < m_table->columnCount(); ++column)
        {
            const QTableWidgetItem* item = m_table->item(m_table->currentRow(), column);
            fields.push_back(normalizedCellText(item != nullptr ? item->text() : QString()));
        }
        clipboardText = fields.join(QLatin1Char('\t'));
    }

    if (!clipboardText.isEmpty() && QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(clipboardText);
    }
}

QString KernelIoTimerTab::pointerText(const std::uint64_t address)
{
    return QStringLiteral("0x%1").arg(static_cast<qulonglong>(address), 16, 16, QChar('0')).toUpper();
}

QString KernelIoTimerTab::normalizedCellText(const QString& text)
{
    QString normalized = text;
    normalized.replace(QLatin1Char('\t'), QLatin1Char(' '));
    normalized.replace(QLatin1Char('\r'), QLatin1Char(' '));
    normalized.replace(QLatin1Char('\n'), QLatin1Char(' '));
    return normalized;
}
