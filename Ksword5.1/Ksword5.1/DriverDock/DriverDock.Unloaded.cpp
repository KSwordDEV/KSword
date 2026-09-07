#include "DriverDock.Internal.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"

#include <QTimeZone>

using namespace ksword::driver_dock_internal;

namespace
{
    // UnloadedColumn 与 issue 截图中的六列一一对应。
    enum class UnloadedColumn : int
    {
        Name = 0,
        Base,
        Size,
        TimeDateStamp,
        LoadStatus,
        UnloadTime,
        Count
    };

    // FilterField::All 使用 -1，其余值直接复用 UnloadedColumn 列号。
    constexpr int kFilterAllFields = -1;
    constexpr int kUnloadedCacheIndexRole = Qt::UserRole + 57;
    constexpr std::uint64_t kWindowsEpochDelta100Ns = 116444736000000000ULL;

    constexpr int columnIndex(const UnloadedColumn column)
    {
        // 输入：强类型列枚举。
        // 处理：转换为 Qt 列号。
        // 返回：稳定列索引。
        return static_cast<int>(column);
    }

    QString fixedHex64(const std::uint64_t value)
    {
        // 输入：地址、大小或 FILETIME 原始值。
        // 处理：格式化为固定宽度十六进制。
        // 返回：0x 前缀大写文本。
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString fixedHex32(const std::uint32_t value)
    {
        // 输入：时间戳、NTSTATUS 或 flags。
        // 处理：格式化为八位十六进制。
        // 返回：0x 前缀大写文本。
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(value), 8, 16, QChar('0'))
            .toUpper();
    }

    QString unloadTimeText(const std::uint64_t fileTime)
    {
        // 输入：R0 _UNLOADED_DRIVERS.CurrentTime 的 100ns FILETIME 值。
        // 处理：安全换算到本地时间；早于 Windows epoch 的异常值保留原始十六进制。
        // 返回：用户可读时间，毫秒精度。
        if (fileTime < kWindowsEpochDelta100Ns)
        {
            return fixedHex64(fileTime);
        }

        const std::uint64_t unixMilliseconds =
            (fileTime - kWindowsEpochDelta100Ns) / 10000ULL;
        if (unixMilliseconds >
            static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()))
        {
            return fixedHex64(fileTime);
        }
        return QDateTime::fromMSecsSinceEpoch(
            static_cast<qint64>(unixMilliseconds),
            QTimeZone::UTC)
            .toLocalTime()
            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    }

    QString sourceName(const std::uint32_t source)
    {
        // 输入：KSWORD_ARK_UNLOADED_DRIVER_SOURCE_*。
        // 处理：映射到截图中的三个技术来源名。
        // 返回：未知来源保留数值。
        switch (source)
        {
        case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS:
            return QStringLiteral("MmUnloadedDrivers");
        case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE:
            return QStringLiteral("PiDDBCacheTable");
        case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST:
            return QStringLiteral("g_KernelHashBucketList");
        default:
            return QStringLiteral("Source(%1)").arg(source);
        }
    }

    std::array<QString, columnIndex(UnloadedColumn::Count)> displayCells(
        const ksword::ark::UnloadedDriverEntry& row)
    {
        // 输入：ArkDriverClient 统一行。
        // 处理：严格按 HAS_* 位生成六列；来源不支持的列显示“-”而不是伪造 0。
        // 返回：可用于表格、过滤和复制的显示文本。
        std::array<QString, columnIndex(UnloadedColumn::Count)> cells{};
        cells[columnIndex(UnloadedColumn::Name)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_NAME) != 0U
            ? QString::fromStdWString(row.driverName)
            : QStringLiteral("-");
        cells[columnIndex(UnloadedColumn::Base)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_BASE) != 0U
            ? fixedHex64(row.baseAddress)
            : QStringLiteral("-");
        cells[columnIndex(UnloadedColumn::Size)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_SIZE) != 0U
            ? fixedHex64(row.imageSize)
            : QStringLiteral("-");
        cells[columnIndex(UnloadedColumn::TimeDateStamp)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP) != 0U
            ? fixedHex32(row.timeDateStamp)
            : QStringLiteral("-");
        cells[columnIndex(UnloadedColumn::LoadStatus)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS) != 0U
            ? fixedHex32(static_cast<std::uint32_t>(row.loadStatus))
            : QStringLiteral("-");
        cells[columnIndex(UnloadedColumn::UnloadTime)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME) != 0U
            ? unloadTimeText(row.unloadTime)
            : QStringLiteral("-");
        return cells;
    }

    QTableWidgetItem* textItem(const QString& text)
    {
        // 输入：单元格展示文本。
        // 处理：创建不可编辑、左对齐单元格。
        // 返回：所有权交给 QTableWidget。
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    class NumericItem final : public QTableWidgetItem
    {
    public:
        NumericItem(const QString& text, const std::uint64_t sortValue)
            : QTableWidgetItem(text)
        {
            // 输入：显示文本与原始无符号数值。
            // 处理：UserRole 保存排序键，单元格保持只读。
            // 返回：构造函数无返回值。
            setFlags(flags() & ~Qt::ItemIsEditable);
            setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
            setData(
                Qt::UserRole,
                QVariant::fromValue<qulonglong>(
                    static_cast<qulonglong>(sortValue)));
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            // 输入：排序比较的另一单元格。
            // 处理：双方都有 UserRole 时比较原始数值，否则退回文本比较。
            // 返回：是否排在 other 之前。
            bool leftOk = false;
            bool rightOk = false;
            const qulonglong leftValue =
                data(Qt::UserRole).toULongLong(&leftOk);
            const qulonglong rightValue =
                other.data(Qt::UserRole).toULongLong(&rightOk);
            if (leftOk && rightOk)
            {
                return leftValue < rightValue;
            }
            return QTableWidgetItem::operator<(other);
        }
    };

    QTableWidgetItem* numericItem(
        const QString& text,
        const std::uint64_t sortValue)
    {
        // 输入：显示文本与原始数值。
        // 处理：UserRole 保存数值，保证十六进制列排序稳定。
        // 返回：所有权交给 QTableWidget。
        return new NumericItem(text, sortValue);
    }

    QString escapedTsvCell(QString text)
    {
        // 输入：表格文本。
        // 处理：压平 Tab/换行，避免破坏复制后的 TSV 列结构。
        // 返回：安全单元格文本。
        text.replace(QLatin1Char('\t'), QLatin1Char(' '));
        text.replace(QLatin1Char('\r'), QLatin1Char(' '));
        text.replace(QLatin1Char('\n'), QLatin1Char(' '));
        return text.trimmed();
    }

    QString tableCellText(
        const QTableWidget* table,
        const int row,
        const int column)
    {
        // 输入：目标表格与单元格坐标。
        // 处理：空 item 归一化为空文本。
        // 返回：当前显示内容。
        if (table == nullptr)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(row, column);
        return item != nullptr ? item->text() : QString();
    }

    void updateQueryStatusLabel(
        QLabel* label,
        const ksword::ark::UnloadedDriverQueryResult& result)
    {
        // 输入：状态标签和最近一次查询结果。
        // 处理：区分传输失败、profile/layout 缺失、partial 与成功。
        // 返回：无；状态只解释读取结果，不提供清理建议。
        if (label == nullptr)
        {
            return;
        }
        if (result.source == 0U && result.io.message.empty())
        {
            label->setText(
                driverText(
                    "driver.unloaded.status.waiting",
                    QStringLiteral("状态：等待刷新")));
            label->setStyleSheet(QString());
            return;
        }
        if (!result.io.ok)
        {
            label->setText(
                result.unsupported
                ? driverText(
                    "driver.unloaded.status.unsupported",
                    QStringLiteral("状态：当前驱动未集成已卸载驱动只读查询"))
                : driverText(
                    "driver.unloaded.status.io_failed",
                    QStringLiteral("状态：查询失败：%1"))
                    .arg(describeDriverCollection(result.io)));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
            return;
        }

        const QString sourceText = sourceName(result.source);
        switch (result.queryStatus)
        {
        case KSWORD_ARK_UNLOADED_DRIVER_STATUS_OK:
            label->setText(
                driverText(
                    "driver.unloaded.status.ok",
                    QStringLiteral("状态：%1 查询完成，返回 %2/%3 条。"))
                    .arg(sourceText)
                    .arg(result.entries.size())
                    .arg(result.totalRows));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(KswordTheme::SuccessColor().name(QColor::HexRgb)));
            break;
        case KSWORD_ARK_UNLOADED_DRIVER_STATUS_PARTIAL:
            label->setText(
                driverText(
                    "driver.unloaded.status.partial",
                    QStringLiteral("状态：%1 部分完成，返回 %2/%3 条，跳过 %4 条。"))
                    .arg(sourceText)
                    .arg(result.entries.size())
                    .arg(result.totalRows)
                    .arg(result.skippedRows));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(KswordTheme::WarningColor().name(QColor::HexRgb)));
            break;
        case KSWORD_ARK_UNLOADED_DRIVER_STATUS_DYNDATA_UNAVAILABLE:
            label->setText(
                driverText(
                    "driver.unloaded.status.dyndata_missing",
                    QStringLiteral("状态：%1 所需 ntoskrnl DynData 尚未应用。"))
                    .arg(sourceText));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(KswordTheme::WarningColor().name(QColor::HexRgb)));
            break;
        case KSWORD_ARK_UNLOADED_DRIVER_STATUS_MODULE_PROFILE_UNAVAILABLE:
            label->setText(
                driverText(
                    "driver.unloaded.status.module_profile_missing",
                    QStringLiteral("状态：%1 所需模块 PDB profile 尚未应用。"))
                    .arg(sourceText));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(KswordTheme::WarningColor().name(QColor::HexRgb)));
            break;
        case KSWORD_ARK_UNLOADED_DRIVER_STATUS_LAYOUT_UNAVAILABLE:
            label->setText(
                driverText(
                    "driver.unloaded.status.layout_missing",
                    QStringLiteral("状态：%1 的当前 PDB profile 缺少安全读取布局。"))
                    .arg(sourceText));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(KswordTheme::WarningColor().name(QColor::HexRgb)));
            break;
        default:
            label->setText(
                driverText(
                    "driver.unloaded.status.read_failed",
                    QStringLiteral("状态：%1 读取失败，NTSTATUS=%2。"))
                    .arg(sourceText)
                    .arg(fixedHex32(
                        static_cast<std::uint32_t>(result.lastStatus))));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
            break;
        }
    }
}

void DriverDock::initializeUnloadedPiddbTab()
{
    // 输入：m_tabWidget。
    // 处理：严格按 issue 图片排布“表格 -> 来源单选 -> 字段过滤/正则/数量 -> 状态”。
    // 返回：无；页面只连接查询、过滤、详情和复制动作。
    m_unloadedPiddbPage = new QWidget(m_tabWidget);
    m_unloadedPiddbLayout = new QVBoxLayout(m_unloadedPiddbPage);
    m_unloadedPiddbLayout->setContentsMargins(4, 4, 4, 4);
    m_unloadedPiddbLayout->setSpacing(6);

    m_unloadedPiddbTable =
        new ks::ui::VisibleTableWidget(m_unloadedPiddbPage);
    m_unloadedPiddbTable->setColumnCount(
        columnIndex(UnloadedColumn::Count));
    m_unloadedPiddbTable->setHorizontalHeaderLabels(
        driverUnloadedDriverTableHeaders());
    m_unloadedPiddbTable->setSelectionBehavior(
        QAbstractItemView::SelectRows);
    m_unloadedPiddbTable->setSelectionMode(
        QAbstractItemView::SingleSelection);
    m_unloadedPiddbTable->setEditTriggers(
        QAbstractItemView::NoEditTriggers);
    m_unloadedPiddbTable->setAlternatingRowColors(true);
    m_unloadedPiddbTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_unloadedPiddbTable->verticalHeader()->setVisible(false);
    m_unloadedPiddbTable->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    m_unloadedPiddbTable->horizontalHeader()->setSectionResizeMode(
        columnIndex(UnloadedColumn::Name),
        QHeaderView::Stretch);
    m_unloadedPiddbTable->horizontalHeader()->setSectionResizeMode(
        columnIndex(UnloadedColumn::UnloadTime),
        QHeaderView::Stretch);
    m_unloadedPiddbLayout->addWidget(m_unloadedPiddbTable, 1);

    m_unloadedPiddbSourceLayout = new QHBoxLayout();
    m_unloadedPiddbSourceLayout->setContentsMargins(0, 0, 0, 0);
    m_unloadedPiddbSourceLayout->setSpacing(12);
    m_unloadedPiddbSourceGroup = new QButtonGroup(m_unloadedPiddbPage);
    m_unloadedPiddbMmSourceRadio =
        new QRadioButton(QStringLiteral("MmUnloadedDrivers"), m_unloadedPiddbPage);
    m_unloadedPiddbPiDdbSourceRadio =
        new QRadioButton(QStringLiteral("PiDDBCacheTable"), m_unloadedPiddbPage);
    m_unloadedPiddbCiSourceRadio =
        new QRadioButton(QStringLiteral("g_KernelHashBucketList"), m_unloadedPiddbPage);
    m_unloadedPiddbSourceGroup->addButton(
        m_unloadedPiddbMmSourceRadio,
        KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS);
    m_unloadedPiddbSourceGroup->addButton(
        m_unloadedPiddbPiDdbSourceRadio,
        KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE);
    m_unloadedPiddbSourceGroup->addButton(
        m_unloadedPiddbCiSourceRadio,
        KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST);
    // issue 截图默认选中 PiDDBCacheTable。
    m_unloadedPiddbPiDdbSourceRadio->setChecked(true);

    m_unloadedPiddbRefreshButton = new QPushButton(m_unloadedPiddbPage);
    m_unloadedPiddbRefreshButton->setIcon(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    m_unloadedPiddbRefreshButton->setToolTip(
        driverText(
            "driver.unloaded.refresh.tooltip",
            QStringLiteral("重新查询当前已卸载驱动来源")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_unloadedPiddbRefreshButton);

    m_unloadedPiddbSourceLayout->addWidget(m_unloadedPiddbMmSourceRadio);
    m_unloadedPiddbSourceLayout->addWidget(m_unloadedPiddbPiDdbSourceRadio);
    m_unloadedPiddbSourceLayout->addWidget(m_unloadedPiddbCiSourceRadio);
    m_unloadedPiddbSourceLayout->addStretch(1);
    m_unloadedPiddbSourceLayout->addWidget(m_unloadedPiddbRefreshButton);
    m_unloadedPiddbLayout->addLayout(m_unloadedPiddbSourceLayout);

    m_unloadedPiddbFilterLayout = new QHBoxLayout();
    m_unloadedPiddbFilterLayout->setContentsMargins(0, 0, 0, 0);
    m_unloadedPiddbFilterLayout->setSpacing(6);
    m_unloadedPiddbFieldCombo = new QComboBox(m_unloadedPiddbPage);
    m_unloadedPiddbFieldCombo->addItem(
        driverText("driver.unloaded.filter.all", QStringLiteral("所有")),
        kFilterAllFields);
    const QStringList filterFields = driverUnloadedDriverTableHeaders();
    for (int column = 0; column < filterFields.size(); ++column)
    {
        m_unloadedPiddbFieldCombo->addItem(filterFields.at(column), column);
    }
    m_unloadedPiddbFilterEdit = new QLineEdit(m_unloadedPiddbPage);
    m_unloadedPiddbFilterEdit->setClearButtonEnabled(true);
    m_unloadedPiddbFilterEdit->setPlaceholderText(
        driverText(
            "driver.unloaded.filter.placeholder",
            QStringLiteral("过滤")));
    m_unloadedPiddbFilterEdit->setToolTip(
        driverText(
            "driver.unloaded.filter.tooltip",
            QStringLiteral("只筛选当前来源缓存，不会重新访问驱动。")));
    m_unloadedPiddbRegexCheck = new QCheckBox(
        driverText("driver.unloaded.filter.regex", QStringLiteral("正则")),
        m_unloadedPiddbPage);
    // issue 截图中“正则”默认勾选；空过滤文本时不会改变结果。
    m_unloadedPiddbRegexCheck->setChecked(true);
    m_unloadedPiddbCountLabel = new QLabel(
        driverText("driver.unloaded.count", QStringLiteral("数量：%1")).arg(0),
        m_unloadedPiddbPage);
    m_unloadedPiddbFilterLayout->addWidget(m_unloadedPiddbFieldCombo);
    m_unloadedPiddbFilterLayout->addWidget(m_unloadedPiddbFilterEdit, 1);
    m_unloadedPiddbFilterLayout->addWidget(m_unloadedPiddbRegexCheck);
    m_unloadedPiddbFilterLayout->addWidget(m_unloadedPiddbCountLabel);
    m_unloadedPiddbLayout->addLayout(m_unloadedPiddbFilterLayout);

    m_unloadedPiddbStatusLabel = new QLabel(
        driverText(
            "driver.unloaded.status.waiting",
            QStringLiteral("状态：等待刷新")),
        m_unloadedPiddbPage);
    m_unloadedPiddbStatusLabel->setWordWrap(true);
    m_unloadedPiddbLayout->addWidget(m_unloadedPiddbStatusLabel);

    m_tabWidget->addTab(
        m_unloadedPiddbPage,
        QIcon(QStringLiteral(":/Icon/process_uncritical.svg")),
        driverText(
            "driver.tab.unloaded_piddb",
            QStringLiteral("已卸载驱动")));

    // 来源变化立即查询；过滤相关控件只重绘本地缓存。
    const auto connectSource = [this](QRadioButton* radio) {
        connect(radio, &QRadioButton::toggled, this, [this](const bool checked) {
            if (checked)
            {
                refreshUnloadedDriversAsync();
            }
        });
    };
    connectSource(m_unloadedPiddbMmSourceRadio);
    connectSource(m_unloadedPiddbPiDdbSourceRadio);
    connectSource(m_unloadedPiddbCiSourceRadio);
    connect(
        m_unloadedPiddbRefreshButton,
        &QPushButton::clicked,
        this,
        &DriverDock::refreshUnloadedDriversAsync);
    connect(
        m_unloadedPiddbFieldCombo,
        &QComboBox::currentIndexChanged,
        this,
        [this](int) { rebuildUnloadedPiddbTable(); });
    connect(
        m_unloadedPiddbFilterEdit,
        &QLineEdit::textChanged,
        this,
        [this](const QString&) { rebuildUnloadedPiddbTable(); });
    connect(
        m_unloadedPiddbRegexCheck,
        &QCheckBox::toggled,
        this,
        [this](bool) { rebuildUnloadedPiddbTable(); });
    connect(
        m_unloadedPiddbTable,
        &QTableWidget::customContextMenuRequested,
        this,
        &DriverDock::showUnloadedPiddbContextMenu);
    connect(
        m_unloadedPiddbTable,
        &QTableWidget::cellDoubleClicked,
        this,
        [this](int, int) { showSelectedUnloadedPiddbDetailDialog(); });
}

void DriverDock::refreshUnloadedDriversAsync()
{
    // 输入：当前来源单选值。
    // 处理：每次查询分配新 ticket，后台只调用 ArkDriverClient。
    // 返回：无；旧来源晚到结果会被丢弃。
    if (m_unloadedPiddbSourceGroup == nullptr)
    {
        return;
    }
    const int checkedId = m_unloadedPiddbSourceGroup->checkedId();
    if (checkedId < 0)
    {
        return;
    }
    const std::uint32_t source = static_cast<std::uint32_t>(checkedId);
    const std::uint64_t ticket = ++m_unloadedDriverQueryTicket;
    m_unloadedDriverQuerying = true;
    if (m_unloadedPiddbRefreshButton != nullptr)
    {
        m_unloadedPiddbRefreshButton->setEnabled(false);
    }
    if (m_unloadedPiddbStatusLabel != nullptr)
    {
        m_unloadedPiddbStatusLabel->setText(
            driverText(
                "driver.unloaded.status.querying",
                QStringLiteral("状态：正在查询 %1..."))
                .arg(sourceName(source)));
        m_unloadedPiddbStatusLabel->setStyleSheet(
            QStringLiteral("color:%1; font-weight:700;")
                .arg(KswordTheme::PrimaryBlueHex));
    }

    QPointer<DriverDock> guardThis(this);
    QRunnable* task = QRunnable::create([guardThis, ticket, source]() {
        const ksword::ark::DriverClient client;
        ksword::ark::UnloadedDriverQueryResult result =
            client.queryUnloadedDrivers(
                source,
                KSWORD_ARK_UNLOADED_DRIVER_MAX_ROWS);

        // 投递使用长生命周期 GUI receiver，并在 GUI 线程内重新检查 QPointer。
        // 这样 DriverDock 在查询期间析构时，worker 不会把悬空 raw pointer
        // 传给 invokeMethod。
        QCoreApplication* application = QCoreApplication::instance();
        if (application == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            application,
            [guardThis, ticket, result = std::move(result)]() mutable {
                if (guardThis != nullptr)
                {
                    guardThis->applyUnloadedDriverQueryResult(
                        ticket,
                        std::move(result));
                }
            },
            Qt::QueuedConnection);
    });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void DriverDock::applyUnloadedDriverQueryResult(
    const std::uint64_t ticket,
    ksword::ark::UnloadedDriverQueryResult result)
{
    // 输入：后台结果与其 ticket。
    // 处理：仅接受最新查询，分离行缓存与查询元信息后刷新 UI。
    // 返回：无。
    if (ticket != m_unloadedDriverQueryTicket)
    {
        return;
    }

    // 查询结果包含可变长行缓存；菜单打开时连 cache replacement 一起延后，
    // 避免 rebuild 前先让动作依赖的来源索引失效。
    const QPointer<DriverDock> guardThis(this);
    const auto deferredResult =
        std::make_shared<ksword::ark::UnloadedDriverQueryResult>(std::move(result));
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("driver-unloaded-snapshot-apply"),
        { m_unloadedPiddbTable },
        [guardThis, ticket, deferredResult]() mutable
        {
            if (!guardThis.isNull())
            {
                guardThis->applyUnloadedDriverQueryResult(
                    ticket,
                    std::move(*deferredResult));
            }
        }))
    {
        return;
    }
    result = std::move(*deferredResult);

    m_unloadedDriverQuerying = false;
    if (m_unloadedPiddbRefreshButton != nullptr)
    {
        m_unloadedPiddbRefreshButton->setEnabled(true);
    }

    m_unloadedDriverCache = std::move(result.entries);
    result.entries.clear();
    m_lastUnloadedDriverResult = std::move(result);
    m_lastUnloadedDriverResult.entries = m_unloadedDriverCache;
    rebuildUnloadedPiddbTable();
    updateQueryStatusLabel(
        m_unloadedPiddbStatusLabel,
        m_lastUnloadedDriverResult);
}

void DriverDock::rebuildUnloadedPiddbTable()
{
    // 输入：当前行缓存、字段选择、关键词和正则开关。
    // 处理：本地筛选并写入截图要求的六列；UserRole 保存源缓存索引。
    // 返回：无。
    if (m_unloadedPiddbTable == nullptr)
    {
        return;
    }
    const QSignalBlocker blocker(m_unloadedPiddbTable);
    m_unloadedPiddbTable->setSortingEnabled(false);
    m_unloadedPiddbTable->setRowCount(0);

    const QString pattern = m_unloadedPiddbFilterEdit != nullptr
        ? m_unloadedPiddbFilterEdit->text().trimmed()
        : QString();
    const int filterField = m_unloadedPiddbFieldCombo != nullptr
        ? m_unloadedPiddbFieldCombo->currentData().toInt()
        : kFilterAllFields;
    const bool regularExpressionEnabled =
        m_unloadedPiddbRegexCheck != nullptr &&
        m_unloadedPiddbRegexCheck->isChecked();
    QRegularExpression expression;
    if (regularExpressionEnabled && !pattern.isEmpty())
    {
        expression = QRegularExpression(
            pattern,
            QRegularExpression::CaseInsensitiveOption);
        if (!expression.isValid())
        {
            if (m_unloadedPiddbCountLabel != nullptr)
            {
                m_unloadedPiddbCountLabel->setText(
                    driverText(
                        "driver.unloaded.count",
                        QStringLiteral("数量：%1"))
                        .arg(0));
            }
            if (m_unloadedPiddbStatusLabel != nullptr)
            {
                m_unloadedPiddbStatusLabel->setText(
                    driverText(
                        "driver.unloaded.status.regex_invalid",
                        QStringLiteral("状态：正则表达式无效：%1"))
                        .arg(expression.errorString()));
                m_unloadedPiddbStatusLabel->setStyleSheet(
                    QStringLiteral("color:%1; font-weight:700;")
                        .arg(KswordTheme::WarningColor().name(QColor::HexRgb)));
            }
            return;
        }
    }

    for (std::size_t cacheIndex = 0U;
         cacheIndex < m_unloadedDriverCache.size();
         ++cacheIndex)
    {
        const ksword::ark::UnloadedDriverEntry& row =
            m_unloadedDriverCache[cacheIndex];
        const auto cells = displayCells(row);
        QString haystack;
        if (filterField >= 0 &&
            filterField < columnIndex(UnloadedColumn::Count))
        {
            haystack = cells[static_cast<std::size_t>(filterField)];
        }
        else
        {
            QStringList parts;
            for (const QString& cell : cells)
            {
                parts << cell;
            }
            haystack = parts.join(QLatin1Char('\n'));
        }

        const bool matches = pattern.isEmpty() ||
            (regularExpressionEnabled
                ? expression.match(haystack).hasMatch()
                : haystack.contains(pattern, Qt::CaseInsensitive));
        if (!matches)
        {
            continue;
        }

        const int outputRow = m_unloadedPiddbTable->rowCount();
        m_unloadedPiddbTable->insertRow(outputRow);
        QTableWidgetItem* nameItem =
            textItem(cells[columnIndex(UnloadedColumn::Name)]);
        nameItem->setData(
            kUnloadedCacheIndexRole,
            QVariant::fromValue<qulonglong>(
                static_cast<qulonglong>(cacheIndex)));
        nameItem->setToolTip(sourceName(row.source));
        m_unloadedPiddbTable->setItem(
            outputRow,
            columnIndex(UnloadedColumn::Name),
            nameItem);

        m_unloadedPiddbTable->setItem(
            outputRow,
            columnIndex(UnloadedColumn::Base),
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_BASE) != 0U
                ? numericItem(
                    cells[columnIndex(UnloadedColumn::Base)],
                    row.baseAddress)
                : textItem(QStringLiteral("-")));
        m_unloadedPiddbTable->setItem(
            outputRow,
            columnIndex(UnloadedColumn::Size),
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_SIZE) != 0U
                ? numericItem(
                    cells[columnIndex(UnloadedColumn::Size)],
                    row.imageSize)
                : textItem(QStringLiteral("-")));
        m_unloadedPiddbTable->setItem(
            outputRow,
            columnIndex(UnloadedColumn::TimeDateStamp),
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP) != 0U
                ? numericItem(
                    cells[columnIndex(UnloadedColumn::TimeDateStamp)],
                    row.timeDateStamp)
                : textItem(QStringLiteral("-")));
        m_unloadedPiddbTable->setItem(
            outputRow,
            columnIndex(UnloadedColumn::LoadStatus),
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS) != 0U
                ? numericItem(
                    cells[columnIndex(UnloadedColumn::LoadStatus)],
                    static_cast<std::uint32_t>(row.loadStatus))
                : textItem(QStringLiteral("-")));
        QTableWidgetItem* unloadItem =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME) != 0U
            ? numericItem(
                cells[columnIndex(UnloadedColumn::UnloadTime)],
                row.unloadTime)
            : textItem(QStringLiteral("-"));
        if ((row.flags &
                KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME) != 0U)
        {
            unloadItem->setToolTip(fixedHex64(row.unloadTime));
        }
        m_unloadedPiddbTable->setItem(
            outputRow,
            columnIndex(UnloadedColumn::UnloadTime),
            unloadItem);
    }

    m_unloadedPiddbTable->setSortingEnabled(true);
    if (m_unloadedPiddbCountLabel != nullptr)
    {
        m_unloadedPiddbCountLabel->setText(
            driverText(
                "driver.unloaded.count",
                QStringLiteral("数量：%1"))
                .arg(m_unloadedPiddbTable->rowCount()));
    }
    updateQueryStatusLabel(
        m_unloadedPiddbStatusLabel,
        m_lastUnloadedDriverResult);
}

void DriverDock::showUnloadedPiddbContextMenu(
    const QPoint& localPosition)
{
    // 输入：表格局部坐标。
    // 处理：只提供详情、复制和重新查询，不提供任何内核写动作。
    // 返回：无。
    if (m_unloadedPiddbTable == nullptr)
    {
        return;
    }
    const QModelIndex clickedIndex =
        m_unloadedPiddbTable->indexAt(localPosition);
    if (clickedIndex.isValid())
    {
        m_unloadedPiddbTable->setCurrentCell(
            clickedIndex.row(),
            clickedIndex.column());
        m_unloadedPiddbTable->selectRow(clickedIndex.row());
    }

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* detailAction = contextMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        driverText(
            "driver.unloaded.menu.detail",
            QStringLiteral("查看已卸载驱动详情")));
    QAction* copyRowAction = contextMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        driverText(
            "driver.menu.copy_row",
            QStringLiteral("复制当前行")));
    QAction* copyVisibleAction = contextMenu.addAction(
        QIcon(QStringLiteral(":/Icon/log_copy.svg")),
        driverText(
            "driver.menu.copy_visible_rows",
            QStringLiteral("复制可见行")));
    contextMenu.addSeparator();
    QAction* refreshAction = contextMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
        driverText(
            "driver.unloaded.menu.refresh",
            QStringLiteral("重新查询当前来源")));
    detailAction->setEnabled(m_unloadedPiddbTable->currentRow() >= 0);
    copyRowAction->setEnabled(m_unloadedPiddbTable->currentRow() >= 0);

    QAction* selectedAction = contextMenu.exec(
        m_unloadedPiddbTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == detailAction)
    {
        showSelectedUnloadedPiddbDetailDialog();
    }
    else if (selectedAction == copyRowAction)
    {
        copySelectedUnloadedPiddbRow();
    }
    else if (selectedAction == copyVisibleAction)
    {
        copyVisibleUnloadedPiddbRows();
    }
    else if (selectedAction == refreshAction)
    {
        refreshUnloadedDriversAsync();
    }
}

void DriverDock::showSelectedUnloadedPiddbDetailDialog()
{
    // 输入：当前选中行。
    // 处理：按 UserRole 源索引展开统一协议行和原始数值。
    // 返回：无；使用 CodeEditorWidget + OpaqueDialogStyle 只读展示。
    if (m_unloadedPiddbTable == nullptr)
    {
        return;
    }
    const int currentRow = m_unloadedPiddbTable->currentRow();
    const QTableWidgetItem* nameItem = currentRow >= 0
        ? m_unloadedPiddbTable->item(
            currentRow,
            columnIndex(UnloadedColumn::Name))
        : nullptr;
    bool indexOk = false;
    const qulonglong cacheIndex = nameItem != nullptr
        ? nameItem->data(kUnloadedCacheIndexRole).toULongLong(&indexOk)
        : 0ULL;
    if (!indexOk ||
        cacheIndex >= static_cast<qulonglong>(m_unloadedDriverCache.size()))
    {
        return;
    }

    const ksword::ark::UnloadedDriverEntry& row =
        m_unloadedDriverCache[static_cast<std::size_t>(cacheIndex)];
    const auto cells = displayCells(row);
    QString detail;
    detail += driverText(
        "driver.unloaded.detail.title",
        QStringLiteral("已卸载驱动只读详情\n"));
    detail += QStringLiteral("Source: %1 (%2)\n")
        .arg(sourceName(row.source))
        .arg(row.source);
    detail += QStringLiteral("EntryAddress: %1\n")
        .arg(fixedHex64(row.entryAddress));
    detail += QStringLiteral("Flags: %1\n")
        .arg(fixedHex32(row.flags));
    detail += QStringLiteral("Name: %1\n")
        .arg(cells[columnIndex(UnloadedColumn::Name)]);
    detail += QStringLiteral("BaseAddress: %1\n")
        .arg(cells[columnIndex(UnloadedColumn::Base)]);
    detail += QStringLiteral("ImageSize: %1\n")
        .arg(cells[columnIndex(UnloadedColumn::Size)]);
    detail += QStringLiteral("TimeDateStamp: %1\n")
        .arg(cells[columnIndex(UnloadedColumn::TimeDateStamp)]);
    detail += QStringLiteral("LoadStatus: %1\n")
        .arg(cells[columnIndex(UnloadedColumn::LoadStatus)]);
    detail += QStringLiteral("UnloadTime: %1\n")
        .arg(cells[columnIndex(UnloadedColumn::UnloadTime)]);
    if ((row.flags &
            KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME) != 0U)
    {
        detail += QStringLiteral("UnloadTimeRaw: %1\n")
            .arg(fixedHex64(row.unloadTime));
    }
    detail += QStringLiteral("QueryStatus: %1\n")
        .arg(m_lastUnloadedDriverResult.queryStatus);
    detail += QStringLiteral("ResponseFlags: %1\n")
        .arg(fixedHex32(m_lastUnloadedDriverResult.responseFlags));
    detail += QStringLiteral("LastStatus: %1\n")
        .arg(fixedHex32(
            static_cast<std::uint32_t>(
                m_lastUnloadedDriverResult.lastStatus)));

    QDialog dialog(this);
    dialog.setObjectName(
        QStringLiteral("driverDockUnloadedDriverDetailDialog"));
    dialog.setWindowTitle(
        driverText(
            "driver.unloaded.dialog.title",
            QStringLiteral("已卸载驱动详情")));
    dialog.resize(860, 620);
    dialog.setStyleSheet(
        KswordTheme::OpaqueDialogStyle(dialog.objectName()));
    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    layout->setContentsMargins(10, 10, 10, 10);
    layout->setSpacing(8);

    CodeEditorWidget* editor = new CodeEditorWidget(&dialog);
    editor->setReadOnly(true);
    editor->setText(detail);
    layout->addWidget(editor, 1);

    QDialogButtonBox* buttonBox =
        new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    QPushButton* copyButton = buttonBox->addButton(
        driverText(
            "driver.dialog.copy_detail",
            QStringLiteral("复制详情")),
        QDialogButtonBox::ActionRole);
    connect(copyButton, &QPushButton::clicked, &dialog, [editor]() {
        if (editor != nullptr && QGuiApplication::clipboard() != nullptr)
        {
            QGuiApplication::clipboard()->setText(editor->text());
        }
    });
    connect(
        buttonBox,
        &QDialogButtonBox::rejected,
        &dialog,
        &QDialog::reject);
    layout->addWidget(buttonBox);
    dialog.exec();
}

void DriverDock::copySelectedUnloadedPiddbRow()
{
    // 输入：当前表格选择。
    // 处理：复制一行 TSV。
    // 返回：无。
    if (m_unloadedPiddbTable == nullptr ||
        QGuiApplication::clipboard() == nullptr ||
        m_unloadedPiddbTable->currentRow() < 0)
    {
        return;
    }
    QStringList cells;
    for (int column = 0;
         column < m_unloadedPiddbTable->columnCount();
         ++column)
    {
        cells << escapedTsvCell(
            tableCellText(
                m_unloadedPiddbTable,
                m_unloadedPiddbTable->currentRow(),
                column));
    }
    QGuiApplication::clipboard()->setText(
        cells.join(QLatin1Char('\t')));
}

void DriverDock::copyVisibleUnloadedPiddbRows()
{
    // 输入：当前过滤后的表格。
    // 处理：复制表头与所有可见行 TSV。
    // 返回：无。
    if (m_unloadedPiddbTable == nullptr ||
        QGuiApplication::clipboard() == nullptr)
    {
        return;
    }
    QStringList lines;
    QStringList headers;
    for (int column = 0;
         column < m_unloadedPiddbTable->columnCount();
         ++column)
    {
        const QTableWidgetItem* header =
            m_unloadedPiddbTable->horizontalHeaderItem(column);
        headers << escapedTsvCell(
            header != nullptr ? header->text() : QString());
    }
    lines << headers.join(QLatin1Char('\t'));
    for (int row = 0; row < m_unloadedPiddbTable->rowCount(); ++row)
    {
        QStringList cells;
        for (int column = 0;
             column < m_unloadedPiddbTable->columnCount();
             ++column)
        {
            cells << escapedTsvCell(
                tableCellText(m_unloadedPiddbTable, row, column));
        }
        lines << cells.join(QLatin1Char('\t'));
    }
    QGuiApplication::clipboard()->setText(
        lines.join(QLatin1Char('\n')));
}
