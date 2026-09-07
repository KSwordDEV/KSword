#include "DriverDock.Internal.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/TableColumnAutoFit.h"
#include "../UI/DetailLayoutRegistry.h"

#include <QPointer>
#include <QRunnable>

using namespace ksword::driver_dock_internal;

namespace
{
    enum class IntegrityColumn : int
    {
        Class = 0,
        Object,
        Target,
        Owner,
        Cpu,
        Risk,
        Confidence,
        Detail,
        Count
    };

    int integrityColumnIndex(const IntegrityColumn column)
    {
        // 输入：完整性表列枚举。
        // 处理：转换为 QTableWidget 列号。
        // 返回：列索引。
        return static_cast<int>(column);
    }

    QString hex64(const std::uint64_t value)
    {
        // 输入：64 位地址或掩码。
        // 处理：格式化为固定宽度十六进制。
        // 返回：0x 前缀大写文本。
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString classText(const std::uint32_t evidenceClass)
    {
        // 输入：KSWORD_ARK_DRIVER_INTEGRITY_CLASS_*。
        // 处理：映射为 DriverDock 页面分组文本。
        // 返回：证据类型名称。
        switch (evidenceClass)
        {
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW: return QStringLiteral("ModuleView");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES: return QStringLiteral("PsLoadedModules");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT: return QStringLiteral("DriverObject");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION: return QStringLiteral("DriverSection");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION: return QStringLiteral("MajorFunction");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO: return QStringLiteral("FastIo");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN: return QStringLiteral("DeviceChain");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE: return QStringLiteral("Service");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_CPU_CONTROL: return QStringLiteral("CPU");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE: return QStringLiteral("Descriptor");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY: return QStringLiteral("MSR");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER: return QStringLiteral("IDT");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL: return QStringLiteral("OptionalGlobal");
        default: return QStringLiteral("Class(%1)").arg(evidenceClass);
        }
    }

    QString riskText(const std::uint32_t flags)
    {
        // 输入：KSWORD_ARK_DRIVER_INTEGRITY_RISK_* 位集合。
        // 处理：转换为紧凑风险标签。
        // 返回：无风险返回“正常”。
        if (flags == 0U)
        {
            return driverText("driver.integrity.risk.normal", QStringLiteral("正常"));
        }
        QStringList parts;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE)
            parts << driverText("driver.integrity.risk.unavailable", QStringLiteral("不可用"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED)
            parts << driverText("driver.integrity.risk.query_failed", QStringLiteral("查询失败"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED)
            parts << driverText("driver.integrity.risk.module_unresolved", QStringLiteral("模块未解析"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH)
            parts << driverText("driver.integrity.risk.owner_mismatch", QStringLiteral("Owner不匹配"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE)
            parts << driverText("driver.integrity.risk.outside_image", QStringLiteral("外跳"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH)
            parts << driverText("driver.integrity.risk.section_mismatch", QStringLiteral("Section不匹配"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING)
            parts << driverText("driver.integrity.risk.service_missing", QStringLiteral("服务缺失"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD)
            parts << driverText("driver.integrity.risk.empty_unload", QStringLiteral("Unload为空"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP)
            parts << driverText("driver.integrity.risk.device_loop", QStringLiteral("Device环"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP)
            parts << driverText("driver.integrity.risk.attached_loop", QStringLiteral("Attached环"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH)
            parts << driverText("driver.integrity.risk.cross_driver_attach", QStringLiteral("跨驱动挂接"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER)
            parts << driverText("driver.integrity.risk.null_pointer", QStringLiteral("空指针"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER)
            parts << driverText("driver.integrity.risk.idt_external_owner", QStringLiteral("IDT外部Owner"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED)
            parts << driverText("driver.integrity.risk.wp_disabled", QStringLiteral("WP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED)
            parts << driverText("driver.integrity.risk.nxe_disabled", QStringLiteral("NXE关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED)
            parts << driverText("driver.integrity.risk.smep_disabled", QStringLiteral("SMEP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED)
            parts << driverText("driver.integrity.risk.smap_disabled", QStringLiteral("SMAP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID)
            parts << driverText("driver.integrity.risk.descriptor_invalid", QStringLiteral("描述符异常"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE)
            parts << driverText("driver.integrity.risk.dyndata_unavailable", QStringLiteral("DynData缺失"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED)
            parts << driverText("driver.integrity.risk.truncated", QStringLiteral("截断"));
        return parts.join(QStringLiteral(" | "));
    }

    QString entryStatusText(const std::uint32_t statusValue)
    {
        // 输入：单条完整性证据的 entryStatus。
        // 处理：把常见协议状态映射为人可读文字，未知值保留数字。
        // 返回：表格摘要使用的短状态。
        switch (statusValue)
        {
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK: return QStringLiteral("OK");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL: return QStringLiteral("Partial");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_NOT_FOUND: return QStringLiteral("NotFound");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_BUFFER_TOO_SMALL: return QStringLiteral("BufferTooSmall");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_QUERY_FAILED: return QStringLiteral("QueryFailed");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_UNAVAILABLE: return QStringLiteral("Unavailable");
        default: return QStringLiteral("Status(%1)").arg(statusValue);
        }
    }

    QString integritySourceText(const std::uint32_t sourceMask)
    {
        // 输入：KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_* 位集合。
        // 处理：转换为来源摘要，帮助阅读最后一列而不是只看十六进制掩码。
        // 返回：来源文本。
        if (sourceMask == 0U)
        {
            return driverText("driver.integrity.source.none", QStringLiteral("无来源"));
        }

        QStringList parts;
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE) parts << QStringLiteral("SystemModule");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB) parts << QStringLiteral("AuxKlib");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES) parts << QStringLiteral("PsLoadedModules");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT) parts << QStringLiteral("DriverObject");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION) parts << QStringLiteral("DriverSection");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY) parts << QStringLiteral("ServiceRegistry");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_CPU_REGISTER) parts << QStringLiteral("CPU");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT) parts << QStringLiteral("IDT");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT) parts << QStringLiteral("GDT");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR) parts << QStringLiteral("MSR");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA) parts << QStringLiteral("DynData");
        return parts.join(QStringLiteral(" | "));
    }

    class NumericItem final : public QTableWidgetItem
    {
    public:
        NumericItem(const QString& text, const qulonglong value)
            : QTableWidgetItem(text)
        {
            // 输入：显示文本和排序数值。
            // 处理：UserRole 保存数值。
            // 返回：构造函数无返回。
            setData(Qt::UserRole, QVariant::fromValue<qulonglong>(value));
            setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            // 输入：另一 item。
            // 处理：优先按 UserRole 数值排序。
            // 返回：排序比较结果。
            bool leftOk = false;
            bool rightOk = false;
            const qulonglong leftValue = data(Qt::UserRole).toULongLong(&leftOk);
            const qulonglong rightValue = other.data(Qt::UserRole).toULongLong(&rightOk);
            if (leftOk && rightOk)
            {
                return leftValue < rightValue;
            }
            return QTableWidgetItem::operator<(other);
        }
    };

    QTableWidgetItem* textItem(const QString& value)
    {
        // 输入：展示文本。
        // 处理：创建只读 item。
        // 返回：交给表格接管生命周期。
        QTableWidgetItem* item = new QTableWidgetItem(value);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QString tableCellText(QTableWidget* table, const int rowIndex, const int columnIndex)
    {
        // 输入：目标表格、行号和列号。
        // 处理：安全读取单元格文本，空 item 归一化为空字符串。
        // 返回：可用于 TSV 或详情展示的文本。
        if (table == nullptr)
        {
            return QString();
        }
        QTableWidgetItem* item = table->item(rowIndex, columnIndex);
        return item != nullptr ? item->text() : QString();
    }

    QString escapeTsvCell(QString value)
    {
        // 输入：单元格原始文本。
        // 处理：把换行和 Tab 规整为空格，避免复制后破坏列结构。
        // 返回：TSV 安全文本。
        value.replace(QLatin1Char('\t'), QLatin1Char(' '));
        value.replace(QLatin1Char('\r'), QLatin1Char(' '));
        value.replace(QLatin1Char('\n'), QLatin1Char(' '));
        return value.trimmed();
    }

    void copyIntegrityTableCurrentRow(QTableWidget* table)
    {
        // copyIntegrityTableCurrentRow：
        // - 输入：完整性证据表；
        // - 处理：复制当前行 TSV；
        // - 返回：无，不执行修复、卸载或清理动作。
        if (table == nullptr || QGuiApplication::clipboard() == nullptr)
        {
            return;
        }

        const int currentRow = table->currentRow();
        if (currentRow < 0)
        {
            return;
        }

        QStringList cells;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            cells << escapeTsvCell(tableCellText(table, currentRow, columnIndex));
        }
        QGuiApplication::clipboard()->setText(cells.join(QLatin1Char('\t')));
    }

    void installIntegrityTableCopyMenu(QTableWidget* table)
    {
        // installIntegrityTableCopyMenu：
        // - 输入：完整性证据表；
        // - 处理：安装复制当前行菜单；
        // - 返回：无，仅做 UI/剪贴板操作。
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition) {
            const QModelIndex clickedIndex = table->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                table->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            }

            QMenu contextMenu(table);
            contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                driverText("driver.menu.copy_row", QStringLiteral("复制当前行")));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            if (contextMenu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyIntegrityTableCurrentRow(table);
            }
        });
    }

    QTableWidgetItem* numericItem(const QString& text, const qulonglong value)
    {
        // 输入：展示文本和排序数值。
        // 处理：创建 NumericItem。
        // 返回：交给表格接管生命周期。
        return new NumericItem(text, value);
    }

    bool parseAddressText(const QString& text, std::uint64_t& valueOut)
    {
        // 输入：用户输入的十六进制或十进制地址。
        // 处理：支持 0x 前缀；空文本解析为 0。
        // 返回：true 表示解析成功。
        const QString trimmed = text.trimmed();
        if (trimmed.isEmpty())
        {
            valueOut = 0;
            return true;
        }
        bool ok = false;
        valueOut = trimmed.toULongLong(&ok, trimmed.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10);
        return ok;
    }

    QString detailText(const ksword::ark::DriverIntegrityEvidenceEntry& row)
    {
        // 输入：完整性证据行。
        // 处理：展开所有关键字段。
        // 返回：详情文本。
        QString text;
        text += driverText("driver.integrity.detail.title", QStringLiteral("驱动完整性证据详情\n"));
        text += QStringLiteral("Class: %1 (%2)\n").arg(classText(row.evidenceClass)).arg(row.evidenceClass);
        text += QStringLiteral("RiskFlags: %1 (0x%2)\n").arg(riskText(row.riskFlags)).arg(row.riskFlags, 8, 16, QChar('0'));
        text += QStringLiteral("SourceMask: 0x%1\n").arg(row.sourceMask, 8, 16, QChar('0'));
        text += QStringLiteral("EntryStatus: %1\n").arg(row.entryStatus);
        text += QStringLiteral("StatusFlags: 0x%1\n").arg(row.statusFlags, 8, 16, QChar('0'));
        text += QStringLiteral("FieldMask: 0x%1\n").arg(row.fieldMask, 8, 16, QChar('0'));
        text += QStringLiteral("RiskScore: %1\n").arg(row.riskScore);
        text += QStringLiteral("Confidence: %1\n").arg(row.confidence);
        text += QStringLiteral("ObjectAddress: %1\n").arg(hex64(row.objectAddress));
        text += QStringLiteral("TargetAddress: %1\n").arg(hex64(row.targetAddress));
        text += QStringLiteral("OwnerModule: %1\n").arg(QString::fromStdWString(row.ownerModule));
        text += QStringLiteral("OwnerModuleBase: %1\n").arg(hex64(row.ownerModuleBase));
        text += QStringLiteral("OwnerModuleSize: %1\n").arg(row.ownerModuleSize);
        text += QStringLiteral("DriverObject: %1 DriverStart: %2 DriverSize: %3\n")
            .arg(hex64(row.driverObjectAddress))
            .arg(hex64(row.driverStart))
            .arg(hex64(row.driverSize));
        text += QStringLiteral("KLDR: entry=%1 listHead=%2 dllBase=%3 size=0x%4\n")
            .arg(hex64(row.kldrEntryAddress))
            .arg(hex64(row.kldrListHeadAddress))
            .arg(hex64(row.kldrDllBase))
            .arg(row.kldrSizeOfImage, 8, 16, QChar('0'));
        text += QStringLiteral("CPU: group=%1 cpu=%2 vector=%3\n")
            .arg(row.processorGroup)
            .arg(row.processorNumber)
            .arg(row.vector);
        text += QStringLiteral("Detail: %1\n").arg(QString::fromStdWString(row.detail));
        return text;
    }

    QString integritySummaryText(const ksword::ark::DriverIntegrityEvidenceEntry& row)
    {
        // 输入：完整性证据行。
        // 处理：生成表格末列摘要，避免把 R0 原始 detail 直接塞入表格。
        // 返回：一行中文说明；完整原始 detail 保留在详情编辑器/弹窗。
        const QString rawDetailText = QString::fromStdWString(row.detail).trimmed();
        const QString detailSummaryText = rawDetailText.isEmpty()
            ? driverText("driver.integrity.detail.no_extra_detail", QStringLiteral("驱动未返回额外说明"))
            : rawDetailText.left(160);
        return driverText("driver.integrity.detail.summary", QStringLiteral("%1；状态=%2；来源=%3；%4"))
            .arg(riskText(row.riskFlags))
            .arg(entryStatusText(row.entryStatus))
            .arg(integritySourceText(row.sourceMask))
            .arg(detailSummaryText);
    }

    // appendEvidenceRow：
    // - 输入：证据表和单元格文本；
    // - 处理：一次性写入一行只读证据；
    // - 返回：无。
    void appendEvidenceRow(
        QTableWidget* table,
        const int rowIndex,
        const QString& evidenceText,
        const QString& objectText,
        const QString& targetText,
        const QString& riskText,
        const QString& confidenceText,
        const QString& detailTextValue)
    {
        if (table == nullptr)
        {
            return;
        }
        table->setItem(rowIndex, 0, textItem(evidenceText));
        table->setItem(rowIndex, 1, textItem(objectText));
        table->setItem(rowIndex, 2, textItem(targetText));
        table->setItem(rowIndex, 3, textItem(riskText));
        table->setItem(rowIndex, 4, textItem(confidenceText));
        table->setItem(rowIndex, 5, textItem(detailTextValue));
    }
}

void DriverDock::initializeIntegrityTab()
{
    // 输入：无，由 initializeUi 调用。
    // 处理：创建只读驱动完整性页。
    // 返回：无。
    m_integrityPage = new QWidget(m_tabWidget);
    m_integrityLayout = new QVBoxLayout(m_integrityPage);
    m_integrityLayout->setContentsMargins(4, 4, 4, 4);
    m_integrityLayout->setSpacing(6);

    QHBoxLayout* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(6);

    m_integrityDriverNameEdit = new QLineEdit(m_integrityPage);
    m_integrityDriverNameEdit->setPlaceholderText(
        driverText("driver.integrity.form.driver_name.placeholder", QStringLiteral("\\Driver\\Name（可选）")));
    m_integrityModuleBaseEdit = new QLineEdit(m_integrityPage);
    m_integrityModuleBaseEdit->setPlaceholderText(
        driverText("driver.integrity.form.module_base.placeholder", QStringLiteral("模块基址（可选）")));
    m_integrityModuleBaseEdit->setMaximumWidth(150);

    m_integrityFillFromSelectionButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QString(), m_integrityPage);
    KswordTheme::ApplyCompactIconButtonMetrics(m_integrityFillFromSelectionButton);
    m_integrityFillFromSelectionButton->setToolTip(
        driverText("driver.integrity.form.fill.tooltip", QStringLiteral("从当前服务选择填充 DriverObject 名称")));

    m_integrityRefreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), m_integrityPage);
    KswordTheme::ApplyCompactIconButtonMetrics(m_integrityRefreshButton);
    m_integrityRefreshButton->setToolTip(
        driverText(
            "driver.integrity.form.refresh.tooltip",
            QStringLiteral("查询 DriverObject/LDR/FastIo/CPU 完整性证据")));

    m_integrityCpuOnlyButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_threads.svg")), QString(), m_integrityPage);
    KswordTheme::ApplyCompactIconButtonMetrics(m_integrityCpuOnlyButton);
    m_integrityCpuOnlyButton->setToolTip(
        driverText("driver.integrity.form.cpu_only.tooltip", QStringLiteral("仅查询 CPU entry / IDT / MSR 证据")));

    m_integrityRiskOnlyCheck = new QCheckBox(
        driverText("driver.integrity.form.risk_only", QStringLiteral("仅风险项")),
        m_integrityPage);
    m_integrityRiskOnlyCheck->setChecked(false);

    m_integrityMaxRowsSpin = new QSpinBox(m_integrityPage);
    m_integrityMaxRowsSpin->setRange(64, static_cast<int>(KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS));
    m_integrityMaxRowsSpin->setValue(1024);
    m_integrityMaxRowsSpin->setToolTip(
        driverText("driver.integrity.form.max_rows.tooltip", QStringLiteral("最大返回证据行数")));

    m_integrityStatusLabel = new QLabel(
        driverText("driver.integrity.status.waiting", QStringLiteral("状态：等待查询")),
        m_integrityPage);
    m_integrityStatusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);

    toolLayout->addWidget(new QLabel(QStringLiteral("DriverObject:"), m_integrityPage));
    toolLayout->addWidget(m_integrityDriverNameEdit, 1);
    toolLayout->addWidget(m_integrityModuleBaseEdit);
    toolLayout->addWidget(m_integrityFillFromSelectionButton);
    toolLayout->addWidget(m_integrityRefreshButton);
    toolLayout->addWidget(m_integrityCpuOnlyButton);
    toolLayout->addWidget(m_integrityRiskOnlyCheck);
    toolLayout->addWidget(new QLabel(
        driverText("driver.integrity.form.rows_label", QStringLiteral("行数:")),
        m_integrityPage));
    toolLayout->addWidget(m_integrityMaxRowsSpin);
    toolLayout->addWidget(m_integrityStatusLabel, 1);
    m_integrityLayout->addLayout(toolLayout);

    QSplitter* splitter = new QSplitter(Qt::Vertical, m_integrityPage);
    m_integrityLayout->addWidget(splitter, 1);

    m_integrityTable = new ks::ui::VisibleTableWidget(splitter);
    m_integrityTable->setColumnCount(integrityColumnIndex(IntegrityColumn::Count));
    m_integrityTable->setHorizontalHeaderLabels(driverIntegrityTableHeaders());
    m_integrityTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_integrityTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_integrityTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_integrityTable->setAlternatingRowColors(true);
    m_integrityTable->setSortingEnabled(true);
    m_integrityTable->verticalHeader()->setVisible(false);
    m_integrityTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_integrityTable->horizontalHeader()->setSectionResizeMode(integrityColumnIndex(IntegrityColumn::Detail), QHeaderView::Stretch);
    installIntegrityTableCopyMenu(m_integrityTable);
    splitter->addWidget(m_integrityTable);

    // 完整性详情区使用项目统一 CodeEditorWidget，方便复制、查找和查看多行 R0 证据。
    m_integrityDetailEdit = new CodeEditorWidget(splitter);
    m_integrityDetailEdit->setReadOnly(true);
    m_integrityDetailEdit->setText(driverText(
        "driver.integrity.detail.initial",
        QStringLiteral("选择一条完整性证据查看 DriverObject / MajorFunction / FastIo / LDR / CPU entry 详情。")));
    splitter->addWidget(m_integrityDetailEdit);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(
        m_integrityTable, m_integrityDetailEdit, m_integrityPage);

    m_tabWidget->addTab(
        m_integrityPage,
        QIcon(QStringLiteral(":/Icon/process_critical.svg")),
        driverText("driver.tab.integrity", QStringLiteral("驱动完整性")));

    rebuildModuleCrossViewTable();
}

void DriverDock::refreshDriverIntegrityAsync(const bool cpuOnly)
{
    // 输入：cpuOnly 控制查询范围。
    // 处理：后台调用 ArkDriverClient，主线程回填完整性证据。
    // 返回：无。
    if (m_integrityQuerying)
    {
        return;
    }
    std::uint64_t moduleBase = 0;
    if (!parseAddressText(m_integrityModuleBaseEdit != nullptr ? m_integrityModuleBaseEdit->text() : QString(), moduleBase))
    {
        if (m_integrityStatusLabel != nullptr)
        {
            m_integrityStatusLabel->setText(
                driverText("driver.integrity.status.module_base_invalid", QStringLiteral("状态：模块基址解析失败")));
        }
        return;
    }

    const std::wstring driverName = m_integrityDriverNameEdit != nullptr
        ? m_integrityDriverNameEdit->text().trimmed().toStdWString()
        : std::wstring();
    const unsigned long maxRows = static_cast<unsigned long>(
        m_integrityMaxRowsSpin != nullptr ? m_integrityMaxRowsSpin->value() : 1024);

    m_integrityQuerying = true;
    const std::uint64_t ticket = ++m_integrityQueryTicket;
    if (m_integrityRefreshButton != nullptr) m_integrityRefreshButton->setEnabled(false);
    if (m_integrityCpuOnlyButton != nullptr) m_integrityCpuOnlyButton->setEnabled(false);
    if (m_integrityStatusLabel != nullptr)
    {
        m_integrityStatusLabel->setText(
            driverText("driver.integrity.status.querying", QStringLiteral("状态：查询中...")));
    }

    QPointer<DriverDock> guardThis(this);
    QRunnable* task = QRunnable::create([guardThis, ticket, driverName, moduleBase, maxRows, cpuOnly]() {
        const ksword::ark::DriverClient client;
        ksword::ark::DriverIntegrityResult result = cpuOnly
            ? client.queryKernelCpuIntegrity(
                KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES,
                maxRows,
                KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS)
            : client.queryDriverIntegrity(
                driverName,
                moduleBase,
                KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS,
                maxRows,
                KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS);

        QMetaObject::invokeMethod(guardThis.data(), [guardThis, ticket, result = std::move(result)]() mutable {
            const auto deferredResult =
                std::make_shared<ksword::ark::DriverIntegrityResult>(std::move(result));
            const auto commitIntegrity = [guardThis, ticket, deferredResult]()
            {
            const ksword::ark::DriverIntegrityResult& result = *deferredResult;
            if (guardThis == nullptr || guardThis->m_integrityQueryTicket != ticket)
            {
                return;
            }
            guardThis->m_integrityQuerying = false;
            if (guardThis->m_integrityRefreshButton != nullptr) guardThis->m_integrityRefreshButton->setEnabled(true);
            if (guardThis->m_integrityCpuOnlyButton != nullptr) guardThis->m_integrityCpuOnlyButton->setEnabled(true);

            guardThis->m_lastDriverIntegrityResult = result;
            guardThis->m_driverIntegrityCache = result.entries;
            guardThis->rebuildDriverIntegrityTable();
            guardThis->rebuildModuleCrossViewTable();
            guardThis->showSelectedDriverIntegrityDetail();

            if (guardThis->m_integrityStatusLabel != nullptr)
            {
                if (!result.io.ok)
                {
                    guardThis->m_integrityStatusLabel->setText(result.unsupported
                        ? driverText(
                            "driver.integrity.status.not_integrated",
                            QStringLiteral("状态：未集成/驱动过旧，等待 R0 支持"))
                        : driverText(
                            "driver.integrity.status.query_failed",
                            QStringLiteral("状态：查询失败 %1"))
                            .arg(describeDriverCollection(result.io)));
                    guardThis->m_integrityStatusLabel->setStyleSheet(
                        QStringLiteral("color:%1; font-weight:700;")
                            .arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
                }
                else
                {
                    const bool degraded =
                        (result.statusFlags &
                            (KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL |
                                KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED |
                                KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_TRUNCATED |
                                KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED)) != 0U;
                    guardThis->m_integrityStatusLabel->setText(
                        driverText(
                            "driver.integrity.status.summary",
                            QStringLiteral("状态：%1，返回 %2/%3，CPU %4，模块 %5，FieldFlags=0x%6，StatusFlags=0x%7"))
                        .arg(degraded ? QStringLiteral("Partial/Degraded") : QStringLiteral("OK"))
                        .arg(result.entries.size())
                        .arg(result.totalCount)
                        .arg(result.cpuCount)
                        .arg(result.moduleCount)
                        .arg(result.fieldFlags, 8, 16, QChar('0'))
                        .arg(result.statusFlags, 8, 16, QChar('0')));
                    guardThis->m_integrityStatusLabel->setStyleSheet(
                        QStringLiteral("color:%1; font-weight:700;")
                            .arg((degraded ? KswordTheme::WarningColor() : KswordTheme::SuccessColor())
                                .name(QColor::HexRgb)));
                }
            }
            };

            if (guardThis == nullptr || guardThis->m_integrityQueryTicket != ticket)
            {
                return;
            }
            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("driver-integrity-cross-view-apply"),
                { guardThis->m_integrityTable, guardThis->m_moduleCrossViewTable },
                commitIntegrity))
            {
                return;
            }
            commitIntegrity();
        }, Qt::QueuedConnection);
    });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void DriverDock::rebuildDriverIntegrityTable()
{
    // 输入：无，读取 m_driverIntegrityCache 和过滤控件。
    // 处理：只重绘表格，不访问驱动。
    // 返回：无。
    if (m_integrityTable == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_integrityDetailEdit);
    const bool riskOnly = m_integrityRiskOnlyCheck != nullptr && m_integrityRiskOnlyCheck->isChecked();
    std::vector<std::size_t> visibleIndexes;
    for (std::size_t index = 0; index < m_driverIntegrityCache.size(); ++index)
    {
        if (riskOnly && m_driverIntegrityCache[index].riskFlags == 0U)
        {
            continue;
        }
        visibleIndexes.push_back(index);
    }

    const QSignalBlocker blocker(m_integrityTable);
    m_integrityTable->setSortingEnabled(false);
    m_integrityTable->setRowCount(static_cast<int>(visibleIndexes.size()));
    for (int rowIndex = 0; rowIndex < static_cast<int>(visibleIndexes.size()); ++rowIndex)
    {
        const std::size_t cacheIndex = visibleIndexes[static_cast<std::size_t>(rowIndex)];
        const auto& row = m_driverIntegrityCache[cacheIndex];
        QTableWidgetItem* classItem = textItem(classText(row.evidenceClass));
        classItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(cacheIndex)));
        m_integrityTable->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::Class), classItem);
        m_integrityTable->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::Object), numericItem(hex64(row.objectAddress), row.objectAddress));
        m_integrityTable->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::Target), numericItem(hex64(row.targetAddress), row.targetAddress));
        m_integrityTable->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::Owner),
            textItem(QStringLiteral("%1 %2").arg(QString::fromStdWString(row.ownerModule), hex64(row.ownerModuleBase))));
        m_integrityTable->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::Cpu),
            textItem(QStringLiteral("G%1 CPU%2 V%3").arg(row.processorGroup).arg(row.processorNumber).arg(row.vector)));
        m_integrityTable->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::Risk), textItem(riskText(row.riskFlags)));
        m_integrityTable->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::Confidence), numericItem(QString::number(row.confidence), row.confidence));
        m_integrityTable->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::Detail), textItem(integritySummaryText(row)));
    }
    if (m_integrityTable->rowCount() > 0 && m_integrityTable->currentRow() < 0)
    {
        m_integrityTable->setCurrentCell(0, integrityColumnIndex(IntegrityColumn::Class));
    }
    m_integrityTable->setSortingEnabled(true);
    ks::ui::RequestTableColumnAutoFit(m_integrityTable);
}

void DriverDock::rebuildModuleCrossViewTable()
{
    // 输入：当前完整性缓存。
    // 处理：从 DriverObject / DriverSection / DeviceChain / Service 等证据中投影可读行。
    // 返回：无。
    if (m_moduleCrossViewTable == nullptr)
    {
        return;
    }

    const QSignalBlocker blocker(m_moduleCrossViewTable);
    m_moduleCrossViewTable->setSortingEnabled(false);
    m_moduleCrossViewTable->setRowCount(0);

    int visibleRows = 0;
    for (const auto& row : m_driverIntegrityCache)
    {
        if (row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW &&
            row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES &&
            row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT &&
            row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION &&
            row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN &&
            row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE)
        {
            continue;
        }

        const int rowIndex = m_moduleCrossViewTable->rowCount();
        m_moduleCrossViewTable->insertRow(rowIndex);
        appendEvidenceRow(
            m_moduleCrossViewTable,
            rowIndex,
            classText(row.evidenceClass),
            hex64(row.objectAddress),
            hex64(row.targetAddress),
            riskText(row.riskFlags),
            QString::number(row.confidence),
            integritySummaryText(row));
        ++visibleRows;
    }

    if (visibleRows == 0)
    {
        m_moduleCrossViewTable->setRowCount(1);
        appendEvidenceRow(
            m_moduleCrossViewTable,
            0,
            QStringLiteral("ModuleView"),
            QStringLiteral("Unavailable"),
            QStringLiteral("-"),
            driverText("driver.integrity.risk.normal", QStringLiteral("正常")),
            QStringLiteral("0"),
            driverText(
                "driver.integrity.cross_view.empty",
                QStringLiteral("当前完整性缓存没有可投影的模块交叉视图证据。")));
    }

    if (m_moduleCrossViewStatusLabel != nullptr)
    {
        m_moduleCrossViewStatusLabel->setText(
            driverText(
                "driver.integrity.cross_view.updated",
                QStringLiteral("状态：模块 Cross-View 已更新，显示 %1 条。"))
            .arg(m_moduleCrossViewTable->rowCount()));
    }
    m_moduleCrossViewTable->setSortingEnabled(true);
}

bool DriverDock::selectedPiDdbEntryIdentity(
    ksword::ark::PiDdbEntry* identity) const
{
    // DriverDock.Unloaded.cpp 把源缓存索引写入名称列的专用角色。
    constexpr int unloadedCacheIndexRole = Qt::UserRole + 57;
    constexpr std::uint32_t requiredIdentityFlags =
        KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_NAME |
        KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP |
        KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS;

    if (m_unloadedDriverQuerying ||
        m_unloadedPiddbTable == nullptr ||
        m_unloadedPiddbSourceGroup == nullptr ||
        m_unloadedPiddbSourceGroup->checkedId() !=
            KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE ||
        !m_lastUnloadedDriverResult.io.ok ||
        m_lastUnloadedDriverResult.source !=
            KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE)
    {
        return false;
    }

    const int currentRow = m_unloadedPiddbTable->currentRow();
    const QTableWidgetItem* nameItem = currentRow >= 0
        ? m_unloadedPiddbTable->item(currentRow, 0)
        : nullptr;
    bool indexOk = false;
    const qulonglong cacheIndex = nameItem != nullptr
        ? nameItem->data(unloadedCacheIndexRole).toULongLong(&indexOk)
        : 0ULL;
    if (!indexOk ||
        cacheIndex >= static_cast<qulonglong>(m_unloadedDriverCache.size()))
    {
        return false;
    }

    const ksword::ark::UnloadedDriverEntry& row =
        m_unloadedDriverCache[static_cast<std::size_t>(cacheIndex)];
    if (row.source != KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE ||
        (row.flags & requiredIdentityFlags) != requiredIdentityFlags ||
        row.entryAddress == 0ULL ||
        row.driverName.empty())
    {
        return false;
    }

    if (identity != nullptr)
    {
        identity->entryAddress = row.entryAddress;
        identity->timeDateStamp = row.timeDateStamp;
        identity->loadStatus = row.loadStatus;
        identity->driverName = row.driverName;
    }
    return true;
}

void DriverDock::deleteSelectedPiDdbEntry()
{
    ksword::ark::PiDdbEntry expected{};
    if (!selectedPiDdbEntryIdentity(&expected))
    {
        return;
    }

    const ksword::ark::DriverClient client;
    const ksword::ark::PiDdbDeleteResult preflight =
        client.deletePiDdbEntry(expected, false, false);
    if (!preflight.io.ok ||
        preflight.status != KSWORD_ARK_PIDDB_DELETE_STATUS_FORCE_REQUIRED)
    {
        QMessageBox::critical(
            this,
            driverText(
                "driver.piddb.delete.title",
                QStringLiteral("删除 PiDDB 表项")),
            driverText(
                "driver.piddb.delete.preflight_failed",
                QStringLiteral(
                    "R0 精确身份预检失败。状态 %1，NTSTATUS %2。\n%3"))
                .arg(preflight.status)
                .arg(formatNtStatusText(preflight.lastStatus))
                .arg(describeDriverCollection(preflight.io)));
        return;
    }

    QMessageBox::warning(
        this,
        driverText(
            "driver.piddb.delete.warning_title",
            QStringLiteral("高风险：修改内核驱动历史缓存")),
        driverText(
            "driver.piddb.delete.warning",
            QStringLiteral(
                "将从活动 PiDDB AVL 表删除“%1”（时间戳 0x%2，地址 %3）。"
                "这会改变内核驱动加载历史，可能影响诊断、安全产品或系统稳定性；"
                "操作不可由本程序自动撤销。"))
            .arg(QString::fromStdWString(expected.driverName))
            .arg(expected.timeDateStamp, 8, 16, QLatin1Char('0'))
            .arg(hex64(expected.entryAddress)));

    bool accepted = false;
    const QString confirmation = QInputDialog::getText(
        this,
        driverText(
            "driver.piddb.delete.confirm_title",
            QStringLiteral("确认删除 PiDDB 表项")),
        driverText(
            "driver.piddb.delete.confirm_prompt",
            QStringLiteral("输入 DELETE PIDDB 继续：")),
        QLineEdit::Normal,
        QString(),
        &accepted);
    if (!accepted || confirmation != QStringLiteral("DELETE PIDDB"))
    {
        return;
    }

    const ksword::ark::PiDdbDeleteResult deleted =
        client.deletePiDdbEntry(expected, true, true);
    if (!deleted.io.ok ||
        deleted.status != KSWORD_ARK_PIDDB_DELETE_STATUS_OK)
    {
        QMessageBox::critical(
            this,
            driverText(
                "driver.piddb.delete.title",
                QStringLiteral("删除 PiDDB 表项")),
            driverText(
                "driver.piddb.delete.failed",
                QStringLiteral("删除失败。状态 %1，NTSTATUS %2。\n%3"))
                .arg(deleted.status)
                .arg(formatNtStatusText(deleted.lastStatus))
                .arg(describeDriverCollection(deleted.io)));
        return;
    }

    QMessageBox::information(
        this,
        driverText(
            "driver.piddb.delete.title",
            QStringLiteral("删除 PiDDB 表项")),
        driverText(
            "driver.piddb.delete.completed",
            QStringLiteral(
                "精确表项已删除，并在同一内核锁保护下复核为不存在。剩余 %1 项。"))
            .arg(deleted.remainingRows));
    refreshUnloadedDriversAsync();
}

void DriverDock::showSelectedDriverIntegrityDetail()
{
    // 输入：无，读取当前完整性表选中行。
    // 处理：通过缓存索引展开详情。
    // 返回：无。
    if (m_integrityDetailEdit == nullptr || m_integrityTable == nullptr)
    {
        return;
    }
    const int currentRow = m_integrityTable->currentRow();
    if (currentRow < 0)
    {
        m_integrityDetailEdit->setText(
            driverText("driver.integrity.detail.select_row", QStringLiteral("请选择一条驱动完整性证据。")));
        return;
    }
    const QTableWidgetItem* classItem = m_integrityTable->item(currentRow, integrityColumnIndex(IntegrityColumn::Class));
    bool ok = false;
    const qulonglong cacheIndex = classItem != nullptr ? classItem->data(Qt::UserRole + 1).toULongLong(&ok) : 0ULL;
    if (!ok || cacheIndex >= static_cast<qulonglong>(m_driverIntegrityCache.size()))
    {
        return;
    }
    m_integrityDetailEdit->setText(detailText(m_driverIntegrityCache[static_cast<std::size_t>(cacheIndex)]));
}
