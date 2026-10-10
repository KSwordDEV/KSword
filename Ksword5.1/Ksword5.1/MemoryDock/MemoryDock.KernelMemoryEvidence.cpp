#include "MemoryDock.Internal.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PageControlStyle.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/AdaptivePageScroll.h" // ks::ui::EnablePageInnerScroll：页内滚动壳。
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../UI/TableColumnAutoFit.h"

#include <memory>

using namespace ksword::memory_dock_internal;

namespace
{
    enum class EvidenceColumn : int
    {
        Address = 0,
        Size,
        Kind,
        Owner,
        Permissions,
        Risk,
        TextHash,
        Detail,
        Count
    };

    int evidenceColumnIndex(const EvidenceColumn column)
    {
        // 输入：内核内存证据列枚举。
        // 处理：转换为 Qt 表格使用的 int 列索引。
        // 返回：对应列号。
        return static_cast<int>(column);
    }

    QString wideToQString(const std::wstring& value)
    {
        // 输入：ArkDriverClient 返回的宽字符串。
        // 处理：转换为 QString；空字符串保持为空。
        // 返回：Qt 可展示文本。
        return value.empty() ? QString() : QString::fromStdWString(value);
    }

    QString memoryEvidenceIoMessageText(const std::string& messageText)
    {
        // 输入：ArkDriverClient 返回的原始 io.message。
        // 处理：将 DeviceIoControl/unsupported/空消息等底层字符串转换为用户可读说明。
        // 返回：适合状态栏和详情区展示的中文文本。
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息");
        }

        const QString rawText = QString::fromStdString(messageText).trimmed();
        if (rawText.isEmpty())
        {
            return QStringLiteral("无额外驱动消息");
        }
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该内存证据入口");
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供该内存证据入口");
        }
        if (rawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("invalid"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动返回数据格式不完整，当前证据表已清空等待下次刷新");
        }
        return rawText;
    }

    QString bytesToHex(const std::vector<std::uint8_t>& bytes)
    {
        // 输入：样本字节数组。
        // 处理：以空格分隔的大写十六进制展示，限制由 R0 协议保证。
        // 返回：可复制的十六进制文本。
        QStringList parts;
        parts.reserve(static_cast<int>(bytes.size()));
        for (const std::uint8_t byteValue : bytes)
        {
            parts << QStringLiteral("%1").arg(byteValue, 2, 16, QChar('0')).toUpper();
        }
        return parts.join(QStringLiteral(" "));
    }

    QString hex64(const std::uint64_t value)
    {
        // 输入：64 位地址或哈希值。
        // 处理：格式化为固定宽度十六进制。
        // 返回：0x 前缀大写字符串。
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString sizeText(const std::uint64_t bytes)
    {
        // 输入：字节数。
        // 处理：在 KB/MB/GB 和原始字节之间选择紧凑展示。
        // 返回：可读大小字符串。
        if (bytes >= 1024ULL * 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 GB").arg(static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
        }
        if (bytes >= 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 MB").arg(static_cast<double>(bytes) / (1024.0 * 1024.0), 0, 'f', 2);
        }
        if (bytes >= 1024ULL)
        {
            return QStringLiteral("%1 KB").arg(static_cast<double>(bytes) / 1024.0, 0, 'f', 2);
        }
        return QStringLiteral("%1 B").arg(static_cast<qulonglong>(bytes));
    }

    QString evidenceKindText(const std::uint32_t kind)
    {
        // 输入：KSWORD_ARK_MEMORY_EVIDENCE_KIND_*。
        // 处理：映射为 UI 分组文本。
        // 返回：中文证据类型。
        switch (kind)
        {
        case KSWORD_ARK_MEMORY_EVIDENCE_KIND_EXECUTABLE_RANGE:
            return QStringLiteral("执行页");
        case KSWORD_ARK_MEMORY_EVIDENCE_KIND_BIGPOOL:
            return QStringLiteral("BigPool");
        case KSWORD_ARK_MEMORY_EVIDENCE_KIND_TEXT_SECTION_MEMORY:
            return QStringLiteral("text hash");
        case KSWORD_ARK_MEMORY_EVIDENCE_KIND_UNKNOWN:
        default:
            return QStringLiteral("未知(%1)").arg(kind);
        }
    }

    QString ownerKindText(const std::uint32_t ownerKind)
    {
        // 输入：KSWORD_ARK_MEMORY_EVIDENCE_OWNER_*。
        // 处理：映射为 owner 分类标签。
        // 返回：中文 owner 类型。
        switch (ownerKind)
        {
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_LOADED_MODULE:
            return QStringLiteral("LoadedModule");
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NONMODULE:
            return QStringLiteral("NonModule");
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_BIGPOOL:
            return QStringLiteral("BigPool");
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_SYSTEM_PTE:
            return QStringLiteral("SystemPte");
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_MDL_LIKE:
            return QStringLiteral("MdlLike");
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_UNKNOWN:
        default:
            return QStringLiteral("Unknown(%1)").arg(ownerKind);
        }
    }

    QString permissionText(const std::uint32_t flags)
    {
        // 输入：KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_* 位集合。
        // 处理：转换为 R/W/X/NX/Large 等紧凑文本。
        // 返回：权限文本。
        QStringList parts;
        QString rwx;
        rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_READ) ? QChar('R') : QChar('-');
        rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE) ? QChar('W') : QChar('-');
        rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) ? QChar('X') : QChar('-');
        parts << rwx;
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_PRESENT) parts << QStringLiteral("Present");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_NX) parts << QStringLiteral("NX");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_LARGE) parts << QStringLiteral("Large");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_GLOBAL) parts << QStringLiteral("Global");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_USER) parts << QStringLiteral("User");
        return parts.join(QStringLiteral(" | "));
    }

    QString riskText(const std::uint32_t flags)
    {
        // 输入：KSWORD_ARK_MEMORY_EVIDENCE_RISK_* 位集合。
        // 处理：转换为风险标签；0 返回正常。
        // 返回：风险描述文本。
        if (flags == 0U)
        {
            return QStringLiteral("正常");
        }
        QStringList parts;
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX) parts << QStringLiteral("RWX");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE) parts << QStringLiteral("非模块执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE) parts << QStringLiteral("模块非text执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL) parts << QStringLiteral("执行池");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE) parts << QStringLiteral("大页执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING) parts << QStringLiteral("Owner缺失");
        return parts.join(QStringLiteral(" | "));
    }

    QString hashText(const ksword::ark::KernelMemoryEvidenceEntry& entry)
    {
        // 输入：内核内存证据行。
        // 处理：按 hashAlgorithm/contentHash/section 字段生成 text hash 状态。
        // 返回：无 hash 时返回“无”。
        if (entry.hashAlgorithm == KSWORD_ARK_MEMORY_EVIDENCE_HASH_NONE || entry.contentHash == 0ULL)
        {
            return QStringLiteral("无");
        }
        const QString algorithm = entry.hashAlgorithm == KSWORD_ARK_MEMORY_EVIDENCE_HASH_FNV1A64
            ? QStringLiteral("FNV1A64")
            : QStringLiteral("Hash(%1)").arg(entry.hashAlgorithm);
        const QString section = QString::fromStdString(entry.sectionName).trimmed();
        return QStringLiteral("%1 %2 %3").arg(algorithm, section.isEmpty() ? QStringLiteral(".text?") : section, hex64(entry.contentHash));
    }

    QTableWidgetItem* textItem(const QString& text)
    {
        // 输入：展示文本。
        // 处理：创建只读表格项。
        // 返回：交给 QTableWidget 接管生命周期的 item。
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QString evidenceCopyMenuStyle()
    {
        // 输入：无。
        // 处理：生成不透明右键菜单样式，防止继承透明背景。
        // 返回：可直接用于 QMenu::setStyleSheet 的字符串。
        // 右键菜单一律走全局主题实现，避免每个页面各拼一份互相漂移的 QSS。
        return KswordTheme::ContextMenuStyle();
    }

    QString evidenceRowText(QTableWidget* table, const int rowIndex)
    {
        // 输入：内核内存证据表和目标行号。
        // 处理：读取当前行所有列并以 Tab 分隔。
        // 返回：可复制的 TSV 文本；行无效时返回空字符串。
        if (table == nullptr || rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return QString();
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        return fields.join(QLatin1Char('\t'));
    }

    void installEvidenceCopyMenu(QTableWidget* table)
    {
        // 输入：内核内存证据表。
        // 处理：安装“复制当前行”右键菜单。
        // 返回：无，只复制 UI 证据，不触发任何写操作。
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex clickedIndex = table->indexAt(localPosition);
            const int rowIndex = clickedIndex.isValid() ? clickedIndex.row() : table->currentRow();
            if (clickedIndex.isValid())
            {
                table->setCurrentCell(clickedIndex.row(), clickedIndex.column());
                table->selectRow(clickedIndex.row());
            }

            QMenu menu(table);
            menu.setStyleSheet(evidenceCopyMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(rowIndex >= 0 && rowIndex < table->rowCount());
            // 内核内存证据的 VA 是内核虚拟地址：在工作台里切到内核范围打开。
            (void)addOpenInWorkbenchAction(
                menu, table, rowIndex, evidenceColumnIndex(EvidenceColumn::Address), true);
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                QClipboard* clipboard = QApplication::clipboard();
                if (clipboard != nullptr)
                {
                    clipboard->setText(evidenceRowText(table, rowIndex));
                }
            }
        });
    }

    void setEvidenceDiagnosticRow(
        QTableWidget* table,
        const QString& addressText,
        const QString& detailText)
    {
        // setEvidenceDiagnosticRow：
        // - 输入：目标表格、首列提示和详情文本；
        // - 处理：补一行可复制诊断，避免空缓存/过滤条件导致表格完全空白；
        // - 返回：无，完整诊断保存到 UserRole+2 供详情区读取。
        if (table == nullptr)
        {
            return;
        }

        table->setRowCount(1);
        QTableWidgetItem* addressItem = textItem(addressText);
        addressItem->setData(Qt::UserRole + 2, detailText);
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::Address), addressItem);
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::Size), textItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::Kind), textItem(QStringLiteral("诊断")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::Owner), textItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::Permissions), textItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::Risk), textItem(QStringLiteral("提示")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::TextHash), textItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::Detail), textItem(detailText));
        table->setCurrentCell(0, evidenceColumnIndex(EvidenceColumn::Address));
    }

    QTableWidgetItem* numericItem(const QString& text, const qulonglong value)
    {
        // 输入：展示文本（十六进制地址或 KB/MB 大小）和参与排序的真实数值。
        // 处理：统一走全局 ks::ui::NumericTableItem，排序读 NumericSortRole，
        //       不再自建私有 item，也不会和地址列自用的 Qt::UserRole+1 缓存索引抢角色。
        // 返回：交给 QTableWidget 接管生命周期的 item。
        ks::ui::NumericTableItem* item = new ks::ui::NumericTableItem(text, value);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QString evidenceTableDetailText(const ksword::ark::KernelMemoryEvidenceEntry& entry)
    {
        // 输入：内核内存证据行。
        // 处理：为表格末列生成中文摘要，避免直接展示原始 R0 detail 长串。
        // 返回：单行摘要；完整原始 detail 仍放在详情编辑器。
        const QString rawDetail = wideToQString(entry.detail).trimmed();
        const QString riskSummary = riskText(entry.riskFlags);
        const QString detailSummary = rawDetail.isEmpty()
            ? QStringLiteral("驱动未返回额外说明")
            : rawDetail.left(160);
        return QStringLiteral("%1；Owner=%2；%3")
            .arg(riskSummary)
            .arg(ownerKindText(entry.ownerKind))
            .arg(detailSummary);
    }

    bool entryMatchesFilter(const ksword::ark::KernelMemoryEvidenceEntry& entry, const QString& filter)
    {
        // 输入：证据行和过滤文本。
        // 处理：在 owner/detail/risk/地址/hash 中做大小写不敏感包含匹配。
        // 返回：true 表示该行应显示。
        if (filter.isEmpty())
        {
            return true;
        }
        const QStringList fields{
            hex64(entry.virtualAddress),
            wideToQString(entry.ownerName),
            wideToQString(entry.detail),
            ownerKindText(entry.ownerKind),
            evidenceKindText(entry.evidenceKind),
            riskText(entry.riskFlags),
            hashText(entry)
        };
        for (const QString& field : fields)
        {
            if (field.contains(filter, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    ks::ui::FieldDocument detailDocument(const ksword::ark::KernelMemoryEvidenceEntry& entry)
    {
        // 输入：当前内核内存证据行。
        // 处理：展开全部关键诊断字段，供详情编辑器复制。
        // 返回：结构详情。
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("内核内存证据详情"));
        document.field(QStringLiteral("Address"), QStringLiteral("%1").arg(hex64(entry.virtualAddress)));
        document.field(QStringLiteral("RegionSize"), QStringLiteral("%1 (%2)").arg(hex64(entry.regionSize), sizeText(entry.regionSize)));
        document.field(QStringLiteral("EvidenceKind"), QStringLiteral("%1").arg(evidenceKindText(entry.evidenceKind)), true);
        document.field(QStringLiteral("OwnerKind"), QStringLiteral("%1").arg(ownerKindText(entry.ownerKind)), true);
        document.field(QStringLiteral("OwnerName"), QStringLiteral("%1").arg(wideToQString(entry.ownerName)));
        document.field(QStringLiteral("OwnerAddress"), QStringLiteral("%1").arg(hex64(entry.ownerAddress)));
        document.field(QStringLiteral("ModuleBase"), QStringLiteral("%1").arg(hex64(entry.moduleBase)));
        document.field(QStringLiteral("ModuleSize"), QStringLiteral("%1").arg(sizeText(entry.moduleSize)));
        document.field(QStringLiteral("PermissionFlags"), QStringLiteral("%1 (0x%2)").arg(permissionText(entry.permissionFlags)).arg(entry.permissionFlags, 8, 16, QChar('0')), true);
        document.field(QStringLiteral("RiskFlags"), QStringLiteral("%1 (0x%2)").arg(riskText(entry.riskFlags)).arg(entry.riskFlags, 8, 16, QChar('0')), true);
        document.field(QStringLiteral("BigPoolTag"), QStringLiteral("0x%1").arg(entry.bigPoolTag, 8, 16, QChar('0')));
        document.field(QStringLiteral("BigPoolFlags"), QStringLiteral("0x%1").arg(entry.bigPoolFlags, 8, 16, QChar('0')));
        document.field(QStringLiteral("Section"), QStringLiteral("%1 RVA=0x%2 Size=%3")
            .arg(QString::fromStdString(entry.sectionName).trimmed())
            .arg(entry.sectionRva, 8, 16, QChar('0'))
            .arg(sizeText(entry.sectionSize)));
        document.field(QStringLiteral("Hash"), QStringLiteral("%1").arg(hashText(entry)));
        document.field(QStringLiteral("SampleSize"), QStringLiteral("%1").arg(entry.sampleSize));
        if (!entry.sample.empty())
        {
            document.field(QStringLiteral("Sample"), QStringLiteral("%1").arg(bytesToHex(entry.sample)));
        }
        document.field(QStringLiteral("Confidence"), QStringLiteral("%1").arg(entry.confidence), true);
        document.field(QStringLiteral("LastStatus"), QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(static_cast<unsigned long>(entry.lastStatus)), 8, 16, QChar('0')));
        document.field(QStringLiteral("Detail"), QStringLiteral("%1").arg(wideToQString(entry.detail)));
        return document;
    }

    QString statusStyle(const QString& color)
    {
        // 输入：CSS 颜色。
        // 处理：统一生成状态标签样式。
        // 返回：stylesheet 文本。
        return QStringLiteral("color:%1; font-weight:700;").arg(color);
    }
}

void MemoryDock::initializeKernelMemoryEvidenceTab()
{
    // 输入：无，由 initializeTabs 调用。
    // 处理：创建内核内存证据只读页面。非模块执行范围扫描默认关闭，必须填写范围后显式启用。
    // 返回：无。
    m_tabKernelMemoryEvidence = new QWidget(m_tabWidget);
    // 页面自带内部滚动壳：内容放不下时在页内滚动，不把 Dock 撑高。页面指针身份不变。
    QWidget* const tabContent = ks::ui::EnablePageInnerScroll(m_tabKernelMemoryEvidence);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // 第一层动作行：只保留“刷新 + 过滤 + 状态”，扫描参数整体下沉到第二层分组框，
    // 否则 8 个控件挤在一条工具条里，窄窗口下输入框会被压到只剩几个像素。
    QHBoxLayout* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(8);

    m_kernelMemoryEvidenceRefreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新证据"), m_tabKernelMemoryEvidence);
    m_kernelMemoryEvidenceRefreshButton->setToolTip(QStringLiteral("刷新内核内存证据"));
    m_kernelMemoryEvidenceRefreshButton->setStyleSheet(buildBlueButtonStyle());

    // 竖线分隔符把“刷新”这个写查询动作与右侧的本地过滤在视觉上分开。
    QFrame* evidenceActionSeparator = new QFrame(m_tabKernelMemoryEvidence);
    evidenceActionSeparator->setFrameShape(QFrame::VLine);
    evidenceActionSeparator->setFrameShadow(QFrame::Sunken);

    m_kernelMemoryEvidenceFilterEdit = new QLineEdit(m_tabKernelMemoryEvidence);
    m_kernelMemoryEvidenceFilterEdit->setClearButtonEnabled(true);
    m_kernelMemoryEvidenceFilterEdit->setPlaceholderText(QStringLiteral("过滤 owner / detail / risk / hash"));
    m_kernelMemoryEvidenceFilterEdit->setToolTip(QStringLiteral("输入关键字后只显示匹配的证据行"));
    m_kernelMemoryEvidenceFilterEdit->setStyleSheet(buildBlueInputStyle());
    ks::ui::StyleSearchField(m_kernelMemoryEvidenceFilterEdit);

    m_kernelMemoryEvidenceStatusLabel = new QLabel(QStringLiteral("状态：等待刷新"), m_tabKernelMemoryEvidence);
    m_kernelMemoryEvidenceStatusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_kernelMemoryEvidenceStatusLabel->setStyleSheet(statusStyle(KswordTheme::TextSecondaryHex()));

    toolLayout->addWidget(m_kernelMemoryEvidenceRefreshButton);
    toolLayout->addWidget(evidenceActionSeparator);
    toolLayout->addWidget(m_kernelMemoryEvidenceFilterEdit, 1);
    toolLayout->addWidget(m_kernelMemoryEvidenceStatusLabel);
    ks::ui::NormalizeToolbarRow(toolLayout);
    tabLayout->addLayout(toolLayout);

    // 第二层扫描参数分组：两个开关一行，三组“标签 + 输入”一行，网格保证标签与输入始终成对。
    QGroupBox* evidenceScanParamGroup = new QGroupBox(QStringLiteral("扫描参数"), m_tabKernelMemoryEvidence);
    QGridLayout* evidenceScanParamLayout = new QGridLayout(evidenceScanParamGroup);
    evidenceScanParamLayout->setContentsMargins(8, 6, 8, 6);
    evidenceScanParamLayout->setHorizontalSpacing(8);
    evidenceScanParamLayout->setVerticalSpacing(6);

    m_kernelMemoryEvidenceRiskOnlyCheck = new QCheckBox(QStringLiteral("仅显示风险项"), evidenceScanParamGroup);
    m_kernelMemoryEvidenceRiskOnlyCheck->setChecked(true);
    m_kernelMemoryEvidenceRiskOnlyCheck->setToolTip(QStringLiteral("只显示驱动判定 riskFlags 非零的证据行"));

    m_kernelMemoryEvidenceIncludeNonModuleCheck = new QCheckBox(QStringLiteral("包含非模块执行范围"), evidenceScanParamGroup);
    m_kernelMemoryEvidenceIncludeNonModuleCheck->setToolTip(QStringLiteral("需要填写起止地址；不会默认扫描全内核地址空间。"));

    // 起止 VA 只在勾选“包含非模块执行范围”时参与查询，占位符给出典型内核地址写法。
    m_kernelMemoryEvidenceStartEdit = new QLineEdit(evidenceScanParamGroup);
    m_kernelMemoryEvidenceStartEdit->setPlaceholderText(QStringLiteral("0xFFFFF80000000000"));
    m_kernelMemoryEvidenceStartEdit->setToolTip(QStringLiteral("非模块执行范围扫描的起始虚拟地址，勾选后必填"));
    m_kernelMemoryEvidenceStartEdit->setMinimumWidth(150);
    m_kernelMemoryEvidenceStartEdit->setStyleSheet(buildBlueInputStyle());

    m_kernelMemoryEvidenceEndEdit = new QLineEdit(evidenceScanParamGroup);
    m_kernelMemoryEvidenceEndEdit->setPlaceholderText(QStringLiteral("0xFFFFF80001000000"));
    m_kernelMemoryEvidenceEndEdit->setToolTip(QStringLiteral("非模块执行范围扫描的结束虚拟地址，必须大于起始地址"));
    m_kernelMemoryEvidenceEndEdit->setMinimumWidth(150);
    m_kernelMemoryEvidenceEndEdit->setStyleSheet(buildBlueInputStyle());

    m_kernelMemoryEvidenceMaxRowsSpin = new QSpinBox(evidenceScanParamGroup);
    m_kernelMemoryEvidenceMaxRowsSpin->setRange(16, static_cast<int>(KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS));
    m_kernelMemoryEvidenceMaxRowsSpin->setValue(static_cast<int>(KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS));
    m_kernelMemoryEvidenceMaxRowsSpin->setToolTip(QStringLiteral("最大返回行数"));

    // 第 0 行两个开关各占两列，第 1 行三组标签/输入，末列留伸缩位吸收窗口多余宽度。
    evidenceScanParamLayout->addWidget(m_kernelMemoryEvidenceRiskOnlyCheck, 0, 0, 1, 2);
    evidenceScanParamLayout->addWidget(m_kernelMemoryEvidenceIncludeNonModuleCheck, 0, 2, 1, 4);
    evidenceScanParamLayout->addWidget(new QLabel(QStringLiteral("起始 VA"), evidenceScanParamGroup), 1, 0);
    evidenceScanParamLayout->addWidget(m_kernelMemoryEvidenceStartEdit, 1, 1);
    evidenceScanParamLayout->addWidget(new QLabel(QStringLiteral("结束 VA"), evidenceScanParamGroup), 1, 2);
    evidenceScanParamLayout->addWidget(m_kernelMemoryEvidenceEndEdit, 1, 3);
    evidenceScanParamLayout->addWidget(new QLabel(QStringLiteral("最大行数"), evidenceScanParamGroup), 1, 4);
    evidenceScanParamLayout->addWidget(m_kernelMemoryEvidenceMaxRowsSpin, 1, 5);
    evidenceScanParamLayout->setColumnStretch(6, 1);
    tabLayout->addWidget(evidenceScanParamGroup);

    QSplitter* splitter = new QSplitter(Qt::Vertical, m_tabKernelMemoryEvidence);
    tabLayout->addWidget(splitter, 1);

    m_kernelMemoryEvidenceTable = new ks::ui::VisibleTableWidget(splitter);
    // Hash/权限与风险变更有前后对比价值，保留完整操作栏。
    ks::ui::SetTableActionBarMode(m_kernelMemoryEvidenceTable, ks::ui::TableActionBarMode::Full);
    m_kernelMemoryEvidenceTable->setColumnCount(evidenceColumnIndex(EvidenceColumn::Count));
    m_kernelMemoryEvidenceTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("VA"),
        QStringLiteral("大小"),
        QStringLiteral("类型"),
        QStringLiteral("Owner"),
        QStringLiteral("PTE权限"),
        QStringLiteral("风险"),
        QStringLiteral("text hash/diff"),
        QStringLiteral("Detail")
        });
    m_kernelMemoryEvidenceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_kernelMemoryEvidenceTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_kernelMemoryEvidenceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_kernelMemoryEvidenceTable->setAlternatingRowColors(true);
    m_kernelMemoryEvidenceTable->setSortingEnabled(true);
    m_kernelMemoryEvidenceTable->verticalHeader()->setVisible(false);
    installEvidenceCopyMenu(m_kernelMemoryEvidenceTable);
    splitter->addWidget(m_kernelMemoryEvidenceTable);

    m_kernelMemoryEvidenceDetailEditor = new ks::ui::StructuredFieldView(splitter);
    m_kernelMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral(
        "请选择一条内核内存证据记录查看详情。\n"
        "说明：text diff 的磁盘对比由 R3 后续阶段完成，本页当前展示 R0 内存 hash/sample 状态。")));
    splitter->addWidget(m_kernelMemoryEvidenceDetailEditor);

    ks::ui::DetailLayoutRegistry::registerStructuredHost(
        m_kernelMemoryEvidenceTable,
        m_kernelMemoryEvidenceDetailEditor,
        m_tabKernelMemoryEvidence);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    m_tabWidget->addTab(m_tabKernelMemoryEvidence, QStringLiteral("内核内存证据"));
}

void MemoryDock::refreshKernelMemoryEvidenceAsync()
{
    // 输入：由刷新按钮或全局刷新触发。
    // 处理：验证非模块范围边界，后台调用 ArkDriverClient，回主线程更新缓存和状态。
    // 返回：无。
    if (m_kernelMemoryEvidenceRefreshInProgress.exchange(true))
    {
        return;
    }

    std::uint64_t startAddress = 0;
    std::uint64_t endAddress = 0;
    unsigned long flags =
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;

    if (m_kernelMemoryEvidenceIncludeNonModuleCheck != nullptr &&
        m_kernelMemoryEvidenceIncludeNonModuleCheck->isChecked())
    {
        const bool startOk = parseAddressText(m_kernelMemoryEvidenceStartEdit != nullptr ? m_kernelMemoryEvidenceStartEdit->text().trimmed() : QString(), startAddress);
        const bool endOk = parseAddressText(m_kernelMemoryEvidenceEndEdit != nullptr ? m_kernelMemoryEvidenceEndEdit->text().trimmed() : QString(), endAddress);
        if (!startOk || !endOk || startAddress >= endAddress)
        {
            // 参数校验失败直接退出采集态：此处尚未置灰按钮，只需还原忙标志并提示。
            m_kernelMemoryEvidenceRefreshInProgress.store(false);
            kLogEvent invalidRangeEvent;
            info << invalidRangeEvent
                << "[MemoryDock] refreshKernelMemoryEvidenceAsync: 非模块执行范围起止 VA 无效，已放弃本次采集。"
                << eol;
            if (m_kernelMemoryEvidenceStatusLabel != nullptr)
            {
                m_kernelMemoryEvidenceStatusLabel->setText(QStringLiteral("状态：非模块执行范围需要有效的起始/结束 VA。"));
                m_kernelMemoryEvidenceStatusLabel->setStyleSheet(
                    statusStyle(KswordTheme::ErrorColor().name(QColor::HexRgb)));
            }
            return;
        }
        flags |= KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES;
    }

    const unsigned long maxRows = static_cast<unsigned long>(
        m_kernelMemoryEvidenceMaxRowsSpin != nullptr
            ? m_kernelMemoryEvidenceMaxRowsSpin->value()
            : static_cast<int>(KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS));

    // 进入采集态：按钮置灰并改写提示，状态标签给出“正在采集”，
    // 两者都在结果回到主线程后由 commitSnapshot 统一恢复。
    if (m_kernelMemoryEvidenceRefreshButton != nullptr)
    {
        m_kernelMemoryEvidenceRefreshButton->setEnabled(false);
        m_kernelMemoryEvidenceRefreshButton->setToolTip(QStringLiteral("正在采集内核内存证据，请等待本轮查询结束"));
    }
    if (m_kernelMemoryEvidenceStatusLabel != nullptr)
    {
        m_kernelMemoryEvidenceStatusLabel->setText(QStringLiteral("状态：正在采集内核内存证据…"));
        m_kernelMemoryEvidenceStatusLabel->setStyleSheet(statusStyle(KswordTheme::PrimaryBlueHex));
    }

    const std::uint64_t ticket = m_kernelMemoryEvidenceRefreshTicket.fetch_add(1U) + 1U;
    const QPointer<MemoryDock> guardThis(this);

    std::thread([guardThis, ticket, flags, maxRows, startAddress, endAddress]() {
        const ksword::ark::DriverClient client;
        ksword::ark::KernelMemoryEvidenceResult result = client.queryKernelMemoryEvidence(
            flags,
            maxRows,
            startAddress,
            endAddress,
            KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES,
            KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS,
            KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES);

        QMetaObject::invokeMethod(
            qApp,
            [guardThis, ticket, result = std::move(result)]() mutable {
                if (guardThis == nullptr || ticket != guardThis->m_kernelMemoryEvidenceRefreshTicket.load()) return;
                auto resultSnapshot =
                    std::make_shared<ksword::ark::KernelMemoryEvidenceResult>(std::move(result));
                auto commitSnapshot = [guardThis, ticket, resultSnapshot]()
                {
                    if (guardThis == nullptr ||
                        ticket < guardThis->m_kernelMemoryEvidenceRefreshTicket.load())
                    {
                        return;
                    }

                    guardThis->m_kernelMemoryEvidenceRefreshInProgress.store(false);
                    // 退出采集态：按钮恢复可点并把 tooltip 换回常态文案，成功/失败两条路径共用。
                    if (guardThis->m_kernelMemoryEvidenceRefreshButton != nullptr)
                    {
                        guardThis->m_kernelMemoryEvidenceRefreshButton->setEnabled(true);
                        guardThis->m_kernelMemoryEvidenceRefreshButton->setToolTip(
                            QStringLiteral("刷新内核内存证据"));
                    }

                    const ksword::ark::KernelMemoryEvidenceResult& snapshot = *resultSnapshot;
                    if (!snapshot.io.ok)
                    {
                        guardThis->m_kernelMemoryEvidenceCache.clear();
                        guardThis->m_kernelMemoryEvidenceVisibleCount = 0U;
                        guardThis->rebuildKernelMemoryEvidenceTable();
                        const QString message = snapshot.unsupported
                            ? QStringLiteral("未集成/驱动过旧，等待 R0 支持")
                            : QStringLiteral("查询失败: %1").arg(
                                memoryEvidenceIoMessageText(snapshot.io.message));
                        if (guardThis->m_kernelMemoryEvidenceStatusLabel != nullptr)
                        {
                            guardThis->m_kernelMemoryEvidenceStatusLabel->setText(
                                QStringLiteral("状态：%1").arg(message));
                            guardThis->m_kernelMemoryEvidenceStatusLabel->setStyleSheet(
                                statusStyle(KswordTheme::ErrorColor().name(QColor::HexRgb)));
                        }
                        if (guardThis->m_kernelMemoryEvidenceDetailEditor != nullptr)
                        {
                            guardThis->m_kernelMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(message));
                        }
                        return;
                    }

                    guardThis->m_kernelMemoryEvidenceCache = snapshot.entries;
                    guardThis->rebuildKernelMemoryEvidenceTable();
                    guardThis->showKernelMemoryEvidenceDetailByCurrentRow();
                    if (guardThis->m_kernelMemoryEvidenceStatusLabel != nullptr)
                    {
                        guardThis->m_kernelMemoryEvidenceStatusLabel->setText(
                            QStringLiteral("状态：总计 %1，返回 %2，显示 %3，模块 %4，BigPool seen %5")
                            .arg(snapshot.totalRows)
                            .arg(snapshot.returnedRows)
                            .arg(guardThis->m_kernelMemoryEvidenceVisibleCount)
                            .arg(snapshot.moduleCount)
                            .arg(snapshot.bigPoolRowsSeen));
                        guardThis->m_kernelMemoryEvidenceStatusLabel->setStyleSheet(
                            statusStyle(KswordTheme::SuccessColor().name(QColor::HexRgb)));
                    }
                };

                if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                    guardThis.data(),
                    QStringLiteral("memory-kernel-evidence-snapshot"),
                    { guardThis->m_kernelMemoryEvidenceTable },
                    commitSnapshot))
                {
                    return;
                }
                commitSnapshot();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MemoryDock::rebuildKernelMemoryEvidenceTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_kernelMemoryEvidenceDetailEditor);
    // 输入：无，读取 m_kernelMemoryEvidenceCache 和过滤控件。
    // 处理：把缓存投影为表格，风险过滤仅在 R3 本地执行。
    // 返回：无。
    if (m_kernelMemoryEvidenceTable == nullptr)
    {
        return;
    }

    const QString filter = m_kernelMemoryEvidenceFilterEdit != nullptr
        ? m_kernelMemoryEvidenceFilterEdit->text().trimmed()
        : QString();
    const bool riskOnly = m_kernelMemoryEvidenceRiskOnlyCheck != nullptr && m_kernelMemoryEvidenceRiskOnlyCheck->isChecked();

    std::vector<std::size_t> visibleIndexes;
    visibleIndexes.reserve(m_kernelMemoryEvidenceCache.size());
    for (std::size_t index = 0; index < m_kernelMemoryEvidenceCache.size(); ++index)
    {
        const auto& entry = m_kernelMemoryEvidenceCache[index];
        if (riskOnly && entry.riskFlags == 0U)
        {
            continue;
        }
        if (!entryMatchesFilter(entry, filter))
        {
            continue;
        }
        visibleIndexes.push_back(index);
    }

    m_kernelMemoryEvidenceVisibleCount = visibleIndexes.size();
    const QSignalBlocker blocker(m_kernelMemoryEvidenceTable);
    m_kernelMemoryEvidenceTable->setSortingEnabled(false);
    m_kernelMemoryEvidenceTable->setRowCount(static_cast<int>(visibleIndexes.size()));
    for (int row = 0; row < static_cast<int>(visibleIndexes.size()); ++row)
    {
        const std::size_t cacheIndex = visibleIndexes[static_cast<std::size_t>(row)];
        const auto& entry = m_kernelMemoryEvidenceCache[cacheIndex];
        // 虚拟地址列：显示 0x 十六进制，排序用 64 位原值，否则点表头会退化成字符串序。
        QTableWidgetItem* addressItem = numericItem(hex64(entry.virtualAddress), static_cast<qulonglong>(entry.virtualAddress));
        addressItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(cacheIndex)));
        m_kernelMemoryEvidenceTable->setItem(row, evidenceColumnIndex(EvidenceColumn::Address), addressItem);
        // 区域大小列：显示 KB/MB/GB，排序用字节数，避免 512 KB 排到 2.50 MB 后面。
        m_kernelMemoryEvidenceTable->setItem(row, evidenceColumnIndex(EvidenceColumn::Size), numericItem(sizeText(entry.regionSize), static_cast<qulonglong>(entry.regionSize)));
        m_kernelMemoryEvidenceTable->setItem(row, evidenceColumnIndex(EvidenceColumn::Kind), textItem(evidenceKindText(entry.evidenceKind)));
        m_kernelMemoryEvidenceTable->setItem(row, evidenceColumnIndex(EvidenceColumn::Owner),
            textItem(QStringLiteral("%1 %2").arg(ownerKindText(entry.ownerKind), wideToQString(entry.ownerName))));
        m_kernelMemoryEvidenceTable->setItem(row, evidenceColumnIndex(EvidenceColumn::Permissions), textItem(permissionText(entry.permissionFlags)));
        m_kernelMemoryEvidenceTable->setItem(row, evidenceColumnIndex(EvidenceColumn::Risk), textItem(riskText(entry.riskFlags)));
        m_kernelMemoryEvidenceTable->setItem(row, evidenceColumnIndex(EvidenceColumn::TextHash), textItem(hashText(entry)));
        m_kernelMemoryEvidenceTable->setItem(row, evidenceColumnIndex(EvidenceColumn::Detail), textItem(evidenceTableDetailText(entry)));
    }
    if (visibleIndexes.empty())
    {
        const QString detailText = m_kernelMemoryEvidenceCache.empty()
            ? QStringLiteral("内核内存证据当前没有缓存行；可能是驱动未返回结果、查询失败或尚未刷新。")
            : QStringLiteral("当前过滤条件隐藏了全部 %1 条内核内存证据；请清空过滤或关闭“仅显示风险项”。")
                .arg(static_cast<qulonglong>(m_kernelMemoryEvidenceCache.size()));
        setEvidenceDiagnosticRow(
            m_kernelMemoryEvidenceTable,
            QStringLiteral("<无内核内存证据>"),
            detailText);
    }
    if (m_kernelMemoryEvidenceTable->rowCount() > 0 && m_kernelMemoryEvidenceTable->currentRow() < 0)
    {
        m_kernelMemoryEvidenceTable->setCurrentCell(0, evidenceColumnIndex(EvidenceColumn::Address));
    }
    m_kernelMemoryEvidenceTable->setSortingEnabled(true);
    ks::ui::RequestTableColumnAutoFit(m_kernelMemoryEvidenceTable);
}

void MemoryDock::showKernelMemoryEvidenceDetailByCurrentRow()
{
    // 输入：无，读取当前表格行。
    // 处理：通过缓存索引写入详情编辑器。
    // 返回：无。
    if (m_kernelMemoryEvidenceDetailEditor == nullptr || m_kernelMemoryEvidenceTable == nullptr)
    {
        return;
    }
    const int row = m_kernelMemoryEvidenceTable->currentRow();
    if (row < 0)
    {
        m_kernelMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择一条内核内存证据记录查看详情。")));
        return;
    }
    const QTableWidgetItem* addressItem = m_kernelMemoryEvidenceTable->item(row, evidenceColumnIndex(EvidenceColumn::Address));
    if (addressItem == nullptr)
    {
        m_kernelMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前记录的缓存已失效，请刷新后重试。")));
        return;
    }
    const QString diagnosticText = addressItem->data(Qt::UserRole + 2).toString();
    if (!diagnosticText.isEmpty())
    {
        m_kernelMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("内核内存证据诊断\n%1").arg(diagnosticText)));
        return;
    }

    bool ok = false;
    const qulonglong cacheIndex = addressItem->data(Qt::UserRole + 1).toULongLong(&ok);
    if (!ok || cacheIndex >= static_cast<qulonglong>(m_kernelMemoryEvidenceCache.size()))
    {
        m_kernelMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前记录的缓存已失效，请刷新后重试。")));
        return;
    }
    m_kernelMemoryEvidenceDetailEditor->setDocument(detailDocument(m_kernelMemoryEvidenceCache[static_cast<std::size_t>(cacheIndex)]));
}
