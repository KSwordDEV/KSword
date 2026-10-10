#include "MemoryDock.Internal.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PageControlStyle.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/AdaptivePageScroll.h" // ks::ui::EnablePageInnerScroll：页内滚动壳。
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/DetailLayoutRegistry.h"
/* 统一入口：这一页不需要知道 GPA、EPT 叶或 ruleId。 */
#include "../UI/HvmWatchDialog.h"

#include <QColor>      // QColor：风险行前景色着色使用。
#include <QPixmap>
#include <QProgressBar> // QProgressBar：扫描进行中的不确定态进度条。

#include <memory>

using namespace ksword::memory_dock_internal;

namespace
{
    // KernelExecutableColumn:
    // - Input: table column enum used by MemoryDock's kernel executable scan UI.
    // - Processing: keeps column numbers stable when rows are rebuilt or sorted.
    // - Return behavior: enum values are converted to int at call sites.
    enum class KernelExecutableColumn : int
    {
        Va = 0,
        RegionSize,
        PageCount,
        PageSize,
        Permissions,
        Owner,
        ModuleBase,
        ModulePath,
        RiskFlags,
        Count
    };

    int kernelExecutableColumnIndex(const KernelExecutableColumn column)
    {
        // 输入：KernelExecutableColumn 枚举值。
        // 处理：执行窄化到 QTableWidget 使用的 int 列号。
        // 返回：对应的表格列号。
        return static_cast<int>(column);
    }

    QString wideToQString(const std::wstring& text)
    {
        // 输入：ArkDriverClient 返回的 UTF-16 宽字符串。
        // 处理：统一转为 QString，空文本保留为空。
        // 返回：可供 Qt UI 展示和过滤的 QString。
        return text.empty() ? QString() : QString::fromStdWString(text);
    }

    QString kernelExecutableIoMessageText(const std::string& messageText)
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
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持内核可执行页扫描入口");
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供内核可执行页扫描入口");
        }
        if (rawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("invalid"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动返回数据格式不完整，当前扫描结果已丢弃");
        }
        return rawText;
    }

    QString hexValue(const std::uint64_t value)
    {
        // 输入：64 位诊断值。
        // 处理：格式化为固定宽度十六进制，便于地址列排序外的文本展示。
        // 返回：0x 前缀大写十六进制字符串。
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString byteSizeText(const std::uint64_t byteCount)
    {
        // 输入：字节数，用于区域大小这类需要横向比较体量的列。
        // 处理：按 1024 进位折算到 KB/MB/GB，1KB 以下保留原始字节数，避免小页区间被折没。
        // 返回：带单位的可读文本；真正的排序依据由 NumericTableItem 的原始字节数提供。
        constexpr double kUnitStep = 1024.0;
        if (byteCount < 1024ULL)
        {
            return QStringLiteral("%1 B").arg(static_cast<qulonglong>(byteCount));
        }

        double scaledValue = static_cast<double>(byteCount) / kUnitStep;
        // 单位表按 KB 起步，最大到 TB；超出范围时停在最后一个单位上继续放大数值。
        constexpr int kUnitCount = 4;
        const char* const unitNames[kUnitCount] = { "KB", "MB", "GB", "TB" };
        int unitIndex = 0;
        while (scaledValue >= kUnitStep && unitIndex + 1 < kUnitCount)
        {
            scaledValue /= kUnitStep;
            ++unitIndex;
        }
        return QStringLiteral("%1 %2")
            .arg(scaledValue, 0, 'f', 2)
            .arg(QString::fromLatin1(unitNames[unitIndex]));
    }

    QString permissionText(const std::uint32_t flags)
    {
        // 输入：KernelExecutableMemoryPermission* 位集合。
        // 处理：转换为紧凑权限文本，保留 NX/Large/User/Global 等诊断位。
        // 返回：权限展示字符串，例如 R-X | Large | Global。
        QStringList parts;
        QString rwx;
        rwx += (flags & ksword::ark::KernelExecutableMemoryPermissionPresent) ? QChar('R') : QChar('-');
        rwx += (flags & ksword::ark::KernelExecutableMemoryPermissionWritable) ? QChar('W') : QChar('-');
        rwx += (flags & ksword::ark::KernelExecutableMemoryPermissionNoExecute) ? QChar('-') : QChar('X');
        parts << rwx;
        if (flags & ksword::ark::KernelExecutableMemoryPermissionNoExecute)
        {
            parts << QStringLiteral("NX");
        }
        if (flags & ksword::ark::KernelExecutableMemoryPermissionLargePage)
        {
            parts << QStringLiteral("Large");
        }
        if (flags & ksword::ark::KernelExecutableMemoryPermissionUser)
        {
            parts << QStringLiteral("User");
        }
        if (flags & ksword::ark::KernelExecutableMemoryPermissionGlobal)
        {
            parts << QStringLiteral("Global");
        }
        return parts.join(QStringLiteral(" | "));
    }

    QString riskFlagsText(const std::uint32_t flags)
    {
        // 输入：KernelExecutableMemoryRisk* 位集合。
        // 处理：把风险位映射为面向分析人员的短标签。
        // 返回：无风险时返回“正常”，否则返回用竖线分隔的风险标签。
        if (flags == 0U)
        {
            return QStringLiteral("正常");
        }

        QStringList parts;
        if (flags & ksword::ark::KernelExecutableMemoryRiskWritableExecutable)
        {
            parts << QStringLiteral("WX");
        }
        if (flags & ksword::ark::KernelExecutableMemoryRiskModuleNonTextExecutable)
        {
            parts << QStringLiteral("非.text可执行");
        }
        if (flags & ksword::ark::KernelExecutableMemoryRiskSectionWritable)
        {
            parts << QStringLiteral("节可写");
        }
        if (flags & ksword::ark::KernelExecutableMemoryRiskLargePage)
        {
            parts << QStringLiteral("大页");
        }
        // 代码节页的正常状态是只读可执行；下面两项是把 RX 改成 RW 之后留下的痕迹。
        if (flags & ksword::ark::KernelExecutableMemoryRiskCodePageNotExecutable)
        {
            parts << QStringLiteral("代码页不可执行");
        }
        if (flags & ksword::ark::KernelExecutableMemoryRiskCodePageWritable)
        {
            parts << QStringLiteral("代码页可写");
        }
        return parts.join(QStringLiteral(" | "));
    }

    QColor kernelExecutableRiskColor(const std::uint32_t flags)
    {
        // 输入：KernelExecutableMemoryRisk* 位集合。
        // 处理：把“可写又可执行”这一类可直接落 shellcode 的风险判为错误级，其余风险位判为警告级。
        // 返回：无风险时返回无效 QColor（调用方据此跳过着色），否则返回该行文字应使用的前景色。
        // 说明：这里刻意使用 ErrorColor()/WarningColor() 快照函数——逐行着色发生在每次填表时，
        //       主题切换会触发重新刷新填表，颜色天然跟随，属于快照 token 的合法用法。
        if (flags == 0U)
        {
            return QColor();
        }

        constexpr std::uint32_t severeRiskMask =
            ksword::ark::KernelExecutableMemoryRiskWritableExecutable |
            ksword::ark::KernelExecutableMemoryRiskSectionWritable |
            ksword::ark::KernelExecutableMemoryRiskCodePageWritable;
        if ((flags & severeRiskMask) != 0U)
        {
            return KswordTheme::ErrorColor();
        }
        return KswordTheme::WarningColor();
    }

    QString ownerKindText(const std::uint32_t ownerKind)
    {
        // 输入：Prompt-1 响应中的 ownerKind 枚举值。
        // 处理：只按共享协议定义的 ownerKind 做 UI 文本映射，不推断额外语义。
        // 返回：Owner 列和详情页可直接展示的中文分类文本。
        switch (ownerKind)
        {
        case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_TEXT:
            return QStringLiteral("模块 .text");
        case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_NON_TEXT:
            return QStringLiteral("模块非 .text");
        case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_WRITABLE_EXECUTABLE:
            return QStringLiteral("模块 WX");
        case KSWORD_ARK_KERNEL_EXEC_OWNER_UNKNOWN:
        default:
            return QStringLiteral("未知(%1)").arg(ownerKind);
        }
    }

    QTableWidgetItem* createTextItem(const QString& text)
    {
        // 输入：单元格展示文本。
        // 处理：创建只读表格项并设置垂直居中。
        // 返回：交给 QTableWidget 接管生命周期的 item 指针。
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QString kernelExecutableCopyMenuStyle()
    {
        // 输入：无。
        // 处理：生成不透明右键菜单样式，避免透明父容器造成黑底黑字。
        // 返回：可直接设置到 QMenu 的样式字符串。
        // 右键菜单一律走全局主题实现，避免每个页面各拼一份互相漂移的 QSS。
        return KswordTheme::ContextMenuStyle();
    }

    QString kernelExecutableRowText(QTableWidget* table, const int rowIndex)
    {
        // 输入：内核可执行页表和目标行号。
        // 处理：按当前列顺序读取单元格，拼接为 TSV。
        // 返回：可写入剪贴板的单行文本。
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

    void installKernelExecutableCopyMenu(QTableWidget* table)
    {
        // 输入：内核可执行页扫描表。
        // 处理：安装只读“复制当前行”菜单。
        // 返回：无，不触发任何 R0 操作。
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
            menu.setStyleSheet(kernelExecutableCopyMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(rowIndex >= 0 && rowIndex < table->rowCount());
            // 内核可执行页的 VA 是内核虚拟地址：在工作台里切到内核范围打开。
            (void)addOpenInWorkbenchAction(
                menu, table, rowIndex, kernelExecutableColumnIndex(KernelExecutableColumn::Va), true);

            /*
             * 三种访问各给一项，而不是一个"监视"再弹二级菜单。
             *
             * 选哪一种不是偏好，是在问不同的问题：写=谁改它，执行=谁跑它，
             * 读=谁在扫它。把三者折进一个入口，用户就得先想明白自己要问什么
             * 才点得下去，而这一页的读者往往正是还不确定的那个人。
             */
            const quint64 rowAddress = (rowIndex >= 0 && table->item(rowIndex, 0) != nullptr)
                ? table->item(rowIndex, 0)->data(Qt::UserRole).toULongLong()
                : 0ULL;
            menu.addSeparator();
            QMenu* const watchMenu = menu.addMenu(QStringLiteral("HVM 监视这一页的下一次访问"));
            watchMenu->setStyleSheet(kernelExecutableCopyMenuStyle());
            QAction* const watchWrite = watchMenu->addAction(QStringLiteral("写入"));
            QAction* const watchExecute = watchMenu->addAction(QStringLiteral("执行"));
            QAction* const watchRead = watchMenu->addAction(QStringLiteral("读取"));
            watchMenu->setEnabled(rowAddress != 0ULL);
            /*
             * 另加一条：谁改了这一页的**映射**。
             *
             * 与上面三条问的不是一件事。上面盯页里的内容，这一条盯指向这一页
             * 的那一项 PTE——一段可执行内核内存被整页重映射到别处时，页里一个
             * 字节都不用改，上面三条永远不会响。
             */
            QAction* const watchPte = menu.addAction(
                QStringLiteral("HVM 监视这一页的页表项（谁改了它的映射）"));
            watchPte->setEnabled(rowAddress != 0ULL);
            watchPte->setToolTip(QStringLiteral(
                "盯的不是这一页的内容，而是指向它的那一项页表项。整页被重映射时内容不变，只有这一项会被改。"));

            QAction* const chosen = menu.exec(table->viewport()->mapToGlobal(localPosition));
            if (chosen == watchPte && rowAddress != 0ULL)
            {
                ks::ui::openHvmWatchOnPte(
                    table,
                    rowAddress,
                    QStringLiteral("可执行内核内存 %1")
                        .arg(rowAddress, 16, 16, QLatin1Char('0')));
                return;
            }
            if (chosen == copyRowAction)
            {
                QClipboard* clipboard = QApplication::clipboard();
                if (clipboard != nullptr)
                {
                    clipboard->setText(kernelExecutableRowText(table, rowIndex));
                }
            }
            else if (rowAddress != 0ULL &&
                     (chosen == watchWrite || chosen == watchExecute || chosen == watchRead))
            {
                ks::ui::HvmWatchRequest request;
                request.virtualAddress = true;
                request.address = rowAddress;
                // 这一页上选中的是一整块可执行区域，没有更细的"用户关心的
                // 几个字节"可言，所以请求范围就是整页。
                request.length = 0ULL;
                request.access = chosen == watchWrite
                    ? KSWORD_ARK_HVM_EPT_ACCESS_WRITE
                    : chosen == watchExecute
                        ? KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE
                        : KSWORD_ARK_HVM_EPT_ACCESS_READ;
                request.label = QStringLiteral("可执行内核内存 %1")
                    .arg(rowAddress, 16, 16, QLatin1Char('0'));
                ks::ui::openHvmWatch(table, request);
            }
        });
    }

    void setKernelExecutableDiagnosticRow(
        QTableWidget* table,
        const QString& detailText)
    {
        // setKernelExecutableDiagnosticRow：
        // - 输入：目标表格与诊断文本；
        // - 处理：写入一行可复制诊断，UserRole+2 保存完整说明；
        // - 返回：无。用于 R0 空结果或过滤空结果时避免页面只剩空表。
        if (table == nullptr)
        {
            return;
        }

        table->setRowCount(1);
        QTableWidgetItem* vaItem = createTextItem(QStringLiteral("<无可执行页证据>"));
        vaItem->setData(Qt::UserRole + 2, detailText);
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::Va), vaItem);
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::RegionSize), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::PageCount), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::PageSize), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::Permissions), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::Owner), createTextItem(QStringLiteral("诊断")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::ModuleBase), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::ModulePath), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::RiskFlags), createTextItem(detailText));
        table->setCurrentCell(0, kernelExecutableColumnIndex(KernelExecutableColumn::Va));
    }

    QTableWidgetItem* createNumericItem(const QString& text, const qulonglong numericValue)
    {
        // 输入：展示文本（十六进制 VA、带单位大小、纯数字计数皆可）与参与排序的原始数值。
        // 处理：统一改用全局 ks::ui::NumericTableItem，排序读 NumericSortRole，DisplayRole 文本不被覆盖；
        //       另外把原始数值写进 Qt::UserRole，供详情面板按 VA 反查缓存行（沿用旧的反查约定）。
        // 返回：交给 QTableWidget 接管生命周期的 item 指针。
        ks::ui::NumericTableItem* item = new ks::ui::NumericTableItem(text, numericValue);
        item->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(numericValue));
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    bool entryMatchesModuleFilter(
        const ksword::ark::KernelExecutableMemoryPageEntry& entry,
        const QString& moduleFilter)
    {
        // 输入：R3 扫描行和模块路径过滤文本。
        // 处理：只按模块路径字段做本地包含匹配；空过滤直接通过。
        // 返回：true 表示该行应显示。
        if (moduleFilter.isEmpty())
        {
            return true;
        }

        return wideToQString(entry.modulePath).contains(moduleFilter, Qt::CaseInsensitive);
    }

    ks::ui::FieldDocument buildKernelExecutableDetailDocument(
        const ksword::ark::KernelExecutableMemoryPageEntry& entry)
    {
        // 输入：当前选中的内核可执行页扫描行。
        // 处理：生成适合 StructuredFieldView 展示的多行诊断文本。
        // 返回：详情文本，调用方直接 setText。
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("内核可执行页扫描详情"));
        document.field(QStringLiteral("VA"), QStringLiteral("%1").arg(hexValue(entry.virtualAddress)));
        document.field(QStringLiteral("RegionSize"), QStringLiteral("%1").arg(hexValue(entry.regionSize)));
        document.field(QStringLiteral("PageCount"), QStringLiteral("%1").arg(entry.pageCount));
        document.field(QStringLiteral("PageSize"), QStringLiteral("%1").arg(entry.pageSize));
        document.field(QStringLiteral("Permissions"), QStringLiteral("%1 (0x%2)")
            .arg(permissionText(entry.permissionFlags))
            .arg(entry.permissionFlags, 8, 16, QChar('0')), true);
        document.field(QStringLiteral("RiskFlags"), QStringLiteral("%1 (0x%2)")
            .arg(riskFlagsText(entry.riskFlags))
            .arg(entry.riskFlags, 8, 16, QChar('0')), true);
        document.field(QStringLiteral("Status"), QStringLiteral("%1").arg(entry.status));
        document.field(QStringLiteral("LastStatus"), QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(static_cast<unsigned long>(entry.lastStatus)), 8, 16, QChar('0')));
        document.field(QStringLiteral("OwnerKind"), QStringLiteral("%1").arg(entry.ownerKind), true);
        document.field(QStringLiteral("Owner"), QStringLiteral("%1").arg(ownerKindText(entry.ownerKind)), true);
        document.field(QStringLiteral("OwnerAddress"), QStringLiteral("%1").arg(hexValue(entry.ownerAddress)));
        document.field(QStringLiteral("ModuleBase"), QStringLiteral("%1").arg(hexValue(entry.moduleBase)));
        document.field(QStringLiteral("ModuleSize"), QStringLiteral("%1").arg(hexValue(entry.moduleSize)));
        document.field(QStringLiteral("ModulePath"), QStringLiteral("%1").arg(wideToQString(entry.modulePath)));

        const QString r0Detail = wideToQString(entry.detail).trimmed();
        if (!r0Detail.isEmpty())
        {
            document.field(QStringLiteral("R0 Detail"), r0Detail);
        }
        return document;
    }

    QString kernelExecutableStatusStyle(const QString& colorText)
    {
        // 输入：颜色字符串。
        // 处理：统一生成状态标签样式。
        // 返回：可直接 setStyleSheet 的 CSS 文本。
        return QStringLiteral("color:%1; font-weight:700;").arg(colorText);
    }
}

void MemoryDock::initializeKernelExecutableMemoryScanTab()
{
    // 输入：无，由 initializeTabs 调用。
    // 处理：构建内核可执行页扫描页面，包含刷新入口、风险/路径过滤、表格和详情编辑器。
    // 返回：无。
    kLogEvent tab7InitEvent;
    info << tab7InitEvent
        << "[MemoryDock] initializeKernelExecutableMemoryScanTab: 构建内核可执行页扫描页面。"
        << eol;

    m_tabKernelExecutableMemory = new QWidget(m_tabWidget);
    // 页面自带内部滚动壳：内容放不下时在页内滚动，不把 Dock 撑高。页面指针身份不变，
    // 下面按 objectName 的 findChild 是递归查找，仍然能找到壳里的进度条。
    QWidget* const tabContent = ks::ui::EnablePageInnerScroll(m_tabKernelExecutableMemory);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    QHBoxLayout* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(8);

    m_kernelExecutableRefreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), m_tabKernelExecutableMemory);
    m_kernelExecutableRefreshButton->setToolTip(QStringLiteral("扫描内核可执行内存"));
    m_kernelExecutableRefreshButton->setStyleSheet(buildBlueButtonStyle());

    // 扫描进度条：R0 扫描一次返回，没有分段进度可报，这里用不确定态进度条表达“正在进行”。
    // 不新增成员变量，刷新入口通过 objectName + findChild 取回，避免改动 MemoryDock.h。
    QProgressBar* scanProgressBar = new QProgressBar(m_tabKernelExecutableMemory);
    scanProgressBar->setObjectName(QStringLiteral("kernelExecutableScanProgress"));
    scanProgressBar->setRange(0, 0);
    scanProgressBar->setTextVisible(false);
    scanProgressBar->setFixedWidth(120);
    scanProgressBar->setToolTip(QStringLiteral("内核可执行页扫描进行中"));
    scanProgressBar->setVisible(false);

    m_kernelExecutableRiskOnlyCheck = new QCheckBox(QStringLiteral("仅风险项"), m_tabKernelExecutableMemory);
    m_kernelExecutableRiskOnlyCheck->setChecked(true);
    m_kernelExecutableRiskOnlyCheck->setToolTip(QStringLiteral("只显示风险标志非零的可执行页，取消勾选可查看全部扫描结果"));
    m_kernelExecutableRiskOnlyCheck->setStyleSheet(QStringLiteral(
        "QCheckBox { color:%1; font-weight:600; }")
        .arg(KswordTheme::TextPrimaryHex()));

    m_kernelExecutableModuleFilterEdit = new QLineEdit(m_tabKernelExecutableMemory);
    m_kernelExecutableModuleFilterEdit->setClearButtonEnabled(true);
    m_kernelExecutableModuleFilterEdit->setPlaceholderText(QStringLiteral("按模块路径过滤，如 ntoskrnl.exe / drivers\\xxx.sys"));
    m_kernelExecutableModuleFilterEdit->setToolTip(QStringLiteral("按模块路径子串过滤扫描结果，不区分大小写；留空显示全部"));
    m_kernelExecutableModuleFilterEdit->setStyleSheet(buildBlueInputStyle());
    ks::ui::StyleSearchField(m_kernelExecutableModuleFilterEdit);

    m_kernelExecutableStatusLabel = new QLabel(QStringLiteral("状态：等待刷新"), m_tabKernelExecutableMemory);
    m_kernelExecutableStatusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_kernelExecutableStatusLabel->setToolTip(QStringLiteral("显示最近一次内核可执行页扫描的统计结果"));
    m_kernelExecutableStatusLabel->setStyleSheet(kernelExecutableStatusStyle(KswordTheme::TextSecondaryHex()));

    toolLayout->addWidget(m_kernelExecutableRefreshButton, 0);
    toolLayout->addWidget(scanProgressBar, 0);
    toolLayout->addWidget(m_kernelExecutableRiskOnlyCheck, 0);
    toolLayout->addWidget(m_kernelExecutableModuleFilterEdit, 1);
    toolLayout->addWidget(m_kernelExecutableStatusLabel, 0);
    ks::ui::NormalizeToolbarRow(toolLayout);
    tabLayout->addLayout(toolLayout);

    QSplitter* splitter = new QSplitter(Qt::Vertical, m_tabKernelExecutableMemory);
    tabLayout->addWidget(splitter, 1);

    m_kernelExecutableTable = new ks::ui::VisibleTableWidget(splitter);
    ks::ui::SetTableActionBarMode(m_kernelExecutableTable, ks::ui::TableActionBarMode::Full);
    m_kernelExecutableTable->setColumnCount(kernelExecutableColumnIndex(KernelExecutableColumn::Count));
    m_kernelExecutableTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("VA"),
        QStringLiteral("区域大小"),
        QStringLiteral("页数"),
        QStringLiteral("页大小"),
        QStringLiteral("权限"),
        QStringLiteral("Owner"),
        QStringLiteral("模块基址"),
        QStringLiteral("模块路径"),
        QStringLiteral("风险标志")
        });
    m_kernelExecutableTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_kernelExecutableTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_kernelExecutableTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_kernelExecutableTable->setAlternatingRowColors(true);
    m_kernelExecutableTable->setSortingEnabled(true);
    m_kernelExecutableTable->verticalHeader()->setVisible(false);
    m_kernelExecutableTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_kernelExecutableTable->horizontalHeader()->setSectionResizeMode(kernelExecutableColumnIndex(KernelExecutableColumn::ModulePath), QHeaderView::Stretch);
    m_kernelExecutableTable->setColumnWidth(kernelExecutableColumnIndex(KernelExecutableColumn::Va), 170);
    m_kernelExecutableTable->setColumnWidth(kernelExecutableColumnIndex(KernelExecutableColumn::ModuleBase), 170);
    m_kernelExecutableTable->setColumnWidth(kernelExecutableColumnIndex(KernelExecutableColumn::Owner), 180);
    m_kernelExecutableTable->setColumnWidth(kernelExecutableColumnIndex(KernelExecutableColumn::RiskFlags), 220);
    installKernelExecutableCopyMenu(m_kernelExecutableTable);
    splitter->addWidget(m_kernelExecutableTable);

    QWidget* detailPanel = new QWidget(splitter);
    QHBoxLayout* detailLayout = new QHBoxLayout(detailPanel);
    detailLayout->setContentsMargins(0, 0, 0, 0);
    detailLayout->setSpacing(8);

    m_kernelExecutableDetailEditor = new ks::ui::StructuredFieldView(detailPanel);
    m_kernelExecutableDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择一条内核可执行页记录查看详情。")));
    detailLayout->addWidget(m_kernelExecutableDetailEditor, 1);
    splitter->addWidget(detailPanel);

    ks::ui::DetailLayoutRegistry::registerStructuredHost(
        m_kernelExecutableTable,
        m_kernelExecutableDetailEditor,
        m_tabKernelExecutableMemory);

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    m_tabWidget->addTab(m_tabKernelExecutableMemory, QStringLiteral("内核可执行页"));
}

void MemoryDock::refreshKernelExecutableMemoryScanAsync()
{
    // 输入：由刷新按钮或初始化路径触发，无参数。
    // 处理：异步调用 DriverClient::scanKernelExecutableMemory，主线程仅负责落地结果。
    // 返回：无。
    if (m_kernelExecutableRefreshInProgress.exchange(true))
    {
        return;
    }

    // 扫描期间禁用刷新入口，避免重复下发 IOCTL；进度条和状态标签同步进入“扫描中”表现。
    if (m_kernelExecutableRefreshButton != nullptr)
    {
        m_kernelExecutableRefreshButton->setEnabled(false);
    }
    if (m_kernelExecutableStatusLabel != nullptr)
    {
        m_kernelExecutableStatusLabel->setText(QStringLiteral("状态：正在扫描内核可执行页…"));
        m_kernelExecutableStatusLabel->setStyleSheet(kernelExecutableStatusStyle(KswordTheme::PrimaryBlueHex));
    }
    if (m_tabKernelExecutableMemory != nullptr)
    {
        QProgressBar* busyBar = m_tabKernelExecutableMemory->findChild<QProgressBar*>(
            QStringLiteral("kernelExecutableScanProgress"));
        if (busyBar != nullptr)
        {
            busyBar->setVisible(true);
        }
    }

    const std::uint64_t ticket = m_kernelExecutableRefreshTicket.fetch_add(1U) + 1U;
    const QPointer<MemoryDock> guardThis(this);

    std::thread([guardThis, ticket]() {
        if (guardThis == nullptr)
        {
            return;
        }

        const ksword::ark::DriverClient driverClient;
        ksword::ark::KernelExecutableMemoryScanResult scanResult = driverClient.scanKernelExecutableMemory(
            KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL,
            4096U,
            std::wstring());

        QMetaObject::invokeMethod(
            qApp,
            [guardThis, ticket, scanResult = std::move(scanResult)]() mutable {
                if (guardThis == nullptr || ticket != guardThis->m_kernelExecutableRefreshTicket.load()) return;
                auto resultSnapshot =
                    std::make_shared<ksword::ark::KernelExecutableMemoryScanResult>(
                        std::move(scanResult));
                auto commitSnapshot = [guardThis, ticket, resultSnapshot]()
                {
                    if (guardThis == nullptr ||
                        ticket < guardThis->m_kernelExecutableRefreshTicket.load())
                    {
                        return;
                    }

                    // 结果回到主线程：先恢复刷新入口和进度条，再按 io.ok 分支写状态摘要。
                    guardThis->m_kernelExecutableRefreshInProgress.store(false);
                    if (guardThis->m_kernelExecutableRefreshButton != nullptr)
                    {
                        guardThis->m_kernelExecutableRefreshButton->setEnabled(true);
                    }
                    if (guardThis->m_tabKernelExecutableMemory != nullptr)
                    {
                        QProgressBar* busyBar = guardThis->m_tabKernelExecutableMemory->findChild<QProgressBar*>(
                            QStringLiteral("kernelExecutableScanProgress"));
                        if (busyBar != nullptr)
                        {
                            busyBar->setVisible(false);
                        }
                    }

                    const ksword::ark::KernelExecutableMemoryScanResult& snapshot = *resultSnapshot;
                    if (!snapshot.io.ok)
                    {
                        guardThis->m_kernelExecutableCache.clear();
                        guardThis->m_kernelExecutableVisibleCount = 0U;
                        guardThis->rebuildKernelExecutableMemoryScanTable();

                        const QString unsupportedText = snapshot.unsupported
                            ? QStringLiteral("不支持/驱动版本过旧")
                            : QStringLiteral("扫描失败");
                        if (guardThis->m_kernelExecutableStatusLabel != nullptr)
                        {
                            guardThis->m_kernelExecutableStatusLabel->setText(
                                QStringLiteral("状态：%1").arg(unsupportedText));
                            guardThis->m_kernelExecutableStatusLabel->setStyleSheet(
                                kernelExecutableStatusStyle(
                                    snapshot.unsupported
                                        ? KswordTheme::ErrorColor().name(QColor::HexRgb)
                                        : KswordTheme::TextSecondaryColorHex()));
                        }
                        if (guardThis->m_kernelExecutableDetailEditor != nullptr)
                        {
                            ks::ui::FieldDocument diagnostic;
                            diagnostic.section(QStringLiteral("内核可执行页诊断"));
                            if (snapshot.unsupported)
                                diagnostic.note(QStringLiteral("当前驱动不支持内核可执行内存扫描，请更新为匹配版本。"));
                            else
                            {
                                diagnostic.field(QStringLiteral("Win32"), QString::number(snapshot.io.win32Error));
                                diagnostic.field(QStringLiteral("详情"), kernelExecutableIoMessageText(snapshot.io.message));
                            }
                            guardThis->m_kernelExecutableDetailEditor->setDocument(diagnostic);
                        }
                        return;
                    }

                    guardThis->m_kernelExecutableCache = snapshot.entries;
                    guardThis->rebuildKernelExecutableMemoryScanTable();
                    guardThis->showKernelExecutableMemoryDetailByCurrentRow();
                    if (guardThis->m_kernelExecutableStatusLabel != nullptr)
                    {
                        guardThis->m_kernelExecutableStatusLabel->setText(
                            QStringLiteral("状态：总计 %1，显示 %2，模块 %3")
                            .arg(snapshot.totalCount)
                            .arg(guardThis->m_kernelExecutableVisibleCount)
                            .arg(snapshot.moduleCount));
                        guardThis->m_kernelExecutableStatusLabel->setStyleSheet(
                            kernelExecutableStatusStyle(
                                snapshot.entries.empty()
                                    ? KswordTheme::ErrorColor().name(QColor::HexRgb)
                                    : KswordTheme::SuccessColor().name(QColor::HexRgb)));
                    }
                };

                if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                    guardThis.data(),
                    QStringLiteral("memory-kernel-executable-snapshot"),
                    { guardThis->m_kernelExecutableTable },
                    commitSnapshot))
                {
                    return;
                }
                commitSnapshot();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MemoryDock::rebuildKernelExecutableMemoryScanTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_kernelExecutableDetailEditor);
    // 输入：无，依赖 m_kernelExecutableCache 与当前过滤控件。
    // 处理：只做缓存到表格的投影，不重新调用 DriverClient。
    // 返回：无。
    const QString moduleFilter = m_kernelExecutableModuleFilterEdit != nullptr
        ? m_kernelExecutableModuleFilterEdit->text().trimmed()
        : QString();
    const bool riskOnly = m_kernelExecutableRiskOnlyCheck != nullptr
        ? m_kernelExecutableRiskOnlyCheck->isChecked()
        : false;

    std::vector<const ksword::ark::KernelExecutableMemoryPageEntry*> visibleEntries;
    visibleEntries.reserve(m_kernelExecutableCache.size());
    for (const ksword::ark::KernelExecutableMemoryPageEntry& entry : m_kernelExecutableCache)
    {
        if (riskOnly && entry.riskFlags == 0U)
        {
            continue;
        }
        if (!entryMatchesModuleFilter(entry, moduleFilter))
        {
            continue;
        }
        visibleEntries.push_back(&entry);
    }

    m_kernelExecutableVisibleCount = visibleEntries.size();
    if (m_kernelExecutableTable == nullptr)
    {
        return;
    }

    m_kernelExecutableTable->setSortingEnabled(false);
    const QSignalBlocker blocker(m_kernelExecutableTable);
    m_kernelExecutableTable->setRowCount(static_cast<int>(visibleEntries.size()));
    for (int row = 0; row < static_cast<int>(visibleEntries.size()); ++row)
    {
        const ksword::ark::KernelExecutableMemoryPageEntry& entry = *visibleEntries[static_cast<std::size_t>(row)];
        // 数值列一律走 NumericTableItem：VA/模块基址按十六进制展示但按真实数值排序，
        // 区域大小按 KB/MB 展示但按字节数排序，页数/页大小按原始计数排序。
        m_kernelExecutableTable->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::Va),
            createNumericItem(hexValue(entry.virtualAddress), entry.virtualAddress));
        m_kernelExecutableTable->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::RegionSize),
            createNumericItem(byteSizeText(entry.regionSize), entry.regionSize));
        m_kernelExecutableTable->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::PageCount),
            createNumericItem(QString::number(entry.pageCount), entry.pageCount));
        m_kernelExecutableTable->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::PageSize),
            createNumericItem(QString::number(entry.pageSize), entry.pageSize));
        m_kernelExecutableTable->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::Permissions),
            createTextItem(permissionText(entry.permissionFlags)));
        m_kernelExecutableTable->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::Owner),
            createTextItem(ownerKindText(entry.ownerKind)));
        // 模块基址为 0 表示这段可执行页没有匹配到已加载模块，此时展示 N/A 但排序值仍取 0。
        m_kernelExecutableTable->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::ModuleBase),
            createNumericItem(
                entry.moduleBase != 0ULL ? hexValue(entry.moduleBase) : QStringLiteral("N/A"),
                entry.moduleBase));
        m_kernelExecutableTable->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::ModulePath),
            createTextItem(wideToQString(entry.modulePath)));
        m_kernelExecutableTable->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::RiskFlags),
            createTextItem(riskFlagsText(entry.riskFlags)));

        // 风险行整行着色：可写可执行一类判错误色，其余风险位判警告色，无风险行保持默认前景。
        const QColor riskColor = kernelExecutableRiskColor(entry.riskFlags);
        if (riskColor.isValid())
        {
            for (int column = 0; column < m_kernelExecutableTable->columnCount(); ++column)
            {
                QTableWidgetItem* cellItem = m_kernelExecutableTable->item(row, column);
                if (cellItem != nullptr)
                {
                    cellItem->setForeground(riskColor);
                }
            }
        }
    }
    if (visibleEntries.empty())
    {
        const QString detailText = m_kernelExecutableCache.empty()
            ? QStringLiteral("内核可执行页扫描当前没有缓存行；可能是驱动未返回结果、扫描失败或尚未刷新。")
            : QStringLiteral("当前过滤条件隐藏了全部 %1 条内核可执行页记录；请清空模块过滤或关闭“仅风险项”。")
                .arg(static_cast<qulonglong>(m_kernelExecutableCache.size()));
        setKernelExecutableDiagnosticRow(m_kernelExecutableTable, detailText);
    }
    if (m_kernelExecutableTable->rowCount() > 0 && m_kernelExecutableTable->currentRow() < 0)
    {
        m_kernelExecutableTable->setCurrentCell(0, kernelExecutableColumnIndex(KernelExecutableColumn::Va));
    }
    m_kernelExecutableTable->setSortingEnabled(true);
}

void MemoryDock::showKernelExecutableMemoryDetailByCurrentRow()
{
    // 输入：无，依赖当前表格选中行。
    // 处理：把当前行对应的 R3 记录展开到 StructuredFieldView。
    // 返回：无。
    if (m_kernelExecutableDetailEditor == nullptr || m_kernelExecutableTable == nullptr)
    {
        return;
    }

    const int currentRow = m_kernelExecutableTable->currentRow();
    if (currentRow < 0 || currentRow >= m_kernelExecutableTable->rowCount())
    {
        m_kernelExecutableDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择一条内核可执行页记录查看详情。")));
        return;
    }

    const QTableWidgetItem* vaItem = m_kernelExecutableTable->item(currentRow, kernelExecutableColumnIndex(KernelExecutableColumn::Va));
    if (vaItem == nullptr)
    {
        m_kernelExecutableDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前记录的缓存已失效，请刷新后重试。")));
        return;
    }
    const QString diagnosticText = vaItem->data(Qt::UserRole + 2).toString();
    if (!diagnosticText.isEmpty())
    {
        m_kernelExecutableDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("内核可执行页诊断\n%1").arg(diagnosticText)));
        return;
    }

    bool ok = false;
    const qulonglong va = vaItem->data(Qt::UserRole).toULongLong(&ok);
    if (!ok)
    {
        m_kernelExecutableDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前记录的缓存已失效，请刷新后重试。")));
        return;
    }

    for (const ksword::ark::KernelExecutableMemoryPageEntry& entry : m_kernelExecutableCache)
    {
        if (entry.virtualAddress == va)
        {
            m_kernelExecutableDetailEditor->setDocument(buildKernelExecutableDetailDocument(entry));
            return;
        }
    }
    m_kernelExecutableDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前记录的缓存已失效，请刷新后重试。")));
}
