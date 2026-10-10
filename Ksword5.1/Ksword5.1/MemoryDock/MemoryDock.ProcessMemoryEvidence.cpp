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
    // 进程内存证据页列定义：用于稳定排序、过滤和详情定位。
    enum class ProcessMemoryEvidenceColumn : int
    {
        VirtualAddress = 0,
        RegionBase,
        RegionSize,
        Protect,
        State,
        Type,
        Valid,
        Shared,
        Locked,
        LargePage,
        Bad,
        ShareCount,
        Node,
        Win32Protection,
        MappedFile,
        Risk,
        Count
    };

    int evidenceColumnIndex(const ProcessMemoryEvidenceColumn column)
    {
        return static_cast<int>(column);
    }

    QString hex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString protectText(const std::uint32_t protect)
    {
        switch (protect & 0xFFU)
        {
        case PAGE_READONLY: return QStringLiteral("R--");
        case PAGE_READWRITE: return QStringLiteral("RW-");
        case PAGE_WRITECOPY: return QStringLiteral("RWC");
        case PAGE_EXECUTE: return QStringLiteral("--X");
        case PAGE_EXECUTE_READ: return QStringLiteral("R-X");
        case PAGE_EXECUTE_READWRITE: return QStringLiteral("RWX");
        case PAGE_EXECUTE_WRITECOPY: return QStringLiteral("RXC");
        default: return QStringLiteral("0x%1").arg(protect, 8, 16, QChar('0')).toUpper();
        }
    }

    QString stateText(const std::uint32_t state)
    {
        switch (state)
        {
        case MEM_COMMIT: return QStringLiteral("COMMIT");
        case MEM_RESERVE: return QStringLiteral("RESERVE");
        case MEM_FREE: return QStringLiteral("FREE");
        default: return QStringLiteral("0x%1").arg(state, 8, 16, QChar('0')).toUpper();
        }
    }

    QString typeText(const std::uint32_t type)
    {
        switch (type)
        {
        case MEM_IMAGE: return QStringLiteral("IMAGE");
        case MEM_MAPPED: return QStringLiteral("MAPPED");
        case MEM_PRIVATE: return QStringLiteral("PRIVATE");
        default: return QStringLiteral("0x%1").arg(type, 8, 16, QChar('0')).toUpper();
        }
    }

    QString buildRiskText(
        const std::uint32_t protect,
        const std::uint32_t state,
        const std::uint32_t type,
        const bool valid,
        const bool largePage,
        const bool bad)
    {
        QStringList parts;
        if (!valid)
        {
            parts << QStringLiteral("无效页");
        }
        if (state != MEM_COMMIT)
        {
            parts << QStringLiteral("非提交");
        }
        if ((protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE ||
            (protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY)
        {
            parts << QStringLiteral("可写可执行");
        }
        if (type == MEM_PRIVATE && (protect & PAGE_EXECUTE) != 0U)
        {
            parts << QStringLiteral("私有执行");
        }
        if (largePage)
        {
            parts << QStringLiteral("大页");
        }
        if (bad)
        {
            parts << QStringLiteral("坏页");
        }
        return parts.isEmpty() ? QStringLiteral("正常") : parts.join(QStringLiteral(" | "));
    }

    ks::ui::FieldDocument buildDetailDocument(const MemoryDock::ProcessMemoryEvidenceEntry& entry)
    {
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("进程内存证据详情"));
        document.field(QStringLiteral("VA"), QStringLiteral("%1").arg(hex64(entry.virtualAddress)));
        document.field(QStringLiteral("RegionBase"), QStringLiteral("%1").arg(hex64(entry.regionBaseAddress)));
        document.field(QStringLiteral("RegionSize"), QStringLiteral("%1").arg(hex64(entry.regionSize)));
        document.field(QStringLiteral("Protect"), QStringLiteral("%1").arg(protectText(entry.protect)), true);
        document.field(QStringLiteral("State"), QStringLiteral("%1").arg(stateText(entry.state)), true);
        document.field(QStringLiteral("Type"), QStringLiteral("%1").arg(typeText(entry.type)), true);
        document.field(QStringLiteral("Win32Protection"), QStringLiteral("0x%1").arg(entry.win32Protection, 8, 16, QChar('0')));
        document.field(QStringLiteral("ShareCount"), QStringLiteral("%1").arg(entry.shareCount));
        document.field(QStringLiteral("Node"), QStringLiteral("%1").arg(entry.node));
        document.field(QStringLiteral("Valid"), QStringLiteral("%1").arg(entry.valid ? QStringLiteral("true") : QStringLiteral("false")), true);
        document.field(QStringLiteral("Shared"), QStringLiteral("%1").arg(entry.shared ? QStringLiteral("true") : QStringLiteral("false")), true);
        document.field(QStringLiteral("Locked"), QStringLiteral("%1").arg(entry.locked ? QStringLiteral("true") : QStringLiteral("false")), true);
        document.field(QStringLiteral("LargePage"), QStringLiteral("%1").arg(entry.largePage ? QStringLiteral("true") : QStringLiteral("false")), true);
        document.field(QStringLiteral("Bad"), QStringLiteral("%1").arg(entry.bad ? QStringLiteral("true") : QStringLiteral("false")), true);
        document.field(QStringLiteral("MappedFile"), QStringLiteral("%1").arg(entry.mappedFilePath.isEmpty() ? QStringLiteral("—") : entry.mappedFilePath));
        document.field(QStringLiteral("Risk"), QStringLiteral("%1").arg(entry.riskText), true);
        document.field(QStringLiteral("Detail"), QStringLiteral("%1").arg(entry.detailText.isEmpty() ? QStringLiteral("—") : entry.detailText));
        return document;
    }

    QTableWidgetItem* makeItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        return item;
    }

    QTableWidgetItem* makeNumericItem(const QString& text, const std::uint64_t value)
    {
        // makeNumericItem：
        // - 输入：单元格显示文本 text（十六进制地址或十进制计数）与参与排序的真实数值 value；
        // - 处理：构造全局统一的 NumericTableItem，排序读 NumericSortRole，同时把原值写进
        //   Qt::UserRole，供详情面板按虚拟地址反查缓存记录；
        // - 返回：只读数值单元格，所有权随 setItem 交给表格。
        auto* item = new ks::ui::NumericTableItem(text, static_cast<qulonglong>(value));
        item->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(value)));
        item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        return item;
    }

    QString evidenceMenuStyle()
    {
        // evidenceMenuStyle：
        // - 输入：无；
        // - 处理：使用主题色生成不透明 QMenu 样式；
        // - 返回：右键菜单样式，避免透明菜单导致不可读。
        // 右键菜单一律走全局主题实现，避免每个页面各拼一份互相漂移的 QSS。
        return KswordTheme::ContextMenuStyle();
    }

    void copyEvidenceCurrentRow(QTableWidget* table)
    {
        // copyEvidenceCurrentRow：
        // - 输入：当前内存证据表；
        // - 处理：把当前行按 TSV 写入剪贴板；
        // - 返回：无，剪贴板不可用或无当前行时直接返回。
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

    void installEvidenceCopyMenu(QTableWidget* table)
    {
        // installEvidenceCopyMenu：
        // - 输入：进程内存证据表；
        // - 处理：安装只读复制菜单；
        // - 返回：无，不改变目标进程内存。
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

            QMenu menu(table);
            menu.setStyleSheet(evidenceMenuStyle());
            QAction* copyRowAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            // 进程内存证据的虚拟地址属于 Dock 附加的进程：提供"在内存工作台打开"。
            (void)addOpenInWorkbenchAction(
                menu, table, table->currentRow(),
                evidenceColumnIndex(ProcessMemoryEvidenceColumn::VirtualAddress), false);
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyEvidenceCurrentRow(table);
            }
        });
    }

    int visibleEvidenceColumnCount(const QTableWidget* table)
    {
        // visibleEvidenceColumnCount：
        // - 输入：进程内存证据表；
        // - 处理：统计当前未被隐藏的列数；
        // - 返回：可见列数量，供选列菜单守住“至少留一列”的底线。
        if (table == nullptr)
        {
            return 0;
        }

        int visibleCount = 0;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            if (!table->isColumnHidden(columnIndex))
            {
                ++visibleCount;
            }
        }
        return visibleCount;
    }

    void installEvidenceColumnMenu(QTableWidget* table)
    {
        // installEvidenceColumnMenu：
        // - 输入：进程内存证据表；
        // - 处理：给表头装右键选列菜单，每列一个 checkable 动作并与 setColumnHidden 双向联动；
        // - 返回：无。菜单在回调里就地构建再销毁，不引入任何成员变量。
        // 十六列的证据表不给收列入口，用户只能横向拖滚动条找“风险”列。
        if (table == nullptr || table->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* header = table->horizontalHeader();
        header->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(header, &QHeaderView::customContextMenuRequested, header,
            [table, header](const QPoint& localPosition) {
                QMenu columnMenu(table);
                columnMenu.setStyleSheet(evidenceMenuStyle());

                // 首项是禁用的标题项，说明这份菜单管的是列可见性而不是行操作。
                QAction* titleAction = columnMenu.addAction(QStringLiteral("显示的列"));
                titleAction->setEnabled(false);
                columnMenu.addSeparator();

                for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* headerItem = table->horizontalHeaderItem(columnIndex);
                    const QString headerText = headerItem != nullptr
                        ? headerItem->text()
                        : QString::number(columnIndex);
                    QAction* columnAction = columnMenu.addAction(headerText);
                    columnAction->setCheckable(true);
                    columnAction->setChecked(!table->isColumnHidden(columnIndex));
                    QObject::connect(columnAction, &QAction::toggled, table,
                        [table, columnIndex](const bool columnVisible) {
                            // 最后一列不允许再关：表格全隐藏后连表头都点不到，无法自救。
                            if (!columnVisible && visibleEvidenceColumnCount(table) <= 1)
                            {
                                return;
                            }
                            table->setColumnHidden(columnIndex, !columnVisible);
                            ks::ui::RequestTableColumnAutoFit(table);
                        });
                }

                columnMenu.addSeparator();
                QAction* showAllAction = columnMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/filter_funnel.svg")),
                    QStringLiteral("显示全部列"));
                showAllAction->setToolTip(QStringLiteral("取消所有列隐藏，恢复完整证据视图"));
                QObject::connect(showAllAction, &QAction::triggered, table, [table]() {
                    for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
                    {
                        table->setColumnHidden(columnIndex, false);
                    }
                    ks::ui::RequestTableColumnAutoFit(table);
                });

                columnMenu.exec(header->mapToGlobal(localPosition));
            });
    }

    void setProcessEvidenceDiagnosticRow(
        QTableWidget* table,
        const QString& detailText)
    {
        // setProcessEvidenceDiagnosticRow：
        // - 输入：目标进程内存证据表和诊断说明；
        // - 处理：写入一行可复制诊断，UserRole+2 保存完整文本；
        // - 返回：无。用于附加失败、空缓存或过滤空结果时避免空表。
        if (table == nullptr)
        {
            return;
        }

        table->setRowCount(1);
        QTableWidgetItem* vaItem = makeItem(QStringLiteral("<无进程内存证据>"));
        vaItem->setData(Qt::UserRole + 2, detailText);
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::VirtualAddress), vaItem);
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::RegionBase), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::RegionSize), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Protect), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::State), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Type), makeItem(QStringLiteral("诊断")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Valid), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Shared), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Locked), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::LargePage), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Bad), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::ShareCount), makeItem(QStringLiteral("0")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Node), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Win32Protection), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::MappedFile), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Risk), makeItem(detailText));
        table->setCurrentCell(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::VirtualAddress));
    }
}

void MemoryDock::initializeProcessMemoryEvidenceTab()
{
    // 输入：无，由 initializeTabs 调用。
    // 处理：构建只读进程内存证据页，围绕 VirtualQueryEx / QueryWorkingSetEx 做风险投影。
    // 返回：无。
    kLogEvent initEvent;
    info << initEvent
        << "[MemoryDock] initializeProcessMemoryEvidenceTab: 构建进程内存证据页面。"
        << eol;

    m_tabProcessMemoryEvidence = new QWidget(m_tabWidget);
    // 页面自带内部滚动壳：内容放不下时在页内滚动，不把 Dock 撑高。页面指针身份不变。
    QWidget* const tabContent = ks::ui::EnablePageInnerScroll(m_tabProcessMemoryEvidence);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // 第一层动作行：只放刷新、两个过滤开关和状态标签，原来十一个控件挤一行已经无法阅读。
    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(8);

    m_processMemoryEvidenceRefreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), m_tabProcessMemoryEvidence);
    m_processMemoryEvidenceRefreshButton->setToolTip(QStringLiteral("按当前附加进程采集内存证据"));
    m_processMemoryEvidenceRefreshButton->setStyleSheet(buildBlueButtonStyle());

    // 竖线分隔符把动作区和开关区在视觉上切开，颜色取动态边框角色，跟随主题切换。
    QFrame* actionSeparator = new QFrame(m_tabProcessMemoryEvidence);
    actionSeparator->setFrameShape(QFrame::VLine);
    actionSeparator->setFrameShadow(QFrame::Plain);
    actionSeparator->setFixedWidth(1);
    actionSeparator->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::BorderHex()));

    m_processMemoryEvidenceRiskOnlyCheck = new QCheckBox(QStringLiteral("仅显示风险项"), m_tabProcessMemoryEvidence);
    m_processMemoryEvidenceRiskOnlyCheck->setChecked(true);
    m_processMemoryEvidenceRiskOnlyCheck->setToolTip(QStringLiteral("只列出命中风险规则的页，风险为正常的页不进表"));
    m_processMemoryEvidenceRiskOnlyCheck->setStyleSheet(QStringLiteral(
        "QCheckBox { color:%1; font-weight:600; }")
        .arg(KswordTheme::TextPrimaryHex()));

    m_processMemoryEvidenceImageOnlyCheck = new QCheckBox(QStringLiteral("仅映像区域"), m_tabProcessMemoryEvidence);
    m_processMemoryEvidenceImageOnlyCheck->setToolTip(QStringLiteral("只采集 MEM_IMAGE 映像区域，跳过私有与映射区域"));

    m_processMemoryEvidenceStatusLabel = new QLabel(QStringLiteral("状态：等待刷新"), m_tabProcessMemoryEvidence);
    m_processMemoryEvidenceStatusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_processMemoryEvidenceStatusLabel->setStyleSheet(QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    actionLayout->addWidget(m_processMemoryEvidenceRefreshButton);
    actionLayout->addWidget(actionSeparator);
    actionLayout->addWidget(m_processMemoryEvidenceRiskOnlyCheck);
    actionLayout->addWidget(m_processMemoryEvidenceImageOnlyCheck);
    actionLayout->addWidget(m_processMemoryEvidenceStatusLabel, 1);
    ks::ui::NormalizeToolbarRow(actionLayout);
    tabLayout->addLayout(actionLayout);

    // 第二层扫描范围分组：四组带标签的输入按 2x2 网格排布，字段名不再是裸标签挤在动作行里。
    QGroupBox* scopeGroup = new QGroupBox(QStringLiteral("扫描范围"), m_tabProcessMemoryEvidence);
    QGridLayout* scopeLayout = new QGridLayout(scopeGroup);
    scopeLayout->setContentsMargins(10, 8, 10, 8);
    scopeLayout->setHorizontalSpacing(8);
    scopeLayout->setVerticalSpacing(6);

    m_processMemoryEvidenceStartEdit = new QLineEdit(scopeGroup);
    m_processMemoryEvidenceStartEdit->setClearButtonEnabled(true);
    m_processMemoryEvidenceStartEdit->setPlaceholderText(QStringLiteral("留空从进程最低地址开始"));
    m_processMemoryEvidenceStartEdit->setToolTip(QStringLiteral("采样起始虚拟地址。无前缀按十六进制解释，也可显式写 0x 前缀。"));
    m_processMemoryEvidenceStartEdit->setStyleSheet(buildBlueInputStyle());

    m_processMemoryEvidenceEndEdit = new QLineEdit(scopeGroup);
    m_processMemoryEvidenceEndEdit->setClearButtonEnabled(true);
    m_processMemoryEvidenceEndEdit->setPlaceholderText(QStringLiteral("留空到进程最高地址结束"));
    m_processMemoryEvidenceEndEdit->setToolTip(QStringLiteral("采样结束虚拟地址。无前缀按十六进制解释，也可显式写 0x 前缀。"));
    m_processMemoryEvidenceEndEdit->setStyleSheet(buildBlueInputStyle());

    m_processMemoryEvidenceFilterEdit = new QLineEdit(scopeGroup);
    m_processMemoryEvidenceFilterEdit->setClearButtonEnabled(true);
    m_processMemoryEvidenceFilterEdit->setPlaceholderText(QStringLiteral("过滤映射文件 / 风险文本"));
    m_processMemoryEvidenceFilterEdit->setToolTip(QStringLiteral("按映射文件路径、风险描述或证据说明实时过滤已采样的行"));
    m_processMemoryEvidenceFilterEdit->setStyleSheet(buildBlueInputStyle());
    ks::ui::StyleSearchField(m_processMemoryEvidenceFilterEdit);

    m_processMemoryEvidenceMaxRowsSpin = new QSpinBox(scopeGroup);
    m_processMemoryEvidenceMaxRowsSpin->setRange(32, 8192);
    m_processMemoryEvidenceMaxRowsSpin->setValue(512);
    m_processMemoryEvidenceMaxRowsSpin->setToolTip(QStringLiteral("单次采样最大页数"));

    // 四个字段名做成正式标签，统一次级文字色，避免和输入内容抢视觉焦点。
    QLabel* startFieldLabel = new QLabel(QStringLiteral("起始地址"), scopeGroup);
    QLabel* endFieldLabel = new QLabel(QStringLiteral("结束地址"), scopeGroup);
    QLabel* maxRowsFieldLabel = new QLabel(QStringLiteral("最大行数"), scopeGroup);
    QLabel* filterFieldLabel = new QLabel(QStringLiteral("文本过滤"), scopeGroup);
    for (QLabel* fieldLabel : { startFieldLabel, endFieldLabel, maxRowsFieldLabel, filterFieldLabel })
    {
        fieldLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    }

    scopeLayout->addWidget(startFieldLabel, 0, 0);
    scopeLayout->addWidget(m_processMemoryEvidenceStartEdit, 0, 1);
    scopeLayout->addWidget(endFieldLabel, 0, 2);
    scopeLayout->addWidget(m_processMemoryEvidenceEndEdit, 0, 3);
    scopeLayout->addWidget(maxRowsFieldLabel, 1, 0);
    scopeLayout->addWidget(m_processMemoryEvidenceMaxRowsSpin, 1, 1);
    scopeLayout->addWidget(filterFieldLabel, 1, 2);
    scopeLayout->addWidget(m_processMemoryEvidenceFilterEdit, 1, 3);
    scopeLayout->setColumnStretch(1, 1);
    scopeLayout->setColumnStretch(3, 2);
    tabLayout->addWidget(scopeGroup);

    QSplitter* splitter = new QSplitter(Qt::Vertical, m_tabProcessMemoryEvidence);
    tabLayout->addWidget(splitter, 1);

    m_processMemoryEvidenceTable = new ks::ui::VisibleTableWidget(splitter);
    // 进程页级证据可重复采样，保留独立现场对比。
    ks::ui::SetTableActionBarMode(m_processMemoryEvidenceTable, ks::ui::TableActionBarMode::Full);
    m_processMemoryEvidenceTable->setColumnCount(evidenceColumnIndex(ProcessMemoryEvidenceColumn::Count));
    m_processMemoryEvidenceTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("虚拟地址"),
        QStringLiteral("区域基址"),
        QStringLiteral("区域大小"),
        QStringLiteral("保护"),
        QStringLiteral("状态"),
        QStringLiteral("类型"),
        QStringLiteral("有效"),
        QStringLiteral("共享"),
        QStringLiteral("锁定"),
        QStringLiteral("大页"),
        QStringLiteral("坏页"),
        QStringLiteral("共享计数"),
        QStringLiteral("NUMA 节点"),
        QStringLiteral("Win32Prot"),
        QStringLiteral("映射文件"),
        QStringLiteral("风险")
    });
    m_processMemoryEvidenceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_processMemoryEvidenceTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_processMemoryEvidenceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_processMemoryEvidenceTable->setAlternatingRowColors(true);
    m_processMemoryEvidenceTable->setSortingEnabled(true);
    m_processMemoryEvidenceTable->verticalHeader()->setVisible(false);
    m_processMemoryEvidenceTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_processMemoryEvidenceTable->horizontalHeader()->setSectionResizeMode(evidenceColumnIndex(ProcessMemoryEvidenceColumn::MappedFile), QHeaderView::Stretch);
    installEvidenceCopyMenu(m_processMemoryEvidenceTable);
    // 十六列表格必须给收列入口，否则用户只能靠横向滚动条找自己关心的列。
    installEvidenceColumnMenu(m_processMemoryEvidenceTable);
    splitter->addWidget(m_processMemoryEvidenceTable);

    m_processMemoryEvidenceDetailEditor = new ks::ui::StructuredFieldView(splitter);
    m_processMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择一条进程内存证据记录查看详情。")));
    splitter->addWidget(m_processMemoryEvidenceDetailEditor);

    ks::ui::DetailLayoutRegistry::registerStructuredHost(
        m_processMemoryEvidenceTable,
        m_processMemoryEvidenceDetailEditor,
        m_tabProcessMemoryEvidence);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    m_tabWidget->addTab(m_tabProcessMemoryEvidence, QStringLiteral("进程内存证据"));
}

void MemoryDock::refreshProcessMemoryEvidenceAsync()
{
    // 输入：无，由刷新按钮或 tab 路由触发。
    // 处理：基于当前附加进程的地址范围采集 VirtualQueryEx / QueryWorkingSetEx 证据。
    // 返回：无。
    if (m_processMemoryEvidenceRefreshInProgress.exchange(true))
    {
        return;
    }

    // 抢到采集权后立刻锁住刷新按钮并写进度文案：采集要遍历整个用户态地址空间，
    // 没有反馈时用户会以为界面卡死并连点，重复排队后续刷新。
    if (m_processMemoryEvidenceRefreshButton != nullptr)
    {
        m_processMemoryEvidenceRefreshButton->setEnabled(false);
    }
    if (m_processMemoryEvidenceStatusLabel != nullptr)
    {
        m_processMemoryEvidenceStatusLabel->setText(QStringLiteral("状态：正在采集进程内存证据…"));
        m_processMemoryEvidenceStatusLabel->setStyleSheet(
            QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    }

    if (m_attachedProcessHandle == nullptr || m_attachedPid == 0U)
    {
        m_processMemoryEvidenceRefreshInProgress.store(false);
        // 提前失败也要把按钮解锁，否则未附加进程时刷新按钮会永久灰掉。
        if (m_processMemoryEvidenceRefreshButton != nullptr)
        {
            m_processMemoryEvidenceRefreshButton->setEnabled(true);
        }
        if (m_processMemoryEvidenceStatusLabel != nullptr)
        {
            m_processMemoryEvidenceStatusLabel->setText(QStringLiteral("状态：请先附加进程。"));
            m_processMemoryEvidenceStatusLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;")
                    .arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
        }
        return;
    }

    std::uint32_t duplicateError = ERROR_SUCCESS;
    const std::shared_ptr<void> processHandleLease =
        duplicateAttachedProcessHandleForWorker(&duplicateError);
    if (!processHandleLease)
    {
        m_processMemoryEvidenceRefreshInProgress.store(false);
        if (m_processMemoryEvidenceRefreshButton != nullptr)
        {
            m_processMemoryEvidenceRefreshButton->setEnabled(true);
        }
        if (m_processMemoryEvidenceStatusLabel != nullptr)
        {
            m_processMemoryEvidenceStatusLabel->setText(
                QStringLiteral("状态：复制进程句柄失败（Win32=%1）。").arg(duplicateError));
            m_processMemoryEvidenceStatusLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;")
                    .arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
        }
        return;
    }

    std::uint64_t startAddress = 0ULL;
    std::uint64_t endAddress = 0ULL;
    if (m_processMemoryEvidenceStartEdit != nullptr)
    {
        parseAddressText(m_processMemoryEvidenceStartEdit->text().trimmed(), startAddress);
    }
    if (m_processMemoryEvidenceEndEdit != nullptr)
    {
        parseAddressText(m_processMemoryEvidenceEndEdit->text().trimmed(), endAddress);
    }

    const std::uint32_t maxRows = m_processMemoryEvidenceMaxRowsSpin != nullptr
        ? static_cast<std::uint32_t>(m_processMemoryEvidenceMaxRowsSpin->value())
        : 512U;
    const bool imageOnly = m_processMemoryEvidenceImageOnlyCheck != nullptr && m_processMemoryEvidenceImageOnlyCheck->isChecked();

    const std::uint64_t ticket = m_processMemoryEvidenceRefreshTicket.fetch_add(1U) + 1U;
    const std::uint64_t attachmentGeneration = m_processAttachmentGeneration.load();
    const QPointer<MemoryDock> guardThis(this);

    std::thread([guardThis,
                 processHandleLease,
                 ticket,
                 attachmentGeneration,
                 startAddress,
                 endAddress,
                 maxRows,
                 imageOnly]() {
        const HANDLE workerProcessHandle = static_cast<HANDLE>(processHandleLease.get());
        std::vector<ProcessMemoryEvidenceEntry> entries;
        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);
        const std::uint64_t pageSize = static_cast<std::uint64_t>(systemInfo.dwPageSize);
        const std::uint64_t minAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const std::uint64_t maxAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);
        std::uint64_t currentAddress = startAddress != 0ULL ? startAddress : minAddress;
        const std::uint64_t stopAddress = endAddress != 0ULL ? endAddress : maxAddress;
        if (pageSize != 0ULL)
        {
            currentAddress = (currentAddress / pageSize) * pageSize;
        }

        while (currentAddress < stopAddress && entries.size() < maxRows)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQueryEx(
                    workerProcessHandle,
                    reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(currentAddress)),
                    &mbi,
                    sizeof(mbi)) != sizeof(mbi))
            {
                break;
            }

            const std::uint64_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uint64_t regionSize = static_cast<std::uint64_t>(mbi.RegionSize);
            const bool regionIsImage = mbi.Type == MEM_IMAGE;
            if (imageOnly && !regionIsImage)
            {
                const std::uint64_t nextAddress = regionBase + regionSize;
                if (nextAddress <= currentAddress)
                {
                    break;
                }
                currentAddress = nextAddress;
                continue;
            }

            const std::uint64_t pageCount = pageSize == 0ULL ? 1ULL : std::max<std::uint64_t>(1ULL, regionSize / pageSize);
            for (std::uint64_t pageIndex = 0; pageIndex < pageCount && entries.size() < maxRows; ++pageIndex)
            {
                const std::uint64_t va = regionBase + (pageIndex * pageSize);
                if (va >= stopAddress)
                {
                    break;
                }

                PSAPI_WORKING_SET_EX_INFORMATION wsInfo{};
                wsInfo.VirtualAddress = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(va));
                const BOOL queryOk = ::QueryWorkingSetEx(
                    workerProcessHandle,
                    &wsInfo,
                    static_cast<DWORD>(sizeof(wsInfo)));

                ProcessMemoryEvidenceEntry entry{};
                entry.virtualAddress = va;
                entry.regionBaseAddress = regionBase;
                entry.regionSize = regionSize;
                entry.protect = static_cast<std::uint32_t>(mbi.Protect);
                entry.state = static_cast<std::uint32_t>(mbi.State);
                entry.type = static_cast<std::uint32_t>(mbi.Type);
                entry.mappedFilePath = (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) ? QStringLiteral("") : QString();

                if (queryOk != FALSE)
                {
                    entry.valid = wsInfo.VirtualAttributes.Valid != 0;
                    entry.shared = wsInfo.VirtualAttributes.Shared != 0;
                    entry.locked = wsInfo.VirtualAttributes.Locked != 0;
                    entry.largePage = wsInfo.VirtualAttributes.LargePage != 0;
                    entry.bad = wsInfo.VirtualAttributes.Bad != 0;
                    entry.shareCount = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.ShareCount);
                    entry.win32Protection = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.Win32Protection);
                    entry.node = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.Node);
                }

                entry.riskText = buildRiskText(entry.protect, entry.state, entry.type, entry.valid, entry.largePage, entry.bad);
                entry.detailText = QStringLiteral("VirtualQueryEx + QueryWorkingSetEx 只读证据");
                entries.push_back(std::move(entry));
            }

            const std::uint64_t nextAddress = regionBase + regionSize;
            if (nextAddress <= currentAddress)
            {
                break;
            }
            currentAddress = nextAddress;
        }

        QMetaObject::invokeMethod(
            qApp,
            [guardThis, ticket, attachmentGeneration, entries = std::move(entries)]() mutable {
                if (guardThis == nullptr || ticket != guardThis->m_processMemoryEvidenceRefreshTicket.load() || attachmentGeneration != guardThis->m_processAttachmentGeneration.load()) return;
                auto entriesSnapshot =
                    std::make_shared<std::vector<ProcessMemoryEvidenceEntry>>(std::move(entries));
                auto commitSnapshot = [guardThis, ticket, attachmentGeneration, entriesSnapshot]() mutable
                {
                    if (guardThis == nullptr ||
                        ticket != guardThis->m_processMemoryEvidenceRefreshTicket.load() ||
                        attachmentGeneration != guardThis->m_processAttachmentGeneration.load())
                    {
                        return;
                    }

                    guardThis->m_processMemoryEvidenceRefreshInProgress.store(false);
                    if (guardThis->m_processMemoryEvidenceRefreshButton != nullptr)
                    {
                        guardThis->m_processMemoryEvidenceRefreshButton->setEnabled(true);
                    }

                    guardThis->m_processMemoryEvidenceCache = std::move(*entriesSnapshot);
                    guardThis->rebuildProcessMemoryEvidenceTable();
                    guardThis->showProcessMemoryEvidenceDetailByCurrentRow();
                    if (guardThis->m_processMemoryEvidenceStatusLabel != nullptr)
                    {
                        guardThis->m_processMemoryEvidenceStatusLabel->setText(
                            QStringLiteral("状态：采样 %1 行").arg(guardThis->m_processMemoryEvidenceCache.size()));
                        guardThis->m_processMemoryEvidenceStatusLabel->setStyleSheet(QStringLiteral(
                            "color:%1; font-weight:600;")
                            .arg(guardThis->m_processMemoryEvidenceCache.empty()
                                ? KswordTheme::ErrorColor().name(QColor::HexRgb)
                                : KswordTheme::SuccessColor().name(QColor::HexRgb)));
                    }
                };

                if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                    guardThis.data(),
                    QStringLiteral("memory-process-evidence-snapshot"),
                    { guardThis->m_processMemoryEvidenceTable },
                    commitSnapshot))
                {
                    return;
                }
                commitSnapshot();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MemoryDock::rebuildProcessMemoryEvidenceTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_processMemoryEvidenceDetailEditor);
    // 输入：读取当前缓存和过滤选项。
    // 处理：把进程内存证据投影到只读表格。
    // 返回：无。
    if (m_processMemoryEvidenceTable == nullptr)
    {
        return;
    }

    const bool riskOnly = m_processMemoryEvidenceRiskOnlyCheck != nullptr && m_processMemoryEvidenceRiskOnlyCheck->isChecked();
    const QString filterText = m_processMemoryEvidenceFilterEdit != nullptr
        ? m_processMemoryEvidenceFilterEdit->text().trimmed()
        : QString();

    std::vector<const ProcessMemoryEvidenceEntry*> visibleEntries;
    visibleEntries.reserve(m_processMemoryEvidenceCache.size());
    for (const ProcessMemoryEvidenceEntry& entry : m_processMemoryEvidenceCache)
    {
        if (riskOnly && entry.riskText == QStringLiteral("正常"))
        {
            continue;
        }
        if (!filterText.isEmpty())
        {
            const QString detailText = entry.detailText;
            const QString mappedText = entry.mappedFilePath;
            if (!detailText.contains(filterText, Qt::CaseInsensitive) &&
                !mappedText.contains(filterText, Qt::CaseInsensitive) &&
                !entry.riskText.contains(filterText, Qt::CaseInsensitive))
            {
                continue;
            }
        }
        visibleEntries.push_back(&entry);
    }

    m_processMemoryEvidenceVisibleCount = visibleEntries.size();
    const QSignalBlocker blocker(m_processMemoryEvidenceTable);
    m_processMemoryEvidenceTable->setSortingEnabled(false);
    m_processMemoryEvidenceTable->setRowCount(static_cast<int>(visibleEntries.size()));
    for (int row = 0; row < static_cast<int>(visibleEntries.size()); ++row)
    {
        const ProcessMemoryEvidenceEntry& entry = *visibleEntries[static_cast<std::size_t>(row)];
        // 地址、大小、计数、节点号一律走数值排序单元格，否则按显示文本排会退化成字符串序。
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::VirtualAddress), makeNumericItem(hex64(entry.virtualAddress), entry.virtualAddress));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::RegionBase), makeNumericItem(hex64(entry.regionBaseAddress), entry.regionBaseAddress));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::RegionSize), makeNumericItem(hex64(entry.regionSize), entry.regionSize));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Protect), makeItem(protectText(entry.protect)));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::State), makeItem(stateText(entry.state)));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Type), makeItem(typeText(entry.type)));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Valid), makeItem(entry.valid ? QStringLiteral("Yes") : QStringLiteral("No")));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Shared), makeItem(entry.shared ? QStringLiteral("Yes") : QStringLiteral("No")));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Locked), makeItem(entry.locked ? QStringLiteral("Yes") : QStringLiteral("No")));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::LargePage), makeItem(entry.largePage ? QStringLiteral("Yes") : QStringLiteral("No")));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Bad), makeItem(entry.bad ? QStringLiteral("Yes") : QStringLiteral("No")));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::ShareCount), makeNumericItem(QString::number(entry.shareCount), entry.shareCount));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Node), makeNumericItem(QString::number(entry.node), entry.node));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Win32Protection), makeNumericItem(QStringLiteral("0x%1").arg(entry.win32Protection, 8, 16, QChar('0')).toUpper(), entry.win32Protection));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::MappedFile), makeItem(entry.mappedFilePath.isEmpty() ? QStringLiteral("—") : entry.mappedFilePath));
        m_processMemoryEvidenceTable->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::Risk), makeItem(entry.riskText));
    }
    if (visibleEntries.empty())
    {
        const QString detailText = m_processMemoryEvidenceCache.empty()
            ? QStringLiteral("进程内存证据当前没有缓存行；请先附加进程并刷新，或检查采样范围。")
            : QStringLiteral("当前过滤条件隐藏了全部 %1 条进程内存证据；请清空文本过滤或取消勾选仅显示风险项/仅映像区域。")
                .arg(static_cast<qulonglong>(m_processMemoryEvidenceCache.size()));
        setProcessEvidenceDiagnosticRow(m_processMemoryEvidenceTable, detailText);
    }

    if (m_processMemoryEvidenceTable->rowCount() > 0 && m_processMemoryEvidenceTable->currentRow() < 0)
    {
        m_processMemoryEvidenceTable->setCurrentCell(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::VirtualAddress));
    }
    m_processMemoryEvidenceTable->setSortingEnabled(true);
    ks::ui::RequestTableColumnAutoFit(m_processMemoryEvidenceTable);
}

void MemoryDock::showProcessMemoryEvidenceDetailByCurrentRow()
{
    // 输入：无，读取当前表格选中行。
    // 处理：从缓存中展开当前证据记录到详情编辑器。
    // 返回：无。
    if (m_processMemoryEvidenceDetailEditor == nullptr || m_processMemoryEvidenceTable == nullptr)
    {
        return;
    }

    const int row = m_processMemoryEvidenceTable->currentRow();
    if (row < 0 || row >= m_processMemoryEvidenceTable->rowCount())
    {
        m_processMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择一条进程内存证据记录查看详情。")));
        return;
    }

    const QTableWidgetItem* addressItem = m_processMemoryEvidenceTable->item(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::VirtualAddress));
    if (addressItem == nullptr)
    {
        m_processMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前记录的缓存已失效，请刷新后重试。")));
        return;
    }
    const QString diagnosticText = addressItem->data(Qt::UserRole + 2).toString();
    if (!diagnosticText.isEmpty())
    {
        m_processMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("进程内存证据诊断\n%1").arg(diagnosticText)));
        return;
    }

    bool ok = false;
    const qulonglong addressValue = addressItem->data(Qt::UserRole).toULongLong(&ok);
    if (!ok)
    {
        m_processMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前记录的缓存已失效，请刷新后重试。")));
        return;
    }

    for (const ProcessMemoryEvidenceEntry& entry : m_processMemoryEvidenceCache)
    {
        if (entry.virtualAddress == static_cast<std::uint64_t>(addressValue))
        {
            m_processMemoryEvidenceDetailEditor->setDocument(buildDetailDocument(entry));
            return;
        }
    }
    m_processMemoryEvidenceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前记录的缓存已失效，请刷新后重试。")));
}
