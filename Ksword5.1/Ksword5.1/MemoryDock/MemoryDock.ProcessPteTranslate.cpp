#include "MemoryDock.Internal.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/AdaptivePageScroll.h" // ks::ui::EnablePageInnerScroll：页内滚动壳。
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../UI/TableColumnAutoFit.h"

// 分层工具条用到的 Qt 控件在这里显式补齐：Internal.h 虽然已经聚合了同名头，
// 但那份聚合头是多人共用的，本页面不依赖它的收录清单，避免它增删条目时被连累。
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>

#include <memory>

using namespace ksword::memory_dock_internal;

namespace
{
    // PTE / VA 翻译页列定义：保持排序、过滤和详情反查使用稳定列号。
    enum class PteTranslateColumn : int
    {
        VirtualAddress = 0,
        RegionBase,
        Valid,
        Shared,
        Locked,
        LargePage,
        Bad,
        ShareCount,
        Win32Protection,
        Node,
        MappedFile,
        Risk,
        Count
    };

    // 将列枚举转为 Qt 列索引。
    int pteTranslateColumnIndex(const PteTranslateColumn column)
    {
        return static_cast<int>(column);
    }

    // 把 `QWidget` 侧宽字符串安全转为 `QString`。
    QString wideToQString(const std::wstring& value)
    {
        return value.empty() ? QString() : QString::fromStdWString(value);
    }

    // 把地址格式化为稳定的 16 进制字符串。
    QString hex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    // 组合一条只读风险文本。
    QString buildPteRiskText(
        const std::uint32_t protect,
        const bool valid,
        const bool bad,
        const bool largePage)
    {
        QStringList parts;
        if (!valid)
        {
            parts << QStringLiteral("无效页");
        }
        if ((protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE ||
            (protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY)
        {
            parts << QStringLiteral("可写可执行");
        }
        if (bad)
        {
            parts << QStringLiteral("Bad 页");
        }
        if (largePage)
        {
            parts << QStringLiteral("大页");
        }
        return parts.isEmpty() ? QStringLiteral("正常") : parts.join(QStringLiteral(" | "));
    }

    // 构造只读表格项。
    QTableWidgetItem* makeReadOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        return item;
    }

    QString pteMenuStyle()
    {
        // pteMenuStyle：
        // - 输入：无；
        // - 处理：生成不透明右键菜单样式；
        // - 返回：QMenu 样式文本。
        // 右键菜单一律走全局主题实现，避免每个页面各拼一份互相漂移的 QSS。
        return KswordTheme::ContextMenuStyle();
    }

    void copyPteCurrentRow(QTableWidget* table)
    {
        // copyPteCurrentRow：
        // - 输入：PTE/VA 翻译表；
        // - 处理：复制当前行所有列；
        // - 返回：无，失败时静默返回。
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

    void installPteCopyMenu(QTableWidget* table)
    {
        // installPteCopyMenu：
        // - 输入：PTE/VA 翻译表；
        // - 处理：安装只读复制菜单；
        // - 返回：无，不读取或修改额外内存。
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
            menu.setStyleSheet(pteMenuStyle());
            QAction* copyRowAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
            // 菜单项也补上 tooltip：与页面内其它按钮保持一致的可发现性。
            copyRowAction->setToolTip(QStringLiteral("把选中行的全部列以制表符分隔复制到剪贴板"));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            // PTE/VA 翻译的虚拟地址属于 Dock 附加的进程：提供"在内存工作台打开"。
            (void)addOpenInWorkbenchAction(
                menu, table, table->currentRow(),
                pteTranslateColumnIndex(PteTranslateColumn::VirtualAddress), false);
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyPteCurrentRow(table);
            }
        });
    }

    void setPteDiagnosticRow(
        QTableWidget* table,
        const QString& detailText)
    {
        // setPteDiagnosticRow：
        // - 输入：目标 PTE 表与诊断说明；
        // - 处理：写入一行可复制诊断，UserRole+2 保存完整文本；
        // - 返回：无。用于尚未附加、查询为空或风险过滤清空时避免空表。
        if (table == nullptr)
        {
            return;
        }

        table->setRowCount(1);
        QTableWidgetItem* vaItem = makeReadOnlyItem(QStringLiteral("<无PTE证据>"));
        vaItem->setData(Qt::UserRole + 2, detailText);
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::VirtualAddress), vaItem);
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::RegionBase), makeReadOnlyItem(QStringLiteral("N/A")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::Valid), makeReadOnlyItem(QStringLiteral("-")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::Shared), makeReadOnlyItem(QStringLiteral("-")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::Locked), makeReadOnlyItem(QStringLiteral("-")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::LargePage), makeReadOnlyItem(QStringLiteral("-")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::Bad), makeReadOnlyItem(QStringLiteral("-")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::ShareCount), makeReadOnlyItem(QStringLiteral("0")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::Win32Protection), makeReadOnlyItem(QStringLiteral("N/A")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::Node), makeReadOnlyItem(QStringLiteral("0")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::MappedFile), makeReadOnlyItem(QStringLiteral("N/A")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::Risk), makeReadOnlyItem(detailText));
        table->setCurrentCell(0, pteTranslateColumnIndex(PteTranslateColumn::VirtualAddress));
    }

    // 数值列一律改用 ks::ui::NumericTableItem：排序值写在 NumericSortRole 上，
    // 页面本地那份把数值塞进 Qt::UserRole 的私有 NumericItem 已删除，避免与
    // 其它页面的 UserRole 约定互相踩踏，也不必再各自维护一份 operator<。

    // 生成用于详情窗的结构字段。
    ks::ui::FieldDocument buildPteDetailDocument(const MemoryDock::ProcessMemoryEvidenceEntry& entry)
    {
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("PTE / VA 翻译详情"));
        document.field(QStringLiteral("VirtualAddress"), QStringLiteral("%1").arg(hex64(entry.virtualAddress)));
        document.field(QStringLiteral("RegionBaseAddress"), QStringLiteral("%1").arg(hex64(entry.regionBaseAddress)));
        document.field(QStringLiteral("RegionSize"), QStringLiteral("%1").arg(hex64(entry.regionSize)));
        document.field(QStringLiteral("Protect"), QStringLiteral("0x%1").arg(entry.protect, 8, 16, QChar('0')), true);
        document.field(QStringLiteral("State"), QStringLiteral("0x%1").arg(entry.state, 8, 16, QChar('0')), true);
        document.field(QStringLiteral("Type"), QStringLiteral("0x%1").arg(entry.type, 8, 16, QChar('0')), true);
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
}

void MemoryDock::initializeProcessPteTranslateTab()
{
    // 输入：无，由 initializeTabs 调用。
    // 处理：构建 PTE / VA 翻译页，仅展示当前附加进程的只读工作集视图。
    // 返回：无。
    kLogEvent initEvent;
    info << initEvent
        << "[MemoryDock] initializeProcessPteTranslateTab: 构建 PTE / VA 翻译页面。"
        << eol;

    m_tabProcessPteTranslate = new QWidget(m_tabWidget);
    // 页面自带内部滚动壳：内容放不下时在页内滚动，不把 Dock 撑高。页面指针身份不变。
    QWidget* const tabContent = ks::ui::EnablePageInnerScroll(m_tabProcessPteTranslate);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // 第一层（动作行）：只放“点一下立刻有反馈”的动作与状态回显，
    // 采样口径全部下沉到第二层的“翻译参数”分组里。
    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(8);

    m_processPteTranslateRefreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), m_tabProcessPteTranslate);
    m_processPteTranslateRefreshButton->setToolTip(QStringLiteral("基于当前附加进程采集 PTE / VA 翻译证据"));
    m_processPteTranslateRefreshButton->setStyleSheet(buildBlueButtonStyle());

    // 竖线分隔符：把“执行动作”和“视图过滤”在视觉上切开，不再一排糊成一条。
    QFrame* actionSeparator = new QFrame(m_tabProcessPteTranslate);
    actionSeparator->setFrameShape(QFrame::VLine);
    actionSeparator->setFrameShadow(QFrame::Sunken);

    m_processPteTranslateRiskOnlyCheck = new QCheckBox(QStringLiteral("仅风险项"), m_tabProcessPteTranslate);
    m_processPteTranslateRiskOnlyCheck->setChecked(true);
    m_processPteTranslateRiskOnlyCheck->setToolTip(QStringLiteral("只保留风险判定不为正常的页记录"));
    m_processPteTranslateRiskOnlyCheck->setStyleSheet(QStringLiteral(
        "QCheckBox { color:%1; font-weight:600; }")
        .arg(KswordTheme::TextPrimaryHex()));

    m_processPteTranslateStatusLabel = new QLabel(QStringLiteral("状态：等待刷新"), m_tabProcessPteTranslate);
    m_processPteTranslateStatusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_processPteTranslateStatusLabel->setStyleSheet(QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    // 状态标签吃掉剩余宽度（stretch=1），长状态文本不会把左侧动作挤走。
    actionLayout->addWidget(m_processPteTranslateRefreshButton);
    actionLayout->addWidget(actionSeparator);
    actionLayout->addWidget(m_processPteTranslateRiskOnlyCheck);
    actionLayout->addWidget(m_processPteTranslateStatusLabel, 1);
    tabLayout->addLayout(actionLayout);

    // 第二层：采样参数分组，起点 VA 与采样页数各配一个文字标签，
    // 避免用户对着一个孤零零的“VA”缩写猜它到底要填什么。
    QGroupBox* translateParameterGroup = new QGroupBox(QStringLiteral("翻译参数"), m_tabProcessPteTranslate);
    QGridLayout* translateParameterLayout = new QGridLayout(translateParameterGroup);
    translateParameterLayout->setContentsMargins(10, 8, 10, 8);
    translateParameterLayout->setHorizontalSpacing(8);
    translateParameterLayout->setVerticalSpacing(6);

    // 参数名统一走次级文字色（动态 token，主题切换能跟随），与输入内容拉开主次。
    const QString parameterCaptionStyle =
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex());

    QLabel* addressCaption = new QLabel(QStringLiteral("起始虚拟地址"), translateParameterGroup);
    addressCaption->setStyleSheet(parameterCaptionStyle);

    m_processPteTranslateAddressEdit = new QLineEdit(translateParameterGroup);
    m_processPteTranslateAddressEdit->setClearButtonEnabled(true);
    m_processPteTranslateAddressEdit->setPlaceholderText(QStringLiteral("输入 VA，例如 0x7FF6..."));
    m_processPteTranslateAddressEdit->setToolTip(QStringLiteral("采样起点虚拟地址，留空则沿用查看器当前地址"));
    m_processPteTranslateAddressEdit->setStyleSheet(buildBlueInputStyle());

    QLabel* pageCountCaption = new QLabel(QStringLiteral("采样页数"), translateParameterGroup);
    pageCountCaption->setStyleSheet(parameterCaptionStyle);

    m_processPteTranslatePageCountSpin = new QSpinBox(translateParameterGroup);
    m_processPteTranslatePageCountSpin->setRange(1, 256);
    m_processPteTranslatePageCountSpin->setValue(16);
    m_processPteTranslatePageCountSpin->setToolTip(QStringLiteral("每次采样的页数上限"));

    // 网格布局：第 1 列留给可拉伸的 VA 输入框，页数控件保持自然宽度贴在右侧。
    translateParameterLayout->addWidget(addressCaption, 0, 0);
    translateParameterLayout->addWidget(m_processPteTranslateAddressEdit, 0, 1);
    translateParameterLayout->addWidget(pageCountCaption, 0, 2);
    translateParameterLayout->addWidget(m_processPteTranslatePageCountSpin, 0, 3);
    translateParameterLayout->setColumnStretch(1, 1);
    tabLayout->addWidget(translateParameterGroup);

    QSplitter* splitter = new QSplitter(Qt::Vertical, m_tabProcessPteTranslate);
    tabLayout->addWidget(splitter, 1);

    m_processPteTranslateTable = new ks::ui::VisibleTableWidget(splitter);
    m_processPteTranslateTable->setColumnCount(pteTranslateColumnIndex(PteTranslateColumn::Count));
    m_processPteTranslateTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("VA"),
        QStringLiteral("区域基址"),
        QStringLiteral("有效"),
        QStringLiteral("共享"),
        QStringLiteral("锁定"),
        QStringLiteral("大页"),
        QStringLiteral("坏页"),
        QStringLiteral("ShareCount"),
        QStringLiteral("Win32Prot"),
        QStringLiteral("Node"),
        QStringLiteral("映射文件"),
        QStringLiteral("风险")
    });
    m_processPteTranslateTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_processPteTranslateTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_processPteTranslateTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_processPteTranslateTable->setAlternatingRowColors(true);
    m_processPteTranslateTable->setSortingEnabled(true);
    m_processPteTranslateTable->verticalHeader()->setVisible(false);
    m_processPteTranslateTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_processPteTranslateTable->horizontalHeader()->setSectionResizeMode(pteTranslateColumnIndex(PteTranslateColumn::MappedFile), QHeaderView::Stretch);
    installPteCopyMenu(m_processPteTranslateTable);
    splitter->addWidget(m_processPteTranslateTable);

    m_processPteTranslateDetailEditor = new ks::ui::StructuredFieldView(splitter);
    m_processPteTranslateDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择一条 PTE / VA 翻译记录查看详情。")));
    splitter->addWidget(m_processPteTranslateDetailEditor);

    ks::ui::DetailLayoutRegistry::registerStructuredHost(
        m_processPteTranslateTable,
        m_processPteTranslateDetailEditor,
        m_tabProcessPteTranslate);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    m_tabWidget->addTab(m_tabProcessPteTranslate, QStringLiteral("PTE / VA 翻译"));
}

void MemoryDock::refreshProcessPteTranslateAsync()
{
    // 输入：无，由刷新按钮或 tab 路由触发。
    // 处理：基于当前附加进程和输入 VA 采样 QueryWorkingSetEx / VirtualQueryEx 结果。
    // 返回：无。
    if (m_processPteTranslateRefreshInProgress.exchange(true))
    {
        return;
    }

    kLogEvent refreshEvent;
    info << refreshEvent
        << "[MemoryDock] refreshProcessPteTranslateAsync: 开始解析页表，刷新按钮已置灰。"
        << eol;

    // 进入采集前先把反馈给足：按钮压灰防重复点击，状态标签明确写“正在解析页表…”。
    if (m_processPteTranslateRefreshButton != nullptr)
    {
        m_processPteTranslateRefreshButton->setEnabled(false);
    }
    if (m_processPteTranslateStatusLabel != nullptr)
    {
        m_processPteTranslateStatusLabel->setText(QStringLiteral("状态：正在解析页表…"));
        m_processPteTranslateStatusLabel->setStyleSheet(
            QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::PrimaryBlueHex));
    }

    if (m_attachedProcessHandle == nullptr || m_attachedPid == 0U)
    {
        // 未附加就直接退出：上面已经压灰了按钮，这里必须把它放回来，否则页面永远点不动。
        m_processPteTranslateRefreshInProgress.store(false);
        if (m_processPteTranslateRefreshButton != nullptr)
        {
            m_processPteTranslateRefreshButton->setEnabled(true);
        }
        if (m_processPteTranslateStatusLabel != nullptr)
        {
            m_processPteTranslateStatusLabel->setText(QStringLiteral("状态：请先附加进程。"));
            m_processPteTranslateStatusLabel->setStyleSheet(
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
        m_processPteTranslateRefreshInProgress.store(false);
        if (m_processPteTranslateRefreshButton != nullptr)
        {
            m_processPteTranslateRefreshButton->setEnabled(true);
        }
        if (m_processPteTranslateStatusLabel != nullptr)
        {
            m_processPteTranslateStatusLabel->setText(
                QStringLiteral("状态：复制进程句柄失败（Win32=%1）。").arg(duplicateError));
            m_processPteTranslateStatusLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;")
                    .arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
        }
        return;
    }

    // 按钮与状态已在函数入口统一置位，此处不再重复下发，直接取采样参数。
    std::uint64_t baseAddress = 0ULL;
    const QString addressText = m_processPteTranslateAddressEdit != nullptr
        ? m_processPteTranslateAddressEdit->text().trimmed() : QString();
    // 明确输入必须解析成功；仅空输入才借用当前工作台插入点，不回退旧页缓存或地址零。
    const auto workbenchAddress = addressText.isEmpty()
        ? workbenchFocusAddress() : std::optional<std::uint64_t>();
    const bool hasAddress = addressText.isEmpty()
        ? workbenchAddress.has_value() : parseAddressText(addressText, baseAddress);
    if (!hasAddress)
    {
        // 本次没有启动采样任务，立即恢复按钮和状态；复制句柄随局部租约正常关闭。
        m_processPteTranslateRefreshInProgress.store(false);
        if (m_processPteTranslateRefreshButton != nullptr)
        {
            m_processPteTranslateRefreshButton->setEnabled(true);
        }
        if (m_processPteTranslateStatusLabel != nullptr)
        {
            m_processPteTranslateStatusLabel->setText(QStringLiteral(
                "状态：请填写有效地址，或在内存工作台选择地址。"));
            m_processPteTranslateStatusLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;")
                    .arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
        }
        return;
    }
    if (workbenchAddress.has_value())
    {
        baseAddress = *workbenchAddress;
    }
    const std::uint32_t pageCount = m_processPteTranslatePageCountSpin != nullptr
        ? static_cast<std::uint32_t>(m_processPteTranslatePageCountSpin->value())
        : 16U;

    const std::uint64_t ticket = m_processPteTranslateRefreshTicket.fetch_add(1U) + 1U;
    const std::uint64_t attachmentGeneration = m_processAttachmentGeneration.load();
    const std::uint32_t pid = m_attachedPid;
    const QPointer<MemoryDock> guardThis(this);

    std::thread([guardThis,
                 processHandleLease,
                 ticket,
                 attachmentGeneration,
                 pid,
                 baseAddress,
                 pageCount]() {
        const HANDLE workerProcessHandle = static_cast<HANDLE>(processHandleLease.get());
        std::vector<ProcessMemoryEvidenceEntry> entries;
        entries.reserve(pageCount);

        MEMORY_BASIC_INFORMATION mbi{};
        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);
        const std::uint64_t pageSize = static_cast<std::uint64_t>(systemInfo.dwPageSize);
        const std::uint64_t alignedBase = pageSize == 0ULL ? baseAddress : (baseAddress / pageSize) * pageSize;

        for (std::uint32_t index = 0; index < pageCount; ++index)
        {
            const std::uint64_t va = alignedBase + (static_cast<std::uint64_t>(index) * pageSize);
            if (va < alignedBase)
            {
                break;
            }

            if (::VirtualQueryEx(
                    workerProcessHandle,
                    reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(va)),
                    &mbi,
                    sizeof(mbi)) != sizeof(mbi))
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
            entry.regionBaseAddress = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            entry.regionSize = static_cast<std::uint64_t>(mbi.RegionSize);
            entry.protect = static_cast<std::uint32_t>(mbi.Protect);
            entry.state = static_cast<std::uint32_t>(mbi.State);
            entry.type = static_cast<std::uint32_t>(mbi.Type);
            entry.mappedFilePath = mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED
                ? QStringLiteral("")
                : QString();

            if (queryOk != FALSE)
            {
                const auto flags = wsInfo.VirtualAttributes.Flags;
                entry.valid = wsInfo.VirtualAttributes.Valid != 0;
                entry.shareCount = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.ShareCount);
                entry.win32Protection = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.Win32Protection);
                entry.shared = wsInfo.VirtualAttributes.Shared != 0;
                entry.node = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.Node);
                entry.locked = wsInfo.VirtualAttributes.Locked != 0;
                entry.largePage = wsInfo.VirtualAttributes.LargePage != 0;
                entry.bad = wsInfo.VirtualAttributes.Bad != 0;
                Q_UNUSED(flags);
            }

            entry.riskText = buildPteRiskText(entry.protect, entry.valid, entry.bad, entry.largePage);
            entry.detailText = QStringLiteral("PID=%1 | VA=%2 | Base=%3 | Size=%4")
                .arg(pid)
                .arg(hex64(entry.virtualAddress))
                .arg(hex64(entry.regionBaseAddress))
                .arg(hex64(entry.regionSize));
            entries.push_back(std::move(entry));
        }

        QMetaObject::invokeMethod(
            qApp,
            [guardThis, ticket, attachmentGeneration, entries = std::move(entries)]() mutable {
                if (guardThis == nullptr) return;
                auto entriesSnapshot =
                    std::make_shared<std::vector<ProcessMemoryEvidenceEntry>>(std::move(entries));
                auto commitSnapshot = [guardThis, ticket, attachmentGeneration, entriesSnapshot]() mutable
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    // 无论快照是否过期，回到主线程就先把“刷新中”状态拆掉：
                    // 旧写法把恢复放在 ticket 校验之后，一旦重新附加进程就会把按钮永久压灰。
                    guardThis->m_processPteTranslateRefreshInProgress.store(false);
                    if (guardThis->m_processPteTranslateRefreshButton != nullptr)
                    {
                        guardThis->m_processPteTranslateRefreshButton->setEnabled(true);
                    }

                    if (ticket != guardThis->m_processPteTranslateRefreshTicket.load() ||
                        attachmentGeneration != guardThis->m_processAttachmentGeneration.load())
                    {
                        return;
                    }

                    guardThis->m_processPteTranslateCache = std::move(*entriesSnapshot);
                    guardThis->rebuildProcessPteTranslateTable();
                    guardThis->showProcessPteTranslateDetailByCurrentRow();

                    if (guardThis->m_processPteTranslateStatusLabel != nullptr)
                    {
                        guardThis->m_processPteTranslateStatusLabel->setText(
                            QStringLiteral("状态：采样 %1 行").arg(guardThis->m_processPteTranslateCache.size()));
                        guardThis->m_processPteTranslateStatusLabel->setStyleSheet(QStringLiteral(
                            "color:%1; font-weight:600;")
                            .arg(guardThis->m_processPteTranslateCache.empty()
                                ? KswordTheme::ErrorColor().name(QColor::HexRgb)
                                : KswordTheme::SuccessColor().name(QColor::HexRgb)));
                    }
                };

                if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                    guardThis.data(),
                    QStringLiteral("memory-process-pte-snapshot"),
                    { guardThis->m_processPteTranslateTable },
                    commitSnapshot))
                {
                    return;
                }
                commitSnapshot();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MemoryDock::rebuildProcessPteTranslateTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_processPteTranslateDetailEditor);
    // 输入：读取当前缓存和风险过滤开关。
    // 处理：把 Tab9 缓存投影到表格并保留排序友好数值列。
    // 返回：无。
    if (m_processPteTranslateTable == nullptr)
    {
        return;
    }

    const bool riskOnly = m_processPteTranslateRiskOnlyCheck != nullptr && m_processPteTranslateRiskOnlyCheck->isChecked();
    std::vector<const ProcessMemoryEvidenceEntry*> visibleEntries;
    visibleEntries.reserve(m_processPteTranslateCache.size());
    for (const ProcessMemoryEvidenceEntry& entry : m_processPteTranslateCache)
    {
        if (riskOnly && entry.riskText == QStringLiteral("正常"))
        {
            continue;
        }
        visibleEntries.push_back(&entry);
    }

    // 批量填表前先关排序：否则每写一格 Qt 就重排一次，既慢又会把行号敲乱。
    m_processPteTranslateVisibleCount = visibleEntries.size();
    const QSignalBlocker blocker(m_processPteTranslateTable);
    m_processPteTranslateTable->setSortingEnabled(false);
    m_processPteTranslateTable->setRowCount(static_cast<int>(visibleEntries.size()));
    for (int row = 0; row < static_cast<int>(visibleEntries.size()); ++row)
    {
        const ProcessMemoryEvidenceEntry& entry = *visibleEntries[static_cast<std::size_t>(row)];
        // 地址列：显示 16 进制文本，排序走真实 64 位数值，不会退化成字符串序。
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::VirtualAddress), new ks::ui::NumericTableItem(hex64(entry.virtualAddress), static_cast<qulonglong>(entry.virtualAddress)));
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::RegionBase), new ks::ui::NumericTableItem(hex64(entry.regionBaseAddress), static_cast<qulonglong>(entry.regionBaseAddress)));
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::Valid), makeReadOnlyItem(entry.valid ? QStringLiteral("Yes") : QStringLiteral("No")));
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::Shared), makeReadOnlyItem(entry.shared ? QStringLiteral("Yes") : QStringLiteral("No")));
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::Locked), makeReadOnlyItem(entry.locked ? QStringLiteral("Yes") : QStringLiteral("No")));
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::LargePage), makeReadOnlyItem(entry.largePage ? QStringLiteral("Yes") : QStringLiteral("No")));
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::Bad), makeReadOnlyItem(entry.bad ? QStringLiteral("Yes") : QStringLiteral("No")));
        // 引用计数、保护属性位图、NUMA 节点同样是数值列，一律挂 NumericSortRole。
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::ShareCount), new ks::ui::NumericTableItem(QString::number(entry.shareCount), static_cast<qulonglong>(entry.shareCount)));
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::Win32Protection), new ks::ui::NumericTableItem(QStringLiteral("0x%1").arg(entry.win32Protection, 8, 16, QChar('0')).toUpper(), static_cast<qulonglong>(entry.win32Protection)));
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::Node), new ks::ui::NumericTableItem(QString::number(entry.node), static_cast<qulonglong>(entry.node)));
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::MappedFile), makeReadOnlyItem(entry.mappedFilePath.isEmpty() ? QStringLiteral("—") : entry.mappedFilePath));
        m_processPteTranslateTable->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::Risk), makeReadOnlyItem(entry.riskText));
    }
    if (visibleEntries.empty())
    {
        const QString detailText = m_processPteTranslateCache.empty()
            ? QStringLiteral("PTE / VA 翻译当前没有缓存行；请先附加进程、输入或定位 VA 后刷新。")
            : QStringLiteral("当前风险过滤隐藏了全部 %1 条 PTE / VA 翻译记录；请关闭“仅风险项”。")
                .arg(static_cast<qulonglong>(m_processPteTranslateCache.size()));
        setPteDiagnosticRow(m_processPteTranslateTable, detailText);
    }

    if (m_processPteTranslateTable->rowCount() > 0 && m_processPteTranslateTable->currentRow() < 0)
    {
        m_processPteTranslateTable->setCurrentCell(0, pteTranslateColumnIndex(PteTranslateColumn::VirtualAddress));
    }
    // 填表完毕再把排序打开，与上面的 setSortingEnabled(false) 成对包夹。
    m_processPteTranslateTable->setSortingEnabled(true);
    ks::ui::RequestTableColumnAutoFit(m_processPteTranslateTable);
}

void MemoryDock::showProcessPteTranslateDetailByCurrentRow()
{
    // 输入：无，读取当前表格选中行。
    // 处理：从缓存中展开当前记录到 StructuredFieldView。
    // 返回：无。
    if (m_processPteTranslateDetailEditor == nullptr || m_processPteTranslateTable == nullptr)
    {
        return;
    }

    const int row = m_processPteTranslateTable->currentRow();
    if (row < 0 || row >= m_processPteTranslateTable->rowCount())
    {
        m_processPteTranslateDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择一条 PTE / VA 翻译记录查看详情。")));
        return;
    }

    const QTableWidgetItem* addressItem = m_processPteTranslateTable->item(row, pteTranslateColumnIndex(PteTranslateColumn::VirtualAddress));
    if (addressItem == nullptr)
    {
        m_processPteTranslateDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前记录的缓存已失效，请刷新后重试。")));
        return;
    }
    const QString diagnosticText = addressItem->data(Qt::UserRole + 2).toString();
    if (!diagnosticText.isEmpty())
    {
        m_processPteTranslateDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("PTE / VA 翻译诊断\n%1").arg(diagnosticText)));
        return;
    }

    // 反查键跟着填表侧一起迁到 NumericSortRole：
    // NumericTableItem 把真实数值写在 Qt::UserRole + 900，再读 Qt::UserRole 会永远取不到值。
    bool ok = false;
    const qulonglong addressValue = addressItem->data(ks::ui::NumericSortRole).toULongLong(&ok);
    if (!ok)
    {
        m_processPteTranslateDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前记录的缓存已失效，请刷新后重试。")));
        return;
    }

    for (const ProcessMemoryEvidenceEntry& entry : m_processPteTranslateCache)
    {
        if (entry.virtualAddress == static_cast<std::uint64_t>(addressValue))
        {
            m_processPteTranslateDetailEditor->setDocument(buildPteDetailDocument(entry));
            return;
        }
    }
    m_processPteTranslateDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前记录的缓存已失效，请刷新后重试。")));
}
