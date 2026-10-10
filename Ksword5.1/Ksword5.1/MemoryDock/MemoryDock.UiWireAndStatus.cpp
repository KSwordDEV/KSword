#include "MemoryDock.Internal.h"
#include "../UI/ToolbarMetrics.h"
#include "SystemMemoryAuditPage.h"
#include "../UI/X64DbgNavigation.h"
#include "../UI/MemoryWorkbench/MemoryWorkbenchView.h"
#include "../UI/MemoryWorkbench/WorkbenchTarget.h"

// 说明：由原聚合式实现迁移为独立 .cpp，成员函数实现保持原样。
using namespace ksword::memory_dock_internal;

// ============================================================
// MemoryDock.UiWireAndStatus.cpp
// 作用：承载信号槽连接与状态栏/定时器初始化代码。
// ============================================================

namespace
{
    // memoryTableRowText 作用：
    // - 输入：MemoryDock 中的普通表格和目标行号；
    // - 处理：按当前列顺序读取文本并使用 TSV 拼接；
    // - 返回：可直接写入剪贴板的整行文本。
    QString memoryTableRowText(QTableWidget* table, const int rowIndex)
    {
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

    // copyMemoryTableRow 作用：
    // - 输入：MemoryDock 表格和目标行号；
    // - 处理：复制当前行全部列，包含隐藏列，便于审计时保留 PID/会话等上下文；
    // - 返回：无，剪贴板不可用或行无效时静默返回。
    void copyMemoryTableRow(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const QString rowText = memoryTableRowText(table, rowIndex);
        if (!rowText.isEmpty())
        {
            QApplication::clipboard()->setText(rowText);
        }
    }

    // copyMemoryTreeRow 作用：
    // - 输入：模块树和当前节点；
    // - 处理：复制当前节点所有列，保持和模块表可见字段一致；
    // - 返回：无，剪贴板不可用或节点为空时直接返回。
    void copyMemoryTreeRow(QTreeWidget* tree, QTreeWidgetItem* item)
    {
        if (tree == nullptr || item == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        QStringList fields;
        fields.reserve(tree->columnCount());
        for (int columnIndex = 0; columnIndex < tree->columnCount(); ++columnIndex)
        {
            fields.push_back(item->text(columnIndex));
        }
        QApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }
}

void MemoryDock::initializeConnections()
{
    // 信号槽连接日志：用于确认所有交互通道都已挂接。
    kLogEvent connectInitEvent;
    info << connectInitEvent
        << "[MemoryDock] initializeConnections: 开始连接全部信号槽。"
        << eol;

    // ========================================================
    // 工具栏逻辑
    // ========================================================

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        // 刷新动作按当前页签的"页面控件"路由（而不是数字下标），减少无关页面刷新开销；
        // 这样日后在页签中间插入新页，刷新钮也不会错位到相邻的页面。
        // currentPage：当前选中页签对应的页面控件；没有任何页签时为空指针。
        QWidget* const currentPage = m_tabWidget->currentWidget();
        // tabIndex：当前页签下标，只用于下面的日志，不参与路由判断。
        const int tabIndex = m_tabWidget->currentIndex();
        kLogEvent refreshClickEvent;
        info << refreshClickEvent
            << "[MemoryDock] 点击刷新按钮, 当前Tab索引="
            << tabIndex
            << ", attachedPid="
            << m_attachedPid
            << eol;
        // 没有任何页签时没有可刷新的页面；同时避免"空指针 == 尚未创建的页面成员(空指针)"的误匹配。
        if (currentPage == nullptr)
        {
            return;
        }
        if (currentPage == m_systemMemoryAuditPage)
        {
            m_systemMemoryAuditPage->refreshSnapshot();
            return;
        }
        // 进程与模块页：刷新进程列表，已附加时顺带刷新该进程的模块列表。
        if (currentPage == m_tabProcessModule)
        {
            refreshProcessList(true);
            if (m_attachedPid != 0)
            {
                refreshModuleListForPid(m_attachedPid);
            }
            return;
        }
        // 内存区域页：重新枚举内存区域。
        if (currentPage == m_tabRegions)
        {
            refreshMemoryRegionList(true);
            return;
        }
        // 内存搜索页：沿用原有行为，同样刷新内存区域列表。
        if (currentPage == m_tabSearch)
        {
            refreshMemoryRegionList(true);
            return;
        }
        // 唯一内存工作台：软重读保留当前目标、暂存补丁与撤销历史。
        if (currentPage == m_tabWorkbench)
        {
            ensureWorkbenchView();
            if (m_workbenchView != nullptr)
            {
                m_workbenchView->target().requestReload();
            }
            return;
        }
        // 内核可执行页：异步重新扫描。
        if (currentPage == m_tabKernelExecutableMemory)
        {
            refreshKernelExecutableMemoryScanAsync();
            return;
        }
        // 内核内存证据页：异步刷新证据。
        if (currentPage == m_tabKernelMemoryEvidence)
        {
            refreshKernelMemoryEvidenceAsync();
            return;
        }
        // PTE / VA 翻译页：异步重新翻译。
        if (currentPage == m_tabProcessPteTranslate)
        {
            refreshProcessPteTranslateAsync();
            return;
        }
        // 进程内存证据页：异步刷新证据。
        if (currentPage == m_tabProcessMemoryEvidence)
        {
            refreshProcessMemoryEvidenceAsync();
        }
        });

    connect(m_tabWidget, &QTabWidget::currentChanged, this, [this](int) {
        if (m_tabWidget->currentWidget() == m_systemMemoryAuditPage)
        {
            m_systemMemoryAuditPage->refreshSnapshot();
        }
        });

    // 下拉框上滚动滚轮会逐项连发 currentIndexChanged，每一项都直接开一轮模块枚举
    // 会瞬间堆出几十个后台任务并把主线程淹没在回投里；这里统一做一次去抖。
    m_processComboChangeTimer = new QTimer(this);
    m_processComboChangeTimer->setSingleShot(true);
    m_processComboChangeTimer->setInterval(200);
    connect(m_processComboChangeTimer, &QTimer::timeout, this, [this]() {
        refreshModuleListForPid(m_pendingModuleRefreshPid);
        });

    connect(m_processCombo, &QComboBox::currentIndexChanged, this, [this](int indexValue) {
        // 顶部进程切换时只刷新模块预览，不自动附加。
        if (indexValue < 0)
        {
            return;
        }
        const std::uint32_t pid = static_cast<std::uint32_t>(
            m_processCombo->itemData(indexValue, Qt::UserRole).toUInt());
        kLogEvent processComboEvent;
        dbg << processComboEvent
            << "[MemoryDock] 进程下拉框切换, index="
            << indexValue
            << ", pid="
            << pid
            << eol;
        m_pendingModuleRefreshPid = pid;
        m_processComboChangeTimer->start();

        // 选中的进程存在同名兄弟时，把用户带到 Tab1 并按这个名字过滤。
        // 理由：同名进程在下拉里只有一行文本，看不出该选哪个；而 Tab1 的进程表
        // 有图标、工作集、CPU、会话，还能按列排序——真正能做出选择的信息都在那里。
        // 只在同名 > 1 时触发：唯一进程没有可选的余地，这时抢走当前页面纯属打扰。
        const QString selectedName =
            m_processCombo->itemData(indexValue, Qt::UserRole + 1).toString();
        int sameNameCount = 0;
        for (const ProcessEntry& entry : m_processCache)
        {
            if (entry.processName.compare(selectedName, Qt::CaseInsensitive) == 0)
            {
                ++sameNameCount;
            }
        }
        if (sameNameCount > 1
            && m_processFilterEdit != nullptr
            && m_tabWidget != nullptr
            && m_processTable != nullptr)
        {
            // setText 会触发 textChanged，过滤由那条连接完成，这里不重复调用。
            m_processFilterEdit->setText(selectedName);
            m_tabWidget->setCurrentWidget(m_tabProcessModule);

            // 把下拉里选中的那一个在表里也选上并滚到可见处，两边保持一致；
            // 用户接着在同名的几行之间上下比较即可，双击任意一行就附加。
            const QString pidText = QString::number(pid);
            for (int row = 0; row < m_processTable->rowCount(); ++row)
            {
                const QTableWidgetItem* const pidItem = m_processTable->item(row, 1);
                if (pidItem != nullptr && pidItem->text() == pidText)
                {
                    m_processTable->selectRow(row);
                    m_processTable->scrollToItem(
                        m_processTable->item(row, 0), QAbstractItemView::PositionAtCenter);
                    break;
                }
            }
        }
        });

    // 十字准星拾取：拖到目标窗口松手，直接按窗口归属的 PID 附加。
    // 拾取结果不经过下拉框的当前选择：下拉框的内容是一份可能已经过期的快照，
    // 而窗口归属是此刻现问出来的，两者不一致时应当以后者为准。附加成功后再把
    // 下拉框对齐过去，让界面上显示的目标与实际附加的一致。
    connect(m_processPickerButton, &ks::ui::WindowPickerButton::processPicked, this,
        [this](const quint32 pickedPid, const QString& pickedName) {
            if (pickedPid == 0)
            {
                m_processPickerHintLabel->setText(
                    QStringLiteral("没拾到窗口：落点上没有其它程序的窗口。"));
                return;
            }
            kLogEvent pickEvent;
            info << pickEvent
                << "[MemoryDock] 窗口拾取附加, pid="
                << pickedPid
                << ", name="
                << pickedName.toStdString()
                << eol;
            m_processPickerHintLabel->setText(
                QStringLiteral("已拾取 %1 [PID:%2]").arg(pickedName).arg(pickedPid));
            // 拾到的进程可能还不在下拉快照里（刚启动的程序），所以先刷新一次，
            // 再按 PID 附加。附加本身只认 PID，不依赖下拉框里有没有这一项。
            attachToProcess(static_cast<std::uint32_t>(pickedPid), pickedName, true);
            refreshProcessList(true);
        });

    connect(m_processPickerButton, &ks::ui::WindowPickerButton::hoverPreview, this,
        [this](const quint32 hoverPid, const QString& hoverName) {
            if (hoverPid == 0)
            {
                m_processPickerHintLabel->setText(QStringLiteral("拖到目标窗口上…"));
                return;
            }
            m_processPickerHintLabel->setText(
                QStringLiteral("%1 [PID:%2]").arg(hoverName).arg(hoverPid));
        });

    connect(m_processPickerButton, &ks::ui::WindowPickerButton::pickingChanged, this,
        [this](const bool picking) {
            m_processPickerHintLabel->setVisible(picking);
            if (picking)
            {
                m_processPickerHintLabel->setText(QStringLiteral("拖到目标窗口上…"));
            }
        });

    // 进程表过滤：进程名或 PID 任一命中即显示。只隐藏行、不重建表格，
    // 这样刷新与过滤互不干扰，也不会丢掉当前选中行。
    connect(m_processFilterEdit, &QLineEdit::textChanged, this, [this](const QString&) {
        applyProcessTableFilter();
        });

    connect(m_attachButton, &QPushButton::clicked, this, [this]() {
        const int comboIndex = m_processCombo->currentIndex();
        if (comboIndex < 0)
        {
            kLogEvent noSelectionEvent;
            warn << noSelectionEvent
                << "[MemoryDock] 点击附加但未选择进程。"
                << eol;
            QMessageBox::warning(this, "附加进程", "请先选择进程。");
            return;
        }
        const std::uint32_t pid = static_cast<std::uint32_t>(
            m_processCombo->itemData(comboIndex, Qt::UserRole).toUInt());
        const QString processName = m_processCombo->itemData(comboIndex, Qt::UserRole + 1).toString();
        kLogEvent attachClickEvent;
        info << attachClickEvent
            << "[MemoryDock] 点击附加按钮, pid="
            << pid
            << ", processName="
            << processName.toStdString()
            << eol;
        attachToProcess(pid, processName, true);
        });

    connect(m_detachButton, &QPushButton::clicked, this, [this]() {
        if (!workbenchAllowsProcessChange())
        {
            return;
        }
        kLogEvent detachClickEvent;
        info << detachClickEvent
            << "[MemoryDock] 点击分离按钮, currentPid="
            << m_attachedPid
            << eol;
        detachProcess();
        QMessageBox::information(this, "分离进程", "已分离当前进程。");
        });

    connect(m_settingsButton, &QPushButton::clicked, this, [this]() {
        kLogEvent settingsOpenEvent;
        info << settingsOpenEvent
            << "[MemoryDock] 打开扫描设置对话框, 当前线程数="
            << m_scanThreadCount
            << ", 当前块大小KB="
            << m_scanChunkSizeKB
            << eol;

        // 设置页面：允许调整扫描线程数和块大小（缓存大小近似）。
        QDialog dialog(this);
        dialog.setWindowTitle("内存扫描设置");
        QFormLayout* formLayout = new QFormLayout(&dialog);

        QSpinBox* threadSpin = new QSpinBox(&dialog);
        threadSpin->setRange(1, 32);
        threadSpin->setValue(static_cast<int>(m_scanThreadCount));

        QSpinBox* chunkSpin = new QSpinBox(&dialog);
        chunkSpin->setRange(64, 16384);
        chunkSpin->setValue(static_cast<int>(m_scanChunkSizeKB));
        chunkSpin->setSuffix(" KB");

        QPushButton* okButton = new QPushButton("确定", &dialog);
        QPushButton* cancelButton = new QPushButton("取消", &dialog);
        okButton->setStyleSheet(buildBlueButtonStyle());
        cancelButton->setStyleSheet(buildBlueButtonStyle());
        QHBoxLayout* buttonLayout = new QHBoxLayout();
        buttonLayout->addWidget(okButton);
        buttonLayout->addWidget(cancelButton);
        ks::ui::NormalizeToolbarRow(buttonLayout);

        formLayout->addRow("扫描线程数", threadSpin);
        formLayout->addRow("读取块大小", chunkSpin);
        formLayout->addRow(buttonLayout);

        connect(okButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);

        if (dialog.exec() == QDialog::Accepted)
        {
            m_scanThreadCount = static_cast<std::uint32_t>(threadSpin->value());
            m_scanChunkSizeKB = static_cast<std::uint32_t>(chunkSpin->value());
            m_scanStatusLabel->setText(
                QString("设置已更新：线程=%1, 块=%2KB")
                .arg(m_scanThreadCount)
                .arg(m_scanChunkSizeKB));

            kLogEvent settingsApplyEvent;
            info << settingsApplyEvent
                << "[MemoryDock] 扫描设置已更新, 线程数="
                << m_scanThreadCount
                << ", 块大小KB="
                << m_scanChunkSizeKB
                << eol;
        }
        else
        {
            kLogEvent settingsCancelEvent;
            dbg << settingsCancelEvent
                << "[MemoryDock] 扫描设置对话框取消。"
                << eol;
        }
        });

    // ========================================================
    // Tab1：进程与模块
    // ========================================================

    connect(m_processTable, &QTableWidget::cellClicked, this, [this](int row, int column) {
        Q_UNUSED(column);
        if (row < 0)
        {
            return;
        }

        // 注意：表格允许排序，row 可能不再对应 m_processCache 原始下标。
        // 因此这里改为“从单元格文本/数据反解 PID + 进程名”，保证绑定准确。
        const QTableWidgetItem* pidItem = m_processTable->item(row, 1);
        const QTableWidgetItem* nameItem = m_processTable->item(row, 0);
        if (pidItem == nullptr || nameItem == nullptr)
        {
            return;
        }

        bool pidOk = false;
        const std::uint32_t pid = pidItem->text().toUInt(&pidOk);
        if (!pidOk || pid == 0)
        {
            kLogEvent processClickParseFailEvent;
            warn << processClickParseFailEvent
                << "[MemoryDock] 进程表单击后 PID 解析失败, row="
                << row
                << eol;
            return;
        }

        kLogEvent processClickEvent;
        dbg << processClickEvent
            << "[MemoryDock] 进程表单击, row="
            << row
            << ", pid="
            << pid
            << eol;

        for (int index = 0; index < m_processCombo->count(); ++index)
        {
            if (m_processCombo->itemData(index, Qt::UserRole).toUInt() == pid)
            {
                m_processCombo->setCurrentIndex(index);
                break;
            }
        }
        refreshModuleListForPid(pid);
        });

    connect(m_processTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int column) {
        Q_UNUSED(column);
        if (row < 0)
        {
            return;
        }
        // 双击附加同样不能直接拿 row 索引缓存，需从当前表格行动态取值。
        const QTableWidgetItem* pidItem = m_processTable->item(row, 1);
        const QTableWidgetItem* nameItem = m_processTable->item(row, 0);
        if (pidItem == nullptr || nameItem == nullptr)
        {
            return;
        }
        bool pidOk = false;
        const std::uint32_t pid = pidItem->text().toUInt(&pidOk);
        if (!pidOk || pid == 0)
        {
            kLogEvent processDoubleClickParseFailEvent;
            warn << processDoubleClickParseFailEvent
                << "[MemoryDock] 进程表双击后 PID 解析失败, row="
                << row
                << eol;
            return;
        }
        kLogEvent processDoubleClickEvent;
        info << processDoubleClickEvent
            << "[MemoryDock] 进程表双击触发附加, row="
            << row
            << ", pid="
            << pid
            << ", processName="
            << nameItem->text().toStdString()
            << eol;
        attachToProcess(pid, nameItem->text(), true);
        });

    connect(m_processTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showProcessTableContextMenu(localPosition);
        });

    connect(m_moduleRefreshButton, &QPushButton::clicked, this, [this]() {
        // 模块刷新按钮：按当前下拉 PID 触发模块重载。
        const int comboIndex = m_processCombo->currentIndex();
        if (comboIndex < 0)
        {
            return;
        }
        const std::uint32_t pid = static_cast<std::uint32_t>(
            m_processCombo->itemData(comboIndex, Qt::UserRole).toUInt());
        kLogEvent moduleRefreshClickEvent;
        info << moduleRefreshClickEvent
            << "[MemoryDock] 点击模块刷新按钮, pid="
            << pid
            << eol;
        refreshModuleListForPid(pid);
        });

    connect(m_moduleSignatureCheck, &QCheckBox::toggled, this, [this](bool checked) {
        // 切换签名校验后立即重刷，确保列表状态与选项一致。
        const int comboIndex = m_processCombo->currentIndex();
        if (comboIndex < 0)
        {
            return;
        }
        const std::uint32_t pid = static_cast<std::uint32_t>(
            m_processCombo->itemData(comboIndex, Qt::UserRole).toUInt());
        kLogEvent moduleSignatureToggleEvent;
        info << moduleSignatureToggleEvent
            << "[MemoryDock] 模块签名校验选项变更, checked="
            << (checked ? "true" : "false")
            << ", pid="
            << pid
            << eol;
        refreshModuleListForPid(pid);
        });

    connect(m_moduleFilterEdit, &QLineEdit::textChanged, this, [this](const QString&) {
        // 过滤输入改为“只重绘缓存”，避免每敲一个字都重新做模块枚举和签名校验。
        kLogEvent moduleFilterEvent;
        dbg << moduleFilterEvent
            << "[MemoryDock] 模块过滤条件变化, filter="
            << m_moduleFilterEdit->text().trimmed().toStdString()
            << ", cacheCount="
            << m_moduleCache.size()
            << eol;

        rebuildModuleTableFromCache();
        if (m_moduleStatusLabel != nullptr)
        {
            m_moduleStatusLabel->setText(
                QString("● 模块:%1 显示:%2 (过滤)")
                .arg(m_moduleCache.size())
                .arg(m_moduleTable->topLevelItemCount()));
            if (!m_moduleRefreshInProgress.load())
            {
                m_moduleStatusLabel->setStyleSheet(
                    QStringLiteral("color:%1; font-weight:600;")
                        .arg(KswordTheme::SuccessColor().name(QColor::HexRgb)));
            }
        }
        });

    connect(m_moduleTable, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item, int column) {
        // 双击模块任意列时，按模块基址跳转到内存查看器。
        Q_UNUSED(column);
        if (item == nullptr)
        {
            return;
        }
        const std::uint64_t baseAddress = item->data(
            toModuleTreeColumnIndex(ModuleTreeColumn::Path),
            Qt::UserRole).toULongLong();
        kLogEvent moduleJumpEvent;
        info << moduleJumpEvent
            << "[MemoryDock] 模块表双击跳转查看器, address="
            << formatAddress(baseAddress).toStdString()
            << eol;
        jumpToModuleBase(baseAddress);
        });

    connect(m_moduleTable, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        QTreeWidgetItem* clickedItem = m_moduleTable->itemAt(localPosition);
        if (clickedItem == nullptr)
        {
            return;
        }
        m_moduleTable->setCurrentItem(clickedItem);

        const std::uint64_t baseAddress = clickedItem->data(
            toModuleTreeColumnIndex(ModuleTreeColumn::Path),
            Qt::UserRole).toULongLong();
        const QString baseText = formatAddress(baseAddress);

        QMenu menu(this);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        QAction* copyBaseAction = menu.addAction("复制基址");
        QAction* copyRowAction = menu.addAction("复制当前行");
        QAction* jumpViewerAction = menu.addAction("跳转到内存查看器");
        QAction* selectedAction = menu.exec(m_moduleTable->viewport()->mapToGlobal(localPosition));
        if (selectedAction == nullptr)
        {
            return;
        }

        if (selectedAction == copyBaseAction)
        {
            QApplication::clipboard()->setText(baseText);
            kLogEvent copyBaseEvent;
            dbg << copyBaseEvent
                << "[MemoryDock] 模块表右键复制基址, text="
                << baseText.toStdString()
                << eol;
            return;
        }
        if (selectedAction == copyRowAction)
        {
            copyMemoryTreeRow(m_moduleTable, clickedItem);
            kLogEvent copyRowEvent;
            dbg << copyRowEvent
                << "[MemoryDock] 模块表右键复制当前行, base="
                << baseText.toStdString()
                << eol;
            return;
        }
        if (selectedAction == jumpViewerAction)
        {
            kLogEvent contextJumpEvent;
            info << contextJumpEvent
                << "[MemoryDock] 模块表右键跳转查看器, address="
                << baseText.toStdString()
                << eol;
            jumpToModuleBase(baseAddress);
        }
        });

    // ========================================================
    // Tab2：内存区域
    // ========================================================

    const auto applyRegionFilter = [this]() {
        kLogEvent regionFilterToggleEvent;
        dbg << regionFilterToggleEvent
            << "[MemoryDock] 区域过滤条件变化, committedOnly="
            << (m_regionCommittedOnlyCheck->isChecked() ? "true" : "false")
            << ", imageOnly="
            << (m_regionImageOnlyCheck->isChecked() ? "true" : "false")
            << ", readableOnly="
            << (m_regionReadableOnlyCheck->isChecked() ? "true" : "false")
            << eol;
        applyRegionFilterAndRebuildTable();
        };
    connect(m_regionCommittedOnlyCheck, &QCheckBox::toggled, this, applyRegionFilter);
    connect(m_regionImageOnlyCheck, &QCheckBox::toggled, this, applyRegionFilter);
    connect(m_regionReadableOnlyCheck, &QCheckBox::toggled, this, applyRegionFilter);

    // 关键字过滤只重排已有缓存，不重新枚举，输入时即时生效。
    connect(m_regionFilterEdit, &QLineEdit::textChanged, this, [this](const QString&) {
        applyRegionFilterAndRebuildTable();
        });

    // 手动刷新会强制重新枚举一次区域，用于目标进程刚分配完内存的场景。
    connect(m_regionRefreshButton, &QPushButton::clicked, this, [this]() {
        kLogEvent regionRefreshClickEvent;
        info << regionRefreshClickEvent
            << "[MemoryDock] 内存区域页点击刷新。"
            << eol;
        refreshMemoryRegionList(true);
        });

    connect(m_regionTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int column) {
        Q_UNUSED(column);
        if (row < 0)
        {
            return;
        }
        const QString baseText = m_regionTable->item(row, 0) != nullptr
            ? m_regionTable->item(row, 0)->text()
            : QString();
        std::uint64_t baseAddress = 0;
        if (parseAddressText(baseText, baseAddress))
        {
            kLogEvent regionDoubleClickEvent;
            info << regionDoubleClickEvent
                << "[MemoryDock] 区域表双击跳转查看器, base="
                << formatAddress(baseAddress).toStdString()
                << eol;
            jumpToAddress(baseAddress);
        }
        });

    connect(m_regionTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        QTableWidgetItem* clickedItem = m_regionTable->itemAt(localPosition);
        if (clickedItem == nullptr)
        {
            return;
        }

        const int row = clickedItem->row();
        const QString baseText = m_regionTable->item(row, 0) != nullptr
            ? m_regionTable->item(row, 0)->text()
            : QString();

        m_regionTable->setCurrentCell(row, clickedItem->column());

        QMenu menu(this);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        QAction* viewAction = menu.addAction("查看此区域");
        QAction* r0ReadAction = menu.addAction("R0读取此区域");
        QAction* copyAction = menu.addAction("复制基址");
        QAction* copyRowAction = menu.addAction("复制当前行");
        QAction* searchAction = menu.addAction("搜索此区域");
        std::uint64_t navigationAddress = 0;
        FILETIME created{}, exited{}, kernel{}, user{};
        if (m_attachedPid != 0 && m_attachedProcessHandle != nullptr
            && GetProcessId(m_attachedProcessHandle) == m_attachedPid
            && GetProcessTimes(m_attachedProcessHandle, &created, &exited, &kernel, &user)
            && parseAddressText(baseText, navigationAddress))
        {
            const auto identity = (static_cast<quint64>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
            ks::ui::x64dbg_navigation::AddAction(&menu, this,
                {m_attachedPid, identity, navigationAddress, ks::ui::x64dbg_navigation::View::Dump});
        }
        QAction* selectedAction = menu.exec(m_regionTable->viewport()->mapToGlobal(localPosition));
        if (selectedAction == nullptr)
        {
            return;
        }

        if (selectedAction == copyAction)
        {
            QApplication::clipboard()->setText(baseText);
            kLogEvent regionCopyEvent;
            dbg << regionCopyEvent
                << "[MemoryDock] 区域表右键复制基址, text="
                << baseText.toStdString()
                << eol;
            return;
        }
        if (selectedAction == copyRowAction)
        {
            copyMemoryTableRow(m_regionTable, row);
            kLogEvent regionCopyRowEvent;
            dbg << regionCopyRowEvent
                << "[MemoryDock] 区域表右键复制当前行, row="
                << row
                << eol;
            return;
        }

        std::uint64_t baseAddress = 0;
        if (!parseAddressText(baseText, baseAddress))
        {
            return;
        }

        if (selectedAction == viewAction)
        {
            kLogEvent regionViewEvent;
            info << regionViewEvent
                << "[MemoryDock] 区域表右键查看区域, base="
                << formatAddress(baseAddress).toStdString()
                << eol;
            jumpToAddress(baseAddress);
            return;
        }
        if (selectedAction == r0ReadAction)
        {
            // R0 读取此区域：
            // - 输入：区域表当前行的 base/size UserRole；
            // - 处理：工作台路由开启时在内存工作台里用标准驱动通道打开区域起点；
            //   关闭时填充旧驱动读写页为“从区域基址向后读”，最多单次读取 4KB；
            // - 返回：无返回值，结果由工作台状态条或旧驱动读写页状态栏和 HexEditor 展示。
            const QTableWidgetItem* baseItem = m_regionTable->item(row, 0);
            const QTableWidgetItem* sizeItem = m_regionTable->item(row, 1);
            if (baseItem != nullptr && sizeItem != nullptr)
            {
                const std::uint64_t regionBase = baseItem->data(Qt::UserRole).toULongLong();
                const std::uint64_t regionSize = sizeItem->data(Qt::UserRole).toULongLong();
                const std::uint64_t bytesToRead = std::min<std::uint64_t>(
                    regionSize == 0ULL ? 4096ULL : regionSize,
                    4096ULL);
                kLogEvent regionR0ReadEvent;
                info << regionR0ReadEvent
                    << "[MemoryDock] 区域表右键R0读取区域, base="
                    << formatAddress(regionBase).toStdString()
                    << ", bytes="
                    << bytesToRead
                    << eol;
                viewRegionViaDriver(regionBase, bytesToRead);
            }
            return;
        }
        if (selectedAction == searchAction)
        {
            // 搜索此区域：切换到 Tab3 并填充起止地址。
            // 注意：区域表启用了排序，row 与 m_regionCache 下标不再等价。
            // 因此基于表格 item 的 UserRole 中缓存的 base/size 进行计算。
            const QTableWidgetItem* baseItem = m_regionTable->item(row, 0);
            const QTableWidgetItem* sizeItem = m_regionTable->item(row, 1);
            if (baseItem != nullptr && sizeItem != nullptr)
            {
                const std::uint64_t regionBase = baseItem->data(Qt::UserRole).toULongLong();
                const std::uint64_t regionSize = sizeItem->data(Qt::UserRole).toULongLong();
                if (regionSize > 0)
                {
                    const std::uint64_t regionEnd = regionBase + regionSize - 1;
                    kLogEvent regionSearchEvent;
                    info << regionSearchEvent
                        << "[MemoryDock] 区域表右键搜索区域, start="
                        << formatAddress(regionBase).toStdString()
                        << ", end="
                        << formatAddress(regionEnd).toStdString()
                        << eol;
                    m_searchRangeCombo->setCurrentIndex(1);
                    m_searchRangeStartEdit->setText(formatAddress(regionBase));
                    m_searchRangeEndEdit->setText(formatAddress(regionEnd));
                    m_tabWidget->setCurrentWidget(m_tabSearch);
                }
            }
        }
        });

    // ========================================================
    // Tab3：搜索
    // ========================================================

    connect(m_searchRangeCombo, &QComboBox::currentIndexChanged, this, [this](int indexValue) {
        const bool customRange = (indexValue == 1);
        m_searchRangeStartEdit->setEnabled(customRange);
        m_searchRangeEndEdit->setEnabled(customRange);
        kLogEvent rangeModeEvent;
        dbg << rangeModeEvent
            << "[MemoryDock] 搜索范围模式切换, index="
            << indexValue
            << ", customRange="
            << (customRange ? "true" : "false")
            << eol;
        });

    connect(m_nextScanCompareCombo, &QComboBox::currentIndexChanged, this, [this](int indexValue) {
        const auto compareMode = static_cast<SearchCompareMode>(
            m_nextScanCompareCombo->itemData(indexValue).toInt());
        const bool needValueInput = !(
            compareMode == SearchCompareMode::Changed ||
            compareMode == SearchCompareMode::Unchanged ||
            compareMode == SearchCompareMode::Increased ||
            compareMode == SearchCompareMode::Decreased);
        const bool needSecondValue = (compareMode == SearchCompareMode::Between);
        m_nextScanValueEdit->setEnabled(needValueInput);
        m_nextScanValueBEdit->setVisible(needSecondValue);
        kLogEvent compareModeEvent;
        dbg << compareModeEvent
            << "[MemoryDock] 再次扫描条件切换, mode="
            << static_cast<int>(compareMode)
            << ", needValue="
            << (needValueInput ? "true" : "false")
            << ", needValueB="
            << (needSecondValue ? "true" : "false")
            << eol;
        });

    connect(m_firstScanButton, &QPushButton::clicked, this, [this]() {
        kLogEvent firstScanClickEvent;
        info << firstScanClickEvent
            << "[MemoryDock] 点击首次扫描按钮。"
            << eol;
        startFirstScan();
        });
    connect(m_nextScanButton, &QPushButton::clicked, this, [this]() {
        kLogEvent nextScanClickEvent;
        info << nextScanClickEvent
            << "[MemoryDock] 点击再次扫描按钮。"
            << eol;
        startNextScan();
        });
    connect(m_resetScanButton, &QPushButton::clicked, this, [this]() {
        kLogEvent resetScanClickEvent;
        info << resetScanClickEvent
            << "[MemoryDock] 点击重置扫描按钮。"
            << eol;
        resetScanState();
        });
    connect(m_cancelScanButton, &QPushButton::clicked, this, [this]() {
        kLogEvent cancelScanClickEvent;
        warn << cancelScanClickEvent
            << "[MemoryDock] 点击取消扫描按钮。"
            << eol;
        cancelCurrentScan();
        });

    // 结果表启用了排序：表格的 row 与 m_searchResultCache 的下标不再等价（点表头排序后第 0 行
    // 不再是缓存里的第 0 条）。所以地址一律取自该行地址列单元格自带的数值（Qt::UserRole，
    // 重建结果表时写入），其余字段再按地址回查缓存。
    // searchRowAddress：读某一行的地址；传入 row 表格行；addressOut 地址输出；返回是否读到。
    const auto searchRowAddress = [this](const int row, std::uint64_t& addressOut) -> bool {
        if (row < 0 || row >= static_cast<int>(m_searchResultVisibleCount))
        {
            return false;
        }
        const QTableWidgetItem* const addressItem = m_searchResultTable->item(row, 0);
        if (addressItem == nullptr)
        {
            return false;
        }
        bool converted = false;
        const qulonglong value = addressItem->data(Qt::UserRole).toULongLong(&converted);
        if (!converted)
        {
            return false;
        }
        addressOut = static_cast<std::uint64_t>(value);
        return true;
    };
    // findSearchEntry：按地址在可见缓存里回查结果行；找不到返回空指针。
    const auto findSearchEntry = [this](const std::uint64_t address) -> const SearchResultEntry* {
        const std::size_t visibleCount = std::min(m_searchResultVisibleCount, m_searchResultCache.size());
        for (std::size_t index = 0; index < visibleCount; ++index)
        {
            if (m_searchResultCache[index].address == address)
            {
                return &m_searchResultCache[index];
            }
        }
        return nullptr;
    };

    connect(m_searchResultTable, &QTableWidget::cellDoubleClicked, this, [this, searchRowAddress](int row, int column) {
        Q_UNUSED(column);
        std::uint64_t resultAddress = 0;
        if (!searchRowAddress(row, resultAddress))
        {
            return;
        }
        kLogEvent resultDoubleClickEvent;
        info << resultDoubleClickEvent
            << "[MemoryDock] 搜索结果双击跳转, row="
            << row
            << ", address="
            << formatAddress(resultAddress).toStdString()
            << eol;
        jumpToAddress(resultAddress);
        });

    connect(m_searchResultTable, &QTableWidget::customContextMenuRequested, this,
        [this, searchRowAddress, findSearchEntry](const QPoint& localPosition) {
        QTableWidgetItem* clickedItem = m_searchResultTable->itemAt(localPosition);
        if (clickedItem == nullptr)
        {
            return;
        }

        const int row = clickedItem->row();
        std::uint64_t rowAddress = 0;
        if (!searchRowAddress(row, rowAddress))
        {
            return;
        }

        m_searchResultTable->setCurrentCell(row, clickedItem->column());

        QMenu menu(this);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        QAction* viewAction = menu.addAction("查看此地址");
        // 地址簿入口：只有用户在这里明确点了才会加入，搜索结果从不自动灌入地址簿。
        QAction* addAddressBookAction = menu.addAction("加入地址簿");
        addAddressBookAction->setToolTip("把这一行的地址加入内存工作台的地址簿（种类：搜索结果，地址簿总数上限 10000）");
        QAction* addAllAddressBookAction = menu.addAction("全部加入地址簿");
        addAllAddressBookAction->setToolTip("把当前结果表显示的全部地址加入内存工作台的地址簿（总数上限 10000，已有的地址不重复加入）");
        // 工作台整体开关关闭时没有地方查看地址簿，这两项不提供。
        addAddressBookAction->setVisible(canOpenInWorkbench());
        addAllAddressBookAction->setVisible(canOpenInWorkbench());
        QAction* copyAddressAction = menu.addAction("复制地址");
        QAction* copyValueAction = menu.addAction("复制值");
        QAction* copyRowAction = menu.addAction("复制当前行");
        QAction* selectedAction = menu.exec(m_searchResultTable->viewport()->mapToGlobal(localPosition));
        if (selectedAction == nullptr)
        {
            return;
        }

        // 菜单是模态的：期间结果缓存可能被新一轮扫描重建，回查必须在菜单返回之后做，
        // 用 rowAddress（点击当时读到的地址）作键；缓存里已没有这个地址时按"该行已失效"处理。
        const SearchResultEntry* const foundEntry = findSearchEntry(rowAddress);
        if (selectedAction == addAddressBookAction)
        {
            addSearchResultsToAddressBook(std::vector<std::uint64_t>{ rowAddress });
            return;
        }
        if (selectedAction == addAllAddressBookAction)
        {
            // 全部可见行的地址取自表格自身（与用户看到的行一致，不依赖缓存下标）。
            std::vector<std::uint64_t> visibleAddresses;
            visibleAddresses.reserve(static_cast<std::size_t>(m_searchResultTable->rowCount()));
            for (int visibleRow = 0; visibleRow < m_searchResultTable->rowCount(); ++visibleRow)
            {
                std::uint64_t visibleAddress = 0;
                if (searchRowAddress(visibleRow, visibleAddress))
                {
                    visibleAddresses.push_back(visibleAddress);
                }
            }
            addSearchResultsToAddressBook(visibleAddresses);
            return;
        }
        if (foundEntry == nullptr)
        {
            // 地址仍在表格里但缓存已换代：只有"查看地址/复制地址"这类只需要地址的动作还能继续。
            if (selectedAction == viewAction)
            {
                jumpToAddress(rowAddress);
            }
            else if (selectedAction == copyAddressAction)
            {
                QApplication::clipboard()->setText(formatAddress(rowAddress));
            }
            else if (selectedAction == copyRowAction)
            {
                copyMemoryTableRow(m_searchResultTable, row);
            }
            return;
        }
        const SearchResultEntry& entry = *foundEntry;
        if (selectedAction == viewAction)
        {
            kLogEvent resultViewActionEvent;
            info << resultViewActionEvent
                << "[MemoryDock] 搜索结果右键查看地址, address="
                << formatAddress(entry.address).toStdString()
                << eol;
            jumpToAddress(entry.address);
            return;
        }
        if (selectedAction == copyAddressAction)
        {
            QApplication::clipboard()->setText(formatAddress(entry.address));
            kLogEvent resultCopyAddressEvent;
            dbg << resultCopyAddressEvent
                << "[MemoryDock] 搜索结果右键复制地址, address="
                << formatAddress(entry.address).toStdString()
                << eol;
            return;
        }
        if (selectedAction == copyValueAction)
        {
            QApplication::clipboard()->setText(
                bytesToDisplayString(entry.currentValueBytes, m_lastSearchValueType));
            kLogEvent resultCopyValueEvent;
            dbg << resultCopyValueEvent
                << "[MemoryDock] 搜索结果右键复制值, row="
                << row
                << eol;
            return;
        }
        if (selectedAction == copyRowAction)
        {
            copyMemoryTableRow(m_searchResultTable, row);
            kLogEvent resultCopyRowEvent;
            dbg << resultCopyRowEvent
                << "[MemoryDock] 搜索结果右键复制当前行, row="
                << row
                << eol;
        }
        });

    // ========================================================
    // Tab7：内核可执行页扫描
    // ========================================================

    connect(m_kernelExecutableRefreshButton, &QPushButton::clicked, this, [this]() {
        kLogEvent refreshKernelExecutableEvent;
        info << refreshKernelExecutableEvent
            << "[MemoryDock] 内核可执行页扫描点击刷新。"
            << eol;
        refreshKernelExecutableMemoryScanAsync();
        });

    connect(m_kernelExecutableRiskOnlyCheck, &QCheckBox::toggled, this, [this]() {
        rebuildKernelExecutableMemoryScanTable();
        showKernelExecutableMemoryDetailByCurrentRow();
        });

    connect(m_kernelExecutableModuleFilterEdit, &QLineEdit::textChanged, this, [this]() {
        rebuildKernelExecutableMemoryScanTable();
        showKernelExecutableMemoryDetailByCurrentRow();
        });

    connect(m_kernelExecutableTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showKernelExecutableMemoryDetailByCurrentRow();
        });

    // ========================================================
    // Tab8：内核内存证据
    // ========================================================

    connect(m_kernelMemoryEvidenceRefreshButton, &QPushButton::clicked, this, [this]() {
        kLogEvent refreshKernelMemoryEvidenceEvent;
        info << refreshKernelMemoryEvidenceEvent
            << "[MemoryDock] 内核内存证据点击刷新。"
            << eol;
        refreshKernelMemoryEvidenceAsync();
        });

    connect(m_kernelMemoryEvidenceRiskOnlyCheck, &QCheckBox::toggled, this, [this]() {
        rebuildKernelMemoryEvidenceTable();
        showKernelMemoryEvidenceDetailByCurrentRow();
        });

    connect(m_kernelMemoryEvidenceIncludeNonModuleCheck, &QCheckBox::toggled, this, [this]() {
        if (m_kernelMemoryEvidenceStatusLabel != nullptr)
        {
            m_kernelMemoryEvidenceStatusLabel->setText(QStringLiteral(
                "状态：非模块执行范围仅在填写起止地址后参与下一次刷新。"));
        }
        });

    connect(m_kernelMemoryEvidenceFilterEdit, &QLineEdit::textChanged, this, [this]() {
        rebuildKernelMemoryEvidenceTable();
        showKernelMemoryEvidenceDetailByCurrentRow();
        });

    connect(m_kernelMemoryEvidenceTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showKernelMemoryEvidenceDetailByCurrentRow();
        });

    // ========================================================
    // Tab9：PTE / VA 翻译
    // ========================================================

    connect(m_processPteTranslateRefreshButton, &QPushButton::clicked, this, [this]() {
        kLogEvent refreshPteTranslateEvent;
        info << refreshPteTranslateEvent
            << "[MemoryDock] PTE / VA 翻译点击刷新。"
            << eol;
        refreshProcessPteTranslateAsync();
        });

    connect(m_processPteTranslateRiskOnlyCheck, &QCheckBox::toggled, this, [this]() {
        rebuildProcessPteTranslateTable();
        showProcessPteTranslateDetailByCurrentRow();
        });

    connect(m_processPteTranslateAddressEdit, &QLineEdit::textChanged, this, [this]() {
        rebuildProcessPteTranslateTable();
        showProcessPteTranslateDetailByCurrentRow();
        });

    connect(m_processPteTranslatePageCountSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        rebuildProcessPteTranslateTable();
        showProcessPteTranslateDetailByCurrentRow();
        });

    connect(m_processPteTranslateTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showProcessPteTranslateDetailByCurrentRow();
        });

    // ========================================================
    // Tab10：进程内存证据
    // ========================================================

    connect(m_processMemoryEvidenceRefreshButton, &QPushButton::clicked, this, [this]() {
        kLogEvent refreshProcessMemoryEvidenceEvent;
        info << refreshProcessMemoryEvidenceEvent
            << "[MemoryDock] 进程内存证据点击刷新。"
            << eol;
        refreshProcessMemoryEvidenceAsync();
        });

    connect(m_processMemoryEvidenceRiskOnlyCheck, &QCheckBox::toggled, this, [this]() {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(m_processMemoryEvidenceImageOnlyCheck, &QCheckBox::toggled, this, [this]() {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(m_processMemoryEvidenceStartEdit, &QLineEdit::textChanged, this, [this]() {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(m_processMemoryEvidenceEndEdit, &QLineEdit::textChanged, this, [this]() {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(m_processMemoryEvidenceFilterEdit, &QLineEdit::textChanged, this, [this]() {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(m_processMemoryEvidenceMaxRowsSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(m_processMemoryEvidenceTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showProcessMemoryEvidenceDetailByCurrentRow();
        });
}

void MemoryDock::initializeStatusBar()
{
    // 初始化状态栏时输出日志，便于确认底部状态组件创建成功。
    kLogEvent statusBarInitEvent;
    info << statusBarInitEvent
        << "[MemoryDock] initializeStatusBar: 创建状态栏标签。"
        << eol;

    // 底部状态栏统一显示进程名、PID、读写能力。
    m_statusBar = new QStatusBar(this);
    m_statusBar->setSizeGripEnabled(false);

    m_statusProcessLabel = new QLabel("进程: 未附加", m_statusBar);
    m_statusPidLabel = new QLabel("PID: -", m_statusBar);
    m_statusMemoryIoLabel = new QLabel("读写状态: 未就绪", m_statusBar);
    m_statusBar->addPermanentWidget(m_statusProcessLabel, 1);
    m_statusBar->addPermanentWidget(m_statusPidLabel);
    m_statusBar->addPermanentWidget(m_statusMemoryIoLabel, 1);

    m_rootLayout->addWidget(m_statusBar);
}

void MemoryDock::initializeWorkbenchLivenessTimer()
{
    // 本定时器只驱动工作台目标存活核验，地址簿值读取由统一组件管理。
    m_workbenchLivenessTimer = new QTimer(this);
    m_workbenchLivenessTimer->setInterval(1000);
    m_workbenchLivenessTimer->start();
    // 视图与定时器创建顺序不固定，两处均通过幂等方法完成接线。
    connectWorkbenchLiveness();
}
