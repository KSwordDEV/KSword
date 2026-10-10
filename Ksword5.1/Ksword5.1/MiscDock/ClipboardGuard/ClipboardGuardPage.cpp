#include "ClipboardGuardPage.h"
#include "../../UI/ToolbarMetrics.h"
#include "../../UI/PrimaryPageStyle.h"
#include "../../UI/VisibleTableWidget.h"
#include "../../UI/FlatButtonTheme.h"
#include "../../theme.h"

#include <QAction>
#include <QCheckBox>
#include <QHBoxLayout>
#include <QBrush>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <array>

// ============================================================
// ClipboardGuardPage.cpp
// 作用：
// 1) 构造"剪贴板保护"页的控件树：规则表 + 事件表 + 工具栏；
// 2) 实现事件表 A/B 列组（概览 / 来源与诊断），照抄 ProcessDock 线程页的
//    ThreadColumnLayout 范式；
// 3) 表头右键菜单逐列勾选显示/隐藏。
// ============================================================

namespace ks::misc
{
    namespace
    {
        // buildToolButtonStyle：工具栏按钮统一外观，颜色取自当前主题。
        QString buildToolButtonStyle()
        {
            // 纯色主题只接管颜色；保留本页按钮尺寸和业务选中状态。
            return ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Neutral)
                + QStringLiteral("QPushButton{border-radius:4px;padding:4px 10px;}");

        }
    }

    ClipboardGuardPage::ClipboardGuardPage(QWidget* const parent)
        : QWidget(parent)
    {
        initializeUi();
        initializeConnections();
    }

    ClipboardGuardPage::~ClipboardGuardPage()
    {
        // 必须最先等 m_scanThreadPool 排空：refreshProcessListAndSessionsAsync 提交
        // 的后台任务会解引用 QPointer<ClipboardGuardPage>（非线程安全，只是靠"任务
        // 存活期间对象不会开始析构"这个前提保证它读到的值不被并发修改）。这里不等的话，
        // 任务里的 guardThis->ensureProcessProtected(...) 等调用可能正好撞上下面这些
        // 成员已经开始销毁的过程，是一个真实的 use-after-free。
        m_scanThreadPool.waitForDone();

        // 页面销毁前必须先让所有会话线程退场，否则线程回调里的 QPointer 判空
        // 之外还会残留没有 join 的 std::thread，析构 std::thread 会直接 terminate。
        std::vector<std::uint32_t> pidList;
        {
            std::lock_guard<std::mutex> lock(m_sessionsMutex);
            for (const std::unique_ptr<Session>& sessionPointer : m_sessions)
            {
                if (sessionPointer != nullptr)
                {
                    pidList.push_back(sessionPointer->pid);
                }
            }
        }
        for (const std::uint32_t pidValue : pidList)
        {
            teardownSession(pidValue);
        }
    }

    void ClipboardGuardPage::notifyPageActivated()
    {
        if (m_hasActivatedOnce)
        {
            return;
        }
        m_hasActivatedOnce = true;
        loadRulesFromDriver();
        refreshProcessListAndSessionsAsync();
        if (m_processPollTimer != nullptr)
        {
            m_processPollTimer->start();
        }
    }

    void ClipboardGuardPage::initializeUi()
    {
        m_rootLayout = new QVBoxLayout(this);
        m_rootLayout->setContentsMargins(6, 6, 6, 6);
        m_rootLayout->setSpacing(6);

        // ---- 工具栏 ----
        m_toolbarLayout = new QHBoxLayout();
        m_toolbarLayout->setContentsMargins(0, 0, 0, 0);
        m_toolbarLayout->setSpacing(8);

        m_addRuleButton = new QPushButton(QIcon(QStringLiteral(":/Icon/plus.svg")), QStringLiteral("添加进程规则"), this);
        m_addRuleButton->setToolTip(QStringLiteral("按进程名或完整路径新增一条剪贴板策略规则，规则会下发到驱动持久保存。"));
        m_addRuleButton->setStyleSheet(buildToolButtonStyle());

        m_removeRuleButton = new QPushButton(QIcon(QStringLiteral(":/Icon/log_clear.svg")), QStringLiteral("删除规则"), this);
        m_removeRuleButton->setToolTip(QStringLiteral("删除规则表里当前选中的一条规则。"));
        m_removeRuleButton->setStyleSheet(buildToolButtonStyle());

        m_refreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), this);
        m_refreshButton->setToolTip(QStringLiteral("立即重新扫描进程列表并按当前规则注入/移除保护，不必等待下一次自动轮询。"));
        m_refreshButton->setStyleSheet(buildToolButtonStyle());

        // 全局监控：勾选后新增一条 targetKind=ALL 的规则，覆盖系统上几乎全部
        // 进程；默认三个方向都只是"仅记录"，不新增任何拦截面，避免一勾选就
        // 打断全机复制粘贴。具体进程规则（PID/名称/路径）优先级更高，两者
        // 都命中时以具体规则的动作为准，见 findMatchingRule 的判定顺序。
        m_globalMonitorCheck = new QCheckBox(QStringLiteral("全局监控（记录所有进程的剪贴板访问）"), this);
        m_globalMonitorCheck->setToolTip(QStringLiteral(
            "注入到系统上几乎所有进程以观察剪贴板访问，事件表里能看到任意进程的读/写/枚举；"
            "默认只记录不拦截，需要拦截某个进程时仍然用规则表单独设置该进程的动作。"
            "注入的进程数量可能达到一两百个，会有一定性能开销。"));

        m_statusLabel = new QLabel(this);
        m_statusLabel->setText(QStringLiteral("尚未加载策略。"));

        m_toolbarLayout->addWidget(m_addRuleButton);
        m_toolbarLayout->addWidget(m_removeRuleButton);
        m_toolbarLayout->addWidget(m_refreshButton);
        m_toolbarLayout->addWidget(m_globalMonitorCheck);
        m_toolbarLayout->addStretch(1);
        m_toolbarLayout->addWidget(m_statusLabel);
        ks::ui::NormalizeToolbarRow(m_toolbarLayout);
        m_rootLayout->addLayout(m_toolbarLayout);

        // ---- 规则表：PID/映像/规则名/读/写/枚举/启用 ----
        m_ruleTable = new QTableWidget(0, 7, this);
        // 规则表是小型配置选择器，不需要快照与冻结操作栏。
        ks::ui::SetTableActionBarMode(m_ruleTable, ks::ui::TableActionBarMode::None);
        m_ruleTable->setHorizontalHeaderLabels({
            QStringLiteral("目标"), QStringLiteral("匹配方式"), QStringLiteral("规则名"),
            QStringLiteral("读"), QStringLiteral("写"), QStringLiteral("枚举"), QStringLiteral("启用") });
        m_ruleTable->horizontalHeader()->setStretchLastSection(false);
        m_ruleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_ruleTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_ruleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_ruleTable->setAlternatingRowColors(true);
        m_ruleTable->setMaximumHeight(160);
        m_rootLayout->addWidget(m_ruleTable, 0);
        // 静态策略和持续事件之间用留白区分，区内仍保持紧凑的操作/结果关系。
        m_rootLayout->addSpacing(8);

        // ---- 事件表工具栏：A/B 列组预设 ----
        QHBoxLayout* const eventTopLayout = new QHBoxLayout();
        eventTopLayout->setContentsMargins(0, 0, 0, 0);
        eventTopLayout->setSpacing(8);
        auto* eventSectionTitle = new QLabel(QStringLiteral("剪贴板访问事件："), this);
        ks::ui::StylePrimarySectionTitle(eventSectionTitle);
        eventTopLayout->addWidget(eventSectionTitle);

        m_columnPresetWidget = new QWidget(this);
        QHBoxLayout* const presetLayout = new QHBoxLayout(m_columnPresetWidget);
        presetLayout->setContentsMargins(0, 0, 0, 0);
        presetLayout->setSpacing(0);
        m_columnPresetAButton = new QPushButton(QStringLiteral("A"), m_columnPresetWidget);
        m_columnPresetBButton = new QPushButton(QStringLiteral("B"), m_columnPresetWidget);
        m_columnPresetAButton->setCheckable(true);
        m_columnPresetBButton->setCheckable(true);
        m_columnPresetAButton->setToolTip(QStringLiteral("列预设 A：概览（时间/进程/PID/操作/格式/结果）。"));
        m_columnPresetBButton->setToolTip(QStringLiteral("列预设 B：来源与诊断（时间/PID/TID/会话/完整性/发起进程/序号）。"));
        presetLayout->addWidget(m_columnPresetAButton);
        presetLayout->addWidget(m_columnPresetBButton);
        ks::ui::NormalizeToolbarRow(presetLayout, 0);
        eventTopLayout->addWidget(m_columnPresetWidget);
        eventTopLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(eventTopLayout);
        m_rootLayout->addLayout(eventTopLayout);

        // ---- 事件表 ----
        m_eventTable = new QTableWidget(0, ColumnCount, this);
        // 剪贴板事件已有时间序列与业务右键操作，保留紧凑复制导出。
        ks::ui::SetTableActionBarMode(m_eventTable, ks::ui::TableActionBarMode::Compact);
        m_eventTable->setHorizontalHeaderLabels({
            QStringLiteral("时间"), QStringLiteral("进程"), QStringLiteral("PID"), QStringLiteral("操作"),
            QStringLiteral("格式"), QStringLiteral("结果"), QStringLiteral("TID"), QStringLiteral("会话"),
            QStringLiteral("完整性"), QStringLiteral("发起进程"), QStringLiteral("序号") });
        m_eventTable->horizontalHeader()->setStretchLastSection(true);
        m_eventTable->horizontalHeader()->setSectionsMovable(true);
        m_eventTable->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);
        m_eventTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_eventTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_eventTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_eventTable->setAlternatingRowColors(true);
        m_eventTable->setContextMenuPolicy(Qt::CustomContextMenu);
        applyColumnLayout(ClipboardGuardColumnLayout::PresetA);
        m_rootLayout->addWidget(m_eventTable, 1);

        m_uiFlushTimer = new QTimer(this);
        m_uiFlushTimer->setInterval(200);

        m_processPollTimer = new QTimer(this);
        // 1 秒轮询：比初版的 2 秒更贴近"实时"，新启动的进程能更快被发现/注入；
        // 扫描本身在 QThreadPool 后台线程执行，缩短间隔不会卡 UI 线程，
        // 代价只是后台扫描更频繁（单次扫描本身通常在数十毫秒量级）。
        m_processPollTimer->setInterval(1000);
    }

    void ClipboardGuardPage::initializeConnections()
    {
        connect(m_addRuleButton, &QPushButton::clicked, this, &ClipboardGuardPage::openAddProcessRuleDialog);
        connect(m_removeRuleButton, &QPushButton::clicked, this, &ClipboardGuardPage::removeSelectedRule);
        connect(m_refreshButton, &QPushButton::clicked, this, &ClipboardGuardPage::refreshProcessListAndSessionsAsync);
        connect(m_globalMonitorCheck, &QCheckBox::toggled, this, &ClipboardGuardPage::toggleGlobalMonitor);
        connect(m_columnPresetAButton, &QPushButton::clicked, this, [this]() { applyColumnLayout(ClipboardGuardColumnLayout::PresetA); });
        connect(m_columnPresetBButton, &QPushButton::clicked, this, [this]() { applyColumnLayout(ClipboardGuardColumnLayout::PresetB); });
        connect(m_eventTable, &QWidget::customContextMenuRequested, this, &ClipboardGuardPage::showEventTableContextMenu);
        connect(m_eventTable->horizontalHeader(), &QWidget::customContextMenuRequested, this, &ClipboardGuardPage::showHeaderContextMenu);
        connect(m_uiFlushTimer, &QTimer::timeout, this, &ClipboardGuardPage::flushPendingRows);
        connect(m_processPollTimer, &QTimer::timeout, this, &ClipboardGuardPage::refreshProcessListAndSessionsAsync);
        m_uiFlushTimer->start();
    }

    void ClipboardGuardPage::applyColumnLayout(const ClipboardGuardColumnLayout layout)
    {
        if (m_eventTable == nullptr || layout == ClipboardGuardColumnLayout::Custom)
        {
            m_columnLayout = layout;
            updateColumnPresetButtons();
            return;
        }

        static constexpr std::array<int, 6> kPresetAColumns{
            ColumnTime, ColumnProcess, ColumnPid, ColumnOperation, ColumnFormat, ColumnResult
        };
        static constexpr std::array<int, 7> kPresetBColumns{
            ColumnTime, ColumnPid, ColumnTid, ColumnSession, ColumnIntegrity, ColumnOwner, ColumnSeq
        };
        const auto columnVisible = [layout](const int columnIndex) {
            if (layout == ClipboardGuardColumnLayout::PresetA)
            {
                return std::find(kPresetAColumns.cbegin(), kPresetAColumns.cend(), columnIndex) != kPresetAColumns.cend();
            }
            return std::find(kPresetBColumns.cbegin(), kPresetBColumns.cend(), columnIndex) != kPresetBColumns.cend();
        };

        m_applyingColumnLayout = true;
        for (int columnIndex = 0; columnIndex < static_cast<int>(ColumnCount); ++columnIndex)
        {
            m_eventTable->setColumnHidden(columnIndex, !columnVisible(columnIndex));
        }
        m_applyingColumnLayout = false;
        m_columnLayout = layout;
        updateColumnPresetButtons();
    }

    void ClipboardGuardPage::clearColumnPresetSelection()
    {
        if (m_applyingColumnLayout)
        {
            return;
        }
        m_columnLayout = ClipboardGuardColumnLayout::Custom;
        updateColumnPresetButtons();
    }

    void ClipboardGuardPage::updateColumnPresetButtons()
    {
        if (m_columnPresetAButton == nullptr || m_columnPresetBButton == nullptr)
        {
            return;
        }
        const QSignalBlocker blockerA(m_columnPresetAButton);
        const QSignalBlocker blockerB(m_columnPresetBButton);
        m_columnPresetAButton->setStyleSheet(buildPresetButtonStyle(true));
        m_columnPresetBButton->setStyleSheet(buildPresetButtonStyle(false));
        m_columnPresetAButton->setChecked(m_columnLayout == ClipboardGuardColumnLayout::PresetA);
        m_columnPresetBButton->setChecked(m_columnLayout == ClipboardGuardColumnLayout::PresetB);
    }

    QString ClipboardGuardPage::buildPresetButtonStyle(const bool leftButton)
    {
        const QString outerRadius = leftButton
            ? QStringLiteral("border-top-left-radius:3px;border-bottom-left-radius:3px;")
            : QStringLiteral("border-top-right-radius:3px;border-bottom-right-radius:3px;border-left:0px;");
        // A/B 保留紧贴外侧圆角；尺寸由工具条统一，checked 强调由公共规则绘制。
        return ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Neutral)
            + QStringLiteral("QPushButton{font-weight:700;border-radius:0px;%1}").arg(outerRadius);
    }

    QTableWidgetItem* ClipboardGuardPage::createReadOnlyItem(const QString& textValue)
    {
        QTableWidgetItem* const itemValue = new QTableWidgetItem(textValue);
        itemValue->setFlags(itemValue->flags() & ~Qt::ItemIsEditable);
        return itemValue;
    }

    void ClipboardGuardPage::showHeaderContextMenu(const QPoint& position)
    {
        if (m_eventTable == nullptr)
        {
            return;
        }
        QMenu columnMenu(m_eventTable);
        columnMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
        static const std::array<QString, ColumnCount> kHeaderNames{
            QStringLiteral("时间"), QStringLiteral("进程"), QStringLiteral("PID"), QStringLiteral("操作"),
            QStringLiteral("格式"), QStringLiteral("结果"), QStringLiteral("TID"), QStringLiteral("会话"),
            QStringLiteral("完整性"), QStringLiteral("发起进程"), QStringLiteral("序号")
        };
        for (int columnIndex = 0; columnIndex < static_cast<int>(ColumnCount); ++columnIndex)
        {
            QAction* const columnAction = columnMenu.addAction(kHeaderNames[static_cast<std::size_t>(columnIndex)]);
            columnAction->setCheckable(true);
            columnAction->setChecked(!m_eventTable->isColumnHidden(columnIndex));
            connect(columnAction, &QAction::toggled, &columnMenu, [this, columnIndex](const bool visible) {
                m_eventTable->setColumnHidden(columnIndex, !visible);
                clearColumnPresetSelection();
            });
        }
        columnMenu.exec(m_eventTable->horizontalHeader()->mapToGlobal(position));
    }
}
