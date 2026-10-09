#include "MemoryDock.Internal.h"
#include "SystemMemoryAuditPage.h"
#include "DdmaPage.h"
#include "../UI/AdaptivePageScroll.h" // ks::ui::EnablePageInnerScroll / IsolateMinimumSize：页内滚动壳与最小尺寸隔离。
#include "../UI/VisibleTableWidget.h"
#include "../Internationalization/LanguageManager.h"

#include <QCompleter> // 进程下拉的包含式补全需要完整类型。

#include <functional>
#include <utility>

// 说明：由原聚合式实现迁移为独立 .cpp，成员函数实现保持原样。
using namespace ksword::memory_dock_internal;

// ============================================================
// MemoryDock.UiBuild.cpp
// 作用：承载构造/析构与 UI 结构初始化代码。
// ============================================================

// ============================================================
// MemoryDock.UiBuild.cpp（由原 UiLifecycle 拆分）
// 作用：
// - 承载 MemoryDock 的构造/析构、UI 结构初始化、信号槽连接等生命周期逻辑。
// - 聚焦“界面与交互绑定”职责，避免与扫描算法、读写工具函数混杂。
// ============================================================

namespace
{
    // PopupLifecycleGuardedComboBox 作用：
    // - 在 QComboBox::showPopup() 进入前登记弹层生命周期，避开 Qt 滚动动画把
    //   真实弹层暂时隐藏、isVisible() 错报 false 的窗口；
    // - 在 hidePopup() 完成后的下一轮事件循环解除登记并回投延迟提交；
    // - generation 防止“刚关闭又立刻重开”时旧回调错误解除新弹层的登记。
    class PopupLifecycleGuardedComboBox final : public QComboBox
    {
    public:
        PopupLifecycleGuardedComboBox(
            QWidget* const parentWidget,
            std::function<void(bool)> popupStateChangedAction)
            : QComboBox(parentWidget),
              m_popupStateChangedAction(std::move(popupStateChangedAction))
        {
        }

    protected:
        void showPopup() override
        {
            // 空模型不会产生弹层，也就没有需要保护的模型/动画生命周期。
            if (count() <= 0)
            {
                QComboBox::showPopup();
                return;
            }

            ++m_popupGeneration;
            if (m_popupStateChangedAction)
            {
                m_popupStateChangedAction(true);
            }
            QComboBox::showPopup();
        }

        void hidePopup() override
        {
            const quint64 closingGeneration = m_popupGeneration;
            QComboBox::hidePopup();

            // QComboBox 的 Hide 收尾尚在当前调用栈内；下一轮再允许清空/重建模型。
            QTimer::singleShot(0, this, [this, closingGeneration]() {
                if (closingGeneration != m_popupGeneration)
                {
                    return;
                }

                if (m_popupStateChangedAction)
                {
                    m_popupStateChangedAction(false);
                }
                });
        }

    private:
        std::function<void(bool)> m_popupStateChangedAction;
        quint64 m_popupGeneration = 0ULL;
    };

    // copyMemoryUtilityCurrentRow 作用：
    // - 复制 MemoryDock 辅助表格当前行；
    // - 输入 table：断点表、书签表等 QTableWidget；
    // - 处理：逐列读取可见文本并按 TSV 写入剪贴板；
    // - 返回：无；无选中行或剪贴板不可用时直接返回。
    void copyMemoryUtilityCurrentRow(QTableWidget* table)
    {
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
        QApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    // installMemoryUtilityCopyMenu 作用：
    // - 给断点/书签等辅助表格安装只读复制菜单；
    // - 输入 table：需要复制行能力的表格；
    // - 处理：点击行时同步当前行，弹出显式不透明 QMenu；
    // - 返回：无，不改变断点/书签状态。
    void installMemoryUtilityCopyMenu(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
            {
                const QModelIndex clickedIndex = table->indexAt(localPosition);
                if (clickedIndex.isValid())
                {
                    table->setCurrentCell(clickedIndex.row(), clickedIndex.column());
                }

                QMenu menu(table);
                menu.setStyleSheet(KswordTheme::ContextMenuStyle());
                QAction* copyRowAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                    QStringLiteral("复制当前行"));
                copyRowAction->setEnabled(table->currentRow() >= 0);
                if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
                {
                    copyMemoryUtilityCurrentRow(table);
                }
            });
    }
}

MemoryDock::MemoryDock(QWidget* parent)
    : QWidget(parent)
{
    // 记录构造起点日志：用于追踪内存页控件的生命周期。
    kLogEvent constructStartEvent;
    info << constructStartEvent
        << "[MemoryDock] 开始构造内存页面控件。"
        << eol;

    // 构造阶段按固定顺序执行，确保 UI 控件先创建再绑定信号。
    initializeUi();
    initializeConnections();
    initializeBookmarkRefreshTimer();
    refreshProcessList(false);
    updateStatusBarText();

    // 记录构造结束日志：确认初始化链路已执行完毕。
    kLogEvent constructFinishEvent;
    info << constructFinishEvent
        << "[MemoryDock] 构造完成，已初始化 UI、连接、定时器与进程列表。"
        << eol;
}

MemoryDock::~MemoryDock()
{
    // 析构开始日志：便于定位窗口关闭时的后台任务状态。
    kLogEvent destroyStartEvent;
    info << destroyStartEvent
        << "[MemoryDock] 开始析构，准备取消扫描并分离进程。"
        << eol;

    // 析构前先取消扫描，避免后台线程继续使用已销毁控件。
    cancelCurrentScan();
    // 内存工作台的设置在子对象（视图）销毁之前落盘；分离钩子仍要用到视图，所以保存之后才分离。
    shutdownWorkbench();
    detachProcess();

    // 析构完成日志：标记控件资源回收流程结束。
    kLogEvent destroyFinishEvent;
    info << destroyFinishEvent
        << "[MemoryDock] 析构完成。"
        << eol;
}

void MemoryDock::initializeUi()
{
    // 初始化根 UI 结构时输出日志，便于定位 UI 组件构造顺序问题。
    kLogEvent uiInitEvent;
    info << uiInitEvent
        << "[MemoryDock] initializeUi: 开始构建根布局。"
        << eol;

    // 根布局：标题行、进程工具栏、中部 Tab、底部状态栏。
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(6);

    // 标题行与其它 Dock 保持同一套三段式：标题在左、状态摘要吃掉中间空白。
    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);
    m_dockTitleLabel = new QLabel(QStringLiteral("内存"), this);
    m_dockTitleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
            .arg(KswordTheme::TextPrimaryHex()));
    m_dockHeaderStatusLabel = new QLabel(QStringLiteral("未附加进程，请先选择目标并点击“附加”。"), this);
    m_dockHeaderStatusLabel->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;").arg(KswordTheme::TextSecondaryHex()));
    headerLayout->addWidget(m_dockTitleLabel, 0);
    headerLayout->addWidget(m_dockHeaderStatusLabel, 1);
    m_rootLayout->addLayout(headerLayout);

    initializeToolbar();
    initializeTabs();
    initializeStatusBar();

    // 状态栏建立之后再统一下发一次语义色，保证底部标签也走同一条路径。
    applyMemoryDockSemanticStyles();
}

void MemoryDock::applyMemoryDockSemanticStyles()
{
    // 高危写回按钮用错误语义色描边，和普通按钮区分开。
    if (m_driverMemoryApplyButton != nullptr)
    {
        m_driverMemoryApplyButton->setStyleSheet(
            QStringLiteral(
                "QPushButton{border:1px solid %1;border-radius:3px;color:%1;padding:4px 10px;}"
                "QPushButton:disabled{border:1px solid %2;color:%2;}")
                .arg(KswordTheme::ErrorHex())
                .arg(KswordTheme::TextSecondaryHex()));
    }

    // 底部状态栏：已附加用成功色，未附加保持次要色，读写不可用用警告色。
    const bool attached = (m_attachedPid != 0U);
    if (m_statusProcessLabel != nullptr)
    {
        m_statusProcessLabel->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(attached ? KswordTheme::SuccessHex() : KswordTheme::TextSecondaryHex()));
    }
    if (m_statusPidLabel != nullptr)
    {
        m_statusPidLabel->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(attached ? KswordTheme::TextPrimaryHex() : KswordTheme::TextSecondaryHex()));
    }
    if (m_statusMemoryIoLabel != nullptr)
    {
        // 已附加但拿不到读写权限是最需要被看见的状态，单独用警告色。
        QString memoryIoColor = KswordTheme::TextSecondaryHex();
        if (attached)
        {
            memoryIoColor = m_canReadWriteMemory
                ? KswordTheme::SuccessHex()
                : KswordTheme::WarningHex();
        }
        m_statusMemoryIoLabel->setStyleSheet(QStringLiteral("color:%1;").arg(memoryIoColor));
    }
}

void MemoryDock::changeEvent(QEvent* eventObject)
{
    QWidget::changeEvent(eventObject);
    if (eventObject == nullptr)
    {
        return;
    }

    // 调色板变化意味着深浅色切换，所有语义色快照都必须重新求值一次。
    if (eventObject->type() == QEvent::ApplicationPaletteChange
        || eventObject->type() == QEvent::PaletteChange)
    {
        applyMemoryDockSemanticStyles();
    }
}

void MemoryDock::initializeToolbar()
{
    // 记录工具栏初始化日志：明确顶部控件何时创建。
    kLogEvent toolbarInitEvent;
    info << toolbarInitEvent
        << "[MemoryDock] initializeToolbar: 创建进程工具栏控件。"
        << eol;

    // 顶部工具栏放在独立容器内，便于统一 margin 和 spacing。
    QWidget* toolbarContainer = new QWidget(this);
    m_toolbarLayout = new QHBoxLayout(toolbarContainer);
    m_toolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolbarLayout->setSpacing(6);

    m_processCombo = new PopupLifecycleGuardedComboBox(
        toolbarContainer,
        [this](const bool active) {
            m_processComboPopupLifecycleActive = active;
            if (!active)
            {
                flushProcessComboDeferredCommit();
            }
            });
    // 最小宽度是整条工具栏乃至整个 Dock 的横向下限：Dock 不再套外层滚动区之后，
    // 窄于这个下限的部分会被右侧直接裁掉。进程名靠可输入的过滤框和 stretch 拿到富余空间，
    // 所以这里只保留够读一个短进程名的宽度；显式最小宽度也会盖过下拉项文本撑出的 sizeHint。
    m_processCombo->setMinimumWidth(160);
    m_processCombo->setToolTip("选择目标进程。可直接输入过滤：进程名和 PID 都能匹配。");

    // 可输入 + 包含式补全。几百个进程用纯滚动的下拉是选不出来的，而同名进程多的
    // 程序（QQ 这类一开就是十个同名进程）更是只能靠 PID 区分——所以补全必须同时
    // 能匹配到条目文本里的 PID，用 MatchContains 而不是默认的前缀匹配。
    m_processCombo->setEditable(true);
    m_processCombo->setInsertPolicy(QComboBox::NoInsert);
    if (QCompleter* const processCompleter = m_processCombo->completer())
    {
        processCompleter->setCompletionMode(QCompleter::PopupCompletion);
        processCompleter->setFilterMode(Qt::MatchContains);
        processCompleter->setCaseSensitivity(Qt::CaseInsensitive);
        processCompleter->setMaxVisibleItems(20);
    }
    if (QLineEdit* const processEdit = m_processCombo->lineEdit())
    {
        processEdit->setPlaceholderText(QStringLiteral("输入进程名或 PID 过滤"));
        processEdit->setClearButtonEnabled(true);
    }

    // 十字准星：按住拖到目标窗口上松手，直接按窗口归属附加。
    // 这条路径存在的理由是它不可能选错——用户知道的是"哪个窗口是我要的"，
    // 而不是 PID；让他们指窗口，由工具去解析 PID。
    m_processPickerButton = new ks::ui::WindowPickerButton(toolbarContainer);
    m_processPickerButton->setIcon(QIcon(QStringLiteral(":/Icon/window_picker_aim.svg")));
    m_processPickerButton->setToolTip(
        QStringLiteral("按住不放，把光标拖到目标程序的窗口上再松手，即按该窗口所属进程附加。拖动时目标窗口会高亮，按 Esc 取消。"));

    // 拾取过程中的实时目标提示。只在拾取时可见：平时占着工具栏宽度没有意义，
    // 而拾取时鼠标已经离开了工具栏，用户需要一个不用低头找的地方看当前目标。
    m_processPickerHintLabel = new QLabel(toolbarContainer);
    m_processPickerHintLabel->setVisible(false);
    m_processPickerHintLabel->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::ControlAccentHex()));

    // 按项目规范：动作按钮优先用图标库里的图标，并且每个按钮都要有 tooltip。
    m_attachButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_start.svg")), "附加", toolbarContainer);
    m_detachButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")), "分离", toolbarContainer);
    m_refreshButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")), "刷新", toolbarContainer);
    m_settingsButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_priority.svg")), "设置", toolbarContainer);
    m_attachButton->setToolTip("附加到上面选中的进程，之后才能查看和搜索它的内存");
    m_detachButton->setToolTip("从当前进程分离，释放已打开的进程句柄");
    m_refreshButton->setToolTip("重新枚举系统进程列表，或刷新当前页的数据");
    m_settingsButton->setToolTip("打开内存读写方式、扫描上限等选项");

    // 分隔符把“附加/分离”这组进程动作与“刷新/设置”这组页面动作在视觉上分开。
    QFrame* toolbarSeparator = new QFrame(toolbarContainer);
    toolbarSeparator->setFrameShape(QFrame::VLine);
    toolbarSeparator->setFrameShadow(QFrame::Sunken);

    m_toolbarLayout->addWidget(new QLabel("进程:", toolbarContainer));
    m_toolbarLayout->addWidget(m_processCombo, 1);
    m_toolbarLayout->addWidget(m_processPickerButton);
    m_toolbarLayout->addWidget(m_processPickerHintLabel);
    m_toolbarLayout->addWidget(m_attachButton);
    m_toolbarLayout->addWidget(m_detachButton);
    m_toolbarLayout->addWidget(toolbarSeparator);
    m_toolbarLayout->addWidget(m_refreshButton);
    m_toolbarLayout->addWidget(m_settingsButton);

    m_rootLayout->addWidget(toolbarContainer);
}

void MemoryDock::initializeTabs()
{
    // 记录 Tab 初始化日志：便于排查某个页面未创建的问题。
    kLogEvent tabInitEvent;
    info << tabInitEvent
        << "[MemoryDock] initializeTabs: 开始创建 11 个功能页。"
        << eol;

    // 全部子页面统一由 QTabWidget 承载。
    m_tabWidget = new QTabWidget(this);
    m_tabWidget->setDocumentMode(true);
    // 加固：QTabWidget 的页面栈会对所有页（含未显示、被隐藏的旧页）的最小高度取最大值。
    // 每个页面本身都已经带内部滚动壳（见 ks::ui::EnablePageInnerScroll），这里再把页签控件
    // 的最小尺寸隔离掉，这样以后有人新增页签却忘了包壳，表现为页内被裁剪，
    // 而不是把 Dock 的头部、工具栏和状态栏挤坏。
    ks::ui::IsolateMinimumSize(m_tabWidget);
    m_rootLayout->addWidget(m_tabWidget, 1);

    initializeProcessModuleTab();
    initializeMemoryRegionTab();
    initializeMemorySearchTab();
    initializeMemoryViewerTab();
    initializeBreakpointBookmarkTab();
    initializeDriverMemoryRwTab();
    initializeKernelExecutableMemoryScanTab();
    initializeKernelMemoryEvidenceTab();
    initializeProcessPteTranslateTab();
    initializeProcessMemoryEvidenceTab();
    initializeSystemMemoryAuditTab();
    initializeTamperDetectionTab();
    initializeDdmaTab();

    // 12 个页签的图标集中在这里设置：分散到各构建函数里会漏，也不好统一调整语义。
    // 下标顺序与上面的构建顺序严格一一对应。
    const char* const tabIconAliases[] = {
        ":/Icon/process_list.svg",        // 进程与模块
        ":/Icon/disk_storage.svg",        // 内存区域
        ":/Icon/codeeditor_find.svg",     // 内存搜索
        ":/Icon/process_details.svg",     // 内存查看器
        ":/Icon/process_pause.svg",       // 断点与书签
        ":/Icon/disk_save.svg",           // 驱动内存读写
        ":/Icon/log_track.svg",           // 内核可执行页
        ":/Icon/file_find.svg",           // 内核内存证据
        ":/Icon/process_tree.svg",        // PTE / VA 翻译
        ":/Icon/process_performance.svg", // 进程内存证据
        ":/Icon/disk_analyze.svg",        // 系统内存审计
        ":/Icon/disk_storage.svg"         // DDMA
    };
    const int iconCount = static_cast<int>(sizeof(tabIconAliases) / sizeof(tabIconAliases[0]));
    for (int tabIndex = 0; tabIndex < m_tabWidget->count() && tabIndex < iconCount; ++tabIndex)
    {
        m_tabWidget->setTabIcon(tabIndex, QIcon(QString::fromLatin1(tabIconAliases[tabIndex])));
    }

    // 内存工作台页签必须在图标循环之后插入：上面的图标按下标对应原有页签顺序，
    // 先插会让后面所有页签的图标整体错位。它自己的图标与语言键在 initializeWorkbenchTab 里设置。
    initializeWorkbenchTab();
    // 新独立页面也在旧图标循环之后插入，避免改变旧页面的下标图标映射。
    initializeMemoryDebugTab();

    // 后加的四个证据页原本漏了语义键绑定，这里补齐，让它们也能跟随语言切换。
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    if (m_tabKernelExecutableMemory != nullptr)
    {
        languageManager.bindTab(
            m_tabWidget, m_tabKernelExecutableMemory,
            QStringLiteral("memory.tab.kernel_executable"), QStringLiteral("内核可执行页"));
    }
    if (m_tabKernelMemoryEvidence != nullptr)
    {
        languageManager.bindTab(
            m_tabWidget, m_tabKernelMemoryEvidence,
            QStringLiteral("memory.tab.kernel_memory_evidence"), QStringLiteral("内核内存证据"));
    }
    if (m_tabProcessPteTranslate != nullptr)
    {
        languageManager.bindTab(
            m_tabWidget, m_tabProcessPteTranslate,
            QStringLiteral("memory.tab.pte_translate"), QStringLiteral("PTE / VA 翻译"));
    }
    if (m_tabProcessMemoryEvidence != nullptr)
    {
        languageManager.bindTab(
            m_tabWidget, m_tabProcessMemoryEvidence,
            QStringLiteral("memory.tab.process_memory_evidence"), QStringLiteral("进程内存证据"));
    }
}

void MemoryDock::initializeSystemMemoryAuditTab()
{
    m_systemMemoryAuditPage = new SystemMemoryAuditPage(m_tabWidget);
    m_systemMemoryAuditPage->openModuleDetails = [this](const QString& path) {
        const auto handler = openPoolModuleDetails;
        if (handler) { handler(path); }
    };
    m_tabWidget->addTab(m_systemMemoryAuditPage, QStringLiteral("系统内存审计"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget,
        m_systemMemoryAuditPage,
        QStringLiteral("memory.tab.system_memory_audit"),
        QStringLiteral("系统内存审计"));
}

void MemoryDock::initializeTamperDetectionTab()
{
    // 放在 DDMA 页**之前**挂载，但依赖它的会话：DDMA 通道是本页唯一一条不经过
    // CPU 页表的读取路径，没有它这一页就只能发现普通补丁。页面自己会在通道不可用
    // 时把这句话写在界面上，而不是只把复选框置灰。
    m_tamperDetectionPage = new ksword::memory_dock::TamperDetectionPage(m_tabWidget);
    m_tabWidget->addTab(m_tamperDetectionPage, QStringLiteral("篡改检测"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget,
        m_tamperDetectionPage,
        QStringLiteral("memory.tab.tamper_detection"),
        QStringLiteral("篡改检测"));
}

void MemoryDock::initializeDdmaTab()
{
    // Tab12：DDMA。页面自己负责通道配置与自检，MemoryDock 只挂载它并订阅
    // 会话变化，把"现在能不能选 DDMA 后端"同步给其它页面的下拉框。
    m_ddmaPage = new DdmaPage(m_tabWidget);
    m_ddmaPage->setSessionChangedCallback([this]() { refreshBackendSelectors(); });

    m_tabWidget->addTab(m_ddmaPage, QStringLiteral("DDMA"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget,
        m_ddmaPage,
        QStringLiteral("memory.tab.ddma"),
        QStringLiteral("DDMA"));

    // 系统内存审计页也要能用 DDMA 复核物理页，这里把会话读取入口交给它。
    if (m_systemMemoryAuditPage != nullptr)
    {
        m_systemMemoryAuditPage->setDdmaSessionProvider(
            [this]() -> const ksword::memory_backend::DdmaSession& {
                return currentDdmaSession();
            });
    }

    // 三个下拉框在各自的 Tab 构建函数里已经创建，这里做首次状态同步。
    refreshBackendSelectors();
}

void MemoryDock::focusDdmaPage()
{
    if (m_tabWidget == nullptr || m_ddmaPage == nullptr)
    {
        return;
    }
    // 进程详情内嵌模式下这个页是被隐藏的；隐藏的 Tab 用 setCurrentWidget 切不过去，
    // 所以先确认它可见再切，避免出现"点了没反应"。
    const int tabIndex = m_tabWidget->indexOf(m_ddmaPage);
    if (tabIndex < 0 || !m_tabWidget->isTabVisible(tabIndex))
    {
        return;
    }
    m_tabWidget->setCurrentWidget(m_ddmaPage);
}

QWidget* MemoryDock::createBackendSelector(
    QWidget* const parent,
    QComboBox*& comboOut,
    QLabel*& hintOut)
{
    QWidget* container = new QWidget(parent);
    QHBoxLayout* layout = new QHBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);

    comboOut = new QComboBox(container);
    // 条目顺序必须与 MemoryAccessBackend 枚举一致，界面按索引直接转换。
    comboOut->addItem(QStringLiteral("R3（ReadProcessMemory）"));
    comboOut->addItem(QStringLiteral("R0（驱动通道）"));
    comboOut->addItem(QStringLiteral("HVM（私有页表窗口）"));
    comboOut->addItem(QStringLiteral("DDMA（磁盘 DMA）"));
    comboOut->setToolTip(
        QStringLiteral("R3 走 ReadProcessMemory / WriteProcessMemory，不经驱动，受句柄权限与进程保护约束，也读不了内核地址和物理地址。\nR0 走驱动的 MmCopyVirtualMemory / MmMapIoSpaceEx，绕开句柄权限，能读内核地址与物理地址，但仍受 SLAT / EPT 约束。\nHVM 改写自有页表项指向目标帧，整条路径不调用任何文档化的内存管理器例程，别的驱动挂钩那些例程挂不到它头上；它同样受 SLAT / EPT 约束，与 R0 分歧说明的是内存管理器被挂了钩，而不是重定向。\nDDMA 走磁盘控制器的总线主控 DMA，不受 SLAT 约束，能读到被上层虚拟化重定向或隐藏的物理页；代价是必须借用磁盘扇区中转，而且明显更慢，需要先在“DDMA”子页配置通道。\n同一个地址几条读到的结果不一样本身就是判据，而分歧落在哪两条之间决定了它说明什么。"));

    hintOut = new QLabel(container);
    hintOut->setWordWrap(true);
    hintOut->setTextInteractionFlags(Qt::TextSelectableByMouse);

    layout->addWidget(new QLabel(QStringLiteral("访问后端"), container));
    layout->addWidget(comboOut);
    layout->addWidget(hintOut, 1);

    // 选中 DDMA 但通道尚未就绪时，refreshBackendSelectors 会把选择弹回标准通道
    // 并在提示里说明缺哪一步；它内部用 QSignalBlocker 改索引，不会递归触发。
    connect(comboOut, &QComboBox::currentIndexChanged, this, [this](int) {
        refreshBackendSelectors();
        });

    return container;
}

void MemoryDock::refreshBackendSelectors()
{
    QString reason;
    const bool ddmaUsable =
        ksword::memory_backend::isDdmaUsable(currentDdmaSession(), &reason);

    // 三个下拉共享同一份判据与同一段文案，避免三处各写一遍后走散。
    const auto syncOne = [this, ddmaUsable, &reason](
                             QComboBox* const combo, QLabel* const hint) {
        if (combo == nullptr)
        {
            return;
        }
        const bool ddmaSelected =
            (combo->currentIndex() ==
             static_cast<int>(ksword::memory_backend::MemoryAccessBackend::Ddma));

        // DDMA 变得不可用时，已经停在 DDMA 上的下拉必须退回标准通道，
        // 否则用户下一次点读取才会撞上失败。
        if (ddmaSelected && !ddmaUsable)
        {
            const QSignalBlocker blocker(combo);
            combo->setCurrentIndex(
                static_cast<int>(ksword::memory_backend::MemoryAccessBackend::StandardDriver));
        }

        if (hint == nullptr)
        {
            return;
        }
        if (ddmaUsable)
        {
            hint->setText(QStringLiteral("DDMA 通道已就绪，可随时切换。"));
            hint->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::SuccessHex()));
        }
        else
        {
            hint->setText(QStringLiteral("DDMA 暂不可用：%1").arg(reason));
            hint->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        }
        };

    syncOne(m_searchBackendCombo, m_searchBackendHintLabel);
    syncOne(m_viewerBackendCombo, m_viewerBackendHintLabel);
    syncOne(m_bookmarkBackendCombo, m_bookmarkBackendHintLabel);
    syncOne(m_driverMemoryBackendCombo, m_driverMemoryBackendHintLabel);

    // 包括 QSignalBlocker 下的 DDMA 自动回退和会话变化，立即失效旧书签值。
    if (m_bookmarkTable != nullptr && !m_bookmarkCache.empty())
    {
        refreshBookmarkValues();
    }

    // 系统内存审计页没有后端下拉，只有一个"DDMA 复核"按钮，但它同样要跟着
    // 会话可用性开关，否则会留下一个点下去必然失败的按钮。
    if (m_systemMemoryAuditPage != nullptr)
    {
        m_systemMemoryAuditPage->refreshDdmaCrossCheckState();
    }

    // 篡改检测页同样要跟着会话走：DDMA 是它唯一一条不经过 CPU 页表的路径，
    // 通道状态变了，它能给出的结论种类也跟着变，必须在界面上如实反映。
    if (m_tamperDetectionPage != nullptr)
    {
        m_tamperDetectionPage->refreshChannelAvailability();
    }
}

const ksword::memory_backend::DdmaSession& MemoryDock::currentDdmaSession() const
{
    // 读进程级会话而不是去问 m_ddmaPage：DDMA 页可能还没构建（Dock 布局恢复
    // 顺序不保证），而进程级会话在任何时刻都有一个确定的值，未配置时就是
    // "未配置"，不会因为空指针而误判成可用。
    return ksword::memory_backend::currentDdmaSession();
}

namespace
{
    // backendFromComboIndex：
    // - 下拉条目顺序与 MemoryAccessBackend 枚举一一对应，所以索引直接转换即可；
    // - 三个下拉共用这一份映射，免得加一个后端就要在三处各改一遍。
    //
    // 原先三处都写成"不是 DDMA 就当标准通道"。枚举只有两个值时那样写看不出
    // 问题，加进 R3 之后它会把 R3 静默折叠成 R0——用户选了 R3、实际走驱动，
    // 而"同一个地址两条通道结果不同"正是这三个选项存在的理由，折叠掉就没了。
    ksword::memory_backend::MemoryAccessBackend backendFromComboIndex(
        const QComboBox* const combo)
    {
        if (combo == nullptr)
        {
            return ksword::memory_backend::MemoryAccessBackend::UserMode;
        }
        const int selectedIndex = combo->currentIndex();
        if (selectedIndex < 0
            || selectedIndex >
                static_cast<int>(ksword::memory_backend::MemoryAccessBackend::Ddma))
        {
            return ksword::memory_backend::MemoryAccessBackend::UserMode;
        }
        return static_cast<ksword::memory_backend::MemoryAccessBackend>(selectedIndex);
    }
}

ksword::memory_backend::MemoryAccessBackend MemoryDock::currentSearchBackend() const
{
    return backendFromComboIndex(m_searchBackendCombo);
}

ksword::memory_backend::MemoryAccessBackend MemoryDock::currentViewerBackend() const
{
    return backendFromComboIndex(m_viewerBackendCombo);
}

ksword::memory_backend::MemoryAccessBackend MemoryDock::currentBookmarkBackend() const
{
    return backendFromComboIndex(m_bookmarkBackendCombo);
}

ksword::memory_backend::MemoryAccessBackend MemoryDock::currentDriverMemoryBackend() const
{
    return backendFromComboIndex(m_driverMemoryBackendCombo);
}

void MemoryDock::initializeProcessModuleTab()
{
    // Tab1 初始化日志：记录“进程与模块”页的构建过程。
    kLogEvent tab1InitEvent;
    info << tab1InitEvent
        << "[MemoryDock] initializeProcessModuleTab: 构建进程与模块页面。"
        << eol;

    // Tab1：进程与模块。
    m_tabProcessModule = new QWidget(m_tabWidget);
    // 页面自带内部滚动壳：内容放不下时在页内滚动，不把 Dock 撑高。页面指针身份不变。
    QWidget* const tabContent = ks::ui::EnablePageInnerScroll(m_tabProcessModule);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // 上下分割布局：上进程表，下模块表。
    QSplitter* splitter = new QSplitter(Qt::Vertical, m_tabProcessModule);

    QWidget* processPanel = new QWidget(splitter);
    QVBoxLayout* processLayout = new QVBoxLayout(processPanel);
    processLayout->setContentsMargins(0, 0, 0, 0);
    processLayout->setSpacing(4);
    QHBoxLayout* processTopBarLayout = new QHBoxLayout();
    processTopBarLayout->setContentsMargins(0, 0, 0, 0);
    processTopBarLayout->setSpacing(8);
    processTopBarLayout->addWidget(new QLabel("进程列表（双击自动附加）", processPanel));

    // 过滤框对齐下面的模块表：模块表一直有，进程表反而没有，而进程数远多于模块数。
    m_processFilterEdit = new QLineEdit(processPanel);
    m_processFilterEdit->setPlaceholderText("按进程名或 PID 过滤");
    m_processFilterEdit->setClearButtonEnabled(true);
    m_processFilterEdit->setStyleSheet(buildBlueInputStyle());
    processTopBarLayout->addWidget(m_processFilterEdit, 1);

    m_processCountLabel = new QLabel(processPanel);
    m_processCountLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    processTopBarLayout->addWidget(m_processCountLabel);

    processLayout->addLayout(processTopBarLayout);

    m_processTable = new ks::ui::VisibleTableWidget(processPanel);
    m_processTable->setColumnCount(5);
    m_processTable->setHorizontalHeaderLabels(QStringList{ "进程名", "PID", "会话ID", "CPU(可选)", "工作集" });
    m_processTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_processTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_processTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_processTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_processTable->setSortingEnabled(true);
    m_processTable->setAlternatingRowColors(true);
    m_processTable->verticalHeader()->setVisible(false);
    m_processTable->verticalHeader()->setDefaultSectionSize(20);
    // 进程图标统一缩放到 16x16，确保行高可以保持更紧凑。
    m_processTable->setIconSize(QSize(16, 16));
    // 会话 ID 与工作集放出来。工作集是同名进程之间唯一一眼可辨的差别——主进程
    // 和辅助进程的内存量通常差一两个数量级，今天正是靠它才分出 QQ 的十个同名
    // 进程里哪个是目标。CPU 那一列继续隐藏：它从来没被填过，恒为 0.00%，
    // 放出来只是多一列废数据，比隐藏更糟。
    m_processTable->setColumnHidden(2, false);
    m_processTable->setColumnHidden(3, true);
    m_processTable->setColumnHidden(4, false);
    m_processTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_processTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_processTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_processTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_processTable->setShowGrid(true);
    processLayout->addWidget(m_processTable, 1);

    QWidget* modulePanel = new QWidget(splitter);
    QVBoxLayout* moduleLayout = new QVBoxLayout(modulePanel);
    moduleLayout->setContentsMargins(0, 0, 0, 0);
    moduleLayout->setSpacing(4);

    // 模块区域布局对齐 ProcessDetailWindow：刷新按钮 + 签名选项 + 状态 + 模块表。
    QHBoxLayout* moduleTopBarLayout = new QHBoxLayout();
    moduleTopBarLayout->setContentsMargins(0, 0, 0, 0);
    moduleTopBarLayout->setSpacing(8);

    m_moduleRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新模块", modulePanel);
    m_moduleRefreshButton->setStyleSheet(buildBlueButtonStyle());
    m_moduleSignatureCheck = new QCheckBox("刷新时校验签名", modulePanel);
    m_moduleSignatureCheck->setChecked(true);
    m_moduleSignatureCheck->setStyleSheet(QStringLiteral(
        "QCheckBox { color:%1; font-weight:600; }")
        .arg(KswordTheme::TextPrimaryHex()));

    moduleTopBarLayout->addWidget(m_moduleRefreshButton);
    moduleTopBarLayout->addWidget(m_moduleSignatureCheck);

    m_moduleFilterEdit = new QLineEdit(modulePanel);
    m_moduleFilterEdit->setPlaceholderText("按模块路径过滤关键字");
    m_moduleFilterEdit->setStyleSheet(buildBlueInputStyle());
    moduleTopBarLayout->addWidget(m_moduleFilterEdit, 1);

    m_moduleStatusLabel = new QLabel("● 待刷新", modulePanel);
    m_moduleStatusLabel->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
            .arg(KswordTheme::TextSecondaryHex()));
    moduleTopBarLayout->addWidget(m_moduleStatusLabel);
    moduleLayout->addLayout(moduleTopBarLayout);

    m_moduleTable = new QTreeWidget(modulePanel);
    m_moduleTable->setColumnCount(static_cast<int>(ModuleTreeColumn::Count));
    m_moduleTable->setHeaderLabels(ModuleTreeHeaders);
    m_moduleTable->setRootIsDecorated(false);
    m_moduleTable->setItemsExpandable(false);
    m_moduleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_moduleTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_moduleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_moduleTable->setAlternatingRowColors(true);
    m_moduleTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_moduleTable->setSortingEnabled(true);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::Path), 460);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::Size), 110);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::Signature), 220);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::EntryOffset), 120);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::State), 100);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::ThreadId), 180);
    moduleLayout->addWidget(m_moduleTable, 1);

    splitter->addWidget(processPanel);
    splitter->addWidget(modulePanel);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 5);

    tabLayout->addWidget(splitter, 1);
    m_tabWidget->addTab(m_tabProcessModule, "进程与模块");
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget, m_tabProcessModule, QStringLiteral("memory.tab.process_module"), QStringLiteral("进程与模块"));
}

void MemoryDock::initializeMemoryRegionTab()
{
    // Tab2 初始化日志：用于追踪区域页控件初始化时机。
    kLogEvent tab2InitEvent;
    info << tab2InitEvent
        << "[MemoryDock] initializeMemoryRegionTab: 构建内存区域页面。"
        << eol;

    // Tab2：内存区域。
    m_tabRegions = new QWidget(m_tabWidget);
    // 页面自带内部滚动壳：内容放不下时在页内滚动，不把 Dock 撑高。页面指针身份不变。
    QWidget* const tabContent = ks::ui::EnablePageInnerScroll(m_tabRegions);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // 动作行：刷新按钮 + 关键字过滤 + 结果计数，和其它页保持同一套头部结构。
    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(6);
    m_regionRefreshButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")), "刷新区域", m_tabRegions);
    m_regionRefreshButton->setToolTip("重新枚举当前附加进程的内存区域");
    m_regionFilterEdit = new QLineEdit(m_tabRegions);
    m_regionFilterEdit->setPlaceholderText("按基址、保护属性或映射文件路径过滤");
    m_regionFilterEdit->setClearButtonEnabled(true);
    m_regionFilterEdit->setToolTip("输入关键字后只显示匹配的区域行");
    m_regionStatusLabel = new QLabel("未附加进程。", m_tabRegions);
    QFrame* regionActionSeparator = new QFrame(m_tabRegions);
    regionActionSeparator->setFrameShape(QFrame::VLine);
    regionActionSeparator->setFrameShadow(QFrame::Sunken);
    actionLayout->addWidget(m_regionRefreshButton);
    actionLayout->addWidget(regionActionSeparator);
    actionLayout->addWidget(m_regionFilterEdit, 1);
    actionLayout->addWidget(m_regionStatusLabel);
    tabLayout->addLayout(actionLayout);

    // 过滤开关收进分组框，避免和动作行挤在一起。
    QGroupBox* filterGroup = new QGroupBox("过滤条件", m_tabRegions);
    QHBoxLayout* filterLayout = new QHBoxLayout(filterGroup);
    filterLayout->setSpacing(10);
    m_regionCommittedOnlyCheck = new QCheckBox("仅已提交(MEM_COMMIT)", filterGroup);
    m_regionImageOnlyCheck = new QCheckBox("仅映像(IMAGE)", filterGroup);
    m_regionReadableOnlyCheck = new QCheckBox("仅可读", filterGroup);
    m_regionCommittedOnlyCheck->setToolTip("只显示已实际分配物理内存的区域，隐藏仅保留未使用的区域");
    m_regionImageOnlyCheck->setToolTip("只显示由 exe/dll 文件映射而来的内存区域");
    m_regionReadableOnlyCheck->setToolTip("只显示当前可以读取的内存区域，隐藏不可访问的区域");
    m_regionCommittedOnlyCheck->setChecked(true);
    m_regionReadableOnlyCheck->setChecked(true);
    filterLayout->addWidget(m_regionCommittedOnlyCheck);
    filterLayout->addWidget(m_regionImageOnlyCheck);
    filterLayout->addWidget(m_regionReadableOnlyCheck);
    filterLayout->addStretch(1);
    tabLayout->addWidget(filterGroup);

    m_regionTable = new ks::ui::VisibleTableWidget(m_tabRegions);
    m_regionTable->setColumnCount(6);
    m_regionTable->setHorizontalHeaderLabels(QStringList{
        "基址", "大小", "保护属性", "状态", "类型", "映射文件"
        });
    m_regionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_regionTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_regionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_regionTable->setAlternatingRowColors(true);
    m_regionTable->setSortingEnabled(true);
    m_regionTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_regionTable->verticalHeader()->setVisible(false);
    m_regionTable->horizontalHeader()->setStretchLastSection(true);
    tabLayout->addWidget(m_regionTable, 1);

    m_tabWidget->addTab(m_tabRegions, "内存区域");
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget, m_tabRegions, QStringLiteral("memory.tab.regions"), QStringLiteral("内存区域"));
}

void MemoryDock::initializeMemorySearchTab()
{
    // Tab3 初始化日志：用于扫描页控件异常时定位阶段。
    kLogEvent tab3InitEvent;
    info << tab3InitEvent
        << "[MemoryDock] initializeMemorySearchTab: 构建内存搜索页面。"
        << eol;

    // Tab3：内存搜索。
    m_tabSearch = new QWidget(m_tabWidget);
    // 页面自带内部滚动壳：内容放不下时在页内滚动，不把 Dock 撑高。页面指针身份不变。
    QWidget* const tabContent = ks::ui::EnablePageInnerScroll(m_tabSearch);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    const QString inputStyle = buildBlueInputStyle();
    const QString comboStyle = buildBlueComboStyle();
    const QString buttonStyle = buildBlueButtonStyle();

    // 搜索条件面板。
    QGroupBox* conditionGroup = new QGroupBox("搜索条件", m_tabSearch);
    QGridLayout* conditionLayout = new QGridLayout(conditionGroup);
    conditionLayout->setHorizontalSpacing(8);
    conditionLayout->setVerticalSpacing(6);

    m_searchTypeCombo = new QComboBox(conditionGroup);
    m_searchTypeCombo->addItem("字节", static_cast<int>(SearchValueType::Byte));
    m_searchTypeCombo->addItem("2字节", static_cast<int>(SearchValueType::Int16));
    m_searchTypeCombo->addItem("4字节", static_cast<int>(SearchValueType::Int32));
    m_searchTypeCombo->addItem("8字节", static_cast<int>(SearchValueType::Int64));
    m_searchTypeCombo->addItem("浮点数", static_cast<int>(SearchValueType::Float32));
    m_searchTypeCombo->addItem("双精度", static_cast<int>(SearchValueType::Float64));
    m_searchTypeCombo->addItem("字节数组(支持??)", static_cast<int>(SearchValueType::ByteArray));
    m_searchTypeCombo->addItem("ASCII字符串", static_cast<int>(SearchValueType::StringAscii));
    m_searchTypeCombo->addItem("Unicode字符串", static_cast<int>(SearchValueType::StringUnicode));
    m_searchTypeCombo->setStyleSheet(comboStyle);

    m_searchValueEdit = new QLineEdit(conditionGroup);
    m_searchValueEdit->setPlaceholderText("输入搜索值");
    m_searchValueEdit->setStyleSheet(inputStyle);

    m_searchRangeCombo = new QComboBox(conditionGroup);
    m_searchRangeCombo->addItem("整个内存");
    m_searchRangeCombo->addItem("自定义范围");
    m_searchRangeCombo->setStyleSheet(comboStyle);

    m_searchRangeStartEdit = new QLineEdit(conditionGroup);
    m_searchRangeEndEdit = new QLineEdit(conditionGroup);
    m_searchRangeStartEdit->setPlaceholderText("起始地址");
    m_searchRangeEndEdit->setPlaceholderText("结束地址");
    m_searchRangeStartEdit->setStyleSheet(inputStyle);
    m_searchRangeEndEdit->setStyleSheet(inputStyle);
    m_searchRangeStartEdit->setEnabled(false);
    m_searchRangeEndEdit->setEnabled(false);

    m_searchImageOnlyCheck = new QCheckBox("仅映像", conditionGroup);
    m_searchHeapOnlyCheck = new QCheckBox("仅堆(近似)", conditionGroup);
    m_searchStackOnlyCheck = new QCheckBox("仅栈(近似)", conditionGroup);
    m_searchTypeCombo->setToolTip("选择要搜索的数据类型；类型必须和内存中实际存放的格式一致才能搜到");
    m_searchRangeCombo->setToolTip("限定搜索的地址范围；选“自定义范围”后可填写右侧的起止地址");
    m_searchImageOnlyCheck->setToolTip("只在 exe/dll 映射的内存中搜索");
    m_searchHeapOnlyCheck->setToolTip("只在推测为堆（程序动态分配）的内存中搜索，判定为近似值");
    m_searchStackOnlyCheck->setToolTip("只在推测为栈（函数局部变量）的内存中搜索，判定为近似值");

    m_firstScanButton = new QPushButton(QIcon(":/Icon/log_track.svg"), "首次扫描", conditionGroup);
    m_nextScanButton = new QPushButton(QIcon(":/Icon/codeeditor_find.svg"), "再次扫描", conditionGroup);
    m_resetScanButton = new QPushButton(QIcon(":/Icon/log_clear.svg"), "重置", conditionGroup);
    m_cancelScanButton = new QPushButton(QIcon(":/Icon/process_terminate.svg"), "取消扫描", conditionGroup);
    m_firstScanButton->setToolTip("按上面的条件全新搜索一遍内存，得到初始结果集");
    m_nextScanButton->setToolTip("在上次结果的基础上继续筛选，逐步缩小范围（需先完成首次扫描）");
    m_resetScanButton->setToolTip("清空已有搜索结果，回到可重新首次扫描的状态");
    m_cancelScanButton->setToolTip("中止正在进行的扫描");
    m_firstScanButton->setStyleSheet(buttonStyle);
    m_nextScanButton->setStyleSheet(buttonStyle);
    m_resetScanButton->setStyleSheet(buttonStyle);
    m_cancelScanButton->setStyleSheet(buttonStyle);
    m_nextScanButton->setEnabled(false);
    m_cancelScanButton->setEnabled(false);

    conditionLayout->addWidget(new QLabel("数据类型", conditionGroup), 0, 0);
    conditionLayout->addWidget(m_searchTypeCombo, 0, 1);
    conditionLayout->addWidget(new QLabel("值", conditionGroup), 0, 2);
    conditionLayout->addWidget(m_searchValueEdit, 0, 3, 1, 3);
    conditionLayout->addWidget(new QLabel("范围", conditionGroup), 1, 0);
    conditionLayout->addWidget(m_searchRangeCombo, 1, 1);
    conditionLayout->addWidget(m_searchRangeStartEdit, 1, 2);
    conditionLayout->addWidget(m_searchRangeEndEdit, 1, 3);
    conditionLayout->addWidget(m_searchImageOnlyCheck, 1, 4);
    conditionLayout->addWidget(m_searchHeapOnlyCheck, 1, 5);
    conditionLayout->addWidget(m_searchStackOnlyCheck, 1, 6);
    conditionLayout->addWidget(m_firstScanButton, 2, 1);
    conditionLayout->addWidget(m_nextScanButton, 2, 2);
    conditionLayout->addWidget(m_resetScanButton, 2, 3);
    conditionLayout->addWidget(m_cancelScanButton, 2, 4);

    tabLayout->addWidget(conditionGroup);

    QGroupBox* compareGroup = new QGroupBox("再次扫描过滤", m_tabSearch);
    QHBoxLayout* compareLayout = new QHBoxLayout(compareGroup);
    compareLayout->setContentsMargins(8, 6, 8, 6);
    compareLayout->setSpacing(8);

    m_nextScanCompareCombo = new QComboBox(compareGroup);
    m_nextScanCompareCombo->addItem("等于", static_cast<int>(SearchCompareMode::Equal));
    m_nextScanCompareCombo->addItem("大于", static_cast<int>(SearchCompareMode::Greater));
    m_nextScanCompareCombo->addItem("小于", static_cast<int>(SearchCompareMode::Less));
    m_nextScanCompareCombo->addItem("介于", static_cast<int>(SearchCompareMode::Between));
    m_nextScanCompareCombo->addItem("变化", static_cast<int>(SearchCompareMode::Changed));
    m_nextScanCompareCombo->addItem("未变化", static_cast<int>(SearchCompareMode::Unchanged));
    m_nextScanCompareCombo->addItem("增加", static_cast<int>(SearchCompareMode::Increased));
    m_nextScanCompareCombo->addItem("减少", static_cast<int>(SearchCompareMode::Decreased));
    m_nextScanCompareCombo->setStyleSheet(comboStyle);
    m_nextScanCompareCombo->setToolTip("再次扫描时的筛选方式：可按新值比较，也可按“变化/未变化/增加/减少”筛选");

    m_nextScanValueEdit = new QLineEdit(compareGroup);
    m_nextScanValueBEdit = new QLineEdit(compareGroup);
    m_nextScanValueEdit->setPlaceholderText("值A");
    m_nextScanValueBEdit->setPlaceholderText("值B");
    m_nextScanValueEdit->setStyleSheet(inputStyle);
    m_nextScanValueBEdit->setStyleSheet(inputStyle);
    m_nextScanValueBEdit->setVisible(false);

    compareLayout->addWidget(new QLabel("条件", compareGroup));
    compareLayout->addWidget(m_nextScanCompareCombo);
    compareLayout->addWidget(new QLabel("值", compareGroup));
    compareLayout->addWidget(m_nextScanValueEdit, 1);
    compareLayout->addWidget(m_nextScanValueBEdit, 1);
    tabLayout->addWidget(compareGroup);

    // 访问后端选择条：扫描页的每一次区域读取都会走这里选中的通道。
    tabLayout->addWidget(
        createBackendSelector(m_tabSearch, m_searchBackendCombo, m_searchBackendHintLabel));

    m_searchResultTable = new ks::ui::VisibleTableWidget(m_tabSearch);
    m_searchResultTable->setColumnCount(4);
    m_searchResultTable->setHorizontalHeaderLabels(QStringList{ "地址", "当前值", "前次值", "备注" });
    m_searchResultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_searchResultTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_searchResultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_searchResultTable->setAlternatingRowColors(true);
    m_searchResultTable->setContextMenuPolicy(Qt::CustomContextMenu);
    // 结果表默认允许按列排序；批量填表期间由 rebuildSearchResultTable 临时关闭再还原。
    m_searchResultTable->setSortingEnabled(true);
    m_searchResultTable->verticalHeader()->setVisible(false);
    m_searchResultTable->horizontalHeader()->setStretchLastSection(true);
    tabLayout->addWidget(m_searchResultTable, 1);

    QHBoxLayout* progressLayout = new QHBoxLayout();
    progressLayout->setContentsMargins(0, 0, 0, 0);
    progressLayout->setSpacing(8);
    m_scanProgressBar = new QProgressBar(m_tabSearch);
    m_scanProgressBar->setRange(0, 100);
    m_scanStatusLabel = new QLabel("就绪", m_tabSearch);
    progressLayout->addWidget(m_scanProgressBar, 1);
    progressLayout->addWidget(m_scanStatusLabel);
    tabLayout->addLayout(progressLayout);

    m_tabWidget->addTab(m_tabSearch, "内存搜索");
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget, m_tabSearch, QStringLiteral("memory.tab.search"), QStringLiteral("内存搜索"));
}

void MemoryDock::initializeMemoryViewerTab()
{
    // Tab4 初始化日志：标记十六进制查看器控件创建。
    kLogEvent tab4InitEvent;
    info << tab4InitEvent
        << "[MemoryDock] initializeMemoryViewerTab: 构建内存查看器页面。"
        << eol;

    // Tab4：内存查看器。
    m_tabViewer = new QWidget(m_tabWidget);
    // 页面自带内部滚动壳：内容放不下时在页内滚动，不把 Dock 撑高。页面指针身份不变。
    QWidget* const tabContent = ks::ui::EnablePageInnerScroll(m_tabViewer);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    QHBoxLayout* navLayout = new QHBoxLayout();
    navLayout->setContentsMargins(0, 0, 0, 0);
    navLayout->setSpacing(8);
    navLayout->addWidget(new QLabel("地址:", m_tabViewer));
    m_viewAddressEdit = new QLineEdit(m_tabViewer);
    m_viewAddressEdit->setPlaceholderText("输入地址后跳转，默认十六进制");
    m_viewAddressEdit->setStyleSheet(buildBlueInputStyle());
    m_viewJumpButton = new QPushButton(QIcon(":/Icon/codeeditor_goto.svg"), "跳转", m_tabViewer);
    m_viewJumpButton->setStyleSheet(buildBlueButtonStyle());
    m_viewJumpButton->setToolTip("跳转到左侧输入的内存地址并显示该处内容。地址无前缀时按十六进制解释。");
    m_viewProtectLabel = new QLabel("保护属性: -", m_tabViewer);
    navLayout->addWidget(m_viewAddressEdit, 1);
    navLayout->addWidget(m_viewJumpButton);
    navLayout->addWidget(m_viewProtectLabel);
    tabLayout->addLayout(navLayout);

    // 访问后端选择条：查看器翻页时按这里选中的通道取数据。
    tabLayout->addWidget(
        createBackendSelector(m_tabViewer, m_viewerBackendCombo, m_viewerBackendHintLabel));

    // 统一十六进制编辑器组件：
    // - 后续内存/文件/网络全部复用该控件；
    // - Tab4 在这里配置成 16 字节每行，默认只读。
    QHBoxLayout* editActions = new QHBoxLayout();
    m_viewerApplyButton = new QPushButton(QStringLiteral("应用差异到真实内存"), m_tabViewer);
    m_viewerDiscardButton = new QPushButton(QStringLiteral("丢弃改动"), m_tabViewer);
    m_viewerApplyButton->setEnabled(false);
    m_viewerDiscardButton->setEnabled(false);
    editActions->addWidget(m_viewerApplyButton);
    editActions->addWidget(m_viewerDiscardButton);
    editActions->addStretch(1);
    tabLayout->addLayout(editActions);

    m_viewerMemoryEditor = new ks::ui::MemoryEditorWidget(m_tabViewer);
    m_hexEditorWidget = m_viewerMemoryEditor->hexEditor();
    m_viewerMemoryEditor->setEditable(false);
    tabLayout->addWidget(m_viewerMemoryEditor, 1);

    m_viewerStatusLabel = new QLabel("未附加进程。", m_tabViewer);
    tabLayout->addWidget(m_viewerStatusLabel);

    m_tabWidget->addTab(m_tabViewer, "内存查看器");
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget, m_tabViewer, QStringLiteral("memory.tab.viewer"), QStringLiteral("内存查看器"));
}

void MemoryDock::initializeBreakpointBookmarkTab()
{
    // Tab5 初始化日志：记录断点与书签页开始构建。
    kLogEvent tab5InitEvent;
    info << tab5InitEvent
        << "[MemoryDock] initializeBreakpointBookmarkTab: 构建断点与书签页面。"
        << eol;

    // Tab5：断点与书签。
    m_tabBpBookmark = new QWidget(m_tabWidget);
    // 页面自带内部滚动壳：内容放不下时在页内滚动，不把 Dock 撑高。页面指针身份不变。
    QWidget* const tabContent = ks::ui::EnablePageInnerScroll(m_tabBpBookmark);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    QSplitter* splitter = new QSplitter(Qt::Vertical, m_tabBpBookmark);
    const QString buttonStyle = buildBlueButtonStyle();

    QWidget* breakpointPanel = new QWidget(splitter);
    QVBoxLayout* breakpointLayout = new QVBoxLayout(breakpointPanel);
    breakpointLayout->setContentsMargins(0, 0, 0, 0);
    breakpointLayout->setSpacing(4);

    QHBoxLayout* bpButtonLayout = new QHBoxLayout();
    bpButtonLayout->setContentsMargins(0, 0, 0, 0);
    bpButtonLayout->setSpacing(6);
    m_addBreakpointButton = new QPushButton(QIcon(":/Icon/plus.svg"), "添加断点", breakpointPanel);
    m_removeBreakpointButton = new QPushButton(QIcon(":/Icon/log_clear.svg"), "删除断点", breakpointPanel);
    m_toggleBreakpointButton = new QPushButton(QIcon(":/Icon/process_pause.svg"), "启用/禁用", breakpointPanel);
    m_addBreakpointButton->setToolTip("在指定地址下断点，目标进程执行到该处时会中断");
    m_removeBreakpointButton->setToolTip("删除选中的断点并恢复该处的原始字节");
    m_toggleBreakpointButton->setToolTip("临时启用或停用选中的断点，不删除该条记录");
    m_addBreakpointButton->setStyleSheet(buttonStyle);
    m_removeBreakpointButton->setStyleSheet(buttonStyle);
    m_toggleBreakpointButton->setStyleSheet(buttonStyle);
    bpButtonLayout->addWidget(m_addBreakpointButton);
    bpButtonLayout->addWidget(m_removeBreakpointButton);
    bpButtonLayout->addWidget(m_toggleBreakpointButton);
    bpButtonLayout->addStretch(1);
    breakpointLayout->addLayout(bpButtonLayout);

    m_breakpointTable = new ks::ui::VisibleTableWidget(breakpointPanel);
    m_breakpointTable->setColumnCount(5);
    m_breakpointTable->setHorizontalHeaderLabels(QStringList{ "地址", "原字节", "状态", "命中次数", "描述" });
    m_breakpointTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_breakpointTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_breakpointTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_breakpointTable->setAlternatingRowColors(true);
    m_breakpointTable->verticalHeader()->setVisible(false);
    m_breakpointTable->horizontalHeader()->setStretchLastSection(true);
    installMemoryUtilityCopyMenu(m_breakpointTable);
    breakpointLayout->addWidget(m_breakpointTable, 1);

    QWidget* bookmarkPanel = new QWidget(splitter);
    QVBoxLayout* bookmarkLayout = new QVBoxLayout(bookmarkPanel);
    bookmarkLayout->setContentsMargins(0, 0, 0, 0);
    bookmarkLayout->setSpacing(4);

    bookmarkLayout->addWidget(createBackendSelector(
        bookmarkPanel, m_bookmarkBackendCombo, m_bookmarkBackendHintLabel));

    QHBoxLayout* bmButtonLayout = new QHBoxLayout();
    bmButtonLayout->setContentsMargins(0, 0, 0, 0);
    bmButtonLayout->setSpacing(6);
    m_addBookmarkButton = new QPushButton(QIcon(":/Icon/plus.svg"), "添加书签", bookmarkPanel);
    m_removeBookmarkButton = new QPushButton(QIcon(":/Icon/log_clear.svg"), "删除书签", bookmarkPanel);
    m_refreshBookmarkButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新值", bookmarkPanel);
    m_jumpBookmarkButton = new QPushButton(QIcon(":/Icon/codeeditor_goto.svg"), "跳转", bookmarkPanel);
    m_addBookmarkButton->setToolTip("把当前地址收藏为书签，便于之后快速回到该位置");
    m_removeBookmarkButton->setToolTip("删除选中的书签");
    m_refreshBookmarkButton->setToolTip("使用所选后端在后台读取每个书签的 8 字节当前值；失败或读取不完整时显示状态。");
    m_jumpBookmarkButton->setToolTip("在内存查看器中跳转到选中书签的地址");
    m_addBookmarkButton->setStyleSheet(buttonStyle);
    m_removeBookmarkButton->setStyleSheet(buttonStyle);
    m_refreshBookmarkButton->setStyleSheet(buttonStyle);
    m_jumpBookmarkButton->setStyleSheet(buttonStyle);
    bmButtonLayout->addWidget(m_addBookmarkButton);
    bmButtonLayout->addWidget(m_removeBookmarkButton);
    bmButtonLayout->addWidget(m_refreshBookmarkButton);
    bmButtonLayout->addWidget(m_jumpBookmarkButton);
    bmButtonLayout->addStretch(1);
    bookmarkLayout->addLayout(bmButtonLayout);

    m_bookmarkTable = new ks::ui::VisibleTableWidget(bookmarkPanel);
    m_bookmarkTable->setColumnCount(4);
    m_bookmarkTable->setHorizontalHeaderLabels(QStringList{ "地址", "当前值", "备注", "添加时间" });
    m_bookmarkTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_bookmarkTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_bookmarkTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_bookmarkTable->setAlternatingRowColors(true);
    m_bookmarkTable->verticalHeader()->setVisible(false);
    m_bookmarkTable->horizontalHeader()->setStretchLastSection(true);
    installMemoryUtilityCopyMenu(m_bookmarkTable);
    bookmarkLayout->addWidget(m_bookmarkTable, 1);

    splitter->addWidget(breakpointPanel);
    splitter->addWidget(bookmarkPanel);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 5);
    tabLayout->addWidget(splitter, 1);

    m_tabWidget->addTab(m_tabBpBookmark, "断点与书签");
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget, m_tabBpBookmark, QStringLiteral("memory.tab.breakpoints_bookmarks"), QStringLiteral("断点与书签"));
}

void MemoryDock::initializeDriverMemoryRwTab()
{
    // Tab6 初始化日志：记录驱动读写页开始构建。
    kLogEvent tab6InitEvent;
    info << tab6InitEvent
        << "[MemoryDock] initializeDriverMemoryRwTab: 构建驱动内存读写页面。"
        << eol;

    // Tab6：驱动内存读写，和原 Win32 查看器分离，避免编辑即写入真实内存。
    m_tabDriverMemoryRw = new QWidget(m_tabWidget);
    // 页面自带内部滚动壳：内容放不下时在页内滚动，不把 Dock 撑高。页面指针身份不变。
    QWidget* const tabContent = ks::ui::EnablePageInnerScroll(m_tabDriverMemoryRw);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // ========================================================
    // 目标分组：来源通道、目标对象、地址与读取预算
    // ========================================================

    QGroupBox* requestGroup = new QGroupBox("读取目标", m_tabDriverMemoryRw);
    QGridLayout* requestLayout = new QGridLayout(requestGroup);
    requestLayout->setHorizontalSpacing(8);
    requestLayout->setVerticalSpacing(6);

    // 来源下拉决定后续走哪条 R0 通道，条目顺序必须与 DriverMemorySourceMode 一致。
    m_driverMemorySourceCombo = new QComboBox(requestGroup);
    m_driverMemorySourceCombo->addItem("进程虚拟内存");
    m_driverMemorySourceCombo->addItem("内核虚拟内存");
    m_driverMemorySourceCombo->addItem("物理内存");
    m_driverMemorySourceCombo->setToolTip(
        "选择读写通道：进程虚拟内存按 PID 定位；内核虚拟内存直接使用内核地址；"
        "物理内存绕过页表，单次读上限 64 KB、写上限 4 KB。");

    m_driverMemoryBaseCombo = new PopupLifecycleGuardedComboBox(
        requestGroup,
        [this](const bool active) {
            m_driverMemoryBaseComboPopupLifecycleActive = active;
            if (!active)
            {
                flushProcessComboDeferredCommit();
            }
            });
    m_driverMemoryBaseCombo->setEditable(true);
    m_driverMemoryBaseCombo->setMinimumWidth(260);
    m_driverMemoryBaseCombo->setToolTip(
        "可输入 0、0x... 数值基址，或“模块名+十六进制偏移”（例如 client.dll+C125D9 或 CI.dll+1A2B）；"
        "其它非 0x 文本按进程名/PID 从下拉列表筛选目标进程。用户态模块取自当前附加进程，"
        "内核模块取自“刷新内核模块”得到的列表。中心地址为 0xFFFF... 高半区时自动按内核虚拟地址读取。");
    m_driverMemoryBaseCombo->addItem("0", QVariant::fromValue(static_cast<uint>(0U)));
    m_driverMemoryBaseCombo->setItemData(0, QString(), Qt::UserRole + 1);

    if (m_driverMemoryBaseCombo->lineEdit() != nullptr)
    {
        m_driverMemoryBaseCombo->lineEdit()->setPlaceholderText("0 / 0x基址 / 模块+偏移 / 进程名或PID");
    }

    // 内核模块列表按需加载：不点这个按钮就不会付出枚举全部内核模块的成本。
    m_driverMemoryKernelModuleRefreshButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")), "刷新内核模块", requestGroup);
    m_driverMemoryKernelModuleRefreshButton->setToolTip(
        "枚举系统已加载的内核模块，之后即可用“CI.dll+偏移”这类表达式直接定位内核地址。");

    m_driverMemoryAddressEdit = new QLineEdit(requestGroup);
    m_driverMemoryAddressEdit->setPlaceholderText("用户态有效地址/偏移，或 0xFFFF... 内核虚拟地址，或物理地址");
    m_driverMemoryAddressEdit->setClearButtonEnabled(true);

    m_driverMemoryBeforeSpin = new QSpinBox(requestGroup);
    m_driverMemoryBeforeSpin->setRange(0, static_cast<int>(KSWORD_ARK_MEMORY_READ_MAX_BYTES / 2UL));
    m_driverMemoryBeforeSpin->setValue(1024);
    m_driverMemoryBeforeSpin->setSuffix(" B");
    m_driverMemoryBeforeSpin->setToolTip("从中心地址往前额外读取的字节数");

    m_driverMemoryAfterSpin = new QSpinBox(requestGroup);
    m_driverMemoryAfterSpin->setRange(1, static_cast<int>(KSWORD_ARK_MEMORY_READ_MAX_BYTES / 2UL));
    m_driverMemoryAfterSpin->setValue(1024);
    m_driverMemoryAfterSpin->setSuffix(" B");
    m_driverMemoryAfterSpin->setToolTip("从中心地址往后额外读取的字节数");

    m_driverMemoryReadButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_details.svg")), "R0 读取", requestGroup);
    m_driverMemoryReadButton->setToolTip(
        "通过驱动以内核权限读取上述范围的内存，可读取普通方式无法访问的地址");

    requestLayout->addWidget(new QLabel("来源", requestGroup), 0, 0);
    requestLayout->addWidget(m_driverMemorySourceCombo, 0, 1);
    requestLayout->addWidget(new QLabel("目标", requestGroup), 0, 2);
    requestLayout->addWidget(m_driverMemoryBaseCombo, 0, 3, 1, 2);
    requestLayout->addWidget(m_driverMemoryKernelModuleRefreshButton, 0, 5);
    requestLayout->addWidget(new QLabel("中心地址", requestGroup), 1, 0);
    requestLayout->addWidget(m_driverMemoryAddressEdit, 1, 1, 1, 4);
    requestLayout->addWidget(m_driverMemoryReadButton, 1, 5);
    requestLayout->addWidget(new QLabel("向前", requestGroup), 2, 0);
    requestLayout->addWidget(m_driverMemoryBeforeSpin, 2, 1);
    requestLayout->addWidget(new QLabel("向后", requestGroup), 2, 2);
    requestLayout->addWidget(m_driverMemoryAfterSpin, 2, 3);
    // 让下拉框与地址框吃掉多余宽度，按钮列保持自身尺寸。
    requestLayout->setColumnStretch(1, 1);
    requestLayout->setColumnStretch(3, 2);
    requestLayout->setColumnStretch(4, 1);
    tabLayout->addWidget(requestGroup);

    // 访问后端选择条：本页的 R0 读取与差异写回都会走这里选中的通道。
    // 它与上方的"来源"下拉是两个正交的维度——来源决定"读哪块地址空间"，
    // 后端决定"用哪条通路去读"，不要把两者合并成一个下拉。
    tabLayout->addWidget(createBackendSelector(
        m_tabDriverMemoryRw, m_driverMemoryBackendCombo, m_driverMemoryBackendHintLabel));

    // ========================================================
    // 操作按钮条：写回、清空、转存、字符串写入
    // ========================================================

    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(6);

    m_driverMemoryApplyButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/disk_save.svg")), "应用差异到真实内存", m_tabDriverMemoryRw);
    m_driverMemoryApplyButton->setToolTip(
        "把下方编辑器中改动过的字节写回目标内存。这会真实修改进程或内核数据，"
        "内核路径带事务与失败回滚，用户态与物理内存路径没有回滚。");
    m_driverMemoryApplyButton->setEnabled(false);

    m_driverMemoryResetButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/log_clear.svg")), "清空缓存", m_tabDriverMemoryRw);
    m_driverMemoryResetButton->setToolTip("丢弃已读取的缓存与未应用的改动");

    m_driverMemoryDumpButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/log_export.svg")), "转存到文件", m_tabDriverMemoryRw);
    m_driverMemoryDumpButton->setToolTip(
        "把当前快照写入磁盘。保存为 .txt 时输出带地址与 ASCII 的十六进制转储，其余扩展名写原始字节。");

    m_driverMemoryWriteStringButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/codeeditor_paste.svg")), "字符串写入", m_tabDriverMemoryRw);
    m_driverMemoryWriteStringButton->setToolTip(
        "按 ANSI 或 UTF-16LE 把一段字符串填入编辑缓存，确认后再用“应用差异到真实内存”写回。");

    actionLayout->addWidget(m_driverMemoryApplyButton);
    actionLayout->addWidget(m_driverMemoryResetButton);
    actionLayout->addWidget(m_driverMemoryDumpButton);
    actionLayout->addWidget(m_driverMemoryWriteStringButton);
    actionLayout->addStretch(1);
    tabLayout->addLayout(actionLayout);

    m_driverMemoryRangeLabel = new QLabel("范围: 未读取", m_tabDriverMemoryRw);
    m_driverMemoryRangeLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    tabLayout->addWidget(m_driverMemoryRangeLabel);
    m_driverMemoryEditor = new ks::ui::MemoryEditorWidget(m_tabDriverMemoryRw);
    m_driverMemoryHexEditor = m_driverMemoryEditor->hexEditor();
    m_driverMemoryEditor->setEditable(false);
    tabLayout->addWidget(m_driverMemoryEditor, 1);

    m_driverMemoryStatusLabel = new QLabel("等待读取。", m_tabDriverMemoryRw);
    m_driverMemoryStatusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_driverMemoryStatusLabel->setWordWrap(true);
    tabLayout->addWidget(m_driverMemoryStatusLabel);

    // 危险按钮与状态标签使用语义色，构造期与主题切换走同一条下发路径。
    applyMemoryDockSemanticStyles();

    m_tabWidget->addTab(m_tabDriverMemoryRw, "驱动内存读写");
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget, m_tabDriverMemoryRw, QStringLiteral("memory.tab.driver_memory_rw"), QStringLiteral("驱动内存读写"));
}
