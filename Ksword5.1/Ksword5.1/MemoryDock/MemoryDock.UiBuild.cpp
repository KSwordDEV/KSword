#include "MemoryDock.Internal.h"
#include "../UI/AsyncOperation.h"
#include "SystemMemoryAuditPage.h"
#include "DdmaPage.h"
#include "MemoryDebugPage.h"
#include "../UI/MemoryPageNavigationSchema.h"
#include "../UI/MemoryWorkbench/MemoryWorkbenchView.h"
#include <QStackedWidget>
#include "../MiscDock/HvciBypass/HvciBypassPage.h"
#include "../MiscDock/HvciBypass/RxpfPage.h"
#include "../UI/AdaptivePageScroll.h" // ks::ui::EnablePageInnerScroll / IsolateMinimumSize：页内滚动壳与最小尺寸隔离。
#include "../UI/VisibleTableWidget.h"
#include "../UI/ThemeBinding.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/PerfTrace.h"
#include <QFormLayout>
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TableRowFilterSupport.h"
#include "../UI/TableInteractionSupport.h"
#include "../Internationalization/LanguageManager.h"

#include <QCompleter> // 进程下拉的包含式补全需要完整类型。
#include <QSignalBlocker>

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
    enum class MemorySearchText
    {
        Condition, TypeByte, TypeInt16, TypeInt32, TypeInt64, TypeFloat32, TypeFloat64,
        TypeBytes, TypeAscii, TypeUnicode, ValuePlaceholder, RangeAll, RangeCustom,
        RangeStart, RangeEnd, ImageOnly, HeapOnly, StackOnly, FirstScan, NextScan,
        Reset, Cancel, TypeCaption, ValueCaption, RangeCaption, Compare,
        Equal, Greater, Less, Between, Changed, Unchanged, Increased, Decreased,
        ValueA, ValueB, CompareConditionCaption, CompareValueCaption,
        BackendUser, BackendDriver, BackendHvm, BackendDdma, BackendCaption, Status
    };
    struct MemorySearchTextEntry
    {
        const char* target;
        const char* source;
        bool mnemonic;
    };
    constexpr MemorySearchTextEntry kMemorySearchTexts[] = {
        {"ks_memory_search_condition", "搜索条件", false},
        {"ks_memory_search_type", "字节", false},
        {"ks_memory_search_type", "2字节", false},
        {"ks_memory_search_type", "4字节", false},
        {"ks_memory_search_type", "8字节", false},
        {"ks_memory_search_type", "浮点数", false},
        {"ks_memory_search_type", "双精度", false},
        {"ks_memory_search_type", "字节数组(支持??)", false},
        {"ks_memory_search_type", "ASCII字符串", false},
        {"ks_memory_search_type", "Unicode字符串", false},
        {"ks_memory_search_value", "输入搜索值", false},
        {"ks_memory_search_range", "整个内存", false},
        {"ks_memory_search_range", "自定义范围", false},
        {"ks_memory_search_range_start", "起始地址", false},
        {"ks_memory_search_range_end", "结束地址", false},
        {"ks_memory_search_image_only", "仅映像", true},
        {"ks_memory_search_heap_only", "仅堆(近似)", true},
        {"ks_memory_search_stack_only", "仅栈(近似)", true},
        {"ks_memory_search_first_scan", "首次扫描", true},
        {"ks_memory_search_next_scan", "再次扫描", true},
        {"ks_memory_search_reset", "重置", true},
        {"ks_memory_search_cancel", "取消扫描", true},
        {"ks_memory_search_type_caption", "数据类型", false},
        {"ks_memory_search_value_caption", "值", false},
        {"ks_memory_search_range_caption", "范围", false},
        {"ks_memory_search_compare", "再次扫描过滤", false},
        {"ks_memory_search_compare_mode", "等于", false},
        {"ks_memory_search_compare_mode", "大于", false},
        {"ks_memory_search_compare_mode", "小于", false},
        {"ks_memory_search_compare_mode", "介于", false},
        {"ks_memory_search_compare_mode", "变化", false},
        {"ks_memory_search_compare_mode", "未变化", false},
        {"ks_memory_search_compare_mode", "增加", false},
        {"ks_memory_search_compare_mode", "减少", false},
        {"ks_memory_search_value_a", "值A", false},
        {"ks_memory_search_value_b", "值B", false},
        {"ks_memory_search_compare_condition_caption", "条件", false},
        {"ks_memory_search_compare_value_caption", "值", false},
        {"ks_memory_search_backend", "R3（ReadProcessMemory）", false},
        {"ks_memory_search_backend", "R0（驱动通道）", false},
        {"ks_memory_search_backend", "HVM（私有页表窗口）", false},
        {"ks_memory_search_backend", "DDMA（磁盘 DMA）", false},
        {"ks_memory_search_backend_caption", "访问后端", false},
        {"ks_memory_search_status", "就绪", false}
    };
    constexpr char kMemorySearchBackendHintTarget[] = "ks_memory_search_backend_hint";
    constexpr char kMemorySearchTableTarget[] = "ks_memory_search_table";
    constexpr char kMemorySearchActionsPrefix[] = "ks_memory_search_actions";

    const MemorySearchTextEntry& memorySearchEntry(MemorySearchText id)
    {
        return kMemorySearchTexts[static_cast<int>(id)];
    }
    QString memorySearchSource(MemorySearchText id)
    {
        return QString::fromUtf8(memorySearchEntry(id).source);
    }
    QString memorySearchTarget(MemorySearchText id)
    {
        return QString::fromLatin1(memorySearchEntry(id).target);
    }
    QStringList memorySearchHeaders()
    {
        return {QStringLiteral("地址"), QStringLiteral("当前值"), QStringLiteral("前次值"), QStringLiteral("备注")};
    }
    QString memorySearchBackendHint(bool ddmaUsable, const QString& reason)
    {
        return ddmaUsable ? QStringLiteral("DDMA 通道已就绪，可随时切换。")
            : QStringLiteral("DDMA 暂不可用：%1").arg(reason);
    }

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

}

MemoryDock::MemoryDock(QWidget* parent, const PageScope scope)
    : QWidget(parent), m_workbenchEmbedded(scope == PageScope::ProcessDetail)
{
    // 记录构造起点日志：用于追踪内存页控件的生命周期。
    kLogEvent constructStartEvent;
    info << constructStartEvent
        << "[MemoryDock] 开始构造内存页面控件。"
        << eol;

    // 构造阶段按固定顺序执行，确保 UI 控件先创建再绑定信号。
    initializeUi();
    initializeConnections();
    if (m_workbenchEmbedded) { setProcessDetailMemoryScope(); }
    initializeWorkbenchLivenessTimer();
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
    if (m_moduleNavigationOperation != nullptr) m_moduleNavigationOperation->close();
    cancelCoreProjection(true);
    // 首先关闭后台投递门禁；正在读取的区域转储将在下一分块边界取消原子文件发布。
    if (m_regionDumpOperation != nullptr)
    {
        tryCancelMemoryRegionDump();
        m_regionDumpOperation->close();
    }
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
    // 方形宿主包住的是完整内存页，过渡覆盖页头/工具条/状态栏外围，不落在中部Tab。
    ks::ui::StyleWorkspaceContentFrame(this, 6);
}

void MemoryDock::applyMemoryDockSemanticStyles()
{
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
    // 目标进程区独立于功能页签，增加轻底面但不增加控件行数。
    ks::ui::StylePrimaryToolbar(toolbarContainer);
    m_toolbarLayout = new QHBoxLayout(toolbarContainer);
    m_toolbarLayout->setContentsMargins(8, 4, 8, 4);
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
    ks::ui::NormalizeToolbarRow(m_toolbarLayout);
    ks::ui::StylePrimaryCombo(m_processCombo);
    ks::ui::ApplyFlatButtonTheme(m_attachButton, ks::ui::FlatButtonTone::Accent);
    ks::ui::ApplyFlatButtonTheme(m_detachButton, ks::ui::FlatButtonTone::Neutral);
    ks::ui::ApplyFlatButtonTheme(m_refreshButton, ks::ui::FlatButtonTone::Neutral);
    ks::ui::ApplyFlatButtonTheme(m_settingsButton, ks::ui::FlatButtonTone::Neutral);

    m_rootLayout->addWidget(toolbarContainer);
}

struct MemoryDock::PageFactory {
    const char *id, *languageKey, *title, *icon;
    bool processDetail, eager;
    std::function<void(MemoryDock&)> build;
    std::function<QWidget*(MemoryDock&)> page;
    std::function<void(MemoryDock&, QWidget*)> assignShell;
    void (MemoryDock::*wire)() = nullptr;
    ks::ui::MemoryNavigationGroup children = ks::ui::MemoryNavigationGroup::None;
};
const std::vector<MemoryDock::PageFactory>& MemoryDock::pageFactories()
{
    static const std::vector<PageFactory> factories{
        {"process_module", "memory.tab.process_module", "进程与模块", ":/Icon/process_list.svg", true, true, [](MemoryDock& d) { d.initializeProcessModuleTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_tabProcessModule; }, [](MemoryDock& d, QWidget* p) { d.m_tabProcessModule = p; }, &MemoryDock::initializeProcessConnections},
        {"regions", "memory.tab.regions", "内存区域", ":/Icon/disk_storage.svg", true, false, [](MemoryDock& d) { d.initializeMemoryRegionTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_tabRegions; }, [](MemoryDock& d, QWidget* p) { d.m_tabRegions = p; }, &MemoryDock::initializeRegionConnections},
        {"search", "memory.tab.search", "内存搜索", ":/Icon/codeeditor_find.svg", true, false, [](MemoryDock& d) { d.initializeMemorySearchTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_tabSearch; }, [](MemoryDock& d, QWidget* p) { d.m_tabSearch = p; }, &MemoryDock::initializeSearchConnections},
        {"workbench", "memory.tab.workbench", "内存工作台", ":/Icon/memwb_tab_hex.svg", true, true, [](MemoryDock& d) { d.initializeWorkbenchTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_tabWorkbench; }, [](MemoryDock& d, QWidget* p) { d.m_tabWorkbench = p; }, nullptr, ks::ui::MemoryNavigationGroup::Workbench},
        {"memory_debug", "memory.tab.debug", "内存调试", ":/Icon/memwb_tab_disasm.svg", false, false, [](MemoryDock& d) { d.initializeMemoryDebugTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_memoryDebugPage; }, {}, nullptr, ks::ui::MemoryNavigationGroup::Workbench},
        {"kernel_executable", "memory.tab.kernel_executable", "内核可执行页", ":/Icon/log_track.svg", false, false, [](MemoryDock& d) { d.initializeKernelExecutableMemoryScanTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_tabKernelExecutableMemory; }, [](MemoryDock& d, QWidget* p) { d.m_tabKernelExecutableMemory = p; }, &MemoryDock::initializeKernelExecutableConnections},
        {"kernel_evidence", "memory.tab.kernel_memory_evidence", "内核内存证据", ":/Icon/file_find.svg", false, false, [](MemoryDock& d) { d.initializeKernelMemoryEvidenceTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_tabKernelMemoryEvidence; }, [](MemoryDock& d, QWidget* p) { d.m_tabKernelMemoryEvidence = p; }, &MemoryDock::initializeKernelEvidenceConnections},
        {"process_pte", "memory.tab.pte_translate", "PTE / VA 翻译", ":/Icon/process_tree.svg", false, false, [](MemoryDock& d) { d.initializeProcessPteTranslateTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_tabProcessPteTranslate; }, [](MemoryDock& d, QWidget* p) { d.m_tabProcessPteTranslate = p; }, &MemoryDock::initializePteConnections},
        {"process_evidence", "memory.tab.process_memory_evidence", "进程内存证据", ":/Icon/process_performance.svg", false, false, [](MemoryDock& d) { d.initializeProcessMemoryEvidenceTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_tabProcessMemoryEvidence; }, [](MemoryDock& d, QWidget* p) { d.m_tabProcessMemoryEvidence = p; }, &MemoryDock::initializeProcessEvidenceConnections},
        {"system_audit", "memory.tab.system_memory_audit", "系统内存审计", ":/Icon/disk_analyze.svg", false, false, [](MemoryDock& d) { d.initializeSystemMemoryAuditTab(); d.ensureSystemMemoryAuditPage(); }, [](MemoryDock& d) -> QWidget* { return d.m_systemMemoryAuditPage; }, {}, nullptr, ks::ui::MemoryNavigationGroup::Audit},
        {"tamper_detection", "memory.tab.tamper_detection", "篡改检测", ":/Icon/process_critical.svg", false, false, [](MemoryDock& d) { d.initializeTamperDetectionTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_tamperDetectionPage; }, {}, nullptr},
        {"ddma", "memory.tab.ddma", "DDMA", ":/Icon/disk_storage.svg", false, false, [](MemoryDock& d) { d.initializeDdmaTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_ddmaPage; }, {}, nullptr, ks::ui::MemoryNavigationGroup::Workbench},
        {"hvci_bypass", "memory.tab.hvci_bypass", "HVCI 绕过", ":/Icon/process_priority.svg", false, false, [](MemoryDock& d) { d.initializeHvciBypassTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_hvciBypassPage; }, {}, nullptr},
        {"rxpf", "memory.tab.rxpf", "RXPF 模拟", ":/Icon/development/terminal_line.svg", false, false, [](MemoryDock& d) { d.initializeRxpfTab(); }, [](MemoryDock& d) -> QWidget* { return d.m_rxpfPage; }, {}, nullptr},
    };
    return factories;
}

namespace {
struct MemoryNavigationContainer {
    QPointer<QTabWidget> tabs;
    QPointer<QStackedWidget> stack;
    int count() const { return tabs ? tabs->count() : stack ? stack->count() : 0; }
    QWidget* widget(int index) const { return tabs ? tabs->widget(index) : stack ? stack->widget(index) : nullptr; }
    bool visible(int index) const { return tabs ? tabs->isTabVisible(index) : true; }
    bool enabled(int index) const { return widget(index) && widget(index)->isEnabled() &&
        (tabs ? tabs->isEnabled() && tabs->isTabEnabled(index) : stack && stack->isEnabled()); }
    int currentIndex() const { return tabs ? tabs->currentIndex() : stack ? stack->currentIndex() : -1; }
    QString title(int index) const {
        if (tabs) { return tabs->tabText(index); }
        const auto titles = stack ? stack->property("ksword_navigation_page_titles").toStringList() : QStringList();
        return index >= 0 && index < titles.size() ? titles[index] : QString();
    }
    void select(int index) const { if (tabs) { tabs->setCurrentIndex(index); } else if (stack) { stack->setCurrentIndex(index); } }
};
bool isMemoryNavigationContainer(QWidget* widget)
{
    return qobject_cast<QTabWidget*>(widget) || (qobject_cast<QStackedWidget*>(widget) &&
        widget->property("ksword_navigation_page_titles").isValid());
}
MemoryNavigationContainer memoryNavigationContainer(QWidget* root)
{
    MemoryNavigationContainer result;
    if (!root) { return result; }
    for (QWidget* child : root->findChildren<QWidget*>()) {
        if (!isMemoryNavigationContainer(child)) { continue; }
        bool nested = false;
        for (QWidget* parent = child->parentWidget(); parent && parent != root; parent = parent->parentWidget()) {
            if (isMemoryNavigationContainer(parent)) { nested = true; break; }
        }
        if (nested) { continue; }
        // Ambiguous groups fail navigation instead of selecting a different nested editor.
        if (result.tabs || result.stack) { return {}; }
        result.tabs = qobject_cast<QTabWidget*>(child); result.stack = qobject_cast<QStackedWidget*>(child);
    }
    return result;
}
void appendMemoryNavigationChildren(ks::ui::PageNavigationCatalog& catalog, const QString& parent,
    const ks::ui::MemoryNavigationGroup group, QWidget* root)
{
    const auto& tabs = ks::ui::MemoryNavigationTabs(group);
    if (tabs.empty()) { return; }
    const auto container = memoryNavigationContainer(root);
    for (int index = 0; index < static_cast<int>(tabs.size()); ++index) {
        const auto& spec = tabs[static_cast<std::size_t>(index)];
        ks::ui::PageNavigationDescriptor page;
        page.id = parent + QLatin1Char('.') + QString::fromLatin1(spec.id); page.parentId = parent;
        page.title = ks::ui::MemoryNavigationTabTitle(group, index); page.searchTexts = {QString::fromUtf8(spec.source)};
        QWidget* actual = nullptr;
        if (index < container.count()) {
            actual = container.widget(index); page.title = container.title(index);
            page.visible = container.visible(index); page.enabled = container.enabled(index); page.current = container.currentIndex() == index;
        } else { page.current = index == 0; }
        catalog.append(page);
        appendMemoryNavigationChildren(catalog, page.id, spec.children, actual);
    }
}
}

ks::ui::PageNavigationCatalog MemoryDock::navigationCatalog(const MemoryDock* existing,
    const bool includeColdSearchBody)
{
    ks::ui::PageNavigationCatalog catalog;
    for (const auto& factory : pageFactories()) {
        if (existing && existing->m_workbenchEmbedded && !factory.processDetail) { continue; }
        ks::ui::PageNavigationDescriptor page;
        page.id = QString::fromLatin1(factory.id);
        page.title = ks::i18n::text(QString::fromLatin1(factory.languageKey), QString::fromUtf8(factory.title));
        page.searchTexts = {QString::fromUtf8(factory.title)};
        QWidget* actual = nullptr;
        if (existing && existing->m_tabWidget) {
            const auto state = std::find_if(existing->m_lazyPages.begin(), existing->m_lazyPages.end(), [&](const auto& entry) { return entry.id == page.id; });
            if (state == existing->m_lazyPages.end()) { continue; }
            const int index = existing->m_tabWidget->indexOf(state->widget);
            if (index < 0) { continue; }
            page.title = existing->m_tabWidget->tabText(index);
            page.visible = existing->m_tabWidget->isTabVisible(index); page.enabled = existing->m_tabWidget->isEnabled() &&
                state->widget->isEnabled() && existing->m_tabWidget->isTabEnabled(index);
            page.current = existing->m_tabWidget->currentWidget() == state->widget;
            if (state->ready) { actual = state->widget; }
        } else { page.current = page.id == QLatin1String("process_module"); }
        if (includeColdSearchBody && !actual && page.id == QLatin1String("process_pte"))
        {
            page.coldBodyTexts = coldProcessPteSearchBody();
            page.coldBodyComplete = true;
        }
        else if (includeColdSearchBody && !actual && page.id == QLatin1String("search"))
        {
            page.coldBodyTexts = coldMemorySearchBody();
            page.coldBodyComplete = true;
        }
        catalog.append(page);
        appendMemoryNavigationChildren(catalog, page.id, factory.children, actual);
    }
    return catalog;
}

QWidget* MemoryDock::activateNavigationDescriptor(const QString& id)
{
    const QPointer<MemoryDock> owner(this);
    const auto resolved = ks::ui::ResolvePageNavigationCatalog(navigationCatalog(this, false), QString());
    if (!resolved) { return nullptr; }
    const auto desired = std::find_if(resolved->cbegin(), resolved->cend(), [&](const auto& page) { return page.page.id == id; });
    if (desired == resolved->cend() || !desired->page.visible || !desired->page.enabled) { return nullptr; }
    const auto path = id.split(QLatin1Char('.'));
    const auto factory = std::find_if(pageFactories().cbegin(), pageFactories().cend(), [&](const auto& item) { return path.front() == QLatin1String(item.id); });
    if (factory == pageFactories().cend()) { return nullptr; }
    const auto initialGroup = factory->children;
    QPointer<QWidget> root = ensureLazyPage(path.front());
    if (!owner || !root) { return nullptr; }
    const QPointer<QTabWidget> topTabs(owner->m_tabWidget);
    const QPointer<QWidget> topRoot(root);
    struct Route { MemoryNavigationContainer container; QPointer<QWidget> page; int index; };
    std::vector<Route> route;
    const auto valid = [&] {
        if (!owner || !topTabs || !topRoot || owner->m_tabWidget != topTabs || !topTabs->isEnabled() || !topRoot->isEnabled()) { return false; }
        const int topIndex = topTabs->indexOf(topRoot);
        if (topIndex < 0 || !topTabs->isTabVisible(topIndex) || !topTabs->isTabEnabled(topIndex) || topTabs->currentWidget() != topRoot) { return false; }
        for (const auto& step : route) {
            if (!step.page || step.index >= step.container.count() || step.container.widget(step.index) != step.page ||
                !step.container.visible(step.index) || !step.container.enabled(step.index) || step.container.currentIndex() != step.index) { return false; }
        }
        return true;
    };
    {
        const ks::ui::ScopedWidgetThemePreparation preparation(topRoot);
        if (!owner || !topTabs || !topRoot) { return nullptr; }
        topTabs->setCurrentWidget(topRoot);
        if (!valid()) { return nullptr; }
        if (initialGroup == ks::ui::MemoryNavigationGroup::Workbench) {
            if (path.front() == QLatin1String("workbench")) { owner->ensureWorkbenchView(); }
            if (!valid()) { return nullptr; }
            if (path.front() == QLatin1String("memory_debug") && owner->m_memoryDebugPage) { owner->m_memoryDebugPage->prepareForNavigation(); }
            if (!valid()) { return nullptr; }
        }
        auto group = initialGroup;
        for (qsizetype depth = 1; depth < path.size(); ++depth) {
            const auto& tabs = ks::ui::MemoryNavigationTabs(group);
            const auto child = std::find_if(tabs.cbegin(), tabs.cend(), [&](const auto& tab) { return path[depth] == QLatin1String(tab.id); });
            if (child == tabs.cend()) { return nullptr; }
            const int index = static_cast<int>(std::distance(tabs.cbegin(), child));
            const auto container = memoryNavigationContainer(root);
            if (index >= container.count() || !container.visible(index) || !container.enabled(index)) { return nullptr; }
            const QPointer<QWidget> childRoot(container.widget(index));
            route.push_back({container, childRoot, index});
            container.select(index);
            if (!valid() || !childRoot) { return nullptr; }
            root = childRoot; group = child->children;
            ks::ui::PrepareWidgetThemeBindingsForShow(root);
            if (!valid() || !root) { return nullptr; }
        }
    } // Theme-scope destruction may synchronously retire or reselect the route.
    if (!valid() || !root) { return nullptr; }
    ks::ui::PrepareWidgetThemeBindingsForShow(root);
    return valid() && root ? root.data() : nullptr;
}

namespace {
const bool kMemoryNavigationRegistered = ks::ui::RegisterTypedPageNavigationCatalog<MemoryDock>(QStringLiteral("memory"));
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
    // 进程选择头和功能页签连成一组，根布局中的其它状态区继续保留原间隔。
    auto* resultGroup = new QWidget(this);
    auto* resultLayout = new QVBoxLayout(resultGroup);
    resultLayout->setContentsMargins(0, 0, 0, 0);
    resultLayout->setSpacing(0);
    QWidget* const processHeader = m_toolbarLayout->parentWidget();
    m_rootLayout->removeWidget(processHeader);
    resultLayout->addWidget(processHeader);
    ks::ui::StyleJoinedResultTabs(m_tabWidget, processHeader);
    m_tabWidget->setDocumentMode(true);
    // 加固：QTabWidget 的页面栈会对所有页（含未显示、被隐藏的旧页）的最小高度取最大值。
    // 每个页面本身都已经带内部滚动壳（见 ks::ui::EnablePageInnerScroll），这里再把页签控件
    // 的最小尺寸隔离掉，这样以后有人新增页签却忘了包壳，表现为页内被裁剪，
    // 而不是把 Dock 的头部、工具栏和状态栏挤坏。
    ks::ui::IsolateMinimumSize(m_tabWidget);
    resultLayout->addWidget(m_tabWidget, 1);
    m_rootLayout->addWidget(resultGroup, 1);

    // The same ordered factory list owns main/embedded registration and first visits.
    const QSignalBlocker blocker(m_tabWidget);
    for (const auto& factory : pageFactories()) {
        if (m_workbenchEmbedded && !factory.processDetail) { continue; }
        LazyPage state; state.id = QString::fromLatin1(factory.id);
        if (factory.eager) {
            factory.build(*this); state.widget = factory.page(*this); state.ready = true;
        } else {
            state.widget = new QWidget(m_tabWidget);
            state.widget->setProperty("ksword_memory_lazy_page", state.id);
            if (state.id == QLatin1String("process_pte") || state.id == QLatin1String("search"))
                state.widget->setProperty("ksword_search_body_page_id", state.id);
            m_tabWidget->addTab(state.widget, QString::fromUtf8(factory.title));
            if (factory.assignShell) { factory.assignShell(*this, state.widget); }
        }
        const int index = m_tabWidget->indexOf(state.widget);
        m_tabWidget->setTabIcon(index, QIcon(QString::fromLatin1(factory.icon)));
        ks::i18n::LanguageManager::instance().bindTab(m_tabWidget, state.widget,
            QString::fromLatin1(factory.languageKey), QString::fromUtf8(factory.title));
        m_lazyPages.push_back(std::move(state));
    }
}

void MemoryDock::ensureCurrentLazyPage()
{
    if (!m_tabWidget) { return; }
    const auto current = m_tabWidget->currentWidget();
    for (const auto& state : m_lazyPages) {
        if (state.widget == current) { const auto id = state.id; ensureLazyPage(id); return; }
    }
}

QWidget* MemoryDock::ensureLazyPage(const QString& id)
{
    const QPointer<MemoryDock> owner(this);
    const QPointer<QTabWidget> tabs(m_tabWidget);
    if (!tabs) { return nullptr; }
    auto state = std::find_if(m_lazyPages.begin(), m_lazyPages.end(), [&](const auto& page) { return page.id == id; });
    if (state == m_lazyPages.end() || state->constructing) { return nullptr; }
    int index = tabs->indexOf(state->widget);
    if (index < 0 || !tabs->isEnabled() || !state->widget->isEnabled() || !tabs->isTabVisible(index) || !tabs->isTabEnabled(index)) { return nullptr; }
    if (state->ready) { return state->widget; }
    const auto factory = std::find_if(pageFactories().begin(), pageFactories().end(), [&](const auto& item) { return id == QLatin1String(item.id); });
    if (factory == pageFactories().end()) { return nullptr; }
    state->constructing = true;
    const QPointer<QWidget> shell(state->widget), previous(tabs->currentWidget());
    const bool selected = previous == shell;
    QPointer<QWidget> page;
    {
        const ks::ui::ScopedWidgetThemePreparation preparation(tabs);
        struct Signals {
            QPointer<QTabWidget> tabs; bool previous;
            ~Signals() { if (tabs) { tabs->blockSignals(previous); } }
        } blocker{tabs, tabs->blockSignals(true)};
        ks::ui::PerfScope performance("perf_memory_tab_construct", id);
        factory->build(*owner);
        if (!owner || !tabs || !shell) { return nullptr; }
        page = factory->page(*owner);
        if (!page) { state->constructing = false; return nullptr; }
        const int builtIndex = tabs->indexOf(page);
        if (builtIndex >= 0) { tabs->removeTab(builtIndex); }
        index = tabs->indexOf(shell);
        if (index < 0) { state->constructing = false; return nullptr; }
        const QString text = tabs->tabText(index);
        const QIcon icon = tabs->tabIcon(index);
        tabs->removeTab(index); tabs->insertTab(index, page, icon, text);
        ks::i18n::LanguageManager::instance().bindTab(tabs, page,
            QString::fromLatin1(factory->languageKey), QString::fromUtf8(factory->title));
        if (!owner || !tabs || !page) { return nullptr; }
        state->widget = page; state->ready = true; state->constructing = false;
        if (owner->m_pageConnectionsReady && factory->wire) { (owner.data()->*factory->wire)(); }
        if (!owner || !tabs || !page) { return nullptr; }
        if (id == QLatin1String("regions")) { owner->applyRegionFilterAndRebuildTable(); }
        if (!owner || !tabs || !page) { return nullptr; }
        if (id == QLatin1String("search")) { owner->rebuildSearchResultTable(); if (owner) { owner->refreshBackendSelectors(); } }
        if (!owner || !tabs || !page) { return nullptr; }
        if (selected || !previous) { tabs->setCurrentWidget(page); }
        else { tabs->setCurrentWidget(previous); }
        if (shell)
        {
            shell->setProperty("ksword_search_body_page_id", QVariant());
            if (!owner || !tabs || !page) { return nullptr; }
            if (shell) shell->deleteLater();
        }
    }
    // The final theme preparation can synchronously close or reselect its host.
    if (!owner || !tabs || !page || owner->m_tabWidget != tabs) { return nullptr; }
    index = tabs->indexOf(page);
    if (index < 0 || !tabs->isEnabled() || !page->isEnabled() || !tabs->isTabVisible(index) || !tabs->isTabEnabled(index) ||
        (selected && tabs->currentWidget() != page)) { return nullptr; }
    return page.data();
}

void MemoryDock::initializeHvciBypassTab()
{
    m_hvciBypassPage = new ks::misc::HvciBypassPage(m_tabWidget);
    m_tabWidget->addTab(m_hvciBypassPage, QStringLiteral("HVCI 绕过"));
}
void MemoryDock::initializeRxpfTab()
{
    m_rxpfPage = new ks::misc::RxpfPage(m_tabWidget);
    m_tabWidget->addTab(m_rxpfPage, QStringLiteral("RXPF 模拟"));
}

void MemoryDock::initializeSystemMemoryAuditTab()
{
    // 系统审计页包含多张表、归因图和 PFN/Hyper-V 子页，首开构造成本明显高于其它
    // MemoryDock 页面。先挂轻量占位页，首次切入时由 ensureSystemMemoryAuditPage 原位替换。
    m_systemMemoryAuditPlaceholder = new QWidget(m_tabWidget);
    m_tabWidget->addTab(m_systemMemoryAuditPlaceholder, QStringLiteral("系统内存审计"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget,
        m_systemMemoryAuditPlaceholder,
        QStringLiteral("memory.tab.system_memory_audit"),
        QStringLiteral("系统内存审计"));
}

void MemoryDock::ensureSystemMemoryAuditPage()
{
    if (m_systemMemoryAuditPage != nullptr ||
        m_systemMemoryAuditPlaceholder == nullptr ||
        m_systemMemoryAuditPageConstructing ||
        m_tabWidget == nullptr)
    {
        return;
    }

    const int tabIndex = m_tabWidget->indexOf(m_systemMemoryAuditPlaceholder);
    if (tabIndex < 0)
    {
        return;
    }

    m_systemMemoryAuditPageConstructing = true;
    const bool wasCurrent = m_tabWidget->currentWidget() == m_systemMemoryAuditPlaceholder;
    const QString tabText = m_tabWidget->tabText(tabIndex);
    const QIcon tabIcon = m_tabWidget->tabIcon(tabIndex);

    auto* const page = new SystemMemoryAuditPage(m_tabWidget);
    page->openModuleDetails = [this](const QString& path) {
        const auto handler = openPoolModuleDetails;
        if (handler) { handler(path); }
    };
    page->setDdmaSessionProvider(
        [this]() -> const ksword::memory_backend::DdmaSession& {
            return currentDdmaSession();
        });

    {
        const QSignalBlocker blocker(m_tabWidget);
        m_tabWidget->removeTab(tabIndex);
        m_tabWidget->insertTab(tabIndex, page, tabText);
        m_tabWidget->setTabIcon(tabIndex, tabIcon);
    }
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget,
        page,
        QStringLiteral("memory.tab.system_memory_audit"),
        QStringLiteral("系统内存审计"));

    QWidget* const placeholder = m_systemMemoryAuditPlaceholder;
    m_systemMemoryAuditPlaceholder = nullptr;
    m_systemMemoryAuditPage = page;
    m_systemMemoryAuditPageConstructing = false;
    if (placeholder != nullptr)
    {
        placeholder->deleteLater();
    }

    if (wasCurrent)
    {
        m_tabWidget->setCurrentIndex(tabIndex);
    }
}

void MemoryDock::initializeTamperDetectionTab()
{
    // 放在 DDMA 页**之前**挂载，但依赖它的会话：DDMA 通道是本页唯一一条不经过
    // CPU 页表的读取路径，没有它这一页就只能发现普通补丁。页面自己会在通道不可用
    // 时把这句话写在界面上，而不是只把复选框置灰。
    m_tamperDetectionPage = new ksword::memory_dock::TamperDetectionPage(m_tabWidget);
    const QPointer<MemoryDock> owner(this);
    m_tamperDetectionPage->setHvmAvailabilityRequester([owner]() {
        if (owner && owner->requestHvmMemoryAvailability) owner->requestHvmMemoryAvailability();
    });
    m_tabWidget->addTab(m_tamperDetectionPage, QStringLiteral("篡改检测"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget,
        m_tamperDetectionPage,
        QStringLiteral("memory.tab.tamper_detection"),
        QStringLiteral("篡改检测"));
}

bool MemoryDock::needsHvmMemoryAvailability() const
{
    return m_tamperDetectionPage && m_tamperDetectionPage->isVisible();
}

quint64 MemoryDock::hvmMemoryAvailabilityEpoch() const
{
    return m_tamperDetectionPage ? m_tamperDetectionPage->hvmAvailabilityEpoch() : 0;
}

void MemoryDock::invalidateHvmMemoryAvailability()
{
    if (m_tamperDetectionPage) m_tamperDetectionPage->invalidateHvmAvailability();
}

void MemoryDock::applyHvmMemoryAvailability(const quint64 epoch, const bool usable, const QString& reason)
{
    if (m_tamperDetectionPage) m_tamperDetectionPage->applyHvmAvailability(epoch, usable, reason);
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
    const QPointer<MemoryDock> owner(this);
    const QPointer<QWidget> page(ensureLazyPage(QStringLiteral("ddma")));
    if (owner && page && owner->m_tabWidget) { owner->m_tabWidget->setCurrentWidget(page); }
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
    // 内存后端是明确的操作条件，完整底面和同高控件便于识别可切换状态。
    ks::ui::StylePrimaryCombo(comboOut);
    ks::ui::NormalizeToolbarControl(comboOut);
    // 条目顺序必须与 MemoryAccessBackend 枚举一致，界面按索引直接转换。
    comboOut->addItem(memorySearchSource(MemorySearchText::BackendUser));
    comboOut->addItem(memorySearchSource(MemorySearchText::BackendDriver));
    comboOut->addItem(memorySearchSource(MemorySearchText::BackendHvm));
    comboOut->addItem(memorySearchSource(MemorySearchText::BackendDdma));
    comboOut->setToolTip(
        QStringLiteral("R3 走 ReadProcessMemory / WriteProcessMemory，不经驱动，受句柄权限与进程保护约束，也读不了内核地址和物理地址。\nR0 走驱动的 MmCopyVirtualMemory / MmMapIoSpaceEx，绕开句柄权限，能读内核地址与物理地址，但仍受 SLAT / EPT 约束。\nHVM 改写自有页表项指向目标帧，整条路径不调用任何文档化的内存管理器例程，别的驱动挂钩那些例程挂不到它头上；它同样受 SLAT / EPT 约束，与 R0 分歧说明的是内存管理器被挂了钩，而不是重定向。\nDDMA 走磁盘控制器的总线主控 DMA，不受 SLAT 约束，能读到被上层虚拟化重定向或隐藏的物理页；代价是必须借用磁盘扇区中转，而且明显更慢，需要先在“DDMA”子页配置通道。\n同一个地址几条读到的结果不一样本身就是判据，而分歧落在哪两条之间决定了它说明什么。"));

    hintOut = new QLabel(container);
    hintOut->setWordWrap(true);
    hintOut->setTextInteractionFlags(Qt::TextSelectableByMouse);

    layout->addWidget(new QLabel(memorySearchSource(MemorySearchText::BackendCaption), container));
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
            hint->setText(memorySearchBackendHint(ddmaUsable, reason));
            hint->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::SuccessHex()));
        }
        else
        {
            hint->setText(memorySearchBackendHint(ddmaUsable, reason));
            hint->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        }
        };

    syncOne(m_searchBackendCombo, m_searchBackendHintLabel);

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
    QWidget* const processToolbar = new QWidget(processPanel);
    ks::ui::StylePrimaryToolbar(processToolbar);
    QHBoxLayout* processTopBarLayout = new QHBoxLayout(processToolbar);
    processTopBarLayout->setContentsMargins(8, 4, 8, 4);
    processTopBarLayout->setSpacing(8);
    processTopBarLayout->addWidget(new QLabel("进程列表（双击自动附加）", processPanel));

    // 过滤框对齐下面的模块表：模块表一直有，进程表反而没有，而进程数远多于模块数。
    m_processFilterEdit = new QLineEdit(processPanel);
    m_processFilterEdit->setPlaceholderText("按进程名或 PID 过滤");
    m_processFilterEdit->setClearButtonEnabled(true);
    m_processFilterEdit->setStyleSheet(buildBlueInputStyle());
    // 进程专用搜索保留具体提示和原输入几何，只接管无线框底面及文字对比度。
    ks::ui::StyleSearchField(m_processFilterEdit);
    processTopBarLayout->addWidget(m_processFilterEdit, 1);

    m_processCountLabel = new QLabel(processPanel);
    m_processCountLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    processTopBarLayout->addWidget(m_processCountLabel);

    processLayout->addWidget(processToolbar);
    ks::ui::NormalizeToolbarRow(processTopBarLayout);

    m_processTable = new MemoryTableView(processPanel);
    // 这里是附加目标选择器，主进程页已有现场功能，不重复放快照栏。
    ks::ui::SetTableActionBarMode(m_processTable, ks::ui::TableActionBarMode::None);
    m_processTable->setHorizontalHeaderLabels(QStringList{ "进程名", "PID", "会话ID", "CPU(可选)", "工作集" });
    m_processTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_processTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_processTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_processTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_processTable->setSortingEnabled(true);
    m_processTable->horizontalHeader()->setSortIndicator(0, Qt::AscendingOrder);
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
    m_processTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Interactive);
    m_processTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Interactive);
    m_processTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Interactive);
    m_processTable->setShowGrid(true);
    ks::ui::SetTableColumnAutoFitEnabled(m_processTable, false);
    ks::ui::SetTableRowFilterBusinessOwnership(m_processTable, ks::ui::TableRowFilterBusinessOwnership::ExclusiveSharedIdentity);
    processLayout->addWidget(m_processTable, 1);
    initializeCoreProjection(CoreKind::Processes);
    m_processCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_processCombo->setMinimumContentsLength(16);
    m_processComboModel = new ks::memory_detail::CoreListModel(m_processCombo);
    m_processCombo->setProperty("ks_i18n_preserve_model_data", true);
    m_processCombo->setModel(m_processComboModel);

    QWidget* modulePanel = new QWidget(splitter);
    QVBoxLayout* moduleLayout = new QVBoxLayout(modulePanel);
    moduleLayout->setContentsMargins(0, 0, 0, 0);
    moduleLayout->setSpacing(4);

    // 模块区域布局对齐 ProcessDetailWindow：刷新按钮 + 签名选项 + 状态 + 模块表。
    // 双表各自拥有筛选条，分割拖动后仍能辨别操作属于哪张表。
    QWidget* const moduleToolbar = new QWidget(modulePanel);
    ks::ui::StylePrimaryToolbar(moduleToolbar);
    QHBoxLayout* moduleTopBarLayout = new QHBoxLayout(moduleToolbar);
    moduleTopBarLayout->setContentsMargins(8, 4, 8, 4);
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
    // 模块表为 QTreeWidget，不走通用 QTableView 识别，需明确登记同一搜索主题。
    ks::ui::StyleSearchField(m_moduleFilterEdit);
    moduleTopBarLayout->addWidget(m_moduleFilterEdit, 1);

    m_moduleStatusLabel = new QLabel("● 待刷新", modulePanel);
    m_moduleStatusLabel->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
            .arg(KswordTheme::TextSecondaryHex()));
    moduleTopBarLayout->addWidget(m_moduleStatusLabel);
    moduleLayout->addWidget(moduleToolbar);
    ks::ui::NormalizeToolbarRow(moduleTopBarLayout);

    m_moduleTable = new MemoryTreeView(modulePanel);
    // 模块树已有刷新/筛选与业务复制菜单，不安装重复的表格操作条。
    m_moduleTable->setProperty(ks::ui::TableActionBarModeProperty, static_cast<int>(ks::ui::TableActionBarMode::None));
    m_moduleTable->setHeaderLabels(ModuleTreeHeaders);
    m_moduleTable->setRootIsDecorated(false);
    m_moduleTable->setItemsExpandable(false);
    m_moduleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_moduleTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_moduleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_moduleTable->setAlternatingRowColors(true);
    m_moduleTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_moduleTable->setSortingEnabled(true);
    m_moduleTable->header()->setSortIndicator(0, Qt::AscendingOrder);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::Path), 460);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::Size), 110);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::Signature), 220);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::EntryOffset), 120);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::State), 100);
    m_moduleTable->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::ThreadId), 180);
    moduleLayout->addWidget(m_moduleTable, 1);
    initializeCoreProjection(CoreKind::Modules);

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
    // 区域结果过滤与扫描值/范围地址输入分开登记。
    ks::ui::StyleSearchField(m_regionFilterEdit);
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
    ks::ui::NormalizeToolbarRow(actionLayout);
    tabLayout->addLayout(actionLayout);

    // 过滤开关收进分组框，避免和动作行挤在一起。
    QGroupBox* filterGroup = new QGroupBox("过滤条件", m_tabRegions);
    ks::ui::StylePrimaryGroup(filterGroup);
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
    ks::ui::NormalizeToolbarRow(filterLayout);
    tabLayout->addWidget(filterGroup);

    m_regionTable = new MemoryTableView(m_tabRegions);
    // 区域清单需要前后快照排查映射变化，保留完整操作栏。
    ks::ui::SetTableActionBarMode(m_regionTable, ks::ui::TableActionBarMode::Full);
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
    m_regionTable->horizontalHeader()->setDefaultSectionSize(128);
    ks::ui::SetTableColumnAutoFitEnabled(m_regionTable, false);
    ks::ui::SetTableRowFilterBusinessOwnership(m_regionTable, ks::ui::TableRowFilterBusinessOwnership::ExclusiveSharedIdentity);
    tabLayout->addWidget(m_regionTable, 1);
    initializeCoreProjection(CoreKind::Regions);

    m_tabWidget->addTab(m_tabRegions, "内存区域");
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget, m_tabRegions, QStringLiteral("memory.tab.regions"), QStringLiteral("内存区域"));
}

QVector<ks::ui::PageSearchBodyText> MemoryDock::coldMemorySearchBody()
{
    QVector<ks::ui::PageSearchBodyText> body;
    body.reserve(50);
    const auto text = [](MemorySearchText id) { return ks::i18n::sourceText(memorySearchSource(id)); };
    const auto append = [&body, &text](MemorySearchText id, const QStringList& groups = {})
    {
        body.append({text(id), memorySearchTarget(id), groups, memorySearchEntry(id).mnemonic});
    };
    // ParameterWorkspace reparents the condition/compare/backend panels into
    // the parameter canvas and the four buttons into its fixed action footer.
    append(MemorySearchText::Condition);
    const QStringList condition{text(MemorySearchText::Condition)};
    for (const auto id : {MemorySearchText::TypeByte, MemorySearchText::TypeInt16,
        MemorySearchText::TypeInt32, MemorySearchText::TypeInt64, MemorySearchText::TypeFloat32,
        MemorySearchText::TypeFloat64, MemorySearchText::TypeBytes, MemorySearchText::TypeAscii,
        MemorySearchText::TypeUnicode, MemorySearchText::ValuePlaceholder, MemorySearchText::RangeAll,
        MemorySearchText::RangeCustom, MemorySearchText::RangeStart, MemorySearchText::RangeEnd,
        MemorySearchText::ImageOnly, MemorySearchText::HeapOnly, MemorySearchText::StackOnly,
        MemorySearchText::TypeCaption, MemorySearchText::ValueCaption, MemorySearchText::RangeCaption})
        append(id, condition);
    append(MemorySearchText::Compare);
    const QStringList compare{text(MemorySearchText::Compare)};
    for (const auto id : {MemorySearchText::Equal, MemorySearchText::Greater, MemorySearchText::Less,
        MemorySearchText::Between, MemorySearchText::Changed, MemorySearchText::Unchanged,
        MemorySearchText::Increased, MemorySearchText::Decreased, MemorySearchText::ValueA,
        MemorySearchText::CompareConditionCaption, MemorySearchText::CompareValueCaption})
        append(id, compare);
    // ValueB is explicitly hidden in the initial Equal mode. Disabled range
    // inputs and scan actions stay revealable and retain their original texts.
    for (const auto id : {MemorySearchText::BackendUser, MemorySearchText::BackendDriver,
        MemorySearchText::BackendHvm, MemorySearchText::BackendDdma}) append(id);
    QString reason;
    const bool ddmaUsable = ksword::memory_backend::isDdmaUsable(
        ksword::memory_backend::currentDdmaSession(), &reason);
    body.append({ks::i18n::sourceText(memorySearchBackendHint(ddmaUsable, reason)),
        QString::fromLatin1(kMemorySearchBackendHintTarget), {}, false});
    append(MemorySearchText::BackendCaption);
    for (const auto id : {MemorySearchText::FirstScan, MemorySearchText::NextScan,
        MemorySearchText::Reset, MemorySearchText::Cancel}) append(id);
    for (const auto& header : memorySearchHeaders())
        body.append({ks::i18n::sourceText(header), QString::fromLatin1(kMemorySearchTableTarget), {}, false});
    body += ks::ui::ColdCompactTableActionBody(QString::fromLatin1(kMemorySearchActionsPrefix));
    append(MemorySearchText::Status);
    return body;
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
    // 扫描条件独立滚动，扫描/取消固定，结果表保持完整工作高度。
    QWidget* const tabContent = m_tabSearch; // 工作区已管理内部滚动，固定动作与结果不再随整页滚动。
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);
    auto* workspace = new ks::ui::ParameterWorkspace(m_tabSearch, 420);
    tabLayout->addWidget(workspace);

    const QString inputStyle = buildBlueInputStyle();
    const QString buttonStyle = buildBlueButtonStyle();

    // 搜索条件面板。
    QGroupBox* conditionGroup = new QGroupBox(memorySearchSource(MemorySearchText::Condition), m_tabSearch);
    conditionGroup->setObjectName(memorySearchTarget(MemorySearchText::Condition));
    ks::ui::StyleParameterSection(conditionGroup);
    QGridLayout* conditionLayout = new QGridLayout(conditionGroup);
    conditionLayout->setHorizontalSpacing(8);
    conditionLayout->setVerticalSpacing(6);

    m_searchTypeCombo = new QComboBox(conditionGroup);
    m_searchTypeCombo->setObjectName(memorySearchTarget(MemorySearchText::TypeByte));
    m_searchTypeCombo->addItem(memorySearchSource(MemorySearchText::TypeByte), static_cast<int>(SearchValueType::Byte));
    m_searchTypeCombo->addItem(memorySearchSource(MemorySearchText::TypeInt16), static_cast<int>(SearchValueType::Int16));
    m_searchTypeCombo->addItem(memorySearchSource(MemorySearchText::TypeInt32), static_cast<int>(SearchValueType::Int32));
    m_searchTypeCombo->addItem(memorySearchSource(MemorySearchText::TypeInt64), static_cast<int>(SearchValueType::Int64));
    m_searchTypeCombo->addItem(memorySearchSource(MemorySearchText::TypeFloat32), static_cast<int>(SearchValueType::Float32));
    m_searchTypeCombo->addItem(memorySearchSource(MemorySearchText::TypeFloat64), static_cast<int>(SearchValueType::Float64));
    m_searchTypeCombo->addItem(memorySearchSource(MemorySearchText::TypeBytes), static_cast<int>(SearchValueType::ByteArray));
    m_searchTypeCombo->addItem(memorySearchSource(MemorySearchText::TypeAscii), static_cast<int>(SearchValueType::StringAscii));
    m_searchTypeCombo->addItem(memorySearchSource(MemorySearchText::TypeUnicode), static_cast<int>(SearchValueType::StringUnicode));
    ks::ui::StylePrimaryCombo(m_searchTypeCombo);

    m_searchValueEdit = new QLineEdit(conditionGroup);
    m_searchValueEdit->setObjectName(memorySearchTarget(MemorySearchText::ValuePlaceholder));
    m_searchValueEdit->setPlaceholderText(memorySearchSource(MemorySearchText::ValuePlaceholder));
    m_searchValueEdit->setStyleSheet(inputStyle);

    m_searchRangeCombo = new QComboBox(conditionGroup);
    m_searchRangeCombo->setObjectName(memorySearchTarget(MemorySearchText::RangeAll));
    m_searchRangeCombo->addItem(memorySearchSource(MemorySearchText::RangeAll));
    m_searchRangeCombo->addItem(memorySearchSource(MemorySearchText::RangeCustom));
    ks::ui::StylePrimaryCombo(m_searchRangeCombo);

    m_searchRangeStartEdit = new QLineEdit(conditionGroup);
    m_searchRangeEndEdit = new QLineEdit(conditionGroup);
    m_searchRangeStartEdit->setObjectName(memorySearchTarget(MemorySearchText::RangeStart));
    m_searchRangeEndEdit->setObjectName(memorySearchTarget(MemorySearchText::RangeEnd));
    m_searchRangeStartEdit->setPlaceholderText(memorySearchSource(MemorySearchText::RangeStart));
    m_searchRangeEndEdit->setPlaceholderText(memorySearchSource(MemorySearchText::RangeEnd));
    m_searchRangeStartEdit->setStyleSheet(inputStyle);
    m_searchRangeEndEdit->setStyleSheet(inputStyle);
    m_searchRangeStartEdit->setEnabled(false);
    m_searchRangeEndEdit->setEnabled(false);

    m_searchImageOnlyCheck = new QCheckBox(memorySearchSource(MemorySearchText::ImageOnly), conditionGroup);
    m_searchHeapOnlyCheck = new QCheckBox(memorySearchSource(MemorySearchText::HeapOnly), conditionGroup);
    m_searchStackOnlyCheck = new QCheckBox(memorySearchSource(MemorySearchText::StackOnly), conditionGroup);
    m_searchImageOnlyCheck->setObjectName(memorySearchTarget(MemorySearchText::ImageOnly));
    m_searchHeapOnlyCheck->setObjectName(memorySearchTarget(MemorySearchText::HeapOnly));
    m_searchStackOnlyCheck->setObjectName(memorySearchTarget(MemorySearchText::StackOnly));
    m_searchTypeCombo->setToolTip("选择要搜索的数据类型；类型必须和内存中实际存放的格式一致才能搜到");
    m_searchRangeCombo->setToolTip("限定搜索的地址范围；选“自定义范围”后可填写起止地址");
    m_searchImageOnlyCheck->setToolTip("只在 exe/dll 映射的内存中搜索");
    m_searchHeapOnlyCheck->setToolTip("只在推测为堆（程序动态分配）的内存中搜索，判定为近似值");
    m_searchStackOnlyCheck->setToolTip("只在推测为栈（函数局部变量）的内存中搜索，判定为近似值");

    m_firstScanButton = new QPushButton(QIcon(":/Icon/log_track.svg"), memorySearchSource(MemorySearchText::FirstScan), conditionGroup);
    m_nextScanButton = new QPushButton(QIcon(":/Icon/codeeditor_find.svg"), memorySearchSource(MemorySearchText::NextScan), conditionGroup);
    m_resetScanButton = new QPushButton(QIcon(":/Icon/log_clear.svg"), memorySearchSource(MemorySearchText::Reset), conditionGroup);
    m_cancelScanButton = new QPushButton(QIcon(":/Icon/process_terminate.svg"), memorySearchSource(MemorySearchText::Cancel), conditionGroup);
    m_firstScanButton->setObjectName(memorySearchTarget(MemorySearchText::FirstScan));
    m_nextScanButton->setObjectName(memorySearchTarget(MemorySearchText::NextScan));
    m_resetScanButton->setObjectName(memorySearchTarget(MemorySearchText::Reset));
    m_cancelScanButton->setObjectName(memorySearchTarget(MemorySearchText::Cancel));
    m_firstScanButton->setToolTip("按上面的条件全新搜索一遍内存，得到初始结果集");
    m_nextScanButton->setToolTip("在上次结果的基础上继续筛选，逐步缩小范围（需先完成首次扫描）");
    m_resetScanButton->setToolTip("清空已有搜索结果，回到可重新首次扫描的状态");
    m_cancelScanButton->setToolTip("中止正在进行的扫描");
    ks::ui::ApplyFlatButtonTheme(m_firstScanButton, ks::ui::FlatButtonTone::Accent);
    m_nextScanButton->setStyleSheet(buttonStyle);
    m_resetScanButton->setStyleSheet(buttonStyle);
    m_cancelScanButton->setStyleSheet(buttonStyle);
    // 网格表单只统一扫描动作按钮，不把整张表单锁到一行高度。
    ks::ui::NormalizeToolbarControl(m_firstScanButton);
    ks::ui::NormalizeToolbarControl(m_nextScanButton);
    ks::ui::NormalizeToolbarControl(m_resetScanButton);
    ks::ui::NormalizeToolbarControl(m_cancelScanButton);
    m_nextScanButton->setEnabled(false);
    m_cancelScanButton->setEnabled(false);

    // 原七列表单拆为单列；起止地址和区域开关保持可见，不依赖横向滚动。
    auto* typeCaption = new QLabel(memorySearchSource(MemorySearchText::TypeCaption), conditionGroup);
    typeCaption->setObjectName(memorySearchTarget(MemorySearchText::TypeCaption));
    conditionLayout->addWidget(typeCaption, 0, 0);
    conditionLayout->addWidget(m_searchTypeCombo, 1, 0);
    auto* valueCaption = new QLabel(memorySearchSource(MemorySearchText::ValueCaption), conditionGroup);
    valueCaption->setObjectName(memorySearchTarget(MemorySearchText::ValueCaption));
    conditionLayout->addWidget(valueCaption, 2, 0);
    conditionLayout->addWidget(m_searchValueEdit, 3, 0);
    auto* rangeCaption = new QLabel(memorySearchSource(MemorySearchText::RangeCaption), conditionGroup);
    rangeCaption->setObjectName(memorySearchTarget(MemorySearchText::RangeCaption));
    conditionLayout->addWidget(rangeCaption, 4, 0);
    conditionLayout->addWidget(m_searchRangeCombo, 5, 0);
    conditionLayout->addWidget(m_searchRangeStartEdit, 6, 0);
    conditionLayout->addWidget(m_searchRangeEndEdit, 7, 0);
    conditionLayout->addWidget(m_searchImageOnlyCheck, 8, 0);
    conditionLayout->addWidget(m_searchHeapOnlyCheck, 9, 0);
    conditionLayout->addWidget(m_searchStackOnlyCheck, 10, 0);
    conditionLayout->setColumnStretch(0, 1);
    workspace->parameters()->addWidget(conditionGroup);

    // 四个扫描动作以两行固定，避免窄栏按钮互相挤压。
    auto* scanActions = new QGridLayout();
    scanActions->addWidget(m_firstScanButton, 0, 0);
    scanActions->addWidget(m_nextScanButton, 0, 1);
    scanActions->addWidget(m_resetScanButton, 1, 0);
    scanActions->addWidget(m_cancelScanButton, 1, 1);
    workspace->actions()->addLayout(scanActions, 1);

    QGroupBox* compareGroup = new QGroupBox(memorySearchSource(MemorySearchText::Compare), m_tabSearch);
    compareGroup->setObjectName(memorySearchTarget(MemorySearchText::Compare));
    ks::ui::StyleParameterSection(compareGroup);
    QFormLayout* compareLayout = new QFormLayout(compareGroup);
    compareLayout->setRowWrapPolicy(QFormLayout::WrapAllRows);
    compareLayout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    compareLayout->setContentsMargins(8, 6, 8, 6);
    compareLayout->setSpacing(8);

    m_nextScanCompareCombo = new QComboBox(compareGroup);
    m_nextScanCompareCombo->setObjectName(memorySearchTarget(MemorySearchText::Equal));
    m_nextScanCompareCombo->addItem(memorySearchSource(MemorySearchText::Equal), static_cast<int>(SearchCompareMode::Equal));
    m_nextScanCompareCombo->addItem(memorySearchSource(MemorySearchText::Greater), static_cast<int>(SearchCompareMode::Greater));
    m_nextScanCompareCombo->addItem(memorySearchSource(MemorySearchText::Less), static_cast<int>(SearchCompareMode::Less));
    m_nextScanCompareCombo->addItem(memorySearchSource(MemorySearchText::Between), static_cast<int>(SearchCompareMode::Between));
    m_nextScanCompareCombo->addItem(memorySearchSource(MemorySearchText::Changed), static_cast<int>(SearchCompareMode::Changed));
    m_nextScanCompareCombo->addItem(memorySearchSource(MemorySearchText::Unchanged), static_cast<int>(SearchCompareMode::Unchanged));
    m_nextScanCompareCombo->addItem(memorySearchSource(MemorySearchText::Increased), static_cast<int>(SearchCompareMode::Increased));
    m_nextScanCompareCombo->addItem(memorySearchSource(MemorySearchText::Decreased), static_cast<int>(SearchCompareMode::Decreased));
    ks::ui::StylePrimaryCombo(m_nextScanCompareCombo);
    m_nextScanCompareCombo->setToolTip("再次扫描时的筛选方式：可按新值比较，也可按“变化/未变化/增加/减少”筛选");

    m_nextScanValueEdit = new QLineEdit(compareGroup);
    m_nextScanValueBEdit = new QLineEdit(compareGroup);
    m_nextScanValueEdit->setObjectName(memorySearchTarget(MemorySearchText::ValueA));
    m_nextScanValueBEdit->setObjectName(memorySearchTarget(MemorySearchText::ValueB));
    m_nextScanValueEdit->setPlaceholderText(memorySearchSource(MemorySearchText::ValueA));
    m_nextScanValueBEdit->setPlaceholderText(memorySearchSource(MemorySearchText::ValueB));
    m_nextScanValueEdit->setStyleSheet(inputStyle);
    m_nextScanValueBEdit->setStyleSheet(inputStyle);
    m_nextScanValueBEdit->setVisible(false);

    compareLayout->addRow(memorySearchSource(MemorySearchText::CompareConditionCaption), m_nextScanCompareCombo);
    compareLayout->labelForField(m_nextScanCompareCombo)->setObjectName(memorySearchTarget(MemorySearchText::CompareConditionCaption));
    compareLayout->addRow(memorySearchSource(MemorySearchText::CompareValueCaption), m_nextScanValueEdit);
    compareLayout->labelForField(m_nextScanValueEdit)->setObjectName(memorySearchTarget(MemorySearchText::CompareValueCaption));
    compareLayout->addRow(m_nextScanValueBEdit);
    workspace->parameters()->addWidget(compareGroup);

    // 只在本页将访问后端横条转为纵向，其他专业编辑器工具条保持原布局。
    QWidget* backendSelector = createBackendSelector(
        m_tabSearch, m_searchBackendCombo, m_searchBackendHintLabel);
    m_searchBackendCombo->setObjectName(memorySearchTarget(MemorySearchText::BackendUser));
    m_searchBackendHintLabel->setObjectName(QString::fromLatin1(kMemorySearchBackendHintTarget));
    backendSelector->layout()->itemAt(0)->widget()->setObjectName(memorySearchTarget(MemorySearchText::BackendCaption));
    static_cast<QHBoxLayout*>(backendSelector->layout())->setDirection(QBoxLayout::TopToBottom);
    workspace->parameters()->addWidget(backendSelector);

    m_searchResultTable = new MemoryTableView(m_tabSearch);
    m_searchResultTable->setObjectName(QString::fromLatin1(kMemorySearchTableTarget));
    // 搜索已经提供前次值/再次扫描比较，通用快照会重复同一信息。
    ks::ui::SetTableActionBarMode(m_searchResultTable, ks::ui::TableActionBarMode::Compact);
    ks::ui::SetCompactTableSearchTargetPrefix(m_searchResultTable, QString::fromLatin1(kMemorySearchActionsPrefix));
    m_searchResultTable->setHorizontalHeaderLabels(memorySearchHeaders());
    m_searchResultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_searchResultTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_searchResultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_searchResultTable->setAlternatingRowColors(true);
    m_searchResultTable->setContextMenuPolicy(Qt::CustomContextMenu);
    // 结果表默认允许按列排序；批量填表期间由 rebuildSearchResultTable 临时关闭再还原。
    m_searchResultTable->setSortingEnabled(true);
    m_searchResultTable->verticalHeader()->setVisible(false);
    m_searchResultTable->horizontalHeader()->setStretchLastSection(true);
    workspace->results()->addWidget(m_searchResultTable, 1);
    ks::ui::SetTableColumnAutoFitEnabled(m_searchResultTable, false);
    ks::ui::SetTableRowFilterBusinessOwnership(m_searchResultTable, ks::ui::TableRowFilterBusinessOwnership::ExclusiveSharedIdentity);
    initializeCoreProjection(CoreKind::SearchResults);

    QHBoxLayout* progressLayout = new QHBoxLayout();
    progressLayout->setContentsMargins(0, 0, 0, 0);
    progressLayout->setSpacing(8);
    m_scanProgressBar = new QProgressBar(m_tabSearch);
    m_scanProgressBar->setRange(0, 100);
    m_scanStatusLabel = new QLabel(memorySearchSource(MemorySearchText::Status), m_tabSearch);
    m_scanStatusLabel->setObjectName(memorySearchTarget(MemorySearchText::Status));
    progressLayout->addWidget(m_scanProgressBar, 1);
    progressLayout->addWidget(m_scanStatusLabel);
    workspace->results()->addLayout(progressLayout);
    workspace->finish();

    m_tabWidget->addTab(m_tabSearch, "内存搜索");
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget, m_tabSearch, QStringLiteral("memory.tab.search"), QStringLiteral("内存搜索"));
}
