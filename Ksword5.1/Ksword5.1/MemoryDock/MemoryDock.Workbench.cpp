#include "MemoryDock.Internal.h"
#include "MemoryDock.WorkbenchServices.h"
#include "MemoryDebugPage.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/MemoryWorkbench/MemoryWorkbenchView.h"
#include "../UI/MemoryWorkbench/WorkbenchNavigation.h"
#include "../UI/MemoryWorkbench/WorkbenchSettings.h"
#include "../UI/MemoryWorkbench/WorkbenchShared.h"
#include "../UI/MemoryWorkbench/WorkbenchTarget.h"

// ============================================================
// MemoryDock.Workbench.cpp
// 作用：
// - 内存工作台（UI/MemoryWorkbench/ 的 MemoryWorkbenchView）在 MemoryDock 里的接线（波 4）：
//   1) 在页签栏插入"内存工作台"页签，视图懒创建（首次切到该页签才创建，不拖慢 Dock 构造）；
//   2) 创建视图时按 MemoryDock.WorkbenchServices.h 的"接线步骤速查"注入全部生产服务；
//   3) 把 Dock 的附加/分离转给视图的 WorkbenchTarget（三个钩子）；
//   4) 统一的"跳到地址"分发器 jumpToAddress：routeJumps 为真（3b 起默认）交给工作台，
//      为假（用户在设置里取消勾选）走旧内存查看器；
//   5) 主窗口关闭前的退出守卫入口 confirmWorkbenchQuit。
// - 3b 起内嵌进程详情窗口里的 Dock 也创建视图（内嵌模式：恒跟随 Dock、禁内核/物理、不落盘设置）；
//   旧页签改名/后移、模块表/区域表/搜索结果/证据页的入口在 MemoryDock.WorkbenchEntry.cpp。
// ============================================================

namespace
{
    // kWorkbenchTabIndex：内存工作台页签的插入位置（内存搜索之后、旧内存查看器之前）。
    constexpr int kWorkbenchTabIndex = 3;
}

// initializeMemoryDebugTab：独立页面不受旧工作台路由开关影响，也不订阅 Dock 附加。
// 页面构造只建立选择器，生产工作台和系统枚举都延迟到首次显示。
void MemoryDock::initializeMemoryDebugTab()
{
    if (m_tabWidget == nullptr || m_memoryDebugPage != nullptr)
    {
        return;
    }
    m_memoryDebugPage = new ks::ui::MemoryDebugPage(m_tabWidget);
    // position：紧邻新工作台；整体开关关闭时仍保留此独立功能入口。
    const int position = m_tabWorkbench != nullptr
        ? m_tabWidget->indexOf(m_tabWorkbench) + 1 : kWorkbenchTabIndex;
    const int index = m_tabWidget->insertTab(position, m_memoryDebugPage,
        QStringLiteral("内存调试"));
    m_tabWidget->setTabIcon(index, QIcon(QStringLiteral(":/Icon/memwb_tab_disasm.svg")));
    ks::i18n::LanguageManager::instance().bindTab(m_tabWidget, m_memoryDebugPage,
        QStringLiteral("memory.tab.debug"), QStringLiteral("内存调试"));
}

// initializeWorkbenchTab：在 initializeTabs 的图标循环之后调用一次。
// 只建一个空容器页并插入页签，视图本身懒创建；内嵌窗口里这个页签是否显示由
// setProcessDetailMemoryScope 按 routeJumps 决定（显示时视图以内嵌模式创建）。
void MemoryDock::initializeWorkbenchTab()
{
    // 整体开关（"enabled" 键，默认开）：关掉就不插页签，也没有视图、没有分发器路由——
    // 这是无需发版的整体回退开关。m_tabWorkbench 保持空指针，分发器据此回退旧路径。
    if (!ks::ui::workbench_settings::LoadEnabled())
    {
        return;
    }

    // 容器页：垂直布局、无边距，视图创建后铺满。
    m_tabWorkbench = new QWidget(m_tabWidget);
    QVBoxLayout* const containerLayout = new QVBoxLayout(m_tabWorkbench);
    containerLayout->setContentsMargins(0, 0, 0, 0);
    containerLayout->setSpacing(0);

    // 插入页签并单独设置图标（图标循环按原有页签下标写死，不包含这一页）。
    const int insertedIndex = m_tabWidget->insertTab(
        kWorkbenchTabIndex, m_tabWorkbench, QStringLiteral("内存工作台"));
    m_tabWidget->setTabIcon(insertedIndex, QIcon(QStringLiteral(":/Icon/memwb_tab_hex.svg")));
    ks::i18n::LanguageManager::instance().bindTab(
        m_tabWidget, m_tabWorkbench,
        QStringLiteral("memory.tab.workbench"), QStringLiteral("内存工作台"));

    // 旧入口的跳转是否交给工作台：读持久设置（3b 起默认真，用户可在"内存扫描设置"里取消勾选回退）。
    m_workbenchRouteJumps = ks::ui::workbench_settings::LoadRouteJumps();

    // 旧页签改名为"（旧）"并移到页签栏末尾（必须在工作台页签插入之后）。
    arrangeLegacyTabs();

    // 首次切到该页签时创建视图；ensureWorkbenchView 幂等，后续切换不再创建。
    connect(m_tabWidget, &QTabWidget::currentChanged, this, [this](int) {
        if (m_tabWidget != nullptr && m_tabWidget->currentWidget() == m_tabWorkbench)
        {
            ensureWorkbenchView();
        }
    });
}

// ensureWorkbenchView：幂等地创建视图并完成全部接线。
// 顺序有要求：先 ConfigureShared（必须在第一个视图之前，且此前不得有人访问共享地址簿），
// 再创建视图、注入服务、加载设置，最后连接信号并回放"创建之前已经发生的附加"。
void MemoryDock::ensureWorkbenchView()
{
    // 已创建或容器页不存在时直接返回。
    if (m_workbenchView != nullptr || m_tabWorkbench == nullptr)
    {
        return;
    }

    // 1) 共享对象配置（幂等；被拒绝时它自己写 err 日志，不抛异常）。
    ks::ui::workbench_dock::ConfigureShared();

    // 2) 创建视图并铺满容器页。
    m_workbenchView = new ks::ui::MemoryWorkbenchView(m_tabWorkbench);
    m_tabWorkbench->layout()->addWidget(m_workbenchView);
    // view：lambda 捕获用的视图裸指针；视图是本 Dock 的子对象，生命周期不长于 Dock。
    ks::ui::MemoryWorkbenchView* const view = m_workbenchView;

    // 3) 注入生产服务（MemoryDock.WorkbenchServices.h 的接线步骤速查逐条落实）。
    view->setDisasmBackends(
        ks::ui::workbench_dock::MakeDecodeBackend(),
        ks::ui::workbench_dock::MakeAssembleBackend());
    view->setGlobalSkipDangerousConfirmProvider(&ks::ui::workbench_dock::GlobalSkipDangerousConfirm);
    view->setAttachedProcessInfoProvider(&ks::ui::workbench_dock::QueryAttachedProcessInfo);
    // 保护段：视图的回调只带地址，pid 取视图当前会话；内核/物理范围下 pid 恒为 0，返回空。
    view->setProtectionProvider([view](const std::uint64_t address) {
        return ks::ui::workbench_dock::QueryProtection(view->target().session().pid, address);
    });
    // 通道可用性输入：QueryGateInputs 不知道当前目标，hasProcessTarget 必须在这里补上，
    // 否则进程范围下所有通道都被判"需要进程"，页读取全部被取消。
    view->setGateInputsProvider([view]() {
        ksword::memwb::GateInputs inputs = ks::ui::workbench_dock::QueryGateInputs();
        inputs.hasProcessTarget = view->target().session().pid != 0;
        return inputs;
    });

    // 4) 主 Dock 的视图是设置权威（只有它落盘）；注入完成后再加载一次设置。
    //    内嵌实例（进程详情窗口）永不落盘，并在设置加载之后切到内嵌模式：恒跟随本 Dock、
    //    禁用内核/物理范围、隐藏侧栏（loadSettings 会把已存的范围/侧栏偏好回写到控件上，
    //    内嵌模式必须在它之后再生效）。
    view->setSettingsAuthoritative(!m_workbenchEmbedded);
    view->loadSettings();
    if (m_workbenchEmbedded)
    {
        view->setEmbeddedProcessMode(true);
    }

    // 5) 信号接线（全部用 lambda，不新增 Qt 槽函数）。
    // 5a) 用户点了目标 chip 的"在 Dock 附加…"：切到进程与模块页并让进程下拉框获得焦点。
    connect(view, &ks::ui::MemoryWorkbenchView::pickTargetRequested, this, [this]() {
        if (m_tabWidget != nullptr && m_tabProcessModule != nullptr)
        {
            m_tabWidget->setCurrentWidget(m_tabProcessModule);
        }
        if (m_processCombo != nullptr)
        {
            m_processCombo->setFocus();
        }
    });
    // 5b) 写入失败的原文：交给既有的提权提示（它自己判断是不是权限问题、已提权时返回 false）。
    connect(view, &ks::ui::MemoryWorkbenchView::writeFailureText, this, [this](const QString& failureText) {
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("内存工作台写入"), failureText);
    });
    // 5c) 跳转被拒绝：状态条已经报告原因，这里只留一条日志，不再弹窗。
    connect(view, &ks::ui::MemoryWorkbenchView::navigationRefused, this, [](const ks::ui::NavStatus status) {
        kLogEvent refusedEvent;
        warn << refusedEvent
            << "[MemoryDock] 内存工作台拒绝了一次跳转, status="
            << static_cast<int>(status)
            << eol;
    });

    // 6) 回放创建之前已经发生的附加：否则视图看不到"早已附加"的进程。
    if (m_attachedPid != 0 && m_attachedProcessHandle != nullptr)
    {
        workbenchOnAttached();
    }
    // 视图懒创建通常晚于计时器；若构造期间已创建视图，则计时器创建端稍后补接同一条连接。
    connectWorkbenchLiveness();

    kLogEvent createdEvent;
    info << createdEvent
        << "[MemoryDock] 内存工作台视图已创建。"
        << eol;
}

// connectWorkbenchLiveness：复用既有一秒 tick；弱身份/非进程范围不探测，不把不可核验目标误判为退出。
void MemoryDock::connectWorkbenchLiveness()
{
    if (m_workbenchView == nullptr || m_bookmarkRefreshTimer == nullptr
        || m_workbenchView->property("ksword_memwb_liveness_hooked").toBool())
    {
        return;
    }
    // view：视图弱指针，只在 UI 线程取用；所有连接以视图为 context，销毁后 Qt 自动断开。
    const QPointer<ks::ui::MemoryWorkbenchView> view(m_workbenchView);
    connect(m_bookmarkRefreshTimer, &QTimer::timeout, view.data(), [view]() {
        if (view && view->target().identityAnchored())
        {
            // identityAnchored 已限定 Process/PID/创建时间；只查持有的进程锚点，不枚举系统进程。
            view->target().checkLiveness();
            // checkLiveness 可同步通知并销毁宿主，故返回后不再访问视图。
        }
    });
    connect(&view->target(), &ks::ui::WorkbenchTarget::livenessChanged, view.data(), [view](const int state) {
        if (!view || state != static_cast<int>(ks::ui::LivenessState::Exited)
            || !view->target().identityAnchored())
        {
            return;
        }
        // captured：按真实目标会话复制 PID/创建时间；DDMA 代次拉取可能同步销毁视图，复制后再探活。
        const auto captured = view->target().capture();
        if (!view || captured.session.scope != ksword::memwb::Scope::ProcessVirtual
            || captured.session.pid == 0U || captured.session.processCreateTime100ns == 0U)
        {
            return;
        }
        ks::ui::WorkbenchShared::Instance().Int3().OnTargetGone(
            captured.session.pid, captured.session.processCreateTime100ns);
        // 账本 changed 通知可同步销毁视图，此后也不再读取成员。
    });
    view->setProperty("ksword_memwb_liveness_hooked", true);
}

// workbenchOnAttached：附加成功之后调用（句柄、PID、名称、读写标志都已就位）。
// 视图尚未创建时是空操作——创建时由 ensureWorkbenchView 回放。
void MemoryDock::workbenchOnAttached()
{
    if (m_workbenchView == nullptr)
    {
        return;
    }
    // attach：Dock 当前附加的快照；句柄只供视图复制，不会被写入或关闭。
    ks::ui::WorkbenchTarget::DockAttach attach;
    attach.handle = m_attachedProcessHandle;
    attach.pid = m_attachedPid;
    attach.name = m_attachedProcessName;
    attach.attachGeneration = m_processAttachmentGeneration.load();
    attach.hintReadOnly = !m_canReadWriteMemory;
    m_workbenchView->target().onDockAttached(attach);
}

// workbenchOnAboutToDetach：detachProcess 最开头（句柄关闭之前）调用。
void MemoryDock::workbenchOnAboutToDetach()
{
    if (m_workbenchView != nullptr)
    {
        m_workbenchView->target().onDockAboutToDetach();
    }
}

// workbenchOnDetached：detachProcess 最末（旧上下文已清零）调用。
void MemoryDock::workbenchOnDetached()
{
    if (m_workbenchView != nullptr)
    {
        m_workbenchView->target().onDockDetached();
    }
}

// workbenchAllowsProcessChange：附加/分离之前问一次工作台的离开守卫。
// 视图尚未创建时没有任何东西要问；创建后守卫会按需弹暂存三选一与 int3 三选一。
bool MemoryDock::workbenchAllowsProcessChange()
{
    if (m_workbenchView == nullptr)
    {
        return true;
    }
    // 工作台钉在别的进程/内核/物理范围时，Dock 的附加或分离与它的会话无关，不该为此打扰用户：
    // 只有"跟随 Dock 且范围为进程"这类确实会改变会话的情形才问守卫。
    if (!m_workbenchView->target().wouldChangeOnDockAttach())
    {
        return true;
    }
    return m_workbenchView->requestLeave(ks::ui::LeaveReason::DockAttachChange);
}

// confirmWorkbenchQuit：MainWindow::closeEvent 最前调用。
bool MemoryDock::confirmWorkbenchQuit()
{
    if (m_workbenchView != nullptr && !m_workbenchView->confirmQuit())
    {
        return false;
    }
    // 独立页可留有暂存补丁；主窗口停止驱动前必须同时通过这份会话的离开守卫。
    return m_memoryDebugPage == nullptr || m_memoryDebugPage->confirmQuit();
}

void MemoryDock::cancelWorkbenchQuit()
{
    if (m_workbenchView != nullptr)
    {
        m_workbenchView->cancelQuitPreparation();
    }
    if (m_memoryDebugPage != nullptr)
    {
        m_memoryDebugPage->cancelQuitPreparation();
    }
}

// shutdownWorkbench：析构路径上先于子对象销毁调用——权威视图把设置落盘。
void MemoryDock::shutdownWorkbench()
{
    if (m_workbenchView != nullptr)
    {
        m_workbenchView->saveSettings();
    }
}

// navigateWorkbench：确保视图存在并切到该页签，再执行一次跳转。
// 传入：request 跳转请求；返回：true=跳转成功（NavStatus::Ok），false=视图不可用或被拒绝
// （拒绝原因已由视图状态条报告）。
bool MemoryDock::navigateWorkbench(const ks::ui::NavRequest& request)
{
    // 整体开关关闭（容器页缺失）时没有工作台。
    if (m_tabWorkbench == nullptr || m_tabWidget == nullptr)
    {
        return false;
    }
    ensureWorkbenchView();
    if (m_workbenchView == nullptr)
    {
        return false;
    }
    // 先切页签（会触发 currentChanged，但视图已存在，ensureWorkbenchView 是空操作）再跳转。
    m_tabWidget->setCurrentWidget(m_tabWorkbench);
    return m_workbenchView->openAt(request) == ks::ui::NavStatus::Ok;
}

// workbenchRoutingActive：旧入口的跳转当前是否交给工作台。
// 整体开关关闭（容器页缺失）或用户取消了 routeJumps 勾选时为假，调用方据此走旧路径。
bool MemoryDock::workbenchRoutingActive() const
{
    return m_workbenchRouteJumps && m_tabWorkbench != nullptr;
}

// jumpToAddress：统一的"跳到地址"分发器（本 Dock 附加进程的用户态地址）。
// - 工作台路由关闭：走旧内存查看器（行为与改动前完全相同）；
// - 路由开启：交给工作台，范围固定为进程（这些来源的地址都是进程地址——工作台此刻停在内核/
//   物理范围时，沿用当前范围只会得到"地址不在当前范围内"），pid 为 0 表示跟随本 Dock 的附加进程
//   （工作台若钉在别的进程上会被带回跟随）。被拒绝时不回退旧页：原因已写在工作台状态条里。
void MemoryDock::jumpToAddress(const std::uint64_t address)
{
    if (!workbenchRoutingActive())
    {
        jumpToAddressLegacy(address);
        return;
    }
    // request：来源标为外部调用（旧入口分发器不区分具体来源页）。
    ks::ui::NavRequest request;
    request.scope = ksword::memwb::Scope::ProcessVirtual;
    request.address = address;
    request.origin = ks::ui::NavOrigin::External;
    if (!navigateWorkbench(request) && m_workbenchView == nullptr)
    {
        // 视图创建失败（理论上不会发生）：回退旧路径，保证用户仍能跳转。
        jumpToAddressLegacy(address);
    }
}
