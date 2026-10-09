// ============================================================
// MemoryWorkbenchView.cpp
// 作用：
// - 实现本类的构造/析构（五个私有管线对象的创建与互相注入，顺序见头文件
//   文件头）、对外的薄转发方法（target()/setEmbeddedProcessMode/
//   setDisasmBackends/setPointerNamer/requestLeave/三个 §8.0 注入点）、设置
//   持久化（loadSettings/saveSettings）、离开守卫组合（installLeaveGuard）、
//   动作与快捷键接线（wireActions）、以及反汇编/文本/对比三个只读子页共用的
//   字节数据源适配器 DisasmBytesProviderAdapter（头文件已声明为私有嵌套类，
//   本文件补完整定义）。
// - 界面搭建与信号接线在 MemoryWorkbenchView.Ui.cpp；会话/写入反馈/地址簿/
//   int3 的处理函数在 MemoryWorkbenchView.Session.cpp；导航/地址条在
//   MemoryWorkbenchView.Nav.cpp。四个文件共用的纯函数帮助器见
//   MemoryWorkbenchView.Internal.h。
// ============================================================

#include "MemoryWorkbenchView.h"
#include "MemoryWorkbenchView.Internal.h"

#include "AddressBookPanel.h"
#include "Int3PatchPanel.h"
#include "WorkbenchActions.h"
#include "WorkbenchBaselineFeeder.h"
#include "WorkbenchCompareView.h"
#include "WorkbenchConfirmations.h"
#include "WorkbenchMessages.h"
#include "WorkbenchPageProvider.h"
#include "WorkbenchSessionBar.h"
#include "WorkbenchSettings.h"
#include "WorkbenchShared.h"
#include "WorkbenchStatusBar.h"
#include "WorkbenchTextView.h"
#include "WorkbenchPseudocodeView.h"
#include "WorkbenchWriteController.h"

#include "../../../../shared/evidence/memory_workbench/SessionAddressResolver.h"

#include <QCheckBox>
#include <QLineEdit>
#include <QPointer>
#include <QShortcut>
#include <QSplitter>
#include <QStackedWidget>
#include <QTimer>
#include <QToolButton>

namespace ks::ui::detail
{
    // BuildSessionIdentityKey：固定 base=0/len=0 求值，见 Internal.h 的说明。
    std::string BuildSessionIdentityKey(const ksword::memwb::MemoryTargetSession& session)
    {
        return ksword::memwb::IdentityKey(session, 0ULL, 0ULL);
    }

    // BuildAddressBookTargetKey：只随目标身份变化，不随通道变化（见 Internal.h）。
    std::string BuildAddressBookTargetKey(const ksword::memwb::MemoryTargetSession& session)
    {
        switch (session.scope)
        {
        case ksword::memwb::Scope::KernelVirtual:
            return "kernel";
        case ksword::memwb::Scope::Physical:
            return "physical";
        case ksword::memwb::Scope::ProcessVirtual:
        default:
            return "pid:" + std::to_string(session.pid) + "@" + std::to_string(session.processCreateTime100ns);
        }
    }

    // BuildTargetDescriptionText：会话条目标 chip 与确认框正文共用的人话描述，
    // 两处各自独立调用，不共用控件状态（装配接口文档 §6 B2）。
    QString BuildTargetDescriptionText(
        bool attached,
        const QString& processName,
        quint32 pid,
        quint32 addressBits,
        bool canReadWrite,
        ksword::memwb::Scope scope)
    {
        if (scope != ksword::memwb::Scope::ProcessVirtual)
        {
            const QString neutral = workbench_messages::TargetChipNoProcessText(scope);
            return neutral.isEmpty() ? workbench_messages::ScopeName(scope) : neutral;
        }
        if (!attached)
        {
            return workbench_messages::TargetChipUnattachedText();
        }
        return workbench_messages::TargetChipAttachedText(processName, pid, addressBits, canReadWrite);
    }
}

namespace ks::ui
{
    namespace
    {
        // LeaveReasonDisplayText（修复缺陷 3）：把 installLeaveGuard 收到的
        // LeaveReason 翻译成一句人话，拼进 PromptLeaveWithPending 的正文
        // （"...前必须先处理"）。MainWindowClose 直接调用 confirmQuit，
        // 不经过这个 target_->setLeaveGuard 回调；两者最终共用 runLeaveSequence，这里只需要
        // 覆盖 WorkbenchTarget::LeaveReason 实际会出现的四个取值。
        QString LeaveReasonDisplayText(const LeaveReason reason)
        {
            switch (reason)
            {
            case LeaveReason::DockAttachChange:
                return QStringLiteral("切换附加目标（分离或重新附加进程）");
            case LeaveReason::ScopeChange:
                return QStringLiteral("切换范围");
            case LeaveReason::ChannelChange:
                return QStringLiteral("切换通道");
            case LeaveReason::PinChange:
                return QStringLiteral("切换钉住的目标");
            default:
                return QStringLiteral("离开当前视图");
            }
        }
    }

    // 静态成员定义：见头文件 confirmPrompterFactoryForTest_ 的注释。
    std::function<std::unique_ptr<IConfirmPrompter>()> MemoryWorkbenchView::confirmPrompterFactoryForTest_;

    // ------------------------------------------------------------
    // DisasmBytesProviderAdapter：反汇编/文本/对比三页共用的只读数据源，包装
    // hexPane_->overlay()。头文件私有嵌套类只声明了类名，这里补完整定义——
    // 不对外公开，只在本文件与 currentBytesProvider() 内使用。
    // ------------------------------------------------------------
    class MemoryWorkbenchView::DisasmBytesProviderAdapter final : public IWorkbenchBytesProvider
    {
    public:
        // 构造：hexPane 非拥有，调用方（本类）保证其生命周期覆盖本适配器。
        explicit DisasmBytesProviderAdapter(WorkbenchHexPane* hexPane) : hexPane_(hexPane) {}

        // FetchWindow：从 overlay() 的四套读数（Materialize/BaselineByte/
        // PreviousByte/ChangeKind）逐字节组装窗口快照；hexPane_ 为空（理论上
        // 不会发生，防御性判断）时返回 ok=false 的空窗口。
        WorkbenchByteWindow FetchWindow(std::uint64_t address, std::uint64_t length) const override
        {
            WorkbenchByteWindow window;
            window.address = address;
            if (hexPane_ == nullptr)
            {
                window.ok = false;
                return window;
            }
            auto& overlay = const_cast<WorkbenchHexPane*>(hexPane_)->overlay();
            const auto* canvas = hexPane_->canvas();
            const auto bounds = canvas ? canvas->addressSpaceRange() : std::nullopt;
            if (!bounds || address < bounds->first || address > bounds->last) return window;
            length = std::min<std::uint64_t>(length, 65536);
            if (length && length - 1 > bounds->last - address) length = bounds->last - address + 1;
            window.ok = true;
            window.bytes.resize(length);
            window.validMask.resize(length);
            window.baselineBytes.resize(length);
            window.baselineValidMask.resize(length);
            window.previousBytes.resize(length);
            window.previousValidMask.resize(length);
            window.changeKinds.resize(length);
            for (std::uint64_t i = 0; i < length; ++i)
            {
                const std::uint64_t cell = address + i;
                const auto visible = canvas->cellStateAt(cell);
                window.bytes[i] = visible.hasValue ? visible.value : 0;
                window.validMask[i] = visible.hasValue ? 1 : visible.byteState == HexCanvas::ByteState::Unreadable ? 0 : 2;
                if (const auto baseline = overlay.BaselineByte(cell))
                {
                    window.baselineBytes[i] = *baseline;
                    window.baselineValidMask[i] = 1;
                }
                if (const auto previous = overlay.PreviousByte(cell))
                {
                    window.previousBytes[i] = *previous;
                    window.previousValidMask[i] = 1;
                }
                window.changeKinds[i] = visible.change;
            }
            return window;
        }

        // AddressBits：取当前地址位数；本类不持有会话，只能退回 overlay 的基线
        // 位数概念不存在——因此由外层（currentBytesProvider 的调用方）在
        // setAddressSpace 时另行调用三个子页的 setAddressBits，本函数给一个
        // 不会误导的默认值（64），仅在三个子页从未被显式设置过架构时才会用到。
        int AddressBits() const override { return 64; }

        // HasPreviousRead：overlay 是否已经有过一次成功的"上一次读取"记录。
        bool HasPreviousRead() const override
        {
            return (hexPane_ != nullptr) && const_cast<WorkbenchHexPane*>(hexPane_)->overlay().HasPreviousRead();
        }

    private:
        WorkbenchHexPane* hexPane_ = nullptr;
    };

    // currentBytesProvider：返回适配器指针（整个视图生命周期内只有一份，构造时
    // 建好，不随目标切换重建——overlay 是同一份，只是内容变化，不需要换适配器）。
    IWorkbenchBytesProvider* MemoryWorkbenchView::currentBytesProvider()
    {
        return bytesProviderAdapter_.get();
    }

    // ensureBytesProviderAdapter：见头文件声明处的注释——本文件是唯一能看到
    // DisasmBytesProviderAdapter 完整定义的翻译单元，对 bytesProviderAdapter_
    // 的赋值（涉及 unique_ptr 的析构/赋值运算符实例化）必须发生在这里。
    void MemoryWorkbenchView::ensureBytesProviderAdapter()
    {
        if (!bytesProviderAdapter_)
        {
            bytesProviderAdapter_ = std::make_unique<DisasmBytesProviderAdapter>(hexPane_);
        }
    }

    // 构造：严格按文件头承诺的顺序创建五个私有对象并互相注入，再搭界面、挂动作、
    // 装离开守卫。WorkbenchShared::Instance() 在此刻可能尚未 Configure（例如夹具
    // 或装配顺序错误），各工厂回调在那种退化状态下本身就会返回空指针/拒绝一切，
    // 本类不重复判断"是否已配置"，只负责把回调原样转发。
    MemoryWorkbenchView::MemoryWorkbenchView(QWidget* parent)
        : QWidget(parent)
    {
        auto& shared = WorkbenchShared::Instance();

        // 1) WorkbenchTarget：用共享单例产出的服务构造，本视图私有。
        target_ = std::make_unique<WorkbenchTarget>(shared.CreateServices(), this);

        // 2) WorkbenchConfirmations：持有共享确认策略的引用。若夹具提前调用过
        //    InstallConfirmPrompterFactoryForTest，消费那个假执行器（见该方法
        //    的注释），避免测试时弹出真实模态框卡死进程；消费后立即清空，不
        //    影响后续任何构造。
        std::unique_ptr<IConfirmPrompter> testPrompter;
        if (confirmPrompterFactoryForTest_)
        {
            testPrompter = confirmPrompterFactoryForTest_();
            confirmPrompterFactoryForTest_ = nullptr;
        }
        confirmations_ = std::make_unique<WorkbenchConfirmations>(
            this, &shared.WritePolicy(), std::move(testPrompter));

        // 3) WorkbenchPageProvider：端口工厂转发共享单例的 CreateIoPort。
        pageProvider_ = std::make_unique<WorkbenchPageProvider>(
            [&shared]() { return shared.CreateIoPort(); },
            target_.get(),
            this);
        pageProvider_->setGateInputsProvider([this]() -> ksword::memwb::GateInputs {
            auto inputs = gateInputsProvider_ ? gateInputsProvider_() : ksword::memwb::GateInputs{};
            // 独立会话的已退出身份不得继续提交新读请求，缓存仍保留供查看。
            if (memoryDebugMode_ && target_->livenessState() == LivenessState::Exited)
            {
                inputs.hasProcessTarget = false;
            }
            return inputs;
        });

        // 4) WorkbenchBaselineFeeder：无额外构造参数，canvas/overlay 由
        //    hexPane_->setBaselineFeeder 注入。
        baselineFeeder_ = std::make_unique<WorkbenchBaselineFeeder>(this);

        // 5) WorkbenchWriteController：先构造，依赖项随后逐个 set*，overlay 由
        //    hexPane_->setWriteController 注入（唯一一份 overlay 不由本类直接持有）。
        writeController_ = std::make_unique<WorkbenchWriteController>(this);
        writeController_->setTarget(target_.get());
        writeController_->setConfirmationSink(confirmations_.get());
        writeController_->setAuditSink(&shared.AuditSink());
        writeController_->setIoPortFactory([&shared]() { return shared.CreateIoPort(); });
        writeController_->setKernelMutationPortFactory([&shared]() { return shared.CreateKernelMutationPort(); });
        const QPointer<MemoryWorkbenchView> pointerView(this);
        writeController_->setWriteValidationCallback([pointerView](const auto& session,
            std::uint64_t address, std::uint64_t length, std::string& reason) {
            if (!pointerView) { reason = "pointer-view-closed"; return false; }
            return pointerView->validatePointerChainWrite(session, address, length, reason);
        });
        writeController_->setRereadRangeCallback([this](std::uint64_t address, std::uint64_t length) {
            if (pageProvider_)
            {
                pageProvider_->rereadByteRange(address, length);
            }
        });
        writeController_->setCanvasReadOnlyHook([this](bool readOnlyDuringCommit) {
            if (hexPane_ != nullptr)
            {
                hexPane_->setEditable(!readOnlyDuringCommit);
            }
        });
        writeController_->setCommitSuspendHook([this](bool suspendedDuringCommit) {
            if (baselineFeeder_)
            {
                baselineFeeder_->setSuspended(suspendedDuringCommit);
            }
        });

        // 6) 搭界面：创建 hexPane_（内部建 overlay_）并把前四者注入其中、创建三个
        //    只读子页、会话条/地址条/侧栏/状态条；界面搭好之后把管线信号接到状态条
        //    与各面板（定义在 .Ui.cpp）。
        buildUi();
        connectPipelineSignals();
        connectPanelSignals();
        connect(&shared.AddressBook(), &AddressBookStore::entryChanged, this, [this](quint64) { cancelPointerChainResolution(); });
        connect(&shared.AddressBook(), &AddressBookStore::entryRemoved, this, [this](quint64) { cancelPointerChainResolution(); });
        connect(&shared.AddressBook(), &AddressBookStore::reset, this, [this]() { cancelPointerChainResolution(); });

        // 7) 快捷键。
        wireActions();

        // 8) 离开守卫组合（N2），注册给 target_。
        installLeaveGuard();

        // sessionChanged / aboutToDetach：装配接口文档 §3 信号表要求的两条核心
        // 连接——没有它们，会话变化永远不会驱动 handleIdentityChange/
        // handleReloadOnly，画布永远停在"从未 setAddressSpace"的初始状态
        // （构造早期的一处遗漏，经夹具实测抓到：stageBytes 恒报"只读视图"，
        // 根因是地址空间从未建立，不是可编辑标志本身的问题）。aboutToDetach
        // 按文档要求用 Direct 连接（WorkbenchTarget.h 原文强制要求，发出时
        // Dock 句柄仍有效）。
        connect(target_.get(), &WorkbenchTarget::sessionChanged, this, &MemoryWorkbenchView::onTargetSessionChanged);
        connect(target_.get(), &WorkbenchTarget::aboutToDetach, this, &MemoryWorkbenchView::onTargetAboutToDetach, Qt::DirectConnection);

        // modulesFailed：装配接口文档 §6 末行明确要求连接；熄灭地址条"刷新模块"
        // 加载指示灯的具体展示留给地址条自身控件（本类只转发，不新增成员持有
        // 这个指示灯状态——地址条控件内部没有这个指示灯时，这里只是安全的空转发）。
        connect(target_.get(), &WorkbenchTarget::modulesFailed, this, [this](bool kernel) {
            Q_UNUSED(kernel);
            if (statusBar_ != nullptr)
            {
                statusBar_->setReadResultText(
                    workbench_messages::ChannelUnavailableReason(
                        target_->session().channel,
                        ksword::memwb::GateVerdict{false, ksword::memwb::GateReason::ProbeFailed}),
                    true);
            }
        });

        // 子页自动跳转：模块目录就绪（modulesChanged）或失败（modulesFailed）时，重试因目录还在加载
        // 而挂起的跟随请求（实现与规则见 MemoryWorkbenchView.SubPages.cpp）。
        connect(target_.get(), &WorkbenchTarget::modulesChanged, this, &MemoryWorkbenchView::onTargetModulesChanged);
        connect(target_.get(), &WorkbenchTarget::modulesFailed, this, &MemoryWorkbenchView::onTargetModulesChanged);
    }

    // 析构：显式先断开管线之间互相持有的"非拥有指针"，再进入成员的隐式销毁。
    // hexPane_ 持有的三个 QPointer（pageProvider_/baselineFeeder_/
    // writeController_）本身会在目标对象销毁时自动置空，这一步显式调用是额外的
    // 防御——不依赖"unique_ptr 成员先于子控件析构"这条隐式规则来保证安全，而是
    // 让"用完就断开"成为本类自己可见、与成员声明顺序无关的动作（任务书明确要求）。
    // WorkbenchWriteController 的 setOverlay/setTarget 等在 transaction_ 已经
    // 构造之后会拒绝换成不同的值（见该类 D1/D2 的设计），所以这里不对
    // writeController_ 做同样的"置空"调用——它的生命周期安全完全来自"本类销毁时
    // 它所引用的 target_/confirmations_ 还活着"这条顺序保证（成员声明顺序已经是
    // target_ 先于 writeController_ 声明，即 writeController_ 先于 target_ 销毁）。
    MemoryWorkbenchView::~MemoryWorkbenchView()
    {
        // Qt 子控件比非拥有字节适配器晚析构，先解除引用并取消分析。
        if (pseudocodeView_ != nullptr) pseudocodeView_->setBytesProvider(nullptr);
        pointerClosing_ = true;
        cancelPointerChainResolution();
        if (hexPane_ != nullptr)
        {
            hexPane_->setPageProvider(nullptr);
            hexPane_->setBaselineFeeder(nullptr);
            hexPane_->setWriteController(nullptr);
        }
        if (liveRefreshTimer_ != nullptr)
        {
            liveRefreshTimer_->stop();
        }
    }

    // target：返回本视图私有的目标持有者引用。
    WorkbenchTarget& MemoryWorkbenchView::target() noexcept
    {
        return *target_;
    }

    // setEmbeddedProcessMode：内嵌进程详情窗口调用。策略锁定跟随 Dock、禁用
    // 内核/物理范围；隐藏侧栏与钉住输入框（本类没有独立的"钉住输入框"控件——
    // 钉住入口在会话条的目标 chip 展开态，这里只隐藏侧栏容器）；范围锁定为进程。
    void MemoryWorkbenchView::setEmbeddedProcessMode(bool embedded)
    {
        // 独立调试页与内嵌跟随页互斥，避免后调用覆盖已经建立的目标策略。
        if (embedded && memoryDebugMode_)
        {
            return;
        }
        if (embedded && target_ != nullptr)
        {
            // 内嵌视图必须把真实会话切回跟随进程，不能只改策略与范围分段的显示。
            IdentityRequest request;
            request.scope = ksword::memwb::Scope::ProcessVirtual;
            request.pinPid = 0U;
            if (sessionBar_ != nullptr)
            {
                request.channel = sessionBar_->rememberedChannel(ksword::memwb::Scope::ProcessVirtual);
            }
            // self：已有暂存可能触发离开询问，取消时保持原状态，被销毁时停止所有后续访问。
            const QPointer<MemoryWorkbenchView> self(this);
            const bool accepted = target_->requestIdentity(request, LeaveReason::ScopeChange);
            if (!self || !accepted)
            {
                return;
            }
        }
        embedded_ = embedded;
        target_->setPolicy(WorkbenchTarget::Policy{
            /*lockToDock=*/embedded,
            /*allowKernelPhysical=*/!embedded && !memoryDebugMode_,
            /*allowFollowDock=*/!memoryDebugMode_});
        // 侧栏可见性统一交给裁决入口：内嵌恒隐藏且不给展开钮（第二轮复核 B1：旧实现
        // 直接 setVisible 绕过了展开钮同步，也用 setSizes({1}) 把分割条弄坏，退出内嵌
        // 后得到 [0,884]）。退出内嵌时按"想要可见"恢复，并重新落一次偏好宽度。
        sidebarWidthApplied_ = false;
        maybeAutoCollapseSidebar();
        applySidebarWidthIfPossible();
        if (embedded && sessionBar_ != nullptr)
        {
            sessionBar_->setScope(ksword::memwb::Scope::ProcessVirtual);
        }
        refreshChannelGateDisplay();
    }

    // focusAddress：见头文件声明处的注释。进程范围且未附加（pid 为 0）时没有可用目标，
    // 画布插入点恒为 0，此时返回空而不是把 0 当成"用户在看地址 0"。
    std::optional<std::uint64_t> MemoryWorkbenchView::focusAddress() const
    {
        if (target_ == nullptr || hexPane_ == nullptr)
        {
            return std::nullopt;
        }
        const auto& session = target_->session();
        const bool hasUsableTarget =
            (session.scope != ksword::memwb::Scope::ProcessVirtual) || (session.pid != 0);
        if (!hasUsableTarget)
        {
            return std::nullopt;
        }
        const std::uint64_t address = hexPane_->insertionAddress();
        if (address == 0)
        {
            return std::nullopt;
        }
        return address;
    }

    // setDisasmBackends：注入点，直接转发给反汇编子页；本类不碰解码/汇编逻辑。
    void MemoryWorkbenchView::setDisasmBackends(DecodeOneFn decodeBackend, AssembleOneFn assembleBackend)
    {
        if (disasmView_ != nullptr)
        {
            disasmView_->setDecodeBackend(std::move(decodeBackend));
            disasmView_->setAssembleBackend(std::move(assembleBackend));
        }
    }

    // setPointerNamer：转发给十六进制子页的解释器面板。
    void MemoryWorkbenchView::setPointerNamer(ksword::memwb::IPointerNamer* namer)
    {
        if (hexPane_ != nullptr && hexPane_->inspector() != nullptr)
        {
            hexPane_->inspector()->setPointerNamer(namer);
        }
    }

    // setSettingsAuthoritative / isSettingsAuthoritative：权威视图标志，默认 false。
    void MemoryWorkbenchView::setSettingsAuthoritative(bool authoritative)
    {
        settingsAuthoritative_ = authoritative;
    }

    bool MemoryWorkbenchView::isSettingsAuthoritative() const noexcept
    {
        return settingsAuthoritative_;
    }

    // requestLeave：薄包装，直接转发 target_.requestLeave。
    bool MemoryWorkbenchView::requestLeave(LeaveReason reason)
    {
        return target_->requestLeave(reason);
    }

    // ---- 夹具白盒测试访问器：见头文件声明处的注释 ----
    WorkbenchHexPane* MemoryWorkbenchView::hexPaneForTest() const noexcept { return hexPane_; }
    WorkbenchSessionBar* MemoryWorkbenchView::sessionBarForTest() const noexcept { return sessionBar_; }
    WorkbenchStatusBar* MemoryWorkbenchView::statusBarForTest() const noexcept { return statusBar_; }
    WorkbenchWriteController* MemoryWorkbenchView::writeControllerForTest() const noexcept { return writeController_.get(); }
    AddressBookPanel* MemoryWorkbenchView::addressBookPanelForTest() const noexcept { return addressBookPanel_; }
    Int3PatchPanel* MemoryWorkbenchView::int3PanelForTest() const noexcept { return int3Panel_; }
    QSplitter* MemoryWorkbenchView::mainSplitterForTest() const noexcept { return mainSplitter_; }
    QToolButton* MemoryWorkbenchView::rerouteButtonForTest() const noexcept { return rerouteButton_; }
    QToolButton* MemoryWorkbenchView::backButtonForTest() const noexcept { return backButton_; }
    QToolButton* MemoryWorkbenchView::forwardButtonForTest() const noexcept { return forwardButton_; }
    QStackedWidget* MemoryWorkbenchView::subTabStackForTest() const noexcept { return subTabStack_; }
    const std::vector<std::uint64_t>& MemoryWorkbenchView::backStackForTest() const noexcept { return backStack_; }
    const std::vector<std::uint64_t>& MemoryWorkbenchView::forwardStackForTest() const noexcept { return forwardStack_; }

    // setGateInputsProvider：存一份回调，并立即转发给 pageProvider_ 的同名方法
    // （pageProvider_ 在构造时已经注入了一个转发到 gateInputsProvider_ 的 lambda，
    // 这里只需要换 gateInputsProvider_ 本身的内容，不需要重新调用
    // pageProvider_->setGateInputsProvider），随后刷新一次会话条的通道判据展示。
    void MemoryWorkbenchView::setGateInputsProvider(std::function<ksword::memwb::GateInputs()> provider)
    {
        gateInputsProvider_ = std::move(provider);
        refreshChannelGateDisplay();
    }

    // setProtectionProvider：存一份回调，并用当前插入点立即刷新一次保护段展示。
    void MemoryWorkbenchView::setProtectionProvider(
        std::function<std::optional<WorkbenchProtectionInfo>(std::uint64_t)> provider)
    {
        protectionProvider_ = std::move(provider);
        refreshProtectionDisplay();
    }

    // setGlobalSkipDangerousConfirmProvider：存一份回调，并立即重算一次确认抑制。
    void MemoryWorkbenchView::setGlobalSkipDangerousConfirmProvider(std::function<bool()> provider)
    {
        globalSkipDangerousConfirmProvider_ = std::move(provider);
        refreshConfirmationsAndSuppression();
    }

    // InstallConfirmPrompterFactoryForTest：静态钩子，见头文件声明处的注释。
    void MemoryWorkbenchView::InstallConfirmPrompterFactoryForTest(
        std::function<std::unique_ptr<IConfirmPrompter>()> factory)
    {
        confirmPrompterFactoryForTest_ = std::move(factory);
    }

    // setAttachedProcessInfoProvider：存一份回调，并立即刷新一次目标展示。
    void MemoryWorkbenchView::setAttachedProcessInfoProvider(
        std::function<std::optional<AttachedProcessDisplayInfo>(std::uint32_t)> provider)
    {
        attachedProcessInfoProvider_ = std::move(provider);
        refreshTargetDisplays();
    }

    // loadSettings：所有视图（权威与否）都读；读失败的键各自退回默认（见
    // WorkbenchSettings.h 的失败语义），范围、通道与写入模式先走真实状态裁决，再回写控件。
    void MemoryWorkbenchView::loadSettings()
    {
        using namespace ks::ui::workbench_settings;

        if (sessionBar_ != nullptr)
        {
            sessionBar_->restoreChannelMemory(
                ksword::memwb::Scope::ProcessVirtual,
                LoadChannelForScope(static_cast<std::uint32_t>(ksword::memwb::Scope::ProcessVirtual)));
            sessionBar_->restoreChannelMemory(
                ksword::memwb::Scope::KernelVirtual,
                LoadChannelForScope(static_cast<std::uint32_t>(ksword::memwb::Scope::KernelVirtual)));
            sessionBar_->restoreChannelMemory(
                ksword::memwb::Scope::Physical,
                LoadChannelForScope(static_cast<std::uint32_t>(ksword::memwb::Scope::Physical)));

            const std::uint32_t scopeValue = LoadScope();
            const ksword::memwb::Scope scope = (!embedded_ && !memoryDebugMode_ && scopeValue <= 2U)
                ? static_cast<ksword::memwb::Scope>(scopeValue)
                : ksword::memwb::Scope::ProcessVirtual;
            if (target_ != nullptr)
            {
                // savedIdentity：范围与对应通道一起交给真实会话裁决，避免显示内核却仍读取进程。
                IdentityRequest savedIdentity;
                savedIdentity.scope = scope;
                // 独立页复用编辑偏好，不从普通工作台恢复内核范围或需要驱动的首个通道。
                savedIdentity.channel = memoryDebugMode_
                    ? ksword::memwb::Channel::UserMode : sessionBar_->rememberedChannel(scope);
                const QPointer<MemoryWorkbenchView> self(this);
                (void)target_->requestIdentity(savedIdentity, LeaveReason::ScopeChange);
                if (!self)
                {
                    return;
                }
                // 守卫拒绝或内嵌策略拒绝时按真实状态回写，不把设置值假装成已经生效。
                const auto session = target_->session();
                if (!self)
                {
                    return;
                }
                sessionBar_->setSession(session.scope, session.channel, /*rememberAsUserChoice=*/false);
            }
            else
            {
                sessionBar_->setScope(scope);
            }

            const std::uint32_t modeValue = LoadWriteMode();
            // savedMode：持久化的真实写入策略，不能只修改工具条而让事务仍按立即写入执行。
            const auto savedMode = modeValue == 1U
                ? ksword::memwb::WriteMode::StagedThenApply
                : ksword::memwb::WriteMode::Immediate;
            if (writeController_ != nullptr)
            {
                // self：注入的服务与事务通知可能同步销毁视图，回调返回后先探活。
                const QPointer<MemoryWorkbenchView> self(this);
                const auto status = writeController_->requestModeSwitch(savedMode);
                if (!self)
                {
                    return;
                }
                if (status == ksword::memwb::ModeSwitchStatus::NeedsDecision)
                {
                    // 重载设置不能代替用户应用/丢弃已有暂存；取消待决切换并保留当前真实模式。
                    (void)writeController_->resolveModeSwitch(ksword::memwb::ModeSwitchDecision::Cancel);
                    if (!self)
                    {
                        return;
                    }
                }
                sessionBar_->setWriteMode(writeController_->mode());
            }
            else
            {
                sessionBar_->setWriteMode(savedMode);
            }
        }

        if (hexPane_ != nullptr)
        {
            hexPane_->inspector()->setVisible(true);
        }
        // 十六进制画布的行宽（自动/手选）、分组、字号偏好；自适应行宽只在这条路径里默认打开
        // （见 MemoryWorkbenchView.HexPrefs.cpp），不调 loadSettings 的宿主/夹具仍是固定 16 字节行宽。
        loadHexPreferences();
        // 侧栏：已存的可见性/宽度只是"偏好"（第二轮复核 B1）。可见性经统一裁决入口
        // 落地（窄窗口仍可折叠一个想要可见的侧栏，但绝不会把已存为隐藏的侧栏放出来；
        // 内嵌模式恒隐藏）；宽度只记下来，等分割条有了真实宽度再落——loadSettings
        // 通常在 show 之前调用，那时直接 setSizes 会让侧栏占满、画布 0px。
        if (sidebarContainer_ != nullptr)
        {
            sidebarWantedVisible_ = LoadSidebarVisible();
            sidebarUserOverride_ = false;
            sidebarPreferredWidth_ = LoadSidebarWidth();
            sidebarWidthApplied_ = false;
            maybeAutoCollapseSidebar();
            applySidebarWidthIfPossible();
        }
        if (subTabStack_ != nullptr)
        {
            // 独立页首次进入反汇编，普通工作台仍恢复用户最后选择的子页。
            const int subTab = memoryDebugMode_ ? 1 : LoadSubTab();
            if (subTab >= 0 && subTab < subTabStack_->count())
            {
                subTabStack_->setCurrentIndex(subTab);
            }
        }
        if (statusBar_ != nullptr)
        {
            statusBar_->setDrawerExpanded(LoadDiagExpanded());
        }
        if (addressBookPanel_ != nullptr)
        {
            addressBookPanel_->applyColumnGroup(
                static_cast<AddressBookPanel::ColumnGroup>(LoadAddrBookColumnGroup()));
            addressBookPanel_->setKindFilterIndex(LoadAddrBookKind());
        }
        if (textView_ != nullptr)
        {
            textView_->setEncoding(static_cast<WorkbenchTextView::Encoding>(LoadTextEncoding()));
        }
        if (liveRefreshCheckBox_ != nullptr)
        {
            liveRefreshCheckBox_->setChecked(LoadLiveRefresh());
        }
        if (liveRefreshTimer_ != nullptr)
        {
            liveRefreshTimer_->setInterval(LoadLiveIntervalMs());
        }
    }

    // saveSettings：非权威视图是空操作（决策 1：只有主 Dock 的非内嵌视图落盘）。
    void MemoryWorkbenchView::saveSettings() const
    {
        if (!settingsAuthoritative_)
        {
            return;
        }
        using namespace ks::ui::workbench_settings;

        if (sessionBar_ != nullptr)
        {
            SaveScope(static_cast<std::uint32_t>(sessionBar_->currentScope()));
            SaveWriteMode(sessionBar_->currentWriteMode() == ksword::memwb::WriteMode::StagedThenApply ? 1U : 0U);
            SaveChannelForScope(
                static_cast<std::uint32_t>(ksword::memwb::Scope::ProcessVirtual),
                static_cast<std::uint32_t>(sessionBar_->rememberedChannel(ksword::memwb::Scope::ProcessVirtual)));
            SaveChannelForScope(
                static_cast<std::uint32_t>(ksword::memwb::Scope::KernelVirtual),
                static_cast<std::uint32_t>(sessionBar_->rememberedChannel(ksword::memwb::Scope::KernelVirtual)));
            SaveChannelForScope(
                static_cast<std::uint32_t>(ksword::memwb::Scope::Physical),
                static_cast<std::uint32_t>(sessionBar_->rememberedChannel(ksword::memwb::Scope::Physical)));
        }
        if (sidebarContainer_ != nullptr)
        {
            // 存"想要可见"（sidebarWantedVisible_），而不是控件此刻的显隐：窄窗口
            // 自动折叠、内嵌模式隐藏都只是显示层的副作用，不能覆盖用户宽屏时的偏好
            // （第二轮复核 B1：旧实现存 !isHidden()，窄窗口关闭后宽屏偏好被冲掉）。
            SaveSidebarVisible(sidebarWantedVisible_);
        }
        if (mainSplitter_ != nullptr && sidebarContainer_ != nullptr
            && !sidebarContainer_->isHidden() && mainSplitter_->sizes().size() == 2)
        {
            // 只在侧栏可见时存宽度：隐藏时第二项恒为 0，存下去会把用户调好的宽度冲掉；
            // 低于读取侧下限（120）的值读回来也会被当非法值，所以不存。
            const int sidebarWidth = mainSplitter_->sizes().at(1);
            if (sidebarWidth >= 120)
            {
                SaveSidebarWidth(sidebarWidth);
            }
        }
        if (subTabStack_ != nullptr)
        {
            SaveSubTab(subTabStack_->currentIndex());
        }
        if (statusBar_ != nullptr)
        {
            SaveDiagExpanded(statusBar_->isDrawerExpanded());
        }
        if (addressBookPanel_ != nullptr)
        {
            SaveAddrBookColumnGroup(static_cast<int>(addressBookPanel_->columnGroup()));
            SaveAddrBookKind(addressBookPanel_->kindFilterIndex());
        }
        if (textView_ != nullptr)
        {
            SaveTextEncoding(static_cast<int>(textView_->encoding()));
        }
        if (liveRefreshCheckBox_ != nullptr)
        {
            SaveLiveRefresh(liveRefreshCheckBox_->isChecked());
        }
        // 十六进制画布偏好：自动状态总是存，bytesPerRow 只在非自动时才存（见 HexPrefs.cpp 文件头）。
        saveHexPreferences();
    }

    // installLeaveGuard：组合两条守卫，注册给 target_。①写控制器是否有未提交
    // 暂存（Idle/Staged 两种写入模式下，HasPendingPatches 恒等价于"待写入区
    // 是否显示"的那个判据——这里直接查询 writeController_ 当前能否撤销来判断
    // "有没有东西"并不准确，真正的判据是"undo 之外、还没提交的暂存"，即
    // writeController_ 所持 overlay 的 DiffBlocks 非空；本类不直接持有 overlay，
    // 经 hexPane_->overlay() 查询）②int3Controller 的
    // HasUnrestoredForCurrentTarget。两者都放行才 true；"只问一次"由
    // WorkbenchTarget::requestIdentity 自己的"先 predict 再问"机制保证（本类
    // 这里只是提供"问到的时候该怎么答"，不重复 predict 逻辑）。
    void MemoryWorkbenchView::installLeaveGuard()
    {
        target_->setLeaveGuard([this](LeaveReason reason) -> bool {
            // self：离开询问会进入模态事件循环，期间宿主可能同步销毁视图；返回后必须先探活。
            const QPointer<MemoryWorkbenchView> self(this);
            // Int3LeaveScenario 只有三个取值：DockDetach/ProcessChange/MainWindowClose；
            // 后者不经过这条 LeaveReason 路径（主窗口关闭走 confirmQuit，见下）。这里只需要
            // 区分"是不是 Dock 的附加/分离事件"，其余三种 LeaveReason（ScopeChange/
            // ChannelChange/PinChange）对 int3 账本而言都是同一类"目标可能要变了"，统一按
            // ProcessChange 处理。
            const auto scenario = (reason == LeaveReason::DockAttachChange)
                ? Int3LeaveScenario::DockDetach
                : Int3LeaveScenario::ProcessChange;
            // 每次询问都先清掉上一次的"用户已选择保留补丁"记号，只有这次明确选了才重新置位。
            int3KeptByLeaveGuard_ = false;
            const bool allowed = runLeaveSequence(LeaveReasonDisplayText(reason), scenario);
            if (!self)
            {
                return false;
            }
            // Dock 的附加/分离是"先问守卫、再真正分离"两步：用户在守卫里选了"保留补丁继续"
            // （放行之后账本里当前目标仍有未还原条目）时，紧接着发出的 aboutToDetach 安全网
            // 不得再把补丁强制还原，否则等于无视用户刚做的明确选择（见 onTargetAboutToDetach）。
            if (allowed && reason == LeaveReason::DockAttachChange)
            {
                syncInt3Context();
                if (!self)
                {
                    return false;
                }
                int3KeptByLeaveGuard_ = WorkbenchShared::Instance().Int3().HasUnrestoredForCurrentTarget();
            }
            return allowed;
        });
    }

    // confirmQuit：见头文件声明处的注释。主窗口关闭路径与"离开守卫"共用同一条三阶段原子逻辑，
    // 只是原因文案固定为"退出程序"、int3 场景固定为 MainWindowClose。
    bool MemoryWorkbenchView::confirmQuit()
    {
        const QPointer<MemoryWorkbenchView> self(this);
        int3KeptByLeaveGuard_ = false;
        const bool allowed = runLeaveSequence(QStringLiteral("退出程序"), Int3LeaveScenario::MainWindowClose);
        if (!self)
        {
            return false;
        }
        if (allowed)
        {
            // 关闭详情窗口随后会分离内嵌 Dock；尊重这次明确选择的保留补丁。
            syncInt3Context();
            if (!self)
            {
                return false;
            }
            int3KeptByLeaveGuard_ = WorkbenchShared::Instance().Int3().HasUnrestoredForCurrentTarget();
        }
        return allowed;
    }

    void MemoryWorkbenchView::cancelQuitPreparation()
    {
        int3KeptByLeaveGuard_ = false;
    }

    // runLeaveSequence：离开守卫与 confirmQuit 共用的三阶段原子逻辑。
    // 传入：reasonText 拼进"有未提交修改"确认框正文的原因短句；scenario 传给 int3 退出提示的场景。
    // 传出：true=可以离开/退出（暂存已应用或丢弃、int3 已还原或用户选择保留）；
    //       false=用户取消或应用失败，此时暂存与 int3 都原封不动（应用失败时暂存保留）。
    bool MemoryWorkbenchView::runLeaveSequence(const QString& reasonText, const Int3LeaveScenario scenario)
    {
        // 外层写确认仍在运行时不能嵌套丢弃、换目标或关闭其事务宿主。
        if (writeController_ != nullptr && writeController_->isCommitting())
        {
            return false;
        }
        // 第二轮复核 B3：守卫必须"原子"——整件事被取消时，用户的未提交编辑不能
        // 已经被丢弃/写入。所以分三个阶段：
        //   阶段一 只"问"暂存补丁三选一（不执行任何动作）；
        //   阶段二 问 int3（取消则整体拒绝，此时暂存原封不动）；
        //   阶段三 两个都同意之后，才真正应用/丢弃暂存。
        // 两个询问框都是嵌套事件循环，期间视图可能被外部同步销毁，每个框之后
        // 先判 self 再碰任何成员（与 WorkbenchTarget::requestIdentity 的 N3 同理）。
        const QPointer<MemoryWorkbenchView> self(this);

        // int3 阶段按"账本当前目标"判断有无未还原补丁：先把它声明回本视图的目标，
        // 否则内嵌进程详情窗口改过它之后，本视图的补丁会被漏问。
        if (!memoryDebugMode_)
        {
            syncInt3Context();
        }

        if (!self || target_ == nullptr)
        {
            return false;
        }
        const auto leaveCapture = target_->capture();
        if (!self)
        {
            return false;
        }
        // 两次询问都只授权开始时的目标与暂存内容，嵌套事件循环里的变更不能继承授权。
        const auto stillCurrent = [self, rev = leaveCapture.rev]() {
            if (!self || self->target_ == nullptr)
            {
                return false;
            }
            const bool stale = self->target_->isStale(rev);
            if (!self)
            {
                return false;
            }
            if (stale && self->statusBar_ != nullptr)
            {
                self->statusBar_->setDiagnosticsText(workbench_messages::Translate(
                    ksword::memwb::CommitOutcome::Stale), /*autoExpand=*/true);
            }
            return !stale;
        };

        auto pendingDecision = ksword::memwb::ModeSwitchDecision::Cancel;
        bool hasPendingDecision = false;
        if (hexPane_ != nullptr && hexPane_->overlay().HasPendingPatches() && confirmations_)
        {
            // 修复缺陷 3（审核报告 wpJ6/wave3 发现 3）：原来这里误调用
            // PromptModeSwitch，from/to 两个参数传同一个表达式——这个
            // 调用点根本不是在切换写入模式，是用户正在触发身份变化
            // （换目标/换范围/换通道）或离开视图，PromptModeSwitch
            // 固定的"切换到「立即写入」前必须先处理"文案对用户是误导性
            // 的（当前就是立即写入，写入模式从未变化）。改用专门的
            // PromptLeaveWithPending，正文写清字节数/块数与离开原因
            // （reasonText 是人话短句），按钮语义也改成"应用并离开/
            // 丢弃并离开/取消"——没有"切换"这件事。
            pendingDecision = confirmations_->PromptLeaveWithPending(
                hexPane_->overlay().PendingByteCount(),
                static_cast<std::uint64_t>(hexPane_->overlay().DiffBlocks().size()),
                reasonText);
            if (!stillCurrent())
            {
                return false;
            }
            if (pendingDecision != ksword::memwb::ModeSwitchDecision::ApplyThenSwitch &&
                pendingDecision != ksword::memwb::ModeSwitchDecision::DiscardThenSwitch)
            {
                return false;
            }
            hasPendingDecision = true;
        }

        // 暂存询问的事件循环可能让另一个视图接管共享 int3 上下文；执行前重新绑定本视图。
        if (!memoryDebugMode_)
        {
            syncInt3Context();
        }
        if (!self)
        {
            return false;
        }

        // 阶段二：int3 账本里当前目标还有未还原补丁时弹三选一（没有则直接放行，不弹框）。
        const bool int3Allowed = memoryDebugMode_
            || WorkbenchShared::Instance().Int3().RequestLeave(this, scenario);
        if (!self || !int3Allowed || !stillCurrent())
        {
            return false;
        }

        // 阶段三：两个都同意之后才执行暂存的应用/丢弃。
        if (!hasPendingDecision)
        {
            return true;
        }
        if (pendingDecision == ksword::memwb::ModeSwitchDecision::ApplyThenSwitch)
        {
            const auto attempt = writeController_->commitPendingNow();
            if (self.isNull())
            {
                return false;
            }
            return attempt.status != CommitEntryStatus::Busy &&
                (attempt.report.outcome == ksword::memwb::CommitOutcome::Committed ||
                 attempt.report.outcome == ksword::memwb::CommitOutcome::NoChange);
        }
        // 丢弃并离开：叠加层清空后画布要重绘，会话条的"N 字节待写入"也要同步清掉
        // （第二轮复核 B4：旧实现漏了后一步，芯片残留）。
        const bool hadPendingPatches = hexPane_->overlay().HasPendingPatches();
        hexPane_->overlay().DiscardAll();
        if (hadPendingPatches && target_ != nullptr)
        {
            // 真正丢弃会改变工作台显示内容；推进内容代次，让既有捕获能识别这次变化。
            target_->noteContentChanged();
        }
        if (hexPane_->canvas() != nullptr)
        {
            hexPane_->canvas()->notifyOverlayChanged();
        }
        refreshPendingPatchesDisplay();
        return true;
    }

    // wireActions：对 WorkbenchActionId 的每一项挂快捷键；Redo 同时挂主键与候补
    // 键到同一个槛（F02/S07 的落实点）。Esc 不注册（各面板自己处理）。
    void MemoryWorkbenchView::wireActions()
    {
        const auto bindUndo = [this]() {
            if (writeController_)
            {
                writeController_->undo();
            }
        };
        const auto bindRedo = [this]() {
            if (writeController_)
            {
                writeController_->redo();
            }
        };
        const auto bindReread = [this]() {
            if (hexPane_ != nullptr)
            {
                hexPane_->rereadWindow();
            }
        };

        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::Undo, this))
        {
            connect(s, &QShortcut::activated, this, bindUndo);
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::Redo, this))
        {
            connect(s, &QShortcut::activated, this, bindRedo);
        }
        if (auto* s = CreateWorkbenchAlternateShortcut(WorkbenchActionId::Redo, this))
        {
            connect(s, &QShortcut::activated, this, bindRedo);
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::Reread, this))
        {
            connect(s, &QShortcut::activated, this, bindReread);
        }
        if (rereadButton_ != nullptr)
        {
            connect(rereadButton_, &QToolButton::clicked, this, bindReread);
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::FocusAddressBar, this))
        {
            connect(s, &QShortcut::activated, this, [this]() {
                if (addressEdit_ != nullptr)
                {
                    addressEdit_->setFocus();
                    addressEdit_->selectAll();
                }
            });
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::GoBack, this))
        {
            connect(s, &QShortcut::activated, this, &MemoryWorkbenchView::onGoBackRequested);
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::GoForward, this))
        {
            connect(s, &QShortcut::activated, this, &MemoryWorkbenchView::onGoForwardRequested);
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::ToggleWriteMode, this))
        {
            connect(s, &QShortcut::activated, this, [this]() {
                if (sessionBar_ != nullptr)
                {
                    const auto next = sessionBar_->currentWriteMode() == ksword::memwb::WriteMode::Immediate
                        ? ksword::memwb::WriteMode::StagedThenApply
                        : ksword::memwb::WriteMode::Immediate;
                    onSessionBarModeRequested(next);
                }
            });
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::ApplyPending, this))
        {
            connect(s, &QShortcut::activated, this, &MemoryWorkbenchView::onSessionBarApplyRequested);
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::DiscardPending, this))
        {
            connect(s, &QShortcut::activated, this, &MemoryWorkbenchView::onSessionBarDiscardRequested);
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::AddToAddressBook, this))
        {
            connect(s, &QShortcut::activated, this, [this]() {
                if (hexPane_ != nullptr)
                {
                    addInsertionPointToAddressBook(hexPane_->insertionAddress());
                }
            });
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::ToggleSidebar, this))
        {
            // 修复缺陷 1：与侧栏自动折叠共用同一个入口（toggleSidebarByUser），
            // 不再在这里重复"直接 setVisible(isHidden())"——那样会绕过
            // sidebarUserOverride_ 的置位，自动折叠逻辑之后还会把用户刚手动
            // 展开的侧栏在下一次 resize 时悄悄收回去。
            connect(s, &QShortcut::activated, this, &MemoryWorkbenchView::toggleSidebarByUser);
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::ToggleInspector, this))
        {
            connect(s, &QShortcut::activated, this, [this]() {
                if (hexPane_ != nullptr && hexPane_->inspector() != nullptr)
                {
                    // 修复缺陷 1 的配套调整：手动按过 Ctrl+I 之后，窄窗口自动
                    // 折叠逻辑（maybeAutoCollapseInspector）不再接管，尊重用户。
                    inspectorUserOverride_ = true;
                    hexPane_->inspector()->setVisible(hexPane_->inspector()->isHidden());
                }
            });
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::Find, this))
        {
            connect(s, &QShortcut::activated, this, &MemoryWorkbenchView::openActiveFind);
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::OpenInDisasm, this))
        {
            connect(s, &QShortcut::activated, this, [this]() {
                // Ctrl+D：在反汇编页打开十六进制选区的起点。旧实现先调 onDisasmRequestHexLocate（把十六进制
                // 的选区折叠成 1 字节并切回十六进制页），再切到反汇编页，再 jumpTo 一次（重复压后退栈）；
                // 现在统一走 showSubPageAt：不折叠选区、只定位一次。
                if (hexPane_ != nullptr && subTabStack_ != nullptr)
                {
                    showSubPageAt(1, hexPane_->selectionStart());
                }
            });
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::SwitchTabHex, this))
        {
            connect(s, &QShortcut::activated, this, [this]() { if (subTabStack_) subTabStack_->setCurrentIndex(0); });
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::SwitchTabDisasm, this))
        {
            connect(s, &QShortcut::activated, this, [this]() { if (subTabStack_) subTabStack_->setCurrentIndex(1); });
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::SwitchTabText, this))
        {
            connect(s, &QShortcut::activated, this, [this]() { if (subTabStack_) subTabStack_->setCurrentIndex(2); });
        }
        if (auto* s = CreateWorkbenchShortcut(WorkbenchActionId::SwitchTabCompare, this))
        {
            connect(s, &QShortcut::activated, this, [this]() { if (subTabStack_) subTabStack_->setCurrentIndex(3); });
        }
    }
}
