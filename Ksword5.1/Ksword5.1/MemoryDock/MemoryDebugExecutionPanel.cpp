#include "../Framework.h"
#include "MemoryDebugExecutionPanel.h"
#include "../UI/ShortcutRegistry.h"
#include "../../../shared/debug/CooperativeDebugClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncUiDispatcher.h"
#include "../UI/DetailDialogChrome.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/UI_All.h"
#include "../UI/ThemedMessageBox.h"
#include "../theme.h"

#include <QComboBox>
#include <QApplication>
#include <QDialog>
#include <QEventLoop>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPointer>
#include <QSignalBlocker>
#include <QShortcut>
#include <QThreadPool>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

namespace ks::ui
{
    namespace
    {
        // 退出事务只允许只读状态/租约查询；内部 prepareClose 不走此交互门。
        bool RejectExecutionDuringQuit(const int operation)
        {
            return operation != 4 && qApp != nullptr
                && qApp->property("ksword_memory_quit_guard_active").toBool();
        }

        // 运行期组合消息逐段翻译，不依赖页面初次创建时的语言。
        QString T(const char* source)
        {
            return ks::i18n::sourceText(QString::fromUtf8(source));
        }

        // Action：输入宿主、资源图标和源语言释义，返回使用共享度量的图标动作。
        QToolButton* Action(QWidget* parent, const char* icon, const char* tip)
        {
            auto* button = new QToolButton(parent); // 生命周期交给工具带。
            button->setIcon(QIcon(QString::fromUtf8(icon)));
            button->setToolTip(T(tip));
            button->setAutoRaise(true);
            KswordTheme::ApplyCompactIconButtonMetrics(button);
            return button;
        }

        // Hex：把寄存器值转为固定宽度文本，不把数字解释为可访问地址。
        QString Hex(const std::uint64_t value)
        {
            return QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0')).toUpper();
        }

        // 身份回执丢失时先查询本请求者的会话；从不调用普通 HVM 的全局 STOP。
        ksword::ark::HvmNoAttachResult CloseOwnedHvm(KSWORD_ARK_HVM_NOATTACH_REQUEST request,
            ksword::ark::DriverHandle* handle, bool kernel)
        {
            ksword::ark::HvmNoAttachResult result;
            if (request.sessionId == 0)
            {
                request.operation = KSWORD_ARK_HVM_NOATTACH_QUERY;
                result = kernel ? ksword::ark::controlKernelNoAttach(request, handle) : ksword::ark::controlHvmNoAttach(request, handle);
                if (result.io.ok && result.response.status >= 0)
                {
                    request.sessionId = result.response.sessionId;
                }
            }
            if (request.sessionId != 0)
            {
                request.operation = KSWORD_ARK_HVM_NOATTACH_CLOSE;
                result = kernel ? ksword::ark::controlKernelNoAttach(request, handle) : ksword::ark::controlHvmNoAttach(request, handle);
            }
            return result;
        }

        // 精确比较规范显示值，包含同一 stopId 下更新的寄存器，不依赖协议结构填充字节。
        template<class Snapshot>
        std::array<std::uint64_t, 28> RegisterDocumentKey(const std::uint64_t backend,
            const std::uint64_t epoch, const std::uint64_t session, const std::uint64_t stop,
            const std::uint64_t pid, const std::uint64_t creation, const std::uint64_t tid,
            const std::uint64_t threadCreation, const std::uint64_t reason, const std::uint64_t cr3,
            const Snapshot& s)
        {
            return {backend, epoch, session, stop, pid, creation, tid, threadCreation, reason, cr3,
                s.rip, s.rsp, s.rflags, s.rax, s.rbx, s.rcx, s.rdx, s.rbp, s.rsi, s.rdi,
                s.r8, s.r9, s.r10, s.r11, s.r12, s.r13, s.r14, s.r15};
        }

        // 两种后端共用具名整数寄存器字段；DR/XSTATE 的能力不得被模板补零冒充。
        template<class Snapshot>
        void AddRegisters(FieldDocument& doc, const Snapshot& s)
        {
            doc.section(T("整数与控制寄存器"));
            doc.field(QStringLiteral("RIP"), Hex(s.rip));
            doc.field(QStringLiteral("RSP"), Hex(s.rsp));
            doc.field(QStringLiteral("RFLAGS"), Hex(s.rflags));
            doc.field(QStringLiteral("RAX"), Hex(s.rax));
            doc.field(QStringLiteral("RBX"), Hex(s.rbx));
            doc.field(QStringLiteral("RCX"), Hex(s.rcx));
            doc.field(QStringLiteral("RDX"), Hex(s.rdx));
            // 这些值来自同一现场，不再逐个查询目标造成寄存器时间混合。
            doc.field(QStringLiteral("RBP"), Hex(s.rbp));
            doc.field(QStringLiteral("RSI"), Hex(s.rsi));
            doc.field(QStringLiteral("RDI"), Hex(s.rdi));
            doc.field(QStringLiteral("R8"), Hex(s.r8));
            doc.field(QStringLiteral("R9"), Hex(s.r9));
            doc.field(QStringLiteral("R10"), Hex(s.r10));
            doc.field(QStringLiteral("R11"), Hex(s.r11));
            // 高位通用寄存器仍沿用原始 64 位值，不裁为界面指针宽度。
            doc.field(QStringLiteral("R12"), Hex(s.r12));
            doc.field(QStringLiteral("R13"), Hex(s.r13));
            doc.field(QStringLiteral("R14"), Hex(s.r14));
            doc.field(QStringLiteral("R15"), Hex(s.r15));
        }
    }

    MemoryDebugExecutionPanel::MemoryDebugExecutionPanel(QWidget* parent)
        : QWidget(parent), dispatcher_(std::make_shared<AsyncUiDispatcher>(this)),
          native_(std::make_shared<MemoryDebugThreadSession>()),
          cooperative_(std::make_shared<ksword::cooperative::Session>()),
          hvmHandle_(std::make_shared<ksword::ark::DriverHandle>())
    {
        setObjectName(QStringLiteral("memory_debug_execution"));
        StylePrimaryToolbar(this);
        auto* root = new QVBoxLayout(this); // 专业页只增加紧凑工具带，结果仍由工作台伸展。
        root->setContentsMargins(8, 4, 8, 4);
        root->setSpacing(6);
        auto* row = new QHBoxLayout(); // 选择器可缩，图标动作保持共享尺寸。
        backend_ = new QComboBox(this);
        backend_->setObjectName(QStringLiteral("memory_debug_backend"));
        backend_->addItems({T("R3 线程检查"), T("协作 VEH 单步"), T("HVM 无附加调试（实验）"), T("普通驱动无附加调试（实验）")});
        backend_->setMinimumWidth(0);
        backend_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
        StylePrimaryCombo(backend_);
        row->addWidget(backend_, 1);
        thread_ = new QComboBox(this);
        thread_->setObjectName(QStringLiteral("memory_debug_thread"));
        thread_->setMinimumWidth(0);
        thread_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
        StylePrimaryCombo(thread_);
        row->addWidget(thread_, 1);
        refresh_ = Action(this, ":/Icon/process_refresh.svg", "刷新线程或连接目标主动加载的协作组件");
        capture_ = Action(this, ":/Icon/process_details.svg", "临时暂停所选线程，读取寄存器后立即恢复");
        pause_ = Action(this, ":/Icon/process_pause.svg", "暂停所选线程；协作模式等待目标主动检查点");
        resume_ = Action(this, ":/Icon/process_start.svg", "仅恢复本会话暂停的线程，或继续当前协作停点");
        step_ = Action(this, ":/Icon/memwb_tab_disasm.svg", "请求真实单步，以后端新的停止事件为准");
        registers_ = Action(this, ":/Icon/process_copy_row.svg", "查看最近一次寄存器现场及来源，可搜索、复制和导出");
        openHvm_ = Action(this, ":/Icon/process_start.svg", "显式启动所选无附加执行后端，以实际能力与确认结果为准");
        openHvm_->setObjectName(QStringLiteral("memory_debug_hvm_open"));
        configureHvm_ = Action(this, ":/Icon/process_details.svg", "管理当前后端执行断点、运行到地址和整数寄存器");
        configureHvm_->setObjectName(QStringLiteral("memory_debug_hvm_controls"));
        closeHvm_ = Action(this, ":/Icon/log_clear.svg", "关闭本会话的独立运行控制，保留内存视图");
        closeHvm_->setObjectName(QStringLiteral("memory_debug_hvm_close"));
        ApplyFlatButtonTheme(openHvm_, FlatButtonTone::Danger);
        ApplyFlatButtonTheme(resume_, FlatButtonTone::Accent);
        refresh_->setObjectName(QStringLiteral("memory_debug_connect"));
        capture_->setObjectName(QStringLiteral("memory_debug_capture"));
        pause_->setObjectName(QStringLiteral("memory_debug_pause"));
        resume_->setObjectName(QStringLiteral("memory_debug_resume"));
        step_->setObjectName(QStringLiteral("memory_debug_step"));
        registers_->setObjectName(QStringLiteral("memory_debug_registers"));
        // 普通线程模式不设置 TF；只有具备目标内异常消费者的后端才启用单步。
        for (auto* button : {refresh_, openHvm_, capture_, pause_, resume_, step_, registers_, configureHvm_, closeHvm_})
        {
            row->addWidget(button);
        }
        NormalizeToolbarRow(row);
        root->addLayout(row);
        status_ = new QLabel(T("选择进程后刷新线程；R3 检查只暂停一个线程，其余线程继续运行。"), this);
        status_->setWordWrap(true);
        status_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        root->addWidget(status_);
        connect(refresh_, &QToolButton::clicked, this, [this]() { execute(0); });
        connect(capture_, &QToolButton::clicked, this, [this]() { execute(2); });
        connect(pause_, &QToolButton::clicked, this, [this]() { execute(1); });
        connect(resume_, &QToolButton::clicked, this, [this]() { execute(3); });
        connect(step_, &QToolButton::clicked, this, [this]() { execute(5); });
        connect(registers_, &QToolButton::clicked, this, &MemoryDebugExecutionPanel::showRegisters);
        connect(openHvm_, &QToolButton::clicked, this, [this]() { execute(7); });
        connect(configureHvm_, &QToolButton::clicked, this, &MemoryDebugExecutionPanel::showHvmControls);
        connect(closeHvm_, &QToolButton::clicked, this, [this]() { if (!busy_) (void)closeHvm(); });
        // 快捷键仅属于本页及工作台子树；隐藏页不抢其它工具窗的调试按键。
        auto* singleStep = new QShortcut(QKeySequence(Qt::Key_F7), parent);
        singleStep->setContext(Qt::WidgetWithChildrenShortcut);
        ks::ui::ShortcutRegistry::instance().bindDefaultShortcut(QStringLiteral("debug"), singleStep);
        connect(singleStep, &QShortcut::activated, step_, &QToolButton::click);
        auto* continueExecution = new QShortcut(QKeySequence(Qt::Key_F9), parent);
        continueExecution->setContext(Qt::WidgetWithChildrenShortcut);
        ks::ui::ShortcutRegistry::instance().bindDefaultShortcut(QStringLiteral("debug"), continueExecution);
        connect(continueExecution, &QShortcut::activated, resume_, &QToolButton::click);
        auto* pauseExecution = new QShortcut(QKeySequence(Qt::Key_F12), parent);
        pauseExecution->setContext(Qt::WidgetWithChildrenShortcut);
        ks::ui::ShortcutRegistry::instance().bindDefaultShortcut(QStringLiteral("debug"), pauseExecution);
        connect(pauseExecution, &QShortcut::activated, pause_, &QToolButton::click);
        ks::ui::ShortcutRegistry::instance().setShortcutHint(QStringLiteral("debug.step"), step_, step_->toolTip());
        ks::ui::ShortcutRegistry::instance().setShortcutHint(QStringLiteral("debug.continue"), resume_, resume_->toolTip());
        ks::ui::ShortcutRegistry::instance().setShortcutHint(QStringLiteral("debug.pause"), pause_, pause_->toolTip());
        connect(backend_, &QComboBox::activated, this, [this](const int index)
        {
            const QPointer<MemoryDebugExecutionPanel> self(this); // HVM 关闭会处理嵌套事件循环。
            {
                const QSignalBlocker blocker(backend_); // 释放完成之前仍展示真实生效的旧后端。
                backend_->setCurrentIndex(mode_);
            }
            if (RejectExecutionDuringQuit(0) || !isEnabled())
            {
                return;
            }
            if (!prepareClose())
            {
                if (!self)
                {
                    return;
                }
                const QSignalBlocker blocker(backend_); // 恢复失败时保留原后端与恢复入口。
                backend_->setCurrentIndex(mode_);
                return;
            }
            mode_ = index;
            backend_->setCurrentIndex(index);
            setTarget(pid_, creation_);
        });
        poll_ = new QTimer(this);
        poll_->setInterval(1000);
        connect(poll_, &QTimer::timeout, this, [this]()
        {
            if (!busy_ && ((mode_ == 1 && connected_) || (mode_ == 0 && ownsPause_)
                || (mode_ >= 2 && (hvmSessionId_ != 0 || hvmOwnershipUncertain_))))
            {
                execute(4);
            }
        });
        poll_->start();
        FILETIME created{}; // 当前控制器创建时间，不依赖稍后复用的 PID。
        FILETIME exited{}; // GetProcessTimes 要求的退出时间输出。
        FILETIME kernel{}; // GetProcessTimes 要求的内核用时输出。
        FILETIME user{}; // GetProcessTimes 要求的用户用时输出。
        if (::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user))
        {
            ownerCreation_ = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        }
        updateActions();
    }

    MemoryDebugExecutionPanel::~MemoryDebugExecutionPanel()
    {
        dispatcher_->close(); // 已入队回投不能访问开始析构的控件。
        if (hvmSessionId_ != 0 || hvmOwnershipUncertain_)
        {
            auto request = KSWORD_ARK_HVM_NOATTACH_REQUEST{}; // 仅清理本页已经确认持有的生命周期。
            request.operation = KSWORD_ARK_HVM_NOATTACH_CLOSE;
            request.ownerCreationTime = ownerCreation_;
            request.sessionId = hvmSessionId_;
            const auto handle = hvmHandle_; // 设备句柄活到后台清理结束，不复用控件指针。
            const bool kernel = mode_ == 3;
            QThreadPool::globalInstance()->start([request, handle, kernel]()
            {
                (void)CloseOwnedHvm(request, handle.get(), kernel);
            });
        }
    }

    void MemoryDebugExecutionPanel::setTarget(const std::uint32_t pid, const std::uint64_t creation)
    {
        if (hvmDialog_) hvmDialog_->close(); // 新目标通过原离开守卫后清退旧目标的工具草稿。
        hvmResponse_ = {};
        ++epoch_;
        pid_ = pid;
        creation_ = creation;
        threads_.clear();
        thread_->clear();
        document_ = {};
        documentKeyValid_ = false;
        stopId_ = 0;
        ownsPause_ = false;
        stopped_ = false;
        connected_ = false;
        hvmAvailable_ = false;
        fastPollBudget_ = 0;
        // 更换只发生在 prepareClose 成功之后；保持惰性，选进程不自动连接组件。
        status_->setText(mode_ == 3
            ? T("普通驱动：先刷新并选定线程。要求已验证内核与测试签名，HVCI 关闭；使用 TF/DR，不注入目标。首次启用后驱动留驻至重启。")
            : mode_ == 2
            ? T("实验 HVM：先刷新并选择线程。要求 Intel MBEC；优先 MTF，备用 VMX TF 会明确报告且 TF 可观察。不注入、不建立调试附加。")
            : mode_ == 1
                ? T("目标须主动启动协作组件；点击连接，不自动注入。暂停请求在目标的下一个主动检查点生效。")
                : T("刷新线程后可检查寄存器或暂停一个线程。此模式没有异常消费者，不能单步。"));
        updateActions();
    }

    bool MemoryDebugExecutionPanel::prepareClose()
    {
        if (busy_)
        {
            status_->setText(T("运行控制正在处理，请完成后重试关闭或切换。"));
            return false;
        }
        const auto result = native_->close(); // 先配平本会话挂起，失败保留句柄重试。
        if (!result.success)
        {
            applyNative(result, 3);
            return false;
        }
        cooperative_->close(); // 主动断开会放行目标，服务端另有 owner/租约恢复。
        if (!closeHvm())
        {
            return false;
        }
        // 确认释放后不让已关闭页面继续占用设备文件；失败仍保留原句柄恢复。
        hvmHandle_ = std::make_shared<ksword::ark::DriverHandle>();
        hvmAvailable_ = false;
        ownsPause_ = false;
        connected_ = false;
        stopped_ = false;
        stopId_ = 0;
        documentKeyValid_ = false;
        fastPollBudget_ = 0;
        updateActions();
        return true;
    }

    void MemoryDebugExecutionPanel::execute(const int operation)
    {
        if (RejectExecutionDuringQuit(operation) || (operation != 4 && !isEnabled()))
        {
            return;
        }
        if (busy_ || pid_ == 0)
        {
            return;
        }
        MemoryDebugThreadIdentity identity; // 选择器快照只在 UI 线程读取。
        if ((mode_ == 0 && operation != 0 && operation != 3 && operation != 4)
            || (mode_ >= 2 && operation == 7))
        {
            const int index = thread_->currentIndex();
            if (index < 0 || static_cast<std::size_t>(index) >= threads_.size())
            {
                return;
            }
            identity = threads_[static_cast<std::size_t>(index)].identity;
        }
        if (mode_ >= 2 && operation == 7)
        {
            // 显式启动会切换全核虚拟化控制；确认仅属于该次操作，不能由选择模式隐式授权。
            const QPointer<MemoryDebugExecutionPanel> self(this);
            const auto answer = QMessageBox::warning(this, T("实验无附加执行控制"),
                mode_ == 3 ? T("将修改已验证内核的异常分发入口，使用 TF 和 DR 控制一个用户线程，不建立 Windows 调试关系或注入目标。首次安装后转接器和驱动留驻至重启；关闭会话恢复目标状态和异常入口。此研究后端不保证 PatchGuard 兼容。是否启动？")
                    : T("将开启独占的 Intel 虚拟化调试会话，允许支持的来宾嵌套执行。要求 MBEC；优先 MTF，缺少 MTF 时仅在具备完整事件拦截能力的平台使用 VMX TF。备用模式的 TF 可观察，仅支持只读普通用户指令，特殊边界或故障可中断执行。是否启动？"),
                QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
            if (!self || answer != QMessageBox::Yes)
            {
                return;
            }
            hvmOwnershipUncertain_ = true;
        }
        if (mode_ != 0 && (operation == 1 || operation == 5))
        {
            fastPollBudget_ = 20;
        }
        else if (operation == 3)
        {
            fastPollBudget_ = 0;
        }
        else if (operation == 4 && fastPollBudget_ > 0)
        {
            --fastPollBudget_;
        }
        busy_ = true;
        updateActions();
        const auto epoch = epoch_; // 旧目标回投不得定位当前工作台。
        const auto pid = pid_; // 请求目标进程编号。
        const auto creation = creation_; // 请求目标创建时间。
        const auto stopId = stopId_; // 仅本次执行动作可消费的停点。
        const int mode = mode_; // 冻结本次后端，不从 worker 读取控件。
        const auto native = native_; // 任务期间持有原生暂停所有者。
        const auto cooperative = cooperative_; // 任务期间持有协作管道会话。
        const auto dispatcher = dispatcher_; // 工作完成后的可关闭回投门禁。
        const auto hvmHandle = hvmHandle_; // HVM 生命周期必须保持同一设备文件。
        const auto hvmSessionId = hvmSessionId_; // 当前独占资源会话代次。
        const auto ownerCreation = ownerCreation_; // 控制器本身的进程身份。
        QThreadPool::globalInstance()->start([this, operation, epoch, pid, creation, stopId, mode, identity, native, cooperative, dispatcher,
            hvmHandle, hvmSessionId, ownerCreation]()
        {
            MemoryDebugThreadResult result; // 工作线程只操作后端和值，不访问 QObject。
            ksword::cooperative::Result cooperativeResult;
            ksword::ark::HvmNoAttachResult hvmResult;
            if (mode == 0)
            {
                if (operation == 4)
                {
                    result = native->status();
                }
                else if (operation == 3)
                {
                    result = native->resume();
                }
                else
                {
                    result = native->open(pid, creation);
                    if (result.success)
                    {
                        if (operation == 0)
                        {
                            result = native->enumerateThreads();
                        }
                        else if (operation == 1)
                        {
                            result = native->pause(identity);
                            if (result.success)
                            {
                                result = native->querySnapshot(identity);
                            }
                        }
                        else if (operation == 2)
                        {
                            result = native->querySnapshot(identity);
                        }
                    }
                }
            }
            else if (mode == 1)
            {
                if (operation == 0)
                {
                    cooperativeResult = cooperative->open(pid, creation);
                }
                else if (operation == 1)
                {
                    cooperativeResult = cooperative->requestPause();
                }
                else if (operation == 3)
                {
                    cooperativeResult = cooperative->resume(stopId);
                }
                else if (operation == 4)
                {
                    cooperativeResult = cooperative->query();
                }
                else if (operation == 5)
                {
                    cooperativeResult = cooperative->step(stopId);
                }
                if (!cooperativeResult.ok())
                {
                    cooperative->close();
                }
            }
            else
            {
                if (operation == 0)
                {
                    result = native->open(pid, creation);
                    if (result.success)
                    {
                        result = native->enumerateThreads();
                    }
                }
                // QUERY 是只读能力/状态请求；唯有 operation 7 的确认分支可 OPEN。
                KSWORD_ARK_HVM_NOATTACH_REQUEST request{};
                request.ownerCreationTime = ownerCreation;
                request.sessionId = hvmSessionId;
                request.stopId = stopId;
                request.operation = KSWORD_ARK_HVM_NOATTACH_QUERY;
                if (operation == 1)
                {
                    request.operation = KSWORD_ARK_HVM_NOATTACH_PAUSE;
                }
                if (operation == 3)
                {
                    request.operation = KSWORD_ARK_HVM_NOATTACH_CONTINUE;
                }
                if (operation == 5)
                {
                    request.operation = KSWORD_ARK_HVM_NOATTACH_STEP;
                }
                if (operation == 7)
                {
                    request.operation = KSWORD_ARK_HVM_NOATTACH_OPEN;
                    request.flags = KSWORD_ARK_HVM_NOATTACH_CONFIRMED | (mode == 3 ? KSWORD_ARK_KERNEL_NOATTACH_HOOK_ACK : KSWORD_ARK_HVM_NOATTACH_ALLOW_NESTED);
                    request.processId = identity.pid;
                    request.threadId = identity.tid;
                    request.processCreationTime = identity.processCreateTime100ns;
                    request.threadCreationTime = identity.threadCreateTime100ns;
                }
                if (!hvmHandle->isValid())
                {
                    *hvmHandle = ksword::ark::DriverClient{}.openSilently();
                }
                if (hvmHandle->isValid())
                {
                    hvmResult = mode == 3 ? ksword::ark::controlKernelNoAttach(request, hvmHandle.get())
                        : ksword::ark::controlHvmNoAttach(request, hvmHandle.get());
                }
                else
                {
                    // 被动能力入口使用本页状态展示权限失败，不隐式弹出提权或加载提示。
                    hvmResult.io.win32Error = ::GetLastError();
                    if (hvmResult.io.win32Error == ERROR_SUCCESS)
                    {
                        hvmResult.io.win32Error = ERROR_INVALID_HANDLE;
                    }
                    hvmResult.io.deviceOpenFailed = true;
                }
            }
            dispatcher->post([this, epoch, operation, mode, result = std::move(result), cooperativeResult = std::move(cooperativeResult),
                hvmResult = std::move(hvmResult)]()
            {
                const QPointer<MemoryDebugExecutionPanel> self(this); // RIP 导航可能进入宿主的离开守卫。
                busy_ = false;
                if (epoch != epoch_)
                {
                    updateActions();
                    return;
                }
                if (mode == 0)
                {
                    applyNative(result, operation);
                }
                else if (mode == 1)
                {
                    applyCooperative(cooperativeResult);
                }
                else
                {
                    if (operation == 0)
                    {
                        applyNative(result, operation);
                    }
                    if (operation != 0 || result.success)
                    {
                        applyHvm(hvmResult);
                        if (operation == 0)
                        {
                            status_->setText(status_->text() + QLatin1Char('\n')
                                + T("已核验线程：%1；无法取得可靠身份：%2。仅控制所选线程。")
                                    .arg(result.threads.size()).arg(result.inaccessibleThreads));
                        }
                    }
                    else
                    {
                        // 体系结构或强身份失败不能被独立硬件能力说明覆盖。
                        hvmAvailable_ = false;
                    }
                }
                if (self)
                {
                    updateActions();
                }
            });
        });
    }

    void MemoryDebugExecutionPanel::applyNative(const MemoryDebugThreadResult& result, const int operation)
    {
        ownsPause_ = result.ownedSuspend;
        if (operation == 0 && result.success)
        {
            threads_ = result.threads;
            thread_->clear();
            for (const auto& record : threads_)
            {
                thread_->addItem(T("线程 %1").arg(record.identity.tid));
            }
        }
        if (!result.success)
        {
            status_->setText(T("线程操作失败：%1；Win32=%2。仍持有自有暂停：%3")
                .arg(ks::i18n::sourceText(QString::fromStdString(result.detail))).arg(result.errorWin32)
                .arg(ownsPause_ ? T("是") : T("否")));
            return;
        }
        status_->setText(ownsPause_
            ? T("本会话已暂停一个线程，其余线程继续运行；恢复按钮只归还这一次暂停。")
            : T("本会话未持有线程暂停；已有寄存器仅是历史快照。"));
        if (operation == 0)
        {
            status_->setText(T("已核验线程：%1；无法取得可靠身份：%2。仅控制所选线程。")
                .arg(result.threads.size()).arg(result.inaccessibleThreads));
        }
        if (!result.hasSnapshot)
        {
            return;
        }
        document_ = {};
        document_.title = T("不附加寄存器现场");
        document_.section(T("现场身份"));
        document_.field(QStringLiteral("PID"), QString::number(result.snapshot.identity.pid));
        document_.field(QStringLiteral("TID"), QString::number(result.snapshot.identity.tid));
        document_.field(T("进程创建时间（100ns）"), QString::number(result.snapshot.identity.processCreateTime100ns));
        document_.field(T("线程创建时间（100ns）"), QString::number(result.snapshot.identity.threadCreateTime100ns));
        document_.field(T("捕获时间（100ns）"), QString::number(result.snapshot.capturedAt100ns));
        document_.note(result.snapshot.transientPause && !result.ownedSuspend ? T("读取后已归还临时暂停；此处不是当前停止事件。")
            : T("此快照来自本会话持有的单线程暂停；其它线程继续运行。"));
        AddRegisters(document_, result.snapshot);
        document_.section(T("只读调试寄存器"));
        document_.field(QStringLiteral("DR0"), Hex(result.snapshot.dr0));
        document_.field(QStringLiteral("DR1"), Hex(result.snapshot.dr1));
        document_.field(QStringLiteral("DR2"), Hex(result.snapshot.dr2));
        document_.field(QStringLiteral("DR3"), Hex(result.snapshot.dr3));
        document_.field(QStringLiteral("DR6"), Hex(result.snapshot.dr6));
        document_.field(QStringLiteral("DR7"), Hex(result.snapshot.dr7));
        if (ownsPause_ && onStoppedAddress)
        {
            onStoppedAddress(result.snapshot.rip);
        }
    }

    void MemoryDebugExecutionPanel::applyCooperative(const ksword::cooperative::Result& result)
    {
        using ksword::cooperative::State;
        if (!result.ok())
        {
            // 工作线程已经关闭失败连接，UI 不执行等待管道响应的操作。
            connected_ = false;
            stopped_ = false;
            fastPollBudget_ = 0;
            status_->setText(T("协作控制失败：%1；Win32=%2。目标需主动启用组件。")
                .arg(QString::fromStdString(result.detail)).arg(result.errorWin32));
            return;
        }
        connected_ = result.state != State::Unavailable && result.state != State::Exited;
        stopped_ = result.state == State::Paused;
        status_->setText(stopped_ ? T("协作线程已停止；可执行真实单步或继续。其它线程继续运行。")
            : result.state == State::PauseRequested ? T("已请求暂停，等待目标的下一个主动检查点。")
            : result.state == State::Interrupted ? T("协作单步进入组件临界区，已中断并恢复运行；未报告单步完成。可重新请求暂停。")
            : connected_ ? T("协作目标正在运行；尚无当前停止现场。") : T("协作目标已退出或组件不可用。"));
        if (!stopped_)
        {
            return;
        }
        fastPollBudget_ = 0;
        const bool newStop = stopId_ != result.stopId; // 轮询相同停点不能重复抢占地址。
        stopId_ = result.stopId;
        const auto key = RegisterDocumentKey(1, epoch_, 0, stopId_, pid_, creation_,
            result.snapshot.threadId, 0, 0, 0, result.snapshot);
        const auto language = ks::i18n::LanguageManager::instance().currentLanguageId();
        if (!newStop && documentKeyValid_ && documentKey_ == key && documentLanguage_ == language)
        {
            return;
        }
        documentKey_ = key;
        documentLanguage_ = language;
        documentKeyValid_ = true;
        document_ = {};
        document_.title = T("不附加寄存器现场");
        document_.section(T("现场身份"));
        document_.field(QStringLiteral("PID"), QString::number(pid_));
        document_.field(QStringLiteral("TID"), QString::number(result.snapshot.threadId));
        document_.field(T("进程创建时间（100ns）"), QString::number(creation_));
        document_.field(T("停止代次"), QString::number(stopId_));
        document_.note(T("捕获时目标主动启用的 VEH 线程已停止；此窗口保存该次快照，只支持整数寄存器查看。"));
        AddRegisters(document_, result.snapshot);
        if (newStop && onStoppedAddress)
        {
            onStoppedAddress(result.snapshot.rip);
        }
    }

    // 驱动快照来自当前 sessionId/stopId，不读取既有 HVM 历史 ring 来冒充停止。
    void MemoryDebugExecutionPanel::applyHvm(const ksword::ark::HvmNoAttachResult& result)
    {
        if (!result.io.ok)
        {
            stopped_ = false;
            hvmAvailable_ = false;
            status_->setText((hvmSessionId_ != 0 || hvmOwnershipUncertain_
                ? T("执行通道通信失败；Win32=%1。自有会话身份保留，仍可重试关闭。")
                : T("执行后端不可用或无访问权限；Win32=%1。未启动执行控制。"))
                    .arg(result.io.win32Error));
            return;
        }
        const auto& response = result.response; // 版本、长度及传输身份由 ArkDriverClient 验证。
        if (response.status >= 0 || response.sessionId == hvmSessionId_)
            hvmResponse_ = response;
        hvmAvailable_ = response.status >= 0
            && (response.capabilities & KSWORD_ARK_HVM_NOATTACH_CAP_EXECUTION) != 0;
        const bool vmxTf = mode_ == 2 && (response.capabilities & KSWORD_ARK_HVM_NOATTACH_CAP_VMX_TF) != 0;
        if (response.sessionId != 0)
        {
            hvmSessionId_ = response.sessionId;
            hvmOwnershipUncertain_ = false;
        }
        else if (response.status >= 0
            && (response.state == KSWORD_ARK_HVM_NOATTACH_CLOSED
                || response.state == KSWORD_ARK_HVM_NOATTACH_UNSUPPORTED))
        {
            hvmOwnershipUncertain_ = false;
        }
        // 拒绝回执可能只有默认 Closed；不能据此丢弃尚待恢复的所有权。
        if (response.status >= 0 || response.sessionId != 0)
        {
            hvmState_ = response.state;
        }
        stopped_ = response.status >= 0 && response.state == KSWORD_ARK_HVM_NOATTACH_STOPPED;
        if (response.status < 0)
        {
            status_->setText(T("执行操作未完成；NTSTATUS=%1，状态=%2。不可用或冲突时不会回退为 Windows 附加。")
                .arg(Hex(static_cast<unsigned long>(response.status))).arg(response.state));
            return;
        }
        if (response.state == KSWORD_ARK_HVM_NOATTACH_CLOSED)
        {
            hvmSessionId_ = 0;
            status_->setText(hvmAvailable_ ? T("所选执行后端能力可用；选择线程并显式启动。尚未取得目标控制权。")
                : T("当前平台、内核或驱动不支持所选独立执行后端；未取得目标控制权。"));
        }
        else if (response.state == KSWORD_ARK_HVM_NOATTACH_INTERRUPTED)
        {
            status_->setText(T("单步遇到中断或状态变化，未报告完成；可重新请求暂停或关闭。"));
        }
        else if (response.state == KSWORD_ARK_HVM_NOATTACH_EXITED)
        {
            status_->setText(T("目标已退出，运行控制已撤销；请关闭以确认资源释放。"));
        }
        else if (response.state == KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED)
        {
            status_->setText(T("执行后端需要恢复，已禁用执行动作；请关闭会话以重试本会话资源释放。"));
        }
        else if (response.state == KSWORD_ARK_HVM_NOATTACH_RUNNING)
        {
            status_->setText(T("独立执行会话已开启，选定线程正在运行；可请求暂停。"));
        }
        else if (response.state == KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING)
        {
            status_->setText(T("执行后端正在等待目标提交恢复状态；真实回执后才确认继续。"));
        }
        else if (response.state == KSWORD_ARK_HVM_NOATTACH_UNSUPPORTED)
        {
            status_->setText(T("当前平台、内核或驱动不支持所选独立执行后端；未取得目标控制权。"));
        }
        else
        {
            status_->setText(stopped_ ? T("选定线程已停止；其它线程继续运行。可单步或继续。")
                : T("执行请求等待目标线程的真实边界；尚无新的停止现场。"));
        }
        if (vmxTf) status_->setText(status_->text() + T(" · VMX TF：TF 可观察，仅支持只读代码中的已验证指令类别。"));
        if (!stopped_)
        {
            return;
        }
        fastPollBudget_ = 0;
        const bool newStop = stopId_ != response.stopId; // 同一停点的状态轮询保持用户地址。
        stopId_ = response.stopId;
        const auto key = RegisterDocumentKey(static_cast<std::uint64_t>(mode_), epoch_, response.sessionId, stopId_, response.processId,
            response.processCreationTime, response.threadId, response.threadCreationTime,
            response.stopReason, response.cr3, response);
        const auto language = ks::i18n::LanguageManager::instance().currentLanguageId();
        if (!newStop && documentKeyValid_ && documentKey_ == key && documentLanguage_ == language)
        {
            return;
        }
        documentKey_ = key;
        documentLanguage_ = language;
        documentKeyValid_ = true;
        document_ = {};
        document_.title = T("不附加寄存器现场");
        document_.section(T("现场身份"));
        document_.field(QStringLiteral("PID"), QString::number(response.processId));
        document_.field(QStringLiteral("TID"), QString::number(response.threadId));
        document_.field(T("进程创建时间（100ns）"), QString::number(response.processCreationTime));
        document_.field(T("线程创建时间（100ns）"), QString::number(response.threadCreationTime));
        document_.field(T("停止代次"), QString::number(response.stopId));
        document_.field(T("停止来源"), response.stopReason == KSWORD_ARK_HVM_NOATTACH_STOP_STEP
            ? (mode_ == 3 ? T("TF 单步异常") : vmxTf ? T("VMX TF/#DB 边界") : T("MTF 单步边界")) : response.stopReason == KSWORD_ARK_HVM_NOATTACH_STOP_BREAKPOINT
                ? (mode_ == 3 ? T("DR 执行断点") : T("EPT 执行断点")) : response.stopReason == KSWORD_ARK_HVM_NOATTACH_STOP_CONTEXT
                    ? T("整数寄存器已提交") : T("用户态取指暂停"));
        document_.field(T("断点 ID"), QString::number(response.breakpointId));
        if (mode_ == 2) document_.field(QStringLiteral("CR3"), Hex(response.cr3));
        document_.note(mode_ == 3 ? T("普通驱动当前持有的单线程异常现场；使用 TF/DR，不附加、不注入，不包含 XSTATE。")
            : vmxTf ? T("VMX 拦截自有 TF/#DB 的单线程停止快照；TF 可观察，不修改目标代码或 DR，不包含 XSTATE。")
            : T("实验 HVM 捕获的单线程停止快照；未修改目标代码、TF 或 DR，不包含 XSTATE。"));
        AddRegisters(document_, response);
        if (newStop && onStoppedAddress)
        {
            onStoppedAddress(response.rip);
        }
    }

    bool MemoryDebugExecutionPanel::closeHvm()
    {
        if (hvmSessionId_ == 0 && !hvmOwnershipUncertain_)
        {
            return true;
        }
        // 全核退出和资源回收在 worker；局部事件循环保持绘制和关闭守卫的响应。
        struct Completion
        {
            QPointer<QEventLoop> loop; // 栈上事件循环销毁时自动失效，迟到回投不能借用栈。
            bool restored = false; // 只有驱动确认关闭才允许放弃会话身份。
        };
        QEventLoop loop;
        const auto completion = std::make_shared<Completion>();
        completion->loop = &loop;
        const QPointer<MemoryDebugExecutionPanel> self(this);
        connect(this, &QObject::destroyed, &loop, &QEventLoop::quit);
        busy_ = true;
        updateActions();
        status_->setText(T("正在释放本会话的执行控制，请等待驱动确认。"));
        KSWORD_ARK_HVM_NOATTACH_REQUEST request{};
        request.operation = KSWORD_ARK_HVM_NOATTACH_CLOSE;
        request.sessionId = hvmSessionId_;
        request.ownerCreationTime = ownerCreation_;
        const auto handle = hvmHandle_; // 即使父页异常销毁，后台仍持有自己的设备句柄。
        const auto dispatcher = dispatcher_;
        const bool kernel = mode_ == 3;
        QThreadPool::globalInstance()->start([this, handle, dispatcher, request, completion, kernel]()
        {
            const auto result = CloseOwnedHvm(request, handle.get(), kernel);
            dispatcher->post([this, completion, result]()
            {
                busy_ = false;
                applyHvm(result);
                completion->restored = result.io.ok && result.response.status >= 0
                    && result.response.sessionId == 0
                    && (result.response.state == KSWORD_ARK_HVM_NOATTACH_CLOSED
                        || result.response.state == KSWORD_ARK_HVM_NOATTACH_UNSUPPORTED);
                updateActions();
                if (completion->loop)
                {
                    completion->loop->quit();
                }
            });
        });
        loop.exec();
        return self && completion->restored;
    }

    void MemoryDebugExecutionPanel::updateActions()
    {
        const bool ready = pid_ != 0 && creation_ != 0 && !busy_;
        const bool hvmActive = mode_ >= 2 && (hvmSessionId_ != 0 || hvmOwnershipUncertain_);
        const bool hvmControllable = mode_ >= 2 && hvmSessionId_ != 0
            && hvmState_ != KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED
            && hvmState_ != KSWORD_ARK_HVM_NOATTACH_EXITED;
        if (mode_ >= 2 && !hvmControllable)
        {
            fastPollBudget_ = 0;
        }
        const int pollingInterval = fastPollBudget_ > 0 ? 50 : 1000; // 仅短时追赶刚发出的真实执行请求。
        if (poll_ != nullptr && poll_->interval() != pollingInterval)
        {
            poll_->setInterval(pollingInterval);
        }
        backend_->setEnabled(!busy_);
        thread_->setVisible(mode_ != 1);
        thread_->setEnabled(ready && !ownsPause_ && !hvmActive);
        refresh_->setEnabled(ready && !ownsPause_ && !connected_ && !hvmActive);
        openHvm_->setVisible(mode_ >= 2);
        openHvm_->setEnabled(ready && hvmAvailable_ && !hvmActive && !threads_.empty());
        capture_->setVisible(mode_ == 0);
        capture_->setEnabled(ready && !threads_.empty());
        pause_->setEnabled(ready && (mode_ == 0 ? !threads_.empty() && !ownsPause_
            : mode_ == 1 ? connected_ && !stopped_ : hvmControllable && !stopped_
                && (hvmState_ == KSWORD_ARK_HVM_NOATTACH_RUNNING
                    || hvmState_ == KSWORD_ARK_HVM_NOATTACH_INTERRUPTED)));
        resume_->setEnabled(ready && (mode_ == 0 ? ownsPause_
            : mode_ == 1 ? connected_ && stopped_ : hvmControllable && stopped_));
        step_->setEnabled(ready && mode_ != 0 && stopped_ && (connected_ || hvmControllable));
        registers_->setEnabled(!document_.isEmpty());
        configureHvm_->setVisible(mode_ >= 2);
        configureHvm_->setEnabled(ready); // 启动前可查看能力与保留草稿，执行仍由真实停点门禁决定。
        closeHvm_->setVisible(mode_ >= 2);
        closeHvm_->setEnabled(!busy_ && hvmActive);
        updateHvmControls();
    }

    void MemoryDebugExecutionPanel::showRegisters()
    {
        if (document_.isEmpty())
        {
            return;
        }
        auto* dialog = new QDialog(this); // 不阻塞工作台；关闭仅销毁当前不可变现场投影。
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setWindowTitle(T("不附加寄存器现场"));
        auto* root = new QVBoxLayout(dialog);
        auto* source = new StructuredFieldView(dialog); // 搜索/复制/导出共用此规范文档。
        source->setDocumentOnly();
        source->setDocument(document_);
        root->addWidget(CreateDetailFieldProjection(source, dialog), 1);
        ApplyDetailDialogChrome(dialog); // 显式不透明详情主题与共享布局。
        applyResponsiveWindowGeometry(dialog, this, QSize(760, 640), QSize(420, 320));
        PrepareDetailWindowForShow(dialog);
        dialog->show();
    }
}
