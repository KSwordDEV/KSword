#include "../Framework.h"
#include "MemoryDebugPage.h"
#include "MemoryDock.WorkbenchServices.h"
#include "../UI/AsyncUiDispatcher.h"
#include "../UI/ToolbarMetrics.h"
#include "../Internationalization/LanguageManager.h"

#include <QComboBox>
#include <QCompleter>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QThreadPool>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <algorithm>

namespace ks::ui
{
    namespace
    {
        // Text：动态状态在拼接前翻译，避免运行期整树扫描无法命中组合后的文字。
        QString Text(const char* source)
        {
            return ks::i18n::sourceText(QString::fromUtf8(source));
        }

        // IconButton：创建带悬停解释的工具按钮；图标交给应用已有的主题图标管理器。
        QToolButton* IconButton(QWidget* owner, const QString& icon, const QString& tooltip)
        {
            auto* button = new QToolButton(owner); // 按钮的 QObject 生命周期由页面管理。
            button->setIcon(QIcon(icon));
            button->setToolTip(ks::i18n::sourceText(tooltip));
            button->setAutoRaise(true);
            return button;
        }
    }

    MemoryDebugPage::MemoryDebugPage(QWidget* parent)
        : QWidget(parent), dispatcher_(std::make_shared<AsyncUiDispatcher>(this))
    {
        setObjectName(QStringLiteral("memory_debug_page"));
        layout_ = new QVBoxLayout(this);
        layout_->setContentsMargins(6, 6, 6, 6);
        layout_->setSpacing(6);

        // 模式说明始终可见；此页只提供内存操作，不把运行目标伪装成调试停止状态。
        auto* explanation = new QLabel(this); // 随布局换行的固定能力说明。
        explanation->setWordWrap(true);
        explanation->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        ks::i18n::LanguageManager::instance().bindText(explanation,
            QStringLiteral("memory.debug.mode"),
            QStringLiteral("不附加模式：目标持续运行，可读写内存和反汇编；不提供暂停、单步或断点。"));
        layout_->addWidget(explanation);

        // 候选选择独立于旧 Dock，输入内容只能匹配当前快照，不能凭 PID 猜测目标身份。
        auto* targetRow = new QHBoxLayout(); // 简短目标工具行，可筛选名称或 PID。
        processCombo_ = new QComboBox(this);
        processCombo_->setObjectName(QStringLiteral("memory_debug_process"));
        processCombo_->setEditable(true);
        processCombo_->setInsertPolicy(QComboBox::NoInsert);
        processCombo_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
        processCombo_->setMinimumWidth(80);
        processCombo_->completer()->setFilterMode(Qt::MatchContains);
        processCombo_->completer()->setCaseSensitivity(Qt::CaseInsensitive);
        processCombo_->completer()->setCompletionMode(QCompleter::PopupCompletion);
        processCombo_->lineEdit()->setPlaceholderText(Text("搜索进程名或 PID"));
        targetRow->addWidget(processCombo_, 1);
        refreshButton_ = IconButton(this, QStringLiteral(":/Icon/process_refresh.svg"),
            QStringLiteral("刷新进程候选"));
        selectButton_ = IconButton(this, QStringLiteral(":/Icon/process_details.svg"),
            QStringLiteral("打开不附加内存会话"));
        closeButton_ = IconButton(this, QStringLiteral(":/Icon/log_clear.svg"),
            QStringLiteral("关闭内存会话"));
        closeButton_->setEnabled(false);
        targetRow->addWidget(refreshButton_);
        targetRow->addWidget(selectButton_);
        targetRow->addWidget(closeButton_);
        ks::ui::NormalizeToolbarRow(targetRow);
        layout_->addLayout(targetRow);

        // 模块下拉框使用目标层的异步身份快照；模块刷新不主动重定位用户当前地址。
        moduleCombo_ = new QComboBox(this);
        moduleCombo_->setObjectName(QStringLiteral("memory_debug_module"));
        moduleCombo_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
        moduleCombo_->setEnabled(false);
        moduleCombo_->setToolTip(Text("选择模块并查看基址处的反汇编"));
        layout_->addWidget(moduleCombo_);
        status_ = new QLabel(Text("请选择进程以打开内存会话。"), this);
        status_->setWordWrap(true);
        status_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        layout_->addWidget(status_);

        connect(refreshButton_, &QToolButton::clicked, this, &MemoryDebugPage::refreshProcesses);
        connect(selectButton_, &QToolButton::clicked, this, &MemoryDebugPage::selectProcess);
        connect(closeButton_, &QToolButton::clicked, this, &MemoryDebugPage::closeSession);
        connect(processCombo_->lineEdit(), &QLineEdit::returnPressed, this, &MemoryDebugPage::selectProcess);
        connect(moduleCombo_, &QComboBox::activated, this, &MemoryDebugPage::openModule);
    }

    MemoryDebugPage::~MemoryDebugPage()
    {
        // 第一时间关闭回投门禁，工作线程即使稍后完成也不能借用已开始析构的页面。
        dispatcher_->close();
    }

    void MemoryDebugPage::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        if (view_ == nullptr)
        {
            ensureView();
            refreshProcesses();
        }
    }

    void MemoryDebugPage::ensureView()
    {
        if (view_ != nullptr)
        {
            return;
        }
        // 配置与标准工作台相同的生产端口，但视图、目标、历史及补丁会话全部独立。
        workbench_dock::ConfigureShared();
        view_ = new MemoryWorkbenchView(this);
        // 显示或加载旧范围设置前先锁定独立模式，避免初始 show/sessionChanged 接管共享 int3。
        if (!view_->setMemoryDebugMode(true))
        {
            delete view_;
            view_ = nullptr;
            status_->setText(Text("内存会话初始化失败。"));
            return;
        }
        view_->setDisasmBackends(workbench_dock::MakeDecodeBackend(), workbench_dock::MakeAssembleBackend());
        view_->setGlobalSkipDangerousConfirmProvider(workbench_dock::GlobalSkipDangerousConfirm);
        view_->setSettingsAuthoritative(false);
        view_->loadSettings();
        // 显示/写入偏好可复用，首个访问通道固定为无需驱动的 R3。
        (void)view_->target().requestChannel(ksword::memwb::Channel::UserMode);

        // 名称取成功选择时的快照；写能力对同一创建时间做访问检查，不借用旧 Dock 状态。
        view_->setAttachedProcessInfoProvider([this](const std::uint32_t pid)
            -> std::optional<AttachedProcessDisplayInfo>
        {
            const auto session = view_->target().session(); // 当前视图已锚定的身份值快照。
            if (pid == 0 || pid != session.pid)
            {
                return std::nullopt;
            }
            QString name; // 同步 sessionChanged 时新身份可能尚未写入页面选择缓存。
            if (selectedProcess_.pid == pid
                && selectedProcess_.createTime100ns == session.processCreateTime100ns)
            {
                name = processName_;
            }
            else
            {
                for (const auto& candidate : catalog_.processes)
                {
                    if (candidate.pid == pid
                        && candidate.createTime100ns == session.processCreateTime100ns)
                    {
                        name = QString::fromStdWString(candidate.name);
                        break;
                    }
                }
            }
            return AttachedProcessDisplayInfo{
                name, CanWriteMemoryDebugProcess(pid, session.processCreateTime100ns)};
        });
        view_->setProtectionProvider([this](const std::uint64_t address)
        {
            return workbench_dock::QueryProtection(view_->target().session().pid, address);
        });
        view_->setGateInputsProvider([this]()
        {
            auto inputs = workbench_dock::QueryGateInputs(); // R0/HVM/DDMA 仍按真实可用性判断。
            inputs.hasProcessTarget = view_->target().session().pid != 0;
            return inputs;
        });
        connect(view_, &MemoryWorkbenchView::pickTargetRequested, this, [this]()
        {
            processCombo_->setFocus();
            processCombo_->showPopup();
        });
        connect(&view_->target(), &WorkbenchTarget::modulesChanged, this, [this](const bool kernel)
        {
            if (!kernel)
            {
                refreshModules();
            }
        });
        connect(&view_->target(), &WorkbenchTarget::modulesFailed, this, [this](const bool kernel)
        {
            if (!kernel)
            {
                initialModulePending_ = false;
                refreshModules();
                status_->setText(Text("模块枚举失败，可在地址栏输入已知地址。"));
            }
        });

        // 每秒只探测已持有的身份锚点；进程退出后由新模式门禁拒绝读写和过期结果。
        livenessTimer_ = new QTimer(this);
        livenessTimer_->setInterval(1000);
        connect(livenessTimer_, &QTimer::timeout, this, [this]()
        {
            if (view_->target().identityAnchored())
            {
                view_->target().checkLiveness();
            }
        });
        connect(&view_->target(), &WorkbenchTarget::livenessChanged, this, [this](const int state)
        {
            if (state == static_cast<int>(LivenessState::Exited))
            {
                moduleCombo_->setEnabled(false);
                initialModulePending_ = false;
                status_->setText(Text("目标已退出；缓存仅供查看，请重新选择进程。"));
            }
        });
        livenessTimer_->start();
        layout_->addWidget(view_, 1);
    }

    void MemoryDebugPage::refreshProcesses()
    {
        if (refreshing_)
        {
            return;
        }
        refreshing_ = true;
        refreshButton_->setEnabled(false);
        selectButton_->setEnabled(false);
        // 在线程池只查询系统，不访问控件；落回 UI 线程时门禁保证页面还在。
        const auto dispatcher = dispatcher_; // 后台任务可以安全持有的共享回投门禁。
        QThreadPool::globalInstance()->start([this, dispatcher]()
        {
            auto result = EnumerateMemoryDebugProcesses(); // 无句柄的值快照。
            std::sort(result.processes.begin(), result.processes.end(), [](const auto& left, const auto& right)
            {
                const int order = QString::compare(QString::fromStdWString(left.name),
                    QString::fromStdWString(right.name), Qt::CaseInsensitive);
                return order == 0 ? left.pid < right.pid : order < 0;
            });
            dispatcher->post([this, result = std::move(result)]() mutable
            {
                refreshing_ = false;
                refreshButton_->setEnabled(true);
                selectButton_->setEnabled(true);
                if (result.error != 0)
                {
                    status_->setText(Text("进程候选刷新失败，错误：%1").arg(result.error));
                    return;
                }
                const QSignalBlocker blocker(processCombo_); // 重建列表不得自动选中目标。
                processCombo_->clear();
                catalog_ = std::move(result);
                for (const auto& candidate : catalog_.processes)
                {
                    processCombo_->addItem(QStringLiteral("%1 · %2")
                        .arg(QString::fromStdWString(candidate.name)).arg(candidate.pid));
                }
                processCombo_->setCurrentIndex(-1);
                if (view_ == nullptr || view_->target().session().pid == 0)
                {
                    status_->setText(Text("请选择进程以打开内存会话。"));
                }
            });
        });
    }

    void MemoryDebugPage::selectProcess()
    {
        if (refreshing_)
        {
            return;
        }
        ensureView();
        if (view_ == nullptr)
        {
            return;
        }
        const QString text = processCombo_->currentText().trimmed(); // 编辑文字只用来检索快照。
        int index = processCombo_->findText(text, Qt::MatchExactly);
        if (index < 0)
        {
            bool validPid = false;
            const auto pid = text.toUInt(&validPid, 10); // 允许输入当前候选列表中的十进制 PID。
            if (validPid)
            {
                for (std::size_t row = 0; row < catalog_.processes.size(); ++row)
                {
                    if (catalog_.processes[row].pid == pid)
                    {
                        index = static_cast<int>(row);
                        break;
                    }
                }
            }
        }
        if (index < 0 || static_cast<std::size_t>(index) >= catalog_.processes.size())
        {
            status_->setText(Text("请从候选列表选择进程，或输入列表中的 PID。"));
            return;
        }
        const auto candidate = catalog_.processes[static_cast<std::size_t>(index)]; // 复制身份，守卫可能重入。
        if (candidate.createTime100ns == 0)
        {
            status_->setText(Text("无法核验该进程身份，请刷新列表或检查访问权限。"));
            return;
        }
        const QPointer<MemoryDebugPage> self(this); // 暂存离开守卫可能触发宿主销毁。
        if (!view_->target().requestPin(candidate.pid, candidate.createTime100ns))
        {
            if (self)
            {
                status_->setText(Text("未切换目标：进程已变化、不可访问或操作已取消。"));
            }
            return;
        }
        if (!self)
        {
            return;
        }
        processName_ = QString::fromStdWString(candidate.name);
        selectedProcess_ = candidate;
        initialModulePending_ = true;
        closeButton_->setEnabled(true);
        status_->setText(Text("内存会话：%1 · PID %2 · 目标持续运行")
            .arg(processName_).arg(candidate.pid));
        refreshModules();
    }

    void MemoryDebugPage::refreshModules()
    {
        if (view_->target().livenessState() == LivenessState::Exited)
        {
            // 迟到的模块完成通知不能重启导航，也不能把退出后的选择器重新启用。
            moduleCombo_->setEnabled(false);
            initialModulePending_ = false;
            return;
        }
        const auto modules = view_->target().pointerChainModules(); // 已通过目录所有者身份核对。
        const QSignalBlocker blocker(moduleCombo_); // 列表回填不产生导航请求。
        moduleCombo_->clear();
        for (const auto& module : modules)
        {
            moduleCombo_->addItem(QStringLiteral("%1 · 0x%2")
                .arg(QString::fromStdString(module.name)).arg(module.base, 0, 16),
                QVariant::fromValue<qulonglong>(module.base));
        }
        moduleCombo_->setEnabled(!modules.empty());
        if (initialModulePending_ && !modules.empty())
        {
            initialModulePending_ = false;
            const auto primary = view_->target().primaryModule(processName_); // 优先主映像而非系统 DLL。
            const auto address = primary.state == WorkbenchTarget::PrimaryModuleState::Ready
                ? primary.record.base : modules.front().base;
            (void)view_->showDisassemblyAt(address);
        }
    }

    void MemoryDebugPage::openModule()
    {
        if (view_ != nullptr && moduleCombo_->currentIndex() >= 0 && moduleCombo_->isEnabled())
        {
            (void)view_->showDisassemblyAt(moduleCombo_->currentData().toULongLong());
        }
    }

    void MemoryDebugPage::closeSession()
    {
        const QPointer<MemoryDebugPage> self(this); // 离开守卫可嵌套事件循环并关闭宿主。
        if (view_ == nullptr || !view_->clearMemoryDebugTarget() || !self)
        {
            return;
        }
        initialModulePending_ = false;
        processName_.clear();
        selectedProcess_ = {};
        moduleCombo_->clear();
        moduleCombo_->setEnabled(false);
        closeButton_->setEnabled(false);
        status_->setText(Text("内存会话已关闭，目标继续运行。"));
    }

    bool MemoryDebugPage::confirmQuit()
    {
        return view_ == nullptr || view_->confirmQuit();
    }

    void MemoryDebugPage::cancelQuitPreparation()
    {
        if (view_ != nullptr)
        {
            view_->cancelQuitPreparation();
        }
    }
}
