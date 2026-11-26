#include "../Framework.h"
#include "DataWriteWatchPage.h"
#include "NativeStopMemoryArchive.h"
#include "ProcessGroupMemoryPane.h"
#include "PrivateAddressWatchFields.h"
#include "PrivateExecutionRangePane.h"
#include "PrivateExecutionCandidatesPane.h"
#include "NativeSessionApiPane.h"

#include "../../../KswordCLI/ActionAnalyze/Control/OwnedDataWatchSession.h"
#include "../Framework/BackgroundTaskRegistry.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/AsyncCleanupRegistry.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/FlowLayout.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ThemedMessageBox.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QComboBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QPointer>
#include <QSignalBlocker>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <utility>

namespace ks::action_analyze
{
namespace
{
    namespace native = ks::cli::action_analyze::control;
    namespace rules = Ksword::ActionAnalyze::Rules;
    using ks::i18n::sourceText;
    using ks::ui::StatusRole;

    enum class Action { Start, Query, Continue, Step, CancelStep, Close, ReadMemory, SaveMemory, DumpMemory, SaveExecution, FollowExecution, AddRange, CaptureApi, Pause, ReadCandidates };

    // 将当前控制状态和同轮判断核对后，决定是否展示真实可继续的写入停点。
    bool IsHeldWrite(const native::NativeControlResult& control, const native::DataWatchConditionReport& condition,
        bool hasCondition)
    {
        if (!native::DataWatchHeldStop(control))
        {
            return false;
        }
        const auto& decision = condition.last; // 旧判断不能授予新事件继续资格。
        return native::IsDataWatchStepStop(control) || control.stopReason == native::NativeStopReason::ManualPause ||
            !hasCondition || (control.responsibility && decision &&
            decision->event == control.responsibility->event && decision->evaluation.truth == rules::Truth::True);
    }

    // 将控制状态与同一回合的条件回执一起交回 UI。
    struct WatchResult
    {
        native::NativeControlResult control; // 停点、清退和过程身份。
        native::DataWatchConditionReport condition; // 最近一次求值与本轮计数。
        ProcessGroupSessionSnapshot memory; // 原session同回合的内存及独立归档投影。
        NativeExecutionArchiveView execution; // raw-native独立流回执与去重结果。
        std::shared_ptr<const Ksword::ActionAnalyze::NativeBoundApiResult> api; // 原writer同采样API采集回执。
        std::shared_ptr<const NativeExecutionCandidatesResult> candidates; // 同document只读候选及原请求身份。
    };

    // 页面与收尾任务短时共享同一个会话，原生调试事件始终归该会话所有。
    struct SessionOwner : std::enable_shared_from_this<SessionOwner>
    {
        std::mutex access; // 关闭页面时仍可能有一个在途工作，必须先等其返回。
        native::OwnedDataWatchSession session; // 只由工作线程调用四个控制入口。
        NativeStopMemoryArchive memory; // 原worker独占项目写租约，Start前登记sample。
        bool retired = false; // 清退先到时，尚未执行的启动请求不得再创建进程。
        std::atomic_bool cleanupStarted = false; // 页面销毁和程序退出只启动同一轮清退。
        std::shared_ptr<ks::ui::AsyncCleanupRegistry::Lease> lease; // 正常退出等待原owner真正clean。

        // 新会话先登记退出责任，弱引用回调不形成lease到owner的引用环。
        static std::shared_ptr<SessionOwner> Create()
        {
            auto owner = std::make_shared<SessionOwner>(); // 原session只由本端异步控制访问。
            const std::weak_ptr<SessionOwner> weak = owner;
            owner->lease = ks::ui::AsyncCleanupRegistry::global().acquire([weak] {
                if (const auto held = weak.lock())
                {
                    held->Cleanup();
                }
            });
            return owner->lease ? owner : nullptr;
        }

        // 请求后台结算；未clean持续保留同一个session和项目，不能一次Close后丢弃责任。
        void Cleanup()
        {
            if (cleanupStarted.exchange(true))
            {
                return;
            }
            QThreadPool::globalInstance()->start([owner = shared_from_this()] {
                std::unique_lock lock(owner->access); // 等待原唯一在途读取/保存/控制回合。
                owner->retired = true;
                std::condition_variable retry; // 有界等待避免清退未决时忙循环。
                for (;;)
                {
                    try
                    {
                        const auto result = owner->session.Close(); // 不创建第二owner或继续票据。
                        if (result.clean && !result.attached)
                        {
                            owner->memory.CloseProject(); // 正常退出租约晚于项目租约释放。
                            owner->lease.reset();
                            return;
                        }
                    }
                    catch (...)
                    {
                        // 原责任仍未知，保活并重试Close；不把异常冒充已清退。
                    }
                    retry.wait_for(lock, std::chrono::milliseconds(250));
                }
            });
        }
    };

    class DataWriteWatchPage final : public QWidget
    {
    public:
        // 父页提供内容边界，参数正文、固定动作和字段结果复用共享组件。
        explicit DataWriteWatchPage(QWidget* parent, std::shared_ptr<DataWatchToolbarPort> toolbar);
        // 阻断回投并将可能仍活跃的调试会话交给后台关闭。
        ~DataWriteWatchPage() override;

    private:
        // 动作提交时冻结参数和停点令牌，完成回调只接收值回执。
        void submit(Action action, std::optional<native::NativeControlResult> selectedStop = {},
            std::optional<native::NativeStepMode> selectedMode = {}, std::optional<ProcessGroupRequest> memory = {},
            std::optional<std::pair<std::uint64_t, std::uint64_t>> range = {},
            std::optional<Ksword::ActionAnalyze::NativeBoundApiRequest> api = {},
            std::optional<NativeExecutionCandidatesRequest> candidates = {});
        // 以真实清退状态控制重试与下一次启动，并更新唯一的字段投影。
        void apply(const WatchResult& receipt, Action action);
        void refresh(); // 按当前语言、草稿与回执更新文本和操作资格。
        void changeEvent(QEvent* event) override; // 语言变更时重译，保留输入和停点身份。

        QGroupBox* m_target = nullptr; // 本端目标及关注范围参数。
        QLabel* m_imageLabel = nullptr; // 标签与路径字段配对。
        QLabel* m_exportLabel = nullptr; // 标签与导出名字段配对。
        QLabel* m_widthLabel = nullptr; // 标签与宽度字段配对。
        QLabel* m_conditionLabel = nullptr; // 标签与条件草稿配对。
        QLineEdit* m_image = nullptr; // 候选自有 EXE 的草稿路径。
        QLineEdit* m_export = nullptr; // 目标声明的可写数据导出名。
        QComboBox* m_width = nullptr; // 硬件关注宽度，单位为字节。
        QComboBox* m_siteKind = nullptr; // 直接映像数据或指针导出的私有区间。
        QLabel* m_siteKindLabel = nullptr; // 绑定方式参数标签。
        PrivateAddressWatchFields* m_privateFields = nullptr; // 已有进程实例与单地址草稿。
        PrivateAddressWatchTarget m_runPrivate; // 本次已提交目标，独立于参数编辑。
        QLineEdit* m_condition = nullptr; // 条件草稿；运行中也可以准备下次输入。
        QLabel* m_conditionError = nullptr; // 独立于当前会话与历史回执的草稿校验结果。
        QPushButton* m_browse = nullptr; // 选择本地程序。
        QPushButton* m_start = nullptr; // 显式启动本轮合作程序。
        QPushButton* m_continue = nullptr; // 仅继续回执代表的当前停点。
        QPushButton* m_pause = nullptr; // 在已有调试附加内主动下断，由原owner发布真实停止。
        QComboBox* m_stepMode = nullptr; // 明确选择机器指令步入、越过调用或跳出可信帧。
        QLabel* m_stepLabel = nullptr; // 参数区的模式标签，保持动作栏紧凑。
        QPushButton* m_step = nullptr; // 对点击时的确切事件线程执行所选步进。
        QPushButton* m_cancelStep = nullptr; // 请求中止当前步进，等待原生停点回执。
        QPushButton* m_followExecution = nullptr; // 同址私有写转执行，仅变更DR0类型，不自动继续。
        QPushButton* m_close = nullptr; // 请求同一所有者复原并脱离。
        QLabel* m_status = nullptr; // 可读的实际会话状态。
        ks::ui::StructuredFieldView* m_fields = nullptr; // 提供复制、导出的规范字段源。
        ProcessGroupMemoryPane* m_memoryPane = nullptr; // 范围草稿显式读取，复用共享参数分区。
        PrivateExecutionRangePane* m_rangePane = nullptr; // 当前NX停点下显式追加范围的独立草稿。
        PrivateExecutionCandidatesPane* m_candidatesPane = nullptr; // 原API实际范围只读目录，选择仅载入原草稿。
        std::shared_ptr<const NativeExecutionCandidatesResult> m_candidatesShown; // 原worker发布的候选来源，不由参数改写。
        NativeSessionApiPane* m_apiPane = nullptr; // 原采样内的明确API来源实例及有限采集草稿。
        QPushButton* m_captureApi = nullptr; // 固定动作栏发起一次已确认API采集，不新增worker。
        std::shared_ptr<const Ksword::ActionAnalyze::NativeBoundApiResult> m_apiShown; // 原worker完整纯值结果。
        ProcessGroupSessionSnapshot m_memoryShown; // 旧结果不由新地址草稿或后续停点改写。
        NativeExecutionArchiveView m_executionShown; // 执行观测归档结果，独立于raw-memory。
        QPushButton* m_saveExecution = nullptr; // 只对真实可提取执行事件显式保存。
        ks::ui::AsyncOperation* m_work = nullptr; // 一次最多一个控制命令或查询在途。
        QTimer* m_poll = nullptr; // 在活会话内回读状态，空闲时停止。
        std::shared_ptr<SessionOwner> m_owner; // 未确认清退前不会替换实际所有者。
        native::NativeControlResult m_result; // GUI 已收到的最后一个值回执。
        native::DataWatchConditionReport m_conditionReport; // 与 m_result 来自同一工作回合。
        native::DataWatchConditionPreparation m_conditionFailure; // 新草稿的校验失败及字节位置。
        std::optional<native::NativeControlResult> m_lastStop; // 继续或清退后保留最近一次命中的冻结身份。
        std::optional<Action> m_queuedAction; // 查询进行中，最多接收一个显式动作。
        std::optional<native::NativeControlResult> m_queuedStop; // 保存排队时用户看到的停止组及修订。
        std::optional<native::NativeStepMode> m_queuedMode; // 查询在途时冻结点击选择的步进模式。
        QString m_runImage; // 已执行请求对应的路径，独立于下一次草稿。
        QString m_runExport; // 已执行请求对应的导出名。
        QString m_runCondition; // 已执行请求对应的条件原文。
        QString m_definitionDraft; // 从定义页带入的ID，手工改模块或位置后清除。
        QString m_runDefinition; // 本次实际启动的定义ID，独立于后续草稿。
        std::uint32_t m_runWidth = 0; // 已执行请求对应的字节宽度，修改草稿时保持原值。
        bool m_runIndirect = false; // 已执行绑定方式，不由下一轮草稿改写。
        bool m_runExecution = false; // 第三种模式明确选择私有执行，不借零宽度推断模式。
        bool m_runImageAttachment = false; // 已有实例普通模块断点，不启动合作程序。
        std::optional<std::uint32_t> m_runImageRva; // 非空表示本次模块RVA，空时使用精确PE导出。
        bool m_registered = false; // 共享后台登记是否成功。
        bool m_mutating = false; // 仅显式控制命令在途时禁用动作，状态查询仍允许记录点击。
        bool m_closing = false; // 已请求清退，防止在清退中继续旧停点。
        bool m_failed = false; // 异步任务本身失败时保留上次已知原生状态。
        std::shared_ptr<DataWatchToolbarPort> m_toolbar; // 工具条仅观察本页已有状态并转交显式动作。
    };

    // 构建单个图标动作，辅助技术名称和悬停文案由 refresh 按语言写入。
    QPushButton* IconAction(QWidget* parent, const char* name, const char* icon)
    {
        auto* button = new QPushButton(parent); // 普通状态和键盘焦点使用应用标准主题。
        button->setObjectName(QString::fromLatin1(name));
        KswordTheme::ApplyStandardIconButtonMetrics(button);
        ks::ui::SetThemeButtonIcon(button, QIcon(QString::fromLatin1(icon)));
        return button;
    }

    DataWriteWatchPage::DataWriteWatchPage(QWidget* parent, std::shared_ptr<DataWatchToolbarPort> toolbar)
        : QWidget(parent), m_toolbar(std::move(toolbar))
    {
        auto* root = new QVBoxLayout(this); // 外层行为分析页负责整体留白。
        root->setContentsMargins(0, 0, 0, 0);
        auto* workspace = new ks::ui::ParameterWorkspace(this, 420); // 窄窗自动调整布局。
        root->addWidget(workspace);
        m_target = new QGroupBox(workspace);
        auto* form = new QFormLayout(m_target); // 窄栏标签可下折，输入框不挤出视口。
        form->setRowWrapPolicy(QFormLayout::WrapLongRows);
        form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        form->setLabelAlignment(Qt::AlignVCenter | Qt::AlignLeft);

        // 输入只提交草稿。文件选择器和直接输入均经同一后端准入。
        m_image = new QLineEdit(m_target);
        m_image->setObjectName(QStringLiteral("action_analyze_watch_image"));
        m_export = new QLineEdit(m_target);
        m_export->setObjectName(QStringLiteral("action_analyze_watch_export"));
        m_export->setMaxLength(255);
        m_width = new QComboBox(m_target);
        m_width->setObjectName(QStringLiteral("action_analyze_watch_width"));
        for (const unsigned bytes : {1u, 2u, 4u, 8u}) // AMD64 原生支持的四个宽度。
        {
            m_width->addItem(QString::number(bytes), bytes);
        }
        m_width->setCurrentIndex(2);
        m_condition = new QLineEdit(m_target);
        m_condition->setObjectName(QStringLiteral("action_analyze_watch_condition"));
        m_conditionError = new QLabel(m_target);
        m_conditionError->setWordWrap(true);
        m_conditionError->setTextFormat(Qt::PlainText);
        ks::ui::ApplyStatusRole(m_conditionError, StatusRole::Error);
        m_imageLabel = new QLabel(m_target);
        m_exportLabel = new QLabel(m_target);
        m_widthLabel = new QLabel(m_target);
        m_conditionLabel = new QLabel(m_target);
        m_imageLabel->setBuddy(m_image);
        m_exportLabel->setBuddy(m_export);
        m_widthLabel->setBuddy(m_width);
        m_conditionLabel->setBuddy(m_condition);
        form->addRow(m_imageLabel, m_image);
        form->addRow(m_exportLabel, m_export);
        form->addRow(m_widthLabel, m_width);
        m_siteKind = new QComboBox(m_target);
        m_siteKind->setObjectName(QStringLiteral("action_analyze_watch_site_kind"));
        m_siteKind->addItem(QString(), 0);
        m_siteKind->addItem(QString(), 1);
        m_siteKind->addItem(QString(), 2); // 执行模式沿用原参数区和唯一会话。
        m_siteKind->addItem(QString(), 3); // 已有进程私有地址写关注。
        m_siteKind->addItem(QString(), 4); // 已有进程私有地址执行关注。
        m_siteKind->addItem(QString(), 5); // 已有进程的整页NX执行关注，沿用同一个owner。
        m_siteKind->addItem(QString(), 6); // 已有进程普通模块的精确PE导出执行关注。
        m_siteKind->addItem(QString(), 7); // 已有进程普通模块的非零RVA执行关注。
        m_siteKindLabel = new QLabel(m_target);
        m_siteKindLabel->setBuddy(m_siteKind);
        form->insertRow(0, m_siteKindLabel, m_siteKind); // 先选对象来源，再填写对应实例或导出。
        m_privateFields = new PrivateAddressWatchFields(m_target);
        m_privateFields->changed = [this] { refresh(); };
        form->insertRow(1, m_privateFields);
        form->addRow(m_conditionLabel, m_condition);
        form->addRow(m_conditionError);
        // 步进模式属于显式控制参数；改变选项本身不会放行线程。
        m_stepMode = new QComboBox(m_target);
        m_stepMode->setObjectName(QStringLiteral("action_analyze_watch_step_mode"));
        for (const auto mode : {native::NativeStepMode::Into, native::NativeStepMode::OverCall, native::NativeStepMode::Out})
        {
            m_stepMode->addItem(QString(), static_cast<int>(mode));
        }
        m_stepLabel = new QLabel(m_target);
        m_stepLabel->setBuddy(m_stepMode);
        form->addRow(m_stepLabel, m_stepMode);
        ks::ui::StyleParameterSection(m_target);
        workspace->parameters()->addWidget(m_target);
        m_rangePane = new PrivateExecutionRangePane(workspace);
        workspace->parameters()->addWidget(m_rangePane);
        m_rangePane->addRange = [this](std::uint64_t base, std::uint64_t bytes) {
            if (m_owner && !m_work->isBusy() && !m_mutating && !m_closing)
            {
                // 点击时冻结原停止快照及新范围，不排队后再读取输入框。
                submit(Action::AddRange, m_result, {}, {}, std::pair{base, bytes});
            }
        };
        m_memoryPane = new ProcessGroupMemoryPane(workspace, true);
        workspace->parameters()->addWidget(m_memoryPane);
        m_apiPane = new NativeSessionApiPane(workspace);
        workspace->parameters()->addWidget(m_apiPane);
        m_candidatesPane = new PrivateExecutionCandidatesPane(workspace);
        workspace->parameters()->addWidget(m_candidatesPane);
        m_candidatesPane->requestRead = [this](const NativeExecutionCandidatesRequest& request) {
            if (!m_owner || m_work->isBusy() || m_mutating || m_closing || m_failed)
            {
                m_candidatesPane->ReadNotQueued(request.serial);
                return;
            }
            // 请求已由目录冻结，只交给原worker，不重新读取参数或打开另一个项目。
            submit(Action::ReadCandidates, m_result, {}, {}, {}, {}, request);
        };
        m_candidatesPane->draftReady = [this](const auto& draft, const QString& origin) {
            const auto owner = m_owner; // 确认替换期间必须仍是同一个原生owner及其项目采样。
            const auto directory = m_memoryShown.projectDirectory;
            const QPointer<DataWriteWatchPage> alive(this); // 模态确认期间页面可销毁。
            const auto current = [alive, owner, directory, draft] {
                return alive && owner && owner == alive->m_owner && !alive->m_work->isBusy() &&
                    !alive->m_mutating && !alive->m_closing && !alive->m_failed &&
                    directory == alive->m_memoryShown.projectDirectory && draft.sampleId == alive->m_memoryShown.sampleId &&
                    draft.targetPid == alive->m_result.pid && draft.targetCreationFileTime == alive->m_result.processCreationTime &&
                    alive->m_result.breakpoint && alive->m_result.breakpoint->rangeBytes &&
                    native::DataWatchHeldStop(alive->m_result) && alive->m_candidatesShown &&
                    alive->m_candidatesShown->page && draft.projectId == alive->m_candidatesShown->page->scope.projectId;
            };
            if (current())
            {
                // 仅替换明确草稿；追加仍由用户点击原AddRange按钮，冻结当时的真实停止令牌。
                m_rangePane->SetDraft(draft.address, draft.bytes, origin, current);
            }
        };
        m_memoryPane->execute = [this](bool save) {
            if (!m_owner || m_work->isBusy() || m_mutating || m_closing)
            {
                return; // 不排队重读控件，用户可在当前回合结束后显式重试。
            }
            ProcessGroupRequest request; // 保存点击时的原capture或读取时的完整stop和范围。
            if (save)
            {
                request.memoryToSave = m_memoryShown.memory;
            }
            else if (!m_memoryPane->PrepareNative(m_result, request))
            {
                return;
            }
            submit(save ? Action::SaveMemory : Action::ReadMemory, m_result, {}, std::move(request));
        };

        // 动作固定在参数区底部。回执独占结果区的伸缩空间。
        auto* footer = workspace->actions()->parentWidget(); // 共享动作行的实际宿主。
        auto* controls = new QWidget(footer); // 固定动作支持窄窗换行，不让普通按钮挤出参数栏。
        auto* actionFlow = new ks::ui::FlowLayout(controls, 0, 8, 8);
        workspace->actions()->addWidget(controls);
        m_browse = IconAction(footer, "action_analyze_watch_browse", ":/Icon/process_open_folder.svg");
        m_start = IconAction(footer, "action_analyze_watch_start", ":/Icon/process_start.svg");
        m_continue = IconAction(footer, "action_analyze_watch_continue", ":/Icon/process_resume.svg");
        m_pause = IconAction(footer, "action_analyze_watch_pause", ":/Icon/process_suspend.svg");
        m_step = IconAction(footer, "action_analyze_watch_step", ":/Icon/action_analyze_step.svg");
        m_cancelStep = IconAction(footer, "action_analyze_watch_cancel_step", ":/Icon/action_analyze_cancel_step.svg");
        m_followExecution = IconAction(footer, "action_analyze_watch_follow_execution", ":/Icon/desktop_switch.svg");
        m_close = IconAction(footer, "action_analyze_watch_close", ":/Icon/process_stop.svg");
        ks::ui::ApplyFlatButtonTheme(m_start, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
        for (auto* button : {m_browse, m_start, m_followExecution, m_pause, m_continue, m_step, m_cancelStep, m_close})
        {
            actionFlow->addWidget(button);
        }
        m_saveExecution = new QPushButton(footer);
        ks::i18n::LanguageManager::instance().bindText(m_saveExecution, {}, QStringLiteral("保存执行观测"));
        ks::i18n::LanguageManager::instance().bindToolTip(m_saveExecution, {}, QStringLiteral("仅保存真实执行入口或 Into 完成事件到原项目 raw-native；普通写入停点不属于执行观测。"));
        m_saveExecution->setObjectName(QStringLiteral("action_analyze_watch_save_execution"));
        actionFlow->addWidget(m_saveExecution);
        m_captureApi = IconAction(footer, "action_analyze_watch_capture_api", ":/Icon/process_start.svg");
        actionFlow->addWidget(m_captureApi);
        connect(m_captureApi, &QPushButton::clicked, this, [this] {
            if (!m_captureApi->isEnabled())
            {
                return;
            }
            const auto owner = m_owner; // 模态确认前冻结本轮会话，不采纳之后替换的owner。
            const auto sample = m_memoryShown.sampleId; // API只能写本轮已登记采样。
            const auto pid = m_result.pid;
            const auto creation = m_result.processCreationTime;
            Ksword::ActionAnalyze::NativeBoundApiRequest request; // 由小参数分区冻结API来源。
            const QPointer<DataWriteWatchPage> alive(this); // 确认期间页面销毁后不再访问控件。
            if (!m_apiPane->Prepare({pid, creation, m_result.attached}, request) || !m_apiPane->Confirm(request))
            {
                return;
            }
            if (!alive || owner != m_owner || sample != m_memoryShown.sampleId || pid != m_result.pid ||
                creation != m_result.processCreationTime || !m_captureApi->isEnabled() || m_work->isBusy())
            {
                return; // 确认仅适用于原会话和原sample，不能跨越重启或清退。
            }
            submit(Action::CaptureApi, m_result, {}, {}, {}, request);
        });
        m_memoryPane->MoveExecutionActions(actionFlow);
        ks::ui::NormalizeToolbarLayout(actionFlow);
        ks::ui::NormalizeToolbarRow(workspace->actions());
        m_status = new QLabel(workspace);
        m_status->setObjectName(QStringLiteral("action_analyze_watch_status"));
        m_status->setWordWrap(true);
        m_status->setTextFormat(Qt::PlainText);
        workspace->results()->addWidget(m_status);
        m_fields = new ks::ui::StructuredFieldView(workspace);
        m_fields->setObjectName(QStringLiteral("action_analyze_watch_receipt"));
        m_fields->setValueModelProjection();
        m_fields->setHiddenProjectionDeferred();
        workspace->results()->addWidget(m_fields, 1);
        workspace->finish();

        // 工作线程串行控制，不直接从 GUI 读原生进程或线程状态。
        m_work = new ks::ui::AsyncOperation(this);
        m_work->setStateChangedCallback([this] {
            if (!m_work->isBusy() && m_queuedAction)
            {
                const auto action = *std::exchange(m_queuedAction, std::nullopt); // 查询已让出执行槽。
                submit(action, std::exchange(m_queuedStop, std::nullopt), std::exchange(m_queuedMode, std::nullopt));
            }
            else if (!m_work->isBusy())
            {
                refresh(); // 回合完全结束后重新开放显式内存动作，不沿用回投时的busy状态。
            }
        });
        m_poll = new QTimer(this);
        m_poll->setInterval(200);
        ks::ui::BackgroundTaskRegistry::External external; // 管理器只回读 UI 已公布会话资格。
        external.running = [this] { return m_owner != nullptr; };
        m_registered = ks::ui::BackgroundTaskRegistry::instance().addExternal(
            QStringLiteral("monitor.action_analyze.data_write_watch"), sourceText(QStringLiteral("写入停点")),
            sourceText(QStringLiteral("监控")), this, std::move(external),
            sourceText(QStringLiteral("在写入停点页继续或关闭本次会话。")));
        connect(m_poll, &QTimer::timeout, this, [this] { submit(Action::Query); });
        connect(m_start, &QPushButton::clicked, this, [this] { submit(Action::Start); });
        connect(m_continue, &QPushButton::clicked, this, [this] { submit(Action::Continue); });
        connect(m_pause, &QPushButton::clicked, this, [this] { submit(Action::Pause, m_result); });
        connect(m_step, &QPushButton::clicked, this, [this] { submit(Action::Step); });
        connect(m_cancelStep, &QPushButton::clicked, this, [this] { submit(Action::CancelStep); });
        connect(m_close, &QPushButton::clicked, this, [this] { submit(Action::Close); });
        connect(m_followExecution, &QPushButton::clicked, this, [this] {
            if (m_followExecution->isEnabled() && !m_work->isBusy())
            {
                submit(Action::FollowExecution, m_result); // 点击时冻结原写入事件，不借用之后的查询状态。
            }
        });
        connect(m_saveExecution, &QPushButton::clicked, this, [this] {
            if (m_saveExecution->isEnabled() && !m_work->isBusy())
            {
                submit(Action::SaveExecution, m_result); // 点击时复制原停止事件，不借用后续状态。
            }
        });
        const auto siteEdited = [this] {
            m_definitionDraft.clear(); // 手工更改位置后，不把新的请求继续标为旧定义。
            refresh();
        };
        connect(m_image, &QLineEdit::textChanged, this, siteEdited);
        connect(m_export, &QLineEdit::textChanged, this, siteEdited);
        connect(m_siteKind, &QComboBox::currentIndexChanged, this, siteEdited);
        connect(m_condition, &QLineEdit::textChanged, this, [this] {
            if (m_conditionFailure.diagnostic)
            {
                m_conditionFailure = {}; // 编辑草稿只消除旧校验提示，不修改运行条件或结果身份。
                refresh();
            }
        });
        connect(m_browse, &QPushButton::clicked, this, [this] {
            const bool imageAttachment = m_siteKind->currentData().toInt() >= 6; // 选择器跟随当前草稿用途。
            const auto path = QFileDialog::getOpenFileName(this, sourceText(imageAttachment
                ? QStringLiteral("选择已加载模块") : QStringLiteral("选择合作程序")),
                m_image->text(), sourceText(imageAttachment
                    ? QStringLiteral("Windows 模块 (*.exe *.dll)") : QStringLiteral("Windows 程序 (*.exe)")));
            if (!path.isEmpty())
            {
                m_image->setText(path);
            }
        });
        if (m_toolbar)
        {
            m_toolbar->prepareImageRva = [page = QPointer<DataWriteWatchPage>(this)](
                const QString& path, std::uint32_t rva, const QString& definitionId, const QString& projectPath)
            {
                if (!page || page->m_owner || page->m_work->isBusy() || !rva || !QFileInfo(path).isAbsolute() ||
                    (!definitionId.isEmpty() && projectPath.isEmpty()))
                {
                    return false; // 活会话与在途动作不接受另一次目标绑定。
                }
                if (!page->m_image->text().isEmpty() || !page->m_export->text().isEmpty())
                {
                    // 显式载入会替换位置草稿，保留实例与条件；旧结果仍显示原请求身份。
                    const auto answer = QMessageBox::question(page, sourceText(QStringLiteral("载入断点定义")),
                        sourceText(QStringLiteral("替换当前模块与位置草稿？目标实例、条件和已有结果将保留。")),
                        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
                    if (answer != QMessageBox::Yes || !page || page->m_owner || page->m_work->isBusy())
                    {
                        return false;
                    }
                }
                const QSignalBlocker modeBlock(page->m_siteKind); // 一次提交完整草稿，不触发半成品刷新。
                const QSignalBlocker pathBlock(page->m_image);
                const QSignalBlocker locationBlock(page->m_export);
                if (!definitionId.isEmpty() && !page->m_memoryPane->SetExistingProjectDraft(projectPath))
                {
                    return false; // 已保存定义必须连同原项目载入，不能错误创建无定义的全新项目。
                }
                page->m_siteKind->setCurrentIndex(page->m_siteKind->findData(7));
                page->m_image->setText(path);
                page->m_export->setText(QStringLiteral("0x%1").arg(rva, 0, 16));
                page->m_definitionDraft = definitionId;
                page->refresh();
                return true; // 仅参数已载入，未调用原生ArmBreakpoint。
            };
            m_toolbar->execute = [page = QPointer<DataWriteWatchPage>(this)](DataWatchToolbarAction action)
            {
                if (!page)
                {
                    return;
                }
                // 各动作再次核对原按钮资格；工具条旧快照不会授予控制权。
                if (action == DataWatchToolbarAction::Pause && page->m_pause->isEnabled())
                {
                    page->submit(Action::Pause, page->m_result);
                }
                else if (action == DataWatchToolbarAction::Continue && page->m_continue->isEnabled())
                {
                    page->submit(Action::Continue, page->m_result);
                }
                else if (action == DataWatchToolbarAction::CancelStep && page->m_cancelStep->isEnabled())
                {
                    page->submit(Action::CancelStep, page->m_result);
                }
                else if (action == DataWatchToolbarAction::Close && page->m_close->isEnabled())
                {
                    page->submit(Action::Close);
                }
                else if (action == DataWatchToolbarAction::DumpMemory && page->m_toolbar && page->m_toolbar->state.canDump)
                {
                    ProcessGroupRequest request; // 相机使用原参数页的范围草稿，点击时冻结完整Held事件。
                    if (page->m_memoryPane->PrepareNative(page->m_result, request))
                    {
                        page->submit(Action::DumpMemory, page->m_result, {}, std::move(request));
                    }
                }
                else if (page->m_step->isEnabled() && (action == DataWatchToolbarAction::Into ||
                    action == DataWatchToolbarAction::OverCall || action == DataWatchToolbarAction::Out))
                {
                    const auto mode = action == DataWatchToolbarAction::Into ? native::NativeStepMode::Into
                        : action == DataWatchToolbarAction::OverCall ? native::NativeStepMode::OverCall : native::NativeStepMode::Out;
                    page->submit(Action::Step, page->m_result, mode);
                }
            };
        }
        refresh();
    }

    DataWriteWatchPage::~DataWriteWatchPage()
    {
        if (m_toolbar)
        {
            m_toolbar->execute = {}; // 页面退出即撤销工具条入口，未决原生责任仍由原owner清退。
            m_toolbar->prepareImageRva = {};
            m_toolbar->state = {};
            if (m_toolbar->changed)
            {
                m_toolbar->changed();
            }
        }
        m_poll->stop();
        m_work->close();
        if (m_owner)
        {
            m_owner->Cleanup(); // 后台闭包继续持有原owner，直到真实clean才释放。
            m_owner.reset();
        }
    }

    void DataWriteWatchPage::submit(Action action, std::optional<native::NativeControlResult> selectedStop,
        std::optional<native::NativeStepMode> selectedMode, std::optional<ProcessGroupRequest> memory,
        std::optional<std::pair<std::uint64_t, std::uint64_t>> range,
        std::optional<Ksword::ActionAnalyze::NativeBoundApiRequest> api,
        std::optional<NativeExecutionCandidatesRequest> candidates)
    {
        if ((action == Action::Start ? !m_start->isEnabled() : !m_owner) ||
            (action == Action::Pause && !m_pause->isEnabled()) ||
            (action == Action::Continue && !selectedStop && !m_continue->isEnabled()) ||
            (action == Action::Step && !selectedStop && !m_step->isEnabled()) ||
            (action == Action::CancelStep && !selectedStop && !m_cancelStep->isEnabled()))
        {
            return;
        }
        // 查询正进行时保留显式动作，以点击时的回执继续，由原生所有者拒绝过期令牌。
        if (m_work->isBusy())
        {
            if (action == Action::ReadMemory || action == Action::SaveMemory || action == Action::DumpMemory || action == Action::SaveExecution ||
                action == Action::FollowExecution || action == Action::AddRange || action == Action::CaptureApi ||
                action == Action::ReadCandidates)
            {
                if (candidates)
                {
                    m_candidatesPane->ReadNotQueued(candidates->serial);
                }
                return; // 内存动作不挤入旧控制队列，避免丢失冻结范围或capture身份。
            }
            if (!m_queuedAction && action != Action::Query && action != Action::Start)
            {
                m_queuedAction = action;
                if (action != Action::Close)
                {
                    m_queuedStop = m_result;
                    m_queuedMode = static_cast<native::NativeStepMode>(m_stepMode->currentData().toInt());
                }
                refresh();
            }
            return;
        }
        rules::PreparedPredicate condition; // 只有启动命令需要携带新编译的不可变条件。
        if (action == Action::Start)
        {
            const auto draft = m_condition->text(); // 原文交给编译器，错误位置从原 UTF-8 字节计算。
            auto prepared = native::PrepareDataWatchCondition(draft.toStdWString());
            if (prepared.diagnostic)
            {
                m_conditionFailure = std::move(prepared);
                m_condition->setFocus();
                refresh();
                return; // 未创建所有者，旧停点与启动回执保持可查。
            }
            condition = std::move(prepared.predicate);
            m_conditionFailure = {};
            m_owner = SessionOwner::Create();
            if (!m_owner)
            {
                m_failed = true; // 应用已退出准入时不创建原生调试副作用。
                refresh();
                return;
            }
            m_runImage = m_image->text().trimmed();
            m_runDefinition = m_definitionDraft; // 只有真正提交的请求才取得定义来源。
            m_runExport = m_export->text().trimmed();
            const auto siteKind = m_siteKind->currentData().toInt(); // 点击时冻结实际模式。
            m_runImageAttachment = siteKind >= 6; // 原有模式0..5语义保留。
            m_runImageRva = siteKind == 7 ? ParseImageExecutionRva(m_runExport) : std::nullopt;
            m_runPrivate = {};
            if (siteKind >= 3)
            {
                m_privateFields->Prepare(m_runPrivate, siteKind == 5, !m_runImageAttachment);
                if (!m_runImageAttachment)
                {
                    m_runImage.clear(); // 普通模块模式同时保留实例选择与模块内位置。
                    m_runExport.clear();
                }
            }
            m_runExecution = siteKind == 2 || siteKind >= 4;
            m_runWidth = m_runExecution ? 0 : m_width->currentData().toUInt();
            m_runIndirect = m_siteKind->currentData().toInt() != 0;
            m_runCondition = draft;
            m_result = {}; // 新启动的身份还未知，不能把上次 PID 投影成当前候选。
            m_conditionReport = {};
            m_lastStop.reset();
            m_memoryShown = {}; // 新会话开始前旧内存仍可查；显式Start才切换身份。
            m_executionShown = {};
            m_apiShown.reset(); // 新一轮会话的API回执不沿用上轮采样。
            m_candidatesShown.reset(); // 旧目录仍由Pane保留原归属，不能授予新会话草稿资格。
        }
        if (action == Action::Close)
        {
            m_closing = true;
        }
        const auto owner = m_owner; // 值任务保留本轮唯一原生所有者。
        const auto path = m_runImage.toStdWString(); // 启动前冻结，之后不访问控件。
        const auto symbol = m_runExport.toStdString(); // 后端校验大小写精确的 PE 导出。
        const auto width = m_runWidth; // 使用本次运行已冻结的宽度。
        const auto indirect = m_runIndirect; // 私有指针选择也冻结到本轮请求。
        const auto execution = m_runExecution; // 不读取后续selector草稿来改变启动类型。
        const auto privateTarget = m_runPrivate; // 仅启动使用冻结实例与地址。
        const bool imageAttachment = m_runImageAttachment; // 冻结已有模块附加类型，不读取后台中的selector。
        const auto imageRva = m_runImageRva; // 模块RVA已在点击时解析为32位非零值。
        const auto definitionId = m_runDefinition.toStdString(); // 定义必须属于本轮实际创建sample的冻结配置。
        const auto displayedStop = selectedStop ? std::move(*selectedStop) : m_result; // 使用实际点击的令牌。
        const auto mode = selectedMode.value_or(static_cast<native::NativeStepMode>(m_stepMode->currentData().toInt()));
        const auto projectDirectory = m_memoryPane->ProjectDirectory(); // 只在Start前采用，后台不读控件。
        const bool openExistingProject = m_memoryPane->OpenExistingProject(); // 显式打开已有项目仍创建本次新采样。
        m_failed = false;
        m_mutating = action != Action::Query;
        const auto candidatesSerial = candidates ? candidates->serial : 0; // 任务失败时解除目录该请求等待态。
        const auto accepted = m_work->submitTransaction<Action, WatchResult>(action,
            [owner, path, symbol, width, indirect, execution, privateTarget, imageAttachment, imageRva, definitionId,
                displayedStop, mode, projectDirectory, openExistingProject,
                memory = std::move(memory), range, api, candidates, condition = std::move(condition)](Action command) {
                std::lock_guard lock(owner->access); // 串行化命令和页面销毁时的关闭。
                if (owner->retired)
                {
                    return WatchResult{};
                }
                native::NativeControlResult result; // 控制命令与随后条件回执保持在同一个加锁区间。
                switch (command)
                {
                case Action::Start:
                    if (owner->memory.PrepareProject(projectDirectory, openExistingProject) &&
                        owner->memory.ValidateImageDefinition(definitionId, path, imageRva.value_or(0)))
                    {
                        result = imageAttachment
                            ? owner->session.AttachImageExecution(privateTarget.pid, privateTarget.creation, path,
                                imageRva, imageRva ? std::string{} : symbol, condition, owner->memory.SampleId())
                            : privateTarget.pid
                            ? owner->session.AttachPrivateAddress(privateTarget.pid, privateTarget.creation,
                                privateTarget.address, width, condition, owner->memory.SampleId(), privateTarget.rangeBytes)
                            : execution
                            ? owner->session.StartPrivateExecution(path, symbol, condition, owner->memory.SampleId())
                            : owner->session.Start(path, symbol, width, condition, indirect, owner->memory.SampleId());
                    }
                    else
                    {
                        result.status = native::NativeControlStatus::Rejected;
                        result.stage = "process-group-memory-project-failed";
                        result.win32Error = owner->memory.View().projectResult.nativeError;
                    }
                    break;
                case Action::Continue: result = owner->session.Continue(displayedStop); break;
                case Action::Pause: result = owner->session.Pause(displayedStop); break;
                case Action::FollowExecution:
                    result = owner->session.FollowPrivateExecution(displayedStop); // 不经Continue或新Start。
                    break;
                case Action::AddRange:
                    result = range ? owner->session.AddPrivateExecutionRange(displayedStop, range->first, range->second)
                        : displayedStop; // 原owner检查完整事件，新范围不改变原停止位置。
                    break;
                case Action::CaptureApi:
                    result = owner->session.QueryWithoutCondition(); // API准入不触发原条件的自动Continue或合作Gate。
                    if (api)
                    {
                        owner->memory.CaptureApi(*api, {result.pid, result.processCreationTime, result.attached});
                    }
                    result = owner->session.QueryWithoutCondition(); // 有限采集期间可能出现真实命中，回投实际状态而不自动放行。
                    break;
                case Action::Step: result = owner->session.Step(displayedStop, mode); break;
                case Action::ReadCandidates:
                    result = owner->session.QueryWithoutCondition(); // 只读目录不触发命中条件自动Continue。
                    if (candidates)
                    {
                        auto request = *candidates; // 核对原owner当前实例，不将请求中的旧PID当成当前实例。
                        if (request.context.target.pid != result.pid ||
                            request.context.target.creationFileTime != result.processCreationTime)
                        {
                            request.context.sampleId.clear(); // 原archive发布归属失败，保留Pane旧结果。
                        }
                        owner->memory.ReadExecutionCandidates(request);
                    }
                    result = owner->session.QueryWithoutCondition(); // 读取期间真实停止变化也从原owner回投。
                    break;
                case Action::CancelStep: result = owner->session.CancelStep(displayedStop); break;
                case Action::Close: result = owner->session.Close(); break;
                case Action::Query: result = owner->session.Query(); break;
                case Action::ReadMemory:
                case Action::DumpMemory:
                    if (memory && memory->memory)
                    {
                        owner->memory.Capture(owner->session, displayedStop, memory->memory->plan);
                        if (command == Action::DumpMemory)
                        {
                            // 保存刚读取的原capture，失败页与部分成功由现有归档层独立呈现。
                            owner->memory.Save(owner->memory.View().memory);
                        }
                    }
                    result = displayedStop; // 读取不经Query/ApplyCondition，不自动继续。
                    break;
                case Action::SaveMemory:
                    if (memory)
                    {
                        owner->memory.Save(memory->memoryToSave);
                    }
                    result = displayedStop;
                    break;
                case Action::SaveExecution:
                    owner->memory.SaveExecution(owner->session, displayedStop);
                    result = displayedStop; // 保存不经条件Query，不执行Continue。
                    break;
                }
                if (result.clean && !result.attached && (command == Action::Close ||
                    result.status == native::NativeControlStatus::Rejected ||
                    result.status == native::NativeControlStatus::Closed ||
                    result.status == native::NativeControlStatus::Detached ||
                    result.status == native::NativeControlStatus::Ended))
                {
                    owner->memory.CloseProject(); // 同串行worker释放，不在GUI回投时析构writer。
                }
                return WatchResult{std::move(result), owner->session.ConditionReport(), owner->memory.View(),
                    owner->memory.ExecutionView(), owner->memory.ApiView(), owner->memory.CandidateView()};
            }, [this, action](const auto& result, std::uint64_t) {
                m_mutating = false;
                apply(result, action);
                return true;
            }, [this, candidatesSerial](std::exception_ptr) {
                m_mutating = false;
                m_failed = true;
                m_poll->stop();
                if (candidatesSerial)
                {
                    m_candidatesPane->ReadNotQueued(candidatesSerial);
                }
                refresh();
            });
        if (!accepted)
        {
            m_mutating = false;
            m_failed = true;
            if (candidatesSerial)
            {
                m_candidatesPane->ReadNotQueued(candidatesSerial);
            }
        }
        if (action != Action::Query)
        {
            refresh();
        }
    }

    void DataWriteWatchPage::apply(const WatchResult& receipt, Action action)
    {
        const auto& result = receipt.control; // 所有字段均从该命令返回的同一快照取得。
        m_result = result;
        m_conditionReport = receipt.condition;
        m_memoryShown = receipt.memory; // 后续Query只复制原内存结果，不重新采集或改写来源。
        m_executionShown = receipt.execution;
        m_apiShown = receipt.api; // API附加、清退和归档状态均由共享服务独立提供。
        m_candidatesShown = receipt.candidates; // 来源快照与本轮native控制值在同一worker回合发布。
        if (action == Action::ReadCandidates)
        {
            m_candidatesPane->Consume(receipt.candidates);
        }
        if (result.breakpoint && !result.breakpoint->writeWatchBytes &&
            (result.breakpoint->executePointerExport || result.breakpoint->explicitPrivateAddress))
        {
            m_runExecution = true; // 同一请求当前已切执行；原写入命中及参数草稿仍保留。
        }
        if (IsHeldWrite(result, receipt.condition, !m_runCondition.isEmpty()) && result.breakpointHit &&
                result.group && result.group->origin &&
                (!m_lastStop || m_lastStop->group->groupId != result.group->groupId))
        {
            m_lastStop = result;
        }
        if (result.clean && !result.attached && (action == Action::Close ||
                result.status == native::NativeControlStatus::Rejected || result.status == native::NativeControlStatus::Closed ||
                result.status == native::NativeControlStatus::Detached || result.status == native::NativeControlStatus::Ended))
        {
            m_owner.reset(); // 已确认无未结原生责任，允许下一次独立启动。
            m_closing = false;
        }
        if (m_owner && result.status != native::NativeControlStatus::RecoveryRequired)
        {
            if (!m_poll->isActive())
            {
                m_poll->start();
            }
        }
        else
        {
            m_poll->stop();
        }
        refresh();
    }

    void DataWriteWatchPage::refresh()
    {
        const bool active = m_owner != nullptr; // 原所有者仍在时保留参数与关闭入口。
        const bool held = IsHeldWrite(m_result, m_conditionReport, !m_runCondition.isEmpty()); // 与当前事件核对手动继续资格。
        const bool recovery = m_result.status == native::NativeControlStatus::RecoveryRequired;
        const bool armed = m_result.breakpoint && m_result.breakpoint->state == native::NativeBreakpointState::Armed;
        const auto siteKind = m_siteKind->currentData().toInt(); // 草稿不改变当前结果身份。
        const bool privateDraft = siteKind >= 3 && siteKind <= 5;
        const bool imageAttachmentDraft = siteKind >= 6; // 普通模块同时展示实例与模块选择器。
        const bool executionDraft = siteKind == 2 || siteKind >= 4;
        const bool pageExecutionDraft = siteKind == 5; // 整页与单地址的草稿只影响下一次启动。
        m_target->setTitle(sourceText(imageAttachmentDraft ? QStringLiteral("已有进程模块断点")
            : privateDraft ? QStringLiteral("已有进程私有地址") : QStringLiteral("合作程序")));
        m_imageLabel->setText(sourceText(imageAttachmentDraft ? QStringLiteral("已加载模块路径") : QStringLiteral("程序路径")));
        m_exportLabel->setText(sourceText(siteKind == 7 ? QStringLiteral("模块 RVA")
            : imageAttachmentDraft ? QStringLiteral("精确 PE 导出名") : QStringLiteral("数据导出名")));
        m_widthLabel->setText(sourceText(QStringLiteral("关注宽度（字节）")));
        m_siteKindLabel->setText(sourceText(QStringLiteral("数据绑定方式")));
        m_siteKind->setItemText(0, sourceText(QStringLiteral("映像数据导出")));
        m_siteKind->setItemText(1, sourceText(QStringLiteral("指针导出的私有区间")));
        m_siteKind->setItemText(2, sourceText(QStringLiteral("指针导出的私有执行入口")));
        m_siteKind->setItemText(3, sourceText(QStringLiteral("已有私有地址写关注")));
        m_siteKind->setItemText(4, sourceText(QStringLiteral("已有私有地址执行关注")));
        m_siteKind->setItemText(5, sourceText(QStringLiteral("已有私有页执行关注")));
        m_siteKind->setItemText(6, sourceText(QStringLiteral("已有模块导出执行关注")));
        m_siteKind->setItemText(7, sourceText(QStringLiteral("已有模块RVA执行关注")));
        m_privateFields->setVisible(privateDraft || imageAttachmentDraft);
        m_privateFields->SetPageExecutionMode(pageExecutionDraft, imageAttachmentDraft);
        m_privateFields->SetActive(active);
        auto* targetForm = static_cast<QFormLayout*>(m_target->layout()); // 原表单只按模式显示适用选择器。
        targetForm->setRowVisible(m_image, !privateDraft);
        targetForm->setRowVisible(m_export, !privateDraft);
        m_siteKind->setToolTip(imageAttachmentDraft
            ? sourceText(QStringLiteral("已有模块执行关注使用目标PID和创建时间，核验已加载模块及模块内执行位置；无需合作握手，不启动程序或修改页保护。"))
            : sourceText(QStringLiteral("私有区间模式需合作目标初始化指针后发出 Ready，并等待 Gate 许可；绑定期间不自动跟随指针变化。")) +
            QLatin1Char('\n') + sourceText(pageExecutionDraft
                ? QStringLiteral("整页执行关注覆盖所选私有页内的实际取指地址；使用NX异常和原生TF重新设防，不占用DR0。")
                : QStringLiteral("私有执行使用8字节映像数据指针选择 MEM_PRIVATE EXECUTE/RX/RWX 入口，不监视数据写入；指针或区域变化将清退原绑定。")));
        m_width->setToolTip(sourceText(pageExecutionDraft
            ? QStringLiteral("执行关注范围由页数决定，每页4096字节；写入关注宽度不适用。")
            : privateDraft
            ? QStringLiteral("地址支持十进制或0x十六进制。执行关注要求私有 EXECUTE/RX/RWX，写关注要求自然对齐的私有 RW/RWX；不会修改页保护。")
            : QStringLiteral("私有执行使用8字节映像数据指针选择 MEM_PRIVATE EXECUTE/RX/RWX 入口，不监视数据写入；指针或区域变化将清退原绑定。")));
        m_conditionLabel->setText(sourceText(QStringLiteral("停点条件（可选）")));
        m_stepLabel->setText(sourceText(QStringLiteral("原生步进模式")));
        m_stepMode->setItemText(0, sourceText(QStringLiteral("步入一条机器指令")));
        m_stepMode->setItemText(1, sourceText(QStringLiteral("越过当前调用")));
        m_stepMode->setItemText(2, sourceText(QStringLiteral("跳出可信调用帧")));
        m_condition->setPlaceholderText(executionDraft ? QStringLiteral("stop.tid != 0u64")
            : QStringLiteral("stop.data.changedByteMask == 1u64")); // 执行模式不以写入字段充当进入条件。
        m_condition->setToolTip((executionDraft
            ? sourceText(QStringLiteral("条件仅作用于执行入口尝试；普通步进停点不重复求值。执行事件不提供 stop.data 字段；假或未知自动继续。"))
            : sourceText(QStringLiteral("留空时在每次字节变化时停下。条件在启动时生效；假或未知时自动继续。"))) +
            QLatin1Char('\n') + sourceText(QStringLiteral("可用字段：stop.address、stop.data.changedByteMask、stop.data.watchedBytes、stop.data.enrolledAfterStop、stop.exceptionCode、stop.firstChance、stop.pid、stop.tid、stop.thread.creationFileTime。stop.thread 下支持 rip、rax、rbx、rcx、rdx、rbp、rsi、rdi、rsp、r8 至 r15、eflags。寄存器取自命中线程的冻结快照，采集失败为未知。")));
        m_condition->setToolTip(m_condition->toolTip() + QLatin1Char('\n') + sourceText(QStringLiteral("数值条件示例：(stop.thread.rax & 0xffu64) == 0u64、stop.thread.rip >= stop.address。位运算比较请加括号；无符号运算溢出环绕，除零为未知。")));
        if (m_conditionFailure.diagnostic)
        {
            auto error = sourceText(QStringLiteral("停点条件无效：%1")).arg(QString::fromLatin1(m_conditionFailure.diagnostic));
            if (const auto& at = m_conditionFailure.location)
            {
                error += QLatin1Char('\n') + sourceText(QStringLiteral("UTF-8 字节偏移：%1")).arg(qulonglong(at->offset));
            }
            m_conditionError->setText(error);
        }
        m_conditionError->setVisible(m_conditionFailure.diagnostic != nullptr);
        m_image->setReadOnly(active);
        m_export->setReadOnly(active);
        m_width->setEnabled(!active && !executionDraft);
        m_siteKind->setEnabled(!active);
        m_browse->setEnabled(!active && !privateDraft);
        PrivateAddressWatchTarget candidate; // 草稿仅检查格式，真实身份与区域由后台核对。
        const bool targetReady = privateDraft ? m_privateFields->Prepare(candidate, pageExecutionDraft)
            : QFileInfo(m_image->text().trimmed()).isAbsolute() && !m_export->text().trimmed().isEmpty() &&
                (!imageAttachmentDraft || (m_privateFields->Prepare(candidate, false, false) &&
                    (siteKind != 7 || ParseImageExecutionRva(m_export->text()).has_value())));
        m_start->setEnabled(m_registered && !active && targetReady);
        const bool busy = m_queuedAction.has_value() || m_mutating; // 控制命令进行中阻止重复点击。
        const bool nxSession = active && m_result.breakpoint && m_result.breakpoint->rangeBytes;
        m_rangePane->setVisible(nxSession || (!active && pageExecutionDraft));
        m_rangePane->SetAvailable(nxSession && held && m_result.group &&
            m_result.group->state == native::GroupState::HeldComplete && !busy && !m_work->isBusy() &&
            !m_closing && !m_failed,
            nxSession && held ? QString() : sourceText(QStringLiteral("需要本会话持有完整的私有页执行停点。")));
        NativeExecutionCandidatesContext candidatesContext; // 本轮项目和强实例来自原worker快照，不读取草稿目录。
        candidatesContext.projectDirectory = m_memoryShown.projectDirectory;
        candidatesContext.sampleId = m_memoryShown.sampleId;
        candidatesContext.target = {m_result.pid, m_result.processCreationTime, m_result.attached};
        candidatesContext.nxBinding = nxSession;
        candidatesContext.fullHeld = held && m_result.group && m_result.group->state == native::GroupState::HeldComplete;
        m_candidatesPane->SetContext(candidatesContext, busy || m_work->isBusy() || m_closing || m_failed);
        m_candidatesPane->setVisible(nxSession || (!active && pageExecutionDraft));
        auto memoryView = m_memoryShown; // 动作资格与原读取结果身份分开。
        memoryView.busy = busy || m_work->isBusy();
        memoryView.closing = m_closing;
        m_memoryPane->Update(memoryView, active && held && m_result.group &&
            m_result.group->state == native::GroupState::HeldComplete, active);
        m_saveExecution->setEnabled(active && !busy && !m_work->isBusy() && !m_closing &&
            !m_memoryShown.projectDirectory.empty() && !m_executionShown.blocked &&
            native::NativeExecutionFromOwnedStop(m_result).has_value());
        m_captureApi->setEnabled(active && m_result.attached && !busy && !m_work->isBusy() && !m_closing &&
            !m_failed && !m_memoryShown.projectDirectory.empty());
        m_captureApi->setAccessibleName(sourceText(QStringLiteral("采集同采样 API")));
        m_captureApi->setToolTip(m_captureApi->isEnabled()
            ? sourceText(QStringLiteral("确认另一来源实例，采集1至10秒并写入原项目与采样。"))
            : sourceText(QStringLiteral("需要已附加的原生会话及本轮项目采样；控制操作期间不可采集。")));
        m_continue->setEnabled(active && held && !busy && !m_closing && !m_failed);
        m_pause->setEnabled(active && !busy && !m_closing && !m_failed && native::CanPauseDataWatchSession(m_result));
        m_followExecution->setEnabled(active && held && !busy && !m_work->isBusy() && !m_closing && !m_failed &&
            native::CanFollowDataWatchPrivateExecution(m_result));
        m_step->setEnabled(m_continue->isEnabled() && m_result.stopReason != native::NativeStopReason::ManualPause);
        const bool stepping = active && m_result.step && m_result.step->state == native::NativeStepState::Running;
        m_cancelStep->setEnabled(stepping && !busy && !m_closing && !m_failed);
        m_close->setEnabled(active && !busy);
        if (m_toolbar)
        {
            DataWatchToolbarState state; // 同一次UI回投生成资格，不额外调用owner.Query。
            if (m_result.pid)
            {
                state.target = QStringLiteral("PID %1 · FILETIME %2").arg(m_result.pid).arg(m_result.processCreationTime);
            }
            state.canContinue = m_continue->isEnabled();
            state.canPause = m_pause->isEnabled();
            state.canStep = m_step->isEnabled();
            state.canCancel = m_cancelStep->isEnabled();
            state.canDump = active && held && m_result.group && m_result.group->state == native::GroupState::HeldComplete &&
                !busy && !m_work->isBusy() && !m_closing && !m_memoryShown.projectDirectory.empty() && !m_memoryShown.memoryArchiveBlocked;
            state.canClose = m_close->isEnabled();
            if (state != m_toolbar->state)
            {
                m_toolbar->state = std::move(state);
                if (m_toolbar->changed)
                {
                    m_toolbar->changed();
                }
            }
        }

        // Tooltip 和无障碍名称对应实际动作。禁用时解释当前资格。
        const auto actionHint = [](auto* button, const QString& name, const QString& disabled = {}) {
            button->setAccessibleName(name);
            button->setToolTip(button->isEnabled() || disabled.isEmpty() ? name : disabled);
        };
        actionHint(m_browse, sourceText(imageAttachmentDraft ? QStringLiteral("选择已加载模块") : QStringLiteral("选择合作程序")));
        actionHint(m_start, sourceText(imageAttachmentDraft ? QStringLiteral("附加并设置模块执行断点")
            : executionDraft ? QStringLiteral("启动私有执行监控") : QStringLiteral("启动写入监控")),
            sourceText(imageAttachmentDraft ? QStringLiteral("需填写目标 PID、创建 FILETIME、模块绝对路径及精确导出名或非零RVA，且本端无活会话。")
                : pageExecutionDraft ? QStringLiteral("需填写目标 PID、创建 FILETIME 与4KiB对齐的私有页起点，且本端无活会话。")
                : privateDraft ? QStringLiteral("需填写目标 PID、创建 FILETIME 与私有地址，且本端无活会话。")
                : QStringLiteral("需选择合作程序并填写数据导出名，且本端无活会话。")));
        actionHint(m_continue, sourceText(QStringLiteral("继续当前停点")),
            sourceText(QStringLiteral("等待可继续的写入、执行或步进停点。")));
        actionHint(m_pause, sourceText(QStringLiteral("主动暂停原执行会话")),
            sourceText(QStringLiteral("需要正在运行且已武装的原生会话；已有停点、步进或恢复期间不能再次暂停。")));
        m_followExecution->setAccessibleName(sourceText(QStringLiteral("同址私有写转执行")));
        m_followExecution->setToolTip(sourceText(QStringLiteral("仅将当前完整写入停点的原私有 RWX 起点切换为单地址执行关注，不继续线程。沿用本轮冻结条件，仅后续真实执行命中求值；转换失败完整回滚，恢复未确认时使用关闭。")));
        actionHint(m_step, sourceText(QStringLiteral("执行所选原生步进")),
            sourceText(QStringLiteral("需持有当前停止事件及其线程身份。")));
        actionHint(m_cancelStep, sourceText(QStringLiteral("取消当前原生步进")),
            sourceText(QStringLiteral("当前没有正在运行的原生步进。")));
        m_stepMode->setToolTip(sourceText(QStringLiteral("步进当前停止事件的线程；跳出仅支持已核验的调用帧，失败时保留停点。")));
        actionHint(m_close, sourceText(m_runImageAttachment ? QStringLiteral("脱离模块执行监控")
            : m_runExecution ? QStringLiteral("脱离私有执行监控") : QStringLiteral("脱离写入监控")),
            sourceText(QStringLiteral("当前没有可关闭的写入监控会话。")));

        // 状态文本只观察当前控制回执。诊断码从原生返回，不以按钮状态推断。
        const auto state = m_result.status; // 忙时仍保留上次已知停点详情。
        const auto status = active && held && !m_failed && !recovery && !m_closing &&
            m_result.stopReason == native::NativeStopReason::ManualPause
            ? sourceText(QStringLiteral("已主动暂停原执行会话"))
            : active && !m_failed && !recovery && !m_closing && m_result.armedPause &&
                m_result.armedPause->state == native::NativeArmedPauseState::Pending
                ? sourceText(QStringLiteral("正在等待原执行会话暂停事件"))
            : m_runImageAttachment
            ? (m_failed || recovery ? sourceText(QStringLiteral("模块执行监控需要恢复"))
                : state == native::NativeControlStatus::Rejected ? sourceText(QStringLiteral("模块执行监控操作被拒绝"))
                : state == native::NativeControlStatus::Ended ? sourceText(QStringLiteral("模块执行目标已退出"))
                : m_closing ? sourceText(QStringLiteral("正在脱离模块执行监控"))
                : stepping ? sourceText(QStringLiteral("正在执行原生步进"))
                : active && held && native::IsDataWatchStepStop(m_result) ? sourceText(QStringLiteral("已停在原生步进事件"))
                : active && held ? sourceText(QStringLiteral("已停在模块执行入口尝试"))
                : active && armed ? sourceText(QStringLiteral("正在等待模块执行入口"))
                : active ? sourceText(QStringLiteral("正在绑定模块执行入口"))
                : sourceText(QStringLiteral("模块执行监控已脱离")))
            : m_runExecution
            ? (m_failed || recovery ? sourceText(QStringLiteral("私有执行监控需要恢复"))
                : state == native::NativeControlStatus::Rejected ? sourceText(QStringLiteral("私有执行监控操作被拒绝"))
                : state == native::NativeControlStatus::Ended ? sourceText(QStringLiteral("私有执行目标已退出"))
                : m_closing ? sourceText(QStringLiteral("正在脱离私有执行监控"))
                : stepping ? sourceText(QStringLiteral("正在执行原生步进"))
                : active && held && native::IsDataWatchStepStop(m_result) ? sourceText(QStringLiteral("已停在原生步进事件"))
                : active && held && m_result.breakpointHit && m_result.breakpointHit->dataChange
                    ? sourceText(QStringLiteral("已切换执行关注，原写入事件仍保持停止"))
                : active && held ? sourceText(QStringLiteral("已停在私有执行入口尝试"))
                : active && armed ? sourceText(QStringLiteral("正在等待私有执行入口"))
                : active ? sourceText(QStringLiteral("正在绑定私有执行入口"))
                : sourceText(QStringLiteral("私有执行监控已脱离")))
            : m_failed || recovery ? sourceText(QStringLiteral("写入监控需要恢复"))
            : state == native::NativeControlStatus::Rejected && !active ? sourceText(QStringLiteral("无法启动写入监控"))
            : state == native::NativeControlStatus::Rejected ? sourceText(QStringLiteral("写入监控操作被拒绝"))
            : state == native::NativeControlStatus::Ended ? sourceText(QStringLiteral("写入监控目标已退出"))
            : m_closing ? sourceText(QStringLiteral("正在脱离写入监控"))
            : stepping ? sourceText(QStringLiteral("正在执行原生步进"))
            : active && held && native::IsDataWatchStepStop(m_result) ? sourceText(QStringLiteral("已停在原生步进事件"))
            : active && held ? sourceText(QStringLiteral("已命中写入停点"))
            : active && armed ? sourceText(QStringLiteral("正在等待写入停点"))
            : active ? sourceText(QStringLiteral("正在绑定写入停点"))
            : state == native::NativeControlStatus::Idle ? sourceText(QStringLiteral("写入监控未开始"))
            : sourceText(QStringLiteral("写入监控已脱离"));
        if (m_status->text() != status)
        {
            m_status->setText(status);
        }
        ks::ui::ApplyStatusRole(m_status, m_failed || recovery || state == native::NativeControlStatus::Rejected
            ? StatusRole::Error : held ? StatusRole::Warning : active ? StatusRole::Info : StatusRole::Idle);

        // 字段由冻结目标与本次原生停点生成，继续和关闭后仍可检查实际写入者。
        ks::ui::FieldDocument document;
        if (!m_runImage.isEmpty() || m_runPrivate.pid)
        {
            document.section(m_runImageAttachment ? QStringLiteral("模块执行监控回执")
                : m_runExecution ? QStringLiteral("私有执行监控回执") : QStringLiteral("写入监控回执"))
                .field(QStringLiteral("关注宽度（字节）"), m_runExecution
                    ? sourceText(QStringLiteral("不适用（执行入口）")) : QString::number(m_runWidth))
                .field(QStringLiteral("数据绑定方式"), sourceText(m_runPrivate.pid
                    ? (m_runImageAttachment ? (m_runImageRva ? QStringLiteral("已有模块RVA执行关注") : QStringLiteral("已有模块导出执行关注"))
                        : m_runPrivate.rangeBytes ? QStringLiteral("已有私有页执行关注")
                        : m_runExecution ? QStringLiteral("已有私有地址执行关注") : QStringLiteral("已有私有地址写关注"))
                    : m_runExecution ? QStringLiteral("指针导出的私有执行入口")
                    : m_runIndirect ? QStringLiteral("指针导出的私有区间") : QStringLiteral("映像数据导出")))
                .field(QStringLiteral("本次停点条件"), m_runCondition.isEmpty() ? sourceText(QStringLiteral("未设置")) : m_runCondition)
                .field(QStringLiteral("PID"), m_result.pid ? QString::number(m_result.pid) : QStringLiteral("—"))
                .field(QStringLiteral("进程创建 FILETIME"), m_result.processCreationTime ? QString::number(m_result.processCreationTime) : QStringLiteral("—"))
                .field(QStringLiteral("诊断阶段"), QString::fromLatin1(m_result.stage))
                .field(QStringLiteral("Win32 错误"), QString::number(m_result.win32Error));
            if (m_runPrivate.pid)
            {
                document.field(QStringLiteral("请求目标 PID"), QString::number(m_runPrivate.pid))
                    .field(QStringLiteral("请求创建 FILETIME"), QString::number(m_runPrivate.creation));
                if (!m_runImageAttachment)
                {
                    document.field(QStringLiteral("私有地址"), QStringLiteral("0x%1").arg(m_runPrivate.address, 0, 16));
                }
            }
            if (!m_runImage.isEmpty())
            {
                document.field(m_runImageAttachment ? QStringLiteral("已加载模块路径") : QStringLiteral("程序路径"), m_runImage)
                    .field(m_runImageRva ? QStringLiteral("模块 RVA") : QStringLiteral("数据导出名"), m_runExport);
            }
        }
        if (const auto& binding = m_result.breakpoint; binding && binding->address)
        {
            document.field(QStringLiteral("关注地址"), QStringLiteral("0x%1").arg(binding->address, 0, 16))
                .field(QStringLiteral("已登记线程数"), QString::number(binding->enrolledThreads));
            if (m_runImageAttachment)
            {
                document.field(QStringLiteral("模块基址"), QStringLiteral("0x%1").arg(binding->moduleBase, 0, 16))
                    .field(QStringLiteral("模块 RVA"), QStringLiteral("0x%1").arg(binding->rva, 0, 16));
            }
            if (binding->rangeBytes)
            {
                // 范围是绑定起点，命中地址来自下方原生事件，两者不要求相等。
                document.field(QStringLiteral("执行关注范围（字节）"), QString::number(binding->rangeBytes))
                    .field(QStringLiteral("执行关注机制"), sourceText(QStringLiteral("NX页异常／原生TF重新设防")));
            }
            if (binding->pointerExportAddress || binding->explicitPrivateAddress)
            {
                if (binding->pointerExportAddress)
                {
                    document.field(QStringLiteral("指针导出地址"), QStringLiteral("0x%1").arg(binding->pointerExportAddress, 0, 16));
                }
                document.field(QStringLiteral("私有分配基址"), QStringLiteral("0x%1").arg(binding->allocationBase, 0, 16))
                    .field(QStringLiteral("绑定区域基址"), QStringLiteral("0x%1").arg(binding->regionBase, 0, 16))
                    .field(QStringLiteral("绑定区域字节数"), QString::number(binding->regionBytes))
                    .field(QStringLiteral("绑定区域保护"), QStringLiteral("0x%1").arg(binding->regionProtection, 0, 16))
                    .field(QStringLiteral("分配代次"), sourceText(QStringLiteral("未知")));
            }
        }
        if (const auto& registers = m_result.registers)
        {
            // 同一次原生事件的寄存器保留原线程身份，编辑草稿不会刷新现场。
            document.section(QStringLiteral("命中线程寄存器"))
                .field(QStringLiteral("线程实例 ID"), QString::fromStdString(registers->thread.threadId));
            for (const auto& field : native::NativeStopRegisterFields)
            {
                // 原规范文档同时供搜索、复制和导出；不另建只读输入框。
                document.field(QString::fromLatin1(field.name).toUpper(),
                    QStringLiteral("0x%1").arg((*registers).*(field.value), 16, 16, QLatin1Char('0')));
            }
        }
        if (!m_runCondition.isEmpty())
        {
            const auto& report = m_conditionReport; // 与冻结条件原文对应的三个真实计数。
            document.section(QStringLiteral("停点条件回执"))
                .field(QStringLiteral("真／假／未知次数"), QStringLiteral("%1 / %2 / %3")
                    .arg(report.trueCount).arg(report.falseCount).arg(report.unknownCount));
            if (const auto& decision = report.last)
            {
                const auto truth = decision->evaluation.truth; // 从求值器返回，不由继续状态推断。
                document.field(QStringLiteral("最近条件结论"), truth == rules::Truth::True ? sourceText(QStringLiteral("条件为真，命中停点"))
                    : truth == rules::Truth::False ? sourceText(QStringLiteral("条件为假")) : sourceText(QStringLiteral("条件未知")))
                    .field(QStringLiteral("条件事件序号"), QString::number(decision->event.serial))
                    .field(QStringLiteral("条件停止组"), QString::fromStdString(decision->groupId))
                    .field(QStringLiteral("条件求值时修订"), QString::number(decision->stateRevision));
                if (decision->evaluation.fault != rules::EvaluationFault::None)
                {
                    document.field(QStringLiteral("条件求值故障"), decision->evaluation.fault == rules::EvaluationFault::Budget
                        ? sourceText(QStringLiteral("超出求值预算"))
                        : decision->evaluation.fault == rules::EvaluationFault::DivisionByZero
                            ? sourceText(QStringLiteral("除数为零，条件未知")) : sourceText(QStringLiteral("求值输入无效")));
                }
                if (decision->failureStage || decision->release == native::ReleaseResult::Continued)
                {
                    document.field(QStringLiteral("自动继续回执"), decision->failureStage
                        ? sourceText(QStringLiteral("继续未确认")) : sourceText(QStringLiteral("已自动继续")));
                    if (decision->failureStage)
                    {
                        // 清退会更新主诊断，条件区仍保留这笔自动继续的原始失败信息。
                        document.field(QStringLiteral("诊断阶段"), QString::fromLatin1(decision->failureStage))
                            .field(QStringLiteral("Win32 错误"), QString::number(decision->releaseError));
                    }
                }
            }
        }
        if (const auto& pause = m_result.armedPause)
        {
            // 主动中断回执独立于断点命中；被真实命中抢先时仍保留原暂停请求结果。
            document.section(QStringLiteral("主动暂停回执"))
                .field(QStringLiteral("请求 ID"), QString::fromStdString(pause->request.requestId))
                .field(QStringLiteral("主动暂停状态"), sourceText(
                    pause->state == native::NativeArmedPauseState::Pending ? QStringLiteral("等待暂停事件") :
                    pause->state == native::NativeArmedPauseState::Held ? QStringLiteral("已主动暂停") :
                    pause->state == native::NativeArmedPauseState::Preempted ? QStringLiteral("真实事件先于主动暂停") :
                    pause->state == native::NativeArmedPauseState::Cancelled ? QStringLiteral("暂停请求已取消") :
                    pause->state == native::NativeArmedPauseState::Ended ? QStringLiteral("目标已退出") :
                    pause->state == native::NativeArmedPauseState::RecoveryRequired ? QStringLiteral("需要恢复") :
                    QStringLiteral("暂停请求被拒绝")))
                .field(QStringLiteral("诊断阶段"), QString::fromLatin1(pause->stage))
                .field(QStringLiteral("Win32 错误"), QString::number(pause->win32Error));
            if (pause->event)
            {
                document.field(QStringLiteral("原生事件序号"), QString::number(pause->event->serial));
            }
        }
        if (const auto& follow = m_result.executionFollow)
        {
            document.section(QStringLiteral("同址写转执行回执"))
                .field(QStringLiteral("请求 ID"), QString::fromStdString(follow->request.stop.requestId))
                .field(QStringLiteral("转换已确认"), follow->converted ? QStringLiteral("是") : QStringLiteral("否"), true)
                .field(QStringLiteral("失败回滚已确认"), follow->rollbackComplete ? QStringLiteral("是") : QStringLiteral("否"), true)
                .field(QStringLiteral("诊断阶段"), QString::fromLatin1(follow->stage))
                .field(QStringLiteral("Win32 错误"), QString::number(follow->win32Error))
                .field(QStringLiteral("关注地址"), QStringLiteral("0x%1").arg(follow->request.address, 0, 16));
            document.note(QStringLiteral("转换本身不是执行证据，原写入事件不会变成执行入口尝试。"));
        }
        if (m_lastStop)
        {
            const auto& hit = m_lastStop->breakpointHit->dataChange; // 执行入口没有数据变化掩码。
            const auto& threadId = m_lastStop->group->origin->threadId; // 账本冻结的命中线程 ID。
            const auto& threads = m_lastStop->frozenThreads; // 使用命中时保存的线程组。
            const auto thread = std::find_if(threads.begin(), threads.end(),
                [&](const auto& member) { return member.identity.threadId == threadId; });
            if (hit)
            {
                document.section(QStringLiteral("最近写入停点"))
                    .field(QStringLiteral("变化字节掩码"), QString::number(hit->changedByteMask))
                    .field(QStringLiteral("登记时已有停点数"), QString::number(hit->enrolledAfterStop));
            }
            else
            {
                document.section(QStringLiteral("最近执行入口尝试"))
                    .field(QStringLiteral("指令地址"), QStringLiteral("0x%1").arg(m_lastStop->breakpointHit->address, 0, 16));
            }
            if (thread != threads.end())
            {
                document.field(QStringLiteral("命中线程 TID"), QString::number(thread->tid))
                    .field(QStringLiteral("线程创建 FILETIME"), QString::number(thread->creationTime));
            }
        }
        if (const auto& step = m_result.step)
        {
            // 回执始终属于实际提交的请求；地址为机器指令坐标，不冒充源码行。
            document.section(QStringLiteral("原生步进回执"))
                .field(QStringLiteral("请求 ID"), QString::fromStdString(step->request.release.requestId))
                .field(QStringLiteral("诊断阶段"), QString::fromLatin1(step->stage))
                .field(QStringLiteral("Win32 错误"), QString::number(step->win32Error))
                .field(QStringLiteral("起始指令地址"), QStringLiteral("0x%1").arg(step->startIp, 0, 16))
                .field(QStringLiteral("已观察指令地址"), step->observedIp
                    ? QStringLiteral("0x%1").arg(*step->observedIp, 0, 16) : sourceText(QStringLiteral("未知")))
                .field(QStringLiteral("步进资源已恢复"), sourceText(step->resourcesRestored ? QStringLiteral("是") : QStringLiteral("否")));
        }
        if (!m_runDefinition.isEmpty())
        {
            document.field(QStringLiteral("断点定义 ID"), m_runDefinition); // 保存本轮来源，不受列表选区影响。
        }
        if (m_result.breakpoint && !m_result.breakpoint->executionRanges.empty())
        {
            document.section(QStringLiteral("已纳入执行范围"));
            for (const auto& range : m_result.breakpoint->executionRanges)
            {
                document.field(QStringLiteral("范围起点 / 字节数 / 分配基址"),
                    QStringLiteral("0x%1 / %2 / 0x%3").arg(range.base, 0, 16).arg(range.bytes)
                        .arg(range.allocationBase, 0, 16));
            }
        }
        if (const auto& added = m_result.executionRange)
        {
            document.section(QStringLiteral("执行范围纳入回执"))
                .field(QStringLiteral("请求 ID"), QString::fromStdString(added->request.stop.requestId))
                .field(QStringLiteral("新范围起点"), QStringLiteral("0x%1").arg(added->request.address, 0, 16))
                .field(QStringLiteral("范围字节数"), QString::number(added->request.bytes))
                .field(QStringLiteral("范围已纳入"), added->added ? QStringLiteral("是") : QStringLiteral("否"), true)
                .field(QStringLiteral("新增范围回滚完整"), added->rollbackComplete ? QStringLiteral("是") : QStringLiteral("否"), true)
                .field(QStringLiteral("诊断阶段"), QString::fromLatin1(added->stage))
                .field(QStringLiteral("Win32 错误"), QString::number(added->win32Error));
        }
        ProcessGroupMemoryPane::Append(document, m_memoryShown);
        if (m_apiShown)
        {
            NativeSessionApiPane::AppendFields(document, *m_apiShown); // 搜索、复制和导出使用同一份规范文档。
        }
        if (const auto observed = native::NativeExecutionFromOwnedStop(m_result))
        {
            document.section(QStringLiteral("当前执行观测"))
                .field(QStringLiteral("执行观测类型"), observed->kind == native::NativeExecutionKind::InstructionCompleted
                    ? QStringLiteral("单指令已完成") : QStringLiteral("执行入口尝试"), true)
                .field(QStringLiteral("指令地址"), QStringLiteral("0x%1").arg(observed->instructionAddress, 0, 16))
                .field(QStringLiteral("原生事件序号"), QString::number(observed->event.serial));
        }
        if (m_executionShown.receipt || !m_executionShown.result)
        {
            document.section(QStringLiteral("执行观测归档回执"))
                .field(QStringLiteral("项目结果"), QString::fromLatin1(m_executionShown.result.detail))
                .field(QStringLiteral("Win32 错误"), QString::number(m_executionShown.result.nativeError))
                .field(QStringLiteral("同事件原坐标"), m_executionShown.duplicate ? QStringLiteral("是") : QStringLiteral("否"), true)
                .field(QStringLiteral("执行流停止追加"), m_executionShown.blocked ? QStringLiteral("是") : QStringLiteral("否"), true);
            if (m_executionShown.duplicate && m_executionShown.blockedFailure)
            {
                const auto& failure = *m_executionShown.blockedFailure; // 原成功坐标与后续坏尾原因同时可查。
                document.field(QStringLiteral("首次执行流阻断"), QString::fromLatin1(failure.result.detail))
                    .field(QStringLiteral("Win32 错误"), QString::number(failure.result.nativeError));
                if (failure.receipt)
                {
                    document.field(QStringLiteral("阻断段号"), QString::number(failure.receipt->ordinal));
                    for (const auto* boundary : {&failure.receipt->raw.written, &failure.receipt->raw.flushed})
                    {
                        document.field(boundary == &failure.receipt->raw.written
                                ? QStringLiteral("阻断写入坐标") : QStringLiteral("阻断刷盘坐标"),
                            *boundary ? QStringLiteral("%1 / %2 / %3").arg((*boundary)->byteOffset)
                                .arg((*boundary)->blockOrdinal).arg((*boundary)->lastSequence) : QStringLiteral("未取得"));
                    }
                }
            }
            if (const auto& observed = m_executionShown.observation)
            {
                document.field(QStringLiteral("后端实例 ID"), QString::fromStdString(observed->event.backendInstanceId))
                    .field(QStringLiteral("原生事件序号"), QString::number(observed->event.serial))
                    .field(QStringLiteral("PID"), QString::number(observed->pid))
                    .field(QStringLiteral("创建 FILETIME"), QString::number(observed->processCreationFileTime))
                    .field(QStringLiteral("线程 TID"), QString::number(observed->thread.tid))
                    .field(QStringLiteral("线程创建 FILETIME"), QString::number(observed->thread.creationTime));
            }
            if (const auto& saved = m_executionShown.receipt)
            {
                document.field(QStringLiteral("raw-native 段号"), QString::number(saved->ordinal))
                    .field(QStringLiteral("同步回读核验"), saved->verified ? QStringLiteral("是") : QStringLiteral("否"), true)
                    .field(QStringLiteral("SHA-256"), QString::fromStdString(saved->sha256));
                for (const auto* boundary : {&saved->raw.written, &saved->raw.flushed})
                {
                    document.field(boundary == &saved->raw.written ? QStringLiteral("执行观测写入坐标") : QStringLiteral("执行观测刷盘坐标"),
                        *boundary ? QStringLiteral("%1 / %2 / %3").arg((*boundary)->byteOffset)
                            .arg((*boundary)->blockOrdinal).arg((*boundary)->lastSequence) : QStringLiteral("未取得"));
                }
            }
        }
        m_fields->setDocument(document);
    }

    void DataWriteWatchPage::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event->type() == QEvent::LanguageChange && m_work)
        {
            refresh();
        }
    }
}

QWidget* CreateDataWriteWatchPage(QWidget* parent, std::shared_ptr<DataWatchToolbarPort> toolbar)
{
    return new DataWriteWatchPage(parent, std::move(toolbar));
}
}
