#include "../Framework.h"
#include "ProcessGroupPage.h"
#include "ProcessGroupSession.h"
#include "ProcessGroupMemoryPane.h"
#include "../Framework/BackgroundTaskRegistry.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/FlowLayout.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/ResultTableHost.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/TablePresentation.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ToolbarMetrics.h"

#include <QAbstractTableModel>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QEvent>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QPointer>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>
#include <algorithm>

namespace ks::action_analyze
{
namespace
{
    namespace native = process_group_native;
    using ks::i18n::sourceText;

    // 从真实组汇总选择可翻译状态，不从首行、按钮或历史票据推断全组。
    QString GroupState(native::ProcessGroupState state)
    {
        switch (state)
        {
        case native::ProcessGroupState::Idle: return sourceText(QStringLiteral("尚未配置集合"));
        case native::ProcessGroupState::Ready: return sourceText(QStringLiteral("集合已核验，尚未暂停"));
        case native::ProcessGroupState::Active: return sourceText(QStringLiteral("正在等待成员回执"));
        case native::ProcessGroupState::HeldPartial: return sourceText(QStringLiteral("部分成员持有停点"));
        case native::ProcessGroupState::HeldComplete: return sourceText(QStringLiteral("全部成员持有停点"));
        case native::ProcessGroupState::Closing: return sourceText(QStringLiteral("正在清退原集合"));
        case native::ProcessGroupState::Closed: return sourceText(QStringLiteral("原集合已清退"));
        case native::ProcessGroupState::RecoveryRequired: return sourceText(QStringLiteral("原集合仍有恢复责任"));
        }
        return {};
    }

    // 成员状态直接来自该行NativeControlResult，未暂停成员与失败分别显示。
    QString MemberState(const native::ProcessGroupMember& member)
    {
        if (!member.control)
        {
            return sourceText(QStringLiteral("尚未暂停"));
        }
        switch (member.control->status)
        {
        case native::NativeControlStatus::Idle: return sourceText(QStringLiteral("空闲"));
        case native::NativeControlStatus::Accepted: return sourceText(QStringLiteral("已受理，等待停点"));
        case native::NativeControlStatus::Held: return sourceText(QStringLiteral("持有原生停点"));
        case native::NativeControlStatus::Released: return sourceText(QStringLiteral("已继续，等待脱离"));
        case native::NativeControlStatus::Detached: return sourceText(QStringLiteral("已脱离"));
        case native::NativeControlStatus::Ended: return sourceText(QStringLiteral("目标已退出"));
        case native::NativeControlStatus::ClosePending: return sourceText(QStringLiteral("清退未完成"));
        case native::NativeControlStatus::Closed: return sourceText(QStringLiteral("已清退"));
        case native::NativeControlStatus::Rejected: return sourceText(QStringLiteral("操作被拒绝"));
        case native::NativeControlStatus::RecoveryRequired: return sourceText(QStringLiteral("恢复未确认"));
        }
        return {};
    }

    // 只有首次准入且真实执行过成员的票据才有恢复/成功语义；拒绝票据没有outcomes。
    bool AppliedOperation(const native::ProcessGroupOperation& operation)
    {
        return operation.ledgerResult == native::LedgerResult::Applied && !operation.outcomes.empty();
    }

    // 展示原生首次准入结论，重放的顶层Duplicate不能冒充首次成功。
    void AppendOperationFields(ks::ui::FieldDocument& document, const native::ProcessGroupOperation& operation)
    {
        document.field(QStringLiteral("账本结果码"), QString::number(static_cast<int>(operation.ledgerResult)))
            .field(QStringLiteral("原生诊断"), QString::fromLatin1(operation.stage))
            .field(QStringLiteral("Win32 错误"), QString::number(operation.win32Error));
        if (!AppliedOperation(operation))
        {
            document.field(QStringLiteral("执行范围"), QStringLiteral("拒绝票据未执行成员"), true);
        }
    }

    // 紧凑六列管理表：路径、完整事件和线程诊断放入同一规范字段详情。
    class MemberModel final : public QAbstractTableModel
    {
    public:
        using QAbstractTableModel::QAbstractTableModel;
        std::vector<native::ProcessGroupTarget> targets; // 当前显示目录，不随输入框编辑变化。
        native::ProcessGroupResult result; // 最后一次真实回读，空时目录仍属于草稿。

        int rowCount(const QModelIndex& parent = {}) const override
        {
            return parent.isValid() ? 0 : static_cast<int>(targets.size());
        }
        int columnCount(const QModelIndex& parent = {}) const override
        {
            return parent.isValid() ? 0 : 6;
        }
        QVariant data(const QModelIndex& index, int role) const override
        {
            if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() ||
                (role != Qt::DisplayRole && role != Qt::ToolTipRole))
            {
                return {};
            }
            const auto& target = targets.at(index.row()); // 行身份只使用PID和创建时间。
            const auto found = std::find_if(result.members.begin(), result.members.end(), [&](const auto& member) {
                return member.target == target;
            });
            if (index.column() == 0) return target.pid;
            if (index.column() == 1) return QString::number(target.creationFileTime);
            if (found == result.members.end())
            {
                return index.column() == 2 ? sourceText(QStringLiteral("草稿，尚未核验")) : QString();
            }
            if (index.column() == 2) return MemberState(*found);
            if (index.column() == 3) return found->stop ? QString::fromStdString(found->stop->stopId) : QString();
            if (index.column() == 4) return sourceText(found->clean ? QStringLiteral("是") : QStringLiteral("否"));
            if (index.column() == 5 && found->control)
            {
                return QStringLiteral("%1 / Win32 %2").arg(QString::fromLatin1(found->control->stage)).arg(found->control->win32Error);
            }
            return {};
        }
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override
        {
            if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
            const QStringList titles{QStringLiteral("PID"), QStringLiteral("创建 FILETIME"), QStringLiteral("成员状态"),
                QStringLiteral("停点 ID"), QStringLiteral("清退确认"), QStringLiteral("原生诊断")};
            return section >= 0 && section < titles.size() ? sourceText(titles.at(section)) : QVariant();
        }
        // 增删仅用于未配置草稿；发布新目录时由模型重置，调用方恢复选择。
        void Replace(std::vector<native::ProcessGroupTarget> rows)
        {
            beginResetModel();
            targets = std::move(rows);
            result = {};
            endResetModel();
        }
        // 固定成员目录只更新值，避免周期查询重置模型和丢失多选。
        void Apply(const native::ProcessGroupResult& snapshot)
        {
            result = snapshot;
            if (!targets.empty()) emit dataChanged(index(0, 0), index(rowCount() - 1, 5));
        }
    };

    class ProcessGroupPage final : public QWidget
    {
    public:
        explicit ProcessGroupPage(QWidget* parent, std::shared_ptr<ProcessGroupToolbarPort> toolbar);
        ~ProcessGroupPage() override;
    private:
        void AddTarget(); // 校验两个十进制草稿字段，显式加入，尚不暂停或附加。
        void Configure(); // 冻结当前目录和显式授权，异步核对整个集合。
        void Control(ProcessGroupCommand command, bool selected); // 点击时复制真实子集与全部令牌。
        void Poll(); // 只复制本端后台的已公布值，不在UI查询进程。
        void Render(); // 状态与资格统一来自最后回执。
        void Detail(); // 选中成员和历史票据投影到单一可复制字段文档。
        void changeEvent(QEvent* event) override; // 语言改变时保留草稿、选择和票据。
        std::vector<native::ProcessGroupTarget> Selected(bool selected) const; // 按冻结行身份收集操作范围。

        MemberModel* m_model = nullptr; // 六列只读管理模型。
        ks::ui::TableActionTableView* m_members = nullptr; // 当前草稿或冻结集合，多选按行。
        ks::ui::StructuredFieldView* m_fields = nullptr; // 成员、来源和票据唯一详情文档。
        QLabel* m_hint = nullptr; // 说明本会话范围和Configure语义。
        QLabel* m_status = nullptr; // 回读时间、真实状态与组层错误。
        QLabel* m_pidLabel = nullptr; // PID输入标签。
        QLabel* m_creationLabel = nullptr; // FILETIME输入标签。
        QLineEdit* m_pid = nullptr; // 下一项PID草稿。
        QLineEdit* m_creation = nullptr; // 下一项原始创建FILETIME草稿。
        QCheckBox* m_authorized = nullptr; // 用户对本次显式集合的授权。
        QPushButton* m_add = nullptr; // 显式加入草稿。
        QPushButton* m_remove = nullptr; // 只删除未配置草稿选中行。
        QPushButton* m_configure = nullptr; // 冻结并核对，不暂停。
        QPushButton* m_newDraft = nullptr; // 仅确认clean后显式开始下一集合草稿。
        QPushButton* m_pauseAll = nullptr; // 请求所有已冻结成员暂停。
        QPushButton* m_pauseSelected = nullptr; // 请求全部选中成员暂停。
        QPushButton* m_continueAll = nullptr; // 请求全部成员的完整停止令牌继续。
        QPushButton* m_continueSelected = nullptr; // 请求全部选中成员的完整停止令牌继续。
        QPushButton* m_query = nullptr; // 手工请求真实回读。
        QPushButton* m_recover = nullptr; // 原继续票据的恢复入口。
        QPushButton* m_close = nullptr; // 原所有者清退与未决重试。
        QComboBox* m_history = nullptr; // 选择同一会话的原操作票据，不改变当前成员状态。
        QTimer* m_poll = nullptr; // 展示已有后台快照，不创建原生操作。
        ProcessGroupMemoryPane* m_memory = nullptr; // 显式范围草稿，原group执行读取和独立lane保存。
        std::unique_ptr<ProcessGroupSession> m_session; // 当前端独立会话，未clean前不替换。
        ProcessGroupSessionSnapshot m_shown; // UI最后实际显示的完整回执。
        QString m_inputError; // 草稿/入队错误与真实回执分开。
        std::string m_sessionId; // 该端本轮owner身份，旧票据不跨owner继续。
        std::uint64_t m_nextRequest = 0; // 同一group的严格单调group/N。
        bool m_registered = false; // 原生常驻所有者管理登记结果。
        std::shared_ptr<ProcessGroupToolbarPort> m_toolbar; // 总览只转交本页已有动作。
    };

    // 文字动作表达全组/选中范围；简单刷新使用主题图标，所有动作均提供tooltip。
    QPushButton* Action(QWidget* parent, const char* id, const QString& text, const QString& hint)
    {
        auto* button = new QPushButton(sourceText(text), parent); // 默认几何和状态由标准主题拥有。
        button->setObjectName(QString::fromLatin1(id));
        ks::i18n::LanguageManager::instance().bindText(button, {}, text);
        ks::i18n::LanguageManager::instance().bindToolTip(button, {}, hint);
        return button;
    }

    ProcessGroupPage::ProcessGroupPage(QWidget* parent, std::shared_ptr<ProcessGroupToolbarPort> toolbar)
        : QWidget(parent), m_toolbar(std::move(toolbar))
    {
        auto* root = new QVBoxLayout(this); // 外层工作台负责页根留白。
        root->setContentsMargins(0, 0, 0, 0);
        auto* workspace = new ks::ui::ParameterWorkspace(this, 340); // 参数滚动，结果占主要空间。
        root->addWidget(workspace);
        m_hint = new QLabel(sourceText(QStringLiteral("仅控制本会话显式选择的最多 16 个进程实例。配置只核对身份；暂停与继续需另行执行。")), workspace);
        m_hint->setWordWrap(true);
        workspace->parameters()->addWidget(m_hint);

        auto* target = new QGroupBox(sourceText(QStringLiteral("目标草稿")), workspace); // 自然高度的身份输入。
        auto* form = new QFormLayout(target); // 窄窗标签折行，不扩大输入至全屏。
        ks::ui::StyleSecondaryForm(form, 100);
        m_pid = new QLineEdit(target);
        m_creation = new QLineEdit(target);
        m_pid->setMaxLength(10);
        m_creation->setMaxLength(20);
        m_pid->setObjectName(QStringLiteral("action_analyze_group_pid"));
        m_creation->setObjectName(QStringLiteral("action_analyze_group_creation"));
        m_pidLabel = new QLabel(sourceText(QStringLiteral("PID")), target);
        m_creationLabel = new QLabel(sourceText(QStringLiteral("创建 FILETIME")), target);
        m_pidLabel->setBuddy(m_pid);
        m_creationLabel->setBuddy(m_creation);
        form->addRow(m_pidLabel, m_pid);
        form->addRow(m_creationLabel, m_creation);
        ks::ui::StyleParameterSection(target);
        workspace->parameters()->addWidget(target);
        m_authorized = new QCheckBox(sourceText(QStringLiteral("我明确授权控制列表中的全部进程实例")), workspace);
        workspace->parameters()->addWidget(m_authorized);

        auto* draft = new QWidget(workspace); // 加入和移除只修改未配置目录。
        auto* draftFlow = new ks::ui::FlowLayout(draft, 0, 8, 8);
        m_add = Action(draft, "action_analyze_group_add", QStringLiteral("加入目标"), QStringLiteral("将 PID 和创建 FILETIME 加入草稿，不附加或暂停目标。"));
        m_remove = Action(draft, "action_analyze_group_remove", QStringLiteral("移除选中目标"), QStringLiteral("只移除尚未配置的草稿成员。"));
        draftFlow->addWidget(m_add);
        draftFlow->addWidget(m_remove);
        ks::ui::NormalizeToolbarLayout(draftFlow);
        workspace->parameters()->addWidget(draft);
        m_memory = new ProcessGroupMemoryPane(workspace); // 参数滚动正文承载范围，不挤占成员列表。
        workspace->parameters()->addWidget(m_memory);
        m_memory->execute = [this](bool save) {
            if (!m_session || m_shown.busy || m_shown.closing) return;
            ProcessGroupRequest request; // 精确冻结当前唯一成员或已显示的内存结果。
            if (save)
            {
                request.command = ProcessGroupCommand::SaveMemory;
                request.memoryToSave = m_shown.memory;
            }
            else
            {
                const auto selected = Selected(true);
                if (selected.size() != 1 || !m_memory->Prepare(m_shown, selected.front(), request)) return;
            }
            m_inputError = m_session->Submit(std::move(request)) ? QString() : sourceText(QStringLiteral("本端会话未受理操作，请刷新后重试。"));
            Poll();
        };
        m_configure = Action(workspace, "action_analyze_group_configure", QStringLiteral("冻结并配置集合"), QStringLiteral("异步回读并核对全部 PID、创建时间和映像来源；此操作不会暂停。"));
        workspace->actions()->addWidget(m_configure);
        m_newDraft = Action(workspace, "action_analyze_group_new", QStringLiteral("新集合"), QStringLiteral("原集合确认清退后，显式清空旧目录与票据并开始下一集合草稿。"));
        workspace->actions()->addWidget(m_newDraft);
        ks::ui::ApplyFlatButtonTheme(m_configure, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);

        auto* controls = new QWidget(workspace); // 每个批量动作明确全组或选中范围。
        auto* flow = new ks::ui::FlowLayout(controls, 0, 8, 8);
        m_memory->MoveExecutionActions(flow); // 范围参数独立滚动，执行动作固定在共享工具区。
        m_pauseAll = Action(controls, "action_analyze_group_pause_all", QStringLiteral("暂停全部成员"), QStringLiteral("依次请求本集合全部成员暂停，逐项检查真实回执。"));
        m_pauseSelected = Action(controls, "action_analyze_group_pause_selected", QStringLiteral("暂停选中成员"), QStringLiteral("仅请求点击时所有选中的冻结实例暂停。"));
        m_continueAll = Action(controls, "action_analyze_group_continue_all", QStringLiteral("继续全部成员"), QStringLiteral("只有全部成员都有当前精确停止令牌时，才提交整组继续。"));
        m_continueSelected = Action(controls, "action_analyze_group_continue_selected", QStringLiteral("继续选中成员"), QStringLiteral("复制所有选中成员的完整停止令牌，任一缺失则不提交。"));
        m_query = Action(controls, "action_analyze_group_query", {}, QStringLiteral("重新回读原集合的每个成员状态。"));
        m_query->setAccessibleName(sourceText(QStringLiteral("刷新状态")));
        KswordTheme::ApplyStandardIconButtonMetrics(m_query);
        ks::ui::SetThemeButtonIcon(m_query, QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
        m_close = Action(controls, "action_analyze_group_close", QStringLiteral("关闭并清退集合"), QStringLiteral("由原所有者恢复并脱离；未确认清退时保留该会话。"));
        for (auto* button : {m_pauseAll, m_pauseSelected, m_continueAll, m_continueSelected, m_query, m_close})
        {
            flow->addWidget(button);
        }
        ks::ui::NormalizeToolbarLayout(flow);
        workspace->results()->addWidget(controls);
        m_status = new QLabel(workspace); // 分别显示草稿错误和最后真实状态来源。
        m_status->setWordWrap(true);
        m_status->setTextFormat(Qt::PlainText);
        workspace->results()->addWidget(m_status);

        auto* splitter = new QSplitter(Qt::Vertical, workspace); // 成员列表优先，字段详情可调高度。
        m_members = new ks::ui::TableActionTableView(splitter);
        m_model = new MemberModel(m_members);
        m_members->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_members->setSelectionMode(QAbstractItemView::ExtendedSelection);
        m_members->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_members->verticalHeader()->hide();
        ks::ui::ResultTableCapabilities capabilities; // 管理表不重复显示复制/快照操作条。
        capabilities.actionBar = ks::ui::TableActionBarMode::None;
        capabilities.headerClickSorting = false;
        ks::ui::ResultTableHost::ensure(m_members)->bindModel(m_model, {{0, QStringLiteral("pid")},
            {1, QStringLiteral("creation")}, {2, QStringLiteral("state")}, {3, QStringLiteral("stop")},
            {4, QStringLiteral("clean")}, {5, QStringLiteral("diagnostic")}}, capabilities);
        ks::ui::ApplyTablePresentation(m_members);
        m_fields = new ks::ui::StructuredFieldView(splitter);
        m_fields->setValueModelProjection();
        m_fields->setHiddenProjectionDeferred();
        splitter->addWidget(m_members);
        splitter->addWidget(m_fields);
        splitter->setStretchFactor(0, 3);
        splitter->setStretchFactor(1, 2);
        workspace->results()->addWidget(splitter, 1);

        auto* tickets = new QWidget(workspace); // 原票据选择与恢复自然换行，历史选择无副作用。
        auto* ticketFlow = new ks::ui::FlowLayout(tickets, 0, 8, 8);
        m_history = new QComboBox(tickets);
        m_history->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
        m_history->setMinimumContentsLength(18);
        m_history->setAccessibleName(sourceText(QStringLiteral("历史操作票据")));
        m_recover = Action(tickets, "action_analyze_group_recover", QStringLiteral("恢复原继续票据"), QStringLiteral("使用选中的原继续请求 ID 调用原所有者恢复，不生成新继续责任。"));
        ticketFlow->addWidget(m_history);
        ticketFlow->addWidget(m_recover);
        ks::ui::NormalizeToolbarLayout(ticketFlow);
        workspace->results()->addWidget(tickets);
        workspace->finish();

        connect(m_add, &QPushButton::clicked, this, [this] { AddTarget(); });
        connect(m_remove, &QPushButton::clicked, this, [this] {
            if (m_session) return;
            const auto selected = Selected(true); // 删除草稿只作用于点击时的精确行身份。
            auto targets = m_model->targets;
            std::erase_if(targets, [&](const auto& item) { return std::find(selected.begin(), selected.end(), item) != selected.end(); });
            m_model->Replace(std::move(targets));
            Render();
        });
        connect(m_configure, &QPushButton::clicked, this, [this] { Configure(); });
        connect(m_newDraft, &QPushButton::clicked, this, [this] {
            if (!m_newDraft->isEnabled()) return;
            m_session.reset(); // 只允许Closed且clean的旧owner结束后重建。
            m_shown = {};
            m_sessionId.clear();
            m_history->clear();
            m_model->Replace({});
            m_inputError.clear();
            Render();
            Detail();
        });
        connect(m_pauseAll, &QPushButton::clicked, this, [this] { Control(ProcessGroupCommand::Pause, false); });
        connect(m_pauseSelected, &QPushButton::clicked, this, [this] { Control(ProcessGroupCommand::Pause, true); });
        connect(m_continueAll, &QPushButton::clicked, this, [this] { Control(ProcessGroupCommand::Continue, false); });
        connect(m_continueSelected, &QPushButton::clicked, this, [this] { Control(ProcessGroupCommand::Continue, true); });
        connect(m_query, &QPushButton::clicked, this, [this] { Control(ProcessGroupCommand::Query, false); });
        connect(m_recover, &QPushButton::clicked, this, [this] { Control(ProcessGroupCommand::Recover, false); });
        connect(m_close, &QPushButton::clicked, this, [this] { if (m_session) m_session->Close(); Poll(); });
        connect(m_authorized, &QCheckBox::toggled, this, [this] { Render(); });
        connect(m_history, &QComboBox::currentIndexChanged, this, [this] { Render(); Detail(); });
        connect(m_members->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this] { Render(); Detail(); });
        m_poll = new QTimer(this);
        m_poll->setInterval(200);
        connect(m_poll, &QTimer::timeout, this, [this] { Poll(); });
        ks::ui::BackgroundTaskRegistry::External external; // 管理器只读取已发布状态，不调用原生查询。
        external.running = [this] { return m_session && m_shown.result.state != native::ProcessGroupState::Closed; };
        m_registered = ks::ui::BackgroundTaskRegistry::instance().addExternal(
            QStringLiteral("monitor.action_analyze.process_group"), sourceText(QStringLiteral("进程集合控制")),
            sourceText(QStringLiteral("监控")), this, std::move(external),
            sourceText(QStringLiteral("在进程集合控制页恢复或清退；恢复责任不能暂停。")));
        if (m_toolbar)
        {
            m_toolbar->execute = [page = QPointer<ProcessGroupPage>(this)](ProcessGroupToolbarAction action)
            {
                if (!page)
                {
                    return;
                }
                // 点击复用原按钮，原Control冻结完整子集/令牌；旧工具条资格不会绕过准入。
                const std::array buttons{page->m_pauseAll, page->m_continueAll, page->m_pauseSelected,
                    page->m_continueSelected, page->m_recover, page->m_close};
                const auto index = static_cast<std::size_t>(action);
                if (index < buttons.size() && buttons[index]->isEnabled())
                {
                    buttons[index]->click();
                }
            };
        }
        Render();
        Detail();
    }

    ProcessGroupPage::~ProcessGroupPage()
    {
        if (m_toolbar)
        {
            m_toolbar->execute = {}; // 解除UI入口不代表原集合已clean，后台继续原清退责任。
            m_toolbar->state = {};
            if (m_toolbar->changed)
            {
                m_toolbar->changed();
            }
        }
        m_poll->stop();
        if (m_session) m_session->Close(); // 后台共享owner继续保活，不能在GUI线程析构未决调试器。
    }

    std::vector<native::ProcessGroupTarget> ProcessGroupPage::Selected(bool selected) const
    {
        if (!selected) return m_model->targets;
        std::vector<native::ProcessGroupTarget> targets; // 完整多选，不使用首行代表全部。
        for (const auto& index : m_members->selectionModel()->selectedRows())
        {
            targets.push_back(m_model->targets.at(index.row()));
        }
        return targets;
    }

    void ProcessGroupPage::AddTarget()
    {
        if (m_session || m_model->targets.size() >= native::kOwnedProcessGroupLimit) return;
        bool pidValid = false, creationValid = false; // 两字段均必须是非零十进制无符号数。
        const auto pid = m_pid->text().trimmed().toUInt(&pidValid, 10);
        const auto creation = m_creation->text().trimmed().toULongLong(&creationValid, 10);
        const native::ProcessGroupTarget target{pid, creation}; // 暂存输入，不作为已核验对象宣称。
        const bool duplicate = std::any_of(m_model->targets.begin(), m_model->targets.end(), [&](const auto& item) { return item.pid == pid; });
        if (!pidValid || !creationValid || !pid || !creation || duplicate)
        {
            m_inputError = sourceText(QStringLiteral("请输入非零十进制 PID 和创建 FILETIME；同一 PID 只能加入一次。"));
        }
        else
        {
            auto targets = m_model->targets; // 显式加入不会改变已经发布的原集合。
            targets.push_back(target);
            m_model->Replace(std::move(targets));
            m_inputError.clear();
        }
        Render();
    }

    void ProcessGroupPage::Configure()
    {
        if (!m_configure->isEnabled()) return;
        m_sessionId = QUuid::createUuid().toString(QUuid::WithoutBraces).toStdString();
        const auto sample = QUuid::createUuid().toString(QUuid::WithoutBraces).toStdString(); // 无项目也必须为账本规范UUID。
        const auto backend = QUuid::createUuid().toString(QUuid::WithoutBraces).toStdString(); // 显示标签不能塞入owner身份。
        m_session = std::make_unique<ProcessGroupSession>(native::OwnerIdentity{
            sample, m_sessionId, m_sessionId, backend});
        ProcessGroupRequest request; // 配置冻结整张目录和此刻授权，不读取之后的输入草稿。
        request.command = ProcessGroupCommand::Configure;
        request.targets = m_model->targets;
        request.authorized = m_authorized->isChecked();
        request.newProjectDirectory = m_memory->ProjectDirectory(); // 新目录与本端唯一采样在配置时固定。
        m_nextRequest = 0;
        m_shown = {};
        m_history->clear();
        m_model->Apply({});
        m_inputError = m_session->Submit(std::move(request)) ? QString() : sourceText(QStringLiteral("本端会话未受理操作，请刷新后重试。"));
        m_poll->start();
        Poll();
    }

    void ProcessGroupPage::Control(ProcessGroupCommand command, bool selected)
    {
        if (!m_session || m_shown.busy) return;
        ProcessGroupRequest request; // 本次操作完整按值冻结，不向后台传模型或控件指针。
        request.command = command;
        request.targets = Selected(selected);
        if (command == ProcessGroupCommand::Recover)
        {
            request.requestId = m_history->currentData().toString().toStdString(); // 原票据恢复不分配新ID。
            if (request.requestId.empty()) return;
        }
        else if (command == ProcessGroupCommand::Pause || command == ProcessGroupCommand::Continue)
        {
            if (request.targets.empty()) return;
            request.requestId = "group/" + std::to_string(++m_nextRequest);
        }
        if (command == ProcessGroupCommand::Continue)
        {
            for (const auto& target : request.targets)
            {
                const auto found = std::find_if(m_shown.result.members.begin(), m_shown.result.members.end(), [&](const auto& member) { return member.target == target; });
                if (found == m_shown.result.members.end() || !found->stop) return; // 全部所选都有精确令牌才提交。
                request.stops.push_back(*found->stop); // 包括backend、event、group、stop和修订。
            }
        }
        m_inputError = m_session->Submit(std::move(request)) ? QString() : sourceText(QStringLiteral("本端会话未受理操作，请刷新后重试。"));
        Poll();
    }

    void ProcessGroupPage::Poll()
    {
        if (!m_session) return;
        const auto snapshot = m_session->Read(); // 只有值复制；OpenProcess和Query在后台。
        const bool changed = snapshot.revision != m_shown.revision;
        m_shown = snapshot;
        if (changed)
        {
            m_model->Apply(snapshot.result);
            const auto oldTicket = m_history->currentData().toString(); // 保留用户当前选择的原票据。
            const QSignalBlocker block(m_history); // 目录更新不产生控制请求或临时详情闪烁。
            m_history->clear();
            for (const auto& operation : snapshot.history)
            {
                const auto id = QString::fromStdString(operation.requestId); // 同一group共享命名空间。
                m_history->addItem(id, id);
            }
            const int previous = m_history->findData(oldTicket);
            m_history->setCurrentIndex(previous >= 0 ? previous : m_history->count() - 1);
            Detail();
        }
        Render();
        if (snapshot.retired) m_poll->stop();
    }

    void ProcessGroupPage::Render()
    {
        const bool ended = m_session && m_shown.retired;
        const bool editable = !m_session; // Close后保持旧成员身份，显式新配置才建立新owner。
        const bool ready = m_session && !m_shown.busy && !m_shown.closing && !m_shown.result.members.empty();
        const auto selected = Selected(true); // 多选资格按全部行检查。
        const auto canContinue = [&](const auto& targets) {
            return !targets.empty() && std::all_of(targets.begin(), targets.end(), [&](const auto& target) {
                return std::any_of(m_shown.result.members.begin(), m_shown.result.members.end(), [&](const auto& member) { return member.target == target && member.stop.has_value(); });
            });
        };
        m_add->setEnabled(editable && m_model->targets.size() < native::kOwnedProcessGroupLimit);
        m_remove->setEnabled(editable && !selected.empty());
        m_configure->setEnabled(m_registered && editable && !m_model->targets.empty() && m_authorized->isChecked());
        m_newDraft->setEnabled(ended);
        m_pauseAll->setEnabled(ready);
        m_pauseSelected->setEnabled(ready && !selected.empty());
        m_continueAll->setEnabled(ready && canContinue(m_model->targets));
        m_continueSelected->setEnabled(ready && canContinue(selected));
        m_query->setEnabled(m_session && !m_shown.busy && !ended);
        const auto ticket = m_history->currentData().toString().toStdString(); // 恢复仅接纳原Continue票据。
        // 无outcomes的拒绝票据不具备恢复资格，不能当作已成功的原继续票据。
        const bool continueTicket = std::any_of(m_shown.history.begin(), m_shown.history.end(), [&](const auto& operation) {
            return operation.requestId == ticket && operation.action == native::ProcessGroupAction::Continue && AppliedOperation(operation);
        });
        m_recover->setEnabled(m_session && !m_shown.busy && continueTicket && !ended);
        m_close->setEnabled(m_session && !ended);
        if (m_toolbar)
        {
            ProcessGroupToolbarState state; // 只有原页已有值参与投影，不调用Query或枚举进程。
            const auto describe = [](const auto& targets)
            {
                QStringList values; // 最大16个冻结成员的精确身份，便于用户确认工具条范围。
                for (const auto& target : targets)
                {
                    values.append(QStringLiteral("PID %1 / FILETIME %2").arg(target.pid).arg(target.creationFileTime));
                }
                return values.join(QLatin1Char('\n'));
            };
            if (m_session)
            {
                state.target = QString::fromStdString(m_shown.sampleId) + QLatin1Char('\n') + describe(m_model->targets);
            }
            state.selected = describe(selected);
            const std::array buttons{m_pauseAll, m_continueAll, m_pauseSelected, m_continueSelected, m_recover, m_close};
            for (std::size_t index = 0; index < buttons.size(); ++index)
            {
                state.enabled[index] = buttons[index]->isEnabled();
            }
            if (state != m_toolbar->state)
            {
                m_toolbar->state = std::move(state);
                if (m_toolbar->changed)
                {
                    m_toolbar->changed();
                }
            }
        }
        const bool memoryHeld = selected.size() == 1 && std::any_of(m_shown.result.members.begin(),
            m_shown.result.members.end(), [&](const auto& member) {
                return member.target == selected.front() && member.stop && member.control && member.control->group &&
                    member.control->group->state == native::GroupState::HeldComplete;
            }); // 只按当前完整回执开放读入口，范围草稿仍可独立编辑。
        m_memory->Update(m_shown, memoryHeld, m_session != nullptr);
        QString status = GroupState(m_shown.result.state); // 真实汇总与错误、来源同时显示。
        if (m_shown.observedFileTime)
        {
            status += sourceText(QStringLiteral(" · 回读 FILETIME %1 · %2 · Win32 %3"))
                .arg(m_shown.observedFileTime).arg(QString::fromLatin1(m_shown.result.stage)).arg(m_shown.result.win32Error);
        }
        if (m_shown.busy) status += sourceText(QStringLiteral(" · 操作进行中"));
        if (m_shown.closing && !ended) status += sourceText(QStringLiteral(" · 原所有者清退未确认，保留恢复责任"));
        if (m_shown.failed) status += sourceText(QStringLiteral(" · 后台执行失败，保留上次回执"));
        if (!m_shown.workerDiagnostic.empty())
        {
            status += QStringLiteral(" / ") + QString::fromStdString(m_shown.workerDiagnostic);
        }
        if (m_shown.lastCommandResult && m_shown.lastCommandResult->operation)
        {
            // 状态显示原票据三字段；顶层Duplicate只是重放结论，不是首次成功。
            const auto& operation = *m_shown.lastCommandResult->operation;
            status += sourceText(QStringLiteral(" · 上次操作 %1 · 账本 %2 · Win32 %3"))
                .arg(QString::fromLatin1(operation.stage))
                .arg(static_cast<int>(operation.ledgerResult))
                .arg(operation.win32Error);
            if (m_shown.lastCommandResult->ledgerResult == native::LedgerResult::Duplicate)
            {
                status += sourceText(QStringLiteral(" · 原票据重放，非首次执行"));
            }
            if (!AppliedOperation(operation))
            {
                status += sourceText(QStringLiteral(" · 拒绝票据未执行成员"));
            }
        }
        else if (m_shown.lastCommandResult && m_shown.lastCommandResult->win32Error)
        {
            status += sourceText(QStringLiteral(" · 上次操作 %1 / Win32 %2"))
                .arg(QString::fromLatin1(m_shown.lastCommandResult->stage)).arg(m_shown.lastCommandResult->win32Error);
        }
        if (!m_registered) status += sourceText(QStringLiteral(" · 后台所有者登记冲突"));
        if (!m_inputError.isEmpty()) status += QStringLiteral("\n") + m_inputError;
        m_status->setText(status);
        ks::ui::ApplyStatusRole(m_status, m_shown.failed || m_shown.result.win32Error ? ks::ui::StatusRole::Error : ks::ui::StatusRole::Info);
    }

    // 字段文档包含原成员回执和历史票据；复制/导出不从可见列反向拼装。
    void ProcessGroupPage::Detail()
    {
        ks::ui::FieldDocument document; // 唯一字段源随当前选择更新，不改控制快照。
        document.title = QStringLiteral("进程集合控制");
        document.section(QStringLiteral("集合身份"))
            .field(QStringLiteral("会话 ID"), QString::fromStdString(m_sessionId))
            .field(QStringLiteral("成员数量"), QString::number(m_model->targets.size()))
            .field(QStringLiteral("回读 FILETIME"), QString::number(m_shown.observedFileTime))
            .field(QStringLiteral("原生诊断"), QString::fromLatin1(m_shown.result.stage));
        if (!m_shown.workerDiagnostic.empty())
        {
            document.field(QStringLiteral("后台异常摘要"), QString::fromStdString(m_shown.workerDiagnostic));
        }
        if (m_shown.lastCommandResult)
        {
            const auto& last = *m_shown.lastCommandResult;
            document.section(QStringLiteral("最近显式操作回执"));
            if (last.operation)
            {
                // 原票据三字段保持首次准入结论；成员control回执仍在各自行内。
                document.field(QStringLiteral("请求 ID"), QString::fromStdString(last.operation->requestId))
                    .field(QStringLiteral("操作类型"), QString::number(static_cast<int>(last.operation->action)));
                AppendOperationFields(document, *last.operation);
                if (last.ledgerResult == native::LedgerResult::Duplicate)
                {
                    document.field(QStringLiteral("回读性质"), QStringLiteral("原票据重放，非首次执行"), true);
                }
            }
            else
            {
                document.field(QStringLiteral("原生诊断"), QString::fromLatin1(last.stage))
                    .field(QStringLiteral("Win32 错误"), QString::number(last.win32Error))
                    .field(QStringLiteral("账本结果码"), QString::number(static_cast<int>(last.ledgerResult)));
            }
        }
        for (const auto& target : Selected(true))
        {
            document.section(QStringLiteral("成员 %1").arg(target.pid))
                .field(QStringLiteral("PID"), QString::number(target.pid))
                .field(QStringLiteral("创建 FILETIME"), QString::number(target.creationFileTime));
            for (const auto& identity : m_shown.identities)
            {
                if (identity.target == target)
                {
                    document.field(QStringLiteral("映像路径"), QString::fromStdWString(identity.imagePath))
                        .field(QStringLiteral("身份回读 Win32"), QString::number(identity.error))
                        .field(QStringLiteral("来源"), QStringLiteral("本端进程句柄身份回读"), true);
                }
            }
            for (const auto& member : m_shown.result.members)
            {
                if (member.target != target) continue;
                document.field(QStringLiteral("成员状态"), MemberState(member));
                if (member.stop)
                {
                    document.field(QStringLiteral("停止组 ID"), QString::fromStdString(member.stop->groupId))
                        .field(QStringLiteral("停点 ID"), QString::fromStdString(member.stop->stopId))
                        .field(QStringLiteral("后端实例 ID"), QString::fromStdString(member.stop->event.backendInstanceId))
                        .field(QStringLiteral("原生事件序号"), QString::number(member.stop->event.serial))
                        .field(QStringLiteral("状态修订"), QString::number(member.stop->stateRevision));
                }
                if (member.control)
                {
                    document.field(QStringLiteral("原生诊断"), QString::fromLatin1(member.control->stage))
                        .field(QStringLiteral("Win32 错误"), QString::number(member.control->win32Error))
                        .field(QStringLiteral("冻结线程数"), QString::number(member.control->frozenThreads.size()));
                }
            }
        }
        const auto selectedTicket = m_history->currentData().toString().toStdString(); // 不变的原票据。
        for (const auto& operation : m_shown.history)
        {
            if (operation.requestId != selectedTicket) continue;
            document.section(QStringLiteral("历史操作票据"))
                .field(QStringLiteral("请求 ID"), QString::fromStdString(operation.requestId))
                .field(QStringLiteral("操作类型"), QString::number(static_cast<int>(operation.action)));
            AppendOperationFields(document, operation);
            for (const auto& outcome : operation.outcomes)
            {
                document.field(QStringLiteral("PID"), QString::number(outcome.target.pid))
                    .field(QStringLiteral("创建 FILETIME"), QString::number(outcome.target.creationFileTime))
                    .field(QStringLiteral("原生诊断"), QString::fromLatin1(outcome.control.stage))
                    .field(QStringLiteral("Win32 错误"), QString::number(outcome.control.win32Error));
                if (outcome.control.responsibility)
                {
                    const auto& stop = *outcome.control.responsibility; // 历史定位不授予当前继续资格。
                    document.field(QStringLiteral("停止组 ID"), QString::fromStdString(stop.groupId))
                        .field(QStringLiteral("停点 ID"), QString::fromStdString(stop.stopId))
                        .field(QStringLiteral("后端实例 ID"), QString::fromStdString(stop.event.backendInstanceId))
                        .field(QStringLiteral("原生事件序号"), QString::number(stop.event.serial));
                }
            }
        }
        ProcessGroupMemoryPane::Append(document, m_shown); // 不由当前列表或地址草稿重新解释旧结果。
        m_fields->setDocument(document);
    }

    void ProcessGroupPage::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event->type() == QEvent::LanguageChange && m_model)
        {
            emit m_model->headerDataChanged(Qt::Horizontal, 0, 5);
            Render();
            Detail();
        }
    }
}

    QWidget* CreateProcessGroupPage(QWidget* parent, std::shared_ptr<ProcessGroupToolbarPort> toolbar)
    {
        return new ProcessGroupPage(parent, std::move(toolbar)); // 页面不创建CLI或外部第三方窗口。
    }
}
