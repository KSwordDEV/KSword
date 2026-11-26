#include "../Framework.h"
#include "ExecutionGroupPage.h"
#include "ExecutionGroupFields.h"
#include "ExecutionGroupSiteEditor.h"
#include "PrivateExecutionRangePane.h"
#include "../Framework/BackgroundTaskRegistry.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/FlowLayout.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/ResultTableHost.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/TablePresentation.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QCheckBox>
#include <QEvent>
#include <QGroupBox>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QPushButton>
#include <QSplitter>
#include <QTimer>
#include <QVBoxLayout>

namespace ks::action_analyze
{
    namespace
    {
        // 创建带动态翻译和释义的范围动作；简单刷新单独使用主题图标。
        QPushButton* Action(QWidget* parent, const char* id, const QString& title, const QString& hint)
        {
            auto* button = new QPushButton(parent); // 控件尺寸、底色和交互状态由共享标准主题拥有。
            button->setObjectName(QString::fromLatin1(id));
            auto& language = ks::i18n::LanguageManager::instance();
            language.bindText(button, {}, title);
            language.bindToolTip(button, {}, hint);
            return button;
        }
    }

    // 导航入口：监控→行为分析→执行断点集合；参数执行页＋管理列表，字段详情同源。
    ExecutionGroupPage::ExecutionGroupPage(QWidget* parent) : QWidget(parent)
    {
        auto& language = ks::i18n::LanguageManager::instance(); // 所有固定文案按共享语言机制热更新。
        setObjectName(QStringLiteral("action_analyze_execution_group"));
        auto* root = new QVBoxLayout(this); // 页根留白交给现有工作台，避免父子重复内缩。
        root->setContentsMargins(0, 0, 0, 0);
        auto* workspace = new ks::ui::ParameterWorkspace(this, 380);
        root->addWidget(workspace);
        auto* hint = new QLabel(workspace); // 范围和执行机制说明放在参数滚动正文。
        hint->setWordWrap(true);
        language.bindText(hint, {}, QStringLiteral("为 1–16 个明确进程实例各配置一个执行站点。开始冻结目录和条件；各成员独立命中，逐项回读，不保证同时冻结。"));
        workspace->parameters()->addWidget(hint);
        auto* section = new QGroupBox(workspace); // 自然高度参数分区，长窗口不拉伸字段。
        language.bindText(section, {}, QStringLiteral("执行站点草稿"));
        auto* sectionLayout = new QVBoxLayout(section);
        m_editor = new ExecutionGroupSiteEditor(section);
        sectionLayout->addWidget(m_editor);
        ks::ui::StyleParameterSection(section);
        workspace->parameters()->addWidget(section);

        auto* draft = new QWidget(workspace); // 草稿编辑动作可自然换行，不影响活集合。
        auto* draftFlow = new ks::ui::FlowLayout(draft, 0, 8, 8);
        m_add = Action(draft, "execution_group_add", QStringLiteral("加入执行站点"), QStringLiteral("将完整表单加入草稿；同一 PID 只允许一个站点，不附加目标。"));
        m_replace = Action(draft, "execution_group_replace", QStringLiteral("替换选中草稿"), QStringLiteral("用当前完整表单替换唯一选中的草稿站点，不改变活集合。"));
        m_remove = Action(draft, "execution_group_remove", QStringLiteral("移除选中目标"), QStringLiteral("只移除尚未配置的草稿成员。"));
        for (auto* button : {m_add, m_replace, m_remove})
        {
            draftFlow->addWidget(button);
        }
        ks::ui::NormalizeToolbarLayout(draftFlow);
        workspace->parameters()->addWidget(draft);
        m_authorized = new QCheckBox(workspace); // 授权在Start请求时冻结，不随后续UI变化重配。
        language.bindText(m_authorized, {}, QStringLiteral("我明确授权控制列表中的全部进程实例"));
        workspace->parameters()->addWidget(m_authorized);
        m_rangeTarget = new QLabel(workspace); // 目标随明确单选展示，编辑范围不改变原成员或站点草稿。
        m_rangeTarget->setTextFormat(Qt::PlainText);
        m_rangeTarget->setWordWrap(true);
        workspace->parameters()->addWidget(m_rangeTarget);
        m_rangePane = new PrivateExecutionRangePane(workspace); // 参数正文沿用唯一滚动责任和统一范围输入。
        workspace->parameters()->addWidget(m_rangePane);
        m_rangePane->addRange = [this](std::uint64_t address, std::uint64_t bytes)
        {
            AddRange(address, bytes); // 点击时再冻结显示停点，worker不读取控件或行索引。
        };
        m_start = Action(workspace, "execution_group_start", QStringLiteral("开始执行集合"), QStringLiteral("在原后台线程冻结全部站点并逐成员附加，部分失败仍保留成功成员和恢复责任。"));
        m_newDraft = Action(workspace, "execution_group_new", QStringLiteral("返回站点草稿"), QStringLiteral("仅在原集合确认清退后返回原站点目录；新开始创建新的集合身份。"));
        workspace->actions()->addWidget(m_start);
        workspace->actions()->addWidget(m_newDraft);
        ks::ui::ApplyFlatButtonTheme(m_start, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);

        auto* controls = new QWidget(workspace); // 固定执行区明确每个动作的范围和所属成员。
        auto* flow = new ks::ui::FlowLayout(controls, 0, 8, 8);
        m_pauseAll = Action(controls, "execution_group_pause_all", QStringLiteral("暂停全部成员"), QStringLiteral("核验全部成员的原会话和完整快照；已持有精确停点者保留原停点，只请求运行成员暂停。"));
        m_pauseSelected = Action(controls, "execution_group_pause_selected", QStringLiteral("暂停选中成员"), QStringLiteral("核验全部所选原会话；已持有精确停点者记为 already-held，运行成员由原 owner 暂停。"));
        m_continueAll = Action(controls, "execution_group_continue_all", QStringLiteral("继续全部成员"), QStringLiteral("核验固定全集的原会话和完整快照；只继续精确停点，已运行者记为 already-running，不生成释放回执。"));
        m_continueSelected = Action(controls, "execution_group_continue_selected", QStringLiteral("继续选中成员"), QStringLiteral("核验全部所选原会话；只继续当前精确停点，已运行成员明确跳过，未知或恢复失败时拒绝。"));
        m_into = Action(controls, "execution_group_into", QStringLiteral("步入选中成员"), QStringLiteral("使用唯一选中成员当前完整停点和事件线程提交步入。"));
        m_over = Action(controls, "execution_group_over", QStringLiteral("步过选中成员"), QStringLiteral("使用唯一选中成员当前完整停点提交步过调用。"));
        m_out = Action(controls, "execution_group_out", QStringLiteral("跳出选中成员"), QStringLiteral("使用唯一选中成员当前完整停点提交跳出。"));
        m_cancel = Action(controls, "execution_group_cancel", QStringLiteral("取消选中步进"), QStringLiteral("只取消唯一选中成员显示的原步进请求；旧请求不能中止后来的步进。"));
        m_query = Action(controls, "execution_group_query", {}, QStringLiteral("重新回读原集合的每个成员状态。"));
        m_query->setAccessibleName(ks::i18n::sourceText(QStringLiteral("刷新状态")));
        KswordTheme::ApplyStandardIconButtonMetrics(m_query);
        ks::ui::SetThemeButtonIcon(m_query, QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
        m_close = Action(controls, "execution_group_close", QStringLiteral("关闭并清退集合"), QStringLiteral("由原所有者恢复并脱离；未确认清退时保留该会话。"));
        for (auto* button : {m_pauseAll, m_pauseSelected, m_continueAll, m_continueSelected, m_into, m_over, m_out, m_cancel, m_query, m_close})
        {
            flow->addWidget(button);
        }
        ks::ui::NormalizeToolbarLayout(flow);
        workspace->results()->addWidget(controls);
        m_status = new QLabel(workspace); // 文案纯文本，避免目标诊断被当作HTML。
        m_status->setTextFormat(Qt::PlainText);
        m_status->setWordWrap(true);
        workspace->results()->addWidget(m_status);

        auto* splitter = new QSplitter(Qt::Vertical, workspace); // 成员列表占主要高度，详情可调整。
        m_members = new ks::ui::TableActionTableView(splitter);
        m_model = new ExecutionGroupMemberModel(m_members);
        m_members->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_members->setSelectionMode(QAbstractItemView::ExtendedSelection);
        m_members->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_members->verticalHeader()->hide();
        ks::ui::ResultTableCapabilities capabilities; // 管理表显式None，不叠加快照/复制条。
        capabilities.actionBar = ks::ui::TableActionBarMode::None;
        capabilities.headerClickSorting = false;
        ks::ui::ResultTableHost::ensure(m_members)->bindModel(m_model, {{0, QStringLiteral("instance")},
            {1, QStringLiteral("site")}, {2, QStringLiteral("state")}, {3, QStringLiteral("diagnostic")}}, capabilities);
        ks::ui::ApplyTablePresentation(m_members);
        m_members->setColumnWidth(0, 190);
        m_members->setColumnWidth(1, 220);
        m_members->setColumnWidth(2, 170);
        m_members->setColumnWidth(3, 260);
        m_fields = new ks::ui::StructuredFieldView(splitter); // 字段型内容使用共享字段视图，不堆只读输入。
        m_fields->setValueModelProjection();
        m_fields->setHiddenProjectionDeferred();
        splitter->addWidget(m_members);
        splitter->addWidget(m_fields);
        splitter->setStretchFactor(0, 3);
        splitter->setStretchFactor(1, 2);
        workspace->results()->addWidget(splitter, 1);
        workspace->finish();

        connect(m_add, &QPushButton::clicked, this, [this] { AddSite(false); });
        connect(m_replace, &QPushButton::clicked, this, [this] { AddSite(true); });
        connect(m_remove, &QPushButton::clicked, this, [this] { RemoveSites(); });
        connect(m_start, &QPushButton::clicked, this, [this] { Start(); });
        connect(m_newDraft, &QPushButton::clicked, this, [this]
        {
            if (!m_session || !m_shown.retired)
            {
                return;
            }
            m_session.reset(); // 后台仅在确认clean后才发布retired，旧原生责任不迁移。
            m_shown = {};
            m_model->Apply({}); // 保留原站点目录供显式修改，不自动重新附加。
            m_authorized->setChecked(false);
            m_inputError.clear();
            Render();
            Detail();
        });
        connect(m_pauseAll, &QPushButton::clicked, this, [this] { Submit(ExecutionGroupCommand::Pause, true); });
        connect(m_pauseSelected, &QPushButton::clicked, this, [this] { Submit(ExecutionGroupCommand::Pause); });
        connect(m_continueAll, &QPushButton::clicked, this, [this] { Submit(ExecutionGroupCommand::Continue, true); });
        connect(m_continueSelected, &QPushButton::clicked, this, [this] { Submit(ExecutionGroupCommand::Continue); });
        connect(m_into, &QPushButton::clicked, this, [this] { Submit(ExecutionGroupCommand::Step, false, execution_group_native::NativeStepMode::Into); });
        connect(m_over, &QPushButton::clicked, this, [this] { Submit(ExecutionGroupCommand::Step, false, execution_group_native::NativeStepMode::OverCall); });
        connect(m_out, &QPushButton::clicked, this, [this] { Submit(ExecutionGroupCommand::Step, false, execution_group_native::NativeStepMode::Out); });
        connect(m_cancel, &QPushButton::clicked, this, [this] { Submit(ExecutionGroupCommand::CancelStep); });
        connect(m_query, &QPushButton::clicked, this, [this] { Submit(ExecutionGroupCommand::Query); });
        connect(m_close, &QPushButton::clicked, this, [this]
        {
            if (m_session)
            {
                m_session->Close(); // 关闭可以在显式操作在途时请求，不释放当前worker。
                Poll();
            }
        });
        connect(m_authorized, &QCheckBox::toggled, this, [this] { Render(); });
        connect(m_members->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this] { Render(); Detail(); });
        m_poll = new QTimer(this); // 该定时器只展示已公布值，隐藏页不停止后台条件处理。
        m_poll->setInterval(200);
        connect(m_poll, &QTimer::timeout, this, [this] { Poll(); });
        ks::ui::BackgroundTaskRegistry::External external; // 真实原生会话按稳定ID登记，禁止第二个同页owner。
        external.running = [this] { return m_session && !m_session->Read().retired; };
        m_registered = ks::ui::BackgroundTaskRegistry::instance().addExternal(
            QStringLiteral("monitor.action_analyze.execution_group"), ks::i18n::sourceText(QStringLiteral("执行断点集合")),
            ks::i18n::sourceText(QStringLiteral("监控")), this, std::move(external),
            ks::i18n::sourceText(QStringLiteral("在执行断点集合页继续或清退；条件处理和恢复责任不能暂停。")));
        Render();
        Detail();
    }

    ExecutionGroupPage::~ExecutionGroupPage()
    {
        m_poll->stop(); // 页面投影停止，原worker不依赖QObject和Qt事件循环。
        if (m_session)
        {
            m_session->Close(); // 析构仅请求原清退，AsyncCleanupRegistry保留退出责任。
        }
    }

    void ExecutionGroupPage::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event); // 不在语言事件中重建业务目录或改变完整票据。
        if (event->type() == QEvent::LanguageChange && m_model)
        {
            m_model->Relocalize();
            Render();
            Detail();
        }
    }
}
