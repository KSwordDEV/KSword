#include "../Framework.h"
#include "PassiveApiCapturePane.h"
#include "ApiTransferPresentation.h"
#include "ApiHandoffPresentation.h"

#include "../Framework/BackgroundTaskRegistry.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/PageControlStyle.h"
#include "../UI/SegmentedControl.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ThemedMessageBox.h"
#include "../theme.h"

#include <QEvent>
#include <QFileDialog>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QPointer>
#include <QSpinBox>
#include <QCheckBox>
#include <QComboBox>
#include <QTabBar>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <charconv>

namespace ks::action_analyze
{
using ks::i18n::sourceText;
namespace
{
    // 从输入严格解析完整十进制身份；空值、零或溢出都返回 0。
    template <class UInt>
    UInt Identity(const QLineEdit* input)
    {
        const auto digits = input->text().trimmed().toLatin1(); // 只接受后端使用的 ASCII 数字。
        const auto* end = digits.constData() + digits.size(); // 不接受后缀或部分消费。
        UInt value = 0; // 用字段真实位宽判断溢出。
        const auto parsed = std::from_chars(digits.constData(), end, value);
        return parsed.ec == std::errc{} && parsed.ptr == end ? value : 0;
    }

    // 建立有可见标签的表单行，窄窗按标签和输入各自垂直堆叠。
    QLabel* AddInput(QVBoxLayout* form, QLineEdit* input, const char* name)
    {
        auto* label = new QLabel(form->parentWidget()); // 排列位置固定，不依赖占位字符串。
        label->setWordWrap(true);
        label->setBuddy(input);
        input->setObjectName(QString::fromLatin1(name));
        form->addWidget(label);
        form->addWidget(input);
        return label;
    }

    // 动作用主题 SVG，固定尺寸与现有采集工具保持一致。
    QPushButton* IconButton(QWidget* parent, const char* name, const char* icon)
    {
        auto* button = new QPushButton(parent); // 标准样式处理悬停、焦点与禁用状态。
        button->setObjectName(QString::fromLatin1(name));
        KswordTheme::ApplyStandardIconButtonMetrics(button);
        ks::ui::SetThemeButtonIcon(button, QIcon(QString::fromLatin1(icon)));
        return button;
    }

    // 依据真实读端状态给出可读描述；待续写、截尾与失败不冒充成功空结果。
    QString SourceState(const QString& state)
    {
        if (state == QStringLiteral("at-tail"))
        {
            return sourceText(QStringLiteral("已到当前文件末尾，等待追加"));
        }
        if (state == QStringLiteral("partial-line"))
        {
            return sourceText(QStringLiteral("等待写入方补全末行"));
        }
        if (state == QStringLiteral("reading"))
        {
            return sourceText(QStringLiteral("正在读取 JSONL"));
        }
        if (state == QStringLiteral("cutoff"))
        {
            return sourceText(QStringLiteral("已读到本次停止边界"));
        }
        return state;
    }

    // 输入控制器已经完成的阶段，返回当前语言的短标签；不按本端时间或模块存在猜测阶段。
    QString StartupStageText(ks::winapi_monitor::CaptureStartupStage stage)
    {
        using Stage = ks::winapi_monitor::CaptureStartupStage; // 后端唯一阶段定义。
        switch (stage)
        {
        case Stage::IdentityVerified:
            return sourceText(QStringLiteral("身份核对完成"));
        case Stage::AgentResolved:
            return sourceText(QStringLiteral("Agent 路径已解析"));
        case Stage::ConfigPublished:
            return sourceText(QStringLiteral("配置已发布"));
        case Stage::AgentLoadStarted:
            return sourceText(QStringLiteral("Agent 装载已开始"));
        case Stage::AgentModuleVerified:
            return sourceText(QStringLiteral("Agent 模块已核验"));
        // 三项协议阶段分别显示，只有原 Ready 回调能够改变正在采样的状态。
        case Stage::PipeConnected:
            return sourceText(QStringLiteral("管道已核对"));
        case Stage::SessionReady:
            return sourceText(QStringLiteral("SessionReady"));
        case Stage::HooksInstalled:
            return sourceText(QStringLiteral("HooksInstalled"));
        case Stage::Ready:
            return sourceText(QStringLiteral("Ready"));
        }
        return {};
    }

    // 将可选启动快照追加到现有规范文档；无快照表示尚无已完成阶段，不伪造初始成功。
    void AppendStartupProgress(ks::ui::FieldDocument& document,
        const std::optional<ks::winapi_monitor::CaptureStartupProgress>& startup)
    {
        if (!startup)
        {
            return;
        }
        document.field(QStringLiteral("最后确认的启动阶段"), StartupStageText(startup->stage))
            .field(QStringLiteral("启动阶段耗时（毫秒）"), QString::number(startup->elapsedMs));
    }
}

// 使用共享参数、固定动作和详情投影；不另设导航、日志或档案表。
PassiveApiCapturePane::PassiveApiCapturePane(QWidget* parent) : QWidget(parent)
{
    auto* root = new QVBoxLayout(this); // 页边距由现有总览负责。
    root->setContentsMargins(0, 0, 0, 0);
    auto* workspace = new ks::ui::ParameterWorkspace(this, 420); // 窄窗自动堆叠，参数独立滚动。
    root->addWidget(workspace);
    auto* source = new QGroupBox(workspace); // 只放本端来源选择和采样身份。
    auto* form = new QVBoxLayout(source); // 标签和字段保持各自自然高度。
    m_projectLabel = new QLabel(source);
    m_projectLabel->setWordWrap(true);
    m_projectLabel->setTextFormat(Qt::PlainText);
    form->addWidget(m_projectLabel);

    // 在原参数分区内切换来源，保持默认文件模式及所有原控件身份。
    m_sourceMode = new QTabBar(source);
    m_sourceMode->setObjectName(QStringLiteral("action_analyze_api_source_mode"));
    m_sourceMode->setExpanding(false);
    m_sourceMode->addTab(QString());
    m_sourceMode->addTab(QString());
    m_sourceMode->addTab(QString());
    m_sourceMode->addTab(QString()); // 启动EXE是独立来源，不借用已有PID或JSONL草稿。
    ks::ui::InstallSegmentedTabBar(m_sourceMode);
    form->addWidget(m_sourceMode);
    m_sourceHint = new QLabel(source); // 解释当前草稿来源，长文本由参数正文自动换行。
    m_sourceHint->setWordWrap(true);
    m_sourceHint->setTextFormat(Qt::PlainText);
    form->addWidget(m_sourceHint);

    // 路径不可手改；只有显式选择器能替换已授权候选文件。
    m_path = new QLineEdit(source);
    m_pathLabel = AddInput(form, m_path, "action_analyze_api_path");
    m_path->setReadOnly(true);
    m_executable = new QLineEdit(source);
    m_executableLabel = AddInput(form, m_executable, "action_analyze_api_executable");
    m_executable->setReadOnly(true);
    m_session = new QLineEdit(source);
    m_sessionLabel = AddInput(form, m_session, "action_analyze_api_session");
    m_pid = new QLineEdit(source);
    m_pidLabel = AddInput(form, m_pid, "action_analyze_api_pid");
    m_creation = new QLineEdit(source);
    m_creationLabel = AddInput(form, m_creation, "action_analyze_api_creation");
    // 复用标准数值输入和原参数滚动区，不用新计时器计算采样区间。
    m_durationLabel = new QLabel(source);
    m_durationLabel->setWordWrap(true);
    m_duration = new QSpinBox(source);
    m_duration->setObjectName(QStringLiteral("action_analyze_api_duration"));
    m_duration->setRange(0, 120);
    m_durationLabel->setBuddy(m_duration);
    form->addWidget(m_durationLabel);
    form->addWidget(m_duration);
    // 同采样来源沿原ParameterWorkspace自然高度排列，不启动独立网络页或第二writer。
    m_networkTrafficLabel = new QLabel(source);
    m_networkTrafficLabel->setWordWrap(true);
    m_networkTraffic = new QComboBox(source);
    m_networkTraffic->setObjectName(QStringLiteral("action_analyze_api_network_traffic"));
    m_networkTraffic->addItem(QString()); // 0：关闭，作为首次默认值。
    m_networkTraffic->addItem(QString()); // 1：原RawSocket来源。
    m_networkTraffic->addItem(QString()); // 2：只读既有WFP来源。
    m_networkTrafficLabel->setBuddy(m_networkTraffic);
    form->addWidget(m_networkTrafficLabel);
    form->addWidget(m_networkTraffic);
    m_captureAgentEtw = new QCheckBox(source); // 使用标准checkbox主题，沿原参数滚动区自然排列。
    m_captureAgentEtw->setObjectName(QStringLiteral("action_analyze_api_capture_agent_etw"));
    form->addWidget(m_captureAgentEtw);
    m_autoTransfer = new QCheckBox(source); // 沿用原ParameterWorkspace正文与标准主题，不增加独立布局。
    auto& language = ks::i18n::LanguageManager::instance(); // 文案随原页面热切换。
    language.bindText(m_autoTransfer, {}, QStringLiteral("自动接管跨进程私有执行目标"));
    language.bindToolTip(m_autoTransfer, {}, QStringLiteral("在已覆盖的线程创建、APC和上下文调用前自动解析私有范围并设防；执行命中保存后自动继续，失败单独报告。"));
    form->addWidget(m_autoTransfer);
    workspace->parameters()->addWidget(source);
    m_sourceGroup = source;
    ks::ui::StyleParameterSection(source);

    // 选择器与开始/停止均放在固定动作带；状态与已提交回执保留剩余高度。
    auto* footer = workspace->actions()->parentWidget(); // 动作由共享工具条统一度量。
    m_browse = IconButton(footer, "action_analyze_api_browse", ":/Icon/process_open_folder.svg");
    m_executableBrowse = IconButton(footer, "action_analyze_api_executable_browse", ":/Icon/process_open_folder.svg");
    m_start = IconButton(footer, "action_analyze_api_start", ":/Icon/process_resume.svg");
    m_stop = IconButton(footer, "action_analyze_api_stop", ":/Icon/process_stop.svg");
    m_pauseTransfers = IconButton(footer, "action_analyze_api_pause_transfers", ":/Icon/process_pause.svg");
    m_resumeTransfers = IconButton(footer, "action_analyze_api_resume_transfers", ":/Icon/process_resume.svg");
    m_archive = IconButton(footer, "action_analyze_api_archive", ":/Icon/process_details.svg");
    ks::ui::ApplyFlatButtonTheme(m_start, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
    for (auto* button : {m_browse, m_executableBrowse, m_start, m_pauseTransfers, m_resumeTransfers, m_stop, m_archive}) // 固定动作顺序同采样步骤。
    {
        workspace->actions()->addWidget(button);
    }
    workspace->actions()->addStretch();
    m_status = new QLabel(workspace);
    m_status->setObjectName(QStringLiteral("action_analyze_api_status"));
    m_status->setTextFormat(Qt::PlainText);
    m_status->setWordWrap(true);
    workspace->results()->addWidget(m_status);
    // 两类结果共用原参数工作区：回执保留原文档，接管页只投影同一样本的后端回执。
    m_resultTabs = new QTabWidget(workspace);
    m_resultTabs->setObjectName(QStringLiteral("action_analyze_api_result_tabs"));
    m_fields = new ks::ui::StructuredFieldView(m_resultTabs);
    m_fields->setObjectName(QStringLiteral("action_analyze_api_receipt"));
    m_fields->setValueModelProjection();
    m_fields->setHiddenProjectionDeferred();
    m_handoffFields = new ks::ui::StructuredFieldView(m_resultTabs);
    m_handoffFields->setObjectName(QStringLiteral("action_analyze_handoff_receipt"));
    m_handoffFields->setSearchTargetPrefix(QStringLiteral("action_analyze_handoff_search"));
    m_handoffFields->setValueModelProjection();
    m_handoffFields->setHiddenProjectionDeferred();
    m_handoffFields->setPresentation(ks::ui::StructuredFieldView::Presentation::Tree);
    m_resultTabs->addTab(m_fields, QString());
    m_resultTabs->addTab(m_handoffFields, QString());
    ks::ui::StylePageTabs(m_resultTabs);
    ks::ui::StylePageTabsContentFrame(m_resultTabs);
    workspace->results()->addWidget(m_resultTabs, 1);
    workspace->finish();

    // 后台注册分开报告真实所有者与轻量回执计时器；管理器不可暂停文件收尾。
    m_operation = new ks::ui::AsyncOperation(this);
    m_preview = new QTimer(this);
    m_preview->setInterval(250);
    auto& registry = ks::ui::BackgroundTaskRegistry::instance(); // 唯一真实监控工作台。
    const auto title = sourceText(QStringLiteral("API 采样")); // 后台目录登记两种互斥输入。
    const auto group = sourceText(QStringLiteral("监控")); // 与现有监控任务同组。
    const auto restriction = sourceText(QStringLiteral("请在行为分析总览停止采样。")); // 不伪造暂停。
    ks::ui::BackgroundTaskRegistry::External external; // 只回读本端所有者的真实运行态。
    external.running = [this]() { return m_owner && m_owner->running(); };
    ks::ui::BackgroundTaskRegistry::Policy policy; // GUI 只观察同一会话，不另开 worker。
    policy.canPause = false;
    policy.canChangeInterval = false;
    policy.restriction = restriction;
    policy.eligible = [this]() { return m_busy; };
    m_registered = registry.addExternal(QStringLiteral("monitor.action_analyze.api_jsonl"), title, group,
        this, std::move(external), restriction) && registry.addTimer(
        QStringLiteral("monitor.action_analyze.api_jsonl_preview"), title, group, m_preview, std::move(policy));

    // 任何编辑只清除参数提示，不改写旧结果或自动开始采样。
    connect(m_preview, &QTimer::timeout, this, &PassiveApiCapturePane::readProgress);
    connect(m_browse, &QPushButton::clicked, this, &PassiveApiCapturePane::chooseFile);
    connect(m_executableBrowse, &QPushButton::clicked, this, &PassiveApiCapturePane::chooseFile);
    connect(m_start, &QPushButton::clicked, this, &PassiveApiCapturePane::start);
    connect(m_stop, &QPushButton::clicked, this, &PassiveApiCapturePane::stop);
    connect(m_pauseTransfers, &QPushButton::clicked, this, [this]() {
        if (m_busy && !m_stopping && m_owner) m_owner->requestTransferPause(true);
        updateControls(); // 只更新请求资格，不提前显示已Held。
    });
    connect(m_resumeTransfers, &QPushButton::clicked, this, [this]() {
        if (m_busy && !m_stopping && m_owner) m_owner->requestTransferPause(false);
        updateControls(); // 实际恢复完成仍取同一worker回执。
    });
    connect(m_sourceMode, &QTabBar::currentChanged, this, [this]() {
        m_invalid = false;
        updateControls();
    });
    connect(m_archive, &QPushButton::clicked, this, [this]() {
        if (canOpenArchive())
        {
            openArchive(*m_receipt.sample);
        }
    });
    for (auto* input : {m_path, m_session, m_pid, m_creation}) // 编辑阶段保留最近一次已提交回执。
    {
        connect(input, &QLineEdit::textChanged, this, [this]() {
            if (m_invalid)
            {
                m_invalid = false;
                updateControls();
            }
        });
    }
    retranslate();
}

// 页面隐藏只影响显示；真实销毁才请求后台读取收尾。
PassiveApiCapturePane::~PassiveApiCapturePane()
{
    m_operation->close();
    if (m_owner)
    {
        m_owner->requestStop();
    }
}

// 冻结项目归属在 start 时完成，当前目录读取不改写已运行的所有者。
void PassiveApiCapturePane::setContext(const QString& manifest, const QString& projectId, const QString& revisionId,
    bool etwBusy, bool readingArchive)
{
    m_context.manifest = manifest;
    m_context.projectId = projectId;
    m_context.revisionId = revisionId;
    m_etwBusy = etwBusy;
    m_readingArchive = readingArchive;
    updateControls();
}

// 文件选择即明确授权读取范围；后端重新校验真实本地文件身份。
void PassiveApiCapturePane::chooseFile()
{
    const bool launched = m_sourceMode->currentIndex() == 3; // 选择器只替换对应来源的独立草稿。
    if (m_busy || (m_sourceMode->currentIndex() != 0 && !launched))
    {
        return;
    }
    auto* target = launched ? m_executable : m_path; // 控件只保存选择结果，不启动进程。
    const auto path = QFileDialog::getOpenFileName(this,
        sourceText(launched ? QStringLiteral("选择普通 AMD64 EXE") : QStringLiteral("选择已授权的 API JSONL")),
        target->text(), sourceText(launched ? QStringLiteral("程序 (*.exe)") : QStringLiteral("API JSONL 文件 (*.jsonl)")),
        nullptr, QFileDialog::ReadOnly);
    if (!path.isEmpty())
    {
        target->setText(path);
        target->setToolTip(path);
        m_invalid = false;
        updateControls();
    }
}

// 限于值请求；后端只在同一个 worker 执行 BeginProject、Tick 和 Finish。
void PassiveApiCapturePane::start()
{
    if (!startDisabledReason().isEmpty())
    {
        return;
    }
    auto request = m_context; // 冻结工作台实际选中的清单和修订。
    request.attachmentConfirmed = false; // 确认只属于本次点击，不继承上下文或上一轮值。
    request.cooperative = m_sourceMode->currentIndex() == 1;
    request.explicitAttachment = m_sourceMode->currentIndex() == 2;
    request.launched = m_sourceMode->currentIndex() == 3;
    request.executable = request.launched ? m_executable->text() : QString();
    request.entryRva.reset(); // 桌面默认PE入口，不继承上下文或其它来源的隐藏位置。
    const bool live = request.cooperative || request.explicitAttachment || request.launched; // 保留各来源独立草稿。
    request.path = live ? QString() : m_path->text();
    request.sessionId = live ? 0 : Identity<quint64>(m_session);
    request.pid = request.launched ? 0 : Identity<quint32>(m_pid);
    request.creationTime = request.launched ? 0 : Identity<quint64>(m_creation);
    request.durationMs = live ? static_cast<quint32>(m_duration->value()) * 1000 : 0;
    request.autoTransfer = live && m_autoTransfer->isChecked(); // 隐藏文件草稿不授予原生控制策略。
    request.captureAgentEtw = live && m_captureAgentEtw->isChecked(); // 文件跟随只保留勾选草稿，不提交ETW来源。
    request.networkTraffic.reset(); // 文件跟随不提交网络策略，控件中的上一份草稿继续保留。
    if (live)
    {
        using Backend = Ksword::ActionAnalyze::NetworkTrafficBackend; // 共用后端枚举，不在UI重复定义来源。
        if (m_networkTraffic->currentIndex() == 1)
        {
            request.networkTraffic = Backend::RawSocket;
        }
        else if (m_networkTraffic->currentIndex() == 2)
        {
            request.networkTraffic = Backend::ExistingWfp;
        }
    }
    // 标题与目标一同冻结；切换语言或编辑下一轮草稿不改变当前后台采样。
    if (live)
    {
        request.cooperativeTitle = request.launched ? sourceText(QStringLiteral("启动 EXE 并采集 API")) :
            sourceText(request.explicitAttachment ? QStringLiteral("显式 API 附加（PID %1）") :
                QStringLiteral("合作 Agent（PID %1）")).arg(request.pid);
    }
    const bool invalidSource = request.launched ? request.executable.isEmpty() : live ? request.pid <= 4 || request.pid == GetCurrentProcessId()
        : request.path.isEmpty() || !request.sessionId || !request.pid;
    if (invalidSource || (!request.launched && !request.creationTime))
    {
        m_invalid = true;
        updateControls();
        return;
    }
    if (request.explicitAttachment)
    {
        // 确认框只展示这份冻结请求；嵌套消息循环内销毁页面时不再访问本对象。
        const QPointer<PassiveApiCapturePane> alive(this); // 防止主窗口关闭导致回调访问已销毁页面。
        m_confirming = true;
        const auto answer = QMessageBox::question(this, sourceText(QStringLiteral("确认显式 API 附加")),
            sourceText(QStringLiteral("向 PID %1、创建 FILETIME %2 的已运行实例装载匹配架构的产品 Agent 并采集 API？\n停止时恢复 Hook 并排空管道；Agent 按现有策略驻留到目标退出。"))
                .arg(request.pid).arg(request.creationTime), QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (!alive)
        {
            return;
        }
        m_confirming = false;
        if (answer != QMessageBox::Yes || !startDisabledReason().isEmpty() ||
            request.manifest != m_context.manifest || request.projectId != m_context.projectId ||
            request.revisionId != m_context.revisionId)
        {
            updateControls();
            return;
        }
        request.attachmentConfirmed = true; // 只授予上面显示的实例，不保存到下一次草稿。
    }
    // 在新采样真正登记前保留上一份回执；失败不能重写旧结果的归属。
    m_owner = std::make_shared<PassiveApiCaptureOwner>(std::move(request));
    m_currentReceipt = {}; // 新启动回执与仍可打开的上次归档分别保存。
    m_liveCoverageRevision = 0;
    m_announced.clear();
    m_startError.clear();
    m_failed = false;
    m_invalid = false;
    m_busy = true;
    m_preview->start();
    const auto accepted = m_operation->submit<std::shared_ptr<PassiveApiCaptureOwner>, PassiveApiCaptureReceipt>(m_owner,
        [](const auto& owner, const ks::ui::AsyncOperationToken& token) { return owner->collect(token); },
        [this](const PassiveApiCaptureReceipt& result, quint64) { finish(result); return true; },
        [this](std::exception_ptr) { finish(m_owner->receipt(), true); }); // 保留异常前最后发布的水位。
    if (!accepted)
    {
        finish({}, true);
        return;
    }
    renderReceipt();
    updateControls();
    if (statusChanged)
    {
        statusChanged();
    }
}

// 发出一次停止请求，继续显示同一会话，直到 worker 交还写租约。
void PassiveApiCapturePane::stop()
{
    if (!m_busy || m_stopping)
    {
        return;
    }
    m_stopping = true;
    m_owner->requestStop();
    updateControls();
    if (statusChanged)
    {
        statusChanged();
    }
}

// 回执只在值变化时投影。第一次获得目录行后通知同一个项目工作台。
void PassiveApiCapturePane::readProgress()
{
    const auto current = m_owner->receipt(); // 已发布值，不发起后端查询。
    const bool currentChanged = current != m_currentReceipt; // 无采样的启动失败也有独立字段。
    m_currentReceipt = current;
    const bool readyChanged = current.readyCoverageRevision != m_liveCoverageRevision; // 同一轮可能收到就绪与首段。
    m_liveCoverageRevision = current.readyCoverageRevision;
    if (!current.sample)
    {
        // 合作采样启动时先更新状态；旧归档仍可通过原回执读取。
        if (readyChanged || currentChanged)
        {
            renderReceipt();
            updateControls();
            if (statusChanged)
            {
                statusChanged();
            }
        }
        return;
    }
    if (current == m_receipt)
    {
        return;
    }
    m_receipt = current;
    m_resultOwner = m_owner;
    renderReceipt();
    updateControls();
    if (m_receipt.sample && m_receipt.sample->sample.id != m_announced)
    {
        m_announced = m_receipt.sample->sample.id;
        if (registered)
        {
            registered(*m_receipt.sample);
        }
    }
    if (statusChanged)
    {
        statusChanged();
    }
}

// 终态到达前不开放新采样；异常也保留能确认的旧前缀。
void PassiveApiCapturePane::finish(const PassiveApiCaptureReceipt& receipt, bool abnormal)
{
    m_preview->stop();
    m_busy = false;
    m_stopping = false;
    m_failed = abnormal || (!receipt.sample && !receipt.error.isEmpty());
    m_currentReceipt = receipt; // 未登记采样也保留本次身份、装载和失败事实。
    m_startError = receipt.error == QStringLiteral("attachedApiAdmission")
        ? sourceText(QStringLiteral("已有实例附加需要本次确认；JSONL、合作已装载、显式附加与启动EXE来源不能混用。")) : receipt.error;
    if (receipt.sample)
    {
        m_receipt = receipt;
        m_resultOwner = m_owner;
    }
    renderReceipt();
    updateControls();
    if (receipt.sample && registered)
    {
        // 清退后再刷新一次目录，覆盖运行期同时读取旧目录的情况。
        m_announced = receipt.sample->sample.id;
        registered(*receipt.sample);
    }
    if (statusChanged)
    {
        statusChanged();
    }
}

// 以最近一次请求为状态，仅用已产生的新回执判断“跟随中”。
QString PassiveApiCapturePane::summary() const
{
    if (!m_owner)
    {
        return {};
    }
    if (m_owner->request().cooperative || m_owner->request().explicitAttachment || m_owner->request().launched)
    {
        // 本轮启动摘要只使用当前快照；旧结果仍由 m_resultOwner 保留自己的身份。
        const auto startup = m_currentReceipt.startup
            ? sourceText(QStringLiteral("最后确认的启动阶段：%1")).arg(StartupStageText(m_currentReceipt.startup->stage))
            : QString(); // 无已完成阶段时继续沿用明确的等待提示。
        const auto withStartup = [&](const QString& text) {
            return startup.isEmpty() ? text : text + QStringLiteral(" · ") + startup;
        }; // 停止或启动失败仍报告最后确认的阶段，不以终态文字覆盖启动原因。
        if (m_stopping)
        {
            return withStartup(sourceText(QStringLiteral("正在停止 API 活采并归档")));
        }
        if (m_busy)
        {
            return m_liveCoverageRevision
                ? sourceText(QStringLiteral("Agent 已就绪 · 覆盖修订 %1 · 正在采样")).arg(m_liveCoverageRevision)
                : withStartup(sourceText(QStringLiteral("API 活采请求处理中，等待 Ready 与覆盖核验")));
        }
        if (!m_startError.isEmpty() && (m_failed || !m_currentReceipt.agentReady))
        {
            return withStartup(sourceText(QStringLiteral("API 活采未完成：%1")).arg(m_startError));
        }
        if (m_resultOwner != m_owner)
        {
            return withStartup(sourceText(QStringLiteral("API 活采未开始")));
        }
        return withStartup(sourceText(m_receipt.incomplete ? QStringLiteral("API 活采已结束（部分结果）· 已归档 %1 个原包")
            : QStringLiteral("API 活采已结束 · 已归档 %1 个原包")).arg(m_receipt.recordedRows));
    }
    if (m_stopping)
    {
        return sourceText(QStringLiteral("正在停止 API JSONL 跟随"));
    }
    if (m_busy)
    {
        return m_resultOwner == m_owner
            ? sourceText(QStringLiteral("正在跟随 API JSONL · 已归档 %1 行 · 规则命中 %2 行"))
                .arg(m_receipt.recordedRows).arg(m_receipt.ruleMatches)
            : sourceText(QStringLiteral("正在打开 API JSONL 来源"));
    }
    if (m_failed)
    {
        return m_startError.isEmpty() ? sourceText(QStringLiteral("API JSONL 跟随异常结束"))
            : sourceText(QStringLiteral("无法启动 API JSONL 跟随：%1")).arg(m_startError);
    }
    if (m_resultOwner != m_owner)
    {
        return sourceText(QStringLiteral("已在登记采样前停止 API JSONL 跟随"));
    }
    if (m_receipt.incomplete)
    {
        const auto reason = !m_receipt.error.isEmpty() ? m_receipt.error : m_receipt.partialLineBytes
            ? sourceText(QStringLiteral("末行未写完（%1 字节）")).arg(m_receipt.partialLineBytes)
            : SourceState(m_receipt.sourceState); // 根据本端实际停止边界说明缺口。
        return sourceText(QStringLiteral("API JSONL 跟随已停止，结果不完整：%1")).arg(reason);
    }
    return sourceText(QStringLiteral("API JSONL 跟随已停止 · 已归档 %1 行 · 规则命中 %2 行"))
        .arg(m_receipt.recordedRows).arg(m_receipt.ruleMatches);
}

// 按实际互斥状态开放下一次开始；参数错误留在原位等待用户修正。
QString PassiveApiCapturePane::startDisabledReason() const
{
    if (!m_registered)
    {
        return sourceText(QStringLiteral("当前无法启动监控。"));
    }
    if (m_busy || m_etwBusy || m_confirming)
    {
        return sourceText(QStringLiteral("已有监控会话在运行或启动中。"));
    }
    if (m_context.manifest.isEmpty() || m_context.projectId.isEmpty() || m_context.revisionId.isEmpty())
    {
        return sourceText(QStringLiteral("请先创建或打开行为分析项目。"));
    }
    return {};
}

// 档案动作始终使用结果身份，且只读本端已经发布的项目检查点。
bool PassiveApiCapturePane::canOpenArchive() const
{
    return bool(openArchive) && !m_readingArchive && m_receipt.sample && m_receipt.segment > 0;
}

// 状态、正文可访问名称和所有按钮提示均从同一份资格计算。
void PassiveApiCapturePane::updateControls()
{
    const bool cooperative = m_sourceMode->currentIndex() == 1; // 只控制草稿和下一次动作。
    const bool attached = m_sourceMode->currentIndex() == 2; // 不从历史回执推断当前参数模式。
    const bool launched = m_sourceMode->currentIndex() == 3; // 新建来源不要求手填目标身份。
    const bool live = cooperative || attached || launched; // 活采不会使用文件路径和外部session。
    for (auto* field : {static_cast<QWidget*>(m_executableLabel), static_cast<QWidget*>(m_executable),
        static_cast<QWidget*>(m_executableBrowse)})
    {
        field->setVisible(launched);
    }
    for (auto* field : {static_cast<QWidget*>(m_pidLabel), static_cast<QWidget*>(m_pid),
        static_cast<QWidget*>(m_creationLabel), static_cast<QWidget*>(m_creation)})
    {
        field->setVisible(!launched); // 原输入保留草稿，实际身份只由worker回执展示。
    }
    m_executableBrowse->setEnabled(!m_busy);
    m_executableBrowse->setToolTip(m_executableBrowse->accessibleName());
    m_sourceMode->setEnabled(!m_busy);
    for (auto* field : {static_cast<QWidget*>(m_pathLabel), static_cast<QWidget*>(m_path),
        static_cast<QWidget*>(m_sessionLabel), static_cast<QWidget*>(m_session), static_cast<QWidget*>(m_browse)})
    {
        field->setVisible(!live);
    }
    m_durationLabel->setVisible(live);
    m_duration->setVisible(live);
    m_duration->setEnabled(!m_busy);
    m_autoTransfer->setVisible(live);
    m_autoTransfer->setEnabled(!m_busy);
    const bool transferControls = m_busy && !m_stopping && m_owner && m_owner->request().autoTransfer; // 冻结策略不取下一轮草稿。
    const auto transferIntent = m_owner ? m_owner->transferIntent() : Ksword::ActionAnalyze::ApiTransferControl::Intent{};
    m_pauseTransfers->setEnabled(transferControls && !transferIntent.paused);
    m_resumeTransfers->setEnabled(transferControls && transferIntent.paused);
    m_pauseTransfers->setAccessibleName(sourceText(QStringLiteral("暂停全部成员")));
    m_resumeTransfers->setAccessibleName(sourceText(QStringLiteral("继续全部成员")));
    m_pauseTransfers->setToolTip(sourceText(QStringLiteral("请求保留本轮全部接管成员；归档继续，实际暂停状态见自动接管回执。")));
    m_resumeTransfers->setToolTip(sourceText(QStringLiteral("请求恢复本轮自动追踪；实际恢复状态见自动接管回执。")));
    m_networkTraffic->setEnabled(live && !m_busy); // JSONL保留选择，运行时冻结本轮策略。
    m_captureAgentEtw->setEnabled(live && !m_busy); // 运行期间与来源参数一起冻结，切换JSONL不清除勾选。
    m_sourceHint->setText(sourceText(launched ? QStringLiteral("选择普通 AMD64 EXE，入口停止后自动附加 Agent；Ready 与覆盖核验通过才恢复主线程。此前 TLS/loader 不在覆盖范围。") :
        attached ? QStringLiteral("附加到明确的 PID 与创建 FILETIME；点击开始后确认装载。文件和外部会话 ID 不参与活采。") :
        cooperative ? QStringLiteral("只连接目标已主动加载的产品 Agent，不尝试装载。文件和外部会话 ID 不参与活采。") :
        QStringLiteral("只跟随选中的本地 JSONL，使用文件声明的会话 ID；不会连接或装载目标 Agent。")));
    m_start->setAccessibleName(sourceText(launched ? QStringLiteral("启动 EXE 并采集 API") : attached ? QStringLiteral("开始显式 API 附加") :
        cooperative ? QStringLiteral("开始合作 API 采样") : QStringLiteral("开始跟随 API JSONL")));
    m_stop->setAccessibleName(sourceText(live ? QStringLiteral("停止 API 活采") : QStringLiteral("停止跟随 API JSONL")));
    m_projectLabel->setText(m_context.projectId.isEmpty()
        ? sourceText(QStringLiteral("请先创建或打开行为分析项目。"))
        : sourceText(QStringLiteral("采样项目：%1")).arg(m_context.projectId));
    m_projectLabel->setToolTip(m_context.manifest);
    for (auto* input : {m_session, m_pid, m_creation}) // 正在运行时不修改提交草稿。
    {
        input->setReadOnly(m_busy);
    }
    m_browse->setEnabled(!m_busy);
    m_browse->setToolTip(m_busy ? sourceText(QStringLiteral("已有监控会话在运行或启动中。")) : m_browse->accessibleName());
    const auto disabled = startDisabledReason(); // 按钮与真实启动入口共用拒绝原因。
    m_start->setEnabled(disabled.isEmpty());
    m_start->setToolTip(!disabled.isEmpty() ? disabled : live
        ? sourceText(QStringLiteral("按冻结的目标实例开始采样；时限从 Ready 起算，0 表示持续到明确停止或目标退出。")) : m_start->accessibleName());
    m_stop->setEnabled(m_busy && !m_stopping);
    m_stop->setToolTip(m_stop->isEnabled() ? m_stop->accessibleName() : m_stopping ? summary()
        : sourceText(QStringLiteral("当前没有可停止的监控会话。")));
    m_archive->setEnabled(canOpenArchive());
    m_archive->setToolTip(m_archive->isEnabled() ? m_archive->accessibleName() : m_readingArchive
        ? sourceText(QStringLiteral("正在读取归档。")) : sourceText(QStringLiteral("尚无已核验的监控归档段。")));

    // 参数错误只影响本次草稿，存量回执继续保持可查看。
    const auto status = m_invalid ? sourceText(launched ? QStringLiteral("请选择已授权的普通 AMD64 EXE。") : live ? QStringLiteral("请输入授权目标的十进制 PID 和创建 FILETIME。")
        : QStringLiteral("请选择已授权的 API JSONL，并输入非零十进制的来源会话 ID、PID 和创建 FILETIME。"))
        : m_owner ? summary() : sourceText(live ? QStringLiteral("API 活采未开始") : QStringLiteral("尚未开始 API JSONL 跟随"));
    if (m_status->text() != status)
    {
        m_status->setText(status);
    }
    using ks::ui::StatusRole;
    ks::ui::ApplyStatusRole(m_status, m_invalid || m_failed ? StatusRole::Error
        : m_resultOwner == m_owner && !m_receipt.ruleConfigError.isEmpty() ? StatusRole::Warning
        : m_busy ? StatusRole::Info : m_receipt.incomplete || m_receipt.ruleFailed ? StatusRole::Warning : StatusRole::Idle);
}

// 结构文档只使用经过核验的坐标，源文件与项目身份来自本次登记时冻结的请求。
void PassiveApiCapturePane::renderReceipt()
{
    ks::ui::FieldDocument document; // 供共享字段视图搜索、复制、导出的唯一正文。
    if (m_owner && m_resultOwner != m_owner &&
        (m_owner->request().explicitAttachment || m_owner->request().cooperative || m_owner->request().launched))
    {
        // 新请求无采样时单列本轮事实，下面仍保留旧归档的完整来源与可复制文档。
        const auto& request = m_owner->request(); // 本轮确认过的冻结实例和项目。
        const auto yesNo = [](bool value) { return sourceText(value ? QStringLiteral("是") : QStringLiteral("否")); };
        const auto attachmentFact = [&](bool value) {
            return !value && m_busy ? sourceText(QStringLiteral("等待最终回执")) : yesNo(value);
        }; // 已发布的真值立即显示；尚未完成的事实在运行期间不能冒充已确认的否。
        const auto actualPid = request.launched ? m_currentReceipt.actualPid : request.pid; // 本轮冻结来源或真实创建PID。
        const auto actualCreation = request.launched ? m_currentReceipt.actualCreationTime : request.creationTime; // 同实例时间。
        document.section(request.launched ? QStringLiteral("本次 EXE 启动采集请求") :
            request.explicitAttachment ? QStringLiteral("本次显式 API 附加请求") : QStringLiteral("本次合作 API 采样请求"))
            .field(QStringLiteral("项目清单"), request.manifest)
            .field(QStringLiteral("来源 PID"), actualPid ? QString::number(actualPid) : QStringLiteral("—"))
            .field(QStringLiteral("进程创建 FILETIME"), actualCreation ? QString::number(actualCreation) : QStringLiteral("—"))
            .field(QStringLiteral("采集时限（毫秒，0 为持续）"), QString::number(request.durationMs));
        AppendStartupProgress(document, m_currentReceipt.startup);
        if (!m_currentReceipt.networkTraffic.isEmpty())
        {
            document.field(QStringLiteral("同采样网络回执"), m_currentReceipt.networkTraffic);
        }
        document.field(QStringLiteral("采集自有 Agent ETW"), yesNo(request.captureAgentEtw));
        if (!m_currentReceipt.agentEtw.isEmpty())
        {
            document.field(QStringLiteral("同采样 ETW 回执"), m_currentReceipt.agentEtw); // 原规范全文留在唯一字段源。
        }
        if (request.launched)
        {
            document.field(QStringLiteral("启动 EXE"), request.executable)
                .field(QStringLiteral("入口交接回执"), m_currentReceipt.launchProgress);
        }
        if (request.explicitAttachment || request.launched)
        {
            document.field(QStringLiteral("附加实例已核验"), attachmentFact(m_currentReceipt.attachmentIdentityVerified))
                .field(QStringLiteral("已尝试装载 Agent"), attachmentFact(m_currentReceipt.agentLoadAttempted))
                .field(QStringLiteral("Agent 模块已核验"), attachmentFact(m_currentReceipt.agentModuleVerified));
        }
        document.field(QStringLiteral("Agent 已就绪"), yesNo(m_currentReceipt.agentReady))
            .field(QStringLiteral("就绪覆盖修订"), m_currentReceipt.readyCoverageRevision
                ? QString::number(m_currentReceipt.readyCoverageRevision) : QStringLiteral("—"));
        if (!m_startError.isEmpty())
        {
            document.field(QStringLiteral("采样诊断"), m_startError);
        }
    }
    if (m_resultOwner && m_receipt.sample)
    {
        const auto& request = m_resultOwner->request(); // 不随草稿和当前目录变动。
        const bool live = request.cooperative || request.explicitAttachment || request.launched; // 回执使用实际请求。
        document.section(request.launched ? QStringLiteral("EXE 启动采集来源") : request.explicitAttachment ? QStringLiteral("显式 API 附加来源") :
            request.cooperative ? QStringLiteral("合作 Agent 来源") : QStringLiteral("API JSONL 来源"))
            .field(QStringLiteral("采样 ID"), m_receipt.sample->sample.id)
            .field(QStringLiteral("项目清单"), request.manifest)
            .field(QStringLiteral("来源 PID"), QString::number(request.launched ? m_receipt.actualPid : request.pid))
            .field(QStringLiteral("进程创建 FILETIME"), QString::number(request.launched ? m_receipt.actualCreationTime : request.creationTime));
        if (request.launched)
        {
            document.field(QStringLiteral("启动 EXE"), request.executable)
                .field(QStringLiteral("入口交接回执"), m_receipt.launchProgress);
        }
        if (live)
        {
            const auto yesNo = [](bool value) { return sourceText(value ? QStringLiteral("是") : QStringLiteral("否")); };
            AppendStartupProgress(document, m_receipt.startup);
            if (!m_receipt.networkTraffic.isEmpty())
            {
                // 同一字段文档承担完整JSON的搜索、复制与导出，不另建过期摘要。
                document.field(QStringLiteral("同采样网络回执"), m_receipt.networkTraffic);
            }
            document.field(QStringLiteral("采集自有 Agent ETW"), yesNo(m_receipt.captureAgentEtw));
            if (!m_receipt.agentEtw.isEmpty())
            {
                document.field(QStringLiteral("同采样 ETW 回执"), m_receipt.agentEtw); // 不借API完成状态改写ETW阶段。
            }
            if (request.explicitAttachment || request.launched)
            {
                // 身份、装载与模块存在各自呈现；任一项均不能代替 Ready 和当前覆盖核验。
                const auto attachmentFact = [&](bool value) {
                    return !value && m_busy && m_resultOwner == m_owner
                        ? sourceText(QStringLiteral("等待最终回执")) : yesNo(value);
                }; // 同一运行回调确认后立即显示，未完成字段等待终态而不抢先判断失败。
                document.field(QStringLiteral("附加实例已核验"), attachmentFact(m_receipt.attachmentIdentityVerified))
                    .field(QStringLiteral("已尝试装载 Agent"), attachmentFact(m_receipt.agentLoadAttempted))
                    .field(QStringLiteral("Agent 模块已核验"), attachmentFact(m_receipt.agentModuleVerified));
            }
            document.field(QStringLiteral("采集时限（毫秒，0 为持续）"), QString::number(request.durationMs));
            if (!m_receipt.transferHandoff.isEmpty())
            {
                document.field(QStringLiteral("自动接管回执"), m_receipt.transferHandoff); // 单一规范文档供搜索/复制/导出。
            }
            document.field(QStringLiteral("来源会话 ID"), m_receipt.cooperativeSession ? QString::number(m_receipt.cooperativeSession) : QStringLiteral("—"))
                .field(QStringLiteral("Agent 已就绪"), yesNo(m_receipt.agentReady))
                .field(QStringLiteral("就绪覆盖修订"), m_receipt.readyCoverageRevision ? QString::number(m_receipt.readyCoverageRevision) : QStringLiteral("—"))
                .field(QStringLiteral("已确认停钩"), yesNo(m_receipt.hooksRemoved))
                .field(QStringLiteral("管道正常读完"), yesNo(m_receipt.cleanPipeEof))
                .field(QStringLiteral("目标已退出"), yesNo(m_receipt.targetExited))
                .field(QStringLiteral("已清退"), yesNo(m_receipt.cleanupComplete))
                .field(QStringLiteral("已核验普通包"), QString::number(m_receipt.validatedRows));
            AppendApiTransferProgress(document, m_receipt.transferCandidates, m_receipt.evictedTransferWrites,
                m_receipt.latestTransfer ? &*m_receipt.latestTransfer : nullptr,
                m_receipt.networkTraffic, m_receipt.agentEtw);
            // 同一规范文档承载 APC 活采摘要，显示的仍是已提交原回执。
            AppendApiApcProgress(document, m_receipt.apcTransferCandidates,
                m_receipt.latestApcTransfer ? &*m_receipt.latestApcTransfer : nullptr);
            // 继续使用已发布回执和同一字段宿主，草稿选择不会改变候选来源。
            AppendApiContextProgress(document, m_receipt.contextTransferCandidates,
                m_receipt.latestContextTransfer ? &*m_receipt.latestContextTransfer : nullptr);
        }
        else
        {
            document.field(QStringLiteral("本地 API JSONL"), request.path)
                .field(QStringLiteral("来源会话 ID"), QString::number(request.sessionId))
                .field(QStringLiteral("文件 ID"), m_receipt.fileId)
                .field(QStringLiteral("采样代次"), m_receipt.epoch)
                .field(QStringLiteral("来源状态"), SourceState(m_receipt.sourceState))
                .field(QStringLiteral("已核验来源行"), QString::number(m_receipt.validatedRows));
        }
        document.field(QStringLiteral("已归档原包"), QString::number(m_receipt.recordedRows))
            .field(QStringLiteral("已核验段号"), QString::number(m_receipt.segment));
        document.section(QStringLiteral("API 规则回执"))
            .field(QStringLiteral("已提交命中行"), QString::number(m_receipt.ruleMatches))
            .field(QStringLiteral("规则状态"), !m_receipt.ruleConfigError.isEmpty() ? QStringLiteral("规则库加载失败")
                : m_receipt.ruleFailed ? QStringLiteral("规则求值失败")
                : m_receipt.latestRuleId.isEmpty() ? QStringLiteral("尚无已提交规则命中") : QStringLiteral("已记录规则命中"), true);
        if (!m_receipt.rulePresetSet.isEmpty())
        {
            document.field(QStringLiteral("规则集"), m_receipt.rulePresetSet);
            document.field(QStringLiteral("SHA-256"), m_receipt.ruleSourceSha256);
        }
        if (!m_receipt.ruleConfigError.isEmpty())
        {
            document.field(QStringLiteral("规则库诊断"), m_receipt.ruleConfigError);
        }
        if (!m_receipt.latestRuleId.isEmpty())
        {
            document.field(QStringLiteral("最近命中的规则"), m_receipt.latestRuleId)
                .field(live ? QStringLiteral("命中坐标（段 / 原包 / 普通包流水号）")
                    : QStringLiteral("命中坐标（段 / 原包 / 来源行）"), QStringLiteral("%1 / %2 / %3")
                    .arg(m_receipt.ruleSegment).arg(m_receipt.ruleRawSequence).arg(m_receipt.ruleSourceSequence));
            // 只展示这条坐标实际附带的语义；缺证据时不从普通归类补推断。
            if (!m_receipt.latestBehaviorId.isEmpty())
            {
                document.field(QStringLiteral("行为规则 ID"), m_receipt.latestBehaviorId)
                    .field(QStringLiteral("证据级别"), m_receipt.latestBehaviorEvidence);
                // 在绘制时选取同一回执携带的语言文本，切换语言无需重新求值。
                const bool useChinese = ks::i18n::LanguageManager::instance().currentLanguageId()
                    .compare(QStringLiteral("zh-CN"), Qt::CaseInsensitive) == 0;
                const auto& summary = useChinese && !m_receipt.latestBehaviorSummaryZh.isEmpty()
                    ? m_receipt.latestBehaviorSummaryZh : m_receipt.latestBehaviorSummary;
                if (!summary.isEmpty())
                {
                    document.field(QStringLiteral("行为释义"), summary);
                }
            }
        }
        document.field(QStringLiteral("行为命中数"), QString::number(m_receipt.behaviorMatches));
        document.field(QStringLiteral("行为窗口截断"),
            m_receipt.behaviorMatches > static_cast<quint64>(m_receipt.recentBehaviors.size())
                ? QStringLiteral("是") : QStringLiteral("否"), true);
        // 原共享字段文档承载全部窗口，搜索、复制和导出与屏幕展示保持一致。
        const bool historyChinese = ks::i18n::LanguageManager::instance().currentLanguageId()
            .compare(QStringLiteral("zh-CN"), Qt::CaseInsensitive) == 0; // 仅在 UI 线程选择显示语言。
        for (const auto& behavior : m_receipt.recentBehaviors)
        {
            document.section(QStringLiteral("行为释义"));
            document.field(QStringLiteral("最近命中的规则"), behavior.ruleId);
            document.field(QStringLiteral("行为规则 ID"), behavior.behaviorId);
            document.field(live ? QStringLiteral("命中坐标（段 / 原包 / 普通包流水号）")
                : QStringLiteral("命中坐标（段 / 原包 / 来源行）"), QStringLiteral("%1 / %2 / %3")
                .arg(behavior.segment).arg(behavior.rawSequence).arg(behavior.sourceSequence));
            // 每条释义只使用自身原坐标，不把当前最终段或后续草稿挂到旧命中上。
            const auto& summary = historyChinese && !behavior.summaryZh.isEmpty()
                ? behavior.summaryZh : behavior.summary; // 中文缺失时显示原默认释义。
            document.field(QStringLiteral("行为释义"), summary);
            document.field(QStringLiteral("证据级别"), behavior.evidence);
        }
        if (!m_receipt.error.isEmpty())
        {
            document.field(QStringLiteral("采样诊断"), m_receipt.error);
        }
    }
    m_fields->setDocument(document);
    // 不以当前编辑草稿覆盖旧采样身份；新请求尚无接管回执时明确保留旧结果所属sample。
    const auto& handoffJson = !m_receipt.transferHandoffStatus.isEmpty()
        ? m_receipt.transferHandoffStatus : m_receipt.transferHandoff; // 活动态优先、终态回执权威，均属于同一样本。
    auto handoff = ApiHandoffDocument(handoffJson); // 同一冻结回执的字段树，不查询现场。
    if (m_receipt.sample)
    {
        ks::ui::FieldNode sample; // 保留真实结果采样身份，不用当前表单草稿重写回执来源。
        sample.kind = ks::ui::FieldNode::Kind::Field;
        sample.name = QStringLiteral("采样 ID");
        sample.value = m_receipt.sample->sample.id;
        handoff.nodes.prepend(std::move(sample));
    }
    m_handoffFields->setDocument(handoff);
}

// 语言变化时只重绘当前投影，不对输入值或已受理工作执行写操作。
void PassiveApiCapturePane::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange && m_status)
    {
        retranslate();
    }
}

// 所有公开动作含辅助技术可读名称；只在当前语言下发布显示用文本。
void PassiveApiCapturePane::retranslate()
{
    m_resultTabs->setTabText(0, sourceText(QStringLiteral("采集回执")));
    m_resultTabs->setTabText(1, sourceText(QStringLiteral("自动接管")));
    m_resultTabs->setTabToolTip(0, m_resultTabs->tabText(0));
    m_resultTabs->setTabToolTip(1, m_resultTabs->tabText(1));
    m_sourceGroup->setTitle(sourceText(QStringLiteral("API 采样")));
    m_sourceMode->setAccessibleName(sourceText(QStringLiteral("API 采样")));
    m_sourceMode->setTabText(0, sourceText(QStringLiteral("JSONL 跟随")));
    m_sourceMode->setTabText(1, sourceText(QStringLiteral("合作已装载")));
    m_sourceMode->setTabText(2, sourceText(QStringLiteral("显式附加")));
    m_sourceMode->setTabText(3, sourceText(QStringLiteral("启动EXE并采集")));
    m_sourceMode->setTabToolTip(0, m_sourceMode->tabText(0));
    m_sourceMode->setTabToolTip(1, m_sourceMode->tabText(1));
    m_sourceMode->setTabToolTip(2, m_sourceMode->tabText(2));
    m_sourceMode->setTabToolTip(3, m_sourceMode->tabText(3));
    m_executableLabel->setText(sourceText(QStringLiteral("启动 EXE")));
    m_executableBrowse->setAccessibleName(sourceText(QStringLiteral("选择普通 AMD64 EXE")));
    m_durationLabel->setText(sourceText(QStringLiteral("采集时限（秒，0 为持续）")));
    m_networkTrafficLabel->setText(sourceText(QStringLiteral("网络采集")));
    m_networkTraffic->setItemText(0, sourceText(QStringLiteral("不采集")));
    m_networkTraffic->setItemText(1, QStringLiteral("raw-socket")); // 后端稳定来源名，热切换不改变当前选择。
    m_networkTraffic->setItemText(2, QStringLiteral("existing-wfp"));
    m_networkTraffic->setAccessibleName(m_networkTrafficLabel->text()); // 辅助技术沿可见标签识别来源选择。
    m_networkTraffic->setToolTip(sourceText(QStringLiteral("与 API 使用同一采样和写入线程；自动接管时在调用放行前追加目标，根进程退出后继续采集。报文归属仍为 PID 线索，不解密 HTTPS。JSONL 跟随不启用。")));
    m_captureAgentEtw->setText(sourceText(QStringLiteral("采集自有 Agent ETW")));
    m_captureAgentEtw->setToolTip(sourceText(QStringLiteral("与 API 使用同一采样；自动接管目标在调用放行前加入同一 ETW 来源。报头 PID 仅作线索，JSONL 跟随不启用。")));
    m_duration->setSpecialValueText(sourceText(QStringLiteral("持续采集")));
    m_duration->setToolTip(sourceText(QStringLiteral("从 Agent Ready 与覆盖核验通过后计时，最多 120 秒；0 表示持续采集。")));
    m_pathLabel->setText(sourceText(QStringLiteral("本地 API JSONL")));
    m_sessionLabel->setText(sourceText(QStringLiteral("来源会话 ID")));
    m_pidLabel->setText(sourceText(QStringLiteral("来源 PID")));
    m_creationLabel->setText(sourceText(QStringLiteral("进程创建 FILETIME")));
    m_browse->setAccessibleName(sourceText(QStringLiteral("选择已授权的 API JSONL")));
    m_archive->setAccessibleName(sourceText(QStringLiteral("打开 API 采样归档")));
    renderReceipt();
    updateControls();
    if (statusChanged)
    {
        statusChanged();
    }
}
}
