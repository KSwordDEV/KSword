#include "../Framework.h"
#include "PassiveApiCapturePane.h"
#include "ApiTransferPresentation.h"

#include "../Framework/BackgroundTaskRegistry.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ParameterWorkspace.h"
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
#include <QTabBar>
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
    workspace->parameters()->addWidget(source);
    m_sourceGroup = source;
    ks::ui::StyleParameterSection(source);

    // 选择器与开始/停止均放在固定动作带；状态与已提交回执保留剩余高度。
    auto* footer = workspace->actions()->parentWidget(); // 动作由共享工具条统一度量。
    m_browse = IconButton(footer, "action_analyze_api_browse", ":/Icon/process_open_folder.svg");
    m_start = IconButton(footer, "action_analyze_api_start", ":/Icon/process_resume.svg");
    m_stop = IconButton(footer, "action_analyze_api_stop", ":/Icon/process_stop.svg");
    m_archive = IconButton(footer, "action_analyze_api_archive", ":/Icon/process_details.svg");
    ks::ui::ApplyFlatButtonTheme(m_start, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
    for (auto* button : {m_browse, m_start, m_stop, m_archive}) // 固定动作顺序同采样步骤。
    {
        workspace->actions()->addWidget(button);
    }
    workspace->actions()->addStretch();
    m_status = new QLabel(workspace);
    m_status->setObjectName(QStringLiteral("action_analyze_api_status"));
    m_status->setTextFormat(Qt::PlainText);
    m_status->setWordWrap(true);
    workspace->results()->addWidget(m_status);
    m_fields = new ks::ui::StructuredFieldView(workspace);
    m_fields->setObjectName(QStringLiteral("action_analyze_api_receipt"));
    m_fields->setValueModelProjection();
    m_fields->setHiddenProjectionDeferred();
    workspace->results()->addWidget(m_fields, 1);
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
    connect(m_start, &QPushButton::clicked, this, &PassiveApiCapturePane::start);
    connect(m_stop, &QPushButton::clicked, this, &PassiveApiCapturePane::stop);
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
    if (m_busy || m_sourceMode->currentIndex() != 0)
    {
        return;
    }
    const auto path = QFileDialog::getOpenFileName(this, sourceText(QStringLiteral("选择已授权的 API JSONL")),
        m_path->text(), sourceText(QStringLiteral("API JSONL 文件 (*.jsonl)")), nullptr, QFileDialog::ReadOnly);
    if (!path.isEmpty())
    {
        m_path->setText(path);
        m_path->setToolTip(path);
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
    const bool live = request.cooperative || request.explicitAttachment; // 文件草稿保留在控件内，不混进活采请求。
    request.path = live ? QString() : m_path->text();
    request.sessionId = live ? 0 : Identity<quint64>(m_session);
    request.pid = Identity<quint32>(m_pid);
    request.creationTime = Identity<quint64>(m_creation);
    request.durationMs = live ? static_cast<quint32>(m_duration->value()) * 1000 : 0;
    // 标题与目标一同冻结；切换语言或编辑下一轮草稿不改变当前后台采样。
    if (live)
    {
        request.cooperativeTitle = sourceText(request.explicitAttachment ? QStringLiteral("显式 API 附加（PID %1）") :
            QStringLiteral("合作 Agent（PID %1）")).arg(request.pid);
    }
    const bool invalidSource = live ? request.pid <= 4 || request.pid == GetCurrentProcessId()
        : request.path.isEmpty() || !request.sessionId || !request.pid;
    if (invalidSource || !request.creationTime)
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
        ? sourceText(QStringLiteral("附加需要本次明确确认，且合作、文件与显式附加来源不能混用。")) : receipt.error;
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
    if (m_owner->request().cooperative || m_owner->request().explicitAttachment)
    {
        // 未越过启动屏障时只显示等待状态。
        if (m_stopping)
        {
            return sourceText(QStringLiteral("正在停止 API 活采并归档"));
        }
        if (m_busy)
        {
            return m_liveCoverageRevision
                ? sourceText(QStringLiteral("Agent 已就绪 · 覆盖修订 %1 · 正在采样")).arg(m_liveCoverageRevision)
                : sourceText(QStringLiteral("API 活采请求处理中，等待 Ready 与覆盖核验"));
        }
        if (!m_startError.isEmpty() && (m_failed || !m_receipt.agentReady))
        {
            return sourceText(QStringLiteral("API 活采未完成：%1")).arg(m_startError);
        }
        if (m_resultOwner != m_owner)
        {
            return sourceText(QStringLiteral("API 活采未开始"));
        }
        return sourceText(m_receipt.incomplete ? QStringLiteral("API 活采已结束（部分结果）· 已归档 %1 个原包")
            : QStringLiteral("API 活采已结束 · 已归档 %1 个原包")).arg(m_receipt.recordedRows);
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
    const bool live = cooperative || attached; // 活采不会使用文件路径和外部 session。
    m_sourceMode->setEnabled(!m_busy);
    for (auto* field : {static_cast<QWidget*>(m_pathLabel), static_cast<QWidget*>(m_path),
        static_cast<QWidget*>(m_sessionLabel), static_cast<QWidget*>(m_session), static_cast<QWidget*>(m_browse)})
    {
        field->setVisible(!live);
    }
    m_durationLabel->setVisible(live);
    m_duration->setVisible(live);
    m_duration->setEnabled(!m_busy);
    m_sourceHint->setText(sourceText(attached ? QStringLiteral("附加到明确的 PID 与创建 FILETIME；点击开始后确认装载。文件和外部会话 ID 不参与活采。") :
        cooperative ? QStringLiteral("只连接目标已主动加载的产品 Agent，不尝试装载。文件和外部会话 ID 不参与活采。") :
        QStringLiteral("只跟随选中的本地 JSONL，使用文件声明的会话 ID；不会连接或装载目标 Agent。")));
    m_start->setAccessibleName(sourceText(attached ? QStringLiteral("开始显式 API 附加") :
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
    const auto status = m_invalid ? sourceText(live ? QStringLiteral("请输入授权目标的十进制 PID 和创建 FILETIME。")
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
    if (m_owner && m_resultOwner != m_owner && m_owner->request().explicitAttachment)
    {
        // 新请求无采样时单列本轮事实，下面仍保留旧归档的完整来源与可复制文档。
        const auto& request = m_owner->request(); // 本轮确认过的冻结实例和项目。
        const auto yesNo = [](bool value) { return sourceText(value ? QStringLiteral("是") : QStringLiteral("否")); };
        const auto attachmentFact = [&](bool value) {
            return m_busy ? sourceText(QStringLiteral("等待最终回执")) : yesNo(value);
        }; // 装载事实由原控制器终态发布，运行期间不能用默认false冒充已确认的否。
        document.section(QStringLiteral("本次显式 API 附加请求"))
            .field(QStringLiteral("项目清单"), request.manifest)
            .field(QStringLiteral("来源 PID"), QString::number(request.pid))
            .field(QStringLiteral("进程创建 FILETIME"), QString::number(request.creationTime))
            .field(QStringLiteral("采集时限（毫秒，0 为持续）"), QString::number(request.durationMs))
            .field(QStringLiteral("附加实例已核验"), attachmentFact(m_currentReceipt.attachmentIdentityVerified))
            .field(QStringLiteral("已尝试装载 Agent"), attachmentFact(m_currentReceipt.agentLoadAttempted))
            .field(QStringLiteral("Agent 模块已核验"), attachmentFact(m_currentReceipt.agentModuleVerified))
            .field(QStringLiteral("Agent 已就绪"), yesNo(m_currentReceipt.agentReady))
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
        const bool live = request.cooperative || request.explicitAttachment; // 回执使用实际请求，不使用当前选择器。
        document.section(request.explicitAttachment ? QStringLiteral("显式 API 附加来源") :
            request.cooperative ? QStringLiteral("合作 Agent 来源") : QStringLiteral("API JSONL 来源"))
            .field(QStringLiteral("采样 ID"), m_receipt.sample->sample.id)
            .field(QStringLiteral("项目清单"), request.manifest)
            .field(QStringLiteral("来源 PID"), QString::number(request.pid))
            .field(QStringLiteral("进程创建 FILETIME"), QString::number(request.creationTime));
        if (live)
        {
            const auto yesNo = [](bool value) { return sourceText(value ? QStringLiteral("是") : QStringLiteral("否")); };
            if (request.explicitAttachment)
            {
                // 身份、装载与模块存在各自呈现；任一项均不能代替 Ready 和当前覆盖核验。
                const auto attachmentFact = [&](bool value) {
                    return m_busy && m_resultOwner == m_owner
                        ? sourceText(QStringLiteral("等待最终回执")) : yesNo(value);
                }; // 活采归档可以先发布，三个事实仍等待原控制器终态。
                document.field(QStringLiteral("附加实例已核验"), attachmentFact(m_receipt.attachmentIdentityVerified))
                    .field(QStringLiteral("已尝试装载 Agent"), attachmentFact(m_receipt.agentLoadAttempted))
                    .field(QStringLiteral("Agent 模块已核验"), attachmentFact(m_receipt.agentModuleVerified));
            }
            document.field(QStringLiteral("采集时限（毫秒，0 为持续）"), QString::number(request.durationMs));
            document.field(QStringLiteral("来源会话 ID"), m_receipt.cooperativeSession ? QString::number(m_receipt.cooperativeSession) : QStringLiteral("—"))
                .field(QStringLiteral("Agent 已就绪"), yesNo(m_receipt.agentReady))
                .field(QStringLiteral("就绪覆盖修订"), m_receipt.readyCoverageRevision ? QString::number(m_receipt.readyCoverageRevision) : QStringLiteral("—"))
                .field(QStringLiteral("已确认停钩"), yesNo(m_receipt.hooksRemoved))
                .field(QStringLiteral("管道正常读完"), yesNo(m_receipt.cleanPipeEof))
                .field(QStringLiteral("目标已退出"), yesNo(m_receipt.targetExited))
                .field(QStringLiteral("已清退"), yesNo(m_receipt.cleanupComplete))
                .field(QStringLiteral("已核验普通包"), QString::number(m_receipt.validatedRows));
            AppendApiTransferProgress(document, m_receipt.transferCandidates, m_receipt.evictedTransferWrites,
                m_receipt.latestTransfer ? &*m_receipt.latestTransfer : nullptr);
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
        if (!m_receipt.error.isEmpty())
        {
            document.field(QStringLiteral("采样诊断"), m_receipt.error);
        }
    }
    m_fields->setDocument(document);
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
    m_sourceGroup->setTitle(sourceText(QStringLiteral("API 采样")));
    m_sourceMode->setAccessibleName(sourceText(QStringLiteral("API 采样")));
    m_sourceMode->setTabText(0, sourceText(QStringLiteral("JSONL 跟随")));
    m_sourceMode->setTabText(1, sourceText(QStringLiteral("合作已装载")));
    m_sourceMode->setTabText(2, sourceText(QStringLiteral("显式附加")));
    m_sourceMode->setTabToolTip(0, m_sourceMode->tabText(0));
    m_sourceMode->setTabToolTip(1, m_sourceMode->tabText(1));
    m_sourceMode->setTabToolTip(2, m_sourceMode->tabText(2));
    m_durationLabel->setText(sourceText(QStringLiteral("采集时限（秒，0 为持续）")));
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
