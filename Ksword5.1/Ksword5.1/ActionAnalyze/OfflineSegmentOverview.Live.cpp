#include "OfflineSegmentOverview.h"
#include "LiveEtwCapture.h"
#include "ToolbarCapabilities.h"

#include "../Framework/BackgroundTaskRegistry.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/FlowLayout.h"
#include "../UI/ResultTableHost.h"
#include "../UI/ThemeAccentIcon.h"
#include "../theme.h"

#include <QLineEdit>
#include <QPushButton>
#include <QTableView>
#include <QTimer>
#include <limits>

namespace ks::action_analyze
{
using ks::i18n::sourceText;
namespace
{
    // 将资格阶段转成当前语言的悬停说明。reason 来自工具条共用判定器。
    QString CaptureActionDisabledText(ToolbarDisabledReason reason)
    {
        switch (reason)
        {
        case ToolbarDisabledReason::CaptureAlreadyInProgress:
            return sourceText(QStringLiteral("已有监控会话在运行或启动中。"));
        case ToolbarDisabledReason::CaptureStopping:
            return sourceText(QStringLiteral("正在停止监控。"));
        case ToolbarDisabledReason::CaptureCleanupPending:
            return sourceText(QStringLiteral("请先完成上一次监控的清退。"));
        case ToolbarDisabledReason::ArchiveReadInProgress:
            return sourceText(QStringLiteral("正在读取归档。"));
        // 已在跟随和等待下一次发布都不需要用户重复启动跟随。
        case ToolbarDisabledReason::AlreadyFollowing:
            return sourceText(QStringLiteral("正在跟随实时记录。"));
        case ToolbarDisabledReason::FollowingAwaitingPreview:
            return sourceText(QStringLiteral("正在等待本次监控的实时记录。"));
        case ToolbarDisabledReason::PreviewUnavailable:
            return sourceText(QStringLiteral("没有可显示的实时窗口。"));
        case ToolbarDisabledReason::CaptureUnavailable:
            return sourceText(QStringLiteral("当前无法启动监控。"));
        default:
            return sourceText(QStringLiteral("当前没有可停止的监控会话。"));
        }
    }

    // 将归档收尾与活动会话状态分开报告；分段回读不代表已发布双流检查点。
    QString ArchiveText(bool hasProject, const LiveArchiveStatus& archive)
    {
        if (!hasProject)
        {
            return sourceText(QStringLiteral("未归档"));
        }
        if (!archive.error.isEmpty())
        {
            return sourceText(QStringLiteral("归档失败，已核验 %1 段：%2")).arg(archive.verifiedSegments).arg(archive.error);
        }
        return (archive.finished
            ? sourceText(QStringLiteral("归档已收尾 · 已核验 %1 个原始段 · 未归档记录 %2 条"))
            : sourceText(QStringLiteral("归档中 · 已核验 %1 个原始段 · 队列丢失 %2 条")))
            .arg(archive.verifiedSegments).arg(archive.dropped);
    }
}

// 组装共享工具带和后台任务登记。显隐只影响实时投影，不改变原生所有权。
void OfflineSegmentOverview::createLiveControls(ks::ui::FlowLayout* parameters, ks::ui::FlowLayout* actions)
{
    // 采样参数保持在工作台，浮窗只承载操作按钮。
    auto* inputBand = parameters->parentWidget(); // 参数输入随总览布局换行。
    auto* actionBand = actions->parentWidget(); // 浮出时保留原按钮的身份与连接。
    m_pidInput = new QLineEdit(inputBand);
    m_pidInput->setObjectName(QStringLiteral("action_analyze_target_pid"));
    m_pidInput->setMaxLength(10);
    m_pidInput->setMaximumWidth(132);
    m_providerInput = new QLineEdit(inputBand);
    m_providerInput->setObjectName(QStringLiteral("action_analyze_etw_provider"));
    m_providerInput->setMaxLength(38);
    m_startLive = new QPushButton(actionBand);
    m_startLive->setObjectName(QStringLiteral("action_analyze_start"));
    m_stopLive = new QPushButton(actionBand);
    m_stopLive->setObjectName(QStringLiteral("action_analyze_stop"));
    m_followLive = new QPushButton(actionBand);
    m_followLive->setObjectName(QStringLiteral("action_analyze_follow_live"));
    m_captureArchive = new QPushButton(actionBand);
    m_captureArchive->setObjectName(QStringLiteral("action_analyze_open_capture_archive"));
    KswordTheme::ApplyStandardIconButtonMetrics(m_captureArchive);
    ks::ui::SetThemeButtonIcon(m_captureArchive, QIcon(QStringLiteral(":/Icon/process_open_folder.svg")));
    m_breakpointPage = new QPushButton(actionBand);
    m_breakpointPage->setObjectName(QStringLiteral("action_analyze_open_breakpoints"));
    KswordTheme::ApplyStandardIconButtonMetrics(m_breakpointPage);
    ks::ui::SetThemeButtonIcon(m_breakpointPage, QIcon(QStringLiteral(":/Icon/window_picker_target.svg")));
    ks::ui::ApplyFlatButtonTheme(m_startLive, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_startLive, QIcon(QStringLiteral(":/Icon/process_resume.svg")));
    ks::ui::SetThemeButtonIcon(m_stopLive, QIcon(QStringLiteral(":/Icon/process_stop.svg")));
    KswordTheme::ApplyStandardIconButtonMetrics(m_startLive);
    KswordTheme::ApplyStandardIconButtonMetrics(m_stopLive);
    parameters->addWidget(m_pidInput);
    parameters->addExpandingWidget(m_providerInput, 185);
    actions->addWidget(m_startLive);
    actions->addWidget(m_stopLive);
    actions->addWidget(m_captureArchive);
    actions->addWidget(m_followLive);
    actions->addWidget(m_breakpointPage);

    // 实时会话由独立后台操作负责，轮询只在界面线程发布值化快照。
    m_liveOperation = new ks::ui::AsyncOperation(this);
    m_liveTimer = new QTimer(this);
    m_liveTimer->setInterval(250);
    ks::ui::BackgroundTaskRegistry::Policy policy; // 可调整展示间隔，采集本身独立运行。
    policy.canPause = false;
    policy.restriction = sourceText(QStringLiteral("仅调整总览刷新间隔，不影响采集与归档。"));
    policy.eligible = [this]() { return m_liveBusy; };
    auto& registry = ks::ui::BackgroundTaskRegistry::instance(); // 两个登记项共用同一采集所有者。
    const auto id = QStringLiteral("monitor.action_analyze.etw_preview"); // 真实工作台仅有一个实例。
    const bool timerRegistered = registry.addTimer(id, sourceText(QStringLiteral("行为分析")),
        sourceText(QStringLiteral("监控")), m_liveTimer, std::move(policy));
    ks::ui::BackgroundTaskRegistry::External session; // 原生任务只提供实际运行状态。
    session.running = [this]() { return m_live && m_live->running(); };
    m_liveRegistered = timerRegistered && registry.addExternal(QStringLiteral("monitor.action_analyze.capture"),
        sourceText(QStringLiteral("进程活动分析")), sourceText(QStringLiteral("监控")), this, std::move(session),
        sourceText(QStringLiteral("请在行为分析总览停止采样。")));
    connect(m_liveTimer, &QTimer::timeout, this, [this]() { refreshLive(); });
    connect(m_startLive, &QPushButton::clicked, this, &OfflineSegmentOverview::startLive);
    connect(m_stopLive, &QPushButton::clicked, this, &OfflineSegmentOverview::stopLive);
    connect(m_captureArchive, &QPushButton::clicked, this, &OfflineSegmentOverview::openCapturedArchive);
    connect(m_followLive, &QPushButton::clicked, this, &OfflineSegmentOverview::followLive);
    connect(m_breakpointPage, &QPushButton::clicked, this, [this]() {
        // 入口仅切换工作台页签，不应用表单草稿。
        if (toolbarCapabilities().openBreakpointDefinitions.enabled())
        {
            openBreakpointPage();
        }
    });
}

// 从项目页转到现有采样草稿，复用 PID 控件的原访问和校验行为。
void OfflineSegmentOverview::focusScanTarget()
{
    if (m_pidInput->isEnabled())
    {
        m_pidInput->setFocus(Qt::OtherFocusReason);
    }
}

// 显式启动常驻采集，冻结项目和过滤参数；开始失败仍保留上一份证据。
void OfflineSegmentOverview::startLive()
{
    if (!toolbarCapabilities().startCapture.enabled())
    {
        return;
    }
    // 读取草稿并冻结目标与 provider。错误会保留之前的结果和筛选。
    bool pidValid = false; // 十进制 32 位进程号。
    const auto pid = m_pidInput->text().toULongLong(&pidValid);
    const auto providerText = m_providerInput->text().trimmed(); // 留空时只采样目标活动。
    const QUuid provider(providerText); // 非空文本必须是有效 provider GUID。
    if (!pidValid || !pid || pid > (std::numeric_limits<quint32>::max)() || (!providerText.isEmpty() && provider.isNull()))
    {
        m_liveFeedback = sourceText(QStringLiteral("请输入有效的 PID。ETW Provider GUID 可以留空。"));
        updateText();
        return;
    }
    m_liveManifest = m_projectManifest;
    m_liveProjectId = m_projectId;
    m_announcedSample.clear();
    m_live = std::make_shared<LiveEtwCapture>(LiveArchiveProject{m_liveManifest, m_liveProjectId, m_projectRevision},
        static_cast<quint32>(pid), provider);
    m_liveBusy = true;
    m_liveStopping = false;
    m_liveHasRows = false;
    m_followingLive = true;
    m_livePreviewEnabled = true;
    m_liveFeedback = sourceText(QStringLiteral("正在启动监控与预设分析。"));
    m_liveTimer->start();
    const auto accepted = m_liveOperation->submit<std::shared_ptr<LiveEtwCapture>, LiveEtwReceipt>(m_live,
        [](const auto& capture, const ks::ui::AsyncOperationToken& token) { return capture->collect(token); },
        [this](const LiveEtwReceipt& result, quint64) { finishLive(result); return true; },
        [this](std::exception_ptr) { finishLive({false, true, sourceText(QStringLiteral("ETW 采样未能正常结束。"))}); });
    if (!accepted)
    {
        finishLive({false, false, sourceText(QStringLiteral("ETW 采样未能正常结束。"))});
    }
    updateText();
}

// 发给原始所有者停止意图；清退失败时重试原会话，绝不另开采样。
void OfflineSegmentOverview::stopLive()
{
    if (!toolbarCapabilities().stopCapture.enabled())
    {
        return;
    }
    // 请求收尾时原所有者仍负责排空。失败后的重试只能使用原会话。
    m_liveStopping = true;
    m_liveFeedback = sourceText(QStringLiteral("正在停止监控。"));
    if (m_liveRecovery && !m_liveBusy)
    {
        m_liveBusy = true;
        const auto accepted = m_liveOperation->submit<std::shared_ptr<LiveEtwCapture>, LiveEtwReceipt>(m_live,
            [](const auto& capture, const ks::ui::AsyncOperationToken&) { return capture->recover(); },
            [this](const LiveEtwReceipt& result, quint64) { finishLive(result); return true; },
            [this](std::exception_ptr) { finishLive({false, true, sourceText(QStringLiteral("ETW 采样未能正常结束。"))}); });
        if (!accepted)
        {
            finishLive({false, true, sourceText(QStringLiteral("ETW 采样未能正常结束。"))});
        }
    }
    else if (m_liveBusy)
    {
        m_live->requestStop();
    }
    updateText();
}

// 回读状态可跨 Tab，重建表与轴仅在页面可见且跟随时进行。
void OfflineSegmentOverview::refreshLive(bool final)
{
    if (!m_live)
    {
        return;
    }
    const auto registered = m_live->registeredSample(); // 只有真实磁盘登记才刷新项目目录。
    if (registered && registered->sample.id != m_announcedSample)
    {
        m_announcedSample = registered->sample.id;
        if (liveSampleRegistered)
        {
            liveSampleRegistered(m_liveManifest, m_liveProjectId);
        }
    }
    updateCapturedArchiveAction();
    // 有新结果才替换前次采样。即使表格不变也回读 ETW 独立状态。
    if (!m_liveStopping && !final && m_live->running())
    {
        const QString coverage = [this]() {
            switch (m_live->coverage())
            {
            case EtwCoverage::Disabled: return sourceText(QStringLiteral("ETW 未启用"));
            case EtwCoverage::Starting: return sourceText(QStringLiteral("ETW 启动中"));
            case EtwCoverage::Active: return sourceText(QStringLiteral("ETW 采集中"));
            case EtwCoverage::Unavailable: return sourceText(QStringLiteral("ETW 不可用"));
            }
            return QString();
        }();
        const auto feedback = sourceText(QStringLiteral("正在监控 · 进程活动分析 · %1 · %2"))
            .arg(coverage, ArchiveText(!m_liveManifest.isEmpty(), m_live->archiveStatus()));
        if (feedback != m_liveFeedback)
        {
            m_liveFeedback = feedback;
            if (sessionStatusChanged)
            {
                sessionStatusChanged(m_liveFeedback);
            }
        }
    }
    if (!m_livePreviewEnabled || m_reading || !isVisible() || !m_followingLive || liveViewInteracting())
    {
        return;
    }
    const bool live = m_snapshot && m_snapshot->live; // 当前可见来源。
    const auto next = m_live->preview(live ? m_snapshot->sampleId : QString(), live ? m_snapshot->liveRevision : 0,
        m_snapshot && !m_snapshot->rows.isEmpty());
    if (!next)
    {
        return;
    }
    // 菜单等操作锁住模型期间，按同一通道延迟提交最新快照。
    const auto owner = m_live; // 延迟回调只允许当前会话覆写当前模型。
    const auto readGeneration = m_read->generation(); // 其后用户发起的归档读取才拥有展示权。
    ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("action_analyze_live"), {m_host},
        [this, owner, readGeneration, snapshot = *next]() {
            if (owner != m_live || !m_livePreviewEnabled || m_reading || readGeneration != m_read->generation() || !isVisible() ||
                !m_followingLive || liveViewInteracting())
            {
                return;
            }
            if (m_snapshot && m_snapshot->live && m_snapshot->sampleId == snapshot.sampleId &&
                m_snapshot->liveRevision >= snapshot.liveRevision)
            {
                return;
            }
            setActiveSnapshot(snapshot);
            if (m_followingLive && m_table->model()->rowCount())
            {
                m_table->scrollToBottom();
            }
        });
}

// 采集终态与归档状态独立发布；当前暂停的时间轴不被收尾刷新重置。
void OfflineSegmentOverview::finishLive(const LiveEtwReceipt& result)
{
    // 先接收最终记录，再发布实际清退状态。未知损失保持空缺。
    refreshLive(true);
    m_liveTimer->stop();
    m_liveBusy = false;
    m_liveStopping = false;
    m_liveRecovery = result.recovery;
    m_liveHasRows = m_liveHasRows || result.hasRows;
    if (result.recovery)
    {
        m_liveFeedback = sourceText(QStringLiteral("ETW 采样清退未完成：%1")).arg(result.error);
    }
    else if (!result.error.isEmpty())
    {
        m_liveFeedback = sourceText(QStringLiteral("监控启动失败：%1")).arg(result.error);
    }
    else if (result.processError)
    {
        m_liveFeedback = sourceText(QStringLiteral("进程活动采样中断（Windows %1）· 已保留结果"))
            .arg(result.processError);
    }
    else
    {
        const auto loss = result.loss ? QString::number(*result.loss) : QStringLiteral("—"); // ETW 尚无统计时不填零。
        m_liveFeedback = sourceText(QStringLiteral("监控已停止 · ETW 丢失事件 %1 · 实时窗口移出旧记录 %2"))
            .arg(loss, QString::number(result.evicted));
        if (result.end == CaptureEnd::TargetExited)
        {
            m_liveFeedback += u' ' + sourceText(QStringLiteral("目标进程已退出。"));
        }
        if (!result.hasRows)
        {
            m_liveFeedback += u' ' + sourceText(QStringLiteral("本次未产生记录。"));
        }
    }
    if (!result.etwIssue.isEmpty() && !result.recovery)
    {
        m_liveFeedback += u' ' + sourceText(QStringLiteral("ETW 来源受限：%1")).arg(result.etwIssue);
    }
    if (result.error.isEmpty() || result.recovery)
    {
        m_liveFeedback += u' ' + ArchiveText(!m_liveManifest.isEmpty(), result.archive);
    }
    updateText();
}

// 恢复最近窗口时只清除已提交时间范围，不覆盖尚未提交的输入草稿。
void OfflineSegmentOverview::followLive()
{
    // 从归档返回时，保留归档结果，直至同一采样有可提交的实时快照。
    if (!toolbarCapabilities().followLive.enabled())
    {
        return;
    }
    m_livePreviewEnabled = true;
    m_followingLive = true;
    if (m_snapshot && m_snapshot->live)
    {
        if (m_start->text().trimmed() == (m_lower ? QString::number(*m_lower) : QString()) &&
            m_end->text().trimmed() == (m_upper ? QString::number(*m_upper) : QString()))
        {
            m_start->clear();
            m_end->clear();
        }
        m_lower.reset();
        m_upper.reset();
        m_invalidRange = false;
        applyFilters();
        m_table->scrollToBottom();
    }
    refreshLive();
    updateText();
}

// 工具条点击时冻结真实采样，调用共用后台回读。成功受理后由工作台定位总览，无返回值。
void OfflineSegmentOverview::openCapturedArchive()
{
    // 首段已经写入并回读后才可重开，方便区分正在等首段和读档过程中遇到异常。
    if (!toolbarCapabilities().openCaptureArchive.enabled())
    {
        return;
    }
    const auto sample = m_live->registeredSample(); // 按采集 owner 确定项目、目录行和描述散列。
    if (sample && openSampleArchive(*sample) && activateOverview)
    {
        activateOverview();
    }
}

// 根据采样的刷盘回执同步当前按钮资格和提示。此函数只读取现有内存状态。
void OfflineSegmentOverview::updateCapturedArchiveAction()
{
    const auto eligibility = toolbarCapabilities().openCaptureArchive; // 与点击守卫使用同一会话快照。
    m_captureArchive->setEnabled(eligibility.enabled());
    const auto title = sourceText(QStringLiteral("打开本次监控归档")); // 内嵌和浮窗共用的动作名称。
    m_captureArchive->setAccessibleName(title);
    QString hint = title; // 已有归档时用动作名，禁用时说明当前阻塞原因。
    if (eligibility.reason == ToolbarDisabledReason::CaptureProjectMissing)
    {
        hint = sourceText(QStringLiteral("在已打开的项目中开始监控后可查看归档。"));
    }
    else if (eligibility.reason == ToolbarDisabledReason::ArchiveReadInProgress)
    {
        hint = sourceText(QStringLiteral("正在读取归档。"));
    }
    else if (eligibility.reason == ToolbarDisabledReason::CaptureArchiveUnverified)
    {
        const auto archive = m_live->archiveStatus(); // 可安全回读当前所有者的首个写入诊断。
        hint = archive.error.isEmpty() ? sourceText(QStringLiteral("尚无已核验的监控归档段。")) : archive.error;
    }
    m_captureArchive->setToolTip(hint);
}

// 读取会话和表格的真实状态，返回按钮可用性。无文件查询或 UI 修改。
ToolbarOverviewCapabilities OfflineSegmentOverview::toolbarCapabilities() const
{
    ToolbarOverviewState state; // 原所有者、归档读入和显示状态保持为不同字段。
    if (m_liveStopping)
    {
        state.capturePhase = ToolbarCapturePhase::Stopping;
    }
    else if (m_liveBusy)
    {
        state.capturePhase = m_live && m_live->running() ? ToolbarCapturePhase::Capturing : ToolbarCapturePhase::Starting;
    }
    else if (m_liveRecovery)
    {
        state.capturePhase = ToolbarCapturePhase::CleanupPending;
    }
    else if (m_live)
    {
        state.capturePhase = ToolbarCapturePhase::Ended;
    }
    // 即使正在浏览其他项目，当前采样仍然归属于启动时冻结的项目。
    state.captureRegistered = m_liveRegistered;
    state.hasCaptureOwner = bool(m_live);
    state.captureHasPreviewRows = m_liveHasRows;
    if (m_live)
    {
        state.captureSample = {m_liveProjectId, m_live->sampleId()};
        state.verifiedCaptureArchive = m_live->archiveStatus().verifiedSegments != 0;
    }
    state.readingArchive = m_reading;
    if (m_snapshot)
    {
        state.viewSource = m_snapshot->live ? ToolbarViewSource::Live : ToolbarViewSource::Archive;
        state.viewSample = {m_snapshot->projectId, m_snapshot->sampleId};
    }
    // 暂停跟随只影响预览，不改变底层会话阶段或采样归属。
    state.livePreviewEnabled = m_livePreviewEnabled;
    state.followingLive = m_followingLive;
    state.breakpointPageAvailable = bool(openBreakpointPage);
    return EvaluateToolbarOverview(state);
}

// 更新语言与实际资格；图标按钮同时提供可访问名称及操作提示。
void OfflineSegmentOverview::updateLiveControls()
{
    // 语言变化与进度更新都复用同一套动作说明与可用性逻辑。
    m_pidInput->setPlaceholderText(sourceText(QStringLiteral("目标 PID")));
    m_pidInput->setAccessibleName(m_pidInput->placeholderText());
    m_providerInput->setAccessibleName(QStringLiteral("ETW Provider GUID"));
    m_providerInput->setPlaceholderText(sourceText(QStringLiteral("ETW Provider GUID（可选）")));
    m_providerInput->setToolTip(sourceText(QStringLiteral("留空时只分析进程活动。辅助采集 Kernel-File 需要系统授权。")));
    const auto capabilities = toolbarCapabilities(); // 按钮状态和点击守卫使用同一规则。
    m_startLive->setAccessibleName(sourceText(QStringLiteral("开始监控")));
    const QString startHint = m_projectManifest.isEmpty()
        ? sourceText(QStringLiteral("开始监控。持续采集到手动停止或目标退出；未打开项目，仅保留实时窗口。"))
        : sourceText(QStringLiteral("开始监控并保存到当前项目：%1。持续采集到手动停止或目标退出。")).arg(m_projectManifest);
    m_startLive->setToolTip(capabilities.startCapture.enabled() ? startHint
        : CaptureActionDisabledText(capabilities.startCapture.reason));
    m_stopLive->setAccessibleName(sourceText(QStringLiteral("停止监控")));
    m_stopLive->setToolTip(!capabilities.stopCapture.enabled() ? CaptureActionDisabledText(capabilities.stopCapture.reason)
        : m_liveRecovery ? sourceText(QStringLiteral("重试清退原 ETW 会话。")) : m_stopLive->accessibleName());
    m_followLive->setText(sourceText(QStringLiteral("恢复实时")));
    m_breakpointPage->setAccessibleName(sourceText(QStringLiteral("打开全局断点")));
    m_breakpointPage->setToolTip(m_breakpointPage->accessibleName());
    m_breakpointPage->setEnabled(capabilities.openBreakpointDefinitions.enabled());
    updateActionToolbarText();
    updateCapturedArchiveAction();
    const bool archiveView = m_snapshot && !m_snapshot->live; // 当前可见结果来自归档。
    m_followLive->setToolTip(!capabilities.followLive.enabled() ? CaptureActionDisabledText(capabilities.followLive.reason)
        : archiveView ? sourceText(QStringLiteral("返回最近一次监控的实时窗口。"))
        : sourceText(QStringLiteral("清除时间范围并继续跟随最新事件。")));
    const bool canStart = capabilities.startCapture.enabled(); // 参数编辑资格保持与开始监控一致。
    m_startLive->setEnabled(canStart);
    m_stopLive->setEnabled(capabilities.stopCapture.enabled());
    m_followLive->setEnabled(capabilities.followLive.enabled());
    m_pidInput->setEnabled(canStart);
    m_providerInput->setEnabled(canStart);
    if (sessionStatusChanged)
    {
        sessionStatusChanged(m_liveFeedback);
    }
}
}
