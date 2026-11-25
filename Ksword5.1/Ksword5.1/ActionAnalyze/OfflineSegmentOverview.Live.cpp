#include "OfflineSegmentOverview.h"
#include "LiveEtwCapture.h"

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

void OfflineSegmentOverview::createLiveControls(QWidget* band, ks::ui::FlowLayout* controls)
{
    // 采样参数留在同一工具带内，输入与开始动作一起换行。
    m_pidInput = new QLineEdit(band);
    m_pidInput->setObjectName(QStringLiteral("action_analyze_target_pid"));
    m_pidInput->setMaxLength(10);
    m_pidInput->setMaximumWidth(132);
    m_providerInput = new QLineEdit(band);
    m_providerInput->setObjectName(QStringLiteral("action_analyze_etw_provider"));
    m_providerInput->setMaxLength(38);
    m_startLive = new QPushButton(band);
    m_startLive->setObjectName(QStringLiteral("action_analyze_start"));
    m_stopLive = new QPushButton(band);
    m_stopLive->setObjectName(QStringLiteral("action_analyze_stop"));
    m_followLive = new QPushButton(band);
    ks::ui::ApplyFlatButtonTheme(m_startLive, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_startLive, QIcon(QStringLiteral(":/Icon/process_resume.svg")));
    ks::ui::SetThemeButtonIcon(m_stopLive, QIcon(QStringLiteral(":/Icon/process_stop.svg")));
    KswordTheme::ApplyStandardIconButtonMetrics(m_stopLive);
    controls->addWidget(m_pidInput);
    controls->addExpandingWidget(m_providerInput, 185);
    controls->addWidget(m_startLive);
    controls->addWidget(m_stopLive);
    controls->addWidget(m_followLive);

    // 实时会话由独立后台操作负责，轮询只在界面线程发布值化快照。
    m_liveOperation = new ks::ui::AsyncOperation(this);
    m_liveTimer = new QTimer(this);
    m_liveTimer->setInterval(250);
    ks::ui::BackgroundTaskRegistry::Policy policy; // 可调整展示间隔，采集本身独立运行。
    policy.canPause = false;
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
    connect(m_followLive, &QPushButton::clicked, this, &OfflineSegmentOverview::followLive);
}

void OfflineSegmentOverview::startLive()
{
    if (!m_liveRegistered || m_liveBusy || m_liveRecovery || m_reading)
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
    m_live = std::make_shared<LiveEtwCapture>(m_projectId, static_cast<quint32>(pid), provider);
    m_liveBusy = true;
    m_liveStopping = false;
    m_followingLive = true;
    m_liveFeedback = sourceText(QStringLiteral("正在启动监控与预设分析。"));
    m_liveTimer->start();
    m_liveOperation->submit<std::shared_ptr<LiveEtwCapture>, LiveEtwReceipt>(m_live,
        [](const auto& capture, const ks::ui::AsyncOperationToken& token) { return capture->collect(token); },
        [this](const LiveEtwReceipt& result, quint64) { finishLive(result); return true; },
        [this](std::exception_ptr) { finishLive({false, true, sourceText(QStringLiteral("ETW 采样未能正常结束。"))}); });
    updateText();
}

void OfflineSegmentOverview::stopLive()
{
    if (!m_live || m_liveStopping)
    {
        return;
    }
    // 请求收尾时原所有者仍负责排空。失败后的重试只能使用原会话。
    m_liveStopping = true;
    m_liveFeedback = sourceText(QStringLiteral("正在停止监控。"));
    if (m_liveRecovery && !m_liveBusy)
    {
        m_liveBusy = true;
        m_liveOperation->submit<std::shared_ptr<LiveEtwCapture>, LiveEtwReceipt>(m_live,
            [](const auto& capture, const ks::ui::AsyncOperationToken&) { return capture->recover(); },
            [this](const LiveEtwReceipt& result, quint64) { finishLive(result); return true; },
            [this](std::exception_ptr) { finishLive({false, true, sourceText(QStringLiteral("ETW 采样未能正常结束。"))}); });
    }
    else if (m_liveBusy)
    {
        m_live->requestStop();
    }
    updateText();
}

void OfflineSegmentOverview::refreshLive(bool final)
{
    if (!m_live)
    {
        return;
    }
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
        const auto feedback = sourceText(QStringLiteral("正在监控 · 进程活动分析 · %1 · 未归档")).arg(coverage);
        if (feedback != m_liveFeedback)
        {
            m_liveFeedback = feedback;
            if (sessionStatusChanged)
            {
                sessionStatusChanged(m_liveFeedback);
            }
        }
    }
    if (!final && !isVisible())
    {
        return;
    }
    const bool live = m_snapshot && m_snapshot->live; // 当前可见来源。
    const auto next = m_live->preview(live ? m_snapshot->sampleId : QString(), m_snapshot ? m_snapshot->rows.size() : -1);
    if (!next)
    {
        return;
    }
    // 菜单等操作锁住模型期间，按同一通道延迟提交最新快照。
    const auto owner = m_live; // 延迟回调只允许当前会话覆写当前模型。
    ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("action_analyze_live"), {m_host},
        [this, owner, snapshot = *next]() {
            if (owner != m_live || m_reading)
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

void OfflineSegmentOverview::finishLive(const LiveEtwReceipt& result)
{
    // 先接收最终记录，再发布实际清退状态。未知损失保持空缺。
    refreshLive(true);
    m_liveTimer->stop();
    m_liveBusy = false;
    m_liveStopping = false;
    m_liveRecovery = result.recovery;
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
        m_liveFeedback = sourceText(QStringLiteral("监控已停止 · ETW 丢失事件 %1 · 预览超限 %2 · 未归档"))
            .arg(loss, QString::number(result.omitted));
        if (result.end == CaptureEnd::TargetExited)
        {
            m_liveFeedback += u' ' + sourceText(QStringLiteral("目标进程已退出。"));
        }
        else if (result.end == CaptureEnd::TimeLimit)
        {
            m_liveFeedback += u' ' + sourceText(QStringLiteral("已达到采样时限。"));
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
    updateText();
}

void OfflineSegmentOverview::followLive()
{
    // 清除拖选范围时保留关键字、对象和类别条件，也不重选记录。
    m_followingLive = true;
    m_start->clear();
    m_end->clear();
    applyTimeRange();
    m_followingLive = true;
    m_table->scrollToBottom();
    updateText();
}

void OfflineSegmentOverview::updateLiveControls()
{
    // 语言变化与进度更新都复用同一套动作说明与可用性逻辑。
    m_pidInput->setPlaceholderText(sourceText(QStringLiteral("目标 PID")));
    m_pidInput->setAccessibleName(m_pidInput->placeholderText());
    m_providerInput->setAccessibleName(QStringLiteral("ETW Provider GUID"));
    m_providerInput->setPlaceholderText(sourceText(QStringLiteral("ETW Provider GUID（可选）")));
    m_providerInput->setToolTip(sourceText(QStringLiteral("留空时只分析进程活动。辅助采集 Kernel-File 需要系统授权。")));
    m_startLive->setText(sourceText(QStringLiteral("开始监控")));
    m_startLive->setToolTip(sourceText(QStringLiteral("开始监控与预设分析，最长 120 秒。每秒分析进程 CPU 和 I/O，同步尝试采集所选 ETW 来源。")));
    m_stopLive->setAccessibleName(sourceText(QStringLiteral("停止监控")));
    m_stopLive->setToolTip(m_liveRecovery ? sourceText(QStringLiteral("重试清退原 ETW 会话。")) : m_stopLive->accessibleName());
    m_followLive->setText(sourceText(QStringLiteral("恢复实时")));
    m_followLive->setToolTip(sourceText(QStringLiteral("清除时间范围并继续跟随最新事件。")));
    const bool canStart = m_liveRegistered && !m_liveBusy && !m_liveRecovery && !m_reading; // 不并发覆盖来源。
    m_startLive->setEnabled(canStart);
    m_stopLive->setEnabled((m_liveBusy || m_liveRecovery) && !m_liveStopping);
    m_followLive->setEnabled(m_liveBusy && m_snapshot && m_snapshot->live && !m_followingLive);
    m_open->setEnabled(!m_liveBusy && !m_liveRecovery);
    m_pidInput->setEnabled(canStart);
    m_providerInput->setEnabled(canStart);
    if (sessionStatusChanged)
    {
        sessionStatusChanged(m_liveFeedback);
    }
}
}
