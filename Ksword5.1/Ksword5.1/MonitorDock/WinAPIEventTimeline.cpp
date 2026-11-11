#include "WinAPIEventTimeline.h"
#include "WinAPIEventTableModel.h"
#include "ProcessTraceTimelineWidget.h"
#include "../UI/ToolbarMetrics.h"
#include <QCheckBox>
#include <QHBoxLayout>
#include <QPushButton>
#include <QShowEvent>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>

namespace {
struct ProjectionRequest {
    std::vector<ProcessTraceTimelineEventPoint> points;
    ProcessTraceTimelineWidget::EventProjectionParameters projection;
    std::uint64_t epoch = 0, revision = 0, count = 0, widthMilliseconds = 10, missingTime = 0;
};
struct ProjectionResult {
    ProcessTraceTimelineWidget::PreparedEventPoints points;
    std::uint64_t epoch = 0, revision = 0, count = 0, widthMilliseconds = 10, missingTime = 0;
};
std::size_t categoryFor(std::uint32_t category) {
    using C = ks::winapi_monitor::EventCategory;
    switch (static_cast<C>(category)) {
    case C::File: return 0;
    case C::Registry: return 1;
    case C::Network: return 2;
    case C::Process: return 3;
    case C::Loader: return 4;
    case C::Clipboard: return 5;
    case C::Memory: return 6;
    case C::Thread: return 7;
    case C::Service: return 8;
    case C::Security: return 9;
    case C::Crypto: return 10;
    case C::Com: return 11;
    case C::Window: return 12;
    case C::Gui: return 13;
    default: return 14;
    }
}
std::vector<ks::ui::EventTimelineTrack> tracks() {
    using C = ks::ui::TimelineCategory; using R = KswordTheme::TimelineRole;
    return {{C::File, QStringLiteral("文件"), R::File},
        {C::Registry, QStringLiteral("注册表"), R::Registry},
        {C::Network, QStringLiteral("网络"), R::Network},
        {C::Process, QStringLiteral("进程"), R::Process},
        {C::Image, QStringLiteral("加载器"), R::Image},
        {C::Thread, QStringLiteral("剪贴板"), R::Thread},
        {C::ApiMemory, QStringLiteral("内存"), R::Storage},
        {C::ApiThread, QStringLiteral("线程"), R::Thread},
        {C::ApiService, QStringLiteral("服务"), R::Wmi},
        {C::ApiSecurity, QStringLiteral("权限"), R::Security},
        {C::ApiCrypto, QStringLiteral("加密"), R::PowerShell},
        {C::ApiCom, QStringLiteral("COM"), R::Dns},
        {C::ApiWindow, QStringLiteral("窗口"), R::Image},
        {C::ApiGui, QStringLiteral("GUI"), R::Image},
        {C::Other, QStringLiteral("其他"), R::Kernel}};
}
}
WinAPIEventTimeline::WinAPIEventTimeline(QWidget* parent, WinAPIEventTableModel* model,
    WinAPIEventFilterModel*, QTableView*, QCheckBox*) : QWidget(parent), m_model(model)
{
    auto* layout = new QVBoxLayout(this); layout->setContentsMargins(0, 0, 0, 0); layout->setSpacing(4);
    auto* timelineRow = new QHBoxLayout(); timelineRow->setContentsMargins(0, 0, 0, 0);
    auto* reset = new QPushButton(QStringLiteral("显示全部时间"), this);
    m_timeline = new ProcessTraceTimelineWidget(this); m_timeline->setTracks(tracks());
    m_timeline->setFixedHeight(154); // Fourteen distinct lanes.
    m_timeline->setToolTip(QStringLiteral("时间轴：等待事件"));
    timelineRow->addWidget(m_timeline, 1);
    timelineRow->addWidget(reset, 0, Qt::AlignVCenter);
    ks::ui::NormalizeToolbarControl(reset); layout->addLayout(timelineRow);
    m_timer = new QTimer(this); m_timer->setSingleShot(true); m_timer->setInterval(800);
    m_filterTimer = new QTimer(this); m_filterTimer->setSingleShot(true); m_filterTimer->setInterval(200);
    m_project = new ks::ui::AsyncOperation(this);
    m_project->setStateChangedCallback([this] { if (!m_project->isBusy() && m_dirty) scheduleRefresh(); });
    connect(m_timer, &QTimer::timeout, this, [this] { refresh(); });
    connect(m_filterTimer, &QTimer::timeout, this, [this] {
        if (m_model) m_model->setTimeRange(m_timeline->hasUserAdjustedSelection(),
            m_timeline->selectionStart100ns(), m_timeline->selectionEnd100ns());
    });
    m_timeline->setSelectionChangedCallback([this](std::uint64_t, std::uint64_t) { m_filterTimer->start(); });
    connect(reset, &QPushButton::clicked, this, [this] {
        m_filterTimer->stop(); m_timeline->resetSelectionToFullRange();
        if (m_model) m_model->setTimeRange(false, 0, 0);
    });
}
WinAPIEventTimeline::~WinAPIEventTimeline() { m_project->close(); }
void WinAPIEventTimeline::showEvent(QShowEvent* event) { QWidget::showEvent(event); if (m_dirty) scheduleRefresh(); }
void WinAPIEventTimeline::appendRecord(const WinAPIEventRef& record)
{
    if (!record || record->value.internalEvent || record->value.eventKindCode != static_cast<std::uint32_t>(ks::winapi_monitor::EventKind::ApiCall)) return;
    auto time = record->value.timestamp100ns;
    if (!time) { bool ok = false; time = record->value.time100nsText.toULongLong(&ok); if (!ok) time = 0; }
    if (!time) { ++m_missingTime; ++m_revision; m_dirty = true; scheduleRefresh(); return; }
    m_density.append(time, categoryFor(record->value.categoryCode));
    ++m_revision; m_dirty = true; scheduleRefresh();
}
void WinAPIEventTimeline::resetTimeline()
{
    ++m_epoch; ++m_revision; m_dirty = false;
    m_timer->stop(); m_filterTimer->stop(); m_project->cancel(); m_density.clear(); m_missingTime = 0;
    m_timeline->resetTimeline(0); m_timeline->setEventPoints({});
    if (m_model) m_model->setTimeRange(false, 0, 0);
    m_timeline->setToolTip(QStringLiteral("时间轴：等待事件"));
}
void WinAPIEventTimeline::scheduleRefresh()
{
    if (isVisible() && !m_timer->isActive() && !m_project->isBusy()) m_timer->start();
}
void WinAPIEventTimeline::refresh()
{
    if (!isVisible() || !m_dirty || m_project->isBusy()) return;
    if (!m_density.count()) {
        m_timeline->setToolTip(m_missingTime ? QStringLiteral("时间轴：%1 次调用缺少有效时间").arg(m_missingTime)
            : QStringLiteral("时间轴：等待事件"));
        m_dirty = false; return;
    }
    ProjectionRequest request;
    request.points = m_density.points();
    request.projection = m_timeline->eventProjectionParameters(m_density.first(), m_density.last());
    request.epoch = m_epoch; request.revision = m_revision;
    request.count = m_density.count(); request.widthMilliseconds = m_density.widthMilliseconds(); request.missingTime = m_missingTime;
    m_dirty = false;
    m_project->submit<ProjectionRequest, ProjectionResult>(std::move(request),
        [](const ProjectionRequest& input, const ks::ui::AsyncOperationToken& token) {
            ProjectionResult result; result.epoch = input.epoch; result.revision = input.revision;
            result.count = input.count; result.widthMilliseconds = input.widthMilliseconds; result.missingTime = input.missingTime;
            if (!token.isCanceled()) result.points = ProcessTraceTimelineWidget::prepareEventPoints(input.points, input.projection);
            return result;
        }, [this](const ProjectionResult& result, std::uint64_t) {
            if (isVisible() && result.epoch == m_epoch && m_timeline->applyPreparedEventPoints(result.points)) {
                m_timeline->setToolTip(QStringLiteral("时间轴：主程序已接收有效 %1 次，缺时间 %2 次，桶宽 %3 毫秒（含隐藏，不含拒收和丢失）")
                    .arg(result.count).arg(result.missingTime).arg(result.widthMilliseconds));
            } else m_dirty = true;
            if (result.revision != m_revision) m_dirty = true;
            if (m_dirty) QTimer::singleShot(0, this, [this] { scheduleRefresh(); });
            return true;
        }, [this](std::exception_ptr) { m_dirty = true; QTimer::singleShot(0, this, [this] { scheduleRefresh(); }); });
}
