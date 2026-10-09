#include "ProcessTraceTimelineWidget.h"

// ============================================================
// ProcessTraceTimelineWidget.cpp
// 作用：
// 1) 绘制紧凑的 ETW 瀑布流时间轴与分类行；
// 2) 维护内部绝对时间选区，作为事件表时间筛选条件；
// 3) 把鼠标操作转换成时间戳更新，不从图形事件点反向推导事件集合。
// ============================================================

#include "../theme.h"
#include "../Internationalization/LanguageManager.h"

#include <QColor>
#include <QEvent>
#include <QFont>
#include <QMouseEvent>
#include <QPainter>
#include <QPen>
#include <QPolygonF>
#include <QSizePolicy>
#include <QtGlobal>
#include <QWheelEvent>
#include <QEasingCurve>
#include <QVariantAnimation>
#include <QResizeEvent>
#include <QHelpEvent>
#include <QToolTip>
#include <QSet>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <utility>
#include <limits>

namespace
{
    // kTimelineHeight：
    // - ETW 瀑布流时间轴的固定可视高度；
    // - 构造函数会同步把控件高度锁定到该值。
    constexpr int kTimelineHeight = 40;

    // kHorizontalPadding：
    // - 为边框和左右标签保留极小横向边距；
    // - 其余宽度全部作为时间轴可用空间。
    constexpr int kHorizontalPadding = 4;

    // kVerticalPadding：
    // - 选区矩形需要占满时间轴高度，因此垂直方向不预留额外空白；
    // - 线条抗锯齿产生的半像素裁剪可接受，优先满足交互语义。
    constexpr int kVerticalPadding = 0;

    // kEdgeHitWidth：
    // - 选区左右边缘可触发拉伸的逻辑像素宽度；
    // - 命中区域故意宽于可见线条，便于鼠标操作。
    constexpr int kEdgeHitWidth = 6;

    // kMinimumSelection100ns：
    // - 防止选区坍缩成零宽时间点；
    // - 10ms 足够细，同时仍然可拖动。
    constexpr std::uint64_t kMinimumSelection100ns = 10ULL * 1000ULL * 10ULL;

    // kDefaultRange100ns：
    // - 第一条 ETW 事件到达前提供非零绘制范围；
    // - 1 秒默认跨度能让初始坐标计算保持稳定。
    constexpr std::uint64_t kDefaultRange100ns = 1ULL * 1000ULL * 1000ULL * 10ULL;

    // saturatingAdd：100ns 边界逼近 UINT64_MAX 时不回绕到另一绝对时间会话。
    std::uint64_t saturatingAdd(const std::uint64_t base, const std::uint64_t duration)
    {
        return duration > std::numeric_limits<std::uint64_t>::max() - base
            ? std::numeric_limits<std::uint64_t>::max() : base + duration;
    }
    // effectiveWheelDelta：
    // - 从 Qt 滚轮事件中读取最可靠的滚动方向；
    // - 正数表示向上滚动，负数表示向下滚动。
    int effectiveWheelDelta(const QWheelEvent* eventPointer)
    {
        if (eventPointer == nullptr)
        {
            return 0;
        }

        const QPoint angleDelta = eventPointer->angleDelta();
        if (angleDelta.y() != 0)
        {
            return angleDelta.y();
        }

        const QPoint pixelDelta = eventPointer->pixelDelta();
        return pixelDelta.y();
    }

    // currentMousePosition：
    // - 返回兼容不同 Qt 版本的本地鼠标坐标；
    // - Qt 6 使用 position()，旧接口使用 pos()。
    QPoint currentMousePosition(const QMouseEvent* eventPointer)
    {
        if (eventPointer == nullptr)
        {
            return QPoint();
        }

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        return eventPointer->position().toPoint();
#else
        return eventPointer->pos();
#endif
    }

    // currentWheelPosition：
    // - 返回兼容不同 Qt 版本的本地滚轮坐标；
    // - 返回点仅用作缩放锚点。
    QPoint currentWheelPosition(const QWheelEvent* eventPointer)
    {
        if (eventPointer == nullptr)
        {
            return QPoint();
        }

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        return eventPointer->position().toPoint();
#else
        return eventPointer->pos();
#endif
    }
}

ProcessTraceTimelineWidget::ProcessTraceTimelineWidget(QWidget* parent)
    : QWidget(parent), m_tracks(ks::ui::EtwTimelineTracks())
{
    // 本控件是窄条时间轴，应该占用父布局提供的全部横向空间。
    setFixedHeight(kTimelineHeight);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setMouseTracking(true);
    setFocusPolicy(Qt::NoFocus);
    m_rateAnimation = new QVariantAnimation(this);
    m_rateAnimation->setDuration(260);
    m_rateAnimation->setEasingCurve(QEasingCurve::OutCubic);
    m_rateAnimation->setStartValue(0.0);
    m_rateAnimation->setEndValue(1.0);
    connect(m_rateAnimation, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
        m_rateAnimationProgress = value.toDouble();
        update();
    });
}

bool ProcessTraceTimelineWidget::setTracks(const std::vector<ks::ui::EventTimelineTrack>& tracks)
{
    if (tracks.empty())
    {
        return false;
    }
    QSet<std::uint32_t> categories; // 配置一次完整校验，失败不改变当前轨道集合。
    for (const auto& track : tracks)
    {
        const auto category = static_cast<std::uint32_t>(track.categoryId);
        if (track.categoryId == ks::ui::TimelineCategory::Unspecified || categories.contains(category))
        {
            return false;
        }
        categories.insert(category);
    }
    m_tracks = tracks;
    m_eventBucketsDirty = true;
    update();
    return true;
}

const std::vector<ks::ui::EventTimelineTrack>& ProcessTraceTimelineWidget::tracks() const
{
    return m_tracks;
}

QString ProcessTraceTimelineWidget::trackLabel(const ks::ui::TimelineCategory categoryId) const
{
    for (const auto& track : m_tracks)
    {
        if (track.categoryId == categoryId)
        {
            return ks::i18n::sourceText(track.label);
        }
    }
    return QString();
}

int ProcessTraceTimelineWidget::aggregationPixelBudget() const
{
    return std::max(1, static_cast<int>(std::ceil(timelineRect().width() * devicePixelRatioF())));
}

void ProcessTraceTimelineWidget::ensureEventBuckets() const
{
    const int pixelBudget = aggregationPixelBudget(); // DPR 热变化也会改变绘制预算。
    if (m_eventBucketsDirty || pixelBudget != m_bucketPixelBudget)
    {
        m_eventBuckets = ks::ui::AggregateTimelineEvents(m_eventPointList, m_tracks,
            m_rangeStart100ns, m_rangeEnd100ns, pixelBudget);
        m_eventBucketsDirty = false;
        m_bucketPixelBudget = pixelBudget;
    }
}

const std::vector<ks::ui::EventTimelineBucket>& ProcessTraceTimelineWidget::eventBuckets() const
{
    ensureEventBuckets();
    return m_eventBuckets;
}

std::size_t ProcessTraceTimelineWidget::eventPointCount() const
{
    return m_eventPointList.size();
}

void ProcessTraceTimelineWidget::resizeEvent(QResizeEvent* eventPointer)
{
    QWidget::resizeEvent(eventPointer);
    m_eventBucketsDirty = true;
    update();
}

bool ProcessTraceTimelineWidget::event(QEvent* eventPointer)
{
    if (eventPointer != nullptr && eventPointer->type() == QEvent::ToolTip)
    {
        // 悬停展示当前轨道的真实桶计数和 100ns 边界，不改选区或宿主过滤结果。
        const auto* help = static_cast<QHelpEvent*>(eventPointer);
        const QRectF axis = timelineRect();
        if (axis.contains(help->pos()))
        {
            const int lane = std::min(static_cast<int>(m_tracks.size()) - 1,
                static_cast<int>((help->pos().y() - axis.top()) * m_tracks.size() / axis.height()));
            const int column = std::min(aggregationPixelBudget() - 1,
                static_cast<int>((help->pos().x() - axis.left()) * devicePixelRatioF()));
            QString summary = trackLabel(m_tracks[static_cast<std::size_t>(lane)].categoryId);
            for (const auto& bucket : eventBuckets())
            {
                if (bucket.laneIndex == lane && bucket.pixelColumn == column)
                {
                    summary = ks::i18n::contextText(QStringLiteral("timeline.bucket.summary"),
                        QStringLiteral("%1 · %2 个事件 · %3–%4 (100ns)"))
                        .arg(summary).arg(static_cast<qulonglong>(bucket.count))
                        .arg(static_cast<qulonglong>(bucket.minTime100ns))
                        .arg(static_cast<qulonglong>(bucket.maxTime100ns));
                    break;
                }
            }
            QToolTip::showText(help->globalPos(), summary + QStringLiteral("\n") + toolTip(), this);
            return true;
        }
    }
    if (eventPointer != nullptr && (eventPointer->type() == QEvent::LanguageChange ||
        eventPointer->type() == QEvent::ApplicationPaletteChange))
    {
        update(); // 重译/换主题不重新分桶，不重置绝对时间选区。
    }
    return QWidget::event(eventPointer);
}

void ProcessTraceTimelineWidget::setCaptureRange(
    const std::uint64_t start100ns,
    const std::uint64_t end100ns)
{
    // normalizedEnd100ns 用途：即使采集刚开始或调用方传入相同起止值，也保证时间轴范围非零。
    const std::uint64_t normalizedEnd100ns = end100ns > start100ns
        ? end100ns
        : saturatingAdd(start100ns, kDefaultRange100ns);

    const bool hadRange = m_rangeEnd100ns > m_rangeStart100ns;
    if (hadRange)
    {
        m_previousRateRangeStart100ns = m_rangeStart100ns;
        m_previousRateRangeEnd100ns = m_rangeEnd100ns;
        m_hasPreviousRateRange =
            m_previousRateRangeStart100ns != start100ns
            || m_previousRateRangeEnd100ns != normalizedEnd100ns;
    }
    else
    {
        m_hasPreviousRateRange = false;
    }
    m_rangeStart100ns = start100ns;
    m_rangeEnd100ns = normalizedEnd100ns;
    m_eventBucketsDirty = true; // 新范围不能继续使用旧范围的像素桶。

    // 用户未手动调整选区前，选区持续覆盖完整捕获范围，避免默认产生隐式时间过滤。
    if (!hadRange || !m_userAdjustedSelection)
    {
        m_selectionStart100ns = m_rangeStart100ns;
        m_selectionEnd100ns = m_rangeEnd100ns;
    }
    else
    {
        clampSelectionToRange();
    }

    update();
}

void ProcessTraceTimelineWidget::resetTimeline(const std::uint64_t start100ns)
{
    m_eventPointList.clear();
    m_eventBucketsDirty = true;
    m_rateAnimation->stop();
    m_rateAnimationProgress = 1.0;
    m_hasPreviousRatePoint = false;
    m_ratePointList.clear();
    m_rangeStart100ns = start100ns;
    m_rangeEnd100ns = saturatingAdd(start100ns, kDefaultRange100ns);
    m_previousRateRangeStart100ns = m_rangeStart100ns;
    m_previousRateRangeEnd100ns = m_rangeEnd100ns;
    m_hasPreviousRateRange = false;
    m_selectionStart100ns = m_rangeStart100ns;
    m_selectionEnd100ns = m_rangeEnd100ns;
    m_dragPressTime100ns = 0;
    m_dragOriginalStart100ns = 0;
    m_dragOriginalEnd100ns = 0;
    m_dragMode = DragMode::None;
    m_userAdjustedSelection = false;
    unsetCursor();
    update();
}

void ProcessTraceTimelineWidget::resetSelectionToFullRange()
{
    // 清空筛选时使用全范围选区，并重新允许后续采集时间右端自动跟随。
    m_selectionStart100ns = m_rangeStart100ns;
    m_selectionEnd100ns = m_rangeEnd100ns;
    m_userAdjustedSelection = false;
    m_dragMode = DragMode::None;
    unsetCursor();
    update();
}

bool ProcessTraceTimelineWidget::setEventPoints(
    const std::vector<ProcessTraceTimelineEventPoint>& eventPointList)
{
    if (std::any_of(eventPointList.begin(), eventPointList.end(), [](const auto& point)
        { return point.categoryId == ks::ui::TimelineCategory::Unspecified; }))
    {
        return false; // 外部旧两字段初始化必须明确适配，不能悄悄改变其原泳道。
    }
    // 原始点完整保留；范围或 viewport 改变后能重新聚合，绝不只保留每格最新事件。
    m_eventPointList = eventPointList;
    m_eventBucketsDirty = true;
    update();
    return true;
}

void ProcessTraceTimelineWidget::setRateOverlayPoints(
    const std::vector<ProcessTraceTimelineRatePoint>& ratePointList)
{
    // 速率折线是可选叠加层：
    // - ETW 页不会设置该列表，因此原有事件瀑布流绘制不受影响；
    // - 网络页传入按秒聚合后的上传/下载速率，控件只负责映射到当前时间范围。
    const ProcessTraceTimelineRatePoint previousRatePoint = m_ratePointList.empty()
        ? (ratePointList.empty() ? ProcessTraceTimelineRatePoint{} : ratePointList.back())
        : m_ratePointList.back();
    m_ratePointList = ratePointList;
    if (m_ratePointList.empty())
    {
        m_rateAnimation->stop();
        m_rateAnimationProgress = 1.0;
        m_hasPreviousRatePoint = false;
        update();
        return;
    }
    m_previousRatePoint = previousRatePoint;
    m_hasPreviousRatePoint = true;
    m_rateAnimationProgress = 0.0;
    m_rateAnimation->stop();
    m_rateAnimation->start();
}

void ProcessTraceTimelineWidget::setSelectionChangedCallback(
    std::function<void(std::uint64_t, std::uint64_t)> callbackValue)
{
    m_selectionChangedCallback = std::move(callbackValue);
}

std::uint64_t ProcessTraceTimelineWidget::selectionStart100ns() const
{
    return m_selectionStart100ns;
}

std::uint64_t ProcessTraceTimelineWidget::selectionEnd100ns() const
{
    return m_selectionEnd100ns;
}

void ProcessTraceTimelineWidget::mousePressEvent(QMouseEvent* eventPointer)
{
    // 只响应左键拖拽，避免右键或中键误触发时间窗口变化。
    if (eventPointer == nullptr || eventPointer->button() != Qt::LeftButton)
    {
        QWidget::mousePressEvent(eventPointer);
        return;
    }

    // hitMode 决定后续鼠标移动是整体平移还是单侧拉伸。
    const QPoint position = currentMousePosition(eventPointer);
    const DragMode hitMode = hitTestSelection(position);
    if (hitMode == DragMode::None)
    {
        QWidget::mousePressEvent(eventPointer);
        return;
    }

    // 记录拖动起点的时间和原始选区，后续移动均基于这组稳定基准计算。
    m_dragMode = hitMode;
    m_dragPressTime100ns = xToTime(position.x());
    m_dragOriginalStart100ns = m_selectionStart100ns;
    m_dragOriginalEnd100ns = m_selectionEnd100ns;
    eventPointer->accept();
}

void ProcessTraceTimelineWidget::mouseMoveEvent(QMouseEvent* eventPointer)
{
    // 空事件直接交回 Qt 默认处理，保持 QWidget 行为一致。
    if (eventPointer == nullptr)
    {
        QWidget::mouseMoveEvent(eventPointer);
        return;
    }

    const QPoint position = currentMousePosition(eventPointer);
    if (m_dragMode == DragMode::None)
    {
        // 未拖动时只更新光标，不改变内部时间选区。
        updateHoverCursor(position);
        QWidget::mouseMoveEvent(eventPointer);
        return;
    }

    // currentTime100ns 是鼠标当前位置对应的真实时间，不依赖事件点绘制结果。
    const std::uint64_t currentTime100ns = xToTime(position.x());
    const std::uint64_t originalWidth100ns =
        m_dragOriginalEnd100ns > m_dragOriginalStart100ns
        ? (m_dragOriginalEnd100ns - m_dragOriginalStart100ns)
        : kMinimumSelection100ns;

    if (m_dragMode == DragMode::Move)
    {
        // 整体移动时保持原选区宽度，只改变左右边界的绝对时间。
        // 全程使用无符号相对差值，高位绝对 FILETIME 不经过有符号 64 位转换。
        std::uint64_t newStart100ns = m_dragOriginalStart100ns;
        if (currentTime100ns >= m_dragPressTime100ns)
        {
            newStart100ns = std::min(m_rangeEnd100ns - originalWidth100ns,
                saturatingAdd(m_dragOriginalStart100ns, currentTime100ns - m_dragPressTime100ns));
        }
        else
        {
            const std::uint64_t offset = m_dragPressTime100ns - currentTime100ns;
            newStart100ns = std::max(m_rangeStart100ns,
                m_dragOriginalStart100ns > offset ? m_dragOriginalStart100ns - offset : 0);
        }
        m_selectionStart100ns = newStart100ns;
        m_selectionEnd100ns = newStart100ns + originalWidth100ns;
    }
    else if (m_dragMode == DragMode::ResizeLeft)
    {
        // 左边缘拉伸只修改起点，终点保持按下时的原值。
        m_selectionStart100ns = currentTime100ns;
        m_selectionEnd100ns = m_dragOriginalEnd100ns;
    }
    else if (m_dragMode == DragMode::ResizeRight)
    {
        // 右边缘拉伸只修改终点，起点保持按下时的原值。
        m_selectionStart100ns = m_dragOriginalStart100ns;
        m_selectionEnd100ns = currentTime100ns;
    }

    // 任何拖动都会把时间轴切换到用户选区模式，并立即通知事件表筛选。
    m_userAdjustedSelection = true;
    clampSelectionToRange();
    update();
    eventPointer->accept();
    notifySelectionChanged(); // 回调可销毁本控件，之后不再访问this或事件对象。
}

void ProcessTraceTimelineWidget::mouseReleaseEvent(QMouseEvent* eventPointer)
{
    // 左键释放即结束拖动；其他按钮继续走 QWidget 默认逻辑。
    if (eventPointer != nullptr && eventPointer->button() == Qt::LeftButton)
    {
        m_dragMode = DragMode::None;
        updateHoverCursor(currentMousePosition(eventPointer));
        eventPointer->accept();
        return;
    }

    QWidget::mouseReleaseEvent(eventPointer);
}

void ProcessTraceTimelineWidget::leaveEvent(QEvent* eventPointer)
{
    // 未拖动时离开控件应恢复普通光标，避免父界面继续显示拉伸光标。
    if (m_dragMode == DragMode::None)
    {
        unsetCursor();
    }

    QWidget::leaveEvent(eventPointer);
}

void ProcessTraceTimelineWidget::wheelEvent(QWheelEvent* eventPointer)
{
    // 捕获范围无效时不消费滚轮，交给父级滚动区域处理。
    if (eventPointer == nullptr || m_rangeEnd100ns <= m_rangeStart100ns)
    {
        QWidget::wheelEvent(eventPointer);
        return;
    }

    const int wheelDelta = effectiveWheelDelta(eventPointer);
    if (wheelDelta == 0)
    {
        // 某些触控板事件可能没有方向信息，此时不改变时间选区。
        QWidget::wheelEvent(eventPointer);
        return;
    }

    // selectionWidth100ns 是本次缩放前的选区宽度，用于计算缩放锚点比例。
    const std::uint64_t rangeWidth100ns = m_rangeEnd100ns - m_rangeStart100ns;
    const std::uint64_t selectionWidth100ns =
        m_selectionEnd100ns > m_selectionStart100ns
        ? (m_selectionEnd100ns - m_selectionStart100ns)
        : rangeWidth100ns;

    // 滚轮方向规则：
    // - 向上扩大选区；
    // - 向下缩小选区。
    const std::uint64_t scaledWidth = ks::ui::ScaleTimelineDuration(selectionWidth100ns,
        wheelDelta > 0 ? 6U : 4U, 5U, rangeWidth100ns);
    const std::uint64_t newWidth100ns = std::min(rangeWidth100ns,
        std::max(kMinimumSelection100ns, scaledWidth));

    // 缩放以鼠标所在时间点为锚点；鼠标不在选区内时比例会被夹到边界。
    const std::uint64_t anchorTime100ns = xToTime(currentWheelPosition(eventPointer).x());
    const std::uint64_t anchorOffset = anchorTime100ns > m_selectionStart100ns
        ? anchorTime100ns - m_selectionStart100ns : 0;
    const std::uint64_t leftPart100ns = ks::ui::TimelineProportionalOffset(
        std::min(anchorOffset, selectionWidth100ns), selectionWidth100ns, newWidth100ns);
    m_selectionStart100ns = anchorTime100ns > leftPart100ns
        ? anchorTime100ns - leftPart100ns
        : m_rangeStart100ns;
    m_selectionEnd100ns = saturatingAdd(m_selectionStart100ns, newWidth100ns);

    // 滚轮缩放同样是用户主动选择时间窗口，需要立即叠加到事件表。
    m_userAdjustedSelection = true;
    clampSelectionToRange();
    update();
    eventPointer->accept();
    notifySelectionChanged(); // 接管事件后才回调，允许宿主同步关闭时间轴窗口。
}

QRectF ProcessTraceTimelineWidget::timelineRect() const
{
    // 高度和宽度最小夹到 1，防止极端布局阶段出现除零或空 QRectF。
    return QRectF(
        static_cast<double>(kHorizontalPadding),
        static_cast<double>(kVerticalPadding),
        static_cast<double>(std::max(1, width() - kHorizontalPadding * 2)),
        static_cast<double>(std::max(1, height() - kVerticalPadding * 2 - 1)));
}

QRectF ProcessTraceTimelineWidget::selectionRect() const
{
    // 无有效捕获范围或选区为空时，绘制层和命中测试都应视为没有选区。
    if (m_rangeEnd100ns <= m_rangeStart100ns || m_selectionEnd100ns <= m_selectionStart100ns)
    {
        return QRectF();
    }

    const QRectF axisRect = timelineRect();
    const double leftX = timeToX(m_selectionStart100ns);
    const double rightX = timeToX(m_selectionEnd100ns);
    return QRectF(
        QPointF(std::min(leftX, rightX), axisRect.top()),
        QPointF(std::max(leftX, rightX), axisRect.bottom()));
}

ProcessTraceTimelineWidget::DragMode ProcessTraceTimelineWidget::hitTestSelection(const QPoint& position) const
{
    // 命中测试只关注当前选区矩形，不读取事件点，因此不会从图形反推事件。
    const QRectF selectedRect = selectionRect();
    if (selectedRect.isEmpty())
    {
        return DragMode::None;
    }

    const QRectF expandedRect = selectedRect.adjusted(
        -static_cast<double>(kEdgeHitWidth),
        0.0,
        static_cast<double>(kEdgeHitWidth),
        0.0);
    // expandedRect 用于扩大可点击区域，但真正移动模式仍要求点在选区内部。
    if (!expandedRect.contains(position))
    {
        return DragMode::None;
    }

    if (std::abs(position.x() - selectedRect.left()) <= kEdgeHitWidth)
    {
        return DragMode::ResizeLeft;
    }
    if (std::abs(position.x() - selectedRect.right()) <= kEdgeHitWidth)
    {
        return DragMode::ResizeRight;
    }
    return selectedRect.contains(position) ? DragMode::Move : DragMode::None;
}

void ProcessTraceTimelineWidget::updateHoverCursor(const QPoint& position)
{
    // 光标只反映当前可执行操作，不改变任何内部状态。
    const DragMode hitMode = hitTestSelection(position);
    if (hitMode == DragMode::ResizeLeft || hitMode == DragMode::ResizeRight)
    {
        setCursor(Qt::SizeHorCursor);
        return;
    }
    if (hitMode == DragMode::Move)
    {
        setCursor(Qt::OpenHandCursor);
        return;
    }
    unsetCursor();
}

double ProcessTraceTimelineWidget::timeToX(const std::uint64_t time100ns) const
{
    // 无有效时间范围时返回左边界，保证调用方仍能完成绘制。
    const QRectF axisRect = timelineRect();
    if (m_rangeEnd100ns <= m_rangeStart100ns)
    {
        return axisRect.left();
    }

    const std::uint64_t clampedTime100ns = std::clamp(
        time100ns,
        m_rangeStart100ns,
        m_rangeEnd100ns);
    // ratio 是时间在完整捕获范围中的相对位置。
    const double ratio = static_cast<double>(clampedTime100ns - m_rangeStart100ns)
        / static_cast<double>(m_rangeEnd100ns - m_rangeStart100ns);
    return axisRect.left() + axisRect.width() * ratio;
}

std::uint64_t ProcessTraceTimelineWidget::xToTime(const double xValue) const
{
    // 坐标转时间仅服务于选区交互，返回值会被夹在捕获范围内。
    const QRectF axisRect = timelineRect();
    if (m_rangeEnd100ns <= m_rangeStart100ns || axisRect.width() <= 0.0)
    {
        return m_rangeStart100ns;
    }

    const double ratio = std::clamp(
        (xValue - axisRect.left()) / axisRect.width(),
        0.0,
        1.0);
    if (ratio >= 1.0)
    {
        return m_rangeEnd100ns; // 浮点四舍五入不能让最大端点转换或相加溢出。
    }
    // offset100ns 是相对起点的时间偏移。
    const double offset100ns = static_cast<double>(m_rangeEnd100ns - m_rangeStart100ns) * ratio;
    return m_rangeStart100ns + static_cast<std::uint64_t>(offset100ns);
}

QString ProcessTraceTimelineWidget::formatDurationText(const std::uint64_t duration100ns) const
{
    // ETW 时间戳单位为 100ns，这里先折算到秒再格式化。
    const std::uint64_t totalSeconds = duration100ns / (1000ULL * 1000ULL * 10ULL);
    const std::uint64_t hours = totalSeconds / 3600ULL;
    const std::uint64_t minutes = (totalSeconds % 3600ULL) / 60ULL;
    const std::uint64_t seconds = totalSeconds % 60ULL;

    if (hours > 0)
    {
        // 超过一小时时展示 hh:mm:ss，避免右侧标签丢失小时信息。
        return QStringLiteral("%1:%2:%3")
            .arg(static_cast<qulonglong>(hours), 2, 10, QChar(u'0'))
            .arg(static_cast<qulonglong>(minutes), 2, 10, QChar(u'0'))
            .arg(static_cast<qulonglong>(seconds), 2, 10, QChar(u'0'));
    }

    // 一小时内展示 mm:ss，符合左侧固定 00:00 的短时间阅读习惯。
    return QStringLiteral("%1:%2")
        .arg(static_cast<qulonglong>(minutes), 2, 10, QChar(u'0'))
        .arg(static_cast<qulonglong>(seconds), 2, 10, QChar(u'0'));
}

void ProcessTraceTimelineWidget::clampSelectionToRange()
{
    // 捕获范围无效时直接同步到范围端点，避免保留陈旧选区。
    if (m_rangeEnd100ns <= m_rangeStart100ns)
    {
        m_selectionStart100ns = m_rangeStart100ns;
        m_selectionEnd100ns = m_rangeEnd100ns;
        return;
    }

    if (m_selectionStart100ns > m_selectionEnd100ns)
    {
        // 左右边缘拖过头时允许交换，随后再按最小宽度修正。
        std::swap(m_selectionStart100ns, m_selectionEnd100ns);
    }

    // 最小宽度不能超过整个捕获范围。
    const std::uint64_t rangeWidth100ns = m_rangeEnd100ns - m_rangeStart100ns;
    const std::uint64_t minimumWidth100ns = std::min(kMinimumSelection100ns, rangeWidth100ns);

    m_selectionStart100ns = std::clamp(
        m_selectionStart100ns,
        m_rangeStart100ns,
        m_rangeEnd100ns);
    m_selectionEnd100ns = std::clamp(
        m_selectionEnd100ns,
        m_rangeStart100ns,
        m_rangeEnd100ns);

    if (m_selectionEnd100ns >= m_selectionStart100ns
        && (m_selectionEnd100ns - m_selectionStart100ns) >= minimumWidth100ns)
    {
        // 选区已经合法时无需额外移动边界。
        return;
    }

    if (m_dragMode == DragMode::ResizeLeft)
    {
        // 左边缘拉伸过窄时优先保持右边缘不动。
        m_selectionStart100ns = m_selectionEnd100ns > minimumWidth100ns
            ? m_selectionEnd100ns - minimumWidth100ns
            : m_rangeStart100ns;
    }
    else
    {
        // 其他场景优先保持左边缘不动并扩展右边缘。
        m_selectionStart100ns = std::min(m_selectionStart100ns, m_rangeEnd100ns - minimumWidth100ns);
        m_selectionEnd100ns = m_selectionStart100ns + minimumWidth100ns;
    }

    if (m_selectionEnd100ns > m_rangeEnd100ns)
    {
        // 修正右侧越界后，反向移动左侧以继续满足最小宽度。
        m_selectionEnd100ns = m_rangeEnd100ns;
        m_selectionStart100ns = m_selectionEnd100ns > minimumWidth100ns
            ? m_selectionEnd100ns - minimumWidth100ns
            : m_rangeStart100ns;
    }
}

void ProcessTraceTimelineWidget::notifySelectionChanged()
{
    // 回调为空时只更新自身绘制状态；宿主可选择不绑定筛选逻辑。
    const auto callback = m_selectionChangedCallback; // 自替换不释放正在执行的callable。
    const std::uint64_t start = m_selectionStart100ns;
    const std::uint64_t end = m_selectionEnd100ns;
    if (callback)
    {
        callback(start, end);
    }
}
