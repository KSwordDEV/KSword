#include "KsPainterChart.h"

#include <QAbstractAnimation>
#include <QFontMetricsF>
#include <QPaintEvent>
#include <QPainterPath>
#include <QSet>
#include <QShowEvent>
#include <QTimer>
#include <QVariantAnimation>

#include <algorithm>
#include <cmath>
#include <utility>

namespace
{
    constexpr qreal kRangeEpsilon = 0.000001;

    qreal interpolateValue(const qreal fromValue, const qreal toValue, const qreal progress)
    {
        return fromValue + (toValue - fromValue) * progress;
    }

    bool nearlyEqual(const qreal firstValue, const qreal secondValue)
    {
        const qreal scale = std::max<qreal>({ 1.0, std::abs(firstValue), std::abs(secondValue) });
        return std::abs(firstValue - secondValue) <= kRangeEpsilon * scale;
    }

    bool pointNearlyEqual(const QPointF& firstPoint, const QPointF& secondPoint)
    {
        return nearlyEqual(firstPoint.x(), secondPoint.x())
            && nearlyEqual(firstPoint.y(), secondPoint.y());
    }

    // Keep the existing live-chart motion contract:
    // - when a full history window shifts, retained samples move one slot left;
    // - only the newest sample interpolates vertically;
    // - while a history window is still growing, existing samples keep their
    //   old position and the new sample enters from the right.
    QList<QPointF> interpolatePointLists(
        const QList<QPointF>& fromPoints,
        const QList<QPointF>& toPoints,
        const qreal progress)
    {
        if (toPoints.isEmpty() || progress >= 1.0)
        {
            return toPoints;
        }
        if (fromPoints.isEmpty())
        {
            return toPoints;
        }

        const int fromCount = fromPoints.size();
        const int toCount = toPoints.size();
        QList<QPointF> result = toPoints;

        if (fromCount == toCount && toCount >= 2)
        {
            bool resetCoordinateShift = true;
            bool absoluteCoordinateShift = true;
            for (int pointIndex = 0; pointIndex + 1 < toCount; ++pointIndex)
            {
                resetCoordinateShift = resetCoordinateShift
                    && nearlyEqual(toPoints.at(pointIndex).x(), fromPoints.at(pointIndex).x())
                    && nearlyEqual(toPoints.at(pointIndex).y(), fromPoints.at(pointIndex + 1).y());
                absoluteCoordinateShift = absoluteCoordinateShift
                    && pointNearlyEqual(toPoints.at(pointIndex), fromPoints.at(pointIndex + 1));
            }

            if (resetCoordinateShift || absoluteCoordinateShift)
            {
                qreal sampleSpacing = toPoints.at(1).x() - toPoints.at(0).x();
                if (nearlyEqual(sampleSpacing, 0.0))
                {
                    sampleSpacing = 1.0;
                }
                for (int pointIndex = 0; pointIndex < toCount; ++pointIndex)
                {
                    const QPointF targetPoint = toPoints.at(pointIndex);
                    const qreal startX = resetCoordinateShift
                        ? targetPoint.x() + sampleSpacing
                        : targetPoint.x();
                    const qreal startY = pointIndex + 1 == toCount
                        ? fromPoints.constLast().y()
                        : targetPoint.y();
                    result[pointIndex] = QPointF(
                        interpolateValue(startX, targetPoint.x(), progress),
                        interpolateValue(startY, targetPoint.y(), progress));
                }
                return result;
            }

            for (int pointIndex = 0; pointIndex < toCount; ++pointIndex)
            {
                result[pointIndex] = QPointF(
                    interpolateValue(fromPoints.at(pointIndex).x(), toPoints.at(pointIndex).x(), progress),
                    interpolateValue(fromPoints.at(pointIndex).y(), toPoints.at(pointIndex).y(), progress));
            }
            return result;
        }

        if (toCount == fromCount + 1)
        {
            for (int pointIndex = 0; pointIndex < fromCount; ++pointIndex)
            {
                result[pointIndex] = QPointF(
                    interpolateValue(fromPoints.at(pointIndex).x(), toPoints.at(pointIndex).x(), progress),
                    interpolateValue(fromPoints.at(pointIndex).y(), toPoints.at(pointIndex).y(), progress));
            }
            const QPointF targetPoint = toPoints.constLast();
            result[toCount - 1] = QPointF(
                targetPoint.x(),
                interpolateValue(fromPoints.constLast().y(), targetPoint.y(), progress));
            return result;
        }

        const int sharedCount = std::min(fromCount, toCount);
        for (int pointIndex = 0; pointIndex < sharedCount; ++pointIndex)
        {
            result[pointIndex] = QPointF(
                interpolateValue(fromPoints.at(pointIndex).x(), toPoints.at(pointIndex).x(), progress),
                interpolateValue(fromPoints.at(pointIndex).y(), toPoints.at(pointIndex).y(), progress));
        }
        return result;
    }

    QVector<qreal> interpolateBarValues(
        const QVector<qreal>& fromValues,
        const QVector<qreal>& toValues,
        const qreal progress)
    {
        QVector<qreal> result = toValues;
        const int sharedCount = std::min(
            static_cast<int>(fromValues.size()),
            static_cast<int>(toValues.size()));
        for (int valueIndex = 0; valueIndex < sharedCount; ++valueIndex)
        {
            result[valueIndex] = interpolateValue(fromValues.at(valueIndex), toValues.at(valueIndex), progress);
        }
        return result;
    }

    QColor brushColorOr(const QBrush& brush, const QColor& fallbackColor)
    {
        return brush.style() == Qt::NoBrush ? fallbackColor : brush.color();
    }

    QString formatAxisValue(const QValueAxis* axis, const qreal value)
    {
        if (axis == nullptr)
        {
            return QString::number(value, 'g', 3);
        }

        const QString format = axis->labelFormat();
        if (format.contains(QStringLiteral("%d")))
        {
            return QString::number(qRound64(value));
        }
        if (format.contains(QStringLiteral("%.0f")))
        {
            QString text = QString::number(value, 'f', 0);
            if (format.contains(QStringLiteral("%%")))
            {
                text += QLatin1Char('%');
            }
            return text;
        }

        const qreal span = std::abs(axis->max() - axis->min());
        if (span >= 1000.0)
        {
            return QString::number(value, 'g', 3);
        }
        return QString::number(value, 'f', span <= 10.0 ? 1 : 0);
    }

    bool isHorizontalAlignment(const Qt::Alignment alignment)
    {
        return alignment.testFlag(Qt::AlignBottom) || alignment.testFlag(Qt::AlignTop);
    }

    QPointF mapChartPoint(
        const QPointF& point,
        const QRectF& plotRect,
        const QPair<qreal, qreal>& xRange,
        const QPair<qreal, qreal>& yRange)
    {
        const qreal xSpan = std::max<qreal>(kRangeEpsilon, xRange.second - xRange.first);
        const qreal ySpan = std::max<qreal>(kRangeEpsilon, yRange.second - yRange.first);
        const qreal xRatio = (point.x() - xRange.first) / xSpan;
        const qreal yRatio = (point.y() - yRange.first) / ySpan;
        return QPointF(
            plotRect.left() + xRatio * plotRect.width(),
            plotRect.bottom() - yRatio * plotRect.height());
    }
}

KsPainterChartObject::KsPainterChartObject(QObject* parent)
    : QObject(parent)
{
}

void KsPainterChartObject::setChangeHandler(std::function<void()> changeHandler)
{
    m_changeHandler = std::move(changeHandler);
}

void KsPainterChartObject::notifyChanged()
{
    if (m_changeHandler)
    {
        m_changeHandler();
    }
}

QAbstractAxis::QAbstractAxis(QObject* parent)
    : KsPainterChartObject(parent)
{
}

void QAbstractAxis::setLabelsVisible(const bool visible)
{
    m_labelsVisible = visible;
    notifyChanged();
}

bool QAbstractAxis::labelsVisible() const
{
    return m_labelsVisible;
}

void QAbstractAxis::setGridLineVisible(const bool visible)
{
    m_gridLineVisible = visible;
    notifyChanged();
}

bool QAbstractAxis::isGridLineVisible() const
{
    return m_gridLineVisible;
}

void QAbstractAxis::setMinorGridLineVisible(const bool visible)
{
    m_minorGridLineVisible = visible;
    notifyChanged();
}

bool QAbstractAxis::isMinorGridLineVisible() const
{
    return m_minorGridLineVisible;
}

void QAbstractAxis::setLineVisible(const bool visible)
{
    m_lineVisible = visible;
    notifyChanged();
}

bool QAbstractAxis::isLineVisible() const
{
    return m_lineVisible;
}

void QAbstractAxis::setLabelsBrush(const QBrush& brush)
{
    m_labelsBrush = brush;
    notifyChanged();
}

QBrush QAbstractAxis::labelsBrush() const
{
    return m_labelsBrush;
}

void QAbstractAxis::setTitleBrush(const QBrush& brush)
{
    m_titleBrush = brush;
    notifyChanged();
}

QBrush QAbstractAxis::titleBrush() const
{
    return m_titleBrush;
}

void QAbstractAxis::setLinePenColor(const QColor& color)
{
    m_linePen.setColor(color);
    notifyChanged();
}

void QAbstractAxis::setGridLineColor(const QColor& color)
{
    m_gridLinePen.setColor(color);
    notifyChanged();
}

void QAbstractAxis::setLinePen(const QPen& pen)
{
    m_linePen = pen;
    notifyChanged();
}

QPen QAbstractAxis::linePen() const
{
    return m_linePen;
}

void QAbstractAxis::setGridLinePen(const QPen& pen)
{
    m_gridLinePen = pen;
    notifyChanged();
}

QPen QAbstractAxis::gridLinePen() const
{
    return m_gridLinePen;
}

void QAbstractAxis::setTitleText(const QString& titleText)
{
    m_titleText = titleText;
    notifyChanged();
}

QString QAbstractAxis::titleText() const
{
    return m_titleText;
}

void QAbstractAxis::setLabelFormat(const QString& labelFormat)
{
    m_labelFormat = labelFormat;
    notifyChanged();
}

QString QAbstractAxis::labelFormat() const
{
    return m_labelFormat;
}

Qt::Alignment QAbstractAxis::alignment() const
{
    return m_alignment;
}

void QAbstractAxis::setAlignment(const Qt::Alignment alignment)
{
    m_alignment = alignment;
    notifyChanged();
}

QValueAxis::QValueAxis(QObject* parent)
    : QAbstractAxis(parent)
{
}

void QValueAxis::setRange(qreal minimum, qreal maximum)
{
    if (maximum < minimum)
    {
        std::swap(minimum, maximum);
    }
    if (nearlyEqual(minimum, maximum))
    {
        maximum = minimum + 1.0;
    }
    if (nearlyEqual(m_minimum, minimum) && nearlyEqual(m_maximum, maximum))
    {
        return;
    }
    m_minimum = minimum;
    m_maximum = maximum;
    notifyChanged();
}

qreal QValueAxis::min() const
{
    return m_minimum;
}

qreal QValueAxis::max() const
{
    return m_maximum;
}

QBarCategoryAxis::QBarCategoryAxis(QObject* parent)
    : QAbstractAxis(parent)
{
}

void QBarCategoryAxis::append(const QString& category)
{
    m_categories.append(category);
    notifyChanged();
}

void QBarCategoryAxis::append(const QStringList& categories)
{
    m_categories.append(categories);
    notifyChanged();
}

QStringList QBarCategoryAxis::categories() const
{
    return m_categories;
}

QAbstractSeries::QAbstractSeries(QObject* parent)
    : KsPainterChartObject(parent)
{
}

void QAbstractSeries::setName(const QString& name)
{
    m_name = name;
    notifyChanged();
}

QString QAbstractSeries::name() const
{
    return m_name;
}

bool QAbstractSeries::attachAxis(QAbstractAxis* axis)
{
    if (axis == nullptr)
    {
        return false;
    }
    if (!m_attachedAxes.contains(axis))
    {
        m_attachedAxes.append(axis);
        notifyChanged();
    }
    return true;
}

QList<QAbstractAxis*> QAbstractSeries::attachedAxes() const
{
    return m_attachedAxes;
}

QLineSeries::QLineSeries(QObject* parent)
    : QAbstractSeries(parent)
{
}

void QLineSeries::append(const qreal x, const qreal y)
{
    append(QPointF(x, y));
}

void QLineSeries::append(const QPointF& point)
{
    m_points.append(point);
    notifyChanged();
}

bool QLineSeries::remove(const int index)
{
    if (index < 0 || index >= m_points.size())
    {
        return false;
    }
    m_points.removeAt(index);
    notifyChanged();
    return true;
}

void QLineSeries::replace(const QList<QPointF>& points)
{
    m_points = points;
    notifyChanged();
}

int QLineSeries::count() const
{
    return static_cast<int>(m_points.size());
}

QList<QPointF> QLineSeries::points() const
{
    return m_points;
}

void QLineSeries::setColor(const QColor& color)
{
    m_pen.setColor(color);
    notifyChanged();
}

QColor QLineSeries::color() const
{
    return m_pen.color();
}

void QLineSeries::setPen(const QPen& pen)
{
    m_pen = pen;
    notifyChanged();
}

QPen QLineSeries::pen() const
{
    return m_pen;
}

QAreaSeries::QAreaSeries(QLineSeries* upperSeries, QLineSeries* lowerSeries, QObject* parent)
    : QAbstractSeries(parent)
    , m_upperSeries(upperSeries)
    , m_lowerSeries(lowerSeries)
{
    if (m_upperSeries != nullptr)
    {
        m_upperSeries->setChangeHandler([this]() { notifyChanged(); });
    }
    if (m_lowerSeries != nullptr)
    {
        m_lowerSeries->setChangeHandler([this]() { notifyChanged(); });
    }
}

QLineSeries* QAreaSeries::upperSeries() const
{
    return m_upperSeries;
}

QLineSeries* QAreaSeries::lowerSeries() const
{
    return m_lowerSeries;
}

void QAreaSeries::setColor(const QColor& color)
{
    m_brush = QBrush(color);
    notifyChanged();
}

QColor QAreaSeries::color() const
{
    return m_brush.color();
}

void QAreaSeries::setBorderColor(const QColor& color)
{
    m_pen.setColor(color);
    notifyChanged();
}

QColor QAreaSeries::borderColor() const
{
    return m_pen.color();
}

void QAreaSeries::setPen(const QPen& pen)
{
    m_pen = pen;
    notifyChanged();
}

QPen QAreaSeries::pen() const
{
    return m_pen;
}

void QAreaSeries::setBrush(const QBrush& brush)
{
    m_brush = brush;
    notifyChanged();
}

QBrush QAreaSeries::brush() const
{
    return m_brush;
}

QBarSet::QBarSet(const QString& label, QObject* parent)
    : KsPainterChartObject(parent)
    , m_label(label)
{
}

QBarSet& QBarSet::operator<<(const qreal value)
{
    append(value);
    return *this;
}

void QBarSet::append(const qreal value)
{
    m_values.append(value);
    notifyChanged();
}

void QBarSet::replace(const int index, const qreal value)
{
    if (index < 0 || index >= m_values.size())
    {
        return;
    }
    if (nearlyEqual(m_values.at(index), value))
    {
        return;
    }
    m_values[index] = value;
    notifyChanged();
}

int QBarSet::count() const
{
    return static_cast<int>(m_values.size());
}

QVector<qreal> QBarSet::values() const
{
    return m_values;
}

QString QBarSet::label() const
{
    return m_label;
}

void QBarSet::setColor(const QColor& color)
{
    m_brush = QBrush(color);
    notifyChanged();
}

QColor QBarSet::color() const
{
    return m_brush.color();
}

void QBarSet::setBorderColor(const QColor& color)
{
    m_borderColor = color;
    notifyChanged();
}

QColor QBarSet::borderColor() const
{
    return m_borderColor;
}

void QBarSet::setBrush(const QBrush& brush)
{
    m_brush = brush;
    notifyChanged();
}

QBrush QBarSet::brush() const
{
    return m_brush;
}

void QBarSet::setLabelBrush(const QBrush& brush)
{
    m_labelBrush = brush;
    notifyChanged();
}

QBrush QBarSet::labelBrush() const
{
    return m_labelBrush;
}

QBarSeries::QBarSeries(QObject* parent)
    : QAbstractSeries(parent)
{
}

bool QBarSeries::append(QBarSet* set)
{
    if (set == nullptr || m_sets.contains(set))
    {
        return false;
    }
    m_sets.append(set);
    if (set->parent() == nullptr)
    {
        set->setParent(this);
    }
    attachSetHandler(set);
    notifyChanged();
    return true;
}

bool QBarSeries::append(const QList<QBarSet*>& sets)
{
    bool appendedAny = false;
    for (QBarSet* set : sets)
    {
        appendedAny = append(set) || appendedAny;
    }
    return appendedAny;
}

QList<QBarSet*> QBarSeries::barSets() const
{
    return m_sets;
}

void QBarSeries::attachSetHandler(QBarSet* set)
{
    if (set != nullptr)
    {
        set->setChangeHandler([this]() { notifyChanged(); });
    }
}

QLegend::QLegend(QObject* parent)
    : KsPainterChartObject(parent)
{
}

void QLegend::hide()
{
    setVisible(false);
}

void QLegend::setVisible(const bool visible)
{
    m_visible = visible;
    notifyChanged();
}

bool QLegend::isVisible() const
{
    return m_visible;
}

void QLegend::setAlignment(const Qt::Alignment alignment)
{
    m_alignment = alignment;
    notifyChanged();
}

Qt::Alignment QLegend::alignment() const
{
    return m_alignment;
}

void QLegend::setLabelColor(const QColor& color)
{
    m_labelBrush = QBrush(color);
    notifyChanged();
}

QColor QLegend::labelColor() const
{
    return m_labelBrush.color();
}

void QLegend::setLabelBrush(const QBrush& brush)
{
    m_labelBrush = brush;
    notifyChanged();
}

QBrush QLegend::labelBrush() const
{
    return m_labelBrush;
}

void QLegend::setFont(const QFont& font)
{
    m_font = font;
    notifyChanged();
}

QFont QLegend::font() const
{
    return m_font;
}

QChart::QChart(QObject* parent)
    : KsPainterChartObject(parent)
    , m_legend(new QLegend(this))
{
    m_legend->setChangeHandler([this]() { notifyChanged(); });
}

void QChart::addSeries(QAbstractSeries* series)
{
    if (series == nullptr || m_series.contains(series))
    {
        return;
    }
    m_series.append(series);
    if (series->parent() == nullptr)
    {
        series->setParent(this);
    }
    attachSeriesHandlers(series);
    QObject::connect(series, &QObject::destroyed, this, [this, series]() {
        m_series.removeAll(series);
        notifyChanged();
    });
    notifyChanged();
}

QList<QAbstractSeries*> QChart::series() const
{
    return m_series;
}

void QChart::addAxis(QAbstractAxis* axis, const Qt::Alignment alignment)
{
    if (axis == nullptr)
    {
        return;
    }
    if (!m_axes.contains(axis))
    {
        m_axes.append(axis);
        if (axis->parent() == nullptr)
        {
            axis->setParent(this);
        }
        axis->setChangeHandler([this]() { notifyChanged(); });
        QObject::connect(axis, &QObject::destroyed, this, [this, axis]() {
            m_axes.removeAll(axis);
            notifyChanged();
        });
    }
    axis->setAlignment(alignment);
    notifyChanged();
}

QList<QAbstractAxis*> QChart::axes() const
{
    return m_axes;
}

QLegend* QChart::legend() const
{
    return m_legend;
}

void QChart::setTitle(const QString& title)
{
    m_title = title;
    notifyChanged();
}

QString QChart::title() const
{
    return m_title;
}

void QChart::setTitleBrush(const QBrush& brush)
{
    m_titleBrush = brush;
    notifyChanged();
}

QBrush QChart::titleBrush() const
{
    return m_titleBrush;
}

void QChart::setTitleFont(const QFont& font)
{
    m_titleFont = font;
    notifyChanged();
}

QFont QChart::titleFont() const
{
    return m_titleFont;
}

void QChart::setBackgroundVisible(const bool visible)
{
    m_backgroundVisible = visible;
    notifyChanged();
}

bool QChart::isBackgroundVisible() const
{
    return m_backgroundVisible;
}

void QChart::setBackgroundRoundness(const qreal roundness)
{
    m_backgroundRoundness = std::max<qreal>(0.0, roundness);
    notifyChanged();
}

qreal QChart::backgroundRoundness() const
{
    return m_backgroundRoundness;
}

void QChart::setBackgroundBrush(const QBrush& brush)
{
    m_backgroundBrush = brush;
    notifyChanged();
}

QBrush QChart::backgroundBrush() const
{
    return m_backgroundBrush;
}

void QChart::setMargins(const QMargins& margins)
{
    m_margins = margins;
    notifyChanged();
}

QMargins QChart::margins() const
{
    return m_margins;
}

void QChart::setPlotAreaBackgroundVisible(const bool visible)
{
    m_plotAreaBackgroundVisible = visible;
    notifyChanged();
}

bool QChart::isPlotAreaBackgroundVisible() const
{
    return m_plotAreaBackgroundVisible;
}

void QChart::setPlotAreaBackgroundBrush(const QBrush& brush)
{
    m_plotAreaBackgroundBrush = brush;
    notifyChanged();
}

QBrush QChart::plotAreaBackgroundBrush() const
{
    return m_plotAreaBackgroundBrush;
}

void QChart::setPlotAreaBackgroundPen(const QPen& pen)
{
    m_plotAreaBackgroundPen = pen;
    notifyChanged();
}

QPen QChart::plotAreaBackgroundPen() const
{
    return m_plotAreaBackgroundPen;
}

void QChart::setAnimationOptions(const AnimationOption options)
{
    m_animationOptions = options;
    notifyChanged();
}

QChart::AnimationOption QChart::animationOptions() const
{
    return m_animationOptions;
}

void QChart::setAnimationDuration(const int durationMs)
{
    m_animationDurationMs = std::max(0, durationMs);
    notifyChanged();
}

int QChart::animationDuration() const
{
    return m_animationDurationMs;
}

void QChart::setAnimationEasingCurve(const QEasingCurve& easingCurve)
{
    m_animationEasingCurve = easingCurve;
    notifyChanged();
}

QEasingCurve QChart::animationEasingCurve() const
{
    return m_animationEasingCurve;
}

void QChart::update()
{
    notifyChanged();
}

void QChart::attachSeriesHandlers(QAbstractSeries* series)
{
    if (series == nullptr)
    {
        return;
    }
    series->setChangeHandler([this]() { notifyChanged(); });

    if (QAreaSeries* areaSeries = dynamic_cast<QAreaSeries*>(series))
    {
        if (areaSeries->upperSeries() != nullptr)
        {
            areaSeries->upperSeries()->setChangeHandler([this]() { notifyChanged(); });
        }
        if (areaSeries->lowerSeries() != nullptr)
        {
            areaSeries->lowerSeries()->setChangeHandler([this]() { notifyChanged(); });
        }
    }
    else if (QBarSeries* barSeries = dynamic_cast<QBarSeries*>(series))
    {
        for (QBarSet* set : barSeries->barSets())
        {
            if (set != nullptr)
            {
                set->setChangeHandler([this]() { notifyChanged(); });
            }
        }
    }
}

QChartView::QChartView(QChart* chart, QWidget* parent)
    : QFrame(parent)
    , m_chart(chart)
    , m_animation(new QVariantAnimation(this))
{
    setAutoFillBackground(false);
    setAttribute(Qt::WA_OpaquePaintEvent, false);
    if (m_chart != nullptr)
    {
        if (m_chart->parent() == nullptr)
        {
            m_chart->setParent(this);
        }
        m_chart->setChangeHandler([this]() { scheduleModelUpdate(); });
    }

    m_animation->setStartValue(0.0);
    m_animation->setEndValue(1.0);
    QObject::connect(
        m_animation,
        &QVariantAnimation::valueChanged,
        this,
        [this](const QVariant& progressValue) {
            m_animationProgress = progressValue.toReal();
            QFrame::update();
        });
    QObject::connect(
        m_animation,
        &QVariantAnimation::finished,
        this,
        [this]() {
            m_animationProgress = 1.0;
            m_displayedLinePoints = m_toLinePoints;
            m_displayedBarValues = m_toBarValues;
            m_displayedAxisRanges = m_toAxisRanges;
            QFrame::update();
        });

    syncSnapshotsToCurrent();
}

QChartView::~QChartView()
{
    if (m_chart != nullptr)
    {
        m_chart->setChangeHandler({});
    }
}

QChart* QChartView::chart() const
{
    return m_chart;
}

QWidget* QChartView::viewport()
{
    return this;
}

const QWidget* QChartView::viewport() const
{
    return this;
}

void QChartView::setRenderHint(const QPainter::RenderHint hint, const bool enabled)
{
    if (hint == QPainter::Antialiasing)
    {
        m_antialiasingEnabled = enabled;
        QFrame::update();
    }
}

void QChartView::setHorizontalScrollBarPolicy(const Qt::ScrollBarPolicy policy)
{
    Q_UNUSED(policy);
}

void QChartView::setVerticalScrollBarPolicy(const Qt::ScrollBarPolicy policy)
{
    Q_UNUSED(policy);
}

void QChartView::setSizeAdjustPolicy(const QAbstractScrollArea::SizeAdjustPolicy policy)
{
    Q_UNUSED(policy);
}

void QChartView::setBackgroundBrush(const QBrush& brush)
{
    m_viewBackgroundBrush = brush;
    QFrame::update();
}

QSize QChartView::sizeHint() const
{
    return QSize(240, 150);
}

void QChartView::showEvent(QShowEvent* event)
{
    QFrame::showEvent(event);
    if (m_animation == nullptr || m_animation->state() != QAbstractAnimation::Running)
    {
        syncSnapshotsToCurrent();
    }
}

void QChartView::scheduleModelUpdate()
{
    if (m_updateScheduled)
    {
        return;
    }
    m_updateScheduled = true;
    QTimer::singleShot(0, this, [this]() { applyPendingModelUpdate(); });
}

void QChartView::applyPendingModelUpdate()
{
    m_updateScheduled = false;
    if (m_chart == nullptr)
    {
        QFrame::update();
        return;
    }
    if (m_chart->animationOptions() == QChart::NoAnimation || m_chart->animationDuration() <= 0)
    {
        if (m_animation->state() == QAbstractAnimation::Running)
        {
            m_animation->stop();
        }
        syncSnapshotsToCurrent();
        QFrame::update();
        return;
    }
    startModelAnimation();
}

void QChartView::startModelAnimation()
{
    if (m_chart == nullptr)
    {
        return;
    }

    if (m_animation->state() == QAbstractAnimation::Running)
    {
        captureCurrentFrameAsDisplayed();
    }

    const LinePointMap targetLinePoints = currentLinePoints();
    const BarValueMap targetBarValues = currentBarValues();
    const AxisRangeMap targetAxisRanges = currentAxisRanges();
    if (m_displayedLinePoints.isEmpty()
        && m_displayedBarValues.isEmpty()
        && m_displayedAxisRanges.isEmpty())
    {
        syncSnapshotsToCurrent();
        QFrame::update();
        return;
    }

    const int optionBits = static_cast<int>(m_chart->animationOptions());
    const bool animateSeries = (optionBits & static_cast<int>(QChart::SeriesAnimations)) != 0;
    const bool animateAxes = (optionBits & static_cast<int>(QChart::GridAxisAnimations)) != 0;

    if (!animateSeries)
    {
        m_displayedLinePoints = targetLinePoints;
        m_displayedBarValues = targetBarValues;
    }
    if (!animateAxes)
    {
        m_displayedAxisRanges = targetAxisRanges;
    }

    m_fromLinePoints.clear();
    m_toLinePoints = targetLinePoints;
    for (auto iterator = targetLinePoints.constBegin(); iterator != targetLinePoints.constEnd(); ++iterator)
    {
        m_fromLinePoints.insert(
            iterator.key(),
            m_displayedLinePoints.value(iterator.key(), iterator.value()));
    }

    m_fromBarValues.clear();
    m_toBarValues = targetBarValues;
    for (auto iterator = targetBarValues.constBegin(); iterator != targetBarValues.constEnd(); ++iterator)
    {
        m_fromBarValues.insert(
            iterator.key(),
            m_displayedBarValues.value(iterator.key(), iterator.value()));
    }

    m_fromAxisRanges.clear();
    m_toAxisRanges = targetAxisRanges;
    for (auto iterator = targetAxisRanges.constBegin(); iterator != targetAxisRanges.constEnd(); ++iterator)
    {
        m_fromAxisRanges.insert(
            iterator.key(),
            m_displayedAxisRanges.value(iterator.key(), iterator.value()));
    }

    const bool seriesChanged = animateSeries
        && (m_fromLinePoints != m_toLinePoints || m_fromBarValues != m_toBarValues);
    const bool axesChanged = animateAxes && m_fromAxisRanges != m_toAxisRanges;
    if (!seriesChanged && !axesChanged)
    {
        syncSnapshotsToCurrent();
        QFrame::update();
        return;
    }

    m_animationProgress = 0.0;
    m_animation->setDuration(m_chart->animationDuration());
    m_animation->setEasingCurve(m_chart->animationEasingCurve());
    m_animation->setStartValue(0.0);
    m_animation->setEndValue(1.0);
    m_animation->start();
}

void QChartView::syncSnapshotsToCurrent()
{
    m_displayedLinePoints = currentLinePoints();
    m_displayedBarValues = currentBarValues();
    m_displayedAxisRanges = currentAxisRanges();
    m_fromLinePoints = m_displayedLinePoints;
    m_toLinePoints = m_displayedLinePoints;
    m_fromBarValues = m_displayedBarValues;
    m_toBarValues = m_displayedBarValues;
    m_fromAxisRanges = m_displayedAxisRanges;
    m_toAxisRanges = m_displayedAxisRanges;
    m_animationProgress = 1.0;
}

void QChartView::captureCurrentFrameAsDisplayed()
{
    LinePointMap frameLinePoints;
    for (auto iterator = m_toLinePoints.constBegin(); iterator != m_toLinePoints.constEnd(); ++iterator)
    {
        frameLinePoints.insert(iterator.key(), renderedPoints(iterator.key()));
    }
    BarValueMap frameBarValues;
    for (auto iterator = m_toBarValues.constBegin(); iterator != m_toBarValues.constEnd(); ++iterator)
    {
        frameBarValues.insert(iterator.key(), renderedBarValues(iterator.key()));
    }
    AxisRangeMap frameAxisRanges;
    for (auto iterator = m_toAxisRanges.constBegin(); iterator != m_toAxisRanges.constEnd(); ++iterator)
    {
        frameAxisRanges.insert(iterator.key(), renderedAxisRange(iterator.key()));
    }
    m_animation->stop();
    m_displayedLinePoints = frameLinePoints;
    m_displayedBarValues = frameBarValues;
    m_displayedAxisRanges = frameAxisRanges;
    m_animationProgress = 1.0;
}

QChartView::LinePointMap QChartView::currentLinePoints() const
{
    LinePointMap result;
    if (m_chart == nullptr)
    {
        return result;
    }
    QSet<const QLineSeries*> visitedSeries;
    const auto addLineSeries = [&result, &visitedSeries](const QLineSeries* lineSeries) {
        if (lineSeries != nullptr && !visitedSeries.contains(lineSeries))
        {
            visitedSeries.insert(lineSeries);
            result.insert(lineSeries, lineSeries->points());
        }
    };
    for (QAbstractSeries* abstractSeries : m_chart->series())
    {
        if (QLineSeries* lineSeries = dynamic_cast<QLineSeries*>(abstractSeries))
        {
            addLineSeries(lineSeries);
        }
        else if (QAreaSeries* areaSeries = dynamic_cast<QAreaSeries*>(abstractSeries))
        {
            addLineSeries(areaSeries->upperSeries());
            addLineSeries(areaSeries->lowerSeries());
        }
    }
    return result;
}

QChartView::BarValueMap QChartView::currentBarValues() const
{
    BarValueMap result;
    if (m_chart == nullptr)
    {
        return result;
    }
    for (QAbstractSeries* abstractSeries : m_chart->series())
    {
        QBarSeries* barSeries = dynamic_cast<QBarSeries*>(abstractSeries);
        if (barSeries == nullptr)
        {
            continue;
        }
        for (QBarSet* set : barSeries->barSets())
        {
            if (set != nullptr)
            {
                result.insert(set, set->values());
            }
        }
    }
    return result;
}

QChartView::AxisRangeMap QChartView::currentAxisRanges() const
{
    AxisRangeMap result;
    if (m_chart == nullptr)
    {
        return result;
    }
    for (QAbstractAxis* abstractAxis : m_chart->axes())
    {
        if (QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(abstractAxis))
        {
            result.insert(valueAxis, qMakePair(valueAxis->min(), valueAxis->max()));
        }
    }
    return result;
}

QList<QPointF> QChartView::renderedPoints(const QLineSeries* series) const
{
    if (series == nullptr)
    {
        return {};
    }
    const int optionBits = m_chart != nullptr
        ? static_cast<int>(m_chart->animationOptions())
        : 0;
    const bool animateSeries = (optionBits & static_cast<int>(QChart::SeriesAnimations)) != 0;
    if (animateSeries && m_animation->state() == QAbstractAnimation::Running)
    {
        return interpolatePointLists(
            m_fromLinePoints.value(series, series->points()),
            m_toLinePoints.value(series, series->points()),
            m_animationProgress);
    }
    return m_displayedLinePoints.value(series, series->points());
}

QVector<qreal> QChartView::renderedBarValues(const QBarSet* set) const
{
    if (set == nullptr)
    {
        return {};
    }
    const int optionBits = m_chart != nullptr
        ? static_cast<int>(m_chart->animationOptions())
        : 0;
    const bool animateSeries = (optionBits & static_cast<int>(QChart::SeriesAnimations)) != 0;
    if (animateSeries && m_animation->state() == QAbstractAnimation::Running)
    {
        return interpolateBarValues(
            m_fromBarValues.value(set, set->values()),
            m_toBarValues.value(set, set->values()),
            m_animationProgress);
    }
    return m_displayedBarValues.value(set, set->values());
}

QPair<qreal, qreal> QChartView::renderedAxisRange(const QValueAxis* axis) const
{
    if (axis == nullptr)
    {
        return qMakePair(0.0, 1.0);
    }
    const QPair<qreal, qreal> currentRange(axis->min(), axis->max());
    const int optionBits = m_chart != nullptr
        ? static_cast<int>(m_chart->animationOptions())
        : 0;
    const bool animateAxes = (optionBits & static_cast<int>(QChart::GridAxisAnimations)) != 0;
    if (animateAxes && m_animation->state() == QAbstractAnimation::Running)
    {
        const QPair<qreal, qreal> fromRange = m_fromAxisRanges.value(axis, currentRange);
        const QPair<qreal, qreal> toRange = m_toAxisRanges.value(axis, currentRange);
        return qMakePair(
            interpolateValue(fromRange.first, toRange.first, m_animationProgress),
            interpolateValue(fromRange.second, toRange.second, m_animationProgress));
    }
    return m_displayedAxisRanges.value(axis, currentRange);
}

void QChartView::paintEvent(QPaintEvent* event)
{
    Q_UNUSED(event);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, m_antialiasingEnabled);
    painter.setRenderHint(QPainter::TextAntialiasing, true);

    if (m_viewBackgroundBrush.style() != Qt::NoBrush)
    {
        painter.fillRect(rect(), m_viewBackgroundBrush);
    }
    if (m_chart == nullptr)
    {
        return;
    }

    const QMargins margins = m_chart->margins();
    QRectF contentRect = QRectF(rect()).adjusted(
        1.0 + margins.left(),
        1.0 + margins.top(),
        -1.0 - margins.right(),
        -1.0 - margins.bottom());
    if (contentRect.width() <= 2.0 || contentRect.height() <= 2.0)
    {
        return;
    }

    if (m_chart->isBackgroundVisible())
    {
        const QBrush backgroundBrush = m_chart->backgroundBrush().style() == Qt::NoBrush
            ? palette().brush(QPalette::Base)
            : m_chart->backgroundBrush();
        painter.setPen(Qt::NoPen);
        painter.setBrush(backgroundBrush);
        painter.drawRoundedRect(
            contentRect,
            m_chart->backgroundRoundness(),
            m_chart->backgroundRoundness());
    }

    QFont titleFont = m_chart->titleFont();
    if (titleFont.family().isEmpty())
    {
        titleFont = font();
    }
    if (!m_chart->title().isEmpty())
    {
        painter.setFont(titleFont);
        const QFontMetricsF titleMetrics(titleFont);
        const qreal titleHeight = std::min<qreal>(
            std::max<qreal>(16.0, titleMetrics.height() + 2.0),
            std::max<qreal>(16.0, contentRect.height() * 0.28));
        const QRectF titleRect(contentRect.left(), contentRect.top(), contentRect.width(), titleHeight);
        painter.setPen(brushColorOr(m_chart->titleBrush(), palette().color(QPalette::WindowText)));
        painter.drawText(
            titleRect,
            Qt::AlignHCenter | Qt::AlignVCenter,
            titleMetrics.elidedText(m_chart->title(), Qt::ElideRight, titleRect.width()));
        contentRect.setTop(titleRect.bottom());
    }

    struct LegendEntry
    {
        QString name;
        QColor color;
    };
    QList<LegendEntry> legendEntries;
    QSet<QString> legendNames;
    for (QAbstractSeries* abstractSeries : m_chart->series())
    {
        QString entryName = abstractSeries != nullptr ? abstractSeries->name() : QString();
        QColor entryColor = palette().color(QPalette::Highlight);
        if (QLineSeries* lineSeries = dynamic_cast<QLineSeries*>(abstractSeries))
        {
            entryColor = lineSeries->pen().color();
        }
        else if (QAreaSeries* areaSeries = dynamic_cast<QAreaSeries*>(abstractSeries))
        {
            entryColor = areaSeries->pen().color();
        }
        else if (QBarSeries* barSeries = dynamic_cast<QBarSeries*>(abstractSeries))
        {
            if (!barSeries->barSets().isEmpty() && barSeries->barSets().first() != nullptr)
            {
                entryColor = barSeries->barSets().first()->color();
            }
        }
        if (!entryName.isEmpty() && !legendNames.contains(entryName))
        {
            legendNames.insert(entryName);
            legendEntries.append({ entryName, entryColor });
        }
    }

    QRectF legendRect;
    if (m_chart->legend()->isVisible() && !legendEntries.isEmpty())
    {
        QFont legendFont = m_chart->legend()->font();
        if (legendFont.family().isEmpty())
        {
            legendFont = font();
        }
        const qreal legendHeight = std::min<qreal>(20.0, std::max<qreal>(14.0, QFontMetricsF(legendFont).height() + 2.0));
        if (m_chart->legend()->alignment().testFlag(Qt::AlignBottom))
        {
            legendRect = QRectF(contentRect.left(), contentRect.bottom() - legendHeight, contentRect.width(), legendHeight);
            contentRect.setBottom(legendRect.top());
        }
        else
        {
            legendRect = QRectF(contentRect.left(), contentRect.top(), contentRect.width(), legendHeight);
            contentRect.setTop(legendRect.bottom());
        }
    }

    QAbstractAxis* horizontalAxis = nullptr;
    QAbstractAxis* verticalAxis = nullptr;
    for (QAbstractAxis* axis : m_chart->axes())
    {
        if (axis == nullptr)
        {
            continue;
        }
        if (isHorizontalAlignment(axis->alignment()) && horizontalAxis == nullptr)
        {
            horizontalAxis = axis;
        }
        else if (!isHorizontalAlignment(axis->alignment()) && verticalAxis == nullptr)
        {
            verticalAxis = axis;
        }
    }

    const qreal leftReserve = verticalAxis != nullptr && verticalAxis->labelsVisible() ? 42.0 : 3.0;
    const qreal bottomReserve = horizontalAxis != nullptr && horizontalAxis->labelsVisible() ? 18.0 : 3.0;
    const qreal leftTitleReserve = verticalAxis != nullptr && !verticalAxis->titleText().isEmpty() ? 13.0 : 0.0;
    const qreal bottomTitleReserve = horizontalAxis != nullptr && !horizontalAxis->titleText().isEmpty() ? 14.0 : 0.0;
    QRectF plotRect = contentRect.adjusted(
        leftReserve + leftTitleReserve,
        2.0,
        -3.0,
        -bottomReserve - bottomTitleReserve);
    if (plotRect.width() <= 3.0 || plotRect.height() <= 3.0)
    {
        return;
    }

    if (m_chart->isPlotAreaBackgroundVisible())
    {
        painter.setPen(m_chart->plotAreaBackgroundPen());
        painter.setBrush(m_chart->plotAreaBackgroundBrush());
        painter.drawRect(plotRect);
    }

    QPair<qreal, qreal> defaultXRange(0.0, 1.0);
    QPair<qreal, qreal> defaultYRange(0.0, 1.0);
    if (QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(horizontalAxis))
    {
        defaultXRange = renderedAxisRange(valueAxis);
    }
    else if (QBarCategoryAxis* categoryAxis = dynamic_cast<QBarCategoryAxis*>(horizontalAxis))
    {
        const int categoryCount = std::max(
            1, static_cast<int>(categoryAxis->categories().size()));
        defaultXRange = qMakePair(-0.5, static_cast<qreal>(categoryCount) - 0.5);
    }
    if (QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(verticalAxis))
    {
        defaultYRange = renderedAxisRange(valueAxis);
    }

    if (verticalAxis != nullptr && verticalAxis->isGridLineVisible())
    {
        painter.setPen(verticalAxis->gridLinePen());
        for (int gridIndex = 0; gridIndex <= 4; ++gridIndex)
        {
            const qreal y = plotRect.bottom() - plotRect.height() * static_cast<qreal>(gridIndex) / 4.0;
            painter.drawLine(QPointF(plotRect.left(), y), QPointF(plotRect.right(), y));
        }
    }
    if (horizontalAxis != nullptr && horizontalAxis->isGridLineVisible())
    {
        painter.setPen(horizontalAxis->gridLinePen());
        for (int gridIndex = 0; gridIndex <= 4; ++gridIndex)
        {
            const qreal x = plotRect.left() + plotRect.width() * static_cast<qreal>(gridIndex) / 4.0;
            painter.drawLine(QPointF(x, plotRect.top()), QPointF(x, plotRect.bottom()));
        }
    }

    if (verticalAxis != nullptr && verticalAxis->isLineVisible())
    {
        painter.setPen(verticalAxis->linePen());
        painter.drawLine(plotRect.topLeft(), plotRect.bottomLeft());
    }
    if (horizontalAxis != nullptr && horizontalAxis->isLineVisible())
    {
        painter.setPen(horizontalAxis->linePen());
        painter.drawLine(plotRect.bottomLeft(), plotRect.bottomRight());
    }

    QFont axisFont = font();
    axisFont.setPointSizeF(std::max<qreal>(7.0, axisFont.pointSizeF() - 1.0));
    painter.setFont(axisFont);
    if (verticalAxis != nullptr && verticalAxis->labelsVisible())
    {
        painter.setPen(brushColorOr(verticalAxis->labelsBrush(), palette().color(QPalette::Text)));
        QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(verticalAxis);
        for (int labelIndex = 0; labelIndex <= 4; ++labelIndex)
        {
            const qreal ratio = static_cast<qreal>(labelIndex) / 4.0;
            const qreal value = defaultYRange.first + (defaultYRange.second - defaultYRange.first) * ratio;
            const qreal y = plotRect.bottom() - plotRect.height() * ratio;
            painter.drawText(
                QRectF(contentRect.left() + leftTitleReserve, y - 8.0, leftReserve - 4.0, 16.0),
                Qt::AlignRight | Qt::AlignVCenter,
                formatAxisValue(valueAxis, value));
        }
    }
    if (horizontalAxis != nullptr && horizontalAxis->labelsVisible())
    {
        painter.setPen(brushColorOr(horizontalAxis->labelsBrush(), palette().color(QPalette::Text)));
        if (QBarCategoryAxis* categoryAxis = dynamic_cast<QBarCategoryAxis*>(horizontalAxis))
        {
            const QStringList categories = categoryAxis->categories();
            const int categoryCount = categories.size();
            const int labelStep = std::max(1, (categoryCount + 11) / 12);
            for (int categoryIndex = 0; categoryIndex < categoryCount; categoryIndex += labelStep)
            {
                const qreal slotWidth = plotRect.width() / std::max(1, categoryCount);
                const QRectF labelRect(
                    plotRect.left() + slotWidth * categoryIndex,
                    plotRect.bottom(),
                    slotWidth * labelStep,
                    bottomReserve);
                painter.drawText(labelRect, Qt::AlignHCenter | Qt::AlignTop, categories.at(categoryIndex));
            }
        }
        else if (QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(horizontalAxis))
        {
            for (int labelIndex = 0; labelIndex <= 4; ++labelIndex)
            {
                const qreal ratio = static_cast<qreal>(labelIndex) / 4.0;
                const qreal value = defaultXRange.first + (defaultXRange.second - defaultXRange.first) * ratio;
                const qreal x = plotRect.left() + plotRect.width() * ratio;
                painter.drawText(
                    QRectF(x - 28.0, plotRect.bottom(), 56.0, bottomReserve),
                    Qt::AlignHCenter | Qt::AlignTop,
                    formatAxisValue(valueAxis, value));
            }
        }
    }

    if (verticalAxis != nullptr && !verticalAxis->titleText().isEmpty())
    {
        painter.save();
        painter.setPen(brushColorOr(verticalAxis->titleBrush(), palette().color(QPalette::Text)));
        painter.translate(contentRect.left() + 7.0, plotRect.center().y());
        painter.rotate(-90.0);
        painter.drawText(
            QRectF(-plotRect.height() / 2.0, -7.0, plotRect.height(), 14.0),
            Qt::AlignCenter,
            verticalAxis->titleText());
        painter.restore();
    }
    if (horizontalAxis != nullptr && !horizontalAxis->titleText().isEmpty())
    {
        painter.setPen(brushColorOr(horizontalAxis->titleBrush(), palette().color(QPalette::Text)));
        painter.drawText(
            QRectF(plotRect.left(), contentRect.bottom() - bottomTitleReserve, plotRect.width(), bottomTitleReserve),
            Qt::AlignCenter,
            horizontalAxis->titleText());
    }

    const auto seriesAxis = [this](QAbstractSeries* series, const bool horizontal) -> QAbstractAxis* {
        if (series != nullptr)
        {
            for (QAbstractAxis* axis : series->attachedAxes())
            {
                if (axis != nullptr && isHorizontalAlignment(axis->alignment()) == horizontal)
                {
                    return axis;
                }
            }
        }
        for (QAbstractAxis* axis : m_chart->axes())
        {
            if (axis != nullptr && isHorizontalAlignment(axis->alignment()) == horizontal)
            {
                return axis;
            }
        }
        return nullptr;
    };
    const auto axisRange = [this](QAbstractAxis* axis, const bool horizontal) {
        if (QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(axis))
        {
            return renderedAxisRange(valueAxis);
        }
        if (QBarCategoryAxis* categoryAxis = dynamic_cast<QBarCategoryAxis*>(axis))
        {
            const int count = std::max(
                1, static_cast<int>(categoryAxis->categories().size()));
            return qMakePair(-0.5, static_cast<qreal>(count) - 0.5);
        }
        return horizontal ? qMakePair(0.0, 1.0) : qMakePair(0.0, 1.0);
    };

    painter.save();
    painter.setClipRect(plotRect.adjusted(-1.0, -1.0, 1.0, 1.0));
    for (QAbstractSeries* abstractSeries : m_chart->series())
    {
        if (abstractSeries == nullptr)
        {
            continue;
        }

        QAbstractAxis* xAxis = seriesAxis(abstractSeries, true);
        QAbstractAxis* yAxis = seriesAxis(abstractSeries, false);
        const QPair<qreal, qreal> xRange = axisRange(xAxis, true);
        const QPair<qreal, qreal> yRange = axisRange(yAxis, false);

        if (QAreaSeries* areaSeries = dynamic_cast<QAreaSeries*>(abstractSeries))
        {
            const QList<QPointF> upperPoints = renderedPoints(areaSeries->upperSeries());
            QList<QPointF> lowerPoints = renderedPoints(areaSeries->lowerSeries());
            if (lowerPoints.isEmpty())
            {
                lowerPoints.reserve(upperPoints.size());
                for (const QPointF& upperPoint : upperPoints)
                {
                    lowerPoints.append(QPointF(upperPoint.x(), 0.0));
                }
            }
            const int pointCount = std::min(
                static_cast<int>(upperPoints.size()),
                static_cast<int>(lowerPoints.size()));
            if (pointCount > 0)
            {
                // 缺失采样按连续有效上下界分段填充，不能跨 gap 合成虚假面积。
                const QList<QPointF> upperTargets = areaSeries->upperSeries()->points();
                const QList<QPointF> lowerTargets = areaSeries->lowerSeries()
                    ? areaSeries->lowerSeries()->points() : upperTargets;
                const auto validPair = [&upperPoints, &lowerPoints, &upperTargets, &lowerTargets](const int index)
                {
                    const QPointF upper = upperPoints.at(index);
                    const QPointF lower = lowerPoints.at(index);
                    return std::isfinite(upper.x()) && std::isfinite(upper.y())
                        && std::isfinite(lower.x()) && std::isfinite(lower.y())
                        && index < upperTargets.size() && index < lowerTargets.size()
                        && nearlyEqual(upperTargets.at(index).x(), lowerTargets.at(index).x());
                };
                int first = 0; // 当前连续有效区间的起点。
                while (first < pointCount)
                {
                    while (first < pointCount && !validPair(first))
                    {
                        ++first;
                    }
                    int last = first; // 区间结束位置，不包含该下标。
                    while (last < pointCount && validPair(last))
                    {
                        ++last;
                    }
                    if (first == last)
                    {
                        break;
                    }
                    QPainterPath fillPath;
                    QPainterPath borderPath;
                    for (int index = first; index < last; ++index)
                    {
                        const QPointF mapped = mapChartPoint(upperPoints.at(index), plotRect, xRange, yRange);
                        if (index == first)
                        {
                            fillPath.moveTo(mapped);
                            borderPath.moveTo(mapped);
                        }
                        else
                        {
                            fillPath.lineTo(mapped);
                            borderPath.lineTo(mapped);
                        }
                    }
                    // 上下界必须同一时间槽有效；反向封闭只在该连续区间内执行。
                    for (int index = last - 1; index >= first; --index)
                    {
                        // 平坦下界的旧插值启发式可能独立横移；上下界以同一动画时间槽闭合。
                        const QPointF lowerPoint(upperPoints.at(index).x(), lowerPoints.at(index).y());
                        fillPath.lineTo(mapChartPoint(lowerPoint, plotRect, xRange, yRange));
                    }
                    fillPath.closeSubpath();
                    painter.fillPath(fillPath, areaSeries->brush());
                    if (areaSeries->pen().style() != Qt::NoPen && areaSeries->pen().color().alpha() > 0)
                    {
                        painter.setPen(areaSeries->pen());
                        painter.setBrush(Qt::NoBrush);
                        painter.drawPath(borderPath);
                    }
                    first = last;
                }
            }
            continue;
        }

        if (QLineSeries* lineSeries = dynamic_cast<QLineSeries*>(abstractSeries))
        {
            const QList<QPointF> points = renderedPoints(lineSeries);
            if (!points.isEmpty() && lineSeries->pen().style() != Qt::NoPen
                && lineSeries->pen().color().alpha() > 0)
            {
                QPainterPath linePath;
                bool continuing = false; // NaN/Inf 缺口后必须重新 moveTo。
                for (int pointIndex = 0; pointIndex < points.size(); ++pointIndex)
                {
                    const QPointF point = points.at(pointIndex);
                    if (!std::isfinite(point.x()) || !std::isfinite(point.y()))
                    {
                        continuing = false;
                        continue;
                    }
                    const QPointF mapped = mapChartPoint(point, plotRect, xRange, yRange);
                    if (continuing)
                    {
                        linePath.lineTo(mapped);
                    }
                    else
                    {
                        linePath.moveTo(mapped);
                    }
                    continuing = true;
                }
                painter.setPen(lineSeries->pen());
                painter.setBrush(Qt::NoBrush);
                painter.drawPath(linePath);
            }
            continue;
        }

        if (QBarSeries* barSeries = dynamic_cast<QBarSeries*>(abstractSeries))
        {
            const QList<QBarSet*> sets = barSeries->barSets();
            int maximumValueCount = 0;
            for (QBarSet* set : sets)
            {
                maximumValueCount = std::max(
                    maximumValueCount,
                    static_cast<int>(renderedBarValues(set).size()));
            }
            const bool setsAreCategories = maximumValueCount <= 1 && sets.size() > 1;
            const int categoryCount = setsAreCategories
                ? static_cast<int>(sets.size())
                : std::max(1, maximumValueCount);
            const int barsPerCategory = setsAreCategories
                ? 1
                : std::max(1, static_cast<int>(sets.size()));
            const qreal slotWidth = plotRect.width() / std::max(1, categoryCount);
            const qreal groupWidth = slotWidth * 0.78;
            const qreal barWidth = groupWidth / barsPerCategory;
            const qreal baselineY = mapChartPoint(QPointF(0.0, 0.0), plotRect, xRange, yRange).y();

            for (int setIndex = 0; setIndex < sets.size(); ++setIndex)
            {
                QBarSet* set = sets.at(setIndex);
                if (set == nullptr)
                {
                    continue;
                }
                const QVector<qreal> values = renderedBarValues(set);
                const int valueCount = setsAreCategories
                    ? std::min(1, static_cast<int>(values.size()))
                    : static_cast<int>(values.size());
                for (int valueIndex = 0; valueIndex < valueCount; ++valueIndex)
                {
                    const int categoryIndex = setsAreCategories ? setIndex : valueIndex;
                    const int groupBarIndex = setsAreCategories ? 0 : setIndex;
                    const qreal groupLeft = plotRect.left()
                        + slotWidth * categoryIndex
                        + (slotWidth - groupWidth) / 2.0;
                    const qreal barLeft = groupLeft + barWidth * groupBarIndex;
                    const qreal valueY = mapChartPoint(
                        QPointF(categoryIndex, values.at(valueIndex)),
                        plotRect,
                        xRange,
                        yRange).y();
                    const QRectF barRect(
                        barLeft + 0.5,
                        std::min(valueY, baselineY),
                        std::max<qreal>(1.0, barWidth - 1.0),
                        std::max<qreal>(0.5, std::abs(baselineY - valueY)));
                    painter.setBrush(set->brush());
                    painter.setPen(set->borderColor().alpha() > 0
                        ? QPen(set->borderColor(), 0.8)
                        : QPen(Qt::NoPen));
                    painter.drawRect(barRect);
                }
            }
        }
    }
    painter.restore();

    if (!legendRect.isEmpty())
    {
        QFont legendFont = m_chart->legend()->font();
        if (legendFont.family().isEmpty())
        {
            legendFont = font();
        }
        painter.setFont(legendFont);
        painter.setPen(brushColorOr(m_chart->legend()->labelBrush(), palette().color(QPalette::Text)));
        const QFontMetricsF legendMetrics(legendFont);
        qreal totalWidth = 0.0;
        for (const LegendEntry& entry : legendEntries)
        {
            totalWidth += 13.0 + legendMetrics.horizontalAdvance(entry.name) + 12.0;
        }
        qreal currentX = legendRect.left() + std::max<qreal>(0.0, (legendRect.width() - totalWidth) / 2.0);
        for (const LegendEntry& entry : legendEntries)
        {
            const qreal textWidth = legendMetrics.horizontalAdvance(entry.name);
            painter.fillRect(
                QRectF(currentX, legendRect.center().y() - 3.0, 8.0, 6.0),
                entry.color);
            painter.drawText(
                QRectF(currentX + 11.0, legendRect.top(), textWidth, legendRect.height()),
                Qt::AlignLeft | Qt::AlignVCenter,
                entry.name);
            currentX += 13.0 + textWidth + 12.0;
            if (currentX > legendRect.right())
            {
                break;
            }
        }
    }
}
