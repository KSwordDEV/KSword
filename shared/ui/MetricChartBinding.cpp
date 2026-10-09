#include "MetricChartBinding.h"

#include <algorithm>
#include <limits>

namespace ks::ui
{
    MetricChartBinding::MetricChartBinding(QLineSeries* series, const std::size_t capacity)
        : QObject(series), m_series(series), m_history(std::make_shared<MetricHistory>(capacity))
    {
        if (series)
        {
            // 构造期预填的零线只决定初始时间槽，不能计入真实峰值或有效样本数。
            for (const QPointF& point : series->points())
            {
                m_history->append({ 0, 0, point.y(), false });
            }
        }
    }

    MetricChartBinding* MetricChartBinding::Find(const QLineSeries* series)
    {
        if (series)
        {
            for (QObject* child : series->children())
            {
                if (auto* binding = dynamic_cast<MetricChartBinding*>(child))
                {
                    return binding;
                }
            }
        }
        return nullptr;
    }

    MetricChartBinding* MetricChartBinding::ForSeries(QLineSeries* series, const std::size_t capacity)
    {
        if (!series)
        {
            return nullptr;
        }
        if (auto* binding = Find(series))
        {
            binding->m_history->setCapacity(capacity);
            return binding;
        }
        return new MetricChartBinding(series, capacity);
    }

    void MetricChartBinding::append(MetricSample sample)
    {
        m_history->append(sample);
        refreshSeries();
    }

    void MetricChartBinding::setXMode(const MetricXMode mode)
    {
        m_xMode = mode;
    }

    MetricXMode MetricChartBinding::xMode() const
    {
        return m_xMode;
    }

    std::shared_ptr<MetricHistory> MetricChartBinding::history() const
    {
        return m_history;
    }

    // 共享数据只替换模型来源；镜像自身 palette、字体、比例与系列仍独立。
    void MetricChartBinding::shareHistoryFrom(const MetricChartBinding& source)
    {
        m_history = source.m_history;
        m_xMode = source.m_xMode;
    }

    void MetricChartBinding::refreshSeries()
    {
        if (!m_series)
        {
            return;
        }
        QList<QPointF> points; // 此视图按自身坐标策略生成的临时显示投影。
        points.reserve(static_cast<qsizetype>(m_history->samples().size()));
        for (std::size_t index = 0; index < m_history->samples().size(); ++index)
        {
            const MetricSample& sample = m_history->samples()[index];
            points.append(QPointF(m_history->projectedX(index, m_xMode),
                sample.valid ? sample.value : std::numeric_limits<double>::quiet_NaN()));
        }
        m_series->replace(points);
    }

    MetricAxisRange MetricChartBinding::range(const MetricAxisPolicy& policy) const
    {
        return m_history->axisRange(m_xMode, policy);
    }

    MetricAxisRange MetricChartBinding::SharedRange(const QList<QLineSeries*>& series,
        const MetricXMode mode, const MetricAxisPolicy& policy)
    {
        std::vector<const MetricHistory*> histories; // 共轴曲线只读取共享历史的有效值。
        for (QLineSeries* line : series)
        {
            if (const auto* binding = Find(line))
            {
                histories.push_back(binding->m_history.get());
            }
        }
        return MetricHistory::combinedAxisRange(histories, mode, policy);
    }

    void MetricChartBinding::MirrorSeries(QLineSeries* source, QLineSeries* target)
    {
        if (!source || !target)
        {
            return;
        }
        auto* sourceBinding = Find(source); // 源采样绑定通常已经由生产 append 创建。
        if (!sourceBinding)
        {
            // 首帧前允许建立占位模型；此后生产 append 接管同一模型。
            sourceBinding = ForSeries(source, static_cast<std::size_t>(std::max(1, source->count())));
        }
        auto* targetBinding = Find(target);
        if (!targetBinding)
        {
            targetBinding = new MetricChartBinding(target, sourceBinding->history()->capacity());
        }
        targetBinding->shareHistoryFrom(*sourceBinding);
        targetBinding->refreshSeries();
    }
}
