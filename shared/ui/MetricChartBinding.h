#pragma once

// 图表绑定只投影历史模型，不持颜色角色；现有系列/坐标轴/主题对象继续复用。
#include "KsPainterChart.h"
#include "MetricHistory.h"

#include <QPointer>
#include <memory>

namespace ks::ui
{
    class MetricChartBinding final : public QObject
    {
    public:
        // series 拥有绑定；已有系列 identity 与 QObject 生命周期均不改变。
        explicit MetricChartBinding(QLineSeries* series, std::size_t capacity = 60);
        // 复用系列已有绑定；首次接入的初始化零线按无效占位保留，不能伪造真实采样。
        static MetricChartBinding* ForSeries(QLineSeries* series, std::size_t capacity = 60);
        static MetricChartBinding* Find(const QLineSeries* series);
        // append 只由采样拥有者调用；mirror 不产生另一份采样。
        void append(MetricSample sample);
        void setXMode(MetricXMode mode);
        MetricXMode xMode() const;
        std::shared_ptr<MetricHistory> history() const;
        // 同进程镜像直接共享模型，HUD 在独立进程复用算法和自己的模型实例。
        void shareHistoryFrom(const MetricChartBinding& source);
        // 重绘数据不采样、不改主题、不替换系列，缺失值用 NaN 标记绘制断点。
        void refreshSeries();
        MetricAxisRange range(const MetricAxisPolicy& policy) const;
        static MetricAxisRange SharedRange(const QList<QLineSeries*>& series,
            MetricXMode mode, const MetricAxisPolicy& policy);
        static void MirrorSeries(QLineSeries* source, QLineSeries* target);

    private:
        QPointer<QLineSeries> m_series; // 现有绘制系列的弱引用。
        std::shared_ptr<MetricHistory> m_history; // 主图和镜像的同一采样模型。
        MetricXMode m_xMode = MetricXMode::StableId; // 坐标投影不改变采样身份。
    };
}
