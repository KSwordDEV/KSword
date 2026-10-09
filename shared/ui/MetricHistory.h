#pragma once

// Qt-free 历史模型：采样身份、真实时间和有效性独立于图表坐标与主题。
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <vector>

namespace ks::ui
{
    struct MetricSample
    {
        std::uint64_t id = 0; // 单调递增的稳定采样身份；0 请求自动分配。
        std::int64_t timestampMs = 0; // 实际采样时间，0 表示时间来源未知。
        double value = 0.0; // 原始指标值，是否可用由 valid 明确说明。
        bool valid = false; // 缺失/失败和真实零值必须分开。
    };

    enum class MetricXMode { StableId, RelativeSlot, ElapsedTime };
    struct MetricAxisPolicy
    {
        double minimumY = 0.0; // 固定纵轴下界。
        double minimumSpan = 1.0; // 无有效数据时也保留非零坐标范围。
        double headroom = 1.15; // 自适应上界保留的顶部空间。
        std::optional<double> fixedMaximumY; // 百分比等固定范围，不随峰值变化。
    };
    struct MetricAxisRange
    {
        double minimumX = 0.0; // 包含缺失采样的时间/身份窗口。
        double maximumX = 1.0;
        double minimumY = 0.0; // 仅有效有限值参与纵轴计算。
        double maximumY = 1.0;
        bool hasValidSamples = false; // 无有效样本时供宿主展示可用性。
    };

    class MetricHistory final
    {
    public:
        explicit MetricHistory(std::size_t capacity = 60);
        // 追加或更新最后同一身份；旧身份不回写已发布历史。
        std::uint64_t append(MetricSample sample);
        // 修改容量立即裁剪；0 表示不记录，并保留已分配身份的单调性。
        void setCapacity(std::size_t capacity);
        void clear();
        std::size_t capacity() const;
        const std::deque<MetricSample>& samples() const;
        // 选中跟随稳定身份；被淘汰时回到最新并恢复 followLatest。
        bool select(std::uint64_t sampleId);
        void setFollowLatest(bool follow);
        bool followsLatest() const;
        std::optional<std::uint64_t> selectedId() const;
        // 坐标仅是显示投影，不修改 id/time/value/valid 或选中状态。
        // ElapsedTime 以首个已知时间为原点；timestampMs=0 返回 NaN，原始采样仍保留。
        double projectedX(std::size_t index, MetricXMode mode) const;
        MetricAxisRange axisRange(MetricXMode mode, const MetricAxisPolicy& policy) const;
        static MetricAxisRange combinedAxisRange(const std::vector<const MetricHistory*>& histories,
            MetricXMode mode, const MetricAxisPolicy& policy);

    private:
        void trimAndRestoreAnchor();
        std::deque<MetricSample> m_samples; // 有界的真实采样，缺失点仍占一个时间位置。
        std::size_t m_capacity = 60; // 记录点数上限。
        std::uint64_t m_lastId = 0; // 清空后仍不复用旧采样身份。
        std::uint64_t m_originId = 0; // 稳定坐标起点，避免大采样 ID 转 double 后丢相邻间隔。
        std::optional<std::uint64_t> m_selectedId; // 用户历史锚点或最新身份。
        bool m_followLatest = true; // 新采样是否自动移动锚点。
    };
}
