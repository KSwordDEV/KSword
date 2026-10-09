#include "MetricHistory.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace ks::ui
{
    MetricHistory::MetricHistory(const std::size_t capacity) : m_capacity(capacity)
    {
    }

    std::uint64_t MetricHistory::append(MetricSample sample)
    {
        if (!sample.id && m_lastId == std::numeric_limits<std::uint64_t>::max())
        {
            return 0;
        }
        if (!sample.id)
        {
            sample.id = m_lastId + 1;
        }
        sample.valid = sample.valid && std::isfinite(sample.value);
        if (sample.id < m_lastId)
        {
            return 0;
        }
        if (sample.id == m_lastId)
        {
            // 同帧更新保留身份和选择，不能制造第二个历史时刻。
            if (!m_samples.empty() && m_samples.back().id == sample.id)
            {
                m_samples.back() = sample;
            }
            return sample.id;
        }
        m_lastId = sample.id;
        if (m_capacity && m_samples.empty())
        {
            m_originId = sample.id;
        }
        if (m_capacity)
        {
            m_samples.push_back(sample);
        }
        trimAndRestoreAnchor();
        return sample.id;
    }

    void MetricHistory::setCapacity(const std::size_t capacity)
    {
        m_capacity = capacity;
        trimAndRestoreAnchor();
    }

    void MetricHistory::clear()
    {
        m_samples.clear();
        m_selectedId.reset();
        m_followLatest = true;
        m_originId = 0;
    }

    std::size_t MetricHistory::capacity() const
    {
        return m_capacity;
    }

    const std::deque<MetricSample>& MetricHistory::samples() const
    {
        return m_samples;
    }

    bool MetricHistory::followsLatest() const
    {
        return m_followLatest;
    }

    std::optional<std::uint64_t> MetricHistory::selectedId() const
    {
        return m_selectedId;
    }

    // 被淘汰锚点不能按旧行号指向另一采样；明确恢复最新状态。
    void MetricHistory::trimAndRestoreAnchor()
    {
        while (m_samples.size() > m_capacity)
        {
            m_samples.pop_front();
        }
        if (m_samples.empty())
        {
            m_selectedId.reset();
            m_followLatest = true;
            return;
        }
        if (m_selectedId && *m_selectedId < m_samples.front().id)
        {
            m_followLatest = true;
        }
        if (m_followLatest || !m_selectedId)
        {
            m_selectedId = m_samples.back().id;
        }
    }

    bool MetricHistory::select(const std::uint64_t sampleId)
    {
        const auto found = std::find_if(m_samples.begin(), m_samples.end(),
            [sampleId](const MetricSample& sample) { return sample.id == sampleId; });
        if (found == m_samples.end())
        {
            return false;
        }
        m_selectedId = sampleId;
        m_followLatest = sampleId == m_samples.back().id;
        return true;
    }

    void MetricHistory::setFollowLatest(const bool follow)
    {
        m_followLatest = follow;
        if (follow && !m_samples.empty())
        {
            m_selectedId = m_samples.back().id;
        }
    }

    double MetricHistory::projectedX(const std::size_t index, const MetricXMode mode) const
    {
        if (index >= m_samples.size())
        {
            return 0.0;
        }
        if (mode == MetricXMode::RelativeSlot)
        {
            return static_cast<double>(index);
        }
        if (mode == MetricXMode::ElapsedTime)
        {
            // 初始占位或旧来源没有真实时间，不能把 0 当 epoch 撑开整条时间轴。
            const auto origin = std::find_if(m_samples.begin(), m_samples.end(),
                [](const MetricSample& sample) { return sample.timestampMs != 0; });
            if (!m_samples[index].timestampMs || origin == m_samples.end())
            {
                return std::numeric_limits<double>::quiet_NaN();
            }
            return static_cast<double>((static_cast<long double>(m_samples[index].timestampMs)
                - static_cast<long double>(origin->timestampMs)) / 1000.0L);
        }
        return static_cast<double>(m_samples[index].id - m_originId);
    }

    MetricAxisRange MetricHistory::axisRange(const MetricXMode mode, const MetricAxisPolicy& policy) const
    {
        return combinedAxisRange({ this }, mode, policy);
    }

    // 多曲线共轴使用同一策略；无效值不扩大纵轴，仍保留缺失时间的位置。
    MetricAxisRange MetricHistory::combinedAxisRange(const std::vector<const MetricHistory*>& histories,
        const MetricXMode mode, const MetricAxisPolicy& policy)
    {
        MetricAxisRange range; // 全部曲线的显示范围。
        double lowX = std::numeric_limits<double>::max();
        double highX = std::numeric_limits<double>::lowest();
        const double minimumY = std::isfinite(policy.minimumY) ? policy.minimumY : 0.0;
        const double span = std::isfinite(policy.minimumSpan) ? std::max(0.000001, policy.minimumSpan) : 1.0;
        double peak = minimumY + span;
        for (const MetricHistory* history : histories)
        {
            if (!history)
            {
                continue;
            }
            for (std::size_t index = 0; index < history->samples().size(); ++index)
            {
                const auto& sample = history->samples()[index];
                const double x = history->projectedX(index, mode);
                if (!std::isfinite(x))
                {
                    continue; // 时间未知点不参与 ElapsedTime 的横轴或纵轴投影。
                }
                lowX = std::min(lowX, x);
                highX = std::max(highX, x);
                if (sample.valid && std::isfinite(sample.value))
                {
                    range.hasValidSamples = true;
                    peak = std::max(peak, sample.value);
                }
            }
        }
        if (lowX != std::numeric_limits<double>::max())
        {
            // 单点以左右一单位留空间，保持历史图首帧可见。
            range.minimumX = highX > lowX ? lowX : lowX - 1.0;
            range.maximumX = highX > lowX ? highX : highX + 1.0;
        }
        range.minimumY = minimumY;
        const double headroom = std::isfinite(policy.headroom) ? std::max(1.0, policy.headroom) : 1.0;
        range.maximumY = minimumY + (peak - minimumY) * headroom;
        if (policy.fixedMaximumY && std::isfinite(*policy.fixedMaximumY))
        {
            range.maximumY = std::max(minimumY + span, *policy.fixedMaximumY);
        }
        return range;
    }
}
