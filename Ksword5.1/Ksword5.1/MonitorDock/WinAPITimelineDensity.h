#pragma once
#include "EventTimelineModel.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <map>
#include <vector>

namespace ks::monitor {
// All-session bounded density. Bucket width increases by powers of two as the
// timestamp span grows. Per-category endpoints retain the time distribution
// inside each bucket, without storing individual event identities.
class WinAPITimelineDensity final {
public:
    static constexpr std::uint64_t ticksPerSecond = 10000000ULL;
    static constexpr std::uint64_t ticksPerMillisecond = 10000ULL;
    static constexpr std::uint64_t initialWidthTicks = 10 * ticksPerMillisecond;
    static constexpr std::size_t maxBuckets = 2048;
    static constexpr std::size_t categoryCount = 7;
    struct DensityCell { std::size_t count = 0; std::uint64_t first = 0, last = 0; };
    using Counts = std::array<DensityCell, categoryCount>;
    void clear() { m_buckets.clear(); m_first = m_last = m_count = 0; m_widthTicks = initialWidthTicks; }
    void append(std::uint64_t timestamp, std::size_t category) {
        if (!timestamp || category >= categoryCount) return;
        if (!m_count) m_first = m_last = timestamp;
        else { m_first = std::min(m_first, timestamp); m_last = std::max(m_last, timestamp); }
        while (m_last / m_widthTicks - m_first / m_widthTicks >= maxBuckets) coarsen();
        auto& cell = m_buckets[timestamp / m_widthTicks][category];
        if (!cell.count) cell.first = cell.last = timestamp;
        else { cell.first = std::min(cell.first, timestamp); cell.last = std::max(cell.last, timestamp); }
        if (cell.count < std::numeric_limits<std::size_t>::max()) ++cell.count;
        if (m_count < std::numeric_limits<std::uint64_t>::max()) ++m_count;
    }
    std::vector<ks::ui::EventTimelinePoint> points() const {
        static constexpr ks::ui::TimelineCategory categories[] = {
            ks::ui::TimelineCategory::File, ks::ui::TimelineCategory::Registry,
            ks::ui::TimelineCategory::Network, ks::ui::TimelineCategory::Process,
            ks::ui::TimelineCategory::Image, ks::ui::TimelineCategory::Thread,
            ks::ui::TimelineCategory::Other };
        std::vector<ks::ui::EventTimelinePoint> out;
        out.reserve(m_buckets.size() * categoryCount);
        for (const auto& [bucket, counts] : m_buckets) {
            (void)bucket;
            for (std::size_t c = 0; c < categoryCount; ++c)
                if (counts[c].count) {
                    // Midpoint is based on this category's real timestamps,
                    // not the shared bucket start; no fabricated event identity.
                    const auto time = counts[c].first + (counts[c].last - counts[c].first) / 2;
                    out.push_back({time, {}, categories[c], counts[c].count});
                }
        }
        return out;
    }
    std::uint64_t first() const { return m_first; }
    std::uint64_t last() const { return m_last; }
    std::uint64_t count() const { return m_count; }
    std::uint64_t widthMilliseconds() const { return m_widthTicks / ticksPerMillisecond; }
    std::size_t bucketCount() const { return m_buckets.size(); }
private:
    void coarsen() {
        std::map<std::uint64_t, Counts> merged;
        for (const auto& [bucket, counts] : m_buckets) {
            auto& dst = merged[bucket / 2];
            for (std::size_t i = 0; i < categoryCount; ++i) {
                const auto& src = counts[i]; auto& cell = dst[i];
                if (!src.count) continue;
                if (!cell.count) cell = src;
                else {
                    cell.first = std::min(cell.first, src.first); cell.last = std::max(cell.last, src.last);
                    cell.count = src.count > std::numeric_limits<std::size_t>::max() - cell.count
                        ? std::numeric_limits<std::size_t>::max() : cell.count + src.count;
                }
            }
        }
        m_buckets.swap(merged); m_widthTicks *= 2;
    }
    std::map<std::uint64_t, Counts> m_buckets;
    std::uint64_t m_first = 0, m_last = 0, m_count = 0, m_widthTicks = initialWidthTicks;
};
}
