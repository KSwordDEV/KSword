#include "EventTimelineModel.h"
#include "../theme.h"
#include "../ksword/network/network.h"

#include <algorithm>
#include <unordered_map>
#include <limits>
#if defined(_MSC_VER) && defined(_M_X64)
#include <intrin.h> // 128 位乘除避免 100ns 范围乘像素数溢出。
#endif

namespace
{
    // scaledRatio：精确计算 floor(numerator*multiplier/denominator)，不转换绝对时间为浮点。
    int scaledRatio(const std::uint64_t numerator, const std::uint64_t denominator, const int multiplier)
    {
        if (numerator >= denominator)
        {
            return multiplier - 1; // 右端点属于最后一桶，不生成预算之外的列。
        }
#if defined(_MSC_VER) && defined(_M_X64)
        unsigned __int64 high = 0; // 乘积高半部，确保完整保留 64 位输入。
        const unsigned __int64 low = _umul128(numerator, static_cast<std::uint64_t>(multiplier), &high);
        unsigned __int64 remainder = 0; // 除法余数，本函数只需要商。
        return static_cast<int>(_udiv128(high, low, denominator, &remainder));
#else
        // 可移植路径按乘数位做商余数累加；比较 denominator-remainder 避免加倍溢出。
        std::uint64_t remainder = 0;
        int quotient = 0;
        for (int bit = 30; bit >= 0; --bit)
        {
            quotient *= 2;
            if (remainder >= denominator - remainder)
            {
                remainder -= denominator - remainder;
                ++quotient;
            }
            else
            {
                remainder += remainder;
            }
            if ((static_cast<unsigned>(multiplier) & (1U << bit)) != 0)
            {
                if (remainder >= denominator - numerator)
                {
                    remainder -= denominator - numerator;
                    ++quotient;
                }
                else
                {
                    remainder += numerator;
                }
            }
        }
        return quotient;
#endif
    }

    // track：构造动态主题轨道，颜色查询发生在绘制时，不固定当前主题快照。
    ks::ui::EventTimelineTrack track(const ks::ui::TimelineCategory category, const QString& label,
        const KswordTheme::TimelineRole role)
    {
        return { category, label, role };
    }
}

namespace ks::ui
{
    std::uint64_t ScaleTimelineDuration(const std::uint64_t duration, const std::uint32_t numerator,
        const std::uint32_t denominator, const std::uint64_t maximum)
    {
        if (denominator == 0 || numerator == 0)
        {
            return 0;
        }
        // 先除再乘：商先检查范围，余数与32位乘数的乘积不会溢出64位。
        const std::uint64_t quotient = duration / denominator;
        const std::uint64_t remainder = duration % denominator;
        if (quotient > maximum / numerator)
        {
            return maximum;
        }
        const std::uint64_t base = quotient * numerator;
        const std::uint64_t extra = remainder * numerator / denominator;
        return extra > maximum - base ? maximum : base + extra;
    }

    std::uint64_t TimelineProportionalOffset(const std::uint64_t offset,
        const std::uint64_t oldSpan, const std::uint64_t newSpan)
    {
        if (oldSpan == 0 || offset == 0)
        {
            return 0;
        }
        if (offset >= oldSpan)
        {
            return newSpan; // 比例为1直接返回精确最大跨度，不把double的2^64转回整数。
        }
#if defined(_MSC_VER) && defined(_M_X64)
        unsigned __int64 high = 0;
        const unsigned __int64 low = _umul128(offset, newSpan, &high);
        unsigned __int64 remainder = 0;
        // offset<oldSpan，故商<newSpan<=UINT64_MAX；高半部严格小于除数。
        return _udiv128(high, low, oldSpan, &remainder);
#else
        std::uint64_t quotient = 0;
        std::uint64_t remainder = 0;
        for (int bit = 63; bit >= 0; --bit)
        {
            quotient *= 2;
            if (remainder >= oldSpan - remainder)
            {
                remainder -= oldSpan - remainder;
                ++quotient;
            }
            else
            {
                remainder += remainder;
            }
            if ((newSpan & (std::uint64_t{1} << bit)) != 0)
            {
                if (remainder >= oldSpan - offset)
                {
                    remainder -= oldSpan - offset;
                    ++quotient;
                }
                else
                {
                    remainder += offset;
                }
            }
        }
        return quotient;
#endif
    }

    std::vector<EventTimelineTrack> EtwTimelineTracks()
    {
        // 轨道顺序延续原 ETW 页，标签可翻译，category 数字身份保持固定。
        using C = TimelineCategory;
        using R = KswordTheme::TimelineRole;
        return {
            track(C::Process, QStringLiteral("进程"), R::Process),
            track(C::Thread, QStringLiteral("线程"), R::Thread),
            track(C::Image, QStringLiteral("镜像"), R::Image),
            track(C::File, QStringLiteral("文件"), R::File),
            track(C::Registry, QStringLiteral("注册表"), R::Registry),
            track(C::Network, QStringLiteral("网络"), R::Network),
            track(C::Dns, QStringLiteral("DNS"), R::Dns),
            track(C::PowerShell, QStringLiteral("PowerShell"), R::PowerShell),
            track(C::Wmi, QStringLiteral("WMI"), R::Wmi),
            track(C::TaskScheduler, QStringLiteral("计划任务"), R::Kernel),
            track(C::Security, QStringLiteral("安全审计"), R::Security),
            track(C::Defender, QStringLiteral("Defender"), R::Storage),
            track(C::Other, QStringLiteral("其他"), R::Kernel)
        };
    }

    std::vector<EventTimelineTrack> PacketTimelineTracks()
    {
        // TCP/UDP 的收发独立呈现，方向未知的报文留在明确的 Other 轨道。
        using C = TimelineCategory;
        using R = KswordTheme::TimelineRole;
        return {
            track(C::TcpSend, QStringLiteral("TCP 发送"), R::Network),
            track(C::TcpReceive, QStringLiteral("TCP 接收"), R::File),
            track(C::UdpSend, QStringLiteral("UDP 发送"), R::Dns),
            track(C::UdpReceive, QStringLiteral("UDP 接收"), R::Wmi),
            track(C::Other, QStringLiteral("其他"), R::Kernel)
        };
    }

    TimelineCategory TimelineCategoryForEtwProvider(const QString& providerMachineName,
        const QString& eventMachineName)
    {
        // Provider 名是 ETW 机器身份，不使用可被语言管理器翻译的 typeText。
        const QString name = providerMachineName.trimmed().toLower();
        QString eventName = eventMachineName.toLower(); // 元数据事件名，不是 UI 类别展示词。
        eventName.remove(QLatin1Char('-'));
        eventName.remove(QLatin1Char('_'));
        eventName.remove(QLatin1Char('/'));
        eventName.remove(QLatin1Char(' '));
        if (name == QStringLiteral("kernel-cswitch") || name == QStringLiteral("kernel-dispatcher") ||
            name == QStringLiteral("thread"))
        {
            return TimelineCategory::Thread;
        }
        if (name == QStringLiteral("image"))
        {
            return TimelineCategory::Image;
        }
        if (name.contains(QStringLiteral("kernel-process")) || name == QStringLiteral("process") ||
            name == QStringLiteral("kernel-job"))
        {
            // Kernel-Process 内的 Thread/Image 子事件延续全局 ETW 原有细分。
            if (eventName.startsWith(QStringLiteral("imageload")) || eventName.startsWith(QStringLiteral("imageunload")))
            {
                return TimelineCategory::Image;
            }
            if (name == QStringLiteral("microsoft-windows-kernel-process") && eventName.startsWith(QStringLiteral("thread")))
            {
                return TimelineCategory::Thread;
            }
            return TimelineCategory::Process;
        }
        if (name == QStringLiteral("fileio") || name == QStringLiteral("microsoft-windows-ntfs"))
        {
            return TimelineCategory::File;
        }
        if (name == QStringLiteral("registry"))
        {
            return TimelineCategory::Registry;
        }
        const std::pair<const char*, TimelineCategory> categories[] = {
            {"Kernel-Process", TimelineCategory::Process}, {"Kernel-Thread", TimelineCategory::Thread},
            {"Kernel-Image", TimelineCategory::Image}, {"Kernel-File", TimelineCategory::File},
            {"Kernel-Registry", TimelineCategory::Registry}, {"DNS-Client", TimelineCategory::Dns},
            {"TCPIP", TimelineCategory::Network}, {"AFD", TimelineCategory::Network},
            {"UDPIP", TimelineCategory::Network}, {"Winsock", TimelineCategory::Network},
            {"Kernel-Network", TimelineCategory::Network},
            {"PowerShell", TimelineCategory::PowerShell}, {"WMI-Activity", TimelineCategory::Wmi},
            {"TaskScheduler", TimelineCategory::TaskScheduler}, {"Security-Auditing", TimelineCategory::Security},
            {"Defender", TimelineCategory::Defender}
        };
        for (const auto& category : categories)
        {
            if (providerMachineName.contains(QLatin1String(category.first), Qt::CaseInsensitive))
            {
                return category.second;
            }
        }
        return TimelineCategory::Other;
    }

    EventTimelinePoint MakeEtwTimelinePoint(const std::uint64_t mappedTime100ns,
        const QString& providerMachineName, const QString& eventMachineName, const QString& displayType)
    {
        // 显式保留宿主已经转换好的绝对/有效运行时间，模型不会再次扣除暂停区间。
        return { mappedTime100ns, displayType, TimelineCategoryForEtwProvider(providerMachineName, eventMachineName) };
    }

    EventTimelinePoint MakeLegacyTimelinePoint(const std::uint64_t time100ns, const QString& sourceType)
    {
        // 兼容转换位于命名明确的入口，避免正常 setEventPoints 暗中猜测展示文本。
        const auto tracks = EtwTimelineTracks();
        for (const auto& track : tracks)
        {
            if (track.label == sourceType.trimmed())
            {
                return { time100ns, sourceType, track.categoryId };
            }
        }
        return { time100ns, sourceType, TimelineCategory::Other };
    }

    TimelineCategory TimelineCategoryForPacket(const ks::network::PacketTransportProtocol protocol,
        const ks::network::PacketDirection direction)
    {
        // 协议和方向来自后端枚举，中文/英文类别文字完全不参与分类。
        using P = ks::network::PacketTransportProtocol;
        using D = ks::network::PacketDirection;
        if (protocol == P::Tcp && direction == D::Outbound)
        {
            return TimelineCategory::TcpSend;
        }
        if (protocol == P::Tcp && direction == D::Inbound)
        {
            return TimelineCategory::TcpReceive;
        }
        if (protocol == P::Udp && direction == D::Outbound)
        {
            return TimelineCategory::UdpSend;
        }
        if (protocol == P::Udp && direction == D::Inbound)
        {
            return TimelineCategory::UdpReceive;
        }
        return TimelineCategory::Other;
    }

    std::vector<EventTimelineBucket> AggregateTimelineEvents(
        const std::vector<EventTimelinePoint>& events, const std::vector<EventTimelineTrack>& tracks,
        const std::uint64_t start100ns, const std::uint64_t end100ns, const int pixelBudget)
    {
        std::vector<EventTimelineBucket> buckets;
        if (end100ns <= start100ns || pixelBudget <= 0 || tracks.empty())
        {
            return buckets;
        }
        // 只分配实际有事件的桶，宽屏或大量配置轨道不会创建整张稀疏像素矩阵。
        std::unordered_map<std::uint32_t, int> lanes;
        for (std::size_t index = 0; index < tracks.size(); ++index)
        {
            lanes.emplace(static_cast<std::uint32_t>(tracks[index].categoryId), static_cast<int>(index));
        }
        std::unordered_map<std::uint64_t, std::size_t> indexByBucket;
        const auto fallback = lanes.find(static_cast<std::uint32_t>(TimelineCategory::Other));
        const std::uint64_t duration = end100ns - start100ns;
        for (const EventTimelinePoint& event : events)
        {
            if (event.categoryId == TimelineCategory::Unspecified)
            {
                continue; // 未适配的旧输入不能装成 Other；Widget 会原子拒绝整批。
            }
            if (event.time100ns < start100ns || event.time100ns > end100ns)
            {
                continue;
            }
            auto lane = lanes.find(static_cast<std::uint32_t>(event.categoryId));
            if (lane == lanes.end())
            {
                lane = fallback;
            }
            if (lane == lanes.end())
            {
                continue;
            }
            const int column = scaledRatio(event.time100ns - start100ns, duration, pixelBudget);
            const std::uint64_t key = static_cast<std::uint64_t>(lane->second) *
                static_cast<std::uint64_t>(pixelBudget) + static_cast<std::uint64_t>(column);
            const auto found = indexByBucket.find(key);
            if (found == indexByBucket.end())
            {
                indexByBucket.emplace(key, buckets.size());
                buckets.push_back({ tracks[static_cast<std::size_t>(lane->second)].categoryId,
                    lane->second, column, 1, event.time100ns, event.time100ns });
            }
            else
            {
                EventTimelineBucket& bucket = buckets[found->second];
                ++bucket.count;
                bucket.minTime100ns = std::min(bucket.minTime100ns, event.time100ns);
                bucket.maxTime100ns = std::max(bucket.maxTime100ns, event.time100ns);
            }
        }
        // 输出顺序固定，原始事件输入顺序或到达顺序不同也得到同一绘制投影。
        std::sort(buckets.begin(), buckets.end(), [](const auto& left, const auto& right)
        {
            return left.laneIndex == right.laneIndex ? left.pixelColumn < right.pixelColumn
                : left.laneIndex < right.laneIndex;
        });
        return buckets;
    }
}
