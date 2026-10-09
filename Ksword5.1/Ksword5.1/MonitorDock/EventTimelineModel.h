#pragma once

// 泛用事件时间轴的轻量模型：类别使用稳定数字身份，标签只参与展示。
#include <QColor>
#include <QString>
#include "../theme.h" // 轨道声明主题语义角色，绘制时才求当前像素色。
#include <cstdint>
#include <vector>

namespace ks::network
{
    enum class PacketTransportProtocol : std::uint8_t;
    enum class PacketDirection : std::uint8_t;
}

namespace ks::ui
{
    enum class TimelineCategory : std::uint32_t
    {
        Other = 0,
        Process = 1,
        Thread = 2,
        Image = 3,
        File = 4,
        Registry = 5,
        Network = 6,
        Dns = 7,
        PowerShell = 8,
        Wmi = 9,
        TaskScheduler = 10,
        Security = 11,
        Defender = 12,
        TcpSend = 101,
        TcpReceive = 102,
        UdpSend = 103,
        UdpReceive = 104,
        Unspecified = 0xffffffffU // 旧两字段初始化缺少身份，禁止偷偷归为 Other。
    };

    struct EventTimelineTrack
    {
        TimelineCategory categoryId = TimelineCategory::Other; // 身份不随标签翻译或排序改变。
        QString label;                       // 源语言标签，绘制/悬停时才翻译。
        KswordTheme::TimelineRole colorRole = KswordTheme::TimelineRole::Kernel; // 当前主题语义角色。
    };

    struct EventTimelinePoint
    {
        std::uint64_t time100ns = 0;          // 原始绝对或会话相对 100ns，不由像素桶反推。
        QString typeText;                    // 兼容展示字段，聚合绝不读取或解析此文本。
        TimelineCategory categoryId = TimelineCategory::Unspecified; // 未明确适配的旧点不能进入新绘制路径。
    };

    struct EventTimelineBucket
    {
        TimelineCategory categoryId = TimelineCategory::Other; // 此桶的稳定轨道身份。
        int laneIndex = 0;                   // 配置顺序决定可视行，调整顺序不改变 categoryId。
        int pixelColumn = 0;                 // 按当前 viewport 物理像素预算分桶。
        std::size_t count = 0;               // 桶中原始事件总数，不用最新一条代替全部事件。
        std::uint64_t minTime100ns = 0;       // 桶中原始最早时间，保留 100ns 精度。
        std::uint64_t maxTime100ns = 0;       // 桶中原始最晚时间，保留 100ns 精度。
    };

    // 配置与分类供实际 ETW/网络两个生产消费者共用，数字身份与机器字段绑定。
    std::vector<EventTimelineTrack> EtwTimelineTracks();
    std::vector<EventTimelineTrack> PacketTimelineTracks();
    TimelineCategory TimelineCategoryForEtwProvider(const QString& providerMachineName,
        const QString& eventMachineName = QString());
    // MakeEtwTimelinePoint：全局 ETW 拼点共用，mappedTime100ns 已经由宿主转换暂停会话。
    EventTimelinePoint MakeEtwTimelinePoint(std::uint64_t mappedTime100ns,
        const QString& providerMachineName, const QString& eventMachineName, const QString& displayType);
    // 显式旧入口适配器：只有调用此方法才会从旧源类别词转换身份，新核心不读 typeText。
    EventTimelinePoint MakeLegacyTimelinePoint(std::uint64_t time100ns, const QString& sourceType);
    // 百分比缩放和锚点均使用精确整数；返回夹限后的100ns时长，不经double转换。
    std::uint64_t ScaleTimelineDuration(std::uint64_t duration, std::uint32_t numerator,
        std::uint32_t denominator, std::uint64_t maximum);
    std::uint64_t TimelineProportionalOffset(std::uint64_t offset, std::uint64_t oldSpan,
        std::uint64_t newSpan);
    TimelineCategory TimelineCategoryForPacket(ks::network::PacketTransportProtocol protocol,
        ks::network::PacketDirection direction);

    // AggregateTimelineEvents：只生成绘制投影，不修改原始事件或宿主筛选集合。
    // 范围包含两个端点；桶 count/min/max 与输入顺序无关，最多 lanes*pixelBudget 桶。
    std::vector<EventTimelineBucket> AggregateTimelineEvents(
        const std::vector<EventTimelinePoint>& events,
        const std::vector<EventTimelineTrack>& tracks,
        std::uint64_t start100ns, std::uint64_t end100ns, int pixelBudget);
}
