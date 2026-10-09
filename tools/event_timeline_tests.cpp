// 实际生产 QWidget + ETW/报文两种轨道配置的离屏验收，不启动抓包或 ETW 会话。
#include "../Ksword5.1/Ksword5.1/MonitorDock/ProcessTraceTimelineWidget.h"
#include "../Ksword5.1/Ksword5.1/ksword/network/network.h"
#include "../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include "../Ksword5.1/Ksword5.1/theme.h"

#include <QApplication>
#include <QHelpEvent>
#include <QImage>
#include <QMouseEvent>
#include <QTest>
#include <QToolTip>
#include <QWheelEvent>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>

namespace
{
    unsigned checks = 0; // 断言计数，不以原始事件数量伪造通过数量。
    using Category = ks::ui::TimelineCategory;

    void require(const bool condition, const char* message)
    {
        ++checks;
        if (!condition)
        {
            std::cerr << "TIMELINE_FAIL [" << checks << "]: " << message << '\n';
            std::exit(1);
        }
    }

    // countEvents：读取生产聚合结果中完整计数，不能用桶数量代替原始事件数量。
    std::size_t countEvents(const std::vector<ks::ui::EventTimelineBucket>& buckets)
    {
        std::size_t count = 0;
        for (const auto& bucket : buckets)
        {
            count += bucket.count;
        }
        return count;
    }

    bool sameBuckets(const std::vector<ks::ui::EventTimelineBucket>& left,
        const std::vector<ks::ui::EventTimelineBucket>& right)
    {
        if (left.size() != right.size())
        {
            return false;
        }
        for (std::size_t index = 0; index < left.size(); ++index)
        {
            if (left[index].categoryId != right[index].categoryId ||
                left[index].pixelColumn != right[index].pixelColumn ||
                left[index].count != right[index].count ||
                left[index].minTime100ns != right[index].minTime100ns ||
                left[index].maxTime100ns != right[index].maxTime100ns)
            {
                return false;
            }
        }
        return true;
    }

    // profiles：真实宿主调用同一生产配置函数，类别身份来自机器字段而非 UI 标签。
    void profiles()
    {
        using Protocol = ks::network::PacketTransportProtocol;
        using Direction = ks::network::PacketDirection;
        const auto etw = ks::ui::EtwTimelineTracks();
        const auto packets = ks::ui::PacketTimelineTracks();
        require(etw.size() == 13 && packets.size() == 5, "ETW and network consumers configure independent lane sets");
        require(ks::ui::TimelineCategoryForEtwProvider(QStringLiteral("Microsoft-Windows-Kernel-Process")) == Category::Process,
            "ETW machine provider selects stable process category");
        require(ks::ui::TimelineCategoryForEtwProvider(QStringLiteral("microsoft-windows-dns-client")) == Category::Dns,
            "ETW provider case does not change identity");
        require(ks::ui::TimelineCategoryForEtwProvider(QStringLiteral("Microsoft-Windows-Kernel-Process"),
            QStringLiteral("Thread/DCStart")) == Category::Thread,
            "directed ETW provider plus actual row event name selects thread subtype");
        require(ks::ui::TimelineCategoryForEtwProvider(QStringLiteral("Microsoft-Windows-Kernel-Process"),
            QStringLiteral("ImageLoad")) == Category::Image,
            "directed ETW provider plus actual row event name selects image subtype");
        require(ks::ui::TimelineCategoryForEtwProvider(QStringLiteral("进程")) == Category::Other,
            "translated category label cannot masquerade as an ETW provider identity");
        require(ks::ui::TimelineCategoryForPacket(Protocol::Tcp, Direction::Outbound) == Category::TcpSend, "TCP outbound has its own lane");
        require(ks::ui::TimelineCategoryForPacket(Protocol::Tcp, Direction::Inbound) == Category::TcpReceive, "TCP inbound has its own lane");
        require(ks::ui::TimelineCategoryForPacket(Protocol::Udp, Direction::Outbound) == Category::UdpSend, "UDP outbound has its own lane");
        require(ks::ui::TimelineCategoryForPacket(Protocol::Udp, Direction::Inbound) == Category::UdpReceive, "UDP inbound has its own lane");
        require(ks::ui::TimelineCategoryForPacket(Protocol::Udp, Direction::Unknown) == Category::Other, "unknown direction remains explicitly unknown");
        require(ks::ui::TimelineCategoryForEtwProvider(QStringLiteral("Kernel-UDPIP")) == Category::Network,
            "classic UDP provider preserves global ETW network lane");
        require(ks::ui::TimelineCategoryForEtwProvider(QStringLiteral("Kernel-CSwitch")) == Category::Thread,
            "classic scheduler provider preserves global ETW thread lane");

        // 与全局 ETW 两个生产拼点位置使用同一完整 factory，暂停转换结果只透传一次。
        const std::uint64_t mappedTime = 133'000'000'012'345'678ULL;
        const auto globalThread = ks::ui::MakeEtwTimelinePoint(mappedTime,
            QStringLiteral("Microsoft-Windows-Kernel-Process"), QStringLiteral("ThreadStart"), QStringLiteral("display type"));
        require(globalThread.time100ns == mappedTime && globalThread.categoryId == Category::Thread,
            "global ETW factory preserves effective absolute time and Kernel-Process thread subtype");
        const auto globalImage = ks::ui::MakeEtwTimelinePoint(mappedTime,
            QStringLiteral("Kernel-Process"), QStringLiteral("Image/Load"), QStringLiteral("translated image label"));
        require(globalImage.categoryId == Category::Image && globalImage.typeText == QStringLiteral("translated image label"),
            "global ETW image subtype is independent of its translated display label");
        const auto legacy = ks::ui::MakeLegacyTimelinePoint(mappedTime, QStringLiteral("镜像"));
        require(legacy.categoryId == Category::Image && legacy.time100ns == mappedTime,
            "named legacy adapter explicitly preserves old source category identity");

        // 标签改语言不影响轨道；重排配置只改变 laneIndex，保持 category 与计数。
        std::vector<ks::ui::EventTimelinePoint> points;
        for (std::size_t index = 0; index < etw.size(); ++index)
        {
            points.push_back({ 100 + index, QStringLiteral("unrelated display label"), etw[index].categoryId });
        }
        auto translated = etw;
        for (auto& track : translated)
        {
            track.label = QStringLiteral("translated display label");
        }
        const auto originalBuckets = ks::ui::AggregateTimelineEvents(points, etw, 100, 120, 200);
        const auto translatedBuckets = ks::ui::AggregateTimelineEvents(points, translated, 100, 120, 200);
        require(sameBuckets(originalBuckets, translatedBuckets), "display text changes never affect category buckets");
        std::reverse(translated.begin(), translated.end());
        const auto reversedBuckets = ks::ui::AggregateTimelineEvents(points, translated, 100, 120, 200);
        require(countEvents(reversedBuckets) == points.size(), "track reorder retains every categorized event");
        require(reversedBuckets.front().categoryId == Category::Other, "reordered track order controls visual lanes by stable IDs");
    }

    // numericBoundaries：极大绝对时间与右端点都以整数精确保留 count/min/max。
    void numericBoundaries()
    {
        const auto tracks = ks::ui::PacketTimelineTracks();
        const std::uint64_t end = std::numeric_limits<std::uint64_t>::max();
        const std::uint64_t start = end - 1'000'000;
        const std::vector<ks::ui::EventTimelinePoint> points = {
            {start, QString(), Category::TcpSend}, {start + 1, QString(), Category::TcpSend},
            {end - 1, QString(), Category::TcpSend}, {end, QString(), Category::TcpSend}
        };
        const auto buckets = ks::ui::AggregateTimelineEvents(points, tracks, start, end, 113);
        require(countEvents(buckets) == 4, "both timestamp endpoints participate in aggregation");
        require(buckets.front().pixelColumn == 0 && buckets.front().minTime100ns == start,
            "first bucket keeps its exact sixty-four-bit minimum");
        require(buckets.back().pixelColumn == 112 && buckets.back().maxTime100ns == end,
            "last bucket keeps UINT64_MAX without product overflow");
        const auto wideRange = ks::ui::AggregateTimelineEvents({ {end / 2, QString(), Category::TcpSend} },
            tracks, 0, end, 10000);
        require(wideRange.front().pixelColumn == 4999,
            "integer 128-bit mapping distinguishes just-below-half from rounded half");
        require(ks::ui::AggregateTimelineEvents(points, tracks, start, end, 0).empty(), "zero drawing budget produces no projection");
        require(ks::ui::AggregateTimelineEvents(points, tracks, end, start, 113).empty(), "reversed range produces no projection");
        const auto oneColumn = ks::ui::AggregateTimelineEvents(points, tracks, start, end, 1);
        require(oneColumn.size() == 1 && oneColumn.front().count == 4,
            "single-pixel viewport retains complete density count");
    }

    // viewportProjection：大样本输入完整保留；真实 resize/range 改变重聚合绘制投影。
    void viewportProjection()
    {
        ProcessTraceTimelineWidget packets;
        packets.setTracks(ks::ui::PacketTimelineTracks());
        packets.resize(160, 40);
        packets.setCaptureRange(10'000'000, 20'000'000);
        std::vector<ProcessTraceTimelineEventPoint> events;
        const Category categories[] = {Category::TcpSend, Category::TcpReceive, Category::UdpSend, Category::UdpReceive};
        for (std::size_t index = 0; index < 50000; ++index)
        {
            events.push_back({ 10'000'000 + (index % 500) * 20000, QStringLiteral("display text"), categories[index % 4] });
        }
        events.push_back({9'999'999, QString(), Category::Other});
        events.push_back({20'000'001, QString(), Category::Other});
        packets.setEventPoints(events);
        packets.show();
        QApplication::processEvents();
        const auto small = packets.eventBuckets();
        require(packets.eventPointCount() == events.size(), "widget retains all raw events including events outside current projection");
        require(countEvents(small) == 50000, "range projection counts all in-range events without using latest-only replacement");
        require(small.size() <= static_cast<std::size_t>(packets.aggregationPixelBudget()) * packets.tracks().size(),
            "drawing work is bounded by actual viewport pixel columns times configured tracks");
        packets.resize(640, 40);
        QApplication::processEvents();
        const auto large = packets.eventBuckets();
        require(large.size() >= small.size() && countEvents(large) == 50000,
            "larger viewport refines buckets while preserving exact density");
        require(packets.eventPointCount() == events.size(), "resize never decimates the raw point cache");

        // 重新排序原事件得到完全相同的桶，再换较窄捕获范围验证不能复用旧投影。
        std::reverse(events.begin(), events.end());
        packets.setEventPoints(events);
        require(sameBuckets(large, packets.eventBuckets()), "input reorder leaves count and timestamp bounds unchanged");
        packets.setCaptureRange(12'000'000, 14'000'000);
        const std::size_t expected = static_cast<std::size_t>(std::count_if(events.begin(), events.end(), [](const auto& event)
        {
            return event.time100ns >= 12'000'000 && event.time100ns <= 14'000'000;
        }));
        require(countEvents(packets.eventBuckets()) == expected, "range change reaggregates raw events with inclusive 100ns endpoints");
        require(packets.eventPointCount() == events.size(), "range filtering does not mutate raw event collection");
        const auto validTracks = packets.tracks();
        auto invalidTracks = validTracks;
        invalidTracks.push_back(invalidTracks.front());
        require(!packets.setTracks(invalidTracks) && packets.tracks().size() == validTracks.size(),
            "duplicate track identity rejects configuration atomically");
        require(!packets.setTracks({}), "empty track configuration is rejected");
        const std::size_t oldCount = packets.eventPointCount();
        require(!packets.setEventPoints({{12'000'000, QStringLiteral("网络")}}) &&
            packets.eventPointCount() == oldCount,
            "unadapted two-field legacy points are rejected atomically instead of silently placed in Other");

        // ETW 消费者与网络消费者可以同时存在，窗口配置不共享可变轨道状态。
        ProcessTraceTimelineWidget etw;
        etw.resize(400, 40);
        etw.setTracks(ks::ui::EtwTimelineTracks());
        etw.setCaptureRange(1000, 2000);
        etw.setEventPoints({{1001, QStringLiteral("Network"), Category::Process}, {1002, QStringLiteral("Process"), Category::Dns}});
        require(etw.eventBuckets().front().categoryId == Category::Process, "ETW point identity wins over contradictory display label");
        require(etw.tracks().size() == 13 && packets.tracks().size() == 5, "independent real widgets retain both consumer profiles");
    }

    void sendWheel(ProcessTraceTimelineWidget& widget, const int delta)
    {
        const QPointF position(widget.width() / 2.0, widget.height() / 2.0);
        QWheelEvent wheel(position, widget.mapToGlobal(position.toPoint()), QPoint(), QPoint(0, delta),
            Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
        QApplication::sendEvent(&widget, &wheel);
    }

    void sendWheelAt(ProcessTraceTimelineWidget& widget, const int delta, const QPoint& position)
    {
        QWheelEvent wheel(position, widget.mapToGlobal(position), QPoint(), QPoint(0, delta),
            Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
        QApplication::sendEvent(&widget, &wheel);
    }

    // 显式满幅 U64 验证区别于高 base 小窗口；倍率与锚点不能经 double 越界转换。
    void fullWidthZoom()
    {
        ProcessTraceTimelineWidget widget;
        widget.resize(420, 40);
        const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
        const auto reset = [&widget, maximum]()
        {
            widget.resetTimeline(0);
            widget.setCaptureRange(0, maximum);
        };
        reset();
        sendWheel(widget, 120);
        require(widget.selectionStart100ns() == 0 && widget.selectionEnd100ns() == maximum,
            "full UINT64 range wheel expansion must saturate before integer conversion");
        reset();
        sendWheelAt(widget, -120, QPoint(416, 20));
        const std::uint64_t reduced = (maximum / 5) * 4 + ((maximum % 5) * 4) / 5;
        require(widget.selectionEnd100ns() == maximum && widget.selectionStart100ns() == maximum - reduced,
            "right-edge full range anchor keeps endpoint and exact four-fifths width");
        reset();
        sendWheelAt(widget, -120, QPoint(4, 20));
        require(widget.selectionStart100ns() == 0 && widget.selectionEnd100ns() == reduced,
            "left-edge full range anchor keeps endpoint and exact four-fifths width");
        reset();
        sendWheelAt(widget, 120, QPoint(416, 20));
        require(widget.selectionStart100ns() == 0 && widget.selectionEnd100ns() == maximum,
            "right-edge unit anchor cannot cast rounded two-to-sixty-four into uint64");
    }

    // 真实 QObject 析构哨兵：回调替换/关闭自身不能释放正在执行 callable 的捕获。
    void callbackLifetime()
    {
        auto* widget = new ProcessTraceTimelineWidget;
        widget->resize(420, 40);
        widget->setCaptureRange(1000, 20'001'000);
        auto sentinel = std::make_shared<QObject>();
        std::weak_ptr<QObject> weakSentinel = sentinel;
        bool destroyed = false;
        bool aliveInside = false;
        QObject::connect(sentinel.get(), &QObject::destroyed, qApp, [&destroyed]() { destroyed = true; });
        widget->setSelectionChangedCallback([widget, sentinel, &destroyed, &aliveInside](std::uint64_t, std::uint64_t)
        {
            widget->setSelectionChangedCallback({});
            aliveInside = !destroyed;
        });
        sentinel.reset();
        sendWheel(*widget, -120);
        require(aliveInside && weakSentinel.expired(), "self-replacing callback keeps capture alive until callback returns");
        delete widget;

        // 同步删除控件后，事件 handler 和 notify 都不再借用成员。
        widget = new ProcessTraceTimelineWidget;
        widget->resize(420, 40);
        widget->setCaptureRange(1000, 20'001'000);
        const QPointer<ProcessTraceTimelineWidget> guard(widget);
        sentinel = std::make_shared<QObject>();
        weakSentinel = sentinel;
        destroyed = false;
        aliveInside = false;
        QObject::connect(sentinel.get(), &QObject::destroyed, qApp, [&destroyed]() { destroyed = true; });
        widget->setSelectionChangedCallback([widget, sentinel, &destroyed, &aliveInside](std::uint64_t, std::uint64_t)
        {
            delete widget;
            aliveInside = !destroyed;
        });
        sentinel.reset();
        sendWheel(*widget, -120);
        require(guard.isNull() && aliveInside && weakSentinel.expired(),
            "callback may synchronously destroy actual QWidget without destroying executing capture");
    }

    // gestures：使用真实事件路径，回调始终返回完整绝对 100ns 选区，不从桶反推。
    void gestures()
    {
        ProcessTraceTimelineWidget widget;
        widget.resize(420, 40);
        widget.show();
        const std::uint64_t base = 133'000'000'000'000'000ULL;
        const std::uint64_t end = base + 20'000'000;
        widget.setCaptureRange(base, end);
        unsigned callbacks = 0;
        widget.setSelectionChangedCallback([&callbacks, base, end](const std::uint64_t left, const std::uint64_t right)
        {
            ++callbacks;
            require(left >= base && right <= end && right > left, "gesture callback retains valid absolute 100ns bounds");
        });
        sendWheel(widget, -120);
        require(callbacks == 1 && widget.selectionEnd100ns() - widget.selectionStart100ns() == 16'000'000,
            "wheel down preserves original eighty-percent selection zoom behavior");
        const std::uint64_t oldStart = widget.selectionStart100ns();
        const std::uint64_t oldWidth = widget.selectionEnd100ns() - oldStart;
        QTest::mousePress(&widget, Qt::LeftButton, Qt::NoModifier, QPoint(210, 20));
        QTest::mouseMove(&widget, QPoint(235, 20));
        QTest::mouseRelease(&widget, Qt::LeftButton, Qt::NoModifier, QPoint(235, 20));
        require(widget.selectionStart100ns() > oldStart && widget.selectionEnd100ns() - widget.selectionStart100ns() == oldWidth,
            "dragging selection keeps its width and moves absolute bounds");
        const int edge = 4 + static_cast<int>((widget.selectionStart100ns() - base) * 412 / (end - base));
        const std::uint64_t rightBeforeResize = widget.selectionEnd100ns();
        QTest::mousePress(&widget, Qt::LeftButton, Qt::NoModifier, QPoint(edge, 20));
        QTest::mouseMove(&widget, QPoint(edge + 7, 20));
        QTest::mouseRelease(&widget, Qt::LeftButton, Qt::NoModifier, QPoint(edge + 7, 20));
        require(widget.selectionEnd100ns() == rightBeforeResize, "left edge resize keeps right timestamp stable");
        widget.resetSelectionToFullRange();
        require(widget.selectionStart100ns() == base && widget.selectionEnd100ns() == end, "full-range reset preserves absolute session endpoints");

        // 超出 signed 64-bit 的绝对时间仍可拖动/缩放，边界默认跨度使用饱和相加。
        widget.setSelectionChangedCallback({});
        const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
        widget.resetTimeline(maximum - 1'000'000);
        widget.setCaptureRange(maximum - 1'000'000, maximum);
        sendWheel(widget, -120);
        const std::uint64_t highWidth = widget.selectionEnd100ns() - widget.selectionStart100ns();
        QTest::mousePress(&widget, Qt::LeftButton, Qt::NoModifier, QPoint(210, 20));
        QTest::mouseMove(&widget, QPoint(235, 20));
        QTest::mouseRelease(&widget, Qt::LeftButton, Qt::NoModifier, QPoint(235, 20));
        require(widget.selectionStart100ns() >= maximum - 1'000'000 && widget.selectionEnd100ns() <= maximum,
            "high absolute timestamp drag never wraps or truncates through signed time");
        require(widget.selectionEnd100ns() - widget.selectionStart100ns() == highWidth,
            "high timestamp drag keeps width exactly");
        widget.resetTimeline(maximum - 4);
        require(widget.selectionEnd100ns() == maximum, "default range saturation cannot wrap to zero");
    }

    // rendering：真实 QPainter 体现桶密度、动态主题和两个配置的热语言显示。
    void rendering()
    {
        ProcessTraceTimelineWidget widget;
        widget.resize(320, 40);
        widget.setTracks(ks::ui::PacketTimelineTracks());
        widget.setCaptureRange(1000, 2000);
        widget.setEventPoints({{1500, QString(), Category::TcpSend}});
        widget.show();
        QApplication::processEvents();
        const QImage sparse = widget.grab().toImage();
        widget.setEventPoints(std::vector<ProcessTraceTimelineEventPoint>(25, {1500, QString(), Category::TcpSend}));
        const QImage dense = widget.grab().toImage();
        require(sparse != dense, "actual painter draws dense bucket differently from a single event");
        require(widget.eventBuckets().front().count == 25 && widget.eventBuckets().front().minTime100ns == 1500,
            "painted density comes from exact count and minimum");
        const auto buckets = widget.eventBuckets();
        KswordTheme::SetPrimaryAccentColor(QStringLiteral("#a035ca"));
        KswordTheme::SetDarkModeEnabled(true);
        widget.update();
        const QImage themed = widget.grab().toImage();
        require(themed != dense, "real existing timeline recomputes theme-derived drawing colors");
        require(sameBuckets(buckets, widget.eventBuckets()), "theme switch does not alter event identity or timestamps");

        QString error;
        require(ks::i18n::LanguageManager::instance().setLanguage(QStringLiteral("en-US"), &error), "real language manager loads English pack");
        require(widget.trackLabel(Category::TcpSend) == QStringLiteral("TCP send"), "existing network lane label is translated by real language pack");
        require(sameBuckets(buckets, widget.eventBuckets()), "language switch does not alter bucket identity or density");
        QHelpEvent help(QEvent::ToolTip, QPoint(160, 4), widget.mapToGlobal(QPoint(160, 4)));
        QApplication::sendEvent(&widget, &help);
        require(QToolTip::text().contains(QStringLiteral("TCP send")) && QToolTip::text().contains(QStringLiteral("25 events")),
            "real tooltip shows translated lane and full density count");
        QToolTip::hideText();
        widget.setRateOverlayPoints({{1200, 10.0, 20.0}, {1800, 20.0, 10.0}});
        QTest::qWait(280);
        require(widget.eventPointCount() == 25 && sameBuckets(buckets, widget.eventBuckets()),
            "existing optional network rate animation cannot modify the event projection");
    }
}

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    application.setQuitOnLastWindowClosed(false);
    QString error;
    require(ks::i18n::LanguageManager::instance().initialize(QStringLiteral("zh-CN"), &error), "real language manager initializes");
    if (argc > 1 && QString::fromLatin1(argv[1]) == QStringLiteral("wheel"))
    {
        fullWidthZoom();
        return 0;
    }
    if (argc > 1 && QString::fromLatin1(argv[1]) == QStringLiteral("callback"))
    {
        callbackLifetime();
        return 0;
    }
    profiles();
    numericBoundaries();
    viewportProjection();
    gestures();
    fullWidthZoom();
    callbackLifetime();
    rendering();
    std::cout << "EVENT_TIMELINE_RESULT=SUCCESS\nEVENT_TIMELINE_CHECKS=" << checks << '\n';
    return 0;
}
