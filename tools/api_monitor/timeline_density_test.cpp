#include "MonitorDock/WinAPITimelineDensity.h"
#include <QCoreApplication>
#include <chrono>
#include <fstream>
#include <iostream>
#include <numeric>
#include <set>
#define CHECK(v) do { if (!(v)) { std::cerr << "FAIL " << __LINE__ << ": " #v "\n"; return 1; } } while(false)
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    using namespace ks::monitor;
    constexpr std::uint64_t base=133000000000000000ULL, unit=WinAPITimelineDensity::ticksPerSecond;
    WinAPITimelineDensity density;
    // Same second and even same 10ms bucket, but different categories must
    // retain their own actual representative time, not share the bucket edge.
    density.append(base+10000,0); density.append(base+80000,1);
    const auto staggered=density.points();
    CHECK(staggered.size()==2 && staggered[0].time100ns==base+10000 && staggered[1].time100ns==base+80000);
    const std::vector<ks::ui::EventTimelineTrack> staggerTracks={{ks::ui::TimelineCategory::File,{},KswordTheme::TimelineRole::File},
        {ks::ui::TimelineCategory::Registry,{},KswordTheme::TimelineRole::Registry}};
    const auto staggerProjection=ks::ui::AggregateTimelineEvents(staggered,staggerTracks,base,base+100000,1000);
    CHECK(staggerProjection.size()==2 && staggerProjection[0].pixelColumn!=staggerProjection[1].pixelColumn);
    density.clear();
    density.append(base+100*unit,0); density.append(base+5*unit,1); density.append(base+5*unit,1);
    CHECK(density.count()==3 && density.first()==base+5*unit && density.last()==base+100*unit);
    CHECK(density.widthMilliseconds()>=10 && density.bucketCount()==2);
    density.append(base+10000*unit,2);
    CHECK(density.widthMilliseconds()>=4000 && density.bucketCount()<=WinAPITimelineDensity::maxBuckets);
    density.append(base+2*unit,3); // Late event earlier than first surviving time is retained.
    CHECK(density.first()==base+2*unit && density.count()==5);
    const auto initial=density.points(); std::size_t initialSum=0; for(const auto& p:initial) initialSum+=p.weight;
    CHECK(initialSum==5);
    density.clear(); CHECK(!density.count() && density.widthMilliseconds()==10 && density.points().empty());
    const auto start=std::chrono::steady_clock::now();
    for (std::uint64_t i=0;i<1000000;++i) density.append(base + (i%500000)*unit, i%WinAPITimelineDensity::categoryCount);
    const auto appended=std::chrono::steady_clock::now();
    CHECK(density.count()==1000000 && density.bucketCount()<=WinAPITimelineDensity::maxBuckets);
    const auto points=density.points(); std::size_t count=0; for(const auto& p:points) count+=p.weight;
    CHECK(count==1000000 && points.size()<=WinAPITimelineDensity::maxBuckets*WinAPITimelineDensity::categoryCount);
    const std::vector<ks::ui::EventTimelineTrack> tracks={{ks::ui::TimelineCategory::File,{},KswordTheme::TimelineRole::File},
        {ks::ui::TimelineCategory::Registry,{},KswordTheme::TimelineRole::Registry},
        {ks::ui::TimelineCategory::Network,{},KswordTheme::TimelineRole::Network},
        {ks::ui::TimelineCategory::Process,{},KswordTheme::TimelineRole::Process},
        {ks::ui::TimelineCategory::Image,{},KswordTheme::TimelineRole::Image},
        {ks::ui::TimelineCategory::Thread,{},KswordTheme::TimelineRole::Thread},
        {ks::ui::TimelineCategory::ApiMemory,{},KswordTheme::TimelineRole::Storage},
        {ks::ui::TimelineCategory::ApiThread,{},KswordTheme::TimelineRole::Thread},
        {ks::ui::TimelineCategory::ApiService,{},KswordTheme::TimelineRole::Wmi},
        {ks::ui::TimelineCategory::ApiSecurity,{},KswordTheme::TimelineRole::Security},
        {ks::ui::TimelineCategory::ApiCrypto,{},KswordTheme::TimelineRole::PowerShell},
        {ks::ui::TimelineCategory::ApiCom,{},KswordTheme::TimelineRole::Dns},
        {ks::ui::TimelineCategory::ApiWindow,{},KswordTheme::TimelineRole::Image},
        {ks::ui::TimelineCategory::Other,{},KswordTheme::TimelineRole::Kernel}};
    const auto projected=ks::ui::AggregateTimelineEvents(points,tracks,density.first(),density.last(),1200);
    std::size_t aggregateCount=0; for(const auto& b:projected) aggregateCount+=b.count;
    CHECK(aggregateCount==count);
    const auto end=std::chrono::steady_clock::now();
    if (argc > 1) {
        std::ifstream input(argv[1]); CHECK(input.good());
        WinAPITimelineDensity replay;
        std::uint64_t timestamp = 0; unsigned category = 0; std::size_t replayCount = 0;
        while (input >> timestamp >> category) {
            const std::size_t lane = category >= 1 && category <= 5 ? category - 1 : category == 7 ? 5 : category >= 8 && category <= 14 ? category - 2 : 13;
            replay.append(timestamp, lane); ++replayCount;
        }
        CHECK(input.eof() && replayCount && replay.last() > replay.first());
        const auto buckets=ks::ui::AggregateTimelineEvents(replay.points(),tracks,replay.first(),replay.last(),1200);
        std::size_t total=0; std::set<int> columns;
        for(const auto& bucket:buckets) { total+=bucket.count; columns.insert(bucket.pixelColumn); }
        CHECK(total==replayCount && columns.size()>1);
        std::cout << "CAPTURE_REPLAY_EVENTS=" << replayCount << " COLUMNS=" << columns.size()
                  << " SPAN_100NS=" << replay.last()-replay.first() << '\n';
    }
    std::vector<QString> timestampText; timestampText.reserve(4096);
    for (std::uint64_t i=0;i<4096;++i) timestampText.push_back(QString::number(base+i*unit));
    WinAPITimelineDensity textDensity; const auto textStart=std::chrono::steady_clock::now();
    for (std::uint64_t i=0;i<1000000;++i) {
        bool ok=false; const auto timestamp=timestampText[i%timestampText.size()].toULongLong(&ok);
        if (!ok) return 1;
        textDensity.append(timestamp, i%WinAPITimelineDensity::categoryCount);
    }
    const auto textEnd=std::chrono::steady_clock::now();
    CHECK(textDensity.count()==1000000);
    std::cout << "DENSITY_EVENTS=" << count << " BUCKETS=" << density.bucketCount() << " POINTS=" << points.size()
              << " WIDTH_MS=" << density.widthMilliseconds() << " INSERT_MS=" << std::chrono::duration_cast<std::chrono::milliseconds>(appended-start).count()
              << " PROJECT_MS=" << std::chrono::duration_cast<std::chrono::milliseconds>(end-appended).count()
              << " TEXT_PARSE_INSERT_MS=" << std::chrono::duration_cast<std::chrono::milliseconds>(textEnd-textStart).count() << '\n';
}
