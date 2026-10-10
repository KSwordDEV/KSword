#include "CommandRegistry.h"
#include "../shared/usermode/backend/hardware/PerformanceSampler.h"
#include <chrono>
#include <exception>
#include <stdexcept>
#include <thread>
namespace ks::cli {
namespace {
namespace b=ks::r3::hardware_stats;
Json evidence(const b::PerformanceEvidence& e) {
    return Json::object({{L"available",Json::boolean(e.available)},{L"complete",Json::boolean(e.complete)},
        {L"empty",Json::boolean(e.empty)},{L"malformed",Json::boolean(e.malformed)},
        {L"status",e.statusKnown?Json::hex(e.status):Json{}},{L"cStatus",e.cStatusKnown?Json::hex(e.cStatus):Json{}},
        {L"returnedCount",Json::number(e.returnedCount)},{L"skippedCount",Json::number(e.skippedCount)}});
}
Json disk(const b::DiskActivityRow& r,bool& partial,bool& malformed) {
    const std::pair<const wchar_t*,double> fields[]={{L"readBytesPerSecond",r.readBytesPerSecond},{L"writeBytesPerSecond",r.writeBytesPerSecond},
        {L"readsPerSecond",r.readsPerSecond},{L"writesPerSecond",r.writesPerSecond},{L"currentQueueLength",r.currentQueueLength},
        {L"averageQueueLength",r.averageQueueLength},{L"busyPercent",r.busyPercent},{L"readLatencySeconds",r.readLatencySeconds},{L"writeLatencySeconds",r.writeLatencySeconds}};
    std::vector<std::pair<std::wstring,Json>> values={{L"instance",Json::string(r.instance)}};std::vector<std::pair<std::wstring,Json>> states;
    for(const auto& [id,value]:fields) {
        const auto found=r.evidence.find(id);const bool known=found!=r.evidence.end()&&found->second.available;
        values.push_back({id,known?Json::real(value):Json{}});partial=partial||!known;
        if(found!=r.evidence.end()){partial=partial||!found->second.complete;malformed=malformed||found->second.malformed;states.push_back({id,evidence(found->second)});}
    }
    values.push_back({L"evidence",Json::object(states)});return Json::object(values);
}
Result sample(const Args& a) {
    const auto count=a.u32(L"--samples",1),interval=a.u32(L"--interval-ms",1000),limit=a.u32(L"--limit",1000);
    if(!count||count>30||interval<250||interval>10000||static_cast<std::uint64_t>(count-1)*interval+1000>120000) throw std::invalid_argument("--samples 1..30 and --interval-ms 250..10000 must fit 120 seconds including first 1000ms warmup");
    if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");
    const auto instance=a.get(L"--instance");if(a.has(L"--instance")&&instance.empty())throw std::invalid_argument("--instance must not be empty");
    Cancellation cancellation;std::exception_ptr failure;b::PerformanceEvidence closure;std::vector<Json> samples;
    bool partial=false,malformed=false,cancelled=false,useful=false;
    std::thread worker([&]{try{
        b::PerformanceSampler sampler(b::PerformanceScope::PhysicalDisk);const auto started=std::chrono::steady_clock::now();
        for(DWORD i=0;i<count;++i) {
            if(i){const auto until=std::chrono::steady_clock::now()+std::chrono::milliseconds(interval);
                while(std::chrono::steady_clock::now()<until&&!cancellation.token->load())std::this_thread::sleep_for(std::chrono::milliseconds(25));}
            if(cancellation.token->load()){cancelled=true;break;}
            const auto snapshot=sampler.sample();bool complete=snapshot.success;std::vector<Json> sources,rows;std::size_t matched=0;
            for(const auto& source:snapshot.sources){complete=complete&&source.evidence.complete;malformed=malformed||source.evidence.malformed;
                sources.push_back(Json::object({{L"field",Json::string(source.id)},{L"path",Json::string(source.path)},{L"evidence",evidence(source.evidence)}}));}
            useful=useful||complete;partial=partial||!complete||(snapshot.baselineStatusKnown&&snapshot.baselineStatus!=ERROR_SUCCESS);
            for(const auto& d:snapshot.disks){if(!instance.empty()&&_wcsicmp(instance.c_str(),d.instance.c_str()))continue;
                ++matched;for(const auto& [key,e]:d.evidence){static_cast<void>(key);useful=useful||e.available;}
                if(rows.size()<limit)rows.push_back(disk(d,partial,malformed));}
            partial=partial||matched>rows.size();samples.push_back(Json::object({{L"sequence",Json::number(i+1)},
                {L"elapsedMilliseconds",Json::count(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count())},
                {L"queryOpened",Json::boolean(snapshot.queryOpened)},{L"queryStatus",snapshot.queryStatusKnown?Json::hex(snapshot.queryStatus):Json{}},
                {L"baselineStatus",snapshot.baselineStatusKnown?Json::hex(snapshot.baselineStatus):Json{}},
                {L"collectStatus",snapshot.collectStatusKnown?Json::hex(snapshot.collectStatus):Json{}},{L"complete",Json::boolean(complete)},
                {L"enumeratedCount",Json::count(snapshot.disks.size())},{L"matchedCount",Json::count(matched)},
                {L"returnedCount",Json::number(static_cast<DWORD>(rows.size()))},{L"truncated",Json::boolean(matched>rows.size())},
                {L"sources",Json::array(sources)},{L"disks",Json::array(rows)}}));
        }
        cancelled=cancelled||cancellation.token->load();closure=sampler.close();partial=partial||!closure.complete;
    }catch(...){failure=std::current_exception();}});
    worker.join();if(failure)std::rethrow_exception(failure);const int code=malformed?4:cancelled?6:!useful?5:partial?6:0;
    return {code,Json::object({{L"source",Json::string(L"PDH PhysicalDisk wildcard counters")},{L"instanceFilter",instance.empty()?Json{}:Json::string(instance)},
        {L"requestedSamples",Json::number(count)},{L"intervalMilliseconds",Json::number(interval)},{L"warmupMilliseconds",Json::number(1000)},
        {L"returnedSamples",Json::number(static_cast<DWORD>(samples.size()))},{L"cancelled",Json::boolean(cancelled)},
        {L"queryClosed",Json::boolean(closure.complete)},{L"closeEvidence",evidence(closure)},{L"samples",Json::array(samples)}}),
        code?std::vector<std::wstring>{L"Some disk counters, instances or output were unavailable, limited, malformed or cancelled. Missing individual fields are null; busyPercent can exceed 100. Native PDH calls finish before cancellation."}:std::vector<std::wstring>{}};
}
}
void registerHardwareDisk() {
    addCommand({L"hardware disk sample",L"KswordCLI.exe hardware disk sample [--instance NAME] [--samples N] [--interval-ms MS] [--limit N] [--backend r3] [--json]",
        L"Sample R3 per-instance physical disk throughput, queues and latency.",
        L"Optional: --instance exact PDH name (case-insensitive), --samples (1..30, default 1), --interval-ms (250..10000, default 1000), --limit (1..100000, default 1000), --backend r3, --json. Warmup plus waits <=120 seconds.",
        L"Output: bounded timestamped samples, individual sources with actual PDH status/array completeness, disks with readBytesPerSecond/writeBytesPerSecond/readsPerSecond/writesPerSecond/currentQueueLength/averageQueueLength/busyPercent/readLatencySeconds/writeLatencySeconds and per-field evidence. Missing fields are null, never zero. Latency unit seconds; busyPercent is uncapped and can exceed 100 with concurrent disk work. _Total is the provider rollup and comes first, not another physical disk. Instance names are PDH labels, not stable device identities or filesystem volume paths. Valid empty complete results/filter misses succeed; no usable evidence 5, partial/cancelled/truncated 6, malformed 4. First sample warms up 1000ms; later waits start after collection; provider calls are not forcibly interrupted. Ctrl+C/Break stops future work; owning worker closes PDH with closeEvidence. Only PhysicalDisk counters are opened; no R0 fallback.",sample});
}
}
