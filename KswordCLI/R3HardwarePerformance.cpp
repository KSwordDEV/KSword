#include "CommandRegistry.h"
#include "../shared/usermode/backend/hardware/PerformanceSampler.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <exception>
#include <iomanip>
#include <sstream>
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
Json metric(const b::PerformanceMetricRow& r) {
    const bool integral=r.unit==L"bytes"||r.unit==L"count"||r.unit==L"mebibytes";
    Json value;
    if(r.valid&&std::isfinite(r.numericValue)) {
        if(r.exactInteger) value=Json::count(r.integerValue);
        else if(integral){std::wostringstream s;s.imbue(std::locale::classic());s<<std::fixed<<std::setprecision(0)<<r.numericValue;value=Json::string(s.str());}
        else value=Json::real(r.numericValue);
    }
    return Json::object({{L"id",Json::string(r.id)},{L"group",Json::string(r.groupId)},{L"label",Json::string(r.name)},
        {L"instance",r.instance.empty()?Json{}:Json::string(r.instance)},{L"unit",Json::string(r.unit)},
        {L"value",value},{L"valid",Json::boolean(r.valid)},{L"display",Json::string(r.value)},
        {L"source",r.source.empty()?Json{}:Json::string(r.source)},{L"evidence",evidence(r.evidence)},
        {L"receivedBytesPerSecond",r.receivedKnown?Json::real(r.received):Json{}},{L"sentBytesPerSecond",r.sentKnown?Json::real(r.sent):Json{}}});
}
Result sample(const Args& a) {
    const auto group=a.get(L"--group",L"all");
    if(group!=L"all"&&group!=L"cpu"&&group!=L"memory"&&group!=L"disk"&&group!=L"system"&&group!=L"network"&&group!=L"gpu") throw std::invalid_argument("--group must be all, cpu, memory, disk, system, network or gpu");
    const auto samples=a.u32(L"--samples",1),interval=a.u32(L"--interval-ms",1000),limit=a.u32(L"--limit",1000);
    if(!samples||samples>30||interval<250||interval>10000||static_cast<std::uint64_t>(samples-1)*interval+1000>120000) throw std::invalid_argument("--samples 1..30 and --interval-ms 250..10000 must fit 120 seconds including first 1000ms warmup");
    if(!limit||limit>100000) throw std::invalid_argument("--limit must be 1..100000");
    Cancellation cancellation;std::vector<Json> values;std::exception_ptr failure;b::PerformanceEvidence closure;bool partial=false,malformed=false,cancelled=false;std::size_t valid=0;
    std::thread worker([&]{try{
        b::PerformanceSampler sampler(b::PerformanceScope::System);const auto started=std::chrono::steady_clock::now();
        for(DWORD i=0;i<samples;++i) {
            if(i) {const auto until=std::chrono::steady_clock::now()+std::chrono::milliseconds(interval);
                while(std::chrono::steady_clock::now()<until&&!cancellation.token->load()) std::this_thread::sleep_for(std::chrono::milliseconds(25));}
            if(cancellation.token->load()){cancelled=true;break;}
            const auto snapshot=sampler.sample();std::vector<Json> metrics,sources;std::size_t matched=0;bool incomplete=!snapshot.success||(snapshot.baselineStatusKnown&&snapshot.baselineStatus!=ERROR_SUCCESS);
            for(const auto& r:snapshot.metrics) {
                if(group!=L"all"&&group!=r.groupId) continue;++matched;malformed=malformed||r.evidence.malformed;
                incomplete=incomplete||!r.valid||!r.evidence.complete;if(r.valid)++valid;if(metrics.size()<limit)metrics.push_back(metric(r));
            }
            for(const auto& s:snapshot.sources) {
                if(group!=L"all"&&group!=s.groupId)continue;malformed=malformed||s.evidence.malformed;incomplete=incomplete||!s.evidence.complete;
                sources.push_back(Json::object({{L"id",Json::string(s.id)},{L"source",Json::string(s.path)},{L"domain",Json::string(s.domain)},{L"evidence",evidence(s.evidence)}}));
            }
            partial=partial||incomplete||matched>metrics.size();
            values.push_back(Json::object({{L"sequence",Json::number(i+1)},
                {L"elapsedMilliseconds",Json::count(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count())},
                {L"queryOpened",Json::boolean(snapshot.queryOpened)},{L"queryStatus",snapshot.queryStatusKnown?Json::hex(snapshot.queryStatus):Json{}},
                {L"baselineStatus",snapshot.baselineStatusKnown?Json::hex(snapshot.baselineStatus):Json{}},
                {L"collectStatus",snapshot.collectStatusKnown?Json::hex(snapshot.collectStatus):Json{}},
                {L"resolutionDisplay",Json::string(snapshot.counterResolutionText)},{L"diagnosticDisplay",Json::string(snapshot.diagnosticText)},
                {L"matchedCount",Json::count(matched)},{L"returnedCount",Json::number(static_cast<DWORD>(metrics.size()))},
                {L"truncated",Json::boolean(matched>metrics.size())},{L"sources",Json::array(sources)},{L"metrics",Json::array(metrics)}}));
        }
        cancelled=cancelled||cancellation.token->load();
        closure=sampler.close();partial=partial||!closure.complete;
    }catch(...){failure=std::current_exception();}});
    worker.join();if(failure)std::rethrow_exception(failure);
    const int code=malformed?4:cancelled?6:!valid?5:partial?6:0;
    return {code,Json::object({{L"source",Json::string(L"PDH system counters + Win32 static metrics")},{L"group",Json::string(group)},
        {L"requestedSamples",Json::number(samples)},{L"intervalMilliseconds",Json::number(interval)},{L"warmupMilliseconds",Json::number(1000)},
        {L"returnedSamples",Json::number(static_cast<DWORD>(values.size()))},{L"cancelled",Json::boolean(cancelled)},
        {L"queryClosed",Json::boolean(closure.complete)},{L"closeEvidence",evidence(closure)},{L"samples",Json::array(values)}}),
        code?std::vector<std::wstring>{L"Some selected counters were unavailable, unready, malformed, truncated or cancelled. Invalid values are null; GPU reports maximum active engine, network totals sum visible interfaces. PDH calls are not forcibly interrupted."}:std::vector<std::wstring>{}};
}
}
void registerHardwarePerformance() {
    addCommand({L"hardware performance sample",L"KswordCLI.exe hardware performance sample [--group all|cpu|memory|disk|system|network|gpu] [--samples N] [--interval-ms MS] [--limit N] [--backend r3] [--json]",
        L"Sample R3 system CPU/memory/disk/network/GPU counters for a bounded interval.",
        L"Optional: --group (all), --samples (1..30, default 1), --interval-ms (250..10000, default 1000), --limit (1..100000, default 1000), --backend r3, --json. Total warmup plus waits <=120 seconds.",
        L"Output: one JSON document with timestamped samples, query/baseline/collect PDH statuses, typed metrics (id/group/instance/unit/value/source/valid/evidence), raw array-source failures and cancellation/cleanup with closeEvidence for actual PdhCloseQuery status. Count/byte integer values are decimal strings; rates/percent are numbers. memory-available is raw mebibytes; other byte metrics use bytes. First rate sample warms up 1000 ms; subsequent waits use interval-ms after each collection. English counter paths may use localized/Processor fallback. PDH VALID_DATA and NEW_DATA accepted; unavailable samples are null (5 if none usable, otherwise 6), malformed data 4. GPU max engine is not total GPU usage; network totals may count virtual interfaces and are not physical link utilization. Ctrl+C/Break stops future collections and closes PDH on the owning worker; native calls finish before cancellation. No R0 fallback or Qt dependency.",sample});
}
}
