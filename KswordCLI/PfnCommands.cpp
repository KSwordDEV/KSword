#include "CommandRegistry.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverPfn.h"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace ks::cli {
namespace {
using namespace ksword::ark;
constexpr auto kUnsupported = static_cast<long>(0xc00000bbUL);
constexpr auto kInvalid = static_cast<long>(0xc000003eUL);

PfnBackend selected(const Args& args) {
    return args.get(L"--backend", L"r3") == L"r0" ? PfnBackend::DriverOnly : PfnBackend::NativeOnly;
}
int failure(long status) { return status == kUnsupported ? 5 : status == kInvalid ? 4 : 3; }
Json traceJson(const PfnQueryTrace& trace) {
    std::vector<Json> attempts;
    for (unsigned i=0; i<trace.nativeAttemptCount && i<trace.nativeAttempts.size(); ++i) {
        const auto& a=trace.nativeAttempts[i];
        attempts.push_back(Json::object({{L"invoked",Json::boolean(a.invoked)}, {L"informationClass",Json::number(a.informationClass)},
            {L"abiVersion",Json::number(a.abiVersion)}, {L"ntStatus",Json::hex(static_cast<std::uint32_t>(a.status))}}));
    }
    return Json::object({{L"nativeAttempts",Json::array(attempts)}, {L"driverAvailable",Json::boolean(trace.driverAvailable)},
        {L"driverInvoked",Json::boolean(trace.driverInvoked)},
        {L"driverOperation",trace.driverInvoked && trace.driverOperation ? Json::number(trace.driverOperation) : Json{}},
        {L"driverStatus",trace.driverInvoked ? Json::hex(static_cast<std::uint32_t>(trace.driverStatus)) : Json{}},
        {L"driverTransportStatus",trace.driverInvoked ? Json::hex(static_cast<std::uint32_t>(trace.driverTransportStatus)) : Json{}}});
}
std::size_t limit(const Args& args, std::size_t cap) {
    const auto value=args.u32(L"--limit",128);
    if (!value || value>cap) throw std::invalid_argument("--limit exceeds the protocol bound or is zero");
    return value;
}
std::vector<std::uint64_t> numbers(const Args& args, const wchar_t* key, std::size_t cap) {
    const auto text=args.require(key); std::vector<std::uint64_t> values;
    for (std::size_t pos=0; pos<=text.size();) {
        const auto end=text.find(L',',pos); const auto part=text.substr(pos,end==std::wstring::npos ? end : end-pos);
        if (part.empty()) throw std::invalid_argument("comma-separated list contains an empty item");
        Args number; number.values[L"--number"]=part; values.push_back(number.integer(L"--number"));
        if (values.size()>cap) throw std::invalid_argument("list exceeds the protocol bound");
        if (end==std::wstring::npos) break;
        pos=end+1;
    }
    return values;
}
std::wstring imageName(const char (&name)[16]) {
    std::wstring result; for (char c : name) { if (!c) break; const auto byte=static_cast<unsigned char>(c); result.push_back(byte < 32 ? L'?' : static_cast<wchar_t>(byte)); } return result;
}
Result ranges(const Args& args) {
    const auto shown=limit(args,KSWORD_ARK_PFN_MAX_RANGES); PfnQueryClient client(selected(args));
    std::vector<KSWORD_ARK_PFN_RANGE> values; const long status=client.ranges(values);
    std::vector<Json> rows; for (std::size_t i=0; i<(std::min)(shown,values.size()); ++i)
        rows.push_back(Json::object({{L"firstPfn",Json::hex(values[i].firstPfn)}, {L"pageCount",Json::count(values[i].pageCount)}}));
    const bool capReached=values.size()>=KSWORD_ARK_PFN_MAX_RANGES;
    return {status<0 ? failure(status) : capReached ? 6 : 0,
        Json::object({{L"source",Json::string(L"Memory Manager Superfetch physical ranges")}, {L"ntStatus",Json::hex(static_cast<std::uint32_t>(status))},
            {L"pageBytes",Json::number(4096)}, {L"returnedCount",Json::number(static_cast<std::uint32_t>(values.size()))},
            {L"displayTruncated",Json::boolean(rows.size()<values.size())}, {L"complete",status<0 ? Json{} : capReached ? Json{} : Json::boolean(true)},
            {L"trace",traceJson(client.lastTrace())}, {L"ranges",Json::array(rows)}}),
        {L"An exactly full protocol buffer has unknown completeness. R3 and R0 query the same Superfetch provider, not independent sources."}};
}
Result owners(const Args& args) {
    const auto shown=limit(args,KSWORD_ARK_PFN_MAX_OWNERS); PfnQueryClient client(selected(args));
    std::vector<KSWORD_ARK_PFN_OWNER> values; const long status=client.owners(values);
    std::vector<Json> rows; for (std::size_t i=0; i<(std::min)(shown,values.size()); ++i)
        rows.push_back(Json::object({{L"processKey",Json::hex(values[i].processKey)}, {L"pid",Json::number(values[i].processId)},
            {L"sessionId",Json::number(values[i].sessionId)}, {L"imageName",Json::string(imageName(values[i].imageName))}}));
    return {status<0 ? failure(status) : 6,
        Json::object({{L"source",Json::string(L"Memory Manager Superfetch private-source snapshot")}, {L"ntStatus",Json::hex(static_cast<std::uint32_t>(status))},
            {L"returnedCount",Json::number(static_cast<std::uint32_t>(values.size()))}, {L"displayTruncated",Json::boolean(rows.size()<values.size())},
            {L"complete",Json{}}, {L"trace",traceJson(client.lastTrace())}, {L"owners",Json::array(rows)}}),
        {L"Only process-type owners are retained; the underlying source does not report whether its bounded list was complete. Process keys are snapshot evidence, not retained process identities."}};
}
Result pages(const Args& args, bool single, bool list) {
    std::vector<std::uint64_t> requested;
    if (single) { (void)args.require(L"--pfn"); requested.push_back(args.integer(L"--pfn")); }
    else if (list) requested=numbers(args,L"--pfns",KSWORD_ARK_PFN_MAX_PAGES);
    else {
        (void)args.require(L"--first"); (void)args.require(L"--count");
        const auto first=args.integer(L"--first"); const auto count=args.u32(L"--count");
        if (!count || count>KSWORD_ARK_PFN_MAX_PAGES || first>(1ULL<<40)-count) throw std::invalid_argument("invalid PFN range");
        for (std::uint32_t i=0;i<count;++i) requested.push_back(first+i);
    }
    if (std::any_of(requested.begin(),requested.end(),[](auto p){return p>=(1ULL<<40);})) throw std::invalid_argument("PFN exceeds 40-bit bound");
    const auto shown=limit(args,KSWORD_ARK_PFN_MAX_PAGES); PfnQueryClient client(selected(args));
    std::vector<KSWORD_ARK_PFN_IDENTITY> values;
    const long status=single||list ? client.identities(requested,values) : client.pages(requested.front(),static_cast<std::uint32_t>(requested.size()),values);
    std::vector<Json> rows; bool missing=false;
    for (std::size_t i=0; i<values.size(); ++i) {
        const bool known=values[i].frame!=std::numeric_limits<std::uint64_t>::max(); missing=missing||!known;
        if (i<shown) rows.push_back(Json::object({{L"pfn",Json::hex(values[i].pfn)}, {L"available",Json::boolean(known)},
            {L"frame",known ? Json::hex(values[i].frame) : Json{}}, {L"backing",known ? Json::hex(values[i].backing) : Json{}}}));
    }
    const bool complete=status>=0 && values.size()==requested.size() && !missing;
    return {status<0 ? failure(status) : complete ? 0 : 6,
        Json::object({{L"source",Json::string(L"Memory Manager Superfetch PFN identity")}, {L"ntStatus",Json::hex(static_cast<std::uint32_t>(status))},
            {L"requestedCount",Json::number(static_cast<std::uint32_t>(requested.size()))}, {L"returnedCount",Json::number(static_cast<std::uint32_t>(values.size()))},
            {L"complete",Json::boolean(complete)}, {L"displayTruncated",Json::boolean(rows.size()<values.size())}, {L"trace",traceJson(client.lastTrace())},
            {L"pages",Json::array(rows)}}),
        {L"Frame and backing are raw version-dependent PFN identity evidence, not a verified owner. The data is a point-in-time observation."}};
}
Result mappings(const Args& args) {
    const auto pid=args.u32(L"--pid"); const auto created=args.integer(L"--creation-time");
    if (!pid || !created) throw std::invalid_argument("--pid and --creation-time must be positive");
    auto addresses=numbers(args,L"--addresses",KSWORD_ARK_PFN_MAX_MAPPINGS);
    const auto shown=limit(args,KSWORD_ARK_PFN_MAX_MAPPINGS); PfnQueryClient client(PfnBackend::DriverOnly);
    std::vector<KSWORD_ARK_PFN_MAPPING> values; const long status=client.mappings(pid,created,addresses,values);
    std::vector<Json> rows; bool missing=false;
    for (std::size_t i=0; i<values.size(); ++i) {
        const bool known=values[i].status>=0; missing=missing||!known;
        if (i<shown) rows.push_back(Json::object({{L"address",Json::hex(addresses[i])},
            {L"ntStatus",Json::hex(static_cast<std::uint32_t>(values[i].status))}, {L"available",Json::boolean(known)},
            {L"pfn",known ? Json::hex(values[i].pfn) : Json{}}, {L"pageBytes",known ? Json::number(values[i].pageSize) : Json{}}}));
    }
    const bool complete=status>=0 && values.size()==addresses.size() && !missing;
    return {status<0 ? failure(status) : complete ? 0 : 6,
        Json::object({{L"source",Json::string(L"R0 resident user-page translation")}, {L"pid",Json::number(pid)}, {L"creationTime",Json::count(created)},
            {L"ntStatus",Json::hex(static_cast<std::uint32_t>(status))}, {L"requestedCount",Json::number(static_cast<std::uint32_t>(addresses.size()))},
            {L"returnedCount",Json::number(static_cast<std::uint32_t>(values.size()))}, {L"complete",Json::boolean(complete)},
            {L"displayTruncated",Json::boolean(rows.size()<values.size())}, {L"trace",traceJson(client.lastTrace())}, {L"mappings",Json::array(rows)}}),
        {L"Only resident user mappings are translated; each result may change after the query. PID creation time is verified by the driver."}};
}
void addPfn(Command command, bool r0Only=false) {
    command.supportsR0=true; command.supportsR3=!r0Only; command.defaultBackend=r0Only ? L"r0" : L"r3"; addCommand(std::move(command));
}
}
void registerPfnCommands() {
    const std::wstring common=L" Explicit backends do not fall back. R3 and R0 use the same underlying Superfetch provider. x64 and 4 KiB native pages are required.";
    addPfn({L"memory pfn ranges",L"KswordCLI.exe memory pfn ranges [--limit N] [--backend r0|r3] [--json]",L"Query bounded physical page ranges.",L"Optional: --limit (1..512), --backend r0|r3, --json.",common,ranges});
    addPfn({L"memory pfn owners",L"KswordCLI.exe memory pfn owners [--limit N] [--backend r0|r3] [--json]",L"Query process owner evidence for PFN records.",L"Optional: --limit (1..16384), --backend r0|r3, --json.",L"Only process-type entries are returned; total source completeness is unknown."+common,owners});
    addPfn({L"memory pfn pages",L"KswordCLI.exe memory pfn pages --first PFN --count N [--limit N] [--backend r0|r3] [--json]",L"Read a bounded contiguous set of PFN identities.",L"Required: --first, --count (1..4096). Optional: --limit, --backend r0|r3, --json.",common,[](const Args& a){return pages(a,false,false);}});
    addPfn({L"memory pfn identity",L"KswordCLI.exe memory pfn identity --pfn PFN [--backend r0|r3] [--json]",L"Query one physical page identity.",L"Required: --pfn. Optional: --backend r0|r3, --json.",common,[](const Args& a){return pages(a,true,false);}});
    addPfn({L"memory pfn identities",L"KswordCLI.exe memory pfn identities --pfns LIST [--limit N] [--backend r0|r3] [--json]",L"Query explicit physical page identities.",L"Required: --pfns comma-separated list (at most 4096). Optional: --limit, --backend r0|r3, --json.",common,[](const Args& a){return pages(a,false,true);}});
    addPfn({L"memory pfn mappings",L"KswordCLI.exe memory pfn mappings --pid PID --creation-time FILETIME --addresses LIST [--limit N] [--backend r0] [--json]",L"Translate resident user virtual addresses to PFNs through the driver.",L"Required: --pid, --creation-time, --addresses comma-separated list (at most 256). Optional: --limit, --backend r0, --json.",L"The driver verifies process creation time and never faults pages in. Per-address NTSTATUS is retained.",mappings},true);
}
}
