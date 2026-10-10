#include "CommandRegistry.h"
#include "../shared/usermode/backend/network/EndpointAudit.h"
namespace ks::cli {
namespace {
Result query(const Args& args, bool afd) {
    const auto limit = args.u32(L"--limit",100);
    const auto snapshot = afd ? ks::r3::network::BuildAfdRows() : ks::r3::network::BuildNsiRows();
    std::vector<Json> rows; bool failed = false, available = false, bounded = false;
    for (const auto& row : snapshot) {
        if (row.evidence) { failed |= !row.available; available |= row.available; bounded |= row.truncated; }
        if (rows.size() >= limit) continue;
        std::vector<Json> cells; for (const auto& cell : row.cells) cells.push_back(Json::string(cell));
        std::vector<std::pair<std::wstring,Json>> fields;
        for (const auto& [name,value] : row.numericFields) fields.push_back({name,Json::number(value)});
        for (const auto& [name,value] : row.textFields) fields.push_back({name,Json::string(value)});
        rows.push_back(Json::object({{L"available",Json::boolean(row.available)}, {L"evidence",Json::boolean(row.evidence)},
            {L"win32Error",Json::number(row.win32Error)}, {L"truncated",Json::boolean(row.truncated)}, {L"fields",Json::object(fields)}, {L"cells",Json::array(cells)}}));
    }
    return {available ? (failed || bounded ? 6 : 0) : 5,
        Json::object({{L"source",Json::string(L"R3 documented IP Helper projection; private AFD/NSI objects are not queried")},
            {L"backendTruncated",Json::boolean(bounded)}, {L"collectedCount",Json::number(static_cast<std::uint32_t>(snapshot.size()))},
            {L"returnedCount",Json::number(static_cast<std::uint32_t>(rows.size()))}, {L"displayTruncated",Json::boolean(rows.size() < snapshot.size())}, {L"rows",Json::array(rows)}}), {}};
}
}
void registerNetworkEndpointAudit() {
    addCommand({L"network endpoint-audit afd query", L"KswordCLI.exe network endpoint-audit afd query [--limit N] [--backend r3] [--json]",
        L"Read documented IPv4 owner-table evidence facing AFD.", L"Optional: --limit (default 100), --backend r3, --json.",
        L"No driver. Backend retains up to 128 TCP and 128 UDP rows. Data: source, backendTruncated, collectedCount, returnedCount, displayTruncated, rows with raw fields and explanatory cells.", [](const Args& args){return query(args,true);}});
    addCommand({L"network endpoint-audit nsi query", L"KswordCLI.exe network endpoint-audit nsi query [--limit N] [--backend r3] [--json]",
        L"Read public interface, IPv4 address and route summaries facing NSI.", L"Optional: --limit (default 100), --backend r3, --json.",
        L"No private NSI layout. Backend retains up to 64 interfaces and address/route counts. Partial evidence or backend truncation returns 6; wholly unavailable evidence returns 5.", [](const Args& args){return query(args,false);}});
}
}
