#include "CommandRegistry.h"
#include "../shared/usermode/backend/network/Diagnostics.h"
#include <stdexcept>
namespace ks::cli {
void registerNetworkDns() {
    addCommand({L"network dns query", L"KswordCLI.exe network dns query --name NAME [--type A|AAAA|NS|CNAME|SOA|PTR|MX|TXT|SRV|ANY] [--backend r3] [--json]",
        L"Query DNS records through the Windows DNS resolver.", L"Required: --name. Optional: --type (default A), --backend r3, --json.",
        L"Data: name, type, win32Error, records (name, type, ttl, dataLength, decoded, fields, value). Resolver errors retain their DNS status; unknown record formats are marked decoded=false.",
        [](const Args& args) {
            const std::map<std::wstring, std::uint16_t> types{{L"A",1},{L"NS",2},{L"CNAME",5},{L"SOA",6},{L"PTR",12},{L"MX",15},{L"TXT",16},{L"AAAA",28},{L"SRV",33},{L"ANY",255}};
            const auto type = args.get(L"--type", L"A"); const auto found = types.find(type);
            if (found == types.end()) throw std::invalid_argument("invalid DNS --type");
            ks::r3::network::DiagnosticRequest request; request.kind = ks::r3::network::DiagnosticKind::DnsLookup;
            request.target = args.require(L"--name"); request.dnsRecordType = found->second;
            if (request.target.empty()) throw std::invalid_argument("empty DNS --name");
            const auto response = ks::r3::network::RunDnsLookup(request); std::vector<Json> records;
            for (const auto& record : response.records) {
                std::vector<std::pair<std::wstring, Json>> fields;
                for (const auto& [name, value] : record.textFields) fields.push_back({name, Json::string(value)});
                for (const auto& [name, value] : record.numericFields) fields.push_back({name, Json::number(value)});
                if (record.type == 16) { std::vector<Json> texts; for (const auto& value : record.textSegments) texts.push_back(Json::string(value)); fields.push_back({L"segments", Json::array(texts)}); }
                records.push_back(Json::object({{L"name", Json::string(record.name)}, {L"type", Json::number(record.type)}, {L"ttl", Json::number(record.ttl)},
                    {L"dataLength", Json::number(record.dataLength)}, {L"decoded", Json::boolean(record.decoded)}, {L"fields", Json::object(fields)}, {L"value", Json::string(record.value)}}));
            }
            return Result{response.win32Error == 0 ? 0 : 3, Json::object({{L"name", Json::string(request.target)}, {L"type", Json::string(type)},
                {L"win32Error", Json::number(response.win32Error)}, {L"records", Json::array(records)}}), response.win32Error ? std::vector<std::wstring>{response.text} : std::vector<std::wstring>{}};
        }});
}
}
