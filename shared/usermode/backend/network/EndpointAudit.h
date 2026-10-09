#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
namespace ks::r3::network {
struct EndpointAuditRow {
    std::vector<std::wstring> cells;
    bool available = true, evidence = true, truncated = false;
    std::uint32_t win32Error = 0;
    std::vector<std::pair<std::wstring, std::uint32_t>> numericFields;
    std::vector<std::pair<std::wstring, std::wstring>> textFields;
};
std::vector<EndpointAuditRow> BuildAfdRows();
std::vector<EndpointAuditRow> BuildNsiRows();
}
