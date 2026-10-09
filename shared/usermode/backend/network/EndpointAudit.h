#pragma once
#include <string>
#include <vector>
namespace ks::r3::network {
struct EndpointAuditRow {
    std::vector<std::wstring> cells;
};
std::vector<EndpointAuditRow> BuildAfdRows();
std::vector<EndpointAuditRow> BuildNsiRows();
}
