#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ks::cli {
// JSON values are stored as serialized Unicode text; callers construct values
// through typed factories so remote strings never become executable JSON.
struct Json {
    std::wstring text = L"null";
    std::wstring display = L"unavailable";
    static Json string(const std::wstring& value);
    static Json number(std::uint32_t value);
    static Json boolean(bool value);
    static Json object(const std::vector<std::pair<std::wstring, Json>>& values);
    static Json array(const std::vector<Json>& values);
};
struct Result {
    int code = 0;
    Json data = Json::object({});
    std::vector<std::wstring> diagnostics;
};
class Args {
public:
    std::map<std::wstring, std::wstring> values;
    bool has(const std::wstring& key) const;
    std::wstring get(const std::wstring& key, const std::wstring& fallback = L"") const;
    std::wstring require(const std::wstring& key) const;
    std::uint64_t integer(const std::wstring& key, std::uint64_t fallback = 0) const;
    std::uint32_t u32(const std::wstring& key, std::uint32_t fallback = 0) const;
};
struct Command {
    std::wstring path, syntax, summary, options, notes;
    std::function<Result(const Args&)> run;
};
void addCommand(Command command);
void addFamily(const std::wstring& name, const std::wstring& summary);
const std::vector<Command>& commands();
bool printHelp(const std::wstring& path);
std::wstring commandPath(int argc, wchar_t* argv[], int first);
std::optional<int> dispatchR3(int argc, wchar_t* argv[]);
void registerNetworkConnections();
void registerNetworkPing();
void registerNetworkTraceRoute();
void registerNetworkDns();
}
