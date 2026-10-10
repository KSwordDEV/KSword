#pragma once
#include <cstdint>
#include <atomic>
#include <memory>
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
    static Json real(double value);
    static Json signedNumber(std::int32_t value);
    static Json boolean(bool value);
    static Json object(const std::vector<std::pair<std::wstring, Json>>& values);
    static Json array(const std::vector<Json>& values);
    static Json strings(const std::vector<std::wstring>& values);
    static Json count(std::uint64_t value);
    static Json hex(std::uint64_t value);
    static Json bytes(const std::vector<std::uint8_t>& value, std::size_t limit);
};
struct Result {
    int code = 0;
    Json data = Json::object({});
    std::vector<std::wstring> diagnostics;
};
class Args {
public:
    std::map<std::wstring, std::wstring> values;
    std::vector<std::wstring> tail;
    bool has(const std::wstring& key) const;
    std::wstring get(const std::wstring& key, const std::wstring& fallback = L"") const;
    std::wstring require(const std::wstring& key) const;
    std::uint64_t integer(const std::wstring& key, std::uint64_t fallback = 0) const;
    std::uint32_t u32(const std::wstring& key, std::uint32_t fallback = 0) const;
};
class Cancellation {
public:
    Cancellation();
    ~Cancellation();
    std::shared_ptr<std::atomic_bool> token;
private:
    bool registered = false;
};
struct Payload {
    std::vector<std::uint8_t> bytes;
    std::uint32_t win32Error = 0;
};
Payload readPayloadFile(const std::wstring& path);
std::vector<std::uint8_t> parseHexPayload(const std::wstring& text);
struct Command {
    std::wstring path, syntax, summary, options, notes;
    std::function<Result(const Args&)> run;
    bool legacyDefault = false;
    std::wstring legacySyntax, legacyOptions;
    bool acceptsTail = false;
};
void addCommand(Command command);
void addFamily(const std::wstring& name, const std::wstring& summary);
const std::vector<Command>& commands();
bool printHelp(const std::wstring& path);
std::wstring commandPath(int argc, wchar_t* argv[], int first);
std::optional<int> dispatchR3(int& argc, wchar_t* argv[]);
void registerNetworkConnections();
void registerNetworkPing();
void registerNetworkTraceRoute();
void registerNetworkDns();
void registerNetworkFirewall();
void registerNetworkEndpointAudit();
void registerService();
void registerRegistryBrowse();
void registerRegistrySearch();
void registerRegistryMutations();
void registerStartupEnumeration();
void registerStartupActions();
void registerPrivilege(std::function<int(std::vector<std::wstring>)> dispatch);
void registerFileDirectory();
void registerFileOperations();
void registerFileOwnership();
void registerFileAnalysis();
void registerFilePe();
void registerProcessEnumeration();
void registerProcessFields();
void registerProcessTelemetry();
void registerProcessControls();
void registerProcessBasic();
void registerProcessThreads();
void registerProcessModules();
void registerProcessToken();
void registerTokenSwitches();
void registerProcessPeb();
void registerProcessHotkeys();
void registerDriverModules();
void registerHardwareDevices();
void registerHardwarePerformance();
void registerHardwareDisk();
void registerHardwareUsb();
void registerHardwareBus();
void registerWindow();
void registerClipboardRead();
void registerWindowCapture();
void registerWindowHierarchy();
void registerWindowHotkeys();
void registerMonitorEtw();
void registerSystemFileHolders();
void registerSystemEventLog();
void registerSystemContextMenu();
void registerSystemTime();
void registerSystemIoctl();
void registerKernelNamespace();
void registerKernelDirectory();
void registerKernelSymlink();
void registerKernelObjects();
}
