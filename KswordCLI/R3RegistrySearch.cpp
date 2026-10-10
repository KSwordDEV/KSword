#include "CommandRegistry.h"
#include "../shared/usermode/backend/registry/RegistryBackend.h"
#include <stdexcept>
namespace ks::cli {
namespace {
using namespace ks::r3::registry;
const wchar_t* reason(RegistrySearchStopReason value) {
    switch(value) {
    case RegistrySearchStopReason::Completed:return L"completed";
    case RegistrySearchStopReason::InvalidRequest:return L"invalid-request";
    case RegistrySearchStopReason::KeyLimitReached:return L"key-limit";
    case RegistrySearchStopReason::SubKeyEnumerationLimitReached:return L"subkey-enumeration-limit";
    case RegistrySearchStopReason::ValueLimitReached:return L"value-limit";
    case RegistrySearchStopReason::ResultLimitReached:return L"result-limit";
    case RegistrySearchStopReason::DepthLimitReached:return L"depth-limit";
    case RegistrySearchStopReason::Cancelled:return L"cancelled";
    case RegistrySearchStopReason::ReadFailure:return L"read-failure";
    default:return L"not-started";
    }
}
Result search(const Args& args) {
    RegistrySearchRequest request;
    request.startPath=args.require(L"--path"); request.query=args.require(L"--query");
    request.maxKeys=args.u32(L"--max-keys",2000);request.maxValues=args.u32(L"--max-values",2000);
    request.maxResults=args.u32(L"--max-results",2000);request.maxDepth=args.u32(L"--max-depth",32);
    request.maxValuePreviewBytes=args.u32(L"--max-preview-bytes",16384);
    if(!ValidateRegistrySearchRequest(request).valid || !ParseRegistryPath(request.startPath).valid) throw std::invalid_argument("invalid registry search path or query");
    Cancellation cancel;const auto snapshot=SearchRegistryWinApi(request,cancel.token);std::vector<Json> hits;
    for(const auto& hit:snapshot.hits) hits.push_back(Json::object({{L"kind",Json::string(hit.kind==RegistrySearchEntryKind::Key ? L"key" : L"value")},
        {L"path",Json::string(hit.keyPath)}, {L"name",Json::string(hit.valueName)}, {L"typeName",Json::string(hit.valueTypeText)},
        {L"dataPreview",Json::string(hit.dataPreview)}, {L"dataBytes",Json::count(hit.dataByteCount)}, {L"depth",Json::count(hit.depth)}, {L"previewTruncated",Json::boolean(hit.dataPreviewTruncated)}}));
    const auto& counters=snapshot.counters;
    const bool complete=snapshot.stopReason==RegistrySearchStopReason::Completed && counters.readFailureCount==0;
    const int code=complete ? 0 : snapshot.stopReason==RegistrySearchStopReason::InvalidRequest ? 1 : snapshot.stopReason==RegistrySearchStopReason::ReadFailure || snapshot.stopReason==RegistrySearchStopReason::NotStarted ? 3 : 6;
    return {code,Json::object({{L"path",Json::string(snapshot.request.startPath)}, {L"query",Json::string(snapshot.normalizedQuery)}, {L"complete",Json::boolean(complete)},
        {L"stopReason",Json::string(reason(snapshot.stopReason))}, {L"firstWin32Error",Json::number(snapshot.firstWin32Error)},
        {L"effectiveBudgets",Json::object({{L"keys",Json::count(snapshot.request.maxKeys)}, {L"values",Json::count(snapshot.request.maxValues)},
            {L"results",Json::count(snapshot.request.maxResults)}, {L"depth",Json::count(snapshot.request.maxDepth)}, {L"previewBytes",Json::count(snapshot.request.maxValuePreviewBytes)}})},
        {L"counters",Json::object({{L"visitedKeys",Json::count(counters.visitedKeyCount)}, {L"visitedValues",Json::count(counters.visitedValueCount)},
            {L"inspectedSubKeys",Json::count(counters.inspectedSubKeyCount)}, {L"matchedKeys",Json::count(counters.matchedKeyCount)}, {L"matchedValues",Json::count(counters.matchedValueCount)},
            {L"skippedDepth",Json::count(counters.skippedDepthCount)}, {L"readFailures",Json::count(counters.readFailureCount)}, {L"truncatedPreviews",Json::count(counters.truncatedPreviewCount)}})}, {L"hits",Json::array(hits)}}),
        snapshot.errorText.empty() ? std::vector<std::wstring>{} : std::vector<std::wstring>{snapshot.errorText}};
}
}
void registerRegistrySearch() {
    addCommand({L"registry search query",L"KswordCLI.exe registry search query --path PATH --query TEXT [--max-keys N] [--max-values N] [--max-results N] [--max-depth N] [--max-preview-bytes N] [--backend r3] [--json]",
        L"Search key paths, value names/types and bounded data previews.",L"Required: --path, --query. Optional: budgets (keys/values/results default 2000, depth 32, preview bytes 16384), --backend r3, --json.",
        L"Case-insensitive substring search in the native registry view. Zero budgets use backend defaults; larger budgets clamp to backend caps. Ctrl+C cancels and returns partial evidence. Data: effectiveBudgets, counters, stopReason, complete, firstWin32Error, hits.",search});
}
}
