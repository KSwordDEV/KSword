#include "RegistryBackend.h"
#include "RegistrySupport.h"
#include <sstream>
namespace ks::r3::registry {
using namespace detail;
namespace {
constexpr DWORD kRegistrySearchMaxNameChars = 32767U;
struct PendingRegistrySearchKey final {
    RegistryPathInfo path;
    std::size_t depth = 0U;
};
bool IsRegistrySearchCancelled(const std::shared_ptr<std::atomic_bool>& cancelToken) {
    return cancelToken && cancelToken->load(std::memory_order_relaxed);
}
bool StopRegistrySearchIfCancelled(
    RegistrySearchSnapshot& snapshot,
    const std::shared_ptr<std::atomic_bool>& cancelToken) {
    if (!IsRegistrySearchCancelled(cancelToken)) {
        return false;
    }
    snapshot.stopReason = RegistrySearchStopReason::Cancelled;
    return true;
}
void RecordRegistrySearchReadFailure(RegistrySearchSnapshot& snapshot, const std::wstring& detail, const std::uint32_t error = 0) {
    ++snapshot.counters.readFailureCount;
    if(snapshot.firstWin32Error==0) snapshot.firstWin32Error=error;
    if (snapshot.errorText.empty()) {
        snapshot.errorText = detail;
    }
}
bool AppendRegistrySearchCandidate(
    RegistrySearchSnapshot& snapshot,
    const RegistrySearchCandidate& candidate) {
    RegistrySearchHit hit = ProjectRegistrySearchHit(candidate, snapshot.request.maxValuePreviewBytes);
    if (hit.dataPreviewTruncated) {
        ++snapshot.counters.truncatedPreviewCount;
    }
    if (!hit.valid || !RegistrySearchHitMatches(hit, snapshot.normalizedQuery)) {
        return true;
    }

    if (hit.kind == RegistrySearchEntryKind::Key) {
        ++snapshot.counters.matchedKeyCount;
    } else {
        ++snapshot.counters.matchedValueCount;
    }
    snapshot.hits.push_back(std::move(hit));
    if (snapshot.hits.size() < snapshot.request.maxResults) {
        return true;
    }

    snapshot.stopReason = RegistrySearchStopReason::ResultLimitReached;
    return false;
}
RegistryPathInfo MakeRegistrySearchChildPath(
    const RegistryPathInfo& parent,
    const std::wstring& childName) {
    RegistryPathInfo child = parent;
    child.subKey = parent.subKey.empty() ? childName : parent.subKey + L"\\" + childName;
    child.displayPath = child.rootText + L"\\" + child.subKey;
    if (!child.kernelPath.empty()) {
        child.kernelPath += L"\\" + childName;
    }
    return child;
}
LONG QueryRegistrySearchValueInfo(HKEY key, DWORD& valueCount, DWORD& maxValueName) {
    valueCount = 0;
    maxValueName = 0;
    return ::RegQueryInfoKeyW(
        key,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &valueCount,
        &maxValueName,
        nullptr,
        nullptr,
        nullptr);
}
}
RegistrySearchSnapshot SearchRegistryWinApi(
    const RegistrySearchRequest& request,
    const std::shared_ptr<std::atomic_bool>& cancelToken) {
    // Inputs:
    // - request: a user-provided path, keyword, and caller-reduced budgets.
    // - cancelToken: a shared worker/UI cancellation signal, or null.
    // Processing:
    // - validates and clamps the request through the pure model;
    // - walks only the WinAPI registry view with an iterative DFS worklist;
    // - accepts no more keys/values than the fixed budgets and reads no value
    //   payload larger than the fixed preview bound.
    // Output:
    // - one immutable complete or partial snapshot; this function never calls
    //   the driver and never changes the existing R0/WinAPI browser mode.
    RegistrySearchSnapshot snapshot;
    const RegistrySearchValidation validation = ValidateRegistrySearchRequest(request);
    snapshot.request = validation.request;
    snapshot.normalizedQuery = validation.normalizedQuery;
    if (!validation.valid) {
        snapshot.stopReason = RegistrySearchStopReason::InvalidRequest;
        snapshot.errorText = validation.errorText;
        snapshot.statusText = BuildRegistrySearchStatusText(snapshot);
        return snapshot;
    }

    const RegistryPathInfo startPath = ParseRegistryPath(snapshot.request.startPath);
    if (!startPath.valid) {
        snapshot.stopReason = RegistrySearchStopReason::InvalidRequest;
        snapshot.errorText = startPath.errorText;
        snapshot.statusText = BuildRegistrySearchStatusText(snapshot);
        return snapshot;
    }
    snapshot.request.startPath = startPath.displayPath;
    if (StopRegistrySearchIfCancelled(snapshot, cancelToken)) {
        snapshot.statusText = BuildRegistrySearchStatusText(snapshot);
        return snapshot;
    }

    std::vector<PendingRegistrySearchKey> pendingKeys;
    pendingKeys.reserve(snapshot.request.maxKeys);
    pendingKeys.push_back({ startPath, 0U });
    bool enumeratedAnyKey = false;
    bool keyWorkLimitReached = false;
    bool subKeyEnumerationLimitReached = false;

    while (!pendingKeys.empty()) {
        if (StopRegistrySearchIfCancelled(snapshot, cancelToken)) {
            break;
        }
        if (snapshot.counters.visitedKeyCount >= snapshot.request.maxKeys) {
            snapshot.stopReason = RegistrySearchStopReason::KeyLimitReached;
            break;
        }

        PendingRegistrySearchKey current = std::move(pendingKeys.back());
        pendingKeys.pop_back();
        ++snapshot.counters.visitedKeyCount;

        // Open values and subkeys independently.  A key can legitimately grant
        // one of these old WinAPI rights without the other; treating the union
        // as mandatory would unnecessarily shrink the search's visible scope.
        LONG valueOpenStatus = ERROR_SUCCESS;
        UniqueRegKey valueKey = OpenKey(current.path, KEY_QUERY_VALUE, &valueOpenStatus);
        LONG subKeyOpenStatus = ERROR_SUCCESS;
        UniqueRegKey subKey = OpenKey(current.path, KEY_ENUMERATE_SUB_KEYS, &subKeyOpenStatus);
        if (!valueKey.valid() && !subKey.valid()) {
            RecordRegistrySearchReadFailure(
                snapshot,
                L"RegOpenKeyExW failed for values/subkeys at " + current.path.displayPath +
                    L": values=" + std::to_wstring(valueOpenStatus) +
                    L", subkeys=" + std::to_wstring(subKeyOpenStatus), static_cast<std::uint32_t>(subKeyOpenStatus));
            continue;
        }
        if (!valueKey.valid()) {
            RecordRegistrySearchReadFailure(
                snapshot,
                L"RegOpenKeyExW(value access) failed for " + current.path.displayPath + L": " + std::to_wstring(valueOpenStatus), static_cast<std::uint32_t>(valueOpenStatus));
        }
        if (!subKey.valid()) {
            RecordRegistrySearchReadFailure(
                snapshot,
                L"RegOpenKeyExW(subkey access) failed for " + current.path.displayPath + L": " + std::to_wstring(subKeyOpenStatus), static_cast<std::uint32_t>(subKeyOpenStatus));
        }

        RegistrySearchCandidate keyCandidate;
        keyCandidate.kind = RegistrySearchEntryKind::Key;
        keyCandidate.keyPath = current.path.displayPath;
        keyCandidate.valueTypeText = L"键";
        keyCandidate.depth = current.depth;
        if (!AppendRegistrySearchCandidate(snapshot, keyCandidate)) {
            break;
        }
        if (StopRegistrySearchIfCancelled(snapshot, cancelToken)) {
            break;
        }

        if (valueKey.valid()) {
            DWORD valueCount = 0;
            DWORD maxValueName = 0;
            const LONG valueInfoStatus = QueryRegistrySearchValueInfo(valueKey.get(), valueCount, maxValueName);
            if (valueInfoStatus != ERROR_SUCCESS) {
                RecordRegistrySearchReadFailure(
                    snapshot,
                    L"RegQueryInfoKeyW(value access) failed for " + current.path.displayPath + L": " + std::to_wstring(valueInfoStatus), static_cast<std::uint32_t>(valueInfoStatus));
            } else if (maxValueName > kRegistrySearchMaxNameChars) {
                RecordRegistrySearchReadFailure(
                    snapshot,
                    L"RegQueryInfoKeyW returned an oversized value-name bound for " + current.path.displayPath + L".");
            } else {
                enumeratedAnyKey = true;
                std::vector<wchar_t> valueName(static_cast<std::size_t>(maxValueName) + 2U);
                for (DWORD index = 0; index < valueCount; ++index) {
                    if (StopRegistrySearchIfCancelled(snapshot, cancelToken)) {
                        break;
                    }
                    if (snapshot.counters.visitedValueCount >= snapshot.request.maxValues) {
                        snapshot.stopReason = RegistrySearchStopReason::ValueLimitReached;
                        break;
                    }
                    ++snapshot.counters.visitedValueCount;

                    DWORD valueNameChars = static_cast<DWORD>(valueName.size());
                    DWORD enumeratedDataBytes = 0;
                    DWORD type = REG_NONE;
                    const LONG enumStatus = ::RegEnumValueW(
                        valueKey.get(),
                        index,
                        valueName.data(),
                        &valueNameChars,
                        nullptr,
                        &type,
                        nullptr,
                        &enumeratedDataBytes);
                    if (enumStatus == ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    if (enumStatus != ERROR_SUCCESS) {
                        RecordRegistrySearchReadFailure(
                            snapshot,
                            L"RegEnumValueW failed for " + current.path.displayPath + L": " + std::to_wstring(enumStatus), static_cast<std::uint32_t>(enumStatus));
                        continue;
                    }

                    RegistrySearchCandidate valueCandidate;
                    valueCandidate.kind = RegistrySearchEntryKind::Value;
                    valueCandidate.keyPath = current.path.displayPath;
                    valueCandidate.valueName.assign(valueName.data(), valueName.data() + valueNameChars);
                    valueCandidate.valueTypeText = RegistryTypeText(type);
                    valueCandidate.dataByteCount = enumeratedDataBytes;
                    valueCandidate.depth = current.depth;

                    DWORD queriedType = type;
                    DWORD fullDataBytes = 0;
                    const wchar_t* valueNamePtr = valueCandidate.valueName.empty()
                        ? nullptr
                        : valueCandidate.valueName.c_str();
                    const LONG sizeStatus = ::RegQueryValueExW(
                        valueKey.get(),
                        valueNamePtr,
                        nullptr,
                        &queriedType,
                        nullptr,
                        &fullDataBytes);
                    if (sizeStatus != ERROR_SUCCESS) {
                        RecordRegistrySearchReadFailure(
                            snapshot,
                            L"RegQueryValueExW(size) failed for " + current.path.displayPath + L": " + std::to_wstring(sizeStatus), static_cast<std::uint32_t>(sizeStatus));
                        valueCandidate.dataPreview = L"<数据预览不可读取>";
                    } else {
                        valueCandidate.valueTypeText = RegistryTypeText(queriedType);
                        valueCandidate.dataByteCount = fullDataBytes;
                        if (fullDataBytes > snapshot.request.maxValuePreviewBytes) {
                            valueCandidate.dataPreview = L"<数据预览超过上限，未读取>";
                        } else if (fullDataBytes != 0U) {
                            std::vector<std::uint8_t> data(static_cast<std::size_t>(fullDataBytes));
                            DWORD readDataBytes = fullDataBytes;
                            const LONG dataStatus = ::RegQueryValueExW(
                                valueKey.get(),
                                valueNamePtr,
                                nullptr,
                                &queriedType,
                                data.data(),
                                &readDataBytes);
                            if (dataStatus != ERROR_SUCCESS) {
                                RecordRegistrySearchReadFailure(
                                    snapshot,
                                    L"RegQueryValueExW(data) failed for " + current.path.displayPath + L": " + std::to_wstring(dataStatus), static_cast<std::uint32_t>(dataStatus));
                                if (dataStatus == ERROR_MORE_DATA && readDataBytes > valueCandidate.dataByteCount) {
                                    valueCandidate.dataByteCount = readDataBytes;
                                }
                                valueCandidate.dataPreview = dataStatus == ERROR_MORE_DATA
                                    ? L"<数据读取期间变化，预览跳过>"
                                    : L"<数据预览不可读取>";
                            } else {
                                data.resize(readDataBytes);
                                valueCandidate.valueTypeText = RegistryTypeText(queriedType);
                                valueCandidate.dataByteCount = readDataBytes;
                                valueCandidate.dataPreview = FormatRegistryData(queriedType, data);
                            }
                        }
                    }

                    if (!AppendRegistrySearchCandidate(snapshot, valueCandidate)) {
                        break;
                    }
                }
            }
        }
        if (snapshot.stopReason == RegistrySearchStopReason::Cancelled ||
            snapshot.stopReason == RegistrySearchStopReason::ValueLimitReached ||
            snapshot.stopReason == RegistrySearchStopReason::ResultLimitReached) {
            break;
        }

        if (!subKey.valid()) {
            continue;
        }
        // RegQueryInfoKeyW requires KEY_QUERY_VALUE, while RegEnumKeyExW only
        // requires KEY_ENUMERATE_SUB_KEYS.  Use a fixed, documented-safe name
        // buffer here so a subkey-only ACL remains searchable without asking
        // for an additional right that the caller does not have.
        std::vector<wchar_t> subKeyName(static_cast<std::size_t>(kRegistrySearchMaxNameChars) + 1U);
        if (current.depth >= snapshot.request.maxDepth) {
            if (StopRegistrySearchIfCancelled(snapshot, cancelToken)) {
                break;
            }
            if (snapshot.counters.inspectedSubKeyCount >= snapshot.request.maxKeys) {
                subKeyEnumerationLimitReached = true;
                break;
            }
            ++snapshot.counters.inspectedSubKeyCount;
            DWORD subKeyNameChars = static_cast<DWORD>(subKeyName.size());
            const LONG depthProbeStatus = ::RegEnumKeyExW(
                subKey.get(),
                0U,
                subKeyName.data(),
                &subKeyNameChars,
                nullptr,
                nullptr,
                nullptr,
                nullptr);
            if (depthProbeStatus == ERROR_SUCCESS) {
                enumeratedAnyKey = true;
                ++snapshot.counters.skippedDepthCount;
            } else if (depthProbeStatus == ERROR_NO_MORE_ITEMS) {
                enumeratedAnyKey = true;
            } else {
                RecordRegistrySearchReadFailure(
                    snapshot,
                    L"RegEnumKeyExW(depth probe) failed for " + current.path.displayPath + L": " + std::to_wstring(depthProbeStatus), static_cast<std::uint32_t>(depthProbeStatus));
            }
            continue;
        }

        for (DWORD index = 0;; ++index) {
            if (StopRegistrySearchIfCancelled(snapshot, cancelToken)) {
                break;
            }
            // The worklist itself is bounded as well as processed keys.  This
            // prevents one key with a huge child count from consuming memory or
            // bypassing the key budget before its children are visited.
            if (snapshot.counters.inspectedSubKeyCount >= snapshot.request.maxKeys) {
                subKeyEnumerationLimitReached = true;
                break;
            }
            if (snapshot.counters.visitedKeyCount + pendingKeys.size() >= snapshot.request.maxKeys) {
                // A full worklist alone does not prove that a child remains.
                // Probe this exact index so an exactly-complete traversal is
                // reported as complete instead of as a false key-limit stop.
                ++snapshot.counters.inspectedSubKeyCount;
                DWORD capacityProbeNameChars = static_cast<DWORD>(subKeyName.size());
                const LONG capacityProbeStatus = ::RegEnumKeyExW(
                    subKey.get(),
                    index,
                    subKeyName.data(),
                    &capacityProbeNameChars,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr);
                if (capacityProbeStatus == ERROR_NO_MORE_ITEMS) {
                    enumeratedAnyKey = true;
                    break;
                }
                if (capacityProbeStatus == ERROR_SUCCESS) {
                    enumeratedAnyKey = true;
                    keyWorkLimitReached = true;
                    break;
                }
                RecordRegistrySearchReadFailure(
                    snapshot,
                    L"RegEnumKeyExW(capacity probe) failed for " + current.path.displayPath + L": " + std::to_wstring(capacityProbeStatus), static_cast<std::uint32_t>(capacityProbeStatus));
                continue;
            }
            ++snapshot.counters.inspectedSubKeyCount;

            DWORD subKeyNameChars = static_cast<DWORD>(subKeyName.size());
            const LONG enumStatus = ::RegEnumKeyExW(
                subKey.get(),
                index,
                subKeyName.data(),
                &subKeyNameChars,
                nullptr,
                nullptr,
                nullptr,
                nullptr);
            if (enumStatus == ERROR_NO_MORE_ITEMS) {
                enumeratedAnyKey = true;
                break;
            }
            if (enumStatus != ERROR_SUCCESS) {
                RecordRegistrySearchReadFailure(
                    snapshot,
                    L"RegEnumKeyExW failed for " + current.path.displayPath + L": " + std::to_wstring(enumStatus), static_cast<std::uint32_t>(enumStatus));
                continue;
            }
            enumeratedAnyKey = true;

            const std::size_t childDepth = current.depth + 1U;
            if (childDepth > snapshot.request.maxDepth) {
                ++snapshot.counters.skippedDepthCount;
                continue;
            }
            pendingKeys.push_back({
                MakeRegistrySearchChildPath(
                    current.path,
                    std::wstring(subKeyName.data(), subKeyName.data() + subKeyNameChars)),
                childDepth
            });
        }
        if (snapshot.stopReason == RegistrySearchStopReason::Cancelled) {
            break;
        }
    }

    if (snapshot.stopReason == RegistrySearchStopReason::NotStarted) {
        if (IsRegistrySearchCancelled(cancelToken)) {
            snapshot.stopReason = RegistrySearchStopReason::Cancelled;
        } else if (keyWorkLimitReached) {
            snapshot.stopReason = RegistrySearchStopReason::KeyLimitReached;
        } else if (subKeyEnumerationLimitReached) {
            snapshot.stopReason = RegistrySearchStopReason::SubKeyEnumerationLimitReached;
        } else if (snapshot.counters.skippedDepthCount != 0U) {
            snapshot.stopReason = RegistrySearchStopReason::DepthLimitReached;
        } else if (!enumeratedAnyKey && snapshot.counters.readFailureCount != 0U) {
            snapshot.stopReason = RegistrySearchStopReason::ReadFailure;
        } else {
            snapshot.stopReason = RegistrySearchStopReason::Completed;
        }
    }
    snapshot.statusText = BuildRegistrySearchStatusText(snapshot);
    return snapshot;
}
}
