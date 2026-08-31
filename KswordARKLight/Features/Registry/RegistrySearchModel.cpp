#include "RegistrySearchModel.h"

#include <algorithm>
#include <cwctype>
#include <utility>

namespace Ksword::Features::Registry {
namespace {

std::wstring TrimCopy(std::wstring text) {
    const auto first = std::find_if(text.begin(), text.end(), [](const wchar_t character) {
        return std::iswspace(static_cast<wint_t>(character)) == 0;
    });
    if (first == text.end()) {
        return {};
    }
    const auto last = std::find_if(text.rbegin(), text.rend(), [](const wchar_t character) {
        return std::iswspace(static_cast<wint_t>(character)) == 0;
    }).base();
    return std::wstring(first, last);
}

std::size_t ClampBudget(const std::size_t requested, const std::size_t hardCap) {
    // A zero budget is normalized to the documented fixed bound.  This keeps
    // an omitted/default-initialized field from accidentally making a search
    // terminate before examining its first key or value.
    if (requested == 0U) {
        return hardCap;
    }
    return (std::min)(requested, hardCap);
}

std::wstring FlattenDisplayText(std::wstring value) {
    for (wchar_t& character : value) {
        if (character == L'\t' || character == L'\r' || character == L'\n') {
            character = L' ';
        }
    }
    return value;
}

bool IsHighSurrogate(const wchar_t character) {
    return character >= 0xD800 && character <= 0xDBFF;
}

bool IsLowSurrogate(const wchar_t character) {
    return character >= 0xDC00 && character <= 0xDFFF;
}

std::wstring BoundedPreview(std::wstring value, const std::size_t maxPreviewBytes, bool& truncated) {
    value = FlattenDisplayText(std::move(value));
    const std::size_t maxChars = maxPreviewBytes / sizeof(wchar_t);
    if (value.size() <= maxChars) {
        return value;
    }

    truncated = true;
    if (maxChars == 0U) {
        return {};
    }

    // Keep the omission marker within the configured byte budget and avoid
    // leaving a UTF-16 high surrogate at the end of the copied prefix.
    const std::size_t markerChars = maxChars >= 3U ? 3U : 0U;
    std::size_t copyChars = maxChars - markerChars;
    if (copyChars > 0U && copyChars < value.size() &&
        IsHighSurrogate(value[copyChars - 1U]) && IsLowSurrogate(value[copyChars])) {
        --copyChars;
    }

    std::wstring preview = value.substr(0U, copyChars);
    if (markerChars != 0U) {
        preview += L"...";
    }
    return preview;
}

std::wstring FoldCase(const std::wstring& value) {
    std::wstring folded;
    folded.reserve(value.size());
    for (const wchar_t character : value) {
        folded.push_back(static_cast<wchar_t>(std::towlower(static_cast<wint_t>(character))));
    }
    return folded;
}

bool ContainsIgnoreCase(const std::wstring& text, const std::wstring& query) {
    if (query.empty()) {
        return false;
    }
    return FoldCase(text).find(FoldCase(query)) != std::wstring::npos;
}

const wchar_t* EntryKindText(const RegistrySearchEntryKind kind) {
    return kind == RegistrySearchEntryKind::Key ? L"键" : L"值";
}

void AppendTsvCell(std::wstring& output, const std::wstring& value, const bool firstCell) {
    if (!firstCell) {
        output.push_back(L'\t');
    }
    output += SanitizeRegistrySearchTsvCell(value);
}

void AppendTsvHit(std::wstring& output, const RegistrySearchHit& hit) {
    AppendTsvCell(output, EntryKindText(hit.kind), true);
    AppendTsvCell(output, hit.keyPath, false);
    AppendTsvCell(output, hit.valueName, false);
    AppendTsvCell(output, hit.valueTypeText, false);
    AppendTsvCell(output, hit.dataPreview, false);
    AppendTsvCell(output, std::to_wstring(hit.dataByteCount), false);
    AppendTsvCell(output, std::to_wstring(hit.depth), false);
    AppendTsvCell(output, hit.dataPreviewTruncated ? L"已截断" : L"完整", false);
    output += L"\r\n";
}

std::wstring CountText(const RegistrySearchSnapshot& snapshot) {
    std::wstring text = L"已扫描 " + std::to_wstring(snapshot.counters.visitedKeyCount) +
        L" 个键、" + std::to_wstring(snapshot.counters.visitedValueCount) +
        L" 个值；进行了 " + std::to_wstring(snapshot.counters.inspectedSubKeyCount) +
        L" 次子键枚举；命中 " + std::to_wstring(snapshot.hits.size()) + L" 项";
    if (snapshot.counters.readFailureCount != 0U) {
        text += L"；跳过 " + std::to_wstring(snapshot.counters.readFailureCount) + L" 个不可读项";
    }
    if (snapshot.counters.truncatedPreviewCount != 0U) {
        text += L"；截断 " + std::to_wstring(snapshot.counters.truncatedPreviewCount) + L" 个预览";
    }
    return text;
}

} // namespace

RegistrySearchValidation ValidateRegistrySearchRequest(const RegistrySearchRequest& request) {
    RegistrySearchValidation validation;
    validation.request = request;
    validation.request.startPath = TrimCopy(request.startPath);
    validation.normalizedQuery = TrimCopy(request.query);
    validation.request.query = validation.normalizedQuery;
    validation.request.maxKeys = ClampBudget(request.maxKeys, kRegistrySearchMaxKeys);
    validation.request.maxValues = ClampBudget(request.maxValues, kRegistrySearchMaxValues);
    validation.request.maxResults = ClampBudget(request.maxResults, kRegistrySearchMaxResults);
    validation.request.maxDepth = ClampBudget(request.maxDepth, kRegistrySearchMaxDepth);
    validation.request.maxValuePreviewBytes = ClampBudget(request.maxValuePreviewBytes, kRegistrySearchMaxValuePreviewBytes);

    if (validation.request.startPath.empty()) {
        validation.errorText = L"注册表搜索起始路径为空。";
        return validation;
    }
    if (validation.normalizedQuery.empty()) {
        validation.errorText = L"注册表搜索关键字为空。";
        return validation;
    }

    validation.valid = true;
    return validation;
}

RegistrySearchHit ProjectRegistrySearchHit(
    const RegistrySearchCandidate& candidate,
    const std::size_t maxPreviewBytes) {
    RegistrySearchHit hit;
    hit.kind = candidate.kind;
    hit.keyPath = TrimCopy(FlattenDisplayText(candidate.keyPath));
    hit.valueName = FlattenDisplayText(candidate.valueName);
    hit.valueTypeText = FlattenDisplayText(candidate.valueTypeText);
    hit.dataByteCount = candidate.dataByteCount;
    hit.depth = candidate.depth;
    hit.dataPreviewTruncated = candidate.dataByteCount > maxPreviewBytes;
    hit.dataPreview = BoundedPreview(candidate.dataPreview, maxPreviewBytes, hit.dataPreviewTruncated);
    hit.valid = !hit.keyPath.empty();
    return hit;
}

bool RegistrySearchHitMatches(const RegistrySearchHit& hit, const std::wstring& normalizedQuery) {
    const std::wstring query = TrimCopy(normalizedQuery);
    if (!hit.valid || query.empty()) {
        return false;
    }
    return ContainsIgnoreCase(hit.keyPath, query) ||
        ContainsIgnoreCase(hit.valueName, query) ||
        ContainsIgnoreCase(hit.valueTypeText, query) ||
        ContainsIgnoreCase(hit.dataPreview, query);
}

std::wstring BuildRegistrySearchStatusText(const RegistrySearchSnapshot& snapshot) {
    const std::wstring counts = CountText(snapshot);
    switch (snapshot.stopReason) {
    case RegistrySearchStopReason::NotStarted:
        return L"注册表搜索尚未开始。";
    case RegistrySearchStopReason::Completed:
        return L"注册表搜索完成：" + counts + L"。";
    case RegistrySearchStopReason::InvalidRequest:
        return snapshot.errorText.empty()
            ? L"注册表搜索请求无效。"
            : L"注册表搜索请求无效：" + snapshot.errorText;
    case RegistrySearchStopReason::KeyLimitReached:
        return L"注册表搜索已达到 " + std::to_wstring(snapshot.request.maxKeys) +
            L" 个键的上限：" + counts + L"。";
    case RegistrySearchStopReason::SubKeyEnumerationLimitReached:
        return L"注册表搜索已达到 " + std::to_wstring(snapshot.request.maxKeys) +
            L" 次子键枚举工作上限：" + counts + L"。";
    case RegistrySearchStopReason::ValueLimitReached:
        return L"注册表搜索已达到 " + std::to_wstring(snapshot.request.maxValues) +
            L" 个值的上限：" + counts + L"。";
    case RegistrySearchStopReason::ResultLimitReached:
        return L"注册表搜索已达到 " + std::to_wstring(snapshot.request.maxResults) +
            L" 项结果上限：" + counts + L"。";
    case RegistrySearchStopReason::DepthLimitReached:
        return L"注册表搜索已达到深度 " + std::to_wstring(snapshot.request.maxDepth) +
            L" 的上限，跳过 " + std::to_wstring(snapshot.counters.skippedDepthCount) +
            L" 个分支：" + counts + L"。";
    case RegistrySearchStopReason::Cancelled:
        return L"注册表搜索已取消：" + counts + L"。";
    case RegistrySearchStopReason::ReadFailure:
        return snapshot.errorText.empty()
            ? L"注册表搜索因读取失败停止：" + counts + L"。"
            : L"注册表搜索因读取失败停止：" + snapshot.errorText + L"；" + counts + L"。";
    default:
        return L"注册表搜索状态未知：" + counts + L"。";
    }
}

std::wstring SanitizeRegistrySearchTsvCell(const std::wstring& text) {
    return FlattenDisplayText(text);
}

std::wstring BuildRegistrySearchTsv(const std::vector<RegistrySearchHit>& hits) {
    std::wstring output;
    bool wroteHeader = false;
    for (const RegistrySearchHit& hit : hits) {
        if (!hit.valid) {
            continue;
        }
        if (!wroteHeader) {
            output = L"类型\t键路径\t值名称\t值类型\t数据预览\t数据字节\t深度\t预览状态\r\n";
            wroteHeader = true;
        }
        AppendTsvHit(output, hit);
    }
    return output;
}

std::wstring BuildVisibleRegistrySearchTsv(
    const std::vector<RegistrySearchHit>& hits,
    const std::vector<std::size_t>& visibleIndexes) {
    std::wstring output;
    bool wroteHeader = false;
    for (const std::size_t index : visibleIndexes) {
        if (index >= hits.size() || !hits[index].valid) {
            continue;
        }
        if (!wroteHeader) {
            output = L"类型\t键路径\t值名称\t值类型\t数据预览\t数据字节\t深度\t预览状态\r\n";
            wroteHeader = true;
        }
        AppendTsvHit(output, hits[index]);
    }
    return output;
}

} // namespace Ksword::Features::Registry
