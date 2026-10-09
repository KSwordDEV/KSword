#include "../../../shared/usermode/backend/driver/DriverFormatting.h"
#include "DriverModel.h"

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <sstream>

namespace Ksword::Features::Driver {
namespace {
using namespace ks::r3::driver;

// ToLowerWstring converts text to lowercase for case-insensitive filters. Input
// is arbitrary Unicode text; processing applies towlower to each character;
// output is a best-effort lowercase copy for comparisons.
std::wstring ToLowerWstring(const std::wstring& text) {
    std::wstring lowered;
    lowered.reserve(text.size());
    for (wchar_t ch : text) {
        lowered.push_back(static_cast<wchar_t>(std::towlower(ch)));
    }
    return lowered;
}

// JoinUniqueText collects unique strings into a sorted vector. Input is a
// sequence of candidate labels; processing trims, deduplicates and sorts;
// output is a stable filter list without empty entries.
std::vector<std::wstring> JoinUniqueText(std::vector<std::wstring> values) {
    values.erase(std::remove_if(values.begin(), values.end(), [](const std::wstring& value) {
        return value.empty();
    }), values.end());

    std::sort(values.begin(), values.end(), [](const std::wstring& left, const std::wstring& right) {
        return ToLowerWstring(left) < ToLowerWstring(right);
    });
    values.erase(std::unique(values.begin(), values.end(), [](const std::wstring& left, const std::wstring& right) {
        return ToLowerWstring(left) == ToLowerWstring(right);
    }), values.end());
    return values;
}

} // namespace

void DriverModel::setOverviewRows(std::vector<DriverOverviewRow> rows) {
    overviewRows_ = std::move(rows);
}

void DriverModel::setObjectRows(std::vector<DriverObjectRow> rows) {
    objectRows_ = std::move(rows);
}

const std::vector<DriverOverviewRow>& DriverModel::overviewRows() const {
    return overviewRows_;
}

const std::vector<DriverObjectRow>& DriverModel::objectRows() const {
    return objectRows_;
}

std::vector<DriverOverviewRow> DriverModel::filterOverviewRows(const std::wstring& keywordText) const {
    const std::wstring keyword = trimCopy(keywordText);
    if (keyword.empty()) {
        return overviewRows_;
    }

    std::vector<DriverOverviewRow> filtered;
    for (const DriverOverviewRow& row : overviewRows_) {
        if (containsIgnoreCase(row.driverName, keyword)
            || containsIgnoreCase(row.baseAddressText, keyword)
            || containsIgnoreCase(row.memoryRangeText, keyword)
            || containsIgnoreCase(row.sizeText, keyword)
            || containsIgnoreCase(row.pathText, keyword)
            || containsIgnoreCase(row.signatureText, keyword)
            || containsIgnoreCase(row.statusText, keyword)
            || containsIgnoreCase(row.anomalyText, keyword)
            || containsIgnoreCase(row.capabilityHint, keyword)) {
            filtered.push_back(row);
        }
    }
    return filtered;
}

std::vector<DriverObjectRow> DriverModel::filterObjectRows(
    const std::wstring& directoryFilterText,
    const std::wstring& typeFilterText,
    const std::wstring& keywordText) const {
    const std::wstring directoryFilter = trimCopy(directoryFilterText);
    const std::wstring typeFilter = trimCopy(typeFilterText);
    const std::wstring keyword = trimCopy(keywordText);

    std::vector<DriverObjectRow> filtered;
    for (const DriverObjectRow& row : objectRows_) {
        if (!directoryFilter.empty() && !containsIgnoreCase(row.directoryPathText, directoryFilter)) {
            continue;
        }
        if (!typeFilter.empty() && !containsIgnoreCase(row.objectTypeText, typeFilter)) {
            continue;
        }
        if (!keyword.empty()
            && !containsIgnoreCase(row.directoryPathText, keyword)
            && !containsIgnoreCase(row.objectNameText, keyword)
            && !containsIgnoreCase(row.objectTypeText, keyword)
            && !containsIgnoreCase(row.referenceCountText, keyword)
            && !containsIgnoreCase(row.handleCountText, keyword)
            && !containsIgnoreCase(row.fullPathText, keyword)
            && !containsIgnoreCase(row.targetPathText, keyword)
            && !containsIgnoreCase(row.statusText, keyword)
            && !containsIgnoreCase(row.capabilityHint, keyword)) {
            continue;
        }
        filtered.push_back(row);
    }
    return filtered;
}

std::wstring DriverModel::overviewSummaryText(const std::wstring& keywordText) const {
    const std::vector<DriverOverviewRow> filtered = filterOverviewRows(keywordText);
    std::wstring text = L"状态：驱动概览 ";
    text += std::to_wstring(filtered.size());
    text += L" 项";
    if (!trimCopy(keywordText).empty()) {
        text += L"，关键字筛选中";
    }
    return text;
}

std::wstring DriverModel::objectSummaryText(
    const std::wstring& directoryFilterText,
    const std::wstring& typeFilterText,
    const std::wstring& keywordText) const {
    const std::vector<DriverObjectRow> filtered = filterObjectRows(directoryFilterText, typeFilterText, keywordText);
    std::wstring text = L"状态：对象信息 ";
    text += std::to_wstring(filtered.size());
    text += L" 项";
    if (!trimCopy(directoryFilterText).empty() || !trimCopy(typeFilterText).empty() || !trimCopy(keywordText).empty()) {
        text += L"，已启用筛选";
    }
    return text;
}

std::vector<std::wstring> DriverModel::overviewDriverNames() const {
    std::vector<std::wstring> values;
    values.reserve(overviewRows_.size());
    for (const DriverOverviewRow& row : overviewRows_) {
        values.push_back(trimCopy(row.driverName));
    }
    return JoinUniqueText(std::move(values));
}

std::vector<std::wstring> DriverModel::objectDirectories() const {
    std::vector<std::wstring> values;
    values.reserve(objectRows_.size());
    for (const DriverObjectRow& row : objectRows_) {
        values.push_back(trimCopy(row.directoryPathText));
    }
    return JoinUniqueText(std::move(values));
}

std::vector<std::wstring> DriverModel::objectTypes() const {
    std::vector<std::wstring> values;
    values.reserve(objectRows_.size());
    for (const DriverObjectRow& row : objectRows_) {
        values.push_back(trimCopy(row.objectTypeText));
    }
    return JoinUniqueText(std::move(values));
}

std::wstring DriverModel::sanitizeTsvCell(const std::wstring& text) {
    std::wstring sanitized = text;
    for (wchar_t& ch : sanitized) {
        if (ch == L'\t' || ch == L'\r' || ch == L'\n') {
            ch = L' ';
        }
    }
    return sanitized;
}

bool DriverModel::containsIgnoreCase(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) {
        return true;
    }
    return ToLowerWstring(haystack).find(ToLowerWstring(needle)) != std::wstring::npos;
}

std::wstring DriverModel::trimCopy(const std::wstring& text) {
    const auto first = std::find_if_not(text.begin(), text.end(), [](wchar_t ch) {
        return std::iswspace(ch) != 0;
    });
    const auto last = std::find_if_not(text.rbegin(), text.rend(), [](wchar_t ch) {
        return std::iswspace(ch) != 0;
    }).base();
    if (first >= last) {
        return {};
    }
    return std::wstring(first, last);
}

std::wstring DriverModel::toLowerCopy(const std::wstring& text) {
    return ToLowerWstring(text);
}





} // namespace Ksword::Features::Driver
