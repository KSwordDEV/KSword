#include "PathNavigator.h"

#include <algorithm>

namespace Ksword::Features::File {
namespace {

// TrimWhitespace removes leading and trailing ASCII/Unicode whitespace from a
// path-like string. Input is any string; output keeps interior characters.
std::wstring TrimWhitespace(const std::wstring& value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](wchar_t ch) {
        return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
    });
    if (first == value.end()) {
        return {};
    }
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](wchar_t ch) {
        return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
    }).base();
    return std::wstring(first, last);
}

// TrimWrappingQuotes removes one matching pair of command-line style quotes.
// Input is a trimmed string; output is unquoted only when both ends match.
std::wstring TrimWrappingQuotes(const std::wstring& value) {
    if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"') {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

// ExpandEnvironmentPath expands %VAR% fragments using ExpandEnvironmentStringsW.
// Input is a user supplied path; output falls back to the input if expansion
// fails or if the result is unexpectedly empty.
std::wstring ExpandEnvironmentPath(const std::wstring& value) {
    const DWORD needed = ::ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
    if (needed == 0) {
        return value;
    }
    std::wstring expanded(needed, L'\0');
    const DWORD written = ::ExpandEnvironmentStringsW(value.c_str(), expanded.data(), needed);
    if (written == 0 || written > needed) {
        return value;
    }
    if (!expanded.empty() && expanded.back() == L'\0') {
        expanded.pop_back();
    }
    return expanded.empty() ? value : expanded;
}

// EndsWithSeparator reports whether a path already ends with a Windows path
// separator. Input is a path string; output is a simple boolean.
bool EndsWithSeparator(const std::wstring& path) {
    return !path.empty() && (path.back() == L'\\' || path.back() == L'/');
}

// IsAsciiDriveLetter reports whether ch can introduce a DOS drive root. Input
// is one character; output is true only for ASCII A-Z or a-z.
bool IsAsciiDriveLetter(const wchar_t ch) {
    return (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z');
}

// IsValidKnownPathComponent accepts one literal component from a cached
// absolute path. It deliberately rejects wildcard, device and traversal syntax
// instead of attempting expansion or filesystem-based canonicalization.
bool IsValidKnownPathComponent(const std::wstring& component) {
    if (component.empty() || component == L"." || component == L"..") {
        return false;
    }
    for (const wchar_t ch : component) {
        if (ch < L' ' || ch == L'"' || ch == L'*' || ch == L'?' || ch == L'<' ||
            ch == L'>' || ch == L'|' || ch == L':') {
            return false;
        }
    }
    return true;
}

// ValidateKnownPathComponents checks every component after a root. Inputs are a
// normalized path and the root length; output is false for empty, duplicate or
// traversal components. No filesystem access occurs.
bool ValidateKnownPathComponents(const std::wstring& path, std::size_t rootLength) {
    if (rootLength > path.size()) {
        return false;
    }
    if (rootLength < path.size() && path[rootLength] == L'\\') {
        ++rootLength;
    }
    while (rootLength < path.size()) {
        const std::size_t separator = path.find(L'\\', rootLength);
        const std::size_t end = separator == std::wstring::npos ? path.size() : separator;
        if (!IsValidKnownPathComponent(path.substr(rootLength, end - rootLength))) {
            return false;
        }
        if (separator == std::wstring::npos) {
            break;
        }
        rootLength = separator + 1U;
    }
    return true;
}

// NormalizeKnownAbsolutePath only accepts literal DOS and UNC names that came
// from an existing snapshot. It neither expands variables nor asks Windows to
// resolve a path, preserving the provenance boundary for cross-page routes.
std::wstring NormalizeKnownAbsolutePath(const std::wstring& value, std::size_t& rootLength) {
    std::wstring path = TrimWrappingQuotes(TrimWhitespace(value));
    std::replace(path.begin(), path.end(), L'/', L'\\');
    rootLength = 0;
    if (path.empty()) {
        return {};
    }

    if (path.rfind(L"\\\\?\\", 0) == 0 || path.rfind(L"\\\\.\\", 0) == 0 ||
        path.rfind(L"\\??\\", 0) == 0 || path.rfind(L"\\Device\\", 0) == 0) {
        return {};
    }

    if (path.size() >= 3U && IsAsciiDriveLetter(path[0]) && path[1] == L':' && path[2] == L'\\') {
        rootLength = 3U;
        while (path.size() > rootLength && path.back() == L'\\') {
            path.pop_back();
        }
        return ValidateKnownPathComponents(path, rootLength) ? path : std::wstring{};
    }

    if (path.rfind(L"\\\\", 0) != 0) {
        return {};
    }
    const std::size_t serverEnd = path.find(L'\\', 2U);
    if (serverEnd == std::wstring::npos || !IsValidKnownPathComponent(path.substr(2U, serverEnd - 2U))) {
        return {};
    }
    const std::size_t shareStart = serverEnd + 1U;
    const std::size_t shareEnd = path.find(L'\\', shareStart);
    const std::size_t shareLength = (shareEnd == std::wstring::npos ? path.size() : shareEnd) - shareStart;
    if (!IsValidKnownPathComponent(path.substr(shareStart, shareLength))) {
        return {};
    }
    rootLength = shareEnd == std::wstring::npos ? path.size() : shareEnd;
    while (path.size() > rootLength && path.back() == L'\\') {
        path.pop_back();
    }
    return ValidateKnownPathComponents(path, rootLength) ? path : std::wstring{};
}

} // namespace

PathNavigator::PathNavigator() = default;

const std::wstring& PathNavigator::currentPath() const {
    return currentPath_;
}

std::wstring PathNavigator::navigateTo(const std::wstring& path) {
    const std::wstring normalized = normalizeDirectoryPath(path);
    if (normalized != currentPath_) {
        pushHistory(currentPath_);
        currentPath_ = normalized;
        forwardStack_.clear();
    }
    return currentPath_;
}

std::wstring PathNavigator::navigateUp() {
    return navigateTo(parentPath(currentPath_));
}

bool PathNavigator::navigateBack() {
    if (backStack_.empty()) {
        return false;
    }
    forwardStack_.push_back(currentPath_);
    currentPath_ = backStack_.back();
    backStack_.pop_back();
    return true;
}

bool PathNavigator::navigateForward() {
    if (forwardStack_.empty()) {
        return false;
    }
    backStack_.push_back(currentPath_);
    currentPath_ = forwardStack_.back();
    forwardStack_.pop_back();
    return true;
}

bool PathNavigator::canNavigateBack() const {
    return !backStack_.empty();
}

bool PathNavigator::canNavigateForward() const {
    return !forwardStack_.empty();
}

std::wstring PathNavigator::normalizeDirectoryPath(const std::wstring& path) {
    std::wstring normalized = ExpandEnvironmentPath(TrimWrappingQuotes(TrimWhitespace(path)));
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
    if (normalized == L"此电脑" || normalized == L"计算机") {
        return {};
    }
    if (normalized == L"." || normalized == L".\\") {
        wchar_t buffer[MAX_PATH]{};
        const DWORD len = ::GetCurrentDirectoryW(MAX_PATH, buffer);
        if (len > 0 && len < MAX_PATH) {
            normalized.assign(buffer, len);
        }
    }
    while (normalized.size() > 3 && normalized.back() == L'\\') {
        normalized.pop_back();
    }
    if (normalized.size() == 2 && normalized[1] == L':') {
        normalized.push_back(L'\\');
    }
    return normalized;
}

std::wstring PathNavigator::normalizeKnownDirectoryPath(const std::wstring& path) {
    std::size_t rootLength = 0;
    return NormalizeKnownAbsolutePath(path, rootLength);
}

std::wstring PathNavigator::parentDirectoryForKnownFilePath(const std::wstring& path) {
    std::size_t rootLength = 0;
    const std::wstring normalized = NormalizeKnownAbsolutePath(path, rootLength);
    if (normalized.empty() || normalized.size() <= rootLength) {
        return {};
    }
    const std::size_t separator = normalized.find_last_of(L'\\');
    if (separator == std::wstring::npos) {
        return {};
    }
    if (rootLength == 3U && separator == rootLength - 1U) {
        return normalized.substr(0, rootLength);
    }
    if (separator <= rootLength) {
        return normalized.substr(0, rootLength);
    }
    return normalized.substr(0, separator);
}

std::wstring PathNavigator::parentPath(const std::wstring& path) {
    const std::wstring normalized = normalizeDirectoryPath(path);
    if (normalized.empty() || isDriveRoot(normalized)) {
        return {};
    }
    if (normalized.size() <= 2) {
        return {};
    }

    std::wstring trimmed = normalized;
    while (trimmed.size() > 3 && trimmed.back() == L'\\') {
        trimmed.pop_back();
    }
    const std::wstring::size_type slash = trimmed.find_last_of(L'\\');
    if (slash == std::wstring::npos) {
        return {};
    }
    if (slash == 2 && trimmed.size() >= 3 && trimmed[1] == L':') {
        return trimmed.substr(0, 3);
    }
    if (slash == 0) {
        return L"\\";
    }
    return trimmed.substr(0, slash);
}

std::wstring PathNavigator::joinChildPath(const std::wstring& directory, const std::wstring& childName) {
    if (directory.empty()) {
        return childName;
    }
    if (EndsWithSeparator(directory)) {
        return directory + childName;
    }
    return directory + L"\\" + childName;
}

std::wstring PathNavigator::makeSearchPattern(const std::wstring& directory) {
    if (directory.empty()) {
        return L"*";
    }
    return joinChildPath(directory, L"*");
}

bool PathNavigator::isDriveRoot(const std::wstring& path) {
    return path.size() == 3 &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' &&
        path[2] == L'\\';
}

void PathNavigator::pushHistory(const std::wstring& path) {
    if (!backStack_.empty() && backStack_.back() == path) {
        return;
    }
    backStack_.push_back(path);
}

} // namespace Ksword::Features::File
