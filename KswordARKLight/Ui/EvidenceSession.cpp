#include "EvidenceSession.h"

#include "../Core/Win32Lean.h"

#include <algorithm>
#include <cwctype>
#include <sstream>
#include <unordered_set>

namespace Ksword::Ui {
namespace {

std::vector<std::wstring> Lines(const std::wstring& text) {
    std::vector<std::wstring> lines;
    std::wstring current;
    for (const wchar_t ch : text) {
        if (ch == L'\r') {
            continue;
        }
        if (ch == L'\n') {
            lines.push_back(std::move(current));
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    if (!current.empty() || (!text.empty() && text.back() != L'\n')) {
        lines.push_back(std::move(current));
    }
    return lines;
}

std::wstring JsonEscape(const std::wstring& text) {
    std::wstring output;
    output.reserve(text.size() + 16U);
    for (const wchar_t ch : text) {
        switch (ch) {
        case L'\\': output += L"\\\\"; break;
        case L'\"': output += L"\\\""; break;
        case L'\r': output += L"\\r"; break;
        case L'\n': output += L"\\n"; break;
        case L'\t': output += L"\\t"; break;
        default: output.push_back(ch); break;
        }
    }
    return output;
}

std::wstring TsvCell(std::wstring text) {
    for (wchar_t& ch : text) {
        if (ch == L'\t' || ch == L'\r' || ch == L'\n') {
            ch = L' ';
        }
    }
    return text;
}

std::uint64_t CurrentFileTime100ns() noexcept {
    FILETIME value{};
    ::GetSystemTimeAsFileTime(&value);
    ULARGE_INTEGER integer{};
    integer.LowPart = value.dwLowDateTime;
    integer.HighPart = value.dwHighDateTime;
    return integer.QuadPart;
}

bool StartsWithNoCase(const std::wstring& text, const std::size_t offset, const wchar_t* prefix) {
    const std::size_t length = std::wcslen(prefix);
    if (offset + length > text.size()) {
        return false;
    }
    for (std::size_t index = 0; index < length; ++index) {
        if (std::towlower(text[offset + index]) != std::towlower(prefix[index])) {
            return false;
        }
    }
    return true;
}

} // namespace

std::wstring RedactEvidenceText(const std::wstring& text, const EvidenceRedaction redaction) {
    if (redaction == EvidenceRedaction::None || text.empty()) {
        return text;
    }
    std::wstring output;
    output.reserve(text.size());
    for (std::size_t index = 0; index < text.size();) {
        if (StartsWithNoCase(text, index, L"C:\\Users\\")) {
            output += L"C:\\Users\\<redacted>";
            index += 9U;
            while (index < text.size() && text[index] != L'\\' && text[index] != L'/' &&
                text[index] != L'\r' && text[index] != L'\n' && text[index] != L'\t') {
                ++index;
            }
            continue;
        }
        output.push_back(text[index++]);
    }
    return output;
}

EvidenceDiff BuildEvidenceDiff(const std::wstring& before, const std::wstring& after) {
    const std::vector<std::wstring> beforeLines = Lines(before);
    const std::vector<std::wstring> afterLines = Lines(after);
    const std::unordered_set<std::wstring> beforeSet(beforeLines.begin(), beforeLines.end());
    const std::unordered_set<std::wstring> afterSet(afterLines.begin(), afterLines.end());
    EvidenceDiff diff;
    for (const std::wstring& line : beforeLines) {
        if (afterSet.contains(line)) {
            diff.unchanged.push_back(line);
        } else {
            diff.removed.push_back(line);
        }
    }
    for (const std::wstring& line : afterLines) {
        if (!beforeSet.contains(line)) {
            diff.added.push_back(line);
        }
    }
    return diff;
}

std::wstring RenderEvidenceDiff(const EvidenceDiff& diff) {
    std::wostringstream output;
    output << L"Evidence diff: +" << diff.added.size() << L" -" << diff.removed.size()
           << L" =" << diff.unchanged.size() << L"\r\n";
    for (const std::wstring& line : diff.removed) {
        output << L"- " << line << L"\r\n";
    }
    for (const std::wstring& line : diff.added) {
        output << L"+ " << line << L"\r\n";
    }
    return output.str();
}

std::uint64_t EvidenceSession::record(std::wstring source, std::wstring format, std::wstring text) {
    if (text.empty()) {
        return 0;
    }
    std::scoped_lock lock(mutex_);
    const std::uint64_t sequence = nextSequence_++;
    items_.push_back({ sequence, CurrentFileTime100ns(), std::move(source), std::move(format), std::move(text) });
    return sequence;
}

std::vector<EvidenceItem> EvidenceSession::snapshot() const {
    std::scoped_lock lock(mutex_);
    return items_;
}

bool EvidenceSession::erase(const std::uint64_t sequence) {
    std::scoped_lock lock(mutex_);
    const auto item = std::find_if(items_.begin(), items_.end(), [sequence](const EvidenceItem& candidate) {
        return candidate.sequence == sequence;
    });
    if (item == items_.end()) {
        return false;
    }
    items_.erase(item);
    return true;
}

void EvidenceSession::clear() {
    std::scoped_lock lock(mutex_);
    items_.clear();
}

std::size_t EvidenceSession::size() const {
    std::scoped_lock lock(mutex_);
    return items_.size();
}

EvidenceDiff EvidenceSession::latestDiff() const {
    std::scoped_lock lock(mutex_);
    if (items_.size() < 2U) {
        return {};
    }
    return BuildEvidenceDiff(items_[items_.size() - 2U].text, items_.back().text);
}

std::wstring EvidenceSession::exportJson(const EvidenceRedaction redaction) const {
    const std::vector<EvidenceItem> items = snapshot();
    std::wostringstream output;
    output << L"{\r\n  \"schema\": \"ksword-arklight-evidence-v1\",\r\n  \"items\": [";
    for (std::size_t index = 0; index < items.size(); ++index) {
        const EvidenceItem& item = items[index];
        output << (index == 0 ? L"\r\n" : L",\r\n")
               << L"    {\"sequence\": " << item.sequence
               << L", \"timestamp100ns\": " << item.timestamp100ns
               << L", \"source\": \"" << JsonEscape(item.source)
               << L"\", \"format\": \"" << JsonEscape(item.format)
               << L"\", \"text\": \"" << JsonEscape(RedactEvidenceText(item.text, redaction)) << L"\"}";
    }
    output << (items.empty() ? L"]\r\n}" : L"\r\n  ]\r\n}");
    return output.str();
}

std::wstring EvidenceSession::exportTsv(const EvidenceRedaction redaction) const {
    const std::vector<EvidenceItem> items = snapshot();
    std::wostringstream output;
    output << L"Sequence\tTimestamp100ns\tSource\tFormat\tText\r\n";
    for (const EvidenceItem& item : items) {
        output << item.sequence << L'\t' << item.timestamp100ns << L'\t'
               << TsvCell(item.source) << L'\t' << TsvCell(item.format) << L'\t'
               << TsvCell(RedactEvidenceText(item.text, redaction)) << L"\r\n";
    }
    return output.str();
}

EvidenceSession& GlobalEvidenceSession() {
    static EvidenceSession session;
    return session;
}

} // namespace Ksword::Ui
