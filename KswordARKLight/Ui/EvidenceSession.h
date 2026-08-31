#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace Ksword::Ui {

enum class EvidenceRedaction {
    None,
    Privacy
};

struct EvidenceItem final {
    std::uint64_t sequence = 0;
    std::uint64_t timestamp100ns = 0;
    std::wstring source;
    std::wstring format;
    std::wstring text;
};

struct EvidenceDiff final {
    std::vector<std::wstring> added;
    std::vector<std::wstring> removed;
    std::vector<std::wstring> unchanged;
};

std::wstring RedactEvidenceText(const std::wstring& text, EvidenceRedaction redaction);
EvidenceDiff BuildEvidenceDiff(const std::wstring& before, const std::wstring& after);
std::wstring RenderEvidenceDiff(const EvidenceDiff& diff);

// EvidenceSession owns immutable exported evidence in capture order. The
// interface records text, returns snapshots, builds the latest diff and exports
// JSON/TSV with optional privacy redaction; locking and serialization stay
// inside the module.
class EvidenceSession final {
public:
    std::uint64_t record(std::wstring source, std::wstring format, std::wstring text);
    std::vector<EvidenceItem> snapshot() const;
    bool erase(std::uint64_t sequence);
    void clear();
    std::size_t size() const;
    EvidenceDiff latestDiff() const;
    std::wstring exportJson(EvidenceRedaction redaction) const;
    std::wstring exportTsv(EvidenceRedaction redaction) const;

private:
    mutable std::mutex mutex_;
    std::vector<EvidenceItem> items_;
    std::uint64_t nextSequence_ = 1;
};

EvidenceSession& GlobalEvidenceSession();

} // namespace Ksword::Ui
