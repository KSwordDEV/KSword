#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Features::Registry {

// These are hard upper bounds for one local, R3 registry search.  Callers may
// request a lower budget, but validation never permits a larger one.  Keeping
// the budgets in this Win32-free model makes the traversal policy testable
// without opening a registry key.
inline constexpr std::size_t kRegistrySearchMaxKeys = 2000U;
inline constexpr std::size_t kRegistrySearchMaxValues = 2000U;
inline constexpr std::size_t kRegistrySearchMaxResults = 2000U;
inline constexpr std::size_t kRegistrySearchMaxDepth = 32U;
inline constexpr std::size_t kRegistrySearchMaxValuePreviewBytes = 16U * 1024U;

// RegistrySearchRequest is the user intent and bounded local-work budget for
// one registry search.  startPath and query are normalized by
// ValidateRegistrySearchRequest; each budget is clamped to its hard cap.
struct RegistrySearchRequest {
    std::wstring startPath;
    std::wstring query;
    // maxKeys limits accepted key nodes and the bounded child-name enumeration
    // work used to discover them; it never permits an unbounded wide key walk.
    std::size_t maxKeys = kRegistrySearchMaxKeys;
    std::size_t maxValues = kRegistrySearchMaxValues;
    std::size_t maxResults = kRegistrySearchMaxResults;
    std::size_t maxDepth = kRegistrySearchMaxDepth;
    std::size_t maxValuePreviewBytes = kRegistrySearchMaxValuePreviewBytes;
};

// RegistrySearchEntryKind describes a candidate independently of Win32 HKEY
// handles or R0 protocol objects.  The action layer maps its enumeration data
// to this type before it reaches the view.
enum class RegistrySearchEntryKind {
    Key,
    Value
};

// RegistrySearchCandidate is an untrusted, pre-rendered search input.  The
// caller supplies a short display preview rather than raw registry data so the
// model remains independent of WinAPI REG_* constants and transport details.
struct RegistrySearchCandidate {
    RegistrySearchEntryKind kind = RegistrySearchEntryKind::Key;
    std::wstring keyPath;
    std::wstring valueName;
    std::wstring valueTypeText;
    std::wstring dataPreview;
    std::size_t dataByteCount = 0;
    std::size_t depth = 0;
};

// RegistrySearchHit is the safe UI/export projection of one matching
// candidate.  A projected hit is valid only when keyPath is non-empty; data
// preview text is bounded and flattened to one display line.
struct RegistrySearchHit {
    bool valid = false;
    RegistrySearchEntryKind kind = RegistrySearchEntryKind::Key;
    std::wstring keyPath;
    std::wstring valueName;
    std::wstring valueTypeText;
    std::wstring dataPreview;
    std::size_t dataByteCount = 0;
    std::size_t depth = 0;
    bool dataPreviewTruncated = false;
};

// RegistrySearchCounters are maintained by the traversal/action layer.  The
// pure model only renders them; it never enumerates keys, reads values, or
// makes a cancellation decision.
struct RegistrySearchCounters {
    std::size_t visitedKeyCount = 0;
    std::size_t visitedValueCount = 0;
    // Includes bounded RegEnumKeyEx attempts, including a no-more-items probe.
    std::size_t inspectedSubKeyCount = 0;
    std::size_t matchedKeyCount = 0;
    std::size_t matchedValueCount = 0;
    std::size_t skippedDepthCount = 0;
    std::size_t readFailureCount = 0;
    std::size_t truncatedPreviewCount = 0;
};

// RegistrySearchStopReason explains whether the snapshot covers the full
// requested scope or stopped at one explicit safety/error boundary.
enum class RegistrySearchStopReason {
    NotStarted,
    Completed,
    InvalidRequest,
    KeyLimitReached,
    SubKeyEnumerationLimitReached,
    ValueLimitReached,
    ResultLimitReached,
    DepthLimitReached,
    Cancelled,
    ReadFailure
};

// RegistrySearchValidation carries a normalized request without requiring an
// exception or UI dialog.  errorText is populated only when valid is false.
struct RegistrySearchValidation {
    bool valid = false;
    RegistrySearchRequest request;
    std::wstring normalizedQuery;
    std::wstring errorText;
};

// RegistrySearchSnapshot is an immutable-value result that can safely cross
// from an action worker to the native view.  statusText is optional cached UI
// text; BuildRegistrySearchStatusText is the canonical pure formatter.
struct RegistrySearchSnapshot {
    RegistrySearchRequest request;
    std::wstring normalizedQuery;
    RegistrySearchCounters counters;
    RegistrySearchStopReason stopReason = RegistrySearchStopReason::NotStarted;
    std::wstring errorText;
    std::wstring statusText;
    std::vector<RegistrySearchHit> hits;
};

// ValidateRegistrySearchRequest trims path/query text, clamps caller-supplied
// budgets to fixed hard caps, and rejects an empty path or query explicitly.
RegistrySearchValidation ValidateRegistrySearchRequest(const RegistrySearchRequest& request);

// ProjectRegistrySearchHit makes one candidate safe for an in-memory result
// snapshot.  Input dataPreview is flattened and capped by maxPreviewBytes; the
// returned hit remains invalid when the candidate has no usable key path.
RegistrySearchHit ProjectRegistrySearchHit(
    const RegistrySearchCandidate& candidate,
    std::size_t maxPreviewBytes = kRegistrySearchMaxValuePreviewBytes);

// RegistrySearchHitMatches performs a case-insensitive substring check across
// the key path, value name/type and bounded data preview.  Empty query text
// never matches every row; callers must validate the request first.
bool RegistrySearchHitMatches(const RegistrySearchHit& hit, const std::wstring& normalizedQuery);

// BuildRegistrySearchStatusText turns traversal counters and a stop reason
// into a compact, explicit Chinese status label suitable for the native view.
std::wstring BuildRegistrySearchStatusText(const RegistrySearchSnapshot& snapshot);

// SanitizeRegistrySearchTsvCell flattens tab/newline separators so one field
// cannot corrupt a TSV export row.
std::wstring SanitizeRegistrySearchTsvCell(const std::wstring& text);

// BuildRegistrySearchTsv serializes valid hits in source order.  It emits an
// empty string when there is no valid hit, matching the other Lite exporters.
std::wstring BuildRegistrySearchTsv(const std::vector<RegistrySearchHit>& hits);

// BuildVisibleRegistrySearchTsv serializes only source indexes that remain
// visible after a local UI filter, preserving their supplied order.
std::wstring BuildVisibleRegistrySearchTsv(
    const std::vector<RegistrySearchHit>& hits,
    const std::vector<std::size_t>& visibleIndexes);

} // namespace Ksword::Features::Registry
