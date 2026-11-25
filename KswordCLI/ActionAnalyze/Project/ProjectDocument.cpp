#include "ProjectDocument.h"

#include "ProjectLock.h"
#include "SampleCatalog.h"

#include <algorithm>
#include <unordered_set>

namespace Ksword::ActionAnalyze {
using namespace ProjectStorage;

namespace {

constexpr wchar_t kManifest[] = L"project.ksaproj";
constexpr wchar_t kPrevious[] = L"previous.ksaproj";
constexpr std::uint64_t kGenerationLimit = 8192;

struct Head {
    ProjectInfo info;
    SampleCatalog catalog;
    std::string journalHash;
};

ProjectResult Corrupt(const char* detail) { return Failure(ProjectError::Corrupt, detail); }

bool IsValid(const RevisionSettings& settings) {
    return IsText(settings.title, kMaxTitleBytes) && IsText(settings.notes, kMaxNotesBytes, true);
}

JsonValue CatalogRef(const SampleCatalog& catalog) {
    return Object({{"generation", Number(catalog.generation)}, {"hash", Text(catalog.hash)}});
}

bool ReadCatalogRef(const JsonValue& object, SampleCatalog& catalog) {
    const auto* ref = object.find("catalogRoot");
    return ref && Fields(*ref, {"generation", "hash"}) && GetNumber(*ref, "generation", catalog.generation) &&
        catalog.generation != 0 && GetHash(*ref, "hash", catalog.hash);
}

JsonValue Manifest(const Head& head) {
    const auto& info = head.info;
    return Object({{"kind", Text("action-analyze-project")}, {"version", JsonValue::makeUInt(1)},
        {"requiredFeatures", JsonValue::makeArray({Text(kOfflineProjectFeature)})},
        {"projectId", Text(info.projectId)}, {"title", Text(info.settings.title)}, {"createdUtc", Number(info.createdUtc)},
        {"currentRevisionId", Text(info.revisionId)}, {"currentRevisionHash", Text(info.revisionHash)},
        {"configSemanticHash", Text(info.configSemanticHash)}, {"journalGeneration", Number(info.generation)},
        {"journalHash", Text(head.journalHash)}, {"catalogRoot", CatalogRef(head.catalog)},
        {"producer", Text("KswordCLI")}, {"storagePolicy", Text("local-ntfs-offline-metadata")}});
}

ProjectResult ParseManifest(const JsonValue& doc, Head& out) {
    if (!IsString(doc, "kind", "action-analyze-project")) return Corrupt("manifestKind");
    const auto* version = doc.find("version");
    std::uint64_t number = 0;
    if (!version || version->type() != JsonType::UInt || !version->tryGetU64(number)) return Corrupt("manifestVersion");
    if (number != 1) return Failure(ProjectError::Unsupported, "manifestVersion");
    const auto* features = doc.find("requiredFeatures");
    const auto* list = features ? features->asArray() : nullptr;
    if (!list) return Corrupt("requiredFeatures");
    std::string feature;
    if (list->size() != 1 || !list->front().tryGetString(feature) || feature != kOfflineProjectFeature) {
        return Failure(ProjectError::Unsupported, "requiredFeatures");
    }
    auto& info = out.info;
    if (!Fields(doc, {"kind", "version", "requiredFeatures", "projectId", "title", "createdUtc",
                      "currentRevisionId", "currentRevisionHash", "configSemanticHash", "journalGeneration",
                      "journalHash", "catalogRoot", "producer", "storagePolicy"}) ||
        !IsString(doc, "producer", "KswordCLI") || !IsString(doc, "storagePolicy", "local-ntfs-offline-metadata") ||
        !GetUuid(doc, "projectId", info.projectId) || !GetString(doc, "title", info.settings.title) ||
        !IsText(info.settings.title, kMaxTitleBytes) || !GetNumber(doc, "createdUtc", info.createdUtc) ||
        !info.createdUtc || !GetUuid(doc, "currentRevisionId", info.revisionId) ||
        !GetHash(doc, "currentRevisionHash", info.revisionHash) || !GetHash(doc, "configSemanticHash", info.configSemanticHash) ||
        !GetNumber(doc, "journalGeneration", info.generation) || !info.generation ||
        !GetHash(doc, "journalHash", out.journalHash) || !ReadCatalogRef(doc, out.catalog) ||
        out.catalog.generation > info.generation) return Corrupt("manifestFields");
    if (info.generation > kGenerationLimit) return Failure(ProjectError::LimitExceeded, "journalGeneration");
    return {};
}

struct Commit {
    std::uint64_t generation = 0;
    std::uint64_t previousGeneration = 0;
    std::string previousHash;
    std::string operation;
    std::string changedId;
    std::string changedHash;
    std::string revisionId;
    std::string revisionHash;
    std::string configSemanticHash;
    SampleCatalog catalog;
};

JsonValue Journal(const Head& head, const Head* previous, std::string_view operation,
                  std::string_view changedId, std::string_view changedHash) {
    const auto& info = head.info;
    return Object({{"kind", Text("project-commit")}, {"projectId", Text(info.projectId)},
        {"generation", Number(info.generation)}, {"previousGeneration", Number(previous ? previous->info.generation : 0)},
        {"previousCommitHash", previous ? Text(previous->journalHash) : JsonValue::makeNull()},
        {"operation", Text(operation)}, {"changedId", Text(changedId)}, {"changedHash", Text(changedHash)},
        {"revisionId", Text(info.revisionId)}, {"revisionHash", Text(info.revisionHash)},
        {"configSemanticHash", Text(info.configSemanticHash)}, {"catalogRoot", CatalogRef(head.catalog)}});
}

ProjectResult ReadCommit(const Directory& root, const ProjectInfo& info, std::uint64_t generation,
                         std::string_view hash, Commit& commit) {
    JsonValue entry;
    if (auto result = Read(root, {L"journal"}, NumberFile(generation), hash, entry); !result) return result;
    if (!Fields(entry, {"kind", "projectId", "generation", "previousGeneration", "previousCommitHash", "operation",
                        "changedId", "changedHash", "revisionId", "revisionHash", "configSemanticHash", "catalogRoot"}) ||
        !IsString(entry, "kind", "project-commit") || !IsString(entry, "projectId", info.projectId) ||
        !GetNumber(entry, "generation", commit.generation) || commit.generation != generation ||
        !GetNumber(entry, "previousGeneration", commit.previousGeneration) || commit.previousGeneration >= generation ||
        !GetString(entry, "operation", commit.operation) || !GetUuid(entry, "changedId", commit.changedId) ||
        !GetHash(entry, "changedHash", commit.changedHash) || !GetUuid(entry, "revisionId", commit.revisionId) ||
        !GetHash(entry, "revisionHash", commit.revisionHash) || !GetHash(entry, "configSemanticHash", commit.configSemanticHash) ||
        !ReadCatalogRef(entry, commit.catalog) || commit.catalog.generation > generation) return Corrupt("journalFields");
    if (commit.operation == "create") {
        if (generation != 1 || commit.previousGeneration || !IsNull(entry, "previousCommitHash") ||
            commit.changedId != info.projectId || commit.changedHash != commit.revisionHash ||
            commit.catalog.generation != 1) return Corrupt("journalCreate");
    } else if (commit.operation == "saveRevision" || commit.operation == "addSample") {
        if (!commit.previousGeneration || !GetHash(entry, "previousCommitHash", commit.previousHash)) {
            return Corrupt("journalPrevious");
        }
    } else {
        return Failure(ProjectError::Unsupported, "journalOperation");
    }
    return {};
}

bool SameCatalog(const SampleCatalog& left, const SampleCatalog& right) {
    return left.generation == right.generation && left.hash == right.hash;
}

ProjectResult ReadRevision(const Directory& root, ProjectInfo& info,
                           std::string& parentId, std::string& parentHash) {
    JsonValue revision;
    if (auto result = Read(root, {L"revisions"}, WideAscii(info.revisionId) + L".json", info.revisionHash, revision);
        !result) return result;
    RevisionSettings settings;
    if (!Fields(revision, {"kind", "projectId", "revisionId", "parentRevisionId", "parentRevisionHash",
                           "configSemanticHash", "config"}) || !IsString(revision, "kind", "offline-project-revision") ||
        !IsString(revision, "projectId", info.projectId) || !IsString(revision, "revisionId", info.revisionId) ||
        !IsString(revision, "configSemanticHash", info.configSemanticHash) ||
        !ParseSettings(*revision.find("config"), settings) || settings.title != info.settings.title) {
        return Corrupt("revisionFields");
    }
    if (!IsNull(revision, "parentRevisionId") || !IsNull(revision, "parentRevisionHash")) {
        if (!GetUuid(revision, "parentRevisionId", parentId) || !GetHash(revision, "parentRevisionHash", parentHash)) {
            return Corrupt("revisionParent");
        }
    }
    std::string actual;
    if (auto result = ConfigHash(settings, actual); !result) return result;
    if (actual != info.configSemanticHash) return Corrupt("revisionConfigHash");
    info.settings = std::move(settings);
    return {};
}

ProjectResult LoadHead(const Directory& root, bool fallback, Head& out) {
    JsonValue doc;
    const auto read = fallback ? Read(root, {L"journal"}, kPrevious, {}, doc) : Read(root, {}, kManifest, {}, doc);
    if (!read) return read;
    Head head;
    if (auto result = ParseManifest(doc, head); !result) return result;
    auto& info = head.info;
    std::string parentId, parentHash;
    if (auto result = ReadRevision(root, info, parentId, parentHash); !result) return result;
    Commit current;
    if (auto result = ReadCommit(root, info, info.generation, head.journalHash, current); !result) return result;
    if (current.revisionId != info.revisionId || current.revisionHash != info.revisionHash ||
        current.configSemanticHash != info.configSemanticHash || !SameCatalog(current.catalog, head.catalog)) {
        return Corrupt("manifestJournalMismatch");
    }
    bool checkedRevisionParent = false;
    std::string lastSampleId, lastSampleHash;
    while (current.previousGeneration) {
        Commit previous;
        if (auto result = ReadCommit(root, info, current.previousGeneration, current.previousHash, previous); !result) return result;
        if (current.operation == "saveRevision") {
            if (current.changedId != current.revisionId || current.changedHash != current.revisionHash ||
                current.revisionId == previous.revisionId || !SameCatalog(current.catalog, previous.catalog)) {
                return Corrupt("journalRevisionTransition");
            }
            if (!checkedRevisionParent) {
                if (parentId != previous.revisionId || parentHash != previous.revisionHash) return Corrupt("revisionParentMismatch");
                checkedRevisionParent = true;
            }
        } else {
            if (current.catalog.generation != current.generation || current.revisionId != previous.revisionId ||
                current.revisionHash != previous.revisionHash || current.configSemanticHash != previous.configSemanticHash) {
                return Corrupt("journalSampleTransition");
            }
            if (lastSampleId.empty()) {
                lastSampleId = current.changedId;
                lastSampleHash = current.changedHash;
            }
        }
        current = std::move(previous);
    }
    if (!checkedRevisionParent && (!parentId.empty() || !parentHash.empty())) return Corrupt("initialRevisionParent");
    if (auto result = head.catalog.Load(root, info.projectId); !result) return result;
    if (lastSampleId.empty() != (head.catalog.count == 0)) return Corrupt("catalogCountMismatch");
    if (head.catalog.count) {
        // 打开时只校验最新采样提交所对应的尾页。其它页与快照按请求读取。
        std::vector<SampleInfo> tail;
        if (auto result = head.catalog.List(root, info.projectId, head.catalog.count - 1, 1, tail); !result) return result;
        if (tail[0].sampleId != lastSampleId || tail[0].descriptionHash != lastSampleHash) return Corrupt("catalogCommitMismatch");
    }
    info.sampleCount = head.catalog.count;
    out = std::move(head);
    return {};
}

ProjectResult LoadReadableHead(const Directory& root, Head& out) {
    auto primary = LoadHead(root, false, out);
    if (primary || (primary.error != ProjectError::NotFound && primary.error != ProjectError::Corrupt &&
                    primary.error != ProjectError::LimitExceeded)) return primary;
    if (auto previous = LoadHead(root, true, out); !previous) return primary;
    out.info.recoveredPrevious = true;
    out.info.primaryFailure = primary;
    return {};
}

ProjectResult PublishRevision(const Directory& root, ProjectInfo& info, const ProjectInfo* previous) {
    if (auto result = NewId(info.revisionId); !result) return result;
    if (auto result = ConfigHash(info.settings, info.configSemanticHash); !result) return result;
    const auto doc = Object({{"kind", Text("offline-project-revision")}, {"projectId", Text(info.projectId)},
        {"revisionId", Text(info.revisionId)}, {"parentRevisionId", previous ? Text(previous->revisionId) : JsonValue::makeNull()},
        {"parentRevisionHash", previous ? Text(previous->revisionHash) : JsonValue::makeNull()},
        {"configSemanticHash", Text(info.configSemanticHash)}, {"config", Settings(info.settings)}});
    return Publish(root, {L"revisions"}, WideAscii(info.revisionId) + L".json", doc, false, &info.revisionHash);
}

ProjectResult NextGeneration(const Directory& root, Head& head, bool createCatalog) {
    Directory journal;
    if (auto result = OpenDirectory(root, {L"journal"}, journal); !result) return result;
    // 未发布的代留下原文件，重试只分配新的代。恢复只读正式指针，不按文件名猜测。
    for (unsigned attempts = 0; head.info.generation < kGenerationLimit && attempts < 128; ++attempts) {
        ++head.info.generation;
        Handle check;
        const auto found = OpenFile(journal, NumberFile(head.info.generation), FILE_READ_ATTRIBUTES,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING, check);
        if (found) continue;
        if (found.error != ProjectError::NotFound) return found;
        if (createCatalog) {
            Directory folder;
            const auto result = OpenDirectory(root, {L"catalog", std::to_wstring(head.info.generation)}, folder, true);
            if (result.error == ProjectError::AlreadyExists) continue;
            if (!result) return result;
            head.catalog.generation = head.info.generation;
        } else {
            Directory unused;
            const auto foundCatalog = OpenDirectory(root, {L"catalog", std::to_wstring(head.info.generation)}, unused);
            if (foundCatalog) continue;
            if (foundCatalog.error != ProjectError::NotFound) return foundCatalog;
        }
        return {};
    }
    return Failure(ProjectError::LimitExceeded, "journalGenerationAttempts");
}

ProjectResult CommitHead(const Directory& root, Head& head, const Head* previous, std::string_view operation,
                         std::string_view changedId, std::string_view changedHash) {
    const auto journal = Journal(head, previous, operation, changedId, changedHash);
    if (auto result = Publish(root, {L"journal"}, NumberFile(head.info.generation), journal, false, &head.journalHash);
        !result) return result;
    if (previous) {
        if (auto result = Publish(root, {L"journal"}, kPrevious, Manifest(*previous), true); !result) return result;
    }
    return Publish(root, {}, kManifest, Manifest(head), previous != nullptr);
}

ProjectResult CheckCurrentManifest(const Directory& root, const Head& expected) {
    JsonValue doc;
    if (auto result = Read(root, {}, kManifest, {}, doc); !result) return result;
    Head actual;
    if (auto result = ParseManifest(doc, actual); !result) return result;
    if (actual.info.projectId != expected.info.projectId || actual.journalHash != expected.journalHash ||
        actual.info.generation != expected.info.generation || actual.info.revisionId != expected.info.revisionId ||
        actual.info.revisionHash != expected.info.revisionHash ||
        actual.info.configSemanticHash != expected.info.configSemanticHash ||
        actual.info.settings.title != expected.info.settings.title || actual.info.createdUtc != expected.info.createdUtc ||
        !SameCatalog(actual.catalog, expected.catalog)) return Failure(ProjectError::StaleRevision, "manifestChanged");
    // 锁只协调遵循协议的写者。写入前同时核对当前三个直接引用的精确字节。
    if (auto result = Read(root, {L"journal"}, NumberFile(expected.info.generation), expected.journalHash, doc); !result) return result;
    if (auto result = Read(root, {L"revisions"}, WideAscii(expected.info.revisionId) + L".json", expected.info.revisionHash, doc);
        !result) return result;
    if (auto result = actual.catalog.Load(root, expected.info.projectId); !result) return result;
    return {};
}

std::wstring RootFromManifest(std::wstring path) {
    const auto separator = path.find_last_of(L"/\\");
    const auto name = std::wstring_view(path).substr(separator == path.npos ? 0 : separator + 1);
    if (name.size() == ARRAYSIZE(kManifest) - 1 &&
        CompareStringOrdinal(name.data(), static_cast<int>(name.size()), kManifest, -1, TRUE) == CSTR_EQUAL) {
        if (separator == path.npos) return L".";
        path.resize(separator + 1);
    }
    return path;
}

} // namespace

struct ProjectDocument::State {
    Directory root;
    ProjectLock lock;
    Head head;
};

const char* ProjectErrorName(ProjectError error) noexcept {
    switch (error) {
    case ProjectError::None: return "ok";
    case ProjectError::InvalidArgument: return "invalidArgument";
    case ProjectError::AlreadyOpen: return "alreadyOpen";
    case ProjectError::NotOpen: return "notOpen";
    case ProjectError::NotFound: return "notFound";
    case ProjectError::AlreadyExists: return "alreadyExists";
    case ProjectError::ReadOnly: return "readOnly";
    case ProjectError::WriterBusy: return "writerBusy";
    case ProjectError::StaleRevision: return "staleRevision";
    case ProjectError::Unsupported: return "unsupported";
    case ProjectError::RecoveryRequired: return "recoveryRequired";
    case ProjectError::UnsafePath: return "unsafePath";
    case ProjectError::Corrupt: return "corrupt";
    case ProjectError::LimitExceeded: return "limitExceeded";
    case ProjectError::IoError: return "ioError";
    }
    return "unknown";
}

ProjectDocument::ProjectDocument() = default;
ProjectDocument::~ProjectDocument() = default;
void ProjectDocument::Close() noexcept { state_.reset(); }
const ProjectInfo* ProjectDocument::Info() const noexcept { return state_ ? &state_->head.info : nullptr; }
const Directory* ProjectDocument::RootForRead() const noexcept { return state_ ? &state_->root : nullptr; }

ProjectResult ProjectDocument::Create(const std::wstring& directory, const RevisionSettings& settings) {
    if (state_) return Failure(ProjectError::AlreadyOpen, "project");
    if (!IsValid(settings)) return Failure(ProjectError::InvalidArgument, "revisionSettings");
    auto next = std::make_unique<State>();
    auto& root = next->root;
    if (auto result = OpenRoot(directory, true, true, root); !result) return result;
    for (const auto* component : {L".staging", L".locks", L"revisions", L"journal", L"catalog", L"samples"}) {
        Directory created;
        if (auto result = OpenDirectory(root, {component}, created, true); !result) return result;
    }
    if (auto result = next->lock.AcquireWriter(root, true); !result) return result;
    if (auto result = next->lock.AcquireReader(root); !result) return result;
    auto& head = next->head;
    auto& info = head.info;
    info.settings = settings;
    info.createdUtc = UtcNow();
    info.access = ProjectAccess::ReadWrite;
    if (auto result = NewId(info.projectId); !result) return result;
    if (auto result = NextGeneration(root, head, true); !result) return result;
    if (auto result = PublishRevision(root, info, nullptr); !result) return result;
    if (auto result = head.catalog.Publish(root, info.projectId, {}); !result) return result;
    if (auto result = CommitHead(root, head, nullptr, "create", info.projectId, info.revisionHash); !result) return result;
    state_ = std::move(next);
    return {};
}

ProjectResult ProjectDocument::Open(const std::wstring& directoryOrManifest, ProjectAccess access) {
    if (state_) return Failure(ProjectError::AlreadyOpen, "project");
    auto next = std::make_unique<State>();
    const bool write = access == ProjectAccess::ReadWrite;
    if (auto result = OpenRoot(RootFromManifest(directoryOrManifest), false, write, next->root); !result) return result;
    if (auto result = next->lock.AcquireReader(next->root); !result) return result;
    if (auto result = LoadReadableHead(next->root, next->head); !result) return result;
    if (write) {
        if (next->head.info.recoveredPrevious) return Failure(ProjectError::RecoveryRequired, "previousManifest");
        if (auto result = next->lock.AcquireWriter(next->root, false); !result) return result;
        // 第一次读取与取得写锁之间，其他写者可能提交了新代。
        if (auto result = LoadHead(next->root, false, next->head); !result) return result;
        next->head.info.access = ProjectAccess::ReadWrite;
    }
    state_ = std::move(next);
    return {};
}

ProjectResult ProjectDocument::Save(const RevisionSettings& settings, std::string_view expectedRevisionId) {
    if (!state_) return Failure(ProjectError::NotOpen, "project");
    const auto& previous = state_->head;
    if (previous.info.access != ProjectAccess::ReadWrite) return Failure(ProjectError::ReadOnly, "project");
    if (!IsValid(settings)) return Failure(ProjectError::InvalidArgument, "revisionSettings");
    if (!expectedRevisionId.empty()) {
        if (!IsUuid(expectedRevisionId)) return Failure(ProjectError::InvalidArgument, "expectedRevisionId");
        if (expectedRevisionId != previous.info.revisionId) return Failure(ProjectError::StaleRevision, "expectedRevisionId");
    }
    const auto& root = state_->root;
    if (auto result = CheckCurrentManifest(root, previous); !result) return result;
    if (settings.title == previous.info.settings.title && settings.notes == previous.info.settings.notes) return {};

    auto next = previous;
    next.info.settings = settings;
    if (auto result = NextGeneration(root, next, false); !result) return result;
    if (auto result = PublishRevision(root, next.info, &previous.info); !result) return result;
    if (auto result = CommitHead(root, next, &previous, "saveRevision", next.info.revisionId, next.info.revisionHash);
        !result) return result;
    state_->head = std::move(next);
    return {};
}

ProjectResult ProjectDocument::CreateSample(std::string_view title, SampleInfo& out) {
    if (!state_) return Failure(ProjectError::NotOpen, "project");
    const auto& previous = state_->head;
    if (previous.info.access != ProjectAccess::ReadWrite) return Failure(ProjectError::ReadOnly, "project");
    if (!IsText(title, kMaxTitleBytes)) return Failure(ProjectError::InvalidArgument, "sampleTitle");
    if (previous.catalog.count >= kProjectSampleLimit) return Failure(ProjectError::LimitExceeded, "sampleLimit");

    const auto& root = state_->root;
    if (auto result = CheckCurrentManifest(root, previous); !result) return result;
    auto next = previous;
    std::vector<SampleInfo> entries;
    if (auto result = previous.catalog.ReadAll(root, next.info.projectId, entries); !result) return result;
    if (auto result = NextGeneration(root, next, true); !result) return result;
    SampleInfo sample;
    sample.title = title;
    sample.createdUtc = UtcNow();
    sample.revisionId = next.info.revisionId;
    if (auto result = NewId(sample.sampleId); !result) return result;
    if (auto result = NewId(sample.snapshotId); !result) return result;
    if (auto result = PublishSample(root, next.info, sample, sample.descriptionHash); !result) return result;
    entries.push_back(sample);
    if (auto result = next.catalog.Publish(root, next.info.projectId, entries); !result) return result;
    next.info.sampleCount = next.catalog.count;
    if (auto result = CommitHead(root, next, &previous, "addSample", sample.sampleId, sample.descriptionHash); !result) return result;
    state_->head = std::move(next);
    out = std::move(sample);
    return {};
}

ProjectResult ProjectDocument::ListSamples(std::uint64_t start, std::uint64_t limit, std::vector<SampleInfo>& out) const {
    if (!state_) return Failure(ProjectError::NotOpen, "project");
    return state_->head.catalog.List(state_->root, state_->head.info.projectId, start, limit, out);
}

ProjectResult ProjectDocument::ReadSample(std::string_view sampleId, SampleRecord& out) const {
    if (!state_) return Failure(ProjectError::NotOpen, "project");
    if (!IsUuid(sampleId)) return Failure(ProjectError::InvalidArgument, "sampleId");
    SampleInfo summary;
    const auto& projectId = state_->head.info.projectId;
    if (auto result = state_->head.catalog.Find(state_->root, projectId, sampleId, summary); !result) return result;
    return ReadSampleRecord(state_->root, projectId, summary, out);
}

ProjectResult ProjectDocument::ListOrphans(std::vector<std::string>& out) const {
    if (!state_) return Failure(ProjectError::NotOpen, "project");
    // 旧只读快照可能落后于当前写者。只有独占写者能判定当前目录没有并发提交。
    if (state_->head.info.access != ProjectAccess::ReadWrite) return Failure(ProjectError::ReadOnly, "orphanScanRequiresWriter");
    std::vector<SampleInfo> entries;
    if (auto result = state_->head.catalog.ReadAll(state_->root, state_->head.info.projectId, entries); !result) return result;
    std::unordered_set<std::string> committed;
    for (const auto& entry : entries) committed.insert(entry.sampleId);

    Directory samples;
    if (auto result = OpenDirectory(state_->root, {L"samples"}, samples); !result) return result;
    WIN32_FIND_DATAW entry{};
    const HANDLE enumerator = FindFirstFileW((samples.path + L"\\*").c_str(), &entry);
    if (enumerator == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND) return WinFailure("orphanScan", error);
        out.clear();
        return {};
    }
    std::vector<std::string> candidates;
    std::size_t scanned = 0;
    do {
        if (++scanned > 2 * kGenerationLimit) {
            FindClose(enumerator);
            return Failure(ProjectError::LimitExceeded, "orphanScan");
        }
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) continue;
        const std::wstring_view name(entry.cFileName);
        if (name.size() != 36 || std::any_of(name.begin(), name.end(), [](wchar_t c) { return c > 127; })) continue;
        std::string id;
        for (wchar_t c : name) id.push_back(static_cast<char>(c));
        if (IsUuid(id) && !committed.contains(id)) candidates.push_back(std::move(id));
    } while (FindNextFileW(enumerator, &entry));
    const DWORD error = GetLastError();
    FindClose(enumerator);
    if (error != ERROR_NO_MORE_FILES) return WinFailure("orphanScan", error);
    std::sort(candidates.begin(), candidates.end());
    out = std::move(candidates);
    return {};
}

} // namespace Ksword::ActionAnalyze
