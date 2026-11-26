#include "MemorySnapshotCommand.h"

#include "../Memory/SelectedMemorySnapshot.h"
#include "../Project/ProjectMemorySnapshot.h"
#include "../Project/MemorySnapshotReader.h"
#include "../Project/ProjectStorage.h"
#include "../../CommandRegistry.h"

#include <filesystem>
#include <stdexcept>

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
namespace storage = project::ProjectStorage;
using V = Ksword::Evidence::JsonValue;
constexpr std::uint64_t kMaxSnapshots = 4096;

std::string Utf8(const std::wstring& text)
{
    if (text.empty()) return {};
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!count) throw std::invalid_argument("Invalid Unicode argument");
    std::string result(count, '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), count, nullptr, nullptr))
        throw std::invalid_argument("Invalid Unicode argument");
    return result;
}

std::wstring Wide(std::string_view text)
{
    if (text.empty()) return {};
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!count) throw std::runtime_error("Invalid archived UTF-8");
    std::wstring result(count, L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), count))
        throw std::runtime_error("Invalid archived UTF-8");
    return result;
}

Json DocumentJson(const V& value)
{
    const auto text = Wide(Ksword::Evidence::WriteJson(value));
    return {text, text};
}

Json Issue(const project::ProjectResult& issue)
{
    if (issue) return {};
    return Json::object({{L"error", Json::string(storage::WideAscii(project::ProjectErrorName(issue.error)))},
        {L"detail", Json::string(storage::WideAscii(issue.detail))}, {L"win32Error", Json::number(issue.nativeError)}});
}

Result Failed(const project::ProjectResult& issue)
{
    return {3, Json::object({{L"error", Issue(issue)}}), {}};
}

Result NativeFailure(const wchar_t* stage, DWORD error)
{
    return {3, Json::object({{L"stage", Json::string(stage)}, {L"win32Error", Json::number(error)}}), {}};
}

std::string SampleId(const Args& args)
{
    auto id = Utf8(args.require(L"--sample"));
    if (!storage::IsUuid(id)) throw std::invalid_argument("--sample must be a canonical sample UUID");
    return id;
}

// Verify every preceding memory segment before selecting a new ordinal or reading a later one.
project::ProjectResult ReadThrough(const project::ProjectDocument& document, std::string_view sample,
    std::uint64_t ordinal, project::ArchivedMemorySnapshot& out)
{
    std::optional<std::uint64_t> previous = 0;
    for (std::uint64_t index = 1; index <= ordinal; ++index) {
        const auto status = project::ReadMemorySnapshot(document, sample, index, previous, out);
        if (!status) return status;
        previous = out.boundary.lastSequence;
    }
    return {};
}

project::ProjectResult NextOrdinal(const project::ProjectDocument& document, std::string_view sample,
    std::uint64_t& ordinal, std::optional<std::uint64_t>& previous)
{
    previous = 0;
    for (ordinal = 1; ordinal <= kMaxSnapshots; ++ordinal) {
        project::ArchivedMemorySnapshot snapshot;
        const auto status = project::ReadMemorySnapshot(document, sample, ordinal, previous, snapshot);
        if (status.error == project::ProjectError::NotFound) return {};
        if (!status) return status;
        previous = snapshot.boundary.lastSequence;
    }
    return storage::Failure(project::ProjectError::LimitExceeded, "memorySnapshotCount");
}

Json SnapshotJson(const project::ProjectDocument& document, std::string_view sample, std::uint64_t ordinal,
    const project::ArchivedMemorySnapshot& snapshot)
{
    std::vector<Json> pages;
    for (const auto& page : snapshot.pages) {
        pages.push_back(Json::object({{L"recordSequence", Json::count(page.sequence)}, {L"recordOffset", Json::count(page.offset)},
            {L"validLength", Json::count(page.bytes.size())}, {L"observation", DocumentJson(page.metadata)}}));
    }
    return Json::object({{L"projectId", Json::string(storage::WideAscii(document.Info()->projectId))},
        {L"sampleId", Json::string(storage::WideAscii(sample))}, {L"stream", Json::string(L"raw-memory")},
        {L"ordinal", Json::count(ordinal)}, {L"segmentVerified", Json::boolean(true)},
        {L"sha256", Json::string(storage::WideAscii(snapshot.sha256))}, {L"endOffset", Json::count(snapshot.boundary.byteOffset)},
        {L"lastSequence", Json::count(snapshot.boundary.lastSequence)}, {L"capturedBytes", Json::count(snapshot.capturedBytes)},
        {L"unavailablePages", Json::count(snapshot.unavailablePages)}, {L"completeRange", Json::boolean(snapshot.completeRange)},
        {L"atomicProcessSnapshot", Json::boolean(false)}, {L"plan", DocumentJson(snapshot.plan)},
        {L"end", DocumentJson(snapshot.end)}, {L"pages", Json::array(pages)}});
}

Result Capture(const Args& args)
{
    if (!args.has(L"--confirm")) throw std::invalid_argument("--confirm is required for an authorized owned process");
    memory::Plan plan;
    plan.target.pid = args.u32(L"--pid");
    plan.target.creationFileTime100ns = args.integer(L"--creation-filetime");
    plan.range = {args.integer(L"--base"), args.integer(L"--bytes")};
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    if (!plan.target.pid || plan.target.pid == UINT32_MAX || !plan.target.creationFileTime100ns || !plan.range.base ||
        !plan.range.length || plan.range.base > UINT64_MAX - plan.range.length || !system.dwPageSize ||
        (plan.range.base + plan.range.length - 1) / system.dwPageSize - plan.range.base / system.dwPageSize + 1 > memory::kMaxTrackedPages)
        throw std::invalid_argument("Expected PID, creation FILETIME and a nonempty address range covering at most 64 pages");

    const HANDLE opened = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, plan.target.pid);
    if (!opened) return NativeFailure(L"OpenProcess", GetLastError());
    const storage::Handle target(opened);
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(opened, &created, &exited, &kernel, &user)) return NativeFailure(L"GetProcessTimes", GetLastError());
    const auto creation = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    if (creation != plan.target.creationFileTime100ns || WaitForSingleObject(opened, 0) != WAIT_TIMEOUT)
        return NativeFailure(L"target-instance-mismatch", ERROR_INVALID_PARAMETER);

    project::ProjectDocument document;
    if (const auto status = document.Open(args.require(L"--project"), project::ProjectAccess::ReadWrite); !status) return Failed(status);
    const auto revision = document.Info()->revisionId;
    project::SampleInfo sample;
    if (args.has(L"--sample")) {
        project::SampleRecord stored;
        if (const auto status = document.ReadSample(SampleId(args), stored); !status) return Failed(status);
        sample = stored.info;
    }
    if (const auto status = storage::NewId(plan.trackingEpoch); !status) return Failed(status);
    // Invocation-local machine/boot labels are scoped to this capture UUID, not asserted as cross-capture OS identities.
    plan.target.machineId = plan.trackingEpoch;
    plan.target.bootId = plan.trackingEpoch;
    plan.target.processInstanceId = std::to_string(plan.target.pid) + ":" + std::to_string(creation);
    plan.authorizedOwnedProcess = true;
    plan.rounds.reset();
    std::uint64_t ordinal = 1;
    std::optional<std::uint64_t> previous = 0;
    if (!sample.sampleId.empty()) {
        if (const auto status = NextOrdinal(document, sample.sampleId, ordinal, previous); !status) return Failed(status);
    } else {
        const auto title = Utf8(args.get(L"--title", L"Selected live memory snapshot"));
        if (const auto status = document.CreateSample(title, sample, revision); !status) return Failed(status);
    }
    plan.sampleId = sample.sampleId;
    const Cancellation cancel;
    const auto snapshot = memory::CaptureSelectedMemory(opened, plan, cancel.token.get());
    project::ProjectMemorySnapshotReceipt receipt;
    const auto written = project::WriteSelectedMemorySnapshot(document, sample.sampleId, ordinal, previous, snapshot, receipt);
    if (!written) {
        return {3, Json::object({{L"projectId", Json::string(storage::WideAscii(document.Info()->projectId))},
            {L"sampleId", Json::string(storage::WideAscii(sample.sampleId))}, {L"stream", Json::string(L"raw-memory")},
            {L"ordinal", Json::count(ordinal)}, {L"segmentVerified", Json::boolean(false)}, {L"error", Issue(written)},
            {L"capturedBytes", Json::count(receipt.capturedBytes)}, {L"endOffset", receipt.raw.flushed ? Json::count(receipt.raw.flushed->byteOffset) : Json{}}}), {}};
    }
    project::ArchivedMemorySnapshot archived;
    if (const auto status = project::ReadMemorySnapshot(document, sample.sampleId, ordinal, previous, archived); !status) return Failed(status);
    return {archived.completeRange ? 0 : 6, SnapshotJson(document, sample.sampleId, ordinal, archived), {}};
}

project::ProjectResult Export(const std::wstring& path, std::string_view bytes, std::string& sha)
{
    const std::filesystem::path destination(path);
    if (destination.filename().empty() || destination.parent_path().empty())
        return storage::Failure(project::ProjectError::InvalidArgument, "memoryExportPath");
    storage::Directory parent;
    if (const auto status = storage::OpenRoot(destination.parent_path().wstring(), false, true, parent); !status) return status;
    storage::Handle file;
    if (const auto status = storage::OpenFile(parent, destination.filename().wstring(), GENERIC_READ | GENERIC_WRITE,
            0, CREATE_NEW, file); !status) return status;
    DWORD written = 0;
    if (!WriteFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) || written != bytes.size())
        return storage::WinFailure("memoryExportWrite", GetLastError() ? GetLastError() : ERROR_WRITE_FAULT);
    if (!FlushFileBuffers(file.get())) return storage::WinFailure("memoryExportFlush", GetLastError());
    return storage::HashArchivePrefix(file.get(), bytes.size(), sha);
}

Result Read(const Args& args, bool exportBytes)
{
    const auto sample = SampleId(args);
    const auto ordinal = args.integer(L"--ordinal");
    if (!ordinal || ordinal > kMaxSnapshots) throw std::invalid_argument("--ordinal must be 1..4096");
    project::ProjectDocument document;
    if (const auto status = document.Open(args.require(L"--project")); !status) return Failed(status);
    project::ArchivedMemorySnapshot snapshot;
    if (const auto status = ReadThrough(document, sample, ordinal, snapshot); !status) return Failed(status);
    if (!exportBytes) return {snapshot.completeRange ? 0 : 6, SnapshotJson(document, sample, ordinal, snapshot), {}};
    if (args.has(L"--base") != args.has(L"--bytes")) throw std::invalid_argument("Supply both --base and --bytes for a subrange");
    const memory::Range range = args.has(L"--base") ? memory::Range{args.integer(L"--base"), args.integer(L"--bytes")} : snapshot.range;
    std::string bytes, sha;
    if (const auto status = project::SelectMemorySnapshotBytes(snapshot, range, bytes); !status) return Failed(status);
    const auto path = args.require(L"--out");
    if (const auto status = Export(path, bytes, sha); !status) return Failed(status);
    return {0, Json::object({{L"projectId", Json::string(storage::WideAscii(document.Info()->projectId))},
        {L"sampleId", Json::string(storage::WideAscii(sample))}, {L"stream", Json::string(L"raw-memory")},
        {L"ordinal", Json::count(ordinal)}, {L"base", Json::hex(range.base)}, {L"validLength", Json::count(bytes.size())},
        {L"out", Json::string(path)}, {L"sha256", Json::string(storage::WideAscii(sha))},
        {L"sourceSha256", Json::string(storage::WideAscii(snapshot.sha256))}, {L"rangeComplete", Json::boolean(true)},
        {L"snapshotCompleteRange", Json::boolean(snapshot.completeRange)}, {L"atomicProcessSnapshot", Json::boolean(false)}}), {}};
}
} // namespace

void RegisterMemorySnapshotCommands()
{
    Command capture;
    capture.path = L"analyze memory snapshot";
    capture.syntax = L"KswordCLI.exe analyze memory snapshot --project PATH [--sample UUID] --pid PID --creation-filetime N --base ADDR --bytes N --confirm [--title TEXT] [--json]";
    capture.summary = L"Archive actual bytes from one authorized live memory range into raw-memory in a project sample.";
    capture.options = L"Requires --project, --pid, --creation-filetime, --base, --bytes and --confirm. Optional --sample appends a new memory segment; otherwise freezes the current project revision into a new sample.";
    capture.notes = L"One read-only, non-atomic round, at most 64 pages. Failed/cancelled pages retain metadata and partial bytes are never padded. Existing API raw streams are preserved. Exit 6 means incomplete range.";
    capture.run = Capture;
    addCommand(std::move(capture));
    Command read;
    read.path = L"analyze memory read";
    read.syntax = L"KswordCLI.exe analyze memory read --project PATH --sample UUID --ordinal N [--json]";
    read.summary = L"Read a verified raw-memory snapshot, its page coordinates, hashes, timing and gaps.";
    read.options = L"Requires --project, --sample and --ordinal (1..4096).";
    read.notes = L"Verifies the memory segment chain and actual page hashes. Exit 6 preserves an incomplete snapshot report. Does not read a live process.";
    read.run = [](const Args& args) { return Read(args, false); };
    addCommand(std::move(read));
    Command exportCommand;
    exportCommand.path = L"analyze memory export";
    exportCommand.syntax = L"KswordCLI.exe analyze memory export --project PATH --sample UUID --ordinal N --out PATH [--base ADDR --bytes N] [--json]";
    exportCommand.summary = L"Export a fully covered range of verified archived memory bytes without filling gaps.";
    exportCommand.options = L"Requires --project, --sample, --ordinal and a new --out file with an existing parent directory. Optional --base and --bytes select a subrange.";
    exportCommand.notes = L"Rejects missing, corrupt or unavailable bytes before creating the output. Never overwrites an existing file. Output is a binary range, not a full process dump.";
    exportCommand.run = [](const Args& args) { return Read(args, true); };
    addCommand(std::move(exportCommand));
}
} // namespace ks::cli::action_analyze
