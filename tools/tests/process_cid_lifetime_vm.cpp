// Controlled end-to-end regression. Never run the mutation suite on the host.
#include <windows.h>
#include <tlhelp32.h>
#include "../../shared/driver/KswordArkProcessIoctl.h"
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

static HANDLE device = INVALID_HANDLE_VALUE;
static unsigned enumerationCalls = 0, incompleteEnumerations = 0;
static void require(bool ok, const char* text) { if (!ok) throw std::runtime_error(std::string(text) + " win32=" + std::to_string(GetLastError())); }
static void requireVm() {
    wchar_t manufacturer[256]{}; DWORD bytes = sizeof(manufacturer);
    require(RegGetValueW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer",
        RRF_RT_REG_SZ, nullptr, manufacturer, &bytes) == ERROR_SUCCESS &&
        std::wstring(manufacturer).find(L"VMware") != std::wstring::npos, "VMware guest required");
    require(GetEnvironmentVariableW(L"KSWORD_CID_VM_LAB", nullptr, 0) != 0, "explicit VM-only lab opt-in required");
}
static int policyTests() {
    unsigned count = 0;
    const auto test = [&](bool condition) { require(condition, "strict policy regression"); ++count; };
    const auto decide = [](ULONG proof, ULONG flags, ULONGLONG address = 16, ULONGLONG created = 32,
        ULONG oldProof = 255, ULONG oldFlags = 0, ULONGLONG oldAddress = 16, ULONGLONG oldCreated = 32) {
        return KswordArkProcessExitedResidual(proof, flags, address, created, oldProof, oldFlags, oldAddress, oldCreated) != 0;
    };
    constexpr ULONG core = KSWORD_ARK_PROCESS_EXIT_REQUIRED;
    test(core == 0x8b); test(decide(core, 0)); test(decide(255, 0));
    for (ULONG bit = 1; bit <= 128; bit <<= 1) {
        if ((core & bit) != 0) { test(!decide(core & ~bit, 0)); test(!decide(core, 0, 16, 32, core & ~bit)); }
        else { test(decide(core | bit, 0)); test(decide(255 & ~bit, 0)); }
    }
    test(!decide(core, KSWORD_ARK_PROCESS_FLAG_PID_FIELD_MISMATCH));
    test(!decide(core, 0, 16, 32, core, KSWORD_ARK_PROCESS_FLAG_PID_FIELD_MISMATCH));
    test(!decide(core, 0, 0)); test(!decide(core, 0, 16, 0));
    test(!decide(core, 0, 24)); test(!decide(core, 0, 16, 40)); test(!decide(core, 0, 16, 32, 0));
    test(decide(core, KSWORD_ARK_PROCESS_FLAG_CID_TABLE_UNCONFIRMED));
    test(!decide(0x2b, 0)); // Signal, exit path and a cleared table still need the actual CID-thread check.
    std::printf("policy cases passed: %u\n", count); return 0;
}
static std::vector<KSWORD_ARK_PROCESS_ENTRY> enumerate() {
    KSWORD_ARK_ENUM_PROCESS_REQUEST request{}; request.flags = KSWORD_ARK_ENUM_PROCESS_FLAG_SCAN_CID_TABLE;
    std::vector<unsigned char> buffer(8U * 1024U * 1024U);
    DWORD bytes = 0;
    require(DeviceIoControl(device, IOCTL_KSWORD_ARK_ENUM_PROCESS, &request, sizeof(request), buffer.data(), static_cast<DWORD>(buffer.size()), &bytes, nullptr) != FALSE, "enum ioctl");
    constexpr size_t header = offsetof(KSWORD_ARK_ENUM_PROCESS_RESPONSE, entries);
    require(bytes >= header, "enum header");
    const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_PROCESS_RESPONSE*>(buffer.data());
    require(response->version >= 4 && response->entrySize >= sizeof(KSWORD_ARK_PROCESS_ENTRY), "v4 driver required");
    require(response->returnedCount <= response->totalCount && header + size_t(response->returnedCount) * response->entrySize <= bytes, "complete returned rows required");
    const bool complete = response->returnedCount == response->totalCount;
    ++enumerationCalls; if (!complete) ++incompleteEnumerations;
    std::printf("{\"enumeration\":true,\"call\":%u,\"returned\":%lu,\"total\":%lu,\"complete\":%s}\n",
        enumerationCalls, response->returnedCount, response->totalCount, complete ? "true" : "false");
    std::vector<KSWORD_ARK_PROCESS_ENTRY> rows;
    for (size_t i = 0; i < response->returnedCount; ++i) {
        rows.push_back(*reinterpret_cast<const KSWORD_ARK_PROCESS_ENTRY*>(buffer.data() + header + i * response->entrySize));
    }
    return rows;
}
static std::set<DWORD> publicPids() {
    std::set<DWORD> ids; HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    require(snapshot != INVALID_HANDLE_VALUE, "public snapshot");
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) do { ids.insert(entry.th32ProcessID); } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot); return ids;
}
static void visibility(DWORD pid, ULONG action, ULONG flags) {
    KSWORD_ARK_SET_PROCESS_VISIBILITY_REQUEST request{}; request.processId = pid; request.action = action; request.flags = flags;
    KSWORD_ARK_SET_PROCESS_VISIBILITY_RESPONSE response{}; DWORD bytes = 0;
    require(DeviceIoControl(device, IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY, &request, sizeof(request), &response, sizeof(response), &bytes, nullptr) != FALSE, "visibility ioctl");
    require(bytes >= sizeof(response) && response.lastStatus == 0, "visibility result");
}
struct Child {
    PROCESS_INFORMATION process{};
    HANDLE done = nullptr;
    std::string kind;
    ULONG hidden = 0;
    bool suspended = false;
};
static Child child(const std::string& kind, unsigned index, DWORD exitCode = 0, bool suspend = false) {
    wchar_t path[MAX_PATH]{}; require(GetModuleFileNameW(nullptr, path, MAX_PATH) != 0, "self path");
    const auto event = L"Local\\KswordCidLab-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(index);
    Child result; result.kind = kind; result.suspended = suspend;
    result.done = CreateEventW(nullptr, TRUE, FALSE, event.c_str()); require(result.done != nullptr, "child event");
    std::wstring command = L"\"" + std::wstring(path) + L"\" --child " + std::to_wstring(exitCode) + L" " + event;
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    require(CreateProcessW(path, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW | (suspend ? CREATE_SUSPENDED : 0), nullptr, nullptr, &startup, &result.process) != FALSE, "create controlled child");
    return result;
}
struct Churn {
    std::atomic<bool> stop{false}, failed{false};
    std::atomic<unsigned> completed{0};
    std::thread worker;
    explicit Churn(bool enabled) {
        if (enabled) worker = std::thread([this] {
            unsigned serial = 10000;
            while (!stop.load()) {
                try {
                    auto target = child("churn", ++serial); SetEvent(target.done);
                    if (WaitForSingleObject(target.process.hProcess, 5000) != WAIT_OBJECT_0) { TerminateProcess(target.process.hProcess, 251); failed = true; }
                    CloseHandle(target.done); CloseHandle(target.process.hThread); CloseHandle(target.process.hProcess); ++completed;
                } catch (...) { failed = true; break; }
            }
        });
    }
    ~Churn() { stop = true; if (worker.joinable()) worker.join(); }
};
static std::string key(const KSWORD_ARK_PROCESS_ENTRY& row) { return std::to_string(row.processObjectAddress) + ":" + std::to_string(row.creationTime100ns); }
static void dump(const KSWORD_ARK_PROCESS_ENTRY& row, const char* kind, bool excluded, bool abnormal, int round) {
    std::printf("{\"round\":%d,\"kind\":\"%s\",\"pid\":%lu,\"pidField\":%lu,\"object\":\"%llx\",\"create\":%llu,\"exitTime\":%llu,\"flags\":%lu,\"proof\":%lu,\"threads\":%lu,\"wait\":%ld,\"excluded\":%s,\"abnormal\":%s}\n",
        round, kind, row.processId, row.observedProcessId, row.processObjectAddress, row.creationTime100ns, row.exitTime100ns, row.flags, row.exitEvidence, row.activeThreadCount, row.exitWaitStatus, excluded ? "true" : "false", abnormal ? "true" : "false");
}
int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--policy") return policyTests();
    if (argc >= 4 && std::string(argv[1]) == "--child") {
        HANDLE event = OpenEventA(SYNCHRONIZE, FALSE, argv[3]); if (!event) return 250;
        WaitForSingleObject(event, INFINITE); CloseHandle(event); return static_cast<int>(std::strtoul(argv[2], nullptr, 10));
    }
    std::vector<Child> children;
    try {
        device = CreateFileW(L"\\\\.\\KswordARKLog", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        require(device != INVALID_HANDLE_VALUE, "open driver");
        if (argc > 1 && std::string(argv[1]) == "--enum") {
            for (const auto& row : enumerate()) dump(row, "inventory", false, false, 0);
            CloseHandle(device); return 0;
        }
        if (argc > 1 && std::string(argv[1]) == "--audit") {
            unsigned normal = 0, excluded = 0, unexplained = 0;
            for (int round = 0; round < 20; ++round) {
                auto publicIds = publicPids();
                std::map<std::string, KSWORD_ARK_PROCESS_ENTRY> previous;
                for (const auto& row : enumerate()) previous[key(row)] = row;
                const auto rows = enumerate();
                const auto after = publicPids(); publicIds.insert(after.begin(), after.end());
                for (const auto& row : rows) {
                    const auto old = previous.find(key(row));
                    const bool residue = old != previous.end() && KswordArkProcessExitedResidual(row.exitEvidence, row.flags,
                        row.processObjectAddress, row.creationTime100ns, old->second.exitEvidence, old->second.flags,
                        old->second.processObjectAddress, old->second.creationTime100ns);
                    const bool anomalous = (row.flags & KSWORD_ARK_PROCESS_FLAG_PID_FIELD_MISMATCH) != 0 || publicIds.count(row.processId) == 0;
                    if (!anomalous) ++normal;
                    else if (residue) ++excluded;
                    else { ++unexplained; dump(row, "unexplained-system-candidate", false, true, round); }
                }
                Sleep(100);
            }
            std::printf("{\"systemAudit\":true,\"rounds\":20,\"normalObservations\":%u,\"excludedResidues\":%u,\"unexplainedCandidates\":%u}\n", normal, excluded, unexplained);
            CloseHandle(device); return unexplained ? 2 : 0;
        }
        requireVm();
        if (argc > 1 && std::string(argv[1]) == "--destructive-cid-removal") {
            require(GetEnvironmentVariableW(L"KSWORD_CID_VM_DESTRUCTIVE", nullptr, 0) != 0, "separate destructive-test opt-in required");
            children.push_back(child("pid-cid-removed", 1)); auto& target = children.back(); Sleep(200);
            visibility(target.process.dwProcessId, KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE, 2); target.hidden = 2;
            KSWORD_ARK_DKOM_PROCESS_REQUEST request{}; request.version = 4; request.processId = target.process.dwProcessId; request.action = KSWORD_ARK_PROCESS_DKOM_ACTION_REMOVE_FROM_PSP_CID_TABLE;
            KSWORD_ARK_DKOM_PROCESS_RESPONSE result{}; DWORD bytes = 0;
            require(DeviceIoControl(device, IOCTL_KSWORD_ARK_DKOM_PROCESS, &request, sizeof(request), &result, sizeof(result), &bytes, nullptr) != FALSE, "remove controlled PID CID");
            std::printf("{\"cidRemoval\":true,\"pid\":%lu,\"status\":%lu,\"lastStatus\":%ld,\"removed\":%lu}\n", request.processId, result.status, result.lastStatus, result.removedEntries); std::fflush(stdout);
            require(result.lastStatus == 0 && result.removedEntries != 0, "PID CID removal completed");
            for (int round = 0; round < 12; ++round) {
                const auto rows = enumerate(); const auto row = std::find_if(rows.begin(), rows.end(), [&](const auto& r) { return r.processId == target.process.dwProcessId; });
                require(row != rows.end() && (row->flags & KSWORD_ARK_PROCESS_FLAG_THREAD_OWNER_ENUMERATED) != 0, "thread CID recovers removed PID CID");
                require((row->flags & KSWORD_ARK_PROCESS_FLAG_CID_TABLE_ENUMERATED) == 0, "do not fabricate a process CID source");
                dump(*row, "pid-cid-removed", false, true, round); std::fflush(stdout); FlushFileBuffers(GetStdHandle(STD_OUTPUT_HANDLE)); Sleep(100);
            }
            std::printf("{\"cidRemovalDetectionSummary\":true,\"detections\":12,\"falseNegative\":0,\"aboutToExitRemovedCidChild\":true}\n");
            std::fflush(stdout); FlushFileBuffers(GetStdHandle(STD_OUTPUT_HANDLE)); // Direct cmd redirection makes the evidence durable before the intentionally destructive cleanup.
            visibility(target.process.dwProcessId, KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE, 0); target.hidden = 0;
            SetEvent(target.done); require(WaitForSingleObject(target.process.hProcess, 5000) == WAIT_OBJECT_0, "removed-CID child exit");
            CloseHandle(target.done); CloseHandle(target.process.hThread); CloseHandle(target.process.hProcess); children.clear();
            std::printf("{\"cidRemovalSummary\":true,\"detections\":12,\"falseNegative\":0,\"cleanupExit\":true}\n"); CloseHandle(device); return 0;
        }
        children.reserve(80);
        unsigned serial = 0;
        for (int i = 0; i < 6; ++i) children.push_back(child("normal", ++serial));
        for (int i = 0; i < 4; ++i) children.push_back(child("suspended", ++serial, 0, true));
        for (int i = 0; i < 4; ++i) children.push_back(child("r3-filtered", ++serial));
        for (int i = 0; i < 16; ++i) children.push_back(child("exited0", ++serial));
        for (int i = 0; i < 16; ++i) children.push_back(child("exited259", ++serial, 259));
        for (const auto mode : {1UL, 2UL, 3UL}) for (int i = 0; i < 4; ++i) {
            children.push_back(child("hidden" + std::to_string(mode), ++serial));
        }
        for (const auto mode : {1UL, 2UL, 3UL}) for (int i = 0; i < 2; ++i) {
            children.push_back(child("hidden" + std::to_string(mode), ++serial, 0, true));
        }
        Sleep(300); // Child initialization is observed before applying a hidden state.
        for (auto& target : children) {
            if (target.kind.rfind("exited", 0) == 0) {
                require(SetEvent(target.done) != FALSE, "request ordinary exit");
                require(WaitForSingleObject(target.process.hProcess, 5000) == WAIT_OBJECT_0, "ordinary exit completed");
            }
            if (target.kind.rfind("hidden", 0) == 0) {
                target.hidden = static_cast<ULONG>(std::strtoul(target.kind.c_str() + 6, nullptr, 10));
                visibility(target.process.dwProcessId, KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE, target.hidden);
            }
        }
        Churn churn(argc > 1 && std::string(argv[1]) == "--stress");
        std::map<std::string, KSWORD_ARK_PROCESS_ENTRY> previous;
        for (const auto& row : enumerate()) previous[key(row)] = row; // Cold-start confirmation uses two collections before first presentation, like the GUI worker.
        unsigned falsePositive = 0, falseNegative = 0, residueVisible = 0, detections = 0, decisions = 0, deadObserved = 0, forgedSignalChecks = 0;
        for (int round = 0; round < 8; ++round) {
            auto r3 = publicPids(); const auto rows = enumerate();
            for (const auto& target : children) if (target.kind == "r3-filtered") r3.erase(target.process.dwProcessId); // Consumer-level source omission, without changing the active list.
            std::map<std::string, KSWORD_ARK_PROCESS_ENTRY> next;
            for (const auto& row : rows) next[key(row)] = row;
            for (const auto& target : children) {
                const auto found = std::find_if(rows.begin(), rows.end(), [&](const auto& row) { return row.processId == target.process.dwProcessId; });
                bool excluded = false, abnormal = false;
                if (found != rows.end()) {
                    const auto old = previous.find(key(*found));
                    excluded = old != previous.end() && KswordArkProcessExitedResidual(found->exitEvidence, found->flags, found->processObjectAddress, found->creationTime100ns,
                        old->second.exitEvidence, old->second.flags, old->second.processObjectAddress, old->second.creationTime100ns);
                    abnormal = !excluded && (r3.count(found->processId) == 0 || (found->flags & KSWORD_ARK_PROCESS_FLAG_PID_FIELD_MISMATCH) != 0);
                    dump(*found, target.kind.c_str(), excluded, abnormal, round);
                    if (target.kind.rfind("exited", 0) != 0) {
                        const auto forged = found->exitEvidence | KSWORD_ARK_PROCESS_EXIT_REFERENCE | KSWORD_ARK_PROCESS_EXIT_SIGNALED | KSWORD_ARK_PROCESS_EXIT_CALLED;
                        require(!KswordArkProcessExitedResidual(forged, found->flags, found->processObjectAddress, found->creationTime100ns,
                            forged, found->flags, found->processObjectAddress, found->creationTime100ns), "actual unfinished CID threads veto consumer-forged process signals");
                        ++forgedSignalChecks;
                    }
                } else std::printf("{\"round\":%d,\"kind\":\"%s\",\"pid\":%lu,\"missing\":true}\n", round, target.kind.c_str(), target.process.dwProcessId);
                {
                    ++decisions;
                    if (target.kind.rfind("hidden", 0) == 0 || target.kind == "r3-filtered") {
                        if (found == rows.end() || !abnormal) ++falseNegative; else ++detections;
                    } else if (target.kind.rfind("exited", 0) == 0) {
                        if (found != rows.end()) ++deadObserved;
                        if (found != rows.end() && !excluded) { ++falsePositive; ++residueVisible; }
                    } else if (found == rows.end() || excluded || abnormal) ++falsePositive;
                }
            }
            previous.swap(next); Sleep(100);
        }
        for (auto& target : children) if (target.hidden) { visibility(target.process.dwProcessId, KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE, 0); target.hidden = 0; }
        const auto restoredRows = enumerate(); const auto restoredPublic = publicPids(); unsigned restored = 0;
        for (const auto& target : children) if (target.kind.rfind("hidden", 0) == 0) {
            const auto found = std::find_if(restoredRows.begin(), restoredRows.end(), [&](const auto& row) { return row.processId == target.process.dwProcessId; });
            if (found == restoredRows.end() || restoredPublic.count(target.process.dwProcessId) == 0 || (found->flags & KSWORD_ARK_PROCESS_FLAG_PID_FIELD_MISMATCH) != 0) ++falsePositive;
            else ++restored;
        }
        std::printf("{\"restoration\":true,\"normalAgain\":%u}\n", restored);
        require(!churn.failed.load(), "background churn completed normally");
        std::printf("{\"churn\":true,\"completed\":%u}\n", churn.completed.load());
        std::printf("{\"consumerForgedSignalChecks\":%u}\n", forgedSignalChecks);
        std::printf("{\"summary\":true,\"targets\":%zu,\"decisionsAfterFirstObservation\":%u,\"hiddenDetections\":%u,\"deadObjectsObserved\":%u,\"falsePositive\":%u,\"falseNegative\":%u,\"residueVisible\":%u,\"incompleteEnumerations\":%u}\n",
            children.size(), decisions, detections, deadObserved, falsePositive, falseNegative, residueVisible, incompleteEnumerations);
        for (auto& target : children) {
            if (target.hidden) { visibility(target.process.dwProcessId, KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE, 0); target.hidden = 0; }
            if (target.suspended) { ResumeThread(target.process.hThread); target.suspended = false; }
            SetEvent(target.done); WaitForSingleObject(target.process.hProcess, 5000);
            CloseHandle(target.done); CloseHandle(target.process.hThread); CloseHandle(target.process.hProcess);
        }
        children.clear(); CloseHandle(device);
        return falsePositive || falseNegative ? 2 : 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        for (auto& target : children) {
            if (target.hidden) { try { visibility(target.process.dwProcessId, KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE, 0); } catch (...) {} }
            if (target.suspended) ResumeThread(target.process.hThread);
            SetEvent(target.done); if (WaitForSingleObject(target.process.hProcess, 5000) != WAIT_OBJECT_0) TerminateProcess(target.process.hProcess, 251);
            CloseHandle(target.done); CloseHandle(target.process.hThread); CloseHandle(target.process.hProcess);
        }
        if (device != INVALID_HANDLE_VALUE) CloseHandle(device);
        return 1;
    }
}
