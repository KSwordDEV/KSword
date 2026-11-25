#include "PassiveThreadObservation.h"

#include "../../../shared/usermode/backend/Common.h"

#include <tlhelp32.h>

#include <map>
#include <utility>

namespace ks::cli::action_analyze::memory {
namespace {

using r3::common::UniqueHandle;
constexpr std::size_t kMaxThreads = 64; // 每轮最多核对这么多线程句柄。

std::uint64_t FileTimeValue(const FILETIME& value)
{
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

std::uint64_t UtcNow100ns()
{
    FILETIME value{};
    GetSystemTimePreciseAsFileTime(&value);
    return FileTimeValue(value);
}

DWORD CheckRunning(HANDLE handle)
{
    const DWORD wait = WaitForSingleObject(handle, 0);
    if (wait == WAIT_TIMEOUT) return ERROR_SUCCESS;
    if (wait == WAIT_OBJECT_0) return ERROR_PROCESS_ABORTED;
    return wait == WAIT_FAILED ? GetLastError() : ERROR_INVALID_DATA;
}

struct ThreadIdentity {
    UniqueHandle handle; // 同一对象的句柄保留至下一轮，用于确认退出，不按 TID 重开。
    std::uint64_t creation = 0;
    DWORD error = ERROR_SUCCESS; // 无法确认线程身份或存活状态时才设置。
    bool exited = false;
};

struct ThreadSnapshot {
    std::map<DWORD, ThreadIdentity> rows;
    std::uint64_t start = 0, end = 0;
    DWORD targetError = ERROR_SUCCESS;
    DWORD snapshotError = ERROR_SUCCESS;
    bool limited = false;

    bool complete() const { return !targetError && !snapshotError && !limited; }
};

ThreadIdentity QueryThreadIdentity(DWORD tid, DWORD pid, std::uint64_t snapshotEnd)
{
    ThreadIdentity result;
    UniqueHandle thread(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, tid));
    if (!thread.valid()) {
        result.error = GetLastError();
        return result;
    }
    const DWORD owner = GetProcessIdOfThread(thread.get());
    if (owner != pid) {
        result.error = owner ? ERROR_INVALID_DATA : GetLastError();
        return result;
    }
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetThreadTimes(thread.get(), &creation, &exit, &kernel, &user)) {
        result.error = GetLastError();
        return result;
    }
    const auto observed = FileTimeValue(creation);
    if (!observed || observed > snapshotEnd) {
        // 快照返回后才创建的同 TID 对象不属于这次枚举。
        result.error = ERROR_INVALID_DATA;
        return result;
    }
    result.creation = observed;
    const DWORD wait = WaitForSingleObject(thread.get(), 0);
    result.exited = wait == WAIT_OBJECT_0;
    if (wait != WAIT_OBJECT_0 && wait != WAIT_TIMEOUT) {
        result.error = wait == WAIT_FAILED ? GetLastError() : ERROR_INVALID_DATA;
    }
    result.handle = std::move(thread);
    return result;
}

// Toolhelp 只按 PID 给候选；只接受同一已验证进程句柄在采集前后均未退出的结果。
ThreadSnapshot TakeThreadSnapshot(HANDLE target, DWORD pid)
{
    ThreadSnapshot result;
    result.targetError = CheckRunning(target);
    if (result.targetError) return result;

    result.start = UtcNow100ns();
    const UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    const DWORD openError = snapshot.valid() ? ERROR_SUCCESS : GetLastError();
    result.end = UtcNow100ns();
    if (openError) {
        result.snapshotError = openError;
    } else {
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        BOOL more = Thread32First(snapshot.get(), &entry);
        while (more) {
            if (entry.dwSize < offsetof(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD)) {
                result.snapshotError = ERROR_INVALID_DATA;
                break;
            }
            if (entry.th32OwnerProcessID == pid) {
                if (result.rows.size() == kMaxThreads) {
                    result.limited = true;
                    break;
                }
                if (!result.rows.try_emplace(entry.th32ThreadID).second) {
                    result.snapshotError = ERROR_INVALID_DATA;
                    break;
                }
            }
            entry.dwSize = sizeof(THREADENTRY32);
            more = Thread32Next(snapshot.get(), &entry);
        }
        if (!more) {
            const DWORD enumerationError = GetLastError();
            if (enumerationError != ERROR_NO_MORE_FILES) result.snapshotError = enumerationError;
        }
        if (!result.snapshotError) {
            for (auto& [tid, thread] : result.rows) thread = QueryThreadIdentity(tid, pid, result.end);
        }
    }
    result.targetError = CheckRunning(target);
    if (result.targetError || result.snapshotError) result.rows.clear();
    return result;
}

// 比较本轮与前次线程列表，生成只读回执；同时在旧句柄上记住已确认的退出，防止失败轮重复报告。
ThreadObservation DescribeThreads(ThreadSnapshot* previous, const ThreadSnapshot& current)
{
    ThreadObservation result;
    auto& events = result.events;
    if (previous) {
        for (auto& [tid, prior] : previous->rows) {
            if (!prior.creation || prior.exited) continue;
            const auto now = current.rows.find(tid);
            const bool same = now != current.rows.end() && now->second.creation == prior.creation;
            if (same && !now->second.error && !now->second.exited) continue;

            // 枚举缺失或 TID 重用只触发复查；只有原句柄变为有信号才确认退出。
            const DWORD wait = WaitForSingleObject(prior.handle.get(), 0);
            if (wait == WAIT_OBJECT_0) {
                prior.exited = true;
                events.push_back({tid, prior.creation, ThreadEventStatus::Exited});
            } else {
                events.push_back({tid, prior.creation, ThreadEventStatus::Unknown,
                    wait == WAIT_FAILED ? GetLastError() : same ? now->second.error : ERROR_SUCCESS});
            }
        }
    }
    for (const auto& [tid, row] : current.rows) {
        const auto prior = previous ? previous->rows.find(tid) : current.rows.end();
        const bool previouslyListed = previous && prior != previous->rows.end();
        const bool same = previouslyListed && row.creation && prior->second.creation == row.creation;
        if (same) continue; // 已由上面的原对象复查覆盖，或已经报告退出。
        if (row.error) {
            events.push_back({tid, row.creation, ThreadEventStatus::Unknown, row.error});
        } else if (row.exited) {
            events.push_back({tid, row.creation, ThreadEventStatus::Exited});
        } else {
            // 创建时间早于前一轮的线程即使刚出现在列表里，也不能报告为新线程。
            const bool isNew = previous && previous->complete() && row.creation >= previous->start &&
                (!previouslyListed || prior->second.creation);
            events.push_back({tid, row.creation, isNew ? ThreadEventStatus::NewlyObserved : ThreadEventStatus::Observed});
        }
    }
    result.status = current.targetError == ERROR_PROCESS_ABORTED ? ThreadSnapshotStatus::TargetExited :
        current.targetError || current.snapshotError ? ThreadSnapshotStatus::Unknown :
        current.limited ? ThreadSnapshotStatus::Limited : ThreadSnapshotStatus::Complete;
    result.win32Error = current.targetError ? current.targetError : current.snapshotError;
    result.snapshotStartUtc100ns = current.start;
    result.snapshotEndUtc100ns = current.end;
    result.readbackEndUtc100ns = UtcNow100ns();
    if (!current.targetError && !current.snapshotError) result.listedThreadCount = current.rows.size();
    return result;
}

} // namespace

class PassiveThreadObservation::Impl {
public:
    Impl(HANDLE process, DWORD pid) : process_(process), pid_(pid) {}

    ThreadObservation Observe()
    {
        auto current = TakeThreadSnapshot(process_, pid_);
        auto result = DescribeThreads(previous_ ? &*previous_ : nullptr, current);
        if (previous_ && !current.targetError && current.snapshotError) {
            // 枚举失败时沿用原句柄；本轮仍为失败，不能当作判断新线程的完整基准。
            current.rows = std::move(previous_->rows);
        }
        previous_ = std::move(current);
        return result;
    }

private:
    const HANDLE process_;
    const DWORD pid_;
    std::optional<ThreadSnapshot> previous_;
};

PassiveThreadObservation::PassiveThreadObservation(HANDLE verifiedProcess, DWORD pid)
    : impl_(std::make_unique<Impl>(verifiedProcess, pid)) {}

PassiveThreadObservation::~PassiveThreadObservation() = default;

ThreadObservation PassiveThreadObservation::Observe()
{
    return impl_->Observe();
}

} // namespace ks::cli::action_analyze::memory
