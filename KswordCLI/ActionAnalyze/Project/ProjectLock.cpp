#include "ProjectLock.h"

namespace Ksword::ActionAnalyze {
using namespace ProjectStorage;

namespace {

ProjectResult LockByte(const Handle& handle, bool exclusive) {
    // byte 0 的系统锁随所有者退出释放。锁文件本身长期保留。
    OVERLAPPED offset{};
    if (LockFileEx(handle.get(), LOCKFILE_FAIL_IMMEDIATELY | (exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0),
                   0, 1, 0, &offset)) {
        return {};
    }
    const DWORD error = GetLastError();
    return error == ERROR_LOCK_VIOLATION
        ? Failure(ProjectError::WriterBusy, exclusive ? "writerLock" : "maintenanceLock", error)
        : WinFailure(exclusive ? "writerLock" : "maintenanceLock", error);
}

} // namespace

ProjectResult ProjectLock::AcquireWriter(const Directory& root, bool create) {
    Directory locks;
    if (auto result = OpenDirectory(root, {L".locks"}, locks); !result) return result;
    constexpr DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    if (create) {
        Handle maintenance;
        if (auto result = OpenFile(locks, L"maintenance.lock", GENERIC_READ | GENERIC_WRITE,
                                   share, CREATE_NEW, maintenance); !result) return result;
    }
    Handle writer;
    if (auto result = OpenFile(locks, L"writer.lock", GENERIC_READ | GENERIC_WRITE,
                               share, create ? CREATE_NEW : OPEN_EXISTING, writer); !result) return result;
    if (auto result = LockByte(writer, true); !result) return result;
    writer_ = std::move(writer);
    return {};
}

ProjectResult ProjectLock::AcquireReader(const Directory& root) {
    Directory locks;
    if (auto result = OpenDirectory(root, {L".locks"}, locks); !result) {
        return result.error == ProjectError::NotFound ? ProjectResult{} : result;
    }
    Handle reader;
    if (auto result = OpenFile(locks, L"maintenance.lock", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, reader); !result) {
        return result.error == ProjectError::NotFound ? ProjectResult{} : result;
    }
    if (auto result = LockByte(reader, false); !result) return result;
    reader_ = std::move(reader);
    return {};
}

} // namespace Ksword::ActionAnalyze
