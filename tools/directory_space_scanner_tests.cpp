#include "DirectorySpaceScanner.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include <Windows.h>
#include <winioctl.h>

#include <cstdio>
#include <cstring>
#include <vector>

namespace {
int checks = 0, failures = 0;
void check(bool value, const char* name)
{
    ++checks;
    if (!value) { ++failures; std::fprintf(stderr, "FAIL: %s\n", name); }
}
void write(const QString& path, const QByteArray& data)
{
    QFile file(path);
    check(file.open(QIODevice::WriteOnly), "create fixture file");
    check(file.write(data) == data.size(), "write fixture file");
}
bool junction(const QString& link, const QString& target)
{
    if (!QDir().mkdir(link)) return false;
    const QString native = QDir::toNativeSeparators(link);
    HANDLE handle = CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()), GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    struct MountPoint {
        DWORD tag;
        WORD dataLength, reserved;
        WORD substituteOffset, substituteLength, printOffset, printLength;
    } header{};
    const QString substitute = QStringLiteral("\\??\\") + QDir::toNativeSeparators(target);
    const QString print = QDir::toNativeSeparators(target);
    header.tag = IO_REPARSE_TAG_MOUNT_POINT;
    header.substituteLength = WORD(substitute.size() * sizeof(wchar_t));
    header.printOffset = header.substituteLength + sizeof(wchar_t);
    header.printLength = WORD(print.size() * sizeof(wchar_t));
    const size_t pathBytes = size_t(header.printOffset) + header.printLength + sizeof(wchar_t);
    header.dataLength = WORD(8 + pathBytes);
    std::vector<unsigned char> buffer(sizeof(header) + pathBytes, 0);
    std::memcpy(buffer.data(), &header, sizeof(header));
    std::memcpy(buffer.data() + sizeof(header), substitute.utf16(), header.substituteLength);
    std::memcpy(buffer.data() + sizeof(header) + header.printOffset, print.utf16(), header.printLength);
    DWORD returned = 0;
    const bool ok = DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, buffer.data(), DWORD(buffer.size()),
        nullptr, 0, &returned, nullptr) != FALSE;
    CloseHandle(handle);
    return ok;
}
} // namespace

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir selected;
    QTemporaryDir outside;
    check(selected.isValid() && outside.isValid(), "temporary scopes");
    if (!selected.isValid() || !outside.isValid()) return 1;
    const QString root = selected.path();
    check(QDir().mkpath(root + QStringLiteral("/nested/empty")), "nested directories");
    write(root + QStringLiteral("/visible.bin"), QByteArray(7301, 'a'));
    write(root + QStringLiteral("/nested/hidden.txt"), QByteArray(51, 'b'));
    write(outside.path() + QStringLiteral("/outside.bin"), QByteArray(999999, 'x'));
    const QString hidden = QDir::toNativeSeparators(root + QStringLiteral("/nested/hidden.txt"));
    check(SetFileAttributesW(reinterpret_cast<LPCWSTR>(hidden.utf16()), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM), "hidden system fixture");
    const QString original = QDir::toNativeSeparators(root + QStringLiteral("/visible.bin"));
    const QString alias = QDir::toNativeSeparators(root + QStringLiteral("/nested/alias.bin"));
    check(CreateHardLinkW(reinterpret_cast<LPCWSTR>(alias.utf16()), reinterpret_cast<LPCWSTR>(original.utf16()), nullptr), "hardlink fixture");
    const QString link = root + QStringLiteral("/outside-junction");
    check(junction(link, outside.path()), "junction fixture");
    quint64 lastProgress = 0;
    auto scanned = ks::files::DirectorySpaceScanner::scan(root, {}, [&](quint64 processed, quint64) { lastProgress = processed; });
    check(bool(scanned.snapshot) && scanned.error.isEmpty(), "normal scan");
    if (scanned.snapshot) {
        const auto& snapshot = *scanned.snapshot;
        check(snapshot.complete && snapshot.rootReference != 0, "committed snapshot");
        check(snapshot.volumeRoot == QDir::toNativeSeparators(root) + QStringLiteral("\\"), "selected root preserved");
        quint64 logical = 0, files = 0, aliases = 0;
        for (const auto& entry : snapshot.entries) {
            if (entry.isDirectory()) continue;
            ++files; logical += entry.logicalBytes; aliases += quint64(entry.names.size());
            check(entry.name != QStringLiteral("outside.bin"), "no escape through junction");
            check(entry.sizeKnown && entry.allocatedBytes >= entry.logicalBytes, "real size metadata");
        }
        check(files == 2 && logical == 7352, "nested hidden files and single hardlink accounting");
        check(aliases == 3 && scanned.duplicateFiles == 1, "hardlink alias preserved");
        check(scanned.skippedReparsePoints == 1, "junction explicitly reported");
        check(scanned.skippedDirectories == 0 && snapshot.unknownSizeCount == 0, "no silent unknown paths");
        check(lastProgress > 0, "progress delivered");
    }
    auto cancel = std::make_shared<std::atomic_bool>(true);
    check(!ks::files::DirectorySpaceScanner::scan(root, cancel).snapshot, "pre-canceled has no partial snapshot");
    cancel->store(false);
    auto canceled = ks::files::DirectorySpaceScanner::scan(root, cancel, [cancel](quint64, quint64) { cancel->store(true); });
    check(!canceled.snapshot && canceled.error.isEmpty(), "mid-scan canceled has no partial snapshot");
    const auto missing = ks::files::DirectorySpaceScanner::scan(root + QStringLiteral("/missing"));
    check(!missing.snapshot && !missing.error.isEmpty(), "missing folder explicit failure");
    const auto file = ks::files::DirectorySpaceScanner::scan(root + QStringLiteral("/visible.bin"));
    check(!file.snapshot && !file.error.isEmpty(), "file root rejected");
    const auto reparse = ks::files::DirectorySpaceScanner::scan(link);
    check(!reparse.snapshot && !reparse.error.isEmpty(), "reparse root rejected");
    const auto relative = ks::files::DirectorySpaceScanner::scan(QStringLiteral("relative"));
    check(!relative.snapshot && !relative.error.isEmpty(), "relative path rejected");
    QTemporaryDir sparseScope;
    const QString sparsePath = QDir::toNativeSeparators(sparseScope.path() + QStringLiteral("/sparse.bin"));
    HANDLE sparse = CreateFileW(reinterpret_cast<LPCWSTR>(sparsePath.utf16()), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    check(sparseScope.isValid() && sparse != INVALID_HANDLE_VALUE, "sparse file created");
    if (sparse != INVALID_HANDLE_VALUE) {
        DWORD returned = 0;
        check(DeviceIoControl(sparse, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned, nullptr), "sparse attribute");
        LARGE_INTEGER end{}; end.QuadPart = 1024 * 1024;
        check(SetFilePointerEx(sparse, end, nullptr, FILE_BEGIN) && SetEndOfFile(sparse), "sparse logical length");
        CloseHandle(sparse);
        const auto sparseResult = ks::files::DirectorySpaceScanner::scan(sparseScope.path());
        bool measuredSparse = false;
        if (sparseResult.snapshot) for (const auto& entry : sparseResult.snapshot->entries)
            if (!entry.isDirectory()) measuredSparse = entry.sizeKnown && entry.logicalBytes == 1024 * 1024 && entry.allocatedBytes == 0;
        check(measuredSparse, "sparse logical and actual allocation stay distinct");
    }
    // The callback attempts an ancestor rename after its Find enumeration has
    // closed and traversal has entered a descendant. A scanner retaining only
    // the current directory handle would let the ancestor become a junction.
    QTemporaryDir raceScope;
    const QString raceRoot = raceScope.path();
    check(raceScope.isValid() && QDir().mkpath(raceRoot + QStringLiteral("/parent/child/grandchild")), "race subtree");
    for (int i = 0; i < 130; ++i)
        write(raceRoot + QStringLiteral("/parent/child/file-%1.bin").arg(i), QByteArray(1, 'r'));
    const QString raceParent = QDir::toNativeSeparators(raceRoot + QStringLiteral("/parent"));
    const QString raceMoved = QDir::toNativeSeparators(raceRoot + QStringLiteral("/moved"));
    bool attempted = false, moved = false;
    auto raced = ks::files::DirectorySpaceScanner::scan(raceRoot, {}, [&](quint64 processed, quint64 total) {
        if (attempted || processed < 128 || total != 0) return;
        attempted = true;
        moved = MoveFileExW(reinterpret_cast<LPCWSTR>(raceParent.utf16()), reinterpret_cast<LPCWSTR>(raceMoved.utf16()), 0) != FALSE;
        if (moved) junction(raceParent, outside.path());
    });
    check(attempted && !moved, "closed-enumeration ancestor remains locked");
    check(bool(raced.snapshot), "race scan remains usable");
    if (raced.snapshot) {
        for (const auto& entry : raced.snapshot->entries)
            check(entry.name != QStringLiteral("outside.bin"), "ancestor replacement cannot escape scope");
    }
    if (moved) RemoveDirectoryW(reinterpret_cast<LPCWSTR>(raceParent.utf16()));
    // Remove only the junction itself before QTemporaryDir cleanup.
    const QString nativeLink = QDir::toNativeSeparators(link);
    check(RemoveDirectoryW(reinterpret_cast<LPCWSTR>(nativeLink.utf16())), "junction removed without following");
    SetFileAttributesW(reinterpret_cast<LPCWSTR>(hidden.utf16()), FILE_ATTRIBUTE_NORMAL);
    std::printf("DIRECTORY_SPACE_SCANNER_CHECKS=%d FAILURES=%d\n", checks, failures);
    return failures ? 1 : 0;
}
