#include "DirectorySpaceScanner.h"

#include <QByteArray>
#include <QDir>
#include <QVector>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace ks::files {
namespace {
bool canceled(const NtfsFastIndex::Cancel& token)
{
    return token && token->load(std::memory_order_relaxed);
}

#ifdef Q_OS_WIN
class FileHandle final {
public:
    explicit FileHandle(HANDLE value) : m_value(value) {}
    ~FileHandle() { if (valid()) CloseHandle(m_value); }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    bool valid() const { return m_value != INVALID_HANDLE_VALUE; }
    HANDLE get() const { return m_value; }
private:
    HANDLE m_value;
};

QString nativePath(const QString& path)
{
    // Extended paths preserve long directory/file names. The displayed root
    // remains an ordinary absolute path for FileDock navigation.
    return path.startsWith(QStringLiteral("\\\\"))
        ? QStringLiteral("\\\\?\\UNC\\") + path.mid(2)
        : QStringLiteral("\\\\?\\") + path;
}

QString childPath(const QString& parent, const QString& name)
{
    return parent + (parent.endsWith(QLatin1Char('\\')) ? QString() : QStringLiteral("\\")) + name;
}

bool recallOrReparse(DWORD attributes)
{
    // Recall flags are checked numerically for compatibility with older SDKs.
    constexpr DWORD recallOnOpen = 0x00040000U;
    constexpr DWORD recallOnDataAccess = 0x00400000U;
    return (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE
        | recallOnOpen | recallOnDataAccess)) != 0;
}

FileHandle metadataHandle(const QString& path, bool directory)
{
    const QString native = nativePath(path);
    // Directory locks also deny reparse-point writes while descendants use
    // their paths. Ordinary file reads/writes retain normal shared access.
    const DWORD sharing = directory ? FILE_SHARE_READ
        : FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    return FileHandle(CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()),
        FILE_READ_ATTRIBUTES, sharing, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
}

QByteArray fileIdentity(HANDLE handle)
{
    FILE_ID_INFO identity{};
    if (GetFileInformationByHandleEx(handle, FileIdInfo, &identity, sizeof(identity))) {
        QByteArray key("I", 1);
        key.append(reinterpret_cast<const char*>(&identity.VolumeSerialNumber), sizeof(identity.VolumeSerialNumber));
        key.append(reinterpret_cast<const char*>(identity.FileId.Identifier), sizeof(identity.FileId.Identifier));
        return key;
    }
    BY_HANDLE_FILE_INFORMATION legacy{};
    if (!GetFileInformationByHandle(handle, &legacy)) return {};
    QByteArray key("L", 1);
    key.append(reinterpret_cast<const char*>(&legacy.dwVolumeSerialNumber), sizeof(legacy.dwVolumeSerialNumber));
    key.append(reinterpret_cast<const char*>(&legacy.nFileIndexHigh), sizeof(legacy.nFileIndexHigh));
    key.append(reinterpret_cast<const char*>(&legacy.nFileIndexLow), sizeof(legacy.nFileIndexLow));
    return key;
}

bool readAttributes(HANDLE handle, DWORD& attributes)
{
    FILE_ATTRIBUTE_TAG_INFO tagged{};
    if (GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tagged, sizeof(tagged))) {
        attributes = tagged.FileAttributes;
        return true;
    }
    BY_HANDLE_FILE_INFORMATION basic{};
    if (!GetFileInformationByHandle(handle, &basic)) return false;
    attributes = basic.dwFileAttributes;
    return true;
}

QString failure(const QString& path, DWORD error)
{
    return QStringLiteral("无法读取扫描目录：%1（Windows 错误 %2）。").arg(path).arg(error);
}
#endif
} // namespace

DirectorySpaceScanner::Result DirectorySpaceScanner::scan(const QString& requestedRoot,
    const NtfsFastIndex::Cancel& cancel, const NtfsFastIndex::Progress& progress)
{
    Result result;
    if (canceled(cancel)) return result;
#ifdef Q_OS_WIN
    QString root = QDir::cleanPath(QDir::fromNativeSeparators(requestedRoot.trimmed()));
    if (!QDir::isAbsolutePath(root) || root.startsWith(QStringLiteral("//?/"))
        || root.startsWith(QStringLiteral("//./"))) {
        result.error = QStringLiteral("请选择有效的绝对文件夹路径。");
        return result;
    }
    root = QDir::toNativeSeparators(root);
    if (!root.endsWith(QLatin1Char('\\'))) root += QLatin1Char('\\');
    // Suppress removable/network media error dialogs on this worker only.
    struct ErrorMode {
        DWORD previous = 0;
        bool changed = SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX, &previous) != FALSE;
        ~ErrorMode() { if (changed) SetThreadErrorMode(previous, nullptr); }
    } errorMode;
    // Strip the final separator when opening a folder, except a drive root.
    const QString rootForOpen = root.size() > 3 ? root.left(root.size() - 1) : root;
    auto rootHandle = metadataHandle(rootForOpen, true);
    if (!rootHandle.valid()) {
        result.error = failure(root, GetLastError());
        return result;
    }
    DWORD rootAttributes = 0;
    if (!readAttributes(rootHandle.get(), rootAttributes)) {
        result.error = failure(root, GetLastError());
        return result;
    }
    if (!(rootAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        result.error = QStringLiteral("扫描路径不是文件夹。");
        return result;
    }
    if (recallOrReparse(rootAttributes)) {
        result.error = QStringLiteral("所选目录是重解析点或脱机目录，请选择实际的本地文件夹。");
        return result;
    }

    auto snapshot = std::make_shared<NtfsIndexSnapshot>();
    snapshot->volumeRoot = root;
    snapshot->rootReference = 1;
    NtfsIndexEntry rootEntry;
    rootEntry.fileReference = 1;
    rootEntry.parentReference = 1;
    rootEntry.name = root;
    rootEntry.attributes = FILE_ATTRIBUTE_DIRECTORY;
    snapshot->entries.insert(1, rootEntry);
    struct DirectoryLock {
        FileHandle handle;
        std::shared_ptr<DirectoryLock> parent;
        DirectoryLock(const QString& path, std::shared_ptr<DirectoryLock> ancestor)
            : handle(metadataHandle(path, true)), parent(std::move(ancestor)) {}
    };
    struct Directory {
        QString path;
        quint64 id;
        int depth;
        std::shared_ptr<DirectoryLock> parent;
    };
    QVector<Directory> pending{{root, 1, 0, {}}};
    QHash<QByteArray, quint64> files;
    quint64 nextId = 2, processed = 0;

    while (!pending.isEmpty()) {
        if (canceled(cancel)) return result;
        const Directory directory = pending.takeLast();
        // A child retains its complete chain of ancestor locks. Closing a
        // parent's Find handle therefore cannot permit that parent to become
        // an intermediate junction before pending descendants are opened.
        // LIFO traversal shares these chains and bounds handles by tree depth.
        auto lock = std::make_shared<DirectoryLock>(directory.path.size() > 3 && directory.path.endsWith(QLatin1Char('\\'))
            ? directory.path.left(directory.path.size() - 1) : directory.path, directory.parent);
        if (!lock->handle.valid()) {
            if (directory.id == 1) { result.error = failure(root, GetLastError()); return result; }
            ++result.skippedDirectories;
            continue;
        }
        DWORD attributes = 0;
        if (!readAttributes(lock->handle.get(), attributes)
            || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            ++result.skippedDirectories;
            continue;
        }
        if (recallOrReparse(attributes)) { ++result.skippedReparsePoints; continue; }
        const QString pattern = nativePath(childPath(directory.path, QStringLiteral("*")));
        WIN32_FIND_DATAW data{};
        HANDLE enumeration = FindFirstFileExW(reinterpret_cast<LPCWSTR>(pattern.utf16()),
            FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (enumeration == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_NO_MORE_FILES) continue; // Truly empty.
            if (directory.id == 1) { result.error = failure(root, error); return result; }
            ++result.skippedDirectories;
            continue;
        }
        struct FindGuard { HANDLE value; ~FindGuard() { FindClose(value); } } findGuard{enumeration};
        do {
            if (canceled(cancel)) return result;
            const QString name = QString::fromWCharArray(data.cFileName);
            if (name == QStringLiteral(".") || name == QStringLiteral("..")) continue;
            ++processed;
            if (progress && (processed == 1 || processed % 128 == 0)) progress(processed, 0);
            if (recallOrReparse(data.dwFileAttributes)) { ++result.skippedReparsePoints; continue; }
            const bool isDirectory = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const QString path = childPath(directory.path, name);
            NtfsIndexEntry entry;
            entry.fileReference = nextId++;
            entry.parentReference = directory.id;
            entry.name = name;
            entry.names.append({directory.id, name});
            entry.baseNames = entry.names;
            entry.attributes = data.dwFileAttributes;
            if (isDirectory) {
                // fullPath supports at most 1023 non-root components.
                if (directory.depth >= 1022) ++result.skippedDirectories;
                else pending.append({path, entry.fileReference, directory.depth + 1, lock});
            }
            else {
                auto file = metadataHandle(path, false);
                QByteArray identity;
                if (file.valid()) {
                    DWORD current = 0;
                    if (readAttributes(file.get(), current)
                        && !recallOrReparse(current)
                        && !(current & FILE_ATTRIBUTE_DIRECTORY)) {
                        identity = fileIdentity(file.get());
                        FILE_STANDARD_INFO sizes{};
                        if (!identity.isEmpty() && GetFileInformationByHandleEx(file.get(), FileStandardInfo, &sizes, sizeof(sizes))
                            && sizes.EndOfFile.QuadPart >= 0 && sizes.AllocationSize.QuadPart >= 0) {
                            entry.logicalBytes = quint64(sizes.EndOfFile.QuadPart);
                            entry.allocatedBytes = quint64(sizes.AllocationSize.QuadPart);
                            entry.sizeKnown = true;
                            if (current & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE)) {
                                // MS-FSA FileCompressionInformation defines
                                // this as the actual backing-storage allocation.
                                FILE_COMPRESSION_INFO compression{};
                                if (GetFileInformationByHandleEx(file.get(), FileCompressionInfo, &compression, sizeof(compression))
                                    && compression.CompressedFileSize.QuadPart >= 0)
                                    entry.allocatedBytes = quint64(compression.CompressedFileSize.QuadPart);
                                else entry.sizeKnown = false;
                            }
                        }
                    }
                }
                const auto existing = files.constFind(identity);
                if (!identity.isEmpty() && existing != files.cend()) {
                    auto& canonical = snapshot->entries[*existing];
                    canonical.names.append({directory.id, name});
                    canonical.baseNames = canonical.names;
                    if (!canonical.sizeKnown && entry.sizeKnown) {
                        canonical.logicalBytes = entry.logicalBytes;
                        canonical.allocatedBytes = entry.allocatedBytes;
                        canonical.sizeKnown = true;
                        --snapshot->unknownSizeCount;
                    }
                    ++result.duplicateFiles;
                    continue;
                }
                if (!identity.isEmpty()) files.insert(identity, entry.fileReference);
                if (!entry.sizeKnown) ++snapshot->unknownSizeCount;
            }
            snapshot->entries.insert(entry.fileReference, std::move(entry));
        } while (FindNextFileW(enumeration, &data));
        const DWORD error = GetLastError();
        if (error != ERROR_NO_MORE_FILES) {
            // Preserve the measurable part, visibly labeled incomplete by the
            // caller, including failures after several successful entries.
            ++result.skippedDirectories;
        }
    }
    if (canceled(cancel)) return result;
    if (progress) progress(processed, processed);
    if (canceled(cancel)) return result;
    snapshot->complete = true;
    snapshot->status = QStringLiteral("目录遍历完成；跳过目录 %1；跳过重解析点或脱机项 %2；硬链接重复项 %3；未计量文件 %4。")
        .arg(result.skippedDirectories).arg(result.skippedReparsePoints)
        .arg(result.duplicateFiles).arg(snapshot->unknownSizeCount);
    result.snapshot = std::move(snapshot);
#else
    Q_UNUSED(requestedRoot);
    Q_UNUSED(progress);
    result.error = QStringLiteral("当前平台不支持 Windows 目录空间扫描。");
#endif
    return result;
}
} // namespace ks::files
