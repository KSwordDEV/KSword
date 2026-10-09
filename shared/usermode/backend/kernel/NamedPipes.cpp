#include "NamedPipes.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
std::wstring FileTimeText(const LARGE_INTEGER& value) {
    if (value.QuadPart == 0) {
        return {};
    }
    FILETIME utc{};
    utc.dwLowDateTime = static_cast<DWORD>(value.LowPart);
    utc.dwHighDateTime = static_cast<DWORD>(value.HighPart);
    FILETIME local{};
    SYSTEMTIME system{};
    if (!::FileTimeToLocalFileTime(&utc, &local) || !::FileTimeToSystemTime(&local, &system)) {
        return {};
    }
    wchar_t text[64]{};
    ::swprintf_s(text, L"%04u-%02u-%02u %02u:%02u:%02u", system.wYear, system.wMonth, system.wDay, system.wHour, system.wMinute, system.wSecond);
    return text;
}
void QueryNamedPipeDirectory(const NtRuntime& runtime, const std::wstring& path, const std::wstring& filter, QueryPacket& packet) {
    if (!runtime.openFile || !runtime.queryDirectoryFile) {
        packet.warnings.push_back(L"NtOpenFile/NtQueryDirectoryFile 不可用。");
        return;
    }

    UNICODE_STRING unicodePath = MakeUnicodeString(path);
    OBJECT_ATTRIBUTES attributes = MakeObjectAttributes(unicodePath);
    IO_STATUS_BLOCK ioStatus{};
    HANDLE directory = nullptr;
    const LONG openStatus = runtime.openFile(
        &directory,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &attributes,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!IsSuccessStatus(openStatus) || !directory) {
        packet.warnings.push_back(std::wstring(L"无法打开命名管道目录 ") + path + L"，NTSTATUS=" + StatusText(openStatus));
        return;
    }

    std::vector<std::byte> buffer(128 * 1024);
    BOOLEAN restart = TRUE;
    for (;;) {
        std::fill(buffer.begin(), buffer.end(), std::byte{});
        ioStatus = {};
        const LONG status = runtime.queryDirectoryFile(
            directory,
            nullptr,
            nullptr,
            nullptr,
            &ioStatus,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            kFileDirectoryInformation,
            FALSE,
            nullptr,
            restart);
        restart = FALSE;
        if (status == kStatusNoMoreEntries) {
            break;
        }
        if (!IsSuccessStatus(status)) {
            packet.warnings.push_back(std::wstring(L"查询命名管道目录失败 ") + path + L"，NTSTATUS=" + StatusText(status));
            break;
        }

        std::size_t offset = 0;
        for (;;) {
            if (offset + sizeof(KFILE_DIRECTORY_INFORMATION) > buffer.size()) {
                break;
            }
            const auto* info = reinterpret_cast<const KFILE_DIRECTORY_INFORMATION*>(buffer.data() + offset);
            const std::wstring name(info->FileName, info->FileName + (info->FileNameLength / sizeof(wchar_t)));
            if (!name.empty() && name != L"." && name != L"..") {
                KernelResultRow row = Row({
                    { L"Pipe", name },
                    { L"Directory", path },
                    { L"NtPath", JoinObjectPath(path, name) },
                    { L"Win32Path", std::wstring(L"\\\\.\\pipe\\") + name },
                    { L"Attributes", HexText(info->FileAttributes) },
                    { L"Size", std::to_wstring(info->EndOfFile.QuadPart) },
                    { L"Created", FileTimeText(info->CreationTime) },
                    { L"LastAccess", FileTimeText(info->LastAccessTime) },
                    { L"LastWrite", FileTimeText(info->LastWriteTime) },
                    { L"Changed", FileTimeText(info->ChangeTime) },
                    { L"Status", L"NtQueryDirectoryFile" },
                });
                if (MatchesColumnsFilter(row, filter)) {
                    packet.rows.push_back(std::move(row));
                }
            }
            if (info->NextEntryOffset == 0) {
                break;
            }
            offset += info->NextEntryOffset;
        }
    }

    ::CloseHandle(directory);
}
KernelOperationResult QueryNamedPipes(const KernelRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    QueryNamedPipeDirectory(runtime, L"\\Device\\NamedPipe", request.filterText, packet);
    QueryNamedPipeDirectory(runtime, L"\\??\\PIPE", request.filterText, packet);
    return MakeResult(request.featureId, !packet.rows.empty(), L"命名管道枚举", std::move(packet));
}
KernelOperationResult ExecuteNativeNamedPipeProbe(const KernelActionRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    const std::wstring path = NativePathFromAction(request);
    if (path.empty()) {
        packet.warnings.push_back(L"当前行没有 NtPath/Pipe，无法验证命名管道。");
        return MakeNativeActionResult(request, false, L"命名管道打开验证", std::move(packet));
    }
    if (!runtime.openFile) {
        packet.warnings.push_back(L"NtOpenFile 不可用。");
        return MakeNativeActionResult(request, false, L"命名管道打开验证", std::move(packet));
    }

    LONG openStatus = kStatusNoSuchFile;
    IO_STATUS_BLOCK ioStatus{};
    HANDLE pipe = OpenNamedPipeReadOnly(runtime, path, &openStatus, &ioStatus);
    AppendObjectBasicInfoRow(packet, runtime, path, pipe, openStatus);
    packet.rows.push_back(Row({
        { L"Action", L"NativeNamedPipeProbe" },
        { L"NtPath", path },
        { L"Win32Path", StartsWithI(path, L"\\Device\\NamedPipe\\") ? std::wstring(L"\\\\.\\pipe\\") + path.substr(18) : L"" },
        { L"OpenStatus", StatusText(openStatus) },
        { L"OpenStatusText", StatusMeaningText(openStatus) },
        { L"IoStatus", StatusText(static_cast<LONG>(ioStatus.Status)) },
        { L"IoStatusText", StatusMeaningText(static_cast<LONG>(ioStatus.Status)) },
        { L"Information", std::to_wstring(static_cast<std::uint64_t>(ioStatus.Information)) },
        { L"Access", L"FILE_READ_ATTRIBUTES|SYNCHRONIZE" },
        { L"Share", L"READ|WRITE|DELETE" },
        { L"Status", pipe ? L"可打开" : L"不可打开、管道忙或权限受限" },
    }, StatusMeaningText(openStatus)));
    if (pipe) {
        ::CloseHandle(pipe);
    }
    return MakeNativeActionResult(request, pipe != nullptr, L"命名管道打开验证", std::move(packet));
}
}
