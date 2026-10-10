#include "NamedPipes.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
namespace {
struct OwnedPipe {HANDLE handle=nullptr;DirectoryQueryEvidence& evidence;~OwnedPipe(){if(handle&&handle!=INVALID_HANDLE_VALUE){evidence.closeAttempted=true;::SetLastError(0);evidence.closed=::CloseHandle(handle)!=FALSE;evidence.closeError=evidence.closed?0: ::GetLastError();}}};
}
NamedPipeSnapshot CollectNamedPipes(const std::wstring& path,const DirectoryQueryOptions& options){
    NamedPipeSnapshot result;auto& evidence=result.evidence;evidence.path=path;const auto& runtime=Runtime();evidence.apiAvailable=runtime.openFile&&runtime.queryDirectoryFile;
    if(!evidence.apiAvailable)return result;if(path.empty()||path.size()>32766){evidence.malformed=true;return result;}
    const auto directoryPath=path.back()==L'\\'?path:path+L"\\";evidence.path=directoryPath;
    [&]{OwnedPipe owned{nullptr,evidence};auto text=MakeUnicodeString(directoryPath);auto attr=MakeObjectAttributes(text);IO_STATUS_BLOCK io{};evidence.openAttempted=true;
        evidence.openStatus=runtime.openFile(&owned.handle,FILE_LIST_DIRECTORY|SYNCHRONIZE,&attr,&io,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT);
        result.ioStatus=static_cast<LONG>(io.Status);result.information=io.Information;
        if(evidence.openStatus!=0)return;if(!owned.handle||owned.handle==INVALID_HANDLE_VALUE){evidence.malformed=true;return;}evidence.opened=true;if(result.ioStatus!=0){evidence.lastQueryStatus=result.ioStatus;return;}
        const auto deadline=options.deadlineTick?options.deadlineTick: ::GetTickCount64()+options.maxDurationMs;std::vector<std::byte> buffer(128*1024);std::set<std::wstring> pages;BOOLEAN restart=TRUE;
        for(;;){if(options.cancelled&&options.cancelled()){evidence.cancelled=true;return;}if(result.entries.size()>=options.maxEntries||::GetTickCount64()>=deadline){evidence.limited=true;return;}
            io={};evidence.queryAttempted=true;evidence.lastQueryStatus=runtime.queryDirectoryFile(owned.handle,nullptr,nullptr,nullptr,&io,buffer.data(),static_cast<ULONG>(buffer.size()),kFileDirectoryInformation,FALSE,nullptr,restart);restart=FALSE;
            result.ioStatus=static_cast<LONG>(io.Status);result.information=io.Information;evidence.returned=static_cast<ULONG>((std::min<std::uint64_t>)(io.Information,MAXDWORD));
            if(evidence.lastQueryStatus==kStatusNoMoreEntries||evidence.lastQueryStatus==static_cast<LONG>(0x80000006UL)){evidence.complete=true;return;}
            if(evidence.lastQueryStatus!=0){evidence.limited=IsRetryStatus(evidence.lastQueryStatus);return;}
            if(result.ioStatus!=0){evidence.lastQueryStatus=result.ioStatus;return;}
            constexpr auto header=offsetof(KFILE_DIRECTORY_INFORMATION,FileName);const auto bytes=static_cast<std::size_t>(io.Information);
            if(bytes<header||bytes>buffer.size()){evidence.malformed=true;return;}
            std::size_t offset=0;std::wstring signature;
            for(;;){if(offset>bytes||bytes-offset<header){evidence.malformed=true;return;}KFILE_DIRECTORY_INFORMATION value{};memcpy(&value,buffer.data()+offset,header);
                if(value.FileNameLength%2||value.FileNameLength>bytes-offset-header){evidence.malformed=true;return;}
                const auto recordBytes=header+value.FileNameLength;
                if(value.NextEntryOffset&&(value.NextEntryOffset%8||value.NextEntryOffset<recordBytes||value.NextEntryOffset>=bytes-offset)){evidence.malformed=true;return;}
                NamedPipeEntry entry;entry.info=value;entry.name.assign(reinterpret_cast<const wchar_t*>(buffer.data()+offset+header),value.FileNameLength/2);signature+=entry.name+L"\n";++evidence.queried;
                if(!entry.name.empty()&&entry.name!=L"."&&entry.name!=L".."){if(result.entries.size()>=options.maxEntries){evidence.limited=true;return;}result.entries.push_back(std::move(entry));}
                if(!value.NextEntryOffset)break;offset+=value.NextEntryOffset;
            }
            if(!pages.insert(signature).second){evidence.cycle=true;evidence.limited=true;return;}
        }
    }();return result;
}
NamedPipeProbeSnapshot ProbeNamedPipe(const std::wstring& path){
    NamedPipeProbeSnapshot result;auto& evidence=result.evidence;const auto& runtime=Runtime();evidence.path=path;evidence.apiAvailable=runtime.openFile!=nullptr;if(!evidence.apiAvailable)return result;if(path.empty()||path.size()>32766){evidence.malformed=true;return result;}
    [&]{OwnedPipe owned{nullptr,evidence};auto text=MakeUnicodeString(path);auto attr=MakeObjectAttributes(text);IO_STATUS_BLOCK io{};evidence.openAttempted=true;
        evidence.openStatus=runtime.openFile(&owned.handle,FILE_READ_ATTRIBUTES|SYNCHRONIZE,&attr,&io,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,FILE_SYNCHRONOUS_IO_NONALERT);result.ioStatus=static_cast<LONG>(io.Status);result.information=io.Information;
        if(evidence.openStatus!=0)return;if(!owned.handle||owned.handle==INVALID_HANDLE_VALUE){evidence.malformed=true;return;}evidence.opened=true;evidence.complete=result.ioStatus==0;
        if(runtime.queryObject){auto& basic=result.basic;basic.attempted=true;basic.status=runtime.queryObject(owned.handle,0,&basic.value,sizeof(basic.value),&basic.returned);
            basic.malformed=basic.status==0&&basic.returned!=sizeof(basic.value);basic.available=basic.status==0&&!basic.malformed;evidence.malformed=basic.malformed;}
    }();return result;
}
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
void QueryNamedPipeDirectory(const NtRuntime& runtime,const std::wstring& path,const std::wstring& filter,QueryPacket& packet){
    (void)runtime;const auto snapshot=CollectNamedPipes(path);
    if(!snapshot.evidence.apiAvailable){packet.warnings.push_back(L"NtOpenFile/NtQueryDirectoryFile 不可用。");return;}
    if(!snapshot.evidence.opened){packet.warnings.push_back(std::wstring(L"无法打开命名管道目录 ")+path+L"，NTSTATUS="+StatusText(snapshot.evidence.openStatus));return;}
    for(const auto& entry:snapshot.entries){const auto* info=&entry.info;const auto& name=entry.name;
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

        if(MatchesColumnsFilter(row,filter))packet.rows.push_back(std::move(row));
    }
    if(!snapshot.evidence.complete)packet.warnings.push_back(std::wstring(L"查询命名管道目录失败 ")+path+L"，NTSTATUS="+StatusText(snapshot.evidence.lastQueryStatus));
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
