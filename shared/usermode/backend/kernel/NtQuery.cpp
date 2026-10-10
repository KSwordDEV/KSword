#include "NtQuery.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
#include <psapi.h>
#include <map>
namespace ks::r3::kernel {
NativeQueryBuffer QueryBounded(const std::function<LONG(PVOID,ULONG,PULONG)>& query,ULONG initialSize){NativeQueryBuffer result;ULONG size=initialSize;std::set<ULONG> sizes;
    for(int attempt=0;attempt<6;++attempt){if(!size||size>16u*1024u*1024u||!sizes.insert(size).second){result.limited=true;return result;}
        result.bytes.assign(size,std::byte{});result.allocatedBytes=size;result.returnedBytes=0;++result.attempts;result.status=query(result.bytes.data(),size,&result.returnedBytes);
        if(result.status==0){result.malformed=result.returnedBytes>size;if(!result.malformed)result.bytes.resize(result.returnedBytes);return result;}
        if(!IsRetryStatus(result.status))return result;
        const auto next=result.returnedBytes&&result.returnedBytes<size?result.returnedBytes:(std::max<std::uint64_t>)(std::uint64_t(size)*2,result.returnedBytes);
        if(next>16u*1024u*1024u){result.limited=true;return result;}size=static_cast<ULONG>(next);
    }result.limited=true;return result;
}
const std::vector<NtQueryPreset>& NtQueryPresets(){static const std::vector<NtQueryPreset> presets{
    {L"system",L"basic",L"NtQuerySystemInformation",0,sizeof(SYSTEM_BASIC_INFORMATION)},{L"system",L"performance",L"NtQuerySystemInformation",2,128*1024},{L"system",L"time",L"NtQuerySystemInformation",3,48},
    {L"system",L"processes",L"NtQuerySystemInformation",5,128*1024},{L"system",L"modules",L"NtQuerySystemInformation",11,1024*1024},{L"system",L"handles",L"NtQuerySystemInformation",16,128*1024},
    {L"process",L"basic",L"NtQueryInformationProcess",0,sizeof(PROCESS_BASIC_INFORMATION)},{L"process",L"debug-port",L"NtQueryInformationProcess",7,sizeof(ULONG_PTR)},{L"process",L"handle-count",L"NtQueryInformationProcess",20,sizeof(ULONG)},{L"process",L"image-name",L"NtQueryInformationProcess",27},
    {L"thread",L"basic",L"NtQueryInformationThread",0,sizeof(void*)==8?48:28},{L"thread",L"times",L"NtQueryInformationThread",1,32},
    {L"token",L"user",L"NtQueryInformationToken",1},{L"token",L"integrity",L"NtQueryInformationToken",25},{L"token",L"statistics",L"NtQueryInformationToken",10,sizeof(TOKEN_STATISTICS)},
    {L"object",L"basic",L"NtQueryObject",0,sizeof(KOBJECT_BASIC_INFORMATION)},{L"object",L"name",L"NtQueryObject",1},{L"object",L"type",L"NtQueryObject",2}};return presets;}
NtQuerySnapshot CollectNtQueries(const std::wstring& category,const std::wstring& name){NtQuerySnapshot result;const auto& runtime=Runtime();result.processId=::GetCurrentProcessId();result.threadId=::GetCurrentThreadId();
    [&]{struct TokenOwner{HANDLE handle=nullptr;NtQuerySnapshot& snapshot;~TokenOwner(){if(handle&&handle!=INVALID_HANDLE_VALUE){snapshot.tokenCloseAttempted=true;::SetLastError(0);snapshot.tokenClosed=::CloseHandle(handle)!=FALSE;snapshot.tokenCloseError=snapshot.tokenClosed?0: ::GetLastError();}}} token{nullptr,result};
        const bool needToken=category.empty()||category==L"token";if(needToken&&runtime.queryInformationToken){result.tokenOpenAttempted=true;::SetLastError(0);result.tokenOpened=::OpenProcessToken(::GetCurrentProcess(),TOKEN_QUERY,&token.handle)!=FALSE;result.tokenOpenError=result.tokenOpened?0: ::GetLastError();result.tokenMalformed=result.tokenOpened&&(!token.handle||token.handle==INVALID_HANDLE_VALUE);}
        for(const auto& preset:NtQueryPresets()){if((!category.empty()&&category!=preset.category)||(!name.empty()&&name!=preset.name))continue;NtQueryEvidence evidence;evidence.preset=preset;std::function<LONG(PVOID,ULONG,PULONG)> query;
            if(preset.category==L"system"&&runtime.querySystemInformation)query=[&](PVOID b,ULONG n,PULONG r){return runtime.querySystemInformation(preset.infoClass,b,n,r);};
            else if(preset.category==L"process"&&runtime.queryInformationProcess)query=[&](PVOID b,ULONG n,PULONG r){return runtime.queryInformationProcess(::GetCurrentProcess(),preset.infoClass,b,n,r);};
            else if(preset.category==L"thread"&&runtime.queryInformationThread)query=[&](PVOID b,ULONG n,PULONG r){return runtime.queryInformationThread(::GetCurrentThread(),preset.infoClass,b,n,r);};
            else if(preset.category==L"token"&&runtime.queryInformationToken){evidence.apiAvailable=true;if(result.tokenOpened&&token.handle&&token.handle!=INVALID_HANDLE_VALUE)query=[&](PVOID b,ULONG n,PULONG r){return runtime.queryInformationToken(token.handle,preset.infoClass,b,n,r);};}
            else if(preset.category==L"object"&&runtime.queryObject)query=[&](PVOID b,ULONG n,PULONG r){return runtime.queryObject(::GetCurrentProcess(),preset.infoClass,b,n,r);};
            evidence.apiAvailable=evidence.apiAvailable||static_cast<bool>(query);if(query){evidence.attempted=true;evidence.result=QueryBounded(query,preset.initialSize);std::vector<std::byte>{}.swap(evidence.result.bytes);}result.queries.push_back(std::move(evidence));
        }
    }();return result;
}
NtExportsSnapshot CollectNtQueryExports(){NtExportsSnapshot result;const auto module=::GetModuleHandleW(L"ntdll.dll");result.moduleAvailable=module!=nullptr;if(!module)return result;
    MODULEINFO info{};if(!::GetModuleInformation(::GetCurrentProcess(),module,&info,sizeof(info))){result.win32Error=::GetLastError();return result;}result.imageBytes=info.SizeOfImage;
    if(info.SizeOfImage<sizeof(IMAGE_DOS_HEADER)||info.SizeOfImage>64u*1024u*1024u){result.malformed=true;return result;}
    std::vector<std::byte> image(info.SizeOfImage);SIZE_T copied=0;if(!::ReadProcessMemory(::GetCurrentProcess(),info.lpBaseOfDll,image.data(),image.size(),&copied)||copied!=image.size()){result.win32Error=::GetLastError();if(!result.win32Error)result.win32Error=ERROR_PARTIAL_COPY;return result;}
    const auto fits=[&](std::uint64_t offset,std::uint64_t bytes){return offset<=image.size()&&bytes<=image.size()-offset;};
    IMAGE_DOS_HEADER dos{};memcpy(&dos,image.data(),sizeof(dos));if(dos.e_magic!=IMAGE_DOS_SIGNATURE||dos.e_lfanew<0||!fits(static_cast<ULONG>(dos.e_lfanew),sizeof(IMAGE_NT_HEADERS))){result.malformed=true;return result;}
    IMAGE_NT_HEADERS nt{};memcpy(&nt,image.data()+dos.e_lfanew,sizeof(nt));
    if(nt.Signature!=IMAGE_NT_SIGNATURE||nt.FileHeader.SizeOfOptionalHeader<sizeof(IMAGE_OPTIONAL_HEADER)||nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR_MAGIC||nt.OptionalHeader.NumberOfRvaAndSizes<=IMAGE_DIRECTORY_ENTRY_EXPORT){result.malformed=true;return result;}
    const auto directory=nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];if(!directory.VirtualAddress&&!directory.Size){result.complete=true;return result;}
    if(directory.Size<sizeof(IMAGE_EXPORT_DIRECTORY)||!fits(directory.VirtualAddress,directory.Size)){result.malformed=true;return result;}
    IMAGE_EXPORT_DIRECTORY exports{};memcpy(&exports,image.data()+directory.VirtualAddress,sizeof(exports));result.namedExports=exports.NumberOfNames;
    if(!fits(exports.AddressOfNames,std::uint64_t(exports.NumberOfNames)*sizeof(DWORD))||!fits(exports.AddressOfNameOrdinals,std::uint64_t(exports.NumberOfNames)*sizeof(WORD))||!fits(exports.AddressOfFunctions,std::uint64_t(exports.NumberOfFunctions)*sizeof(DWORD))){result.malformed=true;return result;}
    for(ULONG index=0;index<exports.NumberOfNames;++index){DWORD rva=0;WORD ordinal=0;memcpy(&rva,image.data()+exports.AddressOfNames+std::size_t(index)*4,4);memcpy(&ordinal,image.data()+exports.AddressOfNameOrdinals+std::size_t(index)*2,2);
        if(ordinal>=exports.NumberOfFunctions||!fits(rva,1)){result.malformed=true;return result;}
        const auto* chars=reinterpret_cast<const char*>(image.data()+rva);const auto* end=static_cast<const char*>(memchr(chars,0,image.size()-rva));if(!end){result.malformed=true;return result;}
        const std::string name(chars,end);if(name.rfind("NtQuery",0)!=0)continue;
        DWORD functionRva=0;memcpy(&functionRva,image.data()+exports.AddressOfFunctions+std::size_t(ordinal)*4,4);
        if(!fits(functionRva,1)||std::uint64_t(exports.Base)+ordinal>MAXDWORD){result.malformed=true;return result;}
        if(result.entries.size()>=kMaxExportRows){result.limited=true;return result;}
        NtExportEntry entry;for(const unsigned char character:name){if(character<32||character>126){result.malformed=true;return result;}entry.name.push_back(character);}entry.rva=functionRva;entry.ordinal=exports.Base+ordinal;
        entry.forwarded=functionRva>=directory.VirtualAddress&&std::uint64_t(functionRva)<std::uint64_t(directory.VirtualAddress)+directory.Size;result.entries.push_back(std::move(entry));
    }result.complete=true;return result;
}
std::pair<LONG, std::vector<std::byte>> QueryGrowable(const std::function<LONG(PVOID, ULONG, PULONG)>& query, ULONG initialSize) {
    auto result=QueryBounded(query,initialSize);result.bytes.resize(result.allocatedBytes);return {result.status,std::move(result.bytes)};
}

void AppendNtQueryRow(QueryPacket& packet, const std::wstring& filter, const std::wstring& category, const std::wstring& functionName, ULONG infoClass, LONG status, std::size_t bytes, const std::wstring& detail) {
    KernelResultRow row = Row({
        { L"Category", category },
        { L"Function", functionName },
        { L"Class", std::to_wstring(infoClass) },
        { L"Status", StatusText(status) },
        { L"Success", status==0 ? L"true" : L"false" },
        { L"Bytes", std::to_wstring(bytes) },
        { L"Detail", detail },
    }, detail);
    if (MatchesColumnsFilter(row, filter)) {
        packet.rows.push_back(std::move(row));
    }
}
void AppendNtdllExportRows(QueryPacket& packet, const std::wstring& filter) {
    const auto snapshot=CollectNtQueryExports();
    if(!snapshot.moduleAvailable){packet.warnings.push_back(L"ntdll.dll 未加载，无法枚举 NtQuery* 导出。");return;}
    if(snapshot.malformed){packet.warnings.push_back(L"ntdll NT 头无效。");return;}
    if(snapshot.complete&&!snapshot.namedExports)packet.warnings.push_back(L"ntdll 无导出目录。");
    for(const auto& entry:snapshot.entries){auto row=Row({{L"Category",L"Export"},{L"Function",entry.name},{L"Ordinal",std::to_wstring(entry.ordinal)},{L"RVA",HexText(entry.rva)},{L"Status",L"Exported"}});if(MatchesColumnsFilter(row,filter))packet.rows.push_back(std::move(row));}
}

KernelOperationResult QueryNtQueryLegacy(const KernelRequest& request) {
    QueryPacket packet;AppendNtdllExportRows(packet,request.filterText);const auto snapshot=CollectNtQueries();
    const std::map<std::wstring,std::wstring> missingMessages{{L"system",L"NtQuerySystemInformation 不可用。"},{L"process",L"NtQueryInformationProcess 不可用。"},{L"thread",L"NtQueryInformationThread 不可用。"},{L"token",L"NtQueryInformationToken 不可用。"},{L"object",L"NtQueryObject 不可用。"}};std::set<std::wstring> warned;
    for(const auto& evidence:snapshot.queries){if(!evidence.apiAvailable&&warned.insert(evidence.preset.category).second)packet.warnings.push_back(missingMessages.at(evidence.preset.category));if(!evidence.attempted)continue;auto category=evidence.preset.category;category[0]=static_cast<wchar_t>(std::towupper(category[0]));
        const auto detail=category==L"System"?L"安全枚举类探测":category==L"Process"?L"当前进程句柄":category==L"Thread"?L"当前线程句柄":category==L"Token"?L"当前进程令牌":L"当前进程伪句柄";
        AppendNtQueryRow(packet,request.filterText,category,evidence.preset.function,evidence.preset.infoClass,evidence.result.status,evidence.result.allocatedBytes,detail);
    }
    if(snapshot.tokenOpenAttempted&&!snapshot.tokenOpened)packet.warnings.push_back(std::wstring(L"OpenProcessToken 失败，Win32=")+std::to_wstring(snapshot.tokenOpenError));
    return MakeResult(request.featureId,!packet.rows.empty(),L"历史 NtQuery 探测",std::move(packet));
}
}
