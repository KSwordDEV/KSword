#include "FileMetadata.h"
#include <limits>
#include <algorithm>
#include <cstring>
#include <Aclapi.h>
#include <Sddl.h>
#include <winternl.h>
#include <PropKey.h>
#include <PropVarUtil.h>
#include <ShObjIdl_core.h>
#include <ShlObj.h>
#include <objbase.h>

#pragma comment(lib, "Propsys.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

namespace ks::r3::file::metadata {
namespace {
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    explicit Handle(HANDLE h) : value(h) {}
};
Handle Open(const std::wstring& path, DWORD access) {
    return Handle(CreateFileW(path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
}
Snapshot Read(HANDLE handle) {
    Snapshot result; BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(handle, &information)) { result.error = GetLastError(); return result; }
    result.identity = {true, information.dwVolumeSerialNumber,
        (static_cast<std::uint64_t>(information.nFileIndexHigh) << 32) | information.nFileIndexLow};
    if (!GetFileInformationByHandleEx(handle, FileBasicInfo, &result.basic, sizeof(result.basic))) {
        result.error = GetLastError(); return result;
    }
    result.ok = true; return result;
}
bool Same(const Identity& a, const Identity& b) {
    return a.known && b.known && a.volumeSerial == b.volumeSerial && a.fileId == b.fileId;
}
}
Snapshot ReadBasic(const std::wstring& path) {
    auto handle = Open(path, FILE_READ_ATTRIBUTES);
    if (handle.value == INVALID_HANDLE_VALUE) { Snapshot result; result.error = GetLastError(); return result; }
    return Read(handle.value);
}
BasicResult WriteBasic(const std::wstring& path, const Identity& expected, const BasicPatch& patch) {
    BasicResult result;
    if (!expected.known || (patch.attributesSelected && (patch.editableAttributes & ~editableAttributeMask))) {
        result.error = ERROR_INVALID_PARAMETER; return result;
    }
    for (std::size_t i = 0; i < patch.times.size(); ++i) {
        if (patch.timeSelected[i] && (!patch.times[i] || patch.times[i] > static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)()))) {
            result.error = ERROR_INVALID_PARAMETER; return result;
        }
    }
    auto handle = Open(path, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES);
    if (handle.value == INVALID_HANDLE_VALUE) { result.error = GetLastError(); return result; }
    result.before = Read(handle.value);
    if (!result.before.ok) { result.error = result.before.error; return result; }
    if (!Same(expected, result.before.identity)) { result.error = ERROR_FILE_INVALID; return result; }
    FILE_BASIC_INFO update{};
    if (patch.timeSelected[0]) update.CreationTime.QuadPart = static_cast<LONGLONG>(patch.times[0]);
    if (patch.timeSelected[1]) update.LastAccessTime.QuadPart = static_cast<LONGLONG>(patch.times[1]);
    if (patch.timeSelected[2]) update.LastWriteTime.QuadPart = static_cast<LONGLONG>(patch.times[2]);
    if (patch.timeSelected[3]) update.ChangeTime.QuadPart = static_cast<LONGLONG>(patch.times[3]);
    if (patch.attributesSelected) {
        update.FileAttributes = (result.before.basic.FileAttributes & ~(editableAttributeMask | FILE_ATTRIBUTE_NORMAL)) | patch.editableAttributes;
        if (!update.FileAttributes) update.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
    result.attempted = true;
    result.written = SetFileInformationByHandle(handle.value, FileBasicInfo, &update, sizeof(update)) != FALSE;
    if (!result.written) { result.error = GetLastError(); return result; }
    result.after = Read(handle.value);
    if (!result.after.ok) { result.error = result.after.error; return result; }
    const auto& value = result.after.basic;
    const std::array<std::uint64_t, 4> actual = {static_cast<std::uint64_t>(value.CreationTime.QuadPart),
        static_cast<std::uint64_t>(value.LastAccessTime.QuadPart), static_cast<std::uint64_t>(value.LastWriteTime.QuadPart),
        static_cast<std::uint64_t>(value.ChangeTime.QuadPart)};
    result.verified = Same(expected, result.after.identity);
    for (std::size_t i = 0; i < actual.size(); ++i) if (patch.timeSelected[i] && actual[i] != patch.times[i]) result.verified = false;
    if (patch.attributesSelected && (value.FileAttributes & editableAttributeMask) != patch.editableAttributes) result.verified = false;
    return result;
}

namespace {
bool ValidStreamName(const std::wstring& name) {
    return !name.empty() && name != L"." && name != L".." && _wcsicmp(name.c_str(),L"$DATA") != 0 &&
        name.find_first_of(L"\\/:*") == std::wstring::npos;
}
std::wstring StreamPath(const std::wstring& path, const std::wstring& name) { return path + L":" + name + L":$DATA"; }
}
NamedResult ListStreams(const std::wstring& path) {
    NamedResult result;
    const auto before=ReadBasic(path); result.identity=before.identity;
    if (!before.ok) {result.error=before.error;return result;}
    if(before.basic.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) {result.error=ERROR_NOT_SUPPORTED;return result;}
    WIN32_FIND_STREAM_DATA item{};
    HANDLE find=FindFirstStreamW(path.c_str(),FindStreamInfoStandard,&item,0);
    if(find==INVALID_HANDLE_VALUE) {
        const auto error=GetLastError();
        if(error!=ERROR_HANDLE_EOF) {result.error=error;return result;}
        const auto after=ReadBasic(path);
        if(!after.ok || !Same(before.identity,after.identity)) {result.error=ERROR_FILE_INVALID;return result;}
        result.ok=result.complete=true;return result;
    }
    do {
        NamedValue row;row.name=item.cStreamName;row.sizeKnown=true;row.size=static_cast<std::uint64_t>(item.StreamSize.QuadPart);result.entries.push_back(std::move(row));
    } while(FindNextStreamW(find,&item));
    const auto error=GetLastError();FindClose(find);
    if(error!=ERROR_HANDLE_EOF) {result.error=error;return result;}
    const auto after=ReadBasic(path);
    if(!after.ok || !Same(before.identity,after.identity)) {result.error=ERROR_FILE_INVALID;return result;}
    result.ok=result.complete=true;return result;
}
NamedResult ReadStream(const std::wstring& path, const std::wstring& name, std::size_t maxBytes) {
    NamedResult result;
    if(!ValidStreamName(name) || maxBytes>64U*1024U*1024U) {result.error=ERROR_INVALID_PARAMETER;return result;}
    const auto base=ReadBasic(path); result.identity=base.identity;
    if(!base.ok) {result.error=base.error;return result;}
    if(base.basic.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) {result.error=ERROR_NOT_SUPPORTED;return result;}
    auto stream=Open(StreamPath(path,name),GENERIC_READ | FILE_READ_ATTRIBUTES);
    if(stream.value==INVALID_HANDLE_VALUE) {result.error=GetLastError();return result;}
    const auto current=Read(stream.value);
    if(!current.ok || !Same(base.identity,current.identity)) {result.error=ERROR_FILE_INVALID;return result;}
    LARGE_INTEGER size{};
    if(!GetFileSizeEx(stream.value,&size) || size.QuadPart<0) {result.error=GetLastError();return result;}
    NamedValue row;row.name=name;row.sizeKnown=true;row.size=static_cast<std::uint64_t>(size.QuadPart);row.bytes.resize(static_cast<std::size_t>((std::min<std::uint64_t>)(static_cast<std::uint64_t>(size.QuadPart),maxBytes)));
    DWORD read=0;
    if(!row.bytes.empty() && !ReadFile(stream.value,row.bytes.data(),static_cast<DWORD>(row.bytes.size()),&read,nullptr)) {result.error=GetLastError();return result;}
    if(read != row.bytes.size()) {result.error=ERROR_HANDLE_EOF;return result;}
    result.entries.push_back(std::move(row));result.ok=true;result.complete=static_cast<std::uint64_t>(size.QuadPart)<=maxBytes;return result;
}
NamedResult WriteStream(const std::wstring& path, const Identity& expected, const std::wstring& name,
                        const std::vector<std::uint8_t>& bytes, bool remove) {
    NamedResult result;
    if(!expected.known || !ValidStreamName(name) || bytes.size()>64U*1024U*1024U) {result.error=ERROR_INVALID_PARAMETER;return result;}
    const auto base=ReadBasic(path);result.identity=base.identity;
    if(!base.ok) {result.error=base.error;return result;}
    if(base.basic.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) {result.error=ERROR_NOT_SUPPORTED;return result;}
    if(!Same(expected,base.identity)) {result.error=ERROR_FILE_INVALID;return result;}
    const auto target=StreamPath(path,name);
    const DWORD access=FILE_READ_ATTRIBUTES | GENERIC_READ | (remove ? DELETE : GENERIC_WRITE);
    Handle stream(CreateFileW(target.c_str(),access,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,
        remove ? OPEN_EXISTING : OPEN_ALWAYS,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if(stream.value==INVALID_HANDLE_VALUE) {result.error=GetLastError();return result;}
    const bool created=!remove && GetLastError()!=ERROR_ALREADY_EXISTS;
    const auto opened=Read(stream.value);
    if(!opened.ok || !Same(expected,opened.identity)) {result.attempted=created;result.written=created;result.error=ERROR_FILE_INVALID;return result;}
    result.attempted=true;
    if(remove) {
        FILE_DISPOSITION_INFO disposition{TRUE};
        result.written=SetFileInformationByHandle(stream.value,FileDispositionInfo,&disposition,sizeof(disposition))!=FALSE;
        if(!result.written) {result.error=GetLastError();return result;}
        CloseHandle(stream.value);stream.value=INVALID_HANDLE_VALUE;
        auto check=Open(target,FILE_READ_ATTRIBUTES);
        if(check.value==INVALID_HANDLE_VALUE) {const DWORD err=GetLastError();result.verified=(err==ERROR_FILE_NOT_FOUND || err==ERROR_PATH_NOT_FOUND);if(!result.verified)result.error=err;}
    } else {
        LARGE_INTEGER zero{};DWORD written=0;
        if(!SetFilePointerEx(stream.value,zero,nullptr,FILE_BEGIN) || !SetEndOfFile(stream.value)) {result.error=GetLastError();return result;}
        result.written=true;
        if(!bytes.empty()) {
            if(!WriteFile(stream.value,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)) {result.error=GetLastError();return result;}
            if(written!=bytes.size()) {result.error=ERROR_WRITE_FAULT;return result;}
        }
        if(!SetFilePointerEx(stream.value,zero,nullptr,FILE_BEGIN)) {result.error=GetLastError();return result;}
        std::vector<std::uint8_t> actual(bytes.size());DWORD read=0;
        if(!actual.empty() && (!ReadFile(stream.value,actual.data(),static_cast<DWORD>(actual.size()),&read,nullptr) || read!=actual.size())) {result.error=GetLastError();return result;}
        result.verified=actual==bytes;
    }
    const auto after=ReadBasic(path);
    if(!after.ok || !Same(expected,after.identity)) {result.error=ERROR_FILE_INVALID;result.verified=false;}
    result.ok=result.written;result.complete=result.verified;return result;
}

namespace {
struct LocalBuffer { HLOCAL value=nullptr; ~LocalBuffer(){if(value)LocalFree(value);} };
constexpr SECURITY_INFORMATION securityMask=OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
DWORD SecurityAccess(SECURITY_INFORMATION parts, bool write) {
    DWORD access=FILE_READ_ATTRIBUTES|READ_CONTROL;
    if(parts&SACL_SECURITY_INFORMATION) access|=ACCESS_SYSTEM_SECURITY;
    if(write && (parts&(OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION))) access|=WRITE_OWNER;
    if(write && (parts&DACL_SECURITY_INFORMATION)) access|=WRITE_DAC;
    return access;
}
bool SecurityPartsValid(SECURITY_INFORMATION parts) {return parts && !(parts&~securityMask);}
bool FormatSecurity(PSECURITY_DESCRIPTOR descriptor,SECURITY_INFORMATION parts,std::wstring& text,DWORD& error) {
    LPWSTR value=nullptr;
    if(!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,SDDL_REVISION_1,parts,&value,nullptr)) {error=GetLastError();return false;}
    text=value;LocalFree(value);return true;
}
SecurityResult QuerySecurityHandle(HANDLE handle,SECURITY_INFORMATION parts) {
    SecurityResult result;const auto snap=Read(handle);result.identity=snap.identity;
    if(!snap.ok) {result.error=snap.error;return result;}
    PSECURITY_DESCRIPTOR raw=nullptr;
    PSID owner=nullptr,group=nullptr;PACL dacl=nullptr,sacl=nullptr;
    const DWORD status=GetSecurityInfo(handle,SE_FILE_OBJECT,parts,&owner,&group,&dacl,&sacl,&raw);
    if(status!=ERROR_SUCCESS) {result.error=status;return result;}
    LocalBuffer descriptor;descriptor.value=raw;
    result.ok=FormatSecurity(raw,parts,result.sddl,result.error);return result;
}
bool EqualAclBytes(PACL first,PACL second) {
    if(!first || !second) return first==second;
    ACL_SIZE_INFORMATION a{},b{};
    if(!GetAclInformation(first,&a,sizeof(a),AclSizeInformation) || !GetAclInformation(second,&b,sizeof(b),AclSizeInformation)) return false;
    return a.AclBytesInUse==b.AclBytesInUse && std::memcmp(first,second,a.AclBytesInUse)==0;
}
bool EqualSecurity(HANDLE handle,PSECURITY_DESCRIPTOR expected,SECURITY_INFORMATION parts,DWORD& error) {
    PSECURITY_DESCRIPTOR actual=nullptr;PSID owner=nullptr,group=nullptr;PACL dacl=nullptr,sacl=nullptr;
    error=GetSecurityInfo(handle,SE_FILE_OBJECT,parts,&owner,&group,&dacl,&sacl,&actual);
    if(error!=ERROR_SUCCESS) return false;
    LocalBuffer actualOwner;actualOwner.value=actual;
    PSID expectedOwner=nullptr,expectedGroup=nullptr;PACL expectedDacl=nullptr,expectedSacl=nullptr;
    BOOL present=FALSE,defaulted=FALSE;
    if((parts&OWNER_SECURITY_INFORMATION) && (!GetSecurityDescriptorOwner(expected,&expectedOwner,&defaulted) || !owner || !expectedOwner || !EqualSid(owner,expectedOwner))) return false;
    if((parts&GROUP_SECURITY_INFORMATION) && (!GetSecurityDescriptorGroup(expected,&expectedGroup,&defaulted) || !group || !expectedGroup || !EqualSid(group,expectedGroup))) return false;
    if((parts&DACL_SECURITY_INFORMATION) && (!GetSecurityDescriptorDacl(expected,&present,&expectedDacl,&defaulted) || !present || !EqualAclBytes(dacl,expectedDacl))) return false;
    if((parts&SACL_SECURITY_INFORMATION) && (!GetSecurityDescriptorSacl(expected,&present,&expectedSacl,&defaulted) || !present || !EqualAclBytes(sacl,expectedSacl))) return false;
    SECURITY_DESCRIPTOR_CONTROL expectedControl=0,actualControl=0;DWORD revision=0;
    if(!GetSecurityDescriptorControl(expected,&expectedControl,&revision) || !GetSecurityDescriptorControl(actual,&actualControl,&revision)) {error=GetLastError();return false;}
    SECURITY_DESCRIPTOR_CONTROL selected=0;
    if(parts&DACL_SECURITY_INFORMATION) selected|=SE_DACL_PROTECTED;
    if(parts&SACL_SECURITY_INFORMATION) selected|=SE_SACL_PROTECTED;
    return (expectedControl&selected)==(actualControl&selected);
}
}
SecurityResult ReadSecurity(const std::wstring& path,SECURITY_INFORMATION parts) {
    SecurityResult result;if(!SecurityPartsValid(parts)) {result.error=ERROR_INVALID_PARAMETER;return result;}
    auto handle=Open(path,SecurityAccess(parts,false));
    if(handle.value==INVALID_HANDLE_VALUE) {result.error=GetLastError();return result;}
    return QuerySecurityHandle(handle.value,parts);
}
SecurityResult WriteSecurity(const std::wstring& path,const Identity& expected,SECURITY_INFORMATION parts,const std::wstring& sddl) {
    SecurityResult result;
    if(!expected.known || !SecurityPartsValid(parts) || sddl.empty()) {result.error=ERROR_INVALID_PARAMETER;return result;}
    PSECURITY_DESCRIPTOR raw=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&raw,nullptr)) {result.error=GetLastError();return result;}
    LocalBuffer descriptor;descriptor.value=raw;
    PSID owner=nullptr,group=nullptr;PACL dacl=nullptr,sacl=nullptr;BOOL defaulted=FALSE,present=FALSE;
    if((parts&OWNER_SECURITY_INFORMATION) && (!GetSecurityDescriptorOwner(raw,&owner,&defaulted) || !owner)) {result.error=ERROR_INVALID_SECURITY_DESCR;return result;}
    if((parts&GROUP_SECURITY_INFORMATION) && (!GetSecurityDescriptorGroup(raw,&group,&defaulted) || !group)) {result.error=ERROR_INVALID_SECURITY_DESCR;return result;}
    if((parts&DACL_SECURITY_INFORMATION) && (!GetSecurityDescriptorDacl(raw,&present,&dacl,&defaulted) || !present)) {result.error=ERROR_INVALID_SECURITY_DESCR;return result;}
    if((parts&SACL_SECURITY_INFORMATION) && (!GetSecurityDescriptorSacl(raw,&present,&sacl,&defaulted) || !present)) {result.error=ERROR_INVALID_SECURITY_DESCR;return result;}
    SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;
    if(!GetSecurityDescriptorControl(raw,&control,&revision)) {result.error=GetLastError();return result;}
    SECURITY_INFORMATION writeParts=parts;
    if(parts&DACL_SECURITY_INFORMATION) writeParts|=(control&SE_DACL_PROTECTED)?PROTECTED_DACL_SECURITY_INFORMATION:UNPROTECTED_DACL_SECURITY_INFORMATION;
    if(parts&SACL_SECURITY_INFORMATION) writeParts|=(control&SE_SACL_PROTECTED)?PROTECTED_SACL_SECURITY_INFORMATION:UNPROTECTED_SACL_SECURITY_INFORMATION;
    auto handle=Open(path,SecurityAccess(parts,true));
    if(handle.value==INVALID_HANDLE_VALUE) {result.error=GetLastError();return result;}
    const auto before=Read(handle.value);result.identity=before.identity;
    if(!before.ok) {result.error=before.error;return result;}
    if(!Same(expected,before.identity)) {result.error=ERROR_FILE_INVALID;return result;}
    result.attempted=true;
    result.error=SetSecurityInfo(handle.value,SE_FILE_OBJECT,writeParts,owner,group,dacl,sacl);
    if(result.error!=ERROR_SUCCESS) return result;
    result.written=true;
    const auto actual=QuerySecurityHandle(handle.value,parts);result.sddl=actual.sddl;
    if(!actual.ok) {result.error=actual.error;return result;}
    result.verified=Same(expected,actual.identity) && EqualSecurity(handle.value,raw,parts,result.error);
    result.ok=true;return result;
}

namespace {
struct FullEa {ULONG next;UCHAR flags;UCHAR nameLength;USHORT valueLength;CHAR name[1];};
using QueryEaFn=NTSTATUS (NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,BOOLEAN,PVOID,ULONG,PULONG,BOOLEAN);
using SetEaFn=NTSTATUS (NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG);
using StatusToErrorFn=ULONG (NTAPI*)(NTSTATUS);
struct EaApis {
    QueryEaFn query=nullptr;SetEaFn set=nullptr;StatusToErrorFn error=nullptr;
    EaApis() {const auto ntdll=GetModuleHandleW(L"ntdll.dll");if(ntdll){query=reinterpret_cast<QueryEaFn>(GetProcAddress(ntdll,"NtQueryEaFile"));set=reinterpret_cast<SetEaFn>(GetProcAddress(ntdll,"NtSetEaFile"));error=reinterpret_cast<StatusToErrorFn>(GetProcAddress(ntdll,"RtlNtStatusToDosError"));}}
    DWORD code(NTSTATUS value)const{return error?error(value):ERROR_GEN_FAILURE;}
};
bool WideUtf8(const std::wstring& value,std::string& bytes) {
    if(value.empty() || value.size()>255) return false;
    const int length=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr);
    if(length<=0 || length>255) return false;
    bytes.resize(length);return WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),bytes.data(),length,nullptr,nullptr)==length;
}
std::wstring EaName(const char* name,std::size_t length) {
    if(!length) return {};
    const int chars=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name,static_cast<int>(length),nullptr,0);
    if(!chars) return {};
    std::wstring result(chars,L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name,static_cast<int>(length),result.data(),chars);return result;
}
NamedResult ReadEaHandle(HANDLE handle) {
    NamedResult result;const auto snap=Read(handle);result.identity=snap.identity;
    if(!snap.ok) {result.error=snap.error;return result;}
    const EaApis api;if(!api.query) {result.error=ERROR_PROC_NOT_FOUND;return result;}
    std::vector<std::uint8_t> buffer(1024U*1024U);IO_STATUS_BLOCK ios{};
    const NTSTATUS status=api.query(handle,&ios,buffer.data(),static_cast<ULONG>(buffer.size()),FALSE,nullptr,0,nullptr,TRUE);
    const auto raw=static_cast<std::uint32_t>(status);
    if(raw==0xC0000052U || raw==0x80000012U) {result.ok=result.complete=true;return result;}
    if(status<0 && raw!=0x80000005U) {result.error=api.code(status);return result;}
    const auto length=static_cast<std::size_t>(ios.Information);
    if(length>buffer.size()) {result.error=ERROR_INVALID_DATA;return result;}
    std::size_t offset=0;
    while(offset<length) {
        constexpr auto nameOffset=offsetof(FullEa,name);
        if(length-offset<nameOffset) {result.error=ERROR_INVALID_DATA;return result;}
        const auto* entry=reinterpret_cast<const FullEa*>(buffer.data()+offset);
        const std::size_t needed=nameOffset+entry->nameLength+1U+entry->valueLength;
        if(needed>length-offset || entry->name[entry->nameLength]!='\0' || (entry->next && (entry->next<needed || entry->next>length-offset))) {result.error=ERROR_INVALID_DATA;return result;}
        NamedValue item;item.name=EaName(entry->name,entry->nameLength);item.needEa=(entry->flags&0x80U)!=0;item.sizeKnown=true;item.size=entry->valueLength;
        if(item.name.empty()) {result.error=ERROR_NO_UNICODE_TRANSLATION;return result;}
        const auto* value=reinterpret_cast<const std::uint8_t*>(entry->name+entry->nameLength+1U);
        item.bytes.assign(value,value+entry->valueLength);result.entries.push_back(std::move(item));
        if(!entry->next) break;offset+=entry->next;
    }
    result.ok=true;result.complete=raw!=0x80000005U;
    if(!result.complete) result.error=ERROR_MORE_DATA;
    return result;
}
}
NamedResult ListEa(const std::wstring& path) {
    NamedResult result;auto handle=Open(path,FILE_READ_ATTRIBUTES|FILE_READ_EA);
    if(handle.value==INVALID_HANDLE_VALUE) {result.error=GetLastError();return result;}
    return ReadEaHandle(handle.value);
}
NamedResult WriteEa(const std::wstring& path,const Identity& expected,const std::wstring& name,
                    const std::vector<std::uint8_t>& bytes,bool remove,bool needEa) {
    NamedResult result;std::string encoded;
    if(!expected.known || !WideUtf8(name,encoded) || encoded.find('\0')!=std::string::npos || bytes.size()>65535U || (!remove && bytes.empty())) {result.error=ERROR_INVALID_PARAMETER;return result;}
    const EaApis api;if(!api.set || !api.query) {result.error=ERROR_PROC_NOT_FOUND;return result;}
    auto handle=Open(path,FILE_READ_ATTRIBUTES|FILE_READ_EA|FILE_WRITE_EA);
    if(handle.value==INVALID_HANDLE_VALUE) {result.error=GetLastError();return result;}
    const auto before=Read(handle.value);result.identity=before.identity;
    if(!before.ok) {result.error=before.error;return result;}
    if(!Same(expected,before.identity)) {result.error=ERROR_FILE_INVALID;return result;}
    const std::size_t size=offsetof(FullEa,name)+encoded.size()+1U+(remove?0U:bytes.size());
    std::vector<std::uint8_t> buffer(size,0);auto* ea=reinterpret_cast<FullEa*>(buffer.data());
    ea->flags=needEa?0x80U:0U;ea->nameLength=static_cast<UCHAR>(encoded.size());ea->valueLength=static_cast<USHORT>(remove?0U:bytes.size());
    std::memcpy(ea->name,encoded.data(),encoded.size());
    if(!remove)std::memcpy(ea->name+encoded.size()+1U,bytes.data(),bytes.size());
    IO_STATUS_BLOCK ios{};result.attempted=true;const auto status=api.set(handle.value,&ios,buffer.data(),static_cast<ULONG>(buffer.size()));
    if(status<0) {result.error=api.code(status);return result;}
    result.written=true;const auto after=ReadEaHandle(handle.value);
    if(!after.ok || !after.complete) {result.error=after.error;return result;}
    const auto it=std::find_if(after.entries.begin(),after.entries.end(),[&](const NamedValue& item){return _wcsicmp(item.name.c_str(),name.c_str())==0;});
    result.verified=remove ? it==after.entries.end() : it!=after.entries.end() && it->bytes==bytes && it->needEa==needEa;
    result.ok=result.written;result.complete=result.verified;return result;
}

namespace {
struct ComScope {
    HRESULT status=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    ~ComScope(){if(SUCCEEDED(status))CoUninitialize();}
};
DWORD HresultError(HRESULT hr){return HRESULT_FACILITY(hr)==FACILITY_WIN32?HRESULT_CODE(hr):static_cast<DWORD>(hr);}
bool CreateBackup(const std::wstring& path,const Identity& expected,const std::wstring& backup,bool& created,DWORD& error) {
    created=false;
    const auto source=ReadBasic(path);
    if(!source.ok) {error=source.error;return false;}
    if(!Same(source.identity,expected)) {error=ERROR_FILE_INVALID;return false;}
    if(source.basic.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) {error=ERROR_NOT_SUPPORTED;return false;}
    if(backup.empty()) {error=ERROR_INVALID_PARAMETER;return false;}
    if(!CopyFileW(path.c_str(),backup.c_str(),TRUE)) {error=GetLastError();return false;}
    created=true;
    const auto after=ReadBasic(path);
    if(!after.ok || !Same(expected,after.identity)) {error=ERROR_FILE_INVALID;return false;}
    error=ERROR_SUCCESS;return true;
}
bool RestoreBackup(const std::wstring& path,const Identity& expected,const std::wstring& backup,DWORD& error) {
    auto target=Open(path,GENERIC_READ|GENERIC_WRITE|FILE_READ_ATTRIBUTES);
    if(target.value==INVALID_HANDLE_VALUE) {error=GetLastError();return false;}
    const auto snap=Read(target.value);
    if(!snap.ok || !Same(expected,snap.identity)) {error=ERROR_FILE_INVALID;return false;}
    Handle source(CreateFileW(backup.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr));
    if(source.value==INVALID_HANDLE_VALUE) {error=GetLastError();return false;}
    LARGE_INTEGER length{},zero{};
    if(!GetFileSizeEx(source.value,&length) || length.QuadPart<0 || !SetFilePointerEx(target.value,zero,nullptr,FILE_BEGIN)) {error=GetLastError();return false;}
    std::array<std::uint8_t,65536> buffer{};std::uint64_t total=0;
    while(total<static_cast<std::uint64_t>(length.QuadPart)) {
        DWORD read=0,written=0;const auto want=static_cast<DWORD>((std::min<std::uint64_t>)(buffer.size(),static_cast<std::uint64_t>(length.QuadPart)-total));
        if(!ReadFile(source.value,buffer.data(),want,&read,nullptr) || !read) {error=GetLastError();if(!error)error=ERROR_HANDLE_EOF;return false;}
        if(!WriteFile(target.value,buffer.data(),read,&written,nullptr) || written!=read) {error=GetLastError();if(!error)error=ERROR_WRITE_FAULT;return false;}
        total+=read;
    }
    if(!SetEndOfFile(target.value) || !FlushFileBuffers(target.value)) {error=GetLastError();return false;}
    if(!SetFilePointerEx(source.value,zero,nullptr,FILE_BEGIN) || !SetFilePointerEx(target.value,zero,nullptr,FILE_BEGIN)) {error=GetLastError();return false;}
    std::array<std::uint8_t,65536> compare{};total=0;
    while(total<static_cast<std::uint64_t>(length.QuadPart)) {
        DWORD a=0,b=0;const auto want=static_cast<DWORD>((std::min<std::uint64_t>)(buffer.size(),static_cast<std::uint64_t>(length.QuadPart)-total));
        if(!ReadFile(source.value,buffer.data(),want,&a,nullptr) || !ReadFile(target.value,compare.data(),want,&b,nullptr) || !a || a!=b || std::memcmp(buffer.data(),compare.data(),a)) {error=ERROR_CRC;return false;}
        total+=a;
    }
    error=ERROR_SUCCESS;return true;
}
struct ShellKey {const wchar_t* name;const PROPERTYKEY* key;bool vector;bool integer;};
const ShellKey shellKeys[]={
    {L"title",&PKEY_Title,false,false},{L"subject",&PKEY_Subject,false,false},
    {L"authors",&PKEY_Author,true,false},{L"keywords",&PKEY_Keywords,true,false},
    {L"comment",&PKEY_Comment,false,false},{L"copyright",&PKEY_Copyright,false,false},
    {L"rating",&PKEY_Rating,false,true}};
const ShellKey* FindShellKey(const std::wstring& name) {
    for(const auto& item:shellKeys) if(_wcsicmp(item.name,name.c_str())==0) return &item;
    return nullptr;
}
ShellProperty ReadProperty(IPropertyStore* store,const ShellKey& key) {
    ShellProperty result;result.name=key.name;PROPVARIANT value;PropVariantInit(&value);
    auto status=store->GetValue(*key.key,&value);
    if(SUCCEEDED(status) && value.vt==VT_EMPTY) {result.available=result.empty=true;}
    else if(SUCCEEDED(status) && key.vector) {
        const ULONG count=PropVariantGetElementCount(value);result.available=true;
        for(ULONG i=0;i<count;++i) {PWSTR item=nullptr;status=PropVariantGetStringElem(value,i,&item);
            if(FAILED(status)){result.available=false;break;}result.values.emplace_back(item?item:L"");CoTaskMemFree(item);}
    } else if(SUCCEEDED(status) && key.integer) {
        ULONG number=0;status=PropVariantToUInt32(value,&number);if(SUCCEEDED(status)){result.available=true;result.values.push_back(std::to_wstring(number));}
    } else if(SUCCEEDED(status)) {
        PWSTR text=nullptr;status=PropVariantToStringAlloc(value,&text);if(SUCCEEDED(status)){result.available=true;result.values.emplace_back(text?text:L"");CoTaskMemFree(text);}
    }
    result.hresult=status;PropVariantClear(&value);return result;
}
ShellResult ReadShellStore(const std::wstring& path) {
    ShellResult result;ComScope com;
    if(FAILED(com.status) && com.status!=RPC_E_CHANGED_MODE) {result.hresult=com.status;result.error=HresultError(com.status);return result;}
    IPropertyStore* store=nullptr;
    const HRESULT status=SHGetPropertyStoreFromParsingName(path.c_str(),nullptr,GPS_DEFAULT,IID_PPV_ARGS(&store));
    if(FAILED(status)) {result.hresult=status;result.error=HresultError(status);return result;}
    for(const auto& key:shellKeys) result.properties.push_back(ReadProperty(store,key));
    store->Release();result.ok=true;return result;
}
}
ShellResult ReadShell(const std::wstring& path) {
    const auto before=ReadBasic(path);ShellResult result;result.identity=before.identity;
    if(!before.ok){result.error=before.error;return result;}
    if(before.basic.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT){result.error=ERROR_NOT_SUPPORTED;return result;}
    result=ReadShellStore(path);result.identity=before.identity;
    const auto after=ReadBasic(path);
    if(!after.ok || !Same(before.identity,after.identity)) {result.ok=false;result.error=ERROR_FILE_INVALID;}
    return result;
}
ShellResult WriteShell(const std::wstring& path,const Identity& expected,const std::wstring& name,
                       const std::vector<std::wstring>& values,const std::wstring& backupPath) {
    ShellResult result;result.backupPath=backupPath;const auto* key=FindShellKey(name);
    if(!key || values.empty() || (!key->vector && values.size()!=1) || !expected.known) {result.error=ERROR_INVALID_PARAMETER;return result;}
    ULONG rating=0;
    if(key->integer) {
        wchar_t* end=nullptr;const auto number=wcstoul(values[0].c_str(),&end,10);
        if(values[0].empty() || !end || *end || number>99) {result.error=ERROR_INVALID_PARAMETER;return result;}
        rating=number;
    }
    const auto before=ReadBasic(path);result.identity=before.identity;
    if(!before.ok) {result.error=before.error;return result;}
    if(!Same(expected,before.identity)) {result.error=ERROR_FILE_INVALID;return result;}
    if(!CreateBackup(path,expected,backupPath,result.backupCreated,result.error)) return result;
    ComScope com;
    if(FAILED(com.status) && com.status!=RPC_E_CHANGED_MODE) {result.hresult=com.status;result.error=HresultError(com.status);return result;}
    IPropertyStore* store=nullptr;
    HRESULT status=SHGetPropertyStoreFromParsingName(path.c_str(),nullptr,GPS_READWRITE,IID_PPV_ARGS(&store));
    if(FAILED(status)) {result.hresult=status;result.error=HresultError(status);return result;}
    PROPVARIANT property;PropVariantInit(&property);
    if(key->vector) {
        std::vector<PCWSTR> strings;for(const auto& value:values)strings.push_back(value.c_str());
        status=InitPropVariantFromStringVector(strings.data(),static_cast<ULONG>(strings.size()),&property);
    } else if(key->integer) status=InitPropVariantFromUInt32(rating,&property);
    else status=InitPropVariantFromString(values[0].c_str(),&property);
    result.attempted=true;
    if(SUCCEEDED(status)) status=store->SetValue(*key->key,property);
    PropVariantClear(&property);
    if(SUCCEEDED(status)) status=store->Commit();
    store->Release();result.hresult=status;
    if(FAILED(status)) {
        result.error=HresultError(status);result.rollbackAttempted=true;
        result.rollbackVerified=RestoreBackup(path,expected,backupPath,result.rollbackError);
        return result;
    }
    result.written=true;
    const auto after=ReadBasic(path);const auto observed=ReadShellStore(path);
    result.afterIdentity=after.identity;
    result.properties=observed.properties;
    const auto it=std::find_if(observed.properties.begin(),observed.properties.end(),[&](const ShellProperty& propertyRow){return propertyRow.name==key->name;});
    const bool valueMatches=it!=observed.properties.end() && it->available &&
        (key->integer ? it->values==std::vector<std::wstring>{std::to_wstring(rating)} : it->values==values);
    result.verified=after.ok && Same(expected,after.identity) && observed.ok && valueMatches;
    result.ok=observed.ok;
    if(!result.verified) result.error=after.ok?observed.error:after.error;
    return result;
}

namespace {
struct ResourceId {
    bool numeric=false;WORD value=0;std::wstring text;
    LPCWSTR ptr() const {return numeric?MAKEINTRESOURCEW(value):text.c_str();}
};
bool ParseResourceId(const std::wstring& text,ResourceId& out) {
    if(text.empty())return false;
    const wchar_t* begin=text.c_str();if(*begin==L'#')++begin;
    if(!*begin)return false;
    wchar_t* end=nullptr;const auto value=wcstoul(begin,&end,0);
    if(end && !*end && value<=65535U) {out.numeric=true;out.value=static_cast<WORD>(value);return true;}
    if(text.front()==L'#')return false;
    out.text=text;return true;
}
bool ResourceMissing(DWORD error) {
    return error==ERROR_RESOURCE_TYPE_NOT_FOUND || error==ERROR_RESOURCE_NAME_NOT_FOUND ||
        error==ERROR_RESOURCE_LANG_NOT_FOUND || error==ERROR_RESOURCE_DATA_NOT_FOUND;
}
}
ResourceResult ReadPeResource(const std::wstring& path,const std::wstring& type,const std::wstring& name,WORD language) {
    ResourceResult result;ResourceId typeId,nameId;
    if(!ParseResourceId(type,typeId) || !ParseResourceId(name,nameId)) {result.error=ERROR_INVALID_PARAMETER;return result;}
    const auto before=ReadBasic(path);result.identity=before.identity;
    if(!before.ok) {result.error=before.error;return result;}
    if(before.basic.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) {result.error=ERROR_NOT_SUPPORTED;return result;}
    const auto module=LoadLibraryExW(path.c_str(),nullptr,LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE|LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if(!module) {result.error=GetLastError();return result;}
    const auto resource=FindResourceExW(module,typeId.ptr(),nameId.ptr(),language);
    if(!resource) {result.error=GetLastError();result.ok=ResourceMissing(result.error);}
    else {
        const auto length=SizeofResource(module,resource);const auto loaded=LoadResource(module,resource);
        const auto* data=loaded?static_cast<const std::uint8_t*>(LockResource(loaded)):nullptr;
        if(length>64U*1024U*1024U) result.error=ERROR_FILE_TOO_LARGE;
        else if(!loaded || (!data && length)) result.error=ERROR_RESOURCE_DATA_NOT_FOUND;
        else {if(length)result.bytes.assign(data,data+length);result.ok=result.present=true;}
    }
    FreeLibrary(module);
    const auto after=ReadBasic(path);
    if(!after.ok || !Same(before.identity,after.identity)) {result.ok=false;result.error=ERROR_FILE_INVALID;}
    return result;
}
ResourceResult WritePeResource(const std::wstring& path,const Identity& expected,const std::wstring& type,
                              const std::wstring& name,WORD language,const std::vector<std::uint8_t>& bytes,
                              bool remove,const std::wstring& backupPath) {
    ResourceResult result;result.backupPath=backupPath;ResourceId typeId,nameId;
    if(!expected.known || !ParseResourceId(type,typeId) || !ParseResourceId(name,nameId) ||
       bytes.size()>64U*1024U*1024U || (!remove && bytes.empty())) {result.error=ERROR_INVALID_PARAMETER;return result;}
    const auto before=ReadBasic(path);result.identity=before.identity;
    if(!before.ok){result.error=before.error;return result;}
    if(!Same(expected,before.identity)){result.error=ERROR_FILE_INVALID;return result;}
    if(!CreateBackup(path,expected,backupPath,result.backupCreated,result.error))return result;
    auto update=BeginUpdateResourceW(path.c_str(),FALSE);
    if(!update){result.error=GetLastError();return result;}
    result.attempted=true;
    if(!UpdateResourceW(update,typeId.ptr(),nameId.ptr(),language,
        remove?nullptr:const_cast<std::uint8_t*>(bytes.data()),remove?0U:static_cast<DWORD>(bytes.size()))) {
        result.error=GetLastError();result.rollbackAttempted=true;
        if(EndUpdateResourceW(update,TRUE)) result.rollbackVerified=true;
        else result.rollbackVerified=RestoreBackup(path,expected,backupPath,result.rollbackError);
        return result;
    }
    if(!EndUpdateResourceW(update,FALSE)) {
        result.error=GetLastError();result.rollbackAttempted=true;
        result.rollbackVerified=RestoreBackup(path,expected,backupPath,result.rollbackError);return result;
    }
    result.written=true;
    const auto after=ReadPeResource(path,type,name,language);
    result.afterIdentity=after.identity;
    result.present=after.present;result.bytes=after.bytes;
    result.verified=after.ok && Same(expected,after.identity) && (remove?!after.present:after.present && after.bytes==bytes);
    result.ok=after.ok;if(!result.verified)result.error=after.error;
    return result;
}
}
