#include "ObjectNamespace.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
#include <tuple>
namespace ks::r3::kernel {
namespace {
bool BoundedCounted(const UNICODE_STRING& value,const void* buffer,std::size_t bytes,std::wstring& out){
    if(value.Length%sizeof(wchar_t)||value.Length>value.MaximumLength)return false;
    if(!value.Length){out.clear();return value.Buffer==nullptr||reinterpret_cast<std::uintptr_t>(value.Buffer)>=reinterpret_cast<std::uintptr_t>(buffer);}
    const auto start=reinterpret_cast<std::uintptr_t>(buffer),pointer=reinterpret_cast<std::uintptr_t>(value.Buffer);
    if(!value.Buffer||pointer%alignof(wchar_t)||pointer<start||pointer-start>bytes||value.Length>bytes-(pointer-start))return false;
    out.assign(value.Buffer,value.Length/sizeof(wchar_t));return true;
}
struct OwnedObject {
    HANDLE handle=nullptr;bool* attempted=nullptr;bool* closed=nullptr;DWORD* error=nullptr;
    void close(){if(!handle||handle==INVALID_HANDLE_VALUE)return;*attempted=true;::SetLastError(ERROR_SUCCESS);*closed=::CloseHandle(handle)!=FALSE;*error=*closed?ERROR_SUCCESS: ::GetLastError();handle=nullptr;}
    ~OwnedObject(){close();}
};
}
KernelResultRow Row(std::initializer_list<std::pair<std::wstring, std::wstring>> columns, const std::wstring& detail) {
    KernelResultRow row;
    row.columns.assign(columns.begin(), columns.end());
    row.detailText = detail;
    return row;
}
std::wstring HexText(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << value;
    return stream.str();
}
std::wstring StatusText(const LONG status) {
    return HexText(static_cast<std::uint32_t>(status));
}
void AppendFlagText(std::wstring& text, const ULONG value, const ULONG flag, const wchar_t* name) {
    if ((value & flag) == 0) {
        return;
    }
    if (!text.empty()) {
        text += L"|";
    }
    text += name;
}
std::wstring ObjectAttributesText(const ULONG attributes) {
    std::wstring text;
    AppendFlagText(text, attributes, OBJ_INHERIT, L"INHERIT");
    AppendFlagText(text, attributes, OBJ_PERMANENT, L"PERMANENT");
    AppendFlagText(text, attributes, OBJ_EXCLUSIVE, L"EXCLUSIVE");
    AppendFlagText(text, attributes, OBJ_CASE_INSENSITIVE, L"CASE_INSENSITIVE");
    AppendFlagText(text, attributes, OBJ_OPENIF, L"OPENIF");
    AppendFlagText(text, attributes, OBJ_OPENLINK, L"OPENLINK");
    AppendFlagText(text, attributes, OBJ_KERNEL_HANDLE, L"KERNEL_HANDLE");
    AppendFlagText(text, attributes, OBJ_FORCE_ACCESS_CHECK, L"FORCE_ACCESS_CHECK");
    AppendFlagText(text, attributes, OBJ_IGNORE_IMPERSONATED_DEVICEMAP, L"IGNORE_IMPERSONATED_DEVICEMAP");
    AppendFlagText(text, attributes, OBJ_DONT_REPARSE, L"DONT_REPARSE");
    const ULONG known = OBJ_INHERIT
        | OBJ_PERMANENT
        | OBJ_EXCLUSIVE
        | OBJ_CASE_INSENSITIVE
        | OBJ_OPENIF
        | OBJ_OPENLINK
        | OBJ_KERNEL_HANDLE
        | OBJ_FORCE_ACCESS_CHECK
        | OBJ_IGNORE_IMPERSONATED_DEVICEMAP
        | OBJ_DONT_REPARSE;
    const ULONG unknown = attributes & ~known;
    if (unknown != 0) {
        if (!text.empty()) {
            text += L"|";
        }
        text += L"UNKNOWN(" + HexText(unknown) + L")";
    }
    return text.empty() ? L"0" : text;
}
std::wstring AccessMaskText(const ACCESS_MASK access) {
    std::wstring text;
    AppendFlagText(text, access, DELETE, L"DELETE");
    AppendFlagText(text, access, READ_CONTROL, L"READ_CONTROL");
    AppendFlagText(text, access, WRITE_DAC, L"WRITE_DAC");
    AppendFlagText(text, access, WRITE_OWNER, L"WRITE_OWNER");
    AppendFlagText(text, access, SYNCHRONIZE, L"SYNCHRONIZE");
    AppendFlagText(text, access, ACCESS_SYSTEM_SECURITY, L"ACCESS_SYSTEM_SECURITY");
    AppendFlagText(text, access, GENERIC_READ, L"GENERIC_READ");
    AppendFlagText(text, access, GENERIC_WRITE, L"GENERIC_WRITE");
    AppendFlagText(text, access, GENERIC_EXECUTE, L"GENERIC_EXECUTE");
    AppendFlagText(text, access, GENERIC_ALL, L"GENERIC_ALL");
    const ULONG known = DELETE
        | READ_CONTROL
        | WRITE_DAC
        | WRITE_OWNER
        | SYNCHRONIZE
        | ACCESS_SYSTEM_SECURITY
        | GENERIC_READ
        | GENERIC_WRITE
        | GENERIC_EXECUTE
        | GENERIC_ALL;
    const ULONG unknown = access & ~known;
    if (unknown != 0) {
        if (!text.empty()) {
            text += L"|";
        }
        text += L"SPECIFIC(" + HexText(unknown) + L")";
    }
    return text.empty() ? L"0" : text;
}
bool IsSuccessStatus(const LONG status) {
    return status >= 0;
}
std::wstring StatusMeaningText(const LONG status) {
    switch (status) {
    case kStatusSuccess: return L"成功";
    case kStatusInfoLengthMismatch: return L"缓冲区长度不匹配";
    case kStatusBufferTooSmall: return L"缓冲区过小";
    case kStatusBufferOverflow: return L"缓冲区溢出/需重试";
    case kStatusNoMoreEntries: return L"没有更多条目";
    case kStatusNoSuchFile: return L"对象/文件不存在";
    case kStatusUnsuccessful: return L"操作失败";
    case kStatusInvalidHandle: return L"句柄无效";
    case kStatusAccessDenied: return L"访问被拒绝";
    case kStatusObjectTypeMismatch: return L"对象类型不匹配";
    case kStatusObjectNameNotFound: return L"对象名不存在";
    case kStatusObjectPathNotFound: return L"对象路径不存在";
    case kStatusNameTooLong: return L"名称过长";
    case kStatusPipeDisconnected: return L"管道已断开";
    case kStatusPipeBusy: return L"管道忙";
    case kStatusInstanceNotAvailable: return L"管道实例不可用";
    default:
        return IsSuccessStatus(status) ? L"成功或信息状态" : L"失败/受限";
    }
}
bool IsRetryStatus(const LONG status) {
    return status == kStatusInfoLengthMismatch || status == kStatusBufferTooSmall || status == kStatusBufferOverflow;
}
std::wstring CountedString(const UNICODE_STRING& value) {
    if (!value.Buffer || value.Length == 0) {
        return {};
    }
    return std::wstring(value.Buffer, value.Buffer + (value.Length / sizeof(wchar_t)));
}
UNICODE_STRING MakeUnicodeString(const std::wstring& text) {
    UNICODE_STRING result{};
    result.Buffer = const_cast<PWSTR>(text.c_str());
    result.Length = static_cast<USHORT>(text.size() * sizeof(wchar_t));
    result.MaximumLength = static_cast<USHORT>(result.Length + sizeof(wchar_t));
    return result;
}
OBJECT_ATTRIBUTES MakeObjectAttributes(UNICODE_STRING& name, HANDLE root) {
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = root;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    attributes.ObjectName = &name;
    return attributes;
}
std::wstring JoinObjectPath(const std::wstring& directoryPath, const std::wstring& name) {
    if (directoryPath.empty()) {
        return name;
    }
    if (name.empty()) {
        return directoryPath;
    }
    if (directoryPath.back() == L'\\') {
        return directoryPath + name;
    }
    return directoryPath + L"\\" + name;
}
std::wstring ToLowerCopy(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return text;
}
bool ContainsI(const std::wstring& text, const std::wstring& fragment) {
    if (fragment.empty()) {
        return true;
    }
    return ToLowerCopy(text).find(ToLowerCopy(fragment)) != std::wstring::npos;
}
bool StartsWithI(const std::wstring& text, const std::wstring& prefix) {
    if (prefix.empty()) {
        return true;
    }
    if (text.size() < prefix.size()) {
        return false;
    }
    return _wcsnicmp(text.c_str(), prefix.c_str(), prefix.size()) == 0;
}
ACCESS_MASK ParseHexOrDecimal(const std::wstring& text) {
    if (text.empty()) {
        return 0;
    }
    wchar_t* end = nullptr;
    const int base = StartsWithI(text, L"0x") ? 16 : 10;
    const unsigned long value = std::wcstoul(text.c_str(), &end, base);
    if (end == text.c_str() || (end != nullptr && *end != L'\0')) {
        return 0;
    }
    return static_cast<ACCESS_MASK>(value);
}
std::wstring JoinStrings(const std::vector<std::wstring>& values, const std::wstring& separator) {
    std::wstring result;
    for (const std::wstring& value : values) {
        if (value.empty()) {
            continue;
        }
        if (!result.empty()) {
            result += separator;
        }
        result += value;
    }
    return result;
}
std::vector<std::wstring> DosPathCandidatesFromNtPath(const std::wstring& ntPath) {
    std::vector<std::wstring> candidates;
    if (!StartsWithI(ntPath, L"\\Device\\")) {
        return candidates;
    }

    for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
        wchar_t driveName[3]{ drive, L':', L'\0' };
        wchar_t mappingBuffer[4096]{};
        const DWORD mappingLength = ::QueryDosDeviceW(driveName, mappingBuffer, static_cast<DWORD>(_countof(mappingBuffer)));
        if (mappingLength == 0) {
            continue;
        }

        const wchar_t* cursor = mappingBuffer;
        while (*cursor != L'\0') {
            const std::wstring mapping(cursor);
            if (!mapping.empty() && StartsWithI(ntPath, mapping)) {
                std::wstring candidate(driveName);
                const std::wstring suffix = ntPath.substr(mapping.size());
                candidate += suffix.empty() ? L"\\" : suffix;
                const bool duplicate = std::any_of(candidates.begin(), candidates.end(), [&](const std::wstring& existing) {
                    return _wcsicmp(existing.c_str(), candidate.c_str()) == 0;
                });
                if (!duplicate) {
                    candidates.push_back(std::move(candidate));
                }
            }
            cursor += std::wcslen(cursor) + 1;
        }
    }
    return candidates;
}
bool MatchesDirectoryFilter(const DirectoryEntry& entry, const std::wstring& filter) {
    if (filter.empty()) {
        return true;
    }
    return ContainsI(entry.parentPath, filter)
        || ContainsI(entry.name, filter)
        || ContainsI(entry.typeName, filter)
        || ContainsI(entry.fullPath, filter)
        || ContainsI(entry.targetPath, filter)
        || ContainsI(entry.statusText, filter);
}
std::wstring FieldValue(const KernelActionRequest& request, const std::wstring& key) {
    for (const auto& field : request.rowFields) {
        if (_wcsicmp(field.first.c_str(), key.c_str()) == 0) {
            return field.second;
        }
    }
    return {};
}
std::wstring FirstNonEmpty(std::initializer_list<std::wstring> values) {
    for (const std::wstring& value : values) {
        if (!value.empty()) {
            return value;
        }
    }
    return {};
}
std::wstring NativePathFromAction(const KernelActionRequest& request) {
    const std::wstring direct = FirstNonEmpty({
        FieldValue(request, L"Path"),
        FieldValue(request, L"NtPath"),
        FieldValue(request, L"fullPath"),
        FieldValue(request, L"FullPath"),
        FieldValue(request, L"完整路径"),
        FieldValue(request, L"NT Path"),
        FieldValue(request, L"targetPath"),
        FieldValue(request, L"symbolicTarget"),
        FieldValue(request, L"目标路径"),
        FieldValue(request, L"符号链接目标"),
        FieldValue(request, L"Directory"),
        FieldValue(request, L"directoryPath"),
        FieldValue(request, L"sourceDirectory"),
        FieldValue(request, L"目录路径"),
        FieldValue(request, L"来源目录"),
        request.filterText,
    });
    if (!direct.empty()) {
        return direct;
    }
    const std::wstring parent = FieldValue(request, L"Parent");
    const std::wstring name = FirstNonEmpty({
        FieldValue(request, L"Name"),
        FieldValue(request, L"objectName"),
        FieldValue(request, L"linkName"),
        FieldValue(request, L"对象名称"),
        FieldValue(request, L"名称"),
        FieldValue(request, L"Pipe"),
        FieldValue(request, L"Pipe Name"),
    });
    return JoinObjectPath(parent, name);
}
std::wstring ObjectTypeNameFromAction(const KernelActionRequest& request) {
    return FirstNonEmpty({
        FieldValue(request, L"Type"),
        FieldValue(request, L"TypeName"),
        FieldValue(request, L"ObjectType"),
        FieldValue(request, L"objectType"),
        FieldValue(request, L"对象类型"),
        FieldValue(request, L"类型"),
        FieldValue(request, L"类型名"),
    });
}
void AppendObjectTypeDetailRow(const KernelActionRequest& request, const std::wstring& type, QueryPacket& packet) {
    packet.rows.push_back(Row({
        { L"Action", L"NativeObjectTypeDetail" },
        { L"Type", type },
        { L"TypeIndex", FieldValue(request, L"TypeIndex") },
        { L"Objects", FieldValue(request, L"Objects") },
        { L"Handles", FieldValue(request, L"Handles") },
        { L"HighObjects", FieldValue(request, L"HighObjects") },
        { L"HighHandles", FieldValue(request, L"HighHandles") },
        { L"ValidAccess", FieldValue(request, L"ValidAccess") },
        { L"ValidAccessText", AccessMaskText(ParseHexOrDecimal(FieldValue(request, L"ValidAccess"))) },
        { L"GenericRead", FieldValue(request, L"GenericRead") },
        { L"GenericWrite", FieldValue(request, L"GenericWrite") },
        { L"GenericExecute", FieldValue(request, L"GenericExecute") },
        { L"GenericAll", FieldValue(request, L"GenericAll") },
        { L"SecurityRequired", FieldValue(request, L"SecurityRequired") },
        { L"MaintainHandleCount", FieldValue(request, L"MaintainHandleCount") },
        { L"PoolType", FieldValue(request, L"PoolType") },
        { L"Strategy", type == L"SymbolicLink"
            ? L"NtOpenSymbolicLinkObject + NtQuerySymbolicLinkObject"
            : (type.find(L"Port") != std::wstring::npos ? L"对象目录枚举 + R3 对象详情" : L"对象类型统计；具体对象需从对象目录页打开") },
        { L"Status", L"对象类型矩阵行详情" },
    }, L"对象类型矩阵行不对应单一对象路径，因此展示类型统计与访问掩码。"));
}
KernelOperationResult MakeNativeActionResult(const KernelActionRequest& request, const bool success, const std::wstring& operation, QueryPacket&& packet) {
    KernelOperationResult result = MakeResult(request.featureId, success, operation, std::move(packet));
    result.destructiveAction = false;
    return result;
}
void AppendObjectBasicInfoRow(QueryPacket& packet, const NtRuntime& runtime, const std::wstring& path, HANDLE handle, const LONG openStatus) {
    KOBJECT_BASIC_INFORMATION basic{};
    ULONG returned = 0;
    LONG queryStatus = kStatusNoSuchFile;
    if (handle && runtime.queryObject) {
        queryStatus = runtime.queryObject(handle, kObjectBasicInformation, &basic, static_cast<ULONG>(sizeof(basic)), &returned);
    }
    const bool hasBasic = handle && runtime.queryObject && IsSuccessStatus(queryStatus);

    packet.rows.push_back(Row({
        { L"Action", L"NativeObjectQueryDetail" },
        { L"Path", path },
        { L"OpenStatus", StatusText(openStatus) },
        { L"OpenStatusText", StatusMeaningText(openStatus) },
        { L"QueryStatus", runtime.queryObject ? StatusText(queryStatus) : L"NtQueryObject unavailable" },
        { L"QueryStatusText", runtime.queryObject ? StatusMeaningText(queryStatus) : L"NtQueryObject 未解析" },
        { L"QueryReturned", std::to_wstring(returned) },
        { L"Attributes", hasBasic ? HexText(basic.Attributes) : L"" },
        { L"AttributesText", hasBasic ? ObjectAttributesText(basic.Attributes) : L"" },
        { L"GrantedAccess", hasBasic ? HexText(basic.GrantedAccess) : L"" },
        { L"GrantedAccessText", hasBasic ? AccessMaskText(basic.GrantedAccess) : L"" },
        { L"Handles", hasBasic ? std::to_wstring(basic.HandleCount) : L"" },
        { L"Pointers", hasBasic ? std::to_wstring(basic.PointerCount) : L"" },
        { L"PagedPool", hasBasic ? std::to_wstring(basic.PagedPoolUsage) : L"" },
        { L"NonPagedPool", hasBasic ? std::to_wstring(basic.NonPagedPoolUsage) : L"" },
        { L"NameInfoSize", hasBasic ? std::to_wstring(basic.NameInfoSize) : L"" },
        { L"TypeInfoSize", hasBasic ? std::to_wstring(basic.TypeInfoSize) : L"" },
        { L"SecurityDescriptorSize", hasBasic ? std::to_wstring(basic.SecurityDescriptorSize) : L"" },
        { L"Status", hasBasic ? L"已打开并读取对象基础信息" : L"未能读取对象基础信息" },
    }, hasBasic ? AccessMaskText(basic.GrantedAccess) : StatusMeaningText(openStatus)));
}
void AppendQueriedObjectText(QueryPacket& packet, const NtRuntime& runtime, HANDLE handle, const ULONG infoClass, const std::wstring& label) {
    if (!runtime.queryObject || !handle) {
        return;
    }
    ULONG bufferSize = 4096;
    std::vector<std::byte> buffer;
    LONG status = kStatusInfoLengthMismatch;
    ULONG returned = 0;
    for (int attempt = 0; attempt < 5; ++attempt) {
        buffer.assign(bufferSize, std::byte{});
        returned = 0;
        status = runtime.queryObject(handle, infoClass, buffer.data(), bufferSize, &returned);
        if (IsSuccessStatus(status) || !IsRetryStatus(status)) {
            break;
        }
        bufferSize = std::max<ULONG>(bufferSize * 2, returned + 0x1000);
    }
    std::wstring value;
    if (IsSuccessStatus(status) && buffer.size() >= sizeof(UNICODE_STRING)) {
        const auto* counted = reinterpret_cast<const UNICODE_STRING*>(buffer.data());
        value = CountedString(*counted);
    }
    packet.rows.push_back(Row({
        { L"Action", L"NtQueryObject" },
        { L"InfoClass", std::to_wstring(infoClass) },
        { L"Field", label },
        { L"Status", StatusText(status) },
        { L"Bytes", std::to_wstring(buffer.size()) },
        { L"Returned", std::to_wstring(returned) },
        { L"Value", value },
    }, value));
}
const NtRuntime& Runtime() {
    static NtRuntime runtime = [] {
        NtRuntime result{};
        struct Library {HMODULE module=::GetModuleHandleW(L"ntdll.dll");bool owned=false;
            Library(){if(!module){module=::LoadLibraryW(L"ntdll.dll");owned=module!=nullptr;}}
            ~Library(){if(owned)::FreeLibrary(module);}};
        static const Library library;HMODULE ntdll=library.module;
        if (!ntdll) {
            return result;
        }
        result.openDirectoryObject = reinterpret_cast<NtOpenDirectoryObjectFn>(::GetProcAddress(ntdll, "NtOpenDirectoryObject"));
        result.queryDirectoryObject = reinterpret_cast<NtQueryDirectoryObjectFn>(::GetProcAddress(ntdll, "NtQueryDirectoryObject"));
        result.openSymbolicLinkObject = reinterpret_cast<NtOpenSymbolicLinkObjectFn>(::GetProcAddress(ntdll, "NtOpenSymbolicLinkObject"));
        result.querySymbolicLinkObject = reinterpret_cast<NtQuerySymbolicLinkObjectFn>(::GetProcAddress(ntdll, "NtQuerySymbolicLinkObject"));
        result.queryObject = reinterpret_cast<NtQueryObjectFn>(::GetProcAddress(ntdll, "NtQueryObject"));
        result.openFile = reinterpret_cast<NtOpenFileFn>(::GetProcAddress(ntdll, "NtOpenFile"));
        result.queryDirectoryFile = reinterpret_cast<NtQueryDirectoryFileFn>(::GetProcAddress(ntdll, "NtQueryDirectoryFile"));
        result.querySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(::GetProcAddress(ntdll, "NtQuerySystemInformation"));
        result.queryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(::GetProcAddress(ntdll, "NtQueryInformationProcess"));
        result.queryInformationThread = reinterpret_cast<NtQueryInformationThreadFn>(::GetProcAddress(ntdll, "NtQueryInformationThread"));
        result.queryInformationToken = reinterpret_cast<NtQueryInformationTokenFn>(::GetProcAddress(ntdll, "NtQueryInformationToken"));
        return result;
    }();
    return runtime;
}
HANDLE OpenDirectory(const NtRuntime& runtime, const std::wstring& path, LONG* statusOut) {
    if(path.size()>32766){if(statusOut)*statusOut=kStatusNameTooLong;return nullptr;}
    if (!runtime.openDirectoryObject || path.empty()) {
        if (statusOut) {
            *statusOut = kStatusNoSuchFile;
        }
        return nullptr;
    }

    UNICODE_STRING unicodePath = MakeUnicodeString(path);
    OBJECT_ATTRIBUTES attributes = MakeObjectAttributes(unicodePath);
    HANDLE handle = nullptr;
    const LONG status = runtime.openDirectoryObject(&handle, DIRECTORY_QUERY, &attributes);
    if (statusOut) {
        *statusOut = status;
    }
    return status==kStatusSuccess ? handle : nullptr;
}
HANDLE OpenSymbolicLink(const NtRuntime& runtime, const std::wstring& path, LONG* statusOut) {
    if(path.size()>32766){if(statusOut)*statusOut=kStatusNameTooLong;return nullptr;}
    if (!runtime.openSymbolicLinkObject || path.empty()) {
        if (statusOut) {
            *statusOut = kStatusNoSuchFile;
        }
        return nullptr;
    }

    UNICODE_STRING unicodePath = MakeUnicodeString(path);
    OBJECT_ATTRIBUTES attributes = MakeObjectAttributes(unicodePath);
    HANDLE handle = nullptr;
    const LONG status = runtime.openSymbolicLinkObject(&handle, SYMBOLIC_LINK_QUERY, &attributes);
    if (statusOut) {
        *statusOut = status;
    }
    return status==kStatusSuccess ? handle : nullptr;
}
std::wstring QuerySymbolicLinkTarget(const NtRuntime& runtime, HANDLE link,DirectoryEntry::TargetEvidence* evidence) {
    DirectoryEntry::TargetEvidence local;auto& e=evidence?*evidence:local;
    if (!runtime.querySymbolicLinkObject || !link) {
        return {};
    }

    std::vector<wchar_t> buffer(2048, L'\0');
    for(int attempt=0;attempt<4;++attempt){UNICODE_STRING target{};target.Buffer=buffer.data();target.MaximumLength=static_cast<USHORT>(buffer.size()*sizeof(wchar_t));
        e.attempted=true;e.required=0;e.status=runtime.querySymbolicLinkObject(link,&target,&e.required);
        if(e.status==kStatusSuccess){std::wstring text;e.available=BoundedCounted(target,buffer.data(),buffer.size()*sizeof(wchar_t),text);e.malformed=!e.available;return e.available?text:std::wstring{};}
        if(!IsRetryStatus(e.status))return {};if(e.required>65534){e.limited=true;return {};}
        const auto wanted=(std::max)(buffer.size()*2,static_cast<std::size_t>((e.required+1)/2));if(wanted>32767){e.limited=true;return {};}buffer.resize(wanted);
    }e.limited=true;return {};
}
void QueryBasicObjectCounts(const NtRuntime& runtime, HANDLE handle, std::wstring& handleCountText, std::wstring& pointerCountText,DirectoryEntry::BasicEvidence* evidence) {
    DirectoryEntry::BasicEvidence local;auto& e=evidence?*evidence:local;
    if (!runtime.queryObject || !handle) {
        return;
    }

    KOBJECT_BASIC_INFORMATION basic{};
    ULONG returned = 0;
    const LONG status = runtime.queryObject(handle, kObjectBasicInformation, &basic, static_cast<ULONG>(sizeof(basic)), &returned);
    e.attempted=true;e.status=status;e.returned=returned;e.malformed=status==kStatusSuccess&&returned!=sizeof(basic);e.available=status==kStatusSuccess&&!e.malformed;
    if (!e.available) {
        return;
    }
    e.value=basic;
    handleCountText = std::to_wstring(basic.HandleCount);
    pointerCountText = std::to_wstring(basic.PointerCount);
}
HANDLE OpenNamedPipeReadOnly(const NtRuntime& runtime, const std::wstring& path, LONG* statusOut, IO_STATUS_BLOCK* ioStatusOut) {
    if (!runtime.openFile || path.empty() || path.size()>32766) {
        if (statusOut) {
            *statusOut = kStatusNoSuchFile;
        }
        if (ioStatusOut) {
            *ioStatusOut = {};
        }
        return nullptr;
    }

    UNICODE_STRING unicodePath = MakeUnicodeString(path);
    OBJECT_ATTRIBUTES attributes = MakeObjectAttributes(unicodePath);
    IO_STATUS_BLOCK localIoStatus{};
    HANDLE pipe = nullptr;
    const LONG openStatus = runtime.openFile(
        &pipe,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attributes,
        &localIoStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT);
    if (statusOut) {
        *statusOut = openStatus;
    }
    if (ioStatusOut) {
        *ioStatusOut = localIoStatus;
    }
    if(openStatus!=0&&pipe&&pipe!=INVALID_HANDLE_VALUE)::CloseHandle(pipe);
    return openStatus==0&&pipe!=INVALID_HANDLE_VALUE ? pipe : nullptr;
}
void AppendDirectoryPreviewRows(QueryPacket& packet, const NtRuntime& runtime, const std::wstring& path, const std::size_t limit) {
    std::vector<std::wstring> warnings;
    const std::vector<DirectoryEntry> entries = EnumerateDirectoryFlat(runtime, path, warnings);
    packet.rows.push_back(Row({
        { L"Action", L"NativeDirectoryPreview" },
        { L"Path", path },
        { L"Children", std::to_wstring(entries.size()) },
        { L"PreviewLimit", std::to_wstring(limit) },
        { L"Warnings", std::to_wstring(warnings.size()) },
        { L"Status", entries.empty() ? L"无可显示子项或访问受限" : L"已读取目录子项预览" },
    }));
    for (const std::wstring& warning : warnings) {
        packet.warnings.push_back(warning);
    }
    std::size_t added = 0;
    for (const DirectoryEntry& entry : entries) {
        if (added >= limit) {
            break;
        }
        AppendDirectoryEntryRow(packet, L"DetailPreview", 0, entry);
        ++added;
    }
}
std::wstring DirectoryStatusText(const std::wstring& typeName, const bool canOpen, const bool hasTarget) {
    if (typeName == L"Directory") {
        return canOpen ? L"目录，可继续展开" : L"目录，当前权限无法打开";
    }
    if (typeName == L"SymbolicLink") {
        return hasTarget ? L"符号链接，已解析目标" : L"符号链接，目标未解析";
    }
    return canOpen ? L"对象可打开" : L"叶子对象或权限受限";
}
std::vector<DirectoryEntry> EnumerateDirectoryFlat(const NtRuntime& runtime,const std::wstring& directoryPath,std::vector<std::wstring>& warnings,DirectoryQueryEvidence* evidence,const DirectoryQueryOptions& options) {
    DirectoryQueryEvidence local;auto& source=evidence?*evidence:local;source.path=directoryPath;std::vector<DirectoryEntry> entries;
    source.apiAvailable=runtime.openDirectoryObject&&runtime.queryDirectoryObject;
    if(!source.apiAvailable){warnings.push_back(L"NtOpenDirectoryObject/NtQueryDirectoryObject 不可用。");return entries;}
    source.openAttempted=true;HANDLE directory=OpenDirectory(runtime,directoryPath,&source.openStatus);
    if(!directory){source.malformed=source.openStatus==kStatusSuccess;warnings.push_back(std::wstring(L"无法打开对象目录 ")+directoryPath+L"，NTSTATUS="+StatusText(source.openStatus));return entries;}
    if(directory==INVALID_HANDLE_VALUE){source.malformed=true;return entries;}
    source.opened=true;OwnedObject owned{directory,&source.closeAttempted,&source.closed,&source.closeError};
    std::vector<std::byte> buffer(64*1024);ULONG context=0;BOOLEAN restart=TRUE;const auto started=::GetTickCount64();
    std::set<std::tuple<std::wstring,std::wstring,ULONG>> seen;
    for(;;){
        if(options.cancelled&&options.cancelled()){source.cancelled=true;break;}
        if(source.queried>=options.maxEntries||::GetTickCount64()-started>=options.maxDurationMs||(options.deadlineTick&&::GetTickCount64()>=options.deadlineTick)){source.limited=true;break;}
        source.returned=0;const auto oldContext=context;source.queryAttempted=true;
        source.lastQueryStatus=runtime.queryDirectoryObject(directory,buffer.data(),static_cast<ULONG>(buffer.size()),TRUE,restart,&context,&source.returned);
        if(source.lastQueryStatus==kStatusNoMoreEntries){source.complete=true;break;}
        if(IsRetryStatus(source.lastQueryStatus)){
            if(source.returned>4u*1024u*1024u||buffer.size()>=4u*1024u*1024u){source.limited=true;break;}
            buffer.resize((std::min<std::size_t>)(4u*1024u*1024u,(std::max)(buffer.size()*2,static_cast<std::size_t>(source.returned))));context=oldContext;continue;
        }
        if(source.lastQueryStatus!=kStatusSuccess){warnings.push_back(std::wstring(L"查询对象目录失败 ")+directoryPath+L"，NTSTATUS="+StatusText(source.lastQueryStatus));break;}
        restart=FALSE;
        if(source.returned<sizeof(KOBJECT_DIRECTORY_INFORMATION)||source.returned>buffer.size()){source.malformed=true;break;}
        const auto* native=reinterpret_cast<const KOBJECT_DIRECTORY_INFORMATION*>(buffer.data());
        if(!native->Name.Buffer&&!native->Name.Length&&!native->Name.MaximumLength&&!native->TypeName.Buffer&&!native->TypeName.Length&&!native->TypeName.MaximumLength){source.complete=true;break;}
        DirectoryEntry entry;entry.parentPath=directoryPath;
        if(!BoundedCounted(native->Name,buffer.data(),source.returned,entry.name)||!BoundedCounted(native->TypeName,buffer.data(),source.returned,entry.typeName)||entry.name.empty()||entry.typeName.empty()){source.malformed=true;break;}
        if(!seen.emplace(entry.name,entry.typeName,context).second){source.cycle=true;break;}++source.queried;
        entry.fullPath=JoinObjectPath(directoryPath,entry.name);
        entry.metadataRequested=options.probeMetadata&&((entry.typeName==L"Directory"&&options.probeDirectories)||entry.typeName==L"SymbolicLink");
        HANDLE child=nullptr;
        if(entry.metadataRequested&&entry.typeName==L"Directory"){entry.openAttempted=runtime.openDirectoryObject!=nullptr;child=OpenDirectory(runtime,entry.fullPath,&entry.openStatus);}
        else if(entry.metadataRequested&&entry.typeName==L"SymbolicLink"){entry.openAttempted=runtime.openSymbolicLinkObject!=nullptr;child=OpenSymbolicLink(runtime,entry.fullPath,&entry.openStatus);}
        if(child&&child!=INVALID_HANDLE_VALUE){entry.canOpen=true;OwnedObject object{child,&entry.closeAttempted,&entry.closed,&entry.closeError};
            QueryBasicObjectCounts(runtime,child,entry.handleCountText,entry.pointerCountText,&entry.basic);
            if(entry.typeName==L"SymbolicLink")entry.targetPath=QuerySymbolicLinkTarget(runtime,child,&entry.target);
            object.close();
        }else if(child==INVALID_HANDLE_VALUE||(entry.openAttempted&&entry.openStatus==kStatusSuccess))source.malformed=true;
        if(entry.handleCountText.empty())entry.handleCountText=L"N/A";if(entry.pointerCountText.empty())entry.pointerCountText=L"N/A";
        entry.statusText=DirectoryStatusText(entry.typeName,entry.canOpen,!entry.targetPath.empty());entries.push_back(std::move(entry));
    }
    owned.close();return entries;
}
void AppendDirectoryEntryRow(
    QueryPacket& packet,
    const std::wstring& source,
    const std::size_t depth,
    const DirectoryEntry& entry,
    const std::wstring& enumApi) {
    packet.rows.push_back(Row({
        { L"Source", source },
        { L"EnumApi", enumApi },
        { L"enumApi", enumApi },
        { L"枚举 API", enumApi },
        { L"Depth", std::to_wstring(depth) },
        { L"Parent", entry.parentPath },
        { L"Directory", entry.parentPath },
        { L"directoryPath", entry.parentPath },
        { L"sourceDirectory", entry.parentPath },
        { L"Name", entry.name },
        { L"objectName", entry.name },
        { L"linkName", entry.name },
        { L"Type", entry.typeName },
        { L"objectType", entry.typeName },
        { L"Path", entry.fullPath },
        { L"fullPath", entry.fullPath },
        { L"Target", entry.targetPath.empty() ? L"" : entry.targetPath },
        { L"targetPath", entry.targetPath.empty() ? L"" : entry.targetPath },
        { L"symbolicTarget", entry.targetPath.empty() ? L"" : entry.targetPath },
        { L"dosCandidate", entry.targetPath.empty() ? L"" : JoinStrings(DosPathCandidatesFromNtPath(entry.targetPath), L"; ") },
        { L"Win32Path", entry.targetPath.empty() ? L"" : JoinStrings(DosPathCandidatesFromNtPath(entry.targetPath), L"; ") },
        { L"Handles", entry.handleCountText },
        { L"Pointers", entry.pointerCountText },
        { L"Status", entry.statusText },
        { L"statusText", entry.statusText },
    }, entry.targetPath.empty() ? entry.statusText : entry.targetPath));
}
KernelOperationResult MakeResult(KernelFeatureId /*id*/, const bool success, const std::wstring& operation, QueryPacket&& packet) {
    KernelOperationResult result;
    result.supported = true;
    result.success = success;
    result.message = operation + (success ? L" 完成。" : L" 未完整完成。");
    if (!packet.warnings.empty()) {
        result.message += L" ";
        for (const std::wstring& warning : packet.warnings) {
            result.message += warning;
            result.message += L" ";
        }
    }
    for (KernelResultRow& row : packet.rows) {
        result.rows.push_back(std::move(row));
    }
    for (const std::wstring& warning : packet.warnings) {
        result.rows.push_back(Row({
            { L"Warning", warning },
        }, warning));
    }
    return result;
}
void AppendDirectoryRoot(QueryPacket& packet, const NtRuntime& runtime, const std::wstring& root, const std::wstring& source, const std::wstring& filter) {
    const std::vector<DirectoryEntry> entries = EnumerateDirectoryFlat(runtime, root, packet.warnings);
    if (entries.empty()) {
        if (filter.empty() || ContainsI(root, filter)) {
            packet.rows.push_back(Row({
                { L"Source", source },
                { L"Path", root },
                { L"Status", L"无可显示子项或访问受限" },
            }));
        }
        return;
    }
    for (const DirectoryEntry& entry : entries) {
        if (MatchesDirectoryFilter(entry, filter)) {
            AppendDirectoryEntryRow(packet, source, 0, entry);
        }
    }
}
std::vector<DWORD> DiscoverSessionIds(const NtRuntime& runtime,DirectoryQueryEvidence* evidence,DWORD* currentSessionError,const DirectoryQueryOptions& options,bool* currentSessionKnown) {
    // DiscoverSessionIds mirrors the original BaseNamedObjects worker by
    // enumerating numeric children under \Sessions. Inputs are the resolved NT
    // runtime; processing also includes the current process session and session
    // 0; output is de-duplicated and sorted for stable UI order.
    DWORD currentSessionId = 0;
    ::SetLastError(ERROR_SUCCESS);const auto currentKnown=::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId)!=FALSE;
    if(currentSessionError)*currentSessionError=currentKnown?ERROR_SUCCESS: ::GetLastError();
    if(currentSessionKnown)*currentSessionKnown=currentKnown;
    std::vector<DWORD> sessions{ 0, currentSessionId };
    std::vector<std::wstring> warnings;
    auto discoveryOptions=options;discoveryOptions.probeMetadata=false;
    const std::vector<DirectoryEntry> entries = EnumerateDirectoryFlat(runtime, L"\\Sessions", warnings,evidence,discoveryOptions);
    for (const DirectoryEntry& entry : entries) {
        wchar_t* end = nullptr;
        const unsigned long long value = std::wcstoull(entry.name.c_str(), &end, 10);
        if (!entry.name.empty()&&std::all_of(entry.name.begin(),entry.name.end(),[](wchar_t c){return c>=L'0'&&c<=L'9';})&&value<=MAXDWORD&&end != entry.name.c_str() && *end == L'\0') {
            sessions.push_back(static_cast<DWORD>(value));
        }
    }
    std::sort(sessions.begin(), sessions.end());
    sessions.erase(std::unique(sessions.begin(), sessions.end()), sessions.end());
    return sessions;
}
std::vector<std::wstring> CommonNamespaceRoots(DirectoryQueryEvidence* discovery,DWORD* currentSessionError,const DirectoryQueryOptions& options,bool* currentSessionKnown) {
    const NtRuntime& runtime = Runtime();
    std::vector<std::wstring> roots{
        L"\\",
        L"\\Device",
        L"\\Driver",
        L"\\FileSystem",
        L"\\FileSystem\\Filters",
        L"\\BaseNamedObjects",
        L"\\RPC Control",
        L"\\Callback",
        L"\\KernelObjects",
        L"\\KnownDlls",
        L"\\KnownDlls32",
        L"\\Nls",
        L"\\ObjectTypes",
        L"\\Security",
        L"\\Sessions",
    };
    for (const DWORD sessionId : DiscoverSessionIds(runtime,discovery,currentSessionError,options,currentSessionKnown)) {
        const std::wstring prefix = std::wstring(L"\\Sessions\\") + std::to_wstring(sessionId);
        roots.push_back(prefix + L"\\BaseNamedObjects");
        roots.push_back(prefix + L"\\DosDevices");
        roots.push_back(prefix + L"\\Windows");
    }
    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
    return roots;
}
KernelOperationResult QueryObjectNamespaceOverview(const KernelRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    for (const std::wstring& root : CommonNamespaceRoots()) {
        AppendDirectoryRoot(packet, runtime, root, root, request.filterText);
    }
    return MakeResult(request.featureId, !packet.rows.empty(), L"对象命名空间枚举", std::move(packet));
}
KernelOperationResult ExecuteNativeObjectDetail(const KernelActionRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    std::wstring type = ObjectTypeNameFromAction(request);
    if (request.featureId == KernelFeatureId::ObjectTypeMatrix && !type.empty()) {
        AppendObjectTypeDetailRow(request, type, packet);
        return MakeNativeActionResult(request, true, L"R3 对象类型详情", std::move(packet));
    }

    const std::wstring path = NativePathFromAction(request);
    if (path.empty()) {
        if (request.featureId == KernelFeatureId::ObjectTypeMatrix && !type.empty()) {
            AppendObjectTypeDetailRow(request, type, packet);
            return MakeNativeActionResult(request, true, L"R3 对象类型详情", std::move(packet));
        }
        packet.warnings.push_back(L"当前行没有 Path/NtPath/Parent+Name，无法定位对象。");
        return MakeNativeActionResult(request, false, L"R3 对象详情", std::move(packet));
    }
    if (type.empty() && (StartsWithI(path, L"\\Device\\NamedPipe") || StartsWithI(path, L"\\??\\PIPE"))) {
        type = L"NamedPipe";
    }
    if (type.empty() && (path == L"\\" || path == FieldValue(request, L"Directory"))) {
        type = L"Directory";
    }

    HANDLE handle = nullptr;
    LONG openStatus = kStatusNoSuchFile;
    IO_STATUS_BLOCK ioStatus{};
    if (_wcsicmp(type.c_str(), L"SymbolicLink") == 0) {
        handle = OpenSymbolicLink(runtime, path, &openStatus);
    } else if (_wcsicmp(type.c_str(), L"Directory") == 0 || path == L"\\") {
        handle = OpenDirectory(runtime, path, &openStatus);
    } else if (_wcsicmp(type.c_str(), L"NamedPipe") == 0 || StartsWithI(path, L"\\Device\\NamedPipe") || StartsWithI(path, L"\\??\\PIPE")) {
        type = L"NamedPipe";
        handle = OpenNamedPipeReadOnly(runtime, path, &openStatus, &ioStatus);
    }

    if (!handle && _wcsicmp(type.c_str(), L"Directory") != 0 && _wcsicmp(type.c_str(), L"SymbolicLink") != 0 && _wcsicmp(type.c_str(), L"NamedPipe") != 0) {
        packet.rows.push_back(Row({
            { L"Action", L"NativeObjectQueryDetail" },
            { L"Path", path },
            { L"Type", type.empty() ? L"<unknown>" : type },
            { L"Status", L"未打开" },
            { L"Reason", L"该对象类型需要专用 NtOpen* API；轻量版当前仅对 Directory/SymbolicLink/NamedPipe 执行安全只读打开。" },
            { L"Next", L"如需深入该类型，应新增专用 opener 并只走 R3 Native 或 ArkDriverClient。" },
        }));
        return MakeNativeActionResult(request, false, L"R3 对象详情", std::move(packet));
    }

    AppendObjectBasicInfoRow(packet, runtime, path, handle, openStatus);
    AppendQueriedObjectText(packet, runtime, handle, kObjectNameInformation, L"Name");
    AppendQueriedObjectText(packet, runtime, handle, kObjectTypeInformation, L"Type");

    if (_wcsicmp(type.c_str(), L"Directory") == 0 && handle) {
        AppendDirectoryPreviewRows(packet, runtime, path, 32);
    } else if (_wcsicmp(type.c_str(), L"SymbolicLink") == 0) {
        std::wstring target;
        if (handle) {
            target = QuerySymbolicLinkTarget(runtime, handle);
        }
        const std::vector<std::wstring> candidates = DosPathCandidatesFromNtPath(target);
        packet.rows.push_back(Row({
            { L"Action", L"NativeSymbolicLinkDetail" },
            { L"Path", path },
            { L"OpenStatus", StatusText(openStatus) },
            { L"OpenStatusText", StatusMeaningText(openStatus) },
            { L"Target", target },
            { L"DosCandidates", JoinStrings(candidates, L"; ") },
            { L"Status", target.empty() ? L"符号链接目标未解析" : L"已解析符号链接目标" },
        }, target));
    } else if (_wcsicmp(type.c_str(), L"NamedPipe") == 0) {
        packet.rows.push_back(Row({
            { L"Action", L"NativeNamedPipeDetail" },
            { L"NtPath", path },
            { L"Win32Path", StartsWithI(path, L"\\Device\\NamedPipe\\") ? std::wstring(L"\\\\.\\pipe\\") + path.substr(18) : L"" },
            { L"OpenStatus", StatusText(openStatus) },
            { L"OpenStatusText", StatusMeaningText(openStatus) },
            { L"IoStatus", StatusText(static_cast<LONG>(ioStatus.Status)) },
            { L"IoStatusText", StatusMeaningText(static_cast<LONG>(ioStatus.Status)) },
            { L"Information", std::to_wstring(static_cast<std::uint64_t>(ioStatus.Information)) },
            { L"Status", handle ? L"可只读打开管道对象" : L"不可打开、管道忙或权限受限" },
        }));
    }

    if (handle) {
        ::CloseHandle(handle);
    }
    return MakeNativeActionResult(request, handle != nullptr, L"R3 对象详情", std::move(packet));
}
}
