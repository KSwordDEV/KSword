#include "R3WindowShared.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <algorithm>
#include <array>
#include <objbase.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <stdexcept>

namespace ks::cli {
namespace {
using ksword::ark::DriverClient;
using ksword::ark::KeyboardHotkeyEntry;
using ksword::ark::KeyboardHotkeyEnumResult;

int ioCode(const ksword::ark::IoResult& io) {
    if (io.ok) return 0;
    if (io.deviceOpenFailed) return 2;
    if (io.win32Error == ERROR_NOT_SUPPORTED || io.win32Error == ERROR_INVALID_FUNCTION ||
        io.win32Error == ERROR_CALL_NOT_IMPLEMENTED || io.win32Error == ERROR_PROC_NOT_FOUND) return 5;
    return 3;
}
Json ioData(const ksword::ark::IoResult& io) {
    return Json::object({{L"success",Json::boolean(io.ok)}, {L"deviceOpenFailed",Json::boolean(io.deviceOpenFailed)},
        {L"win32Error",Json::number(io.win32Error)}, {L"bytesReturned",Json::number(io.bytesReturned)}});
}
void requireConfirmed(const Args& a) {
    if (!a.has(L"--confirm")) throw std::invalid_argument("missing option --confirm");
}
void requireCreation(const Args& a) {
    (void)a.require(L"--creation-time");
    if (!a.integer(L"--creation-time")) throw std::invalid_argument("--creation-time must be positive");
}

Json hotkeyRow(const KeyboardHotkeyEntry& row) {
    return Json::object({{L"source",Json::number(row.source)}, {L"status",Json::number(row.status)},
        {L"flags",Json::hex(row.flags)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(row.lastStatus))},
        {L"processId",Json::number(row.processId)}, {L"threadId",Json::number(row.threadId)},
        {L"sessionId",Json::number(row.sessionId)}, {L"hotkeyId",Json::number(row.hotkeyId)},
        {L"modifiers",Json::hex(row.modifiers)}, {L"modifierFlags2",Json::hex(row.modifierFlags2)}, {L"virtualKey",Json::number(row.virtualKey)},
        {L"object",Json::hex(row.hotkeyObject)}, {L"nextObject",Json::hex(row.nextHotkeyObject)}, {L"snapshotHash",Json::hex(row.snapshotHash)},
        {L"sessionGlobals",Json::hex(row.sessionGlobals)}, {L"threadInfo",Json::hex(row.threadInfo)},
        {L"threadObject",Json::hex(row.threadObject)}, {L"windowObject",Json::hex(row.windowObject)},
        {L"windowHandle",Json::hex(row.windowHandle)}, {L"destinationHandle",Json::hex(row.destinationHandle)},
        {L"callbackAddress",Json::hex(row.callbackAddress)}, {L"bucketIndex",Json::number(row.bucketIndex)},
        {L"childListFlink",Json::hex(row.childListFlink)}, {L"childListBlink",Json::hex(row.childListBlink)},
        {L"depth",Json::number(row.depth)}, {L"objectSize",Json::number(row.objectSize)},
        {L"entryFlags",Json::hex(row.entryFlags)}, {L"detail",Json::string(row.detail)}});
}
bool completeHotkeys(const KeyboardHotkeyEnumResult& r) {
    return r.io.ok && r.version == KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION &&
        r.status == KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK && r.lastStatus >= 0 &&
        r.totalCount == r.returnedCount && r.entries.size() == r.returnedCount;
}
unsigned long hotkeyFlags() {
    return KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS |
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS;
}
KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY hotkeySnapshot(const KeyboardHotkeyEntry& row) {
    KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY result{};
    result.source=row.source; result.status=row.status; result.flags=row.flags; result.bucketIndex=row.bucketIndex;
    result.depth=row.depth; result.modifiers=row.modifiers; result.modifierFlags2=row.modifierFlags2;
    result.virtualKey=row.virtualKey; result.hotkeyId=row.hotkeyId; result.processId=row.processId; result.threadId=row.threadId;
    result.lastStatus=row.lastStatus; result.hotkeyObject=row.hotkeyObject; result.nextHotkeyObject=row.nextHotkeyObject;
    result.sessionGlobals=row.sessionGlobals; result.threadInfo=row.threadInfo; result.threadObject=row.threadObject;
    result.windowObject=row.windowObject; result.windowHandle=row.windowHandle; result.destinationHandle=row.destinationHandle;
    result.callbackAddress=row.callbackAddress; result.childListFlink=row.childListFlink; result.childListBlink=row.childListBlink;
    result.snapshotHash=row.snapshotHash; result.objectSize=row.objectSize; result.entryFlags=row.entryFlags; result.sessionId=row.sessionId;
    return result;
}
Result registeredEnum(const Args& a) {
    const auto limit=a.u32(L"--limit",2048);
    if (!limit || limit>2048) throw std::invalid_argument("--limit must be 1..2048");
    process::Lease lease(a);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable or changed."}};
    MSG message{}; (void)::PeekMessageW(&message,nullptr,0,0,PM_NOREMOVE);
    const auto r=DriverClient{}.enumerateKeyboardHotkeys(lease.pid,hotkeyFlags(),2048);
    if (!r.io.ok) return {ioCode(r.io),Json::object({{L"target",lease.json()}, {L"transport",ioData(r.io)}}),{L"R0 registered-hotkey enumeration failed."}};
    std::vector<Json> rows; for (const auto& row:r.entries) {if(rows.size()>=limit)break;rows.push_back(hotkeyRow(row));}
    const bool complete=completeHotkeys(r) && lease.alive();
    const bool displayTruncated=rows.size()<r.entries.size();
    const int code=!lease.alive()?3:r.status==KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED || r.status==KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND ||
        r.status==KSWORD_ARK_KEYBOARD_ENUM_STATUS_PATTERN_NOT_FOUND || r.status==KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE?5:complete?0:6;
    return {code,Json::object({{L"target",lease.json()}, {L"transport",ioData(r.io)}, {L"version",Json::number(r.version)},
        {L"queryStatus",Json::number(r.status)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))},
        {L"sessionGlobals",Json::hex(r.sessionGlobals)}, {L"totalCount",Json::number(r.totalCount)},
        {L"returnedCount",Json::number(r.returnedCount)}, {L"complete",Json::boolean(complete)},
        {L"displayTruncated",Json::boolean(displayTruncated)}, {L"entries",Json::array(rows)}}),
        {L"R0 registered hotkeys are limited to the caller's USER session. Complete V4 snapshots are required for deletion."}};
}
Result registeredClear(const Args& a) {
    requireConfirmed(a); requireCreation(a);
    (void)a.require(L"--tid"); (void)a.require(L"--object"); (void)a.require(L"--snapshot-hash"); (void)a.require(L"--session-id");
    const auto tid=a.u32(L"--tid"), session=a.u32(L"--session-id");
    const auto object=a.integer(L"--object"), hash=a.integer(L"--snapshot-hash");
    if(!tid || !object || !hash)throw std::invalid_argument("--tid, --object and --snapshot-hash must be positive");
    process::Lease lease(a);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}, {L"attempted",Json::boolean(false)}}),{L"Process identity is unavailable or changed."}};
    MSG message{}; (void)::PeekMessageW(&message,nullptr,0,0,PM_NOREMOVE);
    const DriverClient client;
    const auto before=client.enumerateKeyboardHotkeys(lease.pid,hotkeyFlags(),2048);
    if (!before.io.ok) return {ioCode(before.io),Json::object({{L"target",lease.json()}, {L"transport",ioData(before.io)}, {L"attempted",Json::boolean(false)}}),{L"Could not acquire a current registered-hotkey snapshot."}};
    if (!completeHotkeys(before)) return {5,Json::object({{L"target",lease.json()}, {L"queryStatus",Json::number(before.status)}, {L"attempted",Json::boolean(false)}}),{L"A complete V4 snapshot is required before deleting a registered hotkey."}};
    const KeyboardHotkeyEntry* selected=nullptr;
    for(const auto& row:before.entries) {
        if(row.source!=KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_HOTKEY_TABLE || row.processId!=lease.pid || row.threadId!=tid ||
           row.sessionId!=session || row.hotkeyObject!=object || row.snapshotHash!=hash)continue;
        if(selected)return {3,Json::object({{L"target",lease.json()}, {L"attempted",Json::boolean(false)}}),{L"The hotkey identity is ambiguous."}};
        selected=&row;
    }
    if(!selected || !lease.alive())return {3,Json::object({{L"target",lease.json()}, {L"attempted",Json::boolean(false)}}),{L"The enumerated hotkey no longer matches the requested process, session or snapshot."}};
    constexpr unsigned long unsafe=KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_HAS_CHILDREN |
        KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_PLACEHOLDER | KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_CALLBACK;
    if(!(selected->entryFlags&KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_MUTABLE) ||
       !(selected->entryFlags&KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_MAIN) || (selected->entryFlags&unsafe))
        return {5,Json::object({{L"target",lease.json()}, {L"selected",hotkeyRow(*selected)}, {L"attempted",Json::boolean(false)}}),{L"This row is not a mutable main registered hotkey."}};
    const auto chosen=hotkeyRow(*selected);
    const auto mutation=client.mutateKeyboardHotkey(hotkeySnapshot(*selected),KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_DELETE,0,0);
    constexpr unsigned long required=KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_IDENTITY_VALIDATED |
        KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CALLER_VALIDATED | KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_SNAPSHOT_VALIDATED |
        KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CHANGED;
    const auto flags=mutation.response.responseFlags;
    const bool changed=mutation.io.ok && (flags&KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CHANGED) &&
        !(flags&KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_ROLLED_BACK);
    const bool accepted=mutation.io.ok && mutation.response.status==KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK &&
        (flags&required)==required && changed;
    KeyboardHotkeyEnumResult after{}; bool rechecked=false,present=false;
    if(accepted && lease.alive()) {
        after=client.enumerateKeyboardHotkeys(lease.pid,hotkeyFlags(),2048); rechecked=completeHotkeys(after);
        if(rechecked) for(const auto& row:after.entries)if(row.hotkeyObject==object){present=true;break;}
    }
    const bool verified=accepted && rechecked && !present && lease.alive();
    const int code=verified?0:changed||accepted?6:mutation.io.ok?3:
        mutation.io.deviceOpenFailed?2:6;
    return {code,Json::object({{L"target",lease.json()}, {L"selected",chosen}, {L"attempted",Json::boolean(true)},
        {L"transport",ioData(mutation.io)}, {L"status",mutation.io.ok?Json::number(mutation.response.status):Json{}},
        {L"lastStatus",mutation.io.ok?Json::hex(static_cast<std::uint32_t>(mutation.response.lastStatus)):Json{}},
        {L"responseFlags",mutation.io.ok?Json::hex(flags):Json{}}, {L"changed",Json::boolean(changed)},
        {L"readbackComplete",Json::boolean(rechecked)}, {L"objectStillPresent",rechecked?Json::boolean(present):Json{}},
        {L"verified",Json::boolean(verified)}}),
        code?std::vector<std::wstring>{L"A failed transport may leave the effect unknown; inspect current state before retrying."}:std::vector<std::wstring>{}};
}
Result activationQuery(const Args& a) {
    window::Lease lease(a);
    if(!lease.matches || !lease.ownerMatches())return {3,Json::object({{L"target",lease.json()}}),{L"Window, process or thread identity changed."}};
    DWORD_PTR value=0; ::SetLastError(ERROR_SUCCESS);
    const bool read=::SendMessageTimeoutW(lease.handle,WM_GETHOTKEY,0,0,SMTO_ABORTIFHUNG|SMTO_BLOCK,500,&value)!=0;
    const DWORD error=read ? ERROR_SUCCESS : ::GetLastError();
    const bool stable=lease.ownerMatches();
    return {read&&stable?0:3,Json::object({{L"target",lease.json()}, {L"rawHotkey",read&&stable?Json::number(LOWORD(value)):Json{}},
        {L"win32Error",error?Json::number(error):Json{}}, {L"ownerStillMatches",Json::boolean(stable)}}),
        {L"WM_GETHOTKEY reports the window activation hotkey; it does not enumerate registered global hotkeys."}};
}
Result activationClear(const Args& a) {
    requireConfirmed(a); (void)a.require(L"--expected-hotkey"); const auto expected=a.u32(L"--expected-hotkey");
    if(!expected || expected>0xffff)throw std::invalid_argument("--expected-hotkey must be 1..65535");
    window::Lease lease(a);
    if(!lease.matches || !lease.ownerMatches())return {3,Json::object({{L"target",lease.json()}, {L"attempted",Json::boolean(false)}}),{L"Window, process or thread identity changed."}};
    DWORD_PTR before=0; ::SetLastError(ERROR_SUCCESS);
    if(!::SendMessageTimeoutW(lease.handle,WM_GETHOTKEY,0,0,SMTO_ABORTIFHUNG|SMTO_BLOCK,500,&before))
        return {3,Json::object({{L"target",lease.json()}, {L"attempted",Json::boolean(false)}, {L"win32Error",Json::number(::GetLastError())}}),{L"Could not read the current window activation hotkey."}};
    if(LOWORD(before)!=expected || !lease.ownerMatches())return {3,Json::object({{L"target",lease.json()}, {L"observed",Json::number(LOWORD(before))}, {L"attempted",Json::boolean(false)}}),{L"Window identity or activation hotkey changed."}};
    DWORD_PTR response=0; ::SetLastError(ERROR_SUCCESS);
    const bool returned=::SendMessageTimeoutW(lease.handle,WM_SETHOTKEY,0,0,SMTO_ABORTIFHUNG|SMTO_BLOCK,500,&response)!=0;
    const DWORD error=returned ? ERROR_SUCCESS : ::GetLastError();
    DWORD_PTR after=0; const bool readback=returned && static_cast<LRESULT>(response)>0 && lease.ownerMatches() &&
        ::SendMessageTimeoutW(lease.handle,WM_GETHOTKEY,0,0,SMTO_ABORTIFHUNG|SMTO_BLOCK,500,&after)!=0 && lease.ownerMatches();
    const bool verified=readback && LOWORD(after)==0;
    const int code=verified?0:!returned?6:static_cast<LRESULT>(response)<=0?3:6;
    return {code,Json::object({{L"target",lease.json()}, {L"attempted",Json::boolean(true)}, {L"before",Json::number(LOWORD(before))},
        {L"nativeReturned",Json::boolean(returned)}, {L"nativeResult",returned?Json::signedNumber(static_cast<std::int32_t>(response)):Json{}},
        {L"win32Error",error?Json::number(error):Json{}}, {L"after",readback?Json::number(LOWORD(after)):Json{}},
        {L"verified",Json::boolean(verified)}}),code?std::vector<std::wstring>{L"A timeout or failed readback may leave the effect unknown; inspect before retrying."}:std::vector<std::wstring>{}};
}
struct LinkIdentity {
    bool valid=false; DWORD error=0, volume=0; std::uint64_t fileId=0,size=0,lastWrite=0;
};
std::uint64_t timeValue(const FILETIME& value) {
    return (static_cast<std::uint64_t>(value.dwHighDateTime)<<32)|value.dwLowDateTime;
}
LinkIdentity linkIdentity(const std::wstring& path) {
    LinkIdentity result;
    ks::r3::common::UniqueHandle file(::CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr));
    if(!file.valid()){result.error=::GetLastError();return result;}
    BY_HANDLE_FILE_INFORMATION info{};
    if(!::GetFileInformationByHandle(file.get(),&info)){result.error=::GetLastError();return result;}
    result.volume=info.dwVolumeSerialNumber;
    result.fileId=(static_cast<std::uint64_t>(info.nFileIndexHigh)<<32)|info.nFileIndexLow;
    result.size=(static_cast<std::uint64_t>(info.nFileSizeHigh)<<32)|info.nFileSizeLow;
    result.lastWrite=timeValue(info.ftLastWriteTime);
    result.valid=result.volume && result.fileId && result.size && !(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY);
    if(!result.valid)result.error=ERROR_INVALID_DATA;
    return result;
}
bool sameLink(const LinkIdentity& a,const LinkIdentity& b,bool stableOnly=false) {
    return a.valid && b.valid && a.volume==b.volume && a.fileId==b.fileId &&
        (stableOnly || (a.size==b.size && a.lastWrite==b.lastWrite));
}
Json linkIdentityJson(const LinkIdentity& id) {
    return Json::object({{L"valid",Json::boolean(id.valid)}, {L"win32Error",Json::number(id.error)},
        {L"volumeSerial",id.valid?Json::hex(id.volume):Json{}}, {L"fileId",id.valid?Json::hex(id.fileId):Json{}},
        {L"size",id.valid?Json::count(id.size):Json{}}, {L"lastWriteTime",id.valid?Json::count(id.lastWrite):Json{}}});
}
std::wstring normalizedPath(const std::wstring& path) {
    if(path.empty())return {};
    const DWORD required=::GetFullPathNameW(path.c_str(),0,nullptr,nullptr);
    if(!required || required>32768)return {};
    std::wstring full(required,L'\0'); const DWORD length=::GetFullPathNameW(path.c_str(),required,full.data(),nullptr);
    if(!length || length>=required)return {};
    full.resize(length);
    const DWORD longRequired=::GetLongPathNameW(full.c_str(),nullptr,0);
    if(longRequired && longRequired<=32768) {
        std::wstring expanded(longRequired,L'\0');
        const DWORD longLength=::GetLongPathNameW(full.c_str(),expanded.data(),longRequired);
        if(longLength && longLength<longRequired){expanded.resize(longLength);return expanded;}
    }
    return full;
}
bool samePath(const std::wstring& left,const std::wstring& right) {
    const auto a=normalizedPath(left),b=normalizedPath(right);
    if(a.empty() || b.empty())return false;
    if(::CompareStringOrdinal(a.c_str(),static_cast<int>(a.size()),b.c_str(),static_cast<int>(b.size()),TRUE)==CSTR_EQUAL)return true;
    return sameLink(linkIdentity(a),linkIdentity(b),true);
}
struct LinkAccess {
    HRESULT apartment=E_FAIL, status=E_FAIL; IShellLinkW* link=nullptr; IPersistFile* persist=nullptr;
    LinkAccess(const std::wstring& path,DWORD mode) {
        apartment=::CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
        if(FAILED(apartment)){status=apartment;return;}
        status=::CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&link));
        if(SUCCEEDED(status)&&!link)status=E_POINTER;
        if(SUCCEEDED(status))status=link->QueryInterface(IID_PPV_ARGS(&persist));
        if(SUCCEEDED(status)&&!persist)status=E_NOINTERFACE;
        if(SUCCEEDED(status))status=persist->Load(path.c_str(),mode);
    }
    ~LinkAccess(){if(persist)persist->Release();if(link)link->Release();if(SUCCEEDED(apartment))::CoUninitialize();}
    LinkAccess(const LinkAccess&)=delete; LinkAccess& operator=(const LinkAccess&)=delete;
};
bool readLink(LinkAccess& access,WORD& hotkey,std::wstring& target) {
    if(FAILED(access.status))return false;
    std::array<wchar_t,32768> buffer{}; WIN32_FIND_DATAW data{};
    access.status=access.link->GetHotkey(&hotkey);
    if(SUCCEEDED(access.status))access.status=access.link->GetPath(buffer.data(),static_cast<int>(buffer.size()),&data,SLGP_UNCPRIORITY);
    if(FAILED(access.status))return false;
    target=buffer.data();return !target.empty();
}
std::wstring linkPath(const Args& a) {
    const auto path=a.require(L"--path");
    if(path.size()<4 || ::CompareStringOrdinal(path.c_str()+path.size()-4,4,L".lnk",4,TRUE)!=CSTR_EQUAL)
        throw std::invalid_argument("--path must name a .lnk file");
    return path;
}
Result shortcutQuery(const Args& a) {
    const auto path=linkPath(a); const auto before=linkIdentity(path);
    if(!before.valid)return {3,Json::object({{L"path",Json::string(path)}, {L"identity",linkIdentityJson(before)}}),{L"Shortcut file identity is unavailable."}};
    LinkAccess access(path,STGM_READ); WORD hotkey=0;std::wstring target;
    const bool read=readLink(access,hotkey,target); const auto after=linkIdentity(path);
    const bool complete=read && sameLink(before,after);
    return {complete?0:read?6:3,Json::object({{L"path",Json::string(path)}, {L"identity",linkIdentityJson(before)},
        {L"target",read?Json::string(target):Json{}}, {L"hotkey",read?Json::number(hotkey):Json{}},
        {L"hresult",Json::hex(static_cast<std::uint32_t>(access.status))}, {L"identityStable",Json::boolean(sameLink(before,after))}}),
        {L"This reads the shortcut configuration, not a live Explorer registration."}};
}
Result shortcutClear(const Args& a) {
    requireConfirmed(a);requireCreation(a);const auto path=linkPath(a);
    for(const auto* option:{L"--volume-serial",L"--file-id",L"--size",L"--last-write-time",L"--expected-hotkey",L"--target"})(void)a.require(option);
    LinkIdentity expected{};expected.volume=a.u32(L"--volume-serial");expected.fileId=a.integer(L"--file-id");
    expected.size=a.integer(L"--size");expected.lastWrite=a.integer(L"--last-write-time");
    expected.valid=expected.volume && expected.fileId && expected.size;
    const auto expectedHotkey=a.u32(L"--expected-hotkey");const auto target=a.require(L"--target");
    if(!expected.valid || !expectedHotkey || expectedHotkey>0xffff)throw std::invalid_argument("shortcut identity and expected hotkey must be valid and nonzero");
    process::Lease lease(a);
    if(!lease.matches || !lease.alive())return {3,Json::object({{L"process",lease.json()}, {L"attempted",Json::boolean(false)}}),{L"Process identity is unavailable or changed."}};
    std::wstring image(32768,L'\0');DWORD imageLength=static_cast<DWORD>(image.size());
    if(!::QueryFullProcessImageNameW(lease.handle.get(),0,image.data(),&imageLength))
        return {3,Json::object({{L"process",lease.json()}, {L"win32Error",Json::number(::GetLastError())}, {L"attempted",Json::boolean(false)}}),{L"Process image identity is unavailable."}};
    image.resize(imageLength);
    if(!samePath(image,target))return {3,Json::object({{L"process",lease.json()}, {L"processImage",Json::string(image)}, {L"requestedTarget",Json::string(target)}, {L"attempted",Json::boolean(false)}}),{L"Shortcut target differs from the identified process image."}};
    const auto before=linkIdentity(path);
    if(!sameLink(expected,before))return {3,Json::object({{L"process",lease.json()}, {L"identity",linkIdentityJson(before)}, {L"attempted",Json::boolean(false)}}),{L"Shortcut file identity changed."}};
    HRESULT status=E_FAIL; bool attempted=false, saved=false;WORD current=0;std::wstring currentTarget;
    {
        LinkAccess access(path,STGM_READWRITE);
        if(!readLink(access,current,currentTarget) || current!=expectedHotkey || !samePath(currentTarget,target) ||
           !sameLink(expected,linkIdentity(path)) || !lease.alive())
            return {3,Json::object({{L"process",lease.json()}, {L"hresult",Json::hex(static_cast<std::uint32_t>(access.status))}, {L"attempted",Json::boolean(false)}}),{L"Shortcut content, file identity or process identity changed before saving."}};
        attempted=true;status=access.link->SetHotkey(0);
        if(SUCCEEDED(status))status=access.persist->Save(path.c_str(),TRUE);
        saved=SUCCEEDED(status);
    }
    if(saved)::SHChangeNotify(SHCNE_UPDATEITEM,SHCNF_PATHW,path.c_str(),nullptr);
    bool verified=false;WORD afterHotkey=0;std::wstring afterTarget;const auto after=linkIdentity(path);
    if(saved && sameLink(expected,after,true) && lease.alive()) {
        LinkAccess readback(path,STGM_READ);
        verified=readLink(readback,afterHotkey,afterTarget) && afterHotkey==0 && samePath(afterTarget,target) &&
            sameLink(expected,linkIdentity(path),true) && lease.alive();
    }
    return {verified?0:6,Json::object({{L"process",lease.json()}, {L"path",Json::string(path)}, {L"beforeIdentity",linkIdentityJson(before)},
        {L"afterIdentity",linkIdentityJson(after)}, {L"attempted",Json::boolean(attempted)}, {L"saved",Json::boolean(saved)},
        {L"hresult",Json::hex(static_cast<std::uint32_t>(status))}, {L"verified",Json::boolean(verified)}}),
        {L"Verification applies to the shortcut file; it does not prove an Explorer in-memory registration was removed. A failed save may have partial effects."}};
}
Result band(const Args& a,unsigned long operation) {
    if(operation==KSW_BAND_SET)requireConfirmed(a);
    KSWORD_ARK_WINDOW_BAND_REQUEST request{}; request.operation=operation;
    std::unique_ptr<window::Lease> lease;
    if(operation!=KSW_BAND_PROBE) {
        lease=std::make_unique<window::Lease>(a);
        if(!lease->matches || !lease->ownerMatches())return {3,Json::object({{L"target",lease->json()}, {L"attempted",Json::boolean(false)}}),{L"Window, process or thread identity changed."}};
        request.hwnd=reinterpret_cast<ULONG64>(lease->handle); request.processId=lease->process.pid;
        request.threadId=lease->tid; request.processCreated=lease->process.creationTime;
    }
    const auto position=a.get(L"--position",L"top");
    if(position!=L"top" && position!=L"bottom")throw std::invalid_argument("--position must be top or bottom");
    request.position=position==L"top"?KSW_BAND_TOP:KSW_BAND_BOTTOM;
    if(operation==KSW_BAND_SET) {
        (void)a.require(L"--expected-band"); (void)a.require(L"--new-band"); (void)a.require(L"--window-object");
        request.expectedBand=a.u32(L"--expected-band"); request.newBand=a.u32(L"--new-band"); request.expectedObject=a.integer(L"--window-object");
        if((request.expectedBand!=1&&request.expectedBand!=2)||(request.newBand!=1&&request.newBand!=2)||!request.expectedObject)
            throw std::invalid_argument("band values must be 1 or 2 and --window-object must be nonzero");
        request.confirmation=KSW_BAND_CONFIRMED;
    }
    const auto result=DriverClient{}.controlWindowBand(request);
    const auto& r=result.response;
    const bool valid=result.io.ok && r.lastStatus>=0 && (r.flags&KSW_BAND_VERIFIED)!=0;
    const bool positionVerified=valid && (r.flags&KSW_BAND_POSITION_VERIFIED)!=0;
    const bool identityOk=!lease || lease->ownerMatches();
    const bool rolledBack=(r.flags&KSW_BAND_ROLLED_BACK)!=0;
    int code=!result.io.ok?(operation==KSW_BAND_SET && !result.io.deviceOpenFailed?6:ioCode(result.io)):
        !valid?((static_cast<std::uint32_t>(r.lastStatus)==0xc00000bbU)?5:
            operation==KSW_BAND_SET && !rolledBack?6:3):!identityOk?6:
        operation==KSW_BAND_SET && !positionVerified?6:0;
    return {code,Json::object({{L"target",lease?lease->json():Json{}}, {L"transport",ioData(result.io)},
        {L"operation",Json::number(operation)}, {L"lastStatus",result.io.ok?Json::hex(static_cast<std::uint32_t>(r.lastStatus)):Json{}},
        {L"flags",result.io.ok?Json::hex(r.flags):Json{}}, {L"windowObject",result.io.ok&&r.windowObject?Json::hex(r.windowObject):Json{}},
        {L"previousBand",result.io.ok&&r.windowObject?Json::number(r.previousBand):Json{}}, {L"currentBand",result.io.ok&&r.windowObject?Json::number(r.currentBand):Json{}},
        {L"imageTimeDateStamp",result.io.ok?Json::hex(r.imageTimeDateStamp):Json{}}, {L"imageSize",result.io.ok?Json::number(r.imageSize):Json{}},
        {L"changed",result.io.ok?Json::boolean((r.flags&KSW_BAND_CHANGED)!=0):Json{}}, {L"rolledBack",result.io.ok?Json::boolean(rolledBack):Json{}},
        {L"verified",Json::boolean(valid&&identityOk)}, {L"positionVerified",Json::boolean(positionVerified&&identityOk)}}),
        {L"The driver uses an exact verified win32k build and the caller's USER desktop. Save previousBand and windowObject to construct an explicit restore request; no automatic restore survives process exit."}};
}
void addR0(Command command) {command.supportsR0=true;command.supportsR3=false;command.defaultBackend=L"r0";addCommand(std::move(command));}
}
void registerWindowAdvanced() {
    addR0({L"window hotkeys registrations enum",L"KswordCLI.exe window hotkeys registrations enum --pid PID [--creation-time FILETIME] [--limit N] [--backend r0] [--json]",
        L"Enumerate a process's current-session registered hotkeys through R0.",L"Required: --pid. Optional: --creation-time, --limit 1..2048, --backend r0, --json.",
        L"Returns typed V4 row identity and snapshot hash. Current USER session only; unavailable/partial snapshots are not eligible for deletion.",registeredEnum});
    addR0({L"window hotkeys registrations clear",L"KswordCLI.exe window hotkeys registrations clear --pid PID --creation-time FILETIME --tid TID --session-id N --object VA --snapshot-hash HASH --confirm [--backend r0] [--json]",
        L"Clear one revalidated registered hotkey through R0.",L"Required: --pid, --creation-time, --tid, --session-id, --object, --snapshot-hash, --confirm. Optional: --backend r0, --json.",
        L"Use identity from registrations enum. Re-enumerates a complete V4 snapshot, rejects ambiguous or unsafe rows, and verifies disappearance after deletion. Session 0 is valid; unknown effects return 6.",registeredClear});
    addCommand({L"window hotkeys activation query",L"KswordCLI.exe window hotkeys activation query --hwnd HWND --pid PID --tid TID --creation-time FILETIME --thread-creation-time FILETIME [--backend r3] [--json]",
        L"Read one identified window's activation hotkey.",L"Required: --hwnd, --pid, --tid, --creation-time, --thread-creation-time. Optional: --backend r3, --json.",
        L"Returns rawHotkey for activation clear after checking the live window owner. A zero value means no window activation hotkey.",activationQuery});
    addCommand({L"window hotkeys activation clear",L"KswordCLI.exe window hotkeys activation clear --hwnd HWND --pid PID --tid TID --creation-time FILETIME --thread-creation-time FILETIME --expected-hotkey N --confirm [--backend r3] [--json]",
        L"Clear one identified window activation hotkey.",L"Required: --hwnd, --pid, --tid, --creation-time, --thread-creation-time, --expected-hotkey, --confirm. Optional: --backend r3, --json.",
        L"Checks the current WM_GETHOTKEY value, sends WM_SETHOTKEY only to the same live window owner and verifies readback. Timeout can leave an unknown effect.",activationClear});
    addCommand({L"window hotkeys shortcut query",L"KswordCLI.exe window hotkeys shortcut query --path PATH [--backend r3] [--json]",
        L"Read a shortcut hotkey, target and stable file identity.",L"Required: --path (.lnk). Optional: --backend r3, --json.",
        L"Read-only; returns volumeSerial, fileId, size, lastWriteTime, target and hotkey for a guarded clear. File configuration does not prove a live Explorer registration.",shortcutQuery});
    addCommand({L"window hotkeys shortcut clear",L"KswordCLI.exe window hotkeys shortcut clear --path PATH --pid PID --creation-time FILETIME --volume-serial N --file-id N --size N --last-write-time FILETIME --target PATH --expected-hotkey N --confirm [--backend r3] [--json]",
        L"Clear a shortcut's hotkey after checking file, content and process identity.",L"Required: --path, --pid, --creation-time, --volume-serial, --file-id, --size, --last-write-time, --target, --expected-hotkey, --confirm. Optional: --backend r3, --json.",
        L"Uses shortcut query identity and the target process creation time. Before saving, checks the process image, file identity, shortcut target and hotkey; verifies the same file and target after saving. Explorer memory registration is not verified.",shortcutClear});
    const auto identity=L"--hwnd HWND --pid PID --tid TID --creation-time FILETIME --thread-creation-time FILETIME";
    addR0({L"window band probe",L"KswordCLI.exe window band probe [--backend r0] [--json]",L"Probe native window Band support.",L"Optional: --backend r0, --json.",L"Read-only; exact win32k image identity is checked by the driver.",[](const Args& a){return band(a,KSW_BAND_PROBE);}});
    addR0({L"window band query",L"KswordCLI.exe window band query "+std::wstring(identity)+L" [--position top|bottom] [--backend r0] [--json]",L"Query one identified window Band and order.",L"Required: --hwnd, --pid, --tid, --creation-time, --thread-creation-time. Optional: --position, --backend r0, --json.",L"Caller and target must be on the same USER desktop. Returns the kernel window object and band for a later guarded set.",[](const Args& a){return band(a,KSW_BAND_QUERY);}});
    addR0({L"window band set",L"KswordCLI.exe window band set "+std::wstring(identity)+L" --expected-band N --new-band N --window-object VA [--position top|bottom] --confirm [--backend r0] [--json]",L"Set or restore native Band for one identified window.",L"Required: --hwnd, --pid, --tid, --creation-time, --thread-creation-time, --expected-band, --new-band, --window-object, --confirm. Optional: --position, --backend r0, --json.",L"Band values are 1 or 2. Query immediately before setting; use previousBand and a fresh identity for explicit restore. The driver enforces its exact-build and same-desktop guards; a failed transport can leave an unknown effect.",[](const Args& a){return band(a,KSW_BAND_SET);}});
}
}
