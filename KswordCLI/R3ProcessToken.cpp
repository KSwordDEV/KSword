#include "R3ProcessShared.h"
#include "../shared/usermode/backend/process/ProcessToken.h"
#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>
namespace ks::cli {
namespace {
namespace backend = ks::r3::process_detail::token;
int informationClass(const std::wstring& name) {
    for (int n=1;n<=80;++n) if (_wcsicmp(name.c_str(),backend::TokenClassName(n).c_str()) == 0) return n;
    Args number;number.values[L"--class"] = name;
    const auto n = number.u32(L"--class");
    if (!n || n > 80) throw std::invalid_argument("--class must be an information-class name or number 1..80; use process token classes list");
    return static_cast<int>(n);
}
std::vector<int> selection(const Args& args,bool raw) {
    if (raw) return {informationClass(args.require(L"--class"))};
    const auto input = args.get(L"--classes",L"TokenUser,TokenGroups,TokenPrivileges,TokenElevationType,TokenElevation,TokenIntegrityLevel,TokenSessionId");
    std::vector<int> result;
    if (input == L"all") {for (int n=1;n<=80;++n) result.push_back(n);return result;}
    std::wistringstream stream(input);std::wstring item;std::set<int> seen;
    while (std::getline(stream,item,L',')) {const int n = informationClass(item);if (!seen.insert(n).second) throw std::invalid_argument("duplicate information class");result.push_back(n);}
    if (result.empty() || input.back() == L',') throw std::invalid_argument("empty information class");
    return result;
}
template<typename T> bool read(const std::vector<std::byte>& bytes,T& value,std::size_t offset=0) {
    if (offset > bytes.size() || sizeof(T) > bytes.size()-offset) return false;
    std::memcpy(&value,bytes.data()+offset,sizeof(T));return true;
}
struct SidFailure {DWORD error = 0;};
Json sid(const std::vector<std::byte>& bytes,PSID pointer) {
    const auto start = reinterpret_cast<std::uintptr_t>(bytes.data()), address = reinterpret_cast<std::uintptr_t>(pointer);
    if (!pointer || address < start || address-start > bytes.size() || bytes.size()-(address-start) < 8) throw std::runtime_error("SID header lies outside the token result");
    const auto offset = static_cast<std::size_t>(address-start);
    const auto count = std::to_integer<unsigned>(bytes[offset+1]);
    if (count > SID_MAX_SUB_AUTHORITIES || 8+count*4 > bytes.size()-offset || !IsValidSid(pointer)) throw std::runtime_error("invalid SID extent");
    LPWSTR converted = nullptr;
    if (!ConvertSidToStringSidW(pointer,&converted)) throw SidFailure{GetLastError()};
    const std::wstring text(converted);LocalFree(converted);
    wchar_t name[256]{},domain[256]{};DWORD n=256,d=256;SID_NAME_USE use{};
    const bool named = LookupAccountSidW(nullptr,pointer,name,&n,domain,&d,&use) != FALSE;
    const DWORD error = named ? ERROR_SUCCESS : GetLastError();
    return Json::object({{L"sid",Json::string(text)}, {L"account",named ? Json::string(std::wstring(domain)+(domain[0] ? L"\\" : L"")+name) : Json{}},
        {L"accountWin32Error",Json::number(error)}});
}
struct Decoded {Json value;bool truncated = false;bool malformed = false;DWORD conversionError = 0;};
Decoded decode(const backend::TokenClassSnapshot& row,DWORD limit,bool raw,DWORD maxBytes) {
    Decoded result;const auto& bytes = row.bytes;
    const auto rawValue = [&] {std::vector<std::uint8_t> data(bytes.size());std::memcpy(data.data(),bytes.data(),bytes.size());
        result.truncated = bytes.size() > maxBytes;result.value = Json::bytes(data,maxBytes);};
    if (raw) {rawValue();return result;}
    try {
        if (row.informationClass == TokenUser || row.informationClass == TokenIntegrityLevel || row.informationClass == TokenOwner || row.informationClass == TokenPrimaryGroup) {
            PSID pointer = nullptr;if (!read(bytes,pointer)) throw std::runtime_error("short SID result");
            result.value = sid(bytes,pointer);
        } else if (row.informationClass == TokenGroups) {
            DWORD count = 0;if (!read(bytes,count) || bytes.size() < offsetof(TOKEN_GROUPS,Groups) ||
                count > (bytes.size()-offsetof(TOKEN_GROUPS,Groups))/sizeof(SID_AND_ATTRIBUTES)) throw std::runtime_error("short group result");
            std::vector<Json> rows;
            for (DWORD i=0;i<(std::min)(count,limit);++i) {SID_AND_ATTRIBUTES group{};(void)read(bytes,group,offsetof(TOKEN_GROUPS,Groups)+i*sizeof(group));
                rows.push_back(Json::object({{L"identity",sid(bytes,group.Sid)}, {L"attributes",Json::hex(group.Attributes)}}));}
            result.truncated = count > limit;result.value = Json::object({{L"count",Json::number(count)}, {L"groups",Json::array(rows)}});
        } else if (row.informationClass == TokenPrivileges) {
            DWORD count = 0;if (!read(bytes,count) || bytes.size() < offsetof(TOKEN_PRIVILEGES,Privileges) ||
                count > (bytes.size()-offsetof(TOKEN_PRIVILEGES,Privileges))/sizeof(LUID_AND_ATTRIBUTES)) throw std::runtime_error("short privilege result");
            std::vector<Json> rows;
            for (DWORD i=0;i<(std::min)(count,limit);++i) {LUID_AND_ATTRIBUTES p{};(void)read(bytes,p,offsetof(TOKEN_PRIVILEGES,Privileges)+i*sizeof(p));
                wchar_t name[256]{};DWORD length=256;const bool named = LookupPrivilegeNameW(nullptr,&p.Luid,name,&length) != FALSE;
                const auto error = named ? ERROR_SUCCESS : GetLastError();
                rows.push_back(Json::object({{L"name",named ? Json::string(name) : Json{}}, {L"luid",Json::hex((static_cast<std::uint64_t>(static_cast<DWORD>(p.Luid.HighPart))<<32)|p.Luid.LowPart)},
                    {L"attributes",Json::hex(p.Attributes)}, {L"enabled",Json::boolean((p.Attributes & SE_PRIVILEGE_ENABLED) != 0)}, {L"nameWin32Error",Json::number(error)}}));}
            result.truncated = count > limit;result.value = Json::object({{L"count",Json::number(count)}, {L"privileges",Json::array(rows)}});
        } else if (row.informationClass == TokenElevation || row.informationClass == TokenSessionId || row.informationClass == TokenElevationType || row.informationClass == TokenMandatoryPolicy ||
            row.informationClass == TokenVirtualizationEnabled || row.informationClass == TokenVirtualizationAllowed || row.informationClass == TokenUIAccess) {
            DWORD value = 0;if (!read(bytes,value)) throw std::runtime_error("short scalar result");
            result.value = row.informationClass == TokenElevation || row.informationClass == TokenVirtualizationEnabled || row.informationClass == TokenVirtualizationAllowed || row.informationClass == TokenUIAccess ?
                Json::boolean(value != 0) : Json::number(value);
        } else rawValue();
    } catch (const SidFailure& failure) {result.conversionError = failure.error;result.value = {};}
    catch (const std::runtime_error&) {result.malformed = true;result.value = {};}
    return result;
}
Result query(const Args& args,bool raw) {
    const auto classes = selection(args,raw);const auto limit = args.u32(L"--limit",128), maxBytes = args.u32(L"--max-bytes",512);
    if (!limit || limit > 65535 || !maxBytes || maxBytes > 1048576) throw std::invalid_argument("--limit must be 1..65535 and --max-bytes 1..1048576");
    process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    const auto snapshot = backend::QueryTokenClasses(lease.pid,lease.creationTime,classes);
    if (!snapshot.tokenOpened || !snapshot.identityMatched || !lease.alive()) return {3,Json::object({{L"target",lease.json()},
        {L"win32Error",snapshot.win32ErrorKnown ? Json::number(snapshot.win32Error) : Json{}}}),{L"Token acquisition failed or target exited."}};
    std::vector<Json> rows;DWORD available = 0;bool partial = false, malformed = false, failed = false;
    for (const auto& row : snapshot.classes) {
        const auto value = row.available ? decode(row,limit,raw,maxBytes) : Decoded{};
        const bool known = row.available && !row.malformed && !value.malformed && !value.conversionError;if (known) ++available;
        partial = partial || value.truncated;malformed = malformed || value.malformed || row.malformed;
        failed = failed || value.conversionError != 0 || (!row.available && row.win32Error != ERROR_INVALID_PARAMETER && row.win32Error != ERROR_NOT_SUPPORTED && row.win32Error != ERROR_INVALID_FUNCTION);
        rows.push_back(Json::object({{L"informationClass",Json::number(row.informationClass)}, {L"name",Json::string(backend::TokenClassName(row.informationClass))},
            {L"available",Json::boolean(known)}, {L"win32Error",Json::number(value.conversionError ? value.conversionError : row.win32Error)}, {L"malformed",Json::boolean(value.malformed || row.malformed)},
            {L"byteSize",row.available ? Json::count(row.bytes.size()) : Json{}}, {L"truncated",Json::boolean(value.truncated)}, {L"value",known ? value.value : Json{}}}));
    }
    const int code = malformed ? 4 : available == classes.size() ? partial ? 6 : 0 : available ? 6 : failed ? 3 : 5;
    return {code,Json::object({{L"target",lease.json()}, {L"source",Json::string(L"shared R3 token information")}, {L"requestedCount",Json::number(static_cast<DWORD>(classes.size()))},
        {L"availableCount",Json::number(available)}, {L"classes",Json::array(rows)}}),code ? std::vector<std::wstring>{L"Some classes are unavailable, malformed or limited; per-class errors are retained. Raw pointer values describe this collection only."} : std::vector<std::wstring>{}};
}
std::optional<DWORD> privilegeState(const backend::TokenQuerySnapshot& s,LUID luid) {
    for (const auto& row : s.classes) if (row.informationClass == TokenPrivileges && row.available) {
        DWORD count = 0;if (!read(row.bytes,count) || row.bytes.size() < offsetof(TOKEN_PRIVILEGES,Privileges) || count >
            (row.bytes.size()-offsetof(TOKEN_PRIVILEGES,Privileges))/sizeof(LUID_AND_ATTRIBUTES)) return {};
        for (DWORD i=0;i<count;++i) {LUID_AND_ATTRIBUTES p{};(void)read(row.bytes,p,offsetof(TOKEN_PRIVILEGES,Privileges)+i*sizeof(p));
            if (p.Luid.LowPart == luid.LowPart && p.Luid.HighPart == luid.HighPart) return p.Attributes;}
    }
    return {};
}
Result adjust(const Args& args,bool enable) {
    (void)args.require(L"--confirm");const auto name = args.require(L"--name");LUID luid{};
    if (!LookupPrivilegeValueW(nullptr,name.c_str(),&luid)) throw std::invalid_argument("unknown --name privilege");
    process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    const auto before = privilegeState(backend::QueryTokenClasses(lease.pid,lease.creationTime,{TokenPrivileges}),luid);
    ks::r3::common::UniqueHandle retained;DWORD error = ERROR_SUCCESS;
    const auto outcome = backend::AdjustTokenPrivilegeR3(lease.pid,lease.creationTime,name,luid,enable,retained,error);
    const auto after = privilegeState(backend::QueryTokenClasses(lease.pid,lease.creationTime,{TokenPrivileges}),luid);
    const bool verified = outcome.requestSucceeded && lease.alive() && after && ((*after & SE_PRIVILEGE_ENABLED) != 0) == enable;
    return {!outcome.requestSucceeded ? 3 : verified ? 0 : 6,Json::object({{L"target",lease.json()}, {L"name",Json::string(name)}, {L"enable",Json::boolean(enable)},
        {L"requestSucceeded",Json::boolean(outcome.requestSucceeded)}, {L"verified",Json::boolean(verified)}, {L"identityMatched",Json::boolean(outcome.identityMatched)},
        {L"win32Error",outcome.win32ErrorKnown ? Json::number(outcome.win32Error) : Json{}}, {L"beforeAttributes",before ? Json::hex(*before) : Json{}},
        {L"afterAttributes",after ? Json::hex(*after) : Json{}}}),verified ? std::vector<std::wstring>{} : std::vector<std::wstring>{outcome.statusText,L"Privilege request failed, was not assigned, or readback is missing."}};
}
bool comparable(int id) {return id == TokenSessionId || id == TokenSandBoxInert || id == TokenVirtualizationAllowed || id == TokenVirtualizationEnabled ||
    id == TokenUIAccess || id == TokenMandatoryPolicy;}
Result rawSet(const Args& args) {
    (void)args.require(L"--confirm");const int id = informationClass(args.require(L"--class"));
    if (args.has(L"--hex") == args.has(L"--data-file")) throw std::invalid_argument("supply exactly one of --hex or --data-file");
    const auto input = args.has(L"--hex") ? Payload{parseHexPayload(args.require(L"--hex"))} : readPayloadFile(args.require(L"--data-file"));
    if (input.win32Error) return {3,Json::object({{L"win32Error",Json::number(input.win32Error)}}),{L"Cannot read token payload file."}};
    if (input.bytes.empty() || input.bytes.size() > 16*1024*1024) throw std::invalid_argument("token payload must be 1..16777216 bytes");
    process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    std::vector<std::byte> payload(input.bytes.size());std::memcpy(payload.data(),input.bytes.data(),payload.size());
    const auto outcome = backend::WriteRawTokenValue(id,lease.pid,lease.creationTime,payload);
    const auto snapshot = backend::QueryTokenClasses(lease.pid,lease.creationTime,{id});
    const bool known = lease.alive() && snapshot.tokenOpened && snapshot.classes.size() == 1 && snapshot.classes.front().available;
    const bool verified = outcome.requestSucceeded && known && comparable(id) && snapshot.classes.front().bytes == payload;
    std::vector<std::uint8_t> observed;
    if (known) {observed.resize(snapshot.classes.front().bytes.size());std::memcpy(observed.data(),snapshot.classes.front().bytes.data(),observed.size());}
    const auto status = static_cast<DWORD>(outcome.ntStatus);
    const bool unsupported = outcome.unsupported || (outcome.ntStatusKnown && (status == 0xc0000002 || status == 0xc0000003 || status == 0xc00000bb));
    return {unsupported ? 5 : !outcome.requestSucceeded ? 3 : verified ? 0 : 6,Json::object({{L"target",lease.json()}, {L"informationClass",Json::number(id)},
        {L"name",Json::string(backend::TokenClassName(id))}, {L"payloadSize",Json::count(payload.size())}, {L"requestSucceeded",Json::boolean(outcome.requestSucceeded)},
        {L"verified",Json::boolean(verified)}, {L"readbackKnown",Json::boolean(known)}, {L"readbackComparable",Json::boolean(comparable(id))},
        {L"requestedHex",Json::bytes(input.bytes,512)}, {L"requestedTruncated",Json::boolean(input.bytes.size() > 512)},
        {L"readbackHex",known ? Json::bytes(observed,512) : Json{}}, {L"readbackSize",known ? Json::count(observed.size()) : Json{}},
        {L"readbackTruncated",known ? Json::boolean(observed.size() > 512) : Json{}},
        {L"readbackWin32Error",snapshot.classes.size() == 1 ? Json::number(snapshot.classes.front().win32Error) : snapshot.win32ErrorKnown ? Json::number(snapshot.win32Error) : Json{}},
        {L"ntStatus",outcome.ntStatusKnown ? Json::hex(status) : Json{}}, {L"win32Error",outcome.win32ErrorKnown ? Json::number(outcome.win32Error) : Json{}}}),
        verified ? std::vector<std::wstring>{} : std::vector<std::wstring>{outcome.statusText,L"Raw token writes are verified only for stable scalar classes; pointer-containing data is not comparable."}};
}
}
void registerProcessToken() {
    addCommand({L"process token classes list",L"KswordCLI.exe process token classes list [--backend r3] [--json]",L"List native token information-class names.",L"Optional: --backend r3, --json.",
        L"Names identify TOKEN_INFORMATION_CLASS query/set parameters, not action numbers. Listed classes are not all supported on every Windows version.",[](const Args&){
            std::vector<Json> rows;for (int n=1;n<=80;++n) rows.push_back(Json::object({{L"informationClass",Json::number(n)}, {L"name",Json::string(backend::TokenClassName(n))}}));
            return Result{0,Json::object({{L"classes",Json::array(rows)}})};
        }});
    addCommand({L"process token query",L"KswordCLI.exe process token query --pid PID [--creation-time FILETIME] [--classes NAME[,NAME...]|all] [--limit N] [--max-bytes N] [--backend r3] [--json]",
        L"Read token user, groups, privileges, elevation, integrity and session.",L"Required: --pid. Optional: --creation-time, --classes, --limit (128 group/privilege rows), --max-bytes (512 raw preview), --backend r3, --json.",
        L"Output: target, requestedCount, availableCount, classes with typed value, availability, byteSize, errors and truncation. Default classes: user, groups, privileges, elevation type/state, integrity and session. Unknown/raw classes are hexadecimal bytes. Missing classes or limits return 6; malformed data returns 4. Pure R3 with no token fallback.",[](const Args& a){return query(a,false);}});
    addCommand({L"process token raw query",L"KswordCLI.exe process token raw query --pid PID --class NAME|NUMBER [--creation-time FILETIME] [--max-bytes N] [--backend r3] [--json]",
        L"Read one raw token information class.",L"Required: --pid, --class. Optional: --creation-time, --max-bytes (512), --backend r3, --json.",
        L"Output: target and one class with raw hexadecimal bytes, byteSize, availability and error. Pointer/handle values are ephemeral and are not reusable write payloads. The linked-token handle is released after collecting its numeric value. Unsupported classes return 5; access failure returns 3; limited bytes return 6.",[](const Args& a){return query(a,true);}});
    addCommand({L"process token raw set",L"KswordCLI.exe process token raw set --pid PID --class NAME|NUMBER [--creation-time FILETIME] (--hex HEX|--data-file PATH) --confirm [--backend r3] [--json]",
        L"Set native token information using the existing raw backend.",L"Required: --pid, --class, exactly one of --hex/--data-file, --confirm. Optional: --creation-time, --backend r3, --json.",
        L"Output: target, requestSucceeded, verified, readbackKnown/readbackComparable, requestedHex/readbackHex (512-byte previews), payloadSize, readbackSize, truncation flags, ntStatus and original write/read errors. Token query/default/session-adjust rights and class-specific privileges are required; UIAccess may require SeTcbPrivilege, and a running token may refuse mandatory-policy changes with STATUS_TOKEN_ALREADY_IN_USE. Only session, sandbox, virtualization, UIAccess and mandatory-policy scalar readbacks are byte-comparable. Native success without verified readback returns 6. Read-only/native-unsupported classes return 5 or 3 according to the raw status.",rawSet});
    for (const bool enable : {true,false}) {
        const std::wstring name = enable ? L"enable" : L"disable";
        addCommand({L"process token privilege " + name,L"KswordCLI.exe process token privilege " + name + L" --pid PID --name PRIVILEGE [--creation-time FILETIME] --confirm [--backend r3] [--json]",
            L"Change a target token privilege and read its attributes back.",L"Required: --pid, --name, --confirm. Optional: --creation-time, --backend r3, --json.",
            L"Output: target, name, enable, requestSucceeded, verified, win32Error, beforeAttributes/afterAttributes. Cannot add a privilege absent from the target token. A successful API with ERROR_NOT_ALL_ASSIGNED is failure. Retains process identity. For current CLI privileges around a command use privilege run.",
            [enable](const Args& a){return adjust(a,enable);}});
    }
}
}
