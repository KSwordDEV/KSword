#include "CliArgs.h"
#include "CommandRegistry.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>

namespace {
using namespace ks::cli;
using namespace ks::cli::legacy;
using ksword::ark::PiDdbEntry;
using ksword::ark::PiDdbDeleteResult;

Json entryJson(const PiDdbEntry& entry) {
    return Json::object({{L"entryAddress",Json::hex(entry.entryAddress)},
        {L"driverName",Json::string(entry.driverName)}, {L"timeDateStamp",Json::hex(entry.timeDateStamp)},
        {L"loadStatus",Json::hex(static_cast<std::uint32_t>(entry.loadStatus))}});
}

Json operationJson(const PiDdbDeleteResult& result) {
    return Json::object({{L"transportOk",Json::boolean(result.io.ok)},
        {L"deviceOpenFailed",Json::boolean(result.io.deviceOpenFailed)},
        {L"win32Error",Json::number(result.io.win32Error)},
        {L"bytesReturned",Json::number(result.io.bytesReturned)},
        {L"status",Json::number(result.status)},
        {L"ntStatus",Json::hex(static_cast<std::uint32_t>(result.lastStatus))},
        {L"remainingRows",Json::number(result.remainingRows)},
        {L"matchedEntry",entryJson(result.matchedEntry)}});
}

bool sameIdentity(const PiDdbEntry& a,const PiDdbEntry& b) {
    return a.entryAddress == b.entryAddress && a.timeDateStamp == b.timeDateStamp &&
        a.loadStatus == b.loadStatus && _wcsicmp(a.driverName.c_str(),b.driverName.c_str()) == 0;
}

int transportCode(const ksword::ark::IoResult& io, bool unsupported) {
    if (io.deviceOpenFailed) return 2;
    if (io.win32Error == ERROR_INVALID_DATA) return 4;
    if (unsupported || io.win32Error == ERROR_NOT_SUPPORTED || io.win32Error == ERROR_INVALID_FUNCTION) return 5;
    return 3;
}

bool validResponse(const PiDdbDeleteResult& result) {
    return result.io.ok && result.io.bytesReturned >= sizeof(KSWORD_ARK_DELETE_PIDDB_RESPONSE);
}

int operationFailure(const PiDdbDeleteResult& result) {
    if (!result.io.ok) return transportCode(result.io,result.unsupported);
    if (!validResponse(result)) return 4;
    if (result.status == KSWORD_ARK_PIDDB_DELETE_STATUS_DYNDATA_MISSING) return 5;
    if (result.status == KSWORD_ARK_PIDDB_DELETE_STATUS_VERIFY_FAILED) return 6;
    return 3;
}

void emit(const wchar_t* command,int code,const Json& data,const std::wstring& diagnostic,bool json) {
    if (json) {
        std::wcout << Json::object({{L"schemaVersion",Json::number(1)}, {L"command",Json::string(command)},
            {L"backend",Json::string(L"r0")}, {L"status",Json::string(code==0?L"success":code==6?L"partial":code==5?L"unavailable":L"failed")},
            {L"data",data}, {L"diagnostics",Json::strings(diagnostic.empty()?std::vector<std::wstring>{}:std::vector<std::wstring>{diagnostic})}}).text << L"\n";
    } else {
        std::wcout << data.text << L"\n";
        if (!diagnostic.empty()) std::wcerr << diagnostic << L"\n";
    }
}
}

// Single-row inspection is based on a bounded snapshot and never mutates PiDDB.
int commandPiDdbDetail(int argc,wchar_t* argv[]) {
    using namespace ks::cli::legacy;
    const NamedArgs args=parseNamedArgs(argc,argv,3);
    const auto address=requireOptionU64(args,L"--entry");
    if (!address) throw std::invalid_argument("--entry must be nonzero");
    const auto maxRows=getOptionU32(args,L"--max-rows",KSWORD_ARK_PIDDB_MAX_ROWS);
    if (!maxRows || maxRows>KSWORD_ARK_PIDDB_MAX_ROWS) throw std::invalid_argument("--max-rows must be 1..4096");
    const auto result=ksword::ark::DriverClient{}.queryPiDdb(maxRows);
    const bool responseValid=result.io.bytesReturned>=KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE;
    const bool complete=result.io.ok && responseValid && result.queryStatus==KSWORD_ARK_PIDDB_QUERY_STATUS_OK &&
        (result.responseFlags&KSWORD_ARK_PIDDB_RESPONSE_FLAG_TRUNCATED)==0 && result.entries.size()==result.totalRows;
    const auto it=std::find_if(result.entries.begin(),result.entries.end(),[address](const auto& row){return row.entryAddress==address;});
    const bool found=it!=result.entries.end();
    const bool duplicate=found && std::find_if(it+1,result.entries.end(),[address](const auto& row){return row.entryAddress==address;})!=result.entries.end();
    int code=!result.io.ok?transportCode(result.io,result.unsupported):!responseValid?4:
        result.queryStatus==KSWORD_ARK_PIDDB_QUERY_STATUS_DYNDATA_MISSING || result.queryStatus==KSWORD_ARK_PIDDB_QUERY_STATUS_INVALID_LAYOUT?5:
        result.queryStatus==KSWORD_ARK_PIDDB_QUERY_STATUS_READ_FAILED?3:duplicate?4:found?(complete?0:6):complete?3:6;
    const auto data=Json::object({{L"entry",found&&!duplicate?entryJson(*it):Json{}}, {L"complete",Json::boolean(complete)},
        {L"transportOk",Json::boolean(result.io.ok)}, {L"deviceOpenFailed",Json::boolean(result.io.deviceOpenFailed)},
        {L"bytesReturned",Json::number(result.io.bytesReturned)},
        {L"totalRows",Json::number(result.totalRows)}, {L"returnedRows",Json::number(static_cast<std::uint32_t>(result.entries.size()))},
        {L"queryStatus",Json::number(result.queryStatus)}, {L"responseFlags",Json::hex(result.responseFlags)},
        {L"ntStatus",Json::hex(static_cast<std::uint32_t>(result.lastStatus))}, {L"win32Error",Json::number(result.io.win32Error)}});
    emit(L"r0 piddb-detail",code,data,duplicate?L"Duplicate entry addresses in response.":!found&&!complete?L"Snapshot incomplete; absence is not established.":L"",getOptionBool(args,L"--json"));
    return code;
}

// Force delete is sent only after the driver confirms the same complete identity.
int commandPiDdbDelete(int argc,wchar_t* argv[]) {
    using namespace ks::cli::legacy;
    const NamedArgs args=parseNamedArgs(argc,argv,3);
    if (!getOptionBool(args,L"--confirm")) throw std::invalid_argument("piddb-delete requires --confirm");
    PiDdbEntry expected{};
    expected.entryAddress=requireOptionU64(args,L"--entry");
    expected.driverName=requireOptionText(args,L"--name");
    expected.timeDateStamp=requireOptionU32(args,L"--timestamp");
    expected.loadStatus=static_cast<long>(requireOptionU32(args,L"--load-status"));
    if (!expected.entryAddress || expected.driverName.empty() || expected.driverName.size()>=KSWORD_ARK_PIDDB_NAME_CHARS ||
        expected.driverName.find(L'\0')!=std::wstring::npos) throw std::invalid_argument("invalid PiDDB entry identity");
    const ksword::ark::DriverClient client;
    const auto preflight=client.deletePiDdbEntry(expected,false,false);
    bool ready=validResponse(preflight) && preflight.status==KSWORD_ARK_PIDDB_DELETE_STATUS_FORCE_REQUIRED && sameIdentity(expected,preflight.matchedEntry);
    PiDdbDeleteResult commit{};
    bool attempted=false;
    int code=0;
    if (!ready) code=validResponse(preflight) && preflight.status==KSWORD_ARK_PIDDB_DELETE_STATUS_FORCE_REQUIRED?4:operationFailure(preflight);
    else {
        attempted=true;
        commit=client.deletePiDdbEntry(expected,true,true);
        code=validResponse(commit) && commit.status==KSWORD_ARK_PIDDB_DELETE_STATUS_OK && commit.lastStatus>=0 && sameIdentity(expected,commit.matchedEntry)?0:
            validResponse(commit) && commit.status==KSWORD_ARK_PIDDB_DELETE_STATUS_OK?6:operationFailure(commit);
    }
    const auto data=Json::object({{L"expectedEntry",entryJson(expected)}, {L"preflight",operationJson(preflight)},
        {L"commitAttempted",Json::boolean(attempted)}, {L"commit",attempted?operationJson(commit):Json{}},
        {L"deletedAndVerified",Json::boolean(attempted && code==0)}});
    emit(L"r0 piddb-delete",code,data,attempted&&code!=0?L"Commit did not confirm deletion; consult commit status before retrying.":
        !ready?L"Preflight did not confirm the complete selected identity; no delete was attempted.":L"",getOptionBool(args,L"--json"));
    return code;
}
