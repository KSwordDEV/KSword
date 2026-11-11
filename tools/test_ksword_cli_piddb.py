"""Exercise PiDDB CLI selection and transaction against a fake DriverClient."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include <cassert>
#include <sstream>
#include "SOURCE"

static int scenario=0, calls=0;
static ksword::ark::PiDdbEntry target() { return {0x12345000, 0x10203040, static_cast<long>(0xc000009aU), L"fixture.sys"}; }
ksword::ark::PiDdbQueryResult ksword::ark::DriverClient::queryPiDdb(unsigned long) const {
    PiDdbQueryResult r{}; r.io.ok=true; r.io.bytesReturned=KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE+sizeof(KSWORD_ARK_PIDDB_ROW);
    r.queryStatus=KSWORD_ARK_PIDDB_QUERY_STATUS_OK; r.totalRows=1; r.entries.push_back(target());
    if(scenario==1) {r.responseFlags=KSWORD_ARK_PIDDB_RESPONSE_FLAG_TRUNCATED; r.totalRows=2;}
    if(scenario==2) {r.entries.push_back(target()); r.totalRows=2;}
    if(scenario==3) {r.io.ok=false; r.io.deviceOpenFailed=true; r.io.win32Error=ERROR_FILE_NOT_FOUND;}
    return r;
}
ksword::ark::PiDdbDeleteResult ksword::ark::DriverClient::deletePiDdbEntry(const PiDdbEntry& expected,bool force,bool confirmed) const {
    ++calls; PiDdbDeleteResult r{}; r.io.ok=true; r.io.bytesReturned=sizeof(KSWORD_ARK_DELETE_PIDDB_RESPONSE);
    r.matchedEntry=expected; r.remainingRows=23;
    assert(force==confirmed);
    r.status=force?KSWORD_ARK_PIDDB_DELETE_STATUS_OK:KSWORD_ARK_PIDDB_DELETE_STATUS_FORCE_REQUIRED;
    if(scenario==4&&!force) r.status=KSWORD_ARK_PIDDB_DELETE_STATUS_IDENTITY_CHANGED;
    if(scenario==5&&!force) r.matchedEntry.entryAddress++;
    if(scenario==6&&!force) r.io.bytesReturned=4;
    if(scenario==7&&force) r.status=KSWORD_ARK_PIDDB_DELETE_STATUS_VERIFY_FAILED;
    if(scenario==8&&!force) {r.io.ok=false; r.io.deviceOpenFailed=true; r.io.win32Error=ERROR_FILE_NOT_FOUND;}
    if(scenario==9&&force) r.matchedEntry.timeDateStamp++;
    return r;
}
int run(bool remove,std::vector<std::wstring> values) {
    std::vector<wchar_t*> argv; for(auto& value:values) argv.push_back(value.data());
    return remove?commandPiDdbDelete(static_cast<int>(argv.size()),argv.data()):commandPiDdbDetail(static_cast<int>(argv.size()),argv.data());
}
int main() {
    std::wostringstream out,err; auto* oldOut=std::wcout.rdbuf(out.rdbuf()); auto* oldErr=std::wcerr.rdbuf(err.rdbuf());
    const auto detail=std::vector<std::wstring>{L"cli",L"r0",L"piddb-detail",L"--entry",L"0x12345000",L"--json"};
    const auto del=std::vector<std::wstring>{L"cli",L"r0",L"piddb-delete",L"--entry",L"0x12345000",L"--name",L"fixture.sys",L"--timestamp",L"0x10203040",L"--load-status",L"0xc000009a",L"--confirm",L"--json"};
    scenario=0; assert(run(false,detail)==0); assert(out.str().find(L"fixture.sys")!=std::wstring::npos);
    scenario=1; assert(run(false,detail)==6);
    scenario=2; assert(run(false,detail)==4);
    scenario=3; assert(run(false,detail)==2);
    scenario=0; calls=0; assert(run(true,del)==0 && calls==2); assert(out.str().find(L"\"deletedAndVerified\":true")!=std::wstring::npos);
    for(int fail:{4,5,6,8}) {scenario=fail;calls=0;assert(run(true,del)!=0 && calls==1);}
    for(int fail:{7,9}) {scenario=fail;calls=0;assert(run(true,del)==6 && calls==2);}
    auto unconfirmed=del; unconfirmed.erase(unconfirmed.end()-2); calls=0; bool rejected=false;
    try {run(true,unconfirmed);} catch(const std::invalid_argument&) {rejected=true;} assert(rejected && calls==0);
    std::wcout.rdbuf(oldOut);std::wcerr.rdbuf(oldErr);std::cout<<"PIDDB_CLI_FIXTURE_PASS\n";
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix="ksword-piddb-cli-") as directory:
        directory=Path(directory)
        source=directory/"fixture.cpp"
        source.write_text(HARNESS.replace("SOURCE",(ROOT/"KswordCLI/PiDdbCommands.cpp").as_posix()),encoding="utf-8")
        subprocess.run(["cl","/nologo","/std:c++20","/EHsc","/utf-8","/W4","/WX",str(source),
            *[str(ROOT/"KswordCLI"/file) for file in ("CommandRegistry.cpp","CliArgs.cpp","CliText.cpp")],
            "/Fe:"+str(directory/"fixture.exe"),"/link","Iphlpapi.lib","Ws2_32.lib"],cwd=directory,check=True)
        subprocess.run([str(directory/"fixture.exe")],cwd=directory,check=True)

if __name__=="__main__":
    main()
