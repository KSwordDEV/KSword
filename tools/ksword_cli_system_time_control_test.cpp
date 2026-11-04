#include "../KswordCLI/SystemTimeControlCommand.cpp"
#include <cassert>
#include <cstring>
#include <iostream>

namespace {
int scenario=0, queries=0, controls=0;
unsigned long seenCommand=0, seenFactor=0, seenBackend=0, seenResolution=0, seenGeneration=0;
bool seenConfirmed=false;
}

namespace ksword::ark {
SystemTimeQueryResult DriverClient::querySystemTime() const {
    ++queries;
    SystemTimeQueryResult q{};
    if (scenario==1 || (scenario==3 && queries>1) || (scenario==4 && queries==1)) {
        q.io.win32Error=scenario==1 ? ERROR_NOT_SUPPORTED : ERROR_ACCESS_DENIED;
        q.unsupported=scenario==1;
        return q;
    }
    q.io.ok=true; q.io.bytesReturned=sizeof(q.response);
    q.response.version=KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION; q.response.size=sizeof(q.response);
    q.response.status=KSWORD_ARK_SYSTEM_TIME_STATUS_OK;
    q.response.stateFlags=KSWORD_ARK_SYSTEM_TIME_STATE_SUPPORTED;
    q.response.generation=7;
    q.response.command=KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET; q.response.factor=1;
    q.response.backend=KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC;
    q.response.resolutionMode=KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT;
    if (controls) {
        q.response.generation=8; q.response.command=seenCommand; q.response.factor=seenFactor;
        q.response.backend=seenBackend; q.response.resolutionMode=seenResolution;
    }
    return q;
}
SystemTimeControlResult DriverClient::controlSystemTime(unsigned long command,unsigned long factor,unsigned long backend,
                                                         unsigned long resolution,unsigned long generation,bool confirmed) const {
    ++controls; seenCommand=command; seenFactor=factor; seenBackend=backend; seenResolution=resolution;
    seenGeneration=generation; seenConfirmed=confirmed;
    SystemTimeControlResult result{}; result.io.ok=true; result.io.bytesReturned=sizeof(result.response);
    result.response.version=KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION; result.response.size=sizeof(result.response);
    result.response.status=scenario==2 ? KSWORD_ARK_SYSTEM_TIME_STATUS_STALE_GENERATION : KSWORD_ARK_SYSTEM_TIME_STATUS_OK;
    result.response.lastStatus=scenario==2 ? static_cast<long>(0xC0000059UL) : 0;
    if (scenario==5) {result.io.ok=false;result.io.win32Error=ERROR_ACCESS_DENIED;result.io.ntStatus=static_cast<long>(0xC0000022UL);
        result.response.status=KSWORD_ARK_SYSTEM_TIME_STATUS_CONFIRMATION_REQUIRED;result.response.lastStatus=result.io.ntStatus;}
    return result;
}
}

int main(int argc, char** argv) {
    if (argc==2 && std::strcmp(argv[1],"--child")==0) { std::cout << "child evidence\n";return 0; }
    if (argc==2 && std::strcmp(argv[1],"--slow")==0) { Sleep(2000);return 0; }
    if (argc==2 && std::strcmp(argv[1],"--flood")==0) { for (int i=0;i<40000;++i) std::cout << 'x';return 0; }
    using namespace ks::cli;
    Args a; a.values[L"--mode"]=L"up"; a.values[L"--factor"]=L"3"; a.values[L"--timer-backend"]=L"hal";
    a.values[L"--resolution"]=L"guarded";
    bool denied=false; try { (void)speedControl(a,false); } catch (const std::invalid_argument&) { denied=true; }
    assert(denied && queries==0 && controls==0);
    a.values[L"--confirm"]=L"";
    auto r=speedControl(a,false);
    assert(r.code==0 && controls==1 && queries==2 && seenConfirmed && seenGeneration==7 && seenFactor==3 &&
        seenCommand==KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP && seenBackend==KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT &&
        seenResolution==KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED);
    scenario=1; queries=controls=0; r=speedControl(a,false); assert(r.code==5 && controls==0);
    scenario=0; queries=controls=0; a.values[L"--generation"]=L"8"; r=speedControl(a,false); assert(r.code==3 && controls==0);
    a.values.erase(L"--generation"); scenario=2; queries=controls=0; r=speedControl(a,false); assert(r.code==3 && controls==1);
    scenario=3; queries=controls=0; r=speedControl(a,false); assert(r.code==6 && controls==1);
    scenario=5; queries=controls=0; r=speedControl(a,false);
    assert(r.code==3 && controls==1 && r.data.text.find(L"\"status\":2")!=std::wstring::npos &&
        r.data.text.find(L"\"ntStatus\":\"0xc0000022\"")!=std::wstring::npos);
    scenario=4; queries=controls=0; Args reset; reset.values[L"--confirm"]=L""; r=speedControl(reset,true);
    assert(r.code==0 && controls==1 && seenCommand==KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET && seenFactor==1 &&
        seenGeneration==0 && !seenConfirmed);
    scenario=0; queries=controls=0; a.values[L"--factor"]=L"65"; denied=false;
    try { (void)speedControl(a,false); } catch (const std::invalid_argument&) { denied=true; }
    assert(denied && controls==0 && queries==0);
    wchar_t executable[MAX_PATH]{};const DWORD chars=GetModuleFileNameW(nullptr,executable,MAX_PATH);assert(chars>0 && chars<MAX_PATH);
    auto child=runProgram(executable,L"--child",5000);
    assert(child.started && child.exited && child.exitCode==0 && !child.timedOut && consoleOutput(child.output).find(L"child evidence")!=std::wstring::npos);
    child=runProgram(executable,L"--flood",5000);assert(child.started && child.exited && child.exitCode==0 && child.outputTruncated && child.output.size()==16384);
    child=runProgram(executable,L"--slow",50);assert(child.started && child.timedOut && !child.exited);
    child=runProgram(L"Z:\\ksword-nonexistent\\fixture.exe",L"",1000);assert(!child.started && child.win32Error!=0);
    Args sync;denied=false;try {(void)resync(sync);}catch(const std::invalid_argument&) {denied=true;}assert(denied);
    sync.values[L"--confirm"]=L"";sync.values[L"--timeout-ms"]=L"10";denied=false;
    try {(void)resync(sync);}catch(const std::invalid_argument&) {denied=true;}assert(denied);
    std::cout << "SYSTEM_TIME_CONTROL_PASS\n";
}
