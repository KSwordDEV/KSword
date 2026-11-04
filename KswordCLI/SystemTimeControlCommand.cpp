#include "CommandRegistry.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace ks::cli {
namespace {
using ksword::ark::DriverClient;
using ksword::ark::IoResult;

std::wstring widen(const std::string& text) { return std::wstring(text.begin(),text.end()); }
int ioCode(const IoResult& io, bool unsupported) {
    if (io.deviceOpenFailed) return 2;
    if (io.win32Error == ERROR_INVALID_DATA) return 4;
    if (unsupported || io.win32Error == ERROR_NOT_SUPPORTED || io.win32Error == ERROR_INVALID_FUNCTION ||
        io.win32Error == ERROR_CALL_NOT_IMPLEMENTED || io.win32Error == ERROR_PROC_NOT_FOUND ||
        io.win32Error == ERROR_REVISION_MISMATCH) return 5;
    return 3;
}
Json transport(const IoResult& io, bool unsupported) {
    return Json::object({{L"ok",Json::boolean(io.ok)},{L"deviceOpenFailed",Json::boolean(io.deviceOpenFailed)},
        {L"unsupported",Json::boolean(unsupported)},{L"win32Error",Json::number(io.win32Error)},
        {L"ntStatus",io.ok || io.ntStatus ? Json::hex(static_cast<std::uint32_t>(io.ntStatus)) : Json{}},
        {L"bytesReturned",Json::number(io.bytesReturned)},{L"message",Json::string(widen(io.message))}});
}
Json queryData(const ksword::ark::SystemTimeQueryResult& q) {
    const auto& r=q.response;
    const bool valid=q.io.bytesReturned>=sizeof(r) && r.version==KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION && r.size==sizeof(r);
    if (!valid) return Json::object({{L"transport",transport(q.io,q.unsupported)},{L"available",Json::boolean(false)}});
    return Json::object({{L"transport",transport(q.io,q.unsupported)},{L"available",Json::boolean(true)},
        {L"version",Json::number(r.version)},{L"status",Json::number(r.status)},
        {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))}, {L"stateFlags",Json::hex(r.stateFlags)},
        {L"supported",Json::boolean((r.stateFlags & KSWORD_ARK_SYSTEM_TIME_STATE_SUPPORTED)!=0)},
        {L"active",Json::boolean((r.stateFlags & KSWORD_ARK_SYSTEM_TIME_STATE_ACTIVE)!=0)},
        {L"generation",Json::number(r.generation)},{L"command",Json::number(r.command)},{L"factor",Json::number(r.factor)},
        {L"osBuild",Json::number(r.osBuildNumber)},{L"resolutionMode",Json::number(r.resolutionMode)},
        {L"timerBackend",Json::number(r.backend)},{L"counterValue",Json::count(r.counterValue)},
        {L"counterSourceAddress",Json::hex(r.counterSourceAddress)},{L"primarySlotAddress",Json::hex(r.primarySlotAddress)},
        {L"secondarySlotAddress",Json::hex(r.secondarySlotAddress)},{L"hypervisorSharedPageAddress",Json::hex(r.hypervisorSharedPageAddress)},
        {L"hypervisorTimeUpdateLock",Json::hex(r.hypervisorTimeUpdateLock)},
        {L"hypervisorOriginalMultiplier",Json::hex(r.hypervisorOriginalMultiplier)}, {L"hypervisorOriginalBias",Json::hex(r.hypervisorOriginalBias)},
        {L"hypervisorCurrentMultiplier",Json::hex(r.hypervisorCurrentMultiplier)}, {L"hypervisorCurrentBias",Json::hex(r.hypervisorCurrentBias)}});
}
Json controlData(const ksword::ark::SystemTimeControlResult& c) {
    const auto& r=c.response;
    const bool valid=c.io.bytesReturned>=sizeof(r) && r.version==KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION && r.size==sizeof(r);
    if (!valid) return Json::object({{L"transport",transport(c.io,c.unsupported)},{L"available",Json::boolean(false)}});
    return Json::object({{L"transport",transport(c.io,c.unsupported)},{L"available",Json::boolean(true)},
        {L"status",Json::number(r.status)},{L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))},
        {L"oldStateFlags",Json::hex(r.oldStateFlags)},{L"newStateFlags",Json::hex(r.newStateFlags)},
        {L"oldGeneration",Json::number(r.oldGeneration)},{L"newGeneration",Json::number(r.newGeneration)},
        {L"command",Json::number(r.command)},{L"factor",Json::number(r.factor)},
        {L"osBuild",Json::number(r.osBuildNumber)},{L"resolutionMode",Json::number(r.resolutionMode)},
        {L"timerBackend",Json::number(r.backend)},{L"counterValue",Json::count(r.counterValue)}});
}
Result speedQuery(const Args&) {
    const auto state=DriverClient().querySystemTime();
    const int code=!state.io.ok ? ioCode(state.io,state.unsupported) :
        state.response.status == KSWORD_ARK_SYSTEM_TIME_STATUS_OK ? 0 : 6;
    return {code,Json::object({{L"state",queryData(state)}}),
        {L"R0 state is a snapshot of the performance-counter remapping, not wall-clock synchronization."}};
}
Result speedControl(const Args& args, bool reset) {
    (void)args.require(L"--confirm");
    ULONG mode=KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET, factor=1;
    ULONG backend=KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC;
    ULONG resolution=KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT;
    if (!reset) {
        const auto value=args.require(L"--mode");
        if (value==L"up") mode=KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP;
        else if (value==L"down") mode=KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN;
        else throw std::invalid_argument("--mode must be up or down");
        (void)args.require(L"--factor"); factor=args.u32(L"--factor");
        if (factor<KSWORD_ARK_SYSTEM_TIME_MIN_FACTOR || factor>KSWORD_ARK_SYSTEM_TIME_MAX_FACTOR)
            throw std::invalid_argument("--factor must be 2..64");
        const auto timer=args.get(L"--timer-backend",L"hyperv");
        if (timer==L"hyperv") backend=KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC;
        else if (timer==L"hal") backend=KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT;
        else throw std::invalid_argument("--timer-backend must be hyperv or hal");
        const auto strategy=args.get(L"--resolution",L"compat");
        if (strategy==L"compat") resolution=KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT;
        else if (strategy==L"guarded") resolution=KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED;
        else throw std::invalid_argument("--resolution must be compat or guarded");
    }
    DriverClient client;
    const auto before=client.querySystemTime();
    if (!reset && !before.io.ok)
        return {ioCode(before.io,before.unsupported),Json::object({{L"before",queryData(before)},{L"controlAttempted",Json::boolean(false)}}),
            {L"The pre-control query failed; no change was requested."}};
    if (!reset && ((before.response.stateFlags & KSWORD_ARK_SYSTEM_TIME_STATE_SUPPORTED)==0 || before.response.generation==0))
        return {5,Json::object({{L"before",queryData(before)},{L"controlAttempted",Json::boolean(false)}}),
            {L"The current build or generation is unavailable; no change was requested."}};
    if (!reset && args.has(L"--generation") && args.u32(L"--generation") != before.response.generation)
        return {3,Json::object({{L"before",queryData(before)},{L"controlAttempted",Json::boolean(false)}}),
            {L"The expected generation differs from the current snapshot; no change was requested."}};
    if (reset && before.io.ok) { backend=before.response.backend; resolution=before.response.resolutionMode; }
    const auto control=client.controlSystemTime(mode,factor,backend,resolution,
        reset ? 0UL : before.response.generation,!reset);
    const auto after=client.querySystemTime();
    const bool accepted=control.io.ok && control.response.status==KSWORD_ARK_SYSTEM_TIME_STATUS_OK && control.response.lastStatus>=0;
    const bool verified=accepted && after.io.ok && after.response.status==KSWORD_ARK_SYSTEM_TIME_STATUS_OK &&
        after.response.command==mode && after.response.factor==factor &&
        (reset || (after.response.backend==backend && after.response.resolutionMode==resolution));
    const int code=!control.io.ok ? ioCode(control.io,control.unsupported) :
        !accepted ? ((control.response.status==KSWORD_ARK_SYSTEM_TIME_STATUS_UNSUPPORTED_BUILD ||
                      control.response.status==KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_NOT_PRESENT ||
                      control.response.status==KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_PAGE_UNAVAILABLE) ? 5 : 3) : verified ? 0 : 6;
    return {code,Json::object({{L"before",queryData(before)},{L"controlAttempted",Json::boolean(true)},
        {L"control",controlData(control)},{L"after",queryData(after)},{L"verified",Json::boolean(verified)}}),
        {L"This changes system-wide performance-counter behavior and persists after the CLI exits. Reset switches to continuous 1x; it may retain a hook to avoid moving the counter backward. Queries and control are separate snapshots."}};
}
struct OwnedHandle {
    HANDLE value=nullptr;
    ~OwnedHandle() { if (value && value!=INVALID_HANDLE_VALUE) CloseHandle(value); }
    OwnedHandle()=default;
    OwnedHandle(const OwnedHandle&)=delete;
    OwnedHandle& operator=(const OwnedHandle&)=delete;
};
struct ProgramResult {
    bool started=false, exited=false, timedOut=false, outputTruncated=false;
    DWORD win32Error=ERROR_SUCCESS, exitCode=0;
    std::vector<char> output;
};
ProgramResult runProgram(const std::wstring& executable,const std::wstring& arguments,DWORD timeoutMs) {
    ProgramResult result;
    SECURITY_ATTRIBUTES security{sizeof(security),nullptr,TRUE};
    OwnedHandle readPipe,writePipe,input;
    if (!CreatePipe(&readPipe.value,&writePipe.value,&security,0) ||
        !SetHandleInformation(readPipe.value,HANDLE_FLAG_INHERIT,0)) {result.win32Error=GetLastError();return result;}
    input.value=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&security,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (input.value==INVALID_HANDLE_VALUE) {result.win32Error=GetLastError();return result;}
    SIZE_T attributeSize=0;
    (void)InitializeProcThreadAttributeList(nullptr,1,0,&attributeSize);
    if (!attributeSize) {result.win32Error=GetLastError();return result;}
    std::vector<unsigned char> storage(attributeSize);
    auto* attributes=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(attributes,1,0,&attributeSize)) {result.win32Error=GetLastError();return result;}
    HANDLE inherited[]={writePipe.value,input.value};
    if (!UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr)) {
        result.win32Error=GetLastError();DeleteProcThreadAttributeList(attributes);return result;
    }
    STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput=input.value;startup.StartupInfo.hStdOutput=writePipe.value;startup.StartupInfo.hStdError=writePipe.value;
    startup.lpAttributeList=attributes;
    std::wstring line=L"\""+executable+L"\" "+arguments;
    PROCESS_INFORMATION info{};
    const BOOL started=CreateProcessW(executable.c_str(),line.data(),nullptr,nullptr,TRUE,
        CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&startup.StartupInfo,&info);
    if (!started) result.win32Error=GetLastError();
    DeleteProcThreadAttributeList(attributes);
    if (!started) return result;
    result.started=true;OwnedHandle process,thread;process.value=info.hProcess;thread.value=info.hThread;
    CloseHandle(writePipe.value);writePipe.value=nullptr;
    const auto begin=GetTickCount64();
    bool waitFailed=false;
    for (;;) {
        if (GetTickCount64()-begin>=timeoutMs) {result.timedOut=true;break;}
        DWORD available=0;
        const BOOL peeked=PeekNamedPipe(readPipe.value,nullptr,0,nullptr,&available,nullptr);
        if (!peeked && GetLastError()!=ERROR_BROKEN_PIPE) {result.win32Error=GetLastError();waitFailed=true;break;}
        if (peeked && available) {
            char buffer[4096];DWORD read=0;
            if (!ReadFile(readPipe.value,buffer,(std::min<DWORD>)(available,sizeof(buffer)),&read,nullptr)) {
                result.win32Error=GetLastError();waitFailed=true;break;
            }
            const std::size_t retained=(std::min<std::size_t>)(read,16384-result.output.size());
            result.output.insert(result.output.end(),buffer,buffer+retained);
            result.outputTruncated=result.outputTruncated || retained<read;
            continue;
        }
        const DWORD wait=WaitForSingleObject(process.value,20);
        if (wait==WAIT_OBJECT_0) {result.exited=true;break;}
        if (wait==WAIT_FAILED) {result.win32Error=GetLastError();waitFailed=true;break;}
    }
    if (!result.exited) {
        if (!TerminateProcess(process.value,ERROR_TIMEOUT) && !waitFailed) result.win32Error=GetLastError();
        (void)WaitForSingleObject(process.value,5000);
    }
    // Drain bytes already in the pipe after process exit; no wait for inherited writers.
    for (;;) {
        DWORD available=0,read=0;char buffer[4096];
        if (!PeekNamedPipe(readPipe.value,nullptr,0,nullptr,&available,nullptr) || !available ||
            !ReadFile(readPipe.value,buffer,(std::min<DWORD>)(available,sizeof(buffer)),&read,nullptr) || !read) break;
        const std::size_t retained=(std::min<std::size_t>)(read,16384-result.output.size());
        result.output.insert(result.output.end(),buffer,buffer+retained);
        result.outputTruncated=result.outputTruncated || retained<read;
    }
    if (result.exited && !GetExitCodeProcess(process.value,&result.exitCode)) {
        result.win32Error=GetLastError();result.exited=false;
    }
    return result;
}
std::wstring consoleOutput(const std::vector<char>& input) {
    if (input.empty()) return {};
    const int size=MultiByteToWideChar(CP_OEMCP,0,input.data(),static_cast<int>(input.size()),nullptr,0);
    if (size<=0) return {};
    std::wstring output(static_cast<std::size_t>(size),L'\0');
    if (!MultiByteToWideChar(CP_OEMCP,0,input.data(),static_cast<int>(input.size()),output.data(),size)) return {};
    return output;
}
Result resync(const Args& args) {
    (void)args.require(L"--confirm");
    const auto timeout=args.u32(L"--timeout-ms",15000);
    if (timeout<1000 || timeout>60000) throw std::invalid_argument("--timeout-ms must be 1000..60000");
    wchar_t directory[MAX_PATH]{};const UINT length=GetSystemDirectoryW(directory,MAX_PATH);
    if (!length || length>=MAX_PATH) return {3,Json::object({{L"processStarted",Json::boolean(false)},
        {L"win32Error",Json::number(length ? ERROR_INSUFFICIENT_BUFFER : GetLastError())}}),{L"Could not locate the Windows system directory; no resync was requested."}};
    const auto result=runProgram(std::wstring(directory,length)+L"\\w32tm.exe",L"/resync /rediscover",timeout);
    const int code=!result.started?3:result.timedOut||!result.exited?6:result.exitCode?3:result.outputTruncated?6:0;
    return {code,Json::object({{L"processStarted",Json::boolean(result.started)},{L"exited",Json::boolean(result.exited)},
        {L"timedOut",Json::boolean(result.timedOut)},{L"exitCode",result.exited?Json::number(result.exitCode):Json{}},
        {L"win32Error",Json::number(result.win32Error)},{L"output",Json::string(consoleOutput(result.output))},
        {L"outputTruncated",Json::boolean(result.outputTruncated)}}),
        {L"Runs Windows w32tm /resync /rediscover. A timeout ends the CLI-owned process, but cannot prove whether a synchronization request was already accepted. Output is decoded using the current OEM code page."}};
}
void addR0(Command command) { command.supportsR0=true;command.supportsR3=false;command.defaultBackend=L"r0";addCommand(std::move(command)); }
}
void registerSystemTimeControl() {
    addR0({L"system time speed query",L"KswordCLI.exe system time speed query [--backend r0] [--json]",
        L"Query system-wide performance-counter remapping state.",L"Optional: --backend r0, --json.",
        L"Returns protocol status, flags, generation, mode, factor, backend, OS build and raw counter/HAL/Hyper-V evidence. No system clock update or implicit change.",speedQuery});
    addR0({L"system time speed set",L"KswordCLI.exe system time speed set --mode up|down --factor N [--timer-backend hyperv|hal] [--resolution compat|guarded] [--generation N] --confirm [--backend r0] [--json]",
        L"Apply a system-wide counter speed multiplier or divisor.",L"Required: --mode, --factor 2..64, --confirm. Optional: --timer-backend (hyperv), --resolution (compat), --generation, --backend r0, --json.",
        L"Queries state first and sends its generation to the driver; an explicitly supplied generation must match. The driver still enforces its kernel-patch safety policy. Returns before/control/after evidence and verified; an unconfirmed readback returns 6. Changes persist until reset or driver lifecycle changes.",[](const Args& a){return speedControl(a,false);}});
    addR0({L"system time speed reset",L"KswordCLI.exe system time speed reset --confirm [--backend r0] [--json]",
        L"Restore a continuous 1x performance-counter rate.",L"Required: --confirm. Optional: --backend r0, --json.",
        L"Attempts reset even if the pre-query fails. Driver reset ignores generation and preserves counter continuity; a hook may remain active. Returns control and post-query evidence; incomplete readback returns 6.",[](const Args& a){return speedControl(a,true);}});
    addCommand({L"system time resync",L"KswordCLI.exe system time resync --confirm [--timeout-ms N] [--backend r3] [--json]",
        L"Ask Windows Time to rediscover its source and synchronize.",L"Required: --confirm. Optional: --timeout-ms 1000..60000 (15000), --backend r3, --json.",
        L"Runs the system-directory w32tm.exe /resync /rediscover, with bounded output and timeout. Process exit 0 does not prove long-term synchronization. A timeout leaves the request outcome unknown; it does not retry.",resync});
}
}
