#include "R3ProcessShared.h"
#include "../shared/usermode/backend/process/ProcessControls.h"
#include "../shared/usermode/backend/process/ProcessExtraQueries.h"
#include "../shared/ProcessTerminateMethods.h"
#include <algorithm>
#include <chrono>
#include <thread>
namespace ks::cli {
namespace {
namespace backend = ks::r3::process;
Json evidence(const backend::ProcessOperationEvidence& value) {
    return Json::object({{L"identityMatched", Json::boolean(value.identityMatched)},
        {L"observedCreationTime", value.observedCreationTime ? Json::count(value.observedCreationTime) : Json{}},
        {L"unsupported", Json::boolean(value.unsupported)}, {L"win32Error", value.win32ErrorKnown ? Json::number(value.win32Error) : Json{}},
        {L"ntStatus", value.ntStatusKnown ? Json::hex(static_cast<DWORD>(value.ntStatus)) : Json{}}});
}
int failedCode(const backend::ProcessOperationEvidence& value) {
    const auto nt = static_cast<DWORD>(value.ntStatus);
    if (value.unsupported || (value.win32ErrorKnown && (value.win32Error == 1 || value.win32Error == 50 || value.win32Error == 120 || value.win32Error == 127)) ||
        (value.ntStatusKnown && (nt == 0xc0000002 || nt == 0xc00000bb || nt == 0xc000007a))) return 5;
    return 3;
}
Result rejected(const Args& args) {
    (void)args.require(L"--pid");
    return {5, Json::object({{L"pid", Json::number(args.u32(L"--pid"))}}), {L"The shared backend rejects protected system PIDs."}};
}
DWORD priority(const Args& args) {
    const auto name = args.require(L"--level");
    const std::pair<const wchar_t*, DWORD> levels[] = {{L"idle",IDLE_PRIORITY_CLASS},{L"below-normal",BELOW_NORMAL_PRIORITY_CLASS},
        {L"normal",NORMAL_PRIORITY_CLASS},{L"above-normal",ABOVE_NORMAL_PRIORITY_CLASS},{L"high",HIGH_PRIORITY_CLASS},{L"realtime",REALTIME_PRIORITY_CLASS}};
    for (const auto& [label, value] : levels) if (name == label) return value;
    throw std::invalid_argument("invalid --level");
}
struct State { bool known = false; ULONG value = 0; bool nativeKnown = false; LONG native = 0; DWORD win32 = 0; bool powerState = false; DWORD controlMask = 0, stateMask = 0; ULONG returned = 0; };
State setting(HANDLE process, const std::wstring& action) {
    State result;
    if (action == L"priority") {
        result.value = GetPriorityClass(process); result.known = result.value != 0; result.win32 = result.known ? ERROR_SUCCESS : GetLastError();
    } else if (action.starts_with(L"critical")) {
        using Query = LONG(NTAPI*)(HANDLE,ULONG,PVOID,ULONG,PULONG);
        const auto query = reinterpret_cast<Query>(backend::NtProc("NtQueryInformationProcess"));
        if (query) { result.native = query(process,29,&result.value,sizeof(result.value),nullptr); result.nativeKnown = true; result.known = result.native == 0; }
    } else {
        result.powerState = true;
        using Get = BOOL(WINAPI*)(HANDLE,ULONG,LPVOID,DWORD);
        const auto module = GetModuleHandleW(L"kernel32.dll"); const auto get = module ? reinterpret_cast<Get>(GetProcAddress(module,"GetProcessInformation")) : nullptr;
        struct Power { ULONG version=1,control=0,state=0; } state;
        if (get) { result.known = get(process,4,&state,sizeof(state)) != FALSE; result.win32 = result.known ? ERROR_SUCCESS : GetLastError(); result.value = (state.control & state.state & 1) != 0;
            result.controlMask = state.control; result.stateMask = state.state; }
        if (!result.known) {
            ks::process::ProcessRecord record; record.pid = GetProcessId(process);
            backend::ProcessExtraEvidence extra;
            backend::QueryProcessExtraDetails(record,0,true,&extra);
            result.known = record.efficiencyModeSupported; result.value = record.efficiencyModeEnabled ? 1 : 0;
            result.nativeKnown = extra.efficiencyStatusKnown; result.native = extra.efficiencyStatus;
            result.controlMask = extra.efficiencyControlMask; result.stateMask = extra.efficiencyStateMask; result.returned = extra.efficiencyReturnLength;
        }
    }
    return result;
}
Json stateJson(const State& value) {
    return Json::object({{L"known", Json::boolean(value.known)}, {L"value", value.known ? Json::number(value.value) : Json{}},
        {L"win32Error", Json::number(value.win32)}, {L"ntStatus", value.nativeKnown ? Json::hex(static_cast<DWORD>(value.native)) : Json{}},
        {L"controlMask", value.powerState && value.known ? Json::hex(value.controlMask) : Json{}},
        {L"stateMask", value.powerState && value.known ? Json::hex(value.stateMask) : Json{}},
        {L"nativeLength", value.powerState && value.nativeKnown ? Json::number(value.returned) : Json{}}});
}
Result control(const Args& args, const std::wstring& action) {
    (void)args.require(L"--confirm"); const DWORD level = action == L"priority" ? priority(args) : 0;
    if (backend::IsProtectedSystemPid(args.u32(L"--pid"))) return rejected(args);
    process::Lease lease(args, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | (action.starts_with(L"critical") ? PROCESS_QUERY_INFORMATION : 0));
    if (!lease.matches || !lease.alive()) return {3, Json::object({{L"target",lease.json()}}), {L"Target identity is unavailable, mismatched or has exited."}};
    backend::ProcessOperationEvidence outcome; std::wstring message; bool ok = false, verified = false; Json observed;
    if (action == L"suspend" || action == L"resume") {
        ok = backend::NtSuspendOrResumeProcess(lease.pid,lease.creationTime,action == L"resume",message,&outcome);
        const auto records = ks::process::EnumerateProcesses(ks::process::ProcessEnumStrategy::Auto);
        for (const auto& r : records) if (r.pid == lease.pid && r.creationTime100ns == lease.creationTime) {
            observed = Json::object({{L"known",Json::boolean(r.processStateKnown)},{L"suspended",r.processStateKnown ? Json::boolean(r.processSuspended) : Json{}}});
            verified = r.processStateKnown && r.processSuspended == (action == L"suspend"); break;
        }
    } else {
        const auto before = setting(lease.handle.get(),action); const bool enable = action.ends_with(L"enable");
        if (action == L"priority") ok = backend::SetPriorityForPid(lease.pid,lease.creationTime,level,message,&outcome);
        else if (action.starts_with(L"critical")) ok = backend::SetCriticalFlagForPid(lease.pid,lease.creationTime,enable,message,&outcome);
        else ok = backend::SetEfficiencyModeForPid(lease.pid,lease.creationTime,enable,message,&outcome);
        auto after = setting(lease.handle.get(),action);
        if (ok && action.starts_with(L"efficiency")) {
            for (int attempt = 0; attempt < 20 && after.known && after.value != (enable ? 1u : 0u) && lease.alive(); ++attempt) {
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
                after = setting(lease.handle.get(),action);
            }
        }
        verified = after.known && after.value == (action == L"priority" ? level : enable ? 1u : 0u);
        observed = Json::object({{L"before",stateJson(before)},{L"after",stateJson(after)}});
    }
    const int code = !ok ? failedCode(outcome) : verified ? 0 : 6;
    return {code, Json::object({{L"target",lease.json()},{L"action",Json::string(action)},{L"requestSucceeded",Json::boolean(ok)},
        {L"verified",Json::boolean(ok && verified)},{L"evidence",evidence(outcome)},{L"observed",observed}}),
        code ? std::vector<std::wstring>{message, ok ? L"Request completed but readback did not confirm the result." : L"Action request failed."} : std::vector<std::wstring>{}};
}
const wchar_t* methodNames[] = {L"win32",L"nt",L"wts",L"winstation",L"job",L"nt-job",L"restart-manager",L"restart-manager-force",
    L"duplicate-handle",L"threads",L"nt-threads",L"debug",L"ntsd",L"unmap-ntdll"};
Result terminate(const Args& args, int method) {
    (void)args.require(L"--confirm"); const auto exitStatus = args.u32(L"--exit-status",0xc000013a);
    if (backend::IsProtectedSystemPid(args.u32(L"--pid"))) return rejected(args);
    process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Target identity is unavailable, mismatched or has exited."}};
    backend::ProcessSnapshotRow row;row.processId=lease.pid;row.creationTime100ns=lease.creationTime;
    bool ok = false; std::wstring message; Json outcome; std::vector<Json> steps;
    if (method == -1) {
        std::vector<backend::ProcessActionEntry> entries;const auto result=backend::TerminateProcesses({row},exitStatus,&entries);
        ok=result.success;message=result.detail;if(!entries.empty())outcome=evidence(entries[0].evidence);
    } else if (method == -2) {
        const auto result=backend::ExecuteMultiMethodTerminate({row});ok=result.success;message=result.detail;
        for(const auto& step:result.terminationSteps)steps.push_back(Json::object({{L"round",Json::number(step.round)},{L"method",Json::string(step.method)},
            {L"requestSucceeded",Json::boolean(step.requestSucceeded)},{L"querySucceeded",Json::boolean(step.querySucceeded)},
            {L"presentAfter",step.querySucceeded ? Json::boolean(step.presentAfter) : Json{}},{L"detail",Json::string(step.detail)}}));
    } else {
        std::string detail;ok=ks::process::TerminateMethodTable()[method].invokeMethod(lease.pid,&detail);message=backend::Utf8ToWide(detail);
    }
    const DWORD wait=WaitForSingleObject(lease.handle.get(),2000);const bool exited=wait == WAIT_OBJECT_0;DWORD observedExit=0;
    const bool exitKnown=exited && GetExitCodeProcess(lease.handle.get(),&observedExit);
    const int code=!ok ? 3 : exited ? 0 : 6;
    return {code,Json::object({{L"target",lease.json()},{L"action",Json::string(method == -2 ? L"terminate-chain" : L"terminate")},
        {L"method",method >= 0 ? Json::string(methodNames[method]) : Json{}},{L"requestSucceeded",Json::boolean(ok)},
        {L"verified",Json::boolean(ok && exited)},{L"exited",Json::boolean(exited)},{L"exitCode",exitKnown ? Json::hex(observedExit) : Json{}},
        {L"evidence",outcome},{L"steps",Json::array(steps)},{L"backendDetail",Json::string(message)}}),
        code ? std::vector<std::wstring>{L"Termination request failed or retained-handle wait did not confirm exit."} : std::vector<std::wstring>{}};
}
Result tree(const Args& args) {
    (void)args.require(L"--confirm");const auto exitStatus=args.u32(L"--exit-status",0xc000013a);
    if(backend::IsProtectedSystemPid(args.u32(L"--pid")))return rejected(args);
    process::Lease root(args);if(!root.matches || !root.alive())return {3,Json::object({{L"target",root.json()}}),{L"Root process identity is unavailable or mismatched."}};
    const auto snapshot=backend::EnumerateProcessesByNtQuerySystemInformation();
    if(!snapshot.success || snapshot.malformed)return {snapshot.malformed?4:3,Json::object({{L"target",root.json()}}),{snapshot.diagnosticText}};
    const auto ids=backend::CollectR3ProcessTreePids({root.pid},snapshot.rows);std::vector<Json> results;std::uint32_t confirmed=0,failed=0;
    for(const auto pid:ids) {
        const auto* row=backend::FindRowByPid(snapshot.rows,pid);if(!row)continue;
        if(!row->creationTime100ns) {++failed;results.push_back(Json::object({{L"pid",Json::number(pid)},{L"verified",Json::boolean(false)},
            {L"diagnostic",Json::string(L"Snapshot process identity is unavailable; action skipped.")}}));continue;}
        Args target;target.values={{L"--pid",std::to_wstring(pid)},{L"--creation-time",std::to_wstring(row->creationTime100ns)}};
        process::Lease lease(target);std::vector<backend::ProcessActionEntry> entries;
        bool ok=false,exited=false;
        if(lease.matches && lease.alive()) {ok=backend::TerminateProcesses({*row},exitStatus,&entries).success;exited=WaitForSingleObject(lease.handle.get(),2000)==WAIT_OBJECT_0;}
        const bool verified=ok && exited;if(verified)++confirmed;else ++failed;
        results.push_back(Json::object({{L"target",lease.json()},{L"requestSucceeded",Json::boolean(ok)},{L"exited",Json::boolean(exited)},
            {L"verified",Json::boolean(verified)},{L"evidence",entries.empty()?Json{}:evidence(entries[0].evidence)}}));
    }
    return {failed ? confirmed ? 6 : 3 : results.empty() ? 3 : 0,Json::object({{L"root",root.json()},{L"confirmedCount",Json::number(confirmed)},
        {L"failedCount",Json::number(failed)},{L"targets",Json::array(results)}}),{L"Tree membership is a native snapshot; later-created children are not covered."}};
}
}
void registerProcessControls() {
    for(const auto* action:{L"suspend",L"resume"})addCommand({L"process "+std::wstring(action),L"KswordCLI.exe process "+std::wstring(action)+L" --pid PID [--creation-time FILETIME] --confirm --backend r3 [--json]",
        L"Control process suspension through the R3 native backend.",L"Required: --pid, --confirm, --backend r3. Optional: --creation-time, --json.",
        L"Fields: target, requestSucceeded, native evidence, observed suspension, verified. Readback may be partial. Default/R0 behavior stays compatible.",[action](const Args& args){return control(args,action);}});
    addCommand({L"process settings set-priority",L"KswordCLI.exe process settings set-priority --pid PID --level idle|below-normal|normal|above-normal|high|realtime [--creation-time FILETIME] --confirm [--backend r3] [--json]",
        L"Set the R3 priority class and read it back.",L"Required: --pid, --level, --confirm. Optional: --creation-time, --backend r3, --json.",
        L"Fields: target, requestSucceeded, evidence, before/after priority class, verified.",[](const Args& args){return control(args,L"priority");}});
    for(const auto* kind:{L"efficiency",L"critical"})for(const auto* operation:{L"enable",L"disable"}) {
        const std::wstring action=std::wstring(kind)+L"-"+operation,path=L"process settings "+std::wstring(kind)+L" "+operation;
        addCommand({path,L"KswordCLI.exe "+path+L" --pid PID [--creation-time FILETIME] --confirm [--backend r3] [--json]",
            L"Set and verify the R3 "+std::wstring(kind)+L" state.",L"Required: --pid, --confirm. Optional: --creation-time, --backend r3, --json.",
            L"Fields: requestSucceeded, primary error/status, before/after state, verified. Critical process termination can bugcheck the system; clear the flag before terminating the target. System PIDs retain backend protection.",[action](const Args& args){return control(args,action);}});
    }
    addCommand({L"process terminate",L"KswordCLI.exe process terminate --pid PID [--creation-time FILETIME] [--exit-status NTSTATUS] --confirm --backend r3 [--json]",
        L"Terminate one process using R3 and wait on its retained identity handle.",L"Required: --pid, --confirm, --backend r3. Optional: --creation-time, --exit-status (default 0xC000013A), --json.",
        L"Fields: requestSucceeded, exited, exitCode, native evidence, verified. API acceptance without observed exit returns 6. Default/R0 invocation remains compatible.",[](const Args& args){return terminate(args,-1);}});
    addCommand({L"process terminate chain",L"KswordCLI.exe process terminate chain --pid PID [--creation-time FILETIME] --confirm [--backend r3] [--json]",
        L"Run the existing two-round R3 termination method chain.",L"Required: --pid, --confirm. Optional: --creation-time, --backend r3, --json.",
        L"Fields: per-method request and presence-query status, retained-handle exit verification. Stops when the backend confirms absence; query failure cannot imply exit.",[](const Args& args){return terminate(args,-2);}});
    for(int i=0;i<14;++i) {
        const std::wstring path=L"process terminate "+std::wstring(methodNames[i]);
        addCommand({path,L"KswordCLI.exe "+path+L" --pid PID [--creation-time FILETIME] --confirm [--backend r3] [--json]",
            L"Invoke "+std::wstring(ks::process::TerminateMethodTable()[i].wideName)+L" on a retained process identity.",
            L"Required: --pid, --confirm. Optional: --creation-time, --backend r3, --json.",
            L"Fields: requestSucceeded, exited, exitCode, verified, backendDetail. Methods may be unavailable or refused; missing raw status stays null. The method's own exit behavior is retained.",[i](const Args& args){return terminate(args,i);}});
    }
    addCommand({L"process terminate-tree",L"KswordCLI.exe process terminate-tree --pid PID [--creation-time FILETIME] [--exit-status NTSTATUS] --confirm [--backend r3] [--json]",
        L"Terminate snapshot descendants child-first and verify each retained identity.",L"Required: --pid, --confirm. Optional: --creation-time, --exit-status (default 0xC000013A), --backend r3, --json.",
        L"Fields: root, per-target request/error/exit evidence, confirmedCount, failedCount. Concurrently created children are outside the snapshot; partial completion returns 6.",tree});
}
}
