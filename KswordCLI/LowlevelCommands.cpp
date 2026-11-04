#include "CommandRegistry.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include <stdexcept>
#include <cstring>
#include <utility>

namespace ks::cli {
namespace {
using namespace ksword::ark;
int ioCode(const IoResult& io, bool unsupported) {
    return io.deviceOpenFailed ? 2 : (unsupported || io.win32Error == ERROR_INVALID_FUNCTION || io.win32Error == ERROR_NOT_SUPPORTED) ? 5 : io.win32Error == ERROR_INVALID_DATA ? 4 : 3;
}
Json ioJson(const IoResult& io) {
    return Json::object({{L"win32Error", Json::number(io.win32Error)}, {L"ntStatus", Json::hex(static_cast<std::uint32_t>(io.ntStatus))}, {L"deviceOpenFailed", Json::boolean(io.deviceOpenFailed)}});
}
Result timer(const Args& args, unsigned long action) {
    const auto driver = args.require(L"--driver");
    const auto driverObject = args.integer(L"--driver-object"), device = args.integer(L"--device-object"), timerAddress = args.integer(L"--timer");
    if (!args.has(L"--confirm") || driver.empty() || !driverObject || !device || !timerAddress) throw std::invalid_argument("--driver, three nonzero object addresses and --confirm are required");
    const auto r = DriverClient().controlIoTimer(action, driver, driverObject, device, timerAddress, true);
    const auto code = !r.io.ok ? ioCode(r.io, r.unsupported) : r.status == KSWORD_ARK_IO_TIMER_CONTROL_STATUS_OK ? 0 : 3;
    return {code, Json::object({{L"io", ioJson(r.io)}, {L"status", Json::number(r.status)}, {L"lastStatus", Json::hex(static_cast<std::uint32_t>(r.lastStatus))}, {L"action", Json::number(r.action)}, {L"driverObject", Json::hex(r.observedDriverObjectAddress)}, {L"deviceObject", Json::hex(r.observedDeviceObjectAddress)}, {L"timer", Json::hex(r.observedTimerAddress)}}), {}};
}
Result debugOutput(const Args& args) {
    const auto action = args.require(L"--action");
    unsigned long id = 0;
    if (action == L"query") id = KSWORD_ARK_DEBUG_OUTPUT_ACTION_QUERY;
    else if (action == L"start") id = KSWORD_ARK_DEBUG_OUTPUT_ACTION_START;
    else if (action == L"stop") id = KSWORD_ARK_DEBUG_OUTPUT_ACTION_STOP;
    else throw std::invalid_argument("--action must be query, start or stop");
    if (id != KSWORD_ARK_DEBUG_OUTPUT_ACTION_QUERY && !args.has(L"--confirm")) throw std::invalid_argument("--confirm is required for start or stop");
    const auto r = DriverClient().controlDebugOutput(id);
    const auto code = !r.io.ok ? ioCode(r.io, r.unsupported) : (r.lastStatus < 0 || (id == KSWORD_ARK_DEBUG_OUTPUT_ACTION_START && r.registrationStatus < 0)) ? 3 : 0;
    return {code, Json::object({{L"io", ioJson(r.io)}, {L"version", Json::number(r.version)}, {L"runtimeFlags", Json::hex(r.runtimeFlags)}, {L"ringCapacity", Json::number(r.ringCapacity)}, {L"queuedCount", Json::number(r.queuedCount)}, {L"latestSequence", Json::count(r.latestSequence)}, {L"droppedCount", Json::count(r.droppedCount)}, {L"registrationStatus", Json::hex(static_cast<std::uint32_t>(r.registrationStatus))}, {L"lastStatus", Json::hex(static_cast<std::uint32_t>(r.lastStatus))}}), {}};
}
Result platform(const Args& args) {
    (void)args.require(L"--scope"); (void)args.require(L"--index"); (void)args.require(L"--expected");
    auto scope=args.u32(L"--scope"), index=args.u32(L"--index");
    auto table=args.integer(L"--table"), expected=args.integer(L"--expected"), value=args.integer(L"--value");
    if (!args.has(L"--confirm") || !table || !value) throw std::invalid_argument("--table and --value must be nonzero and --confirm is required");
    const auto r=DriverClient().editPlatformAuditEntry(scope,index,table,expected,value,true);
    const auto& p=r.response;
    const auto code=!r.io.ok ? ioCode(r.io,r.unsupported) : p.status==KSWORD_ARK_PLATFORM_CONTROL_STATUS_OK ? 0 : p.status==KSWORD_ARK_PLATFORM_CONTROL_STATUS_UNSUPPORTED ? 5 : 3;
    return {code,Json::object({{L"io",ioJson(r.io)},{L"status",Json::number(p.status)},{L"lastStatus",Json::hex(static_cast<std::uint32_t>(p.lastStatus))},{L"scope",Json::number(p.scope)},{L"index",Json::number(p.entryIndex)},{L"flags",Json::hex(p.responseFlags)},{L"table",Json::hex(p.tableAddress)},{L"slot",Json::hex(p.slotAddress)},{L"previous",Json::hex(p.previousValue)},{L"current",Json::hex(p.currentValue)},{L"requested",Json::hex(p.requestedValue)}}),{}};
}
Result research(const Args& args) {
    (void)args.require(L"--topic"); const auto topic=args.u32(L"--topic"), max=args.u32(L"--max-entries",KSWORD_ARK_RESEARCH_DEFAULT_MAX_ENTRIES);
    if (!topic || topic>KSWORD_ARK_RESEARCH_TOPIC_COUNT || !max || max>KSWORD_ARK_RESEARCH_HARD_MAX_ENTRIES) throw std::invalid_argument("topic or max-entries out of range");
    const auto r=DriverClient().queryResearchTopic(topic,max); const auto& p=r.response;
    std::vector<Json> entries;
    for (const auto& e:r.entries) {
        std::wstring name; for (const char ch:e.name) { if (!ch) break; name.push_back(static_cast<unsigned char>(ch)); }
        entries.push_back(Json::object({{L"name",Json::string(name)},{L"kind",Json::number(e.kind)},{L"sourceMask",Json::hex(e.sourceMask)},{L"state",Json::number(e.state)},{L"confidence",Json::number(e.confidence)},{L"fieldId",Json::number(e.fieldId)},{L"lastStatus",Json::hex(static_cast<std::uint32_t>(e.lastStatus))},{L"ioctl",Json::hex(e.ioControlCode)},{L"function",Json::number(e.functionNumber)},{L"method",Json::number(e.method)},{L"access",Json::number(e.access)},{L"registryFlags",Json::hex(e.registryFlags)},{L"requiredCapability",Json::hex(e.requiredCapability)},{L"value0",Json::hex(e.value0)},{L"value1",Json::hex(e.value1)},{L"value2",Json::hex(e.value2)},{L"value3",Json::hex(e.value3)}}));
    }
    const auto code=!r.io.ok ? ioCode(r.io,r.unsupported) : p.queryStatus==KSWORD_ARK_RESEARCH_STATUS_OK ? 0 : p.queryStatus==KSWORD_ARK_RESEARCH_STATUS_TRUNCATED ? 6 : p.queryStatus==KSWORD_ARK_RESEARCH_STATUS_SOURCE_MISSING ? 5 : 3;
    return {code,Json::object({{L"io",ioJson(r.io)},{L"version",Json::number(p.version)},{L"topic",Json::number(p.topicId)},{L"status",Json::number(p.queryStatus)},{L"flags",Json::hex(p.responseFlags)},{L"lastStatus",Json::hex(static_cast<std::uint32_t>(p.lastStatus))},{L"totalCount",Json::number(p.totalCount)},{L"returnedCount",Json::number(p.returnedCount)},{L"registeredIoctlCount",Json::number(p.registeredIoctlCount)},{L"duplicateIoctlCount",Json::number(p.duplicateIoctlCount)},{L"currentIrql",Json::number(p.currentIrql)},{L"requestorMode",Json::number(p.requestorMode)},{L"processorGroup",Json::number(p.processorGroup)},{L"processorNumber",Json::number(p.processorNumber)},{L"activeGroupCount",Json::number(p.activeGroupCount)},{L"activeProcessorCount",Json::number(p.activeProcessorCount)},{L"requestorPid",Json::number(p.requestorProcessId)},{L"requestorTid",Json::number(p.requestorThreadId)},{L"systemTime",Json::count(p.systemTime100ns)},{L"interruptTime",Json::count(p.interruptTime100ns)},{L"performanceCounter",Json::count(p.performanceCounter)},{L"performanceFrequency",Json::count(p.performanceFrequency)},{L"driverObject",Json::hex(p.driverObjectAddress)},{L"driverImageBase",Json::hex(p.driverImageBase)},{L"driverImageSize",Json::count(p.driverImageSize)},{L"deviceObject",Json::hex(p.deviceObjectAddress)},{L"topAttachedDevice",Json::hex(p.topAttachedDeviceAddress)},{L"devicePhysicalAddress",Json::hex(p.deviceObjectPhysicalAddress)},{L"entries",Json::array(entries)}}),{}};
}


template<std::size_t N> std::wstring fixedString(const wchar_t (&text)[N]) {
    std::size_t i=0; while (i<N && text[i]) ++i; return std::wstring(text,i);
}
Json protectJson(const ProcessProtectStateResult& r) {
    const auto& s=r.response; std::vector<Json> rules, trusted;
    for (unsigned long i=0; i<s.ruleCount && i<KSWORD_ARK_PROCESS_PROTECT_MAX_RULES; ++i) {
        const auto& v=s.rules[i];
        rules.push_back(Json::object({{L"ruleId",Json::number(v.ruleId)},{L"flags",Json::hex(v.flags)},{L"targetKind",Json::number(v.targetKind)},{L"targetProcessId",Json::number(v.targetProcessId)},{L"protectAccessMask",Json::hex(v.protectAccessMask)},{L"kernelProtection",Json::hex(v.kernelProtection)},{L"hardenFlags",Json::hex(v.hardenFlags)},{L"targetImage",Json::string(fixedString(v.targetImage))},{L"ruleName",Json::string(fixedString(v.ruleName))},{L"hitCount",Json::count(s.ruleHitCounts[i])},{L"kernelApplyCount",Json::count(s.ruleKernelApplyCounts[i])}}));
    }
    for (unsigned long i=0; i<s.trustedCount && i<KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED; ++i) {
        const auto& v=s.trusted[i]; trusted.push_back(Json::object({{L"flags",Json::hex(v.flags)},{L"kind",Json::number(v.kind)},{L"processId",Json::number(v.processId)},{L"image",Json::string(fixedString(v.image))}}));
    }
    return Json::object({{L"io",ioJson(r.io)},{L"version",Json::number(s.version)},{L"globalFlags",Json::hex(s.globalFlags)},{L"capabilityStatus",Json::number(s.capabilityStatus)},{L"objectCallbackStatus",Json::hex(static_cast<std::uint32_t>(s.objectCallbackStatus))},{L"configVersion",Json::count(s.configVersion)},{L"appliedAtUtc100ns",Json::count(s.appliedAtUtc100ns)},{L"scanIntervalMs",Json::number(s.scanIntervalMs)},{L"trackedProcessCount",Json::number(s.trackedProcessCount)},{L"evaluatedCount",Json::count(s.evaluatedCount)},{L"strippedCount",Json::count(s.strippedCount)},{L"trustedBypassCount",Json::count(s.trustedBypassCount)},{L"kernelApplyCount",Json::count(s.kernelApplyCount)},{L"selfHealCount",Json::count(s.selfHealCount)},{L"kernelApplyFailureCount",Json::count(s.kernelApplyFailureCount)},{L"hardenApplyCount",Json::count(s.hardenApplyCount)},{L"rules",Json::array(rules)},{L"trusted",Json::array(trusted)}});
}
Result protect(const Args& args, bool apply) {
    DriverClient client;
    if (!apply) {const auto r=client.queryProcessProtectState(); return {r.io.ok?0:ioCode(r.io,false),protectJson(r),{}};}
    if (!args.has(L"--confirm")) throw std::invalid_argument("--confirm is required for whole-table replacement");
    const auto payload=readPayloadFile(args.require(L"--data-file"));
    if (payload.win32Error) return {3,Json::object({{L"win32Error",Json::number(payload.win32Error)}}),{L"Could not read configuration file."}};
    if (payload.bytes.size()!=sizeof(KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST)) throw std::invalid_argument("configuration file must contain exactly one versioned KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST");
    KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST input{}; std::memcpy(&input,payload.bytes.data(),sizeof(input));
    if (input.size!=sizeof(input) || input.version!=KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION || input.ruleCount>KSWORD_ARK_PROCESS_PROTECT_MAX_RULES || input.trustedCount>KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED) throw std::invalid_argument("invalid configuration protocol header or counts");
    std::vector<KSWORD_ARK_PROCESS_PROTECT_RULE> rules(input.rules,input.rules+input.ruleCount);
    std::vector<KSWORD_ARK_PROCESS_PROTECT_TRUSTED> trusted(input.trusted,input.trusted+input.trustedCount);
    const auto validTarget=[](unsigned long kind, unsigned long pid, const wchar_t* image) {
        return kind==KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID ? pid!=0 :
            (kind==KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME || kind==KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH) && image[0]!=0;
    };
    for (auto& rule:rules) {
        if (rule.targetImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS-1] || rule.ruleName[KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS-1]) throw std::invalid_argument("rule strings must be NUL terminated");
        rule.protectAccessMask &= KSWORD_ARK_PROCESS_PROTECT_ACCESS_ALL;
        rule.hardenFlags &= KSWORD_ARK_PROCESS_PROTECT_HARDEN_ALL;
        if (rule.targetKind!=KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID) rule.targetProcessId=0;
        if (rule.flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED) {
            const auto type=rule.kernelProtection & 7UL, signer=(rule.kernelProtection & 0xf0UL)>>4;
            if ((!rule.protectAccessMask && !rule.kernelProtection) || !validTarget(rule.targetKind,rule.targetProcessId,rule.targetImage) ||
                (rule.kernelProtection && (rule.kernelProtection>255 || (type!=KSWORD_PS_PROTECTED_TYPE_LIGHT && type!=KSWORD_PS_PROTECTED_TYPE_FULL) || !signer || signer>KSWORD_PS_PROTECTED_SIGNER_APP_VALUE))) throw std::invalid_argument("invalid enabled protection rule; no configuration was sent");
        }
    }
    for (auto& item:trusted) {
        if (item.image[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS-1]) throw std::invalid_argument("trusted image must be NUL terminated");
        if (item.kind!=KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID) item.processId=0;
        if ((item.flags & KSWORD_ARK_PROCESS_PROTECT_TRUSTED_FLAG_ENABLED) && !validTarget(item.kind,item.processId,item.image)) throw std::invalid_argument("invalid enabled trusted entry; no configuration was sent");
    }
    const auto changed=client.setProcessProtectConfig(input.globalFlags,rules,trusted,input.scanIntervalMs);
    if (!changed.ok) {const auto after=client.queryProcessProtectState(); return {ioCode(changed,false),Json::object({{L"io",ioJson(changed)},{L"state",protectJson(after)}}),{L"The driver may clear the rule and trusted tables on a rejected configuration; inspect the returned state."}};}
    const auto after=client.queryProcessProtectState();
    const auto interval=input.scanIntervalMs>=KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MIN_MS && input.scanIntervalMs<=KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MAX_MS ? input.scanIntervalMs : KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS;
    bool verified=after.io.ok && after.response.ruleCount==input.ruleCount && after.response.trustedCount==input.trustedCount && after.response.globalFlags==input.globalFlags && after.response.scanIntervalMs==interval;
    if (verified) for (unsigned long i=0;i<input.ruleCount;++i) if (std::memcmp(&rules[i],&after.response.rules[i],sizeof(rules[i]))!=0) {verified=false;break;}
    if (verified) for (unsigned long i=0;i<input.trustedCount;++i) if (std::memcmp(&trusted[i],&after.response.trusted[i],sizeof(trusted[i]))!=0) {verified=false;break;}
    return {verified?0:6,Json::object({{L"io",ioJson(changed)},{L"verified",Json::boolean(verified)},{L"state",protectJson(after)}}),verified?std::vector<std::wstring>{}:std::vector<std::wstring>{L"Configuration write was accepted, but readback did not match; inspect current state."}};
}
Json tokenJson(const ProcessTokenPrivilegeResult& r) {
    std::vector<Json> entries;
    for (const auto& e:r.entries) {
        const auto luid=(static_cast<std::uint64_t>(static_cast<std::uint32_t>(e.luidHighPart))<<32)|e.luidLowPart;
        entries.push_back(Json::object({{L"luid",Json::hex(luid)},{L"attributes",Json::hex(e.attributes)},{L"action",Json::number(e.action)}}));
    }
    return Json::object({{L"io",ioJson(r.io)},{L"status",Json::number(r.status)},{L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))},{L"processId",Json::number(r.processId)},{L"creationTime",Json::count(r.processCreateTime100ns)},{L"requestedCount",Json::number(r.requestedCount)},{L"appliedCount",Json::number(r.appliedCount)},{L"failedIndex",Json::number(r.failedIndex)},{L"entries",Json::array(entries)}});
}
int tokenCode(const ProcessTokenPrivilegeResult& r) {
    return !r.io.ok ? ioCode(r.io,r.unsupported) : r.status==KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ? 0 : r.status==KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL ? 6 : 3;
}
Result token(const Args& args, unsigned long action) {
    (void)args.require(L"--pid"); const auto pid=args.u32(L"--pid"); const auto creation=args.integer(L"--creation-time",0);
    if (!pid) throw std::invalid_argument("--pid must be nonzero");
    DriverClient client;
    if (!action) {const auto r=client.queryProcessTokenPrivileges(pid,creation);return {tokenCode(r),tokenJson(r),{}};}
    if (!creation || !args.has(L"--confirm")) throw std::invalid_argument("nonzero --creation-time and --confirm are required for adjustment");
    if (args.has(L"--luid") == args.has(L"--name")) throw std::invalid_argument("specify exactly one of --luid or --name");
    std::uint64_t luid=0;
    if (args.has(L"--name")) {
        LUID native{}; const auto name=args.require(L"--name");
        if (!LookupPrivilegeValueW(nullptr,name.c_str(),&native)) return {3,Json::object({{L"win32Error",Json::number(GetLastError())}}),{L"Privilege name could not be resolved."}};
        luid=(static_cast<std::uint64_t>(static_cast<std::uint32_t>(native.HighPart))<<32)|native.LowPart;
    } else luid=args.integer(L"--luid");
    const auto before=client.queryProcessTokenPrivileges(pid,creation);
    if (tokenCode(before)) return {tokenCode(before),Json::object({{L"before",tokenJson(before)}}),{L"The requested process token could not be verified."}};
    ProcessTokenPrivilegeEntry edit{}; bool found=false;
    for (const auto& e:before.entries) if (((static_cast<std::uint64_t>(static_cast<std::uint32_t>(e.luidHighPart))<<32)|e.luidLowPart)==luid) {edit=e;found=true;break;}
    if (!found) return {3,Json::object({{L"before",tokenJson(before)}}),{L"Privilege not present in the specified token."}};
    edit.action=action;
    const auto changed=client.adjustProcessTokenPrivileges(pid,creation,{edit},action==KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE);
    if (tokenCode(changed)) return {tokenCode(changed),Json::object({{L"before",tokenJson(before)},{L"adjustment",tokenJson(changed)}}),{}};
    const auto after=client.queryProcessTokenPrivileges(pid,creation);
    bool present=false,enabled=false;
    for (const auto& e:after.entries) if (((static_cast<std::uint64_t>(static_cast<std::uint32_t>(e.luidHighPart))<<32)|e.luidLowPart)==luid) {present=true;enabled=(e.attributes & SE_PRIVILEGE_ENABLED)!=0;break;}
    const bool verified=tokenCode(after)==0 && (action==KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE ? !present : present && enabled==(action==KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE));
    return {verified?0:6,Json::object({{L"before",tokenJson(before)},{L"adjustment",tokenJson(changed)},{L"after",tokenJson(after)},{L"verified",Json::boolean(verified)}}),verified?std::vector<std::wstring>{}:std::vector<std::wstring>{L"Adjustment was accepted but its resulting state could not be verified."}};
}
void addR0(Command c) { c.supportsR0=true; c.supportsR3=false; c.defaultBackend=L"r0"; addCommand(std::move(c)); }
}
void registerLowlevelCommands() {
    for (const bool start:{false,true}) {
        const std::wstring verb=start?L"start":L"stop";
        addR0({L"r0 io-timer "+verb,L"KswordCLI.exe r0 io-timer "+verb+L" --driver NAME --driver-object VA --device-object VA --timer VA --confirm [--backend r0] [--json]",L"Control an I/O timer with three-part snapshot identity.",L"Required: --driver, --driver-object, --device-object, --timer, --confirm.",L"R0 revalidates the driver, device and timer identity before control.",[start](const Args& a){return timer(a,start?KSWORD_ARK_IO_TIMER_CONTROL_ACTION_START:KSWORD_ARK_IO_TIMER_CONTROL_ACTION_STOP);}});
    }
    addR0({L"r0 debug-output-control",L"KswordCLI.exe r0 debug-output-control --action query|start|stop [--confirm] [--backend r0] [--json]",L"Query or control R0 debug output capture.",L"Required: --action. --confirm is required for start and stop.",L"Starting capture clears the existing buffer.",debugOutput});
    addR0({L"r0 platform-edit",L"KswordCLI.exe r0 platform-edit --scope N --index N --table VA --expected VA --value VA --confirm [--backend r0] [--json]",L"Edit a supported HAL or WDF function slot.",L"All options are required.",L"Uses the R0 snapshot identity and expected value for a checked replacement.",platform});
    addR0({L"r0 process-protect query",L"KswordCLI.exe r0 process-protect query [--backend r0] [--json]",L"Query the full R0 process protection configuration and status.",L"No additional options.",L"Capability status reports whether the object callback is available.",[](const Args& a){return protect(a,false);}});
    addR0({L"r0 process-protect apply",L"KswordCLI.exe r0 process-protect apply --data-file PATH --confirm [--backend r0] [--json]",L"Replace the complete R0 process protection configuration.",L"Required: --data-file, --confirm.",L"The file contains exactly one binary KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST of the current protocol version. Both rule and trusted tables are replaced; omitted entries are removed. State is read back after writing.",[](const Args& a){return protect(a,true);}});
    for (unsigned long action=0; action<=3; ++action) {
        const std::wstring verb=action==0?L"query":action==1?L"enable":action==2?L"disable":L"remove";
        addR0({L"r0 token-privilege "+verb, L"KswordCLI.exe r0 token-privilege "+verb+L" --pid PID [--creation-time FILETIME] [--luid LUID] [--name NAME] [--confirm] [--backend r0] [--json]",L"Query or adjust the target primary token privileges in R0.",L"Required: --pid. Adjustment requires --creation-time, --confirm and exactly one of --luid or --name.",L"Writes are identity-bound and read back; remove is irreversible for this token.",[action](const Args& a){return token(a,action);}});
    }
    addR0({L"r0 research-topic",L"KswordCLI.exe r0 research-topic --topic N [--max-entries N] [--backend r0] [--json]",L"Query one R0 kernel research topic and its evidence.",L"Required: --topic. Optional: --max-entries (1..16).",L"Returns the live context and evidence records; truncated results have exit code 6.",research});
}
}
