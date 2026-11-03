#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winioctl.h>
#include "shared/driver/KswordArkManagedNetworkIoctl.h"
#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>

#define min(a,b) ((a)<(b)?(a):(b))
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define MANAGED_LAYER_COUNT 4U
#define MAXULONG 0xffffffffUL
#define RtlCompareMemory TestRtlCompareMemory
using KIRQL = UCHAR;
struct FakeProcess { ULONG pid; ULONGLONG created; NTSTATUS exitStatus = STATUS_PENDING; int references = 0; };
using PEPROCESS = FakeProcess*;
using PPS_CREATE_NOTIFY_INFO = void*;
struct MANAGED_ROW { KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY Policy{}; PEPROCESS Process = nullptr; };
struct MANAGED_STATE {
    ULONG RowsLock = 0;
    HANDLE Engine = reinterpret_cast<HANDLE>(1);
    UINT64 Filters[MANAGED_LAYER_COUNT]{11,22,33,44};
    BOOLEAN EngineReady = TRUE, NotifyRegistered = TRUE;
    NTSTATUS LastStatus = STATUS_SUCCESS, NotifyStatus = STATUS_SUCCESS;
    ULONG Count = 0, Generation = 0;
    MANAGED_ROW Rows[KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES]{};
};
MANAGED_STATE* activeState = nullptr;
std::map<ULONG, PEPROCESS> processes;
NTSTATUS beginStatus = STATUS_SUCCESS, deleteStatus = STATUS_SUCCESS, addStatus = STATUS_SUCCESS;
NTSTATUS commitStatus = STATUS_SUCCESS, abortStatus = STATUS_SUCCESS, ensureStatus = STATUS_SUCCESS;
int closes = 0, aborts = 0;
void KeAcquireSpinLock(ULONG*, KIRQL* old) { *old = 0; }
void KeReleaseSpinLock(ULONG*, KIRQL) {}
MANAGED_STATE* ManagedAcquire() { return activeState; }
void ManagedRelease(MANAGED_STATE*) {}
SIZE_T RtlCompareMemory(const void* a, const void* b, SIZE_T size) { return std::memcmp(a,b,size)==0?size:0; }
NTSTATUS PsLookupProcessByProcessId(HANDLE pid, PEPROCESS* result) {
    const auto found = processes.find(HandleToULong(pid)); if (found == processes.end()) return STATUS_INVALID_CID;
    *result = found->second; ++(*result)->references; return STATUS_SUCCESS;
}
LONGLONG PsGetProcessCreateTimeQuadPart(PEPROCESS process) { return static_cast<LONGLONG>(process->created); }
NTSTATUS PsGetProcessExitStatus(PEPROCESS process) { return process->exitStatus; }
void ObDereferenceObject(PEPROCESS process) { if (--process->references < 0) throw std::runtime_error("process reference underflow"); }
NTSTATUS ManagedEnsureEngine(MANAGED_STATE* state) { if (NT_SUCCESS(ensureStatus)) state->EngineReady = TRUE; return ensureStatus; }
void ManagedCloseEngine(MANAGED_STATE* state) { ++closes; state->EngineReady = FALSE; }
NTSTATUS FwpmTransactionBegin0(HANDLE, ULONG) { return beginStatus; }
NTSTATUS FwpmFilterDeleteById0(HANDLE, UINT64) { return deleteStatus; }
NTSTATUS ManagedAddFilters(MANAGED_STATE*, UINT64 ids[MANAGED_LAYER_COUNT]) {
    if (NT_SUCCESS(addStatus)) for (ULONG i = 0; i < MANAGED_LAYER_COUNT; ++i) ids[i] = 100 + i;
    return addStatus;
}
NTSTATUS FwpmTransactionCommit0(HANDLE) { return commitStatus; }
NTSTATUS FwpmTransactionAbort0(HANDLE) { ++aborts; return abortStatus; }
enum { FWPS_LAYER_ALE_AUTH_CONNECT_V4=48, FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4=44,
    FWPS_LAYER_ALE_AUTH_CONNECT_V6=49, FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6=45 };
enum { FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS=6, FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS=6,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS=6, FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS=6 };
enum { FWP_UINT32=3, FWP_BYTE_ARRAY16_TYPE=13, FWPS_RIGHT_ACTION_WRITE=1,
    FWPS_METADATA_FIELD_PROCESS_ID=32, FWP_ACTION_CONTINUE=0x2006, FWP_ACTION_BLOCK=0x1001 };
struct FWP_BYTE_ARRAY16 { UCHAR byteArray16[16]; };
struct FWP_VALUE0 { ULONG type=0, uint32=0; FWP_BYTE_ARRAY16* byteArray16=nullptr; };
struct IncomingValue { FWP_VALUE0 value; };
struct FWPS_INCOMING_VALUES0 { USHORT layerId=48; ULONG valueCount=7; IncomingValue* incomingValue=nullptr; };
struct FWPS_INCOMING_METADATA_VALUES0 { ULONG currentMetadataValues=0; UINT64 processId=0; };
struct FWPS_FILTER0 {};
struct FWPS_CLASSIFY_OUT0 { ULONG actionType=0, rights=FWPS_RIGHT_ACTION_WRITE; };
__PRODUCTION_CORE__

static_assert(sizeof(KSWORD_ARK_NETWORK_MANAGED_PREFIX) == 24);
static_assert(sizeof(KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY) == 816);
static_assert(sizeof(KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST) == 832);
static_assert(sizeof(KSWORD_ARK_NETWORK_MANAGED_CONTROL_RESPONSE) == 32);
static_assert(sizeof(KSWORD_ARK_NETWORK_MANAGED_QUERY_RESPONSE) == 52256);
int checks = 0;
void check(bool value, const char* text) { ++checks; if (!value) throw std::runtime_error(text); }
KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY policy(UCHAR id, ULONG pid = 0, ULONGLONG created = 0) {
    KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY result{};
    result.policyId[0] = id; result.processId = pid; result.creationTime100ns = created;
    result.directionMask = KSWORD_ARK_NETWORK_DIRECTION_BOTH; result.flags = KSWORD_ARK_NETWORK_MANAGED_ENABLED;
    if (!pid) { result.prefixCount = 1; result.prefixes[0].family = 4; result.prefixes[0].prefixLength = 24;
        result.prefixes[0].address[0] = 192; result.prefixes[0].address[1] = 0; result.prefixes[0].address[2] = 2; }
    return result;
}
NTSTATUS apply(MANAGED_STATE* state, ULONG action, const KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY& entry) {
    KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST request{};
    request.version = 1; request.size = sizeof(request); request.action = action; request.policy = entry;
    return ManagedApply(state, &request);
}
int main() {
    try {
        const UCHAR matching[16]{192,0,2,88}, outside[16]{192,0,3,88};
        auto host = policy(1);
        check(ManagedPolicyValid(&host), "valid canonical host prefix rejected");
        check(ManagedPolicyMatches(&host,1,0,4,matching,TRUE), "IPv4 CIDR inbound mismatch");
        check(!ManagedPolicyMatches(&host,1,0,4,outside,TRUE), "IPv4 prefix escaped subnet");
        check(!ManagedPolicyMatches(&host,1,0,4,matching,FALSE), "missing address invented host match");
        UCHAR mapped4[16]{}; mapped4[10] = mapped4[11] = 0xff; std::memcpy(mapped4 + 12, matching, 4);
        check(ManagedPolicyMatches(&host,1,0,6,mapped4,TRUE), "dual-IP IPv4 traffic bypassed the IPv4 host prefix at V6 ALE");
        mapped4[0] = 1;
        check(!ManagedPolicyMatches(&host,1,0,6,mapped4,TRUE), "ordinary IPv6 address was confused with mapped IPv4");
        auto bad = host; bad.prefixes[0].address[3] = 1;
        check(!ManagedPolicyValid(&bad), "noncanonical host bits accepted");
        auto half = host; half.prefixes[0].prefixLength = 25;
        check(ManagedPolicyValid(&half) && ManagedPolicyMatches(&half,2,0,4,matching,TRUE), "non-byte IPv4 mask mismatch");
        UCHAR upperHalf[16]{192,0,2,200};
        check(!ManagedPolicyMatches(&half,2,0,4,upperHalf,TRUE), "non-byte IPv4 mask escaped prefix");
        bad = host; bad.prefixes[0].prefixLength = 33;
        check(!ManagedPolicyValid(&bad) && !ManagedPolicyMatches(&bad,1,0,4,matching,TRUE), "invalid IPv4 length accepted");
        bad = host; bad.prefixCount = 33;
        check(!ManagedPolicyValid(&bad) && !ManagedPolicyMatches(&bad,1,0,4,matching,TRUE), "prefix bounds lost");
        bad = host; bad.flags |= KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED;
        check(!ManagedPolicyValid(&bad) && !ManagedPolicyMatches(&bad,1,0,4,matching,TRUE), "query-only exited bit became an enabled policy");
        auto v6 = policy(2); v6.prefixes[0] = {}; v6.prefixes[0].family = 6; v6.prefixes[0].prefixLength = 64;
        v6.prefixes[0].address[0] = 0x20; v6.prefixes[0].address[1] = 1; v6.prefixes[0].address[2] = 0xdb; v6.prefixes[0].address[3] = 8;
        UCHAR remote6[16]{}; std::memcpy(remote6,v6.prefixes[0].address,16); remote6[15] = 99;
        check(ManagedPolicyValid(&v6) && ManagedPolicyMatches(&v6,2,0,6,remote6,TRUE), "IPv6 CIDR mismatch");
        check(!ManagedPolicyMatches(&v6,2,0,4,remote6,TRUE), "address family mismatch accepted");
        v6.prefixes[0].prefixLength = 128; v6.prefixes[0].address[15] = 99;
        check(ManagedPolicyValid(&v6) && ManagedPolicyMatches(&v6,1,0,6,remote6,TRUE), "IPv6 exact address mismatch");
        remote6[15] = 98; check(!ManagedPolicyMatches(&v6,1,0,6,remote6,TRUE), "IPv6 /128 mismatch accepted");
        auto processPolicy = policy(3,17,100);
        check(ManagedPolicyValid(&processPolicy) && ManagedPolicyMatches(&processPolicy,2,17,6,remote6,FALSE), "process-only all-host rule rejected");
        check(!ManagedPolicyMatches(&processPolicy,2,18,6,remote6,TRUE), "process rule applied to another PID");
        processPolicy.directionMask = 1; check(!ManagedPolicyMatches(&processPolicy,2,17,6,remote6,TRUE), "flow direction ignored");
        processPolicy.directionMask = 3; bad = processPolicy; bad.creationTime100ns = 0;
        check(!ManagedPolicyValid(&bad), "process instance accepted without creation identity");
        bad = host; bad.prefixCount = 0; check(!ManagedPolicyValid(&bad), "unscoped global block accepted");

        auto state = std::make_unique<MANAGED_STATE>(); activeState = state.get();
        IncomingValue values[7]{}; values[6].value.type = FWP_UINT32; values[6].value.uint32 = 0xc0000258;
        FWPS_INCOMING_VALUES0 fixed{}; fixed.incomingValue = values;
        FWPS_INCOMING_METADATA_VALUES0 metadata{};
        FWPS_CLASSIFY_OUT0 output{};
        ManagedClassify(&fixed,&metadata,nullptr,nullptr,0,&output);
        check(output.actionType == FWP_ACTION_CONTINUE && output.rights == FWPS_RIGHT_ACTION_WRITE, "empty table changed unrelated traffic");
        FakeProcess first{17,100}; processes[17] = &first;
        check(NT_SUCCESS(apply(state.get(),KSWORD_ARK_NETWORK_MANAGED_UPSERT,processPolicy)) && state->Count == 1 && first.references == 1, "process policy did not retain verified instance");
        check(NT_SUCCESS(apply(state.get(),KSWORD_ARK_NETWORK_MANAGED_UPSERT,host)) && state->Count == 2, "independent host policy not preserved");
        output = {}; ManagedClassify(&fixed,&metadata,nullptr,nullptr,0,&output);
        check(output.actionType == FWP_ACTION_BLOCK && output.rights == 0, "real classify did not enforce matching host-order IPv4 address");
        values[6].value.uint32 = 0xc0000358; output = {}; ManagedClassify(&fixed,&metadata,nullptr,nullptr,0,&output);
        check(output.actionType == FWP_ACTION_CONTINUE, "real classify blocked unrelated subnet");
        metadata.currentMetadataValues = FWPS_METADATA_FIELD_PROCESS_ID; metadata.processId = 17;
        output = {}; ManagedClassify(&fixed,&metadata,nullptr,nullptr,0,&output);
        check(output.actionType == FWP_ACTION_BLOCK, "real classify lost process-only rule");
        output.actionType = FWP_ACTION_BLOCK; output.rights = 0; ManagedClassify(&fixed,&metadata,nullptr,nullptr,0,&output);
        check(output.actionType == FWP_ACTION_BLOCK && output.rights == 0, "classify overwrote a decision without action-write rights");
        const auto previous = state->Rows[0].Policy;
        auto changed = processPolicy; changed.directionMask = 2; addStatus = STATUS_INSUFFICIENT_RESOURCES;
        check(!NT_SUCCESS(apply(state.get(),KSWORD_ARK_NETWORK_MANAGED_UPSERT,changed)), "transaction failure reported success");
        check(std::memcmp(&state->Rows[0].Policy,&previous,sizeof(previous)) == 0 && state->Count == 2 && first.references == 1, "failed transaction changed retained policy or leaked references");
        check(closes == 0 && state->EngineReady && aborts == 1, "ordinary policy rollback disabled other healthy managed policies");
        addStatus = STATUS_SUCCESS; first.exitStatus = STATUS_PROCESS_IS_TERMINATING;
        ManagedProcessNotify(&first, ULongToHandle(17), nullptr);
        check((state->Rows[0].Policy.flags & KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED) && !(state->Rows[0].Policy.flags & KSWORD_ARK_NETWORK_MANAGED_ENABLED), "process exit did not retire enforcement");
        check(!NT_SUCCESS(apply(state.get(),KSWORD_ARK_NETWORK_MANAGED_ENABLE,processPolicy)), "exited instance was reenabled");
        FakeProcess reused{17,200}; processes[17] = &reused;
        auto stale = policy(4,17,100);
        check(!NT_SUCCESS(apply(state.get(),KSWORD_ARK_NETWORK_MANAGED_UPSERT,stale)) && reused.references == 0, "reused PID accepted stale creation time");
        check(NT_SUCCESS(apply(state.get(),KSWORD_ARK_NETWORK_MANAGED_REMOVE,processPolicy)) && first.references == 0 && state->Count == 1, "remove failed to release old process identity");
        check(NT_SUCCESS(apply(state.get(),KSWORD_ARK_NETWORK_MANAGED_DISABLE,host)) && state->Count == 1, "disable removed unrelated rule");
        check(NT_SUCCESS(apply(state.get(),KSWORD_ARK_NETWORK_MANAGED_ENABLE,host)), "enable by policy ID failed");
        state->NotifyRegistered = FALSE; state->NotifyStatus = STATUS_ACCESS_DENIED;
        auto unsupported = policy(5,17,200);
        check(!NT_SUCCESS(apply(state.get(),KSWORD_ARK_NETWORK_MANAGED_UPSERT,unsupported)) && reused.references == 0, "missing exit provider falsely advertised process support");
        check(!(ManagedCapabilities(state.get()) & KSWORD_ARK_NETWORK_MANAGED_CAP_PROCESS_INSTANCE), "process capability survived provider failure");
        KSWORD_ARK_NETWORK_MANAGED_CONTROL_RESPONSE header{};
        ManagedControlHeader(state.get(),&header,KSWORD_ARK_NETWORK_STATUS_APPLIED,STATUS_SUCCESS);
        check(header.size == 32 && header.version == 1 && header.policyCount == 1 && header.capabilities == 7, "response ABI/capabilities incorrect");
        check(NT_SUCCESS(apply(state.get(),KSWORD_ARK_NETWORK_MANAGED_REMOVE,host)) && state->Count == 0, "per-ID removal left an unrelated policy");
        auto full = std::make_unique<MANAGED_STATE>();
        for (UCHAR id = 1; id <= 64; ++id) check(NT_SUCCESS(apply(full.get(),KSWORD_ARK_NETWORK_MANAGED_UPSERT,policy(id))), "bounded policy table rejected an available slot");
        check(full->Count == 64 && apply(full.get(),KSWORD_ARK_NETWORK_MANAGED_UPSERT,policy(65)) == STATUS_QUOTA_EXCEEDED, "policy table overflow accepted");
        check(NT_SUCCESS(apply(full.get(),KSWORD_ARK_NETWORK_MANAGED_UPSERT,policy(32))) && full->Count == 64, "updating one full-table policy changed unrelated entries");
        std::printf("MANAGED_NETWORK_CORE=PASS CHECKS=%d IPV4_IPV6_CIDR=1 POLICY_ROLLBACK=1 PROCESS_INSTANCE_EXIT=1 LIVE_NETWORK_CALLS=0\n",checks);
        return 0;
    } catch (const std::exception& error) { std::fprintf(stderr,"MANAGED_NETWORK_CORE=FAIL %s\n",error.what()); return 1; }
}
