"""Test production PFN backend selection with isolated Win32/driver stubs."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = r'''
#include "HEADER"
#include "NATIVE_HEADER"
#include <cassert>
static unsigned nativeCalls = 0, driverOpens = 0;
static unsigned rangeCount = 0, driverCalls = 0;
static bool enableDriver = false, sizeHint = true, legacy = false, stale = false;
static LONG NTAPI fakeNative(ULONG, PVOID packet, ULONG, PULONG required) {
    ++nativeCalls;
    if (!rangeCount) return static_cast<LONG>(0xc0000022UL);
    auto& info = *static_cast<KSW_PF_SUPERFETCH*>(packet);
    assert(info.InfoClass == 17 && required);
    auto* fields = static_cast<ULONG*>(info.Buffer);
    const bool v2 = fields[0] == 2;
    if (v2 && legacy) return static_cast<LONG>(0xc000000dUL);
    const ULONG head = v2 ? 16UL : 8UL;
    const ULONG bytes = head + static_cast<ULONG>(rangeCount * sizeof(KSW_PF_RANGE));
    if (sizeHint) *required = bytes;
    if (info.Length < bytes) return static_cast<LONG>(0x80000005UL);
    fields[v2 ? 2 : 1] = rangeCount;
    if (v2) fields[3] = 0xfeedbaad; // Reserved word is not part of RangeCount.
    auto* rows = reinterpret_cast<KSW_PF_RANGE*>(reinterpret_cast<unsigned char*>(fields) + head);
    for (unsigned i=0; i<rangeCount; ++i) rows[i] = {2ULL*i,1};
    return 0;
}
static FARPROC WINAPI fakeGetProcAddress(HMODULE, LPCSTR) { return reinterpret_cast<FARPROC>(fakeNative); }
static HMODULE WINAPI fakeGetModuleHandleW(LPCWSTR) { return reinterpret_cast<HMODULE>(1); }
static void WINAPI fakeGetNativeSystemInfo(LPSYSTEM_INFO info) { info->wProcessorArchitecture=PROCESSOR_ARCHITECTURE_AMD64; info->dwPageSize=4096; }
static BOOL WINAPI fakeImpersonateSelf(SECURITY_IMPERSONATION_LEVEL) { return FALSE; }
static BOOL WINAPI fakeOpenThreadToken(HANDLE, DWORD, BOOL, PHANDLE) { SetLastError(ERROR_NO_TOKEN); return FALSE; }
#define GetNativeSystemInfo fakeGetNativeSystemInfo
#define GetProcAddress fakeGetProcAddress
#define GetModuleHandleW fakeGetModuleHandleW
#define ImpersonateSelf fakeImpersonateSelf
#define OpenThreadToken fakeOpenThreadToken
#include "IMPLEMENTATION"
namespace ksword::ark {
DriverHandle::~DriverHandle() {}
DriverHandle::DriverHandle(HANDLE value) noexcept : m_handle(value) {}
DriverHandle& DriverHandle::operator=(DriverHandle&& other) noexcept { m_handle=other.m_handle; other.m_handle=INVALID_HANDLE_VALUE; return *this; }
bool DriverHandle::isValid() const noexcept { return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr; }
DriverHandle DriverClient::openSilently(unsigned long) const { ++driverOpens; return DriverHandle(enableDriver ? reinterpret_cast<HANDLE>(1) : nullptr); }
IoResult DriverClient::deviceIoControl(unsigned long code,void* input,unsigned long,void* output,unsigned long size,DriverHandle*) const {
    assert(code == IOCTL_KSWORD_ARK_QUERY_PFN_BATCH);
    const auto& request = *static_cast<KSWORD_ARK_PFN_REQUEST*>(input);
    assert(request.operation == KSWORD_ARK_PFN_RANGES);
    ++driverCalls;
    const ULONG cap = request.count ? request.count : KSWORD_ARK_PFN_MAX_RANGES;
    auto& response = *static_cast<KSWORD_ARK_PFN_RESPONSE*>(output);
    response.version = KSWORD_ARK_PFN_VERSION;
    response.operation = request.operation;
    IoResult io; io.ok = true; io.bytesReturned = sizeof(response);
    if (stale || rangeCount > cap) { response.nativeStatus = static_cast<LONG>(0x80000005UL); return io; }
    response.count = rangeCount;
    assert(size >= sizeof(response) + rangeCount*sizeof(KSWORD_ARK_PFN_RANGE));
    auto* rows = reinterpret_cast<KSWORD_ARK_PFN_RANGE*>(&response + 1);
    for (unsigned i=0; i<rangeCount; ++i) rows[i] = {2ULL*i,1};
    io.bytesReturned += static_cast<ULONG>(rangeCount * sizeof(*rows)); return io;
}
}
int main() {
 using namespace ksword::ark;
 std::vector<KSWORD_ARK_PFN_RANGE> ranges; std::vector<KSWORD_ARK_PFN_OWNER> owners;
 std::vector<KSWORD_ARK_PFN_IDENTITY> pages; std::vector<KSWORD_ARK_PFN_MAPPING> maps;
 { PfnQueryClient client(PfnBackend::NativeOnly);
   assert(client.ranges(ranges)<0); assert(client.owners(owners)<0); assert(client.pages(1,1,pages)<0); assert(client.identities({1},pages)<0);
   assert(nativeCalls>0 && driverOpens==0); assert(!client.mappingAvailable());
   assert(client.mappings(1,1,{1},maps)<0 && driverOpens==0);
 }
 nativeCalls=0;
 { PfnQueryClient client(PfnBackend::DriverOnly);
   assert(client.ranges(ranges)<0); assert(client.owners(owners)<0); assert(client.pages(1,1,pages)<0); assert(client.identities({1},pages)<0);
   assert(nativeCalls==0 && driverOpens==4); assert(client.mappings(1,0,{1},maps)<0 && driverOpens==4);
   assert(client.mappings(1,1,{1},maps)<0 && driverOpens==5);
 }
 nativeCalls=driverOpens=0;
 { PfnQueryClient client; assert(client.ranges(ranges)<0); assert(nativeCalls>0 && driverOpens==1); }
 for (const auto count : {512U, 1500U}) {
   for (const bool useHint : {false,true}) {
     for (const bool oldSystem : {false,true}) {
       rangeCount=count; sizeHint=useHint; legacy=oldSystem; nativeCalls=0;
       PfnQueryClient client(PfnBackend::NativeOnly);
       assert(client.ranges(ranges)==0 && ranges.size()==count && ranges.back().firstPfn==2ULL*(count-1));
       const auto& trace=client.lastTrace(); assert(trace.nativeAttemptCount==(oldSystem?2U:1U));
       assert(trace.nativeAttempts[trace.nativeAttemptCount-1].status==0);
     }
   }
   enableDriver=true; driverCalls=0;
   PfnQueryClient client(PfnBackend::DriverOnly);
   assert(client.ranges(ranges)==0 && ranges.size()==count && driverCalls==(count==512?1U:3U));
 }
 rangeCount=65537; legacy=false; sizeHint=true; nativeCalls=0;
 { PfnQueryClient client(PfnBackend::NativeOnly); assert(client.ranges(ranges)<0 && ranges.empty() && nativeCalls<4); }
 stale=true; driverCalls=0;
 { PfnQueryClient client(PfnBackend::DriverOnly); assert(client.ranges(ranges)<0 && ranges.empty() && driverCalls==8); }
}
'''

def main():
    out = ROOT / 'tools/tests/x64/Release'
    obj = out / 'PfnBackendPolicy/obj'
    obj.mkdir(parents=True, exist_ok=True)
    source = FIXTURE.replace('NATIVE_HEADER', (ROOT/'third_party/systeminformer_dyn/PfnNative.h').as_posix())
    source = source.replace('"HEADER"', '"' + (ROOT/'Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverPfn.h').as_posix() + '"').replace('IMPLEMENTATION', (ROOT/'Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverPfn.cpp').as_posix())
    (obj/'fixture.cpp').write_text(source, encoding='utf-8')
    exe = out/'pfn_backend_policy_tests.exe'
    subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/W4','/WX','/wd4191','/DNOMINMAX','/DUNICODE','/D_UNICODE',str(obj/'fixture.cpp'),'/Fe:'+str(exe),'advapi32.lib'],cwd=obj,check=True)
    subprocess.run([str(exe)],cwd=obj,check=True,timeout=10)
    print('PFN_BACKEND_POLICY_PASS')

if __name__ == '__main__': main()
