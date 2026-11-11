"""Test production PFN backend selection with isolated Win32/driver stubs."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = r'''
#include "HEADER"
#include <cassert>
static unsigned nativeCalls = 0, driverOpens = 0;
static LONG NTAPI fakeNative(ULONG, PVOID, ULONG, PULONG) { ++nativeCalls; return static_cast<LONG>(0xc0000022UL); }
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
DriverHandle& DriverHandle::operator=(DriverHandle&& other) noexcept { m_handle=other.m_handle; other.m_handle=INVALID_HANDLE_VALUE; return *this; }
bool DriverHandle::isValid() const noexcept { return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr; }
DriverHandle DriverClient::openSilently(unsigned long) const { ++driverOpens; return {}; }
IoResult DriverClient::deviceIoControl(unsigned long,void*,unsigned long,void*,unsigned long,DriverHandle*) const { assert(false); return {}; }
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
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix="ksword-pfn-policy-") as temp:
        tmp = Path(temp)
        source = FIXTURE.replace('HEADER', (ROOT/'Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverPfn.h').as_posix()).replace('IMPLEMENTATION', (ROOT/'Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverPfn.cpp').as_posix())
        (tmp/'fixture.cpp').write_text(source, encoding='utf-8')
        exe = tmp/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/W4','/WX','/wd4191','/DNOMINMAX','/DUNICODE','/D_UNICODE',str(tmp/'fixture.cpp'),'/Fe:'+str(exe),'advapi32.lib'],cwd=tmp,check=True)
        subprocess.run([str(exe)],cwd=tmp,check=True,timeout=10)
    print('PFN_BACKEND_POLICY_PASS')

if __name__ == '__main__': main()
