"""Shadow SSDT CLI transaction fixture. No driver or kernel writes are used."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include <cassert>
#include "SOURCE"
static int scenario=0, enumCalls=0, patchCalls=0, forceCalls=0, readCalls=0;
using namespace ksword::ark;
SsdtEnumResult DriverClient::enumerateShadowSsdt(unsigned long) const {
    ++enumCalls; SsdtEnumResult out{}; out.io.ok=true; out.version=KSWORD_ARK_ENUM_SSDT_PROTOCOL_VERSION;
    out.totalCount=out.returnedCount=1; out.serviceTableBase=0x1000; out.serviceCountFromTable=20;
    SsdtEntry row{}; row.serviceIndex=2; row.tableEntrySize=4; row.tableEntryAddress=0x1008;
    row.currentTableValue=0x04030201; row.flags=KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED|
        KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID|KSWORD_ARK_SSDT_ENTRY_FLAG_SHADOW_TABLE|
        KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_VALUE_CAPTURED;
    if(scenario==1) row.tableEntryAddress++;
    if(scenario==2 && enumCalls==2) out.serviceTableBase=0x2000;
    out.entries.push_back(row); if(scenario==3) {out.entries.push_back(row);out.totalCount=out.returnedCount=2;}
    return out;
}
KernelInlinePatchResult DriverClient::patchInlineHook(std::uint64_t address,unsigned long mode,unsigned long n,
    const std::vector<std::uint8_t>& old,const std::vector<std::uint8_t>& clean,unsigned long flags) const {
    ++patchCalls; assert(address==0x1008 && mode==KSWORD_ARK_INLINE_PATCH_MODE_RESTORE_BYTES && n==4);
    assert(old==std::vector<std::uint8_t>({1,2,3,4}) && clean==std::vector<std::uint8_t>({5,6,7,8}));
    KernelInlinePatchResult r{}; r.io.ok=true; r.io.bytesReturned=sizeof(KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE);
    r.version=KSWORD_ARK_KERNEL_HOOK_PROTOCOL_VERSION; r.functionAddress=address;
    if(flags) {++forceCalls;r.status=KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED;r.bytesPatched=4;}
    else r.status=scenario==4?KSWORD_ARK_KERNEL_HOOK_STATUS_PATCH_FAILED:KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED;
    return r;
}
namespace ks::r3::kernel {
bool ReadKernelExact(const DriverClient&,std::uint64_t,std::uint32_t,std::vector<std::uint8_t>& bytes) {
    ++readCalls; bytes=forceCalls && scenario!=5?std::vector<std::uint8_t>{5,6,7,8}:std::vector<std::uint8_t>{1,2,3,4};return true;
}
bool ReadTrustedImageBaseline(const DriverClient&,std::uint64_t,std::uint32_t,TrustedImageBaseline& b,std::wstring& e) {
    if(scenario==6){e=L"no identity";return false;} b.bytes={5,6,7,8};b.sha256=L"abc";b.moduleBase=0x1000;
    b.moduleSize=4096;b.ntPath=L"\\SystemRoot\\fixture.sys";return true;
}
}
static ks::cli::Args arguments() { ks::cli::Args a; a.values={{L"--index",L"2"},{L"--expected-table",L"0x1000"},
    {L"--expected-current",L"01020304"},{L"--expected-baseline",L"05060708"},{L"--expected-sha256",L"abc"},
    {L"--confirm",L""},{L"--confirmation",L"RESTORE SHADOW SSDT"}}; return a; }
int main() {
    auto a=arguments(); scenario=0; assert(ks::cli::run(a,false).code==0 && forceCalls==0 && patchCalls==1);
    patchCalls=enumCalls=readCalls=forceCalls=0; assert(ks::cli::run(a,true).code==0 && patchCalls==2 && forceCalls==1);
    for(int s:{1,2,3,4,6}) { scenario=s;patchCalls=enumCalls=readCalls=forceCalls=0;assert(ks::cli::run(a,true).code!=0 && forceCalls==0); }
    scenario=5;patchCalls=enumCalls=readCalls=forceCalls=0;assert(ks::cli::run(a,true).code==6 && forceCalls==1);
    scenario=0;patchCalls=enumCalls=readCalls=forceCalls=0;a.values[L"--expected-current"]=L"00000000";
    assert(ks::cli::run(a,true).code!=0 && forceCalls==0);
    a=arguments();a.values.erase(L"--confirm");bool rejected=false;
    try{ks::cli::run(a,true);}catch(const std::invalid_argument&){rejected=true;}assert(rejected);
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix="ksword-ssdt-") as d:
        d = Path(d)
        (d / "fixture.cpp").write_text(HARNESS.replace("SOURCE", (ROOT / "KswordCLI/ShadowSsdtRestore.cpp").as_posix()), encoding="utf-8")
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/W4", "/WX", str(d / "fixture.cpp"),
            str(ROOT / "KswordCLI/CommandRegistry.cpp"), str(ROOT / "KswordCLI/R3Input.cpp"), "/Fe:" + str(d / "fixture.exe"),
            "/link", "Iphlpapi.lib", "Ws2_32.lib"], cwd=d, check=True)
        subprocess.run([str(d / "fixture.exe")], cwd=d, check=True)
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/W4", "/WX", "/c",
            str(ROOT / "shared/usermode/backend/kernel/TrustedImageBaseline.cpp")], cwd=d, check=True)
        print("SHADOW_SSDT_FIXTURE_PASS")

if __name__ == "__main__":
    main()
