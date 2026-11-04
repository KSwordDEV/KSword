"""Exercise PFN CLI routing and field/status preservation with a fake client."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=r'''
#include "REGISTRY"
#include "PFN_HEADER"
#include <fcntl.h>
#include <io.h>
#include <cstring>
static std::wstring scenario;
namespace ksword::ark {
DriverHandle::~DriverHandle() {}
PfnQueryClient::PfnQueryClient(PfnBackend backend):m_backend(backend) {}
PfnQueryClient::~PfnQueryClient() {}
long PfnQueryClient::ranges(std::vector<KSWORD_ARK_PFN_RANGE>& out) {
    m_trace={};m_trace.driverInvoked=m_backend==PfnBackend::DriverOnly;m_trace.driverAvailable=m_trace.driverInvoked;
    if(scenario==L"fail")return static_cast<long>(0xc0000022UL);
    out={{0x10,10},{0x30,3}};return 0;
}
long PfnQueryClient::owners(std::vector<KSWORD_ARK_PFN_OWNER>& out) {
    KSWORD_ARK_PFN_OWNER owner{};owner.processId=123;owner.processKey=0x1234;std::memcpy(owner.imageName,"fixture",7);out={owner};return 0;
}
long PfnQueryClient::pages(std::uint64_t first,std::uint32_t count,std::vector<KSWORD_ARK_PFN_IDENTITY>& out) {
    out.clear();for(std::uint32_t i=0;i<count;++i)out.push_back({i==1?~0ULL:0x66,first+i,0x123});return 0;
}
long PfnQueryClient::identities(const std::vector<std::uint64_t>& pfns,std::vector<KSWORD_ARK_PFN_IDENTITY>& out) {
    out.clear();for(auto p:pfns)out.push_back({0x42,p,0xabc});return 0;
}
long PfnQueryClient::mappings(std::uint32_t,std::uint64_t,const std::vector<std::uint64_t>& addrs,std::vector<KSWORD_ARK_PFN_MAPPING>& out) {
    m_trace={};m_trace.driverInvoked=true;m_trace.driverAvailable=true;
    out.clear();for(std::size_t i=0;i<addrs.size();++i)out.push_back({i+10,4096,i ? static_cast<long>(0xc0000005UL) : 0});return 0;
}
}
namespace ks::cli { void registerPfnCommands(); }
int wmain(int argc,wchar_t** argv) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    scenario=argv[1];++argv;--argc;ks::cli::registerPfnCommands();return ks::cli::dispatchR3(argc,argv).value_or(99);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-pfn-cli-") as temp:
        tmp=Path(temp)
        source=FIXTURE.replace("REGISTRY",(ROOT/"KswordCLI/CommandRegistry.h").as_posix()).replace(
            "PFN_HEADER",(ROOT/"Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverPfn.h").as_posix())
        (tmp/"fixture.cpp").write_text(source,encoding="utf-8")
        exe=tmp/"fixture.exe"
        subprocess.run(["cl","/nologo","/std:c++20","/EHsc","/utf-8","/W4","/WX","/DNOMINMAX",
            str(tmp/"fixture.cpp"),str(ROOT/"KswordCLI/CommandRegistry.cpp"),str(ROOT/"KswordCLI/PfnCommands.cpp"),
            "/Fe:"+str(exe)],cwd=tmp,check=True)
        def run(scenario,args,code):
            p=subprocess.run([str(exe),scenario,*args,"--json"],capture_output=True,timeout=10)
            assert p.returncode==code,(args,p.returncode,p.stdout,p.stderr)
            return json.loads(p.stdout)
        a=run("ok",["memory","pfn","ranges","--limit","1","--backend","r0"],0)
        assert a["backend"]=="r0" and a["data"]["trace"]["driverInvoked"] and a["data"]["displayTruncated"]
        b=run("ok",["memory","pfn","identity","--pfn","0x12"],0)
        assert b["backend"]=="r3" and b["data"]["pages"][0]["pfn"]=="0x12"
        c=run("ok",["memory","pfn","pages","--first","16","--count","3"],6)
        assert not c["data"]["complete"] and c["data"]["pages"][1]["frame"] is None
        d=run("ok",["memory","pfn","mappings","--pid","123","--creation-time","456","--addresses","0x1000,0x2000"],6)
        assert d["backend"]=="r0" and d["data"]["mappings"][1]["pfn"] is None
        run("ok",["memory","pfn","mappings","--pid","123","--creation-time","0","--addresses","1"],1)
        run("ok",["memory","pfn","identities","--pfns","1,,2"],1)
        run("ok",["memory","pfn","mappings","--pid","1","--creation-time","1","--addresses","1","--backend","r3"],1)
        e=run("fail",["memory","pfn","ranges","--backend","r0"],3)
        assert e["data"]["ranges"]==[] and e["data"]["ntStatus"]=="0xc0000022"
    print("CLI_PFN_PASS")


if __name__=="__main__":main()
