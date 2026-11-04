"""Test location value semantics against an isolated in-memory registry."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
#include "shared/usermode/backend/system/VirtualLocation.h"
#include "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include <cassert>
#include <cmath>
#include <map>
using namespace ks::r3::location;
namespace ksword::ark {
RegistryReadResult DriverClient::readRegistryValue(const std::wstring&,const std::wstring&,unsigned long) const{return {};}
RegistryOperationResult DriverClient::createRegistryKey(const std::wstring&) const{return {};}
RegistryOperationResult DriverClient::setRegistryValue(const std::wstring&,const std::wstring&,std::uint32_t,const std::vector<std::uint8_t>&) const{return {};}
RegistryOperationResult DriverClient::deleteRegistryValue(const std::wstring&,const std::wstring&) const{return {};}
}
struct Store:Registry {
    std::map<std::wstring,Value> values;int writes=0,failAt=-1;
    Value read(bool,const wchar_t* name) override {auto it=values.find(name);if(it!=values.end())return it->second;Value v;v.known=true;return v;}
    Operation write(bool,const wchar_t* name,DWORD type,const std::vector<std::uint8_t>& bytes) override {
        if(writes++==failAt)return {false,ERROR_ACCESS_DENIED};Value v;v.known=true;v.present=true;v.type=type;v.bytes=bytes;values[name]=v;return {true};}
    Operation remove(bool,const wchar_t* name) override {values.erase(name);return {true};}
};
int main(){Store r;auto before=readDefault(r);assert(before.values[0].known&&!before.values[0].present);
    Coordinate c;c.latitude=31.23456789;c.longitude=121.12345678;c.altitude=5;c.errorRadius=20;c.altitudeAccuracy=2;
    auto set=writeDefault(r,c);assert(set.success&&!set.partial&&set.after.valid[0]&&set.after.valid[1]);
    auto clear=clearDefault(r);assert(clear.success&&!clear.after.values[0].present);
    r.failAt=r.writes+2;auto partial=writeDefault(r,c);assert(!partial.success&&partial.partial);
    r.failAt=-1;auto provider=setProvider(r,true);assert(provider.success&&r.values[L"DisableWindowsLocationProvider"].type==REG_DWORD);
    assert(setProvider(r,false).success&&!r.read(true,L"DisableWindowsLocationProvider").present);
    const auto gcj=convert(c,CoordinateSystem::Wgs84,CoordinateSystem::Gcj02);
    assert(std::fabs(gcj.latitude-c.latitude)>0.0001);
    const auto roundtrip=convert(gcj,CoordinateSystem::Gcj02,CoordinateSystem::Wgs84);
    assert(std::fabs(roundtrip.latitude-c.latitude)<1e-7&&std::fabs(roundtrip.longitude-c.longitude)<1e-7);
    const auto bd=convert(c,CoordinateSystem::Wgs84,CoordinateSystem::Bd09);
    const auto fromBd=convert(bd,CoordinateSystem::Bd09,CoordinateSystem::Wgs84);
    assert(std::fabs(fromBd.latitude-c.latitude)<1e-5&&std::fabs(fromBd.longitude-c.longitude)<1e-5);
}
'''
CLI_SOURCE=r'''
#include "KswordCLI/CommandRegistry.h"
#include "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include <fcntl.h>
#include <io.h>
namespace ksword::ark {
RegistryReadResult DriverClient::readRegistryValue(const std::wstring&,const std::wstring&,unsigned long) const{return {};}
RegistryOperationResult DriverClient::createRegistryKey(const std::wstring&) const{return {};}
RegistryOperationResult DriverClient::setRegistryValue(const std::wstring&,const std::wstring&,std::uint32_t,const std::vector<std::uint8_t>&) const{return {};}
RegistryOperationResult DriverClient::deleteRegistryValue(const std::wstring&,const std::wstring&) const{return {};}
}
namespace ks::cli {void registerVirtualLocation();}
int wmain(int argc,wchar_t** argv){_setmode(_fileno(stdout),_O_U8TEXT);ks::cli::registerVirtualLocation();return ks::cli::dispatchR3(argc,argv).value_or(9);}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-location-") as temp:
        directory=Path(temp);src=directory/"location.cpp";src.write_text(SOURCE,encoding="utf-8")
        exe=directory/"location.exe"
        subprocess.run(["cl","/nologo","/std:c++20","/EHsc","/utf-8","/W4","/WX","/I"+str(ROOT),str(src),
            str(ROOT/"shared/usermode/backend/system/VirtualLocation.cpp"),"/Fe:"+str(exe),"/link","Advapi32.lib","RuntimeObject.lib"],cwd=directory,check=True)
        subprocess.run([str(exe)],check=True)
        cliSrc=directory/"cli.cpp";cliSrc.write_text(CLI_SOURCE,encoding="utf-8");cli=directory/"cli.exe"
        subprocess.run(["cl","/nologo","/std:c++20","/EHsc","/utf-8","/W4","/WX","/I"+str(ROOT),str(cliSrc),
            str(ROOT/"KswordCLI/CommandRegistry.cpp"),str(ROOT/"KswordCLI/VirtualLocationCommand.cpp"),
            str(ROOT/"shared/usermode/backend/system/VirtualLocation.cpp"),"/Fe:"+str(cli),"/link","Advapi32.lib","RuntimeObject.lib"],cwd=directory,check=True)
        result=subprocess.run([str(cli),"system","location","convert","--latitude","31.2","--longitude","121.5","--from","wgs84","--to","gcj02","--json"],capture_output=True)
        assert result.returncode==0 and json.loads(result.stdout)["data"]["latitude"]!=31.2,(result.returncode,result.stderr)
        refused=subprocess.run([str(cli),"system","location","set","--latitude","1","--longitude","2","--backend","r0","--json"],capture_output=True)
        assert refused.returncode==1 and json.loads(refused.stdout)["backend"]=="r0",(refused.returncode,refused.stdout,refused.stderr)
    print("VIRTUAL_LOCATION_PASS")


if __name__=="__main__":main()
