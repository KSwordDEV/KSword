"""Independent SDK CTL_CODE reconstruction and decoder input boundary checks."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
#include <Windows.h>
#include <winioctl.h>
#include "BACKEND"
#include <cassert>
#include <cstdint>
#include <string>
int main(){using namespace ks::r3::system_tools;
 for(const auto device:{0u,1u,0x22u,0x7fffu,0x8000u,0xffffu})for(const auto function:{0u,1u,0x7ffu,0x800u,0xfffu})for(DWORD access=0;access<4;++access)for(DWORD method=0;method<4;++method){
  const DWORD code=CTL_CODE(device,function,method,access);const auto parsed=DecodeIoctlCode(FormatIoctlCode(code));assert(parsed.state==IoctlDecodeState::Valid&&parsed.code==code&&parsed.deviceType==device&&parsed.function==function&&parsed.access==access&&parsed.method==method);
  assert(parsed.common==(device>=0x8000)&&parsed.custom==(function>=0x800));assert(CTL_CODE(parsed.deviceType,parsed.function,parsed.method,parsed.access)==code);
 }
 assert(DecodeIoctlCode(L"").state==IoctlDecodeState::Empty);assert(DecodeIoctlCode(L" \t ").state==IoctlDecodeState::Empty);
 for(const auto* invalid:{L"0x",L"-1",L"100000000",L"0xfffffffff",L"12 34",L"g123"})assert(DecodeIoctlCode(invalid).state==IoctlDecodeState::Invalid);
 assert(DecodeIoctlCode(L" 0Xffffffff ").code==0xffffffff);assert(DecodeIoctlCode(L"0").state==IoctlDecodeState::Valid);
 for(int i=0;i<4;++i){assert(IoctlAccessName(static_cast<std::uint8_t>(i)));assert(IoctlMethodName(static_cast<std::uint8_t>(i)));}
}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-ioctl-') as temp:
        directory=Path(temp);(directory/'fixture.cpp').write_text(SOURCE.replace('BACKEND',(ROOT/'shared/usermode/backend/system/IoctlDecoder.h').as_posix()),encoding='utf-8');binary=directory/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2',str(directory/'fixture.cpp'),str(ROOT/'shared/usermode/backend/system/IoctlDecoder.cpp'),'/Fe:'+str(binary)],cwd=directory,check=True)
        subprocess.run([str(binary)],check=True,timeout=10)
        print('R3_IOCTL_FIXTURE_PASS independent SDK CTL_CODE reconstruction, common/custom boundaries and decoder malformed/empty/uint32 inputs; no native device operations')
if __name__=='__main__':main()
