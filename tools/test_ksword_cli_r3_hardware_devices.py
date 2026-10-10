"""SetupAPI property layout/errors, incomplete enumerations, CM errors and ownership."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
#include "HEADER"
#include "REGISTRY"
#include <setupapi.h>
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <cstring>
static std::wstring mode;static int opens=0,closes=0,propertyReads=0;
static HDEVINFO WINAPI open(const GUID*,PCWSTR,HWND,DWORD){if(mode==L"open-denied"){SetLastError(ERROR_ACCESS_DENIED);return INVALID_HANDLE_VALUE;}++opens;return reinterpret_cast<HDEVINFO>(1);}
static BOOL WINAPI release(HDEVINFO){++closes;return TRUE;}
static BOOL WINAPI enumerate(HDEVINFO,DWORD i,PSP_DEVINFO_DATA info){if(!i&&mode!=L"empty"&&mode!=L"enum-denied"){info->DevInst=1;return TRUE;}SetLastError(mode==L"enum-denied"||mode==L"enum-partial"?ERROR_ACCESS_DENIED:ERROR_NO_MORE_ITEMS);return FALSE;}
static BOOL WINAPI device(HDEVINFO,PCWSTR,HWND,DWORD,PSP_DEVINFO_DATA info){if(mode==L"removed"){SetLastError(ERROR_NO_SUCH_DEVINST);return FALSE;}info->DevInst=1;return TRUE;}
static CONFIGRET WINAPI idSize(PULONG length,DEVINST,ULONG){*length=17;return CR_SUCCESS;}
static CONFIGRET WINAPI id(DEVINST, PWSTR value,ULONG size,ULONG){if(mode==L"cm-denied")return CR_ACCESS_DENIED;return wcscpy_s(value,size,L"ROOT\\Fixture\\0000")==0?CR_SUCCESS:CR_BUFFER_SMALL;}
static CONFIGRET WINAPI parent(PDEVINST p,DEVINST,ULONG){*p=2;return CR_SUCCESS;}
static CONFIGRET WINAPI status(PULONG flags,PULONG problem,DEVINST,ULONG){if(mode==L"cm-status")return CR_NO_SUCH_DEVNODE;*flags=DN_STARTED;*problem=0;return CR_SUCCESS;}
static HKEY WINAPI deviceKey(HDEVINFO,PSP_DEVINFO_DATA,DWORD,DWORD,DWORD,REGSAM){SetLastError(ERROR_FILE_NOT_FOUND);return reinterpret_cast<HKEY>(INVALID_HANDLE_VALUE);}
static HKEY WINAPI classKey(const GUID*,REGSAM,DWORD,PCWSTR,PVOID){SetLastError(ERROR_FILE_NOT_FOUND);return reinterpret_cast<HKEY>(INVALID_HANDLE_VALUE);}
static BOOL WINAPI property(HDEVINFO,PSP_DEVINFO_DATA,DWORD prop,PDWORD type,PBYTE bytes,DWORD size,PDWORD needed){
 if(prop!=SPDRP_FRIENDLYNAME && prop!=SPDRP_HARDWAREID){SetLastError(ERROR_INVALID_DATA);return FALSE;}
 if(prop==SPDRP_HARDWAREID&&mode==L"property-denied"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 const wchar_t multi[]=L"one;with;semicolons\0two\0";const wchar_t name[]=L"Fixture";const auto count=prop==SPDRP_HARDWAREID?sizeof(multi):sizeof(name);
 *type=prop==SPDRP_HARDWAREID?REG_MULTI_SZ:REG_SZ;if(needed)*needed=static_cast<DWORD>(count);
 if(!bytes||size<count){SetLastError(ERROR_INSUFFICIENT_BUFFER);return FALSE;}
 ++propertyReads;memcpy(bytes,prop==SPDRP_HARDWAREID?multi:name,count);
 if(mode==L"malformed"&&prop==SPDRP_HARDWAREID){bytes[count-1]=1;bytes[count-2]=1;}
 return TRUE;
}
#define SetupDiGetClassDevsW open
#define SetupDiDestroyDeviceInfoList release
#define SetupDiEnumDeviceInfo enumerate
#define SetupDiOpenDeviceInfoW device
#define SetupDiGetDeviceRegistryPropertyW property
#define SetupDiOpenDevRegKey deviceKey
#define SetupDiOpenClassRegKeyExW classKey
#define CM_Get_Device_ID_Size idSize
#define CM_Get_Device_IDW id
#define CM_Get_Parent parent
#define CM_Get_DevNode_Status status
#include "CPP"
#undef CM_Get_DevNode_Status
#undef CM_Get_Parent
#undef CM_Get_Device_IDW
#undef CM_Get_Device_ID_Size
#undef SetupDiOpenClassRegKeyExW
#undef SetupDiOpenDevRegKey
#undef SetupDiGetDeviceRegistryPropertyW
#undef SetupDiOpenDeviceInfoW
#undef SetupDiEnumDeviceInfo
#undef SetupDiDestroyDeviceInfoList
#undef SetupDiGetClassDevsW
int wmain(int argc,wchar_t* argv[]){
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 ks::r3::hardware::HardwareFieldEvidence evidence;
 assert(ks::r3::hardware::DecodeProperty(REG_SZ,{1,2,3},evidence).empty()&&evidence.malformed);
 evidence={};assert(ks::r3::hardware::DecodeProperty(REG_MULTI_SZ,{0,0},evidence).empty()&&evidence.malformed);
 evidence={};std::vector<BYTE> dword(4);DWORD number=123;memcpy(dword.data(),&number,4);
 ks::r3::hardware::DecodeProperty(REG_DWORD,dword,evidence);assert(evidence.available&&evidence.numeric&&evidence.number==123);
 ks::cli::registerHardwareDevices();const auto rc=ks::cli::dispatchR3(argc,argv).value_or(1);
 assert(opens==closes);return rc;
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-hardware-') as temp:
        directory=Path(temp);source=SOURCE
        for key,path in {'HEADER':'shared/usermode/backend/hardware/HardwareEnumerator.h','REGISTRY':'KswordCLI/CommandRegistry.h',
                         'CPP':'shared/usermode/backend/hardware/HardwareEnumerator.cpp'}.items():source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',
                        str(directory/'fixture.cpp'),*[str(ROOT/path) for path in ['KswordCLI/CommandRegistry.cpp','KswordCLI/R3HardwareDevices.cpp','shared/usermode/backend/hardware/HardwareFormatting.cpp','shared/usermode/backend/Common.cpp']],
                        '/Fe:'+str(binary),'/link','Advapi32.lib','Setupapi.lib','Cfgmgr32.lib','User32.lib'],cwd=directory,check=True)
        def run(mode,code,detail=False):
            args=[str(binary),mode,'hardware','devices','query' if detail else 'enum','--json']
            if detail:args+=['--instance-id',r'ROOT\Fixture\0000']
            result=subprocess.run(args,capture_output=True,timeout=15)
            assert result.returncode==code,(mode,result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)['data']
        valid=run('valid',0)['devices'][0]
        assert valid['properties']['hardwareIds']['values']==['one;with;semicolons','two']
        assert valid['properties']['className']['absent'] and valid['properties']['className']['values'] is None
        assert run('empty',0)['enumeratedCount']=='0'
        assert run('malformed',4)['devices'][0]['properties']['hardwareIds']['malformed']
        assert run('property-denied',6)['devices'][0]['properties']['hardwareIds']['win32Error']==5
        assert run('cm-denied',6)['devices'][0]['instanceId'] is None
        assert run('cm-status',6)['devices'][0]['statusFlags'] is None
        assert run('enum-denied',3)['win32Error']==5
        assert run('open-denied',3)['win32Error']==5
        partial=run('enum-partial',6);assert partial['enumeratedCount']=='1' and not partial['complete']
        assert run('removed',3,detail=True)['device'] is None
        assert run('valid',0,detail=True)['found']
        print('R3_HARDWARE_DEVICES_FIXTURE_PASS raw property arrays/layout, absence/denial, CM errors, partial data and handle ownership')

if __name__=='__main__':main()
