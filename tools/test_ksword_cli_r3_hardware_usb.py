"""USB source errors, topology, native properties and SetupAPI set ownership."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
#include <Windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <cstring>
static int opens=0,closes=0;
static BOOL WINAPI fixtureDestroy(HDEVINFO){++closes;return TRUE;}
#define SetupDiDestroyDeviceInfoList fixtureDestroy
#include "HEADER"
#undef SetupDiDestroyDeviceInfoList
#include "REGISTRY"
namespace b=ks::r3::hardware_stats;
static std::wstring mode;
static const wchar_t* ids[]={L"HTREE\\ROOT\\0",L"PCI\\VEN_1234&DEV_5678\\3&CONTROLLER",L"USB\\ROOT_HUB30\\4&HUB",L"USB\\VID_046D&PID_C52B&REV_0001\\SERIAL123",L"USBSTOR\\DISK&VEN_FIXTURE\\5&DISK"};
static HDEVINFO WINAPI fixtureOpen(const GUID* guid,PCWSTR enumerator,HWND,DWORD){
 if(mode==L"denied"||(mode==L"partial"&&enumerator&&wcscmp(enumerator,L"USBSTOR")==0)||(mode==L"classification"&&guid&&IsEqualGUID(*guid,b::kUsbHubInterface))){SetLastError(ERROR_ACCESS_DENIED);return INVALID_HANDLE_VALUE;}
 ++opens;int value=guid?(IsEqualGUID(*guid,b::kUsbHostControllerInterface)?1:IsEqualGUID(*guid,b::kUsbHubInterface)?2:3):wcscmp(enumerator,L"USB")==0?4:5;
 return reinterpret_cast<HDEVINFO>(static_cast<std::uintptr_t>(value));
}
static BOOL WINAPI fixtureEnum(HDEVINFO set,DWORD ordinal,PSP_DEVINFO_DATA info){
 const auto value=reinterpret_cast<std::uintptr_t>(set);
 if(mode==L"empty" || ordinal>0 && value!=4 || value==4&&ordinal>1){SetLastError(ERROR_NO_MORE_ITEMS);return FALSE;}
 info->DevInst=static_cast<DEVINST>(value==4?ordinal+2:value==5?4:value);return TRUE;
}
static CONFIGRET WINAPI fixtureIdSize(PULONG size,DEVINST inst,ULONG){*size=static_cast<ULONG>(wcslen(ids[inst]));return CR_SUCCESS;}
static CONFIGRET WINAPI fixtureId(DEVINST inst,PWSTR value,ULONG size,ULONG){if(mode==L"removed"&&inst==3)return CR_NO_SUCH_DEVNODE;return wcscpy_s(value,size,ids[inst])==0?CR_SUCCESS:CR_BUFFER_SMALL;}
static CONFIGRET WINAPI fixtureParent(PDEVINST parent,DEVINST inst,ULONG){*parent=inst-1;return CR_SUCCESS;}
static CONFIGRET WINAPI fixtureStatus(PULONG flags,PULONG problem,DEVINST,ULONG){*flags=DN_STARTED;*problem=0;return mode==L"cm-denied"?CR_ACCESS_DENIED:CR_SUCCESS;}
static BOOL WINAPI fixtureProperty(HDEVINFO,PSP_DEVINFO_DATA info,const DEVPROPKEY* key,DEVPROPTYPE* type,PBYTE data,DWORD size,PDWORD needed,DWORD){
 std::vector<BYTE> bytes;
 if(key->pid==b::kPropFriendlyName.pid){const wchar_t value[]=L"Fixture";*type=DEVPROP_TYPE_STRING;bytes.resize(sizeof(value));memcpy(bytes.data(),value,sizeof(value));}
 else if(key->pid==b::kPropHardwareIds.pid){*type=DEVPROP_TYPE_STRING_LIST;const auto length=wcslen(ids[info->DevInst]);bytes.resize((length+2)*sizeof(wchar_t));memcpy(bytes.data(),ids[info->DevInst],(length+1)*sizeof(wchar_t));if(mode==L"malformed"&&info->DevInst==3)bytes.back()=1;}
 else if(key->pid==b::kPropAddress.pid){*type=DEVPROP_TYPE_UINT32;DWORD value=info->DevInst==1?0x130000:1;bytes.resize(sizeof(value));memcpy(bytes.data(),&value,sizeof(value));}
 else {SetLastError(mode==L"property-denied"&&key->pid==b::kPropLocationInfo.pid?ERROR_ACCESS_DENIED:ERROR_NOT_FOUND);return FALSE;}
 if(mode==L"property-budget"&&key->pid==b::kPropHardwareIds.pid){if(needed)*needed=0xffffffff;SetLastError(ERROR_INSUFFICIENT_BUFFER);return FALSE;}
 if(needed)*needed=static_cast<DWORD>(bytes.size());if(!data||size<bytes.size()){SetLastError(ERROR_INSUFFICIENT_BUFFER);return FALSE;}
 memcpy(data,bytes.data(),bytes.size());return TRUE;
}
#define SetupDiGetClassDevsW fixtureOpen
#define SetupDiEnumDeviceInfo fixtureEnum
#define SetupDiGetDevicePropertyW fixtureProperty
#define CM_Get_Device_ID_Size fixtureIdSize
#define CM_Get_Device_IDW fixtureId
#define CM_Get_Parent fixtureParent
#define CM_Get_DevNode_Status fixtureStatus
#include "CPP"
#undef CM_Get_DevNode_Status
#undef CM_Get_Parent
#undef CM_Get_Device_IDW
#undef CM_Get_Device_ID_Size
#undef SetupDiGetDevicePropertyW
#undef SetupDiEnumDeviceInfo
#undef SetupDiGetClassDevsW
int wmain(int argc,wchar_t* argv[]){
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 ks::cli::registerHardwareUsb();const auto rc=ks::cli::dispatchR3(argc,argv).value_or(1);assert(opens==closes);return rc;
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-usb-') as temp:
        directory=Path(temp);source=SOURCE
        for key,path in {'HEADER':'shared/usermode/backend/hardware/UsbTopology.h','REGISTRY':'KswordCLI/CommandRegistry.h','CPP':'shared/usermode/backend/hardware/UsbTopology.cpp'}.items():source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',str(directory/'fixture.cpp'),
                        *[str(ROOT/path) for path in ['KswordCLI/CommandRegistry.cpp','KswordCLI/R3HardwareUsb.cpp','shared/usermode/backend/Common.cpp']],
                        '/Fe:'+str(binary),'/link','Advapi32.lib','User32.lib','Setupapi.lib','Cfgmgr32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=()):
            result=subprocess.run([str(binary),mode,'hardware','usb','enum','--json',*extra],capture_output=True,timeout=15)
            assert result.returncode==code,(mode,result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['enumeratedCount']=='4' and len(valid['sources'])==6
        controller=next(n for n in valid['nodes'] if n['kind']=='controller');assert controller['address']=='0x130000' and controller['hubPortCandidate'] is None
        device=next(n for n in valid['nodes'] if n['instanceSerialCandidate']=='SERIAL123');assert device['vendorId']=='046D' and device['productId']=='C52B' and device['revision']=='0001'
        assert device['depth']==2 and valid['nodes'][device['parentIndex']]['kind']=='hub'
        assert run('empty',0)['enumeratedCount']=='0'
        assert run('denied',3)['sources'][0]['win32Error']==5
        partial=run('partial',6);assert partial['enumeratedCount']=='3' and not partial['sources'][4]['opened']
        classification=run('classification',6);assert not classification['roleClassificationComplete'] and all(n['kind'] is None for n in classification['nodes'])
        assert run('malformed',4)['nodes'][2]['properties']['hardwareIds']['malformed']
        assert run('property-denied',6)['nodes'][0]['properties']['locationInfo']['win32Error']==5
        assert run('property-budget',6)['nodes'][0]['properties']['hardwareIds']['win32Error']==234
        assert run('cm-denied',6)['nodes'][0]['statusFlags'] is None
        assert run('removed',6)['sources'][3]['skippedCount']==1
        assert run('valid',6,['--limit','1'])['truncated']
        assert run('valid',0,['--kind','hub'])['returnedCount']==1
        assert run('valid',0,['--instance-id',r'USB\NoSuchFixture'])['matchedCount']=='0'
        print('R3_USB_FIXTURE_PASS dedup/tree/roles, PCI-address semantics, ID candidates, empty/source/CM/property failures, malformed/budget data, truncation and set ownership')

if __name__=='__main__':main()
