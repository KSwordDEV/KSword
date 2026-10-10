"""CM resource layouts, allocated/boot/empty semantics, budgets and handle ownership."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_hardware_usb import SOURCE as USB_SOURCE
ROOT=Path(__file__).resolve().parents[1]
OPEN=r'''
static HDEVINFO WINAPI fixtureOpen(const GUID*,PCWSTR enumerator,HWND,DWORD){
 if(mode==L"denied"||(mode==L"partial"&&enumerator&&wcscmp(enumerator,L"ACPI")==0)){SetLastError(ERROR_ACCESS_DENIED);return INVALID_HANDLE_VALUE;}
 ++opens;const auto value=!enumerator?6:wcscmp(enumerator,L"PCI")==0?1:wcscmp(enumerator,L"ACPI")==0?2:wcscmp(enumerator,L"ROOT")==0?3:wcscmp(enumerator,L"PCIIDE")==0?4:7;
 return reinterpret_cast<HDEVINFO>(static_cast<std::uintptr_t>(value));
}
static BOOL WINAPI fixtureEnum(HDEVINFO set,DWORD ordinal,PSP_DEVINFO_DATA info){
 const auto value=reinterpret_cast<std::uintptr_t>(set);if(mode==L"empty"||value==7||value!=6&&ordinal||value==6&&ordinal>=4){SetLastError(ERROR_NO_MORE_ITEMS);return FALSE;}
 info->DevInst=static_cast<DEVINST>(value==6?ordinal+1:value);return TRUE;
}
'''
EXTRA=r'''
static std::set<LOG_CONF> configs;static std::set<RES_DES> descriptors;static int configsCreated=0,configsClosed=0,descriptorsCreated=0,descriptorsClosed=0;
static BOOL WINAPI busProperty(HDEVINFO set,PSP_DEVINFO_DATA info,const DEVPROPKEY* key,DEVPROPTYPE* type,PBYTE data,DWORD size,PDWORD needed,DWORD flags){
 std::vector<BYTE> bytes;
 if(key->pid==b::kPropEnumeratorName.pid){const wchar_t* name=info->DevInst==1?L"PCI":info->DevInst==2?L"ACPI":info->DevInst==3?L"ROOT":L"PCIIDE";*type=DEVPROP_TYPE_STRING;bytes.resize((wcslen(name)+1)*sizeof(wchar_t));memcpy(bytes.data(),name,bytes.size());}
 else if(key->pid==b::kPropBusTypeGuid.pid){const GUID guid={0xc8ebdfb0,0xb510,0x11d0,{0x80,0xe5,0,0xa0,0xc9,0x25,0x42,0xe3}};*type=DEVPROP_TYPE_GUID;bytes.resize(mode==L"bad-guid"?15:sizeof(guid));memcpy(bytes.data(),&guid,bytes.size());}
 else if(key->pid==b::kPropLegacyBusType.pid||key->pid==b::kPropBusNumber.pid||key->pid==b::kPropUiNumber.pid){*type=DEVPROP_TYPE_UINT32;DWORD value=key->pid==b::kPropLegacyBusType.pid?5:key->pid==b::kPropBusNumber.pid?42:4;bytes.resize(sizeof(value));memcpy(bytes.data(),&value,sizeof(value));}
 else if(key->pid==b::kPropLocationPaths.pid){const wchar_t paths[]=L"PCIROOT(0);literal\0PCI(1300)\0";*type=DEVPROP_TYPE_STRING_LIST;bytes.resize(sizeof(paths));memcpy(bytes.data(),paths,sizeof(paths));}
 else return fixtureProperty(set,info,key,type,data,size,needed,flags);
 if(needed)*needed=static_cast<DWORD>(bytes.size());if(!data||size<bytes.size()){SetLastError(ERROR_INSUFFICIENT_BUFFER);return FALSE;}memcpy(data,bytes.data(),bytes.size());return TRUE;
}
static CONFIGRET WINAPI first(PLOG_CONF conf,DEVINST inst,ULONG flags){
 if(mode==L"no-conf"||mode==L"boot"&&flags==ALLOC_LOG_CONF)return CR_NO_MORE_LOG_CONF;
 if(mode==L"resource-denied")return CR_ACCESS_DENIED;
 *conf=100+inst;assert(configs.insert(*conf).second);++configsCreated;return CR_SUCCESS;
}
static std::size_t ordinal(RES_DES value){return (value-100000)%10000;}
static CONFIGRET WINAPI next(PRES_DES value,RES_DES current,RESOURCEID,PRESOURCEID type,ULONG){
 const bool initial=current<100000;assert(initial?configs.count(current)==1:descriptors.count(current)==1);
 const auto inst=initial?current-100:(current-100000)/10000;const auto index=initial?0:ordinal(current)+1;
 if(mode==L"step-denied"&&index==3)return CR_ACCESS_DENIED;
 if(index>=6&&mode!=L"descriptor-budget")return CR_NO_MORE_RES_DES;
 *value=100000+inst*10000+index;assert(descriptors.insert(*value).second);++descriptorsCreated;
 const RESOURCEID types[]={ResType_Mem,ResType_MemLarge,ResType_IO,ResType_DMA,ResType_IRQ,ResType_BusNumber};
 *type=mode==L"descriptor-budget"?ResType_Mem:mode==L"null-resource"&&index==0?ResType_None:mode==L"unknown"&&index==0?99:types[index];return CR_SUCCESS;
}
static CONFIGRET WINAPI releaseDescriptor(RES_DES value){assert(descriptors.erase(value)==1);++descriptorsClosed;return mode==L"close-fail"?CR_INVALID_RES_DES:CR_SUCCESS;}
static CONFIGRET WINAPI releaseConfig(LOG_CONF value){for(const auto resource:descriptors)assert((resource-100000)/10000!=value-100);assert(configs.erase(value)==1);++configsClosed;return CR_SUCCESS;}
static CONFIGRET WINAPI dataSize(PULONG size,RES_DES value,ULONG){assert(descriptors.count(value));const auto index=mode==L"descriptor-budget"?0:ordinal(value);
 const DWORD sizes[]={sizeof(MEM_DES),sizeof(MEM_LARGE_DES),sizeof(IO_DES),sizeof(DMA_DES),sizeof(IRQ_DES),sizeof(BUSNUMBER_DES)};*size=sizes[index];
 if(!index&&mode==L"size-denied")return CR_ACCESS_DENIED;if(!index&&mode==L"short")*size=1;if(!index&&mode==L"null-resource")*size=0;if(!index&&mode==L"size-budget")*size=0xffffffff;if(!index&&mode==L"unknown")*size=1024;return CR_SUCCESS;}
template<class T>static void fill(void* data,ULONG size,const T& value){memcpy(data,&value,(std::min)(static_cast<std::size_t>(size),sizeof(value)));}
static CONFIGRET WINAPI resourceData(RES_DES value,PVOID data,ULONG size,ULONG){assert(descriptors.count(value));const auto index=mode==L"descriptor-budget"?0:ordinal(value);
 if(!index&&mode==L"data-denied")return CR_ACCESS_DENIED;
 if(!index&&mode==L"unknown"){memset(data,42,size);return CR_SUCCESS;}
 switch(index){case 0:{MEM_DES d{};d.MD_Alloc_Base=0x100000;d.MD_Alloc_End=mode==L"bad-range"?0:0x100fff;fill(data,size,d);break;}
 case 1:{MEM_LARGE_DES d{};d.MLD_Alloc_Base=0x1234567890000000ull;d.MLD_Alloc_End=d.MLD_Alloc_Base+0x1fff;fill(data,size,d);break;}
 case 2:{IO_DES d{};d.IOD_Alloc_Base=0x3f8;d.IOD_Alloc_End=0x3ff;fill(data,size,d);break;}
 case 3:{DMA_DES d{};d.DD_Alloc_Chan=3;fill(data,size,d);break;}
 case 4:{IRQ_DES d{};d.IRQD_Alloc_Num=0xffffffd5;fill(data,size,d);break;}
 case 5:{BUSNUMBER_DES d{};d.BUSD_Alloc_Base=42;d.BUSD_Alloc_End=47;fill(data,size,d);break;}}
 return CR_SUCCESS;
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-bus-') as temp:
        directory=Path(temp);source=USB_SOURCE.replace('registerHardwareUsb','registerHardwareBus')
        start=source.index('static HDEVINFO WINAPI fixtureOpen');end=source.index('static CONFIGRET WINAPI fixtureIdSize',start)
        source=source[:start]+OPEN+source[end:]
        source=source.replace('#define SetupDiGetClassDevsW fixtureOpen',EXTRA+'\n#define SetupDiGetClassDevsW fixtureOpen').replace('#define SetupDiGetDevicePropertyW fixtureProperty','#define SetupDiGetDevicePropertyW busProperty')
        source=source.replace('#include "CPP"', '#include "USBCPP"\n#define CM_Get_First_Log_Conf first\n#define CM_Get_Next_Res_Des next\n#define CM_Get_Res_Des_Data_Size dataSize\n#define CM_Get_Res_Des_Data resourceData\n#define CM_Free_Res_Des_Handle releaseDescriptor\n#define CM_Free_Log_Conf_Handle releaseConfig\n#include "BUSCPP"')
        source=source.replace('assert(opens==closes);return rc;', 'assert(opens==closes&&configsCreated==configsClosed&&descriptorsCreated==descriptorsClosed&&configs.empty()&&descriptors.empty());return rc;')
        for key,path in {'HEADER':'shared/usermode/backend/hardware/BusTopology.h','REGISTRY':'KswordCLI/CommandRegistry.h','USBCPP':'shared/usermode/backend/hardware/UsbTopology.cpp','BUSCPP':'shared/usermode/backend/hardware/BusTopology.cpp'}.items():source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',str(directory/'fixture.cpp'),
                        *[str(ROOT/path) for path in ['KswordCLI/CommandRegistry.cpp','KswordCLI/R3HardwareBus.cpp','shared/usermode/backend/Common.cpp']],
                        '/Fe:'+str(binary),'/link','Advapi32.lib','User32.lib','Setupapi.lib','Cfgmgr32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=()):
            result=subprocess.run([str(binary),mode,'hardware','bus','enum','--json',*extra],capture_output=True,timeout=20)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:1500],result.stderr)
            return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['enumeratedCount']=='4' and len(valid['sources'])==5
        pci=next(d for d in valid['devices'] if d['enumeratorName']=='PCI');assert pci['pciDevice']==19 and pci['pciFunction']==0
        assert pci['properties']['busNumber']['number']=='42' and pci['properties']['locationPaths']['values']==['PCIROOT(0);literal','PCI(1300)']
        resources=pci['resources'];assert resources['complete'] and resources['cleanupComplete'] and resources['descriptorCount']==6
        rows=resources['descriptors'];assert rows[0]['baseAddress']=='0x100000' and rows[0]['endAddressInclusive']=='0x100fff'
        assert rows[1]['baseAddress']=='0x1234567890000000' and rows[2]['endAddressInclusive']=='0x3ff' and rows[3]['allocatedNumber']==3
        assert rows[4]['irqSigned']==-43 and rows[4]['allocatedNumber']==4294967253 and rows[4]['messageSignalledCandidate']
        assert rows[5]['baseAddress']=='0x2a' and rows[5]['endAddressInclusive']=='0x2f'
        assert run('valid',0,['--scope','all'])['sources'][0]['name']=='all'
        assert run('empty',0)['enumeratedCount']=='0'
        assert run('denied',3)['sources'][0]['win32Error']==5
        assert not run('partial',6)['sources'][1]['opened']
        assert run('bad-guid',4)['devices'][0]['properties']['busTypeGuid']['malformed']
        assert run('no-conf',0)['devices'][0]['resources']['noConfiguration']
        assert run('boot',0)['devices'][0]['resources']['source']=='boot'
        null=run('null-resource',0)['devices'][0]['resources']['descriptors'][0];assert null['kind']=='none' and null['dataSize']=='0' and null['interpreted'] and not null['malformed']
        assert not run('resource-denied',6)['devices'][0]['resources']['available']
        assert run('short',4)['devices'][0]['resources']['descriptors'][0]['malformed']
        assert run('bad-range',4)['devices'][0]['resources']['descriptors'][0]['baseAddress'] is None
        assert not run('data-denied',6)['devices'][0]['resources']['descriptors'][0]['dataAvailable']
        assert run('size-denied',6)['devices'][0]['resources']['descriptors'][0]['dataSize'] is None
        assert run('size-budget',6)['devices'][0]['resources']['limited']
        unknown=run('unknown',6)['devices'][0]['resources']['descriptors'][0];assert unknown['kind']=='other' and unknown['rawPreviewTruncated']
        assert not run('close-fail',6)['devices'][0]['resources']['cleanupComplete']
        assert run('step-denied',6)['devices'][0]['resources']['descriptorCount']==3
        budget=run('descriptor-budget',6,['--limit','1'])['devices'][0]['resources'];assert budget['limited'] and budget['descriptorCount']==4096 and budget['terminalConfigRet'] is None
        assert run('valid',6,['--limit','1'])['truncated']
        assert run('valid',0,['--instance-id',r'ROOT\NoSuchFixture'])['matchedCount']=='0'
        print('R3_BUS_FIXTURE_PASS native range/DMA/IRQ/BUS layouts, raw properties, allocated/boot/empty/error states, descriptor budgets and exact resource/config/set ownership')

if __name__=='__main__':main()
