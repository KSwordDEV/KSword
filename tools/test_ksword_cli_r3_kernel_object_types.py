"""Native object-type layout/growth/status faults through the production collector/CLI."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_kernel_namespace import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
QUERY=r'''
LONG NTAPI FixtureObject(HANDLE handle,ULONG cls,PVOID data,ULONG bytes,ULONG* returned){assert(!handle&&cls==3);
 if(mode==L"positive")return 258;if(mode==L"denied")return static_cast<LONG>(0xc0000022UL);if(mode==L"unsupported")return static_cast<LONG>(0xc00000bbUL);
 if(mode==L"budget"){*returned=32u*1024u*1024u;return static_cast<LONG>(0xc0000023UL);}
 if(mode==L"growth"&&bytes<512u*1024u){*returned=512u*1024u;return static_cast<LONG>(0xc0000023UL);}
 const ULONG count=mode==L"empty"?0:mode==L"prefix"?257:2;memcpy(data,&count,4);auto cursor=reinterpret_cast<std::uintptr_t>(data)+8;
 for(ULONG i=0;i<count;++i){auto* value=reinterpret_cast<ks::r3::kernel::KOBJECT_TYPE_INFORMATION*>(cursor);*value={};
  const std::wstring name=i==0?L"Event":L"Thread";const auto length=static_cast<USHORT>(name.size()*2),max=static_cast<USHORT>(length+2);
  auto* text=reinterpret_cast<PWSTR>(cursor+sizeof(*value));memcpy(text,name.c_str(),max);value->TypeName={length,max,text};
  value->TotalNumberOfObjects=MAXDWORD;value->TotalNumberOfHandles=7;value->GenericMapping.GenericRead=0x100001;value->TypeIndex=static_cast<UCHAR>(i+2);value->MaintainHandleCount=TRUE;value->SecurityRequired=TRUE;
  if(mode==L"pointer")value->TypeName.Buffer=reinterpret_cast<PWSTR>(1);if(mode==L"odd")++value->TypeName.Length;if(mode==L"max")value->TypeName.MaximumLength=1;if(mode==L"flag")value->SecurityRequired=2;
  cursor=(cursor+sizeof(*value)+max+7)&~std::uintptr_t(7);
 }
 *returned=static_cast<ULONG>(cursor-reinterpret_cast<std::uintptr_t>(data));if(mode==L"short")*returned=4;if(mode==L"huge")*returned=bytes+1;return 0;
}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-object-types-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        source=SOURCE.replace('registerKernelNamespace()','registerKernelObjectTypes()').replace('LONG NTAPI FixtureObject(','LONG NTAPI FixtureBasic(').replace('FARPROC WINAPI FixtureProcedure(',QUERY+'\nFARPROC WINAPI FixtureProcedure(')
        source=source.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('BACKEND',(ROOT/'shared/usermode/backend/kernel/ObjectTypes.h').as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3KernelObjectTypes.cpp','shared/usermode/backend/kernel/ObjectNamespace.cpp','shared/usermode/backend/kernel/ObjectTypes.cpp','shared/usermode/backend/kernel/KernelTypes.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=()):
            result=subprocess.run([str(binary),mode,'kernel','object-types','enum','--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2000],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['complete'] and valid['reportedCount']=='2' and valid['types'][0]['objects']=='4294967295' and valid['types'][0]['genericRead']=='0x100001'
        assert run('empty',0)['complete']
        assert run('growth',0)['bufferBytes']=='589824'
        assert run('prefix',6)['parsedCount']=='256'
        assert run('budget',6)['limited']
        for mode in ('positive','denied'):run(mode,3)
        for mode in ('api-missing','unsupported'):run(mode,5)
        for mode in ('short','huge','pointer','odd','max','flag'):assert run(mode,4)['malformed']
        assert run('valid',6,('--limit','1'))['truncated']
        assert run('valid',0,('--filter','impossible'))['returnedCount']=='0'
        run('owned-library',0)
        print('R3_OBJECT_TYPES_FIXTURE_PASS actual lengths/counts/native string bounds, strict status, growth/prefix/output limits and owned DLL lifecycle')
if __name__=='__main__':main()
