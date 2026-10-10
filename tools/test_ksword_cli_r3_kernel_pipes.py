"""Actual IO byte lengths, linked pipe records, strict statuses and probe ownership."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_kernel_namespace import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
QUERY=r'''
static int page=0;
LONG NTAPI FixtureOpenFile(PHANDLE handle,ACCESS_MASK access,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io,ULONG share,ULONG options){
 assert(share==(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE)&&access==(SYNCHRONIZE|((options&FILE_DIRECTORY_FILE)?FILE_LIST_DIRECTORY:FILE_READ_ATTRIBUTES)));*handle=nullptr;*io={};page=0;
 if(mode==L"open-denied")return static_cast<LONG>(0xc0000022UL);if(mode==L"open-unsupported")return static_cast<LONG>(0xc00000bbUL);if(mode==L"open-positive")return 259;if(mode==L"open-null")return 0;
 if((options&FILE_DIRECTORY_FILE)&&objectName(attributes).back()!=L'\\')return static_cast<LONG>(0xc000000dUL);
 *handle=h(1);assert(live.insert(*handle).second);if(mode==L"open-io-denied")io->Status=static_cast<LONG>(0xc0000022UL);return 0;
}
LONG NTAPI FixtureQueryFile(HANDLE handle,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK io,PVOID data,ULONG bytes,ULONG cls,BOOLEAN single,PUNICODE_STRING,BOOLEAN restart){
 assert(handle==h(1)&&live.count(handle)&&cls==1&&!single&&(page!=0||restart));*io={};
 if(mode==L"query-positive")return 259;if(mode==L"query-denied")return static_cast<LONG>(0xc0000022UL);
 if(mode==L"query-budget")return static_cast<LONG>(0x80000005UL);
 if(mode==L"empty"||page++>0&&mode!=L"cycle"){io->Status=static_cast<LONG>(0x80000006UL);return static_cast<LONG>(0x80000006UL);}
 constexpr auto header=offsetof(ks::r3::kernel::KFILE_DIRECTORY_INFORMATION,FileName);std::size_t offset=0;
 for(int i=0;i<2;++i){const std::wstring name=i?L"SecondPipe":L"FirstPipe";const auto length=static_cast<ULONG>(name.size()*2);const auto next=(header+length+7)&~std::size_t(7);
  assert(offset+header+length<bytes);auto* info=reinterpret_cast<ks::r3::kernel::KFILE_DIRECTORY_INFORMATION*>(static_cast<BYTE*>(data)+offset);*info={};info->FileNameLength=length;info->FileAttributes=0x20;info->EndOfFile.QuadPart=9223372036854775807LL;info->CreationTime.QuadPart=9007199254740993LL;memcpy(info->FileName,name.data(),length);info->NextEntryOffset=i?0:static_cast<ULONG>(next);
  if(mode==L"odd")++info->FileNameLength;if(mode==L"huge-name")info->FileNameLength=bytes;if(mode==L"small-next")info->NextEntryOffset=8;if(mode==L"large-next")info->NextEntryOffset=bytes;
  offset+=i?header+length:next;
 }
 io->Information=offset;if(mode==L"short")io->Information=1;if(mode==L"huge")io->Information=bytes+1;if(mode==L"query-io-denied")io->Status=static_cast<LONG>(0xc0000022UL);
 if(mode==L"cancel"){assert(control);control(CTRL_BREAK_EVENT);}return 0;
}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-pipes-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        source=SOURCE.replace('registerKernelNamespace()','registerKernelPipes()').replace('FARPROC WINAPI FixtureProcedure(',QUERY+'\nFARPROC WINAPI FixtureProcedure(')
        source=source.replace('if(mode==L"api-missing")return nullptr;','if(mode==L"api-missing")return nullptr;\n if(strcmp(name,"NtOpenFile")==0)return reinterpret_cast<FARPROC>(FixtureOpenFile);\n if(strcmp(name,"NtQueryDirectoryFile")==0)return reinterpret_cast<FARPROC>(FixtureQueryFile);')
        source=source.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('BACKEND',(ROOT/'shared/usermode/backend/kernel/NamedPipes.h').as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3KernelPipes.cpp','shared/usermode/backend/kernel/ObjectNamespace.cpp','shared/usermode/backend/kernel/NamedPipes.cpp','shared/usermode/backend/kernel/ObjectTypes.cpp','shared/usermode/backend/kernel/KernelTypes.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=(),probe=False):
            args=['probe','--path',r'\Device\NamedPipe\FirstPipe','--confirm'] if probe else ['enum','--directory','device']
            result=subprocess.run([str(binary),mode,'kernel','pipes',*args,'--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2000],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['enumeratedCount']=='2' and valid['sources'][0]['complete'] and valid['sources'][0]['closed']
        assert valid['pipes'][0]['sizeBytes']=='9223372036854775807' and valid['pipes'][0]['creationTime']=='9007199254740993'
        assert run('empty',0)['returnedCount']=='0'
        for mode in ('open-positive','open-denied','query-positive','query-denied','open-io-denied','query-io-denied'):run(mode,3)
        for mode in ('api-missing','open-unsupported'):run(mode,5)
        for mode in ('open-null','short','huge','odd','huge-name','small-next','large-next'):assert run(mode,4)['malformed']
        assert run('query-budget',6)['limited']
        assert run('cycle',6)['sources'][0]['cycle']
        assert run('cancel',6)['sources'][0]['cancelled']
        assert run('close-denied',6)['sources'][0]['closed'] is False
        assert run('valid',6,('--max-entries','1'))['enumeratedCount']=='1'
        assert run('valid',6,('--limit','1'))['truncated']
        assert run('valid',0,('--filter','missing'))['returnedCount']=='0'
        assert run('valid',0,probe=True)['basic']['available']
        for mode in ('open-positive','open-denied'):run(mode,3,probe=True)
        for mode in ('api-missing','open-unsupported'):run(mode,5,probe=True)
        for mode in ('open-null','short-basic'):run(mode,4,probe=True)
        for mode in ('open-io-denied','basic-positive','basic-api-missing','close-denied'):run(mode,6,probe=True)
        print('R3_PIPE_FIXTURE_PASS IO lengths/statuses, record/name chain bounds, raw 64-bit fields, empty/budgets/cycles/cancel and attribute-probe query/closure')
if __name__=='__main__':main()
