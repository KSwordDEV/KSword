"""PDH API/data status, arrays, partial fallback, cancellation and owning thread."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
#include "HEADER"
#include "REGISTRY"
#include <pdh.h>
#include <pdhmsg.h>
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <map>
#include <limits>
#include <atomic>
#include <thread>
static std::wstring mode;static std::map<PDH_HCOUNTER,std::wstring> paths;
static DWORD owner=0;static int opens=0,closes=0,collections=0;
static std::atomic_bool collected{false};
static PDH_STATUS WINAPI fixtureOpenQuery(LPCWSTR,DWORD_PTR,PDH_HQUERY* query){owner=GetCurrentThreadId();if(mode==L"open-denied")return PDH_ACCESS_DENIED;++opens;*query=reinterpret_cast<PDH_HQUERY>(1);return 0;}
static PDH_STATUS WINAPI close(PDH_HQUERY){assert(owner==GetCurrentThreadId());++closes;return mode==L"close-fail"?PDH_INVALID_HANDLE:0;}
static PDH_STATUS WINAPI add(PDH_HQUERY,LPCWSTR path,DWORD_PTR,PDH_HCOUNTER* counter){assert(owner==GetCurrentThreadId());if(mode==L"missing-gpu"&&std::wstring(path).find(L"GPU")!=std::wstring::npos)return PDH_CSTATUS_NO_OBJECT;
 *counter=reinterpret_cast<PDH_HCOUNTER>(paths.size()+2);paths[*counter]=path;return 0;}
static PDH_STATUS WINAPI collect(PDH_HQUERY){assert(owner==GetCurrentThreadId());++collections;if(collections>1)collected=true;return mode==L"collect-fail"&&collections>1?PDH_INVALID_DATA:mode==L"baseline-fail"&&collections==1?PDH_INVALID_DATA:0;}
static PDH_STATUS WINAPI scalar(PDH_HCOUNTER,DWORD,LPDWORD,PPDH_FMT_COUNTERVALUE value){assert(owner==GetCurrentThreadId());value->CStatus=mode==L"invalid-data"?PDH_CSTATUS_INVALID_DATA:PDH_CSTATUS_NEW_DATA;value->doubleValue=mode==L"nan"?std::numeric_limits<double>::quiet_NaN():17.0;return 0;}
static PDH_STATUS WINAPI array(PDH_HCOUNTER counter,DWORD,LPDWORD size,LPDWORD count,PPDH_FMT_COUNTERVALUE_ITEM_W items){assert(owner==GetCurrentThreadId());
 const DWORD needed=sizeof(PDH_FMT_COUNTERVALUE_ITEM_W)+3*sizeof(wchar_t);*count=1;
 if(mode==L"array-empty"){*count=0;*size=0;return 0;}
 if(paths[counter].find(L"Bytes Sent")!=std::wstring::npos&&mode==L"network-fail")return PDH_INVALID_DATA;
 if(!items||*size<needed){*size=needed;return PDH_MORE_DATA;}*size=needed;
 if(mode==L"bad-count"){*count=0xffffffff;return 0;}
 auto* name=reinterpret_cast<wchar_t*>(items+1);name[0]=L'0';name[1]=0;name[2]=0;items[0].szName=mode==L"bad-pointer"?reinterpret_cast<wchar_t*>(1):name;
 items[0].FmtValue.CStatus=PDH_CSTATUS_NEW_DATA;items[0].FmtValue.doubleValue=19;return 0;
}
#define PdhOpenQueryW fixtureOpenQuery
#define PdhCloseQuery close
#define PdhAddEnglishCounterW add
#define PdhAddCounterW add
#define PdhCollectQueryData collect
#define PdhGetFormattedCounterValue scalar
#define PdhGetFormattedCounterArrayW array
#include "CPP"
#undef PdhGetFormattedCounterArrayW
#undef PdhGetFormattedCounterValue
#undef PdhCollectQueryData
#undef PdhAddCounterW
#undef PdhAddEnglishCounterW
#undef PdhCloseQuery
#undef PdhOpenQueryW
int wmain(int argc,wchar_t* argv[]){
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 std::thread cancellation;if(mode==L"cancel")cancellation=std::thread([]{while(!collected)Sleep(5);Sleep(100);assert(GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT,0));});
 ks::cli::registerHardwarePerformance();const auto rc=ks::cli::dispatchR3(argc,argv).value_or(1);
 if(cancellation.joinable())cancellation.join();
 assert(opens==closes);return rc;
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-performance-') as temp:
        directory=Path(temp);source=SOURCE
        for key,path in {'HEADER':'shared/usermode/backend/hardware/PerformanceSampler.h','REGISTRY':'KswordCLI/CommandRegistry.h',
                         'CPP':'shared/usermode/backend/hardware/SystemPerformanceSampler.cpp'}.items():source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',
                        str(directory/'fixture.cpp'),*[str(ROOT/path) for path in ['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3HardwarePerformance.cpp','shared/usermode/backend/hardware/DiskActivitySampler.cpp','shared/usermode/backend/hardware/HardwareStatsFormatting.cpp']],
                        '/Fe:'+str(binary),'/link','Advapi32.lib','Pdh.lib','User32.lib'],cwd=directory,check=True)
        def run(mode,code,group='all'):
            result=subprocess.run([str(binary),mode,'hardware','performance','sample','--group',group,'--json'],capture_output=True,timeout=15)
            assert result.returncode==code,(mode,result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)['data']
        valid=run('valid',0);metrics=valid['samples'][0]['metrics']
        assert next(m for m in metrics if m['id']=='cpu-total')['value']==17
        assert next(m for m in metrics if m['id']=='cpu-total')['evidence']['cStatus']=='0x1'
        assert next(m for m in metrics if m['id']=='gpu-max-engine')['value']==19
        assert next(m for m in metrics if m['id']=='memory-available')['unit']=='mebibytes'
        assert next(m for m in metrics if m['id']=='physical-memory-total')['value'].isdigit()
        invalid=run('invalid-data',6);assert next(m for m in invalid['samples'][0]['metrics'] if m['id']=='cpu-total')['value'] is None
        assert run('nan',4)['samples'][0]['metrics'][5]['evidence']['malformed']
        assert any(s['evidence']['malformed'] for s in run('bad-count',4)['samples'][0]['sources'])
        assert any(s['evidence']['malformed'] for s in run('bad-pointer',4)['samples'][0]['sources'])
        assert run('missing-gpu',5,group='gpu')['samples'][0]['metrics'][0]['value'] is None
        assert run('array-empty',5,group='gpu')['samples'][0]['metrics'][0]['evidence']['empty']
        network=run('network-fail',6,group='network')['samples'][0]['metrics']
        assert next(m for m in network if m['id']=='network-sent-total')['value'] is None
        assert next(m for m in network if m['id']=='network-adapter')['sentBytesPerSecond'] is None
        failed=run('open-denied',6);assert not failed['samples'][0]['queryOpened'] and len(failed['samples'][0]['metrics'])==5
        assert run('collect-fail',6)['samples'][0]['collectStatus']=='0xc0000bc6'
        assert run('baseline-fail',6)['samples'][0]['baselineStatus']=='0xc0000bc6'
        cleanup=run('close-fail',6);assert not cleanup['queryClosed'] and cleanup['closeEvidence']['status']=='0xc0000bbc'
        startup=subprocess.STARTUPINFO();startup.dwFlags=subprocess.STARTF_USESHOWWINDOW;startup.wShowWindow=subprocess.SW_HIDE
        process=subprocess.run([str(binary),'cancel','hardware','performance','sample','--samples','30','--interval-ms','250','--json'],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NEW_CONSOLE,startupinfo=startup)
        assert process.returncode==6,(process.returncode,process.stdout,process.stderr)
        cancelled=json.loads(process.stdout)['data'];assert cancelled['cancelled'] and cancelled['queryClosed'] and cancelled['returnedSamples']<30
        print('R3_PERFORMANCE_FIXTURE_PASS PDH new/invalid data, finite/layout checks, missing GPU/network, partial Win32 fallback, cancellation and ownership')

if __name__=='__main__':main()
