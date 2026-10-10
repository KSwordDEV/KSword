"""Capture ownership, native errors, readback/downgrade and identity loss."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_window import HEADER as WINDOW_HEADER, SOURCE as WINDOW_SOURCE
ROOT=Path(__file__).resolve().parents[1]
EXTRA=r'''
static DWORD policy=0;static int captureSets=0,captureQueries=0;
LONG NTAPI FixtureVersion(OSVERSIONINFOW* v){if(mode==L"version-unknown")return 258;v->dwMajorVersion=10;v->dwBuildNumber=mode==L"old-version"?18363:19042;return 0;}
FARPROC WINAPI FixtureProcedure(HMODULE,LPCSTR name){return strcmp(name,"RtlGetVersion")==0?reinterpret_cast<FARPROC>(FixtureVersion):nullptr;}
HWND WINAPI FixtureAncestor(HWND h,UINT){return mode==L"child"?reinterpret_cast<HWND>(0x4321):h;}
BOOL WINAPI FixtureGetAffinity(HWND,PDWORD value){++captureQueries;if(mode==L"query-fail"||mode==L"after-fail"&&captureSets){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}*value=policy;return TRUE;}
BOOL WINAPI FixtureSetAffinity(HWND,DWORD value){++captureSets;if(mode==L"set-denied"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}if(mode==L"set-unsupported"){SetLastError(ERROR_NOT_SUPPORTED);return FALSE;}if(mode!=L"unchanged")policy=mode==L"downgrade"&&value==0x11?1:value;return TRUE;}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-capture-') as temp:
        directory=Path(temp)
        header=WINDOW_HEADER+r'''
HWND WINAPI FixtureAncestor(HWND,UINT);
BOOL WINAPI FixtureGetAffinity(HWND,PDWORD);
BOOL WINAPI FixtureSetAffinity(HWND,DWORD);
#define GetAncestor FixtureAncestor
#define GetWindowDisplayAffinity FixtureGetAffinity
#define SetWindowDisplayAffinity FixtureSetAffinity
FARPROC WINAPI FixtureProcedure(HMODULE,LPCSTR);
#define GetProcAddress FixtureProcedure
'''
        (directory/'mock.h').write_text(header,encoding='utf-8')
        source=WINDOW_SOURCE.replace('registerWindow()','registerWindowCapture()').replace('info->dwExStyle=0','info->dwExStyle=WS_EX_LAYERED')
        source=source.replace('static std::wstring time(',EXTRA+'\nstatic std::wstring time(')
        source=source.replace('if(mode==L"owner-change")assert(actions==0);return result;', 'if(mode==L"owner-change"||mode==L"child")assert(captureSets==0);return result;')
        (directory/'fixture.cpp').write_text(source.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()),encoding='utf-8');binary=directory/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),
                        *[str(ROOT/path) for path in ['KswordCLI/CommandRegistry.cpp','KswordCLI/R3WindowCapture.cpp','shared/usermode/backend/window/WindowEnumerator.cpp','shared/usermode/backend/window/CaptureProtection.cpp','shared/usermode/backend/window/WindowListCapture.cpp','shared/usermode/backend/window/WindowFormatting.cpp','shared/usermode/backend/window/WindowQueries.cpp','shared/usermode/backend/Common.cpp']],
                        '/Fe:'+str(binary),'/link','Advapi32.lib','User32.lib'],cwd=directory,check=True)
        def run(mode,code,write=False,affinity='monitor'):
            args=[str(binary),mode,'window','capture','set' if write else 'query','--hwnd','0x1234','--json']
            if write:args+=['--pid','self','--tid','self','--creation-time','self','--thread-creation-time','self','--mode',affinity]
            result=subprocess.run(args,capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:1500],result.stderr)
            return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['affinity']['available'] and valid['affinity']['value']=='0x0' and valid['layered']
        unavailable=run('query-fail',5);assert not unavailable['affinity']['available'] and unavailable['affinity']['value'] is None and unavailable['affinity']['win32Error']==87
        assert not run('owner-change',3)['identityMatched']
        for mode in ('none','monitor','exclude'):
            result=run('valid',0,write=True,affinity=mode);assert result['accepted'] and result['verified'] and result['after']['mode']==mode
        assert not run('child',5,write=True)['attempted']
        assert not run('owner-change',3,write=True)['attempted']
        denied=run('set-denied',3,write=True);assert not denied['accepted'] and denied['win32Error']==5
        assert run('set-unsupported',5,write=True)['win32Error']==50
        downgrade=run('downgrade',6,write=True,affinity='exclude');assert downgrade['requestedValue']=='0x11' and downgrade['after']['value']=='0x1' and not downgrade['verified']
        assert not run('after-fail',6,write=True)['after']['available']
        assert not run('unchanged',6,write=True)['verified']
        old=run('old-version',5,write=True,affinity='exclude');assert not old['attempted'] and old['platform']['build']==18363
        unknown=run('version-unknown',5,write=True,affinity='exclude');assert not unknown['attempted'] and not unknown['platform']['available'] and unknown['platform']['ntStatus']=='0x102'
        print('R3_CAPTURE_FIXTURE_PASS typed query/set errors, same-process/top-level guards, matched readback, downgrade, ignored writes and target identity loss')

if __name__=='__main__':main()
