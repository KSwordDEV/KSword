"""Owner/opener identities and same-thread guarded clear without content materialization."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_clipboard import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-clipboard-control-') as temp:
        directory=Path(temp);header=HEADER+r'''
BOOL WINAPI FixtureEmpty();BOOL WINAPI FixtureWindow(HWND);
#define EmptyClipboard FixtureEmpty
#define IsWindow FixtureWindow
''';(directory/'mock.h').write_text(header,encoding='utf-8')
        source=SOURCE.replace('registerClipboardRead()','registerClipboardControl()').replace('static bool opened=false;','static int empties=0,ownerQueries=0;static bool opened=false;')
        source=source.replace('int WINAPI FixtureCount(){return static_cast<int>(formats.size());}',r'''int WINAPI FixtureCount(){if(mode==L"malformed-count")return -1;if(mode==L"before-count-error"&&!empties||mode==L"after-count-error"&&empties){SetLastError(5);return 0;}return static_cast<int>(formats.size());}''')
        source=source.replace('return mode==L"changed"&&sequenceCalls>2?8:7;', 'return mode==L"sequence-zero"?0:empties?8:7;')
        source=source.replace('HWND WINAPI FixtureOwner(){return reinterpret_cast<HWND>(0x1234);}',r'''HWND WINAPI FixtureOwner(){++ownerQueries;if(mode==L"owner-missing")return nullptr;if(mode==L"owner-query-fail"){SetLastError(5);return nullptr;}return reinterpret_cast<HWND>(mode==L"owner-race"&&ownerQueries>1?0x4321:0x1234);}''')
        source=source.replace('HWND WINAPI FixtureHolder(){return nullptr;}',r'''HWND WINAPI FixtureHolder(){return mode==L"opener-present"?reinterpret_cast<HWND>(0x4321):nullptr;}''')
        source=source.replace('if(pid)*pid=GetCurrentProcessId();return GetCurrentThreadId();',r'''if(mode==L"owner-lookup-fail"){if(pid)*pid=0;SetLastError(5);return 0;}if(pid)*pid=GetCurrentProcessId();return GetCurrentThreadId();''')
        source=source.replace('int wmain(',r'''BOOL WINAPI FixtureWindow(HWND){return mode==L"owner-dead-window"?FALSE:TRUE;}
BOOL WINAPI FixtureEmpty(){assert(opened&&ownerThread==GetCurrentThreadId());++empties;if(mode==L"empty-denied"){SetLastError(5);return FALSE;}if(mode==L"empty-unsupported"){SetLastError(50);return FALSE;}if(mode!=L"empty-ignored")formats.clear();return TRUE;}
int wmain(''')
        source=source.replace('else assert(opens==1&&closes==1);','else if(mode.rfind(L"owner-",0)==0||mode.rfind(L"opener-",0)==0)assert(opens==0&&closes==0);else assert(opens==1&&closes==1);')
        source=source.replace('assert(locks==unlocks);','assert(reads==0&&locks==0&&unlocks==0);if(mode==L"sequence-mismatch")assert(empties==0&&formats.size()==2);assert(locks==unlocks);')
        (directory/'fixture.cpp').write_text(source.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()),encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3ClipboardControl.cpp','shared/usermode/backend/window/ClipboardControl.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','User32.lib'],cwd=directory,check=True)
        def run(mode,code,query=None,extra=()):
            args=[query,'query'] if query else ['clear','--confirm']
            result=subprocess.run([str(binary),mode,'clipboard',*args,'--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2000],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['verified'] and valid['requestSucceeded'] and valid['beforeFormatCount']=='2' and valid['afterFormatCount']=='0' and valid['closed']
        assert run('empty',0)['beforeFormatCount']=='0'
        mismatch=run('sequence-mismatch',3,extra=('--expect-sequence','9'));assert not mismatch['attempted'] and not mismatch['sequenceMatched'] and mismatch['closed']
        assert run('blocked',3)['opened'] is False
        run('empty-denied',3);run('empty-unsupported',5)
        for mode in ('empty-ignored','before-count-error','after-count-error','sequence-zero','close-fail'):run(mode,6)
        assert run('malformed-count',4)['malformed']
        assert run('owner-present',0,'owner')['identityKnown']
        absent=run('owner-missing',0,'owner');assert not absent['windowPresent'] and absent['pid'] is None
        for mode in ('owner-race','owner-query-fail','owner-lookup-fail','owner-dead-window'):run(mode,6,'owner')
        assert run('opener-present',0,'opener')['windowPresent']
        assert run('opener-null',0,'opener')['pid'] is None
        print('R3_CLIPBOARD_CONTROL_FIXTURE_PASS no content access, double-sampled window identity/races/NULL ambiguity, sequence guard prevents writes, actual empty/count/close failures and same-thread owned cleanup')
if __name__=='__main__':main()
