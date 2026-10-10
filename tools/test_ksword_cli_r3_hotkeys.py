"""Hotkey resource syntax, source failures, budgets and COM/module ownership."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
#include "HOTKEYHEADER"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
namespace b=ks::r3::process_detail::hotkeys;
static std::wstring mode;
static int loads=0,frees=0;
static b::AcceleratorResourceEntry entry{0x80,static_cast<WORD>('j'),1002,0};
static const HWND window=reinterpret_cast<HWND>(0x1234);
static HMODULE WINAPI load(LPCWSTR path,HANDLE file,DWORD flags){++loads;return LoadLibraryExW(path,file,flags);}
static BOOL WINAPI release(HMODULE m){++frees;return FreeLibrary(m);}
static HRSRC WINAPI find(HMODULE,LPCWSTR,LPCWSTR){return reinterpret_cast<HRSRC>(1);}
static HGLOBAL WINAPI resource(HMODULE,HRSRC){return reinterpret_cast<HGLOBAL>(1);}
static DWORD WINAPI resourceSize(HMODULE,HRSRC){return mode==L"malformed"?9:sizeof(entry);}
static LPVOID WINAPI resourceData(HGLOBAL){return &entry;}
static BOOL WINAPI enumerate(HMODULE m,LPCWSTR type,ENUMRESNAMEPROCW callback,LONG_PTR data){
 if(mode==L"absent"){SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);return FALSE;}
 if(mode==L"budget"){auto* c=reinterpret_cast<b::AcceleratorContext*>(data);c->report->deadline=std::chrono::steady_clock::now()-std::chrono::seconds(1);}
 return callback(m,type,MAKEINTRESOURCEW(101),data);
}
static BOOL WINAPI windows(WNDENUMPROC callback,LPARAM data){return mode==L"window-timeout"?callback(window,data):TRUE;}
static BOOL WINAPI threadWindows(DWORD,WNDENUMPROC,LPARAM){return TRUE;}
static DWORD WINAPI owner(HWND h,LPDWORD pid){if(h==window){if(pid)*pid=GetCurrentProcessId();return GetCurrentThreadId();}return GetWindowThreadProcessId(h,pid);}
static LRESULT WINAPI message(HWND,UINT,WPARAM,LPARAM,UINT,UINT,PDWORD_PTR){SetLastError(ERROR_TIMEOUT);return 0;}
static HMENU WINAPI menu(HWND){return nullptr;}
static HRESULT WINAPI folder(HWND,int,HANDLE,DWORD,LPWSTR path){wchar_t module[32768]{};GetModuleFileNameW(nullptr,module,32768);std::wstring directory(module);directory.resize(directory.find_last_of(L"\\/"));
 return wcscpy_s(path,MAX_PATH,directory.c_str())==0?S_OK:E_FAIL;}
#define LoadLibraryExW load
#define FreeLibrary release
#define FindResourceW find
#define LoadResource resource
#define SizeofResource resourceSize
#define LockResource resourceData
#define EnumResourceNamesW enumerate
#define EnumWindows windows
#define EnumThreadWindows threadWindows
#define GetWindowThreadProcessId owner
#define SendMessageTimeoutW message
#define GetMenu menu
#define SHGetFolderPathW folder
#include "HOTKEYCPP"
#undef SHGetFolderPathW
#undef GetMenu
#undef SendMessageTimeoutW
#undef GetWindowThreadProcessId
#undef EnumThreadWindows
#undef EnumWindows
#undef EnumResourceNamesW
#undef LockResource
#undef SizeofResource
#undef LoadResource
#undef FindResourceW
#undef FreeLibrary
#undef LoadLibraryExW
int wmain(int argc,wchar_t* argv[]){
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 const auto pid=std::to_wstring(GetCurrentProcessId());for(int i=1;i+1<argc;++i)if(std::wstring(argv[i])==L"--pid")argv[i+1]=const_cast<wchar_t*>(pid.c_str());
 if(mode==L"mta")assert(SUCCEEDED(CoInitializeEx(nullptr,COINIT_MULTITHREADED)));
 ks::cli::registerProcessHotkeys();const auto result=ks::cli::dispatchR3(argc,argv).value_or(1);
 if(mode==L"mta"){APTTYPE apartment;APTTYPEQUALIFIER qualifier;assert(SUCCEEDED(CoGetApartmentType(&apartment,&qualifier)) && apartment==APTTYPE_MTA);CoUninitialize();}
 assert(loads==frees);return result;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-hotkeys-') as temp:
        directory=Path(temp);source=SOURCE
        for key,path in {'HOTKEYHEADER':'shared/usermode/backend/process/ProcessHotkeys.h','REGISTRY':'KswordCLI/CommandRegistry.h',
                         'HOTKEYCPP':'shared/usermode/backend/process/ProcessHotkeys.cpp'}.items():source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        sources=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3ProcessHotkeys.cpp','shared/usermode/backend/process/ProcessEnumerator.cpp',
                 'shared/usermode/backend/NtApi.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',
                        str(directory/'fixture.cpp'),*[str(ROOT/path) for path in sources],'/Fe:'+str(binary),'/link','Advapi32.lib','User32.lib','Ole32.lib','Shell32.lib','Uuid.lib'],cwd=directory,check=True)
        def run(mode,kind,code):
            result=subprocess.run([str(binary),mode,'process','hotkeys','enum','--pid','self','--source',kind,'--json'],capture_output=True,timeout=15)
            assert result.returncode==code,(result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)['data']
        absent=run('absent','accelerators',0)
        assert absent['sources'][0]['absent'] and absent['matchedCount']=='0'
        char=run('character','accelerators',0)['candidates'][0]
        assert char['keyKind']=='character' and char['virtualKey'] is None and char['keyCode']==106 and char['hotkey']=='j'
        malformed=run('malformed','accelerators',4)
        assert malformed['sources'][0]['malformed'] and malformed['sources'][0]['failures'][0]['code']==13
        budget=run('budget','accelerators',6)
        assert budget['sources'][0]['limited'] and not budget['sources'][0]['complete']
        timeout=run('window-timeout','windows',6)
        assert timeout['sources'][0]['failures'][0]['code']==1460 and timeout['matchedCount']=='0'
        mta=run('mta','shortcuts',0)
        assert mta['sources'][0]['comStatus']=='0x80010106' and not mta['sources'][0]['comOwned']
        print('R3_HOTKEYS_FIXTURE_PASS valid empty sources, character resources, malformed data, deadline, timeout and module/COM ownership')


if __name__=='__main__':
    main()
