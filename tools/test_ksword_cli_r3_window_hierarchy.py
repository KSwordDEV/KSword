"""Typed hierarchy faults and bounded native traversals, using the production CLI adapter."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_window import HEADER as WINDOW_HEADER, SOURCE as WINDOW_SOURCE
ROOT=Path(__file__).resolve().parents[1]
HEADER=WINDOW_HEADER+r'''
HWND WINAPI FixtureAncestor(HWND,UINT);HWND WINAPI FixtureParent(HWND);HWND WINAPI FixtureWindow(HWND,UINT);HWND WINAPI FixtureTop(HWND);
ULONG_PTR WINAPI FixtureClassLong(HWND,int);BOOL WINAPI FixtureClassInfo(HINSTANCE,LPCWSTR,LPWNDCLASSEXW);BOOL WINAPI FixtureScreen(HWND,LPPOINT);
BOOL WINAPI FixtureAffinity(HWND,PDWORD);BOOL WINAPI FixtureLayered(HWND,COLORREF*,BYTE*,DWORD*);
FARPROC WINAPI FixtureProcedure(HMODULE,LPCSTR);HMODULE WINAPI FixtureModule(LPCWSTR);HMODULE WINAPI FixtureLoad(LPCWSTR);BOOL WINAPI FixtureFree(HMODULE);
#define GetAncestor FixtureAncestor
#define GetParent FixtureParent
#define GetWindow FixtureWindow
#define GetTopWindow FixtureTop
#define GetClassLongPtrW FixtureClassLong
#define GetClassInfoExW FixtureClassInfo
#define ClientToScreen FixtureScreen
#define GetWindowDisplayAffinity FixtureAffinity
#define GetLayeredWindowAttributes FixtureLayered
#define GetProcAddress FixtureProcedure
#define GetModuleHandleW FixtureModule
#define LoadLibraryW FixtureLoad
#define FreeLibrary FixtureFree
'''
EXTRA=r'''
static int loaded=0,freed=0;
static const HWND parent=reinterpret_cast<HWND>(0x2000);
HWND WINAPI FixtureParent(HWND h){return h==window?parent:nullptr;}
HWND WINAPI FixtureAncestor(HWND h,UINT kind){
 if(kind!=GA_PARENT)return window;
 if(mode==L"ancestry-denied"){SetLastError(5);return nullptr;}
 if(mode==L"ancestry-cycle")return parent;
 if(mode==L"ancestry-limit")return reinterpret_cast<HWND>(reinterpret_cast<std::uintptr_t>(h)+1);
 return h==window?parent:nullptr;
}
HWND WINAPI FixtureWindow(HWND h,UINT kind){if(kind==GW_OWNER||kind==GW_HWNDPREV)return nullptr;
 if(kind==GW_HWNDNEXT){if(mode==L"z-cycle")return window;if(mode==L"z-limit")return reinterpret_cast<HWND>(reinterpret_cast<std::uintptr_t>(h)+1);if(mode==L"z-denied")SetLastError(5);}return nullptr;}
HWND WINAPI FixtureTop(HWND){return mode==L"root-missing"?parent:window;}
ULONG_PTR WINAPI FixtureClassLong(HWND,int kind){if(kind==GCLP_WNDPROC&&mode==L"procedure-denied"){SetLastError(5);return 0;}return 0;}
BOOL WINAPI FixtureClassInfo(HINSTANCE,LPCWSTR,LPWNDCLASSEXW info){if(mode==L"local-class"){info->lpfnWndProc=reinterpret_cast<WNDPROC>(0x5678);info->style=CS_DBLCLKS;return TRUE;}SetLastError(mode==L"class-denied"?5:ERROR_CLASS_DOES_NOT_EXIST);return FALSE;}
BOOL WINAPI FixtureScreen(HWND,LPPOINT point){if(mode==L"geometry-denied"){SetLastError(5);return FALSE;}point->x=-40;point->y=20;return TRUE;}
BOOL WINAPI FixtureAffinity(HWND,PDWORD policy){if(mode==L"affinity-denied"){SetLastError(87);return FALSE;}*policy=0;return TRUE;}
BOOL WINAPI FixtureLayered(HWND,COLORREF* color,BYTE* alpha,DWORD* flags){*color=0xabcdef;*alpha=155;*flags=LWA_ALPHA;return TRUE;}
UINT WINAPI FixtureDpi(HWND){return mode==L"zero-dpi"?0:144;}
void* WINAPI FixtureContext(HWND){return reinterpret_cast<void*>(-4);}
int WINAPI FixtureAwareness(void*){return 2;}
UINT WINAPI FixtureContextDpi(void*){return 0;}
BOOL WINAPI FixtureContextsEqual(void* a,void* b){return a==b;}
HRESULT WINAPI FixtureDwm(HWND,DWORD attribute,PVOID data,DWORD){if(mode==L"dwm-denied")return E_ACCESSDENIED;if(mode==L"dwm-false")return S_FALSE;if(attribute==14)*static_cast<DWORD*>(data)=0;else *static_cast<RECT*>(data)={-10,20,300,400};return S_OK;}
FARPROC WINAPI FixtureProcedure(HMODULE,LPCSTR name){
 if(mode==L"apis-missing")return nullptr;
 if(strcmp(name,"GetDpiForWindow")==0)return reinterpret_cast<FARPROC>(FixtureDpi);
 if(strcmp(name,"GetWindowDpiAwarenessContext")==0)return reinterpret_cast<FARPROC>(FixtureContext);
 if(strcmp(name,"GetAwarenessFromDpiAwarenessContext")==0)return reinterpret_cast<FARPROC>(FixtureAwareness);
 if(strcmp(name,"GetDpiFromDpiAwarenessContext")==0)return reinterpret_cast<FARPROC>(FixtureContextDpi);
 if(strcmp(name,"AreDpiAwarenessContextsEqual")==0)return reinterpret_cast<FARPROC>(FixtureContextsEqual);
 if(strcmp(name,"DwmGetWindowAttribute")==0)return reinterpret_cast<FARPROC>(FixtureDwm);return nullptr;
}
HMODULE WINAPI FixtureModule(LPCWSTR name){if(name&&wcscmp(name,L"dwmapi.dll")==0)return nullptr;return reinterpret_cast<HMODULE>(1);}
HMODULE WINAPI FixtureLoad(LPCWSTR name){assert(wcscmp(name,L"dwmapi.dll")==0);++loaded;return reinterpret_cast<HMODULE>(2);}
BOOL WINAPI FixtureFree(HMODULE h){assert(h==reinterpret_cast<HMODULE>(2));++freed;return TRUE;}
struct VerifyLifetime{~VerifyLifetime(){assert(loaded==freed);}};static VerifyLifetime verifyLifetime;
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-hierarchy-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        source=WINDOW_SOURCE.replace('registerWindow()','registerWindowHierarchy()')
        source=source.replace('LONG_PTR WINAPI FixtureLong(HWND,int){return 0;}',r'''LONG_PTR WINAPI FixtureLong(HWND,int kind){if(kind==GWL_STYLE&&mode==L"high-style")return static_cast<LONG_PTR>(static_cast<LONG>(WS_POPUP));if(kind==GWL_EXSTYLE&&mode==L"layered")return WS_EX_LAYERED;return 0;}''')
        source=source.replace('static std::wstring time(',EXTRA+'\nstatic std::wstring time(')
        (directory/'fixture.cpp').write_text(source.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()),encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3WindowHierarchy.cpp','shared/usermode/backend/window/WindowEnumerator.cpp','shared/usermode/backend/window/WindowFormatting.cpp','shared/usermode/backend/window/WindowQueries.cpp','shared/usermode/backend/window/WindowHierarchy.cpp','shared/usermode/backend/window/WindowHierarchySupport.cpp','shared/usermode/backend/window/PointerText.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','User32.lib'],cwd=directory,check=True)
        def run(mode,code):
            result=subprocess.run([str(binary),mode,'window','hierarchy','query','--hwnd','0x1234','--json'],capture_output=True,timeout=15)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr)
            data=json.loads(result.stdout)['data'];return data,{f['name']:f for f in data.get('fields',[])}
        data,fields=run('valid',0);assert data['parentChain']==['0x2000'] and data['parentChainComplete'] and data['zComplete'] and data['topLevelZIndexZeroBased']==0
        assert fields['style']['available'] and fields['style']['value']=='0x0' and fields['cloaked']['value']=='0x0'
        assert fields['contextDpi']['notApplicable'] and fields['contextDpi']['value'] is None and fields['windowDpi']['value']=='144'
        assert fields['clientOriginScreen']['value']['x']==-40 and fields['callerClassRegistration']['notApplicable']
        assert run('high-style',0)[1]['style']['value']=='0x80000000'
        assert run('local-class',0)[1]['callerClassProcedure']['value']=='0x5678'
        assert run('layered',0)[1]['layeredAlpha']['value']=='155'
        missing=run('apis-missing',6)[1];assert missing['windowDpi']['value'] is None and missing['cloaked']['value'] is None
        assert run('zero-dpi',6)[1]['windowDpi']['value'] is None
        for mode,name,error in [('procedure-denied','classProcedure',5),('geometry-denied','clientOriginScreen',5),('affinity-denied','displayAffinity',87),('class-denied','callerClassRegistration',5),('dwm-denied','cloaked','0x80070005'),('dwm-false','extendedFrameBounds','0x1')]:
            field=run(mode,6)[1][name];assert not field['available'] and field['value'] is None and field['error']==error and not field['notApplicable']
        assert run('ancestry-cycle',6)[0]['parentChainCycle']
        limited=run('ancestry-limit',6)[0];assert limited['parentChainLimited'] and len(limited['parentChain'])==32
        assert run('ancestry-denied',6)[0]['parentChainWin32Error']==5
        assert run('z-cycle',6)[0]['zCycle']
        z=run('z-limit',6)[0];assert z['zLimited'] and z['topLevelZCount']==100000
        assert run('z-denied',6)[0]['zWin32Error']==5
        assert run('root-missing',6)[0]['topLevelZIndexZeroBased'] is None
        assert not run('owner-change',3)[0]['identityMatched']
        print('R3_HIERARCHY_FIXTURE_PASS SDK errors/absence/zero values, typed coordinates/flags, cycles/limits, identity loss, caller class scope and owned DLL release')

if __name__=='__main__':main()
