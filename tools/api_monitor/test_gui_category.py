"""Compile the production Raw classifier and category gate against real config types."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DEV = Path(os.environ.get('KSWORD_VSDEVCMD', r'D:\Software\VS\Common7\Tools\VsDevCmd.bat'))
source = (ROOT/'APIMonitor_x64/hook/HookTargets.cpp').read_text(encoding='utf-8-sig')


def function(name):
    match = re.search(r'        (?:bool|ks::winapi_monitor::EventCategory) '+name+r'\([^;{]*\)\s*\{', source)
    assert match, name
    depth = 1
    end = match.end()
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


fixture = r'''
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "APIMonitor_x64/core/MonitorConfig.h"
#include <cassert>
#include <cstdio>
using apimon::MonitorConfig;
MonitorConfig current;
const MonitorConfig& ActiveConfig(){return current;}
std::wstring ToLowerWide(std::wstring s){for(auto& c:s)c=static_cast<wchar_t>(std::towlower(c));return s;}
std::string ToLowerAnsi(std::string s){for(auto& c:s)c=static_cast<char>(std::tolower(static_cast<unsigned char>(c)));return s;}
// FUNCTIONS
int main(){
 using C=ks::winapi_monitor::EventCategory;
 assert(current.enableProcess && !current.enableGui);
 for(const auto* module:{L"gdi32.dll",L"GDI32FULL.DLL",L"Gdiplus.dll",L"dwmapi.dll",L"msimg32.dll",
  L"d2d1.dll",L"dwrite.dll",L"opengl32.dll",L"dxgi.dll",L"d3d11.dll",L"uxtheme.dll",L"GDI32",L"C:\\Windows\\System32\\gdi32.dll"}){
  for(const auto* api:{"GetBkMode","GetFontFileData","RegAnything"}){
   const auto c=InferRawHookCategory(module,api);assert(c==C::Gui && !CategoryEnabled(c));
   current.enableGui=true;assert(CategoryEnabled(c));current.enableGui=false;
  }
 }
 for(const auto* api:{"GetDC","ReleaseDC","BeginPaint","DrawTextW","PrintWindow","InvalidateRect"})
  assert(InferRawHookCategory(L"user32.dll",api)==C::Gui);
 assert(InferRawHookCategory(L"win32u.dll","NtGdiBitBlt")==C::Gui);
 assert(InferRawHookCategory(L"kernel32.dll","CreateFileW")==C::File);
 assert(InferRawHookCategory(L"advapi32.dll","RegOpenKeyW")==C::Registry);
 assert(InferRawHookCategory(L"ws2_32.dll","socket")==C::Network);
 assert(InferRawHookCategory(L"kernel32.dll","LoadLibraryW")==C::Loader);
 assert(InferRawHookCategory(L"user32.dll","DefWindowProcW")==C::Process); // legacy guesses remain unchanged
 current.enableProcess=false;current.enableGui=true;assert(!CategoryEnabled(C::Process) && CategoryEnabled(C::Gui));
 std::puts("GUI_RAW_CLASSIFIER_GATE=PASS");
}
'''.replace('// FUNCTIONS', function('CategoryEnabled')+'\n'+function('InferRawHookCategory'))

with tempfile.TemporaryDirectory(prefix='ksword-gui-category-') as temp:
    folder = Path(temp)
    cpp = folder/'fixture.cpp'
    cpp.write_text(fixture, encoding='utf-8')
    for arch in ('x86', 'x64'):
        exe = folder/(arch+'.exe')
        batch = folder/(arch+'.cmd')
        batch.write_text(f'@echo off\ncall "{DEV}" -no_logo -host_arch=x64 -arch={arch} >nul\n'
                         f'cl /nologo /std:c++17 /EHsc /MT /I"{ROOT}" /I"{ROOT / "APIMonitor_x64"}" "{cpp}" '
                         f'/Fo"{folder / (arch+".obj")}" /Fe"{exe}"\nif errorlevel 1 exit /b %errorlevel%\n"{exe}"\n', encoding='utf-8')
        subprocess.run(['cmd.exe', '/d', '/c', str(batch)], check=True, cwd=ROOT)
