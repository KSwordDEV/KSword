"""Clipboard metadata avoids rendering; bounded previews and exact ownership/error states."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''
#pragma once
#include <Windows.h>
BOOL WINAPI FixtureOpen(HWND);
BOOL WINAPI FixtureClose();
HANDLE WINAPI FixtureData(UINT);
SIZE_T WINAPI FixtureSize(HGLOBAL);
LPVOID WINAPI FixtureLock(HGLOBAL);
BOOL WINAPI FixtureUnlock(HGLOBAL);
UINT WINAPI FixtureEnum(UINT);
int WINAPI FixtureCount();
DWORD WINAPI FixtureSequence();
HWND WINAPI FixtureOwner();
HWND WINAPI FixtureHolder();
BOOL WINAPI FixtureAvailable(UINT);
int WINAPI FixtureName(UINT,LPWSTR,int);
DWORD WINAPI FixtureWindowOwner(HWND,LPDWORD);
#define OpenClipboard FixtureOpen
#define CloseClipboard FixtureClose
#define GetClipboardData FixtureData
#define GlobalSize FixtureSize
#define GlobalLock FixtureLock
#define GlobalUnlock FixtureUnlock
#define EnumClipboardFormats FixtureEnum
#define CountClipboardFormats FixtureCount
#define GetClipboardSequenceNumber FixtureSequence
#define GetClipboardOwner FixtureOwner
#define GetOpenClipboardWindow FixtureHolder
#define GetClipboardViewer FixtureHolder
#define IsClipboardFormatAvailable FixtureAvailable
#define GetClipboardFormatNameW FixtureName
#define GetWindowThreadProcessId FixtureWindowOwner
'''
SOURCE=r'''
#include "mock.h"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <string>
#include <vector>
static std::wstring mode;
static std::vector<UINT> formats;
static std::vector<wchar_t> unicode;
static const char ansi[]="Ansi\0";
static bool opened=false;static DWORD ownerThread=0;
static int opens=0,closes=0,reads=0,locks=0,unlocks=0,sequenceCalls=0;
BOOL WINAPI FixtureOpen(HWND){++opens;if(mode==L"blocked"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}assert(!opened);opened=true;ownerThread=GetCurrentThreadId();return TRUE;}
BOOL WINAPI FixtureClose(){assert(opened&&ownerThread==GetCurrentThreadId());++closes;opened=false;if(mode==L"close-fail"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return TRUE;}
HANDLE WINAPI FixtureData(UINT format){assert(opened&&ownerThread==GetCurrentThreadId());++reads;if(mode==L"data-fail"){SetLastError(ERROR_ACCESS_DENIED);return nullptr;}return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(format));}
SIZE_T WINAPI FixtureSize(HGLOBAL handle){assert(opened);if(mode==L"size-fail"){SetLastError(ERROR_INVALID_HANDLE);return 0;}if(mode==L"large-size")return 9007199254740993ull;const auto format=reinterpret_cast<std::uintptr_t>(handle);return format==CF_UNICODETEXT?unicode.size()*sizeof(wchar_t):format==CF_TEXT?sizeof(ansi):5;}
LPVOID WINAPI FixtureLock(HGLOBAL handle){assert(opened);if(mode==L"lock-fail"){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return nullptr;}++locks;return reinterpret_cast<std::uintptr_t>(handle)==CF_UNICODETEXT?static_cast<void*>(unicode.data()):const_cast<char*>(ansi);}
BOOL WINAPI FixtureUnlock(HGLOBAL){assert(opened);++unlocks;if(mode==L"unlock-fail"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}SetLastError(ERROR_SUCCESS);return FALSE;}
UINT WINAPI FixtureEnum(UINT previous){assert(opened);if(mode==L"enum-fail"){SetLastError(ERROR_ACCESS_DENIED);return 0;}if(mode==L"duplicate"&&previous)return previous;if(!previous)return formats.empty()?0:formats.front();for(std::size_t i=1;i<formats.size();++i)if(formats[i-1]==previous)return formats[i];return 0;}
int WINAPI FixtureCount(){return static_cast<int>(formats.size());}
DWORD WINAPI FixtureSequence(){++sequenceCalls;return mode==L"changed"&&sequenceCalls>2?8:7;}
HWND WINAPI FixtureOwner(){return reinterpret_cast<HWND>(0x1234);}
HWND WINAPI FixtureHolder(){return nullptr;}
BOOL WINAPI FixtureAvailable(UINT format){for(const auto current:formats)if(current==format)return TRUE;return FALSE;}
int WINAPI FixtureName(UINT,LPWSTR buffer,int size){if(mode==L"name-fail"){SetLastError(ERROR_ACCESS_DENIED);return 0;}if(mode==L"name-unknown")return 0;wcscpy_s(buffer,size,L"FixtureCustom");return 13;}
DWORD WINAPI FixtureWindowOwner(HWND,LPDWORD pid){if(pid)*pid=GetCurrentProcessId();return GetCurrentThreadId();}
int wmain(int argc,wchar_t* argv[]){
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 formats={CF_UNICODETEXT,0xc001};unicode={L'A',L'B',L'C',0};
 if(mode==L"empty")formats.clear();if(mode==L"gdi")formats={CF_BITMAP};if(mode==L"ansi")formats={CF_TEXT};
 if(mode==L"empty-text")unicode={0};if(mode==L"no-terminator")unicode={L'x',L'y'};if(mode==L"bad-surrogate")unicode={0xd800,0};
 if(mode==L"pair")unicode={0xd83d,0xde00,0};
 ks::cli::registerClipboardRead();const auto rc=ks::cli::dispatchR3(argc,argv).value_or(1);
 assert(!opened);if(mode==L"blocked")assert(opens==4&&closes==0);else assert(opens==1&&closes==1);
 assert(locks==unlocks);if(mode==L"metadata")assert(reads==0&&locks==0);return rc;
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-clipboard-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        (directory/'fixture.cpp').write_text(SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()),encoding='utf-8');binary=directory/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),
                        *[str(ROOT/path) for path in ['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Clipboard.cpp','shared/usermode/backend/window/Clipboard.cpp','shared/usermode/backend/window/WindowQueries.cpp','shared/usermode/backend/Common.cpp']],
                        '/Fe:'+str(binary),'/link','Advapi32.lib','User32.lib','Shell32.lib'],cwd=directory,check=True)
        def run(mode,code,text=False,extra=()):
            result=subprocess.run([str(binary),mode,'window','clipboard',*(['text','query'] if text else ['formats','enum']),'--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:1500],result.stderr)
            return json.loads(result.stdout)['data']
        metadata=run('metadata',0);assert all(not f['dataRequested'] and f['byteSize'] is None for f in metadata['formats'])
        assert run('empty',0)['enumeratedCount']=='0'
        assert run('empty',5,text=True)['text'] is None
        gdi=run('gdi',0,extra=['--materialize','on'])['formats'][0];assert gdi['handleBacked'] and not gdi['globalMemorySizeSupported'] and gdi['byteSize'] is None
        assert run('large-size',0,extra=['--materialize','on'])['formats'][0]['byteSize']=='9007199254740993'
        assert run('blocked',3)['clipboard']['openWin32Error']==5
        assert run('data-fail',6,extra=['--materialize','on'])['formats'][0]['dataWin32Error']==5
        assert run('name-fail',6)['formats'][1]['name'] is None
        assert run('name-unknown',6)['formats'][1]['nameWin32Error'] is None
        assert not run('enum-fail',6)['clipboard']['enumComplete']
        assert run('duplicate',4)['clipboard']['enumWin32Error']==13
        assert not run('close-fail',6)['clipboard']['closed']
        assert run('changed',6)['clipboard']['changedDuringCapture']
        text=run('valid',0,text=True);assert text['text']=='ABC' and text['terminated'] and text['unlocked'] and text['returnedUtf16Units']==3
        assert run('ansi',0,text=True,extra=['--format','ansi'])['text']=='Ansi'
        empty=run('empty-text',0,text=True);assert empty['empty'] and empty['text']==''
        assert run('no-terminator',4,text=True)['malformed']
        assert run('bad-surrogate',4,text=True)['text'] is None
        pair=run('pair',6,text=True,extra=['--max-units','1']);assert pair['truncated'] and pair['text']=='' and not pair['empty']
        assert run('pair',0,text=True)['text']=='\U0001f600'
        assert run('size-fail',3,text=True)['readWin32Error']==6
        assert run('lock-fail',3,text=True)['readWin32Error']==8
        assert run('data-fail',3,text=True)['readWin32Error']==5
        assert not run('unlock-fail',6,text=True)['unlocked']
        short=run('valid',6,text=True,extra=['--max-units','2']);assert short['text']=='AB' and short['truncated'] and short['terminated'] is None
        print('R3_CLIPBOARD_FIXTURE_PASS no-render metadata, exact sizes, empty/GDI/unknown data, bounded UTF16/ACP previews, malformed/terminator/surrogate data, API errors, sequence and close/unlock ownership')

if __name__=='__main__':main()
