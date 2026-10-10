"""Context-menu production adapters/backend against private real registry trees and API faults."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''
#pragma once
#include <Windows.h>
LSTATUS WINAPI FixtureOpen(HKEY,LPCWSTR,DWORD,REGSAM,PHKEY);
LSTATUS WINAPI FixtureCreate(HKEY,LPCWSTR,DWORD,LPWSTR,DWORD,REGSAM,const LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
LSTATUS WINAPI FixtureGet(HKEY,LPCWSTR,LPCWSTR,DWORD,LPDWORD,PVOID,LPDWORD);
LSTATUS WINAPI FixtureSet(HKEY,LPCWSTR,DWORD,DWORD,const BYTE*,DWORD);
LSTATUS WINAPI FixtureCopy(HKEY,LPCWSTR,HKEY);LSTATUS WINAPI FixtureDelete(HKEY,LPCWSTR);
LSTATUS WINAPI FixtureEnum(HKEY,DWORD,LPWSTR,LPDWORD,LPDWORD,LPWSTR,LPDWORD,PFILETIME);
LSTATUS WINAPI FixtureClose(HKEY);
#define RegOpenKeyExW FixtureOpen
#define RegCreateKeyExW FixtureCreate
#define RegGetValueW FixtureGet
#define RegSetValueExW FixtureSet
#define RegCopyTreeW FixtureCopy
#define RegDeleteTreeW FixtureDelete
#define RegEnumKeyExW FixtureEnum
#define RegCloseKey FixtureClose
'''
SOURCE=r'''
#include "mock.h"
#include "REGISTRY"
#include "BACKEND"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <set>
#include <string>
#undef RegOpenKeyExW
#undef RegCreateKeyExW
#undef RegGetValueW
#undef RegSetValueExW
#undef RegCopyTreeW
#undef RegDeleteTreeW
#undef RegEnumKeyExW
#undef RegCloseKey
static std::wstring mode,sandbox;static HKEY machine=nullptr,user=nullptr,classes=nullptr;static std::set<HKEY> live;
static bool setup=true,copied=false;static int liveDeletes=0;
static const std::wstring registration=L"*\\shell\\Fixture",physical=L"Software\\Classes\\*\\shell\\Fixture",backup=L"SOFTWARE\\KswordARKLight\\ShellExtensionBackup\\*!shell!Fixture";
static HKEY mapped(HKEY h){return h==HKEY_LOCAL_MACHINE?machine:h==HKEY_CURRENT_USER?user:h==HKEY_CLASSES_ROOT?classes:h;}
static bool active(const wchar_t* value){return !setup&&mode==value;}
static bool rootPath(LPCWSTR path){return path&&(wcscmp(path,L"*\\shell")==0||wcscmp(path,L"*\\shellex\\ContextMenuHandlers")==0||wcscmp(path,L"Directory\\shell")==0||wcscmp(path,L"Directory\\shellex\\ContextMenuHandlers")==0||wcscmp(path,L"Folder\\shellex\\ContextMenuHandlers")==0||wcscmp(path,L"SOFTWARE\\KswordARKLight\\ShellExtensionBackup")==0);}
LSTATUS WINAPI FixtureOpen(HKEY hive,LPCWSTR path,DWORD options,REGSAM access,PHKEY out){if(active(L"roots-denied")&&rootPath(path))return 5;const auto status=RegOpenKeyExW(mapped(hive),path,options,access,out);if(status==0)assert(live.insert(*out).second);return status;}
LSTATUS WINAPI FixtureCreate(HKEY hive,LPCWSTR path,DWORD reserved,LPWSTR cls,DWORD options,REGSAM access,const LPSECURITY_ATTRIBUTES security,PHKEY out,LPDWORD disposition){
 if(active(L"backup-create-denied")&&hive==HKEY_LOCAL_MACHINE)return 5;if(active(L"data-create-denied")&&path&&wcscmp(path,L"Data")==0)return 5;
 const auto status=RegCreateKeyExW(mapped(hive),path,reserved,cls,options,access,security,out,disposition);if(status==0)assert(live.insert(*out).second);return status;}
LSTATUS WINAPI FixtureGet(HKEY hive,LPCWSTR path,LPCWSTR value,DWORD flags,LPDWORD type,PVOID data,LPDWORD size){
 if(active(L"field-denied")&&path&&std::wstring(path).find(L"\\command")!=std::wstring::npos)return 5;
 if((active(L"field-malformed")||active(L"field-growth"))&&value&&wcscmp(value,L"MUIVerb")==0){if(type)*type=REG_SZ;*size=active(L"field-growth")?2u*1024u*1024u:3;return 0;}
 return RegGetValueW(mapped(hive),path,value,flags,type,data,size);}
LSTATUS WINAPI FixtureSet(HKEY h,LPCWSTR name,DWORD reserved,DWORD type,const BYTE* data,DWORD size){if(active(L"metadata-denied")&&wcscmp(name,L"SourcePath")==0)return 5;return RegSetValueExW(mapped(h),name,reserved,type,data,size);}
LSTATUS WINAPI FixtureCopy(HKEY from,LPCWSTR sub,HKEY to){if(active(L"copy-denied")||active(L"restore-copy-denied"))return 5;const auto status=RegCopyTreeW(mapped(from),sub,mapped(to));if(status==0&&!setup)copied=true;return status;}
LSTATUS WINAPI FixtureDelete(HKEY h,LPCWSTR path){if(h==HKEY_CLASSES_ROOT){++liveDeletes;if(active(L"live-delete-denied"))return 5;}if(active(L"cleanup-denied")&&h==HKEY_LOCAL_MACHINE)return 5;return RegDeleteTreeW(mapped(h),path);}
LSTATUS WINAPI FixtureEnum(HKEY h,DWORD index,LPWSTR name,LPDWORD count,LPDWORD reserved,LPWSTR cls,LPDWORD clsCount,PFILETIME time){if(active(L"enum-partial")&&index==1)return 5;return RegEnumKeyExW(mapped(h),index,name,count,reserved,cls,clsCount,time);}
LSTATUS WINAPI FixtureClose(HKEY h){assert(live.erase(h)==1);const auto status=RegCloseKey(h);return active(L"close-denied")&&copied?5:status;}
static HKEY create(HKEY h,const std::wstring& path){HKEY key=nullptr;assert(RegCreateKeyExW(h,path.c_str(),0,nullptr,0,KEY_ALL_ACCESS,nullptr,&key,nullptr)==0);return key;}
static void string(HKEY h,const wchar_t* name,const std::wstring& text){assert(RegSetValueExW(h,name,0,REG_SZ,reinterpret_cast<const BYTE*>(text.c_str()),static_cast<DWORD>((text.size()+1)*sizeof(wchar_t)))==0);}
static void createSource(){const auto key=create(machine,physical);string(key,nullptr,L"Fixture label");string(key,L"MUIVerb",L"Fixture verb");const DWORD marker=321;assert(RegSetValueExW(key,L"Marker",0,REG_DWORD,reinterpret_cast<const BYTE*>(&marker),sizeof(marker))==0);
 const auto cmd=create(key,L"command");string(cmd,nullptr,L"\"C:\\Windows\\System32\\notepad.exe\" \"%1\"");RegCloseKey(cmd);RegCloseKey(key);}
static bool present(HKEY h,const std::wstring& path){HKEY key=nullptr;const auto status=RegOpenKeyExW(h,path.c_str(),0,KEY_READ,&key);if(status==0)RegCloseKey(key);return status==0;}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 sandbox=L"Software\\KSwordCliR3NativeContext-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());const auto root=create(HKEY_CURRENT_USER,sandbox);
 machine=create(root,L"Machine");user=create(root,L"User");classes=create(machine,L"Software\\Classes");createSource();
 bool enable=false;for(int i=1;i<argc;++i)if(std::wstring(argv[i])==L"enable")enable=true;
 if(enable||mode==L"direct-backup-collision"){ks::r3::system_tools::ContextMenuEntry e;e.registrationPath=registration;e.kind=ks::r3::system_tools::ContextMenuKind::ShellVerb;e.scopeText=L"*";e.name=L"Fixture";const auto disabled=ks::r3::system_tools::DisableContextMenuEntry(e);assert(disabled.success&&live.empty());}
 if(mode==L"destination-collision"||mode==L"direct-backup-collision")createSource();
 if(mode==L"user-overlay"){const auto overlay=create(user,physical);string(overlay,L"MUIVerb",L"USER");RegCloseKey(overlay);}
 if(mode==L"missing-kind"||mode==L"wrong-source"){const auto key=create(machine,backup);if(mode==L"missing-kind")assert(RegDeleteValueW(key,L"Kind")==0);else string(key,L"SourcePath",L"Software\\Outside");RegCloseKey(key);}
 setup=false;int code=0;
 if(mode==L"direct-backup-collision"){ks::r3::system_tools::ContextMenuEntry e;e.registrationPath=registration;const auto outcome=ks::r3::system_tools::DisableContextMenuEntry(e);assert(!outcome.success&&outcome.error==183&&outcome.backupRetained&&present(machine,physical));}
 else {ks::cli::registerSystemContextMenu();code=ks::cli::dispatchR3(argc,argv).value_or(1);}
 assert(live.empty());if(mode==L"metadata-denied"||mode==L"copy-denied"||mode==L"data-create-denied"||mode==L"backup-create-denied")assert(liveDeletes==0&&present(machine,physical));
 RegCloseKey(classes);RegCloseKey(user);RegCloseKey(machine);RegCloseKey(root);assert(RegDeleteTreeW(HKEY_CURRENT_USER,sandbox.c_str())==0);return code;
}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-context-menu-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8');source=SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('BACKEND',(ROOT/'shared/usermode/backend/system/ContextMenuScanner.h').as_posix());(directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3SystemContextMenu.cpp','shared/usermode/backend/system/ContextMenuScanner.cpp','shared/usermode/backend/system/AdminState.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,code,operation='enum'):
            args=['--registration',r'*\shell\Fixture','--confirm'] if operation!='enum' else []
            result=subprocess.run([str(binary),mode,'system','context-menu',operation,'--json',*args],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['matchedCount']=='1' and valid['entries'][0]['fields']['command']['available']
        assert run('roots-denied',3)['matchedCount']=='0'
        assert run('enum-partial',6)['matchedCount']=='1'
        assert run('field-denied',6)['entries'][0]['fields']['command']['win32Error']==5
        assert run('field-malformed',4)['entries'][0]['fields']['muiVerb']['malformed']
        assert run('field-growth',6)['entries'][0]['fields']['muiVerb']['limited']
        disabled=run('valid',0,'disable');assert disabled['verified'] and disabled['metadataSucceeded'] and disabled['sourceDeleted'] and disabled['afterBackup']['present']
        enabled=run('valid',0,'enable');assert enabled['verified'] and enabled['backupDeleted'] and enabled['afterMachineRegistration']['present']
        assert not run('user-overlay',5,'disable')['attempted']
        assert not run('destination-collision',3,'enable')['attempted']
        for mode in ('missing-kind','wrong-source'):assert not run(mode,4,'enable')['attempted']
        assert run('backup-create-denied',3,'disable')['win32Error']==5
        assert run('data-create-denied',6,'disable')['backupCreated']
        copied=run('copy-denied',6,'disable');assert not copied['copySucceeded'] and not copied['sourceDeleted'] and not copied['backupRetained']
        metadata=run('metadata-denied',6,'disable');assert metadata['copySucceeded'] and not metadata['metadataSucceeded'] and not metadata['sourceDeleted'] and metadata['backupRetained']
        assert not run('live-delete-denied',6,'disable')['sourceDeleted']
        restore=run('restore-copy-denied',6,'enable');assert restore['destinationCreated'] and not restore['copySucceeded'] and restore['backupRetained']
        cleanup=run('cleanup-denied',6,'enable');assert cleanup['backendSucceeded'] and not cleanup['verified'] and cleanup['backupRetained'] and cleanup['cleanupWin32Error']==5
        closed=run('close-denied',6,'disable');assert closed['backendSucceeded'] and not closed['verified'] and any(c['step']=='close-key' and c['win32Error']==5 for c in closed['calls'])
        subprocess.run([str(binary),'direct-backup-collision'],check=True,capture_output=True,timeout=10)
        print('R3_CONTEXT_MENU_FIXTURE_PASS private real subtrees, query status/type/bounds, metadata-before-delete, copy/create/delete/cleanup failures, collision/overlay/source guards and owned key cleanup')
if __name__=='__main__':main()
