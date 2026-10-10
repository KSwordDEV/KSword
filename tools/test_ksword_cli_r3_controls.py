"""Verify action status, identity checks and process-tree provenance without mutation."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#pragma once
#include <Windows.h>
#include <tlhelp32.h>
HANDLE WINAPI FixtureOpen(DWORD,BOOL,DWORD);
BOOL WINAPI FixtureTimes(HANDLE,LPFILETIME,LPFILETIME,LPFILETIME,LPFILETIME);
BOOL WINAPI FixtureClose(HANDLE);
BOOL WINAPI FixturePriority(HANDLE,DWORD);
FARPROC WINAPI FixtureResolve(HMODULE,LPCSTR);
HANDLE WINAPI FixtureSnapshot(DWORD,DWORD);
BOOL WINAPI FixtureFirst(HANDLE,LPPROCESSENTRY32W);
BOOL WINAPI FixtureNext(HANDLE,LPPROCESSENTRY32W);
BOOL WINAPI FixtureToken(HANDLE,DWORD,PHANDLE);
#define OpenProcess FixtureOpen
#define GetProcessTimes FixtureTimes
#define CloseHandle FixtureClose
#define SetPriorityClass FixturePriority
#define GetProcAddress FixtureResolve
#define CreateToolhelp32Snapshot FixtureSnapshot
#define Process32FirstW FixtureFirst
#define Process32NextW FixtureNext
#define OpenProcessToken FixtureToken
'''
SOURCE = r'''
#include "mock.h"
#include "CONTROLS"
#include <cassert>
#include <cstring>
static LONG status;
static bool available=true;
static unsigned setters;
HANDLE WINAPI FixtureOpen(DWORD,BOOL,DWORD) {return reinterpret_cast<HANDLE>(123);}
BOOL WINAPI FixtureTimes(HANDLE,LPFILETIME create,LPFILETIME,LPFILETIME,LPFILETIME) {*create={5,0};return TRUE;}
BOOL WINAPI FixtureClose(HANDLE) {return TRUE;}
BOOL WINAPI FixturePriority(HANDLE,DWORD) {++setters;SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
LONG NTAPI FixtureSuspend(HANDLE) {return status;}
LONG NTAPI FixtureSet(HANDLE,ULONG,PVOID,ULONG) {return status;}
FARPROC WINAPI FixtureResolve(HMODULE,LPCSTR name) {
 if(!available)return nullptr;
 return std::strcmp(name,"NtSetInformationProcess")==0?reinterpret_cast<FARPROC>(FixtureSet):reinterpret_cast<FARPROC>(FixtureSuspend);
}
HANDLE WINAPI FixtureSnapshot(DWORD,DWORD) {return reinterpret_cast<HANDLE>(124);}
BOOL WINAPI FixtureFirst(HANDLE,LPPROCESSENTRY32W item) {item->th32ProcessID=9000;return TRUE;}
BOOL WINAPI FixtureNext(HANDLE,LPPROCESSENTRY32W) {SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
BOOL WINAPI FixtureToken(HANDLE,DWORD,PHANDLE) {SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
namespace ks::process {
#define STUB(name) bool name(std::uint32_t,std::string*){return false;}
STUB(TerminateProcessByWin32) STUB(TerminateProcessByNtNative) STUB(TerminateProcessByWtsApi) STUB(TerminateProcessByWinStationApi)
STUB(TerminateProcessByJobObject) STUB(TerminateProcessByNtJobObject) STUB(TerminateProcessByDuplicateHandlePseudo)
STUB(TerminateAllThreadsByPid) STUB(TerminateAllThreadsByPidNtNative) STUB(TerminateProcessByDebugAttach)
STUB(TerminateProcessByNtsdCommand) STUB(TerminateProcessByNtUnmapNtdll)
bool TerminateProcessByRestartManager(std::uint32_t,bool,std::string*){return false;}
}
int main() {
 using namespace ks::r3::process;ProcessOperationEvidence e;std::wstring message;
 status=0x102;assert(!NtSuspendOrResumeProcess(8100,5,false,message,&e));assert(e.ntStatusKnown && e.ntStatus==0x102 && e.identityMatched);
 status=static_cast<LONG>(0xc0000022);assert(!SetCriticalFlagForPid(8100,5,true,message,&e));assert(e.ntStatusKnown && static_cast<DWORD>(e.ntStatus)==0xc0000022);
 available=false;assert(!NtSuspendOrResumeProcess(8100,5,false,message,&e) && e.unsupported && !e.ntStatusKnown);available=true;
 assert(!SetPriorityForPid(8100,6,NORMAL_PRIORITY_CLASS,message,&e));assert(!e.identityMatched && e.observedCreationTime==5 && setters==0);
 assert(!SetPriorityForPid(8100,5,NORMAL_PRIORITY_CLASS,message,&e));assert(e.win32ErrorKnown && e.win32Error==5 && setters==1);
 bool known=true;assert(IsProcessPresentBySnapshot(8100,&known) && !known);
 std::vector<ProcessSnapshotRow> rows(4);rows[0].processId=8100;rows[0].creationTime100ns=20;
 rows[1].processId=8101;rows[1].parentProcessId=8100;rows[1].creationTime100ns=10;
 rows[2].processId=8102;rows[2].parentProcessId=8100;rows[2].creationTime100ns=30;
 rows[3].processId=8103;rows[3].parentProcessId=8102;rows[3].creationTime100ns=40;
 assert((CollectR3ProcessTreePids({8100},rows)==std::vector<DWORD>{8103,8102,8100}));
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-controls-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        (directory / 'fixture.cpp').write_text(SOURCE.replace('CONTROLS', (ROOT / 'shared/usermode/backend/process/ProcessControls.h').as_posix()))
        binary = directory / 'fixture.exe'
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        str(ROOT / 'shared/usermode/backend/process/ProcessControls.cpp'), str(ROOT / 'shared/usermode/backend/Common.cpp'),
                        '/Fe:' + str(binary), '/link', 'Advapi32.lib'], cwd=directory, check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
        print('R3_CONTROLS_FIXTURE_PASS NT timeout/failure, raw errors, identity no-op, snapshot failure and recycled-parent tree')


if __name__ == '__main__':
    main()
