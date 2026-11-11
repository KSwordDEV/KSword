"""Production broker authorization, malformed peers, session restart and bounded stop."""
from pathlib import Path
import shutil
import subprocess
import tempfile
from compiler_environment import target_environment
from live_fixture_support import ROOT

source=r'''
#include "ApiMonitorInjectionBroker.h"
#include "ApiMonitorInjection.h"
#include "WinApiMonitorProtocol.h"
#include <cstdio>
int wmain(int argc,wchar_t** argv){
 using namespace ks::winapi_monitor;
 if(argc==2&&wcscmp(argv[1],L"--child")==0){Sleep(60000);return 0;}
 if(argc!=2)return 1;
 wchar_t self[32768]{};GetModuleFileNameW(nullptr,self,32768);
 auto command=quoteWindowsArgument(self)+L" --child";STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION child{};
 if(!CreateProcessW(self,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&child))return 2;
 DWORD failure=0;
 auto config=buildConfigPathForPid(child.dwProcessId);auto rootStop=buildStopFlagPathForPid(GetCurrentProcessId());
 auto childStop=buildStopFlagPathForPid(child.dwProcessId);
 auto test=[&]()->DWORD{
  std::wstring error,session=L"broker-test-"+std::to_wstring(GetCurrentProcessId());
  CreateDirectoryW(buildSessionDirectory().c_str(),nullptr);DeleteFileW(rootStop.c_str());
  InjectionBroker broker;if(!broker.start(GetCurrentProcessId(),argv[1],session,rootStop,&error))return 3;
  auto endpoint=broker.endpoint();auto creation=processCreationIdentity(child.hProcess);
  // A UTF-16 child configuration belonging to the registered parent.
  HANDLE file=CreateFileW(config.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,0,nullptr);if(file==INVALID_HANDLE_VALUE)return 4;
  DWORD written=0;WORD bom=0xfeff;WriteFile(file,&bom,2,&written,nullptr);CloseHandle(file);
  auto ini=[&](const wchar_t* key,const std::wstring& value){return WritePrivateProfileStringW(L"monitor",key,value.c_str(),config.c_str())!=FALSE;};
  ini(L"session_id",session+L"_"+std::to_wstring(child.dwProcessId));ini(L"agent_dll_path",argv[1]);
  ini(L"root_stop_flag_path",rootStop);ini(L"stop_flag_path",childStop);
  ini(L"pipe_name",buildPipeNameForPid(child.dwProcessId));
  ini(L"injection_broker_pipe",endpoint.pipeName);ini(L"injection_broker_token",endpoint.token);
  ini(L"enable_file",L"1");ini(L"enable_registry",L"0");ini(L"enable_network",L"0");ini(L"enable_process",L"0");ini(L"enable_loader",L"0");
  auto bad=endpoint;bad.token=L"wrong-session";
  if(requestChildInjection(bad,child.dwProcessId,creation,&error)||GetLastError()!=ERROR_ACCESS_DENIED)return 5;
  if(requestChildInjection(endpoint,child.dwProcessId,1,&error)||GetLastError()!=ERROR_ACCESS_DENIED)return 6;
  if(requestChildInjection(endpoint,GetCurrentProcessId(),processCreationIdentity(GetCurrentProcess()),&error))return 7;
  bad=endpoint;bad.hostPid=child.dwProcessId;
  if(requestChildInjection(bad,child.dwProcessId,creation,&error))return 8;
  ini(L"agent_dll_path",L"invalid.dll");
  if(requestChildInjection(endpoint,child.dwProcessId,creation,&error))return 9;
  ini(L"agent_dll_path",argv[1]);
  auto stop=CreateFileW(rootStop.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,0,nullptr);CloseHandle(stop);
  if(requestChildInjection(endpoint,child.dwProcessId,creation,&error)||GetLastError()!=ERROR_OPERATION_ABORTED)return 10;
  DeleteFileW(rootStop.c_str());
  // A selected custom backend must be invoked only after authorization. If it
  // rejects, broker must not silently fall back to its native R3 injector.
  broker.stop();std::atomic<unsigned> customCalls{0};
  InjectionBroker::Injector rejected=[&](DWORD pid,const std::wstring& path,std::wstring* detail,std::uint64_t created,HANDLE){
   if(pid!=child.dwProcessId||created!=creation||path!=argv[1])return platformFailure(detail,L"unexpected callback target",ERROR_INVALID_PARAMETER);
   ++customCalls;return platformFailure(detail,L"intentional backend failure",ERROR_NOT_SUPPORTED);
  };
  if(!broker.start(GetCurrentProcessId(),argv[1],session,rootStop,&error,rejected))return 20;
  endpoint=broker.endpoint();
  if(requestChildInjection(endpoint,child.dwProcessId,creation,&error)||GetLastError()!=ERROR_NOT_SUPPORTED)return 21;
  if(customCalls.load()!=1||remoteImageLoaded(child.dwProcessId,argv[1]))return 22;
  broker.stop();if(!broker.start(GetCurrentProcessId(),argv[1],session,rootStop,&error))return 23;
  endpoint=broker.endpoint();
  if(!requestChildInjection(endpoint,child.dwProcessId,creation,&error)){fwprintf(stderr,L"%s\n",error.c_str());return 11;}
  if(!remoteImageLoaded(child.dwProcessId,argv[1]))return 12;
  if(!requestChildInjection(endpoint,child.dwProcessId,creation,&error))return 13;
  // An incomplete peer must not prevent broker shutdown.
  HANDLE pipe=CreateFileW(endpoint.pipeName.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);
  if(pipe==INVALID_HANDLE_VALUE){WaitNamedPipeW(endpoint.pipeName.c_str(),2000);pipe=CreateFileW(endpoint.pipeName.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);}
  if(pipe==INVALID_HANDLE_VALUE)return 14;
  Sleep(50);auto before=GetTickCount64();broker.stop();CloseHandle(pipe);
  if(GetTickCount64()-before>3000)return 15;
  if(requestChildInjection(endpoint,child.dwProcessId,creation,&error))return 16;
  if(!broker.start(GetCurrentProcessId(),argv[1],session+L"-new",rootStop,&error))return 17;
  if(requestChildInjection(endpoint,child.dwProcessId,creation,&error))return 18;
  if(requestChildInjection(broker.endpoint(),child.dwProcessId,creation,&error))return 19;
  broker.stop();return 0;
 };
 failure=test();DeleteFileW(config.c_str());DeleteFileW(rootStop.c_str());DeleteFileW(childStop.c_str());
 TerminateProcess(child.hProcess,0);WaitForSingleObject(child.hProcess,5000);CloseHandle(child.hThread);CloseHandle(child.hProcess);
 if(failure){printf("BROKER_FAILURE=%lu\n",failure);return failure;}
 puts("PASS: broker rejects wrong nonce, identities, parent and config; duplicate load, incomplete-peer stop and stale sessions");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="ksword_broker_test_") as temporary:
    directory=Path(temporary);cpp=directory/"fixture.cpp";cpp.write_text(source,encoding="utf-8")
    environment=target_environment("x64");compiler=shutil.which("cl",path=environment["PATH"])
    executable=directory/"fixture.exe"
    subprocess.run([compiler,"/nologo","/EHsc","/std:c++20","/utf-8","/MT","/I"+str(ROOT/"shared"),str(cpp),
                    str(ROOT/"shared/ApiMonitorInjectionBroker.cpp"),"/Fe:"+str(executable),"/Fo:"+str(directory)+"\\",
                    "/link","Advapi32.lib"],env=environment,check=True)
    subprocess.run([str(executable),str(ROOT/"Ksword5.1/x64/Release/APIMonitor_x64.dll")],check=True,timeout=60)
