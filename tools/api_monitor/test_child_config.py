"""Exercise production child INI inheritance and root stop propagation."""
from pathlib import Path
import subprocess
import os
import tempfile
root = Path(__file__).resolve().parents[2]
source = (root / "APIMonitor_x64/hook/HookTargets.cpp").read_text(encoding="utf-8-sig")
writer = source[source.index("        std::wstring JoinIniList("):source.index("        // InjectAgentIntoChildProcess")]
main = r'''
int main() {
 using namespace apimon;
 DWORD pid=GetCurrentProcessId();
 auto configPath=ks::winapi_monitor::buildConfigPathForPid(pid);
 auto stopPath=ks::winapi_monitor::buildStopFlagPathForPid(pid);
 auto rootStop=stopPath+L".root-test";
 auto touch=[](const std::wstring& p){HANDLE h=CreateFileW(p.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,0,nullptr); if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);};
 MonitorConfig parent;
 parent.agentDllPath=L"C:\\测试\\Agent.dll";
 parent.sessionId=L"parent-session"; parent.rootStopFlagPath=rootStop;
 parent.enableProcess=false; parent.enableMemory=true; parent.enableThread=false; parent.enableService=true;
 parent.enableSecurity=false; parent.enableCrypto=true; parent.enableCom=false; parent.enableWindow=true; parent.enableGui=true;
 parent.enableLoader=false; parent.autoInjectChild=true;
 parent.enableClipboard=true; parent.clipboardReadAction=ClipboardPolicyAction::Block;
 parent.clipboardWriteAction=ClipboardPolicyAction::LogOnly;
 parent.rawModuleList={L"ntdll.dll",L"user32.dll"};parent.rawDenyList={L"ntdll!test"};
 CreateDirectoryW(ks::winapi_monitor::buildSessionDirectory().c_str(),nullptr);
 touch(stopPath);
 std::wstring error;
 if(!WriteChildMonitorConfig(pid,parent,&error))return 1;
 MonitorConfig child;
 bool passed=LoadMonitorConfigForCurrentProcess(&child,&error)
 && child.agentDllPath==parent.agentDllPath && child.rootStopFlagPath==rootStop
 && child.sessionId.find(L"parent-session_")==0 && child.autoInjectChild
 && !child.enableProcess && child.enableMemory && !child.enableThread && child.enableService
 && !child.enableSecurity && child.enableCrypto && !child.enableCom && child.enableWindow && child.enableGui
 && !child.enableLoader && child.enableClipboard
 && child.clipboardReadAction==ClipboardPolicyAction::Block
 && child.clipboardWriteAction==ClipboardPolicyAction::LogOnly
 && child.rawModuleList==parent.rawModuleList && child.rawDenyList==parent.rawDenyList
 && !IsStopFlagPresent(child);
 for (const auto key : {L"enable_memory",L"enable_thread",L"enable_service",L"enable_security",L"enable_crypto",L"enable_com",L"enable_window",L"enable_gui"})
   WritePrivateProfileStringW(L"monitor",key,nullptr,configPath.c_str());
 MonitorConfig legacy; passed=passed && LoadMonitorConfigForCurrentProcess(&legacy,&error)
   && !legacy.enableMemory && !legacy.enableThread && !legacy.enableService && !legacy.enableSecurity
   && !legacy.enableCrypto && !legacy.enableCom && !legacy.enableWindow && !legacy.enableGui;
 WritePrivateProfileStringW(L"monitor",L"enable_process",L"1",configPath.c_str());
 passed=passed && LoadMonitorConfigForCurrentProcess(&legacy,&error)
   && legacy.enableMemory && legacy.enableThread && legacy.enableService && legacy.enableSecurity
   && legacy.enableCrypto && legacy.enableCom && legacy.enableWindow && !legacy.enableGui;
 touch(rootStop);passed=passed && IsStopFlagPresent(child);
 DeleteFileW(configPath.c_str());DeleteFileW(stopPath.c_str());DeleteFileW(rootStop.c_str());
 if(!passed)return 2;
 printf("PASS: child inherits Unicode configuration, policies, session and root stop\n");
}
'''
with tempfile.TemporaryDirectory(prefix="ksword_child_config_") as temp:
 folder=Path(temp); cpp=folder/"fixture.cpp"
 cpp.write_text('#include <cstdio>\n#define WIN32_LEAN_AND_MEAN\n#include <windows.h>\nstatic UINT WINAPI fixtureWindowsDirectory(LPWSTR out, UINT size) { return GetEnvironmentVariableW(L"KSWORD_FIXTURE_ROOT", out, size); }\n#define GetWindowsDirectoryW fixtureWindowsDirectory\n#include "'+(root/"APIMonitor_x64/core/MonitorConfig.cpp").as_posix()+'"\nnamespace apimon {\n'+writer+'\n}\n'+main,encoding="utf-8")
 subprocess.run(["cl","/nologo","/EHsc","/std:c++17","/utf-8","/I"+str(root/"APIMonitor_x64"),str(cpp),"/Fe:"+str(folder/"fixture.exe"),"/Fo:"+str(folder/"fixture.obj"),"/link","Advapi32.lib"],check=True)
 (folder/"Temp").mkdir()
 environment=os.environ.copy(); environment["KSWORD_FIXTURE_ROOT"]=str(folder)
 subprocess.run([str(folder/"fixture.exe")],env=environment,check=True)
