"""Run the production main-program broker in an owned x64 console test host."""
import configparser
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from compiler_environment import target_environment
from live_fixture_support import ROOT

HOST_SOURCE=r'''
#include "ApiMonitorInjectionBroker.h"
#include "ApiMonitorInjection.h"
#include "WinApiMonitorProtocol.h"
#include <cstdio>
#include <cstdlib>
int wmain(int argc,wchar_t** argv){
 if(argc!=5)return 1;DWORD pid=wcstoul(argv[1],nullptr,10);std::wstring error;
 ks::winapi_monitor::InjectionBroker broker;
 if(!broker.start(pid,argv[2],argv[3],argv[4],&error)){fwprintf(stderr,L"%s\n",error.c_str());return 2;}
 auto endpoint=broker.endpoint();auto path=ks::winapi_monitor::buildConfigPathForPid(pid);
 WritePrivateProfileStringW(L"monitor",L"injection_broker_pipe",endpoint.pipeName.c_str(),path.c_str());
 WritePrivateProfileStringW(L"monitor",L"injection_broker_token",endpoint.token.c_str(),path.c_str());
 WritePrivateProfileStringW(L"monitor",L"injection_broker_pid",std::to_wstring(endpoint.hostPid).c_str(),path.c_str());
 WritePrivateProfileStringW(L"monitor",L"injection_broker_creation",std::to_wstring(endpoint.hostCreation).c_str(),path.c_str());
 if(!ks::winapi_monitor::injectAgent(pid,argv[2],&error)){fwprintf(stderr,L"%s\n",error.c_str());return 3;}
 puts("READY");fflush(stdout);
 for(int c;(c=getchar())!=EOF;){if(c=='Q')break;}
 auto begin=GetTickCount64();broker.stop();if(GetTickCount64()-begin>3000)return 4;return 0;
}
'''

class InjectionHost:
    def __init__(self):
        self.temporary=tempfile.TemporaryDirectory(prefix="ksword_main_inject_host_")
        directory=Path(self.temporary.name);cpp=directory/"host.cpp";cpp.write_text(HOST_SOURCE,encoding="utf-8")
        self.executable=directory/"host.exe";self.process=None
        environment=target_environment("x64");compiler=shutil.which("cl",path=environment["PATH"])
        subprocess.run([compiler,"/nologo","/EHsc","/std:c++20","/utf-8","/MT","/I"+str(ROOT/"shared"),
                        str(cpp),str(ROOT/"shared/ApiMonitorInjectionBroker.cpp"),"/Fe:"+str(self.executable),
                        "/Fo:"+str(directory)+"\\","/link","Advapi32.lib"],env=environment,check=True)
    def inject(self,pid,agent):
        path=Path(os.environ.get("WINDIR", "C:/Windows"))/"Temp"/"KswordApiMon"/f"config_{pid}.ini"
        config=configparser.ConfigParser(interpolation=None);config.read(path,encoding="utf-16")
        values=config["monitor"]
        self.process=subprocess.Popen([str(self.executable),str(pid),str(agent),values["session_id"],values["stop_flag_path"]],
                                      stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        ready=self.process.stdout.readline().decode().strip()
        if ready!="READY":raise RuntimeError(f"injection host failed: {self.process.stderr.read()!r}")
    def close(self):
        if self.process and self.process.poll() is None:
            self.process.stdin.write(b"Q\n");self.process.stdin.flush()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5);raise
        if self.process:assert self.process.returncode==0,self.process.stderr.read()
        self.temporary.cleanup()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
