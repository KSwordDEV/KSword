"""Real Qt INI writers round-trip Unicode and broker metadata through the Agent."""
from pathlib import Path
import os,shutil,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
actions=(root/"Ksword5.1/Ksword5.1/MonitorDock/WinAPIDock.Actions.cpp").read_text(encoding="utf-8-sig")
writer=actions[actions.index("QString WinAPIDock::freezeSessionOptions("):actions.index("void WinAPIDock::appendInternalEvent(")]
pipe=(root/"Ksword5.1/Ksword5.1/MonitorDock/WinAPIDock.Pipe.cpp").read_text(encoding="utf-8-sig")
stream_writer=pipe[pipe.index("        QTextStream stream(&file);"):pipe.index("        configPublished = true;")]
normalizer=actions[actions.index("    QString normalizeRawListForSessionConfig("):actions.index("    // toUtf8StdString")]
clip=(root/"Ksword5.1/Ksword5.1/MiscDock/ClipboardGuard/ClipboardGuardPage.Session.cpp").read_text(encoding="utf-8-sig")
clip_writer=clip[clip.index("    bool ClipboardGuardRuntime::writeSessionConfigForPid("):clip.index("    bool ClipboardGuardRuntime::ensureProcessProtected(")]
code=r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static UINT WINAPI fixtureWindowsDirectory(LPWSTR out, UINT size) {
    return GetEnvironmentVariableW(L"KSWORD_FIXTURE_ROOT", out, size);
}
#define GetWindowsDirectoryW fixtureWindowsDirectory
#include "CONFIG_CPP"
#include "ApiMonitorInjectionBroker.h"
#include "ApiMonitorPlatform.h"
#include <QApplication>
#include <QCheckBox>
#include <QDir>
#include <QFileInfo>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QSaveFile>
#include <QStringConverter>
#include <QTableWidget>
#include <QTextStream>
#include <cstdio>
NORMALIZER
class WinAPIDock{public:
 QString m_currentConfigPath,m_currentPipeName,m_currentStopFlagPath,m_currentSessionId; std::uint32_t m_currentSessionPid=0;
 QLineEdit* m_agentDllPathEdit=nullptr;
 QCheckBox *m_hookFileCheck=nullptr,*m_hookRegistryCheck=nullptr,*m_hookNetworkCheck=nullptr,*m_hookProcessCheck=nullptr,
  *m_hookMemoryCheck=nullptr,*m_hookThreadCheck=nullptr,*m_hookServiceCheck=nullptr,*m_hookSecurityCheck=nullptr,
  *m_hookCryptoCheck=nullptr,*m_hookComCheck=nullptr,*m_hookWindowCheck=nullptr,*m_hookGuiCheck=nullptr,*m_captureCallStackCheck=nullptr,
  *m_hookLoaderCheck=nullptr,*m_hookClipboardCheck=nullptr,*m_autoInjectChildCheck=nullptr,*m_rawFallbackCheck=nullptr,
  *m_rawDefaultDenyListCheck=nullptr,*m_fakeRawFallbackCheck=nullptr;
 QPlainTextEdit *m_rawModuleListEdit=nullptr,*m_rawDenyListEdit=nullptr;QTableWidget* m_fakeRuleTable=nullptr;
 std::unique_ptr<ks::winapi_monitor::InjectionBroker> m_injectionBroker;
 bool validateFakeSuccessRules(QString*)const{return true;}QString fakeSuccessRulesIniText()const{return {};}
 QString defaultRawHookModulesText()const{return QString::fromWCharArray(ks::winapi_monitor::kDefaultRawHookModules);}
 QString freezeSessionOptions()const;
};
struct ClipboardGuardRule{quint32 readAction=1,writeAction=2,enumAction=0;};
class ClipboardGuardRuntime{public: QString m_agentBasePath; bool writeSessionConfigForPid(std::uint32_t,const ClipboardGuardRule&,const QString&,QString*)const;};
WRITER
CLIP_WRITER
int main(int argc,char** argv){
 QApplication app(argc,argv);using namespace ks::winapi_monitor;
 const auto pid=GetCurrentProcessId();QDir().mkpath(QString::fromStdWString(buildSessionDirectory()));
 WinAPIDock dock;dock.m_currentSessionPid=pid;dock.m_currentConfigPath=QString::fromStdWString(buildConfigPathForPid(pid));
 dock.m_currentStopFlagPath=QString::fromStdWString(buildStopFlagPathForPid(pid));
 dock.m_currentPipeName=QString::fromStdWString(buildPipeNameForPid(pid));dock.m_currentSessionId="unicode-broker-test";
 QLineEdit dll;dll.setText(QStringLiteral("C:/测试 目录/APIMonitor_x64.dll"));dock.m_agentDllPathEdit=&dll;
 QCheckBox fileCheck,automatic;fileCheck.setChecked(true);automatic.setChecked(true);dock.m_hookFileCheck=&fileCheck;dock.m_autoInjectChildCheck=&automatic;
 QFile stale(dock.m_currentStopFlagPath);if(!stale.open(QIODevice::WriteOnly))return 1;stale.write("stop");stale.close();
 dock.m_injectionBroker=std::make_unique<InjectionBroker>();std::wstring detail;
 if(!dock.m_injectionBroker->start(pid,dll.text().toStdWString(),dock.m_currentSessionId.toStdWString(),dock.m_currentStopFlagPath.toStdWString(),&detail))return 2;
 QCheckBox memory,thread,service,security,crypto,com,window,gui;
 memory.setChecked(true);service.setChecked(true);crypto.setChecked(true);window.setChecked(true);gui.setChecked(true);
 dock.m_hookMemoryCheck=&memory;dock.m_hookThreadCheck=&thread;dock.m_hookServiceCheck=&service;
 dock.m_hookSecurityCheck=&security;dock.m_hookCryptoCheck=&crypto;dock.m_hookComCheck=&com;dock.m_hookWindowCheck=&window;dock.m_hookGuiCheck=&gui;
 struct Config { unsigned pid; QString sessionId, options; } configInput{pid,dock.m_currentSessionId,dock.freezeSessionOptions()};
 auto& config=configInput; QString selectedAgentPath=dll.text(),stopPath=dock.m_currentStopFlagPath,pauseEventName="pause";
 QString startupError,configPath=dock.m_currentConfigPath; auto endpoint=dock.m_injectionBroker->endpoint(); QSaveFile fileOutput(dock.m_currentConfigPath); auto& file=fileOutput;
 if(!file.open(QIODevice::WriteOnly|QIODevice::Text)) return 3;
 std::wstring controllerSid;if(!currentProcessUserSidString(&controllerSid))return 3;
 STREAM_WRITER
 if(QFile::exists(stopPath)&&!QFile::remove(stopPath))return 3;
 QString error;
 QFile saved(dock.m_currentConfigPath);if(!saved.open(QIODevice::ReadOnly)||saved.read(2)!=QByteArray::fromHex("fffe"))return 4;saved.close();
 apimon::MonitorConfig loaded;if(!apimon::LoadMonitorConfigForCurrentProcess(&loaded,&detail))return 5;
 auto& result=loaded;
 if(result.agentDllPath!=dll.text().toStdWString()||result.injectionEndpoint.pipeName!=endpoint.pipeName
  ||result.injectionEndpoint.token!=endpoint.token||result.injectionEndpoint.hostPid!=endpoint.hostPid
  ||result.injectionEndpoint.hostCreation!=endpoint.hostCreation||!result.autoInjectChild)return 6;
 if(!result.enableMemory||result.enableThread||!result.enableService||result.enableSecurity||!result.enableCrypto||result.enableCom||!result.enableWindow||!result.enableGui)return 10;
 auto bad=endpoint;bad.token=L"stale";
 if(requestChildInjection(bad,pid,endpoint.hostCreation,&detail)||GetLastError()!=ERROR_ACCESS_DENIED)return 7;
 dock.m_injectionBroker.reset();
 ClipboardGuardRuntime page;page.m_agentBasePath=QCoreApplication::applicationDirPath()+"/APIMonitor_x64.dll";ClipboardGuardRule rule;
 if(!page.writeSessionConfigForPid(pid,rule,QStringLiteral("剪贴板 会话"),&error))return 8;
 if(!apimon::LoadMonitorConfigForCurrentProcess(&loaded,&detail)||result.sessionId!=L"剪贴板 会话"
  ||!result.enableClipboard||result.enableFile||result.enableMemory||result.enableThread||result.enableService||result.enableSecurity||result.enableCrypto||result.enableCom||result.enableWindow||result.enableGui||result.clipboardReadAction!=apimon::ClipboardPolicyAction::Block
  ||result.clipboardWriteAction!=apimon::ClipboardPolicyAction::LogOnly||!result.injectionEndpoint.pipeName.empty())return 9;
 QFile::remove(dock.m_currentConfigPath);QFile::remove(dock.m_currentStopFlagPath);
 puts("PASS: actual Qt writers, UTF-16 BOM, Unicode, inherited broker identity, stale-stop startup and clipboard policy");return 0;
}
'''.replace("CONFIG_CPP",(root/"APIMonitor_x64/core/MonitorConfig.cpp").as_posix()).replace("STREAM_WRITER",stream_writer).replace("NORMALIZER",normalizer).replace("CLIP_WRITER",clip_writer).replace("WRITER",writer)
qt=root/".deps/Qt/6.9.3/msvc2022_64"
if not qt.exists():qt=Path("D:/Software/Qt/6.9.3/msvc2022_64")
with tempfile.TemporaryDirectory(prefix="ksword_ui_ini_") as temporary:
 directory=Path(temporary);cpp=directory/"fixture.cpp";cpp.write_text(code,encoding="utf-8")
 shutil.copy2(root/"Ksword5.1/x64/Release/APIMonitor_x64.dll",directory/"APIMonitor_x64.dll")
 includes=["/I"+str(qt/"include"/name) for name in ("","QtCore","QtGui","QtWidgets")]
 libraries=[str(qt/"lib"/name) for name in ("Qt6Core.lib","Qt6Gui.lib","Qt6Widgets.lib")]
 executable=directory/"fixture.exe"
 subprocess.run(["cl","/nologo","/EHsc","/permissive-","/std:c++20","/Zc:__cplusplus","/utf-8","/MD",
  "/I"+str(root/"APIMonitor_x64"),"/I"+str(root/"shared"),*includes,str(cpp),str(root/"shared/ApiMonitorInjectionBroker.cpp"),
  "/Fe:"+str(executable),"/Fo:"+str(directory)+"\\","/link","Advapi32.lib",*libraries],check=True)
 subprocess.run([str(qt/"bin/windeployqt.exe"),"--release","--compiler-runtime","--no-opengl-sw",str(executable)],check=True,stdout=subprocess.DEVNULL)
 environment=os.environ.copy();environment["KSWORD_FIXTURE_ROOT"]=str(directory);environment["QT_QPA_PLATFORM"]="offscreen";environment["QT_QPA_PLATFORM_PLUGIN_PATH"]=str(qt/"plugins/platforms")
 subprocess.run([str(executable)],env=environment,check=True,timeout=30)
