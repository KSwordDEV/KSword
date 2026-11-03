"""Exercise production numeric address parsing and full packet-filter matching."""
from pathlib import Path
import subprocess
import argparse
from process_activity_tree_tests import declaration
from native_msvc_test_support import find_msvc_developer_environment,qt_root

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'Ksword5.1/Ksword5.1'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--qt',type=Path);parser.add_argument('--compile-page',action='store_true');args=parser.parse_args()
    qt=qt_root(args.qt);developer=find_msvc_developer_environment();work=ROOT/'.codex-build-logs/network-filter-tests';work.mkdir(parents=True,exist_ok=True)
    source=(APP/'NetworkDock/NetworkDock.FilterAndProcessActions.cpp').read_text(encoding='utf-8-sig')
    header=(APP/'NetworkDock/NetworkDock.h').read_text(encoding='utf-8-sig')
    helpers=(APP/'NetworkDock/NetworkDock.InternalHelpers.cpp').read_text(encoding='utf-8-sig')
    fixture=work/'fixture.cpp'
    prefix='#include "'+(APP/'ksword/network/network_format_tools.h').as_posix()+'"\n#include "'+(ROOT/'shared/usermode/backend/network/NetworkPolicy.h').as_posix()+'"\n#include <QString>\n#include <algorithm>\n'
    prefix+='QString toQString(const std::string& value){return QString::fromUtf8(value.data(),static_cast<qsizetype>(value.size()));}\n'
    prefix+=declaration(helpers,'    bool tryParseIpv4Text(')+'\n'+declaration(helpers,'    bool tryParseIpv4RangeText(')+'\n'
    prefix+=declaration(source,'    bool tryParseMonitorAddressText(')+'\n'+declaration(source,'    bool monitorAddressMatches(')+'\n'
    prefix+='struct NetworkDock { using UInt32Range=std::pair<std::uint32_t,std::uint32_t>;using UInt16Range=std::pair<std::uint16_t,std::uint16_t>;'+declaration(header,'    struct MonitorFilterRuleGroupCompiled')+';static bool packetMatchesMonitorFilterGroup(const ks::network::PacketRecord&,const MonitorFilterRuleGroupCompiled&);};\n'
    prefix+=declaration(source,'bool NetworkDock::packetMatchesMonitorFilterGroup(')+'\n'
    fixture.write_text(prefix+(ROOT/'tools/network_monitor_filter_tests.cpp').read_text(encoding='utf-8'),encoding='utf-8')
    executable=work/'network_monitor_filter_tests.exe'
    command=['cl','/nologo','/std:c++20','/Zc:__cplusplus','/W4','/WX','/utf-8','/EHsc','/MD','/permissive-','/DNOMINMAX','/DWIN32_LEAN_AND_MEAN','/DUNICODE','/D_UNICODE','/external:W0',
             '/external:I'+str(qt/'include'),'/external:I'+str(qt/'include/QtCore'),str(fixture),str(APP/'ksword/network/network_format_tools.cpp'),
             str(ROOT/'shared/usermode/backend/network/NetworkPolicy.cpp'),str(ROOT/'shared/usermode/backend/network/Firewall.cpp'),str(ROOT/'shared/usermode/backend/network/NetworkSupport.cpp'),
             '/Fe:'+str(executable),'/Fo:'+str(work)+'\\','/link','/LIBPATH:'+str(qt/'lib'),'Qt6Core.lib']
    build=work/'build.cmd';build.write_text('@echo off\ncall "'+str(developer)+'" -arch=x64 -host_arch=x64 >nul\nif errorlevel 1 exit /b 1\n'+subprocess.list2cmdline(command)+'\nexit /b %errorlevel%\n',encoding='utf-8')
    subprocess.run(['cmd','/d','/c',str(build)],cwd=work,check=True)
    import os
    environment=dict(os.environ);environment['PATH']=str(qt/'bin')+os.pathsep+environment.get('PATH','')
    subprocess.run([str(executable)],cwd=work,env=environment,check=True)
    assert source.count('tryParseMonitorAddressText(')==4
    assert 'rootObject.insert(QString::fromLatin1(kMonitorFilterJsonVersionKey), 1)' in source
    print('NETWORK_MONITOR_FILTER_WIRING=PASS input_compile_load_schema_v1')
    if args.compile_page:
        include_dirs=[qt/'include',*(item for item in (qt/'include').iterdir() if item.is_dir())]
        page_command=['/nologo','/c','/std:c++20','/Zc:__cplusplus','/W4','/WX','/utf-8','/EHsc','/MD','/permissive-',
                      '/DNOMINMAX','/DWIN32_LEAN_AND_MEAN','/DUNICODE','/D_UNICODE','/DQT_NO_DEBUG','/external:W0',
                      *('/external:I'+str(item) for item in include_dirs),'/I'+str(APP),'/I'+str(ROOT/'third_party/zstd'),'/I'+str(ROOT/'third_party/zydis'),
                      str(APP/'NetworkDock/NetworkDock.FilterAndProcessActions.cpp'),'/Fo:'+str(work/'NetworkDock.FilterAndProcessActions.obj')]
        response=work/'compile-page.rsp';response.write_text(subprocess.list2cmdline(page_command),encoding='utf-8-sig')
        build.write_text('@echo off\ncall "'+str(developer)+'" -arch=x64 -host_arch=x64 >nul\nif errorlevel 1 exit /b 1\ncl @"'+str(response)+'"\nexit /b %errorlevel%\n',encoding='utf-8')
        subprocess.run(['cmd','/d','/c',str(build)],cwd=work,check=True)
        print('NETWORK_MONITOR_FILTER_PAGE_COMPILE=PASS HOSTX64=1 W4_WX=1')

if __name__=='__main__':main()
