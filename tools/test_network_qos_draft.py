"""Exercise the production QoS draft parser/form as value logic, without widgets or policy actions."""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile
from process_activity_tree_tests import declaration
from native_msvc_test_support import find_msvc_developer_environment, qt_root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qt', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    qt = qt_root(args.qt)
    source = (root / 'Ksword5.1/Ksword5.1/NetworkDock/NetworkQosPage.cpp').read_text(encoding='utf-8-sig')
    fixture = r'''#include "shared/usermode/backend/network/NetworkPolicy.h"
#include <QJsonObject>
#include <QString>
#include <algorithm>
#include <cmath>
#include <cassert>
#include <iostream>
using namespace ks::r3::network;
'''
    fixture += declaration(source, 'bool parseQosDraft(') + '\n'
    fixture += r'''
struct Line { QString content; QString text() const { return content; } };
struct Index { int item = 0; int currentIndex() const { return item; } };
struct Integer { int number = 0; int value() const { return number; } };
struct Real { double number = 0; double value() const { return number; } };
struct Flag { bool enabled = true; bool isChecked() const { return enabled; } };
struct QosFormProbe {
    Line path, source, destination;
    Index scope, protocol;
    Integer dscp{-1}, priority{-1}, precedence{127}, sourceStart, sourceEnd, destStart, destEnd;
    Real rate;
    Flag enabled;
    Line *m_path=&path,*m_source=&source,*m_destination=&destination;
    Index *m_scope=&scope,*m_protocol=&protocol;
    Integer *m_dscp=&dscp,*m_priority=&priority,*m_precedence=&precedence,*m_sourceStart=&sourceStart,*m_sourceEnd=&sourceEnd,*m_destStart=&destStart,*m_destEnd=&destEnd;
    Real *m_rate=&rate; Flag *m_enabled=&enabled;
    QString m_editingId;
    std::uint64_t m_originalRateBytes=0;
    double m_originalRateDisplay=0;
'''
    fixture += declaration(source, 'QosPolicy NetworkQosPage::form()').replace('NetworkQosPage::', '') + '\n};\n'
    fixture += r'''
int main() {
    QJsonObject document{{QStringLiteral("application"),QStringLiteral("C:/Apps/client.exe")},
        {QStringLiteral("outboundBytesPerSecond"),QStringLiteral("21")},
        {QStringLiteral("dscp"),46},{QStringLiteral("enabled"),true},
        {QStringLiteral("sourcePortStart"),4000},{QStringLiteral("sourcePortEnd"),4001}};
    QosPolicy value;
    assert(parseQosDraft(document,value));
    assert(value.outboundBytesPerSecond==21 && value.enabled && value.managed && value.policyId.empty());
    assert(value.scope==PolicyScope::ApplicationImage && value.sourcePortStart==4000 && value.sourcePortEnd==4001);
    auto bad=document; bad[QStringLiteral("application")]=123;
    value.policyId=L"sentinel";
    assert(!parseQosDraft(bad,value) && value.policyId==L"sentinel");
    for(const auto& key : {QStringLiteral("application"),QStringLiteral("outboundBytesPerSecond")}) {
        bad=document;bad.remove(key);assert(!parseQosDraft(bad,value));
    }
    for(const auto& rate : {QStringLiteral("-1"),QStringLiteral(" 21"),QStringLiteral("+21"),QStringLiteral("1.5"),QStringLiteral("1024000000001"),QStringLiteral("18446744073709551616")}) {
        bad=document;bad[QStringLiteral("outboundBytesPerSecond")]=rate;assert(!parseQosDraft(bad,value));
    }
    bad=document;bad[QStringLiteral("enabled")]=QStringLiteral("false");assert(!parseQosDraft(bad,value));
    bad=document;bad[QStringLiteral("sourcePrefix")]=123;assert(!parseQosDraft(bad,value));
    for(const auto& setting : {std::pair{QStringLiteral("dscp"),64.0},std::pair{QStringLiteral("priority8021"),8.0},
        std::pair{QStringLiteral("precedence"),256.0},std::pair{QStringLiteral("protocol"),4.0},std::pair{QStringLiteral("dscp"),1.5}}) {
        bad=document;bad[setting.first]=setting.second;assert(!parseQosDraft(bad,value));
    }
    bad=document;bad[QStringLiteral("sourcePortEnd")]=3999;assert(!parseQosDraft(bad,value));
    bad=document;bad[QStringLiteral("sourcePortEnd")]=0;assert(!parseQosDraft(bad,value));
    bad=document;bad[QStringLiteral("application")]=QString();bad[QStringLiteral("enabled")]=false;
    bad[QStringLiteral("id")]=QStringLiteral("foreign-policy");bad[QStringLiteral("managed")]=false;
    assert(parseQosDraft(bad,value));assert(value.scope==PolicyScope::AllApplications && !value.enabled && value.policyId.empty() && value.managed);
    QosFormProbe form;form.path.content=QStringLiteral("C:/Apps/client.exe");
    for(std::uint64_t bytes=1;bytes<=8192;++bytes) {
        form.m_originalRateBytes=bytes;form.m_originalRateDisplay=static_cast<double>(bytes)/1024.0;
        form.rate.number=form.m_originalRateDisplay;
        form.dscp.number=46;
        assert(form.form().outboundBytesPerSecond==bytes);
        // Native ten-digit KiB presentation preserves each byte; the former
        // three-digit representation demonstrably loses bytes for some rates.
        assert(static_cast<std::uint64_t>(std::llround(QString::number(form.rate.number,'f',10).toDouble()*1024.0))==bytes);
    }
    form.m_originalRateBytes=2305843009213693951ULL;
    form.m_originalRateDisplay=static_cast<double>(form.m_originalRateBytes)/1024.0;
    form.rate.number=form.m_originalRateDisplay;
    assert(form.form().outboundBytesPerSecond==form.m_originalRateBytes); // Editing DSCP preserves a large provider rate exactly.
    form.rate.number=2.0;assert(form.form().outboundBytesPerSecond==2048);
    form.scope.item=1;assert(form.form().applicationPath.empty() && form.form().scope==PolicyScope::AllApplications);
    std::cout<<"NETWORK_QOS_DRAFT=PASS STRICT_FIELDS=1 EXACT_BYTE_FORM=1 GLOBAL_SCOPE_EXPLICIT=1 POLICY_ACTIONS=0\n";
}
'''
    developer = find_msvc_developer_environment()
    (root / 'output').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='network-qos-draft-',dir=root/'output') as folder:
        work=Path(folder);cpp=work/'test.cpp';binary=work/'test.exe';cpp.write_text(fixture,encoding='utf-8')
        command=['cl','/nologo','/std:c++20','/Zc:__cplusplus','/permissive-','/utf-8','/EHsc','/MD','/W4','/WX','/external:W0','/I'+str(root),'/external:I'+str(qt/'include'),'/external:I'+str(qt/'include/QtCore'),str(cpp),'/Fe:'+str(binary),'/link','/LIBPATH:'+str(qt/'lib'),'Qt6Core.lib']
        script=work/'build.cmd';script.write_text('@echo off\ncall "'+str(developer)+'" -arch=x64 -host_arch=x64 >nul\n'+subprocess.list2cmdline(command)+'\nexit /b %errorlevel%\n',encoding='utf-8')
        subprocess.run(['cmd','/d','/c',str(script)],cwd=work,check=True)
        env=dict(os.environ);env['PATH']=str(qt/'bin')+os.pathsep+env.get('PATH','')
        subprocess.run([str(binary)],cwd=work,env=env,check=True)


if __name__=='__main__': main()
