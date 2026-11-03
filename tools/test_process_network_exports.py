"""Native tests for actual process packet export and bounded value models; no capture or network policies."""
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
    source = (root / 'Ksword5.1/Ksword5.1/ProcessDock/ProcessNetworkController.cpp').read_text(encoding='utf-8-sig')
    page = (root / 'Ksword5.1/Ksword5.1/ProcessDock/ProcessNetworkPage.cpp').read_text(encoding='utf-8-sig')
    fixture = r'''#include "Ksword5.1/Ksword5.1/ProcessDock/ProcessNetworkController.h"
#include <QAbstractTableModel>
#include <QCoreApplication>
#include <QDataStream>
#include <QDateTime>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QTemporaryDir>
#include <cassert>
#include <deque>
#include <map>
#include <iostream>
namespace ks::network {
'''
    fixture += declaration(source, 'bool rawIpPacket(') + '\n'
    fixture += declaration(source, 'ProcessNetworkResult ProcessNetworkController::exportPcap(') + '\n'
    fixture += declaration(source, 'ProcessNetworkResult ProcessNetworkController::exportDump(') + '\n}\n'
    fixture += '''namespace hub_test {
using ks::network::PacketRecord;
using ks::network::PacketDirection;
struct Handle { bool value = true; };
bool alive(bool value) { return value; }
class FakeTrafficMonitorService {
public:
    void SetPacketCallback(std::function<void(const PacketRecord&)> value) { callback=std::move(value); }
    void SetStatusCallback(std::function<void(const std::string&)> value) { status=std::move(value); }
    bool StartCapture() { if(!running) ++starts; running=true; return true; }
    void StopCapture() { running=false; }
    void RequestStopCapture() { running=false; ++stops; }
    std::function<void(const PacketRecord&)> callback;
    std::function<void(const std::string&)> status;
    unsigned starts=0,stops=0; bool running=false;
};
'''
    fixture += declaration(source, 'struct Subscription {') + ';\n'
    fixture += declaration(source, 'class CaptureHub final').replace('TrafficMonitorService service;', 'FakeTrafficMonitorService service;') + ';\n}\n'
    fixture += '''using Packet = ks::network::PacketRecord;
QString T(const char* source) { return QString::fromUtf8(source); }
'''
    fixture += declaration(page, 'QString endpointText(') + '\n'
    fixture += declaration(page, 'QString endpoint(const std::string&') + '\n'
    fixture += declaration(page, 'QString direction(') + '\n'
    fixture += declaration(page, 'class PacketModel final') + ';\n'
    fixture += r'''
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    assert(argc==2);
    QTemporaryDir work(QString::fromLocal8Bit(argv[1])+QStringLiteral("/exports-XXXXXX"));
    assert(work.isValid());
    Packet ipv4; ipv4.processId=42; ipv4.sequenceId=7; ipv4.captureTimestampMs=1700000000123ULL;
    ipv4.packetBytes.assign(20, 0); ipv4.packetBytes[0]=0x45; ipv4.packetBytes[3]=60;
    ipv4.packetBytesTruncated=true; ipv4.totalPacketSize=60;
    Packet ipv6; ipv6.packetBytes.assign(40, 0); ipv6.packetBytes[0]=0x60;
    ipv6.totalPacketSize=40; ipv6.captureTimestampMs=1700000000456ULL;
    Packet metadata; metadata.wfpAleEventNoPayload=true; metadata.totalPacketSize=500;
    Packet empty; empty.totalPacketSize=100;
    Packet invalid; invalid.packetBytes.assign(14,0); invalid.totalPacketSize=14;
    const std::vector<Packet> packets{ipv4,metadata,empty,ipv6,invalid};
    const auto pcap=work.filePath(QStringLiteral("capture.pcap"));
    const auto saved=ks::network::ProcessNetworkController::exportPcap(pcap,packets);
    if(!saved.success) std::cerr << "EXPORT_ERROR=" << saved.message.toStdString() << '\n';
    assert(saved.success);
    QFile file(pcap); assert(file.open(QIODevice::ReadOnly));
    QDataStream stream(&file); stream.setByteOrder(QDataStream::LittleEndian);
    quint32 magic,zero1,zero2,snaplen,linktype; quint16 major,minor;
    stream>>magic>>major>>minor>>zero1>>zero2>>snaplen>>linktype;
    assert(magic==0xa1b2c3d4U && major==2 && minor==4 && zero1==0 && zero2==0 && snaplen==65535 && linktype==101);
    const auto record=[&](const Packet& expected){
        quint32 secs,micros,captured,wire; stream>>secs>>micros>>captured>>wire;
        assert(secs==expected.captureTimestampMs/1000 && micros==(expected.captureTimestampMs%1000)*1000);
        assert(captured==expected.packetBytes.size() && wire==expected.totalPacketSize);
        QByteArray bytes(captured,0); assert(stream.readRawData(bytes.data(),static_cast<int>(captured))==static_cast<int>(captured));
        assert(bytes==QByteArray(reinterpret_cast<const char*>(expected.packetBytes.data()),static_cast<qsizetype>(expected.packetBytes.size())));
    };
    record(ipv4); record(ipv6); assert(file.atEnd());
    const auto dump=work.filePath(QStringLiteral("capture.jsonl"));
    assert(ks::network::ProcessNetworkController::exportDump(dump,packets).success);
    QFile json(dump); assert(json.open(QIODevice::ReadOnly));
    const auto first=QJsonDocument::fromJson(json.readLine()).object();
    assert(first.value(QStringLiteral("hex")).toString().startsWith(QStringLiteral("45")));
    assert(first.value(QStringLiteral("truncated")).toBool());
    assert(first.value(QStringLiteral("pid")).toInt()==42);
    const auto meta=QJsonDocument::fromJson(json.readLine()).object();
    assert(meta.value(QStringLiteral("metadataOnly")).toBool());
    assert(meta.value(QStringLiteral("hex")).toString().isEmpty());
    // Ring eviction must retain canonical packet identity and bytes. No fake
    // rows are manufactured to fill a missing payload or capture gap.
    PacketModel model(nullptr);
    std::vector<Packet> rows(2105,ipv4);
    for(std::size_t i=0;i<rows.size();++i) rows[i].sequenceId=i+1;
    model.append(std::move(rows));
    assert(model.rowCount()==2000 && model.evicted==105 && model.rows.front().sequenceId==106);
    std::vector<Packet> more(256,ipv6);
    model.append(std::move(more));
    assert(model.rowCount()==2000 && model.evicted==361 && model.rows.front().sequenceId==362);
    assert(model.rows.back().packetBytes==ipv6.packetBytes);
    assert(endpointText(QStringLiteral("::1"),443)==QStringLiteral("[::1]:443"));
    assert(endpointText(QStringLiteral("127.0.0.1"),80)==QStringLiteral("127.0.0.1:80"));
    {
        hub_test::CaptureHub hub;
        auto firstSub=std::make_shared<hub_test::Subscription>(); firstSub->pid=7; firstSub->process=std::make_shared<hub_test::Handle>();
        auto second=std::make_shared<hub_test::Subscription>(); second->pid=8; second->process=std::make_shared<hub_test::Handle>();
        const auto firstLease=hub.subscribe(firstSub); const auto secondLease=hub.subscribe(second);
        assert(hub.service.starts==1); // Multiple details share one capture.
        Packet event; event.processId=7; event.direction=ks::network::PacketDirection::Outbound; event.totalPacketSize=10;
        for(unsigned i=0;i<1500;++i) hub.service.callback(event);
        assert(firstSub->pending.size()==1024 && firstSub->dropped==476 && firstSub->tx==15000);
        assert(second->pending.empty());
        firstSub->process->value=false; hub.service.callback(event);
        assert(!firstSub->active.load() && firstSub->tx==15000); // Dead instance cannot consume reused-PID traffic.
        hub.unsubscribe(firstLease); assert(hub.service.stops==0);
        event.processId=8; hub.service.callback(event); assert(second->pending.size()==1);
        hub.unsubscribe(secondLease); assert(hub.service.stops==1);
    }
    std::cout<<"PROCESS_NETWORK_EXPORTS=PASS PCAP_RAW=1 NO_SYNTHETIC_PACKETS=1 BOUNDED_MODEL=1 NETWORK_IO=0\n";
}
'''
    developer = find_msvc_developer_environment()
    (root / 'output').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='process-network-export-', dir=root / 'output') as folder:
        work = Path(folder); cpp = work / 'test.cpp'; binary = work / 'test.exe'; cpp.write_text(fixture,encoding='utf-8')
        command=['cl','/nologo','/std:c++20','/Zc:__cplusplus','/permissive-','/utf-8','/EHsc','/MD','/W4','/WX','/DNOMINMAX','/DWIN32_LEAN_AND_MEAN','/external:W0','/I'+str(root)]
        command += ['/external:I'+str(qt/'include'/name) for name in ('','QtCore','QtGui','QtWidgets')]
        command += [str(cpp),'/Fe:'+str(binary),'/link','/LIBPATH:'+str(qt/'lib'),'Qt6Core.lib','Qt6Gui.lib']
        script=work/'build.cmd'; script.write_text('@echo off\ncall "'+str(developer)+'" -arch=x64 -host_arch=x64 >nul\n'+subprocess.list2cmdline(command)+'\nexit /b %errorlevel%\n',encoding='utf-8')
        subprocess.run(['cmd','/d','/c',str(script)],cwd=work,check=True)
        env=dict(os.environ);env['PATH']=str(qt/'bin')+os.pathsep+env.get('PATH','')
        subprocess.run([str(binary),str(work)],cwd=work,env=env,check=True)


if __name__=='__main__':
    main()
