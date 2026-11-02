#include <Windows.h>
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <iostream>
#include <thread>
#include <vector>
#include "MonitorDock/WinAPIDiskArchive.h"
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " << __LINE__ << ": " #x << "\n"; return 1; } } while (false)
int main(int argc,char** argv) {
 QCoreApplication app(argc,argv); QTemporaryDir dir; CHECK(dir.isValid());
 WinAPIDiskArchive writer(dir.path()); CHECK(writer.open());
 std::atomic_bool ok{true}; std::vector<std::thread> threads;
 for (int id=0;id<4;++id) threads.emplace_back([&,id](){ for(int n=0;n<2000;++n) {
  ks::winapi_monitor::ApiMonitorEventPacket packet{}; packet.pid=id+1; packet.tid=n;
  packet.resultKind=static_cast<std::uint32_t>(ks::winapi_monitor::EventResultKind::EntryOnly);
  packet.timestamp100ns=0xfedcba9876543210ULL; wcscpy_s(packet.apiName,L"Fixture");
  if (!writer.append(packet,packet.pid)) ok=false;
 }});
 for(auto& t:threads)t.join(); CHECK(ok); CHECK(writer.accepted()==8000); CHECK(writer.finish()); CHECK(writer.closed()); CHECK(writer.written()==8000);
 QFile file(QDir(dir.path()).filePath("events.jsonl")); CHECK(file.open(QIODevice::ReadOnly));
 for(int n=1;n<=8000;++n) { const auto line=file.readLine(); CHECK(!line.isEmpty());
  const auto object=QJsonDocument::fromJson(line).object(); CHECK(object.value("sequence").toString().toULongLong()==n);
  CHECK(object.value("result").isNull()); CHECK(object.value("time100ns").toString()=="18364758544493064720");
  const auto bytes=QByteArray::fromBase64(object.value("packetBase64").toString().toLatin1()); CHECK(bytes.size()==1000);
  ks::winapi_monitor::ApiMonitorEventPacket packet{}; memcpy(&packet,bytes.constData(),sizeof(packet)); CHECK(packet.pid==object.value("pid").toInt());
 }
 CHECK(file.atEnd()); WinAPIDiskArchive collision(dir.path()); CHECK(!collision.open()); CHECK(collision.failed());
 std::cout << "PASS: 8000 concurrent packets, ordering, exact bytes, unknown return, collision and clean close\n";
}
