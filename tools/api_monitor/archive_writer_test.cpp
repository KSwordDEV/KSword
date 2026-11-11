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
 for(auto& t:threads)t.join(); CHECK(ok); CHECK(writer.accepted()==8000);
 ks::winapi_monitor::ApiMonitorEventPacket metadataPacket{}; metadataPacket.pid=42; metadataPacket.tid=345;
 metadataPacket.timestamp100ns=0xfedcba9876543210ULL; wcscpy_s(metadataPacket.apiName,L"IdentityFixture");
 const auto name=QString::fromUtf8("测试进程.exe"); const std::uint64_t creation=134380539646649023ULL;
 CHECK(writer.append(metadataPacket, 42, true, creation, name));
 CHECK(writer.append(metadataPacket, 43, true, creation, name));
 CHECK(writer.append(metadataPacket, 42, false, creation, name));
 CHECK(writer.append(metadataPacket, 42, true, 0, name));
 CHECK(writer.append(metadataPacket, 42, true, creation, {}));
 CHECK(writer.accepted()==8005); CHECK(writer.finish()); CHECK(writer.closed()); CHECK(writer.written()==8005);
 QFile file(QDir(dir.path()).filePath("events.jsonl")); CHECK(file.open(QIODevice::ReadOnly));
 for(int n=1;n<=8000;++n) { const auto line=file.readLine(); CHECK(!line.isEmpty());
  const auto object=QJsonDocument::fromJson(line).object(); CHECK(object.value("sequence").toString().toULongLong()==n);
  CHECK(object.value("result").isNull()); CHECK(object.value("time100ns").toString()=="18364758544493064720");
  CHECK(!object.contains("processCreation100ns") && !object.contains("processName"));
  const auto bytes=QByteArray::fromBase64(object.value("packetBase64").toString().toLatin1()); CHECK(bytes.size()==1000);
  ks::winapi_monitor::ApiMonitorEventPacket packet{}; memcpy(&packet,bytes.constData(),sizeof(packet)); CHECK(packet.pid==object.value("pid").toInt());
 }
 for (int index=0;index<5;++index) {
  const auto object=QJsonDocument::fromJson(file.readLine()).object();
  const auto bytes=QByteArray::fromBase64(object.value("packetBase64").toString().toLatin1());
  CHECK(bytes.size()==sizeof(metadataPacket)); CHECK(memcmp(bytes.constData(), &metadataPacket, sizeof(metadataPacket))==0);
  const bool identityExpected=index==0 || index==4;
  CHECK(object.contains("processCreation100ns")==identityExpected);
  CHECK(object.contains("processName")==(index==0));
  if (identityExpected) CHECK(object.value("processCreation100ns").toString().toULongLong()==creation);
  if (index==0) CHECK(object.value("processName").toString()==name);
 }
 CHECK(file.atEnd()); WinAPIDiskArchive collision(dir.path()); CHECK(!collision.open()); CHECK(collision.failed());
 std::cout << "PASS: 8000 concurrent packets, verified identity, mismatch and unknown identity, exact bytes, collision and clean close\n";
}
