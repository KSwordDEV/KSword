// The runner injects complete production methods. Only OS/UI endpoints are replaced.
#include <QCoreApplication>
#include <QObject>
#include <QPointer>
#include <QVariant>
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchNavigation.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchContinuation.h"
#include <algorithm>
#include <atomic>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <vector>

using DWORD = std::uint32_t;
using HANDLE = void*;
constexpr DWORD PROCESS_VM_READ=1, PROCESS_VM_WRITE=2, PROCESS_VM_OPERATION=4, PROCESS_QUERY_INFORMATION=8;
constexpr DWORD ERROR_ACCESS_DENIED=5;
constexpr bool FALSE=false;
struct FILETIME { DWORD dwLowDateTime=0, dwHighDateTime=0; };
struct TestProcess { DWORD pid=0; std::uint64_t creation=10; bool alive=true, query=true, rw=true, ro=true; };
static std::map<DWORD, TestProcess> processes;
static int openCalls=0;
static bool driverLoaded=false;
enum class ProbeFault { None, Transport, Missing, Partial, WrongPid, WrongAddress, WrongCount, Copy, Lookup, Exit };
static ProbeFault probeFault=ProbeFault::None;
static int probeCalls=0;
static DWORD lastError=0;
DWORD toDwordPid(DWORD pid) { return pid; }
HANDLE OpenProcess(DWORD access, bool, DWORD pid) {
    ++openCalls;
    auto found=processes.find(pid);
    if(found==processes.end() || !found->second.alive) { lastError=87; return nullptr; }
    auto& p=found->second;
    if((access & PROCESS_VM_WRITE) ? !p.rw : !p.ro) { lastError=5; return nullptr; }
    return &p;
}
DWORD GetLastError() { return lastError; }
void CloseHandle(HANDLE) {}
bool GetProcessTimes(HANDLE h, FILETIME* created, FILETIME*, FILETIME*, FILETIME*) {
    auto* p=static_cast<TestProcess*>(h);
    if(!p || !p->query) return false;
    created->dwLowDateTime=static_cast<DWORD>(p->creation);
    created->dwHighDateTime=static_cast<DWORD>(p->creation >> 32);
    return true;
}
namespace ks::ui {
struct AsyncOperationToken { bool isCanceled() const { return false; } };
class AsyncOperation : public QObject {
public:
    explicit AsyncOperation(QObject* parent) : QObject(parent) {}
    std::function<void()> run;
    template<class Request,class Result,class Worker,class Apply,class Failure>
    void submit(Request request,Worker worker,Apply apply,Failure failure) {
        run=[request,worker,apply,failure] { try { const Result r=worker(request,AsyncOperationToken{}); apply(r,1); } catch(...) { failure(std::current_exception()); } };
    }
};
struct AnchorInfo { bool identityWeak=true, targetGone=false; std::uint64_t createTime100ns=0; void* handle=nullptr; };
AnchorInfo AcquireAnchorForPid(DWORD pid) {
    const auto it=processes.find(pid);
    if(it==processes.end() || !it->second.alive) return {true,true,0,nullptr};
    if(!it->second.query) return {};
    return {false,false,it->second.creation,&it->second};
}
void ReleaseAnchorHandle(void*) {}
std::optional<bool> QueryAnchorAlive(void* h) { return h ? std::optional<bool>(static_cast<TestProcess*>(h)->alive) : std::nullopt; }
template<class T> bool requestAdministratorRestartForFeature(T*, const QString&) { return false; }
}
namespace ks::i18n { QString packedSourceText(const QString& text) { return text; } }
namespace ksword::ark {
struct VirtualMemoryReadResult {
    struct Io { bool ok=true; DWORD win32Error=0; } io;
    std::uint32_t readStatus=0, bytesRead=1, processId=0, requestedBytes=1;
    std::uint64_t requestedBaseAddress=0;
    long copyStatus=0, lookupStatus=0;
    std::vector<std::uint8_t> data{0x4D};
};
struct DriverHandle { bool isValid() const { return driverLoaded; } };
struct DriverClient {
    DriverHandle openSilently() const { return {}; }
    VirtualMemoryReadResult readVirtualMemory(DWORD pid,std::uint64_t address,DWORD length,DWORD flags,DriverHandle* existing) const {
        if(!existing || !existing->isValid()) throw std::runtime_error("probe requires a silent device lease");
        if(length!=1 || flags!=0) throw std::runtime_error("probe must not request zero fill");
        ++probeCalls;
        VirtualMemoryReadResult r; r.processId=pid; r.requestedBaseAddress=address;
        switch(probeFault) {
        case ProbeFault::Transport: r.io.ok=false; break;
        case ProbeFault::Missing: r.data.clear(); break;
        case ProbeFault::Partial: r.readStatus=2; break;
        case ProbeFault::WrongPid: ++r.processId; break;
        case ProbeFault::WrongAddress: ++r.requestedBaseAddress; break;
        case ProbeFault::WrongCount: r.bytesRead=0; break;
        case ProbeFault::Copy: r.copyStatus=-1; break;
        case ProbeFault::Lookup: r.lookupStatus=-1; break;
        case ProbeFault::Exit: processes.at(pid).alive=false; break;
        default: break;
        }
        return r;
    }
};
}
constexpr std::uint32_t KSWORD_ARK_MEMORY_READ_STATUS_OK=0;
struct kLogEvent {};
struct Log { template<class T> Log& operator<<(const T&) { return *this; } };
static Log info, warn, err;
static int eol=0;
static const char* kRegionRefreshFromAttachProperty="fixture_attach";
static std::vector<QString> warnings;
struct QMessageBox {
    template<class T> static void warning(T, const QString&, const QString& text) { warnings.push_back(text); }
    template<class T> static void information(T, const QString&, const QString&) {}
};
bool processHandleMatchesModuleTarget(HANDLE h, DWORD pid, std::uint64_t creation) {
    const auto* p=static_cast<TestProcess*>(h);
    return p && p->pid==pid && p->creation==creation && p->query && p->alive;
}
class MemoryDock : public QObject {
public:
    struct ModuleEntry { std::uint64_t baseAddress=0, sizeBytes=0; };
    struct ProcessEntry { DWORD pid=0; QString processName; };
    using ProcessOpenFailure=std::function<void(DWORD)>;
    std::shared_ptr<const std::vector<ModuleEntry>> m_moduleCache=std::make_shared<std::vector<ModuleEntry>>();
    std::shared_ptr<const std::vector<ProcessEntry>> m_processCache=std::make_shared<std::vector<ProcessEntry>>();
    DWORD m_moduleCachePid=0, m_attachedPid=0;
    std::uint64_t m_moduleCacheCreateTime=0, m_processMemoryNavigationGeneration=0;
    std::atomic<std::uint64_t> m_processAttachmentGeneration{1};
    HANDLE m_attachedProcessHandle=nullptr;
    QString m_attachedProcessName;
    bool m_canReadWriteMemory=false, m_workbenchProcessChangePending=false;
    ks::ui::LeaveEntryStatus leaveStatus=ks::ui::LeaveEntryStatus::Completed;
    ks::ui::LeaveCompletion continuation;
    std::vector<ks::ui::NavRequest> navigations;
    int detaches=0;
    ks::ui::AsyncOperation* m_moduleNavigationOperation=nullptr;
    void jumpToModuleBase(std::uint64_t);
    void probeModuleDriverJump(const ks::ui::NavRequest&,std::uint64_t);
    ks::ui::LeaveEntryStatus attachToProcess(DWORD, const QString&, bool, ks::ui::LeaveCompletion={}, ProcessOpenFailure={});
    bool attachToProcessAfterLeave(DWORD, const QString&, bool, std::uint64_t, ProcessOpenFailure={});
    ks::ui::LeaveEntryStatus workbenchAllowsProcessChange(ks::ui::LeaveCompletion c) {
        if(leaveStatus==ks::ui::LeaveEntryStatus::Pending) continuation=std::move(c);
        return leaveStatus;
    }
    void detachProcess() {
        ++detaches; ++m_processAttachmentGeneration;
        m_attachedPid=0; m_attachedProcessHandle=nullptr;
        m_moduleCache=std::make_shared<std::vector<ModuleEntry>>();
    }
    void updateStatusBarText() {}
    void syncTamperDetectionTargets() {}
    void workbenchOnAttached() {}
    void refreshModuleListForPid(DWORD) {}
    void refreshMemoryRegionList(bool) {}
    bool navigateWorkbench(const ks::ui::NavRequest& request) { navigations.push_back(request); return true; }
};
namespace ks::process {
struct ProcessModuleRecord {
    std::uint64_t moduleBaseAddress=0;
    std::uint32_t moduleSizeBytes=0, representativeThreadId=0;
    std::uint64_t representativeThreadCreationTime100ns=0;
    std::string threadIdText;
};
}
#include "module_navigation_production.inc"

static int checks=0, failures=0;
#define CHECK(...) do { ++checks; if(!(__VA_ARGS__)) { ++failures; std::cerr<<"FAIL line "<<__LINE__<<'\n'; } } while(false)
struct Fixture {
    MemoryDock dock;
    Fixture() {
        processes.clear(); processes.emplace(77,TestProcess{77});
        openCalls=0; probeCalls=0; warnings.clear(); driverLoaded=false; probeFault=ProbeFault::None;
        dock.m_moduleCachePid=77; dock.m_moduleCacheCreateTime=10;
        dock.m_moduleCache=std::make_shared<std::vector<MemoryDock::ModuleEntry>>(
            std::initializer_list<MemoryDock::ModuleEntry>{{0x70001000,0x3000}});
        dock.m_processCache=std::make_shared<std::vector<MemoryDock::ProcessEntry>>(
            std::initializer_list<MemoryDock::ProcessEntry>{{77,QStringLiteral("fixture.exe")}});
    }
    void expect(ksword::memwb::Channel channel) {
        if(channel==ksword::memwb::Channel::StandardDriver) {
            CHECK(dock.navigations.empty() && probeCalls==0);
            CHECK(dock.m_moduleNavigationOperation && dock.m_moduleNavigationOperation->run);
            if(dock.m_moduleNavigationOperation) dock.m_moduleNavigationOperation->run();
        }
        CHECK(dock.navigations.size()==1);
        if(dock.navigations.empty()) return;
        const auto& n=dock.navigations.front();
        CHECK(n.scope==ksword::memwb::Scope::ProcessVirtual && n.address==0x70001000);
        CHECK(n.channel==channel && n.origin==ks::ui::NavOrigin::ModuleTable);
        CHECK(channel==ksword::memwb::Channel::UserMode ? n.pid==0 : (n.pid==77 && n.createTime==10));
    }
};
static void NavigationTests() {
    using Status=ks::ui::LeaveEntryStatus;
    using Channel=ksword::memwb::Channel;
    { Fixture f; f.dock.jumpToModuleBase(0x70001000); f.expect(Channel::UserMode); CHECK(openCalls==1 && f.dock.m_attachedPid==77 && warnings.empty()); }
    { Fixture f; processes.at(77).rw=false; f.dock.jumpToModuleBase(0x70001000); f.expect(Channel::UserMode); CHECK(openCalls==2 && !f.dock.m_canReadWriteMemory); }
    { Fixture f; processes.at(77).rw=processes.at(77).ro=false; driverLoaded=true; f.dock.jumpToModuleBase(0x70001000); f.expect(Channel::StandardDriver); CHECK(openCalls==2 && f.dock.m_attachedPid==0 && warnings.empty()); }
    { Fixture f; processes.at(77).rw=processes.at(77).ro=false; f.dock.jumpToModuleBase(0x70001000); CHECK(f.dock.navigations.empty() && warnings.size()==1); }
    for(auto rejected : {Status::Rejected,Status::Busy}) {
        Fixture f; driverLoaded=true; processes.at(77).rw=processes.at(77).ro=false;
        f.dock.leaveStatus=rejected; f.dock.jumpToModuleBase(0x70001000);
        CHECK(f.dock.navigations.empty() && openCalls==0 && f.dock.detaches==0);
    }
    for(bool allowed : {false,true}) for(bool openable : {false,true}) {
        Fixture f; driverLoaded=true; processes.at(77).rw=processes.at(77).ro=openable;
        f.dock.leaveStatus=Status::Pending; f.dock.jumpToModuleBase(0x70001000);
        CHECK(openCalls==0 && f.dock.navigations.empty());
        f.dock.continuation(allowed);
        if(allowed) f.expect(openable ? Channel::UserMode : Channel::StandardDriver);
        else CHECK(openCalls==0 && f.dock.navigations.empty());
    }
    { Fixture f; f.dock.leaveStatus=Status::Pending; f.dock.jumpToModuleBase(0x70001000); processes.at(77).alive=false; f.dock.continuation(true); CHECK(openCalls==0 && f.dock.navigations.empty()); }
    { Fixture f; f.dock.leaveStatus=Status::Pending; f.dock.jumpToModuleBase(0x70001000); processes.at(77).creation=11; f.dock.continuation(true); CHECK(f.dock.navigations.empty()); }
    { Fixture f; f.dock.leaveStatus=Status::Pending; f.dock.jumpToModuleBase(0x70001000); ++f.dock.m_processAttachmentGeneration; f.dock.continuation(true); CHECK(openCalls==0 && f.dock.navigations.empty()); }
    { Fixture f; f.dock.leaveStatus=Status::Pending; f.dock.jumpToModuleBase(0x70001000); ++f.dock.m_processMemoryNavigationGeneration; f.dock.continuation(true); CHECK(f.dock.navigations.empty()); }
    { Fixture f; f.dock.m_attachedPid=77; f.dock.m_attachedProcessHandle=&processes.at(77); f.dock.jumpToModuleBase(0x70001000); f.expect(Channel::UserMode); CHECK(openCalls==0 && f.dock.detaches==0); }
    for(bool weak : {false,true}) { Fixture f; if(weak) processes.at(77).query=false; else f.dock.m_moduleCacheCreateTime=11; f.dock.jumpToModuleBase(0x70001000); CHECK(openCalls==0 && f.dock.navigations.empty() && warnings.size()==1); }
    { Fixture f; f.dock.jumpToModuleBase(0xBAD); CHECK(openCalls==0 && f.dock.navigations.empty()); }
    { Fixture f; auto* dock=new MemoryDock; dock->m_moduleCache=f.dock.m_moduleCache; dock->m_moduleCachePid=77; dock->m_moduleCacheCreateTime=10; dock->leaveStatus=Status::Pending; dock->jumpToModuleBase(0x70001000); auto resume=dock->continuation; delete dock; resume(true); CHECK(openCalls==0); }
    for(auto fault : {ProbeFault::Transport,ProbeFault::Missing,ProbeFault::Partial,ProbeFault::WrongPid,
        ProbeFault::WrongAddress,ProbeFault::WrongCount,ProbeFault::Copy,ProbeFault::Lookup,ProbeFault::Exit}) {
        Fixture f; driverLoaded=true; probeFault=fault; processes.at(77).rw=processes.at(77).ro=false;
        f.dock.jumpToModuleBase(0x70001000);
        CHECK(f.dock.navigations.empty() && probeCalls==0);
        f.dock.m_moduleNavigationOperation->run();
        CHECK(f.dock.navigations.empty() && warnings.size()==1 && probeCalls==1);
    }
    for(bool changedAttachment : {false,true}) {
        Fixture f; driverLoaded=true; processes.at(77).rw=processes.at(77).ro=false;
        f.dock.jumpToModuleBase(0x70001000);
        if(changedAttachment) ++f.dock.m_processAttachmentGeneration; else ++f.dock.m_processMemoryNavigationGeneration;
        f.dock.m_moduleNavigationOperation->run();
        CHECK(f.dock.navigations.empty() && warnings.empty());
    }
    { Fixture f; driverLoaded=true; processes.at(77).rw=processes.at(77).ro=false;
      f.dock.jumpToModuleBase(0x70001000); driverLoaded=false; f.dock.m_moduleNavigationOperation->run();
      CHECK(f.dock.navigations.empty() && warnings.size()==1 && probeCalls==0); }
}
static void ThreadTests() {
    using Module=ks::process::ProcessModuleRecord;
    std::vector<Module> modules(3);
    modules[0].moduleBaseAddress=0x1000; modules[0].moduleSizeBytes=0x100;
    modules[1].moduleBaseAddress=0x1100; modules[1].moduleSizeBytes=0x100;
    modules[2].moduleBaseAddress=0x9000; modules[2].moduleSizeBytes=0x100;
    const std::vector<ModuleThreadStart> starts{{1,10,0x1000},{2,20,0x10FF},{3,30,0x1100},{4,40,0x1200},{5,0,0x1001},{0,50,0x1002}};
    AssignModuleThreads(modules,starts,true);
    CHECK(modules[0].threadIdText=="1, 2" && modules[1].threadIdText=="3" && modules[2].threadIdText=="-");
    CHECK(modules[0].representativeThreadId==1 && modules[0].representativeThreadCreationTime100ns==10);
    CHECK(modules[1].representativeThreadId==3 && modules[2].representativeThreadId==0);
    AssignModuleThreads(modules,starts,false);
    CHECK(modules[0].threadIdText=="1, 2 (?)" && modules[2].threadIdText=="?");
    AssignModuleThreads(modules,{},true);
    CHECK(modules[0].threadIdText=="-" && modules[0].representativeThreadId==0 && modules[0].representativeThreadCreationTime100ns==0);
    modules[0].moduleBaseAddress=UINT64_MAX-2; modules[0].moduleSizeBytes=10;
    AssignModuleThreads(modules,{{9,100,UINT64_MAX}},true);
    CHECK(modules[0].representativeThreadId==0);
    modules[0].moduleBaseAddress=0; modules[1].moduleSizeBytes=0;
    AssignModuleThreads(modules,starts,true);
    CHECK(modules[0].representativeThreadId==0 && modules[1].representativeThreadId==0);
}
int main(int argc,char** argv) {
    QCoreApplication app(argc,argv);
    NavigationTests(); ThreadTests();
    std::cout<<"Module navigation/thread tests: "<<checks<<" checks, "<<failures<<" failures\n";
    return failures ? 1 : 0;
}
