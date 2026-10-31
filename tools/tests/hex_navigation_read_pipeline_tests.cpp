// Reproduce the real WorkbenchHexPane::jumpTo selection/reveal sequence with
// the production target, page provider, scheduler, ReadPool and page reader.
// The Win32 case only reads this test process's own VirtualAlloc fixture.
#include "HexCanvas.h"
#include "WorkbenchPageProvider.h"
#include "WorkbenchServices.h"
#include "WorkbenchTarget.h"
#include "../../Ksword5.1/Ksword5.1/MemoryDock/WorkbenchUserModeRead.h"
#include <Windows.h>
#include <QApplication>
#include <QElapsedTimer>
#include <QFontDatabase>
#include <QThread>
#include <atomic>
#include <cstdio>
#include <functional>
#include <memory>
#include <vector>

using namespace ks::ui;
using namespace ksword::memwb;
int checks=0, failures=0;
void check(bool ok,const char* text) {++checks;if(!ok){++failures;std::printf("FAIL: %s\n",text);}}
bool pump(const std::function<bool()>& predicate,int timeout=2500) {
    QElapsedTimer timer;timer.start();
    while(timer.elapsed()<timeout) {QApplication::processEvents();if(predicate())return true;QThread::msleep(1);}
    return predicate();
}
class Services final : public IWorkbenchServices {
public:
    ModuleEnumResult enumerateProcessModules(std::uint32_t,std::uint64_t) override {return {true,{},{}};}
    ModuleEnumResult enumerateKernelModules() override {return {true,{},{}};}
    std::vector<ProcessCandidate> processCandidates() override {return {};}
    PointerReadResult readPointer(const MemoryTargetSession&,std::uint64_t,std::uint32_t) override {return {};}
    std::uint64_t ddmaGeneration() override {return 0;}
};
struct State {
    std::atomic<unsigned> calls=0,targetReads=0;
    std::uint64_t base=0;
    bool real=false;
    std::atomic<bool> block=false,blocked=false,release=false;
};
class Port final : public IMemoryIoPort {
public:
    explicit Port(std::shared_ptr<State> state):state_(std::move(state)){}
    IoLimits Limits(const MemoryTargetSession&) const override {return {4096,0};}
    IoReadResult Read(const MemoryTargetSession& session,std::uint64_t address,std::uint64_t length) override {
        ++state_->calls;
        if(address<=state_->base && state_->base-address<length) {
            ++state_->targetReads;
            if(state_->block) {
                state_->blocked=true;
                QElapsedTimer timeout;timeout.start();
                while(!state_->release && timeout.elapsed()<4000) QThread::msleep(1);
            }
        }
        IoReadResult result;
        if(session.pid!=GetCurrentProcessId()) {result.failure="wrong process";return result;}
        if(state_->real) {
            return ksword::memwb_ports_detail::ReadUserModeVirtual(session.pid,address,length);
        }
        if(address<state_->base || address-state_->base>=0x10000 || length>0x10000-(address-state_->base)) {
            result.status=IoReadStatus::Unreadable;return result;
        }
        result.status=IoReadStatus::Ok;result.data.assign(static_cast<std::size_t>(length),0x4D);return result;
    }
    IoWriteResult Write(const MemoryTargetSession&,std::uint64_t,const std::vector<std::uint8_t>&,bool) override {return {};}
private:std::shared_ptr<State> state_;
};
void scenario(bool real) {
    auto* allocation=static_cast<unsigned char*>(VirtualAlloc(nullptr,0x10000,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    check(allocation!=nullptr,"allocate isolated readable fixture");if(!allocation)return;
    std::fill(allocation,allocation+0x10000,static_cast<unsigned char>(0x4D));
    auto state=std::make_shared<State>();state->real=real;
    state->base=real ? reinterpret_cast<std::uint64_t>(allocation)+0x2000 : 0x00007FFC96AC0000;
    {
        WorkbenchTarget target(std::make_unique<Services>());
        target.requestPin(GetCurrentProcessId());
        check(pump([&]{return target.capture().session.pid==GetCurrentProcessId();}),"production target captures the test process");
        HexCanvas canvas;canvas.resize(900,420);canvas.setFoldUnknownRegions(true);canvas.setOverviewEnabled(true);
        WorkbenchPageProvider provider([state]{return std::make_unique<Port>(state);},&target);
        QObject::connect(&provider,&WorkbenchPageProvider::readFailed,&canvas,[](quint64,QString text,int count){
            std::printf("PROVIDER_FAILURE count=%d text=%s\n",count,text.toUtf8().constData());
        });
        std::printf("SCENARIO real=%d base=%llX\n",real,static_cast<unsigned long long>(state->base));
        provider.setCanvas(&canvas);
        provider.setGateInputsProvider([]{GateInputs inputs;inputs.hasProcessTarget=true;return inputs;});
        canvas.setPageProvider(&provider);canvas.setAddressSpace(0,0x7FFFFFFFFFFF);
        canvas.show();
        check(pump([&]{return !provider.hasInFlightRequests();}),"initial endpoint requests settle");
        canvas.deliverUnreadable({0,1,0},canvas.sourceRevision());
        canvas.deliverUnreadable({0x7FFFFFFFF000,1,0},canvas.sourceRevision());
        pump([]{return false;},30);
        check(state->targetReads==0,"target fixture has not been read by bootstrap endpoints");
        const auto before=state->calls.load();
        // Exactly the focus path used by module, region and address navigation.
        const auto end=state->base+(real ? 31 : 0);
        check(canvas.setCaretAddress(end,false,false),"select jump endpoint");
        check(canvas.setCaretAddress(state->base,true,false),"select jump start");
        check(canvas.revealCaret(HexCanvas::ScrollAlign::Top),"reveal jump caret");
        const bool loaded=pump([&]{return canvas.cellStateAt(state->base).hasValue;},1500);
        std::printf("PIPELINE real=%d calls_before=%u calls_after=%u target_reads=%u state=%d\n",real,before,state->calls.load(),
            state->targetReads.load(),static_cast<int>(canvas.cellStateAt(state->base).byteState));
        check(loaded && state->targetReads>0,"revealCaret must reach the async read port even when the first visual row stays zero");
        check(canvas.cellStateAt(state->base).hasValue && canvas.cellStateAt(state->base).value==0x4D,"read results reach the HEX cache");
        check(!canvas.cellRect(state->base,HexCanvas::ActivePane::Hex).isNull(),"jumped real bytes remain visible");
        check(canvas.selectedRange() && canvas.selectedRange()->first==state->base && canvas.selectedRange()->last==end,
            "asynchronous read preserves the requested selection");
        state->block=true;state->blocked=false;state->release=false;
        const auto readsBeforePending=state->targetReads.load();
        canvas.refresh();
        const bool pending=pump([&]{return state->blocked.load();});
        check(pending,"target read is genuinely pending in the production worker");
        canvas.setViewportReadEnabled(false);
        check(canvas.revealCaret(HexCanvas::ScrollAlign::Top),"explicit focus remains usable while ordinary viewport reads are paused");
        provider.UpdateViewportInterest({HexFetchRange{0x400000,1,0}},canvas.sourceRevision());
        state->release=true;
        check(pump([&]{return !provider.hasInFlightRequests();}),"protected pending read finishes");
        check(canvas.cellStateAt(state->base).hasValue && state->targetReads==readsBeforePending+1,
            "pending navigation read is promoted and retained without duplicate reads");
        state->block=false;
        canvas.setViewportReadEnabled(true);
        canvas.grab().save(QStringLiteral(".codex-tmp/hex-read-pipeline/")+ (real ? QStringLiteral("real.png") : QStringLiteral("high-address.png")));
        canvas.setPageProvider(nullptr);provider.cancelAllInFlight();
    }
    VirtualFree(allocation,0,MEM_RELEASE);
}
void invalidAddressReads() {
    // These addresses are visited by folded endpoint prefetch. Before the fix,
    // this machine returned an out-of-buffer byte count and threw bad_alloc.
    for(const auto address : {0ULL,0x7FFFFFFFD000ULL,0x7FFFFFFFE000ULL,0x7FFFFFFFF000ULL}) {
        try {
            const auto read=ksword::memwb_ports_detail::ReadUserModeVirtual(GetCurrentProcessId(),address,4096);
            check(read.status==IoReadStatus::Unreadable && read.data.empty(),"invalid user endpoint cannot become data or a channel exception");
        } catch(...) {check(false,"invalid user endpoint must not throw from a failed read receipt");}
    }
}
int main(int argc,char** argv) {
    QApplication app(argc,argv);
    QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/consola.ttf"));
    QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
    invalidAddressReads();scenario(false);scenario(true);
    std::printf("READ_PIPELINE_CHECKS=%d FAILURES=%d\n",checks,failures);return failures ? 1 : 0;
}
