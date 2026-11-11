"""Compile the production tracker and context thunk; check identity and callback races."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
code = r'''
#include <cstdio>
#include <stdexcept>
#include "TRACKER"
#include "THUNK"
namespace apimon {
 std::uint64_t session=1; bool stopping=false;
 struct Event{ks::winapi_monitor::EventKind kind;std::uint64_t operation;int result;std::wstring detail;ks::winapi_monitor::EventResultKind resultKind;};
 std::vector<Event> events;
 std::uint64_t CurrentMonitorSessionIdentity(){return session;}
 bool StopRequested(){return stopping;}
 std::uint32_t RuntimeApiId(const wchar_t*,const wchar_t*){return 42;}
 ScopedInlineHookInternalBypass::ScopedInlineHookInternalBypass(){}
 ScopedInlineHookInternalBypass::~ScopedInlineHookInternalBypass(){}
 bool SendMonitorEventRaw(ks::winapi_monitor::EventCategory,const wchar_t*,const wchar_t*,std::int32_t result,const wchar_t* detail,
  ks::winapi_monitor::EventResultKind resultKind,ks::winapi_monitor::EventKind kind,std::uint64_t operation,std::uint32_t)
 {events.push_back({kind,operation,result,detail ? detail : L"",resultKind});return true;}
}
using namespace apimon;using namespace ks::winapi_monitor;
#define CHECK(x) do{if(!(x)){printf("FAIL %d\n",__LINE__);return 1;}}while(0)
IoToken Start(std::uintptr_t h,OVERLAPPED* ov,bool callback=false){return BeginIo(h,ov,L"Fixture",L"Read",EventCategory::File,42,callback);}
std::size_t Completions(std::uint64_t id){return std::count_if(events.begin(),events.end(),[&](auto& e){return e.operation==id&&e.kind==EventKind::IoComplete;});}
std::uint64_t WINAPI Dispatcher(void* context,std::uintptr_t a,std::uintptr_t b,std::uintptr_t c,std::uintptr_t d,std::uintptr_t e,std::uintptr_t f,std::uintptr_t g,std::uintptr_t h)
 {return reinterpret_cast<std::uintptr_t>(context)+a+2*b+3*c+4*d+5*e+6*f+7*g+8*h;}
void WINAPI Throwing(void*){throw std::runtime_error("owned callback exception");}
bool observerCalled=false;
bool detailAccessed=false;
void CompletionDetail(const IoToken&, wchar_t*, std::size_t){detailAccessed=true;}
void Observer(const IoToken&,DWORD){observerCalled=true;ObserveIoResult(999,nullptr,false,0,0);}
int main(){
 auto thunk=BuildContextThunk(reinterpret_cast<void*>(100),reinterpret_cast<void*>(&Dispatcher),8);CHECK(thunk);
 using Function=std::uint64_t(WINAPI*)(std::uintptr_t,std::uintptr_t,std::uintptr_t,std::uintptr_t,std::uintptr_t,std::uintptr_t,std::uintptr_t,std::uintptr_t);
 CHECK(reinterpret_cast<Function>(thunk)(1,2,3,4,5,6,7,8)==304);
 auto throwing=BuildContextThunk(nullptr,reinterpret_cast<void*>(&Throwing),0);CHECK(throwing);
 bool unwound=false;try{reinterpret_cast<void(WINAPI*)()>(throwing)();}catch(const std::runtime_error&){unwound=true;}CHECK(unwound);
 OVERLAPPED ov{};auto first=Start(10,&ov,true);CHECK(first);first->completionObserver=&Observer;
 CompleteIo(first,0,42);CHECK(Completions(first->id)==0);FinishIo(first,true,true,0,0);CHECK(Completions(first->id)==1&&observerCalled);
 CompleteIo(first,0,42);CHECK(Completions(first->id)==1);
 BindIoPort(10,reinterpret_cast<HANDLE>(20));auto sync=Start(10,&ov);FinishIo(sync,true,false,0,42);CHECK(Completions(sync->id)==1);
 auto pending=Start(10,&ov);FinishIo(pending,true,true,ERROR_IO_PENDING,0);
 CHECK(events.back().kind==EventKind::IoWait && events.back().resultKind==EventResultKind::StatusUnknown);
 ObserveIoResult(10,&ov,false,ERROR_IO_INCOMPLETE,0,false);
 CHECK(events.back().kind==EventKind::IoWait && events.back().resultKind==EventResultKind::StatusCode && events.back().result==ERROR_IO_INCOMPLETE);
 ObservePortCompletion(reinterpret_cast<HANDLE>(20),&ov,0,42);CHECK(Completions(pending->id)==0);
 ObservePortCompletion(reinterpret_cast<HANDLE>(20),&ov,0,42);CHECK(Completions(pending->id)==1);
 ObserveIoResult(10,&ov,true,0,42);CHECK(Completions(pending->id)==1);
 auto old=Start(30,&ov,true);FinishIo(old,true,true,0,0);RetireIoResource(30);
 auto reused=Start(30,&ov);CHECK(reused&&reused->resourceIdentity!=old->resourceIdentity);FinishIo(reused,true,true,0,0);
 CompleteIo(old,ERROR_OPERATION_ABORTED,0);CHECK(Completions(reused->id)==0);
 ObserveIoCancellation(30,&ov,0);CHECK(Completions(reused->id)==0);ObserveIoResult(30,&ov,true,ERROR_OPERATION_ABORTED,0);CHECK(Completions(reused->id)==1);
 auto stopped=Start(40,&ov,true);FinishIo(stopped,true,true,0,0);auto count=events.size();stopping=true;CompleteIo(stopped,0,42);CHECK(events.size()==count);
 stopping=false;session=2;CompleteIo(old,0,42);CHECK(events.size()==count);
 BindIoPort(60,reinterpret_cast<HANDLE>(70));auto oldPort=Start(60,&ov);FinishIo(oldPort,true,true,0,0);
 session=3;BindIoPort(60,reinterpret_cast<HANDLE>(70));auto newPort=Start(60,&ov);FinishIo(newPort,true,true,0,0);
 count=events.size();ObservePortCompletion(reinterpret_cast<HANDLE>(70),&ov,0,42);CHECK(events.size()==count&&Completions(newPort->id)==0);
 ObservePortCompletion(reinterpret_cast<HANDLE>(70),&ov,0,42);CHECK(Completions(newPort->id)==1);
 BindIoPort(90,reinterpret_cast<HANDLE>(91),123);auto keyed=Start(90,&ov);FinishIo(keyed,true,true,0,0);
 ObservePortCompletion(reinterpret_cast<HANDLE>(91),&ov,0,42,999);CHECK(Completions(keyed->id)==0);
 ObservePortCompletion(reinterpret_cast<HANDLE>(91),&ov,0,42,123);CHECK(Completions(keyed->id)==1);
 auto ambiguous=Start(80,&ov,true);FinishIo(ambiguous,true,true,0,0);CHECK(!Start(80,&ov));
 ObserveIoResult(80,&ov,true,0,42);CHECK(Completions(ambiguous->id)==0);
 CompleteIo(ambiguous,0,42);CHECK(Completions(ambiguous->id)==1);
 // Early failure, unknown output, duplicate observation, and reuse.
 OVERLAPPED earlyOv{}; auto earlyUnknown=Start(101,&earlyOv,true);CHECK(earlyUnknown);earlyUnknown->completionDetail=&CompletionDetail;
 ObserveIoResult(101,&earlyOv,true,ERROR_OPERATION_ABORTED,0,false);
 FinishIo(earlyUnknown,true,true,0,0,false); CHECK(Completions(earlyUnknown->id)==1);
 CHECK(events.back().detail.find(L"bytes=unknown")!=std::wstring::npos && events.back().detail.find(L"completion_detail=unknown")!=std::wstring::npos && !detailAccessed);
 auto beforeLate=events.size(); ObserveIoResult(101,&earlyOv,true,0,77,true);
 CHECK(events.size()==beforeLate && Completions(earlyUnknown->id)==1);
 auto reusedUnknown=Start(101,&earlyOv);CHECK(reusedUnknown);FinishIo(reusedUnknown,true,true,0,0,false);
 CompleteIo(earlyUnknown,0,77);CHECK(Completions(reusedUnknown->id)==0);
 ObserveIoResult(101,&earlyOv,true,0,12,true);CHECK(Completions(reusedUnknown->id)==1);
 OVERLAPPED portOv{};BindIoPort(102,reinterpret_cast<HANDLE>(103),104);auto portUnknown=Start(102,&portOv);CHECK(portUnknown);
 FinishIo(portUnknown,true,false,0,0,false);CHECK(Completions(portUnknown->id)==1);
 auto portCount=events.size();ObservePortCompletion(reinterpret_cast<HANDLE>(103),&portOv,0,88,999);CHECK(events.size()==portCount);
 ObservePortCompletion(reinterpret_cast<HANDLE>(103),&portOv,0,88,104);CHECK(Completions(portUnknown->id)==1 && events.size()==portCount);
 ObservePortCompletion(reinterpret_cast<HANDLE>(103),&portOv,0,88,104);CHECK(events.size()==portCount);
 std::array<OVERLAPPED,8192> many{};std::vector<IoToken> tokens;
 for(auto& item:many){auto token=Start(50,&item);CHECK(token);FinishIo(token,true,true,0,0);tokens.push_back(token);}
 OVERLAPPED excess{};CHECK(!Start(50,&excess)&&UntrackedIoCount()==2);
 CompleteIo(tokens[0],0,42);CHECK(Start(50,&excess));
 printf("PASS: thunk register/stack ABI and unwind, 8192 capacity, early/duplicate completion, IOCP ordering, cancellation, handle reuse and session isolation\n");
}
'''.replace("TRACKER", (root / "APIMonitor_x64/core/MonitorAsyncIo.cpp").as_posix()).replace("THUNK", (root / "APIMonitor_x64/hook/ContextThunk.h").as_posix())
with tempfile.TemporaryDirectory(prefix="ksword_async_tracker_") as temp:
    folder = Path(temp)
    cpp = folder / "fixture.cpp"
    cpp.write_text(code, encoding="utf-8")
    subprocess.run(["cl", "/nologo", "/EHsc", "/std:c++17", "/utf-8", "/I" + str(root / "APIMonitor_x64"),
                    str(cpp), "/Fe:" + str(folder / "fixture.exe"), "/Fo:" + str(folder / "fixture.obj")], check=True)
    subprocess.run([str(folder / "fixture.exe")], check=True, timeout=30)
