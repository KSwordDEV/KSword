"""Exercise the production verified-thread WDF handler with mock kernel APIs."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <windows.h>
#include <winioctl.h>
#include <cstring>
#include <cassert>
#include <utility>
#include "PROTOCOL"
using NTSTATUS=LONG; using ULONG64=unsigned long long;
struct Object { ULONG pid; ULONG64 processBirth,threadBirth; };
using PETHREAD=Object*; using PEPROCESS=Object*; using WDFDEVICE=void*;
struct Request { unsigned char bytes[128]; size_t inputLength,outputLength; };
using WDFREQUEST=Request*;
#define STATUS_SUCCESS ((NTSTATUS)0)
#undef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000dU)
#define STATUS_NOT_FOUND ((NTSTATUS)0xc0000225U)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bbU)
#define STATUS_RETRY ((NTSTATUS)0xc000022dU)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xc0000184U)
#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS)0xc000007aU)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022U)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023U)
#define NT_SUCCESS(x) ((NTSTATUS)(x)>=0)
#undef RtlCopyMemory
#undef RtlZeroMemory
#define RtlCopyMemory std::memcpy
#define RtlZeroMemory(p,n) std::memset((p),0,(n))
#define ULongToHandle(v) reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(v))
#define HandleToULong(v) static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(v))
#define OBJ_KERNEL_HANDLE 0x200
#define KernelMode 0
#define KSWORD_ARK_SAFETY_OPERATION_PROCESS_TERMINATE 1
#define KSWORD_ARK_SAFETY_OPERATION_PROCESS_SUSPEND 2
#define KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED 1
struct KSWORD_ARK_SAFETY_CONTEXT { ULONG Operation,TargetProcessId,ContextFlags; };
using KSWORD_ZW_OR_NT_THREAD_SUSPEND_FN=NTSTATUS (*)(HANDLE,PULONG);
static Object target{42,111,222}, self{50,333,444};
static int calls=0, derefs=0, closes=0; static bool denied=false, unavailable=false;
static void* fakeType=nullptr; static void** PsThreadType=&fakeType;
NTSTATUS KswordARKRetrieveRequiredInputBuffer(WDFREQUEST r,size_t n,PVOID* p,size_t* actual) {
    if(r->inputLength<n)return STATUS_BUFFER_TOO_SMALL;*p=r->bytes;*actual=r->inputLength;return 0;
}
NTSTATUS KswordARKRetrieveRequiredOutputBuffer(WDFREQUEST r,size_t n,PVOID* p,size_t* actual) {
    if(r->outputLength<n)return STATUS_BUFFER_TOO_SMALL;*p=r->bytes;*actual=r->outputLength;return 0;
}
NTSTATUS PsLookupThreadByThreadId(HANDLE id,PETHREAD* out) {if(HandleToULong(id)!=7)return STATUS_NOT_FOUND;*out=&target;return 0;}
PEPROCESS PsGetThreadProcess(PETHREAD t) {return t;}
HANDLE PsGetThreadProcessId(PETHREAD t) {return ULongToHandle(t->pid);}
HANDLE PsGetProcessId(PEPROCESS p) {return ULongToHandle(p->pid);}
LONGLONG PsGetProcessCreateTimeQuadPart(PEPROCESS p) {return static_cast<LONGLONG>(p->processBirth);}
LONGLONG PsGetThreadCreateTime(PETHREAD t) {return static_cast<LONGLONG>(t->threadBirth);}
PETHREAD PsGetCurrentThread() {return &self;}
NTSTATUS KswordARKSafetyEvaluate(WDFDEVICE,KSWORD_ARK_SAFETY_CONTEXT*) {return denied ? STATUS_ACCESS_DENIED : 0;}
NTSTATUS KswordARKDriverTerminateReferencedThread(PETHREAD t,NTSTATUS) {assert(t==&target);++calls;return 0;}
NTSTATUS fakeControl(HANDLE h,PULONG previous) {assert(h==reinterpret_cast<HANDLE>(1));++calls;*previous=3;return 0;}
KSWORD_ZW_OR_NT_THREAD_SUSPEND_FN KswordARKResolveThreadSuspendRoutine(BOOLEAN) {return unavailable ? nullptr : fakeControl;}
NTSTATUS ObOpenObjectByPointer(PETHREAD t,ULONG,void*,ULONG,void*,int,HANDLE* out) {assert(t==&target);*out=reinterpret_cast<HANDLE>(1);return 0;}
NTSTATUS ZwClose(HANDLE) {++closes;return 0;}
void ObDereferenceObject(PETHREAD t) {assert(t==&target);++derefs;}
'''
POSTLUDE = r'''
int main() {
    auto run=[](ULONG action,ULONG flags,ULONG64 processBirth,ULONG64 threadBirth,size_t outSize=sizeof(KSWORD_ARK_CONTROL_THREAD_VERIFIED_RESPONSE)) {
        Request request{}; request.inputLength=sizeof(KSWORD_ARK_CONTROL_THREAD_VERIFIED_REQUEST);request.outputLength=outSize;
        KSWORD_ARK_CONTROL_THREAD_VERIFIED_REQUEST input{};
        input.size=sizeof(input);input.version=KSWORD_ARK_THREAD_VERIFIED_VERSION;input.processId=42;input.threadId=7;
        input.action=action;input.flags=flags;input.expectedProcessCreationTime100ns=processBirth;input.expectedThreadCreationTime100ns=threadBirth;
        std::memcpy(request.bytes,&input,sizeof(input));size_t returned=0;
        const auto transport=KswordARKThreadIoctlControlVerified(nullptr,&request,request.inputLength,request.outputLength,&returned);
        KSWORD_ARK_CONTROL_THREAD_VERIFIED_RESPONSE response{};std::memcpy(&response,request.bytes,sizeof(response));
        return std::pair{transport,response};
    };
    auto [io,id]=run(0,0,0,0); assert(io==0&&id.status==0&&id.processCreationTime100ns==111&&id.threadCreationTime100ns==222&&calls==0);
    auto [io2,bad]=run(1,1,111,223); assert(io2==0&&bad.status==STATUS_RETRY&&calls==0);
    auto [io3,unconfirmed]=run(1,0,111,222); assert(io3==0&&unconfirmed.status==STATUS_INVALID_PARAMETER&&calls==0);
    denied=true;auto [io4,blocked]=run(1,1,111,222);assert(io4==0&&blocked.status==STATUS_ACCESS_DENIED&&calls==0);denied=false;
    auto [io5,shortOutput]=run(1,1,111,222,0);assert(io5==STATUS_BUFFER_TOO_SMALL&&calls==0);
    auto [io6,suspend]=run(1,1,111,222);assert(io6==0&&suspend.status==0&&suspend.previousSuspendCount==3&&calls==1&&closes==1);
    auto [io7,terminated]=run(3,1,111,222);assert(io7==0&&terminated.status==0&&calls==2);
    unavailable=true;auto [io8,unsupported]=run(2,1,111,222);assert(io8==0&&unsupported.status==STATUS_PROCEDURE_NOT_FOUND&&calls==2);
    assert(derefs==6);return 0;
}
'''


def main():
    source = (ROOT / "KswordARKDriver/src/features/thread/thread_ioctl.c").read_text(encoding="utf-8")
    start = source.index("NTSTATUS\nKswordARKThreadIoctlControlVerified(")
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        if source[end] == "{": depth += 1
        elif source[end] == "}": depth -= 1
        end += 1
    prelude = PRELUDE.replace('"PROTOCOL"', '"' + (ROOT / "shared/driver/KswordArkThreadIoctl.h").as_posix() + '"')
    with tempfile.TemporaryDirectory(prefix="ksword-thread-kernel-") as temp:
        temp = Path(temp)
        fixture = temp / "fixture.cpp"
        fixture.write_text(prelude + source[start:end] + POSTLUDE, encoding="utf-8")
        binary = temp / "fixture.exe"
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/O2", str(fixture), "/Fe:" + str(binary)], cwd=temp, check=True)
        subprocess.run([str(binary)], check=True, timeout=10)
    print("VERIFIED_THREAD_KERNEL_PASS identity, stale target, safety, short buffer and referenced action")


if __name__ == "__main__":
    main()
