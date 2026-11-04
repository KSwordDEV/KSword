"""Exercise the production verified read path and its client against controlled transport."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

KERNEL_PREFIX = r'''
#define NOMINMAX
#include <Windows.h>
#include <winioctl.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "PROTOCOL"
typedef LONG NTSTATUS;
struct FakeProcess { unsigned long long creation; };
typedef FakeProcess* PEPROCESS;
static FakeProcess target{123456789};
static int copies=0, dereferences=0, lookups=0;
#undef STATUS_SUCCESS
#undef STATUS_INVALID_PARAMETER
#undef STATUS_BUFFER_TOO_SMALL
#undef STATUS_INVALID_CID
#undef STATUS_NOT_SUPPORTED
#undef STATUS_PARTIAL_COPY
constexpr NTSTATUS STATUS_SUCCESS=0;
constexpr NTSTATUS STATUS_INVALID_PARAMETER=static_cast<NTSTATUS>(0xc000000dUL);
constexpr NTSTATUS STATUS_BUFFER_TOO_SMALL=static_cast<NTSTATUS>(0xc0000023UL);
constexpr NTSTATUS STATUS_INVALID_CID=static_cast<NTSTATUS>(0xc000000bUL);
constexpr NTSTATUS STATUS_NOT_SUPPORTED=static_cast<NTSTATUS>(0xc00000bbUL);
constexpr NTSTATUS STATUS_PARTIAL_COPY=static_cast<NTSTATUS>(0x8000000dUL);
#define NT_SUCCESS(s) ((s)>=0)
#define KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE FIELD_OFFSET(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data)
#define PAGE_SIZE 4096
#define KernelMode 0
static bool KswordARKMemoryIsUserAddressRange(ULONG64 base,SIZE_T size){return base>=0x1000&&size<=0x100000&&base+size>=base&&base+size<0x80000000;}
static bool KswordARKMemoryIsKernelAddressRange(ULONG64,SIZE_T){return false;}
static NTSTATUS KswordARKMemoryCopyKernelVirtualMemory(ULONG64,void*,SIZE_T,SIZE_T*){return STATUS_NOT_SUPPORTED;}
static NTSTATUS PsLookupProcessByProcessId(HANDLE,PEPROCESS* value){++lookups;*value=&target;return STATUS_SUCCESS;}
static LONGLONG PsGetProcessCreateTimeQuadPart(PEPROCESS value){return static_cast<LONGLONG>(value->creation);}
static PEPROCESS PsGetCurrentProcess(){return nullptr;}
static void ObDereferenceObject(PEPROCESS){++dereferences;}
static NTSTATUS MmCopyVirtualMemory(PEPROCESS from,void*,PEPROCESS,void* output,SIZE_T size,int,SIZE_T* copied){
    ++copies;if(from!=&target)return STATUS_INVALID_CID;std::memset(output,0x5a,size);*copied=size;return STATUS_SUCCESS;
}
'''

KERNEL_TEST = r'''
int main(){
    unsigned char output[512]{};size_t written=0;
    KSWORD_ARK_READ_VIRTUAL_MEMORY_VERIFIED_REQUEST r{};
    r.size=sizeof(r);r.version=KSWORD_ARK_VERIFIED_MEMORY_READ_VERSION;r.processId=42;
    r.expectedCreationTime100ns=target.creation;r.baseAddress=0x1000;r.bytesToRead=64;
    auto call=[&]{return KswordARKDriverReadVirtualMemoryVerified(output,sizeof(output),&r,&written);};
    if(call()!=STATUS_SUCCESS||copies!=1||lookups!=1||dereferences!=1)return 1;
    auto* response=reinterpret_cast<KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*>(output);
    if(response->readStatus!=KSWORD_ARK_MEMORY_READ_STATUS_OK||response->bytesRead!=64||output[KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE]!=0x5a)return 2;
    r.expectedCreationTime100ns++;std::memset(output,0xcc,sizeof(output));
    if(call()!=STATUS_SUCCESS||copies!=1||lookups!=2||dereferences!=2)return 3;
    if(response->lookupStatus!=STATUS_INVALID_CID||response->bytesRead!=0||written!=KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE)return 4;
    r.expectedCreationTime100ns=0;if(call()!=STATUS_INVALID_PARAMETER||lookups!=2)return 5;
    r.expectedCreationTime100ns=target.creation;r.flags=KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS;
    if(call()!=STATUS_INVALID_PARAMETER||lookups!=2)return 6;
    r.flags=0;r.bytesToRead=0;if(call()!=STATUS_INVALID_PARAMETER||lookups!=2)return 7;
    r.bytesToRead=64;r.version=999;if(call()!=STATUS_INVALID_PARAMETER||lookups!=2)return 8;
    std::cout<<"VERIFIED_MEMORY_KERNEL_PASS\n";
}
'''

CLIENT_TEST = r'''
#include "CLIENT_HEADER"
#include <cstddef>
#include <cstring>
#include <iostream>
using namespace ksword::ark;
static int mode=0,calls=0;static bool packet=true;
IoResult DriverClient::deviceIoControl(unsigned long code,void* input,unsigned long inputBytes,void* output,unsigned long capacity,DriverHandle*) const {
    ++calls;IoResult io{};packet &= code==IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY_VERIFIED;
    const auto& request=*static_cast<KSWORD_ARK_READ_VIRTUAL_MEMORY_VERIFIED_REQUEST*>(input);
    packet &= inputBytes==sizeof(request)&&request.size==sizeof(request)&&request.version==KSWORD_ARK_VERIFIED_MEMORY_READ_VERSION&&request.expectedCreationTime100ns==123456789;
    if(mode==1){io.win32Error=ERROR_INVALID_FUNCTION;return io;}
    auto* r=static_cast<KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*>(output);
    r->version=KSWORD_ARK_MEMORY_PROTOCOL_VERSION;r->headerSize=offsetof(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE,data);
    r->processId=request.processId;r->requestedBaseAddress=request.baseAddress;r->requestedBytes=request.bytesToRead;
    r->readStatus=KSWORD_ARK_MEMORY_READ_STATUS_OK;r->bytesRead=request.bytesToRead;
    if(mode==2)r->processId++;
    if(mode==3)r->bytesRead++;
    if(mode==4)r->version++;
    if(mode==5){r->readStatus=KSWORD_ARK_MEMORY_READ_STATUS_PROCESS_LOOKUP_FAILED;r->lookupStatus=static_cast<LONG>(0xc000000bUL);r->bytesRead=0;}
    if(mode==7)r->bytesRead--;
    if(mode==8)r->lookupStatus=static_cast<LONG>(0xc000000bUL);
    io.ok=true;io.bytesReturned=static_cast<unsigned long>(offsetof(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE,data)+r->bytesRead);
    if(mode==6)io.bytesReturned=capacity+1;
    return io;
}
int main(){
    DriverClient client;auto read=[&]{return client.readVirtualMemoryVerified(42,123456789,0x1000,8);};
    auto good=read();if(!good.io.ok||good.data.size()!=8||!packet||calls!=1)return 1;
    mode=1;auto old=read();if(old.io.ok||old.io.win32Error!=ERROR_INVALID_FUNCTION||calls!=2)return 2;
    for(mode=2;mode<=4;++mode)if(read().io.ok)return 3;
    mode=5;auto mismatch=read();if(!mismatch.io.ok||mismatch.bytesRead||mismatch.lookupStatus!=static_cast<LONG>(0xc000000bUL))return 4;
    mode=6;if(read().io.ok)return 5;
    mode=7;if(read().io.ok)return 7;
    mode=8;if(read().io.ok)return 8;
    auto before=calls;if(client.readVirtualMemoryVerified(42,0,0x1000,8).io.ok||calls!=before)return 6;
    std::cout<<"VERIFIED_MEMORY_CLIENT_PASS\n";
}
'''


def compile_and_run(directory, name, source, extra=()):
    path=directory / (name+".cpp")
    path.write_text(source, encoding="utf-8")
    exe=directory / (name+".exe")
    subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/W4", "/WX", "/O2", "/Gy",
                    str(path), *map(str,extra), "/Fe:"+str(exe), "/link", "/OPT:REF"], cwd=directory, check=True)
    subprocess.run([str(exe)], cwd=directory, check=True)


def main():
    source=(ROOT / "KswordARKDriver/src/features/process/process_memory.c").read_text(encoding="utf-8-sig")
    start=source.index("static NTSTATUS\nKswordARKDriverReadVirtualMemoryInternal(")
    end=source.index("NTSTATUS\nKswordARKDriverWriteVirtualMemory(", start)
    kernel=KERNEL_PREFIX.replace("PROTOCOL",(ROOT / "shared/driver/KswordArkMemoryIoctl.h").as_posix())+source[start:end]+KERNEL_TEST
    client=CLIENT_TEST.replace("CLIENT_HEADER",(ROOT / "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h").as_posix())
    with tempfile.TemporaryDirectory(prefix="ksword-verified-memory-") as temp:
        directory=Path(temp)
        compile_and_run(directory,"kernel",kernel)
        compile_and_run(directory,"client",client,[ROOT / "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverMemory.cpp"])


if __name__=="__main__":
    main()
