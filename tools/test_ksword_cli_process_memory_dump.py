"""Exercise real R3 reads and controlled R0/identity failures of the dump command."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "COMMAND_HEADER"
#include "DRIVER_HEADER"
#include "MODULE_HEADER"
#include "MODULE_IOCTL"
#include <algorithm>
#include <fcntl.h>
#include <io.h>

static std::wstring mode;
static unsigned moduleCalls = 0;
static unsigned char testBytes[150000];
static HANDLE WINAPI fixtureOpen(DWORD access,BOOL inherit,DWORD pid) {
    if (mode==L"r0-only") {SetLastError(ERROR_ACCESS_DENIED);return nullptr;}
    return OpenProcess(access,inherit,pid);
}
static BOOL WINAPI fixtureRead(HANDLE process, LPCVOID address, LPVOID output, SIZE_T size, SIZE_T* read) {
    if ((mode == L"short" || mode == L"cleanup-failure") && reinterpret_cast<std::uintptr_t>(address) > reinterpret_cast<std::uintptr_t>(testBytes)) {
        *read = 0; SetLastError(ERROR_PARTIAL_COPY); return FALSE;
    }
    return ReadProcessMemory(process, address, output, size, read);
}
static BOOL WINAPI fixtureDelete(LPCWSTR path) {
    if (mode==L"cleanup-failure") {SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return DeleteFileW(path);
}
namespace ks::r3::process_detail::detail {
std::vector<ProcessModuleInfo> CollectModules(DWORD, bool& ok, std::wstring&, ModuleEnumerationEvidence* evidence) {
    ++moduleCalls; ok = true; evidence->complete = true;
    ProcessModuleInfo row; row.baseAddress = reinterpret_cast<std::uintptr_t>(testBytes);
    row.imageSize = static_cast<DWORD>(sizeof(testBytes));
    if (mode == L"module-change" && moduleCalls > 1) --row.imageSize;
    row.infoKnown = row.pathKnown = true; row.modulePath = L"fixture.dll";
    return {row};
}
}
namespace ksword::ark {
DriverHandle::DriverHandle(HANDLE value) noexcept : m_handle(value) {}
DriverHandle::~DriverHandle(){reset();}
DriverHandle::DriverHandle(DriverHandle&& other) noexcept : m_handle(other.release()) {}
DriverHandle& DriverHandle::operator=(DriverHandle&& other) noexcept {if(this!=&other)reset(other.release());return *this;}
bool DriverHandle::isValid() const noexcept {return m_handle && m_handle!=INVALID_HANDLE_VALUE;}
HANDLE DriverHandle::native() const noexcept {return m_handle;}
HANDLE DriverHandle::release() noexcept {HANDLE h=m_handle;m_handle=INVALID_HANDLE_VALUE;return h;}
void DriverHandle::reset(HANDLE h) noexcept {if(isValid()) CloseHandle(m_handle);m_handle=h;}
DriverHandle DriverClient::openSilently(unsigned long access) const {
    if ((access & (GENERIC_READ | GENERIC_WRITE)) != (GENERIC_READ | GENERIC_WRITE)) {SetLastError(ERROR_ACCESS_DENIED);return DriverHandle();}
    return DriverHandle(CreateEventW(nullptr,FALSE,FALSE,nullptr));
}
VirtualMemoryReadResult DriverClient::readVirtualMemoryVerified(std::uint32_t pid,std::uint64_t creation,std::uint64_t address,std::uint32_t size,unsigned long flags,DriverHandle*) const {
    VirtualMemoryReadResult result{}; result.io.ok=true; result.version=KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    result.processId=pid; result.requestedBaseAddress=address; result.requestedBytes=size;
    result.readStatus=KSWORD_ARK_MEMORY_READ_STATUS_OK; result.bytesRead=size;
    if (mode==L"r0-malformed" || mode==L"r0-unsupported") {
        result.io.ok=false;result.io.win32Error=mode==L"r0-malformed"?ERROR_INVALID_DATA:ERROR_INVALID_FUNCTION;return result;
    }
    if (flags!=0 || !creation) {result.io.ok=false;result.io.win32Error=ERROR_INVALID_PARAMETER;return result;}
    if (mode==L"r0-identity" || (mode==L"r0-final-mismatch" && size==1)) {
        result.readStatus=KSWORD_ARK_MEMORY_READ_STATUS_PROCESS_LOOKUP_FAILED;
        result.lookupStatus=static_cast<long>(0xc000000bU);result.bytesRead=0;return result;
    }
    if (mode==L"r0-short" && address>reinterpret_cast<std::uintptr_t>(testBytes)) {
        result.readStatus=KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY;result.bytesRead=1;result.data={1};return result;
    }
    auto begin=reinterpret_cast<const unsigned char*>(static_cast<std::uintptr_t>(address));
    result.data.assign(begin,begin+size);return result;
}
IoResult DriverClient::deviceIoControl(unsigned long code,void* input,unsigned long,void* output,unsigned long outputBytes,DriverHandle*) const {
    IoResult io{};if(code!=IOCTL_KSWORD_ARK_ENUM_MODULES){io.win32Error=ERROR_INVALID_FUNCTION;return io;}
    ++moduleCalls;const auto* request=static_cast<const KSWORD_ARK_ENUM_MODULES_REQUEST*>(input);
    constexpr auto header=offsetof(KSWORD_ARK_ENUM_MODULES_RESPONSE,entries);
    if(outputBytes<header+sizeof(KSWORD_ARK_MODULE_ENTRY)){io.win32Error=ERROR_INSUFFICIENT_BUFFER;return io;}
    auto* response=static_cast<KSWORD_ARK_ENUM_MODULES_RESPONSE*>(output);
    response->size=static_cast<unsigned long>(header+sizeof(response->entries[0]));response->version=request->version;
    response->source=request->source;response->status=KSWORD_ARK_MODULE_STATUS_COMPLETE;response->processId=request->processId;
    response->processCreateTime100ns=request->expectedCreateTime100ns;response->entrySize=sizeof(response->entries[0]);response->returnedCount=1;
    auto& row=response->entries[0];row.baseAddress=reinterpret_cast<std::uintptr_t>(testBytes);row.spanBytes=sizeof(testBytes);
    if(mode==L"r0-module-change" && moduleCalls>1)--row.spanBytes;
    row.flags=KSWORD_ARK_MODULE_ROW_PATH_PRESENT;wcscpy_s(row.path,L"fixture.dll");
    io.ok=true;io.bytesReturned=response->size;return io;
}
}
#define ReadProcessMemory fixtureRead
#define OpenProcess fixtureOpen
#define DeleteFileW fixtureDelete
#include "DUMP_SOURCE"
#undef DeleteFileW
#undef OpenProcess
#undef ReadProcessMemory
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT); _setmode(_fileno(stderr),_O_U8TEXT);
    mode=argv[1]; for(int i=1;i+1<argc;++i)argv[i]=argv[i+1]; --argc;
    for(std::size_t i=0;i<sizeof(testBytes);++i)testBytes[i]=static_cast<unsigned char>(i%251);
    const auto pid=std::to_wstring(GetCurrentProcessId());
    const auto address=std::to_wstring(reinterpret_cast<std::uintptr_t>(testBytes));
    for(int i=1;i+1<argc;++i){const std::wstring key=argv[i];
        if(key==L"--pid")argv[i+1]=const_cast<wchar_t*>(pid.c_str());
        if(key==L"--address"||key==L"--base")argv[i+1]=const_cast<wchar_t*>(address.c_str());}
    ks::cli::registerProcessMemoryDump();return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-memory-dump-') as temp:
        root=Path(temp)
        source=HARNESS
        for key,path in {
            'COMMAND_HEADER':'KswordCLI/CommandRegistry.h',
            'DRIVER_HEADER':'Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h',
            'MODULE_HEADER':'shared/usermode/backend/process/ProcessModulesSupport.h',
            'MODULE_IOCTL':'shared/driver/KswordArkModuleIoctl.h',
            'DUMP_SOURCE':'KswordCLI/ProcessMemoryDump.cpp',
        }.items(): source=source.replace(key,(ROOT/path).as_posix())
        cpp=root/'fixture.cpp';cpp.write_text(source,encoding='utf-8');exe=root/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/W4','/WX','/DNOMINMAX','/DUNICODE','/D_UNICODE',str(cpp),
                        *[str(ROOT/p) for p in ('KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','shared/usermode/backend/Common.cpp')],
                        '/Fe:'+str(exe),'/link','Advapi32.lib','Psapi.lib'],cwd=root,check=True)
        expected=bytes(i%251 for i in range(150000))
        def run(mode,backend,output,module=False):
            args=[str(exe),mode,'process','module' if module else 'memory','dump','--pid','self',
                  '--base' if module else '--address','self']
            if not module:args+=['--size','150000']
            if mode=='r0-only':args+=['--creation-time','123']
            args+=['--output',str(output),'--backend',backend,'--json']
            p=subprocess.run(args,capture_output=True,timeout=15)
            try:data=json.loads(p.stdout.decode('utf-8'))
            except Exception:raise AssertionError((p.returncode,p.stdout,p.stderr))
            return p.returncode,data
        for backend in ('r3','r0'):
            path=root/(backend+'.bin');rc,data=run('ok',backend,path)
            assert rc==0 and data['backend']==backend and data['data']['complete'] and path.read_bytes()==expected,(rc,data)
        for mode,backend in [('short','r3'),('r0-short','r0'),('module-change','r3'),('r0-module-change','r0'),('r0-final-mismatch','r0')]:
            path=root/(mode+'.bin');rc,data=run(mode,backend,path,module='module-change' in mode)
            assert rc==6 and not data['data']['published'] and not path.exists(),(rc,data)
        path=root/'identity.bin';rc,data=run('r0-identity','r0',path)
        assert rc==3 and not data['data']['identityValid'] and not path.exists(),(rc,data)
        for mode,expected_rc in [('r0-malformed',4),('r0-unsupported',5)]:
            path=root/(mode+'.bin');rc,data=run(mode,'r0',path)
            assert rc==expected_rc and not data['data']['published'] and not path.exists(),(rc,data)
        path=root/'r0-only.bin';rc,data=run('r0-only','r0',path)
        assert rc==0 and data['data']['complete'] and not data['data']['target']['r3HandleRetained'] and path.read_bytes()==expected,(rc,data)
        path=root/'r0-only-module.bin';rc,data=run('r0-only','r0',path,module=True)
        assert rc==0 and data['data']['moduleRangeSource']=='R0 MEM_IMAGE observed span' and path.read_bytes()==expected,(rc,data)
        path=root/'module.bin';rc,data=run('ok','r3',path,module=True)
        assert rc==0 and data['data']['modulePath']=='fixture.dll' and path.read_bytes()==expected,(rc,data)
        path=root/'existing.bin';path.write_bytes(b'keep');rc,data=run('ok','r3',path)
        assert rc==6 and not data['data']['published'] and path.read_bytes()==b'keep',(rc,data)
        path=root/'cleanup.bin';rc,data=run('cleanup-failure','r3',path)
        temporary=Path(data['data']['temporaryPath'])
        assert rc==6 and not data['data']['temporaryRemoved'] and data['data']['temporaryCleanupWin32Error']==5 and temporary.is_file(),(rc,data)
        temporary.unlink()
        assert not list(root.glob('*.tmp'))
    print('PROCESS_MEMORY_DUMP_PASS: R3/R0, kernel-only identity, short read, module drift and no overwrite')

if __name__=='__main__': main()
