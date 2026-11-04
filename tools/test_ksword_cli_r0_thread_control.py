"""Exercise R0 thread CLI identity and receipt semantics with an owned worker.

The fake driver calls only operate on a thread created by this fixture; no
KswordARK driver or existing process/thread is touched.
"""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "REGISTRY"
#include "DRIVER"
#include <cassert>
#include <io.h>
#include <fcntl.h>
static std::wstring mode;
static unsigned calls = 0;
namespace ksword::ark {
IoResult DriverClient::deviceIoControl(unsigned long code, void* input, unsigned long inputBytes,
    void* output, unsigned long outputBytes, DriverHandle*) const {
    ++calls; IoResult io{};
    if (mode == L"missing-device") { io.deviceOpenFailed = true; io.win32Error = ERROR_FILE_NOT_FOUND; return io; }
    if (mode == L"old-driver") { io.win32Error = ERROR_INVALID_FUNCTION; return io; }
    assert(code == IOCTL_KSWORD_ARK_CONTROL_THREAD_VERIFIED);
    assert(inputBytes == sizeof(KSWORD_ARK_CONTROL_THREAD_VERIFIED_REQUEST));
    assert(outputBytes == sizeof(KSWORD_ARK_CONTROL_THREAD_VERIFIED_RESPONSE));
    const auto request = *static_cast<KSWORD_ARK_CONTROL_THREAD_VERIFIED_REQUEST*>(input);
    assert(request.processId == GetCurrentProcessId());
    const HANDLE h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE, FALSE, request.threadId); assert(h);
    FILETIME c{},x{},k{},u{},pc{}; assert(GetThreadTimes(h,&c,&x,&k,&u)); assert(GetProcessTimes(GetCurrentProcess(),&pc,&x,&k,&u));
    auto& response = *static_cast<KSWORD_ARK_CONTROL_THREAD_VERIFIED_RESPONSE*>(output);
    response = {}; response.size = sizeof(response); response.version = KSWORD_ARK_THREAD_VERIFIED_VERSION;
    response.processId = request.processId; response.threadId = request.threadId; response.action = request.action;
    response.processCreationTime100ns = (static_cast<ULONGLONG>(pc.dwHighDateTime)<<32)|pc.dwLowDateTime;
    response.threadCreationTime100ns = (static_cast<ULONGLONG>(c.dwHighDateTime)<<32)|c.dwLowDateTime;
    if (mode == L"kernel-mismatch" || (request.action != KSWORD_ARK_THREAD_VERIFIED_QUERY &&
        (request.expectedProcessCreationTime100ns != response.processCreationTime100ns ||
         request.expectedThreadCreationTime100ns != response.threadCreationTime100ns))) response.status = static_cast<LONG>(0xc000022dU);
    else {
        response.fieldFlags = KSWORD_ARK_THREAD_VERIFIED_FIELD_IDENTITY;
        if (request.action == KSWORD_ARK_THREAD_VERIFIED_SUSPEND || request.action == KSWORD_ARK_THREAD_VERIFIED_RESUME) {
            const DWORD prior = request.action == KSWORD_ARK_THREAD_VERIFIED_SUSPEND ? SuspendThread(h) : ResumeThread(h);
            assert(prior != DWORD(-1)); response.previousSuspendCount = prior;
            response.fieldFlags |= KSWORD_ARK_THREAD_VERIFIED_FIELD_PREVIOUS_COUNT;
        } else if (request.action == KSWORD_ARK_THREAD_VERIFIED_TERMINATE) assert(TerminateThread(h, static_cast<DWORD>(request.exitStatus)));
    }
    io.ok = true; io.bytesReturned = sizeof(response); CloseHandle(h); return io;
}
IoResult DriverClient::controlDriverThread(std::uint32_t tid, std::uint64_t address, std::uint64_t birth,
    unsigned long action, unsigned long method, bool confirmed) const {
    ++calls; assert(tid == 7 && address == 0x1234 && birth == 8);
    assert(confirmed == (action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME));
    assert((action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE) == (method != 0));
    IoResult result{}; result.ok = true; return result;
}
}
namespace ks::cli {void registerR0ThreadControl();}
static DWORD WINAPI worker(void* value) { WaitForSingleObject(static_cast<HANDLE>(value), INFINITE); return 0; }
int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_U8TEXT); _setmode(_fileno(stderr), _O_U8TEXT);
    mode = argv[1]; for (int i=1; i+1<argc; ++i) argv[i] = argv[i+1]; --argc;
    const HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr); DWORD tid=0;
    const HANDLE thread = CreateThread(nullptr, 0, worker, event, 0, &tid); assert(event && thread);
    FILETIME c{},x{},k{},u{},pc{}; assert(GetThreadTimes(thread,&c,&x,&k,&u));
    assert(GetProcessTimes(GetCurrentProcess(),&pc,&x,&k,&u));
    const auto pidText=std::to_wstring(GetCurrentProcessId()), tidText=std::to_wstring(tid);
    const auto processBirth=std::to_wstring((static_cast<ULONGLONG>(pc.dwHighDateTime)<<32)|pc.dwLowDateTime);
    const auto birthValue=(static_cast<ULONGLONG>(c.dwHighDateTime)<<32)|c.dwLowDateTime;
    const auto birth=std::to_wstring(mode == L"mismatch" ? birthValue+1 : birthValue);
    const bool driverCommand = argc>2 && std::wstring(argv[2])==L"driver";
    if (!driverCommand) for (int i=1; i+1<argc; ++i) {
        const std::wstring option=argv[i];
        if (option==L"--pid") argv[i+1]=const_cast<wchar_t*>(pidText.c_str());
        if (option==L"--tid") argv[i+1]=const_cast<wchar_t*>(tidText.c_str());
        if (option==L"--creation-time") argv[i+1]=const_cast<wchar_t*>(processBirth.c_str());
        if (option==L"--thread-creation-time") argv[i+1]=const_cast<wchar_t*>(birth.c_str());
    }
    if (mode == L"resume") assert(SuspendThread(thread) != DWORD(-1));
    ks::cli::registerR0ThreadControl();
    const auto result = ks::cli::dispatchR3(argc,argv).value_or(1);
    if (mode == L"mismatch" || mode == L"no-confirm") assert(calls == 0);
    if (mode == L"suspend" && calls) assert(ResumeThread(thread) != DWORD(-1));
    SetEvent(event); WaitForSingleObject(thread,2000); CloseHandle(thread); CloseHandle(event);
    return result;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-r0-thread-") as temp:
        root = Path(temp)
        source = SOURCE.replace('"REGISTRY"', '"' + (ROOT / "KswordCLI/CommandRegistry.h").as_posix() + '"').replace(
            '"DRIVER"', '"' + (ROOT / "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h").as_posix() + '"')
        fixture = root / "fixture.cpp"
        fixture.write_text(source, encoding="utf-8")
        binary = root / "fixture.exe"
        sources = ["KswordCLI/CommandRegistry.cpp", "KswordCLI/R0ThreadControl.cpp", "shared/usermode/backend/Common.cpp"]
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/O2", "/DNOMINMAX", "/DUNICODE", "/D_UNICODE",
                        str(fixture), *[str(ROOT / name) for name in sources], "/Fe:" + str(binary), "/link", "Advapi32.lib"], cwd=root, check=True)

        def run(mode, command, expected, extra=()):
            arguments = [str(binary), mode, *command]
            result = subprocess.run(arguments + list(extra) + ["--json"], capture_output=True, timeout=15)
            assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)

        common = ["--pid", "self", "--creation-time", "self", "--tid", "self", "--thread-creation-time", "self", "--confirm"]
        identity = run("identity", ["thread", "r0", "identity", "--pid", "self", "--tid", "self"], 0)
        assert identity["backend"] == "r0" and identity["data"]["identityMatched"]
        for action in ("suspend", "resume", "terminate"):
            result = run(action, ["thread", "r0", action, *common], 0)
            assert result["backend"] == "r0" and result["data"]["verified"]
        mismatch = run("mismatch", ["thread", "r0", "suspend", *common], 3)
        assert not mismatch["data"]["requestAttempted"]
        missing = run("missing-device", ["thread", "r0", "suspend", *common], 2)
        assert missing["data"]["deviceOpenFailed"]
        old = run("old-driver", ["thread", "r0", "suspend", *common], 5)
        assert not old["data"]["requestSucceeded"]
        rejected = run("kernel-mismatch", ["thread", "r0", "suspend", *common], 3)
        assert rejected["data"]["ntStatus"] == "0xc000022d" and not rejected["data"]["requestSucceeded"]
        for action in ("suspend", "resume", "terminate"):
            args = ["thread", "driver", action, "--tid", "7", "--start-address", "0x1234", "--thread-creation-time", "8", "--confirm"]
            if action == "terminate": args += ["--method", "normal-apc"]
            data = run("driver", args, 6)["data"]
            assert data["requestSucceeded"] and not data["effectConfirmed"]
        print("R0_THREAD_CONTROL_PASS identity, suspend/resume/terminate readback, device error and System receipt")


if __name__ == "__main__":
    main()
