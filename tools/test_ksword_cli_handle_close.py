"""Exercise CLI handle close dispatch and separate close/resume receipts."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "REGISTRY_HEADER_PATH"
#include "ARK_HEADER_PATH"
#include "FILE_HEADER_PATH"
#include <fcntl.h>
#include <io.h>
#include <cassert>
static std::wstring mode;
static void identity(std::uint32_t pid, std::uint64_t handle, std::uint64_t creation, std::uint64_t object) {
    assert(pid == 999999 && handle == 0x100 && creation == 0x1234 && object == 0xffff800000001000ULL);
}
namespace ksword::ark {
HandleCloseResult DriverClient::closeHandleDetailed(std::uint32_t pid, std::uint64_t handle, std::uint64_t creation, std::uint64_t object) const {
    identity(pid, handle, creation, object); HandleCloseResult result{};
    if (mode == L"r0-open") {result.io.deviceOpenFailed = true; result.io.win32Error = ERROR_FILE_NOT_FOUND; return result;}
    result.responseValid = true; result.io.ok = mode == L"r0-good";
    if (mode == L"r0-resume") result.resumeStatus = static_cast<long>(0xc0000001U);
    if (mode == L"r0-close") result.closeStatus = static_cast<long>(0xc0000022U);
    return result;
}
}
namespace ks::file {
RemoteHandleCloseResult CloseRemoteHandleByObjectIdentityDetailed(std::uint32_t pid, std::uint64_t handle, std::uint64_t creation, std::uint64_t object) {
    identity(pid, handle, creation, object); RemoteHandleCloseResult result{};
    result.suspendAttempted = result.resumeAttempted = true;
    result.closeAttempted = mode != L"r3-stale";
    result.closeSucceeded = mode == L"r3-good" || mode == L"r3-resume";
    result.success = mode == L"r3-good";
    if (mode == L"r3-resume") result.resumeStatus = static_cast<long>(0xc0000001U);
    return result;
}
}
int wmain(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U8TEXT); _setmode(_fileno(stderr), _O_U8TEXT);
    mode=argv[1]; for(int i=1;i+1<argc;++i) argv[i]=argv[i+1]; --argc;
    ks::cli::addFamily(L"handle",L"fixture"); ks::cli::registerHandleClose();
    return ks::cli::dispatchR3(argc,argv).value_or(99);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-handle-command-") as temp:
        root = Path(temp)
        source = SOURCE
        for name, path in {
            "REGISTRY_HEADER_PATH": "KswordCLI/CommandRegistry.h",
            "ARK_HEADER_PATH": "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h",
            "FILE_HEADER_PATH": "Ksword5.1/Ksword5.1/ksword/file/file_handle_tools.h",
        }.items():
            source = source.replace(name, (ROOT / path).as_posix())
        # The registry declaration is normally supplied by the production header.
        source = source.replace('static std::wstring mode;', 'namespace ks::cli { void registerHandleClose(); }\nstatic std::wstring mode;')
        cpp = root / "fixture.cpp"
        cpp.write_text(source, encoding="utf-8")
        exe = root / "fixture.exe"
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/O2", str(cpp),
                        str(ROOT / "KswordCLI/CommandRegistry.cpp"), str(ROOT / "KswordCLI/HandleCloseCommand.cpp"),
                        "/Fe:" + str(exe)], cwd=root, check=True)
        identity = ["--pid", "999999", "--handle", "0x100", "--creation-time", "0x1234", "--object", "0xffff800000001000"]
        def run(mode, backend, code, confirm=True):
            args = [str(exe), mode, "handle", "close", *identity, "--backend", backend, "--json"]
            if confirm: args.append("--confirm")
            result = subprocess.run(args, capture_output=True, timeout=10)
            assert result.returncode == code, (mode, result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)
        assert run("r3-good", "r3", 0)["data"]["closeSucceeded"]
        partial = run("r3-resume", "r3", 6)["data"]
        assert partial["closeSucceeded"] and partial["resumeStatus"] == "0xc0000001"
        assert not run("r3-stale", "r3", 3)["data"]["closeAttempted"]
        assert run("r0-good", "r0", 0)["backend"] == "r0"
        partial = run("r0-resume", "r0", 6)["data"]
        assert partial["closeSucceeded"] and partial["resumeStatus"] == "0xc0000001"
        assert run("r0-close", "r0", 3)["data"]["closeStatus"] == "0xc0000022"
        assert run("r0-open", "r0", 2)["data"]["closeStatus"] is None
        run("r3-good", "r3", 1, confirm=False)
        print("HANDLE_CLOSE_CLI_PASS backend dispatch, identities, confirmation, partial close and recovery")


if __name__ == "__main__":
    main()
