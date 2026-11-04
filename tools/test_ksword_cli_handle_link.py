"""Link handle-close CLI against the actual shared R3 and R0 implementations."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "REGISTRY_HEADER"
#include <fcntl.h>
#include <io.h>
namespace ks::cli { void registerHandleClose(); }
int wmain(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U8TEXT); _setmode(_fileno(stderr), _O_U8TEXT);
    ks::cli::addFamily(L"handle",L"fixture"); ks::cli::registerHandleClose();
    return ks::cli::dispatchR3(argc,argv).value_or(99);
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix="ksword-handle-link-") as temp:
        directory = Path(temp)
        source = directory / "main.cpp"
        source.write_text(SOURCE.replace("REGISTRY_HEADER", (ROOT / "KswordCLI/CommandRegistry.h").as_posix()), encoding="utf-8")
        exe = directory / "fixture.exe"
        files = ["KswordCLI/CommandRegistry.cpp", "KswordCLI/HandleCloseCommand.cpp",
                 "Ksword5.1/Ksword5.1/ksword/file/file_handle_tools.cpp",
                 "Ksword5.1/Ksword5.1/ksword/process/process.cpp", "Ksword5.1/Ksword5.1/ksword/string/string.cpp",
                 "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.cpp",
                 "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverError.cpp",
                 "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverHandle.cpp"]
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/O2", "/Gy", "/DNOMINMAX", "/DUNICODE", "/D_UNICODE",
                        str(source), *[str(ROOT / f) for f in files], "/Fe:" + str(exe), "/link", "/OPT:REF",
                        "Iphlpapi.lib", "Ws2_32.lib", "Setupapi.lib", "Dnsapi.lib", "Ole32.lib", "OleAut32.lib",
                        "Advapi32.lib", "Shell32.lib", "Taskschd.lib", "Uuid.lib", "Version.lib", "Wintrust.lib"], cwd=directory, check=True)
        result = subprocess.run([str(exe), "handle", "close", "--pid", "4", "--handle", "1", "--creation-time", "1", "--object", "1", "--confirm", "--json"], capture_output=True, timeout=10)
        assert result.returncode == 1, (result.returncode, result.stdout, result.stderr)
        print("HANDLE_CLOSE_REAL_LINK_PASS")

if __name__ == "__main__":
    main()
