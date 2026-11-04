"""Exercise backend selection in the production command registry."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "CommandRegistry.h"
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
using namespace ks::cli;
int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_U8TEXT);
    auto action=[](const Args& a){return Result{0, Json::object({{L"selected",Json::string(a.get(L"--backend",L"default"))}})};};
    Command both{L"test both",L"test both [--backend r0|r3] [--json]",L"",L"",L"",action}; both.supportsR0=true; addCommand(both);
    addCommand({L"test kernel",L"test kernel",L"legacy help placeholder",L"",L""});
    Command kernel{L"test kernel",L"test kernel [--backend r0] [--json]",L"",L"",L"",action}; kernel.supportsR0=true;kernel.supportsR3=false;kernel.defaultBackend=L"r0";addCommand(kernel);
    Command user{L"test user",L"test user [--backend r3] [--json]",L"",L"",L"",action}; addCommand(user);
    auto result=dispatchR3(argc,argv); return result.value_or(10);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-cli-backend-") as temp:
        directory = Path(temp)
        source = directory / "backend.cpp"
        source.write_text(SOURCE, encoding="utf-8")
        exe = directory / "backend.exe"
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/W4", "/WX",
                        "/I" + str(ROOT / "KswordCLI"), str(source),
                        str(ROOT / "KswordCLI/CommandRegistry.cpp"), "/Fe:" + str(exe)],
                       cwd=directory, check=True)
        for command, extra, code, backend in [
            ("both", [], 0, "r3"), ("both", ["--backend", "r0"], 0, "r0"),
            ("kernel", [], 0, "r0"), ("kernel", ["--backend", "r3"], 1, "r3"),
            ("user", ["--backend", "r0"], 1, "r0"), ("both", ["--backend", "bad"], 1, "bad"),
        ]:
            result = subprocess.run([str(exe), "test", command, *extra, "--json"], capture_output=True, check=False)
            assert result.returncode == code, (command, extra, result.returncode, result.stderr)
            assert json.loads(result.stdout)["backend"] == backend
    print("CLI_BACKEND_DISPATCH_PASS")


if __name__ == "__main__":
    main()
