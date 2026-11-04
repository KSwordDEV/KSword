"""Test the production IRP command using a simulated DriverClient."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "CommandRegistry.h"
#include "ArkDriverClient.h"
#include <cassert>
#include <fcntl.h>
#include <io.h>
#include <string>
static std::wstring fixtureMode;
static unsigned submitted = 0;
namespace ksword::ark {
FileIrpSubmitResult DriverClient::submitFileIrp(const FileIrpSubmitRequestParams& req) const {
    ++submitted; FileIrpSubmitResult r{};
    assert(req.ntPath == L"\\??\\C:\\fixture.bin");
    assert(req.uiConfirmed && req.allowDangerous == (fixtureMode == L"dangerous") && req.targetLayer == 1);
    if (fixtureMode == L"missing") { r.io.deviceOpenFailed = true; r.io.win32Error = ERROR_FILE_NOT_FOUND; return r; }
    r.io.ok = true; r.majorFunction = req.majorFunction; r.minorFunction = req.minorFunction; r.resolvedLayer = req.targetLayer;
    r.status = KSWORD_ARK_FILE_IRP_STATUS_OK;
    r.stageFlags = KSWORD_ARK_FILE_IRP_STAGE_CREATE | KSWORD_ARK_FILE_IRP_STAGE_CLOSE;
    if (req.majorFunction != 0) r.stageFlags |= KSWORD_ARK_FILE_IRP_STAGE_OPERATION;
    r.information = req.majorFunction == 4 ? req.inputData.size() : req.outputBytes;
    if (req.majorFunction == 3) r.outputData.assign(req.outputBytes, 0x41);
    if (fixtureMode == L"short") { r.information = 2; if (!r.outputData.empty()) r.outputData.resize(2); }
    if (fixtureMode == L"fail") r.operationStatus = static_cast<long>(0xc0000022U);
    if (fixtureMode == L"cleanup") r.closeStatus = static_cast<long>(0xc0000022U);
    if (fixtureMode == L"timeout") r.status = KSWORD_ARK_FILE_IRP_STATUS_TIMEOUT;
    if (fixtureMode == L"nttimeout") r.operationStatus = 0x102;
    if (fixtureMode == L"truncated") r.stageFlags |= KSWORD_ARK_FILE_IRP_STAGE_OUTPUT_TRUNCATED;
    if (fixtureMode == L"writeflag") r.stageFlags |= KSWORD_ARK_FILE_IRP_STAGE_OUTPUT_TRUNCATED;
    return r;
}
}
namespace ks::cli { void registerFileIrp(); }
int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_U8TEXT); _setmode(_fileno(stderr), _O_U8TEXT);
    fixtureMode = argv[1]; for (int i=1; i+1<argc; ++i) argv[i]=argv[i+1]; --argc;
    ks::cli::registerFileIrp(); const int code=ks::cli::dispatchR3(argc,argv).value_or(1);
    if (fixtureMode == L"invalid") assert(submitted == 0); else assert(submitted == 1);
    return code;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-cli-irp-") as temp:
        d = Path(temp)
        source = d / "fixture.cpp"
        source.write_text(SOURCE, encoding="utf-8")
        exe = d / "fixture.exe"
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/W4", "/WX",
                        "/I" + str(ROOT / "KswordCLI"), "/I" + str(ROOT / "Ksword5.1/Ksword5.1/ArkDriverClient"),
                        str(source), *[str(ROOT / "KswordCLI" / f) for f in ("CommandRegistry.cpp", "R3Input.cpp", "FileIrpCommand.cpp")],
                        "/Fe:" + str(exe)], cwd=d, check=True)
        def run(mode, major="3", extra=(), confirm=True):
            cmd = [str(exe), mode, "file", "irp", "submit", "--path", r"C:\fixture.bin", "--major", major,
                   "--layer", "1", "--output-bytes", "4", "--json", *extra]
            if confirm: cmd.append("--confirm")
            p = subprocess.run(cmd, capture_output=True)
            return p.returncode, json.loads(p.stdout.decode()), p.stderr
        for mode, expected in [("ok", 0), ("short", 6), ("fail", 3), ("cleanup", 6), ("timeout", 3), ("nttimeout", 3), ("truncated", 6), ("missing", 2)]:
            code, data, err = run(mode)
            assert code == expected and data["backend"] == "r0", (mode, code, data, err)
        code, data, _ = run("ok", "0")
        assert code == 0 and data["data"]["operationNtStatus"] is None
        code, data, _ = run("invalid", confirm=False)
        assert code == 1
        code, data, _ = run("dangerous", extra=("--allow-dangerous", "1"))
        assert code == 0
        code, data, _ = run("invalid", extra=("--flags", "1"))
        assert code == 1
        code, data, _ = run("missing")
        assert data["data"]["truncated"] is None and data["data"]["shortRead"] is None
        p = subprocess.run([str(exe), "invalid", "file", "irp", "submit", "--path", r"C:\fixture.bin", "--major", "3",
                            "--layer", "1", "--output-bytes", "262145", "--confirm", "--json"], capture_output=True)
        assert p.returncode == 1
        # WRITE has no output buffer; the driver stage bit can represent byte-count
        # information rather than output truncation and must not turn a full write partial.
        p = subprocess.run([str(exe), "writeflag", "file", "irp", "submit", "--path", r"C:\fixture.bin", "--major", "4",
                            "--layer", "1", "--input-hex", "01020304", "--confirm", "--json"], capture_output=True)
        assert p.returncode == 0 and json.loads(p.stdout)["data"]["shortWrite"] is False, p.stdout
        p = subprocess.run([str(exe), "short", "file", "irp", "submit", "--path", r"C:\fixture.bin", "--major", "4",
                            "--layer", "1", "--input-hex", "01020304", "--confirm", "--json"], capture_output=True)
        assert p.returncode == 6 and json.loads(p.stdout)["data"]["shortWrite"] is True, p.stdout
    print("CLI_FILE_IRP_PASS")


if __name__ == "__main__":
    main()
