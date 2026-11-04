"""Verify handle enumeration accepts old rows and exposes new owner identity."""
from pathlib import Path
import re
import subprocess
import tempfile
import test_ksword_cli as base

ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''
    if (evidenceFixture && code == IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES) {
        KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE r{};
        r.version = 2; r.entrySize = evidenceFixture == 1 ? KSWORD_ARK_HANDLE_ENTRY_LEGACY_SIZE : sizeof(r.entries[0]);
        r.totalCount = r.returnedCount = 1; r.processId = 123;
        r.entries[0].processId = 123; r.entries[0].handleValue = 8; r.entries[0].objectAddress = 0xffff800000001000ULL;
        r.entries[0].processCreationTime100ns = 123456789ULL;
        const DWORD n = static_cast<DWORD>(sizeof(r) - sizeof(r.entries[0]) + r.entrySize);
        if (capacity < n) return FALSE;
        memcpy(output, &r, n); *bytes = n; return TRUE;
    }
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-handle-identity-") as temp:
        directory = Path(temp)
        extended = (ROOT / "KswordCLI/ArkDriverExtended.cpp").read_text(encoding="utf-8-sig")
        helpers = extended[extended.index("    std::wstring utf8ToWide"):extended.index("    void printBytes")]
        helpers += re.search(r"(?ms)^    template <typename Result>\n    int finishResult.*?^    }", extended).group(0)
        harness = base.HARNESS.replace('    *bytes = 0; SetLastError(ioctlError); return FALSE;', MOCK + '\n    *bytes = 0; SetLastError(ioctlError); return FALSE;')
        for key, path in [("CLI_SOURCE", "KswordCLI/KswordCLI.cpp"), ("CORE_SOURCE", "KswordCLI/CliCore.cpp"),
                          ("TYPES_HEADER", "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverTypes.h")]:
            harness = harness.replace(key, (ROOT / path).as_posix())
        source = directory / "handle.cpp"
        source.write_text(harness.replace("/*EXTENDED_HELPERS*/", helpers), encoding="utf-8")
        exe = directory / "handle.exe"
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/O2", str(source),
                        *[str(ROOT / "KswordCLI" / f) for f in ("CommandRegistry.cpp", "CliArgs.cpp", "CliText.cpp")],
                        "/Fe:" + str(exe), "/link", "Iphlpapi.lib", "Ws2_32.lib", "Setupapi.lib", "Ole32.lib"],
                       cwd=directory, check=True)
        for mode, expected in [("--evidence-unavailable", b"creationTime=unavailable"),
                               ("--evidence-available", b"creationTime=123456789")]:
            result = subprocess.run([str(exe), mode, "handle", "enum", "--pid", "123"], capture_output=True)
            assert result.returncode == 0 and expected in result.stdout, (mode, result.returncode, result.stdout, result.stderr)
    print("CLI_HANDLE_IDENTITY_PASS")


if __name__ == "__main__":
    main()
