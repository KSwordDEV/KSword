"""Exercise CLI decoding of legacy driver responses using the production transport fixture."""
from pathlib import Path
import re
import subprocess
import tempfile
import test_ksword_cli as base

ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''
    if (evidenceFixture && code == IOCTL_KSWORD_ARK_QUERY_PREFLIGHT) {
        struct Fixture { KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE r; KSWORD_ARK_PREFLIGHT_CHECK_ENTRY extra; } f{};
        f.r.version = KSWORD_ARK_PREFLIGHT_PROTOCOL_VERSION; f.r.entrySize = sizeof(f.r.checks[0]);
        f.r.totalCheckCount = f.r.returnedCheckCount = 2;
        auto* entries = reinterpret_cast<KSWORD_ARK_PREFLIGHT_CHECK_ENTRY*>(reinterpret_cast<unsigned char*>(&f.r) + offsetof(KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE, checks));
        entries[0].checkId = 1; entries[0].status = KSWORD_ARK_PREFLIGHT_STATUS_PASS;
        strcpy_s(entries[0].checkName, "Driver build");
        entries[1].checkId = 7; entries[1].status = KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN;
        strcpy_s(entries[1].checkName, "Signing pipeline");
        const DWORD n = static_cast<DWORD>(offsetof(KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE, checks) + 2 * sizeof(*entries) + 4);
        if (capacity < n || sizeof(f) < n) return FALSE;
        memcpy(output, &f, n); *bytes = n; return TRUE;
    }
    if (evidenceFixture && code == IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS) {
        KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE r{};
        r.version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION; r.size = offsetof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE, entries); r.status = KSWORD_ARK_NETWORK_STATUS_APPLIED;
        r.entrySize = sizeof(r.entries[0]); r.totalRowCount = r.returnedRowCount = 1;
        r.sourceFlags = KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE; r.budgetRows = 1;
        r.entries[0].addressFamily = KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4;
        r.entries[0].protocol = KSWORD_ARK_NETWORK_PROTOCOL_TCP; r.entries[0].state = 5;
        r.entries[0].sourceFlags = KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
        if (capacity < sizeof(r)) return FALSE;
        memcpy(output, &r, sizeof(r)); *bytes = sizeof(r); return TRUE;
    }
    if (evidenceFixture && code == IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS) {
        KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE r{};
        r.version = KSWORD_ARK_SECTION_PROTOCOL_VERSION; r.entrySize = sizeof(r.mappings[0]);
        r.totalCount = r.returnedCount = 1; r.mappings[0].startVa = 0x3000; r.mappings[0].endVa = 0x1000;
        if (capacity < sizeof(r)) return FALSE;
        memcpy(output, &r, sizeof(r)); *bytes = sizeof(r); return TRUE;
    }
    if (evidenceFixture && code == IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT) {
        KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE r{};
        r.version = KSWORD_ARK_STORAGE_PROTOCOL_VERSION; r.rowSize = sizeof(r.rows[0]);
        r.totalRows = r.returnedRows = 1; r.rows[0].volumeDeviceName[0] = 1;
        r.rows[0].fieldFlags = KSWORD_ARK_STORAGE_FIELD_NT_DEVICE_PATH_PRESENT;
        if (capacity < sizeof(r)) return FALSE;
        memcpy(output, &r, sizeof(r)); *bytes = sizeof(r); return TRUE;
    }
'''

def main():
    with tempfile.TemporaryDirectory(prefix="ksword-cli-protocol-") as temp:
        temp = Path(temp)
        extended = (ROOT / "KswordCLI/ArkDriverExtended.cpp").read_text(encoding="utf-8-sig")
        helpers = extended[extended.index("    std::wstring utf8ToWide"):extended.index("    void printBytes")]
        helpers += re.search(r"(?ms)^    template <typename Result>\n    int finishResult.*?^    }", extended).group(0)
        harness = base.HARNESS.replace('    *bytes = 0; SetLastError(ioctlError); return FALSE;', MOCK + '\n    *bytes = 0; SetLastError(ioctlError); return FALSE;')
        for key, path in [("CLI_SOURCE", "KswordCLI/KswordCLI.cpp"), ("CORE_SOURCE", "KswordCLI/CliCore.cpp"), ("TYPES_HEADER", "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverTypes.h")]:
            harness = harness.replace(key, (ROOT / path).as_posix())
        harness = harness.replace('#include "TYPES_HEADER"', '#include "TYPES_HEADER"\n#include "' + (ROOT / 'shared/driver/KswordArkPreflightIoctl.h').as_posix() + '"') if 'TYPES_HEADER' in harness else harness.replace('#include "' + (ROOT / 'Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverTypes.h').as_posix() + '"', '#include "' + (ROOT / 'Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverTypes.h').as_posix() + '"\n#include "' + (ROOT / 'shared/driver/KswordArkPreflightIoctl.h').as_posix() + '"')
        source = temp / "test.cpp"
        source.write_text(harness.replace("/*EXTENDED_HELPERS*/", helpers), encoding="utf-8")
        exe = temp / "test.exe"
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/O2", str(source),
            *[str(ROOT / ("KswordCLI/" + x)) for x in ("CommandRegistry.cpp", "CliArgs.cpp", "CliText.cpp")],
            "/Fe:" + str(exe), "/link", "Iphlpapi.lib", "Ws2_32.lib", "Setupapi.lib", "Ole32.lib"], cwd=temp, check=True)
        def run(*args):
            p = subprocess.run([str(exe), "--evidence-unavailable", *args], capture_output=True, timeout=10)
            return p.returncode, p.stdout.decode("utf-8", errors="replace"), p.stderr.decode("utf-8", errors="replace")
        rc, out, err = run("preflight", "query")
        assert rc == 0 and "id=1 status=1" in out and "Driver build" in out and "Signing pipeline" in out and "statusName=not-run" in out and "externalChecks=not-run" in out, (rc, out, err)
        rc, out, err = run("network", "tcp")
        assert rc == 6 and "completeR0=0 partial=1" in out and "state=unknown" in out and "state=5" not in out, (rc, out, err)
        rc, out, err = run("section", "query-file-mappings", "--path", r"C:\a.txt")
        assert rc == 6 and "mappingEvidence=unverified" in out and "invalid range" in out and "start=0x" not in out, (rc, out, err)
        rc, out, err = run("file", "bitlocker")
        assert "volume='<unavailable>'" in out and "protection=unknown" in out and "\x01" not in out, (rc, out, err)
        print("protocol response fixture passed")

if __name__ == "__main__":
    main()
