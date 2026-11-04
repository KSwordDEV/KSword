"""Exercise callback inventory and row removal against an isolated transport fixture."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import test_ksword_cli as base

ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''
    if (evidenceFixture && code == IOCTL_KSWORD_ARK_ENUM_CALLBACKS) {
        const auto& in = *static_cast<KSWORD_ARK_ENUM_CALLBACKS_REQUEST*>(input);
        struct Fixture { KSWORD_ARK_ENUM_CALLBACKS_RESPONSE r; KSWORD_ARK_CALLBACK_ENUM_ENTRY extra; } f{};
        auto& r = f.r; r.version = KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION;
        r.size = sizeof(r); r.entrySize = sizeof(r.entries[0]);
        r.snapshotHash = r.enumerationGeneration = 0x1234;
        r.flags = KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_HASH_VALID | KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_IDENTITY_HASH_VALID;
        r.totalCount = evidenceFixture == 2 || evidenceFixture == 4 || evidenceFixture == 5 ? 2 : 1;
        r.returnedCount = evidenceFixture == 2 ? 2 : 1;
        r.nextIndex = in.startIndex + r.returnedCount;
        if (evidenceFixture == 4 || evidenceFixture == 5) {
            if (in.startIndex == 0) { r.flags |= KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_MORE_DATA; r.nextIndex = 1; }
            else if (in.startIndex != 1 || in.expectedSnapshotHash != 0x1234 || in.expectedTotalCount != 2 ||
                in.snapshotPolicy != KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_REQUIRE_MATCH) return FALSE;
            if (evidenceFixture == 5 && in.startIndex == 1) r.snapshotHash = 0x5678;
        } else if (in.startIndex) return FALSE;
        if (evidenceFixture == 6) r.nextIndex = 2;
        auto* rows = reinterpret_cast<KSWORD_ARK_CALLBACK_ENUM_ENTRY*>(reinterpret_cast<unsigned char*>(&r) + offsetof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE, entries));
        for (unsigned i = 0; i < r.returnedCount; ++i) {
            auto& row = rows[i]; row.size = sizeof(row); row.callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT;
            row.status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK; row.source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE;
            row.fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE | KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH | KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION;
            row.callbackAddress = 0xffff800000001000ULL; row.registrationAddress = 0xffff800000002000ULL;
            row.rawStorageValue = 0xffff800000003000ULL; row.enumerationGeneration = 0x1234; row.identityHash = 0x1122;
            row.operationMask = 3; row.objectTypeMask = 1; row.trustFlags = 0xa5;
            row.removeBehavior = KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION;
            wcscpy_s(row.name, L"fixture \"object\"");
            if (evidenceFixture == 3) row.fieldFlags &= ~KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE;
            if ((evidenceFixture == 4 || evidenceFixture == 5) && in.startIndex == 0) row.identityHash = 0x9999;
            if (evidenceFixture == 7) {
                row.callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS;
                row.source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY;
                row.registrationType = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_LEGACY;
                row.trustFlags = KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN;
                row.removeBehavior = 0;
            }
            if (evidenceFixture == 8) { row.callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY; row.removeBehavior = 0; }
        }
        const DWORD n = static_cast<DWORD>(offsetof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE, entries) + r.returnedCount * sizeof(r.entries[0]));
        if (capacity < n || sizeof(f) < n) return FALSE;
        memcpy(output, &f, n); *bytes = n; return TRUE;
    }
    if (evidenceFixture && code == IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX) {
        const auto& in = *static_cast<KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST*>(input);
        const auto expectedClass = evidenceFixture == 7 ? KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS : KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT;
        const auto expectedSource = evidenceFixture == 7 ? KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY : KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE;
        const auto expectedTrust = evidenceFixture == 7 ? KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN : 0xa5;
        if (in.callbackClass != expectedClass || in.identityHash != 0x1122 ||
            in.registrationAddress != 0xffff800000002000ULL || in.rawStorageValue != 0xffff800000003000ULL ||
            in.trustFlags != expectedTrust || in.source != expectedSource ||
            (in.flags & KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_REQUIRE_REVALIDATION) == 0 ||
            in.removeBehavior != (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION)) {
            SetLastError(ERROR_INVALID_DATA); return FALSE;
        }
        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE r{};
        r.size = sizeof(r); r.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
        r.callbackClass = in.callbackClass; r.callbackAddress = in.callbackAddress; r.registrationAddress = in.registrationAddress;
        r.identityHash = in.identityHash; r.ntstatus = 0; r.revalidationStatus = 0;
        if (capacity < sizeof(r)) return FALSE;
        memcpy(output, &r, sizeof(r)); *bytes = sizeof(r); return TRUE;
    }
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-cli-callback-") as tmp:
        directory = Path(tmp)
        extended = (ROOT / "KswordCLI/ArkDriverExtended.cpp").read_text(encoding="utf-8-sig")
        helpers = extended[extended.index("    std::wstring utf8ToWide"):extended.index("    void printBytes")]
        helpers += re.search(r"(?ms)^    template <typename Result>\n    int finishResult.*?^    }", extended).group(0)
        harness = base.HARNESS.replace('DWORD code, LPVOID, DWORD, LPVOID output', 'DWORD code, LPVOID input, DWORD, LPVOID output')
        harness = harness.replace('    if (argc > 1 && std::wstring(argv[1]) == L"--evidence-unavailable")',
            '    if (argc > 1 && std::wstring(argv[1]) == L"--evidence-changed") { evidenceFixture = 5; ++argv; --argc; }\n'
            '    else if (argc > 1 && std::wstring(argv[1]) == L"--evidence-bad-page") { evidenceFixture = 6; ++argv; --argc; }\n'
            '    else if (argc > 1 && std::wstring(argv[1]) == L"--evidence-legacy-candidate") { evidenceFixture = 7; ++argv; --argc; }\n'
            '    else if (argc > 1 && std::wstring(argv[1]) == L"--evidence-no-registry-proof") { evidenceFixture = 8; ++argv; --argc; }\n'
            '    else if (argc > 1 && std::wstring(argv[1]) == L"--evidence-unavailable")')
        harness = harness.replace('    *bytes = 0; SetLastError(ioctlError); return FALSE;', MOCK + '\n    *bytes = 0; SetLastError(ioctlError); return FALSE;')
        harness = harness.replace('#include "TYPES_HEADER"', '#include "TYPES_HEADER"\n#include "' + (ROOT / 'shared/driver/KswordArkCallbackIoctl.h').as_posix() + '"')
        for key, path in [("CLI_SOURCE", "KswordCLI/KswordCLI.cpp"), ("CORE_SOURCE", "KswordCLI/CliCore.cpp"), ("TYPES_HEADER", "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverTypes.h")]:
            harness = harness.replace(key, (ROOT / path).as_posix())
        source = directory / "fixture.cpp"
        source.write_text(harness.replace("/*EXTENDED_HELPERS*/", helpers), encoding="utf-8")
        exe = directory / "fixture.exe"
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/O2", str(source),
            *[str(ROOT / ("KswordCLI/" + x)) for x in ("CommandRegistry.cpp", "CliArgs.cpp", "CliText.cpp")],
            "/Fe:" + str(exe), "/link", "Iphlpapi.lib", "Ws2_32.lib", "Setupapi.lib", "Ole32.lib"], cwd=tmp, check=True)
        def run(mode, *args):
            return subprocess.run([str(exe), mode, *args], capture_output=True, timeout=10)
        enum = run("--evidence-unavailable", "callback", "enum", "--json")
        assert enum.returncode == 0, enum.stderr
        row = json.loads(enum.stdout)["data"]["rows"][0]
        assert row["className"] == "object" and row["removeClass"] == 4 and row["trustFlags"] == "0xa5" and row["removeBehavior"] == "0x5", row
        assert row["name"] == 'fixture "object"', row
        removed = run("--evidence-unavailable", "callback", "remove-row", "--identity-hash", "0x1122", "--confirm", "--json")
        assert removed.returncode == 0 and json.loads(removed.stdout)["data"]["identityHash"] == "0x1122", (removed.stdout, removed.stderr)
        legacy = run("--evidence-legacy-candidate", "callback", "remove-row", "--identity-hash", "0x1122", "--confirm", "--json")
        assert legacy.returncode == 0 and json.loads(legacy.stdout)["data"]["className"] == "process", (legacy.stdout, legacy.stderr)
        registry = run("--evidence-no-registry-proof", "callback", "remove-row", "--identity-hash", "0x1122", "--confirm", "--json")
        assert registry.returncode == 5 and json.loads(registry.stdout)["status"] == "unavailable", (registry.stdout, registry.stderr)
        paged = run("--evidence-partial", "callback", "remove-row", "--identity-hash", "0x1122", "--confirm", "--json")
        assert paged.returncode == 0 and json.loads(paged.stdout)["data"]["identityHash"] == "0x1122", (paged.stdout, paged.stderr)
        changed = run("--evidence-changed", "callback", "remove-row", "--identity-hash", "0x1122", "--confirm", "--json")
        assert changed.returncode == 4 and json.loads(changed.stdout)["status"] == "failed", (changed.stdout, changed.stderr)
        bad_page = run("--evidence-bad-page", "callback", "remove-row", "--identity-hash", "0x1122", "--confirm", "--json")
        assert bad_page.returncode == 4 and json.loads(bad_page.stdout)["status"] == "failed", (bad_page.stdout, bad_page.stderr)
        named = run("--evidence-unavailable", "callback", "remove-ex", "--class", "object", "--callback", "0xffff800000001000",
            "--registration", "0xffff800000002000", "--raw-storage", "0xffff800000003000", "--identity-hash", "0x1122",
            "--source", "10", "--trust-flags", "0xa5", "--remove-behavior", "5", "--flags", "2", "--confirm")
        assert named.returncode == 0, (named.stdout, named.stderr)
        duplicate = run("--evidence-available", "callback", "remove-row", "--identity-hash", "0x1122", "--confirm", "--json")
        assert duplicate.returncode == 4 and b"ambiguous" in duplicate.stderr and json.loads(duplicate.stdout)["status"] == "failed", duplicate.stderr
        unavailable = run("--evidence-unresolved", "callback", "remove-row", "--identity-hash", "0x1122", "--confirm")
        assert unavailable.returncode == 5 and b"lacks" in unavailable.stderr.lower(), unavailable.stderr
        missing = run("--evidence-unavailable", "callback", "remove-row", "--identity-hash", "0x9999", "--confirm")
        assert missing.returncode == 3 and b"not found" in missing.stderr, missing.stderr
        empty = run("--evidence-unavailable", "callback", "enum", "--limit", "0", "--json")
        assert empty.returncode == 0 and json.loads(empty.stdout)["data"]["queried"] is False, empty.stdout
        no_driver = subprocess.run([str(exe), "--missing-device", "callback", "enum", "--json"], capture_output=True, timeout=10)
        assert no_driver.returncode == 2 and json.loads(no_driver.stdout)["status"] == "failed", (no_driver.stdout, no_driver.stderr)
        print("CALLBACK_INVENTORY_PASS complete identity, JSON, unique row and removal packet")


if __name__ == "__main__":
    main()
