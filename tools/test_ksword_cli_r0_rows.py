"""Exercise the production R0 row printers with parsed client results.

Run in an x64 VS developer shell. No driver or VM is required.
"""
from pathlib import Path
import subprocess
import tempfile
import json

ROOT = Path(__file__).resolve().parents[1]
extended = (ROOT / "KswordCLI/ArkDriverExtended.cpp").read_text(encoding="utf-8-sig")
utf8 = extended[extended.index("    std::wstring utf8ToWide"):extended.index("    template <typename T, typename = void>")]
state = extended[extended.index("    template <typename T, typename = void>"):extended.index("    void printBytes")]
rows = extended[extended.index("    // The protocol strings are fixed-size arrays"):extended.index("    std::uint32_t parseUnloadedSource")]
finish = extended[extended.index("    template <typename Result>\n    int finishResult"):extended.index("\n}\n\n// commandArkDriverExtended")]

harness = r'''
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include "TYPES_HEADER"
#include "REGISTRY_HEADER"
namespace fixture {
HELPERS
}
int main() {
    std::wostringstream output;
    std::vector<std::wstring> jsonDocuments;
    auto* original = std::wcout.rdbuf(output.rdbuf());
    ksword::ark::IoctlRegistryQueryResult registry{};
    registry.io.ok = true; registry.status = KSWORD_ARK_IOCTL_REGISTRY_STATUS_TRUNCATED;
    registry.totalCount = 2; registry.returnedCount = 1;
    ksword::ark::IoctlRegistryEntry ioctl{}; ioctl.ioControlCode = 0x1234; ioctl.name = "fixture-ioctl";
    registry.entries.push_back(ioctl);
    assert(fixture::finishRows(L"registry", registry) == 0);
    assert(output.str().find(L"ioctl=0x1234") != std::wstring::npos);
    assert(output.str().find(L"name=fixture-ioctl") != std::wstring::npos);
    assert(output.str().find(L"total=2 returned=1") != std::wstring::npos);
    output.str(L"");
    ksword::ark::PlatformAuditResult platform{}; platform.io.ok = true;
    platform.io.ntStatus = static_cast<long>(0xC000000DU);
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY platformRow{}; platformRow.entryIndex = 42;
    // Deliberately no NUL: bounded string reading must stay within the field.
    std::fill(std::begin(platformRow.name), std::end(platformRow.name), L'X');
    platform.entries.push_back(platformRow);
    assert(fixture::finishRows(L"platform", platform) == 3);
    assert(output.str().find(L"index=42") != std::wstring::npos);
    assert(output.str().find(std::wstring(std::size(platformRow.name), L'X')) != std::wstring::npos);
    platform.io.ntStatus = static_cast<long>(0x80000005U);
    assert(fixture::finishRows(L"platform", platform) == 6);
    output.str(L"");
    platform.io.ok = false;
    fixture::finishRows(L"platform", platform);
    assert(output.str().find(L"index=42") == std::wstring::npos);
    output.str(L"");
    ksword::ark::ObjectTypeTableAuditResult object{}; object.nextIndex = 7;
    KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY objectRow{}; objectRow.typeIndex = 6;
    wcscpy_s(objectRow.typeName, L"Process"); object.entries.push_back(objectRow);
    fixture::printExtendedRows(object);
    assert(output.str().find(L"next_index=7") != std::wstring::npos);
    assert(output.str().find(L"index=6") != std::wstring::npos && output.str().find(L"name=Process") != std::wstring::npos);
    output.str(L"");
    ksword::ark::Win32kTimersResult timers{}; KSWORD_ARK_WIN32K_TIMER_ENTRY timer{};
    timer.processId = 123; timer.timerId = 0x55; timers.entries.push_back(timer);
    fixture::printExtendedRows(timers);
    assert(output.str().find(L"pid=123") != std::wstring::npos && output.str().find(L"timer_id=0x55") != std::wstring::npos);
    output.str(L"");
    ksword::ark::Win32kEventHooksResult hooks{}; KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY hook{};
    hook.targetProcessId = 456; hook.eventMin = 0x100; hooks.entries.push_back(hook);
    fixture::printExtendedRows(hooks);
    assert(output.str().find(L"target_pid=456") != std::wstring::npos && output.str().find(L"event_min=0x100") != std::wstring::npos);
    output.str(L"");
    ksword::ark::UnloadedDriverQueryResult unloaded{}; ksword::ark::UnloadedDriverEntry driver{};
    driver.flags = 1; driver.driverName = L"fixture.sys"; unloaded.entries.push_back(driver);
    fixture::printExtendedRows(unloaded);
    assert(output.str().find(L"name=fixture.sys") != std::wstring::npos && output.str().find(L"flags=0x1") != std::wstring::npos);
    output.str(L"");
    ksword::ark::KernelTimerDpcEnumResult dpc{}; dpc.queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_DYNDATA_MISSING;
    assert(fixture::timerDpcResultCode(dpc, 0) == 5);
    fixture::printExtendedRows(dpc); assert(output.str().find(L"query_state=dyndata-missing") != std::wstring::npos);
    dpc.queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_PARTIAL; assert(fixture::timerDpcResultCode(dpc, 0) == 6);
    dpc.queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_OK; assert(fixture::timerDpcResultCode(dpc, 0) == 0);
    dpc.statusFlags = KSWORD_ARK_TIMER_DPC_STATUS_TRUNCATED; assert(fixture::timerDpcResultCode(dpc, 0) == 6);
    assert(fixture::timerDpcResultCode(dpc, 2) == 2);
    output.str(L""); registry.io.ok = true; registry.entries[0].name = "quoted \"value\"";
    assert(fixture::finishRowsSelected(L"ioctl-registry", registry, true, registry.totalCount) == 0);
    jsonDocuments.push_back(output.str()); output.str(L"");
    object.io.ok = true; object.totalCount = 68; object.nextIndex = KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS;
    assert(fixture::finishRowsSelected(L"object-types", object, true, object.totalCount) == 0);
    jsonDocuments.push_back(output.str()); output.str(L"");
    platform.io.ok = false; platform.io.deviceOpenFailed = true;
    assert(fixture::finishRowsSelected(L"platform", platform, true, platform.totalCount) == 2);
    jsonDocuments.push_back(output.str()); output.str(L"");
    dpc.io.ok = true; dpc.queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_DYNDATA_MISSING;
    assert(fixture::finishRowsJson(L"timer-dpc", dpc, fixture::timerDpcResultCode(dpc, 0), dpc.totalCount) == 5);
    jsonDocuments.push_back(output.str()); output.str(L"");
    unloaded.io.ok = true; fixture::finishRowsSelected(L"unloaded", unloaded, true, unloaded.totalRows);
    jsonDocuments.push_back(output.str()); output.str(L"");
    timers.io.ok = true; fixture::finishRowsSelected(L"win32k-timers", timers, true, timers.totalCount);
    jsonDocuments.push_back(output.str()); output.str(L"");
    hooks.io.ok = true; fixture::finishRowsSelected(L"win32k-events", hooks, true, hooks.totalCount);
    jsonDocuments.push_back(output.str());
    std::wcout.rdbuf(original);
    for (const auto& doc : jsonDocuments) std::wcout << doc;
}
'''

with tempfile.TemporaryDirectory(prefix="ksword-r0-rows-") as temp:
    temp = Path(temp)
    source = temp / "fixture.cpp"
    source.write_text(harness.replace("TYPES_HEADER", (ROOT / "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverTypes.h").as_posix()).replace("REGISTRY_HEADER", (ROOT / "KswordCLI/CommandRegistry.h").as_posix()).replace("HELPERS", utf8 + state + rows + finish), encoding="utf-8")
    exe = temp / "fixture.exe"
    subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", str(source), *[str(ROOT / ('KswordCLI/' + n)) for n in ('CommandRegistry.cpp', 'CliArgs.cpp', 'CliText.cpp')], "/Fe:" + str(exe), "/link", "Ole32.lib"], cwd=temp, check=True)
    result = subprocess.run([str(exe)], check=True, capture_output=True, text=True)
    docs = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(docs) == 7
    assert docs[0]['data']['entries'][0]['name'] == 'quoted "value"' and docs[0]['data']['truncated']
    assert docs[1]['data']['nextIndex'] == 256 and not docs[1]['data']['truncated']
    assert docs[2]['status'] == 'failed' and docs[2]['data']['totalCount'] is None and docs[2]['data']['entries'] == []
    assert docs[3]['status'] == 'unsupported'
    assert [d['command'] for d in docs[4:]] == ['r0 unloaded', 'r0 win32k-timers', 'r0 win32k-events']
    print("R0 row output and timer-DPC status regression passed")
