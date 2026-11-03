"""Test CLI packet projection using the actual JSON factories and projection."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
registry = (root / 'KswordCLI/CommandRegistry.cpp').read_text(encoding='utf-8')
factories = registry[registry.index('Json Json::string('):registry.index('bool Args::has(')]
monitor = (root / 'KswordCLI/R3MonitorApi.cpp').read_text(encoding='utf-8')
projection = monitor[monitor.index('template<std::size_t N>'):monitor.index('void scalar(')]
program = r'''
#include "KswordCLI/CommandRegistry.h"
#include "shared/WinApiMonitorProtocol.h"
#include "shared/ApiMonitorCallStack.h"
#include "shared/ApiMonitorCliView.h"
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <locale>
#include <sstream>
#include <iostream>
namespace ks::cli {
// FACTORIES
namespace {
namespace m = ks::winapi_monitor;
// PROJECTION
}
}
using namespace ks::cli;
namespace m = ks::winapi_monitor;
static bool contains(const std::wstring& text, const wchar_t* value) { return text.find(value) != std::wstring::npos; }
int main() {
    m::ApiMonitorEventPacket p{};
    p.category = static_cast<std::uint32_t>(m::EventCategory::File);
    auto s = packetJson(p).text;
    if (!contains(s,L"\"returnValueAvailable\":false") || !contains(s,L"\"returnValue\":null") ||
        !contains(s,L"\"durationAvailable\":false") || !contains(s,L"\"duration100ns\":null")) return 1;
    p.snapshotIndex = m::kApiCallReturnValueMarker;
    p.snapshotCount = m::kApiCallDurationMarker;
    p.hookAddress = 0; p.snapshotRevision = 0;
    s = packetJson(p).text;
    if (!contains(s,L"\"returnValueAvailable\":true") || !contains(s,L"\"returnValue\":\"0x0\"") ||
        !contains(s,L"\"durationAvailable\":true") || !contains(s,L"\"duration100ns\":\"0\"")) return 2;
    p.hookAddress = 0xfedcba9876543210ULL; p.snapshotRevision = 12345678901234ULL;
    s = packetJson(p).text;
    if (!contains(s,L"\"returnValue\":\"0xfedcba9876543210\"") ||
        !contains(s,L"\"duration100ns\":\"12345678901234\"")) return 3;
    p.resultKind = static_cast<std::uint32_t>(m::EventResultKind::StatusUnknown);
    s = packetJson(p).text;
    if (!contains(s,L"\"resultCode\":null") || !contains(s,L"\"returnValueAvailable\":true") || !contains(s,L"\"durationAvailable\":true")) return 7;
    p.resultKind = static_cast<std::uint32_t>(m::EventResultKind::EntryOnly);
    s = packetJson(p).text;
    if (!contains(s,L"\"returnValue\":null") || !contains(s,L"\"duration100ns\":null")) return 4;
    p.resultKind = static_cast<std::uint32_t>(m::EventResultKind::StatusCode);
    p.eventKind = static_cast<std::uint32_t>(m::EventKind::IoComplete);
    s = packetJson(p).text;
    if (!contains(s,L"\"returnValue\":null") || !contains(s,L"\"duration100ns\":null")) return 5;
    p.eventKind = static_cast<std::uint32_t>(m::EventKind::ApiCall);
    p.category = static_cast<std::uint32_t>(m::EventCategory::Internal);
    s = packetJson(p).text;
    if (!contains(s,L"\"returnValue\":null") || !contains(s,L"\"duration100ns\":null")) return 6;
    std::cout << "PASS CLI packet metrics: absent, zero, wide, Raw, async and control" << std::endl;
}
'''.replace('// FACTORIES', factories).replace('// PROJECTION', projection)
with tempfile.TemporaryDirectory(prefix='ksword_cli_packet_') as temp:
    directory = Path(temp)
    cpp = directory / 'packet.cpp'
    cpp.write_text(program, encoding='utf-8')
    exe = directory / 'packet.exe'
    subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/W4', '/WX', '/I' + str(root),
                    str(cpp), '/Fe:' + str(exe), '/Fo:' + str(directory / 'packet.obj')], check=True)
    subprocess.run([str(exe)], check=True, timeout=20)
