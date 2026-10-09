#include "../shared/usermode/backend/system/FileHolderScanner.h"
#include "../shared/usermode/backend/system/ModulePath.h"
#include "../shared/usermode/backend/monitor/EtwSessionController.h"
#include "../shared/usermode/backend/monitor/EtwFilterModel.h"
#include "../shared/usermode/backend/monitor/EtwEventModel.h"
#include "../shared/usermode/backend/window/GlobalHotkeyProbe.h"
#include "../shared/usermode/backend/window/PointerText.h"
#include "../shared/usermode/backend/window/WindowHierarchy.h"
#include "../shared/usermode/backend/window/WindowHierarchySupport.h"
#include "../shared/usermode/backend/window/CaptureProtection.h"
#include "../shared/usermode/backend/window/ClipboardCopy.h"
#include "../shared/usermode/backend/window/Clipboard.h"
#include "../shared/usermode/backend/window/WindowActions.h"
#include "../shared/usermode/backend/window/WindowEnumerator.h"
#include "../shared/usermode/backend/window/WindowQueries.h"
#include "../shared/usermode/backend/window/WindowFormatting.h"
#include "../shared/usermode/backend/hardware/BusTopology.h"
#include "../shared/usermode/backend/hardware/UsbTopology.h"
#include "../shared/usermode/backend/hardware/PerformanceSampler.h"
#include "../shared/usermode/backend/hardware/HardwareEnumerator.h"
#include "../shared/usermode/backend/hardware/HardwareFormatting.h"
#include "../shared/usermode/backend/driver/DriverQueries.h"
#include "../shared/usermode/backend/driver/DriverFormatting.h"
#include "../shared/usermode/backend/process/ProcessHotkeys.h"
#include "../shared/usermode/backend/process/ProcessPeb.h"
#include "../shared/usermode/backend/process/ProcessTokenSwitches.h"
#include "../shared/usermode/backend/process/ProcessToken.h"
#include "../shared/usermode/backend/process/ModuleActions.h"
#include "../shared/usermode/backend/process/ThreadActions.h"
#include "../shared/usermode/backend/process/ProcessBasicInfo.h"
#include "../shared/usermode/backend/process/ProcessControls.h"
#include "../shared/usermode/backend/process/ProcessCounters.h"
#include "../shared/usermode/backend/file/PeSnapshot.h"
#include "../shared/usermode/backend/file/FileAnalysis.h"
#include "../shared/usermode/backend/file/Ownership.h"
#include "../shared/usermode/backend/file/FileOperations.h"
#include "../shared/usermode/backend/file/PathNavigator.h"
#include "../shared/usermode/backend/file/Directory.h"
#include "../shared/usermode/backend/registry/RegistryBackend.h"
#include "../shared/usermode/backend/service/ServiceActions.h"
#include "../shared/usermode/backend/service/ServiceEnumerator.h"
#include "../shared/usermode/backend/network/EndpointAudit.h"
#include "../shared/usermode/backend/network/Firewall.h"
#include "../shared/usermode/backend/network/Diagnostics.h"
#include "../shared/usermode/backend/network/Connections.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "TestSupport.h"
#include <algorithm>

int RunR3NetworkBackendTests() {
    using namespace ks::r3::network;
    KswordTests::Suite suite(L"R3 network backend");
    ConnectionEntry entry{};
    entry.hasState = true;
    entry.state = MIB_TCP_STATE_ESTAB;
    suite.expect(ConnectionCanClose(entry), L"IPv4 established TCP is closable");
    suite.expect(ConnectionIsEstablished(entry), L"established state is preserved");
    entry.protocol = ConnectionProtocol::Tcp6;
    suite.expect(!ConnectionCanClose(entry), L"IPv6 cannot enter SetTcpEntry");
    entry.protocol = ConnectionProtocol::Udp4;
    const auto rejected = CloseTcpConnection(entry);
    suite.expect(!rejected.success && rejected.message == L"该连接不支持结束：SetTcpEntry 只能删除 IPv4 TCP 已连接状态的 TCB。", L"UDP rejection preserves the original text");
    entry.protocol = ConnectionProtocol::Tcp4;
    entry.state = MIB_TCP_STATE_LISTEN;
    suite.expect(!ConnectionCanClose(entry) && ConnectionIsListening(entry), L"listeners remain read-only");
    entry.state = MIB_TCP_STATE_CLOSED;
    suite.expect(!ConnectionCanClose(entry), L"closed rows cannot be deleted");
    entry.state = MIB_TCP_STATE_DELETE_TCB;
    suite.expect(!ConnectionCanClose(entry), L"already deleting rows cannot be deleted");
    entry.state = MIB_TCP_STATE_TIME_WAIT;
    suite.expect(ConnectionCanClose(entry), L"last original closable state is preserved");
    entry.hasState = false;
    suite.expect(!ConnectionCanClose(entry) && !ConnectionIsEstablished(entry), L"unknown state is not treated as established");
    const std::uint8_t ipv6[16] = {0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    suite.expect(FormatIpv6Address(ipv6, 7) == L"fe80::1%7", L"IPv6 scope identity is preserved");
    suite.expect(FormatIpv6Address(nullptr, 0) == L"::", L"missing IPv6 address retains placeholder");
    EnsureWinsockInitialized();
    const SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    suite.expect(listener != INVALID_SOCKET, L"own loopback listener created");
    if (listener != INVALID_SOCKET) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
        const bool listening = ::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && ::listen(listener, 1) == 0;
        suite.expect(listening, L"own loopback listener bound");
        int length = sizeof(address);
        const bool named = ::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0;
        suite.expect(named, L"own endpoint identity captured");
        const auto snapshot = EnumerateConnections();
        const auto found = std::find_if(snapshot.entries.begin(), snapshot.entries.end(), [&](const ConnectionEntry& row) {
            return row.protocol == ConnectionProtocol::Tcp4 && row.processId == ::GetCurrentProcessId() && row.localPort == ::ntohs(address.sin_port);
        });
        suite.expect(snapshot.success && found != snapshot.entries.end(), L"real enumeration returns own endpoint");
        if (found != snapshot.entries.end()) {
            suite.expect(found->rawLocalAddress == address.sin_addr.s_addr && found->rawLocalPort == address.sin_port, L"raw table tuple remains byte-exact");
        }
        ::closesocket(listener);
    }
    const auto pingEmpty = RunPing(DiagnosticRequest{});
    suite.expect(!pingEmpty.success && pingEmpty.text == L"请先填写目标主机名或 IP 地址。", L"empty ping input preserves original failure");
    suite.expect(pingEmpty.summary == L"Ping 未执行：目标解析失败。", L"ping failure summary preserved");
    const auto traceEmpty = RunTraceRoute(DiagnosticRequest{});
    suite.expect(!traceEmpty.success && traceEmpty.summary == L"路由跟踪未执行：目标解析失败。", L"trace failure semantics preserved");
    const auto dnsEmpty = RunDnsLookup(DiagnosticRequest{});
    suite.expect(!dnsEmpty.success && !dnsEmpty.text.empty(), L"DNS empty input retains failure result");
    const auto emptyService = ks::r3::service::QuerySingleService(L"");
    suite.expect(!emptyService.success && emptyService.diagnosticText == L"服务名为空，无法查询。", L"service empty query retains failure text");
    const auto invalidRegistry = ks::r3::registry::EnumerateRegistryKey(L"");
    suite.expect(!invalidRegistry.success && !invalidRegistry.statusText.empty(), L"registry invalid path retains diagnostic");
    ks::r3::registry::RegistrySearchRequest searchRequest;
    const auto emptySearch = ks::r3::registry::SearchRegistryWinApi(searchRequest, {});
    suite.expect(emptySearch.stopReason == ks::r3::registry::RegistrySearchStopReason::InvalidRequest, L"registry invalid search budget and input are preserved");
    const auto unsupportedRename = ks::r3::registry::RenameRegistryKey(L"HKCU", L"unused");
    suite.expect(!unsupportedRename.success && unsupportedRename.win32Error == ERROR_NOT_SUPPORTED, L"WinAPI key rename remains unsupported");
    const std::wstring testKey = L"HKCU\\Software\\KswordR3BackendTest_" + std::to_wstring(::GetCurrentProcessId()) + L"_" + std::to_wstring(::GetTickCount64());
    const auto created = ks::r3::registry::CreateRegistryKey(testKey);
    suite.expect(created.success, L"own temporary registry key created");
    if (created.success) {
        const std::vector<std::uint8_t> payload = {0x12, 0x34, 0x56, 0x78};
        const auto written = ks::r3::registry::WriteRegistryValue(testKey, L"original", REG_DWORD, payload);
        suite.expect(written.success, L"own DWORD written through shared backend");
        const auto readBack = ks::r3::registry::ReadRegistryValue(testKey, L"original");
        suite.expect(readBack.success && readBack.valueType == REG_DWORD && readBack.data == payload, L"registry read-back preserves raw bytes");
        const auto renamed = ks::r3::registry::RenameRegistryValue(testKey, L"original", L"renamed");
        suite.expect(renamed.success && !ks::r3::registry::ReadRegistryValue(testKey, L"original").success, L"registry value rename preserves copy/delete semantics");
        suite.expect(ks::r3::registry::ReadRegistryValue(testKey, L"renamed").data == payload, L"renamed value payload retained");
        suite.expect(ks::r3::registry::DeleteRegistryValue(testKey, L"renamed").success, L"own temporary value deleted");
        suite.expect(ks::r3::registry::DeleteRegistryKey(testKey).success, L"own temporary key cleaned up");
    }
    suite.expect(ks::r3::file::PathNavigator::normalizeKnownDirectoryPath(L"C:\\probe\\folder") == L"C:\\probe\\folder", L"known absolute file navigation preserved");
    wchar_t tempBase[MAX_PATH]{};
    const DWORD tempLength = ::GetTempPathW(MAX_PATH, tempBase);
    suite.expect(tempLength > 0 && tempLength < MAX_PATH, L"temporary file base available");
    const std::wstring tempRoot = std::wstring(tempBase) + L"KswordR3Test_" + std::to_wstring(::GetCurrentProcessId()) + L"_" + std::to_wstring(::GetTickCount64());
    const bool madeTemp = ::CreateDirectoryW(tempRoot.c_str(), nullptr) != FALSE;
    suite.expect(madeTemp, L"own temporary file directory created");
    if (madeTemp) {
        const auto firstFile = ks::r3::file::CreateEmptyFile(tempRoot);
        const auto secondFile = ks::r3::file::CreateEmptyFile(tempRoot);
        suite.expect(!firstFile.empty() && !secondFile.empty() && firstFile != secondFile, L"new file naming never overwrites existing file");
        const auto renamedFile = ks::r3::file::PathNavigator::joinChildPath(tempRoot, L"renamed.txt");
        suite.expect(ks::r3::file::RenamePath(firstFile, renamedFile) != FALSE, L"own file renamed");
        suite.expect(ks::r3::file::DeleteEmptyDirectory(tempRoot) == FALSE, L"nonempty directory still rejects deletion");
        suite.expect(ks::r3::file::DeleteFilePath(renamedFile) != FALSE && ks::r3::file::DeleteFilePath(secondFile) != FALSE, L"own files cleaned up");
        suite.expect(ks::r3::file::DeleteEmptyDirectory(tempRoot) != FALSE, L"own empty directory cleaned up");
    }
    suite.expect(ks::r3::file::TakeOwnershipPath(L"") == L"路径为空，无法取得所有权。", L"empty ownership target does not modify token");
    suite.expect(ks::r3::file::QueryFileLockers(L"") == L"路径为空，无法扫描占用进程。", L"empty Restart Manager target is rejected");
    ks::r3::process::ProcessSnapshotRow counterRow;
    counterRow.kernelTime100ns = 10000;
    const ULONGLONG previousCpu = 0;
    ks::r3::process::UpdateCpuCounterDelta(counterRow, &previousCpu, 1, 1);
    suite.expect(counterRow.cpuUsagePercent == 100.0, L"process CPU delta retains original capacity formula");
    ks::r3::process::UpdateCpuCounterDelta(counterRow, nullptr, 1, 1);
    suite.expect(counterRow.cpuUsagePercent == 0.0, L"missing identity baseline resets CPU sample");
    std::wstring identityError;
    const auto invalidIdentity = ks::r3::process::OpenProcessForAction(::GetCurrentProcessId(), 0, PROCESS_QUERY_LIMITED_INFORMATION, identityError);
    suite.expect(!invalidIdentity.valid() && identityError == L"process identity is unavailable; action skipped", L"native process actions reject missing creation identity");
    suite.expect(!ks::r3::process_detail::token::QueryTokenReportSnapshotR3(GetCurrentProcessId(), 0, {}).identityMatched, L"token rejects missing identity");
    suite.expect(!ks::r3::process_detail::token::CollectTokenSwitchSnapshot(GetCurrentProcessId(), 0).identityMatched, L"token switches reject missing identity");
    suite.expect(!ks::r3::process_detail::peb::CollectPebSnapshot(GetCurrentProcessId(), 0, 0).identityMatched, L"PEB rejects missing identity");
    suite.expect(!ks::r3::window::QueryWindowDetails(nullptr).found, L"closed HWND has no details");
    suite.expect(!ks::r3::window::CloseWindowGracefully(nullptr).success, L"closed HWND action rejected");
    suite.report();
    return suite.failures();
}
