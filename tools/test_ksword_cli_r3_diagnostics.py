"""Exercise production ICMP backends/CLI adapters with deterministic IP replies.

The only substituted API is IcmpSendEcho2; resolution, handle lifecycle,
argument dispatch, JSON serialization and result codes are production code.
Run in a HostX64 VS developer shell. Build artifacts stay in a temporary folder.
"""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
extern DWORD WINAPI FixtureEcho(HANDLE,HANDLE,FARPROC,PVOID,IPAddr,LPVOID,WORD,PIP_OPTION_INFORMATION,LPVOID,DWORD,DWORD);
#define IcmpSendEcho2 FixtureEcho
'''
SOURCE = r'''
#include "mock.h"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <string>
static std::wstring scenario;
static unsigned calls;
DWORD WINAPI FixtureEcho(HANDLE,HANDLE,FARPROC,PVOID,IPAddr address,LPVOID,WORD bytes,PIP_OPTION_INFORMATION,LPVOID target,DWORD,DWORD) {
    ++calls;
    if (scenario == L"timeout" || (scenario == L"partial" && calls == 2)) { SetLastError(IP_REQ_TIMED_OUT); return 0; }
    auto* reply = static_cast<ICMP_ECHO_REPLY*>(target);
    *reply = {}; reply->Address=address; reply->DataSize=bytes; reply->RoundTripTime=7; reply->Options.Ttl=64;
    reply->Status = scenario == L"hops" && calls == 1 ? IP_TTL_EXPIRED_TRANSIT : IP_SUCCESS;
    return 1;
}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT); _setmode(_fileno(stderr),_O_U8TEXT);
    scenario=argv[1]; ++argv; --argc;
    ks::cli::registerNetworkPing(); ks::cli::registerNetworkTraceRoute();
    return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-icmp-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        (directory / 'fixture.cpp').write_text(SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix()))
        binary = directory / 'fixture.exe'
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3NetworkPing.cpp',
                   'KswordCLI/R3NetworkTraceRoute.cpp', 'shared/usermode/backend/network/Ping.cpp',
                   'shared/usermode/backend/network/TraceRoute.cpp', 'shared/usermode/backend/network/NetworkSupport.cpp']
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        *[str(ROOT / source) for source in sources], '/Fe:' + str(binary),
                        '/link', 'Iphlpapi.lib', 'Ws2_32.lib'], cwd=directory, check=True)
        def run(scenario, family, options, code):
            result = subprocess.run([str(binary), scenario, 'network', family, 'query', '--target', '127.0.0.1', *options, '--json'], capture_output=True, timeout=10)
            assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)['data']
        partial = run('partial', 'ping', ['--count', '2'], 6)
        assert partial['received'] == 1 and partial['lossPercent'] == 50
        assert partial['probes'][1]['status'] == 11010 and partial['probes'][1]['roundTripMs'] is None
        failure = run('timeout', 'ping', ['--count', '1'], 3)
        assert failure['received'] == 0 and failure['lossPercent'] == 100
        route = run('hops', 'trace-route', ['--max-hops', '2'], 0)
        assert route['reached'] and [hop['status'] for hop in route['hops']] == [11013, 0]
        bounded = run('hops', 'trace-route', ['--max-hops', '1'], 6)
        assert not bounded['reached'] and bounded['attemptedHops'] == 1
        timeout = run('timeout', 'trace-route', ['--max-hops', '2'], 3)
        assert not timeout['reached'] and timeout['attemptedHops'] == 2
        print('R3_ICMP_FIXTURE_PASS partial, loss, TTL-expired, hop limit, timeout')


if __name__ == '__main__':
    main()
