"""Validate production DNS field extraction and CLI JSON using native record fixtures."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#pragma once
#include <winsock2.h>
#include <windows.h>
#include <windns.h>
DNS_STATUS WINAPI FixtureQuery(PCWSTR,WORD,DWORD,PVOID,PDNS_RECORD*,PVOID*);
VOID WINAPI FixtureFree(PVOID,DNS_FREE_TYPE);
#define DnsQuery_W FixtureQuery
#define DnsFree FixtureFree
'''
SOURCE = r'''
#include "mock.h"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <string>
static std::wstring scenario;
static bool freed;
DNS_STATUS WINAPI FixtureQuery(PCWSTR,WORD,DWORD,PVOID,PDNS_RECORD* output,PVOID*) {
    static DNS_RECORDW rows[6]; for (auto& row:rows) row={}; *output=nullptr;
    if (scenario==L"failure") return DNS_ERROR_RCODE_NAME_ERROR;
    if (scenario==L"empty") return ERROR_SUCCESS;
    const WORD types[]{DNS_TYPE_A,DNS_TYPE_MX,DNS_TYPE_SRV,DNS_TYPE_SOA,DNS_TYPE_TEXT,65280};
    for (unsigned i=0;i<6;++i) { rows[i].pName=const_cast<PWSTR>(L"测试.example"); rows[i].wType=types[i]; rows[i].dwTtl=123; rows[i].wDataLength=4; if(i<5)rows[i].pNext=&rows[i+1]; }
    rows[0].Data.A.IpAddress=0x0100007f;
    rows[1].Data.MX.pNameExchange=const_cast<PWSTR>(L"mail.example"); rows[1].Data.MX.wPreference=10;
    rows[2].Data.SRV.pNameTarget=const_cast<PWSTR>(L"service.example"); rows[2].Data.SRV.wPort=8443; rows[2].Data.SRV.wPriority=20; rows[2].Data.SRV.wWeight=30;
    rows[3].Data.SOA.pNamePrimaryServer=const_cast<PWSTR>(L"ns.example"); rows[3].Data.SOA.pNameAdministrator=const_cast<PWSTR>(L"admin.example"); rows[3].Data.SOA.dwSerialNo=123456; rows[3].Data.SOA.dwRefresh=5; rows[3].Data.SOA.dwRetry=6; rows[3].Data.SOA.dwExpire=7; rows[3].Data.SOA.dwDefaultTtl=8;
    rows[4].Data.TXT.dwStringCount=1; rows[4].Data.TXT.pStringArray[0]=const_cast<PWSTR>(L"引号\"与反斜线\\\t");
    *output=&rows[0]; return ERROR_SUCCESS;
}
VOID WINAPI FixtureFree(PVOID,DNS_FREE_TYPE) { freed=true; }
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT); _setmode(_fileno(stderr),_O_U8TEXT);
    scenario=argv[1]; ++argv; --argc; ks::cli::registerNetworkDns();
    const auto rc=ks::cli::dispatchR3(argc,argv).value_or(1);
    return scenario==L"records" && !freed ? 9 : rc;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-dns-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        (directory / 'fixture.cpp').write_text(SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix()), encoding='utf-8')
        binary = directory / 'fixture.exe'
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3NetworkDns.cpp',
                   'shared/usermode/backend/network/Dns.cpp', 'shared/usermode/backend/network/NetworkSupport.cpp']
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        *[str(ROOT / source) for source in sources], '/Fe:' + str(binary),
                        '/link', 'Iphlpapi.lib', 'Ws2_32.lib', 'Dnsapi.lib'], cwd=directory, check=True)
        def run(scenario, code):
            result = subprocess.run([str(binary), scenario, 'network', 'dns', 'query', '--name', 'example.test', '--type', 'ANY', '--json'], capture_output=True, timeout=10)
            assert result.returncode == code, (result.returncode, result.stderr)
            return json.loads(result.stdout)
        result = run('records', 0)
        rows = result['data']['records']
        assert len(rows) == 6 and rows[0]['name'] == '测试.example' and rows[0]['fields']['address'] == '127.0.0.1'
        assert rows[1]['fields'] == {'exchange': 'mail.example', 'preference': 10}
        assert rows[2]['fields'] == {'target': 'service.example', 'port': 8443, 'priority': 20, 'weight': 30}
        assert rows[3]['fields']['serial'] == 123456 and rows[3]['fields']['minimumTtl'] == 8
        assert rows[4]['fields']['segments'] == ['引号"与反斜线\\\t']
        assert not rows[5]['decoded'] and rows[5]['dataLength'] == 4
        assert run('empty', 0)['data']['records'] == []
        assert run('failure', 3)['data']['win32Error'] == 9003
        print('R3_DNS_FIXTURE_PASS typed records, Unicode, escaping, empty, DNS_STATUS, free')


if __name__ == '__main__':
    main()
