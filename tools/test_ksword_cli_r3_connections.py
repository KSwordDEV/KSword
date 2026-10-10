"""Check real CLI close-result classification with independently controlled backend states."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "REGISTRY"
#include "CONNECTIONS"
#include <fcntl.h>
#include <io.h>
static std::wstring scenario;
static unsigned queries=0, actions=0;
namespace ks::r3::network {
ConnectionEntry target(){ConnectionEntry e;e.localAddress=L"127.0.0.1";e.remoteAddress=L"127.0.0.1";e.localPort=1234;e.remotePort=4321;e.processId=77;e.state=5;e.hasState=true;return e;}
ConnectionEnumerationResult EnumerateConnections(){ConnectionEnumerationResult r;r.success=true;++queries;
    if(queries==1||scenario==L"failed-present"||scenario==L"succeeded-present")r.entries.push_back(target());
    if(queries>1&&scenario==L"partial-postcheck"){r.entries.push_back(target());r.diagnosticText=L"one table unavailable";}
    if(queries>1&&scenario==L"failed-postcheck")r.success=false;
    return r;
}
bool ConnectionCanClose(const ConnectionEntry&){return true;}
NetToolsActionResult CloseTcpConnection(const ConnectionEntry&){++actions;NetToolsActionResult r;
    r.success=scenario==L"succeeded-absent"||scenario==L"succeeded-present"||scenario==L"partial-postcheck";
    r.win32Error=r.success?0:317;
    r.message=r.success?L"request accepted":L"UI says target vanished without evidence";
    return r;
}
}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    scenario=argv[1];++argv;--argc;ks::cli::registerNetworkConnections();
    const auto code=ks::cli::dispatchR3(argc,argv).value_or(1);return queries==2&&actions==1?code:99;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-connections-') as temp:
        directory = Path(temp)
        source = SOURCE.replace('REGISTRY', (ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('CONNECTIONS', (ROOT/'shared/usermode/backend/network/Connections.h').as_posix())
        (directory/'fixture.cpp').write_text(source, encoding='utf-8')
        binary = directory/'fixture.exe'
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE', str(directory/'fixture.cpp'), str(ROOT/'KswordCLI/CommandRegistry.cpp'), str(ROOT/'KswordCLI/R3NetworkConnections.cpp'), '/Fe:'+str(binary)], cwd=directory, check=True)

        def run(scenario, code):
            result = subprocess.run([str(binary), scenario, 'network', 'connections', 'close', '--pid', '77', '--local-address', '127.0.0.1', '--local-port', '1234', '--remote-address', '127.0.0.1', '--remote-port', '4321', '--confirm', '--json'], capture_output=True, timeout=10)
            assert result.returncode == code, (scenario, result.returncode, result.stdout, result.stderr)
            payload = json.loads(result.stdout)
            assert 'UI says' not in result.stdout.decode('utf-8'), 'UI text cannot classify native failure'
            return payload

        present = run('failed-present', 3)
        assert present['status'] == 'failed' and present['data']['win32Error'] == 317 and present['data']['postcheckPresent'] and not present['data']['requestSucceeded']
        absent = run('failed-absent', 3)
        assert not absent['data']['postcheckPresent'] and not absent['data']['requestSucceeded']
        unknown = run('failed-postcheck', 3)
        assert unknown['data']['postcheckPresent'] is None and not unknown['data']['postcheckComplete']
        assert run('succeeded-absent', 0)['data']['requestSucceeded']
        assert run('succeeded-present', 6)['data']['postcheckPresent']
        partial = run('partial-postcheck', 6)
        assert partial['data']['postcheckPresent'] is None and not partial['data']['postcheckComplete']
        print('R3_CONNECTIONS_FIXTURE_PASS native status vs UI text, failure/present/absent/unknown, partial/success postchecks')


if __name__ == '__main__':
    main()
