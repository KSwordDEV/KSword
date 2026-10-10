"""Check field availability using typed observations contradictory to UI text."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "REGISTRY"
#include "ENRICHMENT"
#include <fcntl.h>
#include <io.h>
static std::wstring mode;
namespace ks::r3::process {
void ApplyMainProcessDetails(std::vector<ProcessSnapshotRow>& rows,const std::vector<ProcessFieldId>& columns,
    std::unordered_map<std::wstring,std::string>&,bool,const std::function<void(const ProcessDetailEvidence&)>& observe) {
    ProcessDetailEvidence e;e.record.pid=rows[0].processId;e.record.creationTime100ns=rows[0].creationTime100ns;
    // Display text deliberately says success while the typed evidence is absent.
    for(const auto id:columns)rows[0].detailTexts[static_cast<std::uint8_t>(id)]=L"success / enabled / Personal";
    if(mode==L"partial" || mode==L"false")e.record.isAdminKnown=true;
    if(mode==L"empty")e.record.packageNameKnown=true;
    observe(e);
}
}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
    const std::wstring self=std::to_wstring(GetCurrentProcessId());
    for(int i=1;i+1<argc;++i)if(std::wstring(argv[i])==L"--pid")argv[i+1]=const_cast<wchar_t*>(self.c_str());
    ks::cli::registerProcessFields();return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-process-fields-') as temp:
        directory = Path(temp)
        source = SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix())
        source = source.replace('ENRICHMENT', (ROOT / 'shared/usermode/backend/process/ProcessEnrichment.h').as_posix())
        (directory / 'fixture.cpp').write_text(source)
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3ProcessFields.cpp',
                   'shared/usermode/backend/process/ProcessEnumerator.cpp', 'shared/usermode/backend/NtApi.cpp',
                   'shared/usermode/backend/Common.cpp', 'Ksword5.1/Ksword5.1/ksword/string/string.cpp']
        binary = directory / 'fixture.exe'
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        str(directory / 'fixture.cpp'), *[str(ROOT / file) for file in sources], '/Fe:' + str(binary),
                        '/link', 'Advapi32.lib'], cwd=directory, check=True)
        def run(mode, fields, code):
            result = subprocess.run([str(binary), mode, 'process', 'detail', 'fields', 'query', '--pid', 'self',
                                     '--fields', fields, '--json'], capture_output=True, timeout=15)
            assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)['data']
        partial = run('partial', 'command-line,user,architecture,elevated', 6)
        assert partial['availableCount'] == 1 and partial['fields'][3]['value'] is False
        assert all(item['value'] is None for item in partial['fields'][:3])
        unknown = run('unknown', 'dep,cfg,signature,enterprise', 5)
        assert unknown['availableCount'] == 0 and all(item['value'] is None for item in unknown['fields'])
        assert unknown['fields'][3]['nativeStatus'] == '0x80004001'
        assert run('false', 'elevated', 0)['fields'][0]['value'] is False
        assert run('empty', 'package', 0)['fields'][0]['value'] == ''
        print('R3_PROCESS_FIELDS_FIXTURE_PASS UI text cannot determine availability, known false/empty remain valid')


if __name__ == '__main__':
    main()
