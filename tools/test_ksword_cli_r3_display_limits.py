"""Verify requested hex preview limits differ from incomplete reads."""
from pathlib import Path
import json
import subprocess
import tempfile
import test_ksword_cli_r3_pe as fixture

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-limits-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(fixture.HEADER)
        (directory / 'fixture.cpp').write_text(fixture.SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix()))
        data = directory / 'example.bin'
        data.write_bytes(bytes(range(64)))
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3FilePe.cpp',
                   'shared/usermode/backend/file/PeSnapshot.cpp', 'shared/usermode/backend/file/FileAnalysis.cpp',
                   'shared/usermode/backend/file/PathNavigator.cpp', 'Ksword5.1/Ksword5.1/ksword/file/pe_analyzer.cpp',
                   'Ksword5.1/Ksword5.1/ksword/string/string.cpp']
        binary = directory / 'fixture.exe'
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        *[str(ROOT / source) for source in sources], '/Fe:' + str(binary), '/link', 'Advapi32.lib'], cwd=directory, check=True)
        def run(mode, path, max_bytes, expected):
            result = subprocess.run([str(binary), mode, 'file', 'hex', 'query', '--path', str(path), '--max-bytes', str(max_bytes), '--json'], capture_output=True, timeout=15)
            assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)['data']
        limited = run('normal', data, 4, 0)
        assert limited['complete'] and limited['displayTruncated'] and limited['limited'] and limited['returnedBytes'] == 4
        short = run('eof', data, 16, 6)
        assert not short['complete'] and short['displayTruncated'] and short['returnedBytes'] == 4
        full = run('normal', data, 128, 0)
        assert full['complete'] and not full['displayTruncated'] and full['returnedBytes'] == 64
        missing = run('normal', directory / 'missing.bin', 4, 3)
        assert not missing['complete'] and missing['displayTruncated'] is None
        print('R3_DISPLAY_LIMITS_PASS requested preview, short read, complete file, missing file')


if __name__ == '__main__':
    main()
