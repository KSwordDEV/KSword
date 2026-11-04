"""Exercise named creation, byte verification, collision protection and registry type parsing."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "REGISTRY_MUTATIONS"
#include <fcntl.h>
#include <io.h>
#include <iostream>
int wmain(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U8TEXT); _setmode(_fileno(stderr), _O_U8TEXT);
    if (argc == 2) {
        ks::cli::Args args; args.values[L"--type"] = argv[1];
        try { std::wcout << ks::cli::type(args) << L"\n"; return 0; }
        catch (...) { return 1; }
    }
    ks::cli::registerFileOperations(); return ks::cli::dispatchR3(argc, argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-cli-create-') as temp:
        directory = Path(temp)
        source = directory / 'fixture.cpp'
        source.write_text(SOURCE.replace('REGISTRY_MUTATIONS', (ROOT / 'KswordCLI/R3RegistryMutations.cpp').as_posix()))
        binary = directory / 'fixture.exe'
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3Input.cpp', 'KswordCLI/R3FileOperations.cpp',
                   'shared/usermode/backend/file/FileOperations.cpp', 'shared/usermode/backend/file/PathNavigator.cpp',
                   'shared/usermode/backend/registry/RegistryMutations.cpp', 'shared/usermode/backend/registry/RegistryBrowse.cpp',
                   'shared/usermode/backend/registry/RegistryModel.cpp']
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        str(source), *[str(ROOT / name) for name in sources], '/Fe:' + str(binary),
                        '/link', 'Advapi32.lib', 'Ole32.lib', 'Shell32.lib'], cwd=directory, check=True)
        for name, number in [('REG_SZ', 1), ('reg_expand_sz', 2), ('REG_BINARY', 3), ('REG_DWORD', 4),
                             ('REG_MULTI_SZ', 7), ('REG_QWORD', 11), ('sz', 1), ('0x4', 4)]:
            result = subprocess.run([str(binary), name], capture_output=True, check=True)
            assert int(result.stdout) == number, (name, result.stdout)
        assert subprocess.run([str(binary), 'REG_UNKNOWN'], capture_output=True).returncode == 1
        def run(args, code):
            result = subprocess.run([str(binary), *args, '--json'], capture_output=True, timeout=15)
            assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)['data']
        target = directory / 'named.bin'
        result = run(['file', 'create', '--path', str(target), '--hex', '00fe7f', '--confirm'], 0)
        assert result['verified'] and target.read_bytes() == bytes.fromhex('00fe7f')
        run(['file', 'create', '--path', str(target), '--text', 'replacement', '--confirm'], 3)
        assert target.read_bytes() == bytes.fromhex('00fe7f')
        utf8 = directory / 'unicode.txt'
        run(['file', 'create', '--path', str(utf8), '--text', '汉字', '--confirm'], 0)
        assert utf8.read_bytes() == '汉字'.encode('utf-8')
        folder = directory / 'named-dir'
        run(['file', 'directory', 'create', '--path', str(folder), '--confirm'], 0)
        assert folder.is_dir()
        missing = directory / 'no-confirm'
        run(['file', 'create', '--path', str(missing)], 1)
        assert not missing.exists()
        run(['file', 'create', '--path', str(missing), '--directory', str(directory), '--confirm'], 1)
        assert not missing.exists()
        print('R3_CREATE_TYPES_PASS registry names, bytes, UTF-8, directory, collision and argument guards')


if __name__ == '__main__':
    main()
