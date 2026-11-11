"""Exercise file metadata identity checking and same-handle readback on a private file."""
from pathlib import Path
import base64
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "COMMAND_HEADER"
#include "METADATA_SOURCE"
#include <fcntl.h>
#include <io.h>
int wmain(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U8TEXT); _setmode(_fileno(stderr), _O_U8TEXT);
    if (argc == 5 && std::wstring(argv[1]) == L"--fixture-restore") {
        const auto current = ks::r3::file::metadata::ReadBasic(argv[2]);
        if (!current.ok) return 1;
        auto identity = current.identity;
        if (std::wstring(argv[4]) == L"stale") ++identity.fileId;
        DWORD error = 0;
        return ks::r3::file::metadata::RestoreBackup(argv[2], identity, argv[3], error) ? 0 : 3;
    }
    ks::cli::registerFileMetadata(); return ks::cli::dispatchR3(argc, argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-file-metadata-") as temp:
        directory = Path(temp)
        source = directory / "fixture.cpp"
        # The production declaration is registered by the parent integrator.
        source.write_text(SOURCE.replace('COMMAND_HEADER', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix())
                          .replace('METADATA_SOURCE', (ROOT / 'shared/usermode/backend/file/FileMetadata.cpp').as_posix())
                          .replace('int wmain(', 'namespace ks::cli { void registerFileMetadata(); }\nint wmain('), encoding='utf-8')
        binary = directory / 'fixture.exe'
        names = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3FileMetadata.cpp', 'KswordCLI/R3Input.cpp',
                 'shared/usermode/backend/file/PathNavigator.cpp']
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/W4', '/WX', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        str(source), *[str(ROOT / n) for n in names], '/Fe:' + str(binary), '/link', 'Advapi32.lib', 'Ole32.lib'], cwd=directory, check=True)

        def run(*args, code=0):
            process = subprocess.run([str(binary), *args, '--json'], capture_output=True, timeout=20)
            assert process.returncode == code, (args, process.returncode, process.stdout, process.stderr)
            return json.loads(process.stdout)['data']

        path = directory / 'owned.txt'
        path.write_text('data', encoding='utf-8')
        first = run('file', 'metadata', 'query', '--path', str(path))['snapshot']
        assert first['available'] and first['volumeSerial'] and first['fileId']
        identity = ['--volume-serial', first['volumeSerial'], '--file-id', first['fileId']]
        tick = str(int(first['writeTime']) - 10000000)
        result = run('file', 'metadata', 'set', '--path', str(path), *identity, '--attributes', '0x2', '--write-time', tick, '--confirm')
        assert result['written'] and result['verified'] and result['after']['writeTime'] == tick
        assert int(result['after']['attributes'], 16) & 2
        stale = run('file', 'metadata', 'set', '--path', str(path), '--volume-serial', first['volumeSerial'], '--file-id', '0xffffffffffffffff', '--attributes', '0', '--confirm', code=3)
        assert not stale['attempted'] and not stale['written']
        run('file', 'metadata', 'set', '--path', str(path), *identity, '--attributes', '0x10', '--confirm', code=1)
        run('file', 'metadata', 'set', '--path', str(path), *identity, '--attributes', '0', code=1)
        final = run('file', 'metadata', 'set', '--path', str(path), *identity, '--attributes', '0', '--confirm')
        assert final['verified'] and not int(final['after']['attributes'], 16) & 2
        stream = run('file', 'metadata', 'streams', 'write', '--path', str(path), *identity,
                     '--name', 'ksword-test', '--hex', '01020304', '--confirm')
        assert stream['written'] and stream['verified']
        listed = run('file', 'metadata', 'streams', 'list', '--path', str(path))
        assert any('ksword-test' in item['name'].lower() for item in listed['entries'])
        read = run('file', 'metadata', 'streams', 'read', '--path', str(path), '--name', 'ksword-test', '--max-bytes', '3', code=6)
        assert not read['complete'] and read['entries'][0]['dataHex'].lower() == '010203'
        bad = run('file', 'metadata', 'streams', 'write', '--path', str(path), '--volume-serial', first['volumeSerial'],
                  '--file-id', '0xffffffffffffffff', '--name', 'ksword-test', '--hex', 'ff', '--confirm', code=3)
        assert not bad['written']
        bad_name = run('file', 'metadata', 'streams', 'write', '--path', str(path), *identity,
                       '--name', '::$DATA', '--hex', 'ff', '--confirm', code=3)
        assert not bad_name['written'] and path.read_text(encoding='utf-8') == 'data'
        deleted = run('file', 'metadata', 'streams', 'delete', '--path', str(path), *identity, '--name', 'ksword-test', '--confirm')
        assert deleted['written'] and deleted['verified'] and path.read_text(encoding='utf-8') == 'data'
        folder = directory / 'owned-directory'
        folder.mkdir()
        directory_snapshot = run('file', 'metadata', 'query', '--path', str(folder))['snapshot']
        directory_identity = ['--volume-serial', directory_snapshot['volumeSerial'], '--file-id', directory_snapshot['fileId']]
        directory_stream = run('file', 'metadata', 'streams', 'write', '--path', str(folder), *directory_identity,
                               '--name', 'ksword-directory', '--hex', '0102', '--confirm')
        assert directory_stream['verified']
        assert run('file', 'metadata', 'streams', 'delete', '--path', str(folder), *directory_identity,
                   '--name', 'ksword-directory', '--confirm')['verified']
        added = run('file', 'metadata', 'ea', 'set', '--path', str(path), *identity, '--name', 'KSWORD.TEST', '--hex', '112233', '--confirm')
        assert added['written'] and added['verified']
        eas = run('file', 'metadata', 'ea', 'list', '--path', str(path))
        assert any(item['name'] == 'KSWORD.TEST' and item['dataHex'].lower() == '112233' for item in eas['entries'])
        stale_ea = run('file', 'metadata', 'ea', 'set', '--path', str(path), '--volume-serial', first['volumeSerial'],
                       '--file-id', '0xffffffffffffffff', '--name', 'KSWORD.TEST', '--hex', 'ff', '--confirm', code=3)
        assert not stale_ea['attempted']
        removed = run('file', 'metadata', 'ea', 'delete', '--path', str(path), *identity, '--name', 'KSWORD.TEST', '--confirm')
        assert removed['written'] and removed['verified']
        security = run('file', 'metadata', 'security', 'query', '--path', str(path), '--parts', 'dacl')
        assert security['sddl'] and security['fileId'] == first['fileId']
        stale_security = run('file', 'metadata', 'security', 'set', '--path', str(path), '--volume-serial', first['volumeSerial'],
                             '--file-id', '0xffffffffffffffff', '--parts', 'dacl', '--sddl', security['sddl'], '--confirm', code=3)
        assert not stale_security['attempted']
        changed = run('file', 'metadata', 'security', 'set', '--path', str(path), *identity, '--parts', 'dacl', '--sddl', security['sddl'], '--confirm')
        assert changed['written'] and changed['verified']
        executable = directory / 'resource-fixture.exe'
        executable.write_bytes(binary.read_bytes())
        executable_snapshot = run('file', 'metadata', 'query', '--path', str(executable))['snapshot']
        executable_identity = ['--volume-serial', executable_snapshot['volumeSerial'], '--file-id', executable_snapshot['fileId']]
        backup = directory / 'resource-before.exe'
        original_executable = executable.read_bytes()
        process = subprocess.run([str(binary), 'file', 'metadata', 'resource', 'set', '--path', str(executable), *executable_identity,
                                  '--type', '#10', '--name', '#101', '--language', '1033', '--hex', '01020304', '--backup', str(backup), '--confirm', '--json'], capture_output=True, timeout=20)
        assert process.returncode in (0, 6), (process.returncode, process.stdout, process.stderr)
        resource = json.loads(process.stdout)['data']
        assert resource['written'] and resource['backupCreated'] and backup.read_bytes() == original_executable
        found = run('file', 'metadata', 'resource', 'query', '--path', str(executable), '--type', '#10', '--name', '#101', '--language', '1033')
        assert found['present'] and found['dataHex'].lower() == '01020304'
        new_snapshot = run('file', 'metadata', 'query', '--path', str(executable))['snapshot']
        executable_identity = ['--volume-serial', new_snapshot['volumeSerial'], '--file-id', new_snapshot['fileId']]
        process = subprocess.run([str(binary), 'file', 'metadata', 'resource', 'delete', '--path', str(executable), *executable_identity,
                                  '--type', '#10', '--name', '#101', '--language', '1033', '--backup', str(directory / 'resource-previous.exe'), '--confirm', '--json'], capture_output=True, timeout=20)
        assert process.returncode in (0, 6), (process.returncode, process.stdout, process.stderr)
        removed = json.loads(process.stdout)['data']
        assert removed['written'] and not removed['present']
        previous = directory / 'resource-previous.exe'
        before_restore = executable.read_bytes()
        stale_restore = subprocess.run([str(binary), '--fixture-restore', str(executable), str(previous), 'stale'], timeout=20)
        assert stale_restore.returncode == 3 and executable.read_bytes() == before_restore
        subprocess.run([str(binary), '--fixture-restore', str(executable), str(previous), 'current'], check=True, timeout=20)
        assert executable.read_bytes() == previous.read_bytes()
        jpeg = directory / 'shell-fixture.jpg'
        jpeg.write_bytes(base64.b64decode('/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDABALDA4MChAODQ4SERATGCgaGBYWGDEjJR0oOjM9PDkzODdASFxOQERXRTc4UG1RV19iZ2hnPk1xeXBkeFxlZ2P/2wBDARESEhgVGC8aGi9jQjhCY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2P/wAARCAAEAAQDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDFoooryz7w/9k='))
        jpeg_original = jpeg.read_bytes()
        image_snapshot = run('file', 'metadata', 'query', '--path', str(jpeg))['snapshot']
        image_identity = ['--volume-serial', image_snapshot['volumeSerial'], '--file-id', image_snapshot['fileId']]
        shell_backup = directory / 'shell-before.jpg'
        process = subprocess.run([str(binary), 'file', 'metadata', 'shell', 'set', '--path', str(jpeg), *image_identity,
                                  '--name', 'title', '--value', 'Ksword metadata fixture', '--backup', str(shell_backup), '--confirm', '--json'],
                                 capture_output=True, timeout=20)
        assert process.returncode in (0, 6), (process.returncode, process.stdout, process.stderr)
        shell = json.loads(process.stdout)['data']
        assert shell['written'] and shell['backupCreated'] and shell_backup.read_bytes() == jpeg_original
        shell_query = run('file', 'metadata', 'shell', 'query', '--path', str(jpeg))
        assert any(entry['name'] == 'title' and entry['values'] == ['Ksword metadata fixture'] for entry in shell_query['properties'])
        print('R3_FILE_METADATA_PASS identity, attributes/timestamps, streams, EA, SDDL, PE resources and Shell properties')


if __name__ == '__main__':
    main()
