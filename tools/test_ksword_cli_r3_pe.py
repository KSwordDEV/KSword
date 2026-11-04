"""Verify snapshot short reads and read failures cannot become successful fallback."""
from pathlib import Path
import json
import subprocess
import tempfile
import struct

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#pragma once
#include <Windows.h>
BOOL WINAPI FixtureRead(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
#define ReadFile FixtureRead
'''
SOURCE = r'''
#include "mock.h"
#undef ReadFile
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
static std::wstring mode;
static unsigned reads;
BOOL WINAPI FixtureRead(HANDLE file,LPVOID data,DWORD size,LPDWORD read,LPOVERLAPPED async) {
    if(mode==L"normal") return ReadFile(file,data,size,read,async);
    if(++reads>1) {*read=0;if(mode==L"error"){SetLastError(ERROR_CRC);return FALSE;}return TRUE;}
    return ReadFile(file,data,size>4?4:size,read,async);
}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
    ks::cli::registerFilePe();return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-pe-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        (directory / 'fixture.cpp').write_text(SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix()))
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
        for mode, error in [('eof', 38), ('error', 23)]:
            result = subprocess.run([str(binary), mode, 'file', 'pe', 'query', '--path', str(data), '--json'], capture_output=True, timeout=15)
            assert result.returncode == 3, (result.returncode, result.stdout, result.stderr)
            document = json.loads(result.stdout)
            assert document['status'] == 'failed' and document['data']['win32Error'] == error
            assert document['data']['bytesRead'] == '4' and document['data']['snapshotSize'] == '64'
            assert not document['data']['deepAvailable'] and not document['data']['header']['available']
        import os
        system_dll = Path(os.environ['SystemRoot']) / 'System32' / 'kernel32.dll'
        result = subprocess.run([str(binary), 'normal', 'file', 'pe', 'query', '--path', str(system_dll), '--json'], capture_output=True, timeout=30)
        assert result.returncode in (0, 6), (result.returncode, result.stderr)
        doc = json.loads(result.stdout)['data']
        assert doc['deepAvailable'] and any(m['functions'] for m in doc['imports'])
        assert doc['exportEvidenceState'] in ('complete', 'partial') and any(e['name'] == 'Ordinal' for e in doc['exportEntries'])
        dll_source = directory / 'exports.cpp'
        dll_source.write_text('extern "C" int namedImpl() { return 11; }\nextern "C" int ordinalImpl() { return 22; }\n')
        definition = directory / 'exports.def'
        definition.write_text('LIBRARY exports\nEXPORTS\n Named=namedImpl @1\n Hidden=ordinalImpl @2 NONAME\n Forwarded=KERNEL32.Sleep @3\n')
        dll = directory / 'exports.dll'
        subprocess.run(['cl', '/nologo', '/LD', str(dll_source), '/link', '/NOLOGO', '/DEF:' + str(definition), '/OUT:' + str(dll)], cwd=directory, check=True)
        def inspect(path):
            process = subprocess.run([str(binary), 'normal', 'file', 'pe', 'query', '--path', str(path), '--json'], capture_output=True, timeout=30)
            assert process.returncode in (0, 6), (process.returncode, process.stderr)
            return process.returncode, json.loads(process.stdout)['data']
        code, doc = inspect(dll)
        by_ordinal = {int(s['ordinal']): s for s in doc['exportSymbols']}
        assert doc['exportEvidenceState'] == 'complete' and doc['exportNamesComplete'], doc
        assert by_ordinal[1]['names'] == ['Named'] and not by_ordinal[1]['ordinalOnly']
        assert by_ordinal[2]['names'] == [] and by_ordinal[2]['ordinalOnly'] and by_ordinal[2]['rva'] != '0x0'
        assert by_ordinal[3]['names'] == ['Forwarded'] and by_ordinal[3]['forwarder'].lower() == 'kernel32.sleep'

        raw = bytearray(dll.read_bytes())
        nt = struct.unpack_from('<I', raw, 0x3c)[0]
        optional = nt + 24
        magic = struct.unpack_from('<H', raw, optional)[0]
        assert magic == 0x20b
        export_rva, export_size = struct.unpack_from('<II', raw, optional + 112)
        section_count = struct.unpack_from('<H', raw, nt + 6)[0]
        section_start = optional + struct.unpack_from('<H', raw, nt + 20)[0]
        def rva_offset(rva):
            for index in range(section_count):
                pos = section_start + 40 * index
                va, raw_size, raw_offset = struct.unpack_from('<III', raw, pos + 12)
                if va <= rva < va + raw_size:
                    return raw_offset + rva - va
            raise AssertionError(hex(rva))
        directory_offset = rva_offset(export_rva)
        names_rva = struct.unpack_from('<I', raw, directory_offset + 32)[0]
        ordinals_rva = struct.unpack_from('<I', raw, directory_offset + 36)[0]
        aliases = bytearray(raw)
        ordinals_offset = rva_offset(ordinals_rva)
        first_ordinal = struct.unpack_from('<H', raw, ordinals_offset)[0]
        struct.pack_into('<H', aliases, ordinals_offset + 2, first_ordinal)
        alias_path = directory / 'aliases.dll'; alias_path.write_bytes(aliases)
        _, doc = inspect(alias_path)
        assert any(len(symbol['names']) == 2 for symbol in doc['exportSymbols']), doc
        malformed = bytearray(raw)
        struct.pack_into('<H', malformed, rva_offset(ordinals_rva), 0xffff)
        malformed_path = directory / 'invalid-ordinal.dll'; malformed_path.write_bytes(malformed)
        code, doc = inspect(malformed_path)
        assert code == 6 and doc['exportMalformed'] and not doc['exportNamesComplete']
        assert all(row['ordinalOnly'] is None for row in doc['exportSymbols'])
        no_names = bytearray(raw)
        struct.pack_into('<I', no_names, directory_offset + 24, 0)
        struct.pack_into('<II', no_names, directory_offset + 32, 0, 0)
        no_names_path = directory / 'ordinal-only.dll'; no_names_path.write_bytes(no_names)
        _, doc = inspect(no_names_path)
        assert doc['exportEvidenceState'] == 'complete' and all(row['ordinalOnly'] for row in doc['exportSymbols']), doc
        assert not any(row['kind'] == 'note' for row in doc['exportEntries']), doc['exportEntries']
        broken = bytearray(raw)
        struct.pack_into('<I', broken, directory_offset + 28, 0)
        broken_path = directory / 'missing-eat.dll'; broken_path.write_bytes(broken)
        code, doc = inspect(broken_path)
        assert code == 6 and doc['exportMalformed'] and doc['exportEvidenceState'] == 'partial'
        invalid_forward = bytearray(raw)
        function_rva = struct.unpack_from('<I', raw, directory_offset + 28)[0]
        forward_slot = rva_offset(function_rva) + 2 * 4
        last_forwarder_rva = export_rva + export_size - 1
        struct.pack_into('<I', invalid_forward, forward_slot, last_forwarder_rva)
        invalid_forward[rva_offset(last_forwarder_rva)] = ord('X')
        invalid_forward_path = directory / 'invalid-forward.dll'; invalid_forward_path.write_bytes(invalid_forward)
        code, doc = inspect(invalid_forward_path)
        forward_symbol = next(s for s in doc['exportSymbols'] if int(s['ordinal']) == 3)
        assert code == 6 and doc['exportMalformed'] and forward_symbol['isForwarder'] and forward_symbol['forwarder'] is None
        bounded = bytearray(raw)
        struct.pack_into('<I', bounded, directory_offset + 20, 4097)
        bounded_path = directory / 'bounded-eat.dll'; bounded_path.write_bytes(bounded)
        code, doc = inspect(bounded_path)
        assert code == 6 and doc['exportTruncated'] and len(doc['exportSymbols']) <= 4096
        print('R3_PE_FIXTURE_PASS early EOF and failed read retain errors and reject false fallback success')


if __name__ == '__main__':
    main()
