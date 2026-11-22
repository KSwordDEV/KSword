"""In-memory regression for the offline thread metadata exporter."""

from io import BytesIO
import errno
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest import mock
from uuid import UUID

import ksword_thread_symbol_corpus as corpus


GUID = 'F923DA2D-238E-7C7C-E180-B962B19A3781'
KEY = GUID.replace('-', '') + '1'


def synthetic_msf(guid=GUID, dbi_age=1, info_age=5):
    """Four stream slots, a two-block directory, and distinct Info/DBI ages."""
    page = 512
    data = bytearray(16 * page)
    data[:32] = corpus.MSF_SIGNATURE
    struct.pack_into('<6I', data, 32, page, 1, 16, 516, 0, 2)
    struct.pack_into('<2I', data, 2 * page, 3, 10)
    struct.pack_into('<8I', data, 3 * page, 4, 0, 28, 256, 64, 4, 5, 6)
    struct.pack_into('<I', data, 4 * page + 8, info_age)
    data[4 * page + 12:4 * page + 28] = UUID(guid).bytes_le
    struct.pack_into('<iII', data, 6 * page, -1, 19990903, dbi_age)
    struct.pack_into('<H', data, 6 * page + 58, corpus.AMD64)
    return data


TPI = '''
  0x1001 | LF_STRUCTURE [size = 48] `_KTHREAD`
           field list: <no type>
           options: forward ref (-> 0x1002), sizeof 0
  0x1002 | LF_STRUCTURE [size = 48] `_KTHREAD`
           field list: 0x1003
           options: has unique name, sizeof 20
  0x1003 | LF_FIELDLIST [size = 88]
           - LF_MEMBER [name = `ApcQueueable`, Type = 0x1004, offset = 0, attrs = public]
           - LF_MEMBER [name = `KernelApcDisable`, Type = 0x0011 (short), offset = 4, attrs = public]
           - LF_MEMBER [name = `SpecialApcDisable`, Type = 0x0011 (short), offset = 19, attrs = public]
           - LF_MEMBER [name = `InitialStack`, Type = 0x0603 (void*), offset = 8, attrs = public]
           - LF_MEMBER [name = `State`, Type = 0x1007, offset = 16, attrs = public]
           - LF_MEMBER [name = `WaitMode`, Type = 0x0070 (char), offset = 17, attrs = public]
  0x1004 | LF_BITFIELD [size = 12]
           type = 0x0022 (unsigned long), bit offset = 14, # bits = 1
  0x1005 | LF_STRUCTURE [size = 48] `_ETHREAD`
           field list: 0x1006
           options: has unique name, sizeof 48
  0x1006 | LF_FIELDLIST [size = 40]
           - LF_MEMBER [name = `Tcb`, Type = 0x1001, offset = 0, attrs = public]
  0x1007 | LF_MODIFIER [size = 12]
           referent = 0x0020 (unsigned char), modifiers = volatile
'''


class IdentityTests(unittest.TestCase):
    def test_buffered_pe_identity_reads_one_exact_rsds_record(self):
        pe_bytes = bytearray(2048)
        debug_rva, debug_raw, rsds_raw = 4096, 512, 1024
        first = b'RSDS' + UUID(GUID).bytes_le + struct.pack('<I', 1) + b'C:\\symbols\\ntkrnlmp.pdb\0'
        second = b'RSDS' + UUID(int=1).bytes_le + struct.pack('<I', 1) + b'ntkrnlmp.pdb\0'
        struct.pack_into('<IIHHIIII', pe_bytes, debug_raw, 0, 0, 0, 0, 2, len(first), 0, rsds_raw)
        struct.pack_into('<IIHHIIII', pe_bytes, debug_raw + 28, 0, 0, 0, 0, 2, len(second), 0, rsds_raw + 128)
        pe_bytes[rsds_raw:rsds_raw + len(first)] = first
        pe_bytes[rsds_raw + 128:rsds_raw + 128 + len(second)] = second
        directory = SimpleNamespace(VirtualAddress=debug_rva, Size=28)
        optional = SimpleNamespace(SizeOfImage=8192, DATA_DIRECTORY=[directory] * 7)
        section = SimpleNamespace(VirtualAddress=debug_rva, SizeOfRawData=512,
                                  get_offset_from_rva=lambda rva: debug_raw + rva - debug_rva)
        pe = SimpleNamespace(FILE_HEADER=SimpleNamespace(Machine=corpus.AMD64, TimeDateStamp=42),
                             OPTIONAL_HEADER=optional, sections=[section])
        with (mock.patch.object(Path, 'open', side_effect=lambda *_: BytesIO(pe_bytes)),
              mock.patch.object(corpus.pefile, 'PE') as parse):
            parse.return_value.__enter__.return_value = pe
            info, identity = corpus.buffered_pe_identity(Path('ntoskrnl.exe'), len(pe_bytes))
            self.assertEqual(info, {'machine': corpus.AMD64, 'timestamp': 42, 'sizeOfImage': 8192})
            self.assertEqual(identity.pdb_name, 'ntkrnlmp.pdb')
            self.assertEqual(identity.symbol_key, KEY)
            self.assertIn('data', parse.call_args.kwargs)
            directory.Size = 56
            with self.assertRaisesRegex(ValueError, 'one distinct PE RSDS'):
                corpus.buffered_pe_identity(Path('ntoskrnl.exe'), len(pe_bytes))

    def test_volume_error_is_retried_but_other_errors_escape(self):
        def detached():
            io_error = OSError('volume detached')
            io_error.winerror = 1006
            raise io_error

        with mock.patch.object(corpus.time, 'sleep') as delay:
            attempts = iter((detached, lambda: 'ready'))
            self.assertEqual(corpus.retry_io(lambda: next(attempts)()), 'ready')
            delay.assert_called_once_with(0.5)
            delay.reset_mock()
            with self.assertRaises(ValueError):
                corpus.retry_io(int, 'not an integer')
            delay.assert_not_called()

    def test_checkpoint_retry_handles_detached_volume_einval(self):
        with (mock.patch.object(corpus.time, 'sleep') as delay,
              mock.patch('builtins.open', side_effect=[OSError(errno.EINVAL, 'detached'), 'ready']) as operation):
            self.assertEqual(corpus.retry_io(operation, 'fixed.pending.json', pending_output=True), 'ready')
            delay.assert_called_once_with(0.5)

    def test_info_age_is_diagnostic_not_rsds_age(self):
        actual = corpus.pdb_identity(BytesIO(synthetic_msf()))
        self.assertEqual(actual, {'guid': GUID, 'infoAge': 5, 'dbiAge': 1, 'machine': 0x8664})
        self.assertEqual(corpus.symbol_key(actual), KEY)

    def test_truncated_and_invalid_dbi_are_rejected(self):
        for source in (synthetic_msf()[:-1], synthetic_msf(dbi_age=0)):
            with self.assertRaises(ValueError):
                corpus.pdb_identity(BytesIO(source))

    def test_wrong_guid_or_dbi_age_never_runs_type_dump(self):
        for source in (synthetic_msf(dbi_age=2, info_age=1), synthetic_msf(guid=str(UUID(int=1)))):
            with (mock.patch.object(Path, 'open', return_value=BytesIO(source)),
                  mock.patch.object(corpus, 'stamp', return_value=[1]),
                  mock.patch.object(corpus.subprocess, 'run') as run):
                entry = corpus.inspect_pdb(Path(), 'llvm-pdbutil', 1, KEY, None)
            self.assertEqual(entry['status'], 'pdb_identity_mismatch')
            self.assertFalse(entry.get('exactPair', False))
            run.assert_not_called()

    def test_resume_rechecks_identity_and_source_stamp(self):
        dump = SimpleNamespace(stdout=TPI, stderr='', returncode=0)
        with (mock.patch.object(Path, 'open', side_effect=lambda *_: BytesIO(synthetic_msf())),
              mock.patch.object(corpus, 'stamp', return_value=[1]) as stamp,
              mock.patch.object(corpus.subprocess, 'run', return_value=dump) as run):
            result = corpus.inspect_pdb(Path(), 'llvm-pdbutil', 1, KEY, None)
            self.assertTrue(result['exactPair'])
            self.assertEqual(result['status'], 'partial')
            self.assertIs(corpus.inspect_pdb(Path(), 'llvm-pdbutil', 1, KEY, result), result)
            run.assert_called_once()
            stamp.return_value = [2]
            self.assertIsNot(corpus.inspect_pdb(Path(), 'llvm-pdbutil', 1, KEY, result), result)
            self.assertEqual(run.call_count, 2)


class LayoutTests(unittest.TestCase):
    def test_typed_members_zero_offsets_and_missing_reasons(self):
        result = corpus.extract_layouts(TPI)
        self.assertEqual(result['typeSizes'], {'_ETHREAD': 48, '_KTHREAD': 20})
        self.assertEqual(result['members']['_ETHREAD.Tcb'], {
            'offsetBytes': 0, 'sizeBytes': 20, 'kind': 'aggregate', 'typeName': '_KTHREAD'})
        self.assertEqual(result['members']['_KTHREAD.ApcQueueable'], {
            'offsetBytes': 0, 'sizeBytes': 4, 'kind': 'bitfield', 'signed': False, 'bitOffset': 14, 'bitWidth': 1})
        self.assertTrue(result['members']['_KTHREAD.KernelApcDisable']['signed'])
        self.assertEqual(result['members']['_KTHREAD.InitialStack']['sizeBytes'], 8)
        self.assertEqual(result['members']['_KTHREAD.State']['sizeBytes'], 1)
        self.assertIsNone(result['members']['_KTHREAD.WaitMode']['signed'])
        self.assertEqual(result['missingEntries']['_KTHREAD.SpecialApcDisable'], 'unsupported_or_out_of_bounds_layout')
        self.assertEqual(result['missingEntries']['_KTHREAD.ApcState'], 'member_not_found')
        self.assertEqual(result['missingEntries']['_KAPC_STATE'], 'type_not_found')

    def test_contradictory_definitions_and_invalid_bit_range_are_not_guessed(self):
        conflicting = corpus.extract_layouts(TPI + '''
  0x1010 | LF_STRUCTURE [size = 48] `_KTHREAD`
           field list: 0x1003
           options: has unique name, sizeof 21
''')
        self.assertEqual(conflicting['missingEntries']['_KTHREAD'], 'ambiguous_type_size')
        invalid_bit = corpus.extract_layouts(TPI.replace('bit offset = 14', 'bit offset = 32'))
        self.assertNotIn('_KTHREAD.ApcQueueable', invalid_bit['members'])

    def test_coverage_counts_images_as_aliases_not_additional_extractions(self):
        layout = corpus.extract_layouts(TPI)
        aliases = [{'status': 'indexed', 'path': path} for path in ('a', 'b')]
        report = corpus.make_report({}, aliases, {KEY: ['a', 'b']}, {KEY, 'OTHER'},
                                    {KEY: {'status': 'partial', 'exactPair': True, **layout}}, True, True)
        coverage = report['coverage']
        self.assertEqual(coverage['exactPairs'], 1)
        self.assertEqual(coverage['peFilesWithExactPair'], 2)
        self.assertEqual(coverage['indexedPeAliases'], 1)
        self.assertEqual(coverage['memberCoverage']['_ETHREAD.Tcb'], {'present': 1, 'missingAmongExactPairs': 0})
        self.assertEqual(coverage['memberCoverage']['_ETHREAD.Cid'], {'present': 0, 'missingAmongExactPairs': 1})
        self.assertEqual(report['cacheKeysWithoutIndexedPe'], ['OTHER'])


if __name__ == '__main__':
    unittest.main()
