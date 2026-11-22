"""Offline regressions. Set KSWORD_TEST_THREAD_CORPUS to replay the real anomaly."""

from dataclasses import replace
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import unittest
from unittest import mock

import ksword_thread_layout_neighbors as neighbors


TARGET = (10, 0, 19041, 100)
BRANCH = TARGET[:3]
Tcb = (0, 0, 'Tcb', '_KTHREAD', '', '', 'member')


def entry(rev, key_id, *, branch=BRANCH, machine=neighbors.AMD64, missing=False, name=None):
    identity = (machine, key_id, 8192, f'{key_id:032X}1')
    image = neighbors.Image(Path(name or f'{key_id}.exe'), (*branch, rev), identity)
    return neighbors.CorpusEntry(image, None if missing else Path(f'{key_id}.pdb'))


class SelectionTests(unittest.TestCase):
    def test_nearest_numeric_revision_with_same_branch_and_arch(self):
        target = entry(100, 20, missing=True).image  # An explicit target need not be indexed.
        previous, following = entry(99, 1), entry(101, 2)
        entries = [entry(120, 3), entry(98, 4), entry(999, 5, branch=(10, 0, 19040)),
                   entry(100, 6), entry(101, 7, machine=0xAA64), entry(1, 8, branch=(10, 1, 19041)),
                   entry(100, 9, branch=(11, 0, 19041)), entry(89, 10, missing=True), following, previous]
        self.assertEqual(neighbors.select_neighbors(target, entries), (previous, following))

    def test_unpaired_revision_is_not_used(self):
        target = entry(100, 20).image
        previous, following = entry(98, 1), entry(105, 2)
        entries = [entry(99, 3, missing=True), entry(101, 4, missing=True), previous, following]
        self.assertEqual(neighbors.select_neighbors(target, entries), (previous, following))

    def test_refuses_one_side_and_refuses_ambiguous_revisions(self):
        target = entry(100, 20).image
        with self.assertRaisesRegex(ValueError, 'lacks two bracketing'):
            neighbors.select_neighbors(target, [entry(99, 1)])
        with self.assertRaisesRegex(ValueError, 'Ambiguous PE identities'):
            neighbors.select_neighbors(target, [entry(99, 1), entry(99, 2), entry(101, 3)])

    def test_aliases_are_deterministic_but_do_not_make_independent_sources(self):
        target = entry(100, 20).image
        alias, previous, following = entry(99, 1, name='alias.exe'), entry(99, 1), entry(101, 2)
        self.assertEqual(neighbors.select_neighbors(target, [alias, following, previous]), (previous, following))
        with self.assertRaisesRegex(ValueError, 'same PDB identity'):
            neighbors.select_neighbors(target, [previous, entry(101, 1)])


class ComparisonTests(unittest.TestCase):
    def test_qualified_paths_use_parents_and_local_offsets_not_row_number(self):
        left = [Tcb, (1, 12, 'Flags', 'unsigned long', 0, 1, 'member'),
                (0, 80, 'Cid', '_CLIENT_ID', '', '', 'member'),
                (3, 0, 'Flags', 'unsigned long', 0, 1, 'member')]
        right = [left[2], (1, 0, 'Flags', 'unsigned long', 0, 1, 'member'), Tcb,
                 (3, 12, 'Flags', 'unsigned long', 0, 1, 'member')]
        self.assertEqual(neighbors.compare((128, left), (130, right)), [
            ('agree', '_ETHREAD.Cid', 80, '_CLIENT_ID', '', ''),
            ('agree', '_ETHREAD.Cid.Flags', 0, 'unsigned long', 0, 1),
            ('agree', '_ETHREAD.Tcb', 0, '_KTHREAD', '', ''),
            ('agree', '_ETHREAD.Tcb.Flags', 12, 'unsigned long', 0, 1),
        ])

    def test_conflicts_preserve_both_sides_and_distinguish_absent_from_zero(self):
        left = [Tcb, (1, 12, 'Removed', 'short', '', '', 'union'),
                (1, 12, 'Shared', 'long', '', '', 'union')]
        right = [Tcb, (1, 0, 'Added', 'char', '', '', 'member'),
                 (1, 16, 'Shared', 'short', '', '', 'union')]
        self.assertEqual(neighbors.compare((128, left), (128, right)), [
            ('agree', '_ETHREAD.Tcb', 0, '_KTHREAD', '', ''),
            ('before', '_ETHREAD.Tcb.Added', '', '', '', ''),
            ('after', '_ETHREAD.Tcb.Added', 0, 'char', '', ''),
            ('before', '_ETHREAD.Tcb.Removed', 12, 'short', '', ''),
            ('after', '_ETHREAD.Tcb.Removed', '', '', '', ''),
            ('before', '_ETHREAD.Tcb.Shared', 12, 'long', '', ''),
            ('after', '_ETHREAD.Tcb.Shared', 16, 'short', '', ''),
        ])

    def test_bit_position_width_display_type_and_union_kind_all_participate(self):
        old = (1, 12, 'Flags', 'unsigned long', 0, 1, 'member')
        for changed in ((1, 12, 'Flags', 'unsigned long', 1, 1, 'member'),
                        (1, 12, 'Flags', 'unsigned long', 0, 2, 'member'),
                        (1, 12, 'Flags', 'unsigned short', 0, 1, 'member'),
                        (1, 12, 'Flags', 'unsigned long', 0, 1, 'union')):
            with self.subTest(changed=changed):
                rows = neighbors.compare((128, [Tcb, old]), (128, [Tcb, changed]))
                self.assertEqual([r[0] for r in rows], ['agree', 'before', 'after'])

    def test_malformed_exact_rows_fail_closed(self):
        for bad in (Tcb, (2, 0, 'Forward', 'char', '', '', 'member'),
                    (1, 128, 'OutOfRoot', 'char', '', '', 'member'),
                    (1, 32, 'BadBitRange', 'char', 64, 1, 'member'),
                    (1, 32, 'HalfBitRange', 'char', 0, '', 'member'),
                    (1, 32, 'Ambiguous.Path', 'char', '', '', 'member'),
                    (1, 32, 'BadTab', 'char\tunsigned', '', '', 'member')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                neighbors.compare((128, [Tcb, bad]), (128, [Tcb]))


class IdentityTests(unittest.TestCase):
    def test_real_dbi_age_not_info_age_used_for_selected_pe(self):
        indexed = entry(100, 20)
        expected = dict(guid='00000000-0000-0000-0000-000000000014', dbiAge=1, infoAge=5, machine=neighbors.AMD64)
        with mock.patch.object(neighbors, 'read_pdb_identity', return_value=([1], expected)):
            self.assertEqual(neighbors.verified_pdb(indexed.image, indexed.pdb), [1])
        for wrong in (dict(expected, dbiAge=2, infoAge=1), dict(expected, guid='EE' * 16),
                      dict(expected, machine=0xAA64)):
            with (self.subTest(wrong=wrong), mock.patch.object(neighbors, 'read_image', return_value=(indexed.image, [1])),
                  mock.patch.object(neighbors, 'read_pdb_identity', return_value=([1], wrong)),
                  mock.patch.object(neighbors, 'dump_types') as dump):
                with self.assertRaisesRegex(ValueError, 'PE RSDS does not match'):
                    neighbors.read_exact_neighbor(indexed, 'unused')
                dump.assert_not_called()

    def test_disk_pe_must_match_indexed_pe_and_version_before_dump(self):
        indexed = entry(100, 20)
        for changed in (replace(indexed.image, version=(*BRANCH, 201)),
                        replace(indexed.image, identity=(neighbors.AMD64, 56, 8192, indexed.image.identity[3]))):
            with (mock.patch.object(neighbors, 'read_image', return_value=(changed, [1])),
                  mock.patch.object(neighbors, 'read_pdb_identity') as pdb):
                with self.assertRaisesRegex(ValueError, 'differs from corpus index'):
                    neighbors.read_exact_neighbor(indexed, 'unused')
                pdb.assert_not_called()

    def test_index_match_checks_recorded_pe_pdb_identity(self):
        key = entry(100, 20).image.identity[3]
        data = {'scanFinished': True,
                'images': [dict(path='ntoskrnl.exe', corpusVersion='10.0.19041.100', machine=neighbors.AMD64,
                                timestamp=20, sizeOfImage=8192, key=key, status='indexed')],
                'byPdbKey': {key: dict(exactPair=True, status='complete',
                                      typeSizes={'_ETHREAD': 128, '_KTHREAD': 64},
                                      identity=dict(guid=key[:32], dbiAge=2, machine=neighbors.AMD64))}}
        with mock.patch.object(Path, 'read_text', return_value=json.dumps(data)):
            with self.assertRaisesRegex(ValueError, 'Corpus PE/PDB identity mismatch'):
                neighbors.read_index(Path('corpus'), Path('report.json'))

    def test_serialization_uses_target_identity_and_empty_fields(self):
        target = entry(100, 20).image
        previous, following = entry(99, 1), entry(101, 2)
        with mock.patch.object(neighbors, 'read_exact_neighbor', side_effect=[
            (128, [Tcb]), (128, [Tcb, (1, 0, 'New', 'char', '', '', 'member')]),
        ]) as load:
            payload, _ = neighbors.build_sidecar(target, [previous, following], 'unused')
        self.assertEqual(load.call_args_list, [mock.call(previous, 'unused'), mock.call(following, 'unused')])
        self.assertEqual(payload.decode('utf-8'),
                         f'KSWNEIGHBORS1\t34404\t20\t8192\t{target.identity[3]}\t10.0.19041.99\t10.0.19041.101\n'
                         'agree\t_ETHREAD.Tcb\t0\t_KTHREAD\t\t\n'
                         'before\t_ETHREAD.Tcb.New\t\t\t\t\n'
                         'after\t_ETHREAD.Tcb.New\t0\tchar\t\t\n')

    def test_sidecar_budget_is_checked_before_writing(self):
        target = entry(100, 20).image
        with (mock.patch.object(neighbors, 'read_exact_neighbor', return_value=(128, [Tcb])),
              mock.patch.object(neighbors, 'MAX_BYTES', 1)):
            with self.assertRaisesRegex(ValueError, 'exceeds display budget'):
                neighbors.build_sidecar(target, [entry(99, 1), entry(101, 2)], 'unused')

    def test_same_filename_different_target_key_cannot_replace_sidecar(self):
        target = entry(100, 20).image
        foreign_key = entry(100, 21).image.identity[3]
        existing = f'KSWNEIGHBORS1\t34404\t20\t8192\t{foreign_key}\t10.0.19041.99\t10.0.19041.101\n'.encode()
        with (mock.patch.object(Path, 'exists', return_value=True),
              mock.patch.object(Path, 'open', return_value=BytesIO(existing)),
              mock.patch.object(neighbors, 'NamedTemporaryFile') as writer):
            with self.assertRaisesRegex(ValueError, 'Conflicting neighbor sidecar identity'):
                neighbors.write_sidecar(Path('profiles/thread_layouts'), target.identity, b'new')
            writer.assert_not_called()

    def test_explicit_target_cli_needs_no_target_pdb_and_checks_stamp(self):
        target = entry(100, 20).image
        payload = b'only metadata'
        output = Path('profiles/thread_layouts')
        with (mock.patch.object(neighbors, 'read_index', return_value=[]),
              mock.patch.object(neighbors, 'read_image', return_value=(target, [1])) as read,
              mock.patch.object(neighbors, 'verified_pdb') as verify,
              mock.patch.object(neighbors, 'build_sidecar', return_value=(payload, [])),
              mock.patch.object(neighbors, 'stamp', side_effect=([1], [2])),
              mock.patch.object(neighbors, 'write_sidecar') as write,
              mock.patch('sys.stdout', new_callable=StringIO), mock.patch('sys.stderr', new_callable=StringIO) as err):
            args = ['--target-pe', str(target.path), '--out-dir', str(output)]
            self.assertEqual(neighbors.main(args), 0)
            read.assert_called_once_with(target.path)
            verify.assert_not_called()
            with self.assertRaises(SystemExit) as failure:
                neighbors.main(args)
            self.assertEqual(failure.exception.code, 1)
            self.assertIn('Target disk PE changed', err.getvalue())
            write.assert_called_once_with(output, target.identity, payload)


@unittest.skipUnless(os.environ.get('KSWORD_TEST_THREAD_CORPUS'), 'optional external corpus replay')
class RealCorpusTests(unittest.TestCase):
    def test_anomaly_neighbor_agreement_is_not_target_truth(self):
        root = Path(os.environ['KSWORD_TEST_THREAD_CORPUS'])
        tool = os.environ.get('KSWORD_TEST_LLVM_PDBUTIL', neighbors.DEFAULT_LLVM_PDBUTIL)
        entries = neighbors.read_index(root, root / neighbors.REPORT_TREE / 'corpus.json')
        version = (10, 0, 14393, 1770)
        middle = neighbors.unique_entry([e for e in entries if e.image.version == version], version)
        _, rows = neighbors.build_sidecar(middle.image, entries, tool)
        exact_size, exact_rows = neighbors.read_exact_neighbor(middle, tool)
        target = neighbors.index_fields(exact_size, exact_rows)
        agree = {path: offset for state, path, offset, *_ in rows if state == 'agree'}
        self.assertEqual(exact_size, 0x7D8)
        self.assertEqual(agree['_ETHREAD.ReadyTime'], 0x7D8)
        self.assertEqual(target['_ETHREAD.ReadyTime'][0], 0x7D0)
        self.assertIn('_ETHREAD.SetContextState', agree)
        self.assertNotIn('_ETHREAD.SetContextState', target)


if __name__ == '__main__':
    unittest.main()
