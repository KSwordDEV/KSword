"""批量布局发布的离线配对、碰撞和保留行为回归。"""

import errno
from pathlib import Path
import shutil
import unittest
from unittest.mock import Mock, patch

import ksword_thread_layout_release as release


# 同一个 GUID 的 DBI Age 1 和 Age 2 必须视为不同键。
GUID = '00000000-0000-0000-0000-000000000001'
KEY = GUID.replace('-', '') + '1'
IDENTITY = (34404, 2, 4096)
ROWS = [(0, 0, 'Field', 'int', '', '', 'member')]


class LayoutReleaseTests(unittest.TestCase):
    def setUp(self):
        """在固定回归目录生成小型 TSV 夹具；仅清理由本次用例创建的子目录。"""
        self.root = Path(__file__).resolve().parents[2] / '.codex-tmp' / 'thread-layout-release-tests'
        self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root)
        self.stage = self.root / 'stage'
        self.output = self.root / 'output'
        for parent in (self.stage, self.output):
            for directory, _ in release.FORMATS.values():
                (parent / directory).mkdir(parents=True)

    def test_index_keeps_aliases_and_detects_age_collision(self):
        """同键重复映像共用分片，另一 DBI Age 则登记为同名碰撞。"""
        entries = [dict(zip(release.IMAGE_FIELDS, IDENTITY, strict=True), status='indexed',
                        path=path, key=key)
                   for path, key in [('z.exe', KEY), ('b.exe', KEY), ('a.exe', KEY[:-1] + '2')]]
        by_path = {entry['path']: entry for entry in entries}
        with patch.object(release, 'read_release_pe', side_effect=lambda path: by_path[path.name]):
            aliases, owners, errors = release.index_images(self.root, entries)
        self.assertEqual(errors, [])
        self.assertEqual(aliases[KEY][IDENTITY], 2)
        self.assertEqual(owners[IDENTITY], {KEY, KEY[:-1] + '2'})

    def test_pe_remount_retries_einval(self):
        """掉盘期间的 EINVAL 后重读磁盘，不能静默采用索引中的 PE 身份。"""
        path = self.root / 'kernel.exe'
        image = {'status': 'indexed'}
        with patch.object(release, 'read_pe', side_effect=[OSError(errno.EINVAL, 'remount'), image]) as read, \
                patch.object(release.time, 'sleep') as delay:
            self.assertEqual(release.read_release_pe(path), image)
        self.assertEqual([call.args for call in read.call_args_list], [(path, None), (path, None)])
        delay.assert_called_once_with(1)

    def test_pdb_info_age_does_not_substitute_for_dbi_age(self):
        """Info Age 匹配 PE 但 DBI Age 不匹配时，不调用 TPI 也不生成 TSV。"""
        identity = {'guid': GUID, 'infoAge': 1, 'dbiAge': 2}
        with patch.object(release, 'read_pdb_identity', return_value=([0, 0, 0], identity)), \
                patch.object(release, 'dump_types') as dump:
            result = release.stage_key(self.root, 'tool', 1, self.stage, KEY, [IDENTITY])
        self.assertEqual(result['status'], 'pdb_identity_mismatch')
        self.assertFalse(result['exactPair'])
        dump.assert_not_called()
        self.assertEqual(list(self.stage.rglob('*.tsv')), [])

    def test_one_dump_produces_both_roots(self):
        """同一个 TPI 回执用于两种 TSV；Info Age 不同时仍按 DBI Age 核验。"""
        identity = {'guid': GUID, 'infoAge': 5, 'dbiAge': 1}
        types = Mock(returncode=0, stdout='one dump')
        with patch.object(release, 'read_pdb_identity', return_value=([0, 0, 0], identity)), \
                patch.object(release, 'dump_types', return_value=types) as dump, \
                patch.object(release, 'extract', return_value=(8, ROWS)) as extract:
            result = release.stage_key(self.root, 'tool', 1, self.stage, KEY, [IDENTITY])
        dump.assert_called_once()
        self.assertEqual([call.args for call in extract.call_args_list],
                         [('one dump', '_ETHREAD'), ('one dump', '_EPROCESS')])
        self.assertTrue(result['exactPair'])
        self.assertEqual(result['errors'], {})
        for directory, marker in release.FORMATS.values():
            path = self.stage / directory / release.shard_name(IDENTITY)
            self.assertEqual(path.read_bytes(),
                             f'{marker}\t34404\t2\t4096\t{KEY}\t8\n0\t0\tField\tint\t\t\tmember\n'.encode())

    def test_missing_thread_root_does_not_discard_process_layout(self):
        """单个根类型缺失时仍输出另一有效布局，配对成功不等于两种布局都可用。"""
        identity = {'guid': GUID, 'infoAge': 1, 'dbiAge': 1}
        types = Mock(returncode=0, stdout='one dump')
        layouts = [ValueError('Missing or ambiguous _ETHREAD definition'), (8, ROWS)]
        with patch.object(release, 'read_pdb_identity', return_value=([0, 0, 0], identity)), \
                patch.object(release, 'dump_types', return_value=types), \
                patch.object(release, 'extract', side_effect=layouts):
            result = release.stage_key(self.root, 'tool', 1, self.stage, KEY, [IDENTITY])
        self.assertTrue(result['exactPair'])
        self.assertEqual(result['layouts'], {'process_layouts': 1})
        self.assertEqual(result['errors'], {'_ETHREAD': 'Missing or ambiguous _ETHREAD definition'})
        self.assertEqual(list(self.stage.glob('thread_layouts/*.tsv')), [])
        self.assertEqual(len(list(self.stage.glob('process_layouts/*.tsv'))), 1)

    def test_existing_collision_aborts_before_any_new_file(self):
        """第二个目录里的碰撞也会阻止发布，不删旧分片或写第一个目录。"""
        name = release.shard_name(IDENTITY)
        (self.stage / 'thread_layouts' / 'new.tsv').write_bytes(b'new')
        original = self.output / 'process_layouts' / name
        original.write_bytes(b'original')
        with self.assertRaisesRegex(ValueError, 'Ambiguous PE tuple'):
            release.publish(self.stage, self.output, {name: [KEY, KEY[:-1] + '2']})
        self.assertEqual(original.read_bytes(), b'original')
        self.assertFalse((self.output / 'thread_layouts' / 'new.tsv').exists())

    def test_publish_adds_only_new_files_and_reruns_idempotently(self):
        """发布保留语料范围外的旧文件，同一批次重跑不覆盖任何文件。"""
        destination = self.output / 'thread_layouts'
        original = destination / 'original.tsv'
        original.write_bytes(b'original')
        (self.stage / 'thread_layouts' / 'new.tsv').write_bytes(b'new')
        counts = release.publish(self.stage, self.output, {})
        self.assertEqual(counts['thread_layouts'], {'added': 1, 'unchanged': 0, 'retained': 1, 'total': 2})
        counts = release.publish(self.stage, self.output, {})
        self.assertEqual(counts['thread_layouts'], {'added': 0, 'unchanged': 1, 'retained': 1, 'total': 2})
        self.assertEqual(original.read_bytes(), b'original')
        self.assertEqual((destination / 'new.tsv').read_bytes(), b'new')


if __name__ == '__main__':
    unittest.main()
