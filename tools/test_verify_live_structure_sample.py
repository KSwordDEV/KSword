"""Synthetic checks for the receipt verifier; these are not VM evidence."""

import copy
from pathlib import Path
import unittest

from verify_live_structure_sample import EvidenceError, read_profile, verify


PROFILE = Path(__file__).parent / 'tests' / 'fixtures' / 'structure_sample_verifier.tsv'


def synthetic_packet():
    """构造明确标记为合成的完整回执，覆盖别名、联合体和位域交叉存储。"""
    identity, fields = read_profile(PROFILE)
    base = 0xffff800000001000
    body = bytearray(range(64))
    body[0:4] = (123).to_bytes(4, 'little')
    body[24:32] = (100).to_bytes(8, 'little')
    rows = []
    parents = {field['parent'] for field in fields if field['parent']}
    for source in fields:
        row = copy.deepcopy(source)
        sampled = bool(row['width'])
        width, offset = row['width'], row['offset']
        raw = int.from_bytes(body[offset:offset + width], 'little')
        bits = row['bitWidth'] if row['bitWidth'] is not None else width * 8
        value = (raw >> (row['bitOffset'] or 0)) & ((1 << bits) - 1)
        status = 'aggregate' if row['id'] in parents else ('sampled' if sampled else 'unsupported_type')
        row.update(status=status, sampled=sampled,
                   storageAddress=hex(base + offset), raw=hex(raw) if sampled else None,
                   value=hex(value) if sampled else None, valueBits=bits if sampled else None,
                   text=str(value) if sampled else None, activeUnionBranchKnown=False)
        rows.append(row)
    kernel = {key: identity[key] for key in ('machine', 'timestamp', 'imageSize', 'pdbKey')}
    data = {
        'source': 'live_object_body', 'live': True, 'atomic': False, 'metadataOnly': False,
        'identityVerified': True, 'driverIdentityVerified': True, 'deviceAccessAttempted': True,
        'requestAttempted': True, 'deviceOpenFailed': False, 'sampleStatus': 'ok',
        'rootType': '_EPROCESS', 'pid': 123, 'tid': None,
        'processCreationTime100ns': '100', 'expectedProcessCreationTime100ns': '100',
        'target': {'aliveAtReadback': True}, 'diskKernelIdentity': copy.deepcopy(kernel),
        'loadedKernelIdentity': copy.deepcopy(kernel), 'rootSize': 64, 'profileRootSize': 64,
        'sampleStartTime100ns': '1000', 'sampleEndTime100ns': '1100',
        'validByteBitmap': 'ff' * 8, 'bytesCopied': 64, 'objectAddress': hex(base),
        'fields': rows, 'totalRows': 11, 'sampledRows': 9, 'unionRows': 2, 'coverageRows': 6,
        'aggregateRows': 1, 'unsupportedRows': 1, 'unreadRows': 0, 'coverageExceedsHalf': True,
        'syntheticTestFixture': True,
    }
    return {'schemaVersion': 1, 'data': data}


class ReceiptTests(unittest.TestCase):
    """只验独立核算与拒绝机制，不连接宿主或来宾驱动。"""

    def run_verifier(self, packet):
        """用固定独立夹具身份核验输入；不会从待验回执反推期望身份。"""
        return verify(packet, PROFILE, pid=123, process_creation=100)

    def test_consistent_synthetic(self):
        report = self.run_verifier(synthetic_packet())
        self.assertEqual((report['coverageRows'], report['totalRows']), (6, 11))
        self.assertTrue(report['evidenceConsistencyVerified'])
        self.assertFalse(report['acquisitionIndependentlyProven'])

    def test_reject_mutations(self):
        """伪造来源、对象代次、符号身份、位图、计数、存储或解码均必须拒绝。"""
        mutations = {
            'offline source': lambda d: d.update(source='kernel_dump'),
            'non-live': lambda d: d.update(live=False),
            'atomic claim': lambda d: d.update(atomic=True),
            'metadata substitute': lambda d: d.update(metadataOnly=True),
            'unverified': lambda d: d.update(identityVerified=False),
            'no driver verification': lambda d: d.update(driverIdentityVerified=False),
            'no device request': lambda d: d.update(requestAttempted=False),
            'wrong PID': lambda d: d.update(pid=124),
            'wrong creation': lambda d: d.update(processCreationTime100ns='101'),
            'target exited': lambda d: d['target'].update(aliveAtReadback=False),
            'wrong loaded PDB': lambda d: d['loadedKernelIdentity'].update(pdbKey='wrong'),
            'wrong disk PE': lambda d: d['diskKernelIdentity'].update(timestamp=124),
            'wrong root': lambda d: d.update(rootSize=65),
            'clock reversed': lambda d: d.update(sampleEndTime100ns='999'),
            'bitmap truncated': lambda d: d.update(validByteBitmap='ff'),
            'fake copied count': lambda d: d.update(bytesCopied=63),
            'bitmap missing bytes': lambda d: d.update(validByteBitmap='fe' + 'ff' * 7, bytesCopied=63, sampleStatus='partial'),
            'drop unsupported row': lambda d: (d['fields'].pop(), d.update(totalRows=6)),
            'wrong metadata': lambda d: d['fields'][0].update(name='different'),
            'wrong offset': lambda d: d['fields'][0].update(offset=32),
            'wrong width': lambda d: d['fields'][0].update(width=8),
            'fake address': lambda d: d['fields'][0].update(storageAddress='0xffff800000003000'),
            'raw overflow': lambda d: d['fields'][0].update(raw='0x100000000'),
            'wrong bitfield': lambda d: d['fields'][3].update(value='0x8'),
            'overlap mismatch': lambda d: d['fields'][2].update(raw='0x1', value='0x1'),
            'missing fake zero': lambda d: d['fields'][6].update(raw='0x0'),
            'fake active branch': lambda d: d['fields'][5].update(activeUnionBranchKnown=True),
            'union counted': lambda d: d.update(coverageRows=7),
            'union unlabeled': lambda d: d['fields'][5].update(unionInterpretation=False),
            'alias counted': lambda d: d.update(coverageRows=8),
            'sampled count': lambda d: d.update(sampledRows=10),
            'wrong public PID': lambda d: d['fields'][0].update(raw='0x7c', value='0x7c'),
            'wrong public creation': lambda d: d['fields'][8].update(raw='0x65', value='0x65'),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                packet = synthetic_packet()
                mutate(packet['data'])
                with self.assertRaises(EvidenceError):
                    self.run_verifier(packet)

    def test_partial_cannot_keep_stale_field(self):
        packet = synthetic_packet()
        data = packet['data']
        data.update(validByteBitmap='ff' * 7 + '00', bytesCopied=56, sampleStatus='partial')
        self.assertTrue(self.run_verifier(packet)['evidenceConsistencyVerified'])

    def test_exact_profile_denominators_and_alias_policy(self):
        """独立解析六份真实分片并重算潜在覆盖；仍明确属于静态元数据回归。"""
        root = Path(__file__).resolve().parents[1] / 'Ksword5.1' / 'Ksword5.1' / 'profiles'
        cases = (
            ('34404-329465876-17059840', 'thread_layouts', 766, 448),
            ('34404-329465876-17059840', 'process_layouts', 672, 468),
            ('34404-3986539294-17063936', 'thread_layouts', 766, 447),
            ('34404-3986539294-17063936', 'process_layouts', 641, 442),
            ('34404-2952155935-21299200', 'thread_layouts', 851, 513),
            ('34404-2952155935-21299200', 'process_layouts', 772, 525),
        )
        for key, kind, total, coverage in cases:
            with self.subTest(kernel=key, kind=kind):
                identity, fields = read_profile(root / kind / (key + '.tsv'))
                parents = {field['parent'] for field in fields if field['parent']}
                storage = {(field['offset'], field['width'], field['bitOffset'], field['bitWidth'])
                           for field in fields if field['id'] not in parents and field['width'] and
                           field['offset'] + field['width'] <= identity['rootSize'] and
                           not field['unionInterpretation']}
                self.assertEqual((len(fields), len(storage)), (total, coverage))
                self.assertGreater(2 * len(storage), len(fields))


if __name__ == '__main__':
    unittest.main(verbosity=2)
