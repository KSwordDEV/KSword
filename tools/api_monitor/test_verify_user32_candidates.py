"""Evidence and failure-isolation tests for SDK batch verification."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_user32_candidates as tool


class CandidateTests(unittest.TestCase):
    def catalog(self):
        return {'reference_signatures': {'schema_version': 1, 'status': 'unverified',
            'verified_abis': {'sdk': tool.SDK_VERSION, 'architectures': ['x86', 'x64'],
                'header_sha256': 'abcd', 'entries': [['User32.dll', 'Existing', 'BOOL', 'WINAPI', []]]},
            'entries': [['User32.dll', 'Existing', 'STDCALL', 'BOOL', [], 'x.xml'],
                ['USER32.dll', 'Valid', 'STDCALL', 'BOOL', [['p', 'HWND']], 'x.xml'],
                ['User32.dll', 'Decorated', 'STDCALL', 'BOOL', [['p', '[custom]']], 'x.xml'],
                ['other.dll', 'WrongModule', 'STDCALL', 'BOOL', [], 'x.xml']]}}

    def test_selection_and_merge(self):
        catalog = self.catalog()
        rows = tool.choose(catalog)
        self.assertEqual(rows, [('Valid', 'BOOL', ('HWND',))])
        result = tool.merge(catalog, rows, 'abcd')['reference_signatures']['verified_abis']['entries']
        self.assertEqual(result[1], ['User32.dll', 'Valid', 'BOOL', 'WINAPI', ['HWND']])
        with self.assertRaises(ValueError):
            tool.merge(self.catalog(), rows, 'different')
        self.assertIn('#undef Valid', tool.source(rows))

    def test_failed_batch_isolated_without_promoting_failure(self):
        rows = [('A', 'BOOL', ()), ('B', 'BOOL', ()), ('C', 'BOOL', ())]
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(tool, 'compile_group', side_effect=lambda group, env, path: all(r[0] != 'B' for r in group)):
                accepted, rejected = tool.verify_arch(rows, {}, Path(temporary) / 'source.cpp')
        self.assertEqual([x[0] for x in accepted], ['A', 'C'])
        self.assertEqual([x[0] for x in rejected], ['B'])


if __name__ == '__main__':
    unittest.main()
