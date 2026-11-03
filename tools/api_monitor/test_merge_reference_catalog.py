import copy
import unittest

from merge_reference_catalog import merge


class MergeTests(unittest.TestCase):
    def test_references_are_metadata_and_conflicts_do_not_override_hooks(self):
        api = {'id': 1, 'module': 'x.dll', 'export': 'F'}
        project = {'schema_version': 1, 'apis': [api]}
        candidate = {'module': 'x.dll', 'export': 'G', 'calling_convention': 'STDCALL',
                     'return_type': 'BOOL', 'parameters': [{'name': 'n', 'type': 'DWORD'}],
                     'source': 'x.xml', 'source_sha256': 'a'}
        review = {'apis': [copy.deepcopy(api)], 'external_review': {
            'status': 'unverified_not_runtime', 'source_files': [{'path': 'x.xml', 'sha256': 'a'}],
            'additions': [{'module': 'x.dll', 'export': 'G', 'variants': [candidate]}],
            'conflicts': [{'project_id': 1, 'candidate': dict(candidate, export='F')}], 'skipped': {}}}
        result = merge(project, review)
        self.assertEqual(result['apis'], project['apis'])
        self.assertEqual(result['reference_signatures']['status'], 'unverified')
        self.assertEqual(result['reference_signatures']['entries'][0][1], 'G')
        self.assertEqual(result['reference_signatures']['conflicts'][0][:3], [1, 'x.dll', 'F'])
        self.assertEqual(merge(project, review), result)
        review['apis'][0]['id'] = 2
        with self.assertRaises(ValueError):
            merge(project, review)


if __name__ == '__main__':
    unittest.main()
