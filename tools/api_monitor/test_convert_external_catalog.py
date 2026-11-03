"""Offline merge safety checks with synthetic declarations."""
import json
from pathlib import Path
import tempfile
import unittest

from convert_external_catalog import convert


class ConverterTests(unittest.TestCase):
    def test_preserves_project_and_quarantines_conflicts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'xml'
            source.mkdir()
            (source / 'a.xml').write_text('''<ApiMonitor><Module Name="Test.dll" CallingConvention="STDCALL">
              <Api Name="Existing"><Param Name="p" Type="DWORD"/><Return Type="BOOL"/></Api>
              <Api Name="New" BothCharset="true"><Param Name="s" Type="LPCTSTR"/><Return Type="BOOL"/></Api>
              <Api Name="Reference"/>
            </Module></ApiMonitor>''', encoding='utf-8')
            entry = {'id': 1, 'module': 'test.DLL', 'export': 'Existing',
                     'return_type': 'BOOL', 'parameters': [{'name': 'p', 'type': 'ULONG'}]}
            project = root / 'project.json'
            project.write_text(json.dumps({'schema_version': 1, 'apis': [entry]}), encoding='utf-8')
            result = convert(source, project)
            self.assertEqual(result['apis'], [entry])
            review = result['external_review']
            self.assertEqual(len(review['conflicts']), 1)
            self.assertEqual(review['conflicts'][0]['project_id'], 1)
            self.assertEqual([x['export'] for x in review['additions']], ['NewA', 'NewW'])
            self.assertEqual(review['additions'][1]['variants'][0]['parameters'][0]['type'], 'LPCWSTR')
            self.assertEqual(review['skipped']['reference_or_missing_return'], 1)
            self.assertEqual(result, convert(source, project))

    def test_invalid_xml_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'bad.xml').write_text('<ApiMonitor>', encoding='utf-8')
            project = root / 'project.json'
            project.write_text('{"schema_version":1,"apis":[]}', encoding='utf-8')
            with self.assertRaises(Exception):
                convert(root, project)


if __name__ == '__main__':
    unittest.main()
