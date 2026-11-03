import copy
from pathlib import Path
import tempfile
import unittest

from merge_reference_metadata import build_metadata, merge


class MetadataTests(unittest.TestCase):
    def test_preserves_graph_and_merges_charset_without_changing_hooks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'one.xml').write_text('''<ApiMonitor><Include Filename="header.xml"/>
              <Interface Name="ITest" Id="{1}" BaseInterface="IUnknown"><Api Name="Call"><Param Name="x" Type="DWORD"/><Return Type="BOOL"/></Api></Interface>
              <Module Name="test.dll" CallingConvention="STDCALL"><ModuleAlias Name="other.dll"/>
                <SourceModule Name="third.dll" Include="third.xml"><Api Name="Fn"/></SourceModule>
                <Api Name="Text" BothCharset="True" SuffixA=""><Param Name="s" Type="LPCTSTR"/><Return Type="BOOL"/></Api>
              </Module></ApiMonitor>''', encoding='utf-8')
            catalog = {'schema_version': 1, 'apis': [{'id': 5, 'module': 'test.dll', 'export': 'Existing'}],
                       'reference_signatures': {'entries': [], 'files': [], 'verified_abis': {'entries': []}}}
            original = copy.deepcopy(catalog)
            metadata = build_metadata(root)
            doc = metadata['documents'][0]
            self.assertEqual(doc['interfaces'][0][1]['BaseInterface'], 'IUnknown')
            self.assertEqual(doc['interfaces'][0][3][0][3][0][1]['Type'], 'DWORD')
            self.assertEqual(doc['modules'][0]['aliases'][0][1]['Name'], 'other.dll')
            self.assertEqual(doc['modules'][0]['source_modules'][0][1]['Include'], 'third.xml')
            merged = merge(catalog, metadata)
            self.assertEqual(catalog, original)
            self.assertEqual(merged['apis'], original['apis'])
            self.assertEqual(merged['reference_signatures']['verified_abis'], {'entries': []})
            rows = merged['reference_signatures']['entries']
            self.assertEqual([x[1] for x in rows], ['Text', 'TextW'])
            self.assertEqual([x[4][0][1] for x in rows], ['LPCSTR', 'LPCWSTR'])
            self.assertEqual(merge(merged, metadata), merged)

    def test_external_entities_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'bad.xml').write_text('<!DOCTYPE x [<!ENTITY y "z">]><ApiMonitor/>', encoding='utf-8')
            with self.assertRaises(ValueError):
                build_metadata(root)


if __name__ == '__main__':
    unittest.main()
