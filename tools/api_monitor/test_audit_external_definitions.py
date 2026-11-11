"""Isolated tests for external-definition audit; uses only invented fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

TOOL = Path(__file__).with_name('audit_external_definitions.py')
spec = importlib.util.spec_from_file_location('xml_audit', TOOL)
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)

GOOD = b'''<ApiMonitor><Module Name="test.dll"><Api Name="Demo"><Param Name="v" Type="DWORD"/><Return Type="BOOL"/></Api><Api Name="Reference"/></Module></ApiMonitor>'''
BROKEN = b'c<!-- fixture -->' + GOOD
UNKNOWN = b'not xml'

class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ksword_xml_audit_')
        self.root = Path(self.temp.name)
        self.source = self.root / 'input'
        self.source.mkdir()
        (self.source / 'one.xml').write_bytes(BROKEN)
        (self.source / 'two.xml').write_bytes(GOOD)
        (self.source / 'unknown.xml').write_bytes(UNKNOWN)
        self.project = self.root / 'project.json'
        self.project.write_text(json.dumps({'schema_version': 1, 'apis': [{
            'id': 7, 'module': 'TEST.dll', 'export': 'Demo', 'return_type': 'BOOL',
            'parameters': [{'name': 'local', 'type': 'ULONG', 'direction': 'in'}]}]}), encoding='utf-8')
        self.sdk = self.root / 'sdk'
        self.sdk.mkdir()
        (self.sdk / 'sample.h').write_text('BOOL\nDemo(ULONG v);\n', encoding='utf-8')
        self.pin = audit_module.digest(BROKEN)
        audit_module.PREFIX_REPAIRS[self.pin] = b'c'

    def tearDown(self):
        audit_module.PREFIX_REPAIRS.pop(self.pin, None)
        self.temp.cleanup()

    def test_repair_copy_and_candidates(self):
        out = self.root / 'result'
        report = audit_module.audit(self.source, self.project, self.sdk, out, True)
        self.assertEqual(report['stats']['xml_files'], 3)
        self.assertEqual(report['stats']['parse_error_original'], 2)
        self.assertEqual(report['stats']['mechanically_repaired_files'], 1)
        self.assertEqual(report['stats']['unresolved_files'], 1)
        self.assertEqual(report['stats']['output_xml_files'], 3)
        self.assertEqual((out / 'xml/one.xml').read_bytes(), BROKEN[1:])
        self.assertEqual((out / 'xml/two.xml').read_bytes(), GOOD)
        self.assertEqual((out / 'xml/unknown.xml').read_bytes(), UNKNOWN)
        self.assertEqual((self.source / 'one.xml').read_bytes(), BROKEN)
        fix = report['repairs'][0]
        self.assertEqual(fix['before_sha256'], audit_module.digest(BROKEN))
        self.assertEqual(fix['after_sha256'], audit_module.digest(BROKEN[1:]))
        self.assertEqual(fix['remove_prefix_hex'], '63')
        self.assertEqual(len(report['files']), 3)
        differences = [d for d in report['diagnostics'] if d['kind'] == 'parameter_type_difference']
        self.assertEqual(len(differences), 2)
        self.assertEqual(differences[0]['status'], 'review')
        self.assertEqual(differences[0]['sdk_candidates'][0]['path'], 'sample.h')
        self.assertEqual(differences[0]['sdk_candidates'][0]['line'], 2)
        self.assertTrue((out / 'audit.json').is_file())

    def test_no_copy_unmodified_and_no_unsafe_outputs(self):
        out = self.root / 'result'
        report = audit_module.audit(self.source, self.project, None, out)
        self.assertEqual(report['stats']['output_xml_files'], 1)
        self.assertFalse((out / 'xml/two.xml').exists())
        with self.assertRaises(ValueError):
            audit_module.audit(self.source, self.project, None, out)
        with self.assertRaises(ValueError):
            audit_module.audit(self.source, self.project, None, self.source / 'child')
        with self.assertRaises(ValueError):
            audit_module.audit(self.source, self.project, None, self.root)

    def test_winverifytrust_partial_repair_is_hash_pinned_and_byte_exact(self):
        trust = (b'<ApiMonitor><Module Name="Wintrust.dll" ErrorFunc="GetLastError">'
                 b'<Api Name="WinVerifyTrust"><Param Type="HWND" Name="hWnd" />'
                 b'<Return Type="HRESULT" Display="LONG" /></Api>'
                 b'<Api Name="Other"><Return Type="HRESULT" Display="LONG" /></Api>'
                 b'</Module></ApiMonitor>')
        source = self.source / 'trust.xml'
        source.write_bytes(trust)
        pin = audit_module.digest(trust)
        audit_module.RETURN_TYPE_REPAIRS[pin] = True
        try:
            candidate = audit_module.repair_winverifytrust_return(trust)
            old = audit_module.WINVERIFYTRUST_OLD
            new = audit_module.WINVERIFYTRUST_NEW
            self.assertEqual(candidate, trust.replace(old, new, 1))
            self.assertIsNone(audit_module.repair_winverifytrust_return(trust + b' '))
            duplicated = trust.replace(b'</Module>',
                b'<Api Name="WinVerifyTrust"><Return Type="HRESULT" Display="LONG" /></Api></Module>')
            duplicate_pin = audit_module.digest(duplicated)
            audit_module.RETURN_TYPE_REPAIRS[duplicate_pin] = True
            try:
                self.assertIsNone(audit_module.repair_winverifytrust_return(duplicated))
            finally:
                del audit_module.RETURN_TYPE_REPAIRS[duplicate_pin]
            report = audit_module.audit(self.source, self.project, None, self.root / 'result')
            self.assertEqual(source.read_bytes(), trust)
            self.assertEqual((self.root / 'result/xml/trust.xml').read_bytes(), candidate)
            item = next(x for x in report['repairs'] if x['kind'] == 'winverifytrust_return_type')
            self.assertEqual(item['status'], 'partial_review_required')
            self.assertIn('GetLastError', item['remaining_review'])
            self.assertEqual(item['before_sha256'], pin)
            self.assertEqual(item['after_sha256'], audit_module.digest(candidate))
            pending = next(x for x in report['diagnostics'] if x['kind'] == 'return_semantics_pending')
            self.assertEqual(pending['status'], 'review')
            self.assertIn('success', pending['message'])
            manifest = next(x for x in report['files'] if x['path'] == 'trust.xml')
            self.assertEqual(manifest['status'], 'partially_corrected')
        finally:
            del audit_module.RETURN_TYPE_REPAIRS[pin]

    def test_hash_pin_and_no_entity(self):
        self.assertIsNone(audit_module.repair_for(BROKEN + b' '))
        self.assertIsNone(audit_module.repair_for(UNKNOWN))
        with self.assertRaises(ValueError):
            audit_module.parse_xml(b'<!DOCTYPE ApiMonitor [<!ENTITY x "test">]><ApiMonitor>&x;</ApiMonitor>')
        self.assertEqual(audit_module.normalize_charset('LPCTSTR', 'W'), 'LPCWSTR')
        self.assertEqual(audit_module.normalize_charset('[Handle]', 'W'), '[Handle]')

if __name__ == '__main__':
    unittest.main()
