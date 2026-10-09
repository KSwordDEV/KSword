import importlib.util
from pathlib import Path
import unittest
import re

spec = importlib.util.spec_from_file_location('ghidra_package', Path(__file__).resolve().parents[1]/'package.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PackagePaths(unittest.TestCase):
    def test_embedded_license_literals_fit_msvc(self):
        source=(Path(__file__).resolve().parents[1]/'RuntimeLicense.inc').read_text(encoding='utf-8')
        sizes=[len(match.group(2).encode('utf-8')) for match in re.finditer(r'R"([^()]*)\((.*?)\)\1"',source,re.S)]
        self.assertTrue(sizes)
        self.assertLessEqual(max(sizes),10000)

    def test_legal_paths_preserved(self):
        for path in ('root/LICENSE', 'root/licenses/GPL_2_With_Classpath_Exception.txt',
                     'root/legal/java.base/ADDITIONAL_LICENSE_INFO', 'root/GPL/README'):
            self.assertEqual(str(module.safe_member(path, 'root')), path)

    def test_unsafe_paths_refused(self):
        for path in ('../root/file', '/root/file', 'other/file', 'root/../escape', 'root/./escape',
                     'root//escape', 'root/back\\slash', 'root/C:/file', 'root/con.txt', 'root/file.',
                     'root/file ', 'root/NUL', 'root/aux.exe', 'root/a\x00b'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                module.safe_member(path, 'root')


if __name__ == '__main__':
    unittest.main()
