"""Exercise warning-only fallback without changing the strict CI result."""

from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).resolve().with_name("ci_build_with_warning_fallback.py")
REQUIRE_MSVC = "--require-msvc" in sys.argv
if REQUIRE_MSVC:
    sys.argv.remove("--require-msvc")


FAKE_BUILD = r'''
import os
from pathlib import Path
import sys

calls = Path(os.environ["KSWORD_TEST_CALLS"])
with calls.open("a", encoding="utf-8") as log:
    log.write(os.environ.get("_CL_", "") + "\n")
fallback = os.environ.get("_CL_", "").endswith("/WX-")
kind = os.environ["KSWORD_TEST_BUILD_KIND"]
if kind == "success":
    sys.exit(0)
if kind == "hard":
    print("error C2065: undeclared identifier")
    sys.exit(1)
if not fallback:
    print("error C2220: warning treated as error")
    sys.exit(1)
if kind == "fallback_failure":
    print("error C2065: undeclared identifier")
    sys.exit(1)
Path(os.environ["KSWORD_TEST_OUTPUT"]).write_text("candidate", encoding="utf-8")
'''


class WarningFallbackTests(unittest.TestCase):
    def execute_fake(self, kind, existing_cl=""):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "fake_build.py"
            fake.write_text(FAKE_BUILD, encoding="utf-8")
            calls = root / "calls.txt"
            artifact = root / "artifact.exe"
            env = os.environ.copy()
            env.update({"KSWORD_TEST_CALLS": str(calls), "KSWORD_TEST_OUTPUT": str(artifact),
                        "KSWORD_TEST_BUILD_KIND": kind, "_CL_": existing_cl})
            result = subprocess.run([sys.executable, str(HELPER), sys.executable, str(fake)],
                                    env=env, capture_output=True, text=True, timeout=30)
            return result, calls.read_text(encoding="utf-8").splitlines(), artifact.exists()

    def test_clean_build_does_not_retry(self):
        result, calls, artifact = self.execute_fake("success")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, [""])
        self.assertFalse(artifact)

    def test_c2220_can_produce_candidate_without_turning_ci_green(self):
        result, calls, artifact = self.execute_fake("warning", "/DORIGINAL=1")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, ["/DORIGINAL=1", "/DORIGINAL=1 /WX-"])
        self.assertTrue(artifact)
        self.assertIn("CI remains failed", result.stdout)

    def test_real_compile_error_does_not_trigger_warning_fallback(self):
        result, calls, artifact = self.execute_fake("hard")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(calls), 1)
        self.assertFalse(artifact)

    def test_unsuccessful_fallback_stays_failed(self):
        result, calls, artifact = self.execute_fake("fallback_failure")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(calls), 2)
        self.assertFalse(artifact)

    def test_link_options_in_environment_do_not_receive_compiler_override(self):
        result, calls, artifact = self.execute_fake("warning", "/link /DEBUG")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(calls), 1)
        self.assertFalse(artifact)

    def test_real_msvc_warning_fallback(self):
        cl = shutil.which("cl.exe") if os.name == "nt" else None
        if not cl:
            if REQUIRE_MSVC:
                self.fail("HostX64 cl.exe was not initialized")
            self.skipTest("Windows MSVC is not available")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "warning.cpp"
            obj = root / "warning.obj"
            source.write_text("int main() { int unused; return 0; }\n", encoding="utf-8")
            env = os.environ.copy()
            env.pop("_CL_", None)
            result = subprocess.run([sys.executable, str(HELPER), cl, "/nologo", "/W4", "/WX", "/c",
                                     str(source), "/Fo" + str(obj)],
                                    env=env, capture_output=True, text=True, errors="replace", timeout=60)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("C2220", result.stdout)
            self.assertTrue(obj.is_file(), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
