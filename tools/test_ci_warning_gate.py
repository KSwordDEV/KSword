"""Verify one-pass builds retain outputs while warnings fail CI."""

from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).resolve().with_name("ci_build_with_warning_gate.py")
REQUIRE_MSVC = "--require-msvc" in sys.argv
if REQUIRE_MSVC:
    sys.argv.remove("--require-msvc")

FAKE_BUILD = r'''
import json, os, sys
from pathlib import Path
import xml.etree.ElementTree as ET
root = ET.parse(os.environ["ForceImportBeforeCppTargets"]).getroot()
with Path(os.environ["KSWORD_TEST_CALLS"]).open("a", encoding="utf-8") as log:
    log.write(json.dumps({"args": sys.argv[1:], "cl": os.environ.get("_CL_", ""),
                          "imports": [e.attrib["Project"] for e in root]}) + "\n")
Path(os.environ["KSWORD_TEST_OUTPUT"]).write_text("generated", encoding="utf-8")
print(os.environ["KSWORD_TEST_MESSAGE"])
sys.exit(int(os.environ["KSWORD_TEST_EXIT"]))
'''


class WarningGateTests(unittest.TestCase):
    def execute_fake(self, message="", exit_code=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "fake_build.py"
            fake.write_text(FAKE_BUILD, encoding="utf-8")
            calls, artifact = root / "calls.jsonl", root / "output.exe"
            previous = root / "previous.props"
            previous.write_text("<Project />", encoding="utf-8")
            env = os.environ.copy()
            env.update({"KSWORD_TEST_CALLS": str(calls), "KSWORD_TEST_OUTPUT": str(artifact),
                        "KSWORD_TEST_MESSAGE": message, "KSWORD_TEST_EXIT": str(exit_code),
                        "_CL_": "/DORIGINAL=1 /WX", "ForceImportBeforeCppTargets": str(previous)})
            result = subprocess.run([sys.executable, str(HELPER), sys.executable, str(fake), "/WX", "/keep"],
                                    env=env, capture_output=True, text=True, timeout=30)
            records = [json.loads(line) for line in calls.read_text(encoding="utf-8").splitlines()]
            return result, records, artifact.exists(), str(previous)

    def test_clean_build_runs_once_and_retains_outputs(self):
        result, calls, artifact, previous = self.execute_fake()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["args"], ["/keep"])
        self.assertEqual(calls[0]["cl"], "/DORIGINAL=1")
        self.assertEqual(calls[0]["imports"][0], previous)
        self.assertTrue(calls[0]["imports"][-1].endswith("ci_msvc_warnings.props"))
        self.assertTrue(artifact)

    def test_compiler_linker_and_msbuild_warnings_fail_after_one_completed_build(self):
        for warning in ("file.cpp(1): warning C4101: unused", "LINK : warning LNK4099: missing PDB",
                        "build.targets(1): warning MSB3026: retrying copy", "cl : command line warning D9002: unknown option"):
            with self.subTest(warning=warning):
                result, calls, artifact, _ = self.execute_fake(warning)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(len(calls), 1)
                self.assertTrue(artifact)
                self.assertIn("Outputs are retained; CI remains failed", result.stdout)

    def test_native_failure_does_not_delete_outputs_already_generated(self):
        result, calls, artifact, _ = self.execute_fake("error C2065: undeclared identifier", 1)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(calls), 1)
        self.assertTrue(artifact)

    def test_ordinary_text_mentioning_warnings_is_not_a_diagnostic(self):
        result, calls, artifact, _ = self.execute_fake("warning gate test completed")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertTrue(artifact)

    def msvc(self):
        cl = shutil.which("cl.exe") if os.name == "nt" else None
        if not cl:
            if REQUIRE_MSVC:
                self.fail("HostX64 cl.exe was not initialized")
            self.skipTest("Windows MSVC is not available")
        return cl

    def test_real_cl_warning_still_produces_executable(self):
        cl = self.msvc()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, exe = root / "warning.cpp", root / "warning.exe"
            source.write_text("int main() { int unused; return 0; }\n", encoding="utf-8")
            result = subprocess.run([sys.executable, str(HELPER), cl, "/nologo", "/W4", "/WX",
                                     str(source), "/Fe" + str(exe), "/Fo" + str(root / "warning.obj")],
                                    capture_output=True, text=True, errors="replace", timeout=60)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("warning C4101", result.stdout)
            self.assertNotIn("C2220", result.stdout)
            self.assertTrue(exe.is_file())

    def test_real_msbuild_overrides_project_and_per_file_wx(self):
        self.msvc()
        vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
        located = subprocess.run([str(vswhere), "-latest", "-products", "*", "-requires",
                                  "Microsoft.Component.MSBuild", "-find", "MSBuild/**/Bin/amd64/MSBuild.exe"],
                                 capture_output=True, text=True, check=True)
        msbuild = located.stdout.splitlines()[0]
        for has_warning in (False, True):
            with self.subTest(has_warning=has_warning), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "main.cpp").write_text("int main() { " + ("int unused; " if has_warning else "")
                                                 + "return 0; }\n", encoding="utf-8")
                project = root / "Fixture.vcxproj"
                project.write_text('''<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations"><ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration></ItemGroup>
  <PropertyGroup Label="Globals"><ProjectGuid>{9253B3A0-F486-4229-A66F-25D82E664BED}</ProjectGuid><WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion></PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
  <PropertyGroup Label="Configuration"><ConfigurationType>Application</ConfigurationType><PlatformToolset>v143</PlatformToolset></PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
  <PropertyGroup><OutDir>$(MSBuildProjectDirectory)\\out\\</OutDir><IntDir>$(MSBuildProjectDirectory)\\obj\\</IntDir><TargetName>Fixture</TargetName></PropertyGroup>
  <ItemDefinitionGroup><ClCompile><WarningLevel>Level4</WarningLevel><TreatWarningAsError>true</TreatWarningAsError><AdditionalOptions>/WX %(AdditionalOptions)</AdditionalOptions></ClCompile><Link><SubSystem>Console</SubSystem><TreatLinkerWarningAsErrors>true</TreatLinkerWarningAsErrors></Link></ItemDefinitionGroup>
  <ItemGroup><ClCompile Include="main.cpp"><TreatWarningAsError>true</TreatWarningAsError><AdditionalOptions>/WX %(AdditionalOptions)</AdditionalOptions></ClCompile></ItemGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
</Project>''', encoding="utf-8")
                result = subprocess.run([sys.executable, str(HELPER), msbuild, str(project),
                                         "/p:Configuration=Release", "/p:Platform=x64", "/p:PreferredToolArchitecture=x64",
                                         "/p:PROCESSOR_ARCHITECTURE=AMD64", "/p:PROCESSOR_ARCHITEW6432=AMD64", "/v:minimal", "/m:1"],
                                        capture_output=True, text=True, errors="replace", timeout=120)
                self.assertEqual(result.returncode, 2 if has_warning else 0, result.stdout + result.stderr)
                self.assertNotIn("C2220", result.stdout)
                self.assertNotIn("D9025", result.stdout)
                self.assertTrue((root / "out/Fixture.exe").is_file(), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
