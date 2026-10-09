"""离线执行真实发行脚本的驱动聚合段，验证完整性与旧模板覆盖。"""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / ".github/workflows/scripts/publish-ci-prerelease.sh"
FILES = (
    "KswordARK.sys",
    "KswordARKDriver.inf",
    "KswordARKStorageController.inf",
    "KswordARKStorageController.cat",
)


def bash_path():
    """选择本机 Git Bash 或 PATH 中的 Bash，不启动 WSL 或查找盘根。"""
    if os.name == "nt":
        candidate = Path("C:/Program Files/Git/bin/bash.exe")
        if candidate.is_file():
            return str(candidate)
    candidate = shutil.which("bash")
    if candidate is None:
        raise RuntimeError("Bash is required for the production packaging regression")
    return candidate


def production_block():
    """从生产脚本提取实际聚合代码，测试不能维护一份替代实现。"""
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("# BEGIN unified driver package:")
    end = source.index("# END unified driver package.", start)
    return source[start:end]


class DriverPackageTests(unittest.TestCase):
    def setUp(self):
        # 每例独享小型假安装材料；不编译、不下载、不操作真实驱动。
        self.directory = tempfile.TemporaryDirectory(prefix="ksword-package fixture-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.artifact = self.root / "artifact with spaces"
        self.source = self.artifact / "nested output" / "Release"
        self.release = self.root / "Release"
        self.source.mkdir(parents=True)
        self.release.mkdir()
        self.expected = {}
        for name in FILES:
            data = ("current-build:" + name).encode("utf-8")
            self.expected[name] = data
            (self.source / name).write_bytes(data)

    def execute(self):
        """以环境变量传递路径，避免把夹具路径插入 shell 代码。"""
        environment = os.environ.copy()
        environment["KSWORD_TEST_DRIVER_ROOT"] = self.artifact.as_posix()
        environment["KSWORD_TEST_RELEASE_ROOT"] = self.release.as_posix()
        prelude = (
            "set -euo pipefail\n"
            'declare -A artifact_directories=([KswordARKDriver-unsigned-Release]="$KSWORD_TEST_DRIVER_ROOT")\n'
            'release_root="$KSWORD_TEST_RELEASE_ROOT"\n'
        )
        return subprocess.run(
            [bash_path(), "--noprofile", "--norc", "-c", prelude + production_block()],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_new_package_populates_both_installation_locations(self):
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        for directory in (self.release, self.release / "KswordARKDriver"):
            for name, data in self.expected.items():
                self.assertEqual((directory / name).read_bytes(), data)

    def test_current_build_replaces_stale_manual_template(self):
        nested = self.release / "KswordARKDriver"
        nested.mkdir()
        for directory in (self.release, nested):
            for name in FILES:
                (directory / name).write_bytes(b"stale-template")
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        for directory in (self.release, nested):
            for name, data in self.expected.items():
                self.assertEqual((directory / name).read_bytes(), data)

    def test_missing_or_empty_input_fails_before_overwriting_template(self):
        # 旧模板即使含有同名材料，也不能掩盖当次构建缺失或空产物。
        for name in FILES:
            for missing in (True, False):
                with self.subTest(name=name, missing=missing):
                    for source_name, data in self.expected.items():
                        (self.source / source_name).write_bytes(data)
                    for destination_name in FILES:
                        (self.release / destination_name).write_bytes(b"original-template")
                    if missing:
                        (self.source / name).unlink()
                    else:
                        (self.source / name).write_bytes(b"")
                    result = self.execute()
                    self.assertNotEqual(result.returncode, 0)
                    for destination_name in FILES:
                        self.assertEqual((self.release / destination_name).read_bytes(), b"original-template")
                    self.assertFalse((self.release / "KswordARKDriver").exists())

    def test_ambiguous_driver_roots_are_rejected(self):
        other = self.artifact / "second output"
        other.mkdir()
        for name, data in self.expected.items():
            (other / name).write_bytes(data)
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one", result.stderr)
        self.assertFalse(any(self.release.iterdir()))

    def test_aggregate_gate_requires_controller_materials_in_both_locations(self):
        # 独立检查压缩前的最终门禁，避免未来只修改复制段而遗漏包校验。
        source = SCRIPT.read_text(encoding="utf-8")
        required = source.split("readonly -a required_release_paths=(", 1)[1].split(")", 1)[0]
        for prefix in ("", "KswordARKDriver/"):
            for name in FILES:
                self.assertIn("'" + prefix + name + "'", required)


if __name__ == "__main__":
    unittest.main()
