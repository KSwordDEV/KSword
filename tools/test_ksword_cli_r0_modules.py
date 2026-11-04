"""Build the production R0 module CLI projection against a transport fixture."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="ksword-r0-modules-") as temporary:
    binary = Path(temporary) / "test.exe"
    subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/W4", "/WX",
                    str(root / "tools/ksword_cli_r0_modules_test.cpp"),
                    str(root / "KswordCLI/CommandRegistry.cpp"), str(root / "KswordCLI/CliArgs.cpp"), str(root / "KswordCLI/CliText.cpp"),
                    "/Fe:" + str(binary)], cwd=temporary, check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
print("R0_MODULE_CLI_PASS: identity, bounded rows, malformed reply and continuation")
