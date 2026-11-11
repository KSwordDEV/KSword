"""Run health projection against synthetic transport and SCM states."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="ksword-health-") as temporary:
    binary = Path(temporary) / "health-test.exe"
    subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/W4", "/WX",
                    str(root / "tools/ksword_cli_health_test.cpp"), str(root / "KswordCLI/CommandRegistry.cpp"),
                    "/Fe:" + str(binary)], cwd=temporary, check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
print("CLI_HEALTH_TEST_PASS: healthy, missing driver, malformed list, degraded feature, unsupported v4, missing and truncated legacy fields")
