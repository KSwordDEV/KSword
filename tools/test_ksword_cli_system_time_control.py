"""Build the production SystemTime CLI projection with synthetic driver receipts."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="ksword-system-time-") as temporary:
    exe = Path(temporary) / "system-time-test.exe"
    subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/W4", "/WX",
                    str(root / "tools/ksword_cli_system_time_control_test.cpp"),
                    str(root / "KswordCLI/CommandRegistry.cpp"), "/Fe:" + str(exe)],
                   cwd=temporary, check=True)
    subprocess.run([str(exe)], check=True, timeout=10)
