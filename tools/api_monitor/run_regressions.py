"""Run each API Monitor regression in the x64 MSVC developer environment."""
from pathlib import Path
import argparse
import os
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--architecture", choices=("x86", "x64"), default="x64")
parser.add_argument("--no-ui", action="store_true", help="Run Agent/protocol regressions without the Qt view fixtures")
args = parser.parse_args()
os.environ["KSWORD_APIMON_ARCH"] = args.architecture
tests = sorted(Path(__file__).resolve().parent.glob("test_*.py"))
if args.architecture == "x86":
    tests = [t for t in tests if t.name not in ("test_hook_decoder.py", "test_capture_shutdown.py") and not t.name.startswith("test_ui_")]
else:
    tests = [t for t in tests if not t.name.startswith("test_x86_")]
if args.no_ui:
    tests = [t for t in tests if not t.name.startswith("test_ui_")]
for test in tests:
    print(f"REGRESSION_START={test.name}", flush=True)
    subprocess.run([sys.executable, str(test)], check=True, timeout=300)
    print(f"REGRESSION_PASS={test.name}", flush=True)
print(f"REGRESSION_RESULT=SUCCESS TEST_COUNT={len(tests)}", flush=True)
