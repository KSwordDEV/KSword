"""Compile the production inventory functions with deterministic native API stubs."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "KswordARKDriver/src/features/kernel/module_inventory.c").read_text(encoding="utf-8")
body = source[source.index("typedef struct _KSW_MODULE_BASIC_INFORMATION"):source.index("/* METHOD_BUFFERED input and output overlap")]
fixture = (root / "tools/r0_modules_driver_fixture.cpp").read_text(encoding="utf-8")
fixture = fixture.replace('#include "../shared/driver/KswordArkModuleIoctl.h"',
                          '#include "' + (root / "shared/driver/KswordArkModuleIoctl.h").as_posix() + '"')
fixture = fixture.replace("/*SOURCE_INSERT*/", body)
with tempfile.TemporaryDirectory(prefix="ksword-module-driver-") as temporary:
    temporary = Path(temporary)
    test = temporary / "fixture.cpp"
    test.write_text(fixture, encoding="utf-8")
    binary = temporary / "fixture.exe"
    subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/W4", "/WX", str(test), "/Fe:" + str(binary)], cwd=temporary, check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
print("R0_MODULE_DRIVER_PASS: bounded snapshots, continuation, PID identity and malformed regions")
