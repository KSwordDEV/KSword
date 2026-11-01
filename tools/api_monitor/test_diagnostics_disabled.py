"""Disabled diagnostics do not evaluate arguments, link profiling code or retain strings."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
marker = "KSWORD_DIAGNOSTIC_MUST_NOT_EXIST_IN_BINARY"
source = r'''
#include "HEADER"
int main(){
 int evaluated=0;
 APIMON_DIAG_RESET();
 APIMON_DIAG_SCOPE(InstallTicks);
 APIMON_DIAG_ADD(NearQueries,++evaluated);
 APIMON_DIAG_MARK("MARKER",++evaluated,UnresolvedDiagnosticArgument());
 return evaluated;
}
'''.replace("HEADER", (root / "APIMonitor_x64/core/MonitorDiagnostics.h").as_posix()).replace("MARKER", marker)
with tempfile.TemporaryDirectory(prefix="ksword_no_diagnostics_") as temporary:
    folder = Path(temporary)
    cpp = folder / "fixture.cpp"
    cpp.write_text(source, encoding="utf-8")
    for mode, defines in (("default", []), ("off", ["/DKSWORD_APIMON_DIAGNOSTICS=0"])):
        exe = folder / (mode + ".exe")
        subprocess.run(["cl", "/nologo", "/EHsc", "/Od", "/std:c++17", *defines, str(cpp),
                        "/Fe:" + str(exe), "/Fo:" + str(folder / (mode + ".obj"))], check=True)
        subprocess.run([str(exe)], check=True, timeout=5)
        assert marker.encode() not in exe.read_bytes()
print("PASS: default/off macros erase argument evaluation, symbol dependencies and profiling strings even under /Od")
