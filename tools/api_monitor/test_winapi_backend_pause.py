"""Exercise the production WinAPI backend against an owned target and Agent."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
qt = root / ".deps/Qt/6.9.3/msvc2022_64"
if not qt.exists():
    qt = Path("D:/Software/Qt/6.9.3/msvc2022_64")
pipe = root / "Ksword5.1/Ksword5.1/MonitorDock/WinAPIDock.Pipe.cpp"
source = pipe.read_text(encoding="utf-8-sig").split("void WinAPIDock::pollSessionBackend()")[0]
source = re.sub(r'#include "(\.\./[^\"]+)"', lambda m: '#include "' + (pipe.parent / m.group(1)).resolve().as_posix() + '"', source)
agent = Path(os.environ.get("KSWORD_PAUSE_AGENT", root / "Ksword5.1/x64/Release/APIMonitor_x64.dll"))
with tempfile.TemporaryDirectory(prefix="ksword_backend_pause_") as temporary:
    directory = Path(temporary)
    extracted = directory / "production_pipe.cpp"
    extracted.write_text(source, encoding="utf-8")
    includes = ["/I" + str(qt / "include" / name) for name in ("", "QtCore", "QtGui", "QtWidgets")]
    includes += ["/I" + str(root / "Ksword5.1/Ksword5.1"), "/I" + str(pipe.parent)]
    sources = [root / "tools/api_monitor/winapi_backend_pause_fixture.cpp", extracted,
               root / "shared/ApiMonitorInjectionBroker.cpp", root / "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.cpp",
               root / "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverError.cpp", root / "Ksword5.1/Ksword5.1/ksword/string/string.cpp"]
    exe = directory / "fixture.exe"
    subprocess.run(["cl", "/nologo", "/EHsc", "/std:c++20", "/Zc:__cplusplus", "/utf-8", "/MD", "/Gy",
                    "/DWIN32_LEAN_AND_MEAN", "/DNOMINMAX", "/FIWinSock2.h", *includes,
                    *map(str, sources), "/Fo:" + str(directory) + os.sep, "/Fe:" + str(exe), "/link", "/OPT:REF",
                    "/LIBPATH:" + str(qt / "lib"), "Qt6Core.lib", "Qt6Gui.lib", "Qt6Widgets.lib", "Advapi32.lib", "Psapi.lib"], check=True)
    env = os.environ.copy()
    env["PATH"] = str(root / "Ksword5.1/x64/Release") + os.pathsep + str(qt / "bin") + os.pathsep + env["PATH"]
    env["KSWORD_PAUSE_AGENT"] = str(agent.resolve())
    env["KSWORD_PAUSE_TEST_ROOT"] = str(directory / "archives")
    release = root / "Ksword5.1/x64/Release"
    for name in ("Qt6Core.dll", "Qt6Gui.dll", "msvcp140.dll", "msvcp140_atomic_wait.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        shutil.copy2(release / name, directory / name)
    subprocess.run([str(exe)], env=env, check=True, timeout=60)
    subprocess.run([str(exe), "--bad-agent"], env=env, check=True, timeout=60)
