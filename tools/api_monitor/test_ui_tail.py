"""Exercise the production WinAPI projection with real Qt layouts and bounded eviction."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
qt = root / ".deps/Qt/6.9.3/msvc2022_64"
if not qt.exists():
    qt = Path("D:/Software/Qt/6.9.3/msvc2022_64")
source = (root / "Ksword5.1/Ksword5.1/MonitorDock/WinAPIDock.Pipe.cpp").read_text(encoding="utf-8-sig")
methods = "\n".join([
    source[source.index("void WinAPIDock::acceptPendingEventRows("):source.index("WinAPIEventRef WinAPIDock::eventRecordAt(")],
    source[source.index("WinAPIEventRef WinAPIDock::eventRecordAt("):source.index("void WinAPIDock::flushPendingRows()")],
    source[source.index("void WinAPIDock::initializeEventTailFollow()"):source.index("void WinAPIDock::clearCanonicalEvents()")],
])
template = (root / "tools/api_monitor/ui_tail_fixture.cpp").read_text(encoding="utf-8")
with tempfile.TemporaryDirectory(prefix="ksword_apimon_tail_") as temporary:
    directory = Path(temporary)
    cpp = directory / "fixture.cpp"
    cpp.write_text(template.replace("// PRODUCTION_METHODS", methods), encoding="utf-8")
    includes = ["/I" + str(qt / "include" / name) for name in ("", "QtCore", "QtGui", "QtWidgets")]
    includes.append("/I" + str(root / "Ksword5.1/Ksword5.1"))
    libraries = [str(qt / "lib" / name) for name in ("Qt6Core.lib", "Qt6Gui.lib", "Qt6Widgets.lib")]
    executable = directory / "fixture.exe"
    subprocess.run(["cl", "/nologo", "/EHsc", "/permissive-", "/std:c++20", "/Zc:__cplusplus", "/utf-8", "/MD",
                    *includes, str(cpp), str(root / "Ksword5.1/Ksword5.1/MonitorDock/WinAPIEventTableModel.cpp"), str(root / "Ksword5.1/Ksword5.1/UI/AsyncOperation.cpp"), "/Fe:" + str(executable), "/Fo:" + str(directory) + os.sep,
                    "/link", *libraries], check=True)
    environment = os.environ.copy()
    key = next(key for key in environment if key.lower() == "path")
    environment[key] = str(qt / "bin") + os.pathsep + environment[key]
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["QT_QPA_PLATFORM_PLUGIN_PATH"] = str(qt / "plugins/platforms")
    subprocess.run([str(executable), os.environ.get("KSWORD_APIMON_UI_FIXTURE", "tail")], check=True, env=environment, timeout=90)
