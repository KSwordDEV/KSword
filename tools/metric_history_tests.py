"""验证共享历史模型、真实QPainter缺口和三个生产调用源的独立MSVC编译。"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import re
import subprocess
import sys

from async_operation_tests import extract_method

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "Ksword5.1/Ksword5.1"
OUTPUT = ROOT / "output"


def split_windows_command(command: str) -> list[str]:
    """使用Windows原生解析器保留MSBuild记录中的引号和空格路径。"""
    count = ctypes.c_int()
    parser = ctypes.windll.shell32.CommandLineToArgvW
    parser.argtypes = (ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int))
    parser.restype = ctypes.POINTER(ctypes.c_wchar_p)
    arguments = parser("cl " + command, ctypes.byref(count))
    try:
        return [arguments[index] for index in range(1, count.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(arguments)


def main() -> None:
    if not OUTPUT.is_dir():
        raise RuntimeError("The existing output directory is required.")
    template = (ROOT / "tools/metric_history_tests.template.cpp").read_text(encoding="utf-8-sig")
    callers = [
        (SOURCE / "HardwareDock/HardwareDock.cpp", "HardwareDock", ("appendCoreSeriesPoint(",
         "appendGeneralSeriesPoint(", "appendFilledSeriesPoint(", "updateSharedSeriesAxisRange(", "samplePerCoreUsage(")),
        (SOURCE / "MonitorDock/MonitorPanelWidget.cpp", "MonitorPanelWidget", ("appendLineSample(",)),
        (ROOT / "KswordHUD/HudPerformancePanel.cpp", "HudPerformancePanel", ("appendGeneralSeriesPoint(",
         "collectLiveSampleResult(", "applyLiveSampleResult(", "samplePerCoreUsage(")),
    ]
    methods = []
    for path, owner, names in callers:
        source = path.read_text(encoding="utf-8-sig")
        methods.extend(extract_method(source, owner + "::" + name) for name in names)
    generated = OUTPUT / "metric_history_production_fixture.cpp"
    hud_header = (ROOT / "KswordHUD/HudPerformancePanel.h").read_text(encoding="utf-8-sig")
    hud_types = "\n".join(extract_method(hud_header, "struct " + name) + ";" for name in
                          ("CpuPowerSnapshot", "SystemPerformanceSnapshot", "LiveSampleResult"))
    generated.write_text(template.replace("__PRODUCTION_CALLERS__", "\n".join(methods))
                         .replace("__PRODUCTION_HUD_TYPES__", hud_types), encoding="utf-8")
    qt = ROOT / ".deps/Qt/6.9.3/msvc2022_64"
    vc = Path("C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207")
    sdk = Path("C:/Program Files (x86)/Windows Kits/10")
    sdk_version = "10.0.26100.0"
    compiler = vc / "bin/Hostx64/x64/cl.exe"
    if not compiler.is_file() or not (qt / "lib/Qt6Widgets.lib").is_file():
        raise RuntimeError("The configured HostX64 MSVC/Qt toolchain is unavailable.")
    flags = ["/nologo", "/std:c++20", "/Zc:__cplusplus", "/permissive-", "/utf-8", "/EHsc", "/MD",
             "/W4", "/WX", "/external:W0", "/DNOMINMAX", "/DUNICODE", "/D_UNICODE",
             "/DQT_CORE_LIB", "/DQT_GUI_LIB", "/DQT_WIDGETS_LIB", "/I" + str(vc / "include")]
    system_flags = []
    for part in ("ucrt", "shared", "um"):
        system_flags.append("/external:I" + str(sdk / "Include" / sdk_version / part))
    flags.extend(system_flags)
    for module in ("", "QtCore", "QtGui", "QtWidgets", "QtSvg", "QtNetwork", "QtConcurrent"):
        flags.append("/external:I" + str(qt / "include" / module))
    log = OUTPUT / "metric_history_tests.log"
    log.write_text("HOST_TOOL_ARCHITECTURE=x64\nPRODUCTION_METHODS=10\n", encoding="utf-8")

    def run(arguments: list[str], environment: dict[str, str], cwd: Path = OUTPUT, timeout: int = 180) -> None:
        result = subprocess.run(arguments, cwd=cwd, env=environment, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout)
        text = result.stdout + result.stderr
        with log.open("a", encoding="utf-8") as stream:
            stream.write(text + "EXIT_CODE=" + str(result.returncode) + "\n")
        if text:
            print(text, end="" if text.endswith("\n") else "\n", flush=True)
        if result.returncode:
            raise RuntimeError("Metric history check failed; see " + str(log))

    environment = dict(os.environ)
    objects = []
    for path, name in ((generated, "fixture"), (ROOT / "shared/ui/MetricHistory.cpp", "model"),
                       (ROOT / "shared/ui/MetricChartBinding.cpp", "binding"),
                       (ROOT / "shared/ui/KsPainterChart.cpp", "painter"),
                       (SOURCE / "UI/PerformanceChartTheme.cpp", "theme")):
        obj = OUTPUT / ("metric_history_" + name + ".obj")
        run([str(compiler), *flags, "/c", str(path), "/Fo" + str(obj)], environment)
        objects.append(str(obj))
    libraries = ["/LIBPATH:" + str(vc / "lib/x64")]
    for part in ("ucrt", "um"):
        libraries.append("/LIBPATH:" + str(sdk / "Lib" / sdk_version / part / "x64"))
    exe = OUTPUT / "metric_history_tests.exe"
    run([str(vc / "bin/Hostx64/x64/link.exe"), "/nologo", "/SUBSYSTEM:CONSOLE", "/OUT:" + str(exe),
         *objects, *libraries, *(str(qt / "lib" / (name + ".lib")) for name in
                                ("Qt6Widgets", "Qt6Gui", "Qt6Core", "Qt6Svg"))], environment)
    environment["PATH"] = str(qt / "bin") + os.pathsep + environment.get("PATH", "")
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["QT_PLUGIN_PATH"] = str(qt / "plugins")
    run([str(exe)], environment, timeout=30)
    if "--skip-consumer-compile" in sys.argv:
        return

    # 复用已有生产编译命令，但所有OBJ/PDB写入专属output，不触生产增量缓存。
    main_record = SOURCE / "Ksword5.1/x64/Release/Ksword5.1.tlog/CL.command.1.tlog"
    hud_record = ROOT / "KswordHUD/x64/Release/KswordHUD.tlog/CL.command.1.tlog"
    for path, owner, _ in callers:
        record = hud_record if owner == "HudPerformancePanel" else main_record
        lines = record.read_text(encoding="utf-16").splitlines()
        commands = [lines[index + 1] for index, line in enumerate(lines[:-1])
                    if line.startswith("^") and str(path).casefold() in line.casefold()]
        if not commands:
            raise RuntimeError("Production compile record does not contain " + str(path))
        arguments = split_windows_command(commands[-1])
        arguments = [argument for argument in arguments
                     if not re.match(r"^/(?:Fo|Fd|Fp|Yu|GL|Zi|Z7)", argument, re.IGNORECASE)]
        arguments += ["/I" + str(vc / "include"), *system_flags,
                      "/Fo" + str(OUTPUT / ("metric_history_consumer_" + owner + ".obj")),
                      "/Fd" + str(OUTPUT / ("metric_history_consumer_" + owner + ".pdb"))]
        print("PRODUCTION_COMPILE=" + owner, flush=True)
        run([str(compiler), *arguments], environment, cwd=path.parent.parent if owner != "HudPerformancePanel"
            else path.parent)
        with log.open("a", encoding="utf-8") as stream:
            stream.write("PRODUCTION_COMPILE_" + owner + "=PASS\n")


if __name__ == "__main__":
    main()
