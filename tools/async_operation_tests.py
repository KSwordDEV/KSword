"""编译真实异步控制器及从当前生产源码完整抽取的方法，使用 Qt/offscreen。"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "Ksword5.1/Ksword5.1"
OUTPUT = ROOT / "output"


def extract_method(source: str, signature: str) -> str:
    """按 C++ 字符串/注释边界提取完整函数体，避免只测试复制的逻辑摘要。"""
    marker = source.index(signature)
    start = source.rfind("\n", 0, marker) + 1
    index = source.index("{", marker)
    depth = 0
    mode = "code"
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if mode in ("string", "char"):
            if char == "\\":
                index += 2
                continue
            if char == ('"' if mode == "string" else "'"):
                mode = "code"
        elif mode == "line":
            if char == "\n":
                mode = "code"
        elif mode == "comment":
            if char == "*" and next_char == "/":
                mode = "code"
                index += 2
                continue
        elif char == "/" and next_char in ("/", "*"):
            mode = "line" if next_char == "/" else "comment"
            index += 2
            continue
        elif char in ('"', "'"):
            mode = "string" if char == '"' else "char"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1] + "\n"
        index += 1
    raise RuntimeError("Unclosed production method: " + signature)


def main() -> None:
    if not OUTPUT.is_dir():
        raise RuntimeError("The existing output directory is required.")
    module = (SOURCE / "ProcessDock/ProcessDetailWindow.Module.cpp").read_text(encoding="utf-8-sig")
    handle = (SOURCE / "句柄/HandleDock.Detail.cpp").read_text(encoding="utf-8-sig")
    module_names = ("~ProcessDetailWindow()", "requestAsyncModuleRefresh(",
                    "tryApplyModuleRefreshResult(", "applyModuleRefreshResult(", "updateModuleStatusLabel(")
    handle_names = ("~HandleDock()", "requestHandleDetailRefresh(",
                    "tryApplyHandleDetailRefreshResult(", "applyHandleDetailRefreshResult(",
                    "showHandleDetailPlaceholder(")
    module_methods = "\n".join(extract_method(module, "ProcessDetailWindow::" + name) for name in module_names)
    handle_methods = "\n".join(extract_method(handle, "HandleDock::" + name) for name in handle_names)
    template = (ROOT / "tools/async_operation_tests.template.cpp").read_text(encoding="utf-8-sig")
    generated = OUTPUT / "async_operation_production_fixture.cpp"
    generated.write_text(template.replace("__PRODUCTION_MODULE__", module_methods)
                         .replace("__PRODUCTION_HANDLE__", handle_methods), encoding="utf-8")

    # 路径沿用仓库验证过的工具链，无全盘查找，不创建目录或重建生产主程序。
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
    for module_name in ("", "QtCore", "QtGui", "QtWidgets"):
        flags.append("/external:I" + str(qt / "include" / module_name))
    for part in ("ucrt", "shared", "um"):
        flags.append("/external:I" + str(sdk / "Include" / sdk_version / part))
    probes = [argument for argument in sys.argv[1:] if argument not in ("--asan", "--record-red")]
    if "--asan" in sys.argv:
        flags.extend(("/fsanitize=address", "/Zi", "/O1"))
    suffix = probes[0].replace("--", "_") if probes else ""
    if "--record-red" in sys.argv:
        suffix = "_red" + suffix
    log = OUTPUT / ("async_operation_tests" + suffix + ".log")
    log.write_text("PRODUCTION_METHODS=10\nHOST_TOOL_ARCHITECTURE=x64\n", encoding="utf-8")

    def run(arguments: list[str], environment: dict[str, str], timeout: int = 120) -> None:
        result = subprocess.run(arguments, cwd=OUTPUT, env=environment, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=timeout)
        text = result.stdout + result.stderr
        with log.open("a", encoding="utf-8") as stream:
            stream.write(text)
            stream.write("EXIT_CODE=" + str(result.returncode) + "\n")
        if text:
            print(text, end="" if text.endswith("\n") else "\n", flush=True)
        if result.returncode:
            raise RuntimeError("Async operation fixture failed; see " + str(log))

    environment = dict(os.environ)
    objects = []
    for file, name in ((generated, "async_operation_production_fixture"),
                       (SOURCE / "UI/AsyncOperation.cpp", "async_operation_controller")):
        obj = OUTPUT / (name + ".obj")
        run([str(compiler), *flags, "/c", str(file), "/Fo" + str(obj)], environment)
        objects.append(str(obj))
    exe = OUTPUT / "async_operation_tests.exe"
    linker = vc / "bin/Hostx64/x64/link.exe"
    libraries = ["/LIBPATH:" + str(vc / "lib/x64")]
    for part in ("ucrt", "um"):
        libraries.append("/LIBPATH:" + str(sdk / "Lib" / sdk_version / part / "x64"))
    run([str(linker), "/nologo", "/SUBSYSTEM:CONSOLE", "/OUT:" + str(exe), *objects,
         *libraries, *(str(qt / "lib" / (name + ".lib")) for name in ("Qt6Widgets", "Qt6Gui", "Qt6Core"))],
        environment)
    environment["PATH"] = str(qt / "bin") + os.pathsep + str(vc / "bin/Hostx64/x64") + os.pathsep + environment.get("PATH", "")
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["QT_PLUGIN_PATH"] = str(qt / "plugins")
    run([str(exe), *probes], environment, 30)


if __name__ == "__main__":
    main()
