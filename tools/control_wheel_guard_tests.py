"""从 MainWindow.cpp 提取真实滚轮过滤器，构建并运行独立 MSVC/Qt 回归夹具。"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess


def run(command: list[str], repo: Path, environment: dict[str, str], log: Path) -> int:
    """输入命令、仓库、环境和日志路径；同步执行并输出退出状态与完整诊断。"""
    # result 保存真实编译或运行回执；text 保留标准输出及错误，不隐藏失败。
    result = subprocess.run(command, cwd=repo, env=environment, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=180)
    text = result.stdout + result.stderr
    with log.open("a", encoding="utf-8") as stream:
        stream.write(text)
    print(text, end="" if text.endswith("\n") else "\n", flush=True)
    return result.returncode


def main() -> int:
    """解析输出目录及可选旧生产类基线，仅在已存在目录写入构建文件。"""
    # parser/args 保存可复现 CLI 参数；repo/output 是仓库与已有产物目录。
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="output")
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    output = (repo / args.output).resolve()
    if not output.is_dir() or not output.is_relative_to(repo):
        raise RuntimeError("Output must be an existing directory within the repository.")

    # qt_candidates 仅查询仓库依赖与约定安装目录，禁止递归搜索磁盘。
    qt_candidates = [repo / ".deps/Qt/6.9.3/msvc2022_64", Path("D:/Software/Qt/6.9.3/msvc2022_64")]
    qt = next((path for path in qt_candidates if (path / "lib/Qt6Test.lib").is_file()), None)
    if qt is None:
        raise RuntimeError("The known MSVC Qt installation is unavailable.")
    vc = Path("C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207")
    sdk = Path("C:/Program Files (x86)/Windows Kits/10")
    sdk_version = "10.0.26100.0"
    compiler = vc / "bin/Hostx64/x64/cl.exe"
    if not compiler.is_file():
        raise RuntimeError("The required HostX64 MSVC compiler is unavailable.")

    # source/class_text 保存原始生产类；fixture_header 用于编译包含，不改变其策略。
    source = (repo / "Ksword5.1/Ksword5.1/MainWindow.cpp").read_text(encoding="utf-8-sig")
    match = re.search(r"    class GlobalSliderWheelFilter final\b.*?^    };", source,
                      flags=re.DOTALL | re.MULTILINE)
    if match is None:
        raise RuntimeError("The production wheel filter class was not found.")
    class_text = args.baseline.read_text(encoding="utf-8-sig") if args.baseline else match.group(0)
    fixture_header = output / "control_wheel_guard_extracted.h"
    fixture_header.write_text(class_text, encoding="utf-8")
    name = "control_wheel_guard_baseline" if args.baseline else "control_wheel_guard"
    log = output / (name + ".log")
    log.write_text("PRODUCTION_FILTER_SOURCE=" + str(args.baseline or repo / "Ksword5.1/Ksword5.1/MainWindow.cpp") + "\n",
                   encoding="utf-8")

    # environment 配置 Qt 离屏运行，cmd 保持 x64/MD/WX 并直接编译生产滚动源码。
    environment = dict(os.environ)
    environment["PATH"] = str(qt / "bin") + os.pathsep + environment.get("PATH", "")
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["QT_PLUGIN_PATH"] = str(qt / "plugins")
    cmd = [str(compiler), "/nologo", "/std:c++20", "/utf-8", "/Zc:__cplusplus", "/permissive-",
           "/EHsc", "/MD", "/W4", "/WX", "/external:W0", "/DUNICODE", "/D_UNICODE",
           "/DWIN32_LEAN_AND_MEAN", "/DNOMINMAX", "/I" + str(repo), "/I" + str(output),
           "/I" + str(vc / "include")]
    for module in ("", "QtCore", "QtGui", "QtWidgets", "QtTest"):
        cmd.append("/external:I" + str(qt / "include" / module))
    for part in ("ucrt", "shared", "um"):
        cmd.append("/external:I" + str(sdk / "Include" / sdk_version / part))
    cmd += [str(repo / "tools/control_wheel_guard_tests.cpp"),
            "/Fo" + str(output / (name + "_fixture.obj")),
            "/Fe" + str(output / (name + ".exe")),
            "/link", "/SUBSYSTEM:CONSOLE", "/INCREMENTAL:NO", "/LIBPATH:" + str(vc / "lib/x64")]
    for part in ("ucrt", "um"):
        cmd.append("/LIBPATH:" + str(sdk / "Lib" / sdk_version / part / "x64"))
    cmd.append("/LIBPATH:" + str(qt / "lib"))
    cmd += ["Qt6Widgets.lib", "Qt6Gui.lib", "Qt6Core.lib", "Qt6Test.lib", "user32.lib"]
    code = run(cmd, repo, environment, log)
    if code:
        return code
    return run([str(output / (name + ".exe"))], repo, environment, log)


if __name__ == "__main__":
    raise SystemExit(main())
