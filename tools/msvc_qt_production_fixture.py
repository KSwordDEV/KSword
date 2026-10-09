"""使用最新主程序 MSVC 对象构建独立 Qt 夹具，不重新构建生产程序。"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess


def run_msvc_fixture(repo: Path, source: Path, output: Path, name: str,
                     *, qt_root: Path | None = None, runtime_args: tuple[str, ...] = ()) -> None:
    """替换生产 main.obj；仅编译测试入口，产物写入调用方已有目录。"""
    repo = repo.resolve()
    output = output.resolve()
    if not output.is_dir():
        raise RuntimeError("The MSVC fixture output directory must already exist.")
    qt_candidates = [repo / ".deps/Qt/6.9.3/msvc2022_64", Path("D:/Software/Qt/6.9.3/msvc2022_64")]
    qt = qt_root.resolve() if qt_root else next((path for path in qt_candidates
                                               if (path / "lib/Qt6Widgets.lib").is_file()), None)
    if qt is None or not (qt / "lib/Qt6Test.lib").is_file():
        raise RuntimeError("A matching MSVC Qt SDK with Qt Test is required.")
    vc = Path("C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207")
    sdk = Path("C:/Program Files (x86)/Windows Kits/10")
    sdk_version = "10.0.26100.0"
    compiler = vc / "bin/Hostx64/x64/cl.exe"
    linker = vc / "bin/Hostx64/x64/link.exe"
    if not compiler.is_file() or not linker.is_file():
        raise RuntimeError("The validated HostX64 MSVC toolchain is unavailable.")

    # 只检查生产已知的两个日志落点；按时间选择最新成功链接记录。
    relative_logs = (
        "Ksword5.1/Ksword5.1/x64/Release/Ksword5.1.tlog/link.command.1.tlog",
        "Ksword5.1/Ksword5.1/Ksword5.1/x64/Release/Ksword5.1.tlog/link.command.1.tlog",
    )
    logs = [repo / path for path in relative_logs if (repo / path).is_file()]
    if not logs:
        raise RuntimeError("The production link record was not found in its known locations.")
    record = max(logs, key=lambda path: path.stat().st_mtime_ns)
    raw = record.read_bytes()
    lines = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig").splitlines()
    inputs: list[str] = []
    link_flags = ""
    for index, line in enumerate(lines):
        if index and re.search(r'/OUT:"[^"\r\n]*\\KSWORD5\.1\.EXE"', line, re.IGNORECASE):
            inputs = lines[index - 1].lstrip("^").split("|")
            link_flags = line
    if not link_flags or len(inputs) < 2:
        raise RuntimeError("The selected log does not contain a production application link.")
    if not any(re.search(r"SNAPSHOTWORKBENCHWIDGET\.EDITING\.OBJ$", path, re.IGNORECASE) for path in inputs):
        raise RuntimeError("The production link record does not include the current snapshot editor.")
    main_objects = [path for path in inputs if Path(path).name.casefold() == "main.obj"]
    if len(main_objects) != 1:
        raise RuntimeError("The production main object is ambiguous.")
    inputs = [path for path in inputs if path not in main_objects and re.search(r"\.(OBJ|LIB)$", path, re.IGNORECASE)]
    if any(not Path(path).is_file() for path in inputs):
        raise RuntimeError("A recorded production object or library is unavailable.")

    # 用同一工具链编译入口；中文 fixture 数据使用 UTF-8，默认 /MD 与生产对象一致。
    obj = output / (name + ".obj")
    exe = output / (name + ".exe")
    args = [str(compiler), "/nologo", "/std:c++20", "/Zc:__cplusplus", "/permissive-", "/utf-8",
            "/EHsc", "/MD", "/W4", "/WX", "/external:W0", "/DWIN32_LEAN_AND_MEAN", "/DNOMINMAX",
            "/DUNICODE", "/D_UNICODE", "/DZYDIS_STATIC_BUILD", "/DQT_WIDGETS_LIB", "/DQT_GUI_LIB",
            "/DQT_CORE_LIB", "/DQT_TESTLIB_LIB", "/I" + str(repo), "/I" + str(vc / "include")]
    for module in ("", "QtCore", "QtGui", "QtWidgets", "QtTest", "QtSvg"):
        args.append("/external:I" + str(qt / "include" / module))
    for part in ("ucrt", "shared", "um"):
        args.append("/external:I" + str(sdk / "Include" / sdk_version / part))
    args += ["/c", str(source), "/Fo" + str(obj)]
    log = output / (name + ".log")

    def run(command: list[str], environment: dict[str, str], timeout: int) -> None:
        result = subprocess.run(command, cwd=repo, env=environment, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=timeout)
        text = result.stdout + result.stderr
        with log.open("a", encoding="utf-8") as stream:
            stream.write(text)
        if text:
            print(text, end="" if text.endswith("\n") else "\n", flush=True)
        if result.returncode:
            raise RuntimeError(f"{name} failed with exit code {result.returncode}; see {log}")

    log.write_text("PRODUCTION_LINK_RECORD=" + str(record) + "\n", encoding="utf-8")
    environment = dict(os.environ)
    environment["PATH"] = str(sdk / "bin" / sdk_version / "x64") + os.pathsep + environment.get("PATH", "")
    print("PRODUCTION_LINK_RECORD=" + str(record), flush=True)
    run(args, environment, 180)

    # 保留全部真实 OBJ/LIB；输出、入口与 LTCG 暂存文件改为夹具自身路径。
    response = re.sub(r'/(?:OUT|PDB|IMPLIB|LTCGOUT):(?:"[^"]*"|\S+)', "", link_flags, flags=re.IGNORECASE)
    response = re.sub(r"/SUBSYSTEM:\S+|\S+\.RES\b", "", response, flags=re.IGNORECASE)
    response += f' /OUT:"{exe}" /SUBSYSTEM:CONSOLE /INCREMENTAL:NO "{obj}"'
    response += f' /LTCG:INCREMENTAL /LTCGOUT:"{output / (name + ".iobj")}" "{qt / "lib/Qt6Test.lib"}"'
    library_dirs = [vc / "lib/x64", vc / "atlmfc/lib/x64", repo / "Ksword5.1/Ksword5.1/lib"]
    library_dirs += [sdk / "Lib" / sdk_version / part / "x64" for part in ("ucrt", "um")]
    for library in library_dirs:
        response += f' /LIBPATH:"{library}"'
    response += "".join(f'\r\n"{path}"' for path in inputs)
    response_file = output / (name + ".rsp")
    response_file.write_text(response, encoding="utf-16")
    run([str(linker), "@" + str(response_file)], environment, 300)

    # 仅启动夹具入口的 QApplication；业务 main 和真实目标会话不在本次程序内启动。
    environment["PATH"] = str(repo / "Ksword5.1/x64/Release") + os.pathsep + str(qt / "bin") + os.pathsep + environment["PATH"]
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["QT_PLUGIN_PATH"] = str(qt / "plugins")
    run([str(exe), *runtime_args], environment, 120)
