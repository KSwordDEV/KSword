#!/usr/bin/env python3
"""Run the production RegistryDock thread/stop code against a blocking backend shim.

No registry key, .reg import/export, Windows process, or real GUI is touched.
"""
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = ROOT / "Ksword5.1/Ksword5.1"


def balanced_end(text: str, start: int, opening: str, closing: str) -> int:
    depth, state, index = 0, "code", start
    while index < len(text):
        char, pair = text[index], text[index:index + 2]
        if state == "line":
            if char == "\n": state = "code"
        elif state == "block":
            if pair == "*/": state = "code"; index += 1
        elif state in ('"', "'"):
            if char == "\\": index += 1
            elif char == state: state = "code"
        elif pair == "//": state = "line"; index += 1
        elif pair == "/*": state = "block"; index += 1
        elif char in ('"', "'"): state = char
        elif char == opening: depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0: return index + 1
        index += 1
    raise ValueError("Unbalanced production block")


def method(source: str, signature: str) -> str:
    begin = source.index(signature)
    opening = source.index("{", begin)
    return source[begin:balanced_end(source, opening, "{", "}")]


def main() -> None:
    # 正式源码分工：Search.cpp 持有真实 worker，Themed.cpp 持有 stop/析构。
    active = (SOURCE_ROOT / "RegistryDock/RegistryDock.Search.cpp").read_text(encoding="utf-8-sig")
    themed = (SOURCE_ROOT / "RegistryDock_Themed.cpp").read_text(encoding="utf-8-sig")
    start = method(active, "void RegistryDock::startSearchAsync()")
    prefix = start[start.index("{") + 1:start.index("    QString keyword")]
    begin = start.index("    m_searchThread = std::make_unique<std::thread>(")
    opening = start.index("(", begin)
    worker = start[begin:balanced_end(start, opening, "(", ")") + 1]
    stop = method(themed, "void RegistryDock::stopSearch(bool waitForThread)")
    destructor = method(themed, "RegistryDock::~RegistryDock()")
    assert ".detach()" not in stop and "std::move(m_searchThread)" not in stop
    assert "m_uiDispatcher->close()" in destructor and "stopSearch(true)" in destructor
    fixture = Path(__file__).with_name("registry_search_lifetime_tests.template.cpp").read_text(encoding="utf-8")
    for marker, content in {"//@@PREFIX@@": prefix, "//@@WORKER@@": worker,
                            "//@@STOP@@": stop, "//@@DESTRUCTOR@@": destructor}.items():
        fixture = fixture.replace(marker, content)
    assert "RegSetValue" not in fixture and "RegOpenKey" not in fixture
    out = ROOT / ".codex-build-logs"
    if not out.is_dir():
        raise SystemExit("Existing .codex-build-logs directory required; no temporary directory is created.")
    cpp = out / "registry_search_lifetime_tests.cpp"
    exe = out / "registry_search_lifetime_tests.exe"
    cpp.write_text(fixture, encoding="utf-8")
    qt = ROOT / ".deps/Qt/6.9.3/msvc2022_64"
    vcvars = Path("C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Auxiliary/Build/vcvars64.bat")
    flags = ["/nologo", "/std:c++20", "/utf-8", "/EHsc", "/MD", "/W4", "/WX", "/external:W0",
             "/DWIN32_LEAN_AND_MEAN", "/DNOMINMAX", "/Zc:__cplusplus", "/permissive-",
             "/external:I" + str(qt / "include"), "/external:I" + str(qt / "include/QtCore"),
             "/I" + str(SOURCE_ROOT), str(cpp), "/Fo" + str(out / "registry_search_lifetime_tests.obj"),
             "/Fe" + str(exe), "/link", "/LIBPATH:" + str(qt / "lib"), "Qt6Core.lib"]
    command = subprocess.list2cmdline(["cl", *flags])
    batch = out / "registry-search-command.cmd"
    batch.write_text('@echo off\ncall "' + str(vcvars) + '" >nul\nif errorlevel 1 exit /b %errorlevel%\n'
                     + command + '\nexit /b %errorlevel%\n', encoding="utf-8")
    import os
    environment = dict(os.environ)
    environment["PATH"] = str(qt / "bin") + os.pathsep + environment.get("PATH", "")
    subprocess.run(["cmd", "/d", "/c", batch], cwd=ROOT, env=environment, check=True, timeout=60)
    subprocess.run([exe], cwd=ROOT, env=environment, check=True, timeout=20)


if __name__ == "__main__": main()
