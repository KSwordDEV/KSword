#!/usr/bin/env python3
"""Compile exact production NTFS projection/path helpers with QtCore only.

No Windows, widgets, filesystem operations or alternative aggregation algorithm
are linked. Pass --qt-include when Qt development headers are outside /usr.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


def function(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for position in range(opening, len(source)):
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
            if depth == 0:
                return source[start:position + 1]
    raise ValueError(f"unterminated production function {signature}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qt-include", type=Path)
    parser.add_argument("--compiler", default="cl" if os.name == "nt" else "g++")
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source_root = root / "Ksword5.1/Ksword5.1"
    page = (source_root / "FileDock/DiskSpacePage.cpp").read_text(encoding="utf-8-sig")
    backend = (source_root / "FileDock/NtfsFastIndex.cpp").read_text(encoding="utf-8")
    if os.name == "nt":
        from native_msvc_test_support import find_msvc_developer_environment, qt_root
        qt = qt_root()
        includes = [options.qt_include or qt / "include"]
    else:
        includes = [options.qt_include] if options.qt_include else [
            Path("/usr/include/x86_64-linux-gnu/qt6"), Path("/usr/include/qt6")]
    qt_include = next((p for p in includes if p and (p / "QtCore/QtGlobal").exists()), None)
    if not qt_include:
        parser.error("Qt6 development headers unavailable; pass --qt-include")
    declarations = page[page.index("struct Totals "):page.index("ProjectionPtr project(")]
    extracted = "\n".join([
        '#include "FileDock/NtfsFastIndex.h"', "#include <QDateTime>",
        "#include <QSet>", "#include <QStringList>", "#include <algorithm>",
        "#include <limits>", "#include <utility>",
        "namespace ks::files {", function(backend, "QString NtfsFastIndex::fullPath("),
        function(backend, "void finish("), "}",
        "using Index = ks::files::NtfsFastIndex;", "using Entry = ks::files::NtfsIndexEntry;",
        function(page, "quint64 addBytes("), declarations, function(page, "ProjectionPtr project("),
    ])
    print("PRODUCTION_HELPERS_SHA256=" + hashlib.sha256(extracted.encode()).hexdigest(), flush=True)
    temporary_root = root / ".codex-build-logs" if os.name == "nt" else None
    if temporary_root:
        temporary_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ksword-ntfs-projection-", dir=temporary_root) as directory:
        work = Path(directory)
        (work / "ntfs_projection.inc").write_text(extracted, encoding="utf-8")
        if os.name == "nt":
            binary = work / "ntfs_projection_test.exe"
            command = [options.compiler, "/nologo", "/std:c++20", "/O2", "/EHsc", "/MD",
                       "/W4", "/WX", "/utf-8", "/Zc:__cplusplus", "/DNOMINMAX", "/external:W0",
                       "/external:I" + str(qt_include), "/external:I" + str(qt_include / "QtCore"),
                       "/I" + str(source_root), "/I" + str(work),
                       str(root / "tools/ntfs_index_projection_test.cpp"), "/Fe:" + str(binary),
                       "/Fo:" + str(work) + "\\", "/link", "/LIBPATH:" + str(qt / "lib"), "Qt6Core.lib"]
            script = work / "build.cmd"
            script.write_text('@echo off\ncall "' + str(find_msvc_developer_environment())
                              + '" -arch=x64 -host_arch=x64 >nul\n' + subprocess.list2cmdline(command)
                              + '\nexit /b %errorlevel%\n', encoding="utf-8")
            subprocess.run(["cmd", "/d", "/c", str(script)], cwd=work, check=True)
            env = dict(os.environ)
            env["PATH"] = str(qt / "bin") + os.pathsep + env.get("PATH", "")
            subprocess.run([str(binary)], cwd=work, env=env, check=True)
            return
        binary = work / "ntfs_projection_test"
        subprocess.run([
            options.compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC",
            "-I" + str(qt_include), "-I" + str(qt_include / "QtCore"),
            "-I" + str(source_root), "-I" + str(work),
            str(root / "tools/ntfs_index_projection_test.cpp"),
            "-l:libQt6Core.so.6", "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
