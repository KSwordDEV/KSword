#!/usr/bin/env python3
"""Native metadata-only scanner regression, confined to new temporary folders."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qt-root", type=Path, required=True)
    parser.add_argument("--cxx", default=shutil.which("cl"))
    args = parser.parse_args()
    compiler = Path(args.cxx).resolve() if args.cxx else None
    if os.name != "nt" or not compiler or "/hostx64/x64/" not in compiler.as_posix().lower():
        parser.error("Requires native Windows MSVC HostX64/x64 developer environment")
    qt = args.qt_root.resolve()
    root = Path(__file__).resolve().parents[1]
    source = root / "Ksword5.1/Ksword5.1/FileDock"
    environment = dict(os.environ)
    environment["PATH"] = str(qt / "bin") + os.pathsep + environment.get("PATH", "")
    output = (root / "output").resolve()
    if not output.is_relative_to(root.resolve()):
        raise SystemExit("Build output must remain inside the repository")
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="directory-space-build-", dir=output) as temporary:
        work = Path(temporary)
        environment["TMP"] = environment["TEMP"] = str(work)
        executable = work / "directory_space_scanner_tests.exe"
        command = [str(compiler), "/nologo", "/std:c++20", "/permissive-", "/Zc:__cplusplus",
                   "/W4", "/WX", "/utf-8", "/EHsc", "/MD", "/DNOMINMAX", "/DUNICODE", "/D_UNICODE",
                   "/I" + str(qt / "include"), "/I" + str(qt / "include/QtCore"), "/I" + str(source),
                   str(root / "tools/directory_space_scanner_tests.cpp"), str(source / "DirectorySpaceScanner.cpp"),
                   "/Fo" + str(work) + "\\", "/Fd" + str(work / "compile.pdb"),
                   "/Fe:" + str(executable), "/link", "/LIBPATH:" + str(qt / "lib"), "Qt6Core.lib"]
        subprocess.run(command, cwd=work, check=True, timeout=120)
        subprocess.run([str(executable)], cwd=work, env=environment, check=True, timeout=30)


if __name__ == "__main__":
    main()
