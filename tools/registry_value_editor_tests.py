"""Build the actual registry draft editor and native HexView with a MinGW Qt SDK.

Usage: python tools/registry_value_editor_tests.py --msvc --output .codex-build-logs
The optional MinGW branch accepts --qt and --compiler. Only an existing output directory is used.
No production application or registry/driver access.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pathlib import Path
import re
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--msvc", action="store_true", help="Reuse the latest validated production MSVC objects")
    parser.add_argument("--qt", type=Path)
    parser.add_argument("--compiler", type=Path)
    parser.add_argument("--output", type=Path, default=Path(".codex-build-logs"), help="Existing output directory")
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    out = (repo / args.output).resolve()
    if not out.is_dir():
        raise RuntimeError("--output must point to an existing directory")
    if args.msvc:
        from msvc_qt_production_fixture import run_msvc_fixture
        run_msvc_fixture(repo, repo / "tools/registry_value_editor_tests.cpp", out,
                         "registry_value_editor_tests", qt_root=args.qt, runtime_args=(str(out),))
        return 0
    if args.qt is None or args.compiler is None:
        raise RuntimeError("The MinGW branch requires --qt and --compiler")
    qt = args.qt.resolve()
    compiler = args.compiler.resolve()
    if not compiler.is_file() or not (qt / "bin" / "moc.exe").is_file():
        raise RuntimeError("A MinGW compiler and matching Qt SDK are required.")
    env = os.environ.copy()
    env["PATH"] = str(compiler.parent) + os.pathsep + str(qt / "bin") + os.pathsep + env.get("PATH", "")
    env["QT_QPA_PLATFORM"] = "offscreen"
    env["QT_PLUGIN_PATH"] = str(qt / "plugins")
    app = repo / "Ksword5.1" / "Ksword5.1"
    ui = app / "UI" / "MemoryWorkbench"
    core = repo / "shared" / "evidence" / "memory_workbench"
    # Use the existing HexView fixture's production source list, avoiding a
    # second stale copy of HexView's split-file and pure-core dependencies.
    manifest = (repo / "tools" / "memwb_ui" / "build-memwb-ui-tests.cmd").read_text(encoding="utf-8-sig")
    build_section = manifest.split("cl /nologo", 1)[1].split("/Fo", 1)[0]
    roots = {"APP": app, "UI": ui, "CORE": core}
    sources = []
    for root, relative in re.findall(r'"%(APP|UI|CORE)%\\([^"\r\n]+\.cpp)"', build_section):
        if relative == "MemoryDock\\WorkbenchIoMapping.cpp":
            continue
        source = roots[root] / Path(relative.replace("\\", "/"))
        if source not in sources:
            sources.append(source)
    sources += [app / "RegistryDock" / "RegistryValueEditorWidget.cpp",
                app / "RegistryDock" / "RegistryValueCodec.cpp",
                app / "RegistryDock" / "RegistryAdvancedDialogs.cpp",
                app / "UI" / "ThemeStatusRole.cpp",
                app / "UI" / "UIBaseFunction.cpp",
                app / "UI" / "ThemeControlGlyphs.cpp",
                app / "UI" / "CodeEditorWidget.cpp",
                app / "UI" / "CodeTextEdit.cpp",
                app / "UI" / "CodeEditorFileSession.cpp",
                app / "UI" / "StructuredFieldView.cpp",
                app / "UI" / "TypedSyntaxDocument.cpp",
                app / "UI" / "TablePresentation.cpp",
                app / "Internationalization" / "LanguageManager.cpp",
                repo / "tools" / "registry_value_editor_tests.cpp"]
    moc_headers = [ui / name for name in (
        "HexCanvas.h", "HexInspectorPanel.h", "HexInspectorRowView.h", "HexView.h",
        "HexFindBar.h", "HexGotoBar.h", "HexViewWidgets.h")]
    moc_headers += [app / "RegistryDock" / "RegistryValueEditorWidget.h"]
    moc_headers += [app / "UI" / "CodeEditorWidget.h", app / "UI" / "StructuredFieldView.h"]
    for header in moc_headers:
        generated = out / ("moc_" + header.stem + ".cpp")
        subprocess.run([str(qt / "bin" / "moc.exe"), str(header), "-o", str(generated)], env=env, check=True)
        sources.append(generated)
    resource = out / "qrc_registry_value_tests.cpp"
    subprocess.run([str(qt / "bin" / "rcc.exe"), str(repo / "tools" / "memwb_ui" / "memwb_ui_icons.qrc"),
                    "-name", "registry_value_tests", "-o", str(resource)], env=env, check=True)
    sources.append(resource)
    flags = ["-std=c++23", "-O0", "-g0", "-Wall", "-Wextra", "-DWIN32_LEAN_AND_MEAN", "-DNOMINMAX",
             "-DUNICODE", "-D_UNICODE", "-DQT_CORE_LIB", "-DQT_GUI_LIB", "-DQT_WIDGETS_LIB"]
    for module in ("", "QtCore", "QtGui", "QtWidgets", "QtSvg"):
        flags += ["-isystem", str(qt / "include" / module)]
    own_sources = {app / "RegistryDock" / "RegistryValueEditorWidget.cpp", app / "RegistryDock" / "RegistryValueCodec.cpp",
                   app / "RegistryDock" / "RegistryAdvancedDialogs.cpp"}
    editor_sources = {app / "UI" / name for name in
                      ("CodeEditorWidget.cpp", "CodeTextEdit.cpp", "CodeEditorFileSession.cpp",
                       "StructuredFieldView.cpp", "TypedSyntaxDocument.cpp", "TablePresentation.cpp")}
    editor_header_time = max((app / "UI" / name).stat().st_mtime for name in
                             ("CodeEditorWidget.h", "CodeTextEdit.h", "CodeEditorFileSession.h",
                              "StructuredFieldView.h", "TypedSyntaxDocument.h", "TablePresentation.h"))

    def compile_one(source: Path) -> Path:
        # File stems are unique in this fixture; mocs have their own prefix.
        obj = out / (source.stem + ".o")
        newest_input = max(source.stat().st_mtime, editor_header_time) if source in editor_sources else source.stat().st_mtime
        if source not in own_sources and obj.exists() and obj.stat().st_mtime > newest_input:
            return obj
        command = [str(compiler), *flags]
        if source in own_sources:
            command += ["-Werror"]
        command += ["-c", str(source), "-o", str(obj)]
        result = subprocess.run(command, env=env, capture_output=True, text=True, errors="replace")
        if result.returncode:
            print(result.stdout + result.stderr, file=sys.stderr, flush=True)
            raise RuntimeError("Compile failed: " + source.name)
        if result.stderr:
            print(result.stderr, file=sys.stderr, flush=True)
        print("COMPILED " + source.name, flush=True)
        return obj

    objects = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 4))) as pool:
        for future in as_completed([pool.submit(compile_one, source) for source in sources]):
            objects.append(future.result())
    exe = out / "registry_value_editor_tests.exe"
    subprocess.run([str(compiler), *map(str, objects), "-L" + str(qt / "lib"), "-lQt6Widgets", "-lQt6Gui", "-lQt6Core", "-lQt6Svg",
                    "-ladvapi32", "-luser32", "-o", str(exe)], env=env, check=True)
    return subprocess.run([str(exe), str(out)], env=env).returncode


if __name__ == "__main__":
    raise SystemExit(main())
