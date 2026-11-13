#!/usr/bin/env python3
"""Exercise the real MFT page and shared layout/theme sources with QtWidgets.

Raw NTFS reads are replaced with controlled immutable snapshots. The production
page, async controller, file search, ParameterWorkspace, result host,
page tabs, toolbar and table surfaces are compiled. Pack loading, tab motion,
control glyph files and table action/search integrations use small adapters;
the table capabilities and source models remain real. This is a UI regression, not
native NTFS/USN or the production MainWindow/ADS visual acceptance test.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "Ksword5.1/Ksword5.1"


def extract_function(source: str, signature: str) -> str:
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
    raise ValueError(signature)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qt-dir", "--qt-root", dest="qt", type=Path,
                        default=Path(os.environ.get("KSWORD_QT_DIR", "/usr")))
    parser.add_argument("--compiler", "--cxx", dest="compiler")
    parser.add_argument("--production-page", type=Path, default=APP / "FileDock/NtfsSearchPage.cpp")
    parser.add_argument("--artifact-dir", type=Path)
    args = parser.parse_args()
    qt = args.qt.resolve()
    candidates = [qt / "include", qt / "include/qt6"]
    candidates.extend(sorted((qt / "include").glob("*/qt6")))
    include = next((item for item in candidates if (item / "QtWidgets/QApplication").exists()), None)
    if not include:
        parser.error("Qt 6 development headers unavailable")
    moc_candidates = [qt / "bin/moc.exe", qt / "bin/moc", qt / "lib/qt6/libexec/moc"]
    moc = next((item for item in moc_candidates if item.exists()), None)
    if not moc:
        parser.error("Qt moc unavailable")
    with tempfile.TemporaryDirectory(prefix="ksword-ntfs-page-ui-") as directory:
        work = Path(directory)
        shim = work / "ui"
        shim.mkdir()
        includes = [work, shim, APP, APP / "UI", APP / "FileDock", include]
        includes.extend(include / module for module in ("QtCore", "QtGui", "QtWidgets"))
        sources = [ROOT / "tools/ntfs_search_page_ui_tests.cpp"]
        (work / "ntfs_qt_umbrella.h").write_text("\n".join(
            f"#include <{name}>" for name in (
                "QApplication", "QAbstractScrollArea", "QAbstractSpinBox", "QCheckBox", "QComboBox",
                "QDir", "QElapsedTimer", "QEvent", "QEventLoop", "QGroupBox", "QHBoxLayout", "QImage", "QItemSelectionModel",
                "QLabel", "QLineEdit", "QPalette", "QProgressBar", "QPushButton", "QScrollArea", "QSet",
                "QSplitter", "QStyle", "QTabWidget", "QTabBar", "QTableView", "QThread", "QThreadPool",
                "QTimer", "QTreeView", "QVBoxLayout", "QWidget")), encoding="utf-8")
        # Remove only the Windows application umbrella from these complete TUs.
        for name in ("ParameterWorkspace", "PrimaryPageStyle", "PageControlStyle",
                     "MainSurfaceStyle", "RoundedViewSurface"):
            source = (APP / "UI" / f"{name}.cpp").read_text(encoding="utf-8-sig")
            marker = '#include "../Framework.h"'
            if source.count(marker) != 1:
                raise SystemExit(f"Expected one Framework include in {name}")
            target = shim / f"{name}.cpp"
            target.write_text(source.replace(marker, '#include "ntfs_qt_umbrella.h"\n#include "../theme.h"'), encoding="utf-8")
            sources.append(target)
        # No editors occur on this page. Their unused type checks retain distinct
        # QWidget meta identities; no MFT control/layout/event is replaced.
        (shim / "CodeTextEdit.h").write_text('''#pragma once
#include <QPlainTextEdit>
class CodeTextEdit : public QPlainTextEdit { public: using QPlainTextEdit::QPlainTextEdit; void refreshThemeColors() {} };
''', encoding="utf-8")
        for name, namespace in (("CodeEditorWidget", ""), ("StructuredFieldView", "ks::ui")):
            declaration = f'class {name} : public QWidget {{ Q_OBJECT public: using QWidget::QWidget; }};'
            if namespace:
                declaration = f"namespace {namespace} {{ {declaration} }}"
            header = shim / f"{name}.h"
            header.write_text('#pragma once\n#include <QWidget>\n' + declaration, encoding="utf-8")
            generated = work / f"moc_{name}.cpp"
            subprocess.run([str(moc), str(header), "-o", str(generated)], check=True)
            sources.append(generated)
        page = args.production_page.read_text(encoding="utf-8-sig")
        (work / "ntfs_search_page_source.inc").write_text(page, encoding="utf-8")
        backend = (APP / "FileDock/NtfsFastIndex.cpp").read_text(encoding="utf-8-sig")
        helper = "namespace ks::files {\n" + extract_function(backend, "QString NtfsFastIndex::fullPath(") + "\n}\n"
        (work / "ntfs_path_source.inc").write_text(helper, encoding="utf-8")
        page_moc = work / "moc_NtfsSearchPage.cpp"
        subprocess.run([str(moc), str(APP / "FileDock/NtfsSearchPage.h"), "-o", str(page_moc)], check=True)
        sources.append(page_moc)
        for name in ("ThemeBinding", "FlatButtonTheme", "PageTabFocusStyle", "TablePresentation", "ThemeStatusRole",
                     "ResultTableHost", "AsyncOperation"):
            sources.append(APP / "UI" / f"{name}.cpp")
        coordinator = (APP / "UI/UiCommitCoordinator.cpp").read_text(encoding="utf-8-sig")
        if os.name != "nt":
            # The actual coordinator already offers an input probe. Only its
            # default Windows physical Ctrl probe needs a non-Windows adapter.
            coordinator = coordinator.replace("#include <Windows.h>", "")
            coordinator = coordinator.replace("(::GetAsyncKeyState(VK_LCONTROL) & 0x8000) != 0", "false")
        commit = shim / "UiCommitCoordinator.cpp"
        commit.write_text(coordinator, encoding="utf-8")
        sources.append(commit)
        compiler = args.compiler or shutil.which("cl" if os.name == "nt" else "c++")
        if not compiler:
            parser.error("C++ compiler unavailable")
        executable = work / ("NtfsSearchPageTests.exe" if os.name == "nt" else "NtfsSearchPageTests")
        if os.name == "nt":
            command = [compiler, "/nologo", "/std:c++20", "/EHsc", "/MD", "/utf-8", "/Zc:__cplusplus", "/DNOMINMAX"]
            command.extend(f"/I{item}" for item in includes)
            command.extend(str(item) for item in sources)
            command.extend([f"/Fe:{executable}", "/link", f"/LIBPATH:{qt / 'lib'}", "Qt6Widgets.lib", "Qt6Gui.lib", "Qt6Core.lib", "user32.lib"])
        else:
            flags = [compiler, "-std=c++20", "-fPIC", "-O1"]
            flags.extend(f"-I{item}" for item in includes)
            objects = [work / f"source_{index}.o" for index in range(len(sources))]
            def compile_source(pair: tuple[Path, Path]) -> None:
                source, obj = pair
                subprocess.run([*flags, "-c", str(source), "-o", str(obj)], cwd=work, check=True, timeout=90)
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(compile_source, zip(sources, objects)))
            command = [compiler, *(str(item) for item in objects), "-l:libQt6Widgets.so.6", "-l:libQt6Gui.so.6", "-l:libQt6Core.so.6", "-o", str(executable)]
        subprocess.run(command, cwd=work, check=True, timeout=180)
        runtime = work / "runtime"
        runtime.mkdir(mode=0o700)
        cache = work / "cache"
        cache.mkdir()
        env = dict(os.environ, QT_QPA_PLATFORM="offscreen", XDG_RUNTIME_DIR=str(runtime), XDG_CACHE_HOME=str(cache))
        if args.artifact_dir:
            env["KSWORD_NTFS_UI_ARTIFACT_DIR"] = str(args.artifact_dir.resolve())
        if os.name == "nt":
            env["PATH"] = str(qt / "bin") + os.pathsep + env.get("PATH", "")
            env["QT_PLUGIN_PATH"] = str(qt / "plugins")
        subprocess.run([str(executable)], env=env, check=True, timeout=45)


if __name__ == "__main__":
    main()
