"""Run the actual FileDock snapshot page in an isolated Qt test host.

The struct, reader and page factory are extracted verbatim from FileDock.cpp.
Only a QFile read seam can shorten one real read to exercise incomplete I/O;
normal reads, native identity, sparse files and async routing use real APIs.
Build shared editor objects first, then pass their directory or object manifest.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


HARNESS_PREFIX = r'''
#include "Ksword5.1/Ksword5.1/UI/MemoryWorkbench/SnapshotWorkbenchWidget.h"
#include "Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexView.h"
#include "Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchDisasmView.h"
#include "Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchTextView.h"
#include "Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchCompareView.h"
#include "Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchPseudocodeView.h"
#include "Ksword5.1/Ksword5.1/UI/MemoryWorkbench/MemoryRowCanvas.h"
#include "Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include <Windows.h>
#include <winioctl.h>
#include <io.h>
#include <QApplication>
#include <QComboBox>
#include <QDateTime>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QSemaphore>
#include <QSettings>
#include <QTabWidget>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTest>
#include <QThreadPool>
#include <QVBoxLayout>
#include <algorithm>
#include <atomic>
#include <bit>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <vector>

namespace {
unsigned checks = 0;
std::atomic_bool shortenNextRead{false};
void Require(bool value, const char* description) {
    ++checks;
    if (!value) { std::cerr << "FAIL [" << checks << "]: " << description << '\n'; std::exit(1); }
}
bool SpinUntil(const std::function<bool()>& done) {
    QElapsedTimer timer; timer.start();
    do { QApplication::processEvents(); if (done()) return true; QTest::qWait(2); } while (timer.elapsed() < 7000);
    return done();
}
class FileReadSeam : public QFile {
public:
    using QFile::QFile;
    QByteArray read(qint64 count) {
        QByteArray bytes = QFile::read(count);
        if (shortenNextRead.exchange(false) && !bytes.isEmpty()) bytes.chop(1);
        return bytes;
    }
};
}
#define QFile FileReadSeam
class FileViewerHost final : public QWidget {
public:
    QString m_filePath;
    QTabWidget* m_tabWidget;
    QWidget* fixturePage = nullptr;
    explicit FileViewerHost(const QString& path) : m_filePath(path), m_tabWidget(new QTabWidget(this)) {
        auto* layout = new QVBoxLayout(this); layout->addWidget(m_tabWidget);
        for (int tab = 0; tab < 14; ++tab) m_tabWidget->addTab(new QWidget, QString::number(tab));
        fixturePage = buildHexTab();
        QWidget* placeholder = m_tabWidget->widget(13);
        m_tabWidget->removeTab(13); delete placeholder;
        m_tabWidget->insertTab(13, fixturePage, QStringLiteral("hex"));
        m_tabWidget->setCurrentIndex(13);
        resize(1000, 700); show();
    }
'''

HARNESS_SUFFIX = r'''
};
#undef QFile
namespace {
ks::ui::SnapshotWorkbenchWidget* Editor(FileViewerHost& host) {
    auto* editor = host.fixturePage->findChild<ks::ui::SnapshotWorkbenchWidget*>();
    Require(editor != nullptr, "FileDock creates the production shared editor"); return editor;
}
QPushButton* Button(FileViewerHost& host, const QString& text) {
    for (auto* button : host.fixturePage->findChildren<QPushButton*>()) if (button->text() == ks::i18n::sourceText(text)) return button;
    Require(false, "expected FileDock navigation button exists"); return nullptr;
}
QLineEdit* Offset(FileViewerHost& host) {
    for (auto* input : host.fixturePage->findChildren<QLineEdit*>()) if (input->placeholderText().contains(QStringLiteral("0x"))) return input;
    Require(false, "external file offset input exists"); return nullptr;
}
bool HasStatus(FileViewerHost& host, const QString& text) {
    for (auto* label : host.fixturePage->findChildren<QLabel*>()) if (label->text().contains(text)) return true;
    return false;
}
void Jump(FileViewerHost& host, const QString& text) {
    Offset(host)->setText(text); Button(host, QStringLiteral("跳转到文件偏移"))->click();
}
void AwaitBase(FileViewerHost& host, std::uint64_t base, qsizetype size) {
    auto* editor = Editor(host);
    Require(SpinUntil([&] { return editor->baseAddress() == base && editor->data().size() == size
        && !HasStatus(host, QStringLiteral("正在读取文件偏移")); }), "async FileDock snapshot reaches expected range");
}
void WriteFile(const QString& path, const QByteArray& data) {
    QFile file(path); const bool opened = file.open(QIODevice::WriteOnly);
    if (!opened) std::cerr << "File error " << path.toStdString() << ": " << file.errorString().toStdString() << '\n';
    Require(opened, "fixture file opens");
    Require(file.write(data) == data.size(), "fixture file contains exact bytes"); file.close();
}
void RuntimeChecks(const QString& folder) {
    constexpr qint64 chunk = 65536;
    const QString path = folder + QStringLiteral("/pages.bin");
    QByteArray bytes(chunk * 3 + 17, std::bit_cast<char>(std::uint8_t{0x90}));
    bytes.replace(0, 6, QByteArray::fromHex("b801000000c3"));
    bytes.replace(chunk, 6, QByteArray::fromHex("b802000000c3"));
    bytes.replace(chunk * 2, 6, QByteArray::fromHex("b803000000c3"));
    WriteFile(path, bytes);
    auto initial = FileViewerHost::readHexFileWindow(path, 0, chunk);
    Require(initial.errorText.isEmpty() && initial.bytes == bytes.left(chunk), "production reader returns real first window");
    Require(!initial.sourceIdentity.isEmpty(), "real file has stable source identity");
    const QString originalIdentity = initial.sourceIdentity;
    {
        QFile edit(path); Require(edit.open(QIODevice::ReadWrite) && edit.seek(16), "same file opens for fixture mutation");
        Require(edit.write(QByteArray(1, std::bit_cast<char>(std::uint8_t{0xCC}))) == 1 && edit.flush(), "same file changes one byte");
        Require(edit.setFileTime(QDateTime::currentDateTimeUtc().addSecs(30), QFileDevice::FileModificationTime), "fixture advances modification time");
    }
    bytes[16] = std::bit_cast<char>(std::uint8_t{0xCC}); initial = FileViewerHost::readHexFileWindow(path, 0, chunk);
    Require(initial.errorText.isEmpty() && initial.sourceIdentity == originalIdentity && initial.bytes == bytes.left(chunk),
        "same file keeps comparison identity after actual content and mtime change");
    const auto clamped = FileViewerHost::readHexFileWindow(path, 4099, 1);
    Require(clamped.errorText.isEmpty() && clamped.baseOffset == 4096 && clamped.bytes == bytes.mid(4096, 4096), "reader clamps tiny windows and aligns offsets");
    const auto tooFar = FileViewerHost::readHexFileWindow(path, bytes.size(), chunk);
    Require(!tooFar.errorText.isEmpty(), "production reader rejects offset equal to EOF");
    FileViewerHost host(path); AwaitBase(host, 0, chunk);
    auto* editor = Editor(host);
    Require(editor->addressKind() == ks::ui::SnapshotAddressKind::FileOffset && !editor->disassemblyView()->isEditable(), "file uses explicit offset domain and read-only assembly");
    Require(editor->data() == initial.bytes, "shared HEX cache receives reader bytes unchanged");
    auto* tabs = editor->findChild<QTabWidget*>();
    Require(tabs != nullptr && tabs->count() == 5, "file page shares HEX disassembly text compare and C tabs");
    auto* pseudocode = editor->findChild<ks::ui::WorkbenchPseudocodeView*>();
    Require(pseudocode != nullptr && tabs->indexOf(pseudocode) == 4,
        "file C tab uses the same production pseudocode component as the live workbench");
    editor->showDisassemblyAt(0); QApplication::processEvents();
    Require(editor->disassemblyView()->model()->rowAt(0).has_value()
        && editor->disassemblyView()->model()->rowAt(0)->bytes == bytes.left(5), "file byte zero decodes through production disassembly");
    Button(host, QStringLiteral("查找当前范围"))->click(); QApplication::processEvents();
    Require(editor->disassemblyView()->isAncestorOf(QApplication::focusWidget()), "FileDock search opens current disassembly search");
    tabs->setCurrentIndex(2); editor->textView()->setEncoding(ks::ui::WorkbenchTextView::Encoding::Utf8);
    Require(!editor->textView()->canvas()->rows().isEmpty() && editor->textView()->canvas()->rows().front().address == 0, "file text view uses exact file offsets");
    Button(host, QStringLiteral("查找当前范围"))->click(); QApplication::processEvents();
    Require(editor->textView()->isAncestorOf(QApplication::focusWidget()), "FileDock search opens current text search");
    {
        QFile edit(path); Require(edit.open(QIODevice::ReadWrite) && edit.seek(16), "live file opens for reread comparison");
        Require(edit.write(QByteArray(1, char(0x41))) == 1 && edit.flush(), "live file changes one captured byte");
        Require(edit.setFileTime(QDateTime::currentDateTimeUtc().addSecs(60), QFileDevice::FileModificationTime), "reread mutation changes mtime");
    }
    bytes[16] = char(0x41); Button(host, QStringLiteral("文件开头"))->click();
    Require(SpinUntil([&] { return editor->data() == bytes.left(chunk)
        && !HasStatus(host, QStringLiteral("正在读取文件偏移")); }), "same file reread publishes real changed bytes");
    tabs->setCurrentIndex(3);
    // 验证共用比较模型实际读取的地址与旧/新字节，避免只证明页面存在。
    auto* comparison = editor->findChild<ks::ui::WorkbenchCompareView*>();
    Require(comparison != nullptr, "file comparison uses the production virtual compare component");
    comparison->setMode(ks::ui::WorkbenchCompareView::Mode::ExternalChange);
    const auto* compareModel = comparison->model();
    Require(compareModel->rowCount() == 1
        && compareModel->data(compareModel->index(0, 0), Qt::UserRole).toULongLong() == 16
        && compareModel->data(compareModel->index(0, 5), Qt::DisplayRole).toInt() == 1,
        "modified same-file byte compares at its actual captured offset");
    Require(compareModel->data(compareModel->index(0, 1), Qt::DisplayRole).toString().startsWith(QStringLiteral("CC"))
        && compareModel->data(compareModel->index(0, 2), Qt::DisplayRole).toString().startsWith(QStringLiteral("41")),
        "shared comparison preserves previous and current actual bytes");
    Button(host, QStringLiteral("下一范围"))->click(); AwaitBase(host, chunk, chunk);
    Require(editor->data() == bytes.mid(chunk, chunk), "next range reuses shared snapshot across current tab");
    Button(host, QStringLiteral("上一范围"))->click(); AwaitBase(host, 0, chunk);
    Button(host, QStringLiteral("文件末尾"))->click(); AwaitBase(host, chunk * 3, 17);
    Jump(host, QStringLiteral("0x10020")); AwaitBase(host, chunk, chunk);
    Require(editor->hexEditor()->caretAddress() == chunk + 32, "hex jump selects exact file byte");
    editor->showPseudocodeAt(chunk + 32); QApplication::processEvents();
    Require(tabs->currentWidget() == pseudocode && editor->hexEditor()->caretAddress() == chunk + 32,
        "file snapshot can activate the shared C tab while preserving its captured offset");
    tabs->setCurrentIndex(0);
    editor->disassemblyView()->setArchitectureOverride(false);
    Button(host, QStringLiteral("文件开头"))->click(); AwaitBase(host, 0, chunk);
    Require(editor->currentArchitecture() == ks::ui::DisassemblyArchitecture::X86, "file reread preserves chosen instruction architecture");

    // A queued old result must never replace the newer target, even if both finish
    // before the UI consumes either callback. The production generation is used.
    auto* pool = QThreadPool::globalInstance(); pool->waitForDone();
    const int oldThreadCount = pool->maxThreadCount(); pool->setMaxThreadCount(1);
    QSemaphore entered, release;
    pool->start(QRunnable::create([&] { entered.release(); release.acquire(); }));
    Require(entered.tryAcquire(1, 3000), "async fixture holds worker queue deterministically");
    std::vector<std::uint64_t> loadedBases;
    const auto connection = QObject::connect(editor, &ks::ui::SnapshotWorkbenchWidget::bytesChanged,
        &host, [&] { loadedBases.push_back(editor->baseAddress()); });
    Jump(host, QString::number(chunk)); Jump(host, QString::number(chunk * 2));
    release.release(); Require(pool->waitForDone(3000), "both queued reads finish");
    AwaitBase(host, chunk * 2, chunk);
    Require(loadedBases == std::vector<std::uint64_t>{chunk * 2}, "stale async range never reaches shared editor");
    QObject::disconnect(connection); pool->setMaxThreadCount(oldThreadCount);

    // Shortening just one real QFile read drives the exact production completeness
    // gate and the exact async failure branch, without changing either method.
    shortenNextRead = true; Button(host, QStringLiteral("文件开头"))->click();
    Require(SpinUntil([&] { return HasStatus(host, QStringLiteral("未跳转")); }), "incomplete read reports failure");
    Require(editor->data().isEmpty() && !Button(host, QStringLiteral("查找当前范围"))->isEnabled(), "incomplete read clears previous snapshot and disables search");
    Button(host, QStringLiteral("文件开头"))->click(); AwaitBase(host, 0, chunk);
    Require(QFile::rename(path, path + QStringLiteral(".previous")), "fixture file can move after reader closes its handle");
    Button(host, QStringLiteral("文件开头"))->click();
    Require(SpinUntil([&] { return HasStatus(host, QStringLiteral("未跳转")); }), "missing file reports failure");
    Require(editor->data().isEmpty(), "open failure cannot leave stale file bytes visible");
    WriteFile(path, bytes);
    const auto replacement = FileViewerHost::readHexFileWindow(path, 0, chunk);
    Require(replacement.errorText.isEmpty() && !replacement.sourceIdentity.isEmpty()
        && replacement.sourceIdentity != originalIdentity, "replacement at same path receives new source identity");

    const QString emptyPath = folder + QStringLiteral("/empty.bin"); WriteFile(emptyPath, {});
    FileViewerHost empty(emptyPath);
    Require(SpinUntil([&] { return HasStatus(empty, QStringLiteral("文件为空")); }), "empty file has explicit result");
    Require(Editor(empty)->data().isEmpty() && !Button(empty, QStringLiteral("下一范围"))->isEnabled(), "empty file has no synthetic bytes or next range");

    const QString sparsePath = folder + QStringLiteral("/sparse.bin");
    constexpr qint64 highOffset = (qint64{1} << 32) + 0x1234;
    const QByteArray marker = QByteArray::fromHex("b878563412c3");
    {
        QFile sparse(sparsePath); Require(sparse.open(QIODevice::ReadWrite), "large offset fixture opens");
        const HANDLE handle = reinterpret_cast<HANDLE>(_get_osfhandle(sparse.handle())); DWORD returned = 0;
        Require(DeviceIoControl(handle, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned, nullptr) != FALSE, "large file is sparse before extending");
        Require(sparse.resize(highOffset + marker.size()) && sparse.seek(highOffset), "sparse fixture reaches offset above 4 GiB");
        Require(sparse.write(marker) == marker.size(), "large-offset file contains exact marker");
    }
    FileViewerHost high(sparsePath); AwaitBase(high, 0, chunk);
    auto* highEditor = Editor(high); highEditor->disassemblyView()->setArchitectureOverride(false);
    Jump(high, QString::number(highOffset)); AwaitBase(high, qint64{1} << 32, 0x1234 + marker.size());
    Require(highEditor->hexEditor()->caretAddress() == highOffset
        && highEditor->data().mid(0x1234, marker.size()) == marker, "above-4-GiB byte selection retains full file offset");
    highEditor->showDisassemblyAt(highOffset); QApplication::processEvents();
    Require(highEditor->selectedInstruction().has_value() && highEditor->selectedInstruction()->address == highOffset
        && highEditor->currentArchitecture() == ks::ui::DisassemblyArchitecture::X86, "x86 decode stays independent of 64-bit file offsets");
    auto* highTabs = highEditor->findChild<QTabWidget*>(); highTabs->setCurrentIndex(2);
    Require(highEditor->textView()->windowAddress() == highOffset && !highEditor->textView()->canvas()->rows().isEmpty(), "text anchors at full large-file offset");

    // Destroy a page with a queued read; provider and callback lifetimes must end
    // cleanly. A worker blocker avoids depending on scheduler timing.
    pool->waitForDone(); pool->setMaxThreadCount(1);
    QSemaphore destroyedEntered, destroyedRelease;
    pool->start(QRunnable::create([&] { destroyedEntered.release(); destroyedRelease.acquire(); }));
    Require(destroyedEntered.tryAcquire(1, 3000), "queued destruction fixture holds worker");
    QPointer<FileViewerHost> destroyed = new FileViewerHost(sparsePath); delete destroyed.data();
    destroyedRelease.release(); Require(pool->waitForDone(3000), "destroyed file page read exits");
    QApplication::processEvents(); pool->setMaxThreadCount(oldThreadCount);
    Require(!destroyed, "file viewer destruction with pending read completes");
}
}
int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QTemporaryDir temp(QCoreApplication::applicationDirPath() + QStringLiteral("/runtime-XXXXXX"));
    Require(temp.isValid(), "temporary file folder exists");
    // 测试偏好写入自建文件夹中的 INI，不读取或写入 Windows 注册表偏好。
    app.setApplicationName(QStringLiteral("KSword File Snapshot Tests"));
    app.setOrganizationName(QStringLiteral("KSword Tests"));
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, temp.path());
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, temp.path());
    RuntimeChecks(temp.path());
    QThreadPool::globalInstance()->waitForDone();
    std::cout << "file snapshot page: " << checks << " checks passed\n"; return 0;
}
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--msvc", action="store_true", help="Reuse the latest validated production MSVC objects")
    parser.add_argument("--objects-root", default=".codex-tmp/file-snapshot-host-tests")
    parser.add_argument("--object-manifest", type=Path)
    parser.add_argument("--qt-root", help="Override the Qt root recorded in the object manifest")
    parser.add_argument("--output", default=".codex-build-logs", help="Existing output directory")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    source = (repo / "Ksword5.1/Ksword5.1/FileDock/FileDock.cpp").read_text(encoding="utf-8-sig")
    start = source.index("        struct FileHexWindow")
    stop = source.index("\n    private:", start)
    methods = source[start:stop]
    assert methods.count("static FileHexWindow readHexFileWindow") == 1
    assert methods.count("QWidget* buildHexTab()") == 1
    assert "showFileDetailDialog(firstPath, selectedAction == hexAction ? QStringLiteral(\"hex\")" in source, "HEX right-click must route directly to the file tab"
    assert 'm_initialTabKey == QStringLiteral("hex") ? 13' in source, "HEX initial-tab key must select index 13"
    print("FileDock direct HEX routing: 2 source checks passed", flush=True)
    out = (repo / args.output).resolve()
    if not out.is_dir():
        raise RuntimeError("--output must point to an existing directory")
    cpp = out / "file_snapshot_page.cpp"
    cpp.write_text(HARNESS_PREFIX + methods + HARNESS_SUFFIX, encoding="utf-8")
    if args.msvc:
        from msvc_qt_production_fixture import run_msvc_fixture
        run_msvc_fixture(repo, cpp, out, "file_snapshot_page",
                         qt_root=Path(args.qt_root) if args.qt_root else None)
        return
    objects_root = (repo / args.objects_root).resolve()
    manifest_path = (repo / args.object_manifest).resolve() if args.object_manifest else objects_root / "link-manifest.json"
    manifest = None
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        objects = [Path(path) for path in (manifest["objects"] if isinstance(manifest, dict) else manifest)]
    elif args.object_manifest:
        raise FileNotFoundError(manifest_path)
    else:
        objects = list(objects_root.glob("*.o"))
    qt_path = args.qt_root or (manifest.get("qtRoot") if isinstance(manifest, dict) else None) or ".codex-tmp/qt-fixture/ucrt64"
    qt = (repo / qt_path).resolve()
    excludes = {"memory_editor_ui_tests.o", "memory_row_views_portable_tests.o", "file_snapshot_page.o"}
    objects = [path for path in objects if path.name not in excludes and not path.name.startswith("mutant-")]
    if len(objects) < 30:
        raise RuntimeError("Build the isolated production shared editor first; fewer than 30 objects found.")
    compiler = shutil.which("g++")
    if compiler is None:
        raise RuntimeError("g++ is required for the existing portable Qt fixture.")
    env = os.environ.copy()
    env["PATH"] = str(qt / "bin") + os.pathsep + env.get("PATH", "")
    env["QT_PLUGIN_PATH"] = str(qt / "share/qt6/plugins")
    env["QT_QPA_PLATFORM"] = "offscreen"
    flags = ["-std=c++20", "-O1", "-g0", "-ffunction-sections", "-fdata-sections", "-DNOMINMAX", "-DUNICODE", "-D_UNICODE", "-DZYDIS_STATIC_BUILD", "-DQT_CORE_LIB", "-DQT_GUI_LIB", "-DQT_WIDGETS_LIB", "-DQT_TESTLIB_LIB", "-I.", "-Ithird_party/zydis"]
    for module in ("", "QtCore", "QtGui", "QtWidgets", "QtTest", "QtSvg"):
        flags += ["-isystem", str(qt / "include/qt6" / module)]
    if isinstance(manifest, dict) and manifest.get("flags") and not args.qt_root:
        flags = list(manifest["flags"])
    obj = out / "file_snapshot_page.o"
    subprocess.run([compiler, *flags, "-c", str(cpp), "-o", str(obj)], cwd=repo, env=env, check=True)
    exe = out / "file_snapshot_page.exe"
    subprocess.run([compiler, *map(str, objects), str(obj), "-Wl,--gc-sections", f"-L{qt / 'lib'}", "-lQt6Widgets", "-lQt6Gui", "-lQt6Core", "-lQt6Test", "-lQt6Svg", "-luser32", "-ladvapi32", "-o", str(exe)], cwd=repo, env=env, check=True)
    subprocess.run([str(exe)], cwd=repo, env=env, timeout=90, check=True)


if __name__ == "__main__":
    main()
