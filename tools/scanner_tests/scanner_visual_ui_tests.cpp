// Isolated production ScannerDock + MemoryEditorWidget, synthetic file only.
#include "../../Ksword5.1/Ksword5.1/ScannerDock/ScannerDock.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryEditorWidget.h"
#include "../../Ksword5.1/Ksword5.1/UI/BinaryOverviewBar.h"
#include "../../Ksword5.1/Ksword5.1/UI/GlobalUiBaseStyle.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchDisasmView.h"
#include "../../Ksword5.1/Ksword5.1/ksword/scanner/binary_layout.h"
#include "../../Ksword5.1/Ksword5.1/theme.h"
#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTabWidget>
#include <QTemporaryDir>
#include <QTest>
#include <algorithm>
#include <cstdlib>
#include <iostream>

namespace
{
    unsigned checks = 0;
    void require(bool condition, const char* message)
    {
        ++checks;
        if (!condition) { std::cerr << "FAIL [" << checks << "]: " << message << '\n'; std::exit(1); }
    }
    template<class Predicate> bool waitFor(Predicate predicate)
    {
        QElapsedTimer timer;
        timer.start();
        while (!predicate() && timer.elapsed() < 10000) QTest::qWait(5);
        return predicate();
    }
    void put(QByteArray& bytes, int offset, std::uint64_t value, int length)
    {
        for (int index = 0; index < length; ++index) bytes[offset + index] = static_cast<char>(value >> (index * 8));
    }
    QByteArray fixture()
    {
        QByteArray bytes(0x68000, '\0');
        bytes[0] = 'M'; bytes[1] = 'Z'; put(bytes, 0x3C, 0x80, 4);
        bytes[0x80] = 'P'; bytes[0x81] = 'E';
        put(bytes, 0x84, 0x8664, 2); put(bytes, 0x86, 3, 2);
        put(bytes, 0x94, 240, 2); put(bytes, 0x96, 0x22, 2);
        const int optional = 0x98;
        put(bytes, optional, 0x20B, 2);
        put(bytes, optional + 16, 0x1000, 4);
        put(bytes, optional + 24, 0x140000000, 8);
        put(bytes, optional + 32, 0x1000, 4); put(bytes, optional + 36, 0x200, 4);
        put(bytes, optional + 56, 0x76000, 4); put(bytes, optional + 60, 0x400, 4);
        put(bytes, optional + 68, 3, 2); put(bytes, optional + 108, 16, 4);
        put(bytes, optional + 128, 0x70000, 4); put(bytes, optional + 132, 0x1000, 4);
        const auto section = [&bytes](int start, const char* name, std::uint32_t virtualSize,
            std::uint32_t rva, std::uint32_t rawSize, std::uint32_t raw, std::uint32_t flags) {
            for (int index = 0; name[index] && index < 8; ++index) bytes[start + index] = name[index];
            put(bytes, start + 8, virtualSize, 4); put(bytes, start + 12, rva, 4);
            put(bytes, start + 16, rawSize, 4); put(bytes, start + 20, raw, 4);
            put(bytes, start + 36, flags, 4);
        };
        section(0x188, ".text", 0x60000, 0x1000, 0x50000, 0x400, 0x60000020);
        section(0x1B0, ".rsrc", 0x1000, 0x70000, 0x1000, 0x60000, 0x40000040);
        section(0x1D8, ".bss", 0x2000, 0x72000, 0, 0x61000, 0xC0000080);
        std::fill(bytes.begin() + 0x400, bytes.begin() + 0x50400, static_cast<char>(0x90));
        const QByteArray function = QByteArray::fromHex("554889E531C05DC3");
        std::copy(function.begin(), function.end(), bytes.begin() + 0x400);
        bytes[0x60020] = 'R'; bytes[0x67000] = 'O';
        return bytes;
    }
    void write(const QString& path, const QByteArray& bytes)
    {
        QFile file(path);
        require(file.open(QIODevice::WriteOnly), "synthetic file opens");
        require(file.write(bytes) == bytes.size(), "synthetic file is complete");
        file.close();
    }
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    app.setFont(QFont(QStringLiteral("Microsoft YaHei"), 9));
    const bool dark = argc > 2 && QString::fromLocal8Bit(argv[2]) == QStringLiteral("dark");
    KswordTheme::SetDarkModeEnabled(dark);
    QPalette palette = app.palette();
    palette.setColor(QPalette::Window, KswordTheme::WindowColor());
    palette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
    palette.setColor(QPalette::Base, KswordTheme::SurfaceColor());
    palette.setColor(QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
    palette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
    palette.setColor(QPalette::Button, KswordTheme::SurfaceColor());
    palette.setColor(QPalette::ButtonText, KswordTheme::TextPrimaryColor());
    palette.setColor(QPalette::Highlight, KswordTheme::PrimaryAccentColor());
    palette.setColor(QPalette::HighlightedText, KswordTheme::OnAccentColor());
    palette.setColor(QPalette::PlaceholderText, KswordTheme::TextSecondaryColor());
    app.setPalette(palette);
    app.setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());
    QTemporaryDir temporary(QDir::currentPath() + QStringLiteral("/work/scanner-visual-tests/fixture-XXXXXX"));
    require(temporary.isValid(), "private fixture directory is available");
    const QString path = temporary.filePath(QStringLiteral("synthetic.exe"));
    const QByteArray bytes = fixture();
    write(path, bytes);
    ks::scanner::ScanOptions options;
    options.retainInputSnapshot = true;
    auto result = ks::scanner::ScanBinaryFile(path.toStdWString(), options);
    require(result.success && result.format == ks::scanner::BinaryFormat::Pe32Plus, "production parser accepts synthetic PE64");
    require(result.inputSnapshot && result.inputSnapshot->size() == static_cast<std::size_t>(bytes.size()), "verified full input is retained");
    require(result.mappedRegions.size() == 5 && result.mappedRegions[2].kind == ks::scanner::BinaryRegionKind::Resources,
        "physical headers/code/resources/bss/overlay are classified");
    require(result.entryPointFileOffsetValid && result.entryPointFileOffset == 0x400 && result.imageBase == 0x140000000,
        "entry and image metadata use physical offsets correctly");
    require(!ks::scanner::ScanBinaryFile(path.toStdWString()).inputSnapshot, "non-viewer callers do not retain full input");
    auto changed = bytes; changed[0x60020] = 'X'; write(path, changed);
    require((*result.inputSnapshot)[0x60020] == 'R', "retained bytes stay immutable after external file changes");
    write(path, bytes);

    ScannerDock dock;
    dock.resize(1040, 680);
    dock.show();
    auto* pathEdit = dock.findChild<QLineEdit*>(QStringLiteral("scanner_target_path"));
    auto* editor = dock.findChild<ks::ui::MemoryEditorWidget*>();
    auto* sections = dock.findChild<QComboBox*>(QStringLiteral("scanner_analysis_sections"));
    auto* entry = dock.findChild<QPushButton*>(QStringLiteral("scanner_analysis_entry"));
    auto* address = dock.findChild<QLineEdit*>(QStringLiteral("scanner_analysis_address"));
    auto* addressKind = dock.findChild<QComboBox*>(QStringLiteral("scanner_analysis_address_kind"));
    auto* position = dock.findChild<QLabel*>(QStringLiteral("scanner_analysis_position"));
    auto* bar = static_cast<ks::ui::BinaryOverviewBar*>(dock.findChild<QWidget*>(QStringLiteral("binary_overview_bar")));
    require(pathEdit && editor && sections && entry && address && addressKind && position && bar, "production visual controls are reachable");
    pathEdit->setText(path);
    QTest::keyClick(pathEdit, Qt::Key_Return);
    require(waitFor([&]() { return sections->count() == 5 && pathEdit->isEnabled(); }), "asynchronous scanner publishes visual layout");
    require(editor->data().size() == 256 * 1024 && editor->baseAddress() == 0, "GUI initially copies only a bounded window");
    require(editor->addressKind() == ks::ui::SnapshotAddressKind::FileOffset, "shared viewer keeps file coordinates distinct");
    QTest::mouseClick(entry, Qt::LeftButton);
    require(waitFor([&]() { const auto row = editor->selectedInstruction(); return row && row->address == 0x400; }),
        "entry point opens real shared disassembly at its physical file offset");
    sections->setCurrentIndex(2);
    require(waitFor([&]() { return editor->baseAddress() == 0x60000; }), "resource section selection crosses to a distant bounded window");
    require(editor->data().at(0x20) == 'R' && bar->currentOffset() == 0x60000, "section bytes and current marker agree");
    write(path, changed);
    addressKind->setCurrentIndex(1);
    address->setText(QStringLiteral("0x52000")); QTest::keyClick(address, Qt::Key_Return);
    require(editor->baseAddress() == 0x60000 && bar->currentOffset() == 0x60000,
        "RVA zero-fill rejects navigation rather than inventing disk bytes");
    address->setText(QStringLiteral("0x1020")); QTest::keyClick(address, Qt::Key_Return);
    require(waitFor([&]() { return bar->currentOffset() == 0x420; }), "RVA navigation maps to raw section bytes");
    addressKind->setCurrentIndex(2); address->setText(QStringLiteral("0x140070020")); QTest::keyClick(address, Qt::Key_Return);
    require(waitFor([&]() { return bar->currentOffset() == 0x60020; }), "64-bit VA navigation maps back to the exact file byte");
    require(editor->data().at(0x20) == 'R', "GUI preview uses analyzed snapshot after file replacement");
    sections->setCurrentIndex(3);
    require(editor->baseAddress() == 0x60000 && bar->currentOffset() == 0x60020, "virtual-only section selection preserves physical evidence");
    require(editor->disassemblyView()->jumpTo(0x30000), "shared disassembly accepts navigation outside its current small window");
    require(waitFor([&]() { return editor->baseAddress() == 0x30000; }), "child window request loads the requested stable file window");
    require(editor->data().size() <= 256 * 1024, "cross-window browsing remains bounded");
    const int x = 1 + static_cast<int>((0x67000 / static_cast<double>(bytes.size())) * (bar->width() - 2));
    QTest::mouseClick(bar, Qt::LeftButton, Qt::NoModifier, QPoint(x, bar->height() / 2));
    require(waitFor([&]() { return bar->currentOffset() >= 0x61000; }), "proportional overview click navigates overlay bytes");
    require(!editor->fileOffsetToVirtualAddress(bar->currentOffset()), "overlay preview never claims a PE virtual address");
    QTest::keyClick(bar, Qt::Key_Home);
    require(bar->currentOffset() == 0, "overview keyboard Home navigates true file offset zero");
    QTest::mouseClick(entry, Qt::LeftButton);
    QTest::qWait(50);
    dock.resize(680, 640);
    QTest::qWait(50);
    if (argc > 1) require(dock.grab().save(QString::fromLocal8Bit(argv[1])), "visual preview saved");
    std::cout << checks << " checks, 0 failures\n";
    return 0;
}
