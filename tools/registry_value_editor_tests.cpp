#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryValueCodec.h"
#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryValueEditorWidget.h"
#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryAdvancedDialogs.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexView.h"
#include "../Ksword5.1/Ksword5.1/UI/CodeEditorWidget.h"
#include "../Ksword5.1/Ksword5.1/theme.h"

#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QDialog>
#include <QFontDatabase>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QStyleFactory>
#include <QTabWidget>
#include <QTimer>

#include <bit>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace
{
    int checks = 0;
    int failures = 0;
    void check(bool condition, const char* message)
    {
        ++checks;
        if (!condition) { ++failures; std::cerr << "FAIL: " << message << '\n'; }
    }
    QByteArray bytes(const std::string& raw)
    {
        return QByteArray(raw.data(), static_cast<qsizetype>(raw.size()));
    }
    QByteArray stringBytes(const std::u16string& text)
    {
        std::string encoded;
        check(ks::registry::EncodeString(text, &encoded), "fixture text encoded");
        return bytes(encoded);
    }
    void testCodec()
    {
        using namespace ks::registry;
        std::uint64_t number = 73;
        check(ParseUnsigned("18446744073709551615", 10, 64, &number)
            && number == (std::numeric_limits<std::uint64_t>::max)(), "QWORD maximum decimal");
        check(ParseUnsigned("0xffffffffffffffff", 16, 64, &number), "QWORD maximum hex");
        for (const auto* bad : {"18446744073709551616", "-1", "+1", " 1", "1 ", "1.2", "", "10x", "0x10"})
        {
            number = 73;
            check(!ParseUnsigned(bad, 10, 64, &number) && number == 73, "bad decimal leaves output untouched");
        }
        for (const auto* bad : {"100000000", "0x100000000", "-1", "+1", "0x", "fffz", "1 1"})
        {
            number = 73;
            check(!ParseUnsigned(bad, 16, 32, &number) && number == 73, "DWORD overflow/invalid hex rejected");
        }
        check(ParseUnsigned("4294967295", 10, 32, &number) && number == UINT64_C(0xffffffff), "DWORD maximum decimal");
        check(!ParseUnsigned("4294967296", 10, 32, &number), "DWORD decimal overflow rejected");
        check(!ParseUnsigned("1", 10, 16, &number), "unsupported integer width rejected");
        check(!ParseUnsigned("1", 2, 32, &number), "unsupported integer base rejected");
        for (unsigned width : {4u, 8u})
        {
            for (bool bigEndian : {false, true})
            {
                for (std::uint64_t input : {UINT64_C(0), UINT64_C(1), UINT64_C(0x12345678), UINT64_C(0xffffffff)})
                {
                    std::string encoded;
                    check(EncodeUnsigned(input, width, &encoded, bigEndian), "integer encoded");
                    check(DecodeUnsigned(encoded, width, &number, bigEndian) && number == input, "integer endian roundtrip");
                }
            }
        }
        std::string encoded = "unchanged";
        check(!EncodeUnsigned(UINT64_C(0x100000000), 4, &encoded) && encoded == "unchanged", "DWORD encoder cannot truncate QWORD");
        number = 73;
        check(!DecodeUnsigned(std::string(5, '\0'), 4, &number) && number == 73, "integer wrong width rejected");
        check(EncodeUnsigned(UINT64_C(0x12345678), 4, &encoded, true)
            && encoded == std::string("\x12\x34\x56\x78", 4), "DWORD big endian byte order");
        std::u16string decoded;
        bool canonical = false;
        for (const auto& input : {std::u16string(), std::u16string(u" leading and trailing "),
            std::u16string(u"中文\U0001f642\r\nsecond line")})
        {
            check(EncodeString(input, &encoded), "UTF16 string encoded");
            check(DecodeString(encoded, &decoded, &canonical) && canonical && decoded == input, "UTF16 string roundtrip");
            encoded.resize(encoded.size() - 2);
            check(DecodeString(encoded, &decoded, &canonical) && !canonical && decoded == input, "unterminated string is readable and flagged");
        }
        decoded = u"unchanged";
        check(!DecodeString(std::string("\x41", 1), &decoded) && decoded == u"unchanged", "odd UTF16 size rejected without partial output");
        check(!DecodeString(std::string("\0\xd8", 2), &decoded), "isolated high surrogate rejected");
        check(!DecodeString(std::string("\0\xdc", 2), &decoded), "isolated low surrogate rejected");
        check(!DecodeString(std::string("A\0\0\0B\0", 6), &decoded), "embedded NUL cannot become lossy string");
        check(DecodeString(std::string("A\0\0\0\0\0", 6), &decoded, &canonical)
            && decoded == u"A" && !canonical, "extra string terminators flagged");
        encoded = "unchanged";
        check(!EncodeString(std::u16string_view(u"A\0B", 3), &encoded) && encoded == "unchanged", "NUL string encode refused");
        std::vector<std::u16string> decodedItems;
        const std::vector<std::u16string> items{u"first", u" 中间 ", u"third\U0001f642"};
        check(EncodeMultiString(items, &encoded), "multi encoded");
        check(DecodeMultiString(encoded, &decodedItems, &canonical) && canonical && decodedItems == items, "multi preserves entries and whitespace");
        encoded.append(2, '\0');
        check(DecodeMultiString(encoded, &decodedItems, &canonical) && !canonical && decodedItems == items, "multi extra NUL flagged");
        check(EncodeMultiString({}, &encoded) && encoded.size() == 4, "empty multi has double NUL");
        check(DecodeMultiString(encoded, &decodedItems, &canonical) && canonical && decodedItems.empty(), "empty multi roundtrip");
        check(DecodeMultiString(std::string("A\0\0\0B\0", 6), &decodedItems, &canonical)
            && !canonical && decodedItems == std::vector<std::u16string>{u"A", u"B"}, "unterminated multi keeps final item");
        decodedItems = {u"unchanged"};
        check(!DecodeMultiString(std::string("A\0\0\0\0\0B\0", 8), &decodedItems)
            && decodedItems == std::vector<std::u16string>{u"unchanged"}, "data after multi terminator rejected without partial output");
        encoded = "unchanged";
        check(!EncodeMultiString({u"first", u"", u"third"}, &encoded)
            && encoded == "unchanged", "empty middle multi entry cannot silently end list");
    }

    void testEditor(const QString& shots)
    {
        using namespace ks::registry;
        RegistryValueEditorWidget editor;
        auto* name = editor.findChild<QLineEdit*>(QStringLiteral("registry_value_name"));
        auto* type = editor.findChild<QComboBox*>(QStringLiteral("registry_value_type"));
        auto* text = editor.findChild<QPlainTextEdit*>(QStringLiteral("registry_value_text"));
        auto* multi = editor.findChild<QPlainTextEdit*>(QStringLiteral("registry_value_multi"));
        auto* hexNumber = editor.findChild<QLineEdit*>(QStringLiteral("registry_value_hex_number"));
        auto* decimalNumber = editor.findChild<QLineEdit*>(QStringLiteral("registry_value_decimal_number"));
        auto* raw = editor.findChild<ks::ui::HexView*>(QStringLiteral("registry_value_raw_hex"));
        auto* length = editor.findChild<QLineEdit*>(QStringLiteral("registry_value_byte_length"));
        auto* color = editor.findChild<QPushButton*>(QStringLiteral("registry_value_console_color"));
        auto* expanded = editor.findChild<QPlainTextEdit*>(QStringLiteral("registry_value_expanded"));
        auto* tabs = editor.findChild<QTabWidget*>(QStringLiteral("registry_value_tabs"));
        check(name && type && text && multi && hexNumber && decimalNumber && raw && length && color && expanded && tabs,
            "all real editor controls available");
        if (!name || !type || !text || !multi || !hexNumber || !decimalNumber || !raw || !length || !color || !expanded || !tabs) return;
        RegistryValueDraft draft;
        QString error;
        const QByteArray odd("\x41", 1);
        editor.setValue(QStringLiteral("HKCU\\Test"), QStringLiteral("odd"), TypeString, odd);
        check(editor.value(&draft, &error) && draft.data == odd && !editor.isModified(), "malformed original bytes remain exact");
        check(text->isReadOnly(), "malformed text cannot normalize silently");
        check(name->isReadOnly() && !type->isEnabled(), "edit identity/type are fixed");
        const QByteArray noncanonical("A\0\0\0\0\0", 6);
        editor.setValue(QStringLiteral("HKCU\\Test"), QStringLiteral(" spaced "), TypeString, noncanonical);
        check(editor.value(&draft, &error) && draft.name == QStringLiteral(" spaced ") && draft.data == noncanonical,
            "untouched whitespace name and extra terminators preserved");
        text->setPlainText(QStringLiteral("changed\nlong text"));
        check(editor.value(&draft, &error) && draft.data == stringBytes(u"changed\nlong text") && editor.isModified(), "long text edit uses complete UTF16");
        text->setPlainText(QStringLiteral("A"));
        check(editor.value(&draft, &error) && draft.data == noncanonical && !editor.isModified(), "returning to original text restores exact unusual bytes");
        text->setPlainText(QString(QChar(0)));
        draft = {QStringLiteral("sentinel"), 999, QByteArray("sentinel")};
        check(!editor.value(&draft, &error) && draft.name == QStringLiteral("sentinel") && !error.isEmpty(), "invalid typed data leaves caller output untouched");
        editor.discardChanges();
        check(editor.value(&draft, &error) && draft.data == noncanonical && error.isEmpty(), "discard restores original bytes and clears error");
        QByteArray unterminated = stringBytes(u"line one\r\nline two");
        unterminated.truncate(unterminated.size() - 2);
        editor.setValue(QStringLiteral("HKCU\\Test"), QStringLiteral("line"), TypeString, unterminated);
        const QString normalized = text->toPlainText();
        text->setPlainText(QStringLiteral("different"));
        text->setPlainText(normalized);
        check(editor.value(&draft, &error) && draft.data == unterminated, "normalized display does not lose original CRLF/termination on revert");
        editor.setValue(QStringLiteral("HKCU\\Test"), QString(), TypeString, QByteArray(2, '\0'), true);
        name->setText(QStringLiteral("  new value  "));
        check(editor.value(&draft, &error) && draft.name == QStringLiteral("  new value  "), "new name keeps legal spaces");
        name->setText(QString());
        check(editor.value(&draft, &error) && draft.name.isEmpty(), "default empty name accepted");
        name->setText(QStringLiteral("a") + QChar(0) + QStringLiteral("b"));
        check(!editor.value(&draft, &error), "NUL name refused");
        editor.discardChanges();
        type->setCurrentIndex(type->findData(TypeQword));
        decimalNumber->setText(QStringLiteral("18446744073709551615"));
        check(editor.value(&draft, &error) && draft.type == TypeQword && draft.data == QByteArray(8, std::bit_cast<char>(std::uint8_t{0xff})), "new QWORD maximum complete bytes");
        check(hexNumber->text().compare(QStringLiteral("0xffffffffffffffff"), Qt::CaseInsensitive) == 0, "decimal updates hex exactly");
        decimalNumber->setText(QStringLiteral("18446744073709551616"));
        check(!editor.value(&draft, &error) && editor.isModified(), "QWORD overflow cannot submit last valid number");
        decimalNumber->setText(QStringLiteral("-1"));
        check(!editor.value(&draft, &error), "negative QWORD refused");
        hexNumber->setText(QStringLiteral("0x123456789abcdef0"));
        check(editor.value(&draft, &error) && decimalNumber->text() == QStringLiteral("1311768467463790320"), "hex corrects invalid input and updates decimal");
        editor.setValue(QStringLiteral("HKCU\\Test"), QStringLiteral("dword"), TypeDword, QByteArray(4, '\0'));
        hexNumber->setText(QStringLiteral("0xffffffff"));
        check(editor.value(&draft, &error) && draft.data == QByteArray(4, std::bit_cast<char>(std::uint8_t{0xff})), "DWORD maximum encoded without sign conversion");
        hexNumber->setText(QStringLiteral("0x100000000"));
        check(!editor.value(&draft, &error), "DWORD does not truncate overflow");
        editor.discardChanges();
        std::vector<std::u16string> entries(60, std::u16string(30, u'中'));
        entries[0] = u" first with spaces ";
        std::string encoded;
        check(EncodeMultiString(entries, &encoded), "large multi fixture encoded");
        encoded.append(2, '\0');
        const QByteArray multiOriginal = bytes(encoded);
        editor.setValue(QStringLiteral("HKCU\\Test"), QStringLiteral("multi"), TypeMultiString, multiOriginal);
        check(editor.value(&draft, &error) && draft.data == multiOriginal && draft.data.size() > 512, "large multi keeps all entries and unusual terminator");
        const QString multiText = multi->toPlainText();
        multi->setPlainText(multiText + QStringLiteral("\nlast"));
        entries.push_back(u"last");
        check(EncodeMultiString(entries, &encoded), "expected modified multi encoded");
        check(editor.value(&draft, &error) && draft.data == bytes(encoded), "multi edit preserves complete list beyond preview length");
        multi->setPlainText(QStringLiteral("first\n\nthird"));
        check(!editor.value(&draft, &error), "blank multi entry blocks submission");
        multi->setPlainText(multiText);
        check(editor.value(&draft, &error) && draft.data == multiOriginal && !editor.isModified(), "multi revert restores original bytes");
        check(EncodeMultiString({u"one\ntwo"}, &encoded), "embedded newline is legal raw multi data");
        editor.setValue(QStringLiteral("HKCU\\Test"), QStringLiteral("raw multi"), TypeMultiString, bytes(encoded));
        check(multi->isReadOnly() && editor.value(&draft, &error) && draft.data == bytes(encoded), "multiline item uses exact raw fallback");
        QByteArray binary(8192, '\0');
        for (qsizetype i = 0; i < binary.size(); ++i) binary[i] = char(i % 256);
        editor.setValue(QStringLiteral("HKCU\\Test"), QStringLiteral("binary"), TypeBinary, binary);
        check(raw->buffer() == binary && editor.value(&draft, &error) && draft.data == binary, "binary editor receives all bytes beyond 512");
        auto* realView = raw;
        check(realView != nullptr, "raw editor uses production HexView");
        if (realView)
        {
            const QByteArray replacement("\x99\xaa", 2);
            realView->canvas()->stageBytes(5000, replacement);
            QApplication::processEvents();
            binary.replace(5000, 2, replacement);
            check(editor.value(&draft, &error) && draft.data == binary && editor.isModified(), "actual Hex edits update full draft at offset beyond preview");
        }
        editor.discardChanges();
        check(editor.value(&draft, &error) && static_cast<unsigned char>(draft.data[5000]) == 5000 % 256,
            "discard restores distant binary byte");
        length->setText(QStringLiteral("9000"));
        for (auto* button : editor.findChildren<QPushButton*>())
            if (button->text() == QStringLiteral("调整长度")) button->click();
        check(editor.value(&draft, &error) && draft.data.size() == 9000 && draft.data.mid(8192) == QByteArray(808, '\0'), "binary resize extends with complete zeros");
        length->setText(QStringLiteral("33554433"));
        for (auto* button : editor.findChildren<QPushButton*>())
            if (button->text() == QStringLiteral("调整长度")) button->click();
        check(editor.value(&draft, &error) && draft.data.size() == 9000, "oversized resize refuses without changing draft");
        editor.setValue(QStringLiteral("HKCU\\Test"), QStringLiteral("unknown"), 777, binary);
        check(editor.value(&draft, &error) && draft.type == 777 && draft.data == binary && !tabs->isTabEnabled(0), "unknown type retains all raw bytes and fixed type");
        editor.setValue(QStringLiteral("HKCU\\Console"), QStringLiteral("ColorTable12"), TypeDword, QByteArray("\x12\x34\x56\0", 4));
        check(!color->isHidden() && !color->icon().isNull(), "known Console COLORREF gets data swatch");
        editor.setValue(QStringLiteral("HKCU\\Other"), QStringLiteral("ColorTable12"), TypeDword, QByteArray(4, '\0'));
        check(color->isHidden(), "same value name outside Console does not acquire color meaning");
        const QByteArray oldEnv = qgetenv("KSWORD_REGISTRY_EDITOR_TEST_ENV");
        qputenv("KSWORD_REGISTRY_EDITOR_TEST_ENV", "expanded-test");
        const QByteArray expandable = stringBytes(u"%KSWORD_REGISTRY_EDITOR_TEST_ENV%\\tail");
        editor.setValue(QStringLiteral("HKCU\\Test"), QStringLiteral("expand"), TypeExpandString, expandable);
        check(expanded->isReadOnly() && expanded->toPlainText() == QStringLiteral("expanded-test\\tail"), "expand preview uses actual current process environment");
        check(editor.value(&draft, &error) && draft.data == expandable, "expanded preview never replaces stored original");
        if (oldEnv.isNull()) qunsetenv("KSWORD_REGISTRY_EDITOR_TEST_ENV"); else qputenv("KSWORD_REGISTRY_EDITOR_TEST_ENV", oldEnv);

        editor.resize(360, 700);
        editor.show();
        QApplication::processEvents();
        check(editor.width() == 360 && editor.findChild<QPlainTextEdit*>(QStringLiteral("registry_value_text"))->width() < 360,
            "editor fits narrow sidebar with responsive form");
        if (!shots.isEmpty())
        {
            QDir().mkpath(shots);
            check(editor.grab().save(shots + QStringLiteral("/registry-value-sidebar-light.png")), "light sidebar screenshot saved");
            KswordTheme::SetDarkModeEnabled(true);
            QPalette palette = QApplication::palette();
            palette.setColor(QPalette::Window, KswordTheme::WindowColor());
            palette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
            palette.setColor(QPalette::Base, KswordTheme::SurfaceColor());
            palette.setColor(QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
            palette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
            palette.setColor(QPalette::Button, KswordTheme::SurfaceAltColor());
            palette.setColor(QPalette::ButtonText, KswordTheme::TextPrimaryColor());
            palette.setColor(QPalette::Mid, KswordTheme::BorderColor());
            palette.setColor(QPalette::PlaceholderText, KswordTheme::TextSecondaryColor());
            palette.setColor(QPalette::Highlight, KswordTheme::PrimaryAccentColor());
            palette.setColor(QPalette::HighlightedText, KswordTheme::OnAccentColor());
            palette.setColor(QPalette::Disabled, QPalette::Base, KswordTheme::SurfaceColor());
            palette.setColor(QPalette::Disabled, QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
            palette.setColor(QPalette::Disabled, QPalette::Button, KswordTheme::SurfaceAltColor());
            palette.setColor(QPalette::Disabled, QPalette::Text, KswordTheme::TextDisabledColor());
            palette.setColor(QPalette::Disabled, QPalette::ButtonText, KswordTheme::TextDisabledColor());
            QApplication::setPalette(palette);
            QApplication::processEvents();
            check(editor.grab().save(shots + QStringLiteral("/registry-value-sidebar-dark.png")), "dark sidebar screenshot saved");
            editor.setValue(QStringLiteral("HKCU\\Console"), QStringLiteral("ColorTable12"), TypeDword, QByteArray("\x12\x34\x56\0", 4));
            editor.resize(900, 700);
            QApplication::processEvents();
            check(editor.grab().save(shots + QStringLiteral("/registry-value-dialog.png")), "wide editor screenshot saved");
        }
    }

    void testAdvancedDialogs(const QString& shots)
    {
        bool opened = false;
        QTimer::singleShot(0, [&] {
            auto* dialog = qobject_cast<QDialog*>(QApplication::activeModalWidget());
            opened = dialog && dialog->objectName() == QStringLiteral("registry_key_permissions");
            check(opened, "permissions dialog opens with immutable target snapshot");
            if (!dialog) return;
            bool foundApply = false;
            for (auto* button : dialog->findChildren<QPushButton*>())
                if (button->text() == QStringLiteral("应用 DACL")) { foundApply = true; check(!button->isEnabled(), "invalid root cannot apply permissions"); }
            check(foundApply, "permissions exposes explicit DACL apply action");
            auto* original = dialog->findChild<CodeEditorWidget*>(QStringLiteral("registry_original_dacl"));
            auto* requested = dialog->findChild<CodeEditorWidget*>(QStringLiteral("registry_requested_dacl"));
            check(original && requested, "permissions uses built-in editors for both DACL areas");
            check(original && original->isReadOnly() && requested && requested->isReadOnly(),
                "invalid target keeps both built-in DACL editors read-only");
            if (original && requested)
            {
                // 只操作 UI 内容，目标仍是解析阶段就拒绝的根，不会调用真实注册表。
                const QString raw = QStringLiteral("D:P(A;;KA;;;SY)(A;;KR;;;BU)");
                original->setRawText(raw);
                requested->setReadOnly(false);
                requested->setRawText(raw + QStringLiteral("(A;;KR;;;AU)"));
                check(original->text() == raw && requested->text().endsWith(QStringLiteral("(A;;KR;;;AU)")),
                    "built-in DACL editors retain exact SDDL without generated-report translation");
            }
            if (!shots.isEmpty()) check(dialog->grab().save(shots + QStringLiteral("/registry-permissions-invalid.png")), "permissions error screenshot saved");
            dialog->close();
        });
        // The invalid root is rejected by the parser before any registry API.
        ShowRegistryKeyPermissions(nullptr, QStringLiteral("INVALID_ROOT\\NoRegistryAccess"), 32);
        check(opened, "permissions modal returned after empty error fixture");
        opened = false;
        QTimer::singleShot(0, [&] {
            auto* dialog = qobject_cast<QDialog*>(QApplication::activeModalWidget());
            opened = dialog && dialog->objectName() == QStringLiteral("registry_offline_hive");
            check(opened, "offline application-hive UI opens without loading a file");
            if (!dialog) return;
            bool foundSave = false;
            for (auto* button : dialog->findChildren<QPushButton*>())
                if (button->text() == QStringLiteral("另存副本")) { foundSave = true; check(!button->isEnabled(), "empty offline fixture cannot save a hive"); }
            check(foundSave, "offline UI exposes explicit save-copy action");
            if (!shots.isEmpty()) check(dialog->grab().save(shots + QStringLiteral("/registry-offline-empty.png")), "offline empty screenshot saved");
            dialog->close();
        });
        ShowRegistryOfflineHive(nullptr);
        check(opened, "offline modal returned without system registry/hive access");
    }
}

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    application.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    for (const QString& font : {QStringLiteral("C:/Windows/Fonts/msyh.ttc"),
        QStringLiteral("C:/Windows/Fonts/consola.ttf"), QStringLiteral("C:/Windows/Fonts/segoeui.ttf")})
        QFontDatabase::addApplicationFont(font);
    application.setFont(QFont(QStringLiteral("Microsoft YaHei"), 9));
    application.setApplicationName(QStringLiteral("KSword Registry Value Editor Tests"));
    application.setOrganizationName(QStringLiteral("KSword Tests"));
    QSettings::setDefaultFormat(QSettings::IniFormat);
    if (argc > 1)
    {
        // 用户与系统作用域都隔离在自建夹具输出目录，不借用生产注册表偏好。
        const QString settingsPath = QString::fromLocal8Bit(argv[1]);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settingsPath);
        QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, settingsPath);
    }
    testCodec();
    testEditor(argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString());
    testAdvancedDialogs(argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString());
    std::cout << "REGISTRY_VALUE_EDITOR_CHECKS=" << checks << " FAILURES=" << failures << std::endl;
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
