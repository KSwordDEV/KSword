// 针对审查修复的离屏夹具；生产入口由 runner 原样填入，仅注册表传输被 mock。
#include <Windows.h>
#include <QApplication>
#include <QMenu>
#include <QImage>
#include <QPixmap>
#include <QStyleFactory>
#include <cstring>
#include <iostream>
#include <string>
#include "RegistryDock/RegistryWorkbenchAccess.h"
#include "UI/CodeEditorWidget.h"
#include "theme.h"

namespace {
int checks = 0;
int failures = 0;
int win32Renames = 0;
int r0Renames = 0;
int lastView = 0;
bool driverOnline = true;
void check(bool ok, const char* label)
{
    ++checks;
    if (!ok)
    {
        ++failures;
        std::cerr << "FAIL " << label << '\n';
    }
}
struct Key { HKEY root; int view; };
LSTATUS WINAPI mockOpen(HKEY root, LPCWSTR, DWORD, REGSAM access, PHKEY output)
{
    const int view = (access & KEY_WOW64_32KEY) ? 32 : (access & KEY_WOW64_64KEY) ? 64 : 0;
    *output = reinterpret_cast<HKEY>(new Key{root, view});
    return ERROR_SUCCESS;
}
LSTATUS WINAPI mockClose(HKEY handle)
{
    delete reinterpret_cast<Key*>(handle);
    return ERROR_SUCCESS;
}
LSTATUS WINAPI mockRename(HKEY handle, LPCWSTR before, LPCWSTR after)
{
    ++win32Renames;
    const auto* key = reinterpret_cast<const Key*>(handle);
    lastView = key->view;
    return key->root == HKEY_CLASSES_ROOT && std::wcscmp(before, L"Before") == 0
        && std::wcscmp(after, L"After") == 0 ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
}
FARPROC WINAPI mockResolve(HMODULE, LPCSTR name)
{
    if (std::strcmp(name, "RegRenameKey") != 0)
        return nullptr;
    const auto function = &mockRename;
    FARPROC result = nullptr;
    static_assert(sizeof(function) == sizeof(result));
    std::memcpy(&result, &function, sizeof(result));
    return result;
}
}

namespace ksword::ark {
struct RegistryOperationResult {};
class DriverClient final {
public:
    RegistryOperationResult renameRegistryKey(const std::wstring&, const std::wstring&) const
    {
        ++r0Renames;
        return {};
    }
};
}
bool registryOperationSucceeded(const ksword::ark::RegistryOperationResult&) { return false; }
QString registryOperationFailureText(const QString&, const ksword::ark::RegistryOperationResult&) { return QStringLiteral("R0 refused"); }
QString RegistryWorkbenchAccess::kernelPath(const QString& path)
{
    return path.startsWith(QStringLiteral("HKEY_CLASSES_ROOT")) ? QString() : QStringLiteral("\\REGISTRY\\MOCK");
}
QString buildKernelRegistryPath(const QString& path) { return RegistryWorkbenchAccess::kernelPath(path); }
QString winErrorText(LSTATUS status) { return QString::number(status); }

class RegistryDock final {
public:
    int m_viewBits = 0;
    bool shouldUseRegistryR0() const { return driverOnline && m_viewBits == 0; }
    RegistryAccessContext accessContextForPath(const QString& path) const;
    bool renameRegistryKeyAny(const QString&, const QString&, QString*, QString*);
    static bool parseRegistryPath(const QString& path, HKEY* root, QString* rest)
    {
        const int slash = static_cast<int>(path.indexOf(QLatin1Char('\\')));
        if (slash < 0)
            return false;
        const QString name = path.left(slash);
        *root = name == QStringLiteral("HKEY_CLASSES_ROOT") ? HKEY_CLASSES_ROOT : HKEY_CURRENT_USER;
        *rest = path.mid(slash + 1);
        return true;
    }
    static QString rootKeyToText(HKEY root)
    {
        return root == HKEY_CLASSES_ROOT ? QStringLiteral("HKEY_CLASSES_ROOT") : QStringLiteral("HKEY_CURRENT_USER");
    }
};

//@@ACCESS_CONTEXT@@
#define RegOpenKeyExW mockOpen
#define RegCloseKey mockClose
#define GetProcAddress mockResolve
//@@RENAME@@
#undef RegOpenKeyExW
#undef RegCloseKey
#undef GetProcAddress

//@@MENU_THEME@@

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    RegistryDock dock;
    for (int view : {0, 32, 64})
    {
        dock.m_viewBits = view;
        QString result, error;
        check(dock.renameRegistryKeyAny(QStringLiteral("HKEY_CLASSES_ROOT\\Software\\Before"),
            QStringLiteral("After"), &result, &error), "actual HKCR rename succeeds with driver online");
        check(result == QStringLiteral("HKEY_CLASSES_ROOT\\Software\\After") && lastView == view,
            "actual rename retains target path and native/32/64 view");
    }
    check(win32Renames == 3 && r0Renames == 0, "HKCR rename executes only mocked Win32 transport");
    for (bool dark : {false, true})
    {
        KswordTheme::SetDarkModeEnabled(dark);
        QMenu menu;
        menu.addAction(QStringLiteral("Enabled"));
        menu.addAction(QStringLiteral("Disabled"))->setEnabled(false);
        applyWorkbenchMenuTheme(menu);
        auto* history = menu.addMenu(QStringLiteral("History"));
        applyWorkbenchMenuTheme(*history);
        check(menu.styleSheet() == KswordTheme::ContextMenuStyle()
            && history->styleSheet() == menu.styleSheet(), "menu and submenu explicitly use current light/dark theme");
        check(menu.styleSheet().contains(QStringLiteral("QMenu::item:selected"))
            && menu.styleSheet().contains(QStringLiteral("QMenu::item:disabled")), "menu theme includes selected and disabled roles");
        menu.show();
        QApplication::processEvents();
        const QImage rendered = menu.grab().toImage();
        check(!rendered.isNull() && rendered.pixelColor(2, 2) == KswordTheme::SurfaceColor(),
            "actual menu paints opaque light/dark surface");
        menu.close();
        CodeEditorWidget original, requested;
        original.setStructuredReportViewEnabled(false);
        requested.setStructuredReportViewEnabled(false);
        original.setReadOnly(true);
        const QString sddl = QStringLiteral("D:P(A;;KA;;;SY)(A;;KR;;;BU)");
        original.setRawText(sddl);
        requested.setRawText(sddl);
        check(original.isReadOnly() && !requested.isReadOnly(), "built-in DACL editors preserve readonly/editable roles");
        requested.setRawText(sddl + QStringLiteral("(A;;KR;;;AU)"));
        QApplication::processEvents();
        check(original.text() == sddl && requested.text() == sddl + QStringLiteral("(A;;KR;;;AU)"),
            "built-in DACL editors preserve exact raw SDDL during theme changes");
    }
    std::cout << "REGISTRY_REVIEW_UI_CHECKS=" << checks << " FAILURES=" << failures << '\n';
    return failures ? 1 : 0;
}
