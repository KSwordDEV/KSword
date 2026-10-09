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
#include <memory>
#include "RegistryDock/RegistryWorkbenchAccess.h"
#include "RegistryDock/RegistryDocumentApply.h"
#include "UI/CodeEditorWidget.h"
#include "theme.h"

namespace {
int checks = 0;
int failures = 0;
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
}

class RegistryDock final {
public:
    int m_viewBits = 0;
    QString m_currentPath;
    QString navigatedPath;
    unsigned navigations = 0, refreshes = 0;
    bool shouldUseRegistryR0() const { return driverOnline && m_viewBits == 0; }
    RegistryAccessContext accessContextForPath(const QString& path) const;
    RegistryAccessContext accessContext() const { return accessContextForPath(m_currentPath); }
    void navigateToPath(const QString& path, bool) { navigatedPath = path; ++navigations; }
    void refreshCurrentKey(bool) { ++refreshes; }


};

//@@ACCESS_CONTEXT@@
//@@MENU_THEME@@

// 原样注入生产回执刷新分支，fake 只记录导航/刷新动作，不查询真实注册表。
void applyReceiptNavigation(RegistryDock* guarded, const std::shared_ptr<RegistryApplyResult>& result)
{
//@@RECEIPT_NAVIGATION@@
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    RegistryDock dock;
    for (int view : {0, 32, 64})
    {
        dock.m_viewBits = view;
        const auto context = dock.accessContextForPath(QStringLiteral("HKEY_CLASSES_ROOT\\Software\\Before"));
        check(!context.useR0 && context.viewBits == view, "actual HKCR context retains merged Win32 native/32/64 view");
    }
    driverOnline = false;
    auto result = std::make_shared<RegistryApplyResult>();
    result->viewBits = 32;
    RegistryApplyReceipt receipt;
    receipt.state = RegistryApplyReceipt::State::Success;
    receipt.mutated = true;
    receipt.operation.kind = RegistryApplyOperation::Kind::CreateKey;
    receipt.operation.keyPath = QStringLiteral("HKEY_LOCAL_MACHINE\\Parent\\New");
    result->receipts.append(receipt);
    dock.m_viewBits = 32;
    dock.m_currentPath = QStringLiteral("HKEY_LOCAL_MACHINE\\Parent");
    applyReceiptNavigation(&dock, result);
    check(dock.navigations == 1 && dock.navigatedPath == receipt.operation.keyPath && dock.refreshes == 0,
        "successful single create navigates to the actual new key");
    dock.navigations = dock.refreshes = 0;
    result->receipts[0].operation.kind = RegistryApplyOperation::Kind::DeleteTree;
    result->receipts[0].operation.keyPath = QStringLiteral("HKEY_LOCAL_MACHINE\\Parent\\Removed");
    dock.m_currentPath = QStringLiteral("HKEY_LOCAL_MACHINE\\Parent\\Removed\\Child");
    applyReceiptNavigation(&dock, result);
    check(dock.navigations == 1 && dock.navigatedPath == QStringLiteral("HKEY_LOCAL_MACHINE\\Parent"),
        "successful deletion of current subtree navigates to its parent");
    dock.navigations = dock.refreshes = 0;
    result->receipts[0].state = RegistryApplyReceipt::State::Failed;
    applyReceiptNavigation(&dock, result);
    check(dock.navigations == 0 && dock.refreshes == 1, "failed deletion only refreshes the actual tree");
    dock.navigations = dock.refreshes = 0;
    result->viewBits = 64;
    applyReceiptNavigation(&dock, result);
    check(dock.navigations == 0 && dock.refreshes == 0, "late receipt from a different registry view cannot navigate or refresh current source");
    result->viewBits = 0;
    dock.m_viewBits = 0;
    driverOnline = true;
    applyReceiptNavigation(&dock, result);
    check(dock.navigations == 0 && dock.refreshes == 0, "late Win32 receipt cannot refresh the current R0 source");
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
