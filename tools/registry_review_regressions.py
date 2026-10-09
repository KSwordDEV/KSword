"""MSVC mock regressions in an already existing output directory; no live registry access."""
from pathlib import Path
import argparse
import os
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qt", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--vcvars", required=True, type=Path)
    parser.add_argument("--ui-only", action="store_true", help="Resume only the offscreen shell gate after codec/access passed")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    app = repo / "Ksword5.1" / "Ksword5.1"
    qt, output = args.qt.resolve(), args.output.resolve()
    if not output.is_dir():
        raise RuntimeError("The output directory must already exist; this runner never creates directories.")
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", QT_PLUGIN_PATH=str(qt / "plugins"))
    env["PATH"] = str(qt / "bin") + os.pathsep + env.get("PATH", "")
    flags = ["/nologo", "/std:c++latest", "/Zc:__cplusplus", "/permissive-", "/utf-8", "/EHsc",
             "/MD", "/W4", "/WX", "/DNOMINMAX", "/DUNICODE", "/D_UNICODE", "/external:W0"]
    for module in ("", "QtCore", "QtGui", "QtWidgets", "QtSvg"):
        flags.append("/external:I" + str(qt / "include" / module))
    flags.append("/I" + str(app))

    def cl(arguments):
        # Access 夹具显式恢复 Windows 宏时，不先定义同名宏再取消，避免 D9025 命令行提示。
        active_flags = [flag for flag in flags if not ("/UNOMINMAX" in arguments and flag == "/DNOMINMAX")]
        command = subprocess.list2cmdline(["cl", *active_flags, *map(str, arguments)])
        batch = output / "registry-review-command.cmd"
        batch.write_text(f'@echo off\ncall "{args.vcvars.resolve()}" >nul\n'
                         'if errorlevel 1 exit /b %errorlevel%\n' + command + '\nexit /b %errorlevel%\n',
                         encoding="utf-8")
        subprocess.run(["cmd", "/d", "/c", batch], cwd=repo, env=env, check=True)

    def build(name, sources, libraries, extra_flags=()):
        objects = []
        for source in sources:
            obj = output / (name + "-" + source.stem + ".obj")
            cl([*extra_flags, "/c", source, "/Fo" + str(obj)])
            objects.append(obj)
        exe = output / (name + ".exe")
        cl([*objects, "/Fe" + str(exe), "/link", "/LIBPATH:" + str(qt / "lib"), *libraries])
        return exe

    if not args.ui_only:
        document = build("registry-review-document", [repo / "tools" / "registry_document_tests.cpp",
        app / "RegistryDock" / "RegistryDocument.cpp", app / "RegistryDock" / "RegistryDocumentApply.cpp",
        app / "RegistryDock" / "RegistryDocumentApply.Win32.cpp"], ["Qt6Core.lib", "advapi32.lib"])
        subprocess.run([document, "--existing-output", output], cwd=repo, env=env, check=True)
        transaction = build("registry-review-transaction", [repo / "tools" / "registry_document_transaction_tests.cpp"], ["Qt6Core.lib"])
        subprocess.run([transaction], cwd=repo, env=env, check=True)
        access = build("registry-review-access", [repo / "tools" / "registry_workbench_access_tests.cpp"],
                   ["Qt6Core.lib", "advapi32.lib"], ["/UNOMINMAX"])
        subprocess.run([access], cwd=repo, env=env, check=True)

    # Extract the production methods verbatim; only Win32/R0 transports in the template are mocks.
    themed = (app / "RegistryDock_Themed.cpp").read_text(encoding="utf-8-sig")
    workbench = (app / "RegistryDock" / "RegistryDock.Workbench.cpp").read_text(encoding="utf-8-sig")
    mutations = (app / "RegistryDock" / "RegistryDock.Mutations.cpp").read_text(encoding="utf-8-sig")
    assert "RegistryValueTransactions::rename" in mutations and "RegistryWorkbenchAccess::renameKey" in mutations
    assert "renameRegistryKeyAny" not in themed and "RegSetValueExW" not in themed
    # 实际共享键重命名与回读由 Access 夹具执行；树删除只在具备能力的正式事务入口验证。
    context = workbench[workbench.index("RegistryAccessContext RegistryDock::accessContextForPath("):workbench.index("void RegistryDock::initializeWorkbenchControls(")]
    menu_start = workbench.index("    void applyWorkbenchMenuTheme(")
    menu_end = workbench.index("\n    }", menu_start) + len("\n    }")
    assert 'QMenu menu(this);\n        applyWorkbenchMenuTheme(menu);' in workbench
    navigation = workbench[workbench.index("void RegistryDock::showNavigationMenu()") :]
    assert 'QMenu menu(this);\n    applyWorkbenchMenuTheme(menu);' in navigation
    assert 'applyWorkbenchMenuTheme(*history);' in navigation
    template = (repo / "tools" / "registry_workbench_ui" / "registry_review_ui_tests.template.cpp").read_text(encoding="utf-8")
    documents = (app / "RegistryDock" / "RegistryDock.Documents.cpp").read_text(encoding="utf-8-sig")
    receipt_start = documents.index("                            const RegistryAccessContext currentContext = guarded->accessContext();")
    receipt_end = documents.index("                            guarded->updateStatusBar(result->completed", receipt_start)
    receipt_navigation = documents[receipt_start:receipt_end]
    generated = output / "registry-review-ui.cpp"
    generated.write_text(template.replace("//@@ACCESS_CONTEXT@@", context).replace("//@@RECEIPT_NAVIGATION@@", receipt_navigation)
                         .replace("//@@MENU_THEME@@", workbench[menu_start:menu_end]), encoding="utf-8")
    advanced = (app / "RegistryDock" / "RegistryAdvancedDialogs.cpp").read_text(encoding="utf-8-sig")
    assert "m_original = new CodeEditorWidget" in advanced and "m_edit = new CodeEditorWidget" in advanced
    assert "m_original->setRawText" in advanced and "m_edit->text()" in advanced
    assert "#include <QPlainTextEdit>" not in advanced
    moc = output / "registry-review-moc-CodeEditorWidget.cpp"
    subprocess.run([qt / "bin" / "moc.exe", app / "UI" / "CodeEditorWidget.h", "-o", moc], env=env, check=True)
    # Compile the actual advanced dialogs, too, to check their use of the production editor API.
    cl(["/c", app / "RegistryDock" / "RegistryAdvancedDialogs.cpp", "/Fo" + str(output / "registry-review-advanced.obj")])
    ui = build("registry-review-ui", [generated, app / "UI" / "CodeEditorWidget.cpp",
        app / "UI" / "CodeTextEdit.cpp", app / "UI" / "CodeEditorFileSession.cpp", app / "UI" / "ReportStructuredView.cpp",
        app / "UI" / "FieldTreePresenter.cpp", app / "UI" / "FieldTreePresenter.Copy.cpp",
        app / "Internationalization" / "LanguageManager.cpp", moc],
        ["Qt6Core.lib", "Qt6Gui.lib", "Qt6Widgets.lib", "Qt6Svg.lib", "user32.lib", "advapi32.lib", "shell32.lib"],
        ["/wd4458"])  # Production editor owns QWidget::data; preserve its existing local-name policy.
    subprocess.run([ui], cwd=repo, env=env, check=True)


if __name__ == "__main__":
    main()
