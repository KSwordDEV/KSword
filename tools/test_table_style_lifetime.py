"""Run the production table proxy/style installation through Qt menu teardown.

Use --source-ref to verify that the previous implementation fails this regression.
MSVC is the default; --compiler supports a portable MinGW Qt fixture.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
from xml.sax.saxutils import escape


def block(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/|[{}]', re.S)
    for token in tokens.finditer(source, opening):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return source[start:token.end()]
    raise ValueError(f"Unterminated production block: {marker}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qt-dir", required=True)
    parser.add_argument("--msbuild")
    parser.add_argument("--compiler")
    parser.add_argument("--source-ref")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    qt = Path(args.qt_dir).resolve()
    generated = root / ".codex-build-logs/table-style-lifetime"
    generated.mkdir(parents=True, exist_ok=True)
    path = "Ksword5.1/Ksword5.1/MainWindow.cpp"
    source = subprocess.check_output(["git", "show", f"{args.source_ref}:{path}"], cwd=root).decode("utf-8-sig") if args.source_ref else (root / path).read_text(encoding="utf-8-sig")
    proxy = block(source, "    class TableSelectionOutlineProxyStyle final") + ";"
    install = block(source, "            if (!tableView->property(kKswordTableSelectionOutlineStylePropertyName).toBool())")
    harness = r'''
#include <QApplication>
#include <QTableView>
#include <QProxyStyle>
#include <QStyleOptionViewItem>
#include <QPainter>
#include <QMenu>
#include <QWidgetAction>
#include <QSpinBox>
#include <QPointer>
#include <cstdio>
#include <cstdlib>
constexpr const char* kKswordTableSelectionOutlineStylePropertyName = "ksword_table_selection_outline_style";
''' + proxy + "\nstatic void install(QTableView* tableView) {\n" + install + "\n}\n" + r'''
static void check(bool ok, const char* message) {
    if (!ok) { std::fprintf(stderr, "TABLE_STYLE_LIFETIME_FAIL=%s\n", message); std::exit(1); }
}
int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QPointer<QProxyStyle> shared;
    int menusReleased = 0;
    for (int i = 0; i < 100; ++i) {
        // Exercise native inheritance and both palette/QSS repolishing paths.
        app.setStyleSheet(i % 3 == 0 ? QString() : i % 3 == 1
            ? "QWidget { color: black; background: white; }"
            : "QWidget { color: white; background: #202020; }");
        auto* table = new QTableView;
        install(table);
        install(table); // Installing twice must not allocate another proxy.
        int styles = 0;
        for (QObject* child : app.children()) {
            if (auto* style = dynamic_cast<TableSelectionOutlineProxyStyle*>(child)) {
                ++styles;
                check(shared.isNull() || shared.data() == style, "all tables share the application proxy");
                shared = style;
            }
        }
        check(styles == 1, "exactly one proxy owned by application");
        auto* menu = new QMenu(table);
        auto* action = new QWidgetAction(menu);
        action->setDefaultWidget(new QSpinBox);
        menu->addAction(action);
        QObject::connect(menu, &QObject::destroyed, [&]() {
            check(!shared.isNull(), "proxy survives embedded menu widget teardown");
            ++menusReleased;
        });
        table->show(); menu->show(); app.processEvents(); menu->hide();
        if (i % 2 == 0) { delete table; }
        else { table->deleteLater(); QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete); }
        app.processEvents();
        check(!shared.isNull(), "proxy survives table destruction");
    }
    check(menusReleased == 100, "all menus were actually destroyed");
    std::puts("TABLE_STYLE_LIFETIME_PASS cycles=100 themes=3 direct_and_deferred_delete");
}
'''
    cpp = generated / "TableStyleLifetimeTests.cpp"
    cpp.write_text(harness, encoding="utf-8")
    modules = ["QtWidgets", "QtGui", "QtCore"]
    if args.compiler:
        include = qt / "include/qt6"
        command = [args.compiler, "-std=c++20", "-O1", "-DNOMINMAX", "-I" + str(include)]
        command += ["-I" + str(include / module) for module in modules]
        exe = generated / "TableStyleLifetimeTests.exe"
        subprocess.run(command + [str(cpp), "-L" + str(qt / "lib")] + ["-l" + module.replace("Qt", "Qt6", 1) for module in modules] + ["-o", str(exe)], check=True)
    else:
        if not args.msbuild:
            parser.error("--msbuild is required unless --compiler is supplied")
        msbuild = Path(args.msbuild).resolve()
        assert msbuild.is_file() and msbuild.parent.name == "amd64", "HostX64 MSBuild is required"
        includes = ";".join(escape(str(qt / "include" / module)) for module in ["", *modules])
        project = f'''<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<ItemGroup Label="ProjectConfigurations"><ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration></ItemGroup>
<PropertyGroup Label="Globals"><ProjectGuid>{{03245E72-620A-48C4-9D23-9C1B3567F221}}</ProjectGuid><WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion></PropertyGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
<PropertyGroup Label="Configuration"><ConfigurationType>Application</ConfigurationType><PlatformToolset>v143</PlatformToolset><UseDebugLibraries>false</UseDebugLibraries></PropertyGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
<PropertyGroup><OutDir>$(ProjectDir)x64\\Release\\</OutDir><IntDir>$(ProjectDir)x64\\obj\\</IntDir></PropertyGroup>
<ItemDefinitionGroup><ClCompile><LanguageStandard>stdcpp20</LanguageStandard><RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary><PreprocessorDefinitions>NOMINMAX;UNICODE;_UNICODE;%(PreprocessorDefinitions)</PreprocessorDefinitions><AdditionalIncludeDirectories>{includes};%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories><AdditionalOptions>/utf-8 /Zc:__cplusplus %(AdditionalOptions)</AdditionalOptions></ClCompile><Link><AdditionalLibraryDirectories>{escape(str(qt / 'lib'))};%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories><AdditionalDependencies>Qt6Widgets.lib;Qt6Gui.lib;Qt6Core.lib;%(AdditionalDependencies)</AdditionalDependencies><SubSystem>Console</SubSystem></Link></ItemDefinitionGroup>
<ItemGroup><ClCompile Include="TableStyleLifetimeTests.cpp" /></ItemGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
</Project>'''
        project_path = generated / "TableStyleLifetimeTests.vcxproj"
        project_path.write_text(project, encoding="utf-8")
        (generated / "TableStyleLifetimeTests.vcxproj.filters").write_text('<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><ItemGroup><ClCompile Include="TableStyleLifetimeTests.cpp" /></ItemGroup></Project>', encoding="utf-8")
        subprocess.run([str(msbuild), str(project_path), "/t:Build", "/p:Configuration=Release", "/p:Platform=x64", "/p:PreferredToolArchitecture=x64", "/p:PROCESSOR_ARCHITECTURE=AMD64", "/p:PROCESSOR_ARCHITEW6432=AMD64", "/m:1", "/v:minimal", "/nologo"], check=True)
        exe = generated / "x64/Release/TableStyleLifetimeTests.exe"
    environment = os.environ.copy()
    environment["PATH"] = str(qt / "bin") + os.pathsep + environment.get("PATH", "")
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["QT_PLUGIN_PATH"] = str(qt / ("share/qt6/plugins" if args.compiler else "plugins"))
    subprocess.run([str(exe)], env=environment, check=True, timeout=60)


if __name__ == "__main__":
    main()
