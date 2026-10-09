"""Exercise the production manifest parser and directory promotion with Qt Core.

The generated harness uses the actual functions from PluginHost.cpp, including
its validation and rollback path. All generated files stay inside the repository.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
from xml.sax.saxutils import escape


def definition(source: str, kind: str, name: str) -> str:
    start = source.index(f"    {kind} {name}" + ("(" if kind == "bool" else "\n"))
    opening = source.index("{", start)
    depth = 0
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/|[{}]', re.S)
    for token in tokens.finditer(source, opening):
        value = token.group()
        if value == "{":
            depth += 1
        elif value == "}":
            depth -= 1
            if not depth:
                return source[start:token.end()] + (";" if kind == "struct" else "")
    raise ValueError(f"Unterminated production definition: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--msbuild", default=r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe")
    parser.add_argument("--qt-dir")
    parser.add_argument("--source-ref", help="Read PluginHost.cpp from a Git revision to check the regression")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    generated = root / ".codex-build-logs/plugin-install-layout"
    generated.mkdir(parents=True, exist_ok=True)
    qt = Path(args.qt_dir).resolve() if args.qt_dir else root / ".deps/Qt/6.9.3/msvc2022_64"
    assert (qt / "lib/Qt6Core.lib").is_file()
    msbuild = Path(args.msbuild).resolve()
    assert msbuild.is_file() and msbuild.parent.name == "amd64", "64-bit MSBuild is required"
    source = subprocess.check_output(["git", "show", args.source_ref + ":Ksword5.1/Ksword5.1/PluginHost.cpp"], cwd=root).decode("utf-8-sig") if args.source_ref else (root / "Ksword5.1/Ksword5.1/PluginHost.cpp").read_text(encoding="utf-8-sig")
    units = [definition(source, "struct", name) for name in [
        "VisualizationValueStyle", "VisualizationField", "PluginVisualization",
        "PluginTabPresentation", "PluginDescriptor", "MarketplacePlugin",
    ]]
    units += [definition(source, "bool", name) for name in [
        "isValidPluginId", "isSafeRelativePath", "isSafeCommandToken", "readRequiredString",
        "isValidProtocolName", "isAllowedVisualizationFormat", "isAllowedVisualizationTone",
        "parseVisualizationField", "parseVisualization", "parseTabPresentation",
        "loadPluginManifestDirectory", "loadPluginManifest", "promoteExtractedPlugin",
    ] if f"    bool {name}(" in source]
    constants = "\n".join(re.search(r"    constexpr[^;]+\b" + name + r"\b[^;]+;", source).group() for name in [
        "kMaxManifestBytes", "kMaxVisualizationColumns", "kMaxVisualizationSummaryItems",
    ])
    harness = r'''
#include <QtCore/QtCore>
#include <Windows.h>
#include "GhidraRuntimePlugin/RuntimeProfile.h"
// 抽取的 MarketplacePlugin 持有 UpstreamPlan；包含其真实声明，不能让夹具依赖传递包含。
#include "Ksword5.1/Ksword5.1/PluginHost.Distribution.h"
#include <cstdlib>
#include <iostream>
'''
    harness += constants + "\n\n" + "\n\n".join(units)
    harness += r'''
static void check(bool value, const char* name) {
    if (!value) { std::cerr << "FAIL " << name << std::endl; std::exit(1); }
    std::cout << "PASS " << name << std::endl;
}
static void put(const QString& path, const QByteArray& content) {
    check(QDir().mkpath(QFileInfo(path).absolutePath()), "create fixture parent");
    QFile file(path); check(file.open(QIODevice::WriteOnly), "open fixture");
    check(file.write(content) == content.size(), "write fixture");
}
static QByteArray bytes(const QString& path) {
    QFile file(path); if (!file.open(QIODevice::ReadOnly)) return {};
    return file.readAll();
}
static QJsonObject manifest(const QString& id) {
    return {{"ksword_plugin_api", "1"}, {"id", id}, {"name", "Installer fixture"},
        {"version", "2.0.0"}, {"description", "Production parser fixture"},
        {"runtime", "executable"}, {"entrypoint", "fixture.exe"},
        {"default_command", "info"}, {"targets", QJsonArray{"process"}}};
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const QString base = QDir::current().filePath(
        ".codex-build-logs/plugin-install-layout/cases-" + QUuid::createUuid().toString(QUuid::WithoutBraces));
    const MarketplacePlugin plugin{.id="x96dbg", .installDirectory="x96dbg"};
    for (const bool wrapped : {false, true}) {
        for (const bool update : {false, true}) {
            const QString root = base + (wrapped ? "/wrapped" : "/root") + (update ? "-update" : "-new");
            const QString stage = root + "/.stage";
            const QString content = wrapped ? stage + "/x96dbg" : stage;
            put(content + "/plugin.json", QJsonDocument(manifest("x96dbg")).toJson());
            put(content + "/fixture.exe", "new-entry");
            put(content + "/payload/subdir/probe.bin", "nested-payload");
            if (update) put(root + "/x96dbg/old.txt", "previous-installed");
            QString error;
            check(promoteExtractedPlugin(plugin, root, stage, &error), wrapped ? "wrapped archive promotes" : "root archive promotes");
            check(bytes(root + "/x96dbg/fixture.exe") == "new-entry", "installed entry retained");
            check(bytes(root + "/x96dbg/payload/subdir/probe.bin") == "nested-payload", "nested payload retained");
            check(!QFileInfo::exists(root + "/x96dbg/old.txt"), "upgrade replaced old directory");
        }
    }
    for (const int fault : {0, 1, 2, 3}) {
        const QString root = base + "/invalid-" + QString::number(fault);
        const QString stage = root + "/.stage";
        put(root + "/x96dbg/old.txt", "previous-installed");
        if (fault == 0) put(stage + "/plugin.json", QJsonDocument(manifest("wrong-id")).toJson());
        if (fault == 1) put(stage + "/plugin.json", QByteArray(65537, ' '));
        if (fault == 2) put(stage + "/plugin.json", QJsonDocument(manifest("x96dbg")).toJson());
        if (fault != 2) put(stage + "/fixture.exe", "new-entry");
        QString error;
        check(!promoteExtractedPlugin(plugin, root, stage, &error), "invalid archive rejected");
        check(!error.isEmpty(), "rejection provides diagnostic");
        check(bytes(root + "/x96dbg/old.txt") == "previous-installed", "rejection preserves installed plugin");
    }
    // 缺少运行载荷的 Ghidra 元数据包必须经过生产校验器拒绝，不能覆盖旧安装。
    const QString ghidraRoot = base + "/invalid-ghidra"; // 本用例独占的插件根目录。
    const QString ghidraStage = ghidraRoot + "/.stage"; // 仅包含规范元数据的暂存目录。
    const MarketplacePlugin ghidraPlugin{.id="ghidra", .installDirectory="ghidra"}; // 待验证的后端插件身份。
    put(ghidraRoot + "/ghidra/old.txt", "previous-installed");
    check(QDir().mkpath(ghidraStage), "create Ghidra fixture stage");
    QString ghidraError; // 保留生产校验器返回的具体失败原因。
    check(ks::plugin_host::ghidra_runtime::writePackageMetadata(ghidraStage, &ghidraError),
        "write canonical Ghidra metadata");
    check(!promoteExtractedPlugin(ghidraPlugin, ghidraRoot, ghidraStage, &ghidraError),
        "Ghidra metadata without runtime payload rejected");
    // 具体错误码证明本用例实际进入生产载荷检查，而非假成功实现或普通清单分支。
    check(ghidraError.startsWith("runtime_payload_missing:"), "Ghidra production validator reports missing payload");
    check(bytes(ghidraRoot + "/ghidra/old.txt") == "previous-installed",
        "Ghidra rejection preserves installed plugin");
    std::cout << "PLUGIN_INSTALL_LAYOUT_PASS cases=9" << std::endl;
}
'''
    (generated / "PluginInstallLayoutTests.cpp").write_text(harness, encoding="utf-8")
    project = f'''<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<ItemGroup Label="ProjectConfigurations"><ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration></ItemGroup>
<PropertyGroup Label="Globals"><ProjectGuid>{{7B58E4D9-FD5E-45C4-AD1B-078640D013DA}}</ProjectGuid><WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion></PropertyGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
<PropertyGroup Label="Configuration"><ConfigurationType>Application</ConfigurationType><PlatformToolset>v143</PlatformToolset><UseDebugLibraries>false</UseDebugLibraries></PropertyGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
<PropertyGroup><OutDir>$(ProjectDir)x64\\Release\\</OutDir><IntDir>$(ProjectDir)x64\\obj\\</IntDir></PropertyGroup>
<ItemDefinitionGroup><ClCompile><LanguageStandard>stdcpp20</LanguageStandard><RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary><PreprocessorDefinitions>NOMINMAX;UNICODE;_UNICODE;%(PreprocessorDefinitions)</PreprocessorDefinitions><AdditionalIncludeDirectories>{escape(str(root))};{escape(str(qt / 'include'))};{escape(str(qt / 'include/QtCore'))};%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories><AdditionalOptions>/utf-8 /Zc:__cplusplus %(AdditionalOptions)</AdditionalOptions></ClCompile><Link><AdditionalLibraryDirectories>{escape(str(qt / 'lib'))};%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories><AdditionalDependencies>Qt6Core.lib;%(AdditionalDependencies)</AdditionalDependencies><SubSystem>Console</SubSystem></Link></ItemDefinitionGroup>
<ItemGroup><ClCompile Include="PluginInstallLayoutTests.cpp" /><ClCompile Include="{escape(str(root / 'GhidraRuntimePlugin/RuntimeProfile.cpp'))}" /></ItemGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
</Project>'''
    project_path = generated / "PluginInstallLayoutTests.vcxproj"
    project_path.write_text(project, encoding="utf-8")
    # 直接编译生产运行时校验模块；工程与 filters 同步引用，避免夹具丢失命名空间依赖。
    (generated / "PluginInstallLayoutTests.vcxproj.filters").write_text(
        '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><ItemGroup>'
        '<ClCompile Include="PluginInstallLayoutTests.cpp" />'
        f'<ClCompile Include="{escape(str(root / "GhidraRuntimePlugin/RuntimeProfile.cpp"))}" />'
        '</ItemGroup></Project>\n', encoding="utf-8")
    subprocess.run([str(msbuild), str(project_path), "/t:Build", "/p:Configuration=Release", "/p:Platform=x64",
        "/p:PreferredToolArchitecture=x64", "/p:PROCESSOR_ARCHITECTURE=AMD64",
        "/p:PROCESSOR_ARCHITEW6432=AMD64", "/m:1", "/v:minimal", "/nologo"], cwd=root, check=True)
    environment = os.environ.copy()
    environment["PATH"] = str(qt / "bin") + os.pathsep + environment.get("PATH", "")
    subprocess.run([str(generated / "x64/Release/PluginInstallLayoutTests.exe")], cwd=root, env=environment, check=True)


if __name__ == "__main__":
    main()
