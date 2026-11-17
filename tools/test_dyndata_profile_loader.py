"""Compile the production Qt v4 loader and test the release pack without IOCTLs."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import shutil
from xml.sax.saxutils import escape

from test_plugin_install_layout import definition


def function(source: str, kind: str, name: str) -> str:
    # Reuse the existing string/comment-aware brace scanner for void helpers.
    signature = f"    {kind} {name}("
    start = source.index(signature)
    tail = source[start:].replace(signature, f"    bool {name}(", 1)
    return definition(tail, "bool", name).replace(f"bool {name}(", f"{kind} {name}(", 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qt-dir")
    parser.add_argument("--msbuild")
    parser.add_argument("--pack", default="Ksword5.1/x64/Release/profiles/ark_dyndata_pack_v4.json.qz")
    parser.add_argument("--source-ref", help="Use a Git revision to demonstrate the old loader failure")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source_path = ("Ksword5.1/Ksword5.1/KernelDock/KernelDock.DynData.cpp" if args.source_ref
                   else "Ksword5.1/Ksword5.1/ArkDriverClient/ArkLocalDynDataProfile.cpp")
    source = (subprocess.check_output(["git", "show", f"{args.source_ref}:{source_path}"], cwd=root).decode("utf-8-sig")
              if args.source_ref else (root / source_path).read_text(encoding="utf-8-sig"))
    type_source = source if args.source_ref else (root / "Ksword5.1/Ksword5.1/ArkDriverClient/ArkLocalDynDataProfile.h").read_text(encoding="utf-8-sig")
    units = [definition(type_source, "struct", "LocalPdbProfile")]
    units.extend(definition(source, "bool", name) for name in
                 ("fieldIdIsCallbackGlobal", "fieldIdIsCallbackOffset"))
    units.append(function(source, "void", "appendProfileExItem"))
    # Skip the earlier forward declaration; extract the actual numeric parser.
    units.append(definition(source[source.index("// parseProfileUInt32："):], "bool", "parseProfileUInt32"))
    units.extend("template <std::size_t Size>\n" + function(source, "void", name)
                 for name in ("copyV4Utf8", "copyV4Wide"))
    units.extend(definition(source, "bool", name) for name in ("v4ItemIdSupported", "loadV4ItemsFromJson"))
    harness = r'''
#include <Windows.h>
#include <QtCore/QtCore>
#include "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverTypes.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <unordered_map>
#include <iostream>
QString kernelText(const char*, const QString& fallback) { return fallback; }
'''+"\n".join(units)+r'''
void check(bool ok, const char* message) {
    if (!ok) { std::cerr << message << std::endl; std::exit(2); }
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QFile file(app.arguments().at(1));
    check(file.open(QIODevice::ReadOnly), "pack open failed");
    const auto document = QJsonDocument::fromJson(qUncompress(file.readAll()));
    const auto profiles = document.object().value("profiles").toArray();
    check(!profiles.isEmpty(), "pack empty");
    std::size_t count = 0;
    QJsonObject current;
    for (const auto& value : profiles) {
        const auto entry = value.toObject();
        ksword::ark::ArkDynModuleIdentity identity{};
        identity.present = true;
        identity.classId = entry.value("moduleClassId").toInt();
        identity.machine = entry.value("machine").toInt();
        identity.timeDateStamp = static_cast<std::uint32_t>(entry.value("timeDateStamp").toDouble());
        identity.sizeOfImage = entry.value("sizeOfImage").toInt();
        LocalPdbProfile profile;
        QStringList diagnostics;
        const auto items = entry.value("items").toArray();
        check(loadV4ItemsFromJson(items, entry.value("capabilityGroups").toArray(), identity,
              entry.value("profileName").toString(), entry.value("pdbName").toString(),
              entry.value("pdbGuid").toString(), entry.value("pdbAge").toInt(), profile, diagnostics),
              qPrintable(entry.value("profileName").toString()+": "+diagnostics.join(" | ")));
        check(profile.applyV4Input.items.size() == static_cast<std::size_t>(items.size()), "V4 item lost");
        const auto expectedEx = std::count_if(profile.applyV4Input.items.begin(), profile.applyV4Input.items.end(),
            [](const auto& item) { return item.itemId <= KSW_DYN_FIELD_ID_MAX &&
                (item.itemKind == 1 || item.itemKind == 2 || item.itemKind == 5 || item.itemKind == 7); });
        check(profile.applyExInput.items.size() == static_cast<std::size_t>(expectedEx), "EX projection lost");
        if (identity.classId == 0 && identity.timeDateStamp == 0xCD28AC68U && identity.sizeOfImage == 0x01045000U) {
            current = entry;
            check(profile.applyV4Input.items.size() == 248U, "current profile must contain 23 additional items");
            for (const auto id : {3UL,4UL,5UL,6UL,7UL,18UL,19UL,20UL,21UL,22UL,23UL,24UL,25UL,26UL,27UL,28UL,29UL,30UL,31UL,32UL,33UL,42UL,43UL}) {
                check(std::any_of(profile.applyExInput.items.begin(), profile.applyExInput.items.end(),
                    [id](const auto& item) { return item.itemId == id; }), "additional field absent from EX projection");
            }
        }
        ++count;
    }
    check(!current.isEmpty(), "current exact profile missing");
    auto rejects = [&](QJsonArray items, QJsonArray groups) {
        LocalPdbProfile result; QStringList messages; ksword::ark::ArkDynModuleIdentity identity{};
        return !loadV4ItemsFromJson(items, groups, identity, {}, {}, {}, 1, result, messages);
    };
    auto items = current.value("items").toArray();
    const auto groups = current.value("capabilityGroups").toArray();
    auto bad = items; auto item = bad.at(0).toObject(); item["itemId"] = 1402; bad[0] = item;
    check(rejects(bad, groups), "unknown ID must reject");
    bad = items; bad[1] = bad[0]; check(rejects(bad, groups), "duplicate ID must reject");
    bad = items; item = bad.at(0).toObject(); item["valueLow"] = -1; bad[0] = item;
    check(rejects(bad, groups), "invalid uint32 must reject");
    auto badGroups = groups; auto group = badGroups.at(0).toObject();
    group["requiredItemCount"] = 0; badGroups[0] = group;
    check(rejects(items, badGroups), "incorrect group count must reject");
    std::cout << "DYNDATA_QT_LOADER_PASS profiles=" << count << " negative_cases=4 current_items=248" << std::endl;
}
'''
    generated = root / ".codex-build-logs/dyndata-profile-loader"
    generated.mkdir(parents=True, exist_ok=True)
    (generated / "DynDataProfileLoaderTests.cpp").write_text(harness, encoding="utf-8")
    bundled_qt = root / ".deps/Qt/6.9.3/msvc2022_64"
    qt = Path(args.qt_dir).resolve() if args.qt_dir else (bundled_qt if (bundled_qt / "lib/Qt6Core.lib").is_file()
        else Path(r"D:\Software\Qt\6.9.3\msvc2022_64"))
    preferred_msbuild = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe")
    msbuild = Path(args.msbuild).resolve() if args.msbuild else (preferred_msbuild if preferred_msbuild.is_file()
        else Path(r"D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe"))
    assert msbuild.parent.name == "amd64" and msbuild.is_file()
    project = fr'''<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<ItemGroup Label="ProjectConfigurations"><ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration></ItemGroup>
<PropertyGroup Label="Globals"><ProjectGuid>{{95CEE36B-086D-4483-A924-9B8D5B745637}}</ProjectGuid><WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion></PropertyGroup>
<Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
<PropertyGroup Label="Configuration"><ConfigurationType>Application</ConfigurationType><PlatformToolset>v143</PlatformToolset><UseDebugLibraries>false</UseDebugLibraries></PropertyGroup>
<Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
<PropertyGroup><OutDir>$(ProjectDir)x64\Release\</OutDir><IntDir>$(ProjectDir)x64\obj\</IntDir></PropertyGroup>
<ItemDefinitionGroup><ClCompile><LanguageStandard>stdcpp20</LanguageStandard><RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary><PreprocessorDefinitions>NOMINMAX;UNICODE;_UNICODE;%(PreprocessorDefinitions)</PreprocessorDefinitions><AdditionalIncludeDirectories>{escape(str(root))};{escape(str(qt/'include'))};{escape(str(qt/'include/QtCore'))};%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories><AdditionalOptions>/utf-8 /Zc:__cplusplus %(AdditionalOptions)</AdditionalOptions></ClCompile><Link><AdditionalLibraryDirectories>{escape(str(qt/'lib'))};%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories><AdditionalDependencies>Qt6Core.lib;%(AdditionalDependencies)</AdditionalDependencies></Link></ItemDefinitionGroup>
<ItemGroup><ClCompile Include="DynDataProfileLoaderTests.cpp" /></ItemGroup>
<Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" /></Project>'''
    project_path = generated / "DynDataProfileLoaderTests.vcxproj"
    project_path.write_text(project, encoding="utf-8")
    (generated / "DynDataProfileLoaderTests.vcxproj.filters").write_text(
        '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><ItemGroup>'
        '<ClCompile Include="DynDataProfileLoaderTests.cpp" /></ItemGroup></Project>', encoding="utf-8")
    subprocess.run([str(msbuild), str(project_path), "/t:Build", "/p:Configuration=Release", "/p:Platform=x64",
                    "/p:PreferredToolArchitecture=x64", "/p:PROCESSOR_ARCHITECTURE=AMD64",
                    "/p:PROCESSOR_ARCHITEW6432=AMD64", "/m:1", "/v:minimal", "/nologo"], check=True)
    # Deploy only the Core and compiler runtimes into this standalone fixture.
    # Some host process launch policies do not search added PATH directories.
    destination = generated / "x64/Release"
    shutil.copy2(qt / "bin/Qt6Core.dll", destination / "Qt6Core.dll")
    for runtime in (root / "Ksword5.1/x64/Release").glob("*140*.dll"):
        shutil.copy2(runtime, destination / runtime.name)
    environment = os.environ.copy()
    environment["PATH"] = str(qt / "bin") + os.pathsep + str(root / "Ksword5.1/x64/Release") + os.pathsep + environment.get("PATH", "")
    subprocess.run([str(generated / "x64/Release/DynDataProfileLoaderTests.exe"),
                    str((root / args.pack).resolve())],
                   cwd=root, env=environment, check=True)


if __name__ == "__main__":
    main()
