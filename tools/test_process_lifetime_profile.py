"""Build and run the non-GUI production lifetime-profile preparation regression.

The resulting executable also supports --prepare-live with a separate VM guard.
Only the IOCTL transport is replaced in offline mode; production serializers,
profile matching, EX projection and readiness readback are compiled unchanged.
"""
from pathlib import Path
import os
import shutil
import subprocess
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]


def main():
    qt = ROOT / ".deps/Qt/6.9.3/msvc2022_64"
    if not (qt / "lib/Qt6Core.lib").is_file():
        qt = Path(r"D:\Software\Qt\6.9.3\msvc2022_64")
    msbuild = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe")
    if not msbuild.is_file():
        msbuild = Path(r"D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe")
    assert msbuild.is_file() and msbuild.parent.name == "amd64"
    generated = ROOT / ".codex-build-logs/process-lifetime-profile"
    generated.mkdir(parents=True, exist_ok=True)
    sources = ["tools/tests/process_lifetime_profile_prepare.cpp"] + [
        f"Ksword5.1/Ksword5.1/ArkDriverClient/{name}.cpp" for name in
        ("ArkLocalDynDataProfile", "ArkProcessLifetimeProfile", "ArkDriverDynData")
    ] + ["Ksword5.1/Ksword5.1/ksword/profile/ProfileJsonLoader.cpp"]
    items = "".join(f'<ClCompile Include="{escape(str(ROOT / path))}" />' for path in sources)
    project = fr'''<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<ItemGroup Label="ProjectConfigurations"><ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration></ItemGroup>
<PropertyGroup Label="Globals"><ProjectGuid>{{06693F8B-6585-4BF3-8DD3-5D385CA218DC}}</ProjectGuid><WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion></PropertyGroup>
<Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
<PropertyGroup Label="Configuration"><ConfigurationType>Application</ConfigurationType><PlatformToolset>v143</PlatformToolset><UseDebugLibraries>false</UseDebugLibraries></PropertyGroup>
<Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
<PropertyGroup><OutDir>$(ProjectDir)x64\Release\</OutDir><IntDir>$(ProjectDir)x64\obj\</IntDir><TargetName>ProcessLifetimePrepareTests</TargetName></PropertyGroup>
<ItemDefinitionGroup><ClCompile><LanguageStandard>stdcpp20</LanguageStandard><RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary><WarningLevel>Level4</WarningLevel><TreatWarningAsError>true</TreatWarningAsError><PreprocessorDefinitions>NOMINMAX;UNICODE;_UNICODE;%(PreprocessorDefinitions)</PreprocessorDefinitions><AdditionalIncludeDirectories>{escape(str(ROOT))};{escape(str(qt/'include'))};{escape(str(qt/'include/QtCore'))};%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories><AdditionalOptions>/utf-8 /Zc:__cplusplus %(AdditionalOptions)</AdditionalOptions></ClCompile><Link><AdditionalLibraryDirectories>{escape(str(qt/'lib'))};%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories><AdditionalDependencies>Qt6Core.lib;advapi32.lib;%(AdditionalDependencies)</AdditionalDependencies></Link></ItemDefinitionGroup>
<ItemGroup>{items}</ItemGroup><Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" /></Project>'''
    path = generated / "ProcessLifetimePrepareTests.vcxproj"
    path.write_text(project, encoding="utf-8")
    subprocess.run([str(msbuild), str(path), "/t:Build", "/p:Configuration=Release", "/p:Platform=x64",
                    "/p:PreferredToolArchitecture=x64", "/p:PROCESSOR_ARCHITECTURE=AMD64",
                    "/p:PROCESSOR_ARCHITEW6432=AMD64", "/m:1", "/v:minimal", "/nologo"], check=True)
    destination = generated / "x64/Release"
    shutil.copy2(qt / "bin/Qt6Core.dll", destination / "Qt6Core.dll")
    for runtime in (ROOT / "Ksword5.1/x64/Release").glob("*140*.dll"):
        shutil.copy2(runtime, destination / runtime.name)
    subprocess.run([str(destination / "ProcessLifetimePrepareTests.exe"),
                    str(ROOT / "Ksword5.1/x64/Release/profiles/ark_dyndata_pack_v4.json.qz")], check=True)


if __name__ == "__main__":
    main()
