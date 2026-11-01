"""Compile production capture/replay/tree methods against deterministic historical samples."""
from pathlib import Path
import argparse
import os
import subprocess


def declaration(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qt", type=Path, default=Path("D:/Software/Qt/6.9.3/msvc2022_64"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = root / ".codex-build-logs/process-activity-tree-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = (root / "Ksword5.1/Ksword5.1/ProcessDock/ProcessDock.cpp").read_text(encoding="utf-8-sig")
    header = (root / "Ksword5.1/Ksword5.1/ProcessDock/ProcessDock.h").read_text(encoding="utf-8-sig")
    types = "\n".join(declaration(header, signature) + ";" for signature in (
        "    enum class TableColumn", "    enum class ProcessTableRowKind", "    enum class FriendlyProcessGroupType",
        "    struct DisplayRow", "    struct CacheEntry", "    struct ProcessActivityProcessPoint", "    struct ProcessActivitySample"))
    methods = "\n".join(declaration(source, signature).replace("ProcessDock::", "") for signature in (
        "template <typename Destination, typename Source>\nvoid ProcessDock::copyProcessActivityDynamicFields",
        "void ProcessDock::captureProcessActivityParentIdentities",
        "bool ProcessDock::isProcessActivitySnapshotProjectionCurrent() const",
        "void ProcessDock::rebuildProcessActivityTableSnapshotRecords()",
        "std::vector<ProcessDock::DisplayRow> ProcessDock::buildProcessTreeDisplayOrder(",
        "std::vector<ProcessDock::DisplayRow> ProcessDock::buildActivitySnapshotDisplayOrder() const",
        "const std::unordered_map<std::string, ProcessDock::CacheEntry>& ProcessDock::displayProcessCache() const",
        "QSet<std::uint32_t> ProcessDock::displayVisibleWindowPidSet() const",
        "std::uint32_t ProcessDock::displayParentPid(",
        "std::vector<ProcessDock::DisplayRow> ProcessDock::buildListDisplayOrder() const",
        "std::vector<ProcessDock::DisplayRow> ProcessDock::buildTreeDisplayOrder() const",
        "std::vector<ProcessDock::DisplayRow> ProcessDock::buildFriendlyDisplayOrder() const",
        "std::uint32_t ProcessDock::findFriendlyApplicationRootPid(",
        "bool ProcessDock::isFriendlyWindowsSystemProcess(",
        "QString ProcessDock::friendlyGroupTitle(",
        "QString ProcessDock::friendlyExpansionKeyForGroup(",
        "QString ProcessDock::friendlyExpansionKeyForApplication(",
        "ks::process::ProcessRecord ProcessDock::aggregateFriendlyApplicationRecord("))
    methods = methods.replace("std::vector<DisplayRow> buildProcessTreeDisplayOrder(",
                              "static std::vector<DisplayRow> buildProcessTreeDisplayOrder(")
    for signature in ("std::uint32_t findFriendlyApplicationRootPid(", "bool isFriendlyWindowsSystemProcess(",
                      "QString friendlyGroupTitle(", "QString friendlyExpansionKeyForGroup(",
                      "QString friendlyExpansionKeyForApplication(", "ks::process::ProcessRecord aggregateFriendlyApplicationRecord("):
        methods = methods.replace(signature, "static " + signature)
    fixture = Path(__file__).with_suffix(".cpp").read_text(encoding="utf-8")
    fixture = fixture.replace("__TYPES__", types).replace("__METHODS__", methods)
    process_source = (root / "Ksword5.1/Ksword5.1/ksword/process/process.cpp").read_text(encoding="utf-8-sig")
    fixture = fixture.replace("__IDENTITY__", declaration(process_source, "std::string BuildProcessIdentityKey("))
    fixture = fixture.replace("__PROCESS_HEADER__", (root / "Ksword5.1/Ksword5.1/ksword/process/process.h").as_posix())
    cpp, exe = output / "fixture.cpp", output / "fixture.exe"
    cpp.write_text(fixture, encoding="utf-8")
    developer = next(path for path in (
        Path("D:/Software/VS/Common7/Tools/VsDevCmd.bat"),
        Path("C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/Tools/VsDevCmd.bat")) if path.exists())
    command = ["cl.exe", "/nologo", "/std:c++20", "/Zc:__cplusplus", "/utf-8", "/EHsc", "/MD", "/W4", "/WX", "/O2",
               "/DNOMINMAX", "/DWIN32_LEAN_AND_MEAN", "/external:W0",
               "/external:I" + str(args.qt / "include"), "/external:I" + str(args.qt / "include/QtCore"),
               str(cpp), "/Fo" + str(output / "fixture.obj"), "/Fe" + str(exe), "/link",
               "/LIBPATH:" + str(args.qt / "lib"), "Qt6Core.lib"]
    build = output / "build.cmd"
    build.write_text('@echo off\ncall "' + str(developer) + '" -arch=x64 -host_arch=x64 >nul\n'
                     + subprocess.list2cmdline(command) + '\nexit /b %errorlevel%\n', encoding="utf-8")
    subprocess.run(["cmd.exe", "/d", "/c", str(build)], check=True, cwd=output)
    environment = dict(os.environ)
    environment["PATH"] = str(args.qt / "bin") + os.pathsep + environment.get("PATH", "")
    subprocess.run([str(exe)], check=True, env=environment)
    append = declaration(source, "void ProcessDock::appendProcessActivitySample()")
    assert "processPoint.parentPid = processRecord.parentPid;" in append
    assert append.index("captureProcessActivityParentIdentities(sample);") < append.index("m_activitySamples.push_back")
    for signature in ("connect(m_friendlyViewCheck,", "connect(m_viewModeCombo,"):
        handler = declaration(source, signature)
        assert "m_activityTableSnapshotActive = false" not in handler
    print("PASS: production sampling and view-switch wiring")


if __name__ == "__main__":
    main()
