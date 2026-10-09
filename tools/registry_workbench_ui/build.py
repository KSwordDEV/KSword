"""Compile actual RegistryDock UI with bounded in-memory registry transports.

The staged production sources are byte-for-byte copies. Only Framework,
DriverClient, optimizer, document/permissions transports and table-menu commit
coordination are replaced; editor, HexView, FlowLayout and Dock logic are real.
"""
from pathlib import Path
import argparse
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor,as_completed


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qt",required=True,type=Path)
    parser.add_argument("--compiler",required=True,type=Path)
    args=parser.parse_args()
    repo=Path(__file__).resolve().parents[2]
    fixture=Path(__file__).resolve().parent
    out=repo/".codex-tmp"/"registry-workbench-ui"
    stage=out/"app"
    app=repo/"Ksword5.1"/"Ksword5.1"
    out.mkdir(parents=True,exist_ok=True)
    # Include paths in copied UI sources resolve exactly as in production.
    for folder in ("RegistryDock","UI","Internationalization"):
        for source in (app/folder).rglob("*.h"):
            target=stage/source.relative_to(app)
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target)
    shutil.copy2(app/"theme.h",stage/"theme.h")
    shutil.copy2(fixture/"Framework.mock.h",stage/"Framework.h")
    privilege=stage/"Framework"/"PrivilegeElevationPrompt.h"
    privilege.parent.mkdir(parents=True,exist_ok=True)
    privilege.write_text('#pragma once\n#include <QWidget>\n#include <QString>\nnamespace ks::ui { inline bool promptForPrivilegeFailure(QWidget*,const QString&,const QString&){return false;} }\n',encoding="utf-8")
    driver=stage/"ArkDriverClient"/"ArkDriverClient.h"
    driver.parent.mkdir(parents=True,exist_ok=True)
    protocol=(repo/"shared"/"driver"/"KswordArkRegistryIoctl.h").as_posix()
    driver.write_text('#include "'+protocol+'"\n'+(fixture/"Driver.mock.h").read_text(encoding="utf-8"),encoding="utf-8")
    candidates=[app/"RegistryDock_Themed.cpp",app/"RegistryDock"/"RegistryDock.Workbench.cpp",app/"RegistryDock"/"RegistryDock.Search.cpp",app/"RegistryDock"/"RegistryDock.Documents.cpp",
        app/"RegistryDock"/"RegistryDock.Mutations.cpp",app/"RegistryDock"/"RegistryDocumentApply.cpp",
        app/"RegistryDock"/"RegistryDocumentApply.Access.cpp",app/"RegistryDock"/"RegistryValueTransactions.cpp"]
    sources=[]
    for source in candidates:
        if source.exists():
            target=stage/source.relative_to(app)
            shutil.copy2(source,target)
            sources.append(target)
    sources += [app/"UI"/"FlowLayout.cpp",fixture/"registry_workbench_mocks.cpp",fixture/"registry_workbench_ui_tests.cpp"]
    qt=args.qt.resolve();compiler=args.compiler.resolve();env=os.environ.copy()
    env["PATH"]=str(compiler.parent)+os.pathsep+str(qt/"bin")+os.pathsep+env.get("PATH","")
    env["QT_QPA_PLATFORM"]="offscreen";env["QT_PLUGIN_PATH"]=str(qt/"plugins")
    generated=out/"moc_RegistryDock.cpp"
    subprocess.run([str(qt/"bin"/"moc.exe"),str(stage/"RegistryDock"/"RegistryDock.h"),"-o",str(generated)],env=env,check=True)
    sources.append(generated)
    aliases={"file_nav_back.svg","file_nav_forward.svg","process_refresh.svg","process_start.svg","process_pause.svg","process_open_folder.svg","process_details.svg","process_priority.svg","process_terminate.svg","reg_import.svg","log_export.svg"}
    icons=ET.Element("RCC");resource=ET.SubElement(icons,"qresource",prefix="/Icon")
    for entry in ET.parse(app/"Ksword5.qrc").iter("file"):
        if entry.get("alias") in aliases:
            ET.SubElement(resource,"file",alias=entry.get("alias")).text=(app/entry.text).as_posix()
    qrc=out/"registry_icons.qrc";ET.ElementTree(icons).write(qrc,encoding="utf-8")
    generatedIcons=out/"qrc_registry_icons.cpp"
    subprocess.run([str(qt/"bin"/"rcc.exe"),str(qrc),"-name","registry_icons","-o",str(generatedIcons)],env=env,check=True)
    sources.append(generatedIcons)
    flags=["-std=c++23","-O0","-g0","-Wall","-Wextra","-DWIN32_LEAN_AND_MEAN","-DNOMINMAX","-DUNICODE","-D_UNICODE","-I"+str(stage),"-I"+str(fixture)]
    for module in ("","QtCore","QtGui","QtWidgets"):flags += ["-isystem",str(qt/"include"/module)]
    def compile_one(source):
        obj=out/(source.stem+".o")
        result=subprocess.run([str(compiler),*flags,"-c",str(source),"-o",str(obj)],env=env,capture_output=True,text=True,errors="replace")
        if result.returncode:
            print(result.stdout+result.stderr,flush=True)
            raise RuntimeError("Compile failed: "+source.name)
        if result.stderr:print(result.stderr,flush=True)
        print("COMPILED "+source.name,flush=True)
        return obj
    objects=[]
    with ThreadPoolExecutor(max_workers=3) as pool:
        for future in as_completed([pool.submit(compile_one,source) for source in sources]):objects.append(future.result())
    cache=repo/".codex-tmp"/"registry-value-editor-tests"
    # All cached production Hex objects were built by the editor fixture against
    # this exact SDK; only that fixture's main and advanced dialog are excluded.
    excluded={"registry_value_editor_tests","RegistryAdvancedDialogs","editor-check","editor","advanced"}
    for obj in cache.glob("*.o"):
        if obj.stem not in excluded:objects.append(obj)
    exe=out/"registry_workbench_ui_tests.exe"
    shutil.copytree(app/"languages",out/"languages",dirs_exist_ok=True)
    subprocess.run([str(compiler),*map(str,objects),"-L"+str(qt/"lib"),"-lQt6Widgets","-lQt6Gui","-lQt6Core","-ladvapi32","-luser32","-lshell32","-o",str(exe)],env=env,check=True)
    return subprocess.run([str(exe),str(out/"shots")],env=env).returncode


if __name__=="__main__":raise SystemExit(main())
