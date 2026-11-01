"""Build and exercise the actual treemap canvas; no process actions or clipboard writes."""
from pathlib import Path
import os
import subprocess
import argparse
from process_activity_tree_tests import declaration

def main():
    parser=argparse.ArgumentParser()
    qt_default=Path(__file__).resolve().parents[1]/'.deps/Qt/6.9.3/msvc2022_64'
    if not qt_default.is_dir():qt_default=Path('D:/Software/Qt/6.9.3/msvc2022_64')
    parser.add_argument('--qt',type=Path,default=qt_default)
    args=parser.parse_args();args.qt=args.qt.resolve();root=Path(__file__).resolve().parents[1]
    output=root/'.codex-build-logs/metric-area-tests';output.mkdir(parents=True,exist_ok=True)
    developer=next(p for p in [Path('D:/Software/VS/Common7/Tools/VsDevCmd.bat'),Path('C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/Tools/VsDevCmd.bat')] if p.exists())
    command=['cl.exe','/nologo','/std:c++20','/Zc:__cplusplus','/utf-8','/EHsc','/MD','/W4','/WX','/O2','/DNOMINMAX','/DWIN32_LEAN_AND_MEAN','/external:W0']
    command+=['/external:I'+str(args.qt/'include'/p) for p in ['','QtCore','QtGui','QtWidgets','QtTest']]
    command+=['/DQT_WIDGETS_LIB','/DQT_GUI_LIB','/DQT_CORE_LIB','/DQT_TESTLIB_LIB']
    source=(root/'Ksword5.1/Ksword5.1/ProcessDock/ProcessDock.cpp').read_text(encoding='utf-8-sig')
    area=(root/'Ksword5.1/Ksword5.1/ProcessDock/ProcessDock.MetricArea.cpp').read_text(encoding='utf-8-sig')
    header=(root/'Ksword5.1/Ksword5.1/ProcessDock/ProcessDock.h').read_text(encoding='utf-8-sig')
    probe='struct MetricProbe { '+declaration(header,'    enum class TableColumn')+';\n'
    probe+='static QVariant processNumericSortValue(const ks::process::ProcessRecord&,TableColumn){return 0.0;}\n'
    probe+='static '+declaration(source,'bool ProcessDock::processUsageHighlightValue(').replace('ProcessDock::','')+'\n'
    probe+='static '+declaration(area,'bool ProcessDock::isMetricAreaColumn(').replace('ProcessDock::','')+'\n};'
    probe=probe[:-2]+'static '+declaration(area,'bool ProcessDock::metricAreaIncludesProcess(').replace('ProcessDock::','')+'\n};'
    probe=probe[:-2]+'static '+declaration(area,'double ProcessDock::metricAreaNetworkValue(').replace('ProcessDock::','')+'\n};'
    fixture=output/'fixture.cpp'
    fixture.write_text('#include <Windows.h>\n#include "../Ksword5.1/Ksword5.1/ksword/process/process.h"\n'+(root/'tools/metric_area_tests.cpp').read_text(encoding='utf-8').replace('__METRIC_PROBE__',probe),encoding='utf-8')
    command+=['/I'+str(root/'tools'),str(fixture),str(root/'Ksword5.1/Ksword5.1/UI/MetricAreaCanvas.cpp'),str(root/'Ksword5.1/Ksword5.1/UI/MetricAreaWindow.cpp'),str(root/'Ksword5.1/Ksword5.1/Internationalization/LanguageManager.cpp'),'/Fo'+str(output)+'\\','/Fe'+str(output/'test.exe'),'/link','/LIBPATH:'+str(args.qt/'lib'),'Qt6Core.lib','Qt6Gui.lib','Qt6Widgets.lib','Qt6Test.lib','user32.lib','advapi32.lib']
    build=output/'build.cmd';build.write_text('@echo off\ncall "'+str(developer)+'" -arch=x64 -host_arch=x64 >nul\n'+subprocess.list2cmdline(command)+'\nexit /b %errorlevel%\n',encoding='utf-8')
    subprocess.run(['cmd.exe','/d','/c',str(build)],cwd=output,check=True)
    environment=dict(os.environ);environment['PATH']=str(args.qt/'bin')+os.pathsep+environment.get('PATH','')
    environment['QT_QPA_PLATFORM']='offscreen';environment['QT_PLUGIN_PATH']=str(args.qt/'plugins')
    for scale in ['1','1.5']:
        environment['QT_SCALE_FACTOR']=scale
        subprocess.run([str(output/'test.exe')],env=environment,check=True)
    source=(root/'Ksword5.1/Ksword5.1/ProcessDock/ProcessDock.cpp').read_text(encoding='utf-8-sig')
    area=(root/'Ksword5.1/Ksword5.1/ProcessDock/ProcessDock.MetricArea.cpp').read_text(encoding='utf-8-sig')
    assert 'logicalIndexAt(localPosition)' in source and 'isMetricAreaColumn(metricColumn)' in source
    assert 'refreshMetricAreaViews(true);' in source
    assert source.index('m_processTableModel->setRows(std::move(tableRows))')<source.index('refreshMetricAreaViews(true);')
    assert 'showBoundProcessContextMenu(global,&row,column' in area
    assert 'processActionTargetFromTableRow(row)' in area and 'display.record->creationTime100ns' in area
    assert 'startTimer' not in area and 'setInterval' not in area
    print('PASS: logical header identity, accepted table publication, shared process menu and stable action identity wiring')
if __name__=='__main__':main()
