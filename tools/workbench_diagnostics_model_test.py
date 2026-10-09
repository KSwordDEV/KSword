"""Compile actual diagnostics drawer and copy action; offscreen, no target or device I/O."""
from pathlib import Path
import argparse, json, os, shutil, subprocess

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--qt-root',type=Path,default=Path('.codex-tmp/qt-fixture/ucrt64'))
    parser.add_argument('--compiler',default='g++')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1];app=root/'Ksword5.1/Ksword5.1';qt=(root/args.qt_root).resolve()
    out=root/'work/native-diagnostics-drawer';out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ);compiler=shutil.which(args.compiler) or args.compiler
    env['PATH']=str(qt/'bin')+os.pathsep+str(Path(compiler).parent)+os.pathsep+env.get('PATH','')
    env['QT_QPA_PLATFORM']='offscreen';env['QT_PLUGIN_PATH']=str(qt/'share/qt6/plugins')
    flags=['-std=c++20','-O1','-g0','-DNOMINMAX','-DUNICODE','-D_UNICODE','-I'+str(root)]
    for module in ('','QtCore','QtGui','QtWidgets','QtSvg'):flags+=['-isystem',str(qt/'include/qt6'/module)]
    shared=['UI/CodeEditorWidget.cpp','UI/CodeTextEdit.cpp','UI/CodeEditorFileSession.cpp','UI/StructuredFieldView.cpp','UI/TypedSyntaxDocument.cpp','UI/ThemeStatusRole.cpp','UI/ThemeControlGlyphs.cpp','Internationalization/LanguageManager.cpp']
    objects=[]
    reusable=root/'work/native-privilege-workbench'
    headers=[app/'UI'/name for name in ('CodeEditorWidget.h','CodeTextEdit.h','CodeEditorFileSession.h',
        'StructuredFieldView.h','TypedSyntaxDocument.h','ThemeStatusRole.h','ThemeControlGlyphs.h')]
    headers += [app/'Internationalization/LanguageManager.h', app/'theme.h']
    latest_header=max(header.stat().st_mtime for header in headers)
    for rel in shared:
        source=app/rel;obj=reusable/('privilege-review-'+source.stem+'.o')
        if not obj.is_file() or obj.stat().st_mtime<max(source.stat().st_mtime, latest_header):
            obj=out/(source.stem+'.o');subprocess.run([compiler,*flags,'-c',str(source),'-o',str(obj)],cwd=root,env=env,check=True,timeout=180)
        objects.append(str(obj))
    sources=[app/'UI/MemoryWorkbench'/name for name in ('WorkbenchDiagnosticsHost.cpp','WorkbenchStatusBar.cpp','WorkbenchMessages.cpp')]
    sources.append(root/'tools/workbench_diagnostics_model_tests.cpp')
    moc=qt/'share/qt6/bin/moc.exe'
    for rel in ('UI/StructuredFieldView.h','UI/CodeEditorWidget.h','UI/MemoryWorkbench/WorkbenchDiagnosticsHost.h','UI/MemoryWorkbench/WorkbenchStatusBar.h'):
        header=app/rel;generated=out/('moc_'+header.stem+'.cpp')
        subprocess.run([str(moc),str(header),'-o',str(generated)],cwd=root,env=env,check=True,timeout=60);sources.append(generated)
    for source in sources:
        obj=out/(source.stem+'.o');subprocess.run([compiler,*flags,'-c',str(source),'-o',str(obj)],cwd=root,env=env,check=True,timeout=180);objects.append(str(obj))
    binary=out/'workbench_diagnostics_model_tests.exe'
    subprocess.run([compiler,*objects,'-L'+str(qt/'lib'),'-lQt6Widgets','-lQt6Gui','-lQt6Core','-lQt6Svg','-ladvapi32','-luser32','-o',str(binary)],cwd=root,env=env,check=True,timeout=120)
    run=subprocess.run([str(binary)],cwd=root,env=env,capture_output=True,text=True,timeout=60)
    (root/'.codex-build-logs/workbench-diagnostics-model-test.json').write_text(json.dumps({'exit_code':run.returncode,'stdout':run.stdout,'stderr':run.stderr,'scope':'actual Qt typed drawer and offscreen clipboard copy, no target/account/device I/O'},indent=2),encoding='utf-8')
    print(run.stdout,end='')
    if run.returncode:print(run.stderr);raise SystemExit(run.returncode)
if __name__=='__main__':main()
