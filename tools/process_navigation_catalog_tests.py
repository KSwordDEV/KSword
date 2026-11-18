"""Compile actual Process catalog/navigation declarations with QtCore QObject fakes only."""
from pathlib import Path
import argparse,json,os,subprocess,time,hashlib

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path);parser.add_argument('--catalog-header',type=Path);parser.add_argument('--output',type=Path);parser.add_argument('--qt',type=Path);args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    source_path=args.source or root/'Ksword5.1/Ksword5.1/ProcessDock/ProcessDock.cpp'
    catalog=args.catalog_header or root/'Ksword5.1/Ksword5.1/UI/PageNavigationCatalog.h'
    if args.qt is None:
        bundled_qt = root/'.deps/Qt/6.9.3/msvc2022_64'
        args.qt = bundled_qt if bundled_qt.is_dir() else Path('D:/Software/Qt/6.9.3/msvc2022_64')
    output=args.output or root/'tools/tests/x64/Release/ProcessNavigation';output.mkdir(parents=True,exist_ok=True)
    source=source_path.read_text(encoding='utf-8-sig');header=source_path.with_suffix('.h').read_text(encoding='utf-8-sig')
    start=source.index('const ProcessDock::NavigationDefinitions& ProcessDock::navigationDefinitions()');end=source.index('void ProcessDock::initializeUi()',start)
    methods=source[start:end];declarations=header[header.index('    enum class NavigationPage'):header.index('    // ======== UI 初始化相关')]
    start=source.index('namespace\n{\n    [[maybe_unused]] const bool kProcessNavigationRegistered')
    registration=source[start:source.index('\n}',start)+2]
    fixture=Path(__file__).with_suffix('.cpp').read_text(encoding='utf-8-sig').replace('__CATALOG_HEADER__',catalog.resolve().as_posix()).replace('__NAVIGATION_DECLARATIONS__',declarations).replace('__ACTUAL_METHODS__',methods).replace('__ACTUAL_REGISTRATION__',registration)
    cpp=output/'fixture.cpp';cpp.write_text(fixture,encoding='utf-8')
    developer=next(p for p in [Path('D:/Software/VS/Common7/Tools/VsDevCmd.bat'),Path('C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/Tools/VsDevCmd.bat')] if p.exists())
    command=['cl.exe','/nologo','/Zc:__cplusplus','/std:c++20','/utf-8','/EHsc','/MD','/O2','/W4','/WX','/I'+str(args.qt/'include'),'/I'+str(args.qt/'include/QtCore'),str(cpp.resolve()),'/Fo'+str((output/'fixture.obj').resolve()),'/Fe'+str((output/'fixture.exe').resolve()),'/link','/LIBPATH:'+str(args.qt/'lib'),'Qt6Core.lib']
    build=output/'build.cmd';build.write_text('@echo off\ncall "'+str(developer)+'" -arch=x64 -host_arch=x64 >nul\n'+subprocess.list2cmdline(command)+'\nexit /b %errorlevel%\n',encoding='utf-8')
    compiled=subprocess.run(['cmd.exe','/d','/c',str(build.resolve())],capture_output=True,text=True);(output/'compile.log').write_text(compiled.stdout+compiled.stderr,encoding='utf-8')
    if compiled.returncode:print(compiled.stdout+compiled.stderr);raise SystemExit(compiled.returncode)
    env=dict(os.environ);env['PATH']=str(args.qt/'bin')+os.pathsep+env.get('PATH','');started=time.perf_counter();run=subprocess.run([str((output/'fixture.exe').resolve())],capture_output=True,text=True,env=env,timeout=30)
    result={'returncode':run.returncode,'elapsed_seconds':round(time.perf_counter()-started,3),'stdout':run.stdout,'stderr':run.stderr,'scope':'actual Process metadata/factory/navigation methods + central header; QObject/QtCore fake tabs only, no QtWidgets GUI/business query','input_sha256':{'source':hashlib.sha256(source_path.read_bytes()).hexdigest(),'header':hashlib.sha256(source_path.with_suffix('.h').read_bytes()).hexdigest(),'catalog_header':hashlib.sha256(catalog.read_bytes()).hexdigest()}}
    (output/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))
    if run.returncode:raise SystemExit(run.returncode)
    # All actual main-Dock factories must consume each shared row once.
    files=[source_path,source_path.with_name('ProcessDock.ThreadTab.cpp'),source_path.with_name('ProcessDock.CrossView.cpp')]
    combined='\n'.join(p.read_text(encoding='utf-8-sig') for p in files)
    for page in ['List','Threads','CrossView','CrossViewProcess','CrossViewThread','Create','DeepDetection','ListProcesses','ListDetection']:
        assert combined.count('registerNavigationTab(NavigationPage::'+page+',')==1,page
    assert 'widget->isEnabled()' not in methods
    assert 'ProcessDetailWindow' not in methods and 'requestProcessEtwCapture' not in methods
    print('PASS: nine actual factory sites each consume one shared definition; content busy state is not a navigation gate')

if __name__=='__main__':main()
