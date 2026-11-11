from pathlib import Path
import json, os, subprocess, sys, tempfile
root=Path(__file__).resolve().parents[2]
qt=root/'.deps/Qt/6.9.3/msvc2022_64'
if not qt.exists():
    qt=Path('D:/Software/Qt/6.9.3/msvc2022_64')
with tempfile.TemporaryDirectory(prefix='ksword_timeline_density_') as temp:
    t=Path(temp); exe=t/'test.exe'
    includes=['/I'+str(qt/'include'/n) for n in ('','QtCore','QtGui','QtWidgets','QtNetwork')]
    includes+=['/I'+str(root/'Ksword5.1/Ksword5.1')]
    libs=[str(qt/'lib'/n) for n in ('Qt6Core.lib','Qt6Gui.lib','Qt6Widgets.lib')]
    subprocess.run(['cl','/nologo','/std:c++20','/Zc:__cplusplus','/EHsc','/utf-8','/MD','/O2','/DWIN32_LEAN_AND_MEAN','/DNOMINMAX',*includes,
        str(root/'tools/api_monitor/timeline_density_test.cpp'),str(root/'Ksword5.1/Ksword5.1/MonitorDock/EventTimelineModel.cpp'),
        '/Fo:'+str(t)+os.sep,'/Fe:'+str(exe),'/link',*libs],check=True)
    env=os.environ.copy(); env['PATH']=str(qt/'bin')+os.pathsep+env['PATH']
    args=[]
    if len(sys.argv)>1:
        capture=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))['data']
        # System-process captures may be wrapped by `privilege run`.
        if 'stdout' in capture:
            capture=json.loads(capture['stdout'])['data']
        events=[event for event in capture['events'] if event['eventKind']==0
                and event['category']!=6 and int(event['timestampFileTime'])]
        if not events:
            raise ValueError('capture has no timestamped API events')
        replay=t/'capture.tsv'
        replay.write_text(''.join(f"{event['timestampFileTime']} {event['category']}\n" for event in events),encoding='ascii')
        args.append(str(replay))
    subprocess.run([str(exe),*args],env=env,check=True,timeout=30)
