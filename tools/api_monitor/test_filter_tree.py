"""Exercise actual WinAPI tree population and search methods with Qt widgets."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
qt = root / '.deps/Qt/6.9.3/msvc2022_64'
if not qt.exists():
    qt = Path('D:/Software/Qt/6.9.3/msvc2022_64')
source = (root / 'Ksword5.1/Ksword5.1/MonitorDock/WinAPIDock.Coverage.cpp').read_text(encoding='utf-8-sig')
category = source[source.index('namespace {\nQString filterCategoryLabel'):source.index('QWidget* WinAPIDock::createEventRulesPanel')]
tree = source[source.index('void WinAPIDock::refreshEventRulesPanel()'):source.index('void WinAPIDock::loadEventRuleDefinitions()')]
bulk = source[source.index('void WinAPIDock::applyVisibleEventRules('):source.index('void WinAPIDock::refreshEventRulesPanel()')]
search = source[source.index('void WinAPIDock::scheduleEventRuleSearch()'):source.index('\nnamespace\n{', source.index('void WinAPIDock::scheduleEventRuleSearch()'))]
template = (root / 'tools/api_monitor/filter_tree_fixture.cpp').read_text(encoding='utf-8')
with tempfile.TemporaryDirectory(prefix='ksword_filter_tree_') as temporary:
    work = Path(temporary); cpp = work / 'fixture.cpp'; exe = work / 'fixture.exe'
    cpp.write_text(template.replace('// PRODUCTION_METHODS', category + bulk + tree + search), encoding='utf-8')
    includes = ['/I' + str(qt / 'include' / name) for name in ('', 'QtCore', 'QtGui', 'QtWidgets')]
    includes.append('/I' + str(root / 'Ksword5.1/Ksword5.1'))
    libs = [str(qt / 'lib' / name) for name in ('Qt6Core.lib', 'Qt6Gui.lib', 'Qt6Widgets.lib')]
    subprocess.run(['cl', '/nologo', '/std:c++20', '/Zc:__cplusplus', '/EHsc', '/utf-8', '/MD',
                    *includes, str(cpp), '/Fe:' + str(exe), '/Fo:' + str(work / 'fixture.obj'), '/link', *libs], check=True)
    env = os.environ.copy(); key = next(k for k in env if k.lower() == 'path')
    env[key] = str(qt / 'bin') + os.pathsep + env[key]
    env['QT_QPA_PLATFORM'] = 'offscreen'; env['QT_PLUGIN_PATH'] = str(qt / 'plugins')
    subprocess.run([str(exe)], env=env, check=True, timeout=60)
