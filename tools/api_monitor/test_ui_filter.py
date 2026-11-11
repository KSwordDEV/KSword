"""Regress production asynchronous value filtering and large retained windows."""
import os
import runpy
from pathlib import Path
os.environ['KSWORD_APIMON_UI_FIXTURE'] = 'filter'
runpy.run_path(str(Path(__file__).with_name('test_ui_tail.py')), run_name='__main__')
