"""在独立桌面用正式 Light 验证同一工程、同一自有进程的两轮被动 ETW。

在仓库根目录使用已安装 pywin32 的 Python 执行下面的命令。
python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/live_project_preview.py
"""

from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
from uuid import UUID

import win32con as con
import win32gui as gui
import win32process

from archive_etw_preview import MAIN_CLASS, SEND, control, restore_state, text, wait_for, windows, workspace_state
from continuous_etw import cleanup_child, regular_identity
from isolated_desktop import launch_gui, require_isolated_desktop
from live_etw import Child, PAYLOAD, PROVIDER, RELEASE, REPO, decode_raw


BINARY = RELEASE / 'KswordARKLight.exe'
SCRATCH = RELEASE / 'ActionAnalyzeLightLiveProjectValidation'
PRODUCER = Path(__file__).resolve().parents[1] / 'cli' / 'continuous_etw.py'
CREATE_TITLE = '新建 ActionAnalyze 工程（输入新文件夹名称）'
OPEN_TITLE = '打开 ActionAnalyze 工程'
CONTROL_IDS = {
    'open': 58301, 'records': 58306, 'detail': 58307, 'status': 58308, 'etw': 58309,
    'samples': 58310, 'replay': 58311, 'switch': 58315, 'pid': 58316, 'provider': 58317,
    'start': 58319, 'stop': 58320, 'create': 58322,
}


def check_scratch():
    """核对正式输出路径和即将清理的唯一测试目录。"""
    assert RELEASE.resolve(strict=True) == RELEASE
    for ancestor in reversed(SCRATCH.parents):
        if ancestor.is_relative_to(REPO):
            regular_identity(ancestor)
    tracked = subprocess.run(['git', 'ls-files', '-z', '--', SCRATCH.relative_to(REPO).as_posix()],
                             cwd=REPO, check=True, capture_output=True, timeout=10)
    assert not tracked.stdout, SCRATCH


def raise_walk_error(error):
    raise error


@contextmanager
def owned_scratch():
    check_scratch()
    SCRATCH.mkdir(exist_ok=False)
    identity = regular_identity(SCRATCH)
    try:
        yield SCRATCH
    finally:
        check_scratch()
        assert SCRATCH.resolve(strict=True) == SCRATCH and regular_identity(SCRATCH) == identity
        for parent, directories, files in os.walk(SCRATCH, followlinks=False, onerror=raise_walk_error):
            for name in directories + files:
                regular_identity(Path(parent) / name)
        shutil.rmtree(SCRATCH)
        assert not os.path.lexists(SCRATCH)
        print(f'LIGHT_TEST_DIRECTORY_REMOVED={SCRATCH}', flush=True)


def set_text(hwnd, value):
    """通过原生编辑控件提交 Unicode 文本并读回。"""
    buffer = ctypes.create_unicode_buffer(value)
    assert SEND(hwnd, con.WM_SETTEXT, 0, ctypes.addressof(buffer))
    assert text(hwnd) == value, (value, text(hwnd))


class Workspace:
    def __init__(self, process):
        self.process = process
        self.main = wait_for('Light 主窗口', lambda: self.owned(MAIN_CLASS))
        gui.SendMessage(self.main, con.WM_COMMAND, 1005, 0)  # 通过实际导航面板进入监控。
        palette = wait_for('Light 导航面板', lambda: self.owned('ListBox', require_visible=False))
        entries = gui.SendMessage(palette, con.LB_GETCOUNT, 0, 0)
        monitor = next(index for index in range(entries)
                       if text(palette, con.LB_GETTEXT, index).startswith('模块： 监控'))
        gui.SendMessage(palette, con.LB_SETCURSEL, monitor, 0)
        gui.SendMessage(palette, con.WM_KEYDOWN, con.VK_RETURN, 0)
        tabs = wait_for('监控页签', lambda: control(self.main, 68100))
        for _ in range(2):
            gui.SendMessage(tabs, con.WM_KEYDOWN, con.VK_RIGHT, 0)
        assert gui.SendMessage(tabs, 0x130B, 0, 0) == 2  # TCM_GETCURSEL
        open_button = wait_for('ActionAnalyze 工程入口', lambda: control(self.main, CONTROL_IDS['open']))
        self.page = gui.GetParent(open_button)
        self.controls = {name: control(self.page, identifier) for name, identifier in CONTROL_IDS.items()}
        assert all(self.controls.values()), self.controls

    def owned(self, kind, title=None, *, require_visible=True):
        """按本次进程和原生类名查找窗口，导航列表在隔离桌面允许暂不可见。"""
        return next((hwnd for hwnd in windows() if win32process.GetWindowThreadProcessId(hwnd)[1] == self.process.pid
                     and (not require_visible or gui.IsWindowVisible(hwnd))
                     and gui.GetClassName(hwnd).casefold() == kind.casefold()
                     and (title is None or gui.GetWindowText(hwnd) == title)), 0)

    def click(self, name, *, modal=False):
        hwnd = self.controls[name]
        assert gui.IsWindowVisible(hwnd) and gui.IsWindowEnabled(hwnd), (name, self.status())
        (gui.PostMessage if modal else gui.SendMessage)(hwnd, con.BM_CLICK, 0, 0)

    def status(self):
        return text(self.controls['status'])

    def wait_status(self, description, predicate):
        def probe():
            status = self.status()
            for failure in ('ETW 不可用', '采集失败', 'ETW 清退失败', '归档失败', '读取失败', '无法预览采样'):
                if failure in status:
                    raise AssertionError((description, status))
            return status if predicate(status) else ''

        try:
            return wait_for(description, probe)
        except AssertionError as error:
            raise AssertionError((description, self.status())) from error

    def row_count(self):
        return gui.SendMessage(self.controls['records'], 0x1004, 0, 0)  # LVM_GETITEMCOUNT

    def default_page(self):
        assert text(self.controls['switch']) == '新一轮扫描'
        for name in ('open', 'create'):
            assert gui.IsWindowVisible(self.controls[name]) and gui.IsWindowEnabled(self.controls[name]), name
        for name in ('pid', 'provider', 'start', 'stop', 'samples'):
            assert not gui.IsWindowVisible(self.controls[name]), name
        assert '新建或打开工程后' in self.status() and self.row_count() == 0

    def browse(self, name, title, path):
        self.click(name, modal=True)
        dialog = wait_for(title, lambda: self.owned('#32770', title))

        def filename_edit():
            combo = control(dialog, 1148)  # Explorer 风格文件对话框的 cmb13。
            if combo:
                nested = next((hwnd for hwnd in windows(combo) if gui.GetClassName(hwnd).casefold() == 'edit'), 0)
                if nested:
                    return nested
            classic = control(dialog, 1152)  # 旧版通用对话框的 edt1，可能位于组合框外。
            if classic and gui.GetClassName(classic).casefold() == 'edit' and gui.IsWindowVisible(classic):
                return classic
            edits = [hwnd for hwnd in windows(dialog) if gui.GetClassName(hwnd).casefold() == 'edit'
                     and gui.IsWindowVisible(hwnd) and gui.IsWindowEnabled(hwnd)]  # 只接受唯一可编辑字段。
            return edits[0] if len(edits) == 1 else 0

        try:
            filename = wait_for('文件名编辑控件', filename_edit)
        except AssertionError as error:
            controls = [(gui.GetClassName(hwnd), gui.GetDlgCtrlID(hwnd), bool(gui.IsWindowVisible(hwnd)))
                        for hwnd in windows(dialog)]  # 记录控件结构，便于定位不同系统的文件选择器。
            raise AssertionError((title, controls)) from error
        assert gui.IsWindowVisible(filename)
        set_text(filename, str(path))
        gui.PostMessage(dialog, con.WM_COMMAND, con.IDOK, 0)
        wait_for(f'{title}已关闭', lambda: not gui.IsWindow(dialog))

    def sample_entries(self):
        combo = self.controls['samples']
        if not gui.IsWindowVisible(combo):
            return {}
        entries = {}
        for index in range(gui.SendMessage(combo, con.CB_GETCOUNT, 0, 0)):
            identifier, separator, title = text(combo, con.CB_GETLBTEXT, index).partition(' · ')
            assert separator and title and identifier not in entries
            entries[identifier] = index
        return entries

    def wait_catalog(self, manifest, expected):
        """从界面目录读取项目和采样身份，等待异步发布。"""
        status = self.wait_status('工程目录发布', lambda value: '已打开工程 · ' in value
                                  and str(manifest).casefold() in value.casefold()
                                  and set(self.sample_entries()) == expected)
        assert text(self.controls['switch']) == '新一轮扫描', status
        return status

    def capture(self, producer, identity, iterations):
        assert producer.process.poll() is None
        pid = identity['pid']
        self.click('switch')
        assert text(self.controls['switch']) == '返回工程'
        for name, value in (('pid', str(pid)), ('provider', str(PROVIDER))):
            assert gui.IsWindowVisible(self.controls[name]), name
            set_text(self.controls[name], value)
        self.click('start')
        self.wait_status('ETW 来源就绪', lambda value: value.startswith(f'PID {pid} · 采集中')
                         and f'创建 {identity["creationFileTime"]}\r\n' in value
                         and '队列丢弃' in value and 'ETW 启动中' not in value)
        assert not gui.IsWindowVisible(self.controls['samples'])
        producer.send(f'write {iterations}')
        expected = iterations * 2
        assert producer.next() == {'operations': expected}
        self.wait_status('实时 ETW 观察已归档', lambda value: value.startswith(f'PID {pid} · 采集中')
                         and f' · ETW {expected} · ' in value and bool(re.search(r'已提交 [1-9]\d* 段', value)))
        self.click('stop')
        stopped = self.wait_status('停止及终段发布', lambda value: value.startswith(f'PID {pid} · 已停止')
                                   and '终段已发布' in value and not gui.IsWindowEnabled(self.controls['stop']))
        assert f' · ETW {expected} · ' in stopped and ' · 队列丢弃 0' in stopped, stopped
        assert producer.process.poll() is None
        self.click('switch')  # 唯一的返回动作。工程目录必须自行读入刚提交的采样。
        return stopped

    def replay(self, project_id, archive):
        """先验证选中即预览，再从正式回放控件读取终段和完整证据。"""
        combo = self.controls['samples']
        sample_id = archive['sampleId']
        index = self.sample_entries()[sample_id]
        assert gui.SendMessage(combo, con.CB_SETCURSEL, index, 0) == index
        gui.SendMessage(self.page, con.WM_COMMAND, CONTROL_IDS['samples'] | (con.CBN_SELCHANGE << 16), combo)
        self.wait_status('自动预览选中的采样', lambda value: f'快速预览 · {sample_id}' in value
                         and '已核验首段' in value)
        assert f'选中采样预览 · 采样：{sample_id}' in text(self.controls['detail'])
        assert self.row_count() == archive['firstSegmentRows']

        self.click('replay')
        self.wait_status('回放终态检查点', lambda value: '正在读取' not in value and sample_id in value
                         and f'终态检查点已验证 · records/{archive["segments"]} ' in value)
        assert self.row_count() == archive['rawRows']
        self.click('etw')
        assert gui.SendMessage(self.controls['etw'], con.BM_GETCHECK, 0, 0) == con.BST_CHECKED
        assert self.row_count() == archive['observations']
        gui.SendMessage(self.controls['records'], con.WM_KEYDOWN, con.VK_HOME, 0)
        ordinal, sequence, metadata, payload = archive['firstObservation']
        coordinate = f'归档记录序号：{sequence}    所属段号：{ordinal}    块号：'

        def selected_detail():
            detail = text(self.controls['detail'])
            return detail if coordinate in detail else ''

        detail = wait_for('选中首条 ETW 归档证据', selected_detail)
        assert f'当前归档 · 采样：{sample_id}' in detail and f'项目：{project_id}' in detail, detail
        _, marker, raw = detail.partition('原始记录元数据（归档 JSON）\r\n')
        shown_metadata, boundary, shown_payload = raw.partition('\r\n\r\n内联原始字节（8 字节）\r\n')
        assert marker and boundary and json.loads(shown_metadata) == metadata, detail
        assert shown_payload.strip() == payload.hex(' '), detail
        self.click('etw')  # 恢复默认显示，保证下一次采样预览可独立验证。
        assert self.row_count() == archive['rawRows']
        return {'segment': ordinal, 'sequence': sequence, 'payload': shown_payload.strip()}


@contextmanager
def light_window():
    """只关闭本次启动的 Light 并恢复原工作区状态。"""
    existing = subprocess.run(['tasklist.exe', '/fi', 'IMAGENAME eq KswordARKLight.exe', '/fo', 'csv', '/nh'],
                              check=True, capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
    assert b'"kswordarklight.exe"' not in existing.stdout.lower(), '请先结束其它 Light 实例'
    saved = workspace_state()
    process = launch_gui([BINARY, '--no-auto-elevation'], cwd=RELEASE)
    try:
        yield Workspace(process)
    finally:
        try:
            main = 0
            for hwnd in windows():
                if win32process.GetWindowThreadProcessId(hwnd)[1] != process.pid:
                    continue
                kind = gui.GetClassName(hwnd)
                if kind == '#32770':
                    gui.PostMessage(hwnd, con.WM_COMMAND, con.IDCANCEL, 0)
                elif kind == MAIN_CLASS:
                    main = hwnd
            if main:
                gui.PostMessage(main, con.WM_CLOSE, 0, 0)
            result = process.wait(timeout=12)
            print(f'LIGHT_GUI_EXIT={result}', flush=True)
            assert result == 0
        finally:
            if process.poll() is None:
                print(f'LIGHT_GUI_FORCED_EXIT_PID={process.pid}', flush=True)
                process.terminate()
                process.wait(timeout=5)
            restore_state(saved)
            print('LIGHT_SETTINGS_RESTORED=True', flush=True)


def read_archive(sample, project, target, first_iteration, iterations):
    """独立回读 Light 产物，将每条 ETW 及其双流检查点与自有输入对账。"""
    sample_id = sample.name
    assert str(UUID(sample_id)) == sample_id
    description_hash = hashlib.sha256((sample / 'sample.json').read_bytes()).hexdigest()
    segment_paths = sorted((sample / 'raw').glob('*.ksaseg'))
    assert len(segment_paths) >= 2, segment_paths  # 停止前已提交观察，停止后另有终段。
    assert len(list((sample / 'records').glob('*.ksaseg'))) == len(segment_paths)
    assert len(list((sample / 'checkpoints').glob('*.json'))) == len(segment_paths)

    expected = {(event_id, struct.pack('<II', iteration, len(PAYLOAD)))
                for iteration in range(first_iteration, first_iteration + iterations) for event_id in (1, 2)}
    observations = []
    raw_hashes = []
    raw_rows = 0
    first_segment_rows = 0
    first_plan = None
    for ordinal, raw_path in enumerate(segment_paths, 1):
        stem = f'{ordinal:020d}'
        assert raw_path.name == f'{stem}.ksaseg'
        marker = json.loads((sample / 'checkpoints' / f'{stem}.json').read_bytes())
        assert marker['kind'] == 'etw-terminal-checkpoint-v1' and marker['generation'] == str(ordinal), marker
        assert marker['projectId'] == project['projectId'] and marker['sampleId'] == sample_id, marker
        assert marker['descriptionHash'] == description_hash, marker
        for stream in ('raw', 'records'):
            data = (sample / stream / raw_path.name).read_bytes()
            prefix = marker[stream]
            assert prefix['ordinal'] == str(ordinal) and prefix['endOffset'] == str(len(data)), marker
            assert prefix['sha256'] == hashlib.sha256(data).hexdigest(), marker
        assert marker['records']['lastSequence'] == str(ordinal), marker

        rows, digest = decode_raw(raw_path, raw_rows + 1)
        raw_hashes.append(digest)
        assert marker['raw']['lastSequence'] == str(raw_rows + len(rows)), marker
        plan, plan_payload = rows[0]
        terminal, terminal_payload = rows[-1]
        assert not plan_payload and not terminal_payload
        if first_plan is None:
            first_plan = plan
            first_segment_rows = len(rows)
        assert plan == first_plan and plan['kind'] == 'etw-capture-plan-v1' and plan['backend'] == 'r3', plan
        assert plan['headerPid'] == target['pid'] and plan['processCreationFileTime'] == target['creationFileTime'], plan
        assert plan['providerId'] == str(PROVIDER) and plan['session']['id'] == sample_id, plan
        assert plan['revisionId'] == project['currentRevisionId'] and plan['headerRole'] == 'record-context', plan
        final = ordinal == len(segment_paths)
        assert terminal['kind'] == 'etw-capture-end-v1' and terminal['finalSegment'] is final, terminal
        assert terminal['stopReason'] == ('requested' if final else 'segment-rotated'), terminal
        assert terminal['segmentObservations'] == str(len(rows) - 2), terminal
        source = terminal['source']
        assert source['sourceEpoch'] == plan['sourceEpoch'] and source['nativeSessionStopped'] is final, source
        if final:
            assert source['consumerJoined'] and not source['tailDeliveryUnconfirmed'], source
            assert source['enqueued'] == str(len(expected)) and source['queued'] == source['queueDropped'] == '0', source

        for sequence, (metadata, payload) in enumerate(rows[1:-1], raw_rows + 2):
            assert metadata['kind'] == 'etw-observation-v1', metadata
            for key in ('providerId', 'sourceEpoch', 'headerPid'):
                assert metadata[key] == plan[key], metadata
            assert metadata['originalPayloadBytes'] == len(payload) == 8, metadata
            observations.append((ordinal, sequence, metadata, payload))
        raw_rows += len(rows)

    observed = {(metadata['descriptor']['id'], payload) for _, _, metadata, payload in observations}
    assert len(observations) == len(expected) and observed == expected, (observed, expected)
    return {'sampleId': sample_id, 'sourceEpoch': first_plan['sourceEpoch'], 'segments': len(segment_paths),
            'firstSegmentRows': first_segment_rows, 'rawRows': raw_rows, 'observations': len(observations),
            'rawSha256': raw_hashes, 'firstObservation': observations[0]}


def main():
    require_isolated_desktop()
    if sys.flags.optimize:
        raise RuntimeError('请用 python -B 运行，保留验收断言')
    assert BINARY.is_file(), BINARY
    light_sha256 = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    with owned_scratch() as directory:
        project_dir = directory / 'owned project'
        manifest = project_dir / 'project.ksaproj'
        producer = Child([sys.executable, '-B', PRODUCER, '--producer', directory / 'owned.bin'])
        try:
            target = producer.next()
            assert target['pid'] == producer.process.pid and int(target['creationFileTime']) > 0, target
            with light_window() as page:
                page.default_page()
                page.browse('create', CREATE_TITLE, project_dir)
                page.wait_status('新建空工程', lambda value: '已新建工程 · ' in value and '工程尚无采样' in value
                                 and str(manifest).casefold() in value.casefold())
                assert manifest.is_file() and not page.sample_entries() and page.row_count() == 0
                project = json.loads(manifest.read_bytes())
                assert project['kind'] == 'action-analyze-project' and project['title'] == project_dir.name, project

                archives = []
                seen = set()
                for first_iteration, iterations in ((0, 6), (6, 7)):
                    stopped = page.capture(producer, target, iterations)
                    candidates = {path.name for path in (project_dir / 'samples').iterdir() if path.is_dir()}
                    assert seen < candidates and len(candidates - seen) == 1, (seen, candidates)
                    sample_id, = candidates - seen
                    catalog_status = page.wait_catalog(manifest, candidates)
                    archive = read_archive(project_dir / 'samples' / sample_id, project, target,
                                           first_iteration, iterations)
                    evidence = page.replay(project['projectId'], archive)
                    archives.append(archive)
                    seen = candidates
                    print(json.dumps({'round': len(archives), 'stop': stopped, 'catalog': catalog_status,
                                      'evidence': evidence, **{k: v for k, v in archive.items() if k != 'firstObservation'}},
                                     ensure_ascii=True), flush=True)

                assert archives[0]['sourceEpoch'] != archives[1]['sourceEpoch']
                prior_raw = sorted((project_dir / 'samples' / archives[0]['sampleId'] / 'raw').glob('*.ksaseg'))
                assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in prior_raw] == archives[0]['rawSha256']
        finally:
            cleanup_child(producer, producer=True)
        assert producer.process.returncode == 0

        # 新窗口从默认工程页打开实际清单，目标退出后回放第二轮证据。
        with light_window() as page:
            page.default_page()
            page.browse('open', OPEN_TITLE, manifest)
            page.wait_catalog(manifest, seen)
            assert page.row_count() == 0 and not gui.IsWindowEnabled(page.controls['replay'])
            reopened = page.replay(project['projectId'], archives[-1])
        assert hashlib.sha256(BINARY.read_bytes()).hexdigest() == light_sha256
        print(json.dumps({'lightSha256': light_sha256, 'projectId': project['projectId'], 'target': target,
                          'reopenedSampleId': archives[-1]['sampleId'], 'reopenedEvidence': reopened}), flush=True)
    print('LIGHT_LIVE_PROJECT_PREVIEW=PASS', flush=True)


if __name__ == '__main__':
    main()
