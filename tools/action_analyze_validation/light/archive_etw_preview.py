"""Verify CLI project replay in the official Light window with pywin32."""

import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import winreg

import win32con as con
import win32gui as gui
import win32process

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cli'))
from live_etw import RELEASE, run


MAIN_CLASS = 'KswordARKLight.MainWindow'
WORKSPACE = r'Software\KSwordDEV\KswordARKLight\Workspace'
SEND = ctypes.WinDLL('user32').SendMessageW
SEND.argtypes = (ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_void_p)
SEND.restype = ctypes.c_ssize_t


def windows(parent=None):
    handles = []

    def collect(hwnd, _):
        handles.append(hwnd)
        return True

    if parent is None:
        gui.EnumWindows(collect, None)
    else:
        gui.EnumChildWindows(parent, collect, None)
    return handles


def wait_for(description, probe):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if result := probe():
            return result
        time.sleep(0.05)
    raise AssertionError(description)


def control(parent, identifier):
    return next((hwnd for hwnd in windows(parent) if gui.GetDlgCtrlID(hwnd) == identifier), 0)


def text(hwnd, message=con.WM_GETTEXT, index=32768):
    buffer = ctypes.create_unicode_buffer(32768)
    SEND(hwnd, message, index, ctypes.addressof(buffer))
    return buffer.value


def workspace_state():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, WORKSPACE) as key:
            return winreg.QueryValueEx(key, 'State')
    except FileNotFoundError:
        return None


def restore_state(original):
    if workspace_state() == original:
        return
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, WORKSPACE, 0, winreg.KEY_SET_VALUE) as key:
        if original is None:
            winreg.DeleteValue(key, 'State')
        else:
            data, kind = original
            winreg.SetValueEx(key, 'State', 0, kind, data)
    assert workspace_state() == original


def verify_continuous(binary, segment, segments, records, detail, status, etw, retry, item_count, verified):
    """通过正式界面测试连续段、未发布检查点、损坏与恢复。"""
    sample = segment.parents[1]  # 由 CLI 验收拥有并负责清理。
    counts = [int(part['lastSequence']) for part in segments]  # 全采样连续原始水位。
    observations = sum(int(part['observationCount']) for part in segments)  # 仅 ETW 观察条数。
    wait_for('terminal segment', lambda: verified() and f'records/{len(segments)} ' in text(status))
    assert item_count() == min(4096, counts[-1])
    gui.SendMessage(etw, con.BM_CLICK, 0, 0)
    assert item_count() == observations
    gui.SendMessage(records, con.WM_KEYDOWN, con.VK_END, 0)
    detail_text = wait_for('last ETW observation', lambda: text(detail) if f'所属段号：{len(segments)-1}' in text(detail) else '')
    assert f'归档记录序号：{counts[-2]-1}' in detail_text
    gui.SendMessage(etw, con.BM_CLICK, 0, 0)
    gui.SendMessage(records, con.WM_KEYDOWN, con.VK_HOME, 0)
    wait_for('first record', lambda: '归档记录序号：1 ' in text(detail))

    # 暂时移走第二段的提交标记，仍只应看到第一段已发布范围。
    marker = sample / 'checkpoints/00000000000000000002.json'
    saved = marker.with_suffix('.pending')  # 固定测试目录中的自有文件。
    assert not saved.exists()
    marker.rename(saved)
    try:
        gui.SendMessage(retry, con.BM_CLICK, 0, 0)
        wait_for('second checkpoint unpublished', lambda: '第 2 段检查点尚未发布' in text(status))
        assert item_count() == counts[0] and '归档记录序号：1 ' in text(detail)
    finally:
        saved.rename(marker)

    # 损坏第三段 records，读取者只应提交完整通过双流校验的前两段。
    coverage = sample / 'records/00000000000000000003.ksaseg'
    original = coverage.read_bytes()  # 恢复原始字节用于再次校验。
    try:
        coverage.write_bytes(original[:-1])
        gui.SendMessage(retry, con.BM_CLICK, 0, 0)
        wait_for('third checkpoint invalid', lambda: '第 3 段核验失败' in text(status))
        assert item_count() == counts[1] and '归档记录序号：1 ' in text(detail)
    finally:
        coverage.write_bytes(original)
    gui.SendMessage(retry, con.BM_CLICK, 0, 0)
    wait_for('all continuous checkpoints restored', verified)
    assert item_count() == counts[-1] and '归档记录序号：1 ' in text(detail)
    print(json.dumps({'lightSha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'sampleId': sample.name,
                     'segments': len(segments), 'rows': counts[-1], 'etwRows': observations,
                     'unpublishedPrefixRows': counts[0], 'damagedPrefixRows': counts[1]}, ensure_ascii=False), flush=True)
    print('LIGHT_CONTINUOUS_ETW_REPLAY=PASS', flush=True)


def preview(segment, first_event=None, api_rows=None, etw_segments=None, api_window_total=None):
    """用正式窗口打开指定项目段，核对 ETW 原样回放或 API 线索。"""
    assert not any(gui.GetClassName(hwnd) == MAIN_CLASS for hwnd in windows()), 'Light is already running'
    binary = RELEASE / 'KswordARKLight.exe'
    saved_state = workspace_state()
    process = subprocess.Popen([binary, '--no-auto-elevation'], cwd=RELEASE)
    main = None

    def owned_window(class_name, title=None):
        return next((hwnd for hwnd in windows() if win32process.GetWindowThreadProcessId(hwnd)[1] == process.pid
                     and gui.GetClassName(hwnd).casefold() == class_name.casefold()
                     and (title is None or gui.GetWindowText(hwnd) == title)), 0)

    try:
        main = wait_for('Light main window', lambda: owned_window(MAIN_CLASS))
        gui.SendMessage(main, con.WM_COMMAND, 1005, 0)  # 导航 menu action.
        palette = wait_for('Light navigation palette', lambda: owned_window('ListBox'))
        entries = gui.SendMessage(palette, con.LB_GETCOUNT, 0, 0)
        monitor = next(index for index in range(entries) if text(palette, con.LB_GETTEXT, index).startswith('模块： 监控'))
        gui.SendMessage(palette, con.LB_SETCURSEL, monitor, 0)
        gui.SendMessage(palette, con.WM_KEYDOWN, con.VK_RETURN, 0)
        tabs = wait_for('Monitor tabs', lambda: control(main, 68100))
        for _ in range(2):
            gui.SendMessage(tabs, con.WM_KEYDOWN, con.VK_RIGHT, 0)
        assert gui.SendMessage(tabs, 0x130B, 0, 0) == 2  # TCM_GETCURSEL
        open_button = wait_for('ActionAnalyze Open', lambda: control(main, 58301))
        page = gui.GetParent(open_button)
        retry = control(page, 58302)
        timeline = control(page, 58305)
        records = control(page, 58306)
        detail = control(page, 58307)
        status = control(page, 58308)
        etw = control(page, 58309)
        samples = control(page, 58310)
        replay = control(page, 58311)
        discard = control(page, 58312)
        api = control(page, 58313)  # 第一个独立来源开关的原生 ID。
        filter_edit = control(page, 58304)  # 同表共享的关键字筛选。
        item_count = lambda: gui.SendMessage(records, 0x1004, 0, 0)  # LVM_GETITEMCOUNT

        def open_file(path=None):
            gui.PostMessage(open_button, con.BM_CLICK, 0, 0)
            try:
                dialog = wait_for('Light file dialog', lambda: owned_window('#32770', '打开 ActionAnalyze 归档'))
            except AssertionError as error:
                captions = [(gui.GetClassName(hwnd), gui.GetWindowText(hwnd)) for hwnd in windows()
                            if win32process.GetWindowThreadProcessId(hwnd)[1] == process.pid and gui.IsWindowVisible(hwnd)]
                raise AssertionError(('Light file dialog', text(status), captions, gui.IsWindowEnabled(main))) from error
            if path is None:
                gui.PostMessage(dialog, con.WM_COMMAND, con.IDCANCEL, 0)
            else:
                def filename_edit():
                    combo = control(dialog, 1148)  # cmb13 in the Explorer-style dialog.
                    if combo:
                        return next((hwnd for hwnd in windows(combo) if gui.GetClassName(hwnd).casefold() == 'edit'), 0)
                    return control(dialog, 1152)  # edt1 in the older dialog.

                filename = wait_for('File name input', filename_edit)
                wait_for('File name input visible', lambda: gui.IsWindowVisible(filename))
                for char in str(path):
                    gui.PostMessage(filename, con.WM_CHAR, ord(char), 1)
                try:
                    wait_for('File name typed', lambda: text(filename) == str(path))
                except AssertionError as error:
                    raise AssertionError(('File name typed', text(filename), str(path))) from error
                gui.PostMessage(dialog, con.WM_COMMAND, con.IDOK, 0)
            wait_for('Light file dialog closed', lambda: not gui.IsWindow(dialog))

        def verified():
            report = text(status)
            return '终态检查点已验证' in report and '正在读取' not in report and '读取失败' not in report

        manifest = segment.parents[3] / 'project.ksaproj'
        sample_id = segment.parents[1].name
        open_file(manifest)
        wait_for('sample chooser', lambda: gui.IsWindowVisible(samples))
        assert item_count() == 0 and not gui.IsWindowEnabled(replay)
        total = gui.SendMessage(samples, con.CB_GETCOUNT, 0, 0)
        selected = next(index for index in range(total)
                        if text(samples, con.CB_GETLBTEXT, index).startswith(sample_id + ' · '))
        gui.SendMessage(samples, con.CB_SETCURSEL, selected, 0)
        gui.SendMessage(page, con.WM_COMMAND, 58310 | (con.CBN_SELCHANGE << 16), samples)
        assert gui.IsWindowEnabled(replay) and item_count() == 0
        memory_before = win32process.GetProcessMemoryInfo(int(process._handle))  # 正式窗口待打开状态。
        started = time.perf_counter()  # 从点击回放起计算实际可见行等待时间。
        gui.SendMessage(replay, con.BM_CLICK, 0, 0)
        if api_window_total is not None:
            wait_for('large API recent window', lambda: item_count() == 4096 and '正在读取' not in text(status))
            elapsed = (time.perf_counter() - started) * 1000  # 包含 50 ms 轮询取整和异步发布。
            memory = win32process.GetProcessMemoryInfo(int(process._handle))  # 本应用整进程峰值，含启动。
            assert f'帧记录 {api_window_total + 1}' in text(status)
            for key, sequence in ((con.VK_HOME, api_window_total - 4095), (con.VK_END, api_window_total)):
                gui.SendMessage(records, con.WM_KEYDOWN, key, 0)
                wait_for('API window endpoint', lambda: f'归档记录序号：{sequence} ' in text(detail))
                assert f'源归档行号：{sequence}\r\n' in text(detail)
            print(json.dumps({'rowsVerified': api_window_total, 'rowsDisplayed': item_count(),
                              'firstVisibleSequence': api_window_total - 4095, 'loadMs': round(elapsed, 2),
                              'preReplayWorkingSetBytes': memory_before['WorkingSetSize'],
                              'peakWorkingSetBytes': memory['PeakWorkingSetSize'],
                              'peakPrivateCommitBytes': memory['PeakPagefileUsage']}), flush=True)
            return

        if api_rows is not None:
            # API 导入用收尾记录确认完整性，项目入口仍显示 raw 段状态。
            wait_for('verified API archive loaded', lambda: item_count() == len(api_rows) and '正在读取' not in text(status))
            assert gui.IsWindowEnabled(api) and not gui.IsWindowEnabled(etw)
            gui.SendMessage(records, con.WM_KEYDOWN, con.VK_HOME, 0)
            for index, row in enumerate(api_rows):
                # ListView 原生方向键推进选择，不直接修改模型或跨进程写入内存。
                if index:
                    gui.SendMessage(records, con.WM_KEYDOWN, con.VK_DOWN, 0)
                detail_text = wait_for('API detail selected', lambda: text(detail) if row['api'] in text(detail) else '')
                for value in (sample_id, f"归档记录序号：{row['rawSequence']}", f"源归档行号：{row['sourceSequence']}",
                              f"FILETIME：{row['time100ns']}", bytes.fromhex(row['packet'])[:128].hex(' '),
                              '目标身份、实际写入范围、执行和归因未知。'):
                    assert value in detail_text, detail_text

            gui.SendMessage(api, con.BM_CLICK, 0, 0)
            assert gui.SendMessage(api, con.BM_GETCHECK, 0, 0) == con.BST_CHECKED and item_count() == len(api_rows)
            keyword = ctypes.create_unicode_buffer('WriteProcessMemory')  # 筛掉当前选中的节映射行。
            SEND(filter_edit, con.WM_SETTEXT, 0, ctypes.addressof(keyword))
            assert item_count() == 1 and text(detail) == detail_text
            empty = ctypes.create_unicode_buffer('')  # 恢复可见行及原选中详情。
            SEND(filter_edit, con.WM_SETTEXT, 0, ctypes.addressof(empty))
            assert item_count() == len(api_rows) and text(detail) == detail_text
            gui.SendMessage(api, con.BM_CLICK, 0, 0)
            assert gui.SendMessage(api, con.BM_GETCHECK, 0, 0) == con.BST_UNCHECKED

            # 改动本脚本拥有的段尾，失败时当前表及详情应继续保持。
            original = segment.read_bytes()
            try:
                segment.write_bytes(original[:-1])
                gui.SendMessage(retry, con.BM_CLICK, 0, 0)
                wait_for('API corruption retains view', lambda: '保留当前归档' in text(status))
                assert item_count() == len(api_rows) and text(detail) == detail_text
            finally:
                segment.write_bytes(original)
            gui.SendMessage(retry, con.BM_CLICK, 0, 0)
            wait_for('API restored', lambda: '正在读取' not in text(status) and '保留当前归档' not in text(status))
            assert item_count() == len(api_rows) and '归档记录序号：5' in text(detail)
            print(f'LIGHT_API_PROJECT_REPLAY=PASS SAMPLE={sample_id} ROWS={len(api_rows)}', flush=True)
            return

        if etw_segments is not None:
            verify_continuous(binary, segment, etw_segments, records, detail, status, etw, retry, item_count, verified)
            return

        wait_for('verified project checkpoint', verified)
        assert item_count() == 14 and not gui.IsWindowEnabled(api)

        gui.SendMessage(etw, con.BM_CLICK, 0, 0)
        assert item_count() == 12
        gui.SendMessage(timeline, con.WM_KEYDOWN, con.VK_HOME, 0)
        selected_text = text(detail)
        event, payload = first_event
        for expected in (sample_id, str(event['headerPid']), event['sourceEpoch'], payload.hex(' '), '归档记录序号：2'):
            assert expected in selected_text, selected_text
        gui.SendMessage(etw, con.BM_CLICK, 0, 0)
        assert item_count() == 14 and text(detail) == selected_text

        open_file()
        assert item_count() == 14 and text(detail) == selected_text
        open_file(manifest)
        wait_for('reopened sample chooser', lambda: gui.IsWindowVisible(samples))
        assert item_count() == 14 and text(detail) == selected_text
        gui.SendMessage(discard, con.BM_CLICK, 0, 0)
        assert not gui.IsWindowVisible(samples) and '已取消选择采样' in text(status)
        assert item_count() == 14 and text(detail) == selected_text

        # Submit again so the retry control owns the sample rather than the catalog.
        open_file(manifest)
        wait_for('sample chooser before retry cases', lambda: gui.IsWindowVisible(samples))
        gui.SendMessage(samples, con.CB_SETCURSEL, selected, 0)
        gui.SendMessage(page, con.WM_COMMAND, 58310 | (con.CBN_SELCHANGE << 16), samples)
        gui.SendMessage(replay, con.BM_CLICK, 0, 0)
        wait_for('sample selected again', verified)
        assert text(detail) == selected_text

        coverage = segment.parents[1] / 'records' / segment.name
        raw_bytes, coverage_bytes = segment.read_bytes(), coverage.read_bytes()
        try:
            segment.write_bytes(raw_bytes + b'tail')
            coverage.write_bytes(coverage_bytes + b'tail')
            gui.SendMessage(retry, con.BM_CLICK, 0, 0)
            bounds = f'帧前缀 {len(raw_bytes)} / {len(raw_bytes) + 4} B'
            wait_for('unpublished tails excluded', lambda: verified() and bounds in text(status))
            assert item_count() == 14 and '归档记录序号：2' in text(detail)
        finally:
            segment.write_bytes(raw_bytes)
            coverage.write_bytes(coverage_bytes)

        selected_text = text(detail)
        try:
            coverage.unlink()
            gui.SendMessage(retry, con.BM_CLICK, 0, 0)
            wait_for('coverage failure retains view', lambda: '保留当前归档' in text(status))
            assert item_count() == 14 and text(detail) == selected_text
        finally:
            coverage.write_bytes(coverage_bytes)
        gui.SendMessage(retry, con.BM_CLICK, 0, 0)
        wait_for('restored project verified', verified)
        assert item_count() == 14 and '归档记录序号：2' in text(detail)

        checkpoint = segment.parents[1] / 'checkpoints/00000000000000000001.json'
        checkpoint_bytes = checkpoint.read_bytes()
        try:
            checkpoint.unlink()
            gui.SendMessage(retry, con.BM_CLICK, 0, 0)
            wait_for('legacy raw fallback', lambda: '未发布终态检查点' in text(status))
            assert item_count() == 14 and '归档记录序号：2' in text(detail)
        finally:
            checkpoint.write_bytes(checkpoint_bytes)
        gui.SendMessage(retry, con.BM_CLICK, 0, 0)
        wait_for('restored legacy checkpoint', verified)

        gui.ShowWindow(main, con.SW_RESTORE)
        gui.SetWindowPos(main, 0, 0, 0, 800, 650, con.SWP_NOZORDER | con.SWP_NOACTIVATE | con.SWP_NOMOVE)
        page_box = gui.GetWindowRect(page)
        for hwnd in (open_button, retry, records, detail, status, api, etw, filter_edit):
            left, top, right, bottom = gui.GetWindowRect(hwnd)
            assert page_box[0] <= left < right <= page_box[2] and page_box[1] <= top < bottom <= page_box[3]
        assert item_count() == 14 and '归档记录序号：2' in text(detail)

        open_file(segment)
        wait_for('standalone segment', lambda: '段内扫描完成' in text(status))
        assert item_count() == 14 and '归档：' in text(detail)
        print(json.dumps({'lightSha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'sampleId': sample_id,
                          'rows': 14, 'etwRows': 12, 'payload': payload.hex(' '), 'windowSize': [800, 650]}), flush=True)
    finally:
        try:
            if main and gui.IsWindow(main) and process.poll() is None:
                for hwnd in windows():
                    if win32process.GetWindowThreadProcessId(hwnd)[1] == process.pid and gui.GetClassName(hwnd) == '#32770':
                        gui.PostMessage(hwnd, con.WM_COMMAND, con.IDCANCEL, 0)
                gui.PostMessage(main, con.WM_CLOSE, 0, 0)
            if main:
                result = process.wait(timeout=12)
                print(f'LIGHT_GUI_EXIT={result}', flush=True)
                assert result == 0
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            restore_state(saved_state)
            print('LIGHT_SETTINGS_RESTORED=True', flush=True)
    print('LIGHT_ETW_PROJECT_REPLAY=PASS', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--continuous']:
        from continuous_etw import run as run_continuous
        run_continuous(inspect_gui=preview)
    elif not sys.argv[1:]:
        run(inspect_gui=preview)
    else:
        raise SystemExit('Usage: archive_etw_preview.py [--continuous]')
