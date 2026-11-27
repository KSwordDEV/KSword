"""双端主采集验收的回执与原包对账；不启动程序或创建新采集来源。"""

from contextlib import contextmanager, redirect_stdout, redirect_stderr
import ctypes
import hashlib
import json
from pathlib import Path
import re
import struct
import traceback

import win32con
import win32gui
import win32process
import win32ui

from api_rule_profile import behavior_rule, display_summary
from cooperative_api_capture import self_write_detail
from isolated_desktop import require_isolated_desktop, test_windows


ROOT = Path(__file__).resolve().parent  # 所有本批配置、截图和回执的固定根。
BEHAVIOR = 'ksword.behavior.memory-write-access-denied-return.v1'  # 自有合作源的拒绝调用。
EVIDENCE = 'reported-api-return'  # 仅证明 API 返回，不扩大到写入或执行。


def release_arguments(endpoint, gui, cli):
    """输入端名和正式路径；要求主协调放行参数并返回核验后的镜像摘要。"""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)  # 帮助不会启动 GUI 或目标。
    parser.add_argument('--released-after-cli', action='store_true', required=True)
    parser.add_argument('--cli-sha256', required=True)
    parser.add_argument('--gui-sha256', required=True)
    args = parser.parse_args()  # 放行须由协调者在 CLI 新包实测完成后提供。
    require_isolated_desktop()
    assert __debug__ and struct.calcsize('P') == 8, '需要启用断言的 x64 Python'
    hashes = {}  # 实际运行文件的冻结身份。
    for path, expected in ((cli, args.cli_sha256), (gui, args.gui_sha256)):
        assert re.fullmatch(r'[0-9a-fA-F]{64}', expected), expected
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == expected.lower(), (path, actual, expected)
        hashes[path.name] = actual
    agent = gui.parent / 'APIMonitor_x64.dll'  # 沿用已有合作传输前提，并记录实际Agent身份。
    marker = 'KSWORD_APIMON_COOPERATIVE_SESSION_V1\0'.encode('utf-16-le')
    for path in (cli, gui, agent):
        binary = path.read_bytes()
        assert marker in binary, ('正式镜像缺合作传输标记', path)
        hashes[path.name] = hashlib.sha256(binary).hexdigest()
    hashes['endpoint'] = endpoint
    return hashes


@contextmanager
def artifacts(endpoint, hashes):
    """输入端名及镜像摘要；保存独占回执，已有运行资料不覆盖，日志在异常时保留。"""
    directory = ROOT / endpoint  # 每端固定一个正式运行落点。
    directory.mkdir(exist_ok=False)
    receipt = {'status': 'RUNNING', 'binaries': hashes, 'guiValidated': False}
    try:
        with (directory / 'run.log').open('x', encoding='utf-8', buffering=1) as log:
            with redirect_stdout(log), redirect_stderr(log):
                try:
                    yield directory, receipt
                    receipt.update(status='PASS', guiValidated=True)
                except BaseException:
                    receipt['status'] = 'FAIL'
                    traceback.print_exc()
                    raise
    finally:
        (directory / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
        # 验收表只依据本轮已有回执；截图产生不自动代表深浅、窄窗或双语视觉全覆盖。
        checks = [
            ('正式Release镜像冻结', 'PASS'),
            ('主采集运行进度', 'PASS' if (directory / 'running.json').exists() else '未验'),
            ('停止后同sample行为与32条窗口', 'PASS' if receipt.get('archive') else '未验'),
            ('归档行为根/真实叶/Enter原坐标', 'PASS' if receipt.get('archiveBehaviorTree') else '未验'),
            ('完整项目原地保留', 'PASS' if receipt.get('archiveProject') else '未验'),
            ('进程与临时配置清理/设置恢复', 'PASS' if receipt.get('cleanup') else '未验'),
            ('正式CLI历史只读replay', '待后续，未重跑CLI采集'),
            ('深浅/窄窗/语言切换矩阵', '未验，本批最小场景未扩展矩阵'),
        ]
        table = '| 本轮验收项 | 状态 |\n| --- | --- |\n'
        table += ''.join(f'| {name} | {status} |\n' for name, status in checks)
        (directory / 'acceptance.md').write_text(f'本端结果：{receipt["status"]}\n\n' + table, encoding='utf-8')
        print(f'{endpoint.upper()}_BEHAVIOR_HISTORY={receipt["status"]} RECEIPT={directory / "receipt.json"}', flush=True)


def write_json(directory, name, value):
    """将本轮实际 GUI 回读值写入固定证据文件，不改写产品配置。"""
    (directory / (name + '.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def preserve_project(project, directory, receipt):
    """输入本次自有项目；项目原地保留于清理范围之外，异常时同样不删除唯一原档。"""
    if project.is_dir():
        assert project == directory / 'archived-project', project
        receipt['archiveProject'] = str(project)


def screenshot(pid, directory, name):
    """输入本次 PID 和证据名；PrintWindow 只画该非输入桌面主窗，不使用屏幕或剪贴板。"""
    require_isolated_desktop()
    windows = [window for window in test_windows()
               if win32process.GetWindowThreadProcessId(window)[1] == pid
               and win32gui.IsWindowVisible(window)
               and not win32gui.GetWindow(window, win32con.GW_OWNER)]
    window = max(windows, key=lambda item: (win32gui.GetWindowRect(item)[2] - win32gui.GetWindowRect(item)[0])
                 * (win32gui.GetWindowRect(item)[3] - win32gui.GetWindowRect(item)[1]))
    left, top, right, bottom = win32gui.GetWindowRect(window)  # 原窗口实际边界。
    source = win32gui.GetWindowDC(window)
    source_dc = win32ui.CreateDCFromHandle(source)
    target_dc = source_dc.CreateCompatibleDC()
    bitmap = win32ui.CreateBitmap()
    bitmap.CreateCompatibleBitmap(source_dc, right - left, bottom - top)
    previous = target_dc.SelectObject(bitmap)
    try:
        printer = ctypes.WinDLL('user32', use_last_error=True).PrintWindow
        printer.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint)
        printer.restype = ctypes.c_int
        assert printer(window, target_dc.GetSafeHdc(), 2), 'PrintWindow 失败，截图未验'
        assert len(set(bitmap.GetBitmapBits(True))) > 1, '截图为空，不能算视觉验收'
        bitmap.SaveBitmapFile(target_dc, str(directory / (name + '.bmp')))
    finally:
        target_dc.SelectObject(previous)
        win32gui.DeleteObject(bitmap.GetHandle())
        target_dc.DeleteDC()
        source_dc.DeleteDC()
        win32gui.ReleaseDC(window, source)


def verify_history(entries, total, truncated):
    """输入实际可见历史；核对32条上限、递增坐标及每条自身的释义与证据，返回规范值。"""
    assert total > 0 and len(entries) == min(total, 32), (total, entries)
    assert truncated == (total > len(entries)), (total, truncated)
    previous = (0, 0, 0)  # 窗口必须按原提交顺序呈现。
    for entry in entries:
        coordinate = tuple(entry['coordinate'])
        assert all(value > 0 for value in coordinate) and coordinate > previous, entry
        assert entry['rule'] == 'ksword.api.memory-write-observed.v1', entry
        assert entry['behavior'] == BEHAVIOR and entry['evidence'] == EVIDENCE, entry
        assert entry['summary'] == display_summary(behavior_rule(BEHAVIOR)), entry
        previous = coordinate
    return entries


def verify_archive(project, sample, entries, identity, decoder, reader):
    """以现有Stored解码器核对所有历史原包；返回相对路径摘要和已验证的历史坐标。"""
    digests, packets, _ = reader(project / 'samples' / sample, decoder)
    by_coordinate = {(segment, raw, int(meta['sourceSequence'])): wire
                     for segment, raw, meta, wire in packets}
    for entry in entries:
        wire = by_coordinate[tuple(entry['coordinate'])]
        assert struct.unpack_from('<II', wire, 8) == (identity['pid'], identity['tid'])
        assert wire[96:224].decode('utf-16-le').split('\0', 1)[0] == 'WriteProcessMemory'
        assert struct.unpack_from('<i', wire, 28)[0] == 5
        detail = self_write_detail(wire)  # 复用已更正的AAIP1与legacy解析，不另写协议。
        assert (detail['base'], detail['process'], detail['requested'], detail['completed']) == (
            identity['deniedBase'], identity['queryHandle'], 1, 0), detail
    # Stop排空也可提交普通包；坐标必须逐条匹配其真实Stored原包，不能假定终段永远只含尾记。
    return {'sample': sample, 'segments': {path.relative_to(project).as_posix(): digest for path, digest in digests.items()},
            'packets': len(packets), 'history': entries, 'terminal': len(digests)}


def light_history(value):
    """输入Light原生状态正文；只解析API归档段窗口，最近普通命中另行保留。"""
    total = re.search(r'行为命中数：([0-9]+)', value)
    truncated = re.search(r'行为窗口截断：(是|否)', value)
    if not total or not truncated:
        return None
    pattern = (r'API 归档段：raw/(\d+) #(\d+) · ([^\r\n]+)\r?\n'
               r'合作流水号（非 JSONL 行号）：(\d+)\r?\n行为规则 ID：([^\r\n]+)\r?\n'
               r'行为释义：([^\r\n]+)\r?\nAPI 规则证据：([^\r\n]+)')
    entries = [{'coordinate': [int(segment), int(raw), int(source)], 'rule': api_rule.split(' · ')[-1],
                'behavior': behavior, 'summary': summary, 'evidence': evidence}
               for segment, raw, api_rule, source, behavior, summary, evidence in re.findall(pattern, value)]
    return {'entries': entries, 'total': int(total[1]), 'truncated': truncated[1] == '是'}
