"""通过正式 Qt 工作台采集自有合作目标，并用 CLI 和 Light 只读对账。"""

from base64 import b64encode
import configparser
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
from queue import Queue
import re
import struct
import subprocess
import sys
from threading import Thread
import time
from unittest.mock import patch
from uuid import UUID

import win32api
import win32con
import win32gui
import win32process
import win32service
from pywintypes import error as Win32Error

from live_passive_api import (
    RELEASE, RULE_ID, decode_raw, dispatch, fixture_directory, open_project,
    press, read_table, select_tab, subtree, test_window, unique, until, visible, wait_visible,
)
from api_rule_profile import behavior_rule, display_summary
from cooperative_api_capture import AGENT, CLI, COOPERATIVE_ENV, SCRIPT, cleanup_session, create_session_directory, invoke
from isolated_desktop import launch_gui, require_isolated_desktop, test_windows
from light import archive_etw_preview as light_preview, cooperative_archive_replay
from project_v1 import regular_identity
from relationship_activation import InputUnavailable, post_click
from smoke import invoke as invoke_session


SCRATCH = RELEASE / 'action-analyze-qt-live-cooperative-api-validation'  # 本轮独占的固定 Release 夹具。
BEHAVIOR = 'ksword.behavior.memory-write-access-denied-return.v1'  # 明确拒绝的规则 ID。
EVIDENCE = 'reported-api-return'  # 只验证原包报告的 API 返回，不推断执行或跨进程写入。


def require_inactive_driver():
    """只查询指定服务的状态；不存在或已停止才允许正式窗口继续。"""
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    try:
        try:
            driver = win32service.OpenService(manager, 'KswordARK', win32service.SERVICE_QUERY_STATUS)
        except Win32Error as error:
            if error.winerror == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST；其它查询错误均阻止验收。
                return
            raise
        try:
            state = win32service.QueryServiceStatus(driver)[1]
            assert state == win32service.SERVICE_STOPPED, f'检测到活动 KswordARK 驱动服务（状态 {state}），未启动 Qt'
        finally:
            win32service.CloseServiceHandle(driver)
    finally:
        win32service.CloseServiceHandle(manager)


def select_cooperation(client, nodes, directory):
    """从总览的真实分段栏切至合作 Agent；无桥接动作时才使用本桌面点击。"""
    bar = wait_visible(nodes, 'action_analyze_api_source_mode', lambda item: item['enabled'])
    if 'set_field' in bar['actions']:
        assert bar['tabs'] == ['API JSONL 跟随', '合作 Agent'] and bar['current_index'] == 0, bar
        dispatch(client, 'set_field', object_id=bar['id'], value=1, confirmed=True)
    else:
        click_cooperation(client, directory)
    until(lambda: visible(nodes, 'action_analyze_api_start')['name'], lambda name: name == '开始合作 API 采样')
    assert not any(item['visible'] and item['object_name'] in {
        'action_analyze_api_path', 'action_analyze_api_session', 'action_analyze_api_browse',
    } for item in nodes()), '合作模式仍显示 JSONL 参数'


def click_cooperation(client, directory):
    """复用关系树用例的原生点击；UIA 只提供同桌面本次主窗的命中坐标。"""
    require_isolated_desktop()
    windows = [hwnd for hwnd in test_windows() if win32process.GetWindowThreadProcessId(hwnd)[1] == client.pid
               and win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd).startswith('Qt')
               and not win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE) & win32con.WS_EX_TOOLWINDOW]
    if len(windows) != 1:
        raise InputUnavailable(f'独立桌面可见 Qt 主窗匹配数：{len(windows)}')
    hwnd, = windows  # 不从用户桌面或其它进程寻找窗口。
    output = directory / 'uia-source-tab.json'  # 本轮固定夹具内的临时坐标回执。
    request = json.dumps(dict(hwnd=hwnd, output=str(output)))  # 仅传入已确认的本轮主窗和输出路径。
    command = "$request = ConvertFrom-Json '" + request.replace("'", "''") + "'\n" + r'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$root = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]$request.hwnd)
$name = [System.Windows.Automation.AutomationElement]::NameProperty
$condition = [System.Windows.Automation.PropertyCondition]::new($name, '合作 Agent')
$tabs = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
if ($tabs.Count -ne 1 -or $tabs[0].Current.IsOffscreen) { throw '找不到唯一可见的合作 Agent 分段' }
$rect = $tabs[0].Current.BoundingRectangle
if ($rect.IsEmpty -or $rect.Width -lt 2 -or $rect.Height -lt 2) { throw '合作 Agent 分段没有可点区域' }
ConvertTo-Json -InputObject @([int]($rect.X + $rect.Width / 2), [int]($rect.Y + $rect.Height / 2)) -Compress |
    Set-Content -LiteralPath $request.output -Encoding UTF8
'''
    encoded = b64encode(command.encode('utf-16-le')).decode('ascii')  # Windows PowerShell 的命令编码。
    powershell = Path(win32api.GetSystemDirectory()) / 'WindowsPowerShell/v1.0/powershell.exe'
    probe = launch_gui([powershell, '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden',
                        '-EncodedCommand', encoded], cwd=directory)
    try:
        if probe.wait(8) != 0 or not output.is_file():
            raise InputUnavailable('独立桌面未返回合作 Agent 分段坐标')
    except subprocess.TimeoutExpired as error:
        probe.terminate()  # 只收尾本函数启动的 UIA 读取器。
        probe.wait(5)
        raise InputUnavailable('独立桌面 UIA 查询超时') from error
    post_click(client.pid, hwnd, json.loads(output.read_text(encoding='utf-8-sig')))


@contextmanager
def owned_behavior_target(directory):
    """子进程仅监测自己的常规调用；返回 Popen 和它报告的 PID/FILETIME/缓冲区。"""
    child = subprocess.Popen([sys.executable, '-B', SCRIPT, '--behavior-target'],
                             env=os.environ | {COOPERATIVE_ENV: str(directory)}, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        lines = Queue()  # 有界读取目标首次报告，避免阻塞正式窗口清退。
        reader = Thread(target=lambda: lines.put(child.stdout.readline()), daemon=True)
        reader.start()
        identity = json.loads(lines.get(timeout=10))
        assert child.poll() is None and identity['pid'] == child.pid and identity['creation'] > 0, identity
        assert identity['agentEnabledNs'] >= identity['agentLoadNs'] >= 0, identity
        yield child, identity
    finally:
        if child.stdin and not child.stdin.closed:
            child.stdin.close()  # 只通过 EOF 让本次目标自行退出。
        child.wait(timeout=10)
        for stream in (child.stdout, child.stderr):
            stream.close()
        print(f'OWNED_TARGET_EXIT={child.returncode}', flush=True)


def read_receipt(client, pane):
    """从总览回执根读取真实可见的字段模型，兼容平铺和按组投影。"""
    tables = [item for item in subtree(client, pane, depth=6, max_nodes=120)
              if item['visible'] and item['type'] == 'item_view']
    if not tables:
        return {}
    table, = tables
    root_rows = read_table(client, table)['rows']
    rows = list(root_rows)
    for index, row in enumerate(root_rows):
        if row and row[0] in {'合作 Agent 来源', 'API 规则回执'}:
            rows.extend(read_table(client, table, [index])['rows'])
    return {str(row[0]): str(row[1]) for row in rows if len(row) >= 2}


def capture(client, nodes, session, child, identity, manifest):
    """用实际 Start/Stop 采一次，返回终态回执及用于验证停止前原包的时间边界。"""
    for suffix, value in (('pid', child.pid), ('creation', identity['creation'])):
        name = 'action_analyze_api_' + suffix  # 使用本轮自有子进程的真实十进制身份。
        field = visible(nodes, name)
        dispatch(client, 'set_field', object_id=field['id'], value=str(value), confirmed=True)
        assert visible(nodes, name)['value'] == str(value), field
    assert child.poll() is None and not list(session.iterdir()), session
    config = session / f'config_{child.pid}_{identity["creation"]}.ini'  # PID 与创建代次共同限定文件。
    marker = session / f'stop_{child.pid}_{identity["creation"]}.flag'
    pane = visible(nodes, 'action_analyze_api_receipt')  # 绑定本次真实窗口回执，不读产品内部所有者。
    start = visible(nodes, 'action_analyze_api_start')
    start_filetime = 116444736000000000 + time.time_ns() // 100  # 与 Agent 原包相同的 Windows UTC 历元。
    press(client, start)
    until(config.is_file, bool)
    regular_identity(config)
    ini = configparser.ConfigParser(interpolation=None)
    ini.read_string(config.read_text(encoding='utf-16'))
    settings = ini['monitor']
    session_label = settings['session_id']  # 当前公共采集器的会话名字和 PID 前缀。
    assert session_label.startswith(f'cli_{client.pid}_'), config
    assert all(Path(settings[key]) == marker for key in ('stop_flag_path', 'root_stop_flag_path')), settings
    assert settings['auto_inject_child'] == '0' and not settings['injection_broker_pipe'], settings
    assert not marker.exists(), marker
    print(f'QT_COOPERATIVE_CONFIG_PUBLISHED={config.name} CONTROLLER_PID={client.pid}', flush=True)

    # 在正式窗口捕获运行期回执，终态须保存同一个实际覆盖修订。
    pattern = re.compile(r'Agent 已就绪 · 覆盖修订 ([1-9]\d*) · 正在采样')  # 界面的实际十进制修订号。
    busy = until(lambda: visible(nodes, 'action_analyze_api_status')['name'], pattern.fullmatch)
    revision = pattern.fullmatch(busy)[1]
    assert child.poll() is None and not marker.exists(), busy
    time.sleep(2)  # 保留接收自有目标普通事件的采样窗口。
    stop = visible(nodes, 'action_analyze_api_stop')
    stop_filetime = 116444736000000000 + time.time_ns() // 100
    press(client, stop)
    status = until(lambda: visible(nodes, 'action_analyze_api_status')['name'],
                   lambda text: text.startswith('合作 API 采样已结束'), timeout=20)
    assert child.poll() is None and not visible(nodes, 'action_analyze_api_stop')['enabled'], status
    fields = until(lambda: read_receipt(client, pane), lambda values: values.get('已清退') == '是')
    expected = {'Agent 已就绪': '是', '就绪覆盖修订': revision, '已确认停钩': '是',
                '管道正常读完': '是', '目标已退出': '否', '已清退': '是'}
    assert expected.items() <= fields.items() and '采样诊断' not in fields, fields
    assert (fields['来源 PID'], fields['进程创建 FILETIME']) == (str(child.pid), str(identity['creation'])), fields
    # 会话字符串在协议中按 UTF-16 码元作 FNV-1a；此处生成的标签只含 ASCII。
    session_id = 14695981039346656037
    for value in session_label.encode('ascii'):
        session_id = ((session_id ^ value) * 1099511628211) & ((1 << 64) - 1)
    assert Path(fields['项目清单']) == manifest and fields['来源会话 ID'] == str(session_id or 1), fields
    assert str(UUID(fields['采样 ID'])) == fields['采样 ID'], fields
    assert int(fields['已核验普通包']) >= int(fields['已归档原包']) >= 2 and int(fields['已核验段号']) > 0, fields
    regular_identity(marker)
    assert marker.read_bytes() == b'stop', marker
    print(f'QT_COOPERATIVE_STOP={status} AGENT_READY=True HOOKS_REMOVED=True PIPE_EOF=True CLEANUP=True '
          f'READY_COVERAGE_REVISION={revision} '
          f'SAMPLE={fields["采样 ID"]} SESSION={fields["来源会话 ID"]} '
          f'PACKETS={fields["已核验普通包"]} COMMITTED_PACKETS={fields["已归档原包"]} SEGMENTS={fields["已核验段号"]} '
          f'REQUEST_TO_STOP_MS={(stop_filetime - start_filetime) / 10000:.3f}', flush=True)
    return fields, (start_filetime, stop_filetime)


def owned_denial(project, fields, identity, lifetime):
    """独立读取已提交 Stored 段，定位 Stop 前本轮自有缓冲区的真实拒绝包。"""
    sample = fields['采样 ID']  # 只读取本轮窗口回执指向的冻结采样。
    digests, packets, last_raw = cooperative_archive_replay.read_cooperative_archive(project / 'samples' / sample, decode_raw)
    assert (len(digests), len(packets)) == (int(fields['已核验段号']), int(fields['已归档原包'])), fields
    for witness in reversed(packets):
        ordinal, raw, metadata, packet = witness  # 原包带有自身段号、全局序号及合作流水号。
        _, version, pid, tid, timestamp, _, status = struct.unpack_from('<IIIIQIi', packet)
        api = packet[96:224].decode('utf-16-le').split('\0', 1)[0]
        if (pid, tid, api, status) != (identity['pid'], identity['tid'], 'WriteProcessMemory', 5):
            continue
        detail = dict(item.split('=', 1) for item in packet[224:864].decode('utf-16-le').split('\0', 1)[0].split())
        if int(detail['base'], 16) != identity['deniedBase'] or not lifetime[0] <= timestamp < lifetime[1]:
            continue
        assert int(detail['process'], 16) == identity['queryHandle'] and (detail['size'], detail['written']) == ('1', '0'), detail
        assert version == 0x20261003 and str(struct.unpack_from('<Q', packet, 896)[0]) == fields['来源会话 ID']
        print(f'QT_COOPERATIVE_PRE_STOP_PACKET=PASS RAW={ordinal}#{raw} SOURCE={metadata["sourceSequence"]} '
              f'FILETIME={timestamp} SEGMENT_SHA256={list(digests.values())[ordinal - 1]}', flush=True)
        return witness, digests, packets, last_raw
    raise AssertionError('没有找到 Stop 前来自自有目标的明确访问拒绝原包')


def verify_project(client, nodes, fields, identity, denial):
    """在真实项目目录按采样 UUID 选中行，核对项目规则页同一拒绝坐标。"""
    sample = fields['采样 ID']
    select_tab(client, nodes, '项目与采样')
    views = [item for item in nodes() if item['visible'] and item['class'] == 'QTableView']
    catalog = unique(views, lambda item: '采样名称' in read_table(client, item)['headers'])
    listing = until(lambda: read_table(client, catalog), lambda table: any(sample in row for row in table['rows']))
    index, = (index for index, row in enumerate(listing['rows']) if sample in row)
    assert f'合作 Agent（PID {identity["pid"]}）' in listing['rows'][index], listing
    dispatch(client, 'select_row', object_id=catalog['id'], row=index, revision=listing['revision'], confirmed=True)
    press(client, wait_visible(nodes, 'action_analyze_sample_rule_replay', lambda item: item['enabled']))
    wrapper = wait_visible(nodes, 'ks_behavior_rule_receipt')
    editor = wait_visible(lambda: subtree(client, wrapper, depth=4, max_nodes=120), 'code_editor_text')
    assert editor['read_only'], editor

    def report_part(offset, length):
        """按 UTF-16 文档坐标读取片段及全文长度。"""
        return client.call('read_text', {'object_id': editor['id'], 'offset': offset, 'length': length})['data']

    ordinal, raw, metadata, _ = denial[0]  # 使用拒绝包的实际归档坐标和流水号。
    source = metadata['sourceSequence']
    explanation = display_summary(behavior_rule(BEHAVIOR))  # 源码规则定义提供界面释义。
    hit = (f'raw/{ordinal} #{raw} · 合作流水号 {source} · WriteProcessMemory · ksword.api.memory-operation-observed.v1'
           f' · {RULE_ID} · {BEHAVIOR} · {EVIDENCE} · {explanation}')
    terminal = f'已核验采样归档至终段 raw/{fields["已核验段号"]}。'  # 从同一次采集的终态回执确认终段。
    header = until(lambda: report_part(0, 512), lambda part: sample in part['text'] and terminal in part['text'])
    tail_length = 65536  # 拒绝见证从最后发布的普通包向前定位。
    tail = report_part(max(0, header['total_length'] - tail_length), tail_length)
    assert hit in tail['text'].splitlines(), hit
    print(f'QT_COOPERATIVE_PROJECT_READBACK=PASS SAMPLE={sample} RAW={ordinal}#{raw} SOURCE={source}', flush=True)


def verify_cli(project, fields, identity, denial):
    """用正式 CLI 只读回放本轮原包，并证明回放前后该 Stored 段字节相同。"""
    sample = fields['采样 ID']
    witness, digests, packets, _ = denial  # 比较整条已发布段链和目标原包。
    ordinal, raw, _, packet = witness
    row, offset, clues = cooperative_archive_replay.replay_witness(invoke, project, sample, witness, digests, packets)
    assert int(fields['已归档原包']) >= clues >= int(fields['已提交命中行']) > 0, fields
    assert (row['pid'], row['tid'], row['archivedCallerCreation100ns'], row['sourceSessionIdentity']) == (
        identity['pid'], identity['tid'], str(identity['creation']), fields['来源会话 ID']), row
    assert (row['family'], row['phase'], row['reportedStatusCode']) == ('memory-write', 'return', 5), row
    assert int(row['reportedReturnBits'], 16) == 0 and row['targetIdentity'] is None, row
    cooperative_archive_replay.verify_cli_behavior(invoke, project, sample, row, offset, denied=True)
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in digests.items())
    print(f'CLI_COOPERATIVE_READ_ONLY=PASS SAMPLE={sample} RAW={ordinal}#{raw} SOURCE={row["sourceSequence"]} '
          f'PACKET_SHA256={hashlib.sha256(packet).hexdigest()}', flush=True)
    return row


def main():
    """仅在正式构建之后由 CodeBuddy 经独立桌面启动；清理后输出最终回执。"""
    require_isolated_desktop()
    assert __debug__ and struct.calcsize('P') == 8 and sys.argv[1:] in ([], ['--readiness-only'])
    readiness_only = sys.argv[1:] == ['--readiness-only']  # 只重验本次改动的启动屏障和对应普通包。
    require_inactive_driver()
    binaries = [RELEASE / 'Ksword5.1.exe', AGENT, CLI]  # 就绪用例不启动只读 Light 回放。
    if not readiness_only:
        binaries.append(RELEASE / 'KswordARKLight.exe')
    for image in binaries:
        binary = image.read_bytes()  # 旧 Agent/Qt 可能不识别私有目录；不启动此类产物。
        assert (COOPERATIVE_ENV + '\0').encode('utf-16-le') in binary, f'缺少合作模式：{image}'
        print(f'{image.name}_SHA256={hashlib.sha256(binary).hexdigest()}', flush=True)
    with fixture_directory(SCRATCH) as directory:
        project = directory / 'project'  # 专供本轮的空项目；CLI 不发起任何采集。
        command = f'project create "{project}" "Qt cooperative API fixture"\nquit\n'.encode('utf-8')
        stdout, stderr = invoke_session(('analyze', 'session', '--backend', 'offline'), command, label='create owned project')
        manifest = project / 'project.ksaproj'
        assert not stderr and b'error:' not in stdout and manifest.is_file(), (stdout, stderr)
        session = directory / 'KswordApiMonCooperative'
        create_session_directory(session)  # 复用 CLI 的原子私有 DACL 创建；不改系统共享目录。
        session_identity = regular_identity(session)
        controller_pid = identity = None
        try:
            with patch.dict(os.environ, {COOPERATIVE_ENV: str(session)}), test_window() as client:
                controller_pid = client.pid  # cleanup_session 以发布方的真实 PID 复核配置归属。
                nodes = open_project(client, manifest)
                until(nodes, lambda items: any(item['visible'] and '项目目录已读取，尚无采样。' in item['name'] for item in items))
                select_tab(client, nodes, '总览')
                overview = wait_visible(nodes, 'action_analyze_overview')

                def overview_nodes():
                    """从总览根读取参数与回执，避免无关页面耗尽快照。"""
                    return subtree(client, overview, depth=16, max_nodes=800)

                press(client, visible(overview_nodes, 'action_analyze_api_capture'))
                select_cooperation(client, overview_nodes, directory)
                with owned_behavior_target(session) as (child, identity):
                    fields, lifetime = capture(client, overview_nodes, session, child, identity, manifest)
                    tail, error = child.communicate(timeout=10)  # 证明采集已清退之后目标才收到 EOF。
                    assert child.returncode == 0 and not error and json.loads(tail)['agentLoaded'], (tail, error)
                denial = owned_denial(project, fields, identity, lifetime)
                if not readiness_only:
                    verify_project(client, nodes, fields, identity, denial)
            if not readiness_only:
                row = verify_cli(project, fields, identity, denial)
                witness, digests, _, last_raw = denial  # 从目录首段进入，见证可落在任意已发布段。
                ordinal, raw, metadata, _ = witness
                segment = next(iter(digests))
                distance = last_raw - raw
                require_inactive_driver()
                cooperative_archive_replay.verify_light(light_preview, segment, row, distance, denied_only=True)
                assert all(hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in digests.items())
                require_inactive_driver()
                print(f'LIGHT_COOPERATIVE_READ_ONLY=PASS SAMPLE={fields["采样 ID"]} RAW={ordinal}#{raw} '
                      f'SOURCE={metadata["sourceSequence"]}', flush=True)
        finally:
            assert regular_identity(session) == session_identity, session
            if identity is not None:
                cleanup_session(session, identity['pid'], identity['creation'], controller_pid)
            assert not list(session.iterdir()), session
            session.rmdir()
            print('COOPERATIVE_SESSION_DIRECTORY_REMOVED=True', flush=True)
    print(f'QT_LIVE_COOPERATIVE_API=PASS SAMPLE={fields["采样 ID"]}', flush=True)


if __name__ == '__main__':
    main()
