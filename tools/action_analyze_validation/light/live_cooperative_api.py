"""Validate the real Light cooperative capture controls on the isolated desktop."""

from contextlib import contextmanager
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from queue import Queue
import re
import struct
import subprocess
import sys
from threading import Thread
from uuid import UUID

import pywintypes
import win32service

from live_passive_api import (API_CONTROLS, BINARY, CREATE_TITLE, SCRATCH, con, control, decode_raw,
                             gui, light_window, owned_scratch, require_isolated_desktop, set_text, text, wait_for)
from continuous_etw import regular_identity
from cooperative_api_capture import (BUFFER_SIZE, COOPERATIVE_ENV, SCRIPT, cleanup_session,
                                     create_session_directory, invoke, winapi)
from cooperative_archive_replay import (ARCHIVE_SOURCE, OPT_IN, check_images, expected_behavior_lines,
                                        read_cooperative_archive, replay_witness, verify_cli_behavior)

READY_RECEIPT = re.compile(r'\r\n源会话 ([1-9]\d*) · 就绪覆盖修订 ([1-9]\d*)\b')


def require_idle_environment():
    for image in ('KswordARKLight.exe', 'Ksword5.1.exe'):
        listing = subprocess.run(['tasklist.exe', '/fi', f'IMAGENAME eq {image}', '/fo', 'csv', '/nh'],
                                 check=True, capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        assert f'"{image}"'.lower().encode('ascii') not in listing.stdout.lower(), f'BLOCKED: {image} is running'
    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    try:
        try:
            driver = win32service.OpenService(scm, 'KswordARK', win32service.SERVICE_QUERY_STATUS)
        except pywintypes.error as error:
            if error.winerror != 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
                raise
            return 'absent'
        try:
            state = win32service.QueryServiceStatus(driver)[1]
            assert state == win32service.SERVICE_STOPPED, f'BLOCKED: KswordARK service state={state}'
            return 'stopped'
        finally:
            win32service.CloseServiceHandle(driver)
    finally:
        win32service.CloseServiceHandle(scm)


@contextmanager
def behavior_target(environment):
    with subprocess.Popen([sys.executable, '-B', SCRIPT, '--behavior-target'], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                          creationflags=subprocess.CREATE_NO_WINDOW) as process:
        lines = Queue()
        Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
        try:
            identity = json.loads(lines.get(timeout=10))
            assert identity['pid'] == process.pid and identity['creation'] > 0, identity
            yield process, identity
        finally:
            tail, error = process.communicate(timeout=10)  # EOF ends only this owned target.
            assert process.returncode == 0 and json.loads(tail)['agentLoaded'], (process.returncode, tail, error)
            print(f'OWNED_TARGET_EXIT={process.returncode} {tail.decode().strip()}', flush=True)


def wait_for_owned_calls(process, identity):
    kernel = C.WinDLL('kernel32', use_last_error=True)
    read = winapi(kernel, 'ReadProcessMemory', W.BOOL, W.HANDLE, C.c_void_p, C.c_void_p,
                  C.c_size_t, C.POINTER(C.c_size_t))
    handle = winapi(kernel, 'OpenProcess', W.HANDLE, W.DWORD, W.BOOL, W.DWORD)(0x0010, False, process.pid)
    if not handle:
        raise C.WinError(C.get_last_error())
    try:
        data, count = C.create_string_buffer(BUFFER_SIZE), C.c_size_t()

        def progress():
            assert process.poll() is None, 'Owned target exited during the capture'
            if not read(handle, identity['base'], data, BUFFER_SIZE, C.byref(count)):
                raise C.WinError(C.get_last_error())
            assert count.value == BUFFER_SIZE
            observed = data.raw.rstrip(b'\0')
            assert observed == b'Z' * len(observed), 'Unexpected bytes in the owned fixture buffer'
            return len(observed)

        before = progress()
        # The next successful byte proves the previous iteration finished its denial check.
        after = wait_for('owned behavior calls after config publication', lambda: (n := progress()) >= before + 120 and n)
        print(f'OWNED_BEHAVIOR_PROGRESS={before}->{after}', flush=True)
    finally:
        assert winapi(kernel, 'CloseHandle', W.BOOL, W.HANDLE)(handle)


def capture(page, directory, process, identity):
    page.controls.update({name: control(page.page, cid) for name, cid in (API_CONTROLS | {'source': 58332}).items()})
    assert all(page.controls.values()), page.controls
    page.click('switch')
    page.click('mode')
    source = page.controls['source']
    assert gui.IsWindowVisible(source) and text(source, con.CB_GETLBTEXT, 0) == 'JSONL 跟随'
    assert gui.SendMessage(source, con.CB_GETCURSEL, 0, 0) == 0
    gui.SendMessage(source, con.WM_KEYDOWN, con.VK_DOWN, 0)
    assert gui.SendMessage(source, con.CB_GETCURSEL, 0, 0) == 1 and text(source, con.CB_GETLBTEXT, 1) == '合作 Agent'
    assert text(page.controls['start']) == '开始采集'
    assert all(not gui.IsWindowVisible(page.controls[name]) for name in ('provider', 'session', 'browse_api', 'api_path'))
    assert not READY_RECEIPT.search(page.status()), page.status()
    pid, creation = identity['pid'], identity['creation']
    set_text(page.controls['api_pid'], str(pid))
    set_text(page.controls['creation'], str(creation))
    config = directory / f'config_{pid}_{creation}.ini'
    assert not any(directory.iterdir()), directory
    page.click('start')
    wait_for('private cooperative config', config.is_file)
    ready = page.wait_status('verified live cooperative readiness', lambda value: bool(READY_RECEIPT.search(value)))
    session, revision = READY_RECEIPT.search(ready).groups()
    target = f'PID {pid} · 创建 FILETIME {creation}'
    assert f'合作 Agent · 采集中 · {target}' in ready and '已核验回读 ' not in ready, ready
    assert gui.IsWindowEnabled(page.controls['stop']) and page.row_count() == 0, ready
    assert all(not gui.IsWindowEnabled(page.controls[name]) for name in ('source', 'api_pid', 'creation', 'start')), ready
    print(f'LIGHT_COOPERATIVE_READY={json.dumps(ready)}', flush=True)
    wait_for_owned_calls(process, identity)
    page.click('stop')
    result = page.wait_status('cooperative terminal receipt', lambda value: '已核验回读 ' in value and
                              not gui.IsWindowEnabled(page.controls['stop']))
    expected = (target, '部分完成', '已响应停止请求', '连接 已核验', '握手 已确认',
                '启动 已确认', '安装 Hook 已确认', '正常 EOF 已确认', '停钩 已确认', '清退 已确认')
    assert all(part in result for part in expected) and '目标已退出' not in result, result
    assert process.poll() is None, 'Target did not survive Stop'
    assert (directory / f'stop_{pid}_{creation}.flag').read_bytes() == b'stop'
    sample = re.search(r'\r\n采样 ([0-9a-f-]{36})', result)[1]
    assert str(UUID(sample)) == sample
    finished = READY_RECEIPT.search(result)
    assert finished and finished.groups() == (session, revision) and '采集中' not in result, (ready, result)
    # 从终态回执分别取累计普通包、累计线索和实际终段。
    count, terminal = map(int, re.search(r'已核验回读 (\d+) 条线索 · raw/([1-9]\d*)', result).groups())
    ordinary, committed = map(int, re.search(r'普通调用 (\d+) · 已提交 (\d+) 包', result).groups())
    assert ordinary >= committed >= count > 0, result
    print(f'LIGHT_COOPERATIVE_TERMINAL={json.dumps(result)}', flush=True)
    return sample, session, count, terminal, committed


def replay(page, project, sample, session, count, terminal, committed, identity):
    """按本轮采样和终段对账，并在 Light API 筛选结果中定位原包。"""
    digests, packets, _ = read_cooperative_archive(project / 'samples' / sample, decode_raw)
    assert (len(digests), len(packets)) == (terminal, committed)
    for witness in reversed(packets):
        ordinal, seq, meta, packet = witness  # 读取每个包的实际段号和 Stored 序号。
        if (struct.unpack_from('<II', packet, 8) == (identity['pid'], identity['tid'])
                and packet[96:224].decode('utf-16-le').split('\0', 1)[0] == 'WriteProcessMemory'
                and struct.unpack_from('<i', packet, 28)[0] == 5):
            break
    else:
        raise AssertionError('The owned access-denied call was not archived')
    fields = dict(item.split('=', 1) for item in packet[224:864].decode('utf-16-le').split('\0', 1)[0].split())
    assert (int(fields['base'], 16), int(fields['process'], 16), fields['size'], fields['written']) == (
        identity['deniedBase'], identity['queryHandle'], '1', '0'), fields
    source = meta['sourceSequence']
    row, offset, clues = replay_witness(invoke, project, sample, witness, digests, packets)
    assert clues == count
    assert (row['sourceSessionIdentity'], row['archivedCallerCreation100ns'], row['reportedStatusCode'],
            int(row['reportedReturnBits'], 16)) == (session, str(identity['creation']), 5, 0), row
    verify_cli_behavior(invoke, project, sample, row, offset, denied=True)

    page.click('replay_current')
    page.wait_status('Light opened this capture', lambda s: sample in s and '当前归档' in s and '正在读取' not in s)
    assert set(page.sample_entries()) == {sample}
    page.click('api_only')
    records_hwnd = page.controls['records']
    distance = count - 1 - offset  # 筛选表仅含线索，按见证之后的线索数倒推出可见行。
    assert distance < page.row_count() <= count
    gui.SendMessage(records_hwnd, con.WM_KEYDOWN, con.VK_END, 0)
    for _ in range(distance):
        gui.SendMessage(records_hwnd, con.WM_KEYDOWN, con.VK_UP, 0)
    shown = text(page.controls['detail']).splitlines()
    assert {f'当前归档 · 采样：{sample}', 'WriteProcessMemory', f'未解析候选 · raw/{ordinal} #{seq}',
            f'归档输入类型（尾记声明）：{ARCHIVE_SOURCE}', f'合作流水号（非 JSONL 行号）：{source}'} <= set(shown), shown
    assert expected_behavior_lines() <= set(shown) and not any(line.startswith('源归档行号：') for line in shown), shown
    assert shown[-1].startswith(packet[:128].hex(' ')), shown
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in digests.items())
    return ordinal, seq, source, hashlib.sha256(packet).hexdigest()


def main():
    require_isolated_desktop()
    assert __debug__, 'Fixture assertions must be enabled'
    driver = require_idle_environment()
    check_images()
    binary = BINARY.read_bytes()
    assert OPT_IN in binary, f'Formal Light must include cooperative transport: {BINARY}'
    binary_hash = hashlib.sha256(binary).hexdigest()
    with owned_scratch(SCRATCH) as scratch:
        directory = scratch / 'KswordApiMonCooperative'
        project = scratch / 'owned project'
        create_session_directory(directory)
        original = regular_identity(directory)
        environment = os.environ | {COOPERATIVE_ENV: str(directory)}
        pid = identity = None
        try:
            with light_window(env=environment) as page:
                pid = page.process.pid
                page.default_page()
                page.browse('create', CREATE_TITLE, project)
                page.wait_status('new owned project', lambda value: '已新建工程 · ' in value and '工程尚无采样' in value)
                with behavior_target(environment) as (process, identity):
                    sample, session, count, terminal, committed = capture(page, directory, process, identity)
                ordinal, seq, source, packet = replay(page, project, sample, session, count, terminal, committed, identity)
        finally:
            if identity is not None:
                cleanup_session(directory, identity['pid'], identity['creation'], pid)
            assert regular_identity(directory) == original and not any(directory.iterdir()), directory
            directory.rmdir()
    assert require_idle_environment() == driver and hashlib.sha256(BINARY.read_bytes()).hexdigest() == binary_hash
    print(f'LIGHT_COOPERATIVE_API=PASS SAMPLE={sample} RAW={ordinal}#{seq} SOURCE={source} '
          f'SEGMENTS={terminal} PACKETS={committed} CLUES={count} PACKET_SHA256={packet} '
          f'LIGHT_SHA256={binary_hash} DRIVER={driver}', flush=True)


if __name__ == '__main__':
    main()
