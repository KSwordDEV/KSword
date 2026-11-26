"""Verify Light's write watch against the existing opted-in AMD64 fixture."""

import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys

from live_cooperative_api import require_idle_environment
from live_project_preview import BINARY, con, control, gui, light_window, set_text, text, wait_for
from isolated_desktop import require_isolated_desktop

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cli'))
from product_breakpoint_long_run import (INT_DIR, REPO, CloseHandle, GetExitCode, GetProcessIdOfThread,
                                        GetThreadTimes, OpenThread, SetEvent, TerminateProcess, Wait,
                                        WAIT_OBJECT, WAIT_TIMEOUT, attached, checked_target, fingerprint,
                                        installed_fixture, write_watch_events)


TAB = 58400
CONTROLS = dict(path=58401, browse=58402, export=58403, bytes=58404,
                start=58405, resume=58406, close=58407, status=58408)
TARGET_ID = re.compile(r'\r\nPID ([1-9]\d*) · 创建 FILETIME ([1-9]\d*)')
THREAD_ID = re.compile(r'\r\n触发线程 TID ([1-9]\d*) · 创建 FILETIME ([1-9]\d*)')
STOP = re.compile(r'\r\n当前停点令牌 (\S+) · 修订 ([1-9]\d*)\r\n停止组 (\S+)\r\n原生事件 (\S+) / ([1-9]\d*)')
CHANGE = re.compile(r'\r\n变化字节掩码 (0x[0-9A-F]+) · 登记时最近停点序号 (\d+)')


def fields(pattern, receipt):
    match = pattern.search(receipt)
    assert match, receipt
    return match.groups()


def enter_watch(page):
    page.default_page()
    tabs = wait_for('ActionAnalyze nested tabs', lambda: control(page.main, TAB))
    assert gui.SendMessage(tabs, 0x130B, 0, 0) == 0  # TCM_GETCURSEL
    gui.SendMessage(tabs, con.WM_KEYDOWN, con.VK_RIGHT, 0)
    assert gui.SendMessage(tabs, 0x130B, 0, 0) == 1
    start = wait_for('write watch start button', lambda: control(tabs, CONTROLS['start']))
    owner = gui.GetParent(start)
    assert gui.IsWindowVisible(owner)
    page.controls.update({name: control(owner, identifier) for name, identifier in CONTROLS.items()})
    assert all(page.controls[name] and gui.IsWindowVisible(page.controls[name]) for name in CONTROLS), page.controls
    return tabs


def check_hit(page, identity, trigger, done, mask, enrolled):
    assert SetEvent(trigger)
    receipt = page.wait_status('write stop', lambda value: value.startswith('写入停点已命中'))
    assert tuple(map(int, fields(TARGET_ID, receipt))) == identity, receipt
    token = fields(STOP, receipt)
    raw_mask, enrollment = fields(CHANGE, receipt)
    assert (int(raw_mask, 16), int(enrollment)) == (mask, enrolled), receipt
    assert Wait(done, 0) == WAIT_TIMEOUT and gui.IsWindowEnabled(page.controls['resume']), receipt
    tid, creation = map(int, fields(THREAD_ID, receipt))
    thread = OpenThread(0x800, False, tid)  # THREAD_QUERY_LIMITED_INFORMATION
    assert thread, C.get_last_error()
    try:
        created, exited, kernel, user = (W.FILETIME() for _ in range(4))
        assert GetProcessIdOfThread(thread) == identity[0]
        assert GetThreadTimes(thread, C.byref(created), C.byref(exited), C.byref(kernel), C.byref(user))
        assert (created.dwHighDateTime << 32) | created.dwLowDateTime == creation, receipt
    finally:
        assert CloseHandle(thread)
    print(f'LIGHT_WRITE_STOP={json.dumps(receipt)}', flush=True)
    return token, (tid, creation)


def exact_child(receipt):
    pid, creation = fields(TARGET_ID, receipt)
    return (int(pid), int(creation)), checked_target(dict(targetPid=int(pid), targetCreationFileTime=creation))


def verify(target, env, events):
    ready, trigger, done = events
    child = None
    try:
        with light_window(env=os.environ | env) as page:
            tabs = enter_watch(page)
            assert page.status() == '尚未启动'
            assert not gui.IsWindowEnabled(page.controls['resume']) and not gui.IsWindowEnabled(page.controls['close'])
            page.browse('browse', '选择合作写入停点目标', target)
            assert text(page.controls['path']) == str(target)
            set_text(page.controls['export'], 'WatchedData')
            size = page.controls['bytes']
            assert gui.SendMessage(size, con.CB_GETCURSEL, 0, 0) == 2 and text(size, con.CB_GETLBTEXT, 2) == '4'
            page.click('start')
            started = page.wait_status('frozen target identity', lambda value: bool(TARGET_ID.search(value)))
            identity, child = exact_child(started)
            armed = page.wait_status('armed write watch', lambda value: value.startswith('已设写入停点'))
            assert tuple(map(int, fields(TARGET_ID, armed))) == identity and 'WatchedData · 范围 4 B' in armed, armed
            assert Wait(ready, 5000) == WAIT_OBJECT and attached(child), armed
            assert all(not gui.IsWindowEnabled(page.controls[name]) for name in ('browse', 'export', 'bytes', 'start', 'resume'))
            assert SetEvent(trigger) and Wait(done, 5000) == WAIT_OBJECT, 'outside-range and same-value writes did not finish'
            assert page.status().startswith('已设写入停点') and not gui.IsWindowEnabled(page.controls['resume'])

            first, first_thread = check_hit(page, identity, trigger, done, 1, 0)
            gui.SendMessage(page.controls['resume'], con.WM_KEYDOWN, con.VK_RETURN, 0)
            assert Wait(done, 5000) == WAIT_OBJECT, 'the first write did not finish after Continue'
            resumed = page.wait_status('watch rearmed after Continue', lambda value: value.startswith('已设写入停点'))
            assert '最近停点令牌 ' + first[0] in resumed and not STOP.search(resumed), resumed

            gui.SendMessage(tabs, con.WM_KEYDOWN, con.VK_LEFT, 0)
            assert gui.SendMessage(tabs, 0x130B, 0, 0) == 0 and not gui.IsWindowVisible(page.controls['status'])
            gui.SendMessage(tabs, con.WM_KEYDOWN, con.VK_RIGHT, 0)
            assert gui.SendMessage(tabs, 0x130B, 0, 0) == 1 and gui.IsWindowVisible(page.controls['status'])
            second, second_thread = check_hit(page, identity, trigger, done, 8, 1)
            assert first[0] != second[0] and first[2] != second[2] and first[3] == second[3] and int(first[4]) < int(second[4])
            assert first_thread[0] != second_thread[0] and first_thread[1] < second_thread[1]

            page.click('close')
            closed = page.wait_status('confirmed detach', lambda value: value.startswith('清退已确认 · 已脱离')
                                      and gui.IsWindowEnabled(page.controls['start']))
            assert tuple(map(int, fields(TARGET_ID, closed))) == identity, closed
            assert '已登记线程 0' in closed and '最近停点令牌 ' + second[0] in closed, closed
            assert not STOP.search(closed) and all(not gui.IsWindowEnabled(page.controls[name]) for name in ('resume', 'close'))
            assert Wait(done, 5000) == WAIT_OBJECT and not attached(child), closed
            assert SetEvent(trigger) and Wait(done, 5000) == WAIT_OBJECT and Wait(child, 5000) == WAIT_OBJECT
            code = W.DWORD()
            assert GetExitCode(child, C.byref(code)) and code.value == 0, code.value
            print(f'LIGHT_WRITE_CLOSED={json.dumps(closed)}', flush=True)
            print('OWNED_TARGET_EXIT=0 OUTSIDE_RANGE=CONTINUED SAME_VALUE=CONTINUED DETACHED_WRITE=DONE', flush=True)
    finally:
        if child:
            try:
                # Use the single fixture handle whose image and creation time were checked above.
                if Wait(child, 0) == WAIT_TIMEOUT:
                    assert TerminateProcess(child, 3) and Wait(child, 5000) == WAIT_OBJECT
            finally:
                assert CloseHandle(child)


def main():
    require_isolated_desktop()
    assert __debug__, 'Fixture assertions must be enabled'
    driver = require_idle_environment()
    light_hash = fingerprint(BINARY)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    evidence = REPO / '.codex-build-logs' / f'light-data-write-watch-fixture-{stamp}.log'
    evidence.parent.mkdir(parents=True, exist_ok=True)
    with evidence.open('x', encoding='utf-8', buffering=1) as log:
        with installed_fixture(log) as target, write_watch_events() as (env, events):
            fixture_hash = fingerprint(target)
            print(f'LIGHT_WRITE_FIXTURE={target} SHA256={fixture_hash} BUILD_LOG={evidence}', flush=True)
            verify(target, env, events)
    assert not target.exists() and not INT_DIR.exists()
    assert require_idle_environment() == driver and fingerprint(BINARY) == light_hash
    print(f'LIGHT_DATA_WRITE_WATCH=PASS LIGHT_SHA256={light_hash} FIXTURE_SHA256={fixture_hash} '
          f'DRIVER={driver} FIXTURE_CLEANED=true', flush=True)


if __name__ == '__main__':
    main()
