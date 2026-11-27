"""Light真实主采集最小验收；只在主协调CLI新包实测后经isolated_desktop.py放行。"""

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
import re
import sys

# 独立桌面启动器已加入本端目录；先复用原Light脚本建立其现有依赖路径。
import live_cooperative_api as existing
from cooperative_api_capture import CLI, COOPERATIVE_ENV, cleanup_session, create_session_directory
from continuous_etw import owned_scratch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'desktop_behavior_history'))
from support import artifacts, light_history, preserve_project, release_arguments, screenshot, verify_archive, verify_history, write_json


@contextmanager
def owned_target(page, environment):
    """复用原合作目标；失败时先停止此页本次采集，避免目标EOF早于owner归还。"""
    with existing.behavior_target(environment) as target:
        try:
            yield target
        finally:
            if existing.gui.IsWindowEnabled(page.controls['stop']):
                page.click('stop')
                page.wait_status('异常路径采集清退', lambda value:
                    not existing.gui.IsWindowEnabled(page.controls['stop']))


def capture(page, session, process, identity, directory):
    """输入真实Light工作台及自有源；经原生控件开始/停止，返回同sample终态及历史。"""
    page.controls.update({name: existing.control(page.page, identifier)
                          for name, identifier in (existing.API_CONTROLS | {'source': 58332}).items()})
    assert all(page.controls.values()), page.controls
    page.click('switch')
    page.click('mode')
    source = page.controls['source']  # 真实来源组合框，只选原有合作Agent选项。
    assert existing.gui.SendMessage(source, existing.con.CB_GETCURSEL, 0, 0) == 0
    existing.gui.SendMessage(source, existing.con.WM_KEYDOWN, existing.con.VK_DOWN, 0)
    assert existing.gui.SendMessage(source, existing.con.CB_GETCURSEL, 0, 0) == 1
    assert existing.text(source, existing.con.CB_GETLBTEXT, 1) == '合作 Agent'
    for name, value in (('api_pid', identity['pid']), ('creation', identity['creation'])):
        existing.set_text(page.controls[name], str(value))
    page.click('start')
    config = session / f'config_{identity["pid"]}_{identity["creation"]}.ini'
    existing.wait_for('合作源配置发布', config.is_file)
    page.wait_status('合作源Ready', lambda value: bool(existing.READY_RECEIPT.search(value)))

    def progress():
        value = page.status()  # 单次WM_GETTEXT提供完整的一份规范正文。
        history = light_history(value)
        return (value, history) if history and history['total'] > 32 else None

    running, running_history = existing.wait_for('主采集已提交行为运行进度', progress)
    sample = re.search(r'\r\n采样 ([0-9a-f-]{36})', running)[1]
    assert process.poll() is None and existing.gui.IsWindowEnabled(page.controls['stop'])
    write_json(directory, 'running', {'status': running, 'history': running_history, 'sample': sample})
    screenshot(page.process.pid, directory, 'running')
    page.click('stop')
    stopped = page.wait_status('主采集停止与清退', lambda value: '已核验回读 ' in value and
        not existing.gui.IsWindowEnabled(page.controls['stop']))
    assert process.poll() is None and f'\r\n采样 {sample}' in stopped, stopped
    assert all(value in stopped for value in ('正常 EOF 已确认', '停钩 已确认', '清退 已确认')), stopped
    assert (session / f'stop_{identity["pid"]}_{identity["creation"]}.flag').read_bytes() == b'stop'
    history = light_history(stopped)
    assert history and history['total'] >= running_history['total'], stopped
    entries = verify_history(history['entries'], history['total'], history['truncated'])
    write_json(directory, 'stopped', {'status': stopped, 'history': history, 'sample': sample})
    screenshot(page.process.pid, directory, 'stopped')
    return sample, entries, history['total']


def replay(page, sample, archive, directory):
    """经当前采样归档按钮定位最新历史见证；只读取同sample原段、原序号及证据正文。"""
    page.click('replay_current')
    page.wait_status('同sample归档打开', lambda value: sample in value and '当前归档' in value
                     and '正在读取' not in value)
    assert set(page.sample_entries()) == {sample}
    page.click('api_only')
    coordinate = archive['history'][-1]['coordinate']  # 最新行为在现有最近窗口内。
    segment, sequence, source = coordinate
    records = page.controls['records']
    existing.gui.SendMessage(records, existing.con.WM_KEYDOWN, existing.con.VK_END, 0)
    # 使用原生方向键依次读最近行，不跨进程写模型，也不使用系统剪贴板。
    for _ in range(min(page.row_count(), 128)):
        value = existing.text(page.controls['detail'])
        if f'未解析候选 · raw/{segment} #{sequence}\r\n' in value:
            break
        existing.gui.SendMessage(records, existing.con.WM_KEYDOWN, existing.con.VK_UP, 0)
    else:
        raise AssertionError(('同一行为原包未出现在归档窗口', coordinate, value))
    assert f'当前归档 · 采样：{sample}' in value and 'WriteProcessMemory' in value, value
    assert f'合作流水号（非 JSONL 行号）：{source}' in value, value
    assert existing.expected_behavior_lines() <= set(value.splitlines()), value
    write_json(directory, 'archive-gui', {'sample': sample, 'coordinate': coordinate, 'detail': value})
    screenshot(page.process.pid, directory, 'archive')


def run(directory, receipt):
    """输入本端固定落点；一个正式Light窗口与一个已有合作源，关闭后恢复配置并清理。"""
    driver = existing.require_idle_environment()
    existing.check_images()
    with owned_scratch(directory / 'work') as work:
        session = work / 'KswordApiMonCooperative'
        project = work / 'project'
        create_session_directory(session)
        environment = os.environ | {COOPERATIVE_ENV: str(session)}
        identity = None
        controller = None
        try:
            with existing.light_window(env=environment) as page:
                controller = page.process.pid
                page.default_page()
                page.browse('create', existing.CREATE_TITLE, project)
                page.wait_status('自有空工程', lambda value: '已新建工程 · ' in value and '工程尚无采样' in value)
                with owned_target(page, environment) as (process, identity):
                    receipt['target'] = identity
                    sample, history, total = capture(page, session, process, identity, directory)
                    receipt['sample'] = sample
                archive = verify_archive(project, sample, history, identity, existing.decode_raw,
                                         existing.read_cooperative_archive)
                receipt.update(archive=archive, behaviorMatches=total, sourceClean=True)
                write_json(directory, 'archive-evidence', archive)
                replay(page, sample, archive, directory)
                assert all(hashlib.sha256((project / path).read_bytes()).hexdigest() == digest
                           for path, digest in archive['segments'].items())
        finally:
            try:
                preserve_project(project, directory, receipt)
            finally:
                if identity is not None:
                    cleanup_session(session, identity['pid'], identity['creation'], controller)
                assert not list(session.iterdir()), session
                session.rmdir()
    assert existing.require_idle_environment() == driver
    receipt['cleanup'] = {'workRemoved': not (directory / 'work').exists(), 'guiClosed': True,
                          'settingsRestored': True, 'targetExit': process.returncode}


def main():
    """协调放行入口；准备批次禁止调用，仅静态验证脚本。"""
    hashes = release_arguments('light', existing.BINARY, CLI)
    with artifacts('light', hashes) as (directory, receipt):
        run(directory, receipt)


if __name__ == '__main__':
    main()
